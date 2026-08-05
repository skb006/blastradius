"""Transports: stdio (spawned subprocess) and streamable HTTP.

Both are strictly request/response here. We never open a long-lived server
event stream, because the prober has nothing to listen for — it asks three
questions and leaves.

Safety notes that are load-bearing, not decorative:

* **stdio spawning executes arbitrary code from config.** The caller must opt
  in explicitly; ``StdioTransport`` refuses to construct otherwise.
* **stderr is captured, never merged into stdout.** Servers log freely to
  stderr and merging would corrupt the protocol stream.
* **Every operation is deadline-bounded.** A hung server must not hang a CI job.
"""

from __future__ import annotations

import os
import queue
import shutil
import subprocess
import threading
import urllib.error
import urllib.request
from typing import Any, Protocol

from .jsonrpc import ProtocolError, Request, iter_sse_payloads

DEFAULT_TIMEOUT = 12.0
_STDERR_KEEP = 4000


class RuntimeMissing(RuntimeError):
    """Declared command is not installed — the grant exists but is inert."""


class Unreachable(RuntimeError):
    """Nothing answered."""


class AuthRequired(RuntimeError):
    """Reachable but refused: a surface exists, closed to us.

    ``challenge`` carries the ``WWW-Authenticate`` header when the server
    sent one. Under the MCP authorization spec a challenge naming a
    protected-resource metadata URL means the server expects a *per-caller*
    token, not a static shared secret — which is the difference between a
    server that delegates and one that acts on its own authority.
    """

    def __init__(self, message: str, challenge: str | None = None) -> None:
        super().__init__(message)
        self.challenge = challenge


class Transport(Protocol):  # pragma: no cover - structural
    def exchange(self, request: Request) -> str | None: ...
    def notify(self, request: Request) -> None: ...
    def close(self) -> None: ...
    @property
    def stderr_tail(self) -> str: ...


class StdioTransport:
    """Speak newline-delimited JSON-RPC to a spawned child process."""

    def __init__(
        self,
        command: str,
        args: tuple[str, ...] = (),
        env: dict[str, str] | None = None,
        cwd: str | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        *,
        allow_spawn: bool,
    ) -> None:
        if not allow_spawn:
            raise PermissionError(
                "refusing to spawn a stdio MCP server without explicit opt-in "
                "(--allow-spawn); spawning executes code declared in config"
            )
        if shutil.which(command) is None and not os.path.isabs(command):
            raise RuntimeMissing(f"command not found on PATH: {command!r}")

        self._timeout = timeout
        self._stderr: list[str] = []
        try:
            self._proc = subprocess.Popen(  # noqa: S603 - intentional, gated above
                [command, *args],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=cwd,
                env={**os.environ, **(env or {})},
                text=True,
                bufsize=1,
            )
        except FileNotFoundError as exc:
            raise RuntimeMissing(f"command not found: {command!r}") from exc
        except OSError as exc:
            raise Unreachable(f"could not spawn {command!r}: {exc}") from exc

        self._lines: queue.Queue[str | None] = queue.Queue()
        self._readers = [
            threading.Thread(target=self._pump_stdout, daemon=True),
            threading.Thread(target=self._pump_stderr, daemon=True),
        ]
        for t in self._readers:
            t.start()

    def _pump_stdout(self) -> None:
        try:
            assert self._proc.stdout is not None
            for line in self._proc.stdout:
                self._lines.put(line)
        except (ValueError, OSError):
            pass
        finally:
            self._lines.put(None)  # EOF sentinel

    def _pump_stderr(self) -> None:
        try:
            assert self._proc.stderr is not None
            for line in self._proc.stderr:
                if sum(len(s) for s in self._stderr) < _STDERR_KEEP:
                    self._stderr.append(line)
        except (ValueError, OSError):
            pass

    @property
    def stderr_tail(self) -> str:
        return "".join(self._stderr)[-_STDERR_KEEP:]

    def _write(self, request: Request) -> None:
        if self._proc.poll() is not None:
            raise Unreachable(f"server exited (rc={self._proc.returncode}) before request")
        try:
            assert self._proc.stdin is not None
            self._proc.stdin.write(request.encode().decode("utf-8"))
            self._proc.stdin.flush()
        except (BrokenPipeError, ValueError) as exc:
            raise Unreachable(f"server closed stdin: {exc}") from exc

    def exchange(self, request: Request) -> str:
        """Send a request and return the first JSON-looking line back.

        Servers routinely print banners on stdout before speaking protocol,
        so non-JSON lines are skipped rather than treated as a failure.
        """
        self._write(request)
        deadline_hits = 0
        while True:
            try:
                line = self._lines.get(timeout=self._timeout)
            except queue.Empty:
                raise TimeoutError(
                    f"no response within {self._timeout}s to {request.method!r}"
                ) from None
            if line is None:
                rc = self._proc.poll()
                raise Unreachable(
                    f"server closed stdout (rc={rc}); stderr: {self.stderr_tail[-300:]!r}"
                )
            stripped = line.strip()
            if not stripped:
                continue
            if not stripped.startswith("{"):
                deadline_hits += 1
                if deadline_hits > 50:
                    raise ProtocolError("server emitted 50 non-JSON lines; giving up")
                continue
            return stripped

    def notify(self, request: Request) -> None:
        self._write(request)

    def close(self) -> None:
        """Tear the child down and close every pipe.

        Leaking pipes here would surface as ResourceWarnings in a consumer's
        test suite and, worse, as exhausted file descriptors when probing a
        deployment with many stdio servers. Closing is best-effort but
        exhaustive: stdin first so the child sees EOF and can exit cleanly,
        then terminate, then the read ends once the pump threads are done.
        """
        try:
            if self._proc.stdin and not self._proc.stdin.closed:
                self._proc.stdin.close()
        except OSError:
            pass

        try:
            self._proc.terminate()
            self._proc.wait(timeout=3)
        except (subprocess.TimeoutExpired, OSError):
            try:
                self._proc.kill()
                self._proc.wait(timeout=2)
            except (subprocess.TimeoutExpired, OSError):
                pass

        # Let the pump threads notice EOF before we pull the files out from
        # under them; they swallow ValueError/OSError either way.
        for t in self._readers:
            t.join(timeout=1.0)

        for pipe in (self._proc.stdout, self._proc.stderr):
            try:
                if pipe and not pipe.closed:
                    pipe.close()
            except OSError:
                pass


class HttpTransport:
    """Streamable HTTP: POST JSON-RPC, accept a JSON body or an SSE stream."""

    def __init__(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self._url = url
        self._timeout = timeout
        self._session_id: str | None = None
        self._headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "User-Agent": "blastradius-prober/0.1 (read-only)",
            **(headers or {}),
        }

    @property
    def stderr_tail(self) -> str:
        return ""

    def _post(self, request: Request) -> tuple[str, dict[str, str]]:
        headers = dict(self._headers)
        if self._session_id:
            headers["Mcp-Session-Id"] = self._session_id
        req = urllib.request.Request(
            self._url, data=request.encode(), headers=headers, method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:  # noqa: S310
                body = resp.read().decode("utf-8", errors="replace")
                resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                sid = resp_headers.get("mcp-session-id")
                if sid:
                    self._session_id = sid
                return body, resp_headers
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:300]
            if exc.code in (401, 403):
                challenge = None
                if exc.headers:
                    challenge = exc.headers.get("WWW-Authenticate")
                raise AuthRequired(f"HTTP {exc.code}: {detail}", challenge) from exc
            if exc.code == 404:
                raise Unreachable(f"HTTP 404 at {self._url}") from exc
            if exc.code == 405:
                raise ProtocolError(
                    f"HTTP 405 — endpoint rejects POST; likely legacy HTTP+SSE transport"
                ) from exc
            raise ProtocolError(f"HTTP {exc.code}: {detail}") from exc
        except urllib.error.URLError as exc:
            raise Unreachable(f"{exc.reason}") from exc
        except TimeoutError:
            raise
        except OSError as exc:
            raise Unreachable(str(exc)) from exc

    def exchange(self, request: Request) -> str:
        body, headers = self._post(request)
        ctype = headers.get("content-type", "")
        if "text/event-stream" in ctype:
            for payload in iter_sse_payloads(body):
                if payload.strip().startswith("{"):
                    return payload
            raise ProtocolError("SSE stream carried no JSON payload")
        return body

    def notify(self, request: Request) -> None:
        try:
            self._post(request)
        except (ProtocolError, Unreachable):
            # Notifications are fire-and-forget; some servers answer 202 with
            # an empty body, which is fine and must not abort the probe.
            pass

    def close(self) -> None:  # pragma: no cover - nothing to release
        return
