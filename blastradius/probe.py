"""Stage 2 — speak MCP to each declared server and recover its real surface.

Failure is never fatal to the run. Every server yields a ``ProbeResult``
whatever happens, because "we could not determine this server's reach" is
itself a finding that must appear in the report. Silently dropping an
unprobeable server would inflate the apparent coverage, which is the one
number this tool must not lie about.
"""

from __future__ import annotations

import time
from typing import Iterable, Sequence
from urllib.parse import urlparse

from .model import Diagnostic, ProbeResult, ProbeStatus, ServerSpec
from .mcp.client import McpClient, ReadOnlyViolation
from .mcp.jsonrpc import ProtocolError, RpcError
from .mcp.transport import (
    AuthRequired,
    DEFAULT_TIMEOUT,
    HttpTransport,
    RuntimeMissing,
    StdioTransport,
    Transport,
    Unreachable,
)


def _build_transport(
    spec: ServerSpec, *, allow_spawn: bool, timeout: float
) -> Transport:
    if spec.transport in ("http", "sse"):
        if not spec.url:
            raise ProtocolError("http transport declared without a url")
        # Credential-bearing headers were dropped at parse time by design, so
        # we probe unauthenticated. A 401 back is a *useful* result: it proves
        # a surface exists and is gated, which is a different fact from
        # "no server here".
        return HttpTransport(spec.url, timeout=timeout)
    if spec.transport == "stdio":
        if not spec.command:
            raise ProtocolError("stdio transport declared without a command")
        return StdioTransport(
            spec.command, spec.args, timeout=timeout, allow_spawn=allow_spawn
        )
    raise ProtocolError(f"unsupported transport {spec.transport!r}")


def _is_loopback(url: str | None) -> bool:
    if not url:
        return False
    try:
        host = (urlparse(url).hostname or "").lower()
    except ValueError:
        return False
    return host in {"127.0.0.1", "localhost", "::1"} or host.startswith("127.")


def probe_server(
    spec: ServerSpec,
    *,
    allow_spawn: bool = False,
    allow_remote: bool = True,
    timeout: float = DEFAULT_TIMEOUT,
) -> ProbeResult:
    """Handshake with one server and enumerate what it exposes."""
    started = time.monotonic()
    diags: list[Diagnostic] = []

    def finish(status: ProbeStatus, **kw) -> ProbeResult:
        return ProbeResult(
            server=spec,
            status=status,
            diagnostics=tuple(diags),
            duration_ms=int((time.monotonic() - started) * 1000),
            **kw,
        )

    if spec.transport in ("http", "sse") and not allow_remote and not _is_loopback(spec.url):
        diags.append(
            Diagnostic(
                "info", "probe.skipped_remote",
                f"'{spec.name}' is a remote endpoint ({spec.url}); --no-remote is set",
                spec.origin,
            )
        )
        return finish("skipped")

    if spec.transport == "stdio" and not allow_spawn:
        diags.append(
            Diagnostic(
                "info", "probe.skipped_stdio",
                f"'{spec.name}' is stdio; probing would execute {spec.command!r}. "
                f"Re-run with --allow-spawn to include it.",
                spec.origin,
            )
        )
        return finish("skipped")

    transport: Transport | None = None
    try:
        transport = _build_transport(spec, allow_spawn=allow_spawn, timeout=timeout)
    except RuntimeMissing as exc:
        diags.append(
            Diagnostic(
                "warn", "probe.runtime_missing",
                f"{exc} — this grant is declared but inert on this host",
                spec.origin,
            )
        )
        return finish("runtime_missing")
    except PermissionError as exc:
        diags.append(Diagnostic("info", "probe.skipped_stdio", str(exc), spec.origin))
        return finish("skipped")
    except (ProtocolError, Unreachable) as exc:
        diags.append(Diagnostic("error", "probe.transport_error", str(exc), spec.origin))
        return finish("protocol_error")

    try:
        with McpClient(transport) as client:
            client.handshake()
            tools = client.list_tools()
            resources = client.list_resources()
            prompts = client.list_prompts()

            if not tools and "tools" in client.capabilities:
                diags.append(
                    Diagnostic("info", "probe.no_tools",
                               f"'{spec.name}' advertises tools capability but listed none",
                               spec.origin))

            unannotated = [t for t in tools if t.read_only is None and t.destructive is None]
            if unannotated:
                diags.append(
                    Diagnostic(
                        "warn", "probe.unannotated_tools",
                        f"{len(unannotated)}/{len(tools)} tools on '{spec.name}' carry no "
                        f"readOnly/destructive hint — counted as write-capable",
                        spec.origin,
                    )
                )

            return finish(
                "ok",
                protocol_version=client.protocol_version,
                server_name=client.server_name,
                server_version=client.server_version,
                capabilities=client.capabilities,
                tools=tools,
                resources=resources,
                prompts=prompts,
            )
    except AuthRequired as exc:
        challenge = getattr(exc, "challenge", None)
        diags.append(
            Diagnostic("info", "probe.auth_required",
                       f"reachable but refused ({exc}); surface exists, scope unknown",
                       spec.origin))
        if challenge:
            diags.append(Diagnostic(
                "info", "probe.caller_token_required",
                f"'{spec.name}' challenges with {challenge!r} — it expects a "
                f"per-caller token, so its authority is bounded by the caller "
                f"rather than held by the server",
                spec.origin))
        return finish("auth_required", auth_challenge=challenge)
    except TimeoutError as exc:
        diags.append(Diagnostic("warn", "probe.timeout", str(exc), spec.origin))
        return finish("timeout")
    except Unreachable as exc:
        diags.append(Diagnostic("info", "probe.unreachable", str(exc), spec.origin))
        return finish("unreachable")
    except RpcError as exc:
        diags.append(
            Diagnostic("warn", "probe.rpc_error", f"server returned {exc}", spec.origin))
        return finish("protocol_error")
    except ReadOnlyViolation:  # pragma: no cover - would be our own bug
        raise
    except ProtocolError as exc:
        diags.append(Diagnostic("warn", "probe.protocol_error", str(exc), spec.origin))
        return finish("protocol_error")
    finally:
        if transport is not None:
            try:
                transport.close()
            except Exception:  # noqa: BLE001 - cleanup must never mask a result
                pass


def probe_all(
    specs: Sequence[ServerSpec],
    *,
    allow_spawn: bool = False,
    allow_remote: bool = True,
    timeout: float = DEFAULT_TIMEOUT,
) -> list[ProbeResult]:
    return [
        probe_server(s, allow_spawn=allow_spawn, allow_remote=allow_remote, timeout=timeout)
        for s in specs
    ]


def coverage(results: Iterable[ProbeResult]) -> dict[str, float | int]:
    """Quantify how much of the declared surface we actually recovered.

    This is the number that validates (or refutes) the Phase 0 estimate that
    an MCP handshake lifts grant-edge coverage from ~2% to ~38%. It is
    reported honestly: skipped and unreachable servers count against us.
    """
    results = list(results)
    total = len(results)
    recovered = sum(1 for r in results if r.recovered)
    tools = sum(len(r.tools) for r in results)
    write_tools = sum(len(r.write_tools) for r in results)
    return {
        "servers_declared": total,
        "servers_recovered": recovered,
        "recovery_rate": round(recovered / total, 4) if total else 0.0,
        "tools_discovered": tools,
        "write_capable_tools": write_tools,
        "resources_discovered": sum(len(r.resources) for r in results),
    }
