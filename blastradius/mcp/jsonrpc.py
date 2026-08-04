"""Minimal JSON-RPC 2.0 framing for MCP.

Hand-rolled rather than taken from an SDK on purpose. This tool talks to
servers it does not trust, holding credentials it must not leak, so we want
to control exactly which bytes go out — and an SDK that helpfully calls a
tool on our behalf would break the read-only guarantee outright.
"""

from __future__ import annotations

import itertools
import json
from dataclasses import dataclass
from typing import Any

JSONRPC_VERSION = "2.0"

_ids = itertools.count(1)


def next_id() -> int:
    return next(_ids)


class ProtocolError(RuntimeError):
    """Peer spoke, but not JSON-RPC/MCP we can use."""


class RpcError(RuntimeError):
    """Peer returned a well-formed JSON-RPC error object."""

    def __init__(self, code: int, message: str, data: Any = None) -> None:
        super().__init__(f"[{code}] {message}")
        self.code = code
        self.message = message
        self.data = data


@dataclass(frozen=True, slots=True)
class Request:
    method: str
    params: dict[str, Any] | None = None
    id: int | None = None

    @property
    def is_notification(self) -> bool:
        return self.id is None

    def encode(self) -> bytes:
        payload: dict[str, Any] = {"jsonrpc": JSONRPC_VERSION, "method": self.method}
        if self.params is not None:
            payload["params"] = self.params
        if self.id is not None:
            payload["id"] = self.id
        # separators: compact and stable, so captured traffic diffs cleanly
        return (json.dumps(payload, separators=(",", ":")) + "\n").encode("utf-8")


def parse_response(raw: str | bytes, expect_id: int | None = None) -> dict[str, Any]:
    """Parse and validate a JSON-RPC response envelope.

    Returns the ``result`` object. Raises ``RpcError`` for a well-formed error
    reply and ``ProtocolError`` for anything malformed.
    """
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="replace")
    raw = raw.strip()
    if not raw:
        raise ProtocolError("empty response")

    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as exc:
        preview = raw[:120].replace("\n", "\\n")
        raise ProtocolError(f"non-JSON response ({exc.msg}): {preview!r}") from exc

    if not isinstance(doc, dict):
        raise ProtocolError(f"response is {type(doc).__name__}, expected object")

    if "error" in doc:
        err = doc["error"]
        if isinstance(err, dict):
            raise RpcError(int(err.get("code", -1)), str(err.get("message", "")), err.get("data"))
        raise ProtocolError(f"malformed error object: {err!r}")

    if "result" not in doc:
        raise ProtocolError(f"response has neither 'result' nor 'error': keys={sorted(doc)}")

    if expect_id is not None and doc.get("id") != expect_id:
        raise ProtocolError(f"id mismatch: expected {expect_id}, got {doc.get('id')!r}")

    result = doc["result"]
    if not isinstance(result, dict):
        raise ProtocolError(f"result is {type(result).__name__}, expected object")
    return result


def iter_sse_payloads(stream_text: str):
    """Yield ``data:`` payloads from a text/event-stream body.

    Streamable HTTP may answer a POST with an SSE stream instead of a JSON
    body. Event framing is blank-line separated; multiple ``data:`` lines in
    one event concatenate with newlines per the EventSource spec.
    """
    buf: list[str] = []
    for line in stream_text.splitlines():
        if not line.strip():
            if buf:
                yield "\n".join(buf)
                buf = []
            continue
        if line.startswith(":"):  # comment / keep-alive
            continue
        field, _, value = line.partition(":")
        if field == "data":
            buf.append(value[1:] if value.startswith(" ") else value)
    if buf:
        yield "\n".join(buf)
