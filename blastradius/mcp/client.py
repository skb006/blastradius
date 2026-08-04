"""MCP client — read-only by construction.

The read-only property is enforced structurally, not by convention. There is
no public method that can invoke a tool, and the private request path
validates every method name against ``READ_ONLY_METHODS`` before a byte
leaves the process. Adding a write capability requires editing that
frozenset, which is exactly the kind of change that should need a code review.

This matters because the prober runs against production agent deployments
holding live credentials. "We promise not to call tools" is not a guarantee
a regulated buyer can accept; "the client cannot express a tool call" is.
"""

from __future__ import annotations

from typing import Any, Iterable

from ..model import ResourceSpec, ToolSpec
from .jsonrpc import ProtocolError, Request, next_id, parse_response
from .transport import Transport

# Newest spec revision we advertise. Servers negotiate down and report what
# they chose; we record their answer rather than insisting on ours.
PREFERRED_PROTOCOL_VERSION = "2025-06-18"

CLIENT_INFO = {"name": "blastradius-prober", "version": "0.1.0"}

#: The complete set of MCP methods this client may ever send.
#: Every one of these is a *read*. Nothing here mutates server state.
READ_ONLY_METHODS: frozenset[str] = frozenset(
    {
        "initialize",
        "notifications/initialized",
        "tools/list",
        "resources/list",
        "resources/templates/list",
        "prompts/list",
        "ping",
    }
)

#: Methods that would constitute a write or an invocation. Named explicitly so
#: the prohibition is documented and directly testable.
FORBIDDEN_METHODS: frozenset[str] = frozenset(
    {
        "tools/call",
        "resources/read",
        "resources/subscribe",
        "prompts/get",
        "completion/complete",
        "sampling/createMessage",
        "roots/list",
        "logging/setLevel",
        "elicitation/create",
    }
)

_MAX_PAGES = 50


class ReadOnlyViolation(RuntimeError):
    """Raised when something tries to send a non-read method."""


class McpClient:
    """Speaks the handshake and the three list calls. Nothing else."""

    def __init__(self, transport: Transport) -> None:
        self._t = transport
        self.protocol_version: str | None = None
        self.server_name: str | None = None
        self.server_version: str | None = None
        self.capabilities: tuple[str, ...] = ()

    # -- guarded request path -------------------------------------------------

    def _check(self, method: str) -> None:
        if method in FORBIDDEN_METHODS:
            raise ReadOnlyViolation(
                f"{method!r} would invoke or mutate; this client is read-only"
            )
        if method not in READ_ONLY_METHODS:
            raise ReadOnlyViolation(f"{method!r} is not on the read-only allowlist")

    def _request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        self._check(method)
        req = Request(method=method, params=params, id=next_id())
        raw = self._t.exchange(req)
        return parse_response(raw, expect_id=req.id)

    def _notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        self._check(method)
        self._t.notify(Request(method=method, params=params, id=None))

    # -- handshake ------------------------------------------------------------

    def handshake(self) -> None:
        """`initialize` then `notifications/initialized`, per spec."""
        result = self._request(
            "initialize",
            {
                "protocolVersion": PREFERRED_PROTOCOL_VERSION,
                # We advertise no capabilities. We are not a host; we do not
                # accept sampling requests or expose roots.
                "capabilities": {},
                "clientInfo": CLIENT_INFO,
            },
        )
        self.protocol_version = str(result.get("protocolVersion") or "") or None
        info = result.get("serverInfo")
        if isinstance(info, dict):
            self.server_name = str(info.get("name") or "") or None
            self.server_version = str(info.get("version") or "") or None
        caps = result.get("capabilities")
        self.capabilities = tuple(sorted(caps)) if isinstance(caps, dict) else ()
        if not self.protocol_version:
            raise ProtocolError("initialize result omitted protocolVersion")
        self._notify("notifications/initialized")

    # -- read-only enumeration -------------------------------------------------

    def _paginate(self, method: str, key: str) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        cursor: str | None = None
        for _ in range(_MAX_PAGES):
            params = {"cursor": cursor} if cursor else None
            result = self._request(method, params)
            page = result.get(key)
            if isinstance(page, list):
                items.extend(x for x in page if isinstance(x, dict))
            cursor = result.get("nextCursor")
            if not isinstance(cursor, str) or not cursor:
                break
        return items

    def list_tools(self) -> tuple[ToolSpec, ...]:
        if self.capabilities and "tools" not in self.capabilities:
            return ()
        return tuple(_to_tool(raw) for raw in self._paginate("tools/list", "tools"))

    def list_resources(self) -> tuple[ResourceSpec, ...]:
        if self.capabilities and "resources" not in self.capabilities:
            return ()
        out: list[ResourceSpec] = []
        for raw in self._paginate("resources/list", "resources"):
            uri = raw.get("uri")
            if isinstance(uri, str):
                out.append(
                    ResourceSpec(
                        uri=uri,
                        name=_opt_str(raw.get("name")),
                        mime_type=_opt_str(raw.get("mimeType")),
                    )
                )
        return tuple(out)

    def list_prompts(self) -> tuple[str, ...]:
        if self.capabilities and "prompts" not in self.capabilities:
            return ()
        names = [raw.get("name") for raw in self._paginate("prompts/list", "prompts")]
        return tuple(str(n) for n in names if isinstance(n, str))

    def close(self) -> None:
        self._t.close()

    def __enter__(self) -> "McpClient":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def _opt_str(v: object) -> str | None:
    return str(v) if isinstance(v, str) and v else None


def _opt_bool(v: object) -> bool | None:
    return v if isinstance(v, bool) else None


def _schema_params(schema: object) -> tuple[tuple[str, ...], tuple[str, ...]]:
    if not isinstance(schema, dict):
        return ((), ())
    props = schema.get("properties")
    names = tuple(sorted(str(k) for k in props)) if isinstance(props, dict) else ()
    req = schema.get("required")
    required = tuple(sorted(str(x) for x in req)) if isinstance(req, list) else ()
    return names, required


def _to_tool(raw: dict[str, Any]) -> ToolSpec:
    params, required = _schema_params(raw.get("inputSchema"))
    ann = raw.get("annotations")
    ann = ann if isinstance(ann, dict) else {}
    desc = _opt_str(raw.get("description"))
    return ToolSpec(
        name=str(raw.get("name") or "<unnamed>"),
        description=(desc[:280] if desc else None),
        input_params=params,
        required_params=required,
        read_only=_opt_bool(ann.get("readOnlyHint")),
        destructive=_opt_bool(ann.get("destructiveHint")),
        idempotent=_opt_bool(ann.get("idempotentHint")),
        open_world=_opt_bool(ann.get("openWorldHint")),
    )
