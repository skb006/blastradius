"""Core data model.

Everything here is frozen and JSON-serialisable. Two invariants hold across
the whole model and the tests enforce both:

1. **No credential values.** Only key names survive parsing (see ``redact``).
2. **Every fact is attributable.** Each declaration carries an ``Origin``
   naming the file and the locator inside it. A finding you cannot trace to
   a line is not evidence, and evidence is the product.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, asdict
from typing import Any, Literal
from urllib.parse import urlparse, urlunparse

Transport = Literal["stdio", "http", "sse", "unknown"]

# Linux default ephemeral range. Ports here on loopback are session-scoped
# and carry no identity, so they are normalised out for grouping.
_EPHEMERAL_LOW, _EPHEMERAL_HIGH = 32768, 60999
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1", "[::1]"})


def _recency(spec: "ServerSpec") -> tuple[float, str]:
    """Sort key: newest declaring config wins, path as a stable tiebreak."""
    try:
        mtime = os.stat(spec.origin.path).st_mtime
    except (OSError, ValueError):
        mtime = 0.0
    return (mtime, spec.origin.path)


def _normalise_ephemeral_url(url: str) -> str:
    """Collapse ``http://127.0.0.1:39765/mcp`` -> ``http://127.0.0.1:<ephemeral>/mcp``."""
    try:
        parts = urlparse(url)
    except ValueError:
        return url
    host = (parts.hostname or "").lower()
    if host not in _LOOPBACK_HOSTS:
        return url
    port = parts.port
    if port is None or not (_EPHEMERAL_LOW <= port <= _EPHEMERAL_HIGH):
        return url
    netloc = f"{parts.hostname}:<ephemeral>"
    return urlunparse(parts._replace(netloc=netloc))

ProbeStatus = Literal[
    "ok",              # handshake completed, tool surface recovered
    "skipped",         # policy said don't (e.g. stdio without --allow-spawn)
    "runtime_missing", # declared command is not installed -> inert grant
    "unreachable",     # nothing listening / connection refused
    "timeout",
    "protocol_error",  # spoke, but not MCP we understand
    "auth_required",   # reachable, refused us -> surface exists but is closed
    "truncated",       # spoke, but the enumeration never finished -> partial
]

Severity = Literal["error", "warn", "info"]


@dataclass(frozen=True, slots=True)
class Origin:
    """Where a declaration came from."""

    path: str
    locator: str = ""

    def __str__(self) -> str:  # pragma: no cover - trivial
        return f"{self.path}#{self.locator}" if self.locator else self.path


@dataclass(frozen=True, slots=True)
class Diagnostic:
    """A problem worth surfacing.

    ``code`` is stable and machine-matchable so CI can allowlist specific
    diagnostics without regex-matching prose.
    """

    severity: Severity
    code: str
    message: str
    origin: Origin | None = None

    def to_json(self) -> dict[str, Any]:
        return {
            "severity": self.severity,
            "code": self.code,
            "message": self.message,
            "origin": str(self.origin) if self.origin else None,
        }


@dataclass(frozen=True, slots=True)
class ServerSpec:
    """An MCP server as *declared* in configuration.

    This is the stage-1 artifact. It records what the config says, including
    what it conspicuously fails to say — ``declared_authz`` is empty for
    almost every server in the wild, which is the Phase 0 finding in one
    field.
    """

    name: str
    transport: Transport
    origin: Origin
    command: str | None = None
    args: tuple[str, ...] = ()
    url: str | None = None
    env_keys: tuple[str, ...] = ()
    header_keys: tuple[str, ...] = ()
    credential_keys: tuple[str, ...] = ()
    declared_authz: tuple[str, ...] = ()

    # -- connect targets: raw, never serialised, never printed ----------------
    #
    # ``url`` and ``args`` above hold the REDACTED forms, because those are
    # what gets rendered and dumped. But a credential embedded in a URL or an
    # argv element is *also* how the server is reached, so probing needs the
    # original. Keeping it in a field that `to_json` deletes and `repr`
    # excludes is what lets both properties hold at once: the report cannot
    # leak it, and the prober can still connect.
    #
    # Re-reading the config at connect time was the alternative and is worse:
    # it reintroduces a TOCTOU window between the scan and the probe.
    connect_url: str | None = field(default=None, repr=False, compare=False)
    connect_args: tuple[str, ...] = field(default=(), repr=False, compare=False)

    @property
    def dial_url(self) -> str | None:
        return self.connect_url or self.url

    @property
    def dial_args(self) -> tuple[str, ...]:
        return self.connect_args or self.args

    @property
    def identity(self) -> str:
        """Exact identity. Used when we need to talk to *this* endpoint."""
        return f"{self.name}|{self.transport}|{self.url or self.command or ''}"

    @property
    def logical_identity(self) -> str:
        """Identity with ephemeral detail normalised away.

        Agent runtimes that bind a fresh loopback port per session (OpenClaw
        does) would otherwise present twenty copies of one server as twenty
        distinct servers — inflating the inventory and, worse, suppressing
        the sprawl warning because no single identity ever repeats.

        Only loopback addresses on ephemeral ports are collapsed. A rotating
        port on a routable host is a different situation and stays distinct.
        """
        target = self.url or self.command or ""
        if self.url:
            target = _normalise_ephemeral_url(self.url)
        return f"{self.name}|{self.transport}|{target}"

    def to_json(self) -> dict[str, Any]:
        d = asdict(self)
        d["origin"] = str(self.origin)
        for k in ("args", "env_keys", "header_keys", "credential_keys", "declared_authz"):
            d[k] = list(d[k])
        # The connect targets are the unredacted originals. They exist so the
        # prober can dial; they must never reach an artifact.
        d.pop("connect_url", None)
        d.pop("connect_args", None)
        return d


@dataclass(frozen=True, slots=True)
class ToolSpec:
    """A tool the server actually exposes — recovered, not declared.

    ``read_only`` / ``destructive`` come from MCP tool annotations when the
    server supplies them. They matter more than anything else here: a
    destructive tool is a write edge in the blast-radius graph, and an
    unannotated tool has to be treated as one until proven otherwise.
    """

    name: str
    description: str | None = None
    input_params: tuple[str, ...] = ()
    required_params: tuple[str, ...] = ()
    read_only: bool | None = None
    destructive: bool | None = None
    idempotent: bool | None = None
    open_world: bool | None = None

    @property
    def write_capable(self) -> bool:
        """Conservative: unannotated tools count as write-capable.

        Sound over-approximation. Under-counting write edges would understate
        blast radius, which is the one error this tool must never make.
        """
        if self.destructive is True:
            return True
        if self.read_only is True:
            return False
        return True

    def to_json(self) -> dict[str, Any]:
        d = asdict(self)
        d["input_params"] = list(self.input_params)
        d["required_params"] = list(self.required_params)
        d["write_capable"] = self.write_capable
        return d


@dataclass(frozen=True, slots=True)
class ResourceSpec:
    """A resource the server exposes."""

    uri: str
    name: str | None = None
    mime_type: str | None = None

    def to_json(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class ProbeResult:
    """Outcome of speaking MCP to one declared server."""

    server: ServerSpec
    status: ProbeStatus
    protocol_version: str | None = None
    server_name: str | None = None
    server_version: str | None = None
    capabilities: tuple[str, ...] = ()
    tools: tuple[ToolSpec, ...] = ()
    resources: tuple[ResourceSpec, ...] = ()
    prompts: tuple[str, ...] = ()
    diagnostics: tuple[Diagnostic, ...] = ()
    duration_ms: int = 0
    auth_challenge: str | None = None

    @property
    def requires_caller_token(self) -> bool:
        """True when the server demands a per-caller token rather than
        accepting a static shared secret.

        Derived from the ``WWW-Authenticate`` challenge: under the MCP
        authorization spec, a challenge pointing at protected-resource
        metadata means OAuth, and OAuth means the caller's identity — not
        the server's — decides what the request may do.
        """
        if not self.auth_challenge:
            return False
        low = self.auth_challenge.lower()
        return "bearer" in low and (
            "resource_metadata" in low or "as_uri" in low
            or "authorization_uri" in low or "realm" in low)

    @property
    def recovered(self) -> bool:
        """Did we learn the tool surface? This is the coverage metric."""
        return self.status == "ok"

    @property
    def write_tools(self) -> tuple[ToolSpec, ...]:
        return tuple(t for t in self.tools if t.write_capable)

    def to_json(self) -> dict[str, Any]:
        return {
            "server": self.server.to_json(),
            "status": self.status,
            "recovered": self.recovered,
            "protocol_version": self.protocol_version,
            "server_name": self.server_name,
            "server_version": self.server_version,
            "capabilities": list(self.capabilities),
            "auth_challenge": self.auth_challenge,
            "requires_caller_token": self.requires_caller_token,
            "tools": [t.to_json() for t in self.tools],
            "resources": [r.to_json() for r in self.resources],
            "prompts": list(self.prompts),
            "diagnostics": [d.to_json() for d in self.diagnostics],
            "duration_ms": self.duration_ms,
        }


@dataclass
class Inventory:
    """Stage-1 output: what configuration declares, plus how badly it parsed."""

    servers: list[ServerSpec] = field(default_factory=list)
    diagnostics: list[Diagnostic] = field(default_factory=list)
    scanned_paths: list[str] = field(default_factory=list)

    def deduped(self) -> list[ServerSpec]:
        """Collapse servers that are the same thing declared many times.

        Grouped by ``logical_identity``, so a runtime that rebinds a fresh
        loopback port each session appears once rather than once per session.
        Keeps the first-seen spec; ``copies()`` carries the multiplicity and
        ``endpoints()`` carries the concrete addresses, so nothing is lost.
        """
        seen: dict[str, ServerSpec] = {}
        for s in self.servers:
            seen.setdefault(s.logical_identity, s)
        return sorted(seen.values(), key=lambda s: (s.name, s.logical_identity))

    def copies(self) -> dict[str, int]:
        """How many times each logical server was declared."""
        counts: dict[str, int] = {}
        for s in self.servers:
            counts[s.logical_identity] = counts.get(s.logical_identity, 0) + 1
        return counts

    def endpoints(self) -> dict[str, list[ServerSpec]]:
        """Every concrete spec behind each logical server.

        The prober needs these: collapsing for the report must not collapse
        what we actually try to talk to.
        """
        groups: dict[str, list[ServerSpec]] = {}
        for s in self.servers:
            groups.setdefault(s.logical_identity, []).append(s)
        return groups

    def probe_targets(self) -> list[ServerSpec]:
        """One candidate endpoint per logical server.

        Chosen by the mtime of the declaring config, because for a runtime
        that rebinds each session the newest config is the only one with a
        chance of being live. Sorting by URL would pick the highest port
        number, which is unrelated to recency — a real bug found by running
        this against a machine whose newest session had the lowest port.
        """
        out: list[ServerSpec] = []
        for _, specs in sorted(self.endpoints().items()):
            out.append(max(specs, key=_recency))
        return sorted(out, key=lambda s: (s.name, s.logical_identity))

    def to_json(self) -> dict[str, Any]:
        return {
            "servers": [s.to_json() for s in self.deduped()],
            "declared_count": len(self.servers),
            "unique_count": len(self.deduped()),
            "diagnostics": [d.to_json() for d in self.diagnostics],
            "scanned_paths": sorted(self.scanned_paths),
        }
