"""The agent reachability graph, assembled from stages 1-3.

Shape of the thing being proved::

    agent ──[tool: create_issue, write]──▶ mcp:github ──[scope: repo, write]──▶ github:octocat

A path through this graph is a blast-radius statement: *if the agent is
prompt-injected, it can effect a write against github:octocat via the
create_issue tool, using the credential the server carries.*

Two soundness rules govern construction, and both err the same way — towards
over-stating reach, never under-stating it:

**An unknown surface is unbounded.** A server we could not probe (gated,
inert, skipped) gets a write-capable edge labelled ``<unknown>``. Treating an
unprobed server as harmless would be the one error this tool must not make.

**An inert credential grants nothing.** A credential the issuer rejected
produces no edge at all. This is where stage 3 earns its place: it does not
only add edges, it *prunes* them. A revoked token in a config looks alarming
until you learn the issuer refuses it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Literal, Sequence

from ..creds.model import CredentialReport, Resolution
from ..model import Origin, ProbeResult, ServerSpec
from .delegation import DelegationMode, classify_server, is_confused_deputy

NodeKind = Literal["agent", "server", "principal"]

#: The capability classes a path can carry. Deliberately coarse: the question
#: worth proving is "can this agent effect a write on that principal", and the
#: specific tool and scope names ride along as witness evidence.
Capability = Literal["read", "write"]

#: Whether a hop can be taken on the caller's own authority (``direct``) or
#: only under a delegation established upstream (``delegated``). A path that
#: is reachable ``direct`` end to end spends authority nobody delegated —
#: the confused deputy.
Mode = Literal["direct", "delegated"]

BOTH_MODES: frozenset[str] = frozenset({"direct", "delegated"})
DELEGATED_ONLY: frozenset[str] = frozenset({"delegated"})

AGENT_ID = "agent"

#: Scopes that confer *only* read authority. Everything else counts as write.
#:
#: This set is an allowlist and the default is deliberately the other way
#: round. An earlier version enumerated WRITE scopes and defaulted the
#: remainder to read, which meant every write scope nobody thought to list —
#: the whole GitHub fine-grained vocabulary (``contents:write``,
#: ``issues:write``, ``pull_requests:write``), ``public_repo``, ``gist``,
#: ``write:discussion``, every Google drive.* variant — became a read edge and
#: the prover emitted PROVEN UNREACHABLE for a write that was plainly
#: reachable. A false proof of absence is the one output this tool must never
#: produce, so the unbounded side of the default has to be write.
#:
#: Curated by hand, not by prefix: several scopes read as harmless and are
#: not. ``security_events`` writes code-scanning alerts; ``gist`` creates
#: gists; ``user`` can change profile and email.
READ_ONLY_SCOPES = frozenset({
    # GitHub (classic)
    "read:org", "read:user", "read:packages", "read:discussion", "read:gpg_key",
    "read:public_key", "read:repo_hook", "read:project", "read:audit_log",
    "read:enterprise", "read:network", "user:email", "user:follow",
    # GitLab
    "read_api", "read_user", "read_repository", "read_registry",
    "read_observability", "read_service_ping",
    # Slack
    "channels:read", "groups:read", "im:read", "mpim:read", "users:read",
    "team:read", "files:read", "channels:history", "groups:history",
    "im:history", "mpim:history", "emoji:read", "reactions:read",
    "usergroups:read", "pins:read", "bookmarks:read", "users:read.email",
    # Google
    "https://www.googleapis.com/auth/drive.readonly",
    "https://www.googleapis.com/auth/drive.metadata.readonly",
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.metadata",
    "https://www.googleapis.com/auth/calendar.readonly",
    "https://www.googleapis.com/auth/spreadsheets.readonly",
    "openid", "email", "profile", "userinfo.email", "userinfo.profile",
    # Generic
    "read", "readonly", "read-only", "view", "list", "get",
})


def scope_capability(scope: str) -> Capability:
    """Classify a scope. Unknown scopes count as write — see READ_ONLY_SCOPES."""
    return "read" if scope.strip().lower() in READ_ONLY_SCOPES else "write"


@dataclass(frozen=True, slots=True)
class Node:
    id: str
    kind: NodeKind
    label: str

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.id


@dataclass(frozen=True, slots=True)
class Edge:
    """A grant. ``operation`` is the concrete thing (tool or scope) that
    justifies it; ``capability`` is what it lets you do."""

    src: str
    dst: str
    operation: str
    capability: Capability
    evidence: str
    origin: Origin | None = None
    inferred: bool = False   # True when we assumed rather than observed
    modes: frozenset[str] = BOTH_MODES

    @property
    def is_write(self) -> bool:
        return self.capability == "write"

    @property
    def allows_direct(self) -> bool:
        """True if this hop can be taken without any delegation upstream."""
        return "direct" in self.modes


@dataclass
class AgentGraph:
    nodes: dict[str, Node] = field(default_factory=dict)
    edges: list[Edge] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    #: server name -> (how it obtains authority, why we think so)
    delegation: dict[str, tuple[str, str]] = field(default_factory=dict)

    def add_node(self, node: Node) -> None:
        self.nodes.setdefault(node.id, node)

    def add_edge(self, edge: Edge) -> None:
        self.edges.append(edge)

    def principals(self) -> list[Node]:
        return [n for n in self.nodes.values() if n.kind == "principal"]

    def servers(self) -> list[Node]:
        return [n for n in self.nodes.values() if n.kind == "server"]

    def edges_from(self, node_id: str) -> list[Edge]:
        return [e for e in self.edges if e.src == node_id]

    def to_json(self) -> dict:
        return {
            "nodes": [
                {"id": n.id, "kind": n.kind, "label": n.label}
                for n in sorted(self.nodes.values(), key=lambda n: n.id)
            ],
            "edges": [
                {
                    "src": e.src, "dst": e.dst, "operation": e.operation,
                    "capability": e.capability, "evidence": e.evidence,
                    "inferred": e.inferred,
                    "origin": str(e.origin) if e.origin else None,
                }
                for e in sorted(self.edges, key=lambda e: (e.src, e.dst, e.operation))
            ],
            "notes": list(self.notes),
            "delegation": {k: {"mode": m, "reason": r}
                           for k, (m, r) in sorted(self.delegation.items())},
        }


def _server_node(spec: ServerSpec) -> Node:
    return Node(id=f"mcp:{spec.name}", kind="server", label=spec.name)


def _principal_node(res: Resolution) -> Node:
    pid = res.principal or f"{res.classification.provider}:<unidentified>"
    return Node(id=f"principal:{pid}", kind="principal", label=pid)


def build_graph(
    servers: Sequence[ServerSpec],
    probes: Sequence[ProbeResult] = (),
    creds: CredentialReport | None = None,
) -> AgentGraph:
    """Assemble the graph from whatever stages 1-3 managed to establish."""
    g = AgentGraph()
    g.add_node(Node(AGENT_ID, "agent", "the AI agent"))

    # Keyed on logical_identity, not name. Two projects each declaring a
    # server called "issues" is ordinary, and keying on the name made every
    # colliding spec resolve to whichever probe happened to survive the dict
    # build — so an *unprobed* endpoint inherited a probed one's surface and
    # contributed no `<unknown>` edge at all. That is a silent
    # under-approximation, the one direction this tool must not err in.
    probe_by_id = {p.server.logical_identity: p for p in probes}

    for spec in servers:
        node = _server_node(spec)
        g.add_node(node)
        probe = probe_by_id.get(spec.logical_identity)
        mode, reason = classify_server(spec, probe)
        g.delegation[spec.name] = (mode, reason)

        if probe is not None and probe.recovered and probe.tools:
            for tool in probe.tools:
                g.add_edge(Edge(
                    src=AGENT_ID, dst=node.id,
                    operation=tool.name,
                    capability="write" if tool.write_capable else "read",
                    evidence=f"tool {tool.name!r} exposed by {spec.name}",
                    origin=spec.origin,
                    inferred=tool.read_only is None and tool.destructive is None,
                ))
        else:
            # Sound over-approximation: an unprobed surface is unbounded.
            why = probe.status if probe is not None else "not probed"
            g.add_edge(Edge(
                src=AGENT_ID, dst=node.id,
                operation="<unknown>",
                capability="write",
                evidence=f"surface of {spec.name} unknown ({why}); assumed unbounded",
                origin=spec.origin,
                inferred=True,
            ))
            g.notes.append(
                f"{spec.name}: tool surface unknown ({why}) — counted as write-capable")

    if creds is None:
        return g

    # Map credential -> the server that carries it, so the grant attaches to
    # the right hop rather than hanging off the agent directly.
    for res in creds.resolutions:
        server_id = f"mcp:{res.ref.server_name}" if res.ref.server_name else None
        if server_id is None or server_id not in g.nodes:
            continue
        mode, mode_reason = g.delegation.get(res.ref.server_name, ("unknown", ""))
        # A server presenting its own static secret confers that authority on
        # anyone who can call it — the hop needs no delegation. One that
        # demands a caller token only works under a delegation.
        edge_modes = BOTH_MODES if is_confused_deputy(mode) else DELEGATED_ONLY

        if res.is_inert:
            g.notes.append(
                f"{res.ref.ident}: issuer rejected this credential — no edge added")
            continue

        if res.status not in ("resolved",):
            # Unresolved credential of unknown authority: sound default is a
            # write edge to an unnamed principal for that provider.
            provider = res.classification.provider
            pid = f"principal:{provider}:<unresolved>"
            g.add_node(Node(pid, "principal", f"{provider} (authority unknown)"))
            g.add_edge(Edge(
                src=server_id, dst=pid, operation="<unresolved>", capability="write",
                evidence=f"{res.ref.ident} carries {provider} authority of unknown "
                         f"scope ({res.status}); {mode_reason}",
                origin=res.ref.origin, inferred=True, modes=edge_modes))
            continue

        pnode = _principal_node(res)
        g.add_node(pnode)

        if not res.scopes:
            g.add_edge(Edge(
                src=server_id, dst=pnode.id, operation="*", capability="write",
                evidence=f"{res.ref.ident} is live as {pnode.label}; issuer exposes "
                         f"no scope list, so reach is unbounded",
                origin=res.ref.origin, inferred=True, modes=edge_modes))
            continue

        for scope in res.scopes:
            g.add_edge(Edge(
                src=server_id, dst=pnode.id, operation=scope,
                capability=scope_capability(scope),
                evidence=f"{res.ref.ident} grants scope {scope!r} as {pnode.label}",
                origin=res.ref.origin, modes=edge_modes,
            ))

    return g
