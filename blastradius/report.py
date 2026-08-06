"""Rendering. Two audiences, one set of facts.

Text output is for a human reading a terminal. JSON output is for CI, and is
deterministic — sorted keys, no timings — so two runs against an unchanged
deployment diff to nothing. Timing data is deliberately excluded from the CI
shape; a report that changes every run cannot gate a pipeline.
"""

from __future__ import annotations

import json
from typing import Iterable, Sequence

from .creds.model import CredentialReport
from .model import Diagnostic, Inventory, ProbeResult
from .probe import coverage

_SEVERITY_ORDER = {"error": 0, "warn": 1, "info": 2}
_MARK = {"error": "!!", "warn": " !", "info": "  "}

_STATUS_NOTE = {
    "ok": "surface recovered",
    "skipped": "not probed (stdio, needs --allow-spawn)",
    "runtime_missing": "declared but inert — runtime absent",
    "unreachable": "nothing listening",
    "timeout": "no response in time",
    "protocol_error": "spoke, but not usable MCP",
    "auth_required": "gated — surface exists, scope unknown",
}


def _sorted_diags(diags: Iterable[Diagnostic]) -> list[Diagnostic]:
    return sorted(
        diags,
        key=lambda d: (_SEVERITY_ORDER.get(d.severity, 9), d.code, str(d.origin or "")),
    )


_CONTROL = {c: f"\\x{c:02x}" for c in range(32)} | {127: "\\x7f"}
del _CONTROL[9]  # tab is harmless and preserves alignment


def _join(lines: list[str]) -> str:
    """Join rendered lines, neutering control characters inside each one.

    Sanitising per line rather than per interpolation is what makes this
    reliable: every renderer funnels through here, so a future line that
    forgets to wrap a config-controlled value is still covered. The newlines
    between lines are ours and never pass through `safe`, so an injected
    newline inside a server name shows up escaped instead of forging a row.
    """
    return "\n".join(safe(line) for line in lines)


def safe(text: object) -> str:
    """Neuter config-controlled text before it reaches a terminal.

    Server names, tool names and URLs come from files this tool does not
    control. A name containing ESC[2J clears the operator's screen; one
    containing a carriage return rewrites the line above it. A security
    report that an attacker can partially erase is worse than no report, so
    every control character is escaped into its visible form.
    """
    return str(text).translate(_CONTROL)


def render_inventory(inv: Inventory) -> str:
    out: list[str] = []
    servers = inv.deduped()
    copies = inv.copies()

    out.append("DECLARED MCP SERVERS")
    out.append("=" * 68)
    if not servers:
        out.append("  none found")
    endpoints = inv.endpoints()
    for s in servers:
        n = copies.get(s.logical_identity, 1)
        dupe = f"  ({n} declarations)" if n > 1 else ""
        target = safe(s.url or (f"{s.command} {' '.join(s.args)}".strip() if s.command else "?"))
        out.append(f"  {safe(s.name)}  [{s.transport}]{dupe}")
        out.append(f"      target : {target}")
        group = endpoints.get(s.logical_identity, [])
        distinct = {g.url for g in group if g.url}
        if len(distinct) > 1:
            out.append(f"      note   : {len(distinct)} rotating endpoints seen "
                       f"(session-scoped ports)")
        out.append(f"      origin : {s.origin}")
        out.append(
            f"      scope  : {', '.join(s.declared_authz) if s.declared_authz else 'NONE DECLARED'}"
        )
        if s.credential_keys:
            out.append(f"      creds  : {', '.join(s.credential_keys)}  (values never read)")

    out.append("")
    out.append(f"scanned {len(inv.scanned_paths)} config file(s); "
               f"{len(inv.servers)} declaration(s) -> {len(servers)} unique server(s)")
    return _join(out)


def render_probe(results: Sequence[ProbeResult], *, verbose: bool = False) -> str:
    out: list[str] = []
    out.append("PROBE RESULTS")
    out.append("=" * 68)

    for r in sorted(results, key=lambda r: (r.status != "ok", r.server.name)):
        s = r.server
        note = _STATUS_NOTE.get(r.status, r.status)
        out.append(f"  [{r.status:>15}] {s.name}  ({note})")
        if r.recovered:
            ident = " ".join(x for x in (r.server_name, r.server_version) if x)
            out.append(f"        server   : {ident or '<unidentified>'}"
                       f"   protocol {r.protocol_version}")
            out.append(f"        surface  : {len(r.tools)} tools "
                       f"({len(r.write_tools)} write-capable), "
                       f"{len(r.resources)} resources, {len(r.prompts)} prompts")
            shown = r.tools if verbose else r.tools[:8]
            for t in shown:
                flag = "W" if t.write_capable else "r"
                params = f"({', '.join(t.input_params[:4])})" if t.input_params else "()"
                out.append(f"          [{flag}] {t.name}{params}")
            if not verbose and len(r.tools) > len(shown):
                out.append(f"          ... {len(r.tools) - len(shown)} more (use -v)")

    cov = coverage(results)
    out.append("")
    out.append("COVERAGE")
    out.append("-" * 68)
    out.append(f"  servers declared      : {cov['servers_declared']}")
    out.append(f"  surfaces recovered    : {cov['servers_recovered']} "
               f"({cov['recovery_rate']:.0%})")
    out.append(f"  tools discovered      : {cov['tools_discovered']}")
    out.append(f"  write-capable tools   : {cov['write_capable_tools']}")
    out.append(f"  resources discovered  : {cov['resources_discovered']}")
    return _join(out)


def render_diagnostics(diags: Iterable[Diagnostic]) -> str:
    diags = _sorted_diags(diags)
    if not diags:
        return "DIAGNOSTICS\n" + "=" * 68 + "\n  none"
    out = ["DIAGNOSTICS", "=" * 68]
    for d in diags:
        out.append(f"  {_MARK.get(d.severity, '  ')} {d.code}: {d.message}")
        if d.origin:
            out.append(f"       at {d.origin}")
    counts: dict[str, int] = {}
    for d in diags:
        counts[d.severity] = counts.get(d.severity, 0) + 1
    out.append("")
    out.append("  " + ", ".join(f"{v} {k}" for k, v in sorted(counts.items())))
    return _join(out)


def to_json(
    inv: Inventory,
    results: Sequence[ProbeResult],
    creds: CredentialReport | None = None,
    *,
    indent: int | None = 2,
) -> str:
    """Deterministic machine output.

    ``duration_ms`` is stripped: it is real information, but it makes every
    run differ, and this document is meant to be committed and diffed.
    """
    payload = {
        "schema": "blastradius/probe/v1",
        "inventory": inv.to_json(),
        "probes": [
            {k: v for k, v in r.to_json().items() if k != "duration_ms"}
            for r in sorted(results, key=lambda r: r.server.identity)
        ],
        "coverage": coverage(results),
        "credentials": creds.to_json() if creds else None,
    }
    return json.dumps(payload, indent=indent, sort_keys=True)


_CRED_NOTE = {
    "resolved": "live",
    "invalid": "REJECTED by issuer — grant is inert",
    "expired": "expired — grant is inert",
    "unsupported": "issuer exposes no introspection",
    "no_value": "reference does not dereference here",
    "network_error": "could not reach issuer",
    "skipped": "not resolved (classify-only)",
}


def render_credentials(report: CredentialReport) -> str:
    """Credential authority — the answer to 'whose permissions does this inherit?'"""
    out = ["CREDENTIAL AUTHORITY", "=" * 68]
    if not report.resolutions:
        out.append("  no credentials declared")
        return _join(out)

    for r in sorted(report.resolutions, key=lambda r: r.ref.ident):
        c = r.classification
        kind = (f"{c.provider}/{c.credential_class}"
                if c.provider != "unknown" else "unidentified")
        mark = "!!" if r.status == "resolved" and r.scopes else (
            " !" if r.is_inert else "  ")
        out.append(f"  [{mark}] {r.ref.ident}")
        out.append(f"        kind     : {kind}  ({c.confidence}, via {c.matched_on})")
        out.append(f"        status   : {r.status} — {_CRED_NOTE.get(r.status, '')}")
        if r.principal:
            acct = f"  in {r.account}" if r.account else ""
            out.append(f"        acts as  : {r.principal}{acct}")
        if r.scopes:
            out.append(f"        scopes   : {', '.join(r.scopes)}")
        if r.expires_at:
            out.append(f"        expires  : {r.expires_at}")
        if r.ref.indirection:
            out.append(f"        inherits : {r.ref.indirection} from the launch environment")

    s = report.to_json()["summary"]
    out.append("")
    out.append(f"  {s['credentials_found']} credential(s): "
               f"{s['resolved']} resolved, {s['inert']} inert")
    return _join(out)


def render_graph(graph) -> str:
    """The assembled agent graph, for eyeballing before trusting a proof."""
    out = ["AGENT GRAPH", "=" * 68]
    for node in sorted(graph.nodes.values(), key=lambda n: (n.kind, n.id)):
        out.append(f"  [{node.kind:>9}] {node.id}")
    out.append("")
    for e in sorted(graph.edges, key=lambda e: (e.src, e.dst, e.operation)):
        flag = "W" if e.is_write else "r"
        tag = " (assumed)" if e.inferred else ""
        out.append(f"  [{flag}] {e.src} --[{e.operation}]--> {e.dst}{tag}")
    if graph.delegation:
        out.append("")
        out.append("  delegation posture:")
        for name, (mode, reason) in sorted(graph.delegation.items()):
            flag = "!!" if mode == "own_credential" else (
                "ok" if mode == "caller_token" else " ?")
            out.append(f"    [{flag}] {name}: {mode}")
            out.append(f"         {reason}")
    for note in graph.notes:
        out.append(f"  note: {note}")
    return _join(out)


def render_proof(report) -> str:
    """Violations with witnesses, and proofs of absence stated explicitly.

    Absence gets its own section on purpose. A tool that only ever prints
    findings teaches its users that silence means "not checked" — and the
    proof that something is unreachable is the artifact an auditor wants.
    """
    out = ["BLAST RADIUS", "=" * 68]

    if not report.verdicts:
        out.append("  nothing to prove — no grants discovered")
        return _join(out)

    deputies = [v for v in report.violations if v.confused_deputy]
    delegated = [v for v in report.violations if not v.confused_deputy]

    if deputies:
        out.append("")
        out.append("  CONFUSED DEPUTY — authority spent that nobody delegated")
        for v in deputies:
            out.append(f"    [!!] {v.src} can {v.capability.upper()} {v.dst} "
                       f"with NO delegation")
            out.append(f"         rule: {v.rule_name}")
            for i, hop in enumerate(v.witness, 1):
                tag = "  (assumed, not observed)" if hop.inferred else ""
                out.append(f"         {i}. {hop.src} --[{hop.operation}]--> "
                           f"{hop.dst}{tag}")
                out.append(f"            {hop.evidence}")
                if hop.origin:
                    out.append(f"            declared at {hop.origin}")

    if delegated:
        out.append("")
        out.append("  DELEGATED REACH — bounded by the caller's own rights")
        for v in delegated:
            out.append(f"    [ !] {v.src} can {v.capability.upper()} {v.dst} "
                       f"only under a delegation")
            out.append(f"         rule: {v.rule_name}")
            for i, hop in enumerate(v.witness, 1):
                out.append(f"         {i}. {hop.src} --[{hop.operation}]--> {hop.dst}")

    if report.proofs_of_absence:
        out.append("")
        out.append("  PROVEN UNREACHABLE")
        for v in report.proofs_of_absence:
            out.append(f"    [ok] {v.src} cannot {v.capability.upper()} {v.dst}")

    s = report.to_json()["summary"]
    out.append("")
    out.append(f"  {s['questions_asked']} question(s): "
               f"{len(deputies)} confused deputy, {len(delegated)} delegated, "
               f"{s['proven_unreachable']} proven unreachable")
    if report.graph_notes:
        out.append("")
        out.append("  graph assumptions:")
        for n in report.graph_notes:
            out.append(f"    - {n}")
    return _join(out)
