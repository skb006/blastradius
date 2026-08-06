"""Discharge a policy against the agent graph.

For each denial, and each (source, destination) pair it matches, ask segval
whether a path exists. Two outcomes, both worth having:

* **violation** — a witness path, hop by hop, naming the tool and the scope
  that make it possible, each traced to the file it was declared in.
* **proof of absence** — no path exists under the encoded policy. This is the
  artifact that is genuinely hard to obtain any other way, and it is the one
  an auditor wants.

Absence is reported as explicitly as violation. A tool that only ever prints
findings teaches its users that silence means "not checked".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Sequence

from ..model import Diagnostic
from .encode import PORT, Encoding, decode_edge, encode
from .graph import AgentGraph, Edge
from .policy import DenyRule, Policy


@dataclass(frozen=True, slots=True)
class Hop:
    src: str
    dst: str
    operation: str
    capability: str
    evidence: str
    origin: str | None
    inferred: bool

    def to_json(self) -> dict[str, Any]:
        return {
            "src": self.src, "dst": self.dst, "operation": self.operation,
            "capability": self.capability, "evidence": self.evidence,
            "origin": self.origin, "inferred": self.inferred,
        }


@dataclass(frozen=True, slots=True)
class Verdict:
    """One (rule, src, dst, capability) question and its answer."""

    rule_name: str
    src: str
    dst: str
    capability: str
    reachable: bool
    witness: tuple[Hop, ...] = ()
    note: str = ""
    #: "direct" means the path needs no delegation at any hop — the caller
    #: spends authority nobody granted it. That is the confused deputy.
    mode: str = "direct"

    @property
    def confused_deputy(self) -> bool:
        return self.reachable and self.mode == "direct"

    @property
    def violates(self) -> bool:
        return self.reachable

    def to_json(self) -> dict[str, Any]:
        return {
            "rule": self.rule_name, "src": self.src, "dst": self.dst,
            "capability": self.capability, "reachable": self.reachable,
            "mode": self.mode, "confused_deputy": self.confused_deputy,
            "violates": self.violates,
            "witness": [h.to_json() for h in self.witness],
            "note": self.note,
        }


@dataclass
class ProofReport:
    verdicts: list[Verdict] = field(default_factory=list)
    diagnostics: list[Diagnostic] = field(default_factory=list)
    graph_notes: list[str] = field(default_factory=list)

    @property
    def violations(self) -> list[Verdict]:
        return [v for v in self.verdicts if v.violates]

    @property
    def proofs_of_absence(self) -> list[Verdict]:
        return [v for v in self.verdicts if not v.violates]

    def to_json(self) -> dict[str, Any]:
        return {
            "verdicts": [v.to_json() for v in self.verdicts],
            "summary": {
                "questions_asked": len(self.verdicts),
                "violations": len(self.violations),
                "proven_unreachable": len(self.proofs_of_absence),
            },
            "graph_notes": list(self.graph_notes),
            "diagnostics": [d.to_json() for d in self.diagnostics],
        }


def _witness_from_decision(decision: Any, encoding: Encoding) -> tuple[Hop, ...]:
    """Turn segval's rule trace back into agent-level hops."""
    hops: list[Hop] = []
    seen: set[tuple[str, str, str]] = set()
    for entry in getattr(decision, "trace", []) or []:
        rule = getattr(entry, "rule", None)
        if rule is None or not getattr(entry, "matched", False):
            continue
        edge = decode_edge(getattr(rule, "raw", ""), encoding)
        if edge is None:
            continue
        key = (edge.src, edge.dst, edge.operation)
        if key in seen:
            continue
        seen.add(key)
        hops.append(Hop(
            src=edge.src, dst=edge.dst, operation=edge.operation,
            capability=edge.capability, evidence=edge.evidence,
            origin=str(edge.origin) if edge.origin else None,
            inferred=edge.inferred,
        ))
    return tuple(hops)


def _build_query(encoding: Encoding, src: str, dst: str, capability: str,
                 mode: str = "direct") -> Any:
    """Construct a segval Query, tolerating the branch divergence in its shape.

    ``Query.state`` exists on some segval revisions and not others (the two
    Step-5 implementations diverged on the public type, not just internals).
    Introspect rather than pin, so the prover works against either.
    """
    import dataclasses

    from segval.engine.query import Query

    kwargs: dict[str, Any] = {
        "src_zone": encoding.zone(src),
        "src_ip": encoding.address(src),
        "dst_zone": encoding.zone(dst),
        "dst_ip": encoding.address(dst),
        "proto": "tcp",
        "dst_port": PORT[(capability, mode)],
    }
    if any(f.name == "state" for f in dataclasses.fields(Query)):
        # v1 reasons about direct invocation only; delegation state is stage 5.
        kwargs["state"] = "NEW"
    return Query(**kwargs)


def _ask(encoding: Encoding, src: str, dst: str, capability: str,
         mode: str = "direct") -> Any:
    from segval.engine.evaluator import reach_multi_hop

    return reach_multi_hop(
        encoding.network, _build_query(encoding, src, dst, capability, mode))


def prove(graph: AgentGraph, policy: Policy) -> ProofReport:
    """Discharge every denial in ``policy`` against ``graph``."""
    report = ProofReport(graph_notes=list(graph.notes))

    if not graph.edges:
        report.diagnostics.append(Diagnostic(
            "info", "prove.empty_graph",
            "no grants discovered — nothing to prove. Run `probe --sweep "
            "--resolve-credentials` first."))
        return report

    encoding = encode(graph)
    node_ids = sorted(graph.nodes)

    for rule in policy.rules:
        sources = [n for n in node_ids if rule.matches_src(n)]
        targets = [n for n in node_ids if rule.matches_dst(n)]
        if not sources or not targets:
            which = "from" if not sources else "to"
            pat = rule.from_pattern if not sources else rule.to_pattern
            # Be explicit that this is NOT a proof of absence. A deny-rule whose
            # target principal was never discovered is vacuously satisfied —
            # there is nothing of that kind to reach — which is a weaker fact
            # than "this discovered principal is provably unreachable". Users
            # read PROVEN UNREACHABLE as a safety guarantee; this is not one, so
            # it must not be dressed up as one.
            report.diagnostics.append(Diagnostic(
                "info", "prove.rule_matched_nothing",
                f"{rule.name!r}: no discovered node matched the {which} pattern "
                f"{pat!r}. The rule is vacuously satisfied (nothing of that kind "
                f"is in the inventory) — this is NOT a proof that such a "
                f"principal is unreachable, only that none was found to reach."))
            continue

        for src in sources:
            for dst in targets:
                if src == dst:
                    continue
                for capability in rule.capabilities():
                    report.verdicts.append(
                        _answer(encoding, rule, src, dst, capability))

    for v in report.violations:
        inferred = [h for h in v.witness if h.inferred]
        suffix = (f" — {len(inferred)} hop(s) assumed rather than observed"
                  if inferred else "")
        if v.confused_deputy:
            report.diagnostics.append(Diagnostic(
                "error", "prove.confused_deputy",
                f"{v.rule_name!r}: {v.src} can {v.capability} {v.dst} in "
                f"{len(v.witness)} hop(s) WITHOUT any delegation — the authority "
                f"belongs to the server, so every caller inherits it" + suffix,
            ))
        else:
            report.diagnostics.append(Diagnostic(
                "warn", "prove.delegated_reach",
                f"{v.rule_name!r}: {v.src} can {v.capability} {v.dst}, but only "
                f"under a delegation — authority stays bounded by the caller"
                + suffix,
            ))

    _summarise_delegation(graph, report)
    return report


def _answer(
    encoding: Encoding, rule: DenyRule, src: str, dst: str, capability: str
) -> Verdict:
    """Ask direct first, then delegated, and report the strongest mode.

    Direct is asked first because it is the stronger claim: a hop that needs
    no delegation is reachable by *anyone* who can call the server. An edge
    that admits direct also admits delegated, so asking both and reporting
    both would just be the same finding twice.
    """
    modes = ("direct",) if rule.delegation == "direct" else ("direct", "delegated")

    for mode in modes:
        decision = _ask(encoding, src, dst, capability, mode)
        if bool(getattr(decision, "allowed", False)):
            return Verdict(
                rule_name=rule.name, src=src, dst=dst, capability=capability,
                reachable=True, mode=mode,
                witness=_witness_from_decision(decision, encoding),
            )

    unreached = ("no path admits this capability without a delegation"
                 if rule.delegation == "direct" else
                 "no path admits this capability under the discovered grants")
    return Verdict(
        rule_name=rule.name, src=src, dst=dst, capability=capability,
        reachable=False, mode=modes[-1], note=unreached,
    )


def _summarise_delegation(graph: AgentGraph, report: ProofReport) -> None:
    """State the deployment-wide delegation posture.

    When no server anywhere derives its authority from the caller, that is a
    single fact worth saying once rather than repeating per finding: the
    deployment has no delegation boundary at all.
    """
    if not graph.delegation:
        return
    modes = {name: mode for name, (mode, _) in graph.delegation.items()}
    delegating = [n for n, m in modes.items() if m == "caller_token"]
    if not delegating:
        report.diagnostics.append(Diagnostic(
            "error", "prove.no_delegation_boundary",
            f"none of the {len(modes)} server(s) derives authority from the "
            f"caller — every one presents its own credential, so there is no "
            f"delegation boundary anywhere in this deployment",
        ))
    else:
        report.diagnostics.append(Diagnostic(
            "info", "prove.delegation_boundary",
            f"{len(delegating)}/{len(modes)} server(s) require a per-caller "
            f"token: {', '.join(sorted(delegating))}",
        ))
