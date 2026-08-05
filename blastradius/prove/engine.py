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
from .encode import CAPABILITY_PORT, Encoding, decode_edge, encode
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

    @property
    def violates(self) -> bool:
        return self.reachable

    def to_json(self) -> dict[str, Any]:
        return {
            "rule": self.rule_name, "src": self.src, "dst": self.dst,
            "capability": self.capability, "reachable": self.reachable,
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


def _build_query(encoding: Encoding, src: str, dst: str, capability: str) -> Any:
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
        "dst_port": CAPABILITY_PORT[capability],
    }
    if any(f.name == "state" for f in dataclasses.fields(Query)):
        # v1 reasons about direct invocation only; delegation state is stage 5.
        kwargs["state"] = "NEW"
    return Query(**kwargs)


def _ask(encoding: Encoding, src: str, dst: str, capability: str) -> Any:
    from segval.engine.evaluator import reach_multi_hop

    return reach_multi_hop(encoding.network, _build_query(encoding, src, dst, capability))


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
            report.diagnostics.append(Diagnostic(
                "info", "prove.rule_matched_nothing",
                f"{rule.name!r}: no node matched "
                f"{'from' if not sources else 'to'} pattern"))
            continue

        for src in sources:
            for dst in targets:
                if src == dst:
                    continue
                for capability in rule.capabilities():
                    decision = _ask(encoding, src, dst, capability)
                    reachable = bool(getattr(decision, "allowed", False))
                    report.verdicts.append(Verdict(
                        rule_name=rule.name,
                        src=src, dst=dst, capability=capability,
                        reachable=reachable,
                        witness=_witness_from_decision(decision, encoding)
                        if reachable else (),
                        note="" if reachable else
                             "no path admits this capability under the discovered grants",
                    ))

    for v in report.violations:
        inferred = [h for h in v.witness if h.inferred]
        report.diagnostics.append(Diagnostic(
            "error", "prove.policy_violation",
            f"{v.rule_name!r}: {v.src} can {v.capability} {v.dst} "
            f"in {len(v.witness)} hop(s)"
            + (f" — {len(inferred)} hop(s) assumed rather than observed"
               if inferred else ""),
        ))

    return report
