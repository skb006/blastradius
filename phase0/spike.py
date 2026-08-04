"""Phase 0 spike — does segval's prover answer agent-reachability questions?

Runs the Kagenti confused-deputy scenario through segval UNMODIFIED and asks:

    "Can agent_d (insurance verification) reach patient records?"

Expected: ACCEPT under the vulnerable policy (the finding), DROP once the grant
is narrowed. Success criterion is not just the verdict — it is whether the
Decision.trace names the offending rule well enough to be a product artifact.
"""
from __future__ import annotations

import sys
from ipaddress import IPv4Address
from pathlib import Path

SEGVAL = Path.home() / "projects" / "segval"
sys.path.insert(0, str(SEGVAL))

from segval.model.schema import TopologySpec  # noqa: E402
from segval.model.loader import load_network  # noqa: E402
from segval.engine.evaluator import reach, reach_multi_hop  # noqa: E402
from segval.engine.query import Query  # noqa: E402

HERE = Path(__file__).parent

# operation encoding under test: dst_port stands in for the invoked operation
OPS = {5432: "read_patient_record", 8443: "verify_insurance"}
ZONE_IP = {
    "agent_a_orchestrator": IPv4Address("10.1.0.10"),
    "agent_d_insurance": IPv4Address("10.4.0.10"),
    "tool_patient_records": IPv4Address("10.90.0.10"),
    "tool_insurance_api": IPv4Address("10.91.0.10"),
}


def build(config_name: str):
    """Load the topology, swapping in the named policy config."""
    spec_text = (HERE / "agent_topology.yaml").read_text()
    spec_text = spec_text.replace("configs/authz_vulnerable.iptables-save",
                                  f"configs/{config_name}")
    tmp = HERE / "_topology_active.yaml"
    tmp.write_text(spec_text)
    try:
        return load_network(tmp)
    finally:
        tmp.unlink(missing_ok=True)


def ask(network, src: str, dst: str, op_port: int, multi_hop: bool = False):
    q = Query(
        src_zone=src, src_ip=ZONE_IP[src],
        dst_zone=dst, dst_ip=ZONE_IP[dst],
        proto="tcp", dst_port=op_port, state="NEW",
    )
    fn = reach_multi_hop if multi_hop else reach
    return q, fn(network, q)


def render(label: str, src: str, dst: str, port: int, decision) -> None:
    verdict = "REACHABLE" if decision.allowed else "proven unreachable"
    mark = "!!" if decision.allowed else "ok"
    print(f"  [{mark}] {label}")
    print(f"       {src} --{OPS[port]}--> {dst}: {verdict}")
    if decision.matched_rule:
        r = decision.matched_rule
        print(f"       granted by: {r.raw.strip()}")
        print(f"       source    : {r.source_file}:{r.line_number}")
    elif decision.default_used:
        print("       no grant matched -> default policy denied")


def main() -> int:
    print("=" * 72)
    print("PHASE 0 SPIKE — agent blast radius on segval's unmodified prover")
    print("=" * 72)

    failures = []

    print("\n[A] VULNERABLE POLICY (bearer token honoured for any agent)\n")
    net = build("authz_vulnerable.iptables-save")
    _, d1 = ask(net, "agent_d_insurance", "tool_patient_records", 5432)
    render("confused deputy", "agent_d_insurance", "tool_patient_records", 5432, d1)
    if not d1.allowed:
        failures.append("expected the vulnerable policy to expose patient records")

    _, d2 = ask(net, "agent_d_insurance", "tool_insurance_api", 8443)
    render("legitimate grant", "agent_d_insurance", "tool_insurance_api", 8443, d2)
    if not d2.allowed:
        failures.append("legitimate insurance call should be permitted")

    print("\n[B] FIXED POLICY (grant narrowed to the orchestrator)\n")
    net_fixed = build("authz_fixed.iptables-save")
    _, d3 = ask(net_fixed, "agent_d_insurance", "tool_patient_records", 5432)
    render("confused deputy", "agent_d_insurance", "tool_patient_records", 5432, d3)
    if d3.allowed:
        failures.append("fixed policy still exposes patient records")

    _, d4 = ask(net_fixed, "agent_d_insurance", "tool_insurance_api", 8443)
    render("legitimate grant", "agent_d_insurance", "tool_insurance_api", 8443, d4)
    if not d4.allowed:
        failures.append("fix broke the legitimate insurance call")

    print("\n[C] IS THE TRACE PRODUCT-GRADE?\n")
    print(f"       trace entries examined : {len(d1.trace)}")
    print(f"       names offending rule   : {d1.matched_rule is not None}")
    print(f"       carries file:line       : "
          f"{bool(d1.matched_rule and d1.matched_rule.source_file)}")
    print(f"       reproducibility hash    : "
          f"{'yes' if d1.checkpoint else 'NOT POPULATED (formatter opt-in)'}")

    print("\n" + "=" * 72)
    if failures:
        print("SPIKE FAILED")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("SPIKE PASSED — the network prover answered every agent query")
    print("               unmodified, and named the offending grant.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
