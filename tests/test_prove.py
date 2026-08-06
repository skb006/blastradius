"""Stage 4: reachability proofs over the agent graph.

The load-bearing tests here are the *negative* ones. An earlier encoding
reported a violation for every graph because the tool hop was silently
ignored — a prover that always says yes is worse than no prover, since it
looks like it is working. ``test_read_only_tools_cannot_reach_write`` is the
regression that catches it.
"""

from __future__ import annotations

import json

import pytest

from blastradius.creds.model import (
    Classification,
    CredentialRef,
    CredentialReport,
    Resolution,
)
from blastradius.model import Origin, ProbeResult, ServerSpec, ToolSpec
from blastradius.prove.engine import prove
from blastradius.prove.graph import AGENT_ID, build_graph
from blastradius.prove.policy import (
    DenyRule,
    Policy,
    PolicyError,
    default_policy,
    parse_policy,
)

segval = pytest.importorskip("segval", reason="stage 4 is an optional extra")

ORIGIN = Origin("/cfg/.mcp.json", "mcpServers.github")


def server(name="github", **kw) -> ServerSpec:
    return ServerSpec(name=name, transport="stdio", origin=ORIGIN, command="npx", **kw)


def probe(spec, *tools, status="ok") -> ProbeResult:
    return ProbeResult(server=spec, status=status, tools=tuple(tools))


def creds(*, scopes=("repo",), status="resolved", principal="github:octocat",
          server_name="github") -> CredentialReport:
    return CredentialReport(resolutions=[Resolution(
        ref=CredentialRef("GITHUB_TOKEN", ORIGIN, "config_env", server_name=server_name),
        classification=Classification("github", "classic_pat", "exact"),
        status=status, principal=principal, scopes=scopes)])


WRITE_TOOL = ToolSpec("create_issue", read_only=False, destructive=True)
READ_TOOL = ToolSpec("search_issues", read_only=True, destructive=False)


def write_policy() -> Policy:
    return Policy(rules=[DenyRule(
        "no agent writes", AGENT_ID, "principal:*", "write")])


# --- the headline case ------------------------------------------------------

def test_write_path_is_found_with_a_two_hop_witness():
    s = server()
    g = build_graph([s], [probe(s, READ_TOOL, WRITE_TOOL)], creds())
    report = prove(g, write_policy())

    assert len(report.violations) == 1
    v = report.violations[0]
    assert v.src == AGENT_ID and v.dst == "principal:github:octocat"
    assert [(h.src, h.operation, h.dst) for h in v.witness] == [
        (AGENT_ID, "create_issue", "mcp:github"),
        ("mcp:github", "repo", "principal:github:octocat"),
    ]


def test_witness_carries_evidence_and_origin():
    s = server()
    g = build_graph([s], [probe(s, WRITE_TOOL)], creds())
    v = prove(g, write_policy()).violations[0]
    assert "create_issue" in v.witness[0].evidence
    assert v.witness[0].origin == str(ORIGIN)
    assert "grants scope 'repo'" in v.witness[1].evidence


# --- negatives: each hop must actually gate the path ------------------------

def test_read_only_tools_cannot_reach_write():
    """REGRESSION: an earlier encoding ignored the tool hop entirely.

    The server holds a write-scoped credential, but the agent has no
    write-capable tool, so no write path exists.
    """
    s = server()
    g = build_graph([s], [probe(s, READ_TOOL)], creds(scopes=("repo",)))
    report = prove(g, write_policy())
    assert report.violations == []
    assert len(report.proofs_of_absence) == 1


def test_read_only_scope_cannot_be_written_through():
    """The mirror case: a write tool over a read-only credential."""
    s = server()
    g = build_graph([s], [probe(s, WRITE_TOOL)], creds(scopes=("read:org",)))
    assert prove(g, write_policy()).violations == []


def test_read_capability_is_still_reachable_when_write_is_not():
    s = server()
    g = build_graph([s], [probe(s, READ_TOOL)], creds(scopes=("read:org",)))
    read_policy = Policy(rules=[DenyRule("no reads", AGENT_ID, "principal:*", "read")])
    assert len(prove(g, read_policy).violations) == 1


# --- stage 3 prunes the graph ----------------------------------------------

def test_inert_credential_removes_the_path():
    """An issuer-rejected credential grants nothing, so no principal exists."""
    s = server()
    g = build_graph([s], [probe(s, WRITE_TOOL)], creds(status="invalid"))
    assert not g.principals()
    assert any("no edge added" in n for n in g.notes)
    assert prove(g, write_policy()).violations == []


def test_unresolved_credential_is_treated_as_unbounded():
    s = server()
    g = build_graph([s], [probe(s, WRITE_TOOL)],
                    creds(status="network_error", principal=None))
    v = prove(g, write_policy()).violations
    assert len(v) == 1
    # The placeholder principal is scoped to the server, so two unresolved
    # credentials stay distinct deputies rather than collapsing into one.
    assert v[0].dst == "principal:github:<unresolved@github>"


def test_live_credential_without_scopes_is_unbounded():
    s = server()
    g = build_graph([s], [probe(s, WRITE_TOOL)], creds(scopes=()))
    v = prove(g, write_policy()).violations
    assert len(v) == 1
    assert any("unbounded" in h.evidence for h in v[0].witness)


# --- soundness of unknowns ---------------------------------------------------

@pytest.mark.parametrize("status", ["auth_required", "runtime_missing", "skipped",
                                    "unreachable", "timeout"])
def test_unprobed_server_is_assumed_write_capable(status):
    s = server()
    g = build_graph([s], [probe(s, status=status)], creds())
    v = prove(g, write_policy()).violations
    assert len(v) == 1, "an unknown surface must not look safe"
    assert v[0].witness[0].operation == "<unknown>"
    assert v[0].witness[0].inferred is True


def test_unannotated_tool_is_marked_inferred():
    s = server()
    g = build_graph([s], [probe(s, ToolSpec("mystery"))], creds())
    v = prove(g, write_policy()).violations[0]
    assert v.witness[0].inferred is True


def test_violation_diagnostic_flags_inferred_hops():
    s = server()
    g = build_graph([s], [probe(s, status="auth_required")], creds())
    report = prove(g, write_policy())
    d = next(d for d in report.diagnostics
             if d.code in ("prove.confused_deputy", "prove.delegated_reach"))
    assert "assumed rather than observed" in d.message


# --- proofs of absence are first-class --------------------------------------

def test_proof_of_absence_is_reported_explicitly():
    s = server()
    g = build_graph([s], [probe(s, READ_TOOL)], creds(scopes=("read:org",)))
    report = prove(g, write_policy())
    assert len(report.proofs_of_absence) == 1
    assert "no path admits this capability" in report.proofs_of_absence[0].note
    assert report.to_json()["summary"]["proven_unreachable"] == 1


def test_empty_graph_reports_nothing_to_prove():
    report = prove(build_graph([], [], None), write_policy())
    assert report.verdicts == []
    assert any(d.code == "prove.empty_graph" for d in report.diagnostics)


def test_rule_matching_nothing_is_reported():
    s = server()
    g = build_graph([s], [probe(s, WRITE_TOOL)], creds())
    p = Policy(rules=[DenyRule("nope", "agent", "principal:gitlab:*", "write")])
    report = prove(g, p)
    assert report.verdicts == []
    assert any(d.code == "prove.rule_matched_nothing" for d in report.diagnostics)


# --- multiple servers --------------------------------------------------------

def test_paths_are_attributed_to_the_right_server():
    a, b = server("alpha"), server("beta")
    report_creds = CredentialReport(resolutions=[
        Resolution(ref=CredentialRef("T", ORIGIN, "config_env", server_name="beta"),
                   classification=Classification("github", "classic_pat", "exact"),
                   status="resolved", principal="github:betauser", scopes=("repo",))])
    g = build_graph([a, b], [probe(a, READ_TOOL), probe(b, WRITE_TOOL)], report_creds)
    v = prove(g, write_policy()).violations
    assert len(v) == 1
    assert [h.src for h in v[0].witness] == [AGENT_ID, "mcp:beta"]


def test_no_cross_server_credential_leak():
    """alpha's write tool must not reach beta's principal."""
    a, b = server("alpha"), server("beta")
    c = CredentialReport(resolutions=[
        Resolution(ref=CredentialRef("T", ORIGIN, "config_env", server_name="beta"),
                   classification=Classification("github", "classic_pat", "exact"),
                   status="resolved", principal="github:betauser", scopes=("repo",))])
    g = build_graph([a, b], [probe(a, WRITE_TOOL), probe(b, READ_TOOL)], c)
    assert prove(g, write_policy()).violations == []


# --- policy parsing -----------------------------------------------------------

def test_parse_minimal_policy():
    p = parse_policy({"version": 1, "rules": [
        {"name": "r", "deny": {"from": "agent", "to": "principal:*",
                               "capability": "write"}}]})
    assert p.rules[0].name == "r"
    assert p.rules[0].capabilities() == ("write",)


def test_capability_any_expands_to_both():
    p = parse_policy({"version": 1, "rules": [
        {"deny": {"from": "a", "to": "b"}}]})
    assert p.rules[0].capabilities() == ("read", "write")


@pytest.mark.parametrize("doc,needle", [
    ([], "must be a mapping"),
    ({"version": 2, "rules": [{}]}, "unsupported policy version"),
    ({"version": 1}, "non-empty list"),
    ({"version": 1, "rules": []}, "non-empty list"),
    ({"version": 1, "rules": ["x"]}, "must be a mapping"),
    ({"version": 1, "rules": [{}]}, "'deny' mapping"),
    ({"version": 1, "rules": [{"deny": {"from": "a", "to": "b",
                                        "capability": "delete"}}]}, "read|write|any"),
    ({"version": 1, "rules": [{"deny": {"from": 1, "to": "b"}}]}, "string 'from' and 'to'"),
])
def test_policy_errors(doc, needle):
    with pytest.raises(PolicyError, match=needle):
        parse_policy(doc)


def test_glob_matching():
    r = DenyRule("r", "agent*", "principal:github:*", "write")
    assert r.matches_src("agent")
    assert r.matches_dst("principal:github:octocat")
    assert not r.matches_dst("principal:slack:bot")


def test_default_policy_denies_all_agent_writes():
    p = default_policy()
    assert p.rules[0].capabilities() == ("write",)
    assert p.rules[0].matches_dst("principal:anything")


# --- serialisation ------------------------------------------------------------

def test_report_json_is_serialisable_and_complete():
    s = server()
    g = build_graph([s], [probe(s, WRITE_TOOL)], creds())
    blob = json.dumps(prove(g, write_policy()).to_json())
    doc = json.loads(blob)
    assert doc["summary"]["violations"] == 1
    assert doc["verdicts"][0]["witness"][0]["operation"] == "create_issue"


def test_graph_json_round_trips():
    s = server()
    g = build_graph([s], [probe(s, WRITE_TOOL)], creds())
    doc = json.loads(json.dumps(g.to_json()))
    assert {n["id"] for n in doc["nodes"]} == {
        "agent", "mcp:github", "principal:github:octocat"}
