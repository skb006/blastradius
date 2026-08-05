"""Stage 5: delegation — *on whose authority* does each hop act?

Stage 4 proves the agent can reach a principal. This proves whether it does
so by spending authority someone delegated to it, or authority that simply
sits on the server and is therefore available to any caller.
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
from blastradius.prove.delegation import classify_server, is_confused_deputy, summarise
from blastradius.prove.engine import prove
from blastradius.prove.graph import AGENT_ID, build_graph
from blastradius.prove.policy import DenyRule, Policy, parse_policy, PolicyError

pytest.importorskip("segval", reason="stage 4/5 is an optional extra")

ORIGIN = Origin("/cfg/.mcp.json", "mcpServers.svc")
WRITE_TOOL = ToolSpec("create_issue", read_only=False, destructive=True)

OAUTH_CHALLENGE = (
    'Bearer resource_metadata="https://api.example.com/.well-known/'
    'oauth-protected-resource"')


def spec(name="svc", creds=("GITHUB_TOKEN",)) -> ServerSpec:
    return ServerSpec(name=name, transport="http", origin=ORIGIN,
                      url="https://api.example.com/mcp",
                      env_keys=creds, credential_keys=creds)


def resolution(server="svc", scopes=("repo",)) -> CredentialReport:
    return CredentialReport(resolutions=[Resolution(
        ref=CredentialRef("GITHUB_TOKEN", ORIGIN, "config_env", server_name=server),
        classification=Classification("github", "classic_pat", "exact"),
        status="resolved", principal="github:octocat", scopes=scopes)])


def write_policy(delegation="any") -> Policy:
    return Policy(rules=[DenyRule("no agent writes", AGENT_ID, "principal:*",
                                  "write", delegation)])


# --- detecting the signal ---------------------------------------------------

@pytest.mark.parametrize("challenge,expected", [
    (OAUTH_CHALLENGE, True),
    ('Bearer realm="mcp"', True),
    ('Bearer as_uri="https://idp/authorize"', True),
    ("Bearer", False),          # bare challenge names no authorization server
    ("Basic realm=x", False),   # not OAuth
    (None, False),
])
def test_caller_token_detection(challenge, expected):
    r = ProbeResult(server=spec(), status="auth_required", auth_challenge=challenge)
    assert r.requires_caller_token is expected


def test_challenge_is_serialised():
    r = ProbeResult(server=spec(), status="auth_required",
                    auth_challenge=OAUTH_CHALLENGE)
    doc = r.to_json()
    assert doc["auth_challenge"] == OAUTH_CHALLENGE
    assert doc["requires_caller_token"] is True


# --- classification ---------------------------------------------------------

def test_static_credential_is_own_credential():
    mode, why = classify_server(spec(), None)
    assert mode == "own_credential"
    assert "presents it on every call" in why


def test_config_credential_beats_an_auth_challenge():
    """A hardcoded secret must not masquerade as delegation.

    We probe unauthenticated, so a 401 only means "some token required". If
    config supplies one, that is what gets presented and the caller's
    identity never enters the request.
    """
    probe = ProbeResult(server=spec(), status="auth_required",
                        auth_challenge=OAUTH_CHALLENGE)
    mode, _ = classify_server(spec(), probe)
    assert mode == "own_credential"


def test_challenge_without_static_credential_is_caller_token():
    s = spec(creds=())
    probe = ProbeResult(server=s, status="auth_required",
                        auth_challenge=OAUTH_CHALLENGE)
    mode, why = classify_server(s, probe)
    assert mode == "caller_token"
    assert "bounded by the caller" in why


def test_no_signal_is_unknown():
    mode, _ = classify_server(spec(creds=()), None)
    assert mode == "unknown"


def test_unknown_counts_as_confused_deputy():
    """Assuming a delegation boundary that may not exist understates reach."""
    assert is_confused_deputy("unknown")
    assert is_confused_deputy("own_credential")
    assert not is_confused_deputy("caller_token")


def test_summarise_covers_every_server():
    a, b = spec("a"), spec("b", creds=())
    out = summarise([a, b], [])
    assert out["a"][0] == "own_credential"
    assert out["b"][0] == "unknown"


# --- the proof ---------------------------------------------------------------

def test_own_credential_path_is_a_confused_deputy():
    s = spec()
    g = build_graph([s], [ProbeResult(server=s, status="ok", tools=(WRITE_TOOL,))],
                    resolution())
    v = prove(g, write_policy()).violations
    assert len(v) == 1
    assert v[0].mode == "direct"
    assert v[0].confused_deputy is True


def test_caller_token_path_is_reachable_only_under_delegation():
    s = spec(creds=())
    probe = ProbeResult(server=s, status="ok", tools=(WRITE_TOOL,),
                        auth_challenge=OAUTH_CHALLENGE)
    creds = CredentialReport(resolutions=[Resolution(
        ref=CredentialRef("T", ORIGIN, "config_env", server_name="svc"),
        classification=Classification("github", "classic_pat", "exact"),
        status="resolved", principal="github:octocat", scopes=("repo",))])
    g = build_graph([s], [probe], creds)
    report = prove(g, write_policy())
    assert len(report.violations) == 1
    v = report.violations[0]
    assert v.mode == "delegated"
    assert v.confused_deputy is False


def test_confused_deputy_diagnostic_names_the_problem():
    s = spec()
    g = build_graph([s], [ProbeResult(server=s, status="ok", tools=(WRITE_TOOL,))],
                    resolution())
    d = next(d for d in prove(g, write_policy()).diagnostics
             if d.code == "prove.confused_deputy")
    assert d.severity == "error"
    assert "WITHOUT any delegation" in d.message
    assert "every caller inherits it" in d.message


def test_delegated_reach_is_a_warning_not_an_error():
    s = spec(creds=())
    probe = ProbeResult(server=s, status="ok", tools=(WRITE_TOOL,),
                        auth_challenge=OAUTH_CHALLENGE)
    creds = CredentialReport(resolutions=[Resolution(
        ref=CredentialRef("T", ORIGIN, "config_env", server_name="svc"),
        classification=Classification("github", "classic_pat", "exact"),
        status="resolved", principal="github:octocat", scopes=("repo",))])
    d = next(d for d in prove(build_graph([s], [probe], creds), write_policy()).diagnostics
             if d.code == "prove.delegated_reach")
    assert d.severity == "warn"
    assert "bounded by the caller" in d.message


# --- policy qualifier --------------------------------------------------------

def test_delegation_direct_ignores_properly_delegated_reach():
    """`delegation: direct` says delegated access is acceptable."""
    s = spec(creds=())
    probe = ProbeResult(server=s, status="ok", tools=(WRITE_TOOL,),
                        auth_challenge=OAUTH_CHALLENGE)
    creds = CredentialReport(resolutions=[Resolution(
        ref=CredentialRef("T", ORIGIN, "config_env", server_name="svc"),
        classification=Classification("github", "classic_pat", "exact"),
        status="resolved", principal="github:octocat", scopes=("repo",))])
    g = build_graph([s], [probe], creds)
    report = prove(g, write_policy(delegation="direct"))
    assert report.violations == []
    assert "without a delegation" in report.proofs_of_absence[0].note


def test_delegation_direct_still_flags_a_deputy():
    s = spec()
    g = build_graph([s], [ProbeResult(server=s, status="ok", tools=(WRITE_TOOL,))],
                    resolution())
    assert len(prove(g, write_policy(delegation="direct")).violations) == 1


def test_policy_parses_delegation_qualifier():
    p = parse_policy({"version": 1, "rules": [
        {"deny": {"from": "agent", "to": "p:*", "delegation": "direct"}}]})
    assert p.rules[0].delegation == "direct"


def test_policy_rejects_bad_delegation_value():
    with pytest.raises(PolicyError, match="delegation must be any|direct"):
        parse_policy({"version": 1, "rules": [
            {"deny": {"from": "a", "to": "b", "delegation": "sideways"}}]})


# --- deployment posture ------------------------------------------------------

def test_no_delegation_boundary_is_reported_once():
    a, b = spec("a"), spec("b")
    probes = [ProbeResult(server=a, status="ok", tools=(WRITE_TOOL,)),
              ProbeResult(server=b, status="ok", tools=(WRITE_TOOL,))]
    g = build_graph([a, b], probes, resolution("a"))
    ds = [d for d in prove(g, write_policy()).diagnostics
          if d.code == "prove.no_delegation_boundary"]
    assert len(ds) == 1
    assert ds[0].severity == "error"
    assert "no delegation boundary anywhere" in ds[0].message


def test_delegation_boundary_reported_when_one_exists():
    a = spec("a")
    b = spec("b", creds=())
    probes = [ProbeResult(server=a, status="ok", tools=(WRITE_TOOL,)),
              ProbeResult(server=b, status="ok", tools=(WRITE_TOOL,),
                          auth_challenge=OAUTH_CHALLENGE)]
    g = build_graph([a, b], probes, resolution("a"))
    d = next(d for d in prove(g, write_policy()).diagnostics
             if d.code == "prove.delegation_boundary")
    assert "1/2 server(s)" in d.message and "b" in d.message


def test_graph_json_records_delegation():
    s = spec()
    g = build_graph([s], [ProbeResult(server=s, status="ok", tools=(WRITE_TOOL,))],
                    resolution())
    doc = json.loads(json.dumps(g.to_json()))
    assert doc["delegation"]["svc"]["mode"] == "own_credential"


def test_verdict_json_carries_mode():
    s = spec()
    g = build_graph([s], [ProbeResult(server=s, status="ok", tools=(WRITE_TOOL,))],
                    resolution())
    doc = prove(g, write_policy()).to_json()
    assert doc["verdicts"][0]["mode"] == "direct"
    assert doc["verdicts"][0]["confused_deputy"] is True
