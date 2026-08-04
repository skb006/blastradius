"""Stage 3 orchestration: classify-only vs resolve, AWS sets, findings."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from blastradius.creds import providers as P
from blastradius.creds.model import CredentialReport
from blastradius.creds.resolve import analyse, collect_refs
from blastradius.creds.source import SecretSource
from blastradius.discovery import discover


@pytest.fixture
def servers(tmp_path: Path):
    cfg = tmp_path / ".mcp.json"
    cfg.write_text(json.dumps({
        "mcpServers": {
            "gh": {"command": "npx", "env": {"GITHUB_TOKEN": "ghp_livetoken"}},
            "aws": {"command": "npx", "env": {
                "AWS_ACCESS_KEY_ID": "AKIAEXAMPLE",
                "AWS_SECRET_ACCESS_KEY": "secretvalue",
                "AWS_SESSION_TOKEN": "sess",
            }},
            "anth": {"command": "npx", "env": {"ANTHROPIC_API_KEY": "sk-ant-api03-x"}},
            "ghost": {"command": "npx", "env": {"SOME_TOKEN": "${UNSET_VAR}"}},
        }
    }))
    inv = discover(home=tmp_path / "nohome", extra_paths=[cfg])
    return inv.deduped()


def codes(report: CredentialReport) -> set[str]:
    return {d.code for d in report.diagnostics} | {
        d.code for r in report.resolutions for d in r.diagnostics}


# --- classify-only mode -----------------------------------------------------

def test_classify_mode_emits_no_network_traffic(servers, monkeypatch):
    def boom(*a, **k):  # pragma: no cover - must never run
        raise AssertionError("classify mode must not touch the network")

    monkeypatch.setattr(P, "_request", boom)
    report = analyse(servers, resolve=False, source=SecretSource(environ={}))
    assert report.resolutions
    assert all(r.status == "skipped" for r in report.resolutions)


def test_classify_identifies_providers_offline(servers):
    report = analyse(servers, resolve=False, source=SecretSource(environ={}))
    got = {r.ref.ident: r.classification.provider for r in report.resolutions}
    assert got["gh:GITHUB_TOKEN"] == "github"
    assert got["anth:ANTHROPIC_API_KEY"] == "anthropic"
    assert any(v == "aws" for v in got.values())


def test_aws_components_collapse_to_one_credential_set(servers):
    report = analyse(servers, resolve=False, source=SecretSource(environ={}))
    aws = [r for r in report.resolutions if r.classification.provider == "aws"]
    assert len(aws) == 1, "three AWS keys are one identity, not three credentials"
    assert aws[0].classification.credential_class == "credential_set"


# --- resolve mode -----------------------------------------------------------

def test_resolve_reports_principal_and_scopes(servers, monkeypatch):
    monkeypatch.setattr(
        P, "_request",
        lambda ep, **kw: (200, '{"login":"octocat"}', {"x-oauth-scopes": "repo"})
        if "github" in ep.url else (200, "<Arn>arn:aws:iam::1:user/d</Arn>"
                                    "<Account>1</Account>", {}))
    report = analyse(servers, resolve=True, source=SecretSource(environ={}))
    gh = next(r for r in report.resolutions if r.ref.ident == "gh:GITHUB_TOKEN")
    assert gh.status == "resolved"
    assert gh.principal == "github:octocat"
    assert gh.scopes == ("repo",)


def test_high_impact_scope_is_an_error_finding(servers, monkeypatch):
    monkeypatch.setattr(
        P, "_request",
        lambda ep, **kw: (200, '{"login":"octocat"}', {"x-oauth-scopes": "repo,delete_repo"}))
    report = analyse(servers, resolve=True, source=SecretSource(environ={}))
    d = next(d for d in report.diagnostics if d.code == "creds.high_impact_scope")
    assert d.severity == "error"
    assert "github:octocat" in d.message
    assert "delete_repo" in d.message


def test_live_credential_without_scope_list_is_flagged_unbounded(servers, monkeypatch):
    monkeypatch.setattr(
        P, "_request", lambda ep, **kw: (200, '{"login":"octocat"}', {}))
    report = analyse(servers, resolve=True, source=SecretSource(environ={}))
    d = next(d for d in report.diagnostics if d.code == "creds.scope_opaque")
    assert "unbounded" in d.message


def test_invalid_credential_is_reported_inert(servers, monkeypatch):
    monkeypatch.setattr(P, "_request", lambda ep, **kw: (401, "{}", {}))
    report = analyse(servers, resolve=True, source=SecretSource(environ={}))
    gh = next(r for r in report.resolutions if r.ref.ident == "gh:GITHUB_TOKEN")
    assert gh.is_inert
    assert "creds.inert" in codes(report)


def test_unsupported_provider_is_not_contacted(servers, monkeypatch):
    calls = []
    monkeypatch.setattr(P, "_request",
                        lambda ep, **kw: (calls.append(ep.host()), (200, "{}", {}))[1])
    report = analyse(servers, resolve=True, source=SecretSource(environ={}))
    anth = next(r for r in report.resolutions
                if r.ref.ident == "anth:ANTHROPIC_API_KEY")
    assert anth.status == "unsupported"
    assert not any("anthropic" in h for h in calls)


def test_unset_indirection_reports_no_value_and_a_finding(servers, monkeypatch):
    monkeypatch.setattr(P, "_request", lambda ep, **kw: (200, "{}", {}))
    report = analyse(servers, resolve=True, source=SecretSource(environ={}))
    ghost = next(r for r in report.resolutions if r.ref.ident == "ghost:SOME_TOKEN")
    assert ghost.status == "no_value"
    assert "creds.unset_reference" in codes(report)
    assert "creds.env_inherited" in codes(report)


def test_indirection_resolves_when_variable_is_set(servers, monkeypatch):
    monkeypatch.setattr(
        P, "_request", lambda ep, **kw: (200, '{"login":"envuser"}',
                                         {"x-oauth-scopes": "read:user"}))
    src = SecretSource(environ={"UNSET_VAR": "ghp_fromenvironment"})
    report = analyse(servers, resolve=True, source=src)
    ghost = next(r for r in report.resolutions if r.ref.ident == "ghost:SOME_TOKEN")
    assert ghost.status == "resolved" and ghost.principal == "github:envuser"


def test_incomplete_aws_set_is_reported(tmp_path: Path, monkeypatch):
    cfg = tmp_path / ".mcp.json"
    cfg.write_text(json.dumps({"mcpServers": {"aws": {
        "command": "n", "env": {"AWS_ACCESS_KEY_ID": "AKIA"}}}}))
    servers = discover(home=tmp_path / "nohome", extra_paths=[cfg]).deduped()
    monkeypatch.setattr(P, "_request", lambda ep, **kw: (200, "", {}))
    report = analyse(servers, resolve=True, source=SecretSource(environ={}))
    aws = next(r for r in report.resolutions if r.classification.provider == "aws")
    assert aws.status == "no_value"
    assert any("missing secret_access_key" in d.message for d in aws.diagnostics)


def test_network_failure_does_not_abort_the_run(servers, monkeypatch):
    def flaky(ep, **kw):
        raise OSError("connection reset")

    monkeypatch.setattr(P, "_request", flaky)
    report = analyse(servers, resolve=True, source=SecretSource(environ={}))
    assert report.resolutions, "a failed issuer must not lose the other findings"
    assert any(r.status == "network_error" for r in report.resolutions)


def test_report_json_contains_no_credential_values(servers, monkeypatch):
    monkeypatch.setattr(
        P, "_request", lambda ep, **kw: (200, '{"login":"octocat"}',
                                         {"x-oauth-scopes": "repo"}))
    report = analyse(servers, resolve=True, source=SecretSource(environ={}))
    blob = json.dumps(report.to_json())
    for secret in ("ghp_livetoken", "secretvalue", "sk-ant-api03-x", "AKIAEXAMPLE"):
        assert secret not in blob, f"{secret} leaked into the report"


def test_collect_refs_skips_servers_without_credentials(tmp_path: Path):
    cfg = tmp_path / ".mcp.json"
    cfg.write_text(json.dumps({"mcpServers": {"plain": {"url": "http://h/mcp"}}}))
    servers = discover(home=tmp_path / "nohome", extra_paths=[cfg]).deduped()
    assert collect_refs(servers, SecretSource(environ={})) == []
