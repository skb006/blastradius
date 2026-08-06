"""The safety ladder at the CLI boundary.

The whole point of separating ``--classify-credentials`` from
``--resolve-credentials`` is that the first rung is provably egress-free.
That claim is worth a test that fails loudly rather than a sentence in a
README.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from blastradius.cli import main
from blastradius.creds import providers as P


@pytest.fixture
def cfg(tmp_path: Path) -> Path:
    p = tmp_path / ".mcp.json"
    p.write_text(json.dumps({"mcpServers": {
        "gh": {"url": "http://127.0.0.1:1/mcp",
               "headers": {"Authorization": "Bearer ghp_realsecretvalue"}},
        "aws": {"command": "true", "env": {
            "AWS_ACCESS_KEY_ID": "AKIAREALKEYID",
            "AWS_SECRET_ACCESS_KEY": "realsecretaccesskey"}},
    }}))
    return p


BASE = ["probe", "--no-home-scan", "--no-remote", "--timeout", "1"]

#: `--no-remote` now suppresses credential resolution, because issuers are
#: off-host by definition and the flag promises nothing leaves the machine.
#: Tests that need resolution to actually run therefore drop it; hermeticity
#: comes from stubbing `P._request`, and the declared servers are loopback or
#: stdio-without-spawn so probing generates no traffic either.
RESOLVING = ["probe", "--no-home-scan", "--timeout", "1"]


def test_classify_mode_makes_no_outbound_request(cfg, capsys, monkeypatch):
    def boom(*a, **k):  # pragma: no cover - must never run
        raise AssertionError("--classify-credentials must not contact any issuer")

    monkeypatch.setattr(P, "_request", boom)
    rc = main([*BASE, "-c", str(cfg), "--classify-credentials"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "CREDENTIAL AUTHORITY" in out
    assert "github/classic_pat" in out, "identified offline from the value prefix"
    assert "aws/credential_set" in out


def test_classify_mode_never_prints_a_value(cfg, capsys, monkeypatch):
    monkeypatch.setattr(P, "_request", lambda *a, **k: (200, "{}", {}))
    main([*BASE, "-c", str(cfg), "--classify-credentials"])
    out = capsys.readouterr().out
    for secret in ("ghp_realsecretvalue", "AKIAREALKEYID", "realsecretaccesskey"):
        assert secret not in out


def test_resolve_mode_contacts_only_pinned_issuers(cfg, capsys, monkeypatch):
    hosts: list[str] = []

    def spy(ep, **kw):
        ep.check()          # the pin must hold
        hosts.append(ep.host())
        if "github" in ep.url:
            return 200, '{"login":"octocat"}', {"x-oauth-scopes": "repo"}
        return 200, "<Arn>arn:aws:iam::9:user/x</Arn><Account>9</Account>", {}

    monkeypatch.setattr(P, "_request", spy)
    main([*RESOLVING, "-c", str(cfg), "--resolve-credentials"])
    out = capsys.readouterr().out
    assert set(hosts) <= {"api.github.com", "sts.amazonaws.com"}
    assert "github:octocat" in out
    assert "arn:aws:iam::9:user/x" in out


def test_resolve_mode_never_prints_a_value(cfg, capsys, monkeypatch):
    monkeypatch.setattr(
        P, "_request",
        lambda ep, **kw: (200, '{"login":"o"}', {"x-oauth-scopes": "repo"}))
    main([*RESOLVING, "-c", str(cfg), "--resolve-credentials"])
    out = capsys.readouterr().out
    for secret in ("ghp_realsecretvalue", "AKIAREALKEYID", "realsecretaccesskey"):
        assert secret not in out


def test_high_impact_scope_fails_the_build(cfg, capsys, monkeypatch):
    """A live credential with write scope is an error, so CI can gate on it."""
    monkeypatch.setattr(
        P, "_request",
        lambda ep, **kw: (200, '{"login":"octocat"}',
                          {"x-oauth-scopes": "repo,delete_repo"})
        if "github" in ep.url else (200, "<Arn>a</Arn>", {}))
    rc = main([*RESOLVING, "-c", str(cfg), "--resolve-credentials"])
    assert rc == 1
    assert "creds.high_impact_scope" in capsys.readouterr().out


def test_json_output_includes_credentials_and_no_values(cfg, capsys, monkeypatch):
    monkeypatch.setattr(
        P, "_request",
        lambda ep, **kw: (200, '{"login":"octocat"}', {"x-oauth-scopes": "repo"}))
    main([*RESOLVING, "-c", str(cfg), "--resolve-credentials", "--json"])
    out = capsys.readouterr().out
    doc = json.loads(out)
    assert doc["credentials"]["summary"]["credentials_found"] >= 2
    for secret in ("ghp_realsecretvalue", "AKIAREALKEYID", "realsecretaccesskey"):
        assert secret not in out


def test_credentials_absent_from_json_when_not_requested(cfg, capsys):
    main([*BASE, "-c", str(cfg), "--json"])
    assert json.loads(capsys.readouterr().out)["credentials"] is None


def test_no_credentials_declared_renders_cleanly(tmp_path: Path, capsys):
    p = tmp_path / ".mcp.json"
    p.write_text(json.dumps({"mcpServers": {"plain": {"url": "http://127.0.0.1:1/mcp"}}}))
    main([*BASE, "-c", str(p), "--classify-credentials"])
    assert "no credentials declared" in capsys.readouterr().out
