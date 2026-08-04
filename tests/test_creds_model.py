"""Structural guarantee: no credential type may carry a credential value.

Stage 3 is the first component that reads secrets, so the invariant is
restated as a test that walks the actual dataclass fields. A future field
named ``token`` fails here rather than in production.
"""

from __future__ import annotations

import dataclasses
import json

from blastradius.creds import model as cred_model
from blastradius.model import Origin

VALUE_BEARING_NAMES = {
    "value", "secret", "token", "password", "credential", "key", "api_key",
    "access_key", "secret_access_key", "session_token", "raw", "authorization",
}


def _cred_dataclasses():
    for name in dir(cred_model):
        obj = getattr(cred_model, name)
        if dataclasses.is_dataclass(obj) and isinstance(obj, type):
            yield obj


def test_no_credential_type_has_a_value_bearing_field():
    offenders = []
    for cls in _cred_dataclasses():
        for f in dataclasses.fields(cls):
            if f.name.lower() in VALUE_BEARING_NAMES:
                offenders.append(f"{cls.__name__}.{f.name}")
    assert not offenders, (
        f"these fields could hold a credential value: {offenders}. "
        "Stage 3 reads secrets; it must never store them."
    )


def test_there_is_at_least_one_dataclass_to_check():
    """Guards the test above from silently passing on an empty scan."""
    assert len(list(_cred_dataclasses())) >= 4


def test_resolution_json_round_trip_carries_no_value():
    ref = cred_model.CredentialRef(
        key_name="GITHUB_TOKEN", origin=Origin("/cfg.json", "mcpServers.gh"),
        source="config_env", server_name="gh", indirection="${GITHUB_TOKEN}")
    res = cred_model.Resolution(
        ref=ref,
        classification=cred_model.Classification("github", "classic_pat", "exact"),
        status="resolved", principal="github:octocat", scopes=("repo",))
    blob = json.dumps(res.to_json())
    assert "ghp_" not in blob
    assert "github:octocat" in blob


def test_inert_statuses():
    def make(status):
        return cred_model.Resolution(
            ref=cred_model.CredentialRef("K", Origin("/x"), "config_env"),
            classification=cred_model.Classification(), status=status)

    assert make("invalid").is_inert
    assert make("expired").is_inert
    assert not make("resolved").is_inert
    assert not make("skipped").is_inert


def test_report_summary_counts():
    def make(status):
        return cred_model.Resolution(
            ref=cred_model.CredentialRef(f"K{status}", Origin("/x"), "config_env"),
            classification=cred_model.Classification(), status=status)

    rep = cred_model.CredentialReport(
        resolutions=[make("resolved"), make("invalid"), make("skipped")])
    summary = rep.to_json()["summary"]
    assert summary == {
        "credentials_found": 3,
        "resolved": 1,
        "inert": 1,
        "by_status": {"invalid": 1, "resolved": 1, "skipped": 1},
    }
