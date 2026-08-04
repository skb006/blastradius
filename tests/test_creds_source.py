"""The deliberate read path: value retrieval and ${VAR} indirection."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from blastradius.creds.model import CredentialRef
from blastradius.creds.source import (
    SecretSource,
    expand,
    is_indirect,
    refs_from_server,
)
from blastradius.model import Origin


@pytest.fixture
def cfg(tmp_path: Path) -> Path:
    p = tmp_path / ".mcp.json"
    p.write_text(json.dumps({
        "mcpServers": {
            "gh": {
                "command": "npx",
                "env": {"GITHUB_TOKEN": "ghp_literalvalue", "REGION": "eu"},
            },
            "indirect": {
                "command": "npx",
                "env": {"API_KEY": "${MY_SECRET}", "WITH_DEFAULT": "${NOPE:-fallback}"},
            },
            "remote": {
                "url": "http://h/mcp",
                "headers": {"Authorization": "Bearer hdr_secret"},
            },
        },
        "projects": {
            "/home/x/my.proj": {"mcpServers": {"nested": {
                "command": "n", "env": {"TOKEN": "nested_secret"}}}},
        },
    }))
    return p


def ref(cfg: Path, locator: str, key: str, source="config_env") -> CredentialRef:
    return CredentialRef(key_name=key, origin=Origin(str(cfg), locator), source=source)


# --- indirection ------------------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    ("${VAR}", True), ("$VAR", True), ("${VAR:-d}", True),
    ("literal", False), ("", False), ("100$", False),
])
def test_is_indirect(raw, expected):
    assert is_indirect(raw) is expected


def test_expand_resolves_from_environment():
    assert expand("${A}/x", {"A": "hello"}) == "hello/x"


def test_expand_uses_default_when_unset():
    assert expand("${A:-fallback}", {}) == "fallback"


def test_expand_returns_none_when_unset_and_no_default():
    assert expand("${MISSING}", {}) is None


def test_expand_handles_bare_dollar_form():
    assert expand("$TOKEN", {"TOKEN": "v"}) == "v"


# --- reading ----------------------------------------------------------------

def test_reads_literal_env_value(cfg):
    src = SecretSource(environ={})
    assert src.value_for(ref(cfg, "mcpServers.gh", "GITHUB_TOKEN")) == "ghp_literalvalue"


def test_reads_header_value(cfg):
    src = SecretSource(environ={})
    got = src.value_for(ref(cfg, "mcpServers.remote", "Authorization", "config_header"))
    assert got == "Bearer hdr_secret"


def test_expands_indirect_value_from_environment(cfg):
    src = SecretSource(environ={"MY_SECRET": "ghp_fromenv"})
    assert src.value_for(ref(cfg, "mcpServers.indirect", "API_KEY")) == "ghp_fromenv"


def test_unset_indirection_yields_none(cfg):
    src = SecretSource(environ={})
    assert src.value_for(ref(cfg, "mcpServers.indirect", "API_KEY")) is None


def test_indirection_default_is_honoured(cfg):
    src = SecretSource(environ={})
    assert src.value_for(ref(cfg, "mcpServers.indirect", "WITH_DEFAULT")) == "fallback"


def test_navigates_locator_containing_dots(cfg):
    """Project keys are filesystem paths and contain dots."""
    src = SecretSource(environ={})
    got = src.value_for(
        ref(cfg, "projects./home/x/my.proj.mcpServers.nested", "TOKEN"))
    assert got == "nested_secret"


def test_process_env_source(tmp_path):
    src = SecretSource(environ={"PATH_TOKEN": "v"})
    r = CredentialRef(key_name="PATH_TOKEN", origin=Origin("<env>"), source="process_env")
    assert src.value_for(r) == "v"


def test_missing_file_yields_none(tmp_path):
    src = SecretSource(environ={})
    assert src.value_for(ref(tmp_path / "nope.json", "mcpServers.x", "K")) is None


def test_malformed_file_yields_none(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    assert SecretSource(environ={}).value_for(ref(bad, "mcpServers.x", "K")) is None


def test_unknown_locator_yields_none(cfg):
    assert SecretSource(environ={}).value_for(ref(cfg, "mcpServers.ghost", "K")) is None


# --- reference construction --------------------------------------------------

def test_refs_record_indirection(cfg):
    src = SecretSource(environ={})
    refs = refs_from_server(
        "indirect", Origin(str(cfg), "mcpServers.indirect"),
        env_keys=("API_KEY", "WITH_DEFAULT"), header_keys=(),
        credential_keys=("API_KEY",), source=src)
    assert len(refs) == 1
    assert refs[0].indirection == "${MY_SECRET}"


def test_refs_mark_literal_values_without_indirection(cfg):
    src = SecretSource(environ={})
    refs = refs_from_server(
        "gh", Origin(str(cfg), "mcpServers.gh"),
        env_keys=("GITHUB_TOKEN",), header_keys=(),
        credential_keys=("GITHUB_TOKEN",), source=src)
    assert refs[0].indirection is None


def test_refs_ignore_keys_in_neither_bucket(cfg):
    refs = refs_from_server(
        "gh", Origin(str(cfg), "mcpServers.gh"),
        env_keys=(), header_keys=(), credential_keys=("GHOST",),
        source=SecretSource(environ={}))
    assert refs == []
