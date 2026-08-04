"""Redaction is a security boundary, so it gets adversarial tests."""

from __future__ import annotations

import pytest

from blastradius.redact import REDACTED, looks_sensitive, scrub, scrub_argv, split_keys


@pytest.mark.parametrize(
    "key",
    [
        "GITHUB_TOKEN", "api_key", "apiKey", "API-KEY", "Authorization",
        "AWS_SECRET_ACCESS_KEY", "password", "PASSWD", "pwd", "SESSION_COOKIE",
        "private_key", "REFRESH_TOKEN", "bearer", "DATABASE_DSN", "x-signature",
        "client_id", "clientId", "SALT",
    ],
)
def test_sensitive_keys_are_caught(key):
    assert looks_sensitive(key), f"{key!r} must be treated as a credential"


@pytest.mark.parametrize(
    "key", ["keyboard", "keywords", "authority", "author", "path", "url", "name", "cwd", ""]
)
def test_benign_keys_are_not_flagged(key):
    assert not looks_sensitive(key)


def test_case_and_separator_styles_cannot_evade():
    for variant in ("api_key", "API-KEY", "ApiKey", "api key", "api.key"):
        assert looks_sensitive(variant), variant


def test_split_keys_returns_names_never_values():
    all_keys, sensitive = split_keys({"GITHUB_TOKEN": "ghp_realsecret", "REGION": "eu"})
    assert all_keys == ("GITHUB_TOKEN", "REGION")
    assert sensitive == ("GITHUB_TOKEN",)
    # the value must appear nowhere in the output
    assert "ghp_realsecret" not in repr((all_keys, sensitive))


def test_split_keys_tolerates_junk():
    assert split_keys(None) == ((), ())
    assert split_keys(["not", "a", "dict"]) == ((), ())


def test_scrub_nested_structures():
    out = scrub({"env": {"TOKEN": "abc"}, "list": [{"password": "p"}], "ok": 1})
    assert out == {"env": {"TOKEN": REDACTED}, "list": [{"password": REDACTED}], "ok": 1}


def test_scrub_is_depth_bounded():
    deep: dict = {}
    node = deep
    for _ in range(20):
        node["next"] = {}
        node = node["next"]
    assert "truncated" in repr(scrub(deep))


def test_scrub_argv_handles_both_secret_styles():
    assert scrub_argv(["--token=ghp_abc", "--verbose"]) == (f"--token={REDACTED}", "--verbose")
    assert scrub_argv(["--api-key", "sk-123", "run"]) == ("--api-key", REDACTED, "run")


def test_scrub_argv_leaves_ordinary_args_alone():
    assert scrub_argv(["server.js", "--port", "8080"]) == ("server.js", "--port", "8080")


def test_scrub_argv_tolerates_junk():
    assert scrub_argv(None) == ()
    assert scrub_argv("a string") == ()
