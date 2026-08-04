"""Offline classification — identification from documented issuer prefixes."""

from __future__ import annotations

import pytest

from blastradius.creds.classify import classify, is_aws_component


@pytest.mark.parametrize("value,provider,cls", [
    ("ghp_16CharsOfStuffHere", "github", "classic_pat"),
    ("github_pat_11ABCDE_xyz", "github", "fine_grained_pat"),
    ("gho_oauthtokenvalue", "github", "oauth_token"),
    ("ghs_serverToServer", "github", "server_to_server_token"),
    ("glpat-abcdefghijklmno", "gitlab", "personal_access_token"),
    ("xoxb-1234-5678-abcd", "slack", "bot_token"),
    ("xoxp-1111-2222-cccc", "slack", "user_token"),
    ("AKIAIOSFODNN7EXAMPLE", "aws", "long_term_access_key"),
    ("ASIAIOSFODNN7EXAMPLE", "aws", "temporary_access_key"),
    ("sk-ant-api03-abcdef", "anthropic", "api_key"),
    ("sk-proj-abcdefghij", "openai", "project_api_key"),
    ("sk-abcdefghijklmnop", "openai", "api_key"),
    ("AIzaSyD-ExampleKeyHere", "google", "api_key"),
    ("ya29.a0AfH6SMB-example", "google", "oauth_access_token"),
    ("hf_ExampleHuggingFace", "huggingface", "access_token"),
    ("shpat_exampleshopify", "shopify", "admin_api_token"),
])
def test_value_prefixes_are_identified_exactly(value, provider, cls):
    got = classify("SOME_GENERIC_NAME", value)
    assert (got.provider, got.credential_class) == (provider, cls)
    assert got.confidence == "exact"
    assert got.matched_on == "value_prefix"


def test_longest_prefix_wins_within_a_provider():
    """github_pat_ must not be classified as the shorter ghp_/gho_ family."""
    assert classify("T", "github_pat_x").credential_class == "fine_grained_pat"
    assert classify("T", "sk-proj-x").credential_class == "project_api_key"


def test_value_beats_a_misleading_key_name():
    got = classify("GITHUB_TOKEN", "xoxb-actually-slack")
    assert got.provider == "slack", "the value is authoritative, not the name"


def test_bearer_prefix_is_stripped_before_matching():
    got = classify("Authorization", "Bearer ghp_tokenvalue")
    assert got.provider == "github" and got.confidence == "exact"


def test_jwt_requires_three_segment_shape():
    assert classify("T", "eyJhbGci.eyJzdWIi.sig").provider == "jwt"
    # base64 that merely starts with eyJ but is not a JWT
    assert classify("T", "eyJustSomeBase64DataHere").provider == "unknown"


def test_key_name_fallback_when_no_value():
    got = classify("GITHUB_TOKEN")
    assert got.provider == "github"
    assert got.confidence == "likely"
    assert got.matched_on == "key_name"


def test_key_name_fallback_when_value_unrecognised():
    got = classify("SLACK_API_TOKEN", "some-opaque-blob-with-no-prefix")
    assert got.provider == "slack" and got.confidence == "likely"


def test_unknown_credential_is_reported_as_unknown():
    got = classify("MY_THING", "opaque")
    assert got.provider == "unknown"
    assert got.resolvable is False


def test_resolvability_is_marked_per_class():
    assert classify("T", "ghp_x").resolvable is True
    assert classify("T", "sk-ant-api03-x").resolvable is False, "no introspection API"
    assert classify("T", "ghr_x").resolvable is False, "refresh tokens are not introspectable"


@pytest.mark.parametrize("key,role", [
    ("AWS_ACCESS_KEY_ID", "access_key_id"),
    ("AWS_SECRET_ACCESS_KEY", "secret_access_key"),
    ("AWS_SESSION_TOKEN", "session_token"),
    ("MY_AWS_ACCESS_KEY_ID", "access_key_id"),
    ("GITHUB_TOKEN", None),
])
def test_aws_component_detection(key, role):
    assert is_aws_component(key) == role


def test_classification_never_echoes_the_value():
    import json
    got = classify("K", "ghp_SUPERSECRETVALUE")
    assert "SUPERSECRET" not in json.dumps(got.to_json())
