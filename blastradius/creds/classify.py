"""Offline credential classification — identify the issuer without egress.

Issuers publish token prefixes precisely so that secret scanners can spot
them: ``ghp_`` is a GitHub classic PAT, ``ASIA`` an AWS *temporary* key, and
so on. That makes classification identification rather than inference, and it
costs nothing — no network, no calls to the issuer, no exposure.

This buys a genuinely useful middle tier between "we know only the key name"
and "we asked the issuer". Knowing a credential is an AWS **long-term** key
(``AKIA``) rather than a session token (``ASIA``) already changes its blast
radius, and we learn that offline.

Prefixes are matched before key names: a variable called ``API_KEY`` holding
``xoxb-...`` is a Slack token whatever it was named.
"""

from __future__ import annotations

import re

from .model import Classification

# (prefix, provider, credential_class, resolvable)
# Ordered longest-prefix-first within a provider so the specific wins.
_VALUE_PREFIXES: tuple[tuple[str, str, str, bool], ...] = (
    ("github_pat_", "github", "fine_grained_pat", True),
    ("ghp_", "github", "classic_pat", True),
    ("gho_", "github", "oauth_token", True),
    ("ghu_", "github", "user_to_server_token", True),
    ("ghs_", "github", "server_to_server_token", True),
    ("ghr_", "github", "refresh_token", False),
    ("glpat-", "gitlab", "personal_access_token", True),
    ("xoxb-", "slack", "bot_token", True),
    ("xoxp-", "slack", "user_token", True),
    ("xoxa-", "slack", "app_token", True),
    ("xoxr-", "slack", "refresh_token", False),
    ("xapp-", "slack", "app_level_token", False),
    ("ASIA", "aws", "temporary_access_key", True),
    ("AKIA", "aws", "long_term_access_key", True),
    ("sk-ant-", "anthropic", "api_key", False),
    ("sk-proj-", "openai", "project_api_key", True),
    ("sk-", "openai", "api_key", True),
    ("AIza", "google", "api_key", False),
    ("ya29.", "google", "oauth_access_token", True),
    ("hf_", "huggingface", "access_token", True),
    ("npm_", "npm", "access_token", False),
    ("dop_v1_", "digitalocean", "personal_access_token", False),
    ("SG.", "sendgrid", "api_key", False),
    ("pypi-", "pypi", "api_token", False),
    ("shpat_", "shopify", "admin_api_token", False),
    ("sk_live_", "stripe", "live_secret_key", False),
    ("sk_test_", "stripe", "test_secret_key", False),
    ("eyJ", "jwt", "json_web_token", False),
)

# Fallback: infer provider from the key name when no value is available or
# the value carries no recognisable prefix.
_KEY_PATTERNS: tuple[tuple[re.Pattern[str], str, str, bool], ...] = (
    (re.compile(r"github", re.I), "github", "unknown", True),
    (re.compile(r"gitlab", re.I), "gitlab", "unknown", True),
    (re.compile(r"^aws_|_aws_|aws_(access|secret|session)", re.I),
     "aws", "unknown", True),
    (re.compile(r"slack", re.I), "slack", "unknown", True),
    (re.compile(r"google|gcp|gcloud", re.I), "google", "unknown", True),
    (re.compile(r"anthropic", re.I), "anthropic", "unknown", False),
    (re.compile(r"openai", re.I), "openai", "unknown", True),
    (re.compile(r"huggingface|^hf_", re.I), "huggingface", "unknown", True),
    (re.compile(r"stripe", re.I), "stripe", "unknown", False),
)

_JWT_SHAPE = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$")


def classify(key: str, value: str | None = None) -> Classification:
    """Identify a credential from its key name and, if available, its value.

    ``value`` is read but never retained — only the classification is
    returned. Callers pass it inside a narrow scope.
    """
    if value:
        stripped = value.strip()
        # Bearer-prefixed header values carry the token after a space.
        if " " in stripped and stripped.split(" ", 1)[0].lower() in ("bearer", "token"):
            stripped = stripped.split(" ", 1)[1].strip()

        for prefix, provider, cls, resolvable in _VALUE_PREFIXES:
            if stripped.startswith(prefix):
                # A JWT-shaped value is a JWT even if it starts with eyJ by
                # coincidence of base64; require the three-segment shape.
                if provider == "jwt" and not _JWT_SHAPE.match(stripped):
                    continue
                return Classification(
                    provider=provider,
                    credential_class=cls,
                    confidence="exact",
                    matched_on="value_prefix",
                    resolvable=resolvable,
                )

    for pattern, provider, cls, resolvable in _KEY_PATTERNS:
        if pattern.search(key):
            return Classification(
                provider=provider,
                credential_class=cls,
                confidence="likely",
                matched_on="key_name",
                resolvable=resolvable,
            )

    return Classification(matched_on="none")


def is_aws_component(key: str) -> str | None:
    """Map an AWS credential component to its role.

    AWS needs three values together, so the resolver has to recognise the
    parts rather than treat each as a standalone credential.
    """
    upper = key.upper()
    if upper.endswith("AWS_ACCESS_KEY_ID") or upper == "AWS_ACCESS_KEY_ID":
        return "access_key_id"
    if upper.endswith("AWS_SECRET_ACCESS_KEY") or upper == "AWS_SECRET_ACCESS_KEY":
        return "secret_access_key"
    if upper.endswith("AWS_SESSION_TOKEN") or upper == "AWS_SESSION_TOKEN":
        return "session_token"
    return None
