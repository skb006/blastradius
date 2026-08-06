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


# --------------------------------------------------------------------------
# value-shape gate for credential DISCOVERY (not redaction)
# --------------------------------------------------------------------------
#
# `looks_sensitive(key)` is deliberately over-eager, which is correct for
# redaction: better to redact a non-secret than leak a real one. But when the
# same predicate drives credential *discovery* — deciding which process-environ
# variables to actually resolve — that over-eagerness is pure noise:
# SSH_AUTH_SOCK, DBUS_SESSION_BUS_ADDRESS and QT_ACCESSIBILITY all trip a needle
# yet hold a socket path, a bus address and a boolean.
#
# The gate below refines the name signal with the VALUE, and it is designed
# around one hard-won result (an adversarial corpus of 163 env-var shapes, 97 of
# them soundness-critical, found 28 ways a naive gate silently drops a real
# secret): **you cannot clear on length, entropy, hex-ness, UUID-ness, a leading
# slash, or the presence of whitespace.** Every one of those has a real
# credential with that exact shape — a 6-char DB password, a numeric VNC
# password, a 32-hex Twilio token indistinguishable from a git SHA, a UUID used
# as an API key, a base64 secret beginning with '/'.
#
# So the gate DEFAULTS TO SECRET and clears only positively-recognised benign
# shapes. A false negative (clearing a real secret) is the fatal error; a
# residual false positive (still flagging a non-secret) is merely noise.

#: Needles that make a name a credential on the NAME ALONE. A value under one of
#: these can be cleared only by being empty or an unambiguous path/socket — never
#: by "it looks low-entropy", because ``PGPASSWORD=hunter2`` is a real password.
_STRONG_NEEDLES: frozenset[str] = frozenset({
    "password", "passwd", "passphrase", "passcode", "pwd", "secret", "token",
    "pat", "credential", "private", "signature", "salt", "bearer", "apikey",
    "connectionstring", "connstr", "sshpass",
})

_KNOWN_ROOTS = ("/run", "/home", "/usr", "/var", "/tmp", "/etc", "/dev",
                "/proc", "/opt", "/Users", "/mnt", "/srv", "/System", "/Library",
                "./", "../", "~/")
_BOOLEANS = frozenset({"true", "false", "yes", "no", "on", "off", "0", "1"})
_LOCALE = re.compile(r"^[a-z]{2}_[A-Z]{2}(\.[\w-]+)?$")
_HOSTNAME = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?$")
_SHORT_ENUM = re.compile(r"^[a-z][a-z0-9]{0,11}$")
_OPAQUE_RUN = re.compile(r"[A-Za-z0-9+/=_-]{20,}")
_NUMERIC_ID_SUFFIX = ("_ID", "_PID", "_UID", "_GID", "_PORT", "_TIMEOUT",
                      "_EXPIRY", "_INTERVAL", "_VERSION", "_COUNT", "_SECONDS",
                      "_MS", "_RETRIES", "SESSIONID")


def _has_strong_needle(key: str) -> bool:
    from ..redact import _normalise  # local import avoids a cycle at module load
    norm = _normalise(key)
    return any(n in norm for n in _STRONG_NEEDLES)


def _has_opaque_segment(text: str, sep: str) -> bool:
    """Does any separator-delimited segment look like an opaque secret run?

    Used to refuse to clear a path or URL whose segment could itself be the
    credential — a Slack webhook hides its token in a URL path segment, a
    signed URL in a query value.
    """
    return any(_OPAQUE_RUN.fullmatch(seg) for seg in text.split(sep) if seg)


def _is_socket_address(v: str) -> bool:
    """A D-Bus / ICE / X11 / abstract-namespace socket reference — a location,
    not a credential, so sound to clear even under a strong needle."""
    return (
        v.startswith("unix:")
        or v.startswith("@/")                 # abstract-namespace socket
        or "/.ICE-unix/" in v or "/.X11-unix/" in v
        or v.startswith("local/")             # ICE: local/host:@/tmp/.ICE-unix/N
    )


def _is_anchored_path(v: str) -> bool:
    if v.startswith(("unix:", "FILE:", "file:")):
        return True
    win_drive = len(v) >= 3 and v[1] == ":" and v[2] in "\\/"
    if not (v.startswith(_KNOWN_ROOTS) or win_drive):
        return False
    # A lone '/opaque' is a base64 secret, not a path — require real structure.
    if v.count("/") < 2 and not win_drive:
        return False
    return not _has_opaque_segment(v, "/")


def _is_plain_url_without_creds(v: str) -> bool:
    if "://" not in v:
        return False
    from ..redact import scrub_url
    safe, keys = scrub_url(v)
    if keys:                      # userinfo password or a sensitive query param
        return False
    # A secret can hide in a path segment with no userinfo (Slack/Discord
    # webhooks). If any segment is an opaque run, do not clear.
    from urllib.parse import urlsplit
    try:
        path = urlsplit(v).path
    except ValueError:
        return False
    return not _has_opaque_segment(path, "/")


def value_is_credential_shaped(value: str | None) -> bool:
    """True if the VALUE positively carries a credential, whatever its key.

    This is the name-blind arm of discovery. It catches the case the name
    needles miss entirely — ``DATABASE_URL=postgres://svc:pw@host/db``,
    ``REDIS_URL=redis://:pw@h``, a Slack webhook whose token is a URL path
    segment — where nothing about the *name* says "secret" but the value plainly
    is one. Without it these are a silent credential miss.
    """
    v = (value or "").strip()
    if "://" not in v:
        return False
    # A URL that is not a plain, credential-free URL carries a secret: a
    # colon-password userinfo, a sensitive query param, or an opaque path
    # segment (webhook token). `_is_plain_url_without_creds` is exactly that
    # clean-URL predicate, so its negation is "URL that carries a credential".
    return not _is_plain_url_without_creds(v)


def value_looks_benign(key: str, value: str | None) -> bool:
    """True only if ``value`` positively matches a known non-secret shape.

    The safe default is False (treat as a secret). See the module note: this
    never clears on length or entropy, and a strong-needle name can be cleared
    only by an empty value or an unambiguous path/socket.
    """
    v = (value or "").strip()
    if len(v) <= 2:               # empty / trivially short → carries nothing
        return True
    if _is_anchored_path(v) or _is_socket_address(v):  # sound even under a strong needle
        return True

    if _has_strong_needle(key):
        return False              # password/secret/token/… : nothing else clears

    if v.lower() in _BOOLEANS:
        return True
    if _LOCALE.match(v):
        return True
    if _is_plain_url_without_creds(v):
        return True
    if "://" not in v and "@" not in v and not _OPAQUE_RUN.search(v) \
            and _HOSTNAME.match(v):
        return True               # a bare hostname
    if _SHORT_ENUM.match(v):
        return True               # xdg_session_type=wayland, aws_profile=prod
    upper = key.upper()
    if upper.endswith(_NUMERIC_ID_SUFFIX) and (v.isdigit() or (len(v) < 12 and v.isalnum())):
        return True
    return False


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
