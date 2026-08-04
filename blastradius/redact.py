"""Secret handling.

Design rule: **redact at the boundary, not at the edge of output.**

Credential values are dropped the moment a config is parsed, so they never
enter any dataclass, never reach a serialiser, and cannot leak through a
newly-added output path later. The only thing that survives is the *key*,
because "this server carries a GITHUB_TOKEN" is a blast-radius fact while
the token itself never is.

`looks_sensitive` is deliberately over-eager. A false positive costs one
redacted key in a report; a false negative writes a live credential to disk.
"""

from __future__ import annotations

import re

# Substrings that mark a config key as carrying a secret. Matched
# case-insensitively against the key, after stripping separators, so
# ``API_KEY``, ``api-key`` and ``apiKey`` all hit the same needle.
_SENSITIVE_NEEDLES: tuple[str, ...] = (
    "token",
    "key",
    "secret",
    "password",
    "passwd",
    "pwd",
    "credential",
    "auth",
    "session",
    "cookie",
    "signature",
    "private",
    "salt",
    "bearer",
    "access",
    "refresh",
    "client_id",
    "clientid",
    "pat",
    "dsn",
)

# Keys that contain a needle but are not secrets. Without this,
# ``keyboard`` and ``authority`` would be flagged, and an over-redacted
# report trains users to ignore redaction.
_ALLOWLIST: frozenset[str] = frozenset(
    {
        "keyboard",
        "keywords",
        "keyword",
        "authority",
        "author",
        "keymap",
        "monkeypatch",
        "pathspec",
        "patch",
        "path",
    }
)

_SEPARATORS = re.compile(r"[-_.\s]+")

REDACTED = "<redacted>"


def _normalise(key: str) -> str:
    """Lowercase and strip separators so casing/styling can't evade a match."""
    return _SEPARATORS.sub("", key).lower()


def looks_sensitive(key: str) -> bool:
    """True if ``key`` plausibly names a credential.

    Over-eager by design — see module docstring.
    """
    if not key:
        return False
    norm = _normalise(key)
    if norm in _ALLOWLIST or key.lower() in _ALLOWLIST:
        return False
    return any(needle.replace("_", "") in norm for needle in _SENSITIVE_NEEDLES)


def split_keys(mapping: dict | None) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Split a config mapping into (all keys, keys judged sensitive).

    Values are never returned. Callers get key names only.
    """
    if not isinstance(mapping, dict):
        return ((), ())
    all_keys = tuple(sorted(str(k) for k in mapping))
    sensitive = tuple(k for k in all_keys if looks_sensitive(k))
    return all_keys, sensitive


def scrub(value: object, _depth: int = 0) -> object:
    """Recursively replace sensitive values in an arbitrary structure.

    Used for the rare case where a raw fragment must be shown in a
    diagnostic. Prefer never carrying the value at all.
    """
    if _depth > 6:
        return "<truncated>"
    if isinstance(value, dict):
        return {
            k: (REDACTED if looks_sensitive(str(k)) else scrub(v, _depth + 1))
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [scrub(v, _depth + 1) for v in value]
    return value


def scrub_argv(args: object) -> tuple[str, ...]:
    """Scrub a command argv.

    Secrets reach argv two ways and both are handled:
      ``--token=abc``      -> ``--token=<redacted>``
      ``--token`` ``abc``  -> ``--token`` ``<redacted>``
    """
    if not isinstance(args, (list, tuple)):
        return ()
    out: list[str] = []
    redact_next = False
    for raw in args:
        arg = str(raw)
        if redact_next:
            out.append(REDACTED)
            redact_next = False
            continue
        if "=" in arg and arg.startswith("-"):
            flag, _, _value = arg.partition("=")
            if looks_sensitive(flag.lstrip("-")):
                out.append(f"{flag}={REDACTED}")
                continue
        if arg.startswith("-") and looks_sensitive(arg.lstrip("-")):
            out.append(arg)
            redact_next = True
            continue
        out.append(arg)
    return tuple(out)
