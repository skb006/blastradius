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
    "webhook",
    "connectionstring",
    "connstr",
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

    A key is sensitive if its *name* says so (``GITHUB_TOKEN``) **or** if its
    *value* is a DSN carrying its own credentials
    (``DATABASE_URL=postgresql://svc:pw@db/prod``). The second test is what
    catches the whole ``*_URL``/``*_URI`` family, and it is better than adding
    ``url`` to the needle list: a bare ``url`` key is an MCP server's address,
    and flagging it would report every HTTP server as carrying a credential.
    Judge the value's shape, record only the name.
    """
    if not isinstance(mapping, dict):
        return ((), ())
    all_keys = tuple(sorted(str(k) for k in mapping))
    sensitive = tuple(
        k for k in all_keys
        if looks_sensitive(k) or _value_carries_credential(mapping.get(k))
    )
    return all_keys, sensitive


def _value_carries_credential(value: object) -> bool:
    """Does this value embed a secret, whatever its key is called?

    Returns a boolean — never the value, never any part of it.
    """
    if not isinstance(value, str) or "://" not in value:
        return False
    _safe, keys = scrub_url(value)
    return bool(keys)


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


#: Flags whose *next* argv element is a value, regardless of what the flag
#: itself is called. ``-H`` and ``-e`` carry no sensitive needle, but
#: ``-H 'Authorization: Bearer ...'`` and ``-e GITHUB_TOKEN=ghp_...`` are how
#: mcp-remote and docker-based MCP servers actually pass credentials.
_VALUE_CARRYING_FLAGS: frozenset[str] = frozenset({
    "-h", "--header", "-e", "--env", "--data", "-d", "--url", "-u",
    "--user", "--password-stdin", "--arg", "--set",
})

_URL_WITH_USERINFO = re.compile(r"^[a-z][a-z0-9+.-]*://[^/\s@]+@", re.I)


def scrub_url(url: object) -> tuple[str, tuple[str, ...]]:
    """Strip credentials out of a URL. Returns ``(safe_url, key_names)``.

    Two shapes carry secrets and neither has a config key to match on, which
    is why key-name redaction alone never saw them:

      ``https://host/mcp?api_key=SECRET``  -> ``?api_key=<redacted>``
      ``https://user:SECRET@host/mcp``     -> ``https://user@host/mcp``

    The returned key names are folded into ``ServerSpec.credential_keys`` so
    the server is correctly reported as carrying a credential — which also
    restores its ``own_credential`` delegation classification.
    """
    if not isinstance(url, str) or "://" not in url:
        return (str(url) if url is not None else "", ())

    from urllib.parse import parse_qsl, urlsplit, urlunsplit

    try:
        parts = urlsplit(url)
    except ValueError:
        return (REDACTED, ("<unparseable-url>",))

    found: list[str] = []
    netloc = parts.netloc
    if "@" in netloc:
        userinfo, _, hostpart = netloc.rpartition("@")
        user, sep, _password = userinfo.partition(":")
        if sep:
            found.append("<url-password>")
            netloc = f"{user}@{hostpart}"
        else:
            netloc = f"{user}@{hostpart}"

    query = parts.query
    if query:
        pairs = parse_qsl(query, keep_blank_values=True)
        if pairs:
            rebuilt = []
            for k, v in pairs:
                if v and looks_sensitive(k):
                    found.append(k)
                    rebuilt.append(f"{k}={REDACTED}")
                else:
                    rebuilt.append(f"{k}={v}" if v or "=" in query else k)
            query = "&".join(rebuilt)

    return (urlunsplit((parts.scheme, netloc, parts.path, query, parts.fragment)),
            tuple(found))


def scrub_argv(args: object) -> tuple[str, ...]:
    """Scrub a command argv. See :func:`scrub_argv_with_keys`."""
    return scrub_argv_with_keys(args)[0]


def scrub_argv_with_keys(args: object) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Scrub a command argv, and name the credentials found in it.

    Redaction is keyed on the *token*, not only on a preceding flag, because
    the flag-anchored approach cannot be completed: a positional connection
    string (``postgresql://svc:PASSWORD@db/prod``) has no flag in front of it
    at all. Four shapes are handled:

      ``--token=abc``                 -> ``--token=<redacted>``
      ``--token`` ``abc``             -> ``--token`` ``<redacted>``
      ``-H`` ``Authorization: Bearer`` -> ``-H`` ``Authorization: <redacted>``
      ``postgres://u:pw@h/db``        -> ``postgres://u@h/db``

    Returns ``(scrubbed_argv, key_names)``. The key names matter as much as
    the scrubbing: a credential passed in argv is authority the server carries
    on every call, so it has to reach ``credential_keys`` or the server is
    classified as having no static credential and its confused-deputy posture
    is understated.
    """
    if not isinstance(args, (list, tuple)):
        return ((), ())
    found: list[str] = []
    out: list[str] = []
    # None | "full" | "structural". A flag whose *name* is sensitive
    # (``--token``) makes its whole value a secret. A merely value-carrying
    # flag (``-H``) does not: ``-H 'Authorization: Bearer x'`` should keep the
    # header name, which is a blast-radius fact, and drop only the value.
    pending: str | None = None
    pending_name: str | None = None
    for raw in args:
        arg = str(raw)
        if pending:
            if pending == "full":
                out.append(REDACTED)
                found.append(pending_name or "<argv>")
            else:
                scrubbed, keys = _scrub_token_with_keys(arg)
                out.append(scrubbed)
                found.extend(keys)
            pending = None
            pending_name = None
            continue
        if "=" in arg and arg.startswith("-"):
            flag, _, _value = arg.partition("=")
            if looks_sensitive(flag.lstrip("-")):
                out.append(f"{flag}={REDACTED}")
                found.append(flag.lstrip("-"))
                continue
        if arg.startswith("-"):
            if looks_sensitive(arg.lstrip("-")):
                out.append(arg)
                pending, pending_name = "full", arg.lstrip("-")
                continue
            if arg.lower() in _VALUE_CARRYING_FLAGS:
                out.append(arg)
                pending = "structural"
                continue
        scrubbed, keys = _scrub_token_with_keys(arg)
        out.append(scrubbed)
        found.extend(keys)
    return tuple(out), tuple(sorted(set(found)))


def _scrub_token(arg: str) -> str:
    return _scrub_token_with_keys(arg)[0]


def _scrub_token_with_keys(arg: str) -> tuple[str, tuple[str, ...]]:
    """Structural scrub of a single argv element, with no flag context.

    Handles ``NAME=value``, ``Header: value`` and URLs carrying credentials.
    """
    if "://" in arg:
        safe, keys = scrub_url(arg)
        if safe != arg:
            return safe, keys
    if ": " in arg:
        name, _, _value = arg.partition(": ")
        if looks_sensitive(name):
            return f"{name}: {REDACTED}", (name,)
    if "=" in arg and not arg.startswith("-"):
        name, _, value = arg.partition("=")
        if value and looks_sensitive(name):
            return f"{name}={REDACTED}", (name,)
    return arg, ()
