"""The deliberate read path for credential values.

Discovery drops secrets on purpose, so stage 3 cannot reuse it — resolution
needs a *separate*, explicitly-invoked way to obtain a value. Keeping that
path in its own module makes the boundary auditable: exactly one function in
the codebase returns a credential value, and everything that calls it is one
grep away.

Nothing here caches. A value is read from disk or the environment on demand
and handed to a single caller, which uses it for one pinned request and lets
it fall out of scope.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Mapping

from ..model import Origin
from .model import CredentialRef

# ${VAR}, ${VAR:-default}, and bare $VAR
_INTERP = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}|\$([A-Za-z_][A-Za-z0-9_]*)")


def is_indirect(raw: str) -> bool:
    return bool(_INTERP.search(raw))


def expand(raw: str, environ: Mapping[str, str]) -> str | None:
    """Expand ``${VAR}`` references against ``environ``.

    Returns ``None`` when a referenced variable is unset and has no default —
    an unset reference means the grant is not actually held, which is a
    finding rather than an error.
    """
    missing = False

    def sub(m: re.Match[str]) -> str:
        nonlocal missing
        name = m.group(1) or m.group(3)
        default = m.group(2)
        if name in environ:
            return environ[name]
        if default is not None:
            return default
        missing = True
        return ""

    out = _INTERP.sub(sub, raw)
    return None if missing else out


def _navigate(doc: Any, locator: str) -> Any:
    """Walk a dotted locator, tolerating dots inside project-path segments.

    ``projects./home/x/proj.mcpServers.name`` cannot be split naively, so we
    resolve greedily: at each step take the longest key that matches.
    """
    node = doc
    remaining = locator
    while remaining:
        if not isinstance(node, dict):
            return None
        candidates = [k for k in node if remaining == k or remaining.startswith(k + ".")]
        if not candidates:
            return None
        key = max(candidates, key=len)
        node = node[key]
        remaining = remaining[len(key):].lstrip(".")
    return node


class SecretSource:
    """Obtains credential values. The only such thing in the codebase."""

    def __init__(self, environ: Mapping[str, str] | None = None) -> None:
        self._environ = environ if environ is not None else os.environ

    def raw_for(self, ref: CredentialRef) -> str | None:
        """Return the literal, un-expanded config value for a reference."""
        if ref.source == "process_env":
            return self._environ.get(ref.key_name)
        if ref.source == "config_embedded":
            # A credential lifted out of a URL or argv. Its value was scrubbed
            # at parse time and is deliberately unrecoverable — re-reading the
            # config to get it back would defeat boundary redaction. It exists
            # in the model only so the prover counts the server as carrying a
            # credential; there is no value to return.
            return None

        try:
            doc = json.loads(Path(ref.origin.path).read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            return None

        node = _navigate(doc, ref.origin.locator)
        if not isinstance(node, dict):
            return None
        bucket = node.get("env" if ref.source == "config_env" else "headers")
        if not isinstance(bucket, dict):
            return None
        value = bucket.get(ref.key_name)
        return value if isinstance(value, str) else None

    def value_for(self, ref: CredentialRef) -> str | None:
        """Return the usable credential value, expanding ``${VAR}`` if needed.

        ``None`` means the reference exists but dereferences to nothing.
        """
        raw = self.raw_for(ref)
        if raw is None:
            return None
        if is_indirect(raw):
            return expand(raw, self._environ)
        return raw


def refs_from_server(
    server_name: str,
    origin: Origin,
    env_keys: tuple[str, ...],
    header_keys: tuple[str, ...],
    credential_keys: tuple[str, ...],
    source: SecretSource | None = None,
) -> list[CredentialRef]:
    """Build references for the credential-bearing keys of one server."""
    src = source or SecretSource()
    refs: list[CredentialRef] = []
    for key in credential_keys:
        where: str
        if key in env_keys:
            where = "config_env"
        elif key in header_keys:
            where = "config_header"
        else:
            # A credential embedded in a URL or an argv element — its value was
            # scrubbed at parse time, so it dereferences to nothing, but the
            # server still *carries* it and presents it on every call. Dropping
            # it here made the prover blind to a confused deputy that discovery
            # had already flagged (`creds: <url-password>`), which is an
            # under-approximation — the one direction this tool must not err in.
            # Emitted value-less; it resolves as unbounded authority, the sound
            # over-approximation.
            where = "config_embedded"
        ref = CredentialRef(key_name=key, origin=origin, source=where, server_name=server_name)
        raw = src.raw_for(ref)
        refs.append(
            CredentialRef(
                key_name=key, origin=origin, source=where, server_name=server_name,
                indirection=raw if (raw and is_indirect(raw)) else None,
            )
        )
    return refs
