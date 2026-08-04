"""Credential model.

The governing rule, and the reason this module is separate from
``blastradius.model``:

    **No type in this file has a field that can hold a credential value.**

Stages 1 and 2 never read secrets at all. Stage 3 must — you cannot ask an
issuer what a token authorises without presenting the token. The safety
property is therefore restated rather than abandoned: a value is read into a
local variable, used for exactly one pinned outbound call, and dropped. It
never lands in a dataclass, a report, a diagnostic, or a JSON document.

``test_creds_model.py`` asserts this structurally by walking every field of
every type here, so a future field named ``token`` fails the suite.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

from ..model import Diagnostic, Origin

#: Where a credential reference was found.
CredSource = Literal["config_env", "config_header", "process_env"]

#: How confident the offline classifier is.
Confidence = Literal["exact", "likely", "unknown"]

ResolveStatus = Literal[
    "resolved",        # issuer answered; principal and/or scopes recovered
    "invalid",         # issuer rejected it -> the grant is inert
    "expired",
    "unsupported",     # no read-only introspection endpoint for this provider
    "no_value",        # reference could not be dereferenced (unset ${VAR})
    "network_error",
    "skipped",         # policy said don't
]


@dataclass(frozen=True, slots=True)
class CredentialRef:
    """A pointer to a credential. Never the credential.

    ``indirection`` records a ``${VAR}`` reference exactly as written, which
    is a blast-radius fact in itself: a config that says ``${GITHUB_TOKEN}``
    inherits whatever the surrounding process environment holds, and that is
    a wider grant than a literal.
    """

    key_name: str
    origin: Origin
    source: CredSource
    server_name: str = ""
    indirection: str | None = None

    @property
    def ident(self) -> str:
        return f"{self.server_name}:{self.key_name}" if self.server_name else self.key_name

    def to_json(self) -> dict[str, Any]:
        d = asdict(self)
        d["origin"] = str(self.origin)
        return d


@dataclass(frozen=True, slots=True)
class Classification:
    """What kind of credential this is, determined without any network call.

    Derived from the key name and — when a value is available — its public
    prefix. Prefixes like ``ghp_`` are documented issuer conventions, so this
    is identification, not guessing, and it costs no egress.
    """

    provider: str = "unknown"
    credential_class: str = "unknown"
    confidence: Confidence = "unknown"
    matched_on: str = ""
    resolvable: bool = False

    def to_json(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class Resolution:
    """What an issuer says a credential authorises.

    ``principal`` is the identity the credential maps to — an AWS ARN, a
    GitHub login, a Slack team. That is the single most useful field for
    blast radius: it tells you *whose* authority an injected agent inherits.
    """

    ref: CredentialRef
    classification: Classification
    status: ResolveStatus
    principal: str | None = None
    account: str | None = None
    scopes: tuple[str, ...] = ()
    expires_at: str | None = None
    diagnostics: tuple[Diagnostic, ...] = ()

    @property
    def is_inert(self) -> bool:
        """A credential the issuer rejects grants nothing — like a declared
        server whose runtime is missing."""
        return self.status in ("invalid", "expired")

    def to_json(self) -> dict[str, Any]:
        return {
            "ref": self.ref.to_json(),
            "classification": self.classification.to_json(),
            "status": self.status,
            "principal": self.principal,
            "account": self.account,
            "scopes": list(self.scopes),
            "expires_at": self.expires_at,
            "is_inert": self.is_inert,
            "diagnostics": [d.to_json() for d in self.diagnostics],
        }


@dataclass
class CredentialReport:
    resolutions: list[Resolution] = field(default_factory=list)
    diagnostics: list[Diagnostic] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        by_status: dict[str, int] = {}
        for r in self.resolutions:
            by_status[r.status] = by_status.get(r.status, 0) + 1
        return {
            "resolutions": [r.to_json() for r in
                            sorted(self.resolutions, key=lambda r: r.ref.ident)],
            "summary": {
                "credentials_found": len(self.resolutions),
                "resolved": sum(1 for r in self.resolutions if r.status == "resolved"),
                "inert": sum(1 for r in self.resolutions if r.is_inert),
                "by_status": dict(sorted(by_status.items())),
            },
            "diagnostics": [d.to_json() for d in self.diagnostics],
        }
