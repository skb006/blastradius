"""Stage 3 orchestration — from credential reference to authority.

Two modes, deliberately separated so the safe one is usable everywhere:

``classify``
    Reads values locally, identifies each issuer from its documented prefix,
    emits **no network traffic at all**. Safe to run in CI, on a laptop, in a
    customer's environment on the first call.

``resolve``
    Additionally asks each issuer what the credential authorises, over a
    pinned host. This is what turns "carries a credential of unknown scope"
    into "acts as arn:aws:iam::123456789012:user/deploy".

The value of a credential is read inside :func:`_answer_for` and nowhere
else. It is passed to exactly one provider call and never returned.
"""

from __future__ import annotations

from typing import Iterable, Sequence

from ..model import Diagnostic, ServerSpec
from .classify import classify, is_aws_component
from .model import (
    Classification,
    CredentialRef,
    CredentialReport,
    Resolution,
)
from .providers import (
    DEFAULT_TIMEOUT,
    HostNotPinned,
    SINGLE_VALUE_RESOLVERS,
    ProviderAnswer,
    resolve_aws,
)
from .source import SecretSource, refs_from_server


def collect_refs(
    servers: Sequence[ServerSpec], source: SecretSource | None = None
) -> list[CredentialRef]:
    """Build a credential reference for every credential-bearing config key."""
    src = source or SecretSource()
    refs: list[CredentialRef] = []
    for s in servers:
        refs.extend(
            refs_from_server(
                s.name, s.origin, s.env_keys, s.header_keys, s.credential_keys, src
            )
        )
    return refs


def _answer_for(
    ref: CredentialRef,
    cls: Classification,
    src: SecretSource,
    timeout: float,
) -> tuple[ProviderAnswer, list[Diagnostic]]:
    """Ask the issuer. The only place a credential value is used."""
    diags: list[Diagnostic] = []
    value = src.value_for(ref)
    if value is None:
        return (
            ProviderAnswer("no_value",
                           note=f"{ref.indirection or ref.key_name} does not dereference "
                                f"to a value in this environment"),
            diags,
        )

    fn = SINGLE_VALUE_RESOLVERS.get(cls.provider)
    if fn is None:
        return (
            ProviderAnswer("unsupported",
                           note=f"no read-only introspection endpoint for "
                                f"{cls.provider!r}"),
            diags,
        )
    try:
        return fn(value, timeout=timeout), diags
    except HostNotPinned as exc:  # pragma: no cover - would be our own bug
        diags.append(Diagnostic("error", "creds.host_not_pinned", str(exc), ref.origin))
        return ProviderAnswer("skipped", note="host pin refused the request"), diags
    except (OSError, TimeoutError) as exc:
        return ProviderAnswer("network_error", note=f"{type(exc).__name__}: {exc}"), diags


def _resolve_aws_set(
    refs: Sequence[CredentialRef], src: SecretSource, timeout: float
) -> tuple[ProviderAnswer, CredentialRef | None]:
    """AWS needs three values together, so its components resolve as a set."""
    parts: dict[str, str] = {}
    anchor: CredentialRef | None = None
    for ref in refs:
        role = is_aws_component(ref.key_name)
        if not role:
            continue
        value = src.value_for(ref)
        if value:
            parts[role] = value
            if role == "access_key_id":
                anchor = ref
        anchor = anchor or ref

    if "access_key_id" not in parts or "secret_access_key" not in parts:
        missing = [r for r in ("access_key_id", "secret_access_key") if r not in parts]
        return (
            ProviderAnswer("no_value",
                           note=f"incomplete AWS credential set; missing {', '.join(missing)}"),
            anchor,
        )
    try:
        return (
            resolve_aws(
                parts["access_key_id"],
                parts["secret_access_key"],
                parts.get("session_token"),
                timeout=timeout,
            ),
            anchor,
        )
    except (OSError, TimeoutError, HostNotPinned) as exc:
        return ProviderAnswer("network_error", note=f"{type(exc).__name__}: {exc}"), anchor


def analyse(
    servers: Sequence[ServerSpec],
    *,
    resolve: bool = False,
    source: SecretSource | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    allow_remote: bool = True,
) -> CredentialReport:
    """Classify — and optionally resolve — every credential these servers carry.

    Args:
        servers: from the stage-1 inventory.
        resolve: when False, no network traffic is generated at all.
        source: injected by tests.
        timeout: per issuer request.
        allow_remote: when False, resolution is refused outright. Issuers are
            all off-host by definition, so `--no-remote` — a flag whose whole
            promise is that nothing leaves this machine — has to stop here too.
            Refusing loudly rather than silently downgrading, because a user who
            asked for resolution and got classification without being told would
            read the weaker result as the stronger one.
    """
    src = source or SecretSource()
    report_diags: list[Diagnostic] = []
    if resolve and not allow_remote:
        resolve = False
        report_diags.append(Diagnostic(
            "warn", "creds.resolution_suppressed",
            "--resolve-credentials needs to contact each credential's issuer, "
            "which is off-host; --no-remote is set, so credentials were only "
            "classified. Scope and principal are UNKNOWN, not empty."))
    refs = collect_refs(servers, src)
    report = CredentialReport()
    report.diagnostics.extend(report_diags)

    # Group AWS components per server: three keys, one identity.
    aws_by_server: dict[str, list[CredentialRef]] = {}
    singles: list[CredentialRef] = []
    for ref in refs:
        if is_aws_component(ref.key_name):
            aws_by_server.setdefault(ref.server_name, []).append(ref)
        else:
            singles.append(ref)

    for ref in singles:
        value = src.value_for(ref)
        cls = classify(ref.key_name, value)
        del value  # not needed beyond classification in this branch

        if not resolve:
            report.resolutions.append(
                Resolution(ref=ref, classification=cls, status="skipped"))
            continue

        # Dereference before resolvability. An unset ${VAR} classified from
        # its key name alone looks like an unknown provider, and reporting
        # "unsupported" would hide the far more actionable fact that the
        # reference points at nothing in this environment.
        if src.value_for(ref) is None:
            report.resolutions.append(
                _to_resolution(
                    ref, cls,
                    ProviderAnswer(
                        "no_value",
                        note=f"{ref.indirection or ref.key_name} does not dereference "
                             f"to a value in this environment"),
                    []))
            continue

        if not cls.resolvable:
            report.resolutions.append(
                Resolution(ref=ref, classification=cls, status="unsupported",
                           diagnostics=(Diagnostic(
                               "info", "creds.unsupported_provider",
                               f"{ref.ident}: {cls.provider} exposes no read-only "
                               f"introspection endpoint",
                               ref.origin),)))
            continue

        answer, diags = _answer_for(ref, cls, src, timeout)
        report.resolutions.append(_to_resolution(ref, cls, answer, diags))

    for server_name, group in sorted(aws_by_server.items()):
        anchor = group[0]
        cls = Classification(provider="aws", credential_class="credential_set",
                             confidence="exact", matched_on="key_name", resolvable=True)
        if not resolve:
            report.resolutions.append(
                Resolution(ref=anchor, classification=cls, status="skipped"))
            continue
        answer, chosen = _resolve_aws_set(group, src, timeout)
        report.resolutions.append(_to_resolution(chosen or anchor, cls, answer, []))

    _add_findings(report)
    return report


def _to_resolution(
    ref: CredentialRef,
    cls: Classification,
    answer: ProviderAnswer,
    diags: list[Diagnostic],
) -> Resolution:
    if answer.note:
        diags = diags + [Diagnostic("info", "creds.note",
                                    f"{ref.ident}: {answer.note}", ref.origin)]
    return Resolution(
        ref=ref,
        classification=cls,
        status=answer.status,
        principal=answer.principal,
        account=answer.account,
        scopes=answer.scopes,
        expires_at=answer.expires_at,
        diagnostics=tuple(diags),
    )


#: Scopes that confer broad write authority. Present in a resolved set, these
#: are the edges that turn a prompt injection into an incident.
_HIGH_IMPACT = {
    "repo", "write:org", "admin:org", "delete_repo", "workflow", "admin:repo_hook",
    "write:packages", "admin:gpg_key", "user", "api",
    "chat:write", "files:write", "channels:manage", "admin",
    "https://www.googleapis.com/auth/drive",
    "https://www.googleapis.com/auth/gmail.modify",
}


def _add_findings(report: CredentialReport) -> None:
    for r in report.resolutions:
        if r.is_inert:
            report.diagnostics.append(Diagnostic(
                "info", "creds.inert",
                f"{r.ref.ident}: issuer rejected this credential — declared grant "
                f"confers nothing", r.ref.origin))
            continue

        if r.status == "no_value":
            report.diagnostics.append(Diagnostic(
                "info", "creds.unset_reference",
                f"{r.ref.ident}: reference does not dereference here; the grant "
                f"depends on the environment the agent actually runs in",
                r.ref.origin))

        if r.status == "resolved":
            high = sorted(set(r.scopes) & _HIGH_IMPACT)
            if high:
                report.diagnostics.append(Diagnostic(
                    "error", "creds.high_impact_scope",
                    f"{r.ref.ident} acts as {r.principal} with write-capable "
                    f"scope(s): {', '.join(high)}", r.ref.origin))
            elif not r.scopes:
                report.diagnostics.append(Diagnostic(
                    "warn", "creds.scope_opaque",
                    f"{r.ref.ident} is live as {r.principal} but the issuer "
                    f"exposes no scope list — treat its reach as unbounded",
                    r.ref.origin))

        if r.ref.indirection:
            report.diagnostics.append(Diagnostic(
                "info", "creds.env_inherited",
                f"{r.ref.ident} is {r.ref.indirection} — inherits whatever the "
                f"launching environment holds, which may differ from this one",
                r.ref.origin))
