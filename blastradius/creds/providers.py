"""Read-only introspection against credential issuers.

Two safety properties are enforced here, both testable:

**Host pinning.** Every provider declares the exact hosts it may talk to, and
``_request`` refuses to send a credential anywhere else. Without this, a tool
that reads secrets and makes outbound requests is one config-injection away
from being an exfiltration channel. The pin is not advisory — an unpinned host
raises before the socket is opened.

**Response scrubbing.** Issuers sometimes echo the presented credential in an
error body. Any text taken from a response and put into a diagnostic is
scrubbed of the credential value first, so a helpful 401 cannot leak the token
into a report that gets committed.

Every endpoint used below is a read. None can mutate anything.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import urlparse

from .model import ResolveStatus
from .sigv4 import sign_post

DEFAULT_TIMEOUT = 8.0
_MAX_BODY = 4000


class HostNotPinned(RuntimeError):
    """A credential was about to be sent somewhere its issuer does not own."""


@dataclass(frozen=True, slots=True)
class ProviderAnswer:
    status: ResolveStatus
    principal: str | None = None
    account: str | None = None
    scopes: tuple[str, ...] = ()
    expires_at: str | None = None
    note: str = ""


@dataclass(frozen=True, slots=True)
class Endpoint:
    """A pinned read-only introspection endpoint."""

    url: str
    allowed_hosts: frozenset[str]

    def host(self) -> str:
        return (urlparse(self.url).hostname or "").lower()

    def check(self) -> None:
        if self.host() not in self.allowed_hosts:
            raise HostNotPinned(
                f"refusing to send a credential to {self.host()!r}; "
                f"pinned hosts are {sorted(self.allowed_hosts)}"
            )


def scrub_response(text: str, secret: str | None) -> str:
    """Remove the presented credential from text destined for a report."""
    out = text[:400]
    if secret and len(secret) >= 6:
        out = out.replace(secret, "<redacted>")
        # also catch a truncated echo of the leading characters
        out = re.sub(re.escape(secret[:8]) + r"\S*", "<redacted>", out)
    return out


def _request(
    endpoint: Endpoint,
    *,
    headers: dict[str, str],
    method: str = "GET",
    body: bytes | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> tuple[int, str, dict[str, str]]:
    """Perform one pinned request. Returns (status, body, headers)."""
    endpoint.check()
    req = urllib.request.Request(
        endpoint.url,
        data=body,
        headers={"User-Agent": "blastradius/0.1 (read-only introspection)", **headers},
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            return (
                resp.status,
                resp.read(_MAX_BODY).decode("utf-8", errors="replace"),
                {k.lower(): v for k, v in resp.headers.items()},
            )
    except urllib.error.HTTPError as exc:
        return (
            exc.code,
            exc.read(_MAX_BODY).decode("utf-8", errors="replace"),
            {k.lower(): v for k, v in (exc.headers or {}).items()},
        )


def _json(body: str) -> dict[str, Any]:
    try:
        doc = json.loads(body)
        return doc if isinstance(doc, dict) else {}
    except json.JSONDecodeError:
        return {}


def _split_scopes(raw: str | None) -> tuple[str, ...]:
    if not raw:
        return ()
    return tuple(s for s in re.split(r"[,\s]+", raw.strip()) if s)


# --------------------------------------------------------------------------
# providers
# --------------------------------------------------------------------------

def resolve_github(value: str, timeout: float = DEFAULT_TIMEOUT) -> ProviderAnswer:
    """`GET /user` — returns identity, and scopes via the X-OAuth-Scopes header.

    Fine-grained PATs return an empty scope header by design; the identity is
    still the useful part, and the empty scope set is reported honestly rather
    than as an error.
    """
    ep = Endpoint("https://api.github.com/user", frozenset({"api.github.com"}))
    status, body, headers = _request(
        ep,
        headers={"Authorization": f"Bearer {value}",
                 "Accept": "application/vnd.github+json"},
        timeout=timeout,
    )
    if status == 401:
        return ProviderAnswer("invalid", note="GitHub rejected the token")
    if status != 200:
        return ProviderAnswer(
            "network_error", note=f"HTTP {status}: {scrub_response(body, value)}")

    doc = _json(body)
    scopes = _split_scopes(headers.get("x-oauth-scopes"))
    login = doc.get("login")
    return ProviderAnswer(
        "resolved",
        principal=f"github:{login}" if login else "github:<unknown>",
        scopes=scopes,
        note=("fine-grained token: scopes are per-resource and not exposed here"
              if not scopes else ""),
    )


def resolve_slack(value: str, timeout: float = DEFAULT_TIMEOUT) -> ProviderAnswer:
    """`auth.test` — identity plus granted scopes."""
    ep = Endpoint("https://slack.com/api/auth.test", frozenset({"slack.com"}))
    status, body, headers = _request(
        ep, headers={"Authorization": f"Bearer {value}"}, method="POST",
        body=b"", timeout=timeout)
    doc = _json(body)
    if status != 200:
        return ProviderAnswer("network_error", note=f"HTTP {status}")
    if not doc.get("ok"):
        err = str(doc.get("error", "unknown"))
        if err in ("invalid_auth", "not_authed", "account_inactive"):
            return ProviderAnswer("invalid", note=f"Slack: {err}")
        if err == "token_expired":
            return ProviderAnswer("expired", note="Slack: token_expired")
        return ProviderAnswer("network_error", note=f"Slack: {err}")
    return ProviderAnswer(
        "resolved",
        principal=f"slack:{doc.get('user') or doc.get('user_id') or '<unknown>'}",
        account=str(doc.get("team") or doc.get("team_id") or "") or None,
        scopes=_split_scopes(headers.get("x-oauth-scopes")),
    )


def resolve_google(value: str, timeout: float = DEFAULT_TIMEOUT) -> ProviderAnswer:
    """`tokeninfo` — the OAuth scope list for an access token.

    Uses the Authorization-header form rather than the query-string form so
    the token does not end up in an intermediary's access log.
    """
    ep = Endpoint("https://www.googleapis.com/oauth2/v3/tokeninfo",
                  frozenset({"www.googleapis.com", "oauth2.googleapis.com"}))
    status, body, _ = _request(
        ep, headers={"Authorization": f"Bearer {value}"}, timeout=timeout)
    if status in (400, 401):
        return ProviderAnswer("invalid", note="Google rejected the token")
    if status != 200:
        return ProviderAnswer("network_error", note=f"HTTP {status}")
    doc = _json(body)
    return ProviderAnswer(
        "resolved",
        principal=f"google:{doc.get('email') or doc.get('sub') or '<unknown>'}",
        account=str(doc.get("aud") or "") or None,
        scopes=_split_scopes(doc.get("scope")),
        expires_at=str(doc.get("exp")) if doc.get("exp") else None,
    )


def resolve_gitlab(value: str, timeout: float = DEFAULT_TIMEOUT) -> ProviderAnswer:
    """`personal_access_tokens/self` — scopes and expiry."""
    ep = Endpoint("https://gitlab.com/api/v4/personal_access_tokens/self",
                  frozenset({"gitlab.com"}))
    status, body, _ = _request(
        ep, headers={"PRIVATE-TOKEN": value}, timeout=timeout)
    if status in (401, 403):
        return ProviderAnswer("invalid", note="GitLab rejected the token")
    if status != 200:
        return ProviderAnswer("network_error", note=f"HTTP {status}")
    doc = _json(body)
    scopes = doc.get("scopes")
    return ProviderAnswer(
        "resolved",
        principal=f"gitlab:user/{doc.get('user_id', '<unknown>')}",
        scopes=tuple(str(s) for s in scopes) if isinstance(scopes, list) else (),
        expires_at=str(doc.get("expires_at")) if doc.get("expires_at") else None,
    )


def resolve_huggingface(value: str, timeout: float = DEFAULT_TIMEOUT) -> ProviderAnswer:
    ep = Endpoint("https://huggingface.co/api/whoami-v2",
                  frozenset({"huggingface.co"}))
    status, body, _ = _request(
        ep, headers={"Authorization": f"Bearer {value}"}, timeout=timeout)
    if status in (401, 403):
        return ProviderAnswer("invalid", note="Hugging Face rejected the token")
    if status != 200:
        return ProviderAnswer("network_error", note=f"HTTP {status}")
    doc = _json(body)
    auth = doc.get("auth") if isinstance(doc.get("auth"), dict) else {}
    token = auth.get("accessToken") if isinstance(auth.get("accessToken"), dict) else {}
    role = token.get("role")
    return ProviderAnswer(
        "resolved",
        principal=f"huggingface:{doc.get('name', '<unknown>')}",
        scopes=(str(role),) if role else (),
    )


def resolve_openai(value: str, timeout: float = DEFAULT_TIMEOUT) -> ProviderAnswer:
    """`GET /v1/models` — validity only.

    OpenAI exposes no scope introspection, so this answers one question:
    is the grant live or inert? That is still worth knowing — an invalid key
    is a declared grant that confers nothing.
    """
    ep = Endpoint("https://api.openai.com/v1/models", frozenset({"api.openai.com"}))
    status, body, _ = _request(
        ep, headers={"Authorization": f"Bearer {value}"}, timeout=timeout)
    if status == 401:
        return ProviderAnswer("invalid", note="OpenAI rejected the key")
    if status != 200:
        return ProviderAnswer("network_error", note=f"HTTP {status}")
    return ProviderAnswer(
        "resolved",
        principal="openai:<key holder>",
        note="OpenAI exposes no scope introspection; validity confirmed only",
    )


_STS_FIELD = {
    "arn": re.compile(r"<Arn>([^<]{1,512})</Arn>"),
    "account": re.compile(r"<Account>([^<]{1,64})</Account>"),
    "user_id": re.compile(r"<UserId>([^<]{1,128})</UserId>"),
}


def resolve_aws(
    access_key_id: str,
    secret_access_key: str,
    session_token: str | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> ProviderAnswer:
    """`sts:GetCallerIdentity` — which principal, in which account.

    The single most valuable resolution in the set: it converts an opaque key
    into the identity an injected agent would be acting as.

    The XML response is field-extracted by regex rather than parsed. Three
    known fields from a TLS-authenticated endpoint do not justify exposing an
    XML parser's attack surface.
    """
    body = "Action=GetCallerIdentity&Version=2011-06-15"
    host = "sts.amazonaws.com"
    ep = Endpoint(f"https://{host}/", frozenset({host}))
    try:
        headers = sign_post(
            access_key_id=access_key_id,
            secret_access_key=secret_access_key,
            session_token=session_token,
            host=host, region="us-east-1", service="sts", body=body,
        )
    except (TypeError, ValueError) as exc:
        return ProviderAnswer("network_error", note=f"could not sign request: {exc}")

    status, text, _ = _request(
        ep, headers=headers, method="POST", body=body.encode("utf-8"), timeout=timeout)

    if status == 403:
        low = text.lower()
        if "expired" in low:
            return ProviderAnswer("expired", note="AWS: security token expired")
        return ProviderAnswer(
            "invalid",
            note=f"AWS rejected the credentials: "
                 f"{scrub_response(text, secret_access_key)[:160]}")
    if status != 200:
        return ProviderAnswer("network_error", note=f"HTTP {status}")

    found = {k: (m.group(1) if (m := rx.search(text)) else None)
             for k, rx in _STS_FIELD.items()}
    return ProviderAnswer(
        "resolved",
        principal=found["arn"] or found["user_id"] or "aws:<unknown>",
        account=found["account"],
        note="identity only; run SimulatePrincipalPolicy for effective permissions",
    )


def resolve_oauth_introspection(
    value: str,
    endpoint_url: str,
    client_id: str,
    client_secret: str,
    timeout: float = DEFAULT_TIMEOUT,
) -> ProviderAnswer:
    """RFC 7662 token introspection against an explicitly configured endpoint.

    The host allowlist is the endpoint's own host: the operator nominated it,
    so it is pinned to itself rather than to a hardcoded list.
    """
    import base64
    from urllib.parse import urlencode

    host = (urlparse(endpoint_url).hostname or "").lower()
    if not host:
        return ProviderAnswer("network_error", note="introspection URL has no host")
    ep = Endpoint(endpoint_url, frozenset({host}))
    basic = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
    status, body, _ = _request(
        ep,
        headers={"Authorization": f"Basic {basic}",
                 "Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
        body=urlencode({"token": value}).encode(),
        timeout=timeout,
    )
    if status != 200:
        return ProviderAnswer("network_error", note=f"HTTP {status}")
    doc = _json(body)
    if not doc.get("active"):
        return ProviderAnswer("invalid", note="introspection reports token inactive")
    return ProviderAnswer(
        "resolved",
        principal=str(doc.get("sub") or doc.get("username") or "<unknown>"),
        account=str(doc.get("client_id") or "") or None,
        scopes=_split_scopes(doc.get("scope")),
        expires_at=str(doc.get("exp")) if doc.get("exp") else None,
    )


#: provider name -> single-value resolver. AWS is absent because it needs a
#: credential *set*, and is dispatched separately.
SINGLE_VALUE_RESOLVERS: dict[str, Callable[..., ProviderAnswer]] = {
    "github": resolve_github,
    "slack": resolve_slack,
    "google": resolve_google,
    "gitlab": resolve_gitlab,
    "huggingface": resolve_huggingface,
    "openai": resolve_openai,
}
