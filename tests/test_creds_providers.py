"""Provider resolvers: host pinning, response scrubbing, SigV4, parsing.

No test here touches the network. ``_request`` is replaced so responses are
deterministic, and the pinning test asserts the refusal happens *before* a
socket would be opened.
"""

from __future__ import annotations

import pytest

from blastradius.creds import providers as P
from blastradius.creds.sigv4 import derive_signing_key, sign_post


# --- SigV4 ------------------------------------------------------------------

def test_signing_key_matches_aws_published_vector():
    """Vector from AWS's own SigV4 documentation."""
    key = derive_signing_key(
        "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "20150830", "us-east-1", "iam")
    assert key.hex() == "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9"


def test_sign_post_produces_expected_header_shape():
    from datetime import datetime, timezone
    headers = sign_post(
        access_key_id="AKIDEXAMPLE",
        secret_access_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        session_token=None, host="sts.amazonaws.com", region="us-east-1",
        service="sts", body="Action=GetCallerIdentity&Version=2011-06-15",
        now=datetime(2015, 8, 30, 12, 36, tzinfo=timezone.utc))
    auth = headers["Authorization"]
    assert auth.startswith("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/sts/aws4_request")
    assert "SignedHeaders=content-type;host;x-amz-date" in auth
    assert headers["X-Amz-Date"] == "20150830T123600Z"
    assert "X-Amz-Security-Token" not in headers


def test_sign_post_includes_session_token_when_present():
    headers = sign_post(
        access_key_id="ASIA", secret_access_key="s", session_token="tok",
        host="sts.amazonaws.com", region="us-east-1", service="sts", body="x")
    assert headers["X-Amz-Security-Token"] == "tok"
    assert "x-amz-security-token" in headers["Authorization"]


def test_signature_changes_with_body():
    kw = dict(access_key_id="A", secret_access_key="s", session_token=None,
              host="sts.amazonaws.com", region="us-east-1", service="sts")
    from datetime import datetime, timezone
    now = datetime(2020, 1, 1, tzinfo=timezone.utc)
    a = sign_post(body="one", now=now, **kw)["Authorization"]
    b = sign_post(body="two", now=now, **kw)["Authorization"]
    assert a != b


# --- host pinning -----------------------------------------------------------

def test_endpoint_rejects_unpinned_host():
    ep = P.Endpoint("https://evil.example.com/steal", frozenset({"api.github.com"}))
    with pytest.raises(P.HostNotPinned, match="refusing to send a credential"):
        ep.check()


def test_endpoint_accepts_pinned_host():
    P.Endpoint("https://api.github.com/user", frozenset({"api.github.com"})).check()


def test_request_checks_pin_before_opening_a_socket(monkeypatch):
    opened = []
    monkeypatch.setattr(P.urllib.request, "urlopen",
                        lambda *a, **k: opened.append(1))
    ep = P.Endpoint("https://elsewhere.test/x", frozenset({"api.github.com"}))
    with pytest.raises(P.HostNotPinned):
        P._request(ep, headers={})
    assert opened == [], "the pin must refuse before any connection attempt"


def test_every_provider_pins_to_its_own_issuer(monkeypatch):
    """No resolver may be pointed at an arbitrary host."""
    seen: list[str] = []

    def fake(ep, **kw):
        ep.check()
        seen.append(ep.host())
        return 200, "{}", {}

    monkeypatch.setattr(P, "_request", fake)
    for name, fn in P.SINGLE_VALUE_RESOLVERS.items():
        fn("tok")
    assert set(seen) == {
        "api.github.com", "slack.com", "www.googleapis.com",
        "gitlab.com", "huggingface.co", "api.openai.com",
    }


# --- scrubbing --------------------------------------------------------------

def test_scrub_removes_echoed_credential():
    body = '{"error":"bad token ghp_SUPERSECRETVALUE"}'
    assert "SUPERSECRET" not in P.scrub_response(body, "ghp_SUPERSECRETVALUE")


def test_scrub_removes_truncated_echo():
    body = '{"error":"token ghp_SUPER... rejected"}'
    out = P.scrub_response(body, "ghp_SUPERSECRETVALUE")
    assert "ghp_SUPER" not in out


def test_scrub_tolerates_no_secret():
    assert P.scrub_response("plain body", None) == "plain body"


def test_scrub_ignores_implausibly_short_secrets():
    assert P.scrub_response("aaa bbb", "ab") == "aaa bbb"


# --- provider parsing --------------------------------------------------------

def _mock(monkeypatch, status, body, headers=None):
    monkeypatch.setattr(
        P, "_request", lambda ep, **kw: (ep.check(), (status, body, headers or {}))[1])


def test_github_resolved_with_scopes(monkeypatch):
    _mock(monkeypatch, 200, '{"login":"octocat"}', {"x-oauth-scopes": "repo, read:org"})
    a = P.resolve_github("ghp_x")
    assert a.status == "resolved"
    assert a.principal == "github:octocat"
    assert a.scopes == ("repo", "read:org")


def test_github_fine_grained_has_no_scope_header(monkeypatch):
    _mock(monkeypatch, 200, '{"login":"octocat"}', {})
    a = P.resolve_github("github_pat_x")
    assert a.status == "resolved" and a.scopes == ()
    assert "fine-grained" in a.note


def test_github_invalid(monkeypatch):
    _mock(monkeypatch, 401, '{"message":"Bad credentials"}')
    assert P.resolve_github("ghp_x").status == "invalid"


def test_github_other_error_is_network_error(monkeypatch):
    _mock(monkeypatch, 503, "upstream down")
    assert P.resolve_github("ghp_x").status == "network_error"


def test_slack_resolved(monkeypatch):
    _mock(monkeypatch, 200, '{"ok":true,"user":"bot","team":"Acme"}',
          {"x-oauth-scopes": "chat:write,files:read"})
    a = P.resolve_slack("xoxb-x")
    assert a.principal == "slack:bot" and a.account == "Acme"
    assert a.scopes == ("chat:write", "files:read")


@pytest.mark.parametrize("err,status", [
    ("invalid_auth", "invalid"),
    ("token_expired", "expired"),
    ("ratelimited", "network_error"),
])
def test_slack_error_mapping(monkeypatch, err, status):
    _mock(monkeypatch, 200, '{"ok":false,"error":"%s"}' % err)
    assert P.resolve_slack("xoxb-x").status == status


def test_google_resolved(monkeypatch):
    _mock(monkeypatch, 200,
          '{"email":"a@b.com","scope":"https://www.googleapis.com/auth/drive","exp":"1700"}')
    a = P.resolve_google("ya29.x")
    assert a.principal == "google:a@b.com"
    assert a.scopes == ("https://www.googleapis.com/auth/drive",)
    assert a.expires_at == "1700"


def test_google_invalid(monkeypatch):
    _mock(monkeypatch, 400, '{"error":"invalid_token"}')
    assert P.resolve_google("ya29.x").status == "invalid"


def test_gitlab_resolved(monkeypatch):
    _mock(monkeypatch, 200, '{"user_id":42,"scopes":["api","read_user"],"expires_at":"2027-01-01"}')
    a = P.resolve_gitlab("glpat-x")
    assert a.principal == "gitlab:user/42"
    assert a.scopes == ("api", "read_user")
    assert a.expires_at == "2027-01-01"


def test_huggingface_resolved(monkeypatch):
    _mock(monkeypatch, 200, '{"name":"abd","auth":{"accessToken":{"role":"write"}}}')
    a = P.resolve_huggingface("hf_x")
    assert a.principal == "huggingface:abd" and a.scopes == ("write",)


def test_openai_validity_only(monkeypatch):
    _mock(monkeypatch, 200, '{"data":[]}')
    a = P.resolve_openai("sk-x")
    assert a.status == "resolved" and a.scopes == ()
    assert "no scope introspection" in a.note


def test_openai_invalid(monkeypatch):
    _mock(monkeypatch, 401, "{}")
    assert P.resolve_openai("sk-x").status == "invalid"


# --- AWS --------------------------------------------------------------------

STS_OK = """<GetCallerIdentityResponse><GetCallerIdentityResult>
<Arn>arn:aws:iam::123456789012:user/deploy</Arn>
<UserId>AIDACKCEVSQ6C2EXAMPLE</UserId>
<Account>123456789012</Account>
</GetCallerIdentityResult></GetCallerIdentityResponse>"""


def test_aws_resolved(monkeypatch):
    _mock(monkeypatch, 200, STS_OK)
    a = P.resolve_aws("AKIA...", "secret")
    assert a.status == "resolved"
    assert a.principal == "arn:aws:iam::123456789012:user/deploy"
    assert a.account == "123456789012"


def test_aws_invalid(monkeypatch):
    _mock(monkeypatch, 403, "<Error><Code>InvalidClientTokenId</Code></Error>")
    assert P.resolve_aws("AKIA", "s").status == "invalid"


def test_aws_expired_session(monkeypatch):
    _mock(monkeypatch, 403, "<Error><Code>ExpiredToken</Code></Error>")
    assert P.resolve_aws("ASIA", "s", "tok").status == "expired"


def test_aws_error_body_is_scrubbed_of_the_secret(monkeypatch):
    _mock(monkeypatch, 403, "<Error>rejected key SUPERSECRETAWSKEY here</Error>")
    a = P.resolve_aws("AKIA", "SUPERSECRETAWSKEY")
    assert "SUPERSECRET" not in a.note


# --- RFC 7662 ---------------------------------------------------------------

def test_oauth_introspection_active(monkeypatch):
    _mock(monkeypatch, 200, '{"active":true,"sub":"user1","scope":"read write","exp":9}')
    a = P.resolve_oauth_introspection(
        "tok", "https://idp.example.com/introspect", "cid", "csec")
    assert a.status == "resolved" and a.scopes == ("read", "write")


def test_oauth_introspection_inactive(monkeypatch):
    _mock(monkeypatch, 200, '{"active":false}')
    a = P.resolve_oauth_introspection(
        "tok", "https://idp.example.com/introspect", "cid", "csec")
    assert a.status == "invalid"


def test_oauth_introspection_rejects_hostless_url():
    a = P.resolve_oauth_introspection("tok", "not-a-url", "cid", "csec")
    assert a.status == "network_error"
