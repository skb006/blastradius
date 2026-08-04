"""AWS Signature Version 4, stdlib only.

Needed because ``sts:GetCallerIdentity`` is the one call that turns an opaque
AWS key into the fact that matters — which principal, in which account, an
injected agent would be acting as. There is no unsigned equivalent, and
pulling in botocore for one request would put a large supply chain behind a
tool whose selling point is not having one.

Implements the documented algorithm:

    canonical request -> string to sign -> derived signing key -> signature

Deliberately narrow: POST, form-encoded body, no query string. Enough for
GetCallerIdentity and nothing more, because a general signer is a much
larger thing to keep correct.
"""

from __future__ import annotations

import hashlib
import hmac
from datetime import datetime, timezone

ALGORITHM = "AWS4-HMAC-SHA256"


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hmac(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def derive_signing_key(secret: str, date_stamp: str, region: str, service: str) -> bytes:
    """The four-step key derivation chain from the SigV4 spec."""
    k_date = _hmac(f"AWS4{secret}".encode("utf-8"), date_stamp)
    k_region = _hmac(k_date, region)
    k_service = _hmac(k_region, service)
    return _hmac(k_service, "aws4_request")


def sign_post(
    *,
    access_key_id: str,
    secret_access_key: str,
    session_token: str | None,
    host: str,
    region: str,
    service: str,
    body: str,
    now: datetime | None = None,
) -> dict[str, str]:
    """Return the headers required to authenticate a form-encoded POST.

    The credential material is used here and nowhere else; the returned dict
    contains an Authorization header, which is a derived signature rather
    than the secret itself.
    """
    now = now or datetime.now(timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")

    payload_hash = _sha256_hex(body.encode("utf-8"))
    content_type = "application/x-www-form-urlencoded; charset=utf-8"

    headers: dict[str, str] = {
        "content-type": content_type,
        "host": host,
        "x-amz-date": amz_date,
    }
    if session_token:
        headers["x-amz-security-token"] = session_token

    signed_headers = ";".join(sorted(headers))
    canonical_headers = "".join(
        f"{k}:{headers[k].strip()}\n" for k in sorted(headers)
    )
    canonical_request = "\n".join([
        "POST",
        "/",
        "",                 # no query string
        canonical_headers,
        signed_headers,
        payload_hash,
    ])

    scope = f"{date_stamp}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join([
        ALGORITHM,
        amz_date,
        scope,
        _sha256_hex(canonical_request.encode("utf-8")),
    ])

    signing_key = derive_signing_key(secret_access_key, date_stamp, region, service)
    signature = hmac.new(
        signing_key, string_to_sign.encode("utf-8"), hashlib.sha256
    ).hexdigest()

    authorization = (
        f"{ALGORITHM} Credential={access_key_id}/{scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )

    out = {
        "Content-Type": content_type,
        "X-Amz-Date": amz_date,
        "Authorization": authorization,
    }
    if session_token:
        out["X-Amz-Security-Token"] = session_token
    return out
