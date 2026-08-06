"""The value-shape gate for credential discovery.

Running the tool against a real process environment flagged 3 of 29 variables
and all three were false positives — a socket path, a bus address, a boolean —
because ``looks_sensitive`` scores the NAME, and a name is a weak signal.

An adversarial corpus (163 env-var shapes, 97 soundness-critical) then found 28
ways a naive "does the value look like a secret" gate silently DROPS a real
credential. The lesson, encoded below: you cannot clear on length, entropy,
hex-ness, UUID-ness, a leading slash, or whitespace — every one of those has a
real credential with that exact shape. So the gate defaults to secret and clears
only positively-benign shapes.

All values here are fabricated. The soundness-critical direction — never clear a
real secret — is the whole point, so those cases dominate.
"""

from __future__ import annotations

import pytest

from blastradius.creds.classify import value_looks_benign

# ---------------------------------------------------------------------------
# MUST STAY FLAGGED — value_looks_benign must return False. A True here is a
# silent credential miss, the fatal error.
# ---------------------------------------------------------------------------

SECRETS = [
    # the entropy trap: short / low-charset passwords are real passwords
    ("POSTGRES_PASSWORD", "s3cr3t"),
    ("PGPASSWORD", "hunter2"),
    ("MYSQL_PWD", "p@ss1"),
    ("REDIS_PASSWORD", "r3d1s"),
    ("DB_PASSWORD", "xqwphrmnbdkfsjzt"),          # 16 lowercase, diceware-ish
    ("ANSIBLE_VAULT_PASSWORD", "correcthorse"),   # a dictionary word IS the pw
    # the shape traps: real secrets shaped like non-secrets
    ("TWILIO_AUTH_TOKEN", "0a1b2c3d4e5f60718293a4b5c6d7e8f9"),  # 32-hex ≈ git SHA
    ("SECRET_KEY_BASE", "0a1b2c3d4e5f" * 10),                   # 120-hex, low charset
    ("API_KEY", "550e8400-e29b-41d4-a716-446655440000"),       # UUID as key
    ("SECRET_KEY", "/aB3xK9zLmQ7pR2sT"),                       # base64 secret, leading /
    ("TOTP_SECRET", "JBSWY3DPEHPK3PXP"),                       # base32 seed, all caps
    ("VNC_PASSWORD", "48261537"),                              # numeric, looks like a PID
    ("ADMIN_PASSWORD_HASH", "$2b$12$" + "A" * 22 + "u" + "B" * 30),  # bcrypt
    # named credentials with opaque values
    ("GITHUB_TOKEN", "ghp_" + "A1" * 18),
    ("VAULT_TOKEN", "hvs.CAESIExampleExampleExampleFAKE"),
    ("BW_SESSION", "A" * 43 + "="),                            # weak 'session' needle, real key
    ("CLIENT_SECRET", "FAKEfake0000ABCDefgh1234ijklMNOP5678qrst"),
    ("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),  # has '/', not a path
    ("AWS_SESSION_TOKEN", "FQoGZXIvYXdz" + "x" * 60),          # long base64 with '/'
    ("SESSION_KEY", "FAKEfake0000ABCD/efgh1234==" + "z" * 30),
    # credentials whose NAME looks innocent — caught by the value, not the name
    ("DATABASE_URL", "postgresql://svc:S3cr3tPw@db.internal:5432/prod"),
    ("REDIS_URL", "redis://:S3cr3tCache@cache.internal:6379/0"),
    ("SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/T00/B00/" + "X" * 24),
]

# ---------------------------------------------------------------------------
# MUST BE CLEARED — value_looks_benign must return True. These are the noise
# the gate exists to remove; a False here is only annoying, never dangerous.
# ---------------------------------------------------------------------------

BENIGN = [
    # the original three false positives from the live run
    ("SSH_AUTH_SOCK", "/run/user/1000/keyring/ssh"),
    ("DBUS_SESSION_BUS_ADDRESS", "unix:path=/run/user/1000/bus"),
    ("QT_ACCESSIBILITY", "1"),
    # more weak-needle non-secrets
    ("XAUTHORITY", "/run/user/1000/.mutter-Xwaylandauth.7GH2K1"),
    ("XDG_SESSION_TYPE", "wayland"),
    ("XDG_SESSION_CLASS", "user"),
    ("SSH_AGENT_PID", "4242"),
    ("AWS_DEFAULT_REGION", "us-east-1"),         # short-enum-ish / hostname
    ("GPG_TTY", "/dev/pts/3"),
    ("SESSION_MANAGER", "local/host:@/tmp/.ICE-unix/1234"),
    ("AUTH_METHOD", "oauth2"),
    ("ACCESS_MODE", "readonly"),
    ("KEY_FORMAT", "pem"),
]

#: Non-secrets the gate still flags, on purpose. Each has a STRONG needle in its
#: name (credential/password/token/…) with a benign value; the gate refuses to
#: clear anything under a strong needle by shape, because that is the rule that
#: keeps ``PGPASSWORD=hunter2`` flagged. Noise, not danger — disclosed honestly.
ACCEPTED_RESIDUAL_FALSE_POSITIVES = [
    ("CREDENTIAL_STORE_TYPE", "file"),
    ("PASSWORD_POLICY", "alphanumeric"),
    ("TOKENIZERS_PARALLELISM", "false"),
]


@pytest.mark.parametrize("name,value", SECRETS)
def test_real_secrets_are_never_cleared(name, value):
    assert value_looks_benign(name, value) is False, (
        f"{name} would be SILENTLY DROPPED — a real credential cleared as benign")


@pytest.mark.parametrize("name,value", BENIGN)
def test_benign_values_are_cleared(name, value):
    assert value_looks_benign(name, value) is True, (
        f"{name} stays flagged — a false positive the gate should remove")


@pytest.mark.parametrize("name,value", ACCEPTED_RESIDUAL_FALSE_POSITIVES)
def test_strong_needle_residual_false_positives_are_accepted(name, value):
    """Documented noise: a strong-needle name is not cleared by a benign value.

    This is the deliberate cost of the sound default. If one of these ever
    starts clearing, the same relaxation would clear a real password.
    """
    assert value_looks_benign(name, value) is False


def test_empty_value_is_benign():
    assert value_looks_benign("API_KEY", "") is True
    assert value_looks_benign("AWS_SESSION_TOKEN", "") is True


def test_strong_needle_never_cleared_by_shape():
    """A strong-needle name clears only on empty/path/socket — never on shape."""
    # boolean, short word, numeric: all benign shapes, but under 'password'/'secret'
    # they must NOT clear.
    assert value_looks_benign("DB_PASSWORD", "true") is False
    assert value_looks_benign("API_SECRET", "prod") is False
    assert value_looks_benign("AUTH_TOKEN", "12345") is False
    # ...but an empty or path value still clears even under a strong needle.
    assert value_looks_benign("DB_PASSWORD", "") is True
    assert value_looks_benign("TLS_KEY_FILE", "/etc/ssl/private/server.key") is True


def test_a_lone_slash_value_is_not_a_path():
    """A base64 secret can begin with '/'; one segment is not a filesystem path."""
    assert value_looks_benign("SECRET_KEY", "/aB3xK9zLmQ7pR2sT") is False
    assert value_looks_benign("CONFIG_DIR", "/etc/myapp/conf.d") is True


def test_webhook_secret_in_url_path_is_not_a_plain_url():
    """A URL with no userinfo can still carry its secret in the path."""
    assert value_looks_benign(
        "NOTIFY_URL", "https://hooks.slack.com/services/T0/B0/" + "X" * 24) is False
    assert value_looks_benign("API_BASE_URL", "https://api.example.com/v1") is True


# ---------------------------------------------------------------------------
# The name-blind arm: a value that carries a credential is flagged even when
# the NAME trips no needle. Without it, DATABASE_URL=postgres://u:pw@h is a
# silent miss.
# ---------------------------------------------------------------------------

from blastradius.creds.classify import value_is_credential_shaped  # noqa: E402


@pytest.mark.parametrize("value", [
    "postgresql://svc:S3cr3tPw@db.internal:5432/prod",
    "redis://:S3cr3tCache@cache.internal:6379/0",
    "mongodb+srv://u:M0ngoPw@cluster0.mongodb.net/prod",
    "amqp://guest:guestpw@rabbit.internal:5672/",
    "https://ingest.example.com/events?api_key=FAKEfake0000ABCDefgh1234",
    "https://hooks.slack.com/services/T0/B0/" + "X" * 24,
])
def test_credential_shaped_values_are_flagged_regardless_of_name(value):
    assert value_is_credential_shaped(value) is True


@pytest.mark.parametrize("value", [
    "https://api.example.com/v1",       # a plain API base URL — no credential
    "https://server.example/mcp",       # an MCP endpoint address
    "/run/user/1000/bus",               # not a URL at all
    "wayland",
    "",
])
def test_credential_free_values_are_not_flagged_by_shape(value):
    assert value_is_credential_shaped(value) is False
