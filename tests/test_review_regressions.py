"""Regressions from the two-team adversarial review.

Every test here corresponds to a defect that was *demonstrated* against the
shipped code, not one that was imagined. They are grouped by the invariant they
defend, because that is what makes them worth keeping: each one pins a claim the
README makes.

The mutation-testing pass that accompanied this review found that several
security guards had no test that could fail if the guard were deleted. Where
that was true the test below deletes the guard's effect and asserts the
consequence, rather than asserting on a value the test itself constructed.
"""

from __future__ import annotations

import contextlib
import http.server
import json
import os
import socket
import threading
import urllib.error

import pytest

from blastradius.creds import providers as P
from blastradius.discovery import discover
from blastradius.mcp.transport import HttpTransport, ProtocolError, Unreachable
from blastradius.mcp.jsonrpc import Request
from blastradius.model import Origin, ProbeResult, ServerSpec, ToolSpec
from blastradius.redact import REDACTED, scrub_argv, scrub_argv_with_keys, scrub_url

# ---------------------------------------------------------------------------
# "never store or print a credential value"
#
# Redaction used to be keyed on the *config key name*. Two shapes have no key
# name to match on — a secret inside a URL, and a secret inside an argv element
# — so both flowed verbatim into ServerSpec, to_json(), and stdout.
# ---------------------------------------------------------------------------

CANARIES = {
    "smithery": {"url": "https://s.example/mcp?api_key=CANARY_A"},
    "basicauth": {"url": "https://alice:CANARY_B@vendor.example/mcp"},
    "remote": {"command": "npx", "args": [
        "mcp-remote", "https://x.example/mcp",
        "--header", "Authorization: Bearer CANARY_C"]},
    "dockered": {"command": "docker", "args": [
        "run", "-i", "-e", "GITHUB_TOKEN=CANARY_D", "img"]},
    "pg": {"command": "npx", "args": [
        "server-postgres", "postgresql://svc:CANARY_E@db.internal:5432/prod"]},
    "urlflag": {"command": "npx", "args": [
        "mcp", "--url", "https://u:CANARY_F@h.example/mcp"]},
    "classic": {"command": "srv", "args": ["--token", "CANARY_G"]},
    "envvar": {"command": "srv", "env": {"GITHUB_TOKEN": "CANARY_H"}},
}


@pytest.fixture
def canary_inventory(tmp_path):
    cfg = tmp_path / ".mcp.json"
    cfg.write_text(json.dumps({"mcpServers": CANARIES}))
    return discover(home=tmp_path / "nohome", extra_paths=[cfg])


@pytest.mark.parametrize("canary", sorted(f"CANARY_{c}" for c in "ABCDEFGH"))
def test_no_canary_survives_into_the_model_or_its_serialisation(
    canary_inventory, canary
):
    """The whole point of boundary redaction: the value never enters an artifact."""
    blob = json.dumps(canary_inventory.to_json())
    assert canary not in blob, f"{canary} reached the serialised inventory"
    for spec in canary_inventory.deduped():
        assert canary not in repr(spec), f"{canary} reachable via repr()"
        assert canary not in json.dumps(spec.to_json())


def test_probing_still_works_because_the_raw_target_survives_out_of_band(
    canary_inventory,
):
    """Redaction must not break the tool.

    `url`/`args` are redacted, so the connect target lives in a field that
    `to_json` drops. If this ever regresses to reading the redacted value, the
    prober would dial `https://alice@vendor.example/mcp` and silently fail to
    authenticate — a redaction fix that breaks probing is not a fix.
    """
    by_name = {s.name: s for s in canary_inventory.deduped()}
    assert by_name["basicauth"].dial_url == "https://alice:CANARY_B@vendor.example/mcp"
    assert "CANARY_G" in by_name["classic"].dial_args
    # ...and none of that appears in the serialised form.
    assert "CANARY_B" not in json.dumps(by_name["basicauth"].to_json())


def test_url_and_argv_credentials_are_counted_as_carried(canary_inventory):
    """A credential in a URL or argv is still authority the server holds.

    If it does not reach `credential_keys`, `delegation.classify_server` sees no
    static credential and can classify a confused deputy as caller-bounded.
    """
    by_name = {s.name: s for s in canary_inventory.deduped()}
    for name in ("smithery", "basicauth", "remote", "dockered", "pg", "urlflag"):
        assert by_name[name].credential_keys, (
            f"{name} carries a credential but declares none")


@pytest.mark.parametrize("url,expect_key", [
    ("https://h/mcp?api_key=S", "api_key"),
    ("https://h/mcp?token=S&page=2", "token"),
    ("https://u:pw@h/mcp", "<url-password>"),
])
def test_scrub_url_reports_what_it_removed(url, expect_key):
    safe, keys = scrub_url(url)
    assert "S" not in safe.replace("https", "").replace("mcp", "")
    assert expect_key in keys


def test_scrub_url_leaves_a_clean_url_alone():
    url = "https://server.example/mcp?page=2"
    assert scrub_url(url) == (url, ())


def test_scrub_argv_keeps_the_header_name_but_drops_its_value():
    """`Authorization` is a blast-radius fact; the bearer token is not."""
    out = scrub_argv(["-H", "Authorization: Bearer ghp_x"])
    assert out == ("-H", f"Authorization: {REDACTED}")


def test_scrub_argv_handles_a_positional_connection_string():
    """No flag precedes it, so flag-anchored redaction could never catch it."""
    out = scrub_argv(["server-postgres", "postgresql://svc:pw@db/prod"])
    assert out == ("server-postgres", "postgresql://svc@db/prod")


def test_scrub_argv_names_what_it_redacted():
    _out, keys = scrub_argv_with_keys(["-e", "GITHUB_TOKEN=ghp_x", "--token", "y"])
    assert "GITHUB_TOKEN" in keys and "token" in keys


# ---------------------------------------------------------------------------
# "a credential only ever reaches its own issuer"
#
# Endpoint.check() validated the declared URL, then handed the request to
# urllib's default opener, which follows redirects and honours proxy env vars.
# Both deliver the credential, with its Authorization header, somewhere else.
# ---------------------------------------------------------------------------

class _Recorder(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        type(self).seen.append(self.headers.get("Authorization"))
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'{"login":"x"}')

    def log_message(self, *a):  # noqa: A002
        pass


@contextlib.contextmanager
def _serve(handler, host="127.0.0.1"):
    """A throwaway HTTP server, fully torn down.

    `server_close()` matters as much as `shutdown()`: the suite runs with
    `filterwarnings = ["error"]`, so a leaked listening socket fails the test.
    """
    srv = http.server.HTTPServer((host, 0), handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield srv
    finally:
        srv.shutdown()
        srv.server_close()
        t.join(timeout=5)


def test_a_redirect_off_the_pinned_host_is_refused_not_followed():
    sink = type("Sink", (_Recorder,), {"seen": []})
    with _serve(sink, "127.0.0.2") as sink_srv:
        class Redirector(http.server.BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                self.send_response(302)
                self.send_header(
                    "Location", f"http://127.0.0.2:{sink_srv.server_port}/steal")
                self.end_headers()

            def log_message(self, *a):  # noqa: A002
                pass

        with _serve(Redirector) as issuer:
            ep = P.Endpoint(f"http://127.0.0.1:{issuer.server_port}/user",
                            frozenset({"127.0.0.1"}))
            with pytest.raises(P.HostNotPinned):
                P._request(ep, headers={"Authorization": "Bearer ghp_canary"},
                           timeout=5)
        assert sink.seen == [], "credential reached a host the pin never approved"


def test_proxy_environment_cannot_reroute_a_credential(monkeypatch):
    sink = type("Sink2", (_Recorder,), {"seen": []})
    with _serve(sink, "127.0.0.2") as sink_srv:
        monkeypatch.setenv("HTTP_PROXY", f"http://127.0.0.2:{sink_srv.server_port}")
        monkeypatch.setenv("ALL_PROXY", f"http://127.0.0.2:{sink_srv.server_port}")
        # Port 9 (discard) is closed, so the only way a request succeeds is via
        # the proxy — which is exactly what must not happen.
        ep = P.Endpoint("http://127.0.0.1:9/user", frozenset({"127.0.0.1"}))
        with pytest.raises((urllib.error.URLError, OSError)):
            P._request(ep, headers={"Authorization": "Bearer ghp_canary"}, timeout=3)
        assert sink.seen == [], "proxy env var exfiltrated the credential"


# ---------------------------------------------------------------------------
# soundness: the prover must never under-state reach
# ---------------------------------------------------------------------------

segval = pytest.importorskip("segval", reason="prove is an optional extra")

from blastradius.creds.model import (  # noqa: E402
    Classification, CredentialRef, CredentialReport, Resolution,
)
from blastradius.prove.encode import _zone_name, encode  # noqa: E402
from blastradius.prove.engine import prove  # noqa: E402
from blastradius.prove.graph import (  # noqa: E402
    READ_ONLY_SCOPES, build_graph, scope_capability,
)
from blastradius.prove.policy import default_policy  # noqa: E402

ORIGIN = Origin("/cfg/.mcp.json", "mcpServers.github")
WRITE_TOOL = ToolSpec("create_issue", read_only=False, destructive=True)


def _spec(name="github", **kw):
    return ServerSpec(name=name, transport="stdio", origin=ORIGIN,
                      command="npx", **kw)


def _creds(scope, server_name="github"):
    return CredentialReport(resolutions=[Resolution(
        ref=CredentialRef("T", ORIGIN, "config_env", server_name=server_name),
        classification=Classification("github", "classic_pat", "exact"),
        status="resolved", principal="acme-bot", scopes=(scope,))])


@pytest.mark.parametrize("scope", [
    "public_repo", "gist", "write:discussion",
    # The entire GitHub fine-grained PAT vocabulary — none of it used the
    # classic scope names the old WRITE_SCOPES allowlist enumerated.
    "contents:write", "issues:write", "pull_requests:write",
    "administration:write",
    # Anything an issuer mints that nobody has thought about yet.
    "some_vendor_scope_invented_next_year",
])
def test_an_unrecognised_scope_counts_as_write(scope):
    """REGRESSION: the classifier used a WRITE allowlist and defaulted to read.

    Every write scope nobody enumerated became a read edge, deleting the write
    hop and making `prove` emit PROVEN UNREACHABLE for a plainly reachable
    write. A false proof of absence is the one output this tool must not
    produce, so the default has to be the unbounded side.
    """
    assert scope_capability(scope) == "write"
    s = _spec()
    report = prove(
        build_graph([s], [ProbeResult(server=s, status="ok", tools=(WRITE_TOOL,))],
                    _creds(scope)),
        default_policy())
    assert report.violations, f"scope {scope!r} produced a false proof of absence"


@pytest.mark.parametrize("scope", sorted(READ_ONLY_SCOPES)[:8])
def test_read_only_scopes_are_still_classified_read(scope):
    """The inversion must not make everything write — that would be useless."""
    assert scope_capability(scope) == "read"


def test_zone_names_are_injective():
    """REGRESSION: the sanitiser was many-to-one.

    `mcp:a b` and `mcp:a_b` both spelled `mcp__a_b`, so `encode()`'s
    last-write-wins dictionaries merged two nodes into one — one node's grants
    became the other's and the loser's rules were evaluated on a device that no
    longer existed.
    """
    colliding = ["mcp:evil:svc", "mcp:evil__svc", "mcp:gh docs", "mcp:gh_docs",
                 "principal:gitlab:user/12", "principal:gitlab:user_12"]
    names = [_zone_name(n, i) for i, n in enumerate(colliding)]
    assert len(set(names)) == len(names)


def test_two_nodes_that_sanitise_alike_keep_separate_grants():
    """End-to-end version of the above, through the real encoder."""
    a, b = _spec("gh docs"), _spec("gh_docs")
    g = build_graph(
        [a, b],
        [ProbeResult(server=a, status="ok", tools=(ToolSpec("search", read_only=True),)),
         ProbeResult(server=b, status="ok", tools=(WRITE_TOOL,))],
        None)
    enc = encode(g)
    zones = {enc.zone(n) for n in g.nodes}
    assert len(zones) == len(g.nodes), "two nodes share a zone"


def test_a_second_server_with_the_same_config_name_is_not_assumed_probed():
    """REGRESSION: the probe lookup was keyed on `name`.

    Two projects each declaring a server called "issues" is ordinary. The
    unprobed one inherited the probed one's surface and contributed no
    `<unknown>` write edge at all — a silent under-approximation.
    """
    probed = _spec("issues")
    unprobed = ServerSpec(name="issues", transport="http", origin=ORIGIN,
                          url="https://prod.internal/mcp")
    g = build_graph(
        [probed, unprobed],
        [ProbeResult(server=probed, status="ok",
                     tools=(ToolSpec("search", read_only=True),))],
        None)
    assert any(e.capability == "write" and e.inferred for e in g.edges), (
        "the unprobed endpoint vanished from the graph")
    assert g.notes, "and nothing said so"


def test_a_truncated_enumeration_is_treated_as_an_unknown_surface():
    """REGRESSION: `_paginate` gave up at 50 pages and returned `ok`.

    Tools past the budget were invisible, and the prover happily proved
    absence over a surface it had only partly seen.
    """
    s = _spec()
    truncated = ProbeResult(server=s, status="truncated",
                            tools=(ToolSpec("search", read_only=True),))
    assert not truncated.recovered
    g = build_graph([s], [truncated], None)
    assert any(e.operation == "<unknown>" and e.capability == "write"
               for e in g.edges)


def test_pagination_stops_on_a_repeating_cursor_and_says_so():
    """A server that loops us must not look like a server that finished."""
    from blastradius.mcp.client import McpClient

    class Looping:
        def exchange(self, request):
            return json.dumps({
                "jsonrpc": "2.0", "id": request.id,
                "result": {"tools": [{"name": "t"}], "nextCursor": "same"}})

        def notify(self, request):
            pass

        def close(self):
            pass

    c = McpClient(Looping())
    c.capabilities = ("tools",)
    c.list_tools()
    assert "tools/list" in c.truncated


# ---------------------------------------------------------------------------
# reliability: a hostile or broken peer must not take the scan down
# ---------------------------------------------------------------------------

def test_a_malformed_http_response_is_contained_not_raised():
    """REGRESSION: http.client exceptions are not OSError.

    `IncompleteRead`/`BadStatusLine` descend from Exception, so they escaped
    `_post`'s handlers, escaped `probe_server`, and killed the whole scan.
    """
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(5)

    def serve():
        while True:
            try:
                conn, _ = sock.accept()
            except OSError:
                return
            try:
                conn.recv(65536)
                conn.sendall(b"NOT-HTTP AT ALL\r\n\r\n")
                conn.close()
            except OSError:
                pass

    threading.Thread(target=serve, daemon=True).start()
    t = HttpTransport(f"http://127.0.0.1:{sock.getsockname()[1]}/mcp", timeout=5)
    try:
        with pytest.raises((ProtocolError, Unreachable)):
            t.exchange(Request("ping", None, 1))
    finally:
        sock.close()


def test_an_endless_response_body_is_capped():
    """REGRESSION: `resp.read()` streamed to EOF — measured at ~900 MiB in 10s."""
    class Flood(http.server.BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            try:
                while True:
                    self.wfile.write(b"A" * 65536)
            except OSError:
                pass

        def log_message(self, *a):  # noqa: A002
            pass

    with _serve(Flood) as srv:
        t = HttpTransport(f"http://127.0.0.1:{srv.server_port}/mcp", timeout=20)
        with pytest.raises(ProtocolError, match="exceeded"):
            t.exchange(Request("ping", None, 1))


# ---------------------------------------------------------------------------
# claim integrity
# ---------------------------------------------------------------------------

def test_the_banner_does_not_deny_what_resolve_credentials_does():
    """The banner claimed it "never reads a credential value". Stage 3 does."""
    from blastradius.cli import BANNER

    lowered = BANNER.lower()
    assert "never reads a credential value" not in lowered
    assert "resolve-credentials" in lowered, (
        "the banner must name the one mode that does read values")


@pytest.mark.parametrize("url", [
    "file:///etc/passwd", "file:///tmp/x", "ftp://h/x", "gopher://h/x", "/no/scheme",
])
def test_only_http_schemes_are_dialled(url):
    """REGRESSION: a `file://` URL in a config made the prober read a local file.

    urllib's default opener handles `file:` and `ftp:`. The URL comes from a
    config the tool does not control — that is the threat model — so an
    attacker who could drop a config could read an arbitrary local file and
    carry its contents into the report.
    """
    with pytest.raises(Unreachable, match="only http and https"):
        HttpTransport(url, timeout=1)


def test_a_file_url_cannot_leak_local_contents_through_a_probe(tmp_path):
    secret = tmp_path / "secret.txt"
    secret.write_text("LOCAL_FILE_CONTENTS_XYZ")
    from blastradius.probe import probe_server

    spec = ServerSpec(name="evil", transport="http", origin=Origin("/c", ""),
                      url=f"file://{secret}")
    result = probe_server(spec, allow_spawn=False, timeout=5)
    assert "LOCAL_FILE_CONTENTS_XYZ" not in json.dumps(result.to_json())


# ---------------------------------------------------------------------------
# "never executes config"
#
# Mutation testing found that BOTH spawn guards could be deleted individually
# with the whole suite still green: they are mutually redundant, and the suite
# only pinned their conjunction. A refactor could remove either as dead code
# with tests passing, leaving one guard where the README promises two.
# ---------------------------------------------------------------------------

def test_stdio_transport_itself_refuses_without_optin():
    """Guard 1, in isolation: the transport must not spawn on its own say-so."""
    from blastradius.mcp.transport import StdioTransport

    with pytest.raises(PermissionError, match="--allow-spawn"):
        StdioTransport("echo", ("hi",), allow_spawn=False)


def test_probe_refuses_before_it_ever_builds_a_transport(monkeypatch):
    """Guard 2, in isolation: probe_server must short-circuit *earlier*.

    Asserting only on the returned status cannot distinguish this guard from
    the transport's, because both produce `skipped`. Blowing up inside
    `_build_transport` is what makes the two separable.
    """
    import blastradius.probe as probe_mod

    def explode(*a, **kw):
        raise AssertionError("probe_server reached the transport layer")

    monkeypatch.setattr(probe_mod, "_build_transport", explode)
    spec = ServerSpec(name="s", transport="stdio", origin=Origin("/c", ""),
                      command="echo", args=("hi",))
    result = probe_mod.probe_server(spec, allow_spawn=False, timeout=1)
    assert result.status == "skipped"
    assert any(d.code == "probe.skipped_stdio" for d in result.diagnostics)


# ---------------------------------------------------------------------------
# Medium findings: crashes that discard the whole scan, and flags that lie
# ---------------------------------------------------------------------------

def test_an_out_of_range_port_does_not_abort_the_scan():
    """REGRESSION: `parts.port` raises, and the traceback killed everything.

    Worse, it exited 1 — indistinguishable from a normal run that found
    problems. A malformed port is a fact about one server, not a reason to
    stop auditing the other twenty.
    """
    spec = ServerSpec(name="x", transport="http", origin=Origin("/c", ""),
                      url="http://127.0.0.1:99999/mcp")
    assert spec.logical_identity  # must not raise


def test_deeply_nested_json_is_a_diagnostic_not_a_crash(tmp_path):
    """REGRESSION: RecursionError escaped _load_json and ended the scan."""
    cfg = tmp_path / "deep.json"
    cfg.write_text('{"a":' * 60000 + "1" + "}" * 60000)
    inv = discover(home=tmp_path / "nohome", extra_paths=[cfg])
    assert any(d.code == "config.malformed" for d in inv.diagnostics)


def test_a_broken_yaml_policy_is_a_policy_error(tmp_path):
    """REGRESSION: yaml.YAMLError surfaced as a raw traceback."""
    from blastradius.prove.policy import PolicyError, load_policy

    p = tmp_path / "bad.yaml"
    p.write_text("rules: [\n  unclosed")
    with pytest.raises(PolicyError, match="invalid YAML"):
        load_policy(p)


@pytest.mark.parametrize("url,expected", [
    ("http://127.0.0.1:9/mcp", True),
    ("http://localhost:9/mcp", True),
    ("http://[::1]:9/mcp", True),
    ("http://127.5.5.5:9/mcp", True),
    # REGRESSION: `host.startswith("127.")` accepted these. Both are ordinary
    # resolvable public hostnames, so --no-remote could be walked straight
    # past by a config-controlled URL.
    ("http://127.0.0.1.attacker.example/mcp", False),
    ("http://localhost.evil.com/mcp", False),
    ("http://169.254.169.254/latest/meta-data", False),
])
def test_loopback_detection_parses_addresses_rather_than_matching_text(url, expected):
    from blastradius.probe import _is_loopback

    assert _is_loopback(url) is expected


def test_no_remote_also_suppresses_credential_resolution():
    """REGRESSION: --no-remote promised no remote contact, then resolved anyway.

    Issuers are off-host by definition. Suppression is loud, not silent: a
    user who asked for resolution and got classification would otherwise read
    the weaker result as the stronger one.
    """
    from blastradius.creds.resolve import analyse
    from blastradius.creds.source import SecretSource

    def boom(*a, **kw):
        raise AssertionError("contacted an issuer under --no-remote")

    spec = ServerSpec(name="gh", transport="http", origin=Origin("/c", ""),
                      url="https://x/mcp", header_keys=("Authorization",),
                      credential_keys=("Authorization",))
    import blastradius.creds.providers as providers_mod
    original = providers_mod._request
    providers_mod._request = boom
    try:
        report = analyse([spec], resolve=True, allow_remote=False,
                         source=SecretSource(environ={}))
    finally:
        providers_mod._request = original
    assert any(d.code == "creds.resolution_suppressed" for d in report.diagnostics)


def test_control_characters_in_a_server_name_cannot_reach_the_terminal(tmp_path):
    """REGRESSION: a name containing ESC[2J cleared the operator's screen.

    A security report an attacker can partially erase is worse than none.
    """
    from blastradius.report import render_inventory

    esc = chr(27)
    cfg = tmp_path / ".mcp.json"
    cfg.write_text(json.dumps(
        {"mcpServers": {f"evil{esc}[2Jcleared": {"command": "x"}}}))
    inv = discover(home=tmp_path / "nohome", extra_paths=[cfg])
    rendered = render_inventory(inv)
    assert esc not in rendered
    assert "\\x1b" in rendered, "the name should still be visible, just inert"


@pytest.mark.parametrize("mapping,sensitive", [
    ({"DATABASE_URL": "postgresql://svc:pw@db.internal/prod"}, True),
    ({"REDIS_URL": "redis://:pw@h:6379"}, True),
    ({"MONGODB_URI": "mongodb://u:p@h/db"}, True),
    # ...but a plain server address is not a credential. Adding `url` to the
    # needle list would report every HTTP MCP server as carrying a secret.
    ({"url": "https://server.example/mcp"}, False),
    ({"BASE_URL": "https://api.example.com"}, False),
])
def test_dsn_values_are_judged_by_shape_not_by_key_name(mapping, sensitive):
    from blastradius.redact import split_keys

    _all, secret = split_keys(mapping)
    assert bool(secret) is sensitive


def test_contradictory_home_flags_are_reported(tmp_path):
    """REGRESSION: --home was silently ignored alongside --no-home-scan.

    `--home /mnt/target --no-home-scan` returned a clean "none found" that
    read as a verdict about the target and was really one about an empty
    temp directory.
    """
    from blastradius.cli import build_parser, _collect

    args = build_parser().parse_args(
        ["discover", "--home", str(tmp_path), "--no-home-scan"])
    inv = _collect(args)
    assert any(d.code == "cli.contradictory_scope" for d in inv.diagnostics)
