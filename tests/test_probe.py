"""Probe behaviour across both transports and every failure mode."""

from __future__ import annotations

import sys

import pytest

from blastradius.model import Origin, ServerSpec
from blastradius.probe import coverage, probe_all, probe_server


# --- stdio -----------------------------------------------------------------

def test_stdio_handshake_recovers_the_surface(stdio_spec):
    r = probe_server(stdio_spec(), allow_spawn=True)
    assert r.status == "ok" and r.recovered
    assert r.server_name == "fake-mcp" and r.server_version == "1.2.3"
    assert r.protocol_version == "2025-06-18"
    assert set(r.capabilities) == {"tools", "resources", "prompts"}
    assert [t.name for t in r.tools] == ["search_tickets", "delete_ticket", "export_all"]
    assert [res.uri for res in r.resources] == ["file:///var/data/tickets.db"]
    assert r.prompts == ("triage",)


def test_annotations_drive_write_capability(stdio_spec):
    r = probe_server(stdio_spec(), allow_spawn=True)
    by_name = {t.name: t for t in r.tools}
    assert by_name["search_tickets"].write_capable is False   # readOnlyHint
    assert by_name["delete_ticket"].write_capable is True     # destructiveHint
    assert by_name["export_all"].write_capable is True        # unannotated -> assume write
    assert {t.name for t in r.write_tools} == {"delete_ticket", "export_all"}


def test_unannotated_tools_produce_a_warning(stdio_spec):
    r = probe_server(stdio_spec("--no-annotations"), allow_spawn=True)
    assert all(t.write_capable for t in r.tools), "no hints -> every tool is a write edge"
    d = next(d for d in r.diagnostics if d.code == "probe.unannotated_tools")
    assert d.severity == "warn" and "3/3" in d.message


def test_input_schema_is_captured(stdio_spec):
    r = probe_server(stdio_spec(), allow_spawn=True)
    t = next(t for t in r.tools if t.name == "search_tickets")
    assert t.input_params == ("limit", "query")
    assert t.required_params == ("query",)


def test_pagination_is_followed(stdio_spec):
    r = probe_server(stdio_spec("--paginate"), allow_spawn=True)
    assert [t.name for t in r.tools] == ["search_tickets", "delete_ticket", "export_all"]


def test_stdout_banner_noise_is_tolerated(stdio_spec):
    r = probe_server(stdio_spec("--banner"), allow_spawn=True)
    assert r.status == "ok" and len(r.tools) == 3


def test_server_that_dies_is_unreachable_not_a_crash(stdio_spec):
    r = probe_server(stdio_spec("--die"), allow_spawn=True)
    assert r.status == "unreachable"
    assert any(d.code == "probe.unreachable" for d in r.diagnostics)


def test_hanging_server_times_out(stdio_spec):
    r = probe_server(stdio_spec("--hang"), allow_spawn=True, timeout=0.6)
    assert r.status == "timeout"
    assert any(d.code == "probe.timeout" for d in r.diagnostics)


def test_rpc_error_during_handshake(stdio_spec):
    r = probe_server(stdio_spec("--rpc-error"), allow_spawn=True)
    assert r.status == "protocol_error"
    assert any("internal error" in d.message for d in r.diagnostics)


def test_missing_runtime_is_reported_as_inert_grant():
    spec = ServerSpec(name="bunny", transport="stdio", origin=Origin("<t>"),
                      command="definitely-not-installed-xyz")
    r = probe_server(spec, allow_spawn=True)
    assert r.status == "runtime_missing"
    d = next(d for d in r.diagnostics if d.code == "probe.runtime_missing")
    assert "inert" in d.message


# --- http ------------------------------------------------------------------

def test_http_json_response(http_spec):
    r = probe_server(http_spec("json"))
    assert r.status == "ok"
    assert r.server_name == "fake-http-mcp"
    assert [t.name for t in r.tools] == ["fetch_url"]
    assert r.tools[0].open_world is True


def test_http_sse_response(http_spec):
    r = probe_server(http_spec("sse"))
    assert r.status == "ok" and [t.name for t in r.tools] == ["fetch_url"]


def test_http_401_is_auth_required_not_unreachable(http_spec):
    r = probe_server(http_spec("auth"))
    assert r.status == "auth_required"
    d = next(d for d in r.diagnostics if d.code == "probe.auth_required")
    assert "surface exists" in d.message


def test_http_405_is_diagnosed_as_legacy_transport(http_spec):
    r = probe_server(http_spec("legacy"))
    assert r.status == "protocol_error"
    assert any("legacy HTTP+SSE" in d.message for d in r.diagnostics)


def test_http_non_mcp_endpoint(http_spec):
    r = probe_server(http_spec("notjson"))
    assert r.status == "protocol_error"


def test_http_nothing_listening():
    spec = ServerSpec(name="dead", transport="http", origin=Origin("<t>"),
                      url="http://127.0.0.1:1/mcp")
    r = probe_server(spec, timeout=2)
    assert r.status in ("unreachable", "timeout")


def test_http_capability_gating_skips_absent_lists(http_spec):
    """Server advertises only 'tools'; we must not ask for resources/prompts."""
    r = probe_server(http_spec("json"))
    assert r.resources == () and r.prompts == ()


# --- aggregate --------------------------------------------------------------

def test_probe_all_and_coverage(stdio_spec, http_spec):
    specs = [stdio_spec(name="a"), http_spec(name="b"), stdio_spec("--die", name="c")]
    results = probe_all(specs, allow_spawn=True)
    cov = coverage(results)
    assert cov["servers_declared"] == 3
    assert cov["servers_recovered"] == 2
    assert cov["recovery_rate"] == pytest.approx(2 / 3, abs=1e-4)
    assert cov["tools_discovered"] == 4          # 3 stdio + 1 http
    assert cov["write_capable_tools"] == 2       # delete_ticket + export_all


def test_coverage_of_empty_run_is_zero_not_a_crash():
    assert coverage([])["recovery_rate"] == 0.0


def test_unsupported_transport_is_a_protocol_error():
    spec = ServerSpec(name="weird", transport="unknown", origin=Origin("<t>"))
    r = probe_server(spec, allow_spawn=True)
    assert r.status == "protocol_error"


# --- egress control ---------------------------------------------------------

def test_no_remote_skips_non_loopback_endpoints():
    spec = ServerSpec(name="saas", transport="http", origin=Origin("<t>"),
                      url="https://mcp.example.com")
    r = probe_server(spec, allow_remote=False)
    assert r.status == "skipped"
    d = next(d for d in r.diagnostics if d.code == "probe.skipped_remote")
    assert "--no-remote" in d.message


def test_no_remote_still_probes_loopback(http_spec):
    r = probe_server(http_spec("json"), allow_remote=False)
    assert r.status == "ok", "loopback must remain probeable under --no-remote"


@pytest.mark.parametrize("url,expected", [
    ("http://127.0.0.1:9/mcp", True),
    ("http://localhost:9/mcp", True),
    ("http://127.0.0.53:9/mcp", True),
    ("https://mcp.vercel.com", False),
    ("http://10.0.0.1/mcp", False),
    (None, False),
])
def test_loopback_detection(url, expected):
    from blastradius.probe import _is_loopback
    assert _is_loopback(url) is expected
