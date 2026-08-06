"""Liveness sweep — finding MCP servers that config does not declare."""

from __future__ import annotations

from pathlib import Path

import pytest

from blastradius.model import Origin, ServerSpec
from blastradius.sweep import (
    WELL_KNOWN_NON_HTTP,
    _is_local_bind,
    listening_ports,
    port_source_available,
    sweep,
)


def _port_of(url: str) -> int:
    from urllib.parse import urlparse
    return urlparse(url).port


# --- /proc parsing ----------------------------------------------------------

PROC_TCP = """  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid
   0: 0100007F:4A44 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000
   1: 0100007F:1A6B 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000
   2: 00000000:1F90 00000000:0000 0A 00000000:00000000 00000000 00000000  1000
   3: 0101A8C0:0016 0201A8C0:D431 01 00000000:00000000 00:00000000 00000000     0
"""


def test_listening_ports_parses_proc(tmp_path: Path):
    f = tmp_path / "tcp"
    f.write_text(PROC_TCP)
    ports = listening_ports([f])
    assert 0x4A44 in ports          # loopback listener
    assert 0x1A6B in ports          # loopback listener
    assert 0x1F90 in ports          # wildcard bind is reachable on loopback
    assert 0x0016 not in ports      # established, not listening; also not local


def test_listening_ports_tolerates_missing_file(tmp_path: Path):
    assert listening_ports([tmp_path / "nope"]) == set()


def test_listening_ports_tolerates_garbage(tmp_path: Path):
    f = tmp_path / "tcp"
    f.write_text("header\ngarbage line\n   0: ZZZZ:ZZZZ x x 0A\n")
    assert listening_ports([f]) == set()


@pytest.mark.parametrize("hexaddr,expected", [
    ("0100007F:1F90", True),                                    # 127.0.0.1
    ("00000000:1F90", True),                                    # 0.0.0.0
    ("0101A8C0:1F90", False),                                   # 192.168.1.1
    ("00000000000000000000000001000000:1F90", True),            # ::1
    ("0000000000000000000000000000000:1F90", False),            # malformed length
])
def test_local_bind_detection(hexaddr, expected):
    assert _is_local_bind(hexaddr) is expected


# --- sweep behaviour --------------------------------------------------------

def test_sweep_finds_undeclared_mcp_server(http_server):
    url = http_server("json")
    port = _port_of(url)
    results, diags = sweep(declared=[], ports=[port], timeout=3)
    assert len(results) == 1
    assert results[0].status == "ok"
    d = next(d for d in diags if d.code == "sweep.shadow_agent")
    assert d.severity == "error"
    assert "declared in NO config file" in d.message
    assert "1 tools" in d.message


def test_sweep_does_not_flag_a_declared_port(http_server):
    url = http_server("json")
    port = _port_of(url)
    declared = [ServerSpec(name="known", transport="http", origin=Origin("<cfg>"), url=url)]
    results, diags = sweep(declared=declared, ports=[port], timeout=3)
    assert len(results) == 1, "still probed"
    assert not [d for d in diags if d.code == "sweep.shadow_agent"]


def test_sweep_flags_gated_server_as_warning(http_server):
    port = _port_of(http_server("auth"))
    results, diags = sweep(declared=[], ports=[port], timeout=3)
    assert results[0].status == "auth_required"
    d = next(d for d in diags if d.code == "sweep.shadow_agent")
    assert d.severity == "warn" and "gated" in d.message


def test_sweep_ignores_non_mcp_ports(http_server):
    port = _port_of(http_server("notjson"))
    results, diags = sweep(declared=[], ports=[port], timeout=3)
    assert results == []
    assert not [d for d in diags if d.code == "sweep.shadow_agent"]


def test_sweep_skips_well_known_non_http_ports():
    results, diags = sweep(declared=[], ports=[6379, 5432, 27017], timeout=1)
    assert results == []
    assert 6379 in WELL_KNOWN_NON_HTTP


def test_sweep_honours_extra_skip_list(http_server):
    port = _port_of(http_server("json"))
    results, _ = sweep(declared=[], ports=[port], skip_ports=[port], timeout=2)
    assert results == []


def test_all_declared_endpoints_dead_is_reported(http_server):
    """The exact situation on the machine this was built against."""
    live = _port_of(http_server("json"))
    dead = ServerSpec(name="stale", transport="http", origin=Origin("<cfg>"),
                      url="http://127.0.0.1:39765/mcp")
    _, diags = sweep(declared=[dead], ports=[live], timeout=3)
    d = next(d for d in diags if d.code == "sweep.all_declared_endpoints_dead")
    assert "past sessions, not current reach" in d.message


# --- platforms with no readable socket table --------------------------------

def test_port_source_available_detects_a_readable_table(tmp_path: Path):
    f = tmp_path / "tcp"
    f.write_text(PROC_TCP)
    assert port_source_available([f]) is True
    assert port_source_available([tmp_path / "nope", f]) is True


def test_port_source_available_is_false_when_nothing_is_readable(tmp_path: Path):
    assert port_source_available([tmp_path / "nope", tmp_path / "also-nope"]) is False


def test_sweep_reports_error_when_it_cannot_enumerate(monkeypatch, tmp_path: Path):
    """An empty sweep on a platform with no /proc must not read as clean.

    This is the whole point: `listening_ports` returns the empty set both when
    nothing is listening and when there is no way to look, so the sweep has to
    say which one happened.
    """
    monkeypatch.setattr("blastradius.sweep._PROC_TCP", (tmp_path / "nope",))
    results, diags = sweep(declared=[], timeout=1)
    assert results == []
    d = next(d for d in diags if d.code == "sweep.unsupported_platform")
    assert d.severity == "error", "must be non-zero exit, not a quiet pass"
    assert "could not look, not because nothing is listening" in d.message


def test_sweep_without_socket_table_does_not_claim_declared_endpoints_are_dead(
    monkeypatch, tmp_path: Path
):
    """Liveness is not something we observed if we could not read any sockets."""
    monkeypatch.setattr("blastradius.sweep._PROC_TCP", (tmp_path / "nope",))
    dead = ServerSpec(name="stale", transport="http", origin=Origin("<cfg>"),
                      url="http://127.0.0.1:39765/mcp")
    _, diags = sweep(declared=[dead], timeout=1)
    assert not [d for d in diags if d.code == "sweep.all_declared_endpoints_dead"]


def test_explicit_ports_still_sweep_without_a_socket_table(monkeypatch, tmp_path: Path,
                                                          http_server):
    """`ports=` is a caller-supplied list, so no enumeration is needed."""
    monkeypatch.setattr("blastradius.sweep._PROC_TCP", (tmp_path / "nope",))
    port = _port_of(http_server("json"))
    results, diags = sweep(declared=[], ports=[port], timeout=3)
    assert len(results) == 1
    assert not [d for d in diags if d.code == "sweep.unsupported_platform"]


def test_sweep_enumerates_from_the_socket_table_it_is_given(monkeypatch, tmp_path: Path,
                                                            http_server):
    """Positive control for the two tests above.

    Without this, a substitution that silently failed to take effect would make
    them pass on a machine that has no /proc for unrelated reasons.
    """
    port = _port_of(http_server("json"))
    f = tmp_path / "tcp"
    f.write_text(
        "  sl  local_address rem_address   st\n"
        f"   0: 0100007F:{port:04X} 00000000:0000 0A 00000000:00000000 00:00000000 0 1000\n"
    )
    monkeypatch.setattr("blastradius.sweep._PROC_TCP", (f,))
    results, diags = sweep(declared=[], timeout=3)
    assert len(results) == 1, "the substituted socket table was not read"
    assert not [d for d in diags if d.code == "sweep.unsupported_platform"]
    assert [d for d in diags if d.code == "sweep.shadow_agent"]
