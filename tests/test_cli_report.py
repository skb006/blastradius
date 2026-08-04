"""CLI contract and report determinism."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from blastradius.cli import main
from blastradius.discovery import discover
from blastradius.model import Diagnostic, Inventory, Origin, ProbeResult, ServerSpec
from blastradius.probe import probe_all
from blastradius.report import render_diagnostics, render_inventory, render_probe, to_json


def write(path: Path, doc) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc))


@pytest.fixture
def config_file(tmp_path: Path) -> Path:
    p = tmp_path / "cfg" / ".mcp.json"
    write(p, {"mcpServers": {
        "github": {"command": "npx", "args": ["-y", "srv", "--token", "ghp_secret"],
                   "env": {"GITHUB_TOKEN": "ghp_secret"}},
        "remote": {"url": "http://127.0.0.1:1/mcp"},
    }})
    return p


def test_discover_exits_zero_and_lists_servers(config_file, capsys):
    rc = main(["discover", "--no-home-scan", "-c", str(config_file)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "github" in out and "remote" in out
    assert "NONE DECLARED" in out


def test_secrets_never_reach_stdout(config_file, capsys):
    main(["discover", "--no-home-scan", "-c", str(config_file)])
    assert "ghp_secret" not in capsys.readouterr().out


def test_secrets_never_reach_json_output(config_file, capsys):
    main(["discover", "--no-home-scan", "-c", str(config_file), "--json"])
    out = capsys.readouterr().out
    assert "ghp_secret" not in out
    assert "<redacted>" in out
    assert json.loads(out)["inventory"]["unique_count"] == 2


def test_malformed_config_exits_nonzero(tmp_path: Path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text("{nope")
    rc = main(["discover", "--no-home-scan", "-c", str(bad)])
    assert rc == 1, "an unreadable config must not report success"
    assert "config.malformed" in capsys.readouterr().out


def test_probe_skips_stdio_by_default(config_file, capsys):
    rc = main(["probe", "--no-home-scan", "-c", str(config_file)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "skipped" in out
    assert "--allow-spawn" in out


def test_probe_only_filter(config_file, capsys):
    main(["probe", "--no-home-scan", "-c", str(config_file), "--only", "remote", "--timeout", "2"])
    out = capsys.readouterr().out
    assert "remote" in out
    assert "servers declared      : 1" in out


def test_probe_only_unknown_name_warns(config_file, capsys):
    main(["probe", "--no-home-scan", "-c", str(config_file), "--only", "nope"])
    assert "cli.unknown_server" in capsys.readouterr().out


def test_quiet_suppresses_diagnostics(config_file, capsys):
    main(["discover", "--no-home-scan", "-c", str(config_file), "-q"])
    assert "DIAGNOSTICS" not in capsys.readouterr().out


# --- determinism ------------------------------------------------------------

def test_json_output_is_stable_across_runs(stdio_spec, tmp_path: Path):
    specs = [stdio_spec()]
    inv = Inventory(servers=list(specs))
    a = to_json(inv, probe_all(specs, allow_spawn=True))
    b = to_json(inv, probe_all(specs, allow_spawn=True))
    assert a == b, "two runs against an unchanged deployment must diff to nothing"


def test_json_output_excludes_timing(stdio_spec):
    inv = Inventory(servers=[stdio_spec()])
    payload = json.loads(to_json(inv, probe_all(inv.servers, allow_spawn=True)))
    assert "duration_ms" not in payload["probes"][0]


def test_json_schema_marker_present(stdio_spec):
    inv = Inventory(servers=[stdio_spec()])
    assert json.loads(to_json(inv, []))["schema"] == "blastradius/probe/v1"


# --- renderers --------------------------------------------------------------

def test_render_inventory_handles_empty():
    assert "none found" in render_inventory(Inventory())


def test_render_inventory_shows_copy_counts():
    s = ServerSpec(name="dup", transport="http", origin=Origin("<t>"), url="http://h/mcp")
    inv = Inventory(servers=[s, s, s])
    assert "(3 declarations)" in render_inventory(inv)


def test_render_probe_marks_write_tools(stdio_spec):
    results = probe_all([stdio_spec()], allow_spawn=True)
    out = render_probe(results, verbose=True)
    assert "[W] delete_ticket" in out
    assert "[r] search_tickets" in out


def test_render_probe_truncates_without_verbose(stdio_spec, monkeypatch):
    results = probe_all([stdio_spec()], allow_spawn=True)
    assert "more (use -v)" not in render_probe(results)  # only 3 tools, under the cap


def test_render_diagnostics_orders_by_severity():
    diags = [
        Diagnostic("info", "z.info", "i"),
        Diagnostic("error", "a.err", "e"),
        Diagnostic("warn", "m.warn", "w"),
    ]
    out = render_diagnostics(diags)
    assert out.index("a.err") < out.index("m.warn") < out.index("z.info")
    assert "1 error, 1 info, 1 warn" in out


def test_render_diagnostics_empty():
    assert "none" in render_diagnostics([])
