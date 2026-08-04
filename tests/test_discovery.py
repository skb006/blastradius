"""Discovery: shapes it must handle, and failures it must not swallow."""

from __future__ import annotations

import json
from pathlib import Path

from blastradius.discovery import discover


def write(path: Path, doc) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc) if not isinstance(doc, str) else doc)
    return path


def codes(inv) -> set[str]:
    return {d.code for d in inv.diagnostics}


def test_finds_servers_in_mcpservers_block(fake_home: Path):
    write(fake_home / ".claude.json", {
        "mcpServers": {
            "github": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"],
                       "env": {"GITHUB_TOKEN": "ghp_secret"}},
        }
    })
    inv = discover(home=fake_home)
    (s,) = inv.deduped()
    assert s.name == "github"
    assert s.transport == "stdio"
    assert s.credential_keys == ("GITHUB_TOKEN",)
    assert s.declared_authz == ()
    assert "ghp_secret" not in json.dumps(inv.to_json())


def test_finds_project_scoped_servers(fake_home: Path):
    write(fake_home / ".claude.json", {
        "projects": {"/home/x/proj": {"mcpServers": {"db": {"url": "http://127.0.0.1:9/mcp"}}}}
    })
    (s,) = discover(home=fake_home).deduped()
    assert s.name == "db"
    assert s.transport == "http"
    assert "projects./home/x/proj" in s.origin.locator


def test_vscode_servers_block(fake_home: Path):
    write(fake_home / ".vscode" / "mcp.json", {"servers": {"local": {"command": "node"}}})
    assert [s.name for s in discover(home=fake_home).deduped()] == ["local"]


def test_transport_classification(fake_home: Path):
    write(fake_home / ".claude.json", {"mcpServers": {
        "a": {"command": "node"},
        "b": {"url": "http://h/mcp"},
        "c": {"url": "http://h/sse"},
        "d": {"type": "streamable-http", "url": "http://h/x"},
        "e": {"description": "nothing useful"},
    }})
    got = {s.name: s.transport for s in discover(home=fake_home).deduped()}
    assert got == {"a": "stdio", "b": "http", "c": "sse", "d": "http", "e": "unknown"}


def test_declared_authz_is_recorded_when_present(fake_home: Path):
    write(fake_home / ".claude.json", {"mcpServers": {
        "scoped": {"url": "http://h/mcp", "tools": ["read"], "scopes": ["r"]},
    }})
    (s,) = discover(home=fake_home).deduped()
    assert set(s.declared_authz) == {"tools", "scopes"}
    assert "server.no_declared_scope" not in codes(discover(home=fake_home))


# --- failures must be loud -------------------------------------------------

def test_malformed_json_is_an_error_not_a_skip(fake_home: Path):
    write(fake_home / ".claude.json", "{ this is not json")
    inv = discover(home=fake_home)
    assert "config.malformed" in codes(inv)
    err = next(d for d in inv.diagnostics if d.code == "config.malformed")
    assert err.severity == "error"
    assert "UNKNOWN, not absent" in err.message


def test_non_utf8_config_is_an_error(fake_home: Path):
    p = fake_home / ".claude.json"
    p.write_bytes(b'{"mcpServers": {"a": "\xff\xfe"}}')
    assert "config.not_utf8" in codes(discover(home=fake_home))


def test_unexpected_top_level_shape_warns(fake_home: Path):
    write(fake_home / ".claude.json", ["a", "list"])
    assert "config.unexpected_shape" in codes(discover(home=fake_home))


def test_malformed_server_entry_warns_but_keeps_going(fake_home: Path):
    write(fake_home / ".claude.json", {"mcpServers": {"bad": "a string", "good": {"command": "node"}}})
    inv = discover(home=fake_home)
    assert "server.malformed" in codes(inv)
    assert [s.name for s in inv.deduped()] == ["good"]


def test_missing_files_are_silent(fake_home: Path):
    inv = discover(home=fake_home)
    assert inv.deduped() == []
    assert not [d for d in inv.diagnostics if d.severity == "error"]


# --- findings ---------------------------------------------------------------

def test_no_declared_scope_is_reported_per_server(fake_home: Path):
    write(fake_home / ".claude.json", {"mcpServers": {"wide": {"url": "http://h/mcp"}}})
    inv = discover(home=fake_home)
    d = next(d for d in inv.diagnostics if d.code == "server.no_declared_scope")
    assert "wide" in d.message


def test_credential_bearing_server_is_flagged(fake_home: Path):
    write(fake_home / ".claude.json", {"mcpServers": {
        "s": {"url": "http://h/mcp", "headers": {"Authorization": "Bearer x"}}}})
    inv = discover(home=fake_home)
    d = next(d for d in inv.diagnostics if d.code == "server.carries_credentials")
    assert d.severity == "warn" and "Authorization" in d.message


def test_config_sprawl_is_reported(fake_home: Path):
    for i in range(6):
        write(fake_home / "tmp" / f"openclaw-cli-mcp-{i}" / "mcp.json",
              {"mcpServers": {"openclaw": {"type": "http", "url": "http://127.0.0.1:1/mcp"}}})
    inv = discover(home=fake_home)
    assert len(inv.servers) == 6
    assert len(inv.deduped()) == 1, "identical declarations must collapse"
    d = next(d for d in inv.diagnostics if d.code == "config.sprawl")
    assert "6 separate config copies" in d.message


def test_scanned_paths_are_recorded(fake_home: Path):
    write(fake_home / ".claude.json", {"mcpServers": {}})
    inv = discover(home=fake_home)
    assert any(p.endswith(".claude.json") for p in inv.scanned_paths)


def test_project_roots_are_walked_and_noise_pruned(fake_home: Path, tmp_path: Path):
    proj = tmp_path / "proj"
    write(proj / ".mcp.json", {"mcpServers": {"inproj": {"command": "node"}}})
    write(proj / "node_modules" / "pkg" / ".mcp.json",
          {"mcpServers": {"vendored": {"command": "node"}}})
    inv = discover(home=fake_home, project_roots=[proj])
    names = [s.name for s in inv.deduped()]
    assert "inproj" in names and "vendored" not in names
