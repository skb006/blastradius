"""Logical identity — grouping servers that are the same thing.

Regression cover for a defect found by running the tool against a real
machine: OpenClaw rebinds a fresh loopback port per session, so twenty
declarations of one server presented as twenty distinct servers and the
sprawl warning never fired.
"""

from __future__ import annotations

import json
from pathlib import Path

from blastradius.discovery import discover
from blastradius.model import Inventory, Origin, ServerSpec


def spec(url: str | None = None, name="openclaw", command=None, origin="<t>") -> ServerSpec:
    return ServerSpec(
        name=name,
        transport="http" if url else "stdio",
        origin=Origin(origin),
        url=url,
        command=command,
    )


def test_ephemeral_loopback_ports_collapse():
    a = spec("http://127.0.0.1:39765/mcp")
    b = spec("http://127.0.0.1:40293/mcp")
    assert a.identity != b.identity, "exact identity must stay distinct"
    assert a.logical_identity == b.logical_identity


def test_non_ephemeral_loopback_port_is_preserved():
    a = spec("http://127.0.0.1:8080/mcp")
    b = spec("http://127.0.0.1:9090/mcp")
    assert a.logical_identity != b.logical_identity, "8080 is a chosen port, not ephemeral"


def test_routable_host_ports_are_never_collapsed():
    a = spec("http://10.0.0.5:39765/mcp")
    b = spec("http://10.0.0.5:40293/mcp")
    assert a.logical_identity != b.logical_identity


def test_different_paths_stay_distinct():
    a = spec("http://127.0.0.1:39765/mcp")
    b = spec("http://127.0.0.1:40293/other")
    assert a.logical_identity != b.logical_identity


def test_ipv6_loopback_collapses():
    a = spec("http://[::1]:39765/mcp")
    b = spec("http://[::1]:40293/mcp")
    assert a.logical_identity == b.logical_identity


def test_malformed_url_does_not_explode():
    assert spec("not a url at all").logical_identity.endswith("not a url at all")


def test_inventory_groups_and_counts():
    servers = [spec(f"http://127.0.0.1:{p}/mcp") for p in (39765, 40293, 33355)]
    inv = Inventory(servers=servers)
    assert len(inv.deduped()) == 1
    assert list(inv.copies().values()) == [3]
    assert len(inv.endpoints()[servers[0].logical_identity]) == 3


def test_probe_targets_picks_one_endpoint_per_logical_server():
    servers = [spec(f"http://127.0.0.1:{p}/mcp") for p in (33355, 40293, 39765)]
    inv = Inventory(servers=servers)
    targets = inv.probe_targets()
    assert len(targets) == 1
    assert targets[0].url is not None
    assert targets[0].url in {s.url for s in servers}


def test_sprawl_warning_now_fires_for_rotating_ports(fake_home: Path):
    for i, port in enumerate(range(39000, 39006)):
        d = fake_home / "tmp" / f"openclaw-cli-mcp-{i}"
        d.mkdir(parents=True)
        (d / "mcp.json").write_text(json.dumps(
            {"mcpServers": {"openclaw": {"type": "http",
                                         "url": f"http://127.0.0.1:{port}/mcp"}}}))
    inv = discover(home=fake_home)
    assert len(inv.servers) == 6
    assert len(inv.deduped()) == 1, "rotating ports are one logical server"
    assert any(d.code == "config.sprawl" for d in inv.diagnostics)


def test_scope_finding_is_emitted_once_per_logical_server(fake_home: Path):
    for i, port in enumerate(range(39000, 39004)):
        d = fake_home / "tmp" / f"openclaw-cli-mcp-{i}"
        d.mkdir(parents=True)
        (d / "mcp.json").write_text(json.dumps(
            {"mcpServers": {"openclaw": {"type": "http",
                                         "url": f"http://127.0.0.1:{port}/mcp"}}}))
    inv = discover(home=fake_home)
    scope_findings = [d for d in inv.diagnostics if d.code == "server.no_declared_scope"]
    assert len(scope_findings) == 1, "one finding per server, not per config copy"


def test_probe_target_is_chosen_by_config_recency(tmp_path: Path):
    """Regression: selection used to sort by URL, picking the highest port.

    Port number has nothing to do with which session is live. The newest
    config is the only endpoint with a chance of answering.
    """
    import os
    import time

    old = tmp_path / "old.json"
    new = tmp_path / "new.json"
    old.write_text("{}")
    new.write_text("{}")
    os.utime(old, (1000, 1000))
    os.utime(new, (time.time(), time.time()))

    # deliberately give the OLD config the higher port
    stale = ServerSpec(name="oc", transport="http", origin=Origin(str(old)),
                       url="http://127.0.0.1:40293/mcp")
    live = ServerSpec(name="oc", transport="http", origin=Origin(str(new)),
                      url="http://127.0.0.1:33355/mcp")

    targets = Inventory(servers=[stale, live]).probe_targets()
    assert len(targets) == 1
    assert targets[0].url == "http://127.0.0.1:33355/mcp", "newest config must win"


def test_recency_tolerates_missing_config_file():
    ghost = ServerSpec(name="x", transport="http", origin=Origin("/does/not/exist"),
                       url="http://127.0.0.1:39000/mcp")
    assert Inventory(servers=[ghost]).probe_targets() == [ghost]
