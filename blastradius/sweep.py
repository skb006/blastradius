"""Stage 2b — liveness sweep for undeclared MCP servers.

Why this exists, empirically:

    declared openclaw endpoints : 17 loopback ports
    actually listening          : 6 loopback ports
    intersection                : none

Every endpoint the configuration declared was dead, and the agent that was
actually running held a port no file on disk mentioned. Config is a record of
sessions that *have happened*; the socket table is the record of what is
happening. A prober that trusts only config reports 0% coverage on a machine
with a live agent on it — which is exactly what this one did before the sweep
existed.

So: enumerate listening loopback sockets, ask each whether it speaks MCP, and
diff the answer against what was declared. Anything live and undeclared is a
shadow agent, which is the finding the whole product is pointed at.

Sweeping is opt-in. It sends one small JSON-RPC POST to local ports, and doing
that uninvited is not a decision this tool makes on a user's behalf.

The socket table is read from ``/proc/net/tcp``, so enumeration currently works
on Linux only. Where no socket table is readable the sweep reports
``sweep.unsupported_platform`` at error severity rather than returning an empty
result, because an empty result is indistinguishable from a clean machine and
this tool must never understate reach.
"""

from __future__ import annotations

import ipaddress
import sys
from pathlib import Path
from typing import Iterable, Sequence

from .model import Diagnostic, Origin, ProbeResult, ServerSpec
from .probe import probe_server

_PROC_TCP = (Path("/proc/net/tcp"), Path("/proc/net/tcp6"))
_LISTEN = "0A"

#: Ports running well-known non-HTTP protocols. Sending them a JSON-RPC POST
#: would be harmless but rude, and they will never be MCP.
WELL_KNOWN_NON_HTTP: frozenset[int] = frozenset(
    {
        22,    # ssh
        25, 465, 587,   # smtp
        53,    # dns
        3306,  # mysql
        5432,  # postgres
        6379,  # redis
        11211, # memcached
        27017, # mongodb
        9092,  # kafka
        5672,  # amqp
    }
)

#: Paths an MCP server is plausibly mounted at, in order of likelihood.
CANDIDATE_PATHS: tuple[str, ...] = ("/mcp", "/", "/api/mcp", "/message")


def _hex_to_port(hex_pair: str) -> int | None:
    try:
        return int(hex_pair.split(":")[1], 16)
    except (IndexError, ValueError):
        return None


def _is_local_bind(hex_addr: str) -> bool:
    """True for loopback or wildcard binds (both are reachable on loopback)."""
    try:
        raw = hex_addr.split(":")[0]
    except IndexError:
        return False
    if len(raw) == 8:  # IPv4, little-endian hex
        packed = bytes.fromhex(raw)[::-1]
        try:
            addr = ipaddress.IPv4Address(packed)
        except ValueError:
            return False
        return addr.is_loopback or addr == ipaddress.IPv4Address("0.0.0.0")
    if len(raw) == 32:  # IPv6
        groups = [raw[i:i + 8] for i in range(0, 32, 8)]
        packed = b"".join(bytes.fromhex(g)[::-1] for g in groups)
        try:
            addr = ipaddress.IPv6Address(packed)
        except ValueError:
            return False
        return addr.is_loopback or addr == ipaddress.IPv6Address("::")
    return False


def listening_ports(proc_files: Sequence[Path] = _PROC_TCP) -> set[int]:
    """Ports in LISTEN state bound to loopback or wildcard.

    Reads ``/proc/net/tcp`` directly rather than shelling out to ``ss``: no
    subprocess, no parsing of a human-facing format, and it works in a
    container without iproute2 installed.
    """
    ports: set[int] = set()
    for path in proc_files:
        try:
            lines = path.read_text().splitlines()
        except (OSError, UnicodeDecodeError):
            continue
        for line in lines[1:]:
            fields = line.split()
            if len(fields) < 4 or fields[3] != _LISTEN:
                continue
            if not _is_local_bind(fields[1]):
                continue
            port = _hex_to_port(fields[1])
            if port is not None:
                ports.add(port)
    return ports


def port_source_available(proc_files: Sequence[Path] = _PROC_TCP) -> bool:
    """True if at least one socket table is readable.

    ``listening_ports`` cannot distinguish "nothing is listening" from "I have
    no way to look" — both are the empty set. On a platform without ``/proc``
    every read raises and the sweep quietly finds nothing, which reads as a
    clean result. That is the one error this tool must never make, so the
    caller asks this first and says so out loud.
    """
    for path in proc_files:
        try:
            with path.open("rb"):
                return True
        except OSError:
            continue
    return False


def _candidate_specs(port: int) -> list[ServerSpec]:
    return [
        ServerSpec(
            name=f"undeclared:{port}",
            transport="http",
            origin=Origin(f"<sweep:127.0.0.1:{port}>", path),
            url=f"http://127.0.0.1:{port}{path}",
        )
        for path in CANDIDATE_PATHS
    ]


def sweep(
    declared: Iterable[ServerSpec] = (),
    *,
    ports: Iterable[int] | None = None,
    timeout: float = 2.0,
    skip_ports: Iterable[int] = (),
) -> tuple[list[ProbeResult], list[Diagnostic]]:
    """Find MCP servers that are listening but not declared.

    Args:
        declared: servers already known from config, used to suppress
            duplicates and to tell "shadow" from "expected".
        ports: override the port list (tests pass this).
        timeout: per-request; kept short because most ports are not MCP.
        skip_ports: additional ports to leave alone.

    Returns:
        (results for ports that spoke MCP, diagnostics)
    """
    declared_ports: set[int] = set()
    for spec in declared:
        if spec.url:
            try:
                from urllib.parse import urlparse

                p = urlparse(spec.url).port
                if p:
                    declared_ports.add(p)
            except ValueError:
                pass

    results: list[ProbeResult] = []
    diags: list[Diagnostic] = []

    # Read _PROC_TCP through the module global rather than the def-time default
    # so the source is substitutable at call time.
    if ports is None and not port_source_available(_PROC_TCP):
        tried = ", ".join(str(p) for p in _PROC_TCP)
        diags.append(
            Diagnostic(
                "error", "sweep.unsupported_platform",
                f"cannot enumerate listening sockets on {sys.platform}: no readable "
                f"socket table (tried {tried}) — the sweep found nothing because it "
                f"could not look, not because nothing is listening",
            )
        )
        # Return before the liveness diff below: with no socket table, "none of
        # the declared endpoints are listening" is not something we observed.
        return results, diags

    candidates = set(ports) if ports is not None else listening_ports(_PROC_TCP)
    excluded = WELL_KNOWN_NON_HTTP | set(skip_ports)
    targets = sorted(candidates - excluded)

    for port in targets:
        for spec in _candidate_specs(port):
            result = probe_server(spec, timeout=timeout)
            if result.status in ("ok", "auth_required"):
                shadow = port not in declared_ports
                results.append(result)
                if shadow:
                    diags.append(
                        Diagnostic(
                            "error" if result.status == "ok" else "warn",
                            "sweep.shadow_agent",
                            f"MCP server listening on 127.0.0.1:{port}{spec.origin.locator} "
                            f"is declared in NO config file"
                            + (f" — exposes {len(result.tools)} tools "
                               f"({len(result.write_tools)} write-capable)"
                               if result.status == "ok" else " (gated)"),
                            spec.origin,
                        )
                    )
                break  # found the mount point; stop trying paths on this port

    if declared_ports and not (declared_ports & candidates):
        diags.append(
            Diagnostic(
                "warn", "sweep.all_declared_endpoints_dead",
                f"none of the {len(declared_ports)} declared loopback endpoint(s) are "
                f"listening — configuration describes past sessions, not current reach",
            )
        )

    return results, diags
