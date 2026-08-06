"""Command line interface.

Exit codes are stable so this can gate CI:

    0  clean
    1  one or more ``error`` diagnostics (something was unreadable/unprovable)
    2  bad usage

A parse failure exits non-zero on purpose. An unreadable config means the
inventory is incomplete, and an incomplete inventory reported as success is
the exact failure mode this tool exists to prevent.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Sequence

from .creds.model import CredentialReport
from .creds.resolve import analyse
from .discovery import discover
from .prove.engine import prove as run_prover
from .prove.graph import build_graph as build_agent_graph
from .prove.policy import PolicyError, default_policy, load_policy
from .model import Diagnostic, Inventory, ProbeResult
from .probe import probe_all
from .sweep import sweep
from .report import (
    render_credentials, render_diagnostics, render_inventory, render_probe, to_json,
)
from .mcp.transport import DEFAULT_TIMEOUT

# Say exactly what it does. An earlier banner claimed it "never reads a
# credential value" and "never sends your credentials anywhere"; stage 3 made
# both false, because resolving a credential means presenting it to its issuer.
# Overclaiming is worse than the behaviour it hides — a buyer who discovers the
# gap stops believing the guarantees that *are* true.
BANNER = (
    "blastradius — read-only MCP prober. It never invokes a tool and never "
    "writes findings anywhere but your terminal. It contacts the MCP endpoints "
    "declared in your config, because that is how their surface is discovered; "
    "--no-remote restricts that to loopback. Credential values are read LOCALLY "
    "to redact them and identify the issuer, but are never TRANSMITTED except "
    "under --resolve-credentials, which presents each value to that credential's "
    "own issuer and nowhere else — redirects and proxies refused, not followed."
)


def _add_common(p: argparse.ArgumentParser) -> None:
    p.add_argument("-r", "--root", action="append", type=Path, default=[],
                   metavar="DIR", help="project directory to walk for .mcp.json "
                                       "(repeatable)")
    p.add_argument("-c", "--config", action="append", type=Path, default=[],
                   metavar="FILE", help="explicit config file to include (repeatable)")
    p.add_argument("--home", type=Path, default=None, metavar="DIR",
                   help="treat DIR as the home directory instead of $HOME — use to "
                        "audit a mounted container filesystem or another account")
    p.add_argument("--no-home-scan", action="store_true",
                   help="scan only --config/--root, skipping well-known home locations")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.add_argument("-q", "--quiet", action="store_true", help="suppress diagnostics")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="blastradius", description=BANNER)
    sub = p.add_subparsers(dest="command", required=True)

    d = sub.add_parser("discover", help="find declared MCP servers (no network, no spawn)")
    _add_common(d)

    pr = sub.add_parser("probe", help="handshake with declared servers and list their surface")
    _add_common(pr)
    pr.add_argument("--allow-spawn", action="store_true",
                    help="permit spawning stdio servers — this EXECUTES commands "
                         "declared in config; off by default")
    pr.add_argument("--classify-credentials", action="store_true",
                    help="identify each credential's issuer from its documented "
                         "prefix — reads values locally, sends NOTHING")
    pr.add_argument("--resolve-credentials", action="store_true",
                    help="ask each issuer what the credential authorises. Implies "
                         "--classify-credentials. Sends the credential to its own "
                         "issuer ONLY, over a pinned host, using read-only endpoints")
    pr.add_argument("--sweep", action="store_true",
                    help="also scan listening loopback ports for MCP servers that "
                         "no config declares (finds shadow agents)")
    pr.add_argument("--no-remote", action="store_true",
                    help="probe only loopback endpoints; never contact a remote host")
    pr.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                    metavar="SEC", help=f"per-request timeout (default {DEFAULT_TIMEOUT})")
    pr.add_argument("--only", action="append", default=[], metavar="NAME",
                    help="probe only these server names (repeatable)")
    pr.add_argument("-v", "--verbose", action="store_true", help="list every tool")

    pv = sub.add_parser(
        "prove", help="prove what the agent can reach, or that it cannot")
    _add_common(pv)
    pv.add_argument("--policy", type=Path, default=None, metavar="FILE",
                    help="policy file (.json/.yaml). Without one, a conservative "
                         "default denies all agent write authority.")
    pv.add_argument("--allow-spawn", action="store_true",
                    help="permit spawning stdio servers while collecting the surface")
    pv.add_argument("--sweep", action="store_true",
                    help="include undeclared listening MCP servers")
    pv.add_argument("--no-remote", action="store_true",
                    help="probe only loopback endpoints")
    pv.add_argument("--resolve-credentials", action="store_true",
                    help="ask issuers what each credential authorises — without "
                         "this, credential authority is treated as unbounded")
    pv.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, metavar="SEC")
    pv.add_argument("--show-graph", action="store_true",
                    help="print the assembled agent graph")
    return p


def _emit(text: str, quiet: bool = False) -> None:
    if not quiet:
        print(text)


def _exit_code(diags: Sequence[Diagnostic]) -> int:
    return 1 if any(d.severity == "error" for d in diags) else 0


def _collect(args: argparse.Namespace) -> Inventory:
    """Build the inventory honouring the home-scan switches.

    ``--no-home-scan`` is implemented by pointing discovery at an empty
    directory rather than by branching inside discovery: one code path,
    and the "well-known locations" list stays the single source of truth.
    """
    home = args.home
    if args.no_home_scan:
        home = Path(tempfile.mkdtemp(prefix="blastradius-empty-"))
    inv = discover(project_roots=args.root, home=home, extra_paths=args.config)
    if args.no_home_scan and args.home is not None:
        # Contradictory, and it used to resolve silently in favour of
        # --no-home-scan. Someone auditing a mounted container filesystem with
        # `--home /mnt/target --no-home-scan` got a clean "none found" that
        # looked like a verdict about the target and was really a verdict
        # about an empty temp directory. Say so rather than guess.
        inv.diagnostics.append(Diagnostic(
            "warn", "cli.contradictory_scope",
            f"--home {args.home} was ignored because --no-home-scan is set; "
            f"only --config/--root were scanned. Drop one of the two flags."))
    return inv


def cmd_discover(args: argparse.Namespace) -> int:
    inv = _collect(args)
    if args.json:
        print(to_json(inv, []))
    else:
        _emit(render_inventory(inv))
        if not args.quiet:
            print()
            print(render_diagnostics(inv.diagnostics))
    return _exit_code(inv.diagnostics)


def cmd_probe(args: argparse.Namespace) -> int:
    inv = _collect(args)
    # Report groups logical servers; probing must still target a concrete
    # endpoint, so use the live candidate from each group.
    specs = inv.probe_targets()
    if args.only:
        wanted = set(args.only)
        specs = [s for s in specs if s.name in wanted]
        missing = wanted - {s.name for s in specs}
        for name in sorted(missing):
            inv.diagnostics.append(
                Diagnostic("warn", "cli.unknown_server",
                           f"--only {name!r} matched no declared server"))

    results: list[ProbeResult] = probe_all(
        specs, allow_spawn=args.allow_spawn, allow_remote=not args.no_remote,
        timeout=args.timeout
    )
    if args.sweep:
        swept, sweep_diags = sweep(specs, timeout=min(args.timeout, 3.0))
        results.extend(swept)
        inv.diagnostics.extend(sweep_diags)

    creds: CredentialReport | None = None
    if args.classify_credentials or args.resolve_credentials:
        creds = analyse(inv.deduped(), resolve=args.resolve_credentials,
                        timeout=args.timeout,
                        allow_remote=not args.no_remote)

    all_diags = list(inv.diagnostics) + [d for r in results for d in r.diagnostics]
    if creds:
        all_diags += list(creds.diagnostics)
        all_diags += [d for r in creds.resolutions for d in r.diagnostics]

    if args.json:
        print(to_json(inv, results, creds))
    else:
        _emit(render_inventory(inv))
        print()
        _emit(render_probe(results, verbose=args.verbose))
        if creds:
            print()
            _emit(render_credentials(creds))
        if not args.quiet:
            print()
            print(render_diagnostics(all_diags))
    return _exit_code(all_diags)


def cmd_prove(args: argparse.Namespace) -> int:
    """Collect the surface, assemble the graph, discharge the policy."""
    from .prove.encode import SegvalUnavailable
    from .report import render_graph, render_proof

    inv = _collect(args)
    specs = inv.probe_targets()
    results = probe_all(specs, allow_spawn=args.allow_spawn,
                        allow_remote=not args.no_remote, timeout=args.timeout)
    if args.sweep:
        swept, sweep_diags = sweep(specs, timeout=min(args.timeout, 3.0))
        results.extend(swept)
        inv.diagnostics.extend(sweep_diags)

    creds = analyse(inv.deduped(), resolve=args.resolve_credentials,
                    timeout=args.timeout, allow_remote=not args.no_remote)

    try:
        policy = load_policy(args.policy) if args.policy else default_policy()
    except PolicyError as exc:
        print(f"policy error: {exc}", file=sys.stderr)
        return 2

    graph = build_agent_graph(inv.deduped(), results, creds)
    try:
        report = run_prover(graph, policy)
    except SegvalUnavailable as exc:
        print(f"{exc}", file=sys.stderr)
        return 2

    all_diags = (list(inv.diagnostics)
                 + [d for r in results for d in r.diagnostics]
                 + list(creds.diagnostics)
                 + [d for r in creds.resolutions for d in r.diagnostics]
                 + list(report.diagnostics))

    if args.json:
        payload = json.loads(to_json(inv, results, creds))
        payload["schema"] = "blastradius/prove/v1"
        payload["graph"] = graph.to_json()
        payload["proof"] = report.to_json()
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        if args.show_graph:
            _emit(render_graph(graph))
            print()
        _emit(render_proof(report))
        if not args.quiet:
            print()
            print(render_diagnostics(all_diags))
    return _exit_code(all_diags)


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "discover":
            return cmd_discover(args)
        if args.command == "probe":
            return cmd_probe(args)
        if args.command == "prove":
            return cmd_prove(args)
    except KeyboardInterrupt:  # pragma: no cover
        print("\ninterrupted", file=sys.stderr)
        return 130
    return 2  # pragma: no cover - argparse enforces a valid subcommand


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
