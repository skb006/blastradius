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
import sys
import tempfile
from pathlib import Path
from typing import Sequence

from .discovery import discover
from .model import Diagnostic, Inventory, ProbeResult
from .probe import probe_all
from .sweep import sweep
from .report import render_diagnostics, render_inventory, render_probe, to_json
from .mcp.transport import DEFAULT_TIMEOUT

BANNER = (
    "blastradius — read-only MCP prober. It never invokes a tool, never reads a "
    "credential value, and never sends your findings or credentials anywhere. "
    "It does contact the MCP endpoints declared in your config, because that is "
    "how their surface is discovered; use --no-remote to restrict probing to "
    "loopback."
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
    return discover(project_roots=args.root, home=home, extra_paths=args.config)


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

    all_diags = list(inv.diagnostics) + [d for r in results for d in r.diagnostics]

    if args.json:
        print(to_json(inv, results))
    else:
        _emit(render_inventory(inv))
        print()
        _emit(render_probe(results, verbose=args.verbose))
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
    except KeyboardInterrupt:  # pragma: no cover
        print("\ninterrupted", file=sys.stderr)
        return 130
    return 2  # pragma: no cover - argparse enforces a valid subcommand


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
