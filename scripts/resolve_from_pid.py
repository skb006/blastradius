#!/usr/bin/env python3
"""Resolve the credentials in a running process's environment.

This is the capability blastradius has been circling since stage 3: to see an
agent's *true* blast radius you have to look at the credentials it was actually
launched with, which live in its process environment — not in any config file.

Two deliberate safety choices, because this reads live secrets:

  * It never prints a credential VALUE. Only the key name, the issuer, and what
    the issuer says the credential authorises (principal + scopes).
  * Resolution is OPT-IN. Without --resolve it classifies only, which is
    provably egress-free. With --resolve it presents each credential to that
    credential's own pinned issuer and nowhere else — the same host-pinning and
    response-scrubbing the rest of the tool uses.

Usage:
    python scripts/resolve_from_pid.py <pid>            # classify only, no network
    python scripts/resolve_from_pid.py <pid> --resolve  # ask each issuer (real egress)

You are running this yourself, on your own machine, against your own process.
Reading /proc/<pid>/environ requires that you own the process (or are root).
"""

from __future__ import annotations

import sys
from pathlib import Path

# Make the package importable when run from the repo without installing.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from blastradius.creds.model import CredentialRef
from blastradius.creds.resolve import resolve_refs
from blastradius.creds.classify import classify
from blastradius.creds.source import SecretSource
from blastradius.model import Origin
from blastradius.redact import looks_sensitive
from blastradius.report import render_credentials


def read_environ(pid: int) -> dict[str, str]:
    raw = Path(f"/proc/{pid}/environ").read_bytes()
    env: dict[str, str] = {}
    for chunk in raw.split(b"\0"):
        if not chunk or b"=" not in chunk:
            continue
        k, _, v = chunk.partition(b"=")
        env[k.decode("utf-8", "replace")] = v.decode("utf-8", "replace")
    return env


def main() -> int:
    if len(sys.argv) < 2 or not sys.argv[1].isdigit():
        print(__doc__)
        return 2
    pid = int(sys.argv[1])
    resolve = "--resolve" in sys.argv[1:]

    try:
        env = read_environ(pid)
    except PermissionError:
        print(f"permission denied reading /proc/{pid}/environ — you must own the process")
        return 1
    except FileNotFoundError:
        print(f"no process {pid}")
        return 1

    origin = Origin(f"/proc/{pid}/environ", f"pid={pid}")
    source = SecretSource(environ=env)

    # Identify credential-bearing variables. A variable counts if its NAME looks
    # sensitive or its VALUE carries a recognised issuer prefix. The value is
    # only ever read here to classify it; it is never printed or returned.
    refs: list[CredentialRef] = []
    for key in sorted(env):
        cls = classify(key, env[key])
        if looks_sensitive(key) or cls.provider != "unknown":
            # source="process_env" tells SecretSource to read the value straight
            # from this environ by key name.
            refs.append(CredentialRef(key, origin, "process_env", server_name=f"pid:{pid}"))

    if not refs:
        print(f"pid {pid}: {len(env)} variables, none credential-bearing")
        return 0

    print(f"pid {pid}: {len(env)} variables, {len(refs)} credential-bearing")
    if resolve:
        issuers = sorted({
            classify(r.key_name, source.value_for(r) or "").provider
            for r in refs
        } - {"unknown"})
        print("resolving — each credential is sent to its OWN pinned issuer only: "
              f"{', '.join(issuers) or '(none have a known issuer; nothing is sent)'}")
    else:
        print("classify-only — NOTHING leaves this machine. Add --resolve to query issuers.")
    print()

    # The same pinned, response-scrubbed resolution path the CLI uses.
    report = resolve_refs(refs, src=source, resolve=resolve)
    print(render_credentials(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
