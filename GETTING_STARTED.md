# Getting started

A ten-minute path from nothing to a real blast-radius report on your own
machine. Every command here has been run start-to-finish on a clean clone — if
one fails for you, that is a bug, so please open an issue.

## What this tool does, in one line

It reads the AI-agent configuration on a machine and proves what an agent there
could reach if it were hijacked — and, just as usefully, proves what it
*cannot* reach.

## Prerequisites

- Python 3.11 or newer
- `git`
- That's it. The base tool has **zero dependencies**.

## 1. Install

```bash
git clone https://github.com/skb006/blastradius.git
cd blastradius
python3 -m venv .venv
.venv/bin/pip install -e .
```

Check it works:

```bash
.venv/bin/blastradius --help
```

## 2. See what's declared — no network, nothing executed

```bash
.venv/bin/blastradius discover
```

This scans the well-known agent config locations under your home directory and
lists every declared MCP server. It opens no sockets and runs no processes, so
it is completely safe to run anywhere. If you have no agents installed you'll
see `none found` — that's a valid answer, not an error.

Reading the output: each server shows its `target`, the config file it was
declared in (`origin`), and — if it carries a credential — a `creds` line naming
the *key only*, never the value.

## 3. See what's actually running

```bash
.venv/bin/blastradius probe --sweep --no-remote
```

`probe` handshakes with each declared server and lists the tools it really
exposes. `--sweep` also scans your loopback ports for MCP servers that **no
config declares** — this is how it finds "shadow agents" that a config-only view
misses entirely. `--no-remote` keeps all contact on `127.0.0.1`, so nothing
leaves the machine.

Two flags you'll reach for:

- `--allow-spawn` — **executes** the commands in stdio server configs to probe
  them. Off by default because it runs code from config files. Only use it on a
  machine whose configs you trust.
- `--timeout 3` — shorten per-request waits if a dead endpoint is slow.

## 4. Prove the blast radius

The prover needs one extra package (a reachability engine called
[segval](https://github.com/skb006/segval)); it's kept separate so the
credential-reading parts of the tool ship no dependencies of their own.

```bash
.venv/bin/pip install -e ".[prove]"
.venv/bin/blastradius prove --sweep --no-remote
```

You'll get one of two things for every question, and **both matter**:

```
CONFUSED DEPUTY — authority spent that nobody delegated
  [!!] agent can WRITE principal:github:octocat with NO delegation
       1. agent --[create_issue]--> mcp:github
       2. mcp:github --[repo]--> principal:github:octocat
```

or

```
PROVEN UNREACHABLE
  [ok] agent cannot WRITE principal:slack:readbot
```

A **confused deputy** means the server holds its own credential, so anyone who
can reach it inherits that authority — the dangerous case. A **proof of absence**
is the thing that's genuinely hard to get any other way: evidence that a path
does *not* exist.

## Reading the first run: it will be loud, on purpose

Anything the tool cannot inspect is counted as fully write-capable. That's
deliberate — understating blast radius is the one error a tool like this must
never make — so a first run over-reports. To turn the noise into signal, write a
policy describing what your deployment is actually allowed to do:

```yaml
# policy.yaml
version: 1
rules:
  - name: agents must not write to production GitHub
    deny: { from: agent, to: "principal:github:*", capability: write }
```

```bash
.venv/bin/blastradius prove --policy policy.yaml
```

Now it reports only the paths that violate *your* rules, with a witness for each.

## Auditing a machine that isn't this one

Point `--home` at a mounted filesystem or another account's home:

```bash
.venv/bin/blastradius discover --home /mnt/target/home/user
```

## Exit codes (for CI)

| code | meaning |
|---|---|
| `0` | clean |
| `1` | something was unreadable, or a policy was violated |
| `2` | bad usage |

An unparseable config exits non-zero on purpose: an incomplete inventory
reported as success is exactly the failure this tool exists to prevent.

## Two safety facts worth knowing before you run it

- **It never reads a credential *value*** unless you pass `--resolve-credentials`,
  and even then each credential is sent only to its own issuer (GitHub → GitHub),
  over a pinned connection that refuses redirects and proxies. Everything else
  works from key names alone.
- **It never executes anything from a config** unless you pass `--allow-spawn`.

## Confirm the build is sound

```bash
.venv/bin/pip install -e ".[dev]"
.venv/bin/python -m pytest -q
```

A green suite (400+ tests) means the security invariants above are holding on
your machine, not just claimed in a README.

## Where to go next

- `README.md` — the design and the safety properties, in depth.
- `phase0/FINDINGS.md` — why this is a prober and not a linter, measured against
  a real install.
