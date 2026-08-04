# blastradius

**Prove what an AI agent can actually reach.**

Everyone else sells runtime AI security — gateways, filters, prompt-injection
classifiers. That is a losing arms race: prompt injection has been OWASP's #1
LLM risk three years running, and adversarial *poetry* beats the guardrails.

Blast radius is a structural property. It does not depend on detecting the
injection.

> We can't stop your agent being hijacked. We can prove what happens when it is.

The buying trigger, from IBM's 2026 Cost of a Data Breach report: **92% of
AI-related breaches hit organisations lacking access controls — not
organisations with bad models.**

---

## Status

Stage 2 of 3. This repo currently answers *"what MCP servers exist here and
what can they actually do?"* It does not yet compute reachability — that lands
when the [segval](https://github.com/skb006/segval) prover is wired in.

```
stage 1  parse configs      ->  what is declared      [done]
stage 2  handshake + sweep  ->  what is running       [done]  <- you are here
stage 3  resolve creds      ->  what it authorises    [next]
stage 4  prove reach        ->  blast radius          [planned]
```

## Install

```bash
python -m venv .venv && .venv/bin/pip install -e ".[dev]"
```

Zero runtime dependencies, deliberately. This tool reads live credentials, so
it ships no supply chain of its own.

## Use

```bash
# what does configuration declare? no network, no processes spawned
blastradius discover -r ~/projects

# talk to them and list what they really expose
blastradius probe --sweep

# CI-safe: no remote egress, no code execution, machine-readable
blastradius probe --no-remote --json > agent-surface.json
```

Exit codes: `0` clean · `1` something was unreadable or unprovable · `2` usage.
A malformed config exits non-zero on purpose — an incomplete inventory reported
as success is the failure mode this tool exists to prevent.

## Safety properties

These are enforced, not promised, and each has a test:

| property | how it is enforced |
|---|---|
| **never invokes a tool** | `McpClient` has no method that can express a call; every method name is checked against a read-only allowlist before a byte is sent (`test_readonly.py`) |
| **never reads a credential value** | secrets are dropped at parse time, so they never enter a dataclass and cannot leak through a new output path (`test_redact.py`) |
| **never executes config** | stdio servers are only spawned under explicit `--allow-spawn` |
| **no unexpected egress** | `--no-remote` restricts probing to loopback |
| **no supply chain** | zero runtime dependencies |

The test peer answers `tools/call` with a tripwire string. If the prober ever
invoked a tool, the suite fails.

## What it finds

Real output from the machine this was built on:

```
sweep.shadow_agent: MCP server listening on 127.0.0.1:40279/mcp
                    is declared in NO config file
sweep.all_declared_endpoints_dead: none of the declared loopback endpoints
                    are listening — configuration describes past sessions,
                    not current reach
config.sprawl:      'openclaw' declared in 20 separate config copies
config.malformed:   invalid JSON — any servers declared here are UNKNOWN,
                    not absent
probe.runtime_missing: command not found on PATH: 'bun'
                    — this grant is declared but inert on this host
server.carries_credentials: 'openclaw' carries 2 credential(s) whose backend
                    scope is not visible from config
probe.unannotated_tools: 3/3 tools carry no readOnly/destructive hint
                    — counted as write-capable
```

### Why the sweep is not optional

Measured on a real install:

```
declared openclaw endpoints : 17 loopback ports
actually listening          :  6 loopback ports
intersection                : none
```

Every declared endpoint was dead, and the running agent held a port no file on
disk mentioned. Configuration is a record of sessions that *have happened*; the
socket table is the record of what *is* happening. A prober that trusts only
config reports 0% coverage on a machine with a live agent on it.

## Design decisions worth knowing

**Unannotated tools count as write-capable.** MCP tool annotations
(`readOnlyHint`, `destructiveHint`) are optional and usually absent. Treating an
unannotated tool as read-only would understate blast radius, which is the one
error this tool must never make. Sound over-approximation, always.

**`auth_required` is a result, not a failure.** A 401 proves a surface exists
and is gated — a materially different fact from "nothing here". Getting past the
gate needs the credential, which is stage 3.

**Ephemeral loopback ports are normalised for grouping.** A runtime that rebinds
per session would otherwise present twenty copies of one server as twenty
servers, and suppress the sprawl warning because no identity ever repeats.

**JSON output excludes timing.** The report is meant to be committed and
diffed; two runs against an unchanged deployment must diff to nothing.

## Tests

```bash
.venv/bin/python -m pytest -q     # 151 tests
```

`filterwarnings = ["error"]` is on. It has already caught one real file
descriptor leak in the stdio transport.

## Next

Stage 3 — resolve each discovered credential against its provider, read-only:
GitHub `X-OAuth-Scopes`, AWS `GetCallerIdentity` + `SimulatePrincipalPolicy`,
Google `tokeninfo`, RFC 7662 introspection. That is the 54% of grant edges
configuration cannot see, and it is the part a competitor cannot clone in a
weekend.
