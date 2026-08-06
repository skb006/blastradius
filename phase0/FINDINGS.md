# Phase 0 findings — is agent blast radius derivable?

Measured against a real agent installation — a developer workstation running two
agent runtimes, a plugin marketplace, and a set of managed cloud connectors — not
a hypothetical. Host-identifying detail (connector vendors, plugin names, live
port numbers) is redacted; every count and every ratio is as measured.

## Verdict

**Pure static config parsing fails. Parse + probe passes. This is a prober, not a linter.**

## 1. What is actually on disk

| source | count | note |
|---|---|---|
| ephemeral `mcp.json` under a per-session temp dir | 21 | 20 identical, **1 unparseable** |
| plugin-declared `.mcp.json` (marketplace) | 4 | four messaging/chat plugins |
| MCP servers in the agent's global config | 0 | global and project scope both empty |
| skills declared by the runtime | 41 | **all disabled** |
| `SKILL.md` with frontmatter | 3 | 2 declare `allowed-tools` |
| explicit `denyCommands` | 8 | device-capability denials |
| managed connectors live this session | 5 | configured in the vendor account, not on disk |

The 21 ephemeral configs are the shadow-agent problem in miniature: agent
authorization material scattered through temp directories, one of it already
corrupt. Any collector must be **diagnostic** on parse failure rather than
silently skipping — a skipped config is an unproven claim.

## 2. The measurement that matters

Naively counting every grant-bearing *fact* gives 48.4% declared, which flatters
the result. Split the facts by whether they **grant** reach or **restrict** it:

- grant-bearing edges: **63**
- restriction-bearing facts: **58**

Blast radius is computed from grants; restrictions only prune. Over grants alone:

| classification | count | share | what it is |
|---|---:|---:|---|
| DECLARED | 1 | **1.6%** | workspace filesystem root |
| INTROSPECTABLE | 23 | 36.5% | MCP servers + tool profile — recoverable via `tools/list` |
| OPAQUE | 34 | 54.0% | env/header credentials whose backend reach is invisible |
| OFF_HOST | 5 | 7.9% | managed connectors, configured in the vendor account |

> **Configuration files tell you what an agent is forbidden to do.
> They almost never tell you what it can reach.**

Of 58 restriction facts, all 58 are declared. Of 63 grant edges, 1 is.
The asymmetry is the finding.

## 3. Consequence for the architecture

The collector is three stages, not one:

1. **Parse** — configs on disk. Yields the restriction lattice and the server
   inventory. ~2% of grants.
2. **Handshake** — speak MCP to each server, `tools/list`. Recovers the tool
   surface. Takes coverage to **38%**.
3. **Resolve** — take each discovered credential and ask its provider what it
   actually authorises, read-only:
   - GitHub → `X-OAuth-Scopes` response header
   - AWS → `sts:GetCallerIdentity` + `iam:SimulatePrincipalPolicy`
   - Google → `tokeninfo` endpoint
   - generic OAuth → introspection endpoint (RFC 7662)

   This is the 54% bucket and the only route to it short of runtime observation.

Managed connectors (8%) need vendor admin APIs — enterprise tier, deferred.

**Stage 3 is the moat.** Stage 1 is a weekend of work and anyone can clone it.
Cross-provider credential→scope resolution, kept sound, is not.

**Design constraint it imposes:** the tool handles live secrets. It must run
locally, transmit nothing, and only ever issue read-only introspection calls.
That has to be a stated guarantee, testable in CI, or no regulated buyer will
run it.

## 4. Does the prover work unmodified?

Yes. `spike.py` encodes the Kagenti confused-deputy hospital scenario into
segval's existing IR and runs it through `reach()` untouched:

```
[!!] agent_d_insurance --read_patient_record--> tool_patient_records: REACHABLE
     granted by: -A FORWARD -s 10.0.0.0/8 -d 10.90.0.0/24 -p tcp --dport 5432 -j ACCEPT
     source    : configs/authz_vulnerable.iptables-save:6

     (narrow the grant to the orchestrator's range)

[ok] agent_d_insurance --read_patient_record--> tool_patient_records: proven unreachable
     no grant matched -> default policy denied
```

The verdict is not the interesting part. The **witness** is: it names the
offending grant, with file and line. That is the product's output, already
working.

## 5. IR generalisations Phase 1 must do

The spike works by encoding principals as CIDRs and operations as TCP ports.
That proves the graph algebra transfers; it is not shippable. Required:

| segval today | needs to become |
|---|---|
| `src_ip: IPv4Address` | opaque principal identifier |
| `dst_port: int` | operation name (string) |
| `proto: tcp/udp/icmp` | invocation kind (tool call / resource read / sub-agent) |
| `state: NEW/ESTABLISHED` | delegation state — token obtained at hop N−1 |
| AP partition over 5-tuple | AP partition over (principal × resource × operation) |

The last row is the load-bearing one. The atomic-predicate partitioner is what
makes exhaustive "for all requests" queries tractable; it must be re-derived over
the new dimensions or the whole soundness claim degrades to spot-checking.

`Decision.checkpoint` exists but is not populated by default — wire it on, it is
the audit-evidence primitive and it is already built.

## 6. Blocker carried forward

segval `main` and `cursor/segval-improvements-0bc1` diverged at `861321c` and
implemented Step 5 twice, differently:

- `main` — `derive_sessions()`, per-query, sound
- `cursor` — `synthesize_stateful_returns()`, static wildcard over-approximation

Take `main` as the base. The product sells proofs; an unsound reverse edge makes
every "unreachable" verdict worthless. Cherry-pick the cursor branch's additive
work (CI, GitHub Action, +266-line iptables parser, parse diagnostics, trace v2).

## 7. Go / no-go

**Go**, with the thesis amended: this is not "parse the config and prove the
graph." It is **probe the deployment and prove the graph**. The amendment makes
the product harder to build and much harder to copy.

---

# Addendum — measured against a live install (stage-2 prober built)

The 38% handshake-recovery estimate in §2 **did not hold**. Measured, not estimated:

```
servers declared      : 7
surfaces recovered    : 0  (0%)
```

Four distinct, all legitimate reasons — none of which the config-only model predicted:

| reason | count | meaning |
|---|---:|---|
| `runtime_missing` | 4 | the plugins' JS runtime is not installed, so those servers cannot run at all — declared grant, inert host |
| `unreachable` | 1 | every declared endpoint was a finished session |
| `auth_required` | 2 | surface exists and is gated |

## The finding that changes the architecture

```
declared loopback endpoints : 17 distinct ephemeral ports, across 21 config files
actually listening          :  6 loopback ports
intersection                : none
```

**All 17 declared endpoints were dead. The live agent held a seventeenth port,
declared in no file on disk.** Configuration is a record of sessions that have happened;
the socket table is the record of what is happening.

So stage 2 is two things, not one:

- **2a handshake** — ask declared servers what they expose
- **2b liveness sweep** — enumerate listening loopback sockets, ask each whether
  it speaks MCP, diff against what was declared

The sweep found the shadow agent on the first run:

```
sweep.shadow_agent: MCP server listening on 127.0.0.1:<port>/mcp
                    is declared in NO config file (gated)
```

## What this does to the thesis

It strengthens it. The stages are not additive-optional, they are a **chain**:

1. parse → what was declared (mostly stale)
2. sweep → what is actually live (config missed it entirely)
3. **resolve credentials → what it authorises** ← everything live was gated

Both live MCP servers returned 401. The tool surface is
unreachable *without the credential*, which means stage 3 is not one of three
routes to coverage — it is the only route past the gate. Phase 0 called
credential→scope resolution "the moat" on the basis that it covered 54% of
grant edges. The live measurement is stronger: without it, recovery is 0%.

## Corrected estimate

| stage | coverage on the measured host |
|---|---:|
| parse only | 1.6% of grant edges |
| + handshake | 0% of *servers* (everything inert, stale, or gated) |
| + sweep | live surface located, still gated |
| + credential resolution | **required for any tool enumeration at all** |

## Defects the live run exposed in the tool itself

1. **Ephemeral port rotation defeated dedup** — 20 declarations of one server
   reported as 19 distinct servers, and the sprawl warning never fired because
   no identity repeated. Fixed with `logical_identity`.
2. **`probe_targets()` picked the lexicographically highest URL**, i.e. the
   highest port number, which has nothing to do with which session is live.
   Fixed to select by config mtime.
3. **The CLI banner overclaimed** — "never transmits anything off this host" is
   false the moment you probe a remote endpoint. Reworded, and `--no-remote`
   added to make the restricted mode real.
4. **A file-descriptor leak in the stdio transport**, caught by
   `filterwarnings = ["error"]`.

All four were found by running the tool for real. None would have been found by
testing alone.
