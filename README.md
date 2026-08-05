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

All five stages. It answers *"what can this agent actually reach, on whose
authority, and can you prove it can't reach the rest?"*

```
stage 1  parse configs      ->  what is declared           [done]
stage 2  handshake + sweep  ->  what is running            [done]
stage 3  resolve creds      ->  what it authorises         [done]
stage 4  prove reach        ->  blast radius               [done]
stage 5  delegation state   ->  whose authority is spent   [done]
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

# identify every credential's issuer — reads values locally, sends NOTHING
blastradius probe --classify-credentials

# ask each issuer what its credential authorises, over a pinned host
blastradius probe --resolve-credentials

# prove it: collect the surface, then discharge a policy against it
blastradius prove --sweep --resolve-credentials --policy policy.yaml

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
| **credentials go only to their issuer** | every provider pins its hosts; an unpinned host raises *before* a socket opens |
| **no credential type can store a value** | a test walks every dataclass field; a future field named `token` fails the suite |
| **echoed secrets are scrubbed** | issuers sometimes return the token in a 401 body; response text is scrubbed before it reaches a report |

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
.venv/bin/python -m pytest -q     # 298 tests
```

`filterwarnings = ["error"]` is on. It has already caught one real file
descriptor leak in the stdio transport.

## Stage 3: credential authority

The question stage 3 answers is *whose permissions does an injected agent
inherit?* It turns an opaque config key into a named principal:

```
  [!!] github:GITHUB_TOKEN
        kind     : github/classic_pat  (exact, via value_prefix)
        acts as  : github:octocat
        scopes   : repo, workflow, read:org
  [  ] deploy:AWS_ACCESS_KEY_ID
        kind     : aws/credential_set
        acts as  : arn:aws:iam::123456789012:user/ci-deploy  in 123456789012
  [ !] stale:OLD_TOKEN
        status   : invalid — REJECTED by issuer — grant is inert

creds.high_impact_scope: github:GITHUB_TOKEN acts as github:octocat with
                         write-capable scope(s): repo, workflow
```

**A two-rung safety ladder.** `--classify-credentials` identifies each issuer
from its documented token prefix (`ghp_`, `AKIA`, `xoxb-`) and emits **no
network traffic at all** — safe to run anywhere, on the first call, in a
customer's environment. `--resolve-credentials` additionally asks the issuer,
over a host pinned to that issuer, using endpoints that cannot mutate.

Supported: GitHub, GitLab, Slack, Google, Hugging Face, OpenAI, AWS
(`sts:GetCallerIdentity`, SigV4 signed with stdlib `hmac`), and RFC 7662
introspection against an operator-nominated endpoint.

**Inert credentials are findings.** A token the issuer rejects is a declared
grant that confers nothing — the same class of result as an MCP server whose
runtime is missing.

**A live credential with no scope list is treated as unbounded**, not as
harmless. AWS and OpenAI expose no scope introspection, so their reach is
reported as unknown rather than empty.

## Stage 4: the proof

```
BLAST RADIUS
====================================================================

  VIOLATIONS
    [!!] agent can WRITE principal:github:octocat
         rule: agent must not hold write authority over any external principal
         1. agent --[create_issue]--> mcp:github
            tool 'create_issue' exposed by github
            declared at /cfg/.mcp.json#mcpServers.github
         2. mcp:github --[repo]--> principal:github:octocat
            github:GITHUB_TOKEN grants scope 'repo' as github:octocat
            declared at /cfg/.mcp.json#mcpServers.github

  PROVEN UNREACHABLE
    [ok] agent cannot WRITE principal:slack:readbot

  3 question(s): 2 violation(s), 1 proven unreachable
```

**Proofs of absence get their own section.** A tool that only ever prints
findings teaches its users that silence means "not checked". The line saying
the agent *cannot* write to Slack — because a read-only tool composed with a
read-only scope admits no write path — is the artifact an auditor actually
wants, and the one that is hard to get any other way.

**Assumed hops are labelled.** Where the surface could not be observed, the
witness says so, and the run lists its assumptions. A violation built entirely
from assumptions is a prompt to go get better data, not a finding to act on.

### Policy

```yaml
version: 1
rules:
  - name: agents must not write to production GitHub
    deny:
      from: agent
      to: "principal:github:*"
      capability: write
```

Without `--policy`, a conservative default denies all agent write authority —
loud by design. Run it, look at what the agent can genuinely reach, then narrow.

### How it is proved

The prover is [segval](https://github.com/skb006/segval), a network
segmentation prover, reused unmodified. **We do not fork it, we adapt at the
boundary:**

```
node       -> zone (a synthetic /24)
hop (u,v)  -> its own device, so each hop has its own filter
capability -> destination port  (1 = read, 2 = write)
grant      -> ACCEPT rule on that hop's device
absence    -> the device's DROP default
```

The encoding preserves the machinery rather than weakening it: segval
partitions the 5-tuple into atomic predicates, which under this mapping
becomes a partition over (principal × resource × capability) — exactly what
stage 4 needs. Soundness is inherited, not re-derived.

Two encoding decisions were bought with bugs:

**Capability, not operation, is the port.** A path has a different operation at
each hop (`create_issue` then `repo`) and one 5-tuple cannot carry both. The
capability class *is* uniform along the path, and is the thing worth proving.
Tool and scope names ride along as witness evidence.

**One device per hop.** A packet's addresses are constant end to end, so a rule
cannot identify its hop by CIDR. An earlier encoding tried, the tool hop was
silently ignored, and every graph looked violated — a prover that always says
yes is worse than none, because it looks like it works.
`test_read_only_tools_cannot_reach_write` pins this down.

### Optional extra, on purpose

`prove` needs segval, so it lives behind `pip install 'blastradius[prove]'`.
The components that read credentials keep their zero-dependency guarantee; the
one that does arithmetic on an already-collected inventory, and touches no
secrets, is where a dependency is acceptable.

## Stage 5: whose authority is being spent

Reachability is only half the question. The half that decides whether a
deployment is defensible is *on whose authority* the agent acts when it gets
there.

```
mode              what it means                              verdict
own_credential    server holds a static secret and presents  confused deputy
                  it whoever called                          
caller_token      server demands a per-caller token, so      bounded
                  authority is the caller's own              
unknown           we could not tell                          counted as deputy
```

Two structurally identical paths — same tool, same scope, same capability —
separate cleanly:

```
CONFUSED DEPUTY - authority spent that nobody delegated
  [!!] agent can WRITE principal:github:octocat with NO delegation
       1. agent --[create_issue]--> mcp:github-static
       2. mcp:github-static --[repo]--> principal:github:octocat

DELEGATED REACH - bounded by the caller's own rights
  [ !] agent can WRITE principal:github:caller only under a delegation
```

The first is the finding worth paging someone about: a hijacked agent inherits
the *server's* rights. The second is a deployment doing it correctly — the
agent can only ever spend what its own caller already had.

### How delegation is proved

`WWW-Authenticate` is captured on the 401 during stage 2 (the MCP authorization
spec puts `resource_metadata` there), surfaced as `ProbeResult.auth_challenge`,
and classified in `prove/delegation.py`.

**Config wins over the challenge.** We probe unauthenticated, so a 401 only says
"some token is required". If the configuration supplies a static one, that is
what the server presents and the caller's identity never enters the request.
Checking the challenge first would let a server with a hardcoded secret
masquerade as delegating. This ordering is also the conservative one, so
correctness and over-approximation agree.

The reachability question is then asked twice, in two capability dimensions:

```python
PORT = {("read", "direct"): 1, ("write", "direct"): 2,
        ("read", "delegated"): 3, ("write", "delegated"): 4}
```

A path reachable in the **direct** dimension needs no delegation at any hop —
anyone who can call the server inherits its authority, proven, with a witness.
A path reachable only in the **delegated** dimension has a real authority
boundary. `direct` is asked first because it is the stronger claim.

Policies can act on the distinction:

```yaml
- name: unbounded server authority is unacceptable
  deny: {from: agent, to: "principal:*", capability: write, delegation: direct}
```

`delegation: direct` flags only reach that needs no delegation, which is the
right rule for a deployment that has accepted delegated access but not
confused deputies.

When *no* server anywhere derives authority from its caller, that is stated
once as a deployment-wide fact (`prove.no_delegation_boundary`) rather than
repeated per finding.

This is segval's conntrack semantics wearing different clothes: a hop is
admissible only because an earlier hop established the right to take it. It is
encoded in the port dimension rather than `Query.state` because `state` exists
on only some segval revisions — see the boundary-adaptation note above.

## Next

Merge the segval branch divergence (`Query.state`, the iptables parser, parse
diagnostics) onto sound `main`, and decide deliberately whether the prober
should read `/proc/<pid>/environ` to see an agent's true surface — that has a
privacy dimension, not just a capability one.
