"""Delegation: *on whose authority* does each hop act?

Stage 4 answers "can the agent reach this principal". That is not the whole
question. The one that decides whether a deployment is defensible is:

    when the agent reaches it, whose permissions is it spending?

Three modes, and the difference between them is the whole confused-deputy
literature:

``own_credential``
    The server holds a static secret and presents it regardless of who
    called. **Every caller inherits the server's full authority.** No
    delegation exists; there is nothing for a policy to bound. This is the
    confused deputy, and it is what almost every MCP server in the wild does.

``caller_token``
    The server demands a per-caller token (OAuth, under the MCP authorization
    spec). Authority is bounded by the *caller's* rights, so a hijacked agent
    inherits only what its own identity already had.

``unknown``
    We could not tell. Treated as ``own_credential`` for reach purposes,
    because assuming a delegation boundary exists when it might not is the
    error that matters.

**The formal claim this enables.** Encode "requires no delegation" as one
capability dimension and "requires a delegation established upstream" as
another. Then a path that is reachable in the *direct* mode is one where
authority was obtained without the agent's identity being involved at any
hop — a confused deputy, proven, with a witness. A path reachable only in the
*delegated* mode has a genuine authority boundary.

This is segval's conntrack semantics wearing different clothes: a hop is
admissible only because an earlier hop established the right to take it.
"""

from __future__ import annotations

from typing import Literal, Sequence

from ..model import ProbeResult, ServerSpec

DelegationMode = Literal["own_credential", "caller_token", "unknown"]


def classify_server(
    spec: ServerSpec, probe: ProbeResult | None
) -> tuple[DelegationMode, str]:
    """Decide how a server obtains the authority it acts with.

    Returns ``(mode, reason)``; the reason becomes witness evidence.
    """
    # Config wins over the challenge. We probe unauthenticated, so a 401 only
    # says "some token is required" — if the configuration supplies a static
    # one, that is what the server will present, and the caller's identity
    # never enters the request. Checking the challenge first would let a
    # server with a hardcoded secret masquerade as delegating.
    #
    # This ordering is also the conservative one, so correctness and
    # over-approximation agree.
    if spec.credential_keys:
        return (
            "own_credential",
            f"{spec.name} holds {', '.join(spec.credential_keys)} in its own "
            f"configuration and presents it on every call, whoever made it",
        )

    # No static secret, and the server demands a token: the caller must supply
    # one, so authority is bounded by whoever called.
    if probe is not None and probe.requires_caller_token:
        return (
            "caller_token",
            f"{spec.name} challenges for a per-caller token "
            f"({(probe.auth_challenge or '')[:80]!r}) and holds no static "
            f"credential, so authority is bounded by the caller",
        )

    if probe is not None and probe.status == "auth_required":
        return (
            "unknown",
            f"{spec.name} is gated but issued no challenge we could read; "
            f"delegation boundary unproven",
        )

    return (
        "unknown",
        f"{spec.name} declares no credential and issued no challenge; "
        f"delegation boundary unproven",
    )


def is_confused_deputy(mode: DelegationMode) -> bool:
    """Does this mode let a caller spend authority that is not its own?

    ``unknown`` counts. Assuming a delegation boundary that may not exist is
    the error that understates blast radius, and this tool errs the other way.
    """
    return mode in ("own_credential", "unknown")


def summarise(
    servers: Sequence[ServerSpec], probes: Sequence[ProbeResult]
) -> dict[str, tuple[DelegationMode, str]]:
    by_name = {p.server.name: p for p in probes}
    return {
        s.name: classify_server(s, by_name.get(s.name))
        for s in servers
    }
