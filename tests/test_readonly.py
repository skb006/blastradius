"""The read-only guarantee.

This is the security property the product is sold on, so it is tested three
ways: the allowlist rejects writes, the client exposes no write method, and
an end-to-end probe against a peer that *would* answer ``tools/call`` never
sends one.
"""

from __future__ import annotations

import pytest

from blastradius.mcp.client import (
    FORBIDDEN_METHODS,
    READ_ONLY_METHODS,
    McpClient,
    ReadOnlyViolation,
)
from blastradius.probe import probe_server


class _RecordingTransport:
    def __init__(self):
        self.sent: list[str] = []

    def exchange(self, request):
        self.sent.append(request.method)
        return (
            '{"jsonrpc":"2.0","id":%d,"result":{"protocolVersion":"2025-06-18",'
            '"capabilities":{},"serverInfo":{"name":"t","version":"1"}}}' % request.id
        )

    def notify(self, request):
        self.sent.append(request.method)

    def close(self):
        pass

    @property
    def stderr_tail(self):
        return ""


def test_allowlist_and_forbidden_set_are_disjoint():
    assert not (READ_ONLY_METHODS & FORBIDDEN_METHODS)


def test_every_allowed_method_is_a_read():
    # A method that mutates would have to be named here to be sendable at all.
    assert READ_ONLY_METHODS == {
        "initialize",
        "notifications/initialized",
        "tools/list",
        "resources/list",
        "resources/templates/list",
        "prompts/list",
        "ping",
    }


@pytest.mark.parametrize("method", sorted(FORBIDDEN_METHODS))
def test_forbidden_methods_are_rejected_before_any_bytes_are_sent(method):
    t = _RecordingTransport()
    client = McpClient(t)
    with pytest.raises(ReadOnlyViolation):
        client._request(method)
    assert t.sent == [], "nothing may leave the process for a forbidden method"


def test_unknown_methods_are_rejected_too():
    client = McpClient(_RecordingTransport())
    with pytest.raises(ReadOnlyViolation, match="not on the read-only allowlist"):
        client._request("some/newMethod")


def test_client_exposes_no_invocation_method():
    """The public surface is four reads and a close. Nothing can invoke."""
    public = {n for n in dir(McpClient) if not n.startswith("_")}
    assert public == {"handshake", "list_tools", "list_resources", "list_prompts", "close"}
    for banned in ("call", "call_tool", "invoke", "read_resource", "get_prompt", "complete"):
        assert banned not in public


def test_end_to_end_probe_never_calls_a_tool(stdio_spec):
    """The fake peer answers tools/call with a tripwire string.

    If that string ever appears in the result, the prober invoked a tool.
    """
    result = probe_server(stdio_spec(), allow_spawn=True)
    assert result.status == "ok"
    assert "READ_ONLY_BREACH" not in str(result.to_json())


def test_probe_refuses_to_spawn_without_optin(stdio_spec):
    result = probe_server(stdio_spec(), allow_spawn=False)
    assert result.status == "skipped"
    assert any(d.code == "probe.skipped_stdio" for d in result.diagnostics)
    assert result.tools == ()
