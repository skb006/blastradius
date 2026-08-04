from __future__ import annotations

import json

import pytest

from blastradius.mcp.jsonrpc import (
    ProtocolError,
    Request,
    RpcError,
    iter_sse_payloads,
    parse_response,
)


def test_request_encoding_is_compact_and_newline_delimited():
    raw = Request("tools/list", {"cursor": "x"}, id=7).encode()
    assert raw.endswith(b"\n")
    assert b", " not in raw, "compact separators keep captured traffic diffable"
    assert json.loads(raw) == {
        "jsonrpc": "2.0", "method": "tools/list", "params": {"cursor": "x"}, "id": 7
    }


def test_notification_omits_id():
    doc = json.loads(Request("notifications/initialized").encode())
    assert "id" not in doc
    assert Request("x").is_notification


def test_parse_response_returns_result():
    assert parse_response('{"jsonrpc":"2.0","id":1,"result":{"ok":true}}', 1) == {"ok": True}


def test_parse_response_raises_on_rpc_error():
    with pytest.raises(RpcError) as ei:
        parse_response('{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"nope"}}')
    assert ei.value.code == -32601


@pytest.mark.parametrize("raw,needle", [
    ("", "empty"),
    ("not json", "non-JSON"),
    ("[1,2]", "expected object"),
    ('{"jsonrpc":"2.0","id":1}', "neither"),
    ('{"jsonrpc":"2.0","id":1,"result":5}', "expected object"),
])
def test_parse_response_rejects_malformed(raw, needle):
    with pytest.raises(ProtocolError) as ei:
        parse_response(raw)
    assert needle in str(ei.value)


def test_parse_response_detects_id_mismatch():
    with pytest.raises(ProtocolError, match="id mismatch"):
        parse_response('{"jsonrpc":"2.0","id":9,"result":{}}', expect_id=1)


def test_parse_response_accepts_bytes():
    assert parse_response(b'{"jsonrpc":"2.0","id":1,"result":{}}') == {}


def test_sse_parsing_single_event():
    body = "event: message\ndata: {\"a\":1}\n\n"
    assert list(iter_sse_payloads(body)) == ['{"a":1}']


def test_sse_parsing_multiline_and_comments():
    body = ": keep-alive\n\ndata: {\"a\":\ndata: 1}\n\ndata: {\"b\":2}\n"
    assert list(iter_sse_payloads(body)) == ['{"a":\n1}', '{"b":2}']


def test_sse_parsing_empty_body():
    assert list(iter_sse_payloads("")) == []
