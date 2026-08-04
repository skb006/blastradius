#!/usr/bin/env python3
"""A real, minimal MCP server over stdio — used as a test peer.

Deterministic on purpose: the probe tests assert exact tool counts and
annotation handling, so this server must not vary between runs.

Behaviour is switched by argv so one script covers the negative cases too:

    --banner        print noise on stdout before speaking protocol
    --no-annotations  omit tool annotations (exercises write-capable default)
    --paginate      return tools across two pages
    --die           exit immediately (exercises Unreachable)
    --hang          accept the request and never answer (exercises TimeoutError)
    --rpc-error     answer initialize with a JSON-RPC error
"""
from __future__ import annotations

import json
import sys
import time

PROTOCOL = "2025-06-18"

TOOLS_PAGE_1 = [
    {
        "name": "search_tickets",
        "description": "Search the ticket system.",
        "inputSchema": {
            "type": "object",
            "properties": {"query": {"type": "string"}, "limit": {"type": "number"}},
            "required": ["query"],
        },
        "annotations": {"readOnlyHint": True, "destructiveHint": False},
    },
    {
        "name": "delete_ticket",
        "description": "Permanently delete a ticket.",
        "inputSchema": {
            "type": "object",
            "properties": {"ticket_id": {"type": "string"}},
            "required": ["ticket_id"],
        },
        "annotations": {"readOnlyHint": False, "destructiveHint": True},
    },
]

TOOLS_PAGE_2 = [
    {
        "name": "export_all",
        "description": "Export every record.",
        "inputSchema": {"type": "object", "properties": {"dest": {"type": "string"}}},
        # no annotations -> must be treated as write-capable
    }
]


def main() -> int:
    flags = set(sys.argv[1:])

    if "--die" in flags:
        return 3

    if "--banner" in flags:
        print("fake-mcp starting up, listening on stdio", flush=True)
        print("not json at all", flush=True)

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            continue

        method = req.get("method")
        rid = req.get("id")

        if method == "notifications/initialized":
            continue  # notifications get no reply

        if "--hang" in flags and method == "tools/list":
            time.sleep(60)
            continue

        if method == "initialize":
            if "--rpc-error" in flags:
                _send({"jsonrpc": "2.0", "id": rid,
                       "error": {"code": -32603, "message": "internal error"}})
                continue
            _send({
                "jsonrpc": "2.0", "id": rid,
                "result": {
                    "protocolVersion": PROTOCOL,
                    "capabilities": {"tools": {}, "resources": {}, "prompts": {}},
                    "serverInfo": {"name": "fake-mcp", "version": "1.2.3"},
                },
            })
        elif method == "tools/list":
            tools = list(TOOLS_PAGE_1)
            result: dict = {}
            if "--no-annotations" in flags:
                tools = [{k: v for k, v in t.items() if k != "annotations"} for t in tools]
            if "--paginate" in flags:
                if req.get("params", {}).get("cursor") == "page2":
                    tools = TOOLS_PAGE_2
                else:
                    result["nextCursor"] = "page2"
            else:
                tools = tools + TOOLS_PAGE_2
            result["tools"] = tools
            _send({"jsonrpc": "2.0", "id": rid, "result": result})
        elif method == "resources/list":
            _send({"jsonrpc": "2.0", "id": rid, "result": {"resources": [
                {"uri": "file:///var/data/tickets.db", "name": "tickets",
                 "mimeType": "application/x-sqlite3"},
            ]}})
        elif method == "prompts/list":
            _send({"jsonrpc": "2.0", "id": rid,
                   "result": {"prompts": [{"name": "triage"}]}})
        elif method == "tools/call":
            # Should never happen. If the prober ever sends this, the test
            # suite must fail loudly rather than quietly succeed.
            _send({"jsonrpc": "2.0", "id": rid,
                   "result": {"content": [{"type": "text", "text": "READ_ONLY_BREACH"}]}})
        else:
            _send({"jsonrpc": "2.0", "id": rid,
                   "error": {"code": -32601, "message": f"unknown method {method}"}})
    return 0


def _send(payload: dict) -> None:
    sys.stdout.write(json.dumps(payload) + "\n")
    sys.stdout.flush()


if __name__ == "__main__":
    raise SystemExit(main())
