"""Shared fixtures: a stdio peer and an in-process HTTP peer."""

from __future__ import annotations

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from blastradius.model import Origin, ServerSpec

FAKE_SERVER = Path(__file__).parent / "fake_mcp_server.py"

PROTOCOL = "2025-06-18"


@pytest.fixture
def stdio_spec():
    """Build a ServerSpec that spawns the fake stdio server with given flags."""

    def _make(*flags: str, name: str = "fake") -> ServerSpec:
        return ServerSpec(
            name=name,
            transport="stdio",
            origin=Origin("<test>", f"mcpServers.{name}"),
            command=sys.executable,
            args=(str(FAKE_SERVER), *flags),
        )

    return _make


class _Handler(BaseHTTPRequestHandler):
    """Streamable-HTTP MCP peer. Mode is set on the server object."""

    protocol_version = "HTTP/1.1"

    def log_message(self, *args):  # noqa: A003 - silence test noise
        return

    def do_POST(self):  # noqa: N802
        mode = self.server.mode  # type: ignore[attr-defined]
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode()
        req = json.loads(raw) if raw.strip() else {}
        method, rid = req.get("method"), req.get("id")

        self.server.seen_methods.append(method)  # type: ignore[attr-defined]

        if mode == "auth":
            self._respond_raw(401, b'{"error":"unauthorized"}', "application/json")
            return
        if mode == "notjson":
            self._respond_raw(200, b"<html>not mcp</html>", "text/html")
            return
        if mode == "legacy":
            self._respond_raw(405, b"use GET /sse", "text/plain")
            return

        if method == "notifications/initialized":
            self._respond_raw(202, b"", "application/json")
            return

        if method == "initialize":
            body = {"jsonrpc": "2.0", "id": rid, "result": {
                "protocolVersion": PROTOCOL,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "fake-http-mcp", "version": "0.9"},
            }}
        elif method == "tools/list":
            body = {"jsonrpc": "2.0", "id": rid, "result": {"tools": [
                {"name": "fetch_url",
                 "inputSchema": {"type": "object", "properties": {"url": {"type": "string"}}},
                 "annotations": {"readOnlyHint": True, "openWorldHint": True}},
            ]}}
        else:
            body = {"jsonrpc": "2.0", "id": rid, "result": {}}

        payload = json.dumps(body).encode()
        if mode == "sse":
            payload = b"event: message\ndata: " + payload + b"\n\n"
            self._respond_raw(200, payload, "text/event-stream",
                              extra={"Mcp-Session-Id": "sess-123"})
        else:
            self._respond_raw(200, payload, "application/json",
                              extra={"Mcp-Session-Id": "sess-123"})

    def _respond_raw(self, code: int, body: bytes, ctype: str, extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if body:
            self.wfile.write(body)


@pytest.fixture
def http_server():
    """Start an MCP-speaking HTTP peer; yields a factory returning its URL."""
    servers = []

    def _start(mode: str = "json") -> str:
        srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        srv.mode = mode  # type: ignore[attr-defined]
        srv.seen_methods = []  # type: ignore[attr-defined]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append(srv)
        return f"http://127.0.0.1:{srv.server_address[1]}/mcp"

    yield _start
    for srv in servers:
        srv.shutdown()
        srv.server_close()


@pytest.fixture
def http_spec(http_server):
    def _make(mode: str = "json", name: str = "http-fake") -> ServerSpec:
        return ServerSpec(
            name=name, transport="http",
            origin=Origin("<test>", f"mcpServers.{name}"),
            url=http_server(mode),
        )

    return _make


@pytest.fixture
def fake_home(tmp_path: Path) -> Path:
    """A HOME containing nothing, so discovery tests are hermetic."""
    (tmp_path / ".claude").mkdir(parents=True)
    return tmp_path
