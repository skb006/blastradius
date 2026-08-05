"""Stage 1 — find and parse declared MCP servers.

Parse failures are **findings**, never silent skips. A config we could not
read is an unproven claim, and this tool exists to avoid dressing unproven
claims up as proofs. Every unreadable file produces an ``error`` diagnostic
that survives into the report and the exit code.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Iterable, Iterator, Sequence

from .model import Diagnostic, Inventory, Origin, ServerSpec, Transport
from .redact import scrub_argv_with_keys, scrub_url, split_keys

# Config keys that would constitute a *declared* authorisation scope. Their
# near-total absence in real installs is the Phase 0 finding; we record
# presence per-server so the report can quantify it rather than assert it.
AUTHZ_KEYS: tuple[str, ...] = (
    "tools",
    "allowedTools",
    "allowed_tools",
    "disallowedTools",
    "scopes",
    "permissions",
    "resources",
    "roots",
)

# Directories that are never worth walking.
_PRUNE = frozenset(
    {
        ".git", "node_modules", ".venv", "venv", "__pycache__", ".mypy_cache",
        ".pytest_cache", "dist", "build", ".next", "target", ".tox", "site-packages",
    }
)

_MAX_FILE_BYTES = 8 * 1024 * 1024


def default_search_paths(home: Path) -> list[Path]:
    """Well-known locations that declare MCP servers.

    Ordered roughly by how authoritative they are. Missing paths are fine —
    they are filtered later — but each one that *exists* and fails to parse
    becomes a diagnostic.
    """
    return [
        home / ".claude.json",
        home / ".claude" / "settings.json",
        home / ".claude" / "settings.local.json",
        home / ".config" / "Claude" / "claude_desktop_config.json",
        home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json",
        home / ".cursor" / "mcp.json",
        home / ".vscode" / "mcp.json",
        home / ".codex" / "config.json",
    ]


def default_glob_roots(home: Path) -> list[tuple[Path, str]]:
    """(root, glob) pairs walked for scattered configs."""
    return [
        (home / "tmp", "openclaw-cli-mcp-*/mcp.json"),
        (home / ".claude" / "plugins", "**/.mcp.json"),
        (home / ".openclaw", "**/mcp.json"),
    ]


def _iter_project_configs(roots: Sequence[Path]) -> Iterator[Path]:
    """Walk project roots for `.mcp.json` / `.vscode/mcp.json`, pruning noise."""
    for root in roots:
        if not root.is_dir():
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in _PRUNE and not d.startswith(".venv")]
            for fn in filenames:
                if fn in (".mcp.json", "mcp.json") and (
                    fn == ".mcp.json" or Path(dirpath).name in (".vscode", ".cursor")
                ):
                    yield Path(dirpath) / fn


def _load_json(path: Path, diags: list[Diagnostic]) -> Any | None:
    """Read JSON, converting every failure mode into a diagnostic."""
    try:
        if path.stat().st_size > _MAX_FILE_BYTES:
            diags.append(
                Diagnostic("warn", "config.too_large",
                           f"skipped: larger than {_MAX_FILE_BYTES} bytes",
                           Origin(str(path))))
            return None
        text = path.read_text(encoding="utf-8", errors="strict")
    except PermissionError:
        diags.append(Diagnostic("error", "config.unreadable",
                                "permission denied — declared servers here are UNKNOWN",
                                Origin(str(path))))
        return None
    except UnicodeDecodeError as exc:
        diags.append(Diagnostic("error", "config.not_utf8", f"not valid UTF-8: {exc.reason}",
                                Origin(str(path))))
        return None
    except OSError as exc:
        diags.append(Diagnostic("error", "config.io_error", f"{type(exc).__name__}: {exc}",
                                Origin(str(path))))
        return None

    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        diags.append(
            Diagnostic(
                "error", "config.malformed",
                f"invalid JSON at line {exc.lineno} col {exc.colno} ({exc.msg}) — "
                f"any servers declared here are UNKNOWN, not absent",
                Origin(str(path)),
            )
        )
        return None


def _classify_transport(cfg: dict) -> Transport:
    declared = str(cfg.get("type") or cfg.get("transport") or "").lower()
    if declared in ("stdio", "http", "sse"):
        return declared  # type: ignore[return-value]
    if declared in ("streamable-http", "streamablehttp", "http-stream"):
        return "http"
    if cfg.get("command"):
        return "stdio"
    if cfg.get("url"):
        url = str(cfg["url"])
        return "sse" if url.rstrip("/").endswith("/sse") else "http"
    return "unknown"


def _parse_server(name: str, cfg: Any, origin: Origin,
                  diags: list[Diagnostic]) -> ServerSpec | None:
    if not isinstance(cfg, dict):
        diags.append(Diagnostic("warn", "server.malformed",
                                f"server '{name}' is {type(cfg).__name__}, expected object",
                                origin))
        return None

    transport = _classify_transport(cfg)
    env_keys, env_secrets = split_keys(cfg.get("env"))
    hdr_keys, hdr_secrets = split_keys(cfg.get("headers"))
    declared_authz = tuple(k for k in AUTHZ_KEYS if k in cfg)

    if transport == "unknown":
        diags.append(Diagnostic("warn", "server.transport_unknown",
                                f"server '{name}' declares neither command nor url",
                                origin))

    raw_url = str(cfg["url"]) if cfg.get("url") else None
    safe_url, url_secret_keys = scrub_url(raw_url) if raw_url else (None, ())

    raw_args = tuple(str(a) for a in cfg["args"]) if isinstance(
        cfg.get("args"), (list, tuple)) else ()
    safe_args, argv_secret_keys = scrub_argv_with_keys(cfg.get("args"))

    return ServerSpec(
        name=name,
        transport=transport,
        origin=origin,
        command=str(cfg["command"]) if cfg.get("command") else None,
        args=safe_args,
        url=safe_url,
        env_keys=env_keys,
        header_keys=hdr_keys,
        # A credential in a URL is still a credential the server carries, so
        # it belongs in credential_keys — that is what raises
        # `server.carries_credentials` and what makes delegation.py classify
        # the server as own_credential rather than as an unknown.
        credential_keys=tuple(sorted(
            set(env_secrets) | set(hdr_secrets) | set(url_secret_keys)
            | set(argv_secret_keys))),
        declared_authz=declared_authz,
        connect_url=raw_url,
        connect_args=raw_args,
    )


def _harvest(doc: Any, path: Path, diags: list[Diagnostic]) -> Iterator[ServerSpec]:
    """Pull servers out of any known config shape.

    Handles the three layouts seen in the wild: a bare ``mcpServers`` map, a
    ``servers`` map (VS Code), and per-project maps nested under
    ``projects.<dir>.mcpServers`` (``~/.claude.json``).
    """
    if not isinstance(doc, dict):
        diags.append(Diagnostic("warn", "config.unexpected_shape",
                                f"top level is {type(doc).__name__}, expected object",
                                Origin(str(path))))
        return

    for container in ("mcpServers", "servers"):
        block = doc.get(container)
        if isinstance(block, dict):
            for name, cfg in block.items():
                spec = _parse_server(str(name), cfg,
                                     Origin(str(path), f"{container}.{name}"), diags)
                if spec:
                    yield spec

    projects = doc.get("projects")
    if isinstance(projects, dict):
        for proj_path, pdoc in projects.items():
            if not isinstance(pdoc, dict):
                continue
            block = pdoc.get("mcpServers")
            if isinstance(block, dict):
                for name, cfg in block.items():
                    spec = _parse_server(
                        str(name), cfg,
                        Origin(str(path), f"projects.{proj_path}.mcpServers.{name}"), diags)
                    if spec:
                        yield spec


def discover(
    project_roots: Sequence[Path] = (),
    home: Path | None = None,
    extra_paths: Iterable[Path] = (),
) -> Inventory:
    """Locate every declared MCP server reachable from this machine.

    Args:
        project_roots: directories walked for ``.mcp.json``.
        home: overrides ``$HOME``; injected by tests.
        extra_paths: explicit config files to include.

    Returns:
        Inventory of declared servers plus diagnostics for anything unreadable.
    """
    home = home or Path.home()
    diags: list[Diagnostic] = []
    servers: list[ServerSpec] = []
    scanned: list[str] = []

    candidates: list[Path] = [p for p in default_search_paths(home)]
    for root, pattern in default_glob_roots(home):
        if root.is_dir():
            candidates.extend(sorted(root.glob(pattern)))
    candidates.extend(_iter_project_configs(project_roots))
    candidates.extend(Path(p) for p in extra_paths)

    seen_paths: set[Path] = set()
    for path in candidates:
        try:
            resolved = path.resolve()
        except OSError:
            resolved = path
        if resolved in seen_paths or not path.is_file():
            continue
        seen_paths.add(resolved)
        scanned.append(str(path))

        doc = _load_json(path, diags)
        if doc is None:
            continue
        servers.extend(_harvest(doc, path, diags))

    inv = Inventory(servers=servers, diagnostics=diags, scanned_paths=scanned)

    # Per-server finding: a server with no declared authorisation scope is a
    # grant of unknown size. This is the Phase 0 result, restated per server
    # instead of asserted globally.
    for spec in inv.deduped():
        if not spec.declared_authz:
            diags.append(Diagnostic(
                "info", "server.no_declared_scope",
                f"'{spec.name}' declares no tool/scope restriction — "
                f"reach is unknown until probed",
                spec.origin))
        if spec.credential_keys:
            diags.append(Diagnostic(
                "warn", "server.carries_credentials",
                f"'{spec.name}' carries {len(spec.credential_keys)} credential(s) "
                f"({', '.join(spec.credential_keys)}) whose backend scope is not "
                f"visible from config",
                spec.origin))

    # Sprawl is a finding in its own right: N copies of the same declaration
    # scattered across temp directories is how shadow agents survive audits.
    for identity, count in inv.copies().items():
        if count >= 5:
            name = identity.split("|", 1)[0]
            diags.append(Diagnostic(
                "warn", "config.sprawl",
                f"'{name}' declared in {count} separate config copies",
                None))

    return inv
