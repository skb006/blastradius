"""Policy: what must be unreachable.

A policy is a list of denials. The prover's job is to discharge each one —
either prove no path exists, or produce the path that violates it. Both
outcomes are useful, and the proof of *absence* is the one that is hard to
get any other way.

Format (JSON or YAML)::

    version: 1
    rules:
      - name: agents must not write to production GitHub
        deny:
          from: agent
          to: "principal:github:*"
          capability: write

``from``/``to`` are shell-style globs over node ids. ``capability`` is
``read``, ``write`` or ``any``.
"""

from __future__ import annotations

import fnmatch
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, Sequence

Capability = Literal["read", "write", "any"]


class PolicyError(ValueError):
    """The policy document is not usable."""


@dataclass(frozen=True, slots=True)
class DenyRule:
    name: str
    from_pattern: str
    to_pattern: str
    capability: Capability = "any"
    #: ``any`` flags reach however it is obtained. ``direct`` flags only reach
    #: that needs no delegation — use it when delegated access is acceptable
    #: but unbounded server authority is not.
    delegation: Literal["any", "direct"] = "any"

    def matches_src(self, node_id: str) -> bool:
        return fnmatch.fnmatch(node_id, self.from_pattern)

    def matches_dst(self, node_id: str) -> bool:
        return fnmatch.fnmatch(node_id, self.to_pattern)

    def capabilities(self) -> tuple[str, ...]:
        return ("read", "write") if self.capability == "any" else (self.capability,)

    def to_json(self) -> dict[str, Any]:
        return {
            "name": self.name, "from": self.from_pattern,
            "to": self.to_pattern, "capability": self.capability,
            "delegation": self.delegation,
        }


@dataclass
class Policy:
    rules: list[DenyRule] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        return {"version": 1, "rules": [{"deny": r.to_json(), "name": r.name}
                                        for r in self.rules]}


def _load_document(path: Path) -> Any:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() in (".yaml", ".yml"):
        try:
            import yaml  # segval already requires it; prove is an optional extra
        except ImportError as exc:  # pragma: no cover - environment dependent
            raise PolicyError(
                "YAML policies need PyYAML; use a .json policy or install "
                "'blastradius[prove]'") from exc
        try:
            return yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise PolicyError(f"{path}: invalid YAML: {exc}") from exc
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise PolicyError(f"{path}: invalid JSON at line {exc.lineno}: {exc.msg}") from exc


def parse_policy(doc: Any, source: str = "<policy>") -> Policy:
    if not isinstance(doc, dict):
        raise PolicyError(f"{source}: top level must be a mapping")
    version = doc.get("version", 1)
    if version != 1:
        raise PolicyError(f"{source}: unsupported policy version {version!r}")

    raw_rules = doc.get("rules")
    if not isinstance(raw_rules, list) or not raw_rules:
        raise PolicyError(f"{source}: 'rules' must be a non-empty list")

    rules: list[DenyRule] = []
    for i, entry in enumerate(raw_rules):
        if not isinstance(entry, dict):
            raise PolicyError(f"{source}: rules[{i}] must be a mapping")
        deny = entry.get("deny")
        if not isinstance(deny, dict):
            raise PolicyError(f"{source}: rules[{i}] must contain a 'deny' mapping")
        cap = str(deny.get("capability", "any")).lower()
        if cap not in ("read", "write", "any"):
            raise PolicyError(
                f"{source}: rules[{i}] capability must be read|write|any, got {cap!r}")
        src = deny.get("from")
        dst = deny.get("to")
        if not isinstance(src, str) or not isinstance(dst, str):
            raise PolicyError(f"{source}: rules[{i}] needs string 'from' and 'to'")
        deleg = str(deny.get("delegation", "any")).lower()
        if deleg not in ("any", "direct"):
            raise PolicyError(
                f"{source}: rules[{i}] delegation must be any|direct, got {deleg!r}")
        rules.append(DenyRule(
            name=str(entry.get("name") or f"rule[{i}]"),
            from_pattern=src, to_pattern=dst, capability=cap,  # type: ignore[arg-type]
            delegation=deleg,  # type: ignore[arg-type]
        ))
    return Policy(rules=rules)


def load_policy(path: str | Path) -> Policy:
    p = Path(path)
    if not p.is_file():
        raise PolicyError(f"policy file not found: {p}")
    return parse_policy(_load_document(p), source=str(p))


def default_policy() -> Policy:
    """A conservative starting point when no policy is supplied.

    Denies agent write access to every discovered principal. Loud by design:
    the intended workflow is to run it, look at what the agent can actually
    reach, and then narrow the policy to what the deployment genuinely needs.
    """
    return Policy(rules=[
        DenyRule(
            name="agent must not hold write authority over any external principal",
            from_pattern="agent", to_pattern="principal:*", capability="write",
        )
    ])
