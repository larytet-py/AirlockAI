"""Operations (SPEC 6.2): named, parametrised commands with a risk level, run on tag-selected nodes.

The script goes through the node's execution mode (runner). Parameters are typed and validated, and a
string parameter can never carry shell metacharacters, so a value cannot become a second command.
"""
from __future__ import annotations

import os
import re
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Literal

import yaml

from . import runner
from .config import HOME, Config, ConfigError, Node, Strict

BUILTIN = Path(os.environ.get("AIRLOCK_BUILTIN_OPS") or Path(__file__).resolve().parent.parent / "operations")
STR_RE = re.compile(r"^[A-Za-z0-9_.@:/=-]{1,128}$")
PLACEHOLDER = re.compile(r"\{\{\s*(\w+)\s*\}\}")


class Param(Strict):
    name: str
    type: Literal["int", "str"] = "str"
    default: Any = None
    min: int | None = None
    max: int | None = None


class Operation(Strict):
    name: str
    description: str = ""
    risk: Literal["read", "safe", "destructive"] = "read"
    params: list[Param] = []
    run: str
    timeout: int = 60

    def bind(self, given: dict[str, str]) -> str:
        known = {p.name: p for p in self.params}
        extra = set(given) - set(known)
        if extra:
            raise ConfigError(f"{self.name}: unknown parameter(s) {', '.join(sorted(extra))}")
        vals: dict[str, str] = {}
        for p in self.params:
            raw = given.get(p.name, p.default)
            if raw is None:
                raise ConfigError(f"{self.name}: parameter {p.name} is required")
            if p.type == "int":
                try:
                    v = int(raw)
                except (TypeError, ValueError):
                    raise ConfigError(f"{self.name}: {p.name} must be an integer")
                if (p.min is not None and v < p.min) or (p.max is not None and v > p.max):
                    raise ConfigError(f"{self.name}: {p.name} out of range [{p.min}, {p.max}]")
                vals[p.name] = str(v)
            else:
                if not STR_RE.match(str(raw)):
                    raise ConfigError(f"{self.name}: {p.name} has characters outside [A-Za-z0-9_.@:/=-]")
                vals[p.name] = str(raw)
        undeclared = set(PLACEHOLDER.findall(self.run)) - set(known)
        if undeclared:
            raise ConfigError(f"{self.name}: template uses undeclared parameter(s) {', '.join(sorted(undeclared))}")
        return PLACEHOLDER.sub(lambda m: vals[m.group(1)], self.run)


def load_operations(cfg: Config | None = None) -> dict[str, Operation]:
    ops: dict[str, Operation] = {}
    raws: list[dict] = []
    for d in (BUILTIN, HOME / "operations"):
        for f in sorted(d.glob("*.yaml")) if d.exists() else []:
            raws.append(yaml.safe_load(f.read_text()))
    raws += list(cfg.operations) if cfg else []
    for r in raws:
        op = Operation.model_validate(r)  # later definitions override earlier ones
        ops[op.name] = op
    return ops


def run_operation(cfg: Config, op: Operation, nodes: list[Node], params: dict[str, str], *, confirm: bool = False) -> dict[str, runner.Result]:
    if op.risk == "destructive" and not confirm:
        raise ConfigError(f"{op.name} is destructive: pass --yes to confirm")
    script = op.bind(params)
    if not nodes:
        raise ConfigError("select at least one node")

    def one(n: Node) -> tuple[str, runner.Result]:
        ex = n.ssh_exec().model_copy(update={"auth": "key", "mode": n.exec.mode if n.exec.mode != "direct" else "ssh"})
        # The script travels on stdin to `sh -s`: argv stays one binary with no newlines (SPEC 7.2).
        w = runner.wrap(ex, ["sh", "-s"])
        w.stdin = (w.stdin or b"") + script.encode()
        return n.name, runner.execute(w, timeout=op.timeout)

    with ThreadPoolExecutor(max_workers=min(8, len(nodes))) as pool:
        return dict(pool.map(one, nodes))
