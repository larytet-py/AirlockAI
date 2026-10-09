"""Append-only JSONL audit log, hash-chained per session (SPEC 11)."""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

from .config import HOME, redact


def _who(node, ec2):
    """(node, ec2) as strings or lists of strings, from Node objects, names or lists."""
    nodes = node if isinstance(node, (list, tuple)) else [node] if node is not None else []
    names, ids = [], list(ec2) if isinstance(ec2, (list, tuple)) else [ec2] if ec2 else []
    for n in nodes:
        names.append(getattr(n, "name", n))
        if not ec2 and hasattr(n, "resolved_instance_id"):
            ids.append(n.resolved_instance_id() or "")
    one = lambda xs: (xs[0] if len(xs) == 1 else xs) if any(xs) else None
    return one(names), one(ids)


class Audit:
    def __init__(self, session_id: str):
        self.path = HOME / "audit" / f"{session_id}.jsonl"
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _last_hash(self) -> str:
        if not self.path.exists() or not self.path.stat().st_size:
            return "0" * 64
        return json.loads(self.path.read_text().splitlines()[-1])["hash"]

    def log(self, actor: str, kind: str, *, node=None, ec2=None, **payload) -> None:
        """`node` / `ec2` come right after `ts` in the record: the node name and its EC2 instance id.

        Each may be a Node, a name, or a list of them (an operation on several hosts); a Node supplies its own EC2 id.
        The fields are omitted from the record when unknown, so old and new records verify the same way."""
        node, ec2 = _who(node, ec2)
        body = {"ts": time.time(), **({"node": node} if node else {}), **({"ec2": ec2} if ec2 else {}),
                "actor": actor, "kind": kind,
                "payload": json.loads(redact(json.dumps(payload, default=str))), "prev": self._last_hash()}
        body["hash"] = hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()
        with self.path.open("a") as f:
            f.write(json.dumps(body) + "\n")

    def verify(self) -> bool:
        prev = "0" * 64
        for line in self.path.read_text().splitlines():
            rec = json.loads(line)
            h = rec.pop("hash")
            if rec["prev"] != prev or hashlib.sha256(json.dumps(rec, sort_keys=True).encode()).hexdigest() != h:
                return False
            prev = h
        return True
