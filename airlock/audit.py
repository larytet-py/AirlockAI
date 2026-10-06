"""Append-only JSONL audit log, hash-chained per session (SPEC 11)."""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

from .config import HOME, redact


class Audit:
    def __init__(self, session_id: str):
        self.path = HOME / "audit" / f"{session_id}.jsonl"
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _last_hash(self) -> str:
        if not self.path.exists() or not self.path.stat().st_size:
            return "0" * 64
        return json.loads(self.path.read_text().splitlines()[-1])["hash"]

    def log(self, actor: str, kind: str, **payload) -> None:
        body = {"ts": time.time(), "actor": actor, "kind": kind,
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
