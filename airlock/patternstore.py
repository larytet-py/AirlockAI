"""Pattern store: SQLite with immutable versions (SPEC 7.1, 10) plus a JSON snapshot the gateway reads.

The controller owns the database. After every change it writes `snapshot.json` atomically; the gateway container
mounts that directory read-only and reloads the file when its mtime changes, so a save is live on the next call.
Agent proposals travel the other way as small files in a per-session inbox (see gateway.py), never into the database
without a human.
"""
from __future__ import annotations

import json
import os
import sqlite3
import time
from pathlib import Path
from typing import Any

import yaml

from .config import HOME
from .patterns import Pattern, PatternError, Policy, validate

DB = HOME / "airlock.db"
SNAPSHOT = HOME / "patterns" / "snapshot.json"

SCHEMA = """
create table if not exists query_pattern(name text primary key, kind text not null, scope_json text not null,
  risk text not null, enabled integer not null, proposed_by_agent integer not null, current_version integer not null);
create table if not exists query_pattern_version(name text not null, version integer not null, body_json text not null,
  updated_by text not null, updated_at real not null, primary key(name, version));
"""


class PatternStore:
    def __init__(self, db: Path | None = None, snapshot: Path | None = None):
        self.db_path = Path(db) if db else DB
        self.snapshot = Path(snapshot) if snapshot else SNAPSHOT
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.snapshot.parent.mkdir(parents=True, exist_ok=True)
        with self._c() as c:
            c.executescript(SCHEMA)
        if not self.snapshot.exists():
            self._write_snapshot()

    def _c(self) -> sqlite3.Connection:
        c = sqlite3.connect(self.db_path, timeout=10)
        c.row_factory = sqlite3.Row
        return c

    # --- reads
    def _pattern(self, c: sqlite3.Connection, name: str) -> tuple[Pattern, int] | None:
        r = c.execute("select * from query_pattern where name=?", (name,)).fetchone()
        if not r:
            return None
        body = json.loads(c.execute("select body_json from query_pattern_version where name=? and version=?",
                                    (name, r["current_version"])).fetchone()[0])
        body.update(enabled=bool(r["enabled"]), proposed_by_agent=bool(r["proposed_by_agent"]))
        return Pattern.model_validate(body), r["current_version"]

    def get(self, name: str) -> Pattern | None:
        with self._c() as c:
            got = self._pattern(c, name)
        return got[0] if got else None

    def version(self, name: str) -> int:
        with self._c() as c:
            r = c.execute("select current_version from query_pattern where name=?", (name,)).fetchone()
        return r[0] if r else 0

    def list(self, *, kind: str | None = None, env: str | None = None, enabled: bool | None = None,
             proposed: bool | None = None) -> list[Pattern]:
        with self._c() as c:
            names = [r[0] for r in c.execute("select name from query_pattern order by name")]
            out = [self._pattern(c, n)[0] for n in names]
        return [p for p in out if (kind is None or p.kind == kind) and (env is None or p.in_scope(env))
                and (enabled is None or p.enabled == enabled) and (proposed is None or p.proposed_by_agent == proposed)]

    def history(self, name: str) -> list[dict]:
        with self._c() as c:
            return [{"version": r["version"], "updated_by": r["updated_by"], "updated_at": r["updated_at"],
                     **json.loads(r["body_json"])}
                    for r in c.execute("select * from query_pattern_version where name=? order by version", (name,))]

    # --- writes
    def upsert(self, p: Pattern, *, by: str = "ui", policy: Policy = Policy()) -> int:
        """Validate, then save as a new immutable version. A pattern that fails validation cannot be saved."""
        validate(p, policy)
        body = p.model_dump(mode="json", exclude={"enabled", "proposed_by_agent"})
        with self._c() as c:
            cur = self._pattern(c, p.name)
            ver = (cur[1] if cur else 0) + 1
            c.execute("insert into query_pattern_version values(?,?,?,?,?)", (p.name, ver, json.dumps(body), by, time.time()))
            c.execute("insert into query_pattern values(?,?,?,?,?,?,?) on conflict(name) do update set kind=excluded.kind,"
                      "scope_json=excluded.scope_json, risk=excluded.risk, enabled=excluded.enabled,"
                      "proposed_by_agent=excluded.proposed_by_agent, current_version=excluded.current_version",
                      (p.name, p.kind, json.dumps(p.scope), p.risk, int(p.enabled), int(p.proposed_by_agent), ver))
        self._write_snapshot()
        return ver

    def remove(self, name: str) -> None:
        """Delete the pattern. Its versions stay (audit history); the gateway rejects it from the next call."""
        with self._c() as c:
            c.execute("delete from query_pattern where name=?", (name,))
        self._write_snapshot()

    def set_enabled(self, name: str, enabled: bool) -> None:
        with self._c() as c:
            if not c.execute("update query_pattern set enabled=? where name=?", (int(enabled), name)).rowcount:
                raise PatternError(f"unknown pattern {name}")
        self._write_snapshot()

    def propose(self, p: Pattern, *, by: str = "agent") -> int:
        """An agent proposal: stored disabled and marked, does nothing until a human approves it."""
        if self.get(p.name):
            raise PatternError(f"a pattern named {p.name} already exists")
        p = p.model_copy(update={"enabled": False, "proposed_by_agent": True})
        return self.upsert(p, by=by)

    def approve(self, name: str, *, by: str = "ui", policy: Policy = Policy()) -> None:
        p = self.get(name)
        if not p:
            raise PatternError(f"unknown pattern {name}")
        validate(p, policy)
        with self._c() as c:
            c.execute("update query_pattern set enabled=1, proposed_by_agent=0 where name=?", (name,))
        self._write_snapshot()

    def import_list(self, items: list[dict], *, by: str = "import", policy: Policy = Policy()) -> list[str]:
        names = []
        for raw in items:
            p = Pattern.model_validate(raw)
            old = self.get(p.name)
            if old and old.model_dump(mode="json", exclude={"enabled", "proposed_by_agent"}) == \
                    p.model_dump(mode="json", exclude={"enabled", "proposed_by_agent"}) and old.enabled == p.enabled:
                continue  # unchanged: no new version
            self.upsert(p, by=by, policy=policy)
            names.append(p.name)
        return names

    def export_yaml(self, env: str | None = None) -> str:
        items = [p.model_dump(mode="json", exclude_defaults=True, exclude={"proposed_by_agent"}) | {"name": p.name}
                 for p in self.list(env=env, proposed=False)]
        return yaml.safe_dump({"query_patterns": items}, sort_keys=False)

    # --- snapshot for the gateway
    def _write_snapshot(self) -> None:
        pats = []
        with self._c() as c:
            for r in c.execute("select name from query_pattern order by name"):
                p, v = self._pattern(c, r[0])
                pats.append({**p.model_dump(mode="json"), "version": v})
        tmp = self.snapshot.with_suffix(".tmp")
        tmp.write_text(json.dumps({"rev": time.time_ns(), "patterns": pats}))
        os.replace(tmp, self.snapshot)


class SnapshotReader:
    """Gateway side: cached read of snapshot.json, reloaded when the file changes (so a UI save is live in < 1 s)."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self._mtime = None
        self._data: list[tuple[Pattern, int]] = []

    def patterns(self, env: str) -> list[tuple[Pattern, int]]:
        try:
            st = self.path.stat()
            key = (st.st_mtime_ns, st.st_size)
            if key != self._mtime:
                raw = json.loads(self.path.read_text())["patterns"]
                self._data = [(Pattern.model_validate({k: v for k, v in r.items() if k != "version"}), r["version"]) for r in raw]
                self._mtime = key
        except (OSError, ValueError, KeyError):
            pass  # keep the last good copy: a half-written file must never widen what is accepted
        return [(p, v) for p, v in self._data if p.enabled and p.in_scope(env)]
