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
from .access import Proposal, Route
from .patterns import Pattern, PatternError, Policy, validate

DB = HOME / "airlock.db"
SNAPSHOT = HOME / "patterns" / "snapshot.json"

SCHEMA = """
create table if not exists query_pattern(name text primary key, kind text not null, scope_json text not null,
  risk text not null, enabled integer not null, proposed_by_agent integer not null, current_version integer not null);
create table if not exists query_pattern_version(name text not null, version integer not null, body_json text not null,
  updated_by text not null, updated_at real not null, primary key(name, version));
create table if not exists route(key text primary key, env text not null, kind text not null, name text not null,
  body_json text not null, approved_by text, approved_at real);
create table if not exists proposal(id text primary key, env text not null, session text, task text, by text,
  created_at real not null, body_json text not null, status text not null);
create table if not exists proposal_item(proposal_id text not null, item_id text not null, kind text not null,
  body_json text not null, feasibility_json text, decision text not null, note text, result text, decided_by text,
  decided_at real, primary key(proposal_id, item_id));
create table if not exists pattern_alias(old text primary key, new text not null);
create table if not exists pattern_call(name text not null, version integer, ts real not null, session text, env text,
  ok integer not null, ms integer, rows integer, error text);
create index if not exists pattern_call_name_ts on pattern_call(name, ts);
create table if not exists usage_offset(file text primary key, pos integer not null);
"""
MIGRATIONS = [("query_pattern", "approved_at", "real"), ("query_pattern", "approved_by", "text")]


class PatternStore:
    def __init__(self, db: Path | None = None, snapshot: Path | None = None):
        self.db_path = Path(db) if db else DB
        self.snapshot = Path(snapshot) if snapshot else SNAPSHOT
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.snapshot.parent.mkdir(parents=True, exist_ok=True)
        with self._c() as c:
            c.executescript(SCHEMA)
            for table, col, typ in MIGRATIONS:
                if col not in {r[1] for r in c.execute(f"pragma table_info({table})")}:
                    c.execute(f"alter table {table} add column {col} {typ}")
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
            c.execute("insert into query_pattern(name, kind, scope_json, risk, enabled, proposed_by_agent, current_version) "
                      "values(?,?,?,?,?,?,?) on conflict(name) do update set kind=excluded.kind,"
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
            c.execute("update query_pattern set enabled=1, proposed_by_agent=0, approved_at=?, approved_by=? where name=?",
                      (time.time(), by, name))
        self._write_snapshot()

    def mark_approved(self, name: str, by: str) -> None:
        with self._c() as c:
            c.execute("update query_pattern set approved_at=?, approved_by=? where name=?", (time.time(), by, name))
        self._write_snapshot()

    def approved_at(self) -> dict[str, tuple[float | None, str | None]]:
        with self._c() as c:
            return {r[0]: (r[1], r[2]) for r in c.execute("select name, approved_at, approved_by from query_pattern")}

    def rename(self, old: str, new: str, *, by: str = "ui") -> None:
        """A new name for the same pattern: versions, approval and usage follow it (alias kept for the audit)."""
        p = self.get(old)
        if not p:
            raise PatternError(f"unknown pattern {old}")
        Pattern.model_validate({**p.model_dump(), "name": new})   # name rules
        if self.get(new):
            raise PatternError(f"a pattern named {new} already exists")
        with self._c() as c:
            c.execute("update query_pattern set name=? where name=?", (new, old))
            for r in c.execute("select version, body_json from query_pattern_version where name=?", (old,)).fetchall():
                body = json.loads(r[1]) | {"name": new}
                c.execute("update query_pattern_version set name=?, body_json=? where name=? and version=?", (new, json.dumps(body), old, r[0]))
            c.execute("update pattern_alias set new=? where new=?", (new, old))
            c.execute("update pattern_call set name=? where name=?", (new, old))   # usage follows the pattern, not the name
            c.execute("insert into pattern_alias values(?,?) on conflict(old) do update set new=excluded.new", (old, new))
        self._write_snapshot()

    def aliases(self) -> dict[str, str]:
        with self._c() as c:
            return {r[0]: r[1] for r in c.execute("select old, new from pattern_alias")}

    # --- routes (SPEC 7.8): approved through proposals; the config's `tools:` entries are added by the caller
    def routes(self, env: str | None = None) -> list[Route]:
        with self._c() as c:
            rows = c.execute("select body_json from route" + (" where env=?" if env else "") + " order by key", (env,) if env else ()).fetchall()
        return [Route.model_validate(json.loads(r[0])) for r in rows]

    def route(self, key: str) -> Route | None:
        with self._c() as c:
            r = c.execute("select body_json from route where key=?", (key,)).fetchone()
        return Route.model_validate(json.loads(r[0])) if r else None

    def put_route(self, r: Route, *, by: str = "ui") -> None:
        with self._c() as c:
            c.execute("insert into route values(?,?,?,?,?,?,?) on conflict(key) do update set body_json=excluded.body_json",
                      (r.key, r.env, r.kind, r.name, r.model_dump_json(), by, time.time()))
        self._write_snapshot()

    def remove_route(self, key: str) -> None:
        with self._c() as c:
            c.execute("delete from route where key=?", (key,))
        self._write_snapshot()

    # --- proposals
    def add_proposal(self, p: Proposal, feasibility: dict[str, dict]) -> None:
        with self._c() as c:
            c.execute("insert into proposal values(?,?,?,?,?,?,?,?)",
                      (p.id, p.env, p.session, p.task, p.by, p.created_at, p.model_dump_json(), "pending"))
            for iid, kind, it in p.items():
                c.execute("insert into proposal_item values(?,?,?,?,?,?,?,?,?,?)",
                          (p.id, iid, kind, it.model_dump_json(), json.dumps(feasibility.get(iid, {})), "pending", None, None, None, None))

    def proposals(self, status: str | None = "pending") -> list[dict]:
        with self._c() as c:
            rows = c.execute("select * from proposal" + (" where status=?" if status else "") + " order by created_at", (status,) if status else ()).fetchall()
            out = []
            for r in rows:
                items = [dict(i) for i in c.execute("select * from proposal_item where proposal_id=? order by item_id", (r["id"],))]
                out.append({**dict(r), "proposal": Proposal.model_validate_json(r["body_json"]), "items": items})
        return out

    def proposal(self, pid: str) -> dict | None:
        return next((x for x in self.proposals(None) if x["id"] == pid), None)

    def decide_item(self, pid: str, iid: str, decision: str, *, by: str, note: str | None = None, result: str | None = None) -> None:
        with self._c() as c:
            c.execute("update proposal_item set decision=?, note=?, result=?, decided_by=?, decided_at=? where proposal_id=? and item_id=?",
                      (decision, note, result, by, time.time(), pid, iid))
            if not c.execute("select 1 from proposal_item where proposal_id=? and decision='pending'", (pid,)).fetchone():
                c.execute("update proposal set status='decided' where id=?", (pid,))

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
        with self._c() as c:
            routes = [json.loads(r[0]) for r in c.execute("select body_json from route order by key")]
        tmp = self.snapshot.with_suffix(".tmp")
        tmp.write_text(json.dumps({"rev": time.time_ns(), "patterns": pats, "routes": routes}))
        os.replace(tmp, self.snapshot)


class SnapshotReader:
    """Gateway side: cached read of snapshot.json, reloaded when the file changes (so a UI save is live in < 1 s)."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self._mtime = None
        self._data: list[tuple[Pattern, int]] = []
        self._routes: list[Route] = []

    def _load(self) -> None:
        try:
            st = self.path.stat()
            key = (st.st_mtime_ns, st.st_size)
            if key != self._mtime:
                raw = json.loads(self.path.read_text())
                data = [(Pattern.model_validate({k: v for k, v in r.items() if k != "version"}), r["version"]) for r in raw["patterns"]]
                routes = [Route.model_validate(r) for r in raw.get("routes", [])]
                self._data, self._routes, self._mtime = data, routes, key
        except (OSError, ValueError, KeyError):
            pass  # keep the last good copy: a half-written file must never widen what is accepted

    def patterns(self, env: str) -> list[tuple[Pattern, int]]:
        self._load()
        return [(p, v) for p, v in self._data if p.enabled and p.in_scope(env)]

    def routes(self, env: str) -> list[Route]:
        """Approved, enabled and active routes of the environment."""
        self._load()
        return [r for r in self._routes if r.env == env and r.enabled and r.status == "active"]
