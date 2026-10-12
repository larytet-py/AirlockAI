"""Usage statistics per approved pattern (SPEC 7.8), derived from the audit log.

Every call is audited by the gateway (`tool.result` with `pattern=name@version`, ok, ms, rows). The controller reads the
audit files incrementally into `pattern_call` and aggregates from there; `rebuild` starts again from the audit, so the
numbers can always be checked against it. Nothing here holds query values or results.
"""
from __future__ import annotations

import json
import statistics
import time
from pathlib import Path

from . import audit as _audit
from .patternstore import PatternStore


def _env_of(sid: str, cache: dict) -> str | None:
    if sid not in cache:
        from . import session
        try:
            cache[sid] = json.loads((session.SESSIONS / sid / "session.json").read_text()).get("environment")
        except (OSError, ValueError):
            cache[sid] = None
    return cache[sid]


def update(store: PatternStore, audit_dir: Path | None = None) -> int:
    """Read new audit records into pattern_call. Returns the number of calls added."""
    audit_dir = Path(audit_dir or _audit.HOME / "audit")   # where Audit writes
    aliases = store.aliases()
    envs: dict[str, str | None] = {}
    added = 0
    with store._c() as c:
        offsets = {r[0]: r[1] for r in c.execute("select file, pos from usage_offset")}
        for f in sorted(audit_dir.glob("*.jsonl")) if audit_dir.is_dir() else []:
            pos = offsets.get(f.name, 0)
            size = f.stat().st_size
            if size < pos:
                pos = 0   # rewritten file: read it again
            if size == pos:
                continue
            with f.open("rb") as fh:
                fh.seek(pos)
                data = fh.read()
            end = data.rfind(b"\n") + 1   # only whole lines; a line being written is read next time
            for line in data[:end].splitlines():
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                pl = rec.get("payload") or {}
                if rec.get("kind") != "tool.result":
                    continue
                if pl.get("pattern"):
                    name, _, ver = str(pl["pattern"]).partition("@")
                    name = aliases.get(name, name)
                elif str(pl.get("tool", "")).startswith("files.") and pl.get("route"):
                    name, ver = f"route:{pl['route']}", ""   # files routes have no patterns: usage per route
                else:
                    continue
                c.execute("insert into pattern_call values(?,?,?,?,?,?,?,?,?)",
                          (name, int(ver) if ver.isdigit() else None, rec["ts"], f.stem, _env_of(f.stem, envs),
                           int(bool(pl.get("ok"))), pl.get("ms"), pl.get("rows"), (pl.get("error") or "")[:200] or None))
                added += 1
            c.execute("insert into usage_offset values(?,?) on conflict(file) do update set pos=excluded.pos", (f.name, pos + end))
    return added


def rebuild(store: PatternStore, audit_dir: Path | None = None) -> int:
    with store._c() as c:
        c.execute("delete from pattern_call")
        c.execute("delete from usage_offset")
    return update(store, audit_dir)


def _median(xs):
    xs = [x for x in xs if x is not None]
    return int(statistics.median(xs)) if xs else None


def stats(store: PatternStore, now: float | None = None) -> dict[str, dict]:
    """name -> calls, calls_7d, errors, first_used, last_used, p50_ms, max_ms, p50_rows, sessions, envs."""
    now = now or time.time()
    out: dict[str, dict] = {}
    with store._c() as c:
        rows = c.execute("select name, ts, session, env, ok, ms, rows from pattern_call order by ts").fetchall()
    by: dict[str, list] = {}
    for r in rows:
        by.setdefault(r["name"], []).append(r)
    for name, calls in by.items():
        out[name] = {"calls": len(calls), "calls_7d": sum(1 for r in calls if r["ts"] > now - 7 * 86400),
                     "errors": sum(1 for r in calls if not r["ok"]), "first_used": calls[0]["ts"], "last_used": calls[-1]["ts"],
                     "p50_ms": _median([r["ms"] for r in calls]), "max_ms": max((r["ms"] or 0 for r in calls), default=None),
                     "p50_rows": _median([r["rows"] for r in calls]), "sessions": len({r["session"] for r in calls}),
                     "envs": sorted({r["env"] for r in calls if r["env"]})}
    return out


def recent(store: PatternStore, name: str, n: int = 50) -> list[dict]:
    with store._c() as c:
        return [dict(r) for r in c.execute("select * from pattern_call where name=? order by ts desc limit ?", (name, n))]


def daily(store: PatternStore, name: str, days: int = 30, now: float | None = None) -> list[tuple[str, int, int]]:
    """(YYYY-MM-DD, calls, errors) for each of the last `days` days, oldest first, local time."""
    now = now or time.time()
    with store._c() as c:
        rows = c.execute("select ts, ok from pattern_call where name=? and ts > ?", (name, now - days * 86400)).fetchall()
    counts: dict[str, list[int]] = {}
    for r in rows:
        d = time.strftime("%Y-%m-%d", time.localtime(r["ts"]))
        counts.setdefault(d, [0, 0])
        counts[d][0] += 1
        counts[d][1] += 0 if r["ok"] else 1
    out = []
    for i in range(days - 1, -1, -1):
        d = time.strftime("%Y-%m-%d", time.localtime(now - i * 86400))
        out.append((d, *counts.get(d, [0, 0])))
    return out
