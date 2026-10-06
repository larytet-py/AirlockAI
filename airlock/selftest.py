"""`airlock test`: policy self-checks (SPEC 8, 13). Forbidden calls must fail and must never reach a backend."""
from __future__ import annotations

import tempfile
from pathlib import Path

from . import runner
from .config import Config
from .envs import Environment
from .gateway import Gateway
from .patternstore import PatternStore
from .patterns import Pattern

FORBIDDEN = [
    ("sql.query", {"sql": "drop table orders"}),
    ("sql.query", {"sql": "delete from orders"}),
    ("sql.query", {"sql": "select 1; drop table orders"}),
    ("sql.query", {"sql": "select pg_sleep(100)"}),
    ("sql.query", {"sql": "select * from orders where id = 1 or 1=1"}),
    ("sql.orders_by_status", {"hours": "1; drop table x"}),
    ("sql.orders_by_status", {"hours": 100000}),
    ("es.search", {"index": "*", "body": {"script": {"source": "1"}}}),
    ("es.search", {"index": "events-*", "body": {"query": {"match_all": {}}, "size": 100000}}),
    ("redis.command", {"command": "FLUSHALL"}),
    ("redis.command", {"command": "GET a\r\nFLUSHALL"}),
    ("redis.command", {"command": "EVAL 'return 1' 0"}),
    ("kubernetes.get", {"resource": "secrets", "namespace": "default"}),
    ("kubernetes.get", {"resource": "pods,secrets", "namespace": "default"}),
    ("kubernetes.get", {"resource": "pods; rm -rf /", "namespace": "default"}),
    ("kubernetes.exec", {"pod": "x", "command": "sh"}),
    ("kubernetes.logs", {"pod": "../../etc", "namespace": "default"}),
    ("kubectl.delete", {"pod": "x"}),
    ("kubectl.exec", {"pod": "x", "command": "sh"}),
    ("disk.read", {"path": "../../etc/passwd"}),
    ("disk.read", {"path": "/etc/shadow"}),
    ("ops.run", {"name": "docker-purge", "params": {"keep_hours": "1; reboot"}}),
]


class Recorder:
    """Stands in for every connector: any call that reaches it is a policy failure."""
    def __init__(self):
        self.calls: list[str] = []

    def __getattr__(self, name):
        def hit(*a, **k):
            self.calls.append(name)
            return runner.Result(0, "", "") if name.startswith("run") else {}
        return hit


def run_selftest(env: Environment, cfg: Config) -> list[str]:
    """Returns a list of failures (empty = all forbidden calls were refused without touching a backend)."""
    tmp = Path(tempfile.mkdtemp(prefix="airlock-selftest-"))
    store = PatternStore(tmp / "db.sqlite", tmp / "snap" / "snapshot.json")
    store.upsert(Pattern(name="orders_by_status", kind="sql", scope=[env.name],
                         template="select status, count(*) from orders where created_at > now() - interval '{{ hours:int }} hours' group by status",
                         params={"hours": {"min": 1, "max": 168, "default": 6}}))
    rec = Recorder()
    from .audit import Audit
    gw = Gateway(env, cfg, session_id="selftest", snapshot=store.snapshot, inbox=tmp / "inbox", backends=rec, audit=Audit("selftest-" + tmp.name),
                 secrets={}, approval_timeout=0.2, rate_per_min=10_000)
    failures = []
    for tool, args in FORBIDDEN:
        res = gw.call(tool, args)
        if res["ok"]:
            failures.append(f"{tool} {args} was ACCEPTED")
        elif rec.calls:
            failures.append(f"{tool} {args} reached a backend: {rec.calls}")
            rec.calls.clear()
    return failures
