"""Gateway core (Mode 2): pattern enforcement, kubernetes policy and execution modes, approvals, secrets, audit."""
import json
import threading
import time

import pytest

from airlock import gateway as G
from airlock import patterns as P
from airlock import runner
from airlock.audit import Audit
from airlock.config import Config, Exec, load_config
from airlock.envs import Environment
from airlock.patternstore import PatternStore


class Fake:
    def __init__(self):
        self.calls = []

    def sql(self, dsn, sql, params, limits, **kw):
        self.calls.append(("sql", dsn, sql, params, limits.rows))
        self.sql_kw = kw
        return {"columns": ["status", "count"], "rows": [["new", 3]], "truncated": False}

    def es(self, url, auth, index, endpoint, body, limits):
        self.calls.append(("es", url, index, endpoint, body))
        return {"hits": {"total": 1}}

    def redis(self, url, argv, limits):
        self.calls.append(("redis", url, argv))
        return {"k": "v"}

    def run(self, ex, argv, **kw):
        self.calls.append(("run", ex.mode, ex.host, argv))
        return runner.Result(0, "pod-a Running\n", "")

    def run_script(self, ex, script, **kw):
        self.calls.append(("script", ex.mode, ex.host, script))
        return runner.Result(0, "ok", "")

    def http_json(self, url, **kw):
        self.calls.append(("http", url, kw.get("headers")))
        return {"ok": True, "messages": {"matches": []}}


def env(tools=None, **kw):
    return Environment.model_validate({"name": "uat", "kube_context": "uat-ctx", "tools": tools or [
        {"postgres": {"dsn_env": "PG_DSN", "mode": "read", "schemas": ["public"]}},
        {"elastic": {"url_env": "ES_URL", "indices": ["events-*"]}},
        {"redis": {"url_env": "REDIS_URL", "key_prefixes": ["session:"]}},
        {"kubernetes": {"mode": "read", "namespaces": ["app"]}},
    ], **kw})


@pytest.fixture
def gw(tmp_path, monkeypatch):
    monkeypatch.setattr("airlock.audit.HOME", tmp_path)
    store = PatternStore(tmp_path / "db.sqlite", tmp_path / "snap" / "snapshot.json")
    fake = Fake()
    g = G.Gateway(env(), Config(), session_id="s1", snapshot=store.snapshot, inbox=tmp_path / "inbox", backends=fake,
                  secrets={"PG_DSN": "postgres://u:SuperSecretPw@db/x", "ES_URL": "http://es:9200", "REDIS_URL": "redis://r"},
                  approval_timeout=3)
    g.store, g.fake, g.tmp = store, fake, tmp_path
    return g


ORDERS = P.Pattern(name="orders_by_status", kind="sql", description="Count orders per status in the last N hours",
                   template="select status, count(*) from orders where created_at > now() - interval '{{ hours:int }} hours' group by status",
                   params={"hours": {"min": 1, "max": 168, "default": 6}}, scope=["uat"])


def test_unknown_queries_rejected_with_closest_patterns(gw):
    r = gw.call("sql.query", {"sql": "select * from users"})
    assert not r["ok"] and "no enabled patterns" in r["error"]
    assert gw.fake.calls == []
    gw.store.upsert(ORDERS)
    r = gw.call("sql.query", {"sql": "select * from users"})
    assert "does not match any enabled pattern" in r["error"] and "orders_by_status" in r["error"]  # lists the closest patterns


def test_pattern_added_in_store_is_accepted_at_once_and_removed_is_rejected(gw):
    sql = "select status, count(*) from orders where created_at > now() - interval '6 hours' group by status"
    assert not gw.call("sql.query", {"sql": sql})["ok"]
    gw.store.upsert(ORDERS)                                   # UC9: add a pattern in the UI
    r = gw.call("sql.query", {"sql": sql})
    assert r["ok"], r
    kind, dsn, bound_sql, params, rows = gw.fake.calls[-1]
    assert "6 hours" in bound_sql and rows == 100
    assert dsn.startswith("postgres://")
    assert gw.call("sql.orders_by_status", {"hours": 12})["ok"]   # named call, typed schema
    assert "12 hours" in gw.fake.calls[-1][2]
    gw.store.set_enabled("orders_by_status", False)            # disable: rejected on the next call
    assert not gw.call("sql.query", {"sql": sql})["ok"]
    assert not gw.call("sql.orders_by_status", {})["ok"]
    gw.store.set_enabled("orders_by_status", True)
    gw.store.remove("orders_by_status")                        # removed: rejected on the next call
    assert not gw.call("sql.query", {"sql": sql})["ok"]


@pytest.mark.parametrize("bad", [
    "select status, count(*) from orders where created_at > now() - interval '6 hours' group by status; drop table orders",
    "select status, count(*) from orders where created_at > now() - interval '6 hours; drop table x' group by status",
    "select status, count(*) from orders where created_at > now() - interval '9999 hours' group by status",
    "select status, count(*) from orders where 1=1 or created_at > now() - interval '6 hours' group by status",
    "drop table orders",
])
def test_sql_injection_attempts_rejected(gw, bad):
    gw.store.upsert(ORDERS)
    r = gw.call("sql.query", {"sql": bad})
    assert not r["ok"]
    assert gw.fake.calls == []


def test_sql_literal_in_non_placeholder_position_rejected(gw):
    gw.store.upsert(P.Pattern(name="by_status", kind="sql", template="select count(*) from orders where status = {{ s:enum(new,done) }}"))
    assert gw.call("sql.query", {"sql": "select count(*) from orders where status = 'new'"})["ok"]
    assert not gw.call("sql.query", {"sql": "select count(*) from orders where status = 'other'"})["ok"]
    assert not gw.call("sql.query", {"sql": "select count(*) from orders where status = 'new' and id = 1"})["ok"]


def test_pattern_that_fails_validation_cannot_be_saved(gw):
    for tpl in ("drop table x", "delete from orders", "select pg_sleep(10)", "select * from a; select * from b"):
        with pytest.raises(P.PatternError):
            gw.store.upsert(P.Pattern(name="bad", kind="sql", template=tpl))
    with pytest.raises(P.PatternError):
        gw.store.upsert(P.Pattern(name="bad", kind="redis", template="DEL session:{{ id:str }}"))
    with pytest.raises(P.PatternError):
        gw.store.upsert(P.Pattern(name="bad", kind="elasticsearch", template={"index": "a", "body": {"script": "x"}}))


def test_elasticsearch_and_redis_patterns(gw):
    gw.store.upsert(P.Pattern(name="events_for_order", kind="elasticsearch", description="events", params={"size": {"max": 200, "default": 50}},
                              template={"index": "events-*", "body": {"query": {"term": {"order_id": "{{ order_id:str }}"}}, "size": "{{ size:int }}"}}))
    ok = gw.call("es.search", {"index": "events-*", "body": {"query": {"term": {"order_id": "A-1"}}, "size": 10}})
    assert ok["ok"] and gw.fake.calls[-1][4]["size"] == 10
    for body in ({"query": {"term": {"order_id": {"script": "1"}}}, "size": 10},
                 {"query": {"term": {"order_id": "A-1"}}, "size": 5000},
                 {"query": {"match_all": {}}, "size": 1}):
        assert not gw.call("es.search", {"index": "events-*", "body": body})["ok"]
    gw.store.upsert(P.Pattern(name="session_hash", kind="redis", description="s", template="HGETALL session:{{ id:str }}",
                              params={"id": {"regex": "^[A-Za-z0-9_-]{1,64}$"}}))
    assert gw.call("redis.command", {"command": "HGETALL session:abc"})["ok"]
    assert gw.fake.calls[-1][2] == ["HGETALL", "session:abc"]       # separate arguments
    n = len(gw.fake.calls)
    for bad in ("HGETALL session:x\r\nFLUSHALL", "HGETALL session:x y", "FLUSHALL", ["HGETALL", "session:x", "extra"], "GET session:abc"):
        assert not gw.call("redis.command", {"command": bad})["ok"]
    assert len(gw.fake.calls) == n


def test_environment_allowlist_applies_to_global_patterns(gw):
    gw.store.upsert(P.Pattern(name="secrets_tbl", kind="sql", template="select * from vault.keys where id = {{ i:int }}"))
    r = gw.call("sql.query", {"sql": "select * from vault.keys where id = 1"})
    assert not r["ok"] and "not allowed in this environment" in r["error"]


def test_scope_limits_a_pattern_to_its_environment(gw):
    gw.store.upsert(ORDERS.model_copy(update={"scope": ["prod"]}))
    assert not gw.call("sql.orders_by_status", {})["ok"]
    assert gw.call("query.list", {})["ok"] and json.loads(gw.call("query.list", {})["result"])["patterns"] == []


def test_query_list_and_propose_flow(gw):
    gw.store.upsert(ORDERS)
    listed = json.loads(gw.call("query.list", {"kind": "sql"})["result"])
    assert listed["patterns"][0]["name"] == "orders_by_status" and listed["patterns"][0]["params"]["hours"]["type"] == "int"
    r = gw.call("query.propose", {"kind": "sql", "name": "recent_users", "description": "d", "template": "select count(*) from users where id > {{ i:int }}"})
    assert r["ok"], r
    pid = json.loads(r["result"])["id"]
    bundle = json.loads((gw.tmp / "inbox" / "proposals" / f"{pid}.json").read_text())
    assert bundle["type"] == "bundle" and bundle["proposal"]["queries"][0]["pattern"]["name"] == "recent_users"
    assert not gw.call("sql.query", {"sql": "select count(*) from users where id > 1"})["ok"]      # nothing runs until approved
    bad = json.loads(gw.call("query.propose", {"kind": "sql", "name": "evil", "description": "d", "template": "drop table x"})["result"])
    assert bad["status"] == "refused" and not bad["items"]["q0"]["ok"]      # refused back to the agent, never queued


def test_kubernetes_policy_and_execution_modes(gw):
    r = gw.call("kubernetes.get", {"resource": "pods", "namespace": "app"})
    assert r["ok"]
    assert gw.fake.calls[-1][3] == ["kubectl", "--context", "uat-ctx", "get", "pods", "-n", "app"]   # direct: --context
    for bad in ({"resource": "secrets", "namespace": "app"}, {"resource": "pods,secrets", "namespace": "app"},
                {"resource": "pods", "namespace": "kube-system"}, {"resource": "pods", "all_namespaces": True},
                {"resource": "pods"}, {"resource": "pods; rm -rf /", "namespace": "app"}, {"resource": "pods", "namespace": "app", "output": "go-template={{x}}"}):
        assert not gw.call("kubernetes.get", bad)["ok"], bad
    assert not gw.call("kubernetes.exec", {"pod": "x"})["ok"]
    # same tool schema, different mode: policy first, then the wrapper
    g2 = G.Gateway(env(exec={"mode": "ssh_sudo", "host": "bastion.example.com", "user": "u", "kubeconfig": "/etc/k.yaml"}), Config(), session_id="s2",
                   snapshot=gw.store.snapshot, inbox=gw.tmp / "inbox2", backends=gw.fake, secrets={}, audit=Audit("s2"))
    assert g2.call("kubernetes.logs", {"pod": "web-1", "namespace": "app", "tail": 50})["ok"]
    kind, mode, host, argv = gw.fake.calls[-1]
    assert (mode, host) == ("ssh_sudo", "bastion.example.com")
    assert argv == ["kubectl", "--kubeconfig", "/etc/k.yaml", "logs", "web-1", "-n", "app", "--tail=50"]   # no --context over ssh
    w = runner.wrap(Exec(mode="ssh_sudo", host="bastion.example.com", user="u", auth="key", sudo_password=None), argv)
    assert w.cmd[-1].startswith("sudo -n kubectl") and "--context" not in w.cmd[-1]


def test_kubernetes_per_tool_exec_override(tmp_path):
    e = env(tools=[{"kubernetes": {"mode": "read", "exec": {"mode": "ssh", "host": "h"}}}, {"postgres": {"dsn_env": "PG_DSN"}}])
    assert e.exec_for("kubernetes").mode == "ssh" and e.exec_for("postgres").mode == "direct"


def test_mutating_tools_off_by_default_and_need_approval(gw):
    gw.store.upsert(P.Pattern(name="touch", kind="sql", risk="write", template="update orders set seen = true where id = {{ i:int }}"), policy=P.Policy()) if False else None
    # remote_ops in read mode refuses a destructive operation
    e = env(tools=[{"remote_ops": {"hosts": ["n1"], "mode": "read"}}])
    cfg = Config.model_validate({"nodes": [{"name": "n1", "host": "10.0.0.1", "exec": {"mode": "ssh_sudo"}}]})
    g = G.Gateway(e, cfg, session_id="s3", snapshot=gw.store.snapshot, inbox=gw.tmp / "i3", backends=gw.fake, secrets={}, audit=Audit("s3"), approval_timeout=3)
    assert g.call("ops.run", {"name": "cpu", "hosts": ["n1"]})["ok"]
    assert gw.fake.calls[-1][0] == "script"
    r = g.call("ops.run", {"name": "docker-purge", "hosts": ["n1"]})
    assert not r["ok"] and "read-only" in r["error"]
    assert not g.call("ops.run", {"name": "cpu", "hosts": ["other"]})["ok"]
    assert not g.call("ops.run", {"name": "cpu", "params": {"x": "1"}})["ok"]
    # with approve_writes the call blocks until a human decides in the UI
    e2 = env(tools=[{"remote_ops": {"hosts": ["n1"], "mode": "approve_writes"}}])
    g2 = G.Gateway(e2, cfg, session_id="s4", snapshot=gw.store.snapshot, inbox=gw.tmp / "i4", backends=gw.fake, secrets={}, audit=Audit("s4"), approval_timeout=5)
    out = {}
    t = threading.Thread(target=lambda: out.update(g2.call("ops.run", {"name": "docker-purge", "hosts": ["n1"], "params": {"keep_hours": 2}})))
    t.start()
    for _ in range(50):
        pend = G.list_approvals(gw.tmp / "i4")
        if pend:
            break
        time.sleep(0.1)
    assert pend and pend[0]["tool"] == "ops.docker-purge"
    G.decide_approval(gw.tmp / "i4", pend[0]["id"], "rejected")
    t.join()
    assert not out["ok"] and "not approved" in out["error"]
    t = threading.Thread(target=lambda: out.update(g2.call("ops.run", {"name": "docker-purge", "hosts": ["n1"]})))
    t.start()
    time.sleep(0.5)
    G.decide_approval(gw.tmp / "i4", G.list_approvals(gw.tmp / "i4")[0]["id"], "approved")
    t.join()
    assert out["ok"]
    # approvals.mutating: deny
    e3 = env(tools=[{"remote_ops": {"hosts": ["n1"], "mode": "approve_writes"}}], approvals={"mutating": "deny"})
    g3 = G.Gateway(e3, cfg, session_id="s5", snapshot=gw.store.snapshot, inbox=gw.tmp / "i5", backends=gw.fake, secrets={}, audit=Audit("s5"))
    assert "denies mutating" in g3.call("ops.run", {"name": "docker-purge"})["error"]


def test_secrets_never_in_results_or_audit(gw):
    gw.fake.sql = lambda *a, **k: {"rows": [["postgres://u:SuperSecretPw@db/x"]]}
    gw.store.upsert(ORDERS)
    r = gw.call("sql.orders_by_status", {})
    assert "SuperSecretPw" not in r["result"] and "***" in r["result"]
    log = (gw.tmp / "audit" / "s1.jsonl").read_text()
    assert "SuperSecretPw" not in log
    assert Audit("s1").verify()
    assert "pattern" in log and "orders_by_status@1" in log


def test_tool_allowlist_per_environment(gw):
    names = {t.name for t in gw.list_tools()}
    assert {"sql.query", "es.search", "redis.command", "kubernetes.get", "query.list"} <= names
    assert not any(n.startswith(("ops.", "disk.", "airflow.", "slack.", "jira.")) for n in names)
    assert not gw.call("disk.read", {"path": "/etc/passwd"})["ok"]
    assert not gw.call("ops.run", {"name": "cpu"})["ok"]


def test_rate_limit_and_output_cap(gw):
    gw.rate = 3
    for _ in range(3):
        gw.call("query.list", {})
    assert "rate limit" in gw.call("query.list", {})["error"]
    gw.rate, gw._calls = 100, type(gw._calls)()
    gw.max_output = 50
    gw.fake.run = lambda *a, **k: runner.Result(0, "x" * 500, "")
    r = gw.call("kubernetes.get", {"resource": "pods", "namespace": "app"})
    assert "[truncated" in r["result"] and len(r["result"]) < 120


def test_disk_stays_inside_root_symlink_safe(tmp_path, gw):
    root = tmp_path / "logs"
    root.mkdir()
    (root / "a.log").write_text("hello")
    (tmp_path / "outside.txt").write_text("secret")
    (root / "link").symlink_to(tmp_path / "outside.txt")
    g = G.Gateway(env(tools=[{"disk": {"mounts": [str(root)]}}]), Config(), session_id="s6", snapshot=gw.store.snapshot, inbox=tmp_path / "i6",
                  backends=gw.fake, secrets={}, audit=Audit("s6"))
    assert g.call("disk.read", {"path": str(root / "a.log")})["result"] == "hello"
    assert g.call("disk.read", {"path": "a.log"})["ok"]
    for p in (str(root / "link"), "../outside.txt", str(tmp_path / "outside.txt"), str(root / ".." / "outside.txt")):
        assert not g.call("disk.read", {"path": p})["ok"], p


def test_audit_records_intent_and_result_for_rejections_too(gw):
    gw.call("sql.query", {"sql": "drop table x"})
    gw.call("nope", {})
    kinds = [json.loads(l)["kind"] for l in (gw.tmp / "audit" / "s1.jsonl").read_text().splitlines()]
    assert kinds == ["tool.intent", "tool.result", "tool.rejected"] and Audit("s1").verify()


def test_slack_untrusted_and_channel_allowlist(gw):
    e = env(tools=[{"slack": {"channels": ["alerts"], "token_env": "SLACK_TOKEN"}}])
    g = G.Gateway(e, Config(), session_id="s7", snapshot=gw.store.snapshot, inbox=gw.tmp / "i7", backends=gw.fake,
                  secrets={"SLACK_TOKEN": "xoxp-123456"}, audit=Audit("s7"))
    r = g.call("slack.search", {"query": "error"})
    assert r["ok"] and json.loads(r["result"])["untrusted"] is True
    assert not g.call("slack.read_channel", {"channel": "D123"})["ok"]
    assert not g.call("slack.read_channel", {"channel": "random"})["ok"]


def test_require_replica_is_passed_to_the_driver_and_enforced(tmp_path, monkeypatch):
    # gateway side: the setting reaches the backend for patterns and for the fixed helpers
    monkeypatch.setattr("airlock.audit.HOME", tmp_path)
    store = PatternStore(tmp_path / "db.sqlite", tmp_path / "snap" / "snapshot.json")
    store.upsert(ORDERS)
    fake = Fake()
    e = env(tools=[{"postgres": {"dsn_env": "PG_DSN", "require_replica": True, "schemas": ["public"]}}])
    g = G.Gateway(e, Config(), session_id="r1", snapshot=store.snapshot, inbox=tmp_path / "i", backends=fake, secrets={"PG_DSN": "postgres://x"}, audit=Audit("r1"))
    assert g.call("sql.orders_by_status", {})["ok"] and fake.sql_kw == {"require_replica": True}
    assert g.call("sql.list_tables", {})["ok"] and fake.sql_kw == {"require_replica": True}
    # driver side: with a fake psycopg, a primary is refused before any query runs, a standby is accepted, SQL is sent in a READ ONLY transaction
    from airlock import backends
    log = []

    class Cur:
        description = [type("D", (), {"name": "n"})()]

        def __init__(self, in_recovery): self.rec = in_recovery
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def execute(self, sql, params=None): log.append(sql)
        def fetchone(self): return (self.rec,)
        def fetchmany(self, n): return [(1,)]

    class Conn:
        def __init__(self, rec): self.rec, self.read_only = rec, False
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def cursor(self): return Cur(self.rec)
        def rollback(self): log.append("rollback")

    import sys, types
    for rec in (False, True):
        log.clear()
        sys.modules["psycopg"] = types.SimpleNamespace(connect=lambda dsn, **kw: Conn(rec))
        run = lambda: backends.Backends().sql("postgres://x", "select 1", {}, backends.Limits(timeout_s=7), require_replica=True)
        if not rec:
            with pytest.raises(backends.BackendError, match="not a read-only replica"):
                run()
            assert log == ["set local statement_timeout = 7000", "select pg_is_in_recovery()"]   # the query itself never ran
        else:
            assert run()["rows"] == [[1]] and "select 1" in log
    sys.modules.pop("psycopg", None)


def test_remote_ops_hosts_must_be_node_names_not_a_tag_selector(gw):
    e = env(tools=[{"remote_ops": {"hosts": "tag:env=uat", "mode": "read"}}])
    cfg = Config.model_validate({"nodes": [{"name": "n1", "host": "10.0.0.1", "exec": {"mode": "ssh_sudo"}}]})
    g = G.Gateway(e, cfg, session_id="s9", snapshot=gw.store.snapshot, inbox=gw.tmp / "i9", backends=gw.fake, secrets={}, audit=Audit("s9"), approval_timeout=3)
    r = g.call("ops.list", {})
    assert not r["ok"] and "list of node names" in str(r)


# ---------------------------------------------------------------- agent-proposed access (SPEC 7.8)

class KubeFake(Fake):
    """`kubectl get` answers with the backend deployment's container; sql_exec records what would run in the pod."""

    def run(self, ex, argv, **kw):
        self.calls.append(("run", ex.mode, ex.host, argv))
        if "deploy/backend" in argv:
            return runner.Result(0, "backend", "")
        return runner.Result(1, "", 'Error from server (NotFound): deployments.apps "x" not found')

    def sql_exec(self, ex, argv, sql, params, limits, **kw):
        self.calls.append(("sql_exec", argv, sql, params))
        return {"columns": ["date", "count"], "rows": [["2026-10-09", 4210]], "truncated": False}


@pytest.fixture
def bare(tmp_path, monkeypatch):
    """An environment created from a kube context only: no data store configured yet."""
    monkeypatch.setattr("airlock.audit.HOME", tmp_path)
    store = PatternStore(tmp_path / "db.sqlite", tmp_path / "snap" / "snapshot.json")
    fake = KubeFake()
    e = Environment.model_validate({"name": "uat", "kube_context": "uat", "tools": [{"kubernetes": {"mode": "read"}}]})
    g = G.Gateway(e, Config(), session_id="s9", snapshot=store.snapshot, inbox=tmp_path / "inbox", backends=fake, secrets={})
    g.store, g.fake, g.tmp = store, fake, tmp_path
    return g


SDD = {"kind": "sql", "name": "orders_daily", "description": "Orders per date",
       "template": "select date, count(*) from app_orderdaily where date >= {{ since:ts }} group by date order by date",
       "evidence": "app/models.py:120 OrderDaily"}
MGMT = {"kind": "postgres", "transport": "exec", "runner": "django", "evidence": "settings.py DATABASES",
        "target": {"namespace": "app", "workload": "deploy/backend", "container": "backend"}}


def test_query_tools_exist_from_the_start_and_refuse_without_a_route(bare):
    # an MCP client lists tools once, when it connects: tools that run approved queries must already be there
    names = {t.name for t in bare.list_tools()}
    assert {"proposal.submit", "proposal.status", "access.list", "query.list", "query.run", "sql.query", "es.search", "redis.command"} <= names
    assert json.loads(bare.call("access.list", {})["result"])["routes"] == []
    r = bare.call("sql.list_tables", {})
    assert not r["ok"] and "no approved postgres route" in r["error"] and "proposal.submit" in r["error"]


def test_infeasible_items_go_back_to_the_agent_and_nothing_connects(bare):
    bad_route = {**MGMT, "target": {"namespace": "app", "workload": "deploy/gone"}}
    r = json.loads(bare.call("proposal.submit", {"task": "t", "routes": [bad_route], "queries": [SDD]})["result"])
    assert r["status"] == "refused" and "not found" in r["items"]["r0"]["reason"]
    assert not (bare.tmp / "inbox" / "proposals").exists() or not list((bare.tmp / "inbox" / "proposals").iterdir())
    r = json.loads(bare.call("proposal.submit", {"task": "t", "queries": [SDD]})["result"])
    assert r["status"] == "refused" and "no route postgres/default" in r["items"]["q0"]["reason"]
    err = bare.call("proposal.submit", {"task": "t", "routes": [{**MGMT, "runner": "rails"}]})
    assert not err["ok"] and "proposal refused" in err["error"]                 # only built-in runners
    # before approval the gateway only ran `kubectl get`: no exec, no database connection
    assert bare.fake.calls and all(c[0] == "run" and "get" in c[3] and "exec" not in c[3] for c in bare.fake.calls)


def test_submit_wait_approve_run_end_to_end(bare, monkeypatch, tmp_path):
    from airlock import proposals as PR, session
    r = json.loads(bare.call("proposal.submit", {"task": "number of orders yesterday and today", "routes": [MGMT],
                                                  "queries": [SDD]})["result"])
    assert r["status"] == "pending" and all(v["ok"] for v in r["items"].values())
    pid = r["id"]
    assert json.loads(bare.call("proposal.status", {"id": pid})["result"])["status"] == "pending"
    # the controller side: inbox -> store -> human approves -> activation -> status back to the agent
    sess = tmp_path / "sessions"
    (sess / "s9").mkdir(parents=True)
    (sess / "s9" / "inbox").symlink_to(bare.tmp / "inbox")
    monkeypatch.setattr(session, "SESSIONS", sess)
    assert PR.import_inboxes(bare.store) == [pid]
    cfg = Config.model_validate({"environments": [{"name": "uat", "kube_context": "uat", "tools": [{"kubernetes": {"mode": "read"}}]}]})

    class Probe(KubeFake):
        def sql_exec(self, ex, argv, sql, params, limits, **kw):
            return {"columns": ["read_only_txn", "replica", "role", "superuser"], "rows": [["on", False, "app", False]], "truncated": False}

    PR.decide(bare.store, cfg, pid, approve=["r0", "q0"], by="human", backends=Probe())
    route = bare.store.route("uat/postgres/default")
    assert route.status == "active" and route.guarantees["read_only_txn"] is True and route.guarantees["replica"] is False
    st = json.loads(bare.call("proposal.status", {"id": pid, "wait": 1})["result"])
    assert st["status"] == "decided" and {i["decision"] for i in st["items"]} == {"approved"}
    # the route and the pattern are live in the running session, through tools the agent had from the start
    r = bare.call("query.run", {"name": "orders_daily", "params": {"since": "2026-10-08"}})
    assert r["ok"], r
    kind, argv, sql, params = bare.fake.calls[-1]
    assert kind == "sql_exec" and argv[-5:] == ["python", "manage.py", "shell", "-v", "0"] and "deploy/backend" in argv
    assert params == {"since": "2026-10-08"}
    listed = json.loads(bare.call("access.list", {})["result"])["routes"]
    assert listed[0]["transport"] == "exec" and listed[0]["guarantees"]["read_only_txn"] is True
    rec = [json.loads(x) for x in (tmp_path / "audit" / "s9.jsonl").read_text().splitlines()]
    assert any(x["kind"] == "proposal.submitted" for x in rec)
    assert any(x["kind"] == "tool.result" and x["payload"].get("pattern") == "orders_daily@1" and x["payload"].get("rows") == 1 for x in rec)
    assert not bare.call("query.run", {"name": "orders_daily", "params": {"since": "x; drop"}})["ok"]   # typed values only
    assert not bare.call("query.run", {"name": "orders_daily", "params": {"evil": 1}})["ok"]
    assert bare.call("sql.query", {"sql": "select date, count(*) from app_orderdaily where date >= '2026-10-09' group by date order by date"})["ok"]


def test_secret_values_are_refused_as_route_secrets(bare):
    err = bare.call("proposal.submit", {"task": "t", "routes": [{"kind": "redis", "transport": "direct", "secret": "redis://:pw@host"}]})
    assert not err["ok"] and "secret names" in err["error"] and "pw@host" not in err["error"]
    ok = json.loads(bare.call("proposal.submit", {"task": "t", "routes": [{"kind": "redis", "transport": "direct", "secret": "REDIS_URL"}]})["result"])
    assert ok["status"] == "pending" and "needs" in ok["items"]["r0"]       # the secret is entered when it is approved


# ---------------------------------------------------------------- files routes (SPEC 7.8)

def run_files_program(op, args, roots):
    """The files runner as the pod would run it: `python -I -` with the program on stdin."""
    import base64, subprocess, sys
    from airlock.backends import FILES_CAPS, FILES_PROGRAM
    enc = base64.b64encode(json.dumps({"op": op, "args": args, "roots": roots, "caps": FILES_CAPS}).encode()).decode()
    out = subprocess.run([sys.executable, "-I", "-"], input=FILES_PROGRAM.replace("PAYLOAD", enc), capture_output=True, text=True).stdout
    return json.loads(out.strip().splitlines()[-1][len("AIRLOCK_RESULT "):])


@pytest.fixture
def trails(tmp_path):
    root = tmp_path / "data" / "reports"
    day = root / "2026" / "10" / "09" / "ETC" / "qdir1"
    day.mkdir(parents=True)
    f = day / "orders-20261009.fix"
    f.write_bytes(b"8=FIX.4.2\x0135=D\x0111=ABC123\x0155=AAPL\n8=FIX.4.2\x0135=8\x0111=ABC123\x0139=2\n")
    (tmp_path / "secret.env").write_text("PW=hunter2")
    (root / "escape").symlink_to(tmp_path / "secret.env")
    return root, f


def test_files_runner_reads_only_inside_the_roots(trails, tmp_path):
    root, f = trails
    roots = [str(root)]
    assert run_files_program("find", {"path": str(root), "name": "*20261009*.fix"}, roots)["matches"] == [str(f)]
    hit = run_files_program("grep", {"path": str(root), "text": "ABC123", "name": "*.fix"}, roots)["matches"]
    assert len(hit) == 2 and hit[0]["text"] == "8=FIX.4.2|35=D|11=ABC123|55=AAPL"      # SOH shown as |
    assert run_files_program("tail", {"path": str(f), "lines": 1}, roots)["lines"] == ["8=FIX.4.2|35=8|11=ABC123|39=2"]
    assert run_files_program("read", {"path": str(f), "offset": 0, "limit": 9}, roots)["text"] == "8=FIX.4.2"
    for bad in (str(root / "escape"), str(tmp_path / "secret.env"), str(root) + "/../../secret.env", "relative/path", "/etc/passwd"):
        r = run_files_program("read", {"path": bad}, roots)
        assert "outside the allowed roots" in r.get("error", "") or "absolute path" in r.get("error", ""), bad
        assert "hunter2" not in json.dumps(r)
    assert run_files_program("probe", {}, roots)[str(root)]["exists"] is True


class FilesFake(KubeFake):
    def run(self, ex, argv, **kw):
        self.calls.append(("run", ex.mode, ex.host, argv))
        if "deploy/worker" in argv:
            return runner.Result(0, "worker", "")
        return super().run(ex, argv, **kw)

    def files_exec(self, ex, argv, op, args, roots, **kw):
        self.calls.append(("files_exec", argv, op, args, roots))
        if op == "probe":
            return {r: {"exists": True, "readable": True, "writable": True} for r in roots}
        return {"path": args.get("path"), "matches": [{"path": "/data/reports/x.fix", "line": 1, "text": "11=ABC123"}]}


FILES = {"kind": "files", "transport": "exec", "runner": "python", "evidence": "k8s/worker.yaml:46-84",
         "target": {"namespace": "app", "workload": "deploy/worker", "container": "worker"},
         "roots": ["/data/reports", "/data/incoming"]}


def test_files_route_propose_approve_read(bare, monkeypatch, tmp_path):
    from airlock import proposals as PR, session
    bare.backends = bare.fake = FilesFake()
    assert not bare.call("files.grep", {"path": "/data/reports", "text": "ABC123"})["ok"]   # no route yet
    err = bare.call("proposal.submit", {"task": "t", "routes": [{**FILES, "roots": ["/run/secrets/app"]}]})
    assert not err["ok"] and "credentials directory" in err["error"]
    r = json.loads(bare.call("proposal.submit", {"task": "find order ABC123 in the reports", "routes": [FILES]})["result"])
    assert r["status"] == "pending", r
    assert not any(c[0] == "files_exec" for c in bare.fake.calls)              # nothing read before approval
    sess = tmp_path / "sessions"
    (sess / "s9").mkdir(parents=True)
    (sess / "s9" / "inbox").symlink_to(bare.tmp / "inbox")
    monkeypatch.setattr(session, "SESSIONS", sess)
    PR.import_inboxes(bare.store)
    cfg = Config.model_validate({"environments": [{"name": "uat", "kube_context": "uat", "tools": [{"kubernetes": {"mode": "read"}}]}]})
    PR.decide(bare.store, cfg, r["id"], approve=["r0"], by="human", backends=FilesFake())
    route = bare.store.route("uat/files/default")
    assert route.status == "active" and route.guarantees["writable_mount"] is True
    got = bare.call("files.grep", {"path": "/data/reports", "text": "ABC123", "name": "*.fix"})
    assert got["ok"], got
    kind, argv, op, args, roots = bare.fake.calls[-1]
    assert kind == "files_exec" and op == "grep" and roots == FILES["roots"]
    assert argv[-3:] == ["python", "-I", "-"] and "deploy/worker" in argv
    rec = [json.loads(x) for x in (tmp_path / "audit" / "s9.jsonl").read_text().splitlines()]
    assert any(x["kind"] == "tool.result" and x["payload"].get("route") == "uat/files/default" for x in rec)


# ---------------------------------------------------------------- exec routes without passwords: airflow, redis, elasticsearch
class PodFake(KubeFake):
    def run(self, ex, argv, **kw):
        self.calls.append(("run", ex.mode, ex.host, argv))
        return runner.Result(0, "scheduler backend", "")

    def sql_exec(self, ex, argv, sql, params, limits, **kw):
        if "transaction_read_only" in sql:
            return {"columns": ["read_only_txn", "replica", "role", "superuser"], "rows": [["on", False, "airflow", False]]}
        return super().sql_exec(ex, argv, sql, params, limits, **kw)

    def redis_exec(self, ex, argv, pod_vars, command, limits):
        self.calls.append(("redis_exec", argv, pod_vars, command))
        return "role:master" if command[0] == "INFO" else "42"

    def es_exec(self, ex, argv, pod_vars, index, endpoint, body, limits):
        self.calls.append(("es_exec", argv, pod_vars, index, endpoint, body))
        return {"status": "green"} if endpoint == "_cluster/health" else {"count": 7}


def test_exec_routes_use_the_pods_own_credentials(bare, monkeypatch, tmp_path):
    from airlock import proposals as PR, session
    bare.backends = bare.fake = PodFake()
    tgt = {"namespace": "app", "workload": "deploy/backend", "container": "backend"}
    bad = bare.call("proposal.submit", {"task": "t", "routes": [{"kind": "redis", "transport": "exec", "runner": "python", "target": tgt}]})
    assert not bad["ok"] and "url_var" in bad["error"]
    bad = bare.call("proposal.submit", {"task": "t", "routes": [{"kind": "redis", "transport": "exec", "runner": "python", "target": tgt,
                                                                 "url_var": "redis://:pw@host"}]})
    assert not bad["ok"] and "pw@host" not in bad["error"]
    sub = {"task": "airflow failures and cache state", "routes": [
        {"kind": "postgres", "name": "airflow", "transport": "exec", "runner": "airflow",
         "target": {"namespace": "airflow", "workload": "deploy/airflow-scheduler", "container": "scheduler"}},
        {"kind": "redis", "transport": "exec", "runner": "python", "target": tgt, "url_var": "REDIS_URLS"},
        {"kind": "elasticsearch", "transport": "exec", "runner": "python", "target": tgt, "url_var": "ELASTICSEARCH_URLS",
         "user_var": "ELASTICSEARCH_USER", "password_var": "ELASTICSEARCH_PASS"}],
        "queries": [
            {"kind": "sql", "name": "af_failed", "description": "failed dag runs", "route": "airflow",
             "template": "select dag_id, count(*) from dag_run where state = 'failed' group by dag_id"},
            {"kind": "redis", "name": "cache_get", "description": "a cache key", "template": "GET {{ key:str }}"},
            {"kind": "elasticsearch", "name": "orders_count", "description": "orders", "template": {"index": "orders", "endpoint": "_count", "body": {}}}]}
    r = json.loads(bare.call("proposal.submit", sub)["result"])
    assert r["status"] == "pending" and not any("needs" in v for v in r["items"].values()), r   # no secret to enter
    sess = tmp_path / "sessions"
    (sess / "s9").mkdir(parents=True)
    (sess / "s9" / "inbox").symlink_to(bare.tmp / "inbox")
    monkeypatch.setattr(session, "SESSIONS", sess)
    PR.import_inboxes(bare.store)
    cfg = Config.model_validate({"environments": [{"name": "uat", "kube_context": "uat", "tools": [{"kubernetes": {"mode": "read"}}]}]})
    PR.decide(bare.store, cfg, r["id"], approve=["r0", "r1", "r2", "q0", "q1", "q2"], by="human", backends=PodFake())
    assert bare.store.route("uat/redis/default").guarantees["role"] == "master"
    assert bare.store.route("uat/elasticsearch/default").guarantees["cluster_status"] == "green"
    got = bare.call("query.run", {"name": "af_failed"})
    assert got["ok"], (got, bare.store.get("af_failed"))
    kind, argv, *_ = bare.fake.calls[-1]
    assert kind == "sql_exec" and argv[-2:] == ["python", "-"] and "deploy/airflow-scheduler" in argv
    assert json.loads(bare.call("query.run", {"name": "cache_get", "params": {"key": "k1"}})["result"]) == 42
    assert bare.fake.calls[-1][2:] == ({"url": "REDIS_URLS"}, ["GET", "k1"]) and bare.fake.calls[-1][1][-3:] == ["python", "-I", "-"]
    assert json.loads(bare.call("query.run", {"name": "orders_count"})["result"]) == {"count": 7}
    assert bare.fake.calls[-1][2] == {"url": "ELASTICSEARCH_URLS", "user": "ELASTICSEARCH_USER", "password": "ELASTICSEARCH_PASS"}


def run_pod_program(payload, env):
    import base64, subprocess, sys
    from airlock.backends import POD_STORE_PROGRAM
    enc = base64.b64encode(json.dumps(payload).encode()).decode()
    out = subprocess.run([sys.executable, "-I", "-"], input=POD_STORE_PROGRAM.replace("PAYLOAD", enc), capture_output=True,
                         text=True, env=env).stdout
    return json.loads(out.strip().splitlines()[-1][len("AIRLOCK_RESULT "):])


def test_pod_program_speaks_redis_and_masks_the_url():
    import socket
    import threading
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port, seen = srv.getsockname()[1], []

    def serve():
        c, _ = srv.accept()
        f = c.makefile("rb")
        for _ in range(2):   # AUTH, then the command
            n = int(f.readline()[1:])
            args = [f.readline() and f.readline().rstrip(b"\r\n").decode() for _ in range(n)]
            seen.append(args)
            c.sendall(b"+OK\r\n" if args[0] == "AUTH" else b"$5\r\nhello\r\n")
        c.close()
    threading.Thread(target=serve, daemon=True).start()
    env = {"REDIS_URLS": f"redis://:s3cretpw@127.0.0.1:{port}"}
    base = {"store": "redis", "vars": {"url": "REDIS_URLS"}, "timeout": 5, "scan_count": 10, "allowed": ["GET"]}
    assert run_pod_program({**base, "argv": ["GET", "k"]}, env) == {"result": "hello"}
    assert seen == [["AUTH", "s3cretpw"], ["GET", "k"]]
    assert "allowlist" in run_pod_program({**base, "argv": ["FLUSHALL"]}, env)["error"]
    err = run_pod_program({**base, "argv": ["GET", "k"]}, {"REDIS_URLS": "redis://:s3cretpw@127.0.0.1:1"})["error"]
    assert "s3cretpw" not in err
