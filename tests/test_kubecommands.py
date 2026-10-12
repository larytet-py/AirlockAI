"""Predefined kubectl commands: validated at load time, bound with typed values, and the only extra kubectl the agent gets."""
import pytest

from airlock import config as C
from airlock import envs, runner
from airlock import gateway as G
from airlock import kubecommands as K
from airlock.audit import Audit
from airlock.config import Config
from airlock.patternstore import PatternStore
from tests.test_gateway import Fake


def cmd(**kw):
    return K.KubeCommand.model_validate({"name": "x", **kw})


def test_read_exec_and_write_verbs_are_classified():
    K.validate(cmd(argv=["-n", "postgres", "get", "pods", "-L", "cnpg.io/instanceRole"]))
    K.validate(cmd(argv=["-n", "{{ ns:enum(postgres,redis) }}", "get", "pods"]))
    K.validate(cmd(argv=["-n", "postgres", "exec", "app-database-2", "-c", "postgres", "--", "psql", "-U", "ro", "-At", "-c", "select 1"], allow_exec=True))
    K.validate(cmd(argv=["-n", "app", "rollout", "restart", "deploy/web"], risk="write"))


@pytest.mark.parametrize("kw,msg", [
    (dict(argv=["delete", "pod", "x"]), "must declare risk: write"),
    (dict(argv=["rollout", "restart", "deploy/x"]), "must declare risk: write"),
    (dict(argv=["get", "pods"], risk="write"), None),                                                   # a read verb marked write is harmless
    (dict(argv=["exec", "p", "--", "psql"]), "allow_exec"),
    (dict(argv=["exec", "p", "--", "sh", "-c", "id"], allow_exec=True), "not a shell"),
    (dict(argv=["exec", "p", "--", "env", "x"], allow_exec=True), "not a shell"),
    (dict(argv=["exec", "p", "psql"], allow_exec=True), "needs `--`"),
    (dict(argv=["get", "pods", "--token=abc"]), "not allowed"),
    (dict(argv=["get", "pods", "--context", "prod"]), "not allowed"),
    (dict(argv=["get", "pods", "-f", "x.yaml"]), "not allowed"),
    (dict(argv=["exec", "-it", "p", "--", "psql"], allow_exec=True), "not allowed"),
    (dict(argv=["port-forward", "svc/x", "5432"]), "not allowed"),
    (dict(argv=["cp", "a", "b"]), "not allowed"),
    (dict(argv=[]), "argv"),
    (dict(argv=["get", "pods\nx"]), "argv"),
    (dict(argv=["exec", "p", "--", "psql", "-c", "{{ q:str }}"], allow_exec=True), "needs a regex or values"),
    (dict(argv=["get", "pods"], params={"nope": {"min": 1}}), "undeclared"),
])
def test_unsafe_commands_refused_at_load_time(kw, msg):
    if msg is None:
        K.validate(cmd(**kw))
        return
    with pytest.raises(C.ConfigError, match=msg):
        K.validate(cmd(**kw))


def test_bind_typed_values_never_free_text():
    c = cmd(argv=["-n", "{{ ns:enum(postgres,redis) }}", "get", "pods", "-l", "app={{ app:str }}", "--limit", "{{ n:int }}"],
            params={"n": {"min": 1, "max": 50, "default": 10}, "app": {"regex": "^[a-z0-9-]{1,30}$"}})
    K.validate(c)
    assert K.bind(c, {"ns": "redis", "app": "web-1"}) == ["-n", "redis", "get", "pods", "-l", "app=web-1", "--limit", "10"]
    for bad in ({"ns": "kube-system", "app": "x"}, {"ns": "redis", "app": "x; rm"}, {"ns": "redis", "app": "x", "n": 999},
                {"ns": "redis"}, {"ns": "redis", "app": "x", "extra": 1}, {"ns": "redis", "app": "a\nb"}):
        with pytest.raises(Exception):
            K.bind(c, bad)


def env_with(commands, **kw):
    return envs.Environment.model_validate({"name": "uat", "kube_context": "uat-ctx", "tools": [{"kubectl_commands": {"mode": "read", "commands": commands, **kw}}]})


@pytest.fixture
def gw(tmp_path, monkeypatch):
    monkeypatch.setattr("airlock.audit.HOME", tmp_path)
    store = PatternStore(tmp_path / "db.sqlite", tmp_path / "snap" / "snapshot.json")
    fake = Fake()

    def make(commands, env_kw=None, **kw):
        e = envs.Environment.model_validate({"name": "uat", "kube_context": "uat-ctx", **(env_kw or {}),
                                             "tools": [{"kubectl_commands": {"commands": commands, **kw}}]})
        g = G.Gateway(e, Config(), session_id="k1", snapshot=store.snapshot, inbox=tmp_path / "inbox", backends=fake, secrets={},
                      audit=Audit("k1"), approval_timeout=2)
        g.fake = fake
        return g
    return make


COMMANDS = [
    {"name": "db_roles", "description": "Which database pod is primary", "argv": ["-n", "postgres", "get", "pods", "-L", "cnpg.io/instanceRole"]},
    {"name": "product_count", "description": "Active products", "allow_exec": True,
     "argv": ["-n", "postgres", "exec", "{{ pod:enum(app-database-2,app-database-3) }}", "-c", "postgres", "--", "psql", "-U", "readonly", "-d", "app", "-At",
              "-c", "select count(*) from products where active and category = '{{ kind:enum(Book,Video) }}'"]},
    {"name": "restart_web", "risk": "write", "argv": ["-n", "app", "rollout", "restart", "deploy/{{ svc:enum(web,ws) }}"]},
]


def test_commands_become_tools_and_nothing_else_is_possible(gw):
    g = gw(COMMANDS, mode="read")
    names = {t.name for t in g.list_tools()}
    assert {"kubectl.db_roles", "kubectl.product_count", "kubectl.restart_web"} <= names
    assert not any(n.startswith("kubernetes.") for n in names)                       # no generic kubectl unless that tool is enabled
    r = g.call("kubectl.db_roles", {})
    assert r["ok"]
    kind, mode, host, argv = g.fake.calls[-1]
    assert argv == ["kubectl", "--context", "uat-ctx", "-n", "postgres", "get", "pods", "-L", "cnpg.io/instanceRole"]
    r = g.call("kubectl.product_count", {"pod": "app-database-2", "kind": "Book"})
    assert r["ok"] and g.fake.calls[-1][3][-1] == "select count(*) from products where active and category = 'Book'"
    assert "--" in g.fake.calls[-1][3] and g.fake.calls[-1][3][g.fake.calls[-1][3].index("--") + 1] == "psql"
    n = len(g.fake.calls)
    for tool, args in (("kubectl.product_count", {"pod": "app-database-1", "kind": "Book"}),               # not in the enum: the primary is off limits
                       ("kubectl.product_count", {"pod": "app-database-2", "kind": "Book'; drop table x; --"}),
                       ("kubectl.product_count", {"pod": "app-database-2"}),
                       ("kubectl.db_roles", {"namespace": "kube-system"}),                                  # no extra arguments
                       ("kubectl.delete", {"pod": "x"}), ("kubernetes.get", {"resource": "pods"})):
        assert not g.call(tool, args)["ok"], (tool, args)
    assert len(g.fake.calls) == n


def test_write_commands_are_off_in_read_mode_and_need_approval_otherwise(gw):
    g = gw(COMMANDS, mode="read")
    r = g.call("kubectl.restart_web", {"svc": "web"})
    assert not r["ok"] and "read-only" in r["error"]
    g2 = gw(COMMANDS, mode="approve_writes")
    import threading, time
    out = {}
    t = threading.Thread(target=lambda: out.update(g2.call("kubectl.restart_web", {"svc": "web"})))
    t.start()
    for _ in range(40):
        pend = G.list_approvals(g2.inbox)
        if pend:
            break
        time.sleep(0.1)
    assert pend and pend[0]["tool"] == "kubectl.restart_web"
    G.decide_approval(g2.inbox, pend[0]["id"], "rejected")
    t.join()
    assert not out["ok"] and "not approved" in out["error"]
    assert not any(c[0] == "run" and "rollout" in c[3] for c in g2.fake.calls)


def test_execution_mode_is_applied_after_the_policy(gw):
    g = gw(COMMANDS, env_kw={"exec": {"mode": "ssh_sudo", "host": "bastion", "user": "u", "auth": "key", "kubeconfig": "/etc/k.yaml"}})
    assert g.call("kubectl.db_roles", {})["ok"]
    kind, mode, host, argv = g.fake.calls[-1]
    assert (mode, host) == ("ssh_sudo", "bastion") and argv[:3] == ["kubectl", "--kubeconfig", "/etc/k.yaml"] and "--context" not in argv


def test_bad_config_is_refused_by_the_loader(tmp_path):
    base = "version: 1\nenvironments:\n  - name: uat\n    tools:\n      - kubectl_commands:\n          commands:\n"
    p = tmp_path / "a.yaml"
    p.write_text(base + "            - {name: ok, argv: [get, pods]}\n")
    assert envs.environment(C.load_config(p), "uat").tool("kubectl_commands")["commands"][0]["name"] == "ok"
    p.write_text(base + "            - {name: bad, argv: [delete, pod, x]}\n")
    with pytest.raises(C.ConfigError, match="risk: write"):
        C.load_config(p)
    p.write_text(base + "            - {name: a, argv: [get, pods]}\n            - {name: a, argv: [get, nodes]}\n")
    with pytest.raises(C.ConfigError, match="twice"):
        C.load_config(p)


def test_selftest_style_forbidden_calls_never_reach_a_backend(gw):
    g = gw(COMMANDS)
    n = len(g.fake.calls)
    for args in ({"pod": "app-database-1", "kind": "Book"}, {"pod": "x", "kind": "y"}, {}):
        assert not g.call("kubectl.product_count", args)["ok"]
    assert len(g.fake.calls) == n
