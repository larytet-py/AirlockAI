"""Per-session kubeconfig (Mode 2): exec logins become a bearer token on the host; session networks avoid VPN routes."""
import base64
import ipaddress
import json
import stat
import sys
import time
from types import SimpleNamespace

import pytest

from airlock import gateway as G
from airlock import kubecreds, session
from airlock.config import ConfigError
from airlock.envs import Environment


def jwt(exp: float) -> str:
    body = base64.urlsafe_b64encode(json.dumps({"exp": exp}).encode()).decode().rstrip("=")
    return f"h.{body}.s"


def plugin(tmp_path, status: dict, rc: int = 0) -> dict:
    """An exec stanza whose command prints an ExecCredential."""
    f = tmp_path / "plugin.py"
    f.write_text(f"import json,sys\nprint(json.dumps({{'status': {status!r}}}))\nsys.exit({rc})\n")
    return {"command": sys.executable, "args": [str(f)], "apiVersion": "client.authentication.k8s.io/v1beta1"}


def mini(ctx: str, user: dict) -> dict:
    return {"clusters": [{"name": f"c-{ctx}", "cluster": {"server": f"https://{ctx}:6443", "certificate-authority-data": "Q0E="}}],
            "users": [{"name": "shared", "user": user}], "contexts": [{"name": ctx, "context": {"cluster": f"c-{ctx}", "user": "shared"}}]}


def env(tools, **kw) -> Environment:
    return Environment.model_validate({"name": "e", "kube_context": "uat", "tools": tools, **kw})


def test_contexts_only_direct_kube_tools():
    assert kubecreds.contexts(env([{"kubernetes": {}}, {"kubectl_commands": {"context": "other", "commands": []}}])) == ["uat", "other"]
    assert kubecreds.contexts(env([{"slack": {}}])) == ["uat"]     # exec routes may be approved mid-session
    assert kubecreds.contexts(Environment.model_validate({"name": "e", "tools": [{"slack": {}}]})) == []
    assert kubecreds.contexts(env([{"kubernetes": {}}], exec={"mode": "ssh", "host": "b"})) == []


def test_exec_user_becomes_token(tmp_path, monkeypatch):
    exp = time.time() + 3600
    ex = plugin(tmp_path, {"token": jwt(exp)})
    monkeypatch.setattr(kubecreds, "_kubectl_json", lambda args, timeout=20: mini(args[-1], {"exec": ex}))
    kube = kubecreds.write(tmp_path, env([{"kubernetes": {}}, {"kubectl_commands": {"context": "prd", "commands": []}}]))
    assert abs(kube["expires"] - exp) < 1
    f = tmp_path / "kube" / "config"
    assert stat.S_IMODE(f.stat().st_mode) == 0o600
    conf = json.loads(f.read_text())
    assert all("exec" not in u["user"] and u["user"]["token"] for u in conf["users"])
    # two contexts sharing a user name each get their own user entry
    assert [c["context"]["user"] for c in conf["contexts"]] == ["airlock-uat", "airlock-prd"]
    assert conf["current-context"] == "uat"


def test_expiration_timestamp_wins_over_jwt(tmp_path):
    token, exp = kubecreds.exec_token(plugin(tmp_path, {"token": "opaque", "expirationTimestamp": "2030-01-01T00:00:00Z"}), "uat")
    assert token == "opaque" and exp == 1893456000.0


def test_plugin_failure_and_no_token(tmp_path):
    with pytest.raises(ConfigError, match="login plugin failed"):
        kubecreds.exec_token(plugin(tmp_path, {}, rc=1), "uat")
    with pytest.raises(ConfigError, match="no token"):
        kubecreds.exec_token(plugin(tmp_path, {"clientCertificateData": "x"}), "uat")


def test_no_kubectl_no_file(tmp_path):
    assert kubecreds.write(tmp_path, Environment.model_validate({"name": "e", "tools": [{"slack": {}}]})) is None
    assert not (tmp_path / "kube").exists()


def test_expired_token_tells_the_agent_who_can_fix_it():
    msg = G.kube_error("error: You must be logged in to the server (Unauthorized)")
    assert "kube-refresh" in msg
    assert "kube-refresh" not in G.kube_error("pods not found")


def test_network_avoids_host_routes(monkeypatch):
    calls = []
    monkeypatch.setattr(session, "_host_routes", lambda: [ipaddress.ip_network("10.200.0.0/23")])
    monkeypatch.setattr(session, "_docker_subnets", lambda: [ipaddress.ip_network("10.200.2.0/24")])
    monkeypatch.setattr(session, "uplink_mtu", lambda: 1280)
    monkeypatch.setattr(session, "docker", lambda *a, check=True: calls.append(a) or SimpleNamespace(returncode=0, stderr=""))
    session.network_create("air-x", internal=True)
    assert calls == [("network", "create", "--internal", "-o", "com.docker.network.driver.mtu=1280", "--subnet", "10.200.3.0/24", "air-x")]


def test_sql_exec_sends_data_not_code(monkeypatch):
    from airlock.backends import Backends, BackendError, SQL_EXEC_MARK
    from airlock.config import Exec
    from airlock.patterns import Limits
    sent = {}

    def fake(self, ex, argv, data, *, timeout):
        sent["argv"], sent["data"] = argv, data
        return SimpleNamespace(rc=0, err="", out="42 objects imported\n" + SQL_EXEC_MARK + json.dumps({"columns": ["n"], "rows": [[3]], "truncated": False}))

    monkeypatch.setattr(Backends, "run_stdin", fake)
    evil = "select 1 where x = %(v)s -- \"\"\" ; import os"
    r = Backends().sql_exec(Exec(mode="direct"), ["kubectl", "exec"], evil, {"v": "'); drop table t; --"}, Limits(rows=5))
    assert r["rows"] == [[3]]
    payload = sent["data"].split('b64decode("')[1].split('"')[0]
    assert json.loads(base64.b64decode(payload)) == {"sql": evil, "params": {"v": "'); drop table t; --"}, "rows": 5,
                                                     "require_replica": False, "timeout_ms": 10000}
    assert evil not in sent["data"] and "set transaction read only" in sent["data"] and "set_rollback(True)" in sent["data"]

    monkeypatch.setattr(Backends, "run_stdin", lambda *a, **k: SimpleNamespace(rc=0, err="", out=SQL_EXEC_MARK + '{"error": "ReadOnlySqlTransaction: cannot execute CREATE"}'))
    with pytest.raises(BackendError, match="ReadOnly"):
        Backends().sql_exec(Exec(mode="direct"), ["kubectl"], "create table t()", {}, Limits())
    monkeypatch.setattr(Backends, "run_stdin", lambda *a, **k: SimpleNamespace(rc=1, err="error: Unauthorized", out=""))
    with pytest.raises(BackendError, match="no result"):
        Backends().sql_exec(Exec(mode="direct"), ["kubectl"], "select 1", {}, Limits())


def test_sql_exec_program_compiles():
    from airlock.backends import SQL_EXEC_PROGRAM
    compile(SQL_EXEC_PROGRAM.replace("PAYLOAD", "e30="), "airlock-sql", "exec")
