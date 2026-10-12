"""Mode 2 acceptance with real containers (SPEC 13, M3 'Done when').

Run (isolated home, needs docker and `airlock image --gateway`):
  AIRLOCK_HOME=$(mktemp -d) uv run pytest -m integration tests/test_acceptance_mode2.py
Proves, from inside the agent container: the gateway answers only with the session token, a DROP is rejected and audited, the
agent cannot read the secrets or reach the database/internet/controller, has no ssh or kubectl, and cleanup removes everything.
"""
import json
import os
import subprocess
import textwrap

import pytest

from airlock import gwsession, session
from airlock.config import HOME, load_config
from airlock.patternstore import PatternStore
from airlock.patterns import Pattern

pytestmark = pytest.mark.integration
CANARY = "CanaryDbPassw0rd-7e41"
USER_CANARY = "canary-user-pw-31bd"


@pytest.fixture(scope="module")
def sess(tmp_path_factory):
    if "AIRLOCK_HOME" not in os.environ:
        pytest.skip("set AIRLOCK_HOME to a scratch directory")
    os.environ["USER_PASSWORD"] = USER_CANARY
    cfgp = HOME / "airlock.yaml"
    cfgp.parent.mkdir(parents=True, exist_ok=True)
    cfgp.write_text(textwrap.dedent("""
        version: 1
        environments:
          - name: uat
            kube_context: uat-ctx
            tools:
              - postgres: {dsn_env: PG_DSN, mode: read, schemas: [public]}
              - kubernetes: {mode: read, namespaces: [app]}
    """))
    sd = HOME / "secrets" / "uat"
    sd.mkdir(parents=True, exist_ok=True)
    f = sd / "secrets.env"
    f.write_text(f"PG_DSN=postgres://app:{CANARY}@db.invalid:5432/orders\n")
    f.chmod(0o600)
    PatternStore().upsert(Pattern(name="orders_by_status", kind="sql", scope=["uat"], description="Orders per status",
                                  template="select status, count(*) from orders where created_at > now() - interval '{{ hours:int }} hours' group by status",
                                  params={"hours": {"min": 1, "max": 168, "default": 6}}))
    from airlock import sources
    src = HOME / "proj-src"
    src.mkdir(exist_ok=True)
    (src / "app.py").write_text("print('hello')\n")
    sources.save([sources.Source(str(src), "rw", True)])                  # rw is requested but PROD must still get read-only
    cfg = load_config(cfgp)
    st = gwsession.start_gateway_session(cfg, cfgp, "uat", model_login=False)
    yield cfg, st
    if session.load_state(st["id"])["status"] != "stopped":
        session.stop_session(cfg, st["id"])


def sh(st, cmd, timeout=60):
    return session.exec_in(st["id"], "sh", "-c", cmd, timeout=timeout)


def mcp(st, method, params=None, token=None):
    """JSON-RPC to the gateway from inside the agent container."""
    code = textwrap.dedent(f"""
        import json, os, urllib.request, urllib.error
        tok = os.environ["MCP_TOKEN"] if {token is None!r} else {token!r}
        req = urllib.request.Request(os.environ["MCP_URL"], data=json.dumps({{"jsonrpc": "2.0", "id": 1, "method": {method!r}, "params": {params or {}!r}}}).encode(),
            headers={{"Content-Type": "application/json", "Accept": "application/json, text/event-stream", "Authorization": "Bearer " + tok}})
        try:
            print(urllib.request.urlopen(req, timeout=60).read().decode())
        except urllib.error.HTTPError as e:
            print(json.dumps({{"http": e.code}}))
    """)
    p = session.exec_in(st["id"], "python3", "-c", code, timeout=90)
    return json.loads(p.stdout.strip().splitlines()[-1])


def call(st, tool, args):
    return mcp(st, "tools/call", {"name": tool, "arguments": args})


def test_gateway_needs_the_session_token(sess):
    cfg, st = sess
    assert mcp(st, "tools/list", token="wrong") == {"http": 401}
    names = {t["name"] for t in mcp(st, "tools/list")["result"]["tools"]}
    assert {"query.list", "sql.query", "sql.orders_by_status", "kubernetes.get"} <= names


def test_drop_is_rejected_and_audited_and_valid_query_reaches_the_driver(sess):
    cfg, st = sess
    r = call(st, "sql.query", {"sql": "drop table orders"})["result"]
    assert r["isError"] and "pattern" in r["content"][0]["text"]
    ok = call(st, "sql.orders_by_status", {"hours": 3})["result"]          # allowed shape: reaches the driver, which cannot resolve db.invalid
    assert ok["isError"] and CANARY not in json.dumps(ok)                  # and no secret is echoed back
    log = (HOME / "audit" / f"{st['id']}.jsonl").read_text()
    assert "tool.result" in log and "drop table" in log and CANARY not in log and "orders_by_status@1" in log
    from airlock.audit import Audit
    assert Audit(st["id"]).verify()


def test_agent_has_no_secrets_no_tools_and_no_route(sess):
    cfg, st = sess
    assert CANARY not in sh(st, "env; cat /proc/*/environ 2>/dev/null | tr '\\0' '\\n'").stdout
    assert USER_CANARY not in sh(st, "env; cat /proc/*/environ 2>/dev/null | tr '\\0' '\\n'").stdout
    assert sh(st, f"grep -rIl {CANARY} / --exclude-dir=proc --exclude-dir=sys 2>/dev/null").stdout.strip() == ""
    assert sh(st, "ls /secrets /airlock-config /inbox /airlock-home 2>&1").returncode != 0
    for binary in ("ssh", "kubectl", "psql", "docker", "aws"):
        assert sh(st, f"command -v {binary}").returncode != 0, binary
    assert sh(st, "curl -sS -m 6 https://example.com").returncode != 0
    assert sh(st, "python3 -c \"import socket;socket.create_connection(('db.invalid',5432),3)\"").returncode != 0
    assert sh(st, "python3 -c \"import socket;socket.create_connection(('1.1.1.1',443),3)\"").returncode != 0
    gw_ip = sh(st, "getent hosts gateway | cut -d' ' -f1").stdout.strip()
    assert gw_ip
    for port in (22, 80, 5432, 9000):                                       # only the MCP port of the gateway answers
        assert sh(st, f"python3 -c \"import socket;socket.create_connection(('{gw_ip}',{port}),2)\"").returncode != 0


def test_no_shared_volume_and_hardened_containers(sess):
    cfg, st = sess
    sid = st["id"]
    gw = json.loads(subprocess.run(["docker", "inspect", f"air-gateway-{sid}"], capture_output=True, text=True).stdout)[0]
    ag = json.loads(subprocess.run(["docker", "inspect", f"air-agent-{sid}"], capture_output=True, text=True).stdout)[0]
    gw_mounts = {m["Source"] for m in gw["Mounts"]}
    ag_mounts = {m["Source"] for m in ag["Mounts"]}
    assert not (gw_mounts & ag_mounts)
    assert not any("docker.sock" in m for m in gw_mounts | ag_mounts)
    for c in (gw, ag):
        assert c["HostConfig"]["ReadonlyRootfs"] and c["HostConfig"]["CapDrop"] == ["ALL"] and not c["HostConfig"]["Privileged"]
    assert all("MCP_TOKEN" not in e for e in gw["Config"]["Env"])          # the gateway holds only the token hash
    assert any(e.startswith("MCP_TOKEN=") for e in ag["Config"]["Env"]) and not any("PG_DSN" in e or CANARY in e for e in ag["Config"]["Env"])
    assert subprocess.run(["docker", "network", "inspect", f"air-{sid}", "-f", "{{.Internal}}"], capture_output=True, text=True).stdout.strip() == "true"


def test_ssh_into_the_agent_by_id_and_by_name(sess):
    from airlock import sshaccess
    cfg, st = sess
    assert session.load_state(st["id"])["ssh"] is True
    sshaccess.refresh_sessions()          # conftest gives every test its own key path: install this test's key in the container
    assert sshaccess.set_name(st["id"], "uat-agent") == "uat-agent"
    conf = sshaccess.CONFIG.read_text()
    assert f"Host {st['id']} uat-agent" in conf
    probe = "id -un; pwd; [ -n \"$MCP_TOKEN\" ] && echo token-present; command -v kubectl ssh || echo no-ssh-client"
    for host in (st["id"], "uat-agent"):
        r = subprocess.run(["ssh", "-F", str(sshaccess.CONFIG), host, probe], capture_output=True, text=True, timeout=60)
        assert r.returncode == 0, r.stderr
        out = r.stdout.split()
        assert out[:3] == ["agent", "/src", "token-present"] and out[-1] == "no-ssh-client", r.stdout
    r = subprocess.run(["ssh", "-F", str(sshaccess.CONFIG), "-o", "IdentityFile=/dev/null", "-o", "BatchMode=yes", "uat-agent", "true"], capture_output=True, text=True, timeout=60)
    nets = subprocess.run(["docker", "port", f"air-agent-{st['id']}"], capture_output=True, text=True).stdout
    assert nets.strip() == ""                                              # no published port: only docker access reaches sshd


def test_source_folder_is_mounted_read_only_even_when_rw_requested(sess):
    cfg, st = sess
    assert sh(st, "cat /src/proj-src/app.py").stdout.strip() == "print('hello')"
    assert sh(st, "touch /src/proj-src/x").returncode != 0                 # read-only mount
    assert "`/src/proj-src` (read-only)" in (HOME / "workspaces" / st["id"] / "AIRLOCK_ENV.md").read_text()


def test_agent_uses_the_classic_tui(sess):
    cfg, st = sess
    assert sh(st, "echo $CLAUDE_CODE_DISABLE_ALTERNATE_SCREEN").stdout.strip() == "1"
    cur = json.loads(sh(st, "cat ~/.claude/settings.json").stdout)
    assert cur["tui"] == "default"
    cmd = cur["hooks"]["SessionStart"][0]["hooks"][0]["command"]
    assert "tengu_pewter_brook = false" in cmd and sh(st, "command -v jq").returncode == 0     # the hook's tool is in the image


def test_cleanup_removes_everything(sess):
    cfg, st = sess
    done = session.stop_session(cfg, st["id"])
    assert done["status"] == "stopped"
    names = subprocess.run(["docker", "ps", "-a", "--format", "{{.Names}}"], capture_output=True, text=True).stdout
    assert st["id"] not in names
    nets = subprocess.run(["docker", "network", "ls", "--format", "{{.Name}}"], capture_output=True, text=True).stdout
    assert st["id"] not in nets
