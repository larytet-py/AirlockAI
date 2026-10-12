"""Mode 1 acceptance against a real test node (SPEC 13, 'Mode 1 test node').

Run:  AIRLOCK_CONFIG=local/test-node.yaml uv run pytest -m integration tests/test_acceptance_mode1.py
Needs docker, the airlock-agent image (`airlock image`) and a node tagged env=test.
Set AIRLOCK_ACCEPT_KUBE=1 to also fetch the kube token over ssh from inside the sandbox
and run `kubectl get ns` (this reads the node's token, so it is opt-in).
"""
import os
import subprocess

import pytest

from airlock import nodeaccess, session
from airlock.config import load_config

pytestmark = pytest.mark.integration
CANARY = "canary-pw-9f3a1c"


@pytest.fixture(scope="module")
def env():
    os.environ["USER_PASSWORD"] = CANARY  # must never reach the agent
    cfg = load_config()
    node = cfg.nodes[0]
    st = session.start_session(cfg, [node.name], model_login=False)
    yield cfg, node, st
    if session.load_state(st["id"])["status"] not in ("stopped",):
        session.stop_session(cfg, st["id"])


def sh(st, cmd, timeout=60):
    return session.exec_in(st["id"], "sh", "-c", cmd, timeout=timeout)


def test_ssh_and_passwordless_sudo(env):
    cfg, node, st = env
    assert sh(st, f"ssh {node.name} hostname").returncode == 0
    r = sh(st, f"ssh {node.name} sudo -n id -u")
    assert r.returncode == 0 and r.stdout.strip() == "0", r.stderr
    assert sh(st, f"airlock-run {node.name} -- hostname").returncode == 0


def test_only_model_api_and_nodes_reachable(env):
    cfg, node, st = env
    assert sh(st, "curl -sS -m 8 https://example.com").returncode != 0
    assert sh(st, "curl -sS -m 8 --noproxy '*' https://example.com").returncode != 0
    assert sh(st, "curl -sS -m 8 --noproxy '*' http://1.1.1.1").returncode != 0
    assert sh(st, "ssh -o BatchMode=yes -o ConnectTimeout=6 -o StrictHostKeyChecking=no "
                  "-o ProxyCommand='nc -X connect -x egress:3128 %h %p' root@1.1.1.1 true").returncode != 0
    assert sh(st, f"nc -z -w 5 {st['ips'][node.name]} 22").returncode != 0           # no direct route to the node
    for u in node.urls.values():                                                       # web/docs are not on the allowlist
        assert sh(st, f"curl -sS -m 8 {u}").returncode != 0
    r = sh(st, "curl -sS -m 15 -o /dev/null -w '%{http_code}' https://api.anthropic.com/")
    assert r.returncode == 0 and r.stdout.strip() != "403", r.stderr             # model API goes through


def test_agent_container_has_no_secrets_and_is_hardened(env):
    cfg, node, st = env
    ag = f"air-agent-{st['id']}"
    assert CANARY not in sh(st, "env; cat /proc/*/environ 2>/dev/null | tr '\\0' '\\n'").stdout
    assert "USER_PASSWORD" not in sh(st, "env").stdout
    assert sh(st, f"grep -rIl {CANARY} /workspace /airlock /home/agent 2>/dev/null").stdout.strip() == ""
    assert sh(st, "ls /var/run/docker.sock").returncode != 0
    info = subprocess.run(["docker", "inspect", ag, "--format",
                           "{{.HostConfig.ReadonlyRootfs}} {{.HostConfig.CapDrop}} {{.HostConfig.Privileged}} {{.HostConfig.SecurityOpt}}"],
                          capture_output=True, text=True).stdout
    assert info.startswith("true [ALL] false") and "no-new-privileges" in info
    assert sh(st, "touch /etc/x").returncode != 0                                      # read-only rootfs


def test_instructions_file_lists_node_and_mode(env):
    cfg, node, st = env
    md = sh(st, "cat /workspace/AIRLOCK_NODES.md").stdout
    assert node.name in md and "airlock-run" in md


def test_kubectl_on_the_node_from_the_sandbox(env):
    """The node has its own kubectl: the agent drives it over ssh, no token leaves the node."""
    cfg, node, st = env
    r = sh(st, f"airlock-run {node.name} -- kubectl -n app get pods", timeout=90)
    assert r.returncode == 0 and "NAME" in r.stdout, r.stderr
    r = sh(st, f"ssh {node.name} ls /")
    assert r.returncode == 0 and r.stdout.strip(), r.stderr


@pytest.mark.skipif(not os.environ.get("AIRLOCK_ACCEPT_KUBE"), reason="opt-in: reads the node's kube token")
def test_kubectl_get_ns_with_token_over_ssh(env):
    cfg, node, st = env
    script = (f"T=$(ssh {node.name} cat /etc/kubernetes/remote-token) && "
              f"kubectl --server {node.kube.server} --token \"$T\" get ns")
    r = sh(st, script, timeout=90)
    assert r.returncode == 0 and "default" in r.stdout, r.stderr


def test_zz_cleanup_after_stop(env):
    cfg, node, st = env
    assert nodeaccess.access_state(node, st["id"]) == "key_lines=1 sudoers=yes"   # the check must be able to see it
    done = session.stop_session(cfg, st["id"])
    assert done["status"] == "stopped", done["needs_cleanup"]
    assert nodeaccess.access_state(node, st["id"]) == "key_lines=0 sudoers=no"
    names = subprocess.run(["docker", "ps", "-a", "--format", "{{.Names}}"], capture_output=True, text=True).stdout
    assert st["id"] not in names
    nets = subprocess.run(["docker", "network", "ls", "--format", "{{.Name}}"], capture_output=True, text=True).stdout
    assert st["id"] not in nets
    assert not list((session.SESSIONS / st["id"]).glob("id_ed25519*"))
    assert session.Audit(st["id"]).verify()


def test_sweeper_removes_orphaned_markers(env, tmp_path):
    """A session that vanished (controller crash) leaves a key and sudoers rule; the sweeper removes both."""
    cfg, node, _ = env
    sid = "feedface"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(tmp_path / "k")], check=True)
    acc = nodeaccess.enable_access(node, sid, (tmp_path / "k.pub").read_text(), str(tmp_path / "k"))
    assert acc.ready, acc.detail
    assert nodeaccess.access_state(node, sid) == "key_lines=1 sudoers=yes"
    assert session.sweep(cfg).get(node.name) == [sid]
    assert nodeaccess.access_state(node, sid) == "key_lines=0 sudoers=no"


def test_browser_terminal_over_websocket():
    """The UI's websocket attaches to the agent container: typed input runs inside the sandbox."""
    from starlette.testclient import TestClient
    from starlette.websockets import WebSocketDisconnect

    from airlock.ui import make_app
    cfg = load_config()
    node = cfg.nodes[0]
    st = session.start_session(cfg, [node.name], model_login=False)
    try:
        c = TestClient(make_app(), base_url="http://127.0.0.1:8800")
        assert "xterm" in c.get(f"/sessions/{st['id']}/term").text
        with pytest.raises(WebSocketDisconnect):  # cross-site origin refused
            with c.websocket_connect(f"/sessions/{st['id']}/ws", headers={"origin": "https://evil.example"}) as ws:
                ws.receive_bytes()
        with c.websocket_connect(f"/sessions/{st['id']}/ws", headers={"origin": "http://127.0.0.1:8800"}) as ws:
            ws.send_text('{"resize":[100,30]}')
            ws.send_bytes(b"echo AIR-$((40+2)); hostname; exit\n")
            buf = b""
            try:
                while b"AIR-42" not in buf:
                    buf += ws.receive_bytes()
            except WebSocketDisconnect:
                pass
        assert b"AIR-42" in buf
    finally:
        session.stop_session(cfg, st["id"])


def test_delete_of_a_running_session_stops_it_and_leaves_the_node_clean():
    """Group delete on a running session: stop first (key and sudoers rule revoked), then the record is removed."""
    cfg = load_config()
    node = cfg.nodes[0]
    st = session.start_session(cfg, [node.name], model_login=False)
    sid = st["id"]
    try:
        assert nodeaccess.access_state(node, sid) == "key_lines=1 sudoers=yes"
        assert session.delete_many([sid], cfg) == [sid]
    finally:
        if session.state_path(sid).exists():
            session.stop_session(cfg, sid)
    assert nodeaccess.access_state(node, sid) == "key_lines=0 sudoers=no"              # nothing left on the node
    assert not session.state_path(sid).exists()                                         # record gone
    names = subprocess.run(["docker", "ps", "-a", "--format", "{{.Names}}"], capture_output=True, text=True).stdout
    nets = subprocess.run(["docker", "network", "ls", "--format", "{{.Name}}"], capture_output=True, text=True).stdout
    assert sid not in names and sid not in nets
