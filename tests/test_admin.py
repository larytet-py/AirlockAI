"""Node add/remove/edit write-back, labels, session delete."""
import json

import pytest

from airlock import config as C
from airlock import session

BASE = """# my nodes
version: 1
nodes:
  # the API box
  - {name: JohnTestApi, host: 10.0.1.11, exec: {mode: ssh}}
  - {name: JaneTestGateway, host: 10.0.1.12}
"""


@pytest.fixture
def cfgfile(tmp_path, monkeypatch):
    p = tmp_path / "airlock.yaml"
    p.write_text(BASE)
    monkeypatch.setattr(session, "SESSIONS", tmp_path / "sessions")
    return p


def test_add_node_preserves_comments_and_validates(cfgfile):
    C.add_node(cfgfile, C.node_spec("BobTestOrders", "10.0.1.13", mode="ssh_sudo"))
    text = cfgfile.read_text()
    assert "# my nodes" in text and "# the API box" in text           # comments survive
    n = C.load_config(cfgfile).node("BobTestOrders")
    assert n.exec.mode == "ssh_sudo"


def test_bad_changes_are_refused_and_file_untouched(cfgfile):
    before = cfgfile.read_text()
    with pytest.raises(C.ConfigError, match="already exists"):
        C.add_node(cfgfile, C.node_spec("JohnTestApi", "x"))
    with pytest.raises(C.ConfigError):
        C.add_node(cfgfile, C.node_spec("bad name!", "x"))
    with pytest.raises(C.ConfigError):
        C.add_node(cfgfile, {"name": "Z", "host": "h", "exec": {"mode": "ssh", "sudo_password": "hunter2"}})
    with pytest.raises(C.ConfigError):
        C.set_exec_mode(cfgfile, "JohnTestApi", "telnet")
    assert cfgfile.read_text() == before
    assert not list(cfgfile.parent.glob("*tmp*"))                      # no temp files left behind


def test_remove_and_mode_change(cfgfile):
    C.set_exec_mode(cfgfile, "JohnTestApi", "ssh_sudo")
    assert C.load_config(cfgfile).node("JohnTestApi").exec.mode == "ssh_sudo"
    C.remove_node(cfgfile, "JaneTestGateway")
    assert [n.name for n in C.load_config(cfgfile).nodes] == ["JohnTestApi"]
    with pytest.raises(C.ConfigError, match="not defined"):
        C.remove_node(cfgfile, "Ghost")


def test_labels_single_and_bulk(cfgfile):
    C.edit_meta(cfgfile, ["JohnTestApi", "JaneTestGateway"], add_labels=["emea", "gw"])
    assert all(n.labels == ["emea", "gw"] for n in C.load_config(cfgfile).nodes)
    C.edit_meta(cfgfile, ["JohnTestApi"], remove_labels=["gw"])
    assert C.load_config(cfgfile).node("JohnTestApi").labels == ["emea"]
    C.edit_meta(cfgfile, ["JohnTestApi"], replace_labels=[])
    assert C.load_config(cfgfile).node("JohnTestApi").labels == []
    with pytest.raises(C.ConfigError):
        C.edit_meta(cfgfile, [])


def test_old_config_files_with_tags_still_load_and_tags_are_dropped(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text("version: 1\nnodes:\n  - {name: N, host: h, tags: {env: test, aws_instance_id: i-0aaaaaaaa, aws_region: eu-west-1}}\n")
    n = C.load_config(p).node("N")
    assert not hasattr(n, "tags") and n.instance_id == "i-0aaaaaaaa" and n.region == "eu-west-1"   # EC2 id/region moved to fields


def test_included_node_cannot_be_edited_here(tmp_path, cfgfile):
    (tmp_path / "extra.yaml").write_text("nodes:\n  - {name: Inc, host: h}\n")
    cfgfile.write_text(BASE.replace("nodes:", "include: ['extra.yaml']\nnodes:", 1))
    with pytest.raises(C.ConfigError, match="not defined in this file"):
        C.remove_node(cfgfile, "Inc")


def test_json_config_supported(tmp_path):
    p = tmp_path / "c.json"
    p.write_text(json.dumps({"version": 1, "nodes": [{"name": "A", "host": "h"}]}))
    C.add_node(p, C.node_spec("B", "h2"))
    assert [n.name for n in C.load_config(p).nodes] == ["A", "B"]


def fake_session(sid, status, nodes=("JohnTestApi",), tmp=None):
    d = session.SESSIONS / sid
    d.mkdir(parents=True)
    ws = tmp / f"ws-{sid}"
    ws.mkdir()
    (ws / "AIRLOCK_NODES.md").write_text("x")
    session.save_state({"id": sid, "status": status, "nodes": list(nodes), "workspace": str(ws)})
    return d, ws


def test_session_delete_only_when_stopped(cfgfile, tmp_path):
    d, ws = fake_session("aaaaaa11", "stopped", tmp=tmp_path)
    fake_session("bbbbbb22", "running", tmp=tmp_path)
    fake_session("cccccc33", "needs_cleanup", tmp=tmp_path)
    for sid in ("bbbbbb22", "cccccc33"):
        with pytest.raises(C.ConfigError, match="stop it first"):
            session.delete_session(sid)
    session.delete_session("aaaaaa11")
    assert not d.exists() and not ws.exists()
    assert (session.SESSIONS / "bbbbbb22").exists()


def test_prune_removes_only_stopped(cfgfile, tmp_path):
    fake_session("aaaaaa11", "stopped", tmp=tmp_path)
    fake_session("aaaaaa22", "stopped", tmp=tmp_path)
    fake_session("bbbbbb22", "running", tmp=tmp_path)
    assert sorted(session.prune_sessions()) == ["aaaaaa11", "aaaaaa22"]
    assert [s["id"] for s in session.list_sessions()] == ["bbbbbb22"]


def test_node_in_use_cannot_be_removed(cfgfile, tmp_path):
    fake_session("bbbbbb22", "running", tmp=tmp_path)
    with pytest.raises(C.ConfigError, match="stop sessions first"):
        session.remove_node_checked(cfgfile, "JohnTestApi")
    session.edit_meta_checked(cfgfile, ["JohnTestApi"], add_labels=["ok"])      # labels are harmless
    session.remove_node_checked(cfgfile, "JaneTestGateway")                      # unrelated node is free


def test_ui_flows(cfgfile, tmp_path, monkeypatch):
    from starlette.testclient import TestClient

    import airlock.ui as ui

    from airlock.ui import make_app
    c = TestClient(make_app(str(cfgfile)), base_url="http://127.0.0.1:8800", follow_redirects=True)
    assert "JohnTestApi" in c.get("/").text
    c.post("/nodes", data={"name": "UiNode", "host": "10.9.9.9", "mode": "ssh"})
    assert C.load_config(cfgfile).node("UiNode").host == "10.9.9.9"
    assert "name=tags" not in c.get("/").text                                  # no tags field in the add-node form
    r = c.post("/nodes", data={"name": "UiNode", "host": "x"})
    assert "already exists" in r.text                                        # refusal is shown, not a stack trace
    assert "/meta" not in c.get("/").text and "Tags and labels" not in c.get("/").text and "Apply tags" not in c.get("/").text   # no tag editor in the UI
    assert c.post("/nodes/UiNode/meta", data={"tags": "x=1"}).status_code in (404, 405)
    c.post("/nodes/UiNode/mode", data={"mode": "ssh_sudo"})
    assert C.load_config(cfgfile).node("UiNode").exec.mode == "ssh_sudo"
    c.post("/nodes/bulk-delete", data={"sel": ["UiNode"]})
    assert "UiNode" not in [n.name for n in C.load_config(cfgfile).nodes]
    assert c.post("/nodes/UiNode/remove").status_code in (404, 405)       # no single-delete route any more
    fake_session("aaaaaa11", "stopped", tmp=tmp_path)
    assert "aaaaaa11" in c.get("/").text
    assert c.post("/sessions/aaaaaa11/delete").status_code in (404, 405)
    c.post("/sessions/bulk-delete", data={"ssel": ["aaaaaa11"]})
    assert "aaaaaa11" not in c.get("/").text


class FakeProc:
    def __init__(self, stdout=""):
        self.stdout, self.stderr, self.returncode = stdout, "", 0


def test_session_stats_reports_real_container_state(cfgfile, tmp_path, monkeypatch):
    d, ws = fake_session("aaaaaa11", "running", tmp=tmp_path)
    (ws / "big.bin").write_bytes(b"x" * 3000)
    fake_session("bbbbbb22", "running", tmp=tmp_path)       # state says running, container is gone
    fake_session("cccccc33", "stopped", tmp=tmp_path)

    def fake_docker(*args, **kw):
        if args[0] == "inspect":
            return FakeProc("/air-agent-aaaaaa11 true\n/air-egress-aaaaaa11 true\n/air-egress-bbbbbb22 false\n")
        if args[0] == "stats":
            assert args[-1] == "air-agent-aaaaaa11"          # only live containers are queried
            return FakeProc("air-agent-aaaaaa11|3.20%|120.5MiB / 15.5GiB\n")
        raise AssertionError(args)
    monkeypatch.setattr(session, "docker", fake_docker)
    st = session.session_stats()
    assert st["aaaaaa11"]["running"] and st["aaaaaa11"]["cpu"] == "3.20%" and st["aaaaaa11"]["mem"] == "120.5MiB"
    assert st["aaaaaa11"]["workspace"].endswith("KB") and st["aaaaaa11"]["egress_up"]
    assert not st["bbbbbb22"]["running"] and st["bbbbbb22"]["cpu"] == "-"
    assert not st["cccccc33"]["running"]


def test_delete_many_deletes_stopped_and_reports_running(cfgfile, tmp_path):
    fake_session("aaaaaa11", "stopped", tmp=tmp_path)
    fake_session("aaaaaa22", "stopped", tmp=tmp_path)
    fake_session("bbbbbb22", "running", tmp=tmp_path)
    with pytest.raises(C.ConfigError, match=r"deleted 2; not deleted.*bbbbbb22 \(running\)"):
        session.delete_many(["aaaaaa11", "bbbbbb22", "aaaaaa22"])
    assert [s["id"] for s in session.list_sessions()] == ["bbbbbb22"]
    with pytest.raises(C.ConfigError, match="at least one"):
        session.delete_many([])


def test_ui_group_delete_and_stats_endpoint(cfgfile, tmp_path, monkeypatch):
    from starlette.testclient import TestClient

    import airlock.ui as ui
    monkeypatch.setattr(session, "session_stats", lambda: {"aaaaaa11": {"running": False, "cpu": "-", "mem": "-", "workspace": "1 KB"}})
    stopped = []

    def fake_stop(cfg, sid):
        stopped.append(sid)
        st = session.load_state(sid)
        st["status"] = "stopped"
        session.save_state(st)
        return st
    monkeypatch.setattr(session, "stop_session", fake_stop)
    for sid in ("aaaaaa11", "aaaaaa22", "aaaaaa33"):
        fake_session(sid, "stopped", tmp=tmp_path)
    fake_session("bbbbbb22", "running", tmp=tmp_path)
    c = TestClient(ui.make_app(str(cfgfile)), base_url="http://127.0.0.1:8800", follow_redirects=True)
    page = c.get("/").text
    assert page.count('name=ssel value=') == 4 and 'id=all' in page and "Delete selected" in page and "data-f=cpu" in page
    assert c.get("/api/sessions/stats").json()["aaaaaa11"]["workspace"] == "1 KB"
    c.post("/sessions/bulk-delete", data={"ssel": ["aaaaaa11", "aaaaaa22", "bbbbbb22"]})
    assert stopped == ["bbbbbb22"]                                           # the running one was stopped first, then deleted
    assert [s["id"] for s in session.list_sessions()] == ["aaaaaa33"]
    assert "at least one" in c.post("/sessions/bulk-delete", data={}).text
    assert c.post("/sessions/bulk-delete", data={"ssel": ["../x"]}, follow_redirects=False).status_code == 404


LOADAVG = """2.79 3.38 3.44 4/1873 24348
CORES 8
Filesystem 1024-blocks Used Available Capacity Mounted on
/dev/nvme0n1p1 209612800 83886080 125726720 41% /
/dev/nvme1n1 524288000 52428800 471859200 10% /data
"""


def test_nodestats_parse():
    from airlock import nodestats
    r = nodestats.parse(LOADAVG)
    assert r["load1"] == 2.79 and r["cores"] == 8
    assert [(d["mount"], d["pct"]) for d in r["disks"]] == [("/", "41%"), ("/data", "10%")]
    assert r["disks"][0]["used"] == 83886080 * 1024
    same = LOADAVG.replace("/dev/nvme1n1 524288000", "/dev/nvme0n1p1 209612800")   # /data on the same filesystem as /
    assert len(nodestats.parse(same)["disks"]) == 1
    assert nodestats.parse("garbage\n") == {"load1": None, "cores": None, "disks": []}


def test_nodestats_collect_caches_and_reports_failures(cfgfile, monkeypatch):
    from airlock import nodestats, runner
    monkeypatch.setenv("USER_NAME", "alice")
    monkeypatch.setenv("USER_PASSWORD", "pw")
    nodestats._cache.clear()
    calls = []

    def fake_run(ex, argv, **kw):
        calls.append(ex.host)
        if ex.host == "10.0.1.12":
            return runner.Result(255, "", "ssh: connect to host 10.0.1.12 port 22: Connection timed out")
        return runner.Result(0, LOADAVG, "")
    monkeypatch.setattr(runner, "run", fake_run)
    nodes = C.load_config(cfgfile).nodes
    r = nodestats.collect(nodes)
    assert r["JohnTestApi"]["up"] and r["JohnTestApi"]["load1"] == 2.79
    assert not r["JaneTestGateway"]["up"] and "timed out" in r["JaneTestGateway"]["error"]
    nodestats.collect(nodes)
    assert len(calls) == 2                       # second call served from the 15 s cache


def test_nodestats_fixed_command_has_no_newlines():
    from airlock import nodestats, runner
    runner.check_args(nodestats.CMD)


def test_ui_nodes_page_has_checkboxes_links_and_no_delete_buttons(cfgfile, monkeypatch):
    from starlette.testclient import TestClient

    import airlock.ui as ui
    from airlock import nodestats
    cfgfile.write_text(BASE.replace("{name: JohnTestApi,", "{name: JohnTestApi, notes: 'dev instance #1', urls: {web: 'https://w.example', docs: 'javascript:alert(1)'},", 1))
    monkeypatch.setattr(nodestats, "collect", lambda nodes: {n.name: {"up": True, "load1": 1.0, "cores": 4, "disks": []} for n in nodes})
    c = TestClient(ui.make_app(str(cfgfile)), base_url="http://127.0.0.1:8800")
    page = c.get("/").text
    assert 'href="https://w.example"' in page and "javascript:alert" not in page     # only http(s) links are rendered
    assert 'href="ssh://10.0.1.11"' in page and "dev instance #1" in page
    assert page.count("name=sel value=") == 2 and "Delete selected" in page
    assert ">Remove<" not in page and ">Delete<" not in page                          # no per-row delete buttons
    assert c.get("/api/nodes/stats").json()["JohnTestApi"]["load1"] == 1.0


def test_remove_nodes_checked_skips_busy(cfgfile, tmp_path):
    fake_session("bbbbbb22", "running", tmp=tmp_path)
    with pytest.raises(C.ConfigError, match=r"deleted 1; not deleted .*JohnTestApi \(session bbbbbb22\)"):
        session.remove_nodes_checked(cfgfile, ["JohnTestApi", "JaneTestGateway"])
    assert [n.name for n in C.load_config(cfgfile).nodes] == ["JohnTestApi"]
    with pytest.raises(C.ConfigError, match="at least one"):
        session.remove_nodes_checked(cfgfile, [])


def test_start_buttons_live_in_node_rows(cfgfile, monkeypatch):
    from starlette.testclient import TestClient

    import airlock.ui as ui
    from airlock import nodestats
    monkeypatch.setattr(nodestats, "collect", lambda nodes: {})
    started = []
    monkeypatch.setattr(session, "start_session", lambda cfg, names, **kw: started.append(list(names)) or {"id": "x"})
    c = TestClient(ui.make_app(str(cfgfile)), base_url="http://127.0.0.1:8800", follow_redirects=True)
    page = c.get("/").text
    assert "Start Sandbox session" not in page                                   # the old section is gone
    for n in ("JohnTestApi", "JaneTestGateway"):                                  # one Start form per node row
        assert f'<input type=hidden name=nodes value="{n}">' in page
    assert page.count(">Start</button>") == 2 and "Start session on selected" in page
    c.post("/sessions", data={"nodes": "JohnTestApi"})                            # row button: one node
    c.post("/sessions", data={"sel": ["JohnTestApi", "JaneTestGateway"]})         # selected rows: one session on both
    assert started == [["JohnTestApi"], ["JohnTestApi", "JaneTestGateway"]]
    assert "at least one node" in c.post("/sessions", data={}).text


def test_start_failure_is_shown_not_a_500(cfgfile, monkeypatch):
    from starlette.testclient import TestClient

    import airlock.ui as ui
    from airlock import nodestats
    monkeypatch.setattr(nodestats, "collect", lambda nodes: {})

    def boom(cfg, names, **kw):
        raise RuntimeError("JohnTestApi: authorized_keys step failed: Permission denied")
    monkeypatch.setattr(session, "start_session", boom)
    c = TestClient(ui.make_app(str(cfgfile)), base_url="http://127.0.0.1:8800", follow_redirects=True)
    r = c.post("/sessions", data={"nodes": "JohnTestApi"})
    assert r.status_code == 200 and "Permission denied" in r.text


def test_rename_node_validates_preserves_comments_and_refuses_duplicates(cfgfile):
    C.rename_node(cfgfile, "JohnTestApi", "JohnApi-2")
    assert "# the API box" in cfgfile.read_text()
    assert [n.name for n in C.load_config(cfgfile).nodes] == ["JohnApi-2", "JaneTestGateway"]
    assert C.load_config(cfgfile).node("JohnApi-2").host == "10.0.1.11"             # everything else is untouched
    before = cfgfile.read_text()
    for new, why in (("JaneTestGateway", "already exists"), ("bad name!", "must match"), ("", "must match"), ("../x", "must match")):
        with pytest.raises(C.ConfigError, match=why):
            C.rename_node(cfgfile, "JohnApi-2", new)
    with pytest.raises(C.ConfigError, match="not defined"):
        C.rename_node(cfgfile, "Ghost", "Whatever")
    assert cfgfile.read_text() == before
    C.rename_node(cfgfile, "JohnApi-2", "JohnApi-2")                                  # same name is a no-op, not an error


def test_rename_carries_running_sessions_along(cfgfile, tmp_path, monkeypatch):
    monkeypatch.setenv("USER_NAME", "alice")
    monkeypatch.setattr(session, "KNOWN_HOSTS", tmp_path / "kh")
    d, ws = fake_session("bbbbbb22", "running", tmp=tmp_path)
    st = session.load_state("bbbbbb22")
    st.update({"ips": {"JohnTestApi": "10.0.1.11"}, "access": {"JohnTestApi": {"expires": 1}},
               "node_specs": {"JohnTestApi": {"name": "JohnTestApi", "host": "10.0.1.11"}}})
    session.save_state(st)
    session.rename_node_checked(cfgfile, "JohnTestApi", "JohnRenamed")
    st = session.load_state("bbbbbb22")
    assert st["nodes"] == ["JohnRenamed"] and st["ips"] == {"JohnRenamed": "10.0.1.11"}
    assert "JohnRenamed" in st["access"] and st["node_specs"]["JohnRenamed"]["name"] == "JohnRenamed"
    assert "Host JohnRenamed" in (d / "ssh_config").read_text()                      # what the agent reads is regenerated
    assert "JohnRenamed" in (ws / "AIRLOCK_NODES.md").read_text() and "JohnTestApi" not in (ws / "AIRLOCK_NODES.md").read_text()
    assert session.sessions_using("JohnRenamed") == ["bbbbbb22"] and session.sessions_using("JohnTestApi") == []


def test_rename_waits_for_a_starting_session_and_rolls_back_on_failure(cfgfile, tmp_path, monkeypatch):
    fake_session("cccccc33", "starting", tmp=tmp_path)
    with pytest.raises(C.ConfigError, match="starting or stopping"):
        session.rename_node_checked(cfgfile, "JohnTestApi", "X")
    assert "JohnTestApi" in [n.name for n in C.load_config(cfgfile).nodes]
    fake_session("bbbbbb22", "running", tmp=tmp_path)
    session.save_state({**session.load_state("cccccc33"), "status": "stopped"})
    real = session.save_state
    monkeypatch.setattr(session, "save_state", lambda st: (_ for _ in ()).throw(OSError("disk full")))
    with pytest.raises(OSError):
        session.rename_node_checked(cfgfile, "JohnTestApi", "Y")
    monkeypatch.setattr(session, "save_state", real)
    assert "JohnTestApi" in [n.name for n in C.load_config(cfgfile).nodes]            # config rolled back to match the sessions


def test_stop_revokes_access_via_snapshot_when_node_is_gone_from_config(cfgfile, tmp_path, monkeypatch):
    from airlock import nodeaccess
    fake_session("bbbbbb22", "running", tmp=tmp_path)
    st = session.load_state("bbbbbb22")
    st["node_specs"] = {"JohnTestApi": {"name": "JohnTestApi", "host": "10.0.1.11"}}
    session.save_state(st)
    revoked = []
    monkeypatch.setattr(nodeaccess, "revoke_access", lambda node, sid, audit=None: revoked.append((node.host, sid)) or (True, ""))
    monkeypatch.setattr(session, "docker", lambda *a, **k: FakeProc())
    monkeypatch.setattr(session, "Audit", lambda sid: type("A", (), {"log": lambda *a, **k: None})())
    cfg = C.Config.model_validate({"version": 1})                                    # node no longer in the config
    assert session.stop_session(cfg, "bbbbbb22")["status"] == "stopped"
    assert revoked == [("10.0.1.11", "bbbbbb22")]


def test_nodestats_includes_ip_even_when_down(cfgfile, monkeypatch):
    from airlock import nodestats, runner
    nodestats._cache.clear()
    cfg = C.load_config(cfgfile)
    cfg.nodes[0].host = "node.example.com"
    monkeypatch.setattr(nodestats.socket, "gethostbyname", lambda h: "192.0.2.10")
    monkeypatch.setattr(runner, "run", lambda ex, argv, **kw: runner.Result(255, "", "ssh: connection refused"))
    r = nodestats.collect(cfg.nodes[:1])["JohnTestApi"]
    assert not r["up"] and r["ip"] == "192.0.2.10" and r["host"] == "node.example.com" and r["port"] == 22
    assert nodestats.resolve_ip("10.0.1.11") == "10.0.1.11"                          # literals are not looked up
    monkeypatch.setattr(nodestats.socket, "gethostbyname", lambda h: (_ for _ in ()).throw(OSError("nxdomain")))
    assert nodestats.resolve_ip("nope.invalid") is None


def test_ui_name_is_click_to_rename_and_status_is_one_group(cfgfile, monkeypatch):
    import re

    from starlette.testclient import TestClient

    import airlock.ui as ui
    from airlock import nodestats
    monkeypatch.setattr(nodestats, "collect", lambda nodes: {})
    c = TestClient(ui.make_app(str(cfgfile)), base_url="http://127.0.0.1:8800", follow_redirects=True)
    page = c.get("/").text
    assert 'class=nm title="Click to rename" onclick="rn(this)">JohnTestApi' in page
    assert 'action="/nodes/JohnTestApi/rename"' in page and "Escape" in page and "Enter" in page
    wrap = re.search(r'<div class=nmwrap>.*?</div>', page, re.S).group(0)
    assert "<button" not in wrap                                                  # no Save/Cancel buttons: Enter saves, blur/Escape cancels
    assert "[hidden]{display:none!important}" in page.split("</style>")[0]       # form{display:inline} must not defeat `hidden`
    row = re.search(r'<tr data-node="JohnTestApi">.*?</tr>', page, re.S).group(0)
    cells = re.split(r"<td>", row)
    status = next(x for x in cells if "data-n=ip" in x)
    assert all(k in status for k in ("data-n=dot", "data-n=ip", "data-n=load", "data-n=disk"))   # all status in one cell
    assert "max-width" not in page.split("</style>")[0]                                          # uses the full wide screen
    c.post("/nodes/JohnTestApi/rename", data={"new": "JohnRenamed"})
    assert "JohnRenamed" in [n.name for n in C.load_config(cfgfile).nodes]
    assert "already exists" in c.post("/nodes/JohnRenamed/rename", data={"new": "JaneTestGateway"}).text
    assert "must match" in c.post("/nodes/JohnRenamed/rename", data={"new": "bad name"}).text


def test_terminal_page_takes_focus_by_itself(cfgfile, tmp_path):
    from starlette.testclient import TestClient

    import airlock.ui as ui
    fake_session("aaaaaa11", "running", tmp=tmp_path)
    page = TestClient(ui.make_app(str(cfgfile)), base_url="http://127.0.0.1:8800").get("/sessions/aaaaaa11/term").text
    assert page.count("term.focus()") >= 4 and "addEventListener('load'" in page and "addEventListener('focus'" in page
    assert "pending.push(d)" in page and "pending.splice(0)" in page                 # early keystrokes are queued, not dropped


def test_session_actions_sit_right_after_the_container_column(cfgfile, tmp_path, monkeypatch):
    import re

    from starlette.testclient import TestClient

    import airlock.ui as ui
    from airlock import nodestats
    monkeypatch.setattr(nodestats, "collect", lambda nodes: {})
    fake_session("bbbbbb22", "running", tmp=tmp_path)
    page = TestClient(ui.make_app(str(cfgfile)), base_url="http://127.0.0.1:8800").get("/").text
    head = re.search(r'<table id=sess><tr>(.*?)</tr>', page, re.S).group(1)
    cols = [re.sub(r"<[^>]+>", "", c).strip() for c in head.split("<th>")[1:]]
    assert cols[:5] == ["", "ID", "Status", "Container", "Actions"] and cols[-1] == "Allowlist"
    row = re.search(r'<tr data-sid="bbbbbb22".*?</tr>', page, re.S).group(0)
    cells = row.split("<td")[1:]
    assert "data-f=container" in cells[3] and "/term" in cells[4] and "Stop" not in cells[4]   # shell, claude follow Container; stopping is "Stop selected" only
    assert "data-f=cpu" in cells[5]


def test_delete_many_stops_running_sessions_first(cfgfile, tmp_path, monkeypatch):
    fake_session("aaaaaa11", "stopped", tmp=tmp_path)
    fake_session("bbbbbb22", "running", tmp=tmp_path)
    order = []

    def fake_stop(cfg, sid):
        order.append(("stop", sid))
        st = session.load_state(sid)
        st["status"] = "stopped"
        session.save_state(st)
        return st
    monkeypatch.setattr(session, "stop_session", fake_stop)
    real_delete = session.delete_session
    monkeypatch.setattr(session, "delete_session", lambda sid: (order.append(("delete", sid)), real_delete(sid))[1])
    session.delete_many(["aaaaaa11", "bbbbbb22"], C.load_config(cfgfile))
    assert order == [("delete", "aaaaaa11"), ("stop", "bbbbbb22"), ("delete", "bbbbbb22")]      # stop always precedes delete
    assert session.list_sessions() == []


def test_failed_node_cleanup_keeps_the_session_record(cfgfile, tmp_path, monkeypatch):
    fake_session("bbbbbb22", "running", tmp=tmp_path)

    def stuck_stop(cfg, sid):
        st = session.load_state(sid)
        st.update(status="needs_cleanup", needs_cleanup=[{"node": "JohnTestApi", "error": "ssh: connection timed out"}])
        session.save_state(st)
        return st
    monkeypatch.setattr(session, "stop_session", stuck_stop)
    with pytest.raises(C.ConfigError, match=r"cleanup on the node failed.*connection timed out.*still there"):
        session.delete_many(["bbbbbb22"], C.load_config(cfgfile))
    assert session.load_state("bbbbbb22")["status"] == "needs_cleanup"                         # the record survives so Stop can be retried


def test_error_banner_stays_visible_and_confirm_mentions_stopping(cfgfile, monkeypatch):
    from starlette.testclient import TestClient

    import airlock.ui as ui
    from airlock import nodestats
    monkeypatch.setattr(nodestats, "collect", lambda nodes: {})
    page = TestClient(ui.make_app(str(cfgfile)), base_url="http://127.0.0.1:8800").get("/").text
    css = page.split("</style>")[0]
    assert ".err{color:#d33;position:sticky;top:0" in css and ".err:empty{display:none}" in css
    assert "Running ones are stopped first" in page


def test_terminal_links_open_in_a_new_tab_and_tabs_are_titled(cfgfile, tmp_path, monkeypatch):
    import re

    from starlette.testclient import TestClient

    import airlock.ui as ui
    from airlock import nodestats
    monkeypatch.setattr(nodestats, "collect", lambda nodes: {})
    fake_session("bbbbbb22", "running", tmp=tmp_path)
    c = TestClient(ui.make_app(str(cfgfile)), base_url="http://127.0.0.1:8800")
    page = c.get("/").text
    for label in ("shell", "claude"):
        a = re.search(rf'<a [^>]*>{label}</a>', page).group(0)
        assert "target=_blank" in a and "rel=noopener" in a, a                    # new tab, and no window.opener back-reference
    assert "<title>claude bbbbbb22</title>" in c.get("/sessions/bbbbbb22/term?cmd=claude").text
    assert "<title>shell bbbbbb22</title>" in c.get("/sessions/bbbbbb22/term").text


def test_discard_session_forces_removal_of_a_stuck_session(cfgfile, tmp_path, monkeypatch):
    from airlock import audit
    monkeypatch.setattr(audit, "HOME", tmp_path)                 # the audit line must not land in the real ~/.airlock
    removed = []
    monkeypatch.setattr(session, "docker", lambda *a, **k: removed.append(a))
    monkeypatch.setattr(session.sshaccess, "write_config", lambda *a, **k: None)
    monkeypatch.setattr(session, "HOME", tmp_path)
    d, ws = fake_session("dddddd44", "needs_cleanup", tmp=tmp_path)
    st = session.load_state("dddddd44")
    st.update({"containers": ["air-agent-dddddd44"], "networks": ["air-dddddd44"],
               "needs_cleanup": [{"node": "JohnTestApi", "error": "No route to host"}]})
    session.save_state(st)
    with pytest.raises(C.ConfigError):
        session.delete_session("dddddd44")                      # the normal path still refuses
    left = session.discard_session("dddddd44")
    assert left == [{"node": "JohnTestApi", "error": "No route to host"}]
    assert not d.exists() and not ws.exists()
    assert ("rm", "-f", "air-agent-dddddd44") in [a[:3] for a in removed] and ("network", "rm", "air-dddddd44") in removed


def test_discard_refuses_a_running_session(cfgfile, tmp_path):
    fake_session("eeeeee55", "running", tmp=tmp_path)
    with pytest.raises(C.ConfigError, match="stop it first"):
        session.discard_session("eeeeee55")
    assert session.state_path("eeeeee55").exists()


def test_removing_every_node_keeps_the_file_valid_and_the_comments(tmp_path, monkeypatch):
    p = tmp_path / "airlock.yaml"
    p.write_text("""version: 1
nodes:
  # Name nodes after owner + environment.
  # Second comment line.
  - {name: A, host: 10.0.0.1}
  - {name: B, host: 10.0.0.2}
integrations:
  # keep me
  aws:
    regions: [us-east-1]
""")
    cfg = C.remove_nodes(p, ["A", "B"])
    text = p.read_text()
    assert cfg.nodes == [] and C.load_config(p).nodes == []
    assert "# Name nodes after owner" in text and "# Second comment line." in text and "# keep me" in text
    assert "nodes: []" in text and "aws:\n    regions: [us-east-1]" in text.replace("\n  ", "\n  ")
    C.add_node(p, C.node_spec("C", "10.0.0.3"))        # and the emptied list can grow again
    assert [n.name for n in C.load_config(p).nodes] == ["C"] and "- " in p.read_text()
