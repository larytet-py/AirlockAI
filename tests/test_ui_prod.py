"""The EC2 / PROD tabs: PROD lists local kubectl clusters, keeps gateway sessions apart, manages patterns and approvals."""
import json

import pytest
from starlette.testclient import TestClient

from airlock import config as C
from airlock import envs, gateway, gwsession, patternstore, session, ui, ui_prod

CFG = """version: 1
defaults:
  links: {logs: "https://logs.example.com/{context}", web: "https://web-{instance_id}.example.com/"}
nodes:
  - {name: JohnTestApi, host: 10.0.1.11}
environments:
  - name: uat
    kube_context: uat-ctx
    exec: {mode: direct}
    tools:
      - kubernetes: {mode: read, namespaces: [app]}
"""


def pg_route(env="uat"):
    """An approved direct Postgres route, as the approval flow stores it."""
    from airlock import access
    patternstore.PatternStore().put_route(access.Route(env=env, kind="postgres", transport="direct", secret="PG_DSN", schemas=["public"]), by="test")


@pytest.fixture
def client(tmp_path, monkeypatch):
    p = tmp_path / "airlock.yaml"
    p.write_text(CFG)
    for mod in (session, gwsession):
        monkeypatch.setattr(mod, "SESSIONS", tmp_path / "sessions")
    monkeypatch.setattr(patternstore, "DB", tmp_path / "db.sqlite")
    monkeypatch.setattr(patternstore, "SNAPSHOT", tmp_path / "patterns" / "snapshot.json")
    monkeypatch.setattr(ui_prod, "HOME", tmp_path)
    monkeypatch.setattr(envs, "HOME", tmp_path)
    monkeypatch.setattr(envs, "kubectl_contexts", lambda timeout=10: ["uat-ctx", "prod-eu", "kind-dev"])
    monkeypatch.setattr(envs, "context_status", lambda c, timeout=8: {"up": c != "prod-eu", "nodes": 3, "ms": 12, "error": "" if c != "prod-eu" else "refused"})
    pg_route()
    c = TestClient(ui.make_app(str(p)), base_url="http://127.0.0.1:8800", follow_redirects=True)
    c.cfg, c.tmp = p, tmp_path
    return c


def fake_session(tmp, sid, mode, status="running", **kw):
    d = tmp / "sessions" / sid
    d.mkdir(parents=True)
    st = {"id": sid, "status": status, "mode": mode, "nodes": [] if mode == "gateway" else ["JohnTestApi"], "workspace": str(tmp / "ws" / sid), **kw}
    (d / "session.json").write_text(json.dumps(st))
    (d / "inbox").mkdir()
    return st


def test_two_tabs_on_the_left_and_choice_is_remembered(client):
    ec2 = client.get("/?tab=ec2").text
    assert 'href="/?tab=ec2"' in ec2 and 'href="/prod"' in ec2 and ">EC2" in ec2 and ">PROD" in ec2
    assert "<h2>Nodes</h2>" in ec2 and "JohnTestApi" in ec2 and "Clusters" not in ec2
    prod = client.get("/prod").text
    assert "<h2>Clusters" in prod and "<h2>Nodes</h2>" not in prod and "JohnTestApi" not in prod
    assert 'class="tab prod on"' in prod and 'class="tab ec2 on"' not in prod
    # the last tab is remembered: "/" now lands on PROD, "/?tab=ec2" goes back
    assert "<h2>Clusters" in client.get("/").text
    assert "<h2>Nodes</h2>" in client.get("/?tab=ec2").text
    assert "<h2>Nodes</h2>" in client.get("/").text


def test_prod_lists_local_kubectl_contexts_not_ec2_nodes(client):
    page = client.get("/prod").text
    assert "uat" in page and "context uat-ctx" in page                        # registered environment
    assert "prod-eu" in page and "kind-dev" in page                           # discovered, not registered
    assert page.count("not registered") == 2
    assert 'href="https://logs.example.com/uat-ctx"' in page                  # {context} link pattern; {instance_id} one is skipped
    clusters = page.split("<h2>Clusters")[1].split("<h2>Claude")[0]
    assert "web-" not in clusters                                              # {instance_id} links are for EC2 rows only
    stats = client.get("/api/prod/stats").json()
    assert stats["uat"]["up"] is True and stats["prod-eu"]["up"] is False and stats["kind-dev"]["nodes"] == 3


def test_no_row_buttons_only_checkboxes_and_bulk_actions(client):
    page = client.get("/prod").text
    bar, rows = page.split("<h2>Clusters")[1].split("<table id=envs>")[0], page.split("<table id=envs>")[1].split("</table>")[0]
    assert "Start session on selected" in bar and "Register selected" in bar and "Remove from list" in bar   # bulk bar sits above the table
    assert "<button" not in rows.replace("<button>Save</button>", "").replace("<button>Set secret</button>", "").replace("<button>Save tools</button>", "")
    assert rows.count("name=ctx") == 2 and 'name=sel value="uat"' in rows
    assert "Start session on selected" in page and "Register selected" in page
    client.post("/prod/register", data={"ctx": ["kind-dev", "prod-eu"]})
    assert {e.name for e in envs.environments(C.load_config(client.cfg))} == {"uat", "kind-dev", "prod-eu"}
    assert "unknown kubectl context" in client.post("/prod/register", data={"ctx": ["nope"]}).text


def test_sessions_are_separated_by_tab(client):
    fake_session(client.tmp, "aaaaaa11", "sandbox")
    fake_session(client.tmp, "bbbbbb22", "gateway", environment="uat", tools=["postgres"])
    ec2, prod = client.get("/?tab=ec2").text, client.get("/prod").text
    assert 'data-sid="aaaaaa11"' in ec2 and 'data-sid="bbbbbb22"' not in ec2
    assert 'data-sid="bbbbbb22"' in prod and 'data-sid="aaaaaa11"' not in prod
    assert '<span class=badge title="running sessions">1</span>' in ec2          # one running session per tab


def test_gateway_sessions_cannot_be_stopped_from_the_ec2_side_by_mistake(client):
    fake_session(client.tmp, "bbbbbb22", "gateway", status="stopped", environment="uat")
    fake_session(client.tmp, "aaaaaa11", "sandbox", status="stopped")
    client.post("/prod/sessions/prune")
    left = {s["id"] for s in session.list_sessions()}
    assert left == {"aaaaaa11"}                                                # PROD prune removes only gateway sessions
    r = client.post("/prod/sessions/bulk-delete", data={"ssel": ["aaaaaa11"]})
    assert r.status_code == 404 and "aaaaaa11" in {s["id"] for s in session.list_sessions()}   # a sandbox session is not deletable from PROD


def test_environment_admin_writes_back_to_the_config(client):
    r = client.post("/prod/register", data={"ctx": ["kind-dev"]})
    cfg = C.load_config(client.cfg)
    e = envs.environment(cfg, "kind-dev")
    assert e.kube_context == "kind-dev" and e.exec_for("kubernetes").mode == "direct" and e.tool("kubernetes") == {"mode": "read"}
    client.post("/prod/envs/uat/mode", data={"mode": "ssh_sudo", "host": "bastion.example.com"})
    ex = envs.environment(C.load_config(client.cfg), "uat").exec_for("kubernetes")
    assert (ex.mode, ex.host, ex.sudo_password) == ("ssh_sudo", "bastion.example.com", "${USER_PASSWORD}")
    page = client.get("/prod").text
    assert "Tags and labels" not in page and "Apply tags" not in page and "/meta" not in page      # no tag editor in the UI
    assert client.post("/prod/envs/uat/meta", data={"tags": "x=1"}).status_code in (404, 405)
    assert 'name="on_postgres"' not in client.get("/prod").text and "on_postgres" not in client.get("/prod").text   # stores are routes
    client.post("/prod/envs/uat/tools", data={"on_airflow": "1", "mode_airflow": "approve_writes", "cfg_airflow": "url_env=AF_URL",
                                               "on_slack": "1", "cfg_slack": "channels=alerts|ops"})
    e = envs.environment(C.load_config(client.cfg), "uat")
    assert e.tool("airflow") == {"url_env": "AF_URL", "mode": "approve_writes"}
    assert e.tool("slack")["channels"] == ["alerts", "ops"] and e.tool("kubernetes") is None
    client.post("/prod/envs/uat/rename", data={"new": "uat2"})
    assert envs.environment(C.load_config(client.cfg), "uat2")
    client.post("/prod/envs/bulk-delete", data={"sel": ["uat2", "kind-dev"]})
    assert C.load_config(client.cfg).environments == []
    assert "Add environment" in client.get("/prod").text


def test_bad_environment_is_refused_and_file_untouched(client):
    before = client.cfg.read_text()
    r = client.post("/prod/envs", data={"name": "bad name", "context": "x"})
    assert client.cfg.read_text() == before
    r = client.post("/prod/envs", data={"name": "uat", "context": "x"})
    assert "already exists" in r.text
    r = client.post("/prod/envs/uat/tools", data={"on_airflow": "1", "cfg_airflow": "bogus=1"})
    assert "unknown setting" in r.text and client.cfg.read_text() == before


def test_secret_entry_is_masked_and_stored_0600(client, monkeypatch):
    monkeypatch.setenv("AIRLOCK_X", "1")
    client.post("/prod/envs/uat/secret", data={"var": "PG_DSN", "value": "postgres://u:TopSecret@db/x"})
    f = client.tmp / "secrets" / "uat" / "secrets.env"
    assert f.read_text().strip() == "PG_DSN=postgres://u:TopSecret@db/x" and oct(f.stat().st_mode)[-3:] == "600"
    page = client.get("/prod").text
    assert "TopSecret" not in page and "present" in page
    assert "TopSecret" not in client.cfg.read_text()


TPL = "select status, count(*) from orders where created_at > now() - interval '{{ hours:int }} hours' group by status"


def queue_proposal(client, sid="bbbbbb22", queries=None, routes=None, task="orders per status"):
    """What the gateway does for proposal.submit: a feasible bundle in the session inbox."""
    from airlock import access
    if not (client.tmp / "sessions" / sid).exists():
        fake_session(client.tmp, sid, "gateway", environment="uat")
    prop = access.parse_submission("uat", sid, {"task": task, "routes": routes or [], "queries": queries if queries is not None else [
        {"kind": "sql", "name": "orders_by_status", "description": "Orders per status", "template": TPL,
         "params": {"hours": {"min": 1, "max": 168, "default": 6}}, "evidence": "orders/models.py:12"}]})
    d = client.tmp / "sessions" / sid / "inbox" / "proposals"
    d.mkdir(exist_ok=True)
    (d / f"{prop.id}.json").write_text(json.dumps({"type": "bundle", "proposal": prop.model_dump(mode="json"),
                                                   "feasibility": {i: {"ok": True} for i, _, _ in prop.items()}}))
    return prop.id


def bulk_buttons(html_text):
    return html_text.count("<button")


def test_proposal_is_approved_with_checkboxes_and_the_agent_is_told(client):
    pid = queue_proposal(client)
    assert "1 waiting" in client.get("/prod").text                             # badge on the PROD tab
    frag = client.get("/prod/waiting-fragment").text
    assert "New access requested" in frag and "orders/models.py:12" in frag and f'value="{pid}:q0"' in frag
    assert bulk_buttons(frag) == 1                                             # one bulk bar, no buttons in rows
    st = patternstore.PatternStore()
    assert st.list(env="uat", enabled=True) == []                              # nothing runs before approval
    client.post("/prod/waiting/bulk", data={"item": f"{pid}:q0", "action": "approve"})
    p = st.get("orders_by_status")
    assert p.enabled and p.scope == ["uat"] and p.route == "default" and not p.proposed_by_agent
    assert json.loads(st.snapshot.read_text())["patterns"][0]["name"] == "orders_by_status"   # live in the gateway
    status = json.loads((client.tmp / "sessions" / "bbbbbb22" / "inbox" / "proposal-status" / f"{pid}.json").read_text())
    assert status["status"] == "decided" and status["items"][0]["decision"] == "approved"
    assert "Nothing is waiting" in client.get("/prod/waiting-fragment").text and "waiting</span>" not in client.get("/prod").text
    assert "orders_by_status" in client.get("/prod/patterns-fragment").text   # recently approved


def test_reject_with_a_note_goes_back_to_the_agent(client):
    pid = queue_proposal(client)
    client.get("/prod")
    client.post("/prod/waiting/bulk", data={"item": f"{pid}:q0", "action": "reject", "note": "use the replica view"})
    status = json.loads((client.tmp / "sessions" / "bbbbbb22" / "inbox" / "proposal-status" / f"{pid}.json").read_text())
    assert status["items"][0] == {"id": "q0", "kind": "query", "name": "orders_by_status", "decision": "rejected", "note": "use the replica view"}
    assert patternstore.PatternStore().get("orders_by_status") is None


def test_query_is_edited_by_clicking_it_and_renamed_by_clicking_the_name(client):
    pid = queue_proposal(client)
    client.get("/prod")
    # before approval: the human edits the agent's query
    client.post(f"/prod/proposals/{pid}/q0/edit", data={"template": TPL.replace("status,", "status as s,"), "params": ""})
    r = client.post(f"/prod/proposals/{pid}/q0/edit", data={"template": "select * from vault.keys", "params": ""})
    assert "not on the allowlist" in r.text                                    # uat allows only the public schema
    client.post("/prod/waiting/bulk", data={"item": f"{pid}:q0", "action": "approve"})
    st = patternstore.PatternStore()
    assert "status as s" in st.get("orders_by_status").template
    # after approval: click to edit makes a new version, invalid edits change nothing
    client.post("/prod/patterns/orders_by_status/edit", data={"template": TPL, "params": '{"hours": {"max": 24}}'})
    assert st.version("orders_by_status") == 2 and st.get("orders_by_status").params["hours"].max == 24
    r = client.post("/prod/patterns/orders_by_status/edit", data={"template": "delete from orders", "params": ""})
    assert "error=" in str(r.url) and st.version("orders_by_status") == 2
    client.post("/prod/patterns/orders_by_status/rename", data={"new": "orders_per_status"})
    assert st.get("orders_by_status") is None and st.version("orders_per_status") == 2
    assert 'data-orig="orders_per_status"' in client.get("/prod/patterns-fragment").text


def test_bulk_disable_enable_remove_export(client):
    pid = queue_proposal(client)
    client.get("/prod")
    client.post("/prod/waiting/bulk", data={"item": f"{pid}:q0", "action": "approve"})
    st = patternstore.PatternStore()
    client.post("/prod/patterns/bulk", data={"sel": "orders_by_status", "action": "disable"})
    assert not st.get("orders_by_status").enabled
    client.post("/prod/patterns/bulk", data={"sel": "orders_by_status", "action": "enable"})
    assert st.get("orders_by_status").enabled
    out = client.post("/prod/patterns/bulk", data={"sel": "orders_by_status", "action": "export"}).text
    assert "orders_by_status" in out and "interval" in out
    client.post("/prod/patterns/bulk", data={"sel": "orders_by_status", "action": "remove"})
    assert st.get("orders_by_status") is None and json.loads(st.snapshot.read_text())["patterns"] == []


def test_pattern_import_export_roundtrip(client):
    yaml_text = ("query_patterns:\n  - {name: session_hash, kind: redis, description: s, template: 'HGETALL session:{{ id:str }}'}\n"
                 "  - {name: bad, kind: redis, template: 'FLUSHALL'}\n")
    r = client.post("/settings/access/import", data={"yaml": yaml_text})
    assert "always denied" in r.text and patternstore.PatternStore().list() == []     # one bad item: nothing imported
    client.post("/settings/access/import", data={"yaml": yaml_text.split("  - {name: bad")[0]})
    out = client.get("/prod/patterns/export").text
    assert "session_hash" in out and "HGETALL" in out


def test_access_page_groups_by_kind_and_transport_with_usage(client):
    pid = queue_proposal(client)
    client.get("/prod")
    client.post("/prod/waiting/bulk", data={"item": f"{pid}:q0", "action": "approve"})
    from airlock.audit import Audit
    from airlock import audit as audit_mod
    a = Audit("bbbbbb22")
    for ok, ms in ((True, 12), (True, 30), (False, 5)):
        a.log("gateway", "tool.result", tool="sql.query", ok=ok, ms=ms, rows=3 if ok else None, pattern="orders_by_status@1")
    page = client.get("/settings/access?kind=postgres").text
    assert "Postgres" in page and "Elasticsearch" in page and "Redis" in page          # tabs by store kind
    assert "Direct (the gateway connects with a secret)" in page and "uat/postgres/default" in page
    assert "from config" not in page and "orders_by_status" in page
    row = page[page.index('value="orders_by_status"'):]
    assert ">3<" in row and ">1<" in row                                       # calls, errors
    detail = client.get("/settings/access/pattern/orders_by_status").text
    assert "Recent calls" in detail and "audit" in detail and detail.count("<tr><td>") >= 3
    assert client.get("/settings/access?kind=redis").text.count('name=sel value=') == 0


def test_propose_for_environment_needs_its_own_approval(client):
    text = CFG + """  - name: prd
    kube_context: prod-eu
    tools:
      - kubernetes: {mode: read}
"""
    client.cfg.write_text(text)
    pg_route("prd")
    pid = queue_proposal(client)
    client.get("/prod")
    client.post("/prod/waiting/bulk", data={"item": f"{pid}:q0", "action": "approve"})
    st = patternstore.PatternStore()
    client.post("/prod/patterns/bulk", data={"sel": "orders_by_status", "action": "propose", "env": "prd", "to": "/settings/access"})
    assert st.get("orders_by_status").scope == ["uat"]                         # approvals are per environment
    pend = st.proposals("pending")
    assert len(pend) == 1 and pend[0]["env"] == "prd"
    client.post("/prod/waiting/bulk", data={"item": f"{pend[0]['id']}:e0", "action": "approve"})
    assert st.get("orders_by_status").scope == ["prd", "uat"]


def test_legacy_single_pattern_proposal_still_arrives(client):
    fake_session(client.tmp, "bbbbbb22", "gateway", environment="uat")
    inbox = client.tmp / "sessions" / "bbbbbb22" / "inbox" / "proposals"
    inbox.mkdir()
    (inbox / "recent.json").write_text(json.dumps({"name": "recent", "kind": "sql", "description": "agent idea", "scope": ["uat"],
                                                   "template": "select count(*) from orders where id > {{ i:int }}"}))
    assert "recent" in client.get("/prod").text
    pend = patternstore.PatternStore().proposals("pending")
    assert pend[0]["proposal"].queries[0].pattern.name == "recent"


def test_approval_queue_in_the_ui(client):
    fake_session(client.tmp, "bbbbbb22", "gateway", environment="uat")
    inbox = client.tmp / "sessions" / "bbbbbb22" / "inbox"
    q = gateway.ApprovalQueue(inbox, timeout=5)
    import threading
    out = {}
    t = threading.Thread(target=lambda: out.update(r=q.request("ops.docker-purge", {"hosts": ["n1"]}, "destructive")))
    t.start()
    for _ in range(50):
        if gateway.list_approvals(inbox):
            break
        import time; time.sleep(0.1)
    page = client.get("/prod").text
    assert "Calls blocked right now" in page and "ops.docker-purge" in page and "Approve for session" in page
    frag = client.get("/prod/waiting-fragment").text
    assert bulk_buttons(frag) == 1                                             # same bulk bar as proposals, no row buttons
    aid = gateway.list_approvals(inbox)[0]["id"]
    assert "bad session id" in client.post("/prod/waiting/bulk", data={"call": f"../x:{aid}", "action": "approve"}).text
    client.post("/prod/waiting/bulk", data={"call": f"bbbbbb22:{aid}", "action": "approve"})
    t.join()
    assert out["r"] == "approved"
    assert "Nothing is waiting" in client.get("/prod/waiting-fragment").text


def test_one_bulk_bar_decides_a_blocked_call_and_a_proposal_together(client):
    pid = queue_proposal(client)
    inbox = client.tmp / "sessions" / "bbbbbb22" / "inbox"
    q = gateway.ApprovalQueue(inbox, timeout=5)
    import threading, time
    out = {}
    t = threading.Thread(target=lambda: out.update(r=q.request("sql.purge_cache", {"id": 7}, "write")))
    t.start()
    while not gateway.list_approvals(inbox):
        time.sleep(0.05)
    assert "2 waiting" in client.get("/prod").text
    aid = gateway.list_approvals(inbox)[0]["id"]
    client.post("/prod/waiting/bulk", data={"call": f"bbbbbb22:{aid}", "item": f"{pid}:q0", "action": "reject", "note": "not now"})
    t.join()
    assert out["r"] == "rejected"
    st = json.loads((inbox / "proposal-status" / f"{pid}.json").read_text())
    assert st["items"][0]["decision"] == "rejected" and st["items"][0]["note"] == "not now"


def test_cross_site_post_refused(client):
    r = client.post("/prod/patterns/x/remove", headers={"origin": "https://evil.example"})
    assert r.status_code == 403


def test_credentials_are_checked_before_a_session_starts(monkeypatch):
    monkeypatch.delenv("USER_PASSWORD", raising=False)
    monkeypatch.delenv("USER_NAME", raising=False)
    e = envs.Environment.model_validate({"name": "uat", "exec": {"mode": "ssh_sudo", "host": "h", "user": "${USER_NAME}", "auth": "password", "sudo_password": "${USER_PASSWORD}"},
                                         "tools": [{"kubernetes": {"mode": "read"}}]})
    with pytest.raises(C.ConfigError, match="USER_NAME|USER_PASSWORD"):
        gwsession.check_credentials(e)
    monkeypatch.setenv("USER_NAME", "me")
    monkeypatch.setenv("USER_PASSWORD", "pw")
    gwsession.check_credentials(e)
    gwsession.check_credentials(envs.Environment.model_validate({"name": "d", "tools": [{"kubernetes": {}}]}))   # direct needs nothing
    with pytest.raises(C.ConfigError, match="needs a host"):
        gwsession.check_credentials(envs.Environment.model_validate({"name": "x", "exec": {"mode": "ssh", "auth": "key", "user": "u"}, "tools": [{"kubernetes": {}}]}))


def test_claude_sign_in_lives_only_in_the_settings_tab(client):
    assert "Claude sign-in" not in client.get("/?tab=ec2").text and "Claude sign-in" not in client.get("/prod").text
    page = client.get("/settings").text
    assert "Claude sign-in" in page and 'href="/settings"' in page and 'class="tab on" href="/settings"' in page
    assert "<h2>Clusters" in client.get("/").text                      # visiting Settings keeps the remembered PROD tab


def test_session_names_and_ssh_command(client, monkeypatch):
    from airlock import sshaccess
    monkeypatch.setattr(sshaccess, "CONFIG", client.tmp / "ssh_config")
    monkeypatch.setattr(sshaccess, "USER_SSH_CONFIG", client.tmp / "dot_ssh_config")
    fake_session(client.tmp, "aaaaaa11", "sandbox", ssh=True)
    fake_session(client.tmp, "bbbbbb22", "gateway", environment="uat", ssh=True)
    fake_session(client.tmp, "cccccc33", "gateway", environment="uat")                      # started before ssh existed: no command
    ec2, prod = client.get("/?tab=ec2").text, client.get("/prod").text
    assert "ssh -F" not in ec2 and "ssh -F" not in prod and "class=cmd" not in ec2 + prod   # no ssh command in the Actions column
    assert 'onclick="rn(this)">aaaaaa11' in ec2                                              # click the id to name it
    assert '<span class=lbl title="not editable: this is the ssh command prefix">ssh</span> <b class=nm' in ec2   # fixed "ssh" before the name
    assert 'ssh</span> <b' not in prod.split('data-sid="cccccc33"')[1].split("</tr>")[0]                  # no prefix without ssh support
    client.post("/sessions/bbbbbb22/name", data={"name": "uat-debug"})
    assert session.load_state("bbbbbb22")["name"] == "uat-debug"
    prod = client.get("/prod").text
    assert ">uat-debug</b>" in prod and "ssh -F" not in prod
    conf = sshaccess.CONFIG.read_text()
    assert "Host aaaaaa11\n" in conf and "Host bbbbbb22 uat-debug\n" in conf and "cccccc33" not in conf
    assert "ProxyCommand docker exec -i air-agent-bbbbbb22 /usr/sbin/sshd -i" in conf and "User agent" in conf
    # validation: unique, not id-like, safe characters, clearable
    assert "already used" in client.post("/sessions/aaaaaa11/name", data={"name": "uat-debug"}).text
    assert "looks like a session id" in client.post("/sessions/aaaaaa11/name", data={"name": "deadbeef"}).text
    assert "starts with a letter" in client.post("/sessions/aaaaaa11/name", data={"name": "a b;rm"}).text
    assert "name" not in session.load_state("aaaaaa11")
    client.post("/sessions/bbbbbb22/name", data={"name": ""})
    assert "name" not in session.load_state("bbbbbb22") and "uat-debug" not in sshaccess.CONFIG.read_text()
    assert client.post("/sessions/zzzzzz99/name", data={"name": "x"}).status_code == 404


def test_ssh_include_setup_is_idempotent_and_changes_the_command(client, monkeypatch):
    from airlock import sshaccess
    monkeypatch.setattr(sshaccess, "CONFIG", client.tmp / "ssh_config")
    cfg = client.tmp / "dot_ssh_config"
    cfg.write_text("Host other\n  User x\n")
    monkeypatch.setattr(sshaccess, "USER_SSH_CONFIG", cfg)
    s = {"id": "aaaaaa11", "name": "dev", "ssh": True, "status": "running"}
    assert sshaccess.command(s).startswith("ssh -F ")
    sshaccess.setup_include()
    sshaccess.setup_include()
    text = cfg.read_text()
    assert text.startswith(f"Include {sshaccess.CONFIG}") and text.count("Include") == 1 and "Host other" in text   # first line, once
    assert sshaccess.command(s) == "ssh dev"


def test_tools_form_survives_and_keeps_config_defined_kubectl_commands(client):
    client.cfg.write_text(client.cfg.read_text() + "      - kubectl_commands:\n          mode: read\n          commands:\n"
                          "            - {name: roles, argv: [get, pods], description: d}\n")
    page = client.get("/prod").text
    assert "kubectl_commands" in page and "Traceback" not in page                       # the list-of-dicts setting renders
    client.post("/prod/envs/uat/tools", data={"on_kubectl_commands": "1", "mode_kubectl_commands": "approve_writes", "cfg_kubectl_commands": ""})
    tool = envs.environment(C.load_config(client.cfg), "uat").tool("kubectl_commands")
    assert tool["mode"] == "approve_writes" and tool["commands"][0]["name"] == "roles"   # edited mode, commands preserved


def test_files_routes_have_their_own_tab_with_roots_and_usage(client):
    from airlock import access
    from airlock.audit import Audit
    st = patternstore.PatternStore()
    st.put_route(access.Route(env="uat", kind="files", transport="exec", runner="python", roots=["/data/reports"],
                              target={"namespace": "app", "workload": "deploy/worker"},
                              guarantees={"writable_mount": True}), by="test")
    fake_session(client.tmp, "bbbbbb22", "gateway", environment="uat")
    a = Audit("bbbbbb22")
    for ok in (True, True, False):
        a.log("gateway", "tool.result", tool="files.grep", ok=ok, ms=40, route="uat/files/default")
    page = client.get("/settings/access?kind=files").text
    assert ">Files<" in page and "/data/reports" in page and "mount is writable" in page
    assert "3 call(s)" in page and "1 error(s)" in page
    assert 'name=route value="uat/files/default"' in page                      # selectable: disable / remove in bulk
