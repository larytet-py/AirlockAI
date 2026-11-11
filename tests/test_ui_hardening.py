"""SECURITY.md F01 (UI token, Host, Origin), F02 (node text is never markup) and F10 (a value cannot become a flag)."""
import pytest

from airlock import kubecommands as K
from airlock import nodestats, session
from airlock.config import ConfigError
from airlock.ops import load_operations

ORIGIN = {"origin": "http://127.0.0.1:8800"}
TOKEN = "t0ken-for-this-test"


def client(tmp_path, monkeypatch, cookies=None, headers=None, base="http://127.0.0.1:8800"):
    from starlette.testclient import TestClient

    import airlock.ui as ui
    monkeypatch.setattr(nodestats, "collect", lambda nodes: {})
    monkeypatch.setattr(session, "SESSIONS", tmp_path / "sessions")
    p = tmp_path / "c.yaml"
    p.write_text("version: 1\n")
    return TestClient(ui.make_app(str(p), ui_token=TOKEN), base_url=base, cookies=cookies or {}, headers=headers or {})


# ---- F01 ----------------------------------------------------------------------------------------------------------

def test_every_page_refuses_a_request_without_the_token(raw_ui, tmp_path, monkeypatch):
    c = client(tmp_path, monkeypatch)
    for path in ("/", "/prod", "/api/nodes/stats", "/api/sessions/stats", "/audit/aaaaaa11", "/prod/waiting-fragment"):
        assert c.get(path, follow_redirects=False).status_code == 401, path


def test_wrong_token_cookie_is_refused(raw_ui, tmp_path, monkeypatch):
    c = client(tmp_path, monkeypatch, cookies={"airlock_ui": "guess"})
    assert c.get("/").status_code == 401


def test_the_printed_link_sets_an_httponly_cookie_and_drops_the_token_from_the_url(raw_ui, tmp_path, monkeypatch):
    c = client(tmp_path, monkeypatch)
    r = c.get(f"/?token={TOKEN}&tab=ec2", follow_redirects=False)
    assert r.status_code == 303 and "token" not in r.headers["location"] and "tab=ec2" in r.headers["location"]
    cookie = r.headers["set-cookie"].lower()
    assert "airlock_ui=" in cookie and "httponly" in cookie and "samesite=strict" in cookie
    assert c.get("/").status_code == 200                    # the client kept the cookie


def test_a_wrong_token_in_the_url_does_not_sign_in(raw_ui, tmp_path, monkeypatch):
    c = client(tmp_path, monkeypatch)
    r = c.get("/?token=nope", follow_redirects=False)
    assert r.status_code == 401 and "set-cookie" not in r.headers


def test_token_in_the_url_is_not_accepted_on_posts(raw_ui, tmp_path, monkeypatch):
    c = client(tmp_path, monkeypatch, headers=ORIGIN)
    assert c.post(f"/sessions?token={TOKEN}", data={"nodes": "x"}).status_code == 401


def test_rebinding_host_is_refused_even_with_the_cookie(raw_ui, tmp_path, monkeypatch):
    c = client(tmp_path, monkeypatch, cookies={"airlock_ui": TOKEN}, base="http://evil.example:8800")
    assert c.get("/").status_code == 421


def test_post_without_origin_is_refused_but_a_same_origin_post_passes_the_gate(raw_ui, tmp_path, monkeypatch):
    c = client(tmp_path, monkeypatch, cookies={"airlock_ui": TOKEN})
    r = c.post("/sessions/aaaaaa11/name", data={"name": "x"})
    assert r.status_code == 403 and "Origin" in r.text
    r = c.post("/sessions/aaaaaa11/name", data={"name": "x"}, headers={"origin": "http://evil.example"})
    assert r.status_code == 403
    r = c.post("/sessions/aaaaaa11/name", data={"name": "x"}, headers={"origin": "null"})
    assert r.status_code == 403
    r = c.post("/sessions/aaaaaa11/name", data={"name": "x"}, headers=ORIGIN, follow_redirects=False)
    assert r.status_code not in (401, 403, 421)             # past the gate (whatever the route then says about the unknown session)


def test_websocket_needs_the_token_and_the_origin(raw_ui, tmp_path, monkeypatch):
    from starlette.websockets import WebSocketDisconnect
    c = client(tmp_path, monkeypatch)
    for headers in ({"origin": "http://127.0.0.1:8800"},                                                   # no cookie
                    {"origin": "http://127.0.0.1:8800", "cookie": "airlock_ui=guess"},
                    {"cookie": f"airlock_ui={TOKEN}"},                                                     # no origin
                    {"origin": "http://evil.example", "cookie": f"airlock_ui={TOKEN}"}):
        with pytest.raises(WebSocketDisconnect):
            with c.websocket_connect("/sessions/aaaaaa11/ws", headers=headers):
                pass


def test_pages_carry_framing_and_sniffing_protection(raw_ui, tmp_path, monkeypatch):
    c = client(tmp_path, monkeypatch, cookies={"airlock_ui": TOKEN})
    h = c.get("/").headers
    assert h["x-frame-options"] == "DENY" and h["x-content-type-options"] == "nosniff" and "frame-ancestors 'none'" in h["content-security-policy"]


# ---- F02 ----------------------------------------------------------------------------------------------------------

def test_node_supplied_text_is_reduced_to_plain_values():
    df = ("Filesystem 1K-blocks Used Available Use% Mounted\n"
          "a 100 50 50 50% /ok/dir\n"
          "b 100 50 50 <img>% /<img src=x onerror=alert(1)>\n")
    disks = nodestats.parse(df)["disks"]
    assert (disks[0]["mount"], disks[0]["pct"]) == ("/ok/dir", "50%")
    assert disks[1]["mount"] == "(unprintable mount name)" and disks[1]["pct"] == "-"
    assert "<" not in str(disks)


def test_the_page_script_never_writes_node_values_with_innerhtml(raw_ui, tmp_path, monkeypatch):
    page = client(tmp_path, monkeypatch, cookies={"airlock_ui": TOKEN}).get("/").text
    for dangerous in ("${k.mount}", "k.mount}</span>", "innerHTML='<span class=lbl>IP"):
        assert dangerous not in page
    assert "textContent=k.mount" in page


# ---- F10 ----------------------------------------------------------------------------------------------------------

def kcmd(**kw):
    return K.KubeCommand.model_validate({"name": "x", **kw})


@pytest.mark.parametrize("bad", ["--as=system:admin", "--server=https://evil", "--kubeconfig=/tmp/x", "-s", "--token=abc", "-f"])
def test_a_bound_value_cannot_become_a_kubectl_flag(bad):
    c = kcmd(argv=["get", "pods", "{{ name:str }}"])
    K.validate(c)
    with pytest.raises(K.Mismatch):
        K.bind(c, {"name": bad})
    assert K.bind(c, {"name": "web-1"}) == ["get", "pods", "web-1"]


def test_flag_like_value_cannot_open_a_composite_argument():
    c = kcmd(argv=["get", "pods", "{{ a:str }}={{ b:str }}"])
    with pytest.raises(K.Mismatch):
        K.bind(c, {"a": "--as", "b": "x"})


def test_negative_numbers_and_operator_declared_closed_sets_still_work():
    c = kcmd(argv=["logs", "p", "--tail", "{{ n:int }}"], params={"n": {"min": -1, "max": 100}})
    assert K.bind(c, {"n": -1}) == ["logs", "p", "--tail", "-1"]
    c = kcmd(argv=["get", "pods", "-o", "{{ fmt:enum(json,name) }}"])
    assert K.bind(c, {"fmt": "json"}) == ["get", "pods", "-o", "json"]
    c = kcmd(argv=["get", "pods", "{{ sel:str }}"], params={"sel": {"values": ["-A"]}})
    assert K.bind(c, {"sel": "-A"}) == ["get", "pods", "-A"]          # the operator wrote that value, the agent only picks it


def test_a_list_value_is_checked_item_by_item():
    c = kcmd(argv=["get", "pods", "{{ names:list[str] }}"])
    with pytest.raises(K.Mismatch):
        K.bind(c, {"names": ["ok", "--as=root"]})


@pytest.mark.parametrize("bad", ["--follow", "-n", "-1", "--output=x", "-"])
def test_operation_string_values_cannot_start_with_a_dash(bad):
    op = load_operations()["journal-tail"]
    with pytest.raises(ConfigError):
        op.bind({"unit": bad})
    assert "nginx.service" in op.bind({"unit": "nginx.service"})


def test_referrer_policy_lets_our_own_forms_send_their_origin(raw_ui, tmp_path, monkeypatch):
    # With "no-referrer" browsers send `Origin: null` on same-origin form POSTs, which the gate refuses as cross-site.
    c = client(tmp_path, monkeypatch, cookies={"airlock_ui": TOKEN})
    assert c.get("/settings").headers["referrer-policy"] == "same-origin"
