import pytest

from airlock import config as C
from airlock import nodeaccess


def node(tags, **kw):
    return C.Node(name="N", host="h.example", tags=tags, exec=C.Exec(user="alice"), **kw)


def test_login_is_required_before_anything_starts(monkeypatch):
    monkeypatch.delenv("USER_NAME", raising=False)
    monkeypatch.delenv("USER_PASSWORD", raising=False)
    with pytest.raises(C.ConfigError, match="USER_NAME"):
        nodeaccess.require_login()
    monkeypatch.setenv("USER_NAME", "alice")
    with pytest.raises(C.ConfigError, match="USER_PASSWORD"):
        nodeaccess.require_login()
    monkeypatch.setenv("USER_PASSWORD", "pw")
    nodeaccess.require_login()


def test_legacy_bootstrap_keys_in_old_config_files_still_load():
    n = C.Node.model_validate({"name": "N", "host": "h", "bootstrap": {"method": "key", "sudo": "none"}, "allow_bootstrap": True})
    assert n.name == "N" and not hasattr(n, "bootstrap")


def test_unsafe_user_refused():
    n = C.Node(name="N", host="h", tags={"env": "test"}, exec=C.Exec(user="a b; rm -rf /"))
    assert "unsafe user" in nodeaccess.enable_access(n, "abcdef12", "ssh-ed25519 AAAA", "/x").detail


@pytest.mark.parametrize("sid", ["../etc", "ABC", "x;y", ""])
def test_bad_session_id_refused(sid):
    with pytest.raises(C.ConfigError):
        nodeaccess.revoke_access(node({"env": "test"}), sid)


def test_ttl_parse():
    assert nodeaccess.parse_ttl("8h") == 28800 and nodeaccess.parse_ttl("90m") == 5400
    with pytest.raises(C.ConfigError):
        nodeaccess.parse_ttl("soon")


def test_session_ssh_config_has_the_resolved_user(tmp_path, monkeypatch):
    from airlock import session
    monkeypatch.setattr(session, "SESSIONS", tmp_path)
    monkeypatch.setenv("USER_NAME", "jdoe")
    (tmp_path / "abcdef12").mkdir()
    ws = tmp_path / "ws"
    ws.mkdir()
    n = C.Node(name="N", host="h.example", tags={"env": "test"}, exec=C.Exec(user="${USER_NAME}"))
    monkeypatch.setattr(session, "host_key_lines", lambda h: [])
    session.write_session_files({"id": "abcdef12", "workspace": str(ws)}, [n], {"N": "10.0.0.1"})
    cfg = (tmp_path / "abcdef12" / "ssh_config").read_text()
    assert "User jdoe\n" in cfg and "${" not in cfg
    monkeypatch.setenv("USER_NAME", "a b")
    with pytest.raises(C.ConfigError):
        session.write_session_files({"id": "abcdef12", "workspace": str(ws)}, [n], {"N": "10.0.0.1"})


def test_status_probe_says_login_is_missing_without_trying_ssh(monkeypatch):
    from airlock import nodestats
    monkeypatch.delenv("USER_NAME", raising=False)
    monkeypatch.delenv("USER_PASSWORD", raising=False)
    monkeypatch.setattr(nodestats.runner, "run", lambda *a, **k: pytest.fail("must not try ssh without a login"))
    r = nodestats.probe(node({"env": "test"}))
    assert r["up"] is False and r["login_missing"] is True and "login is missing" in r["error"] and "Settings" in r["error"]
    monkeypatch.setenv("USER_NAME", "alice")                 # one of the two is not enough
    assert nodestats.probe(node({}))["login_missing"] is True
