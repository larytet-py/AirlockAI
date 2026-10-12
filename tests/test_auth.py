import os
import stat

import pytest

from airlock import config as C
from airlock import session

TOKEN = "sk-ant-oat01-" + "x" * 40


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    monkeypatch.setattr(C, "HOME", tmp_path)
    monkeypatch.delenv("CLAUDE_CODE_OAUTH_TOKEN", raising=False)
    return tmp_path


def test_token_from_env_then_file(home, monkeypatch):
    assert C.claude_oauth_token() is None
    f = C.save_claude_oauth_token(TOKEN)
    assert f == home / "secrets" / "claude_oauth_token" and stat.S_IMODE(f.stat().st_mode) == 0o600
    assert C.claude_oauth_token() == TOKEN
    monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "from-env-" + "y" * 20)
    assert C.claude_oauth_token().startswith("from-env-")                       # the environment wins over the file


def test_loose_file_permissions_are_refused_like_an_ssh_key(home):
    f = C.save_claude_oauth_token(TOKEN)
    f.chmod(0o644)
    with pytest.raises(C.ConfigError, match="chmod 600"):
        C.claude_oauth_token()


@pytest.mark.parametrize("bad", ["", "short", "has space " + "x" * 30, "multi\nline" + "x" * 30])
def test_bad_tokens_are_not_saved(home, bad):
    with pytest.raises(C.ConfigError):
        C.save_claude_oauth_token(bad)
    assert not (home / "secrets" / "claude_oauth_token").exists()


def test_token_is_redacted_from_output(home):
    C.save_claude_oauth_token(TOKEN)
    assert C.redact(f"auth failed for {TOKEN}") == "auth failed for ***"


def test_token_never_on_a_command_line_and_host_login_not_copied(home, monkeypatch, tmp_path):
    """Drive start_session with a fake docker: the token must reach the container by name only."""
    monkeypatch.setenv("USER_NAME", "alice")
    monkeypatch.setenv("USER_PASSWORD", "pw")
    C.save_claude_oauth_token(TOKEN)
    import airlock.audit as audit_mod
    monkeypatch.setattr(audit_mod, "HOME", tmp_path)                           # never write to the real ~/.airlock/audit
    monkeypatch.setattr(session, "SESSIONS", tmp_path / "sessions")
    monkeypatch.setattr(session, "HOME", tmp_path)
    monkeypatch.setattr(session.Path, "home", classmethod(lambda cls: tmp_path))
    from airlock import sshaccess                                              # the fake ssh-keygen below must never touch ~/.airlock/ssh
    monkeypatch.setattr(sshaccess, "KEY", tmp_path / "ssh" / "id_ed25519")
    monkeypatch.setattr(sshaccess, "CONFIG", tmp_path / "ssh_config")
    monkeypatch.setattr(sshaccess, "provision", lambda sid: False)
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / ".credentials.json").write_text('{"host": "login"}')
    calls = []

    class P:
        stdout, stderr, returncode = "", "", 0

    def fake_docker(*args, check=True, input=None, env=None):
        calls.append((args, env))
        return P()
    monkeypatch.setattr(session, "docker", fake_docker)
    monkeypatch.setattr(session, "resolve_ip", lambda h: "10.0.0.1")
    def fake_run(cmd, **kw):
        if cmd[0] == "ssh-keygen" and "-t" in cmd:                              # key generation; the known_hosts lookup (-F) returns nothing
            key = cmd[cmd.index("-f") + 1]
            open(key, "w").write("private")
            open(key + ".pub", "w").write("ssh-ed25519 AAAA")
        return P()
    monkeypatch.setattr(session.subprocess, "run", fake_run)
    monkeypatch.setattr(session.nodeaccess, "enable_access", lambda *a, **k: type("A", (), {"ready": True, "detail": "", "expires": 1})())
    cfg = C.Config.model_validate({"version": 1, "nodes": [{"name": "N", "host": "10.0.0.1", "tags": {"env": "test"}, "exec": {"user": "u"}}]})
    st = session.start_session(cfg, ["N"])
    run = next((a, e) for a, e in calls if a[0] == "run" and f"air-agent-{st['id']}" in a)
    args, env = run
    assert TOKEN not in " ".join(args)                                          # not in argv, so not in `ps`
    assert "CLAUDE_CODE_OAUTH_TOKEN" in args and args[args.index("CLAUDE_CODE_OAUTH_TOKEN") - 1] == "-e"
    assert env["CLAUDE_CODE_OAUTH_TOKEN"] == TOKEN
    assert not (tmp_path / "sessions" / st["id"] / "claude-credentials.json").exists()   # host login is not shared
    assert (tmp_path / "audit" / f"{st['id']}.jsonl").exists()                            # the audit went to the temp dir


def test_without_token_the_host_login_copy_still_works(home, monkeypatch, tmp_path):
    assert C.claude_oauth_token() is None                                       # the fallback path is unchanged


def ui_client(tmp_path, monkeypatch):
    from starlette.testclient import TestClient

    import airlock.ui as ui
    from airlock import nodestats
    monkeypatch.setattr(nodestats, "collect", lambda nodes: {})
    monkeypatch.setattr(session, "SESSIONS", tmp_path / "sessions")
    p = tmp_path / "c.yaml"
    p.write_text("version: 1\n")
    return TestClient(ui.make_app(str(p)), base_url="http://127.0.0.1:8800", follow_redirects=True)


def test_ui_shows_status_and_saves_the_token_without_echoing_it(tmp_path, monkeypatch):
    c = ui_client(tmp_path, monkeypatch)
    page = c.get("/settings").text
    assert "not set up" in page and "claude setup-token" in page and 'type=password name=token' in page
    r = c.post("/auth/claude-token", data={"token": TOKEN})
    assert "automatic sign-in is on" in r.text and TOKEN not in r.text and "Remove token" in r.text
    f = tmp_path / "secrets" / "claude_oauth_token"
    assert f.read_text().strip() == TOKEN and stat.S_IMODE(f.stat().st_mode) == 0o600
    assert TOKEN not in c.get("/settings").text                                           # never rendered back, not even in a value attribute
    assert "not set up" in c.post("/auth/claude-token/remove").text and not f.exists()


def test_ui_rejects_a_bad_token_and_explains(tmp_path, monkeypatch):
    c = ui_client(tmp_path, monkeypatch)
    assert "does not look like a token" in c.post("/auth/claude-token", data={"token": "short"}).text
    assert not (tmp_path / "secrets").exists() or not any((tmp_path / "secrets").iterdir())


def test_ui_reports_a_loose_token_file(tmp_path, monkeypatch):
    f = C.save_claude_oauth_token(TOKEN)
    f.chmod(0o644)
    assert "chmod 600" in ui_client(tmp_path, monkeypatch).get("/settings").text


def test_environment_token_is_reported_as_on(tmp_path, monkeypatch):
    monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", TOKEN)
    page = ui_client(tmp_path, monkeypatch).get("/settings").text
    assert "automatic sign-in is on" in page and "CLAUDE_CODE_OAUTH_TOKEN variable" in page and TOKEN not in page


def test_cross_site_posts_are_refused_on_every_form(tmp_path, monkeypatch):
    c = ui_client(tmp_path, monkeypatch)
    evil = {"origin": "https://evil.example"}
    for path, data in (("/auth/claude-token", {"token": TOKEN}), ("/sessions/bulk-delete", {"ssel": ["aaaaaa11"]}),
                       ("/nodes/bulk-delete", {"sel": ["x"]}), ("/sessions", {"nodes": "x"})):
        r = c.post(path, data=data, headers=evil, follow_redirects=False)
        assert r.status_code == 403, path
    assert c.post("/auth/claude-token", data={"token": TOKEN}, headers={"origin": "null"}).status_code == 403
    assert c.post("/auth/claude-token", data={"token": TOKEN}, headers={"sec-fetch-site": "cross-site"}).status_code == 403
    assert not (tmp_path / "secrets" / "claude_oauth_token").exists()              # nothing was planted
    ok = c.post("/auth/claude-token", data={"token": TOKEN}, headers={"origin": "http://127.0.0.1:8800"})
    assert ok.status_code == 200 and (tmp_path / "secrets" / "claude_oauth_token").exists()
    assert c.post("/auth/claude-token/remove", headers={"origin": "http://localhost:8800"}).status_code == 200


def test_node_login_is_memory_only(home, monkeypatch):
    for v in ("USER_NAME", "USER_PASSWORD"):
        monkeypatch.delenv(v, raising=False)
    assert C.node_login_status() == ("none", "")
    C.save_node_login("jdoe", "s3cret pw")
    assert os.environ["USER_NAME"] == "jdoe" and os.environ["USER_PASSWORD"] == "s3cret pw"
    assert C.node_login_status() == ("memory", "jdoe")      # the password is never in the status
    assert not list(home.rglob("*"))                            # nothing at all written under AIRLOCK_HOME
    assert C.remove_node_login() and "USER_PASSWORD" not in os.environ


def test_node_login_form_does_not_override_server_environment(home, monkeypatch):
    monkeypatch.setenv("USER_NAME", "envuser")
    monkeypatch.setenv("USER_PASSWORD", "envpw")
    assert C.node_login_status() == ("env", "envuser")
    with pytest.raises(C.ConfigError):
        C.save_node_login("fileuser", "filepw")
    assert not C.remove_node_login() and os.environ["USER_PASSWORD"] == "envpw"


@pytest.mark.parametrize("user,pw", [("a b", "x"), ("a;rm", "x"), ("ok", ""), ("ok", "a\nb"), ("", "x")])
def test_node_login_rejects_unsafe_input(home, monkeypatch, user, pw):
    monkeypatch.delenv("USER_NAME", raising=False)
    monkeypatch.delenv("USER_PASSWORD", raising=False)
    with pytest.raises(C.ConfigError):
        C.save_node_login(user, pw)
    assert "USER_NAME" not in os.environ
