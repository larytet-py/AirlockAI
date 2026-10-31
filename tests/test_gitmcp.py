"""Git MCP: commit and push of a writable source folder, with the folder treated as hostile."""
import subprocess

import pytest

from airlock import gitmcp
from airlock.audit import Audit


def sh(*a, cwd=None):
    return subprocess.run(a, cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


@pytest.fixture
def repo(tmp_path):
    bare = tmp_path / "remote.git"
    sh("git", "init", "-q", "--bare", "-b", "main", str(bare))
    w = tmp_path / "app"
    sh("git", "init", "-q", "-b", "main", str(w))
    for k, v in (("user.name", "T"), ("user.email", "t@x")):
        sh("git", "config", k, v, cwd=w)
    sh("git", "remote", "add", "origin", str(bare), cwd=w)
    (w / "a.txt").write_text("1")
    sh("git", "add", "-A", cwd=w)
    sh("git", "commit", "-q", "-m", "init", cwd=w)
    sh("git", "push", "-q", "origin", "main", cwd=w)
    return w, bare


def tool(w):
    url = gitmcp.pin(str(w))
    return gitmcp.GitTool("s1", {"app": {"path": str(w), "url": url}}, Audit("s1"))


def test_commit_and_push_current_branch(repo):
    w, bare = repo
    sh("git", "checkout", "-q", "-b", "feature", cwd=w)
    (w / "b.txt").write_text("2")
    r = tool(w).call("git.commit_push", {"message": "add b"})
    assert r["ok"], r
    assert sh("git", "log", "-1", "--format=%s", "feature", cwd=bare) == "add b"
    assert "Airlock-Session: s1" in sh("git", "log", "-1", "--format=%B", "feature", cwd=bare)
    assert sh("git", "log", "-1", "--format=%s", "main", cwd=bare) == "init"       # other branches untouched


def test_nothing_to_commit_still_pushes(repo):
    w, bare = repo
    (w / "c.txt").write_text("3")
    sh("git", "add", "-A", cwd=w)
    sh("git", "commit", "-q", "-m", "local", cwd=w)
    r = tool(w).call("git.commit_push", {"repo": "/src/app", "message": "x"})
    assert r["ok"] and "nothing to commit" in r["result"]
    assert sh("git", "log", "-1", "--format=%s", "main", cwd=bare) == "local"


@pytest.mark.parametrize("args", [{}, {"message": " "}, {"message": "m", "repo": "other"}, {"message": "m", "force": True},
                                  {"message": "m" * 5000}])
def test_bad_arguments(repo, args):
    assert not tool(repo[0]).call("git.commit_push", args)["ok"]


def test_detached_head_refused(repo):
    w, _ = repo
    sh("git", "checkout", "-q", "--detach", cwd=w)
    r = tool(w).call("git.commit_push", {"message": "m"})
    assert not r["ok"] and "detached" in r["error"]


def test_hooks_do_not_run(repo):
    w, _ = repo
    hook = w / ".git" / "hooks" / "pre-commit"
    hook.write_text(f"#!/bin/sh\ntouch {w}/PWNED\n")
    hook.chmod(0o755)
    (w / "d.txt").write_text("4")
    assert tool(w).call("git.commit_push", {"message": "m"})["ok"]
    assert not (w / "PWNED").exists()


@pytest.mark.parametrize("key,val", [("core.sshCommand", "touch /tmp/x"), ("filter.x.clean", "sh -c id"), ("alias.push", "!id"),
                                     ("url.http://evil/.insteadOf", "x"), ("include.path", "/tmp/y"), ("core.fsmonitor", "x")])
def test_unsafe_config_refused(repo, key, val):
    w, _ = repo
    sh("git", "config", key, val, cwd=w)
    r = tool(w).call("git.commit_push", {"message": "m"})
    assert not r["ok"] and "not allowed" in r["error"]


def test_remote_is_pinned(repo, tmp_path):
    w, bare = repo
    evil = tmp_path / "evil.git"
    sh("git", "init", "-q", "--bare", str(evil))
    t = tool(w)                                   # pinned at session start
    sh("git", "remote", "set-url", "origin", str(evil), cwd=w)
    (w / "e.txt").write_text("5")
    assert t.call("git.commit_push", {"message": "m"})["ok"]
    assert sh("git", "log", "-1", "--format=%s", "main", cwd=bare) == "m"
    assert subprocess.run(["git", "log"], cwd=evil, capture_output=True).returncode != 0   # nothing reached the other repo


def test_gitfile_and_symlink_refused(repo, tmp_path):
    w, _ = repo
    other = tmp_path / "other"
    w.rename(other)
    w.mkdir()
    (w / ".git").write_text(f"gitdir: {other}/.git\n")
    assert gitmcp.pin(str(w)) is None
    (w / ".git").unlink()
    (w / ".git").symlink_to(other / ".git")
    assert gitmcp.pin(str(w)) is None


def test_pins_only_writable_git_folders(repo, tmp_path):
    w, _ = repo
    plain = tmp_path / "plain"
    plain.mkdir()
    ms = [{"host": str(w), "container": "/src/app", "ro": False}, {"host": str(w), "container": "/src/ro", "ro": True},
          {"host": str(plain), "container": "/src/plain", "ro": False}]
    assert list(gitmcp.pins(ms)) == ["app"]


def test_agent_gitconfig_is_valid_git_config(tmp_path, monkeypatch):
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(tmp_path / "host"))
    sh("git", "config", "--global", "user.name", 'Ann "Q" Lee')
    sh("git", "config", "--global", "user.email", "ann@x.org")
    f = tmp_path / "agent.cfg"
    f.write_text(gitmcp.agent_gitconfig())
    out = sh("git", "config", "-f", str(f), "--list")
    assert 'user.name=Ann "Q" Lee' in out and "user.email=ann@x.org" in out and "safe.directory=*" in out
