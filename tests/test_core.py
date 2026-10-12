import json
import shlex

import pytest

from airlock import config as C
from airlock import runner
from airlock.audit import Audit
from airlock.config import Exec


def write(tmp_path, text, name="airlock.yaml"):
    p = tmp_path / name
    p.write_text(text)
    return p


NODES = """
version: 1
defaults: {exec: {mode: ssh, user: "${USER_NAME}"}}
nodes:
  - {name: JohnTestApi, host: 10.0.1.11}
  - {name: JaneTestGateway, host: 10.0.1.12, exec: {mode: ssh_sudo, sudo_password: "${USER_PASSWORD}"}}
  - {name: ProdBox, host: 10.0.2.1}
"""


def test_load_merges_defaults(tmp_path):
    cfg = C.load_config(write(tmp_path, NODES))
    assert cfg.node("JohnTestApi").exec.user == "${USER_NAME}"
    assert cfg.node("JaneTestGateway").exec.mode == "ssh_sudo"


def test_unknown_keys_and_literal_secrets_refused(tmp_path):
    with pytest.raises(C.ConfigError):
        C.load_config(write(tmp_path, "version: 1\nbogus: 1\n"))
    bad = NODES.replace('"${USER_PASSWORD}"', "hunter2")
    with pytest.raises(C.ConfigError, match="literal value in secret field"):
        C.load_config(write(tmp_path, bad))


def test_duplicate_names_refused(tmp_path):
    with pytest.raises(C.ConfigError, match="duplicate"):
        C.load_config(write(tmp_path, "version: 1\nnodes:\n - {name: A, host: h}\n - {name: A, host: h2}\n"))


def test_missing_vars_reported(tmp_path, monkeypatch):
    monkeypatch.delenv("USER_NAME", raising=False)
    cfg = C.load_config(write(tmp_path, NODES))
    assert "USER_NAME" in C.missing_vars(cfg)
    with pytest.raises(C.MissingSecret, match="USER_NAME"):
        C.resolve("${USER_NAME}", "node X")


def test_export_drops_local_and_refuses_secret_values(tmp_path, monkeypatch):
    cfg = C.load_config(write(tmp_path, NODES + "  - {name: Mine, host: h, local: true}\n"))
    out = C.export_config(cfg)
    assert "Mine" not in out
    monkeypatch.setenv("USER_PASSWORD", "JohnTestApi")  # value appears in output -> refuse
    with pytest.raises(C.ConfigError):
        C.export_config(cfg)


def ex(**kw):
    return Exec(host="h.example", user="alice", **kw)


def test_direct_adds_context_only_locally():
    e = Exec(mode="direct")
    assert runner.kubectl_argv(e, ["get", "ns"], "uat") == ["kubectl", "--context", "uat", "get", "ns"]
    s = ex(mode="ssh", kubeconfig="/etc/rancher/k3s/k3s.yaml")
    assert runner.kubectl_argv(s, ["get", "ns"], "uat") == ["kubectl", "--kubeconfig", "/etc/rancher/k3s/k3s.yaml", "get", "ns"]


def test_ssh_and_sudo_wrapping(monkeypatch):
    monkeypatch.setenv("USER_PASSWORD", "s3cret")
    w = runner.wrap(ex(mode="ssh"), ["kubectl", "get", "pods", "-n", "app"])
    assert w.cmd[-2:] == ["--", "kubectl get pods -n app"] and w.cmd[-3].startswith("alice@") or "alice@h.example" in w.cmd
    assert w.stdin is None
    w = runner.wrap(ex(mode="ssh_sudo", sudo_password="${USER_PASSWORD}"), ["kubectl", "get", "ns"])
    assert w.cmd[-1] == "sudo -S -p '' kubectl get ns"
    assert w.stdin == b"s3cret\n"
    assert "s3cret" not in " ".join(w.cmd)
    w = runner.wrap(ex(mode="ssh_sudo"), ["docker", "ps"])
    assert w.cmd[-1] == "sudo -n docker ps" and w.stdin is None


def test_password_ssh_uses_askpass_not_argv(monkeypatch, tmp_path):
    monkeypatch.setattr(runner, "HOME", tmp_path)
    monkeypatch.setenv("USER_PASSWORD", "s3cret")
    w = runner.wrap(ex(mode="ssh", auth="password"), ["true"])
    assert w.env["SSH_ASKPASS_REQUIRE"] == "force"
    assert "s3cret" not in " ".join(w.cmd) and "s3cret" not in json.dumps(w.env)


@pytest.mark.parametrize("arg", ["a\nb", "x\0y"])
def test_newline_and_nul_rejected(arg):
    with pytest.raises(ValueError):
        runner.wrap(ex(mode="ssh"), ["echo", arg])


def test_shell_metacharacters_stay_inert():
    nasty = "x; rm -rf / $(id) `id` | cat"
    w = runner.wrap(ex(mode="ssh"), ["echo", nasty])
    assert shlex.split(w.cmd[-1]) == ["echo", nasty]  # one argument, not interpreted


def test_redaction_masks_password(monkeypatch):
    monkeypatch.setenv("USER_PASSWORD", "s3cret")
    assert C.redact("token=s3cret ok") == "token=*** ok"


def test_audit_chain_detects_tampering(tmp_path, monkeypatch):
    import airlock.audit as A
    monkeypatch.setattr(A, "HOME", tmp_path)
    a = Audit("abc123")
    a.log("t", "one", x=1)
    a.log("t", "two", x=2)
    assert a.verify()
    lines = a.path.read_text().splitlines()
    lines[0] = lines[0].replace('"x": 1', '"x": 9')
    a.path.write_text("\n".join(lines) + "\n")
    assert not a.verify()


def test_default_allowlist_covers_claude_code_hosts(tmp_path):
    from airlock import session
    cfg = C.load_config(write(tmp_path, "version: 1\nnodes:\n - {name: N, host: 10.0.0.1}\n"))
    allow = session.allowlist(cfg, cfg.nodes, {"N": "10.0.0.1"}, mirrors=False)
    assert {"api.anthropic.com:443", "claude.ai:443", "claude.com:443", "platform.claude.com:443", "10.0.0.1:22"} == set(allow)
