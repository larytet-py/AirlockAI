"""Execution modes (SPEC 7.2): direct, ssh, ssh_sudo.

Tools build an argv list; policy is evaluated on that argv; only then does the runner wrap it.
The remote command is exactly one binary plus shlex-quoted arguments. Passwords never reach argv:
ssh auth goes through SSH_ASKPASS, the sudo password through stdin.
"""
from __future__ import annotations

import os
import shlex
import stat
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from .config import HOME, ConfigError, Exec, redact, resolve

KNOWN_HOSTS = HOME / "known_hosts"


@dataclass
class Wrapped:
    cmd: list[str]
    stdin: bytes | None = None
    env: dict[str, str] = field(default_factory=dict)


@dataclass
class Result:
    rc: int
    out: str
    err: str

    @property
    def ok(self) -> bool:
        return self.rc == 0


def check_args(argv: list[str]) -> None:
    if not argv:
        raise ValueError("empty command")
    for a in argv:
        if "\n" in a or "\0" in a:
            raise ValueError("arguments with newline or NUL are rejected")


def askpass_helper() -> Path:
    """Tiny script that prints $USER_PASSWORD, so the password is never on a command line."""
    p = HOME / "bin" / "askpass.sh"
    p.parent.mkdir(parents=True, exist_ok=True)
    body = "#!/bin/sh\nprintf '%s\\n' \"$USER_PASSWORD\"\n"
    if not p.exists() or p.read_text() != body:
        p.write_text(body)
    p.chmod(stat.S_IRWXU)
    return p


def ssh_base(ex: Exec, *, identity: str | None = None, batch: bool | None = None) -> tuple[list[str], dict[str, str]]:
    if not ex.host:
        raise ConfigError("ssh execution mode needs a host")
    env: dict[str, str] = {}
    password = ex.auth == "password" and identity is None
    batch = (not password) if batch is None else batch
    kh = KNOWN_HOSTS
    strict = "accept-new"
    if ex.host_key:  # pinned: connection refused if it differs
        kh = Path(tempfile.mkdtemp(prefix="airlock-kh-")) / "known_hosts"
        kh.write_text(f"{ex.host} {ex.host_key}\n")
        strict = "yes"
    KNOWN_HOSTS.parent.mkdir(parents=True, exist_ok=True)
    cmd = ["ssh", "-o", f"BatchMode={'yes' if batch else 'no'}", "-o", f"StrictHostKeyChecking={strict}",
           "-o", f"UserKnownHostsFile={kh}", "-o", "HashKnownHosts=no", "-o", "ConnectTimeout=15",
           "-p", str(ex.port)]
    if identity:
        cmd += ["-i", identity, "-o", "IdentitiesOnly=yes", "-o", "PreferredAuthentications=publickey"]
    elif password:
        cmd += ["-o", "PreferredAuthentications=password,keyboard-interactive", "-o", "PubkeyAuthentication=no"]
        env = {"SSH_ASKPASS": str(askpass_helper()), "SSH_ASKPASS_REQUIRE": "force"}
    user = resolve(ex.user, "exec.user")
    cmd.append(f"{user}@{ex.host}" if user else ex.host)
    return cmd, env


def wrap(ex: Exec, argv: list[str], *, identity: str | None = None) -> Wrapped:
    """Turn an argv into the final command for the node's execution mode."""
    check_args(argv)
    if ex.mode == "direct":
        return Wrapped(list(argv))
    stdin = None
    remote = list(argv)
    if ex.mode == "ssh_sudo":
        pw = resolve(ex.sudo_password, "exec.sudo_password")   # none set: `sudo -n`
        if pw is None:
            remote = ["sudo", "-n"] + remote
        else:
            remote = ["sudo", "-S", "-p", ""] + remote
            stdin = (pw + "\n").encode()
    base, env = ssh_base(ex, identity=identity)
    return Wrapped(base + ["--", shlex.join(remote)], stdin, env)


def kubectl_argv(ex: Exec, args: list[str], context: str | None = None) -> list[str]:
    """kubectl argv for the mode: --context only applies where the kubeconfig is local."""
    out = [ex.kubectl_path]
    if ex.mode == "direct" and context:
        out += ["--context", context]
    if ex.kubeconfig:
        out += ["--kubeconfig", ex.kubeconfig]
    return out + args


def kube_token_argv(server: str, token: str, args: list[str]) -> list[str]:
    return ["kubectl", "--server", server, "--token", token] + args


def execute(w: Wrapped, *, timeout: float = 60, max_bytes: int = 256_000) -> Result:
    env = {**os.environ, **w.env}
    try:
        p = subprocess.run(w.cmd, input=w.stdin, capture_output=True, timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        return Result(124, "", f"timeout after {timeout}s")
    out = redact(p.stdout.decode(errors="replace"))[:max_bytes]
    err = redact(p.stderr.decode(errors="replace"))[:max_bytes]
    return Result(p.returncode, out, err)


def run(ex: Exec, argv: list[str], *, timeout: float = 60, **kw) -> Result:
    return execute(wrap(ex, argv, **kw), timeout=timeout)


def kube_token(node, timeout: float = 30) -> str:
    """Run the node's token_cmd (over ssh) and return the token; never written to disk."""
    if not node.kube or not node.kube.token_cmd:
        raise ConfigError(f"{node.name}: no kube.token_cmd")
    r = execute(Wrapped(shlex.split(node.kube.token_cmd)), timeout=timeout)
    if not r.ok:
        raise RuntimeError(f"token_cmd failed: {r.err.strip()}")
    return r.out.strip()
