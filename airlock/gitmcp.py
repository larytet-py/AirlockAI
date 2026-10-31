"""Git MCP for sandbox sessions (SPEC 6.4): the agent edits a read-write source folder, this server commits and pushes it.

Runs on the host, outside the agent container, with the user's own git credentials, which never enter the container.
One tool, `git.commit_push(repo, message)`: no AI in the path, the commit message is the agent's text, the decision is code.

The folder is agent-writable, so everything the agent could plant in it is treated as hostile:
- `.git` must be a real directory (not a file or symlink that points elsewhere), without `commondir`; git is run with an explicit
  --git-dir/--work-tree, hooks disabled, and the repository config must contain only keys from SAFE_CONFIG (no filters, aliases,
  ssh commands, url rewrites, includes);
- the remote is pinned when the session starts (`origin`'s URL as the host saw it); the push goes to that URL, never to what
  the repo's config says at call time;
- only the currently checked-out branch is pushed, as `HEAD:refs/heads/<branch>`, never forced.
"""
from __future__ import annotations

import os
import re
import signal
import socket
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from .config import redact

PORT_RELAY = 8766   # the egress container relays this port to the host server, so the agent only talks to `egress`
SAFE_CONFIG = re.compile(
    r"^(core\.(repositoryformatversion|filemode|bare|logallrefupdates|ignorecase|precomposeunicode|symlinks)"
    r"|remote\.[^.\n]+\.(url|fetch)|branch\..+\.(remote|merge|rebase|vscode-merge-base)|user\.(name|email)|gc\..+|pull\..+|init\..+)$",
    re.I)
MAX_MESSAGE = 4000
SCHEMA = {"type": "object", "additionalProperties": False, "required": ["message"], "properties": {
    "repo": {"type": "string", "description": "Folder name under /src (the part after /src/). Optional when only one folder is writable."},
    "message": {"type": "string", "description": "The commit message, used as written."}}}


@dataclass
class Tool:
    name: str
    description: str
    schema: dict


def _git(path: str, *args: str, input: str | None = None, timeout: float = 120) -> subprocess.CompletedProcess:
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_SSH_COMMAND": os.environ.get("GIT_SSH_COMMAND") or "ssh -o BatchMode=yes"}
    for k in ("GIT_DIR", "GIT_WORK_TREE", "GIT_CONFIG", "GIT_CONFIG_COUNT", "GIT_INDEX_FILE", "GIT_COMMON_DIR"):
        env.pop(k, None)
    return subprocess.run(["git", f"--git-dir={path}/.git", f"--work-tree={path}", "-c", "core.hooksPath=/dev/null",
                           "-c", "core.fsmonitor=false", "-c", "protocol.ext.allow=never", *args],
                          capture_output=True, text=True, input=input, timeout=timeout, env=env)


def check_layout(path: str) -> None:
    """Raise ValueError unless `path` is a plain repository whose config holds only safe keys."""
    g = Path(path) / ".git"
    if g.is_symlink() or not g.is_dir():
        raise ValueError(".git is not a plain directory")
    if (g / "commondir").exists():
        raise ValueError(".git/commondir is present")
    p = _git(path, "config", "--local", "--list", "-z")
    if p.returncode:
        raise ValueError("cannot read the repository config")
    for item in p.stdout.split("\0"):
        key = item.split("\n", 1)[0]
        if key and not SAFE_CONFIG.match(key):
            raise ValueError(f"repository config key {key!r} is not allowed")


def agent_gitconfig() -> str:
    """Global git config for the agent container: your own identity if set on this host, `safe.directory` so folders owned by
    another uid are not refused. Repository config still wins over it."""
    def get(k):
        return subprocess.run(["git", "config", "--global", k], capture_output=True, text=True).stdout.strip()
    name, email = get("user.name") or "Airlock Agent", get("user.email") or "airlock-agent@localhost"
    q = lambda v: '"' + v.replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ") + '"'
    return f"[safe]\n\tdirectory = *\n[user]\n\tname = {q(name)}\n\temail = {q(email)}\n"


def pin(path: str) -> str | None:
    """`origin`'s URL if `path` is a plain git repository with one (read on the host before the agent runs), else None."""
    try:
        check_layout(path)
        url = _git(path, "config", "--get", "remote.origin.url").stdout.strip()
    except (ValueError, OSError, subprocess.SubprocessError):
        return None
    return url if url and not url.startswith("-") and not url.lower().startswith("ext::") else None


def pins(sources: list[dict]) -> dict[str, dict]:
    """{mount name: {path, url}} for the writable source folders that are git repositories with an origin."""
    out = {}
    for m in sources:
        if m["ro"]:
            continue
        url = pin(m["host"])
        if url:
            out[m["container"].rsplit("/", 1)[-1]] = {"path": m["host"], "url": url}
    return out


class GitTool:
    def __init__(self, sid: str, repos: dict[str, dict], audit):
        self.sid, self.repos, self.audit = sid, repos, audit

    def list_tools(self) -> list[Tool]:
        names = ", ".join(f"/src/{n}" for n in self.repos)
        return [Tool("git.commit_push", "Commit every change in a writable source folder with your message and push the branch that is "
                     f"checked out there to its origin. Folders: {names}. No force push, no other branch, no other remote.", SCHEMA)]

    def call(self, name: str, args: dict | None = None) -> dict:
        args = args or {}
        try:
            if name != "git.commit_push":
                raise ValueError(f"unknown tool {name}")
            bad = set(args) - set(SCHEMA["properties"])
            if bad:
                raise ValueError(f"unknown argument(s): {', '.join(sorted(bad))}")
            msg = args.get("message")
            if not isinstance(msg, str) or not msg.strip():
                raise ValueError("message is required")
            if len(msg) > MAX_MESSAGE:
                raise ValueError(f"message is longer than {MAX_MESSAGE} characters")
            repo = args.get("repo") or (next(iter(self.repos)) if len(self.repos) == 1 else None)
            repo = repo.removeprefix("/src/").strip("/") if isinstance(repo, str) else None
            if repo not in self.repos:
                raise ValueError(f"repo must be one of: {', '.join(self.repos)}")
        except ValueError as e:
            self.audit.log("gitmcp", "tool.rejected", tool=name, args=args, error=str(e))
            return {"ok": False, "error": str(e)}
        r = self.repos[repo]
        self.audit.log("gitmcp", "tool.intent", tool=name, repo=repo, path=r["path"], remote=r["url"], message=msg)
        try:
            out = self.commit_push(r["path"], r["url"], msg)
        except (ValueError, OSError, subprocess.SubprocessError) as e:
            err = redact(str(e))
            self.audit.log("gitmcp", "tool.result", tool=name, ok=False, repo=repo, error=err)
            return {"ok": False, "error": err}
        self.audit.log("gitmcp", "tool.result", tool=name, ok=True, repo=repo, **out["audit"])
        return {"ok": True, "result": redact(out["text"])}

    def commit_push(self, path: str, url: str, message: str) -> dict:
        check_layout(path)
        branch = _git(path, "symbolic-ref", "--short", "-q", "HEAD").stdout.strip()
        if not branch:
            raise ValueError("HEAD is detached: check out a branch first")
        if _git(path, "check-ref-format", "--branch", branch).returncode:
            raise ValueError(f"unusable branch name {branch!r}")
        steps = []
        for cmd in (["add", "-A"],):
            p = _git(path, *cmd)
            if p.returncode:
                raise ValueError(f"git {cmd[0]} failed: {p.stderr.strip()[:500]}")
        committed = _git(path, "diff", "--cached", "--quiet").returncode != 0
        if committed:
            p = _git(path, "commit", "-F", "-", input=f"{message.strip()}\n\nAirlock-Session: {self.sid}\n")
            if p.returncode:
                raise ValueError(f"git commit failed: {(p.stderr or p.stdout).strip()[:500]}")
            steps.append("committed")
        else:
            steps.append("nothing to commit")
        sha = _git(path, "rev-parse", "--short", "HEAD").stdout.strip()
        p = _git(path, "push", url, f"HEAD:refs/heads/{branch}", timeout=300)
        if p.returncode:
            raise ValueError(f"git push failed ({steps[0]}, {sha}): {p.stderr.strip()[:800]}")
        steps.append("pushed")
        return {"text": f"{', '.join(steps)}: {branch} at {sha}\n{p.stderr.strip()}",
                "audit": {"branch": branch, "commit": sha, "committed": committed}}


# ---------------------------------------------------------------- process management (controller side)
def free_port(bind: str) -> int:
    with socket.socket() as s:
        s.bind((bind, 0))
        return s.getsockname()[1]


def start(sid: str, repos: dict[str, dict], token_sha256: str, bind: str, d: Path) -> dict:
    """Start the server as a detached host process bound to `bind` (the egress network's gateway address)."""
    import json
    import time
    port = free_port(bind)
    (d / "gitmcp.json").write_text(json.dumps(repos))
    (d / "gitmcp.json").chmod(0o600)
    log = open(d / "gitmcp.log", "ab")
    p = subprocess.Popen([sys.executable, "-m", "airlock.gitmcp"], stdout=log, stderr=log, start_new_session=True,
                         env={**os.environ, "AIRLOCK_SESSION": sid, "AIRLOCK_TOKEN_HASH": token_sha256, "BIND": bind,
                              "PORT": str(port), "REPOS_FILE": str(d / "gitmcp.json")})
    deadline = time.time() + 15
    while time.time() < deadline:
        if p.poll() is not None:
            raise RuntimeError(f"git MCP exited: see {d / 'gitmcp.log'}")
        try:
            socket.create_connection((bind, port), timeout=1).close()
            return {"pid": p.pid, "bind": bind, "port": port}
        except OSError:
            time.sleep(0.2)
    stop(p.pid)
    raise RuntimeError(f"git MCP did not come up: see {d / 'gitmcp.log'}")


def stop(pid: int | None) -> None:
    """SIGTERM the server if the pid is still a git MCP (a reused pid is left alone)."""
    if not pid:
        return
    try:
        cmd = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
        if b"airlock.gitmcp" in cmd:
            os.kill(pid, signal.SIGTERM)
    except (OSError, ProcessLookupError):
        pass


def instructions(repos: dict[str, dict]) -> str:
    return ("\n## Git\n\nYou have no git credentials. To publish work, call the MCP tool `git.commit_push` {repo, message}: it commits "
            "everything in that folder with your message and pushes the checked-out branch to origin (never forced, no other branch). "
            "Folders: " + ", ".join(f"`/src/{n}`" for n in repos) + ". Check out the branch you want to push first.\n")


def main() -> None:  # pragma: no cover - host process entry point
    import json
    import uvicorn
    from .audit import Audit
    from .gwserver import make_app

    sid = os.environ["AIRLOCK_SESSION"]
    gt = GitTool(sid, json.loads(Path(os.environ["REPOS_FILE"]).read_text()), Audit(sid))
    gt.audit.log("gitmcp", "gitmcp.start", repos=list(gt.repos))
    app = make_app(gt, os.environ["AIRLOCK_TOKEN_HASH"], instructions=instructions(gt.repos).strip(), name="airlock-git")
    uvicorn.run(app, host=os.environ["BIND"], port=int(os.environ["PORT"]), log_level="warning")


if __name__ == "__main__":  # pragma: no cover
    main()
