"""Sandbox sessions (SPEC 4 Mode 1): per-session key, egress allowlist, agent container, mandatory cleanup."""
from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import time
from pathlib import Path
from urllib.parse import urlparse

from . import nodeaccess, sources, sshaccess
from .audit import Audit
from .config import HOME, Config, ConfigError, Node, claude_oauth_token, redact, resolve
from .runner import KNOWN_HOSTS

IMAGE = "airlock-agent:latest"
EGRESS_IMAGE = "python:3.12-slim"
SESSIONS = HOME / "sessions"
PROXY = "http://egress:3128"
# Hosts Claude Code needs: API, and sign-in / OAuth (claude.ai, claude.com, platform.claude.com).
MODEL_API = ["api.anthropic.com", "claude.ai", "claude.com", "platform.claude.com"]
PROXY_SRC = Path(__file__).with_name("egress_proxy.py")
# `claude` for attach and the UI: starts in /src next to the code like a shell does, so it cannot pick up /workspace/CLAUDE.md;
# pass the session instructions (and a gateway session's MCP server) explicitly, as the ssh profile does.
CLAUDE_CMD = ["bash", "-c",
              'cd /src 2>/dev/null || cd /workspace; '
              'if [ -f /workspace/.mcp.json ]; then exec claude --mcp-config /workspace/.mcp.json '
              '--append-system-prompt "$(cat /workspace/AIRLOCK_ENV.md 2>/dev/null)" "$@"; '
              'elif [ -f /workspace/AIRLOCK_NODES.md ]; then exec claude --append-system-prompt "$(cat /workspace/AIRLOCK_NODES.md)" "$@"; fi; '
              'exec claude "$@"',
              "claude", "--dangerously-skip-permissions"]


def docker(*args: str, check: bool = True, input: str | None = None, env: dict | None = None) -> subprocess.CompletedProcess:
    p = subprocess.run(["docker", *args], capture_output=True, text=True, input=input, env=env)
    if check and p.returncode:
        msg = f"docker {' '.join(args[:2])} failed: {p.stderr.strip()}"
        if m := re.search(r"Unable to find image '(airlock-[\w-]+)", p.stderr):
            flag = " --gateway" if m.group(1) in ("airlock-gateway", "airlock-agent-gw") else ""
            msg += f"\nhint: image {m.group(1)} is not built yet, run: uv run airlock image{flag}"
        raise RuntimeError(msg)
    return p


def state_path(sid: str) -> Path:
    return SESSIONS / sid / "session.json"


def load_state(sid: str) -> dict:
    p = state_path(sid)
    if not p.exists():
        raise ConfigError(f"unknown session {sid}")
    return json.loads(p.read_text())


def save_state(st: dict) -> None:
    p = state_path(st["id"])
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(st, indent=2))


def list_sessions() -> list[dict]:
    return [json.loads(p.read_text()) for p in sorted(SESSIONS.glob("*/session.json"))] if SESSIONS.exists() else []


def live_ids() -> set[str]:
    return {s["id"] for s in list_sessions() if s.get("status") in ("running", "starting")}


def resolve_ip(host: str) -> str:
    return socket.gethostbyname(host)


def host_key_lines(host: str) -> list[str]:
    if not KNOWN_HOSTS.exists():
        return []
    p = subprocess.run(["ssh-keygen", "-F", host, "-f", str(KNOWN_HOSTS)], capture_output=True, text=True)
    return [ln for ln in p.stdout.splitlines() if ln and not ln.startswith("#")]


def instructions(nodes: list[Node]) -> str:
    lines = ["# AirlockAI session nodes", "",
             "You run in a sandbox. Only the model API and these nodes are reachable. ssh keys and passwordless",
             "sudo are already set up for this session; never ask for a password.", ""]
    for n in nodes:
        mode = n.exec.mode
        how = {"direct": "run commands locally", "ssh": f"airlock-run {n.name} -- <command>",
               "ssh_sudo": f"airlock-run {n.name} -- <command>  (runs with sudo -n)"}[mode]
        lines.append(f"- **{n.name}**: `{how}`; or `ssh {n.name}` and `sudo -n ...`")
        if n.kube:
            lines.append(f"  - kubernetes server: {n.kube.server} (the token is read over ssh on the node)")
        for k, u in n.urls.items():
            lines.append(f"  - {k}: {u}")
    return "\n".join(lines) + "\n"


def write_session_files(st: dict, nodes: list[Node], ips: dict[str, str]) -> None:
    d = SESSIONS / st["id"]
    cfg = []
    for n in nodes:
        ex = n.ssh_exec()
        user = resolve(ex.user, f"node {n.name} exec.user") if ex.user else None   # ssh does not expand ${USER_NAME} in `User`
        if user is not None and not nodeaccess.USER_RE.match(user):
            raise ConfigError(f"node {n.name}: unsafe ssh user {user!r}")
        # the IP is an alias too, so `ssh <ip>` also goes through the egress proxy
        cfg.append(f"Host {n.name} {ips[n.name]}\n  HostName {ips[n.name]}\n  Port {ex.port}\n" + (f"  User {user}\n" if user else "") +
                   f"  IdentityFile /airlock/id_ed25519\n  IdentitiesOnly yes\n  StrictHostKeyChecking yes\n"
                   f"  UserKnownHostsFile /airlock/known_hosts\n  HostKeyAlias {ex.host}\n"
                   f"  ProxyCommand nc -X connect -x egress:3128 %h %p\n  ServerAliveInterval 30\n")
    (d / "ssh_config").write_text("\n".join(cfg))
    kh = [ln for n in nodes for ln in host_key_lines(n.ssh_exec().host)]
    (d / "known_hosts").write_text("\n".join(kh) + "\n")
    (d / "nodes.json").write_text(json.dumps([{"name": n.name, "mode": n.exec.mode} for n in nodes]))
    ws = Path(st["workspace"])
    (ws / "AIRLOCK_NODES.md").write_text(instructions(nodes) + sources.instructions(st.get("sources", [])))
    claude_md = ws / "CLAUDE.md"
    if not claude_md.exists():
        claude_md.write_text("Read AIRLOCK_NODES.md first: it lists the nodes of this session and how to run commands on them.\n")
    for f in ("ssh_config", "known_hosts", "nodes.json"):
        (d / f).chmod(0o644)


def refresh_instructions(cfg: Config, sid: str) -> None:
    """Regenerate per-session files after a node's execution mode changed in the UI."""
    st = load_state(sid)
    nodes = [cfg.node(n) for n in st["nodes"]]
    write_session_files(st, nodes, st["ips"])


def allowlist(cfg: Config, nodes: list[Node], ips: dict[str, str], mirrors: bool) -> list[str]:
    allow = [f"{h}:443" for h in (cfg.defaults.get("egress", {}).get("model_api") or MODEL_API)]
    for n in nodes:
        allow.append(f"{ips[n.name]}:{n.ssh_exec().port}")
        if n.kube:
            u = urlparse(n.kube.server)
            allow.append(f"{u.hostname}:{u.port or 443}")
    if mirrors:
        allow += ["pypi.org:443", "files.pythonhosted.org:443", "registry.npmjs.org:443"]
    return sorted(set(allow))


def model_login_args(args: list[str], d: Path, audit: Audit, model_login: bool) -> str | None:
    """Add the model login to a `docker run` argument list. Returns the OAuth token (to pass in the environment) if any."""
    token = claude_oauth_token() if model_login else None
    if token:
        # Passed by name only (`-e NAME`), so the value is never on a command line. It outranks any login file,
        # which is why the host's own login is not copied: two machines sharing one refresh token break each other.
        args += ["-e", "CLAUDE_CODE_OAUTH_TOKEN"]
        audit.log("controller", "model_login", method="oauth_token")
    elif model_login:
        src = Path.home() / ".claude" / ".credentials.json"
        if src.exists():
            cred = d / "claude-credentials.json"
            shutil.copyfile(src, cred)
            cred.chmod(0o600)
    return token


# The agent's user settings, as on the developer's machine (added at the developer's explicit request): the classic renderer
# (`/tui default`), so terminal selection and Ctrl+Shift+C work, and the SessionStart hook that turns the
# `tengu_pewter_brook` feature flag off in ~/.claude.json.
CLAUDE_SETTINGS = {
    "tui": "default",
    "hooks": {"SessionStart": [{"hooks": [{
        "type": "command", "async": True,
        "command": "jq '.cachedGrowthBookFeatures.tengu_pewter_brook = false' ~/.claude.json > ~/.claude.json.tmp && mv ~/.claude.json.tmp ~/.claude.json"}]}]},
}


def apply_claude_settings(ag: str) -> None:
    """Write ~/.claude/settings.json in the agent container (keeps keys already there, ours win). Never fails a session."""
    code = ("import json,os,sys;f=os.path.expanduser('~/.claude/settings.json');os.makedirs(os.path.dirname(f),exist_ok=True);"
            "cur=json.load(open(f)) if os.path.exists(f) else {};cur.update(json.load(sys.stdin));json.dump(cur,open(f,'w'),indent=2)")
    subprocess.run(["docker", "exec", "-i", ag, "python3", "-c", code], input=json.dumps(CLAUDE_SETTINGS), text=True, capture_output=True)


def finish_model_login(ag: str, d: Path, token: str | None) -> None:
    apply_claude_settings(ag)
    if (d / "claude-credentials.json").exists():
        docker("exec", ag, "sh", "-c", "mkdir -p ~/.claude && cp /airlock/claude-credentials.json ~/.claude/.credentials.json")
    if token or (d / "claude-credentials.json").exists():
        # Interactive `claude` runs first-run onboarding (login picker) and a folder-trust prompt even when a token
        # is set; `claude -p` skips both. The session is already the trust boundary, so pre-accept them.
        seed = ('import json,os;f=os.path.expanduser("~/.claude.json");'
                'j=json.load(open(f)) if os.path.exists(f) else {};j["hasCompletedOnboarding"]=True;'
                'j.setdefault("projects",{}).setdefault("/workspace",{})["hasTrustDialogAccepted"]=True;json.dump(j,open(f,"w"))')
        docker("exec", ag, "python3", "-c", seed, check=False)


def start_session(cfg: Config, node_names: list[str], *, model_login: bool = True, mirrors: bool = False,
                  image: str = IMAGE, ttl: str | None = None) -> dict:
    nodes = [cfg.node(n) for n in node_names]
    if not nodes:
        raise ConfigError("a session needs at least one node")
    nodeaccess.require_login()
    sid = secrets.token_hex(4)
    d = SESSIONS / sid
    d.mkdir(parents=True)
    ws = HOME / "workspaces" / sid
    ws.mkdir(parents=True)
    audit = Audit(sid)
    st = {"id": sid, "status": "starting", "mode": "sandbox", "nodes": node_names, "image": image,
          "workspace": str(ws), "started_at": time.time(), "containers": [], "networks": [], "needs_cleanup": [],
          # snapshot (references only, no secrets): lets stop revoke access even if the node vanished from the config
          "node_specs": {n.name: n.model_dump(mode="json", exclude_none=True) for n in nodes}}
    save_state(st)
    audit.log("controller", "session.start", nodes=node_names)
    try:
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", f"airlock:{sid}", "-f", str(d / "id_ed25519")],
                       check=True)
        pub = (d / "id_ed25519.pub").read_text()
        ips = {n.name: resolve_ip(n.ssh_exec().host) for n in nodes}
        st["ips"] = ips
        st["sources"] = sources.mounts(sandbox=True, nodes=node_names)
        for n in nodes:
            acc = nodeaccess.enable_access(n, sid, pub, str(d / "id_ed25519"), ttl=ttl, audit=audit)
            if not acc.ready:
                raise RuntimeError(f"{n.name}: {acc.detail}")
            st.setdefault("access", {})[n.name] = {"expires": acc.expires}
            save_state(st)
        write_session_files(st, nodes, ips)
        allow = allowlist(cfg, nodes, ips, mirrors)
        st["allow"] = allow
        internal, outbound = f"air-{sid}", f"air-out-{sid}"
        docker("network", "create", "--internal", internal)
        docker("network", "create", outbound)
        st["networks"] = [internal, outbound]
        eg = f"air-egress-{sid}"
        docker("run", "-d", "--name", eg, "--network", outbound, "--user", "65534:65534", "--read-only",
               "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "-e", f"ALLOW={','.join(allow)}",
               "-v", f"{PROXY_SRC}:/egress_proxy.py:ro", EGRESS_IMAGE, "python", "/egress_proxy.py")
        st["containers"].append(eg)
        docker("network", "connect", "--alias", "egress", internal, eg)
        ag = f"air-agent-{sid}"
        env = {"HTTPS_PROXY": PROXY, "HTTP_PROXY": PROXY, "https_proxy": PROXY, "http_proxy": PROXY,
               "NO_PROXY": "egress", "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1", "HOME": "/home/agent", "AIRLOCK_SESSION": sid,
               "CLAUDE_CODE_DISABLE_ALTERNATE_SCREEN": "1"}   # classic renderer: normal terminal selection and copy
        args = ["run", "-d", "--name", ag, "--network", internal, "--user", f"{os.getuid()}:{os.getgid()}",
                "--read-only", "--tmpfs", "/tmp", "--tmpfs", f"/home/agent:uid={os.getuid()},gid={os.getgid()}",
                "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "512",
                "-v", f"{d}:/airlock:ro", "-v", f"{ws}:/workspace", *sources.docker_args(st["sources"])]
        token = model_login_args(args, d, audit, model_login)
        for k, v in env.items():
            args += ["-e", f"{k}={v}"]
        docker(*args, image, "sleep", "infinity", env={**os.environ, "CLAUDE_CODE_OAUTH_TOKEN": token} if token else None)
        st["containers"].append(ag)
        finish_model_login(ag, d, token)
        st["ssh"] = sshaccess.provision(sid)
        st["status"] = "running"
        audit.log("controller", "session.running", allow=allow, containers=st["containers"])
    except Exception as e:
        st["error"] = redact(str(e))
        save_state(st)
        audit.log("controller", "session.error", error=st["error"])
        stop_session(cfg, sid)
        raise
    save_state(st)
    sshaccess.write_config()
    return st


def stop_session(cfg: Config, sid: str) -> dict:
    """Mandatory cleanup: revoke node access, remove containers and networks, delete the key."""
    st = load_state(sid)
    audit = Audit(sid)
    st["status"] = "stopping"
    save_state(st)
    for c in st.get("containers", []):
        docker("rm", "-f", c, check=False)
    for n in st.get("networks", []):
        docker("network", "rm", n, check=False)
    pending = []
    for name in st["nodes"]:
        try:
            try:
                node = cfg.node(name)
            except ConfigError:  # renamed or removed by hand-editing the file: use the snapshot taken at start
                spec = st.get("node_specs", {}).get(name)
                if not spec:
                    raise
                node = Node.model_validate(spec)
            ok, detail = nodeaccess.revoke_access(node, sid, audit)
        except Exception as e:  # node removed from config, unreachable, ...
            ok, detail = False, str(e)
        if not ok:
            pending.append({"node": name, "error": redact(detail)})
    st["needs_cleanup"] = pending
    st["status"] = "needs_cleanup" if pending else "stopped"
    st["ended_at"] = time.time()
    d = SESSIONS / sid
    for f in d.glob("id_ed25519*"):
        f.unlink()
    for f in d.glob("claude-credentials.json"):
        f.unlink()
    save_state(st)
    audit.log("controller", "session." + st["status"], pending=pending)
    sshaccess.write_config()
    return st


def delete_session(sid: str) -> None:
    """Remove a finished session's record and workspace. Audit logs are kept (append-only history)."""
    st = load_state(sid)
    if st["status"] != "stopped":
        raise ConfigError(f"session {sid} is {st['status']}: stop it first so the node access is revoked")
    shutil.rmtree(SESSIONS / sid)
    shutil.rmtree(st.get("workspace") or "", ignore_errors=True)


def discard_session(sid: str) -> list[dict]:
    """Force removal of a stuck session whose node cannot be reached (needs_cleanup / stopping).

    Containers and networks are removed and the session record and workspace are deleted, but the key and sudo rule are NOT
    removed from the node. Returns what may still be there, `[{"node", "error"}]`, and writes it to the audit log. The key
    line carries an expiry marker and `airlock sweep` removes leftovers once the node is reachable. A running or starting
    session is refused: stop it first."""
    st = load_state(sid)
    if st["status"] in ("running", "starting"):
        raise ConfigError(f"session {sid} is {st['status']}: stop it first")
    left = st.get("needs_cleanup") or [{"node": n, "error": "not verified"} for n in st.get("nodes", [])
                                       if st["status"] != "stopped"]
    for c in st.get("containers", []):
        docker("rm", "-f", c, check=False)
    for n in st.get("networks", []):
        docker("network", "rm", n, check=False)
    Audit(sid).log("controller", "session.discarded", forced=True, node_access_may_remain=left)
    shutil.rmtree(SESSIONS / sid)
    shutil.rmtree(st.get("workspace") or "", ignore_errors=True)
    sshaccess.write_config()
    return left


def prune_sessions() -> list[str]:
    done = []
    for st in list_sessions():
        if st["status"] == "stopped":
            delete_session(st["id"])
            done.append(st["id"])
    return done


def sessions_using(node: str) -> list[str]:
    return [s["id"] for s in list_sessions() if node in s["nodes"] and s["status"] in ("running", "starting", "needs_cleanup")]


def set_node_mode(config_path, name: str, mode: str) -> Config:
    """Change a node's execution mode in the config file and regenerate the instructions of running sessions."""
    from .config import set_exec_mode
    cfg = set_exec_mode(config_path, name, mode)
    for sid in sessions_using(name):
        try:
            refresh_instructions(cfg, sid)
        except Exception:
            pass
    return cfg


def rename_node_checked(config_path, old: str, new: str) -> Config:
    """Rename a node and carry live sessions along: their records, and the ssh config / instructions the agent sees.

    The agent only reads names from files the controller generates, so nothing in a running session depends on the
    old name once those are rewritten. A session that is starting or stopping is left alone: try again in a moment."""
    from .config import rename_node
    new = new.strip()
    if new == old:
        return rename_node(config_path, old, new)
    sessions = [s for s in list_sessions() if old in s["nodes"] and s["status"] in ("running", "starting", "stopping", "needs_cleanup")]
    transient = [s["id"] for s in sessions if s["status"] in ("starting", "stopping")]
    if transient:
        raise ConfigError(f"session(s) {', '.join(transient)} using {old} are starting or stopping: try again in a moment")
    cfg = rename_node(config_path, old, new)
    sources.rename_node(old, new)
    try:
        for st in sessions:
            st["nodes"] = [new if n == old else n for n in st["nodes"]]
            for key in ("ips", "access", "node_specs"):
                if old in st.get(key, {}):
                    st[key][new] = st[key].pop(old)
            if new in st.get("node_specs", {}):
                st["node_specs"][new]["name"] = new
            st["needs_cleanup"] = [{**p, "node": new} if p["node"] == old else p for p in st.get("needs_cleanup", [])]
            save_state(st)
    except Exception:
        rename_node(config_path, new, old)  # could not update the sessions: undo, never leave them pointing at nothing
        sources.rename_node(new, old)
        raise
    for st in sessions:
        if st["status"] == "running" and st.get("ips"):
            try:
                write_session_files(st, [cfg.node(n) for n in st["nodes"]], st["ips"])
            except Exception:
                pass  # best effort: regenerated on the next refresh
    return cfg


def remove_node_checked(config_path, name: str) -> Config:
    return remove_nodes_checked(config_path, [name])


def remove_nodes_checked(config_path, names: list[str]) -> Config:
    """Group delete: removes the free nodes in one validated write; nodes used by a live session are skipped and reported."""
    from .config import load_config, remove_nodes
    if not names:
        raise ConfigError("select at least one node")
    busy = {n: sessions_using(n) for n in names if sessions_using(n)}
    free = [n for n in names if n not in busy]
    cfg = remove_nodes(config_path, free) if free else load_config(config_path)
    for n in free:
        sources.reset_node(n)
    if busy:
        detail = "; ".join(f"{n} (session {', '.join(s)})" for n, s in busy.items())
        raise ConfigError(f"deleted {len(free)}; not deleted (stop sessions first): {detail}")
    return cfg


def edit_meta_checked(config_path, names: list[str], **kw) -> Config:
    """Labels do not affect policy, so they can change under a live session."""
    from .config import edit_meta
    return edit_meta(config_path, names, **kw)


def human_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return ""


def dir_size(path: str) -> int:
    total = 0
    for root, _, files in os.walk(path):
        for f in files:
            try:
                total += os.lstat(os.path.join(root, f)).st_size
            except OSError:
                pass
    return total


def session_stats() -> dict[str, dict]:
    """Live view per session: are the containers actually up, CPU and memory of the agent, workspace disk use.

    One `docker inspect` and one `docker stats` call for all sessions, so it stays cheap enough to poll."""
    sessions = list_sessions()
    live = [s for s in sessions if s["status"] in ("running", "starting", "needs_cleanup", "stopping")]
    names = [n for s in live for n in (f"air-agent-{s['id']}", f"air-egress-{s['id']}")]
    up: set[str] = set()
    if names:
        p = docker("inspect", "--format", "{{.Name}} {{.State.Running}}", *names, check=False)
        up = {ln.split()[0].lstrip("/") for ln in p.stdout.splitlines() if ln.endswith(" true")}
    agents = [f"air-agent-{s['id']}" for s in live if f"air-agent-{s['id']}" in up]
    stats: dict[str, tuple[str, str]] = {}
    if agents:
        p = docker("stats", "--no-stream", "--format", "{{.Name}}|{{.CPUPerc}}|{{.MemUsage}}", *agents, check=False)
        for ln in p.stdout.splitlines():
            name, _, rest = ln.partition("|")
            cpu, _, mem = rest.partition("|")
            stats[name] = (cpu, mem.split("/")[0].strip())
    out = {}
    for s in sessions:
        sid = s["id"]
        agent_up = f"air-agent-{sid}" in up
        cpu, mem = stats.get(f"air-agent-{sid}", ("", ""))
        ws = s.get("workspace")
        out[sid] = {"running": agent_up, "egress_up": f"air-egress-{sid}" in up,
                    "cpu": cpu or "-", "mem": mem or "-",
                    "workspace": human_bytes(dir_size(ws)) if ws and os.path.isdir(ws) else "-"}
    return out


def delete_many(ids: list[str], cfg: Config | None = None) -> list[str]:
    """Group delete. With `cfg`, running sessions are stopped first (node access revoked) and then deleted; a session whose
    node cleanup fails stays listed as needs_cleanup so the key and sudo rule are never forgotten. Without `cfg`,
    running sessions are skipped and reported."""
    if not ids:
        raise ConfigError("select at least one session")
    skipped = []
    for sid in ids:
        try:
            if cfg and state_path(sid).exists() and load_state(sid)["status"] in ("running", "starting"):
                st = stop_session(cfg, sid)
                if st["status"] != "stopped":
                    bad = "; ".join(f"{p['node']}: {p['error']}" for p in st["needs_cleanup"])
                    skipped.append(f"{sid} (stopped, but cleanup on the node failed: {bad}. Retry Stop, the key and sudo rule are still there)")
                    continue
            delete_session(sid)
        except ConfigError as e:
            skipped.append(f"{sid} ({load_state(sid)['status']})" if state_path(sid).exists() else str(e))
    if skipped:
        raise ConfigError(f"deleted {len(ids) - len(skipped)}; not deleted: {', '.join(skipped)}")
    return ids


def retry_cleanup(cfg: Config) -> list[str]:
    """Retry revocation for sessions stuck in needs_cleanup."""
    done = []
    for st in list_sessions():
        if st["status"] == "needs_cleanup":
            if stop_session(cfg, st["id"])["status"] == "stopped":
                done.append(st["id"])
    return done


def sweep(cfg: Config) -> dict[str, list[str]]:
    """Controller-start sweeper: remove airlock markers whose session is gone or expired."""
    live = live_ids()
    removed: dict[str, list[str]] = {}
    for n in cfg.nodes:
        try:
            stale = nodeaccess.stale_sessions(n, live)
        except Exception as e:
            removed[n.name] = [f"unreachable: {e}"]
            continue
        for sid in stale:
            nodeaccess.revoke_access(n, sid)
        if stale:
            removed[n.name] = stale
    return removed


def exec_in(sid: str, *cmd: str, timeout: float = 60) -> subprocess.CompletedProcess:
    p = subprocess.run(["docker", "exec", f"air-agent-{sid}", *cmd], capture_output=True, text=True, timeout=timeout)
    p.stdout, p.stderr = redact(p.stdout), redact(p.stderr)
    return p
