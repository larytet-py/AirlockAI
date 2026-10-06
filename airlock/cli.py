"""airlock command line."""
from __future__ import annotations

import argparse
import os
import socket
import subprocess
import sys
from pathlib import Path

from . import ops, runner, session
from .config import (ConfigError, export_config, load_config, missing_vars, secret_values)

ROOT = Path(__file__).resolve().parent.parent


def cmd_validate(a, cfg) -> int:
    miss = missing_vars(cfg)
    if miss:
        print("undefined environment variables: " + ", ".join(miss), file=sys.stderr)
        return 1
    from . import envs, patterns
    ev = envs.environments(cfg)
    for raw in cfg.query_patterns:
        p = patterns.Pattern.model_validate(raw)
        for env in [x for x in ev if p.in_scope(x.name)] or [None]:
            pol = patterns.Policy() if env is None else patterns.Policy(
                schemas=(env.tool("postgres") or {}).get("schemas"), indices=(env.tool("elastic") or {}).get("indices"),
                key_prefixes=(env.tool("redis") or {}).get("key_prefixes"))
            try:
                patterns.validate(p, pol)
            except patterns.PatternError as e:
                print(f"query pattern {p.name}: {e}", file=sys.stderr)
                return 1
    print(f"ok: {len(cfg.nodes)} nodes, {len(cfg.operations)} operations, "
          f"{len(cfg.environments)} environments, {len(cfg.query_patterns)} query patterns")
    return 0


def health(node, timeout: float = 5) -> dict:
    ex = node.ssh_exec()
    try:
        with socket.create_connection((ex.host, ex.port), timeout=timeout) as s:
            banner = s.recv(64).decode(errors="replace").strip()
        return {"name": node.name, "reachable": True, "banner": banner}
    except OSError as e:
        return {"name": node.name, "reachable": False, "banner": str(e)}


def cmd_nodes(a, cfg) -> int:
    from .config import add_node, node_spec
    if a.action == "add":
        if len(a.args) != 2:
            raise ConfigError("usage: airlock nodes add NAME HOST [--exec-mode M] [--user U]")
        add_node(a.config, node_spec(a.args[0], a.args[1], port=a.port, user=a.user,
                                     mode=a.exec_mode))
        print(f"added {a.args[0]}")
        return 0
    if a.action == "import-aws":
        from . import awsimport
        if not awsimport.available():
            raise ConfigError("the AWS CLI is not installed on this host")
        found = awsimport.new_instances(cfg, awsimport.find_instances(
            cfg, user=a.aws_user, regions=a.region or None, profile=a.profile, include_stopped=not a.running_only))
        if not found:
            print("no new instances found for this user")
            return 0
        taken = {n.name for n in cfg.nodes}
        from .config import add_node
        for i in found:
            spec = awsimport.to_spec(i, cfg, taken)
            taken.add(spec["name"])
            print(f"{'adding ' if a.yes else 'found  '} {spec['name']:28} {i.id} {i.state:8} {spec['host']}  (tag: {i.matched_on})")
            if a.yes:
                add_node(a.config, spec)
        if not a.yes:
            print("dry run: nothing written. Re-run with --yes to add these nodes to the config.")
        return 0
    if a.action == "tag":
        if not a.args:
            raise ConfigError("usage: airlock nodes tag NAME [NAME...] [--label l] [--unlabel l]   (labels only: tags were removed)")
        session.edit_meta_checked(a.config, a.args, add_labels=a.label, remove_labels=a.unlabel)
        print(f"updated {', '.join(a.args)}")
        return 0
    if a.action == "remove":
        session.remove_node_checked(a.config, a.args[0] if a.args else "")
        print(f"removed {a.args[0]}")
        return 0
    if a.action == "set-mode":
        if len(a.args) != 2:
            raise ConfigError("usage: airlock nodes set-mode NAME direct|ssh|ssh_sudo")
        session.set_node_mode(a.config, a.args[0], a.args[1])
        print(f"{a.args[0]}: exec mode is now {a.args[1]}")
        return 0
    for n in cfg.nodes:
        h = health(n) if a.action == "health" else {}
        extra = f"  {'up' if h['reachable'] else 'DOWN'} {h['banner']}" if h else ""
        labels = f" [{','.join(n.labels)}]" if n.labels else ""
        print(f"{n.name:20} {n.host:42} exec={n.exec.mode:8}{labels}{extra}")
    return 0


def cmd_run(a, cfg) -> int:
    node = cfg.node(a.node)
    ex = node.ssh_exec().model_copy(update={"auth": "key", "mode": node.exec.mode})
    r = runner.run(ex, a.command)
    sys.stdout.write(r.out)
    sys.stderr.write(r.err)
    return r.rc


def cmd_session(a, cfg) -> int:
    if a.action == "name":
        from . import sshaccess
        if not a.id:
            raise ConfigError("usage: airlock session name ID [NAME]  (empty NAME clears it)")
        nm = sshaccess.set_name(a.id, " ".join(a.command))
        print(f"session {a.id}: " + (f"named {nm}; ssh {nm}" if nm else "name cleared"))
        return 0
    if a.action == "start" and a.env:
        from . import gwsession
        for _ in range(a.count):
            st = gwsession.start_gateway_session(cfg, a.config, a.env, model_login=not a.no_model_login)
            print(f"session {st['id']} running (gateway); environment: {a.env}; tools: {', '.join(st['tools'])}")
            print(f"attach: airlock session attach {st['id']}")
        return 0
    if a.action == "start":
        if not a.nodes:
            raise ConfigError("session start needs --nodes NAME[,NAME...]")
        names = a.nodes.split(",")
        st = session.start_session(cfg, names, model_login=not a.no_model_login, mirrors=a.mirrors)
        print(f"session {st['id']} running; nodes: {', '.join(names)}")
        print(f"egress allowlist: {', '.join(st['allow'])}")
        print(f"attach: airlock session attach {st['id']}")
    elif a.action == "stop":
        st = session.stop_session(cfg, a.id)
        print(f"session {a.id}: {st['status']}")
        for p in st["needs_cleanup"]:
            print(f"  needs cleanup on {p['node']}: {p['error']}")
        return 1 if st["needs_cleanup"] else 0
    elif a.action == "rm":
        if a.force:
            for p in session.discard_session(a.id):
                print(f"  not removed on {p['node']} (may remain): {p['error']}. Run `airlock sweep` once it is reachable")
        else:
            session.delete_session(a.id)
        print(f"session {a.id} removed" + (" (forced)" if a.force else ""))
    elif a.action == "prune":
        print("removed:", ", ".join(session.prune_sessions()) or "nothing")
    elif a.action == "list":
        for s in session.list_sessions():
            print(f"{s['id']}  {s.get('name', ''):16} {s['status']:14} " + (f"gateway:{s.get('environment')}" if s.get("mode") == "gateway" else ",".join(s["nodes"])))
    elif a.action == "attach":
        cmd = a.command or session.CLAUDE_CMD
        if cmd[0] == "bash":  # a shell starts in /src (the mounted source), falling back to /workspace
            cmd = ["bash", "-lc", "cd /src 2>/dev/null || cd /workspace; exec bash -l"]
        os.execvp("docker", ["docker", "exec", "-it", "-e", "CLAUDE_CODE_DISABLE_ALTERNATE_SCREEN=1", f"air-agent-{a.id}", *cmd])
    return 0


def cmd_ops(a, cfg) -> int:
    catalog = ops.load_operations(cfg)
    if a.action == "list":
        for o in catalog.values():
            ps = ",".join(p.name for p in o.params)
            print(f"{o.name:16} {o.risk:12} {o.description}" + (f"  params: {ps}" if ps else ""))
        return 0
    if a.name not in catalog:
        raise ConfigError(f"unknown operation {a.name!r}; try: airlock ops list")
    if not a.nodes:
        raise ConfigError("ops run needs --nodes NAME[,NAME...]")
    nodes = [cfg.node(n) for n in a.nodes.split(",")]
    params = dict(kv.split("=", 1) for kv in a.param)
    rc = 0
    for name, r in ops.run_operation(cfg, catalog[a.name], nodes, params, confirm=a.yes).items():
        print(f"=== {name} (rc={r.rc})")
        print(r.out, end="")
        if r.err.strip():
            print(r.err, end="", file=sys.stderr)
        rc = rc or r.rc
    return rc


def prompt_claude_token() -> bool:
    """Ask for a `claude setup-token` token and save it. Empty input skips; returns whether a token was saved."""
    import getpass

    from .config import ConfigError, save_claude_oauth_token
    print("To get a token: run `claude setup-token` in another terminal, sign in in the browser, and copy the token it prints.")
    while True:
        t = getpass.getpass("Paste the token (input is hidden, empty to skip): ")
        if not t.strip():
            return False
        try:
            f = save_claude_oauth_token(t)
        except ConfigError as e:
            print(f"error: {e}")
            continue
        print(f"saved to {f} (mode 600). New sandbox sessions sign in with it automatically; running sessions are unchanged.")
        return True


def cmd_auth(a, cfg) -> int:
    from .config import check_claude_token, claude_oauth_token
    if a.action == "status":
        t = claude_oauth_token()
        print("claude token:", f"set, {check_claude_token(t)} (checked with the API)" if t
              else "not set (run: claude setup-token, then: airlock auth claude-token)")
        return 0
    prompt_claude_token()
    return 0


def cmd_sweep(a, cfg) -> int:
    print("retried:", session.retry_cleanup(cfg))
    for node, sids in session.sweep(cfg).items():
        print(f"{node}: removed stale {sids}")
    return 0


def cmd_image(a, cfg) -> int:
    uid = ["--build-arg", f"UID={os.getuid()}"]
    if not a.gateway:
        return subprocess.call(["docker", "build", *uid, "-t", session.IMAGE, str(ROOT / "agent-image")])
    from . import gwsession  # Mode 2: the agent image without ssh/kubectl, and the gateway image that holds the credentials
    rc = subprocess.call(["docker", "build", *uid, "-f", str(ROOT / "agent-image" / "Dockerfile.gateway"), "-t", gwsession.AGENT_IMAGE,
                          str(ROOT / "agent-image")])
    return rc or subprocess.call(["docker", "build", *uid, "-f", str(ROOT / "gateway-image" / "Dockerfile"), "-t", gwsession.GATEWAY_IMAGE, str(ROOT)])


def cmd_ssh(a, cfg) -> int:
    from . import sshaccess
    if a.action == "setup":
        print(sshaccess.setup_include())
        for line in sshaccess.refresh_sessions():  # re-install the key in running agent containers (repairs a replaced key)
            print(line)
        print("then:  ssh <session id or name>   (user agent; run `airlock session list`)")
        return 0
    print(sshaccess.write_config())
    return 0


def cmd_envs(a, cfg) -> int:
    from . import envs
    if a.action == "list":
        reg = envs.environments(cfg)
        for e in reg:
            ex = e.exec_for("kubernetes")
            tools = ",".join(f"{t}:{(e.tool(t) or {}).get('mode', 'read')}" for t in e.tool_names())
            miss = [v for v, s in envs.secret_status(e).items() if s == "missing"]
            print(f"{e.name:16} ctx={e.kube_context or '-':20} exec={ex.mode:9} tools={tools}" + (f"  missing secrets: {','.join(miss)}" if miss else ""))
        known = {e.kube_context for e in reg}
        for c in envs.kubectl_contexts():
            if c not in known:
                print(f"{c:16} (local kubectl context, not registered: airlock envs add {envs.sanitise_name(c)} --context {c})")
        return 0
    if a.action == "add":
        if len(a.args) != 1:
            raise ConfigError("usage: airlock envs add NAME [--context C] [--exec-mode M] [--host H] [--user U] [--tool name[:k=v,..]] [--no-check]")
        tools = {}
        for t in a.tool or ["kubernetes"]:
            name, _, rest = t.partition(":")
            tools[name] = envs.parse_tool_settings(rest)
        spec = envs.env_spec(a.args[0], context=a.context, mode=a.exec_mode, host=a.host, user=a.user, tools=tools)
        env = envs.Environment.model_validate(spec)
        if not a.no_check and "kubernetes" in env.tool_names():
            err = envs.check_cluster(env)
            if err:
                raise ConfigError(f"check failed: {err} (use --no-check to save anyway)")
        envs.add_environment(a.config, spec)
        print(f"added environment {a.args[0]}")
        return 0
    if a.action == "set-mode":
        if len(a.args) != 2:
            raise ConfigError("usage: airlock envs set-mode NAME direct|ssh|ssh_sudo [--host H]")
        envs.set_env_exec(a.config, a.args[0], a.args[1], a.host)
        print(f"{a.args[0]}: exec mode is now {a.args[1]}")
        return 0
    if a.action == "remove":
        envs.remove_environments(a.config, a.args)
        print("removed " + ", ".join(a.args))
        return 0
    if a.action == "check":
        for e in ([envs.environment(cfg, n) for n in a.args] or envs.environments(cfg)):
            err = envs.check_cluster(e)
            print(f"{e.name:16} {'ok' if not err else 'FAILED: ' + err}")
        return 0
    return 0


def cmd_patterns(a, cfg) -> int:
    from . import envs
    from .patternstore import PatternStore
    from .patterns import Pattern, PatternError
    import yaml
    st = PatternStore()
    if a.action == "list":
        for p in st.list():
            sc = p.scope if p.scope == "global" else ",".join(p.scope)
            flag = "proposed" if p.proposed_by_agent else ("on" if p.enabled else "off")
            tpl = p.template if isinstance(p.template, str) else str(p.template)
            print(f"{p.name:24} {p.kind:14} {flag:8} v{st.version(p.name)} scope={sc} risk={p.risk}  {tpl[:70]}")
        return 0
    if a.action == "export":
        print(st.export_yaml(), end="")
        return 0
    if a.action == "import":
        data = yaml.safe_load(Path(a.args[0]).read_text()) if a.args else {}
        items = data.get("query_patterns") if isinstance(data, dict) else data
        if not isinstance(items, list):
            raise ConfigError("expected a list under query_patterns")
        for raw in items:
            Pattern.model_validate(raw)
        print("imported:", ", ".join(st.import_list(items, by="cli")) or "nothing changed")
        return 0
    if a.action == "sync":  # config file -> store
        print("synced:", ", ".join(st.import_list(list(cfg.query_patterns), by="config")) or "nothing changed")
        return 0
    name = a.args[0] if a.args else ""
    if a.action in ("enable", "disable"):
        st.set_enabled(name, a.action == "enable")
    elif a.action == "approve":
        st.approve(name)
    elif a.action in ("rm", "reject"):
        st.remove(name)
    print(f"{name}: {a.action} ok")
    return 0


def cmd_approvals(a, cfg) -> int:
    from . import gwsession
    if a.action == "list":
        for x in gwsession.pending_approvals():
            print(f"{x['session']}/{x['id']}  {x['environment']:12} {x['tool']:28} {x['risk']:12} {x['args']}")
        return 0
    if len(a.args) != 1 or "/" not in a.args[0]:
        raise ConfigError("usage: airlock approvals approve|reject|session SESSION/ID")
    sid, aid = a.args[0].split("/", 1)
    gwsession.decide(sid, aid, {"approve": "approved", "reject": "rejected", "session": "session"}[a.action])
    print("recorded")
    return 0


def cmd_test(a, cfg) -> int:
    """Policy self-checks: forbidden calls through the gateway code must fail and never reach a connector."""
    from . import envs
    from .selftest import run_selftest
    targets = [envs.environment(cfg, a.env)] if a.env else envs.environments(cfg)
    bad = 0
    for e in targets:
        fails = run_selftest(e, cfg)
        print(f"{e.name}: {'ok, forbidden calls refused' if not fails else str(len(fails)) + ' FAILURES'}")
        for f in fails:
            print("  " + f)
        bad += len(fails)
    return 1 if bad else 0


def cmd_ui(a, cfg) -> int:
    import uvicorn

    from .config import check_claude_token, claude_oauth_token, claude_token_status
    from .ui import make_app
    state = claude_token_status()[0]
    if state in ("env", "file") and check_claude_token(claude_oauth_token() or "") == "invalid":
        print("The saved Claude token was rejected (revoked or expired), so agent sessions would start unauthorized.")
        if state == "env":
            print("It comes from the CLAUDE_CODE_OAUTH_TOKEN variable: unset or replace it, then restart.")
        elif sys.stdin.isatty():
            prompt_claude_token()
    elif state == "none" and not (Path.home() / ".claude" / ".credentials.json").exists() and sys.stdin.isatty():
        print("Claude is not signed in: no saved token and no login on this machine, so agent sessions would start unauthorized.")
        prompt_claude_token()
    uvicorn.run(make_app(a.config), host="127.0.0.1", port=a.port, log_level="info")
    return 0


def cmd_export(a, cfg) -> int:
    print(export_config(cfg), end="")
    return 0


def main(argv=None) -> None:
    p = argparse.ArgumentParser(prog="airlock")
    p.add_argument("--config", help="config file (default $AIRLOCK_CONFIG or ~/.airlock/airlock.yaml)")
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("config")
    c.add_argument("action", choices=["validate", "export"])
    n = sub.add_parser("nodes")
    n.add_argument("action", choices=["list", "health", "add", "remove", "set-mode", "tag", "import-aws"])
    n.add_argument("args", nargs="*")
    n.add_argument("--label", action="append", default=[], help="tag: add a label")
    n.add_argument("--unlabel", action="append", default=[], help="tag: remove a label")
    n.add_argument("--aws-user", metavar="NAME", help="import-aws: user to match (default $USER_NAME)")
    n.add_argument("--region", action="append", default=[], help="import-aws: AWS region (repeatable)")
    n.add_argument("--profile", help="import-aws: AWS profile")
    n.add_argument("--running-only", action="store_true", help="import-aws: skip stopped instances")
    n.add_argument("--yes", action="store_true", help="import-aws: write the nodes (default is a dry run)")
    n.add_argument("--port", type=int, default=22)
    n.add_argument("--user", default="")
    n.add_argument("--exec-mode", default="ssh", choices=["direct", "ssh", "ssh_sudo"])
    r = sub.add_parser("run", help="run a command on a node with its execution mode")
    r.add_argument("node")
    r.add_argument("command", nargs="+")
    s = sub.add_parser("session")
    s.add_argument("action", choices=["start", "stop", "list", "attach", "rm", "prune", "name"])
    s.add_argument("id", nargs="?")
    s.add_argument("--nodes")
    s.add_argument("--force", action="store_true", help="rm: discard a stuck session without removing its key and sudo rule from the node")
    s.add_argument("--env", help="start a Gateway (Mode 2) session on this environment")
    s.add_argument("--count", type=int, default=1, help="with --env: number of agent sessions (each has its own gateway and audit trail)")
    s.add_argument("--no-model-login", action="store_true", help="do not copy Claude subscription credentials")
    s.add_argument("--mirrors", action="store_true", help="allow pypi/npm egress")
    s.add_argument("command", nargs="*")
    o = sub.add_parser("ops", help="named operations on nodes")
    o.add_argument("action", choices=["list", "run"])
    o.add_argument("name", nargs="?")
    o.add_argument("--nodes")
    o.add_argument("--param", action="append", default=[], metavar="K=V")
    o.add_argument("--yes", action="store_true", help="confirm a destructive operation")
    au = sub.add_parser("auth", help="sign the sandbox agent in automatically")
    au.add_argument("action", choices=["claude-token", "status"])
    sh = sub.add_parser("ssh", help="ssh into agent containers by session id or name")
    sh.add_argument("action", choices=["setup", "config"])
    sub.add_parser("sweep")
    im = sub.add_parser("image")
    im.add_argument("--gateway", action="store_true", help="build the Mode 2 images (gateway and agent without ssh/kubectl)")
    ev = sub.add_parser("envs", help="Mode 2 environments (kubectl contexts)")
    ev.add_argument("action", choices=["list", "add", "set-mode", "remove", "check"])
    ev.add_argument("args", nargs="*")
    ev.add_argument("--context", default="")
    ev.add_argument("--exec-mode", default="direct", choices=["direct", "ssh", "ssh_sudo"])
    ev.add_argument("--host", default="")
    ev.add_argument("--user", default="")
    ev.add_argument("--tool", action="append", default=[], metavar="NAME[:k=v,..]")
    ev.add_argument("--no-check", action="store_true")
    pt = sub.add_parser("patterns", help="query patterns (SQL, Elasticsearch, Redis)")
    pt.add_argument("action", choices=["list", "export", "import", "sync", "enable", "disable", "approve", "reject", "rm"])
    pt.add_argument("args", nargs="*")
    ap = sub.add_parser("approvals", help="mutating calls waiting for a human")
    ap.add_argument("action", choices=["list", "approve", "reject", "session"])
    ap.add_argument("args", nargs="*")
    te = sub.add_parser("test", help="policy self-checks of the gateway")
    te.add_argument("--env")
    u = sub.add_parser("ui")
    u.add_argument("--port", type=int, default=8800)
    a = p.parse_args(argv)
    try:
        cfg = None if a.cmd == "ssh" else load_config(a.config)   # ssh setup needs no config file
        code = {"config": lambda: cmd_validate(a, cfg) if a.action == "validate" else cmd_export(a, cfg),
                "nodes": lambda: cmd_nodes(a, cfg), "run": lambda: cmd_run(a, cfg),
                "session": lambda: cmd_session(a, cfg), "auth": lambda: cmd_auth(a, cfg), "ops": lambda: cmd_ops(a, cfg), "sweep": lambda: cmd_sweep(a, cfg),
                "image": lambda: cmd_image(a, cfg), "envs": lambda: cmd_envs(a, cfg), "ssh": lambda: cmd_ssh(a, cfg), "patterns": lambda: cmd_patterns(a, cfg),
                "approvals": lambda: cmd_approvals(a, cfg), "test": lambda: cmd_test(a, cfg), "ui": lambda: cmd_ui(a, cfg)}[a.cmd]()
    except (ConfigError, RuntimeError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        code = 2
    sys.exit(code)


if __name__ == "__main__":
    main()
