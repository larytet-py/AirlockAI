"""PROD tab (SPEC 9.3): Kubernetes clusters from the local kubectl, Gateway sessions, approvals and query patterns."""
from __future__ import annotations

import html
import json
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from . import envs as E
from . import gwsession, session
from .audit import Audit
from .config import (HOME, ConfigError, claude_token_status, load_config, parse_kv, remove_claude_oauth_token,
                     save_claude_oauth_token)
from .patterns import PatternError

SID = re.compile(r"^[a-f0-9]{6,32}$")

CSS = """:root{color-scheme:light dark}body{font:14px system-ui;margin:0}table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid #8884;padding:.4rem;text-align:left;vertical-align:top}
.up{color:#2a9d4a}.down{color:#d33}button{padding:.2rem .6rem}.err{color:#d33;position:sticky;top:0;z-index:9;background:Canvas;padding:.4rem .6rem;border:1px solid #d33;border-radius:6px}
.err:empty{display:none}form{display:inline}.add input,.add select,.add textarea{margin:.2rem}.chips{display:flex;flex-wrap:wrap;gap:.15rem 1.2rem;align-items:center}.chip{white-space:nowrap}
.lbl{color:#888}[hidden]{display:none!important}.nm{cursor:text;border-bottom:1px dotted #888}.nm:hover{background:#8882}.warn{border:1px solid #c2410c;border-radius:6px;padding:.5rem .8rem;background:#c2410c18}
textarea{font:12px ui-monospace,monospace;width:100%;box-sizing:border-box}details{margin:.4rem 0}h2{margin-top:1.6rem}code{background:#8882;padding:0 .25rem;border-radius:3px}"""

PAGE = """<!doctype html><meta charset=utf-8><title>AirlockAI - PROD</title><style>{base_css}{css}{access_css}</style>
{nav}<main><p class=err>{error}</p>
<div class=warn><b>PROD: Gateway mode.</b> The agent in these sessions has no ssh, kubectl or database client. Its only reach is the MCP gateway of one
environment; credentials stay in the gateway container. Mutating tools are off unless you enable <code>approve_writes</code>, and then every call waits for you below.</div>
<h2 id=waiting>Waiting for approval <small class=lbl>(calls blocked right now, and new access agents ask for)</small></h2><div id=wait>{waiting}</div>
<h2>Clusters <small class=lbl>(from the local kubectl contexts and the config file)</small></h2>
<form id=ebulk method=post action=/prod/sessions class=add><b>Selected clusters:</b>
<button formaction=/prod/sessions onclick="return startingMsg(this)" title="unregistered contexts are registered first (direct, kubernetes read-only)">Start session on selected</button>
<button formaction=/prod/register>Register selected</button>
<button formaction=/prod/envs/bulk-delete onclick="return confirm('Remove the selected environments from the config? The clusters and your kubeconfig are not touched.')">Remove from list</button></form>
<table id=envs><tr><th><input type=checkbox id=eall title="select all"><th>Name <small class=lbl>(click to rename)</small><th>Status: reachable, nodes, latency<th>Links<th>Exec<th>Tools</tr>{envrows}</table>
<details><summary>Add environment</summary><form method=post action=/prod/envs class=add>
<input name=name placeholder="name (e.g. uat)" required pattern="[A-Za-z0-9][A-Za-z0-9_.\\-]{{0,63}}"> <input name=context list=ctxs placeholder="kube context"><datalist id=ctxs>{ctx_options}</datalist>
<select name=mode><option>direct<option>ssh<option>ssh_sudo</select> <input name=host placeholder="ssh host (ssh modes)"> <input name=user placeholder="user (default $USER_NAME)">
<br>Tools: {tool_checks}<br>
<label><input type=checkbox name=check value=1 checked> check first: <code>kubectl --context X get ns</code> (or the ssh variant)</label> <button>Add</button></form></details>
<p><a href=/prod>Rescan local kubectl contexts</a></p>
<h2>AI Sessions</h2>
<form id=sbulk method=post class=add><button formaction=/prod/sessions/bulk-stop onclick="return confirm('Stop selected sessions?')">Stop selected</button>
<button formaction=/prod/sessions/bulk-delete onclick="return confirm('Delete selected sessions? Running ones are stopped first.')">Delete selected</button>
<button formaction=/prod/sessions/prune>Remove all stopped</button> <span id=stamp class=lbl></span></form>
<table id=sess><tr><th><input type=checkbox id=all title="select all"><th>ID<th>Status<th>Container<th>Actions<th>CPU<th>Memory<th>Workspace<th>Environment<th>Tools<th>Audit</tr>{sessions}</table>
<h2>Query patterns <small class=lbl>(recently approved; the only queries the agent can run)</small></h2>
<div id=pwrap>{patterns}</div>
</main>
<script>
function startingMsg(b){{setTimeout(()=>{{b.disabled=true;b.textContent='Starting\\u2026 (15-40 s)'}},0);return true}}
document.getElementById('eall').onchange=e=>document.querySelectorAll('input[name=sel],input[name=ctx]').forEach(c=>c.checked=e.target.checked);
document.getElementById('all').onchange=e=>document.querySelectorAll('input[name=ssel]').forEach(c=>c.checked=e.target.checked);
async function etick(){{try{{const r=await fetch('/api/prod/stats');if(!r.ok)return;const d=await r.json();
  for(const [k,s] of Object.entries(d)){{const row=document.querySelector(`tr[data-env="${{k}}"]`);if(!row)continue;const q=n=>row.querySelector(`[data-n=${{n}}]`);
    q('dot').className='chip '+(s.up?'up':'down');q('dot').textContent=s.up?'\\u25cf up':'\\u25cf down';q('dot').title=s.error||'';
    q('info').textContent=s.up?((s.nodes!=null?s.nodes+' nodes, ':'')+s.ms+' ms'):(s.error||'').slice(0,90)}}}}catch(e){{}}}}
etick();setInterval(etick,30000);
async function stick(){{try{{const r=await fetch('/api/sessions/stats');if(!r.ok)return;const d=await r.json();
  for(const [sid,s] of Object.entries(d)){{const row=document.querySelector(`tr[data-sid="${{sid}}"]`);if(!row)continue;const c=row.querySelector('[data-f=container]'),life=row.dataset.life;
    c.className=s.running?'up':(life==='stopped'?'':'down');c.textContent=s.running?'\\u25cf running':(life==='stopped'?'\\u25cb not running':'\\u25cf NOT RUNNING');
    for(const f of ['cpu','mem','workspace'])row.querySelector(`[data-f=${{f}}]`).textContent=s[f]}}
  document.getElementById('stamp').textContent='updated '+new Date().toLocaleTimeString()}}catch(e){{}}}}
stick();setInterval(stick,5000);
function busy(w){{const a=document.activeElement;   // never refresh while you work in it
  return (w.contains(a)&&a!==document.body)||w.querySelector('input[type=checkbox]:checked,form.edf:not([hidden])')}}
async function wtick(){{try{{const w=document.getElementById('wait');if(busy(w))return;
  const r=await fetch('/prod/waiting-fragment');if(r.ok)w.innerHTML=await r.text()}}catch(e){{}}}}
setInterval(wtick,3000);
{access_js}
async function ptick(){{try{{const w=document.getElementById('pwrap');if(busy(w))return;
  const r=await fetch('/prod/patterns-fragment');if(r.ok)w.innerHTML=await r.text()}}catch(e){{}}}}
setInterval(ptick,5000);
</script>"""

def make_prod(app: FastAPI, config_path, nav_html, base_css: str, session_cells) -> None:
    from .ui_access import make_access
    e = html.escape
    cache: dict[str, tuple[float, dict]] = {}
    lock = threading.Lock()

    def tab_response(body: str) -> HTMLResponse:
        r = HTMLResponse(body)
        r.set_cookie("airlock_tab", "prod", samesite="strict")
        return r

    def back(fn, to: str = "/prod"):
        try:
            fn()
            return RedirectResponse(to, status_code=303)
        except (ConfigError, RuntimeError, PatternError, ValueError) as ex:
            path, _, frag = to.partition("#")
            return RedirectResponse(path + ("&" if "?" in path else "?") + "error=" + quote(str(ex)) + (f"#{frag}" if frag else ""), status_code=303)

    access = make_access(app, config_path, nav_html, base_css, back)

    # ------------------------------------------------------------------ rendering
    def env_rows(cfg) -> str:
        registered = E.environments(cfg)
        known_ctx = {x.kube_context for x in registered if x.kube_context}
        templates = (cfg.defaults or {}).get("links", {}) or {}
        rows = ""
        for env in registered:
            n = e(env.name)
            ex = env.exec_for("kubernetes")
            tools = " ".join(f'<span class=tag title="mode">{e(t)}:{e((env.tool(t) or {}).get("mode", "read"))}</span>' for t in env.tool_names()) or '<span class=lbl>none</span>'
            sec = E.secret_status(env)
            miss = [v for v, s in sec.items() if s == "missing"]
            secbit = (f'<br><small class=down>missing secrets: {e(", ".join(miss))}</small>' if miss else
                      (f'<br><small class=lbl>secrets present ({len(sec)})</small>' if sec else ""))
            tool_form = tools_form(env)
            links = " ".join(f'<a href="{e(u)}" target=_blank rel=noopener>{e(k)}</a>' for k, u in E.env_links(env, templates).items())
            kc = f'<br><small class=lbl>context {e(env.kube_context)}</small>' if env.kube_context else ""
            name = (f'<div class=nmwrap><b class=nm title="Click to rename" onclick="rn(this)">{n}</b>'
                    f'<form method=post action="/prod/envs/{n}/rename" hidden><input name=new value="{n}" size=22 required autocomplete=off '
                    f'spellcheck=false data-orig="{n}" pattern="[A-Za-z0-9][A-Za-z0-9_.\\-]{{0,63}}" onkeydown="rnKey(event,this)" onblur="rnCancel(this)"></form></div>{kc}')
            opts = "".join(f"<option{' selected' if m == ex.mode else ''}>{m}" for m in ("direct", "ssh", "ssh_sudo"))
            mode = (f'<form method=post action="/prod/envs/{n}/mode" class=add><select name=mode onchange="this.form.submit()">{opts}</select>'
                    f'<input name=host value="{e(ex.host or "")}" placeholder="ssh host" size=16></form>')
            status = (f'<div class=chips><span class=chip data-n=dot>&hellip;</span><span class=chip data-n=info class=lbl></span></div>'
                      if env.kube_context else '<span class=lbl>no kube context</span>')
            rows += (f'<tr data-env="{n}"><td><input type=checkbox name=sel value="{n}" form=ebulk><td>{name}'
                     f'<td>{status}<td>{links}<td>{mode}<td>{tools}{secbit}{tool_form}</tr>')
        for c in E.kubectl_contexts():
            if c in known_ctx:
                continue
            k = e(c)
            rows += (f'<tr data-env="{k}"><td><input type=checkbox name=ctx value="{k}" form=ebulk><td><b>{k}</b><br><span class=tag>local kubectl context, not registered</span>'
                     f'<td><div class=chips><span class=chip data-n=dot>&hellip;</span><span class=chip data-n=info></span></div><td><td colspan=2></tr>')
        return rows or '<tr><td colspan=6><span class=lbl>No kubectl contexts found and no environments in the config. Use "Add environment".</span></tr>'

    def tools_form(env: E.Environment) -> str:
        rows = ""
        for t in sorted(E.TOOLS):
            cur = env.tool(t)
            on = cur is not None
            mode = (cur or {}).get("mode", "read")
            rest = ",".join(f"{k}={'|'.join(v) if isinstance(v, list) else v}" for k, v in (cur or {}).items() if k not in ("mode", "exec", "commands") and not isinstance(v, dict))
            rows += (f'<div><label><input type=checkbox name="on_{t}" value=1 {"checked" if on else ""}> {t}</label> '
                     f'<select name="mode_{t}"><option {"selected" if mode == "read" else ""}>read<option {"selected" if mode == "approve_writes" else ""}>approve_writes</select> '
                     f'<input name="cfg_{t}" value="{e(rest)}" placeholder="k=v,k=v" size=40></div>')
        sec = E.secret_status(env)
        secrow = ""
        if sec:
            secrow = ("<div>Secrets: " + ", ".join(f"<code>{e(v)}</code> {'<span class=up>present</span>' if s == 'present' else '<span class=down>missing</span>'}"
                                                   for v, s in sec.items()) + "</div>")
        return (f'<details><summary>edit</summary><form method=post action="/prod/envs/{e(env.name)}/tools" class=add>{rows}<button>Save tools</button></form>{secrow}'
                f'<form method=post action="/prod/envs/{e(env.name)}/secret" class=add><input name=var placeholder="VAR (e.g. PG_DSN)" size=14 required>'
                f'<input type=password name=value placeholder="value (masked, stored 0600 in the secrets dir)" size=30 autocomplete=off required><button>Set secret</button></form></details>')

    def session_rows() -> str:
        out = ""
        for s in session.list_sessions():
            if s.get("mode") != "gateway":
                continue
            sid = e(s["id"])
            idcell, sshcmd = session_cells(s)
            links = (f'<a href=/sessions/{sid}/term target=_blank rel=noopener>shell</a> '
                     f'<a href="/sessions/{sid}/term?cmd=claude" target=_blank rel=noopener>claude</a>' if s["status"] == "running" else "")
            err = f'<br><small class=down>{e(s["error"])}</small>' if s.get("error") else ""
            kube = ""
            if (s.get("kube") or s.get("kube_error")) and s["status"] == "running":
                exp = (s.get("kube") or {}).get("expires")
                if s.get("kube_error"):
                    kube = f'<br><small class=down>k8s: {e(s["kube_error"])}</small> '
                else:
                    left = "expired" if exp and exp < time.time() else ("until " + time.strftime("%a %H:%M", time.localtime(exp)) if exp else "")
                    kube = f'<br><small class="{"down" if exp and exp < time.time() + 3600 else "lbl"}">k8s token {left}</small> '
                kube += (f'<form method=post action="/prod/sessions/{sid}/kube-refresh">'
                         f'<button title="get a new token on this machine (may open the browser to sign in)">refresh</button></form>')
            if s.get("sql_error") and s["status"] == "running":
                kube += f'<br><small class=down>sql: {e(s["sql_error"])}</small>'
            out += (f'<tr data-sid="{sid}" data-life="{e(s["status"])}"><td><input type=checkbox name=ssel value="{sid}" form=sbulk><td>{idcell}<td>{e(s["status"])}{err}'
                    f'<td data-f=container>&hellip;<td>{links}{sshcmd}<td data-f=cpu>-<td data-f=mem>-<td data-f=workspace>-<td>{e(s.get("environment", ""))}'
                    f'<td>{e(", ".join(s.get("tools", [])))}{kube}<td><a href=/audit/{sid} target=_blank>log</a></tr>')
        return out

    # ------------------------------------------------------------------ pages
    @app.get("/prod", response_class=HTMLResponse)
    def prod_page(error: str = ""):
        cfg = load_config(config_path)
        ctx = "".join(f'<option value="{e(c)}">' for c in E.kubectl_contexts())
        checks = " ".join(f'<label><input type=checkbox name="on_{t}" value=1 {"checked" if t == "kubernetes" else ""}> {t}</label>' for t in sorted(E.TOOLS))
        body = PAGE.format(base_css=base_css, css=CSS, nav=nav_html("prod"), error=e(error), envrows=env_rows(cfg), ctx_options=ctx, tool_checks=checks,
                           waiting=access["waiting"](), sessions=session_rows(), patterns=access["fragment"](),
                           access_css=access["css"], access_js=access["js"])
        return tab_response(body)

    @app.get("/api/prod/stats")
    def prod_stats():
        cfg = load_config(config_path)
        ctxs = {x.name: x.kube_context for x in E.environments(cfg) if x.kube_context}
        for c in E.kubectl_contexts():
            ctxs.setdefault(c, c)
        now = time.time()
        todo = [(k, c) for k, c in ctxs.items() if now - cache.get(c, (0, {}))[0] > 20]
        with ThreadPoolExecutor(max_workers=max(1, min(8, len(todo)))) as pool:
            for (k, c), res in zip(todo, pool.map(lambda kc: E.context_status(kc[1]), todo)):
                with lock:
                    cache[c] = (now, res)
        return {k: cache[c][1] for k, c in ctxs.items() if c in cache}

    @app.get("/audit/{sid}", response_class=HTMLResponse)
    def audit_page(sid: str):
        if not SID.match(sid):
            raise HTTPException(404)
        f = HOME / "audit" / f"{sid}.jsonl"
        if not f.exists():
            raise HTTPException(404)
        rows = ""
        for line in f.read_text().splitlines()[-300:]:
            r = json.loads(line)
            rows += (f'<tr><td>{time.strftime("%H:%M:%S", time.localtime(r["ts"]))}<td>{e(r["actor"])}<td>{e(r["kind"])}'
                     f'<td><code style="white-space:pre-wrap">{e(json.dumps(r["payload"], default=str)[:600])}</code></tr>')
        ok = Audit(sid).verify()
        return (f'<!doctype html><meta charset=utf-8><title>audit {e(sid)}</title><style>{CSS}body{{margin:1rem 2rem}}</style><h1>Audit {e(sid)}</h1>'
                f'<p>Hash chain: {"<span class=up>intact</span>" if ok else "<b class=down>BROKEN</b>"} &middot; <a href=/prod>back</a></p>'
                f'<table><tr><th>Time<th>Actor<th>Kind<th>Detail</tr>{rows}</table>')

    # ------------------------------------------------------------------ environment actions
    def tools_from_form(form) -> dict[str, dict]:
        out = {}
        for t in E.TOOLS:
            if form.get(f"on_{t}"):
                cfg = E.parse_tool_settings(str(form.get(f"cfg_{t}", "")))
                mode = str(form.get(f"mode_{t}", "read"))
                if mode not in ("read", "approve_writes"):
                    raise ConfigError("mode is read or approve_writes")
                if t in ("postgres", "elastic", "redis", "kubernetes", "kubectl_commands", "remote_ops", "airflow", "disk", "django"):
                    cfg["mode"] = mode
                out[t] = cfg
        return out

    @app.post("/prod/envs")
    async def env_add(request: Request):
        form = await request.form()

        def go():
            spec = E.env_spec(str(form.get("name", "")), context=str(form.get("context", "")), mode=str(form.get("mode", "direct")),
                              host=str(form.get("host", "")), user=str(form.get("user", "")), tools=tools_from_form(form) or {"kubernetes": {"mode": "read"}},
                              )
            env = E.Environment.model_validate(spec)
            if form.get("check") and ("kubernetes" in env.tool_names() or env.sql_via()):
                err = E.check_cluster(env)
                if err:
                    raise ConfigError(f"check failed, nothing saved ({err}). Untick the check to save anyway.")
            E.add_environment(config_path, spec)
        return back(go)

    @app.post("/prod/register")
    def register(ctx: list[str] = Form([]), context: str = Form("")):
        names = ctx + ([context] if context else [])

        def go():
            if not names:
                raise ConfigError("select at least one unregistered context")
            known = E.kubectl_contexts()
            if any(c not in known for c in names):
                raise ConfigError("unknown kubectl context")
            for c in names:
                E.add_environment(config_path, E.env_spec(E.sanitise_name(c), context=c))
        return back(go)

    @app.post("/prod/envs/{name}/rename")
    def env_rename(name: str, new: str = Form(...)):
        def go():
            busy = [s["id"] for s in gwsession.gateway_sessions() if s.get("environment") == name]
            if busy:
                raise ConfigError(f"session(s) {', '.join(busy)} use {name}: stop them first")
            E.rename_environment(config_path, name, new)
        return back(go)

    @app.post("/prod/envs/{name}/mode")
    def env_mode(name: str, mode: str = Form(...), host: str = Form("")):
        return back(lambda: E.set_env_exec(config_path, name, mode, host))

    @app.post("/prod/envs/bulk-delete")
    def env_bulk_delete(sel: list[str] = Form([])):
        def go():
            busy = {n: [s["id"] for s in gwsession.gateway_sessions() if s.get("environment") == n] for n in sel}
            busy = {n: v for n, v in busy.items() if v}
            if busy:
                raise ConfigError("stop sessions first: " + "; ".join(f"{n} ({', '.join(v)})" for n, v in busy.items()))
            E.remove_environments(config_path, sel)
        return back(go)

    @app.post("/prod/envs/{name}/tools")
    async def env_tools(name: str, request: Request):
        form = await request.form()
        def go():
            tools = tools_from_form(form)
            cur = E.environment(load_config(config_path), name).tool("kubectl_commands") or {}
            if "kubectl_commands" in tools and cur.get("commands"):
                tools["kubectl_commands"]["commands"] = cur["commands"]   # defined in the config file, not editable in this form
            E.set_env_tools(config_path, name, tools)
        return back(go)

    @app.post("/prod/envs/{name}/secret")
    def env_secret(name: str, var: str = Form(...), value: str = Form(...)):
        return back(lambda: E.write_secret(E.environment(load_config(config_path), name), var.strip(), value))

    # ------------------------------------------------------------------ sessions
    @app.post("/prod/sessions")
    def start(env: list[str] = Form([]), sel: list[str] = Form([]), ctx: list[str] = Form([])):
        names = env + sel

        def go():
            known = E.kubectl_contexts()
            for c in ctx:  # a local kubectl context that is not registered yet: register it, then start
                if c not in known:
                    raise ConfigError("unknown kubectl context")
                nm = E.sanitise_name(c)
                E.add_environment(config_path, E.env_spec(nm, context=c))
                names.append(nm)
            if not names:
                raise ConfigError("select at least one cluster")
            cfg = load_config(config_path)
            for n in names:
                gwsession.start_gateway_session(cfg, config_path, n)
        return back(go)

    def ids(ssel):
        if not all(SID.match(x) for x in ssel):
            raise HTTPException(404)
        for x in ssel:
            if session.load_state(x).get("mode") != "gateway":
                raise HTTPException(404)
        return ssel

    @app.post("/prod/sessions/bulk-stop")
    def bulk_stop(ssel: list[str] = Form([])):
        def go():
            if not ssel:
                raise ConfigError("select at least one session")
            cfg = load_config(config_path)
            for sid in ids(ssel):
                if session.load_state(sid)["status"] in ("running", "starting", "needs_cleanup"):
                    session.stop_session(cfg, sid)
        return back(go)

    @app.post("/prod/sessions/bulk-delete")
    def bulk_delete(ssel: list[str] = Form([])):
        return back(lambda: session.delete_many(ids(ssel), load_config(config_path)))

    @app.post("/prod/sessions/{sid}/kube-refresh")
    def kube_refresh(sid: str):
        if not SID.match(sid):
            raise HTTPException(404)
        return back(lambda: gwsession.refresh_kube(load_config(config_path), sid))

    @app.post("/prod/sessions/prune")
    def prune():
        def go():
            for s in session.list_sessions():
                if s.get("mode") == "gateway" and s["status"] == "stopped":
                    session.delete_session(s["id"])
        return back(go)

    # ------------------------------------------------------------------ query patterns
    return None
