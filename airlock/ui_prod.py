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
from . import gwsession, kubecreds, session
from .audit import Audit
from .config import (HOME, ConfigError, claude_token_status, load_config, parse_kv, remove_claude_oauth_token,
                     save_claude_oauth_token)
from .patterns import PatternError
from .ui_kit import KIT_CSS, bar_btn, bulk_bar, chip, edit_name, kebab, kit_tail, menu, mi_act, mi_post, post_btn

SID = re.compile(r"^[a-f0-9]{6,32}$")

CSS = """:root{color-scheme:light dark}body{font:14px system-ui;margin:0}table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid #8884;padding:.4rem;text-align:left;vertical-align:top}
.up{color:#2a9d4a}.down{color:#d33}button{padding:.2rem .6rem}.err{color:#d33;position:sticky;top:0;z-index:9;background:Canvas;padding:.4rem .6rem;border:1px solid #d33;border-radius:6px}
.err:empty{display:none}.okmsg{color:#2a9d4a;padding:.4rem .6rem;border:1px solid #2a9d4a;border-radius:6px}.okmsg:empty{display:none}form{display:inline}.add input,.add select,.add textarea{margin:.2rem}.chips{display:flex;flex-wrap:wrap;gap:.15rem 1.2rem;align-items:center}.chip{white-space:nowrap}
.lbl{color:#888}[hidden]{display:none!important}.nm{cursor:text;border-bottom:1px dotted #888}.nm:hover{background:#8882}.warn{border:1px solid #c2410c;border-radius:6px;padding:.5rem .8rem;background:#c2410c18}
textarea{font:12px ui-monospace,monospace;width:100%;box-sizing:border-box}details{margin:.4rem 0}h2{margin-top:1.6rem}code{background:#8882;padding:0 .25rem;border-radius:3px}"""

PAGE = """<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>AirlockAI - PROD</title><style>{base_css}{css}{access_css}{kit_css}</style>
{nav}<main><p class=err>{error}</p><p class=okmsg>{info}</p>
<h1 style="font-size:1.05rem;margin:0 0 .3rem">PROD &middot; Gateway</h1>
<div class=warn><b>The agent here has no ssh, kubectl or database client.</b> Its only reach is the MCP gateway of one environment; credentials stay in the
gateway container. Mutating tools are off unless you set <code>approve_writes</code>, and then every write waits for you below.</div>
<h2 id=waiting>Waiting for you</h2><div id=wait>{waiting}</div>
<h2>Clusters <span class=hint>from local kubectl contexts and the config file</span></h2>
<form id=ebulk method=post hidden></form>
<div class=tablewrap id=envscroll><table id=envs aria-label=Clusters><thead><tr><th style="width:2rem"><input type=checkbox class=selall data-for=env aria-label="Select all clusters">
<th>Cluster<th>Status<th>Tools <span class=hint style="text-transform:none;letter-spacing:0">(click to cycle)</span><th>Links<th>Sessions<th style="width:2.5rem"></tr></thead><tbody>{envrows}</tbody></table></div>
<details><summary class=btn style="display:inline-block;margin-top:.5rem">Add environment</summary><p style="margin:.4rem 0"><form method=post action=/prod/rescan style="display:inline"><button class=btn>Rescan local kubectl contexts</button></form>
<span class=lbl>every kubectl context is an environment; a rescan adds new ones</span></p>
<form method=post action=/prod/envs class=add>
<input name=name placeholder="name (e.g. uat)" required pattern="[A-Za-z0-9][A-Za-z0-9_.\\-]{{0,63}}" aria-label=Name> <input name=context list=ctxs placeholder="kube context" aria-label="Kube context"><datalist id=ctxs>{ctx_options}</datalist>
<select name=mode aria-label="Exec mode"><option>direct<option>ssh<option>ssh_sudo</select> <input name=host placeholder="ssh host (ssh modes)" aria-label="ssh host"> <input name=user placeholder="user (default $USER_NAME)" aria-label=User>
<br>Tools: {tool_checks}<br>
<label><input type=checkbox name=check value=1 checked> check first: <code>kubectl --context X get ns</code> (or the ssh variant)</label> <button class="btn primary">Add</button></form></details>
<h2>AI sessions <span class=hint>{sess_hint}</span> {prune} <span id=stamp class=hint></span></h2>
<form id=psbulk method=post hidden></form>
<div class=tablewrap><table id=sess aria-label="PROD sessions" style="min-width:820px"><thead><tr><th style="width:2rem"><input type=checkbox class=selall data-for=psess aria-label="Select all PROD sessions">
<th>Session<th>Agent<th>MCP tool calls<th>Cluster<th style="width:2.5rem"></tr></thead><tbody>{sessions}</tbody></table></div>
<h2 id=patterns-h>Query patterns <small class=lbl>(recently approved; the only queries the agent can run)</small></h2>
<div id=pwrap>{patterns}</div>
{env_bar}{sess_bar}{kit}
<script>
// Cluster status from /api/prod/stats. Error text from kubectl is set as text, never markup.
async function etick(){{try{{const r=await fetch('/api/prod/stats');if(!r.ok)return;const d=await r.json();
  for(const row of $$('tr[data-kind=env]')){{const s=d[row.dataset.key];if(!s)continue;const st=row.querySelector('[data-f=status]');if(!st)continue;
    row.dataset.up=s.up?'1':'0';st.textContent='';
    if(s.up)st.append(chipEl('c-ok','up'+(s.nodes!=null?' \\u00b7 '+Number(s.nodes)+' nodes':'')+(s.ms!=null?' \\u00b7 '+Number(s.ms)+' ms':'')));
    else{{const b=chipEl('c-bad',(s.error||'unreachable').slice(0,90),'\\u21bb refresh');b.title=(s.error||'')+' \\u2014 click to refresh the kubectl credentials';
      b.setAttribute('form','act');b.setAttribute('formaction','/prod/envs/refresh');b.name='sel';b.value=row.dataset.key;b.dataset.busy='refreshing\\u2026';st.append(b)}}}}
  syncBars()}}catch(e){{}}}}
etick();setInterval(etick,30000);
function busy(w){{const a=document.activeElement;   // never refresh while you work in it
  return (w.contains(a)&&a!==document.body)||w.querySelector('input[type=checkbox]:checked,form.edf:not([hidden]),button.armed')}}
async function wtick(){{try{{const w=document.getElementById('wait');if(busy(w))return;
  const r=await fetch('/prod/waiting-fragment');if(r.ok)w.innerHTML=await r.text()}}catch(e){{}}}}   // server-rendered, escaped fragment
setInterval(wtick,3000);
{access_js}
async function ptick(){{try{{const w=document.getElementById('pwrap');if(busy(w))return;
  const r=await fetch('/prod/patterns-fragment');if(r.ok)w.innerHTML=await r.text()}}catch(e){{}}}}
setInterval(ptick,5000);
</script></main>"""

MODE_TOOLS = ("kubernetes", "kubectl_commands", "remote_ops", "airflow", "disk", "django")   # tools with read / approve_writes


def route_secrets(env_name: str) -> list[str]:
    """Secret names the approved direct routes of an environment read (SPEC 7.8); exec routes need none."""
    from .patternstore import PatternStore
    try:
        rs = PatternStore().routes(env_name)
    except Exception:   # no store yet
        return []
    return sorted({n for r in rs for n in (r.secret, r.user_secret, r.password_secret) if n})


def tool_counts(sid: str) -> tuple[int, int]:
    """(tool calls, of which writes) for a gateway session, from its audit log."""
    f = HOME / "audit" / f"{sid}.jsonl"
    calls = writes = 0
    try:
        with f.open() as fh:
            for line in fh:
                if '"tool.intent"' not in line:
                    continue
                try:
                    r = json.loads(line)
                except ValueError:
                    continue
                if r.get("kind") == "tool.intent":
                    calls += 1
                    writes += (r.get("payload") or {}).get("risk", "read") != "read"
    except OSError:
        pass
    return calls, writes


def make_prod(app: FastAPI, config_path, nav_html, base_css: str, start_async) -> None:
    from .ui import NODE_NAME_PATTERN, prune_button, session_dead, session_row
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
    def tool_chips(env: E.Environment) -> str:
        """One chip per tool; a click saves the next mode of that tool only: off -> read -> approve_writes -> off (UI_REFACTOR_SPEC 5.2)."""
        out = ""
        for t in sorted(E.TOOLS):
            cur = env.tool(t)
            mode = "off" if cur is None else (cur.get("mode", "read") if t in MODE_TOOLS else "on")
            nxt = {"off": "read", "read": "approve_writes" if t in MODE_TOOLS else "off", "on": "off", "approve_writes": "off"}[mode]
            cls = {"off": "c-idle", "read": "c-ok", "on": "c-ok", "approve_writes": "c-warn"}[mode]
            label = t if mode == "off" else f"{t}: {mode.replace('_', ' ')}"
            out += (f'<form method=post action="/prod/envs/{quote(env.name)}/tools"><input type=hidden name=tool value="{t}">'
                    f'<button class="chip {cls}" name=mode value={nxt} title="{e(t)} is {mode}. Click: {nxt}." '
                    f'aria-label="{e(t)}: {mode}, click to set {nxt}"><span class=dot></span><span class=t>{e(label)}</span></button></form>')
        return f'<div style="display:flex;flex-wrap:wrap;gap:.25rem">{out}</div>'

    def env_rows(cfg) -> str:
        registered = E.environments(cfg)
        templates = (cfg.defaults or {}).get("links", {}) or {}
        gw = [s for s in session.list_sessions() if s.get("mode") == "gateway"]
        rows = ""
        for i, env in enumerate(registered):
            n, q = env.name, quote(env.name)
            ex = env.exec_for("kubernetes")
            sec = E.secret_status(env, route_secrets(env.name))
            miss = [v for v, st in sec.items() if st == "missing"]
            sub = [f"context {e(env.kube_context)}" if env.kube_context else "no kube context",
                   f"secrets {sum(1 for st in sec.values() if st == 'present')}", e(ex.mode) + (f" via {e(ex.host)}" if ex.host else "")]
            subline = " &middot; ".join(sub) + (f'<div style="color:var(--bad)">missing secrets: {e(", ".join(miss))}</div>' if miss else "")
            links = " ".join(f'<a class=lnk href="{e(u)}" target=_blank rel=noopener>{e(k)}</a>' for k, u in E.env_links(env, templates).items())
            name = edit_name(n, f"/prod/envs/{q}/rename", pattern=NODE_NAME_PATTERN, placeholder="cluster name", size=22)
            secform = (f'<form id=sec{i} method=post action="/prod/envs/{q}/secret" class=inline hidden>'
                       '<input name=var placeholder="VAR (e.g. PG_DSN)" size=14 required aria-label="Secret name">'
                       '<input type=password name=value placeholder="value (never shown again)" size=24 autocomplete=off required aria-label="Secret value">'
                       f'<button class="btn primary mini">Set secret</button><button type=button class="btn mini" data-hide=sec{i}>Cancel</button></form>')
            opts = "".join(f"<option{' selected' if m == ex.mode else ''}>{m}" for m in ("direct", "ssh", "ssh_sudo"))
            modeform = (f'<form id=mode{i} method=post action="/prod/envs/{q}/mode" class=inline hidden><select name=mode aria-label="Exec mode">{opts}</select>'
                        f'<input name=host value="{e(ex.host or "")}" placeholder="ssh host" size=16 aria-label="ssh host">'
                        f'<button class="btn primary mini">Save</button><button type=button class="btn mini" data-hide=mode{i}>Cancel</button></form>')
            toolsform = f'<div id=tools{i} class=inline hidden>{tools_form(env, i)}</div>'
            status = (f'<td data-f=status>{chip("c-idle", "checking" + chr(0x2026))}' if env.kube_context
                      else f'<td>{chip("c-idle", "no kube context")}')
            mine = [s for s in gw if s.get("environment") == n]
            dead = sum(1 for s in mine if session_dead(s))
            cnt = " ".join(x for x in (f"<span><b>{len(mine) - dead}</b> running</span>" if len(mine) - dead else "",
                                       f"<span class=hot><b>{dead}</b> not running</span>" if dead else "") if x)
            cnt = f'<span class="meta row">{cnt}</span>' if cnt else "<span class=hint>&ndash;</span>"
            items = [mi_post("Start session", "/prod/sessions", "env", n, need="up", key="s", extra='data-start data-busy="Starting…"'),
                     mi_act("Rename", "rename"), mi_act("Set secret…", "reveal", target=f"sec{i}"),
                     mi_act("Tool settings…", "reveal", target=f"tools{i}"), mi_act("Exec mode…", "reveal", target=f"mode{i}"),
                     mi_post("Refresh kubectl token", "/prod/envs/refresh", "sel", n), "-",
                     mi_post("Remove from list", "/prod/envs/bulk-delete", "sel", n, danger=True, arm="Remove from the list?")]
            rows += (f'<tr data-kind=env data-key="{e(n)}" data-env="{e(n)}" data-up={0 if env.kube_context else 1}>'
                     f'<td><input type=checkbox class=rowsel name=sel value="{e(n)}" form=ebulk aria-label="Select {e(n)}">'
                     f'<td>{name}<small class=sub>{subline}</small>{secform}{modeform}{status}<td>{tool_chips(env)}{toolsform}'
                     f'<td>{links}<td>{cnt}<td>{kebab(n)}{menu(n, items)}</tr>')
        return rows or '<tr><td colspan=7 class=hint>No kubectl contexts found and no environments in the config. Use "Add environment".</tr>'

    def tools_form(env: E.Environment, i: int = 0) -> str:
        """Every tool with its settings (k=v), for what a chip cannot say. The chips are the everyday control."""
        rows = ""
        for t in sorted(E.TOOLS):
            cur = env.tool(t)
            on = cur is not None
            mode = (cur or {}).get("mode", "read")
            rest = ",".join(f"{k}={'|'.join(v) if isinstance(v, list) else v}" for k, v in (cur or {}).items() if k not in ("mode", "exec", "commands") and not isinstance(v, dict))
            rows += (f'<div><label><input type=checkbox name="on_{t}" value=1 {"checked" if on else ""}> {t}</label> '
                     f'<select name="mode_{t}" aria-label="{t} mode"><option {"selected" if mode == "read" else ""}>read<option {"selected" if mode == "approve_writes" else ""}>approve_writes</select> '
                     f'<input name="cfg_{t}" value="{e(rest)}" placeholder="k=v,k=v" size=40 aria-label="{t} settings"></div>')
        return (f'<form method=post action="/prod/envs/{e(env.name)}/tools" class=add>{rows}<button class="btn primary mini">Save tools</button> '
                f'<button type=button class="btn mini" data-hide=tools{i}>Cancel</button></form>')

    def session_rows() -> str:
        out = ""
        for s in session.list_sessions():
            if s.get("mode") != "gateway":
                continue
            sid = s["id"]
            calls, writes = tool_counts(sid)
            metrics = (f'<span class="meta row"><span><b>{calls}</b> calls</span><span><b>{writes}</b> writes</span>'
                       f'<a class=lnk href="/audit/{e(sid)}" target=_blank rel=noopener>live log &#x2197;</a></span>')
            kube = ""
            if (s.get("kube") or s.get("kube_error")) and s["status"] == "running":
                exp = (s.get("kube") or {}).get("expires")
                if s.get("kube_error"):
                    kube = f'<div class=sub style="color:var(--bad)">k8s: {e(s["kube_error"])}</div>'
                else:
                    left = "expired" if exp and exp < time.time() else ("until " + time.strftime("%a %H:%M", time.localtime(exp)) if exp else "")
                    kube = f'<div class=sub{" style=color:var(--bad)" if exp and exp < time.time() + 3600 else ""}>k8s token {left}</div>'
                kube += post_btn("↻ refresh token", f"/prod/sessions/{sid}/kube-refresh", "x", "1", cls="btn mini",
                                 title="get a new token on this machine (may open the browser to sign in)")
            out += session_row(s, kind="psess", form="psbulk", rm="/prod/sessions/bulk-remove", stop="/prod/sessions/bulk-stop",
                               metrics=metrics, where=s.get("environment", ""), extra=kube)
        return out or '<tr><td colspan=6 class=hint style="text-align:center;padding:1rem">No PROD sessions. Tick a cluster and click Start session.</tr>'

    # ------------------------------------------------------------------ pages
    @app.get("/prod", response_class=HTMLResponse)
    def prod_page(error: str = "", info: str = ""):
        cfg = load_config(config_path)
        ctx = "".join(f'<option value="{e(c)}">' for c in E.kubectl_contexts())
        checks = " ".join(f'<label><input type=checkbox name="on_{t}" value=1 {"checked" if t == "kubernetes" else ""}> {t}</label>' for t in sorted(E.TOOLS))
        gw = [s for s in session.list_sessions() if s.get("mode") == "gateway"]
        env_bar = bulk_bar("env", "cluster", "clusters", [
            bar_btn("Start session", "ebulk", "/prod/sessions", need="up", only=True, labeln="Start {n} sessions", primary=True,
                    busy="Starting…", start=True),
            bar_btn("Refresh tokens", "ebulk", "/prod/envs/refresh", busy="Refreshing…")])
        sess_bar = bulk_bar("psess", "session", "sessions", [
            bar_btn("Stop & remove", "psbulk", "/prod/sessions/bulk-remove", arm="Stop {n} running & remove?", arm_need="live", danger=True),
            bar_btn("Stop only", "psbulk", "/prod/sessions/bulk-stop", need="live", only=True)])
        body = PAGE.format(base_css=base_css, css=CSS, kit_css=KIT_CSS, kit=kit_tail(), nav=nav_html("prod"), error=e(error), info=e(info),
                           envrows=env_rows(cfg), ctx_options=ctx, tool_checks=checks, waiting=access["waiting"](), sessions=session_rows(),
                           patterns=access["fragment"](), access_css=access["css"], access_js=access["js"], env_bar=env_bar, sess_bar=sess_bar,
                           sess_hint=f'{sum(1 for s in gw if s["status"] == "running")} running',
                           prune=prune_button("/prod/sessions/prune", sum(1 for s in gw if session_dead(s))))
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
                if t in ("kubernetes", "kubectl_commands", "remote_ops", "airflow", "disk", "django"):
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
            if form.get("check") and "kubernetes" in env.tool_names():
                err = E.check_cluster(env)
                if err:
                    raise ConfigError(f"check failed, nothing saved ({err}). Untick the check to save anyway.")
            E.add_environment(config_path, spec)
        return back(go)

    def auto_register() -> list[str]:
        """Every local kubectl context is an environment (direct, kubernetes read-only): add the ones not in the config yet."""
        added = []
        cfg = load_config(config_path)
        have = {x.kube_context for x in E.environments(cfg) if x.kube_context}
        for c in E.kubectl_contexts():
            if c in have:
                continue
            try:
                E.add_environment(config_path, E.env_spec(E.sanitise_name(c), context=c))
                added.append(c)
            except ConfigError:   # the name is taken by another environment: leave it to "Add environment"
                pass
        return added

    @app.post("/prod/rescan")
    def rescan():
        return back(auto_register)

    try:
        auto_register()   # at start, so the clusters of the kubeconfig are listed without any step
    except Exception:
        pass

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
        """Either the full tools form, or one chip click: `tool` + `mode` (off | read | approve_writes), which changes that tool
        only and keeps the others and their settings as they are (UI_REFACTOR_SPEC 7.4)."""
        form = await request.form()

        def one():
            t, mode = str(form.get("tool", "")), str(form.get("mode", ""))
            if t not in E.TOOLS:
                raise ConfigError(f"unknown tool {t!r}")
            if mode not in ("off", "read", "approve_writes"):
                raise ConfigError("mode is off, read or approve_writes")
            env = E.environment(load_config(config_path), name)
            tools = {x: dict(env.tool(x) or {}) for x in env.tool_names()}
            if mode == "off":
                tools.pop(t, None)
            elif t in MODE_TOOLS:
                tools[t] = {**tools.get(t, {}), "mode": mode}
            elif mode == "approve_writes":
                raise ConfigError(f"{t} has no approve_writes mode")
            else:
                tools.setdefault(t, {})
            E.set_env_tools(config_path, name, tools)
            Audit("settings").log("ui", "env.tool", environment=name, tool=t, mode=mode)

        def full():
            tools = tools_from_form(form)
            cur = E.environment(load_config(config_path), name).tool("kubectl_commands") or {}
            if "kubectl_commands" in tools and cur.get("commands"):
                tools["kubectl_commands"]["commands"] = cur["commands"]   # defined in the config file, not editable in this form
            E.set_env_tools(config_path, name, tools)
        return back(one if "tool" in form else full)

    @app.post("/prod/envs/refresh")
    def env_refresh(sel: list[str] = Form([])):
        """New kubectl credentials for these clusters: runs the context's login plugin on this machine (it may open the browser),
        then hands the new token to every running session of the cluster and probes the cluster again."""
        def go():
            if not sel:
                raise ConfigError("select at least one cluster")
            cfg = load_config(config_path)
            for n in dict.fromkeys(sel):
                env = E.environment(cfg, n)
                ctxs = kubecreds.contexts(env)
                if not ctxs:
                    raise ConfigError(f"{n}: no kubectl context to refresh")
                kubecreds.build(ctxs)
                for s in gwsession.gateway_sessions():
                    if s.get("environment") == n and s["status"] == "running":
                        gwsession.refresh_kube(cfg, s["id"])
                with lock:
                    for c in ctxs:
                        cache.pop(c, None)
        return back(go)

    @app.post("/prod/envs/{name}/secret")
    def env_secret(name: str, var: str = Form(...), value: str = Form(...)):
        return back(lambda: E.write_secret(E.environment(load_config(config_path), name), var.strip(), value))

    # ------------------------------------------------------------------ sessions
    @app.post("/prod/sessions")
    def start(env: list[str] = Form([]), sel: list[str] = Form([]), ctx: list[str] = Form([])):
        """One session per cluster (a row's menu sends `env`, the bulk bar `sel`), started in the background (UI_REFACTOR_SPEC 7.5)."""
        names = list(dict.fromkeys(env + sel))
        try:
            known = E.kubectl_contexts() if ctx else []
            for c in ctx:  # a local kubectl context that is not registered yet: register it, then start
                if c not in known:
                    raise ConfigError("unknown kubectl context")
                nm = E.sanitise_name(c)
                E.add_environment(config_path, E.env_spec(nm, context=c))
                names.append(nm)
            if not names:
                raise ConfigError("select at least one cluster")
            cfg = load_config(config_path)
        except (ConfigError, RuntimeError) as ex:
            return RedirectResponse("/prod?error=" + quote(str(ex)), status_code=303)
        return start_async([(n, lambda n=n: gwsession.start_gateway_session(cfg, config_path, n)) for n in names], "/prod")

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

    @app.post("/prod/sessions/bulk-remove")
    def bulk_remove(ssel: list[str] = Form([])):
        """Same one-click remove as the EC2 tab (session.remove_many), for gateway sessions only."""
        def go():
            left = session.remove_many(load_config(config_path), ids(ssel))
            if left:
                raise ConfigError("removed. Access may remain on: " + ", ".join(left) + " (run airlock sweep once reachable)")
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
            dead = session.dead_sessions("gateway")
            left = session.remove_many(load_config(config_path), dead) if dead else []
            if left:
                raise ConfigError("removed. Access may remain on: " + ", ".join(left) + " (run airlock sweep once reachable)")
        return back(go)

    # ------------------------------------------------------------------ query patterns
    return None
