"""Minimal controller UI (loopback only, no auth in v1): nodes, sessions, start/stop."""
from __future__ import annotations

import asyncio
import fcntl
import html
import json
import os
import pty
import re
import signal
import struct
import termios
from urllib.parse import quote

from fastapi import FastAPI, Form, HTTPException, Request, WebSocket
from fastapi.responses import HTMLResponse, RedirectResponse

from . import awsimport, nodestats, session, sources, sshaccess
from .config import (ConfigError, resolve_env_user, add_node, claude_token_status, load_config, node_login_status, node_spec,
                     parse_kv, parse_list, remove_claude_oauth_token, remove_node_login, save_claude_oauth_token, save_node_login)

PAGE = """<!doctype html><meta charset=utf-8><title>AirlockAI - EC2</title>
<style>{base_css}body{{font:14px system-ui;margin:0}}table{{border-collapse:collapse;width:100%}}
td,th{{border-bottom:1px solid #8884;padding:.4rem;text-align:left}}.up{{color:#2a9d4a}}.down{{color:#d33}}
button{{padding:.2rem .6rem}}.err{{color:#d33;position:sticky;top:0;z-index:9;background:Canvas;padding:.4rem .6rem;border:1px solid #d33;border-radius:6px}}.err:empty{{display:none}}.ok{{color:#2a9d4a;padding:.4rem .6rem;border:1px solid #2a9d4a;border-radius:6px}}.ok:empty{{display:none}}form{{display:inline}}.add input{{margin:.2rem}}
.chips{{display:flex;flex-wrap:wrap;gap:.15rem 1.6rem;align-items:center}}.chip{{white-space:nowrap}}.lbl{{color:#888}}
[hidden]{{display:none!important}}.nm{{cursor:text;border-bottom:1px dotted #888}}.nm:hover{{background:#8882}}</style>
{nav}<main><p class=err>{error}</p><p class=ok>{info}</p>
<h2>Nodes</h2>
<form id=bulk method=post action=/sessions class=add><b>Selected nodes:</b>
<select name=cmd><option value=/sessions data-start=1>Start session on selected
<option value=/nodes/aws/start>AWS: start instances
<option value=/nodes/aws/stop data-confirm="STOP the EC2 instances of the selected nodes? They go offline until started again.">AWS: stop instances
<option value=/nodes/aws/reboot data-confirm="Reboot the EC2 instances of the selected nodes?">AWS: reboot instances
<option value=/nodes/bulk-delete data-confirm="Delete selected nodes from the config?">Delete from config</select>
<button onclick="return applyBulk(this)">Apply</button></form>
<table id=nodes><tr><th><input type=checkbox id=nall title="select all"><th>Name <small class=lbl>(click to rename)</small><th>Status: reachable, IP, load (1 min), storage<th>Links<th>Session<th>Exec</tr>{nodes}</table>
<details><summary>Add node</summary><form method=post action=/nodes class=add>
<input name=name placeholder="name (e.g. JohnTestApi)" required> <input name=host placeholder="host or IP" required>
<input name=port type=number value=22 style="width:5rem"> <input name=user placeholder="ssh user">
<select name=mode><option>ssh<option>ssh_sudo<option>direct</select>
<button>Add</button></form></details>
<p>{aws_link}</p>
<h2>AI Sessions</h2>
<form id=sbulk method=post class=add><button formaction=/sessions/bulk-stop onclick="return confirm('Stop selected sessions?')">Stop selected</button>
<button formaction=/sessions/bulk-delete onclick="return confirm('Delete selected sessions? Running ones are stopped first (this removes their key and sudo rule from the node).')">Delete selected</button>
<button formaction=/sessions/bulk-discard onclick="return confirm('FORCE discard the selected sessions? Their containers and records are removed WITHOUT removing the ssh key and sudo rule from the nodes. Use only when a node cannot be reached; run airlock sweep later to clean up.')">Force discard</button>
<button formaction=/sessions/prune formmethod=post>Remove all stopped</button> <span id=stamp style="color:#888"></span></form>
<table id=sess><tr><th><input type=checkbox id=all title="select all"><th>ID<th>Status<th>Container<th>Actions<th>CPU<th>Memory<th>Workspace<th>Nodes<th>Allowlist</tr>{sessions}</table></main>
<script>
function applyBulk(b){{const o=b.form.cmd.selectedOptions[0];
  if(o.dataset.confirm&&!confirm(o.dataset.confirm))return false;
  b.formAction=o.value;return o.dataset.start?startingMsg(b):true}}
function startingMsg(b){{const f=b.form||b.closest('form');
  setTimeout(()=>{{b.disabled=true;b.textContent='Starting\u2026 (15-30 s)'}},0);return true}}
document.getElementById('nall').onchange=e=>document.querySelectorAll('input[name=sel]').forEach(c=>c.checked=e.target.checked);
const gb=b=>b>=2**30?(b/2**30).toFixed(1)+' GB':(b/2**20).toFixed(0)+' MB';
function cp(el){{const t=el.textContent,done=()=>{{el.textContent='copied';setTimeout(()=>el.textContent=t,800)}};
  (navigator.clipboard&&navigator.clipboard.writeText?navigator.clipboard.writeText(t):Promise.reject()).then(done,()=>{{
    const a=document.createElement('textarea');a.value=t;document.body.appendChild(a);a.select();document.execCommand('copy');a.remove();done()}})}}
function rn(el){{const w=el.closest('.nmwrap'),f=w.querySelector('form'),i=f.querySelector('input');
  el.hidden=true;f.hidden=false;i.focus();i.select()}}
function rnCancel(i){{const w=i.closest('.nmwrap');i.value=i.dataset.orig;w.querySelector('form').hidden=true;w.querySelector('.nm').hidden=false}}
function rnKey(ev,i){{
  if(ev.key==='Escape'){{ev.preventDefault();rnCancel(i)}}
  else if(ev.key==='Enter'){{ev.preventDefault();
    if(i.value.trim()===i.dataset.orig){{rnCancel(i);return}}   // unchanged: just close
    i.onblur=null;if(i.form.reportValidity())i.form.requestSubmit();else i.onblur=()=>rnCancel(i)}}
}}
async function ntick(){{try{{
  const r=await fetch('/api/nodes/stats');if(!r.ok)return;const d=await r.json();
  for(const [name,s] of Object.entries(d)){{
    const row=document.querySelector(`tr[data-node="${{name}}"]`);if(!row)continue;
    const q=k=>row.querySelector(`[data-n=${{k}}]`);
    q('dot').className='chip '+(s.up?'up':'down');q('dot').textContent=s.up?'\u25cf up':(s.login_missing?'\u25cf down: login is missing':'\u25cf down');q('dot').title=s.error||'';
    q('ip').innerHTML='<span class=lbl>IP</span> '+(s.ip||'unresolved');q('ip').title=s.host+':'+s.port;
    const ld=q('load'),dk=q('disk');dk.innerHTML='';
    if(!s.up){{ld.innerHTML='<span class=lbl>load</span> -';dk.innerHTML='<span class="chip lbl">storage -</span>';continue}}
    ld.innerHTML='<span class=lbl>load</span> '+(s.load1==null?'-':s.load1.toFixed(2)+(s.cores?' / '+s.cores+' cores':''));
    ld.className='chip '+((s.load1!=null&&s.cores&&s.load1>s.cores)?'down':'');
    for(const k of s.disks){{const sp=document.createElement('span');sp.className='chip'+(parseInt(k.pct)>=85?' down':'');
      sp.innerHTML=`<span class=lbl>${{k.mount}}</span> ${{k.pct}} (${{gb(k.used)}} / ${{gb(k.size)}})`;dk.appendChild(sp)}}
  }}
}}catch(e){{}}}}
ntick();setInterval(ntick,30000);
document.getElementById('all').onchange=e=>document.querySelectorAll('input[name=ssel]').forEach(c=>c.checked=e.target.checked);
async function tick(){{try{{
  const r=await fetch('/api/sessions/stats');if(!r.ok)return;const d=await r.json();
  for(const [sid,s] of Object.entries(d)){{
    const row=document.querySelector(`tr[data-sid="${{sid}}"]`);if(!row)continue;
    const c=row.querySelector('[data-f=container]'),life=row.dataset.life;
    const up=s.running;c.className=up?'up':(life==='stopped'?'':'down');
    c.textContent=up?'\u25cf running':(life==='stopped'?'\u25cb not running':'\u25cf NOT RUNNING');
    for(const f of ['cpu','mem','workspace'])row.querySelector(`[data-f=${{f}}]`).textContent=s[f];
  }}
  document.getElementById('stamp').textContent='updated '+new Date().toLocaleTimeString();
}}catch(e){{}}}}
tick();setInterval(tick,5000);
</script>"""


BASE_CSS = """:root{color-scheme:light dark}nav{position:sticky;top:0;align-self:flex-start;height:100vh;box-sizing:border-box;width:9rem;flex:none;padding:1rem .6rem;
border-right:1px solid #8884;display:flex;flex-direction:column;gap:.4rem}.brand{font-weight:700;margin-bottom:.6rem}
nav .tab{display:flex;justify-content:space-between;align-items:center;padding:.5rem .7rem;border-radius:6px;text-decoration:none;color:inherit;
border:1px solid #8884;font-weight:600}nav .tab.on{background:#2a6df4;color:#fff;border-color:#2a6df4}nav .tab.prod.on{background:#c2410c;border-color:#c2410c}
nav .tab.prod{border-left:4px solid #c2410c}nav .tab.ec2{border-left:4px solid #2a6df4}.badge{font-size:.75rem;background:#8883;border-radius:9px;padding:0 .45rem}
nav .tab.on .badge{background:#fff3}nav small{color:#888;margin-top:auto}body{display:flex}main{flex:1;min-width:0;padding:1rem 2rem}
.tag{font-size:.75rem;padding:0 .4rem;border:1px solid #8886;border-radius:4px;color:#888}pre.json{white-space:pre-wrap;margin:0}.cmd{cursor:copy;font-size:.8rem;background:#8882;padding:0 .3rem;border-radius:3px;display:inline-block;margin-top:.2rem}"""


def session_cells(s: dict) -> tuple[str, str]:
    """(id cell, ssh snippet) for a session row: click the id/name to set a name; the name is also the ssh host name."""
    import html as _h
    sid, name = _h.escape(s["id"]), _h.escape(s.get("name", ""))
    shown = name or sid
    sub = f' <small class=lbl>{sid}</small>' if name else ""
    pre = '<span class=lbl title="not editable: this is the ssh command prefix">ssh</span> ' if s.get("ssh") else ""
    idcell = (f'<div class=nmwrap>{pre}<b class=nm title="Click to name this session (the name works as the ssh host)" onclick="rn(this)">{shown}</b>{sub}'
              f'<form method=post action="/sessions/{sid}/name" hidden><input name=name value="{name}" placeholder="name (ssh host)" size=18 '
              f'autocomplete=off spellcheck=false data-orig="{name}" pattern="[A-Za-z][A-Za-z0-9_.\\-]{{0,62}}" '
              f'onkeydown="rnKey(event,this)" onblur="rnCancel(this)"></form></div>')
    return idcell, ""   # the ssh command is no longer shown in the Actions column; the "ssh" prefix before the name stays


def nav_html(active: str) -> str:
    """Left tab strip: EC2 (Mode 1, sandbox) and PROD (Mode 2, gateway). Badges count running sessions of each mode."""
    live = [s for s in session.list_sessions() if s["status"] in ("running", "starting")]
    n_prod = sum(1 for s in live if s.get("mode") == "gateway")
    n_ec2 = len(live) - n_prod

    def badge(n):
        return f'<span class=badge title="running sessions">{n}</span>' if n else ""
    return (f'<nav><div class=brand>AirlockAI</div>'
            f'<a class="tab ec2{" on" if active == "ec2" else ""}" href="/?tab=ec2">EC2 {badge(n_ec2)}</a>'
            f'<a class="tab prod{" on" if active == "prod" else ""}" href="/prod">PROD {badge(n_prod)}</a>'
            f'<a class="tab{" on" if active == "settings" else ""}" href="/settings">Settings</a>'
            f'<small>{"Mode 2: gateway" if active == "prod" else "Mode 1: sandbox" if active == "ec2" else ""}</small></nav>')


TERM_PAGE = """<!doctype html><meta charset=utf-8><title>{cmd} {sid}</title>
<link rel=stylesheet href="https://cdn.jsdelivr.net/npm/@xterm/xterm@5.5.0/css/xterm.css">
<style>html,body{{height:100%;margin:0;background:#000}}#t{{height:calc(100% - 1.4rem)}}#h{{height:1.4rem;font:12px system-ui;color:#888;padding:0 .5rem}}</style><div id=t></div><div id=h>Copy: drag to select, it copies on release (or Ctrl+Shift+C). Paste: Ctrl+Shift+V.</div>
<script src="https://cdn.jsdelivr.net/npm/@xterm/xterm@5.5.0/lib/xterm.js"></script>
<script src="https://cdn.jsdelivr.net/npm/@xterm/addon-fit@0.10.0/lib/addon-fit.js"></script>
<script>
const term=new Terminal({{cursorBlink:true}}),fit=new FitAddon.FitAddon();term.loadAddon(fit);
term.open(document.getElementById('t'));fit.fit();term.focus();
// Copy/paste: drag to select and it is copied on release;
// Ctrl+C copies when there is a selection (otherwise it stays SIGINT), Ctrl+Shift+C always copies, Ctrl+(Shift+)V pastes.
function copySel(){{const t=term.getSelection();if(!t)return false;
  (navigator.clipboard&&navigator.clipboard.writeText?navigator.clipboard.writeText(t):Promise.reject()).catch(()=>{{
    const a=document.createElement('textarea');a.value=t;document.body.appendChild(a);a.select();document.execCommand('copy');a.remove();term.focus()}});return true}}
term.attachCustomKeyEventHandler(e=>{{
  if(e.type!=='keydown')return true;
  const k=e.key.toLowerCase(),mod=e.ctrlKey||e.metaKey;
  if(mod&&k==='c'&&(e.shiftKey||term.hasSelection())){{copySel();return false}}
  if(mod&&k==='v'){{return false}}   // let the browser paste event reach xterm (bracketed paste handled by xterm)
  return true}});
// Claude Code turns on mouse reporting, so a plain drag would go to the app. Present every drag as Shift+drag, which xterm.js
// always treats as "select text"; the mouse wheel is left alone.
for(const ev of ['mousedown','mousemove','mouseup'])
  document.getElementById('t').addEventListener(ev,e=>Object.defineProperty(e,'shiftKey',{{get:()=>true}}),true);
document.getElementById('t').addEventListener('mouseup',()=>setTimeout(()=>{{if(term.hasSelection())copySel()}},0));
document.getElementById('t').addEventListener('contextmenu',e=>{{if(term.hasSelection()){{e.preventDefault();copySel()}}}});
const ws=new WebSocket(`ws://${{location.host}}/sessions/{sid}/ws?cmd={cmd}`);ws.binaryType='arraybuffer';
const enc=new TextEncoder();
const pending=[];   // keystrokes typed before the connection is open are queued, not lost
ws.onopen=()=>{{ws.send(JSON.stringify({{resize:[term.cols,term.rows]}}));for(const d of pending.splice(0))ws.send(enc.encode(d));term.focus()}};
addEventListener('load',()=>term.focus());addEventListener('focus',()=>term.focus());   // type straight away, no click needed
document.addEventListener('click',()=>term.focus());
ws.onmessage=e=>term.write(new Uint8Array(e.data));ws.onclose=()=>term.write('\\r\\n[disconnected]');
term.onData(d=>{{if(ws.readyState==1)ws.send(enc.encode(d));else if(ws.readyState==0)pending.push(d)}});
addEventListener('resize',()=>{{fit.fit();ws.readyState==1&&ws.send(JSON.stringify({{resize:[term.cols,term.rows]}}))}});
</script>"""


def make_app(config_path=None) -> FastAPI:
    app = FastAPI(title="AirlockAI")
    e = html.escape
    loopback = re.compile(r"^https?://(127\.0\.0\.1|localhost|\[::1\])(:\d+)?$")

    @app.middleware("http")
    async def refuse_cross_site_posts(request, call_next):
        """The UI has no login, so a page on another site must not be able to submit its forms (start/delete sessions,
        plant a token). Browsers always send Origin (or Sec-Fetch-Site) on a cross-site POST."""
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            origin = request.headers.get("origin")
            if (origin and origin != "null" and not loopback.match(origin)) or origin == "null" \
                    or request.headers.get("sec-fetch-site") == "cross-site":
                from fastapi.responses import PlainTextResponse
                return PlainTextResponse("cross-site request refused", status_code=403)
        return await call_next(request)

    @app.get("/", response_class=HTMLResponse)
    def index(request: Request, error: str = "", tab: str = "", info: str = ""):
        if tab != "ec2" and request.cookies.get("airlock_tab") == "prod":
            return RedirectResponse("/prod" + (f"?error={quote(error)}" if error else ""), status_code=303)
        resp = HTMLResponse(ec2_page(error, info))
        resp.set_cookie("airlock_tab", "ec2", samesite="strict")
        return resp

    def ec2_page(error: str = "", info: str = "") -> str:
        cfg = load_config(config_path)
        rows = ""
        for n in cfg.nodes:
            opts = "".join(f"<option{' selected' if m == n.exec.mode else ''}>{m}" for m in ("ssh", "ssh_sudo", "direct"))
            mode = f'<form method=post action="/nodes/{e(n.name)}/mode"><select name=mode onchange="this.form.submit()">{opts}</select></form>'
            links = [f'<a href="{e(u)}" target=_blank rel=noopener>{e(k)}</a>' for k, u in n.links.items()]
            if "ssh" not in n.links:  # no ssh template configured: fall back to the node's own address
                user = n.exec.user if n.exec.user and "$" not in n.exec.user else ""
                links.append(f'<a href="ssh://{e(user + "@" if user else "")}{e(n.host)}">ssh</a>')
            iid = n.resolved_instance_id()
            own = n.notes if n.notes and not n.notes.startswith("imported from AWS:") else ""   # drop the old auto-generated import note
            note = "".join(f'<br><small style="color:#888">{e(x)}</small>' for x in (iid, n.created_by and f"created by {n.created_by}", own) if x)
            su = n.exec.user or ""
            su = (resolve_env_user(su) if "$" in su else su) or os.environ.get("USER_NAME", "")
            sshcmd = f"ssh {su}@{n.host}" if su else f"ssh {n.host}"
            chk = f'<input type=checkbox name=sel value="{e(n.name)}" form=bulk>'
            start = (f'<form method=post action=/sessions><input type=hidden name=nodes value="{e(n.name)}">'
                     f'<button onclick="return startingMsg(this)">Start</button></form>')
            name = (f'<div class=nmwrap><b class=nm title="Click to rename" onclick="rn(this)">{e(n.name)}</b>'
                    f'<form method=post action="/nodes/{e(n.name)}/rename" hidden><input name=new value="{e(n.name)}" size=34 required '
                    f'autocomplete=off spellcheck=false data-orig="{e(n.name)}" pattern="[A-Za-z0-9][A-Za-z0-9_.\\-]{{0,63}}" '
                    f'onkeydown="rnKey(event,this)" onblur="rnCancel(this)"></form></div>')
            status = ('<div class=chips><span class="chip" data-n=dot>&hellip;</span><span class=chip data-n=ip><span class=lbl>IP</span> -</span>'
                      '<span class=chip data-n=load><span class=lbl>load</span> -</span><span class=chips data-n=disk></span></div>')
            rows += (f'<tr data-node="{e(n.name)}"><td>{chk}<td>{name}<small style="cursor:pointer" title="click to copy" onclick="cp(this)">{e(sshcmd)}</small>{note}'
                     f'<td>{status}<td>{" ".join(links)}<td>{start}<td>{mode}</tr>')
        srows = ""
        for s in session.list_sessions():
            if s.get("mode") == "gateway":
                continue  # production sessions live in the PROD tab only
            stop = (f'<a href=/sessions/{e(s["id"])}/term target=_blank rel=noopener>shell</a> '
                    f'<a href="/sessions/{e(s["id"])}/term?cmd=claude" target=_blank rel=noopener>claude</a>'
                    if s["status"] == "running" else "")
            sid = e(s["id"])
            idcell, sshcmd = session_cells(s)
            srows += (f'<tr data-sid="{sid}" data-life="{e(s["status"])}"><td><input type=checkbox name=ssel value="{sid}" form=sbulk>'
                      f'<td>{idcell}<td>{e(s["status"])}<td data-f=container>&hellip;<td>{stop}{sshcmd}<td data-f=cpu>-<td data-f=mem>-<td data-f=workspace>-'
                      f'<td>{e(", ".join(s["nodes"]))}<td>{e(", ".join(s.get("allow", [])))}</tr>')
        if not awsimport.available():
            aws_link = '<span style="color:#888">Import from AWS: AWS CLI not found</span>'
        elif not awsimport.current_user():
            aws_link = '<span style="color:#888">Import from AWS: USER_NAME is not set in the environment of this server</span>'
        else:
            aws_link = '<a href=/aws>Import my AWS instances</a>'
        return PAGE.format(nodes=rows, sessions=srows, error=e(error), info=e(info), aws_link=aws_link,
                           nav=nav_html("ec2"), base_css=BASE_CSS)

    SETTINGS = """<!doctype html><meta charset=utf-8><title>AirlockAI - Settings</title><style>{base_css}body{{font:14px system-ui;margin:0}}
.up{{color:#2a9d4a}}.down{{color:#d33}}.lbl{{color:#888}}.err{{color:#d33;padding:.4rem .6rem;border:1px solid #d33;border-radius:6px}}.err:empty{{display:none}}
form{{display:inline}}.add input{{margin:.2rem}}code{{background:#8882;padding:0 .25rem;border-radius:3px}}</style>
{nav}<main><p class=err>{error}</p><h2>Claude sign-in for sandbox and gateway sessions</h2>
<p class=lbl>Shared by every session, on both the EC2 and the PROD tab.</p><div id=auth>{auth_box}</div>
<h2>Node login (passwordless ssh and sudo on EC2 nodes)</h2>
<p class=lbl>Used by the controller only, once per session, to install the session's ssh key and a validated sudoers rule
(<code>/etc/sudoers.d/90-airlock-&lt;session&gt;</code>) on test nodes, and removed again when the session ends. Prod nodes are refused unless
allowed in the config. The agent never sees the password.</p><div id=login>{login_box}</div>
<h2>Source code mounted into agents</h2>
<p class=lbl>Each folder appears in the agent container as <code>/src/&lt;folder name&gt;</code>. Read-only by default; read-write applies to EC2 (sandbox)
sessions only, PROD sessions always get read-only. Takes effect for sessions started after the change. Anything inside a mounted folder (a <code>.env</code> file, for example)
is visible to the agent, and folders that overlap credential directories (<code>~/.ssh</code>, <code>~/.aws</code>, <code>~/.kube</code>, ...) are refused.</p>
<table><tr><th>Folder<th>Mounted as<th>Mode<th>Enabled<th></tr>{src_rows}</table>
<form method=post action=/settings/sources class=add><input type=hidden name=action value=add><input name=path placeholder="~/myproject" size=36 required>
<select name=mode><option value=ro>read-only<option value=rw>read-write (EC2)</select> <button>Add folder</button></form></main>"""

    @app.get("/settings", response_class=HTMLResponse)
    def settings_page(error: str = ""):
        state, detail = claude_token_status()
        if state in ("env", "file"):
            auth_box = (f'<span class=up>&#9679; automatic sign-in is on</span> <span class=lbl>({e(detail)}). New sessions start signed in.</span> '
                        + ('<form method=post action=/auth/claude-token/remove><button onclick="return confirm(\'Remove the saved token?\')">Remove token</button></form>' if state == "file" else ""))
        else:
            why = f'<span class=down>{e(detail)}</span> ' if state == "error" else ""
            auth_box = (f'{why}<span class=down>&#9679; not set up: new sessions will ask you to sign in.</span><br>'
                        '<span class=lbl>Run <code>claude setup-token</code> in a terminal, sign in, copy the token it prints and paste it here once:</span><br>'
                        '<form method=post action=/auth/claude-token class=add><input type=password name=token autocomplete=off required size=60 '
                        'placeholder="token from claude setup-token"><button>Save token</button></form>')
        lstate, ldetail = node_login_status()
        if lstate in ("env", "memory"):
            login_box = (f'<span class=up>&#9679; node login is set</span> <span class=lbl>(user <code>{e(ldetail)}</code>, '
                         f'{"from the USER_NAME / USER_PASSWORD variables of this server" if lstate == "env" else "kept in memory only, forgotten when this server stops"}).</span> '
                         + ('<form method=post action=/auth/node-login/remove><button>Forget login</button></form>' if lstate == "memory" else ""))
        else:
            login_box = (f'<span class=down>&#9679; not set: sandbox sessions cannot prepare nodes.</span><br>'
                         '<form method=post action=/auth/node-login class=add><input name=user autocomplete=username required size=20 placeholder="user name">'
                         '<input type=password name=password autocomplete=off required size=30 placeholder="password (also the sudo password)">'
                         '<button>Keep in memory</button></form>')
        rows = ""
        for src in sources.load():
            p = e(src.path)
            miss = "" if src.exists else ' <span class=down>(folder not found, skipped)</span>'
            rows += (f'<tr><td><code>{p}</code>{miss}<td>{"/src/" + e(src.mount_name) if src.exists else "-"}'
                     f'<td><form method=post action=/settings/sources><input type=hidden name=action value=mode><input type=hidden name=path value="{p}">'
                     f'<select name=mode onchange="this.form.submit()"><option value=ro {"selected" if src.mode == "ro" else ""}>read-only'
                     f'<option value=rw {"selected" if src.mode == "rw" else ""}>read-write (EC2)</select></form>'
                     f'<td><form method=post action=/settings/sources><input type=hidden name=action value=toggle><input type=hidden name=path value="{p}">'
                     f'<input type=checkbox {"checked" if src.enabled else ""} onchange="this.form.submit()"></form>'
                     f'<td><form method=post action=/settings/sources><input type=hidden name=action value=remove><input type=hidden name=path value="{p}">'
                     f'<button>Remove</button></form></tr>')
        rows = rows or '<tr><td colspan=5><span class=lbl>No folders: agents see only their /workspace.</span></tr>'
        return SETTINGS.format(base_css=BASE_CSS, nav=nav_html("settings"), error=e(error), auth_box=auth_box, login_box=login_box, src_rows=rows)

    @app.post("/settings/sources")
    def settings_sources(action: str = Form(...), path: str = Form(""), mode: str = Form("ro")):
        def go():
            if action == "add":
                sources.add(path, mode)
            elif action == "mode":
                sources.update(path, mode=mode)
            elif action == "toggle":
                cur = next((x for x in sources.load() if x.path == path), None)
                if cur is None:
                    raise ConfigError(f"unknown source {path}")
                sources.update(path, enabled=not cur.enabled)
            elif action == "remove":
                sources.remove(path)
            else:
                raise ConfigError("unknown action")
        return back(go, "/settings")

    def back(fn, to: str = "/"):
        """Run an action, then return to the page; a refused action shows its reason instead of a stack trace."""
        try:
            fn()
            return RedirectResponse(to, status_code=303)
        except (ConfigError, RuntimeError) as ex:
            return RedirectResponse(to + "?error=" + quote(str(ex)), status_code=303)

    @app.post("/auth/claude-token")
    def auth_save(token: str = Form(...)):
        return back(lambda: save_claude_oauth_token(token), "/settings")

    @app.post("/auth/claude-token/remove")
    def auth_remove():
        return back(remove_claude_oauth_token, "/settings")

    @app.post("/auth/node-login")
    def login_save(user: str = Form(...), password: str = Form(...)):
        return back(lambda: save_node_login(user, password), "/settings")

    @app.post("/auth/node-login/remove")
    def login_remove():
        return back(remove_node_login, "/settings")

    @app.post("/nodes")
    def node_add(name: str = Form(...), host: str = Form(...), port: int = Form(22), user: str = Form(""),
                 mode: str = Form("ssh")):
        return back(lambda: add_node(config_path, node_spec(name, host, port=port, user=user,
                                                            mode=mode)))

    AWS_PAGE = """<!doctype html><meta charset=utf-8><title>Import from AWS</title>
<style>:root{{color-scheme:light dark}}body{{font:14px system-ui;margin:1rem 2rem}}table{{border-collapse:collapse;width:100%}}
td,th{{border-bottom:1px solid #8884;padding:.4rem;text-align:left}}.err{{color:#d33;position:sticky;top:0;z-index:9;background:Canvas;padding:.4rem .6rem;border:1px solid #d33;border-radius:6px}}.err:empty{{display:none}}</style>
<h1>Import from AWS</h1><p><a href=/>&larr; back</a></p><p class=err>{error}</p>{hint}
<p>Read-only <code>ec2 describe-instances</code>, instances with a tag value containing <b>{user}</b>. Nothing is written to AWS.</p>
{body}"""

    @app.get("/aws", response_class=HTMLResponse)
    def aws_page(error: str = ""):
        user = awsimport.current_user()
        if not awsimport.available() or not user:
            return AWS_PAGE.format(error="AWS CLI missing, or USER_NAME not set in the server environment", user=e(user or "?"), body="", hint="")
        cfg = load_config(config_path)
        try:
            found = awsimport.new_instances(cfg, awsimport.find_instances(cfg))
        except awsimport.AwsAuthError as ex:
            hint = (f'<div style="border:1px solid #d33;padding:.8rem;border-radius:6px"><b>Your AWS session needs a login.</b>'
                    f'<p>Run this in a terminal, complete the browser sign-in, then retry:</p>'
                    f'<pre style="background:#8882;padding:.5rem">{e(ex.command)}</pre><a href=/aws>Retry</a></div>')
            return AWS_PAGE.format(error="", user=e(user), body="", hint=hint)
        except (ConfigError, RuntimeError) as ex:
            return AWS_PAGE.format(error=e(str(ex)), user=e(user), body="", hint='<a href=/aws>Retry</a>')
        if not found:
            return AWS_PAGE.format(error=e(error), user=e(user), body="<p>No new instances found.</p>", hint="")
        rows = "".join(
            f'<tr><td><input type=checkbox name=iid value="{e(i.id)}|{e(i.region)}" checked><td>{e(i.name or "-")}<td>{e(i.id)}'
            f'<td>{e(i.region)}<td>{e(i.state)}<td>{e(i.public_ip or i.private_ip or "-")}<td>{e(i.matched_on)}</tr>' for i in found)
        body = (f'<form method=post action=/aws/add><table><tr><th><th>Name<th>Instance<th>Region<th>State<th>IP<th>Matched tag</tr>{rows}</table>'
                '<p><button>Add selected nodes</button></p></form>')
        return AWS_PAGE.format(error=e(error), user=e(user), body=body, hint="")

    @app.post("/aws/add")
    def aws_add(iid: list[str] = Form([])):
        def go():
            if not iid:
                raise ConfigError("select at least one instance")
            cfg = load_config(config_path)
            wanted = {x.split("|")[0] for x in iid}
            found = [i for i in awsimport.new_instances(cfg, awsimport.find_instances(cfg)) if i.id in wanted]  # re-query: never trust the form
            taken = {n.name for n in cfg.nodes}
            for i in found:
                spec = awsimport.to_spec(i, cfg, taken)
                taken.add(spec["name"])
                add_node(config_path, spec)
        try:
            go()
            return RedirectResponse("/", status_code=303)
        except (ConfigError, RuntimeError) as ex:
            return RedirectResponse("/aws?error=" + quote(str(ex)), status_code=303)

    @app.post("/nodes/{name}/rename")
    def node_rename(name: str, new: str = Form(...)):
        return back(lambda: session.rename_node_checked(config_path, name, new))

    @app.post("/nodes/bulk-delete")
    def node_bulk_delete(sel: list[str] = Form([])):
        return back(lambda: session.remove_nodes_checked(config_path, sel))

    @app.post("/nodes/aws/{action}")
    def nodes_aws(action: str, sel: list[str] = Form([])):
        """Start, stop or reboot the EC2 instances of the checked nodes ("Selected nodes" drop list)."""
        try:
            cfg = load_config(config_path)
            lines = awsimport.control(cfg, [cfg.node(n) for n in sel], action)
        except (ConfigError, RuntimeError) as ex:   # includes AwsAuthError: its message says how to log in again
            return RedirectResponse("/?tab=ec2&error=" + quote(str(ex)), status_code=303)
        bad = any(("failed" in ln or "skipped" in ln) for ln in lines)
        return RedirectResponse(f"/?tab=ec2&{'error' if bad else 'info'}=" + quote("; ".join(lines)), status_code=303)

    @app.get("/api/nodes/stats")
    def api_nodes_stats():
        return nodestats.collect(load_config(config_path).nodes)

    @app.post("/nodes/{name}/mode")
    def node_mode(name: str, mode: str = Form(...)):
        return back(lambda: session.set_node_mode(config_path, name, mode))

    @app.get("/api/sessions/stats")
    def sessions_stats():
        return session.session_stats()

    @app.post("/sessions/{sid}/name")
    def session_name(sid: str, name: str = Form("")):
        if not re.match(r"^[a-f0-9]{6,32}$", sid):
            raise HTTPException(404)
        try:
            gw = session.load_state(sid).get("mode") == "gateway"
        except ConfigError:
            raise HTTPException(404)
        return back(lambda: sshaccess.set_name(sid, name), "/prod" if gw else "/")

    @app.post("/sessions/bulk-delete")
    def sessions_bulk_delete(ssel: list[str] = Form([])):
        if not all(re.match(r"^[a-f0-9]{6,32}$", x) for x in ssel):
            raise HTTPException(404)
        return back(lambda: session.delete_many(ssel, load_config(config_path)))

    @app.post("/sessions/bulk-discard")
    def sessions_bulk_discard(ssel: list[str] = Form([])):
        """Force removal of stuck sessions (node unreachable): node access may remain, which is listed in the message."""
        if not ssel:
            return back(lambda: (_ for _ in ()).throw(ConfigError("select at least one session")))
        if not all(re.match(r"^[a-f0-9]{6,32}$", x) for x in ssel):
            raise HTTPException(404)

        def go():
            left, refused = [], []
            for sid in ssel:
                try:
                    left += [f"{sid}/{p['node']}" for p in session.discard_session(sid)]
                except ConfigError as ex:
                    refused.append(str(ex))
            if refused:
                raise ConfigError("; ".join(refused))
            if left:
                raise ConfigError("discarded. Key and sudo rule may remain on: " + ", ".join(left) + " (run airlock sweep when reachable)")
        return back(go)

    @app.post("/sessions/bulk-stop")
    def sessions_bulk_stop(ssel: list[str] = Form([])):
        if not ssel:
            return back(lambda: (_ for _ in ()).throw(ConfigError("select at least one session")))
        if not all(re.match(r"^[a-f0-9]{6,32}$", x) for x in ssel):
            raise HTTPException(404)

        def stop_all():
            cfg = load_config(config_path)
            bad = []
            for sid in ssel:
                if session.load_state(sid)["status"] in ("running", "needs_cleanup"):
                    if session.stop_session(cfg, sid)["status"] != "stopped":
                        bad.append(sid)
            if bad:
                raise ConfigError("needs cleanup on node, retry: " + ", ".join(bad))
        return back(stop_all)

    @app.post("/sessions/prune")
    def sessions_prune():
        return back(session.prune_sessions)

    @app.post("/sessions")
    def start(nodes: list[str] = Form([]), sel: list[str] = Form([])):
        """`nodes` comes from a row's Start button, `sel` from the checked rows ("Start session on selected")."""
        names = nodes or sel
        if not names:
            return back(lambda: (_ for _ in ()).throw(ConfigError("select at least one node")))
        return back(lambda: session.start_session(load_config(config_path), names))

    @app.post("/sessions/{sid}/stop")
    def stop(sid: str):
        session.stop_session(load_config(config_path), sid)
        return RedirectResponse("/", status_code=303)

    sid_re = re.compile(r"^[a-f0-9]{6,32}$")
    commands = {"shell": ["bash", "-lc", "cd /src 2>/dev/null || cd /workspace; exec bash -l"], "claude": session.CLAUDE_CMD}

    def running(sid: str) -> dict:
        if not sid_re.match(sid):
            raise HTTPException(404)
        try:
            st = session.load_state(sid)
        except Exception:
            raise HTTPException(404)
        if st["status"] != "running":
            raise HTTPException(409, "session not running")
        return st

    @app.get("/sessions/{sid}/term", response_class=HTMLResponse)
    def term_page(sid: str, cmd: str = "shell"):
        running(sid)
        return TERM_PAGE.format(sid=sid, cmd=cmd if cmd in commands else "shell")

    @app.websocket("/sessions/{sid}/ws")
    async def term_ws(ws: WebSocket, sid: str, cmd: str = "shell"):
        # No auth in v1, so refuse cross-site pages: the Origin must be this loopback server.
        origin = ws.headers.get("origin", "")
        if not re.match(r"^https?://(127\.0\.0\.1|localhost)(:\d+)?$", origin):
            await ws.close(code=1008)
            return
        try:
            running(sid)
        except HTTPException:
            await ws.close(code=1008)
            return
        await ws.accept()
        argv = ["docker", "exec", "-it", "-e", "TERM=xterm-256color", "-e", "CLAUDE_CODE_DISABLE_ALTERNATE_SCREEN=1", f"air-agent-{sid}", *commands.get(cmd, commands["shell"])]
        pid, fd = pty.fork()
        if pid == 0:
            os.execvp("docker", argv)
        loop = asyncio.get_running_loop()
        q: asyncio.Queue[bytes] = asyncio.Queue()

        def on_read():
            try:
                data = os.read(fd, 65536)
            except OSError:
                data = b""
            q.put_nowait(data)
            if not data:
                loop.remove_reader(fd)

        loop.add_reader(fd, on_read)

        async def pump_out():
            while data := await q.get():
                await ws.send_bytes(data)
            await ws.close()

        out = asyncio.create_task(pump_out())
        try:
            while True:
                msg = await ws.receive()
                if msg["type"] == "websocket.disconnect":
                    break
                if msg.get("text") is not None:
                    m = json.loads(msg["text"])
                    if "resize" in m:
                        cols, rows = m["resize"]
                        fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", int(rows), int(cols), 0, 0))
                elif msg.get("bytes"):
                    os.write(fd, msg["bytes"])
        finally:
            out.cancel()
            try:
                loop.remove_reader(fd)
            except Exception:
                pass
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
            os.close(fd)

    from .ui_prod import make_prod
    make_prod(app, config_path, nav_html, BASE_CSS, session_cells)
    return app
