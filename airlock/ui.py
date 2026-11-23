"""Controller UI (loopback only, per-start token): EC2 nodes and sandbox sessions, Settings. Layout and behaviour: docs/UI_REFACTOR_SPEC.md."""
from __future__ import annotations

import asyncio
import fcntl
import hmac
import html
import json
import os
import pty
import re
import secrets
import signal
import struct
import termios
import threading
import time
from urllib.parse import quote

from fastapi import FastAPI, Form, HTTPException, Request, WebSocket
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from . import awsimport, nodeaccess, nodestats, session, sources, sshaccess
from .ui_kit import (KIT_CSS, bar_btn, bulk_bar, chip, copy_pill, edit_name, kebab, kit_tail, menu, mi_act, mi_link, mi_post,
                     post_btn)
from .audit import Audit
from .config import (ConfigError, resolve_env_user, add_node, claude_token_status, load_config, node_login_status, node_spec,
                     parse_kv, parse_list, remove_claude_oauth_token, remove_node_login, save_claude_oauth_token, save_node_login)

e = html.escape

PAGE = """<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>AirlockAI - EC2</title>
<style>{base_css}{kit_css}body{{font:14px system-ui;margin:0}}
.err{{color:#d33;position:sticky;top:0;z-index:9;background:Canvas;padding:.4rem .6rem;border:1px solid #d33;border-radius:6px}}.err:empty{{display:none}}
.ok{{color:#2a9d4a;padding:.4rem .6rem;border:1px solid #2a9d4a;border-radius:6px}}.ok:empty{{display:none}}.add input,.add select{{margin:.2rem}}
.lbl{{color:#888}}[hidden]{{display:none!important}}</style>
{nav}<main><p class=err>{error}</p><p class=ok>{info}</p>
<h1 style="font-size:1.05rem;margin:0 0 .3rem">EC2 &middot; Sandbox</h1>
<div class=hint>Tick nodes to start sessions; a ticked or clicked node lights up its AI sessions. Click a name to edit it, click an <code>ssh &hellip;</code> line to copy it, <kbd>&#x22ef;</kbd> or right-click for the rest. Press <kbd>?</kbd> for keys.</div>
<h2>Nodes <span class=hint>{node_hint}</span></h2>
<form id=nbulk method=post hidden></form>
<div class=tablewrap><table id=nodes aria-label=Nodes><thead><tr><th style="width:2rem"><input type=checkbox class=selall data-for=nodes aria-label="Select all nodes">
<th>Node<th>Status<th>Load<th>Links<th>Sessions<th style="width:2.5rem"><span class=hint aria-hidden=true></span></tr></thead><tbody>{nodes}</tbody></table></div>
<div style="margin-top:.5rem;display:flex;gap:.4rem;flex-wrap:wrap;align-items:center"><button type=button class=btn data-show-form=addnode
onclick="const f=document.getElementById('addnode');f.hidden=!f.hidden;if(!f.hidden)f.querySelector('input').focus()">+ Add node</button> {aws_link}</div>
<form id=addnode method=post action=/nodes class="add inline" hidden>
<input name=name placeholder="name (e.g. JohnTestApi)" required aria-label="Node name"> <input name=host placeholder="host or IP" required aria-label=Host>
<input name=port type=number value=22 style="width:5rem" aria-label=Port> <input name=user placeholder="ssh user" aria-label="ssh user">
<select name=mode aria-label="Exec mode"><option>ssh<option>ssh_sudo<option>direct</select>
<button class="btn primary">Add</button> <button type=button class=btn data-hide=addnode>Cancel</button></form>
<h2>AI sessions <span class=hint>{sess_hint}</span> {prune} <span id=stamp class=hint></span></h2>
<form id=sbulk method=post hidden></form>
<div class=tablewrap><table id=sess aria-label="AI sessions" style="min-width:820px"><thead><tr><th style="width:2rem"><input type=checkbox class=selall data-for=sess aria-label="Select all sessions">
<th>Session<th>Agent<th>CPU &middot; memory &middot; workspace<th>Node<th style="width:2.5rem"></tr></thead><tbody>{sessions}</tbody></table></div>
{node_bar}{sess_bar}{kit}
<script>
const gb=b=>b>=2**30?(b/2**30).toFixed(1)+' GB':(b/2**20).toFixed(0)+' MB';
const gbn=b=>{{const g=b/2**30;return g>=10?g.toFixed(0):g.toFixed(1)}};
const f2=x=>x==null?'-':Number(x).toFixed(2);
const BUSY={{pending:'instance starting\\u2026',stopping:'instance stopping\\u2026',rebooting:'rebooting\\u2026','shutting-down':'instance shutting down\\u2026'}};
// Node rows from /api/nodes/stats. Text from a node is never markup: elements + textContent only.
async function ntick(){{try{{
  const r=await fetch('/api/nodes/stats');if(!r.ok)return;const d=await r.json();
  for(const row of $$('tr[data-kind=nodes]')){{const s=d[row.dataset.key];if(!s)continue;
    const ec2=s.ec2_state||'',iid=row.dataset.iid==='1';
    Object.assign(row.dataset,{{up:s.up?'1':'0',stopped:ec2==='stopped'?'1':'0',running:ec2==='running'?'1':'0',noec2:iid&&!ec2?'1':'0'}});
    const w=row.querySelector('a[data-link=web]');if(w&&'web_up' in s){{w.style.color=s.web_up?'var(--ok)':'var(--bad)';w.title=s.web_up?'web UI is up':'web UI is down'}}
    const h=row.querySelector('a[data-link=ssh]');if(h&&'ssh_link_up' in s){{h.style.color=s.ssh_link_up?'var(--ok)':'var(--bad)';h.title=s.ssh_link_up?'ssh server answers':'ssh refuses to connect'}}
    const st=row.querySelector('[data-f=status]');st.textContent='';
    const where=(s.ip||'unresolved')+' \\u00b7 '+s.host+':'+s.port;
    if(BUSY[ec2])st.append(chipEl('c-warn pulse',BUSY[ec2]));
    else if(ec2==='stopped'){{const b=chipEl('c-idle','instance stopped','\\u25b6 start');b.setAttribute('form','act');b.setAttribute('formaction','/nodes/aws/start');
      b.name='sel';b.value=row.dataset.key;b.title='Start the EC2 instance';st.append(b)}}
    else if(s.up){{const c=chipEl('c-ok','up');c.title=where;st.append(c)}}
    else if(s.login_missing){{st.append(el('a',{{class:'chip c-bad',href:'/settings',title:s.error||''}},el('span',{{class:'dot'}}),el('span',{{class:'t'}},'down: login missing'),el('span',{{class:'go'}},'fix \\u2192')))}}
    else{{const c=chipEl('c-bad','down');c.title=(s.error||'')+' ('+where+')';st.append(c)}}
    const ld=row.querySelector('[data-f=load]');ld.textContent='';
    if(!s.up){{ld.append(el('span',{{class:'hint'}},'\\u2013'));continue}}
    const m=el('div',{{class:'meta load'}}),hot=s.load1!=null&&s.cores&&s.load1>s.cores;
    m.append(el('span',{{class:hot?'hot':null,title:'/proc/loadavg: 1, 5 and 15 minute averages, running/total tasks'}},'cpu ',
      el('b',{{}},f2(s.load1)+' '+f2(s.load5)+' '+f2(s.load15)+(s.tasks?'  '+s.tasks:'')),s.cores?' \\u00b7 '+Number(s.cores)+' cores':''));
    if((s.disks||[]).length){{const dk=el('span',{{}},'disk');
      for(const [i,k] of s.disks.entries()){{const x=el('span',{{class:parseInt(k.pct)>=85?'hot':null}},(i?' \u00b7':'')+' '+k.mount+' ',el('b',{{}},gbn(k.used)+'/'+gbn(k.size)+' GB'),' ',el('b',{{}},k.pct),' ');
        x.title=k.mount+': '+gb(k.used)+' used of '+gb(k.size);dk.append(x)}}m.append(dk)}}
    ld.append(m)}}
  syncBars()}}catch(e){{}}}}
ntick();setInterval(ntick,30000);
</script></main>"""


BASE_CSS = """:root{color-scheme:light dark}nav{position:sticky;top:0;align-self:flex-start;height:100vh;box-sizing:border-box;width:9rem;flex:none;padding:1rem .6rem;
border-right:1px solid #8884;display:flex;flex-direction:column;gap:.4rem}.brand{font-weight:700;margin-bottom:.6rem}
nav .tab{display:flex;flex-wrap:wrap;justify-content:space-between;align-items:center;gap:.3rem;padding:.5rem .7rem;border-radius:6px;text-decoration:none;color:inherit;
border:1px solid #8884;font-weight:600}nav .tab.on{background:#2a6df4;color:#fff;border-color:#2a6df4}nav .tab.prod.on{background:#c2410c;border-color:#c2410c}
nav .tab.prod{border-left:4px solid #c2410c}nav .tab.ec2{border-left:4px solid #2a6df4}.badge{font-size:.75rem;background:#8883;border-radius:9px;padding:0 .45rem}
nav .tab.on .badge{background:#fff3}.badge.wait{background:#c2410c;color:#fff;margin-left:auto}nav .tab.on .badge.wait{background:#fff;color:#c2410c}nav small{color:#888;margin-top:auto}body{display:flex}main{flex:1;min-width:0;padding:1rem 2rem 6rem}
@media (max-width:640px){nav{display:none}main{padding:1rem 16px 6rem}}
.tag{font-size:.75rem;padding:0 .4rem;border:1px solid #8886;border-radius:4px;color:#888}pre.json{white-space:pre-wrap;margin:0}"""

SESSION_NAME_PATTERN = r"[A-Za-z][A-Za-z0-9_.\-]{0,62}"
NODE_NAME_PATTERN = r"[A-Za-z0-9][A-Za-z0-9_.\-]{0,63}"
STALE_START = 600   # a session "starting" for longer than this is dead (session.dead_sessions uses the same limit)


def session_dead(s: dict) -> bool:
    """Not doing anything, as far as the state file says (a running record whose container is gone is found by the page script)."""
    if s["status"] == "starting":
        return time.time() - s.get("started_at", time.time()) > STALE_START
    return s["status"] in ("stopped", "needs_cleanup")


def session_row(s: dict, *, kind: str, form: str, rm: str, stop: str, metrics: str, where: str, extra: str = "") -> str:
    """One row of an AI sessions table (EC2 and PROD alike, docs/UI_REFACTOR_SPEC.md 4.2 and 5.3)."""
    sid, name, status = s["id"], s.get("name", ""), s["status"]
    live, dead = status == "running", session_dead(s)
    namecell = edit_name(name or sid, f"/sessions/{sid}/name", field="name", value=name, pattern=SESSION_NAME_PATTERN,
                         placeholder="name (ssh host)", title="Click to name this session (the name works as the ssh host)", required=False, size=18)
    sub = f'<span class=sub>{e(sid)}</span>' if name else ""
    # `ssh <name or id>` once `airlock ssh setup` put the Include in ~/.ssh/config; until then the -F form, which works as pasted
    pill = f'<div data-liveonly>{copy_pill(sshaccess.command(s))}</div>' if live and s.get("ssh") else ""
    err = f'<div class=sub style="color:var(--bad);font-family:inherit">{e(s["error"])}</div>' if s.get("error") else ""
    rm_attrs = f'form=act formaction="{e(rm)}" name=ssel value="{e(sid)}"'
    if live:
        agent = chip("c-idle", "checking…")   # the page script asks docker and turns it into "running" or "NOT RUNNING ✕ remove"
    elif status == "starting" and not dead:
        agent = chip("c-warn pulse", "starting…", attrs=f'data-starting="{int(s.get("started_at", time.time()))}"')
    elif status == "stopping":
        agent = chip("c-warn pulse", "stopping…")
    else:
        label = {"stopped": "stopped", "needs_cleanup": "cleanup pending"}.get(status, "NOT RUNNING")
        agent = chip("c-idle" if status == "stopped" else "c-bad", label, "✕ remove", attrs=rm_attrs,
                     title="Not doing anything. Click to remove it" + (" (the key and sudo rule are revoked first)." if status != "stopped" else "."))
    opens = ""
    if live:
        opens = (f'<a class=lnk data-liveonly data-claude href="/sessions/{e(sid)}/term?cmd=claude" target=_blank rel=noopener>claude &#x2197;</a>'
                 f'<a class=lnk data-liveonly href="/sessions/{e(sid)}/term" target=_blank rel=noopener>shell &#x2197;</a>')
    busy = status == "stopping" or (status == "starting" and not dead)
    items = []
    if live:
        items += [mi_link("Open claude", f"/sessions/{sid}/term?cmd=claude", newtab=True, key="Enter", extra="data-show=live"),
                  mi_link("Open shell", f"/sessions/{sid}/term", newtab=True, extra="data-show=live")]
    items += [mi_act("Name this session", "rename"), "-"]
    if live:
        items.append(mi_post("Stop only", stop, "ssel", sid, show="live"))
    if not busy:
        items.append(mi_post("Stop & remove" if live else "Remove", rm, "ssel", sid, arm="Stop & remove?" if live else "", danger=True, key="Del",
                             extra="data-rm"))
    return (f'<tr data-kind={kind} data-key="{e(sid)}" data-sid="{e(sid)}" data-life="{e(status)}" data-live=0 data-dead={1 if dead else 0} '
            f'data-nodes="{e(",".join(s.get("nodes", [])))}" data-targets="{e(",".join(s.get("nodes", [])) or s.get("environment", ""))}" data-rmform=act data-rmaction="{e(rm)}">'
            f'<td><input type=checkbox class=rowsel name=ssel value="{e(sid)}" form={form} aria-label="Select session {e(name or sid)}">'
            f'<td>{namecell}{sub}{pill}{f"<div class=opens>{opens}</div>" if opens else ""}{err}<td data-f=agent>{agent}<td>{metrics if live else "<span class=hint>&ndash;</span>"}<td>{e(where)}{extra}'
            f'<td>{kebab(name or sid)}{menu(name or sid, items)}</tr>')


def prune_button(action: str, dead: int) -> str:
    """P7: shown only when there is something to remove; the page script keeps the count current."""
    return (f'<button class=btn form=act formaction="{e(action)}" data-prune{"" if dead else " hidden"} '
            f'title="stopped, stuck in cleanup, or whose agent container is gone">Remove {dead} not running</button>')


def nav_html(active: str) -> str:
    """Left tab strip: EC2 (Mode 1, sandbox), PROD (Mode 2, gateway), Settings. Badges count running sessions of each mode;
    PROD also shows how many items wait for an approval."""
    live = [s for s in session.list_sessions() if s["status"] in ("running", "starting")]
    n_prod = sum(1 for s in live if s.get("mode") == "gateway")
    n_ec2 = len(live) - n_prod

    def badge(n):
        return f'<span class=badge title="running sessions">{n}</span>' if n else ""
    try:   # items in the PROD tab's "Waiting for you": blocked calls and proposal items
        from . import gwsession, proposals
        from .patternstore import PatternStore
        st = PatternStore()
        proposals.import_inboxes(st)
        waiting = len(gwsession.pending_approvals()) + sum(
            1 for p in st.proposals("pending") for i in p["items"] if i["decision"] == "pending")
    except Exception:
        waiting = 0
    wait = f'<span class="badge wait" title="waiting for your approval">{waiting} waiting</span>' if waiting else ""
    return (f'<nav aria-label=Tabs><div class=brand>AirlockAI</div>'
            f'<a class="tab ec2{" on" if active == "ec2" else ""}" href="/?tab=ec2">EC2 {badge(n_ec2)}</a>'
            f'<a class="tab prod{" on" if active == "prod" else ""}" href="/prod{"#waiting" if waiting else ""}">PROD {badge(n_prod)}{wait}</a>'
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


UI_COOKIE = "airlock_ui"
LOOPBACK_HOST = re.compile(r"^(127\.0\.0\.1|localhost|\[::1\])(:\d+)?$")


def make_app(config_path=None, ui_token: str | None = None) -> FastAPI:
    """The controller UI. It has no user accounts, so every request must carry a random per-start token (cookie `airlock_ui`),
    handed over once through the URL that `airlock ui` prints; the Host must be loopback (DNS rebinding) and state-changing
    requests must come from this origin. `ui_token` is for tests; normally a fresh random value is made per start."""
    app = FastAPI(title="AirlockAI")
    token = ui_token or secrets.token_urlsafe(32)
    app.state.ui_token = token
    e = html.escape
    loopback = re.compile(r"^https?://(127\.0\.0\.1|localhost|\[::1\])(:\d+)?$")

    def has_token(value: str | None) -> bool:
        return bool(value) and hmac.compare_digest(value.encode(), token.encode())

    @app.middleware("http")
    async def guard(request, call_next):
        from fastapi.responses import PlainTextResponse
        if not LOOPBACK_HOST.match(request.headers.get("host", "")):
            return PlainTextResponse("host not allowed", status_code=421)  # DNS rebinding: the page's origin is not ours
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            origin = request.headers.get("origin")
            site = request.headers.get("sec-fetch-site")
            if origin == "null" or (origin and not loopback.match(origin)) or site == "cross-site":
                return PlainTextResponse("cross-site request refused", status_code=403)
            if not origin and site != "same-origin":
                return PlainTextResponse("a state-changing request needs an Origin", status_code=403)
        supplied = request.query_params.get("token")
        if supplied and request.method == "GET" and has_token(supplied):
            # First visit through the printed URL: keep the token in a cookie and drop it from the address bar and history.
            resp = RedirectResponse(str(request.url.remove_query_params("token")), status_code=303)
            resp.set_cookie(UI_COOKIE, token, httponly=True, samesite="strict", path="/")
            return resp
        if not has_token(request.cookies.get(UI_COOKIE)):
            return PlainTextResponse("not signed in: open the URL that `airlock ui` printed (it carries a one-time token)", status_code=401)
        resp = await call_next(request)
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("Referrer-Policy", "same-origin")  # not no-referrer: that makes browsers send Origin: null on our own form POSTs
        resp.headers.setdefault("Content-Security-Policy", "frame-ancestors 'none'; object-src 'none'; base-uri 'none'")
        return resp

    @app.get("/", response_class=HTMLResponse)
    def index(request: Request, error: str = "", tab: str = "", info: str = ""):
        if tab != "ec2" and request.cookies.get("airlock_tab") == "prod":
            return RedirectResponse("/prod" + (f"?error={quote(error)}" if error else ""), status_code=303)
        resp = HTMLResponse(ec2_page(error, info))
        resp.set_cookie("airlock_tab", "ec2", samesite="strict")
        return resp

    def ec2_page(error: str = "", info: str = "") -> str:
        cfg = load_config(config_path)
        all_sessions = session.list_sessions()
        sandbox = [s for s in all_sessions if s.get("mode") != "gateway"]   # production sessions live in the PROD tab only
        rows = ""
        for n in cfg.nodes:
            nm = n.name
            links = [f'<a class=lnk href="{e(u)}" target=_blank rel=noopener data-link="{e(k)}">{e(k)}</a>' for k, u in n.links.items()]
            if "ssh" not in n.links:  # no ssh template configured: fall back to the node's own address
                user = n.exec.user if n.exec.user and "$" not in n.exec.user else ""
                links.append(f'<a class=lnk href="ssh://{e(user + "@" if user else "")}{e(n.host)}" data-link=ssh>ssh</a>')
            iid = n.resolved_instance_id()
            own = n.notes if n.notes and not n.notes.startswith("imported from AWS:") else ""   # drop the old auto-generated import note
            srcs = ", ".join(x.mount_name for x in sources.load(nm) if x.enabled) or "none"
            sub = " &middot; ".join(e(x) for x in (iid, n.exec.mode, n.created_by and f"created by {n.created_by}") if x)
            sub += (f' &middot; <a href="/nodes/{quote(nm)}/sources" title="source folders mounted in AI sessions on this node">'
                    f'src: {e(srcs)}</a>{"" if sources.is_custom(nm) else " (default)"}')
            note = f'<div class=hint>{e(own)}</div>' if own else ""
            su = n.exec.user or ""
            su = (resolve_env_user(su) if "$" in su else su) or os.environ.get("USER_NAME", "")
            sshcmd = f"ssh {su}@{n.host}" if su else f"ssh {n.host}"
            name = edit_name(nm, f"/nodes/{quote(nm)}/rename", pattern=NODE_NAME_PATTERN, placeholder="node name", size=30)
            mine = [s for s in sandbox if nm in s["nodes"]]
            n_dead = sum(1 for s in mine if session_dead(s))
            n_live = len(mine) - n_dead
            count = " ".join(x for x in (f"<span><b>{n_live}</b> running</span>" if n_live else "",
                                         f"<span class=hot><b>{n_dead}</b> not running</span>" if n_dead else "") if x)
            count = f'<span class="meta row">{count}</span>' if count else "<span class=hint>&ndash;</span>"
            items = [mi_post("Start session", "/sessions", "nodes", nm, need="up", key="s", extra="data-start"),
                     mi_act("Rename", "rename"), mi_link("Source folders…", f"/nodes/{quote(nm)}/sources"), "-"]
            items += [mi_post(("● " if m == n.exec.mode else "○ ") + f"exec: {m}", f"/nodes/{quote(nm)}/mode", "mode", m,
                              role="menuitemradio", checked=m == n.exec.mode) for m in ("ssh", "ssh_sudo", "direct")]
            if iid:
                items += ["-", mi_post("Start instance", "/nodes/aws/start", "sel", nm, show="stopped|noec2"),
                          mi_post("Reboot instance", "/nodes/aws/reboot", "sel", nm, show="running|noec2"),
                          mi_post("Stop instance", "/nodes/aws/stop", "sel", nm, show="running|noec2", danger=True, arm=f"Stop {nm}?")]
            items += ["-", mi_post("Delete from list", "/nodes/bulk-delete", "sel", nm, danger=True, arm="Delete from the list?")]
            rows += (f'<tr data-kind=nodes data-key="{e(nm)}" data-node="{e(nm)}" data-iid={1 if iid else 0}>'
                     f'<td><input type=checkbox class=rowsel name=sel value="{e(nm)}" form=nbulk aria-label="Select {e(nm)}">'
                     f'<td>{name}<div>{copy_pill(sshcmd)}</div><small class=sub>{sub}</small>{note}'
                     f'<td data-f=status>{chip("c-idle", "checking" + chr(0x2026))}<td data-f=load><span class=hint>&ndash;</span>'
                     f'<td><div style="display:flex;gap:.5rem">{" ".join(links)}</div><td data-f=nsess>{count}'
                     f'<td>{kebab(nm)}{menu(nm, items)}</tr>')
        if not rows:
            rows = '<tr><td colspan=7 class=hint style="text-align:center;padding:1rem">No nodes yet. Add one, or import your AWS instances.</tr>'
        srows = ""
        for s in sandbox:
            metrics = ('<div class="meta row"><span>cpu <b data-f=cpu>-</b></span><span>mem <b data-f=mem>-</b></span>'
                       '<span>ws <b data-f=workspace>-</b></span></div>')
            srows += session_row(s, kind="sess", form="sbulk", rm="/sessions/bulk-remove", stop="/sessions/bulk-stop", metrics=metrics,
                                 where=", ".join(s["nodes"]))
        if not srows:
            srows = '<tr><td colspan=6 class=hint style="text-align:center;padding:1rem">No AI sessions. Tick a node that is up and click Start session.</tr>'
        if not awsimport.available():
            aws_link = '<span class=hint>Import from AWS: AWS CLI not found</span>'
        elif not awsimport.current_user():
            aws_link = '<span class=hint>Import from AWS: USER_NAME is not set in the environment of this server</span>'
        else:
            aws_link = '<a class=btn href=/aws style="text-decoration:none">Import my AWS instances</a>'
        node_bar = bulk_bar("nodes", "node", "nodes", [
            bar_btn("Start session", "nbulk", "/sessions", need="up", only=True, labeln="Start {n} sessions", primary=True,
                    busy="Starting…", start=True),
            bar_btn("Start instance", "nbulk", "/nodes/aws/start", need="stopped|noec2", only=True),
            bar_btn("Reboot", "nbulk", "/nodes/aws/reboot", need="running|noec2", only=True),
            bar_btn("Stop instance", "nbulk", "/nodes/aws/stop", need="running|noec2", only=True, arm="Stop {n}?", danger=True),
            bar_btn("Delete", "nbulk", "/nodes/bulk-delete", arm="Delete {n}?", danger=True)])
        sess_bar = bulk_bar("sess", "session", "sessions", [
            bar_btn("Stop & remove", "sbulk", "/sessions/bulk-remove", arm="Stop {n} running & remove?", arm_need="live", danger=True),
            bar_btn("Stop only", "sbulk", "/sessions/bulk-stop", need="live", only=True)])
        n_run = sum(1 for s in sandbox if s["status"] == "running")
        return PAGE.format(nodes=rows, sessions=srows, error=e(error), info=e(info), aws_link=aws_link, nav=nav_html("ec2"), base_css=BASE_CSS,
                           kit_css=KIT_CSS, kit=kit_tail(), node_hint=f"{len(cfg.nodes)} node{'s' if len(cfg.nodes) != 1 else ''}",
                           sess_hint=f"{n_run} running", prune=prune_button("/sessions/prune", sum(1 for s in sandbox if session_dead(s))),
                           node_bar=node_bar, sess_bar=sess_bar)

    SETTINGS = """<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>AirlockAI - Settings</title>
<style>{base_css}{kit_css}body{{font:14px system-ui;margin:0}}
.lbl{{color:#888}}.err{{color:#d33;padding:.4rem .6rem;border:1px solid #d33;border-radius:6px}}.err:empty{{display:none}}
.add input{{margin:.2rem}}code{{background:#8882;padding:0 .25rem;border-radius:3px}}.line{{display:flex;gap:.6rem;align-items:center;flex-wrap:wrap}}</style>
{nav}<main><p class=err>{error}</p><h1 style="font-size:1.05rem;margin:0 0 .3rem">Settings</h1>
<div class=hint>Shared by every session on both tabs.</div>
<h2>Claude sign-in <span class=hint>for sandbox and gateway sessions</span></h2>{auth_box}
<h2>Node login <span class=hint>used by the controller once per session to install the session key and sudo rule</span></h2>{login_box}
<p class=hint>The controller installs the session's ssh key and a validated sudoers rule (<code>/etc/sudoers.d/90-airlock-&lt;session&gt;</code>)
on test nodes, and removes them when the session ends. Prod nodes are refused unless allowed in the config. The agent never sees the password.</p>
<h2>Source folders mounted into agents <span class=hint>default list; a node can have its own (the <i>src:</i> link under a node name)</span></h2>
<p class=hint>Each folder appears in the agent container as <code>/src/&lt;folder name&gt;</code>. A session on several nodes mounts the folders of all of them.
Read-only by default; read-write applies to EC2 (sandbox) sessions only, PROD sessions always get read-only. Takes effect for sessions started after the change.
Anything inside a mounted folder (a <code>.env</code> file, for example) is visible to the agent; folders that overlap credential directories
(<code>~/.ssh</code>, <code>~/.aws</code>, <code>~/.kube</code>, ...) are refused.</p>
<div class=tablewrap><table aria-label="Source folders" style="min-width:560px"><thead><tr><th>Folder<th>Mounted as<th>Mode<th>Enabled<th style="text-align:right">Remove</tr></thead>
<tbody>{src_rows}</tbody></table></div>
<form method=post action=/settings/sources class="add inline"><input type=hidden name=action value=add><input name=path id=srcpath placeholder="~/myproject" size=36 required aria-label="Folder path">
<button type=button class=btn onclick="pickFolder()">Browse&hellip;</button>
<select name=mode aria-label=Mode><option value=ro>read-only<option value=rw>read-write (EC2)</select> <button class="btn primary">Add folder</button></form>
<h2>Access</h2><div class=hint>Approved routes and query patterns live on their own page: <a class=lnk href=/settings/access>Access &rarr;</a></div>
{picker}{kit}</main>"""

    PICKER = """<dialog id=picker style="min-width:22rem;max-width:90vw"><b>Select a folder</b>
<p id=pcur style="margin:.4rem 0"><code></code></p><p id=perr style="color:var(--bad)"></p>
<div id=plist style="max-height:50vh;overflow:auto;border:1px solid #8884;border-radius:6px"></div>
<p style="margin-top:.6rem"><button type=button class=btn id=pup>&uarr; Up</button> <button type=button class="btn primary" id=pok>Select this folder</button>
<button type=button class=btn id=pcancel>Cancel</button></p></dialog>
<script>
function pickFolder(start){
  const dlg=document.getElementById('picker'),list=document.getElementById('plist'),cur=document.querySelector('#pcur code'),
        err=document.getElementById('perr'),up=document.getElementById('pup');
  let at='~',parent=null;
  async function go(path){
    const r=await fetch('/fs/dirs?path='+encodeURIComponent(path));
    const d=await r.json();
    if(!r.ok){err.textContent=d.error||'cannot list';return}
    err.textContent='';at=d.path;parent=d.parent;cur.textContent=at;up.disabled=!parent;list.replaceChildren();
    if(!d.dirs.length){const m=document.createElement('div');m.className='lbl';m.style.padding='.4rem';m.textContent='no sub-folders';list.append(m)}
    for(const k of d.dirs){const b=document.createElement('button');b.type='button';b.style.cssText='display:block;width:100%;text-align:left;border:0;border-bottom:1px solid #8882;padding:.35rem .5rem;background:none;color:inherit;cursor:pointer';
      b.textContent=k.name+(k.git?'  (git)':'');b.onclick=()=>go(k.path);list.append(b)}
  }
  up.onclick=()=>parent&&go(parent);
  document.getElementById('pok').onclick=()=>{const i=document.getElementById('srcpath');i.value=at;dlg.close();i.focus()};
  document.getElementById('pcancel').onclick=()=>dlg.close();
  const typed=(start||document.getElementById('srcpath').value).trim();
  go(typed||'~').then(()=>{if(err.textContent&&typed)go('~')});
  dlg.showModal();
}
</script>"""

    @app.get("/fs/dirs")
    def fs_dirs(path: str = "~"):
        try:
            return sources.list_dirs(path)
        except ConfigError as ex:
            return JSONResponse({"error": str(ex)}, status_code=400)

    def src_rows(node: str = "") -> str:
        """Folder table rows (Settings tab: the default list; a node page: that node's list). Every control is one click."""
        nd = f'<input type=hidden name=node value="{e(node)}">' if node else ""
        rows = ""
        for src in sources.load(node or None):
            p = e(src.path)
            miss = "" if src.exists else ' <span style="color:var(--bad)">(folder not found, skipped)</span>'
            other = "rw" if src.mode == "ro" else "ro"
            mode = (f'<form method=post action=/settings/sources>{nd}<input type=hidden name=action value=mode><input type=hidden name=path value="{p}">'
                    + chip("c-idle" if src.mode == "ro" else "c-warn", "read-only" if src.mode == "ro" else "read-write (EC2)", "⇄",
                           title="Click to switch to " + ("read-write (EC2 sessions only)" if other == "rw" else "read-only"),
                           attrs=f'name=mode value={other}') + '</form>')
            rows += (f'<tr><td><a href=# title="browse from this folder" onclick="pickFolder(this.textContent);return false"><code>{p}</code></a>{miss}'
                     f'<td>{"/src/" + e(src.mount_name) if src.exists else "-"}<td>{mode}'
                     f'<td><form method=post action=/settings/sources>{nd}<input type=hidden name=action value=toggle><input type=hidden name=path value="{p}">'
                     f'<input type=checkbox {"checked" if src.enabled else ""} onchange="this.form.submit()" aria-label="Enabled: {p}"></form>'
                     f'<td style="text-align:right"><form method=post action=/settings/sources>{nd}<input type=hidden name=action value=remove><input type=hidden name=path value="{p}">'
                     f'<button class="btn danger mini" aria-label="Remove {p}" title="Remove from the list (the folder itself is not touched)">&#x2715;</button></form></tr>')
        return rows or '<tr><td colspan=5><span class=hint>No folders: agents see only their /workspace.</span></tr>'

    NODE_SRC = """<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>AirlockAI - {name} sources</title>
<style>{base_css}{kit_css}body{{font:14px system-ui;margin:0}}
.lbl{{color:#888}}.err{{color:#d33;padding:.4rem .6rem;border:1px solid #d33;border-radius:6px}}.err:empty{{display:none}}
.add input{{margin:.2rem}}code{{background:#8882;padding:0 .25rem;border-radius:3px}}</style>
{nav}<main><p class=err>{error}</p><p><a class=lnk href=/>&larr; EC2 nodes</a></p><h2>Source code mounted for node {name}</h2>
<p class=hint>AI sessions on this node mount these folders as <code>/src/&lt;folder name&gt;</code> (a session on several nodes mounts the folders of all of them).
{state} Takes effect for sessions started after the change.</p>
<div class=tablewrap><table aria-label="Source folders" style="min-width:560px"><thead><tr><th>Folder<th>Mounted as<th>Mode<th>Enabled<th style="text-align:right">Remove</tr></thead><tbody>{src_rows}</tbody></table></div>
<form method=post action=/settings/sources class="add inline"><input type=hidden name=node value="{name}"><input type=hidden name=action value=add><input name=path id=srcpath placeholder="~/myproject" size=36 required aria-label="Folder path">
<button type=button class=btn onclick="pickFolder()">Browse&hellip;</button>
<select name=mode aria-label=Mode><option value=ro>read-only<option value=rw>read-write (EC2)</select> <button class="btn primary">Add folder</button></form>{reset}{picker}{kit}</main>"""

    @app.get("/nodes/{name}/sources", response_class=HTMLResponse)
    def node_sources(name: str, error: str = ""):
        if name not in {n.name for n in load_config(config_path).nodes}:
            raise HTTPException(404)
        custom = sources.is_custom(name)
        state = ("This node has its own list." if custom else
                 'This node uses the <a href=/settings>default list</a>; changing it here gives the node its own copy.')
        reset = ('<p><form method=post action=/settings/sources><input type=hidden name=node value="' + e(name) + '">'
                 '<input type=hidden name=action value=reset><button class=btn>Use the default list again</button></form></p>') if custom else ""
        return NODE_SRC.format(base_css=BASE_CSS, kit_css=KIT_CSS, kit=kit_tail(), nav=nav_html("ec2"), error=e(error), name=e(name), state=state,
                               src_rows=src_rows(name), reset=reset, picker=PICKER)

    @app.get("/settings", response_class=HTMLResponse)
    def settings_page(error: str = ""):
        state, detail = claude_token_status()
        if state in ("env", "file"):
            auth_box = (f'<div class=line>{chip("c-ok", "automatic sign-in is on")} <span class=hint>({e(detail)}). New sessions start signed in.</span> '
                        + ('<form method=post action=/auth/claude-token/remove><button class="btn danger" data-arm="Remove the saved token?">'
                           'Remove token</button></form>' if state == "file" else "") + '</div>')
        else:
            why = f'<div style="color:var(--bad)">{e(detail)}</div>' if state == "error" else ""
            auth_box = (f'{why}<div class=line>{chip("c-idle", "off: each session asks you to log in")} '
                        '<button type=button class=btn onclick="const f=document.getElementById(\'tokform\');f.hidden=false;f.querySelector(\'input\').focus()">'
                        'Paste token&hellip;</button></div>'
                        '<form id=tokform method=post action=/auth/claude-token class="add inline" hidden>'
                        '<span class=hint>Run <code>claude setup-token</code> in a terminal, sign in, and paste the token it prints:</span>'
                        '<input type=password name=token autocomplete=off required size=60 placeholder="token from claude setup-token" aria-label="Claude token">'
                        '<button class="btn primary">Save token</button> <button type=button class=btn data-hide=tokform>Cancel</button></form>')
        lstate, ldetail = node_login_status()
        if lstate in ("env", "memory"):
            src = ("from the USER_NAME / USER_PASSWORD variables of this server" if lstate == "env"
                   else "kept in memory only, forgotten when this server stops")
            login_box = (f'<div class=line>{chip("c-ok", "login set for user " + ldetail)} <span class=hint>({src})</span> '
                         + ('<form method=post action=/auth/node-login/remove><button class=btn>Forget login</button></form>' if lstate == "memory" else "")
                         + '</div>')
        else:
            login_box = ('<div class=line><button type=button class="chip c-bad" onclick="const f=document.getElementById(\'loginform\');f.hidden=false;f.querySelector(\'input\').focus()">'
                         '<span class=dot></span><span class=t>login missing: sandbox sessions cannot prepare nodes</span><span class=go>set &rarr;</span></button></div>'
                         '<form id=loginform method=post action=/auth/node-login class="add inline" hidden><input name=user autocomplete=username required size=20 placeholder="user name" aria-label="User name">'
                         '<input type=password name=password autocomplete=off required size=30 placeholder="password (also the sudo password)" aria-label=Password>'
                         '<button class="btn primary">Keep in memory</button> <button type=button class=btn data-hide=loginform>Cancel</button></form>')
        return SETTINGS.format(base_css=BASE_CSS, kit_css=KIT_CSS, kit=kit_tail(), nav=nav_html("settings"), error=e(error), auth_box=auth_box,
                               login_box=login_box, src_rows=src_rows(), picker=PICKER)

    @app.post("/settings/sources")
    def settings_sources(action: str = Form(...), path: str = Form(""), mode: str = Form("ro"), node: str = Form("")):
        """The default folder list, or with `node` that node's own list."""
        nd = node or None
        if nd and nd not in {n.name for n in load_config(config_path).nodes}:
            raise HTTPException(404)
        def go():
            if action == "add":
                sources.add(path, mode, nd)
            elif action == "mode":
                sources.update(path, mode=mode, node=nd)
            elif action == "toggle":
                cur = next((x for x in sources.load(nd) if x.path == path), None)
                if cur is None:
                    raise ConfigError(f"unknown source {path}")
                sources.update(path, enabled=not cur.enabled, node=nd)
            elif action == "remove":
                sources.remove(path, nd)
            elif action == "reset" and nd:
                sources.reset_node(nd)
            else:
                raise ConfigError("unknown action")
            Audit("settings").log("ui", "sources.change", node=nd or "default", action=action, path=path,
                                  mode=mode if action in ("add", "mode") else None)
        return back(go, f"/nodes/{quote(node)}/sources" if nd else "/settings")

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
        def go():
            save_node_login(user, password)
            nodeaccess.provision_async(load_config(config_path).nodes)   # own ssh key + passwordless sudo, if a ~/.ssh/*.pub exists
        return back(go, "/settings")

    @app.post("/auth/node-login/remove")
    def login_remove():
        return back(remove_node_login, "/settings")

    @app.post("/nodes")
    def node_add(name: str = Form(...), host: str = Form(...), port: int = Form(22), user: str = Form(""),
                 mode: str = Form("ssh")):
        def go():
            h = awsimport.expand_host(host, load_config(config_path))
            add_node(config_path, node_spec(name, h, port=port, user=user, mode=mode))
            nodeaccess.provision_async([n for n in load_config(config_path).nodes if n.name == name.strip()])
        return back(go)

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
        body = (f'<form method=post action=/aws/add><table><tr><th><input type=checkbox id=iall checked title="Select / unselect all"><th>Name<th>Instance<th>Region<th>State<th>IP<th>Matched tag</tr>{rows}</table>'
                '<p><button>Add selected nodes</button></p></form>'
                "<script>const all=document.getElementById('iall'),boxes=()=>document.querySelectorAll('input[name=iid]');"
                "all.onchange=()=>boxes().forEach(c=>c.checked=all.checked);"
                "boxes().forEach(c=>c.onchange=()=>{all.checked=[...boxes()].every(x=>x.checked)});</script>")
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
            added = set()
            for i in found:
                spec = awsimport.to_spec(i, cfg, taken)
                taken.add(spec["name"])
                added.add(spec["name"])
                add_node(config_path, spec)
            nodeaccess.provision_async([n for n in load_config(config_path).nodes if n.name in added])
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
        """Sessions on these nodes that are not doing anything are removed first, so a dead agent never pins a node."""
        def go():
            stale = [sid for sid in session.dead_sessions("sandbox") + session.dead_sessions("gateway")
                     if set(session.load_state(sid)["nodes"]) & set(sel)]
            left = session.remove_many(load_config(config_path), stale) if stale else []
            session.remove_nodes_checked(config_path, sel)
            if left:
                raise ConfigError("deleted. Key and sudo rule may remain on: " + ", ".join(left) + " (run airlock sweep once reachable)")
        return back(go)

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
        """ssh status per node (cached 15 s), plus the EC2 state from one cached describe-instances (UI_REFACTOR_SPEC 7.3)."""
        cfg = load_config(config_path)
        out = {k: dict(v) for k, v in nodestats.collect(cfg.nodes).items()}
        try:
            for name, state in awsimport.instance_states(cfg, cfg.nodes).items():
                out.setdefault(name, {})["ec2_state"] = state
        except Exception:   # noqa: BLE001 - AWS is optional here; the table then shows ssh status only
            pass
        return out

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

    @app.post("/sessions/bulk-remove")
    def sessions_bulk_remove(ssel: list[str] = Form([])):
        """One click: stop if needed, revoke node access, remove. Unreachable nodes do not block it; the leftover is listed."""
        if not all(re.match(r"^[a-f0-9]{6,32}$", x) for x in ssel):
            raise HTTPException(404)
        return removed(lambda: session.remove_many(load_config(config_path), ssel))

    def removed(fn):
        try:
            left = fn()
        except (ConfigError, RuntimeError) as ex:
            return RedirectResponse("/?tab=ec2&error=" + quote(str(ex)), status_code=303)
        if left:
            msg = "removed. Key and sudo rule may remain on: " + ", ".join(left) + " (run airlock sweep once the node is reachable)"
            return RedirectResponse("/?tab=ec2&error=" + quote(msg), status_code=303)
        return RedirectResponse("/?tab=ec2", status_code=303)

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
        """Remove every sandbox session that is not doing anything (stopped, stuck in cleanup, container gone)."""
        def go():
            dead = session.dead_sessions("sandbox")
            return session.remove_many(load_config(config_path), dead) if dead else []
        return removed(go)

    def start_async(jobs: list, to: str, wait: float = 3.0):
        """Start sessions in background threads, so the table shows them as "starting… 12s" (UI_REFACTOR_SPEC 7.5). A start
        that fails within `wait` seconds (no node login, unknown node, refused key) is reported in the banner; a later failure
        leaves a stopped row that carries its error."""
        errors: list[str] = []

        def run(label, fn):
            try:
                fn()
            except Exception as ex:   # noqa: BLE001 - shown to the user, never a stack trace
                errors.append(f"{label}: {ex}" if len(jobs) > 1 else str(ex))
        threads = [threading.Thread(target=run, args=job, daemon=True) for job in jobs]
        for t in threads:
            t.start()
        deadline = time.time() + wait
        for t in threads:
            t.join(max(0.0, deadline - time.time()))
        pending = sum(t.is_alive() for t in threads)
        sep = "&" if "?" in to else "?"
        if errors:
            return RedirectResponse(to + sep + "error=" + quote("; ".join(errors)), status_code=303)
        if pending:
            return RedirectResponse(to + sep + "info=" + quote(f"starting {pending} session{'s' if pending > 1 else ''} (15-40 s)"), status_code=303)
        return RedirectResponse(to, status_code=303)

    @app.post("/sessions")
    def start(nodes: list[str] = Form([]), sel: list[str] = Form([])):
        """`nodes`: one session on these nodes (a row's menu, the CLI's multi-node form). `sel`: the ticked rows of the bulk bar,
        one separate session per node."""
        if not nodes and not sel:
            return back(lambda: (_ for _ in ()).throw(ConfigError("select at least one node")))
        cfg = load_config(config_path)
        groups = [nodes] if nodes else [[n] for n in dict.fromkeys(sel)]
        return start_async([(", ".join(g), lambda g=g: session.start_session(cfg, g)) for g in groups], "/?tab=ec2")

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
        # The terminal is a shell in the agent's container: same token as the pages, a loopback Host, and this origin only.
        origin = ws.headers.get("origin", "")
        if (not LOOPBACK_HOST.match(ws.headers.get("host", "")) or not loopback.match(origin)
                or not has_token(ws.cookies.get(UI_COOKIE))):
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
    make_prod(app, config_path, nav_html, BASE_CSS, start_async)
    return app
