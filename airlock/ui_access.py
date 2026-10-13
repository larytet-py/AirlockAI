"""UI of the approval flow (SPEC 7.8): proposals and recent patterns in the PROD tab, the full catalogue in Settings > Access.

Rules for every list here: no buttons in rows. Rows have select checkboxes and the list has one bulk bar (a drop list of
actions and Apply). Clicking a query's text edits it in place (Ctrl+Enter saves, Esc cancels); clicking a name renames it.
"""
from __future__ import annotations

import html
import json
import re
import time
from urllib.parse import quote, urlencode

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse

from . import access as A
from . import envs as E
from . import gwsession
from . import proposals as PR
from . import usage
from .config import ConfigError, load_config
from .patterns import NAME_RE, Pattern, PatternError
from .patternstore import PatternStore

e = html.escape
RECENT_DAYS, RECENT_MIN, PAGE_SIZE = 7, 20, 50
KIND_TABS = [("postgres", "Postgres"), ("elasticsearch", "Elasticsearch"), ("redis", "Redis"), ("files", "Files")]

CSS = """[hidden]{display:none!important}body{font:14px system-ui;margin:0}.scroll{max-height:24rem;overflow-y:auto;border:1px solid #8884;border-radius:6px}.scroll table th{position:sticky;top:0;background:Canvas}
.ed{cursor:text;border-bottom:1px dotted #888;white-space:pre-wrap}.ed:hover{background:#8882}.edf textarea{width:100%}
.prop{border:1px solid #c2410c66;border-radius:6px;margin:.5rem 0;padding:.3rem .6rem}.ok{color:#2a9d4a}.no{color:#d33}
.bulk{margin:.4rem 0;display:flex;gap:.4rem;align-items:center;flex-wrap:wrap}.subnav a,.subnav b{margin-right:1rem}
.ktabs a{padding:.3rem .8rem;border:1px solid #8884;border-radius:6px 6px 0 0;text-decoration:none;color:inherit}.ktabs a.on{background:#8883;font-weight:600}
td.num{text-align:right;white-space:nowrap}.grp td{background:#8881;font-weight:600}"""

# click-to-edit (name: one line, Enter saves; query: textarea, Ctrl+Enter saves; Esc cancels both)
EDIT_JS = """
function rn(el){const w=el.closest('.nmwrap'),f=w.querySelector('form'),i=f.querySelector('input');el.hidden=true;f.hidden=false;i.focus();i.select()}
function rnCancel(i){const w=i.closest('.nmwrap');i.value=i.dataset.orig;w.querySelector('form').hidden=true;w.querySelector('.nm').hidden=false}
function rnKey(ev,i){if(ev.key==='Escape'){ev.preventDefault();rnCancel(i)}else if(ev.key==='Enter'){ev.preventDefault();
  if(i.value.trim()===i.dataset.orig){rnCancel(i);return}i.onblur=null;if(i.form.reportValidity())i.form.requestSubmit();else i.onblur=()=>rnCancel(i)}}
function ed(el){const w=el.closest('.edwrap'),f=w.querySelector('form');el.hidden=true;f.hidden=false;f.querySelector('textarea').focus()}
function edKey(ev,t){const w=t.closest('.edwrap');if(ev.key==='Escape'){ev.preventDefault();t.form.reset();t.form.hidden=true;w.querySelector('.ed').hidden=false}
  else if(ev.key==='Enter'&&(ev.ctrlKey||ev.metaKey)){ev.preventDefault();t.form.requestSubmit()}}
function selAll(box,name){box.closest('form,div').querySelectorAll(`input[name="${name}"]`).forEach(c=>c.checked=box.checked)}
function selProp(box){box.closest('.prop').querySelectorAll('input[name=item]').forEach(c=>c.checked=box.checked)}
"""


def fmt_ts(ts) -> str:
    if not ts:
        return '<span class=lbl>never</span>'
    utc = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))
    return f'<span title="{utc}">{time.strftime("%Y-%m-%d %H:%M", time.localtime(ts))}</span>'


def tpl_text(p_or_t) -> str:
    t = p_or_t.template if isinstance(p_or_t, Pattern) else p_or_t
    return t if isinstance(t, str) else json.dumps(t, indent=1)


def name_cell(name: str, action: str) -> str:
    n = e(name)
    return (f'<div class=nmwrap><b class=nm title="Click to rename" onclick="rn(this)">{n}</b>'
            f'<form method=post action="{action}" hidden><input name=new value="{n}" size=28 required autocomplete=off spellcheck=false '
            f'data-orig="{n}" pattern="{NAME_RE.pattern[1:-1]}" onkeydown="rnKey(event,this)" onblur="rnCancel(this)"></form></div>')


def query_cell(template: str, params: dict, action: str) -> str:
    pj = json.dumps(params) if params else ""
    return (f'<div class=edwrap><code class=ed title="Click to edit (Ctrl+Enter saves, Esc cancels)" onclick="ed(this)">{e(template)}</code>'
            f'<form method=post action="{action}" class=edf hidden><textarea name=template rows=5 onkeydown="edKey(event,this)">{e(template)}</textarea>'
            f'<textarea name=params rows=1 placeholder="params JSON" onkeydown="edKey(event,this)">{e(pj)}</textarea>'
            f'<small class=lbl>Ctrl+Enter saves a new version (validated first), Esc cancels.</small></form></div>')


def stat_cells(s: dict | None) -> str:
    s = s or {}
    return (f'<td class=num>{s.get("calls", 0)}<td class=num>{s.get("calls_7d", 0)}<td>{fmt_ts(s.get("first_used"))}<td>{fmt_ts(s.get("last_used"))}'
            f'<td class=num>{s.get("errors", 0)}<td class=num>{"" if s.get("p50_ms") is None else str(s["p50_ms"]) + " ms"}'
            f'<td class=num>{"" if s.get("max_ms") is None else str(s["max_ms"]) + " ms"}<td class=num>{"" if s.get("p50_rows") is None else s["p50_rows"]}')


STAT_HEAD = "<th>Calls<th>7 days<th>First used<th>Last used<th>Errors<th>p50<th>max<th>Rows p50"


def route_text(r: A.Route) -> str:
    if r.transport == "exec":
        t = r.target
        where = f"{t.namespace}/{t.workload}" + (f" -c {t.container}" if t.container else "")
        body = f"exec {e(where)} runner {e(r.runner or '')}"
        if r.roots:
            body += " &middot; roots " + ", ".join(f"<code>{e(x)}</code>" for x in r.roots)
    else:
        body = f"direct, secret {e(r.secret or '')}"
    state = {"active": "", "pending": " <span class=tag>pending</span>",
             "inactive": f' <span class=no title="{e(r.error or "")}">inactive</span>'}[r.status]
    g = r.guarantees or {}
    meas = []
    if "read_only_txn" in g:
        meas.append("read-only txn" if g["read_only_txn"] else "<span class=no>writable txn</span>")
    if "replica" in g:
        meas.append("replica" if g["replica"] else "primary")
    if g.get("superuser"):
        meas.append("<span class=no>superuser</span>")
    if g.get("writable_mount"):
        meas.append("<span class=no>mount is writable; the runner only reads</span>")
    return f'{body}{state}' + (f' <small class=lbl>({", ".join(meas)})</small>' if meas else "")


def make_access(app: FastAPI, config_path, nav_html, base_css: str, back) -> dict:
    """Registers the routes; returns the PROD-tab fragment renderer for ui_prod."""

    def store() -> PatternStore:
        return PatternStore()

    def refresh(st: PatternStore) -> None:
        PR.import_inboxes(st)
        usage.update(st)

    def all_routes(cfg, st: PatternStore) -> dict[str, A.Route]:
        return {r.key: r for r in st.routes()}

    def envs_of(p: Pattern, cfg) -> list[str]:
        names = [x.name for x in E.environments(cfg)]
        return names if p.scope == "global" else [n for n in names if p.in_scope(n)]

    def shown_envs(p: Pattern, cfg) -> list[str]:
        """The environments a pattern is listed under: the registered ones in its scope, plus scope names that are not
        registered (the approved rules stay visible; their route then shows as not approved)."""
        known = envs_of(p, cfg)
        if p.scope == "global":
            return known
        scoped = [p.scope] if isinstance(p.scope, str) else p.scope
        return known + [n for n in scoped if n not in known]

    # ------------------------------------------------------------------ PROD tab: proposals + recently approved
    def proposals_html(st: PatternStore, cfg) -> str:
        props = st.proposals("pending")
        if not props:
            return ""
        out = ""
        for pr in props:
            prop: A.Proposal = pr["proposal"]
            items = {i["item_id"]: i for i in pr["items"]}
            rows = ""
            for iid, kind, it in prop.items():
                rec = items[iid]
                if rec["decision"] != "pending":
                    continue
                feas = json.loads(rec["feasibility_json"] or "{}")
                fb = ('<span class=ok>feasible</span>' if feas.get("ok", True) else f'<span class=no>{e(feas.get("reason", ""))}</span>')
                if feas.get("needs"):
                    fb += f' <span class=tag>needs {e(feas["needs"])}</span>'
                box = f'<input type=checkbox name=item value="{e(pr["id"])}:{iid}" form=wbulk>'
                ev = f'<br><small class=lbl>evidence: {e(it.evidence)}</small>' if it.evidence else ""
                if kind == "route":
                    r = it.route
                    sec = "".join(f'<br><input type=password name="secret_{e(s)}" form=wbulk placeholder="{e(s)} value (stored 0600 on approve)" '
                                  f'size=40 autocomplete=off>' for s in (r.secret, r.user_secret, r.password_secret)
                                  if s and "needs" in feas)
                    rows += (f'<tr><td>{box}<td><span class=tag>route</span><td><b>{e(r.kind)}/{e(r.name)}</b>'
                             f'<td>{route_text(r)}{sec}{ev}<td>{fb}</tr>')
                elif kind == "query":
                    p = it.pattern
                    q = query_cell(tpl_text(p), {k: v.model_dump(exclude_none=True) for k, v in p.params.items()},
                                   f"/prod/proposals/{e(pr['id'])}/{iid}/edit")
                    rows += (f'<tr><td>{box}<td><span class=tag>{e(p.kind)}</span><td><b>{e(p.name)}</b><br><small class=lbl>{e(p.description)}</small>'
                             f'<br><small class=lbl>route {e(it.route)}{"" if p.risk == "read" else " &middot; <b class=no>write</b>"}</small>'
                             f'<td>{q}{ev}<td>{fb}</tr>')
                else:
                    rows += (f'<tr><td>{box}<td><span class=tag>enable</span><td><b>{e(it.pattern)}</b><td>make it available in {e(prop.env)} '
                             f'(route {e(it.route)}){ev}<td>{fb}</tr>')
            who = f'agent, session {e(prop.session)}' if prop.session else e(prop.by)
            out += (f'<div class=prop><label><input type=checkbox onchange="selProp(this)"> <b>{e(prop.env)}</b></label> '
                    f'<span class=lbl>{who} &middot; {fmt_ts(prop.created_at)}</span><br><i>{e(prop.task)}</i>'
                    f'<table><tr><th><th>Item<th>Name<th>Detail<th>Feasibility</tr>{rows}</table></div>')
        return out

    def recent_html(st: PatternStore, cfg) -> str:
        appr = st.approved_at()
        stats = usage.stats(st)
        pats = [p for p in st.list() if p.enabled and not p.proposed_by_agent]
        pats.sort(key=lambda p: (appr.get(p.name, (None, None))[0] or 0), reverse=True)
        cut = time.time() - RECENT_DAYS * 86400
        recent = [p for i, p in enumerate(pats) if i < RECENT_MIN or (appr.get(p.name, (None,))[0] or 0) >= cut]
        if not recent:
            return '<p class=lbl>Nothing approved yet: until a pattern is approved, every raw query is rejected.</p>'
        rows = ""
        for p in recent:
            at, by = appr.get(p.name, (None, None))
            rows += (f'<tr><td><input type=checkbox name=sel value="{e(p.name)}" form=rbulk><td>{name_cell(p.name, f"/prod/patterns/{e(p.name)}/rename")}'
                     f'<small class=lbl>{e(p.description)}</small><td>{e(p.kind)}<td>{e(", ".join(envs_of(p, cfg)))}<br><small class=lbl>route {e(p.route or "default")}</small>'
                     f'<td>{query_cell(tpl_text(p), {k: v.model_dump(exclude_none=True) for k, v in p.params.items()}, f"/prod/patterns/{e(p.name)}/edit")}'
                     f'<td>{fmt_ts(at)}{f"<br><small class=lbl>{e(by)}</small>" if by else ""}{stat_cells(stats.get(p.name))}</tr>')
        return ('<form id=rbulk method=post action=/prod/patterns/bulk class=bulk><b>Selected patterns:</b><select name=action>'
                '<option value=disable>Disable<option value=enable>Enable<option value=remove>Remove<option value=export>Export YAML</select>'
                '<button onclick="return this.form.action.value!==\'remove\'||confirm(\'Remove the selected patterns? History stays in the audit log.\')">Apply</button>'
                '<span class=lbl>Recently approved only; the full catalogue is in <a href=/settings/access>Settings &rsaquo; Access</a>.</span></form>'
                f'<div class=scroll><table><tr><th><input type=checkbox onchange="selAll(this,\'sel\')" form=rbulk><th>Name<th>Kind<th>Environments<th>Query'
                f'<th>Approved{STAT_HEAD}</tr>{rows}</table></div>')

    def calls_html() -> str:
        """Mutating calls blocked in a running session until a human decides (one call, or the tool for the session)."""
        rows = ""
        for a in gwsession.pending_approvals():
            rows += (f'<tr><td><input type=checkbox name=call value="{e(a["session"])}:{e(a["id"])}" form=wbulk>'
                     f'<td>{e(a["environment"])}<br><small class=lbl>session {e(a["session"])} &middot; {fmt_ts(a.get("ts"))}</small>'
                     f'<td><b>{e(a["tool"])}</b> <span class=tag>{e(a["risk"])}</span>'
                     f'<td><pre class=json>{e(json.dumps(a["args"], indent=1, default=str))}</pre></tr>')
        if not rows:
            return ""
        return ('<div class=prop><label><input type=checkbox onchange="selAll(this,\'call\')"> <b>Calls blocked right now</b></label> '
                '<span class=lbl>the agent waits (up to 5 minutes) for this one call to change something</span>'
                f'<table><tr><th><th>Environment<th>Call<th>Arguments</tr>{rows}</table></div>')

    def waiting_html() -> str:
        st = store()
        refresh(st)
        cfg = load_config(config_path)
        calls, props = calls_html(), proposals_html(st, cfg)
        if not calls and not props:
            return '<p class=lbl>Nothing is waiting.</p>'
        groups = calls + (f'<h3>New access requested <small class=lbl>(approving enables it in that environment for every later '
                          f'session)</small></h3>{props}' if props else "")
        return ('<form id=wbulk method=post action=/prod/waiting/bulk class=bulk><b>Selected:</b><select name=action>'
                '<option value=approve>Approve<option value=session>Approve for session (calls)<option value=reject>Reject</select>'
                '<input name=note placeholder="note for the agent (reject)" size=40><button>Apply</button></form>' + groups)

    def waiting_count() -> int:
        st = store()
        PR.import_inboxes(st)
        return len(gwsession.pending_approvals()) + sum(1 for p in st.proposals("pending") for i in p["items"] if i["decision"] == "pending")

    def prod_fragment() -> str:
        st = store()
        refresh(st)
        return f'<div id=patterns>{recent_html(st, load_config(config_path))}</div>'

    @app.get("/prod/patterns-fragment", response_class=HTMLResponse)
    def patterns_fragment():
        return prod_fragment()

    @app.get("/prod/waiting-fragment", response_class=HTMLResponse)
    def waiting_fragment():
        return waiting_html()

    # ------------------------------------------------------------------ actions
    @app.post("/prod/waiting/bulk")
    async def waiting_bulk(request: Request):
        form = await request.form()
        sel = [str(x) for x in form.getlist("item")]
        calls = [str(x) for x in form.getlist("call")]
        action, note = str(form.get("action", "")), str(form.get("note", "")).strip()
        secrets = {k[7:]: str(v) for k, v in form.items() if k.startswith("secret_") and str(v)}

        def go():
            if not sel and not calls:
                raise ConfigError("select at least one item")
            if action not in ("approve", "session", "reject"):
                raise ConfigError("unknown action")
            for v in calls:   # a blocked call: once, for the session, or not at all
                sid, _, aid = v.partition(":")
                if not re.fullmatch(r"[a-f0-9]{6,32}", sid):
                    raise ConfigError("bad session id")
                gwsession.decide(sid, aid, {"approve": "approved", "session": "session", "reject": "rejected"}[action])
            if action == "session":
                action_p = "approve"   # proposals have no session scope: an approval is per environment
            else:
                action_p = action
            by_pid: dict[str, list[str]] = {}
            for v in sel:
                pid, _, iid = v.partition(":")
                by_pid.setdefault(pid, []).append(iid)
            st, cfg = store(), load_config(config_path)
            for pid, iids in by_pid.items():
                PR.decide(st, cfg, pid, approve=iids if action_p == "approve" else [], reject=iids if action_p == "reject" else [],
                          note=note, by="ui", secrets=secrets)
        return back(go, "/prod#waiting")

    @app.post("/prod/proposals/{pid}/{iid}/edit")
    def proposal_edit(pid: str, iid: str, template: str = Form(...), params: str = Form("")):
        def go():
            st, cfg = store(), load_config(config_path)
            rec = st.proposal(pid)
            if rec is None or not iid.startswith("q"):
                raise ConfigError("unknown proposal item")
            prop: A.Proposal = rec["proposal"]
            q = prop.queries[int(iid[1:])]
            p = edited(q.pattern, template, params)
            route = all_routes(cfg, st).get(f"{prop.env}/{A.ROUTE_KIND[p.kind]}/{q.route}") or \
                next((x.route for x in prop.routes if x.route.name == q.route and x.route.kind == A.ROUTE_KIND[p.kind]), None)
            from .patterns import Policy, validate
            validate(p, route.policy() if route else Policy())
            q2 = q.model_copy(update={"pattern": p})
            prop2 = prop.model_copy(update={"queries": [q2 if i == int(iid[1:]) else x for i, x in enumerate(prop.queries)]})
            with st._c() as c:
                c.execute("update proposal set body_json=? where id=?", (prop2.model_dump_json(), pid))
                c.execute("update proposal_item set body_json=? where proposal_id=? and item_id=?", (q2.model_dump_json(), pid, iid))
        return back(go, "/prod#waiting")

    def edited(p: Pattern, template: str, params: str) -> Pattern:
        t = template.strip()
        try:
            tpl = json.loads(t) if p.kind == "elasticsearch" else t
            prm = json.loads(params.strip() or "{}")
        except ValueError as ex:
            raise PatternError(f"not valid JSON: {ex}")
        return Pattern.model_validate({**p.model_dump(), "template": tpl, "params": prm})

    def policy_for(p: Pattern, cfg, st: PatternStore):
        from .patterns import Policy
        routes = all_routes(cfg, st)
        envs = envs_of(p, cfg)
        pols = [routes[k].policy() for k in (f"{n}/{A.ROUTE_KIND[p.kind]}/{p.route or 'default'}" for n in envs) if k in routes]
        return pols or [Policy()]

    @app.post("/prod/patterns/{name}/edit")
    def pattern_edit(name: str, template: str = Form(...), params: str = Form(""), to: str = Form("/prod#patterns")):
        def go():
            st, cfg = store(), load_config(config_path)
            p = st.get(name)
            if not p:
                raise PatternError("unknown pattern")
            p2 = edited(p, template, params)
            pols = policy_for(p2, cfg, st)
            for pol in pols[1:]:
                from .patterns import validate
                validate(p2, pol)
            st.upsert(p2, by="ui", policy=pols[0])
        return back(go, safe_to(to))

    @app.post("/prod/patterns/{name}/rename")
    def pattern_rename(name: str, new: str = Form(...), to: str = Form("/prod#patterns")):
        return back(lambda: store().rename(name, new.strip(), by="ui"), safe_to(to))

    def safe_to(to: str) -> str:
        return to if to.startswith("/prod") or to.startswith("/settings/access") else "/prod#patterns"

    @app.post("/prod/patterns/bulk")
    async def patterns_bulk(request: Request):
        form = await request.form()
        names = [str(x) for x in form.getlist("sel")]
        keys = [str(x) for x in form.getlist("route")]
        action, target_env = str(form.get("action", "")), str(form.get("env", ""))
        to = safe_to(str(form.get("to", "/prod#patterns")))
        st = store()
        if action == "export":
            pats = [p for p in st.list() if p.name in names]
            import yaml
            items = [p.model_dump(mode="json", exclude_defaults=True, exclude={"proposed_by_agent"}) | {"name": p.name} for p in pats]
            routes = [r.model_dump(mode="json", exclude_defaults=True, exclude={"status", "guarantees", "error", "source"})
                      for r in st.routes() if r.key in keys]
            return PlainTextResponse(yaml.safe_dump({"query_patterns": items, **({"routes": routes} if routes else {})}, sort_keys=False),
                                     media_type="text/yaml")

        def go():
            if not names and not keys:
                raise ConfigError("select at least one pattern or route")
            if action in ("disable", "enable"):
                for n in names:
                    st.set_enabled(n, action == "enable")
                for k in keys:
                    r = st.route(k)
                    if r:
                        st.put_route(r.model_copy(update={"enabled": action == "enable"}), by="ui")
            elif action == "remove":
                for n in names:
                    st.remove(n)
                for k in keys:
                    st.remove_route(k)
            elif action == "propose":
                E.environment(load_config(config_path), target_env)   # must exist
                PR.propose_for_env(st, names, target_env, by="ui")
            else:
                raise ConfigError("unknown action")
        return back(go, to)

    # ------------------------------------------------------------------ Settings > Access
    PAGE = """<!doctype html><meta charset=utf-8><title>AirlockAI - Access</title><style>{base_css}{css}{xcss}</style>
{nav}<main><p class=err>{error}</p><p class=subnav><a href=/settings>General</a><b>Access</b></p>
<h2>Approved access <small class=lbl>(routes and query patterns, per environment; new ones arrive as proposals in the PROD tab)</small></h2>
<p class=ktabs>{ktabs}</p>
<form method=get class=bulk><input type=hidden name=kind value="{kind}"><input name=q value="{q}" placeholder="search name, description, query" size=32>
<select name=env><option value="">all environments{env_opts}</select>
<select name=enabled><option value="">enabled and disabled<option value=on {en_on}>enabled<option value=off {en_off}>disabled</select>
<select name=sort><option value=name {s_name}>sort: name<option value=last_used {s_last}>sort: last used<option value=calls {s_calls}>sort: calls</select>
<button>Filter</button> <span class=lbl>{count}</span></form>
<form id=abulk method=post action=/prod/patterns/bulk class=bulk><input type=hidden name=to value="{here}"><b>Selected:</b>
<select name=action><option value=disable>Disable<option value=enable>Enable<option value=remove>Remove<option value=export>Export YAML
<option value=propose>Propose for environment...</select><select name=env>{env_opts}</select>
<button onclick="return this.form.action.value!=='remove'||confirm('Remove the selected items? History stays in the audit log.')">Apply</button></form>
<table><tr><th><input type=checkbox onchange="selAll(this,'sel')"><th>Name<th>Environments<th>Query<th>Approved{stat_head}</tr>{rows}</table>
<p>{pager}</p>
<details><summary>Import YAML</summary><form method=post action=/settings/access/import class=add><textarea name=yaml rows=6 cols=90
placeholder="query_patterns:\\n  - name: ..."></textarea><br><button>Import</button></form></details>
</main><script>{js}</script>"""

    @app.get("/settings/access", response_class=HTMLResponse)
    def access_page(kind: str = "postgres", q: str = "", env: str = "", enabled: str = "", sort: str = "name", page: int = 1, error: str = ""):
        if kind not in A.ROUTE_KINDS:
            kind = "postgres"
        st, cfg = store(), load_config(config_path)
        refresh(st)
        stats, appr = usage.stats(st), st.approved_at()
        routes = {k: r for k, r in all_routes(cfg, st).items() if r.kind == kind and (not env or r.env == env)}
        pk = A.PATTERN_KIND.get(kind)   # files routes have no patterns
        ql = q.lower().strip()
        rows_by_route: dict[str, list[Pattern]] = {}
        for p in st.list(kind=pk, proposed=False) if pk else []:
            if enabled and p.enabled != (enabled == "on"):
                continue
            if ql and ql not in f"{p.name} {p.description} {tpl_text(p)}".lower():
                continue
            for n in shown_envs(p, cfg):
                if env and n != env:
                    continue
                key = f"{n}/{kind}/{p.route or 'default'}"
                rows_by_route.setdefault(key if key in routes else f"{n}/{kind}/?{p.route or 'default'}", []).append(p)
        sortkey = {"name": lambda p: p.name, "last_used": lambda p: -(stats.get(p.name, {}).get("last_used") or 0),
                   "calls": lambda p: -stats.get(p.name, {}).get("calls", 0)}.get(sort, lambda p: p.name)
        flat = []   # (transport, route key, pattern | None) in display order
        for transport in ("direct", "exec", "none"):
            keys = sorted(k for k in set(routes) | set(rows_by_route)
                          if (routes[k].transport if k in routes else "none") == transport)
            for k in keys:
                flat.append((transport, k, None))
                flat += [(transport, k, p) for p in sorted(rows_by_route.get(k, []), key=sortkey)]
        n_pat = sum(1 for x in flat if x[2] is not None)
        pages = max(1, -(-len(flat) // PAGE_SIZE))
        page = min(max(1, page), pages)
        chunk = flat[(page - 1) * PAGE_SIZE: page * PAGE_SIZE]
        here = "/settings/access?" + urlencode({"kind": kind, "q": q, "env": env, "enabled": enabled, "sort": sort, "page": page})
        rows, last_t = "", None
        ncol = 5 + STAT_HEAD.count("<th>")
        for transport, k, p in chunk:
            if transport != last_t:
                label = {"direct": "Direct (the gateway connects with a secret)", "exec": "Exec (a runner in an application pod)",
                         "none": "No approved route"}[transport]
                rows += f'<tr class=grp><td colspan={ncol}>{label}</tr>'
                last_t = transport
            if p is None:
                r = routes.get(k)
                box = (f'<input type=checkbox name=route value="{e(k)}" form=abulk>' if r else "")
                desc = route_text(r) + ("" if r.enabled else ' <span class=lbl>disabled</span>') if r else '<span class=no>route not approved</span>'
                us = stats.get(f"route:{k}")
                use = (f' <small class=lbl>&middot; {us["calls"]} call(s), last {fmt_ts(us["last_used"])}, {us["errors"]} error(s)</small>'
                       if us else "")
                rows += f'<tr><td>{box}<td colspan={ncol - 1}>route <b>{e(k.replace("?", ""))}</b> &middot; {desc}{use}</tr>'
                continue
            at, by = appr.get(p.name, (None, None))
            st_ = "" if p.enabled else ' <span class=lbl>disabled</span>'
            rows += (f'<tr><td><input type=checkbox name=sel value="{e(p.name)}" form=abulk><td>{name_cell(p.name, f"/prod/patterns/{e(p.name)}/rename")}'
                     f'<small class=lbl>{e(p.description)}</small>{st_}<br><a href="/settings/access/pattern/{quote(p.name)}">usage and history</a>'
                     f'<td>{e(", ".join(shown_envs(p, cfg)))}<td>{query_cell(tpl_text(p), {a: b.model_dump(exclude_none=True) for a, b in p.params.items()}, f"/prod/patterns/{e(p.name)}/edit")}'
                     f'<td>{fmt_ts(at)}{stat_cells(stats.get(p.name))}</tr>')
        if not chunk:
            rows = f'<tr><td colspan={ncol}><span class=lbl>Nothing here yet.</span></tr>'
        pager = " ".join(f'<b>{i}</b>' if i == page else f'<a href="{e(here.replace(f"page={page}", f"page={i}"))}">{i}</a>' for i in range(1, pages + 1)) if pages > 1 else ""
        env_names = [x.name for x in E.environments(cfg)]
        ktabs = "".join(f'<a class="{"on" if k == kind else ""}" href="/settings/access?kind={k}">{lbl}</a>' for k, lbl in KIND_TABS)
        body = PAGE.format(base_css=base_css, css=CSS, xcss="table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid #8884;padding:.35rem;text-align:left;vertical-align:top}"
                           ".lbl{color:#888}.err{color:#d33}.err:empty{display:none}form{display:inline}",
                           nav=nav_html("settings"), error=e(error), ktabs=ktabs, kind=e(kind), q=e(q),
                           env_opts="".join(f'<option{" selected" if n == env else ""}>{e(n)}' for n in env_names),
                           en_on="selected" if enabled == "on" else "", en_off="selected" if enabled == "off" else "",
                           s_name="selected" if sort == "name" else "", s_last="selected" if sort == "last_used" else "",
                           s_calls="selected" if sort == "calls" else "", count=f"{n_pat} pattern(s), {len(routes)} route(s)",
                           here=e(here), stat_head=STAT_HEAD, rows=rows, pager=pager, js=EDIT_JS)
        return HTMLResponse(body)

    @app.get("/settings/access/pattern/{name}", response_class=HTMLResponse)
    def pattern_detail(name: str):
        st = store()
        refresh(st)
        p = st.get(name)
        if not p:
            raise HTTPException(404)
        s = usage.stats(st).get(name, {})
        calls = "".join(f'<tr><td>{fmt_ts(c["ts"])}<td>{e(c["session"] or "")}<td>{e(c["env"] or "")}<td>{"ok" if c["ok"] else "<span class=no>error</span>"}'
                        f'<td class=num>{c["ms"] if c["ms"] is not None else ""}<td class=num>{c["rows"] if c["rows"] is not None else ""}<td>v{c["version"] or "?"}'
                        f'<td><a href="/audit/{e(c["session"] or "")}" target=_blank>audit</a>{f" <small class=no>{e(c["error"])}</small>" if c["error"] else ""}</tr>'
                        for c in usage.recent(st, name))
        days = usage.daily(st, name)
        top = max([d[1] for d in days] + [1])
        chart = "".join(f'<div title="{d[0]}: {d[1]} calls, {d[2]} errors" style="display:inline-block;width:10px;margin-right:2px;vertical-align:bottom;'
                        f'height:{max(2, int(60 * d[1] / top))}px;background:{"#d33" if d[2] else "#2a6df4"}"></div>' for d in days)
        hist = "".join(f'<tr><td>v{h["version"]}<td>{fmt_ts(h["updated_at"])}<td>{e(h["updated_by"])}<td><code class=ed>{e(tpl_text(h["template"]))}</code></tr>'
                       for h in reversed(st.history(name)))
        return HTMLResponse(f'<!doctype html><meta charset=utf-8><title>{e(name)}</title><style>{base_css}{CSS}table{{border-collapse:collapse}}'
                            f'td,th{{border-bottom:1px solid #8884;padding:.35rem;text-align:left;vertical-align:top}}.lbl{{color:#888}}</style>'
                            f'{nav_html("settings")}<main><p class=subnav><a href=/settings>General</a><a href="/settings/access?kind={A.ROUTE_KIND[p.kind]}">Access</a></p>'
                            f'<h2>{e(name)} <small class=lbl>{e(p.kind)}, route {e(p.route or "default")}</small></h2><p>{e(p.description)}</p>'
                            f'<table><tr>{STAT_HEAD}</tr><tr>{stat_cells(s)[0:]}</tr></table>'
                            f'<h3>Calls per day, last 30 days</h3><div style="height:64px">{chart}</div>'
                            f'<h3>Recent calls</h3><table><tr><th>Time<th>Session<th>Environment<th>Outcome<th>ms<th>Rows<th>Version<th></tr>{calls or "<tr><td colspan=8 class=lbl>No calls yet.</tr>"}</table>'
                            f'<h3>Versions</h3><table><tr><th>Version<th>Saved<th>By<th>Query</tr>{hist}</table></main>')

    @app.post("/settings/access/import")
    def access_import(yaml_text: str = Form("", alias="yaml")):
        import yaml

        def go():
            try:
                data = yaml.safe_load(yaml_text) or {}
            except yaml.YAMLError as ex:
                raise PatternError(f"not valid YAML: {ex}")
            items = data.get("query_patterns") if isinstance(data, dict) else data
            if not isinstance(items, list):
                raise PatternError("expected a list under query_patterns")
            st, cfg = store(), load_config(config_path)
            pats = [Pattern.model_validate(raw) for raw in items]
            for p in pats:   # all validated before any is saved
                from .patterns import validate
                for pol in policy_for(p, cfg, st):
                    validate(p, pol)
            for n in st.import_list(items, by="ui-import"):
                st.mark_approved(n, "ui-import")
        return back(go, "/settings/access")

    @app.get("/prod/patterns/export", response_class=PlainTextResponse)
    def pattern_export():
        return PlainTextResponse(store().export_yaml(), media_type="text/yaml")

    return {"fragment": prod_fragment, "waiting": waiting_html, "count": waiting_count, "css": CSS, "js": EDIT_JS}
