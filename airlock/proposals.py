"""Controller side of the approval flow (SPEC 7.8): import proposals from session inboxes, decide them, report back.

The gateway queues a feasible proposal as `inbox/proposals/<id>.json`. The controller moves it into the store, a human
decides each item in the UI, and the controller then writes the routes and patterns (live in the gateway through the
snapshot), runs the activation check on new routes, and writes `inbox/proposal-status/<id>.json`, which the agent's
`proposal.status` reads.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

from . import access as A
from .audit import Audit
from .backends import Backends
from .config import Config, ConfigError
from .envs import environment, load_secrets, write_secret
from .patterns import Pattern, PatternError
from .patternstore import PatternStore


def _sessions_dir() -> Path:
    from . import session
    return session.SESSIONS


def import_inboxes(store: PatternStore) -> list[str]:
    """Move queued proposals (bundles, and single patterns from older gateways) into the store. Returns their ids."""
    done = []
    root = _sessions_dir()
    for d in sorted(root.glob("*/inbox/proposals")) if root.is_dir() else []:
        sid = d.parent.parent.name
        for f in sorted(d.glob("*.json")):
            try:
                raw = json.loads(f.read_text())
                if raw.get("type") == "bundle":
                    prop = A.Proposal.model_validate(raw["proposal"])
                    feas = raw.get("feasibility") or {}
                else:   # a single pattern written by a gateway from before the bundles
                    p = Pattern.model_validate(raw)
                    env = p.scope[0] if isinstance(p.scope, list) and p.scope else str(p.scope)
                    prop = A.Proposal(id=A.new_proposal_id(), env=env, session=sid, task=p.description, created_at=time.time(),
                                      queries=[A.QueryItem(pattern=p.model_copy(update={"scope": [env]}))])
                    feas = {"q0": {"ok": True}}
                if store.proposal(prop.id) is None:
                    store.add_proposal(prop, feas)
                    Audit(sid).log("controller", "proposal.received", id=prop.id, items=[i for i, _, _ in prop.items()])
                    done.append(prop.id)
            except (ValueError, KeyError, PatternError):
                pass   # malformed: dropped; the gateway's audit has what was submitted
            f.unlink()
    return done


def propose_for_env(store: PatternStore, names: list[str], env: str, *, by: str = "ui") -> str:
    """UI bulk action: make existing patterns available in another environment, as a proposal that needs approval there."""
    if not names:
        raise ConfigError("select at least one pattern")
    items = []
    for n in names:
        p = store.get(n)
        if not p:
            raise ConfigError(f"unknown pattern {n}")
        if p.in_scope(env):
            raise ConfigError(f"{n} is already available in {env}")
        items.append(A.EnableItem(pattern=n, route=p.route or "default", evidence=f"copied by {by}"))
    prop = A.Proposal(id=A.new_proposal_id(), env=env, task=f"make {len(names)} pattern(s) available in {env}", by=by,
                      created_at=time.time(), enable=items)
    store.add_proposal(prop, {i: {"ok": True} for i, _, _ in prop.items()})
    return prop.id


def _route_in(store: PatternStore, cfg: Config, env_name: str, kind: str, name: str) -> A.Route | None:
    return store.route(f"{env_name}/{kind}/{name}")


def decide(store: PatternStore, cfg: Config, pid: str, *, approve: list[str] = (), reject: list[str] = (), note: str = "",
           by: str = "ui", secrets: dict[str, str] | None = None, backends: Backends | None = None) -> dict:
    """Apply a human's decision to items of a proposal. Routes first (activated), then queries, then enable items."""
    rec = store.proposal(pid)
    if rec is None:
        raise ConfigError(f"unknown proposal {pid}")
    prop: A.Proposal = rec["proposal"]
    pending = {i["item_id"] for i in rec["items"] if i["decision"] == "pending"}
    bad = (set(approve) | set(reject)) - pending
    if bad:
        raise ConfigError(f"not pending: {', '.join(sorted(bad))}")
    env = environment(cfg, prop.env)
    audit = Audit(prop.session or "approvals")
    for var, value in (secrets or {}).items():
        if value:
            write_secret(env, var, value)
    for iid in reject:
        store.decide_item(pid, iid, "rejected", by=by, note=note or None)
    backends = backends or Backends()
    items = {iid: (kind, it) for iid, kind, it in prop.items()}
    for iid in sorted(approve, key=lambda i: "rqe".index(i[0])):
        kind, it = items[iid]
        try:
            result = _approve_item(store, cfg, env, kind, it, by=by, backends=backends)
            store.decide_item(pid, iid, "approved", by=by, result=result)
        except (ConfigError, PatternError, ValueError) as e:
            store.decide_item(pid, iid, "failed", by=by, result=str(e))
    audit.log("controller", "proposal.decided", id=pid, approved=list(approve), rejected=list(reject), by=by)
    status = report(store, pid)
    return status


def _approve_item(store: PatternStore, cfg: Config, env, kind: str, it, *, by: str, backends: Backends) -> str:
    if kind == "route":
        r = it.route.model_copy(update={"env": env.name, "source": "approved", "enabled": True, "status": "pending"})
        secrets = load_secrets(env.secrets_path())
        r = A.activate(r, env, backends, secret=lambda n: secrets.get(n), ex=env.exec_for(None))
        store.put_route(r, by=by)
        return "active" if r.status == "active" else f"approved but inactive: {r.error}"
    if kind == "query":
        p = it.pattern
        route = _route_in(store, cfg, env.name, A.ROUTE_KIND[p.kind], it.route)
        if route is None:
            raise ConfigError(f"route {A.ROUTE_KIND[p.kind]}/{it.route} is not approved in {env.name}")
        old = store.get(p.name)
        if old is not None:
            same = (old.kind, old.template, old.route or "default") == (p.kind, p.template, it.route)
            if not same:
                raise ConfigError(f"a different pattern named {p.name} already exists; rename it and propose again")
            scope = old.scope if isinstance(old.scope, list) else [old.scope] if old.scope != "global" else "global"
            if scope != "global" and env.name not in scope:
                store.upsert(old.model_copy(update={"scope": [*scope, env.name], "enabled": True}), by=by, policy=route.policy())
        else:
            store.upsert(p.model_copy(update={"scope": [env.name], "route": it.route, "enabled": True, "proposed_by_agent": False}),
                         by=by, policy=route.policy())
        store.mark_approved(p.name, by)
        return "enabled" + ("" if route.status == "active" else f" (route {route.name} is {route.status})")
    # enable: an existing pattern in another environment
    p = store.get(it.pattern)
    if p is None:
        raise ConfigError(f"unknown pattern {it.pattern}")
    route = _route_in(store, cfg, env.name, A.ROUTE_KIND[p.kind], it.route)
    if route is None:
        raise ConfigError(f"{env.name} has no route {A.ROUTE_KIND[p.kind]}/{it.route}: approve one there first")
    scope = p.scope if isinstance(p.scope, list) else [p.scope]
    store.upsert(p.model_copy(update={"scope": sorted({*scope, env.name}), "enabled": True}), by=by, policy=route.policy())
    store.mark_approved(p.name, by)
    return "enabled"


def report(store: PatternStore, pid: str) -> dict:
    """The decision as the agent sees it, written to its session inbox."""
    rec = store.proposal(pid)
    prop: A.Proposal = rec["proposal"]
    names = {iid: (it.route.key if kind == "route" else it.pattern.name if kind == "query" else it.pattern)
             for iid, kind, it in prop.items()}
    items = [{"id": i["item_id"], "kind": i["kind"], "name": names[i["item_id"]], "decision": i["decision"],
              **({"note": i["note"]} if i["note"] else {}), **({"result": i["result"]} if i["result"] else {})} for i in rec["items"]]
    out = {"id": pid, "status": "pending" if any(i["decision"] == "pending" for i in items) else "decided", "items": items,
           "message": "Approved queries are usable now: run them with query.run {name, params} (or sql.query / es.search / "
                      "redis.command with the actual query). Rejected items carry the human's note."}
    if prop.session:
        d = _sessions_dir() / prop.session / "inbox" / "proposal-status"
        if d.parent.is_dir():
            d.mkdir(exist_ok=True)
            tmp = d / f".{pid}.tmp"
            tmp.write_text(json.dumps(out))
            tmp.replace(d / f"{pid}.json")
    return out
