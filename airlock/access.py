"""Access routes and proposals (SPEC 7.8): how the gateway reaches a data store, and the agent's way to ask for more.

A route belongs to one environment and one store kind. `direct`: the gateway connects with a secret it holds.
`exec`: the gateway runs a built-in runner in an application pod (`kubectl exec -i`), with the pod's own credentials.
Routes come only from the approval flow: stored with the patterns, live in the gateway through the snapshot.

Before a human approves, a proposal is only validated and Kubernetes metadata is read (`check_target`): no connection
to a store, no exec. After approval the controller runs `activate` once per new route, which probes it read-only and
records what it measured.
"""
from __future__ import annotations

import re
import secrets
import time
from typing import Any, Callable, Literal

from pydantic import field_validator, model_validator

from .config import ConfigError, Exec, Strict
from .patterns import KINDS as PATTERN_KINDS, Limits, Pattern, PatternError, Policy, validate as validate_pattern

ROUTE_KINDS = ("postgres", "elasticsearch", "redis", "files")
PATTERN_KIND = {"postgres": "sql", "elasticsearch": "elasticsearch", "redis": "redis"}   # files: no patterns, the roots are the policy
ROUTE_KIND = {v: k for k, v in PATTERN_KIND.items()}
# (kind, runner) pairs built in so far; the agent picks from these only. Every one uses the pod's own credentials:
# django and airflow: the application's database connection; python: the pod's mounted files, or (redis, elasticsearch)
# the pod's environment variables named by `url_var` etc., whose values never leave the pod.
RUNNERS = {("postgres", "django"), ("postgres", "airflow"), ("files", "python"), ("redis", "python"), ("elasticsearch", "python")}
ROUTE_NAME = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
SECRET_NAME = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
K8S_NAME = r"[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?"
DJANGO_SHELL = ["python", "manage.py", "shell", "-v", "0"]
PYTHON_STDIN = ["python", "-I", "-"]   # the python runner: a fixed program on stdin, standard library only
# The airflow runner imports Airflow, which the official image installs in the user site: no -I (that would hide it)
AIRFLOW_STDIN = ["python", "-"]
# Never a files root, nor inside one: credentials and kernel interfaces of the pod
DENIED_ROOTS = ("/", "/etc", "/proc", "/sys", "/dev", "/run", "/var/run", "/root", "/home", "/boot", "/usr", "/bin", "/sbin", "/lib")


class ExecTarget(Strict):
    namespace: str
    workload: str                    # deploy/NAME, statefulset/NAME or a pod name
    container: str | None = None

    @field_validator("workload")
    @classmethod
    def _workload(cls, v):
        if not re.fullmatch(rf"((deploy|deployment|statefulset|sts|pod)/)?{K8S_NAME}", v):
            raise ValueError(f"workload {v!r} must be deploy/NAME, statefulset/NAME or a pod name")
        return v

    @field_validator("namespace", "container")
    @classmethod
    def _name(cls, v):
        if v is not None and not re.fullmatch(K8S_NAME, v):
            raise ValueError(f"bad kubernetes name {v!r}")
        return v


class Route(Strict):
    env: str
    kind: Literal["postgres", "elasticsearch", "redis", "files"]
    name: str = "default"
    transport: Literal["direct", "exec"]
    secret: str | None = None          # direct: the variable holding the DSN / URL (value in the secrets dir, never here)
    user_secret: str | None = None     # direct elasticsearch with basic auth
    password_secret: str | None = None
    target: ExecTarget | None = None   # exec
    runner: Literal["django", "airflow", "python"] | None = None
    roots: list[str] | None = None     # files: absolute directories readable through this route (nothing outside them)
    url_var: str | None = None         # exec redis / elasticsearch: NAME of the pod's environment variable holding the URL
    user_var: str | None = None        # exec elasticsearch with basic auth: names of the pod's variables (values stay there)
    password_var: str | None = None
    context: str | None = None         # exec: kube context, default the environment's
    schemas: list[str] | None = None   # allowlists applied when patterns on this route are validated
    indices: list[str] | None = None
    key_prefixes: list[str] | None = None
    require_replica: bool = False
    max_rows: int | None = None
    # state, set by the controller
    enabled: bool = True
    status: Literal["pending", "active", "inactive"] = "active"
    guarantees: dict[str, Any] = {}
    error: str | None = None
    source: Literal["approved"] = "approved"

    @field_validator("name")
    @classmethod
    def _rname(cls, v):
        if not ROUTE_NAME.match(v):
            raise ValueError(f"route name must match {ROUTE_NAME.pattern}")
        return v

    @field_validator("secret", "user_secret", "password_secret", "url_var", "user_var", "password_var")
    @classmethod
    def _secret(cls, v):
        if v is not None and not SECRET_NAME.match(v):
            raise ValueError(f"secret names and pod variable names are environment variable names like PG_DSN, not values ({v[:4]}...)")
        return v

    @field_validator("roots")
    @classmethod
    def _roots(cls, v):
        if v is None:
            return v
        import posixpath
        out = []
        for r in v:
            if not isinstance(r, str) or not r.startswith("/") or posixpath.normpath(r) != r or "\0" in r:
                raise ValueError(f"root {r!r} must be a normalized absolute path (no .., no trailing /)")
            if any(r == d or d.startswith(r.rstrip("/") + "/") for d in DENIED_ROOTS) or \
                    any(r.startswith(d + "/") for d in ("/etc", "/proc", "/sys", "/dev", "/run", "/var/run", "/root")):
                raise ValueError(f"root {r} is, contains or is inside a system or credentials directory")
            out.append(r)
        if not out:
            raise ValueError("roots must not be empty")
        return out

    @model_validator(mode="after")
    def _shape(self):
        if self.kind == "files":
            if self.transport != "exec" or self.runner != "python" or not self.roots:
                raise ValueError("a files route is transport exec with runner python and `roots` (the directories it may read)")
        elif self.roots is not None:
            raise ValueError("roots are for files routes only")
        if self.transport == "exec" and self.kind in ("redis", "elasticsearch"):
            if self.runner != "python" or not self.url_var:
                raise ValueError(f"an exec {self.kind} route is runner python with `url_var`: the name of the pod's environment "
                                 "variable that holds the URL (e.g. REDIS_URLS); the value stays in the pod")
            if bool(self.user_var) != bool(self.password_var) or (self.user_var and self.kind == "redis"):
                raise ValueError("user_var and password_var go together, for elasticsearch only (redis: credentials in the URL)")
        elif self.url_var or self.user_var or self.password_var:
            raise ValueError("url_var, user_var and password_var are for exec redis and elasticsearch routes")
        if self.transport == "direct":
            if not self.secret:
                raise ValueError("a direct route needs `secret`: the name of the variable that holds the DSN or URL")
            if self.target or self.runner:
                raise ValueError("a direct route has no target or runner")
        else:
            if not self.target or not self.runner:
                raise ValueError("an exec route needs `target` {namespace, workload, container} and `runner`")
            if self.secret:
                raise ValueError("an exec route uses the pod's own credentials: no secret")
        return self

    @property
    def key(self) -> str:
        return f"{self.env}/{self.kind}/{self.name}"

    @property
    def pattern_kind(self) -> str:
        return PATTERN_KIND[self.kind]

    def policy(self) -> Policy:
        return Policy(schemas=self.schemas, indices=self.indices, key_prefixes=self.key_prefixes)

    def describe(self) -> dict:
        """What the agent and the UI see: never a secret value (only its name)."""
        d = self.model_dump(mode="json", exclude_none=True, exclude={"enabled", "error"} if self.status == "active" else {"enabled"})
        return d

    def pod_vars(self) -> dict[str, str]:
        """exec redis / elasticsearch: which of the pod's environment variables hold the URL and credentials (names only)."""
        return {k: v for k, v in (("url", self.url_var), ("user", self.user_var), ("password", self.password_var)) if v}

    def exec_args(self) -> list[str]:
        t = self.target
        cmd = {"python": PYTHON_STDIN, "airflow": AIRFLOW_STDIN}.get(self.runner, DJANGO_SHELL)
        return ["exec", "-i", "-n", t.namespace, t.workload] + (["-c", t.container] if t.container else []) + ["--", *cmd]


class RouteItem(Strict):
    route: Route
    evidence: str = ""


class QueryItem(Strict):
    pattern: Pattern
    route: str = "default"            # route name in the same environment
    evidence: str = ""


class EnableItem(Strict):
    """Make an existing pattern available in this environment (UI: Propose for environment)."""
    pattern: str
    route: str = "default"
    evidence: str = ""


class Proposal(Strict):
    id: str
    env: str
    session: str | None = None
    task: str = ""
    by: str = "agent"
    created_at: float
    routes: list[RouteItem] = []
    queries: list[QueryItem] = []
    enable: list[EnableItem] = []

    def items(self) -> list[tuple[str, str, Any]]:
        """(item id, kind, item) in a stable order: r0.., q0.., e0.."""
        return ([(f"r{i}", "route", x) for i, x in enumerate(self.routes)] + [(f"q{i}", "query", x) for i, x in enumerate(self.queries)]
                + [(f"e{i}", "enable", x) for i, x in enumerate(self.enable)])


def new_proposal_id() -> str:
    return secrets.token_hex(6)


def parse_submission(env_name: str, session: str | None, a: dict, *, by: str = "agent") -> Proposal:
    """Build a proposal from the agent's `proposal.submit` arguments. Raises ValueError with a readable message that
    never repeats the submitted values (a value in the wrong field may be a secret)."""
    from pydantic import ValidationError
    try:
        return _parse_submission(env_name, session, a, by=by)
    except ValidationError as e:
        raise ValueError("; ".join(f"{'.'.join(str(x) for x in err['loc']) or 'value'}: {err['msg']}" for err in e.errors())) from None


def _parse_submission(env_name: str, session: str | None, a: dict, *, by: str) -> Proposal:
    routes = []
    for r in a.get("routes") or []:
        r = dict(r)
        ev = r.pop("evidence", "")
        for k in ("env", "enabled", "status", "guarantees", "error", "source"):
            r.pop(k, None)   # set by airlock, never by the proposer
        routes.append(RouteItem(route=Route.model_validate({**r, "env": env_name, "status": "pending"}), evidence=str(ev)))
    queries = []
    for q in a.get("queries") or []:
        q = dict(q)
        ev, rname = q.pop("evidence", ""), q.pop("route", "default")
        kind = q.get("kind")
        if kind not in PATTERN_KINDS:
            raise ValueError(f"query {q.get('name', '?')}: kind must be one of {', '.join(PATTERN_KINDS)}")
        for k in ("scope", "enabled", "proposed_by_agent", "route"):
            q.pop(k, None)
        p = Pattern.model_validate({**q, "scope": [env_name], "enabled": False, "proposed_by_agent": by == "agent", "route": rname})
        queries.append(QueryItem(pattern=p, route=rname, evidence=str(ev)))
    if not routes and not queries:
        raise ValueError("a proposal needs at least one route or query")
    return Proposal(id=new_proposal_id(), env=env_name, session=session, task=str(a.get("task") or "")[:2000], by=by,
                    created_at=time.time(), routes=routes, queries=queries)


def check_target(route: Route, kube_context: str | None, kubectl: Callable[[list[str], str | None], Any]) -> str | None:
    """Kubernetes metadata only (`kubectl get`): the workload exists and has the container. `kubectl(args, context)` runs
    kubectl with the caller's execution mode and returns an object with ok / out / err. Returns an error text or None."""
    t = route.target
    target = t.workload if "/" in t.workload else f"pod/{t.workload}"
    path = "{.spec.containers[*].name}" if target.startswith("pod/") else "{.spec.template.spec.containers[*].name}"
    r = kubectl(["get", "-n", t.namespace, target, "-o", f"jsonpath={path}"], route.context or kube_context)
    where = f"{target} in namespace {t.namespace}"
    if not r.ok:
        err = ((r.err or "").strip().splitlines() or ["kubectl failed"])[-1][:200]
        return f"{where} not found ({err})"
    if t.container and t.container not in r.out.split():
        return f"{where} has no container {t.container} (containers: {r.out.strip() or 'none'})"
    return None


def check_static(p: Proposal, known: dict[str, Route], *, have_secret: Callable[[str], bool],
                 target_check: Callable[[Route], str | None]) -> dict[str, dict]:
    """The feasibility check before approval (SPEC 7.8): validation and Kubernetes metadata, nothing else.
    `known` maps route keys of this environment that already exist. Returns {item id: {"ok": bool, "reason"?, "needs"?}}."""
    out: dict[str, dict] = {}
    proposed = {x.route.key: x.route for x in p.routes}
    for iid, kind, it in p.items():
        try:
            if kind == "route":
                r = it.route
                if r.key in known:
                    raise ValueError(f"route {r.kind}/{r.name} is already approved in {r.env}")
                if r.transport == "exec":
                    if (r.kind, r.runner) not in RUNNERS:
                        raise ValueError(f"runner {r.runner} does not support {r.kind} yet; built in: "
                                         + ", ".join(f"{k}/{n}" for k, n in sorted(RUNNERS)))
                    err = target_check(r)
                    if err:
                        raise ValueError(err)
                    out[iid] = {"ok": True}
                else:
                    secrets_needed = [s for s in (r.secret, r.user_secret, r.password_secret) if s and not have_secret(s)]
                    out[iid] = {"ok": True, **({"needs": f"secret {', '.join(secrets_needed)} (entered at approval)"} if secrets_needed else {})}
            elif kind == "query":
                rkey = f"{p.env}/{ROUTE_KIND[it.pattern.kind]}/{it.route}"
                route = proposed.get(rkey) or known.get(rkey)
                if route is None:
                    raise ValueError(f"no route {ROUTE_KIND[it.pattern.kind]}/{it.route} in {p.env}: propose one in the same submission")
                validate_pattern(it.pattern, route.policy())
                out[iid] = {"ok": True}
            else:
                out[iid] = {"ok": True}
        except (ValueError, PatternError, ConfigError) as e:
            out[iid] = {"ok": False, "reason": str(e)}
    names = [q.pattern.name for q in p.queries]
    for iid, kind, it in p.items():
        if kind == "query" and names.count(it.pattern.name) > 1 and out[iid]["ok"]:
            out[iid] = {"ok": False, "reason": f"query name {it.pattern.name} is used twice in this proposal"}
    return out


# ---------------------------------------------------------------- activation (controller, after approval)

PG_PROBE = ("select current_setting('transaction_read_only') as read_only_txn, pg_is_in_recovery() as replica, "
            "current_user as role, (select rolsuper from pg_roles where rolname = current_user) as superuser")


def activate(route: Route, env, backends, *, secret: Callable[[str], str | None], ex: Exec) -> Route:
    """Probe a newly approved route read-only; returns it active with measured guarantees, or inactive with the error."""
    try:
        if route.kind == "files":
            from . import kubetools
            argv = kubetools.command(ex, route.exec_args(), route.context or env.kube_context)
            res = backends.files_exec(ex, argv, "probe", {}, route.roots)
            missing = [r for r, v in res.items() if not v["exists"] or not v["readable"]]
            if missing:
                raise ConfigError(f"not a readable directory in the pod: {', '.join(missing)}")
            g = {"roots": res, "writable_mount": any(v["writable"] for v in res.values())}
        elif route.kind == "postgres":
            if route.transport == "exec":
                from . import kubetools
                argv = kubetools.command(ex, route.exec_args(), route.context or env.kube_context)
                res = backends.sql_exec(ex, argv, PG_PROBE, {}, Limits(rows=1, timeout_s=10), runner=route.runner)
            else:
                res = backends.sql(_need(secret, route.secret), PG_PROBE, {}, Limits(rows=1, timeout_s=10))
            row = dict(zip(res["columns"], res["rows"][0]))
            g = {"read_only_txn": row["read_only_txn"] == "on", "replica": bool(row["replica"]), "role": row["role"],
                 "superuser": bool(row["superuser"])}
        elif route.transport == "exec":
            from . import kubetools
            argv = kubetools.command(ex, route.exec_args(), route.context or env.kube_context)
            if route.kind == "redis":
                info = backends.redis_exec(ex, argv, route.pod_vars(), ["INFO", "replication"], Limits(timeout_s=10))
                m = re.search(r"role:(\w+)", str(info))
                g = {"role": m.group(1) if m else "unknown", "replica": bool(m and m.group(1) in ("slave", "replica"))}
            else:
                h = backends.es_exec(ex, argv, route.pod_vars(), "", "_cluster/health", None, Limits(timeout_s=10))
                g = {"cluster_status": h.get("status") if isinstance(h, dict) else None}
        elif route.kind == "redis":
            info = backends.redis(_need(secret, route.secret), ["INFO", "replication"], Limits())
            m = re.search(r"role:(\w+)", info if isinstance(info, str) else str(info))
            g = {"role": m.group(1) if m else "unknown", "replica": bool(m and m.group(1) in ("slave", "replica"))}
        else:
            import base64
            hdr = {}
            if route.user_secret:
                cred = f"{_need(secret, route.user_secret)}:{_need(secret, route.password_secret)}"
                hdr["Authorization"] = "Basic " + base64.b64encode(cred.encode()).decode()
            h = backends.http_json(_need(secret, route.secret).rstrip("/") + "/_cluster/health", headers=hdr)
            g = {"cluster_status": h.get("status") if isinstance(h, dict) else None}
        return route.model_copy(update={"status": "active", "guarantees": {**g, "checked_at": time.time()}, "error": None})
    except Exception as e:   # any failure leaves the route approved but inactive, with the reason
        from .config import redact
        return route.model_copy(update={"status": "inactive", "error": redact(f"{type(e).__name__}: {e}")[:400]})


def _need(secret: Callable[[str], str | None], name: str | None) -> str:
    v = secret(name) if name else None
    if not v:
        raise ConfigError(f"secret {name} is not set")
    return v
