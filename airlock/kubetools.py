"""Kubernetes read tools (SPEC 7): argv is built from validated pieces and policy is checked on that argv,
before the runner wraps it for direct / ssh / ssh_sudo (SPEC 7.2). No free flags, no exec, no secrets."""
from __future__ import annotations

import re

from .config import Exec
from . import runner

RES_RE = re.compile(r"^[a-z0-9]([a-z0-9.\-]{0,62})(/[A-Za-z0-9.\-]{1,253})?$")
NAME_RE = re.compile(r"^[a-z0-9]([a-z0-9.\-]{0,251})$")
SEL_RE = re.compile(r"^[A-Za-z0-9_./=!,() -]{1,200}$")
SINCE_RE = re.compile(r"^\d{1,4}[smh]$")
DENY_RESOURCES = {"secret", "secrets", "secrets.v1", "serviceaccounts/token", "tokenreviews", "certificatesigningrequests", "csr"}
OUTPUTS = ("wide", "name", "json", "yaml")
VERBS = ("get", "describe", "logs", "top", "events")


class KubePolicyError(Exception):
    pass


def _ns(namespace: str | None, allowed: list[str] | None, *, all_ns: bool = False) -> list[str]:
    if all_ns:
        if allowed:
            raise KubePolicyError("all_namespaces is not allowed here; this environment limits namespaces to " + ", ".join(allowed))
        return ["--all-namespaces"]
    if namespace is None:
        if allowed:
            raise KubePolicyError("namespace is required; one of " + ", ".join(allowed))
        return []
    if not NAME_RE.match(namespace):
        raise KubePolicyError("bad namespace")
    if allowed and namespace not in allowed:
        raise KubePolicyError(f"namespace {namespace} is not allowed; allowed: {', '.join(allowed)}")
    return ["-n", namespace]


def _resource(res: str) -> str:
    for r in res.split(","):
        base = r.strip().lower()
        if not RES_RE.match(base):
            raise KubePolicyError(f"bad resource {r!r}")
        if base.split("/")[0] in DENY_RESOURCES or base.split(".")[0] in DENY_RESOURCES:
            raise KubePolicyError(f"resource {r} is denied")
    return res.lower()


def build(verb: str, a: dict, namespaces: list[str] | None = None) -> list[str]:
    """kubectl arguments (without the binary) for one allowed read verb."""
    if verb not in VERBS:
        raise KubePolicyError(f"verb {verb} is not allowed; allowed: {', '.join(VERBS)}")
    allowed = [x for x in (namespaces or [])] or None
    out: list[str]
    if verb in ("get", "describe"):
        out = [verb, _resource(str(a.get("resource", "")))]
        if a.get("name"):
            if not NAME_RE.match(str(a["name"])):
                raise KubePolicyError("bad name")
            out.append(str(a["name"]))
        out += _ns(a.get("namespace"), allowed, all_ns=bool(a.get("all_namespaces")))
        if a.get("selector"):
            if not SEL_RE.match(str(a["selector"])):
                raise KubePolicyError("bad selector")
            out += ["-l", str(a["selector"])]
        if verb == "get" and a.get("output"):
            if a["output"] not in OUTPUTS:
                raise KubePolicyError(f"output must be one of {', '.join(OUTPUTS)}")
            out += ["-o", a["output"]]
        return out
    if verb == "logs":
        pod = str(a.get("pod", ""))
        if not NAME_RE.match(pod):
            raise KubePolicyError("bad pod name")
        out = ["logs", pod] + _ns(a.get("namespace"), allowed)
        if a.get("container"):
            if not NAME_RE.match(str(a["container"])):
                raise KubePolicyError("bad container name")
            out += ["-c", str(a["container"])]
        tail = int(a.get("tail", 200))
        out.append(f"--tail={max(1, min(tail, 2000))}")
        if a.get("since"):
            if not SINCE_RE.match(str(a["since"])):
                raise KubePolicyError("since looks like 30s, 10m or 2h")
            out.append(f"--since={a['since']}")
        if a.get("previous"):
            out.append("--previous")
        return out
    if verb == "top":
        kind = a.get("kind", "pods")
        if kind not in ("pods", "nodes"):
            raise KubePolicyError("kind must be pods or nodes")
        return ["top", kind] + ([] if kind == "nodes" else _ns(a.get("namespace"), allowed, all_ns=bool(a.get("all_namespaces"))))
    # events
    return ["get", "events", "--sort-by=.lastTimestamp"] + _ns(a.get("namespace"), allowed, all_ns=bool(a.get("all_namespaces")))


def command(ex: Exec, args: list[str], context: str | None) -> list[str]:
    """Policy has already passed on `args`; only now is the mode applied (--context for direct, --kubeconfig if set)."""
    return runner.kubectl_argv(ex, args, context)
