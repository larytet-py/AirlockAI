"""Per-session kubeconfig for the gateway (Mode 2): the cluster plus a bearer token, no exec plugin.

Contexts that log in through an exec plugin (for example `kubectl oidc-login get-token`) cannot do that inside the gateway
container: no plugin, no browser, no token cache. The controller runs the plugin on the host once per session (a cached
login answers at once, otherwise the plugin opens the browser) and hands the gateway a kubeconfig holding only that token,
for only the contexts the environment uses. The token is not renewed inside the gateway; `refresh` writes a new one in place.
"""
from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

from .config import ConfigError
from .envs import Environment

KUBE_TOOLS = ("kubernetes", "kubectl_commands")
CONTAINER_DIR = "/home/airlock/.kube-session"   # mounted read-only; the file is replaced atomically on refresh


def contexts(env: Environment) -> list[str | None]:
    """Contexts the gateway runs kubectl against locally (direct mode). None is the current context."""
    out: list[str | None] = []
    for t in KUBE_TOOLS:
        if t in env.tool_names() and env.exec_for(t).mode == "direct":
            c = env.context(env.tool(t))
            if c not in out:
                out.append(c)
    via = env.sql_via()   # approved SQL run with `kubectl exec` in an application pod
    if via and env.exec_for("postgres").mode == "direct":
        c = via.context or env.kube_context
        if c not in out:
            out.append(c)
    # the environment's own context: the gateway checks proposed exec routes (`kubectl get`) and runs approved ones,
    # and either can happen in a session that started with no Kubernetes tool (SPEC 7.8)
    if env.kube_context and env.exec_for("postgres").mode == "direct" and env.kube_context not in out:
        out.append(env.kube_context)
    return out


def _kubectl_json(args: list[str], timeout: float = 20) -> dict:
    p = subprocess.run(["kubectl", *args, "-o", "json"], capture_output=True, text=True, timeout=timeout)
    if p.returncode:
        raise ConfigError(f"kubectl {' '.join(args)}: {p.stderr.strip()[-300:]}")
    return json.loads(p.stdout)


def _jwt_exp(token: str) -> float | None:
    try:
        part = token.split(".")[1]
        return float(json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))["exp"])
    except Exception:
        return None


def exec_token(ex: dict, context: str | None, timeout: float = 180) -> tuple[str, float | None]:
    """Run a kubeconfig exec plugin on the host; returns (token, expiry epoch or None)."""
    env = {**os.environ, **{v["name"]: v["value"] for v in ex.get("env") or []}}
    env["KUBERNETES_EXEC_INFO"] = json.dumps({"apiVersion": ex.get("apiVersion", "client.authentication.k8s.io/v1beta1"),
                                              "kind": "ExecCredential", "spec": {"interactive": sys.stdin.isatty()}})
    try:
        p = subprocess.run([ex["command"], *(ex.get("args") or [])], capture_output=True, text=True, timeout=timeout, env=env)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise ConfigError(f"kube context {context or '(current)'}: login plugin failed: {e}") from e
    if p.returncode:
        raise ConfigError(f"kube context {context or '(current)'}: login plugin failed: {p.stderr.strip()[-300:]}")
    status = json.loads(p.stdout).get("status") or {}
    token = status.get("token")
    if not token:
        raise ConfigError(f"kube context {context or '(current)'}: login plugin returned no token (client certificates are not supported)")
    exp = status.get("expirationTimestamp")
    return token, (datetime.fromisoformat(exp.replace("Z", "+00:00")).timestamp() if exp else _jwt_exp(token))


def build(ctxs: list[str | None]) -> tuple[dict, float | None]:
    """A self-contained kubeconfig for these contexts, exec users replaced by their token. Returns (config, earliest expiry)."""
    out = {"apiVersion": "v1", "kind": "Config", "clusters": [], "users": [], "contexts": [], "current-context": ""}
    expiry: float | None = None
    for ctx in ctxs:
        mini = _kubectl_json(["config", "view", "--minify", "--flatten", "--raw"] + (["--context", ctx] if ctx else []))
        c = mini["contexts"][0]
        user = (mini.get("users") or [{}])[0].get("user") or {}
        if "exec" in user:
            token, exp = exec_token(user["exec"], ctx)
            user = {"token": token}
            expiry = exp if expiry is None or (exp and exp < expiry) else expiry
        uname = f"airlock-{c['name']}"   # one user per context: two contexts may share a user name with different logins
        if not any(x["name"] == mini["clusters"][0]["name"] for x in out["clusters"]):
            out["clusters"].append(mini["clusters"][0])
        out["users"].append({"name": uname, "user": user})
        out["contexts"].append({"name": c["name"], "context": {**c["context"], "user": uname}})
        out["current-context"] = out["current-context"] or c["name"]
    return out, expiry


def write(d: Path, env: Environment) -> dict | None:
    """Write <session dir>/kube/config for the environment. Returns {"expires": epoch|None} or None if no kubectl is needed."""
    ctxs = contexts(env)
    if not ctxs:
        return None
    conf, expiry = build(ctxs)
    kd = d / "kube"
    kd.mkdir(mode=0o700, exist_ok=True)
    tmp = kd / ".config.tmp"
    tmp.write_text(json.dumps(conf))
    tmp.chmod(0o600)
    os.replace(tmp, kd / "config")   # the directory is mounted, so the gateway sees the new file
    return {"expires": expiry, "written": time.time()}


def docker_args(d: Path) -> list[str]:
    (d / "kube").mkdir(mode=0o700, exist_ok=True)
    return ["-v", f"{d / 'kube'}:{CONTAINER_DIR}:ro", "-e", f"KUBECONFIG={CONTAINER_DIR}/config",
            "-e", "KUBECACHEDIR=/tmp/kube-cache"]   # the discovery cache needs a writable place
