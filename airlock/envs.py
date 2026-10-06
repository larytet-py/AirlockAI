"""Mode 2 environments (SPEC 7): connectivity, tool servers and policy, plus discovery of local kubectl contexts."""
from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from typing import Any, Literal

from pydantic import field_validator, model_validator

from .config import HOME, Config, ConfigError, Exec, Strict, NAME_RE

TOOLS = {  # tool server -> allowed config keys
    "postgres": {"dsn_env", "mode", "schemas", "max_rows", "require_replica"},
    "elastic": {"url_env", "mode", "indices", "user_env", "password_env"},
    "redis": {"url_env", "mode", "key_prefixes"},
    "kubernetes": {"context", "mode", "namespaces", "exec"},
    "kubectl_commands": {"commands", "context", "mode", "exec"},   # predefined kubectl commands, SPEC 7
    "remote_ops": {"hosts", "operations", "mode"},
    "airflow": {"url_env", "mode", "user_env", "password_env"},
    "disk": {"mounts", "mode", "max_bytes"},
    "django": {"mode", "url_env", "queries"},
    "slack": {"channels", "deny_dm", "token_env"},
    "jira": {"url", "projects", "user_env", "token_env"},
}


class Environment(Strict):
    @model_validator(mode="before")
    @classmethod
    def _drop_legacy_tags(cls, data):
        """Tags were removed; an old config file that still has them keeps loading."""
        return {k: v for k, v in data.items() if k != "tags"} if isinstance(data, dict) else data

    name: str
    kind: Literal["kubernetes"] = "kubernetes"
    kube_context: str | None = None
    exec: Exec | None = None
    secrets_dir: str | None = None
    tools: list[dict[str, dict[str, Any]]] = []
    approvals: dict[str, Literal["ask", "deny"]] = {"mutating": "ask"}
    labels: list[str] = []
    notes: str = ""
    local: bool = False
    isolation: Literal["container", "gvisor", "microvm"] = "container"

    @field_validator("name")
    @classmethod
    def _name(cls, v):
        if not NAME_RE.match(v):
            raise ValueError(f"environment name must match {NAME_RE.pattern}")
        return v

    @field_validator("tools")
    @classmethod
    def _tools(cls, items):
        seen = set()
        for it in items:
            if len(it) != 1:
                raise ValueError("each tools entry is one {tool: {settings}} mapping")
            (name, cfg), = it.items()
            if name not in TOOLS:
                raise ValueError(f"unknown tool {name!r}; known: {', '.join(sorted(TOOLS))}")
            bad = set(cfg or {}) - TOOLS[name]
            if bad:
                raise ValueError(f"tool {name}: unknown setting(s) {', '.join(sorted(bad))}")
            if name == "kubectl_commands":
                from . import kubecommands
                kubecommands.parse(cfg or {})   # raises ConfigError with the command name; surfaced by environments()
            if name in seen:
                raise ValueError(f"tool {name} listed twice")
            seen.add(name)
        return items

    def tool(self, name: str) -> dict[str, Any] | None:
        for it in self.tools:
            if name in it:
                return it[name] or {}
        return None

    def tool_names(self) -> list[str]:
        return [n for it in self.tools for n in it]

    def exec_for(self, tool: str | None = None) -> Exec:
        """Execution mode: the tool's own `exec`, else the environment's, else direct."""
        t = self.tool(tool) if tool else None
        if t and t.get("exec"):
            return Exec.model_validate({**(self.exec.model_dump(exclude_none=True) if self.exec else {}), **t["exec"]})
        return self.exec or Exec(mode="direct")

    def secrets_path(self) -> Path:
        return Path(os.path.expanduser(self.secrets_dir)) if self.secrets_dir else HOME / "secrets" / self.name

    def context(self, tool_cfg: dict | None = None) -> str | None:
        return (tool_cfg or {}).get("context") or self.kube_context


def environments(cfg: Config) -> list[Environment]:
    out = []
    for raw in cfg.environments:
        try:
            out.append(Environment.model_validate(raw))
        except Exception as e:
            raise ConfigError(f"environment {raw.get('name', '?')!r}: {e}") from e
    names = [e.name for e in out]
    dup = {n for n in names if names.count(n) > 1}
    if dup:
        raise ConfigError(f"duplicate environment names: {', '.join(sorted(dup))}")
    return out


def environment(cfg: Config, name: str) -> Environment:
    for e in environments(cfg):
        if e.name == name:
            return e
    raise ConfigError(f"unknown environment {name!r}; known: {', '.join(e.name for e in environments(cfg)) or 'none'}")


# --- secrets directory: `<env>/*.env` files with KEY=VALUE lines (mode 0600), mounted into the gateway only

def load_secrets(directory: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    if not directory.is_dir():
        return out
    for f in sorted(directory.glob("*.env")):
        if f.stat().st_mode & 0o077:
            raise ConfigError(f"{f} is readable by other users: run chmod 600 {f}")
        for line in f.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                out[k.strip()] = v.strip().strip("'\"")
    return out


def secret_status(env: Environment) -> dict[str, str]:
    """Which `*_env` references of the tools are present (never the values): {VAR: present|missing}."""
    have = {**load_secrets(env.secrets_path()), **os.environ}
    status: dict[str, str] = {}
    for it in env.tools:
        for tool, cfg in it.items():
            for k, v in (cfg or {}).items():
                if k.endswith("_env") and isinstance(v, str):
                    status[v] = "present" if v in have else "missing"
    return status


def write_secret(env: Environment, var: str, value: str) -> Path:
    """Masked-field entry in the UI: stored in the environment's secrets dir (0600), never in the config or SQLite."""
    if not re.fullmatch(r"[A-Z_][A-Z0-9_]*", var):
        raise ConfigError("variable names are upper case letters, digits and _")
    d = env.secrets_path()
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    f = d / "secrets.env"
    lines = [ln for ln in (f.read_text().splitlines() if f.exists() else []) if not ln.startswith(f"{var}=")]
    lines.append(f"{var}={value}")
    fd = os.open(f, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write("\n".join(lines) + "\n")
    f.chmod(0o600)
    return f


# --- local kubectl contexts (the PROD tab)

def kubectl_contexts(timeout: float = 10) -> list[str]:
    """Contexts known to the local kubectl (honours KUBECONFIG). Empty if kubectl is missing or has none."""
    try:
        p = subprocess.run(["kubectl", "config", "get-contexts", "-o", "name"], capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return []
    return [ln.strip() for ln in p.stdout.splitlines() if ln.strip()] if p.returncode == 0 else []


def context_status(context: str, timeout: float = 8) -> dict:
    """Read-only reachability probe for the clusters table: `kubectl --context X get ns`, plus node count."""
    import time
    t0 = time.time()
    try:
        p = subprocess.run(["kubectl", "--context", context, "--request-timeout", f"{int(timeout)}s", "get", "nodes", "-o", "name"],
                           capture_output=True, text=True, timeout=timeout + 4)
    except (OSError, subprocess.TimeoutExpired) as e:
        return {"up": False, "error": str(e)}
    ms = int((time.time() - t0) * 1000)
    if p.returncode:
        err = p.stderr.strip().splitlines()[-1] if p.stderr.strip() else "unreachable"
        # a cluster that refuses `get nodes` (RBAC) but answers is still up
        return {"up": "forbidden" in err.lower(), "error": err, "ms": ms}
    return {"up": True, "nodes": len([x for x in p.stdout.splitlines() if x]), "ms": ms}


# --- config write-back for the PROD tab (the file stays the source of truth, SPEC 7.3)

def _own_env(data: dict, name: str) -> dict:
    for e in data.get("environments") or []:
        if e.get("name") == name:
            return e
    raise ConfigError(f"environment {name!r} is not defined in this file (unknown, or defined in an included file)")


def env_spec(name: str, *, context: str = "", mode: str = "direct", host: str = "", user: str = "", tools: dict | None = None,
             labels: str = "") -> dict:
    from .config import parse_list
    spec: dict = {"name": name.strip()}
    if context.strip():
        spec["kube_context"] = context.strip()
    ex: dict = {"mode": mode}
    if mode != "direct":
        if host.strip():
            ex["host"] = host.strip()
        ex["user"] = user.strip() or "${USER_NAME}"
        ex["auth"] = "password" if not user.strip() or "$" in user else "key"
        if mode == "ssh_sudo" and ex["auth"] == "password":
            ex["sudo_password"] = "${USER_PASSWORD}"
    spec["exec"] = ex
    spec["tools"] = [{t: dict(c)} for t, c in (tools if tools is not None else {"kubernetes": {"mode": "read"}}).items()]
    if parse_list(labels):
        spec["labels"] = parse_list(labels)
    return spec


def add_environment(path, spec: dict):
    from .config import _guard

    def mutate(data):
        envs = data.setdefault("environments", [])
        if any(e.get("name") == spec["name"] for e in envs):
            raise ConfigError(f"environment {spec['name']!r} already exists")
        envs.append(spec)
    return _guard(path, mutate)


def remove_environments(path, names: list[str]):
    from .config import _guard
    if not names:
        raise ConfigError("select at least one environment")

    def mutate(data):
        for n in names:
            _own_env(data, n)
        data["environments"] = [e for e in data["environments"] if e.get("name") not in set(names)]
    return _guard(path, mutate)


def rename_environment(path, old: str, new: str):
    from .config import _guard
    new = new.strip()
    if not NAME_RE.match(new):
        raise ConfigError(f"environment name {new!r} must match {NAME_RE.pattern}")

    def mutate(data):
        e = _own_env(data, old)
        if new != old and any(x.get("name") == new for x in data["environments"]):
            raise ConfigError(f"environment {new!r} already exists")
        e["name"] = new
    return _guard(path, mutate)


def set_env_exec(path, name: str, mode: str, host: str | None = None):
    from .config import _guard
    if mode not in ("direct", "ssh", "ssh_sudo"):
        raise ConfigError(f"bad execution mode {mode!r}")

    def mutate(data):
        e = _own_env(data, name)
        ex = e.get("exec") or {}
        ex["mode"] = mode
        if mode != "direct":
            if host and host.strip():
                ex["host"] = host.strip()
            ex.setdefault("user", "${USER_NAME}")
            ex.setdefault("auth", "password")
            if mode == "ssh_sudo":
                ex.setdefault("sudo_password", "${USER_PASSWORD}")
        e["exec"] = ex
    return _guard(path, mutate)


def parse_tool_settings(text: str) -> dict:
    """`dsn_env=PG_DSN,schemas=public|app,max_rows=100` -> typed dict. `|` separates list items."""
    out: dict = {}
    for part in filter(None, (x.strip() for x in text.split(","))):
        if "=" not in part:
            raise ConfigError(f"bad setting {part!r}, use key=value")
        k, v = (x.strip() for x in part.split("=", 1))
        if "|" in v:
            out[k] = [x.strip() for x in v.split("|") if x.strip()]
        elif v.lower() in ("true", "false"):
            out[k] = v.lower() == "true"
        elif v.isdigit():
            out[k] = int(v)
        elif k in ("schemas", "namespaces", "indices", "key_prefixes", "mounts", "channels", "projects", "operations", "queries", "hosts"):
            out[k] = [v]
        else:
            out[k] = v
    return out


def set_env_tools(path, name: str, tools: dict[str, dict]):
    from .config import _guard

    def mutate(data):
        _own_env(data, name)["tools"] = [{t: dict(c)} for t, c in tools.items()]
    return _guard(path, mutate)


def edit_env_meta(path, names: list[str], *, add_labels=(), remove_labels=(), replace_labels: list[str] | None = None):
    from .config import _guard
    if not names:
        raise ConfigError("select at least one environment")

    def mutate(data):
        for name in names:
            e = _own_env(data, name)
            labels = list(replace_labels) if replace_labels is not None else list(e.get("labels") or [])
            labels += [x for x in add_labels if x not in labels]
            labels = [x for x in labels if x not in set(remove_labels)]
            if labels:
                e["labels"] = labels
            else:
                e.pop("labels", None)
    return _guard(path, mutate)


def sanitise_name(context: str) -> str:
    n = re.sub(r"[^A-Za-z0-9_.-]+", "-", context).strip("-.")[:63] or "env"
    return n if NAME_RE.match(n) else "env-" + n


def check_cluster(env: Environment, timeout: float = 20) -> str | None:
    """SPEC 7 step 1: `kubectl --context X get ns`, or over ssh / ssh+sudo as configured. Returns an error text or None."""
    from . import runner
    try:
        ex = env.exec_for("kubernetes")
        argv = runner.kubectl_argv(ex, ["get", "ns", "-o", "name"], env.context(env.tool("kubernetes")))
        r = runner.execute(runner.wrap(ex, argv), timeout=timeout)
    except ConfigError as e:
        return str(e)
    except ValueError as e:
        return str(e)
    return None if r.ok else (r.err.strip().splitlines() or ["kubectl failed"])[-1][:300]


def env_links(env: Environment, templates: dict[str, str]) -> dict[str, str]:
    """Link templates whose placeholders are only {name} and {context} (the rest belong to node rows)."""
    from urllib.parse import quote
    from .config import template_fields
    vals = {"name": quote(env.name, safe="._-"), "context": quote(env.kube_context or "", safe="._-") if env.kube_context else None}
    out = {}
    for k, tpl in templates.items():
        fields = template_fields(tpl)
        if fields and fields <= set(vals) and all(vals[f] for f in fields):
            out[k] = tpl.format(**vals)
    return out
