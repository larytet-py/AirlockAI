"""Shared config file (SPEC 7.3): YAML or JSON, versioned, strict, never holds secrets."""
from __future__ import annotations

import glob
import json
import os
import re
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, PrivateAttr, ValidationError, model_validator

HOME = Path(os.environ.get("AIRLOCK_HOME", Path.home() / ".airlock"))
REF_RE = re.compile(r"^(\$\{[A-Z_][A-Z0-9_]*\}|secret:[\w.-]+)$")
VAR_RE = re.compile(r"\$\{([A-Z_][A-Z0-9_]*)\}")
SECRET_KEYS = re.compile(r"(^|_)(password|passwd|token|secret|api_key|dsn)$")
SECRET_VARS = ("USER_PASSWORD",)
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


class ConfigError(Exception):
    pass


class MissingSecret(ConfigError):
    pass


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Exec(Strict):
    mode: Literal["direct", "ssh", "ssh_sudo"] = "ssh"
    host: str | None = None
    port: int = 22
    user: str | None = None
    auth: Literal["password", "key"] = "key"
    sudo_password: str | None = None
    kubectl_path: str = "kubectl"
    kubeconfig: str | None = None
    host_key: str | None = None


class Kube(Strict):
    server: str
    token_cmd: str | None = None
    context: str = "airlock"


LINK_VARS = {"instance_id", "name", "host", "user", "port", "context"}  # {context}: kube context, PROD rows only
INSTANCE_RE = re.compile(r"\bi-[0-9a-f]{8,17}\b")
LINK_SCHEMES = ("http://", "https://", "ssh://")


class Node(Strict):
    @model_validator(mode="before")
    @classmethod
    def _drop_legacy_keys(cls, data):
        """`bootstrap:` and `allow_bootstrap:` were removed: node access always uses USER_NAME / USER_PASSWORD. Old files still load."""
        if isinstance(data, dict):
            tags = data.get("tags") if isinstance(data.get("tags"), dict) else {}
            data = {k: v for k, v in data.items() if k not in ("bootstrap", "allow_bootstrap", "tags")}
            if tags.get("aws_instance_id") and not data.get("instance_id"):   # tags were removed; the EC2 id/region moved to fields
                data["instance_id"] = tags["aws_instance_id"]
            if tags.get("aws_region") and not data.get("region"):
                data["region"] = tags["aws_region"]
        return data

    name: str
    host: str
    instance_id: str | None = None  # EC2 id; else the aws_instance_id tag, else found in the host or name
    port: int = 22
    region: str | None = None
    labels: list[str] = []
    notes: str = ""
    created_by: str = ""   # EC2 InitiatedBy / CreatedBy tag, filled by the AWS import
    exec: Exec = Exec()
    local: bool = False
    urls: dict[str, str] = {}
    kube: Kube | None = None

    _links: dict[str, str] = PrivateAttr(default_factory=dict)

    @property
    def links(self) -> dict[str, str]:
        """Computed from defaults.links templates plus this node's explicit `urls` (never written back to the file)."""
        return self._links

    def resolved_instance_id(self) -> str | None:
        if self.instance_id:
            return self.instance_id
        for text in (self.host, self.name):
            m = INSTANCE_RE.search(text)
            if m:
                return m.group(0)
        return None

    def ssh_exec(self) -> Exec:
        """Exec settings with the node's own address filled in."""
        return self.exec.model_copy(update={"host": self.exec.host or self.host,
                                            "port": self.exec.port if self.exec.host else self.port})



class Config(Strict):
    version: Literal[1] = 1
    include: list[str] = []
    defaults: dict[str, Any] = {}
    nodes: list[Node] = []
    operations: list[dict[str, Any]] = []
    environments: list[dict[str, Any]] = []
    query_patterns: list[dict[str, Any]] = []
    integrations: dict[str, Any] = {}

    def node(self, name: str) -> Node:
        for n in self.nodes:
            if n.name == name:
                return n
        raise ConfigError(f"unknown node {name!r}; known: {', '.join(n.name for n in self.nodes) or 'none'}")


def template_fields(tpl: str) -> set[str]:
    import string
    return {f for _, f, _, _ in string.Formatter().parse(tpl) if f}


def expand_link(tpl: str, node: Node) -> str | None:
    """Fill {instance_id}, {name}, {host}, {user}, {port}. Returns None when a value is unknown for this node,
    so a node without an EC2 id simply gets no link that needs one."""
    from urllib.parse import quote
    user = node.exec.user
    if user and "$" in user:
        user = resolve_env_user(user)
    vals = {"instance_id": node.resolved_instance_id(), "name": quote(node.name, safe="._-"), "host": node.host,
            "user": quote(user, safe="._-@") if user else None, "port": str(node.port), "context": None}
    fields = template_fields(tpl)
    if any(vals[f] is None for f in fields):
        return None
    return tpl.format(**vals)


def resolve_env_user(user: str) -> str | None:
    try:
        return resolve(user, "exec.user")
    except MissingSecret:
        return None


def compute_links(node: Node, templates: dict[str, str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for key, tpl in {**templates, **node.urls}.items():  # explicit node urls override a template of the same name
        url = expand_link(tpl, node)
        if url and url.startswith(LINK_SCHEMES):
            out[key] = url
    return out


def check_link_templates(templates) -> dict[str, str]:
    if not isinstance(templates, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in templates.items()):
        raise ConfigError("defaults.links must map a link name to a URL template")
    for k, v in templates.items():
        bad = template_fields(v) - LINK_VARS
        if bad:
            raise ConfigError(f"defaults.links.{k}: unknown placeholder(s) {', '.join('{' + b + '}' for b in sorted(bad))}; "
                              f"allowed: {', '.join('{' + x + '}' for x in sorted(LINK_VARS))}")
        if not v.startswith(LINK_SCHEMES):
            raise ConfigError(f"defaults.links.{k}: must start with http://, https:// or ssh://")
    return templates


def default_path() -> Path:
    return Path(os.environ.get("AIRLOCK_CONFIG") or HOME / "airlock.yaml")


def _read(path: Path) -> dict[str, Any]:
    text = path.read_text()
    data = json.loads(text) if path.suffix == ".json" else yaml.safe_load(text)
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ConfigError(f"{path}: top level must be a mapping")
    return data


def find_literal_secrets(obj: Any, where: str = "") -> list[str]:
    """Fields known to hold secrets must be references, never literal values."""
    bad: list[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            here = f"{where}.{k}" if where else str(k)
            if SECRET_KEYS.search(str(k)) and isinstance(v, str) and not REF_RE.match(v):
                bad.append(here)
            bad += find_literal_secrets(v, here)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            bad += find_literal_secrets(v, f"{where}[{i}]")
    return bad


def referenced_vars(obj: Any) -> set[str]:
    return set(VAR_RE.findall(json.dumps(obj)))


def load_config(path: str | Path | None = None) -> Config:
    path = Path(path) if path else default_path()
    if not path.exists():
        raise ConfigError(f"config file not found: {path}")
    raw = _read(path)
    for pattern in raw.get("include", []):
        for inc in sorted(glob.glob(str(path.parent / pattern))):
            extra = _read(Path(inc))
            for key in ("nodes", "operations", "environments", "query_patterns"):
                if key in extra:
                    raw.setdefault(key, []).extend(extra.pop(key))
            if extra:
                raise ConfigError(f"{inc}: only nodes/operations/environments/query_patterns may be included")
    secrets = find_literal_secrets(raw)
    if secrets:
        raise ConfigError("literal value in secret field (use ${VAR} or secret:<name>): " + ", ".join(secrets))
    dex = (raw.get("defaults") or {}).get("exec", {})
    for n in raw.get("nodes", []):
        n["exec"] = {**dex, **(n.get("exec") or {})}
    try:
        cfg = Config.model_validate(raw)
    except ValidationError as e:
        raise ConfigError(f"{path}: {e}") from e
    names = [n.name for n in cfg.nodes]
    for n in cfg.nodes:
        if not NAME_RE.match(n.name):
            raise ConfigError(f"node name {n.name!r} must match {NAME_RE.pattern}")
    templates = check_link_templates((cfg.defaults or {}).get("links", {}))
    for n in cfg.nodes:
        for k, v in n.urls.items():
            bad = template_fields(v) - LINK_VARS
            if bad:
                raise ConfigError(f"node {n.name} urls.{k}: unknown placeholder(s) {', '.join(sorted(bad))}")
        n._links = compute_links(n, templates)
    dup = {x for x in names if names.count(x) > 1}
    if dup:
        raise ConfigError(f"duplicate node names: {', '.join(sorted(dup))}")
    from . import envs, patterns  # unknown keys are errors in environments and query patterns too (SPEC 7.3)
    envs.environments(cfg)
    for raw_p in cfg.query_patterns:
        try:
            patterns.Pattern.model_validate(raw_p)
        except ValidationError as e:
            raise ConfigError(f"query pattern {raw_p.get('name', '?')!r}: {e}") from e
    return cfg


def missing_vars(cfg: Config) -> list[str]:
    return sorted(v for v in referenced_vars(cfg.model_dump()) if v not in os.environ)


def resolve(value: str | None, where: str = "") -> str | None:
    """Expand a ${VAR} or secret:<name> reference. Raises MissingSecret naming `where`."""
    if value is None:
        return None
    if value.startswith("secret:"):
        f = HOME / "secrets" / value[7:]
        if not f.exists():
            raise MissingSecret(f"{where}: secret {value[7:]!r} not found at {f}")
        return f.read_text().strip()

    def sub(m: re.Match[str]) -> str:
        v = os.environ.get(m.group(1))
        if v is None:
            raise MissingSecret(f"{where}: environment variable {m.group(1)} is not set")
        return v

    return VAR_RE.sub(sub, value)


TOKEN_FILE = HOME / "secrets" / "claude_oauth_token"


def claude_oauth_token() -> str | None:
    """Long-lived subscription token from `claude setup-token`: $CLAUDE_CODE_OAUTH_TOKEN, else ~/.airlock/secrets/claude_oauth_token.

    The file must not be readable by others (like an ssh key); a loose file is an error, not silently ignored."""
    t = os.environ.get("CLAUDE_CODE_OAUTH_TOKEN")
    f = HOME / "secrets" / "claude_oauth_token"
    if not t and f.exists():
        if f.stat().st_mode & 0o077:
            raise ConfigError(f"{f} is readable by other users: run chmod 600 {f}")
        t = f.read_text()
    t = (t or "").strip()
    return t if t and not any(c.isspace() for c in t) else None


def save_claude_oauth_token(token: str) -> Path:
    token = token.strip()
    if len(token) < 20 or any(c.isspace() for c in token):
        raise ConfigError("that does not look like a token (expected one long string from `claude setup-token`)")
    f = HOME / "secrets" / "claude_oauth_token"
    f.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(f, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(token + "\n")
    f.chmod(0o600)
    return f


def remove_claude_oauth_token() -> bool:
    f = HOME / "secrets" / "claude_oauth_token"
    if f.exists():
        f.unlink()
        return True
    return False


def claude_token_status() -> tuple[str, str]:
    """(state, detail) for the UI: state is `env`, `file`, `none` or `error`. Never returns the token."""
    if os.environ.get("CLAUDE_CODE_OAUTH_TOKEN", "").strip():
        return "env", "from the CLAUDE_CODE_OAUTH_TOKEN variable of this server"
    try:
        return ("file", "saved in ~/.airlock/secrets") if claude_oauth_token() else ("none", "")
    except ConfigError as e:
        return "error", str(e)


LOGIN_USER_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]*$")
_LOGIN_FROM_UI: set[str] = set()   # env vars this process set from the Settings tab (so removing it can unset them)


def save_node_login(user: str, password: str) -> None:
    """Keep the login used to inject the session key and the passwordless sudoers file on the nodes in memory only.

    It is held as USER_NAME / USER_PASSWORD in this process, which is what node access, ssh/ssh_sudo exec, AWS import,
    gateway sessions and log redaction already read. Nothing is written to disk; a restart forgets it."""
    user = user.strip()
    if not LOGIN_USER_RE.match(user):
        raise ConfigError("user name: letters, digits, . _ - only (it is written into the sudoers rule)")
    if not password or "\n" in password or "\r" in password:
        raise ConfigError("password is empty or contains a line break")
    if {"USER_NAME", "USER_PASSWORD"} & (set(os.environ) - _LOGIN_FROM_UI):
        raise ConfigError("USER_NAME / USER_PASSWORD are set in the environment of this server and take precedence: unset them to use this form")
    os.environ["USER_NAME"], os.environ["USER_PASSWORD"] = user, password
    _LOGIN_FROM_UI.update(("USER_NAME", "USER_PASSWORD"))


def remove_node_login() -> bool:
    had = bool(_LOGIN_FROM_UI)
    for var in _LOGIN_FROM_UI:
        os.environ.pop(var, None)
    _LOGIN_FROM_UI.clear()
    return had


def node_login_status() -> tuple[str, str]:
    """(state, detail) for the UI: `env` (from the server's environment), `memory` (entered in Settings) or `none`.
    detail is the user name, never the password."""
    if not (os.environ.get("USER_NAME") and os.environ.get("USER_PASSWORD")):
        return "none", ""
    return ("memory" if _LOGIN_FROM_UI else "env"), os.environ["USER_NAME"]


def check_claude_token(token: str, timeout: float = 8.0) -> str:
    """Ask the API whether the token is accepted: `valid`, `invalid` (HTTP 401) or `unknown` (offline, proxy, anything else).

    GET /v1/models costs no inference. The token only goes in a request header, never in a URL, argv or message."""
    import urllib.error
    import urllib.request
    req = urllib.request.Request("https://api.anthropic.com/v1/models?limit=1", headers={
        "Authorization": f"Bearer {token}", "anthropic-beta": "oauth-2025-04-20", "anthropic-version": "2023-06-01"})
    try:
        with urllib.request.urlopen(req, timeout=timeout):
            return "valid"
    except urllib.error.HTTPError as e:
        return "invalid" if e.code == 401 else "unknown"
    except Exception:
        return "unknown"


EXTRA_SECRETS: set[str] = set()  # values registered at runtime (the gateway adds every value from its secrets dir)


def register_secret(value: str) -> None:
    if value and len(value) >= 4:
        EXTRA_SECRETS.add(value)


def secret_values() -> list[str]:
    vals = [os.environ[v] for v in SECRET_VARS if os.environ.get(v)] + sorted(EXTRA_SECRETS, key=len, reverse=True)
    try:
        t = claude_oauth_token()
    except ConfigError:
        t = None
    return vals + ([t] if t else [])


def redact(text: str) -> str:
    for s in secret_values():
        text = text.replace(s, "***")
    return text


def export_config(cfg: Config) -> str:
    """Config export: drops local nodes and refuses to emit secret values."""
    data = cfg.model_dump(exclude_none=True)
    data["nodes"] = [n for n in data["nodes"] if not n.get("local")]
    out = yaml.safe_dump(data, sort_keys=False)
    leaked = [v for v in secret_values() if v in out]
    if leaked:
        raise ConfigError("export refused: output contains the value of a secret variable")
    return out


# --- write-back: UI and CLI edits go to the config file, which stays the source of truth (SPEC 7.3) ---

def _round_trip():
    from ruamel.yaml import YAML
    y = YAML()
    y.preserve_quotes = True
    y.indent(mapping=2, sequence=4, offset=2)
    y.width = 4096
    return y


def _edit(path: str | Path | None, mutate) -> Config:
    """Apply `mutate` to the raw file, validate the result with the real loader, then replace atomically.
    Comments and layout of the YAML file are preserved. A change that fails validation is never written."""
    import io
    path = Path(path) if path else default_path()
    if not path.exists():
        raise ConfigError(f"config file not found: {path}")
    if path.suffix == ".json":
        data = json.loads(path.read_text())
        mutate(data)
        out = json.dumps(data, indent=2) + "\n"
    else:
        y = _round_trip()
        data = y.load(path.read_text()) or {}
        mutate(data)
        buf = io.StringIO()
        y.dump(data, buf)
        out = buf.getvalue()
    tmp = path.with_name(f"{path.stem}.airlock-tmp{path.suffix}")
    tmp.write_text(out)
    try:
        cfg = load_config(tmp)  # raises ConfigError on a bad change; _guard removes the temp file
    except yaml.YAMLError as ex:
        raise ConfigError(f"that change would produce an invalid YAML file, nothing was written: {ex}") from ex
    os.replace(tmp, path)
    return cfg


def _empty_list(data, key: str) -> None:
    """Set a round-tripped YAML list to `[]`. Emptying a list that has comments before its first item makes ruamel
    emit an invalid file (the comment lines swallow the next key), so the comments move above the key instead."""
    from ruamel.yaml.comments import CommentedSeq
    old = data[key]
    lines = [t.value.rstrip("\n").lstrip("# ").strip() for t in ((old.ca.comment or [None, []])[1] or [])]
    empty = CommentedSeq()
    empty.fa.set_flow_style()
    data[key] = empty
    data.ca.items.pop(key, None)
    if lines:
        data.yaml_set_comment_before_after_key(key, before="\n".join(lines))


def _own_node(data: dict, name: str) -> dict:
    for n in data.get("nodes") or []:
        if n.get("name") == name:
            return n
    raise ConfigError(f"node {name!r} is not defined in this file (unknown, or defined in an included file)")


def add_node(path, spec: dict) -> Config:
    def mutate(data):
        nodes = data.setdefault("nodes", [])
        if any(n.get("name") == spec["name"] for n in nodes):
            raise ConfigError(f"node {spec['name']!r} already exists")
        if hasattr(nodes, "fa") and nodes.fa.flow_style():   # an emptied `nodes: []` grows into a normal block list
            nodes.fa.set_block_style()
        nodes.append(spec)
    return _guard(path, mutate)


def remove_nodes(path, names: list[str]) -> Config:
    if not names:
        raise ConfigError("select at least one node")

    def mutate(data):
        for name in names:
            _own_node(data, name)
        keep = [n for n in data["nodes"] if n.get("name") not in set(names)]
        if keep or not hasattr(data["nodes"], "ca"):
            data["nodes"] = keep
        else:
            _empty_list(data, "nodes")
    return _guard(path, mutate)


def remove_node(path, name: str) -> Config:
    return remove_nodes(path, [name])


def rename_node(path, old: str, new: str) -> Config:
    new = new.strip()
    if not NAME_RE.match(new):
        raise ConfigError(f"node name {new!r} must match {NAME_RE.pattern}")

    def mutate(data):
        n = _own_node(data, old)
        if new != old and any(x.get("name") == new for x in data["nodes"]):
            raise ConfigError(f"node {new!r} already exists")
        n["name"] = new
    return _guard(path, mutate)


def set_exec_mode(path, name: str, mode: str) -> Config:
    if mode not in ("direct", "ssh", "ssh_sudo"):
        raise ConfigError(f"bad execution mode {mode!r}")

    def mutate(data):
        n = _own_node(data, name)
        n.setdefault("exec", {})["mode"] = mode
    return _guard(path, mutate)


def parse_kv(text: str) -> dict[str, str]:
    out = {}
    for part in filter(None, (x.strip() for x in text.split(","))):
        if "=" not in part:
            raise ConfigError(f"bad tag {part!r}, use key=value")
        k, v = part.split("=", 1)
        out[k.strip()] = v.strip()
    return out


def parse_list(text: str) -> list[str]:
    return [x.strip() for x in text.split(",") if x.strip()]


def edit_meta(path, names: list[str], *, add_labels: list[str] = (), remove_labels: list[str] = (),
              replace_labels: list[str] | None = None) -> Config:
    """Edit the labels of one or many nodes."""
    if not names:
        raise ConfigError("select at least one node")

    def mutate(data):
        for name in names:
            n = _own_node(data, name)
            if replace_labels is not None:
                n["labels"] = list(replace_labels)
            labels = list(n.get("labels") or [])
            labels += [l for l in add_labels if l not in labels]
            labels = [l for l in labels if l not in set(remove_labels)]
            if labels:
                n["labels"] = labels
            else:
                n.pop("labels", None)
    return _guard(path, mutate)


def _guard(path, mutate) -> Config:
    """_edit, but a failed validation leaves no temp file behind."""
    p = Path(path) if path else default_path()
    tmp = p.with_name(f"{p.stem}.airlock-tmp{p.suffix}")
    try:
        return _edit(path, mutate)
    except Exception:
        tmp.unlink(missing_ok=True)
        raise


def node_spec(name: str, host: str, *, port: int = 22, user: str = "", mode: str = "ssh",
) -> dict:
    """Build a node entry from simple form fields."""
    spec: dict = {"name": name.strip(), "host": host.strip()}
    if port != 22:
        spec["port"] = port
    ex: dict = {"mode": mode}
    if user.strip():
        ex["user"] = user.strip()
    spec["exec"] = ex
    return spec
