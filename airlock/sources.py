"""Source code folders mounted into agent containers (Settings tab).

Local to this machine (`~/.airlock/settings.json`), not part of the shared config file, because the paths are personal.
Each folder appears in the agent at /src/<folder name>. Read-only by default. A read-write mount is honoured only for
sandbox (EC2) sessions; gateway (PROD) sessions always get read-only source. Mounts are fixed at session start.

A node can have its own folder list (`node_sources` in the same file); a node without one uses the default list.
A sandbox session mounts the folders of all its nodes.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path

from .config import HOME, ConfigError

DEFAULTS: list[dict] = []   # no folders until added in the Settings tab
# A source folder must neither be, contain, nor sit inside any of these: they hold credentials.
SENSITIVE = [".ssh", ".aws", ".kube", ".gnupg", ".airlock", ".claude", ".config", ".docker", ".netrc", ".npmrc", ".pypirc"]
NAME_RE = re.compile(r"[^A-Za-z0-9_.-]+")


def settings_path() -> Path:
    return HOME / "settings.json"


@dataclass
class Source:
    path: str            # as written, e.g. ~/myapp
    mode: str = "ro"     # ro | rw
    enabled: bool = True

    @property
    def resolved(self) -> Path:
        return Path(os.path.expanduser(self.path)).resolve()

    @property
    def exists(self) -> bool:
        return self.resolved.is_dir()

    @property
    def mount_name(self) -> str:
        return NAME_RE.sub("-", self.resolved.name).strip("-.") or "src"


def _read() -> dict:
    p = settings_path()
    if not p.exists():
        return {"sources": DEFAULTS}
    try:
        return json.loads(p.read_text())
    except ValueError:
        raise ConfigError(f"{p} is not valid JSON")


def _items(raw: list[dict]) -> list[Source]:
    return [Source(r["path"], r.get("mode", "ro"), bool(r.get("enabled", True))) for r in raw]


def is_custom(node: str) -> bool:
    return node in (_read().get("node_sources") or {})


def load(node: str | None = None) -> list[Source]:
    """The default list, or the node's own list when it has one."""
    d = _read()
    per = d.get("node_sources") or {}
    return _items(per[node] if node and node in per else d.get("sources", []))


def save(sources: list[Source], node: str | None = None) -> None:
    d = _read()
    rows = [s.__dict__ for s in sources]
    if node:
        d.setdefault("node_sources", {})[node] = rows
    else:
        d["sources"] = rows
    _write(d)


def _write(d: dict) -> None:
    p = settings_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(d, indent=2))
    os.replace(tmp, p)


def reset_node(node: str) -> None:
    """Back to the default list."""
    d = _read()
    if (d.get("node_sources") or {}).pop(node, None) is not None:
        _write(d)


def rename_node(old: str, new: str) -> None:
    d = _read()
    per = d.get("node_sources") or {}
    if old in per and old != new:
        per[new] = per.pop(old)
        _write(d)


def check_path(path: str) -> str:
    """Normalise to `~/...` where possible and refuse folders that are, contain or sit inside credential directories."""
    path = path.strip()
    if not path:
        raise ConfigError("enter a folder path")
    p = Path(os.path.expanduser(path)).resolve()
    home = Path.home().resolve()
    if not p.is_dir():
        raise ConfigError(f"{p} is not a folder on this machine")
    if p == Path("/") or p == home or home.is_relative_to(p):
        raise ConfigError("mount a project folder, not your home directory or a parent of it")
    for name in SENSITIVE:
        s = (home / name).resolve()
        if p == s or p.is_relative_to(s) or s.is_relative_to(p):
            raise ConfigError(f"{p} overlaps ~/{name}, which holds credentials")
    return f"~/{p.relative_to(home)}" if p.is_relative_to(home) else str(p)


def add(path: str, mode: str = "ro", node: str | None = None) -> None:
    """Add a folder to the default list, or to the node's list (which starts as a copy of the default one)."""
    if mode not in ("ro", "rw"):
        raise ConfigError("mode is ro or rw")
    norm = check_path(path)
    items = load(node)
    if any(s.path == norm for s in items):
        raise ConfigError(f"{norm} is already listed")
    new = Source(norm, mode, True)
    if any(s.mount_name == new.mount_name for s in items):
        raise ConfigError(f"another source is already mounted as /src/{new.mount_name}")
    save(items + [new], node)


def update(path: str, *, mode: str | None = None, enabled: bool | None = None, node: str | None = None) -> None:
    items = load(node)
    for s in items:
        if s.path == path:
            if mode is not None:
                if mode not in ("ro", "rw"):
                    raise ConfigError("mode is ro or rw")
                s.mode = mode
            if enabled is not None:
                s.enabled = enabled
            save(items, node)
            return
    raise ConfigError(f"unknown source {path}")


def remove(path: str, node: str | None = None) -> None:
    items = load(node)
    if not any(s.path == path for s in items):
        raise ConfigError(f"unknown source {path}")
    save([s for s in items if s.path != path], node)


def mounts(sandbox: bool, nodes: list[str] | None = None) -> list[dict]:
    """docker -v specs for a new session: enabled folders that exist and pass the credential check.

    With `nodes`, the folders of all those nodes (each its own list or the default one); a folder listed by several
    nodes is mounted once, read-write if any of them says so."""
    picked: dict[Path, Source] = {}
    for lst in ([load(n) for n in nodes] if nodes else [load()]):
        for s in lst:
            if not s.enabled or not s.exists:
                continue
            cur = picked.get(s.resolved)
            if cur is None or (s.mode == "rw" and cur.mode != "rw"):
                picked[s.resolved] = s
    out, used = [], set()
    for s in picked.values():
        try:
            check_path(s.path)
        except ConfigError:
            continue  # the folder moved or the denylist grew: never mount it silently
        name, i = s.mount_name, 2
        while name in used:
            name = f"{s.mount_name}-{i}"
            i += 1
        used.add(name)
        ro = not (sandbox and s.mode == "rw")
        out.append({"host": str(s.resolved), "container": f"/src/{name}", "ro": ro, "path": s.path})
    return out


def docker_args(ms: list[dict]) -> list[str]:
    args: list[str] = []
    for m in ms:
        args += ["-v", f"{m['host']}:{m['container']}" + (":ro" if m["ro"] else "")]
    return args


def instructions(ms: list[dict]) -> str:
    if not ms:
        return ""
    lines = ["", "## Source code", "", "Source folders of this machine are mounted in the container:"]
    lines += [f"- `{m['container']}` ({'read-only' if m['ro'] else 'read-write'})" for m in ms]
    return "\n".join(lines) + "\n"
