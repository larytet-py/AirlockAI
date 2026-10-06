"""Source code folders mounted into agent containers (Settings tab).

Local to this machine (`~/.airlock/settings.json`), not part of the shared config file, because the paths are personal.
Each folder appears in the agent at /src/<folder name>. Read-only by default. A read-write mount is honoured only for
sandbox (EC2) sessions; gateway (PROD) sessions always get read-only source. Mounts are fixed at session start.
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


def load() -> list[Source]:
    p = settings_path()
    raw = DEFAULTS
    if p.exists():
        try:
            raw = json.loads(p.read_text()).get("sources", [])
        except ValueError:
            raise ConfigError(f"{p} is not valid JSON")
    return [Source(r["path"], r.get("mode", "ro"), bool(r.get("enabled", True))) for r in raw]


def save(sources: list[Source]) -> None:
    p = settings_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps({"sources": [s.__dict__ for s in sources]}, indent=2))
    os.replace(tmp, p)


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


def add(path: str, mode: str = "ro") -> None:
    if mode not in ("ro", "rw"):
        raise ConfigError("mode is ro or rw")
    norm = check_path(path)
    items = load()
    if any(s.path == norm for s in items):
        raise ConfigError(f"{norm} is already listed")
    new = Source(norm, mode, True)
    if any(s.mount_name == new.mount_name for s in items):
        raise ConfigError(f"another source is already mounted as /src/{new.mount_name}")
    save(items + [new])


def update(path: str, *, mode: str | None = None, enabled: bool | None = None) -> None:
    items = load()
    for s in items:
        if s.path == path:
            if mode is not None:
                if mode not in ("ro", "rw"):
                    raise ConfigError("mode is ro or rw")
                s.mode = mode
            if enabled is not None:
                s.enabled = enabled
            save(items)
            return
    raise ConfigError(f"unknown source {path}")


def remove(path: str) -> None:
    items = load()
    if not any(s.path == path for s in items):
        raise ConfigError(f"unknown source {path}")
    save([s for s in items if s.path != path])


def mounts(sandbox: bool) -> list[dict]:
    """docker -v specs for a new session: enabled folders that exist and pass the credential check."""
    out, used = [], set()
    for s in load():
        if not s.enabled or not s.exists:
            continue
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
