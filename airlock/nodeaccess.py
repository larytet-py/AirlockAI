"""Node access (SPEC 6.3): per-session key in authorized_keys and passwordless sudo, with cleanup.

Only the controller side uses USER_NAME / USER_PASSWORD (required: there is no key-only mode). The agent only ever receives the per-session private key.
"""
from __future__ import annotations

import os
import re
import shlex
import time
from dataclasses import dataclass

from . import runner
from .audit import Audit
from .config import ConfigError, Node, resolve

SID_RE = re.compile(r"^[a-f0-9]{6,32}$")
DEFAULT_TTL = "8h"
USER_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]*$")


def login_missing() -> bool:
    """True when USER_NAME or USER_PASSWORD is unset (nothing can log in to a node, so no probe or session can work)."""
    return not (os.environ.get("USER_NAME") and os.environ.get("USER_PASSWORD"))


def require_login() -> None:
    """Node access needs the login: refuse to start before anything is created if USER_NAME / USER_PASSWORD are unset."""
    for var in ("USER_NAME", "USER_PASSWORD"):
        try:
            resolve("${%s}" % var, "node login")
        except ConfigError as e:
            raise ConfigError(f"{e}. Enter the node login in Settings, or export USER_NAME and USER_PASSWORD") from e


def parse_ttl(s: str) -> int:
    m = re.fullmatch(r"(\d+)([smhd])", s.strip())
    if not m:
        raise ConfigError(f"bad ttl {s!r} (use e.g. 90m, 8h)")
    return int(m.group(1)) * {"s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]


def marker(sid: str, expiry: int) -> str:
    return f"airlock:{sid}:{expiry}"


def _admin_exec(node: Node):
    """How the controller logs in to prepare the node: always USER_NAME / USER_PASSWORD (password via askpass)."""
    return node.ssh_exec().model_copy(update={"auth": "password", "mode": "ssh"}), "password"


def _sudo(node: Node, method: str, argv: list[str], timeout: float = 60) -> runner.Result:
    """Run argv with sudo on the node: password on stdin when we have one, else sudo -n."""
    ex, _ = _admin_exec(node)
    pw = resolve("${USER_PASSWORD}", f"node {node.name} login") if method == "password" else None
    remote = (["sudo", "-S", "-p", ""] if pw else ["sudo", "-n"]) + argv
    base, env = runner.ssh_base(ex)
    return runner.execute(runner.Wrapped(base + ["--", shlex.join(remote)], (pw + "\n").encode() if pw else None, env),
                          timeout=timeout)


def _script(node: Node, script: str, *args: str, timeout: float = 60) -> runner.Result:
    ex, _ = _admin_exec(node)
    base, env = runner.ssh_base(ex)
    return runner.execute(runner.Wrapped(base + ["--", shlex.join(["sh", "-s", "--", *args]), ], script.encode(), env),
                          timeout=timeout)


ADD_KEY = r"""set -e
umask 077
mkdir -p ~/.ssh
touch ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
grep -v "airlock:$1:" ~/.ssh/authorized_keys > ~/.ssh/.airlock.tmp || true
cat ~/.ssh/.airlock.tmp > ~/.ssh/authorized_keys
rm -f ~/.ssh/.airlock.tmp
"""

DEL_KEY = r"""umask 077
[ -f ~/.ssh/authorized_keys ] || exit 0
grep -v "airlock:$1:" ~/.ssh/authorized_keys > ~/.ssh/.airlock.tmp
cat ~/.ssh/.airlock.tmp > ~/.ssh/authorized_keys
rm -f ~/.ssh/.airlock.tmp
"""

# Installs a validated sudoers drop-in: a broken file never lands.
INSTALL_SUDOERS = r"""set -e
f=/etc/sudoers.d/90-airlock-$1
t=$(mktemp)
printf '%s\n' "$2" > "$t"
visudo -cf "$t" >/dev/null
install -m 0440 -o root -g root "$t" "$f"
rm -f "$t"
"""

KEY_LINES = r"""grep -c "airlock:$1:" ~/.ssh/authorized_keys 2>/dev/null || true
"""

LIST_KEYS = r"""grep -o 'airlock:[a-f0-9]*:[0-9]*' ~/.ssh/authorized_keys 2>/dev/null || true
"""


@dataclass
class Access:
    node: str
    ready: bool
    detail: str
    expires: int | None = None


def enable_access(node: Node, sid: str, pubkey: str, identity: str, *, ttl: str | None = None,
                  from_ip: str | None = None, audit: Audit | None = None) -> Access:
    if not SID_RE.match(sid):
        raise ConfigError("bad session id")
    sudo_mode = "nopasswd"
    ex, method = _admin_exec(node)
    user = resolve(ex.user, "exec.user") or ""
    if not USER_RE.match(user):
        return Access(node.name, False, f"refused: unsafe user name {user!r}")
    expiry = int(time.time()) + parse_ttl(ttl or DEFAULT_TTL)
    mk = marker(sid, expiry)
    opts = f'from="{from_ip}" ' if from_ip else ""
    line = f"{opts}{pubkey.strip()} {mk}\n"

    r = _script(node, ADD_KEY + f"printf '%s' {shlex.quote(line)} >> ~/.ssh/authorized_keys\n", sid)
    if not r.ok:
        return Access(node.name, False, f"authorized_keys step failed: {r.err.strip()}")
    if sudo_mode == "nopasswd":
        rule = f"{user} ALL=(ALL) NOPASSWD:ALL"
        r = _sudo(node, method, ["sh", "-c", INSTALL_SUDOERS, "sh", sid, rule])
        if not r.ok:
            return Access(node.name, False, f"sudoers step failed: {r.err.strip()}")
    # Verify from the outside with the new key.
    v = runner.execute(runner.Wrapped(runner.ssh_base(ex.model_copy(update={"auth": "key"}), identity=identity)[0]
                                      + ["--", "sudo -n true" if sudo_mode == "nopasswd" else "true"]), timeout=30)
    if audit:
        audit.log("node-access", "enable", node=node.name, session=sid, marker=mk, sudo=sudo_mode, ok=v.ok)
    if not v.ok:
        return Access(node.name, False, f"verification with session key failed: {v.err.strip()}", expiry)
    return Access(node.name, True, "ready", expiry)


def access_state(node: Node, sid: str) -> str:
    """`key_lines=N sudoers=yes|no`. /etc/sudoers.d is root-only, so it is checked through sudo."""
    _, method = _admin_exec(node)
    r = _script(node, KEY_LINES, sid)
    if not r.ok:
        return f"unreachable: {r.err.strip()}"
    t = _sudo(node, method, ["test", "-e", f"/etc/sudoers.d/90-airlock-{sid}"])
    if t.rc not in (0, 1):
        return f"unreachable: sudo failed: {t.err.strip()}"
    return f"key_lines={r.out.strip() or 0} sudoers={'yes' if t.rc == 0 else 'no'}"


def revoke_access(node: Node, sid: str, audit: Audit | None = None) -> tuple[bool, str]:
    """Remove this session's key lines and sudoers drop-in. Returns (clean, detail)."""
    if not SID_RE.match(sid):
        raise ConfigError("bad session id")
    _, method = _admin_exec(node)
    r1 = _script(node, DEL_KEY, sid)
    r2 = _sudo(node, method, ["rm", "-f", f"/etc/sudoers.d/90-airlock-{sid}"])
    ok = r1.ok and r2.ok
    if audit:
        audit.log("node-access", "revoke", node=node.name, session=sid, ok=ok)
    return ok, "" if ok else (r1.err + r2.err).strip()


def stale_sessions(node: Node, live: set[str]) -> list[str]:
    """Sweeper: session ids with airlock markers on the node that no longer exist or have expired."""
    _, method = _admin_exec(node)
    r = _script(node, LIST_KEYS)
    if not r.ok:
        raise RuntimeError(f"{node.name}: {r.err.strip()}")
    found: dict[str, int] = {}
    for ln in r.out.split():
        parts = ln.split(":")
        if len(parts) == 3 and SID_RE.match(parts[1]):
            found[parts[1]] = int(parts[2]) if parts[2].isdigit() else 0
    ls = _sudo(node, method, ["ls", "/etc/sudoers.d"])
    if ls.ok:
        for name in ls.out.split():
            if name.startswith("90-airlock-") and SID_RE.match(name[11:]):
                found.setdefault(name[11:], 0)  # no expiry recorded in the filename: stale once the session is gone
    now = time.time()
    return sorted(s for s, exp in found.items() if s not in live or (exp and exp < now))
