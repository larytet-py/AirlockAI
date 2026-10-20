"""Live node status for the UI: reachable, 1-minute load average, disk use. One ssh call per node, run in parallel."""
from __future__ import annotations

import ipaddress
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from . import nodeaccess, runner
from .config import ConfigError, Node

# One fixed command; `; true` keeps the remote exit status 0 when /data does not exist, so rc != 0 means ssh itself failed.
CMD = ["sh", "-c", "cat /proc/loadavg; echo CORES $(nproc); df -Pk / /data 2>/dev/null; true"]
TTL = 15.0
_cache: dict[str, tuple[float, dict]] = {}
_lock = threading.Lock()


def parse(out: str) -> dict:
    load1, cores, disks, seen = None, None, [], set()
    for ln in out.splitlines():
        parts = ln.split()
        if not parts:
            continue
        if load1 is None and len(parts) == 5 and parts[3].replace("/", "", 1).isdigit() and parts[0].replace(".", "", 1).isdigit():
            load1 = float(parts[0])  # /proc/loadavg: 1m 5m 15m running/total lastpid
        elif parts[0] == "CORES" and len(parts) == 2 and parts[1].isdigit():
            cores = int(parts[1])
        elif len(parts) >= 6 and parts[1].isdigit() and parts[2].isdigit() and parts[5].startswith("/"):
            key = (parts[0], parts[1])  # same filesystem mounted twice: show it once
            if key in seen:
                continue
            seen.add(key)
            disks.append({"mount": parts[5], "used": int(parts[2]) * 1024, "size": int(parts[1]) * 1024, "pct": parts[4]})
    return {"load1": load1, "cores": cores, "disks": disks}


def resolve_ip(host: str) -> str | None:
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    try:
        return socket.gethostbyname(host)
    except OSError:
        return None


LOGIN_HINT = "login is missing: enter the node login (user name and password) in Settings, or export USER_NAME and USER_PASSWORD"


def web_up(url: str, timeout: float = 6) -> bool:
    """The web UI answers: any reply below 500 after redirects (a login page or 401/403 counts as up)."""
    try:
        with urllib.request.urlopen(urllib.request.Request(url, method="GET"), timeout=timeout) as r:
            return r.status < 500
    except urllib.error.HTTPError as e:
        return e.code < 500
    except (OSError, ValueError):
        return False


def ssh_banner_up(url: str, timeout: float = 6) -> bool:
    """An ssh server answers on the link's host and port: it sends its "SSH-" banner, so a login or password prompt follows."""
    try:
        p = urllib.parse.urlsplit(url)
        with socket.create_connection((p.hostname, p.port or 22), timeout=timeout) as s:
            s.settimeout(timeout)
            return s.recv(64).startswith(b"SSH-")
    except (OSError, ValueError, TypeError):
        return False


def probe(node: Node, timeout: float = 12) -> dict:
    res = ssh_probe(node, timeout)
    url = node.links.get("web")
    if url and url.startswith(("http://", "https://")):
        res["web_up"] = web_up(url)
    url = node.links.get("ssh")
    if url and url.startswith("ssh://"):
        res["ssh_link_up"] = ssh_banner_up(url)
    return res


def ssh_probe(node: Node, timeout: float) -> dict:
    ex0 = node.ssh_exec()
    ip = resolve_ip(ex0.host)  # shown even when the node is down
    base = {"ip": ip, "host": ex0.host, "port": ex0.port}
    if nodeaccess.login_missing():   # no point in an ssh attempt: say what is wrong instead of a bare "down"
        return {**base, "up": False, "login_missing": True, "error": LOGIN_HINT}
    try:
        ex, _ = nodeaccess._admin_exec(node)
        r = runner.run(ex, CMD, timeout=timeout)
    except ConfigError as e:
        return {**base, "up": False, "error": str(e)}
    if not r.ok:
        return {**base, "up": False, "error": (r.err.strip().splitlines() or ["ssh failed"])[-1]}
    return {**base, "up": True, **parse(r.out)}


def collect(nodes: list[Node]) -> dict[str, dict]:
    now = time.time()
    with _lock:
        fresh = {n.name: _cache[n.name][1] for n in nodes if n.name in _cache and now - _cache[n.name][0] < TTL}
    todo = [n for n in nodes if n.name not in fresh]
    if todo:
        with ThreadPoolExecutor(max_workers=min(8, len(todo))) as pool:
            for n, res in zip(todo, pool.map(probe, todo)):
                with _lock:
                    _cache[n.name] = (time.time(), res)
                fresh[n.name] = res
    return fresh
