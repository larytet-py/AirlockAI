"""Live node status for the UI: reachable, 1-minute load average, disk use. One ssh call per node, run in parallel."""
from __future__ import annotations

import ipaddress
import socket
import threading
import time
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


def probe(node: Node, timeout: float = 12) -> dict:
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
