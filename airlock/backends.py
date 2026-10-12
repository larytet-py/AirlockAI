"""Real connectors used by the gateway. Imported lazily; tests replace this class with a fake.

Everything here runs inside the gateway/tool container, where the credentials live. Each call is bounded
(timeout, row/byte caps) and read-only by construction (read-only transactions, GET-style HTTP)."""
from __future__ import annotations

import base64
import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from . import runner
from .config import Exec
from .patterns import Limits


class BackendError(Exception):
    pass


def _jsonable(v: Any) -> Any:
    if isinstance(v, (bytes, bytearray, memoryview)):
        return bytes(v).decode(errors="replace")
    return v if isinstance(v, (int, float, str, bool, type(None), list, dict)) else str(v)


SQL_EXEC_MARK = "AIRLOCK_RESULT "
# Runs in the application container (Django shell). Only the base64 PAYLOAD varies; it is decoded as data, never as code.
SQL_EXEC_PROGRAM = '''
import base64, json
from django.db import connection, transaction
a = json.loads(base64.b64decode("PAYLOAD"))
def j(v):
    if isinstance(v, (bytes, bytearray, memoryview)):
        return bytes(v).decode(errors="replace")
    return v if isinstance(v, (int, float, str, bool, type(None), list, dict)) else str(v)
try:
    with transaction.atomic():
        c = connection.cursor()
        c.execute("set transaction read only")
        c.execute("set local statement_timeout = %d" % a["timeout_ms"])
        if a["require_replica"]:
            c.execute("select pg_is_in_recovery()")
            if not c.fetchone()[0]:
                raise RuntimeError("refusing to run: the application connection is not a read-only replica (require_replica is set)")
        c.execute(a["sql"], a["params"] or None)
        if c.description is None:
            out = {"columns": [], "rows": [], "truncated": False}
        else:
            rows = c.fetchmany(a["rows"] + 1)
            out = {"columns": [d[0] for d in c.description], "rows": [[j(x) for x in r] for r in rows[:a["rows"]]],
                   "truncated": len(rows) > a["rows"]}
        transaction.set_rollback(True)
except Exception as e:
    out = {"error": "%s: %s" % (type(e).__name__, e)}
print("AIRLOCK_RESULT " + json.dumps(out, default=str))
'''

# Runs in an application pod for a `files` route (`python -I -`, standard library only). Only the base64 PAYLOAD varies,
# decoded as data. Every path is resolved (symlinks too) and must stay inside an allowed root; files are only opened for
# reading. FIX field separators (SOH, \x01) are shown as "|".
FILES_PROGRAM = r'''
import base64, fnmatch, json, os, stat, sys
a = json.loads(base64.b64decode("PAYLOAD"))
roots = [os.path.realpath(r) for r in a["roots"]]
cap = a["caps"]
def inside(p):
    if not isinstance(p, str) or not p.startswith("/") or "\0" in p:
        raise ValueError("an absolute path inside the allowed roots is required")
    rp = os.path.realpath(p)
    for r in roots:
        if rp == r or rp.startswith(r + "/"):
            return rp
    raise ValueError("outside the allowed roots: " + ", ".join(a["roots"]))
def text(b):
    return b.decode("utf-8", "replace").replace("\x01", "|")
def entry(path, name):
    st = os.lstat(os.path.join(path, name))
    kind = "dir" if stat.S_ISDIR(st.st_mode) else "link" if stat.S_ISLNK(st.st_mode) else "file"
    return {"name": name, "type": kind, "size": st.st_size, "mtime": int(st.st_mtime)}
def lines_of(path, limit):
    with open(path, "rb") as f:
        for i, line in enumerate(f, 1):
            if i > limit:
                return
            yield i, line
try:
    op, args = a["op"], a["args"]
    if op == "probe":
        out = {r: {"exists": os.path.isdir(rr), "readable": os.access(rr, os.R_OK), "writable": os.access(rr, os.W_OK)}
               for r, rr in zip(a["roots"], roots)}
    else:
        p = inside(args.get("path", ""))
        if op == "list":
            names = sorted(os.listdir(p))
            out = {"path": p, "entries": [entry(p, n) for n in names[:cap["entries"]]], "truncated": len(names) > cap["entries"]}
        elif op == "stat":
            st = os.stat(p)
            out = {"path": p, "type": "dir" if stat.S_ISDIR(st.st_mode) else "file", "size": st.st_size, "mtime": int(st.st_mtime)}
        elif op == "find":
            pat, found, depth0 = args.get("name") or "*", [], p.count("/")
            for dp, dns, fns in os.walk(p):
                dns[:] = sorted(d for d in dns if dp.count("/") - depth0 < cap["depth"])
                for n in sorted(fns):
                    if fnmatch.fnmatch(n, pat):
                        found.append(os.path.join(dp, n))
                        if len(found) >= cap["entries"]:
                            break
                if len(found) >= cap["entries"]:
                    break
            out = {"path": p, "name": pat, "matches": found, "truncated": len(found) >= cap["entries"]}
        elif op == "read":
            with open(p, "rb") as f:
                f.seek(max(0, int(args.get("offset") or 0)))
                data = f.read(min(int(args.get("limit") or cap["bytes"]), cap["bytes"]))
            out = {"path": p, "offset": int(args.get("offset") or 0), "text": text(data), "bytes": len(data)}
        elif op == "head":
            n = min(int(args.get("lines") or 50), cap["lines"])
            got = [text(l).rstrip("\n") for _, l in lines_of(p, n)]
            out = {"path": p, "lines": got}
        elif op == "tail":
            n = min(int(args.get("lines") or 50), cap["lines"])
            with open(p, "rb") as f:
                f.seek(0, 2)
                end = f.tell()
                f.seek(max(0, end - cap["bytes"]))
                got = f.read().splitlines()[-n:]
            out = {"path": p, "lines": [text(l) for l in got]}
        elif op == "grep":
            needle = str(args.get("text") or "")
            if not needle:
                raise ValueError("text to search for is required")
            nb, hits, scanned = needle.encode(), [], 0
            def walk(top):   # files under top, sorted, depth- and count-capped (no full walk of a large tree)
                depth0, n = top.count("/"), 0
                for dp, dns, fns in os.walk(top):
                    dns[:] = sorted(d for d in dns if dp.count("/") - depth0 < cap["depth"])
                    for fn in sorted(fns):
                        if fnmatch.fnmatch(fn, args.get("name") or "*"):
                            yield os.path.join(dp, fn)
                            n += 1
                            if n >= cap["entries"]:
                                return
            for fp in ([p] if os.path.isfile(p) else walk(p)):
                fp = inside(fp)
                with open(fp, "rb") as f:
                    for i, line in enumerate(f, 1):
                        scanned += len(line)
                        if nb in line:
                            hits.append({"path": fp, "line": i, "text": text(line).rstrip("\n")[:cap["line_chars"]]})
                            if len(hits) >= cap["matches"]:
                                break
                        if scanned > cap["scan"]:
                            break
                if len(hits) >= cap["matches"] or scanned > cap["scan"]:
                    break
            out = {"path": p, "text": needle, "matches": hits, "truncated": len(hits) >= cap["matches"] or scanned > cap["scan"]}
        else:
            raise ValueError("unknown operation")
except Exception as e:
    out = {"error": "%s: %s" % (type(e).__name__, e)}
sys.stdout.write("\nAIRLOCK_RESULT " + json.dumps(out) + "\n")
'''
# The airflow runner: the same read-only query through Airflow's own SQLAlchemy engine (its configured metadata database).
AIRFLOW_SQL_PROGRAM = '''
import base64, json
a = json.loads(base64.b64decode("PAYLOAD"))
def j(v):
    if isinstance(v, (bytes, bytearray, memoryview)):
        return bytes(v).decode(errors="replace")
    return v if isinstance(v, (int, float, str, bool, type(None), list, dict)) else str(v)
try:
    from airflow import settings
    if getattr(settings, "engine", None) is None:
        settings.configure_orm()
    conn = settings.engine.raw_connection()
    try:
        c = conn.cursor()
        c.execute("set transaction read only")
        c.execute("set local statement_timeout = %d" % a["timeout_ms"])
        if a["require_replica"]:
            c.execute("select pg_is_in_recovery()")
            if not c.fetchone()[0]:
                raise RuntimeError("refusing to run: Airflow's connection is not a read-only replica (require_replica is set)")
        c.execute(a["sql"], a["params"] or None)
        if c.description is None:
            out = {"columns": [], "rows": [], "truncated": False}
        else:
            rows = c.fetchmany(a["rows"] + 1)
            out = {"columns": [d[0] for d in c.description], "rows": [[j(x) for x in r] for r in rows[:a["rows"]]],
                   "truncated": len(rows) > a["rows"]}
    finally:
        conn.rollback()
        conn.close()
except Exception as e:
    out = {"error": "%s: %s" % (type(e).__name__, e)}
print("AIRLOCK_RESULT " + json.dumps(out, default=str))
'''

# Redis and Elasticsearch through a pod's own environment (`python -I -`, standard library only). The URL and credentials
# are read from the pod's environment variables named in the payload; their values never leave the pod and are masked in
# any error text. Redis: one command from the read-only allowlist, spoken in RESP over a socket (TLS for rediss://).
# Elasticsearch: one HTTP request to a read-only endpoint.
POD_STORE_PROGRAM = r'''
import base64, json, os, socket, ssl, sys, urllib.parse, urllib.request, urllib.error
a = json.loads(base64.b64decode("PAYLOAD"))
vals = {k: os.environ.get(v) for k, v in a["vars"].items()}
def mask(t):
    for v in vals.values():
        if v and len(v) > 3:
            t = t.replace(v, "***")
            q = urllib.parse.quote(v, safe="")
            t = t.replace(q, "***") if len(q) > 3 else t
    return t
def first_url(default_scheme, default_port):
    raw = vals.get("url")
    if not raw:
        raise ValueError("the pod has no environment variable " + a["vars"]["url"])
    u = raw.split(",")[0].strip()
    if "://" not in u:
        u = default_scheme + "://" + u
    p = urllib.parse.urlsplit(u)
    return p, p.port or default_port
def redis_cmd(argv):
    p, port = first_url("redis", 6379)
    s = socket.create_connection((p.hostname, port), timeout=a["timeout"])
    if p.scheme == "rediss":
        s = ssl.create_default_context().wrap_socket(s, server_hostname=p.hostname)
    s.settimeout(a["timeout"])
    f = s.makefile("rb")
    def send(args):
        out = b"*%d\r\n" % len(args)
        for x in args:
            x = str(x).encode()
            out += b"$%d\r\n%s\r\n" % (len(x), x)
        s.sendall(out)
        return read()
    def read():
        line = f.readline()
        if not line:
            raise ConnectionError("connection closed")
        t, rest = line[:1], line[1:].rstrip(b"\r\n")
        if t == b"+":
            return rest.decode(errors="replace")
        if t == b"-":
            raise RuntimeError(rest.decode(errors="replace"))
        if t == b":":
            return int(rest)
        if t == b"$":
            n = int(rest)
            if n < 0:
                return None
            data = f.read(n + 2)[:-2]
            return data.decode(errors="replace")
        if t == b"*":
            n = int(rest)
            return None if n < 0 else [read() for _ in range(n)]
        raise RuntimeError("unexpected reply from redis")
    user, pw = urllib.parse.unquote(p.username or ""), urllib.parse.unquote(p.password or "")
    if pw:
        send(["AUTH", user, pw] if user else ["AUTH", pw])
    db = (p.path or "/").strip("/")
    if db:
        send(["SELECT", db])
    return send(argv)
def es(path, body):
    p, port = first_url("http", 9200)
    base = "%s://%s:%d" % (p.scheme, p.hostname, port)
    user, pw = vals.get("user") or urllib.parse.unquote(p.username or ""), vals.get("password") or urllib.parse.unquote(p.password or "")
    hdr = {"Content-Type": "application/json"}
    if user:
        hdr["Authorization"] = "Basic " + base64.b64encode(("%s:%s" % (user, pw)).encode()).decode()
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(base + path, data=data, method="POST" if data is not None else "GET", headers=hdr)
    try:
        with urllib.request.urlopen(req, timeout=a["timeout"]) as r:
            raw = r.read(a["max_bytes"] + 1)
    except urllib.error.HTTPError as e:
        raise RuntimeError("HTTP %d: %s" % (e.code, e.read(300).decode(errors="replace")))
    text = raw[:a["max_bytes"]].decode(errors="replace")
    try:
        return json.loads(text)
    except ValueError:
        return {"text": text, "truncated": len(raw) > a["max_bytes"]}
try:
    if a["store"] == "redis":
        if str(a["argv"][0]).upper() not in a["allowed"]:
            raise ValueError("command not in the read-only allowlist")
        res = redis_cmd(a["argv"])
        if isinstance(res, list) and len(res) > a["scan_count"]:
            res = {"items": res[:a["scan_count"]], "truncated": True}
        out = {"result": res}
    else:
        if a["method_body"] is not None and not a["path"].rsplit("/", 1)[-1] in ("_search", "_count", "_field_caps"):
            raise ValueError("endpoint not allowed")
        out = {"result": es(a["path"], a["method_body"])}
except Exception as e:
    out = {"error": mask("%s: %s" % (type(e).__name__, e))}
sys.stdout.write("\nAIRLOCK_RESULT " + json.dumps(out, default=str) + "\n")
'''

FILES_CAPS = {"bytes": 64_000, "lines": 2000, "entries": 1000, "depth": 6, "matches": 200, "line_chars": 2000, "scan": 200_000_000}


class Backends:
    def sql(self, dsn: str, sql: str, params: dict, limits: Limits, *, require_replica: bool = False) -> dict:
        """Read-only by construction: a READ ONLY transaction, a statement timeout, and optionally a refusal to run unless the
        server is a standby (pg_is_in_recovery), which cannot write at all. Session settings are sent as SQL inside the
        transaction, not as startup options, because PgBouncer poolers reject unknown startup parameters."""
        import psycopg
        with psycopg.connect(dsn, connect_timeout=10, autocommit=False) as conn:
            conn.read_only = True
            with conn.cursor() as cur:
                cur.execute(f"set local statement_timeout = {int(limits.timeout_s) * 1000}")
                if require_replica:
                    cur.execute("select pg_is_in_recovery()")
                    if not cur.fetchone()[0]:
                        raise BackendError("refusing to run: this connection is not a read-only replica (require_replica is set); "
                                           "point PG_DSN at the read-only pooler")
                cur.execute(sql, params)  # driver-side binding: never string concatenation
                if cur.description is None:
                    return {"columns": [], "rows": [], "truncated": False}
                cols = [d.name for d in cur.description]
                rows = cur.fetchmany(limits.rows + 1)
            conn.rollback()
        return {"columns": cols, "rows": [[_jsonable(c) for c in r] for r in rows[:limits.rows]], "truncated": len(rows) > limits.rows}

    def sql_exec(self, ex: Exec, argv: list[str], sql: str, params: dict, limits: Limits, *, require_replica: bool = False,
                 runner: str | None = "django") -> dict:
        """The same read-only query, run by the application's own database connection inside its pod: `argv` is
        `kubectl exec -i ... -- python manage.py shell`, and the program below arrives on stdin. The SQL and values travel
        base64-encoded as data and are bound by the driver; the transaction is READ ONLY and always rolled back."""
        payload = {"sql": sql, "params": params, "rows": limits.rows, "require_replica": require_replica, "timeout_ms": int(limits.timeout_s) * 1000}
        program = AIRFLOW_SQL_PROGRAM if runner == "airflow" else SQL_EXEC_PROGRAM
        return self._program(ex, argv, program, payload, timeout=limits.timeout_s + 45)

    def redis_exec(self, ex: Exec, argv: list[str], pod_vars: dict[str, str], command: list[str], limits: Limits) -> Any:
        """One read-only Redis command from inside a pod, with the URL from the pod's own environment (`pod_vars` are names)."""
        from .patterns import REDIS_READ
        payload = {"store": "redis", "vars": pod_vars, "argv": command, "allowed": sorted(REDIS_READ | {"INFO"}),
                   "timeout": limits.timeout_s, "scan_count": limits.scan_count}
        return self._program(ex, argv, POD_STORE_PROGRAM, payload, timeout=limits.timeout_s + 45)["result"]

    def es_exec(self, ex: Exec, argv: list[str], pod_vars: dict[str, str], index: str, endpoint: str, body: Any, limits: Limits) -> Any:
        """One read-only Elasticsearch request from inside a pod, with the URL and credentials from the pod's environment."""
        path = f"/{urllib.parse.quote(index, safe=',*-_.')}/{endpoint}" if index and not endpoint.startswith("_cat/") else f"/{endpoint}"
        get = endpoint.startswith("_cat/") or endpoint in ("_mapping", "_cluster/health")
        payload = {"store": "elasticsearch", "vars": pod_vars, "path": path, "method_body": None if get else (body or {}),
                   "timeout": limits.timeout_s, "max_bytes": limits.max_bytes}
        return self._program(ex, argv, POD_STORE_PROGRAM, payload, timeout=limits.timeout_s + 45)["result"]

    def files_exec(self, ex: Exec, argv: list[str], op: str, args: dict, roots: list[str], *, timeout: float = 60) -> dict:
        """A read-only file operation in an application pod (`files` route): list, stat, find, read, head, tail, grep."""
        return self._program(ex, argv, FILES_PROGRAM, {"op": op, "args": args, "roots": roots, "caps": FILES_CAPS}, timeout=timeout)

    def _program(self, ex: Exec, argv: list[str], program: str, payload: dict, *, timeout: float) -> dict:
        enc = base64.b64encode(json.dumps(payload, default=str).encode()).decode()
        r = self.run_stdin(ex, argv, program.replace("PAYLOAD", enc), timeout=timeout)
        line = next((ln for ln in reversed(r.out.splitlines()) if ln.startswith(SQL_EXEC_MARK)), None)
        if line is None:
            raise BackendError(f"no result from the application container (exit {r.rc}): {(r.err or r.out).strip()[-400:]}")
        res = json.loads(line[len(SQL_EXEC_MARK):])
        if "error" in res:
            raise BackendError(res["error"])
        return res

    def run_stdin(self, ex: Exec, argv: list[str], data: str, *, timeout: float) -> runner.Result:
        w = runner.wrap(ex, argv)
        w.stdin = (w.stdin or b"") + data.encode()   # after the sudo password, if the mode sends one
        return runner.execute(w, timeout=timeout)

    def http_json(self, url: str, *, method: str = "GET", body: Any = None, headers: dict | None = None,
                  timeout: int = 10, max_bytes: int = 1_000_000) -> Any:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method, headers={"Content-Type": "application/json", **(headers or {})})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                raw = r.read(max_bytes + 1)
        except urllib.error.HTTPError as e:
            raise BackendError(f"HTTP {e.code} from {urllib.parse.urlsplit(url).netloc}: {e.read(300).decode(errors='replace')}") from e
        except OSError as e:
            raise BackendError(f"cannot reach {urllib.parse.urlsplit(url).netloc}: {e}") from e
        text = raw[:max_bytes].decode(errors="replace")
        try:
            return json.loads(text)
        except ValueError:
            return {"text": text, "truncated": len(raw) > max_bytes}

    def es(self, url: str, auth: tuple[str, str] | None, index: str, endpoint: str, body: Any, limits: Limits) -> Any:
        headers = {}
        if auth:
            headers["Authorization"] = "Basic " + base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
        path = f"/{urllib.parse.quote(index, safe=',*-_.')}/{endpoint}" if not endpoint.startswith("_cat/") else f"/{endpoint}"
        method = "GET" if endpoint.startswith("_cat/") or endpoint == "_mapping" else "POST"
        return self.http_json(url.rstrip("/") + path, method=method, body=body if method == "POST" else None, headers=headers,
                              timeout=limits.timeout_s, max_bytes=limits.max_bytes)

    def redis(self, url: str, argv: list[str], limits: Limits) -> Any:
        import redis
        r = redis.Redis.from_url(url, socket_timeout=limits.timeout_s, socket_connect_timeout=5, decode_responses=True)
        out = r.execute_command(*argv)
        if isinstance(out, (list, tuple)) and len(out) > limits.scan_count:
            return {"items": list(out[:limits.scan_count]), "truncated": True}
        return out

    def run(self, ex: Exec, argv: list[str], *, timeout: float = 60, max_bytes: int = 256_000) -> runner.Result:
        """Execution mode applied here (SPEC 7.2): direct, ssh or ssh_sudo."""
        w = runner.wrap(ex, argv)
        return runner.execute(w, timeout=timeout, max_bytes=max_bytes)

    def run_script(self, ex: Exec, script: str, *, timeout: float) -> runner.Result:
        w = runner.wrap(ex, ["sh", "-s"])
        w.stdin = (w.stdin or b"") + script.encode()
        return runner.execute(w, timeout=timeout)
