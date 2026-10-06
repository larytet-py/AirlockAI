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
