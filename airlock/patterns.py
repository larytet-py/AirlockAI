"""Query patterns (SPEC 7.1): the only way an agent may query SQL, Elasticsearch or Redis.

A pattern is a template with typed placeholders `{{ name:type }}`. A raw query from the agent is accepted only if it is
an instance of an enabled pattern: same structure, literals only in placeholder positions, every value valid for its
type. A match yields bound values; the executor never concatenates agent text into a query.
"""
from __future__ import annotations

import fnmatch
import json
import re
import shlex
from dataclasses import dataclass
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, field_validator

PH_RE = re.compile(r"\{\{\s*(\w+)\s*:\s*([^{}]+?)\s*\}\}")
KINDS = ("sql", "elasticsearch", "redis")
NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}$")
SAFE_EMBED = re.compile(r"^[A-Za-z0-9_.:@ -]*$")  # str value allowed inside a larger literal (never quotes or backslashes)
CTRL = re.compile(r"[\x00-\x1f\x7f]")
TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:?\d{2})?)?$")
MAX_STR, MAX_LIST = 256, 100


class PatternError(Exception):
    """Raised for an invalid pattern or a query that does not match any pattern."""


class Mismatch(Exception):
    pass


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ParamSpec(Strict):
    min: float | None = None
    max: float | None = None
    default: Any = None
    regex: str | None = None
    values: list[str] | None = None
    max_length: int | None = None


class Limits(Strict):
    rows: int = 100
    timeout_s: int = 10
    max_bytes: int = 64_000
    size: int = 200      # Elasticsearch `size` cap
    scan_count: int = 1000  # Redis SCAN/range cap


class Pattern(Strict):
    name: str
    kind: Literal["sql", "elasticsearch", "redis"]
    description: str = ""
    template: Any                      # str for sql/redis; {index, body, endpoint?} for elasticsearch
    params: dict[str, ParamSpec] = {}
    scope: str | list[str] = "global"
    risk: Literal["read", "write"] = "read"
    limits: Limits = Limits()
    enabled: bool = True
    proposed_by_agent: bool = False

    @field_validator("name")
    @classmethod
    def _name(cls, v):
        if not NAME_RE.match(v):
            raise ValueError(f"pattern name must match {NAME_RE.pattern}")
        return v

    def in_scope(self, env: str) -> bool:
        return self.scope == "global" or (isinstance(self.scope, list) and env in self.scope) or self.scope == env


# ---------------------------------------------------------------- typed values

def parse_type(t: str) -> tuple[str, list[str] | None]:
    t = t.strip()
    m = re.fullmatch(r"enum\(([^)]*)\)", t)
    if m:
        vals = [x.strip() for x in m.group(1).split(",") if x.strip()]
        if not vals:
            raise PatternError("enum() needs at least one value")
        return "enum", vals
    if t in ("int", "float", "str", "ts", "list[int]", "list[str]"):
        return t, None
    raise PatternError(f"unknown placeholder type {t!r}")


def placeholders(template: Any) -> dict[str, str]:
    """name -> declared type string, from every string in the template."""
    found: dict[str, str] = {}

    def walk(x):
        if isinstance(x, str):
            for n, t in PH_RE.findall(x):
                parse_type(t)
                if n in found and found[n] != t.strip():
                    raise PatternError(f"placeholder {n} declared with two types")
                found[n] = t.strip()
        elif isinstance(x, dict):
            for k, v in x.items():
                walk(k)
                walk(v)
        elif isinstance(x, list):
            for v in x:
                walk(v)
    walk(template)
    return found


def coerce(name: str, value: Any, type_: str, spec: ParamSpec | None = None) -> Any:
    spec = spec or ParamSpec()
    kind, enum_vals = parse_type(type_)
    if kind.startswith("list["):
        if not isinstance(value, list) or not 1 <= len(value) <= MAX_LIST:
            raise Mismatch(f"{name}: expected a list of 1..{MAX_LIST} items")
        return [coerce(name, v, kind[5:-1], spec) for v in value]
    if kind == "enum":
        if str(value) not in enum_vals:
            raise Mismatch(f"{name}: must be one of {', '.join(enum_vals)}")
        return str(value)
    if kind in ("int", "float"):
        if isinstance(value, bool) or value is None or not isinstance(value, (int, float, str)):
            raise Mismatch(f"{name}: expected a number")
        if isinstance(value, str):
            if not re.fullmatch(r"-?\d+(\.\d+)?", value.strip()):
                raise Mismatch(f"{name}: expected {kind}")
            value = float(value) if "." in value else int(value)
        if kind == "int":
            if isinstance(value, float) and value != int(value):
                raise Mismatch(f"{name}: expected int")
            v = int(value)
        else:
            v = float(value)
        if (spec.min is not None and v < spec.min) or (spec.max is not None and v > spec.max):
            raise Mismatch(f"{name}: {v} outside [{spec.min}, {spec.max}]")
        return v
    # str / ts
    if isinstance(value, bool) or not isinstance(value, (str, int, float)):
        raise Mismatch(f"{name}: expected a string")
    s = str(value)
    if CTRL.search(s):
        raise Mismatch(f"{name}: control characters are not allowed")
    if len(s) > (spec.max_length or MAX_STR):
        raise Mismatch(f"{name}: longer than {spec.max_length or MAX_STR}")
    if kind == "ts" and not TS_RE.match(s):
        raise Mismatch(f"{name}: expected an ISO-8601 timestamp")
    if spec.values is not None and s not in spec.values:
        raise Mismatch(f"{name}: must be one of {', '.join(spec.values)}")
    if spec.regex and not re.fullmatch(spec.regex, s):
        raise Mismatch(f"{name}: does not match the allowed format")
    return s


def apply_defaults(p: Pattern, values: dict[str, Any]) -> dict[str, Any]:
    types = placeholders(p.template)
    unknown = set(values) - set(types)
    if unknown:
        raise Mismatch(f"unknown parameter(s): {', '.join(sorted(unknown))}")
    out = {}
    for n, t in types.items():
        spec = p.params.get(n)
        if n in values:
            raw = values[n]
        elif spec and spec.default is not None:
            raw = spec.default
        else:
            raise Mismatch(f"missing parameter {n}")
        out[n] = coerce(n, raw, t, spec)
    return out


# ---------------------------------------------------------------- shared string-with-placeholders matching

def split_literal(s: str) -> list[tuple[str, str | None]]:
    """'a{{ x:int }}b' -> [('a', None), ('x', 'int'), ('b', None)] as (text, type) pairs."""
    out: list[tuple[str, str | None]] = []
    pos = 0
    for m in PH_RE.finditer(s):
        if m.start() > pos:
            out.append((s[pos:m.start()], None))
        out.append((m.group(1), m.group(2).strip()))
        pos = m.end()
    if pos < len(s):
        out.append((s[pos:], None))
    return out


def match_string(tpl: str, raw: Any, p: Pattern, bound: dict) -> None:
    """tpl may mix fixed text and placeholders. A whole-value placeholder accepts any scalar of its type."""
    parts = split_literal(tpl)
    if len(parts) == 1 and parts[0][1] is not None:
        n, t = parts[0]
        _bind(bound, n, coerce(n, raw, t, p.params.get(n)))
        return
    if not isinstance(raw, str):
        raise Mismatch("expected a string")
    rx, names = "", []
    for text, t in parts:
        if t is None:
            rx += re.escape(text)
        else:
            kind, _ = parse_type(t)
            rx += r"(-?\d+)" if kind == "int" else r"(-?\d+(?:\.\d+)?)" if kind == "float" else r"([^\x00-\x1f]{1,%d})" % MAX_STR
            names.append((text, t))
    m = re.fullmatch(rx, raw)
    if not m:
        raise Mismatch("does not fit the pattern")
    for (n, t), g in zip(names, m.groups()):
        v = coerce(n, g, t, p.params.get(n))
        if isinstance(v, str) and not SAFE_EMBED.match(v) and not p.params.get(n, ParamSpec()).regex:
            raise Mismatch(f"{n}: only letters, digits and _.:@ - are allowed inside a larger value")
        _bind(bound, n, v)


def _bind(bound: dict, n: str, v: Any) -> None:
    if n in bound and bound[n] != v:
        raise Mismatch(f"{n} appears twice with different values")
    bound[n] = v


# ---------------------------------------------------------------- SQL

SQL_DENY_FUNCS = {"pg_sleep", "pg_sleep_for", "pg_sleep_until", "set_config", "nextval", "setval", "pg_terminate_backend",
                  "pg_cancel_backend", "pg_reload_conf", "pg_rotate_logfile", "pg_ls_dir", "pg_read_file",
                  "pg_read_binary_file", "pg_stat_file", "current_setting_unsafe", "txid_current", "pg_switch_wal",
                  "pg_create_restore_point", "pg_replication_slot_advance", "query_to_xml", "xpath", "pg_logical_emit_message"}
SQL_DENY_PREFIX = ("dblink", "lo_", "pg_advisory", "pg_file", "pg_copy", "copy_", "pg_replication_origin")
SQL_WRITE_STMT = {"InsertStmt", "UpdateStmt", "DeleteStmt", "MergeStmt", "CopyStmt", "DropStmt", "AlterTableStmt", "CreateStmt",
                  "TruncateStmt", "GrantStmt", "VariableSetStmt", "DoStmt", "CallStmt", "CreateTableAsStmt", "LockStmt",
                  "VacuumStmt", "RefreshMatViewStmt", "TransactionStmt", "ExecuteStmt", "PrepareStmt", "ListenStmt",
                  "NotifyStmt", "DeclareCursorStmt", "CreateFunctionStmt", "ClusterStmt", "ReindexStmt"}
SENTINEL = "__ph_{}__"


def _sql_template(template: str) -> tuple[str, dict[str, bool]]:
    """Replace placeholders by sentinels. Returns (sql, {name: embedded_in_quotes})."""
    types = placeholders(template)
    out, pos, embedded = [], 0, {}
    # decide per placeholder whether it sits inside a '...' literal by counting quotes before it
    for m in PH_RE.finditer(template):
        before = template[:m.start()]
        inside = before.count("'") % 2 == 1
        embedded[m.group(1)] = embedded.get(m.group(1), False) or inside
        out.append(template[pos:m.start()])
        s = SENTINEL.format(m.group(1))
        out.append(s if inside else f"'{s}'")
        pos = m.end()
    out.append(template[pos:])
    assert set(embedded) == set(types)
    return "".join(out), embedded


def _parse_sql(sql: str) -> list[dict]:
    try:
        from pglast.parser import parse_sql_json
    except ImportError as e:  # pragma: no cover
        raise PatternError("pglast is not installed") from e
    try:
        return [s["stmt"] for s in json.loads(parse_sql_json(sql))["stmts"]]
    except Exception as e:
        raise PatternError(f"SQL does not parse: {str(e).splitlines()[0]}") from e


def _walk(node, visit):
    if isinstance(node, dict):
        for k, v in node.items():
            visit(k, v)
            _walk(v, visit)
    elif isinstance(node, list):
        for v in node:
            _walk(v, visit)


def validate_sql(template: str, *, allowed_schemas: list[str] | None = None, risk: str = "read") -> None:
    sql, _ = _sql_template(template)
    stmts = _parse_sql(sql)
    if len(stmts) != 1:
        raise PatternError("exactly one SQL statement is allowed")
    stmt = stmts[0]
    kind = next(iter(stmt))
    if risk == "read":
        if kind == "ExplainStmt":
            for o in stmt[kind].get("options", []):
                if o["DefElem"]["defname"].lower() in ("analyze", "analyse"):
                    raise PatternError("EXPLAIN ANALYZE executes the statement and is not allowed")
            inner = next(iter(stmt[kind]["query"]))
            if inner != "SelectStmt":
                raise PatternError("EXPLAIN is allowed only for SELECT")
        elif kind != "SelectStmt":
            raise PatternError(f"{kind} is not allowed for a read pattern: only SELECT, EXPLAIN and WITH ... SELECT")
    bad: list[str] = []

    def visit(k, v):
        if k in SQL_WRITE_STMT:
            bad.append(f"data-modifying or session statement {k} inside the query")
        if k == "intoClause" and v:
            bad.append("SELECT INTO writes a table")
        if k == "lockingClause" and v:
            bad.append("row locking (FOR UPDATE/SHARE) is not allowed")
        if k == "FuncCall":
            fn = ".".join(n["String"]["sval"] for n in v.get("funcname", []) if "String" in n).lower()
            base = fn.rsplit(".", 1)[-1]
            if base in SQL_DENY_FUNCS or base.startswith(SQL_DENY_PREFIX):
                bad.append(f"function {fn} is denied")
        if k == "RangeVar" and allowed_schemas is not None:
            schema = v.get("schemaname") or "public"
            if schema not in allowed_schemas:
                bad.append(f"schema {schema} is not on the allowlist")
    _walk(stmt, visit)
    if bad:
        raise PatternError("; ".join(dict.fromkeys(bad)))


def _strip(node):
    """AST without source locations, for structural comparison."""
    if isinstance(node, dict):
        return {k: _strip(v) for k, v in node.items() if k not in ("location", "stmt_location", "stmt_len", "rexpr_list_start", "rexpr_list_end")}
    if isinstance(node, list):
        return [_strip(v) for v in node]
    return node


def _const_value(c: dict) -> Any:
    c = c["A_Const"]
    if c.get("isnull"):
        raise Mismatch("NULL is not accepted in a placeholder position")
    for key, conv in (("ival", lambda x: x.get("ival", 0)), ("fval", lambda x: x["fval"]), ("sval", lambda x: x["sval"]),
                      ("boolval", lambda x: x.get("boolval", False))):
        if key in c:
            return conv(c[key])
    return c.get("ival", {}).get("ival", 0)  # pglast omits ival when it is 0


def _is_const(n) -> bool:
    return isinstance(n, dict) and set(n) == {"A_Const"}


def _sentinel_of(n) -> str | None:
    if _is_const(n) and "sval" in n["A_Const"]:
        m = re.fullmatch(r"__ph_(\w+)__", n["A_Const"]["sval"]["sval"])
        return m.group(1) if m else None
    return None


def _sql_match(t, r, p: Pattern, types: dict, embedded: dict, bound: dict) -> None:
    if isinstance(t, list):
        if not isinstance(r, list):
            raise Mismatch("structure differs")
        if len(t) == 1 and (name := _sentinel_of(t[0])) and types[name].startswith("list["):
            if not all(_is_const(x) for x in r):
                raise Mismatch("list values must be literals")
            _bind(bound, name, coerce(name, [_const_value(x) for x in r], types[name], p.params.get(name)))
            return
        if len(t) != len(r):
            raise Mismatch("structure differs")
        for a, b in zip(t, r):
            _sql_match(a, b, p, types, embedded, bound)
        return
    if isinstance(t, dict):
        name = _sentinel_of(t)
        if name:
            if not _is_const(r):
                raise Mismatch(f"{name}: a literal value is required here")
            _bind(bound, name, coerce(name, _const_value(r), types[name], p.params.get(name)))
            return
        if not isinstance(r, dict) or set(t) != set(r):
            raise Mismatch("structure differs")
        for k in t:
            if k == "sval" and isinstance(t[k], str) and "__ph_" in t[k]:
                # placeholder embedded in a larger string literal, e.g. '__ph_hours__ hours'
                _match_embedded(t[k], r[k], p, types, bound)
            else:
                _sql_match(t[k], r[k], p, types, embedded, bound)
        return
    if t != r:
        raise Mismatch("differs from the pattern")


def _match_embedded(tpl: str, raw: Any, p: Pattern, types: dict, bound: dict) -> None:
    rebuilt = re.sub(r"__ph_(\w+)__", lambda m: "{{ %s:%s }}" % (m.group(1), types[m.group(1)]), tpl)
    match_string(rebuilt, raw, p, bound)


def sql_match(p: Pattern, raw: str) -> dict[str, Any]:
    sql, embedded = _sql_template(p.template)
    types = placeholders(p.template)
    (t,) = _parse_sql(sql)
    r = _parse_sql(raw)
    if len(r) != 1:
        raise Mismatch("exactly one SQL statement is allowed")
    bound: dict[str, Any] = {}
    _sql_match(_strip(t), _strip(r[0]), p, types, embedded, bound)
    return bound


def sql_bind(p: Pattern, values: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """Template -> (sql with %(name)s markers, params). Whole-literal placeholders are bound by the driver; a placeholder
    inside a quoted literal is substituted only after type validation (int/float/enum/safe string)."""
    sql, embedded = _sql_template(p.template)
    params: dict[str, Any] = {}
    # rebuild from the original text so no sentinel survives
    out, pos = [], 0
    for m in PH_RE.finditer(p.template):
        out.append(p.template[pos:m.start()].replace("%", "%%"))
        n = m.group(1)
        inside = p.template[:m.start()].count("'") % 2 == 1
        v = values[n]
        if inside:
            if isinstance(v, list) or (isinstance(v, str) and not SAFE_EMBED.match(v)):
                raise PatternError(f"{n}: unsafe value for a placeholder inside a quoted literal")
            out.append(str(v))
        elif isinstance(v, list):  # IN (...) lists: one bound parameter per element
            for i, item in enumerate(v):
                params[f"{n}_{i}"] = item
            out.append(", ".join(f"%({n}_{i})s" for i in range(len(v))))
        else:
            params[n] = v
            out.append(f"%({n})s")
        pos = m.end()
    out.append(p.template[pos:].replace("%", "%%"))
    return "".join(out), params


# ---------------------------------------------------------------- Elasticsearch

ES_ENDPOINTS = ("_search", "_count", "_mapping", "_field_caps")
ES_DENY_KEYS = {"script", "script_fields", "scripted_metric", "runtime_mappings", "stored_script", "painless", "inline"}


def es_parts(t: Any) -> tuple[str, str, Any]:
    if not isinstance(t, dict) or "index" not in t:
        raise PatternError("an Elasticsearch template needs {index, body, endpoint?}")
    extra = set(t) - {"index", "body", "endpoint"}
    if extra:
        raise PatternError(f"unknown template key(s): {', '.join(sorted(extra))}")
    return t["index"], t.get("endpoint", "_search"), t.get("body", {})


def validate_es(template: Any, *, allowed_indices: list[str] | None = None, limits: Limits = Limits()) -> None:
    index, endpoint, body = es_parts(template)
    if endpoint not in ES_ENDPOINTS and not endpoint.startswith("_cat/"):
        raise PatternError(f"endpoint {endpoint} is not allowed (use _search, _count, _mapping, _field_caps, _cat/*)")
    if not isinstance(index, str) or not re.fullmatch(r"[A-Za-z0-9_.*,{}: -]+", index):
        raise PatternError("bad index expression")
    if allowed_indices is not None and not all(any(fnmatch.fnmatch(i, a) for a in allowed_indices)
                                               for i in index.split(",") if "{{" not in i):
        raise PatternError("index is not on the allowlist")
    bad = []

    def visit(x, path=""):
        if isinstance(x, dict):
            for k, v in x.items():
                if k in ES_DENY_KEYS:
                    bad.append(f"{k} is not allowed")
                if k == "size" and isinstance(v, int) and v > limits.size:
                    bad.append(f"size {v} exceeds the cap {limits.size}")
                visit(v, path + "/" + k)
        elif isinstance(x, list):
            for v in x:
                visit(v, path)
    visit(body)
    if bad:
        raise PatternError("; ".join(bad))


def _es_match(t, r, p: Pattern, bound: dict) -> None:
    if isinstance(t, dict):
        if not isinstance(r, dict) or set(t) != set(r):
            raise Mismatch("structure differs")
        for k in t:
            _es_match(t[k], r[k], p, bound)
    elif isinstance(t, list):
        if len(t) == 1 and isinstance(t[0], str) and (m := PH_RE.fullmatch(t[0].strip())) and \
                parse_type(m.group(2))[0].startswith("list["):
            raise Mismatch("use a whole-value list placeholder instead of a list of one")
        if not isinstance(r, list) or len(t) != len(r):
            raise Mismatch("structure differs")
        for a, b in zip(t, r):
            _es_match(a, b, p, bound)
    elif isinstance(t, str) and PH_RE.search(t):
        match_string(t, r, p, bound)
    elif t != r or type(t) is not type(r):
        raise Mismatch("differs from the pattern")


def es_match(p: Pattern, raw: dict) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise Mismatch("expected {index, body, endpoint?}")
    ti, te, tb = es_parts(p.template)
    ri, re_, rb = raw.get("index"), raw.get("endpoint", "_search"), raw.get("body", {})
    bound: dict[str, Any] = {}
    match_string(ti, ri, p, bound) if PH_RE.search(ti) else None
    if not PH_RE.search(ti) and ti != ri:
        raise Mismatch("index differs from the pattern")
    if te != re_:
        raise Mismatch("endpoint differs from the pattern")
    _es_match(tb, rb, p, bound)
    return bound


def _subst(x: Any, values: dict) -> Any:
    if isinstance(x, dict):
        return {k: _subst(v, values) for k, v in x.items()}
    if isinstance(x, list):
        return [_subst(v, values) for v in x]
    if isinstance(x, str) and PH_RE.search(x):
        parts = split_literal(x)
        if len(parts) == 1:
            return values[parts[0][0]]  # whole value: typed JSON value, never re-parsed
        return "".join(t if ty is None else str(values[t]) for t, ty in parts)
    return x


def es_bind(p: Pattern, values: dict[str, Any]) -> dict:
    index, endpoint, body = es_parts(p.template)
    out_index = _subst(index, values)
    body = _subst(body, values)
    sz = body.get("size") if isinstance(body, dict) else None
    if isinstance(sz, int) and sz > p.limits.size:
        raise PatternError(f"size {sz} exceeds the cap {p.limits.size}")
    return {"index": out_index, "endpoint": endpoint, "body": body}


# ---------------------------------------------------------------- Redis

REDIS_READ = {"GET", "MGET", "HGET", "HGETALL", "HMGET", "HLEN", "HKEYS", "LRANGE", "LLEN", "LINDEX", "SMEMBERS", "SCARD",
              "SISMEMBER", "ZRANGE", "ZCARD", "ZSCORE", "ZRANGEBYSCORE", "TTL", "PTTL", "TYPE", "SCAN", "SSCAN", "HSCAN",
              "ZSCAN", "EXISTS", "STRLEN", "XLEN", "XRANGE", "XREVRANGE", "GETRANGE"}
REDIS_NEVER = {"KEYS", "FLUSHALL", "FLUSHDB", "DEL", "UNLINK", "EVAL", "EVALSHA", "FCALL", "CONFIG", "SHUTDOWN", "SCRIPT",
               "MODULE", "DEBUG", "SLAVEOF", "REPLICAOF", "MIGRATE", "RESTORE", "SAVE", "BGSAVE", "CLIENT", "ACL", "MONITOR"}


def redis_tokens(s: str) -> list[str]:
    if CTRL.search(s):
        raise PatternError("control characters (CR, LF, NUL) are not allowed in a Redis command")
    try:
        return shlex.split(s)
    except ValueError as e:
        raise PatternError(f"cannot tokenise the command: {e}") from e


def redis_template_tokens(template: str) -> list[str]:
    """Like redis_tokens, but a placeholder (which contains spaces) stays inside its token."""
    held: list[str] = []

    def hold(m):
        held.append(m.group(0))
        return f"PHTOK{len(held) - 1}PHTOK"
    toks = redis_tokens(PH_RE.sub(hold, template))
    return [re.sub(r"PHTOK(\d+)PHTOK", lambda m: held[int(m.group(1))], t) for t in toks]


def validate_redis(template: str, *, key_prefixes: list[str] | None = None, risk: str = "read") -> None:
    toks = redis_template_tokens(template)
    if not toks:
        raise PatternError("empty command")
    cmd = toks[0].upper()
    if "{{" in toks[0]:
        raise PatternError("the command name cannot be a placeholder")
    if cmd in REDIS_NEVER:
        raise PatternError(f"{cmd} is always denied")
    if risk == "read" and cmd not in REDIS_READ:
        raise PatternError(f"{cmd} is not on the read-only allowlist")
    if key_prefixes is not None and len(toks) > 1 and cmd not in ("SCAN",):
        key = toks[1]
        fixed = key.split("{{")[0]
        if not any(fixed.startswith(pref) for pref in key_prefixes):
            raise PatternError(f"key does not start with an allowed prefix ({', '.join(key_prefixes)})")


def redis_match(p: Pattern, raw: Any) -> dict[str, Any]:
    toks = raw if isinstance(raw, list) else redis_tokens(str(raw))
    if not all(isinstance(x, (str, int)) for x in toks):
        raise Mismatch("arguments must be strings")
    toks = [str(x) for x in toks]
    t = redis_template_tokens(p.template)
    if len(t) != len(toks) or not toks or t[0].upper() != toks[0].upper():
        raise Mismatch("command or argument count differs")
    bound: dict[str, Any] = {}
    for a, b in zip(t[1:], toks[1:]):
        if PH_RE.search(a):
            match_string(a, b, p, bound)
        elif a != b:
            raise Mismatch(f"fixed token {a!r} differs")
    return bound


def redis_bind(p: Pattern, values: dict[str, Any]) -> list[str]:
    """Separate arguments, never one command string."""
    out = []
    for tok in redis_template_tokens(p.template):
        parts = split_literal(tok)
        if len(parts) == 1 and parts[0][1] is not None:
            v = values[parts[0][0]]
            out += [str(x) for x in v] if isinstance(v, list) else [str(v)]
        else:
            out.append("".join(t if ty is None else str(values[t]) for t, ty in parts))
    return out


# ---------------------------------------------------------------- common entry points

@dataclass
class Policy:
    """Per-environment allowlists used when validating patterns."""
    schemas: list[str] | None = None
    indices: list[str] | None = None
    key_prefixes: list[str] | None = None


def validate(p: Pattern, policy: Policy = Policy()) -> list[str]:
    """Raise PatternError if the pattern may not be saved. Returns the placeholder names."""
    types = placeholders(p.template)
    unknown = set(p.params) - set(types)
    if unknown:
        raise PatternError(f"params for undeclared placeholder(s): {', '.join(sorted(unknown))}")
    for n, spec in p.params.items():
        if spec.regex:
            try:
                re.compile(spec.regex)
            except re.error as e:
                raise PatternError(f"{n}: bad regex ({e})")
        if spec.default is not None:
            coerce(n, spec.default, types[n], spec)
    if p.kind == "sql":
        if not isinstance(p.template, str):
            raise PatternError("an SQL template is a string")
        validate_sql(p.template, allowed_schemas=policy.schemas, risk=p.risk)
    elif p.kind == "elasticsearch":
        validate_es(p.template, allowed_indices=policy.indices, limits=p.limits)
    else:
        if not isinstance(p.template, str):
            raise PatternError("a Redis template is a string")
        validate_redis(p.template, key_prefixes=policy.key_prefixes, risk=p.risk)
    return list(types)


def match(p: Pattern, raw: Any) -> dict[str, Any]:
    """Bound values if `raw` is an instance of `p`, else raises Mismatch. Defaults fill unbound placeholders."""
    fn = {"sql": sql_match, "elasticsearch": es_match, "redis": redis_match}[p.kind]
    bound = fn(p, raw)
    missing = set(placeholders(p.template)) - set(bound)
    if missing:
        raise Mismatch(f"unbound placeholder(s) {', '.join(sorted(missing))}")
    return bound


def closest(patterns: list[Pattern], raw: Any, n: int = 3) -> list[Pattern]:
    """Cheap similarity so a rejected query lists the patterns it most resembles."""
    import difflib
    text = raw if isinstance(raw, str) else json.dumps(raw, sort_keys=True, default=str)

    def score(p: Pattern) -> float:
        t = p.template if isinstance(p.template, str) else json.dumps(p.template, sort_keys=True)
        return difflib.SequenceMatcher(None, re.sub(r"\s+", " ", text.lower()), re.sub(r"\s+", " ", PH_RE.sub("?", t).lower())).ratio()
    return sorted(patterns, key=score, reverse=True)[:n]


def describe(p: Pattern) -> dict:
    types = placeholders(p.template)
    return {"name": p.name, "kind": p.kind, "description": p.description, "template": p.template, "risk": p.risk,
            "params": {n: {"type": t, **p.params.get(n, ParamSpec()).model_dump(exclude_none=True)} for n, t in types.items()}}


def json_schema(p: Pattern) -> dict:
    props, req = {}, []
    for n, t in placeholders(p.template).items():
        kind, enum_vals = parse_type(t)
        spec = p.params.get(n, ParamSpec())
        js: dict[str, Any] = ({"type": "integer"} if kind == "int" else {"type": "number"} if kind == "float" else
                              {"type": "array", "items": {"type": "integer" if kind == "list[int]" else "string"}}
                              if kind.startswith("list[") else {"type": "string"})
        if kind == "enum":
            js["enum"] = enum_vals
        if spec.values:
            js["enum"] = spec.values
        for src, dst in (("min", "minimum"), ("max", "maximum")):
            if getattr(spec, src) is not None and kind in ("int", "float"):
                js[dst] = getattr(spec, src)
        if spec.default is not None:
            js["default"] = spec.default
        else:
            req.append(n)
        props[n] = js
    return {"type": "object", "properties": props, "required": req, "additionalProperties": False}
