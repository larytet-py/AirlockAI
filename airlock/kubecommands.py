"""Predefined kubectl commands (SPEC 7, 6.2): the only kubectl the agent can run besides the fixed read tools.

An administrator defines each command in the config: a name, a fixed argv for kubectl (no shell), typed parameters and a
risk. The gateway exposes each one as the MCP tool `kubectl.<name>`. The agent supplies only parameter values; it never
supplies a verb, a flag or a command line. Checked when the config is loaded, and again at call time.
"""
from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, field_validator

from .config import ConfigError
from .patterns import PH_RE, Mismatch, ParamSpec, coerce, parse_type, placeholders, split_literal, SAFE_EMBED

NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}$")
READ_VERBS = {"get", "describe", "logs", "top", "events", "version", "cluster-info", "api-resources", "api-versions"}
WRITE_VERBS = {"apply", "delete", "scale", "rollout", "patch", "annotate", "label", "cordon", "uncordon", "drain", "taint",
               "create", "replace", "set", "run", "expose", "autoscale"}
EXEC_VERBS = {"exec"}
# Flags that would change identity, target or interactivity. The runner adds --context / --kubeconfig itself.
DENY_FLAGS = {"--context", "--kubeconfig", "--server", "-s", "--token", "--as", "--as-group", "--as-uid", "--certificate-authority",
              "--client-certificate", "--client-key", "--insecure-skip-tls-verify", "--username", "--password", "-i", "--stdin",
              "-t", "--tty", "-it", "-ti", "-w", "--watch", "-f", "--filename", "-k", "--kustomize", "--raw"}
SHELLS = {"sh", "bash", "zsh", "dash", "ash", "ksh", "csh", "fish", "su", "sudo", "env", "xargs", "nsenter", "chroot"}


class KubeCommand(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    description: str = ""
    argv: list[str]                     # kubectl arguments, without the binary
    params: dict[str, ParamSpec] = {}
    risk: Literal["read", "write"] = "read"
    allow_exec: bool = False            # needed for `exec`: runs a fixed command inside a pod
    timeout: int = 60
    max_bytes: int = 64_000

    @field_validator("name")
    @classmethod
    def _name(cls, v):
        if not NAME_RE.match(v):
            raise ValueError(f"command name must match {NAME_RE.pattern}")
        return v

    def verb(self) -> str:
        """The kubectl verb: the first argument that is not a flag or a flag's value (-n ns, --namespace=ns, -c container)."""
        skip = False
        for a in self.argv:
            if skip:
                skip = False
                continue
            if a in ("-n", "--namespace", "-c", "--container", "-l", "--selector", "-o", "--output"):
                skip = True
                continue
            if a.startswith("-"):
                continue
            return a
        return ""

    def declared(self) -> dict[str, str]:
        return placeholders(self.argv)


def validate(c: KubeCommand) -> None:
    if not c.argv or not all(isinstance(a, str) and a and "\n" not in a and "\0" not in a for a in c.argv):
        raise ConfigError(f"kubectl command {c.name}: argv is a list of non-empty single-line strings")
    verb = c.verb()
    if verb in WRITE_VERBS:
        if c.risk != "write":
            raise ConfigError(f"kubectl command {c.name}: `{verb}` changes state, so it must declare risk: write")
    elif verb in EXEC_VERBS:
        if not c.allow_exec:
            raise ConfigError(f"kubectl command {c.name}: `exec` needs allow_exec: true")
    elif verb not in READ_VERBS:
        raise ConfigError(f"kubectl command {c.name}: verb {verb!r} is not allowed; "
                          f"read: {', '.join(sorted(READ_VERBS))}; exec (allow_exec); write: {', '.join(sorted(WRITE_VERBS))}")
    if c.risk == "read" and verb in WRITE_VERBS:
        raise ConfigError(f"kubectl command {c.name}: a write verb cannot be risk: read")
    for a in c.argv:
        flag = a.split("=", 1)[0]
        if flag in DENY_FLAGS:
            raise ConfigError(f"kubectl command {c.name}: flag {flag} is not allowed (identity, target and interactivity are fixed)")
    if verb in EXEC_VERBS:
        if "--" not in c.argv:
            raise ConfigError(f"kubectl command {c.name}: exec needs `--` before the command to run in the pod")
        inner = c.argv[c.argv.index("--") + 1:]
        if not inner or inner[0].rsplit("/", 1)[-1] in SHELLS:
            raise ConfigError(f"kubectl command {c.name}: exec must run one program with fixed arguments, not a shell")
    types = c.declared()
    unknown = set(c.params) - set(types)
    if unknown:
        raise ConfigError(f"kubectl command {c.name}: params for undeclared placeholder(s) {', '.join(sorted(unknown))}")
    for n, t in types.items():
        try:
            kind, _ = parse_type(t)
        except Exception as e:
            raise ConfigError(f"kubectl command {c.name}: {e}") from e
        spec = c.params.get(n, ParamSpec())
        # A free string inside an exec'd program (a SQL text, for example) would be an injection channel: demand a closed set.
        if verb in EXEC_VERBS and kind in ("str", "list[str]") and not (spec.regex or spec.values):
            raise ConfigError(f"kubectl command {c.name}: str parameter {n} used with exec needs a regex or values")
        if spec.default is not None:
            try:
                coerce(n, spec.default, t, spec)
            except Mismatch as e:
                raise ConfigError(f"kubectl command {c.name}: default of {n}: {e}") from e
    if types and any(PH_RE.search(a) and not a.strip() for a in c.argv):
        raise ConfigError(f"kubectl command {c.name}: empty placeholder argument")


def parse(settings: dict[str, Any]) -> list[KubeCommand]:
    """The `commands` list of a `kubectl_commands` tool entry, validated."""
    out, seen = [], set()
    for raw in settings.get("commands") or []:
        try:
            c = KubeCommand.model_validate(raw)
        except Exception as e:
            raise ConfigError(f"kubectl command {raw.get('name', '?') if isinstance(raw, dict) else '?'}: {e}") from e
        if c.name in seen:
            raise ConfigError(f"kubectl command {c.name} is defined twice")
        seen.add(c.name)
        validate(c)
        out.append(c)
    return out


def bind(c: KubeCommand, given: dict[str, Any]) -> list[str]:
    """Fill the placeholders with typed values and return the kubectl arguments. Raises Mismatch on a bad value."""
    types = c.declared()
    extra = set(given) - set(types)
    if extra:
        raise Mismatch(f"unknown parameter(s): {', '.join(sorted(extra))}")
    vals: dict[str, Any] = {}
    for n, t in types.items():
        spec = c.params.get(n)
        if n in given:
            raw = given[n]
        elif spec and spec.default is not None:
            raw = spec.default
        else:
            raise Mismatch(f"missing parameter {n}")
        vals[n] = coerce(n, raw, t, spec)
    out: list[str] = []
    for a in c.argv:
        parts = split_literal(a)
        if len(parts) == 1 and parts[0][1] is not None:
            v = vals[parts[0][0]]
            out += [str(x) for x in v] if isinstance(v, list) else [str(v)]
            continue
        piece = ""
        for text, ty in parts:
            if ty is None:
                piece += text
                continue
            v = vals[text]
            if isinstance(v, list) or (isinstance(v, str) and not SAFE_EMBED.match(v)):
                raise Mismatch(f"{text}: unsafe value inside a larger argument")
            piece += str(v)
        out.append(piece)
    if any("\n" in a or "\0" in a for a in out):
        raise Mismatch("arguments with newline or NUL are rejected")
    return out


def json_schema(c: KubeCommand) -> dict:
    """Input schema for the MCP tool: one property per placeholder, typed like a query-pattern parameter."""
    from .patterns import Pattern, json_schema as pattern_schema
    holders = " ".join(f"{{{{ {n}:{t} }}}}" for n, t in c.declared().items())
    return pattern_schema(Pattern(name="x", kind="redis", template="GET " + (holders or "k"), params=c.params))
