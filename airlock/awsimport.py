"""Import nodes from AWS (SPEC 6.1): read-only `ec2 describe-instances`, filtered to instances that carry USER_NAME.

Needs the AWS CLI and valid credentials on the controller host. Importing is read-only; `control` below is the only
code that changes anything in AWS (start/stop/reboot of the selected nodes, from the UI). The agent never gets AWS
credentials. Instances are matched by any tag value containing the user name (Name, Owner, CreatedBy, ...).
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field

from .audit import Audit
from .config import NAME_RE, Config, ConfigError, Node

USER_RE = re.compile(r"^[A-Za-z0-9_.@-]{1,64}$")


@dataclass
class Instance:
    id: str
    region: str
    name: str
    state: str
    private_ip: str | None
    public_ip: str | None
    tags: dict[str, str] = field(default_factory=dict)
    matched_on: str = ""


def available() -> bool:
    return shutil.which("aws") is not None


def settings(cfg: Config) -> dict:
    return (cfg.integrations or {}).get("aws", {}) or {}


def current_user() -> str | None:
    u = os.environ.get("USER_NAME")
    return u if u and USER_RE.match(u) else None


class AwsAuthError(RuntimeError):
    """AWS credentials are missing or expired; `command` is what the user runs to log in again."""

    def __init__(self, detail: str, command: str):
        super().__init__(f"AWS login needed: {detail}. Log in again in a terminal with: {command}")
        self.detail, self.command = detail, command


AUTH_HINTS = ("expired", "unable to locate credentials", "expiredtoken", "invalidclienttokenid", "authfailure",
              "security token", "aws login", "sso login", "no credentials", "token has expired")


def login_command(err: str, profile: str | None) -> str:
    sso = "sso" in err.lower()
    return ("aws sso login" if sso else "aws login") + (f" --profile {profile}" if profile else "")


def _aws(args: list[str], profile: str | None, timeout: float = 60) -> str:
    cmd = ["aws", *args, "--output", "json"] + (["--profile", profile] if profile else [])
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if p.returncode:
        err = (p.stderr.strip().splitlines() or ["aws failed"])[-1]
        err = re.sub(r"^(aws: )+(\[ERROR\]: )?", "", err).strip()
        if any(h in p.stderr.lower() for h in AUTH_HINTS):
            raise AwsAuthError(err.split(". ")[0].rstrip("."), login_command(p.stderr, profile))
        raise RuntimeError(f"aws: {err}")
    return p.stdout


def parse(raw: str, region: str, user: str) -> list[Instance]:
    out = []
    for inst in json.loads(raw or "[]"):
        tags = {t["Key"]: t.get("Value", "") for t in inst.get("Tags", []) if "Key" in t}
        hit = next((k for k, v in tags.items() if user.lower() in v.lower()), "")
        if not hit:
            continue
        out.append(Instance(inst["InstanceId"], region, tags.get("Name", ""), inst.get("State", {}).get("Name", "?"),
                            inst.get("PrivateIpAddress"), inst.get("PublicIpAddress"), tags, hit))
    return out


def find_instances(cfg: Config, *, user: str | None = None, regions: list[str] | None = None,
                   profile: str | None = None, include_stopped: bool = True) -> list[Instance]:
    user = user or current_user()
    if not user or not USER_RE.match(user):
        raise ConfigError("USER_NAME is not set (or has unsafe characters)")
    s = settings(cfg)
    profile = profile or s.get("profile")
    regions = regions or s.get("regions") or []
    if not regions:
        r = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION")
        if not r and available():
            r = subprocess.run(["aws", "configure", "get", "region"] + (["--profile", profile] if profile else []),
                               capture_output=True, text=True).stdout.strip()
        regions = [r] if r else []
    if not regions:
        raise ConfigError("no AWS region: pass --region, set integrations.aws.regions, or configure a default region")
    states = "pending,running" + (",stopping,stopped" if include_stopped else "")
    found: list[Instance] = []
    for region in regions:
        raw = _aws(["ec2", "describe-instances", "--region", region,
                    "--filters", f"Name=tag-value,Values=*{user}*", f"Name=instance-state-name,Values={states}",
                    "--query", "Reservations[].Instances[]"], profile)
        found += parse(raw, region, user)
    return found


def node_name(inst: Instance, taken: set[str]) -> str:
    base = re.sub(r"[^A-Za-z0-9_.-]+", "-", inst.name).strip("-._") or inst.id
    name = base if NAME_RE.match(base) else inst.id
    if name in taken:
        name = f"{name[:50]}-{inst.id[-6:]}"
    return name


def host_for(inst: Instance, cfg: Config) -> str:
    tpl = settings(cfg).get("host_template")  # e.g. "{instance_id}.example.com" when nodes are reached by DNS name
    if tpl:
        return tpl.format(instance_id=inst.id, name=inst.name, region=inst.region)
    ip = inst.public_ip or inst.private_ip
    if not ip:
        raise ConfigError(f"{inst.id} has no IP address (state {inst.state})")
    return ip


def to_spec(inst: Instance, cfg: Config, taken: set[str]) -> dict:
    from .config import node_spec
    spec = node_spec(node_name(inst, taken), host_for(inst, cfg), user="${USER_NAME}", mode="ssh")
    spec["instance_id"], spec["region"] = inst.id, inst.region
    return spec


def new_instances(cfg: Config, found: list[Instance]) -> list[Instance]:
    """Drop instances that are already nodes (same aws_instance_id tag)."""
    have = {n.resolved_instance_id() for n in cfg.nodes}
    return [i for i in found if i.id not in have]


LIFECYCLE = {"start": "start-instances", "stop": "stop-instances", "reboot": "reboot-instances"}


def control(cfg: Config, nodes: list[Node], action: str) -> list[str]:
    """Start, stop or reboot the EC2 instances behind the given nodes. Returns one status line per node.

    Only nodes with a known instance id are touched, and stop/reboot are refused
    while a session uses the node (its key and sudo rule could not be removed from a stopped machine). Calls are
    grouped by region; a failed call is reported for every node in its group."""
    from .session import sessions_using   # session imports this package's ssh/node code: keep the import local
    if action not in LIFECYCLE:
        raise ConfigError(f"unknown action {action!r} (use start, stop or reboot)")
    if not nodes:
        raise ConfigError("select at least one node")
    if not available():
        raise ConfigError("AWS CLI not found on this host")
    profile = settings(cfg).get("profile")
    regions = settings(cfg).get("regions") or []
    lines: list[str] = []
    groups: dict[str | None, list[tuple[Node, str]]] = {}
    for n in nodes:
        iid = n.resolved_instance_id()
        if not iid:
            lines.append(f"{n.name}: skipped, no EC2 instance id (set instance_id on the node)")
        elif action != "start" and sessions_using(n.name):
            lines.append(f"{n.name}: skipped, a session uses it: stop the session first")
        else:
            region = n.region or (regions[0] if len(regions) == 1 else None)
            groups.setdefault(region, []).append((n, iid))
    audit = Audit("aws-control")
    for region, items in groups.items():
        ids = [iid for _, iid in items]
        try:
            _aws(["ec2", LIFECYCLE[action], "--instance-ids", *ids] + (["--region", region] if region else []), profile)
            ok, detail = True, ""
        except AwsAuthError:
            raise
        except RuntimeError as ex:
            ok, detail = False, str(ex)
        for n, iid in items:
            lines.append(f"{n.name}: {action} requested" if ok else f"{n.name}: {action} failed ({detail})")
            audit.log("controller", "aws.control", node=n.name, instance=iid, region=region, action=action, ok=ok)
    return lines
