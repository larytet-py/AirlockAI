"""Build the static UI mock in docs/mock from the real UI, rendered against fictional demo data.

    uv run python docs/mock/build.py

Starts `airlock ui` on a free port with a throwaway AIRLOCK_HOME (fake nodes, clusters, sessions, patterns, a waiting
approval and a proposal), crawls every page, rewrites links to the static copies, and injects mock.js, which stubs the
live endpoints (node/session/cluster stats, fragments, folder picker) and turns form submits into a notice.
Nothing from the real ~/.airlock is read. Re-run after UI changes and commit the result.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path
from urllib.parse import urljoin, urlsplit

OUT = Path(__file__).resolve().parent
REPO = OUT.parent.parent

CONFIG = """version: 1
defaults:
  exec: {mode: ssh, user: jdoe, auth: key}
  links:
    web:  "https://web-{instance_id}.dev.example.com/"
    docs: "https://docs-{instance_id}.dev.example.com/"
    ssh:  "ssh://{user}@{instance_id}.dev.example.com"
    grafana: "https://grafana.example.com/d/k8s?var-cluster={context}"
nodes:
  - {name: JaneTestApi, host: 10.0.1.11, instance_id: i-0a1b2c3d4e5f60718, created_by: Jane Doe, exec: {mode: ssh}}
  - {name: JaneTestGateway, host: i-0fedcba9876543210.dev.example.com, created_by: Jane Doe, exec: {mode: ssh_sudo}}
  - {name: LoadTest01, host: i-0123456789abcdef0.dev.example.com, exec: {mode: ssh}}
  - {name: PaymentsSandbox, host: 10.0.2.37, instance_id: i-07c8d9e0f1a2b3c4d, exec: {mode: direct}}
environments:
  - name: staging
    kube_context: staging
    tools:
      - kubernetes: {mode: read, namespaces: [shop, payments]}
      - kubectl_commands:
          mode: read
          commands:
            - name: db_roles
              description: Which database pod is the primary and which are replicas
              argv: [-n, postgres, get, pods, -L, cnpg.io/instanceRole]
      - slack: {channels: [alerts, incidents], deny_dm: true, token_env: SLACK_TOKEN}
  - name: production
    kube_context: production
    tools:
      - kubernetes: {mode: read, namespaces: [shop, payments]}
      - jira: {url: "https://example.atlassian.net", projects: [OPS], user_env: JIRA_USER, token_env: JIRA_API_TOKEN}
"""

PATTERNS = """query_patterns:
  - name: orders_by_status
    kind: sql
    description: Count orders per status created in the last N hours
    scope: [staging, production]
    template: >
      select status, count(*) from orders
      where created_at > now() - interval '{{ hours:int }} hours'
      group by status
    params: {hours: {min: 1, max: 168, default: 6}}
    limits: {rows: 100, timeout_s: 10}
  - name: failed_payments_by_provider
    kind: sql
    description: Failed payments per provider and error code in a time window
    scope: [production]
    template: >
      select provider, error_code, count(*) from payments
      where status = 'failed' and created_at between {{ start:ts }} and {{ end:ts }}
      group by provider, error_code order by 3 desc
  - name: events_for_order
    kind: elasticsearch
    description: Events for one order id in the last day
    scope: [staging]
    template:
      index: "events-*"
      body: {query: {bool: {filter: [{term: {order_id: "{{ order_id:str }}"}}, {range: {ts: {gte: "now-1d"}}}]}}, size: "{{ size:int }}"}
    params: {size: {max: 200, default: 50}}
  - name: session_hash
    kind: redis
    description: Read one session hash
    scope: [production]
    template: "HGETALL session:{{ id:str }}"
    params: {id: {regex: "^[A-Za-z0-9_-]{1,64}$"}}
"""

KUBECONFIG = """apiVersion: v1
kind: Config
clusters:
- {name: staging, cluster: {server: "https://127.0.0.1:1"}}
- {name: production, cluster: {server: "https://127.0.0.1:1"}}
users: [{name: u, user: {}}]
contexts:
- {name: staging, context: {cluster: staging, user: u}}
- {name: production, context: {cluster: production, user: u}}
current-context: staging
"""

ALLOW = ["api.anthropic.com:443", "claude.ai:443", "claude.com:443", "platform.claude.com:443"]
SESSIONS = [
    {"id": "3f2a91c4", "name": "checkout-bug", "status": "running", "ssh": True, "nodes": ["JaneTestApi", "JaneTestGateway"],
     "allow": ["10.0.1.11:22", "10.0.3.20:22", *ALLOW]},
    {"id": "b71e05d8", "status": "stopped", "nodes": ["LoadTest01"], "allow": ["10.0.4.8:22", *ALLOW]},
    {"id": "c9d4e612", "name": "prod-latency", "mode": "gateway", "status": "running", "ssh": True, "environment": "production",
     "tools": ["kubernetes", "jira", "query"]},
]
PROPOSAL = {"name": "slow_checkouts_last_hour", "kind": "sql", "scope": ["production"],
            "description": "Checkouts slower than N ms in the last hour, by payment provider",
            "template": "select provider, count(*), percentile_cont(0.95) within group (order by duration_ms) from checkouts "
                        "where created_at > now() - interval '1 hour' and duration_ms > {{ min_ms:int }} group by provider",
            "params": {"min_ms": {"min": 100, "max": 60000, "default": 2000}}}

# Every host name and IP in the published mock must be fictional (or a public service the UI really uses).
HOST = re.compile(r"\b(?:[a-z0-9-]+\.)+(?:com|dev|io|net|org|ai|co)\b|\b\d{1,3}(?:\.\d{1,3}){3}\b", re.I)
ALLOWED = re.compile(r"(^|\.)(example\.com|example\.atlassian\.net|anthropic\.com|claude\.ai|claude\.com|jsdelivr\.net|github\.com)$"
                     r"|^10\.0\.\d+\.\d+$|^127\.0\.0\.1$", re.I)


def leak(text: str) -> str | None:
    return next((h for h in HOST.findall(text) if not ALLOWED.search(h)), None)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


FAKE_AWS = """#!/bin/sh
# fake `aws` for the mock: two importable instances tagged with the demo user
cat <<'JSON'
[{"InstanceId": "i-0b5c6d7e8f9a0b1c2", "State": {"Name": "running"}, "PrivateIpAddress": "10.0.5.14",
  "Tags": [{"Key": "Name", "Value": "jdoe-search-test"}, {"Key": "Owner", "Value": "jdoe"}]},
 {"InstanceId": "i-0c6d7e8f9a0b1c2d3", "State": {"Name": "stopped"}, "PrivateIpAddress": "10.0.5.15",
  "Tags": [{"Key": "Name", "Value": "jdoe-batch-worker"}, {"Key": "Owner", "Value": "jdoe"}]}]
JSON
"""


def setup(d: Path) -> dict:
    home, fake = d / "home", d / "fakehome"
    (d / "bin").mkdir()
    (d / "bin" / "aws").write_text(FAKE_AWS)
    (d / "bin" / "aws").chmod(0o755)
    (home / "audit").mkdir(parents=True)
    (home / "airlock.yaml").write_text(CONFIG)
    (d / "kubeconfig").write_text(KUBECONFIG)
    for s in SESSIONS:
        (home / "sessions" / s["id"]).mkdir(parents=True)
        (home / "sessions" / s["id"] / "session.json").write_text(json.dumps(s))
    inbox = home / "sessions" / "c9d4e612" / "inbox"
    (inbox / "approvals").mkdir(parents=True)
    (inbox / "proposals").mkdir(parents=True)
    (inbox / "approvals" / "a1.json").write_text(json.dumps(
        {"id": "a1", "state": "pending", "tool": "kubernetes.rollout_restart", "risk": "write", "ts": time.time() - 40,
         "args": {"namespace": "shop", "deployment": "checkout-api"}}))
    (inbox / "proposals" / "p1.json").write_text(json.dumps(PROPOSAL))
    for r in ("shop-api", "shop-web", "infra"):
        (fake / "src" / r).mkdir(parents=True)
        subprocess.run(["git", "init", "-q", str(fake / "src" / r)], check=True)
    return {"PATH": f"{d / 'bin'}:/usr/bin:/bin", "HOME": str(fake), "AWS_REGION": "us-east-1",
            "SLACK_TOKEN": "x", "JIRA_USER": "x", "JIRA_API_TOKEN": "x", "USER_PASSWORD": "example-not-real",
            "CLAUDE_CODE_OAUTH_TOKEN": "sk-ant-oat01-example-not-real", "AIRLOCK_HOME": str(home), "KUBECONFIG": str(d / "kubeconfig"),
            "USER_NAME": "jdoe"}


def audit(env: dict) -> None:
    code = """
from airlock.audit import Audit
a = Audit('c9d4e612')
a.log('controller', 'session.started', environment='production', tools=['kubernetes', 'jira', 'query'])
a.log('agent', 'tool.call', tool='kubernetes.get_pods', args={'namespace': 'shop'}, result='12 pods, 0 restarting')
a.log('agent', 'tool.call', tool='kubernetes.logs', args={'namespace': 'shop', 'pod': 'checkout-api-7d9f8-x2k4p', 'tail': 200}, result='200 lines')
a.log('agent', 'tool.call', tool='query.run', args={'pattern': 'orders_by_status', 'hours': 6}, result='5 rows')
a.log('agent', 'proposal.submitted', name='slow_checkouts_last_hour')
a.log('agent', 'approval.requested', tool='kubernetes.rollout_restart', args={'namespace': 'shop', 'deployment': 'checkout-api'})
"""
    subprocess.run([sys.executable, "-c", code], env=env, cwd=REPO, check=True)


def post(base: str, path: str, data: dict) -> None:
    from urllib.parse import urlencode
    req = urllib.request.Request(base + path, data=urlencode(data).encode(), headers={"Origin": base})
    try:
        urllib.request.urlopen(req)
    except urllib.error.HTTPError as e:
        if e.code not in (303,):
            raise


def get(base: str, path: str) -> tuple[str, str]:
    with urllib.request.urlopen(base + path) as r:
        return r.headers.get_content_type(), r.read().decode()


def page_name(path: str) -> str | None:
    """Static file name for a UI path, or None when the link is not mirrored."""
    u = urlsplit(path)
    p, q = u.path, u.query
    if p.startswith("/sessions/") and p.endswith("/term"):
        return "term.html?" + ("cmd=claude" if "cmd=claude" in q else "cmd=shell")
    if p == "/" or (p == "/" and q == "tab=ec2"):
        return "index.html"
    if p in ("/prod", "/settings", "/aws"):
        return p[1:] + ".html"
    if p == "/settings/access":
        kind = re.search(r"kind=([a-z_]+)", q)
        return f"access-{kind.group(1) if kind else 'postgres'}.html"
    m = re.fullmatch(r"/settings/access/pattern/([\w.-]+)", p)
    if m:
        return f"pattern-{m.group(1)}.html"
    m = re.fullmatch(r"/nodes/([\w.-]+)/sources", p)
    if m:
        return f"sources-{m.group(1)}.html"
    m = re.fullmatch(r"/audit/(\w+)", p)
    if m:
        return f"audit-{m.group(1)}.html"
    return None


BANNER = ('<style>body{padding-bottom:2.2rem}</style><div id=mockbar style="position:fixed;bottom:0;left:0;right:0;z-index:99;background:#2a6df4;color:#fff;font:13px system-ui;'
          'padding:.35rem 1rem;text-align:center">Static mock of the AirlockAI UI with fictional data: buttons and forms do nothing. '
          '<a style="color:#fff" href="https://github.com/larytet-py/AirlockAI">Back to the README</a></div>'
          '<script src="fragments.js"></script><script src="mock.js"></script>')


def rewrite(html: str) -> str:
    def link(m: re.Match) -> str:
        attr, q, url = m.group(1), m.group(2), m.group(3)
        if not url.startswith("/") or url.startswith("//"):
            return m.group(0)
        frag = ""
        if "#" in url:
            url, frag = url.split("#", 1)
            frag = "#" + frag
        name = page_name(url)
        return f'{attr}={q}{name + frag if name else "#"}{q}'
    html = re.sub(r'\b(href)=(["\']?)(/[^"\'\s>]*)\2', link, html)
    return re.sub(r"(?=<script)", BANNER, html, count=1) if "<script" in html else html + BANNER


def crawl(base: str) -> dict[str, str]:
    pages: dict[str, str] = {}
    todo = ["/?tab=ec2", "/prod", "/settings", "/aws", "/settings/access"]
    seen = set()
    while todo:
        path = todo.pop(0)
        name = page_name(path)
        if not name or name in seen or name.startswith("term.html"):
            continue
        seen.add(name)
        ctype, body = get(base, path)
        if ctype != "text/html":
            continue
        pages[name] = body
        for m in re.finditer(r'href=["\']?(/[^"\'\s>#]*)', body):
            todo.append(urljoin(path, m.group(1)))
    # fragments the pages poll for
    pages["_fragments.json"] = json.dumps({"/prod/waiting-fragment": get(base, "/prod/waiting-fragment")[1],
                                           "/prod/patterns-fragment": get(base, "/prod/patterns-fragment")[1]})
    return pages


def main() -> None:
    d = Path(tempfile.mkdtemp(prefix="airlock-mock-"))
    port = free_port()
    base = f"http://127.0.0.1:{port}"
    env = setup(d)
    srv = subprocess.Popen([sys.executable, "-c",
                            f"import uvicorn; from airlock.ui import make_app; uvicorn.run(make_app(), host='127.0.0.1', port={port}, log_level='warning')"],
                           env=env, cwd=REPO)
    try:
        for _ in range(50):
            try:
                get(base, "/settings")
                break
            except OSError:
                time.sleep(0.2)
        fake = Path(env["HOME"]) / "src"
        post(base, "/settings/sources", {"action": "add", "path": str(fake / "shop-api"), "mode": "ro"})
        post(base, "/settings/sources", {"action": "add", "path": str(fake / "infra"), "mode": "ro"})
        for r in ("shop-api", "shop-web"):
            post(base, "/settings/sources", {"node": "JaneTestApi", "action": "add", "path": str(fake / r), "mode": "rw"})
        post(base, "/settings/access/import", {"yaml": PATTERNS})
        audit(env)
        pages = crawl(base)
    finally:
        srv.terminate()
        shutil.rmtree(d, ignore_errors=True)
    frags = json.loads(pages.pop("_fragments.json"))
    for f in OUT.glob("*.html"):
        if f.name != "term.html":
            f.unlink()
    for name, body in pages.items():
        body = rewrite(body)
        if leak(body):
            raise SystemExit(f"{name}: contains a host that is not fictional: {leak(body)}")
        (OUT / name).write_text(body)
    frags = {k: rewrite(v).replace(BANNER, "") for k, v in frags.items()}
    if leak(json.dumps(frags)):
        raise SystemExit(f"fragments: contains a host that is not fictional: {leak(json.dumps(frags))}")
    (OUT / "fragments.js").write_text("window.MOCK_FRAGMENTS=" + json.dumps(frags) + ";\n")
    print("wrote", ", ".join(sorted(pages)))


if __name__ == "__main__":
    main()
