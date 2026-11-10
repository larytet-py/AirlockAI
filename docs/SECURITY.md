# AirlockAI - Security specification and attack-surface map

Status: draft v1, 2026-11-10. Method: static read of the repository (code, images, config template, scripts, CI, docs). No server, container or test was run. No secret value was read; secrets are referred to by file path and kind only. Items that were reasoned from code but not reproduced are marked **unverified**.

This file is the dedicated security spec. `SPEC.md` section 11 ("Security model") holds the original control table and the egress-traceability options; this file extends it with an inventory, findings and a remediation plan. Where this file and SPEC 11 disagree, the code reading here wins, and the gap is listed in section 7.

Contents: 1 Scope and assumptions, 2 Assets, 3 Trust boundaries and data flow, 4 Attack surface inventory, 5 Threats, 6 Findings, 7 SPEC vs code gaps, 8 Possible fixes / remediation plan.

Line numbers refer to the tree at commit 70cf10a plus the uncommitted working tree; they drift, re-grep before acting.

---

## 1. Scope and assumptions

In scope: `airlock/` (controller, UI, gateway, egress proxy, git MCP), `agent-image/`, `gateway-image/`, `airlock.example.yaml`, `operations/`, `scripts/setup-access.sh`, `pyproject.toml` / `uv.lock`, `.github/workflows/pages.yml`, `docs/` (static mock), `local/` (gitignored, kind only: a node config for acceptance tests).

Out of scope: Docker, the kernel, Claude Code itself, Anthropic's API, AWS, the target Kubernetes clusters and databases (only the privileges AirlockAI hands to its own tools are considered).

Two modes with different trust models:
- Mode 1 Sandbox: the agent is free (`claude --dangerously-skip-permissions`, `airlock/session.py:39`) inside a container; only the model API and the session's EC2 nodes are reachable; the agent holds a per-session ssh key and passwordless root on those nodes.
- Mode 2 Gateway: the agent has only an MCP URL and token; a gateway container holds credentials and enforces policy (patterns, kubectl argv builders, approvals).

Assumptions (stated by the design, kept here as the baseline to attack):
- A1. The operator's workstation and the operator account are trusted. The UI is for one local user (loopback, no login: `airlock/ui.py:1`, `airlock/cli.py:422`).
- A2. The agent (model plus any prompt injection it reads) is untrusted and may be fully adversarial inside its container.
- A3. The operator who writes `airlock.yaml`, patterns and operations is trusted, but a shared or committed config file (README "share and commit") is a supply-chain input and is treated as semi-trusted here.
- A4. The model API is an accepted exfiltration channel (SPEC 11, 11.1).
- A5. Docker on the host is a trusted boundary (anyone in the `docker` group is root and out of scope).
- A6. Nodes in Mode 1 are test machines; a compromised node is a lesser loss than a compromised workstation or production cluster.

Severity scale: Critical = agent or remote party reaches host/production credentials or code execution on the workstation without a human step; High = breaks a stated control or crosses a trust boundary with realistic preconditions; Medium = needs a precondition (config choice, human error, second flaw) or has a bounded effect; Low = hardening or information leak.

---

## 2. Assets

| Id | Asset | Where it lives (path / kind only) | Who must not get it |
|---|---|---|---|
| AS1 | Claude subscription token / OAuth credentials | `~/.airlock/secrets/claude_oauth_token` (file, 0600); env `CLAUDE_CODE_OAUTH_TOKEN`; copy of `~/.claude/.credentials.json` per session | Other users, anything outside the model API path (the agent gets it by design) |
| AS2 | Node login `USER_NAME` / `USER_PASSWORD` | UI process memory/env; env of gateway container (`gwsession.py:148-151`); `~/.airlock/bin/askpass.sh` reads it from env | Agent, audit, logs |
| AS3 | Per-session ssh private key and sudoers rule on nodes | `~/.airlock/sessions/<id>/id_ed25519` (mounted into the agent, `session.py:342`); node `authorized_keys`, `/etc/sudoers.d/90-airlock-<id>` | Anyone but that session's agent (root on nodes) |
| AS4 | Environment secrets (DSNs, Jira/Slack/Airflow tokens) | `~/.airlock/secrets/<env>/*.env` (0600, `envs.py:155-167`) | Agent, other environments |
| AS5 | Kubernetes bearer token for a gateway session | `~/.airlock/sessions/<id>/kube/config` (0600) mounted into the gateway | Agent |
| AS6 | Controller ssh key for container logins | `~/.airlock/ssh/id_ed25519` | Agent |
| AS7 | Audit chain | `~/.airlock/audit/<session>.jsonl` | Agent; any writer other than the controller |
| AS8 | Approved patterns, routes, proposals | `~/.airlock/airlock.db` (SQLite), snapshot mounted into the gateway | Agent (write); wrong-environment use |
| AS9 | Operator workstation code and files | source folders mounted into the agent (`sources.py`), the host shell, `~/.ssh`, `~/.aws`, `~/.kube` | Agent (write outside intent; read credentials) |
| AS10 | Production data reachable through tools | Postgres, Elasticsearch, Redis, pod files, Kubernetes API, Slack, Jira, Airflow | Agent beyond approved queries; PII leaving via results |
| AS11 | Git credentials of the operator | host `ssh-agent`/credential helpers used by the git MCP (`gitmcp.py`) | Agent; unreviewed pushes |
| AS12 | Release integrity: images, Python and npm dependencies, docs site | `gateway-image/`, `agent-image/`, `uv.lock`, `.github/workflows/pages.yml` | Tampering |

---

## 3. Trust boundaries and data flow

```
                      HOST (operator workstation, trusted)
  +--------------------------------------------------------------------------------+
  | browser ---HTTP 127.0.0.1:8800---> [airlock UI/controller  (FastAPI, no login)] |
  |                                      | docker CLI   | ssh/aws/kubectl  | sqlite |
  |   ~/.airlock/{secrets,sessions,audit,airlock.db,ssh,known_hosts}                |
  |   git MCP process (host, operator git creds)  <---token--- relay port           |
  +------------------------|--------------------------|-----------------------------+
                           | docker                   |
        B1 (container boundary)                       |
   +-----------------------v------------------+       |       B4 (nodes / clusters / stores)
   | per-session INTERNAL docker network      |       |
   |   [AGENT container]  Claude, bypass mode |       |
   |      | HTTPS_PROXY=egress:3128           |       |
   |      v                                   |       |
   |   [EGRESS proxy] ---(outbound net)---> api.anthropic.com, claude.ai, ... :443,
   |      CONNECT allowlist host:port          node-IP:22, kube API (Mode 1), pypi/npm (opt.)
   |   Mode 2: [GATEWAY container] <-MCP+Bearer-- agent   (B2: agent -> gateway)
   |      holds secrets; also on OUTBOUND net --------> Postgres/ES/Redis/Slack/Jira/Airflow/
   |      kubectl (session token), ssh (USER_PASSWORD)     k8s API / bastion (B3: gateway -> world)
   +------------------------------------------+
```

Boundaries and what crosses them:
- B1 Agent container to host: bind mounts (`/workspace`, `/src/*` possibly read-write, `/airlock` read-only session dir), docker `exec` from the UI terminal and ssh-over-`docker exec`, the container kernel surface.
- B2 Agent to gateway or git MCP: HTTP + `Authorization: Bearer <per-session token>`, JSON tool arguments in, text results out (`gwserver.py`).
- B3 Gateway to environment: kubectl with a session token, ssh with `USER_PASSWORD`, DSNs, HTTP APIs, `kubectl exec` runners in pods.
- B4 Controller to nodes: ssh with `USER_PASSWORD` to install keys and sudoers; later ssh with the session key.
- B5 Browser/local processes to UI: unauthenticated HTTP on loopback; Origin check on non-GET only (`ui.py:198-210`).
- B6 Operator/shared config to controller: YAML parsed and executed (host commands via `token_cmd`, `${VAR}` expansion, mounts of config directory).
- B7 Build/supply chain: base images, apt, npm, pip, kubectl download, CDN scripts, GitHub Actions.

Data flows that matter most: (1) secrets controller to gateway only; (2) tool results gateway to agent (redaction and caps only); (3) approvals gateway to controller via files in `sessions/<id>/inbox`, answered in the UI; (4) audit written by controller, gateway container and git MCP.

---

## 4. Attack surface inventory

Exposure: L = loopback/host-local, N = internal docker network, A = reachable by the agent, X = external/remote party, B = build time.

| Id | Surface | Location | Exposure | Current controls |
|---|---|---|---|---|
| S01 | Controller web UI, all POST routes (start/stop sessions, node login, token save, approvals, patterns, secrets) | `airlock/ui.py`, `ui_prod.py`, `ui_access.py`; bind `cli.py:422` | L (any local process, any browser tab) | Loopback bind; Origin/Sec-Fetch-Site check on non-GET; `html.escape` in server-built HTML; cookie `samesite=strict` for tab only |
| S02 | UI WebSocket terminal into agent container | `ui.py:630-680` (`/sessions/{sid}/ws`) | L | Origin must be loopback; session must be running |
| S03 | Client-side rendering of node-supplied data | `ui.py:80-86`, `nodestats.py:25-40` | A via node, X via node | None for `mount`, `pct`, `ip` strings put in `innerHTML` |
| S04 | `GET /audit/{sid}` and approval/proposal fragments | `ui_prod.py:207-222`, `ui_access.py:241-270` | L | SID regex; payload escaped and cut to 600 chars |
| S05 | Egress proxy (HTTP CONNECT) | `airlock/egress_proxy.py`; started `session.py:325`, `gwsession.py:117` | A | Exact `host:port` allowlist, non-root, read-only, cap-drop ALL, loopback/link-local resolved-IP check |
| S06 | Relay port 8766 to host git MCP | `egress_proxy.py:83-102`, `session.py:320` | A | Fixed target, per-session bearer token |
| S07 | Agent network and DNS | `session.py:111-125,308-310` (`--internal` network) | A | Internal network, proxy env as convenience |
| S08 | Agent container runtime | `session.py:339-342`, `gwsession.py:163-165` | A | non-root uid, `--read-only`, tmpfs, `--cap-drop ALL`, `no-new-privileges`, `--pids-limit 512`; optional `--runtime runsc` (gateway only) |
| S09 | Bind mounts into agent: `/workspace`, `/src/*` (rw in Mode 1), `/airlock:ro` (session dir with ssh private key, `gitconfig`, `known_hosts`, `nodes.json`) | `session.py:342`, `sources.py:161-222` | A, L (writes land on host) | Credential-dir denylist (`sources.py:22,107-122`); read-only for Mode 2; rw only on explicit setting |
| S10 | Git MCP (host process) `git.commit_push` | `airlock/gitmcp.py` | A | Layout check, `SAFE_CONFIG` regexp, hooks off, pinned origin URL, current branch only, no force |
| S11 | Node access: key + `NOPASSWD:ALL` install/revoke on nodes | `airlock/nodeaccess.py` | L to node, A (agent gets the key) | Session marker + expiry comment, revoke on stop, validation with `visudo -cf`, `USER_RE` |
| S12 | Personal access install (permanent keys + sudoers on every remote node) | `nodeaccess.py:188-267`, `ui.py` settings | L | Idempotent; audited as `personal_access` |
| S13 | ssh into agent container (sshd per connection via `docker exec`) | `sshaccess.py` | L, A (agent writes the sshd config and profile) | No listening port; controller-only key; `StrictHostKeyChecking no` on that hop |
| S14 | MCP gateway HTTP endpoint | `gwserver.py:56-94`; container port 8765 | A | Per-session bearer token (sha256 compare, `hmac.compare_digest`), audit of refused auth, internal network |
| S15 | Gateway core: tool registry, rate limit, output cap, redaction | `gateway.py:151-427` | A | 120 calls/min, 64 kB output cap, unknown-arg rejection, intent/result audit |
| S16 | Approval queue (file inbox) and UI decisions | `gateway.py:89-148`, `gwsession.py:229-243` | A (queue flooding), L | Mutating tools off unless `mode: approve_writes`; 300 s timeout; ids are random hex |
| S17 | Proposal flow (agent submits routes, patterns) | `gateway.py:450-490`, `access.py`, `proposals.py` | A | Validation, feasibility check without connecting, human approval per item, patterns start disabled |
| S18 | Pattern engine: SQL (pglast AST), Elasticsearch, Redis | `patterns.py` | A | Template match with typed placeholders, SELECT-only, deny lists, read-only transaction, statement timeout, row/byte caps |
| S19 | Exec routes: `kubectl exec -i` runners in pods (Django shell, python, airflow) | `access.py:167-170`, `backends.py:29-304` | A (after approval) | Fixed programs, base64 data payload, read-only txn, route target validated, human approval |
| S20 | Files route (read-only file access in a pod) | `backends.py:64-165`, `access.py:38,102-118` | A (after approval) | realpath roots, `DENIED_ROOTS`, byte/line/entry caps |
| S21 | Kubernetes read tools | `kubetools.py` | A | Verb allowlist, name regexes, secrets denied, namespace allowlist |
| S22 | Predefined kubectl commands | `kubecommands.py`, `airlock.example.yaml:67-80` | A | Verb allowlist, deny flags on template argv, closed set for exec params |
| S23 | Remote operations on nodes | `ops.py`, `operations/*.yaml`, `gateway.py:665-687` | A | Typed params, `STR_RE`, script on stdin, risk levels, approval for non-read |
| S24 | Disk tool (gateway-local files) | `gateway.py:689-723` | A | realpath under configured mounts, size cap |
| S25 | Slack / Jira / Airflow / Django HTTP tools | `gateway.py:725-855`, `backends.py:374-389` | A, X (remote content) | Read-only endpoints, https for Jira, project/channel allowlists, results wrapped `untrusted` |
| S26 | Config file parsing and write-back | `config.py:187-250`, `_edit` `config.py:~430`, `airlock.example.yaml` | B6 | `yaml.safe_load`, pydantic `extra=forbid`, literal-secret scan, atomic replace, validation before write |
| S27 | Secret resolution and storage | `config.py:257-273`, `envs.py:127-167` | L | `${VAR}` / `secret:` refs, 0600 files, masked UI field, exact-value redaction |
| S28 | Host subprocess use | `docker`, `ssh`, `ssh-keygen`, `kubectl`, `aws`, `git`, `ip` calls | L | All `subprocess` calls use argv lists, none `shell=True` (grep: no `shell=True`/`os.system`/`eval`/`pickle`) |
| S29 | Kube credential minting (runs kubeconfig exec plugins on the host) | `kubecreds.py:56-93` | B6 | Only contexts used by the environment; token only (no plugin) handed to the gateway |
| S30 | Audit log | `airlock/audit.py`; mounts `gwsession.py:130` | A (if gateway compromised), L | Hash chain, `redact()` over payload |
| S31 | Local files and state: sessions, workspaces, settings | `~/.airlock/{sessions,workspaces,settings.json,airlock.db}` | L | 0600 on key/credential files; directories default umask |
| S32 | Agent image | `agent-image/Dockerfile`, `Dockerfile.gateway`, `airlock-run` | B | non-root user, no secrets baked in, no ssh client in Mode 2 image |
| S33 | Gateway image and egress image | `gateway-image/Dockerfile`, `session.py:23` (`python:3.12-slim`) | B | non-root, deps layer |
| S34 | Python dependencies | `pyproject.toml`, `uv.lock` (54 packages, hashes present) | B | Lock file with hashes for host installs |
| S35 | CI / publishing | `.github/workflows/pages.yml` | X | Only `docs/**` triggers; `contents: write` |
| S36 | Static docs and mock UI | `docs/index.html`, `docs/mock/*`, `docs/mock/build.py` | X (public GitHub Pages) | Fictional data, forms inert |
| S37 | Dev/ops scripts | `scripts/setup-access.sh` | L | `read -s`, password via `SSHPASS` env, `visudo -cf` |
| S38 | AWS import | `awsimport.py` | L | argv list, read-only `DescribeInstances` |
| S39 | Claude settings/hook injection into agent | `session.py:243-258` | A | Static JSON, no user data |
| S40 | Untracked/ignored dev material | `local/` (gitignored node config), `medium/` (untracked article, PDF, PNG), `LICENSE`, `scripts/` (untracked) | L | `.gitignore` covers `local/` only |

---

## 5. Threats

Severity is the residual risk with current controls. "F" refers to findings in section 6.

| Id | Threat | Actor | Sev | Main findings |
|---|---|---|---|---|
| T01 | Agent (or injected text) escalates from a node or container to the controller UI and then to approvals, new sessions, node login, tokens | Agent | High | F01, F02, F25 |
| T02 | Agent or a compromised gateway tool reads other environments' secrets, the Claude token, or the controller ssh key | Agent / tool bug | High | F03 |
| T03 | Agent plants code that runs on the operator workstation (git hooks, config, build scripts) or pushes unreviewed code | Agent | High | F05, F28 |
| T04 | Audit tampering or loss, so an incident cannot be reconstructed | Compromised gateway / agent via gateway | High | F04 |
| T05 | Root persistence or lateral movement on nodes beyond the session (key and sudo rule outlive the session, personal permanent access) | Agent / stale access | High | F06 |
| T06 | Policy bypass inside the gateway: injected kubectl flags, index/key allowlist bypass, SQL deny-list gaps, Slack/Jira allowlist bypass | Agent | High/Medium | F10, F11, F14 |
| T07 | Data exfiltration: model API, DNS, allowed mirrors, tool results with PII and secrets, gateway outbound network | Agent | Medium | F07, F08, F13, F15 |
| T08 | Prompt injection through logs, DB rows, Slack/Jira, repo files, proposals and approval text | Third party via data | Medium | F16, F17 |
| T09 | Credential theft from process/env/ssh first connect (USER_PASSWORD, tokens) | Local user, MITM | Medium | F19, F20, F21, F31 |
| T10 | Container escape or resource exhaustion | Agent | Medium | F09, F32 |
| T11 | Supply-chain compromise via images, npm/pip, kubectl download, CDN script, shared config | External | Medium/High | F19, F22, F23 |
| T12 | Denial of service of the gateway or UI (thread starvation, approval flooding, big reads) | Agent | Low/Medium | F30, F32 |
| T13 | Confused deputy: agent nominates existing secret names or kube contexts in a proposal a human approves | Agent + human | Medium | F12, F16 |
| T14 | Information disclosure through local file permissions on shared hosts | Local user | Low/Medium | F29 |

---

## 6. Findings

Each finding: id, severity, title, evidence (file:line), impact, and a status flag (code-evident, or unverified when a runtime test is needed). Fixes are in section 8.

### F01 (High) Controller UI has no authentication; CSRF defence is Origin-only
Evidence: `airlock/ui.py:1` ("no auth in v1"), `ui.py:198-210` (`refuse_cross_site_posts` lets a request through when no `Origin` header is sent and `Sec-Fetch-Site` is not `cross-site`), `cli.py:422` (bind 127.0.0.1). No Host-header validation. GET routes (`/audit/{sid}`, `/prod/waiting-fragment`, `/api/*`) are unauthenticated.
Impact: any local process or other local user can POST (start sessions, save node login at `/auth/node-login`, save token, approve calls at `/prod/waiting/bulk`, set secrets at `/prod/envs/{name}/secret`). A DNS-rebinding page can read GET pages; browser POSTs from a rebound origin are refused only because the Origin is not loopback. The agent in Mode 1 has network access to nothing local, so this mostly matters together with F02.
Status: code-evident; DNS rebinding read of GETs unverified.

### F02 (High) XSS in the UI from node-supplied strings (agent with root on a node can reach the controller)
Evidence: `airlock/nodestats.py:34-38` takes `mount` (`df` column 6) from the remote node; `ui.py:86` writes it with `innerHTML` (`${{k.mount}}`, also `k.pct`, and `s.ip` at `ui.py:80`). The agent in Mode 1 has `sudo` on the node (F06) and can mount a tmpfs at a directory whose name is HTML without whitespace.
Impact: script runs in the UI origin (loopback), where same-origin POSTs pass the Origin check: approve gateway calls, start sessions, change settings, open the websocket terminal into any container, read audit pages. This is an agent-to-controller escalation across B4/B5.
Status: code-evident; end-to-end exploit unverified.

### F03 (High) Gateway container mounts the whole config directory and the audit directory
Evidence: `airlock/gwsession.py:129` mounts `config_path.parent` (default `~/.airlock`) at `/airlock-config:ro`; this directory also holds `secrets/` for every environment, `secrets/claude_oauth_token`, `ssh/` (controller key), `sessions/*` (including other sessions' kube tokens and ssh keys), `known_hosts`, `airlock.db`. Line 130 mounts `~/.airlock/audit` read-write. Line 133-137 mounts operations and the environment secrets dir (path from `secrets_dir`, `envs.py:42,98`, arbitrary host path).
Impact: SPEC 11 says credentials of one environment never leave its gateway. Any gateway-side bug that reads files (`disk` tool mounts, a path flaw, an exec runner, a library vulnerability) reaches all environments' secrets and the Claude token. Gateway also runs as the host uid, so file modes do not protect.
Status: code-evident when the config lives in `~/.airlock`; if `--config` points elsewhere the exposure is that directory.

### F04 (High) Audit chain is not tamper-resistant and not safe under concurrent writers
Evidence: `airlock/audit.py:29-47` (`_last_hash` re-reads the file; no lock, `open("a")`, no fsync; hash is unkeyed SHA-256 over the record, so anyone with write access can recompute the full chain; `verify` cannot detect tail truncation; no sequence number). Writers: controller, git MCP process (`gitmcp.py` `Audit(sid)`), and the gateway container with the audit dir mounted read-write (`gwsession.py:130`). SPEC 11 and 11.1 state the controller is the only writer; that is not so.
Impact: a compromised gateway can rewrite any session's audit; concurrent processes can fork the chain (false "BROKEN" or silent loss); an attacker can delete the last records undetectably. Records contain full tool arguments (F13).
Status: code-evident; interleaving race unverified.

### F05 (High) Read-write source mounts give the agent code execution on the host and the git MCP pushes agent content
Evidence: `airlock/sources.py:185` (Mode 1 mounts rw when the folder is set rw), `session.py:342`; agent writes `.git/hooks/*`, `.git/config`, `.envrc`, `Makefile`, `package.json` scripts, IDE tasks. `gitmcp.py:150` runs `git add -A` and pushes `HEAD:refs/heads/<current branch>` to the pinned origin with the operator's credentials (`gitmcp.py:~163`); no branch policy, any branch including the default one. `agent_gitconfig` sets `safe.directory=*` for the agent.
Impact: the next `git commit`, `make`, `npm test`, editor open or `direnv` run by the operator executes agent-planted code with the operator's privileges (workstation takeover, AS9, AS11). Pushing to a protected-by-convention branch can trigger CI/CD at the remote.
Status: code-evident. TOCTOU between `check_layout` and `git` use (agent writes the folder concurrently) is a related unverified risk.

### F06 (High) Node access is root on the node; expiry and "test-node only" are advisory
Evidence: `nodeaccess.py:129` (`NOPASSWD:ALL`), `nodeaccess.py:69-77,123` (the expiry is only a comment field `airlock:<sid>:<epoch>` on the key line, which sshd ignores), `session.py:609-623` and `cli.py:219` (the sweeper runs only via `airlock sweep`, not on controller start as SPEC 11 states), `nodeaccess.py:188-267` (personal access is permanent on every remote node, installed in the background when login is saved). SPEC 11 says access is "refused on nodes not tagged as test"; tags were removed from `Node` (`config.py:64-67`) and no check exists.
Impact: a session key that leaks, or a session that was discarded (`discard_session`, `session.py:413-434`) or crashed, stays valid indefinitely; the agent can add its own persistence (cron, extra keys) since it is root; production hosts can be added as nodes without any guard.
Status: code-evident.

### F07 (Medium) Egress proxy weaknesses
Evidence: `egress_proxy.py:13` (`BAD_NETS` only 127/8, 169.254/16, ::1, fe80::/10; no RFC1918, 100.64/10, 0.0.0.0, IPv4-mapped IPv6, fd00:ec2::254), `:58-65` (hostname resolved once for the check and again by `open_connection`: rebinding/TOCTOU), no logging to the audit (SPEC 11.1 option A not built), no per-connection time/byte limits, no concurrent-connection cap, ssh hosts allowed by raw IP so the check is skipped (`literal_ip`). `session.py:221-222` adds `pypi.org`, `files.pythonhosted.org`, `registry.npmjs.org` when `mirrors` is on (usable as exfil/staging channels).
Impact: with the exact allowlist the practical exposure is small (model API hosts, node IPs); risk rises if a user extends `defaults.egress.model_api` or enables mirrors. No record of what was reached.
Status: code-evident.

### F08 (Medium, unverified) DNS may leak from the "internal" network
Evidence: networks are created with `--internal` (`session.py:111-125`); Docker's embedded resolver on such networks may still forward external lookups depending on engine version and configuration.
Impact: DNS tunnelling exfil that bypasses the CONNECT allowlist. Needs a runtime test (`getent hosts` of a controlled domain from the agent).

### F09 (Medium) Container hardening is partial
Evidence: `session.py:339-342`, `gwsession.py:126-132,163-165`: no `--memory`/`--cpus` (egress container has no `--pids-limit` either), no explicit seccomp/AppArmor profile or `--userns`, agent runs as the host uid so rw mounts are written as the operator; `isolation: microvm` is accepted but only `gvisor` changes the runtime (`gwsession.py:152,166`; SPEC 14 known gaps); sandbox sessions ignore `isolation` completely; egress image is a mutable tag (`session.py:23`) and the proxy source is bind-mounted from the host checkout (`session.py:327`). `/airlock` read-only includes the session ssh private key (needed) and `session.json`.
Impact: a kernel or runtime escape is not mitigated by extra layers; memory/CPU exhaustion of the workstation; users may believe `microvm` is active.

### F10 (High) kubectl flag injection through bound parameter values; same class in operations
Evidence: `kubecommands.py:66-77` (DENY_FLAGS checked on the template argv only); `kubecommands.py:129-151` (`bind`): a whole-value placeholder is appended as `[str(v)]` with no check that it does not start with `-`; `str` parameters without regex/values are allowed for read commands (the closed-set rule is only for `exec`, `kubecommands.py:~98-103`). A value such as `--as=system:admin`, `--server=...` or `--kubeconfig=...` becomes a kubectl flag. `ops.py:20,59` (`STR_RE` permits a leading `-`): `journalctl -u {{unit}}`, `systemctl restart {{unit}}` receive option-like values.
Impact: impersonation, redirection of the gateway's kubectl credentials to another server, or changed behaviour for a "read" command; the example config (`airlock.example.yaml:67-80`) is safe only because it uses `enum`.
Status: code-evident; whether kubectl accepts each override with the session kubeconfig is unverified.

### F11 (Medium) Pattern engine allowlist gaps
Evidence:
- Elasticsearch index allowlist skipped for placeholder parts: `patterns.py:452` (`if "{{" not in i`); a whole-value `{{ idx:str }}` index lets the agent supply any index (including `.security*` or other tenants) at call time; no re-check after binding (`es_bind`, `gateway.py:522-556`).
- Redis key prefix check applies only to `toks[1]` (`patterns.py:572`): multi-key commands (`MGET`) and `XRANGE`-style commands are not covered; `INFO` is accepted by the pod program (`backends.py:342`).
- SQL is a deny-list (`patterns.py:230-238`): schema allowlist applies to `RangeVar` only, so functions that read other relations (`table_to_xml`, `query_to_xml` is listed but `table_to_xml`, `schema_to_xml`, `database_to_xml`, `cursor_to_xml` are not), `pg_ls_*` variants beyond `pg_ls_dir`, `pg_notify`, `pg_stat_reset*`, `pg_promote`, `pg_wal_replay_*` are not listed. The READ ONLY transaction (`backends.py:40-43,313-316`) blocks many writes but not all side effects (unverified for `pg_notify`).
- Elasticsearch endpoints `_cat/*` are prefix-matched with the template endpoint used verbatim in the path (`backends.py:348,395`); a pattern with `_cat/../...` is possible if the server normalises (unverified); patterns can be agent-proposed (human approves).
Impact: policy bypass inside an approved route; reading data outside the intended index/schema.

### F12 (Medium, unverified) Confused deputy through proposals
Evidence: `access.py:66-68,95-99,263-285`: the agent chooses `secret`, `user_secret`, `password_secret` names; `have_secret` and `Gateway.secret` also read `os.environ` of the gateway container (`gateway.py:175,208`), which holds `USER_PASSWORD` and `USER_NAME` (`gwsession.py:148-151`). A direct Elasticsearch route can send an existing token/password as Basic auth to a URL the human enters at approval; the UI shows only secret names. `Route.context` (`access.py:75`) is free text passed to `kubectl --context`.
Impact: a human approving a plausible-looking route may route an existing credential to a new endpoint; environment variables become addressable secrets.

### F13 (Medium) Redaction is exact-match and incomplete; PII anonymisation is specified but absent
Evidence: `config.py:394-397` (`redact` replaces only known secret strings: `USER_PASSWORD`, values loaded from the secrets dir, the Claude token; values under 4 chars are skipped; encoded or split forms pass); `gateway.py:395-400` (`_finish`); `audit.py:34-37` (JSON-escaped payload); `grep -ri anonym airlock/` finds nothing although SPEC 7.6 describes `anonymize:` rules. Credentials that come from the cluster (pod env in `get pods -o yaml`, ConfigMaps, logs; `kubetools.py:14` only denies `secret`-type resources) and PII from query results are returned and, in intent records, queried values and commit messages are written to the audit.
Impact: secrets and personal data reach the model provider and the audit file.

### F14 (Medium) Slack and Jira allowlists can be bypassed
Evidence: `gateway.py:805-812`: the agent's `query` is used raw, so `in:#private-channel` inside the query is not constrained by the channel allowlist (Slack search ORs `in:` filters; unverified); `gateway.py:793-800` compares a channel id with an allowlist of channel names, which makes the allowlist ineffective for ids (fails closed, or open when `channels` is unset). `gateway.py:841-843`: `jira.search` takes arbitrary JQL and never applies `projects`.
Impact: reading messages/issues outside the configured scope.

### F15 (Medium) Outbound HTTP from the gateway: redirects, SSRF, unrestricted network
Evidence: `backends.py:374-389` uses `urllib.request.urlopen` (follows redirects, keeps `Authorization` across hosts, accepts `file:` and `ftp:` schemes); Airflow and Django base URLs have no scheme/host policy (`gateway.py:725-733,764-776`, Jira checks only `https://`); the gateway sits on a normal (non-internal) bridge (`gwsession.py:111,126`), so it can reach the host LAN, docker bridges and cloud metadata. No egress filter on the gateway container.
Impact: token leakage to a redirect target; SSRF from tool code if a base URL or a proposed ES URL points internally; a compromised tool has full outbound.

### F16 (Medium) Approval model is coarse
Evidence: `gateway.py:96-113` (a "session" decision approves the tool for the rest of the session for any arguments); `gateway.py:98-121` approvals block a thread for up to 300 s each, unlimited requests; `ui_access.py:250-270` bulk approval; proposal `task`/`evidence`/`description` are free agent text shown to the approver (escaped, but persuasion and fatigue remain); `decide_approval` (`gateway.py:136-148`) is a non-atomic read-modify-write on a file the gateway also writes on timeout.
Impact: human approval can be socially engineered or exhausted; one approval can authorise a broad class of later calls.

### F17 (Medium) Prompt injection and tool-call abuse
Evidence: Mode 1 agent has no permission prompts and root on nodes (`session.py:39`, F06); Mode 2 relies on instruction text and the `untrusted` wrapper (`gateway.py:777-781`, `gwsession.py:53-69`), which is advisory; tool results (logs, rows, Slack, Jira) enter the model context; approved pattern descriptions persist across sessions and are shown by `query.list` (`gateway.py:430-435`), so an injected proposal that a human approves persists. Rate limit is 120/min (`gateway.py:386-393`); no per-tool or per-target budget; no anomaly alerting.
Impact: injected instructions can drive any allowed tool; the controls that matter are the hard ones (F10, F11, F16), not the text.

### F18 (Low) MCP endpoints: DNS-rebinding protection off, plain HTTP, wide bind
Evidence: `gwserver.py:56` (`enable_dns_rebinding_protection=False`), `:94` (`host="0.0.0.0"` in the gateway container), plain HTTP between agent and gateway/relay; the git MCP binds the docker bridge gateway address (`gitmcp.py:start`, `session.py:316-320`) which other containers on that bridge or host-local processes can reach; token auth protects both (`secrets.token_urlsafe(32)`, `hmac.compare_digest`).
Impact: low given per-session tokens; defence in depth only.

### F19 (Medium) Config file is code-equivalent and parsed with broad expansion
Evidence: `config.py:257-273` (`${VAR}` expands any environment variable in any resolved field, `secret:<name>` joins a path without a character check outside `SECRET_KEYS` fields so `secret:../../x` is possible in `exec.user` and error text echoes the value, `nodeaccess.py:118-119`); `config.py:211-218` (`include` globs relative paths); `config.py:48`, `runner.py:132-138` (`kube.token_cmd` is executed on the host); `kubecreds.py:56-66` (kubeconfig exec plugins run with the full environment including `USER_PASSWORD`); `gwsession.py:133-137` (config selects host paths to mount into the gateway: `secrets_dir`).
Impact: a shared or committed `airlock.yaml` (README "share and commit") can run commands on the workstation, leak environment variables into hostnames/users, and mount arbitrary host paths into the gateway.

### F20 (Medium) ssh trust on first use for password logins
Evidence: `runner.py:65-67` (`StrictHostKeyChecking=accept-new` unless `host_key` is pinned; pinning is optional and commented out in `airlock.example.yaml:60`); controller logins to nodes use password auth by design (`nodeaccess.py:47-49`); a per-call temp known_hosts directory for pinned keys is never removed (`runner.py:68-70`). `scripts/setup-access.sh:36` uses `accept-new` too.
Impact: a MITM at first contact receives `USER_PASSWORD`, which is also the sudo password.

### F21 (Medium) USER_PASSWORD spreads through process environments
Evidence: held in the UI process env (`config.py:328-343`), passed to every subprocess (`runner.py:117` `env={**os.environ, **w.env}`), exported to the gateway container (`gwsession.py:148-151`) where every tool subprocess inherits it, read from env by the askpass helper (`runner.py:48-56`), readable from `/proc/<pid>/environ` by the same uid. `redact` masks it in output.
Impact: any code running as the operator or in the gateway sees it; plaintext sudo password for all nodes.

### F22 (Medium) Supply chain: images and dependencies are not pinned or verified
Evidence: `gateway-image/Dockerfile:12-14` builds the gateway from `pyproject.toml` lower bounds (`pydantic>=2.6`, `mcp<2`, ...) and ignores `uv.lock`, so the gateway that holds credentials is not the tested dependency set; `agent-image/Dockerfile:7-9` and `Dockerfile.gateway:6-8`, `gateway-image/Dockerfile:7` download `kubectl` with `curl` and no checksum; `npm install -g @anthropic-ai/claude-code` is unpinned (`agent-image/Dockerfile:10`); base images by mutable tag (`node:22-bookworm-slim`, `python:3.12-slim`, `session.py:23`); apt packages unpinned; xterm.js and addon-fit loaded from jsDelivr without SRI in the live terminal page (`ui.py:156-159`) and in the mock (`docs/mock/term.html:2-6`); `uv.lock` has hashes for 54 packages but no audit step; no SBOM.
Impact: a poisoned dependency or CDN asset executes in the gateway (credentials) or the UI origin (F01/F02 powers).

### F23 (Low) CI is minimal and publishing is broad
Evidence: `.github/workflows/pages.yml` is the only workflow in the tree (git log mentions CI jobs for tests and conformance that are not in the working tree: unverified); `permissions: contents: write`, `actions/checkout@v4` by tag, force-push of an orphan `gh-pages` branch, triggers on `main` push for `docs/**`. No test, lint, secret-scan, dependency-audit or SAST job in the tree. The workflow takes no untrusted inputs (only `GITHUB_SHA`), so script injection risk is low.
Impact: tamper or leak risk through the pages branch; regressions in the controls above are not caught in CI.

### F24 (Low) `scripts/setup-access.sh` shell-injection and exposure
Evidence: `scripts/setup-access.sh:23-30,39` interpolates the operator-typed user name `U` into a `bash -c '...'` string and into the sudoers line (`LINE`) without the character check used in the Python path (`nodeaccess.USER_RE`); a `'` in the name breaks out of the quoted command; the password travels in the `SSHPASS` environment variable; installs permanent `NOPASSWD:ALL`; the same keys are appended from every `~/.ssh/*.pub`. The script is untracked (`git status`).
Impact: self-inflicted injection and a permanent root rule; low because the input is the operator's own.

### F25 (Medium) Agent-controlled data reaches the operator's terminal and ssh client
Evidence: the UI terminal pumps raw bytes from `docker exec` into xterm.js (`ui.py:640-680`) and `ssh <session>` uses agent-writable `sshd_config`, `authorized_keys`, `.bash_profile` (`sshaccess.py:25-62,82-94`) as the server for the host's ssh client via ProxyCommand with `StrictHostKeyChecking no` (`sshaccess.py:107`).
Impact: terminal escape sequences (OSC 52 clipboard write, title, cursor tricks) and a hostile sshd talking to the host ssh client. The profile exports `MCP_TOKEN` from `/proc/1/environ` (the agent already holds it).
Status: code-evident; exploit unverified.

### F26 (Low) Static docs and mock site
Evidence: `docs/mock/*` is generated from the real UI with fictional data (`docs/mock/build.py`); loads xterm from a CDN without SRI (`docs/mock/term.html`); published publicly by `pages.yml`. `medium/` (article, PDF, PNG) is untracked and not published unless added to `docs/`.
Impact: low; risk is leaking real hostnames or IDs if the build is run against a real environment (the generator copies server-rendered HTML), and the CDN dependency.

### F27 (Low) Local file permissions
Evidence: directories under `~/.airlock` are created with the default umask (`session.py:128-142`, `audit.py:25`, `sessions/<id>`, `workspaces/<id>`); only individual secret/credential files are chmod 0600 (`envs.py:155-167`, `session.py:238-239`, `gitmcp.py:start`). `session.json` stores node specs and `token_sha256`; audit files are default-readable; `~/.airlock/known_hosts`.
Impact: other local users can read audit and session metadata on a shared host.

### F28 (Medium) Git MCP residual risks
Evidence: `gitmcp.py:28-31` (`SAFE_CONFIG` allows `remote.*.url`, `gc.*`, `pull.*`, `init.*`, `branch.*`), `check_layout` then `git` are separate steps on a folder the agent can modify at any moment; `git add -A` commits everything the agent staged or created including files that `.gitignore` (agent-editable) no longer hides; `agent_gitconfig` sets `safe.directory = *`; push uses the operator's own ssh/credentials with `GIT_SSH_COMMAND` from the controller environment (`gitmcp.py:~40`). Commit messages are logged verbatim in the audit.
Impact: planted configuration or secrets in commits; exposure window for TOCTOU.

### F29 (Low) Slack/Airflow identifier path, disk tool read size
Evidence: Airflow `ident` regex allows `..` and `.` (`gateway.py:739-745`), producing paths like `/dags/../dagRuns` (server normalisation unverified); `disk` read with negative `limit` passes `min(limit, cap)` to `f.read` (`gateway.py:721`) and reads the whole file into memory before the cap; `_inside` resolves symlinks once (`gateway.py:695-702`) so a swap between check and open is possible if the tree is writable by others.
Impact: bounded information and memory effects.

### F30 (Medium) Gateway can be starved by the agent
Evidence: `gwserver.py:307` runs every call with `asyncio.to_thread` on the default pool; `gateway.py:98-121` blocks a thread per pending approval for 300 s with no cap; rate limit is a per-process counter (`gateway.py:386-393`) and approvals/proposals are not counted separately; inbox files are unbounded (`gateway.py:101-106`, `proposal` files).
Impact: tools stall for all sessions of that gateway; UI approval list flooded.

### F31 (Medium) Claude credentials are copied into the agent
Evidence: `session.py:226-240`: when no long-lived token exists, `~/.claude/.credentials.json` (OAuth refresh token) is copied into the session directory and into the agent's home; the token mode passes `CLAUDE_CODE_OAUTH_TOKEN` as an environment variable of the agent (visible to the agent and `docker inspect`). Accepted in SPEC 11, listed here because the egress allowlist includes `claude.ai` and `platform.claude.com`.
Impact: the token is fully available to the agent and to anything it is tricked into running; revocation is manual.

### F32 (Low) Resource limits
Evidence: no `--memory`/`--cpus`/`--ulimit` on any container (`session.py:325,339`, `gwsession.py:117,126,163`); egress container has no `--pids-limit`; `docker stats` polling in the UI. See also F09.
Impact: workstation DoS by the agent.

---

## 7. SPEC 11 vs code: gaps to close or to document

| SPEC 11 claim | What the code shows | Finding |
|---|---|---|
| Audit file written by the controller only | Gateway container writes `~/.airlock/audit` rw; git MCP is a separate writer | F04 |
| Controller on loopback with token auth | Loopback yes; no authentication, Origin check only | F01 |
| Credentials of other environments never in the gateway | Whole `~/.airlock` is mounted ro | F03 |
| Passwordless sudo has a session marker and a TTL; sweeper runs on controller start; refused on nodes not tagged test | TTL is a comment; sweeper is a manual CLI command; tags were removed | F06 |
| Egress proxy decisions are traceable | Proxy prints to container stdout only (SPEC 11.1 admits "not built") | F07 |
| Anonymisation of results (7.6) | Not implemented | F13 |
| `microvm` isolation level | Not implemented; accepted silently | F09 |
| Prompt injection from Slack/Jira treated as untrusted | Wrapper text only | F17 |
| Mutating tools need approval, "per-call limits" | "Session" approvals cover any arguments; no per-target budgets | F16 |

---

## 8. Possible fixes / remediation plan

Priority: P0 = fix before any shared or production use; P1 = next release; P2 = planned hardening; P3 = nice to have. Effort: S = under a day, M = 1-3 days, L = a week or more. Items marked **unverified** need a runtime check before or while implementing.

| Finding | Concrete fix | Prio | Effort | Verification / test idea |
|---|---|---|---|---|
| F02 | Stop using `innerHTML` for remote data: build nodes with `textContent`/`createElement` in `ui.py` (and `ui_prod.py` JS); validate `mount` and `pct` server-side in `nodestats.py` (`^/[A-Za-z0-9_./-]*$`, `^\d+%$`); add a `Content-Security-Policy: default-src 'self'; script-src 'self' <hashes>` header; serve xterm from a vendored file. | P0 | S | Unit test: feed `df` output with `/<img src=x onerror=1>` and assert the rendered page/JSON has no markup; browser test with CSP enabled shows no inline execution. |
| F01 | Add a random per-start UI token (cookie set on first load via a one-time URL printed by `airlock ui`, `SameSite=Strict`, `HttpOnly`) required on every route including GET and the websocket; reject requests with a missing `Origin` on POST; validate `Host` against `127.0.0.1:port`/`localhost:port`; optionally bind a unix socket with 0600. | P0 | M | Tests: POST without token and without Origin gets 401/403; Host `evil.example` gets 421; websocket without token refused; rebinding script against a running UI cannot read `/audit/<sid>`. |
| F03 | Mount only what the gateway needs: a generated per-session config copy (the one environment, patterns snapshot, operations) and that environment's secrets dir; never `config_path.parent`; mount audit as a write-only channel (see F04); validate `secrets_dir` is under `~/.airlock/secrets` or explicitly allowed. | P0 | M | Integration test (`-m integration`): from inside the gateway container, `ls /airlock-config` shows only the copy; other environments' secrets and `claude_oauth_token` are absent; `disk` tool cannot read them. |
| F04 | Make the controller the only writer: gateway sends audit events over an authenticated channel (unix socket or the MCP return path) to the controller; or give each gateway a private audit file that the controller seals and chains. Add per-session `seq`, HMAC with a controller-held key, periodic signed checkpoints, `flock`+`fsync`, and head-hash pinning in `session.stopped`. `verify` checks `seq` continuity and the checkpoint. Create audit dir/files 0700/0600. | P1 | M-L | Tests: two processes appending concurrently keep a valid chain; truncating the last record is detected via checkpoint; gateway container cannot open `/airlock-home/audit` of other sessions. |
| F05 | Default source mounts to read-only in Mode 1; for rw folders mount a copy/overlay and have the operator review a diff, or at minimum mount `.git/hooks` and `.git/config` read-only (bind overlays) and deny writes to `.git`, `.envrc`, `.vscode`, `.idea`, `Makefile`-class files via a diff-and-confirm step in the git MCP. In the git MCP: refuse the default branch (configurable), run `git` with `GIT_CONFIG_GLOBAL`/`GIT_CONFIG_SYSTEM` empty and `-c` overrides, do the layout check and the operation on a snapshot (`git worktree`/bare clone) to remove the TOCTOU, and show a summary (files, size, secret-scan) in the audit. | P1 | M | Tests: container writes `.git/hooks/pre-commit` in an rw mount and the host path stays unchanged (or the hook is not executed by gitmcp); push to `main` refused; concurrent `.git/config` rewrite during `commit_push` does not change the remote/command. |
| F06 | Enforce expiry on the node: write the key line with `expiry-time="YYYYMMDDHHMMSS"` (OpenSSH 10.1+) or install a root-owned systemd timer/`at` job that removes key and sudoers at the TTL (**unverified**: depends on the node's OpenSSH version); run the sweeper on controller start and on a timer; add an opt-in `allow_sudo: true` on nodes and refuse nodes not marked `sandbox: true` (restore the guard SPEC 11 promises); scope sudo with a command list where feasible; make personal access opt-in per node and listed in Settings. | P1 | M | Test with a throwaway node/container: after TTL the key no longer logs in and the sudoers file is gone with the controller down; `airlock session start` on an unmarked node is refused. |
| F07 | Extend `BAD_NETS` with RFC1918, 100.64/10, 0.0.0.0/8, 192.0.0.0/24, `fc00::/7`, `fd00:ec2::254`, and unwrap IPv4-mapped addresses; resolve once and connect to the resolved IP (pin) for hostname targets; add idle and total timeouts, byte counters, a connection cap; log ALLOW/DENY events to the controller audit (SPEC 11.1 option A); keep mirrors off by default and document them as exfil channels. | P2 | S-M | Unit tests with a fake resolver returning 10.0.0.5, `::ffff:127.0.0.1`, and a flip between first and second lookup; audit shows allow/deny records. |
| F08 | Test whether the agent can resolve external names; if yes, run the agent on a network with `--dns 127.0.0.1`/no resolver (or `--dns` pointing at a sink) and rely on the proxy's `CONNECT host:port` resolution; add the check to `airlock test`. **unverified** | P2 | S | In the agent container: `getent hosts <controlled-domain>` must fail; assert in `selftest.py`. |
| F09 | Add `--memory`, `--cpus`, `--pids-limit` (egress too), explicit `--security-opt seccomp=<profile>` and `apparmor`, `--ulimit nofile`; pin egress image by digest and copy the proxy into a tiny image instead of bind-mounting source from the checkout; reject or warn on `isolation: microvm` until implemented; add `runsc` support to Mode 1; consider rootless Docker/userns remap so the agent uid is not the operator uid. | P2 | M | `docker inspect` assertions in container tests; a memory-bomb in the agent is killed without affecting the host. |
| F10 | In `kubecommands.bind` reject any bound string value beginning with `-` and any value containing `=`-prefixed flag shapes; separate flags from positionals with `--` where kubectl allows; require `regex`/`values`/`enum` for every `str` parameter (not only exec); re-run the DENY_FLAGS check on the final argv; same for `ops.py` (`STR_RE` must not allow a leading `-`) and for `kubetools`. | P0 | S | Tests: parameter `--as=system:admin`, `--server=https://x`, `-f`, `--kubeconfig=/x` rejected for every command; property test over placeholders. |
| F11 | ES: after binding, validate the final index against `allowed_indices` and reject wildcards that escape them; at save time reject whole-value index placeholders unless `values`/`regex` is set; reject `..` and non-`[a-z_/]` in `endpoint`. Redis: check every key argument per command table (MGET, XRANGE, ...), drop `INFO` from the pod program outside activation. SQL: move to an allowlist of functions (or at least add `table_to_xml`/`*_to_xml`, `pg_ls_*`, `pg_notify`, `pg_stat_reset*`, `pg_promote`, `pg_wal_*`, `pg_export_snapshot`) and apply the schema allowlist to function calls and `pg_catalog` access; run queries as a role that has only SELECT on allowed schemas (document this as the real control). | P1 | M | Tests per bullet (bound index outside allowlist is refused; `MGET other:k1 allowed:k2` refused; the listed SQL functions refused); optional Postgres integration test using a role without privileges. |
| F12 | Resolve secret names only from the environment's secrets dir (drop the `os.environ` fallback in the gateway); show approver the full route target including which existing secrets are reused; refuse a direct route whose `user_secret`/`password_secret` is already bound to another service unless confirmed; validate `Route.context` against the environment's known contexts. **unverified** exploit path | P2 | S-M | Test: a proposal naming `USER_PASSWORD` or an unknown context is infeasible; the approval UI lists reused secrets. |
| F13 | Implement SPEC 7.6 anonymisation (start with `strict` mode for SQL/ES/Redis); extend `redact` with common encodings (base64, URL-encoded, case variants) and format-based detectors (JWT, AWS keys, `postgres://user:pass@`); for kubectl output run a scrubber on env values of `get/describe pods -o yaml/json`; stop logging raw args at `tool.intent` for patterns that mark params sensitive (log names and hashes); cap audit message length. | P1 | L | Fixtures with fake secrets in rows, pod env and logs must come out masked; audit grep for the fixture values is empty. |
| F14 | Parse and strip `in:`/`from:` operators from the agent's `query` (or reject them) and build them only from allowlisted values; resolve channel ids to names (or allowlist ids); apply the Jira `projects` allowlist by wrapping JQL (`project in (...) AND (<jql>)`) and rejecting JQL containing `project` overrides. **unverified** Slack OR semantics | P2 | S | Unit tests: `secret in:#hr` is rejected; Jira search for a non-allowed project returns nothing. |
| F15 | Use a custom opener without redirects (or re-check host and drop `Authorization` on cross-host redirect), restrict schemes to https/http, resolve and block private ranges for tool URLs except an explicit per-environment allowlist; place the gateway behind an egress allowlist (second proxy or nftables rules inside its network namespace) limited to the environment's endpoints. | P1 | M | Test server that 302s to an internal URL: tool refuses; gateway container cannot reach `169.254.169.254` or the docker gateway IP. |
| F16 | Bind "session" approvals to a normalised argument shape (e.g. tool + allowed arg schema) or remove the option for write tools; cap pending approvals per session and per tool; make `decide_approval` atomic (`os.replace` of a new file, state transitions checked); show the approver the exact argv/SQL and the target; add "approve once" as the default. | P2 | M | Tests: ten pending approvals beyond the cap are refused; a concurrent timeout and approve cannot both succeed. |
| F17 | Treat model content as hostile in design reviews: keep hard controls (F10, F11, F16); add a content-security layer for tool results (strip ANSI/control chars, cap per-field size), mark fields from external systems with a stable delimiter, add per-session budgets (calls per tool, bytes returned) and an alert hook on anomalies; review approved pattern descriptions for instructions before enabling. | P2 | M | Red-team set of injection strings in logs/rows/Jira; verify budgets trigger and no mutating tool runs without approval. |
| F18 | Turn DNS-rebinding protection back on with `allowed_hosts=["gateway:8765","egress:8766"]`; bind the gateway to its internal-network address only; consider mTLS or a unix socket for the git MCP relay. | P3 | S | Request with a wrong `Host` is refused (421/403). |
| F19 | Document the config as code; add `airlock config validate --strict` that rejects `token_cmd`, `include` outside the config directory, `secret:` names with `/` or `..` (apply `REF_RE` to every resolved field), and `${VAR}` outside an allowlist (`USER_NAME`, `USER_PASSWORD`, `AIRLOCK_*`); warn when the config was not authored by the operator (git origin check or checksum prompt) and show a diff when it changes; do not mount config-selected host paths without confirmation. | P1 | M | Tests: configs with `secret:../../x`, `${AWS_SECRET_ACCESS_KEY}`, `token_cmd` are refused in strict mode. |
| F20 | Require `host_key` (or `known_hosts` pinning from an out-of-band source, e.g. EC2 console output / `aws ec2 get-console-output`) before sending a password; keep `accept-new` for key auth only; delete temp known_hosts dirs. | P1 | M | Test with a fake sshd presenting an unknown key: password is not sent. |
| F21 | Prefer key or SSO-based login for the controller; keep `USER_PASSWORD` out of the gateway container unless an `ssh_sudo` tool needs it (pass only to that subprocess's stdin/env); drop inherited env for subprocesses (`env=` allowlist) in `runner.execute`; zeroise where possible; consider reading the password from the OS keyring. | P2 | M | `grep USER_PASSWORD` in `/proc/<pid>/environ` of `kubectl`/`ssh` children and the gateway shows absent unless needed. |
| F22 | Gateway image: install from `uv.lock` (`uv export --frozen --no-dev --hashes` then `pip install --require-hashes`); verify `kubectl` with the published sha256; pin npm package and version of `@anthropic-ai/claude-code`; pin base images by digest; vendor xterm assets or add SRI hashes; add `pip-audit`/`uv`-based advisory checks and an SBOM (`syft`) to CI; set Dependabot/Renovate. | P1 | M | CI job fails when a hash mismatches or an advisory is found; `docker history` shows pinned digests. |
| F23 | Add CI: unit tests, `ruff`/`bandit`, secret scan (`gitleaks`), dependency audit, image build with trivy; pin actions by SHA; run `pages.yml` with `contents: write` only on the publish job; protect `gh-pages` and `main`; verify the mock build contains no real hostnames (regex gate). Confirm whether CI jobs mentioned in git history exist elsewhere (**unverified**). | P2 | M | A failing test or a seeded fake secret blocks the pipeline. |
| F24 | Validate `U` with `^[A-Za-z0-9_][A-Za-z0-9_.-]*$` and quote with `printf %q`; pass the remote scripts via stdin instead of `bash -c '...'`; require `ssh -o StrictHostKeyChecking=yes` with a pinned key; warn that the sudoers rule is permanent; or delete the script in favour of `airlock auth`/UI. | P3 | S | `shellcheck` clean; a user name containing `'` is rejected. |
| F25 | Filter or neutralise OSC 52 and other dangerous escapes in the UI terminal (xterm.js options: disable clipboard addon, `allowProposedApi=false`); for ssh-in, run the host client with `-o ForwardAgent=no -o ForwardX11=no -o PermitLocalCommand=no -o EscapeChar=none`, and keep the host-side sshd config outside the agent's writable tree (separate read-only mount) so the agent cannot modify the server the host connects to. | P2 | S-M | Test: an agent printing `\e]52;c;...` does not change the host clipboard; the ssh config in `ssh_config` carries the options. |
| F26 | Add SRI or vendor assets; make `docs/mock/build.py` read only fictional fixtures (it already does, add a test); keep `medium/` out of `docs/`. | P3 | S | Mock build test greps output for non-fictional domains. |
| F27 | Create `~/.airlock` and subdirectories with 0700 (umask 077 at startup of controller/CLI); verify on start and fix or warn. | P2 | S | Test: fresh `AIRLOCK_HOME` has mode 0700 on `sessions`, `audit`, `workspaces`. |
| F28 | See F05 for the snapshot approach; additionally tighten `SAFE_CONFIG` (drop `gc.*`, `pull.*`, `init.*`, `remote.*.url`), scan staged files for secrets, require a separate confirmation for new files outside the tracked set, record the diff stat in the audit. | P2 | M | Tests as in F05; staged `.env`-like file is flagged. |
| F29 | Tighten the `ident` regex to exclude `.`-only names, clamp negative `limit`/`offset`, open files with `O_NOFOLLOW` and verify the fd path (`/proc/self/fd`) after open. | P3 | S | Tests with `limit=-1`, `dag_id=..`, symlink swap. |
| F30 | Run tool calls in a bounded executor (e.g. 16 workers) with a queue limit and per-call deadline; count approval/proposal requests in the rate limiter; cap inbox files and sizes; move the limiter state into the gateway-wide lock (already) and expose a gauge in the audit. | P2 | S-M | Load test: 200 pending approvals do not stall `query.list`. |
| F31 | Prefer the setup-token path (no refresh token) and document revocation; never copy `~/.claude/.credentials.json`; set short token lifetimes where the provider allows; add a "revoke this device" note in Settings after a session ends; keep the egress allowlist minimal. | P2 | S | Session start with no token set and no credentials file does not copy anything from `~/.claude`. |
| F32 | Add `--memory`, `--cpus`, `--pids-limit`, and log-size limits to all containers (merge with F09). | P2 | S | `docker inspect` shows limits; fork-bomb test does not hang the host. |

Suggested order of work: (1) F02, F01, F10, F03 (P0, mostly small); (2) F04, F05, F06, F11, F13, F15, F19, F20, F22 (P1); (3) the remaining P2/P3 items. Re-run this review after each batch and update sections 4, 6 and 7.

Open verification checklist (needs a running stack, not done here): F01 DNS rebinding read of GET routes; F02 end-to-end XSS with a crafted mount name; F04 concurrent audit writers; F08 DNS from the internal network; F10 kubectl accepting `--as`/`--server` as bound values; F11 `pg_notify` in a READ ONLY transaction, `_cat/../` normalisation; F14 Slack OR semantics for multiple `in:`; F6 `expiry-time` support on target OpenSSH versions.
