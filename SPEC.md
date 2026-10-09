# AirlockAI - Spec

Status: draft v0.1

AirlockAI lets a developer run AI coding agents (Claude Code first, Codex and Cursor CLI later) next to real infrastructure without handing the agent the keys to it. The agent works inside an airlock: a container or microVM with a tightly controlled network, and the only way out is a door that the developer built and controls.

## 1. Problem

1. Debugging test nodes on EC2 (usually 2-3 at the same time) is slow by hand. An agent that can SSH, read logs, check CPU and purge Docker would remove most of the toil, but a permission-prompting agent is too slow, and an unrestricted agent on a laptop is a risk.
2. Debugging UAT or production needs read access to Postgres, Elasticsearch, Redis, Kubernetes, disks and logs. The developer holds admin credentials. Giving them to an agent, or relying on the agent's own rules (CLAUDE.md, permission modes, hooks), is not a boundary. A prompt-injected or simply over-eager agent can drop a database.
3. Today's setup is hand-made: a Dockerfile, aliases, MCP servers with hardcoded macOS paths, `.env` files, no inventory, no audit, no UI. It does not scale beyond one person, and the tools cannot be shared.

## 2. Goals and non-goals

Goals

- G1. Run agents with full autonomy (`claude --dangerously-skip-permissions`) where the blast radius is physically bounded.
- G2. Two modes with different trust models (section 4): Sandbox (agent is free, the world is small) and Gateway (agent is constrained, the world is big).
- G3. Credentials for production never enter the agent's container, filesystem, environment or network namespace.
- G4. One browser UI to manage nodes, environments, operations and agent sessions.
- G5. Adding a new capability (a tool or an operation) is a few lines of code or one form, and it takes effect without rebuilding the agent image.
- G6. Everything the agent does through the door is logged and replayable.
- G7. Query patterns for Elasticsearch, SQL and Redis are managed in the UI (add, edit, remove, enable/disable). A pattern that is added is immediately accepted by the MCP gateway from the agent; a removed or disabled one is rejected. No restart, no code change (section 7.1).
- G8. Command execution mode is a per-target choice in the UI and config: run the CLI directly (`kubectl ...`), over SSH (`ssh host kubectl ...`) or over SSH with sudo (`ssh host sudo kubectl ...`). It is configurable per EC2 node and per production environment (and per tool inside an environment). Mode 2 tool code and Mode 1 agents adapt their commands to the choice automatically (section 7.2).
- G9. The whole setup (nodes, operations, environments, query patterns, execution modes, policies) lives in one YAML or JSON config file that can be shared and kept in git. It never contains secrets (section 7.3).
- G10. Runs locally on one developer machine in v1. Shared hosts are out of scope for v1; the target after v1 is a gateway deployed by DevOps and shared by all agents (milestone M7, section 12.1).
- G11. Enforcement is deterministic. What an agent may do and see is decided by code and configuration that run outside the agent, the same way for the same input every time. No model judgement is in the decision path: the agent, the model and any classifier cannot widen it, and an ambiguous or unvalidated case is refused (fail closed). Section 4.1.
- G12. Data returned to the agent can be anonymized by the gateway where the configuration says so, also deterministically (section 7.6).

Assumptions

- The environment of the controller and of the MCP containers defines `USER_NAME` and `USER_PASSWORD`. They are the login for SSH (and the sudo password) on nodes and production hosts. See section 7.4 for how they are handled.
- Docker is available on the controller host; `ssh` and `kubectl` are available where the chosen execution mode needs them.

Non-goals (v1)

- Defending against a nation-state level container escape. Mitigation is the microVM option, not new research.
- Replacing database roles. Read-only DB roles are still recommended as defense in depth; AirlockAI exists because they are often missing.
- Being a general agent framework or an LLM gateway.
- Agents other than Claude Code (Codex, Cursor CLI) in v1; the design stays agent-neutral.
- Shared / multi-user hosts, and authentication of the web UI (it listens on 127.0.0.1 only).
- Alert-driven or ticket-driven session start.
- Artifact storage and session sharing is out of scope. AirlockAI only emits session transcripts and operation logs in a format an artifact store can ingest (section 12).

## 3. Use cases

| ID | Actor | Scenario |
|---|---|---|
| UC1 | Developer | Register 3 test EC2 nodes named after owner and purpose: `JohnTestApi`, `JaneTestGateway`, `BobTestOrders`. Start a Sandbox session on all three. Ask: "why is JohnTestApi at 100% CPU, and clean up Docker if disk is above 80%". Agent SSHes in, investigates, runs `docker system prune`, reports. |
| UC2 | Developer | Tick the nodes in the UI and run "Check CPU" on them; see a table. Same operation is available to the agent as a tool. |
| UC3 | Developer | Add a new operation "restart gateway" (command template + risk level) from a form; agent can use it in the next turn. |
| UC4 | Developer | A production alert arrives. Create a Gateway session for environment `uat`. Paste a link to the alert. Agent queries Elastic, Postgres, Redis, Kubernetes through MCP tools and reports. Cannot delete anything, cannot see a password. |
| UC5 | Developer | Add a new read-only diagnostic tool (e.g. index statistics for a Postgres table) in Python. Gateway hot-reloads; all environments that opt in get it. |
| UC6 | Developer | Run two or three agent containers against the same environment at once (e.g. one per git worktree / ticket), each with its own audit trail. |
| UC7 | Reviewer | Open a finished session and replay the exact list of tool calls, arguments, and (truncated) results. |
| UC8 | Developer | A tool wants to do something mutating (scale a deployment). The UI shows an approval card; the developer approves or rejects. |
| UC9 | Developer | In the UI add the SQL pattern `select status, count(*) from orders where created_at > now() - interval '{{ hours:int }} hours' group by status`. In the next turn the agent can run it with `hours=6`; any other query is still rejected. |
| UC10 | Developer | Edit a Redis pattern to allow `HGETALL session:{{ id:str }}` in `uat` only; disable an ES pattern that turned out to be too heavy. |
| UC11 | Developer | The agent tries a query that matches no pattern. The gateway rejects it and lists the closest patterns. The agent calls `query.propose`; the proposal appears in the UI as pending, and the developer approves, edits or rejects it. |
| UC12 | Developer | `JohnTestApi` allows `kubectl` as a normal user, `JaneTestGateway` needs `sudo kubectl`. Set `JohnTestApi` to `ssh` and `JaneTestGateway` to `ssh_sudo` in the UI. The agent asks for pods on both and the right command runs on each. |
| UC13 | Developer | Switch production environment `uat` from `direct` to `ssh_sudo` after the kubeconfig moved to a bastion. No change in the agent prompts or the tool code. |
| UC14 | Developer | Export the config, commit it, and a colleague imports it, sets their own `USER_NAME` and `USER_PASSWORD`, and gets the same nodes, operations, environments and query patterns. |
| UC15 | Developer | Start a Sandbox session on `JohnTestApi` and `JaneTestGateway`. The node access MCP logs in with `USER_NAME` / `USER_PASSWORD`, installs the session key and enables passwordless sudo. The agent runs `ssh JohnTestApi` and `sudo systemctl restart api` with no password prompts and never sees the password. When the session ends the key and the sudo rule are removed. |
| UC16 | Developer | Open the UI. The `EC2` tab on the left lists test nodes and Sandbox sessions. Click `PROD`: the list is replaced by the Kubernetes clusters found in the local `kubectl` contexts, and the session list shows only Gateway sessions with MCP access to production. The agent that reads `uat` through MCP is never visible in, or startable from, the `EC2` tab. |

## 4. Modes

### Mode 1 - Sandbox ("agent is free, world is small")

- Agent: unrestricted. Claude Code runs in bypass mode (`--dangerously-skip-permissions`; flag name is accurate for the Claude CLI; Codex equivalent is `--dangerously-bypass-approvals-and-sandbox`). It can install packages, edit files, run anything.
- Jail: a container (default) or a microVM (optional) with no host mounts except a per-session workspace directory.
- Network: default deny. Allowed egress is exactly:
  - the model API (`api.anthropic.com`, optionally `api.openai.com`),
  - the registered nodes of this session, by public / Elastic IP and port (usually 22). The nodes' security groups should allow SSH only from the controller host's public IP, and the egress gateway forwards only to the listed IPs,
  - the MCP gateway (section 7.5: Slack, Jira, operations); the agent reaches Slack and Jira through it, never directly,
  - optional package mirrors (pypi, npm, apt) toggled per session.
- Model login: Claude Code authenticates with your subscription login. The controller mounts a per-session copy of the Claude Code credentials read-only into the agent container. This token is inside the container (accepted risk); it can leave only toward the model API because of the egress allowlist, and a session copy can be revoked by logging out of that device.
- Credentials: the agent holds only a per-session SSH key, generated by the controller. The node access MCP (section 6.3) logs in once with `USER_NAME` / `USER_PASSWORD`, authorises that key and sets up passwordless sudo on the test node, then removes both at session end. The agent never sees the password and never needs one: `ssh` and `sudo` just work. Never the developer's personal keys. No AWS credentials unless the user adds a read-only profile explicitly.
- Blast radius: the test nodes and the workspace. By design these are disposable.

### Mode 2 - Gateway ("agent is constrained, world is big")

- Agent: also runs in a container in bypass mode (permission prompts are not the safety mechanism), but its only reach is the MCP gateway. The agent has no `ssh`, no `kubectl`, no database or cloud clients and no way to run commands on production. It can call only the API defined by the MCP tools; the MCP code is what uses ssh and kubectl internally (section 7.2). Model login is the same as in Mode 1 (mounted subscription token).
- Network: no internet except the model API; no route to the environment's real endpoints (Postgres, ES, Redis, kube API, SSH). The only reachable internal address is the gateway.
- MCP servers: written by the user, run in separate containers (or a separate VM), receive credentials from a secrets directory on the host that is mounted into the MCP containers only.
- Policy is enforced in code that the agent cannot read or modify: the MCP code is not in the agent's workspace mount; the gateway container has no Docker socket and no shared volume with the agent.
- Blast radius: whatever the tools can do. Tools are individually classified read-only or mutating; mutating ones are off by default and need approval.

### Why not rely on the agent's own rules

Hooks, permission modes, CLAUDE.md and auto-mode classifiers are part of the harness; they can be bypassed by a bug, an update or a clever prompt (the same argument Docker makes for its AI Governance product). AirlockAI enforces at the network and container boundary, below any harness, so the same policy holds for any agent (v1 targets Claude Code only).

### 4.1 Access flow and deterministic enforcement

Two separate questions, answered by two separate mechanisms.

How the gateway (MCP) gets access to the infrastructure. The gateway is the only holder of credentials:

| Source | Used for | Where it lives |
|---|---|---|
| The developer's own Google sign-in (local use) | Kubernetes through `kubectl` with the kubeconfig's `kubectl oidc-login` plugin (Dex, Google) | The developer's `~/.kube/config` (read-only) and the token cache `~/.kube/cache/oidc-login` (read-write, so tokens refresh), mounted into the gateway container only. The gateway runs `kubectl` as that person, so the cluster audit names them. Expired login: the gateway tries a silent refresh, otherwise the tool call fails with "sign in again" and the UI offers a Sign in button that runs the login on the host. A pre-start check runs `kubectl --context X get ns` on the host. |
| The application's own container (v1 database path) | Postgres, Elasticsearch, Redis as the application sees them, through the Django or Python shell of a pod such as `deploy/backend` | The gateway runs `kubectl exec` as the identity above; the database credentials stay inside the application and are never read by the gateway or the agent (section 7.7). |
| A service identity (shared deployment, section 12.1) | The same, with a ServiceAccount or workload identity whose RBAC is written for the tools it exposes | The deployment's own secret store |
| Secrets files or Infisical / 1Password references | Database, Elasticsearch, Redis, Airflow, Slack, Jira, ssh | `~/.airlock/secrets/<env>/*.env` (0600), mounted read-only into the gateway container only |
| `kubectl port-forward` run by the gateway (design) | Stores inside the cluster, for example the read-only Postgres pooler, without opening any host port | A child process inside the gateway container using the identity above; setting `via_kube: {namespace, service, port}` on the tool |

How the agent gets access, always through the gateway:

1. The controller starts a session: an internal network with no route out, the gateway container, and the agent container. The agent receives `MCP_URL` and `MCP_TOKEN` and nothing else; the gateway keeps only a hash of the token.
2. The agent calls `tools/list`. The list is computed from the environment's configuration: enabled tool groups, query patterns, predefined kubectl commands. A capability that is not configured does not exist for the agent.
3. The agent calls a tool with parameter values. The gateway then runs this fixed pipeline, in code, in this order:
   1. authenticate the token and rate-limit;
   2. look the tool up in the allowlist;
   3. validate the arguments against the tool's schema and the typed placeholders (int, enum, regex, ranges);
   4. match raw queries to an enabled pattern, or bind values into a predefined command; reject everything else;
   5. apply the environment policy (schema and index allowlists, namespaces, denied resources, read-only transactions, replica-only connections);
   6. for a mutating call, wait for an approval by a human in the UI;
   7. execute through the execution mode (7.2) with the gateway's credentials;
   8. anonymize and redact the result, cap its size (7.6);
   9. write the audit record: intent before, result after, with `pattern@version` and the rule names applied.
4. The agent receives the (possibly anonymized) result. It never receives a credential, a connection string, a token, or the raw data an anonymization rule hides.

What deterministic means here, as testable rules:

- The decision for a call is a pure function of the call, the configuration and the pattern version. The same call gets the same answer on any day and for any agent. Nothing consults a model, a prompt, a score or a classifier.
- A rule that cannot be evaluated refuses the call: a query that does not parse, a column no rule covers under `strict` anonymization, a parameter outside its type, a command whose verb is not classified.
- The policy lives in configuration and gateway code that the agent cannot read or change; the agent cannot enable or edit a pattern, only propose one for a human.
- Every refusal is explained with the rule that caused it, and logged. `airlock test` replays a table of forbidden calls against the policy and must find every one refused without touching a backend (section 13).
- Approvals are the only non-automatic step, and they are a human decision recorded in the audit, not a model decision.

## 5. Architecture

```
 Browser  ---------------------------------------------+
    |                                                  |
    v                                                  |
+-----------------------------+                        |
| Controller (host, 127.0.0.1)|  Docker API / libvirt  |
|  - Web UI + REST API        |------------------+     |
|  - SQLite state             |                  |     |
|  - Secrets store reader     |                  v     |
|  - Audit log                |      +-----------------------+
+-------------+---------------+      | Agent container(s)    |
              |                      |  claude (bypass mode) |
              | manages              |  workspace volume     |
              v                      |  NO secrets           |
+-----------------------------+      +-----------+-----------+
| Egress gateway (per session)|<-----------------+  internal network "air-<session>"
|  nftables + SNI proxy       |
|  allow: model API, node IPs |        Mode 2 only:
+-------------+---------------+      +-----------------------+
              |                      | MCP gateway           |
              v                      |  auth, policy, audit  |
        EC2 test nodes               +-----------+-----------+
        (Mode 1)                                 | docker net "air-mcp" (agent cannot join)
                                     +-----------v-----------+
                                     | MCP servers (user code)|
                                     |  pg | es | redis | k8s |
                                     |  ssh | disk | django   |
                                     |  secrets mounted RO    |
                                     +-----------+-----------+
                                                 v
                                         UAT / production
```

Components

1. Controller: single Python process. Serves the UI, stores config, creates and destroys sessions, programs the egress gateway, tails audit logs. Listens on 127.0.0.1 only. The agent network has no route to it.
2. Agent image: Debian slim + Claude Code + git, ssh client, kubectl-less (kubectl only in MCP containers), user's skills mounted read-only. One image, session specific env.
3. Egress gateway: a small container with two interfaces (session internal network and outbound). nftables default drop; an allowlist of IP:port plus an SNI-based HTTPS proxy for the model API (so DNS changes do not break it). The controller rewrites the allowlist when nodes change.
4. MCP gateway (Mode 2): one process per session that speaks MCP over streamable HTTP to the agent and forwards to tool servers. Responsibilities: per-session bearer token, per-environment tool allowlist, argument validation, rate limits, output size caps, redaction, audit, approval hook.
5. MCP tool servers: Python packages built on the official MCP SDK using the AirlockAI tool decorator (section 8). Run in their own container per environment so a bug in one cannot read another's credentials.
6. Secrets store: directory on the host (`~/.airlock/secrets/<env>/*.env`, mode 0600) or a pluggable backend (macOS Keychain, `pass`, AWS SSM Parameter Store). Only the MCP containers of that environment get it, as env vars or tmpfs file mounts.

Isolation levels (per session, selectable in the UI)

| Level | Mechanism | Notes |
|---|---|---|
| container | Docker, user namespaces, no privileged, seccomp default, read-only root + tmpfs, cap drop all | default, fast |
| gvisor | Docker with `runsc` runtime | stronger syscall filtering |
| microvm | Firecracker or Lima/QEMU VM running the same image | for production sessions; also the answer to "container is not a perfect boundary" |

## 6. Mode 1 detail: nodes, labels, operations

### 6.1 Node inventory

Fields: `id`, `name`, `host`, `port`, `user`, `auth` (key ref or SSM instance id), `region`, `instance_id`, `labels` (free strings), `notes`, `created_at`, and `exec` (execution mode, section 7.2).

- UI: table with add / edit / remove, bulk label editor, and "import from AWS" (read-only `ec2:DescribeInstances` filtered by tag). It is enabled only if the AWS CLI and credentials are present on the controller host. The same read-only call is offered to the Mode 1 agent as the MCP tool `aws.describe_instances`; the agent never receives AWS credentials.
- Names are meaningful and unique, for example `JohnTestApi` (owner + environment + service); the agent and the UI refer to nodes by name. The name is what appears in prompts, audit entries and `airlock-run <name>`; the host address can change without breaking anything.
- There are no tags and no selectors: a session or an operation is bound to explicit nodes (UI checkboxes, `--nodes`). Labels are free strings for grouping in the UI only.
- Health: controller pings (TCP + SSH banner) every 30 s; shows reachable, load, disk.
- AirlockAI never writes EC2 tags. Its only AWS writes are start / stop / reboot of the selected nodes from the UI, which need a write-capable AWS profile on the controller only.

### 6.2 Operations (named, reusable actions)

An operation is a parametrised command with metadata. Stored as YAML in `~/.airlock/operations/*.yaml` (git friendly) and editable in the UI.

```yaml
name: docker-purge
description: Remove stopped containers, dangling images, build cache
risk: destructive        # read | safe | destructive
params:
  - {name: keep_hours, type: int, default: 24}
run: |
  docker system prune -af --filter "until={{ keep_hours }}h"
  df -h /var/lib/docker
timeout: 300
```

```yaml
name: cpu
description: Top CPU consumers and load
risk: read
run: |
  uptime; ps -eo pid,pcpu,pmem,comm --sort=-pcpu | head -15
```

Use:

- Human: button in the UI, runs on selected nodes in parallel, streams output.
- Agent: exposed as the MCP tool `ops.run(name, nodes, params)` and listed by `ops.list()`. In Sandbox mode the agent can also just SSH; operations are a shortcut and a shared vocabulary ("run docker-purge on JohnTestApi"), and they log uniformly.
- Prompt injection into the session: UI offers "send to agent: <operation>" which types the instruction into the terminal.

Starter library: `cpu`, `mem`, `disk`, `docker-ps`, `docker-purge`, `journal-tail`, `restart-service`, `top-ports`, `reboot` (destructive, confirm).

### 6.3 Node access MCP: passwordless login and sudo for the agent (Mode 1)

A small MCP server, the node access MCP, runs on the controller side in its own container with `USER_NAME` and `USER_PASSWORD` in its environment. It prepares test nodes so that the agent can work on them with no passwords at all.

What it does for a node (`enable_access`)

1. Connects to the node as `USER_NAME` with `USER_PASSWORD` (SSH password auth through `SSH_ASKPASS`, host key pinned or recorded on first use and shown in the UI).
2. Appends the session's public key to `~/.ssh/authorized_keys`, tagged with a marker comment `airlock:<session-id>:<expiry>` and, if configured, restricted with `from="<egress gateway IP>"`.
3. Creates passwordless sudo for that user: writes `/etc/sudoers.d/90-airlock-<session-id>` containing `<user> ALL=(ALL) NOPASSWD:ALL`, validates it with `visudo -cf` before installing it with mode 0440 (a broken sudoers file never lands). The sudo password goes to `sudo -S` on stdin once, to create the file.
4. Verifies from the outside with the new key: `ssh -i <key> user@host 'sudo -n true'` must succeed. Reports `ready` or the failure reason in the UI.

Tools (exposed to the controller, and to the agent for nodes of its own session only)

| Tool | Behaviour |
|---|---|
| `nodes.enable_access(name, ttl?)` | steps above; idempotent; default TTL = session lifetime, max configurable (for example 8 h) |
| `nodes.access_status(name?)` | enabled / expires / last verified for the session's nodes |
| `nodes.revoke_access(name?)` | removes the authorized_keys line(s) and the sudoers drop-in carrying this session's marker |

The agent receives only the per-session private key (mounted read-only in the agent container, unique per session), never the password. Enabling is normally done automatically for all session nodes at session start; the tools exist so the agent can re-enable a node after a reboot wiped `/etc/sudoers.d` or the key.

Safety rules

- Only nodes bound to the session are touched. The request names a node from the session's list, not a host or an address.
- Passwordless sudo is a deliberate escalation: it is installed on every node of a Sandbox session, with the login `USER_NAME` / `USER_PASSWORD` (required: the session refuses to start without them; there is no per-node `bootstrap` option and no key-only mode). The rule is validated with `visudo`, expires with the session (default TTL 8h) and is removed at session end. Production environments (Mode 2) never use this MCP.
- Cleanup is mandatory: on session stop, on TTL expiry, and by a sweeper at controller start that finds `airlock:` markers whose session no longer exists. Revocation failures (node unreachable) are shown in the UI as "needs cleanup" with a retry button and are retried until they succeed or the node is removed.
- Every action is audited with node, session, user and the marker, never the password.
- The node access MCP container is not reachable from the agent except through the controller-brokered MCP endpoint, and its environment is not visible to the agent.

Config (per node, section 7.3)

```yaml
nodes:
  - name: JohnTestApi
    host: 10.0.1.11
    exec: {mode: ssh_sudo}
```

## 7. Mode 2 detail: environments

An environment bundles connectivity, tool servers and policy.

```yaml
name: uat
kind: kubernetes
kube_context: uat            # used by exec mode "direct"; checked with: kubectl --context uat get ns
exec:                        # how CLI-style tools run: direct | ssh | ssh_sudo (section 7.2)
  mode: ssh_sudo
  host: uat-bastion.example.com
secrets_dir: ~/.airlock/secrets/uat
tools:
  - postgres:   {dsn_env: PG_DSN,        mode: read}
  - elastic:    {url_env: ES_URL,        mode: read}
  - redis:      {url_env: REDIS_URL,     mode: read}
  - kubernetes: {context: uat,           mode: read, namespaces: [app, gateway]}
  - remote_ops: {hosts: [JohnTestApi],   operations: [disk_usage, journal_tail]}   # named operations only; MCP uses ssh internally
  - airflow:    {url_env: AIRFLOW_URL,   mode: read}
  - disk:       {mounts: [/data/logs],   mode: read}
  - django:                                       # v1 database access: scripts run in the application container (section 7.7)
      target: {namespace: app, workload: deploy/backend}
      shell: django                               # django (manage.py shell) | python
      scripts: [product_count, orders_trail]
approvals: {mutating: ask}
```

Environments are listed in the `PROD` tab (section 9.3). Local kubectl contexts are discovered automatically and shown as candidate environments; saving one (or adding one by hand) makes it a registered environment.

"Add environment" flow in UI:

1. Pick the execution mode (direct, ssh, ssh+sudo). For direct, paste or pick a kube context and the controller runs `kubectl --context X get ns` as a validity check (on the host, not in the agent). For ssh and ssh+sudo, enter the host and the controller runs `ssh host kubectl get ns` (with `sudo` if chosen) as the check.
2. Pick tool servers; fill the secret names (values are entered in a masked field and written to the secrets dir, or referenced from an existing store).
3. Choose mode per tool (read, read+approve-writes). Mutating off by default.
4. Save; "Start session" launches N agent containers wired to this environment's gateway.

Session start: controller creates the internal network, starts the MCP gateway with a fresh token, starts the tool server containers for the environment (or reuses shared ones), starts agent container(s) with env `MCP_URL` and `MCP_TOKEN` only.

Per-tool policy (examples)

- postgres: connection opened with `default_transaction_read_only=on`, `statement_timeout`, row cap; SQL parsed (pglast) and only `SELECT`/`EXPLAIN` on an allowlist of schemas; functions with side effects denied. Plus named tools (`list_schemas`, `list_tables`, `table_stats`, `slow_queries`). Recommended: also use a read-only DB role when one exists.
  In v1 the default route to a database that an application already uses is the Python or Django shell of that application's container (section 7.7): the database credentials stay in the application, the gateway needs no database address, and SQL patterns run through it. The direct `postgres` connection above stays available for stores the gateway can reach itself.
- elastic: search / count / mapping / `_cat` endpoints only, via a fixed request builder; index patterns allowlisted; no `_delete_by_query`, no scripts.
- redis: `SCAN`, `GET`, `TTL`, `TYPE`, `HGETALL` with size caps; command allowlist, not blocklist.
- kubernetes: `get`, `describe`, `logs`, `top`, events; secrets resource denied; exec denied by default.
- kubectl_commands: predefined kubectl commands, the only kubectl the agent gets besides the fixed read tools. Each command is defined in the config (name, fixed argv without the binary, typed `{{ name:type }}` parameters, `risk`) and becomes the MCP tool `kubectl.<name>`. The agent supplies parameter values only, never a verb, flag or command line. Refused when the config loads: write verbs not marked `risk: write`; `exec` without `allow_exec: true`, without `--`, or running a shell; flags that change identity, target or interactivity (`--token`, `--context`, `-f`, `-it`, ...); free-string parameters inside an `exec` (they need an enum or a regex). Write commands also need the tool's `mode: approve_writes` and a human approval per call. The execution mode (7.2) is applied after this check.
- remote_ops: the agent cannot get a shell. Remote host work is exposed only as named operations (section 6.2) with fixed commands and typed parameters; the MCP runs them over ssh or ssh+sudo (section 7.2). No free command string, no shell metacharacters.
- airflow: read-only REST API (DAG list, DAG run status and history, task instance status, task logs with size cap and range); no trigger, clear or pause.
- disk: listing and reading within configured roots, resolved path must stay inside root (symlink safe), size cap.
- django (and python): v1 relies on the Python shell and the Django shell inside the application's container to implement the API the agent can use (section 7.7). The agent never writes code: it calls a named script that an administrator defined and reviewed, and supplies typed values. A free shell tool (`django.shell`, taking the agent's own code) does not exist; it would be a mutating tool, off by default, with approval for every call, and is not part of v1.

### 7.1 Query patterns (managed in the UI)

Free-form queries are never accepted from the agent. A query is accepted only if it is an instance of an enabled pattern. Patterns are data, created and edited in the UI, and take effect on save.

Pattern fields

| Field | Meaning |
|---|---|
| `name` | unique, becomes the tool name `sql.<name>`, `es.<name>`, `redis.<name>` |
| `kind` | `sql`, `elasticsearch`, `redis` |
| `description` | shown to the agent in `tools/list`, so write it for the model |
| `template` | the query with typed placeholders `{{ name:type }}`; types `int`, `float`, `str`, `enum(a,b)`, `ts`, `list[int]`, `list[str]` |
| `params` | per placeholder: type, default, min/max, allowed values or regex, max length |
| `scope` | `global` or a list of environments |
| `risk` | `read` (default) or `write`; write patterns need approval (section 7, approvals) |
| `limits` | row cap, timeout, max result bytes, ES `size` cap, Redis scan count cap |
| `enabled` | on/off without deleting |
| `version`, `updated_at`, `updated_by` | every save creates a new immutable version |

Examples

```yaml
- name: orders_by_status
  kind: sql
  description: Count orders per status created in the last N hours
  template: >
    select status, count(*) from orders
    where created_at > now() - make_interval(hours => {{ hours:int }})
    group by status
  params: {hours: {min: 1, max: 168, default: 6}}
  limits: {rows: 100, timeout_s: 10}

- name: events_for_order
  kind: elasticsearch
  description: Events for one order id in the last day
  template:
    index: "events-*"
    body: {query: {bool: {filter: [{term: {order_id: "{{ order_id:str }}"}}, {range: {ts: {gte: "now-1d"}}}]}}, size: "{{ size:int }}"}
  params: {size: {max: 200, default: 50}}

- name: session_hash
  kind: redis
  description: Read one session hash
  template: "HGETALL session:{{ id:str }}"
  params: {id: {regex: "^[A-Za-z0-9_-]{1,64}$"}}
```

How the agent uses a pattern

1. Actual queries (primary). The agent sends real queries through `sql.query`, `es.search` or `redis.command`, written the way it would write them. The gateway parses the query, replaces literals in placeholder positions with parameters and compares the result with every enabled pattern for the environment:
   - SQL: parsed with pglast, normalised AST compared; placeholders may stand only where a literal is allowed.
   - ES: JSON structure compared key by key; only placeholder positions may differ.
   - Redis: tokenised; command name and fixed tokens must match exactly.
   A match is run through the binding path below. No match is rejected with an error that lists the closest patterns (name, description, template) so the agent can fix its query.
2. Named call (optional). Each enabled pattern is also an MCP tool with a typed input schema generated from `params`, for example `sql.orders_by_status(hours=6)`. The gateway binds the values: SQL through bound parameters (never string concatenation), ES by substituting into the JSON tree (never into a string), Redis as separate arguments (never one command string).
3. Discovery: `query.list(kind?)` returns every supported query: the enabled patterns with name, description, template and parameter schema (and examples). The agent is told in its tool description to call it first, so it knows what the MCP will accept. The list is generated from the current patterns, so a pattern added or removed in the UI shows up on the next call.
4. Proposal: `query.propose(kind, template, description)` stores a disabled pattern marked `proposed by agent`. It does nothing until a human enables it in the UI. The agent cannot enable, edit or delete patterns.

Validation on save (UI and API)

- SQL: must parse; only `SELECT`, `EXPLAIN` and `WITH ... SELECT` for `read`; no data-modifying CTEs; schema/table allowlist from the environment; denied functions (`pg_sleep`, `dblink`, `lo_*`, `set_config`, and so on); placeholders only in literal positions.
- ES: allowed endpoints only (`_search`, `_count`, `_mapping`, `_cat/*`); no script fields, no `_delete_by_query`/`_update_by_query`; index pattern allowlist; `size` capped.
- Redis: command must be on the read-only allowlist (`GET`, `MGET`, `HGET`, `HGETALL`, `HMGET`, `LRANGE`, `SMEMBERS`, `ZRANGE`, `TTL`, `TYPE`, `SCAN`, `EXISTS`, `STRLEN`, ...) for `read`; `KEYS`, `FLUSH*`, `DEL`, `EVAL`, `CONFIG` always denied; key prefix allowlist.
- A pattern that fails validation cannot be saved; the UI shows the reason.
- Preview before save: "Test" button runs the pattern against the selected environment with sample values, shows the bound statement, `EXPLAIN` for SQL, row count and the first rows. Test runs go through the same gateway path and are audited.

UI (page "Query patterns", section 9)

- List with filters by kind, environment, enabled, proposed-by-agent.
- Add / edit form: kind, name, description, template editor with syntax highlighting and live placeholder detection that generates the parameter table; scope, risk, limits; enable toggle.
- Remove: deletes the pattern (history is kept in audit); disable is the soft option.
- Edit: saves a new version; tool calls in the audit log reference `pattern@version`.
- Pending proposals queue with approve / edit / reject.
- Import and export as YAML, so pattern sets live in git and can be reused across environments.

Gateway behaviour

- Patterns are stored in SQLite and cached by the gateway; a save emits a change event and the gateway reloads that environment's pattern set in under a second. The agent sees new tools after its next `tools/list` (MCP `notifications/tools/list_changed` is sent to attached agents).
- Disabled or removed patterns are rejected on the next call, including calls already in flight in that session.
- Pattern matching happens only in the gateway; the agent container never receives pattern internals beyond the schema and description.

### 7.2 Command execution modes: direct, ssh, ssh+sudo

Many setups reach Kubernetes (or Docker, journald, and so on) in different ways: kubectl is installed and configured where the MCP runs, or only on a bastion/node, or only for root there. Instead of hard-coding one way, every CLI-style target has an execution mode, chosen in the UI per EC2 node, per production environment, and optionally per tool (for example `kubernetes` through `ssh_sudo` while `postgres` stays direct).

| Mode | What is run | Typical case |
|---|---|---|
| `direct` | `kubectl --context uat get ns` on the machine running the MCP/agent | kubeconfig available locally |
| `ssh` | `ssh user@host kubectl get ns` | kubectl and kubeconfig of that user on the host |
| `ssh_sudo` | `ssh user@host sudo kubectl get ns` | kubectl or kubeconfig only available to root (for example k3s, or a locked-down node) |

Config:

```yaml
exec:
  mode: ssh_sudo            # direct | ssh | ssh_sudo
  host: uat-bastion.example.com
  port: 22
  user: ${USER_NAME}
  auth: password            # password (USER_PASSWORD) | key
  sudo_password: ${USER_PASSWORD}
  kubectl_path: /usr/local/bin/kubectl
  kubeconfig: /etc/rancher/k3s/k3s.yaml   # optional, passed as --kubeconfig remotely
  host_key: "ssh-ed25519 AAAA..."          # pinned; connection refused if it differs
```

Per-tool override in an environment:

```yaml
tools:
  - kubernetes: {mode: read, exec: {mode: ssh_sudo, host: uat-bastion.example.com}}
  - postgres:   {mode: read}        # connects directly; exec not used
```

How the commands adapt

1. Tools build commands as an argv list (`["kubectl", "get", "pods", "-n", "app"]`), never as shell strings. Policy (verb allowlist, namespaces, denied resources) is evaluated on this argv before any wrapping, so changing the mode never widens what is permitted.
2. A runner turns the argv into the final command:
   - `direct`: argv with `--context <ctx>` added (and `--kubeconfig` if set).
   - `ssh`: `ssh -o BatchMode=no -o StrictHostKeyChecking=yes user@host -- <shlex.join(argv)>`; `--context` is dropped because the remote kubeconfig applies, `--kubeconfig` is added if configured.
   - `ssh_sudo`: same as `ssh` with `sudo -S -p '' ` before the argv; the sudo password is written to the remote stdin, never put on a command line or in a file.
3. Every argument is quoted with `shlex.quote` for the remote shell; arguments containing newlines or NUL bytes are rejected. The remote command is exactly the one binary and its arguments.
4. Output handling is identical in all modes (size cap, timeout, redaction, audit). The audit record stores the mode and host, and the argv (not the password).
5. The same runner executes operations (section 6.2): the operation `run` script is passed through the node's mode, so `docker system prune` works as `ssh host sudo ...` if the node is configured that way.

Mode 1 (Sandbox) adaptation

The agent is free, so it is helped rather than restricted:

- The agent image contains `airlock-run <node> -- <command...>`, which applies the node's execution mode; the agent can also use the `exec.run` and `ops.run` MCP tools.
- For every session the controller generates a short instruction file in the workspace (for example `AIRLOCK_NODES.md`, referenced from the session's CLAUDE.md) listing each node and the exact way to run commands on it: "JaneTestGateway: use `airlock-run JaneTestGateway -- kubectl get ns` (ssh+sudo)". Changing the mode in the UI regenerates the file for running sessions.
- After the node access MCP has enabled a node (section 6.3), the agent can run raw `ssh <user>@<host>` and `sudo ...` without passwords; `airlock-run` is a convenience that applies the node's mode and logging. For a node set to `ssh_sudo`, the sudo password is not needed because sudo is passwordless (`sudo -n`).

Mode 2 (Gateway) adaptation

The MCP tool code calls the runner; the agent only sees the same tool schema (`kubernetes.get`, `kubernetes.logs`, ...) regardless of the mode. Switching an environment from `direct` to `ssh_sudo` in the UI needs no change in the agent, prompts or tools. The runner and the credentials live in the MCP container; the agent container cannot reach the host.

Recommended hardening for ssh and ssh+sudo: a sudoers rule limited to the kubectl binary (`user ALL=(root) NOPASSWD: /usr/local/bin/kubectl`), a dedicated low-privilege user, and pinned host keys. AirlockAI does not require NOPASSWD; with `sudo_password` it sends the password on stdin.

### 7.3 Shared configuration file

The whole setup is described by one config file, YAML or JSON (selected by extension), so it can be committed, reviewed and shared. Default path `~/.airlock/airlock.yaml`, overridable with `--config` or `AIRLOCK_CONFIG`.

```yaml
version: 1
include:                      # optional split into several files
  - patterns/*.yaml
defaults:
  exec: {mode: ssh, user: ${USER_NAME}, auth: password}
  egress: {model_api: [api.anthropic.com]}
  links:                      # link patterns for the UI node rows; {instance_id} is the EC2 id (7.3 rules)
    web:  "https://web-{instance_id}.dev.example.com/"
    docs: "https://docs-{instance_id}.dev.example.com/"
    ssh:  "ssh://{user}@{instance_id}.example.com"
nodes:
  - {name: JohnTestApi,     host: 10.0.1.11,     exec: {mode: ssh}}
  - {name: JaneTestGateway, host: 10.0.1.12, exec: {mode: ssh_sudo}}
  - {name: BobTestOrders,   host: 10.0.1.13,  exec: {mode: ssh}}
operations: [ ... see 6.2 ... ]
environments: [ ... see 7 ... ]
query_patterns: [ ... see 7.1 ... ]
```

Rules

- Secrets are never in the file. Only references: `${USER_NAME}`, `${USER_PASSWORD}`, `${PG_DSN}` (environment variables) or `secret:<name>` (a secrets backend entry). The loader refuses a file that contains a literal value in a field known to hold a secret, and `airlock config export` scans its output for secret-like strings and for the current values of the known secret variables before writing.
- Versioned schema (`version`), JSON Schema published for editor validation. Unknown keys are errors.
- `airlock config validate` checks syntax, schema, references (every `${VAR}` must be defined at start, otherwise a clear message), pattern validity (section 7.1) and host key format.
- UI: Export (whole config or selected sections), Import with a diff preview (added / changed / removed objects) and a choice per object, Reload on file change. Edits made in the UI are written back to the file, so the file stays the source of truth for nodes, operations, environments and query patterns. Runtime state (sessions, tool calls, approvals, audit) stays in SQLite and is never part of the shared file.
- Link patterns: `defaults.links` maps a link name to a URL template (schemes http, https, ssh) with the placeholders `{instance_id}`, `{name}`, `{host}`, `{user}`, `{port}`. `{instance_id}` is the node's `instance_id`, else its `aws_instance_id` tag, else an `i-...` id found in the host or name. A node with no value for a placeholder gets no such link. A node's own `urls:` entries override a pattern of the same name and may use the same placeholders. Unknown placeholders are errors. The computed links are never written back to the file or exported.
- Template: `airlock.example.yaml` is a commented starting point that is kept valid by a test.
- Sharing: commit the file to git; each user supplies their own `USER_NAME`, `USER_PASSWORD` and other secrets locally. `node` and `environment` entries may be marked `local: true` to be kept out of exports (for example a personal sandbox).

### 7.4 Credentials from the environment: USER_NAME and USER_PASSWORD

AirlockAI assumes these two variables exist in the environment of the controller:

- `USER_NAME`: login on nodes and hosts (used for SSH and as the sudo user).
- `USER_PASSWORD`: SSH password and sudo password where `auth: password` or `sudo_password` is configured.

Handling

- The controller refuses to start a session that needs them if they are unset, and says which node or environment required them. Values are never logged, never written to the config, SQLite, audit log or the UI (the UI shows "set" / "missing").
- Mode 2: the variables are passed only to the MCP/tool containers of that environment (as env vars or a tmpfs file), never to the agent container. SSH password authentication uses `SSH_ASKPASS` with a helper that reads the variable, or `sshpass -e`; the password never appears in argv or in `ps`. The sudo password goes through stdin.
- Mode 1: the node access MCP (section 6.3) is the only component that uses the password. It runs in its own container with `USER_NAME` / `USER_PASSWORD`, installs the session key and a passwordless sudo rule on the test nodes, and the agent works with the key from then on. The agent container does not get `USER_PASSWORD`. An explicit per-session escape hatch `inject_credentials: true` (default false) puts both variables into the agent environment, for nodes where key setup is impossible (for example SSH keys disabled).
- The audit and output redaction treat the current value of `USER_PASSWORD` as a secret and mask it if it ever appears in a tool result or log line.
- Keys are supported as an alternative (`auth: key`, key file or ssh-agent socket on the controller side), and are preferred; the password path exists because it is the stated setup.

### 7.5 Airflow, Slack and Jira tools (both modes)

These tools are part of the MCP gateway and are available in Mode 1 and Mode 2, so the agent can read context without any network access of its own.

Airflow (Mode 2 environments, optionally Mode 1)

- `airflow.dags(filter?)`, `airflow.dag_runs(dag_id, state?, since?)`, `airflow.run_status(dag_id, run_id)`, `airflow.task_instances(dag_id, run_id)`, `airflow.task_log(dag_id, run_id, task_id, try, tail_lines?)`.
- Read only; log output size-capped and redacted; no trigger, clear, pause or variable access.

Slack (read and search only)

- `slack.search(query, in?, from?, after?, before?)`, `slack.read_channel(channel, limit?, oldest?)`, `slack.read_thread(channel, ts)`, `slack.permalink_resolve(url)` (so an alert link pasted in the prompt can be opened).
- Login: `airlock auth slack` opens the browser once (OAuth with the workspace SSO, for example Google), and the resulting token is stored in `~/.airlock/tokens/slack.json` (mode 0600, mounted only into the Slack MCP container, refreshed automatically). `SLACK_TOKEN` in the environment is a fallback. The token is never in the agent container. No posting, reacting, file upload or channel changes.
- Channel allowlist in the config (`slack: {channels: [...], deny_dm: true}`), because search can otherwise reach private conversations.

Jira (read and search only)

- `jira.search(jql)`, `jira.get_issue(key, include: comments, attachments_meta, links)`, `jira.get_attachment(key, name)` (text and images, size-capped), `jira.list_comments(key)`.
- Login: `airlock auth jira` does the same browser login once (Atlassian OAuth) and stores the token in `~/.airlock/tokens/jira.json`; `JIRA_URL` / `JIRA_USER` / `JIRA_API_TOKEN` are a fallback. Held by the MCP container only. No create, edit, transition or comment.
- `jira.get_issue` returns description, all comments and attachments by default, so the agent does not stop at the description.

Policy common to both

- Treated as untrusted input: Slack messages and Jira text can contain prompt injection. Results are wrapped as quoted data with the source, and these tools can never trigger a mutating call without approval.
- Result caps (items, bytes), redaction of known secret formats, audit of each call.
- Config (section 7.3):

```yaml
integrations:
  slack: {auth: browser, channels: [alerts, incidents], deny_dm: true}
  jira:  {auth: browser, url: https://example.atlassian.net, projects: [OPS, DEV]}
```

### 7.6 Anonymizing results

The gateway can transform what it returns before the agent sees it, where the configuration asks for it. Rules are data, applied by code, and decided only by the tool, the pattern, the column or key, and the value format; never by judging the content with a model.

Where rules are set: per environment (`anonymize:` default), per query pattern (`anonymize:` on the pattern, which wins over the environment), per predefined kubectl command, and per tool group. Each rule has a name, so the audit can say which ran.

```yaml
environments:
  - name: prod
    anonymize:
      mode: strict                 # off | best_effort | strict
      salt: per_session            # per_session | per_environment | none
      rules:
        - {name: customer_email, match: {column: "email|.*_email"}, action: hash}
        - {name: account_no,     match: {column: "account(_no|_number)?"}, action: mask, keep_last: 4}
        - {name: names,          match: {column: "(first|last|full)_name"}, action: replace, with: "person-{n}"}
        - {name: free_text,      match: {value_regex: "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+"}, action: redact}
        - {name: ips,            match: {value_regex: "\\b\\d{1,3}(\\.\\d{1,3}){3}\\b"}, action: mask}
        - {name: balances,       match: {column: "balance|amount"}, action: bucket, step: 1000}
        - {name: secrets,        match: {column: ".*(password|token|secret|key).*"}, action: drop}
query_patterns:
  - name: orders_by_status
    anonymize: {mode: off}         # aggregate counts only: nothing personal in the result
```

Actions, all deterministic:

| Action | Result | Property |
|---|---|---|
| `hash` | a short keyed hash (HMAC with the salt) | the same input gives the same token inside the salt's scope, so the agent can still join, group and count |
| `replace` | `person-1`, `person-2`, ... in order of first appearance in this session | stable inside a session; the mapping is kept by the gateway and never returned |
| `mask` | `****1234`, with `keep_first` / `keep_last` | shape and length are kept |
| `bucket` | numbers rounded to a step, dates truncated to a unit | keeps magnitude, drops precision |
| `redact` | `[redacted:<rule>]` | the value is gone |
| `drop` | the column or key is removed from the result | the agent cannot see that it existed, except in the audit |

How matching works: SQL results by column name and by value format; Elasticsearch by field path (including inside `_source`) and value format; Redis by key pattern and hash field; kubectl output and log lines by value format only (they have no schema), for example e-mail addresses, IPs, tokens. Parameters that the agent sends in (a customer id in a `WHERE`) are not anonymized; the rules transform what comes back.

Modes:

- `off`: nothing is changed beyond the existing secret redaction (known secret values and formats).
- `best_effort`: the rules run; anything not covered is returned as is.
- `strict`: a result is returned only if every column or field of it is covered by a rule that says how to treat it (`keep` is a rule too). A column that no rule covers makes the call fail with the name of the column, so a new sensitive column added to a table cannot leak because someone forgot to list it. Value-format rules still run on the kept columns.

Safety properties:

- The salt for `per_session` is generated by the controller for each session and never leaves the gateway; it is not recoverable by the agent. `none` makes hashes comparable across sessions and is meant for lookups the human also does.
- Anonymization runs before the size cap and before the audit preview, so the audit log and the transcript hold the same anonymized values the agent saw. The audit also lists the rule names and counts per call, never the original values.
- Re-identification by the agent is limited, not eliminated: small result sets, `hash` of low-entropy values and joins against known data can still reveal identities. A pattern that returns individual rows from a table with personal data should use `strict`, and `bucket` or aggregates where the question allows it.
- A human reading the UI's test run sees the anonymized result by default, with an explicit control to view the original (audited).
- Rules are validated on save like patterns (the regexes compile, the actions are known, `strict` has a rule for every column of the pattern's result where that is knowable); `airlock test` includes fixtures that must come out anonymized.

### 7.7 Application shell execution (v1 database access)

In v1 the gateway implements the database-facing part of the agent's API with the Python shell and the Django shell of the application container, instead of holding database credentials and a network path of its own. The application already has the connections, the models and the settings; the gateway only asks it to run a fixed script.

```
agent --MCP tool call (typed values)--> gateway --kubectl exec -i (identity of 4.1)--> pod: python manage.py shell
                                                   stdin: fixed preamble + the administrator's script + base64 JSON params
agent <--anonymized, capped JSON result-- gateway <--stdout (JSON)-----------------------
```

What the agent can call: only what the configuration lists.

1. Named scripts. An administrator defines each in the configuration (reviewed in git like any code): a name, a description for the model, typed parameters (the placeholder types of 7.1), a `shell` (`django` runs `manage.py shell`, `python` runs the interpreter without Django) and the code. A script is exposed as the MCP tool `django.<name>` or `python.<name>`. Scripts that live in the application repository as management commands are called the same way (`python manage.py <command> --arg {{ name:type }}`, through `kubectl_commands`), and are preferred for anything non-trivial because they are reviewed and tested with the application.
2. SQL patterns. A pattern of 7.1 is matched and validated in the gateway exactly as before. It is then executed by a fixed runner in the pod: `cursor.execute(sql, params)` on the application's database connection, with the SQL text and the bound values sent as data (JSON on stdin), never spliced into code. The same applies to the Elasticsearch and Redis clients the application holds.

How the code is protected, deterministically:

- The code that runs is always administrator-written text from the configuration or the application repository. The agent's values reach it only as a base64-encoded JSON blob that a fixed preamble decodes into a `params` dictionary after the gateway has validated every value against its type, enum or regex. No parameter is concatenated into code or into a command line.
- The preamble opens a database transaction, runs `SET TRANSACTION READ ONLY` and always rolls back at the end, so a script (or an ORM call in it) cannot write; a write script must be declared `risk: write`, needs the tool's `mode: approve_writes` and a human approval per call, and is then allowed to commit.
- Limits are applied by the gateway around the call: timeout (the `kubectl exec` is killed), output size, row count when the script returns rows, and the anonymization rules of 7.6 on the returned JSON.
- Scripts are validated when the configuration loads: parameters declared and typed, no shell-out helpers (`os.system`, `subprocess`) unless the script is marked `risk: write`, a syntax check with `compile()`, a name that does not collide with another tool.
- Each call is audited with the script name and version (git hash of the config), the typed values, the target pod, the exit code and the byte count; never the decoded environment of the pod.

Costs and constraints to state plainly:

- Every call starts a Python process in a running application pod. That uses its memory and CPU, so scripts are meant to be short, and the target should be a pod that is not on the trading path (a worker or a dedicated `airlock` deployment of the same image with no traffic is better than a front-end pod).
- It needs `pods/exec` on that namespace for the gateway's identity; the cluster audit logs the `exec` and its command line, which is why parameters travel on stdin and secrets never appear in arguments.
- The application's database login is normally read-write. The read-only transaction and the review of scripts are the safeguards; a read-only role or a standby connection for the Django alias is still recommended as defense in depth.
- Python in the pod is as trusted as the image: this route relies on the image the application ships, so a new application version can change what a script sees. Scripts therefore pin the application image version they were tested with and the gateway refuses to run them against another unless told to.

Configuration:

```yaml
- django:
    target: {namespace: app, workload: deploy/backend, container: backend}
    shell: django
    mode: read
    scripts:
      - name: product_count
        description: Number of active products of one category
        params: {kind: {type: "enum(Book,Video)"}}
        code: |
          from api.models import Product
          print(json.dumps({"count": Product.objects.filter(active=True, category=params["kind"]).count()}))
```

## 8. Tool authoring SDK

The user adds capability by writing a Python function. Same file defines schema, risk and policy.

```python
from airlock import tool, Risk, Env

@tool(risk=Risk.READ, timeout=20, max_output_bytes=64_000)
def table_stats(env: Env, schema: str, table: str) -> dict:
    """Row estimates and last analyze time for a table."""
    with env.postgres() as cur:
        cur.execute(
            "select reltuples::bigint, last_analyze from pg_stat_all_tables "
            "join pg_class on relname = %s where schemaname = %s",
            (table, schema),
        )
        return cur.fetchone()
```

Rules enforced by the framework:

- Every tool declares `risk` (`READ`, `WRITE`, `DESTRUCTIVE`). Missing risk means the tool does not load.
- `env` gives access to connections built from secrets the agent never sees; tool code cannot return the connection string (output scanner redacts known secret values and common patterns).
- Hot reload: file watcher reloads the module in the tool server; no agent restart (the agent calls `tools/list` again).
- Tests: a `airlock test` command runs each tool against a recorded fixture and runs the policy self-checks (e.g. attempt `DROP` through the SQL tool must fail).
- Tool code lives in a separate git repo (`airlock-tools`) mounted into MCP containers only. Never in the agent workspace.

## 9. Web UI

Single page app served by the controller (FastAPI + HTMX/Alpine to stay small; React only if needed). Dark/light. Binds to 127.0.0.1 only and has no authentication in v1; no remote exposure.

### 9.1 Layout: two tabs on the left, EC2 and PROD

The two modes are never mixed on one screen. A vertical tab strip on the left edge of the window has two tabs, labelled exactly `EC2` and `PROD`. The selected tab decides what the main area shows. The last selected tab is remembered in the browser.

| Tab | Mode | Targets listed | Agent sessions started from it |
|---|---|---|---|
| `EC2` | Mode 1, Sandbox (section 4) | EC2 test nodes (section 6.1) | Sandbox sessions with SSH access to the selected nodes |
| `PROD` | Mode 2, Gateway (section 4) | Kubernetes clusters (kube contexts) available to the local `kubectl` on the controller host (section 7) | Gateway sessions whose only access to the cluster is through the MCP gateway |

An agent session that reaches a production environment through MCP always lives in the `PROD` tab and never in `EC2`, so a Sandbox session and a production session cannot be confused or selected together. Each tab has its own session list, own bulk actions and own "Remove all stopped". The tab strip shows a count of running sessions as a badge on each tab, and the `PROD` tab uses a distinct accent colour.

### 9.2 `EC2` tab (what the UI shows today)

One page, in this order:

1. Nodes table. Columns: name (click to rename), status (reachable / down, IP, load over 1 minute against core count, storage used with sizes), links (`web`, `docs`, `ssh`, from `defaults.links`, section 7.3), session (`Start` button), exec (execution mode selector: direct / ssh / ssh+sudo), labels (editable, with `Save`). The description line under the name shows the origin, for example `imported from AWS: <instance name> (stopped), matched tag Name`, or the build, branch and kube namespace notes. A row checkbox selects the node.
2. Bulk bar for the selected nodes: a drop list of commands (`Start session on selected`, `AWS: start instances`, `AWS: stop instances`, `AWS: reboot instances`, `Delete from config`) and an `Apply` button. A stuck session has `Force discard`.
3. `Add node` and `Import my AWS instances` (section 6.1).
4. `Claude sign-in for sandbox sessions`: shows whether automatic sign-in is on (token saved in `~/.airlock/secrets`), so new sessions start signed in, with `Remove token`.
5. Sessions list (Sandbox only): `Stop selected`, `Delete selected`, `Remove all stopped`, last updated time, and per session "attach" (xterm.js terminal over websocket to `docker exec` in the agent container) with a side panel of live operations.
6. Operations, node access status (section 6.3) and history for these nodes.

### 9.3 `PROD` tab

The same page structure as `EC2`, with the target type swapped from EC2 nodes to Kubernetes clusters:

1. Clusters table instead of the nodes table. The list is built from the local kubectl: the contexts of `kubectl config get-contexts` (honouring `KUBECONFIG`), plus any `environment` entries of the config file (section 7) that name a `kube_context`. No cluster is invented: a context that exists locally appears with no further setup. Columns: name (the environment name, click to rename an alias; the context name stays visible), status (reachable / down from a read-only `kubectl --context X get ns`, server version, node count, API latency), links (patterns from `defaults.links` with placeholders for the cluster, such as `{context}`), session (`Start` button, creates a Gateway session), exec (execution mode: direct / ssh / ssh+sudo, section 7.2; `direct` by default for local contexts), tools (the tool servers enabled for this environment with mode read or read+approve-writes, section 7), tags and labels (editable, `Save`). Status checks and the exec mode apply per cluster.
2. Bulk bar for the selected clusters: `Start session on selected`, `Remove from list` (only unregisters an environment from the config; it never touches the cluster or the local kubeconfig).
3. `Add environment` (the wizard of section 7) and `Rescan local kubectl contexts`. There is no AWS import in this tab.
4. Secret status per environment (present / missing, never the value) and a Claude sign-in block identical to `EC2` (the model login is shared, section 4).
5. Sessions list (Gateway only): `Stop selected`, `Delete selected`, `Remove all stopped`, with the environment, the MCP gateway state and the tools exposed. "Attach" opens the terminal for the agent container, and the side panel shows live MCP tool calls.
6. Approvals (section 9.4 item 5) for the environments listed here, query patterns and audit scoped to the selected environment.

Differences that matter in the `PROD` tab: no passwordless-sudo node access (section 6.3 never applies), no SSH key is handed to the agent, mutating tools default to off, and the agent in the session can only call MCP tools. Starting a session on several clusters at once is allowed; each gets its own gateway token and audit trail.

### 9.3a Session names and ssh into the agent

- Click a session id in the session list to give it a name (or edit or clear it). The name is also the ssh host name, and appears in `airlock session list`; `airlock session name ID NAME` does the same.
- Every agent image runs an unprivileged `sshd` per connection (no listening port, no published port): the generated `~/.airlock/ssh_config` has `ProxyCommand docker exec -i air-agent-<id> /usr/sbin/sshd -i ...`, so only someone who can run docker on the controller host can connect. The Actions column shows the command to copy: `ssh <name or id>` (or `ssh -F ~/.airlock/ssh_config <name>` until `airlock ssh setup` has added the `Include` line to `~/.ssh/config`).
- The login user is `agent`, not `root`: the container runs with all capabilities dropped as an unprivileged user, so `ssh root@<name>` is not possible by design. The shell starts in `/workspace` with the session's proxy and MCP variables (read from PID 1 at login, never written to a file).
- The Mode 2 image contains `sshd` but no ssh client binaries, so the "no ssh in the agent" rule of section 4 still holds.

### 9.4 Other pages

In v1 these live inside the tabs rather than as separate left-strip entries:

1. Operations: run from the `EC2` tab and through the `ops.*` MCP tools; in `PROD` only as named operations through `remote_ops` (section 7).
2. Environments: the `PROD` clusters table is the editor (rename, execution mode and host, tools with per-tool mode and settings, labels, masked secret entry, remove from list) plus the `Add environment` wizard of section 7.
3. Query patterns (`PROD` tab, section 7.1): list, add / edit / disable / remove, the pending proposals queue (approve or reject), YAML import and export. A save is validated first and is live in the gateway at once.
4. Approvals (`PROD` tab): pending mutating calls with arguments; approve / reject / approve-for-session. Also `airlock approvals`.
5. Audit: per session, `/audit/<session>` shows the hash-chained log and whether the chain is intact (linked from the session row).
6. Config: the file is edited in place by every UI action (comments preserved); `airlock config validate|export`, `airlock patterns import|export|sync`.
7. Settings: images are built with `airlock image [--gateway]`; the Claude sign-in block is shared between the tabs.

## 10. Data model (SQLite)

- `node(id, name, host, port, user, auth_ref, region, notes)`
- `node_label(node_id, label)`
- `operation(name, yaml, risk, updated_at)` (source of truth is the config file, section 7.3; DB is an index)
- `environment(name, kind, config_json)`
- `query_pattern(id, name, kind, scope_json, risk, enabled, proposed_by_agent, current_version)`
- `query_pattern_version(pattern_id, version, template, params_json, limits_json, description, updated_by, updated_at)`
- `session(id, mode, isolation, env_or_nodes, image, model, status, started_at, ended_at, token_hash)`
- `agent(id, session_id, container_id, workspace_path, initial_prompt)`
- `tool_call(id, session_id, agent_id, tool, args_json, status, risk, started_at, duration_ms, result_bytes, result_preview, approval_id, pattern_id, pattern_version)`
- `approval(id, tool_call_id, state, decided_by, decided_at)`
- `audit_event(ts, actor, kind, payload_json)`

Secret values are never stored in SQLite; only references.

## 11. Security model

Threats and controls

| Threat | Control |
|---|---|
| Agent reads production credentials | Never in its container, env, volume or network; separate containers for MCP; secrets dir not mounted into agent |
| Agent finds credentials in the MCP source | MCP code not in the agent workspace; tool containers not reachable except through the gateway |
| Agent connects directly to prod endpoints | Internal network without route; egress allowlist enforced in the gateway container, outside the agent's control |
| Agent exfiltrates data to the internet | Egress allowlist (model API only). Model API itself is an exfil channel, accepted and documented; output size caps and redaction reduce it |
| Prompt injection from logs or DB content makes agent call a destructive tool | Destructive tools off by default, approvals out of band in the UI, per-call limits |
| Agent escapes container | Non-root, no capabilities, no Docker socket, read-only rootfs; gVisor/microVM option for prod sessions |
| Agent attacks controller | Controller on host loopback; agent network has no route to the host; token auth |
| Tool bug allows write | Defense in depth: read-only transactions, read-only roles where available, tests that try forbidden operations |
| Wider access through ssh+sudo than intended | Policy evaluated on argv before wrapping; remote command is one binary plus quoted args; recommended sudoers rule limited to that binary; pinned host keys |
| `USER_PASSWORD` leaks to the agent or into files | Passed only to tool containers (Mode 2), via stdin / askpass, never argv; masked in outputs and logs; Mode 1 injection is opt-in per session |
| Passwordless sudo left behind on a node | Rules and keys carry a session marker and a TTL; removed at session end, on controller start (sweeper) and by `airlock nodes revoke`; refused on nodes not tagged as test |
| Agent grants itself access to a production host | The access MCP only touches nodes bound to the session, which the user selected; the request names a node from that list, never a host. Production environments use Mode 2 and never this MCP |
| Claude subscription token stolen from the agent container | Egress allowlist (model API only) limits where it can go; per-session credential copy; revoke by logging out that device; accepted residual risk |
| Prompt injection via Slack or Jira content | Read-only integrations, results wrapped as untrusted data, mutating tools require approval in the UI |
| Stale access on test nodes | Per-session keys with expiry (EC2 Instance Connect / SSM), removed at session end |

Audit: every gateway call is logged before execution (intent) and after (result); the log is append-only JSONL outside the agent's reach, hash-chained per session.

Audit record format: `{ts, node, ec2, actor, kind, payload, prev, hash}`. `node` (node name) and `ec2` (EC2 instance id) come right after `ts` on every record that concerns a node; they are strings, or lists for an operation on several hosts, and are omitted when the event has no node. Old records without them still verify.

### 11.1 Traceability of what leaves the agent (options, not yet decided)

Goal: for every shell command and outbound request of an agent, a record in the audit chain with timestamp, node name, EC2 id and session. Today the audit covers the controller and the gateway; the egress proxy (HTTP CONNECT, host:port allowlist) prints to its container's stdout only. All options below keep the agent network internal-only with the proxy as its sole exit; `HTTPS_PROXY` / `ALL_PROXY` set in the agent are a convenience, the network is the enforcement. In every option the audit file is written by the controller only (the proxy reports events to it over an authenticated channel; `Audit` is a single-writer chain), never by anything the agent can reach.

| # | Option | What is recorded | Pros | Cons |
|---|---|---|---|---|
| A | Log in the existing HTTP CONNECT proxy | Per connection: time, session, destination host:port mapped to node name and EC2 id (the allowlist is built from the nodes), bytes, allowed or denied | Smallest change; works for curl, the model API and ssh via `ProxyCommand nc -X connect`; hostnames visible for HTTPS (from CONNECT) | No URL path, headers or body; no DNS or UDP; tools that ignore the proxy env are simply blocked, not traced |
| B | SOCKS5 proxy as the single exit (replaces or sits next to A) | Same as A, plus every TCP destination, with remote DNS resolution (`socks5h`) | One choke point for http, ssh (`nc -X 5`) and anything honouring `ALL_PROXY`; DNS lookups are logged too, no DNS leak | New listener to write and test (stdlib only, in the proxy image); UDP ASSOCIATE should stay unsupported; still no payload; clients without SOCKS support need a shim |
| C | TLS-terminating proxy (mitmproxy or squid ssl-bump) | Full HTTP request line, headers, optionally bodies, per curl call | The only option that records "curl https://host/path"; can enforce path rules | Agent container must trust a private CA; pinned clients break; bodies carry secrets and need `redact()` before storage; a larger attack surface in the proxy; the model API stream is better left un-intercepted (exempt it) |
| D | nftables `log` / conntrack events on the gateway | One line per new connection (src, dst, port), any protocol | Catches non-proxy traffic and denied attempts that never reach the proxy; no client cooperation | No names, only IPs; needs correlation by container IP to session, node and EC2 id; kernel log plumbing |
| E | Shell command capture in the agent container: wrapper (`script`, bash `DEBUG` trap / `PROMPT_COMMAND`) | Each typed command with time and working directory | Simple; no kernel features | An agent that execs directly or edits its shell avoids it; a record of intent, not of what ran |
| F | `execve` tracing outside the agent (auditd, eBPF: Tetragon or Falco) | Every process started in the container, with argv, parent and session | Cannot be bypassed from inside; includes children of scripts (`curl` called by a script) | Needs host privileges and a kernel that supports it; noisy, needs filtering; argv only, not what the command did |
| G | Node-side logging on the EC2 nodes (sshd marker `airlock:<sid>:<expiry>`, auditd or sudo I/O logging) | What a session actually executed on the node, tied to the session by the key marker | Works even if the agent network is bypassed; ground truth on the node | Logs live on the node and must be collected; auditd rules to install and clean up; only covers nodes |

Combinations worth considering
- Minimum (low effort): A, plus D for denied non-proxy attempts. Answers "which node and EC2 instance did the agent talk to, and when".
- Recommended: B (one exit, DNS included) plus F (every command, unbypassable). Answers "what ran and where it connected".
- Full request visibility: add C for chosen hosts only (never the model API). Answers "which URL was requested".
- G is independent and complements any of the above for node-side forensics.

Constraints common to all options: the proxy cannot see commands run inside an ssh session (only that the connection happened), so command-level records for nodes come from F or G; recorded request data must pass through `redact()`; a record is written before the connection is allowed to proceed when the decision is an approval, after it otherwise.

Known residual risks (to state in the README): bypass mode means anything inside the agent container is fair game; the model API sees whatever the agent sees; a malicious tool author (the user) is out of scope.

## 12. Deployment, sharing and reuse

- Shared hosting (after v1): the controller and containers can run on a shared Ubuntu EC2 with a controller instance per user; a provisioning tool (Ansible/AWX, Terraform) only sets up the host. Per-user isolation is a user per controller plus separate Docker networks.

- Shared tools: the tool repo and environment definitions are the shareable unit (git repo of YAML and Python), while credentials stay per host.
- Session export: sessions are stored as transcript JSONL plus the tool_call log. A future `airlock export <session>` writes a manifest (session id, ticket, git SHA) that an artifact store can ingest. Out of scope here.
- Build vs reuse: reuse existing projects where they fit.

| Concern | Candidate to reuse | Decision |
|---|---|---|
| MCP routing, auth, OAuth to upstreams | agentgateway, Pomerium, Bifrost | evaluate for the gateway in v2; v1 has own thin gateway to keep policy in code |
| Postgres SQL safety | llm-sql-safety-executor-mcp ideas, centralmind gateway, hoop.dev wire proxy | borrow checks; hoop.dev as optional upstream for DB |
| Sandbox runtime | E2B (Firecracker, self-host), Docker Sandbox, Coder | microVM isolation level may use Docker Sandbox or Firecracker directly |
| Governance console | Docker AI Governance | not required; revisit once it is generally available |

### 12.1 Shared gateway requirements (M7)

The gateway is deployed by DevOps (Kubernetes manifests, Helm or Flux) and serves every agent. It holds powerful access to production on purpose: the agent never sees it, and every action it can take is a defined tool. Needed beyond v1:

1. Service identity. Each environment has its own identity for the gateway (a Kubernetes ServiceAccount or workload identity with RBAC written for the tools it exposes), not a person's Google login: a login expires, and it would put one person's name in the cluster audit. The gateway's own audit records the session, the agent and the human who started it.
2. Authenticated approvals. Mutating calls are approved in a UI with SSO and group-based approvers, not in a loopback UI without login. Production writes can require that the approver is not the requester.
3. Many agents, one gateway. Per-agent tokens, TLS between agent and gateway, rate limits per agent, and every call tagged with agent, session and user.
4. Per-user permissions: which user or group may use which environment, tool and write command.
5. Deployment. Secrets come from Infisical or 1Password, not local files; configuration (environments, commands, query patterns) comes from git and reloads; the audit log is shipped to Loki; the gateway image and config are versioned and rolled back like any service.
6. Reachability. Data stores that sit inside the cluster (Postgres poolers, Redis) are reached from inside it, so no port-forward is needed; stores outside it (Elasticsearch) by network policy.
7. Database access without a read-only role: point the tool at the read-only pooler and set `require_replica: true`; the gateway then refuses any connection that is not a standby. A real read-only role is still recommended as defense in depth.

## 13. Implementation plan

Tech stack: Python 3.12, FastAPI, SQLite (SQLModel), Docker SDK for Python, official `mcp` Python SDK, pglast, nftables via a tiny helper in the gateway container, xterm.js, HTMX. Packaging: `uv`, single `docker compose` for the controller-less dev setup.

Repository layout

```
AirlockAI/
  controller/        FastAPI app, session manager, audit, secrets readers
  gateway/           MCP gateway (auth, policy, approvals, audit)
  egress/            nftables + SNI proxy image
  agent-image/       Dockerfile, entrypoint, status line, skills mount
  sdk/               airlock SDK (tool decorator, Env, test harness)
  tools/             built-in tool servers: postgres, elastic, redis, k8s, ssh, disk, django
  operations/        starter operation YAML
  ui/                templates and static assets
  docs/
  tests/
```

Milestones

1. M1 - Sandbox MVP (about 1 week). Config file loader and `airlock config validate` (section 7.3), node access MCP with passwordless key and sudo setup and cleanup (section 6.3), node inventory (CLI + minimal UI), execution runner with direct / ssh / ssh+sudo and `airlock-run` (section 7.2), agent image, session start with egress allowlist to model API and node IPs, bypass mode, attach terminal in browser. Done when: agent in a session can SSH and `sudo -n` on its nodes with no password, the key and sudoers rule are gone after session stop, and the agent cannot reach anything else (`curl example.com` fails, `ssh other-host` fails), verified by an automated test.
2. M2 - Operations. Operation YAML, `ops.*` MCP tools available in Sandbox mode, UI buttons, parallel execution, AWS import.
3. M3 - Gateway core. (v1 database access goes through the application's Python and Django shell, section 7.7; the direct postgres tool is the alternative for stores the gateway reaches itself.) Slack and Jira read/search tools (both modes, section 7.5). Runner reused by tools with per-environment and per-tool execution mode; MCP gateway with token auth, tool allowlist, audit, approvals; SDK; first tools: postgres (read), kubernetes (read), ssh (allowlist). Done when: from a Gateway session the agent can run `kubectl get ns` equivalent and a SELECT, cannot read the secrets dir, cannot open a socket to the database, and a DROP attempt is rejected and logged.
4. M4 - Environments UI. Execution mode selector, config import/export with diff. Add-environment wizard with `kubectl --context` validation, secret entry, multi-agent sessions on one environment.
5. M5 - More tools: elastic, redis, airflow, disk, django named queries; hot reload; `airlock test`.
   M5a - Query patterns (could move before M4 if databases are the first need): pattern store and versions, UI add/edit/remove/enable, SQL/ES/Redis validators, named-call tools, raw-command matching, `query.propose`, test run, YAML import/export. Done when: a pattern added in the UI is accepted from the agent within a second without restart; the same query with a different literal in a non-placeholder position is rejected; removing the pattern rejects the next call; an injection attempt in a placeholder value (`1; drop table x`, `{"script": ...}`, `x\r\nFLUSHALL`) is rejected or bound as inert data.
6. M6 - Hardening and multi-user use: gVisor/microVM level, SSM/Instance Connect keys, shared-host deployment, export to the artifact store, docs.
7. M7 - Shared gateway (target deployment). The gateway is a privileged service deployed by DevOps and used by all agents, including interventions in production through approved write tools. Its power is bounded by what it exposes (named kubectl commands, query patterns, operations), approvals and audit, not by a weak identity. Requirements in section 12.1.

Implementation status (Mode 2)

Implemented and covered by tests (unit tests with fake connectors, plus `tests/test_acceptance_mode2.py` against real containers):

- Query patterns: typed placeholders, SQL (pglast AST match and validation), Elasticsearch, Redis; raw-query matching, named tools, `query.list`, `query.propose` with a human approval queue, versions, YAML import/export, `airlock patterns`.
- MCP gateway: MCP over streamable HTTP, per-session bearer token (the gateway holds only a hash), tool allowlist per environment, rate limit, size caps, redaction of every value in the environment's secrets dir and of `USER_PASSWORD`, hash-chained audit with `pattern@version`, file-based approvals. Tools: `sql.*`, `es.search`, `redis.command`, `kubernetes.*`, `ops.*` (remote_ops), `disk.*`, `airflow.*`, `django.query`, `slack.*`, `jira.*`.
- Execution modes direct / ssh / ssh_sudo for kubernetes and operations, per environment and per tool; policy runs on the argv before the mode wraps it.
- Gateway sessions: internal network, egress proxy for the model API only, gateway container (read-only, no capabilities, no Docker socket, secrets mounted into it only), agent container with `MCP_URL` and `MCP_TOKEN` only and no ssh/kubectl. Cleanup on stop. `airlock session start --env uat [--count N]`; one gateway, token and audit trail per agent.
- UI: the `EC2` and `PROD` tabs (section 9); `airlock test` policy self-checks; `airlock envs`.

Designed, not built yet: application shell execution (7.7: named Django and Python scripts, the pattern runner, stdin parameters, the READ ONLY preamble), the Google sign-in flow in 4.1 (kubelogin plugin in the gateway image, the kubeconfig and token-cache mounts, the host pre-check and the Sign in button), `via_kube` tunnels, result anonymization (7.6), and the shared deployment of 12.1.

Known gaps in v1: the pattern "Test" button (a test run through a live gateway) is not built; the gateway is stateless MCP, so it cannot push `notifications/tools/list_changed` (agents see new named tools at their next `tools/list`, raw queries and `query.list` are always current); Slack and Jira use tokens from the secrets dir or environment, not the browser OAuth flow of 7.5; `gvisor` isolation passes `--runtime runsc` and `microvm` is not implemented; kubeconfigs that rely on exec plugins (for example `aws eks get-token`) do not work for `direct` mode inside the gateway container, use ssh mode or a token kubeconfig; hot-reloaded Python tool modules (section 8 SDK) are not built, tools are built in.

Testing strategy

- Policy tests: for each tool a table of forbidden calls that must fail (DROP, DELETE, path traversal, `;` injection, secret kinds in output).
- Network tests: spin a session and assert reachability matrix from inside the agent container (allowed and denied destinations).
- Secret leak test: grep agent container filesystem, env and process list for the known test secret values after a full session.
- Golden session replay for the UI.
- Mode 1 test node: a real disposable EC2 devbox registered as a node is the acceptance target. It is reachable by SSH as a normal user, serves web and docs endpoints, and exposes Kubernetes through a bearer token that is read over SSH (`ssh host cat /etc/kubernetes/remote-token`) and used to build a kubeconfig. Acceptance: the node access MCP sets up the key and passwordless sudo; the agent runs `ssh` and `sudo -n`, fetches the token, runs `kubectl get ns` against the devbox cluster, and cannot reach any other host; after stop, the key and sudoers rule are gone. Real hostnames are kept in a git-ignored `local/` file, not in this repo.
- Kubernetes via token over SSH is a supported variant of the `direct` mode: `kube: {server, token_cmd, context}`; the runner runs `token_cmd` (over ssh) and passes `--server`/`--token` without writing the token to disk.

## 14. Open questions

Decided
- Platform: Linux only in v1 (macOS later via a Linux VM such as Colima or Lima).
- Mode 1 reaches nodes over public / Elastic IPs; security groups allow SSH only from the controller host.
- Approvals: browser UI only.
- Mode 2: the agent has no ssh and no kubectl; only the MCP API. The MCP code uses ssh and kubectl internally.
- Raw queries from the agent are matched against patterns; `query.list` returns all supported queries.
- Model login: subscription token mounted per session.
- v1 tools: Postgres, Elasticsearch, Redis, Kubernetes, Airflow (logs, DAG run status), and Slack and Jira read/search in both modes.

- AWS read-only node discovery: yes, when the AWS CLI and credentials are present on the controller (section 6.1).
- Slack and Jira: browser login once, token stored locally (section 7.5).
- Web UI: no authentication in v1; loopback only.
- No alert or ticket driven session start.
- No shared hosts in v1.
- Claude Code only in v1.
- `USER_NAME` / `USER_PASSWORD` are shared across all MCPs and nodes.

Open
- Traceability of outbound traffic and commands: which option or combination of section 11.1 to build first.

## 15. Naming

Chosen: AirlockAI (repo `larytet-py/AirlockAI`). Alternatives considered: Moat, Tether, Bulkhead, Gatehouse, Sluice.
