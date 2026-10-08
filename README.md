# AirlockAI

Run AI coding agents (Claude Code first, Codex and Cursor CLI later) next to real infrastructure without handing them the keys.

The agent works inside an airlock: a container or microVM with a tightly controlled network. The only way out is a door you built and control.

Status: Mode 1 (Sandbox) and Mode 2 (Gateway) are implemented; see [SPEC.md](SPEC.md) for the design and the list of known gaps.

## Getting started (Mode 1, step by step)

### 1. Prerequisites

- Docker, usable without sudo (`docker ps` works).
- [uv](https://docs.astral.sh/uv/).
- AWS CLI v2, only to import your EC2 instances and start or stop them from the UI. Install it from AWS, not with
  `apt install awscli` (too old for `aws login`):
  ```
  curl "https://awscli.amazonaws.com/awscli-exe-linux-$(uname -m).zip" -o awscliv2.zip && unzip -q awscliv2.zip && sudo ./aws/install
  ```
- A Claude subscription for the agent.

### 2. Install

```
git clone git@github.com:larytet-py/AirlockAI.git
cd AirlockAI
uv sync
```

### 3. Build the agent image

```
uv run airlock image             # Mode 1 agent image (airlock-agent)
docker images | grep airlock     # check it is there
```

The first build takes a few minutes, mostly in the `apt-get install` step; let it finish. Rebuild after pulling changes
to `agent-image/`. For Mode 2 also run `uv run airlock image --gateway`.

### 4. Set up the config file

airlock reads `~/.airlock/airlock.yaml` (or `--config FILE`, or `$AIRLOCK_CONFIG`). Start from the template:

```
mkdir -p ~/.airlock
cp airlock.example.yaml ~/.airlock/airlock.yaml
```

Edit `~/.airlock/airlock.yaml`:

- `nodes`: delete the two example nodes. Add your own here, or import them from AWS in step 7.
- `defaults.links`: the links shown in every node row, for example
  ```yaml
  links:
    web:  "https://omniverse-{instance_id}.dev.nvidia.com"
    docs: "https://omniverse-{instance_id}.dev.nvidia.com"
    ssh:  "ssh://{user}@omniverse-{instance_id}.dev.nvidia.com"
  ```
- `environments` and `query_patterns` are for Mode 2 only. Leave or delete them for Mode 1.

The file holds no secrets: `${USER_NAME}` and `${USER_PASSWORD}` are filled in at run time. Check it with
`uv run airlock config validate` (it reports `USER_PASSWORD` as undefined until you set the login in step 6).

### 5. Start the UI

```
export USER_NAME=<your login>    # needed for "Import my AWS instances"
aws login                        # only if you import or control EC2 instances
uv run airlock ui                # http://127.0.0.1:8800
```

Restart `airlock ui` (Ctrl+C, then run it again) after every `git pull`: the server keeps running the code it started with.

### 6. Settings tab: user name, password and Claude sign-in

Open **Settings** in the UI.

1. **Node login**: enter your user name and password (the password is also the sudo password on the nodes) and click
   **Keep in memory**. airlock uses them once per session to install a session ssh key and passwordless sudo on the
   nodes, and removes both when the session stops. The password is kept in the memory of the UI server only: it is
   never written to disk and is forgotten when the server stops, so enter it again after a restart. (Alternative:
   `export USER_NAME=... USER_PASSWORD=...` before `airlock ui`.)
2. **Claude sign-in**: run `claude setup-token` in a terminal, sign in, paste the token it prints and click
   **Save token**. New sessions then start signed in.
3. **Source code**: add the folders the agent should see, for example `~/myproject`. Each appears in the agent
   container as `/src/<folder name>`, read-only by default.
   This is the default list. A node can have its own list: click **src:** under the node name on the EC2 tab.
   A session mounts the folders of all its nodes.

### 7. Add your nodes

On the **EC2** tab click **Import my AWS instances**, select your instances and click **Add selected nodes**. They are
written to `~/.airlock/airlock.yaml`. CLI: `uv run airlock nodes import-aws` (dry run), then add `--yes`.

### 8. Start a session

On the **EC2** tab click **Start** in a node's row. For several nodes, tick them, choose **Start session on selected**
and click **Apply**. If a node's EC2 instance is stopped, start it first with **AWS: start instances**.
CLI: `uv run airlock session start --nodes MyTestNode`.

airlock sets up the ssh key and passwordless sudo on the nodes and starts the agent container. The container can reach
only the model API and the selected nodes.

### 9. Work with the agent

- In the UI: the **claude** or **shell** link in the session row opens a terminal in a new tab.
- Over ssh: run `uv run airlock ssh setup` once (adds an `Include` line to `~/.ssh/config`), then
  `ssh <session id or name>` and run `claude`.
- CLI: `uv run airlock session attach <id>`.

Claude starts in `/src` with your code, runs without permission prompts (`--dangerously-skip-permissions`) and is told
which nodes it has. It reaches them with `ssh MyTestNode` or `airlock-run MyTestNode -- <command>`, with
`sudo -n` and no password.

### 10. Stop the session

Tick it in the sessions table on the **EC2** tab and click **Stop selected**, or run `uv run airlock session stop <id>`. This removes the
ssh key and sudo rule from the nodes and deletes the containers and networks. `uv run airlock sweep` cleans up after
sessions that did not stop cleanly.

### Troubleshooting

| Message | Fix |
|---|---|
| `config file not found: ~/.airlock/airlock.yaml` | Step 4. |
| `Unable to find image 'airlock-agent:latest'` | Step 3: `uv run airlock image`. |
| `ssh: Could not resolve hostname <session id>` | `uv run airlock ssh setup`. |
| `sandbox sessions cannot prepare nodes` | Step 6: set the node login (again after restarting the UI). |
| Agent asks for permission or does not know its nodes | Restart `airlock ui`, run `uv run airlock ssh setup`, log out of the session and back in. |
| `Import from AWS: USER_NAME is not set` | `export USER_NAME=...` before `uv run airlock ui`. |

Tests: `uv run pytest` (unit). Acceptance against a real test node:
`AIRLOCK_CONFIG=local/test-node.yaml uv run pytest -m integration tests/test_acceptance_mode1.py`
(`AIRLOCK_ACCEPT_KUBE=1` adds the kubectl-over-token step).

## Quick start (Mode 2)

```
uv run airlock image --gateway                          # gateway image (holds credentials) + agent image without ssh/kubectl
uv run airlock envs list                                # registered environments and local kubectl contexts
uv run airlock envs add uat --context uat --tool postgres:dsn_env=PG_DSN --tool kubernetes
# secrets: ~/.airlock/secrets/uat/*.env (chmod 600) or the masked field in the PROD tab
uv run airlock patterns import patterns.yaml            # the only queries the agent may run
uv run airlock test --env uat                           # policy self-checks: forbidden calls must be refused
uv run airlock session start --env uat                  # internal network, gateway container, agent with MCP_URL/MCP_TOKEN only
uv run airlock approvals list                           # mutating calls waiting for you (also in the PROD tab)
uv run airlock ui                                       # EC2 tab (sandbox nodes) and PROD tab (kubectl clusters, gateway sessions)
```

ssh into an agent container (rebuild the images once): `airlock ssh setup`, then `ssh <session id or name>` (user `agent`). Name a session by clicking its id in the UI or with `airlock session name ID NAME`.

Predefined kubectl commands (`kubectl_commands` tool, see `airlock.example.yaml`) are the way to give the agent specific kubectl actions, for example a read-only `psql` count inside a replica pod. Rebuild the gateway image after updating (`airlock image --gateway`).

Acceptance with real containers: `AIRLOCK_HOME=$(mktemp -d) uv run pytest -m integration tests/test_acceptance_mode2.py`.

## What it does

AirlockAI has two modes with different trust models.

### Mode 1 - Sandbox: the agent is free, the world is small

For debugging your own test nodes on EC2 (typically 2-3 at a time).

- The agent runs unrestricted (`claude --dangerously-skip-permissions`) inside a container or VM.
- Network egress is default deny. Only the model API and the registered EC2 nodes are reachable.
- A node access MCP uses your `USER_NAME` / `USER_PASSWORD` (enter them in the **Settings** tab under "Node login", kept in the memory of the UI server only and never written to disk, or export them) once to set up a per-session SSH key and passwordless sudo on the test nodes, then removes them when the session ends. The agent never sees the password.
- A browser UI manages the node inventory: add or remove EC2 nodes, set labels, start / stop / reboot their EC2 instances.
- Reusable operations (for example `docker-purge`, `cpu`) are defined once and can be run from the UI or by the agent.

### Mode 2 - Gateway: the agent is constrained, the world is big

For investigating UAT or production.

- The agent can only reach MCP servers that you wrote: Postgres, Elasticsearch, Redis, Kubernetes, SSH, disk, Django.
- The MCP code runs in separate containers on your machine and loads credentials from your environment. The agent never sees them.
- SQL, Elasticsearch and Redis queries are managed as patterns in the UI (add, edit, remove, enable). The agent can run only queries that match an enabled pattern, and a new pattern is accepted immediately.
- Tools are classified read or mutating. Mutating tools are off by default and need approval in the UI.
- The UI lets you add an environment (for example `kubectl --context uat get ns`) and start one or more agent containers wired to it.
- Commands run directly, over SSH, or over SSH with sudo (`kubectl ...`, `ssh host kubectl ...`, `ssh host sudo kubectl ...`), chosen per node or environment. The tools adapt the commands automatically.
- Every tool call is audited.

## Configuration

Start from [airlock.example.yaml](airlock.example.yaml), a commented template (copy it to `~/.airlock/airlock.yaml` or pass `--config`).

Link patterns: `defaults.links` turns the EC2 name into the links shown in each node row, for example `web: "https://web-{instance_id}.dev.example.com/"` and `ssh: "ssh://{user}@{instance_id}.example.com"`. `{instance_id}` comes from the node's `instance_id`, its `aws_instance_id` tag, or the host/name; also `{name} {host} {user} {port}`. A node's own `urls:` override a pattern of the same name.

Everything (nodes, operations, environments, query patterns, execution modes) lives in one YAML or JSON file that you can share and commit. It holds no secrets: logins come from the `USER_NAME` and `USER_PASSWORD` environment variables and other references.

## Why not rely on the agent's own rules

Permission modes, hooks and CLAUDE.md are part of the agent harness and can be bypassed by a bug, an update or a prompt injection. AirlockAI enforces limits at the network and container boundary, below any harness, so the same policy holds for every agent.

## Planned architecture

- Controller: local web UI and REST API, session manager, audit log (Python, FastAPI, SQLite).
- Agent image: Claude Code in a locked-down container.
- Egress gateway: nftables allowlist plus an SNI proxy for the model API.
- MCP gateway: auth, per-environment tool allowlist, rate limits, redaction, approvals.
- Tool SDK: add a read-only tool as a short Python function with a declared risk level; hot reload, no agent restart.

Details, threat model, data model and milestones are in [SPEC.md](SPEC.md).
