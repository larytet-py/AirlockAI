# UI test plan

Manual checks for the web UI (`uv run airlock ui`). Layout and behaviour are specified in
[docs/UI_REFACTOR_SPEC.md](docs/UI_REFACTOR_SPEC.md). Automated coverage for the same flows is in `tests/test_admin.py`
(`test_remove_session_handles_every_state`, `test_dead_sessions_skip_live_and_fresh_starts`,
`test_ui_one_click_remove_and_remove_all_not_running`, `test_deleting_a_node_clears_its_dead_sessions_first`),
`tests/test_ui_prod.py` and `tests/test_ui_hardening.py` (spec section 10). Run them with `uv run pytest -q`.

Each case says how to set it up, what to click, and what must be true afterwards. "Gone" means gone from the list
after the page reloads, and `ls ~/.airlock/sessions` no longer shows the session id. "Two clicks" means: the first click
turns the button red and shows the question, a second click within 3 seconds runs it; no browser `confirm()` appears
anywhere.

## Setup

- Two test nodes in the EC2 tab, both imported from AWS so the AWS actions work: call them `A` and `B`.
- AWS CLI logged in (`aws login`), Docker running, agent image built (`uv run airlock image`).
- Keep a terminal open on the controller with `watch -n2 'docker ps --format "{{.Names}}" | grep air-'`.

## 1. Stop and remove, the everyday case

| # | Setup | Action | Expected |
|---|-------|--------|----------|
| 1.1 | Session running on `A`, `A` reachable | Session row `⋯` → `Stop & remove`, then click it again | First click: the item turns red, "Stop & remove?". Second click: row gone, `air-agent-<id>` and `air-egress-<id>` gone from `docker ps`, no banner. On `A`: no `airlock` line for the id in `~/.ssh/authorized_keys`, no `/etc/sudoers.d/90-airlock-<id>`. |
| 1.2 | Same as 1.1 | Click `Stop & remove` once and wait 3 s | The item reverts; the session keeps running. |
| 1.3 | Session already stopped (`Stop only` earlier) | Click the grey `● stopped ✕ remove` chip | One click: row gone. |
| 1.4 | Three sessions, two running, one stopped | Tick all three; the bar at the bottom shows "3 sessions"; click `Stop & remove` twice | First click: "Stop 2 running & remove?". Second: all three gone, no banner, the bar disappears. |
| 1.5 | One session running | Put the row cursor on it (`j`), press `Del` twice | The menu opens on `Stop & remove`, armed; the second `Del` runs it. Same as 1.1. |

## 2. Agent already dead (the case that used to need several clicks)

| # | Setup | Action | Expected |
|---|-------|--------|----------|
| 2.1 | Session running, then `docker rm -f air-agent-<id>` by hand | Wait 5 s | The agent chip turns into red `● NOT RUNNING ✕ remove`; `claude ↗`, `shell ↗` and the ssh line disappear; `Remove 1 not running` appears in the heading. |
| 2.2 | As 2.1 | Click the chip | One click (nothing is running). Row gone; node `A` cleaned as in 1.1. |
| 2.3 | Session running on `A`, then stop the EC2 instance of `A` (row `⋯` → `Stop instance`, two clicks) | Click the session's `NOT RUNNING ✕ remove` chip | Row gone. Red banner: "removed. Key and sudo rule may remain on: `<id>/A` (run airlock sweep once the node is reachable)". |
| 2.4 | As 2.3, then click `A`'s `● instance stopped ▶ start` chip and run `uv run airlock sweep` once it is up | | The leftover key line and sudoers file for `<id>` are removed on `A`. |
| 2.5 | Session in `needs_cleanup` (do 2.3 with `⋯` → `Stop only` instead) | Click the red `● cleanup pending ✕ remove` chip | Stop is retried first. If `A` is back up: row gone, no banner. If `A` is still down: row gone, banner lists `<id>/A`. |
| 2.6 | Kill the UI process while a session is starting (the row shows `starting… 12s`), restart the UI | | The row keeps `starting…`. Within the first 10 minutes `Remove N not running` does not count it; after 10 minutes it shows `NOT RUNNING ✕ remove` and is counted. `⋯` → `Remove` removes it at any time. |

## 3. Remove N not running

| # | Setup | Action | Expected |
|---|-------|--------|----------|
| 3.1 | One healthy running session, one stopped, one `needs_cleanup`, one with the agent container removed by hand | `Remove 3 not running` in the AI sessions heading | Only the healthy running session remains. Banner lists node leftovers for any node that could not be reached; no banner if all were reachable. |
| 3.2 | Start a session and click `Remove N not running` while the row shows `starting…` | | The starting session survives and comes up; the row turns `running` by itself. |
| 3.3 | Only healthy running sessions | | No `Remove … not running` button at all. |
| 3.4 | PROD tab, same mix as 3.1 with gateway sessions | PROD `Remove 3 not running` | Same result, and no EC2-tab session is touched. |

## 4. Removing a node (EC2 instance) from the list

| # | Setup | Action | Expected |
|---|-------|--------|----------|
| 4.1 | Node `B` with no sessions | `B`'s `⋯` → `Delete from list`, twice | `B` gone from the list and from `~/.airlock/airlock.yaml` (comments in the file kept). |
| 4.2 | Node `A` whose only session is stopped, `needs_cleanup`, or has a dead container (EC2 instance already stopped) | Tick `A`, bar → `Delete` twice | `A` gone and the dead session gone, in one action. Banner lists `<id>/A` if the node could not be reached. |
| 4.3 | Node `A` with a healthy running session | Tick `A`, bar → `Delete` twice | `A` stays. Banner: "not deleted, a running AI session uses it (Stop & remove the session first): A (session <id>)". |
| 4.4 | `A` busy (4.3) and `B` free, both ticked | Bar → `Delete` twice | `B` deleted, `A` kept, banner names `A`. |

## 5. New controls

| # | Setup | Action | Expected |
|---|-------|--------|----------|
| 5.1 | `A` and `B` up | Tick both | Bar: "2 nodes", `Start 2 sessions`. Click it: two separate sessions, one per node, both shown as `starting… Ns`, then `running` without a manual reload. |
| 5.2 | `A` up, `B`'s instance stopped | Tick both | `Start session` (one), `Start instance` enabled (for `B` only), `Reboot` and `Stop instance` apply to `A` only. |
| 5.3 | | Click a node name, type a new one, Enter. Then click it, Esc | Renamed (and its sessions follow). Esc restores the old name without saving. |
| 5.4 | | Click the `ssh jdoe@…` line under a node, paste in a terminal | The command is in the clipboard; the pill shows "copied" for a second. Over plain http with the Clipboard API refused: the text is selected and the pill says "Press Ctrl+C". |
| 5.5 | Session running | Click its `ssh <name>` line, paste in a terminal | Logs in as `agent` (after `airlock ssh setup`; before it, the copied command carries `-F ~/.airlock/ssh_config`). |
| 5.6 | | Right-click a node row; then press `↓`, `Esc` | The same menu as `⋯`; arrows move, Esc closes. With 2+ ticked rows, right-click on one of them says "2 selected, use the bar". |
| 5.7 | Rows in both tables | Tick a node, then tick a session | The node is unticked; the bar now acts on sessions. `Esc` clears all ticks and hides the bar. |
| 5.8 | | `?` | The key list opens; `j`/`k` move the row cursor, `x` ticks, `s` starts a session on the cursor node, `Enter` opens claude for the cursor session, `m` opens its menu. Keys do nothing while typing in a field. |
| 5.9 | Node login forgotten (Settings → `Forget login`) | EC2 tab | Every node shows red `● down: login missing fix →`; clicking it opens Settings with the login form one click away (`login missing … set →`). |
| 5.10 | PROD, cluster `uat` with `kubernetes: read` | Click the `kubernetes: read` chip, reload | `kubernetes: approve writes` (amber); the other tools and their settings in the config file are unchanged. Click again: off. |
| 5.11 | PROD, a context with an expired login | | Red status chip with the kubectl error and `↻ refresh`. Click: the login plugin runs on this machine (may open the browser), the chip turns green on the next poll. |
| 5.12 | PROD, an agent asks for a write call | | A card with the call and its arguments: `Approve` (one click), `For this session`, `Reject` (two clicks). The agent gets the decision. |
| 5.13 | Settings | Click the source folder's `read-only ⇄` chip; untick Enabled; click `✕` | Each saves at once: `read-write (EC2)`, disabled, removed. |
| 5.14 | Sessions on `A` and on `B` | Tick `A`; then untick it and click an empty part of `B`'s row | `A`'s sessions are tinted with a blue bar on the left, the others are not; after the click only `B`'s sessions are. Same on PROD for a cluster and its sessions. |

## 6. Regression checks

- `Stop only` (row `⋯` or the bar) stops but keeps the row (`● stopped ✕ remove`), so the workspace can still be inspected.
- `claude ↗` and `shell ↗` appear only on running rows and open in a new tab.
- Renaming a node or a session by clicking its name still works after a remove (the page is not left in a half state).
- A forged request is refused: `curl -X POST http://127.0.0.1:8800/sessions/bulk-remove -d ssel=../x` returns 401/403/404
  (no UI token, wrong Origin, or bad id).
- A node note or session name such as `<img src=x onerror=alert(1)>` (written into the config or state file) shows as text.
- No page (`/`, `/prod`, `/settings`) shows a drop list + `Apply` for nodes or sessions, and no browser `confirm()` dialog.
- The audit log `~/.airlock/audit/<id>.jsonl` of a force-removed session has a `session.discarded` line with
  `node_access_may_remain`.
- `uv run python docs/mock/build.py` rebuilds the static mock without errors.
