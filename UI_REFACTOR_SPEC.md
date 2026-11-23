# UI refactor: one-click actions, no toolbars

Requirements for refactoring the controller web UI (`airlock/ui.py`, `airlock/ui_prod.py`, the Settings page) to match
the clickable mock in [`docs/ui-refactor-mock.html`](ui-refactor-mock.html). Open the mock in a browser next to this
file. The mock is the reference for layout and behaviour. This file is the reference for anything the mock only
pretends to do, for the backend, and for the rules the mock does not follow (security, see section 8).

## 1. Goal

Today most actions need a select, then a drop list, then Apply, then a browser confirm. Removing a dead agent took
several different buttons, and some combinations did not work at all. After the refactor:

- The everyday paths take one click: copy an ssh command, rename something, open claude, remove a dead session,
  approve a call.
- Actions that are hard to undo take two clicks on the same button, and never a browser `confirm()`.
- No toolbar is visible unless rows are ticked.

## 2. Interaction patterns (apply everywhere)

| ID | Pattern | Rule |
|----|---------|------|
| P1 | **Click a name to edit it** | Node, cluster and session names are click-to-edit inline. Enter saves, Esc cancels, blur cancels. The text has a dotted underline and a text cursor. Server-side validation stays as it is; a refusal shows in the error banner. |
| P2 | **Click to copy** | An ssh command under each node name (`ssh <user>@<host>`) and under each running session name (`ssh <session name or id>`). Rendered as a monospace pill with a copy icon. Click copies and shows "copied" for about a second. Fallback when the Clipboard API is refused: select the text and say "Press Ctrl+C". Stopped sessions have no ssh pill (their key is revoked). |
| P3 | **Status chip as action** | A status chip is a button when there is one obvious next step, otherwise plain text. Clickable chips show the step as a small suffix (`▶ start`, `✕ remove`, `fix →`, `↻ refresh`). See the chip tables in sections 4 to 6. |
| P4 | **Bulk bar on selection** | Tables have checkboxes. When at least one row is ticked, a bar floats at the bottom of the viewport with the actions for the ticked rows and a count ("3 nodes"). It disappears when nothing is ticked. Ticking a row in one table clears the selection in the other tables on the page, so the bar always acts on one kind of row. Esc clears the selection. |
| P5 | **Row menu** | A `⋯` button at the end of each row, and right-click on the row, open the same menu with the rarer actions. If the right-clicked row is one of several ticked rows, the menu says "N selected, use the bar" instead of acting on one row. Arrow keys move in the menu, Esc closes it. |
| P6 | **Two-click destructive buttons** | Stopping, deleting, rejecting and similar: the first click turns the button red and changes its label to the question ("Stop & remove?"), a second click within 3 seconds runs it, otherwise it reverts. Removing something that is not running is one click. No `confirm()` anywhere. |
| P7 | **Show the action only when it applies** | Buttons such as "Remove N not running" appear only when N > 0, and show N. |
| P8 | **Keyboard** | `j`/`k` move a row cursor, `x` ticks, `s` starts a session (cursor node or ticked nodes), `Enter` opens claude for the cursor session, `Del` removes the cursor session (second press if running), `m` opens the row menu, `?` shows the key list, `Esc` closes or clears. Keys are ignored while typing in an input. |
| P9 | **Result messages** | Keep the existing banners (`.err` / `.ok`, from the `error` / `info` query parameters) for results that come back from a POST and redirect. Text from nodes or the server is never inserted as markup. |

## 3. Page structure

Left tab strip, unchanged in look: EC2, PROD, Settings, each a real link to its page (`/`, `/prod`, `/settings`).
EC2 shows the number of running sandbox sessions. PROD shows running gateway sessions, plus the waiting count when
it is above 0.

## 4. EC2 page (`/`)

### 4.1 Nodes table

Columns: checkbox · **Node** · **Status** · **Load** · **Links** · **Sessions** · `⋯`.

- **Node:** the name (P1, posts to the existing `/nodes/{name}/rename`). Below it the ssh pill (P2), using the same
  user resolution as today's `sshcmd` in `ec2_page`. Below that, small grey text: instance id, exec mode, and
  `src: <folders>` as a link to `/nodes/{name}/sources`.
- **Status chip:**

  | State | Chip | Click |
  |-------|------|-------|
  | reachable | green `● up` | none |
  | EC2 instance stopped | grey `● instance stopped ▶ start` | POST `/nodes/aws/start` for this node |
  | login missing | red `● down: login missing fix →` | go to `/settings` |
  | unreachable for another reason | red `● down`, error in the tooltip | none |
  | AWS action in progress | amber pulsing `● instance starting…` (or stopping, rebooting) | none |

  The "instance stopped" state needs the EC2 state per node. Add it to `/api/nodes/stats` (see 7.3).
- **Load:** the column is called "Load" (not "Load · storage"). Two lines:
  - `cpu <1m> <5m> <15m>  <running>/<total> · <N> cores`, the fields of `/proc/loadavg`. Red when the 1-minute value is above the core count.
  - `disk / <pct>  /data <pct>`, red at 85 % or more. Keep the used/size detail in the tooltip.
- **Links:** as today (web, ssh, with their up/down colour).
- **Sessions:** a count, for example `1 running · 2 not running` (the second part in red). `–` when there are none.
- **No Start button in the row, and no exec-mode select in the row.**
- **`⋯` menu:** Start session (disabled when the node is down), Rename, Source folders…, exec mode as three radio
  items (`ssh`, `ssh_sudo`, `direct`, posts `/nodes/{name}/mode`), Start instance or Reboot instance, Stop instance
  (P6), Delete from list.
- **Bulk bar for nodes:** `Start session` (one separate session per ticked node that is up, label `Start N sessions`
  when N > 1), `Start instance`, `Reboot`, `Stop instance` (P6), `Delete` (P6). Buttons that do not apply to any
  ticked node are disabled.
- Below the table: `+ Add node` (opens today's add form inline) and `Import my AWS instances`.
- Remove the "Selected nodes" drop list and the Apply button.

### 4.2 AI sessions table

Columns: checkbox · **Session** · **Agent** · **CPU · memory · workspace** · **Node** · open/remove.

- **Session:** the name or id (P1, posts `/sessions/{sid}/name`). If named, the id follows in small grey text. Below
  it the ssh pill (P2) while running.
- **Agent chip:**

  | State | Chip | Click |
  |-------|------|-------|
  | container up | green `● running` | none |
  | starting | amber `● starting… 12s` | none |
  | status `running` but container gone | red `● NOT RUNNING ✕ remove` | remove (one click) |
  | `needs_cleanup` | red `● cleanup pending ✕ remove` | remove (one click) |
  | `stopped` | grey `● stopped ✕ remove` | remove (one click) |
  | being removed | amber `● removing…` | none |

- **CPU · memory · workspace:** from `/api/sessions/stats`, as today. `–` when not running.
- **Last column:** `claude ↗` and `shell ↗` (new tab, `rel=noopener`) while running, then `✕` (P6 when running,
  one click otherwise), then `⋯`.
- **`⋯` menu:** Open claude, Open shell, Name this session, Stop only (running only), Stop & remove / Remove.
- **Heading:** `AI sessions` + "N running" + a `Remove N not running` button (P7), which posts `/sessions/prune`.
- **Bulk bar for sessions:** `Stop & remove` (P6 if any ticked session runs, else one click), `Stop only`.
- Remove the old `Stop selected` / `Delete selected` / `Force discard` / `Remove all stopped` buttons. (The current
  working tree already has `Stop & remove`, `/sessions/bulk-remove` and the new prune; reuse them.)
- Multi-node sessions are not shown as a concept in the UI. A session started on several nodes from the CLI still
  appears here, with all its node names in the Node column.

## 5. PROD page (`/prod`)

### 5.1 Waiting for you

Replaces the "Waiting for approval" select + Apply. One card per item, with a left border in the PROD colour:

- The title (tool call name or new query name), a chip (`write, agent is waiting` or `new access`), the arguments in
  monospace (wrapping, never overflowing), and `environment · session · time`.
- Buttons on the card: `Approve`, `For this session` (calls only), `Reject` (P6). Each posts the existing
  `/prod/waiting/bulk` with that one item and action.
- Keep the existing pattern editing (Ctrl+Enter saves, Esc cancels) for new-access items.
- Empty state: a dashed box, "Nothing is waiting. Write calls and new access requests show up here."

### 5.2 Clusters table

Columns: checkbox · **Cluster** · **Status** · **Tools** · **Links** · **Sessions** · `⋯`.

- **Cluster:** name (P1, `/prod/envs/{name}/rename`), and below it `context <ctx> · secrets <n>`.
- **Status chip:** green `● up · N nodes · 38 ms`. Red with the error and `↻ refresh` when the context fails;
  clicking refreshes the kubectl credentials.
- **Tools:** one chip per tool. Click cycles `off → read → approve_writes → off` and saves immediately through
  `/prod/envs/{name}/tools`. Colours: grey for off, green for read, amber for approve_writes. This replaces the
  `edit` details, the per-tool selects and the `Save tools` button.
- **`⋯` menu:** Start session, Set secret… (inline field, value never shown again), Refresh kubectl token, Remove
  from list (refused with a message while a running session uses it).
- **Bulk bar:** `Start session` (one per ticked cluster that is up), `Refresh tokens`.
- Keep "Add environment" and "Rescan local kubectl contexts" below the table.

### 5.3 PROD sessions table

Same as 4.2, except that the third column shows `N calls · N writes · live log ↗` instead of CPU and memory, and the
Node column is the cluster. Prune posts `/prod/sessions/prune`. Bulk remove uses the same remove path as EC2
(`session.remove_many`), restricted to gateway sessions.

## 6. Settings page (`/settings`)

- **Claude sign-in:** a status chip (`● automatic sign-in is on`, or grey "off: each session asks you to log in")
  and one button beside it: `Remove token` (P6) or `Paste token…`.
- **Node login:** chip `● login set for user jdoe` + `Forget login`, or a red clickable chip
  `● login missing … set →` that opens the login form.
- **Source folders table:** Folder · Mounted as · Mode · Enabled · Remove.
  - Mode is a chip that toggles `read-only` / `read-write (EC2)` on click.
  - Enabled is a checkbox that saves on change.
  - `✕` removes in one click.
  - An "Add folder" field and button, plus today's folder picker. Keep the existing refusal of credential folders.
- **Access:** a link to `/settings/access` (unchanged).

## 7. Backend changes

### 7.1 Reuse

`session.remove_session`, `remove_many` and `dead_sessions` and the routes `/sessions/bulk-remove` and
`/sessions/prune` already exist in the working tree. Node delete already clears dead sessions first.

### 7.2 One-row routes

Every row action posts to an existing bulk route with a single id (`ssel=<sid>`, `sel=<node>`, `item=<id>`), so no
per-row routes are needed. Keep the old routes that the CLI or tests use. Delete the routes the UI no longer calls
only if no test or CLI path needs them.

### 7.3 Node stats

`/api/nodes/stats` adds, per node:

- `load5`, `load15`, `tasks` (the `running/total` field). `nodestats.parse` already reads the whole `/proc/loadavg`
  line; it keeps only `load1` today.
- `ec2_state` (`running`, `stopped`, `pending`, `stopping`, or absent for non-AWS nodes), from a single cached
  `describe-instances` call. Refresh it at most once a minute, and right after a start, stop or reboot. Do not call AWS
  once per node.

### 7.4 Tools autosave

`/prod/envs/{name}/tools` accepts a single `tool` + `mode` (`off` | `read` | `approve_writes`) besides the full form,
so a chip click saves one tool.

### 7.5 Start feedback

The starting state needs the page to refresh while a session starts. Keep the server-rendered page. Poll
`/api/sessions/stats` (already every 5 s) and reload the row when a session leaves `starting`.

## 8. Constraints

- **Stack:** keep server-rendered HTML from Python plus small vanilla JS, as today. No framework, no build step, no
  CDN.
- **Security (do not regress `docs/SECURITY.md`, findings F01, F02, F10):**
  - Every state change stays a POST that carries the UI token cookie and passes the Origin / Host checks.
  - Text that comes from nodes, AWS or session state is set with `textContent` or escaped with `html.escape`, never
    put in `innerHTML`. The mock builds toasts with `innerHTML`; the real UI must not.
  - Session ids keep the `^[a-f0-9]{6,32}$` check; names keep their current patterns.
  - The ssh pill copies text only. It never runs anything and never links to `ssh://` with a command.
- **No `confirm()`:** P6 replaces it. Keep the confirm wording as the armed label or tooltip.
- **Accessibility:** every icon-only button has an `aria-label`. Menus use `role=menu` / `menuitem`, chips that are
  buttons are real `<button>` elements, and focus is visible. Respect `prefers-reduced-motion` (no pulsing).
- **Theme:** light and dark through CSS variables. The current `BASE_CSS` stays the base.
- **Width:** tables scroll horizontally inside their own container. The page never scrolls sideways.

## 9. Out of scope

- The Access page (`/settings/access`) and pattern editing beyond moving it onto the cards in 5.1.
- The terminal page (`/sessions/{sid}/term`).
- The AWS import page.
- Removing multi-node sessions from the CLI or the session layer.

## 10. Acceptance

Automated (extend `tests/test_admin.py`, `tests/test_ui_prod.py`, `tests/test_ui_hardening.py`):

1. The EC2 page has no `<select name=cmd>`, no Apply button, no `Start` button inside node rows, and no
   `confirm(` anywhere in the HTML of `/`, `/prod` or `/settings`.
2. Each node row has an ssh copy element with `ssh <user>@<host>`; each running session row has one with
   `ssh <name or id>`; a stopped session row has none.
3. Node, session and cluster names render as click-to-edit elements whose form posts to the existing rename routes.
4. `/api/nodes/stats` returns `load1`, `load5`, `load15`, `tasks`, `cores`, `disks`, and `ec2_state` for AWS nodes;
   AWS is called at most once per refresh, whatever the number of nodes.
5. A dead session (any of the four dead states in 4.2) is removed by one POST to `/sessions/bulk-remove` with
   `ssel=<sid>`.
6. A chip click on a tool saves only that tool; the other tools of the cluster are unchanged.
7. Every POST route used by the new UI is refused without the UI token and with a foreign Origin
   (`test_ui_hardening.py` pattern).
8. A node or session name containing `<img src=x onerror=alert(1)>` (set through the config file or the state file)
   renders as text on every page.

Manual: run `testplan.md`. Then update it for the new controls: replace the button names in sections 1 to 4 with
the row `✕`, the chips and the bulk bar. Then rebuild the static mock with `uv run python docs/mock/build.py`. Note
that this script fails with HTTP 401 on `main` today, since the UI token was added; fix it as part of this work.

## 11. Suggested order of work

1. Shared JS and CSS helpers in `ui.py`: copy pill, click-to-edit, two-click button, bulk bar, row menu, keyboard.
   One small script block that both pages include.
2. EC2 page (section 4), with its tests.
3. `/api/nodes/stats` additions (7.3).
4. PROD page (section 5) and the tools autosave (7.4).
5. Settings page (section 6).
6. Update `SPEC.md` (the UI section), `testplan.md` and the static mock.
