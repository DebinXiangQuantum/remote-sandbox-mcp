---
name: remote-sandbox-script-exec
description: "Execute script/test/build tasks in an SSH remote sandbox instead of local machine. Use when the agent needs to run Python, shell, test, or build commands. Enforces: sandbox selection, uv environment bootstrap, code sync, execution with log capture, result inspection, optional artifact sync back to local, and long-task resilience (auto polling, reconnect, and resume after reboot from logs)."
---

# Remote Sandbox Script Exec

Follow this workflow for every runnable task unless the user explicitly asks for local execution.

## Step 0 – Pick the Best Sandbox (multi-sandbox setups)

If more than one sandbox is configured, call `list_sandboxes(check_resources=True)` first.
Choose the sandbox with the highest `idle_score` (0 = fully busy, 1 = fully idle).
Then call `select_sandbox(sandbox_name=<chosen>)` to make it active for the session.
If the active sandbox later becomes overloaded (e.g. a check reveals high GPU/CPU),
call `list_sandboxes(check_resources=True)` again and switch with `select_sandbox`.

## Step 1 – Define Remote Workspace

Use a stable remote project root, e.g. `~/sandboxes/<project-name>`, and a unique run ID
(timestamp or task ID). All paths below are relative to this root.

## Step 2 – Bootstrap Runtime with uv

Run a remote setup command through `exec_bash`:
- Ensure `uv` is present; install if missing.
- Create `.venv` if it does not exist.
- Install dependencies with `uv sync` or `uv pip install -r requirements.txt`.

## Step 3 – Sync Code

Call `sync_local_to_remote` before execution.
Exclude heavy/unnecessary paths (`.git`, `node_modules`, caches, build outputs).

## Step 4 – Define Checkpoint + Resume Plan (required for long tasks)

Before starting any long task, define these artifacts explicitly:

- `run_id`: stable identifier for the task
- `checkpoint_path` or `checkpoint_command`: how progress is persisted and read
- `resume_command`: the command that resumes from the latest checkpoint
- `resume_plan`: a structured JSON object that at minimum includes the checkpoint and resume command

Do **not** rely on "let the agent inspect the failure later and invent a new script".
When the server is down, that is impossible. The recovery plan must already exist before launch.

Checkpoint guidance:
- Prefer a single machine-readable file such as `run_state.json`, `progress.json`, or a text checkpoint file
- Update it periodically during execution
- Make sure the content is enough to decide whether resuming is safe

Resume plan guidance:
- Prefer an idempotent `resume_command`
- Make it safe to run more than once
- It should continue from checkpoint, not restart blindly unless restart is intended

## Step 5 – Execute Task

**Short tasks (< 2 minutes):** use `exec_bash` with `tee` to a log file.

**Long tasks (training, batch jobs, slow builds):** prefer `exec_bash_background_watch`
instead of raw `exec_bash_background`. This starts the tmux task and registers the local
watchdog in one step, including `run_id`, checkpoint metadata, and resume plan.
Never block with `exec_bash` on jobs that may exceed its timeout.

### Long-Task Reliability Loop (required)

After starting a long task, rely on the local watchdog daemon as the persistent poller.
During the active Codex turn, inspect progress with:

- `get_background_watch_progress`
- `read_background_watch_log`
- `read_background_watch_checkpoint`

Do not depend on waking another Codex instance to recover the task. The watchdog should
only need the predefined checkpoint and resume plan.

If polling fails due to timeout, transient network failure, or SSH connection interruption:
- Call `get_active_sandbox` to verify connection health.
- Retry polling after a short backoff.
- If needed, re-select the same sandbox with `select_sandbox`, then continue polling.

If the server rebooted and the task/session is interrupted:
- Read the latest checkpoint and log via the progress tools.
- Use the predefined `resume_plan` to determine the next action.
- Resume with the predefined `resume_command`; do not invent a fresh plan after failure unless the user explicitly asks for intervention.

## Step 6 – Inspect Results

Use `read_remote_file` to inspect logs and `list_remote_files` to check artifacts.
If output artifacts are needed locally, call `sync_remote_to_local`.

## Tool Mapping

| Tool | When to use |
|------|-------------|
| `list_sandboxes` | Discover available sandboxes and compare load |
| `select_sandbox` | Switch active sandbox for the session |
| `get_active_sandbox` | Verify connection health before a long task |
| `exec_bash` | Short commands, setup, quick checks |
| `exec_bash_background_watch` | Preferred long-task launcher with watchdog, checkpoint, and resume plan |
| `watch_background_task` | Register an existing tmux task with checkpoint and resume metadata |
| `get_background_watch_progress` | Read stored + live task progress |
| `read_background_watch_log` | Read the latest remote log tail for a managed task |
| `read_background_watch_checkpoint` | Read the latest checkpoint snapshot for a managed task |
| `sync_local_to_remote` | Push code to remote before execution |
| `read_remote_file` | Inspect log files or output files |
| `list_remote_files` | Browse outputs and verify files exist |
| `sync_remote_to_local` | Pull logs/artifacts back locally when needed |

## Execution Policy

- Prefer idempotent setup commands so repeated runs are safe.
- Keep one log file per run ID; include command and timestamp in the log header.
- For long tasks, establish `checkpoint + resume_plan` before launch; this is mandatory.
- If a command fails, capture the exit code and include the failing log section in the response.
- If remote setup fails, stop and report the exact failing command plus stderr.
- Only skip this workflow when the user explicitly requests local execution.
- For long tasks, do NOT wait – use `exec_bash_background_watch` when possible.
- Check connection health with `get_active_sandbox` before starting any long task.
- Use `get_background_watch_progress` to inspect current task state during the turn.
- On timeout/connection interruption during polling, reconnect and continue polling instead of abandoning the run.
- If task interruption is caused by host reboot/session loss, resume from the predefined checkpoint-aware plan rather than generating a new ad-hoc plan.

## Command Templates

See [references/remote-runbook.md](references/remote-runbook.md) for ready-to-use templates.
