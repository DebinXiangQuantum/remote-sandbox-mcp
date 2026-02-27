---
name: remote-sandbox-script-exec
description: Execute script/test/build tasks in an SSH remote sandbox instead of local machine. Use when the agent needs to run Python, shell, test, or build commands. Enforces: sandbox selection, uv environment bootstrap, code sync, execution with log capture, result inspection, and optional artifact sync back to local.
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

## Step 4 – Execute Task

**Short tasks (< 2 minutes):** use `exec_bash` with `tee` to a log file.

**Long tasks (training, batch jobs, slow builds):** use `exec_bash_background` to start
the command in a detached tmux session. This returns immediately with a `tmux_session`
name and `log_file` path. Then use `check_background_task` to poll progress periodically.
Never block with `exec_bash` on jobs that may exceed its timeout.

## Step 5 – Inspect Results

Use `read_remote_file` to inspect logs and `list_remote_files` to check artifacts.
If output artifacts are needed locally, call `sync_remote_to_local`.

## Tool Mapping

| Tool | When to use |
|------|-------------|
| `list_sandboxes` | Discover available sandboxes and compare load |
| `select_sandbox` | Switch active sandbox for the session |
| `get_active_sandbox` | Verify connection health before a long task |
| `exec_bash` | Short commands, setup, quick checks |
| `exec_bash_background` | Long-running tasks (training, pipelines, slow builds) |
| `check_background_task` | Poll a background task's tmux session and log tail |
| `sync_local_to_remote` | Push code to remote before execution |
| `read_remote_file` | Inspect log files or output files |
| `list_remote_files` | Browse outputs and verify files exist |
| `sync_remote_to_local` | Pull logs/artifacts back locally when needed |

## Execution Policy

- Prefer idempotent setup commands so repeated runs are safe.
- Keep one log file per run ID; include command and timestamp in the log header.
- If a command fails, capture the exit code and include the failing log section in the response.
- If remote setup fails, stop and report the exact failing command plus stderr.
- Only skip this workflow when the user explicitly requests local execution.
- For long tasks, do NOT wait – use `exec_bash_background` + `check_background_task`.
- Check connection health with `get_active_sandbox` before starting any long task.

## Command Templates

See [references/remote-runbook.md](references/remote-runbook.md) for ready-to-use templates.
