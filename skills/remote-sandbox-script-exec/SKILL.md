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

For any long-running task, reserve these paths up front:
- `logs/<run_id>.log`
- `checkpoints/<run_id>.json`
- `scripts/run_<run_id>.sh`
- `scripts/resume_<run_id>.sh`

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

**Long tasks (training, batch jobs, slow builds):** before starting anything, the agent must
materialize a checkpoint-aware run script and a resume script. This is mandatory, not optional.
Do not launch a long job as an inline one-liner unless the task is disposable and the user has
explicitly waived resume support.

Required preflight for every long task:
1. Write `scripts/run_<run_id>.sh`. It should emit progress logs and update `checkpoints/<run_id>.json`
   after each meaningful unit of work.
2. Write `scripts/resume_<run_id>.sh`. It should read the checkpoint file, skip completed work,
   and continue only the unfinished portion.
3. Choose a concrete `checkpoint_path` and keep its format stable, preferably JSON.
4. Start the job with `exec_bash_background(command=\"bash scripts/run_<run_id>.sh\", auto_resume=true, resume_command=\"bash scripts/resume_<run_id>.sh\", checkpoint_path=..., checkpoint_format=...)`.

`exec_bash_background` remains the default long-task entrypoint after these files exist. It
starts the detached tmux job, records logs, ensures the local watchdog is available, and returns
a `watch_id` for later queries. Never block with `exec_bash` on jobs that may exceed its timeout.

### Long-Task Reliability Loop (required)

For long tasks, the agent should use this exact control flow:

1. First create the checkpoint file contract plus `run_<run_id>.sh` and `resume_<run_id>.sh`.
2. Start the job with `exec_bash_background(...)`.
3. Save the returned `watch_id`. This is the primary query handle.
4. Poll with `check_background_task(watch_id=<watch_id>)` until the task reaches a terminal state.
5. Read `running`, `exit_code`, `log_tail`, and the embedded `watch` snapshot from each poll.
6. Stop only when `running=false` and the final status is clear.

Use `tmux_session` or `log_file` only as secondary debugging aids. For normal operation,
query by `watch_id` instead of rebuilding state manually from tmux.

If polling fails because of timeout, transient network failure, or SSH reconnection:
- Call `get_active_sandbox` to probe current connectivity.
- Re-select the same sandbox with `select_sandbox` if needed.
- Continue polling with the same `watch_id`; do not start a duplicate job unless you have
  confirmed the original one is gone.

For long tasks, checkpoint-aware recovery is the default requirement. Pass `auto_resume=true`
together with `resume_command` and checkpoint metadata when calling `exec_bash_background`.
The tool's watchdog handles interrupted-session monitoring and resume attempts internally. The
agent's job is to create the required files first, then keep querying `check_background_task(watch_id=...)`
and report the resulting state.

## Step 5 – Inspect Results

Use `read_remote_file` to inspect logs and `list_remote_files` to check artifacts.
If output artifacts are needed locally, call `sync_remote_to_local`.

## Tool Mapping

| Tool | When to use |
|------|-------------|
| `list_sandboxes` | Discover available sandboxes and compare load |
| `select_sandbox` | Switch active sandbox for the session |
| `get_active_sandbox` | Verify or re-probe connection health during polling |
| `exec_bash` | Short commands, setup, quick checks |
| `exec_bash_background` | Start any long-running task and register monitoring |
| `check_background_task` | Poll a background task by `watch_id` and read progress/logs |
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
- For long tasks, first create a checkpoint file plus both `run_<run_id>.sh` and `resume_<run_id>.sh`. Do not skip this unless the user explicitly says resume is unnecessary.
- The main long-task script must write observable progress and update the checkpoint after each meaningful step.
- The resume script must read the checkpoint and continue only unfinished work.
- For long tasks, do NOT wait. Start with `exec_bash_background`, with `auto_resume=true`, then query only with `check_background_task(watch_id=...)`.
- Treat the returned `watch_id` as the canonical handle for the run.
- `exec_bash_background` already handles detached tmux launch, log capture, and watchdog setup. Do not add a separate manual monitoring workflow unless debugging the MCP itself.
- Check connection health with `get_active_sandbox` before starting a long task and again if polling errors occur.
- For long tasks, continuously poll until terminal state (`running=false` and `exit_code` available).
- On timeout or connection interruption during polling, reconnect and continue polling the same `watch_id` instead of abandoning the run.
- Provide `auto_resume` plus resume/checkpoint inputs up front and let the tool manage the interrupted -> resume flow.

## Command Templates

See [references/remote-runbook.md](references/remote-runbook.md) for ready-to-use templates.
