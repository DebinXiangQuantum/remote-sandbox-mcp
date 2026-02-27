# Remote Runbook

Use these templates with the MCP tools.

---

## 0) Sandbox selection (multi-sandbox setups)

```bash
# Via MCP tools (not exec_bash) – call in order:
# 1. list_sandboxes(check_resources=True)
#    → inspect idle_score for each sandbox (0=busy, 1=idle)
# 2. select_sandbox(sandbox_name="<name of most idle sandbox>")
# 3. get_active_sandbox()   ← verify connection before long tasks
```

---

## 1) Bootstrap uv

```bash
set -euo pipefail
cd <remote_project_root>
if ! command -v uv >/dev/null 2>&1; then
  curl -LsSf https://astral.sh/uv/install.sh | sh
  export PATH="$HOME/.local/bin:$PATH"
fi
if [ ! -d .venv ]; then
  uv venv .venv
fi
if [ -f pyproject.toml ]; then
  uv sync
elif [ -f requirements.txt ]; then
  uv pip install -r requirements.txt
fi
```

---

## 2) Run short task with log capture (exec_bash)

For tasks that finish in under ~2 minutes.

```bash
set -euo pipefail
cd <remote_project_root>
RUN_ID="<run_id>"
LOG_DIR=".codex_logs"
LOG_FILE="$LOG_DIR/${RUN_ID}.log"
mkdir -p "$LOG_DIR"
{
  echo "== run_id: $RUN_ID"
  echo "== started_at: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "== command: <task_command>"
  uv run bash -lc "<task_command>"
} 2>&1 | tee -a "$LOG_FILE"
```

---

## 3) Run long task in background with tmux (exec_bash_background)

For training, long builds, batch jobs – anything that may exceed a timeout.

**Start the task** via `exec_bash_background`:
```
command  = "uv run python train.py --epochs 100"
cwd      = "~/sandboxes/myproject"
session_name = "train-20240101"   # optional, auto-generated if empty
log_file     = "~/sandboxes/myproject/.codex_logs/train-20240101.log"
```

This returns immediately:
```json
{
  "status": "started",
  "tmux_session": "train-20240101",
  "log_file": "~/sandboxes/myproject/.codex_logs/train-20240101.log"
}
```

**Poll progress** via `check_background_task` (call every few minutes):
```
tmux_session = "train-20240101"
log_file     = "~/sandboxes/myproject/.codex_logs/train-20240101.log"
last_n_lines = 50
```

Response fields:
- `running: true` → task still in progress
- `running: false` + `exit_code: 0` → task completed successfully
- `running: false` + `exit_code: <non-zero>` → task failed; read log_tail for details
- `log_tail` → last N lines of output for progress inspection

**Manual tmux commands** (via exec_bash if needed):
```bash
# List all running sessions
tmux list-sessions

# Attach to inspect interactively (only useful with a real terminal)
tmux attach -t <session_name>

# Kill a runaway session
tmux kill-session -t <session_name>

# Tail the log directly
tail -f <log_file>
```

---

## 4) Read recent log lines

Prefer `read_remote_file` for the full log (with `max_bytes`).
For very large logs use exec_bash:

```bash
tail -n 200 <remote_project_root>/.codex_logs/<run_id>.log
```

---

## 5) Common task commands

- Python script: `python scripts/job.py --arg value`
- Pytest: `pytest -q`
- Module entry: `python -m app.main`
- Bash pipeline: `bash scripts/run_pipeline.sh`
- GPU training: `uv run python train.py --device cuda`

---

## 6) Check resource usage on a sandbox

Via `list_sandboxes(check_resources=True)`. The response includes:

```json
{
  "sandboxes": [{
    "name": "gpu1",
    "resources": {
      "cpu": {"load_1m": 1.2, "load_5m": 1.5, "count": 16},
      "memory": {"total_mb": 64000, "used_mb": 12000, "used_pct": 18.7},
      "gpu": [{"index": 0, "util_pct": 42, "mem_used_mb": 8000, "mem_total_mb": 24000}],
      "idle_score": 0.72
    }
  }]
}
```

`idle_score` weights: CPU load 40%, memory usage 40%, GPU utilization 20%.
Pick the sandbox with the highest `idle_score`.
