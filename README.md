# remote-sandbox-mcp

[![PyPI version](https://img.shields.io/pypi/v/remote-sandbox-mcp)](https://pypi.org/project/remote-sandbox-mcp/)
[![Python](https://img.shields.io/pypi/pyversions/remote-sandbox-mcp)](https://pypi.org/project/remote-sandbox-mcp/)

一个把远程 SSH 服务器当作运行沙箱的 MCP Server，支持：

- **多沙箱管理**：配置多台服务器，自动查询 CPU/内存/GPU 占用率，选出最空闲的沙箱
- **持久 SSH 会话**：每个沙箱维持一条长连接，自动健康检查与断线重连，不再每次调用新建连接
- **可靠的超时控制**：双层超时（远端 `timeout` 命令 + 客户端 deadline）确保超时真的生效
- **后台长任务**：通过 `exec_bash_background` 在 tmux 中运行长任务，默认自动登记 watchdog 并返回 `watch_id`
- **macOS 守护监控**：本地 `launchd` watchdog 持续监控远端长任务，把状态写入 SQLite，在 SSH 连续失败后发本地通知，并在 tmux 丢失时按 checkpoint/resume 计划恢复
- 本地文件/目录同步到远程沙箱（增量，按 `size + mtime` 跳过未变更文件）
- 远程文件/目录同步回本地
- 在远程沙箱执行 bash 命令并返回结果
- 浏览远程文件列表与读取文件内容

## 1. 快速添加到 Claude Code

无需手动安装，直接用 `claude mcp add` 即可（依赖 [uv](https://docs.astral.sh/uv/) 自动管理运行环境）。

### 单沙箱

```bash
claude mcp add remote-sandbox \
  -e REMOTE_HOST=192.168.9.16 \
  -e REMOTE_PORT=22 \
  -e REMOTE_USER=your_user \
  -e REMOTE_PASSWORD=your_password \
  -- uvx remote-sandbox-mcp
```

### 多沙箱

```bash
claude mcp add remote-sandbox \
  -e REMOTE_SANDBOX_LIST='[{"name":"A100","host":"192.168.9.15","port":22,"user":"ubuntu","password":"xxx"},{"name":"H100","host":"192.168.9.16","port":22,"user":"ubuntu","password":"xxx"}]' \
  -- uvx remote-sandbox-mcp
```

添加后验证：

```bash
claude mcp list
```

> **作用域**：默认添加到当前项目（`-s project`）。如需全局可用，加 `-s user`。
> **更新**：重新执行同一条 `claude mcp add` 命令（会覆盖旧配置），或 `uvx` 每次自动拉取最新版本。

---

## 2. 手动安装（Codex/Claude 通用，推荐先做）

```bash
pip install remote-sandbox-mcp
# 或
uv tool install remote-sandbox-mcp
```

如果你使用项目虚拟环境，也可以安装到 `.venv`，然后在 Codex 配置里把 `command` 指向 `.venv/bin/remote-sandbox-mcp`。

---

## 3. Codex 配置指南（同一套工具）

先完成第 2 节安装，再配置 Codex MCP。

### 推荐配置（TOML）

```toml
[mcp_servers."remote-sandbox"]
command = "/absolute/path/to/remote-sandbox-mcp" # `which remote-sandbox-mcp` 可以查看到
enabled = true

[mcp_servers."remote-sandbox".env]
REMOTE_SANDBOX_LIST = '[{"name":"A100","host":"192.168.9.15","port":22,"user":"ubuntu","password":"xxx"},{"name":"H100","host":"192.168.9.16","port":22,"user":"ubuntu","password":"xxx"}]'
```

### `command` 绝对路径怎么找

```toml
[mcp_servers."remote-sandbox"]
command = "/absolute/path/to/python"
args = ["-m", "remote_sandbox_mcp.server"]
enabled = true
```

### 验证

连接后先调用 `list_sandboxes(check_resources=true)`，确认返回里的 `sandboxes` 非空。

## 4. 环境变量

认证方式支持**密码**和**私钥**两种，`password` 与 `key_file` 至少提供一个；同时提供时优先使用私钥。

### 单沙箱（向后兼容）

```bash
# 密码认证
export REMOTE_HOST=1.2.3.4
export REMOTE_PORT=22
export REMOTE_USER=your_user
export REMOTE_PASSWORD=your_password

# 私钥认证
export REMOTE_HOST=1.2.3.4
export REMOTE_USER=your_user
export REMOTE_KEY_FILE=~/.ssh/id_ed25519
export REMOTE_KEY_PASSPHRASE=           # 有加密 passphrase 才需要填
```

### 多沙箱（推荐）

```bash
export REMOTE_SANDBOX_LIST='[
  {"name": "gpu1", "host": "10.0.0.1", "user": "ubuntu", "password": "secret1"},
  {"name": "gpu2", "host": "10.0.0.2", "user": "ubuntu", "key_file": "~/.ssh/id_ed25519"},
  {"name": "L20",  "host": "10.0.0.3", "user": "root",   "key_file": "~/.ssh/id_rsa", "key_passphrase": "mypass"}
]'
```

字段说明：
| 字段 | 必填 | 说明 |
|------|------|------|
| `name` | 否 | 沙箱标识符，默认使用 host |
| `host` | 是 | SSH 地址 |
| `port` | 否 | SSH 端口，默认 22 |
| `user` | 是 | 用户名 |
| `password` | 二选一 | 密码认证 |
| `key_file` | 二选一 | 私钥文件路径（支持 `~` 展开），支持 Ed25519 / RSA / ECDSA / DSS |
| `key_passphrase` | 否 | 私钥的加密 passphrase（无加密则留空）|

## 5. 启动 MCP Server

```bash
remote-sandbox-mcp
```

使用 `stdio` 传输，适合被 MCP Client 作为子进程拉起。

## 6. MCP Client 配置示例

### 单沙箱

```json
{
  "mcpServers": {
    "remote-sandbox": {
      "command": "remote-sandbox-mcp",
      "env": {
        "REMOTE_HOST": "192.168.9.16",
        "REMOTE_PORT": "22",
        "REMOTE_USER": "ubuntu",
        "REMOTE_PASSWORD": "mypassword"
      }
    }
  }
}
```

### 多沙箱

```json
{
  "mcpServers": {
    "remote-sandbox": {
      "command": "remote-sandbox-mcp",
      "env": {
        "REMOTE_SANDBOX_LIST": "[{\"name\":\"gpu1\",\"host\":\"10.0.0.1\",\"user\":\"ubuntu\",\"password\":\"s1\"},{\"name\":\"gpu2\",\"host\":\"10.0.0.2\",\"user\":\"ubuntu\",\"password\":\"s2\"}]"
      }
    }
  }
}
```

## 7. 可用工具

### 沙箱管理

#### `list_sandboxes`
列出所有已配置的沙箱及连接状态。

参数：
- `check_resources` (bool, 默认 `false`)：是否同时查询每个沙箱的 CPU/内存/GPU 占用率与 `idle_score`（0=全忙，1=全空）

#### `select_sandbox`
将某个沙箱设为当前会话的活跃沙箱，后续所有工具调用默认使用它。

参数：
- `sandbox_name` (str, 必填)

#### `get_active_sandbox`
返回当前活跃沙箱及其连接健康状态（`connection_alive`）。

---

### 命令执行

#### `exec_bash`
在远端执行 bash 命令，适合短任务（< 2 分钟）。

参数：
- `command` (str, 必填)
- `cwd` (str, 可选)：切换到该目录后执行
- `timeout_s` (int, 默认 120)：超时秒数（双层保障，真正生效）
- `max_output_chars` (int, 默认 20000)
- `sandbox_name` (str, 可选)：临时覆盖活跃沙箱

返回额外字段：`timed_out: true`（超时时）、`connection_error: true`（连接断开时）

#### `exec_bash_background`
在远端 tmux 中以后台方式运行长任务，立即返回。输出通过 `tee` 写入日志文件，并在末尾追加 `EXIT_CODE=<n>`。

从 `0.6.x` 开始，这是**推荐的长任务入口**：
- 默认自动登记 watchdog，并返回 `watch_id` / `watch_query_id`
- 在 macOS 上默认自动确保本地 `launchd` watchdog 已安装并启动
- 如果提供 `checkpoint_*` + `resume_command` / `resume_plan_json`，watchdog 会在 SSH 中断恢复后继续检查，并在 tmux 丢失时按计划恢复

参数：
- `command` (str, 必填)：要执行的命令
- `session_name` (str, 可选)：tmux session 名，默认自动生成（`bg-<timestamp>`）
- `log_file` (str, 可选)：远端日志路径，默认 `.codex_logs/<session_name>.log`
- `cwd` (str, 可选)：工作目录
- `sandbox_name` (str, 可选)
- `watch` (bool, 默认 `true`)：是否自动登记 watchdog
- `ensure_watchdog` (bool, 默认 `true`)：是否自动安装/启动本地 watchdog
- `run_id` / `watch_name` (str, 可选)：watch 稳定标识与展示名
- `resume_command` (str, 可选)：恢复命令
- `resume_plan_json` (str, 可选)：结构化恢复计划
- `checkpoint_path` / `checkpoint_command` / `checkpoint_format`：checkpoint 读取方式
- `interval_s` (int, 默认 `300`)：watchdog 检查间隔，默认每 5 分钟
- `alert_after_failures` (int, 默认 `2`)：连续多少次 SSH 检查失败后才发本地通知/事件
- `resume_delay_s` (int, 默认 `300`)：tmux 丢失后等待多久再尝试 resume
- `notify_local` (bool, 默认 `true`)：在 macOS 上对严重事件发本地通知
- `webhook_url` / `event_command`：watchdog 事件回调
- `auto_resume` / `max_resume_attempts`：自动恢复策略
- `metadata_json` (str, 可选)：附加 JSON 元数据
- `codex_wakeup` / `codex_command`：为 watchdog 自动生成本地 Codex 事件命令

#### `check_background_task`
查询后台 tmux 任务的运行状态与最新日志。

参数：
- `tmux_session` (str, 可选)：`exec_bash_background` 返回的 session 名
- `log_file` (str, 可选)：日志路径（`exec_bash_background` 返回的值）
- `watch_id` (int, 可选)：如果你已经拿到了 `watch_id`，可以直接只传这个
- `last_n_lines` (int, 默认 50)：返回日志尾部行数
- `sandbox_name` (str, 可选)

返回：`running`（是否仍在运行）、`exit_code`（任务结束后解析自日志）、`log_tail`、`watch_id`

---

### 长任务守护

以下工具用于在 **macOS 本机** 安装一个常驻 watchdog。watchdog 独立于 MCP `stdio` 进程，因此 Codex/Claude 会话结束后仍会继续轮询后台任务。

正常情况下，你**不需要**先手动调用 `install_macos_watchdog()`。
直接调用 `exec_bash_background()` 即可；它默认会在后台自动确保 watchdog 已安装/启动，并为这次长任务登记 watch。

#### `install_macos_watchdog`
可选的预装/诊断入口：安装或刷新 `launchd` 守护进程，并可把当前 MCP 环境里的沙箱配置持久化到本地配置文件。

参数：
- `start_now` (bool, 默认 `true`)：安装后立即启动 `launchd` agent
- `persist_current_sandboxes` (bool, 默认 `true`)：把当前 `REMOTE_SANDBOX_LIST` / 单沙箱环境变量写入本地配置文件

#### `uninstall_macos_watchdog`
移除 `launchd` 守护进程。

#### `get_watchdog_status`
查看 watchdog 的 `launchd` 状态、最近心跳、SQLite 路径和当前 watch 数量。

#### `watch_background_task`
登记一个已经在远端 `tmux` 中运行的长任务，让 watchdog 后续持续检查。推荐同时提供 `checkpoint` 和 `resume_plan`，这样 watchdog 才能在远端中断后按既定计划恢复。

如果只是启动新任务，优先用 `exec_bash_background`。`watch_background_task` 更适合“任务已经在远端跑起来了，现在补登记 watchdog”。

参数：
- `tmux_session` (str, 必填)
- `log_file` (str, 必填)
- `sandbox_name` (str, 可选)：默认当前活跃沙箱
- `run_id` (str, 可选)：长任务的稳定标识
- `name` (str, 可选)：便于识别的 watch 名称
- `cwd` (str, 可选)：恢复命令的远端工作目录
- `launch_command` (str, 可选)：原始启动命令
- `resume_command` (str, 可选)：中断后要重新执行的命令
- `resume_plan_json` (str, 可选)：结构化恢复计划，建议至少包含 `resume_command` 和 checkpoint 信息
- `checkpoint_path` (str, 可选)：远端 checkpoint 文件路径
- `checkpoint_format` (str, 默认 `text`)：`text` 或 `json`
- `checkpoint_command` (str, 可选)：如果 checkpoint 需要自定义读取逻辑，可提供 shell 命令
- `interval_s` (int, 默认 `300`)：检查间隔，默认每 5 分钟
- `max_log_lines` (int, 默认 `80`)
- `webhook_url` (str, 可选)：收到事件时 POST JSON
- `event_command` (str, 可选)：收到事件时在本机执行的 shell 命令
- `auto_resume` (bool, 默认 `false`)：当远端恢复可连接且 tmux 丢失时，自动尝试 `resume_command`
- `max_resume_attempts` (int, 默认 `1`)
- `ensure_watchdog` (bool, 默认 `true`)：如果本机是 macOS，自动确保 `launchd` watchdog 正在运行
- `notify_local` (bool, 默认 `true`)：对严重事件发本地通知
- `alert_after_failures` (int, 默认 `2`)：SSH 连续失败多少次后才告警
- `resume_delay_s` (int, 默认 `300`)：tmux 丢失后等待多久再触发 resume
- `metadata_json` (str, 可选)：附加 JSON 元数据

#### `exec_bash_background_watch`
`exec_bash_background` 的兼容别名。新代码建议直接调用 `exec_bash_background`。

参数：
- 继承 `exec_bash_background` 的 `command`, `session_name`, `log_file`, `cwd`, `sandbox_name`
- 继承 `watch_background_task` 的 `run_id`, `watch_name`, `resume_command`, `resume_plan_json`, `checkpoint_path`, `checkpoint_format`, `checkpoint_command`, `interval_s`, `webhook_url`, `event_command`, `auto_resume`, `max_resume_attempts`, `metadata_json`
- `ensure_watchdog` (bool, 默认 `true`)：自动安装/启动本地 watchdog
- `codex_wakeup` (bool, 默认 `false`)：仅当你明确想用另一个本地 Codex 处理事件时才启用

#### `list_background_watches`
列出全部 watch。参数：`status`（可选）

#### `get_background_watch`
查看单个 watch。参数：`watch_id`

#### `cancel_background_watch`
停止某个 watch 的监控。参数：`watch_id`

#### `list_background_watch_events`
查看 watchdog 事件。参数：`watch_id`（可选）、`limit`

#### `get_background_watch_progress`
读取一个 watch 的当前进度，返回：
- SQLite 中存储的最近状态
- 当前远端 log tail
- 当前 checkpoint 快照

参数：
- `watch_id`
- `refresh_live` (bool, 默认 `true`)
- `log_lines` (int, 默认 `80`)

#### `read_background_watch_log`
读取一个 watch 的最新远端日志尾部。

参数：
- `watch_id`
- `last_n_lines`

#### `read_background_watch_checkpoint`
读取一个 watch 的最新 checkpoint 快照。

参数：
- `watch_id`
- `max_bytes`

watchdog 事件会写入本地 SQLite，同时把事件 JSON 落盘到 `db_path` 同目录下的 `events/`。如果设置了 `event_command`，watchdog 会附带以下环境变量：
- `RSMCP_EVENT_FILE`
- `RSMCP_EVENT_JSON`
- `RSMCP_EVENT_TYPE`
- `RSMCP_WATCH_ID`
- `RSMCP_SANDBOX_NAME`
- `RSMCP_TMUX_SESSION`
- `RSMCP_LOG_FILE`
- `RSMCP_SUGGESTED_PROMPT`

如果你明确需要让另一个本地 Codex 处理事件，可以把 `event_command` 配成：

```sh
codex exec "$RSMCP_SUGGESTED_PROMPT"
```

#### 推荐长任务脚本约定

为了让 watchdog 的自动恢复真正可靠，建议让每个长任务都满足下面几个约定：

1. 把实际工作拆成可重复执行的分片，不要把全部逻辑塞进一个不可恢复的大循环。
2. 持续写日志，并在日志末尾保留 `EXIT_CODE=<n>`，这样 watchdog 才能区分“已完成”和“tmux 被打断”。
3. 持续写 checkpoint。简单任务可以写文本；复杂任务建议写 JSON，记录已完成分片、剩余队列、产物路径等。
4. 提供一个 `resume_command` 或 `resume_plan_json.resume_command`。这个命令应当读取 checkpoint，只继续做未完成部分。
5. resume 脚本应重新创建同名 tmux session。watchdog 默认会用原来的 `tmux_session` 名称去拉起恢复任务。

一个简化示例：

```bash
python train.py \
  --workdir runs/exp-01 \
  --checkpoint runs/exp-01/progress.json \
  --resume
```

对应的 MCP 调用可以是：

```json
{
  "command": "python train.py --workdir runs/exp-01 --checkpoint runs/exp-01/progress.json",
  "cwd": "~/sandboxes/project",
  "checkpoint_path": "runs/exp-01/progress.json",
  "checkpoint_format": "json",
  "resume_command": "python train.py --workdir runs/exp-01 --checkpoint runs/exp-01/progress.json --resume",
  "auto_resume": true
}
```

默认恢复流程：
- watchdog 每 5 分钟检查一次任务状态
- SSH 连续 2 次检查失败后，触发事件并在 macOS 上发本地通知
- 连接恢复后，如果 tmux session 已消失且日志里还没有 `EXIT_CODE=...`，watchdog 会等待 `resume_delay_s` 到期后，用原 session 名启动 `resume_command`

---

### 文件操作

所有文件操作工具新增 `sandbox_name` 参数（可选，临时覆盖活跃沙箱）。

#### `list_remote_files`
列出远程目录内容。参数：`remote_path`, `recursive`, `max_entries`, `sandbox_name`

#### `read_remote_file`
读取远程文件。参数：`remote_path`, `max_bytes`, `sandbox_name`

#### `sync_local_to_remote`
本地文件或目录同步到远端（SFTP，增量）。
参数：`local_path`, `remote_path`, `delete_extras`, `excludes`, `exclude_file`, `sandbox_name`

#### `sync_remote_to_local`
远端文件或目录同步到本地（SFTP，增量）。
参数：`remote_path`, `local_path`, `excludes`, `exclude_file`, `sandbox_name`

---

## 8. 多沙箱典型工作流

```
1. list_sandboxes(check_resources=True)
   → 查看每个沙箱的 idle_score、GPU 占用等

2. select_sandbox(sandbox_name="gpu1")
   → 选择最空闲的沙箱，后续调用都用它

3. get_active_sandbox()
   → 确认连接正常（connection_alive: true）

4. exec_bash_background(
     command="python train.py --epochs 100",
     cwd="~/projects/mymodel",
     session_name="train-001"
   )
   → 后台启动，立即返回 {tmux_session, log_file, watch_id}

5. check_background_task(
     watch_id=<id>
   )
   → 每隔几分钟轮询一次，查看日志尾部和运行状态
```

## 9. macOS Watchdog 工作流

```text
1. exec_bash_background(
     command="python train.py --epochs 100",
     cwd="~/projects/mymodel",
     run_id="train-001",
     watch_name="train-001",
     auto_resume=true,
     checkpoint_path="~/projects/mymodel/run_state.json",
     checkpoint_format="json",
     resume_command="bash scripts/resume_train.sh",
     resume_plan_json='{"resume_command":"bash scripts/resume_train.sh","checkpoint_path":"~/projects/mymodel/run_state.json","checkpoint_format":"json"}'
   )
   → 远端启动 tmux 任务
   → 如本机 watchdog 尚未安装，会自动安装/启动
   → 自动登记 watchdog，返回 watch_id

2. check_background_task(watch_id=<id>)
   → 直接按 watch_id 查询远端任务状态

3. get_watchdog_status()
   → 查看 launchd 是否正常、最近心跳是否新鲜

4. get_background_watch_progress(watch_id=<id>)
   → 查看当前 log tail + checkpoint + 最近状态

5. list_background_watch_events(watch_id=<id>)
   → 查看 ssh_unreachable / interrupted / resume_started / completed 等事件
```

如果你想提前把本地 `launchd` watchdog 装好，或者单独排查守护进程状态，再手动调用 `install_macos_watchdog()`。

## 10. 注意事项

- 首次连接会自动接受主机指纹（`AutoAddPolicy`）。生产环境建议改成固定 known_hosts 校验。
- 后台任务需要远端已安装 `tmux`（大多数 Linux 发行版默认有）。
- `delete_extras=true` 会删除远端不在本地的文件，请谨慎使用。
- 持久会话每 30 秒做一次健康检查，断线后下一次工具调用会自动重连。
- 对需要自动恢复的长任务，推荐总是提供 `checkpoint_path` 与 `resume_plan_json`；否则 watchdog 只能检测失败，无法可靠恢复。
- watchdog 会把沙箱凭据持久化到本地配置文件，当前实现未做系统钥匙串集成；请确保本机用户目录权限安全。
- `event_command` 是本机 shell 命令，只应指向你信任的脚本或 `codex` / `python` 可执行文件。
