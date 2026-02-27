# remote-sandbox-mcp

[![PyPI version](https://img.shields.io/pypi/v/remote-sandbox-mcp)](https://pypi.org/project/remote-sandbox-mcp/)
[![Python](https://img.shields.io/pypi/pyversions/remote-sandbox-mcp)](https://pypi.org/project/remote-sandbox-mcp/)

一个把远程 SSH 服务器当作运行沙箱的 MCP Server，支持：

- **多沙箱管理**：配置多台服务器，自动查询 CPU/内存/GPU 占用率，选出最空闲的沙箱
- **持久 SSH 会话**：每个沙箱维持一条长连接，自动健康检查与断线重连，不再每次调用新建连接
- **可靠的超时控制**：双层超时（远端 `timeout` 命令 + 客户端 deadline）确保超时真的生效
- **后台长任务**：通过 `exec_bash_background` 在 tmux 中运行长任务，用 `check_background_task` 异步轮询进度
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

## 2. 手动安装（可选）

```bash
pip install remote-sandbox-mcp
# 或
uv tool install remote-sandbox-mcp
```

## 3. 环境变量

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

## 3. 启动 MCP Server

```bash
remote-sandbox-mcp
```

使用 `stdio` 传输，适合被 MCP Client 作为子进程拉起。

## 4. MCP Client 配置示例

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

## 5. 可用工具

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

参数：
- `command` (str, 必填)：要执行的命令
- `session_name` (str, 可选)：tmux session 名，默认自动生成（`bg-<timestamp>`）
- `log_file` (str, 可选)：远端日志路径，默认 `.codex_logs/<session_name>.log`
- `cwd` (str, 可选)：工作目录
- `sandbox_name` (str, 可选)

#### `check_background_task`
查询后台 tmux 任务的运行状态与最新日志。

参数：
- `tmux_session` (str, 必填)：`exec_bash_background` 返回的 session 名
- `log_file` (str, 可选)：日志路径（`exec_bash_background` 返回的值）
- `last_n_lines` (int, 默认 50)：返回日志尾部行数
- `sandbox_name` (str, 可选)

返回：`running`（是否仍在运行）、`exit_code`（任务结束后解析自日志）、`log_tail`

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

## 6. 多沙箱典型工作流

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
   → 后台启动，立即返回 {tmux_session, log_file}

5. check_background_task(
     tmux_session="train-001",
     log_file="~/projects/mymodel/.codex_logs/train-001.log"
   )
   → 每隔几分钟轮询一次，查看日志尾部和运行状态
```

## 7. 注意事项

- 首次连接会自动接受主机指纹（`AutoAddPolicy`）。生产环境建议改成固定 known_hosts 校验。
- 后台任务需要远端已安装 `tmux`（大多数 Linux 发行版默认有）。
- `delete_extras=true` 会删除远端不在本地的文件，请谨慎使用。
- 持久会话每 30 秒做一次健康检查，断线后下一次工具调用会自动重连。
