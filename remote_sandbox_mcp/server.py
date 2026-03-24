from __future__ import annotations

import argparse
import fnmatch
import functools
import json
import os
import posixpath
import signal
import shutil
import shlex
import stat
import subprocess
import sys
import threading
import time
import traceback
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Optional

import paramiko
from mcp.server.fastmcp import FastMCP
from remote_sandbox_mcp.watchdog_daemon import WatchdogDaemon
from remote_sandbox_mcp.watchdog_service import (
    get_launch_agent_status,
    install_launch_agent,
    uninstall_launch_agent,
)
from remote_sandbox_mcp.watchdog_store import (
    DEFAULT_ALERT_AFTER_FAILURES,
    DEFAULT_MAX_LOG_LINES,
    DEFAULT_RESUME_DELAY_S,
    DEFAULT_WATCH_INTERVAL_S,
    HEARTBEAT_STALE_S,
    config_path as watchdog_config_path,
    create_watch,
    create_transfer_task,
    db_path as watchdog_db_path,
    get_daemon_meta,
    get_transfer_task,
    get_watch,
    init_db as init_watchdog_db,
    list_events as list_watchdog_events,
    list_watches as list_watchdog_watches,
    save_sandbox_config,
    cancel_watch as cancel_watchdog_watch,
    update_transfer_task,
)

mcp = FastMCP("remote-sandbox")
_EXPOSE_ADVANCED_TOOLS = os.environ.get(
    "REMOTE_SANDBOX_EXPOSE_ADVANCED_TOOLS",
    "",
).strip().lower() in {"1", "true", "yes", "on"}


def _safe_tool(fn: Callable) -> Callable:
    """Decorator: catch any unhandled exception from a tool and return it as
    {"error": "..."} so MCP always gets a valid JSON response."""
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except Exception as exc:
            return {"error": f"{type(exc).__name__}: {exc}"}
    return wrapper


def _optional_tool(*, enabled: bool) -> Callable[[Callable], Callable]:
    def decorator(fn: Callable) -> Callable:
        wrapped = _safe_tool(fn)
        if enabled:
            return mcp.tool()(wrapped)
        return wrapped

    return decorator


DEFAULT_EXCLUDES = [
    ".git/*",
    ".idea/*",
    ".vscode/*",
    "__pycache__/*",
    "*.pyc",
    "node_modules/*",
]

_CONNECT_TIMEOUT = 15.0
_HEALTH_CHECK_INTERVAL = 30.0  # seconds between keep-alive probes
_SSH_KEEPALIVE_INTERVAL_S = 15  # seconds between Paramiko keepalives
_CHANNEL_OPEN_TIMEOUT = 15.0
_SFTP_CHANNEL_TIMEOUT = 30.0


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


_INLINE_SYNC_MAX_FILES = min(_env_int("REMOTE_SANDBOX_INLINE_SYNC_MAX_FILES", 10), 10)
_INLINE_SYNC_MAX_BYTES = min(
    _env_int("REMOTE_SANDBOX_INLINE_SYNC_MAX_BYTES", 1 * 1024 * 1024),
    1 * 1024 * 1024,
)


# ---------------------------------------------------------------------------
# Sandbox configuration
# ---------------------------------------------------------------------------


@dataclass
class SandboxConfig:
    name: str
    host: str
    user: str
    password: str = ""
    port: int = 22
    key_file: str = ""        # Path to private key file, e.g. "~/.ssh/id_ed25519"
    key_passphrase: str = ""  # Passphrase for encrypted private key (optional)


# Key types tried in order when auto-detecting key format
_KEY_CLASSES = (
    paramiko.Ed25519Key,
    paramiko.RSAKey,
    paramiko.ECDSAKey,
)


def _load_private_key(key_file: str, passphrase: str = "") -> paramiko.PKey:
    """Load a private key from *key_file*, trying all supported key types."""
    path = os.path.expanduser(key_file)
    pw: Optional[str] = passphrase if passphrase else None
    last_exc: Exception = Exception("no key types tried")
    for cls in _KEY_CLASSES:
        try:
            return cls.from_private_key_file(path, password=pw)
        except paramiko.SSHException as exc:
            last_exc = exc
        except (FileNotFoundError, PermissionError):
            raise  # re-raise filesystem errors immediately
    raise ValueError(
        f"Cannot load private key from {key_file!r}: "
        f"unsupported key type or wrong passphrase. ({last_exc})"
    )


def _load_sandbox_configs() -> list[SandboxConfig]:
    """Load sandbox configs from REMOTE_SANDBOX_LIST or legacy single-sandbox env vars.

    REMOTE_SANDBOX_LIST must be a JSON array of objects. Auth is either password
    or key-based; at least one of password / key_file must be provided.

    Password auth fields: password
    Key auth fields:      key_file, key_passphrase (optional)

    Example (password):
      '[{"name":"gpu1","host":"10.0.0.1","user":"ubuntu","password":"secret"}]'
    Example (key):
      '[{"name":"gpu1","host":"10.0.0.1","user":"ubuntu","key_file":"~/.ssh/id_ed25519"}]'
    """
    sandbox_list_json = os.environ.get("REMOTE_SANDBOX_LIST", "").strip()
    if sandbox_list_json:
        try:
            items = json.loads(sandbox_list_json)
        except json.JSONDecodeError as exc:
            # Show the raw bytes around the bad position so it's diagnosable
            pos = exc.pos if exc.pos is not None else 0
            snippet = repr(sandbox_list_json[max(0, pos - 5): pos + 10])
            raise ValueError(
                f"REMOTE_SANDBOX_LIST is not valid JSON: {exc}. "
                f"Raw bytes around error position {pos}: {snippet}"
            ) from exc
        if not isinstance(items, list):
            raise ValueError("REMOTE_SANDBOX_LIST must be a JSON array")
        configs: list[SandboxConfig] = []
        for i, item in enumerate(items):
            if not isinstance(item, dict):
                raise ValueError(f"REMOTE_SANDBOX_LIST[{i}] must be a JSON object")
            if not item.get("host"):
                raise ValueError(f"REMOTE_SANDBOX_LIST[{i}] missing required field: 'host'")
            if not item.get("user"):
                raise ValueError(f"REMOTE_SANDBOX_LIST[{i}] missing required field: 'user'")
            if not item.get("password") and not item.get("key_file"):
                raise ValueError(
                    f"REMOTE_SANDBOX_LIST[{i}] must have either 'password' or 'key_file'"
                )
            configs.append(
                SandboxConfig(
                    name=item.get("name") or item["host"],
                    host=item["host"],
                    user=item["user"],
                    password=item.get("password", ""),
                    port=int(item.get("port", 22)),
                    key_file=item.get("key_file", ""),
                    key_passphrase=item.get("key_passphrase", ""),
                )
            )
        return configs

    # Legacy single-sandbox env vars
    host = os.environ.get("REMOTE_HOST", "").strip()
    if not host:
        return []
    user = os.environ.get("REMOTE_USER", "").strip()
    if not user:
        raise ValueError("REMOTE_USER is required when REMOTE_HOST is set")
    password = os.environ.get("REMOTE_PASSWORD", "").strip()
    key_file = os.environ.get("REMOTE_KEY_FILE", "").strip()
    key_passphrase = os.environ.get("REMOTE_KEY_PASSPHRASE", "").strip()
    if not password and not key_file:
        raise ValueError(
            "Either REMOTE_PASSWORD or REMOTE_KEY_FILE is required when REMOTE_HOST is set"
        )
    port = int(os.environ.get("REMOTE_PORT", "22"))
    return [
        SandboxConfig(
            name=host,
            host=host,
            user=user,
            password=password,
            port=port,
            key_file=key_file,
            key_passphrase=key_passphrase,
        )
    ]


# ---------------------------------------------------------------------------
# Persistent SSH session
# ---------------------------------------------------------------------------


class SandboxSession:
    """Maintains a persistent, auto-reconnecting SSH connection to one sandbox."""

    def __init__(self, config: SandboxConfig) -> None:
        self.config = config
        self._client: Optional[paramiko.SSHClient] = None
        self._lock = threading.Lock()
        self._last_health_check: float = 0.0

    @property
    def id(self) -> str:
        return self.config.name

    def _make_client(self) -> paramiko.SSHClient:
        cfg = self.config
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # Resolve authentication: key-based takes priority over password
        pkey: Optional[paramiko.PKey] = None
        if cfg.key_file:
            try:
                pkey = _load_private_key(cfg.key_file, cfg.key_passphrase)
            except (FileNotFoundError, PermissionError) as exc:
                raise ConnectionError(
                    f"Cannot read private key file {cfg.key_file!r}: {exc}"
                ) from exc
            except ValueError as exc:
                raise ConnectionError(str(exc)) from exc

        connect_kwargs: dict = dict(
            hostname=cfg.host,
            port=cfg.port,
            username=cfg.user,
            look_for_keys=False,
            allow_agent=False,
            timeout=_CONNECT_TIMEOUT,
            auth_timeout=_CONNECT_TIMEOUT,
            banner_timeout=_CONNECT_TIMEOUT,
        )
        if pkey is not None:
            connect_kwargs["pkey"] = pkey
            auth_method = f"key ({cfg.key_file})"
        else:
            connect_kwargs["password"] = cfg.password
            auth_method = "password"

        try:
            client.connect(**connect_kwargs)
        except PermissionError as exc:
            client.close()
            raise ConnectionError(
                f"SSH connect blocked to {cfg.host}:{cfg.port}. "
                "Outbound network may be denied by the runtime sandbox."
            ) from exc
        except paramiko.AuthenticationException as exc:
            client.close()
            raise ConnectionError(
                f"SSH authentication failed ({auth_method}) for "
                f"{cfg.user}@{cfg.host}:{cfg.port}. "
                "Check credentials and sshd settings."
            ) from exc
        except OSError as exc:
            client.close()
            raise ConnectionError(
                f"SSH connect failed to {cfg.host}:{cfg.port}: {exc}"
            ) from exc
        transport = client.get_transport()
        if transport is not None:
            try:
                transport.set_keepalive(_SSH_KEEPALIVE_INTERVAL_S)
            except Exception:
                pass
        setattr(client, "_rsmcp_session", self)
        return client

    def _reset_client_locked(self) -> None:
        if self._client is not None:
            try:
                self._client.close()
            except Exception:
                pass
            self._client = None
        self._last_health_check = 0.0
        _REMOTE_HOME_CACHE.pop(self.id, None)

    def is_alive(self) -> bool:
        """Non-blocking check: True if the current transport is still active."""
        if self._client is None:
            return False
        transport = self._client.get_transport()
        if transport is None or not transport.is_active():
            return False
        try:
            transport.send_ignore()
            return True
        except Exception:
            return False

    def ensure_connected(self) -> paramiko.SSHClient:
        """Return a live SSHClient, transparently reconnecting if the session dropped."""
        with self._lock:
            if self._client is not None:
                transport = self._client.get_transport()
                if transport is None or not transport.is_active():
                    self._reset_client_locked()

            now = time.monotonic()
            if self._client is not None and now - self._last_health_check > _HEALTH_CHECK_INTERVAL:
                if not self.is_alive():
                    self._reset_client_locked()
                self._last_health_check = now

            if self._client is None:
                self._client = self._make_client()
                self._last_health_check = now
            return self._client

    def mark_broken(self) -> None:
        with self._lock:
            self._reset_client_locked()

    def reconnect(self) -> paramiko.SSHClient:
        with self._lock:
            self._reset_client_locked()
            self._client = self._make_client()
            self._last_health_check = time.monotonic()
            return self._client

    def close(self) -> None:
        self.mark_broken()


# ---------------------------------------------------------------------------
# Global session registry
# ---------------------------------------------------------------------------

_SESSIONS: dict[str, SandboxSession] = {}
_ACTIVE_SANDBOX: Optional[str] = None
_REGISTRY_LOCK = threading.Lock()
_INIT_ERROR: Optional[str] = None  # surface config errors to tool callers
_REMOTE_HOME_CACHE: dict[str, str] = {}


def _init_sessions() -> None:
    global _ACTIVE_SANDBOX, _INIT_ERROR
    try:
        configs = _load_sandbox_configs()
    except Exception as exc:
        _INIT_ERROR = str(exc)
        configs = []
    with _REGISTRY_LOCK:
        for cfg in configs:
            _SESSIONS[cfg.name] = SandboxSession(cfg)
        if configs and _ACTIVE_SANDBOX is None:
            _ACTIVE_SANDBOX = configs[0].name


_init_sessions()


def _get_session(sandbox_name: str = "") -> SandboxSession:
    if _INIT_ERROR:
        raise ValueError(f"Sandbox configuration error: {_INIT_ERROR}")
    name = sandbox_name.strip() or _ACTIVE_SANDBOX
    if not name:
        raise ValueError(
            "No sandbox configured. Set REMOTE_HOST/REMOTE_USER/REMOTE_PASSWORD "
            "or REMOTE_SANDBOX_LIST."
        )
    with _REGISTRY_LOCK:
        session = _SESSIONS.get(name)
    if session is None:
        raise ValueError(
            f"Unknown sandbox: {name!r}. Available: {list(_SESSIONS.keys())}"
        )
    return session


# ---------------------------------------------------------------------------
# Resource monitoring
# ---------------------------------------------------------------------------

# Single compound shell command; each section delimited by =KEY= markers.
_RESOURCE_CMD = (
    "echo '=CPU=' && (cat /proc/loadavg 2>/dev/null || uptime); "
    "echo '=NCPU=' && (nproc 2>/dev/null || echo 1); "
    "echo '=MEM=' && (free -m 2>/dev/null | awk 'NR==2{print $2, $3, $4}' || echo '0 0 0'); "
    "echo '=GPU=' && (nvidia-smi --query-gpu=index,utilization.gpu,memory.used,memory.total "
    "--format=csv,noheader,nounits 2>/dev/null || echo 'no_gpu')"
)


def _parse_resource_output(output: str) -> dict:
    sections: dict[str, str] = {}
    current_key: Optional[str] = None
    buf: list[str] = []
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith("=") and stripped.endswith("=") and len(stripped) > 2:
            if current_key is not None:
                sections[current_key] = "\n".join(buf).strip()
            current_key = stripped[1:-1]
            buf = []
        elif current_key is not None:
            buf.append(line)
    if current_key is not None:
        sections[current_key] = "\n".join(buf).strip()

    result: dict = {"cpu": {}, "memory": {}, "gpu": []}

    # CPU load averages (from /proc/loadavg: "0.10 0.15 0.12 1/432 12345")
    try:
        loads = sections.get("CPU", "").split()
        result["cpu"]["load_1m"] = float(loads[0])
        result["cpu"]["load_5m"] = float(loads[1])
        result["cpu"]["load_15m"] = float(loads[2])
    except (IndexError, ValueError):
        result["cpu"]["load_1m"] = 0.0

    # CPU count
    try:
        result["cpu"]["count"] = int(sections.get("NCPU", "1").strip())
    except ValueError:
        result["cpu"]["count"] = 1

    # Memory (free -m: total used free ...)
    try:
        parts = sections.get("MEM", "0 0 0").split()
        total, used, free = int(parts[0]), int(parts[1]), int(parts[2])
        result["memory"] = {
            "total_mb": total,
            "used_mb": used,
            "free_mb": free,
            "used_pct": round(used / total * 100, 1) if total > 0 else 0.0,
        }
    except (IndexError, ValueError):
        result["memory"] = {"total_mb": 0, "used_mb": 0, "free_mb": 0, "used_pct": 0.0}

    # GPU (nvidia-smi: index, util%, mem_used_mb, mem_total_mb)
    gpu_text = sections.get("GPU", "no_gpu").strip()
    if gpu_text and gpu_text != "no_gpu":
        for line in gpu_text.splitlines():
            try:
                idx, util, mem_used, mem_total = [p.strip() for p in line.split(",")]
                mem_total_i = int(mem_total)
                mem_used_i = int(mem_used)
                result["gpu"].append(
                    {
                        "index": int(idx),
                        "util_pct": int(util),
                        "mem_used_mb": mem_used_i,
                        "mem_total_mb": mem_total_i,
                        "mem_used_pct": (
                            round(mem_used_i / mem_total_i * 100, 1) if mem_total_i > 0 else 0.0
                        ),
                    }
                )
            except (ValueError, TypeError):
                pass

    # Composite idle score: 0 = fully busy, 1 = fully idle
    ncpu = max(result["cpu"].get("count", 1), 1)
    cpu_ratio = min(result["cpu"].get("load_1m", 0.0) / ncpu, 1.0)
    mem_ratio = result["memory"].get("used_pct", 50.0) / 100.0
    gpu_ratio = (
        sum(g["util_pct"] for g in result["gpu"]) / len(result["gpu"]) / 100.0
        if result["gpu"]
        else 0.0
    )
    result["idle_score"] = round(
        (1.0 - cpu_ratio) * 0.4 + (1.0 - mem_ratio) * 0.4 + (1.0 - gpu_ratio) * 0.2,
        3,
    )
    return result


def _query_resources(session: SandboxSession) -> dict:
    """Query resource usage on a sandbox. Returns error key on failure, never raises."""
    try:
        client = session.ensure_connected()
        r = _exec_on_channel(client, _RESOURCE_CMD, timeout_s=10, max_output_chars=4000)
        if r["exit_code"] not in (0, 1) and not r["stdout"].strip():
            return {"error": f"Resource query failed (exit {r['exit_code']}): {r['stderr'][:200]}"}
        return _parse_resource_output(r["stdout"])
    except Exception as exc:
        return {"error": str(exc)}


def _probe_connection_status(session: SandboxSession) -> dict[str, object]:
    """Return whether a sandbox is currently usable for the next command.

    Unlike ``is_alive()``, this may reconnect when the cached transport is stale,
    so it better reflects what users care about: whether the MCP can execute now.
    """
    try:
        client = session.ensure_connected()
        transport = client.get_transport()
        if transport is None or not transport.is_active():
            session.mark_broken()
            return {"alive": False, "error": "SSH transport is not active"}
        try:
            transport.send_ignore()
        except Exception as exc:
            session.mark_broken()
            return {"alive": False, "error": str(exc)}
        channel = None
        try:
            channel = _open_ssh_session(
                transport,
                open_timeout_s=_CHANNEL_OPEN_TIMEOUT,
                channel_timeout_s=_CHANNEL_OPEN_TIMEOUT,
            )
        except Exception as exc:
            session.mark_broken()
            return {"alive": False, "error": f"SSH channel open failed: {exc}"}
        finally:
            if channel is not None:
                try:
                    channel.close()
                except Exception:
                    pass
        return {"alive": True}
    except Exception as exc:
        return {"alive": False, "error": str(exc)}


def _remote_home(session: SandboxSession) -> str:
    cached = _REMOTE_HOME_CACHE.get(session.id)
    if cached:
        return cached
    client = session.ensure_connected()
    result = _exec_on_channel(client, 'printf "%s" "$HOME"', timeout_s=10, max_output_chars=200)
    home = result.get("stdout", "").strip()
    if result.get("exit_code") != 0 or not home:
        raise ValueError("Unable to resolve remote home directory")
    _REMOTE_HOME_CACHE[session.id] = home
    return home


def _expand_remote_user_path(session: SandboxSession, path: str) -> str:
    raw = path.strip()
    if not raw:
        return ""
    if raw == "~":
        return _remote_home(session)
    if raw.startswith("~/"):
        return posixpath.join(_remote_home(session), raw[2:])
    return raw


def _resolve_watch_path(session: SandboxSession, cwd: str, path: str) -> str:
    raw_path = path.strip()
    if not raw_path:
        return ""
    raw_cwd = cwd.strip()
    resolved_cwd = _expand_remote_user_path(session, raw_cwd)
    if resolved_cwd and not posixpath.isabs(resolved_cwd):
        resolved_cwd = posixpath.normpath(posixpath.join(_remote_home(session), resolved_cwd))
    resolved_path = _expand_remote_user_path(session, raw_path)
    if posixpath.isabs(resolved_path):
        return posixpath.normpath(resolved_path)

    base_dir = resolved_cwd or _remote_home(session)
    normalized_path = posixpath.normpath(resolved_path)
    if raw_cwd and not posixpath.isabs(raw_cwd):
        normalized_cwd = posixpath.normpath(_expand_remote_user_path(session, raw_cwd))
        cwd_prefix = normalized_cwd.rstrip("/") + "/"
        if normalized_path == normalized_cwd or normalized_path.startswith(cwd_prefix):
            suffix = posixpath.relpath(normalized_path, normalized_cwd)
            return posixpath.normpath(posixpath.join(base_dir, suffix))
    return posixpath.normpath(posixpath.join(base_dir, normalized_path))


def _resolve_background_paths(
    session: SandboxSession,
    *,
    cwd: str,
    log_file: str,
    session_name: str,
) -> tuple[str, str, str]:
    raw_cwd = cwd.strip()
    resolved_cwd = _expand_remote_user_path(session, raw_cwd)
    if resolved_cwd and not posixpath.isabs(resolved_cwd):
        resolved_cwd = posixpath.normpath(posixpath.join(_remote_home(session), resolved_cwd))
    raw_log = log_file.strip() or posixpath.join(".codex_logs", f"{session_name}.log")
    resolved_log = _expand_remote_user_path(session, raw_log)
    if posixpath.isabs(resolved_log):
        watch_log = resolved_log
    else:
        base_dir = resolved_cwd or _remote_home(session)
        normalized_log = posixpath.normpath(resolved_log)
        if raw_cwd and not posixpath.isabs(raw_cwd):
            normalized_cwd = posixpath.normpath(_expand_remote_user_path(session, raw_cwd))
            cwd_prefix = normalized_cwd.rstrip("/") + "/"
            if normalized_log == normalized_cwd or normalized_log.startswith(cwd_prefix):
                suffix = posixpath.relpath(normalized_log, normalized_cwd)
                watch_log = posixpath.normpath(posixpath.join(base_dir, suffix))
            else:
                watch_log = posixpath.normpath(posixpath.join(base_dir, normalized_log))
        else:
            watch_log = posixpath.normpath(posixpath.join(base_dir, normalized_log))

    if posixpath.isabs(resolved_log):
        command_log = resolved_log
    elif resolved_cwd:
        command_log = posixpath.relpath(watch_log, resolved_cwd)
    else:
        command_log = watch_log
    return resolved_cwd, command_log, watch_log


def _background_script_path(log_file: str, session_name: str) -> str:
    log_dir = posixpath.dirname(log_file) or ".codex_logs"
    return posixpath.join(log_dir, ".rsmcp", f"{session_name}.sh")


def _build_background_script(
    *,
    command: str,
    cwd: str,
    session_name: str,
    log_file: str,
) -> str:
    command_preview = " ".join(command.split())[:120]
    lines = [
        "#!/usr/bin/env bash",
        "set -uo pipefail",
        f"mkdir -p {shlex.quote(posixpath.dirname(log_file) or '.')}",
    ]
    if cwd:
        lines.append(f"cd {shlex.quote(cwd)}")
    lines.extend(
        [
            "{",
            f"  printf '%s\\n' {shlex.quote(f'== session: {session_name}')}",
            "  printf '== started_at: %s\\n' \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"",
            f"  printf '%s\\n' {shlex.quote(f'== command: {command_preview}')}",
            f"  {command}",
            "  rc=$?",
            "  printf 'EXIT_CODE=%s\\n' \"$rc\"",
            f"}} 2>&1 | tee -a {shlex.quote(log_file)}",
            "rc=${PIPESTATUS[0]}",
            "exit \"$rc\"",
        ]
    )
    return "\n".join(lines)


def _build_tmux_new_session_command(
    session_name: str,
    *,
    script_path: str,
    script_content: str,
) -> str:
    heredoc = "__RSMCP_BG__"
    return "\n".join(
        [
            f"mkdir -p {shlex.quote(posixpath.dirname(script_path) or '.')}",
            f"cat > {shlex.quote(script_path)} <<'{heredoc}'",
            script_content,
            heredoc,
            f"chmod 700 {shlex.quote(script_path)}",
            f"tmux new-session -d -s {shlex.quote(session_name)} bash {shlex.quote(script_path)}",
        ]
    )


# ---------------------------------------------------------------------------
# Core exec helper with reliable two-layer timeout
# ---------------------------------------------------------------------------


def _is_retriable_transport_error(exc: Exception) -> bool:
    if isinstance(exc, (ConnectionError, EOFError, OSError, paramiko.SSHException)):
        return True
    message = str(exc).lower()
    return any(
        token in message
        for token in (
            "transport is not active",
            "channel closed",
            "channel open failure",
            "socket is closed",
            "connection reset",
            "broken pipe",
        )
    )


def _open_ssh_session(
    transport: paramiko.Transport,
    *,
    open_timeout_s: float,
    channel_timeout_s: float,
):
    channel = transport.open_session(timeout=open_timeout_s)
    channel.settimeout(float(channel_timeout_s))
    return channel


def _open_sftp_client(client: paramiko.SSHClient) -> paramiko.SFTPClient:
    transport = client.get_transport()
    if transport is None or not transport.is_active():
        raise ConnectionError("SSH transport is not active; the connection may have dropped")
    channel = _open_ssh_session(
        transport,
        open_timeout_s=_CHANNEL_OPEN_TIMEOUT,
        channel_timeout_s=_SFTP_CHANNEL_TIMEOUT,
    )
    try:
        channel.invoke_subsystem("sftp")
        return paramiko.SFTPClient(channel)
    except Exception:
        try:
            channel.close()
        except Exception:
            pass
        raise


def _exec_on_channel(
    client: paramiko.SSHClient,
    command: str,
    timeout_s: int = 120,
    max_output_chars: int = 20000,
) -> dict:
    """Execute *command* via a fresh channel on *client*.

    Timeout enforcement is two-layered:
    1. Remote side: the command is wrapped in ``timeout <N>s bash -c '...'`` which
       sends SIGTERM/SIGKILL to the remote process after *timeout_s* seconds.
    2. Client side: a monotonic deadline (timeout_s + 10 s) guards the read loop,
       closing the channel if the remote wrapper itself hangs.

    Returns a dict with keys: exit_code, stdout, stderr, command, and optionally
    timed_out=True or connection_error=True.
    """
    session: Optional[SandboxSession] = getattr(client, "_rsmcp_session", None)
    wrapped = f"timeout {timeout_s}s bash -c {shlex.quote(command)}"
    attempts_remaining = 1 if session is not None else 0
    active_client = client

    while True:
        transport = active_client.get_transport()
        if transport is None or not transport.is_active():
            if session is not None and attempts_remaining > 0:
                active_client = session.reconnect()
                attempts_remaining -= 1
                continue
            raise ConnectionError("SSH transport is not active; the connection may have dropped")

        stdout_buf: list[bytes] = []
        stderr_buf: list[bytes] = []
        deadline = time.monotonic() + timeout_s + 10
        channel = None

        try:
            channel = _open_ssh_session(
                transport,
                open_timeout_s=min(float(timeout_s + 10), _CHANNEL_OPEN_TIMEOUT),
                channel_timeout_s=float(timeout_s + 10),
            )
            channel.exec_command(wrapped)

            while True:
                if time.monotonic() > deadline:
                    channel.close()
                    out = b"".join(stdout_buf).decode("utf-8", errors="replace")
                    return _compact_payload({
                        "exit_code": -1,
                        "stdout": out[-max_output_chars:] if len(out) > max_output_chars else out,
                        "stderr": (
                            f"[TIMEOUT] Client-side deadline exceeded after {timeout_s}s. "
                            "The remote process may still be running."
                        ),
                        "timed_out": True,
                    })

                if channel.recv_ready():
                    data = channel.recv(65536)
                    if data:
                        stdout_buf.append(data)
                if channel.recv_stderr_ready():
                    data = channel.recv_stderr(65536)
                    if data:
                        stderr_buf.append(data)

                if channel.exit_status_ready():
                    while channel.recv_ready():
                        data = channel.recv(65536)
                        if data:
                            stdout_buf.append(data)
                    while channel.recv_stderr_ready():
                        data = channel.recv_stderr(65536)
                        if data:
                            stderr_buf.append(data)
                    break

                time.sleep(0.05)

            exit_code = channel.recv_exit_status()
        except Exception as exc:
            if (
                session is not None
                and attempts_remaining > 0
                and not stdout_buf
                and not stderr_buf
                and _is_retriable_transport_error(exc)
            ):
                session.mark_broken()
                active_client = session.reconnect()
                attempts_remaining -= 1
                continue

            out = b"".join(stdout_buf).decode("utf-8", errors="replace")
            err = b"".join(stderr_buf).decode("utf-8", errors="replace")
            return _compact_payload({
                "exit_code": -1,
                "stdout": out[-max_output_chars:] if len(out) > max_output_chars else out,
                "stderr": (err + f"\n[CONNECTION ERROR] {exc}").strip(),
                "connection_error": True,
            })
        finally:
            if channel is not None:
                try:
                    channel.close()
                except Exception:
                    pass

        out_text = b"".join(stdout_buf).decode("utf-8", errors="replace")
        err_text = b"".join(stderr_buf).decode("utf-8", errors="replace")

        if len(out_text) > max_output_chars:
            out_text = out_text[:max_output_chars] + "\n...<truncated>"
        if len(err_text) > max_output_chars:
            err_text = err_text[:max_output_chars] + "\n...<truncated>"

        result: dict = {
            "exit_code": exit_code,
            "stdout": out_text,
            "stderr": err_text,
        }
        if exit_code == 124:
            result["timed_out"] = True
            result["stderr"] = (
                result["stderr"]
                + f"\n[TIMEOUT] Remote process killed by timeout after {timeout_s}s"
            ).strip()
        return _compact_payload(result)


# ---------------------------------------------------------------------------
# Path / exclude helpers (unchanged from v0.1.0)
# ---------------------------------------------------------------------------


def _normalize_remote(path: str) -> str:
    if not path:
        return "."
    return posixpath.normpath(path)


def _resolve_remote_input_path(session: SandboxSession, path: str) -> str:
    return _normalize_remote(_expand_remote_user_path(session, path))


def _normalize_pattern(pattern: str) -> str:
    normalized = pattern.strip().replace("\\", "/")
    if not normalized:
        return ""
    negated = normalized.startswith("!")
    if negated:
        normalized = normalized[1:].strip()
    while normalized.startswith("./"):
        normalized = normalized[2:]
    normalized = normalized.lstrip("/")
    if normalized.endswith("/"):
        normalized = f"{normalized}*"
    if not normalized:
        return ""
    return f"!{normalized}" if negated else normalized


def _rule_matches(rel_path: str, pattern: str) -> bool:
    if fnmatch.fnmatch(rel_path, pattern):
        return True
    if "/" not in pattern:
        return any(fnmatch.fnmatch(part, pattern) for part in rel_path.split("/") if part)
    return False


def _is_excluded(rel_path: str, rules: Iterable[str], is_dir: bool = False) -> bool:
    rel = rel_path.strip("/")
    if not rel:
        return False
    candidates = [rel, f"{rel}/"] if is_dir else [rel]
    excluded = False
    for raw_rule in rules:
        rule = raw_rule.strip()
        if not rule:
            continue
        negated = rule.startswith("!")
        if negated:
            rule = rule[1:].strip()
        if not rule:
            continue
        if any(_rule_matches(candidate, rule) for candidate in candidates):
            excluded = not negated
    return excluded


def _load_excludes_file(exclude_file: str) -> list[str]:
    path = Path(exclude_file).expanduser()
    if not path.is_absolute():
        path = Path.cwd() / path
    path = path.resolve()
    if not path.exists():
        raise ValueError(f"exclude_file does not exist: {path}")
    if not path.is_file():
        raise ValueError(f"exclude_file must be a file: {path}")
    rules: list[str] = []
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            normalized = _normalize_pattern(stripped)
            if normalized:
                rules.append(normalized)
    return rules


def _build_exclude_rules(excludes: list[str] | None, exclude_file: str | None) -> list[str]:
    rules: list[str] = []
    for pattern in DEFAULT_EXCLUDES:
        normalized = _normalize_pattern(pattern)
        if normalized:
            rules.append(normalized)
    if exclude_file:
        rules.extend(_load_excludes_file(exclude_file))
    for pattern in excludes or []:
        normalized = _normalize_pattern(pattern)
        if normalized:
            rules.append(normalized)
    return rules


# ---------------------------------------------------------------------------
# SFTP helpers (unchanged from v0.1.0)
# ---------------------------------------------------------------------------


def _ensure_remote_dir(sftp: paramiko.SFTPClient, remote_dir: str) -> None:
    remote_dir = _normalize_remote(remote_dir)
    if remote_dir in (".", "/"):
        return
    parts = remote_dir.split("/")
    prefix = "/" if remote_dir.startswith("/") else ""
    current = prefix
    for part in parts:
        if not part:
            continue
        current = posixpath.join(current, part) if current else part
        try:
            sftp.stat(current)
        except FileNotFoundError:
            sftp.mkdir(current)


def _upload_tree(
    sftp: paramiko.SFTPClient,
    local_root: Path,
    remote_root: str,
    exclude_rules: list[str],
    progress_callback: Optional[Callable[[dict], None]] = None,
) -> tuple[int, int, int, set[str]]:
    uploaded_files = 0
    skipped_files = 0
    uploaded_dirs = 0
    sent: set[str] = set()

    def report(current_path: str = "") -> None:
        if progress_callback is None:
            return
        progress_callback(
            {
                "phase": "uploading",
                "current_path": current_path,
                "uploaded_dirs": uploaded_dirs,
                "uploaded_files": uploaded_files,
                "skipped_files": skipped_files,
                "deleted_dirs": 0,
                "deleted_files": 0,
            }
        )

    _ensure_remote_dir(sftp, remote_root)

    for root, dirs, files in os.walk(local_root):
        rel_root = str(Path(root).relative_to(local_root)).replace("\\", "/")
        if rel_root == ".":
            rel_root = ""

        filtered_dirs = []
        for d in dirs:
            rel = f"{rel_root}/{d}".strip("/")
            if _is_excluded(rel, exclude_rules, is_dir=True):
                continue
            filtered_dirs.append(d)
        dirs[:] = filtered_dirs

        remote_dir = remote_root if not rel_root else posixpath.join(remote_root, rel_root)
        _ensure_remote_dir(sftp, remote_dir)
        if rel_root:
            sent.add(rel_root)
            uploaded_dirs += 1
            report(rel_root)

        for f in files:
            rel = f"{rel_root}/{f}".strip("/")
            if _is_excluded(rel, exclude_rules):
                continue
            local_file = Path(root) / f
            local_stat = local_file.stat()
            remote_file = posixpath.join(remote_root, rel)
            remote_parent = posixpath.dirname(remote_file)
            _ensure_remote_dir(sftp, remote_parent)
            sent.add(rel)
            try:
                remote_stat = sftp.stat(remote_file)
                same_size = remote_stat.st_size == local_stat.st_size
                same_mtime = abs(int(remote_stat.st_mtime) - int(local_stat.st_mtime)) <= 1
                if same_size and same_mtime:
                    skipped_files += 1
                    report(rel)
                    continue
            except FileNotFoundError:
                pass
            sftp.put(str(local_file), remote_file)
            sftp.utime(remote_file, (int(local_stat.st_atime), int(local_stat.st_mtime)))
            uploaded_files += 1
            report(rel)

    return uploaded_dirs, uploaded_files, skipped_files, sent


def _walk_remote(
    sftp: paramiko.SFTPClient, root: str, prefix: str = ""
) -> tuple[set[str], set[str]]:
    files: set[str] = set()
    dirs: set[str] = set()
    for item in sftp.listdir_attr(root):
        name = item.filename
        remote_path = posixpath.join(root, name)
        rel = f"{prefix}/{name}".strip("/")
        if stat.S_ISDIR(item.st_mode):
            dirs.add(rel)
            sub_files, sub_dirs = _walk_remote(sftp, remote_path, rel)
            files.update(sub_files)
            dirs.update(sub_dirs)
        else:
            files.add(rel)
    return files, dirs


def _safe_remove_remote_extras(
    sftp: paramiko.SFTPClient,
    remote_root: str,
    sent_paths: set[str],
    exclude_rules: list[str],
    progress_callback: Optional[Callable[[dict], None]] = None,
) -> tuple[int, int]:
    deleted_files = 0
    deleted_dirs = 0

    def report(current_path: str = "") -> None:
        if progress_callback is None:
            return
        progress_callback(
            {
                "phase": "deleting",
                "current_path": current_path,
                "uploaded_dirs": 0,
                "uploaded_files": 0,
                "skipped_files": 0,
                "deleted_dirs": deleted_dirs,
                "deleted_files": deleted_files,
            }
        )

    try:
        remote_files, remote_dirs = _walk_remote(sftp, remote_root)
    except FileNotFoundError:
        return 0, 0
    for rel in sorted(remote_files):
        if _is_excluded(rel, exclude_rules):
            continue
        if rel not in sent_paths:
            sftp.remove(posixpath.join(remote_root, rel))
            deleted_files += 1
            report(rel)
    for rel in sorted(remote_dirs, key=lambda x: x.count("/"), reverse=True):
        if _is_excluded(rel, exclude_rules, is_dir=True):
            continue
        if rel not in sent_paths:
            try:
                sftp.rmdir(posixpath.join(remote_root, rel))
                deleted_dirs += 1
                report(rel)
            except OSError:
                pass
    return deleted_dirs, deleted_files


def _download_tree(
    sftp: paramiko.SFTPClient,
    remote_root: str,
    local_root: Path,
    exclude_rules: list[str],
) -> tuple[int, int, int]:
    downloaded_files = 0
    skipped_files = 0
    created_dirs = 0
    local_root.mkdir(parents=True, exist_ok=True)

    def recurse(current_remote: str, current_rel: str = "") -> None:
        nonlocal downloaded_files, created_dirs, skipped_files
        for item in sftp.listdir_attr(current_remote):
            name = item.filename
            rel = f"{current_rel}/{name}".strip("/")
            if _is_excluded(rel, exclude_rules, is_dir=stat.S_ISDIR(item.st_mode)):
                continue
            remote_path = posixpath.join(current_remote, name)
            local_path = local_root / rel
            if stat.S_ISDIR(item.st_mode):
                existed = local_path.exists()
                local_path.mkdir(parents=True, exist_ok=True)
                if not existed:
                    created_dirs += 1
                recurse(remote_path, rel)
            else:
                local_path.parent.mkdir(parents=True, exist_ok=True)
                if local_path.exists():
                    local_stat = local_path.stat()
                    same_size = local_stat.st_size == item.st_size
                    same_mtime = abs(int(local_stat.st_mtime) - int(item.st_mtime)) <= 1
                    if same_size and same_mtime:
                        skipped_files += 1
                        continue
                sftp.get(remote_path, str(local_path))
                os.utime(local_path, (int(item.st_atime), int(item.st_mtime)))
                downloaded_files += 1

    recurse(remote_root)
    return created_dirs, downloaded_files, skipped_files


def _resolve_remote_file_target(sftp: paramiko.SFTPClient, remote_path: str, filename: str) -> str:
    remote_target = _normalize_remote(remote_path)
    try:
        attr = sftp.stat(remote_target)
        if stat.S_ISDIR(attr.st_mode):
            return _normalize_remote(posixpath.join(remote_target, filename))
    except FileNotFoundError:
        pass
    if remote_path.endswith("/") or remote_target in (".", "/"):
        return _normalize_remote(posixpath.join(remote_target, filename))
    return remote_target


def _resolve_local_file_target(local_path: str, remote_file_path: str) -> Path:
    local_target = Path(local_path).expanduser()
    if local_target.exists() and local_target.is_dir():
        return local_target.resolve() / posixpath.basename(remote_file_path)
    if local_path.endswith("/") or local_path.endswith("\\"):
        return local_target.resolve() / posixpath.basename(remote_file_path)
    return local_target.resolve()


def _single_file_candidates(path_arg: str, abs_path: Path) -> list[str]:
    candidates: list[str] = []
    raw = path_arg.strip().replace("\\", "/")
    while raw.startswith("./"):
        raw = raw[2:]
    raw = raw.lstrip("/")
    if raw:
        candidates.append(raw)
    candidates.append(abs_path.name)
    deduped: list[str] = []
    seen: set[str] = set()
    for item in candidates:
        if item not in seen:
            seen.add(item)
            deduped.append(item)
    return deduped


def _compact_payload(value):
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            compacted = _compact_payload(item)
            if compacted is None:
                continue
            if compacted == "":
                continue
            if isinstance(compacted, (dict, list)) and not compacted:
                continue
            result[key] = compacted
        return result
    if isinstance(value, list):
        result = []
        for item in value:
            compacted = _compact_payload(item)
            if compacted is None:
                continue
            if compacted == "":
                continue
            if isinstance(compacted, (dict, list)) and not compacted:
                continue
            result.append(compacted)
        return result
    return value


def _summarize_transfer_progress(progress: dict | None) -> dict:
    if not isinstance(progress, dict):
        return {}
    summary: dict = {}
    synced_type = str(progress.get("synced_type", "")).strip()
    if synced_type:
        summary["synced_type"] = synced_type
    phase = str(progress.get("phase", "")).strip()
    if phase:
        summary["phase"] = phase
    current_path = str(progress.get("current_path", "")).strip()
    if current_path:
        summary["current_path"] = current_path
    duration = progress.get("duration_s")
    if isinstance(duration, (int, float)) and duration > 0:
        summary["duration_s"] = duration
    for key in (
        "uploaded_dirs",
        "uploaded_files",
        "skipped_files",
        "deleted_dirs",
        "deleted_files",
        "created_dirs",
        "downloaded_files",
    ):
        value = progress.get(key)
        if isinstance(value, int) and value > 0:
            summary[key] = value
    return summary


# ---------------------------------------------------------------------------
# MCP tools – sandbox management
# ---------------------------------------------------------------------------


@mcp.tool()
@_safe_tool
def list_sandboxes(check_resources: bool = False) -> dict:
    """List all configured sandboxes with connection info.

    When check_resources=True, queries each sandbox for CPU/memory/GPU usage and
    returns an idle_score (0=fully busy, 1=fully idle) to help pick the best sandbox.
    Use select_sandbox to make the most idle one active.
    """
    with _REGISTRY_LOCK:
        sessions = dict(_SESSIONS)

    # Always include diagnostic info so the caller can see what went wrong
    env_sandbox_list = os.environ.get("REMOTE_SANDBOX_LIST", "")
    env_host = os.environ.get("REMOTE_HOST", "")
    diagnostics = {
        "REMOTE_SANDBOX_LIST_set": bool(env_sandbox_list),
        "REMOTE_SANDBOX_LIST_length": len(env_sandbox_list),
        "REMOTE_HOST_set": bool(env_host),
        "init_error": _INIT_ERROR,
    }

    if _INIT_ERROR:
        return {
            "error": f"Sandbox configuration error: {_INIT_ERROR}",
            "hint": (
                "Check REMOTE_SANDBOX_LIST is valid JSON and contains host/user "
                "and password or key_file for each sandbox."
            ),
            "diagnostics": diagnostics,
            "sandboxes": [],
        }
    if not sessions:
        return {
            "error": (
                "No sandboxes configured. "
                "Set REMOTE_HOST/REMOTE_USER/REMOTE_PASSWORD or REMOTE_SANDBOX_LIST."
            ),
            "diagnostics": diagnostics,
            "sandboxes": [],
        }
    sandboxes = []
    for name, session in sessions.items():
        connection = _probe_connection_status(session)
        info: dict = {
            "name": name,
            "host": session.config.host,
            "port": session.config.port,
            "user": session.config.user,
            "is_active": name == _ACTIVE_SANDBOX,
            "connection_alive": bool(connection["alive"]),
        }
        if not connection["alive"]:
            info["connection_error"] = str(connection.get("error", ""))
        if check_resources:
            info["resources"] = _query_resources(session)
        sandboxes.append(info)
    return {"active_sandbox": _ACTIVE_SANDBOX, "sandboxes": sandboxes}


@mcp.tool()
@_safe_tool
def select_sandbox(sandbox_name: str) -> dict:
    """Set the active sandbox for all subsequent tool calls in this session.

    Call list_sandboxes(check_resources=True) first to compare idle scores and
    choose the least loaded sandbox. When the active sandbox becomes overloaded,
    call this again with a less loaded alternative.
    """
    global _ACTIVE_SANDBOX
    with _REGISTRY_LOCK:
        available = list(_SESSIONS.keys())
        exists = sandbox_name in _SESSIONS
    if not exists:
        return {"error": f"Unknown sandbox: {sandbox_name!r}", "available": available}
    _ACTIVE_SANDBOX = sandbox_name
    return {"active_sandbox": _ACTIVE_SANDBOX, "status": "selected"}


@mcp.tool()
@_safe_tool
def get_active_sandbox() -> dict:
    """Return the currently active sandbox and its live connection health.

    Use this to verify the session is still connected before running a long task.
    If connection_alive is False, the next tool call will auto-reconnect.
    """
    if _INIT_ERROR:
        return {"active_sandbox": None, "error": f"Sandbox configuration error: {_INIT_ERROR}"}
    if not _ACTIVE_SANDBOX:
        return {"active_sandbox": None, "error": "No active sandbox configured"}
    with _REGISTRY_LOCK:
        session = _SESSIONS.get(_ACTIVE_SANDBOX)
    if session is None:
        return {"active_sandbox": _ACTIVE_SANDBOX, "error": "Session object not found"}
    connection = _probe_connection_status(session)
    return {
        "active_sandbox": _ACTIVE_SANDBOX,
        "host": session.config.host,
        "port": session.config.port,
        "user": session.config.user,
        "connection_alive": bool(connection["alive"]),
        **(
            {"connection_error": str(connection.get("error", ""))}
            if not connection["alive"]
            else {}
        ),
    }


# ---------------------------------------------------------------------------
# MCP tools – command execution
# ---------------------------------------------------------------------------


@mcp.tool()
@_safe_tool
def exec_bash(
    command: str,
    cwd: str | None = None,
    timeout_s: int = 120,
    max_output_chars: int = 20000,
    sandbox_name: str = "",
) -> dict:
    """Execute a bash command on the remote sandbox and return stdout/stderr/exit_code.

    The command is wrapped in ``timeout <timeout_s>s`` on the remote side for
    reliable termination, plus a client-side deadline. timed_out=True is set in
    the response when the timeout fires.

    sandbox_name: override the active sandbox for this call (optional).
    """
    if not command.strip():
        raise ValueError("command cannot be empty")
    if timeout_s <= 0:
        raise ValueError("timeout_s must be positive")

    session = _get_session(sandbox_name)
    client = session.ensure_connected()

    remote_cmd = command
    if cwd:
        remote_cmd = f"cd {cwd} && {command}"

    return _exec_on_channel(client, remote_cmd, timeout_s=timeout_s, max_output_chars=max_output_chars)


@mcp.tool()
@_safe_tool
def exec_bash_background(
    command: str,
    session_name: str = "",
    log_file: str = "",
    cwd: str = "",
    sandbox_name: str = "",
    watch: bool = True,
    ensure_watchdog: bool = True,
    run_id: str = "",
    watch_name: str = "",
    resume_command: str = "",
    resume_plan_json: str = "",
    checkpoint_path: str = "",
    checkpoint_format: str = "text",
    checkpoint_command: str = "",
    interval_s: int = DEFAULT_WATCH_INTERVAL_S,
    max_log_lines: int = DEFAULT_MAX_LOG_LINES,
    webhook_url: str = "",
    event_command: str = "",
    auto_resume: bool = False,
    max_resume_attempts: int = 1,
    metadata_json: str = "",
    notify_local: bool = True,
    alert_after_failures: int = DEFAULT_ALERT_AFTER_FAILURES,
    resume_delay_s: int = DEFAULT_RESUME_DELAY_S,
    codex_wakeup: bool = False,
    codex_command: str = "",
) -> dict:
    """Start a long-running command in a detached tmux session on the remote sandbox.

    Output (stdout + stderr) is streamed via ``tee`` into *log_file* for async
    inspection. An EXIT_CODE=<n> line is appended to the log when the command ends.

    On macOS, this also auto-registers a local watchdog watch by default and
    returns the resulting watch id for later polling.

    Recommended for: training jobs, long builds, batch pipelines, anything that
    would exceed exec_bash's timeout or that you want to check on periodically.

    Args:
        command: Shell command to run (can be multi-line or a script invocation).
        session_name: tmux session name; auto-generated from timestamp if empty.
        log_file: Remote path for captured output; defaults to
                  .codex_logs/<session_name>.log relative to cwd.
        cwd: Working directory on the remote host.
        sandbox_name: Override the active sandbox for this call (optional).
        watch: Whether to register a watchdog watch and return watch_id.
    """
    if not command.strip():
        raise ValueError("command cannot be empty")
    if interval_s <= 0:
        raise ValueError("interval_s must be positive")
    if max_log_lines <= 0:
        raise ValueError("max_log_lines must be positive")
    if max_resume_attempts < 0:
        raise ValueError("max_resume_attempts must be zero or positive")
    if alert_after_failures < 1:
        raise ValueError("alert_after_failures must be positive")
    if resume_delay_s < 0:
        raise ValueError("resume_delay_s must be zero or positive")

    session = _get_session(sandbox_name)
    client = session.ensure_connected()

    tmux_session_name = session_name.strip() or f"bg-{int(time.time())}"
    resolved_cwd, command_log, watch_log = _resolve_background_paths(
        session,
        cwd=cwd,
        log_file=log_file,
        session_name=tmux_session_name,
    )
    script_content = _build_background_script(
        command=command,
        cwd=resolved_cwd,
        session_name=tmux_session_name,
        log_file=command_log,
    )
    tmux_cmd = _build_tmux_new_session_command(
        tmux_session_name,
        script_path=_background_script_path(watch_log, tmux_session_name),
        script_content=script_content,
    )

    launch_recovered = False
    launch_check = None
    result = _exec_on_channel(client, tmux_cmd, timeout_s=30, max_output_chars=2000)
    if result["exit_code"] != 0:
        if result.get("timed_out") or result.get("connection_error"):
            try:
                launch_check = check_background_task(
                    tmux_session=tmux_session_name,
                    log_file=watch_log,
                    sandbox_name=session.id,
                    last_n_lines=20,
                )
            except Exception:
                launch_check = None
        if isinstance(launch_check, dict):
            log_tail = str(launch_check.get("log_tail", ""))
            if launch_check.get("running") or launch_check.get("exit_code") is not None or (
                log_tail and "[log file not found]" not in log_tail
            ):
                launch_recovered = True
                result["exit_code"] = 0
                result["stdout"] = launch_check.get("log_tail", "")
        if not launch_recovered:
            stderr = result.get("stderr", "")
            stdout = result.get("stdout", "")
            combined = (stderr + "\n" + stdout).lower()

            if result.get("timed_out"):
                diagnosis = (
                    "The tmux startup command itself timed out (30 s). "
                    "The remote host may be under heavy load or the shell is hanging on login. "
                    "Try running exec_bash('tmux new-session -d -s test echo ok') to diagnose."
                )
            elif result.get("connection_error"):
                diagnosis = f"SSH connection error while launching tmux: {stderr.strip()}"
            elif "duplicate session" in combined or "already exists" in combined:
                diagnosis = (
                    f"A tmux session named {tmux_session_name!r} already exists on the remote host. "
                    "Use a different session_name or kill the existing session first with: "
                    f"tmux kill-session -t {tmux_session_name}"
                )
            elif "command not found" in combined or "no tmux" in combined:
                diagnosis = (
                    "tmux is not installed on the remote host. "
                    "Install it with: sudo apt-get install tmux  (Debian/Ubuntu) "
                    "or: sudo yum install tmux  (CentOS/RHEL)"
                )
            else:
                diagnosis = (
                    "Unknown failure. Check stderr/stdout above for details. "
                    "Common causes: tmux not installed, duplicate session name, "
                    "or permission denied on the log directory."
                )

            return _compact_payload({
                "error": "Failed to start background task in tmux",
                "diagnosis": diagnosis,
                "stderr": stderr,
                "stdout": stdout,
                "exit_code": result["exit_code"],
                "timed_out": result.get("timed_out", False),
                "connection_error": result.get("connection_error", False),
            })
    task = {
        "status": "started",
        "tmux_session": tmux_session_name,
        "log_file": watch_log,
        "sandbox": session.id,
    }
    if launch_recovered:
        task["launch_recovered"] = True
    if not watch:
        return _compact_payload(task)

    if ensure_watchdog:
        if sys.platform == "darwin":
            _ensure_watchdog_ready(
                persist_current_sandboxes=True,
                start_now=True,
            )
        else:
            init_watchdog_db()
            _persist_current_sandboxes()
    else:
        init_watchdog_db()
        _persist_current_sandboxes()

    effective_event_command = event_command
    if not effective_event_command.strip() and codex_wakeup:
        effective_event_command = _default_codex_event_command(codex_command)

    watch_result = watch_background_task(
        tmux_session=task["tmux_session"],
        log_file=task["log_file"],
        sandbox_name=sandbox_name or task["sandbox"],
        run_id=run_id.strip() or task["tmux_session"],
        name=watch_name,
        cwd=resolved_cwd,
        launch_command=command,
        resume_command=resume_command,
        resume_plan_json=resume_plan_json,
        checkpoint_path=_resolve_watch_path(session, resolved_cwd, checkpoint_path),
        checkpoint_format=checkpoint_format,
        checkpoint_command=checkpoint_command,
        interval_s=interval_s,
        max_log_lines=max_log_lines,
        webhook_url=webhook_url,
        event_command=effective_event_command,
        auto_resume=auto_resume,
        max_resume_attempts=max_resume_attempts,
        metadata_json=metadata_json,
        ensure_watchdog=False,
        notify_local=notify_local,
        alert_after_failures=alert_after_failures,
        resume_delay_s=resume_delay_s,
    )
    if isinstance(watch_result, dict) and watch_result.get("watch"):
        watch_payload = watch_result["watch"]
        task["watch_id"] = watch_payload["id"]
        return _compact_payload(task)

    return _compact_payload(task)


@mcp.tool()
@_safe_tool
def check_background_task(
    tmux_session: str = "",
    log_file: str = "",
    watch_id: int = 0,
    last_n_lines: int = 50,
    sandbox_name: str = "",
) -> dict:
    """Check the status of a background tmux task and return recent log output.

    Returns:
        running: True if the tmux session is still alive (task in progress).
        log_tail: Last *last_n_lines* lines from the log file.
        exit_code: Parsed from EXIT_CODE= line in log if task has finished,
                   else None.

    Poll this tool periodically for long tasks instead of blocking with exec_bash.
    When running=False and exit_code is present, the task is complete.
    """
    resolved_watch = None
    resolved_tmux_session = tmux_session.strip()
    resolved_log_file = log_file.strip()
    resolved_sandbox = sandbox_name.strip()
    if watch_id > 0:
        init_watchdog_db()
        resolved_watch = get_watch(watch_id, path=str(watchdog_db_path()))
        if resolved_watch is None:
            raise ValueError(f"Unknown watch id: {watch_id}")
        resolved_tmux_session = resolved_tmux_session or resolved_watch["tmux_session"]
        resolved_log_file = resolved_log_file or resolved_watch["log_file"]
        resolved_sandbox = resolved_sandbox or resolved_watch["sandbox_name"]
    if not resolved_tmux_session:
        raise ValueError("tmux_session cannot be empty")
    if last_n_lines <= 0:
        raise ValueError("last_n_lines must be positive")

    session = _get_session(resolved_sandbox)
    client = session.ensure_connected()
    if resolved_log_file:
        resolved_log_file = _expand_remote_user_path(session, resolved_log_file)

    # Check if the tmux session exists
    check_cmd = (
        f"tmux has-session -t {shlex.quote(resolved_tmux_session)} 2>/dev/null "
        f"&& echo RUNNING || echo DONE"
    )
    status_result = _exec_on_channel(client, check_cmd, timeout_s=10, max_output_chars=200)
    if status_result.get("connection_error"):
        return _compact_payload({
            "error": status_result.get("stderr", "").strip() or "SSH connection failed",
            "connection_error": True,
            "tmux_session": resolved_tmux_session,
            "watch_id": watch_id if watch_id > 0 else None,
        })
    is_running = "RUNNING" in status_result.get("stdout", "")

    log_tail = ""
    parsed_exit_code = None

    if resolved_log_file:
        tail_cmd = (
            f"tail -n {last_n_lines} {shlex.quote(resolved_log_file)} 2>/dev/null "
            f"|| echo '[log file not found]'"
        )
        log_result = _exec_on_channel(client, tail_cmd, timeout_s=15, max_output_chars=20000)
        if log_result.get("connection_error"):
            return _compact_payload({
                "error": log_result.get("stderr", "").strip() or "SSH connection failed",
                "connection_error": True,
                "tmux_session": resolved_tmux_session,
                "watch_id": watch_id if watch_id > 0 else None,
            })
        log_tail = log_result.get("stdout", "")

        # Try to extract EXIT_CODE from the log
        for line in reversed(log_tail.splitlines()):
            if line.startswith("EXIT_CODE="):
                try:
                    parsed_exit_code = int(line.split("=", 1)[1].strip())
                except ValueError:
                    pass
                break

    return _compact_payload({
        "tmux_session": resolved_tmux_session,
        "running": is_running,
        "log_tail": log_tail,
        "exit_code": parsed_exit_code,
        "watch_id": watch_id if watch_id > 0 else None,
    })


# ---------------------------------------------------------------------------
# Watchdog helpers and MCP tools
# ---------------------------------------------------------------------------


def _serialize_sandbox_config(cfg: SandboxConfig) -> dict:
    return {
        "name": cfg.name,
        "host": cfg.host,
        "user": cfg.user,
        "password": cfg.password,
        "port": cfg.port,
        "key_file": cfg.key_file,
        "key_passphrase": cfg.key_passphrase,
    }


def _persist_current_sandboxes() -> dict:
    if _INIT_ERROR:
        raise ValueError(f"Sandbox configuration error: {_INIT_ERROR}")
    configs = _load_sandbox_configs()
    if not configs:
        raise ValueError("No sandbox configuration is available to persist")
    return save_sandbox_config([_serialize_sandbox_config(cfg) for cfg in configs])


def _watchdog_status_payload() -> dict:
    init_watchdog_db()
    active = len(list_watchdog_watches(status="active", path=str(watchdog_db_path())))
    completed = len(list_watchdog_watches(status="completed", path=str(watchdog_db_path())))
    cancelled = len(list_watchdog_watches(status="cancelled", path=str(watchdog_db_path())))
    heartbeat = get_daemon_meta("heartbeat", path=str(watchdog_db_path()))
    stale = True
    if heartbeat and isinstance(heartbeat.get("value"), dict):
        ts = int(heartbeat["value"].get("ts", 0))
        stale = (int(time.time()) - ts) > HEARTBEAT_STALE_S
    return {
        "paths": {
            "config_path": str(watchdog_config_path()),
            "db_path": str(watchdog_db_path()),
        },
        "launchd": get_launch_agent_status(),
        "heartbeat": heartbeat,
        "heartbeat_stale": stale,
        "watch_counts": {
            "active": active,
            "completed": completed,
            "cancelled": cancelled,
        },
    }


def _is_watchdog_heartbeat_stale() -> bool:
    heartbeat = get_daemon_meta("heartbeat", path=str(watchdog_db_path()))
    if not heartbeat or not isinstance(heartbeat.get("value"), dict):
        return True
    ts = int(heartbeat["value"].get("ts", 0))
    return (int(time.time()) - ts) > HEARTBEAT_STALE_S


def _ensure_watchdog_ready(
    *,
    persist_current_sandboxes: bool = True,
    start_now: bool = True,
) -> dict:
    init_watchdog_db()
    persisted = None
    if persist_current_sandboxes:
        persisted = _persist_current_sandboxes()

    install = None
    launchd = get_launch_agent_status()
    if sys.platform == "darwin" and (
        not launchd.get("loaded", False) or _is_watchdog_heartbeat_stale()
    ):
        install = install_launch_agent(
            config_path=str(watchdog_config_path()),
            db_path=str(watchdog_db_path()),
            start_now=start_now,
        )

    return {
        "persisted_sandboxes": persisted,
        "install": install,
        "status": _watchdog_status_payload(),
    }


def _default_codex_event_command(codex_command: str = "") -> str:
    resolved = codex_command.strip() or shutil.which("codex") or "codex"
    quoted = shlex.quote(resolved)
    return (
        'case "$RSMCP_EVENT_TYPE" in '
        'ssh_unreachable|interrupted|resume_failed|completed|config_missing) '
        f'{quoted} exec "$RSMCP_SUGGESTED_PROMPT" ;; '
        "esac"
    )


def _parse_json_object(raw: str, label: str) -> dict:
    if not raw.strip():
        return {}
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{label} is not valid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must decode to a JSON object")
    return value


def _prepare_resume_plan(
    *,
    launch_command: str,
    resume_command: str,
    checkpoint_path: str,
    checkpoint_format: str,
    checkpoint_command: str,
    cwd: str,
    resume_plan_json: str,
    auto_resume: bool,
) -> tuple[str, dict]:
    plan = _parse_json_object(resume_plan_json, "resume_plan_json")

    effective_resume = resume_command.strip() or str(plan.get("resume_command", "")).strip()
    effective_checkpoint_path = checkpoint_path.strip() or str(plan.get("checkpoint_path", "")).strip()
    effective_checkpoint_command = (
        checkpoint_command.strip() or str(plan.get("checkpoint_command", "")).strip()
    )
    effective_checkpoint_format = (
        checkpoint_format.strip()
        or str(plan.get("checkpoint_format", "")).strip()
        or "text"
    )

    if launch_command.strip():
        plan.setdefault("launch_command", launch_command)
    if cwd.strip():
        plan.setdefault("cwd", cwd)
    if effective_resume:
        plan["resume_command"] = effective_resume
    if effective_checkpoint_path:
        plan["checkpoint_path"] = effective_checkpoint_path
    if effective_checkpoint_command:
        plan["checkpoint_command"] = effective_checkpoint_command
    plan["checkpoint_format"] = effective_checkpoint_format

    if auto_resume and not effective_resume:
        raise ValueError("auto_resume=True requires resume_command or resume_plan_json.resume_command")
    if auto_resume and not (effective_checkpoint_path or effective_checkpoint_command):
        raise ValueError(
            "auto_resume=True requires checkpoint_path or resume_plan_json.checkpoint_path"
        )

    return effective_resume, plan


def _parse_checkpoint_payload(text: str, checkpoint_format: str) -> dict:
    result = {
        "raw": text,
        "format": checkpoint_format,
        "parsed": None,
    }
    if checkpoint_format.strip().lower() == "json" and text.strip():
        try:
            result["parsed"] = json.loads(text)
        except json.JSONDecodeError:
            result["parsed"] = None
    return result


@_optional_tool(enabled=_EXPOSE_ADVANCED_TOOLS)
def install_macos_watchdog(
    start_now: bool = True,
    persist_current_sandboxes: bool = True,
) -> dict:
    """Install or refresh the macOS launchd watchdog service used for long tasks."""
    init_watchdog_db()
    persisted = None
    if persist_current_sandboxes:
        persisted = _persist_current_sandboxes()
    install = install_launch_agent(
        config_path=str(watchdog_config_path()),
        db_path=str(watchdog_db_path()),
        start_now=start_now,
    )
    return {
        "install": install,
        "persisted_sandboxes": persisted,
        "status": _watchdog_status_payload(),
    }


@_optional_tool(enabled=_EXPOSE_ADVANCED_TOOLS)
def uninstall_macos_watchdog() -> dict:
    """Remove the macOS launchd watchdog service."""
    removal = uninstall_launch_agent()
    return {
        "removal": removal,
        "status": _watchdog_status_payload(),
    }


@_optional_tool(enabled=_EXPOSE_ADVANCED_TOOLS)
def get_watchdog_status() -> dict:
    """Return launchd and heartbeat status for the long-task watchdog daemon."""
    return _watchdog_status_payload()


@_optional_tool(enabled=_EXPOSE_ADVANCED_TOOLS)
def watch_background_task(
    tmux_session: str,
    log_file: str,
    sandbox_name: str = "",
    run_id: str = "",
    name: str = "",
    cwd: str = "",
    launch_command: str = "",
    resume_command: str = "",
    resume_plan_json: str = "",
    checkpoint_path: str = "",
    checkpoint_format: str = "text",
    checkpoint_command: str = "",
    interval_s: int = DEFAULT_WATCH_INTERVAL_S,
    max_log_lines: int = DEFAULT_MAX_LOG_LINES,
    webhook_url: str = "",
    event_command: str = "",
    auto_resume: bool = False,
    max_resume_attempts: int = 1,
    metadata_json: str = "",
    ensure_watchdog: bool = True,
    notify_local: bool = True,
    alert_after_failures: int = DEFAULT_ALERT_AFTER_FAILURES,
    resume_delay_s: int = DEFAULT_RESUME_DELAY_S,
) -> dict:
    """Register a background tmux task for watchdog monitoring and recovery hooks."""
    if not tmux_session.strip():
        raise ValueError("tmux_session cannot be empty")
    if not log_file.strip():
        raise ValueError("log_file cannot be empty")
    if interval_s <= 0:
        raise ValueError("interval_s must be positive")
    if max_log_lines <= 0:
        raise ValueError("max_log_lines must be positive")
    if max_resume_attempts < 0:
        raise ValueError("max_resume_attempts must be zero or positive")
    if alert_after_failures < 1:
        raise ValueError("alert_after_failures must be positive")
    if resume_delay_s < 0:
        raise ValueError("resume_delay_s must be zero or positive")

    init_watchdog_db()
    persisted = _persist_current_sandboxes()
    watchdog_setup = None
    if ensure_watchdog:
        if sys.platform == "darwin":
            watchdog_setup = _ensure_watchdog_ready(
                persist_current_sandboxes=False,
                start_now=True,
            )
        else:
            watchdog_setup = {
                "warning": (
                    "ensure_watchdog=True requested outside macOS; watch registered in SQLite "
                    "but launchd auto-start is unavailable."
                )
            }

    sandbox = sandbox_name.strip() or _ACTIVE_SANDBOX
    if not sandbox:
        raise ValueError("sandbox_name is required when no active sandbox is selected")
    session = _get_session(sandbox)
    resolved_cwd = _expand_remote_user_path(session, cwd)
    resolved_log_file = _resolve_watch_path(session, resolved_cwd, log_file)
    resolved_checkpoint_path = _resolve_watch_path(session, resolved_cwd, checkpoint_path)

    metadata = _parse_json_object(metadata_json, "metadata_json")
    effective_resume_command, resume_plan = _prepare_resume_plan(
        launch_command=launch_command,
        resume_command=resume_command,
        checkpoint_path=resolved_checkpoint_path,
        checkpoint_format=checkpoint_format,
        checkpoint_command=checkpoint_command,
        cwd=resolved_cwd,
        resume_plan_json=resume_plan_json,
        auto_resume=auto_resume,
    )
    resume_plan.setdefault("tmux_session", tmux_session.strip())

    watch = create_watch(
        sandbox,
        tmux_session,
        resolved_log_file,
        run_id=run_id.strip() or tmux_session.strip(),
        name=name,
        cwd=resolved_cwd,
        launch_command=launch_command,
        resume_command=effective_resume_command,
        resume_plan=resume_plan,
        checkpoint_path=resolved_checkpoint_path or str(resume_plan.get("checkpoint_path", "")),
        checkpoint_format=str(resume_plan.get("checkpoint_format", checkpoint_format or "text")),
        checkpoint_command=checkpoint_command.strip() or str(resume_plan.get("checkpoint_command", "")),
        interval_s=interval_s,
        max_log_lines=max_log_lines,
        webhook_url=webhook_url,
        event_command=event_command,
        auto_resume=auto_resume,
        max_resume_attempts=max_resume_attempts,
        alert_after_failures=alert_after_failures,
        notify_local=notify_local,
        resume_delay_s=resume_delay_s,
        metadata=metadata,
        path=str(watchdog_db_path()),
    )
    return {
        "watch": watch,
        "watch_id": watch["id"],
        "watch_query_id": watch["id"],
        "persisted_sandboxes": persisted,
        "watchdog_setup": watchdog_setup,
        "status": _watchdog_status_payload(),
    }


@_optional_tool(enabled=_EXPOSE_ADVANCED_TOOLS)
def exec_bash_background_watch(
    command: str,
    session_name: str = "",
    log_file: str = "",
    cwd: str = "",
    sandbox_name: str = "",
    run_id: str = "",
    watch_name: str = "",
    resume_command: str = "",
    resume_plan_json: str = "",
    checkpoint_path: str = "",
    checkpoint_format: str = "text",
    checkpoint_command: str = "",
    interval_s: int = DEFAULT_WATCH_INTERVAL_S,
    max_log_lines: int = DEFAULT_MAX_LOG_LINES,
    webhook_url: str = "",
    event_command: str = "",
    auto_resume: bool = False,
    max_resume_attempts: int = 1,
    metadata_json: str = "",
    ensure_watchdog: bool = True,
    notify_local: bool = True,
    alert_after_failures: int = DEFAULT_ALERT_AFTER_FAILURES,
    resume_delay_s: int = DEFAULT_RESUME_DELAY_S,
    codex_wakeup: bool = False,
    codex_command: str = "",
) -> dict:
    """Backward-compatible alias for exec_bash_background with watch=True."""
    return exec_bash_background(
        command=command,
        session_name=session_name,
        log_file=log_file,
        cwd=cwd,
        sandbox_name=sandbox_name,
        watch=True,
        ensure_watchdog=ensure_watchdog,
        run_id=run_id,
        watch_name=watch_name,
        resume_command=resume_command,
        resume_plan_json=resume_plan_json,
        checkpoint_path=checkpoint_path,
        checkpoint_format=checkpoint_format,
        checkpoint_command=checkpoint_command,
        interval_s=interval_s,
        max_log_lines=max_log_lines,
        webhook_url=webhook_url,
        event_command=event_command,
        auto_resume=auto_resume,
        max_resume_attempts=max_resume_attempts,
        metadata_json=metadata_json,
        notify_local=notify_local,
        alert_after_failures=alert_after_failures,
        resume_delay_s=resume_delay_s,
        codex_wakeup=codex_wakeup,
        codex_command=codex_command,
    )


@_optional_tool(enabled=_EXPOSE_ADVANCED_TOOLS)
def list_background_watches(status: str = "") -> dict:
    """List registered watchdog watches."""
    init_watchdog_db()
    return {
        "watches": list_watchdog_watches(status=status.strip(), path=str(watchdog_db_path())),
        "status": _watchdog_status_payload(),
    }


@_optional_tool(enabled=_EXPOSE_ADVANCED_TOOLS)
def get_background_watch(watch_id: int) -> dict:
    """Fetch one watchdog watch by id."""
    init_watchdog_db()
    watch = get_watch(watch_id, path=str(watchdog_db_path()))
    if watch is None:
        raise ValueError(f"Unknown watch id: {watch_id}")
    return {"watch": watch}


@_optional_tool(enabled=_EXPOSE_ADVANCED_TOOLS)
def get_background_watch_progress(
    watch_id: int,
    refresh_live: bool = True,
    log_lines: int = 80,
    checkpoint_max_bytes: int = 20000,
) -> dict:
    """Return stored and live progress for one watchdog watch."""
    init_watchdog_db()
    watch = get_watch(watch_id, path=str(watchdog_db_path()))
    if watch is None:
        raise ValueError(f"Unknown watch id: {watch_id}")

    live_task = None
    live_checkpoint = None
    live_errors: list[dict] = []

    if refresh_live:
        live_task = check_background_task(
            watch_id=watch_id,
            last_n_lines=log_lines,
        )
        if isinstance(live_task, dict) and live_task.get("error"):
            live_errors.append({"kind": "task", "error": live_task["error"]})

        checkpoint_path = watch.get("checkpoint_path", "").strip()
        checkpoint_command = str(watch.get("resume_plan", {}).get("checkpoint_command", "")).strip() or watch.get("checkpoint_command", "").strip()
        if checkpoint_command:
            checkpoint_result = exec_bash(
                command=checkpoint_command,
                cwd=watch.get("cwd", ""),
                timeout_s=30,
                max_output_chars=checkpoint_max_bytes,
                sandbox_name=watch["sandbox_name"],
            )
            if checkpoint_result.get("error"):
                live_errors.append({"kind": "checkpoint", "error": checkpoint_result["error"]})
            else:
                live_checkpoint = _parse_checkpoint_payload(
                    checkpoint_result.get("stdout", ""),
                    watch.get("checkpoint_format", "text"),
                )
        elif checkpoint_path:
            checkpoint_result = read_remote_file(
                remote_path=checkpoint_path,
                max_bytes=checkpoint_max_bytes,
                sandbox_name=watch["sandbox_name"],
            )
            if checkpoint_result.get("error"):
                live_errors.append({"kind": "checkpoint", "error": checkpoint_result["error"]})
            else:
                live_checkpoint = _parse_checkpoint_payload(
                    checkpoint_result.get("content", ""),
                    watch.get("checkpoint_format", "text"),
                )

    stored_checkpoint = _parse_checkpoint_payload(
        watch.get("last_checkpoint_text", ""),
        watch.get("checkpoint_format", "text"),
    )

    return {
        "watch": watch,
        "stored": {
            "last_state": watch.get("last_state", ""),
            "last_summary": watch.get("last_summary", ""),
            "last_error": watch.get("last_error", ""),
            "last_log_tail": watch.get("last_log_tail", ""),
            "checkpoint": stored_checkpoint,
        },
        "live": {
            "task": live_task,
            "checkpoint": live_checkpoint,
            "errors": live_errors,
        },
    }


@_optional_tool(enabled=_EXPOSE_ADVANCED_TOOLS)
def read_background_watch_log(
    watch_id: int,
    last_n_lines: int = 200,
) -> dict:
    """Read the latest remote log tail for one watchdog watch."""
    init_watchdog_db()
    watch = get_watch(watch_id, path=str(watchdog_db_path()))
    if watch is None:
        raise ValueError(f"Unknown watch id: {watch_id}")
    live_task = check_background_task(
        watch_id=watch_id,
        last_n_lines=last_n_lines,
    )
    return {
        "watch": watch,
        "log": live_task,
    }


@_optional_tool(enabled=_EXPOSE_ADVANCED_TOOLS)
def read_background_watch_checkpoint(
    watch_id: int,
    max_bytes: int = 20000,
) -> dict:
    """Read the latest checkpoint snapshot for one watchdog watch."""
    init_watchdog_db()
    watch = get_watch(watch_id, path=str(watchdog_db_path()))
    if watch is None:
        raise ValueError(f"Unknown watch id: {watch_id}")

    checkpoint_command = (
        str(watch.get("resume_plan", {}).get("checkpoint_command", "")).strip()
        or watch.get("checkpoint_command", "").strip()
    )
    if checkpoint_command:
        result = exec_bash(
            command=checkpoint_command,
            cwd=watch.get("cwd", ""),
            timeout_s=30,
            max_output_chars=max_bytes,
            sandbox_name=watch["sandbox_name"],
        )
        payload = _parse_checkpoint_payload(
            result.get("stdout", ""),
            watch.get("checkpoint_format", "text"),
        )
        return {
            "watch": watch,
            "checkpoint": payload,
            "command_result": result,
        }

    checkpoint_path = watch.get("checkpoint_path", "").strip()
    if not checkpoint_path:
        raise ValueError(f"Watch {watch_id} does not define checkpoint_path or checkpoint_command")

    result = read_remote_file(
        remote_path=checkpoint_path,
        max_bytes=max_bytes,
        sandbox_name=watch["sandbox_name"],
    )
    payload = _parse_checkpoint_payload(
        result.get("content", ""),
        watch.get("checkpoint_format", "text"),
    )
    return {
        "watch": watch,
        "checkpoint": payload,
        "file_result": result,
    }


@_optional_tool(enabled=_EXPOSE_ADVANCED_TOOLS)
def cancel_background_watch(watch_id: int) -> dict:
    """Stop watchdog monitoring for one watch."""
    init_watchdog_db()
    watch = cancel_watchdog_watch(watch_id, path=str(watchdog_db_path()))
    return {
        "watch": watch,
        "status": _watchdog_status_payload(),
    }


@_optional_tool(enabled=_EXPOSE_ADVANCED_TOOLS)
def list_background_watch_events(watch_id: int = 0, limit: int = 20) -> dict:
    """List watchdog events for one watch or for all watches."""
    init_watchdog_db()
    return {
        "events": list_watchdog_events(
            watch_id=watch_id,
            limit=limit,
            path=str(watchdog_db_path()),
        )
    }


# ---------------------------------------------------------------------------
# Local transfer helpers
# ---------------------------------------------------------------------------


def _resolve_local_input_path(path: str) -> Path:
    expanded = Path(path).expanduser()
    if not expanded.is_absolute():
        expanded = Path.cwd() / expanded
    return expanded.resolve()


def _resolve_optional_local_file(path: str | None) -> str:
    if not path or not path.strip():
        return ""
    return str(_resolve_local_input_path(path))


def _transfer_runtime_dir() -> Path:
    directory = Path(watchdog_db_path()).expanduser().parent / "transfers"
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def _transfer_log_path(task_id: int) -> Path:
    return _transfer_runtime_dir() / f"transfer-{task_id}.log"


def _tail_local_file(path: str, *, last_n_lines: int, max_chars: int = 20000) -> str:
    if not path.strip():
        return ""
    target = Path(path).expanduser()
    if not target.exists() or not target.is_file():
        return ""
    read_size = min(target.stat().st_size, max_chars * 4)
    with target.open("rb") as fh:
        if read_size > 0:
            fh.seek(-read_size, os.SEEK_END)
        data = fh.read()
    text = data.decode("utf-8", errors="replace")
    lines = text.splitlines()
    tail = "\n".join(lines[-last_n_lines:])
    if len(tail) > max_chars:
        tail = tail[-max_chars:]
    return tail


def _pid_is_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def _is_terminal_transfer_status(status: str) -> bool:
    return status in {"completed", "failed", "cancelled"}


def _terminate_local_process_group(pid: int, force_kill_after_s: float = 5.0) -> dict:
    if pid <= 0:
        return {"terminated": False, "running": False}
    if not _pid_is_alive(pid):
        return {"terminated": False, "running": False}

    target_pgid: int | None = None
    if hasattr(os, "getpgid"):
        try:
            target_pgid = os.getpgid(pid)
        except OSError:
            return {"terminated": False, "running": False}

    def send(sig: int) -> bool:
        try:
            if target_pgid is not None and hasattr(os, "killpg"):
                os.killpg(target_pgid, sig)
            else:
                os.kill(pid, sig)
            return True
        except OSError:
            return False

    if not send(signal.SIGTERM):
        return {"terminated": False, "running": False}

    deadline = time.monotonic() + max(force_kill_after_s, 0.0)
    while time.monotonic() < deadline:
        if not _pid_is_alive(pid):
            return {"terminated": True, "running": False}
        time.sleep(0.1)

    force_killed = send(signal.SIGKILL)
    settle_deadline = time.monotonic() + 2.0
    while time.monotonic() < settle_deadline:
        if not _pid_is_alive(pid):
            return {"terminated": True, "force_killed": True if force_killed else None, "running": False}
        time.sleep(0.1)

    return {
        "terminated": True,
        "force_killed": True if force_killed else None,
        "running": True,
    }


def _validate_local_sync_request(
    local_path: str,
    exclude_file: str | None,
) -> tuple[Path, str]:
    local_root = _resolve_local_input_path(local_path)
    if not local_root.exists():
        raise ValueError(f"local_path does not exist: {local_root}")
    if not local_root.is_file() and not local_root.is_dir():
        raise ValueError(f"local_path must be a file or directory: {local_root}")

    resolved_exclude_file = _resolve_optional_local_file(exclude_file)
    if resolved_exclude_file and not Path(resolved_exclude_file).is_file():
        raise ValueError(f"exclude_file must be a file: {resolved_exclude_file}")
    return local_root, resolved_exclude_file


def _estimate_local_sync_workload(
    *,
    local_path_arg: str,
    local_root: Path,
    exclude_rules: list[str],
    max_files: int,
    max_bytes: int,
) -> dict:
    summary = {
        "synced_type": "file" if local_root.is_file() else "directory",
        "file_count": 0,
        "total_bytes": 0,
        "skipped_files": 0,
        "threshold_exceeded": False,
    }

    if local_root.is_file():
        candidates = _single_file_candidates(local_path_arg, local_root)
        if any(_is_excluded(candidate, exclude_rules) for candidate in candidates):
            summary["skipped_files"] = 1
            return summary
        summary["file_count"] = 1
        summary["total_bytes"] = local_root.stat().st_size
        summary["threshold_exceeded"] = (
            summary["file_count"] > max_files or summary["total_bytes"] > max_bytes
        )
        return summary

    for root, dirs, files in os.walk(local_root):
        rel_root = str(Path(root).relative_to(local_root)).replace("\\", "/")
        if rel_root == ".":
            rel_root = ""

        filtered_dirs = []
        for name in dirs:
            rel = f"{rel_root}/{name}".strip("/")
            if _is_excluded(rel, exclude_rules, is_dir=True):
                continue
            filtered_dirs.append(name)
        dirs[:] = filtered_dirs

        for name in files:
            rel = f"{rel_root}/{name}".strip("/")
            if _is_excluded(rel, exclude_rules):
                summary["skipped_files"] += 1
                continue
            local_file = Path(root) / name
            summary["file_count"] += 1
            summary["total_bytes"] += local_file.stat().st_size
            if summary["file_count"] > max_files or summary["total_bytes"] > max_bytes:
                summary["threshold_exceeded"] = True
                return summary

    return summary


def _sync_local_to_remote_impl(
    *,
    local_path: str = ".",
    remote_path: str = ".",
    delete_extras: bool = False,
    excludes: list[str] | None = None,
    exclude_file: str | None = None,
    sandbox_name: str = "",
    progress_callback: Optional[Callable[[dict], None]] = None,
) -> dict:
    local_root = _resolve_local_input_path(local_path)
    if not local_root.exists():
        raise ValueError(f"local_path does not exist: {local_root}")

    session = _get_session(sandbox_name)
    remote_root = _resolve_remote_input_path(session, remote_path)
    exclude_rules = _build_exclude_rules(excludes, exclude_file)
    start = time.time()

    if progress_callback is not None:
        progress_callback(
            {
                "phase": "connecting",
                "current_path": "",
                "uploaded_dirs": 0,
                "uploaded_files": 0,
                "skipped_files": 0,
                "deleted_dirs": 0,
                "deleted_files": 0,
            }
        )

    client = session.ensure_connected()
    sftp = _open_sftp_client(client)
    try:
        if local_root.is_file():
            if delete_extras:
                raise ValueError("delete_extras is only supported when local_path is a directory")

            candidates = _single_file_candidates(local_path, local_root)
            if any(_is_excluded(candidate, exclude_rules) for candidate in candidates):
                result = {
                    "local_path": str(local_root),
                    "remote_path": remote_root,
                    "synced_type": "file",
                    "uploaded_dirs": 0,
                    "uploaded_files": 0,
                    "skipped_files": 1,
                    "deleted_dirs": 0,
                    "deleted_files": 0,
                    "delete_extras": False,
                    "duration_s": round(time.time() - start, 3),
                }
                if progress_callback is not None:
                    progress_callback({"phase": "complete", "current_path": local_root.name, **result})
                return result

            remote_file = _resolve_remote_file_target(sftp, remote_root, local_root.name)
            _ensure_remote_dir(sftp, posixpath.dirname(remote_file))

            local_stat = local_root.stat()
            skipped_files = 0
            uploaded_files = 0
            try:
                remote_stat = sftp.stat(remote_file)
                same_size = remote_stat.st_size == local_stat.st_size
                same_mtime = abs(int(remote_stat.st_mtime) - int(local_stat.st_mtime)) <= 1
                if same_size and same_mtime:
                    skipped_files = 1
                else:
                    sftp.put(str(local_root), remote_file)
                    sftp.utime(remote_file, (int(local_stat.st_atime), int(local_stat.st_mtime)))
                    uploaded_files = 1
            except FileNotFoundError:
                sftp.put(str(local_root), remote_file)
                sftp.utime(remote_file, (int(local_stat.st_atime), int(local_stat.st_mtime)))
                uploaded_files = 1

            result = {
                "local_path": str(local_root),
                "remote_path": remote_file,
                "synced_type": "file",
                "uploaded_dirs": 0,
                "uploaded_files": uploaded_files,
                "skipped_files": skipped_files,
                "deleted_dirs": 0,
                "deleted_files": 0,
                "delete_extras": False,
                "duration_s": round(time.time() - start, 3),
            }
            if progress_callback is not None:
                progress_callback({"phase": "complete", "current_path": local_root.name, **result})
            return result

        if not local_root.is_dir():
            raise ValueError(f"local_path must be a file or directory: {local_root}")

        uploaded_dirs, uploaded_files, skipped_files, sent = _upload_tree(
            sftp,
            local_root,
            remote_root,
            exclude_rules,
            progress_callback=progress_callback,
        )
        deleted_dirs = 0
        deleted_files = 0
        if delete_extras:
            deleted_dirs, deleted_files = _safe_remove_remote_extras(
                sftp,
                remote_root,
                sent,
                exclude_rules,
                progress_callback=progress_callback,
            )

        result = {
            "local_path": str(local_root),
            "remote_path": remote_root,
            "synced_type": "directory",
            "uploaded_dirs": uploaded_dirs,
            "uploaded_files": uploaded_files,
            "skipped_files": skipped_files,
            "deleted_dirs": deleted_dirs,
            "deleted_files": deleted_files,
            "delete_extras": delete_extras,
            "duration_s": round(time.time() - start, 3),
        }
        if progress_callback is not None:
            progress_callback({"phase": "complete", "current_path": "", **result})
        return result
    finally:
        sftp.close()


def _spawn_transfer_worker(task_id: int, log_file: str) -> subprocess.Popen:
    log_path = Path(log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("ab") as log_handle:
        return subprocess.Popen(
            [sys.executable, "-m", "remote_sandbox_mcp.server", "transfer-worker", "--task-id", str(task_id)],
            stdin=subprocess.DEVNULL,
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            env={**os.environ, "PYTHONUNBUFFERED": "1"},
            start_new_session=True,
            close_fds=True,
        )


def _run_transfer_worker(task_id: int) -> int:
    db_path = str(watchdog_db_path())
    init_watchdog_db(db_path)
    task = get_transfer_task(task_id, path=db_path)
    if task is None:
        print(f"[transfer] unknown task id: {task_id}", flush=True)
        return 2
    if task.get("status") == "cancelled":
        print(f"[transfer] task={task_id} already cancelled", flush=True)
        return 0

    if task.get("direction") != "local_to_remote":
        update_transfer_task(
            task_id,
            path=db_path,
            status="failed",
            finished_ts=int(time.time()),
            last_error=f"Unsupported transfer direction: {task.get('direction', '')}",
        )
        return 2

    progress_state: dict = {
        "phase": "starting",
        "current_path": "",
        "uploaded_dirs": 0,
        "uploaded_files": 0,
        "skipped_files": 0,
        "deleted_dirs": 0,
        "deleted_files": 0,
    }
    update_transfer_task(
        task_id,
        path=db_path,
        status="running",
        pid=os.getpid(),
        started_ts=int(time.time()),
        finished_ts=0,
        last_error="",
        progress=progress_state,
    )

    print(
        f"[transfer] task={task_id} sandbox={task['sandbox_name']} "
        f"local={task['local_path']} remote={task['remote_path']}",
        flush=True,
    )

    last_flush = 0.0

    def progress_callback(update: dict) -> None:
        nonlocal last_flush
        progress_state.update(update)
        now = time.monotonic()
        phase = str(update.get("phase", ""))
        if phase not in {"complete", "failed"} and now - last_flush < 0.5:
            return
        last_flush = now
        update_transfer_task(task_id, path=db_path, progress=progress_state)

    try:
        result = _sync_local_to_remote_impl(
            local_path=task["local_path"],
            remote_path=task["remote_path"],
            delete_extras=bool(task.get("delete_extras")),
            excludes=task.get("excludes", []),
            exclude_file=task.get("exclude_file", ""),
            sandbox_name=task["sandbox_name"],
            progress_callback=progress_callback,
        )
        progress_state.update(result)
        progress_state["phase"] = "complete"
        update_transfer_task(
            task_id,
            path=db_path,
            status="completed",
            finished_ts=int(time.time()),
            result=result,
            progress=progress_state,
            last_error="",
        )
        print(f"[transfer] task={task_id} completed", flush=True)
        return 0
    except Exception as exc:
        progress_state["phase"] = "failed"
        progress_state["current_path"] = progress_state.get("current_path", "")
        error_text = f"{type(exc).__name__}: {exc}"
        update_transfer_task(
            task_id,
            path=db_path,
            status="failed",
            finished_ts=int(time.time()),
            last_error=error_text,
            progress=progress_state,
        )
        print(f"[transfer] task={task_id} failed: {error_text}", flush=True)
        print(traceback.format_exc(), flush=True)
        return 1


def _start_sync_local_to_remote_background(
    *,
    local_root: Path,
    remote_root: str,
    delete_extras: bool,
    excludes: list[str] | None,
    resolved_exclude_file: str,
    sandbox_name: str,
    auto_switched: bool = False,
) -> dict:
    session = _get_session(sandbox_name)
    init_watchdog_db(str(watchdog_db_path()))
    task = create_transfer_task(
        "local_to_remote",
        session.id,
        str(local_root),
        remote_root,
        delete_extras=delete_extras,
        excludes=list(excludes or []),
        exclude_file=resolved_exclude_file,
        path=str(watchdog_db_path()),
    )

    log_file = str(_transfer_log_path(task["id"]))
    Path(log_file).write_text(
        (
            f"== transfer task: {task['id']}\n"
            f"== created_at: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}\n"
            f"== sandbox: {session.id}\n"
            f"== local_path: {local_root}\n"
            f"== remote_path: {remote_root}\n"
        ),
        encoding="utf-8",
    )
    update_transfer_task(
        task["id"],
        path=str(watchdog_db_path()),
        log_file=log_file,
        progress={
            "phase": "queued",
            "current_path": "",
            "uploaded_dirs": 0,
            "uploaded_files": 0,
            "skipped_files": 0,
            "deleted_dirs": 0,
            "deleted_files": 0,
        },
    )
    try:
        proc = _spawn_transfer_worker(task["id"], log_file)
    except Exception:
        update_transfer_task(
            task["id"],
            path=str(watchdog_db_path()),
            status="failed",
            finished_ts=int(time.time()),
            last_error="Failed to spawn detached transfer worker",
        )
        raise

    task = update_transfer_task(
        task["id"],
        path=str(watchdog_db_path()),
        pid=proc.pid,
    )
    return _compact_payload({
        "mode": "background",
        "auto_switched": True if auto_switched else None,
        "task_id": task["id"],
        "status": task["status"],
        "pid": proc.pid,
        "log_file": task["log_file"],
    })


# ---------------------------------------------------------------------------
# MCP tools – file operations (updated to use persistent sessions)
# ---------------------------------------------------------------------------


@mcp.tool()
@_safe_tool
def list_remote_files(
    remote_path: str = ".",
    recursive: bool = False,
    max_entries: int = 200,
    sandbox_name: str = "",
) -> dict:
    """List files in a remote sandbox path."""
    if max_entries <= 0:
        raise ValueError("max_entries must be positive")

    session = _get_session(sandbox_name)
    remote_path = _resolve_remote_input_path(session, remote_path)
    client = session.ensure_connected()
    sftp = _open_sftp_client(client)
    try:
        entries: list[dict] = []

        def walk(path: str) -> None:
            if len(entries) >= max_entries:
                return
            for item in sftp.listdir_attr(path):
                is_dir = stat.S_ISDIR(item.st_mode)
                full = posixpath.join(path, item.filename)
                entries.append(
                    {
                        "path": full,
                        "is_dir": is_dir,
                        "size": item.st_size,
                        "mtime": int(item.st_mtime),
                    }
                )
                if len(entries) >= max_entries:
                    return
                if recursive and is_dir:
                    walk(full)

        walk(remote_path)
        return _compact_payload(
            {
                "truncated": len(entries) >= max_entries,
                "entries": entries,
            }
        )
    finally:
        sftp.close()


@mcp.tool()
@_safe_tool
def read_remote_file(
    remote_path: str,
    max_bytes: int = 200000,
    sandbox_name: str = "",
) -> dict:
    """Read a remote file from the sandbox."""
    if not remote_path.strip():
        raise ValueError("remote_path cannot be empty")
    if max_bytes <= 0:
        raise ValueError("max_bytes must be positive")

    session = _get_session(sandbox_name)
    remote_path = _resolve_remote_input_path(session, remote_path)
    client = session.ensure_connected()
    sftp = _open_sftp_client(client)
    try:
        with sftp.file(remote_path, "rb") as fh:
            data = fh.read(max_bytes + 1)
        truncated = len(data) > max_bytes
        if truncated:
            data = data[:max_bytes]
        return _compact_payload(
            {
                "size": len(data),
                "truncated": truncated,
                "content": data.decode("utf-8", errors="replace"),
            }
        )
    finally:
        sftp.close()


@mcp.tool()
@_safe_tool
def sync_local_to_remote(
    local_path: str = ".",
    remote_path: str = ".",
    delete_extras: bool = False,
    excludes: list[str] | None = None,
    exclude_file: str | None = None,
    sandbox_name: str = "",
) -> dict:
    """Sync local files/directories to the remote sandbox via SFTP.

    Small transfers run inline. Large transfers are automatically delegated to
    a detached background worker to avoid MCP tool-call timeouts.
    """
    local_root, resolved_exclude_file = _validate_local_sync_request(local_path, exclude_file)
    exclude_rules = _build_exclude_rules(excludes, resolved_exclude_file)
    workload = _estimate_local_sync_workload(
        local_path_arg=local_path,
        local_root=local_root,
        exclude_rules=exclude_rules,
        max_files=_INLINE_SYNC_MAX_FILES,
        max_bytes=_INLINE_SYNC_MAX_BYTES,
    )
    session = _get_session(sandbox_name)
    remote_root = _resolve_remote_input_path(session, remote_path)

    if workload["threshold_exceeded"]:
        return _start_sync_local_to_remote_background(
            local_root=local_root,
            remote_root=remote_root,
            delete_extras=delete_extras,
            excludes=excludes,
            resolved_exclude_file=resolved_exclude_file,
            sandbox_name=sandbox_name,
            auto_switched=True,
        )

    result = _sync_local_to_remote_impl(
        local_path=local_path,
        remote_path=remote_root,
        delete_extras=delete_extras,
        excludes=excludes,
        exclude_file=resolved_exclude_file,
        sandbox_name=sandbox_name,
    )
    return _compact_payload({"mode": "inline", **result})

#
# Internal compatibility helper. Large transfers should normally enter through
# sync_local_to_remote(), which auto-delegates to this path when needed.
def sync_local_to_remote_background(
    local_path: str = ".",
    remote_path: str = ".",
    delete_extras: bool = False,
    excludes: list[str] | None = None,
    exclude_file: str | None = None,
    sandbox_name: str = "",
) -> dict:
    """Force a local-to-remote sync to run in a detached local worker process."""
    local_root, resolved_exclude_file = _validate_local_sync_request(local_path, exclude_file)
    session = _get_session(sandbox_name)
    return _start_sync_local_to_remote_background(
        local_root=local_root,
        remote_root=_resolve_remote_input_path(session, remote_path),
        delete_extras=delete_extras,
        excludes=excludes,
        resolved_exclude_file=resolved_exclude_file,
        sandbox_name=sandbox_name,
    )


@mcp.tool()
@_safe_tool
def check_file_transfer_task(task_id: int, last_n_lines: int = 50) -> dict:
    """Return status and recent log output for one background file transfer task."""
    if task_id <= 0:
        raise ValueError("task_id must be positive")
    if last_n_lines <= 0:
        raise ValueError("last_n_lines must be positive")

    init_watchdog_db(str(watchdog_db_path()))
    task = get_transfer_task(task_id, path=str(watchdog_db_path()))
    if task is None:
        raise ValueError(f"Unknown transfer task id: {task_id}")

    pid = int(task.get("pid", 0) or 0)
    worker_alive = _pid_is_alive(pid) if pid > 0 else False
    status = task.get("status", "")
    stale = status == "running" and pid > 0 and not worker_alive and not task.get("finished_ts")
    payload = {
        "task_id": task_id,
        "status": status,
        "running": True if status == "running" and worker_alive else None,
        "pending": True if status == "queued" else None,
        "stale": True if stale else None,
        "progress": _summarize_transfer_progress(task.get("progress")),
        "result": _summarize_transfer_progress(task.get("result")),
        "error": task.get("last_error", "") if status == "failed" else "",
        "log_tail": _tail_local_file(task.get("log_file", ""), last_n_lines=last_n_lines),
    }
    return _compact_payload(payload)


@mcp.tool()
@_safe_tool
def cancel_file_transfer_task(task_id: int, force_kill_after_s: float = 5.0) -> dict:
    """Cancel one background file transfer task and stop its local worker if needed."""
    if task_id <= 0:
        raise ValueError("task_id must be positive")
    if force_kill_after_s < 0:
        raise ValueError("force_kill_after_s must be zero or positive")

    db_path = str(watchdog_db_path())
    init_watchdog_db(db_path)
    task = get_transfer_task(task_id, path=db_path)
    if task is None:
        raise ValueError(f"Unknown transfer task id: {task_id}")

    status = str(task.get("status", ""))
    pid = int(task.get("pid", 0) or 0)
    if _is_terminal_transfer_status(status):
        return _compact_payload({
            "task_id": task_id,
            "status": status,
            "already_finished": True,
        })

    termination = (
        _terminate_local_process_group(pid, force_kill_after_s=force_kill_after_s)
        if pid > 0
        else {"terminated": False, "running": False}
    )

    latest = get_transfer_task(task_id, path=db_path) or task
    latest_status = str(latest.get("status", ""))
    if termination.get("running"):
        return _compact_payload({
            "task_id": task_id,
            "status": latest_status or status or "running",
            "terminated": termination.get("terminated"),
            "force_killed": termination.get("force_killed"),
            "error": "Worker still running after cancellation attempt",
        })
    if _is_terminal_transfer_status(latest_status):
        return _compact_payload({
            "task_id": task_id,
            "status": latest_status,
            "already_finished": True,
            "terminated": termination.get("terminated"),
            "force_killed": termination.get("force_killed"),
        })

    progress = dict(latest.get("progress") or {})
    progress["phase"] = "cancelled"
    updated = update_transfer_task(
        task_id,
        path=db_path,
        status="cancelled",
        finished_ts=int(time.time()),
        last_error="",
        progress=progress,
    )
    return _compact_payload({
        "task_id": task_id,
        "status": updated["status"],
        "terminated": termination.get("terminated"),
        "force_killed": termination.get("force_killed"),
    })


@mcp.tool()
@_safe_tool
def sync_remote_to_local(
    remote_path: str = ".",
    local_path: str = "./remote_mirror",
    excludes: list[str] | None = None,
    exclude_file: str | None = None,
    sandbox_name: str = "",
) -> dict:
    """Download remote sandbox files/directories to local path via SFTP."""
    local_root = Path(local_path).resolve()
    exclude_rules = _build_exclude_rules(excludes, exclude_file)

    start = time.time()
    session = _get_session(sandbox_name)
    remote_root = _resolve_remote_input_path(session, remote_path)
    client = session.ensure_connected()
    sftp = _open_sftp_client(client)
    try:
        remote_attr = sftp.stat(remote_root)
        if stat.S_ISDIR(remote_attr.st_mode):
            created_dirs, downloaded_files, skipped_files = _download_tree(
                sftp, remote_root, local_root, exclude_rules
            )
            return {
                "remote_path": remote_root,
                "local_path": str(local_root),
                "synced_type": "directory",
                "created_dirs": created_dirs,
                "downloaded_files": downloaded_files,
                "skipped_files": skipped_files,
                "duration_s": round(time.time() - start, 3),
            }

        candidates = _single_file_candidates(remote_path, Path(posixpath.basename(remote_root)))
        if any(_is_excluded(candidate, exclude_rules) for candidate in candidates):
            local_target = _resolve_local_file_target(local_path, remote_root)
            return {
                "remote_path": remote_root,
                "local_path": str(local_target),
                "synced_type": "file",
                "created_dirs": 0,
                "downloaded_files": 0,
                "skipped_files": 1,
                "duration_s": round(time.time() - start, 3),
            }

        local_target = _resolve_local_file_target(local_path, remote_root)
        if local_target.exists() and local_target.is_dir():
            raise ValueError(
                f"local_path points to a directory, expected a file target: {local_target}"
            )
        local_target.parent.mkdir(parents=True, exist_ok=True)

        downloaded_files = 0
        skipped_files = 0
        if local_target.exists():
            local_stat = local_target.stat()
            same_size = local_stat.st_size == remote_attr.st_size
            same_mtime = abs(int(local_stat.st_mtime) - int(remote_attr.st_mtime)) <= 1
            if same_size and same_mtime:
                skipped_files = 1
            else:
                sftp.get(remote_root, str(local_target))
                os.utime(local_target, (int(remote_attr.st_atime), int(remote_attr.st_mtime)))
                downloaded_files = 1
        else:
            sftp.get(remote_root, str(local_target))
            os.utime(local_target, (int(remote_attr.st_atime), int(remote_attr.st_mtime)))
            downloaded_files = 1

        return {
            "remote_path": remote_root,
            "local_path": str(local_target),
            "synced_type": "file",
            "created_dirs": 0,
            "downloaded_files": downloaded_files,
            "skipped_files": skipped_files,
            "duration_s": round(time.time() - start, 3),
        }
    finally:
        sftp.close()


def main() -> None:
    if len(sys.argv) == 1:
        mcp.run(transport="stdio")
        return

    parser = argparse.ArgumentParser(prog="remote-sandbox-mcp")
    subparsers = parser.add_subparsers(dest="command")

    daemon_parser = subparsers.add_parser("daemon", help="Run the local watchdog daemon")
    daemon_parser.add_argument("--config", default=str(watchdog_config_path()))
    daemon_parser.add_argument("--db", default=str(watchdog_db_path()))
    daemon_parser.add_argument("--loop-sleep", type=int, default=5)

    transfer_worker_parser = subparsers.add_parser(
        "transfer-worker",
        help="Run one detached local file transfer worker",
    )
    transfer_worker_parser.add_argument("--task-id", type=int, required=True)

    args = parser.parse_args()
    if args.command == "daemon":
        WatchdogDaemon(
            config_path=args.config,
            db_path=args.db,
            loop_sleep_s=args.loop_sleep,
        ).run_forever()
        return
    if args.command == "transfer-worker":
        raise SystemExit(_run_transfer_worker(args.task_id))

    parser.error(f"unknown subcommand: {args.command}")


if __name__ == "__main__":
    main()
