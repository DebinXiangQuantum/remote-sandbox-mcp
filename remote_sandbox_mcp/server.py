from __future__ import annotations

import fnmatch
import json
import os
import posixpath
import shlex
import stat
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

import paramiko
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("remote-sandbox")


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
    paramiko.DSSKey,
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
            raise ValueError(f"REMOTE_SANDBOX_LIST is not valid JSON: {exc}") from exc
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
        return client

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
            now = time.monotonic()
            if now - self._last_health_check > _HEALTH_CHECK_INTERVAL:
                if not self.is_alive():
                    if self._client is not None:
                        try:
                            self._client.close()
                        except Exception:
                            pass
                        self._client = None
                self._last_health_check = now

            if self._client is None:
                self._client = self._make_client()
            return self._client

    def close(self) -> None:
        with self._lock:
            if self._client is not None:
                try:
                    self._client.close()
                except Exception:
                    pass
                self._client = None


# ---------------------------------------------------------------------------
# Global session registry
# ---------------------------------------------------------------------------

_SESSIONS: dict[str, SandboxSession] = {}
_ACTIVE_SANDBOX: Optional[str] = None
_REGISTRY_LOCK = threading.Lock()


def _init_sessions() -> None:
    global _ACTIVE_SANDBOX
    try:
        configs = _load_sandbox_configs()
    except Exception:
        configs = []
    with _REGISTRY_LOCK:
        for cfg in configs:
            _SESSIONS[cfg.name] = SandboxSession(cfg)
        if configs and _ACTIVE_SANDBOX is None:
            _ACTIVE_SANDBOX = configs[0].name


_init_sessions()


def _get_session(sandbox_name: str = "") -> SandboxSession:
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


# ---------------------------------------------------------------------------
# Core exec helper with reliable two-layer timeout
# ---------------------------------------------------------------------------


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
    transport = client.get_transport()
    if transport is None or not transport.is_active():
        raise ConnectionError("SSH transport is not active; the connection may have dropped")

    # Layer 1: wrap with GNU timeout(1) for a hard server-side kill
    wrapped = f"timeout {timeout_s}s bash -c {shlex.quote(command)}"

    channel = transport.open_session()
    # Layer 2: socket-level timeout a few seconds beyond the remote kill window
    channel.settimeout(float(timeout_s + 10))

    stdout_buf: list[bytes] = []
    stderr_buf: list[bytes] = []
    deadline = time.monotonic() + timeout_s + 10

    try:
        channel.exec_command(wrapped)

        while True:
            if time.monotonic() > deadline:
                channel.close()
                out = b"".join(stdout_buf).decode("utf-8", errors="replace")
                return {
                    "exit_code": -1,
                    "stdout": out[-max_output_chars:] if len(out) > max_output_chars else out,
                    "stderr": (
                        f"[TIMEOUT] Client-side deadline exceeded after {timeout_s}s. "
                        "The remote process may still be running."
                    ),
                    "command": command,
                    "timed_out": True,
                }

            if channel.recv_ready():
                data = channel.recv(65536)
                if data:
                    stdout_buf.append(data)
            if channel.recv_stderr_ready():
                data = channel.recv_stderr(65536)
                if data:
                    stderr_buf.append(data)

            if channel.exit_status_ready():
                # Drain remaining output before reading exit status
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
        out = b"".join(stdout_buf).decode("utf-8", errors="replace")
        err = b"".join(stderr_buf).decode("utf-8", errors="replace")
        return {
            "exit_code": -1,
            "stdout": out[-max_output_chars:] if len(out) > max_output_chars else out,
            "stderr": (err + f"\n[CONNECTION ERROR] {exc}").strip(),
            "command": command,
            "connection_error": True,
        }
    finally:
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
        "command": command,
    }
    # GNU timeout exits 124 when it kills the remote process
    if exit_code == 124:
        result["timed_out"] = True
        result["stderr"] = (
            result["stderr"]
            + f"\n[TIMEOUT] Remote process killed by timeout after {timeout_s}s"
        ).strip()
    return result


# ---------------------------------------------------------------------------
# Path / exclude helpers (unchanged from v0.1.0)
# ---------------------------------------------------------------------------


def _normalize_remote(path: str) -> str:
    if not path:
        return "."
    return posixpath.normpath(path)


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
) -> tuple[int, int, int, set[str]]:
    uploaded_files = 0
    skipped_files = 0
    uploaded_dirs = 0
    sent: set[str] = set()

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
                    continue
            except FileNotFoundError:
                pass
            sftp.put(str(local_file), remote_file)
            sftp.utime(remote_file, (int(local_stat.st_atime), int(local_stat.st_mtime)))
            uploaded_files += 1

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
) -> tuple[int, int]:
    deleted_files = 0
    deleted_dirs = 0
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
    for rel in sorted(remote_dirs, key=lambda x: x.count("/"), reverse=True):
        if _is_excluded(rel, exclude_rules, is_dir=True):
            continue
        if rel not in sent_paths:
            try:
                sftp.rmdir(posixpath.join(remote_root, rel))
                deleted_dirs += 1
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


# ---------------------------------------------------------------------------
# MCP tools – sandbox management
# ---------------------------------------------------------------------------


@mcp.tool()
def list_sandboxes(check_resources: bool = False) -> dict:
    """List all configured sandboxes with connection info.

    When check_resources=True, queries each sandbox for CPU/memory/GPU usage and
    returns an idle_score (0=fully busy, 1=fully idle) to help pick the best sandbox.
    Use select_sandbox to make the most idle one active.
    """
    with _REGISTRY_LOCK:
        sessions = dict(_SESSIONS)
    if not sessions:
        return {
            "error": (
                "No sandboxes configured. "
                "Set REMOTE_HOST/REMOTE_USER/REMOTE_PASSWORD or REMOTE_SANDBOX_LIST."
            ),
            "sandboxes": [],
        }
    sandboxes = []
    for name, session in sessions.items():
        info: dict = {
            "name": name,
            "host": session.config.host,
            "port": session.config.port,
            "user": session.config.user,
            "is_active": name == _ACTIVE_SANDBOX,
            "connection_alive": session.is_alive(),
        }
        if check_resources:
            info["resources"] = _query_resources(session)
        sandboxes.append(info)
    return {"active_sandbox": _ACTIVE_SANDBOX, "sandboxes": sandboxes}


@mcp.tool()
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
def get_active_sandbox() -> dict:
    """Return the currently active sandbox and its live connection health.

    Use this to verify the session is still connected before running a long task.
    If connection_alive is False, the next tool call will auto-reconnect.
    """
    if not _ACTIVE_SANDBOX:
        return {"active_sandbox": None, "error": "No active sandbox configured"}
    with _REGISTRY_LOCK:
        session = _SESSIONS.get(_ACTIVE_SANDBOX)
    if session is None:
        return {"active_sandbox": _ACTIVE_SANDBOX, "error": "Session object not found"}
    return {
        "active_sandbox": _ACTIVE_SANDBOX,
        "host": session.config.host,
        "port": session.config.port,
        "user": session.config.user,
        "connection_alive": session.is_alive(),
    }


# ---------------------------------------------------------------------------
# MCP tools – command execution
# ---------------------------------------------------------------------------


@mcp.tool()
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
def exec_bash_background(
    command: str,
    session_name: str = "",
    log_file: str = "",
    cwd: str = "",
    sandbox_name: str = "",
) -> dict:
    """Start a long-running command in a detached tmux session on the remote sandbox.

    Output (stdout + stderr) is streamed via ``tee`` into *log_file* for async
    inspection. An EXIT_CODE=<n> line is appended to the log when the command ends.

    Returns immediately with the tmux session name and log path.
    Use check_background_task to poll progress and read recent log output.

    Recommended for: training jobs, long builds, batch pipelines, anything that
    would exceed exec_bash's timeout or that you want to check on periodically.

    Args:
        command: Shell command to run (can be multi-line or a script invocation).
        session_name: tmux session name; auto-generated from timestamp if empty.
        log_file: Remote path for captured output; defaults to
                  .codex_logs/<session_name>.log relative to cwd.
        cwd: Working directory on the remote host.
        sandbox_name: Override the active sandbox for this call (optional).
    """
    if not command.strip():
        raise ValueError("command cannot be empty")

    session = _get_session(sandbox_name)
    client = session.ensure_connected()

    run_id = session_name.strip() or f"bg-{int(time.time())}"
    # Resolve log path relative to cwd if not absolute
    if log_file.strip():
        log = log_file.strip()
    else:
        base = cwd.strip() if cwd.strip() else "."
        log = posixpath.join(base, ".codex_logs", f"{run_id}.log")

    log_dir = posixpath.dirname(log)

    # Build the inner command: run user command, capture output, write exit code
    inner = (
        f"mkdir -p {shlex.quote(log_dir)} && "
        f"{{"
        f" echo '== session: {run_id}';"
        f" echo '== started_at: '$(date -u +%Y-%m-%dT%H:%M:%SZ);"
        f" echo '== command: {command.replace(chr(39), chr(39)+chr(92)+chr(39)+chr(39))[:120]}';"
        f" {command};"
        f" echo \"EXIT_CODE=$?\";"
        f"}} 2>&1 | tee -a {shlex.quote(log)}"
    )

    if cwd.strip():
        inner = f"cd {shlex.quote(cwd)} && " + inner

    tmux_cmd = (
        f"tmux new-session -d -s {shlex.quote(run_id)} "
        f"'bash -c {shlex.quote(inner)}'"
    )

    result = _exec_on_channel(client, tmux_cmd, timeout_s=15, max_output_chars=2000)
    if result["exit_code"] != 0:
        stderr = result.get("stderr", "")
        stdout = result.get("stdout", "")
        combined = (stderr + "\n" + stdout).lower()

        if result.get("timed_out"):
            diagnosis = (
                "The tmux startup command itself timed out (15 s). "
                "The remote host may be under heavy load or the shell is hanging on login. "
                "Try running exec_bash('tmux new-session -d -s test echo ok') to diagnose."
            )
        elif result.get("connection_error"):
            diagnosis = f"SSH connection error while launching tmux: {stderr.strip()}"
        elif "duplicate session" in combined or "already exists" in combined:
            diagnosis = (
                f"A tmux session named {run_id!r} already exists on the remote host. "
                "Use a different session_name or kill the existing session first with: "
                f"tmux kill-session -t {run_id}"
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

        return {
            "error": "Failed to start background task in tmux",
            "diagnosis": diagnosis,
            "stderr": stderr,
            "stdout": stdout,
            "exit_code": result["exit_code"],
            "timed_out": result.get("timed_out", False),
            "connection_error": result.get("connection_error", False),
        }
    return {
        "status": "started",
        "tmux_session": run_id,
        "log_file": log,
        "sandbox": session.id,
        "note": (
            "Task is running in background. "
            "Call check_background_task with this tmux_session and log_file to poll progress."
        ),
    }


@mcp.tool()
def check_background_task(
    tmux_session: str,
    log_file: str = "",
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
    if not tmux_session.strip():
        raise ValueError("tmux_session cannot be empty")

    session = _get_session(sandbox_name)
    client = session.ensure_connected()

    # Check if the tmux session exists
    check_cmd = (
        f"tmux has-session -t {shlex.quote(tmux_session)} 2>/dev/null "
        f"&& echo RUNNING || echo DONE"
    )
    status_result = _exec_on_channel(client, check_cmd, timeout_s=10, max_output_chars=200)
    is_running = "RUNNING" in status_result.get("stdout", "")

    log_tail = ""
    parsed_exit_code = None

    if log_file:
        tail_cmd = (
            f"tail -n {last_n_lines} {shlex.quote(log_file)} 2>/dev/null "
            f"|| echo '[log file not found]'"
        )
        log_result = _exec_on_channel(client, tail_cmd, timeout_s=15, max_output_chars=20000)
        log_tail = log_result.get("stdout", "")

        # Try to extract EXIT_CODE from the log
        for line in reversed(log_tail.splitlines()):
            if line.startswith("EXIT_CODE="):
                try:
                    parsed_exit_code = int(line.split("=", 1)[1].strip())
                except ValueError:
                    pass
                break

    return {
        "tmux_session": tmux_session,
        "running": is_running,
        "log_file": log_file,
        "log_tail": log_tail,
        "exit_code": parsed_exit_code,
        "sandbox": session.id,
    }


# ---------------------------------------------------------------------------
# MCP tools – file operations (updated to use persistent sessions)
# ---------------------------------------------------------------------------


@mcp.tool()
def list_remote_files(
    remote_path: str = ".",
    recursive: bool = False,
    max_entries: int = 200,
    sandbox_name: str = "",
) -> dict:
    """List files in a remote sandbox path."""
    if max_entries <= 0:
        raise ValueError("max_entries must be positive")

    remote_path = _normalize_remote(remote_path)
    session = _get_session(sandbox_name)
    client = session.ensure_connected()
    sftp = client.open_sftp()
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
                        "name": item.filename,
                        "is_dir": is_dir,
                        "size": item.st_size,
                        "mtime": int(item.st_mtime),
                        "mode": item.st_mode,
                    }
                )
                if len(entries) >= max_entries:
                    return
                if recursive and is_dir:
                    walk(full)

        walk(remote_path)
        return {
            "remote_path": remote_path,
            "recursive": recursive,
            "truncated": len(entries) >= max_entries,
            "entries": entries,
        }
    finally:
        sftp.close()


@mcp.tool()
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

    remote_path = _normalize_remote(remote_path)
    session = _get_session(sandbox_name)
    client = session.ensure_connected()
    sftp = client.open_sftp()
    try:
        with sftp.file(remote_path, "rb") as fh:
            data = fh.read(max_bytes + 1)
        truncated = len(data) > max_bytes
        if truncated:
            data = data[:max_bytes]
        return {
            "remote_path": remote_path,
            "size": len(data),
            "truncated": truncated,
            "content": data.decode("utf-8", errors="replace"),
        }
    finally:
        sftp.close()


@mcp.tool()
def sync_local_to_remote(
    local_path: str = ".",
    remote_path: str = ".",
    delete_extras: bool = False,
    excludes: list[str] | None = None,
    exclude_file: str | None = None,
    sandbox_name: str = "",
) -> dict:
    """Sync local files/directories to the remote sandbox via SFTP."""
    local_root = Path(local_path).resolve()
    if not local_root.exists():
        raise ValueError(f"local_path does not exist: {local_root}")

    remote_root = _normalize_remote(remote_path)
    exclude_rules = _build_exclude_rules(excludes, exclude_file)

    start = time.time()
    session = _get_session(sandbox_name)
    client = session.ensure_connected()
    sftp = client.open_sftp()
    try:
        if local_root.is_file():
            if delete_extras:
                raise ValueError("delete_extras is only supported when local_path is a directory")

            candidates = _single_file_candidates(local_path, local_root)
            if any(_is_excluded(candidate, exclude_rules) for candidate in candidates):
                return {
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

            return {
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

        if not local_root.is_dir():
            raise ValueError(f"local_path must be a file or directory: {local_root}")

        uploaded_dirs, uploaded_files, skipped_files, sent = _upload_tree(
            sftp, local_root, remote_root, exclude_rules
        )
        deleted_dirs = 0
        deleted_files = 0
        if delete_extras:
            deleted_dirs, deleted_files = _safe_remove_remote_extras(
                sftp, remote_root, sent, exclude_rules
            )

        return {
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
    finally:
        sftp.close()


@mcp.tool()
def sync_remote_to_local(
    remote_path: str = ".",
    local_path: str = "./remote_mirror",
    excludes: list[str] | None = None,
    exclude_file: str | None = None,
    sandbox_name: str = "",
) -> dict:
    """Download remote sandbox files/directories to local path via SFTP."""
    remote_root = _normalize_remote(remote_path)
    local_root = Path(local_path).resolve()
    exclude_rules = _build_exclude_rules(excludes, exclude_file)

    start = time.time()
    session = _get_session(sandbox_name)
    client = session.ensure_connected()
    sftp = client.open_sftp()
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
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
