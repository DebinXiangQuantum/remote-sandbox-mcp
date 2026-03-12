from __future__ import annotations

import hashlib
import json
import os
import posixpath
import shlex
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

import paramiko

from remote_sandbox_mcp.watchdog_store import (
    DEFAULT_LOOP_SLEEP_S,
    HEARTBEAT_STALE_S,
    init_db,
    list_due_watches,
    load_sandbox_config,
    record_event,
    set_daemon_meta,
    update_watch,
)

_CONNECT_TIMEOUT = 15.0
_HEALTH_CHECK_INTERVAL = 30.0


@dataclass
class SandboxConfig:
    name: str
    host: str
    user: str
    password: str = ""
    port: int = 22
    key_file: str = ""
    key_passphrase: str = ""


_KEY_CLASSES = (
    paramiko.Ed25519Key,
    paramiko.RSAKey,
    paramiko.ECDSAKey,
)


def _load_private_key(key_file: str, passphrase: str = "") -> paramiko.PKey:
    path = os.path.expanduser(key_file)
    pw: Optional[str] = passphrase if passphrase else None
    last_exc: Exception = Exception("no key types tried")
    for cls in _KEY_CLASSES:
        try:
            return cls.from_private_key_file(path, password=pw)
        except paramiko.SSHException as exc:
            last_exc = exc
        except (FileNotFoundError, PermissionError):
            raise
    raise ValueError(
        f"Cannot load private key from {key_file!r}: unsupported key type or wrong passphrase. "
        f"({last_exc})"
    )


class SandboxSession:
    def __init__(self, config: SandboxConfig) -> None:
        self.config = config
        self._client: Optional[paramiko.SSHClient] = None
        self._last_health_check = 0.0

    def _make_client(self) -> paramiko.SSHClient:
        cfg = self.config
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        pkey: Optional[paramiko.PKey] = None
        if cfg.key_file:
            pkey = _load_private_key(cfg.key_file, cfg.key_passphrase)

        kwargs: dict[str, Any] = {
            "hostname": cfg.host,
            "port": cfg.port,
            "username": cfg.user,
            "look_for_keys": False,
            "allow_agent": False,
            "timeout": _CONNECT_TIMEOUT,
            "auth_timeout": _CONNECT_TIMEOUT,
            "banner_timeout": _CONNECT_TIMEOUT,
        }
        if pkey is not None:
            kwargs["pkey"] = pkey
        else:
            kwargs["password"] = cfg.password
        client.connect(**kwargs)
        return client

    def is_alive(self) -> bool:
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
        now = time.monotonic()
        if now - self._last_health_check > _HEALTH_CHECK_INTERVAL:
            if not self.is_alive():
                self.close()
            self._last_health_check = now
        if self._client is None:
            self._client = self._make_client()
        return self._client

    def close(self) -> None:
        if self._client is not None:
            try:
                self._client.close()
            except Exception:
                pass
            self._client = None


class SessionRegistry:
    def __init__(self) -> None:
        self._sessions: dict[str, tuple[str, SandboxSession]] = {}

    def get(self, config: SandboxConfig) -> SandboxSession:
        signature = json.dumps(config.__dict__, ensure_ascii=True, sort_keys=True)
        cached = self._sessions.get(config.name)
        if cached and cached[0] == signature:
            return cached[1]
        if cached:
            cached[1].close()
        session = SandboxSession(config)
        self._sessions[config.name] = (signature, session)
        return session

    def close_all(self) -> None:
        for _, session in self._sessions.values():
            session.close()
        self._sessions.clear()


def _exec_on_channel(
    client: paramiko.SSHClient,
    command: str,
    timeout_s: int = 120,
    max_output_chars: int = 20000,
) -> dict[str, Any]:
    transport = client.get_transport()
    if transport is None or not transport.is_active():
        raise ConnectionError("SSH transport is not active; the connection may have dropped")

    wrapped = f"timeout {timeout_s}s bash -c {shlex.quote(command)}"
    channel = transport.open_session()
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
                    "stderr": f"[TIMEOUT] Client-side deadline exceeded after {timeout_s}s",
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
    return {
        "exit_code": exit_code,
        "stdout": out_text,
        "stderr": err_text,
        "timed_out": exit_code == 124,
    }


def _check_task(
    session: SandboxSession,
    tmux_session: str,
    log_file: str,
    max_log_lines: int,
) -> dict[str, Any]:
    client = session.ensure_connected()
    status = _exec_on_channel(
        client,
        f"tmux has-session -t {shlex.quote(tmux_session)} 2>/dev/null && echo RUNNING || echo DONE",
        timeout_s=10,
        max_output_chars=200,
    )
    if status.get("connection_error"):
        return {
            "connection_error": True,
            "error": status.get("stderr", "").strip(),
        }

    log_tail = ""
    exit_code = None
    log_result = _exec_on_channel(
        client,
        f"tail -n {max_log_lines} {shlex.quote(log_file)} 2>/dev/null || echo '[log file not found]'",
        timeout_s=15,
        max_output_chars=20000,
    )
    if log_result.get("connection_error"):
        return {
            "connection_error": True,
            "error": log_result.get("stderr", "").strip(),
        }
    log_tail = log_result.get("stdout", "")
    for line in reversed(log_tail.splitlines()):
        if line.startswith("EXIT_CODE="):
            try:
                exit_code = int(line.split("=", 1)[1].strip())
            except ValueError:
                exit_code = None
            break
    return {
        "running": "RUNNING" in status.get("stdout", ""),
        "exit_code": exit_code,
        "log_tail": log_tail,
        "log_digest": hashlib.sha1(log_tail.encode("utf-8", errors="replace")).hexdigest(),
    }


def _remote_home(session: SandboxSession) -> str:
    client = session.ensure_connected()
    result = _exec_on_channel(client, 'printf "%s" "$HOME"', timeout_s=10, max_output_chars=200)
    home = result.get("stdout", "").strip()
    if result.get("exit_code") != 0 or not home:
        raise ValueError("Unable to resolve remote home directory")
    return home


def _resolve_remote_path(session: SandboxSession, cwd: str, path: str) -> str:
    raw_path = path.strip()
    if not raw_path:
        return ""

    home = _remote_home(session)
    raw_cwd = cwd.strip()
    resolved_cwd = raw_cwd
    if resolved_cwd == "~":
        resolved_cwd = home
    elif resolved_cwd.startswith("~/"):
        resolved_cwd = posixpath.join(home, resolved_cwd[2:])
    elif resolved_cwd and not posixpath.isabs(resolved_cwd):
        resolved_cwd = posixpath.normpath(posixpath.join(home, resolved_cwd))

    if raw_path == "~":
        return home
    if raw_path.startswith("~/"):
        return posixpath.join(home, raw_path[2:])
    if posixpath.isabs(raw_path):
        return posixpath.normpath(raw_path)

    base_dir = resolved_cwd or home
    normalized_path = posixpath.normpath(raw_path)
    if raw_cwd and not posixpath.isabs(raw_cwd):
        normalized_cwd = posixpath.normpath(raw_cwd)
        cwd_prefix = normalized_cwd.rstrip("/") + "/"
        if normalized_path == normalized_cwd or normalized_path.startswith(cwd_prefix):
            suffix = posixpath.relpath(normalized_path, normalized_cwd)
            return posixpath.normpath(posixpath.join(base_dir, suffix))
    return posixpath.normpath(posixpath.join(base_dir, normalized_path))


def _start_background_task(
    session: SandboxSession,
    command: str,
    cwd: str,
    session_name: str,
    log_file: str,
) -> dict[str, Any]:
    client = session.ensure_connected()
    resolved_cwd = _resolve_remote_path(session, "", cwd)
    resolved_log_file = _resolve_remote_path(session, cwd, log_file)
    command_log_file = resolved_log_file
    if resolved_cwd:
        command_log_file = posixpath.relpath(resolved_log_file, resolved_cwd)
    command_preview = " ".join(command.split())[:120]
    script_content = "\n".join(
        [
            "#!/usr/bin/env bash",
            "set -uo pipefail",
            f"mkdir -p {shlex.quote(posixpath.dirname(command_log_file) or '.')}",
            *((f"cd {shlex.quote(resolved_cwd)}",) if resolved_cwd else ()),
            "{",
            f"  printf '%s\\n' {shlex.quote(f'== session: {session_name}')}",
            "  printf '== started_at: %s\\n' \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"",
            f"  printf '%s\\n' {shlex.quote(f'== command: {command_preview}')}",
            f"  {command}",
            "  rc=$?",
            "  printf 'EXIT_CODE=%s\\n' \"$rc\"",
            f"}} 2>&1 | tee -a {shlex.quote(command_log_file)}",
            "rc=${PIPESTATUS[0]}",
            "exit \"$rc\"",
        ]
    )
    script_path = posixpath.join(
        posixpath.dirname(resolved_log_file) or ".codex_logs",
        ".rsmcp",
        f"{session_name}.sh",
    )
    launcher = "\n".join(
        [
            f"mkdir -p {shlex.quote(posixpath.dirname(script_path) or '.')}",
            "cat > " + shlex.quote(script_path) + " <<'__RSMCP_BG__'",
            script_content,
            "__RSMCP_BG__",
            f"chmod 700 {shlex.quote(script_path)}",
            f"tmux new-session -d -s {shlex.quote(session_name)} bash {shlex.quote(script_path)}",
        ]
    )
    result = _exec_on_channel(
        client,
        launcher,
        timeout_s=15,
        max_output_chars=2000,
    )
    return {
        "started": result.get("exit_code") == 0,
        "stdout": result.get("stdout", ""),
        "stderr": result.get("stderr", ""),
    }


def _read_checkpoint(
    session: SandboxSession,
    checkpoint_path: str,
    checkpoint_format: str,
    checkpoint_command: str,
) -> dict[str, Any]:
    if not checkpoint_path.strip() and not checkpoint_command.strip():
        return {
            "text": "",
            "digest": "",
            "parsed": None,
        }

    client = session.ensure_connected()
    if checkpoint_command.strip():
        command = checkpoint_command
    else:
        command = (
            f"cat {shlex.quote(checkpoint_path)} 2>/dev/null "
            "|| echo '[checkpoint file not found]'"
        )
    result = _exec_on_channel(
        client,
        command,
        timeout_s=15,
        max_output_chars=20000,
    )
    if result.get("connection_error"):
        return {
            "connection_error": True,
            "error": result.get("stderr", "").strip(),
        }

    text = result.get("stdout", "")
    parsed = None
    if checkpoint_format.strip().lower() == "json" and text.strip():
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            parsed = None
    return {
        "text": text,
        "digest": hashlib.sha1(text.encode("utf-8", errors="replace")).hexdigest(),
        "parsed": parsed,
    }


def _event_file_path(event_id: int, db_path: str) -> Path:
    directory = Path(db_path).expanduser().resolve().parent / "events"
    directory.mkdir(parents=True, exist_ok=True)
    return directory / f"event-{event_id}.json"


def _should_send_local_popup(watch: dict[str, Any], event_type: str) -> bool:
    if not watch.get("notify_local", False):
        return False
    return event_type in {"ssh_unreachable", "resume_failed"}


def _send_local_popup(watch: dict[str, Any], event_type: str, summary: str) -> None:
    if not hasattr(os, "uname") or os.uname().sysname.lower() != "darwin":
        return

    title = "Remote Sandbox Watchdog"
    name = watch.get("name", "").strip() or watch.get("run_id", "").strip() or watch.get("tmux_session", "")
    subtitle = f"watch {watch['id']} · {name}"[:120]
    message = summary.replace("\n", " ").strip()[:240]
    script = (
        f"display notification {json.dumps(message)} "
        f"with title {json.dumps(title)} subtitle {json.dumps(subtitle)}"
    )
    try:
        subprocess.run(
            ["/usr/bin/osascript", "-e", script],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except Exception as exc:
        print(f"[watchdog] local notification failed for watch {watch['id']}: {exc}", flush=True)


def _suggested_codex_prompt(watch: dict[str, Any], event_type: str, summary: str, log_tail: str) -> str:
    parts = [
        "Inspect the remote sandbox long-running task and decide how to resume it.",
        f"Run id: {watch.get('run_id', '')}",
        f"Watch id: {watch['id']}",
        f"Sandbox: {watch['sandbox_name']}",
        f"tmux session: {watch['tmux_session']}",
        f"log file: {watch['log_file']}",
        f"Current event: {event_type}",
        f"Summary: {summary}",
    ]
    if watch.get("checkpoint_path"):
        parts.append(f"Checkpoint path: {watch['checkpoint_path']}")
    if watch.get("resume_command"):
        parts.append(f"Suggested resume command: {watch['resume_command']}")
    plan = watch.get("resume_plan") or {}
    if plan:
        parts.append("Resume plan JSON:\n" + json.dumps(plan, ensure_ascii=True))
    elif watch.get("launch_command"):
        parts.append(f"Original launch command: {watch['launch_command']}")
    if log_tail.strip():
        parts.append("Latest log tail:\n" + log_tail.strip())
    if watch.get("last_checkpoint_text", "").strip():
        parts.append("Latest checkpoint:\n" + watch["last_checkpoint_text"].strip())
    return "\n".join(parts)


def _dispatch_event(
    watch: dict[str, Any],
    event_type: str,
    summary: str,
    payload: dict[str, Any],
    db_path: str,
) -> None:
    event = record_event(watch["id"], event_type, summary, payload, path=db_path)
    event_file = _event_file_path(event["id"], db_path)
    prompt = payload.get("suggested_codex_prompt", "")
    event_file.write_text(json.dumps(event, ensure_ascii=True, indent=2), encoding="utf-8")
    if _should_send_local_popup(watch, event_type):
        _send_local_popup(watch, event_type, summary)

    webhook_url = watch.get("webhook_url", "").strip()
    if webhook_url:
        body = json.dumps(event, ensure_ascii=True).encode("utf-8")
        request = urllib.request.Request(
            webhook_url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=15):
                pass
        except urllib.error.URLError as exc:
            print(f"[watchdog] webhook delivery failed for watch {watch['id']}: {exc}", flush=True)

    event_command = watch.get("event_command", "").strip()
    if event_command:
        env = os.environ.copy()
        env.update(
            {
                "RSMCP_EVENT_FILE": str(event_file),
                "RSMCP_EVENT_JSON": json.dumps(event, ensure_ascii=True),
                "RSMCP_EVENT_TYPE": event_type,
                "RSMCP_WATCH_ID": str(watch["id"]),
                "RSMCP_SANDBOX_NAME": watch["sandbox_name"],
                "RSMCP_TMUX_SESSION": watch["tmux_session"],
                "RSMCP_LOG_FILE": watch["log_file"],
                "RSMCP_SUGGESTED_PROMPT": prompt,
            }
        )
        try:
            result = subprocess.run(
                ["/bin/sh", "-lc", event_command],
                env=env,
                capture_output=True,
                text=True,
                timeout=300,
                check=False,
            )
            if result.returncode != 0:
                print(
                    "[watchdog] event command failed for watch "
                    f"{watch['id']}: {result.stderr.strip() or result.stdout.strip()}",
                    flush=True,
                )
        except Exception as exc:
            print(f"[watchdog] event command crashed for watch {watch['id']}: {exc}", flush=True)


def _emit_state_event(
    watch: dict[str, Any],
    event_type: str,
    summary: str,
    *,
    db_path: str,
    log_tail: str = "",
    extra: dict[str, Any] | None = None,
) -> None:
    payload = {
        "watch": {
            "id": watch["id"],
            "run_id": watch.get("run_id", ""),
            "name": watch.get("name", ""),
            "sandbox_name": watch["sandbox_name"],
            "tmux_session": watch["tmux_session"],
            "log_file": watch["log_file"],
            "checkpoint_path": watch.get("checkpoint_path", ""),
            "resume_attempts": watch.get("resume_attempts", 0),
            "max_resume_attempts": watch.get("max_resume_attempts", 0),
            "auto_resume": watch.get("auto_resume", False),
            "status": watch.get("status", ""),
            "last_state": watch.get("last_state", ""),
        },
        "summary": summary,
        "log_tail": log_tail,
        "checkpoint_text": watch.get("last_checkpoint_text", ""),
        "suggested_codex_prompt": _suggested_codex_prompt(watch, event_type, summary, log_tail),
    }
    if extra:
        payload.update(extra)
    _dispatch_event(watch, event_type, summary, payload, db_path)


class WatchdogDaemon:
    def __init__(self, *, config_path: str, db_path: str, loop_sleep_s: int = DEFAULT_LOOP_SLEEP_S) -> None:
        self.config_path = config_path
        self.db_path = db_path
        self.loop_sleep_s = max(loop_sleep_s, 1)
        self.sessions = SessionRegistry()

    def run_forever(self) -> None:
        init_db(self.db_path)
        print("[watchdog] started", flush=True)
        try:
            while True:
                self._tick()
                time.sleep(self.loop_sleep_s)
        finally:
            self.sessions.close_all()

    def _tick(self) -> None:
        now = int(time.time())
        set_daemon_meta(
            "heartbeat",
            {
                "ts": now,
                "stale_after_s": HEARTBEAT_STALE_S,
                "config_path": self.config_path,
                "db_path": self.db_path,
            },
            path=self.db_path,
        )
        configs = self._load_configs()
        due = list_due_watches(now, path=self.db_path)
        set_daemon_meta(
            "last_scan",
            {"ts": now, "due_watch_count": len(due)},
            path=self.db_path,
        )
        for watch in due:
            self._process_watch(watch, configs, now)

    def _load_configs(self) -> dict[str, SandboxConfig]:
        payload = load_sandbox_config(self.config_path)
        configs: dict[str, SandboxConfig] = {}
        for item in payload.get("sandboxes", []):
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or item.get("host") or "").strip()
            host = str(item.get("host") or "").strip()
            user = str(item.get("user") or "").strip()
            if not name or not host or not user:
                continue
            configs[name] = SandboxConfig(
                name=name,
                host=host,
                user=user,
                password=str(item.get("password", "")),
                port=int(item.get("port", 22)),
                key_file=str(item.get("key_file", "")),
                key_passphrase=str(item.get("key_passphrase", "")),
            )
        return configs

    def _record_ssh_failure(
        self,
        watch: dict[str, Any],
        now: int,
        summary: str,
    ) -> None:
        failure_count = int(watch.get("consecutive_ssh_failures", 0)) + 1
        alert_after = max(int(watch.get("alert_after_failures", 1)), 1)
        should_alert = failure_count >= alert_after and not watch.get("ssh_alert_sent", False)
        if should_alert:
            state_summary = (
                f"{summary} "
                f"(failed {failure_count} consecutive checks; user notification sent)"
            )
        else:
            state_summary = (
                f"{summary} "
                f"(failed {failure_count} consecutive checks; alert after {alert_after})"
            )

        updated = update_watch(
            watch["id"],
            path=self.db_path,
            last_state="ssh_unreachable",
            last_summary=state_summary,
            last_error=summary,
            consecutive_ssh_failures=failure_count,
            ssh_alert_sent=1 if (should_alert or watch.get("ssh_alert_sent", False)) else 0,
            last_checked_ts=now,
            next_check_ts=now + watch["interval_s"],
        )
        if should_alert:
            _emit_state_event(
                updated,
                "ssh_unreachable",
                state_summary,
                db_path=self.db_path,
            )

    def _reset_connection_state(self, updates: dict[str, Any]) -> dict[str, Any]:
        merged = dict(updates)
        merged.setdefault("consecutive_ssh_failures", 0)
        merged.setdefault("ssh_alert_sent", 0)
        return merged

    def _process_watch(self, watch: dict[str, Any], configs: dict[str, SandboxConfig], now: int) -> None:
        cfg = configs.get(watch["sandbox_name"])
        if cfg is None:
            updated = update_watch(
                watch["id"],
                path=self.db_path,
                last_state="config_missing",
                last_summary=f"Sandbox {watch['sandbox_name']!r} is missing from persisted config",
                last_error="persisted sandbox config missing",
                last_checked_ts=now,
                next_check_ts=now + watch["interval_s"],
            )
            if watch.get("last_state") != "config_missing":
                _emit_state_event(
                    updated,
                    "config_missing",
                    updated["last_summary"],
                    db_path=self.db_path,
                )
            return

        try:
            session = self.sessions.get(cfg)
            session.ensure_connected()
        except Exception as exc:
            summary = f"SSH unreachable for {cfg.user}@{cfg.host}:{cfg.port}: {exc}"
            self._record_ssh_failure(watch, now, summary)
            return

        result = _check_task(
            session,
            watch["tmux_session"],
            watch["log_file"],
            watch["max_log_lines"],
        )
        if result.get("connection_error"):
            summary = result.get("error", "SSH connection failed while checking background task")
            self._record_ssh_failure(watch, now, summary)
            return

        log_tail = result.get("log_tail", "")
        digest = result.get("log_digest", "")
        checkpoint = _read_checkpoint(
            session,
            watch.get("checkpoint_path", ""),
            watch.get("checkpoint_format", "text"),
            watch.get("checkpoint_command", ""),
        )
        checkpoint_text = checkpoint.get("text", "")
        checkpoint_digest = checkpoint.get("digest", "")
        checkpoint_updated_ts = (
            now if checkpoint_digest and checkpoint_digest != watch.get("last_checkpoint_digest", "") else 0
        )

        common_updates = {
            "last_log_digest": digest,
            "last_log_tail": log_tail,
            "last_checkpoint_text": checkpoint_text,
            "last_checkpoint_digest": checkpoint_digest,
            "last_checked_ts": now,
            "next_check_ts": now + watch["interval_s"],
            "consecutive_ssh_failures": 0,
            "ssh_alert_sent": 0,
        }
        if checkpoint_updated_ts:
            common_updates["checkpoint_updated_ts"] = checkpoint_updated_ts

        if result.get("running"):
            summary = "Background task is still running"
            updated = update_watch(
                watch["id"],
                path=self.db_path,
                last_state="running",
                last_summary=summary,
                last_error="",
                interrupted_ts=0,
                resume_due_ts=0,
                **self._reset_connection_state(common_updates),
            )
            if watch.get("last_state") not in ("", "running"):
                _emit_state_event(
                    updated,
                    "running_restored",
                    summary,
                    db_path=self.db_path,
                    log_tail=log_tail,
                )
            return

        if result.get("exit_code") is not None:
            summary = f"Background task completed with exit code {result['exit_code']}"
            updated = update_watch(
                watch["id"],
                path=self.db_path,
                status="completed",
                last_state="completed",
                last_summary=summary,
                last_exit_code=result["exit_code"],
                last_error="",
                interrupted_ts=0,
                resume_due_ts=0,
                next_check_ts=0,
                **{
                    key: value
                    for key, value in self._reset_connection_state(common_updates).items()
                    if key != "next_check_ts"
                },
            )
            if watch.get("last_state") != "completed":
                _emit_state_event(
                    updated,
                    "completed",
                    summary,
                    db_path=self.db_path,
                    log_tail=log_tail,
                    extra={"exit_code": result["exit_code"]},
                )
            return

        resume_delay_s = max(int(watch.get("resume_delay_s", 0)), 0)
        first_interrupt = int(watch.get("interrupted_ts", 0)) == 0
        interrupted_ts = int(watch.get("interrupted_ts", 0)) or now
        resume_due_ts = int(watch.get("resume_due_ts", 0)) or (
            interrupted_ts + resume_delay_s if resume_delay_s > 0 else interrupted_ts
        )
        if resume_due_ts > now:
            wait_s = resume_due_ts - now
            summary = (
                "tmux session disappeared before EXIT_CODE was written; "
                f"waiting {wait_s}s before resume check"
            )
        else:
            summary = "tmux session disappeared before EXIT_CODE was written"
        updated = update_watch(
            watch["id"],
            path=self.db_path,
            last_state="interrupted",
            last_summary=summary,
            last_error=summary,
            interrupted_ts=interrupted_ts,
            resume_due_ts=resume_due_ts,
            **self._reset_connection_state(common_updates),
        )
        if first_interrupt:
            _emit_state_event(
                updated,
                "interrupted",
                summary,
                db_path=self.db_path,
                log_tail=log_tail,
            )

        plan = updated.get("resume_plan") or {}
        command = (
            str(plan.get("resume_command", "")).strip()
            or updated.get("resume_command", "")
            or updated.get("launch_command", "")
        )
        can_resume = (
            updated.get("auto_resume")
            and command.strip()
            and updated.get("resume_attempts", 0) < updated.get("max_resume_attempts", 0)
        )
        if not can_resume or resume_due_ts > now:
            return

        next_attempt = updated.get("resume_attempts", 0) + 1
        resume_session = str(plan.get("tmux_session", "")).strip() or updated["tmux_session"]
        resume = _start_background_task(
            session,
            command,
            updated.get("cwd", ""),
            resume_session,
            updated["log_file"],
        )
        if resume.get("started"):
            resumed = update_watch(
                updated["id"],
                path=self.db_path,
                resume_attempts=next_attempt,
                last_state="running",
                last_summary=f"Started resume attempt {next_attempt} in tmux session {resume_session}",
                last_error="",
                interrupted_ts=0,
                resume_due_ts=0,
                last_checked_ts=now,
                next_check_ts=now + updated["interval_s"],
            )
            _emit_state_event(
                resumed,
                "resume_started",
                resumed["last_summary"],
                db_path=self.db_path,
                log_tail=log_tail,
                extra={"resume_attempt": next_attempt},
            )
            return

        failed = update_watch(
            updated["id"],
            path=self.db_path,
            resume_attempts=next_attempt,
            last_summary=f"Resume attempt {next_attempt} failed to start",
            last_error=resume.get("stderr", "").strip() or "failed to start resume command",
            resume_due_ts=now + max(updated.get("interval_s", 0), updated.get("resume_delay_s", 0)),
            last_checked_ts=now,
            next_check_ts=now + updated["interval_s"],
        )
        _emit_state_event(
            failed,
            "resume_failed",
            failed["last_summary"],
            db_path=self.db_path,
            log_tail=log_tail,
            extra={
                "resume_attempt": next_attempt,
                "stderr": resume.get("stderr", ""),
                "stdout": resume.get("stdout", ""),
            },
        )
