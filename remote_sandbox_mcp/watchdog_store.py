from __future__ import annotations

import json
import os
import sqlite3
import time
from pathlib import Path
from typing import Any, Iterable

APP_NAME = "remote-sandbox-mcp"
LAUNCHD_LABEL = "com.remote-sandbox-mcp.watchdog"
DEFAULT_WATCH_INTERVAL_S = 300
DEFAULT_MAX_LOG_LINES = 80
DEFAULT_LOOP_SLEEP_S = 5
HEARTBEAT_STALE_S = 180
DEFAULT_ALERT_AFTER_FAILURES = 2
DEFAULT_RESUME_DELAY_S = 300


def base_dir() -> Path:
    override = os.environ.get("REMOTE_SANDBOX_MCP_HOME", "").strip()
    if override:
        return Path(override).expanduser()
    home = Path.home()
    if os.name == "posix" and sys_platform() == "darwin":
        return home / "Library" / "Application Support" / APP_NAME
    xdg_state = os.environ.get("XDG_STATE_HOME", "").strip()
    if xdg_state:
        return Path(xdg_state).expanduser() / APP_NAME
    return home / ".local" / "state" / APP_NAME


def sys_platform() -> str:
    return os.uname().sysname.lower() if hasattr(os, "uname") else os.name


def config_path(path: str = "") -> Path:
    return Path(path).expanduser() if path.strip() else base_dir() / "config.json"


def db_path(path: str = "") -> Path:
    return Path(path).expanduser() if path.strip() else base_dir() / "watchdog.sqlite3"


def events_dir(path: str = "") -> Path:
    if path.strip():
        return Path(path).expanduser()
    return base_dir() / "events"


def launch_agent_path(label: str = LAUNCHD_LABEL) -> Path:
    return Path.home() / "Library" / "LaunchAgents" / f"{label}.plist"


def ensure_runtime_dirs(
    cfg_path: str = "",
    database_path: str = "",
    event_dir: str = "",
) -> dict[str, str]:
    use_defaults = not cfg_path.strip() and not database_path.strip() and not event_dir.strip()
    cfg = config_path(cfg_path)
    db = db_path(database_path)
    evt = events_dir(event_dir)
    if use_defaults or cfg_path.strip():
        cfg.parent.mkdir(parents=True, exist_ok=True)
    if use_defaults or database_path.strip():
        db.parent.mkdir(parents=True, exist_ok=True)
    if use_defaults or event_dir.strip():
        evt.mkdir(parents=True, exist_ok=True)
    return {
        "config_path": str(cfg),
        "db_path": str(db),
        "events_dir": str(evt),
    }


def _secure_file(path: Path, mode: int) -> None:
    try:
        os.chmod(path, mode)
    except OSError:
        pass


def save_sandbox_config(
    sandboxes: Iterable[dict[str, Any]],
    path: str = "",
) -> dict[str, Any]:
    ensure_runtime_dirs(cfg_path=path)
    target = config_path(path)
    payload = {
        "schema_version": 1,
        "saved_at": int(time.time()),
        "sandboxes": list(sandboxes),
    }
    target.write_text(json.dumps(payload, ensure_ascii=True, indent=2), encoding="utf-8")
    _secure_file(target, 0o600)
    return {
        "config_path": str(target),
        "sandbox_count": len(payload["sandboxes"]),
    }


def load_sandbox_config(path: str = "") -> dict[str, Any]:
    target = config_path(path)
    if not target.exists():
        return {"schema_version": 1, "saved_at": 0, "sandboxes": []}
    data = json.loads(target.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"Invalid config payload in {target}")
    sandboxes = data.get("sandboxes", [])
    if not isinstance(sandboxes, list):
        raise ValueError(f"Invalid sandboxes list in {target}")
    data.setdefault("schema_version", 1)
    data.setdefault("saved_at", 0)
    return data


def _connect(path: str = "") -> sqlite3.Connection:
    ensure_runtime_dirs(database_path=path)
    conn = sqlite3.connect(db_path(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def init_db(path: str = "") -> dict[str, Any]:
    conn = _connect(path)
    try:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS watches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT NOT NULL DEFAULT '',
                name TEXT NOT NULL DEFAULT '',
                sandbox_name TEXT NOT NULL,
                tmux_session TEXT NOT NULL,
                log_file TEXT NOT NULL,
                cwd TEXT NOT NULL DEFAULT '',
                launch_command TEXT NOT NULL DEFAULT '',
                resume_command TEXT NOT NULL DEFAULT '',
                resume_plan_json TEXT NOT NULL DEFAULT '{}',
                checkpoint_path TEXT NOT NULL DEFAULT '',
                checkpoint_format TEXT NOT NULL DEFAULT 'text',
                checkpoint_command TEXT NOT NULL DEFAULT '',
                interval_s INTEGER NOT NULL DEFAULT 60,
                max_log_lines INTEGER NOT NULL DEFAULT 80,
                status TEXT NOT NULL DEFAULT 'active',
                last_state TEXT NOT NULL DEFAULT '',
                last_summary TEXT NOT NULL DEFAULT '',
                last_error TEXT NOT NULL DEFAULT '',
                last_exit_code INTEGER,
                last_log_digest TEXT NOT NULL DEFAULT '',
                last_log_tail TEXT NOT NULL DEFAULT '',
                last_checkpoint_text TEXT NOT NULL DEFAULT '',
                last_checkpoint_digest TEXT NOT NULL DEFAULT '',
                checkpoint_updated_ts INTEGER NOT NULL DEFAULT 0,
                webhook_url TEXT NOT NULL DEFAULT '',
                event_command TEXT NOT NULL DEFAULT '',
                auto_resume INTEGER NOT NULL DEFAULT 0,
                resume_attempts INTEGER NOT NULL DEFAULT 0,
                max_resume_attempts INTEGER NOT NULL DEFAULT 1,
                alert_after_failures INTEGER NOT NULL DEFAULT 2,
                consecutive_ssh_failures INTEGER NOT NULL DEFAULT 0,
                ssh_alert_sent INTEGER NOT NULL DEFAULT 0,
                notify_local INTEGER NOT NULL DEFAULT 1,
                resume_delay_s INTEGER NOT NULL DEFAULT 300,
                interrupted_ts INTEGER NOT NULL DEFAULT 0,
                resume_due_ts INTEGER NOT NULL DEFAULT 0,
                metadata_json TEXT NOT NULL DEFAULT '{}',
                created_ts INTEGER NOT NULL,
                updated_ts INTEGER NOT NULL,
                last_checked_ts INTEGER NOT NULL DEFAULT 0,
                next_check_ts INTEGER NOT NULL DEFAULT 0,
                last_event_ts INTEGER NOT NULL DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_watches_due
            ON watches(status, next_check_ts);

            CREATE TABLE IF NOT EXISTS watch_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                watch_id INTEGER NOT NULL,
                event_type TEXT NOT NULL,
                summary TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                created_ts INTEGER NOT NULL,
                FOREIGN KEY(watch_id) REFERENCES watches(id)
            );

            CREATE INDEX IF NOT EXISTS idx_watch_events_watch
            ON watch_events(watch_id, created_ts DESC);

            CREATE TABLE IF NOT EXISTS daemon_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_ts INTEGER NOT NULL
            );
            """
        )
        _ensure_watch_columns(conn)
        conn.commit()
    finally:
        conn.close()
    target = db_path(path)
    _secure_file(target, 0o600)
    return {"db_path": str(target)}


def _decode_watch(row: sqlite3.Row | None) -> dict[str, Any] | None:
    if row is None:
        return None
    item = dict(row)
    try:
        item["metadata"] = json.loads(item.pop("metadata_json", "{}") or "{}")
    except json.JSONDecodeError:
        item["metadata"] = {}
    try:
        item["resume_plan"] = json.loads(item.pop("resume_plan_json", "{}") or "{}")
    except json.JSONDecodeError:
        item["resume_plan"] = {}
    item["auto_resume"] = bool(item.get("auto_resume", 0))
    item["notify_local"] = bool(item.get("notify_local", 0))
    item["ssh_alert_sent"] = bool(item.get("ssh_alert_sent", 0))
    return item


def _decode_event(row: sqlite3.Row | None) -> dict[str, Any] | None:
    if row is None:
        return None
    item = dict(row)
    try:
        item["payload"] = json.loads(item.pop("payload_json", "{}") or "{}")
    except json.JSONDecodeError:
        item["payload"] = {}
    return item


def create_watch(
    sandbox_name: str,
    tmux_session: str,
    log_file: str,
    *,
    run_id: str = "",
    name: str = "",
    cwd: str = "",
    launch_command: str = "",
    resume_command: str = "",
    resume_plan: dict[str, Any] | None = None,
    checkpoint_path: str = "",
    checkpoint_format: str = "text",
    checkpoint_command: str = "",
    interval_s: int = DEFAULT_WATCH_INTERVAL_S,
    max_log_lines: int = DEFAULT_MAX_LOG_LINES,
    webhook_url: str = "",
    event_command: str = "",
    auto_resume: bool = False,
    max_resume_attempts: int = 1,
    alert_after_failures: int = DEFAULT_ALERT_AFTER_FAILURES,
    notify_local: bool = True,
    resume_delay_s: int = DEFAULT_RESUME_DELAY_S,
    metadata: dict[str, Any] | None = None,
    path: str = "",
) -> dict[str, Any]:
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
    now = int(time.time())
    conn = _connect(path)
    try:
        cur = conn.execute(
            """
            INSERT INTO watches (
                run_id, name, sandbox_name, tmux_session, log_file, cwd, launch_command,
                resume_command, resume_plan_json, checkpoint_path, checkpoint_format,
                checkpoint_command, interval_s, max_log_lines, webhook_url, event_command,
                auto_resume, max_resume_attempts, alert_after_failures, notify_local,
                resume_delay_s, metadata_json, created_ts, updated_ts, next_check_ts
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id.strip() or tmux_session.strip(),
                name.strip(),
                sandbox_name.strip(),
                tmux_session.strip(),
                log_file.strip(),
                cwd.strip(),
                launch_command,
                resume_command,
                json.dumps(resume_plan or {}, ensure_ascii=True, separators=(",", ":")),
                checkpoint_path.strip(),
                checkpoint_format.strip() or "text",
                checkpoint_command,
                interval_s,
                max_log_lines,
                webhook_url.strip(),
                event_command,
                1 if auto_resume else 0,
                max_resume_attempts,
                alert_after_failures,
                1 if notify_local else 0,
                resume_delay_s,
                json.dumps(metadata or {}, ensure_ascii=True, separators=(",", ":")),
                now,
                now,
                now,
            ),
        )
        conn.commit()
        watch_id = int(cur.lastrowid)
        return get_watch(watch_id, path=path) or {"id": watch_id}
    finally:
        conn.close()


def get_watch(watch_id: int, path: str = "") -> dict[str, Any] | None:
    conn = _connect(path)
    try:
        row = conn.execute("SELECT * FROM watches WHERE id = ?", (watch_id,)).fetchone()
        return _decode_watch(row)
    finally:
        conn.close()


def list_watches(
    *,
    status: str = "",
    path: str = "",
) -> list[dict[str, Any]]:
    conn = _connect(path)
    try:
        if status.strip():
            rows = conn.execute(
                "SELECT * FROM watches WHERE status = ? ORDER BY id DESC",
                (status.strip(),),
            ).fetchall()
        else:
            rows = conn.execute("SELECT * FROM watches ORDER BY id DESC").fetchall()
        return [_decode_watch(row) for row in rows if row is not None]
    finally:
        conn.close()


def list_due_watches(now_ts: int | None = None, *, limit: int = 20, path: str = "") -> list[dict[str, Any]]:
    now = int(time.time()) if now_ts is None else now_ts
    conn = _connect(path)
    try:
        rows = conn.execute(
            """
            SELECT * FROM watches
            WHERE status = 'active'
              AND (next_check_ts = 0 OR next_check_ts <= ?)
            ORDER BY next_check_ts ASC, id ASC
            LIMIT ?
            """,
            (now, limit),
        ).fetchall()
        return [_decode_watch(row) for row in rows if row is not None]
    finally:
        conn.close()


def update_watch(
    watch_id: int,
    *,
    path: str = "",
    **fields: Any,
) -> dict[str, Any]:
    if not fields:
        watch = get_watch(watch_id, path=path)
        if watch is None:
            raise ValueError(f"Unknown watch id: {watch_id}")
        return watch
    updates: dict[str, Any] = dict(fields)
    if "metadata" in updates:
        updates["metadata_json"] = json.dumps(
            updates.pop("metadata") or {},
            ensure_ascii=True,
            separators=(",", ":"),
        )
    if "resume_plan" in updates:
        updates["resume_plan_json"] = json.dumps(
            updates.pop("resume_plan") or {},
            ensure_ascii=True,
            separators=(",", ":"),
        )
    now = int(time.time())
    updates["updated_ts"] = now

    columns = ", ".join(f"{key} = ?" for key in updates.keys())
    values = list(updates.values())
    values.append(watch_id)
    conn = _connect(path)
    try:
        cur = conn.execute(f"UPDATE watches SET {columns} WHERE id = ?", values)
        if cur.rowcount == 0:
            raise ValueError(f"Unknown watch id: {watch_id}")
        conn.commit()
        watch = conn.execute("SELECT * FROM watches WHERE id = ?", (watch_id,)).fetchone()
        return _decode_watch(watch) or {"id": watch_id}
    finally:
        conn.close()


def cancel_watch(watch_id: int, *, path: str = "") -> dict[str, Any]:
    return update_watch(
        watch_id,
        path=path,
        status="cancelled",
        next_check_ts=0,
    )


def record_event(
    watch_id: int,
    event_type: str,
    summary: str,
    payload: dict[str, Any],
    *,
    path: str = "",
) -> dict[str, Any]:
    now = int(time.time())
    conn = _connect(path)
    try:
        cur = conn.execute(
            """
            INSERT INTO watch_events (watch_id, event_type, summary, payload_json, created_ts)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                watch_id,
                event_type,
                summary,
                json.dumps(payload, ensure_ascii=True, separators=(",", ":")),
                now,
            ),
        )
        conn.execute(
            "UPDATE watches SET last_event_ts = ?, updated_ts = ? WHERE id = ?",
            (now, now, watch_id),
        )
        conn.commit()
        event_id = int(cur.lastrowid)
        row = conn.execute("SELECT * FROM watch_events WHERE id = ?", (event_id,)).fetchone()
        return _decode_event(row) or {"id": event_id}
    finally:
        conn.close()


def list_events(
    *,
    watch_id: int = 0,
    limit: int = 20,
    path: str = "",
) -> list[dict[str, Any]]:
    if limit <= 0:
        raise ValueError("limit must be positive")
    conn = _connect(path)
    try:
        if watch_id > 0:
            rows = conn.execute(
                """
                SELECT * FROM watch_events
                WHERE watch_id = ?
                ORDER BY id DESC
                LIMIT ?
                """,
                (watch_id, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM watch_events ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [_decode_event(row) for row in rows if row is not None]
    finally:
        conn.close()


def set_daemon_meta(key: str, value: Any, *, path: str = "") -> None:
    now = int(time.time())
    conn = _connect(path)
    try:
        conn.execute(
            """
            INSERT INTO daemon_meta(key, value, updated_ts)
            VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_ts = excluded.updated_ts
            """,
            (key, json.dumps(value, ensure_ascii=True, separators=(",", ":")), now),
        )
        conn.commit()
    finally:
        conn.close()


def get_daemon_meta(key: str, *, path: str = "") -> dict[str, Any] | None:
    conn = _connect(path)
    try:
        row = conn.execute(
            "SELECT key, value, updated_ts FROM daemon_meta WHERE key = ?",
            (key,),
        ).fetchone()
        if row is None:
            return None
        try:
            value = json.loads(row["value"])
        except json.JSONDecodeError:
            value = row["value"]
        return {
            "key": row["key"],
            "value": value,
            "updated_ts": row["updated_ts"],
        }
    finally:
        conn.close()


def list_daemon_meta(*, path: str = "") -> dict[str, Any]:
    conn = _connect(path)
    try:
        rows = conn.execute("SELECT key, value, updated_ts FROM daemon_meta").fetchall()
        result: dict[str, Any] = {}
        for row in rows:
            try:
                value = json.loads(row["value"])
            except json.JSONDecodeError:
                value = row["value"]
            result[row["key"]] = {
                "value": value,
                "updated_ts": row["updated_ts"],
            }
        return result
    finally:
        conn.close()


def _ensure_watch_columns(conn: sqlite3.Connection) -> None:
    existing = {
        row["name"]
        for row in conn.execute("PRAGMA table_info(watches)").fetchall()
    }
    required = {
        "run_id": "TEXT NOT NULL DEFAULT ''",
        "resume_plan_json": "TEXT NOT NULL DEFAULT '{}'",
        "checkpoint_path": "TEXT NOT NULL DEFAULT ''",
        "checkpoint_format": "TEXT NOT NULL DEFAULT 'text'",
        "checkpoint_command": "TEXT NOT NULL DEFAULT ''",
        "last_log_tail": "TEXT NOT NULL DEFAULT ''",
        "last_checkpoint_text": "TEXT NOT NULL DEFAULT ''",
        "last_checkpoint_digest": "TEXT NOT NULL DEFAULT ''",
        "checkpoint_updated_ts": "INTEGER NOT NULL DEFAULT 0",
        "alert_after_failures": f"INTEGER NOT NULL DEFAULT {DEFAULT_ALERT_AFTER_FAILURES}",
        "consecutive_ssh_failures": "INTEGER NOT NULL DEFAULT 0",
        "ssh_alert_sent": "INTEGER NOT NULL DEFAULT 0",
        "notify_local": "INTEGER NOT NULL DEFAULT 1",
        "resume_delay_s": f"INTEGER NOT NULL DEFAULT {DEFAULT_RESUME_DELAY_S}",
        "interrupted_ts": "INTEGER NOT NULL DEFAULT 0",
        "resume_due_ts": "INTEGER NOT NULL DEFAULT 0",
    }
    for column, ddl in required.items():
        if column in existing:
            continue
        conn.execute(f"ALTER TABLE watches ADD COLUMN {column} {ddl}")
