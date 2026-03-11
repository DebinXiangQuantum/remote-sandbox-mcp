from __future__ import annotations

import os
import plistlib
import subprocess
import sys
from pathlib import Path
from typing import Any

from remote_sandbox_mcp.watchdog_store import LAUNCHD_LABEL, ensure_runtime_dirs, launch_agent_path


def _launchctl_target() -> str:
    return f"gui/{os.getuid()}"


def _program_args(config_path: str, db_path: str) -> list[str]:
    return [
        sys.executable,
        "-m",
        "remote_sandbox_mcp.server",
        "daemon",
        "--config",
        config_path,
        "--db",
        db_path,
    ]


def install_launch_agent(
    *,
    config_path: str,
    db_path: str,
    label: str = LAUNCHD_LABEL,
    start_now: bool = True,
) -> dict[str, Any]:
    if sys.platform != "darwin":
        raise RuntimeError("launchd installation is only supported on macOS")

    paths = ensure_runtime_dirs(cfg_path=config_path, database_path=db_path)
    plist_path = launch_agent_path(label)
    plist_path.parent.mkdir(parents=True, exist_ok=True)

    stdout_path = str(Path(paths["db_path"]).with_name("watchdog.stdout.log"))
    stderr_path = str(Path(paths["db_path"]).with_name("watchdog.stderr.log"))
    env_path = os.environ.get(
        "PATH",
        "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
    )

    payload = {
        "Label": label,
        "ProgramArguments": _program_args(paths["config_path"], paths["db_path"]),
        "RunAtLoad": True,
        "KeepAlive": True,
        "WorkingDirectory": str(Path(paths["db_path"]).parent),
        "EnvironmentVariables": {
            "PATH": env_path,
            "PYTHONUNBUFFERED": "1",
        },
        "StandardOutPath": stdout_path,
        "StandardErrorPath": stderr_path,
    }
    with plist_path.open("wb") as fh:
        plistlib.dump(payload, fh, sort_keys=True)
    os.chmod(plist_path, 0o644)

    if start_now:
        _run_launchctl(["bootout", _launchctl_target(), str(plist_path)], ignore_errors=True)
        _run_launchctl(["bootstrap", _launchctl_target(), str(plist_path)])
        _run_launchctl(["kickstart", "-k", f"{_launchctl_target()}/{label}"])

    return {
        "label": label,
        "plist_path": str(plist_path),
        "stdout_path": stdout_path,
        "stderr_path": stderr_path,
        "config_path": paths["config_path"],
        "db_path": paths["db_path"],
        "started": start_now,
    }


def uninstall_launch_agent(label: str = LAUNCHD_LABEL) -> dict[str, Any]:
    if sys.platform != "darwin":
        raise RuntimeError("launchd removal is only supported on macOS")

    plist_path = launch_agent_path(label)
    if plist_path.exists():
        _run_launchctl(["bootout", _launchctl_target(), str(plist_path)], ignore_errors=True)
        plist_path.unlink(missing_ok=True)
    return {"label": label, "plist_path": str(plist_path), "removed": True}


def get_launch_agent_status(label: str = LAUNCHD_LABEL) -> dict[str, Any]:
    if sys.platform != "darwin":
        return {
            "platform": sys.platform,
            "label": label,
            "loaded": False,
            "detail": "launchd status is only available on macOS",
        }
    result = subprocess.run(
        ["launchctl", "print", f"{_launchctl_target()}/{label}"],
        capture_output=True,
        text=True,
        check=False,
    )
    return {
        "platform": sys.platform,
        "label": label,
        "loaded": result.returncode == 0,
        "stdout": result.stdout.strip(),
        "stderr": result.stderr.strip(),
        "exit_code": result.returncode,
        "plist_path": str(launch_agent_path(label)),
    }


def _run_launchctl(args: list[str], *, ignore_errors: bool = False) -> None:
    result = subprocess.run(
        ["launchctl", *args],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0 and not ignore_errors:
        message = result.stderr.strip() or result.stdout.strip() or "unknown launchctl error"
        raise RuntimeError(message)
