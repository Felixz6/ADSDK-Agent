import os
import shutil
import subprocess
from datetime import datetime, timezone
from typing import List, Optional

from app.config import ADB_TIMEOUT


def ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)


def now_iso() -> str:
    """Current UTC time as ISO-8601 with a trailing Z (e.g. 2026-03-14T10:00:00Z).

    Single source of truth for timestamps written into hook.log; matches the
    ISO_TS_PATTERN consumed by hook_parser.
    """
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def command_exists(cmd: str) -> bool:
    """Return True if an executable is on PATH. Safer than relying on returncode."""
    return shutil.which(cmd) is not None


def _resolve_spawn_argv(cmd: List[str]) -> List[str]:
    """Build the argv actually passed to ``subprocess`` while keeping the
    caller-visible ``cmd`` record identical to what was requested.

    On Windows, ``CreateProcess`` (used by ``subprocess`` with ``shell=False``)
    cannot launch ``cmd``/``bat`` shell scripts directly — only PE executables
    are loaded, with no ``PATHEXT`` search. Tools shipped purely as a ``.bat``
    wrapper on PATH (e.g. ``apktool.bat``) are resolvable via ``shutil.which``
    but raise ``[WinError 2]`` when spawned this way. When the requested head
    resolves to a ``.bat``/``.cmd`` on PATH, launch it through ``cmd.exe /c``
    so the script interpreter handles it. The original ``cmd`` list is never
    mutated; this only constructs a separate spawn argv, so callers that record
    the requested ``cmd`` (tests assert ``["apktool", ...]`` verbatim) see the
    unmodified input.
    """
    if not cmd:
        return cmd
    if os.name != "nt":
        return cmd
    head = cmd[0]
    resolved = shutil.which(head)
    if resolved and resolved.lower().endswith((".bat", ".cmd")):
        return ["cmd.exe", "/c", *cmd]
    return cmd


def run_cmd(
    cmd: List[str],
    cwd: Optional[str] = None,
    timeout: int = ADB_TIMEOUT,
) -> dict:
    """Run a subprocess with a hard timeout.

    Without a timeout, a hung adb/apktool/frida would block the (sync) request
    handler indefinitely. On timeout we return a structured error result instead
    of raising, so callers can keep using the same ``returncode`` contract.
    """
    spawn_argv = _resolve_spawn_argv(cmd)
    try:
        result = subprocess.run(
            spawn_argv,
            capture_output=True,
            text=True,
            shell=False,
            cwd=cwd,
            timeout=timeout,
        )
        return {
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "cmd": cmd,
        }
    except subprocess.TimeoutExpired as e:
        return {
            "returncode": -1,
            "stdout": e.stdout or "",
            "stderr": e.stderr or f"command timed out after {timeout}s",
            "cmd": cmd,
        }
    except FileNotFoundError as e:
        return {
            "returncode": -1,
            "stdout": "",
            "stderr": str(e),
            "cmd": cmd,
        }
