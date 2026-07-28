import os
import shutil
import signal
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
        # The bundled apktool wrapper is a one-line ``java -jar`` launcher.
        # Spawn Java directly so timeout ownership stays on the long-running
        # process instead of an intermediate cmd.exe that may exit first.
        if os.path.basename(head).casefold() == "apktool":
            companion_jar = os.path.join(
                os.path.dirname(resolved),
                "apktool.jar",
            )
            java = shutil.which("java")
            if java and os.path.isfile(companion_jar):
                return [java, "-jar", companion_jar, *cmd[1:]]
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
    process: subprocess.Popen[str] | None = None
    try:
        process_options = {
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
            "text": True,
            "shell": False,
            "cwd": cwd,
        }
        if os.name == "nt":
            process_options["creationflags"] = getattr(
                subprocess,
                "CREATE_NEW_PROCESS_GROUP",
                0,
            )
        else:
            process_options["start_new_session"] = True
        process = subprocess.Popen(
            spawn_argv,
            **process_options,
        )
        stdout, stderr = process.communicate(timeout=timeout)
        return {
            "returncode": process.returncode,
            "stdout": stdout,
            "stderr": stderr,
            "cmd": cmd,
            "timed_out": False,
        }
    except subprocess.TimeoutExpired as e:
        if process is not None:
            _terminate_owned_process_tree(process)
            try:
                stdout, stderr = process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                try:
                    stdout, stderr = process.communicate(timeout=1)
                except (subprocess.TimeoutExpired, OSError):
                    stdout, stderr = e.stdout or "", e.stderr or ""
                    for pipe in (process.stdout, process.stderr):
                        if pipe is not None:
                            try:
                                pipe.close()
                            except OSError:
                                pass
        else:
            stdout, stderr = e.stdout or "", e.stderr or ""
        return {
            "returncode": -1,
            "stdout": stdout or e.stdout or "",
            "stderr": stderr or e.stderr or f"command timed out after {timeout}s",
            "cmd": cmd,
            "timed_out": True,
            "error_code": "command_timeout",
        }
    except FileNotFoundError as e:
        return {
            "returncode": -1,
            "stdout": "",
            "stderr": str(e),
            "cmd": cmd,
            "timed_out": False,
        }


def _terminate_owned_process_tree(process: subprocess.Popen[str]) -> None:
    """Terminate the exact spawned command tree after a hard timeout."""
    if process.poll() is not None:
        return
    if os.name == "nt":
        try:
            completed = subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                shell=False,
                timeout=5,
                check=False,
            )
            if completed.returncode == 0 or process.poll() is not None:
                return
        except (OSError, subprocess.SubprocessError):
            pass
    else:
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
            return
        except OSError:
            pass
    process.kill()
