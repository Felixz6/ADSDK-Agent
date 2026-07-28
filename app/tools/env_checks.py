"""Environment self-check probes used by ``GET /env/check``.

These helpers are deliberately side-effect free and never leak secrets:
they report *configuration status* (configured / placeholder / missing,
tool present / version / error) rather than raw values. The HMAC key
probes in particular must never return the key material itself.

Tests monkeypatch the functions in this module (or the helpers they
call) to exercise the absent / failure / placeholder branches without
requiring a real apktool or frida install.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from typing import Any, Dict, List, Optional

from app.config import APK_ALLOWED_ROOTS, APKTOOL_TIMEOUT


# Known development placeholder values for REDACTION_HMAC_KEY. Matching any of
# these means the deployment has not yet replaced the development default —
# reported as ``placeholder``, never ``secure``. Keep in sync with
# ``app/config.py`` (module default) and ``.env.example`` (documented stub).
_REDACTION_PLACEHOLDER_VALUES: tuple[str, ...] = (
    "adsdk-agent-development-only-change-me",
    "change-me-to-a-long-private-random-secret",
    "change-me",
)

# Minimum length a non-placeholder key must reach to be considered
# ``secure``. Long enough to be a credible HMAC-SHA256 key while staying
# lenient about reasonable operator choices.
_REDACTION_SECURE_MIN_LENGTH = 16


def _safe_path_display(path: str | None) -> str | None:
    """Return a path safe to surface in /env/check.

    Absolute paths may contain a Windows username (``C:\\Users\\<name>\\...``),
    which is private to the operator. For env-check we only need to confirm
    presence, so we return just the file name. ``None`` stays ``None``.
    """
    if path is None:
        return None
    try:
        return os.path.basename(path.rstrip("/\\")) or None
    except (TypeError, ValueError, OSError):
        return None


def _apktool_version_timeout() -> int:
    """Clamp apktool --version probe timeout to a short, sensible window."""
    try:
        configured = int(APKTOOL_TIMEOUT)
    except (TypeError, ValueError):
        configured = 10
    return max(5, min(configured, 15))


def check_apktool() -> Dict[str, Any]:
    """Detect apktool and return its version.

    On Windows apktool is typically distributed as ``apktool.bat`` /
    ``apktool.cmd``; ``shutil.which`` resolves those via ``PATHEXT``. The
    resolved wrapper is launched through ``cmd.exe /c`` (mirroring
    ``app.tools.utils._resolve_spawn_argv``) so shell scripts on PATH
    actually execute under ``CreateProcess``. No ``shell=True`` is used,
    and no untrusted arguments are interpolated — argv is hand-built.
    """
    cmd_name = "apktool"
    resolved = shutil.which(cmd_name)

    if resolved is None:
        return {
            "apktool_available": False,
            "apktool_version": None,
            "apktool_path": None,
            "apktool_error": "apktool not found on PATH",
        }

    argv: List[str] = [cmd_name, "--version"]
    spawn_argv: List[str] = [resolved, "--version"]
    if os.name == "nt" and resolved.lower().endswith((".bat", ".cmd")):
        # Launch the wrapper through cmd.exe /c; the recorded command stays
        # the operator-visible ``["apktool", "--version"]``.
        spawn_argv = ["cmd.exe", "/c", resolved, "--version"]

    try:
        result = subprocess.run(
            spawn_argv,
            capture_output=True,
            text=True,
            shell=False,
            timeout=_apktool_version_timeout(),
        )
    except subprocess.TimeoutExpired:
        return {
            "apktool_available": True,
            "apktool_version": None,
            "apktool_path": _safe_path_display(resolved),
            "apktool_error": "apktool --version timed out",
            "_cmd": argv,
        }
    except (FileNotFoundError, OSError) as exc:
        return {
            "apktool_available": True,
            "apktool_version": None,
            "apktool_path": _safe_path_display(resolved),
            "apktool_error": f"apktool execution failed: {type(exc).__name__}",
            "_cmd": argv,
        }

    # ``apktool_available`` reflects PATH resolution (the tool is installed and
    # we could attempt to invoke it), independent of whether ``--version``
    # succeeded. This lets the UI distinguish:
    #   - not on PATH at all            ⇒ missing  (未配置)
    #   - on PATH but --version failed  ⇒ unknown (无法检测) via ``apktool_error``
    #   - on PATH and --version ok      ⇒ ok      (正常)
    available = True
    version: Optional[str] = None
    if result.returncode == 0:
        out = (result.stdout or result.stderr or "").strip()
        # apktool prints a single version line; take the first token-bearing
        # line to avoid trailing banners / blank lines.
        for line in out.splitlines():
            if line.strip():
                version = line.strip()
                break
        if version is None:
            version = out or None
    error: Optional[str] = None
    if result.returncode != 0:
        raw = (result.stderr or result.stdout or "").strip()
        error = raw or "apktool --version failed"

    return {
        "apktool_available": available,
        "apktool_version": version,
        "apktool_path": _safe_path_display(resolved),
        "apktool_error": error,
        "_cmd": argv,
    }


def check_frida_python_package() -> Dict[str, Any]:
    """Detect the ``frida`` Python package on the *current* interpreter.

    This is distinct from ``check_frida_connection`` (frida-server
    reachability via ``frida-ps``) and from a device being online. All
    three are independent states; only the import availability + version
    is reported here. Raises are caught so a broken install reads as
    ``available=False`` rather than crashing env-check.
    """
    try:
        import frida  # type: ignore[import-not-found]
    except ImportError as exc:
        return {
            "frida_python_available": False,
            "frida_python_version": None,
            "frida_python_error": "frida package not importable",
            "frida_python_error_detail": str(exc),
        }
    except Exception as exc:  # pragma: no cover - defensive: import side effects
        return {
            "frida_python_available": False,
            "frida_python_version": None,
            "frida_python_error": f"frida import failed: {type(exc).__name__}",
            "frida_python_error_detail": "",
        }

    version: Optional[str] = None
    try:
        version = getattr(frida, "__version__", None)
        if version is None:
            # Older bindings expose ``frida.version()`` instead.
            maybe = getattr(frida, "version", None)
            if callable(maybe):
                version = maybe()
    except Exception:
        version = None

    return {
        "frida_python_available": True,
        "frida_python_version": str(version) if version is not None else None,
        "frida_python_error": None,
        "frida_python_error_detail": None,
        "_python_executable": sys.executable,
    }


def check_redaction_hmac_key() -> Dict[str, Any]:
    """Probe REDACTION_HMAC_KEY configuration status without exposing the key.

    Status logic (the *effective* value, i.e. what ``app.config`` resolved):
      - ``missing``    : no value resolved at all (env unset AND module default
                         also empty — only reachable under a broken environment).
      - ``placeholder``: env unset (silently defaulted to the dev placeholder)
                         OR equals a known development placeholder string OR is
                         configured but shorter than the secure minimum.
      - ``secure``     : a non-placeholder value of adequate length.

    The raw key is never returned or logged; only booleans + a coarse
    security status. ``redaction_hmac_key_configured`` is true whenever a
    value exists in the effective config (even a placeholder), so the UI can
    separate "absent" from "present but insecure".
    """
    # Local import: read the module-level effective value rather than re-reading
    # env, so the probe reflects exactly what the rest of the backend is using.
    from app.config import REDACTION_HMAC_KEY

    env_value = os.getenv("REDACTION_HMAC_KEY")
    env_configured = env_value is not None and env_value.strip() != ""

    effective = (REDACTION_HMAC_KEY or "").strip()

    is_known_placeholder = effective in _REDACTION_PLACEHOLDER_VALUES or (
        env_value in _REDACTION_PLACEHOLDER_VALUES if env_value is not None else False
    )

    if not effective:
        security_status = "missing"
        uses_placeholder = True
    elif is_known_placeholder:
        security_status = "placeholder"
        uses_placeholder = True
    elif len(effective) >= _REDACTION_SECURE_MIN_LENGTH:
        security_status = "secure"
        uses_placeholder = False
    else:
        # Configured-but-too-short: better than a known placeholder but not
        # "secure"; classify as placeholder so the UI stays honest and nudges
        # the operator to set a longer key.
        security_status = "placeholder"
        uses_placeholder = True

    return {
        "redaction_hmac_key_configured": bool(effective),
        "redaction_hmac_key_uses_placeholder": uses_placeholder,
        "redaction_hmac_key_security_status": security_status,
    }


def check_apk_allowed_roots() -> Dict[str, Any]:
    """Return the normalized, absolute allowed APK roots.

    Uses the real parsed value from ``app.config`` (already resolved to
    absolute, normalized paths). Reads *no* APK files inside the roots
    and exposes nothing outside the configured list.
    """
    roots_normalized: List[str] = [str(root) for root in APK_ALLOWED_ROOTS]
    configured = len(roots_normalized) > 0
    return {
        "apk_allowed_roots_configured": configured,
        "apk_allowed_roots": roots_normalized,
    }
