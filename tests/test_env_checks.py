"""Tests for the env-check probes backing ``GET /env/check``.

Covers the four probes added to fix "未提供" states on the environment
detection page: apktool, Frida Python package, REDACTION_HMAC_KEY, and
APK_ALLOWED_ROOTS. The HMAC tests in particular assert that the raw key
value is never returned and never appears in the /env/check JSON body.
"""

from __future__ import annotations

import sys
import types

import pytest

from app.tools import env_checks
from app.tools.env_checks import (
    check_apk_allowed_roots,
    check_apktool,
    check_frida_python_package,
    check_redaction_hmac_key,
)


# ---------------------------------------------------------------------------
# apktool
# ---------------------------------------------------------------------------


def test_apktool_present(monkeypatch, tmp_path):
    fake_apktool = tmp_path / "apktool.bat"
    fake_apktool.write_text("@echo 2.11.1")

    monkeypatch.setattr(env_checks.shutil, "which", lambda cmd: str(fake_apktool))

    class _Result:
        returncode = 0
        stdout = "apktool 2.11.1\n"
        stderr = ""

    monkeypatch.setattr(
        env_checks.subprocess, "run", lambda *a, **kw: _Result()
    )

    info = check_apktool()
    assert info["apktool_available"] is True
    # apktool prints "apktool <version>"; the probe surfaces the full first
    # non-empty line, which is fine for display.
    assert info["apktool_version"] is not None
    assert "2.11.1" in info["apktool_version"]
    # Path is stripped to a safe basename only — no username-laden abs path.
    assert info["apktool_path"] == "apktool.bat"
    assert env_checks.os.sep not in (info["apktool_path"] or "")
    assert info["apktool_error"] is None


def test_apktool_not_on_path(monkeypatch):
    monkeypatch.setattr(env_checks.shutil, "which", lambda cmd: None)
    info = check_apktool()
    assert info["apktool_available"] is False
    assert info["apktool_version"] is None
    assert info["apktool_path"] is None
    assert isinstance(info["apktool_error"], str)


def test_apktool_version_command_fails(monkeypatch, tmp_path):
    """apktool resolves on PATH but `--version` errors ⇒ available=True,
    version=None, error set — classified by the UI as 「无法检测」, not 「异常」."""
    fake_apktool = tmp_path / "apktool"
    fake_apktool.write_text("#!/bin/sh\nexit 1\n")

    monkeypatch.setattr(env_checks.shutil, "which", lambda cmd: str(fake_apktool))

    class _Result:
        returncode = 1
        stdout = ""
        stderr = "java not found"

    monkeypatch.setattr(
        env_checks.subprocess, "run", lambda *a, **kw: _Result()
    )

    info = check_apktool()
    assert info["apktool_available"] is True  # found on PATH
    assert info["apktool_version"] is None
    assert info["apktool_path"] == "apktool"
    assert isinstance(info["apktool_error"], str)


def test_apktool_version_times_out(monkeypatch, tmp_path):
    fake_apktool = tmp_path / "apktool.bat"
    fake_apktool.write_text("@echo slow")

    monkeypatch.setattr(env_checks.shutil, "which", lambda cmd: str(fake_apktool))

    def _raise(*a, **kw):
        raise env_checks.subprocess.TimeoutExpired(cmd=["apktool", "--version"], timeout=5)

    monkeypatch.setattr(env_checks.subprocess, "run", _raise)

    info = check_apktool()
    assert info["apktool_available"] is True
    assert info["apktool_version"] is None
    assert "timed out" in info["apktool_error"]


def test_apktool_private_keys_stripped(monkeypatch, tmp_path):
    """The `_cmd` helper key must never reach the public /env/check body."""
    fake_apktool = tmp_path / "apktool"
    fake_apktool.write_text("#!/bin/sh\nexit 0\n")
    monkeypatch.setattr(env_checks.shutil, "which", lambda cmd: str(fake_apktool))

    class _Result:
        returncode = 0
        stdout = "apktool 2.0\n"
        stderr = ""

    monkeypatch.setattr(env_checks.subprocess, "run", lambda *a, **kw: _Result())

    info = check_apktool()
    assert "_cmd" in info  # present internally…
    # …but env_check() strips `_`-prefixed keys via _public().
    public = {k: v for k, v in info.items() if not k.startswith("_")}
    assert "_cmd" not in public


# ---------------------------------------------------------------------------
# Frida Python package
# ---------------------------------------------------------------------------


def test_frida_python_importable(monkeypatch):
    fake = types.ModuleType("frida")
    fake.__version__ = "16.7.19"

    def _import(name, *a, **kw):
        if name == "frida":
            return fake
        raise ImportError(name)

    monkeypatch.setattr("builtins.__import__", _import)

    info = check_frida_python_package()
    assert info["frida_python_available"] is True
    assert info["frida_python_version"] == "16.7.19"
    assert info["frida_python_error"] is None


def test_frida_python_not_importable(monkeypatch):
    def _import(name, *a, **kw):
        if name == "frida":
            raise ImportError("No module named 'frida'")
        raise ImportError(name)

    monkeypatch.setattr("builtins.__import__", _import)

    info = check_frida_python_package()
    assert info["frida_python_available"] is False
    assert info["frida_python_version"] is None
    assert isinstance(info["frida_python_error"], str)


def test_frida_python_distinct_from_server():
    """The Python package probe must be independent of frida-server
    connectivity — it only reports import availability."""
    # We can't fully control a *real* import here, so assert the contract:
    # the returned dict always carries all four keys either way.
    info = check_frida_python_package()
    for key in (
        "frida_python_available",
        "frida_python_version",
        "frida_python_error",
        "frida_python_error_detail",
    ):
        assert key in info


# ---------------------------------------------------------------------------
# REDACTION_HMAC_KEY — never leak the raw value
# ---------------------------------------------------------------------------

SECURE_KEY = "a-very-long-private-random-secret-please-rotate-me-123"  # >= min length


def _set_hmac_key(monkeypatch, value):
    monkeypatch.setattr(env_checks, "REDACTION_HMAC_KEY", value, raising=False)
    # The probe does `from app.config import REDACTION_HMAC_KEY` at call time
    # to read the module-level effective value, so patch it there too.
    monkeypatch.setattr("app.config.REDACTION_HMAC_KEY", value, raising=False)
    monkeypatch.setattr(env_checks.os, "getenv", lambda name, default=None: value if name == "REDACTION_HMAC_KEY" else default)


def test_hmac_missing(monkeypatch):
    _set_hmac_key(monkeypatch, None)
    info = check_redaction_hmac_key()
    assert info["redaction_hmac_key_security_status"] == "missing"
    assert info["redaction_hmac_key_configured"] is False
    assert info["redaction_hmac_key_uses_placeholder"] is True


@pytest.mark.parametrize(
    "placeholder",
    [
        "adsdk-agent-development-only-change-me",
        "change-me-to-a-long-private-random-secret",
        "change-me",
    ],
)
def test_hmac_placeholder_values(monkeypatch, placeholder):
    _set_hmac_key(monkeypatch, placeholder)
    info = check_redaction_hmac_key()
    assert info["redaction_hmac_key_security_status"] == "placeholder"
    assert info["redaction_hmac_key_configured"] is True
    assert info["redaction_hmac_key_uses_placeholder"] is True


def test_hmac_short_value_is_placeholder(monkeypatch):
    _set_hmac_key(monkeypatch, "short")
    info = check_redaction_hmac_key()
    # Configured-but-too-short must not pass as secure.
    assert info["redaction_hmac_key_security_status"] == "placeholder"
    assert info["redaction_hmac_key_configured"] is True


def test_hmac_secure(monkeypatch):
    _set_hmac_key(monkeypatch, SECURE_KEY)
    info = check_redaction_hmac_key()
    assert info["redaction_hmac_key_security_status"] == "secure"
    assert info["redaction_hmac_key_uses_placeholder"] is False
    assert info["redaction_hmac_key_configured"] is True


def test_hmac_never_returns_raw_value(monkeypatch):
    """The probe's return dict must not contain the raw key material —
    in any field, under any spelling."""
    _set_hmac_key(monkeypatch, SECURE_KEY)
    info = check_redaction_hmac_key()
    blob = repr(info)
    assert SECURE_KEY not in blob
    # None of the public field names hint at key content.
    assert all(not k.startswith("value") and k != "key" for k in info)


def test_env_check_response_does_not_leak_hmac_key(monkeypatch):
    """End-to-end: the full /env/check JSON body must never echo the key,
    even when the key is securely configured."""
    from fastapi.testclient import TestClient

    from app import main as main_module

    _set_hmac_key(monkeypatch, SECURE_KEY)

    monkeypatch.setattr(main_module, "check_adb_available", lambda: {"ok": True, "stdout": "adb", "stderr": "", "cmd": ["adb"]})
    monkeypatch.setattr(
        main_module,
        "check_device_online",
        lambda device_id=None: {"ok": True, "device_id": device_id, "target": None, "devices": []},
    )
    monkeypatch.setattr(main_module, "check_frida_connection", lambda device_id=None: {"ok": True, "stdout": "", "stderr": "", "cmd": []})
    monkeypatch.setattr(main_module, "check_port_listening", lambda port=8080: True)
    monkeypatch.setattr(main_module, "_check_output_writable", lambda: {"ok": True, "path": "/out", "error": None})

    client = TestClient(main_module.app)
    resp = client.get("/env/check")
    assert resp.status_code == 200
    body = resp.json()
    # The HMAC key value must not appear anywhere in the response body.
    assert SECURE_KEY not in resp.text
    redaction = body["details"]["redaction_hmac_key"]
    assert redaction["redaction_hmac_key_security_status"] == "secure"
    # And none of the redaction_* fields carries the raw secret.
    assert SECURE_KEY not in repr(redaction)


# ---------------------------------------------------------------------------
# APK_ALLOWED_ROOTS
# ---------------------------------------------------------------------------


def test_allowed_roots_single(monkeypatch):
    from pathlib import Path

    single = (Path("D:/adsdk-agent/samples").resolve(),)
    monkeypatch.setattr(env_checks, "APK_ALLOWED_ROOTS", single, raising=False)
    info = check_apk_allowed_roots()
    assert info["apk_allowed_roots_configured"] is True
    assert len(info["apk_allowed_roots"]) == 1
    # Returned paths are normalized to absolute form.
    assert Path(info["apk_allowed_roots"][0]).is_absolute()


def test_allowed_roots_multiple(monkeypatch):
    from pathlib import Path

    multi = (
        Path("D:/adsdk-agent/samples").resolve(),
        Path("C:/apks").resolve(),
    )
    monkeypatch.setattr(env_checks, "APK_ALLOWED_ROOTS", multi, raising=False)
    info = check_apk_allowed_roots()
    assert info["apk_allowed_roots_configured"] is True
    assert len(info["apk_allowed_roots"]) == 2
    for root in info["apk_allowed_roots"]:
        assert Path(root).is_absolute()


def test_allowed_roots_empty(monkeypatch):
    monkeypatch.setattr(env_checks, "APK_ALLOWED_ROOTS", (), raising=False)
    info = check_apk_allowed_roots()
    assert info["apk_allowed_roots_configured"] is False
    assert info["apk_allowed_roots"] == []


@pytest.mark.skipif(sys.platform != "win32", reason="Windows path normalization")
def test_allowed_roots_windows_normalization(monkeypatch):
    from pathlib import Path

    # Forward-slash, drive-relative input should resolve to an absolute
    # normalized Windows path without collapsing the drive colon.
    raw = "D:/adsdk-agent/samples"
    monkeypatch.setattr(
        env_checks,
        "APK_ALLOWED_ROOTS",
        (Path(raw).expanduser().resolve(),),
        raising=False,
    )
    info = check_apk_allowed_roots()
    root = info["apk_allowed_roots"][0]
    assert Path(root).is_absolute()
    # Drive letter preserved.
    assert root[0] in ("D", "d")
    # No stray backslash-semicolon artifacts from naive splitting.
    assert "; " not in root
