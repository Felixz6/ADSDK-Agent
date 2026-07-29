import importlib
import os
from pathlib import Path

from app import config


def test_empty_allowed_roots_uses_project_samples_directory():
    assert config._parse_allowed_roots("") == (
        Path(config.SAMPLES_DIR).resolve(),
    )


def test_allowed_roots_are_semicolon_separated_and_resolved(tmp_path):
    first = tmp_path / "允许 根一"
    second = tmp_path / "root-two"

    assert config._parse_allowed_roots(f"{first}; {second}") == (
        first.resolve(),
        second.resolve(),
    )


def test_apk_input_defaults_are_bounded():
    assert config.APK_ALLOWED_ROOTS
    assert all(root.is_absolute() for root in config.APK_ALLOWED_ROOTS)
    assert config.APK_MAX_SIZE_BYTES > 0
    assert isinstance(config.ALLOW_UNC_APK_PATHS, bool)


def test_task_database_path_defaults_under_output_and_honors_env():
    original = os.environ.pop("TASK_DATABASE_PATH", None)
    try:
        cfg_default = importlib.reload(config)
        assert Path(cfg_default.TASK_DATABASE_PATH) == (
            Path(cfg_default.OUTPUT_DIR) / "state" / "adsdk-agent.db"
        )

        os.environ["TASK_DATABASE_PATH"] = "   "
        cfg_blank = importlib.reload(config)
        assert Path(cfg_blank.TASK_DATABASE_PATH) == (
            Path(cfg_blank.OUTPUT_DIR) / "state" / "adsdk-agent.db"
        )

        custom = Path(cfg_default.OUTPUT_DIR) / "state" / "custom-tasks.db"
        os.environ["TASK_DATABASE_PATH"] = str(custom)
        cfg_override = importlib.reload(config)
        assert Path(cfg_override.TASK_DATABASE_PATH) == custom
    finally:
        os.environ.pop("TASK_DATABASE_PATH", None)
        if original is not None:
            os.environ["TASK_DATABASE_PATH"] = original
        importlib.reload(config)


def test_boolean_config_parser(monkeypatch):
    monkeypatch.setenv("P0_BOOL_SETTING", "yes")
    assert config._env_bool("P0_BOOL_SETTING") is True

    monkeypatch.setenv("P0_BOOL_SETTING", "off")
    assert config._env_bool("P0_BOOL_SETTING", default=True) is False

    monkeypatch.delenv("P0_BOOL_SETTING")
    assert config._env_bool("P0_BOOL_SETTING", default=False) is False


def test_dynamic_session_timeouts_and_port_pool_are_bounded():
    assert config.FRIDA_READY_TIMEOUT_SECONDS > 0
    assert config.FRIDA_STOP_TIMEOUT_SECONDS > 0
    assert config.MITM_READY_TIMEOUT_SECONDS > 0
    assert config.MITM_STOP_TIMEOUT_SECONDS > 0
    assert 1 <= config.MITM_PORT_START <= config.MITM_PORT_END <= 65535


def test_mitm_listen_host_defaults_to_loopback_and_env_overrides():
    """MITM_LISTEN_HOST default keeps non-emulator behavior unchanged; the
    emulator override (0.0.0.0) must be honored. The value is read at import
    time, so we reload the module after setting/clearing the env var.
    """
    # 1) default: no env set -> 127.0.0.1 (host loopback, non-emulator default)
    original = os.environ.pop("MITM_LISTEN_HOST", None)
    try:
        cfg_default = importlib.reload(config)
        assert cfg_default.MITM_LISTEN_HOST == "127.0.0.1"

        # 2) override: MITM_LISTEN_HOST=0.0.0.0 -> honored, stripped of blanks
        os.environ["MITM_LISTEN_HOST"] = " 0.0.0.0 "
        cfg_override = importlib.reload(config)
        assert cfg_override.MITM_LISTEN_HOST == "0.0.0.0"

        # empty/whitespace-only falls back to empty string (downstream MitmSession
        # __post_init__ guards emptiness); we assert it is NOT silently coerced
        # to a default here, so callers see the misconfiguration.
        os.environ["MITM_LISTEN_HOST"] = "   "
        cfg_blank = importlib.reload(config)
        assert cfg_blank.MITM_LISTEN_HOST == ""
    finally:
        os.environ.pop("MITM_LISTEN_HOST", None)
        if original is not None:
            os.environ["MITM_LISTEN_HOST"] = original
        importlib.reload(config)
