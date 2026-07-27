from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import main as main_module
from app.core.device import DeviceContext
from app.tools import adb_runner
from app.tools.adb_runner import DeviceSelectionError


def test_analyze_path_validation_returns_structured_422(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output_root = tmp_path / "output"
    missing_apk = tmp_path / "missing.apk"
    monkeypatch.setattr(main_module, "OUTPUT_DIR", str(output_root))
    monkeypatch.setattr(
        main_module,
        "APK_ALLOWED_ROOTS",
        (tmp_path.resolve(),),
    )

    response = TestClient(
        main_module.app,
        raise_server_exceptions=False,
    ).post("/analyze", json={"apk_path": str(missing_apk)})

    assert response.status_code == 422
    payload = response.json()
    assert payload["status"] == "failed"
    assert payload["error_code"] == "path_not_found"
    assert payload["steps"][0]["name"] == "apk_validation"
    assert payload["steps"][0]["status"] == "failed"
    assert not output_root.exists()


def test_device_selection_requires_id_when_multiple_devices_are_online(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        adb_runner,
        "adb_devices",
        lambda: {
            "returncode": 0,
            "stdout": (
                "List of devices attached\n"
                "emulator-5554\tdevice\n"
                "R58M123456A\tdevice\n"
            ),
            "stderr": "",
            "cmd": ["adb", "devices"],
        },
    )

    with pytest.raises(DeviceSelectionError) as caught:
        adb_runner.select_device_context()

    assert caught.value.code == "multiple_devices"


def test_selected_device_is_used_by_adb_install_and_launch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: list[list[str]] = []
    monkeypatch.setattr(
        adb_runner,
        "run_cmd",
        lambda command: captured.append(command)
        or {
            "returncode": 0,
            "stdout": "",
            "stderr": "",
            "cmd": command,
        },
    )
    context = DeviceContext(serial="emulator-5554")

    adb_runner.install_apk("TARGET.apk", device_context=context)
    adb_runner.launch_app("com.example.target", device_context=context)

    assert captured == [
        ["adb", "-s", "emulator-5554", "install", "-r", "TARGET.apk"],
        [
            "adb",
            "-s",
            "emulator-5554",
            "shell",
            "monkey",
            "-p",
            "com.example.target",
            "1",
        ],
    ]
