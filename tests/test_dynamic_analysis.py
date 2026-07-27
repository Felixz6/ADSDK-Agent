import zipfile
from pathlib import Path

from fastapi.testclient import TestClient

from app import main as main_module
from app.core.device import DeviceContext
from app.tools.log_writer import append_log


class DummyProcess:
    def __init__(self):
        self.alive = True

    def poll(self):
        return None if self.alive else 0

    def terminate(self):
        self.alive = False

    def wait(self, timeout=None):
        self.alive = False
        return 0

    def kill(self):
        self.alive = False


def _write_fake_apk(path: Path, package_name: str) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(
            "AndroidManifest.xml",
            f"<manifest package='{package_name}'/>",
        )


def test_build_dynamic_findings_detect_sensitive_call():
    events = [
        {
            "timestamp": None,
            "event_type": "sensitive_api",
            "api": "Settings.Secure.getString",
            "arg": "android_id",
            "result": "abc",
            "source": "frida",
        }
    ]
    findings = main_module._build_dynamic_findings(events)
    assert findings["summary"]["pre_consent_sensitive_access"] == "suspicious"


def test_build_dynamic_findings_pre_consent_on_non_android_id():
    events = [
        {
            "timestamp": None,
            "event_type": "sensitive_api",
            "api": "Settings.Secure.getString",
            "arg": "bluetooth_name",
            "result": "demo",
            "source": "frida",
        }
    ]
    findings = main_module._build_dynamic_findings(events)
    assert findings["summary"]["pre_consent_sensitive_access"] == "suspicious"
    assert findings["summary"]["high_frequency_sensitive_access"] == "not_detected"


def test_dynamic_analyze_uses_manifest_package_and_writes_findings(tmp_path, monkeypatch):
    client = TestClient(main_module.app)
    apk_path = tmp_path / "demo.apk"
    _write_fake_apk(apk_path, "com.example.demo")
    output_dir = tmp_path / "output"

    called = {"package": None}

    def fake_unpack(apk, out_dir):
        Path(out_dir).mkdir(parents=True, exist_ok=True)
        return {"returncode": 0, "stdout": "", "stderr": "", "cmd": []}

    def fake_launch(package_name, device_context=None):
        assert device_context.serial == "emulator-5554"
        called["package"] = package_name
        return {"returncode": 0, "stdout": "ok", "stderr": "", "cmd": []}

    def fake_spawn(package_name, script_path, log_path, device_context=None):
        assert device_context.serial == "emulator-5554"
        append_log(log_path, "[HOOK] Settings.Secure.getString name=android_id ret=abc")
        return {
            "ok": True,
            "error": None,
            "process": DummyProcess(),
            "log_file": None,
            "cmd": ["frida"],
        }

    monkeypatch.setattr(main_module, "OUTPUT_DIR", str(output_dir))
    monkeypatch.setattr(main_module, "APK_ALLOWED_ROOTS", (tmp_path.resolve(),))
    monkeypatch.setattr(
        main_module,
        "select_device_context",
        lambda device_id=None: DeviceContext(serial=device_id or "emulator-5554"),
    )
    monkeypatch.setattr(main_module, "unpack_apk", fake_unpack)
    monkeypatch.setattr(
        main_module,
        "parse_manifest_info",
        lambda _: {
            "package_name": "com.example.demo",
            "version_name": "1.0.0",
            "version_code": "1",
            "application_label": "Demo",
        },
    )
    monkeypatch.setattr(
        main_module,
        "scan_for_sdks",
        lambda _: [
            {
                "sdk_name": "Pangle",
                "package": "com.bytedance.sdk.openadsdk",
                "confidence": 0.95,
                "version": None,
            }
        ],
    )
    monkeypatch.setattr(
        main_module,
        "install_apk",
        lambda _, device_context=None: {
            "returncode": 0,
            "stdout": "ok",
            "stderr": "",
            "cmd": device_context.adb_command("install"),
        },
    )
    monkeypatch.setattr(main_module, "launch_app", fake_launch)
    monkeypatch.setattr(main_module, "spawn_and_inject", fake_spawn)
    monkeypatch.setattr(
        main_module,
        "start_mitm",
        lambda _: {"ok": True, "error": None, "traffic_dir": str(output_dir / "traffic"), "stream_log": str(output_dir / "traffic" / "mitm_stream.log")},
    )
    monkeypatch.setattr(main_module, "stop_mitm", lambda: {"ok": True, "error": None})
    monkeypatch.setattr(
        main_module,
        "parse_traffic_to_summary_json",
        lambda traffic_text_path, output_path: {"total_requests": 0, "top_hosts": [], "sample_requests": []},
    )
    monkeypatch.setattr(
        main_module,
        "evaluate_timeline_rules",
        lambda events_json_path, consent_time, pre_consent_seconds, post_consent_seconds, evidence_available=True: {
            "summary": {"pre_consent_sensitive_access_strict": "not_detected"},
            "rules": [],
            "window": {
                "consent_time": consent_time,
                "pre_consent_seconds": pre_consent_seconds,
                "post_consent_seconds": post_consent_seconds,
            },
        },
    )

    resp = client.post("/dynamic/analyze", json={"apk_path": str(apk_path), "pre_consent_seconds": 0, "post_consent_seconds": 0})
    assert resp.status_code == 200

    body = resp.json()
    assert called["package"] == "com.example.demo"
    assert body["dynamic_findings"]["summary"]["pre_consent_sensitive_access"] == "suspicious"
    assert body["dynamic_findings"]["summary"]["high_frequency_sensitive_access"] == "not_detected"
    assert Path(body["hook_log"]).exists()
    assert Path(body["events_json"]).exists()
    assert body["traffic_summary_json"].endswith("traffic_summary.json")


def test_high_frequency_sensitive_access_rule(tmp_path, monkeypatch):
    client = TestClient(main_module.app)
    apk_path = tmp_path / "demo2.apk"
    _write_fake_apk(apk_path, "com.example.demo2")
    output_dir = tmp_path / "output"

    def fake_unpack(apk, out_dir):
        Path(out_dir).mkdir(parents=True, exist_ok=True)
        return {"returncode": 0, "stdout": "", "stderr": "", "cmd": []}

    def fake_spawn(package_name, script_path, log_path, device_context=None):
        assert device_context.serial == "emulator-5554"
        for _ in range(4):
            append_log(log_path, "[HOOK] Settings.Secure.getString name=android_id ret=abc")
        for _ in range(2):
            append_log(log_path, "[HOOK] ClipboardManager.getPrimaryClip called")
        return {
            "ok": True,
            "error": None,
            "process": DummyProcess(),
            "log_file": None,
            "cmd": ["frida"],
        }

    monkeypatch.setattr(main_module, "OUTPUT_DIR", str(output_dir))
    monkeypatch.setattr(main_module, "APK_ALLOWED_ROOTS", (tmp_path.resolve(),))
    monkeypatch.setattr(
        main_module,
        "select_device_context",
        lambda device_id=None: DeviceContext(serial=device_id or "emulator-5554"),
    )
    monkeypatch.setattr(main_module, "unpack_apk", fake_unpack)
    monkeypatch.setattr(
        main_module,
        "parse_manifest_info",
        lambda _: {
            "package_name": "com.example.demo2",
            "version_name": "1.0.0",
            "version_code": "1",
            "application_label": "Demo2",
        },
    )
    monkeypatch.setattr(main_module, "scan_for_sdks", lambda _: [])
    monkeypatch.setattr(
        main_module,
        "install_apk",
        lambda _, device_context=None: {
            "returncode": 0,
            "stdout": "ok",
            "stderr": "",
            "cmd": device_context.adb_command("install"),
        },
    )
    monkeypatch.setattr(
        main_module,
        "launch_app",
        lambda _, device_context=None: {
            "returncode": 0,
            "stdout": "ok",
            "stderr": "",
            "cmd": device_context.adb_command("shell"),
        },
    )
    monkeypatch.setattr(main_module, "spawn_and_inject", fake_spawn)
    monkeypatch.setattr(
        main_module,
        "start_mitm",
        lambda _: {"ok": True, "error": None, "traffic_dir": str(output_dir / "traffic"), "stream_log": str(output_dir / "traffic" / "mitm_stream.log")},
    )
    monkeypatch.setattr(main_module, "stop_mitm", lambda: {"ok": True, "error": None})
    monkeypatch.setattr(
        main_module,
        "parse_traffic_to_summary_json",
        lambda traffic_text_path, output_path: {"total_requests": 0, "top_hosts": [], "sample_requests": []},
    )
    monkeypatch.setattr(
        main_module,
        "evaluate_timeline_rules",
        lambda events_json_path, consent_time, pre_consent_seconds, post_consent_seconds, evidence_available=True: {
            "summary": {"pre_consent_high_frequency_sensitive_access": "suspicious"},
            "rules": [],
            "window": {
                "consent_time": consent_time,
                "pre_consent_seconds": pre_consent_seconds,
                "post_consent_seconds": post_consent_seconds,
            },
        },
    )

    resp = client.post("/dynamic/analyze", json={"apk_path": str(apk_path), "pre_consent_seconds": 0, "post_consent_seconds": 0})
    assert resp.status_code == 200
    body = resp.json()
    assert body["dynamic_findings"]["summary"]["high_frequency_sensitive_access"] == "suspicious"
