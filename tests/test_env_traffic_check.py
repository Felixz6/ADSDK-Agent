from fastapi.testclient import TestClient

from app import main as main_module


def test_env_check(monkeypatch):
    client = TestClient(main_module.app)

    monkeypatch.setattr(main_module, "check_adb_available", lambda: {"ok": True, "stdout": "adb", "stderr": "", "cmd": ["adb", "version"]})
    monkeypatch.setattr(
        main_module,
        "check_device_online",
        lambda device_id=None: {"ok": True, "device_id": device_id, "target": {"device_id": "emulator-5554", "status": "device"}},
    )
    monkeypatch.setattr(main_module, "check_frida_connection", lambda device_id=None: {"ok": True, "stdout": "frida", "stderr": "", "cmd": ["frida-ps", "-U"]})
    monkeypatch.setattr(
        main_module,
        "check_frida_device_runtime",
        lambda device_id=None: {
            "status": "server_available",
            "server_running": True,
            "abi": "x86_64",
            "mode_hint": "exact-device frida-server transport",
        },
    )
    monkeypatch.setattr(main_module, "check_port_listening", lambda port=8080: True)
    monkeypatch.setattr(main_module, "_check_output_writable", lambda: {"ok": True, "path": "D:/adsdk-agent/output", "error": None})
    # New env-check probes — patch so the test does not depend on the real
    # host environment (real apktool / frida / .env key presence).
    monkeypatch.setattr(main_module, "check_apktool", lambda: {"apktool_available": True, "apktool_version": "2.11.1", "apktool_path": "apktool", "apktool_error": None})
    monkeypatch.setattr(main_module, "check_frida_python_package", lambda: {"frida_python_available": True, "frida_python_version": "16.7.19", "frida_python_error": None, "frida_python_error_detail": None})
    monkeypatch.setattr(main_module, "check_redaction_hmac_key", lambda: {"redaction_hmac_key_configured": True, "redaction_hmac_key_uses_placeholder": False, "redaction_hmac_key_security_status": "secure"})
    monkeypatch.setattr(main_module, "check_apk_allowed_roots", lambda: {"apk_allowed_roots_configured": True, "apk_allowed_roots": ["D:/adsdk-agent/samples"]})

    resp = client.get("/env/check", params={"device_id": "emulator-5554"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert body["checks"]["adb_available"] is True
    assert body["checks"]["mitm_8080_listening"] is True
    assert "emulator-5554" not in resp.text
    assert body["device_id"].startswith("redacted:")


def test_traffic_check_failure_reason(monkeypatch):
    client = TestClient(main_module.app)

    monkeypatch.setattr(
        main_module,
        "check_device_online",
        lambda device_id=None: {"ok": False, "device_id": device_id, "target": None},
    )
    monkeypatch.setattr(
        main_module,
        "get_mitm_status",
        lambda port=8080: {
            "has_last_session": True,
            "running": False,
            "port_listening": False,
            "traffic_dir_exists": True,
            "traffic_dir_writable": True,
            "flow_file_size": 0,
            "stream_log": "D:/adsdk-agent/output/demo/traffic/mitm_stream.log",
            "stream_log_exists": True,
            "stream_log_size": 0,
        },
    )
    monkeypatch.setattr(main_module, "parse_traffic_text", lambda _: [])

    resp = client.get("/traffic/check", params={"device_id": "emulator-5554"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["captured_success"] is False
    assert body["captured_request_count"] == 0
    assert len(body["possible_reasons"]) >= 2
    assert "emulator-5554" not in resp.text
    assert body["device_id"].startswith("redacted:")
