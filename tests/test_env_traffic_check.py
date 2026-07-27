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
    monkeypatch.setattr(main_module, "check_port_listening", lambda port=8080: True)
    monkeypatch.setattr(main_module, "_check_output_writable", lambda: {"ok": True, "path": "D:/adsdk-agent/output", "error": None})

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
