"""Environment, traffic, and Frida diagnostics API router."""

from __future__ import annotations

from typing import Any
from fastapi import APIRouter, HTTPException, Query

from app.config import DEFAULT_MITM_PORT
from app.frida import (
    FridaDiagnosticsRequest,
    FridaServerActionRequest,
)
from app.tools.adb_runner import (
    DeviceSelectionError,
    check_adb_available,
    check_device_online,
    select_device_context,
)
from app.tools.env_checks import (
    check_apk_allowed_roots,
    check_apktool,
    check_frida_python_package,
    check_redaction_hmac_key,
)
from app.tools.frida_runner import check_frida_connection, check_frida_device_runtime
from app.tools.mitm_runner import check_port_listening, get_mitm_status
from app.tools.traffic_parser import parse_traffic_text

router = APIRouter(tags=["environment"])


def _main():
    import app.main as main_module
    return main_module


@router.get("/env/check")
def env_check(device_id: str | None = None):
    main = _main()
    resolved_device_id = device_id
    if device_id:
        try:
            select_fn = getattr(main, "select_device_context", select_device_context)
            resolved_device_id = select_fn(device_id).serial
        except DeviceSelectionError:
            resolved_device_id = device_id
    adb_info = getattr(main, "check_adb_available", check_adb_available)()
    device_info = getattr(main, "check_device_online", check_device_online)(device_id=resolved_device_id)
    frida_info = getattr(main, "check_frida_connection", check_frida_connection)(device_id=resolved_device_id)
    frida_runtime_info = getattr(main, "check_frida_device_runtime", check_frida_device_runtime)(resolved_device_id)
    mitm_listen_port = getattr(main, "DEFAULT_MITM_PORT", DEFAULT_MITM_PORT)
    mitm_8080_listening = getattr(main, "check_port_listening", check_port_listening)(port=mitm_listen_port)
    output_info = main._check_output_writable()
    serials = main._device_serials(device_info, resolved_device_id)

    apktool_info = getattr(main, "check_apktool", check_apktool)()
    frida_python_info = getattr(main, "check_frida_python_package", check_frida_python_package)()
    redaction_info = getattr(main, "check_redaction_hmac_key", check_redaction_hmac_key)()
    allowed_roots_info = getattr(main, "check_apk_allowed_roots", check_apk_allowed_roots)()

    checks = {
        "adb_available": adb_info.get("ok", False),
        "device_online": device_info.get("ok", False),
        "frida_connectable": frida_info.get("ok", False),
        "frida_server_running": frida_runtime_info.get(
            "server_running",
            False,
        ),
        "frida_python_available": frida_python_info.get(
            "frida_python_available", False
        ),
        "apktool_available": apktool_info.get("apktool_available", False),
        "mitm_8080_listening": mitm_8080_listening,
        "output_writable": output_info.get("ok", False),
        "redaction_hmac_key_secure": redaction_info.get(
            "redaction_hmac_key_security_status"
        ) == "secure",
        "apk_allowed_roots_configured": allowed_roots_info.get(
            "apk_allowed_roots_configured", False
        ),
    }

    def _public(obj: dict[str, Any]) -> dict[str, Any]:
        return {k: v for k, v in obj.items() if not k.startswith("_")}

    return {
        "ok": all(checks.values()),
        "device_id": main._redact_known_device_serials(resolved_device_id, serials),
        "checks": checks,
        "details": {
            "adb": main._redact_known_device_serials(adb_info, serials),
            "device": main._redact_known_device_serials(
                device_info,
                serials,
            ),
            "frida": main._redact_known_device_serials(frida_info, serials),
            "frida_runtime": frida_runtime_info,
            "mitm": {"port": mitm_listen_port, "listening": mitm_8080_listening},
            "output": output_info,
            "apktool": _public(apktool_info),
            "frida_python": _public(frida_python_info),
            "redaction_hmac_key": redaction_info,
            "apk_allowed_roots": allowed_roots_info["apk_allowed_roots"],
        },
    }


@router.get("/traffic/check")
def traffic_check(device_id: str):
    main = _main()
    try:
        select_fn = getattr(main, "select_device_context", select_device_context)
        resolved_device_id = select_fn(device_id).serial
    except DeviceSelectionError:
        resolved_device_id = device_id
    device_info = getattr(main, "check_device_online", check_device_online)(device_id=resolved_device_id)
    mitm_status = getattr(main, "get_mitm_status", get_mitm_status)(port=getattr(main, "DEFAULT_MITM_PORT", DEFAULT_MITM_PORT))
    stream_log = mitm_status.get("stream_log")
    records = getattr(main, "parse_traffic_text", parse_traffic_text)(stream_log) if stream_log else []
    flow_file_size = mitm_status.get("flow_file_size", 0)

    captured_ok = bool(records) and bool(
        mitm_status.get("owned_by_session")
    )
    reasons = []

    if not device_info.get("ok"):
        reasons.append("Device is offline or unauthorized (adb state is not 'device').")
    if not mitm_status.get("has_last_session"):
        reasons.append("No recent mitm session found.")
    if not mitm_status.get("traffic_dir_exists"):
        reasons.append("traffic directory is missing; capture may not have started or path is inaccessible.")
    if not mitm_status.get("traffic_dir_writable"):
        reasons.append("traffic directory is not writable; cannot persist capture files.")
    if not mitm_status.get("port_listening"):
        reasons.append("mitmproxy is not listening on port 8080.")
    if mitm_status.get("stream_log_exists") and mitm_status.get("stream_log_size", 0) == 0:
        reasons.append("mitm stream log is empty; proxy may not be hit or HTTPS decryption failed.")
    if not captured_ok:
        reasons.append("No requests detected in latest capture; verify proxy/IP/certificate/SSL pinning.")

    serials = main._device_serials(device_info, resolved_device_id)
    response = {
        "ok": captured_ok,
        "device_id": resolved_device_id,
        "captured_success": captured_ok,
        "captured_request_count": len(records),
        "flow_file_size": flow_file_size,
        "possible_reasons": reasons,
        "mitm_status": mitm_status,
        "sample_requests": records[:10],
    }
    return main._redact_known_device_serials(response, serials)


@router.post("/frida/diagnostics")
def frida_diagnostics(request: FridaDiagnosticsRequest):
    """Run a read-only, exact-device diagnostic pass."""
    main = _main()
    select_fn = getattr(main, "select_device_context", select_device_context)
    device = select_fn(request.device_id)
    return main.frida_diagnostics_service.diagnose(
        request.model_copy(update={"device_id": device.serial})
    )


@router.get("/frida/status")
def frida_server_status(device_id: str = Query(min_length=1, max_length=256)):
    main = _main()
    select_fn = getattr(main, "select_device_context", select_device_context)
    return main.frida_server_manager.status(select_fn(device_id))


@router.post("/frida/server/deploy")
def deploy_frida_server(request: FridaServerActionRequest):
    main = _main()
    select_fn = getattr(main, "select_device_context", select_device_context)
    return main.frida_server_manager.deploy(
        select_fn(request.device_id),
        confirm=request.confirm,
    )


@router.post("/frida/server/start")
def start_frida_server(request: FridaServerActionRequest):
    main = _main()
    select_fn = getattr(main, "select_device_context", select_device_context)
    return main.frida_server_manager.start(
        select_fn(request.device_id),
        confirm=request.confirm,
    )


@router.post("/frida/server/stop")
def stop_frida_server(request: FridaServerActionRequest):
    main = _main()
    select_fn = getattr(main, "select_device_context", select_device_context)
    return main.frida_server_manager.stop(
        select_fn(request.device_id),
        confirm=request.confirm,
    )
