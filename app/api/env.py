"""Environment, traffic, and Frida diagnostics API router."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, Depends, Query

from app import config as app_config
from app.api.deps import (
    get_frida_diagnostics_service,
    get_frida_server_manager,
)
from app.core.env_checks import (
    check_apk_allowed_roots,
    check_apktool,
    check_frida_python_package,
    check_redaction_hmac_key,
)
from app.core.redaction import _device_serials, _redact_known_device_serials
from app.frida import (
    FridaDiagnosticsRequest,
    FridaServerActionRequest,
)
from app.frida.frida_runner import check_frida_connection, check_frida_device_runtime
from app.pipelines.common import _check_output_writable
from app.tools.adb_runner import (
    DeviceSelectionError,
    check_adb_available,
    check_device_online,
    select_device_context,
)
from app.traffic.mitm_runner import check_port_listening, get_mitm_status
from app.traffic.traffic_parser import parse_traffic_text

if TYPE_CHECKING:
    from app.frida import FridaDiagnosticsService, FridaServerManager

router = APIRouter(tags=["environment"])


@router.get("/env/check")
def env_check(device_id: str | None = None):
    resolved_device_id = device_id
    if device_id:
        try:
            resolved_device_id = select_device_context(device_id).serial
        except DeviceSelectionError:
            resolved_device_id = device_id
    adb_info = check_adb_available()
    device_info = check_device_online(device_id=resolved_device_id)
    frida_info = check_frida_connection(device_id=resolved_device_id)
    frida_runtime_info = check_frida_device_runtime(resolved_device_id)
    mitm_listen_port = app_config.DEFAULT_MITM_PORT
    mitm_8080_listening = check_port_listening(port=mitm_listen_port)
    output_info = _check_output_writable()
    serials = _device_serials(device_info, resolved_device_id)

    apktool_info = check_apktool()
    frida_python_info = check_frida_python_package()
    redaction_info = check_redaction_hmac_key()
    allowed_roots_info = check_apk_allowed_roots()

    checks = {
        "adb_available": adb_info.get("ok", False),
        "device_online": device_info.get("ok", False),
        "frida_connectable": frida_info.get("ok", False),
        "frida_server_running": frida_runtime_info.get(
            "server_running",
            False,
        ),
        "frida_python_available": frida_python_info.get("frida_python_available", False),
        "apktool_available": apktool_info.get("apktool_available", False),
        "mitm_8080_listening": mitm_8080_listening,
        "output_writable": output_info.get("ok", False),
        "redaction_hmac_key_secure": redaction_info.get("redaction_hmac_key_security_status")
        == "secure",
        "apk_allowed_roots_configured": allowed_roots_info.get(
            "apk_allowed_roots_configured", False
        ),
    }

    def _public(obj: dict[str, Any]) -> dict[str, Any]:
        return {k: v for k, v in obj.items() if not k.startswith("_")}

    return {
        "ok": all(checks.values()),
        "device_id": _redact_known_device_serials(resolved_device_id, serials),
        "checks": checks,
        "details": {
            "adb": _redact_known_device_serials(adb_info, serials),
            "device": _redact_known_device_serials(device_info, serials),
            "frida": _redact_known_device_serials(frida_info, serials),
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
    try:
        resolved_device_id = select_device_context(device_id).serial
    except DeviceSelectionError:
        resolved_device_id = device_id
    device_info = check_device_online(device_id=resolved_device_id)
    mitm_status = get_mitm_status(port=app_config.DEFAULT_MITM_PORT)
    records: list[dict[str, Any]] = []
    jsonl_path = mitm_status.get("jsonl_path")
    if jsonl_path and Path(jsonl_path).is_file():
        try:
            with open(jsonl_path, encoding="utf-8") as f:
                for line in f:
                    stripped = line.strip()
                    if stripped:
                        item = json.loads(stripped)
                        if item.get("type") == "http_request":
                            records.append(item)
        except Exception:
            pass
    if not records:
        stream_log = mitm_status.get("stream_log")
        records = parse_traffic_text(stream_log) if stream_log else []
    flow_file_size = mitm_status.get("flow_file_size", 0)

    captured_ok = bool(records) and bool(mitm_status.get("owned_by_session"))
    reasons = []

    if not device_info.get("ok"):
        reasons.append("Device is offline or unauthorized (adb state is not 'device').")
    if not mitm_status.get("has_last_session"):
        reasons.append("No recent mitm session found.")
    if not mitm_status.get("traffic_dir_exists"):
        reasons.append(
            "traffic directory is missing; capture may not have started or path is inaccessible."
        )
    if not mitm_status.get("traffic_dir_writable"):
        reasons.append("traffic directory is not writable; cannot persist capture files.")
    if not mitm_status.get("port_listening"):
        reasons.append("mitmproxy is not listening on port 8080.")
    if mitm_status.get("stream_log_exists") and mitm_status.get("stream_log_size", 0) == 0:
        reasons.append("mitm stream log is empty; proxy may not be hit or HTTPS decryption failed.")
    if not captured_ok:
        reasons.append(
            "No requests detected in latest capture; verify proxy/IP/certificate/SSL pinning."
        )

    serials = _device_serials(device_info, resolved_device_id)
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
    return _redact_known_device_serials(response, serials)


@router.post("/frida/diagnostics")
def frida_diagnostics(
    request: FridaDiagnosticsRequest,
    frida_diagnostics_service: FridaDiagnosticsService = Depends(get_frida_diagnostics_service),
):
    """Run a read-only, exact-device diagnostic pass."""
    device = select_device_context(request.device_id)
    return frida_diagnostics_service.diagnose(
        request.model_copy(update={"device_id": device.serial})
    )


@router.get("/frida/status")
def frida_server_status(
    device_id: str = Query(min_length=1, max_length=256),
    frida_server_manager: FridaServerManager = Depends(get_frida_server_manager),
):
    return frida_server_manager.status(select_device_context(device_id))


@router.post("/frida/server/deploy")
def deploy_frida_server(
    request: FridaServerActionRequest,
    frida_server_manager: FridaServerManager = Depends(get_frida_server_manager),
):
    return frida_server_manager.deploy(
        select_device_context(request.device_id),
        confirm=request.confirm,
    )


@router.post("/frida/server/start")
def start_frida_server(
    request: FridaServerActionRequest,
    frida_server_manager: FridaServerManager = Depends(get_frida_server_manager),
):
    return frida_server_manager.start(
        select_device_context(request.device_id),
        confirm=request.confirm,
    )


@router.post("/frida/server/stop")
def stop_frida_server(
    request: FridaServerActionRequest,
    frida_server_manager: FridaServerManager = Depends(get_frida_server_manager),
):
    return frida_server_manager.stop(
        select_device_context(request.device_id),
        confirm=request.confirm,
    )
