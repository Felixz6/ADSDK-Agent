"""P0 regression contracts for isolation, evidence status, redaction, and devices.

These tests intentionally exercise the public compatibility APIs and the small
core contracts that the P0 hardening work introduces.  All external Android
tools are replaced with local fakes; a real device, Frida, apktool, and
mitmproxy are not required.
"""

from __future__ import annotations

import json
import zipfile
from pathlib import Path
from typing import Any, Callable

import pytest
from fastapi.testclient import TestClient

from app import main as main_module
from app.core.device import DeviceContext
from app.core.redaction import Redactor
from app.tools.log_writer import append_log


class DummyProcess:
    def __init__(self) -> None:
        self.alive = True

    def poll(self) -> int | None:
        return None if self.alive else 0

    def terminate(self) -> None:
        self.alive = False

    def wait(self, timeout: float | None = None) -> int:
        self.alive = False
        return 0

    def kill(self) -> None:
        self.alive = False


def _result_ok(**extra: Any) -> dict[str, Any]:
    return {
        "returncode": 0,
        "stdout": "ok",
        "stderr": "",
        "cmd": [],
        **extra,
    }


def _write_fake_apk(path: Path, marker: str = "fixture") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", f"<manifest package='{marker}'/>")


def _extract_argument(
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    *,
    keyword: str,
    position: int,
) -> Any:
    if keyword in kwargs:
        return kwargs[keyword]
    return args[position]


def _run_dir(body: dict[str, Any], output_root: Path) -> Path:
    """Assert and return the canonical output/runs/<run_id> directory."""

    run_id = body.get("run_id")
    output_dir = body.get("output_dir")
    assert isinstance(run_id, str) and run_id
    assert isinstance(output_dir, str) and output_dir

    actual = Path(output_dir).resolve()
    expected_parent = (output_root / "runs").resolve()
    assert actual.parent == expected_parent
    assert actual.name == run_id
    return actual


def _read_artifacts(run_dir: Path) -> dict[str, str]:
    names = ("hook.log", "events.json", "traffic_summary.json", "report.json", "report.md")
    result: dict[str, str] = {}
    for name in names:
        path = run_dir / name
        if path.exists():
            result[name] = path.read_text(encoding="utf-8", errors="strict")
    return result


def _rule_statuses(value: Any) -> list[str]:
    statuses: list[str] = []
    if isinstance(value, dict):
        if "rule_id" in value and isinstance(value.get("status"), str):
            statuses.append(value["status"])
        for child in value.values():
            statuses.extend(_rule_statuses(child))
    elif isinstance(value, list):
        for child in value:
            statuses.extend(_rule_statuses(child))
    return statuses


def _assert_degraded_result(body: dict[str, Any], expected_keyword: str) -> None:
    assert body.get("status") in {"partial", "failed"}

    steps = body.get("steps")
    assert isinstance(steps, list) and steps
    degraded_steps = [
        step
        for step in steps
        if isinstance(step, dict) and step.get("status") in {"partial", "failed"}
    ]
    assert degraded_steps
    assert expected_keyword.casefold() in json.dumps(
        degraded_steps,
        ensure_ascii=False,
    ).casefold()

    statuses = _rule_statuses(body)
    assert "not_evaluated" in statuses


def _install_common_fakes(
    monkeypatch: pytest.MonkeyPatch,
    output_root: Path,
    *,
    hook_writer: Callable[[Path, int], None] | None = None,
    traffic_mode: str = "request",
) -> dict[str, Any]:
    """Install deterministic fakes while retaining real parsers and writers."""

    state: dict[str, Any] = {
        "spawn_count": 0,
        "installed_apks": [],
        "launched_packages": [],
    }

    monkeypatch.setattr(main_module, "OUTPUT_DIR", str(output_root))
    monkeypatch.setattr(
        main_module,
        "APK_ALLOWED_ROOTS",
        (output_root.parent.resolve(),),
    )
    monkeypatch.setattr(
        main_module,
        "select_device_context",
        lambda device_id=None: DeviceContext(
            serial=device_id or "emulator-5554",
        ),
    )
    monkeypatch.setattr(main_module.time, "sleep", lambda _: None)

    def fake_unpack(*args: Any, **kwargs: Any) -> dict[str, Any]:
        apk_path = Path(
            _extract_argument(args, kwargs, keyword="apk_path", position=0)
        ).resolve()
        out_dir = Path(
            _extract_argument(args, kwargs, keyword="out_dir", position=1)
        )
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / ".source_apk").write_text(str(apk_path), encoding="utf-8")
        (out_dir / "AndroidManifest.xml").write_text(
            "<manifest package='fixture'/>",
            encoding="utf-8",
        )
        return _result_ok()

    def fake_manifest(unpack_dir: str) -> dict[str, str]:
        source = Path(unpack_dir, ".source_apk").read_text(encoding="utf-8")
        discriminator = sum(source.encode("utf-8")) % 1_000_000
        return {
            "package_name": f"com.example.app{discriminator}",
            "version_name": "1.0",
            "version_code": "1",
            "application_label": f"fixture-{discriminator}",
        }

    def fake_sdks(_: str) -> list[dict[str, Any]]:
        return [
            {
                "sdk_name": "Fixture SDK",
                "package": "com.example.fixture.sdk",
                "confidence": 0.99,
                "version": "1",
                "evidence": [],
            }
        ]

    def fake_install(*args: Any, **kwargs: Any) -> dict[str, Any]:
        apk_path = _extract_argument(args, kwargs, keyword="apk_path", position=0)
        state["installed_apks"].append(str(apk_path))
        return _result_ok()

    def fake_launch(*args: Any, **kwargs: Any) -> dict[str, Any]:
        package_name = _extract_argument(
            args,
            kwargs,
            keyword="package_name",
            position=0,
        )
        state["launched_packages"].append(str(package_name))
        return _result_ok()

    def fake_spawn(*args: Any, **kwargs: Any) -> dict[str, Any]:
        log_path = Path(
            _extract_argument(args, kwargs, keyword="log_path", position=2)
        )
        state["spawn_count"] += 1
        if hook_writer is None:
            append_log(
                str(log_path),
                f"[INFO] 2026-07-24T00:00:0{state['spawn_count']}Z "
                f"fixture-run-marker-{state['spawn_count']}",
            )
        else:
            hook_writer(log_path, state["spawn_count"])
        return {
            "ok": True,
            "error": None,
            "process": DummyProcess(),
            "log_file": None,
            "cmd": ["frida"],
        }

    def fake_start_mitm(*args: Any, **kwargs: Any) -> dict[str, Any]:
        output_dir = Path(
            _extract_argument(args, kwargs, keyword="output_dir", position=0)
        )
        traffic_dir = output_dir / "traffic"
        traffic_dir.mkdir(parents=True, exist_ok=True)
        stream_log = traffic_dir / "mitm_stream.log"
        flow_file = traffic_dir / "flows.mitm"

        if traffic_mode == "request":
            stream_log.write_text(
                "10:00:01.001 GET https://api.example.test/v1/init HTTP/1.1\n",
                encoding="utf-8",
            )
            flow_file.write_bytes(b"fixture-flow")
        elif traffic_mode == "empty":
            stream_log.write_text("", encoding="utf-8")
            flow_file.write_bytes(b"")
        elif traffic_mode == "missing":
            pass
        else:
            raise AssertionError(f"unknown traffic mode: {traffic_mode}")

        return {
            "ok": True,
            "error": None,
            "traffic_dir": str(traffic_dir),
            "stream_log": str(stream_log),
            "flow_file": str(flow_file),
        }

    monkeypatch.setattr(main_module, "unpack_apk", fake_unpack)
    monkeypatch.setattr(main_module, "parse_manifest_info", fake_manifest)
    monkeypatch.setattr(main_module, "scan_for_sdks", fake_sdks)
    monkeypatch.setattr(main_module, "install_apk", fake_install)
    monkeypatch.setattr(main_module, "launch_app", fake_launch)
    monkeypatch.setattr(main_module, "spawn_and_inject", fake_spawn)
    monkeypatch.setattr(main_module, "start_mitm", fake_start_mitm)
    monkeypatch.setattr(
        main_module,
        "stop_mitm",
        lambda *args, **kwargs: {"ok": True, "error": None},
    )
    return state


def _post_dynamic(client: TestClient, apk_path: Path) -> dict[str, Any]:
    response = client.post(
        "/dynamic/analyze",
        json={
            "apk_path": str(apk_path),
            "device_id": "emulator-5554",
            "package_name": "com.example.fixture",
            "pre_consent_seconds": 0,
            "post_consent_seconds": 0,
        },
    )
    assert response.headers.get("content-type", "").startswith("application/json")
    return response.json()


def test_redactor_masks_android_id_oaid_short_and_empty_values() -> None:
    redactor = Redactor(secret=b"p0-test-secret")

    android_id = "9774d56d682e549c"
    oaid = "3f2504e0-4f89-41d3-9a0c-0305e82c3301"
    short_value = "QZ"

    android_redacted = redactor.redact_identifier(android_id, kind="android_id")
    oaid_redacted = redactor.redact_identifier(oaid, kind="oaid")
    short_redacted = redactor.redact_identifier(short_value, kind="device_id")

    assert isinstance(android_redacted, str) and android_redacted
    assert isinstance(oaid_redacted, str) and oaid_redacted
    assert isinstance(short_redacted, str) and short_redacted
    assert android_id.casefold() not in android_redacted.casefold()
    assert oaid.casefold() not in oaid_redacted.casefold()
    assert short_value.casefold() not in short_redacted.casefold()
    assert android_redacted != oaid_redacted

    assert redactor.redact_identifier(None, kind="android_id") is None
    assert redactor.redact_identifier("", kind="oaid") is None


def test_redactor_stable_token_is_deterministic_for_the_same_secret() -> None:
    first = Redactor(secret=b"stable-test-secret")
    second = Redactor(secret=b"stable-test-secret")
    value = "9774d56d682e549c"

    token = first.stable_token(value)
    assert token == first.stable_token(value)
    assert token == second.stable_token(value)
    assert token != first.stable_token("9774d56d682e549d")
    assert value.casefold() not in token.casefold()


def test_device_context_binds_every_command_and_redacts_public_serial() -> None:
    serial = "emulator-5554"
    context = DeviceContext(serial=serial)

    assert context.adb_command("shell", "getprop", "ro.product.cpu.abi") == [
        "adb",
        "-s",
        serial,
        "shell",
        "getprop",
        "ro.product.cpu.abi",
    ]
    assert context.frida_command("frida-ps", "-a") == [
        "frida-ps",
        "-D",
        serial,
        "-a",
    ]

    public_first = context.to_public_dict()
    public_second = context.to_public_dict()
    serialized = json.dumps(public_first, ensure_ascii=False)
    assert public_first == public_second
    assert serial not in serialized
    assert serial not in repr(context)
    assert public_first


def test_dynamic_derived_artifacts_and_response_do_not_contain_raw_identifier(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw_android_id = "9774d56d682e549c"
    output_root = tmp_path / "output"
    apk_path = tmp_path / "fixture.apk"
    _write_fake_apk(apk_path)

    def write_sensitive_hook(log_path: Path, _: int) -> None:
        append_log(
            str(log_path),
            "[HOOK] Settings.Secure.getString "
            f"name=android_id ret={raw_android_id}",
        )

    _install_common_fakes(
        monkeypatch,
        output_root,
        hook_writer=write_sensitive_hook,
    )
    client = TestClient(main_module.app, raise_server_exceptions=False)

    body = _post_dynamic(client, apk_path)
    run_dir = _run_dir(body, output_root)
    artifacts = _read_artifacts(run_dir)

    assert {"events.json", "report.json", "report.md"} <= artifacts.keys()
    assert raw_android_id not in json.dumps(body, ensure_ascii=False)
    assert raw_android_id not in artifacts["events.json"]
    assert raw_android_id not in artifacts["report.json"]
    assert raw_android_id not in artifacts["report.md"]


def test_same_apk_twice_uses_distinct_runs_without_reading_previous_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output_root = tmp_path / "output"
    apk_path = tmp_path / "same.apk"
    _write_fake_apk(apk_path, marker="same")
    _install_common_fakes(monkeypatch, output_root)
    client = TestClient(main_module.app, raise_server_exceptions=False)

    first_body = _post_dynamic(client, apk_path)
    first_dir = _run_dir(first_body, output_root)
    first_snapshot = _read_artifacts(first_dir)
    assert "fixture-run-marker-1" in first_snapshot["events.json"]

    second_body = _post_dynamic(client, apk_path)
    second_dir = _run_dir(second_body, output_root)
    second_artifacts = _read_artifacts(second_dir)

    assert first_body["run_id"] != second_body["run_id"]
    assert first_dir != second_dir
    assert first_snapshot == _read_artifacts(first_dir)
    assert "fixture-run-marker-1" not in second_artifacts["events.json"]
    assert "fixture-run-marker-1" not in second_artifacts["report.json"]
    assert "fixture-run-marker-2" in second_artifacts["events.json"]


def test_same_basename_and_static_dynamic_calls_have_independent_run_directories(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output_root = tmp_path / "output"
    apk_a = tmp_path / "source-a" / "demo.apk"
    apk_b = tmp_path / "source-b" / "demo.apk"
    _write_fake_apk(apk_a, marker="source-a")
    _write_fake_apk(apk_b, marker="source-b")
    _install_common_fakes(monkeypatch, output_root)
    client = TestClient(main_module.app, raise_server_exceptions=False)

    static_a_response = client.post("/analyze", json={"apk_path": str(apk_a)})
    assert static_a_response.headers.get("content-type", "").startswith(
        "application/json"
    )
    static_a = static_a_response.json()
    static_a_dir = _run_dir(static_a, output_root)
    static_a_snapshot = _read_artifacts(static_a_dir)

    static_b_response = client.post("/analyze", json={"apk_path": str(apk_b)})
    assert static_b_response.headers.get("content-type", "").startswith(
        "application/json"
    )
    static_b = static_b_response.json()
    static_b_dir = _run_dir(static_b, output_root)

    dynamic_a = _post_dynamic(client, apk_a)
    dynamic_a_dir = _run_dir(dynamic_a, output_root)

    assert len(
        {
            static_a["run_id"],
            static_b["run_id"],
            dynamic_a["run_id"],
        }
    ) == 3
    assert len({static_a_dir, static_b_dir, dynamic_a_dir}) == 3
    assert static_a_snapshot == _read_artifacts(static_a_dir)
    assert static_a["app_info"] != static_b["app_info"]


def test_legacy_poison_files_are_not_read_by_a_new_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output_root = tmp_path / "output"
    apk_path = tmp_path / "legacy.apk"
    _write_fake_apk(apk_path, marker="legacy")

    legacy_dir = output_root / "legacy"
    legacy_dir.mkdir(parents=True)
    poison = "LEGACY-POISON-MUST-NOT-BE-READ"
    (legacy_dir / "hook.log").write_text(poison, encoding="utf-8")
    (legacy_dir / "events.json").write_text(
        json.dumps([{"result": poison}]),
        encoding="utf-8",
    )
    (legacy_dir / "report.json").write_text(
        json.dumps({"poison": poison}),
        encoding="utf-8",
    )
    (legacy_dir / "report.md").write_text(poison, encoding="utf-8")

    _install_common_fakes(monkeypatch, output_root)
    client = TestClient(main_module.app, raise_server_exceptions=False)
    body = _post_dynamic(client, apk_path)
    run_dir = _run_dir(body, output_root)

    assert run_dir != legacy_dir.resolve()
    assert poison not in json.dumps(body, ensure_ascii=False)
    for content in _read_artifacts(run_dir).values():
        assert poison not in content


@pytest.mark.parametrize(
    ("failure_mode", "expected_keyword"),
    [
        ("missing_hook", "hook"),
        ("corrupt_hook", "hook"),
        ("missing_traffic", "traffic"),
        ("empty_traffic", "traffic"),
        ("manifest_error", "manifest"),
        ("sdk_error", "sdk"),
    ],
)
def test_missing_or_corrupt_evidence_degrades_status_and_rules_are_not_evaluated(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_mode: str,
    expected_keyword: str,
) -> None:
    output_root = tmp_path / "output"
    apk_path = tmp_path / f"{failure_mode}.apk"
    _write_fake_apk(apk_path, marker=failure_mode)
    traffic_mode = "empty" if failure_mode == "empty_traffic" else "request"
    _install_common_fakes(
        monkeypatch,
        output_root,
        traffic_mode=traffic_mode,
    )

    if failure_mode == "missing_hook":
        monkeypatch.setattr(
            main_module,
            "parse_hook_to_events_json",
            lambda *args, **kwargs: (_ for _ in ()).throw(
                FileNotFoundError("hook evidence is missing")
            ),
        )
    elif failure_mode == "corrupt_hook":
        monkeypatch.setattr(
            main_module,
            "parse_hook_to_events_json",
            lambda *args, **kwargs: (_ for _ in ()).throw(
                UnicodeDecodeError("utf-8", b"\xff", 0, 1, "corrupt hook evidence")
            ),
        )
    elif failure_mode == "missing_traffic":
        monkeypatch.setattr(
            main_module,
            "parse_traffic_to_summary_json",
            lambda *args, **kwargs: (_ for _ in ()).throw(
                FileNotFoundError("traffic evidence is missing")
            ),
        )
    elif failure_mode == "manifest_error":
        monkeypatch.setattr(
            main_module,
            "parse_manifest_info",
            lambda *args, **kwargs: (_ for _ in ()).throw(
                ValueError("manifest parse failed")
            ),
        )
    elif failure_mode == "sdk_error":
        monkeypatch.setattr(
            main_module,
            "scan_for_sdks",
            lambda *args, **kwargs: (_ for _ in ()).throw(
                RuntimeError("sdk scan failed")
            ),
        )

    client = TestClient(main_module.app, raise_server_exceptions=False)
    body = _post_dynamic(client, apk_path)
    _run_dir(body, output_root)
    _assert_degraded_result(body, expected_keyword)


def test_manifest_value_error_keeps_structured_reports_and_correlation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output_root = tmp_path / "output"
    apk_path = tmp_path / "manifest-error-regression.apk"
    _write_fake_apk(apk_path, marker="manifest-error-regression")
    _install_common_fakes(monkeypatch, output_root)
    monkeypatch.setattr(
        main_module,
        "parse_manifest_info",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            ValueError("manifest parse failed")
        ),
    )

    client = TestClient(main_module.app, raise_server_exceptions=True)
    response = client.post(
        "/dynamic/analyze",
        json={
            "apk_path": str(apk_path),
            "device_id": "emulator-5554",
            "package_name": "com.example.fixture",
            "pre_consent_seconds": 0,
            "post_consent_seconds": 0,
        },
    )

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    body = response.json()
    assert body["status"] == "partial"
    assert body["app_info"]["package_name"] == "com.example.fixture"
    assert body["app_info"]["declared_permissions"] == []
    assert body["manifest_evidence"] == {
        "status": "not_evaluated",
        "error_code": "manifest_parse_failed",
        "message": "manifest parse failed: ValueError",
    }
    assert body["evidence_correlation"]["schema_version"] == "correlation-v1"
    assert body["evidence_correlation"]["status"] in {
        "evaluated",
        "not_evaluated",
        "no_observations",
    }
    assert "manifest" in json.dumps(body["steps"], ensure_ascii=False).casefold()
    assert "not_evaluated" in _rule_statuses(body)

    run_dir = _run_dir(body, output_root)
    for name in (
        "correlations.json",
        "report.json",
        "report.md",
        "report.html",
    ):
        assert (run_dir / name).is_file()
    persisted = json.loads((run_dir / "report.json").read_text(encoding="utf-8"))
    assert persisted["manifest_evidence"]["status"] == "not_evaluated"
    assert persisted["evidence_correlation"]["schema_version"] == "correlation-v1"
