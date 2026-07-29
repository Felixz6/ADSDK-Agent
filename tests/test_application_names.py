import json
from pathlib import Path

from app.core.application_names import (
    resolve_application_label,
    stable_application_name,
)
from app.repositories.task_repository import TaskRepository
from app.services.application_name_service import repair_historical_application_names
from app.tools.manifest_parser import parse_manifest_info


def _manifest(label: str, package: str = "com.example.labels") -> str:
    return f"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="{package}">
  <application android:label="{label}" />
</manifest>
"""


def _write_strings(directory: Path, value: str, *, name: str = "app_name") -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "strings.xml").write_text(
        f'<?xml version="1.0" encoding="utf-8"?><resources>'
        f'<string name="{name}">{value}</string></resources>',
        encoding="utf-8",
    )


def test_manifest_resolves_named_resource_from_base_values(tmp_path: Path):
    (tmp_path / "AndroidManifest.xml").write_text(
        _manifest("@string/app_name"),
        encoding="utf-8",
    )
    _write_strings(tmp_path / "res" / "values", "红果免费短剧")
    _write_strings(tmp_path / "res" / "values-en", "Hongguo")

    info = parse_manifest_info(str(tmp_path), apk_filename="hongguo.apk")

    assert info["application_label"] == "红果免费短剧"


def test_manifest_prefers_chinese_when_base_value_is_absent(tmp_path: Path):
    (tmp_path / "AndroidManifest.xml").write_text(
        _manifest("@string/app_name"),
        encoding="utf-8",
    )
    _write_strings(tmp_path / "res" / "values-en", "English name")
    _write_strings(tmp_path / "res" / "values-zh-rCN", "中文名称")

    assert resolve_application_label(tmp_path, "@string/app_name") == "中文名称"


def test_manifest_resolves_numeric_resource_id_from_public_xml(tmp_path: Path):
    (tmp_path / "AndroidManifest.xml").write_text(
        _manifest("@0x7f120001"),
        encoding="utf-8",
    )
    values = tmp_path / "res" / "values"
    _write_strings(values, "数字资源名称", name="display_name")
    (values / "public.xml").write_text(
        '<?xml version="1.0" encoding="utf-8"?><resources>'
        '<public type="string" name="display_name" id="0x7f120001" />'
        '</resources>',
        encoding="utf-8",
    )

    info = parse_manifest_info(str(tmp_path), apk_filename="numeric.apk")

    assert info["application_label"] == "数字资源名称"


def test_application_name_fallback_never_leaks_resource_reference(tmp_path: Path):
    (tmp_path / "AndroidManifest.xml").write_text(
        _manifest("@string/missing"),
        encoding="utf-8",
    )

    info = parse_manifest_info(str(tmp_path), apk_filename="fallback.apk")

    assert info["application_label"] == "fallback.apk"
    assert stable_application_name("@string/app_name", package_name="com.demo") == "com.demo"
    assert stable_application_name("@string/app_name") == "未知应用"


def test_historical_resource_reference_is_repaired_in_sqlite_and_report(tmp_path: Path):
    repository = TaskRepository(tmp_path / "tasks.db")
    repository.initialize()
    sha = "a" * 64
    report_path = tmp_path / "report.json"
    report_path.write_text(
        json.dumps(
            {
                "app_info": {
                    "application_label": "@string/app_name",
                    "package_name": "com.phoenix.read",
                }
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    repository.create_task(
        {
            "id": "legacy-task",
            "task_type": "static",
            "status": "completed",
            "apk_path": "D:/samples/hongguo.apk",
            "package_name": "com.phoenix.read",
            "app_name": "@string/app_name",
        }
    )
    repository.update_task(
        "legacy-task",
        apk_sha256=sha,
        report_json_path=str(report_path),
    )
    unpacked = tmp_path / "cache" / sha / "unpacked"
    (unpacked / "AndroidManifest.xml").parent.mkdir(parents=True, exist_ok=True)
    (unpacked / "AndroidManifest.xml").write_text(
        _manifest("@string/app_name", "com.phoenix.read"),
        encoding="utf-8",
    )
    _write_strings(unpacked / "res" / "values", "红果免费短剧")

    repaired = repair_historical_application_names(
        repository,
        static_unpack_cache_dir=tmp_path / "cache",
    )

    task = repository.get_task("legacy-task")
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert repaired == 2
    assert task is not None
    assert task.app_name == "红果免费短剧"
    assert report["app_info"]["application_label"] == "红果免费短剧"
    assert report["app_info"]["resolved_app_name"] == "红果免费短剧"
