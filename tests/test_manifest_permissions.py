from pathlib import Path

from app.analyzers.risk_scoring import calculate_risk_summary
from app.tools.manifest_parser import parse_manifest_info


MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.permissions">
  <uses-permission android:name=" android.permission.CAMERA "/>
  <uses-permission android:name="android.permission.CAMERA"/>
  <uses-permission-sdk-23 android:name="android.permission.READ_PHONE_STATE"/>
  <permission android:name="com.example.permissions.CUSTOM"/>
  <application android:label="Demo">
    <activity android:name=".Main"
      android:permission="com.example.permissions.ACTIVITY"/>
    <provider android:name=".Provider"
      android:readPermission="com.example.permissions.READ"
      android:writePermission="com.example.permissions.WRITE"/>
  </application>
</manifest>
"""


def test_manifest_permission_categories_are_exact_and_deduplicated(tmp_path: Path):
    (tmp_path / "AndroidManifest.xml").write_text(MANIFEST, encoding="utf-8")
    info = parse_manifest_info(str(tmp_path))

    assert info["declared_permissions"] == [
        "android.permission.CAMERA",
        "android.permission.READ_PHONE_STATE",
    ]
    assert info["permissions"] == info["declared_permissions"]
    assert info["custom_permissions"] == ["com.example.permissions.CUSTOM"]
    assert info["component_permissions"] == [
        "com.example.permissions.ACTIVITY",
        "com.example.permissions.READ",
        "com.example.permissions.WRITE",
    ]
    assert info["sensitive_permissions"] == info["declared_permissions"]
    assert info["high_attention_permissions"] == info["declared_permissions"]


def test_risk_scoring_uses_only_declared_permissions():
    summary = calculate_risk_summary(
        {
            "app_info": {
                "declared_permissions": [],
                "permissions": ["android.permission.CAMERA"],
                "custom_permissions": ["android.permission.CAMERA"],
                "component_permissions": ["android.permission.READ_PHONE_STATE"],
            }
        }
    )
    assert summary.score == 0
    assert not summary.top_risks


def test_legacy_permissions_field_remains_score_compatible():
    summary = calculate_risk_summary(
        {"app_info": {"permissions": ["android.permission.CAMERA"]}}
    )
    assert summary.score == 12
    assert summary.top_risks[0].id == "manifest_sensitive_permissions"
