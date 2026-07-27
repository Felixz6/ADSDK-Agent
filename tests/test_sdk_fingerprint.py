from app.tools.sdk_fingerprint import scan_for_sdks


def test_scan_for_sdks(tmp_path):
    fake_dir = tmp_path / "unpacked" / "smali_classes2" / "com" / "bytedance" / "sdk" / "openadsdk"
    fake_dir.mkdir(parents=True)

    results = scan_for_sdks(str(tmp_path / "unpacked"))
    packages = [x["package"] for x in results]

    assert "com.bytedance.sdk.openadsdk" in packages
