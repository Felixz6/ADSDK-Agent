from pathlib import Path

import pytest

from app.tools.sdk_fingerprint import scan_for_sdks


PANGLE_PACKAGE = "com.bytedance.sdk.openadsdk"


def _pangle_hits(unpack_dir: Path | str) -> list[dict]:
    return [
        hit
        for hit in scan_for_sdks(str(unpack_dir))
        if hit.get("package") == PANGLE_PACKAGE
    ]


def test_scan_for_sdks_empty_directory_does_not_match(tmp_path):
    unpack_dir = tmp_path / "unpacked"
    unpack_dir.mkdir()

    assert scan_for_sdks(str(unpack_dir)) == []


def test_scan_for_sdks_empty_working_directory_does_not_match(tmp_path, monkeypatch):
    working_dir = tmp_path / PANGLE_PACKAGE
    working_dir.mkdir()
    monkeypatch.chdir(working_dir)

    assert scan_for_sdks(str(Path.cwd())) == []


@pytest.mark.parametrize(
    "relative_parts",
    [
        pytest.param(
            ("output", f"demo-{PANGLE_PACKAGE}", "unpacked"),
            id="apk-name-contains-signature",
        ),
        pytest.param(
            (f"parent-{PANGLE_PACKAGE}", "output", "demo", "unpacked"),
            id="ancestor-contains-signature",
        ),
    ],
)
def test_scan_for_sdks_signature_outside_decoded_tree_does_not_match(
    tmp_path, relative_parts
):
    unpack_dir = tmp_path.joinpath(*relative_parts)
    unpack_dir.mkdir(parents=True)

    assert _pangle_hits(unpack_dir) == []


@pytest.mark.parametrize("similar_leaf", ["openadsdk2", "openadsdk_beta"])
def test_scan_for_sdks_similar_package_name_does_not_match(tmp_path, similar_leaf):
    similar_package_dir = (
        tmp_path
        / "unpacked"
        / "smali"
        / "com"
        / "bytedance"
        / "sdk"
        / similar_leaf
    )
    similar_package_dir.mkdir(parents=True)

    assert _pangle_hits(tmp_path / "unpacked") == []


@pytest.mark.parametrize("smali_root", ["smali", "smali_classes2"])
def test_scan_for_sdks_smali_layout_emits_structured_evidence(tmp_path, smali_root):
    unpack_dir = tmp_path / "unpacked"
    sdk_dir = (
        unpack_dir
        / smali_root
        / "com"
        / "bytedance"
        / "sdk"
        / "openadsdk"
    )
    sdk_dir.mkdir(parents=True)

    hits = _pangle_hits(unpack_dir)

    assert len(hits) == 1
    evidence = hits[0].get("evidence")
    assert isinstance(evidence, list)
    assert evidence

    for item in evidence:
        assert {"source_type", "relative_path", "detector"} <= item.keys()
        assert isinstance(item["source_type"], str) and item["source_type"]
        assert isinstance(item["detector"], str) and item["detector"]
        assert isinstance(item["relative_path"], str) and item["relative_path"]
        assert not Path(item["relative_path"]).is_absolute()
        assert str(tmp_path) not in item["relative_path"]
