from __future__ import annotations

from pathlib import Path
import zipfile

import pytest

from app.core.paths import ApkPathValidationError, ApkPathValidator


def _write_valid_apk(path: Path, payload: bytes = b"dex\n035\x00") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("AndroidManifest.xml", b"<manifest package='com.example.test' />")
        archive.writestr("classes.dex", payload)
    return path


def _validator(root: Path, *, max_size_bytes: int = 1024 * 1024) -> ApkPathValidator:
    return ApkPathValidator(
        allowed_roots=[root],
        max_size_bytes=max_size_bytes,
    )


def test_accepts_absolute_valid_zip_apk(tmp_path: Path) -> None:
    apk_path = _write_valid_apk(tmp_path / "sample.apk")

    validated = _validator(tmp_path).validate(apk_path)

    assert isinstance(validated, Path)
    assert validated == apk_path.resolve()
    assert validated.is_absolute()


@pytest.mark.parametrize(
    "invalid_kind",
    ["missing", "directory", "wrong_extension", "invalid_zip"],
)
def test_rejects_missing_directory_non_apk_and_fake_apk(
    tmp_path: Path,
    invalid_kind: str,
) -> None:
    if invalid_kind == "missing":
        candidate = tmp_path / "missing.apk"
    elif invalid_kind == "directory":
        candidate = tmp_path / "directory.apk"
        candidate.mkdir()
    elif invalid_kind == "wrong_extension":
        candidate = _write_valid_apk(tmp_path / "sample.zip")
    else:
        candidate = tmp_path / "fake.apk"
        candidate.write_bytes(b"PK\x03\x04this-is-not-a-valid-zip")

    with pytest.raises(ApkPathValidationError):
        _validator(tmp_path).validate(candidate)


def test_rejects_apk_larger_than_configured_limit(tmp_path: Path) -> None:
    apk_path = _write_valid_apk(tmp_path / "large.apk", payload=b"x" * 4096)
    limit = apk_path.stat().st_size - 1

    with pytest.raises(ApkPathValidationError):
        _validator(tmp_path, max_size_bytes=limit).validate(apk_path)


def test_rejects_relative_path_even_when_file_exists(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _write_valid_apk(tmp_path / "relative.apk")
    monkeypatch.chdir(tmp_path)

    with pytest.raises(ApkPathValidationError):
        _validator(tmp_path).validate(Path("relative.apk"))


def test_rejects_apk_outside_allowed_roots(tmp_path: Path) -> None:
    allowed_root = tmp_path / "allowed"
    allowed_root.mkdir()
    outside_apk = _write_valid_apk(tmp_path / "outside" / "sample.apk")

    with pytest.raises(ApkPathValidationError):
        _validator(allowed_root).validate(outside_apk)


def test_no_root_restriction_allows_an_absolute_apk(tmp_path: Path) -> None:
    apk_path = _write_valid_apk(tmp_path / "outside" / "sample.apk")
    validator = ApkPathValidator(
        allowed_roots=None,
        max_size_bytes=1024 * 1024,
    )

    assert validator.validate(apk_path) == apk_path.resolve()


@pytest.mark.parametrize(
    "windows_special_path",
    [
        r"\\server\share\sample.apk",
        r"\\?\C:\sample.apk",
        r"\\?\UNC\server\share\sample.apk",
        r"\\.\C:\sample.apk",
    ],
)
def test_rejects_unc_and_windows_device_paths_by_syntax_only(
    windows_special_path: str,
) -> None:
    validator = ApkPathValidator(
        allowed_roots=None,
        max_size_bytes=1024 * 1024,
    )

    with pytest.raises(ApkPathValidationError):
        validator.validate(windows_special_path)


def test_accepts_spaces_and_chinese_characters_in_path(tmp_path: Path) -> None:
    apk_path = _write_valid_apk(tmp_path / "包含 空格" / "广告 测试.apk")

    validated = _validator(tmp_path).validate(str(apk_path))

    assert validated == apk_path.resolve()

