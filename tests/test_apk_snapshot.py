from __future__ import annotations

import hashlib
import io
import os
from pathlib import Path
from typing import BinaryIO
import zipfile

import pytest

from app.core import apk_snapshot as snapshot_module
from app.core.apk_snapshot import ApkSnapshotError, create_apk_snapshot
from app.core.device import DeviceContext
from app import main as main_module
from app.tools import adb_runner, apk_unpack
from app.tools import utils as tools_utils


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _temporary_files(input_dir: Path) -> list[Path]:
    if not input_dir.exists():
        return []
    return [
        item
        for item in input_dir.iterdir()
        if item.name != "app.apk"
    ]


def test_snapshot_streams_to_fixed_run_path_and_returns_safe_report_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    content = (b"streaming-apk-payload-" * 32) + b"tail"
    source = tmp_path / "source" / "fixture.apk"
    source.parent.mkdir()
    source.write_bytes(content)
    run_dir = tmp_path / "output" / "runs" / "run-id"

    fsync_calls: list[int] = []
    replace_calls: list[tuple[Path, Path]] = []
    read_sizes: list[int] = []
    real_replace = os.replace

    class TrackingReader(io.BytesIO):
        def read(self, size: int = -1) -> bytes:
            read_sizes.append(size)
            return super().read(size)

    monkeypatch.setattr(
        snapshot_module,
        "_open_binary_source",
        lambda _: TrackingReader(content),
    )
    monkeypatch.setattr(
        snapshot_module.os,
        "fsync",
        lambda descriptor: fsync_calls.append(descriptor),
    )

    def record_replace(
        temporary: str | os.PathLike[str],
        destination: str | os.PathLike[str],
    ) -> None:
        temporary_path = Path(temporary)
        destination_path = Path(destination)
        assert temporary_path.exists()
        assert temporary_path.parent == destination_path.parent
        replace_calls.append((temporary_path, destination_path))
        real_replace(temporary, destination)

    monkeypatch.setattr(snapshot_module.os, "replace", record_replace)

    result = create_apk_snapshot(
        source,
        run_dir,
        expected_sha256=_sha256(content),
        max_size_bytes=len(content),
        chunk_size=17,
    )

    expected_path = run_dir / "input" / "app.apk"
    assert result.path == expected_path
    assert expected_path.read_bytes() == content
    assert result.sha256 == _sha256(content)
    assert result.size_bytes == len(content)
    assert result.relative_path == "input/app.apk"
    assert result.status == "success"
    assert result.source_display == "fixture.apk"
    assert result.to_report_dict() == {
        "source_path_display": "fixture.apk",
        "snapshot_relative_path": "input/app.apk",
        "snapshot_sha256": _sha256(content),
        "snapshot_size_bytes": len(content),
        "snapshot_status": "success",
    }
    assert str(source.resolve()) not in repr(result.to_report_dict())
    assert len(fsync_calls) == 1
    assert len(replace_calls) == 1
    assert replace_calls[0][1] == expected_path
    assert len(read_sizes) > 2
    assert set(read_sizes) == {17}
    assert _temporary_files(expected_path.parent) == []


def test_snapshot_supports_chinese_and_spaces_in_source_and_run_paths(
    tmp_path: Path,
) -> None:
    content = "中文 APK 快照".encode("utf-8") * 20
    source = tmp_path / "输入 目录" / "广告 示例.apk"
    source.parent.mkdir()
    source.write_bytes(content)
    run_dir = tmp_path / "输出 目录" / "runs" / "中文 run"

    result = create_apk_snapshot(
        source,
        run_dir,
        expected_sha256=_sha256(content),
        max_size_bytes=len(content) + 1,
        chunk_size=9,
    )

    assert result.path == run_dir / "input" / "app.apk"
    assert result.path.read_bytes() == content
    assert result.source_display == "广告 示例.apk"


def test_snapshot_enforces_maximum_during_streaming_and_cleans_partial_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    content = b"x" * 32
    streamed_content = b"x" * 65
    source = tmp_path / "growing.apk"
    source.write_bytes(content)
    run_dir = tmp_path / "run"

    monkeypatch.setattr(
        snapshot_module,
        "_open_binary_source",
        lambda _: io.BytesIO(streamed_content),
    )

    with pytest.raises(ApkSnapshotError) as exc_info:
        create_apk_snapshot(
            source,
            run_dir,
            expected_sha256=_sha256(content),
            max_size_bytes=64,
            chunk_size=8,
        )

    assert exc_info.value.code == "apk_snapshot_too_large"
    assert not (run_dir / "input" / "app.apk").exists()
    assert _temporary_files(run_dir / "input") == []


def test_source_change_during_copy_is_detected_and_published_snapshot_is_removed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = b"A" * 128
    changed = b"B" * 128
    source = tmp_path / "changing.apk"
    source.write_bytes(original)
    run_dir = tmp_path / "run"

    class MutatingReader(io.BytesIO):
        def __init__(self) -> None:
            super().__init__(original)
            self._mutated = False

        def read(self, size: int = -1) -> bytes:
            chunk = super().read(size)
            if chunk and not self._mutated:
                source.write_bytes(changed)
                self._mutated = True
            return chunk

    def open_mutating_source(_: Path) -> BinaryIO:
        return MutatingReader()

    monkeypatch.setattr(
        snapshot_module,
        "_open_binary_source",
        open_mutating_source,
    )

    with pytest.raises(ApkSnapshotError) as exc_info:
        create_apk_snapshot(
            source,
            run_dir,
            expected_sha256=_sha256(original),
            max_size_bytes=1024,
            chunk_size=16,
        )

    assert exc_info.value.code == "apk_snapshot_source_changed"
    assert not (run_dir / "input" / "app.apk").exists()
    assert _temporary_files(run_dir / "input") == []


def test_post_publish_hash_mismatch_is_detected_and_snapshot_is_removed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    content = b"verified-before-copy"
    source = tmp_path / "fixture.apk"
    source.write_bytes(content)
    run_dir = tmp_path / "run"
    expected_destination = run_dir / "input" / "app.apk"
    real_sha256_file = snapshot_module.sha256_file

    def corrupt_destination_digest(
        path: str | os.PathLike[str],
        *,
        chunk_size: int = 1024 * 1024,
    ) -> str:
        if Path(path) == expected_destination:
            return "0" * 64
        return real_sha256_file(path, chunk_size=chunk_size)

    monkeypatch.setattr(
        snapshot_module,
        "sha256_file",
        corrupt_destination_digest,
    )

    with pytest.raises(ApkSnapshotError) as exc_info:
        create_apk_snapshot(
            source,
            run_dir,
            expected_sha256=_sha256(content),
            max_size_bytes=1024,
        )

    assert exc_info.value.code == "apk_snapshot_hash_mismatch"
    assert not expected_destination.exists()
    assert _temporary_files(expected_destination.parent) == []


def test_copy_exception_leaves_no_formal_or_temporary_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    content = b"copy-failure"
    source = tmp_path / "fixture.apk"
    source.write_bytes(content)
    run_dir = tmp_path / "run"

    def fail_copy(
        source_stream: BinaryIO,
        output_stream: BinaryIO,
        *,
        max_size_bytes: int,
        chunk_size: int,
    ) -> tuple[str, int]:
        output_stream.write(source_stream.read(2))
        raise OSError("simulated copy failure")

    monkeypatch.setattr(snapshot_module, "_stream_copy", fail_copy)

    with pytest.raises(ApkSnapshotError) as exc_info:
        create_apk_snapshot(
            source,
            run_dir,
            expected_sha256=_sha256(content),
            max_size_bytes=1024,
        )

    assert exc_info.value.code == "apk_snapshot_io_error"
    assert "simulated copy failure" not in str(exc_info.value)
    assert not (run_dir / "input" / "app.apk").exists()
    assert _temporary_files(run_dir / "input") == []


def test_apktool_and_adb_commands_receive_snapshot_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    content = b"downstream-snapshot-only"
    source = tmp_path / "original.apk"
    source.write_bytes(content)
    run_dir = tmp_path / "run"
    snapshot = create_apk_snapshot(
        source,
        run_dir,
        expected_sha256=_sha256(content),
        max_size_bytes=1024,
    )
    commands: list[list[str]] = []

    def record_command(
        command: list[str],
        **_: object,
    ) -> dict[str, object]:
        commands.append(command)
        return {"returncode": 0, "stdout": "", "stderr": "", "cmd": command}

    monkeypatch.setattr(apk_unpack, "run_cmd", record_command)
    monkeypatch.setattr(adb_runner, "run_cmd", record_command)

    apk_unpack.unpack_apk(str(snapshot.path), str(run_dir / "unpacked"))
    adb_runner.install_apk(
        str(snapshot.path),
        DeviceContext(serial="emulator-5554"),
    )

    assert commands[0] == [
        "apktool",
        "d",
        "-f",
        str(snapshot.path),
        "-o",
        str(run_dir / "unpacked"),
    ]
    assert commands[1] == [
        "adb",
        "-s",
        "emulator-5554",
        "install",
        "-r",
        str(snapshot.path),
    ]
    assert str(source) not in commands[0]
    assert str(source) not in commands[1]


def test_prepare_run_rebinds_all_downstream_reads_to_verified_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "输入 目录" / "原始 应用.apk"
    source.parent.mkdir()
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"<manifest />")
        archive.writestr("classes.dex", b"dex\n035\x00")
    output_root = tmp_path / "output"

    monkeypatch.setattr(main_module, "OUTPUT_DIR", str(output_root))
    monkeypatch.setattr(
        main_module,
        "APK_ALLOWED_ROOTS",
        (tmp_path.resolve(),),
    )

    context, steps, failure = main_module._prepare_run(
        str(source),
        device_id=None,
    )

    assert failure is None
    assert context is not None
    assert context.apk_path == context.run_dir / "input" / "app.apk"
    assert context.apk_path.read_bytes() == source.read_bytes()
    assert context.apk_path != source.resolve()
    snapshot_step = next(step for step in steps if step.name == "apk_snapshot")
    assert snapshot_step.status.value == "success"
    assert snapshot_step.details["snapshot_relative_path"] == "input/app.apk"
    assert str(source.resolve()) not in repr(snapshot_step.details)


def test_resolve_spawn_argv_wraps_bat_and_cmd_via_cmd_exe(monkeypatch: pytest.MonkeyPatch) -> None:
    """Regression: on Windows, a PATH-resolvable ``.bat``/``.cmd`` wrapper
    (e.g. ``apktool.bat``) cannot be launched by ``CreateProcess`` directly
    (``[WinError 2]``). ``_resolve_spawn_argv`` must prepend ``cmd.exe /c`` so
    the interpreter handles the script, preserve the rest of the argv, and NOT
    mutate the caller-visible ``cmd`` list.
    """
    bat_path = "C:/fake-path-on-PATH/apktool.bat"
    cmd_path = "C:/fake-path-on-PATH/wrapper.cmd"

    def fake_which(name: str):
        if name == "apktool.bat":
            return bat_path
        if name == "wrapper.cmd":
            return cmd_path
        return None

    monkeypatch.setattr(tools_utils.os, "name", "nt")
    monkeypatch.setattr(tools_utils.shutil, "which", fake_which)

    original = ["apktool.bat", "d", "-f", "in.apk", "-o", "out"]
    spawn_argv = tools_utils._resolve_spawn_argv(original)

    assert spawn_argv == ["cmd.exe", "/c", "apktool.bat", "d", "-f", "in.apk", "-o", "out"]
    assert spawn_argv is not original
    assert original == ["apktool.bat", "d", "-f", "in.apk", "-o", "out"]

    original_cmd = ["wrapper.cmd", "--flag", "x"]
    spawn_argv_cmd = tools_utils._resolve_spawn_argv(original_cmd)
    assert spawn_argv_cmd == ["cmd.exe", "/c", "wrapper.cmd", "--flag", "x"]
    assert original_cmd == ["wrapper.cmd", "--flag", "x"]


def test_resolve_spawn_argv_does_not_wrap_plain_exe_or_unresolved(monkeypatch: pytest.MonkeyPatch) -> None:
    """A real PE executable (``.exe``) or an unresolved head must pass through
    unchanged so we don't wrongly shim executables that ``CreateProcess`` can
    already launch, and we don't invent a wrapper for missing commands.
    """
    exe_path = "C:/fake-path-on-PATH/adb.exe"

    def fake_which(name: str):
        if name == "adb.exe":
            return exe_path
        return None

    monkeypatch.setattr(tools_utils.os, "name", "nt")
    monkeypatch.setattr(tools_utils.shutil, "which", fake_which)

    exe_cmd = ["adb.exe", "-s", "emulator-5554", "install", "-r", "x.apk"]
    assert tools_utils._resolve_spawn_argv(exe_cmd) == exe_cmd

    unresolved = ["nonexistent-tool", "arg"]
    assert tools_utils._resolve_spawn_argv(unresolved) == unresolved


def test_resolve_spawn_argv_passes_through_empty_and_non_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    """Empty argv and non-Windows platforms must return the input unchanged
    (the wrapper is a Windows-only remediation).
    """
    monkeypatch.setattr(tools_utils.os, "name", "posix")
    monkeypatch.setattr(tools_utils.shutil, "which", lambda name: None)

    assert tools_utils._resolve_spawn_argv([]) == []
    posix_cmd = ["apktool.bat", "d", "in.apk"]
    assert tools_utils._resolve_spawn_argv(posix_cmd) == posix_cmd
