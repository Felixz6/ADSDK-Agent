from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import time

import pytest

from app.core.static_unpack_cache import (
    StaticUnpackCacheError,
    prepare_static_unpack,
)


def _snapshot(tmp_path: Path) -> Path:
    path = tmp_path / "input.apk"
    path.write_bytes(b"apk")
    return path


def _unpacker(counter: list[int], *, delay: float = 0):
    def unpack(_apk: str, output: str):
        counter.append(1)
        if delay:
            time.sleep(delay)
        target = Path(output)
        target.mkdir(parents=True)
        (target / "AndroidManifest.xml").write_text(
            "<manifest package='fixture'/>",
            encoding="utf-8",
        )
        return {"returncode": 0, "stdout": "", "stderr": ""}

    return unpack


def test_cold_then_hot_cache_are_consistent(tmp_path: Path):
    calls: list[int] = []
    arguments = {
        "snapshot_path": _snapshot(tmp_path),
        "apk_sha256": "a" * 64,
        "cache_root": tmp_path / "cache",
        "apktool_version": "2.11.1",
        "unpacker": _unpacker(calls),
    }
    cold = prepare_static_unpack(**arguments)
    hot = prepare_static_unpack(**arguments)
    assert cold.cache_hit is False
    assert hot.cache_hit is True
    assert hot.unpacked_dir == cold.unpacked_dir
    assert calls == [1]


def test_corrupt_cache_and_version_change_rebuild(tmp_path: Path):
    calls: list[int] = []
    snapshot = _snapshot(tmp_path)
    base = {
        "snapshot_path": snapshot,
        "apk_sha256": "b" * 64,
        "cache_root": tmp_path / "cache",
        "unpacker": _unpacker(calls),
    }
    first = prepare_static_unpack(apktool_version="2.11.1", **base)
    (first.unpacked_dir / "AndroidManifest.xml").unlink()
    rebuilt = prepare_static_unpack(apktool_version="2.11.1", **base)
    changed = prepare_static_unpack(apktool_version="2.12.0", **base)
    assert rebuilt.cache_hit is False
    assert changed.cache_hit is False
    assert len(calls) == 3


def test_same_sha_concurrent_build_uses_one_publisher(tmp_path: Path):
    calls: list[int] = []
    arguments = {
        "snapshot_path": _snapshot(tmp_path),
        "apk_sha256": "c" * 64,
        "cache_root": tmp_path / "cache",
        "apktool_version": "2.11.1",
        "unpacker": _unpacker(calls, delay=0.05),
    }
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: prepare_static_unpack(**arguments), range(2)))
    assert sorted(item.cache_hit for item in results) == [False, True]
    assert calls == [1]


def test_apktool_timeout_is_classified_and_temporary_cache_is_removed(tmp_path: Path):
    def timed_out(_apk: str, _output: str):
        return {
            "returncode": -1,
            "error_code": "command_timeout",
            "stderr": "timed out",
        }

    with pytest.raises(StaticUnpackCacheError) as captured:
        prepare_static_unpack(
            snapshot_path=_snapshot(tmp_path),
            apk_sha256="d" * 64,
            cache_root=tmp_path / "cache",
            apktool_version="2.11.1",
            unpacker=timed_out,
        )
    assert captured.value.code == "apktool_timeout"
    assert not any((tmp_path / "cache").glob(".*.tmp"))
