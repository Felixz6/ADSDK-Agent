from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import threading
from typing import Any, Callable
from uuid import uuid4

from app.core.artifacts import atomic_write_json


CACHE_FORMAT_VERSION = "static-unpack-v1"
Unpacker = Callable[[str, str], dict[str, Any]]

_LOCKS_GUARD = threading.Lock()
_KEY_LOCKS: dict[str, threading.Lock] = {}


class StaticUnpackCacheError(RuntimeError):
    def __init__(self, code: str, message: str, result: dict[str, Any] | None = None):
        self.code = code
        self.result = result or {}
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class StaticUnpackCacheResult:
    unpacked_dir: Path
    cache_hit: bool
    cache_key: str
    apktool_version: str
    cache_format_version: str = CACHE_FORMAT_VERSION


def _key_lock(cache_key: str) -> threading.Lock:
    with _LOCKS_GUARD:
        return _KEY_LOCKS.setdefault(cache_key, threading.Lock())


def _metadata_valid(
    cache_dir: Path,
    *,
    apk_sha256: str,
    apktool_version: str,
) -> bool:
    metadata_path = cache_dir / "metadata.json"
    unpacked_dir = cache_dir / "unpacked"
    manifest_path = unpacked_dir / "AndroidManifest.xml"
    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return False
    return bool(
        metadata.get("cache_format_version") == CACHE_FORMAT_VERSION
        and metadata.get("apk_sha256") == apk_sha256
        and metadata.get("apktool_version") == apktool_version
        and unpacked_dir.is_dir()
        and manifest_path.is_file()
        and manifest_path.stat().st_size > 0
    )


def prepare_static_unpack(
    *,
    snapshot_path: Path,
    apk_sha256: str,
    cache_root: Path,
    apktool_version: str,
    unpacker: Unpacker,
) -> StaticUnpackCacheResult:
    """Return a verified cache entry, atomically building it on a miss."""
    normalized_sha256 = apk_sha256.strip().lower()
    cache_root = cache_root.resolve(strict=False)
    cache_dir = cache_root / normalized_sha256

    with _key_lock(normalized_sha256):
        if _metadata_valid(
            cache_dir,
            apk_sha256=normalized_sha256,
            apktool_version=apktool_version,
        ):
            return StaticUnpackCacheResult(
                unpacked_dir=cache_dir / "unpacked",
                cache_hit=True,
                cache_key=normalized_sha256,
                apktool_version=apktool_version,
            )

        if cache_dir.exists():
            shutil.rmtree(cache_dir, ignore_errors=True)
        cache_root.mkdir(parents=True, exist_ok=True)
        temporary_dir = cache_root / f".{normalized_sha256}.{uuid4().hex}.tmp"
        unpacked_dir = temporary_dir / "unpacked"
        temporary_dir.mkdir()
        try:
            result = unpacker(str(snapshot_path), str(unpacked_dir))
            if result.get("returncode") != 0:
                code = (
                    "apktool_timeout"
                    if result.get("error_code") == "command_timeout"
                    else "apk_unpack_failed"
                )
                raise StaticUnpackCacheError(
                    code,
                    result.get("stderr")
                    or result.get("stdout")
                    or "apktool failed",
                    result,
                )
            if not (unpacked_dir / "AndroidManifest.xml").is_file():
                raise StaticUnpackCacheError(
                    "apk_cache_invalid",
                    "apktool output did not contain AndroidManifest.xml",
                    result,
                )
            atomic_write_json(
                temporary_dir / "metadata.json",
                {
                    "cache_format_version": CACHE_FORMAT_VERSION,
                    "apk_sha256": normalized_sha256,
                    "apktool_version": apktool_version,
                    "created_at": datetime.now(timezone.utc)
                    .isoformat()
                    .replace("+00:00", "Z"),
                },
            )
            try:
                os.replace(temporary_dir, cache_dir)
            except FileExistsError:
                # Another publisher won a cross-request race. Only adopt it
                # after the same metadata and manifest validation.
                shutil.rmtree(temporary_dir, ignore_errors=True)
                if not _metadata_valid(
                    cache_dir,
                    apk_sha256=normalized_sha256,
                    apktool_version=apktool_version,
                ):
                    raise StaticUnpackCacheError(
                        "apk_cache_publish_failed",
                        "published cache entry failed validation",
                    )
            return StaticUnpackCacheResult(
                unpacked_dir=cache_dir / "unpacked",
                cache_hit=False,
                cache_key=normalized_sha256,
                apktool_version=apktool_version,
            )
        except BaseException:
            shutil.rmtree(temporary_dir, ignore_errors=True)
            raise
