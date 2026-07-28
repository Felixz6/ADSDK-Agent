from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import threading
import time
from typing import Any, Callable
from uuid import uuid4

from app.core.artifacts import atomic_write_json


CACHE_FORMAT_VERSION = "static-unpack-v1"
Unpacker = Callable[[str, str], dict[str, Any]]

_RETRY_ATTEMPTS = 5
_RETRY_DELAY_SECONDS = 0.1

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


def _retry_delay(attempt: int) -> None:
    """Apply a short bounded backoff for transient Windows file locks."""
    time.sleep(_RETRY_DELAY_SECONDS * (attempt + 1))


def _remove_tree_with_retries(
    path: Path,
    *,
    error_code: str,
    attempts: int = _RETRY_ATTEMPTS,
) -> None:
    """Remove a directory without silently swallowing transient failures."""
    last_error: OSError | None = None

    for attempt in range(attempts):
        if not path.exists():
            return

        try:
            shutil.rmtree(path)
        except OSError as exc:
            last_error = exc
        else:
            if not path.exists():
                return

        if attempt < attempts - 1:
            _retry_delay(attempt)

    raise StaticUnpackCacheError(
        error_code,
        f"unable to remove static unpack cache directory: {path}",
        {
            "path": str(path),
            "attempts": attempts,
            "os_error": str(last_error) if last_error else None,
        },
    ) from last_error


def _cleanup_tree_best_effort(path: Path) -> None:
    """Clean temporary artifacts without hiding the primary failure."""
    try:
        _remove_tree_with_retries(
            path,
            error_code="apk_cache_cleanup_failed",
        )
    except StaticUnpackCacheError:
        # Temporary cleanup failure is diagnostic-only here. The original
        # build/publish exception must remain the exception seen by callers.
        pass


def _publish_cache_with_retries(
    temporary_dir: Path,
    cache_dir: Path,
    *,
    apk_sha256: str,
    apktool_version: str,
    attempts: int = _RETRY_ATTEMPTS,
) -> None:
    """Publish a completed cache entry, tolerating short Windows locks."""
    last_error: OSError | None = None

    for attempt in range(attempts):
        try:
            os.replace(temporary_dir, cache_dir)
            return
        except OSError as exc:
            # A different process may have published the same cache key first.
            # Adopt it only after validating the complete metadata and manifest.
            if _metadata_valid(
                cache_dir,
                apk_sha256=apk_sha256,
                apktool_version=apktool_version,
            ):
                _cleanup_tree_best_effort(temporary_dir)
                return

            last_error = exc
            if attempt < attempts - 1:
                _retry_delay(attempt)

    raise StaticUnpackCacheError(
        "apk_cache_publish_failed",
        f"unable to publish static unpack cache: {cache_dir}",
        {
            "temporary_dir": str(temporary_dir),
            "cache_dir": str(cache_dir),
            "attempts": attempts,
            "os_error": str(last_error) if last_error else None,
        },
    ) from last_error


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
            _remove_tree_with_retries(
                cache_dir,
                error_code="apk_cache_invalidation_failed",
            )

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

            _publish_cache_with_retries(
                temporary_dir,
                cache_dir,
                apk_sha256=normalized_sha256,
                apktool_version=apktool_version,
            )

            return StaticUnpackCacheResult(
                unpacked_dir=cache_dir / "unpacked",
                cache_hit=False,
                cache_key=normalized_sha256,
                apktool_version=apktool_version,
            )
        except BaseException:
            _cleanup_tree_best_effort(temporary_dir)
            raise
