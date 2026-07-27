"""Create an immutable, run-scoped APK input snapshot.

The path validator and initial SHA-256 check happen before a run is created.
This module closes the remaining time-of-check/time-of-use gap: external tools
receive only the atomically published snapshot whose bytes were checked against
that earlier digest.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import tempfile
from typing import Any, BinaryIO

from .paths import PathInput, sha256_file


DEFAULT_CHUNK_SIZE = 1024 * 1024
SNAPSHOT_RELATIVE_PATH = Path("input") / "app.apk"
_SHA256_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")


class ApkSnapshotError(RuntimeError):
    """APK snapshot failure with a stable machine-readable error code."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class ApkSnapshot:
    """Verified metadata for the fixed snapshot consumed by external tools."""

    path: Path
    relative_path: str
    sha256: str
    size_bytes: int
    source_display: str
    status: str = "success"

    def to_report_dict(self) -> dict[str, Any]:
        """Return report-safe metadata without the original absolute path."""

        return {
            "source_path_display": self.source_display,
            "snapshot_relative_path": self.relative_path,
            "snapshot_sha256": self.sha256,
            "snapshot_size_bytes": self.size_bytes,
            "snapshot_status": self.status,
        }


@dataclass(frozen=True, slots=True)
class _SourceFingerprint:
    device: int
    inode: int
    size_bytes: int
    modified_ns: int


def _validate_positive_integer(value: int, *, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an integer")
    if value <= 0:
        raise ValueError(f"{name} must be greater than zero")
    return value


def _normalize_expected_sha256(value: str) -> str:
    if not isinstance(value, str) or not _SHA256_PATTERN.fullmatch(value):
        raise ValueError(
            "expected_sha256 must contain exactly 64 hexadecimal characters"
        )
    return value.lower()


def _safe_source_display(source_path: Path) -> str:
    name = "".join(
        character
        if ord(character) >= 32 and ord(character) != 127
        else "_"
        for character in source_path.name
    ).strip()
    return name or "app.apk"


def _fingerprint_source(source_path: Path) -> _SourceFingerprint:
    try:
        stat_result = source_path.stat()
    except OSError as exc:
        raise ApkSnapshotError(
            "apk_snapshot_source_unavailable",
            "The validated APK source is no longer available.",
        ) from exc
    if not source_path.is_file():
        raise ApkSnapshotError(
            "apk_snapshot_source_unavailable",
            "The validated APK source is no longer a regular file.",
        )
    return _SourceFingerprint(
        device=int(stat_result.st_dev),
        inode=int(stat_result.st_ino),
        size_bytes=int(stat_result.st_size),
        modified_ns=int(stat_result.st_mtime_ns),
    )


def _open_binary_source(source_path: Path) -> BinaryIO:
    """Small I/O seam used by deterministic source-change tests."""

    return source_path.open("rb")


def _stream_copy(
    source_stream: BinaryIO,
    output_stream: BinaryIO,
    *,
    max_size_bytes: int,
    chunk_size: int,
) -> tuple[str, int]:
    """Copy in bounded chunks while calculating the digest of copied bytes."""

    digest = hashlib.sha256()
    total_bytes = 0
    while True:
        chunk = source_stream.read(chunk_size)
        if not chunk:
            break
        if not isinstance(chunk, bytes):
            raise OSError("binary APK source returned non-bytes data")
        total_bytes += len(chunk)
        if total_bytes > max_size_bytes:
            raise ApkSnapshotError(
                "apk_snapshot_too_large",
                "The APK exceeded the configured snapshot size limit.",
            )
        output_stream.write(chunk)
        digest.update(chunk)
    return digest.hexdigest(), total_bytes


def _unlink_quietly(path: Path) -> None:
    try:
        path.unlink(missing_ok=True)
    except OSError:
        # Keep the primary snapshot failure. A later run-directory cleanup can
        # remove a locked temporary file if the platform prevents unlink here.
        pass


def create_apk_snapshot(
    source_path: PathInput,
    run_dir: PathInput,
    *,
    expected_sha256: str,
    max_size_bytes: int,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> ApkSnapshot:
    """Stream, atomically publish, and verify ``input/app.apk`` for one run.

    ``expected_sha256`` must be the digest produced by the validation stage.
    The returned ``path`` is the only APK path that apktool, ADB, and later
    external tools should receive.
    """

    normalized_expected_sha256 = _normalize_expected_sha256(expected_sha256)
    normalized_max_size = _validate_positive_integer(
        max_size_bytes,
        name="max_size_bytes",
    )
    normalized_chunk_size = _validate_positive_integer(
        chunk_size,
        name="chunk_size",
    )

    try:
        resolved_source = Path(source_path).resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ApkSnapshotError(
            "apk_snapshot_source_unavailable",
            "The validated APK source is no longer available.",
        ) from exc
    if not resolved_source.is_file():
        raise ApkSnapshotError(
            "apk_snapshot_source_unavailable",
            "The validated APK source is no longer a regular file.",
        )

    resolved_run_dir = Path(run_dir).resolve(strict=False)
    destination = resolved_run_dir / SNAPSHOT_RELATIVE_PATH
    input_dir = destination.parent
    input_dir.mkdir(parents=True, exist_ok=True)

    before_copy = _fingerprint_source(resolved_source)
    if before_copy.size_bytes > normalized_max_size:
        raise ApkSnapshotError(
            "apk_snapshot_too_large",
            "The APK exceeded the configured snapshot size limit.",
        )

    descriptor = -1
    temporary_path: Path | None = None
    published = False
    try:
        descriptor, raw_temporary_path = tempfile.mkstemp(
            dir=input_dir,
            prefix=f".{destination.name}.",
            suffix=".tmp",
        )
        temporary_path = Path(raw_temporary_path)

        with _open_binary_source(resolved_source) as source_stream:
            with os.fdopen(descriptor, "wb") as output_stream:
                descriptor = -1
                copied_sha256, copied_size = _stream_copy(
                    source_stream,
                    output_stream,
                    max_size_bytes=normalized_max_size,
                    chunk_size=normalized_chunk_size,
                )
                output_stream.flush()
                os.fsync(output_stream.fileno())

        if copied_sha256 != normalized_expected_sha256:
            raise ApkSnapshotError(
                "apk_snapshot_source_changed",
                "The APK source changed after validation.",
            )

        os.replace(temporary_path, destination)
        published = True
        temporary_path = None

        snapshot_sha256 = sha256_file(
            destination,
            chunk_size=normalized_chunk_size,
        )
        if snapshot_sha256 != normalized_expected_sha256:
            raise ApkSnapshotError(
                "apk_snapshot_hash_mismatch",
                "The published APK snapshot failed SHA-256 verification.",
            )

        after_copy = _fingerprint_source(resolved_source)
        source_sha256_after_copy = sha256_file(
            resolved_source,
            chunk_size=normalized_chunk_size,
        )
        if (
            after_copy != before_copy
            or source_sha256_after_copy != normalized_expected_sha256
        ):
            raise ApkSnapshotError(
                "apk_snapshot_source_changed",
                "The APK source changed while the snapshot was being created.",
            )

        return ApkSnapshot(
            path=destination,
            relative_path=SNAPSHOT_RELATIVE_PATH.as_posix(),
            sha256=snapshot_sha256,
            size_bytes=copied_size,
            source_display=_safe_source_display(resolved_source),
        )
    except ApkSnapshotError:
        if published:
            _unlink_quietly(destination)
        raise
    except BaseException as exc:
        if published:
            _unlink_quietly(destination)
        raise ApkSnapshotError(
            "apk_snapshot_io_error",
            "The APK snapshot could not be created.",
        ) from exc
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if temporary_path is not None:
            _unlink_quietly(temporary_path)


__all__ = [
    "ApkSnapshot",
    "ApkSnapshotError",
    "DEFAULT_CHUNK_SIZE",
    "SNAPSHOT_RELATIVE_PATH",
    "create_apk_snapshot",
]
