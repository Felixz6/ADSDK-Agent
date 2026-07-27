from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Iterable
import zipfile


PathInput = str | os.PathLike[str]


class ApkPathValidationError(ValueError):
    """A validation error with a stable machine-readable error code."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(message)


class ApkPathValidator:
    """Validate a local APK before it is passed to any external tool."""

    _WINDOWS_DEVICE_PREFIXES = ("\\\\?\\", "\\\\.\\", "\\??\\")

    def __init__(
        self,
        allowed_roots: Iterable[PathInput] | None,
        max_size_bytes: int,
        allow_unc: bool = False,
    ) -> None:
        if isinstance(max_size_bytes, bool) or not isinstance(max_size_bytes, int):
            raise TypeError("max_size_bytes must be an integer")
        if max_size_bytes <= 0:
            raise ValueError("max_size_bytes must be greater than zero")

        self.max_size_bytes = max_size_bytes
        self.allow_unc = allow_unc
        self.allowed_roots = self._normalize_allowed_roots(allowed_roots)

    @staticmethod
    def _normalize_allowed_roots(
        allowed_roots: Iterable[PathInput] | None,
    ) -> tuple[Path, ...] | None:
        if allowed_roots is None:
            return None

        normalized: list[Path] = []
        for raw_root in allowed_roots:
            try:
                root = Path(raw_root)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"invalid allowed root: {raw_root!r}") from exc
            if not root.is_absolute():
                raise ValueError(f"allowed root must be absolute: {raw_root!r}")
            normalized.append(root.resolve(strict=False))

        if not normalized:
            raise ValueError("allowed_roots must contain at least one root or be None")
        return tuple(normalized)

    @classmethod
    def _classify_windows_special_path(cls, value: str) -> str | None:
        normalized = value.replace("/", "\\")
        if normalized.startswith(cls._WINDOWS_DEVICE_PREFIXES):
            return "device"
        if normalized.startswith("\\\\"):
            return "unc"
        return None

    @staticmethod
    def _is_within(candidate: Path, root: Path) -> bool:
        return candidate == root or candidate.is_relative_to(root)

    def validate(self, value: PathInput) -> Path:
        if isinstance(value, str):
            raw_value = value
        else:
            try:
                raw_value = os.fspath(value)
            except TypeError as exc:
                raise ApkPathValidationError(
                    "invalid_path",
                    "APK path must be a string or path-like value.",
                ) from exc

        if not isinstance(raw_value, str) or not raw_value.strip():
            raise ApkPathValidationError("empty_path", "APK path is empty.")

        windows_path_kind = self._classify_windows_special_path(raw_value)
        if windows_path_kind == "device":
            raise ApkPathValidationError(
                "device_path_not_allowed",
                "Windows device and extended-length paths are not accepted.",
            )
        if windows_path_kind == "unc" and not self.allow_unc:
            raise ApkPathValidationError(
                "unc_path_not_allowed",
                "UNC paths are not accepted.",
            )

        try:
            candidate = Path(raw_value)
        except (TypeError, ValueError, OSError) as exc:
            raise ApkPathValidationError(
                "invalid_path",
                "APK path has invalid syntax.",
            ) from exc

        if not candidate.is_absolute():
            raise ApkPathValidationError(
                "relative_path_not_allowed",
                "APK path must be absolute.",
            )

        try:
            resolved = candidate.resolve(strict=True)
        except FileNotFoundError as exc:
            raise ApkPathValidationError(
                "path_not_found",
                f"APK does not exist: {candidate}",
            ) from exc
        except (OSError, RuntimeError) as exc:
            raise ApkPathValidationError(
                "path_resolution_failed",
                f"APK path could not be resolved: {candidate}",
            ) from exc

        if self.allowed_roots is not None and not any(
            self._is_within(resolved, root) for root in self.allowed_roots
        ):
            raise ApkPathValidationError(
                "outside_allowed_roots",
                f"APK is outside the configured allowed roots: {resolved}",
            )

        if not resolved.is_file():
            raise ApkPathValidationError(
                "not_a_file",
                f"APK path is not a regular file: {resolved}",
            )

        if resolved.suffix.lower() != ".apk":
            raise ApkPathValidationError(
                "invalid_extension",
                f"APK path must use the .apk extension: {resolved}",
            )

        try:
            size_bytes = resolved.stat().st_size
        except OSError as exc:
            raise ApkPathValidationError(
                "file_stat_failed",
                f"APK size could not be read: {resolved}",
            ) from exc
        if size_bytes > self.max_size_bytes:
            raise ApkPathValidationError(
                "file_too_large",
                (
                    f"APK size {size_bytes} bytes exceeds the configured "
                    f"limit of {self.max_size_bytes} bytes."
                ),
            )

        try:
            valid_zip = zipfile.is_zipfile(resolved)
        except OSError as exc:
            raise ApkPathValidationError(
                "apk_read_failed",
                f"APK could not be read: {resolved}",
            ) from exc
        if not valid_zip:
            raise ApkPathValidationError(
                "invalid_apk_zip",
                f"APK is not a valid ZIP archive: {resolved}",
            )

        return resolved


def sha256_file(path: PathInput, *, chunk_size: int = 1024 * 1024) -> str:
    """Return the lowercase SHA-256 digest of a regular file."""

    if isinstance(chunk_size, bool) or not isinstance(chunk_size, int):
        raise TypeError("chunk_size must be an integer")
    if chunk_size <= 0:
        raise ValueError("chunk_size must be greater than zero")

    file_path = Path(path)
    if not file_path.is_file():
        raise FileNotFoundError(f"not a regular file: {file_path}")

    digest = hashlib.sha256()
    with file_path.open("rb") as source:
        while chunk := source.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()
