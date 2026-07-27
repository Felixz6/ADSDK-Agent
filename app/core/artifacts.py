"""Atomic helpers for writing analysis artifacts.

Each helper writes to a uniquely named temporary file in the destination
directory, flushes it, and publishes it with :func:`os.replace`.  Keeping the
temporary file on the same filesystem is important because it preserves the
atomic replacement guarantee on Windows.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any

PathLike = str | os.PathLike[str]


def _prepare_destination(path: PathLike) -> Path:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    return destination


def _temporary_path(destination: Path) -> Path:
    descriptor, raw_path = tempfile.mkstemp(
        dir=destination.parent,
        prefix=f".{destination.name}.",
        suffix=".tmp",
    )
    os.close(descriptor)
    return Path(raw_path)


def _publish_temporary(temporary: Path, destination: Path) -> Path:
    try:
        os.replace(temporary, destination)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    return destination


def atomic_write_bytes(
    path: PathLike,
    content: bytes | bytearray | memoryview,
) -> Path:
    """Atomically replace *path* with binary *content*."""

    destination = _prepare_destination(path)
    temporary = _temporary_path(destination)
    try:
        with temporary.open("wb") as stream:
            stream.write(bytes(content))
            stream.flush()
            os.fsync(stream.fileno())
        return _publish_temporary(temporary, destination)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def atomic_write_text(
    path: PathLike,
    content: str,
    *,
    encoding: str = "utf-8",
) -> Path:
    """Atomically replace *path* with text encoded as UTF-8 by default."""

    if not isinstance(content, str):
        raise TypeError("content must be str")
    destination = _prepare_destination(path)
    temporary = _temporary_path(destination)
    try:
        with temporary.open("w", encoding=encoding, newline="") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        return _publish_temporary(temporary, destination)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def atomic_write_json(
    path: PathLike,
    payload: Any,
    *,
    ensure_ascii: bool = False,
    indent: int | None = 2,
    sort_keys: bool = False,
) -> Path:
    """Serialize *payload* and atomically replace a JSON artifact."""

    text = json.dumps(
        payload,
        ensure_ascii=ensure_ascii,
        indent=indent,
        sort_keys=sort_keys,
    )
    if indent is not None:
        text += "\n"
    return atomic_write_text(path, text)


def atomic_copy(source: PathLike, destination: PathLike) -> Path:
    """Copy a file and atomically publish it at *destination*."""

    source_path = Path(source)
    if not source_path.is_file():
        raise FileNotFoundError(f"source artifact is not a file: {source_path}")

    destination_path = _prepare_destination(destination)
    temporary = _temporary_path(destination_path)
    try:
        with source_path.open("rb") as source_stream, temporary.open("wb") as output:
            shutil.copyfileobj(source_stream, output)
            output.flush()
            os.fsync(output.fileno())
        return _publish_temporary(temporary, destination_path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
