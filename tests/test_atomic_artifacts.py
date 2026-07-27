from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

from app.core import artifacts as artifacts_module
from app.core.artifacts import atomic_write_json, atomic_write_text


def test_atomic_write_text_creates_parent_and_writes_utf8(tmp_path: Path) -> None:
    target = tmp_path / "nested" / "report.md"
    content = "# 分析报告\n\n包含 UTF-8 文本。\n"

    atomic_write_text(target, content)

    assert target.read_text(encoding="utf-8") == content
    assert set(target.parent.iterdir()) == {target}


def test_atomic_write_text_completely_replaces_existing_content(tmp_path: Path) -> None:
    target = tmp_path / "report.md"
    target.write_text("old-content-" * 100, encoding="utf-8")

    atomic_write_text(target, "# new\n")

    assert target.read_text(encoding="utf-8") == "# new\n"
    assert target.stat().st_size == len("# new\n".encode("utf-8"))


@pytest.mark.parametrize("artifact_kind", ["markdown", "json"])
def test_replace_failure_preserves_old_file_and_cleans_temporary_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    artifact_kind: str,
) -> None:
    suffix = ".md" if artifact_kind == "markdown" else ".json"
    target = tmp_path / f"report{suffix}"
    original = "old artifact remains byte-for-byte intact\n"
    target.write_text(original, encoding="utf-8")
    replace_calls: list[tuple[Path, Path]] = []

    def fail_replace(source: str | os.PathLike[str], destination: str | os.PathLike[str]) -> None:
        replace_calls.append((Path(source), Path(destination)))
        raise OSError("simulated os.replace failure")

    monkeypatch.setattr(artifacts_module.os, "replace", fail_replace)

    with pytest.raises(OSError, match="simulated os\\.replace failure"):
        if artifact_kind == "markdown":
            atomic_write_text(target, "# replacement\n")
        else:
            atomic_write_json(target, {"replacement": True})

    assert target.read_text(encoding="utf-8") == original
    assert len(replace_calls) == 1
    temporary_path, destination_path = replace_calls[0]
    assert destination_path == target
    assert temporary_path.parent.resolve() == target.parent.resolve()
    assert not temporary_path.exists()
    assert set(tmp_path.iterdir()) == {target}


@pytest.mark.parametrize(
    ("artifact_kind", "payload"),
    [
        ("markdown", "# 原子 Markdown\n"),
        ("json", {"schema_version": "1.0", "title": "广告分析"}),
    ],
)
def test_json_and_markdown_share_atomic_replace_guarantee(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    artifact_kind: str,
    payload: Any,
) -> None:
    suffix = ".md" if artifact_kind == "markdown" else ".json"
    target = tmp_path / f"artifact{suffix}"
    real_replace = os.replace
    replace_calls: list[tuple[Path, Path]] = []

    def record_replace(source: str | os.PathLike[str], destination: str | os.PathLike[str]) -> None:
        replace_calls.append((Path(source), Path(destination)))
        real_replace(source, destination)

    monkeypatch.setattr(artifacts_module.os, "replace", record_replace)

    if artifact_kind == "markdown":
        atomic_write_text(target, payload)
        assert target.read_text(encoding="utf-8") == payload
    else:
        atomic_write_json(target, payload)
        assert json.loads(target.read_text(encoding="utf-8")) == payload
        assert "广告分析" in target.read_text(encoding="utf-8")

    assert len(replace_calls) == 1
    temporary_path, destination_path = replace_calls[0]
    assert destination_path == target
    assert temporary_path.parent.resolve() == target.parent.resolve()
    assert not temporary_path.exists()
    assert set(tmp_path.iterdir()) == {target}
