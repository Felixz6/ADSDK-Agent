"""Tests for Container lifecycle, zero-IO import, and single-execution recover."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock

from fastapi.testclient import TestClient

from app.container import Container, build_container
from tests.conftest import make_test_app


def test_container_import_has_no_io(tmp_path: Path):
    """Verify importing app.container does not create database files or output dirs."""
    project_root = Path(__file__).resolve().parent.parent
    code = (
        f"import sys; sys.path.insert(0, r'{project_root}'); "
        "import app.container as c; "
        "print('IMPORTED_OK')"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=str(tmp_path),
        capture_output=True,
        text=True,
        check=True,
    )
    assert "IMPORTED_OK" in result.stdout
    # Confirm no db or state files were created in tmp_path
    created_files = list(tmp_path.rglob("*"))
    assert created_files == []


def test_build_container_constructs_pure_dataclass(tmp_path: Path):
    """build_container should return a populated Container dataclass without IO."""
    db_file = tmp_path / "custom.db"
    container = build_container(settings={"task_database_path": db_file})
    assert isinstance(container, Container)
    assert container.task_repository.database_path == db_file
    assert not db_file.exists()


def test_recover_called_only_once_during_lifespan(tmp_path: Path):
    """recover() must execute exactly once during application startup lifespan."""
    app = make_test_app(tmp_path)
    container = app.state.container

    recover_mock = MagicMock(return_value=0)
    container.task_service.recover = recover_mock

    assert recover_mock.call_count == 0

    with TestClient(app):
        # Lifespan startup has executed
        assert recover_mock.call_count == 1

    # On shutdown, recover is not called again
    assert recover_mock.call_count == 1
