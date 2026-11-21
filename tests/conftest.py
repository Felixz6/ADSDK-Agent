"""Pytest configuration and global test fixtures for ADSDK Agent."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI

from app.container import build_container
from app.main import create_app


def make_test_app(tmp_path: Path, **settings: Any) -> FastAPI:
    """Build a test FastAPI instance with an isolated SQLite database."""
    db_path = tmp_path / "test_tasks.db"
    merged_settings = {"task_database_path": db_path, **settings}
    container = build_container(settings=merged_settings)
    return create_app(container=container)


@pytest.fixture
def test_app(tmp_path: Path) -> FastAPI:
    """Provide a fresh FastAPI app instance backed by an isolated database."""
    return make_test_app(tmp_path)


@pytest.fixture(autouse=True)
def _reset_global_app_state():
    """Ensure global dependency overrides don't bleed across tests."""
    yield
    from app.main import app

    app.dependency_overrides.clear()
