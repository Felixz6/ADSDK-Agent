"""Pytest configuration and global test fixtures for ADSDK Agent."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI

from app.ai import secret_store as secret_store_module
from app.ai.secret_store import DPAPIError
from app.container import build_container
from app.main import create_app


def enable_test_secret_store_on_non_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    """Allow non-Windows CI test runs to exercise SecretStore round-trips via a test seam."""
    if secret_store_module._IS_WINDOWS:
        return

    prefix = b"TEST_SEALED:"

    def _fake_protect(data: bytes) -> bytes:
        return prefix + data[::-1]

    def _fake_unprotect(data: bytes) -> bytes:
        if not data.startswith(prefix):
            raise DPAPIError("dpapi_unprotect_failed", "corrupted test secret blob")
        return data[len(prefix) :][::-1]

    monkeypatch.setattr(secret_store_module, "_dpapi_available", lambda: True)
    monkeypatch.setattr(secret_store_module, "_protect", _fake_protect)
    monkeypatch.setattr(secret_store_module, "_unprotect", _fake_unprotect)


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
