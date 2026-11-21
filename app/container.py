"""Service container and dependency wiring for ADSDK Agent."""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.ai.settings_service import AISettingsService
from app.ai.settings_store import AISettingsStore
from app.comparisons import ComparisonService
from app.config import (
    DEVICE_LEASE_STALE_SECONDS,
    FRIDA_SERVER_HANDSHAKE_TIMEOUT_SECONDS,
    FRIDA_SERVER_LOCAL_PATH,
    FRIDA_SERVER_MANAGEMENT_ENABLED,
    FRIDA_SERVER_REMOTE_PATH,
    FRIDA_SERVER_START_TIMEOUT_SECONDS,
    TASK_DATABASE_PATH,
)
from app.frida import FridaDiagnosticsService, FridaServerManager
from app.frida.frida_session import FridaSession
from app.orchestration.consent_checkpoint import ConsentCheckpointService
from app.orchestration.device_lease import LeaseRegistry
from app.repositories import TaskRepository
from app.repositories.task_repository import utc_now as task_utc_now
from app.services import TaskService
from app.traffic.mitm_session import MitmSession

project_root = Path(__file__).resolve().parent.parent


def default_frida_session_factory(*args: Any, **kwargs: Any) -> Any:
    return FridaSession(*args, **kwargs)


default_frida_session_factory.is_real = True  # type: ignore[attr-defined]


def default_mitm_session_factory(*args: Any, **kwargs: Any) -> Any:
    return MitmSession(*args, **kwargs)


@dataclass
class Container:
    """Dependency container holding instantiated services with zero import-time IO."""

    task_repository: TaskRepository
    task_service: TaskService
    comparison_service: ComparisonService
    ai_settings_store: AISettingsStore
    ai_settings_service: AISettingsService
    consent_checkpoint_service: ConsentCheckpointService
    device_lease_registry: LeaseRegistry
    frida_diagnostics_service: FridaDiagnosticsService
    frida_server_manager: FridaServerManager
    frida_session_factory: Any = default_frida_session_factory
    mitm_session_factory: Any = default_mitm_session_factory
    frida_real_device: bool = True


def _get_setting(settings: Any, key: str, default: Any) -> Any:
    if settings is None:
        return default
    if isinstance(settings, dict):
        return settings.get(key, default)
    return getattr(settings, key, default)


def build_container(settings: Any = None) -> Container:
    """Build and wire application services without executing database or disk IO."""
    db_path = _get_setting(settings, "task_database_path", TASK_DATABASE_PATH)
    ai_settings_path = _get_setting(settings, "ai_settings_path", None)
    secret_store = _get_setting(settings, "secret_store", None)
    stale_seconds = _get_setting(settings, "device_lease_stale_seconds", DEVICE_LEASE_STALE_SECONDS)

    repository = TaskRepository(db_path)
    service = TaskService(repository)
    comparison = ComparisonService(repository)
    ai_store = AISettingsStore(
        settings_path=ai_settings_path,
        secret_store=secret_store,
    )
    ai_service = AISettingsService(ai_store)
    consent = ConsentCheckpointService(clock=task_utc_now)
    lease_registry = LeaseRegistry(
        clock=time.monotonic,
        stale_after_seconds=stale_seconds,
    )
    diagnostics = FridaDiagnosticsService(
        project_root=project_root,
        server_remote_path=FRIDA_SERVER_REMOTE_PATH,
        management_enabled=FRIDA_SERVER_MANAGEMENT_ENABLED,
    )
    manager = FridaServerManager(
        enabled=FRIDA_SERVER_MANAGEMENT_ENABLED,
        local_path=FRIDA_SERVER_LOCAL_PATH,
        remote_path=FRIDA_SERVER_REMOTE_PATH,
        start_timeout_seconds=FRIDA_SERVER_START_TIMEOUT_SECONDS,
        handshake_timeout_seconds=FRIDA_SERVER_HANDSHAKE_TIMEOUT_SECONDS,
    )

    frida_real = _get_setting(settings, "frida_real_device", True)

    container = Container(
        task_repository=repository,
        task_service=service,
        comparison_service=comparison,
        ai_settings_store=ai_store,
        ai_settings_service=ai_service,
        consent_checkpoint_service=consent,
        device_lease_registry=lease_registry,
        frida_diagnostics_service=diagnostics,
        frida_server_manager=manager,
        frida_session_factory=default_frida_session_factory,
        mitm_session_factory=default_mitm_session_factory,
        frida_real_device=frida_real,
    )

    from functools import partial

    from app.pipelines.task_runner import run_persisted_task

    service.set_runner(partial(run_persisted_task, container=container))
    return container


__all__ = [
    "Container",
    "build_container",
    "default_frida_session_factory",
    "default_mitm_session_factory",
]
