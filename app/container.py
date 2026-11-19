"""Service container and dependency wiring for ADSDK Agent."""

from __future__ import annotations

import time
from pathlib import Path

from app.ai.settings_service import AISettingsService
from app.ai.settings_store import AISettingsStore
from app.comparisons import ComparisonService
from app.config import (
    FRIDA_SERVER_HANDSHAKE_TIMEOUT_SECONDS,
    FRIDA_SERVER_LOCAL_PATH,
    FRIDA_SERVER_MANAGEMENT_ENABLED,
    FRIDA_SERVER_REMOTE_PATH,
    FRIDA_SERVER_START_TIMEOUT_SECONDS,
    M7A_LEASE_STALE_SECONDS,
    STATIC_UNPACK_CACHE_DIR,
    TASK_DATABASE_PATH,
)
from app.frida import FridaDiagnosticsService, FridaServerManager
from app.orchestration.consent_checkpoint import ConsentCheckpointService
from app.orchestration.device_lease import LeaseRegistry
from app.repositories import TaskRepository
from app.repositories.task_repository import utc_now as task_utc_now
from app.services import TaskService
from app.services.application_name_service import repair_historical_application_names

project_root = Path(__file__).resolve().parent.parent

frida_diagnostics_service = FridaDiagnosticsService(
    project_root=project_root,
    server_remote_path=FRIDA_SERVER_REMOTE_PATH,
    management_enabled=FRIDA_SERVER_MANAGEMENT_ENABLED,
)

frida_server_manager = FridaServerManager(
    enabled=FRIDA_SERVER_MANAGEMENT_ENABLED,
    local_path=FRIDA_SERVER_LOCAL_PATH,
    remote_path=FRIDA_SERVER_REMOTE_PATH,
    start_timeout_seconds=FRIDA_SERVER_START_TIMEOUT_SECONDS,
    handshake_timeout_seconds=FRIDA_SERVER_HANDSHAKE_TIMEOUT_SECONDS,
)

task_repository = TaskRepository(TASK_DATABASE_PATH)
task_service = TaskService(task_repository)
repair_historical_application_names(
    task_repository,
    static_unpack_cache_dir=STATIC_UNPACK_CACHE_DIR,
)
comparison_service = ComparisonService(task_repository)
task_service.recover()

ai_settings_store = AISettingsStore()
ai_settings_service = AISettingsService(ai_settings_store)

consent_checkpoint_service = ConsentCheckpointService(clock=task_utc_now)
device_lease_registry = LeaseRegistry(
    clock=time.monotonic,
    stale_after_seconds=M7A_LEASE_STALE_SECONDS,
)

__all__ = [
    "ai_settings_service",
    "ai_settings_store",
    "comparison_service",
    "consent_checkpoint_service",
    "device_lease_registry",
    "frida_diagnostics_service",
    "frida_server_manager",
    "task_repository",
    "task_service",
]
