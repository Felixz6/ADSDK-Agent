"""FastAPI dependency providers."""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING, Any

from app import container

if TYPE_CHECKING:
    from app.ai.settings_service import AISettingsService
    from app.comparisons import ComparisonService
    from app.frida import FridaDiagnosticsService, FridaServerManager
    from app.orchestration.consent_checkpoint import ConsentCheckpointService
    from app.orchestration.device_lease import LeaseRegistry
    from app.repositories import TaskRepository
    from app.services import TaskService


def _get_container_or_main(attr: str, default: Any) -> Any:
    main = sys.modules.get("app.main")
    if main is not None and hasattr(main, attr):
        return getattr(main, attr)
    return default


def get_task_repository() -> TaskRepository:
    return _get_container_or_main("task_repository", container.task_repository)


def get_task_service() -> TaskService:
    return _get_container_or_main("task_service", container.task_service)


def get_comparison_service() -> ComparisonService:
    return _get_container_or_main("comparison_service", container.comparison_service)


def get_ai_settings_service() -> AISettingsService:
    return _get_container_or_main("ai_settings_service", container.ai_settings_service)


def get_consent_checkpoint_service() -> ConsentCheckpointService:
    return _get_container_or_main(
        "consent_checkpoint_service", container.consent_checkpoint_service
    )


def get_device_lease_registry() -> LeaseRegistry:
    return _get_container_or_main(
        "device_lease_registry", container.device_lease_registry
    )


def get_frida_server_manager() -> FridaServerManager:
    return _get_container_or_main(
        "frida_server_manager", container.frida_server_manager
    )


def get_frida_diagnostics_service() -> FridaDiagnosticsService:
    return _get_container_or_main(
        "frida_diagnostics_service", container.frida_diagnostics_service
    )


__all__ = [
    "get_ai_settings_service",
    "get_comparison_service",
    "get_consent_checkpoint_service",
    "get_device_lease_registry",
    "get_frida_diagnostics_service",
    "get_frida_server_manager",
    "get_task_repository",
    "get_task_service",
]
