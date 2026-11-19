"""FastAPI dependency providers."""

from __future__ import annotations

from typing import TYPE_CHECKING

from app import container

if TYPE_CHECKING:
    from app.ai.settings_service import AISettingsService
    from app.comparisons import ComparisonService
    from app.frida import FridaDiagnosticsService, FridaServerManager
    from app.orchestration.consent_checkpoint import ConsentCheckpointService
    from app.orchestration.device_lease import LeaseRegistry
    from app.repositories import TaskRepository
    from app.services import TaskService


def get_task_repository() -> TaskRepository:
    return container.task_repository


def get_task_service() -> TaskService:
    return container.task_service


def get_comparison_service() -> ComparisonService:
    return container.comparison_service


def get_ai_settings_service() -> AISettingsService:
    return container.ai_settings_service


def get_consent_checkpoint_service() -> ConsentCheckpointService:
    return container.consent_checkpoint_service


def get_device_lease_registry() -> LeaseRegistry:
    return container.device_lease_registry


def get_frida_server_manager() -> FridaServerManager:
    return container.frida_server_manager


def get_frida_diagnostics_service() -> FridaDiagnosticsService:
    return container.frida_diagnostics_service


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
