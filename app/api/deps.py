"""FastAPI dependency providers backed by the request application container."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from starlette.requests import HTTPConnection

if TYPE_CHECKING:
    from app.ai.settings_service import AISettingsService
    from app.comparisons import ComparisonService
    from app.container import Container
    from app.frida import FridaDiagnosticsService, FridaServerManager
    from app.orchestration.consent_checkpoint import ConsentCheckpointService
    from app.orchestration.device_lease import LeaseRegistry
    from app.repositories import TaskRepository
    from app.services import TaskService


def _get_container(connection: HTTPConnection | None = None) -> Container:
    if connection is not None:
        container = getattr(connection.app.state, "container", None)
        if container is not None:
            return container
    from app.container import build_container

    return build_container()


def get_task_repository(connection: HTTPConnection = None) -> TaskRepository:  # type: ignore[assignment]
    return _get_container(connection).task_repository


def get_task_service(connection: HTTPConnection = None) -> TaskService:  # type: ignore[assignment]
    return _get_container(connection).task_service


def get_comparison_service(connection: HTTPConnection = None) -> ComparisonService:  # type: ignore[assignment]
    return _get_container(connection).comparison_service


def get_ai_settings_service(connection: HTTPConnection = None) -> AISettingsService:  # type: ignore[assignment]
    return _get_container(connection).ai_settings_service


def get_consent_checkpoint_service(
    connection: HTTPConnection = None,  # type: ignore[assignment]
) -> ConsentCheckpointService:
    return _get_container(connection).consent_checkpoint_service


def get_device_lease_registry(connection: HTTPConnection = None) -> LeaseRegistry:  # type: ignore[assignment]
    return _get_container(connection).device_lease_registry


def get_frida_server_manager(connection: HTTPConnection = None) -> FridaServerManager:  # type: ignore[assignment]
    return _get_container(connection).frida_server_manager


def get_frida_diagnostics_service(
    connection: HTTPConnection = None,  # type: ignore[assignment]
) -> FridaDiagnosticsService:
    return _get_container(connection).frida_diagnostics_service


def get_frida_session_factory(connection: HTTPConnection = None) -> Any:  # type: ignore[assignment]
    return _get_container(connection).frida_session_factory


def get_mitm_session_factory(connection: HTTPConnection = None) -> Any:  # type: ignore[assignment]
    return _get_container(connection).mitm_session_factory


__all__ = [
    "get_ai_settings_service",
    "get_comparison_service",
    "get_consent_checkpoint_service",
    "get_device_lease_registry",
    "get_frida_diagnostics_service",
    "get_frida_server_manager",
    "get_frida_session_factory",
    "get_mitm_session_factory",
    "get_task_repository",
    "get_task_service",
]
