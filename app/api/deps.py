"""FastAPI dependency providers backed by the request application container."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from fastapi import Request
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


def get_container(request: Request) -> Container:
    return _get_container(request)


def get_task_repository(request: Request) -> TaskRepository:
    return _get_container(request).task_repository


def get_task_service(connection: HTTPConnection) -> TaskService:
    return _get_container(connection).task_service


def get_comparison_service(request: Request) -> ComparisonService:
    return _get_container(request).comparison_service


def get_ai_settings_service(request: Request) -> AISettingsService:
    return _get_container(request).ai_settings_service


def get_consent_checkpoint_service(
    request: Request,
) -> ConsentCheckpointService:
    return _get_container(request).consent_checkpoint_service


def get_device_lease_registry(request: Request) -> LeaseRegistry:
    return _get_container(request).device_lease_registry


def get_frida_server_manager(request: Request) -> FridaServerManager:
    return _get_container(request).frida_server_manager


def get_frida_diagnostics_service(
    request: Request,
) -> FridaDiagnosticsService:
    return _get_container(request).frida_diagnostics_service


def get_frida_session_factory(request: Request) -> Any:
    return _get_container(request).frida_session_factory


def get_mitm_session_factory(request: Request) -> Any:
    return _get_container(request).mitm_session_factory


__all__ = [
    "get_ai_settings_service",
    "get_comparison_service",
    "get_consent_checkpoint_service",
    "get_container",
    "get_device_lease_registry",
    "get_frida_diagnostics_service",
    "get_frida_server_manager",
    "get_frida_session_factory",
    "get_mitm_session_factory",
    "get_task_repository",
    "get_task_service",
]
