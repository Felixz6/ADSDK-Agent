"""Frida reliability domain services.

The package intentionally keeps diagnostics, lifecycle ownership and execution
policy outside ``app.main`` so every layer can be tested without a real device.
"""

from .diagnostics import FridaDiagnosticsService
from .errors import DynamicErrorCode, legacy_error_code
from .execution_modes import (
    DynamicEvidenceQuality,
    DynamicModePolicy,
    ExecutionMode,
    ExecutionModeDecision,
    build_evidence_quality,
    select_execution_mode,
)
from .execution_session import PolicyFridaSession
from .models import (
    FridaDiagnosticsRequest,
    FridaDiagnosticsResponse,
    FridaServerActionRequest,
    FridaServerActionResponse,
)
from .server_manager import FridaServerManager

__all__ = [
    "DynamicErrorCode",
    "DynamicEvidenceQuality",
    "DynamicModePolicy",
    "ExecutionMode",
    "ExecutionModeDecision",
    "FridaDiagnosticsRequest",
    "FridaDiagnosticsResponse",
    "FridaDiagnosticsService",
    "FridaServerActionRequest",
    "FridaServerActionResponse",
    "FridaServerManager",
    "PolicyFridaSession",
    "build_evidence_quality",
    "legacy_error_code",
    "select_execution_mode",
]
