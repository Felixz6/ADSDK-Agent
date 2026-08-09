"""M7A — full AI-analysis orchestration for a single real device.

This package layers the safety envelope around the existing deterministic
analysis tools and the M6A/M6C AI orchestrator. It owns none of the facts
(those come from deterministic tools) and only owns the *constrained* plan
selection, confirmation gates, resource ownership, failure recovery and state
restoration, and the final AI narrative.

Public surface (see ``app.orchestration.full_analysis_session`` for usage):

* :class:`DeviceSessionSnapshot`               — ``device-session-v1`` schema.
* :class:`ResourceOwnershipRegistry`           — external vs owned_by_run bookkeeping.
* :class:`CleanupManager`                       — try/finally state restore.
* :class:`ConsentCheckpointService`             — manual consent checkpoint.
* :class:`DeviceLease` / :class:`LeaseRegistry` — reclaimable device lease.
* :class:`FullAnalysisSession`                 — the state machine.
* :func:`build_full_analysis_plan`             — constrained plan builder.
* :func:`execute_full_analysis_plan`           — plan executor.
* :func:`verify_cleanup`                         — post-run cleanup verification.
* :func:`build_full_analysis_acceptance`       — acceptance record.

Every module forbids extra Pydantic fields, carries no secrets, and relies on
injectable clocks / ADB / Frida / mitm / AI so unit tests run without a real
device, ADB, Frida, mitmproxy, or DeepSeek connection.
"""

from __future__ import annotations

from .cleanup_manager import CleanupManager, CleanupOutcome, ResourceOwnershipRegistry
from .consent_checkpoint import (
    ConsentCheckpointRequest,
    ConsentCheckpointService,
    ConsentCheckpointState,
)
from .device_lease import DeviceLease, LeaseRegistry, LeaseState
from .device_session import (
    DEVICE_SESSION_SCHEMA_VERSION,
    DeviceSessionSnapshot,
    DeviceState,
    SnapshotProbe,
)
from app.ai.models import AIPlan
from .full_analysis_session import (
    FullAnalysisAcceptance,
    FullAnalysisSession,
    PlanValidationError,
    SessionEvent,
    SessionState,
    SessionTransition,
    build_default_plan,
    build_full_analysis_acceptance,
    build_full_analysis_plan,
    execute_full_analysis_plan,
    verify_cleanup,
)
from .production_session_effects import ProductionSessionEffects

__all__ = [
    "AIPlan",
    "CleanupManager",
    "CleanupOutcome",
    "ConsentCheckpointRequest",
    "ConsentCheckpointService",
    "ConsentCheckpointState",
    "DEVICE_SESSION_SCHEMA_VERSION",
    "DeviceLease",
    "DeviceSessionSnapshot",
    "DeviceState",
    "FullAnalysisAcceptance",
    "FullAnalysisSession",
    "LeaseRegistry",
    "LeaseState",
    "PlanValidationError",
    "ProductionSessionEffects",
    "ResourceOwnershipRegistry",
    "SessionEvent",
    "SessionState",
    "SessionTransition",
    "SnapshotProbe",
    "build_default_plan",
    "build_full_analysis_acceptance",
    "build_full_analysis_plan",
    "execute_full_analysis_plan",
    "verify_cleanup",
]
