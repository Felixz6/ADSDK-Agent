"""M6A low-token AI orchestration module.

This package adds an opt-in, provider-agnostic AI orchestrator on top of the
existing deterministic analysis pipeline. It never re-implements static /
dynamic / correlation / privacy-rule logic: it only schedules existing tools
and synthesises a natural-language report grounded in a deterministic evidence
digest.

Design invariants (enforced everywhere):

* Deterministic tools own the facts; the AI owns scheduling and narration.
* The API key is read from the environment only and never enters logs, the
  database, responses, reports, or the frontend.
* All AI behaviour defaults OFF; AI unavailable never breaks deterministic
  analysis or reports.
* Tool results sent to the model are compact summaries, never full artifacts.
* The model never receives Shell / adb / frida / mitmproxy command surfaces.
"""

from __future__ import annotations

from .models import (
    AIPlan,
    AIReport,
    AISynthesisStatus,
    AIToolTrace,
    AITokenUsage,
    EvidenceDigest,
    EvidenceDigestFinding,
    PlanStep,
    PlanStrategy,
    PreparedPlan,
    ToolCandidate,
    ToolCompactResult,
    ToolRiskLevel,
    ai_plan_schema_version,
    ai_report_schema_version,
    evidence_digest_schema_version,
)
from .provider import AIProvider, MockAIProvider, OpenAICompatibleProvider
from .report_composer import FIXED_DISCLAIMER

__all__ = [
    "AIPlan",
    "AIProvider",
    "AIReport",
    "AISynthesisStatus",
    "AIToolTrace",
    "AITokenUsage",
    "EvidenceDigest",
    "EvidenceDigestFinding",
    "FIXED_DISCLAIMER",
    "MockAIProvider",
    "OpenAICompatibleProvider",
    "PlanStep",
    "PlanStrategy",
    "PreparedPlan",
    "ToolCandidate",
    "ToolCompactResult",
    "ToolRiskLevel",
    "ai_plan_schema_version",
    "ai_report_schema_version",
    "evidence_digest_schema_version",
]
