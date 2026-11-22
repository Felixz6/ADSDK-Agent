"""Shared pure helper functions and payloads for dynamic pipeline stages."""

from __future__ import annotations

from collections import Counter
from typing import Any

from app.config import SCHEMA_VERSION
from app.traffic.traffic_events import (
    TrafficCollectionOutcome,
    TrafficCollectionResult,
)


def _traffic_summary_from_result(
    result: TrafficCollectionResult,
) -> dict[str, Any]:
    """Derive serializable traffic summary document from collection result."""
    hosts = Counter(record.hostname for record in result.records)
    failed = result.outcome is TrafficCollectionOutcome.COLLECTOR_FAILED
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "failed" if failed else "success",
        "evaluation_status": "not_evaluated" if failed else "not_matched",
        "coverage": result.coverage,
        "collector_outcome": result.outcome.value,
        "warnings": (
            ["traffic collector did not produce trustworthy evidence"]
            if failed
            else (
                ["collector succeeded; no HTTP requests were observed"]
                if result.valid_request_count == 0
                else []
            )
        ),
        "total_requests": result.valid_request_count,
        "top_hosts": [{"host": host, "count": count} for host, count in hosts.most_common(20)],
        "sample_requests": [record.model_dump(mode="json") for record in result.records[:50]],
        "validation": result.to_dict(),
    }


def _traffic_failure_summary(exc: Exception) -> dict[str, Any]:
    """Build fallback traffic summary payload when collection processing raises."""
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "failed",
        "evaluation_status": "not_evaluated",
        "coverage": "unavailable",
        "collector_outcome": TrafficCollectionOutcome.COLLECTOR_FAILED.value,
        "warnings": [f"traffic processing failed: {type(exc).__name__}"],
        "total_requests": 0,
        "top_hosts": [],
        "sample_requests": [],
        "validation": {
            "outcome": TrafficCollectionOutcome.COLLECTOR_FAILED.value,
            "coverage": "unavailable",
            "process_ready": False,
            "addon_ready": False,
            "records": [],
            "issues": [{"code": "traffic_processing_exception", "line_number": 0}],
        },
    }


__all__ = [
    "_traffic_failure_summary",
    "_traffic_summary_from_result",
]
