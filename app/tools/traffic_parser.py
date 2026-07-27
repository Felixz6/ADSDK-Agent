import os
import re
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import urlparse

from app.config import SCHEMA_VERSION
from app.core.artifacts import atomic_write_json
from app.tools.traffic_events import (
    TrafficCollectionOutcome,
    TrafficCollectionResult,
    validate_traffic_jsonl,
)

REQUEST_PATTERN = re.compile(
    r"(?P<ts>\d{2}:\d{2}:\d{2}(?:\.\d+)?)?.*?\b(?P<method>GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\s+(?P<url>https?://[^\s]+)",
    re.IGNORECASE,
)


def parse_traffic_text(traffic_text_path: str) -> List[Dict[str, Any]]:
    if not traffic_text_path or not os.path.exists(traffic_text_path):
        return []

    records: List[Dict[str, Any]] = []
    with open(traffic_text_path, "r", encoding="utf-8", errors="strict") as f:
        for line in f:
            match = REQUEST_PATTERN.search(line)
            if not match:
                continue

            method = match.group("method").upper()
            url = match.group("url")
            parsed = urlparse(url)
            records.append(
                {
                    "timestamp": match.group("ts"),
                    "method": method,
                    "host": parsed.netloc,
                    "path": parsed.path or "/",
                }
            )
    return records


def build_traffic_summary(
    records: List[Dict[str, Any]],
    *,
    source_available: bool = True,
    collection_outcome: str | TrafficCollectionOutcome | None = None,
) -> Dict[str, Any]:
    host_counter = Counter(
        record.get("hostname") or record.get("host")
        for record in records
        if record.get("hostname") or record.get("host")
    )
    top_hosts = [{"host": host, "count": count} for host, count in host_counter.most_common(20)]

    normalized_outcome = (
        collection_outcome.value
        if isinstance(collection_outcome, TrafficCollectionOutcome)
        else collection_outcome
    )
    if normalized_outcome == TrafficCollectionOutcome.SUCCESS_REQUESTS_OBSERVED.value:
        status = "success"
        evaluation_status = "not_matched"
        coverage = "observed"
        warnings: list[str] = []
    elif normalized_outcome == TrafficCollectionOutcome.SUCCESS_ZERO_REQUESTS.value:
        status = "success"
        evaluation_status = "not_evaluated"
        coverage = "no_observations"
        warnings = ["traffic collector succeeded with zero observed requests"]
    elif normalized_outcome == TrafficCollectionOutcome.COLLECTOR_FAILED.value:
        status = "partial"
        evaluation_status = "not_evaluated"
        coverage = "unavailable"
        warnings = ["structured traffic collector validation failed"]
    else:
        # Compatibility semantics for historical human-readable mitmdump logs.
        status = "success" if source_available and records else "partial"
        evaluation_status = (
            "not_matched" if source_available and records else "not_evaluated"
        )
        coverage = "observed" if source_available and records else "unavailable"
        warnings = (
            []
            if source_available and records
            else ["traffic evidence has no valid HTTP request records"]
        )

    return {
        "schema_version": SCHEMA_VERSION,
        "status": status,
        "evaluation_status": evaluation_status,
        "coverage": coverage,
        "collector_outcome": normalized_outcome,
        "warnings": warnings,
        "total_requests": len(records),
        "top_hosts": top_hosts,
        "sample_requests": records[:50],
    }


def write_traffic_summary(summary: Dict[str, Any], output_path: str):
    atomic_write_json(output_path, summary)


def parse_traffic_to_summary_json(traffic_text_path: str, output_path: str) -> Dict[str, Any]:
    if not traffic_text_path or not os.path.isfile(traffic_text_path):
        raise FileNotFoundError(f"traffic evidence is missing: {traffic_text_path}")
    records = parse_traffic_text(traffic_text_path)
    summary = build_traffic_summary(records, source_available=True)
    write_traffic_summary(summary, output_path)
    return summary


def build_structured_traffic_summary(
    collection: TrafficCollectionResult,
) -> Dict[str, Any]:
    records = [
        record.model_dump(mode="json")
        for record in collection.records
    ]
    summary = build_traffic_summary(
        records,
        source_available=(
            collection.outcome
            is not TrafficCollectionOutcome.COLLECTOR_FAILED
        ),
        collection_outcome=collection.outcome,
    )
    summary["validation"] = {
        "process_ready": collection.process_ready,
        "addon_ready": collection.addon_ready,
        "malformed_count": collection.malformed_count,
        "mismatch_count": collection.mismatch_count,
        "issues": [
            {"code": issue.code, "line_number": issue.line_number}
            for issue in collection.issues
        ],
    }
    return summary


def parse_structured_traffic_to_summary_json(
    jsonl_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
    *,
    run_id: str,
    session_id: str,
    process_ready: bool,
) -> Dict[str, Any]:
    """Validate owned JSONL and keep the legacy summary artifact contract."""

    source = Path(jsonl_path)
    if not source.is_file():
        raise FileNotFoundError(
            f"structured traffic evidence is missing: {source}"
        )
    collection = validate_traffic_jsonl(
        source,
        run_id=run_id,
        session_id=session_id,
        process_ready=process_ready,
    )
    summary = build_structured_traffic_summary(collection)
    write_traffic_summary(summary, os.fspath(output_path))
    return summary
