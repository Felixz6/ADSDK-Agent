"""Correlate static SDK fingerprints with run-owned dynamic evidence."""

from __future__ import annotations

from copy import deepcopy
import json
from typing import Any

from app.tools.sdk_fingerprint import load_sdk_knowledge_base


def correlate_sdk_evidence(
    sdk_hits: list[dict[str, Any]],
    report: dict[str, Any],
) -> list[dict[str, Any]]:
    """Return SDK hits enriched only by evidence present in this report."""
    hits = {str(item.get("id")): deepcopy(item) for item in sdk_hits}
    event_blob = json.dumps(
        report.get("dynamic_events") or [],
        ensure_ascii=False,
        sort_keys=True,
    ).replace("/", ".").lower()
    hosts = _observed_hosts(report.get("traffic_summary"))

    for knowledge in load_sdk_knowledge_base():
        evidence: list[dict[str, Any]] = []
        for pattern in [
            *knowledge.get("package_patterns", []),
            *knowledge.get("class_patterns", []),
        ]:
            normalized = str(pattern).replace("/", ".").lower()
            if normalized and normalized in event_blob:
                evidence.append(
                    {
                        "source_type": "dynamic_event",
                        "relative_path": "events.raw.jsonl",
                        "detector": "runtime_signature",
                        "description": f"动态事件命中 {pattern}",
                    }
                )

        for pattern in knowledge.get("domain_patterns", []):
            normalized = str(pattern).lower().lstrip(".")
            for host in hosts:
                if host == normalized or host.endswith(f".{normalized}"):
                    evidence.append(
                        {
                            "source_type": "network",
                            "relative_path": "traffic/requests.jsonl",
                            "detector": "observed_domain",
                            "description": f"实际观测到网络主机 {host}",
                        }
                    )

        if not evidence:
            continue

        sdk_id = str(knowledge["id"])
        hit = hits.get(sdk_id)
        if hit is None:
            package_patterns = knowledge.get("package_patterns") or [sdk_id]
            hit = {
                "id": sdk_id,
                "sdk_name": knowledge["name"],
                "package": str(package_patterns[0]),
                "vendor": knowledge["vendor"],
                "category": knowledge["category"],
                "risk_level": knowledge["risk_level"],
                "confidence": 0.85,
                "version": None,
                "capabilities": list(knowledge.get("capabilities") or []),
                "static_only": False,
                "dynamic_correlated": True,
                "evidence": [],
            }
            hits[sdk_id] = hit

        hit["static_only"] = False
        hit["dynamic_correlated"] = True
        hit["confidence"] = max(float(hit.get("confidence") or 0), 0.95)
        hit_evidence = hit.setdefault("evidence", [])
        existing = {
            (
                item.get("source_type"),
                item.get("relative_path"),
                item.get("detector"),
                item.get("description"),
            )
            for item in hit_evidence
        }
        for item in evidence:
            key = (
                item["source_type"],
                item["relative_path"],
                item["detector"],
                item["description"],
            )
            if key not in existing:
                hit_evidence.append(item)
                existing.add(key)

    return sorted(
        hits.values(),
        key=lambda item: (
            not bool(item.get("dynamic_correlated")),
            -float(item.get("confidence") or 0),
            str(item.get("sdk_name") or "").casefold(),
        ),
    )


def _observed_hosts(value: Any) -> set[str]:
    if not isinstance(value, dict):
        return set()
    hosts: set[str] = set()
    for item in value.get("top_hosts") or []:
        if isinstance(item, dict) and item.get("host"):
            hosts.add(str(item["host"]).lower().rstrip("."))
    for item in value.get("sample_requests") or []:
        if not isinstance(item, dict):
            continue
        host = item.get("hostname") or item.get("host")
        if host:
            hosts.add(str(host).lower().rstrip("."))
    return hosts
