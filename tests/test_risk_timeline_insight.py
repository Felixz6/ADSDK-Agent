from app.analyzers.compliance_insight import generate_compliance_insight
from app.analyzers.risk_scoring import calculate_risk_summary, level_for_score
from app.analyzers.timeline_builder import build_timeline, classify_timing
from app.models import AnalyzeResponse
from app.tools.report_writer import write_markdown_report


def test_risk_level_boundaries():
    assert level_for_score(0) == "low"
    assert level_for_score(29) == "low"
    assert level_for_score(30) == "medium"
    assert level_for_score(59) == "medium"
    assert level_for_score(60) == "high"
    assert level_for_score(79) == "high"
    assert level_for_score(80) == "critical"
    assert level_for_score(100) == "critical"


def test_score_is_clamped_and_not_evaluated_is_not_a_hit():
    report = {
        "dynamic_findings": {
            "rules": [
                {"rule_id": f"pre_consent_sensitive_{index}", "status": "matched"}
                for index in range(10)
            ]
            + [{"rule_id": "missing", "status": "not_evaluated"}]
        }
    }
    summary = calculate_risk_summary(report)
    assert summary.score == 100
    assert summary.unevaluated_rule_count == 1
    assert all(item.id != "missing" for item in summary.top_risks)


def test_error_and_missing_evidence_reduce_confidence():
    summary = calculate_risk_summary(
        {
            "collection_status": "failed",
            "traffic_summary": {"coverage": "unavailable"},
            "dynamic_findings": {
                "rules": [
                    {"rule_id": "a", "status": "error"},
                    {"rule_id": "b", "status": "not_evaluated"},
                ]
            },
        }
    )
    assert summary.score == 0
    assert 0 <= summary.score <= 100
    assert summary.confidence == "low"


def test_manifest_permission_and_protocol_error_are_scored_from_evidence():
    summary = calculate_risk_summary(
        {
            "app_info": {
                "permissions": ["android.permission.READ_PHONE_STATE"],
            },
            "dynamic_events": [
                {"event": "protocol_error", "category": "protocol_error"},
            ],
        }
    )
    assert summary.score == 20
    assert {item.id for item in summary.top_risks} == {
        "manifest_sensitive_permissions",
        "dynamic_protocol_error",
    }


def test_consent_boundary_is_post_and_invalid_is_unknown():
    assert classify_timing(8.2, 8.2) == "post_consent"
    assert classify_timing(8.19, 8.2) == "pre_consent"
    assert classify_timing(None, 8.2) == "unknown"
    assert classify_timing(float("nan"), 8.2) == "unknown"


def test_timeline_sorts_reliable_events_and_preserves_unknown():
    timeline = build_timeline(
        {
            "dynamic_timeline": {
                "collection_started_monotonic_ms": 1000,
                "consent_monotonic_ms": 1200,
            },
            "dynamic_events": [
                {
                    "type": "event",
                    "event_id": "later",
                    "monotonic_ms": 1300,
                    "category": "identifier",
                    "api": "Settings.Secure.getString",
                    "action": "读取 Android ID",
                },
                {
                    "type": "event",
                    "event_id": "earlier",
                    "monotonic_ms": 1100,
                    "category": "identifier",
                    "api": "Settings.Secure.getString",
                    "action": "读取 Android ID",
                },
                {"type": "event", "event_id": "unknown", "category": "system"},
            ],
        }
    )
    ids = [event.id for event in timeline.events]
    assert ids == [
        "control-collection_started",
        "earlier",
        "control-consent",
        "later",
        "unknown",
    ]
    assert timeline.events[1].consent_state == "pre_consent"
    assert timeline.events[3].consent_state == "post_consent"
    assert timeline.events[4].consent_state == "unknown"


def test_insight_only_uses_risk_evidence():
    risk = calculate_risk_summary(
        {
            "dynamic_findings": {
                "rules": [
                    {
                        "rule_id": "pre_consent_identifier_access",
                        "status": "matched",
                        "evidence_refs": ["events.raw.jsonl#2"],
                    },
                    {"rule_id": "not_seen", "status": "not_matched"},
                ]
            }
        }
    )
    insight = generate_compliance_insight(risk)
    assert len(insight.key_findings) == 1
    assert insight.key_findings[0].evidence_refs == ["events.raw.jsonl#2"]
    assert "not_seen" not in insight.overall_assessment


def test_old_report_without_enrichment_fields_remains_readable():
    response = AnalyzeResponse.model_validate(
        {"ok": True, "apk_path": "sample.apk", "sdks": []}
    )
    assert response.risk_summary is None
    assert response.timeline is None
    assert response.compliance_insight is None


def test_markdown_report_contains_risk_and_remediation(tmp_path):
    risk = calculate_risk_summary(
        {
            "dynamic_findings": {
                "rules": [
                    {
                        "rule_id": "pre_consent_identifier_access",
                        "status": "matched",
                        "evidence_refs": ["events.raw.jsonl#2"],
                    }
                ]
            }
        }
    )
    insight = generate_compliance_insight(risk)
    output = tmp_path / "report.md"
    write_markdown_report(
        {
            "status": "success",
            "risk_summary": risk.model_dump(),
            "timeline": {"events": []},
            "compliance_insight": insight.model_dump(),
        },
        str(output),
    )
    markdown = output.read_text(encoding="utf-8")
    assert "综合风险摘要" in markdown
    assert "整改优先级" in markdown
