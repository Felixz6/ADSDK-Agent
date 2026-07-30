from __future__ import annotations

from copy import deepcopy
import json
from types import SimpleNamespace

import pytest

from app.analyzers.privacy_findings import (
    FINDINGS_DISCLAIMER,
    MAX_EVIDENCE_REFS,
    RULE_IDS,
    SCHEMA_VERSION,
    build_error_privacy_findings,
    build_finding_id,
    build_privacy_findings,
    calculate_finding_confidence,
    safe_path_summary,
)
from app.reporting import render_html_report
from app.tools.report_writer import write_markdown_report


def _event(**values):
    return {
        "event_id": "evt-1",
        "type": "event",
        "event_type": "identifier",
        "api": "Settings.Secure.getString",
        "identifier_type": "android_id",
        "consent_state": "pre_consent",
        "timestamp_utc": "2026-01-01T00:00:01Z",
        "timing_reliable": True,
        **values,
    }


def _request(**values):
    return {
        "flow_id": "req-1",
        "hostname": "api.example.test",
        "method": "POST",
        "path": "/v1/track/session/deep",
        "timestamp_utc": "2026-01-01T00:00:01.200Z",
        "consent_state": "pre_consent",
        **values,
    }


def _correlation(**values):
    return {
        "status": "evaluated",
        "items": [
            {
                "correlation_id": "corr-1",
                "dynamic_event_id": "evt-1",
                "network_request_id": "req-1",
                "event_type": "identifier",
                "request_host": "api.example.test",
                "request_method": "POST",
                "delta_ms": 200,
                "consent_state": "pre_consent",
                "confidence": "high",
                "reason_codes": ["monotonic_near", "same_consent_state"],
            }
        ],
        **values,
    }


def _full(**overrides):
    kwargs = {
        "dynamic_events": [_event()],
        "network_requests": [_request()],
        "correlation": _correlation(),
        "manifest_evidence": {"status": "evaluated"},
        "dynamic_evidence_available": True,
        "network_evidence_available": True,
        "consent_boundary_available": True,
        "dynamic_evidence_grade": "A",
    }
    kwargs.update(overrides)
    return build_privacy_findings(**kwargs)


def _rule(result, rule_id):
    return next(item for item in result.rule_results if item.rule_id == rule_id)


def _finding(result, rule_id):
    return next(
        (item for item in result.findings if item.rule_id == rule_id),
        None,
    )


def test_full_evidence_matches_pre_consent_rules_and_keeps_inputs_immutable():
    events = [_event()]
    requests = [_request()]
    correlation = _correlation()
    original = deepcopy((events, requests, correlation))

    result = _full(
        dynamic_events=events,
        network_requests=requests,
        correlation=correlation,
    )

    assert result.schema_version == SCHEMA_VERSION
    assert result.status == "evaluated"
    assert {item.rule_id for item in result.findings} == {
        "PF-PRECONSENT-SENSITIVE-EVENT",
        "PF-PRECONSENT-NETWORK",
        "PF-PRECONSENT-CORRELATED-ACTIVITY",
    }
    assert (events, requests, correlation) == original


def test_all_seven_rules_are_always_reported():
    result = _full()
    assert [item.rule_id for item in result.rule_results] == sorted(RULE_IDS)


def test_observed_and_suspected_findings_are_distinguished():
    result = _full()
    observed = _finding(result, "PF-PRECONSENT-SENSITIVE-EVENT")
    suspected = _finding(result, "PF-PRECONSENT-CORRELATED-ACTIVITY")
    assert observed is not None and observed.finding_type == "observed"
    assert suspected is not None and suspected.finding_type == "suspected"
    assert result.summary.confirmed_observation_count == 2
    assert result.summary.suspected_risk_count == 1


def test_correlated_finding_never_claims_causality_or_upload():
    result = _full()
    finding = _finding(result, "PF-PRECONSENT-CORRELATED-ACTIVITY")
    assert finding is not None
    assert "不证明事件触发了网络请求" in finding.explanation
    assert "no_causality_established" in finding.reason_codes
    assert "上传" not in finding.summary


def test_no_finding_text_claims_illegality_or_compliance_conclusion():
    serialized = _full().model_dump_json()
    for forbidden in ("违法", "不合规", "已上传个人信息", "合规结论已形成"):
        assert forbidden not in serialized
    assert FINDINGS_DISCLAIMER in serialized


def test_missing_dynamic_evidence_marks_only_dynamic_rules_not_evaluated():
    result = _full(
        dynamic_events=[],
        dynamic_evidence_available=False,
        dynamic_evidence_grade=None,
    )
    assert _rule(result, "PF-PRECONSENT-SENSITIVE-EVENT").status == "not_evaluated"
    assert _rule(result, "PF-PRECONSENT-NETWORK").status == "matched"
    assert _rule(result, "PF-DYNAMIC-EVIDENCE-GAP").status == "matched"
    assert result.status == "partially_evaluated"


def test_grade_d_produces_no_deterministic_dynamic_conclusion():
    result = _full(dynamic_evidence_grade="D")
    assert _rule(result, "PF-PRECONSENT-SENSITIVE-EVENT").status == "not_evaluated"
    assert "dynamic_evidence_grade_insufficient" in _rule(
        result,
        "PF-PRECONSENT-SENSITIVE-EVENT",
    ).reason_codes
    assert _rule(result, "PF-DYNAMIC-EVIDENCE-GAP").status == "matched"


def test_missing_network_evidence_keeps_dynamic_rules_evaluated():
    result = _full(network_requests=[], network_evidence_available=False)
    assert _rule(result, "PF-PRECONSENT-NETWORK").status == "not_evaluated"
    assert _rule(result, "PF-PRECONSENT-SENSITIVE-EVENT").status == "matched"
    assert _rule(result, "PF-NETWORK-EVIDENCE-GAP").status == "matched"


def test_missing_correlation_does_not_block_independent_rules():
    result = _full(correlation=None)
    assert _rule(result, "PF-PRECONSENT-CORRELATED-ACTIVITY").status == "not_evaluated"
    assert _rule(result, "PF-PRECONSENT-SENSITIVE-EVENT").status == "matched"
    assert _rule(result, "PF-PRECONSENT-NETWORK").status == "matched"
    assert "correlation_not_available" in _rule(
        result,
        "PF-PRECONSENT-CORRELATED-ACTIVITY",
    ).reason_codes


def test_manifest_failure_does_not_block_dynamic_rules():
    result = _full(
        manifest_evidence={
            "status": "not_evaluated",
            "error_code": "manifest_parse_failed",
            "message": "manifest parse failed: ValueError",
        }
    )
    assert _rule(result, "PF-PRECONSENT-SENSITIVE-EVENT").status == "matched"
    assert any("Manifest" in item for item in result.limitations)


def test_missing_consent_boundary_is_not_evaluated_not_safe():
    result = _full(consent_boundary_available=False)
    assert _rule(result, "PF-PRECONSENT-SENSITIVE-EVENT").status == "not_evaluated"
    assert _rule(result, "PF-PRECONSENT-NETWORK").status == "not_evaluated"
    assert _rule(result, "PF-POSTCONSENT-OBSERVATION").status == "not_evaluated"
    assert _rule(result, "PF-CONSENT-STATE-UNKNOWN").status == "matched"
    assert result.status == "partially_evaluated"


def test_unknown_consent_state_creates_evidence_gap_finding():
    result = _full(
        dynamic_events=[_event(consent_state="unknown", timing_reliable=False)],
        network_requests=[_request(consent_state="unknown")],
    )
    finding = _finding(result, "PF-CONSENT-STATE-UNKNOWN")
    assert finding is not None
    assert finding.finding_type == "evidence_gap"
    assert finding.severity == "info"
    assert finding.confidence == "low"


def test_post_consent_observation_is_low_severity_baseline():
    result = _full(
        dynamic_events=[_event(consent_state="post_consent")],
        network_requests=[_request(consent_state="post_consent")],
        correlation=_correlation(items=[]),
    )
    finding = _finding(result, "PF-POSTCONSENT-OBSERVATION")
    assert finding is not None
    assert finding.severity == "low"
    assert finding.finding_type == "observed"
    assert _rule(result, "PF-PRECONSENT-SENSITIVE-EVENT").status == "not_matched"


def test_no_observations_never_means_safe():
    result = build_privacy_findings(
        dynamic_events=[],
        network_requests=[],
        correlation=None,
        manifest_evidence={"status": "evaluated"},
        dynamic_evidence_available=False,
        network_evidence_available=False,
        consent_boundary_available=False,
        dynamic_evidence_grade=None,
    )
    serialized = result.model_dump_json()
    assert result.status in {"partially_evaluated", "no_observations", "not_evaluated"}
    for forbidden in ("无风险", "零风险", "符合合规要求", "未发现风险，可放心"):
        assert forbidden not in serialized
    # Every safety mention must be a negation, never a clearance.
    for index in range(len(serialized)):
        if serialized.startswith("安全", index):
            assert "不" in serialized[max(0, index - 12) : index]
    assert "未评估不等于安全" in serialized
    assert result.summary.confirmed_observation_count == 0
    assert result.summary.suspected_risk_count == 0


def test_severity_and_confidence_are_independent():
    result = _full(dynamic_evidence_grade="C")
    finding = _finding(result, "PF-PRECONSENT-SENSITIVE-EVENT")
    assert finding is not None
    assert finding.severity == "high"
    assert finding.confidence == "medium"


def test_correlation_medium_confidence_caps_finding_confidence():
    correlation = _correlation()
    correlation["items"][0]["confidence"] = "medium"
    result = _full(correlation=correlation)
    finding = _finding(result, "PF-PRECONSENT-CORRELATED-ACTIVITY")
    assert finding is not None
    assert finding.confidence == "medium"


def test_utc_fallback_caps_confidence_to_low():
    correlation = _correlation()
    correlation["items"][0]["reason_codes"] = ["utc_time_near", "clock_unreliable"]
    result = _full(correlation=correlation)
    finding = _finding(result, "PF-PRECONSENT-CORRELATED-ACTIVITY")
    assert finding is not None
    assert finding.confidence == "low"
    assert "utc_time_fallback" in finding.reason_codes


def test_calculate_finding_confidence_thresholds():
    def confidence(**overrides):
        kwargs = {"consent_state": "pre_consent", "base": "high"}
        kwargs.update(overrides)
        return calculate_finding_confidence(**kwargs)

    assert confidence(dynamic_grade="A") == "high"
    assert confidence(dynamic_grade="B") == "high"
    assert confidence(dynamic_grade="C") == "medium"
    assert confidence(dynamic_grade="D") == "low"
    assert confidence(correlation_confidence="medium") == "medium"
    assert confidence(correlation_confidence="low") == "low"
    assert confidence(utc_time_fallback=True) == "low"
    assert confidence(consent_state="unknown") == "low"
    assert confidence(dynamic_grade="A", base="medium") == "medium"


def test_finding_ids_are_stable_and_order_independent():
    first = build_finding_id(
        rule_id="PF-PRECONSENT-NETWORK",
        evidence_ids=["b", "a"],
        consent_state="pre_consent",
    )
    second = build_finding_id(
        rule_id="PF-PRECONSENT-NETWORK",
        evidence_ids=["a", "b"],
        consent_state="pre_consent",
    )
    assert first == second
    assert first.startswith("pf-")
    assert first != build_finding_id(
        rule_id="PF-PRECONSENT-NETWORK",
        evidence_ids=["a", "b"],
        consent_state="post_consent",
    )


def test_same_input_produces_identical_output_and_ordering():
    first = _full()
    second = _full(
        dynamic_events=[_event()],
        network_requests=[_request()],
        correlation=_correlation(),
    )
    assert first == second
    severities = [item.severity for item in first.findings]
    assert severities == sorted(severities, key=lambda value: ["high", "medium", "low", "info"].index(value))


def test_sensitive_request_fields_never_enter_findings():
    result = _full(
        network_requests=[
            _request(
                headers={"Cookie": "secret-cookie", "Authorization": "Bearer secret"},
                body="secret-body",
                response_body="secret-response",
                query={"token": "secret-token"},
                device_serial="SECRETSERIAL",
                android_id="SECRETANDROIDID",
            )
        ]
    )
    serialized = result.model_dump_json()
    for forbidden in (
        "secret-cookie",
        "Bearer secret",
        "secret-body",
        "secret-response",
        "secret-token",
        "SECRETSERIAL",
        "SECRETANDROIDID",
        "Cookie",
        "Authorization",
    ):
        assert forbidden not in serialized


def test_path_summary_is_coarse_and_bounded():
    assert safe_path_summary("/v1/track/session/deep") == "/v1/track/…"
    assert safe_path_summary("/v1/track?token=secret") == "/v1/track"
    assert safe_path_summary(None) == "/"
    assert "secret" not in safe_path_summary("/a/b/c?token=secret")


def test_evidence_refs_are_bounded_and_truncation_is_reported():
    events = [
        _event(event_id=f"evt-{index}", timestamp_utc="2026-01-01T00:00:01Z")
        for index in range(MAX_EVIDENCE_REFS + 5)
    ]
    result = _full(dynamic_events=events)
    finding = _finding(result, "PF-PRECONSENT-SENSITIVE-EVENT")
    assert finding is not None
    assert len(finding.evidence_refs) == MAX_EVIDENCE_REFS
    assert "evidence_refs_truncated" in finding.reason_codes


def test_evidence_refs_only_use_safe_identifiers():
    result = _full()
    for finding in result.findings:
        for ref in finding.evidence_refs:
            assert ref.evidence_type in {
                "manifest",
                "dynamic_event",
                "network_request",
                "correlation",
                "timeline",
                "diagnostic",
            }
            assert ref.artifact
            assert ref.evidence_id


def test_single_rule_exception_does_not_abort_other_rules(monkeypatch):
    import app.analyzers.privacy_findings as module

    def explode(_context):
        raise RuntimeError("synthetic rule failure")

    monkeypatch.setattr(
        module,
        "_RULES",
        (
            ("PF-PRECONSENT-SENSITIVE-EVENT", explode),
            ("PF-PRECONSENT-NETWORK", module._rule_preconsent_network),
        ),
    )
    result = _full()
    assert _rule(result, "PF-PRECONSENT-SENSITIVE-EVENT").status == "error"
    assert _rule(result, "PF-PRECONSENT-NETWORK").status == "matched"
    assert result.summary.error_rule_count == 1
    assert "synthetic rule failure" not in result.model_dump_json()


def test_build_error_privacy_findings_is_safe_and_complete():
    result = build_error_privacy_findings(reason="RuntimeError")
    assert result.status == "error"
    assert result.findings == []
    assert [item.rule_id for item in result.rule_results] == list(RULE_IDS)
    assert result.summary.error_rule_count == len(RULE_IDS)
    assert FINDINGS_DISCLAIMER in result.limitations


def test_markdown_and_html_include_privacy_section_and_disclaimer(tmp_path):
    report = {
        "schema_version": "1.0",
        "status": "success",
        "sdks": [],
        "dynamic_events": [],
        "traffic_summary": {},
        "privacy_findings": _full().model_dump(mode="json"),
    }
    markdown_path = tmp_path / "report.md"
    write_markdown_report(report, str(markdown_path))
    markdown = markdown_path.read_text(encoding="utf-8")
    html = render_html_report(report)

    assert "## 可解释隐私发现" in markdown
    assert "不构成法律合规结论" in markdown
    assert "可解释隐私发现" in html
    assert 'href="#privacy-findings"' in html
    assert SCHEMA_VERSION not in html


def test_legacy_report_without_privacy_findings_still_renders(tmp_path):
    report = {
        "schema_version": "1.0",
        "status": "success",
        "sdks": [],
        "dynamic_events": [],
        "traffic_summary": {},
    }
    markdown_path = tmp_path / "legacy.md"
    write_markdown_report(report, str(markdown_path))
    assert markdown_path.is_file()
    assert "可解释隐私发现" not in markdown_path.read_text(encoding="utf-8")
    assert "<!doctype html>" in render_html_report(report)


def test_empty_findings_section_states_no_findings_not_safe(tmp_path):
    payload = _full(
        dynamic_events=[_event(consent_state="post_consent", api="Other.api")],
        network_requests=[_request(consent_state="post_consent")],
        correlation=_correlation(items=[]),
    ).model_dump(mode="json")
    payload["findings"] = []
    report = {
        "schema_version": "1.0",
        "status": "success",
        "sdks": [],
        "dynamic_events": [],
        "traffic_summary": {},
        "privacy_findings": payload,
    }
    markdown_path = tmp_path / "empty.md"
    write_markdown_report(report, str(markdown_path))
    markdown = markdown_path.read_text(encoding="utf-8")
    assert "没有形成可展示的隐私发现" in markdown
    assert "不代表应用安全或合规" in markdown


def test_privacy_findings_failure_isolated_and_error_artifact_written(
    tmp_path,
    monkeypatch,
):
    import app.main as main

    def fail(*_args, **_kwargs):
        raise RuntimeError("synthetic privacy failure")

    monkeypatch.setattr(main, "build_privacy_findings", fail)
    context = SimpleNamespace(privacy_findings_path=tmp_path / "privacy-findings.json")
    payload = main._build_and_write_privacy_findings(
        context=context,
        dynamic_events=[_event()],
        network_requests=[_request()],
        correlation=_correlation(),
        manifest_evidence={"status": "evaluated"},
        dynamic_evidence_available=True,
        network_evidence_available=True,
        consent_boundary_available=True,
        dynamic_evidence_grade="A",
    )

    assert payload["status"] == "error"
    written = json.loads(
        (tmp_path / "privacy-findings.json").read_text(encoding="utf-8")
    )
    assert written["status"] == "error"
    assert "synthetic privacy failure" not in json.dumps(written, ensure_ascii=False)


def test_report_generation_survives_privacy_module_exception(tmp_path, monkeypatch):
    import app.main as main

    def fail(*_args, **_kwargs):
        raise RuntimeError("synthetic privacy failure")

    monkeypatch.setattr(main, "build_privacy_findings", fail)
    context = SimpleNamespace(privacy_findings_path=tmp_path / "privacy-findings.json")
    payload = main._build_and_write_privacy_findings(
        context=context,
        dynamic_events=[],
        network_requests=[],
        correlation=None,
        manifest_evidence=None,
        dynamic_evidence_available=False,
        network_evidence_available=False,
        consent_boundary_available=False,
        dynamic_evidence_grade=None,
    )
    report = {
        "schema_version": "1.0",
        "status": "success",
        "sdks": [],
        "dynamic_events": [],
        "traffic_summary": {},
        "privacy_findings": payload,
    }
    markdown_path = tmp_path / "degraded.md"
    write_markdown_report(report, str(markdown_path))
    assert markdown_path.is_file()
    assert "<!doctype html>" in render_html_report(report)


def test_write_failure_is_reported_without_aborting(tmp_path, monkeypatch):
    import app.main as main

    def fail_write(*_args, **_kwargs):
        raise OSError("synthetic write failure")

    monkeypatch.setattr(main, "atomic_write_json", fail_write)
    context = SimpleNamespace(privacy_findings_path=tmp_path / "privacy-findings.json")
    payload = main._build_and_write_privacy_findings(
        context=context,
        dynamic_events=[_event()],
        network_requests=[_request()],
        correlation=_correlation(),
        manifest_evidence={"status": "evaluated"},
        dynamic_evidence_available=True,
        network_evidence_available=True,
        consent_boundary_available=True,
        dynamic_evidence_grade="A",
    )
    assert payload["status"] == "error"
    assert any("写入失败" in item for item in payload["limitations"])


def test_network_consent_states_are_classified_from_utc_evidence():
    import app.main as main

    states = main._network_consent_states(
        [
            {"flow_id": "req-pre", "timestamp_utc": "2026-01-01T00:00:00Z"},
            {"flow_id": "req-post", "timestamp_utc": "2026-01-01T00:00:05Z"},
            {"flow_id": "req-none"},
        ],
        "2026-01-01T00:00:02Z",
    )
    assert states == {"req-pre": "pre_consent", "req-post": "post_consent"}


def test_consent_boundary_requires_finite_monotonic_mark():
    import app.main as main

    assert main._has_trusted_consent_boundary(
        {"consent_at": {"monotonic_ms": 1500.0}}
    )
    assert not main._has_trusted_consent_boundary({"consent_at": None})
    assert not main._has_trusted_consent_boundary(
        {"consent_at": {"monotonic_ms": None}}
    )
    assert not main._has_trusted_consent_boundary(
        {"consent_at": {"monotonic_ms": float("inf")}}
    )


@pytest.mark.parametrize("grade", ["A", "B", "C", "D", None, "unexpected"])
def test_all_dynamic_grades_produce_a_valid_result(grade):
    result = _full(dynamic_evidence_grade=grade)
    assert result.status in {
        "evaluated",
        "partially_evaluated",
        "not_evaluated",
        "no_observations",
        "error",
    }
    assert len(result.rule_results) == len(RULE_IDS)
