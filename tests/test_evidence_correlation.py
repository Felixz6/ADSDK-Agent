from __future__ import annotations

from copy import deepcopy
import json
from types import SimpleNamespace

from app.analyzers.evidence_correlation import (
    EvidenceCorrelationConfig,
    build_evidence_correlations,
)
from app.reporting import render_html_report
from app.tools.report_writer import write_markdown_report


def _event(**values):
    return {
        "event_id": "evt-1",
        "event_type": "identifier",
        "run_id": "run-1",
        "session_id": "frida-1",
        "timestamp_utc": "2026-01-01T00:00:01Z",
        "monotonic_ms": 1000,
        "timing_reliable": True,
        "consent_state": "post_consent",
        **values,
    }


def _request(**values):
    return {
        "flow_id": "req-1",
        "run_id": "run-1",
        "session_id": "mitm-1",
        "timestamp_utc": "2026-01-01T00:00:01.200Z",
        "monotonic_ms": 1200,
        "hostname": "api.example.test",
        "method": "POST",
        "consent_state": "post_consent",
        **values,
    }


def test_monotonic_high_confidence_and_input_immutability():
    events = [_event()]
    requests = [_request()]
    original = deepcopy((events, requests))

    result = build_evidence_correlations(events, requests)

    assert result.status == "evaluated"
    assert result.items[0].confidence == "high"
    assert result.items[0].delta_ms == 200
    assert result.items[0].reason_codes == [
        "monotonic_near",
        "same_consent_state",
        "time_only_correlation",
    ]
    assert (events, requests) == original


def test_monotonic_medium_confidence():
    result = build_evidence_correlations(
        [_event()],
        [_request(monotonic_ms=2200)],
    )
    assert result.items[0].confidence == "medium"


def test_utc_fallback_is_low_confidence():
    result = build_evidence_correlations(
        [_event(monotonic_ms=None)],
        [_request(monotonic_ms=None)],
    )
    assert result.items[0].confidence == "low"
    assert result.items[0].reason_codes == [
        "utc_time_near",
        "same_consent_state",
        "time_only_correlation",
        "clock_unreliable",
    ]


def test_outside_window_is_evaluated_without_pairs():
    result = build_evidence_correlations(
        [_event()],
        [_request(monotonic_ms=4000)],
    )
    assert result.status == "evaluated"
    assert result.items == []
    assert result.summary.correlated_pair_count == 0


def test_consent_conflict_is_not_correlated():
    result = build_evidence_correlations(
        [_event(consent_state="pre_consent")],
        [_request(consent_state="post_consent")],
    )
    assert result.status == "evaluated"
    assert result.items == []


def test_unknown_consent_can_be_medium_when_monotonic_is_near():
    result = build_evidence_correlations(
        [_event(consent_state="unknown")],
        [_request(monotonic_ms=2000)],
    )
    assert result.items[0].confidence == "medium"
    assert "unknown_consent_state" in result.items[0].reason_codes


def test_no_observations_for_missing_side():
    no_events = build_evidence_correlations([], [_request()])
    no_requests = build_evidence_correlations([_event()], [])
    assert no_events.status == "no_observations"
    assert no_requests.status == "no_observations"


def test_untrusted_time_is_not_evaluated():
    result = build_evidence_correlations(
        [_event(monotonic_ms=None, timestamp_utc=None)],
        [_request(monotonic_ms=None, timestamp_utc=None)],
    )
    assert result.status == "not_evaluated"


def test_only_five_nearest_candidates_are_kept_per_event():
    requests = [
        _request(flow_id=f"req-{index}", monotonic_ms=1000 + index * 100)
        for index in range(1, 8)
    ]
    result = build_evidence_correlations([_event()], requests)
    assert [item.network_request_id for item in result.items] == [
        "req-1",
        "req-2",
        "req-3",
        "req-4",
        "req-5",
    ]


def test_correlation_id_and_sorting_are_stable():
    requests = [
        _request(flow_id="req-b", monotonic_ms=1300),
        _request(flow_id="req-a", monotonic_ms=1300),
    ]
    first = build_evidence_correlations([_event()], requests)
    second = build_evidence_correlations([_event()], list(reversed(requests)))
    assert first == second
    assert first.items[0].correlation_id.startswith("corr-")


def test_sensitive_network_fields_never_enter_output():
    result = build_evidence_correlations(
        [_event()],
        [
            _request(
                headers={"Cookie": "secret"},
                body="secret",
                query_value="secret",
                authorization="secret",
            )
        ],
    )
    serialized = result.model_dump_json()
    assert "secret" not in serialized
    assert "headers" not in serialized


def test_window_configuration_boundaries():
    assert EvidenceCorrelationConfig(window_ms=100).window_ms == 100
    assert EvidenceCorrelationConfig(window_ms=10_000).window_ms == 10_000


def test_markdown_and_html_reports_include_correlation_section(tmp_path):
    result = build_evidence_correlations([_event()], [_request()])
    report = {
        "schema_version": "1.0",
        "status": "success",
        "sdks": [],
        "dynamic_events": [],
        "traffic_summary": {},
        "evidence_correlation": result.model_dump(mode="json"),
    }
    markdown_path = tmp_path / "report.md"
    write_markdown_report(report, str(markdown_path))

    markdown = markdown_path.read_text(encoding="utf-8")
    html = render_html_report(report)
    assert "## 动态事件与网络请求关联" in markdown
    assert "时间上接近" in markdown
    assert "动态事件与网络请求关联" in html
    assert "correlation-v1" not in html  # technical schema is not promoted as a conclusion


def test_legacy_report_without_correlation_still_renders(tmp_path):
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
    assert "<!doctype html>" in render_html_report(report)


def test_correlation_failure_isolated_and_error_artifact_written(
    tmp_path,
    monkeypatch,
):
    import app.main as main

    def fail(*_args, **_kwargs):
        raise RuntimeError("synthetic correlation failure")

    monkeypatch.setattr(main, "build_evidence_correlations", fail)
    context = SimpleNamespace(correlations_path=tmp_path / "correlations.json")
    payload = main._build_and_write_evidence_correlation(
        context=context,
        dynamic_events=[_event()],
        network_requests=[_request()],
        consent_timestamp_utc=None,
    )

    assert payload["status"] == "error"
    assert json.loads(context.correlations_path.read_text(encoding="utf-8"))[
        "status"
    ] == "error"
