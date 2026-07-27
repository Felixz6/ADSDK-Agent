from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

from app.analyzers.traffic.mitm_addon import SafeTrafficAddon
from app.tools.traffic_events import (
    TrafficCollectionOutcome,
    TrafficJSONLWriter,
    build_http_request_record,
    validate_traffic_jsonl,
)


def _writer_with_ready(path: Path) -> TrafficJSONLWriter:
    writer = TrafficJSONLWriter(path)
    writer.write_control(
        event="mitm_ready",
        run_id="run-a",
        session_id="session-a",
        timestamp_utc=datetime(2026, 7, 24, tzinfo=timezone.utc),
    )
    return writer


def test_structured_record_drops_query_values_headers_and_bodies(
    tmp_path: Path,
) -> None:
    secret_query = "QUERY_SECRET_94a51b"
    secret_header = "HEADER_SECRET_f32a90"
    secret_body = "BODY_SECRET_8c0d7f"
    record = build_http_request_record(
        flow_id="flow-1",
        run_id="run-a",
        session_id="session-a",
        timestamp_utc=datetime(2026, 7, 24, 23, 59, 59, tzinfo=timezone.utc),
        method="POST",
        url=(
            "https://API.Example.COM./v1/collect"
            f"?token={secret_query}&empty=&page=1"
        ),
        status_code=204,
        request_size=len(secret_body),
        response_size=0,
        request_headers={
            "Authorization": f"Bearer {secret_header}",
            "Cookie": f"sid={secret_header}",
        },
        request_body=secret_body.encode(),
        response_headers={"Set-Cookie": f"sid={secret_header}"},
        response_body=b"response-secret",
    )

    writer = _writer_with_ready(tmp_path / "requests.jsonl")
    writer.write_request(record)
    persisted = (tmp_path / "requests.jsonl").read_text(encoding="utf-8")
    payload = json.loads(persisted.splitlines()[1])

    assert payload["hostname"] == "api.example.com"
    assert payload["path"] == "/v1/collect"
    assert payload["query_keys"] == ["token", "empty", "page"]
    assert "headers" not in payload
    assert "body" not in payload
    assert secret_query not in persisted
    assert secret_header not in persisted
    assert secret_body not in persisted
    assert "response-secret" not in persisted


def test_sensitive_and_long_path_segments_are_redacted() -> None:
    token = "eyJhbGciOiJIUzI1NiJ9.abcdef0123456789.signature"
    record = build_http_request_record(
        flow_id="flow-2",
        run_id="run-a",
        session_id="session-a",
        timestamp_utc="2026-07-24T00:00:00.000Z",
        method="GET",
        url=f"https://example.com/reset/token/{token}/profile",
    )
    serialized = record.model_dump_json()

    assert token not in serialized
    assert record.path == "/reset/token/:redacted/profile"


def test_encoded_path_identifier_and_tokenish_query_key_are_redacted() -> None:
    encoded_identifier = "person%40example.com"
    tokenish_key = "SecretKey0123456789ABCDEF"
    record = build_http_request_record(
        flow_id="flow-encoded",
        run_id="run-a",
        session_id="session-a",
        timestamp_utc="2026-07-24T00:00:00.000Z",
        method="GET",
        url=(
            f"https://example.com/users/{encoded_identifier}"
            f"?{tokenish_key}=ignored&page=1"
        ),
    )
    serialized = record.model_dump_json()

    assert record.path == "/users/:redacted"
    assert record.query_keys == [":redacted_key", "page"]
    assert encoded_identifier not in serialized
    assert tokenish_key not in serialized


def test_hostname_normalization_supports_idna_and_ipv6() -> None:
    dns = build_http_request_record(
        flow_id="dns",
        run_id="run-a",
        session_id="session-a",
        timestamp_utc="2026-07-24T00:00:00Z",
        method="GET",
        url="https://BÜCHER.Example./",
    )
    ipv6 = build_http_request_record(
        flow_id="ipv6",
        run_id="run-a",
        session_id="session-a",
        timestamp_utc="2026-07-24T00:00:00Z",
        method="GET",
        url="https://[2001:0DB8:0:0:0:0:0:1]:8443/v1?q=secret",
    )

    assert dns.hostname == "xn--bcher-kva.example"
    assert ipv6.hostname == "2001:db8::1"
    assert ipv6.port == 8443
    assert ipv6.tls is True
    assert ipv6.query_keys == ["q"]


def test_timestamp_is_normalized_to_utc_across_midnight() -> None:
    record = build_http_request_record(
        flow_id="flow-midnight",
        run_id="run-a",
        session_id="session-a",
        timestamp_utc="2026-07-25T00:00:00+08:00",
        method="GET",
        url="http://example.com/",
    )

    assert record.timestamp_utc == "2026-07-24T16:00:00.000Z"


def test_validated_jsonl_distinguishes_zero_requests_from_failure(
    tmp_path: Path,
) -> None:
    ready_path = tmp_path / "ready.jsonl"
    _writer_with_ready(ready_path)

    zero = validate_traffic_jsonl(
        ready_path,
        run_id="run-a",
        session_id="session-a",
        process_ready=True,
    )
    not_ready = validate_traffic_jsonl(
        ready_path,
        run_id="run-a",
        session_id="session-a",
        process_ready=False,
    )

    assert zero.outcome is TrafficCollectionOutcome.SUCCESS_ZERO_REQUESTS
    assert zero.coverage == "no_observations"
    assert zero.valid_request_count == 0
    assert not_ready.outcome is TrafficCollectionOutcome.COLLECTOR_FAILED
    assert not_ready.coverage == "unavailable"


def test_malformed_and_session_mismatch_never_count_as_requests(
    tmp_path: Path,
) -> None:
    path = tmp_path / "requests.jsonl"
    writer = _writer_with_ready(path)
    foreign = build_http_request_record(
        flow_id="foreign",
        run_id="run-a",
        session_id="session-b",
        timestamp_utc="2026-07-24T00:00:00Z",
        method="GET",
        url="https://example.com/",
    )
    writer.write_request(foreign)
    with path.open("a", encoding="utf-8") as stream:
        stream.write("{this is not json}\n")

    result = validate_traffic_jsonl(
        path,
        run_id="run-a",
        session_id="session-a",
        process_ready=True,
    )

    assert result.valid_request_count == 0
    assert result.mismatch_count == 1
    assert result.malformed_count == 1
    assert result.outcome is TrafficCollectionOutcome.COLLECTOR_FAILED
    assert {issue.code for issue in result.issues} == {
        "traffic_session_mismatch",
        "traffic_malformed_json",
    }


def test_valid_request_yields_observed_coverage(tmp_path: Path) -> None:
    path = tmp_path / "requests.jsonl"
    writer = _writer_with_ready(path)
    writer.write_request(
        build_http_request_record(
            flow_id="flow-1",
            run_id="run-a",
            session_id="session-a",
            timestamp_utc="2026-07-24T00:00:00Z",
            method="GET",
            url="https://example.com/a?password=discarded",
        )
    )

    result = validate_traffic_jsonl(
        path,
        run_id="run-a",
        session_id="session-a",
        process_ready=True,
    )

    assert result.outcome is TrafficCollectionOutcome.SUCCESS_REQUESTS_OBSERVED
    assert result.coverage == "observed"
    assert result.valid_request_count == 1


class _Headers(dict[str, str]):
    pass


def test_addon_emits_ready_and_safe_request_without_mitmproxy(
    tmp_path: Path,
) -> None:
    path = tmp_path / "requests.jsonl"
    addon = SafeTrafficAddon(
        run_id="run-a",
        session_id="session-a",
        jsonl_path=path,
        utc_now=lambda: datetime(2026, 7, 24, tzinfo=timezone.utc),
    )
    addon.running()

    raw_token = "RAW_TOKEN_097ae0"
    request = SimpleNamespace(
        method="POST",
        scheme="https",
        host="EXAMPLE.COM.",
        port=443,
        path=f"/v1/device/{raw_token}?access_token={raw_token}&page=1",
        headers=_Headers(
            Authorization=f"Bearer {raw_token}",
            Cookie=f"sid={raw_token}",
        ),
        raw_content=f'{{"password":"{raw_token}"}}'.encode(),
        timestamp_start=1784851200.0,
    )
    response = SimpleNamespace(
        status_code=200,
        headers=_Headers({"Set-Cookie": f"sid={raw_token}"}),
        raw_content=f'{{"token":"{raw_token}"}}'.encode(),
    )
    flow = SimpleNamespace(
        id="flow-addon",
        request=request,
        response=response,
        error=None,
    )

    addon.request(flow)
    addon.response(flow)

    persisted = path.read_text(encoding="utf-8")
    lines = [json.loads(line) for line in persisted.splitlines()]
    assert lines[0]["event"] == "mitm_ready"
    assert lines[1]["type"] == "http_request"
    assert lines[1]["run_id"] == "run-a"
    assert lines[1]["session_id"] == "session-a"
    assert lines[1]["query_keys"] == ["access_token", "page"]
    assert raw_token not in persisted
    assert "Authorization" not in persisted
    assert "Cookie" not in persisted
    assert "Set-Cookie" not in persisted


def test_addon_sanitizes_raw_flow_error(tmp_path: Path) -> None:
    path = tmp_path / "requests.jsonl"
    addon = SafeTrafficAddon(
        run_id="run-a",
        session_id="session-a",
        jsonl_path=path,
        utc_now=lambda: datetime(2026, 7, 24, tzinfo=timezone.utc),
    )
    addon.running()
    raw_token = "ERROR_TOKEN_582b40"
    flow = SimpleNamespace(
        id="flow-error",
        request=SimpleNamespace(
            method="GET",
            scheme="https",
            host="example.com",
            port=443,
            path="/",
            headers={},
            raw_content=b"",
            timestamp_start=1784851200.0,
        ),
        response=None,
        error=SimpleNamespace(msg=f"TLS failed with token {raw_token}"),
    )

    addon.request(flow)
    addon.error(flow)

    persisted = path.read_text(encoding="utf-8")
    request_line = json.loads(persisted.splitlines()[1])
    assert request_line["error"] == "flow_error"
    assert raw_token not in persisted
