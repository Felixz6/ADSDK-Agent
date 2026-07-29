from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import math
from typing import Any, Literal, Mapping, Sequence

from pydantic import AliasChoices, BaseModel, ConfigDict, Field


CorrelationStatus = Literal[
    "evaluated",
    "not_evaluated",
    "no_observations",
    "error",
]
CorrelationConfidence = Literal["high", "medium", "low"]
ConsentState = Literal["pre_consent", "post_consent", "unknown"]
TimeSource = Literal["monotonic", "utc"]
ReasonCode = Literal[
    "monotonic_near",
    "utc_time_near",
    "same_consent_state",
    "unknown_consent_state",
    "time_only_correlation",
    "clock_unreliable",
    "consent_state_conflict",
    "outside_window",
]
SUPPORTED_REASON_CODES: frozenset[str] = frozenset(
    {
        "monotonic_near",
        "utc_time_near",
        "same_consent_state",
        "unknown_consent_state",
        "time_only_correlation",
        "clock_unreliable",
        "consent_state_conflict",
        "outside_window",
    }
)


class EvidenceCorrelationConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    window_ms: int = Field(default=2500, ge=100, le=10_000)
    max_candidates_per_event: int = Field(default=5, ge=1, le=20)


class DynamicEvidence(BaseModel):
    """Only the fields required for deterministic temporal correlation."""

    model_config = ConfigDict(extra="ignore")

    event_id: str
    event_type: str = "dynamic_event"
    run_id: str | None = None
    session_id: str | None = None
    timestamp_utc: datetime | None = Field(
        default=None,
        validation_alias=AliasChoices("timestamp_utc", "timestamp"),
    )
    monotonic_ms: float | None = None
    timing_reliable: bool = True
    consent_state: ConsentState = "unknown"


class NetworkEvidence(BaseModel):
    """Safe request metadata; sensitive request fields are intentionally absent."""

    model_config = ConfigDict(extra="ignore")

    request_id: str = Field(
        validation_alias=AliasChoices("request_id", "flow_id"),
    )
    request_host: str = Field(
        default="unknown",
        validation_alias=AliasChoices("request_host", "hostname", "host"),
    )
    request_method: str = Field(
        default="HTTP",
        validation_alias=AliasChoices("request_method", "method"),
    )
    run_id: str | None = None
    session_id: str | None = None
    timestamp_utc: datetime | None = Field(
        default=None,
        validation_alias=AliasChoices("timestamp_utc", "timestamp"),
    )
    monotonic_ms: float | None = None
    timing_reliable: bool = True
    consent_state: ConsentState = "unknown"


class CorrelationItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    correlation_id: str
    dynamic_event_id: str
    network_request_id: str
    event_type: str
    request_host: str
    request_method: str
    delta_ms: int
    consent_state: ConsentState
    confidence: CorrelationConfidence
    reason_codes: list[ReasonCode] = Field(default_factory=list)
    summary: str


class CorrelationSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    dynamic_event_count: int = Field(ge=0)
    network_request_count: int = Field(ge=0)
    correlated_pair_count: int = Field(ge=0)
    high_confidence_count: int = Field(ge=0)
    medium_confidence_count: int = Field(ge=0)
    low_confidence_count: int = Field(ge=0)


class EvidenceCorrelation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["correlation-v1"] = "correlation-v1"
    status: CorrelationStatus
    window_ms: int = Field(ge=100, le=10_000)
    items: list[CorrelationItem] = Field(default_factory=list)
    summary: CorrelationSummary
    limitations: list[str] = Field(default_factory=list)


def _finite_ms(value: float | None) -> float | None:
    if value is None:
        return None
    number = float(value)
    return number if math.isfinite(number) and number >= 0 else None


def _same_run(left: str | None, right: str | None) -> bool:
    return bool(left and right and left == right)


def _utc_ms(value: datetime | None) -> float | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return None
    return value.astimezone(timezone.utc).timestamp() * 1000.0


def _consent_compatible(left: ConsentState, right: ConsentState) -> bool:
    return left == "unknown" or right == "unknown" or left == right


def _combined_consent(left: ConsentState, right: ConsentState) -> ConsentState:
    if left == right:
        return left
    if left == "unknown":
        return right
    if right == "unknown":
        return left
    return "unknown"


def calculate_confidence(
    *,
    delta_ms: int,
    time_source: TimeSource,
    dynamic_consent_state: ConsentState,
    network_consent_state: ConsentState,
) -> CorrelationConfidence:
    """Apply the fixed correlation-v1 confidence thresholds."""

    same_known_consent = (
        dynamic_consent_state != "unknown"
        and dynamic_consent_state == network_consent_state
    )
    if time_source == "monotonic" and delta_ms <= 500 and same_known_consent:
        return "high"
    if (
        time_source == "monotonic"
        and delta_ms <= 1500
        and _consent_compatible(
            dynamic_consent_state,
            network_consent_state,
        )
    ):
        return "medium"
    return "low"


def build_correlation_summary(
    items: Sequence[CorrelationItem],
    *,
    dynamic_event_count: int,
    network_request_count: int,
) -> CorrelationSummary:
    return CorrelationSummary(
        dynamic_event_count=dynamic_event_count,
        network_request_count=network_request_count,
        correlated_pair_count=len(items),
        high_confidence_count=sum(item.confidence == "high" for item in items),
        medium_confidence_count=sum(item.confidence == "medium" for item in items),
        low_confidence_count=sum(item.confidence == "low" for item in items),
    )


def _stable_id(event_id: str, request_id: str) -> str:
    digest = hashlib.sha256(
        f"correlation-v1\0{event_id}\0{request_id}".encode("utf-8")
    ).hexdigest()
    return f"corr-{digest[:24]}"


def _event_type(raw: Mapping[str, Any], index: int) -> str:
    return str(
        raw.get("event_type")
        or raw.get("category")
        or raw.get("action")
        or raw.get("event")
        or f"dynamic_event_{index + 1}"
    )


def _validate_dynamic(
    raw: Mapping[str, Any],
    index: int,
) -> DynamicEvidence | None:
    payload = {
        **raw,
        "event_id": str(raw.get("event_id") or f"event-{index + 1}"),
        "event_type": _event_type(raw, index),
    }
    try:
        return DynamicEvidence.model_validate(payload)
    except (TypeError, ValueError):
        return None


def _validate_network(
    raw: Mapping[str, Any],
    index: int,
) -> NetworkEvidence | None:
    payload = {
        **raw,
        "request_id": str(
            raw.get("request_id")
            or raw.get("flow_id")
            or f"request-{index + 1}"
        ),
    }
    try:
        return NetworkEvidence.model_validate(payload)
    except (TypeError, ValueError):
        return None


def _classify_unknown_consent(
    state: ConsentState,
    *,
    timestamp_utc: datetime | None,
    consent_timestamp_utc: datetime | None,
) -> ConsentState:
    if state != "unknown":
        return state
    observed = _utc_ms(timestamp_utc)
    consent = _utc_ms(consent_timestamp_utc)
    if observed is None or consent is None:
        return "unknown"
    return "pre_consent" if observed < consent else "post_consent"


def _pair_delta(
    event: DynamicEvidence,
    request: NetworkEvidence,
) -> tuple[TimeSource, int] | None:
    if not event.timing_reliable or not request.timing_reliable:
        return None
    event_monotonic = _finite_ms(event.monotonic_ms)
    request_monotonic = _finite_ms(request.monotonic_ms)
    if (
        event_monotonic is not None
        and request_monotonic is not None
        and _same_run(event.run_id, request.run_id)
    ):
        return "monotonic", int(round(request_monotonic - event_monotonic))
    event_utc = _utc_ms(event.timestamp_utc)
    request_utc = _utc_ms(request.timestamp_utc)
    if (
        event_utc is not None
        and request_utc is not None
        and _same_run(event.run_id, request.run_id)
    ):
        return "utc", int(round(request_utc - event_utc))
    return None


def _empty_result(
    *,
    status: CorrelationStatus,
    config: EvidenceCorrelationConfig,
    dynamic_event_count: int,
    network_request_count: int,
    limitations: list[str],
) -> EvidenceCorrelation:
    return EvidenceCorrelation(
        status=status,
        window_ms=config.window_ms,
        summary=build_correlation_summary(
            [],
            dynamic_event_count=dynamic_event_count,
            network_request_count=network_request_count,
        ),
        limitations=limitations,
    )


def build_evidence_correlations(
    dynamic_events: Sequence[Mapping[str, Any]],
    network_requests: Sequence[Mapping[str, Any]],
    *,
    config: EvidenceCorrelationConfig | None = None,
    consent_timestamp_utc: datetime | str | None = None,
) -> EvidenceCorrelation:
    """Correlate existing observations by trustworthy time only.

    The result expresses temporal proximity, never causality. Inputs are copied
    into narrow Pydantic models and are not modified.
    """

    selected_config = config or EvidenceCorrelationConfig()
    raw_dynamic_count = len(dynamic_events)
    raw_network_count = len(network_requests)
    if raw_dynamic_count == 0 or raw_network_count == 0:
        missing = []
        if raw_dynamic_count == 0:
            missing.append("未观察到动态事件")
        if raw_network_count == 0:
            missing.append("未观察到网络请求")
        return _empty_result(
            status="no_observations",
            config=selected_config,
            dynamic_event_count=raw_dynamic_count,
            network_request_count=raw_network_count,
            limitations=missing,
        )

    consent_utc: datetime | None
    if isinstance(consent_timestamp_utc, str):
        try:
            consent_utc = datetime.fromisoformat(
                consent_timestamp_utc.replace("Z", "+00:00")
            )
        except ValueError:
            consent_utc = None
    else:
        consent_utc = consent_timestamp_utc

    events = [
        model
        for index, raw in enumerate(dynamic_events)
        if isinstance(raw, Mapping)
        and (model := _validate_dynamic(raw, index)) is not None
    ]
    requests = [
        model
        for index, raw in enumerate(network_requests)
        if isinstance(raw, Mapping)
        and (model := _validate_network(raw, index)) is not None
    ]
    comparable_time_seen = False
    items: list[CorrelationItem] = []

    for event in events:
        candidates: list[tuple[int, str, CorrelationItem]] = []
        event_consent = _classify_unknown_consent(
            event.consent_state,
            timestamp_utc=event.timestamp_utc,
            consent_timestamp_utc=consent_utc,
        )
        for request in requests:
            pair = _pair_delta(event, request)
            if pair is None:
                continue
            comparable_time_seen = True
            time_source, signed_delta = pair
            delta = abs(signed_delta)
            if delta > selected_config.window_ms:
                continue
            request_consent = _classify_unknown_consent(
                request.consent_state,
                timestamp_utc=request.timestamp_utc,
                consent_timestamp_utc=consent_utc,
            )
            if not _consent_compatible(event_consent, request_consent):
                continue
            confidence = calculate_confidence(
                delta_ms=delta,
                time_source=time_source,
                dynamic_consent_state=event_consent,
                network_consent_state=request_consent,
            )
            reasons = [
                "monotonic_near" if time_source == "monotonic" else "utc_time_near",
            ]
            if (
                event_consent != "unknown"
                and event_consent == request_consent
            ):
                reasons.append("same_consent_state")
            if "unknown" in {event_consent, request_consent}:
                reasons.append("unknown_consent_state")
            reasons.append("time_only_correlation")
            if time_source == "utc":
                reasons.append("clock_unreliable")
            summary = (
                f"时间差 {delta} ms，时间上接近，可能相关；"
                "该结果不表示事件触发了网络请求"
            )
            item = CorrelationItem(
                correlation_id=_stable_id(event.event_id, request.request_id),
                dynamic_event_id=event.event_id,
                network_request_id=request.request_id,
                event_type=event.event_type,
                request_host=request.request_host,
                request_method=request.request_method.upper(),
                delta_ms=signed_delta,
                consent_state=_combined_consent(
                    event_consent,
                    request_consent,
                ),
                confidence=confidence,
                reason_codes=reasons,
                summary=summary,
            )
            candidates.append((delta, request.request_id, item))
        candidates.sort(key=lambda value: (value[0], value[1]))
        items.extend(
            item
            for _delta, _request_id, item in candidates[
                : selected_config.max_candidates_per_event
            ]
        )

    if not comparable_time_seen:
        return _empty_result(
            status="not_evaluated",
            config=selected_config,
            dynamic_event_count=raw_dynamic_count,
            network_request_count=raw_network_count,
            limitations=[
                "事件与请求存在，但缺少同任务内可对齐的可信时间信息",
            ],
        )

    items.sort(
        key=lambda item: (
            abs(item.delta_ms),
            item.dynamic_event_id,
            item.network_request_id,
        )
    )
    limitations = [
        "关联仅表示时间接近或证据上可能相关，不证明因果关系",
    ]
    if not items:
        limitations.append("未观察到时间窗口内且 Consent 阶段兼容的关联证据")
    return EvidenceCorrelation(
        status="evaluated",
        window_ms=selected_config.window_ms,
        items=items,
        summary=build_correlation_summary(
            items,
            dynamic_event_count=raw_dynamic_count,
            network_request_count=raw_network_count,
        ),
        limitations=limitations,
    )


def build_error_correlation(
    *,
    window_ms: int,
    dynamic_event_count: int,
    network_request_count: int,
) -> EvidenceCorrelation:
    config = EvidenceCorrelationConfig(window_ms=window_ms)
    return _empty_result(
        status="error",
        config=config,
        dynamic_event_count=dynamic_event_count,
        network_request_count=network_request_count,
        limitations=["关联模块执行异常，主报告仍基于原始证据生成"],
    )
