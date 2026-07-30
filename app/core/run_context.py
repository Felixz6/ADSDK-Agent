from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
import re
from uuid import UUID, uuid4

from .paths import PathInput, sha256_file


_SHA256_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")
_UNSAFE_NAME_PATTERN = re.compile(r'[<>:"/\\|?*\x00-\x1f]+')
_WINDOWS_RESERVED_NAMES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{index}" for index in range(1, 10)),
    *(f"LPT{index}" for index in range(1, 10)),
}


@dataclass(frozen=True, slots=True)
class AnalysisRunContext:
    run_id: str
    apk_path: Path
    apk_sha256: str
    output_root: Path
    run_dir: Path
    unpacked_dir: Path
    hook_log_path: Path
    events_path: Path
    traffic_dir: Path
    traffic_summary_path: Path
    report_json_path: Path
    report_markdown_path: Path
    device_id: str | None = field(repr=False)
    normalized_apk_name: str
    started_at: datetime
    flow_file_path: Path
    mitm_stream_log_path: Path
    source_apk_path: Path | None = field(default=None, repr=False)
    source_apk_display: str | None = None
    apk_snapshot_relative_path: str | None = None
    apk_snapshot_size_bytes: int | None = None

    @property
    def input_dir(self) -> Path:
        return self.run_dir / "input"

    @property
    def apk_snapshot_path(self) -> Path:
        return self.input_dir / "app.apk"

    @property
    def events_raw_path(self) -> Path:
        return self.run_dir / "events.raw.jsonl"

    @property
    def traffic_jsonl_path(self) -> Path:
        return self.traffic_dir / "requests.jsonl"

    @property
    def mitm_stderr_path(self) -> Path:
        return self.traffic_dir / "mitm.stderr.log"

    @property
    def sessions_path(self) -> Path:
        return self.run_dir / "sessions.json"

    @property
    def report_html_path(self) -> Path:
        return self.run_dir / "report.html"

    @property
    def correlations_path(self) -> Path:
        return self.run_dir / "correlations.json"

    @property
    def privacy_findings_path(self) -> Path:
        return self.run_dir / "privacy-findings.json"


def _normalize_run_id(value: str | UUID | None) -> str:
    if value is None:
        return str(uuid4())
    try:
        return str(UUID(str(value)))
    except (ValueError, AttributeError) as exc:
        raise ValueError("run_id must be a valid UUID") from exc


def _normalize_sha256(value: str) -> str:
    if not _SHA256_PATTERN.fullmatch(value):
        raise ValueError("apk_sha256 must contain exactly 64 hexadecimal characters")
    return value.lower()


def _normalize_apk_name(apk_path: Path) -> str:
    name = _UNSAFE_NAME_PATTERN.sub("_", apk_path.stem).strip().rstrip(" .")
    name = re.sub(r"\s+", "_", name)
    if not name:
        name = "apk"
    if name.upper() in _WINDOWS_RESERVED_NAMES:
        name = f"_{name}"
    return name[:120]


def _normalize_started_at(value: datetime | None) -> datetime:
    if value is None:
        return datetime.now(timezone.utc)
    if value.tzinfo is None:
        raise ValueError("started_at must include timezone information")
    return value.astimezone(timezone.utc)


def create_analysis_run_context(
    apk_path: PathInput,
    output_root: PathInput,
    *,
    apk_sha256: str | None = None,
    run_id: str | UUID | None = None,
    device_id: str | None = None,
    started_at: datetime | None = None,
) -> AnalysisRunContext:
    """Create a unique, immutable run context before any external tool starts."""

    resolved_apk = Path(apk_path).resolve(strict=True)
    if not resolved_apk.is_file():
        raise FileNotFoundError(f"not a regular file: {resolved_apk}")

    resolved_output_root = Path(output_root).resolve(strict=False)
    normalized_run_id = _normalize_run_id(run_id)
    normalized_sha256 = (
        sha256_file(resolved_apk)
        if apk_sha256 is None
        else _normalize_sha256(apk_sha256)
    )
    normalized_device_id = device_id.strip() if device_id and device_id.strip() else None
    normalized_apk_name = _normalize_apk_name(resolved_apk)
    normalized_started_at = _normalize_started_at(started_at)

    run_dir = resolved_output_root / "runs" / normalized_run_id
    unpacked_dir = run_dir / "unpacked"
    traffic_dir = run_dir / "traffic"

    run_dir.mkdir(parents=True, exist_ok=False)
    unpacked_dir.mkdir()
    traffic_dir.mkdir()

    return AnalysisRunContext(
        run_id=normalized_run_id,
        apk_path=resolved_apk,
        apk_sha256=normalized_sha256,
        output_root=resolved_output_root,
        run_dir=run_dir,
        unpacked_dir=unpacked_dir,
        hook_log_path=run_dir / "hook.log",
        events_path=run_dir / "events.json",
        traffic_dir=traffic_dir,
        traffic_summary_path=run_dir / "traffic_summary.json",
        report_json_path=run_dir / "report.json",
        report_markdown_path=run_dir / "report.md",
        device_id=normalized_device_id,
        normalized_apk_name=normalized_apk_name,
        started_at=normalized_started_at,
        flow_file_path=traffic_dir / "flows.mitm",
        mitm_stream_log_path=traffic_dir / "mitm_stream.log",
    )
