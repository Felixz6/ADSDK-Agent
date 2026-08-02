import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent
OUTPUT_DIR = str(BASE_DIR / "output")
TASK_DATABASE_PATH = (
    os.getenv("TASK_DATABASE_PATH", "").strip()
    or str(Path(OUTPUT_DIR) / "state" / "adsdk-agent.db")
)
SAMPLES_DIR = str(BASE_DIR / "samples")
STATIC_UNPACK_CACHE_DIR = (
    os.getenv("STATIC_UNPACK_CACHE_DIR", "").strip()
    or str(Path(OUTPUT_DIR) / "cache" / "static-unpack")
)

# 当前未使用,预留后续 AI 辅助分析扩展。
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
DEFAULT_HOST = os.getenv("HOST", "127.0.0.1")
DEFAULT_PORT = int(os.getenv("PORT", "8000"))

# 子进程默认超时(秒)。集中管理,避免魔法数字散落各 runner。
ADB_TIMEOUT = int(os.getenv("ADB_TIMEOUT", "120"))
APKTOOL_TIMEOUT = int(os.getenv("APKTOOL_TIMEOUT", "1800"))
FRIDA_CHECK_TIMEOUT = 10


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_positive_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    value = default if raw is None or not raw.strip() else float(raw)
    if value <= 0:
        raise ValueError(f"{name} must be greater than zero")
    return value


def _env_port(name: str, default: int) -> int:
    raw = os.getenv(name)
    value = default if raw is None or not raw.strip() else int(raw)
    if not 1 <= value <= 65535:
        raise ValueError(f"{name} must be between 1 and 65535")
    return value


def _env_int_range(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = os.getenv(name)
    value = default if raw is None or not raw.strip() else int(raw)
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


def _parse_allowed_roots(raw: str | None) -> tuple[Path, ...]:
    """Parse a semicolon-separated list without treating a drive colon as a separator."""
    if not raw or not raw.strip():
        return (Path(SAMPLES_DIR).resolve(),)
    roots = []
    for item in raw.split(";"):
        value = item.strip()
        if value:
            roots.append(Path(value).expanduser().resolve())
    return tuple(roots) or (Path(SAMPLES_DIR).resolve(),)


# APK input boundary. The default accepts only the project's samples directory;
# additional local folders must be explicitly listed in .env.
APK_ALLOWED_ROOTS = _parse_allowed_roots(os.getenv("APK_ALLOWED_ROOTS"))
APK_MAX_SIZE_MB = int(os.getenv("APK_MAX_SIZE_MB", "1024"))
APK_MAX_SIZE_BYTES = APK_MAX_SIZE_MB * 1024 * 1024
ALLOW_UNC_APK_PATHS = _env_bool("ALLOW_UNC_APK_PATHS", default=False)

# Run-owned dynamic collector sessions. ``MITM_PORT`` remains a compatibility
# alias for deployments that have not yet moved to an explicit port pool.
FRIDA_READY_TIMEOUT_SECONDS = _env_positive_float(
    "FRIDA_READY_TIMEOUT_SECONDS",
    15.0,
)
FRIDA_SPAWN_STABILITY_SECONDS = _env_positive_float(
    "FRIDA_SPAWN_STABILITY_SECONDS",
    3.0,
)
FRIDA_STOP_TIMEOUT_SECONDS = _env_positive_float(
    "FRIDA_STOP_TIMEOUT_SECONDS",
    5.0,
)
FRIDA_SERVER_MANAGEMENT_ENABLED = _env_bool(
    "FRIDA_SERVER_MANAGEMENT_ENABLED",
    default=False,
)
FRIDA_SERVER_LOCAL_PATH = os.getenv("FRIDA_SERVER_LOCAL_PATH", "").strip()
FRIDA_SERVER_REMOTE_PATH = (
    os.getenv("FRIDA_SERVER_REMOTE_PATH", "").strip()
    or "/data/local/tmp/frida-server"
)
FRIDA_SERVER_START_TIMEOUT_SECONDS = _env_positive_float(
    "FRIDA_SERVER_START_TIMEOUT_SECONDS",
    10.0,
)
FRIDA_SERVER_HANDSHAKE_TIMEOUT_SECONDS = _env_positive_float(
    "FRIDA_SERVER_HANDSHAKE_TIMEOUT_SECONDS",
    10.0,
)
FRIDA_SERVER_STOP_ON_TASK_END = _env_bool(
    "FRIDA_SERVER_STOP_ON_TASK_END",
    default=False,
)
MITM_READY_TIMEOUT_SECONDS = _env_positive_float(
    "MITM_READY_TIMEOUT_SECONDS",
    10.0,
)
MITM_STOP_TIMEOUT_SECONDS = _env_positive_float(
    "MITM_STOP_TIMEOUT_SECONDS",
    5.0,
)
_LEGACY_MITM_PORT = _env_port("MITM_PORT", 8080)
MITM_PORT_START = _env_port("MITM_PORT_START", _LEGACY_MITM_PORT)
MITM_PORT_END = _env_port("MITM_PORT_END", MITM_PORT_START)
if MITM_PORT_END < MITM_PORT_START:
    raise ValueError("MITM_PORT_END must be greater than or equal to MITM_PORT_START")
DEFAULT_MITM_PORT = MITM_PORT_START
EVIDENCE_CORRELATION_WINDOW_MS = _env_int_range(
    "EVIDENCE_CORRELATION_WINDOW_MS",
    2500,
    100,
    10_000,
)

# Host interface mitmdump binds to. Defaults to ``127.0.0.1`` (host loopback),
# which is correct for analysis pipelines that share the host's loopback with the
# traffic origin. For emulators whose guest cannot reach the host loopback
# (e.g. MuMu: guest ``127.0.0.1`` is its own loopback, while the QEMU gateway
# ``10.0.2.2`` is the host-side address), set ``MITM_LISTEN_HOST=0.0.0.0`` and
# point the device proxy at ``10.0.2.2:<port>``. No default is changed for
# non-emulator deployments unless this env var is set.
MITM_LISTEN_HOST = os.getenv("MITM_LISTEN_HOST", "127.0.0.1").strip()
MITM_DEVICE_PROXY_HOST = (
    os.getenv("MITM_DEVICE_PROXY_HOST", "").strip() or None
)

# Development fallback only. Deployments should set a stable random value in .env.
REDACTION_HMAC_KEY = os.getenv(
    "REDACTION_HMAC_KEY",
    "adsdk-agent-development-only-change-me",
)

SCHEMA_VERSION = "1.0"


# ---------------------------------------------------------------------------
# AI orchestration (M6A).
#
# Everything here defaults OFF: enabling AI must never change existing
# deterministic analysis or report behaviour. API keys are read from the
# environment only and never logged/persisted by config. The AI module owns
# its own redaction; this block only captures raw configurable surface.
# ---------------------------------------------------------------------------
AI_ENABLED = _env_bool("AI_ENABLED", default=False)
AI_PROVIDER = os.getenv("AI_PROVIDER", "openai_compatible").strip() or (
    "openai_compatible"
)

# API key: env var only. Never read a literal value here; never log it.
AI_API_KEY = os.getenv("AI_API_KEY", "")
AI_BASE_URL = os.getenv("AI_BASE_URL", "").strip()
AI_MODEL = os.getenv("AI_MODEL", "").strip()
AI_TIMEOUT_SECONDS = _env_int_range("AI_TIMEOUT_SECONDS", 60, 1, 600)
AI_MAX_ROUNDS = _env_int_range("AI_MAX_ROUNDS", 2, 1, 6)
AI_MAX_TOOL_CALLS = _env_int_range("AI_MAX_TOOL_CALLS", 6, 1, 20)
AI_MAX_INPUT_TOKENS = _env_int_range("AI_MAX_INPUT_TOKENS", 6000, 512, 65536)
AI_MAX_OUTPUT_TOKENS = _env_int_range("AI_MAX_OUTPUT_TOKENS", 1800, 128, 16384)
AI_MAX_TOOL_RESULT_CHARS = _env_int_range(
    "AI_MAX_TOOL_RESULT_CHARS", 8000, 256, 65536
)

# M6C — DeepSeek runtime compatibility & low-token orchestration.
#
# Compatibility profile selection. ``auto`` detects from base_url host
# (api.deepseek.com -> deepseek); ``generic_openai`` forces the OpenAI
# baseline; explicit ``deepseek`` is for diagnostics/overrides.
AI_PROVIDER_PROFILE = os.getenv("AI_PROVIDER_PROFILE", "auto").strip() or "auto"
# Thinking mode handling. ``disabled`` always emits
# ``extra_body={"thinking": {"type": "disabled"}}`` so DeepSeek returns no
# reasoning_content and behaves deterministically. ``auto`` emits it only for
# detected DeepSeek hosts; ``off`` never emits it (provider default).
AI_THINKING_MODE = os.getenv("AI_THINKING_MODE", "disabled").strip() or "disabled"
# Per-stage output-token caps. The orchestrator takes
# min(stage_cap, global AI_MAX_OUTPUT_TOKENS, remaining budget) so a stage can
# never exceed the global ceiling, and each stage has its own bound that keeps
# planner/report/repair answers tight (low-token acceptance).
AI_PLANNER_MAX_OUTPUT_TOKENS = _env_int_range(
    "AI_PLANNER_MAX_OUTPUT_TOKENS", 500, 64, 4000
)
AI_REPORT_MAX_OUTPUT_TOKENS = _env_int_range(
    "AI_REPORT_MAX_OUTPUT_TOKENS", 1000, 128, 8000
)
AI_REPAIR_MAX_OUTPUT_TOKENS = _env_int_range(
    "AI_REPAIR_MAX_OUTPUT_TOKENS", 300, 64, 2000
)
# Retry-with-backoff. At most 1 retry by default (capped at 3). Base delay in
# ms; actual delay respects the server's Retry-After header up to
# AI_MAX_RETRY_AFTER_SECONDS, then falls back to exponential base-delay jitter
# derived deterministically from the attempt (no real randomness so tests are
# reproducible).
AI_REQUEST_RETRIES = _env_int_range("AI_REQUEST_RETRIES", 1, 0, 3)
AI_RETRY_BASE_DELAY_MS = _env_int_range(
    "AI_RETRY_BASE_DELAY_MS", 200, 0, 5000
)
AI_MAX_RETRY_AFTER_SECONDS = _env_int_range(
    "AI_MAX_RETRY_AFTER_SECONDS", 30, 1, 300
)
# When True, store a short sanitized excerpt of the model response in the
# reasoning audit trail. When False (default) no model response text is kept on
# disk beyond the validated report artifact. Disabled by default per spec.
AI_STORE_RESPONSE_EXCERPTS = _env_bool(
    "AI_STORE_RESPONSE_EXCERPTS", default=False
)
AI_CACHE_ENABLED = _env_bool("AI_CACHE_ENABLED", default=True)
AI_CACHE_TTL_SECONDS = _env_int_range("AI_CACHE_TTL_SECONDS", 86400, 60, 604800)
AI_REPORT_LANGUAGE = os.getenv("AI_REPORT_LANGUAGE", "zh-CN").strip() or "zh-CN"
# When False, dynamic/device-touching tools are never offered to the model
# regardless of the task objective (defense-in-depth on the capability router).
AI_ALLOW_DYNAMIC_TOOLS = _env_bool("AI_ALLOW_DYNAMIC_TOOLS", default=False)
# Tagged version of the system prompt / tool definitions. Bump it when the
# prompt or tool schemas change; it is part of the cache key so cached answers
# are not reused against a different prompt surface.
AI_PROMPT_VERSION = os.getenv("AI_PROMPT_VERSION", "ai-plan-v1.1").strip() or (
    "ai-plan-v1.1"
)

# ---------------------------------------------------------------------------
# M7A — full-analysis orchestration (device lease + consent checkpoint).
# ---------------------------------------------------------------------------
# How long a device lease may go without a heartbeat before another run may
# reclaim it. A lease whose holder is still alive is never stolen regardless of
# this value; the window only bounds recovery after a crash.
M7A_LEASE_STALE_SECONDS = _env_int_range(
    "M7A_LEASE_STALE_SECONDS", 600, 30, 86400
)
# Upper bound on how long the orchestrator waits for the operator to resolve a
# consent checkpoint. Reaching it NEVER auto-confirms consent — the wait exits
# so cleanup can run and the run is recorded as partial.
M7A_CONSENT_WAIT_SECONDS = _env_int_range(
    "M7A_CONSENT_WAIT_SECONDS", 900, 30, 86400
)
