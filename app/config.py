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
FRIDA_STOP_TIMEOUT_SECONDS = _env_positive_float(
    "FRIDA_STOP_TIMEOUT_SECONDS",
    5.0,
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
