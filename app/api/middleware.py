"""ASGI middleware enforcing local-only writes and Origin checks."""

from __future__ import annotations

from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from app import config as app_config

_AI_SETTINGS_PATHS = frozenset(
    {
        "/ai/settings",
        "/ai/settings/test",
        "/ai/settings/api-key",
    }
)
_WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "::ffff:127.0.0.1", "localhost", "testclient"})


def _client_is_loopback(client_host: str | None) -> bool:
    if not client_host:
        return False
    return client_host in _LOOPBACK_HOSTS


def is_origin_allowed(origin: str | None) -> bool:
    """Return True if Origin is absent (non-browser) or present in configured ALLOWED_ORIGINS."""
    if not origin:
        return True
    normalized = origin.strip().rstrip("/")
    allowed = {item.strip().rstrip("/") for item in app_config.ALLOWED_ORIGINS}
    return normalized in allowed


def _origin_allowed_for_ai_settings(origin: str | None) -> bool:
    return is_origin_allowed(origin)


def is_websocket_allowed(client_host: str | None, origin: str | None) -> bool:
    """Validate WebSocket handshake client host and Origin header."""
    if not is_origin_allowed(origin):
        return False
    if not app_config.ALLOW_REMOTE_WRITES and not _client_is_loopback(client_host):
        return False
    return True


class AILocalOnlyMiddleware(BaseHTTPMiddleware):
    """Enforces loopback and Origin guards on write endpoints (always strict for AI settings)."""

    async def dispatch(self, request: Request, call_next) -> Response:
        path = request.url.path
        method = request.method.upper()

        if method in _WRITE_METHODS:
            is_ai_settings = path in _AI_SETTINGS_PATHS
            if is_ai_settings or not app_config.ALLOW_REMOTE_WRITES:
                client_host = request.client.host if request.client else None
                if not _client_is_loopback(client_host):
                    return JSONResponse(
                        status_code=403,
                        content={
                            "detail": (
                                "AI 配置写接口仅允许本机访问"
                                if is_ai_settings
                                else "写接口仅允许本机访问"
                            ),
                            "error_code": (
                                "ai_settings_remote_client_forbidden"
                                if is_ai_settings
                                else "remote_client_forbidden"
                            ),
                        },
                    )
                origin = request.headers.get("origin")
                if not is_origin_allowed(origin):
                    return JSONResponse(
                        status_code=403,
                        content={
                            "detail": "非法 Origin",
                            "error_code": (
                                "ai_settings_origin_forbidden"
                                if is_ai_settings
                                else "origin_forbidden"
                            ),
                        },
                    )

        return await call_next(request)


__all__ = [
    "AILocalOnlyMiddleware",
    "_client_is_loopback",
    "_origin_allowed_for_ai_settings",
    "is_origin_allowed",
    "is_websocket_allowed",
]
