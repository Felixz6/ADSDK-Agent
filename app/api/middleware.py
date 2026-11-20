"""ASGI middleware enforcing local-only writes to AI configuration endpoints."""

from __future__ import annotations

from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

_AI_SETTINGS_ALLOWED_ORIGINS = frozenset(
    {
        "http://127.0.0.1:5173",
        "http://localhost:5173",
    }
)
_AI_SETTINGS_PATHS = frozenset(
    {
        "/ai/settings",
        "/ai/settings/test",
        "/ai/settings/api-key",
    }
)
_AI_SETTINGS_WRITE_METHODS = frozenset({"PUT", "POST", "DELETE"})


def _client_is_loopback(client_host: str | None) -> bool:
    if not client_host:
        return False
    return client_host in {"127.0.0.1", "::1", "localhost", "testclient"}


def _origin_allowed_for_ai_settings(origin: str | None) -> bool:
    if not origin:
        return True
    return origin in _AI_SETTINGS_ALLOWED_ORIGINS


class AILocalOnlyMiddleware(BaseHTTPMiddleware):
    """Enforces host-only writes on sensitive AI settings endpoints."""

    async def dispatch(self, request: Request, call_next) -> Response:
        path = request.url.path
        method = request.method.upper()

        if path in _AI_SETTINGS_PATHS and method in _AI_SETTINGS_WRITE_METHODS:
            client_host = request.client.host if request.client else None
            if not _client_is_loopback(client_host):
                return JSONResponse(
                    status_code=403,
                    content={
                        "detail": "AI 配置写接口仅允许本机访问",
                        "error_code": "ai_settings_remote_client_forbidden",
                    },
                )
            origin = request.headers.get("origin")
            if not _origin_allowed_for_ai_settings(origin):
                return JSONResponse(
                    status_code=403,
                    content={
                        "detail": "非法 Origin",
                        "error_code": "ai_settings_origin_forbidden",
                    },
                )

        return await call_next(request)


__all__ = [
    "AILocalOnlyMiddleware",
    "_client_is_loopback",
    "_origin_allowed_for_ai_settings",
]
