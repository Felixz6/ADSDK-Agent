"""Deterministic pseudonymization for sensitive device identifiers."""

from __future__ import annotations

import hashlib
import hmac
import os
from collections.abc import Mapping
from typing import Any, Final

_PRIMARY_SECRET_ENV: Final = "REDACTION_HMAC_KEY"
_COMPAT_SECRET_ENVS: Final = (
    "ADSDK_REDACTION_SECRET",
    "ADSDK_AGENT_REDACTION_SECRET",
)
_DEVELOPMENT_SECRET: Final = (
    b"adsdk-agent-development-only-change-me"
)
_TOKEN_DOMAIN: Final = b"adsdk-agent/stable-token/v1\x00"
_IDENTIFIER_DOMAIN: Final = b"adsdk-agent/identifier/v1\x00"


def _as_bytes(value: str | bytes) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8")
    raise TypeError("value must be str or bytes")


class Redactor:
    """Create stable, non-reversible HMAC tokens.

    Production deployments should set ``REDACTION_HMAC_KEY`` to a stable
    private value.  The built-in key intentionally exists only so local
    development artifacts remain deterministic without extra configuration.
    """

    def __init__(
        self,
        secret: str | bytes | None = None,
        *,
        token_length: int = 20,
    ) -> None:
        configured = (
            os.getenv(_PRIMARY_SECRET_ENV)
            or next(
                (
                    value
                    for name in _COMPAT_SECRET_ENVS
                    if (value := os.getenv(name))
                ),
                None,
            )
        )
        selected = secret if secret is not None else configured
        if selected is None:
            selected = _DEVELOPMENT_SECRET

        secret_bytes = _as_bytes(selected)
        if not secret_bytes:
            raise ValueError("redaction secret must not be empty")
        if not 12 <= token_length <= hashlib.sha256().digest_size * 2:
            raise ValueError("token_length must be between 12 and 64")

        self._secret = secret_bytes
        self._token_length = token_length

    def _token(self, payload: bytes) -> str:
        return hmac.new(
            self._secret,
            payload,
            hashlib.sha256,
        ).hexdigest()[: self._token_length]

    def stable_token(self, value: str | bytes) -> str:
        """Return a deterministic short HMAC-SHA256 token for *value*."""

        return self._token(_TOKEN_DOMAIN + _as_bytes(value))

    def redact_identifier(
        self,
        value: str | bytes | None,
        kind: str | None = None,
    ) -> str | None:
        """Return a stable redaction token, preserving missing-value semantics."""

        if value is None:
            return None
        value_bytes = _as_bytes(value)
        if not value_bytes.strip():
            return None

        kind_bytes = (kind or "identifier").strip().casefold().encode("utf-8")
        token = self._token(
            _IDENTIFIER_DOMAIN
            + kind_bytes
            + b"\x00"
            + value_bytes
        )
        return f"redacted:{token}"

    def redact_text(
        self,
        text: str | None,
        identifiers: Mapping[str, str | bytes | None],
    ) -> str | None:
        """Replace known raw identifiers in free-form diagnostic text.

        The mapping key is the identifier type and the value is the raw value.
        Longer values are replaced first to avoid partial overlap.
        """

        if text is None:
            return None
        if not isinstance(text, str):
            raise TypeError("text must be str or None")

        replacements: list[tuple[str, str]] = []
        for kind, raw_value in identifiers.items():
            if raw_value is None:
                continue
            raw_text = (
                raw_value.decode("utf-8")
                if isinstance(raw_value, bytes)
                else raw_value
            )
            if not raw_text:
                continue
            token = self.redact_identifier(raw_value, kind=kind)
            if token is not None:
                replacements.append((raw_text, token))

        redacted = text
        for raw_text, token in sorted(
            replacements,
            key=lambda item: len(item[0]),
            reverse=True,
        ):
            redacted = redacted.replace(raw_text, token)
        return redacted


def extract_device_serials(
    device_info: Mapping[str, Any],
    requested_device_id: str | None = None,
) -> list[str]:
    serials: list[str] = []
    if requested_device_id:
        serials.append(requested_device_id)
    target = device_info.get("target")
    if isinstance(target, dict) and target.get("device_id"):
        serials.append(str(target["device_id"]))
    for item in device_info.get("devices") or []:
        if isinstance(item, dict) and item.get("device_id"):
            serials.append(str(item["device_id"]))
    return list(dict.fromkeys(serials))


_device_serials = extract_device_serials


def redact_known_device_serials(
    value: Any,
    serials: list[str],
    *,
    secret: str | bytes | None = None,
) -> Any:
    from app.config import REDACTION_HMAC_KEY

    redactor = Redactor(secret=secret if secret is not None else REDACTION_HMAC_KEY)

    def redact_text(text: str) -> str:
        result = text
        for serial in sorted(serials, key=len, reverse=True):
            token = redactor.redact_identifier(
                serial,
                kind="device_serial",
            )
            if token is not None:
                result = result.replace(serial, token)
        return result

    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, list):
        return [
            redact_known_device_serials(item, serials, secret=secret)
            for item in value
        ]
    if isinstance(value, tuple):
        return [
            redact_known_device_serials(item, serials, secret=secret)
            for item in value
        ]
    if isinstance(value, dict):
        return {
            key: redact_known_device_serials(item, serials, secret=secret)
            for key, item in value.items()
        }
    return value


_redact_known_device_serials = redact_known_device_serials


__all__ = [
    "Redactor",
    "_device_serials",
    "_redact_known_device_serials",
    "extract_device_serials",
    "redact_known_device_serials",
]

