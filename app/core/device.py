"""Immutable device targeting context."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

from .redaction import Redactor

CommandArgument = str | os.PathLike[str]


@dataclass(frozen=True, slots=True)
class DeviceContext:
    """Bind every ADB and Frida command to one immutable device serial."""

    serial: str = field(repr=False)
    redactor: Redactor = field(
        default_factory=Redactor,
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        normalized = self.serial.strip()
        if not normalized:
            raise ValueError("device serial must not be empty")
        if any(character in normalized for character in ("\x00", "\r", "\n")):
            raise ValueError("device serial contains invalid control characters")
        object.__setattr__(self, "serial", normalized)

    @staticmethod
    def _arguments(values: tuple[CommandArgument, ...]) -> list[str]:
        return [os.fspath(value) for value in values]

    def adb_command(self, *args: CommandArgument) -> list[str]:
        return ["adb", "-s", self.serial, *self._arguments(args)]

    def frida_command(
        self,
        tool: CommandArgument,
        *args: CommandArgument,
    ) -> list[str]:
        tool_name = os.fspath(tool).strip()
        if not tool_name:
            raise ValueError("Frida tool name must not be empty")
        return [tool_name, "-D", self.serial, *self._arguments(args)]

    @property
    def public_serial(self) -> str:
        redacted = self.redactor.redact_identifier(
            self.serial,
            kind="device_serial",
        )
        assert redacted is not None
        return redacted

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "serial": self.public_serial,
            "serial_token": self.public_serial,
            "raw_retained": False,
        }

    def __repr__(self) -> str:
        return f"DeviceContext(serial={self.public_serial!r})"
