"""``device-session-v1`` — read-only device snapshot captured before any
device-state-changing tool runs.

The snapshot is the single source of truth for *what the device looked like
before we touched it* so cleanup can restore exactly that. It deliberately
stores **no full serial**: only a stable masked ``device_ref`` plus boolean /
version / pid / port facts that are safe to persist and to show in the UI.

This module is pure (no I/O): the actual probes are injected through
:class:`SnapshotProbe`. Tests build snapshots from literals and never touch
ADB, so the schema, masking, and equality logic can be exercised without a
device.
"""

from __future__ import annotations

from typing import Any, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field

from app.core.redaction import Redactor

# ---------------------------------------------------------------------------
# Schema tag — versioned so future migrations can detect and refuse mismatched
# snapshots rather than silently mis-reading them.
# ---------------------------------------------------------------------------
DEVICE_SESSION_SCHEMA_VERSION: Literal["device-session-v1"] = "device-session-v1"


# ---------------------------------------------------------------------------
# Models. Every field is a safe observable fact; never a raw serial, never a
# cookie / auth / body, never a full proxy URL with credentials.
# ---------------------------------------------------------------------------
class DeviceState(BaseModel):
    """A snapshot of the mutable device state that cleanup must restore.

    ``http_proxy`` is the *original* device proxy read at snapshot time
    (``adb shell settings get global http_proxy``). Empty string means "no
    proxy was set"; ``None`` means we could not determine it (cleanup then
    leaves the proxy untouched rather than guessing).
    """

    model_config = ConfigDict(extra="forbid")

    online: bool = False
    boot_id: str | None = None
    abi: str | None = None
    android_release: str | None = None
    sdk_version: str | None = None
    http_proxy: str | None = None
    # Package-installation state we are *allowed* to observe (read-only).
    package_installed: bool | None = None
    package_version_name: str | None = None
    # Foreground packageName at snapshot time (current focus), or None.
    foreground_package: str | None = None
    # Whether a frida-server process was observed; ``owned`` is False unless
    # the registry confirms we started it.
    frida_server_present: bool | None = None
    frida_server_owned: bool = False
    frida_server_pid: int | None = None
    frida_server_version: str | None = None
    # mitm processes owned by *this* run — empty when none started yet.
    mitm_pids: list[int] = Field(default_factory=list)
    mitm_ports: list[int] = Field(default_factory=list)

    def safe_dump(self) -> dict[str, Any]:
        """Return a representation safe to persist/show (no masking needed here:
        nothing in this model is a secret identifier)."""
        return self.model_dump(mode="json")


class DeviceSessionSnapshot(BaseModel):
    """The ``device-session-v1`` artifact.

    Pairs an immutable masked device reference with a captured initial state.
    The full serial is never kept: ``device_ref`` is a stable token from the
    Redactor, sufficient to correlate artifacts within a run but useless to an
    observer who only reads the report or the database.
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["device-session-v1"] = DEVICE_SESSION_SCHEMA_VERSION
    run_id: str
    device_ref: str
    captured_at: str
    initial_state: DeviceState = Field(default_factory=DeviceState)
    # Free-form, secret-free environment notes (e.g. "MuMu x86_64 + Native
    # Bridge"). Treated as data, never instructions.
    environment_notes: list[str] = Field(default_factory=list)
    # Whether the snapshot is read-only-validated vs a full preflight. Phase B
    # produces read_only snapshots; Phase D re-captures before state changes.
    capture_kind: Literal["read_only", "preflight", "pre_state_change"] = (
        "read_only"
    )

    def safe_dump(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


# ---------------------------------------------------------------------------
# Injectable probe — the only place real ADB calls live. Tests inject a fake.
# ---------------------------------------------------------------------------
class SnapshotProbe(Protocol):
    """Read-only device probes. Implementations MUST NOT change device state."""

    def adb_devices(self) -> dict[str, Any]: ...
    def getprop(self, device: str, name: str) -> str | None: ...
    def settings_get(self, device: str, namespace: str, key: str) -> str | None: ...
    def pidof(self, device: str, process: str) -> list[int]: ...
    def frida_server_version(self, device: str) -> str | None: ...
    def current_focus(self, device: str) -> str | None: ...
    def pm_package_info(self, device: str, package: str) -> dict[str, Any]: ...


def mask_device_ref(device_id: str | None) -> str:
    """Return a stable masked token for a device serial, or ``__no_device__``."""
    if not device_id:
        return "__no_device__"
    token = Redactor().redact_identifier(device_id, kind="device_serial")
    return token or "__no_device__"


def build_snapshot(
    *,
    run_id: str,
    device_id: str | None,
    probe: SnapshotProbe,
    captured_at: str,
    package_name: str | None = None,
    capture_kind: Literal["read_only", "preflight", "pre_state_change"] = (
        "read_only"
    ),
    environment_notes: list[str] | None = None,
) -> DeviceSessionSnapshot:
    """Capture a read-only snapshot using ``probe``.

    The probe is read-only by contract; this function issues no mutating ADB
    command. Any probe-level failure degrades gracefully (the corresponding
    field becomes ``None``) rather than aborting the snapshot.
    """
    if not device_id:
        return DeviceSessionSnapshot(
            run_id=run_id,
            device_ref="__no_device__",
            captured_at=captured_at,
            initial_state=DeviceState(),
            environment_notes=list(environment_notes or []),
            capture_kind=capture_kind,
        )

    state = DeviceState()
    try:
        devices = probe.adb_devices()
    except BaseException:
        devices = {}
    online = isinstance(devices, dict) and any(
        str(item.get("device_id") or "") == device_id
        and str(item.get("status") or "") == "device"
        for item in devices.get("devices", [])
    )
    state.online = online

    def _prop(name: str) -> str | None:
        try:
            return probe.getprop(device_id, name)
        except BaseException:
            return None

    state.abi = _prop("ro.product.cpu.abi")
    state.android_release = _prop("ro.build.version.release")
    state.sdk_version = _prop("ro.build.version.sdk")
    state.boot_id = _prop("ro.boot.boot_id") or _prop("ro.bootime.boot_id")

    try:
        state.http_proxy = probe.settings_get(
            device_id, "global", "http_proxy"
        )
    except BaseException:
        state.http_proxy = None
    # Normalise: adb returns "" or ":0" (or, on some MuMu builds, the literal
    # string ":null") for "no proxy set" with exit code 0. Treat all of these
    # as empty so cleanup deletes the proxy rather than writing back a bogus
    # ":null"/":0" value. A genuine proxy URL never looks like these.
    if state.http_proxy is not None and state.http_proxy.strip() in {
        "",
        ":0",
        ":null",
    }:
        state.http_proxy = ""

    try:
        pids = probe.pidof(device_id, "frida-server")
    except BaseException:
        pids = []
    state.frida_server_present = bool(pids) if online else None
    state.frida_server_pid = pids[0] if pids else None
    state.frida_server_version = (
        probe.frida_server_version(device_id) if pids else None
    )

    try:
        state.foreground_package = probe.current_focus(device_id)
    except BaseException:
        state.foreground_package = None

    if package_name:
        try:
            info = probe.pm_package_info(device_id, package_name)
            state.package_installed = bool(info.get("installed"))
            state.package_version_name = info.get("version_name")
        except BaseException:
            state.package_installed = None

    return DeviceSessionSnapshot(
        run_id=run_id,
        device_ref=mask_device_ref(device_id),
        captured_at=captured_at,
        initial_state=state,
        environment_notes=list(environment_notes or []),
        capture_kind=capture_kind,
    )


# Re-export run so static checkers see the import is used (kept for parity
# with other modules that compose snapshot capture into a run helper).
__all__ = [
    "DEVICE_SESSION_SCHEMA_VERSION",
    "DeviceSessionSnapshot",
    "DeviceState",
    "SnapshotProbe",
    "build_snapshot",
    "mask_device_ref",
]
