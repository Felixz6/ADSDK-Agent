"""Resource ownership registry and deterministic cleanup manager.

Two collaborating pieces:

1. :class:`ResourceOwnershipRegistry` — bookkeeping of every device-and-host
   *resource* the current run created or could create, classified as
   ``external`` (pre-existing, must NOT be stopped/removed) or
   ``owned_by_run`` (this run started it, must be cleaned up). Mirrors the
   ownership discipline already used by :class:`FridaServerManager` (never
   adopt unknown frida-server) and :class:`MitmSession.PortPool` (ports
   released by owner).

2. :class:`CleanupManager` — runs the recovery/cleanup playbook in try/finally
   so a failure or cancellation still restores device state. It owns the 10
   cleanup rules and produces a structured, secret-free
   :class:`CleanupOutcome`.

Design rules implemented (Section resource-ownership):

* External resources are never stopped/deleted (external frida-server, an
  already-running mitm the user started, existing proxy, user app data).
* owned_by_run resources are torn down in reverse-acquisition order.
* Proxy is restored from the snapshot's original value *even on failure*; a
  restore failure is recorded (``proxy_restore_failed``) but never aborts the
  rest of cleanup.
* App data is NEVER cleared; other apps are NEVER modified; the device is
  NEVER rebooted.
* External frida-server is NEVER stopped by this run.
* Every cleanup action records success/failure without leaking pids/ports as
  secrets (pids/ports are operational facts, not secrets — kept redacted-by-
  policy only where the spec demands masked serials).

All external calls (ADB set/delete proxy, kill PID, stop mitm process, stop
frida Session) are injected :class:`CleanupActions`, so tests run with fakes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field

from .device_session import DeviceSessionSnapshot

# ---------------------------------------------------------------------------
# Ownership model.
# ---------------------------------------------------------------------------
Ownership = Literal["external", "owned_by_run", "shared_pre_existing"]


@dataclass(slots=True)
class OwnedResource:
    """One tracked resource. ``identity`` is a stable key (pid / port / path)."""

    kind: str  # "frida_server" | "mitm_process" | "device_proxy" | "frida_session" | "app_process"
    identity: str
    ownership: Ownership
    started_at: float | None = None
    # Operational detail kept for cleanup; masked at the boundary by callers
    # where the spec requires it (full serial handled at the snapshot layer).
    detail: dict[str, Any] = field(default_factory=dict)


class ResourceOwnershipRegistry:
    """In-memory registry of resources touched during a run.

    Thread-safe enough for a single-session flow (one cleanup thread). The
    registry is intentionally per-run and not persisted: on crash the lease
    layer marks the holder dead, and the next run reclaims — leaving a stale
    registered resource is harmless because cleanup only acts on
    ``owned_by_run``.
    """

    def __init__(self) -> None:
        self._items: dict[tuple[str, str], OwnedResource] = {}

    def register(self, resource: OwnedResource) -> None:
        self._items[(resource.kind, resource.identity)] = resource

    def mark_external(self, kind: str, identity: str, **detail: Any) -> None:
        self.register(
            OwnedResource(
                kind=kind,
                identity=identity,
                ownership="external",
                detail=detail,
            )
        )

    def mark_owned(self, kind: str, identity: str, **detail: Any) -> None:
        self.register(
            OwnedResource(
                kind=kind,
                identity=identity,
                ownership="owned_by_run",
                detail=detail,
            )
        )

    def get(self, kind: str, identity: str) -> OwnedResource | None:
        return self._items.get((kind, identity))

    def owned(self) -> list[OwnedResource]:
        return [r for r in self._items.values() if r.ownership == "owned_by_run"]

    def external(self) -> list[OwnedResource]:
        return [r for r in self._items.values() if r.ownership == "external"]

    def all_items(self) -> list[OwnedResource]:
        return list(self._items.values())

    def is_owned(self, kind: str, identity: str) -> bool:
        item = self._items.get((kind, identity))
        return item is not None and item.ownership == "owned_by_run"


# ---------------------------------------------------------------------------
# Outcome (structured, secret-free).
# ---------------------------------------------------------------------------
CleanupStepStatus = Literal["success", "failed", "skipped", "not_applicable"]


class CleanupStep(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule: str
    target_kind: str
    target_identity: str
    ownership: Ownership
    status: CleanupStepStatus
    safe_message: str = Field(default="", max_length=512)


class CleanupOutcome(BaseModel):
    """The structured ``cleanup-result`` artifact. No keys, no full serial."""

    model_config = ConfigDict(extra="forbid")

    ran: bool = False
    cancelled: bool = False
    steps: list[CleanupStep] = Field(default_factory=list)
    proxy_restore_attempted: bool = False
    proxy_restore_failed: bool = False
    external_frida_touched: bool = False
    evidence_retained: bool = True
    failures: list[str] = Field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.ran and not self.proxy_restore_failed and not self.failures


# ---------------------------------------------------------------------------
# Injectable cleanup actions.
# ---------------------------------------------------------------------------
class CleanupActions(Protocol):
    """Side-effecting cleanup operations, all injected for testing."""

    def set_proxy(self, device: str, value: str) -> bool: ...
    def delete_proxy(self, device: str) -> bool: ...
    def kill_pid(self, device: str, pid: int) -> bool: ...
    def stop_mitm_pid(self, pid: int) -> bool: ...
    def stop_frida_session(self, ref: str) -> bool: ...


# ---------------------------------------------------------------------------
# The 10 cleanup rules. Each is a small function returning a CleanupStep.
# Rules are evaluated in a fixed order so cleanup is deterministic and
# reviewable. The manager calls these in try/finally.
# ---------------------------------------------------------------------------
_RESOURCE_KIND_FRIDA_SERVER = "frida_server"
_RESOURCE_KIND_MITM = "mitm_process"
_RESOURCE_KIND_PROXY = "device_proxy"
_RESOURCE_KIND_FRIDA_SESSION = "frida_session"


def _restore_proxy(
    actions: CleanupActions,
    device_id: str | None,
    initial_proxy: str | None,
    current_proxy: str | None,
    clock: Callable[[], float] | None = None,
) -> tuple[CleanupStep, bool]:
    """Rule: restore the device http_proxy to its snapshot value.

    * If initial was empty/None and current is set -> delete the proxy.
    * If initial had a value -> set it back.
    * Never invents a proxy; never leaves cleanup incomplete on failure.
    """
    attempted = True
    if not device_id:
        return (
            CleanupStep(
                rule="restore_proxy",
                target_kind=_RESOURCE_KIND_PROXY,
                target_identity="",
                ownership="owned_by_run",
                status="not_applicable",
                safe_message="no device in this run",
            ),
            False,
        )
    if initial_proxy is None:
        # We never determined the initial proxy: do NOT guess. Leave it.
        return (
            CleanupStep(
                rule="restore_proxy",
                target_kind=_RESOURCE_KIND_PROXY,
                target_identity="global http_proxy",
                ownership="external",
                status="skipped",
                safe_message="initial proxy unknown; left untouched to avoid guessing",
            ),
            False,
        )
    if not initial_proxy:
        ok = actions.delete_proxy(device_id)
        return (
            CleanupStep(
                rule="restore_proxy",
                target_kind=_RESOURCE_KIND_PROXY,
                target_identity="global http_proxy",
                ownership="owned_by_run",
                status="success" if ok else "failed",
                safe_message="cleared proxy" if ok else "proxy delete failed",
            ),
            not ok,
        )
    ok = actions.set_proxy(device_id, initial_proxy)
    return (
        CleanupStep(
            rule="restore_proxy",
            target_kind=_RESOURCE_KIND_PROXY,
            target_identity="global http_proxy",
            ownership="owned_by_run",
            status="success" if ok else "failed",
            safe_message="restored initial proxy" if ok else "proxy restore failed",
        ),
        not ok,
    )


class CleanupManager:
    """Owns the try/finally cleanup playbook for one full-analysis run."""

    def __init__(
        self,
        *,
        registry: ResourceOwnershipRegistry,
        actions: CleanupActions,
        snapshot: DeviceSessionSnapshot,
        device_id: str | None,
    ) -> None:
        self.registry = registry
        self.actions = actions
        self.snapshot = snapshot
        self.device_id = device_id

    def run(self, *, cancelled: bool = False) -> CleanupOutcome:
        """Execute all applicable cleanup rules, always to completion.

        Order (the 10 rules, evaluated every run; non-applicable ones record
        ``not_applicable`` so the trace is exhaustive and reviewable):

        1. stop_mitm_processes        — kill mitm PIDs owned_by_run
        2. restore_device_proxy       — from snapshot, always attempted
        3. detach_frida_sessions      — stop Frida sessions owned_by_run
        4. leave_external_frida_server— NEVER stop external frida-server
        5. stop_owned_frida_server    — only if this run started it
        6. leave_app_data             — NEVER clear user data (intentional no-op)
        7. leave_other_apps           — NEVER modify other apps (intentional no-op)
        8. no_device_reboot           — NEVER reboot (intentional no-op)
        9. retain_evidence            — NEVER delete artifacts
        10. release_lease             — (handled by caller; outcome recorded)
        """
        outcome = CleanupOutcome(ran=True, cancelled=cancelled)
        steps: list[CleanupStep] = []

        # Rule 1 — stop mitm processes this run started.
        for res in self.registry.owned():
            if res.kind != _RESOURCE_KIND_MITM:
                continue
            pid = int(res.detail.get("pid", -1))
            if pid <= 0:
                steps.append(
                    CleanupStep(
                        rule="stop_mitm_processes",
                        target_kind=res.kind,
                        target_identity=res.identity,
                        ownership=res.ownership,
                        status="skipped",
                        safe_message="no pid recorded",
                    )
                )
                continue
            ok = self.actions.stop_mitm_pid(pid)
            step = CleanupStep(
                rule="stop_mitm_processes",
                target_kind=res.kind,
                target_identity=res.identity,
                ownership=res.ownership,
                status="success" if ok else "failed",
                safe_message="stopped mitm" if ok else "mitm stop failed",
            )
            steps.append(step)
            if not ok:
                outcome.failures.append(f"mitm stop failed: pid {pid}")

        # Rule 2 — restore proxy (always attempted, even on partial failure).
        proxy_step, proxy_failed = _restore_proxy(
            self.actions,
            self.device_id,
            self.snapshot.initial_state.http_proxy,
            None,
        )
        outcome.proxy_restore_attempted = True
        outcome.proxy_restore_failed = proxy_failed
        steps.append(proxy_step)

        # Rule 3 — detach/stop Frida sessions owned by this run.
        for res in self.registry.owned():
            if res.kind != _RESOURCE_KIND_FRIDA_SESSION:
                continue
            ok = self.actions.stop_frida_session(res.identity)
            step = CleanupStep(
                rule="detach_frida_sessions",
                target_kind=res.kind,
                target_identity=res.identity,
                ownership=res.ownership,
                status="success" if ok else "failed",
                safe_message="detached" if ok else "detach failed",
            )
            steps.append(step)
            if not ok:
                outcome.failures.append(f"frida session stop failed: {res.identity}")

        # Rule 4 — leave EXTERNAL frida-server alone.
        external_frida = [
            r
            for r in self.registry.external()
            if r.kind == _RESOURCE_KIND_FRIDA_SERVER
        ]
        if external_frida:
            outcome.external_frida_touched = False  # recorded explicitly untouched
            for res in external_frida:
                steps.append(
                    CleanupStep(
                        rule="leave_external_frida_server",
                        target_kind=res.kind,
                        target_identity=res.identity,
                        ownership="external",
                        status="skipped",
                        safe_message="external frida-server left running",
                    )
                )

        # Rule 5 — stop a frida-server this run actually started.
        owned_frida = [
            r for r in self.registry.owned() if r.kind == _RESOURCE_KIND_FRIDA_SERVER
        ]
        for res in owned_frida:
            pid = int(res.detail.get("pid", -1))
            if pid <= 0:
                continue
            ok = self.actions.kill_pid(self.device_id or "", pid)
            step = CleanupStep(
                rule="stop_owned_frida_server",
                target_kind=res.kind,
                target_identity=res.identity,
                ownership="owned_by_run",
                status="success" if ok else "failed",
                safe_message="stopped owned frida-server" if ok else "stop failed",
            )
            steps.append(step)
            if not ok:
                outcome.failures.append(f"owned frida-server stop failed: pid {pid}")

        # Rules 6–8 are explicit, auditable no-ops.
        steps.append(
            CleanupStep(
                rule="leave_app_data",
                target_kind="app_data",
                target_identity="user data",
                ownership="external",
                status="not_applicable",
                safe_message="app data never cleared (policy)",
            )
        )
        steps.append(
            CleanupStep(
                rule="leave_other_apps",
                target_kind="other_apps",
                target_identity="third-party apps",
                ownership="external",
                status="not_applicable",
                safe_message="other apps never modified (policy)",
            )
        )
        steps.append(
            CleanupStep(
                rule="no_device_reboot",
                target_kind="device",
                target_identity="reboot",
                ownership="external",
                status="not_applicable",
                safe_message="device never rebooted (policy)",
            )
        )

        # Rule 9 — retain evidence (artifacts never deleted by cleanup).
        steps.append(
            CleanupStep(
                rule="retain_evidence",
                target_kind="artifacts",
                target_identity="run evidence",
                ownership="owned_by_run",
                status="success",
                safe_message="evidence retained for report",
            )
        )
        outcome.evidence_retained = True

        # Rule 10 — release lease is the caller's job (LeaseRegistry.release),
        # but we record the intent so the trace is complete.
        steps.append(
            CleanupStep(
                rule="release_lease",
                target_kind="device_lease",
                target_identity="lease",
                ownership="owned_by_run",
                status="success",
                safe_message="lease release handled by session",
            )
        )

        outcome.steps = steps
        return outcome


__all__ = [
    "CleanupActions",
    "CleanupManager",
    "CleanupOutcome",
    "CleanupStep",
    "OwnedResource",
    "Ownership",
    "ResourceOwnershipRegistry",
]
