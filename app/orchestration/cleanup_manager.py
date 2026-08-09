"""Run-owned resource cleanup with post-action ownership verification."""

from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
from typing import Any, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field

from .device_session import DeviceSessionSnapshot

Ownership = Literal["external", "owned_by_run", "shared_pre_existing"]
CleanupStepStatus = Literal["success", "failed", "skipped", "not_applicable"]
CleanupStatus = Literal["success", "partial", "failed"]


@dataclass(slots=True)
class OwnedResource:
    """Per-run resource record; ownership is explicit, never name-derived."""

    kind: str
    identity: str
    ownership: Ownership
    started_at: float | None = None
    detail: dict[str, Any] = field(default_factory=dict)


class ResourceOwnershipRegistry:
    """In-memory, per-run ownership ledger."""

    def __init__(self) -> None:
        self._items: dict[tuple[str, str], OwnedResource] = {}

    def register(self, resource: OwnedResource) -> None:
        self._items[(resource.kind, resource.identity)] = resource

    def mark_external(self, kind: str, identity: str, **detail: Any) -> None:
        self.register(OwnedResource(kind, identity, "external", detail=detail))

    def mark_owned(self, kind: str, identity: str, **detail: Any) -> None:
        # Callers must only register after observing preflight/start evidence.
        self.register(OwnedResource(kind, identity, "owned_by_run", detail=detail))

    def get(self, kind: str, identity: str) -> OwnedResource | None:
        return self._items.get((kind, identity))

    def owned(self) -> list[OwnedResource]:
        return [item for item in self._items.values() if item.ownership == "owned_by_run"]

    def external(self) -> list[OwnedResource]:
        return [item for item in self._items.values() if item.ownership == "external"]

    def all_items(self) -> list[OwnedResource]:
        return list(self._items.values())

    def is_owned(self, kind: str, identity: str) -> bool:
        item = self.get(kind, identity)
        return item is not None and item.ownership == "owned_by_run"


class CleanupStep(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule: str
    target_kind: str
    target_identity: str
    ownership: Ownership
    status: CleanupStepStatus
    safe_message: str = Field(default="", max_length=512)


class CleanupDiagnostic(BaseModel):
    """Secret-free resource verification result for the cleanup artifact."""

    model_config = ConfigDict(extra="forbid")

    resource_type: str
    identifier_hash: str
    preexisting: bool = False
    owned_by_run: bool
    created_by_run: bool = False
    initial_state: str = "unknown"
    expected_final_state: str = "absent"
    cleanup_attempted: bool = False
    cleanup_action_result: bool | None = None
    verification_attempted: bool = False
    verification_result: Literal["verified", "present", "unavailable", "not_owned", "identity_changed"]
    retry_attempted: bool = False
    final_status: CleanupStatus
    reason_code: str
    raw_expected_state: str | None = None
    raw_observed_state: str | None = None
    canonical_expected_state: str | None = None
    canonical_observed_state: str | None = None


class CleanupOutcome(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ran: bool = False
    cancelled: bool = False
    status: CleanupStatus = "success"
    steps: list[CleanupStep] = Field(default_factory=list)
    diagnostics: list[CleanupDiagnostic] = Field(default_factory=list)
    verification_attempted: bool = False
    proxy_restore_attempted: bool = False
    proxy_restore_failed: bool = False
    external_frida_touched: bool = False
    evidence_retained: bool = True
    failures: list[str] = Field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.ran and self.status == "success" and not self.proxy_restore_failed and not self.failures


class CleanupActions(Protocol):
    def set_proxy(self, device: str, value: str) -> bool: ...
    def delete_proxy(self, device: str) -> bool: ...
    def kill_pid(self, device: str, pid: int) -> bool: ...
    def force_stop_package(self, device: str, package_name: str) -> bool: ...
    def stop_mitm_pid(self, pid: int) -> bool: ...
    def stop_frida_session(self, ref: str) -> bool: ...


_RESOURCE_KIND_FRIDA_SERVER = "frida_server"
_RESOURCE_KIND_FRIDA_HELPER = "frida_helper"
_RESOURCE_KIND_MITM = "mitm_process"
_RESOURCE_KIND_PROXY = "device_proxy"
_RESOURCE_KIND_FRIDA_SESSION = "frida_session"
_RESOURCE_KIND_APP = "app_process"
_PORT_KINDS = {"frida_port", "mitm_port"}


def _hash_identifier(value: str) -> str:
    return sha256(value.encode("utf-8")).hexdigest()[:16]


def _proxy_semantic(value: str | None) -> str:
    return "" if value is None or value.strip().lower() in {"", "null", ":null"} else value.strip()


def _reason_for(kind: str, verification: str) -> str:
    prefix = {
        _RESOURCE_KIND_APP: "target_process",
        _RESOURCE_KIND_FRIDA_SERVER: "frida",
        _RESOURCE_KIND_FRIDA_HELPER: "frida_helper",
        "frida_port": "frida_port",
        _RESOURCE_KIND_MITM: "mitm",
        "mitm_port": "mitm_port",
    }.get(kind, kind)
    return {
        "verified": f"{prefix}_cleanup_verified",
        "present": f"{prefix}_still_running" if kind not in _PORT_KINDS else f"{prefix}_still_listening",
        "unavailable": f"{prefix}_verification_unavailable",
        "not_owned": f"{prefix}_not_owned",
        "identity_changed": f"{prefix}_identity_changed",
    }[verification]


class CleanupManager:
    """Exact cleanup, verify, one ownership-gated retry, then final verify."""

    def __init__(self, *, registry: ResourceOwnershipRegistry, actions: CleanupActions,
                 snapshot: DeviceSessionSnapshot, device_id: str | None) -> None:
        self.registry = registry
        self.actions = actions
        self.snapshot = snapshot
        self.device_id = device_id

    def _present(self, resource: OwnedResource) -> bool | None:
        probe = getattr(self.actions, "resource_present", None)
        if not callable(probe):
            return None
        try:
            return probe(resource.kind, dict(resource.detail))
        except BaseException:
            return None

    def _action(self, resource: OwnedResource) -> bool | None:
        pid = int(resource.detail.get("pid", -1))
        if resource.kind == _RESOURCE_KIND_MITM:
            return self.actions.stop_mitm_pid(pid) if pid > 0 else False
        if resource.kind in {_RESOURCE_KIND_APP, _RESOURCE_KIND_FRIDA_SERVER, _RESOURCE_KIND_FRIDA_HELPER}:
            return self.actions.kill_pid(self.device_id or "", pid) if pid > 0 else False
        if resource.kind == _RESOURCE_KIND_FRIDA_SESSION:
            return self.actions.stop_frida_session(resource.identity)
        if resource.kind in _PORT_KINDS:
            return True  # port belongs to its registered managed process
        return None

    def _bounded_retry(self, resource: OwnedResource) -> bool | None:
        """Retry one exact action, or one ownership-gated package fallback."""
        if resource.kind != _RESOURCE_KIND_APP:
            return self._action(resource)

        detail = resource.detail
        package_name = str(detail.get("expected_command_token") or "").strip()
        package_fallback_allowed = (
            not bool(detail.get("preexisting", False))
            and bool(detail.get("created_by_run", False))
            and bool(package_name)
        )
        force_stop = getattr(self.actions, "force_stop_package", None)
        if package_fallback_allowed and callable(force_stop):
            return bool(force_stop(self.device_id or "", package_name))
        return self._action(resource)

    def _record_resource(self, outcome: CleanupOutcome, resource: OwnedResource) -> None:
        identity_matches = getattr(self.actions, "resource_identity_matches", None)
        matches = True
        if callable(identity_matches):
            try:
                matches = bool(identity_matches(resource.kind, dict(resource.detail)))
            except BaseException:
                matches = False
        action = self._action(resource) if matches else None
        present = self._present(resource)
        verification = "identity_changed" if not matches else ("unavailable" if present is None else ("present" if present else "verified"))
        retry = False
        if matches and present is True:
            retry = True
            retry_action = self._bounded_retry(resource)
            action = bool(retry_action) if retry_action is not None else action
            present = self._present(resource)
            verification = "unavailable" if present is None else ("present" if present else "verified")
        final = "success" if verification == "verified" else ("failed" if action is False else "partial")
        diagnostic = CleanupDiagnostic(
            resource_type=resource.kind,
            identifier_hash=_hash_identifier(resource.identity),
            preexisting=bool(resource.detail.get("preexisting", False)),
            owned_by_run=True,
            created_by_run=bool(resource.detail.get("created_by_run", True)),
            initial_state=str(resource.detail.get("initial_state", "present")),
            cleanup_attempted=True,
            cleanup_action_result=action,
            verification_attempted=True,
            verification_result=verification,
            retry_attempted=retry,
            final_status=final,
            reason_code=_reason_for(resource.kind, verification),
        )
        outcome.diagnostics.append(diagnostic)
        outcome.verification_attempted = True
        if final != "success":
            outcome.failures.append(diagnostic.reason_code)
        rule = "stop_mitm_processes" if resource.kind == _RESOURCE_KIND_MITM else (
            "detach_frida_sessions" if resource.kind == _RESOURCE_KIND_FRIDA_SESSION else (
                "stop_owned_frida_server" if resource.kind == _RESOURCE_KIND_FRIDA_SERVER else "stop_owned_resource"
            )
        )
        outcome.steps.append(CleanupStep(
            rule=rule, target_kind=resource.kind, target_identity=_hash_identifier(resource.identity),
            ownership="owned_by_run", status="success" if final == "success" else "failed",
            safe_message=diagnostic.reason_code,
        ))

    def _restore_proxy(self, outcome: CleanupOutcome) -> None:
        initial = self.snapshot.initial_state.http_proxy
        if not self.device_id:
            outcome.steps.append(CleanupStep(rule="restore_proxy", target_kind=_RESOURCE_KIND_PROXY,
                target_identity="", ownership="owned_by_run", status="not_applicable", safe_message="no device in this run"))
            return
        if initial is None:
            outcome.steps.append(CleanupStep(rule="restore_proxy", target_kind=_RESOURCE_KIND_PROXY,
                target_identity="global http_proxy", ownership="external", status="skipped",
                safe_message="initial proxy unknown; left untouched"))
            return
        desired = _proxy_semantic(initial)
        action = self.actions.delete_proxy(self.device_id) if not desired else self.actions.set_proxy(self.device_id, initial)
        outcome.proxy_restore_attempted = True
        read_proxy = getattr(self.actions, "read_proxy", None)
        observed: str | None
        if callable(read_proxy):
            try:
                observed = read_proxy(self.device_id)
            except BaseException:
                observed = None
            verified = _proxy_semantic(observed) == desired
            verification = "verified" if verified else "present"
        else:
            # Compatibility shims do not claim verified success.
            verified, verification = False, "unavailable"
        final = "success" if action and verified else ("failed" if not action else "partial")
        outcome.proxy_restore_failed = final != "success"
        outcome.verification_attempted = True
        outcome.diagnostics.append(CleanupDiagnostic(
            resource_type=_RESOURCE_KIND_PROXY, identifier_hash=_hash_identifier("global http_proxy"),
            owned_by_run=True, cleanup_attempted=True, cleanup_action_result=action,
            verification_attempted=True, verification_result=verification,
            final_status=final, reason_code="proxy_restore_verified" if verified else "proxy_restore_mismatch",
            expected_final_state="initial_proxy_semantics",
            raw_expected_state=initial,
            raw_observed_state=observed if callable(read_proxy) else None,
            canonical_expected_state=desired or "none",
            canonical_observed_state=(
                _proxy_semantic(observed) or "none"
                if callable(read_proxy) else None
            ),
        ))
        outcome.steps.append(CleanupStep(rule="restore_proxy", target_kind=_RESOURCE_KIND_PROXY,
            target_identity="global http_proxy", ownership="owned_by_run",
            status="success" if final == "success" else "failed",
            safe_message="proxy_restore_verified" if verified else "proxy_restore_mismatch"))
        if final != "success":
            outcome.failures.append("proxy_restore_mismatch")

    def run(self, *, cancelled: bool = False) -> CleanupOutcome:
        outcome = CleanupOutcome(ran=True, cancelled=cancelled)
        # Exact cleanup only touches explicit run-owned records.
        for resource in self.registry.owned():
            self._record_resource(outcome, resource)
        for resource in self.registry.external():
            if resource.kind in {_RESOURCE_KIND_FRIDA_SERVER, _RESOURCE_KIND_FRIDA_HELPER, _RESOURCE_KIND_MITM, _RESOURCE_KIND_APP}:
                outcome.steps.append(CleanupStep(rule="leave_external_frida_server" if resource.kind == _RESOURCE_KIND_FRIDA_SERVER else "leave_external_resource", target_kind=resource.kind,
                    target_identity=_hash_identifier(resource.identity), ownership="external", status="skipped",
                    safe_message="resource not owned by this run"))
        self._restore_proxy(outcome)
        for rule, kind, identity, ownership, status, message in [
            ("leave_app_data", "app_data", "user data", "external", "not_applicable", "app data retained"),
            ("leave_other_apps", "other_apps", "third-party apps", "external", "not_applicable", "other apps retained"),
            ("no_device_reboot", "device", "reboot", "external", "not_applicable", "device not rebooted"),
            ("retain_evidence", "artifacts", "run evidence", "owned_by_run", "success", "evidence retained"),
        ]:
            outcome.steps.append(CleanupStep(rule=rule, target_kind=kind, target_identity=identity,
                ownership=ownership, status=status, safe_message=message))
        outcome.status = "success" if not outcome.failures else (
            "failed" if any(d.cleanup_action_result is False for d in outcome.diagnostics) else "partial"
        )
        return outcome


__all__ = ["CleanupActions", "CleanupDiagnostic", "CleanupManager", "CleanupOutcome",
           "CleanupStep", "OwnedResource", "Ownership", "ResourceOwnershipRegistry"]

