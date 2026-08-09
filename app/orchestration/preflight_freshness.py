"""Preflight freshness — re-preflight + diff before any state change (十).

Section 十三 requires that, *before* the run performs the first
device-state-changing tool, it re-captures a read-only preflight and compares
it against the snapshot taken before planning. The device can reboot, drop
off adb, lose the frida-server, or change proxy between the two captures —
all *after* the AI plan was validated. The plan was validated against the
world as it was; if that world changed, the validation may no longer hold.

This module is the deterministic diff between two
:class:`DeviceSessionSnapshot` objects plus a verdict the session uses to
decide:

* ``block_factor=None`` — nothing material changed; re-run the runtime
  validator on the fresh snapshot (no new AI plan, Section 十三) and proceed.
* ``block_factor="device_rebooted"`` / ``"device_disconnected"`` — the device
  left the run's world; the session must block **and** run cleanup (it can no
  longer trust any prior lease, proxy, or frida handle), then fail.
* ``block_factor="frida_server_gone"`` etc. — material but recoverable; the
  session drops to ``static_only`` (deterministic fallback) rather than
  launching a dynamic leg it can no longer satisfy. No new AI plan is made.

Why the diff lives here, not inline in the session
---------------------------------------------------
The diff is the precise, testable surface Section 十三 names (online, boot,
package installed, target PID, http_proxy, frida-server present/owned). Owning
it in a pure function means Phase A tests can exercise every branch with two
literal snapshots and no device, and the session only has to supply the
"re-preflight now" effect. The fresh-preflight comparison never triggers a new
AI planning round by design: the AI already produced a plan against a valid
world; a degraded world can only narrow it, never widen it.

Secret-free: only boolean / pid / bounded-string facts are compared; the
masked ``device_ref`` is used as an identity token, never the serial.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .device_session import DeviceSessionSnapshot

# Stable reason codes recorded alongside ``preflight_changed`` in the
# ai-runtime-diagnostics artifact. Block factors are fatal; the others are
# recoverable-downgrade reasons.
BLOCK_DEVICE_REBOOTED = "device_rebooted_since_preflight"
BLOCK_DEVICE_DISCONNECTED = "device_disconnected_since_preflight"
BLOCK_DEVICE_REF_CHANGED = "device_ref_changed_since_preflight"

# Recoverable (non-fatal) material changes — the session may downgrade rather
# than fail, and must re-run the runtime validator.
CHANGE_PACKAGE_UNINSTALLED = "package_uninstalled_since_preflight"
CHANGE_TARGET_GONE = "target_process_gone_since_preflight"
CHANGE_FRIDA_GONE = "frida_server_gone_since_preflight"
CHANGE_FRIDA_OWNERSHIP_LOST = "frida_ownership_lost_since_preflight"
CHANGE_PROXY_CHANGED = "proxy_changed_since_preflight"

# PID-only churn (foreground app restarted with a new pid) is recorded but is
# not by itself a block — attach_only can re-attach to the new pid.
CHANGE_TARGET_PID_CHANGED = "target_pid_changed_since_preflight"


@dataclass(slots=True)
class PreflightFreshnessResult:
    """Outcome of :func:`compare_preflight`.

    ``preflight_changed`` is True when any monitored fact differs. The session
    records this verbatim in diagnostics. ``block_factor`` is None when the run
    may continue (perhaps after a downgrade); otherwise the run must block +
    cleanup.
    """

    preflight_changed: bool = False
    block_factor: str | None = None
    changes: list[str] = field(default_factory=list)

    @property
    def fatal(self) -> bool:
        return self.block_factor is not None

    def as_diagnostics(self) -> dict[str, object]:
        return {
            "preflight_changed": self.preflight_changed,
            "block_factor": self.block_factor,
            "changes": list(self.changes),
        }


def compare_preflight(
    original: DeviceSessionSnapshot | None,
    fresh: DeviceSessionSnapshot | None,
) -> PreflightFreshnessResult:
    """Diff two read-only preflight snapshots and produce a verdict.

    Tolerates either snapshot being ``None`` (the session may reach this point
    before a snapshot was captured): a missing original is treated as "we have
    never seen this device" and a missing fresh as "the device could not be
    re-probed" — both are *recoverable* unless the fresh snapshot is offline.
    """

    res = PreflightFreshnessResult()

    # Missing original: nothing to compare against. Record the fact but do not
    # block — the runtime validator (run on the fresh snapshot) makes the
    # blocking decision. This path is defensive; the session always captures an
    # original pre-plan.
    if original is None or fresh is None:
        res.changes.append("missing_preflight_baseline_or_recheck")
        res.preflight_changed = True
        # A missing fresh snapshot with a present original means the device
        # could not be re-probed at all -> treat as disconnected (fatal).
        if original is not None and fresh is None:
            res.block_factor = BLOCK_DEVICE_DISCONNECTED
        return res

    orig = original.initial_state
    now = fresh.initial_state

    # --- device identity (masked token) ---
    if original.device_ref != fresh.device_ref:
        # The masked id changed -> a different device answered adb. This is a
        # fatal mismatch; the lease held for the original device is invalid.
        res.changes.append(BLOCK_DEVICE_REF_CHANGED)
        res.block_factor = BLOCK_DEVICE_REF_CHANGED
        res.preflight_changed = True
        return res

    # --- online ---
    if not now.online and orig.online:
        res.changes.append(BLOCK_DEVICE_DISCONNECTED)
        res.block_factor = BLOCK_DEVICE_DISCONNECTED
        res.preflight_changed = True
        return res
    if now.online != orig.online and not now.online:
        # Both offline-now cases funnel to the disconnected block above.
        res.changes.append(BLOCK_DEVICE_DISCONNECTED)
        res.block_factor = BLOCK_DEVICE_DISCONNECTED
        res.preflight_changed = True
        return res

    # --- boot id (a reboot changes the boot id) ---
    # Only compare when both were observed; a probe that gained/lost a boot id
    # is not by itself evidence of a reboot (emu quirk).
    if orig.boot_id and now.boot_id and orig.boot_id != now.boot_id:
        res.changes.append(BLOCK_DEVICE_REBOOTED)
        res.block_factor = BLOCK_DEVICE_REBOOTED
        res.preflight_changed = True
        return res

    # --- package installed (a uninstall between preflight and state change
    # means the dynamic leg has nothing to attach to) ---
    if (
        orig.package_installed is True
        and now.package_installed is False
    ):
        res.changes.append(CHANGE_PACKAGE_UNINSTALLED)
        res.preflight_changed = True

    # --- frida server presence / ownership ---
    if orig.frida_server_present is True and now.frida_server_present is False:
        res.changes.append(CHANGE_FRIDA_GONE)
        res.preflight_changed = True
    elif (
        orig.frida_server_owned is True
        and now.frida_server_owned is False
        and now.frida_server_present is not False
    ):
        # We lost ownership but the server is still around (another process
        # stole it, or we crashed-and-restarted). The dynamic leg can no longer
        # rely on our handle.
        res.changes.append(CHANGE_FRIDA_OWNERSHIP_LOST)
        res.preflight_changed = True

    # --- http proxy (a proxy change between the two read-only captures is
    # evidence someone touched settings between our preflight and our state
    # change — cleanup must restore the *original*, not the fresh value) ---
    if _proxy_normalised(orig.http_proxy) != _proxy_normalised(now.http_proxy):
        res.changes.append(CHANGE_PROXY_CHANGED)
        res.preflight_changed = True

    # --- target PID churn (foreground/target pid differs). We compare the
    # frida_server_pid as a proxy for "the process we were going to attach to
    # is a different pid now". This is non-fatal; attach_only rebinds. ---
    if (
        orig.frida_server_pid is not None
        and now.frida_server_pid is not None
        and orig.frida_server_pid != now.frida_server_pid
    ):
        res.changes.append(CHANGE_TARGET_PID_CHANGED)
        res.preflight_changed = True

    # A "target gone" condition: frida was present and target_pids went from
    # nonzero to zero is not observable from DeviceState directly (PIDs live in
    # RuntimeCapabilities, not the snapshot). The runtime layer's
    # target_process_not_found check already covers that on re-validation; we
    # only surface the frida-server-pid churn here for diagnostics honesty.

    return res


def _proxy_normalised(value: str | None) -> str:
    """Treat unset proxy variants (``""``, ``":0"``, ``":null"``) as empty.

    Mirrors :mod:`app.orchestration.device_session`'s normalisation so a
    MuMu ``":null"`` at preflight and an empty string at recheck do not flip
    ``preflight_changed`` spuriously (Section 十三: only *material* changes
    count, not adb/emu quirks).
    """

    if value is None:
        return ""
    if value.strip() in {"", ":0", ":null"}:
        return ""
    return value.strip()


__all__ = [
    "BLOCK_DEVICE_DISCONNECTED",
    "BLOCK_DEVICE_REBOOTED",
    "BLOCK_DEVICE_REF_CHANGED",
    "CHANGE_FRIDA_GONE",
    "CHANGE_FRIDA_OWNERSHIP_LOST",
    "CHANGE_PACKAGE_UNINSTALLED",
    "CHANGE_PROXY_CHANGED",
    "CHANGE_TARGET_GONE",
    "CHANGE_TARGET_PID_CHANGED",
    "PreflightFreshnessResult",
    "compare_preflight",
]
