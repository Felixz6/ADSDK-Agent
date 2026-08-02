"""Reclaimable, heartbeat-aware device lease.

The existing :class:`TaskService` uses a per-device ``threading.Lock`` which
is lost on crash and cannot be reclaimed for a stale holding process. M7A
introduces a *process-wide* :class:`LeaseRegistry` that records, per masked
device key:

* the run_id that currently holds the lease,
* the heartbeat timestamp (monotonic) refreshed while waiting on consent,
* whether the holder is still active.

Rules (Section 19):

* One device, at most one state-changing task at a time.
* Static-only tasks do NOT take a lease.
* A consent-wait *holds* the lease (heartbeat refreshed).
* Cancel releases the lease.
* A stale lease (heartbeat older than ``stale_after_seconds``, no active
  heartbeat from the holding task) is reclaimable *after a crash* — i.e. the
  holder task is no longer alive in this process.
* An *active* heartbeat lease is never stolen. Concurrent acquires against an
  active lease queue (or fail) rather than reclaiming it.

This module is pure and injectable (clock + sleep) so tests run deterministically
without real wall-clock waits.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Callable, Literal

LeaseState = Literal["held", "stale", "free"]


@dataclass(slots=True)
class DeviceLease:
    """A single device lease record. Mutated only under the registry lock."""

    device_key: str
    owner_run_id: str | None = None
    owner_task_id: str | None = None
    acquired_at: float | None = None
    last_heartbeat_at: float | None = None
    # Whether the holding task is still considered alive in *this* process.
    alive: bool = True

    @property
    def state(self) -> LeaseState:
        if self.owner_run_id is None:
            return "free"
        if not self.alive:
            return "stale"
        return "held"


class LeaseAcquireError(RuntimeError):
    """Raised when a lease cannot be acquired for a legit (non-stale) reason."""

    def __init__(self, code: str, message: str, current: DeviceLease | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.current = current


class LeaseRegistry:
    """Process-wide registry of reclaimable device leases.

    ``clock`` and ``sleep`` are injected so tests are deterministic. ``alive``
    is a callable returning ``True`` while a given task is still active in
    this process (used to decide stale-reclaim vs. active-busy).
    """

    def __init__(
        self,
        *,
        clock: Callable[[], float],
        stale_after_seconds: float = 600.0,
        alive: Callable[[str], bool] | None = None,
    ) -> None:
        self._clock = clock
        self._stale_after = float(stale_after_seconds)
        self._alive = alive or (lambda _task_id: True)
        self._leases: dict[str, DeviceLease] = {}
        self._lock = threading.RLock()

    # ------------------------------------------------------------------
    # Introspection (safe, masked — callers pass already-masked device keys).
    # ------------------------------------------------------------------
    def state(self, device_key: str) -> LeaseState:
        with self._lock:
            lease = self._leases.get(device_key)
            if lease is None or lease.owner_run_id is None:
                return "free"
            return lease.state

    def owner(self, device_key: str) -> DeviceLease | None:
        with self._lock:
            lease = self._leases.get(device_key)
            if lease is None or lease.owner_run_id is None:
                return None
            return lease

    def occupied_masked(self) -> list[str]:
        with self._lock:
            return sorted(
                key
                for key, lease in self._leases.items()
                if lease.owner_run_id is not None and lease.state == "held"
            )

    # ------------------------------------------------------------------
    # Acquire / release.
    # ------------------------------------------------------------------
    def acquire(
        self,
        *,
        device_key: str,
        run_id: str,
        task_id: str,
        wait: bool = False,
        sleep: Callable[[float], None] | None = None,
        poll_interval: float = 0.2,
        wait_timeout: float = 30.0,
    ) -> DeviceLease:
        """Acquire the lease for ``device_key`` on behalf of ``run_id``.

        * If the device is free, acquire immediately.
        * If held by an *active* task: ``wait=False`` -> raise
          ``LeaseAcquireError("lease_busy")``; ``wait=True`` -> poll until free
          or ``wait_timeout`` (then raise ``lease_timeout``).
        * If the lease is *stale* (holder task no longer alive in this
          process), reclaim it regardless of ``wait``.
        """
        deadline = self._clock() + wait_timeout if wait else self._clock()
        while True:
            with self._lock:
                lease = self._leases.setdefault(
                    device_key, DeviceLease(device_key=device_key)
                )
                now = self._clock()
                if lease.owner_run_id is None:
                    lease.owner_run_id = run_id
                    lease.owner_task_id = task_id
                    lease.acquired_at = now
                    lease.last_heartbeat_at = now
                    lease.alive = True
                    return lease
                # Already held — decide stale vs busy.
                holder_alive = (
                    lease.alive
                    and self._alive(lease.owner_task_id or "")
                )
                heartbeat_stale = (
                    lease.last_heartbeat_at is not None
                    and (now - lease.last_heartbeat_at) > self._stale_after
                )
                if not holder_alive or heartbeat_stale:
                    # Reclaim: a crashed/abandoned holder. Log nothing sensitive.
                    lease.owner_run_id = run_id
                    lease.owner_task_id = task_id
                    lease.acquired_at = now
                    lease.last_heartbeat_at = now
                    lease.alive = True
                    return lease
                # Active hold: busy.
                if not wait:
                    raise LeaseAcquireError(
                        "lease_busy",
                        "device is already held by an active task",
                        current=lease,
                    )
            if self._clock() >= deadline:
                raise LeaseAcquireError(
                    "lease_timeout",
                    "timed out waiting for a busy device lease",
                )
            if sleep is not None:
                sleep(poll_interval)

    def heartbeat(self, *, device_key: str, run_id: str) -> bool:
        """Refresh the lease heartbeat. Returns False if not the owner."""
        with self._lock:
            lease = self._leases.get(device_key)
            if lease is None or lease.owner_run_id != run_id:
                return False
            lease.last_heartbeat_at = self._clock()
            lease.alive = True
            return True

    def release(self, *, device_key: str, run_id: str) -> bool:
        """Release the lease iff ``run_id`` is the current owner."""
        with self._lock:
            lease = self._leases.get(device_key)
            if lease is None or lease.owner_run_id != run_id:
                return False
            lease.owner_run_id = None
            lease.owner_task_id = None
            lease.acquired_at = None
            lease.last_heartbeat_at = None
            lease.alive = True
            return True

    def mark_dead(self, task_id: str) -> int:
        """Mark a holding task as no-longer-alive (crash/recover), enabling
        stale reclaim. Returns the number of leases freed-of-active-hold."""
        with self._lock:
            count = 0
            for lease in self._leases.values():
                if lease.owner_task_id == task_id and lease.alive:
                    lease.alive = False
                    count += 1
            return count


__all__ = [
    "DeviceLease",
    "LeaseAcquireError",
    "LeaseRegistry",
    "LeaseState",
]
