"""Manual consent checkpoint service.

During a full-analysis run, after the app has been launched and Hook is loaded
(pre-consent collection), the orchestrator reaches an ``awaiting_consent_action``
state. The human operator must complete a *manual* consent action inside the
app (we never auto-click the UI; we never clear app data). The operator then
tells us the outcome via :func:`ConsentCheckpointService.resolve`:

  * ``confirmed``  — consent UI was reached and completed by the human;
  * ``not_found``  — no consent UI was observed (recorded as evidence, not a
                     failure);
  * ``skipped``    — operator explicitly skipped consent for this run.

Rules (Section consent-checkpoint):

* The state must be ``awaiting_consent_action`` to resolve; resolving from any
  other state is rejected (state-gated) but *idempotent* for a repeat
  ``confirmed`` with the same value.
* AI can NOT auto-confirm.
* No timeout auto-confirmed: a checkpoint never flips itself to confirmed on a
  timer. An external watchdog may *cancel* the task (which exits the wait and
  runs cleanup), but it never confirms.
* Cancel exits the wait (the session observes cancellation and proceeds to
  cleanup rather than waiting indefinitely).

This module is pure and injectable (clock) so tests are deterministic and do
not depend on wall-clock sleeps.
"""

from __future__ import annotations

import threading
import time
from typing import Callable, Literal

from pydantic import BaseModel, ConfigDict, Field

ConsentAction = Literal["confirmed", "not_found", "skipped"]
ConsentCheckpointOutcome = Literal[
    "confirmed", "not_found", "skipped", "cancelled", "awaiting", "expired"
]


class ConsentCheckpointState(BaseModel):
    """Public, secret-free representation of a checkpoint."""

    model_config = ConfigDict(extra="forbid")

    task_id: str
    run_id: str
    status: ConsentCheckpointOutcome = "awaiting"
    entered_at: str = ""
    resolved_at: str | None = None
    resolved_by_action: ConsentAction | None = None
    # Heartbeat read-only facts; no UI text, no cookies, no bodies.
    last_heartbeat_at: str | None = None
    note: str = Field(default="", max_length=240)


class ConsentCheckpointRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: ConsentAction
    note: str = Field(default="", max_length=240)


class ConsentCheckpointError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


class ConsentCheckpointService:
    """In-process registry of consent checkpoints, one per active run.

    The service is the single authority for ``awaiting_consent_action`` and
    its transition. The session layer calls :meth:`enter` before waiting on
    consent and :meth:`resolve` (via the API) when the operator responds.
    Cancellation is observed via :meth:`cancel`.
    """

    def __init__(self, *, clock: Callable[[], str]) -> None:
        self._clock = clock
        self._locks: dict[str, threading.RLock] = {}
        self._states: dict[str, ConsentCheckpointState] = {}
        self._events: dict[str, threading.Event] = {}
        self._registry_lock = threading.RLock()

    # ------------------------------------------------------------------
    def _lock_for(self, task_id: str) -> threading.RLock:
        with self._registry_lock:
            return self._locks.setdefault(task_id, threading.RLock())

    def enter(
        self, *, task_id: str, run_id: str
    ) -> ConsentCheckpointState:
        """Mark a checkpoint as awaiting. Re-entering for the same task+run is
        a no-op refresh (heartbeats). Re-entering after resolution is rejected
        unless the prior resolution was a non-terminal ``awaiting``."""
        lock = self._lock_for(task_id)
        with lock:
            existing = self._states.get(task_id)
            now = self._clock()
            if existing is not None and existing.status != "awaiting":
                raise ConsentCheckpointError(
                    "checkpoint_already_resolved",
                    "consent checkpoint already resolved",
                )
            if existing is None:
                state = ConsentCheckpointState(
                    task_id=task_id,
                    run_id=run_id,
                    status="awaiting",
                    entered_at=now,
                    last_heartbeat_at=now,
                )
                self._states[task_id] = state
                self._events[task_id] = threading.Event()
            else:
                existing.last_heartbeat_at = now
                state = existing
            return state.model_copy()

    def heartbeat(self, *, task_id: str) -> bool:
        lock = self._lock_for(task_id)
        with lock:
            state = self._states.get(task_id)
            if state is None or state.status != "awaiting":
                return False
            state.last_heartbeat_at = self._clock()
            return True

    def state(self, task_id: str) -> ConsentCheckpointState | None:
        lock = self._lock_for(task_id)
        with lock:
            state = self._states.get(task_id)
            return state.model_copy() if state else None

    def resolve(
        self,
        *,
        task_id: str,
        action: ConsentAction,
        note: str = "",
    ) -> ConsentCheckpointState:
        """Apply the operator's consent action. Idempotent for a repeat of the
        *same* action; any other action when already resolved is rejected."""
        lock = self._lock_for(task_id)
        with lock:
            state = self._states.get(task_id)
            if state is None:
                raise ConsentCheckpointError(
                    "checkpoint_not_found",
                    "no consent checkpoint is awaiting for this task",
                )
            if state.status != "awaiting":
                if state.resolved_by_action == action:
                    # Idempotent repeat of the same action.
                    return state.model_copy()
                raise ConsentCheckpointError(
                    "checkpoint_already_resolved",
                    "consent checkpoint already resolved with a different action",
                )
            state.status = action
            state.resolved_by_action = action
            state.resolved_at = self._clock()
            state.note = note[:240]
            event = self._events.get(task_id)
            if event is not None:
                event.set()
            return state.model_copy()

    def cancel(self, *, task_id: str) -> ConsentCheckpointState | None:
        """Mark the checkpoint cancelled and wake the waiter so the session
        can proceed to cleanup. Does NOT confirm consent."""
        lock = self._lock_for(task_id)
        with lock:
            state = self._states.get(task_id)
            if state is None:
                return None
            if state.status == "awaiting":
                state.status = "cancelled"
                state.resolved_at = self._clock()
            event = self._events.get(task_id)
            if event is not None:
                event.set()
            return state.model_copy()

    def expire(self, *, task_id: str) -> ConsentCheckpointState | None:
        """Bound an operator wait without ever manufacturing confirmation."""
        lock = self._lock_for(task_id)
        with lock:
            state = self._states.get(task_id)
            if state is None:
                return None
            if state.status == "awaiting":
                state.status = "expired"
                state.resolved_at = self._clock()
            event = self._events.get(task_id)
            if event is not None:
                event.set()
            return state.model_copy()

    def wait(
        self,
        *,
        task_id: str,
        sleep: Callable[[float], None] | None = None,
        poll_interval: float = 0.2,
        is_cancelled: Callable[[], bool] | None = None,
        heartbeat: Callable[[], None] | None = None,
        timeout_seconds: float | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> ConsentCheckpointState:
        """Block (cooperatively, via injected sleep) until resolved or
        cancelled. A cancellation callback short-circuits the wait. No
        timeout ever auto-confirms — this returns ``cancelled`` if the
        watchdog fires and never ``confirmed`` on a timer."""
        lock = self._lock_for(task_id)
        with lock:
            state = self._states.get(task_id)
            if state is None:
                raise ConsentCheckpointError(
                    "checkpoint_not_found",
                    "no consent checkpoint is awaiting for this task",
                )
            event = self._events.get(task_id)
            if event is None:
                event = threading.Event()
                self._events[task_id] = event
        deadline = (
            monotonic() + max(0.0, float(timeout_seconds))
            if timeout_seconds is not None
            else None
        )
        while True:
            if event.is_set():
                break
            if is_cancelled is not None and is_cancelled():
                self.cancel(task_id=task_id)
                break
            if heartbeat is not None:
                try:
                    heartbeat()
                except BaseException:
                    pass
            if deadline is not None and monotonic() >= deadline:
                self.expire(task_id=task_id)
                break
            if sleep is None:
                # No sleeper injected: spin once then break (test path).
                break
            sleep(poll_interval)
        with lock:
            final = self._states.get(task_id)
            return final.model_copy() if final else state.model_copy()

    def clear(self, task_id: str) -> None:
        """Remove the checkpoint record once cleanup is complete."""
        lock = self._lock_for(task_id)
        with lock:
            self._states.pop(task_id, None)
            self._events.pop(task_id, None)


__all__ = [
    "ConsentAction",
    "ConsentCheckpointError",
    "ConsentCheckpointOutcome",
    "ConsentCheckpointRequest",
    "ConsentCheckpointService",
    "ConsentCheckpointState",
]
