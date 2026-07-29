from __future__ import annotations

from contextvars import ContextVar, Token
from dataclasses import dataclass, field
from threading import Event, RLock
from typing import Callable


class TaskCancelled(RuntimeError):
    """Raised at a real analysis safe point after cancellation was requested."""


ProgressCallback = Callable[[str, str, str | None], None]
CleanupCallback = Callable[[], object]


@dataclass(slots=True)
class TaskExecutionContext:
    task_id: str
    cancel_event: Event
    progress: ProgressCallback
    cleanup_callbacks: list[CleanupCallback] = field(default_factory=list)


_current: ContextVar[TaskExecutionContext | None] = ContextVar(
    "adsdk_task_execution",
    default=None,
)
_active: dict[str, TaskExecutionContext] = {}
_lock = RLock()


def bind_task_context(context: TaskExecutionContext) -> Token:
    with _lock:
        _active[context.task_id] = context
    return _current.set(context)


def reset_task_context(token: Token) -> None:
    context = _current.get()
    _current.reset(token)
    if context is not None:
        with _lock:
            _active.pop(context.task_id, None)


def current_task_id() -> str | None:
    context = _current.get()
    return context.task_id if context is not None else None


def checkpoint() -> None:
    context = _current.get()
    if context is not None and context.cancel_event.is_set():
        raise TaskCancelled("task cancellation requested")


def report_step(step_key: str, status: str, message: str | None = None) -> None:
    context = _current.get()
    if context is None:
        return
    checkpoint()
    context.progress(step_key, status, message)


def register_cleanup(callback: CleanupCallback) -> None:
    context = _current.get()
    if context is None:
        return
    with _lock:
        context.cleanup_callbacks.append(callback)


def request_cancel(task_id: str) -> bool:
    with _lock:
        context = _active.get(task_id)
        if context is None:
            return False
        context.cancel_event.set()
        callbacks = list(reversed(context.cleanup_callbacks))
    for callback in callbacks:
        try:
            callback()
        except Exception:
            # The owning analysis thread performs and records final cleanup.
            pass
    return True

