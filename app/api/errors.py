"""API error responses and exception helpers."""

from __future__ import annotations

from fastapi import HTTPException


def task_not_found(task_id: str) -> HTTPException:
    return HTTPException(
        status_code=404,
        detail={"code": "task_not_found", "message": f"任务 {task_id} 不存在"},
    )


_task_not_found = task_not_found

__all__ = ["_task_not_found", "task_not_found"]
