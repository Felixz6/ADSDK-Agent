from __future__ import annotations

import json
import math
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from app.tasks.models import (
    TaskListResponse,
    TaskRecord,
    TaskStepRecord,
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00",
        "Z",
    )


class TaskRepository:
    """Small sqlite3 repository with one connection per operation."""

    _TASK_COLUMNS = {
        "status",
        "apk_snapshot_path",
        "apk_sha256",
        "package_name",
        "app_name",
        "version_name",
        "version_code",
        "progress_percent",
        "current_stage",
        "error_code",
        "error_message",
        "report_json_path",
        "report_markdown_path",
        "report_html_path",
        "risk_score",
        "risk_level",
        "started_at",
        "completed_at",
    }

    def __init__(self, database_path: str | Path) -> None:
        self.database_path = Path(database_path)

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(
            self.database_path,
            timeout=30,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA busy_timeout = 30000")
        try:
            yield connection
        finally:
            connection.close()

    def initialize(self) -> None:
        with self._connection() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS tasks (
                    id TEXT PRIMARY KEY,
                    task_type TEXT NOT NULL CHECK(task_type IN ('static','dynamic','comparison')),
                    status TEXT NOT NULL CHECK(status IN ('queued','running','completed','failed','cancelled')),
                    apk_path TEXT,
                    apk_snapshot_path TEXT,
                    apk_sha256 TEXT,
                    package_name TEXT,
                    app_name TEXT,
                    version_name TEXT,
                    version_code TEXT,
                    device_id TEXT,
                    enable_traffic INTEGER NOT NULL DEFAULT 0,
                    enable_ui_stimulation INTEGER NOT NULL DEFAULT 0,
                    progress_percent INTEGER NOT NULL DEFAULT 0,
                    current_stage TEXT,
                    error_code TEXT,
                    error_message TEXT,
                    report_json_path TEXT,
                    report_markdown_path TEXT,
                    report_html_path TEXT,
                    risk_score INTEGER,
                    risk_level TEXT,
                    request_json TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL,
                    started_at TEXT,
                    completed_at TEXT,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_tasks_status_created
                    ON tasks(status, created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_tasks_type_created
                    ON tasks(task_type, created_at DESC);

                CREATE TABLE IF NOT EXISTS task_steps (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
                    step_key TEXT NOT NULL,
                    step_name TEXT NOT NULL,
                    status TEXT NOT NULL,
                    progress_percent INTEGER NOT NULL DEFAULT 0,
                    message TEXT,
                    started_at TEXT,
                    completed_at TEXT,
                    updated_at TEXT NOT NULL,
                    UNIQUE(task_id, step_key)
                );

                CREATE TABLE IF NOT EXISTS comparisons (
                    id TEXT PRIMARY KEY,
                    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
                    base_task_id TEXT NOT NULL REFERENCES tasks(id),
                    target_task_id TEXT NOT NULL REFERENCES tasks(id),
                    result_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                """
            )

    def create_task(self, payload: dict[str, Any]) -> TaskRecord:
        now = utc_now()
        values = {
            "id": payload["id"],
            "task_type": payload["task_type"],
            "status": payload.get("status", "queued"),
            "apk_path": payload.get("apk_path"),
            "package_name": payload.get("package_name"),
            "device_id": payload.get("device_id"),
            "enable_traffic": int(bool(payload.get("enable_traffic"))),
            "enable_ui_stimulation": int(
                bool(payload.get("enable_ui_stimulation"))
            ),
            "request_json": json.dumps(
                payload.get("request_payload") or {},
                ensure_ascii=False,
                sort_keys=True,
            ),
            "created_at": payload.get("created_at") or now,
            "updated_at": now,
        }
        columns = ", ".join(values)
        placeholders = ", ".join(f":{key}" for key in values)
        with self._connection() as connection:
            connection.execute(
                f"INSERT INTO tasks ({columns}) VALUES ({placeholders})",
                values,
            )
        task = self.get_task(payload["id"])
        assert task is not None
        return task

    def get_task(self, task_id: str, *, include_steps: bool = True) -> TaskRecord | None:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM tasks WHERE id = ?",
                (task_id,),
            ).fetchone()
            if row is None:
                return None
            steps = (
                connection.execute(
                    "SELECT * FROM task_steps WHERE task_id = ? ORDER BY id",
                    (task_id,),
                ).fetchall()
                if include_steps
                else []
            )
        return self._to_task(row, steps)

    def list_tasks(
        self,
        *,
        status: str | None = None,
        task_type: str | None = None,
        keyword: str | None = None,
        page: int = 1,
        page_size: int = 20,
        sort: str = "-created_at",
    ) -> TaskListResponse:
        clauses: list[str] = []
        parameters: list[Any] = []
        if status:
            clauses.append("status = ?")
            parameters.append(status)
        if task_type:
            clauses.append("task_type = ?")
            parameters.append(task_type)
        if keyword:
            clauses.append(
                "(LOWER(COALESCE(app_name,'')) LIKE ? OR "
                "LOWER(COALESCE(package_name,'')) LIKE ? OR "
                "LOWER(COALESCE(apk_path,'')) LIKE ? OR LOWER(id) LIKE ?)"
            )
            value = f"%{keyword.lower()}%"
            parameters.extend([value, value, value, value])
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        sort_map = {
            "-created_at": "created_at DESC",
            "created_at": "created_at ASC",
            "-updated_at": "updated_at DESC",
            "updated_at": "updated_at ASC",
        }
        order = sort_map.get(sort, sort_map["-created_at"])
        with self._connection() as connection:
            total = int(
                connection.execute(
                    f"SELECT COUNT(*) FROM tasks {where}",
                    parameters,
                ).fetchone()[0]
            )
            rows = connection.execute(
                f"SELECT * FROM tasks {where} ORDER BY {order} LIMIT ? OFFSET ?",
                [*parameters, page_size, (page - 1) * page_size],
            ).fetchall()
        items = [self._to_task(row, []) for row in rows]
        return TaskListResponse(
            items=items,
            total=total,
            page=page,
            page_size=page_size,
            pages=math.ceil(total / page_size) if total else 0,
        )

    def update_task(self, task_id: str, **changes: Any) -> TaskRecord:
        invalid = set(changes) - self._TASK_COLUMNS
        if invalid:
            raise ValueError(f"unsupported task columns: {sorted(invalid)}")
        changes["updated_at"] = utc_now()
        assignments = ", ".join(f"{key} = ?" for key in changes)
        with self._connection() as connection:
            cursor = connection.execute(
                f"UPDATE tasks SET {assignments} WHERE id = ?",
                [*changes.values(), task_id],
            )
            if cursor.rowcount != 1:
                raise KeyError(task_id)
        task = self.get_task(task_id)
        assert task is not None
        return task

    def upsert_step(
        self,
        task_id: str,
        *,
        step_key: str,
        step_name: str,
        status: str,
        progress_percent: int,
        message: str | None,
    ) -> TaskStepRecord:
        now = utc_now()
        completed_at = now if status in {"success", "partial", "failed", "skipped"} else None
        with self._connection() as connection:
            connection.execute(
                """
                INSERT INTO task_steps (
                    task_id, step_key, step_name, status, progress_percent,
                    message, started_at, completed_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(task_id, step_key) DO UPDATE SET
                    step_name = excluded.step_name,
                    status = excluded.status,
                    progress_percent = excluded.progress_percent,
                    message = excluded.message,
                    completed_at = excluded.completed_at,
                    updated_at = excluded.updated_at
                """,
                (
                    task_id,
                    step_key,
                    step_name,
                    status,
                    progress_percent,
                    message,
                    now,
                    completed_at,
                    now,
                ),
            )
            row = connection.execute(
                "SELECT * FROM task_steps WHERE task_id = ? AND step_key = ?",
                (task_id, step_key),
            ).fetchone()
        assert row is not None
        return self._to_step(row)

    def recover_interrupted_tasks(self) -> int:
        now = utc_now()
        with self._connection() as connection:
            cursor = connection.execute(
                """
                UPDATE tasks
                SET status = 'failed', error_code = 'service_restarted',
                    error_message = '服务重启前任务未正常结束',
                    completed_at = ?, updated_at = ?
                WHERE status IN ('queued', 'running')
                """,
                (now, now),
            )
        return max(0, cursor.rowcount)

    def delete_task(self, task_id: str) -> bool:
        with self._connection() as connection:
            cursor = connection.execute("DELETE FROM tasks WHERE id = ?", (task_id,))
        return cursor.rowcount == 1

    def create_comparison(
        self,
        *,
        comparison_id: str,
        task_id: str,
        base_task_id: str,
        target_task_id: str,
        result: dict[str, Any],
    ) -> None:
        with self._connection() as connection:
            connection.execute(
                """
                INSERT INTO comparisons (
                    id, task_id, base_task_id, target_task_id, result_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    comparison_id,
                    task_id,
                    base_task_id,
                    target_task_id,
                    json.dumps(result, ensure_ascii=False, sort_keys=True),
                    utc_now(),
                ),
            )

    def get_comparison(self, comparison_id: str) -> dict[str, Any] | None:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT result_json FROM comparisons WHERE id = ?",
                (comparison_id,),
            ).fetchone()
        return json.loads(row["result_json"]) if row is not None else None

    @staticmethod
    def _to_step(row: sqlite3.Row) -> TaskStepRecord:
        return TaskStepRecord(**dict(row))

    def _to_task(
        self,
        row: sqlite3.Row,
        steps: list[sqlite3.Row],
    ) -> TaskRecord:
        item = dict(row)
        item["enable_traffic"] = bool(item["enable_traffic"])
        item["enable_ui_stimulation"] = bool(item["enable_ui_stimulation"])
        item["request_payload"] = json.loads(item.pop("request_json") or "{}")
        item["steps"] = [self._to_step(step) for step in steps]
        return TaskRecord(**item)
