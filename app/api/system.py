"""System health and root API router."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter

router = APIRouter(tags=["system"], include_in_schema=False)


@router.get("/")
def root() -> dict[str, Any]:
    return {"ok": True, "message": "AdSDK Agent is running"}
