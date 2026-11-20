"""Comparisons API router."""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import APIRouter, Depends, HTTPException

from app.api.deps import get_comparison_service
from app.comparisons import ComparisonCreateRequest, ComparisonResult

if TYPE_CHECKING:
    from app.comparisons import ComparisonService

router = APIRouter(tags=["comparisons"])


@router.post("/comparisons", response_model=ComparisonResult, status_code=201)
def create_comparison(
    request: ComparisonCreateRequest,
    comparison_service: ComparisonService = Depends(get_comparison_service),
):
    try:
        return comparison_service.create(request)
    except KeyError:
        raise HTTPException(
            status_code=404,
            detail={"code": "comparison_input_not_found", "message": "对比任务不存在"},
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail={"code": "invalid_comparison", "message": str(exc)},
        )


@router.get("/comparisons", response_model=list[ComparisonResult])
def list_comparisons(
    limit: int = 20,
    comparison_service: ComparisonService = Depends(get_comparison_service),
):
    return comparison_service.list(limit=max(1, min(limit, 100)))


@router.get("/comparisons/{comparison_id}", response_model=ComparisonResult)
def get_comparison(
    comparison_id: str,
    comparison_service: ComparisonService = Depends(get_comparison_service),
):
    result = comparison_service.get(comparison_id)
    if result is None:
        raise HTTPException(
            status_code=404,
            detail={"code": "comparison_not_found", "message": "对比结果不存在"},
        )
    return result
