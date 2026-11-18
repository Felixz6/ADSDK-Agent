"""Comparisons API router."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.comparisons import ComparisonCreateRequest, ComparisonResult

router = APIRouter(tags=["comparisons"])


def _main():
    import app.main as main_module
    return main_module


@router.post("/comparisons", response_model=ComparisonResult, status_code=201)
def create_comparison(request: ComparisonCreateRequest):
    main = _main()
    try:
        return main.comparison_service.create(request)
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
def list_comparisons(limit: int = 20):
    main = _main()
    return main.comparison_service.list(limit=max(1, min(limit, 100)))


@router.get("/comparisons/{comparison_id}", response_model=ComparisonResult)
def get_comparison(comparison_id: str):
    main = _main()
    result = main.comparison_service.get(comparison_id)
    if result is None:
        raise HTTPException(
            status_code=404,
            detail={"code": "comparison_not_found", "message": "对比结果不存在"},
        )
    return result
