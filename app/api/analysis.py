"""Analysis API router for synchronous static and dynamic analysis endpoints."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, Depends

from app.api.deps import get_container, get_frida_session_factory, get_mitm_session_factory
from app.models import AnalyzeRequest, AnalyzeResponse, DynamicAnalyzeRequest
from app.pipelines.dynamic import dynamic_analyze
from app.pipelines.static import analyze

if TYPE_CHECKING:
    from app.container import Container

router = APIRouter(tags=["analysis"], include_in_schema=False)


@router.post("/analyze", response_model=AnalyzeResponse)
def analyze_endpoint(req: AnalyzeRequest) -> AnalyzeResponse:
    return analyze(req)


@router.post("/dynamic/analyze", response_model=AnalyzeResponse)
def dynamic_analyze_endpoint(
    req: DynamicAnalyzeRequest,
    container: Container = Depends(get_container),
    frida_session_factory: Any = Depends(get_frida_session_factory),
    mitm_session_factory: Any = Depends(get_mitm_session_factory),
) -> AnalyzeResponse:
    return dynamic_analyze(
        req,
        container=container,
        frida_session_factory=frida_session_factory,
        mitm_session_factory=mitm_session_factory,
    )
