"""AdSDK Agent FastAPI application entry point."""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.deps import get_frida_session_factory, get_mitm_session_factory
from app.api.middleware import AILocalOnlyMiddleware
from app.container import task_repository, task_service
from app.models import AnalyzeRequest, AnalyzeResponse, DynamicAnalyzeRequest
from app.pipelines.dynamic import dynamic_analyze
from app.pipelines.static import analyze
from app.pipelines.task_runner import _run_persisted_task

task_service.set_runner(_run_persisted_task)


@asynccontextmanager
async def lifespan(app: FastAPI):
    task_repository.initialize()
    task_service.recover()
    yield
    task_service.shutdown()


def create_app() -> FastAPI:
    """Build the ASGI app: CORS, local-only guard, and domain routers."""
    app_instance = FastAPI(title="AdSDK Agent", version="0.2.0", lifespan=lifespan)
    app_instance.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://127.0.0.1:5173",
            "http://localhost:5173",
        ],
        allow_credentials=False,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["Accept", "Content-Type"],
    )
    app_instance.add_middleware(AILocalOnlyMiddleware)

    from app.api.ai import router as ai_router
    from app.api.comparisons import router as comparisons_router
    from app.api.env import router as env_router
    from app.api.tasks import router as tasks_router

    app_instance.include_router(env_router)
    app_instance.include_router(tasks_router)
    app_instance.include_router(ai_router)
    app_instance.include_router(comparisons_router)

    return app_instance


app = create_app()


@app.get("/")
def root():
    return {"ok": True, "message": "AdSDK Agent is running"}


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze_endpoint(req: AnalyzeRequest):
    return analyze(req)


@app.post("/dynamic/analyze", response_model=AnalyzeResponse)
def dynamic_analyze_endpoint(
    req: DynamicAnalyzeRequest,
    frida_session_factory: Any = Depends(get_frida_session_factory),
    mitm_session_factory: Any = Depends(get_mitm_session_factory),
):
    return dynamic_analyze(
        req,
        frida_session_factory=frida_session_factory,
        mitm_session_factory=mitm_session_factory,
    )


__all__ = ["analyze", "app", "create_app", "dynamic_analyze", "lifespan", "root"]
