"""AdSDK Agent FastAPI application entry point."""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.deps import get_frida_session_factory, get_mitm_session_factory
from app.api.middleware import AILocalOnlyMiddleware
from app.config import STATIC_UNPACK_CACHE_DIR
from app.container import Container, _default_container, build_container
from app.models import AnalyzeRequest, AnalyzeResponse, DynamicAnalyzeRequest
from app.pipelines.dynamic import dynamic_analyze
from app.pipelines.static import analyze
from app.pipelines.task_runner import run_persisted_task
from app.services.application_name_service import repair_historical_application_names


@asynccontextmanager
async def lifespan(app: FastAPI):
    container: Container = getattr(app.state, "container", None)
    if container is None:
        container = build_container()
        app.state.container = container
    container.task_service.set_runner(run_persisted_task)
    container.task_repository.initialize()
    repair_historical_application_names(
        container.task_repository,
        static_unpack_cache_dir=STATIC_UNPACK_CACHE_DIR,
    )
    container.task_service.recover()
    yield
    container.task_service.shutdown()


def create_app(container: Container | None = None) -> FastAPI:
    """Build the ASGI app: CORS, local-only guard, and domain routers."""
    if container is None:
        container = build_container()
    app_instance = FastAPI(title="AdSDK Agent", version="0.2.0", lifespan=lifespan)
    app_instance.state.container = container
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


app = create_app(_default_container)


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
