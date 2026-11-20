"""Export OpenAPI schema from FastAPI backend to openapi.json."""

from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from app.main import create_app  # noqa: E402

OPENAPI_JSON = PROJECT_ROOT / "openapi.json"


def export_openapi() -> Path:
    app = create_app()
    schema = app.openapi()
    OPENAPI_JSON.write_text(
        json.dumps(schema, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(f"Exported OpenAPI schema to {OPENAPI_JSON}")
    return OPENAPI_JSON


if __name__ == "__main__":
    export_openapi()
