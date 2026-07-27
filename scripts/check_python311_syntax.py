"""Parse project Python sources using the Python 3.11 grammar."""

from __future__ import annotations

import ast
from pathlib import Path


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    files = sorted(
        [
            *root.joinpath("app").rglob("*.py"),
            *root.joinpath("tests").rglob("*.py"),
        ]
    )
    for path in files:
        source = path.read_text(encoding="utf-8")
        ast.parse(
            source,
            filename=str(path),
            feature_version=(3, 11),
        )
    print(f"Python 3.11 grammar check passed: {len(files)} files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
