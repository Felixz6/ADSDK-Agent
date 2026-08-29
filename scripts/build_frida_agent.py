"""Build the bundled Frida hook agent artifact.

Frida 17 no longer ships the Java bridge inside GumJS, so the hook script's
``Java`` global must be restored by bundling ``frida-java-bridge`` with
frida-compile. This script compiles ``scripts/frida-agent/agent_main.js``
(plus ``app/frida_hooks/sensitive_apis.js``) into the fixed artifact
``app/frida_hooks/agent.compiled.js`` that the dynamic pipeline loads at
runtime. The build is fully local: the pinned dependency lives in
``scripts/frida-agent/node_modules`` (installed once via npm) and no network
access happens at task runtime.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
AGENT_DIR = PROJECT_ROOT / "scripts" / "frida-agent"
ENTRY = AGENT_DIR / "agent_main.js"
OUTPUT = PROJECT_ROOT / "app" / "frida_hooks" / "agent.compiled.js"

# The bundled artifact must keep the three load-bearing pieces: the entry's
# globalThis.Java restoration, the java bridge itself, and the hook script's
# pending branch (which stays as the honest diagnostic for a broken bundle).
_REQUIRED_MARKERS = ("globalThis.Java", "libart", "java_runtime_pending")


def _resolve_frida_compile() -> str:
    venv_candidate = (
        PROJECT_ROOT / ".venv" / "Scripts" / "frida-compile.exe"
    )
    if venv_candidate.is_file():
        return str(venv_candidate)
    return "frida-compile"


def build() -> Path:
    if not ENTRY.is_file():
        raise SystemExit(f"agent entry missing: {ENTRY}")
    node_modules = AGENT_DIR / "node_modules" / "frida-java-bridge"
    if not node_modules.is_dir():
        raise SystemExit(
            "frida-java-bridge not installed; run `npm install` in "
            f"{AGENT_DIR} once (offline afterwards)"
        )

    # ``-B iife`` emits plain JS: the dynamic pipeline prepends the per-run
    # ``__ADSDK_CONTEXT__`` line, and GumJS only parses the multi-chunk
    # ``📦`` bundle format when it starts at byte 0.
    command = [
        _resolve_frida_compile(),
        "-S",
        "-B",
        "iife",
        str(ENTRY),
        "-o",
        str(OUTPUT),
    ]
    completed = subprocess.run(
        command,
        cwd=str(AGENT_DIR),
        capture_output=True,
        text=True,
        shell=False,
        timeout=300,
    )
    if completed.returncode != 0:
        raise SystemExit(
            "frida-compile failed:\n"
            f"{completed.stdout or ''}\n{completed.stderr or ''}"
        )

    artifact = OUTPUT.read_bytes()
    text = artifact.decode("utf-8", errors="replace")
    missing = [m for m in _REQUIRED_MARKERS if m not in text]
    raw_script = (
        PROJECT_ROOT / "app" / "frida_hooks" / "sensitive_apis.js"
    ).stat().st_size
    if missing or len(artifact) < 8 * raw_script:
        raise SystemExit(
            "built artifact failed verification; missing markers: "
            f"{missing}, size={len(artifact)}, raw={raw_script}"
        )
    print(f"built {OUTPUT} ({len(artifact)} bytes)")
    return OUTPUT


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    os.environ.setdefault("PYTHONUTF8", "1")
    build()


if __name__ == "__main__":
    sys.exit(main())
