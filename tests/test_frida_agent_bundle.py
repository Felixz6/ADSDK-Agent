"""Regression tests for the Frida 17 hook-agent bundle.

Frida 17 no longer ships the Java bridge inside GumJS, so the dynamic
pipeline must inject the frida-compile bundle (``agent.compiled.js``) that
restores ``globalThis.Java`` via ``frida-java-bridge``. These tests pin the
build contract without executing Frida or touching a device.
"""

from __future__ import annotations

from pathlib import Path

from app.main import resolve_frida_hook_script


PROJECT_ROOT = Path(__file__).resolve().parent.parent
HOOKS_DIR = PROJECT_ROOT / "app" / "frida_hooks"
RAW_SCRIPT = HOOKS_DIR / "sensitive_apis.js"
ARTIFACT = HOOKS_DIR / "agent.compiled.js"


def test_bundled_hook_agent_artifact_exists():
    """The fixed artifact is committed and present for offline runs."""

    assert ARTIFACT.is_file(), (
        "agent.compiled.js missing; run scripts/build_frida_agent.py"
    )


def test_artifact_is_frida_compile_bundle_not_raw_script():
    """The injected source is the bundle, not the raw ``sensitive_apis.js``.

    The bundle must carry the entry's ``globalThis.Java`` restoration and the
    java bridge itself (``libart`` appears inside bridge sources), and be far
    larger than the raw hook script.
    """

    artifact = ARTIFACT.read_text(encoding="utf-8", errors="replace")
    raw = RAW_SCRIPT.read_text(encoding="utf-8")

    assert "globalThis.Java" in artifact, (
        "bundle does not restore the globalThis.Java contract"
    )
    assert "libart" in artifact, "java bridge is not bundled in the artifact"
    assert len(artifact) >= 8 * len(raw)
    assert artifact != raw, (
        "artifact is a verbatim copy of the raw script; rebuild with "
        "frida-compile"
    )
    assert not artifact.lstrip().startswith("📦"), (
        "multi-chunk bundle format would break the __ADSDK_CONTEXT__ "
        "prepend; build with -B iife"
    )


def test_java_runtime_pending_is_diagnostic_not_runtime_failure():
    """The pending marker stays bound to its pending-only branch.

    The raw script keeps ``java_runtime_pending`` exactly once — the honest
    initial diagnostic emitted before hook installation — and reports the
    resolved Java runtime state in the same control event's metadata, so a
    healthy Frida 17 environment (bridge bundled) can never be stuck
    reporting pending.
    """

    raw = RAW_SCRIPT.read_text(encoding="utf-8")
    assert raw.count('"java_runtime_pending"') == 1
    assert "java_runtime" in raw
    assert 'typeof Java === "undefined"' in raw, (
        "the guard keeps hook installation safe when the bridge is absent"
    )


def test_resolver_prefers_bundle_and_falls_back_to_raw(tmp_path):
    """Loader selection: bundle wins when present, raw script otherwise."""

    empty_dir = tmp_path / "hooks-empty"
    empty_dir.mkdir()
    fallback = resolve_frida_hook_script(hooks_dir=empty_dir)
    assert fallback.name == "sensitive_apis.js"

    populated = tmp_path / "hooks-built"
    populated.mkdir()
    (populated / "agent.compiled.js").write_text("bundle", encoding="utf-8")
    (populated / "sensitive_apis.js").write_text("raw", encoding="utf-8")
    assert resolve_frida_hook_script(hooks_dir=populated) == (
        populated / "agent.compiled.js"
    )

    assert resolve_frida_hook_script() == ARTIFACT


def test_session_context_prepend_wraps_bundle_intact(tmp_path: Path):
    """The per-run context prepend still lands above a loadable script."""

    from app.core.device import DeviceContext
    from app.tools.frida_session import FridaSession

    session = FridaSession(
        run_id="bundle-contract",
        device=DeviceContext("SERIAL"),
        package_name="com.example.app",
        script_path=ARTIFACT,
        event_log_path=tmp_path / "events.jsonl",
    )
    source = session._script_source()
    assert source.startswith("globalThis.__ADSDK_CONTEXT__ = Object.freeze(")
    assert "globalThis.Java" in source
    assert 'globalThis.__ADSDK_CONTEXT__' not in ARTIFACT.read_text(
        encoding="utf-8", errors="replace"
    )[:200]
