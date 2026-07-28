from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Iterable, Pattern


KNOWLEDGE_BASE_PATH = (
    Path(__file__).resolve().parents[1] / "data" / "sdk_knowledge_base.json"
)
TEXT_FILE_EXTS = {
    ".smali", ".xml", ".txt", ".json", ".properties", ".html", ".js"
}
SMALI_CONTENT_HINTS = (
    "config", "constant", "buildconfig", "application", "manifest", "url", "host"
)
SMALI_ROOT_PATTERN = re.compile(r"^smali(?:_classes\d+)?$", re.IGNORECASE)


def load_sdk_knowledge_base(
    path: Path = KNOWLEDGE_BASE_PATH,
) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as file_obj:
        payload = json.load(file_obj)
    entries = payload.get("sdks")
    if not isinstance(entries, list):
        raise ValueError("sdk knowledge base must contain an sdks list")
    required = {
        "id",
        "name",
        "vendor",
        "category",
        "risk_level",
        "package_patterns",
        "domain_patterns",
        "capabilities",
    }
    for entry in entries:
        if not isinstance(entry, dict) or not required.issubset(entry):
            raise ValueError("invalid sdk knowledge base entry")
    return entries


SDK_KNOWLEDGE_BASE = load_sdk_knowledge_base()
SDK_BY_PACKAGE = {
    package: entry
    for entry in SDK_KNOWLEDGE_BASE
    for package in entry["package_patterns"]
}
# Compatibility export retained for existing callers and tests.
KNOWN_SDKS = {
    package: {"name": entry["name"], "confidence": 0.95}
    for package, entry in SDK_BY_PACKAGE.items()
}


def _compile_content_patterns(package: str) -> tuple[Pattern[str], Pattern[str]]:
    dotted = re.compile(
        rf"(?<![A-Za-z0-9_$]){re.escape(package)}(?![A-Za-z0-9_$])",
        re.IGNORECASE,
    )
    slash = re.compile(
        rf"(?<![A-Za-z0-9_$])L?{re.escape(package.replace('.', '/'))}"
        rf"(?![A-Za-z0-9_$])",
        re.IGNORECASE,
    )
    return dotted, slash


_CONTENT_PATTERNS = {
    package: _compile_content_patterns(package) for package in KNOWN_SDKS
}

_LITERAL_LOOKUP: dict[bytes, tuple[str, str, str]] = {}
for _package, _knowledge in SDK_BY_PACKAGE.items():
    _LITERAL_LOOKUP[_package.casefold().encode()] = (
        _package, "file_content", "package_literal"
    )
    _LITERAL_LOOKUP[_package.replace(".", "/").casefold().encode()] = (
        _package, "file_content", "package_literal"
    )
    _LITERAL_LOOKUP[("L" + _package.replace(".", "/")).casefold().encode()] = (
        _package, "file_content", "package_literal"
    )
    for _domain in _knowledge.get("domain_patterns", []):
        _LITERAL_LOOKUP[_domain.casefold().encode()] = (
            _package, "domain", "domain_literal"
        )
_COMBINED_LITERAL_PATTERN = re.compile(
    rb"(?<![A-Za-z0-9_$])(?:"
    + b"|".join(
        re.escape(token)
        for token in sorted(_LITERAL_LOOKUP, key=len, reverse=True)
    )
    + rb")(?![A-Za-z0-9_$])",
    re.IGNORECASE,
)


def _iter_smali_roots(unpack_dir: str) -> list[Path]:
    base = Path(unpack_dir)
    if not base.is_dir():
        return []
    return sorted(
        (
            child
            for child in base.iterdir()
            if child.is_dir() and SMALI_ROOT_PATTERN.fullmatch(child.name)
        ),
        key=lambda path: path.name.casefold(),
    )


def _relative_path(path: Path, unpack_root: Path) -> str:
    return path.relative_to(unpack_root).as_posix()


def _make_hit(
    package: str,
    *,
    confidence: float,
    source_type: str,
    relative_path: str,
    detector: str,
    description: str,
) -> dict[str, Any]:
    knowledge = SDK_BY_PACKAGE[package]
    return {
        "id": knowledge["id"],
        "sdk_name": knowledge["name"],
        "package": package,
        "vendor": knowledge["vendor"],
        "category": knowledge["category"],
        "risk_level": knowledge["risk_level"],
        "confidence": confidence,
        "version": None,
        "capabilities": list(knowledge["capabilities"]),
        "static_only": True,
        "dynamic_correlated": False,
        "evidence": [
            {
                "source_type": source_type,
                "relative_path": relative_path,
                "detector": detector,
                "description": description,
            }
        ],
    }


def _scan_paths(unpack_dir: str) -> list[dict[str, Any]]:
    unpack_root = Path(unpack_dir)
    hits: list[dict[str, Any]] = []
    for smali_root in _iter_smali_roots(unpack_dir):
        for package in KNOWN_SDKS:
            package_dir = smali_root.joinpath(*package.split("."))
            if package_dir.is_dir():
                hits.append(
                    _make_hit(
                        package,
                        confidence=0.95,
                        source_type="path",
                        relative_path=_relative_path(package_dir, unpack_root),
                        detector="package_directory",
                        description="命中完整 SDK 包目录",
                    )
                )
    return hits


def _matches_package_literal(
    text: str,
    patterns: Iterable[Pattern[str]],
) -> bool:
    return any(pattern.search(text) is not None for pattern in patterns)


def _scan_file_contents(unpack_dir: str) -> list[dict[str, Any]]:
    unpack_root = Path(unpack_dir)
    hits: list[dict[str, Any]] = []
    for smali_root in _iter_smali_roots(unpack_dir):
        for root, dirs, files in os.walk(smali_root):
            dirs.sort(key=str.casefold)
            files.sort(key=str.casefold)
            for file_name in files:
                if Path(file_name).suffix.lower() not in TEXT_FILE_EXTS:
                    continue
                suffix = Path(file_name).suffix.lower()
                if (
                    suffix == ".smali"
                    and not any(
                        hint in file_name.casefold() for hint in SMALI_CONTENT_HINTS
                    )
                ):
                    # Package directories cover bundled classes.  Content
                    # scanning focuses on configuration-like smali files to
                    # avoid repeatedly reading every decoded method body.
                    continue
                file_path = Path(root) / file_name
                try:
                    data = file_path.read_bytes()
                except OSError:
                    continue
                relative = _relative_path(file_path, unpack_root)
                matched: set[tuple[str, str, str]] = set()
                for match in _COMBINED_LITERAL_PATTERN.finditer(data):
                    token = match.group(0).lower()
                    info = _LITERAL_LOOKUP.get(token)
                    if info is not None:
                        matched.add(info)
                for package, source_type, detector in matched:
                    hits.append(
                        _make_hit(
                            package,
                            confidence=0.97 if detector == "package_literal" else 0.82,
                            source_type=source_type,
                            relative_path=relative,
                            detector=detector,
                            description=(
                                "命中边界完整的包名或 Dalvik 类路径"
                                if detector == "package_literal"
                                else "命中 SDK 域名模式"
                            ),
                        )
                    )
    return hits


def _scan_native_libraries(unpack_dir: str) -> list[dict[str, Any]]:
    unpack_root = Path(unpack_dir)
    hits: list[dict[str, Any]] = []
    for file_path in sorted(unpack_root.glob("lib/**/*.so")):
        name = file_path.name.casefold()
        for package, knowledge in SDK_BY_PACKAGE.items():
            if any(
                pattern.casefold() in name
                for pattern in knowledge.get("native_library_patterns", [])
            ):
                hits.append(
                    _make_hit(
                        package,
                        confidence=0.88,
                        source_type="native_library",
                        relative_path=_relative_path(file_path, unpack_root),
                        detector="native_library_name",
                        description=f"命中原生库 {file_path.name}",
                    )
                )
    return hits


def _merge_hits(raw_hits: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[tuple[str, str], dict[str, Any]] = {}
    evidence_keys: dict[tuple[str, str], set[tuple[str, str, str]]] = {}
    for hit in raw_hits:
        key = (hit["sdk_name"], hit["package"])
        if key not in merged:
            merged[key] = {**hit, "evidence": []}
            evidence_keys[key] = set()
        current = merged[key]
        current["confidence"] = max(current["confidence"], hit["confidence"])
        for evidence in hit.get("evidence", []):
            evidence_key = (
                evidence["source_type"],
                evidence["relative_path"],
                evidence["detector"],
            )
            if evidence_key not in evidence_keys[key]:
                evidence_keys[key].add(evidence_key)
                current["evidence"].append(evidence)
    for hit in merged.values():
        hit["evidence"].sort(
            key=lambda item: (
                item["relative_path"],
                item["source_type"],
                item["detector"],
            )
        )
    return sorted(
        merged.values(),
        key=lambda hit: (
            -hit["confidence"],
            hit["sdk_name"].casefold(),
            hit["package"],
        ),
    )


def scan_for_sdks(unpack_dir: str) -> list[dict[str, Any]]:
    return _merge_hits(
        [
            *_scan_paths(unpack_dir),
            *_scan_file_contents(unpack_dir),
            *_scan_native_libraries(unpack_dir),
        ]
    )
