import os
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Pattern


KNOWN_SDKS = {
    "com.bytedance.sdk.openadsdk": {"name": "Pangle", "confidence": 0.95},
    "com.qq.e.comm": {"name": "优量汇/GDT", "confidence": 0.95},
    "com.baidu.mobads": {"name": "百度广告SDK", "confidence": 0.92},
    "com.kwad.sdk": {"name": "快手/Kwai Ads", "confidence": 0.92},
    "com.mbridge.msdk": {"name": "Mintegral", "confidence": 0.92},
    "com.unity3d.ads": {"name": "Unity Ads", "confidence": 0.90},
    "com.applovin": {"name": "AppLovin", "confidence": 0.90},
    "com.google.android.gms.ads": {"name": "AdMob", "confidence": 0.95},
    "com.ironsource": {"name": "ironSource", "confidence": 0.88},
    "com.vungle": {"name": "Vungle", "confidence": 0.88},
}

TEXT_FILE_EXTS = {".smali", ".xml", ".txt", ".json", ".properties"}
SMALI_ROOT_PATTERN = re.compile(r"^smali(?:_classes\d+)?$", re.IGNORECASE)


def _compile_content_patterns(package: str) -> tuple[Pattern[str], Pattern[str]]:
    """Compile boundary-aware dotted and Dalvik/slash package patterns."""
    dotted = re.compile(
        rf"(?<![A-Za-z0-9_$]){re.escape(package)}(?![A-Za-z0-9_$])",
        re.IGNORECASE,
    )
    slash_package = package.replace(".", "/")
    slash = re.compile(
        rf"(?<![A-Za-z0-9_$])L?{re.escape(slash_package)}(?![A-Za-z0-9_$])",
        re.IGNORECASE,
    )
    return dotted, slash


_CONTENT_PATTERNS: Dict[str, tuple[Pattern[str], Pattern[str]]] = {
    package: _compile_content_patterns(package) for package in KNOWN_SDKS
}


def _iter_smali_roots(unpack_dir: str) -> List[Path]:
    """Return only direct ``smali``/``smali_classesN`` children."""
    base = Path(unpack_dir)
    children = list(base.iterdir())

    return sorted(
        (
            child
            for child in children
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
) -> Dict[str, Any]:
    meta = KNOWN_SDKS[package]
    return {
        "sdk_name": meta["name"],
        "package": package,
        "confidence": confidence,
        "version": None,
        "evidence": [
            {
                "source_type": source_type,
                "relative_path": relative_path,
                "detector": detector,
                "description": description,
            }
        ],
    }


def _scan_paths(unpack_dir: str) -> List[Dict[str, Any]]:
    """Match complete package-directory segments below decoded smali roots."""
    unpack_root = Path(unpack_dir)
    hits: List[Dict[str, Any]] = []

    for smali_root in _iter_smali_roots(unpack_dir):
        for package, meta in KNOWN_SDKS.items():
            package_dir = smali_root.joinpath(*package.split("."))
            if not package_dir.is_dir():
                continue

            relative_package = package_dir.relative_to(smali_root).as_posix()
            hits.append(
                _make_hit(
                    package,
                    confidence=meta["confidence"],
                    source_type="path",
                    relative_path=_relative_path(package_dir, unpack_root),
                    detector="package_directory",
                    description=(
                        f"Matched complete package directory {relative_package} "
                        f"under {smali_root.name}"
                    ),
                )
            )

    return hits


def _matches_package_literal(
    text: str,
    patterns: Iterable[Pattern[str]],
) -> bool:
    return any(pattern.search(text) is not None for pattern in patterns)


def _scan_file_contents(unpack_dir: str) -> List[Dict[str, Any]]:
    """Match boundary-aware package literals inside decoded smali roots only."""
    unpack_root = Path(unpack_dir)
    hits: List[Dict[str, Any]] = []

    for smali_root in _iter_smali_roots(unpack_dir):
        for root, dirs, files in os.walk(smali_root):
            dirs.sort(key=str.casefold)
            files.sort(key=str.casefold)

            for file_name in files:
                if Path(file_name).suffix.lower() not in TEXT_FILE_EXTS:
                    continue

                file_path = Path(root) / file_name
                matched_packages: set[str] = set()
                try:
                    with file_path.open(
                        "r",
                        encoding="utf-8",
                        errors="ignore",
                    ) as file_obj:
                        for line in file_obj:
                            for package, patterns in _CONTENT_PATTERNS.items():
                                if package in matched_packages:
                                    continue
                                if _matches_package_literal(line, patterns):
                                    matched_packages.add(package)
                except OSError:
                    continue

                relative_file = _relative_path(file_path, unpack_root)
                for package in matched_packages:
                    meta = KNOWN_SDKS[package]
                    hits.append(
                        _make_hit(
                            package,
                            confidence=min(0.99, meta["confidence"] + 0.02),
                            source_type="file_content",
                            relative_path=relative_file,
                            detector="package_literal",
                            description=(
                                "Matched a boundary-delimited dotted or "
                                "Dalvik package literal"
                            ),
                        )
                    )

    return hits


def _merge_hits(raw_hits: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    merged: Dict[tuple[str, str], Dict[str, Any]] = {}
    evidence_keys: Dict[tuple[str, str], set[tuple[str, str, str]]] = {}

    for hit in raw_hits:
        key = (hit["sdk_name"], hit["package"])
        current = merged.get(key)
        if current is None:
            current = {
                "sdk_name": hit["sdk_name"],
                "package": hit["package"],
                "confidence": hit["confidence"],
                "version": hit.get("version"),
                "evidence": [],
            }
            merged[key] = current
            evidence_keys[key] = set()
        elif hit["confidence"] > current["confidence"]:
            current["confidence"] = hit["confidence"]
            current["version"] = hit.get("version")

        for evidence in hit.get("evidence", []):
            evidence_key = (
                evidence["source_type"],
                evidence["relative_path"],
                evidence["detector"],
            )
            if evidence_key in evidence_keys[key]:
                continue
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


def scan_for_sdks(unpack_dir: str) -> List[Dict[str, Any]]:
    path_hits = _scan_paths(unpack_dir)
    content_hits = _scan_file_contents(unpack_dir)
    return _merge_hits([*path_hits, *content_hits])
