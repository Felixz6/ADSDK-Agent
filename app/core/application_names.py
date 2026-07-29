from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path


_NAMED_STRING_REFERENCE = re.compile(
    r"^@(?:\*?[A-Za-z0-9_.]+:)?string/(?P<name>[A-Za-z0-9_.-]+)$"
)
_NUMERIC_REFERENCE = re.compile(r"^@(?:0x)?(?P<id>[0-9A-Fa-f]{8})$")
_LOCALE_QUALIFIER = re.compile(
    r"^(?:[a-z]{2,3}|b\+[A-Za-z0-9+]+)(?:-r[A-Z]{2})?(?:-.+)?$"
)


def is_android_resource_reference(value: str | None) -> bool:
    text = (value or "").strip()
    return bool(text) and text[0] in {"@", "?"}


def stable_application_name(
    resolved_app_name: str | None,
    *,
    apk_filename: str | None = None,
    package_name: str | None = None,
) -> str:
    """Return a user-facing name without leaking Android resource expressions."""

    for candidate in (resolved_app_name, apk_filename, package_name, "未知应用"):
        text = (candidate or "").strip()
        if text and not is_android_resource_reference(text):
            return text
    return "未知应用"


def resolve_application_label(
    unpack_dir: str | Path,
    raw_label: str | None,
) -> str | None:
    """Resolve an apktool-decoded application label.

    apktool expands ``resources.arsc`` into ``res/values*`` XML files. The
    lookup order is deterministic: base values, Simplified/Traditional
    Chinese, English, then the remaining locale-qualified directories.
    """

    label = (raw_label or "").strip()
    if not label:
        return None
    if not is_android_resource_reference(label):
        return label

    root = Path(unpack_dir)
    resource_name = _resource_name(root, label)
    if not resource_name:
        return None

    for values_dir in _ordered_values_directories(root / "res"):
        value = _read_string_resource(values_dir, resource_name)
        if value:
            return value
    return None


def _resource_name(unpack_dir: Path, label: str) -> str | None:
    named = _NAMED_STRING_REFERENCE.fullmatch(label)
    if named:
        return named.group("name")

    numeric = _NUMERIC_REFERENCE.fullmatch(label)
    if not numeric:
        return None
    target = int(numeric.group("id"), 16)
    public_xml = unpack_dir / "res" / "values" / "public.xml"
    try:
        root = ET.parse(public_xml).getroot()
    except (ET.ParseError, OSError):
        return None
    for element in root:
        if (
            _local_name(element.tag) == "public"
            and element.attrib.get("type") == "string"
        ):
            try:
                resource_id = int(element.attrib.get("id", ""), 16)
            except ValueError:
                continue
            if resource_id == target:
                return element.attrib.get("name")
    return None


def _ordered_values_directories(res_dir: Path) -> list[Path]:
    if not res_dir.is_dir():
        return []
    directories = [path for path in res_dir.iterdir() if path.is_dir()]
    base = [path for path in directories if path.name == "values"]
    locale_dirs = [
        path
        for path in directories
        if path.name.startswith("values-")
        and _LOCALE_QUALIFIER.fullmatch(path.name.removeprefix("values-"))
    ]

    def priority(path: Path) -> tuple[int, str]:
        qualifier = path.name.removeprefix("values-").lower()
        if qualifier in {"zh-rcn", "b+zh+Hans".lower()}:
            return (0, qualifier)
        if qualifier in {"zh", "zh-rtw", "b+zh+Hant".lower()}:
            return (1, qualifier)
        if qualifier.startswith(("zh-", "b+zh+")):
            return (2, qualifier)
        if qualifier == "en" or qualifier.startswith(("en-", "b+en+")):
            return (3, qualifier)
        return (4, qualifier)

    return [*base, *sorted(locale_dirs, key=priority)]


def _read_string_resource(values_dir: Path, resource_name: str) -> str | None:
    for xml_path in sorted(values_dir.glob("*.xml")):
        try:
            root = ET.parse(xml_path).getroot()
        except (ET.ParseError, OSError):
            continue
        for element in root:
            tag = _local_name(element.tag)
            is_string = tag == "string" or (
                tag == "item" and element.attrib.get("type") == "string"
            )
            if not is_string or element.attrib.get("name") != resource_name:
                continue
            value = "".join(element.itertext()).strip()
            if value and not is_android_resource_reference(value):
                return _decode_android_escapes(value)
    return None


def _decode_android_escapes(value: str) -> str:
    return (
        value.replace(r"\n", " ")
        .replace(r"\'", "'")
        .replace(r'\"', '"')
        .replace(r"\\", "\\")
        .strip()
    )


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]
