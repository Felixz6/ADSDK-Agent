"""XML utility helpers for Android manifest and resource parsing."""

from __future__ import annotations


def local_tag_name(tag: str) -> str:
    """Strip XML namespace prefix from an ElementTree tag name."""
    return tag.rsplit("}", 1)[-1]


_local_name = local_tag_name

__all__ = ["_local_name", "local_tag_name"]
