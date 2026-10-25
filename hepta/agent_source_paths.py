"""Normalize snapshot-bound Hepta declaration paths for stable Agent identity.

Only source paths resolved by the canonical module loader and present in the
pinned v4 validated-source inventory qualify. No filesystem reads or symlink
resolution occur here: the workspace pin already owns those checks.
"""
from __future__ import annotations

from pathlib import Path


def relative_validated_source(source_path: str, snapshot_root: str,
                              validated_sources: list[str]) -> str:
    """Return the manifest-relative POSIX path, reject unbound or escaped paths."""
    if (not isinstance(snapshot_root, str) or not snapshot_root
            or not isinstance(source_path, str) or not source_path
            or not isinstance(validated_sources, list) or not validated_sources):
        raise ValueError("missing pinned source/root/validated inventory")
    root, source = Path(snapshot_root), Path(source_path)
    if not root.is_absolute() or not source.is_absolute():
        raise ValueError("semantic source and pinned root must be absolute")
    if any(part == ".." for part in source.parts):
        raise ValueError("semantic source contains parent traversal")
    inventory = set()
    for item in validated_sources:
        if (not isinstance(item, str) or not item or "\\" in item
                or not item.endswith(".hepta")):
            raise ValueError("invalid validated source inventory")
        path = Path(item)
        if path.is_absolute() or any(part in {".", ".."} for part in path.parts):
            raise ValueError("validated source escapes project root")
        if path.as_posix() != item or item in inventory:
            raise ValueError("noncanonical or repeated validated source")
        inventory.add(item)
    try:
        relative = source.relative_to(root).as_posix()
    except ValueError as exc:
        raise ValueError("semantic source escapes pinned workspace") from exc
    if relative not in inventory:
        raise ValueError("semantic source absent from validated snapshot")
    return relative
