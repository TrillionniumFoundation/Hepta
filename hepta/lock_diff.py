"""Read-only comparison of v1 package snapshots, not API compatibility analysis."""
from __future__ import annotations

import json
from pathlib import Path, PurePosixPath
import posixpath
import re

from .packages import digest, fail


def _invalid(path, message):
    fail("E_LOCK_INVALID", message, path)


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def _constant(value):
    raise ValueError(f"Non-JSON constant: {value}")


def _relative(value, *, root=False):
    return (isinstance(value, str) and bool(value) and "\x00" not in value
            and not PurePosixPath(value).is_absolute()
            and posixpath.normpath(value) == value and (root or value != "."))


def _hash(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def read_lock_snapshot(path) -> dict:
    """Validate a self-contained lock document without opening its recorded paths."""
    path = Path(path)
    try:
        snapshot = json.loads(path.read_bytes(), object_pairs_hook=_object,
                              parse_constant=_constant)
    except (ValueError, UnicodeError, RecursionError) as error:
        _invalid(path, f"Cannot decode package lock: {error}")
    if (not isinstance(snapshot, dict)
            or set(snapshot) != {"schema", "packages", "files", "sha256"}
            or snapshot["schema"] != "hepta.lock.v1"):
        _invalid(path, "Expected the exact hepta.lock.v1 snapshot schema")
    packages, files = snapshot["packages"], snapshot["files"]
    if not isinstance(packages, dict) or "." not in packages or not isinstance(files, dict):
        _invalid(path, "Lock requires a root package and a file hash map")
    for name, sha in files.items():
        if not _relative(name) or not _hash(sha):
            _invalid(path, "Lock file entries require canonical relative paths and SHA-256 hashes")
    for location, package in packages.items():
        if (not _relative(location, root=True) or not isinstance(package, dict)
                or set(package) != {"name", "version", "kind", "entry", "dependencies"}):
            _invalid(path, "Invalid lock package record")
        name, version, kind = package["name"], package["version"], package["kind"]
        entry, dependencies = package["entry"], package["dependencies"]
        if (not isinstance(name, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name)
                or not isinstance(version, str)
                or not re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", version)
                or not isinstance(kind, str) or kind not in {"bin", "lib"}
                or not _relative(entry) or ".." in PurePosixPath(entry).parts
                or not entry.endswith(".hepta") or not isinstance(dependencies, dict)):
            _invalid(path, "Invalid lock package metadata")
        for alias, target in dependencies.items():
            if (not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", alias)
                    or not isinstance(target, str) or target not in packages):
                _invalid(path, "Lock dependency must name an existing package")
        if posixpath.normpath(posixpath.join(location, "hepta.toml")) not in files:
            _invalid(path, "Lock omits a package manifest hash")
    # Iterative traversal also rejects cycles without consuming Python call depth.
    visited, active, stack = set(), set(), [(".", False)]
    while stack:
        location, leaving = stack.pop()
        if leaving:
            active.remove(location)
            visited.add(location)
            continue
        if location in active:
            _invalid(path, "Lock dependency graph contains a cycle")
        if location in visited:
            continue
        active.add(location)
        stack.append((location, True))
        for target in packages[location]["dependencies"].values():
            if packages[target]["kind"] != "lib":
                _invalid(path, "Lock dependencies must be libraries")
            stack.append((target, False))
    if visited != set(packages):
        _invalid(path, "Lock contains unreachable packages")
    content = {"packages": packages, "files": files}
    expected = digest(json.dumps(content, sort_keys=True, separators=(",", ":")).encode())
    if not _hash(snapshot["sha256"]) or snapshot["sha256"] != expected:
        _invalid(path, "Lock content hash does not match its package and file maps")
    return snapshot


def compare_locks(before, after) -> dict:
    """Compare two valid snapshots by recorded path, preserving all changes."""
    old, new = read_lock_snapshot(before), read_lock_snapshot(after)
    left, right = old["packages"], new["packages"]
    packages = {
        "added": [{"path": p, "package": right[p]} for p in sorted(right.keys() - left.keys())],
        "removed": [{"path": p, "package": left[p]} for p in sorted(left.keys() - right.keys())],
        "changed": [],
    }
    for path in sorted(left.keys() & right.keys()):
        changes = {field: {"before": left[path][field], "after": right[path][field]}
                   for field in ("name", "version", "kind", "entry")
                   if left[path][field] != right[path][field]}
        if changes:
            packages["changed"].append({"path": path, "changes": changes})
    edges = lambda nodes: {(p, alias): target for p, node in nodes.items()
                           for alias, target in node["dependencies"].items()}
    old_edges, new_edges = edges(left), edges(right)
    dependencies = {
        "added": [{"package": p, "alias": a, "target": new_edges[p, a]}
                  for p, a in sorted(new_edges.keys() - old_edges.keys())],
        "removed": [{"package": p, "alias": a, "target": old_edges[p, a]}
                    for p, a in sorted(old_edges.keys() - new_edges.keys())],
        "retargeted": [{"package": p, "alias": a, "before": old_edges[p, a], "after": new_edges[p, a]}
                       for p, a in sorted(old_edges.keys() & new_edges.keys())
                       if old_edges[p, a] != new_edges[p, a]],
    }
    left_files, right_files = old["files"], new["files"]
    files = {
        "added": [{"path": p, "sha256": right_files[p]}
                  for p in sorted(right_files.keys() - left_files.keys())],
        "removed": [{"path": p, "sha256": left_files[p]}
                    for p in sorted(left_files.keys() - right_files.keys())],
        "changed": [{"path": p, "before": left_files[p], "after": right_files[p]}
                    for p in sorted(left_files.keys() & right_files.keys()) if left_files[p] != right_files[p]],
    }
    return {"schema": "hepta.lock-diff.v1", "ok": True,
            "changed": old != new, "compatibility": "not_assessed",
            "before_sha256": old["sha256"], "after_sha256": new["sha256"],
            "packages": packages, "dependencies": dependencies, "files": files}
