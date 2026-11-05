"""Deterministic, bounded version solving over explicitly named local candidates.

This module never downloads packages, runs build scripts or selects an implicit
registry. Fixed path dependencies retain their existing identity semantics.
"""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import re

from .ast import HeptaError
from .packages import fail, load_package, read_package

MAX_CANDIDATES = 32
MAX_IDENTITIES = 64
MAX_ATTEMPTS = 4096
_VERSION = r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
_COMPARATOR = re.compile(r"(>=|<=|>|<|=)?\s*(" + _VERSION + r")")


def version_key(version):
    # Numeric ordering without converting arbitrarily long decimal components
    # to Python integers. Manifest parsing already verifies canonical spelling.
    return tuple((len(part), part) for part in version.split("."))


def requirement(text, manifest):
    if not isinstance(text, str) or not text or len(text) > 256:
        fail("E_PACKAGE_REQUIREMENT", "version must be a nonempty version requirement of at most 256 characters", manifest)
    parts = text.split(",")
    if len(parts) > 8:
        fail("E_PACKAGE_REQUIREMENT", "At most eight comma-separated version comparisons are supported", manifest)
    result = []
    for part in parts:
        match = _COMPARATOR.fullmatch(part.strip())
        if match is None:
            fail("E_PACKAGE_REQUIREMENT", "Use full major.minor.patch versions with =, >=, >, <= or <, joined by commas", manifest)
        operator, version = match.groups()
        result.append((operator or "=", version_key(version)))
    return result


def satisfies(version, comparisons):
    actual = version_key(version)
    for operator, expected in comparisons:
        if not {"=": actual == expected, ">=": actual >= expected,
                ">": actual > expected, "<=": actual <= expected,
                "<": actual < expected}[operator]:
            return False
    return True


class _Choice(Exception):
    def __init__(self, name, roots):
        self.name, self.roots = name, roots


class _Conflict(Exception):
    def __init__(self, message, manifest):
        self.message, self.manifest = message, manifest


class _Resolution:
    def __init__(self):
        self.selected = {}
        self.manifests = {}

    def read(self, root):
        if root not in self.manifests:
            self.manifests[root] = read_package(root)
        package, deps = self.manifests[root]
        # Each search attempt gets its own graph; never reuse a failed attempt's
        # mutable dependency edges. The manifest bytes stay fixed for this run.
        return replace(package, dependencies={}), deps

    def choose(self, root, alias, spec):
        manifest = root / "hepta.toml"
        if not isinstance(spec, dict) or set(spec) != {"package", "version", "candidates"}:
            fail("E_PACKAGE_DEPENDENCY", 'Dependencies require { path = "..." } or { package, version, candidates }; no network/registry resolution is performed', manifest)
        name, paths = spec["package"], spec["candidates"]
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            fail("E_PACKAGE_DEPENDENCY", "Candidate package must be an ASCII identifier", manifest)
        comparisons = requirement(spec["version"], manifest)
        if not isinstance(paths, list) or not 1 <= len(paths) <= MAX_CANDIDATES or any(not isinstance(p, str) or not p for p in paths):
            fail("E_PACKAGE_DEPENDENCY", f"candidates must contain 1 to {MAX_CANDIDATES} nonempty local paths", manifest)
        roots = [(root / path).resolve() for path in paths]
        if len(set(roots)) != len(roots):
            fail("E_PACKAGE_DEPENDENCY", "Candidate paths must be distinct", manifest)
        eligible = []
        for candidate in roots:
            package, _ = self.read(candidate)
            if package.name != name or package.kind != "lib":
                fail("E_PACKAGE_DEPENDENCY", f"Every candidate for {alias} must be a library named {name}", manifest)
            if satisfies(package.version, comparisons):
                eligible.append((candidate, package.version))
        # Highest version first, then canonical path for equal versions. Sorting
        # never depends on manifest array order or filesystem enumeration order.
        eligible.sort(key=lambda item: item[0].as_posix())
        eligible.sort(key=lambda item: version_key(item[1]), reverse=True)
        allowed = [candidate for candidate, _ in eligible]
        if not allowed:
            raise _Conflict(f"No local candidate for {alias} ({name}) satisfies {spec['version']}", manifest)
        if name in self.selected:
            candidate = self.selected[name]
            if candidate not in allowed:
                raise _Conflict(f"Conflicting local candidate requirements for package {name} at dependency {alias}", manifest)
            return candidate
        if len(self.selected) >= MAX_IDENTITIES:
            fail("E_PACKAGE_RESOLUTION_LIMIT", f"Local resolution exceeds {MAX_IDENTITIES} selected package identities", manifest)
        raise _Choice(name, allowed)


def resolve_package(root, stack=None, cache=None):
    root = Path(root).resolve()
    resolution = _Resolution()
    pending = [{}]
    attempts = 0
    conflict = None
    while pending:
        if attempts >= MAX_ATTEMPTS:
            fail("E_PACKAGE_RESOLUTION_LIMIT", f"Local resolution exceeds {MAX_ATTEMPTS} graph attempts; narrow candidate lists or requirements", root / "hepta.toml")
        attempts += 1
        resolution.selected = pending.pop()
        try:
            # A previous loaded graph cannot supply this search's constraints.
            # Rebuild every attempt, even when the legacy caller supplied a cache;
            # only a complete solution is published back to that cache.
            attempt_cache = {}
            result = load_package(root, stack, attempt_cache, _resolution=resolution)
        except _Choice as choice:
            for candidate in reversed(choice.roots):
                pending.append({**resolution.selected, choice.name: candidate})
        except _Conflict as error:
            conflict = error
        except HeptaError as error:
            if error.diagnostic.code != "E_PACKAGE_CYCLE" or not resolution.selected:
                raise
            conflict = _Conflict(error.diagnostic.message, root / "hepta.toml")
        else:
            if cache is not None:
                cache.update(attempt_cache)
            return result
    assert conflict is not None
    fail("E_PACKAGE_RESOLUTION", conflict.message, conflict.manifest)
