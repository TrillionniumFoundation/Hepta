"""Isolated fork for request-context qualification; not production.
Upstream: #615 hepta/packages.py. Keep parity controls with the original.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
import tomllib

from hepta.ast import Diagnostic, HeptaError, Span


def fail(code, message, path):
    raise HeptaError(Diagnostic(code, message, Span(path=str(path)), phase="package"))


def digest(data):
    return hashlib.sha256(data).hexdigest()


@dataclass
class Package:
    root: Path
    name: str
    version: str
    entry: Path
    kind: str
    source_root: Path
    dependencies: dict[str, "Package"] = field(default_factory=dict)
    manifest_bytes: bytes | None = None


def _inside(path: Path, root: Path, message: str):
    if not path.is_relative_to(root):
        fail("E_PACKAGE_ESCAPE", message, path)
    return path


def load_package(root, _stack=None, _cache=None, *, context) -> Package:
    root = Path(root).resolve()
    stack = [] if _stack is None else _stack
    cache = {} if _cache is None else _cache
    manifest = root / "hepta.toml"
    context.charge('package_edges')
    context.depth(len(stack) + 1, context.limits.package_depth)
    if root in stack:
        fail("E_PACKAGE_CYCLE", "Dependency cycle: " + " -> ".join(str(p) for p in stack + [root]), manifest)
    if root in cache:
        return cache[root]
    if not manifest.is_file():
        fail("E_PACKAGE_MANIFEST", "Expected a hepta.toml manifest", manifest)
    context.admit('packages', len(stack) + 1, context.limits.package_depth)
    data = context.read(manifest, 'manifest')
    try:
        config = context.toml(data, manifest)
    except (ValueError, UnicodeError) as e:
        fail("E_PACKAGE_MANIFEST", str(e), manifest)
    if set(config) - {"package", "dependencies"} or not isinstance(config.get("package"), dict):
        fail("E_PACKAGE_SCHEMA", "Only [package] and optional [dependencies] are supported", manifest)
    meta = config["package"]
    if set(meta) - {"name", "version", "kind", "entry", "source_root"}:
        fail("E_PACKAGE_SCHEMA", "Unsupported package key; build scripts are not supported", manifest)
    name, version = meta.get("name"), meta.get("version")
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
        fail("E_PACKAGE_NAME", "Package name must be an ASCII identifier", manifest)
    if not isinstance(version, str) or not re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", version):
        fail("E_PACKAGE_VERSION", "Package version must be an explicit major.minor.patch", manifest)
    kind = meta.get("kind", "bin")
    if kind not in {"bin", "lib"}:
        fail("E_PACKAGE_SCHEMA", "Package kind must be bin or lib", manifest)
    source_value = meta.get("source_root", "src")
    entry_value = meta.get("entry", f"{source_value}/{'main' if kind == 'bin' else 'lib'}.hepta")
    if not isinstance(source_value, str) or not isinstance(entry_value, str):
        fail("E_PACKAGE_SCHEMA", "entry and source_root must be paths", manifest)
    source_root = _inside((root / source_value).resolve(), root, "source_root escapes its package")
    entry = _inside((root / entry_value).resolve(), source_root, "entry escapes source_root")
    if entry.suffix != ".hepta" or not entry.is_file():
        fail("E_PACKAGE_ENTRY", "Package entry must be an existing .hepta file", entry)
    package = Package(root, name, version, entry, kind, source_root, manifest_bytes=data)
    deps = config.get("dependencies", {})
    if not isinstance(deps, dict):
        fail("E_PACKAGE_SCHEMA", "dependencies must be a table", manifest)
    for alias, spec in sorted(deps.items()):
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", alias):
            fail("E_PACKAGE_NAME", "Dependency aliases must be ASCII identifiers", manifest)
        if not isinstance(spec, dict) or set(spec) != {"path"} or not isinstance(spec["path"], str):
            fail("E_PACKAGE_DEPENDENCY", "Dependencies require exactly { path = \"...\" }; network/registry resolution is not implemented", manifest)
        dep_root = (root / spec["path"]).resolve()
        dep = load_package(dep_root, stack + [root], cache, context=context)
        if dep.kind != "lib":
            fail("E_PACKAGE_DEPENDENCY", "Dependencies must declare kind = \"lib\"", dep_root)
        package.dependencies[alias] = dep
    cache[root] = package
    return package


def find_manifest(source: Path, *, context) -> Path | None:
    source = source.resolve()
    for parent in [source.parent, *source.parent.parents]:
        context.charge('path_checks')
        if (parent / "hepta.toml").is_file():
            return parent
    return None


def package_snapshot(package: Package, *, context) -> dict:
    files = {}
    nodes = {}
    seen = set()

    def visit(p, depth=1):
        context.depth(depth, context.limits.package_depth)
        if p.root in seen:
            return
        seen.add(p.root)
        rel = Path(os.path.relpath(p.root, package.root)).as_posix()
        nodes[rel] = {"name": p.name, "version": p.version, "kind": p.kind,
                      "entry": p.entry.relative_to(p.root).as_posix(),
                      "dependencies": {a: Path(os.path.relpath(d.root, package.root)).as_posix() for a, d in sorted(p.dependencies.items())}}
        manifest = p.root / "hepta.toml"
        files[Path(os.path.relpath(manifest, package.root)).as_posix()] = context.digest(manifest, 'manifest')
        # Path.rglob does not descend into directory symlinks. Module imports
        # do follow them, so an alias could otherwise retarget an import between
        # already-hashed directories without changing a v1 content lock.
        # Refuse this unrepresented topology instead of issuing a partial lock.
        source_files = []
        for candidate in sorted(context.inventory(p.source_root)):
            if candidate.is_symlink() and candidate.is_dir():
                _inside(candidate.resolve(), p.source_root, "Source directory symlink escapes its source_root")
                fail("E_PACKAGE_SOURCE_LINK", "Source directory symlinks are not supported by package locks; use a real directory", candidate)
            if candidate.name.endswith(".hepta"):
                source_files.append(candidate)
        for f in source_files:
            _inside(f.resolve(), p.root, "Source symlink escapes its package")
            if f.is_file():
                files[Path(os.path.relpath(f, package.root)).as_posix()] = context.digest(f, 'source')
                sidecar = f.with_suffix(f.suffix + ".imports.json")
                if sidecar.is_file():
                    _inside(sidecar.resolve(), p.root, "C import metadata symlink escapes its package")
                    files[Path(os.path.relpath(sidecar, package.root)).as_posix()] = context.digest(sidecar, 'sidecar')
        for d in p.dependencies.values():
            visit(d, depth + 1)
    visit(package)
    content = {"packages": nodes, "files": files}
    return {"schema": "hepta.lock.v1", **content,
            "sha256": digest(json.dumps(content, sort_keys=True, separators=(",", ":")).encode())}


def verify_lock(package: Package, *, context) -> dict:
    file = package.root / "Hepta.lock"
    if not file.is_file():
        fail("E_LOCK_MISSING", "Run hepta lock to create Hepta.lock before --locked validation", file)
    try:
        actual = context.json(context.read(file, 'lock'), file)
    except (ValueError, UnicodeError) as e:
        fail("E_LOCK_INVALID", str(e), file)
    expected = package_snapshot(package, context=context)
    if actual != expected:
        fail("E_LOCK_STALE", "Manifest, dependency graph, or source bytes differ from Hepta.lock", file)
    return actual

