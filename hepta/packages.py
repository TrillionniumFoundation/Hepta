"""Local, content-locked packages. Manifests never execute build scripts."""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
import tomllib

from .ast import Diagnostic, HeptaError, Span
from ._loader_ops import LegacyLoaderOps as _LegacyLoaderOps, dispatch as _dispatch


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


def load_package(root, _stack=None, _cache=None) -> Package:
    return _load_package(root, _stack, _cache, ops=_LegacyLoaderOps())


_LEGACY_LOAD_PACKAGE = load_package


def _load_package(root, _stack=None, _cache=None, *, ops) -> Package:
    ops.edge("package", 1 if _stack is None else len(_stack) + 1)
    root = ops.path(Path(root), 'resolve')
    stack = [] if _stack is None else _stack
    cache = {} if _cache is None else _cache
    manifest = root / "hepta.toml"
    if root in stack:
        fail("E_PACKAGE_CYCLE", "Dependency cycle: " + " -> ".join(str(p) for p in stack + [root]), manifest)
    if root in cache:
        return cache[root]
    ops.node("package")
    if not ops.path(manifest, 'is_file'):
        fail("E_PACKAGE_MANIFEST", "Expected a hepta.toml manifest", manifest)
    data = ops.read(manifest, 'manifest')
    try:
        config = ops.toml(tomllib.loads, data, manifest)
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
    source_root = _inside(ops.path(root / source_value, 'resolve'), root, "source_root escapes its package")
    entry = _inside(ops.path(root / entry_value, 'resolve'), source_root, "entry escapes source_root")
    if entry.suffix != ".hepta" or not ops.path(entry, 'is_file'):
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
        dep_root = ops.path(root / spec["path"], 'resolve')
        dep = _dispatch(load_package, _LEGACY_LOAD_PACKAGE, _load_package, ops, dep_root, stack + [root], cache)
        if dep.kind != "lib":
            fail("E_PACKAGE_DEPENDENCY", "Dependencies must declare kind = \"lib\"", dep_root)
        package.dependencies[alias] = dep
    cache[root] = package
    return package


def find_manifest(source: Path) -> Path | None:
    return _find_manifest(source, ops=_LegacyLoaderOps())


def _find_manifest(source: Path, *, ops) -> Path | None:
    source = ops.path(source, 'resolve')
    for parent in [source.parent, *source.parent.parents]:
        if ops.path(parent / "hepta.toml", 'is_file'):
            return parent
    return None


_LEGACY_FIND_MANIFEST = find_manifest


def package_snapshot(package: Package) -> dict:
    return _package_snapshot(package, ops=_LegacyLoaderOps())


_LEGACY_PACKAGE_SNAPSHOT = package_snapshot


def _package_snapshot(package: Package, *, ops) -> dict:
    files = {}
    nodes = {}
    seen = set()

    def visit(p, depth=1):
        ops.edge("package", depth)
        if p.root in seen:
            return
        ops.node("package")
        seen.add(p.root)
        rel = Path(os.path.relpath(p.root, package.root)).as_posix()
        nodes[rel] = {"name": p.name, "version": p.version, "kind": p.kind,
                      "entry": p.entry.relative_to(p.root).as_posix(),
                      "dependencies": {a: Path(os.path.relpath(d.root, package.root)).as_posix() for a, d in sorted(p.dependencies.items())}}
        manifest = p.root / "hepta.toml"
        files[Path(os.path.relpath(manifest, package.root)).as_posix()] = digest(ops.read(manifest, 'manifest'))
        # Path.rglob does not descend into directory symlinks. Module imports
        # do follow them, so an alias could otherwise retarget an import between
        # already-hashed directories without changing a v1 content lock.
        # Refuse this unrepresented topology instead of issuing a partial lock.
        source_files = []
        for candidate in sorted(ops.inventory(p.source_root)):
            if ops.path(candidate, 'is_symlink') and ops.path(candidate, 'is_dir'):
                _inside(ops.path(candidate, 'resolve'), p.source_root, "Source directory symlink escapes its source_root")
                fail("E_PACKAGE_SOURCE_LINK", "Source directory symlinks are not supported by package locks; use a real directory", candidate)
            if candidate.name.endswith(".hepta"):
                source_files.append(candidate)
        for f in source_files:
            _inside(ops.path(f, 'resolve'), p.root, "Source symlink escapes its package")
            if ops.path(f, 'is_file'):
                files[Path(os.path.relpath(f, package.root)).as_posix()] = digest(ops.read(f, 'source'))
                sidecar = f.with_suffix(f.suffix + ".imports.json")
                if ops.path(sidecar, 'is_file'):
                    _inside(ops.path(sidecar, 'resolve'), p.root, "C import metadata symlink escapes its package")
                    files[Path(os.path.relpath(sidecar, package.root)).as_posix()] = digest(ops.read(sidecar, 'sidecar'))
        for d in p.dependencies.values():
            visit(d, depth + 1)
    visit(package)
    content = {"packages": nodes, "files": files}
    return {"schema": "hepta.lock.v1", **content,
            "sha256": digest(json.dumps(content, sort_keys=True, separators=(",", ":")).encode())}


def verify_lock(package: Package) -> dict:
    return _verify_lock(package, ops=_LegacyLoaderOps())


_LEGACY_VERIFY_LOCK = verify_lock


def _verify_lock(package: Package, *, ops) -> dict:
    file = package.root / "Hepta.lock"
    if not ops.path(file, 'is_file'):
        fail("E_LOCK_MISSING", "Run hepta lock to create Hepta.lock before --locked validation", file)
    try:
        actual = ops.json(json.loads, ops.read(file, 'lock'), file)
    except (ValueError, UnicodeError) as e:
        fail("E_LOCK_INVALID", str(e), file)
    expected = _dispatch(package_snapshot, _LEGACY_PACKAGE_SNAPSHOT, _package_snapshot, ops, package)
    if actual != expected:
        fail("E_LOCK_STALE", "Manifest, dependency graph, or source bytes differ from Hepta.lock", file)
    return actual


def write_lock(root) -> dict:
    return _write_lock(root, ops=_LegacyLoaderOps())


def _write_lock(root, *, ops) -> dict:
    package = _dispatch(load_package, _LEGACY_LOAD_PACKAGE, _load_package, ops, root)
    snapshot = _dispatch(package_snapshot, _LEGACY_PACKAGE_SNAPSHOT, _package_snapshot, ops, package)
    path = package.root / "Hepta.lock"
    staged = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", dir=package.root, prefix=".hepta-lock-", delete=False) as f:
            staged = Path(f.name)
            json.dump(snapshot, f, indent=2, sort_keys=True)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        # Re-read manifests as well: stale dependency topology is not a valid lock.
        if _dispatch(package_snapshot, _LEGACY_PACKAGE_SNAPSHOT, _package_snapshot, ops,
                     _dispatch(load_package, _LEGACY_LOAD_PACKAGE, _load_package, ops, package.root)) != snapshot:
            fail("E_LOCK_RACE", "Package changed while locking; retry on a stable tree", path)
        os.replace(staged, path)
        staged = None
    finally:
        if staged is not None:
            staged.unlink(missing_ok=True)
    return {"schema": "hepta.package-lock.v1", "ok": True, "path": str(path), "snapshot": snapshot}
