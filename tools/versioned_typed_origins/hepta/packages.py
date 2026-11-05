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
    root = Path(root).resolve()
    stack = [] if _stack is None else _stack
    cache = {} if _cache is None else _cache
    manifest = root / "hepta.toml"
    if root in stack:
        fail("E_PACKAGE_CYCLE", "Dependency cycle: " + " -> ".join(str(p) for p in stack + [root]), manifest)
    if root in cache:
        return cache[root]
    if not manifest.is_file():
        fail("E_PACKAGE_MANIFEST", "Expected a hepta.toml manifest", manifest)
    data = manifest.read_bytes()
    try:
        config = tomllib.loads(data.decode("utf-8"))
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
        dep = load_package(dep_root, stack + [root], cache)
        if dep.kind != "lib":
            fail("E_PACKAGE_DEPENDENCY", "Dependencies must declare kind = \"lib\"", dep_root)
        package.dependencies[alias] = dep
    cache[root] = package
    return package


def find_manifest(source: Path) -> Path | None:
    source = source.resolve()
    for parent in [source.parent, *source.parent.parents]:
        if (parent / "hepta.toml").is_file():
            return parent
    return None


def package_snapshot(package: Package) -> dict:
    files = {}
    nodes = {}
    seen = set()

    def visit(p):
        if p.root in seen:
            return
        seen.add(p.root)
        rel = Path(os.path.relpath(p.root, package.root)).as_posix()
        nodes[rel] = {"name": p.name, "version": p.version, "kind": p.kind,
                      "entry": p.entry.relative_to(p.root).as_posix(),
                      "dependencies": {a: Path(os.path.relpath(d.root, package.root)).as_posix() for a, d in sorted(p.dependencies.items())}}
        manifest = p.root / "hepta.toml"
        files[Path(os.path.relpath(manifest, package.root)).as_posix()] = digest(manifest.read_bytes())
        for f in sorted(p.source_root.rglob("*.hepta")):
            _inside(f.resolve(), p.root, "Source symlink escapes its package")
            if f.is_file():
                files[Path(os.path.relpath(f, package.root)).as_posix()] = digest(f.read_bytes())
                sidecar = f.with_suffix(f.suffix + ".imports.json")
                if sidecar.is_file():
                    _inside(sidecar.resolve(), p.root, "C import metadata symlink escapes its package")
                    files[Path(os.path.relpath(sidecar, package.root)).as_posix()] = digest(sidecar.read_bytes())
        for d in p.dependencies.values():
            visit(d)
    visit(package)
    content = {"packages": nodes, "files": files}
    return {"schema": "hepta.lock.v1", **content,
            "sha256": digest(json.dumps(content, sort_keys=True, separators=(",", ":")).encode())}


def verify_lock(package: Package) -> dict:
    file = package.root / "Hepta.lock"
    if not file.is_file():
        fail("E_LOCK_MISSING", "Run hepta lock to create Hepta.lock before --locked validation", file)
    try:
        actual = json.loads(file.read_bytes())
    except (ValueError, UnicodeError) as e:
        fail("E_LOCK_INVALID", str(e), file)
    expected = package_snapshot(package)
    if actual != expected:
        fail("E_LOCK_STALE", "Manifest, dependency graph, or source bytes differ from Hepta.lock", file)
    return actual


def write_lock(root) -> dict:
    package = load_package(root)
    snapshot = package_snapshot(package)
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
        if package_snapshot(load_package(package.root)) != snapshot:
            fail("E_LOCK_RACE", "Package changed while locking; retry on a stable tree", path)
        os.replace(staged, path)
        staged = None
    finally:
        if staged is not None:
            staged.unlink(missing_ok=True)
    return {"schema": "hepta.package-lock.v1", "ok": True, "path": str(path), "snapshot": snapshot}
