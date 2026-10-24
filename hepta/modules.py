"""Explicit module graphs, privacy, and deterministic AST name resolution."""
from __future__ import annotations

from dataclasses import dataclass, fields, is_dataclass
import copy
import json
import os
from pathlib import Path
import re
import platform
import struct

from .ast import Diagnostic, Expr, Function, HeptaError, Program, Span, Type
from .parser import parse
from .lexer import tokenize
from .packages import Package, digest, find_manifest, load_package, package_snapshot, verify_lock


def fail(code, message, span):
    raise HeptaError(Diagnostic(code, message, span, phase="module"))


@dataclass
class Unit:
    path: Path
    program: Program
    package: Package
    imports: dict[str, "Unit"]
    functions: dict
    types: dict
    names: dict[str, str]


@dataclass
class LoadedProject:
    program: Program
    entry: Path
    sources: dict[str, str]
    source_bytes: dict[str, bytes]
    identity: str
    modules: list[dict]
    package: Package | None
    package_state: dict | None
    locked: bool
    bindings: dict[str, str]
    c_imports: list[dict]

    def unchanged(self, *, except_paths=()) -> bool:
        omitted = {str(Path(p).resolve()) for p in except_paths}
        try:
            if any(str(Path(p).resolve()) != expected for p, expected in self.bindings.items()):
                return False
            if any(Path(p).read_bytes() != b for p, b in self.source_bytes.items() if p not in omitted):
                return False
            if self.package_state is not None:
                return package_snapshot(load_package(self.package.root)) == self.package_state
            return True
        except (OSError, HeptaError):
            return False

    def report(self):
        return {"schema": "hepta.module-graph.v1", "sha256": self.identity,
                "entry": str(self.entry), "sources": self.sources,
                "modules": self.modules, "locked": self.locked,
                "path_bindings": self.bindings,
                "c_imports": self.c_imports,
                "package": {"name": self.package.name, "version": self.package.version,
                            "root": str(self.package.root)} if self.package else None}


def load_project(entry, *, locked=False, source_overrides=None) -> LoadedProject:
    requested_path = Path(entry).absolute()
    entry = Path(entry).resolve()
    bindings = {str(requested_path): str(entry)}
    package = None
    if entry.is_dir():
        package = load_package(entry)
        entry = package.entry
    elif entry.name == "hepta.toml":
        package = load_package(entry.parent)
        entry = package.entry
    else:
        root = find_manifest(entry)
        if root is not None:
            package = load_package(root)
            if not entry.is_relative_to(package.source_root):
                fail("E_MODULE_ROOT", "Source lies outside the package source_root", Span(path=str(entry)))
    if locked and package is None:
        fail("E_LOCK_CONTEXT", "--locked requires a package manifest", Span(path=str(entry)))
    state = verify_lock(package) if locked else (package_snapshot(package) if package else None)
    owner = package or Package(entry.parent, "standalone", "0.0.0", entry, "bin", entry.parent)
    overrides = {str(Path(k).resolve()): v.encode("utf-8") for k, v in (source_overrides or {}).items()}
    units: dict[Path, Unit] = {}
    stack = []
    sources = {}
    source_bytes = {}
    c_imports = []

    def visit(path: Path, pkg: Package, span: Span):
        lexical_path = path.absolute()
        path = path.resolve()
        bindings[str(lexical_path)] = str(path)
        if not path.is_relative_to(pkg.source_root) or path.suffix != ".hepta":
            fail("E_MODULE_ESCAPE", "Module path escapes its declared source_root", span)
        if path in stack:
            fail("E_MODULE_CYCLE", "Import cycle: " + " -> ".join(str(p) for p in stack + [path]), span)
        if path in units:
            return units[path]
        try:
            data = overrides.get(str(path))
            if data is None:
                data = path.read_bytes()
            text = data.decode("utf-8")
        except (OSError, UnicodeError) as e:
            fail("E_MODULE_READ", str(e), span)
        if text.startswith("// hepta:c-import:v1\n"):
            sidecar = path.with_suffix(path.suffix + ".imports.json")
            try:
                metadata_bytes = sidecar.read_bytes()
                metadata = json.loads(metadata_bytes)
            except (OSError, ValueError) as e:
                fail("E_C_IMPORT_MANIFEST", "Imported C bindings require their generated sidecar: " + str(e), span)
            if not isinstance(metadata, dict) or metadata.get("schema") != "hepta.c-import.v1" or metadata.get("source_sha256") != digest(data):
                fail("E_C_IMPORT_IDENTITY", "C binding source differs from its probe metadata", span)
            relative_header = metadata.get("header_path_kind") == "relative_to_manifest"
            if (not all(isinstance(metadata.get(k), str) for k in ("header", "header_sha256", "target"))
                    or metadata.get("header_path_kind") not in {None, "relative_to_manifest"}
                    or Path(metadata["header"]).is_absolute() == relative_header):
                fail("E_C_IMPORT_MANIFEST", "C import metadata has invalid header/target identity fields", span)
            host = {"system": platform.system(), "machine": platform.machine(), "pointer_bits": struct.calcsize("P") * 8}
            if metadata.get("host") != host:
                fail("E_C_IMPORT_TARGET", "Imported C facts must be re-probed on this host", span)
            sources[str(sidecar)] = digest(metadata_bytes)
            source_bytes[str(sidecar)] = metadata_bytes
            bindings[str(sidecar)] = str(sidecar.resolve())
            original_header = Path(metadata.get("header", ""))
            if relative_header:
                original_header = (sidecar.parent / original_header).resolve()
                if not original_header.is_relative_to(pkg.root) or not original_header.is_file():
                    fail("E_C_IMPORT_MANIFEST", "Portable C header must exist inside its package", span)
            if original_header.resolve().is_relative_to(pkg.root) and original_header.is_file():
                original_data = original_header.read_bytes()
                if digest(original_data) != metadata.get("header_sha256"):
                    fail("E_C_IMPORT_IDENTITY", "Original C header changed since probing", span)
                sources[str(original_header)] = digest(original_data)
                source_bytes[str(original_header)] = original_data
                bindings[str(original_header)] = str(original_header.resolve())
            c_imports.append({"source": str(path), "manifest": str(sidecar), "target": metadata.get("target"), "host": host})
        for token in tokenize(text, str(path)):
            if token.kind == "IDENT" and re.match(r"M[0-9a-f]{16}_", token.value):
                fail("E_MODULE_RESERVED", "Compiler module symbols cannot be spelled in source", token.span)
        program = parse(text, str(path))
        # An imported file may omit module, which defaults to main. Explicit
        # module names are informational; file identity owns namespace identity.
        types = {s.name: s for s in [*program.structs, *getattr(program, "enums", [])]}
        functions = {f.name: f for f in program.functions}
        declarations = [*program.structs, *getattr(program, "enums", []), *program.functions]
        if len(types) + len(functions) != len(declarations) or set(types) & set(functions):
            fail("E_MODULE_DUPLICATE", "Duplicate declaration name in module", span)
        relative = Path(os.path.relpath(path, owner.root)).as_posix()
        prefix = "M" + digest(relative.encode())[:16] + "_"
        names = {n: (n if path == entry else prefix + n) for n in types}
        names.update({n: (n if path == entry or f.extern_c or f.export_c else prefix + n) for n, f in functions.items()})
        unit = Unit(path, program, pkg, {}, functions, types, names)
        sources[str(path)] = digest(data)
        source_bytes[str(path)] = data
        stack.append(path)
        for imp in getattr(program, "imports", []):
            if imp.alias in unit.imports or imp.alias in types or imp.alias in functions:
                fail("E_MODULE_ALIAS", "Import alias collides with an existing name: " + imp.alias, imp.span)
            parts = imp.name.split("::")
            if parts[0] in pkg.dependencies:
                dep = pkg.dependencies[parts[0]]
                target = dep.entry if len(parts) == 1 else dep.source_root.joinpath(*parts[1:]).with_suffix(".hepta")
            else:
                dep = pkg
                target = pkg.source_root.joinpath(*parts).with_suffix(".hepta")
            unit.imports[imp.alias] = visit(target, dep, imp.span)
        stack.pop()
        units[path] = unit
        return unit

    main = visit(entry, owner, Span(path=str(entry)))
    assembled = copy.deepcopy(main.program)
    assembled.structs = []
    assembled.functions = []
    if hasattr(assembled, "enums"):
        assembled.enums = []
    if hasattr(assembled, "imports"):
        assembled.imports = []
    module_reports = []
    for unit in units.values():
        def resolve(name, role, span):
            if "::" not in name:
                declarations = unit.types if role == "type" else {**unit.types, **unit.functions}
                return unit.names.get(name, name) if name in declarations else name
            parts = name.split("::")
            if parts[0] in unit.imports:
                imported = unit.imports[parts[0]]
                declarations = imported.types if role == "type" or len(parts) > 2 else {**imported.types, **imported.functions}
                declaration = declarations.get(parts[1])
                if declaration is None:
                    fail("E_MODULE_SYMBOL", "Unknown imported symbol: " + name, span)
                if not (getattr(declaration, "public", False) or getattr(declaration, "extern_c", False) or getattr(declaration, "export_c", False)):
                    fail("E_MODULE_PRIVATE", "Imported symbol is private: " + name, span)
                return "::".join([imported.names[parts[1]], *parts[2:]])
            if parts[0] in unit.types:
                return "::".join([unit.names[parts[0]], *parts[1:]])
            if parts[0] == "Result":
                return name
            fail("E_MODULE_NAMESPACE", "Unknown namespace: " + parts[0], span)

        def transform(value, params=frozenset()):
            if isinstance(value, Type):
                name = value.name if value.name in params else resolve(value.name, "type", Span(path=str(unit.path)))
                return Type(name, tuple(transform(a, params) for a in value.args), value.length)
            if isinstance(value, Expr):
                if value.kind in {"name", "call"} and isinstance(value.value, str):
                    if value.kind == "call" or "::" in value.value or value.value in unit.functions:
                        value.value = resolve(value.value, "term", value.span)
                elif value.kind == "struct" and isinstance(value.value, dict):
                    value.value["name"] = resolve(value.value["name"], "type", value.span)
                for f in fields(value):
                    if f.name not in {"kind", "span"}:
                        setattr(value, f.name, transform(getattr(value, f.name), params))
                return value
            if isinstance(value, list):
                return [transform(v, params) for v in value]
            if isinstance(value, tuple):
                return tuple(transform(v, params) for v in value)
            if isinstance(value, dict):
                return {k: transform(v, params) for k, v in value.items()}
            if is_dataclass(value) and not isinstance(value, Span):
                if hasattr(value, "enum_name"):
                    value.enum_name = resolve(value.enum_name, "type", value.span)
                for f in fields(value):
                    if f.name not in {"span", "body_span", "name", "enum_name", "type_params"}:
                        setattr(value, f.name, transform(getattr(value, f.name), params))
                return value
            return value

        for attr in ("structs", "enums", "functions"):
            for original in getattr(unit.program, attr, []):
                declaration = copy.deepcopy(original)
                declaration.name = unit.names[original.name]
                transform(declaration, frozenset(getattr(original, "type_params", ())))
                getattr(assembled, attr).append(declaration)
        module_reports.append({"path": str(unit.path), "module": unit.program.name,
                               "imports": {a: str(u.path) for a, u in unit.imports.items()},
                               "symbols": unit.names})
    portable_sources = {Path(os.path.relpath(Path(p), owner.root)).as_posix(): h for p, h in sorted(sources.items())}
    import_edges = {Path(os.path.relpath(u.path, owner.root)).as_posix():
                    {alias: Path(os.path.relpath(imported.path, owner.root)).as_posix() for alias, imported in sorted(u.imports.items())}
                    for u in units.values()}
    identity = digest(json.dumps({"entry": Path(os.path.relpath(entry, owner.root)).as_posix(),
                                 "sources": portable_sources, "imports": import_edges, "package": state},
                                sort_keys=True, separators=(",", ":")).encode())
    result = LoadedProject(assembled, entry, sources, source_bytes, identity, module_reports, package, state, locked, bindings, c_imports)
    if not result.unchanged(except_paths=overrides):
        fail("E_MODULE_RACE", "Source graph changed while loading", Span(path=str(entry)))
    return result
