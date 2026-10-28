"""Explicit input and backend routes into the one standalone HIA authority.

The inventory describes boundaries; it is not a safety or refinement receipt.
Only admit_route executes an adapter, and every supported adapter ends in the
same verify_program. Unsupported languages/IR/backend combinations fail closed.
"""
from __future__ import annotations

from hashlib import sha256
import json

from .hia_program import verify_program
from .hia_schema import schema_registry


class RouteRejected(ValueError):
    pass


_ADMITTED = frozenset({"standalone-hia", "hepta-source", "legacy-executable",
                       "legacy-scalar", "legacy-composite-v2"})
_CPP_ROUTES = frozenset({"cpp-project", "cpp-matrix", "cpp-composed-project", "cpp-composed-matrix"})


def route_inventory():
    """Detached, versioned route metadata, including explicit nonroutes."""
    inputs = [
        {"route": "standalone-hia", "input": "primitive v1-v7 / composite v1-v2",
         "adapter": "hepta.hia_program.verify_program", "admission": "supported",
         "origin_required": False},
        {"route": "hepta-source", "input": "checked finite Hepta source profile",
         "adapter": "hepta.hia_program_source.lower_source", "admission": "supported",
         "origin_required": True},
        {"route": "legacy-executable", "input": "hepta.executable-core.v1",
         "adapter": "hepta.core.from_executable_core", "admission": "supported",
         "origin_required": True},
        {"route": "legacy-scalar", "input": "hepta.hia.scalar-core.v0",
         "adapter": "hepta.core.from_scalar_core", "admission": "supported",
         "origin_required": True},
        {"route": "legacy-composite-v2", "input": "historical nominal v2 spelling",
         "adapter": "hepta.hia_core_upgrade.import_legacy_composite_v2",
         "admission": "supported", "origin_required": False,
         "implicit_schema_guessing": False},
    ]
    for route in sorted(_CPP_ROUTES):
        inputs.append({"route": route, "input": "captured C++ compilation database" +
                       (" matrix" if route.endswith("matrix") else ""),
                       "adapter": "hepta.hia_routes.admit_captured_cpp", "admission": "supported",
                       "origin_required": True, "all_declared_configurations_verified": True,
                       "scope": "finite leaf owner or composed by-value owner profile"})
    sources = [
        {"language": "Hepta", "path": "hepta-source -> standalone-hia", "scope": "finite checked source profile"},
        {"language": "C", "path": "migrate-c / migrate-c-project -> Hepta -> hepta-source",
         "scope": "each complete captured profile must pass standalone admission; general C pointers are not admitted"},
        {"language": "C++", "path": "migrate-cpp[-class|-owned|-composed] -> Hepta -> hepta-source",
         "scope": "representable subset only; native legacy success does not imply standalone admission"},
        {"language": "C++ compilation database", "path": "hia import-cpp-[composed-]project / import-cpp-[composed-]matrix -> standalone-hia",
         "scope": "captured concrete bodies, finite configuration inventory and checked by-value owner transfer across translation units"},
    ]
    for language in ("Rust", "TypeScript", "Python", "Go", "assembly"):
        sources.append({"language": language, "path": None, "scope": "no source frontend; reject as HIA input"})
    historical = [
        {"input": "hepta.hsir.v0 / hepta.hsir.scalar.v1 / hepta.cfg.v0 / hepta.ssa.scalar.v0",
         "path": "only inside authenticated legacy-scalar import", "independent_execution": False},
        {"input": "HMIR export", "path": None, "independent_execution": False,
         "reason": "structural export, not a standalone executable authority"},
        {"input": "hepta.resource-ir.v1-v5", "path": "source resource-check side condition",
         "independent_execution": False, "reason": "resource descriptions do not execute values or memory"},
        {"input": "hepta.concurrent-ir.v1", "path": None, "independent_execution": False,
         "reason": "protocol checker is not a general threaded runtime"},
    ]
    backends = [
        {"backend": "interpreter", "entry": "hepta.core.execute_core", "same_standalone_core": True,
         "scope": "reverified values, traps, effects and resource CFG; evaluator budgets separate"},
        {"backend": "direct-llvm", "entry": "hepta.core.build_core", "same_standalone_core": True,
         "scope": "x86-64 Linux shared/object; AArch64/RV64 objects require separate execution qualification"},
        {"backend": "rust-shadow", "entry": "hepta.hia_rust_crosscheck.crosscheck_rust_shadow",
         "same_standalone_core": "finite profile only", "scope": "independent comparison, never deployment authority"},
        {"backend": "legacy-rust", "entry": "hepta.backend", "same_standalone_core": False,
         "scope": "checked source backend and reference; not silently selected by HIA"},
        {"backend": "legacy-c", "entry": "hepta.c_backend", "same_standalone_core": False,
         "scope": "checked source backend and reference; not silently selected by HIA"},
        {"backend": "legacy-direct-owned-llvm", "entry": "hepta.llvm_owned_backend",
         "same_standalone_core": False,
         "scope": "source/Resource IR profile; must explicitly lower to HIA to use standalone authority"},
    ]
    optimizations = [
        {"route": "scalar-equivalence", "entry": "hepta.hia_optimization.verify_optimization",
         "scope": "equal control/resource skeleton and exact scalar first-trap equivalence"},
        {"route": "guarded-reduction", "entry": "hepta.hia_guarded_optimization.verify_guarded_optimization",
         "scope": "proved runtime guard, inductive entry/edge/check obligations and complete original fallback"},
    ]
    result = {"schema": "hepta.hia.routes.v1", "inputs": inputs, "source_languages": sources,
              "historical_ir": historical, "backends": backends, "versions": schema_registry(),
              "optimizations": optimizations,
              "authority": "hepta.hia_program.verify_program",
              "claims": {"implicit_fallback_allowed": False, "all_source_languages_implemented": False,
                         "source_to_core_refinement_proved": False, "backend_refinement_proved": False,
                         "metadata_grants_admission": False}}
    result["inventory_sha256"] = sha256(json.dumps(result, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return result


def admit_captured_cpp(route, payload, *, clangxx="clang++", variant=None):
    """Capture implementations, then verify every Core before selecting one.

    The declaration ledger is provenance, never permission to execute. A bad
    unselected matrix variant rejects the entire capture as well.
    """
    if route not in _CPP_ROUTES:
        raise RouteRejected("E_HIA_ROUTE_UNSUPPORTED: no captured C++ adapter for " + str(route))
    matrix = route.endswith("matrix")
    if (matrix and type(variant) is not str) or (not matrix and variant is not None):
        raise RouteRejected("E_HIA_ROUTE_VARIANT: exactly one declared matrix variant is required")
    if route.startswith("cpp-composed-"):
        from .cpp_composed_project import lower_composed_project, lower_composed_matrix
        lower = lower_composed_matrix if matrix else lower_composed_project
    else:
        from .cpp_project_migrate import lower_cpp_project, lower_cpp_project_matrix
        lower = lower_cpp_project_matrix if matrix else lower_cpp_project
    migrated = lower(payload, clangxx=clangxx)
    if matrix:
        programs = {}
        for row in migrated["variants"]:
            name = row["name"]
            if name in programs:
                raise RouteRejected("E_HIA_ROUTE_VARIANT: duplicate captured variant")
            programs[name] = verify_program(row.pop("program"))
            row["program_sha256"] = programs[name].sha256
        if variant not in programs:
            raise RouteRejected("E_HIA_ROUTE_VARIANT: requested variant is not declared")
        program = programs[variant]
    else:
        program = verify_program(migrated.pop("program"))
        migrated.update(schema="hepta.hia." + route + "-import.v1",
                        program_sha256=program.sha256)
    migrated.update(route=route, native_executed=False, admission_authority="hepta.hia_program.verify_program")
    return verify_program(program), migrated


def admit_route(route, payload, *, source=None, path=None, project_sha256=None, module=None,
                clangxx=None, variant=None):
    """Perform the named import and reverify the resulting actual operations."""
    if route in _CPP_ROUTES:
        if any(value is not None for value in (source, path, project_sha256, module)):
            raise RouteRejected("E_HIA_ROUTE_CONTEXT: capture accepts no origin override")
        return admit_captured_cpp(route, payload, clangxx=clangxx or "clang++", variant=variant)[0]
    if route not in _ADMITTED:
        raise RouteRejected("E_HIA_ROUTE_UNSUPPORTED: no executable adapter for " + str(route))
    if clangxx is not None or variant is not None:
        raise RouteRejected("E_HIA_ROUTE_CONTEXT: capture options require a captured C++ route")
    if route == "standalone-hia":
        if any(value is not None for value in (source, path, project_sha256, module)):
            raise RouteRejected("E_HIA_ROUTE_CONTEXT: standalone bytes accept no source override")
        program = verify_program(payload)
    elif route == "hepta-source":
        if source is not None or project_sha256 is not None:
            raise RouteRejected("E_HIA_ROUTE_CONTEXT: source text must be the payload")
        from .hia_program_source import lower_source
        text = payload.decode("utf-8") if isinstance(payload, bytes) else payload
        program = lower_source(text, path=path or "<hia-route-source>", module=module)
    elif route == "legacy-composite-v2":
        if any(value is not None for value in (source, path, project_sha256, module)):
            raise RouteRejected("E_HIA_ROUTE_CONTEXT: nominal adapter accepts only its explicit document")
        from .hia_core_upgrade import import_legacy_composite_v2
        program, _ = import_legacy_composite_v2(payload)
    else:
        if type(source) is not str:
            raise RouteRejected("E_HIA_ROUTE_ORIGIN: historical import requires actual origin source")
        from .core import from_executable_core, from_scalar_core
        if route == "legacy-executable":
            from .hia_program_tools import decode_json
            document = decode_json(payload) if isinstance(payload, (bytes, str)) else payload
            program = from_executable_core(document, source=source, path=path,
                                           project_sha256=project_sha256, module=module)
        else:
            from .hia_core import HIAScalarCore
            from .checker import check
            from .parser import parse
            if type(project_sha256) is not str:
                raise RouteRejected("E_HIA_ROUTE_ORIGIN: old scalar core requires its project digest")
            original = parse(source, path or "<hia-route-origin>")
            if isinstance(payload, HIAScalarCore):
                snapshot = payload
            else:
                raw = payload.encode("utf-8") if isinstance(payload, str) else payload
                if type(raw) is not bytes or len(raw) > 4 * 1024 * 1024:
                    raise RouteRejected("E_HIA_ROUTE_ORIGIN: bounded original scalar snapshot bytes required")
                snapshot = HIAScalarCore(raw.decode("utf-8"), sha256(raw).hexdigest())
            program = from_scalar_core(snapshot, program=original, checked=check(original),
                                       project_sha256=project_sha256, module=module)
    return verify_program(program)


def execute_route(route, payload, function, arguments, *, context=None, backend="interpreter", **limits):
    if backend != "interpreter":
        raise RouteRejected("E_HIA_ROUTE_BACKEND: no implicit source backend or native fallback")
    from .core import execute_core
    admitted = admit_route(route, payload, **(context or {}))
    return execute_core(admitted, function, arguments, **limits)
