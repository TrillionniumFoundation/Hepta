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


_ADMITTED = frozenset({"standalone-hia", "agent-assembly", "hepta-source", "legacy-executable",
                       "legacy-scalar", "legacy-composite-v2"})
_CPP_ROUTES = frozenset({"cpp-project", "cpp-matrix", "cpp-composed-project", "cpp-composed-matrix",
                         "cpp-unique-project", "cpp-unique-matrix",
                         "cpp-unique-assignment-project", "cpp-unique-assignment-matrix"})


def route_inventory():
    """Detached, versioned route metadata, including explicit nonroutes."""
    versions = schema_registry()
    latest = versions["latest_core_schema"].rsplit(".", 1)[-1]
    inputs = [
        {"route": "standalone-hia", "input": "primitive v1-" + latest + " / composite v1-v4",
         "adapter": "hepta.hia_program.verify_program", "admission": "supported",
         "origin_required": False},
        {"route": "agent-assembly", "input": "hia-asm.v1 explicit primitive v6/v7/v8",
         "adapter": "hepta.hia_agent_assembly.assemble_program", "admission": "supported",
         "origin_required": False, "implicit_schema_guessing": False,
         "scope": "bounded typed syntax for the same checked Core; no second evaluator"},
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
                       "scope": ("captured default-deleter std::unique_ptr<byte[]> with guarded leaf and fieldwise composite move assignment"
                                 if route.startswith("cpp-unique-assignment-") else
                                 "captured default-deleter std::unique_ptr<byte[]> wrapper with complete library census"
                                 if route.startswith("cpp-unique-") else
                                 "finite leaf owner or composed by-value owner profile")})
    sources = [
        {"language": "Hepta", "path": "hepta-source -> standalone-hia", "scope": "finite checked source profile"},
        {"language": "HIA assembly", "path": "agent-assembly -> standalone-hia",
         "scope": "explicit primitive v6/v7/v8 typed assembly; machine assembly input remains unsupported"},
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
         "scope": "x86-64 Linux shared/object; AArch64/RV64 objects through v8 require separate execution qualification; finite v8 execution has QEMU qualification, not physical-device qualification"},
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
        {"route": "modular-narrowing", "entry": "hepta.hia_narrowing.verify_modular_narrowing",
         "scope": "exact unsigned truncation edits with independent scalar/effect/first-trap equivalence"},
        {"route": "guarded-narrowing", "entry": "hepta.hia_narrowing.verify_guarded_narrowing",
         "scope": "shared proof budget and exact original/intermediate/final Core chain; final artifact binding"},
    ]
    result = {"schema": "hepta.hia.routes.v1", "inputs": inputs, "source_languages": sources,
              "historical_ir": historical, "backends": backends, "versions": versions,
              "optimization_profiles": [
                  {"command": "verify-translation", "checker": "hepta.hia_translation_validation.validate_translation",
                   "scope": "primitive v1-v7; selected public scalar function; full acyclic values and first traps",
                   "success": "proved", "other_outcomes": ["disproved", "unknown"],
                   "resource_or_call_rewrites": False, "receipt_grants_admission": False},
                  {"command": "verify-optimization", "checker": "hepta.hia_optimization.verify_optimization",
                   "scope": "primitive v1-v7; whole module; unchanged CFG, interfaces and ordered resource/call skeleton",
                   "success": "verified", "other_outcomes": ["rejected", "unknown", "timeout"],
                   "resource_or_call_rewrites": False, "receipt_grants_admission": False},
                  {"command": "fold-constants", "proposal": "whole-module constant folding",
                   "verification_command": "verify-optimization", "native_ndu": False,
                   "publication": "checked Core only; explicit output path"},
                  {"command": "optimize", "proposal": "finite selected-function recipes",
                   "verification_command": "verify-translation", "native_ndu": True,
                   "publication": "decision and selected Core; no native publication"},
                  {"command": "build-optimized", "verification_command": "verify-optimization",
                   "publication": "fresh checked native artifact bound to actual source and target"},
                  {"command": "verify-guarded", "checker": "hepta.hia_guarded_optimization.verify_guarded_optimization",
                   "scope": "inductively proved guarded reduction and complete original fallback",
                   "success": "verified", "other_outcomes": ["rejected", "unknown", "timeout"],
                   "resource_or_call_rewrites": False, "receipt_grants_admission": False},
                  {"command": "optimize-guarded", "proposal": "bounded counted-byte reduction with explicit guard",
                   "verification_command": "verify-guarded", "native_ndu": False,
                   "publication": "checked proposal only; explicit output path"},
                  {"command": "build-guarded", "verification_command": "verify-guarded",
                   "publication": "fresh guarded native artifact with complete original fallback"},
              ],
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
    if route.startswith("cpp-unique-assignment-"):
        from .cpp_unique_project import lower_unique_assignment_project, lower_unique_assignment_matrix
        lower = lower_unique_assignment_matrix if matrix else lower_unique_assignment_project
    elif route.startswith("cpp-unique-"):
        from .cpp_unique_project import lower_unique_project, lower_unique_matrix
        lower = lower_unique_matrix if matrix else lower_unique_project
    elif route.startswith("cpp-composed-"):
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
                core_schema=None, clangxx=None, variant=None):
    """Perform the named import and reverify the resulting actual operations."""
    if route in _CPP_ROUTES:
        if any(value is not None for value in (source, path, project_sha256, module, core_schema)):
            raise RouteRejected("E_HIA_ROUTE_CONTEXT: capture accepts no origin or Core schema override")
        return admit_captured_cpp(route, payload, clangxx=clangxx or "clang++", variant=variant)[0]
    if route not in _ADMITTED:
        raise RouteRejected("E_HIA_ROUTE_UNSUPPORTED: no executable adapter for " + str(route))
    if core_schema is not None and route != "hepta-source":
        raise RouteRejected("E_HIA_ROUTE_CONTEXT: a source Core schema cannot override submitted or historical bytes")
    if clangxx is not None or variant is not None:
        raise RouteRejected("E_HIA_ROUTE_CONTEXT: capture options require a captured C++ route")
    if route in {"standalone-hia", "agent-assembly"}:
        if any(value is not None for value in (source, path, project_sha256, module)):
            raise RouteRejected("E_HIA_ROUTE_CONTEXT: standalone bytes accept no source override")
        if route == "agent-assembly":
            from .hia_agent_assembly import assemble_program
            program = assemble_program(payload)
        else:
            program = verify_program(payload)
    elif route == "hepta-source":
        if source is not None or project_sha256 is not None:
            raise RouteRejected("E_HIA_ROUTE_CONTEXT: source text must be the payload")
        from .hia_program_source import lower_source
        text = payload.decode("utf-8") if isinstance(payload, bytes) else payload
        options = {} if core_schema is None else {"core_schema": core_schema}
        program = lower_source(text, path=path or "<hia-route-source>", module=module, **options)
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
