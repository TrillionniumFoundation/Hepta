"""One validation pipeline for human and agent entrypoints."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path

from . import __version__
from .ast import Diagnostic, HeptaError, Program, Span
from .backend import compile_rust, emit_rust, emit_header, sha256
from .parser import parse
from .checker import check
from .borrowed_storage import has_borrowed_storage


def interface(program: Program) -> dict:
    return {"module": program.name,
            "imports": [{"name": i.name, "alias": i.alias} for i in getattr(program, "imports", [])],
            "structs": [{"name": s.name, "repr_c": s.repr_c, "public": getattr(s, "public", False),
                         "type_params": list(getattr(s, "type_params", ())),
                         **({"lifetime_params": list(s.lifetime_params)} if s.lifetime_params else {}),
                         "fields": [{"name": f.name, "type": str(f.type)} for f in s.fields]}
                        for s in program.structs],
            "enums": [{"name": e.name, "public": e.public, "type_params": list(e.type_params),
                       "variants": [{"name": v.name, "fields": [str(t) for t in v.fields]} for v in e.variants]}
                      for e in getattr(program, "enums", [])],
            "functions": [{"name": f.name, "params": [{"name": p.name, "mode": p.mode, "type": str(p.type), **({"lifetime": p.lifetime} if p.lifetime is not None else {})} for p in f.params],
                           **({"lifetime_params": list(f.lifetime_params), "return_lifetime": f.return_lifetime} if f.lifetime_params else {}),
                           "type_params": list(getattr(f, "type_params", ())),
                           "type_bounds": {name: f.type_bounds.get(name, "Copy") for name in f.type_params},
                           "returns": str(f.return_type), "return_mode": getattr(f, "return_mode", "value"), "return_origin": f.return_origin,
                           "effects": sorted(f.effects),
                           "resources": f.resources, "public": f.public, "export_c": f.export_c,
                           "extern_c": f.extern_c} for f in program.functions]}


def interface_hash(program: Program) -> str:
    return sha256(json.dumps(interface(program), sort_keys=True, separators=(",", ":")).encode())


def compiler_hash() -> str:
    h = hashlib.sha256()
    for p in sorted(Path(__file__).parent.glob("*.py")):
        h.update(p.name.encode() + b"\0" + p.read_bytes() + b"\0")
    return h.hexdigest()


@dataclass
class Analysis:
    report: dict
    program: Program | None = None
    checked: object | None = None
    rust: str | None = None
    project: object | None = None
    c: str | None = None


def analyze(source: str, path: str = "<input>", *, rustc=None, target=None,
            no_std=False, native=True, crate_type="rlib", loaded_project=None,
            backend="rust", cc=None, c_optimization="default") -> Analysis:
    report = {"schema": "hepta.check.v1", "compiler_version": __version__,
              "compiler_sha256": compiler_hash(), "source_sha256": sha256(source.encode()),
              "path": path, "ok": False, "status": "rejected", "diagnostics": [],
              "checks": {"syntax": "not_run", "types_effects_resources": "not_run", "rust_borrows_types": "not_run"},
              "assumptions": [], "claims": {"whole_language_soundness_proved": False,
              "all_programs_faster_than_rust": False, "hardware_execution_verified": False,
              "bounded_cancellation_latency_proved": False, "deadlock_freedom_proved": False}}
    result = Analysis(report)
    try:
        program = loaded_project.program if loaded_project is not None else parse(source, path)
        if loaded_project is None and getattr(program, "imports", []):
            if path == "<input>":
                raise HeptaError(Diagnostic("E_IMPORT_UNRESOLVED", "Imports require a source file or package context", Span(path=path), phase="module"))
            from .modules import load_project
            loaded_project = load_project(path, source_overrides={path: source})
            program = loaded_project.program
        result.project = loaded_project
        if loaded_project is not None:
            report["project"] = loaded_project.report()
            if loaded_project.c_imports and target is not None:
                raise HeptaError(Diagnostic("E_C_IMPORT_TARGET", "C imports have native-host probe facts; cross-target reuse requires a target-specific import profile", Span(path=path), phase="module"))
        result.program = program
        if has_borrowed_storage(program):
            report["borrowed_storage"] = {"profile": "explicit-lifetime-records-v1", "native_lifetimes_required": True,
                                          "native_lifetimes_checked": False, "independent_resource_ir_supported": False,
                                          "c_backend_supported": False, "general_lifetime_system_complete": False}
        report["checks"]["syntax"] = "passed"
        report["interface_sha256"] = interface_hash(program)
        checked = check(program)
        result.checked = checked
        report["diagnostics"] += [d.to_dict() for d in checked.diagnostics]
        report["effects"] = {k: sorted(v) for k, v in checked.effects.items()}
        report["assumptions"] = checked.assumptions
        report["resource_contracts"] = checked.resource_contracts
        if not checked.ok:
            report["checks"]["types_effects_resources"] = "rejected"
            return result
        report["checks"]["types_effects_resources"] = "passed_in_supported_subset"
        if any(s.repr_c for s in program.structs) or any(f.extern_c or f.export_c for f in program.functions):
            emit_header(program)  # Reject unrepresentable C declaration dependencies.
        if backend not in {"rust", "c"}:
            raise HeptaError(Diagnostic("E_BACKEND", "Unknown compiler backend", Span(path=path), phase="backend"))
        if c_optimization not in {"default", "unroll"} or (backend != "c" and c_optimization != "default"):
            raise HeptaError(Diagnostic("E_C_OPTIMIZATION", "A named C optimization profile requires --backend c", Span(path=path), phase="backend"))
        if backend == "c":
            if target is not None or no_std:
                raise HeptaError(Diagnostic("E_C_PROFILE", "The C backend currently supports host compilation only", Span(path=path), phase="backend"))
            from .c_backend import emit_c, compile_c
            c_crate_type = "obj" if crate_type == "rlib" else crate_type
            generated = emit_c(program, checked, crate_type=c_crate_type)
            result.c = generated
            report["c_sha256"] = sha256(generated.encode())
        else:
            generated = emit_rust(program, checked, no_std, crate_type)
            result.rust = generated
            report["rust_sha256"] = sha256(generated.encode())
        report["profile"] = {"no_std": no_std, "crate_type": crate_type, "overflow_checks": True, "panic": "abort"}
        if backend == "c":
            report["profile"]["c_optimization"] = c_optimization
        if native:
            native_report = (compile_c(generated, cc=cc, crate_type=c_crate_type, check_only=True, optimization_profile=c_optimization) if backend == "c"
                             else compile_rust(generated, rustc=rustc, target=target, crate_type=crate_type, check_only=True))
            report["backend"] = native_report
            report["diagnostics"] += native_report["diagnostics"]
            report["checks"]["rust_borrows_types" if backend == "rust" else "c_types_codegen"] = native_report["status"]
            report["ok"] = native_report["ok"]
            if "borrowed_storage" in report:
                report["borrowed_storage"]["native_lifetimes_checked"] = backend == "rust" and native_report["ok"] is True
            report["status"] = "checked_with_external_assumptions" if native_report["ok"] and report["assumptions"] else ("checked" if native_report["ok"] else native_report["status"])
        else:
            report["ok"] = True
            report["status"] = "frontend_only"
        return result
    except HeptaError as e:
        report["diagnostics"].append(e.diagnostic.to_dict())
        return result


def analyze_project(path, *, locked=False, source_overrides=None, **options):
    from .modules import load_project
    project = load_project(path, locked=locked, source_overrides=source_overrides)
    source = project.source_bytes[str(project.entry)].decode("utf-8")
    result = analyze(source, str(project.entry), loaded_project=project, **options)
    # Overrides are candidate in-memory source, not an assertion that the disk
    # already contains the candidate. All other files must remain unchanged.
    if not project.unchanged(except_paths=(source_overrides or {}).keys()):
        result.report["ok"] = False
        result.report["status"] = "rejected"
        result.report["diagnostics"].append(Diagnostic("E_MODULE_RACE", "Source graph changed during validation", Span(path=str(project.entry)), phase="module").to_dict())
    return result


def inspect_analysis(analysis: Analysis) -> dict:
    out = dict(analysis.report)
    out["schema"] = "hepta.inspect.v1"
    if analysis.program:
        out["interface"] = interface(analysis.program)
        out["symbols"] = [{"name": f.name, "path": f.span.path, "start": f.span.start, "end": f.span.end,
                           "body_start": f.body_span.start, "body_end": f.body_span.end,
                           "calls": sorted(_calls(f.body or []))} for f in analysis.program.functions]
    return out


def _calls(body):
    from dataclasses import fields, is_dataclass
    from .ast import Expr, Stmt
    found = set()
    def visit(x):
        if isinstance(x, Expr):
            if x.kind == "call":
                found.add(x.value)
            for child in x.children:
                visit(child)
        elif isinstance(x, Stmt):
            visit(x.data)
        elif isinstance(x, dict):
            for value in x.values():
                visit(value)
        elif isinstance(x, (list, tuple)):
            for value in x:
                visit(value)
        elif is_dataclass(x):
            for field in fields(x):
                if field.name != "span":
                    visit(getattr(x, field.name))
    visit(body)
    return found


def hsir_analysis(analysis: Analysis) -> dict:
    """Export typed source-graph IR without mistaking it for native validation.

    A rejected frontend has no HSIR.  A frontend-only analysis can have an
    interchange graph, but must retain its incomplete qualification status.
    """
    if analysis.program is None or analysis.checked is None or not analysis.checked.ok:
        return {"schema": "hepta.hsir.export.v0", "ok": False,
                "status": "rejected", "validation": analysis.report, "hsir": None}
    from .semantic_ir import lower_checked_program
    try:
        snapshot = lower_checked_program(
            analysis.program, analysis.checked,
            project_sha256=getattr(analysis.project, "identity", None))
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        return {"schema": "hepta.hsir.export.v0", "ok": False,
                "status": "rejected", "hsir": None, "validation": analysis.report,
                "diagnostics": [{"code": "E_HSIR_LOWER", "phase": "semantic-ir",
                                 "message": str(exc)}]}
    return {"schema": "hepta.hsir.export.v0", "ok": bool(analysis.report["ok"]),
            "status": analysis.report["status"],
            "hsir": snapshot, "validation": analysis.report}



def hsir_v1_analysis(analysis: Analysis) -> dict:
    """Expose a versioned, lossless interface view without granting codegen.

    The old v0 CLI remains unchanged. Native validation and producer-specific
    FFI/ownership obligations are never inferred from a successful projection.
    """
    legacy = hsir_analysis(analysis)
    rejected = {"schema": "hepta.hsir.integration.export.v1", "ok": False,
                "status": "rejected", "hsir": None, "validation": analysis.report}
    if not legacy["ok"] or legacy["hsir"] is None:
        return rejected
    try:
        from .hsir_v1 import HSIRV1Rejected, integrate_v0, verify_v1
        project_id = getattr(analysis.project, "identity", None)
        # program.source is the checked aggregate source. For multi-file
        # imports it need not equal the entry file's standalone source hash.
        source_id = hashlib.sha256(analysis.program.source.encode("utf-8")).hexdigest()
        snapshot = integrate_v0(legacy["hsir"], expected_source_sha256=source_id,
                                expected_project_sha256=project_id)
        verify_v1(snapshot)
    except (HSIRV1Rejected, ValueError, TypeError, OverflowError, RecursionError) as exc:
        return {**rejected, "diagnostics": [
            {"code": "E_HSIR_V1_LOWER", "phase": "integration-hsir",
             "message": str(exc)}]}
    return {"schema": "hepta.hsir.integration.export.v1",
            "ok": True, "status": legacy["status"],
            "hsir": snapshot, "validation": analysis.report,
            "native_validity_not_established_by_hsir_v1": True}



def hsir_v1_resource_analysis(analysis: Analysis) -> dict:
    """Independently verify owners/loans against the checked project's v1 HSIR."""
    rejected = {"schema": "hepta.hsir-resource.export.v1", "ok": False,
                "status": "rejected", "binding": None, "validation": analysis.report}
    exported = hsir_v1_analysis(analysis)
    if not exported["ok"]:
        return rejected
    try:
        from .hsir_v1_resource import HSIRResourceRejected, checked_resource_snapshot
        binding = checked_resource_snapshot(analysis, exported["hsir"])
    except (HSIRResourceRejected, TypeError, ValueError, KeyError, OverflowError,
            RecursionError) as exc:
        return {**rejected, "diagnostics": [{"code": "E_HSIR_RESOURCE_LOWER",
                  "phase": "resource-ir", "message": str(exc)}]}
    return {"schema": "hepta.hsir-resource.export.v1",
            "ok": True, "status": exported["status"],
            "binding": binding, "validation": analysis.report,
            "native_validity_not_established_by_resource_binding": True}


def cfg_analysis(analysis: Analysis) -> dict:
    """Export checked structured control flow without upgrading proof claims."""
    if analysis.program is None or analysis.checked is None or not analysis.checked.ok:
        return {"schema": "hepta.cfg.export.v0", "ok": False,
                "status": "rejected", "validation": analysis.report, "cfg": None}
    from .flow_ir import FlowLowerError, lower_checked_cfg
    try:
        snapshot = lower_checked_cfg(
            analysis.program, analysis.checked,
            project_sha256=getattr(analysis.project, "identity", None))
    except (FlowLowerError, TypeError, ValueError, OverflowError, RecursionError) as exc:
        return {"schema": "hepta.cfg.export.v0", "ok": False,
                "status": "rejected", "cfg": None, "validation": analysis.report,
                "diagnostics": [{"code": "E_CFG_LOWER", "phase": "flow-ir",
                                 "message": str(exc)}]}
    return {"schema": "hepta.cfg.export.v0", "ok": bool(analysis.report["ok"]),
            "status": analysis.report["status"], "cfg": snapshot,
            "validation": analysis.report}


def resource_ir_analysis(analysis: Analysis) -> dict:
    """Export and independently validate the bounded resource abstraction."""
    report = {"schema": "hepta.resource-ir.export.v1", "ok": False,
              "status": "rejected", "resource_ir": None, "verifier": None,
              "validation": analysis.report}
    if analysis.program is None or analysis.checked is None or not analysis.checked.ok:
        return report
    from .resource_ir import ResourceIRError, verify_resource_ir
    from .resource_lowering import lower_resource_ir
    try:
        graph = lower_resource_ir(analysis.program, analysis.checked,
                                  project_sha256=getattr(analysis.project, "identity", None))
        # The verifier consumes data, not checker object identities.
        verification = verify_resource_ir(json.loads(json.dumps(graph)))
        report.update(resource_ir=graph, verifier=verification,
                      ok=bool(analysis.report["ok"] and verification["ok"]),
                      status=analysis.report["status"] if verification["ok"] else "rejected")
    except (ResourceIRError, ValueError, TypeError, OverflowError, RecursionError) as exc:
        report["diagnostics"] = [{"phase": "resource-ir", "code": getattr(exc, "code", "E_RIR_LOWER"),
                                   "message": str(exc)}]
    return report


def concurrent_ir_analysis(analysis: Analysis) -> dict:
    """Check explicit task/group obligations without upgrading runtime proofs."""
    report = {"schema": "hepta.concurrent-ir.export.v1", "ok": False,
              "status": "rejected", "concurrent_ir": None, "verifier": None,
              "validation": analysis.report}
    if analysis.program is None or analysis.checked is None or not analysis.checked.ok:
        return report
    from .concurrent_ir import ConcurrentIRError, verify_concurrent_ir
    from .concurrent_lowering import lower_concurrent_ir
    try:
        graph = lower_concurrent_ir(analysis.program, analysis.checked,
                                   project_sha256=getattr(analysis.project, "identity", None))
        verification = verify_concurrent_ir(json.loads(json.dumps(graph)))
        report.update(concurrent_ir=graph, verifier=verification,
                      ok=bool(analysis.report["ok"] and verification["ok"]),
                      status=analysis.report["status"] if verification["ok"] else "rejected")
    except (ConcurrentIRError, ValueError, TypeError, OverflowError, RecursionError) as exc:
        report["diagnostics"] = [{"phase": "concurrent-ir", "code": getattr(exc, "code", "E_CIR_LOWER"),
                                   "message": str(exc)}]
    return report
