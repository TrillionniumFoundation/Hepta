"""One validation pipeline for human and agent entrypoints."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path

from . import __version__
from .ast import HeptaError, Program
from .backend import compile_rust, emit_rust, emit_header, sha256
from .parser import parse
from .checker import check


def interface(program: Program) -> dict:
    return {"module": program.name,
            "structs": [{"name": s.name, "repr_c": s.repr_c,
                         "fields": [{"name": f.name, "type": str(f.type)} for f in s.fields]}
                        for s in program.structs],
            "functions": [{"name": f.name, "params": [{"name": p.name, "mode": p.mode, "type": str(p.type)} for p in f.params],
                           "returns": str(f.return_type), "effects": sorted(f.effects),
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


def analyze(source: str, path: str = "<input>", *, rustc=None, target=None,
            no_std=False, native=True, crate_type="rlib") -> Analysis:
    report = {"schema": "hepta.check.v1", "compiler_version": __version__,
              "compiler_sha256": compiler_hash(), "source_sha256": sha256(source.encode()),
              "path": path, "ok": False, "status": "rejected", "diagnostics": [],
              "checks": {"syntax": "not_run", "types_effects_resources": "not_run", "rust_borrows_types": "not_run"},
              "assumptions": [], "claims": {"whole_language_soundness_proved": False,
              "all_programs_faster_than_rust": False, "hardware_execution_verified": False,
              "bounded_cancellation_latency_proved": False, "deadlock_freedom_proved": False}}
    result = Analysis(report)
    try:
        program = parse(source, path)
        result.program = program
        report["checks"]["syntax"] = "passed"
        report["interface_sha256"] = interface_hash(program)
        checked = check(program)
        result.checked = checked
        report["diagnostics"] += [d.to_dict() for d in checked.diagnostics]
        report["effects"] = {k: sorted(v) for k, v in checked.effects.items()}
        report["assumptions"] = checked.assumptions
        if not checked.ok:
            report["checks"]["types_effects_resources"] = "rejected"
            return result
        report["checks"]["types_effects_resources"] = "passed_in_supported_subset"
        if any(s.repr_c for s in program.structs) or any(f.extern_c or f.export_c for f in program.functions):
            emit_header(program)  # Reject unrepresentable C declaration dependencies.
        generated = emit_rust(program, checked, no_std, crate_type)
        result.rust = generated
        report["rust_sha256"] = sha256(generated.encode())
        report["profile"] = {"no_std": no_std, "crate_type": crate_type, "overflow_checks": True, "panic": "abort"}
        if native:
            backend = compile_rust(generated, rustc=rustc, target=target, crate_type=crate_type, check_only=True)
            report["backend"] = backend
            report["diagnostics"] += backend["diagnostics"]
            report["checks"]["rust_borrows_types"] = backend["status"]
            report["ok"] = backend["ok"]
            report["status"] = "checked_with_external_assumptions" if backend["ok"] and report["assumptions"] else ("checked" if backend["ok"] else backend["status"])
        else:
            report["ok"] = True
            report["status"] = "frontend_only"
        return result
    except HeptaError as e:
        report["diagnostics"].append(e.diagnostic.to_dict())
        return result


def inspect_analysis(analysis: Analysis) -> dict:
    out = dict(analysis.report)
    out["schema"] = "hepta.inspect.v1"
    if analysis.program:
        out["interface"] = interface(analysis.program)
        out["symbols"] = [{"name": f.name, "start": f.span.start, "end": f.span.end,
                           "body_start": f.body_span.start, "body_end": f.body_span.end,
                           "calls": sorted(_calls(f.body or []))} for f in analysis.program.functions]
    return out


def _calls(body):
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
    visit(body)
    return found
