"""Bind an independently verified resource graph to freshly checked source.

The data-only resource verifier establishes properties of the supplied graph;
its source/project hashes are merely producer assertions.  This optional
entrypoint replays the existing frontend, canonical semantic encoder and
resource lowerer on the actual project, then requires an exact graph match.
It is executable correspondence evidence for this compiler snapshot, not a
proof that the resource abstraction or a native backend preserves semantics.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .ast import HeptaError
from .pipeline import analyze_project
from .resource_ir import ResourceIRError, read_resource_ir, verify_resource_ir
from .resource_lowering import lower_resource_ir
from .semantic_ir import lower_checked_program


SCHEMA = "hepta.resource-source-validation.v1"
_MAX_GRAPH_BYTES = 16 * 1024 * 1024
_CLAIMS = {
    "source_to_ir_refinement_proved": False,
    "native_codegen_uses_this_ir": False,
    "whole_language_soundness_proved": False,
    "external_contracts_proved": False,
    "termination_proved": False,
    "scalar_value_semantics_verified": False,
    "functional_equivalence_proved": False,
    "user_program_executed": False,
}


def _new_report() -> dict:
    return {"schema": SCHEMA, "ok": False, "status": "rejected",
            "source_binding_verified": False,
            "binding_scope": "exact_current_source_resource_projection_replay",
            "source_binding": None, "source_validation": None,
            "resource_verification": None, "diagnostics": [],
            "claims": dict(_CLAIMS)}


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _seal(report: dict) -> dict:
    # Digest identifies these evidence bytes, not a signing capability.
    report["sha256"] = hashlib.sha256(_canonical(report)).hexdigest()
    return report


def _reject(code: str, message: str) -> None:
    raise ResourceIRError(code, message)


def verify_resource_source(entry: str | Path, document: object, *,
                           rustc: str | None = None, target: str | None = None,
                           locked: bool = False, native: bool = True) -> dict:
    """Recheck actual source and compare its entire resource projection.

    The default performs a fresh pinned Rust metadata check.  ``native=False``
    is an explicit frontend-only profile and is never reported as a native
    qualification.  This function does not consume supplied validation/proof
    receipts and does not execute the source program.  Existing source graph
    and path-binding rechecks detect changes during the operation; they do not
    provide an atomic snapshot against a noncooperating writer.
    """
    report = _new_report()
    try:
        if type(native) is not bool or type(locked) is not bool:
            _reject("E_RIR_SOURCE_PROFILE", "native and locked must be explicit booleans")
        # Freeze caller-owned containers before checks and retain only JSON
        # values.  A graph changing after this point cannot change the checked
        # payload.  The file entrypoint also rejects duplicate JSON fields.
        encoded = _canonical(document)
        if len(encoded) > _MAX_GRAPH_BYTES:
            _reject("E_RIR_LIMIT", "Serialized resource graph exceeds 16 MiB")
        graph = json.loads(encoded)
        independent = verify_resource_ir(graph)
        report["resource_verification"] = independent
        if independent.get("ok") is not True:
            report["diagnostics"] = independent["diagnostics"]
            return _seal(report)

        # Reuse the actual implementation authority.  The caller cannot supply
        # a checked AST, expression-type table or a successful native receipt.
        analysis = analyze_project(entry, locked=locked, rustc=rustc,
                                   target=target, backend="rust", native=native)
        report["source_validation"] = analysis.report
        if (analysis.report.get("ok") is not True or analysis.program is None
                or analysis.checked is None or not analysis.checked.ok
                or analysis.project is None):
            _reject("E_RIR_SOURCE_REJECTED", "The actual source project did not pass the requested validation")
        if native:
            if (analysis.report.get("checks", {}).get("rust_borrows_types") != "rustc_checked"
                    or analysis.report.get("backend", {}).get("ok") is not True
                    or analysis.report.get("status") not in {"checked", "checked_with_external_assumptions"}):
                _reject("E_RIR_SOURCE_NATIVE", "Fresh pinned native Rust qualification is required")
        elif (analysis.report.get("status") != "frontend_only"
              or analysis.report.get("checks", {}).get("rust_borrows_types") != "not_run"):
            _reject("E_RIR_SOURCE_PROFILE", "Frontend-only replay cannot inherit native qualification")

        project = analysis.project
        semantic = lower_checked_program(analysis.program, analysis.checked,
                                         project_sha256=project.identity)
        if semantic["all_expressions_typed"] is not True or semantic["untyped_expressions"]:
            _reject("E_RIR_SOURCE_TYPES", "Canonical source semantics contain untyped expressions")
        expected = lower_resource_ir(analysis.program, analysis.checked,
                                     project_sha256=project.identity)
        # Check identities separately for an actionable stale-source result.
        # Equality then includes all declarations, type shapes, control-flow,
        # owner/loan transitions, return origins and foreign obligations.  A
        # newly hashed but internally valid replacement is not a source proof.
        if (graph["source_sha256"] != expected["source_sha256"]
                or graph["project_sha256"] != expected["project_sha256"]):
            _reject("E_RIR_SOURCE_IDENTITY", "Resource graph does not identify the freshly loaded source project")
        if _canonical(graph) != _canonical(expected):
            _reject("E_RIR_SOURCE_GRAPH", "Resource graph differs from the current checked-source projection")
        if not project.unchanged():
            _reject("E_RIR_SOURCE_STALE", "Source graph or path bindings changed during resource replay")

        report["source_binding"] = {
            "source_sha256": expected["source_sha256"],
            "project_sha256": project.identity,
            "source_inventory": dict(project.sources),
            "canonical_semantic_schema": semantic["schema"],
            "canonical_semantic_sha256": semantic["sha256"],
            "resource_ir_sha256": independent["ir_sha256"],
            "compiler_sha256": analysis.report["compiler_sha256"],
            "native_reference": "rustc_checked" if native else "not_run",
            "external_obligations": independent["external_obligations"],
            "canonical_external_obligations": semantic["external_obligations"],
            "canonical_foreign_assumptions": semantic["foreign_assumptions"],
        }
        if "stored_views" in independent:
            # The frontend's general stored-borrow capability remains false:
            # only this explicitly checked local slice-view profile is added.
            report["source_binding"]["independent_stored_views"] = independent["stored_views"]
        # Canonical obligations include unsafe/FFI effect boundaries that the
        # resource abstraction intentionally does not represent as operations.
        has_assumptions = bool(independent["external_obligations"]
                               or semantic["external_obligations"]
                               or semantic["foreign_assumptions"])
        report.update(ok=True, source_binding_verified=True,
                      status=("frontend_only_source_replayed" if not native else
                              "source_replayed_with_external_assumptions" if has_assumptions else
                              "source_replayed"))
    except (HeptaError, ResourceIRError, OSError, TypeError, ValueError,
            OverflowError, RecursionError) as exc:
        report["diagnostics"] = [{"code": getattr(exc, "code", "E_RIR_SOURCE"),
                                  "message": str(exc)}]
    return _seal(report)


def main(argv=None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="Actual Hepta entry source, package or manifest")
    parser.add_argument("graph", type=Path, help="Resource JSON exported for that exact project")
    parser.add_argument("--rustc")
    parser.add_argument("--target")
    parser.add_argument("--locked", action="store_true")
    parser.add_argument("--frontend-only", action="store_true",
                        help="Explicitly skip native checking; never claim native validation")
    args = parser.parse_args(argv)
    try:
        graph = read_resource_ir(args.graph)
        report = verify_resource_source(args.source, graph, rustc=args.rustc,
                                        target=args.target, locked=args.locked,
                                        native=not args.frontend_only)
    except (OSError, ValueError, RecursionError) as exc:
        report = _new_report()
        report["diagnostics"] = [{"code": getattr(exc, "code", "E_RIR_JSON"), "message": str(exc)}]
        report = _seal(report)
    print(json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
