"""Full-graph, multiple-file Agent patch validation, with no unsafe partial writes.

This v3 *preview* supports multiple edits, but apply is deliberately denied:
standard POSIX rename has no atomic multi-path commit. A future persistent
transaction log plus recovery and reader protocol is required before writeback.
"""
from __future__ import annotations

from pathlib import Path

from .ast import HeptaError
from .backend import sha256
from .modules import load_project
from .parser import parse
from .pipeline import analyze_project, interface_hash

SCHEMA = "hepta.patch.v3.preview"
_EDIT_FIELDS = {"target", "symbol", "expected_source_sha256", "replacement_body"}
_ROOT_FIELDS = {"schema", "expected_project_sha256", "expected_interface_sha256", "edits"}


def _reject(code: str, message: str, *, validation: dict | None = None) -> dict:
    result = {"schema": SCHEMA, "ok": False, "status": "rejected", "applied": False,
              "diagnostics": [{"phase": "transaction", "code": code, "message": message}]}
    if validation is not None:
        result["validation"] = validation
    return result


def preview_project_patch(entry: str | Path, request: dict, *, apply=False, rustc=None, target=None) -> dict:
    """Validate a multi-file candidate under exactly one frozen graph snapshot.

    Rejects apply rather than misrepresenting sequential file replacements as
    atomic transactions. A validated preview does not prove functional equivalence.
    """
    if not isinstance(request, dict) or set(request) != _ROOT_FIELDS or request.get("schema") != SCHEMA:
        return _reject("E_PATCH_SCHEMA", "Require the complete hepta.patch.v3.preview schema")
    if (not isinstance(request.get("expected_project_sha256"), str)
            or not isinstance(request.get("expected_interface_sha256"), str)):
        return _reject("E_PATCH_SCHEMA", "Expected project and interface hashes must be strings")
    edits = request.get("edits")
    if (not isinstance(edits, list) or not 2 <= len(edits) <= 32
            or any(not isinstance(item, dict) or set(item) != _EDIT_FIELDS
                   or any(not isinstance(v, str) for v in item.values()) for item in edits)):
        return _reject("E_PATCH_SCHEMA", "Require 2..32 typed one-function-body edits")
    if apply:
        return _reject("E_MULTI_FILE_ATOMICITY", "v3 only validates multi-file previews; crash-safe commit and recovery are not implemented")
    try:
        original = load_project(entry)
        if original.identity != request["expected_project_sha256"]:
            return _reject("E_STALE_PROJECT", "Project graph changed since requested snapshot")
        if interface_hash(original.program) != request["expected_interface_sha256"]:
            return _reject("E_STALE_INTERFACE", "Interface snapshot changed since request")
        base = original.package.root if original.package else original.entry.parent
        overrides: dict[Path, str] = {}
        changed = []
        for edit in edits:
            rel = Path(edit["target"])
            if rel.is_absolute() or not edit["target"].strip():
                return _reject("E_PATCH_FILE", "Targets must be nonempty relative source paths")
            path = (base / rel).resolve()
            if path.suffix != ".hepta" or str(path) not in original.source_bytes:
                return _reject("E_PATCH_FILE", "Target is not a source within this resolved dependency graph")
            if path in overrides:
                return _reject("E_PATCH_DUPLICATE", "Only one function body edit per source is accepted in this preview")
            before = original.source_bytes[str(path)]
            if sha256(before) != edit["expected_source_sha256"]:
                return _reject("E_STALE_SOURCE", "One target differs from its expected source bytes")
            source = before.decode("utf-8")
            parsed = parse(source, str(path))
            functions = [f for f in parsed.functions if f.name == edit["symbol"] and f.body is not None]
            if len(functions) != 1:
                return _reject("E_PATCH_SYMBOL", "Each edit must identify exactly one implemented function")
            old = functions[0]
            body = edit["replacement_body"]
            candidate = source[:old.body_span.start] + body + source[old.body_span.end:]
            cand_ast = parse(candidate, str(path))
            matching = [f for f in cand_ast.functions if f.name == old.name and f.body is not None]
            if (len(matching) != 1 or
                    candidate[matching[0].body_span.start:matching[0].body_span.end] != body):
                return _reject("E_PATCH_SCOPE", "Replacement must be exactly one function body")
            overrides[path] = candidate
            changed.append({"target": str(path), "symbol": old.name,
                            "before_sha256": sha256(before),
                            "after_sha256": sha256(candidate.encode("utf-8"))})
        # One pass checks the entire candidate graph, not each edit separately.
        checked = analyze_project(original.entry, source_overrides=overrides, rustc=rustc, target=target)
        if not checked.report["ok"]:
            return _reject("E_PATCH_VALIDATION", "Candidate graph fails native validation", validation=checked.report)
        if interface_hash(checked.program) != request["expected_interface_sha256"]:
            return _reject("E_CONTRACT_CHANGE", "Multi-file patch changed declarations or contracts")
        expected_sources = {**original.sources, **{str(p): sha256(s.encode("utf-8")) for p, s in overrides.items()}}
        if (checked.project.sources != expected_sources
                or checked.project.modules != original.modules
                or checked.project.package_state != original.package_state
                or not original.unchanged()):
            return _reject("E_STALE_PROJECT", "Candidate did not validate against the frozen graph")
        return {"schema": SCHEMA, "ok": True, "status": "validated", "applied": False,
                "changes": changed, "project_before_sha256": original.identity,
                "project_candidate_sha256": checked.project.identity,
                "interface_sha256": request["expected_interface_sha256"],
                "scope": "multi_body_complete_import_graph_preview_only",
                "writeback": "not_implemented_for_multi_file_atomicity",
                "functional_equivalence_proved": False,
                "native_borrow_validation": checked.report["checks"].get("rust_borrows_types"),
                "validation": checked.report}
    except (HeptaError, OSError, UnicodeError) as exc:
        return _reject("E_PATCH_PROJECT", str(exc))
