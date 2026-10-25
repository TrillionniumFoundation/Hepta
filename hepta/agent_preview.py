"""P7 multi-body, multi-source *preview only* Agent transaction.

No files are changed. A validated preview is not an atomic multi-file commit,
a functional equivalence proof, or an approval token for subsequent writing.
"""
from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import re

from .ast import HeptaError
from .modules import load_project
from .parser import parse
from .pipeline import analyze_project, interface_hash


SCHEMA = "hepta.patch.preview.v3"
MAX_EDITS = 32
_SHA = re.compile(r"[0-9a-f]{64}\Z")


def _digest(data: bytes) -> str:
    return sha256(data).hexdigest()


def _reject(code: str, message: str, *, validation: dict | None = None) -> dict:
    report = {"schema": SCHEMA, "ok": False, "status": "rejected", "applied": False,
              "write_capability": False, "transaction_atomicity": "not_implemented",
              "diagnostics": [{"code": code, "message": message, "phase": "transaction"}]}
    if validation is not None:
        report["validation"] = validation
    return report


def preview_multi_body_patch(entry: str | Path, request: dict, *, apply: bool = False,
                             rustc: str | None = None, target: str | None = None) -> dict:
    """Validate a combined candidate dependency graph without disk writes.

    Unlike chaining v2 previews, all candidate bodies are analyzed *together*
    with their shared changed-import context. Original graph identities must
    still match after validation. Crash-safe multi-file commit is NOT implemented.
    """
    if apply:
        return _reject("E_PREVIEW_APPLY_UNSUPPORTED", "v3 preview is read-only; multi-file atomic commit is not implemented")
    required = {"schema", "expected_project_sha256", "expected_interface_sha256", "edits"}
    edit_keys = {"target", "symbol", "expected_source_sha256", "replacement_body"}
    if not isinstance(request, dict) or set(request) != required or request.get("schema") != SCHEMA:
        return _reject("E_PREVIEW_SCHEMA", "Require exactly v3-preview schema, project hash, interface hash and edits")
    if any(not isinstance(request.get(k), str) or not _SHA.fullmatch(request[k])
           for k in ("expected_project_sha256", "expected_interface_sha256")):
        return _reject("E_PREVIEW_SCHEMA", "Project and interface identities must be lowercase SHA-256")
    edits = request["edits"]
    if not isinstance(edits, list) or not 1 <= len(edits) <= MAX_EDITS:
        return _reject("E_PREVIEW_LIMIT", "Require one to 32 body changes")
    for edit in edits:
        if (not isinstance(edit, dict) or set(edit) != edit_keys
                or not all(isinstance(x, str) for x in edit.values())
                or not edit["target"] or not edit["symbol"]
                or not _SHA.fullmatch(edit["expected_source_sha256"])):
            return _reject("E_PREVIEW_SCHEMA", "Each edit needs a relative target, symbol, expected hash and exact body")
    try:
        original = load_project(entry)
        if original.identity != request["expected_project_sha256"]:
            return _reject("E_STALE_PROJECT", "Dependency graph identity does not match the requested snapshot")
        if interface_hash(original.program) != request["expected_interface_sha256"]:
            return _reject("E_STALE_INTERFACE", "Project declarations/contracts differ from the expected identity")
        root = original.package.root if original.package else original.entry.parent
        groups: dict[Path, list[dict]] = {}
        seen: set[tuple[Path, str]] = set()
        for edit in edits:
            relative = Path(edit["target"])
            if relative.is_absolute():
                return _reject("E_PREVIEW_PATH", "Edit paths must be relative to the owning project root")
            path = (root / relative).resolve(strict=True)
            if path.suffix != ".hepta" or str(path) not in original.source_bytes:
                return _reject("E_PREVIEW_SCOPE", "Edit must target a loaded Hepta source file")
            if (path, edit["symbol"]) in seen:
                return _reject("E_PREVIEW_DUPLICATE", "A function may be edited only once in a preview")
            seen.add((path, edit["symbol"]))
            if _digest(original.source_bytes[str(path)]) != edit["expected_source_sha256"]:
                return _reject("E_STALE_SOURCE", "Edited source bytes differ from expected snapshot")
            groups.setdefault(path, []).append(edit)
        overrides: dict[Path, str] = {}
        edit_report: list[dict] = []
        for path, file_edits in sorted(groups.items(), key=lambda item: str(item[0])):
            original_bytes = original.source_bytes[str(path)]
            source = original_bytes.decode("utf-8")
            parsed = parse(source, str(path))
            replacements: list[tuple[int, int, str, str]] = []
            for edit in file_edits:
                matches = [f for f in parsed.functions if f.name == edit["symbol"] and f.body is not None]
                if len(matches) != 1:
                    return _reject("E_PREVIEW_SYMBOL", "Symbol must identify exactly one implemented local function")
                fn = matches[0]
                start, end = fn.body_span.start, fn.body_span.end
                if start < 0 or end > len(source) or start >= end:
                    return _reject("E_PREVIEW_SPAN", "Function body span is invalid")
                replacements.append((start, end, edit["symbol"], edit["replacement_body"]))
            replacements.sort(reverse=True)
            for higher, lower in zip(replacements, replacements[1:]):
                if lower[1] > higher[0]:
                    return _reject("E_PREVIEW_OVERLAP", "Edit spans must not overlap")
            candidate = source
            for start, end, symbol, new_body in replacements:
                candidate = candidate[:start] + new_body + candidate[end:]
            reparsed = parse(candidate, str(path))
            for _, _, symbol, expected_body in replacements:
                after_fn = [f for f in reparsed.functions if f.name == symbol and f.body is not None]
                if len(after_fn) != 1 or candidate[after_fn[0].body_span.start:after_fn[0].body_span.end] != expected_body:
                    return _reject("E_PREVIEW_SCOPE", "Each replacement must be exactly one function body")
            overrides[path] = candidate
            edit_report.extend({"target": str(path), "symbol": e["symbol"],
                                "source_before_sha256": _digest(original_bytes),
                                "source_after_sha256": _digest(candidate.encode("utf-8"))} for e in file_edits)
        checked = analyze_project(original.entry, source_overrides=overrides,
                                  rustc=rustc, target=target)
        if not checked.report["ok"]:
            return _reject("E_PREVIEW_NATIVE", "Combined candidate did not pass the selected native validation",
                           validation=checked.report)
        if interface_hash(checked.program) != request["expected_interface_sha256"]:
            return _reject("E_CONTRACT_CHANGE", "Combined edit changes a frozen declaration or contract")
        expected_sources = {**original.sources, **{str(path): _digest(text.encode("utf-8"))
                                                  for path, text in overrides.items()}}
        if (checked.project.sources != expected_sources or checked.project.modules != original.modules
                or checked.project.package_state != original.package_state
                or checked.project.bindings != original.bindings
                or not original.unchanged()):
            return _reject("E_STALE_PROJECT", "Combined check did not preserve exact source/import graph")
        return {"schema": SCHEMA, "ok": True, "status": "validated", "applied": False,
                "write_capability": False, "transaction_atomicity": "not_implemented",
                "project_before_sha256": original.identity,
                "project_candidate_sha256": checked.project.identity,
                "interface_sha256": request["expected_interface_sha256"],
                "edits": edit_report, "scope": "multi_body_complete_import_graph_preview_only",
                "validation": checked.report,
                "functional_equivalence_proved": False,
                "external_effects_rolled_back": False,
                "concurrency": "snapshot_recheck_no_write",
                "package_lock_requires_refresh_if_later_applied": original.package is not None}
    except (HeptaError, OSError, ValueError, UnicodeError) as exc:
        return _reject("E_PREVIEW_PROJECT", str(exc))
