"""Source-bound project migration bundle publication and qualification."""
from __future__ import annotations

from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time

from .ast import HeptaError
from .c_migrate import MigrationRejected
from .c_contracts import contract_identity, snapshot_contracts
from .c_project import capture_project, digest, verify_capture
from .c_translation import CTranslator


def migrate_project(database: str | Path, output_directory: str | Path, *,
                    contracts: dict | None = None, clang: str = "clang",
                    rustc: str | None = None, verify_native: bool = False,
                    command_indices: list[int] | None = None) -> dict:
    started = time.perf_counter()
    destination = Path(output_directory).absolute()
    report = {"schema": "hepta.c-project-migration.v1", "ok": False, "status": "rejected",
              "profile": "captured_c_value_and_contracted_slice_subset",
              "output_directory": str(destination), "diagnostics": [], "declarations": [],
              "claims": {"source_equivalence_proved": False, "whole_language_soundness_proved": False,
                         "pointer_contracts_inferred": False, "all_c_or_cpp_supported": False,
                         "unlisted_build_configurations_qualified": False,
                         "foreign_pointer_validity_checked": False},
              "declaration_inventory_complete": False,
              "frontend_validation": "not_run", "native_validation": "not_run",
              "differential_execution": "not_run", "publication": "new_directory_manifest_last_not_crash_atomic"}
    translator = None
    try:
        if destination.exists() or destination.is_symlink():
            raise MigrationRejected("E_C_PROJECT_EXISTS", "Output bundle must be a new non-symlink directory")
        report["contract_input_origin"] = ("default_empty_scalar_contract" if contracts is None
                                           else "caller_supplied_contract")
        contracts = snapshot_contracts(contracts)
        report["contract_identity"] = contract_identity(contracts)
        capture = capture_project(database, clang=clang, command_indices=command_indices)
        report["build"] = capture
        if isinstance(contracts, dict) and contracts.get("schema") == "hepta.c-record-views.v1":
            from .c_record_views import CRecordViewTranslator
            translator = CRecordViewTranslator(capture, contracts)
            report["profile"] = "captured_C_record_views_and_checked_cursor_slices"
        else:
            translator = CTranslator(capture, contracts)
        source, bridge, functions = translator.emit()
        report["source_type_admission"] = translator.original_type_receipts
        report["functions"] = functions
        from .parser import parse
        from .checker import check
        from .backend import emit_rust, compile_rust
        program = parse(source, str(destination / "source.hepta"))
        checked = check(program)
        if not checked.ok:
            report["diagnostics"] = [item.to_dict() for item in checked.diagnostics]
            raise MigrationRejected("E_C_PROJECT_FRONTEND", "Generated safe core failed Hepta checking")
        report["frontend_validation"] = "passed"
        generated_rust = emit_rust(program, checked, crate_type="cdylib") + "\n" + bridge
        report["contracts"] = translator.contracts
        if getattr(translator, "allow_record_views", False):
            report["record_views"] = translator.view_report()
        report["contract_scope"] = {
            "origin": "caller_supplied_not_inferred_or_proved",
            "may_narrow_original_c_input_domain": any(p["pointer"] for fn in functions for p in fn["params"]),
            "pointer_requirements": ["initialized elements", "one live aligned allocation", "stable lifetime throughout call",
                                     "exclusive access for mutable slices", "length at most isize::MAX / element_size"],
            "runtime_checks": ["non-null for nonempty buffers", "alignment", "representable slice length", "safe-core bounds checks"],
            "not_runtime_checked": ["allocation provenance", "actual allocation size", "initialization", "aliasing", "concurrent foreign accesses"],
        }
        report["artifacts"] = {name: {"sha256": digest(value.encode()), "bytes": len(value.encode())} for name, value in
                               (("source.hepta", source), ("bridge.rs", bridge), ("generated.rs", generated_rust))}
        report["cost"] = {
            "project_input_bytes": sum(item["bytes"] for item in capture["dependencies"] if item["project_input"]),
            "project_input_files": sum(item["project_input"] for item in capture["dependencies"]),
            "compile_configurations": len(capture["configurations"]),
            "caller_slice_contracts": sum(p["pointer"] and not p.get("record", False) for fn in functions for p in fn["params"]),
            "caller_record_view_contracts": sum(p.get("record", False) for fn in functions for p in fn["params"]),
            "generated_hepta_lines": len(source.splitlines()),
            "generated_abi_bridge_lines": len(bridge.splitlines()),
            "manual_review_hours": None, "agent_tokens": None,
        }
        destination.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix=".hepta-c-project-", dir=destination.parent) as temporary:
            stage = Path(temporary)
            contents = {"source.hepta": source, "bridge.rs": bridge, "generated.rs": generated_rust}
            if verify_native:
                native = compile_rust(generated_rust, output=stage / "libtranslated.so", rustc=rustc, crate_type="cdylib")
                report["native_build"] = native
                if not native["ok"]:
                    report["diagnostics"].extend(native.get("diagnostics", []))
                    raise MigrationRejected("E_C_PROJECT_NATIVE", "Generated native code failed borrow/type/codegen validation")
                native["artifact"] = str(destination / "libtranslated.so")
                report["native_validation"] = "passed"
                report["artifacts"]["libtranslated.so"] = {"sha256": digest((stage / "libtranslated.so").read_bytes()),
                                                           "bytes": (stage / "libtranslated.so").stat().st_size}
            verify_capture(capture)
            report["declarations"] = translator.inventory
            report["declaration_inventory_complete"] = translator.inventory_complete
            _coverage(report)
            report["cost"]["migration_seconds"] = time.perf_counter() - started
            report.update(ok=True, status="native_built_not_equivalence_proved" if verify_native else "frontend_checked_not_native_qualified")
            contents["migration.json"] = json.dumps(report, indent=2, sort_keys=True) + "\n"
            for name, text in contents.items():
                path = stage / name
                with path.open("x", encoding="utf-8") as stream:
                    stream.write(text)
                    stream.flush()
                    os.fsync(stream.fileno())
            # The manifest is published last. No claim of a crash-atomic
            # directory transaction is made. No existing name is overwritten.
            destination.mkdir()
            created = []
            try:
                for path in sorted(stage.iterdir(), key=lambda p: p.name == "migration.json"):
                    target = destination / path.name
                    os.link(path, target)
                    created.append((target, digest(path.read_bytes())))
            except OSError:
                for path, expected in reversed(created):
                    if path.is_file() and digest(path.read_bytes()) == expected:
                        path.unlink()
                try:
                    destination.rmdir()
                except OSError:
                    pass
                raise
        return report
    except (MigrationRejected, HeptaError, OSError, ValueError, KeyError, TypeError, RecursionError) as exc:
        report.update(ok=False, status="rejected")
        report["diagnostics"].append({"code": getattr(exc, "code", "E_C_PROJECT_INPUT"), "message": str(exc)})
        if translator is not None:
            report["source_type_admission"] = translator.original_type_receipts
            report["declaration_inventory_complete"] = translator.inventory_complete
            for item in translator.inventory:
                if item["status"] in {"pending", "prototype_pending", "function_pending"}:
                    item.update(status="not_attempted_due_to_rejection", reason="whole_bundle_rejected")
            report["declarations"] = translator.inventory
        _coverage(report)
        report["elapsed_seconds"] = time.perf_counter() - started
        return report


def _coverage(report: dict) -> None:
    project = [item for item in report["declarations"] if item["status"] != "system_or_compiler_declaration"]
    counts = Counter(item["status"] for item in project)
    report["coverage"] = {"active_project_declarations": len(project), "status_counts": dict(sorted(counts.items())),
                          "system_or_compiler_declarations_recorded": len(report["declarations"]) - len(project),
                          "denominator": "active_declarations_in_all_listed_preprocessed_translation_units",
                          "unlisted_macro_configurations_included": False}
