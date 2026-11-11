"""Complete C build matrices through the existing contracted resource frontend.

This is a safe-Hepta/Rust migration route with an explicitly caller-unsafe C
ABI. It does not claim standalone HIA lowering, pointer-contract inference or
source equivalence. Every selected variant is retained, including failures.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path

from .c_migrate import MigrationRejected, migrate_c_project
from .c_project_matrix import capture_project_matrix, verify_project_matrix


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def migrate_c_resource_matrix(manifest, output_directory, *, contracts_by_variant,
                              clang="clang", rustc=None, verify_native=False):
    """Bind each complete declared build to its own explicit resource contract.

    A selected build capture always retains its original database indices and
    selection schema. The outer matrix replays the exhaustive partition before
    and after translation; an individual variant cannot claim the full matrix.
    Output directories must be new. Partial work is kept but never published as
    an overall successful matrix.
    """
    destination = Path(output_directory).absolute()
    report = {
        "schema": "hepta.c-resource-matrix-migration.v1", "ok": False,
        "status": "rejected", "output_directory": str(destination),
        "variants": [], "diagnostics": [],
        "claims": {
            "every_listed_command_assigned_exactly_once": False,
            "all_active_declarations_have_disposition": False,
            "original_c_implementation_in_translated_target": False,
            "same_contracted_c_translation_authority": True,
            "standalone_hia_lowering_qualified": False,
            "foreign_pointer_contracts_inferred_or_proved": False,
            "unlisted_configurations_qualified": False,
            "source_equivalence_proved": False,
            "native_behavior_or_abi_executed": False,
        },
    }
    created = False
    try:
        if destination.exists() or destination.is_symlink():
            raise MigrationRejected("E_C_RESOURCE_MATRIX_PATH", "Matrix output must be a new directory")
        if type(verify_native) is not bool:
            raise MigrationRejected("E_C_RESOURCE_MATRIX_INPUT", "verify_native must be boolean")
        captured = capture_project_matrix(manifest, clang=clang, language="c")
        report["matrix_capture"] = captured
        names = {row["name"] for row in captured["variants"]}
        if type(contracts_by_variant) is not dict or set(contracts_by_variant) != names:
            raise MigrationRejected("E_C_RESOURCE_MATRIX_CONTRACT", "Exactly one contract per declared variant is required")
        contracts = deepcopy(contracts_by_variant)
        contract_identity = _canonical(contracts)
        report["contracts_sha256"] = hashlib.sha256(contract_identity.encode()).hexdigest()
        report["claims"]["every_listed_command_assigned_exactly_once"] = True
        destination.mkdir(parents=True)
        created = True
        for variant in captured["variants"]:
            name = variant["name"]
            row = {"name": name, "command_indices": variant["command_indices"],
                   "contract_sha256": hashlib.sha256(_canonical(contracts[name]).encode()).hexdigest(),
                   "status": "started", "migration": None}
            report["variants"].append(row)
            migrated = migrate_c_project(captured["database"]["path"], destination / name,
                                         contracts=contracts[name], clang=clang, rustc=rustc,
                                         verify_native=verify_native,
                                         command_indices=variant["command_indices"])
            row["migration"] = migrated
            row["status"] = "passed" if migrated["ok"] else "rejected"
            # Exact comparison distinguishes true/1 and retained selection
            # identity, not merely an equal source filename set.
            if "build" in migrated and _canonical(migrated["build"]) != _canonical(variant["capture"]):
                raise MigrationRejected("E_C_RESOURCE_MATRIX_CHANGED", "Variant recapture differs from frozen matrix")
        verify_project_matrix(captured)
        if _canonical(contracts_by_variant) != contract_identity:
            raise MigrationRejected("E_C_RESOURCE_MATRIX_CHANGED", "Caller contract changed during migration")
        complete = all(row["migration"]["declaration_inventory_complete"] and
                       all(not item["status"].endswith("pending")
                           for item in row["migration"]["declarations"])
                       for row in report["variants"])
        report["claims"]["all_active_declarations_have_disposition"] = complete
        report["ok"] = complete and all(row["status"] == "passed" for row in report["variants"])
        report["status"] = ("all_variants_native_built_not_executed" if verify_native else
                            "all_variants_frontend_checked_not_native_qualified") if report["ok"] else "variant_rejected"
    except (MigrationRejected, OSError, ValueError, TypeError, KeyError, RecursionError) as exc:
        report["diagnostics"].append({"code": getattr(exc, "code", "E_C_RESOURCE_MATRIX_INPUT"),
                                      "message": str(exc)})
    if created and destination.is_dir() and not destination.is_symlink():
        # No existing output is overwritten, including on a failed invocation.
        path = destination / "matrix-migration.json"
        if not path.exists():
            with path.open("x", encoding="utf-8") as stream:
                json.dump(report, stream, indent=2, sort_keys=True)
                stream.write("\n")
    return report
