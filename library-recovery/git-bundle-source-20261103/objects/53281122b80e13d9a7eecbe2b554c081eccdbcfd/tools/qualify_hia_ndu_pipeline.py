#!/usr/bin/env python3
"""Run the bounded HIA/NDU increment against one committed source inventory.

Every gate executes its real command. Missing dependencies, skipped/empty tests,
changed inputs and missing evidence are failures. Independent gates continue so
the report retains failures. Mechanism qualification is separate from scientific
advantage, whole-language safety and the six broad closure conditions.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.qualify_hia_unified import _command, cargo_test_outcome, unittest_outcome
from tools.release_check import _read_regular_evidence

SOURCE_PATHS = ("hepta", "tests", "tools", "rust", "pyproject.toml", "toolchain-lock.json", ".github/workflows")
TEST_MODULES = (
    "tests.test_hia_program", "tests.test_hia_program_tools", "tests.test_hia_program_llvm",
    "tests.test_hia_rust_owned_vm", "tests.test_hia_rust_owned_cfg", "tests.test_hia_rust_migration",
    "tests.test_hia_translation_validation", "tests.test_hia_finite_actions",
    "tests.test_hia_ndu_bridge", "tests.test_hia_ndu_optimizer", "tests.test_hia_optimization_cli",
    "tests.test_hia_multiversion", "tests.test_hia_background_optimizer", "tests.test_hia_x86_search",
)


def _git(*arguments):
    return subprocess.check_output(["git", *arguments], cwd=ROOT)


def inventory():
    names = _git("ls-files", "-z", "--", *SOURCE_PATHS).decode().split("\0")
    return {name: sha256((ROOT / name).read_bytes()).hexdigest() for name in sorted(set(names)) if name}


def _write(path, value):
    data = json.dumps(value, sort_keys=True, indent=2, allow_nan=False).encode() + b"\n"
    with path.open("xb") as stream:
        stream.write(data)
    return sha256(data).hexdigest()


def plan(directory, *, clang, bridge, build_receipt, cargo, full_regression):
    py = sys.executable
    rows = [
        ("focused_regression", [py, "-m", "unittest", *TEST_MODULES, "-v"], None, "unittest", None),
        ("rust_resource_crate", [cargo, "test", "--locked", "--offline", "--manifest-path",
                                 "rust/hia-core-shadow/Cargo.toml"], None, "cargo", None),
        ("translation_controls", [py, "tools/qualify_hia_translation_validation.py", "--output", directory / "translation.json"],
         directory / "translation.json", "hepta.hia.translation-validation-qualification.v1", "ok"),
        ("rust_owned_cfg", [py, "tools/qualify_hia_rust_owned_cfg.py", "--output", directory / "rust-cfg.json"],
         directory / "rust-cfg.json", "hepta.hia.rust-byte-owner-cfg-qualification.v1", "ok"),
        ("real_migration", [py, "tools/qualify_hia_rust_migration.py", "--workdir", directory / "migration", "--clang", clang,
                            "--clangxx", str(Path(clang).with_name("clang++"))],
         directory / "migration/qualification.json", "hepta.hia.rust-migration-qualification.v1", "ok"),
        ("equal_budget_ndu", [py, "tools/qualify_hia_ndu_search.py", "--clang", clang, "--bridge", bridge,
                              "--bridge-build-receipt", build_receipt, "--artifacts", directory / "ndu-native",
                              "--output", directory / "ndu-search.json"],
         directory / "ndu-search.json", "hepta.hia.ndu-search-qualification.v1", "qualified_for_finite_paired_replay"),
        ("native_generations", [py, "tools/qualify_hia_multiversion.py", "--clang", clang, "--output", directory / "multiversion.json"],
         directory / "multiversion.json", "hepta.hia.scalar-multiversion-qualification.v1", "qualified_for_declared_finite_lifecycle"),
        ("background_reoptimization", [py, "tools/qualify_hia_background_optimizer.py", "--clang", clang, "--bridge", bridge,
                                        "--bridge-build-receipt", build_receipt, "--output", directory / "background.json"],
         directory / "background.json", "hepta.hia.background-optimization-qualification.v1", "ok"),
        ("finite_x86_search", [py, "tools/qualify_hia_x86_search.py", "--clang", clang, "--artifacts", directory / "x86-native",
                               "--output", directory / "x86-search.json"],
         directory / "x86-search.json", "hepta.hia.x86-finite-search-qualification.v1", "ok"),
    ]
    if full_regression:
        rows.append(("full_regression", [py, "-m", "unittest", "discover", "-s", "tests", "-q"], None, "unittest", None))
    return rows


def qualify(directory, *, clang, bridge, build_receipt, upstream, cargo="cargo", full_regression=False):
    directory = Path(directory).resolve()
    directory.mkdir(parents=True, exist_ok=False)
    clang = shutil.which(str(clang)) or str(Path(clang).resolve())
    bridge, build_receipt = Path(bridge).resolve(), Path(build_receipt).resolve()
    # These are task-scoped test-tool paths, not changes to admission semantics.
    os.environ.update(HEPTA_CLANG=clang, CLANG=clang, HEPTA_NDU_BRIDGE=str(bridge),
                      HEPTA_NDU_BUILD=str(build_receipt.parent), HEPTA_NDU_UPSTREAM=str(Path(upstream).resolve()))
    before = inventory()
    revision = _git("rev-parse", "HEAD").decode().strip()
    source_status = _git("status", "--porcelain", "--untracked-files=normal", "--", *SOURCE_PATHS).decode()
    report = {"schema": "hepta.hia.ndu-pipeline-qualification.v1", "started_utc": datetime.now(timezone.utc).isoformat(),
              "source_revision": revision, "source_inventory_before": before, "source_status_before": source_status,
              "source_is_committed": not source_status.strip(), "full_regression_requested": full_regression,
              "gates": [], "mechanism_qualified": False, "six_stages_closed": False,
              "scientific_incremental_advantage_established": False,
              "whole_language_soundness_proved": False, "global_optimality_established": False}
    frozen_plan = plan(directory, clang=clang, bridge=bridge, build_receipt=build_receipt,
                       cargo=cargo, full_regression=full_regression)
    report["planned_gates"] = [row[0] for row in frozen_plan]
    _write(directory / "frozen-plan.json", {"source_revision": revision,
            "commands": [{"name": name, "argv": list(map(str, argv)), "schema": schema, "success_field": field}
                         for name, argv, path, schema, field in frozen_plan]})
    try:
        receipt_bytes, _ = _read_regular_evidence(build_receipt)
        _write(directory / "ndu-build-receipt.json", json.loads(receipt_bytes))
        report["ndu_build_receipt_sha256"] = sha256(receipt_bytes).hexdigest()
        report["native_bridge_sha256"] = sha256(bridge.read_bytes()).hexdigest()
    except Exception as error:
        report["ndu_setup_error"] = type(error).__name__ + ": " + str(error)
    for name, argv, evidence_path, schema, field in frozen_plan:
        print(json.dumps({"gate": name, "state": "running"}), flush=True)
        execution = _command(argv, timeout=1800)
        row = {"name": name, "execution": execution, "passed": False}
        if schema == "unittest":
            row.update(unittest_outcome(execution["stderr"], execution["returncode"]))
        elif schema == "cargo":
            row.update(cargo_test_outcome(execution["stdout"], execution["returncode"]))
        else:
            try:
                raw, _ = _read_regular_evidence(evidence_path)
                value = json.loads(raw)
                row.update(evidence=str(evidence_path), evidence_sha256=sha256(raw).hexdigest(), schema=value.get("schema"))
                row["passed"] = execution["returncode"] == 0 and value.get("schema") == schema and value.get(field) is True
                if name == "real_migration":
                    from tools.qualify_hia_rust_migration import validate_report
                    validate_report(value)
                    row["denominators"] = value["denominators"]
                if name == "equal_budget_ndu":
                    row["scientific_claims"] = value.get("claims", {})
                if value.get("source_inputs_unchanged") is False or value.get("source_unchanged") is False:
                    row["passed"] = False
            except Exception as error:
                row.update(passed=False, evidence_error=type(error).__name__ + ": " + str(error))
        report["gates"].append(row)
        _write(directory / (name + "-execution.json"), row)
        print(json.dumps({"gate": name, "passed": row["passed"], "seconds": execution["seconds"]}), flush=True)
    after = inventory()
    report["source_inventory_after"] = after
    report["source_revision_after"] = _git("rev-parse", "HEAD").decode().strip()
    report["source_status_after"] = _git("status", "--porcelain", "--untracked-files=normal", "--", *SOURCE_PATHS).decode()
    report["source_unchanged"] = (before == after and revision == report["source_revision_after"]
                                  and not report["source_status_after"].strip())
    core_gates = [row for row in report["gates"] if row["name"] != "full_regression"]
    report["mechanism_qualified"] = (report["source_is_committed"] and report["source_unchanged"] and "ndu_setup_error" not in report
                                     and len(core_gates) == 9 and all(row["passed"] for row in core_gates))
    report["ok"] = report["mechanism_qualified"] and all(row["passed"] for row in report["gates"])
    report["status"] = ("bounded_mechanisms_passed_scientific_gates_open" if report["ok"]
                         else "qualification_incomplete_or_failed")
    report["finished_utc"] = datetime.now(timezone.utc).isoformat()
    report["scope"] = "declared finite mechanisms; actual executed host only; all broad closure flags remain false"
    _write(directory / "qualification.json", report)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-directory", type=Path, required=True)
    parser.add_argument("--clang", default=os.environ.get("HEPTA_CLANG", "clang"))
    parser.add_argument("--bridge", required=True, type=Path)
    parser.add_argument("--bridge-build-receipt", required=True, type=Path)
    parser.add_argument("--upstream", required=True, type=Path, help="Git checkout containing the pinned NDU object for independent provenance tests")
    parser.add_argument("--cargo", default="cargo")
    parser.add_argument("--full-regression", action="store_true", help="Also execute every existing Python test; no skips qualify")
    args = parser.parse_args(argv)
    result = qualify(args.output_directory, clang=args.clang, bridge=args.bridge,
                     build_receipt=args.bridge_build_receipt, upstream=args.upstream,
                     cargo=args.cargo, full_regression=args.full_regression)
    print(json.dumps({key: result[key] for key in ("ok", "status", "mechanism_qualified", "source_revision", "source_unchanged")}))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
