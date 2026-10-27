#!/usr/bin/env python3
"""Fresh C/C++ migration, native execution and independent Rust resource parity.

Reuses the existing translators and native qualifier. It does not introduce a
second C/C++ parser, widen the migration subset or promote Rust admission.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hepta.clang_capture import run_bounded
from hepta.hia_program import verify_program
from hepta.hia_program_runtime import execute_program
from tools.evidence_checks import require, strict_equal
from tools.qualify_hia_migration import qualify as qualify_native, _cases, validate_cpp_owned_hia_receipt
from tools.validate_cpp_owned import cases as owner_cases

POLICY = {"max_steps": 1_000_000, "max_heap_bytes": 16 * 1024 * 1024, "max_call_depth": 32}
CLAIMS = {
    "fresh_c_cpp_sources_migrated_to_actual_core": True,
    "actual_python_rust_full_ledgers_compared": True,
    "native_original_and_hia_corpus_executed": True,
    "entire_native_corpus_executed_by_rust": False,
    "all_c_cpp_supported": False,
    "source_equivalence_proved": False,
    "rust_production_admission_authorized": False,
    "native_backend_refinement_proved": False,
    "whole_language_soundness_proved": False,
    "full_P2_or_P4_closed": False,
}


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def inventory():
    files = set((ROOT / "hepta").glob("*.py"))
    files.update((ROOT / "rust/hia-core-shadow/src").rglob("*.rs"))
    for folder in ("examples/hia_migration", "examples/cpp/class_migration", "examples/cpp/owned_migration"):
        files.update(p for p in (ROOT / folder).rglob("*") if p.is_file())
    files.update(ROOT / p for p in (
        "rust/hia-core-shadow/Cargo.toml", "rust/hia-core-shadow/Cargo.lock",
        "tests/test_hia_rust_migration.py",
        "tools/qualify_hia_rust_migration.py", "tools/qualify_hia_migration.py",
        "tools/validate_cpp_owned.py", "tools/evidence_checks.py"))
    return {str(path.relative_to(ROOT)): digest(path) for path in sorted(files)}


def _process(argv, *, stdin=None, timeout=60):
    result = run_bounded(list(map(str, argv)), cwd=ROOT, input_text=stdin, timeout=timeout,
                         stdin_limit=8 * 1024 * 1024, stdout_limit=2_000_000, stderr_limit=1_000_000)
    return {"argv": list(map(str, argv)), "returncode": result.returncode,
            "stdout": result.stdout, "stderr": result.stderr,
            "stdin_sha256": hashlib.sha256((stdin or "").encode()).hexdigest()}


def _plans(native, directory):
    require(native.get("ok") is True and native.get("schema") == "hepta.hia-migration-qualification.v1"
            and native.get("status") == "finite_source_to_hia_native_qualification_passed",
            "fresh complete native migration qualification required")
    require(native["implementation_sha256"] == native["implementation_after_sha256"]
            and native["source_inputs_sha256"] == native["source_inputs_after_sha256"],
            "native migration inputs or implementation changed")
    plans = []
    require(len(native["multi_owner_cases"]) == len(_cases()), "C migration denominator changed")
    for index, (row, case) in enumerate(zip(native["multi_owner_cases"], _cases())):
        require(strict_equal({k: row[k] for k in case}, case), "C migration vectors changed")
        plans.append({"family": "c_multi_owner", "case_index": index,
                      "program_path": str(directory / "paired_bytes.hia.json"),
                      "entry": "c_hia_paired_bytes", "arguments": case["arguments"],
                      "allocation_fail_at": case["allocation_fail_at"], "expected": row["expected"],
                      "native_observation": row["native"]})
    require(len(native["cpp_class_cases"]) == native["cpp_class_case_count"] == 20,
            "C++ scalar class denominator changed")
    for index, row in enumerate(native["cpp_class_cases"]):
        require(strict_equal(row["native"], {"original_cpp": row["reference"],
                                            "standalone_hia": row["reference"]}),
                "C++ scalar native observations disagree")
        plans.append({"family": "cpp_scalar_class", "case_index": index,
                      "program_path": str(directory / "cpp_class/class.hia.json"),
                      "entry": row["function"], "arguments": row["arguments"],
                      "allocation_fail_at": None, "expected": row["reference"],
                      "native_observation": row["native"]})
    owned = native["cpp_owned"]
    validate_cpp_owned_hia_receipt(owned)
    vectors = owner_cases()
    selected = [index for index, row in enumerate(vectors) if row["size"] <= 17]
    require([row["case_index"] for row in owned["interpreter_cases"]] == selected,
            "bounded C++ owner interpreter denominator changed")
    require(strict_equal(json.loads((directory / "cpp_owned/cases.json").read_text()), vectors),
            "retained C++ native cases differ from the frozen source oracle")
    for index in selected:
        row = vectors[index]
        plans.append({"family": "cpp_byte_owner", "case_index": index,
                      "program_path": str(directory / "cpp_owned/owned.hia.json"),
                      "entry": "owned_case",
                      "arguments": [row[k] for k in ("size", "value", "index", "reject", "early")],
                      "allocation_fail_at": 1 if row["refuse"] else None, "expected": row["expected"],
                      # The native owned harness reports an aggregate over all
                      # vectors, not fabricated per-case stdout. Its validator
                      # checks the full digest, cases and allocation totals.
                      "native_corpus_case": row})
    denominators = {
        "c_multi_owner_native_cases_per_implementation": len(_cases()),
        "cpp_scalar_class_native_cases_per_implementation": len(native["cpp_class_cases"]),
        "cpp_byte_owner_native_cases_per_implementation": len(vectors),
        "cpp_byte_owner_python_rust_cases": len(selected),
        "cpp_byte_owner_python_rust_selection": "size <= 17",
        "total_native_result_executions": 2 * (len(_cases()) + len(native["cpp_class_cases"]) + len(vectors)),
        "total_python_rust_pairs": len(plans),
    }
    require(native["native_result_executions"] == denominators["total_native_result_executions"],
            "native execution denominator differs")
    return plans, denominators


def _compare(plan, python, rust, core):
    require(rust.get("schema") == "hepta.hia.rust-byte-owner-execution.v1"
            and rust.get("profile") == "bounded-cfg-byte-owner-v2"
            and rust.get("program_sha256") == core.sha256
            and python.get("program_sha256") == core.sha256,
            "execution profile or Core identity differs")
    for field in ("status", "steps", "values", "resources"):
        require(strict_equal(rust.get(field), python.get(field)), "Rust/Python mismatch: " + field)
    require(python["status"] == "returned" and strict_equal(python["values"], [plan["expected"]]),
            "migration execution differs from native corpus expected value")
    resources = python["resources"]
    require(resources["live_owners"] == resources["live_local_loans"] == resources["live_bytes"] == 0,
            "successful migrated program retained resources")
    require(rust["claims"]["production_admission_authorized"] is False
            and rust["claims"]["native_backend_refinement_proved"] is False,
            "Rust result claims unqualified authority")
    if plan["family"] == "c_multi_owner":
        observed = {"result": plan["expected"], "attempts": resources["allocation_attempts"],
                    "allocations": resources["allocations"], "frees": resources["frees"], "live": 0}
        require(strict_equal(plan["native_observation"], {"original_c": observed, "standalone_hia": observed}),
                "C native allocator/value observations differ from the independent VMs")
    elif plan["family"] == "cpp_byte_owner":
        row = plan["native_corpus_case"]
        require(resources["allocations"] == resources["frees"] == row["allocated"]
                and resources["allocation_attempts"] == row["allocated"] + row["refusals"],
                "C++ owned native corpus allocation/refusal totals differ")


def validate_report(report):
    require(report.get("schema") == "hepta.hia.rust-migration-qualification.v1"
            and report.get("ok") is True and report.get("status") == "finite_migration_rust_native_parity_passed",
            "completed Rust migration report required")
    require(strict_equal(report["claims"], CLAIMS), "unsupported migration/Rust qualification claim")
    require(report["source_before"] == report["source_after"]
            and all(digest(ROOT / path) == value for path, value in report["source_before"].items()),
            "qualification source identity changed")
    receipt = report["native_report"]
    require(digest(receipt["path"]) == receipt["sha256"], "native migration report identity changed")
    native_path = Path(receipt["path"])
    native = json.loads(native_path.read_text())
    plans, denominators = _plans(native, native_path.parent)
    require(strict_equal(report["denominators"], denominators), "native/interpreter denominator relabelled")
    require(len(report["observations"]) == len(plans), "missing or additional migration parity case")
    binary = report["rust_binary"]
    require(digest(binary["path"]) == binary["sha256"], "Rust binary identity changed")
    for row, plan in zip(report["observations"], plans):
        require(strict_equal(row["case"], plan), "migration case or native relation changed")
        core = verify_program(Path(plan["program_path"]).read_bytes())
        require(strict_equal(report["programs_by_sha256"][core.sha256], core.as_dict()),
                "retained Core program differs")
        process = row["process"]
        expected_argv = [binary["path"], "--owned-run", plan["entry"],
                         json.dumps(plan["arguments"], separators=(",", ":")), str(POLICY["max_steps"]),
                         str(POLICY["max_heap_bytes"]), str(plan["allocation_fail_at"] or "none")]
        require(process["argv"] == expected_argv and process["returncode"] == 0
                and process["stderr"] == "" and process["stdin_sha256"] == core.sha256
                and strict_equal(json.loads(process["stdout"]), row["rust"]),
                "actual Rust process evidence differs from the declared execution")
        python = execute_program(core, plan["entry"], plan["arguments"], **POLICY,
                                 allocation_fail_at=plan["allocation_fail_at"])
        require(strict_equal(python, row["python"]), "Python migration execution cannot be replayed")
        _compare(plan, python, row["rust"], core)


def qualify(workdir, *, clang="clang", clangxx="clang++", cc="gcc", cxx="g++"):
    directory = Path(workdir).absolute()
    directory.mkdir(parents=True, exist_ok=False)
    report = {"schema": "hepta.hia.rust-migration-qualification.v1", "ok": False,
              "status": "in_progress", "started_utc": datetime.now(timezone.utc).isoformat(),
              "source_before": inventory(), "observations": [], "programs_by_sha256": {}}
    try:
        native = qualify_native(directory / "native", clang=clang, clangxx=clangxx, cc=cc, cxx=cxx)
        report["native_report"] = {"path": str(directory / "native/qualification.json"),
                                   "sha256": digest(directory / "native/qualification.json")}
        plans, denominators = _plans(native, directory / "native")
        report["denominators"] = denominators
        build = _process(["cargo", "build", "--locked", "--offline", "--message-format=json",
                          "--manifest-path", ROOT / "rust/hia-core-shadow/Cargo.toml"], timeout=240)
        report["rust_build_process"] = build
        require(build["returncode"] == 0, "Rust migration oracle build failed: " + build["stderr"][-2000:])
        binaries = [row["executable"] for line in build["stdout"].splitlines()
                    if (row := json.loads(line)).get("reason") == "compiler-artifact"
                    and row.get("executable") and "bin" in row.get("target", {}).get("kind", [])]
        require(len(binaries) == 1, "Cargo must identify exactly one Rust binary")
        report["rust_binary"] = {"path": binaries[0], "sha256": digest(binaries[0])}
        for plan in plans:
            core = verify_program(Path(plan["program_path"]).read_bytes())
            report["programs_by_sha256"][core.sha256] = core.as_dict()
            python = execute_program(core, plan["entry"], plan["arguments"], **POLICY,
                                     allocation_fail_at=plan["allocation_fail_at"])
            argv = [binaries[0], "--owned-run", plan["entry"],
                    json.dumps(plan["arguments"], separators=(",", ":")), str(POLICY["max_steps"]),
                    str(POLICY["max_heap_bytes"]), str(plan["allocation_fail_at"] or "none")]
            process = _process(argv, stdin=core.canonical_bytes.decode())
            row = {"case": plan, "python": python, "process": process}
            report["observations"].append(row)
            require(process["returncode"] == 0, "Rust rejected actual migrated Core: " + process["stderr"])
            row["rust"] = json.loads(process["stdout"])
            _compare(plan, python, row["rust"], core)
        report["source_after"] = inventory()
        report.update(ok=True, status="finite_migration_rust_native_parity_passed", claims=CLAIMS)
        validate_report(report)
    except Exception as error:
        report.update(ok=False, status="finite_migration_rust_native_parity_not_qualified",
                      diagnostic={"type": type(error).__name__, "message": str(error)})
    report["finished_utc"] = datetime.now(timezone.utc).isoformat()
    (directory / "qualification.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workdir", required=True, type=Path)
    for name, default in (("clang", "clang"), ("clangxx", "clang++"), ("cc", "gcc"), ("cxx", "g++")):
        parser.add_argument("--" + name, default=os.environ.get(name.upper(), default))
    args = parser.parse_args(argv)
    report = qualify(args.workdir, clang=args.clang, clangxx=args.clangxx, cc=args.cc, cxx=args.cxx)
    print(json.dumps({key: report[key] for key in ("ok", "status", "denominators", "diagnostic") if key in report}, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
