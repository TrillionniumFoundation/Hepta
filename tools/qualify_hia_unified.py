#!/usr/bin/env python3
"""Run the integrated HIA gates against one unchanged, committed source tree.

An actual compiler/test/native run is required for every planned gate. The
collector records skips and failures and continues independent gates. Scoped
success never upgrades the seven-part research/production request to complete.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hepta.clang_capture import CaptureRejected, run_bounded
from hepta.pipeline import compiler_hash
from tools.release_check import _read_regular_evidence, require_collected_qualification, snapshot


# Reuse the existing producers' replay validators for imported native paths.
# A success-looking top-level flag is not sufficient for those structured
# migration, lifetime and task/I/O reports.
IMPORTED_QUALIFICATION_NAMES = {
    "cpp_composed_implementation_llvm": "cpp_composed_to_llvm",
    "llvm_local_stored_views": "llvm_local_stored_views",
    "task_io_composition": "task_io_composition",
    "bounded_concurrency": "bounded_concurrency",
    "shared_runtime": "shared_runtime",
    "independent_concurrent_ir": "independent_concurrent_ir",
    "structured_task_trees": "structured_task_trees",
    "bounded_async_io": "bounded_async_io",
    "native_host_gcc": "native_host_abi",
    "native_host_clang": "native_host_abi",
    "provenance_and_type_core": "provenance_and_type_core",
    "formal_core": "formal_core",
    "application_performance": "application_performance",
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def write_new(path, data):
    with path.open("xb") as stream:
        stream.write(data)


def _command(argv, timeout=1800):
    started = time.monotonic()
    try:
        value = run_bounded(list(map(str, argv)), timeout=timeout, stdin_limit=0,
                            stdout_limit=4 * 1024 * 1024, stderr_limit=8 * 1024 * 1024)
        return {"argv": list(map(str, argv)), "returncode": value.returncode,
                "stdout": value.stdout, "stderr": value.stderr,
                "seconds": time.monotonic() - started}
    except CaptureRejected as exc:
        partial = getattr(exc, "capture", None)
        stdout = partial.stdout.decode("utf-8", errors="replace") if partial is not None else ""
        stderr = partial.stderr.decode("utf-8", errors="replace") if partial is not None else ""
        return {"argv": list(map(str, argv)), "returncode": None,
                "stdout": stdout, "stderr": stderr + "\n" + str(exc),
                "capture_error": exc.code,
                "partial_capture": None if partial is None else {
                    "returncode": partial.returncode,
                    "stdout_total_bytes": partial.stdout_total_bytes,
                    "stderr_total_bytes": partial.stderr_total_bytes,
                    "stdout_retained_bytes": len(partial.stdout),
                    "stderr_retained_bytes": len(partial.stderr)},
                "seconds": time.monotonic() - started}


def unittest_outcome(stderr, returncode):
    """Retain failed-run counts without accepting partial or skipped runs."""
    match = re.search(
        r"(?m)^Ran ([0-9]+) tests? in [0-9.]+s\s+"
        r"(OK|FAILED)(?: \(([^\n]*)\))?\s*\Z", stderr)
    result = {"tests_run": None, "skipped": None, "failures": None,
              "errors": None, "passed": False}
    if match is None:
        return result
    result.update(tests_run=int(match.group(1)), skipped=0, failures=0, errors=0)
    details = match.group(3)
    if details:
        for item in details.split(", "):
            field = re.fullmatch(r"(skipped|failures|errors)=([0-9]+)", item)
            if field is None:
                # Expected/unexpected successes or a changed summary format
                # require an explicit policy before the aggregate can pass.
                return result
            result[field.group(1)] = int(field.group(2))
    result["passed"] = (returncode == 0 and match.group(2) == "OK"
                        and result["tests_run"] > 0
                        and result["skipped"] == 0
                        and result["failures"] == 0
                        and result["errors"] == 0)
    return result


def cargo_test_outcome(stdout, returncode):
    """Count actual lib/bin/doc test results; an empty or ignored run fails."""
    matches = list(re.finditer(
        r"(?m)^test result: (ok|FAILED)\. ([0-9]+) passed; ([0-9]+) failed; "
        r"([0-9]+) ignored; ([0-9]+) measured; ([0-9]+) filtered out; "
        r"finished in [0-9.]+s\s*$", stdout))
    result = {"tests_run": None, "skipped": None, "failures": None,
              "filtered_out": None, "measured": None, "test_binaries": len(matches),
              "passed": False}
    if not matches:
        return result
    passed, failed, ignored, measured, filtered = (
        sum(int(match.group(index)) for match in matches) for index in range(2, 7))
    result.update(tests_run=passed + failed, skipped=ignored, failures=failed,
                  filtered_out=filtered, measured=measured)
    result["passed"] = (returncode == 0 and passed > 0 and
                        failed == ignored == measured == filtered == 0 and
                        all(match.group(1) == "ok" for match in matches) and
                        not stdout[matches[-1].end():].strip())
    return result


def qualification_plan(output, *, python, clang, cc, rustc, cargo, qemu_aarch64,
                       qemu_riscv64, qemu_system_arm, linker, lean, cxx):
    """The complete declared candidate plan; no feature is selected by availability."""
    output = Path(output)
    return [
        ("unit_regression", [python, "-m", "unittest", "discover", "-s", "tests", "-q"], None),
        ("rust_shadow_cargo", [cargo, "test", "--locked", "--offline", "--manifest-path",
                               "rust/hia-core-shadow/Cargo.toml"], None),
        ("rust_shadow_parity", [python, "-m", "unittest",
                                "tests.test_hia_rust_shadow", "tests.test_hia_rust_owned_shadow",
                                "tests.test_hia_rust_calls_shadow", "tests.test_hia_rust_chain_shadow",
                                "tests.test_hia_rust_scalar_vm", "tests.test_hia_rust_crosscheck",
                                "tests.test_hia_rust_crosscheck_cli", "tests.test_hia_rust_owned_vm",
                                "tests.test_hia_rust_raw_integer", "tests.test_hia_rust_returned_loans",
                                "tests.test_hia_rust_returned_chains", "tests.test_hia_rust_owned_memory",
                                "-v"], None),
        ("agent_query_semantics", [python, "-m", "unittest",
                                   "tests.test_hia_edit_query", "tests.test_hia_edit_batch",
                                   "tests.test_hia_edit_transitive_context", "tests.test_hia_edit_cfg_context",
                                   "tests.test_hia_edit_control_context", "tests.test_hia_edit_batch_identity",
                                   "tests.test_hia_cfg_render_convergence", "tests.test_hia_context_render_input",
                                   "tests.test_hia_incremental", "tests.test_hia_incremental_independent",
                                   "tests.test_hia_incremental_v8",
                                   "-v"], None),
        ("standalone_native", [python, "tools/qualify_hia_program.py", "--clang", clang,
                               "--output", output / "native.json"], output / "native.json"),
        ("standalone_resources", [python, "tools/qualify_hia_program_resources.py",
                                  "--output", output / "resources.json"], output / "resources.json"),
        ("composite_resources", [python, "tools/qualify_hia_program_composite.py", "--clang", clang,
                                 "--workdir", output / "composite"], output / "composite/qualification.json"),
        ("partial_record_resources", [python, "tools/qualify_hia_partial_records.py", "--clang", clang,
                                      "--rust-vm", output / "rust-shadow-target/debug/hia-core-shadow",
                                      "--output-directory", output / "partial-records"], output / "partial-records/report.json"),
        ("composite_bulk_targets", [python, "tools/qualify_hia_composite_bulk.py", "--clang", clang,
                                    "--linker", linker, "--qemu-aarch64", qemu_aarch64,
                                    "--output-directory", output / "composite-bulk"], output / "composite-bulk/qualification.json"),
        ("recursive_resource_chains", [python, "tools/qualify_hia_recursive_chain.py", "--clang", clang,
                                       "--output-directory", output / "recursive-chain"], output / "recursive-chain/qualification.json"),
        ("source_migration", [python, "tools/qualify_hia_migration.py", "--clang", clang,
                              "--clangxx", str(Path(clang).with_name("clang++")),
                              "--workdir", output / "migration"], output / "migration/qualification.json"),
        ("cpp_template_migration", [python, "tools/qualify_cpp_project_hia.py", "--clang", clang,
                                   "--clangxx", str(Path(clang).with_name("clang++")),
                                   "--workdir", output / "cpp-templates"], output / "cpp-templates/qualification.json"),
        ("cpp_constexpr_migration", [python, "tools/qualify_cpp_constexpr.py", "--clang", clang,
                                    "--clangxx", str(Path(clang).with_name("clang++")),
                                    "--output-directory", output / "cpp-constexpr"], output / "cpp-constexpr/report.json"),
        ("c_configuration_matrix", [python, "tools/qualify_c_project_matrix.py", "--clang", clang,
                                    "--workdir", output / "c-matrix"], output / "c-matrix/qualification.json"),
        ("cpp_configuration_matrix", [python, "tools/qualify_cpp_project_matrix.py", "--clang", clang,
                                      "--clangxx", str(Path(clang).with_name("clang++")),
                                      "--workdir", output / "cpp-matrix"], output / "cpp-matrix/qualification.json"),
        ("upstream_c_resource_matrix", [python, "tools/qualify_c_resource_matrix.py", "--clang", clang,
                                       "--rustc", rustc, "--workdir", output / "c-resource-matrix"], output / "c-resource-matrix/qualification.json"),
        ("upstream_cpp_composed_lifetimes", [python, "tools/qualify_cpp_composed.py", "--cxx", cxx,
                                           "--rustc", rustc, "--workdir", output / "cpp-composed"], output / "cpp-composed/qualification.json"),
        ("cpp_composed_implementation_llvm", [python, "tools/qualify_cpp_composed_llvm.py",
                                             "--clang", clang, "--clangxx", str(Path(clang).with_name("clang++")),
                                             "--rustc", rustc, "--cc", cc,
                                             "--workdir", output / "cpp-composed-llvm",
                                             "--output", output / "cpp-composed-llvm.json"], output / "cpp-composed-llvm.json"),
        ("llvm_local_stored_views", [python, "tools/qualify_llvm_local_views.py", "--clang", clang,
                                    "--rustc", rustc, "--cc", cc,
                                    "--output", output / "llvm-local-views.json"], output / "llvm-local-views.json"),
        ("task_io_composition", [python, "tools/qualify_task_io.py", "--rustc", rustc,
                                 "--cc", cc, "--repeats", "3",
                                 "--output", output / "task-io.json"], output / "task-io.json"),
        ("selected_core_formal", [python, "tools/qualify_hia_selected_formal.py", "--lean", lean,
                                  "--clang", clang, "--output-directory", output / "selected-formal"], output / "selected-formal/qualification.json"),
        ("standalone_aarch64_qemu", [python, "tools/qualify_hia_program_aarch64.py", "--clang", clang,
                                   "--linker", linker, "--qemu-aarch64", qemu_aarch64,
                                   "--output", output / "aarch64.json"], output / "aarch64.json"),
        ("standalone_riscv64_qemu", [python, "tools/qualify_hia_riscv64.py", "--clang", clang,
                                    "--linker", linker,
                                    "--readobj", str(Path(clang).with_name("llvm-readobj")),
                                    "--qemu-riscv64", qemu_riscv64,
                                    "--output-directory", output / "riscv64"], output / "riscv64/qualification.json"),
        ("legacy_executable_core", [python, "-m", "hepta.executable_core_qualify", "--clang", clang,
                                    "--cc", cc, "--rustc", rustc,
                                    "--report", output / "legacy-core.json"], output / "legacy-core.json"),
        ("legacy_hosted_composition", [python, "-m", "tools.qualify_lifecycle_composition",
                                       "--rustc", rustc, "--output", output / "hosted-composition.json"], output / "hosted-composition.json"),
        ("legacy_cortex_m4_qemu", [python, "tools/validate_board.py", "--rustc", rustc,
                                   "--qemu", qemu_system_arm, "--output", output / "board.json"], output / "board.json"),
        ("bounded_concurrency", [python, "tools/validate_groups.py", "--rustc", rustc,
                                 "--repeats", "3", "--output", output / "groups.json"], output / "groups.json"),
        ("shared_runtime", [python, "tools/validate_shared_runtime.py", "--rustc", rustc,
                            "--cc", cc, "--repeats", "3",
                            "--output", output / "shared-runtime.json"], output / "shared-runtime.json"),
        ("independent_concurrent_ir", [python, "tools/validate_concurrent_ir.py",
                                      "--output", output / "concurrent-ir.json"], output / "concurrent-ir.json"),
        ("structured_task_trees", [python, "tools/validate_task_tree.py", "--rustc", rustc,
                                   "--cc", cc, "--repeats", "3",
                                   "--output", output / "task-trees.json"], output / "task-trees.json"),
        ("bounded_async_io", [python, "tools/validate_io.py", "--rustc", rustc,
                              "--cc", cc, "--repeats", "3",
                              "--output", output / "async-io.json"], output / "async-io.json"),
        ("native_host_gcc", [python, "tools/validate_native_host.py", "--rustc", rustc,
                             "--cc", cc, "--cc-family", "gcc",
                             "--expected-system", "Linux", "--expected-machine", "x86_64",
                             "--output", output / "native-host-gcc.json"], output / "native-host-gcc.json"),
        ("native_host_clang", [python, "tools/validate_native_host.py", "--rustc", rustc,
                               "--cc", clang, "--cc-family", "clang",
                               "--expected-system", "Linux", "--expected-machine", "x86_64",
                               "--output", output / "native-host-clang.json"], output / "native-host-clang.json"),
        ("provenance_and_type_core", [python, "tools/verify_memory.py", "--lean", lean,
                                      "--output", output / "memory-proofs.json"], output / "memory-proofs.json"),
        ("formal_core", [python, "tools/verify_formal.py", "--lean", lean,
                         "--output", output / "formal-core.json"], output / "formal-core.json"),
        # Timed gates run last, after compiler/hosted/formal correctness work.
        # Application requests are sequential ABI calls, not network SLOs.
        ("application_performance", [python, "tools/benchmark_applications.py", "--rustc", rustc,
                                     "--cc", cc, "--trials", "3", "--requests", "96", "--warmups", "16",
                                     "--output", output / "applications.json"], output / "applications.json"),
        ("standalone_performance", [python, "tools/qualify_hia_program_perf.py", "--clang", clang,
                                    "--rustc", rustc, "--output", output / "performance.json",
                                    "--artifact-directory", output / "performance-artifacts"], output / "performance.json"),
    ]


def qualify(output, *, clang, cc, rustc, cargo, qemu_aarch64, qemu_riscv64,
            qemu_system_arm, linker, lean, cxx, unit_timeout_seconds=1800):
    if type(unit_timeout_seconds) is not int or not 1 <= unit_timeout_seconds <= 3600:
        raise ValueError("unit timeout must be an integer in 1..3600 seconds")
    output = Path(output).absolute()
    if output.exists() or output.is_symlink():
        raise ValueError("output directory must be new")
    before = snapshot()
    commit = _command(["git", "-C", ROOT, "rev-parse", "HEAD"], 10)
    dirty = _command(["git", "-C", ROOT, "status", "--porcelain", "--untracked-files=no"], 10)
    if commit["returncode"] != 0 or dirty["returncode"] != 0 or dirty["stdout"].strip():
        raise ValueError("commit tracked implementation before running the qualification")
    output.mkdir(parents=True)
    plan = qualification_plan(output, python=sys.executable, clang=clang, cc=cc, rustc=rustc, cargo=cargo,
                              qemu_aarch64=qemu_aarch64, qemu_riscv64=qemu_riscv64,
                              qemu_system_arm=qemu_system_arm, linker=linker, lean=lean, cxx=cxx)
    report = {"schema": "hepta.hia.unified-qualification.v3", "git_commit": commit["stdout"].strip(),
        "compiler_tree_sha256": compiler_hash(), "source_snapshot_before": before,
        "temporary_directory": tempfile.gettempdir(),
        "unit_timeout_seconds": unit_timeout_seconds,
        "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "planned_gates": [name for name, _, _ in plan], "gates": [],
        "full_six_deliverables_complete": False,
        "full_seven_deliverables_complete": False,
        "scope_limits": ["Dynamic recursive buffer chains are admitted; general recursive heap ADTs, escaping stored loans and background scheduling/channels remain outside the current core",
            "C/C++ migration covers declared finite profiles, not arbitrary historical libraries",
            "The upstream C resource matrix uses safe Hepta/Rust lowering; the upstream C++ library study is a bridge, while a separate bounded composed-owner profile rewrites implementations to native LLVM",
            "Rust remains an opt-in shadow: verifier, scalar and finite single-block byte-owner parity do not qualify general resource execution or transfer production admission authority",
            "Hosted concurrency, task/I/O, ABI and formal profiles retain their own finite scopes and do not become standalone Core guarantees",
            "Application measurements are sequential in-process ABI requests, not an external network service or service-level objective",
            "C++ noexcept termination observations do not establish allocation-failure recovery",
            "QEMU is not physical hardware or device timing/protocol qualification",
            "Agent productivity and independent total development-cost improvement require their own qualified trials",
            "Whole-compiler soundness and Rust-wide performance superiority are unproved"]}
    write_new(output / "plan.json", (json.dumps({"git_commit": report["git_commit"],
        "source_snapshot_sha256": before["sha256"],
        "commands": [{"name": name, "argv": list(map(str, argv))} for name, argv, _ in plan]},
        indent=2, sort_keys=True) + "\n").encode())
    previous_cwd = Path.cwd()
    environment = {"RUSTC": rustc, "CLANG": clang, "HEPTA_CLANG": clang, "CC": cc, "LEAN": lean,
                   "HEPTA_LLD": linker,
                   "HEPTA_LLVM_READOBJ": str(Path(clang).with_name("llvm-readobj")),
                   "HEPTA_QEMU_AARCH64": qemu_aarch64, "HEPTA_QEMU_RISCV64": qemu_riscv64,
                   "CARGO_TARGET_DIR": str(output / "rust-shadow-target"),
                   "CARGO_NET_OFFLINE": "true", "PYTHONDONTWRITEBYTECODE": "1"}
    old_environment = {name: os.environ.get(name) for name in (*environment, "PATH")}
    try:
        os.chdir(ROOT)
        with tempfile.TemporaryDirectory(prefix="hepta-hia-gate-tools-") as directory:
            bin_dir = Path(directory)
            if Path(qemu_aarch64).is_file():
                (bin_dir / "qemu-aarch64").symlink_to(Path(qemu_aarch64).resolve())
            if Path(qemu_riscv64).is_file():
                (bin_dir / "qemu-riscv64").symlink_to(Path(qemu_riscv64).resolve())
            if Path(linker).is_file():
                (bin_dir / "ld.lld").symlink_to(Path(linker).resolve())
            if Path(cargo).is_file():
                (bin_dir / "cargo").symlink_to(Path(cargo).resolve())
            os.environ["PATH"] = os.pathsep.join([str(bin_dir), str(Path(clang).parent),
                                                  str(Path(rustc).parent), str(Path(lean).parent),
                                                  old_environment["PATH"] or ""])
            os.environ.update(environment)
            for name, argv, evidence in plan:
                print(json.dumps({"gate": name, "status": "running"}), flush=True)
                timeout = unit_timeout_seconds if name == "unit_regression" else 1800
                executed = _command(argv, timeout=timeout)
                row = {k: v for k, v in executed.items() if k not in {"stdout", "stderr"}}
                row["name"], row["passed"] = name, False
                row["timeout_seconds"] = timeout
                for channel in ("stdout", "stderr"):
                    raw = executed[channel].encode()
                    logfile = output / (name + "." + channel + ".log")
                    write_new(logfile, raw)
                    row[channel] = {"path": str(logfile.relative_to(output)), "sha256": sha(raw), "bytes": len(raw)}
                if name == "rust_shadow_cargo":
                    row.update(cargo_test_outcome(executed["stdout"], executed["returncode"]))
                elif evidence is None:
                    row.update(unittest_outcome(executed["stderr"], executed["returncode"]))
                elif evidence.is_file() and not evidence.is_symlink():
                    try:
                        raw, _ = _read_regular_evidence(evidence)
                        payload = json.loads(raw)
                        if type(payload) is not dict:
                            raise ValueError("gate evidence must be a JSON object")
                        row["evidence"] = {"path": str(evidence.relative_to(output)), "sha256": sha(raw),
                                           "status": payload.get("status"), "ok": payload.get("ok")}
                        if name == "partial_record_resources":
                            from tools.hia_semantic_gate_receipts import validate_partial_records
                            validate_partial_records(payload, evidence.parent)
                            scoped_ok = True
                        elif name == "cpp_constexpr_migration":
                            from tools.qualify_cpp_constexpr import validate_cpp_constexpr_receipt
                            validate_cpp_constexpr_receipt(payload)
                            scoped_ok = payload.get("ok") is True
                        elif name in IMPORTED_QUALIFICATION_NAMES:
                            # Existing producers have different success fields.
                            # Their shared validator owns that convention and
                            # the complete nested evidence requirements.
                            require_collected_qualification(IMPORTED_QUALIFICATION_NAMES[name], payload)
                            scoped_ok = True
                        else:
                            scoped_ok = payload.get("ok") is True or (name == "legacy_cortex_m4_qemu" and payload.get("status") == "passed")
                        row["passed"] = executed["returncode"] == 0 and scoped_ok
                    except (OSError, ValueError, TypeError, KeyError) as exc:
                        row["evidence_error"] = {"type": type(exc).__name__, "message": str(exc)}
                report["gates"].append(row)
                print(json.dumps({"gate": name, "passed": row["passed"], "seconds": row["seconds"],
                                  "returncode": row["returncode"]}), flush=True)
    finally:
        os.chdir(previous_cwd)
        for name, value in old_environment.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
    report["source_snapshot_after"] = snapshot()
    report["unchanged_source"] = before == report["source_snapshot_after"]
    report["completed_gates"] = len(report["gates"])
    report["passed_gates"] = sum(row["passed"] for row in report["gates"])
    report["ok"] = report["unchanged_source"] and report["completed_gates"] == len(plan) and all(row["passed"] for row in report["gates"])
    report["status"] = "all_scoped_gates_passed" if report["ok"] else "scoped_gates_not_all_qualified"
    report["finished_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    write_new(output / "qualification.json", (json.dumps(report, indent=2, sort_keys=True) + "\n").encode())
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-directory", required=True)
    parser.add_argument("--clang", default=shutil.which("clang") or "clang")
    parser.add_argument("--cc", default=shutil.which("gcc") or "gcc")
    parser.add_argument("--rustc", default=os.environ.get("RUSTC") or shutil.which("rustc") or "rustc")
    parser.add_argument("--cargo", default=os.environ.get("CARGO") or shutil.which("cargo") or "cargo")
    parser.add_argument("--qemu-aarch64", required=True)
    parser.add_argument("--qemu-riscv64", required=True)
    parser.add_argument("--qemu-system-arm", default=shutil.which("qemu-system-arm") or "qemu-system-arm")
    parser.add_argument("--linker", required=True)
    parser.add_argument("--lean", required=True)
    parser.add_argument("--cxx", default=shutil.which("g++") or "g++")
    parser.add_argument("--unit-timeout-seconds", type=int, default=1800,
                        help="full unit regression timeout, in 1..3600 seconds")
    args = parser.parse_args()
    if not 1 <= args.unit_timeout_seconds <= 3600:
        parser.error("--unit-timeout-seconds must be in 1..3600")
    result = qualify(args.output_directory, clang=args.clang, cc=args.cc, rustc=args.rustc, cargo=args.cargo,
                     qemu_aarch64=args.qemu_aarch64, qemu_riscv64=args.qemu_riscv64,
                     qemu_system_arm=args.qemu_system_arm, linker=args.linker, lean=args.lean,
                     cxx=args.cxx, unit_timeout_seconds=args.unit_timeout_seconds)
    print(json.dumps({key: result[key] for key in ("ok", "status", "passed_gates", "completed_gates", "unchanged_source", "full_seven_deliverables_complete")}))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
