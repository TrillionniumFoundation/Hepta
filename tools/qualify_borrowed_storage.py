"""Run real Rust view/owner checks; never execute a rejected lifetime candidate."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hepta.backend import compile_rust, find_rustc, toolchain_info
from hepta.pipeline import analyze, analyze_project, compiler_hash, concurrent_ir_analysis, resource_ir_analysis
from hepta.source_map import map_diagnostics
from tools.borrowed_storage_cases import FRONTEND_REJECTIONS, NATIVE_REJECTIONS, POSITIVES
from tools.evidence_checks import is_sha, native_build, normalized_errors, require, sha, strict_equal, text

SCHEMA = "hepta.borrowed-storage-qualification.v1"
ENTRY = ROOT / "examples/borrowed_storage/main.hepta"
SOURCES = ("examples/borrowed_storage/library.hepta", "examples/borrowed_storage/main.hepta",
           "tools/borrowed_storage_cases.py", "tools/qualify_borrowed_storage.py")
CLAIMS = {"actual_valid_native_programs_executed": True, "actual_rust_lifetime_rejections_checked": True,
          "rejected_candidates_executed": False, "frontend_independently_proves_lifetimes": False,
          "stored_borrow_resource_ir_supported": False, "stored_borrow_c_backend_supported": False,
          "general_lifetimes_or_traits_complete": False, "compiler_refinement_proved": False,
          "performance_superiority_measured": False}
SCOPE = {"syntax": "at_most_eight_named_lifetimes_on_records_and_functions_without_outlives_or_type_parameter_mixing",
         "shared": "Copy_records_preserve_Rust_referent_lifetime_and_alias_checks",
         "mutable": "affine_record_values_require_explicit_move_and_consumption_no_owning_payload_mixture",
         "verification": "structural_Hepta_check_then_mandatory_pinned_Rust_region_and_alias_check",
         "unsupported": ["standalone_stored_reference_values", "self_referential_owners", "stored_borrow_enum_payloads",
                         "stored_borrow_array_or_generic_arguments", "raw_or_C_ABI_view_layout", "higher_ranked_lifetimes", "user_traits"],
         "negative_execution": "rustc_metadata_checks_only_no_rejected_candidate_linking_or_execution"}
CHECK_FLAGS = ["--edition=2021", "--crate-name=hepta_storage_candidate", "--crate-type=lib",
               "--emit=metadata", "-C", "opt-level=0", "-C", "overflow-checks=yes", "-C", "panic=abort", "--error-format=json"]


def identities():
    return {path: sha((ROOT / path).read_bytes()) for path in SOURCES}


def native_diagnostics(stderr, generated, generated_path):
    diagnostics = []
    for line in stderr.splitlines():
        item = json.loads(line)
        if item.get("level") == "error":
            diagnostics.append({"code": (item.get("code") or {}).get("code", "E_RUSTC"),
                                "message": item["message"], "phase": "backend", "rendered": item.get("rendered"),
                                "generated_spans": item.get("spans", [])})
    return map_diagnostics(generated, diagnostics, generated_path=generated_path)


def _analysis(name, directory, *, native=False, rustc=None):
    if name == "multifile_library":
        return analyze_project(ENTRY, native=native, rustc=rustc, crate_type="bin")
    source = POSITIVES[name]
    return analyze(source, str(directory / (name + ".hepta")), native=native, rustc=rustc, crate_type="bin")


def qualify(output, *, rustc=None):
    output = Path(output).resolve()
    directory = output.with_name(output.stem + ".files")
    if output.exists() or directory.exists():
        raise ValueError("Use a fresh report and artifact directory; earlier attempts are immutable")
    directory.mkdir(parents=True)
    report = {"schema": SCHEMA, "status": "running", "started_utc": datetime.now(timezone.utc).isoformat(),
              "compiler_sha256": compiler_hash(), "sources": identities(), "artifact_directory": str(directory),
              "claims": dict(CLAIMS), "scope": dict(SCOPE), "positives": [], "native_rejections": [],
              "frontend_rejections": [], "unsupported_profiles": {}}
    try:
        compiler = find_rustc(rustc)
        report["rust_toolchain"] = toolchain_info(compiler)
        for name in ("multifile_library", *POSITIVES):
            if name in POSITIVES:
                (directory / (name + ".hepta")).write_text(POSITIVES[name])
            analysis = _analysis(name, directory, native=True, rustc=compiler)
            require(analysis.report["ok"] is True, f"valid view program rejected: {name}: {analysis.report}")
            source = directory / (name + ".rs")
            source.write_text(analysis.rust)
            artifact = directory / name
            built = compile_rust(analysis.rust, rustc=compiler, crate_type="bin", output=artifact)
            require(built["ok"] is True, f"valid view program did not build: {name}")
            started = time.monotonic_ns()
            process = subprocess.run([str(artifact)], capture_output=True, text=True, timeout=10)
            row = {"name": name, "frontend": analysis.report, "generated_source": analysis.rust,
                   "generated_source_sha256": sha(analysis.rust.encode()), "build": built,
                   "execution": {"argv": [str(artifact)], "returncode": process.returncode,
                                 "elapsed_ns": time.monotonic_ns() - started, "stdout": process.stdout, "stderr": process.stderr,
                                 "stdout_sha256": sha(process.stdout.encode()), "stderr_sha256": sha(process.stderr.encode())}}
            report["positives"].append(row)
            require(process.returncode == 0 and process.stdout == ("275\n" if name == "multifile_library" else "") and not process.stderr,
                    f"valid program violated its actual runtime assertions: {name}")
        for name, (source_text, expected) in NATIVE_REJECTIONS.items():
            source = directory / (name + ".hepta")
            source.write_text(source_text)
            frontend = analyze(source_text, str(source), native=False, crate_type="bin")
            require(frontend.report["ok"] is True, f"negative case no longer reaches native lifetime checking: {name}")
            generated = directory / (name + ".rs")
            generated.write_text(frontend.rust)
            metadata = directory / (name + ".rmeta")
            command = [compiler, str(generated), *CHECK_FLAGS, "-o", str(metadata)]
            started = time.monotonic_ns()
            process = subprocess.run(command, capture_output=True, text=True, timeout=30)
            row = {"name": name, "source_path": str(source), "source_sha256": sha(source_text.encode()),
                   "frontend": frontend.report, "generated_source": frontend.rust, "generated_source_sha256": sha(frontend.rust.encode()),
                   "native_execution_attempted": False,
                   "native_check": {"argv": command, "returncode": process.returncode, "elapsed_ns": time.monotonic_ns() - started,
                                    "stdout": process.stdout, "stderr": process.stderr, "stdout_sha256": sha(process.stdout.encode()),
                                    "stderr_sha256": sha(process.stderr.encode()), "metadata_emitted": metadata.exists()},
                   "diagnostics": native_diagnostics(process.stderr, frontend.rust, str(generated))}
            report["native_rejections"].append(row)
            require(process.returncode != 0 and expected.intersection(d["code"] for d in row["diagnostics"]),
                    f"native lifetime candidate was not rejected as required: {name}")
        for name, (source, expected) in FRONTEND_REJECTIONS.items():
            path = directory / (name + ".hepta")
            path.write_text(source)
            analysis = analyze(source, str(path), native=False, crate_type="bin")
            report["frontend_rejections"].append({"name": name, "source_sha256": sha(source.encode()), "frontend": analysis.report})
            require(analysis.report["ok"] is False and expected in {d["code"] for d in analysis.report["diagnostics"]},
                    f"unsupported or affine misuse case was not rejected: {name}")
        frontend = analyze_project(ENTRY, native=False, crate_type="bin")
        report["unsupported_profiles"] = {"c": analyze_project(ENTRY, native=False, backend="c", crate_type="bin").report,
                                           "resource_ir": resource_ir_analysis(frontend), "concurrent_ir": concurrent_ir_analysis(frontend)}
        require(report["sources"] == identities() and report["compiler_sha256"] == compiler_hash(), "source changed during qualification")
        require(report["rust_toolchain"] == toolchain_info(compiler), "native toolchain changed during qualification")
        report["status"] = "passed"
        validate_borrowed_storage_report(report)
    except Exception as error:
        report["status"] = "failed"
        report["error"] = type(error).__name__ + ": " + str(error)
    report["completed_utc"] = datetime.now(timezone.utc).isoformat()
    with output.open("x") as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")
    return report


@normalized_errors
def validate_borrowed_storage_report(report):
    require(isinstance(report, dict) and report.get("schema") == SCHEMA and report.get("status") == "passed", "not a passing borrowed-record qualification")
    fields = {"schema", "status", "started_utc", "compiler_sha256", "sources", "artifact_directory", "claims", "scope",
              "positives", "native_rejections", "frontend_rejections", "unsupported_profiles", "rust_toolchain"}
    require(set(report) in (fields, fields | {"completed_utc"}), "unexpected borrowed-record report fields")
    require(text(report.get("started_utc")) and ("completed_utc" not in report or text(report["completed_utc"])), "qualification time missing")
    require(report.get("compiler_sha256") == compiler_hash() and strict_equal(report.get("sources"), identities()), "source/compiler identity changed")
    require(strict_equal(report.get("claims"), CLAIMS) and strict_equal(report.get("scope"), SCOPE), "borrowed-record proof/backend scope changed")
    require(text(report.get("artifact_directory")) and Path(report["artifact_directory"]).is_absolute(), "artifact location missing")
    directory = Path(report["artifact_directory"])
    toolchain = report.get("rust_toolchain", {})
    require(text(toolchain.get("path")) and text(toolchain.get("host")) and toolchain.get("version", "").startswith("rustc 1.90.0 ")
            and "release: 1.90.0" in toolchain["version"].splitlines()
            and is_sha(toolchain.get("executable_sha256")), "pinned native Rust identity missing")
    positive = report.get("positives", [])
    require(isinstance(positive, list) and [r.get("name") for r in positive] == ["multifile_library", *POSITIVES], "positive execution denominator")
    for row in positive:
        name = row["name"]
        expected = _analysis(name, directory)
        require(expected.report["ok"] and row.get("generated_source") == expected.rust
                and row.get("generated_source_sha256") == sha(expected.rust.encode()), "positive body differs from current checked source")
        frontend = row.get("frontend", {})
        require(set(frontend) == set(expected.report) | {"backend"}, "unexpected positive frontend fields")
        for key in ("schema", "compiler_version", "path", "source_sha256", "compiler_sha256", "interface_sha256", "rust_sha256", "effects", "assumptions", "resource_contracts", "profile", "project", "claims"):
            require(strict_equal(frontend.get(key), expected.report.get(key)), "positive frontend identity/scope mismatch: " + key)
        require(frontend.get("ok") is True and frontend.get("status") == "checked" and frontend.get("diagnostics") == []
                and strict_equal(frontend.get("checks"), dict(expected.report["checks"], rust_borrows_types="rustc_checked")), "positive native borrow validation did not run")
        storage = dict(expected.report["borrowed_storage"], native_lifetimes_checked=True)
        require(strict_equal(frontend.get("borrowed_storage"), storage), "native lifecycle qualification was inflated or omitted")
        native_build(frontend.get("backend"), "rust", check_only=True, crate_type="bin", source_sha256=row["generated_source_sha256"])
        native_build(row.get("build"), "rust", check_only=False, crate_type="bin", source_sha256=row["generated_source_sha256"])
        require(strict_equal(frontend["backend"]["toolchain"], toolchain) and strict_equal(row["build"]["toolchain"], toolchain), "different native checker/build toolchains")
        require(frontend["backend"]["target"] == row["build"]["target"] == toolchain["host"]
                and strict_equal(frontend["backend"]["flags"], row["build"]["flags"]), "native checker/build host or flags differ")
        require(row["build"]["artifact"] == str(directory / name)
                and {"overflow-checks=yes", "panic=abort", "edition=2021"} <= set(row["build"]["flags"]), "native artifact/profile differs")
        run = row.get("execution", {})
        require(run.get("argv") == [str(directory / name)] and type(run.get("returncode")) is int and run["returncode"] == 0
                and type(run.get("elapsed_ns")) is int and run["elapsed_ns"] > 0, "positive native program was not executed")
        require(run.get("stdout") == ("275\n" if name == "multifile_library" else "") and run.get("stderr") == ""
                and run.get("stdout_sha256") == sha(run["stdout"].encode()) and run.get("stderr_sha256") == sha(b""), "positive native result changed")
    negative = report.get("native_rejections", [])
    require(isinstance(negative, list) and [r.get("name") for r in negative] == list(NATIVE_REJECTIONS), "native rejection denominator")
    for row in negative:
        name = row["name"]
        source, codes = NATIVE_REJECTIONS[name]
        path, generated, metadata = (directory / (name + suffix) for suffix in (".hepta", ".rs", ".rmeta"))
        frontend = analyze(source, str(path), native=False, crate_type="bin")
        require(frontend.report["ok"] is True and strict_equal(row.get("frontend"), frontend.report), "negative did not reach the structural frontend boundary")
        require(row.get("source_path") == str(path) and row.get("source_sha256") == sha(source.encode())
                and row.get("generated_source") == frontend.rust and row.get("generated_source_sha256") == sha(frontend.rust.encode()), "negative source/lowering mismatch")
        check = row.get("native_check", {})
        require(check.get("argv") == [toolchain["path"], str(generated), *CHECK_FLAGS, "-o", str(metadata)]
                and type(check.get("returncode")) is int and check["returncode"] != 0
                and type(check.get("elapsed_ns")) is int and check["elapsed_ns"] > 0
                and check.get("metadata_emitted") is False and row.get("native_execution_attempted") is False, "negative native metadata-only check missing")
        require(check.get("stdout") == "" and text(check.get("stderr")) and check.get("stdout_sha256") == sha(b"")
                and check.get("stderr_sha256") == sha(check["stderr"].encode()), "native diagnostic transcript changed")
        actual = native_diagnostics(check["stderr"], frontend.rust, str(generated))
        require(strict_equal(row.get("diagnostics"), actual) and codes.intersection(d["code"] for d in actual), "native rejection diagnostics were not derived from rustc")
        require(any(mapping.get("is_primary") is True and mapping["span"]["path"] == str(path)
                    for diagnostic in actual for mapping in diagnostic.get("source_mappings", [])), "native lifetime error lacks source mapping")
        if name == "unrelated_lifetime_cannot_satisfy_return":
            require(any("lifetime may not live long enough" in diagnostic["message"] for diagnostic in actual), "unrelated regions did not reach lifetime checking")
    frontend_rows = report.get("frontend_rejections", [])
    require(isinstance(frontend_rows, list) and [r.get("name") for r in frontend_rows] == list(FRONTEND_REJECTIONS), "frontend rejection denominator")
    for row in frontend_rows:
        name = row["name"]
        source, code = FRONTEND_REJECTIONS[name]
        expected = analyze(source, str(directory / (name + ".hepta")), native=False, crate_type="bin")
        require(row.get("source_sha256") == sha(source.encode()) and strict_equal(row.get("frontend"), expected.report)
                and expected.report["ok"] is False and expected.rust is None
                and code in {d["code"] for d in expected.report["diagnostics"]}, "frontend rejected case differs")
    frontend = analyze_project(ENTRY, native=False, crate_type="bin")
    unsupported = {"c": analyze_project(ENTRY, native=False, backend="c", crate_type="bin").report,
                   "resource_ir": resource_ir_analysis(frontend), "concurrent_ir": concurrent_ir_analysis(frontend)}
    require(strict_equal(report.get("unsupported_profiles"), unsupported) and all(r["ok"] is False for r in unsupported.values()), "unsupported backend or resource IR was accepted")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--rustc", default=os.environ.get("RUSTC"))
    args = parser.parse_args()
    result = qualify(args.output, rustc=args.rustc)
    print(json.dumps({"status": result["status"], "positive_native_executions": len(result["positives"]),
                      "native_compile_rejections": len(result["native_rejections"]), "frontend_rejections": len(result["frontend_rejections"]),
                      "output": str(args.output), "error": result.get("error")}))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
