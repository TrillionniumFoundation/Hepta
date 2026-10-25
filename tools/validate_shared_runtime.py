"""Qualify two-group selection and explicit shared task reservations.

Runs source programs and separate native concurrency/fault controls against the
exact generated runtime. The Linux pthread interposer refuses one real native
spawn; it is not linked into production binaries. No fixture fallback exists.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hepta.backend import GROUP_RUNTIME, TASK_RUNTIME, compile_rust, find_rustc, toolchain_info
from hepta.pipeline import analyze, compiler_hash

SCENARIOS = {
    "select_pipeline": {"left_received": 128, "right_received": 128, "sum": 19328, "active_after_join": 0},
    "shared_budget": {"peak_threads": 2, "peak_input_bytes": 12, "peak_queue_slots": 5,
                      "peak_requested_stack_bytes": 131072, "reserved_threads_after_children_join": 0,
                      "admission_refusals": 1, "attachment_refusals": 1},
}
CONTROLS = {
    "ready_closed_and_identity_cases": 6, "registration_refusals": 2,
    "registration_send_races": 128, "spurious_deadline_cases": 2,
    "failure_wakeup_cases": 1, "independent_budget_bound_cases": 3,
    "concurrent_budget_races": 64, "actual_spawn_or_handle_refusals": 2,
    "post_refusal_recovery_spawns": 2, "remaining_pool_reservations": 0,
}
CLAIMS = {
    "whole_process_resources_bounded": False, "actual_os_stack_bytes_measured": False,
    "worker_termination_proved": False, "structured_task_tree_qualified_by_this_report": False,
    "arbitrary_select_arity_implemented": False, "source_to_runtime_refinement_proved": False,
}
SOURCE_FILES = ["hepta/runtime_concurrency.py", "tools/validate_shared_runtime.py",
                "tools/fixtures/shared_runtime_controls.rs", "tools/fixtures/shared_runtime_faults.c",
                *[f"examples/groups/{name}.hepta" for name in SCENARIOS]]


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def identities() -> dict:
    return {name: digest((ROOT / name).read_bytes()) for name in SOURCE_FILES}


def native_controls_source() -> str:
    return "#![allow(dead_code,unused)]\n" + TASK_RUNTIME + GROUP_RUNTIME + (ROOT / SOURCE_FILES[2]).read_text()


def executions(executable: Path, expected: dict, repeats: int) -> list[dict]:
    records = []
    for number in range(repeats):
        start = time.monotonic_ns()
        proc = subprocess.run([str(executable)], capture_output=True, text=True, timeout=30)
        elapsed = time.monotonic_ns() - start
        if proc.returncode != 0 or proc.stderr:
            raise RuntimeError(f"native execution failed: {proc.returncode}: {proc.stderr}")
        values = proc.stdout.splitlines()
        if len(values) != len(expected) or any(re.fullmatch(r"[0-9]+", value) is None for value in values):
            raise RuntimeError("unexpected runtime output: " + repr(proc.stdout))
        measured = dict(zip(expected, map(int, values)))
        if measured != expected:
            raise RuntimeError(f"runtime observations differ: {measured!r}")
        records.append({"trial": number, "returncode": proc.returncode, "elapsed_ns": elapsed,
                        "stdout": proc.stdout, "stdout_sha256": digest(proc.stdout.encode()),
                        "stderr_sha256": digest(proc.stderr.encode()), "metrics": measured})
    return records


def run_qualification(*, rustc: str | None = None, cc: str | None = None, repeats: int = 3) -> dict:
    if type(repeats) is not int or not 1 <= repeats <= 20:
        raise ValueError("repeats must be 1..20")
    if platform.system() != "Linux":
        raise RuntimeError("the pthread boundary qualification requires a real Linux host")
    rustc = find_rustc(rustc)
    cc = shutil.which(cc or "gcc")
    if not cc:
        raise RuntimeError("a native GCC-compatible compiler is required")
    source_before = identities()
    compiler_before = compiler_hash()
    report = {"schema": "hepta.shared-runtime.evidence.v1", "status": "passed",
              "created_utc": datetime.now(timezone.utc).isoformat(),
              "compiler_sha256": compiler_before, "source_files": source_before,
              "host": {"system": platform.system(), "machine": platform.machine()},
              "toolchain": toolchain_info(rustc), "repeats": repeats,
              "claims": dict(CLAIMS), "source_cases": [],
              "limits": ["Selection has exactly two distinct sealed groups and explicit caller-selected priority.",
                         "Select registration is bounded at 64 concurrent calls per group; metadata remains allocated until group destruction.",
                         "A channel wait deadline does not bound mutex scheduling, worker lifetime, or join duration.",
                         "Only explicitly attached groups share reservations; completed threads retain reservations until join.",
                         "Input lengths and requested stack sizes are reservations, not measurements of live heap or OS stack mappings.",
                         "Unattached groups, worker/FFI allocations, presubmission buffers, metadata, RSS and CPU time are excluded.",
                         "Ordinary allocator abort and panic=abort remain process fatal."]}
    with tempfile.TemporaryDirectory(prefix="hepta-shared-runtime-") as directory:
        temporary = Path(directory)
        for name, expected in SCENARIOS.items():
            path = ROOT / f"examples/groups/{name}.hepta"
            analysis = analyze(path.read_text(), str(path), rustc=rustc, native=True, crate_type="bin")
            if not analysis.report["ok"]:
                raise RuntimeError(json.dumps(analysis.report))
            executable = temporary / name
            build = compile_rust(analysis.rust, rustc=rustc, crate_type="bin", output=executable)
            if not build["ok"]:
                raise RuntimeError(json.dumps(build))
            report["source_cases"].append({"name": name, "source": str(path.relative_to(ROOT)),
                                           "analysis": analysis.report, "build": build,
                                           "runs": executions(executable, expected, repeats)})
        obj = temporary / "faults.o"
        command = [cc, "-std=c11", "-O2", "-c", str(ROOT / SOURCE_FILES[3]), "-o", str(obj)]
        compiled = subprocess.run(command, capture_output=True, text=True, timeout=30)
        if compiled.returncode != 0 or not obj.is_file() or obj.stat().st_size == 0:
            raise RuntimeError("failed to build native boundary injector: " + compiled.stderr)
        c_build = {"returncode": compiled.returncode, "compiler": str(Path(cc).resolve()),
                   "version": subprocess.check_output([cc, "--version"], text=True).splitlines()[0],
                   "flags": ["-std=c11", "-O2"], "source_sha256": source_before[SOURCE_FILES[3]],
                   "object_sha256": digest(obj.read_bytes()), "object_bytes": obj.stat().st_size,
                   "stdout_sha256": digest(compiled.stdout.encode()), "stderr_sha256": digest(compiled.stderr.encode())}
        source = native_controls_source()
        executable = temporary / "controls"
        build = compile_rust(source, rustc=rustc, crate_type="bin", output=executable,
                             link_args=[str(obj), "-Wl,--wrap=pthread_create"])
        if not build["ok"]:
            raise RuntimeError(json.dumps(build))
        report["native_controls"] = {"source_sha256": digest(source.encode()), "c_build": c_build,
                                     "linked_object_sha256": c_build["object_sha256"],
                                     "build": build, "runs": executions(executable, CONTROLS, repeats)}
    if identities() != source_before or compiler_hash() != compiler_before:
        raise RuntimeError("source changed during qualification")
    validate_shared_runtime_report(report)
    return report


def validate_shared_runtime_report(report: dict, *, minimum_repeats: int = 1) -> None:
    """Check identities, executed denominators, builds and every recorded trial.

    This rejects malformed or claim-inflated reports. Hashes bind evidence to
    source; they are not signatures or a proof that arbitrary records are true.
    """
    def require(condition, message):
        if not condition:
            raise ValueError(message)

    def hash_(value):
        return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None

    def built(value, source_hash):
        require(isinstance(value, dict) and value.get("ok") is True and value.get("status") == "rustc_checked",
                "missing actual native build")
        require(value.get("check_only") is False and value.get("crate_type") == "bin", "metadata-only build")
        require(value.get("rust_sha256") == source_hash, "build/source mismatch")
        require(hash_(value.get("artifact_sha256")) and value["artifact_sha256"] == value.get("validation_artifact_sha256"),
                "missing or inconsistent executable identity")
        require(value.get("toolchain") == report.get("toolchain"), "toolchain mismatch")
        require(value.get("rustc_crate_type") == "bin" and value.get("target") == report["toolchain"]["host"],
                "native target/crate mismatch")
        require(isinstance(value.get("flags"), list) and all(flag in value["flags"] for flag in
                ("edition=2021", "opt-level=3", "overflow-checks=yes", "panic=abort", "codegen-units=1")),
                "native safety/optimization flags changed")

    def runs(values, expected):
        require(isinstance(values, list) and len(values) == report["repeats"], "incorrect trial denominator")
        for index, value in enumerate(values):
            require(isinstance(value, dict) and type(value.get("trial")) is int and value["trial"] == index,
                    "trial order/identity mismatch")
            require(type(value.get("returncode")) is int and value["returncode"] == 0, "execution failed or missing")
            require(type(value.get("elapsed_ns")) is int and value["elapsed_ns"] > 0, "invalid observed duration")
            require(value.get("metrics") == expected and all(type(x) is int for x in value["metrics"].values()),
                    "incorrect executed case count or runtime observation")
            stdout = "".join(f"{number}\n" for number in expected.values())
            require(value.get("stdout") == stdout and value.get("stdout_sha256") == digest(stdout.encode())
                    and value.get("stderr_sha256") == digest(b""), "execution transcript mismatch")

    require(isinstance(report, dict) and report.get("schema") == "hepta.shared-runtime.evidence.v1"
            and report.get("status") == "passed", "invalid shared runtime report")
    require(type(report.get("repeats")) is int and minimum_repeats <= report["repeats"] <= 20, "insufficient trials")
    require(report.get("compiler_sha256") == compiler_hash() and report.get("source_files") == identities(),
            "qualification source identity changed")
    require(report.get("claims") == CLAIMS and all(value is False for value in report["claims"].values()),
            "unsupported safety/coverage claim")
    require(isinstance(report.get("toolchain"), dict) and hash_(report["toolchain"].get("executable_sha256"))
            and isinstance(report["toolchain"].get("host"), str), "missing native toolchain identity")
    cases = report.get("source_cases")
    require(isinstance(cases, list) and all(isinstance(case, dict) for case in cases)
            and [case.get("name") for case in cases] == list(SCENARIOS), "missing/duplicate source cases")
    for case in cases:
        expected = SCENARIOS[case["name"]]
        path = f"examples/groups/{case['name']}.hepta"
        require(case.get("source") == path, "source case path mismatch")
        analysis = case.get("analysis", {})
        require(isinstance(analysis, dict), "invalid source analysis")
        require(analysis.get("ok") is True and analysis.get("compiler_sha256") == report["compiler_sha256"]
                and analysis.get("source_sha256") == report["source_files"][path], "unchecked source case")
        require(analysis.get("status") == "checked" and analysis.get("checks") == {
            "rust_borrows_types": "rustc_checked", "syntax": "passed", "types_effects_resources": "passed_in_supported_subset"},
            "source checking was incomplete")
        require(hash_(analysis.get("rust_sha256")), "missing lowered source identity")
        backend = analysis.get("backend", {})
        require(isinstance(backend, dict) and backend.get("ok") is True and backend.get("status") == "rustc_checked"
                and backend.get("check_only") is True and hash_(backend.get("validation_artifact_sha256"))
                and backend.get("rust_sha256") == analysis["rust_sha256"]
                and backend.get("toolchain") == report["toolchain"], "source native reference check missing")
        built(case.get("build"), analysis["rust_sha256"])
        runs(case.get("runs"), expected)
    controls = report.get("native_controls", {})
    require(isinstance(controls, dict), "invalid native control record")
    require(controls.get("source_sha256") == digest(native_controls_source().encode()), "native controls changed")
    built(controls.get("build"), controls["source_sha256"])
    c_build = controls.get("c_build", {})
    require(isinstance(c_build, dict), "invalid native injector build")
    require(type(c_build.get("returncode")) is int and c_build["returncode"] == 0
            and type(c_build.get("object_bytes")) is int and c_build["object_bytes"] > 0
            and hash_(c_build.get("object_sha256"))
            and controls.get("linked_object_sha256") == c_build.get("object_sha256")
            and c_build.get("source_sha256") == report["source_files"][SOURCE_FILES[3]], "native injector was not built")
    links = controls["build"].get("link_args")
    require(isinstance(links, list) and len(links) == 2 and isinstance(links[0], str)
            and links[0].endswith("/faults.o") and links[1] == "-Wl,--wrap=pthread_create", "native refusal boundary not linked")
    runs(controls.get("runs"), CONTROLS)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rustc", default=os.environ.get("RUSTC"))
    parser.add_argument("--cc")
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    report = run_qualification(rustc=args.rustc, cc=args.cc, repeats=args.repeats)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"status": report["status"], "source_cases": len(report["source_cases"]),
                      "native_control_groups": len(CONTROLS), "repeats": args.repeats,
                      "output": str(args.output)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
