"""Replay bounded consuming task trees, real refusal paths and wrong runtimes.

Every launched command retains raw stdout/stderr, including aborts and timeout
partials. This is executable qualification, not a scheduling or refinement proof.
"""
from __future__ import annotations

import argparse
import base64
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
from hepta.backend import GROUP_RUNTIME, TASK_RUNTIME, find_rustc, toolchain_info
from hepta.concurrent_ir import verify_concurrent_ir
from hepta.pipeline import analyze, compiler_hash, concurrent_ir_analysis

SCENARIOS = {
    "tree_pipeline": {"groups": 4, "depth": 3, "joined_groups": 4, "completed_tasks": 4,
                      "discarded": 256, "sum": 16, "pool_threads_after_tree_join": 0},
    "tree_cancellation": {"groups": 3, "joined_groups": 3, "completed_tasks": 1,
                          "adoption_refusals": 1, "rejected_tasks": 1, "active_tasks": 0},
}
CONTROLS = {
    "interdependent_queue_tree": 1, "legacy_join_modes_wait_for_descendants": 3,
    "parent_cancel_wakes_descendants": 1, "failure_directions": 2,
    "actual_allocator_or_pthread_refusals": 2, "post_refusal_recoveries": 2,
    "topology_and_budget_boundaries": 7, "deterministic_adoption_failure_orders": 4,
    "adoption_failure_races": 128, "spawn_close_races": 64,
    "spurious_tree_notifications": 64, "failure_while_child_owner_taken_for_join": 1,
    "minimum_requested_stack_deep_failure": 1,
    "remaining_pool_reservations": 0,
}
PROFILE = {
    "backend": "hosted_native_Rust", "tree_groups": 256, "tree_depth": 16,
    "adoption": "consumes_actual_child_owner_and_descendants",
    "refusal": "consumes_cancels_and_joins_child_before_returning_false",
    "join": "all_legacy_and_tree_join_operations_wait_for_all_descendants",
    "budget": "identical_explicit_pool_or_all_unattached",
    "drain": "one_tree_condition_variable_all_queues_polled_on_each_wake",
    "cancellation": "cooperative_no_forced_worker_termination",
    "report": "flat_GroupReport_or_aggregate_GroupTreeReport",
}
CLAIMS = {
    "runtime_race_freedom_proved": False, "deadlock_freedom_proved": False,
    "bounded_cancellation_latency_proved": False, "arbitrary_worker_termination_proved": False,
    "source_to_runtime_refinement_proved": False, "whole_process_resources_bounded": False,
    "actual_OS_stack_bytes_measured": False, "C_backend_tree_support": False,
    "async_scheduler_or_worker_created_escaping_children_supported": False,
}
SOURCE_FILES = [
    "hepta/runtime_task_tree.py", "hepta/runtime_concurrency.py", "tools/validate_task_tree.py",
    "tools/fixtures/task_tree_controls.rs", "tools/fixtures/shared_runtime_faults.c",
    *[f"examples/groups/{name}.hepta" for name in SCENARIOS],
]
RUST_FLAGS = ["--edition=2021", "--crate-name=hepta_tree_qualification", "--crate-type=bin",
              "-C", "opt-level=3", "-C", "overflow-checks=yes", "-C", "panic=abort",
              "-C", "codegen-units=1"]
C_FLAGS = ["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def identities():
    return {name: digest((ROOT / name).read_bytes()) for name in SOURCE_FILES}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def native_controls_source():
    return "#![allow(dead_code,unused)]\n" + TASK_RUNTIME + GROUP_RUNTIME + (ROOT / SOURCE_FILES[3]).read_text()


def negative_sources():
    prefix = "#![allow(dead_code,unused)]\n" + TASK_RUNTIME
    simple = r'''
fn main() {
    let mut root=__hepta_group_new(0,0,1); let child=__hepta_group_new(0,0,1);
    let state=std::sync::Arc::clone(&child.shared);
    ACTION
}
'''
    def mutant(old, new, action):
        if GROUP_RUNTIME.count(old) != 1:
            raise ValueError("negative runtime mutation boundary changed")
        return prefix + GROUP_RUNTIME.replace(old, new, 1) + simple.replace("ACTION", action)
    return {
        "orphan_child_on_join": {
            "source": mutant("if let Some(mut child) = child { __hepta_tree_finish(&mut child); }",
                             "if let Some(child) = child { core::mem::forget(child); }",
                             'assert!(__hepta_group_adopt(&mut root,child)); let done=__hepta_group_tree_join(root,false); '
                             'assert!(done.h_joined_groups==2,"orphaned descendant detected");'),
            "expected": "nonzero", "diagnostic": "orphaned descendant detected", "timeout_seconds": 10,
        },
        "lost_descendant_cancellation": {
            "source": mutant("for child in &tree.children { __hepta_tree_stop(&child.shared, failure, discard); }",
                             "for child in &tree.children { let _ = (child, failure, discard); }",
                             'assert!(__hepta_group_adopt(&mut root,child)); __hepta_group_cancel(&mut root); '
                             'assert!(state.cancel.load(std::sync::atomic::Ordering::Acquire),"uncancelled descendant detected"); '
                             '__hepta_group_join(root,2);'),
            "expected": "nonzero", "diagnostic": "uncancelled descendant detected", "timeout_seconds": 10,
        },
        "adoption_refusal_detaches_child": {
            "source": mutant("__hepta_group_join(refused, 2);", "core::mem::forget(refused);",
                             '__hepta_group_seal(&mut root); assert!(!__hepta_group_adopt(&mut root,child)); '
                             'assert!(state.state.lock().unwrap().report.h_joined,"unjoined refused child detected"); '
                             '__hepta_group_join(root,0);'),
            "expected": "nonzero", "diagnostic": "unjoined refused child detected", "timeout_seconds": 10,
        },
        "sequential_queue_drain_deadlocks": {
            "source": native_controls_source().replace(
                "closed &= __hepta_tree_drain_poll(&child.shared);",
                "closed = closed && __hepta_tree_drain_poll(&child.shared);", 1),
            "expected": "timeout", "diagnostic": None, "timeout_seconds": 2,
        },
    }


def execute(argv, *, timeout=30):
    """Return completed, failed-launch, or timeout evidence without discarding it."""
    argv = list(map(str, argv))
    start = time.monotonic_ns()
    executable = Path(argv[0])
    record = {"argv": argv, "timeout_seconds": timeout, "error": None,
              "executable_sha256": digest(executable.read_bytes()) if executable.is_file() else None}
    try:
        process = subprocess.run(argv, cwd=ROOT, capture_output=True, timeout=timeout)
        stdout, stderr = process.stdout, process.stderr
        record.update(status="completed", returncode=process.returncode)
    except subprocess.TimeoutExpired as error:
        stdout, stderr = error.stdout or b"", error.stderr or b""
        record.update(status="timeout", returncode=None)
    except OSError as error:
        stdout, stderr = b"", b""
        record.update(status="launch_failed", returncode=None, error=str(error))
    record.update(elapsed_ns=time.monotonic_ns() - start,
                  stdout_base64=base64.b64encode(stdout).decode(), stderr_base64=base64.b64encode(stderr).decode(),
                  stdout_sha256=digest(stdout), stderr_sha256=digest(stderr))
    return record


def output(record, stream="stdout"):
    return base64.b64decode(record[stream + "_base64"], validate=True)


def success(record):
    return record.get("status") == "completed" and type(record.get("returncode")) is int and record["returncode"] == 0


def build(source, name, directory, toolchain, cc, obj):
    path = directory / (name + ".rs")
    executable = directory / name
    path.write_text(source)
    flags = [*RUST_FLAGS]
    if toolchain["sysroot"]:
        flags += ["--sysroot", toolchain["sysroot"]]
    lld_dir = Path(toolchain["sysroot"]) / "lib/rustlib" / toolchain["host"] / "bin/gcc-ld"
    flags += ["-C", "linker=" + cc, "-C", "link-arg=-B" + str(lld_dir), "-C", "link-arg=-fuse-ld=lld", "-C", "link-arg=" + str(obj), "-C", "link-arg=-Wl,--wrap=pthread_create"]
    command = execute([toolchain["path"], str(path), *flags, "-o", str(executable)], timeout=60)
    result = {"source_sha256": digest(source.encode()), "source_path": str(path),
              "artifact": str(executable), "artifact_sha256": None, "artifact_bytes": 0,
              "flags": flags, "linked_object_sha256": digest(obj.read_bytes()) if obj.is_file() else None, "execution": command}
    if success(command) and executable.is_file():
        result.update(artifact_sha256=digest(executable.read_bytes()), artifact_bytes=executable.stat().st_size)
    return result


def observations(build_record, expected, repeats):
    records = []
    for trial in range(repeats):
        execution = execute([build_record["artifact"]])
        row = {"trial": trial, "execution": execution, "metrics": None}
        if success(execution):
            values = output(execution).splitlines()
            if len(values) == len(expected) and all(re.fullmatch(rb"[0-9]+", item) for item in values):
                row["metrics"] = dict(zip(expected, map(int, values)))
        records.append(row)
    return records


def run_qualification(*, rustc=None, cc=None, repeats=3):
    if type(repeats) is not int or not 1 <= repeats <= 20:
        raise ValueError("repeats must be an integer in 1..20")
    before, sources = compiler_hash(), identities()
    report = {"schema": "hepta.task-tree.evidence.v1", "status": "failed", "errors": [],
              "created_at": datetime.now(timezone.utc).isoformat(), "compiler_sha256": before,
              "source_files": sources, "repeats": repeats, "profile": dict(PROFILE), "claims": dict(CLAIMS),
              "host": {"system": platform.system(), "machine": platform.machine()},
              "source_cases": [], "native_controls": None, "negative_controls": [],
              "toolchain": None, "c_compiler": None, "linker": None, "injector": None,
              "denominators": {"source_runs": repeats * len(SCENARIOS), "native_runs": repeats,
                               "wrong_runtime_programs": 4, "adoption_failure_races": repeats * 128,
                               "spawn_close_races": repeats * 64}}
    try:
        if platform.system() != "Linux":
            raise ValueError("the real pthread refusal control requires a Linux host")
        toolchain = toolchain_info(find_rustc(rustc))
        cc = shutil.which(cc or "gcc")
        if cc is None:
            raise ValueError("a native C compiler is required for the pthread refusal boundary")
        cc = str(Path(cc).resolve())
        report["toolchain"] = toolchain
        lld = Path(toolchain["sysroot"]) / "lib/rustlib" / toolchain["host"] / "bin/rust-lld"
        wrapper = lld.parent / "gcc-ld/ld.lld"
        report["linker"] = {"path": str(lld), "sha256": digest(lld.read_bytes()),
                            "wrapper_path": str(wrapper), "wrapper_sha256": digest(wrapper.read_bytes())}
        report["c_compiler"] = {"path": cc, "sha256": digest(Path(cc).read_bytes()),
                                "version": execute([cc, "--version"])}
        with tempfile.TemporaryDirectory(prefix="hepta-task-tree-") as temporary:
            directory = Path(temporary)
            obj = directory / "faults.o"
            compiled = execute([cc, *C_FLAGS, "-c", str(ROOT / SOURCE_FILES[4]), "-o", str(obj)])
            report["injector"] = {"source": SOURCE_FILES[4], "source_sha256": sources[SOURCE_FILES[4]],
                                  "artifact": str(obj), "artifact_sha256": None, "artifact_bytes": 0,
                                  "execution": compiled}
            if success(compiled) and obj.is_file():
                report["injector"].update(artifact_sha256=digest(obj.read_bytes()), artifact_bytes=obj.stat().st_size)
            for name, expected in SCENARIOS.items():
                relative = f"examples/groups/{name}.hepta"
                analysis = analyze((ROOT / relative).read_text(), relative, native=True,
                                   rustc=toolchain["path"], crate_type="bin")
                case = {"name": name, "source": relative, "analysis": analysis.report,
                        "build": None, "runs": [], "concurrent_ir": None, "ir_replay": None}
                report["source_cases"].append(case)
                if not analysis.report["ok"]:
                    report["errors"].append("source rejected: " + name)
                    continue
                exported = concurrent_ir_analysis(analysis)
                case["concurrent_ir"] = exported["concurrent_ir"]
                graph_path = directory / (name + ".ir.json")
                graph_path.write_bytes(canonical(case["concurrent_ir"]))
                case["ir_replay"] = execute([sys.executable, "-m", "hepta.concurrent_ir", str(graph_path)])
                case["build"] = build(analysis.rust, name, directory, toolchain, cc, obj)
                case["runs"] = observations(case["build"], expected, repeats)
            source = native_controls_source()
            native = build(source, "native_controls", directory, toolchain, cc, obj)
            report["native_controls"] = {"build": native, "runs": observations(native, CONTROLS, repeats)}
            for name, control in negative_sources().items():
                compiled = build(control["source"], name, directory, toolchain, cc, obj)
                execution = execute([compiled["artifact"]], timeout=control["timeout_seconds"])
                report["negative_controls"].append({"name": name, "expected": control["expected"],
                                                    "build": compiled, "execution": execution})
        if compiler_hash() != before or identities() != sources:
            report["errors"].append("source changed during qualification")
        if not report["errors"]:
            report["status"] = "passed"
            try:
                validate_task_tree_report(report, minimum_repeats=1, trusted_rustc=rustc)
            except (ValueError, TypeError, KeyError) as error:
                report["status"] = "failed"
                report["errors"].append(str(error))
    except Exception as error:
        report["status"] = "failed"
        report["errors"].append(type(error).__name__ + ": " + str(error))
    return report


def _validate_task_tree_report(report, *, minimum_repeats=3, trusted_rustc=None):
    """Recompute identities, source lowering, IR checks and raw observations.

    The report is replayable evidence with source hashes, not a signed attestation
    or proof that an arbitrary author truthfully recorded the external process.
    """
    def require(condition, message):
        if not condition:
            raise ValueError(message)

    def hash_(value):
        return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None

    def process(value, argv=None, *, timeout=30, expected="success", diagnostic=None, executable_sha256=None):
        require(isinstance(value, dict) and set(value) == {
            "argv", "timeout_seconds", "error", "status", "returncode", "elapsed_ns", "executable_sha256",
            "stdout_base64", "stderr_base64", "stdout_sha256", "stderr_sha256"}, "invalid process record fields")
        require(isinstance(value["argv"], list) and value["argv"] and all(isinstance(x, str) for x in value["argv"]),
                "missing actual argv")
        if argv is not None:
            require(value["argv"] == argv, "execution command differs from built artifact")
        require(hash_(value["executable_sha256"]), "executed binary identity missing")
        if executable_sha256 is not None:
            require(value["executable_sha256"] == executable_sha256, "executed binary differs from build")
        require(type(value["timeout_seconds"]) is int and value["timeout_seconds"] == timeout,
                "timeout contract changed")
        require(type(value["elapsed_ns"]) is int and value["elapsed_ns"] > 0, "invalid measured duration")
        require(value["error"] is None, "process could not launch")
        for stream in ("stdout", "stderr"):
            require(isinstance(value[stream + "_base64"], str), "raw stream missing")
            try:
                data = output(value, stream)
            except Exception as error:
                raise ValueError("invalid base64 transcript") from error
            require(base64.b64encode(data).decode() == value[stream + "_base64"]
                    and digest(data) == value[stream + "_sha256"], "raw transcript hash differs")
        if expected == "timeout":
            require(value["status"] == "timeout" and value["returncode"] is None,
                    "wrong blocking runtime was not detected by the finite timeout")
            require(value["elapsed_ns"] >= timeout * 1_000_000_000, "timeout duration was invented")
        else:
            require(value["status"] == "completed" and type(value["returncode"]) is int,
                    "execution did not complete")
            require(value["returncode"] == 0 if expected == "success" else value["returncode"] != 0,
                    "process result does not match qualification expectation")
        if diagnostic is not None:
            require(diagnostic.encode() in output(value, "stderr"), "wrong-runtime rejection diagnostic missing")

    def built(value, source):
        require(isinstance(value, dict) and set(value) == {"source_sha256", "source_path", "artifact", "artifact_sha256",
                                                         "artifact_bytes", "flags", "linked_object_sha256", "execution"}, "build record differs")
        require(value["source_sha256"] == digest(source.encode()), "build/lowered source mismatch")
        require(value["linked_object_sha256"] == report["injector"]["artifact_sha256"], "linked native refusal object differs")
        require(hash_(value["artifact_sha256"]) and type(value["artifact_bytes"]) is int and value["artifact_bytes"] > 0,
                "missing actual native binary")
        require(isinstance(value["artifact"], str) and Path(value["source_path"]) == Path(value["artifact"] + ".rs"),
                "source/executable identities differ")
        flags = [*RUST_FLAGS]
        if report["toolchain"]["sysroot"]:
            flags += ["--sysroot", report["toolchain"]["sysroot"]]
        lld_dir = Path(report["toolchain"]["sysroot"]) / "lib/rustlib" / report["toolchain"]["host"] / "bin/gcc-ld"
        flags += ["-C", "linker=" + report["c_compiler"]["path"],
                  "-C", "link-arg=-B" + str(lld_dir), "-C", "link-arg=-fuse-ld=lld",
                  "-C", "link-arg=" + report["injector"]["artifact"], "-C", "link-arg=-Wl,--wrap=pthread_create"]
        require(value["flags"] == flags, "build optimization, overflow, panic, linker or fault linkage changed")
        process(value["execution"], [report["toolchain"]["path"], value["source_path"], *flags, "-o", value["artifact"]], timeout=60, executable_sha256=report["toolchain"]["executable_sha256"])

    def runs(values, build_, expected):
        require(isinstance(values, list) and len(values) == report["repeats"], "run denominator changed")
        transcript = "".join(f"{number}\n" for number in expected.values()).encode()
        for index, value in enumerate(values):
            require(isinstance(value, dict) and set(value) == {"trial", "execution", "metrics"}, "invalid trial record")
            require(type(value["trial"]) is int and value["trial"] == index, "trial is missing, duplicated or reordered")
            require(value["metrics"] == expected and all(type(x) is int for x in value["metrics"].values()),
                    "runtime assertions or executed case count differ")
            process(value["execution"], [build_["artifact"]], executable_sha256=build_["artifact_sha256"])
            require(output(value["execution"]) == transcript and output(value["execution"], "stderr") == b"",
                    "native observations disagree with raw output")

    require(isinstance(report, dict) and set(report) == {
        "schema", "status", "errors", "created_at", "compiler_sha256", "source_files", "repeats", "profile",
        "claims", "host", "source_cases", "native_controls", "negative_controls", "toolchain", "c_compiler",
        "injector", "linker", "denominators"}, "invalid task tree report fields")
    require(report["schema"] == "hepta.task-tree.evidence.v1" and report["status"] == "passed"
            and report["errors"] == [], "qualification did not pass")
    require(type(minimum_repeats) is int and 1 <= minimum_repeats <= 20
            and type(report["repeats"]) is int and minimum_repeats <= report["repeats"] <= 20, "insufficient trials")
    require(report["compiler_sha256"] == compiler_hash() and report["source_files"] == identities(), "source identity changed")
    require(report["profile"] == PROFILE and all(type(report["profile"][key]) is type(value) for key, value in PROFILE.items()),
            "finite tree contract changed")
    require(report["claims"] == CLAIMS and all(type(x) is bool for x in report["claims"].values()), "unsupported proof/coverage claim")
    require(report["host"] == {"system": platform.system(), "machine": platform.machine()} and platform.system() == "Linux",
            "qualification is not for this real Linux host")
    require(report["denominators"] == {"source_runs": report["repeats"] * len(SCENARIOS), "native_runs": report["repeats"],
                                      "wrong_runtime_programs": 4, "adoption_failure_races": report["repeats"] * 128,
                                      "spawn_close_races": report["repeats"] * 64}
            and all(type(x) is int for x in report["denominators"].values()), "executed denominators changed")
    info = report["toolchain"]
    require(isinstance(info, dict) and hash_(info.get("executable_sha256")) and isinstance(info.get("path"), str)
            and isinstance(info.get("host"), str) and info.get("version", "").startswith("rustc 1.90.0 "), "native rustc identity missing")
    # A report is data, not authority to execute its claimed compiler path.
    require(info == toolchain_info(find_rustc(trusted_rustc)), "rustc identity is not the qualified pinned compiler")
    lld = Path(info["sysroot"]) / "lib/rustlib" / info["host"] / "bin/rust-lld"
    wrapper = lld.parent / "gcc-ld/ld.lld"
    require(report["linker"] == {"path": str(lld), "sha256": digest(lld.read_bytes()),
                                 "wrapper_path": str(wrapper), "wrapper_sha256": digest(wrapper.read_bytes())},
            "bundled native linker identity changed")
    cc = report["c_compiler"]
    require(isinstance(cc, dict) and set(cc) == {"path", "sha256", "version"}
            and hash_(cc["sha256"]) and digest(Path(cc["path"]).read_bytes()) == cc["sha256"], "C compiler identity differs")
    process(cc["version"], [cc["path"], "--version"], executable_sha256=cc["sha256"])
    require(output(cc["version"]) != b"", "C compiler version output missing")
    injector = report["injector"]
    require(isinstance(injector, dict) and set(injector) == {"source", "source_sha256", "artifact", "artifact_sha256",
                                                         "artifact_bytes", "execution"}, "injector build missing")
    require(injector["source"] == SOURCE_FILES[4] and injector["source_sha256"] == report["source_files"][SOURCE_FILES[4]]
            and hash_(injector["artifact_sha256"]) and type(injector["artifact_bytes"]) is int and injector["artifact_bytes"] > 0,
            "real pthread boundary was not compiled")
    process(injector["execution"], [cc["path"], *C_FLAGS, "-c", str(ROOT / SOURCE_FILES[4]), "-o", injector["artifact"]], executable_sha256=cc["sha256"])
    cases = report["source_cases"]
    require(isinstance(cases, list) and all(isinstance(x, dict) for x in cases)
            and [x.get("name") for x in cases] == list(SCENARIOS), "source cases missing or duplicated")
    for case in cases:
        require(set(case) == {"name", "source", "analysis", "build", "runs", "concurrent_ir", "ir_replay"}, "source case fields differ")
        path = f"examples/groups/{case['name']}.hepta"
        require(case["source"] == path, "source path mismatch")
        source = (ROOT / path).read_text()
        lowered = analyze(source, path, native=False, crate_type="bin")
        analysis = case["analysis"]
        require(isinstance(analysis, dict) and analysis.get("ok") is True and analysis.get("status") == "checked"
                and analysis.get("checks") == {"syntax": "passed", "types_effects_resources": "passed_in_supported_subset",
                                               "rust_borrows_types": "rustc_checked"}, "source was not natively checked")
        for key in ("compiler_sha256", "source_sha256", "interface_sha256", "claims", "effects", "assumptions", "resource_contracts"):
            require(analysis.get(key) == lowered.report.get(key), "source analysis/binding changed: " + key)
        rust_hash = digest(lowered.rust.encode())
        require(analysis.get("rust_sha256") == rust_hash, "lowered Rust identity differs")
        native_check = analysis.get("backend", {})
        require(native_check.get("ok") is True and native_check.get("status") == "rustc_checked"
                and native_check.get("check_only") is True and native_check.get("rust_sha256") == rust_hash
                and native_check.get("toolchain") == info and hash_(native_check.get("validation_artifact_sha256")),
                "native source type/borrow check missing")
        graph = concurrent_ir_analysis(lowered)["concurrent_ir"]
        require(case["concurrent_ir"] == graph, "serialized topology/ownership IR is not the current lowering")
        verified = verify_concurrent_ir(graph)
        require(verified["ok"] is True and verified["group_adoptions"] == 3 and verified["tree_joins"] == 1,
                "independent parent/child ownership transfer did not verify")
        replay = case["ir_replay"]
        process(replay, executable_sha256=digest(Path(sys.executable).read_bytes()))
        require(len(replay["argv"]) == 4 and replay["argv"][:3] == [sys.executable, "-m", "hepta.concurrent_ir"]
                and Path(replay["argv"][3]).name == case["name"] + ".ir.json", "IR standalone replay command changed")
        require(json.loads(output(replay)) == {**verified, "source_binding_verified": False}
                and output(replay, "stderr") == b"", "standalone IR result differs from independent recheck")
        built(case["build"], lowered.rust)
        runs(case["runs"], case["build"], SCENARIOS[case["name"]])
    controls = report["native_controls"]
    require(isinstance(controls, dict) and set(controls) == {"build", "runs"}, "native control record missing")
    built(controls["build"], native_controls_source())
    runs(controls["runs"], controls["build"], CONTROLS)
    negatives = report["negative_controls"]
    expected = negative_sources()
    require(isinstance(negatives, list) and all(isinstance(x, dict) for x in negatives)
            and [x.get("name") for x in negatives] == list(expected), "wrong-runtime denominator changed")
    for entry in negatives:
        require(set(entry) == {"name", "expected", "build", "execution"}, "wrong-runtime record differs")
        control = expected[entry["name"]]
        require(entry["expected"] == control["expected"], "negative control result expectation was changed")
        built(entry["build"], control["source"])
        process(entry["execution"], [entry["build"]["artifact"]], timeout=control["timeout_seconds"],
                expected=control["expected"], diagnostic=control["diagnostic"], executable_sha256=entry["build"]["artifact_sha256"])


def validate_task_tree_report(report, *, minimum_repeats=3, trusted_rustc=None):
    """Fail closed on malformed data while retaining scoped replay semantics."""
    try:
        _validate_task_tree_report(report, minimum_repeats=minimum_repeats, trusted_rustc=trusted_rustc)
    except (TypeError, KeyError, AttributeError, OSError, RecursionError) as error:
        raise ValueError("malformed task tree qualification: " + str(error)) from error


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rustc", default=os.environ.get("RUSTC"))
    parser.add_argument("--cc")
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    report = run_qualification(rustc=args.rustc, cc=args.cc, repeats=args.repeats)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    print(json.dumps({"status": report["status"], "errors": report["errors"], "output": str(args.output),
                      "denominators": report["denominators"]}, sort_keys=True))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
