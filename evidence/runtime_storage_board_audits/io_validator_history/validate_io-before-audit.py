"""Qualify the bounded local-stream I/O reactor on its actual native profile.

This runs owned, cross-file Hepta programs and a separate native boundary
control against the exact embedded production runtime. The private socketpair
tests need permission for local Unix-stream send syscalls. Denial is a failed
attempt, never a simulated success. Reports are checkpointed before assertions;
an existing output is not overwritten, including an earlier failed attempt.
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
import struct
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hepta.backend import compile_rust, find_rustc, toolchain_info
from hepta.pipeline import analyze, analyze_project, compiler_hash, concurrent_ir_analysis, resource_ir_analysis
from hepta.runtime_io import IO_RUNTIME
from tools.evidence_checks import is_sha, native_build, normalized_errors, require, strict_equal

PROFILE = "x86_64-unknown-linux-gnu"
SCENARIOS = {
    "pipeline": {"admitted": 4, "read_bytes": 128, "written_bytes": 128, "peak_buffer_bytes": 256, "abandoned": 0},
    "cancellation": {"cancelled": 1, "timed_out": 1, "completed": 4, "abandoned": 0},
    "failure_paths": {"early_return_cancellation": 1, "early_return_capacity_refusal": 8, "invalid_reactor_ports": 0},
}
CONTROLS = {
    "delayed_readiness_cases": 1, "partial_read_eof_cases": 1, "broken_peer_cases": 1,
    "partial_write_cancel_cases": 1, "partial_read_cancel_cases": 1, "delayed_write_readiness_cases": 1,
    "ready_before_cancel_cases": 1, "readiness_cancel_races": 64,
    "deadline_interruptions": 5, "poll_failure_recovery_cases": 1, "admission_refusal_cases": 5,
    "completed_slot_reservation_cases": 1, "fd_reuse_cases": 1, "stale_port_cases": 1,
    "stale_request_cases": 1, "foreign_reactor_cases": 1, "actual_fd_limit_refusals": 1,
    "metadata_refusal_sites": 3, "identifier_exhaustion_cases": 2,
    "shutdown_fd_close_cases": 1, "native_drop_cleanup_cases": 1, "queued_shutdown_cancellations": 2,
    "hot_path_allocations": 0, "final_tracked_buffer_bytes": 0,
}
MEASURED = {"blocking_elapsed_ns", "blocking_poll_ns", "blocking_thread_cpu_ns", "blocking_real_poll_calls",
            "partial_write_bytes", "final_deadline_poll_millis", "write_blocking_elapsed_ns", "write_blocking_poll_ns", "write_real_poll_calls"}
CLAIMS = {
    "async_await_language_implemented": False, "background_executor_implemented": False,
    "cross_thread_cancellation_implemented": False, "task_tree_composition_qualified": False,
    "arbitrary_io_or_network_protocols_implemented": False, "other_platforms_qualified": False,
    "whole_process_resources_bounded": False, "hard_realtime_cancellation_proved": False,
    "source_to_ir_or_backend_refinement_proved": False, "c_backend_or_independent_ir_supported": False,
}
LIMITS = [
    "Single-owner, caller-driven readiness pump; no worker per I/O operation and no background executor.",
    "Private UnixStream pairs only; no filesystem, TCP, listeners, external/raw FD import, async/await or DNS API.",
    "One pending reader and one pending writer per endpoint; 2..256 ports and 1..1024 occupied request slots.",
    "Completed uncollected buffers retain slot and Vec-capacity byte reservations until take/wait or shutdown.",
    "Cancellation prevents future pump syscalls and preserves the transferred prefix; it cannot undo prior effects.",
    "A consumed foreign admitted ticket cannot access its origin; that origin retains its buffer until shutdown.",
    "Metadata, preadmission/refused buffers, allocator overhead, kernel buffers, other reactors, RSS and CPU are not the byte budget.",
    "Fallible fixed metadata admission is checked; ordinary Buffer allocation or unrelated OOM and panic=abort may terminate the process.",
    "Timing and allocation observations cover the named native controls on this host, not a general latency or allocator proof.",
]
SOURCE_FILES = [
    "hepta/runtime_io.py", "hepta/checker.py", "hepta/backend.py", "tools/validate_io.py",
    "tools/fixtures/io_controls.rs", "tools/fixtures/io_faults.c", "examples/io/library.hepta",
    *[f"examples/io/{name}.hepta" for name in SCENARIOS],
]
EFFECTS = "alloc,block,panic,io,write"
MAIN = f"fn main()->Unit effects {{{EFFECTS}}} {{"
START = "let mut io=io_reactor(2,2,16);"
REQUEST = "let pair=io_local_pair(mut io);let bytes=buffer(8);let request=io_read(mut io,pair.left,move bytes,8,10);"
TAKE = "let mut count:usize=0;let mut status:u8=0;let returned=io_take(mut io,move request,mut count,mut status);release(move returned);"
VALID = MAIN + START + "io_shutdown(move io);}"
REJECTIONS = {
    "unconsumed_reactor": ("frontend", MAIN + START + "}", "E_LINEAR_UNCONSUMED"),
    "unconsumed_request": ("frontend", MAIN + START + REQUEST + "io_shutdown(move io);}", "E_LINEAR_UNCONSUMED"),
    "duplicate_request": ("frontend", MAIN + START + REQUEST + TAKE +
                          "let again=io_take(mut io,move request,mut count,mut status);release(move again);io_shutdown(move io);}", "E_USE_AFTER_MOVE"),
    "release_request": ("frontend", MAIN + START + REQUEST + "drop(move request);io_shutdown(move io);}", "E_BUILTIN_TYPE"),
    "mutation_via_read": ("frontend", MAIN + START + "io_local_pair(read io);io_shutdown(move io);}", "E_BORROW_MODE"),
    "hidden_owner": ("frontend", "struct Hidden{io:IoReactor}" + VALID, "E_NESTED_LINEAR"),
    "generic_owner": ("frontend", "fn keep<T:Owned>(x:take T)->T effects {}{return move x;}" + MAIN + START +
                      "let kept=keep::<IoReactor>(move io);io_shutdown(move kept);}", "E_GENERIC_COPY"),
    "forged_report": ("frontend", MAIN + START + "let r=IoReport{};io_shutdown(move io);}", "E_REPORT_CONSTRUCTION"),
    "move_borrow": ("frontend", "fn bad(x:read IoReactor)->IoReactor effects {} {return move x;}", "E_MOVE_BORROW"),
    "consume_in_later_operand": ("native", MAIN + START + "io_poll(mut io,io_shutdown(move io).admitted);}", "E0505"),
    "mut_alias": ("native", "fn both(a:mut IoReactor,b:mut IoReactor)->Unit effects {}{}" + MAIN + START +
                  "both(mut io,mut io);io_shutdown(move io);}", "E0499"),
    "c_backend": ("c", VALID, "E_C_RESOURCE_IR"),
    "no_std": ("no_std", VALID, "E_NO_STD"),
    "resource_ir": ("resource_ir", VALID, "E_RIR_LOWER_UNSUPPORTED"),
    "concurrent_ir": ("concurrent_ir", VALID, "E_CIR_LOWER"),
}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def identities() -> dict:
    return {name: digest((ROOT / name).read_bytes()) for name in SOURCE_FILES}


def native_controls_source() -> str:
    insertion = "// HEPTA_IO_TEST_INSERTION"
    require(IO_RUNTIME.count(insertion) == 1, "native control insertion point changed")
    source = IO_RUNTIME.replace(insertion, (ROOT / "tools/fixtures/io_controls.rs").read_text())
    return "#![allow(unused,dead_code,non_camel_case_types)]\n" + source + "\nfn main(){__hepta_io_runtime::io_control_main();}\n"


def rejection_report(kind: str, source: str, rustc: str) -> dict:
    if kind in {"resource_ir", "concurrent_ir"}:
        analysis = analyze(source, native=False)
        return (resource_ir_analysis if kind == "resource_ir" else concurrent_ir_analysis)(analysis)
    return analyze(source, native=kind == "native", rustc=rustc, crate_type="bin",
                   backend="c" if kind == "c" else "rust", no_std=kind == "no_std").report


def _unique_object(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate JSON key in native transcript")
        result[key] = value
    return result


def control_metrics(stdout: str) -> dict:
    value = json.loads(stdout, object_pairs_hook=_unique_object)
    require(isinstance(value, dict) and set(value) == {"schema"} | set(CONTROLS) | MEASURED,
            "native control observations are missing or extra")
    require(value["schema"] == "hepta.io-native-controls.v1", "native control schema changed")
    require(all(type(value[key]) is int for key in set(CONTROLS) | MEASURED), "native counts must be integers")
    require(strict_equal({key: value[key] for key in CONTROLS}, CONTROLS), "native case count or resource observation changed")
    elapsed, blocked, cpu = (value[key] for key in ("blocking_elapsed_ns", "blocking_poll_ns", "blocking_thread_cpu_ns"))
    require(elapsed >= 15_000_000 and 10_000_000 <= blocked <= elapsed + 1_000_000,
            "the delayed read did not demonstrate a real blocking poll")
    require(0 <= cpu < elapsed // 2 + 5_000_000 and 1 <= value["blocking_real_poll_calls"] <= 4,
            "the delayed read did not meet the bounded-wakeup/CPU control")
    require(0 < value["partial_write_bytes"] < 2 * 1024 * 1024, "no actual partial write observed")
    require(value["write_blocking_elapsed_ns"] >= 15_000_000
            and 10_000_000 <= value["write_blocking_poll_ns"] <= value["write_blocking_elapsed_ns"] + 1_000_000
            and 1 <= value["write_real_poll_calls"] <= 256, "no actual bounded write-readiness wait observed")
    require(0 <= value["final_deadline_poll_millis"] <= 200, "EINTR restarted or lost the absolute deadline")
    return {key: value[key] for key in set(CONTROLS) | MEASURED}


class QualificationFailed(RuntimeError):
    def __init__(self, report):
        self.report = report
        super().__init__(report["failure"])


def run_qualification(*, rustc=None, cc=None, repeats=3, output=None) -> dict:
    if type(repeats) is not int or not 1 <= repeats <= 20:
        raise ValueError("repeats must be 1..20")
    report = {"schema": "hepta.io-reactor.evidence.v1", "status": "running",
              "created_utc": datetime.now(timezone.utc).isoformat(), "profile": PROFILE,
              "compiler_sha256": compiler_hash(), "source_files": identities(),
              "host": {"system": platform.system(), "machine": platform.machine(), "pointer_bits": struct.calcsize("P") * 8},
              "repeats": repeats, "claims": dict(CLAIMS), "limits": list(LIMITS),
              "source_cases": [], "rejections": [], "native_controls": {}}
    target = Path(output) if output is not None else None
    if target is not None:
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("x", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2, sort_keys=True)

    def checkpoint():
        if target is not None:
            with tempfile.NamedTemporaryFile("w", dir=target.parent, prefix=target.name + ".", delete=False) as stream:
                json.dump(report, stream, indent=2, sort_keys=True)
                stream.write("\n")
                temporary = stream.name
            os.replace(temporary, target)

    def run(executable, record, expected=None):
        record["runs"] = []
        for trial in range(repeats):
            start = time.monotonic_ns()
            try:
                process = subprocess.run([str(executable)], capture_output=True, text=True, timeout=30)
                stdout, stderr, returncode, timeout = process.stdout, process.stderr, process.returncode, False
            except subprocess.TimeoutExpired as error:
                decode = lambda value: value.decode(errors="replace") if isinstance(value, bytes) else value or ""
                stdout, stderr, returncode, timeout = decode(error.stdout), decode(error.stderr), None, True
            observed = {"trial": trial, "returncode": returncode, "timed_out": timeout,
                        "elapsed_ns": time.monotonic_ns() - start, "stdout": stdout, "stderr": stderr,
                        "stdout_sha256": digest(stdout.encode()), "stderr_sha256": digest(stderr.encode())}
            record["runs"].append(observed)
            checkpoint()
            require(returncode == 0 and not timeout and not stderr, f"native execution failed: {returncode}: {stderr}")
            if expected is None:
                observed["metrics"] = control_metrics(stdout)
            else:
                require(stdout == "".join(f"{number}\n" for number in expected.values()), "source application output mismatch")
                observed["metrics"] = dict(zip(expected, map(int, stdout.splitlines())))
            checkpoint()

    try:
        require(report["host"] == {"system": "Linux", "machine": "x86_64", "pointer_bits": 64}, "unqualified I/O host")
        rustc = find_rustc(rustc)
        report["toolchain"] = toolchain_info(rustc)
        require(report["toolchain"]["host"] == PROFILE and report["toolchain"]["version"].startswith("rustc 1.90.0 "),
                "I/O qualification requires the pinned Rust 1.90.0 x86_64 GNU toolchain")
        cc = shutil.which(cc or "gcc")
        require(cc is not None, "a native GCC-compatible compiler is required")
        checkpoint()
        with tempfile.TemporaryDirectory(prefix="hepta-io-qualification-") as directory:
            temporary = Path(directory)
            for name, expected in SCENARIOS.items():
                path = ROOT / f"examples/io/{name}.hepta"
                analysis = analyze_project(path, native=True, rustc=rustc, crate_type="bin")
                case = {"name": name, "source": str(path.relative_to(ROOT)), "analysis": analysis.report}
                report["source_cases"].append(case)
                checkpoint()
                require(analysis.report["ok"] is True, "source application was rejected: " + name)
                executable = temporary / name
                case["build"] = compile_rust(analysis.rust, rustc=rustc, crate_type="bin", output=executable)
                checkpoint()
                require(case["build"]["ok"] is True, "source native build failed: " + name)
                run(executable, case, expected)
            for name, (kind, source, code) in REJECTIONS.items():
                rejected = rejection_report(kind, source, rustc)
                report["rejections"].append({"name": name, "kind": kind, "source_sha256": digest(source.encode()), "report": rejected})
                checkpoint()
                require(rejected.get("ok") is False and code in {item.get("code") for item in rejected.get("diagnostics", [])},
                        "unsupported/invalid program was not rejected: " + name)
            controls = report["native_controls"]
            obj = temporary / "faults.o"
            flags = ["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"]
            command = [cc, *flags, "-c", str(ROOT / "tools/fixtures/io_faults.c"), "-o", str(obj)]
            built = subprocess.run(command, capture_output=True, text=True, timeout=30)
            controls["c_build"] = {
                "command": command, "returncode": built.returncode, "compiler": str(Path(cc).resolve()),
                "compiler_sha256": digest(Path(cc).read_bytes()),
                "version": subprocess.check_output([cc, "--version"], text=True).splitlines()[0],
                "target": subprocess.check_output([cc, "-dumpmachine"], text=True).strip(), "flags": flags,
                "source_sha256": report["source_files"]["tools/fixtures/io_faults.c"],
                "object_sha256": digest(obj.read_bytes()) if obj.is_file() else None,
                "object_bytes": obj.stat().st_size if obj.is_file() else 0,
                "stdout": built.stdout, "stderr": built.stderr,
                "stdout_sha256": digest(built.stdout.encode()), "stderr_sha256": digest(built.stderr.encode()),
            }
            checkpoint()
            require(built.returncode == 0 and controls["c_build"]["object_bytes"] > 0, "native boundary fixture build failed")
            source = native_controls_source()
            controls["source_sha256"] = digest(source.encode())
            controls["linked_object_sha256"] = controls["c_build"]["object_sha256"]
            executable = temporary / "controls"
            controls["build"] = compile_rust(source, rustc=rustc, crate_type="bin", output=executable,
                                              link_args=[str(obj), "-Wl,--wrap=poll"])
            checkpoint()
            require(controls["build"]["ok"] is True, "native boundary controls did not compile")
            run(executable, controls)
        require(identities() == report["source_files"] and compiler_hash() == report["compiler_sha256"], "source changed during qualification")
        report["status"] = "passed"
        validate_io_report(report)
        checkpoint()
        return report
    except Exception as error:
        report["status"] = "failed"
        report["failure"] = f"{type(error).__name__}: {error}"
        checkpoint()
        raise QualificationFailed(report) from error


@normalized_errors
def validate_io_report(report: dict, *, minimum_repeats=1) -> None:
    """Rebind to current sources and reject incomplete or inflated observations.

    Transcript hashes are identity bindings, not signatures. Authentic execution
    still requires rerunning this producer on the declared host and toolchain.
    """
    require(type(minimum_repeats) is int and 1 <= minimum_repeats <= 20, "invalid minimum repeat count")
    require(isinstance(report, dict) and report.get("schema") == "hepta.io-reactor.evidence.v1"
            and report.get("status") == "passed" and "failure" not in report, "invalid or incomplete I/O evidence")
    require(type(report.get("repeats")) is int and minimum_repeats <= report["repeats"] <= 20, "insufficient repetitions")
    require(report.get("profile") == PROFILE and strict_equal(report.get("host"), {"system": "Linux", "machine": "x86_64", "pointer_bits": 64}),
            "unqualified host/profile")
    require(report.get("compiler_sha256") == compiler_hash() and report.get("source_files") == identities(), "I/O qualification source identity changed")
    require(strict_equal(report.get("claims"), CLAIMS) and all(value is False for value in report["claims"].values())
            and report.get("limits") == LIMITS, "unsupported I/O safety or coverage claim")
    toolchain = report.get("toolchain", {})
    require(isinstance(toolchain, dict) and toolchain.get("host") == PROFILE and is_sha(toolchain.get("executable_sha256"))
            and isinstance(toolchain.get("version"), str) and toolchain["version"].startswith("rustc 1.90.0 "), "unqualified native toolchain")
    require(isinstance(report.get("created_utc"), str) and datetime.fromisoformat(report["created_utc"]).utcoffset() is not None,
            "missing qualification timestamp")

    def build(value, source_hash, check_only=False):
        native_build(value, "rust", check_only=check_only, crate_type="bin", source_sha256=source_hash)
        require(value.get("target") == PROFILE and value.get("toolchain") == toolchain
                and value.get("rustc_crate_type") == ("lib" if check_only else "bin"),
                "native toolchain/target changed")
        require(all(flag in value["flags"] for flag in ("edition=2021", "opt-level=3", "overflow-checks=yes", "panic=abort", "codegen-units=1")),
                "native safety/optimization flags changed")

    def runs(values, expected=None):
        require(isinstance(values, list) and len(values) == report["repeats"], "trial denominator is incomplete")
        for trial, value in enumerate(values):
            require(isinstance(value, dict) and type(value.get("trial")) is int and value["trial"] == trial, "duplicate or out-of-order trial")
            require(type(value.get("returncode")) is int and value["returncode"] == 0 and value.get("timed_out") is False,
                    "failed or timed-out execution")
            require(type(value.get("elapsed_ns")) is int and value["elapsed_ns"] > 0, "missing observed execution duration")
            stdout = value.get("stdout")
            require(isinstance(stdout, str) and value.get("stdout_sha256") == digest(stdout.encode())
                    and value.get("stderr") == "" and value.get("stderr_sha256") == digest(b""), "native transcript identity differs")
            if expected is None:
                actual = control_metrics(stdout)
                require(value["elapsed_ns"] >= actual["blocking_elapsed_ns"] + actual["write_blocking_elapsed_ns"],
                        "native timing is outside the execution interval")
            else:
                require(stdout == "".join(f"{number}\n" for number in expected.values()), "source output changed")
                actual = expected
            require(strict_equal(value.get("metrics"), actual), "metrics differ from the actual raw transcript")

    cases = report.get("source_cases")
    require(isinstance(cases, list) and all(isinstance(case, dict) for case in cases)
            and [case.get("name") for case in cases] == list(SCENARIOS), "missing/duplicate source applications")
    for case in cases:
        name = case["name"]
        path = f"examples/io/{name}.hepta"
        require(case.get("source") == path, "source application path changed")
        current = analyze_project(ROOT / path, native=False, crate_type="bin")
        require(current.report["ok"] is True, "current source application no longer checks")
        analysis = case.get("analysis", {})
        require(isinstance(analysis, dict) and analysis.get("ok") is True and analysis.get("status") == "checked"
                and analysis.get("diagnostics") == [] and analysis.get("assumptions") == [], "source analysis was not successful")
        for key in ("compiler_sha256", "source_sha256", "rust_sha256", "interface_sha256", "project", "resource_contracts", "effects", "profile", "claims"):
            require(strict_equal(analysis.get(key), current.report.get(key)), "current source graph/lowering differs: " + key)
        require(analysis.get("checks") == {"rust_borrows_types": "rustc_checked", "syntax": "passed", "types_effects_resources": "passed_in_supported_subset"},
                "source checking was incomplete")
        build(analysis.get("backend"), analysis["rust_sha256"], True)
        build(case.get("build"), analysis["rust_sha256"])
        require(case["build"].get("link_args") == [], "source application linked unqualified code")
        runs(case.get("runs"), SCENARIOS[name])
    rejected = report.get("rejections")
    require(isinstance(rejected, list) and all(isinstance(item, dict) for item in rejected)
            and [item.get("name") for item in rejected] == list(REJECTIONS), "missing/duplicate rejection controls")
    for item in rejected:
        kind, source, code = REJECTIONS[item["name"]]
        require(item.get("kind") == kind and item.get("source_sha256") == digest(source.encode()), "rejection source/profile changed")
        result = item.get("report", {})
        require(isinstance(result, dict) and result.get("ok") is False and isinstance(result.get("diagnostics"), list)
                and code in {entry.get("code") for entry in result["diagnostics"]}, "rejection was not observed")
        if kind in {"resource_ir", "concurrent_ir"}:
            require(result.get("verifier") is None and result.get(kind) is None and result.get("validation", {}).get("ok") is True,
                    "unsupported IR acquired false semantics")
        else:
            require(result.get("compiler_sha256") == report["compiler_sha256"] and result.get("source_sha256") == item["source_sha256"],
                    "rejection compiler/source identity changed")
        if kind == "native":
            require(result.get("checks", {}).get("rust_borrows_types") == "rejected"
                    and result.get("backend", {}).get("toolchain") == toolchain
                    and result["backend"].get("check_only") is True and result["backend"].get("ok") is False,
                    "borrow-invalid control was not rejected by actual Rust")
    controls = report.get("native_controls", {})
    require(isinstance(controls, dict) and controls.get("source_sha256") == digest(native_controls_source().encode()), "native controls changed")
    build(controls.get("build"), controls["source_sha256"])
    c = controls.get("c_build", {})
    require(isinstance(c, dict) and type(c.get("returncode")) is int and c["returncode"] == 0
            and c.get("target") in {PROFILE, "x86_64-linux-gnu"} and is_sha(c.get("compiler_sha256"))
            and isinstance(c.get("version"), str) and bool(c["version"]), "missing native C ABI/control build")
    require(c.get("flags") == ["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"]
            and c.get("source_sha256") == report["source_files"]["tools/fixtures/io_faults.c"]
            and is_sha(c.get("object_sha256")) and type(c.get("object_bytes")) is int and c["object_bytes"] > 0
            and controls.get("linked_object_sha256") == c["object_sha256"], "native boundary object identity changed")
    require(c.get("stdout") == "" and c.get("stderr") == "" and c.get("stdout_sha256") == digest(b"")
            and c.get("stderr_sha256") == digest(b""), "native boundary build transcript differs")
    links = controls["build"].get("link_args")
    require(isinstance(links, list) and len(links) == 2 and isinstance(links[0], str)
            and links[0].endswith("/faults.o") and links[1] == "-Wl,--wrap=poll", "native poll boundary fixture was not linked")
    command = c.get("command")
    require(isinstance(command, list) and len(command) == 10 and command[1:6] == c["flags"]
            and command[6:] == ["-c", str(ROOT / "tools/fixtures/io_faults.c"), "-o", links[0]], "C fixture command changed")
    runs(controls.get("runs"))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rustc", default=os.environ.get("RUSTC"))
    parser.add_argument("--cc")
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--output", required=True, help="new report path; earlier successful or failed attempts are preserved")
    args = parser.parse_args(argv)
    try:
        report = run_qualification(rustc=args.rustc, cc=args.cc, repeats=args.repeats, output=args.output)
    except (QualificationFailed, ValueError, OSError) as error:
        print(str(error), file=sys.stderr)
        return 1
    print(json.dumps({"status": report["status"], "source_applications": len(report["source_cases"]),
                      "rejection_controls": len(report["rejections"]), "repeats": report["repeats"], "report": args.output}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
