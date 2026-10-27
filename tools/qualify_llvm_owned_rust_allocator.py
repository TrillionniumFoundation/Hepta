"""Untimed real allocator refusal for the two unchanged owned Rust baselines.

This is additional correctness evidence, not a revision of any performance
attempt. Each application source is an exact prefix of its instrumented
program. The appended GlobalAlloc observer forwards to System except for
explicit refusal and the separately compiled deallocation-omission control.
Retained files/receipts establish local consistency, not authentication of
arbitrary third-party JSON. validate_report never executes native programs.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

from hepta.backend import RUST_VERSION, compile_rust
from hepta.pipeline import analyze, compiler_hash
from tools import qualify_llvm_owned as frozen
from tools.evidence_checks import native_build, normalized_errors, require, strict_equal

SCHEMA = "hepta.llvm-owned-rust-allocator-qualification.v1"
BACKENDS = ("rust", "handwritten_rust")
MODES = ("normal", "leak")
OBSERVER_PATH = "examples/llvm_owned/rust_allocator_observer.rs"
INPUTS = ("tools/qualify_llvm_owned_rust_allocator.py", OBSERVER_PATH,
          "tools/evidence_checks.py", "tools/qualify_llvm_owned.py",
          "examples/llvm_owned/owned.hepta", "examples/llvm_owned/qualification.hepta",
          "examples/llvm_owned/reference.rs")
CLAIMS = {
    "application_sources_unchanged": True,
    "actual_first_and_second_refusal_observed": True,
    "cleanup_and_recovery_observed": True,
    "compiled_deallocation_omission_detected": True,
    "performance_measured": False,
    "original_performance_attempt_modified": False,
    "original_measured_binaries_instrumented": False,
    "whole_language_memory_safety_proved": False,
    "arbitrary_third_party_execution_authenticated": False,
}
PROTOCOL = {
    "id": "hepta.llvm-owned-rust-allocator-observation.v1",
    "scope": "new untimed correctness only; unchanged application prefixes plus System allocator observer",
    "target": "x86_64-unknown-linux-gnu",
    "fixed_calls": [[3, 0, 22], [5, 1, 2], [0, 0, 19], [12281, 0, 1], [18446744073709551615, 0, 1]],
    "second_refusal_size": 12281,
    "first_refusal_size": 7,
    "recovery_call": [3, 0, 22],
    "first_refusal_result": 101,
    "negative_control": "omit System.dealloc while tracking; application Drop calls unchanged",
    "negative_exit_code": 86,
    "process_timeout_seconds": 10,
    "native_process_denominator": 4,
    "optimization_policy": "observed counts must match; do not manufacture requests removed by optimization",
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def inputs():
    return {name: sha((ROOT / name).read_bytes()) for name in INPUTS}


def current_sources():
    source = (ROOT / "examples/llvm_owned/owned.hepta").read_text() + "\n" + (
        ROOT / "examples/llvm_owned/qualification.hepta").read_text()
    reference = (ROOT / "examples/llvm_owned/reference.rs").read_text()
    require(source == frozen.SOURCE and reference == frozen.RUST_REFERENCE,
            "Frozen qualifier sources changed after module import; start a fresh qualification")
    return source, reference


def path_text(path):
    path = Path(path).resolve()
    return str(path.relative_to(ROOT)) if path.is_relative_to(ROOT) else str(path)


def resolve(path):
    path = Path(path)
    return (path if path.is_absolute() else ROOT / path).resolve()


def identity(path):
    data = Path(path).read_bytes()
    return {"path": path_text(path), "sha256": sha(data), "bytes": len(data)}


def expected_observations(backend, mode):
    def row(phase, calls, allocated, freed, live, refused, ok):
        return {"backend": backend, "negative_control": mode == "leak", "phase": phase,
                "calls": calls, "allocations": allocated, "frees": freed, "live": live,
                "refusals": refused, "attempts": allocated + refused, "system_refusals": 0, "ok": ok}
    if mode == "leak":
        return [row("fixed_five", [22, 2, 19, 1, 1], 7, 0, 7, 1, False)]
    return [row("fixed_five", [22, 2, 19, 1, 1], 7, 7, 0, 1, True),
            row("second_refusal_recovery", [22], 9, 9, 0, 1, True),
            row("first_refusal", [101], 0, 0, 0, 1, True),
            row("first_refusal_recovery", [22], 2, 2, 0, 1, True)]


def render(application, backend, mode):
    require(backend in BACKENDS and mode in MODES, "Unknown observer configuration")
    observer = (ROOT / OBSERVER_PATH).read_text()
    require(observer.count("__HEPTA_OBSERVER_BACKEND__") == 1
            and observer.count("__HEPTA_OBSERVER_LEAK__") == 1, "Observer template markers differ")
    observer = observer.replace("__HEPTA_OBSERVER_BACKEND__", backend)
    observer = observer.replace("__HEPTA_OBSERVER_LEAK__", "true" if mode == "leak" else "false")
    return application + "\n" + observer


def _stream(data, path):
    if isinstance(data, str):
        data = data.encode()
    data = data or b""
    path.write_bytes(data)
    return {"text": data.decode("utf-8", errors="replace"),
            "base64": base64.b64encode(data).decode(), "file": identity(path)}


def _execute(row, executable):
    # Install the row before launch: timeouts/launch failures preserve partial
    # stdout/stderr bytes and do not erase earlier or later denominator rows.
    record = {"argv": [path_text(executable)], "executable_sha256": sha(executable.read_bytes()),
              "status": "running", "returncode": None, "stdout": None, "stderr": None}
    row["execution"] = record
    stdout, stderr = b"", b""
    try:
        process = subprocess.run(record["argv"], cwd=ROOT, capture_output=True,
                                 timeout=PROTOCOL["process_timeout_seconds"])
        stdout, stderr = process.stdout, process.stderr
        record.update(status="completed", returncode=process.returncode)
    except subprocess.TimeoutExpired as error:
        stdout, stderr = error.stdout, error.stderr
        record["status"] = "timeout"
        raise
    except OSError:
        record["status"] = "launch_failed"
        raise
    finally:
        record["stdout"] = _stream(stdout, Path(str(executable) + ".stdout.bin"))
        record["stderr"] = _stream(stderr, Path(str(executable) + ".stderr.bin"))


def _file(record, path, expected=None):
    try:
        require(isinstance(record, dict) and set(record) == {"path", "sha256", "bytes"}
                and resolve(record["path"]) == path.resolve()
                and strict_equal(record, identity(path)), "Retained file identity/path differs")
        if expected is not None:
            require(path.read_bytes() == expected, "Retained source is not the exact current source/observer composition")
    except OSError as error:
        raise ValueError("Retained artifact unavailable: " + str(error)) from error


def _execution(row, directory):
    backend, mode = row["backend"], row["mode"]
    executable = directory / (backend + "." + mode)
    record = row["execution"]
    require(set(record) == {"argv", "executable_sha256", "status", "returncode", "stdout", "stderr"}
            and strict_equal(record["argv"], [path_text(executable)])
            and record["status"] == "completed"
            and type(record["returncode"]) is int
            and record["returncode"] == (86 if mode == "leak" else 0)
            and record["executable_sha256"] == row["artifact"]["sha256"], "Native observer execution is missing/misbound")
    for name in ("stdout", "stderr"):
        stream = record[name]
        require(isinstance(stream, dict) and set(stream) == {"text", "base64", "file"}, "Native stream schema differs")
        data = base64.b64decode(stream["base64"], validate=True)
        require(stream["text"] == data.decode("utf-8", errors="replace"), "Native stream decoded text differs")
        _file(stream["file"], Path(str(executable) + "." + name + ".bin"), data)
    require(record["stderr"]["text"] == "", "Native observer emitted stderr")
    actual = [json.loads(line) for line in record["stdout"]["text"].splitlines()]
    require(strict_equal(actual, row["observations"])
            and strict_equal(actual, expected_observations(backend, mode)), "Actual refusal/cleanup/recovery observations differ")


def _native_frontend(actual, expected):
    require(set(actual) == set(expected) | {"backend"}, "Native source validation schema differs")
    for key in expected:
        if key not in {"status", "checks", "borrowed_storage"}:
            require(strict_equal(actual[key], expected[key]), "Current source validation differs: " + key)
    require(actual["status"] == "checked" and strict_equal(actual["checks"],
            dict(expected["checks"], rust_borrows_types="rustc_checked")), "Actual Rust metadata validation missing")
    if "borrowed_storage" in expected:
        require(strict_equal(actual["borrowed_storage"], dict(expected["borrowed_storage"], native_lifetimes_checked=True)),
                "Stored lifetime validation scope differs")
    native_build(actual["backend"], "rust", check_only=True, crate_type="cdylib", source_sha256=expected["rust_sha256"])


@normalized_errors
def validate_report(report):
    """Check current source, retained bytes and execution bindings without reruns."""
    require(isinstance(report, dict) and set(report) == {
        "schema", "ok", "status", "protocol", "performance_protocol_sha256", "claims", "inputs",
        "compiler_sha256", "directory", "hepta_source", "frontend", "baseline_sources", "rows", "validation_error"},
        "Allocator qualification schema differs")
    require(report["schema"] == SCHEMA and report["ok"] is True and report["status"] == "passed"
            and report["validation_error"] is None, "Not a passing untimed allocator qualification")
    require(strict_equal(report["protocol"], PROTOCOL) and strict_equal(report["claims"], CLAIMS)
            and report["performance_protocol_sha256"] == sha(wire(frozen.PROTOCOL)), "Untimed qualification scope differs")
    require(strict_equal(report["inputs"], inputs()) and report["compiler_sha256"] == compiler_hash(),
            "Current qualification/compiler inputs differ")
    directory = resolve(report["directory"])
    entry = directory / "kernels.hepta"
    source, reference = current_sources()
    _file(report["hepta_source"], entry, source.encode())
    fresh = analyze(source, str(entry), native=False, crate_type="cdylib")
    require(fresh.report["ok"] is True and fresh.report["assumptions"] == [], "Current source check failed")
    _native_frontend(report["frontend"], fresh.report)
    applications = {"rust": fresh.rust, "handwritten_rust": reference}
    require(set(report["baseline_sources"]) == set(BACKENDS), "Baseline denominator differs")
    for backend, source in applications.items():
        _file(report["baseline_sources"][backend], directory / (backend + ".rs"), source.encode())
    require(isinstance(report["rows"], list) and len(report["rows"]) == 4, "Four native observer/control runs required")
    tool = report["frontend"]["backend"]["toolchain"]
    require(tool["version"].startswith("rustc " + RUST_VERSION + " ")
            and sha(Path(tool["path"]).read_bytes()) == tool["executable_sha256"], "Pinned Rust executable differs")
    for row, (backend, mode) in zip(report["rows"], ((b, m) for b in BACKENDS for m in MODES)):
        require(set(row) == {"backend", "mode", "status", "instrumented_source", "build", "artifact",
                             "execution", "observations", "validation_error"}
                and strict_equal([row["backend"], row["mode"]], [backend, mode])
                and row["status"] == "completed" and row["validation_error"] is None, "Observer/control row missing or failed")
        source = render(applications[backend], backend, mode)
        _file(row["instrumented_source"], directory / (backend + "." + mode + ".rs"), source.encode())
        build = row["build"]
        native_build(build, "rust", check_only=False, crate_type="bin", source_sha256=sha(source.encode()))
        flags = ["edition=2021", "opt-level=3", "overflow-checks=yes", "panic=abort", "codegen-units=1"]
        if tool["sysroot"]:
            flags += ["sysroot=" + tool["sysroot"]]
        require(strict_equal(build["toolchain"], tool) and strict_equal(build["flags"], flags)
                and build["target"] == PROTOCOL["target"] and build["linker"] is None
                and build["link_args"] == [], "Native Rust toolchain/flags/target differs")
        executable = directory / (backend + "." + mode)
        _file(row["artifact"], executable)
        require(Path(build["artifact"]).resolve() == executable and build["artifact_sha256"] == row["artifact"]["sha256"]
                and type(build["artifact_bytes"]) is int and build["artifact_bytes"] == row["artifact"]["bytes"],
                "Compiled observer executable differs")
        _execution(row, directory)
    require(strict_equal(report["inputs"], inputs()) and report["compiler_sha256"] == compiler_hash(),
            "Qualification/compiler inputs changed during replay")
    return True


def qualify(output, *, rustc=None):
    output = Path(output).resolve()
    directory = output.with_suffix(".files")
    require(not any(p.exists() or p.is_symlink() for p in (output, directory)), "New report and artifact directory required")
    directory.mkdir(parents=True)
    rows = [{"backend": b, "mode": m, "status": "not_started", "instrumented_source": None, "build": None,
             "artifact": None, "execution": None, "observations": [], "validation_error": None}
            for b in BACKENDS for m in MODES]
    report = {"schema": SCHEMA, "ok": False, "status": "failed", "protocol": json.loads(wire(PROTOCOL)),
              "performance_protocol_sha256": sha(wire(frozen.PROTOCOL)),
              "claims": {key: False for key in CLAIMS}, "inputs": inputs(), "compiler_sha256": compiler_hash(),
              "directory": path_text(directory), "hepta_source": None, "frontend": None,
              "baseline_sources": {}, "rows": rows, "validation_error": None}
    errors = (OSError, RuntimeError, ValueError, KeyError, TypeError, AttributeError, subprocess.TimeoutExpired)
    try:
        require(platform.system() == "Linux" and platform.machine() in {"x86_64", "amd64"}, "Linux x86_64 host required")
        source, reference = current_sources()
        entry = directory / "kernels.hepta"
        entry.write_text(source)
        report["hepta_source"] = identity(entry)
        analysis = analyze(source, str(entry), native=True, rustc=rustc, crate_type="cdylib")
        report["frontend"] = analysis.report
        require(analysis.report["ok"] is True and analysis.report["checks"]["rust_borrows_types"] == "rustc_checked",
                "Actual pinned Rust source validation failed")
        applications = {"rust": analysis.rust, "handwritten_rust": reference}
        for backend, application in applications.items():
            baseline = directory / (backend + ".rs")
            baseline.write_text(application)
            report["baseline_sources"][backend] = identity(baseline)
        for row in rows:
            try:
                row["status"] = "building"
                backend, mode = row["backend"], row["mode"]
                source = render(applications[backend], backend, mode)
                emitted = directory / (backend + "." + mode + ".rs")
                emitted.write_text(source)
                row["instrumented_source"] = identity(emitted)
                executable = directory / (backend + "." + mode)
                row["build"] = compile_rust(source, rustc=rustc, crate_type="bin", output=executable)
                require(row["build"]["ok"] is True, "Actual observer/control compilation failed")
                row["artifact"] = identity(executable)
                row["status"] = "executing"
                _execute(row, executable)
                row["observations"] = [json.loads(line) for line in row["execution"]["stdout"]["text"].splitlines()]
                _execution(row, directory)
                row["status"] = "completed"
            except errors as error:
                row.update(status="failed", validation_error=type(error).__name__ + ": " + str(error))
        require(all(row["status"] == "completed" for row in rows), "One or more native observer/control rows failed; all rows retained")
        report.update(ok=True, status="passed", claims=dict(CLAIMS))
        validate_report(report)
    except errors as error:
        report.update(ok=False, status="failed", claims={key: False for key in CLAIMS},
                      validation_error=type(error).__name__ + ": " + str(error))
    with output.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write("\n")
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--rustc")
    args = parser.parse_args(argv)
    report = qualify(args.output, rustc=args.rustc)
    print(json.dumps({"ok": report["ok"], "status": report["status"], "report": str(args.output),
                      "validation_error": report["validation_error"]}, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
