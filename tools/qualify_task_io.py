"""Execute and source-replay the bounded task-tree/local-reactor composition.

Every planned source, fault/race control and wrong-runtime binary is retained.
The receipt binds current source, tool, command, binary and raw stream bytes;
it is not an authentication scheme for an arbitrary third-party JSON author.
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
import shutil
import stat
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hepta.backend import GROUP_RUNTIME, TASK_RUNTIME, find_rustc
from hepta.pipeline import analyze, analyze_project, compiler_hash
from hepta.runtime_io import IO_RUNTIME
from hepta.runtime_task_io import TASK_IO_RUNTIME
from tools.evidence_checks import require, strict_equal

SCHEMA = "hepta.task-io.evidence.v1"
SCENARIOS = {"pipeline": "4\n256\n0\n", "cancellation": "2\n1\n1\n", "recovery": "1\n1\n16\n"}
CONTROL_COUNTS = {
    "blocking_cancel_cases": 2, "partial_cancel_cases": 1,
    "timeout_recovery_cases": 1, "poll_error_recovery_cases": 1,
    "native_drop_cases": 1, "completed_before_cancel_cases": 1,
    "budget_refusal_dimensions": 4, "metadata_allocation_refusals": 2,
    "wake_socket_refusals": 1, "registration_limit_recovery_cases": 1,
    "wake_nonblocking_refusals": 2, "final_canceller_arc_cleanup_cases": 1,
    "refused_subtree_cleanup_recovery_cases": 1,
    "parent_child_cancel_failure_races": 64, "attachment_cancel_races": 64,
    "readiness_cancel_races": 64, "shared_byte_admission_races": 32,
}
CLAIMS = {
    "worker_owned_reactor_tree_cancellation_qualified": True,
    "explicit_shared_pool_io_reservations_qualified": True,
    "actual_native_fault_and_race_controls_executed": True,
    "source_and_emitted_runtime_replayed": True,
    "cross_thread_reactor_access_exposed": False,
    "whole_process_allocation_or_actual_stack_budget": False,
    "async_await_or_background_executor": False,
    "TCP_TLS_or_arbitrary_file_IO": False,
    "hard_realtime_or_arbitrary_worker_termination_proved": False,
    "independent_IO_IR_or_source_runtime_refinement_proved": False,
    "performance_measured": False,
    "arbitrary_third_party_execution_authenticated": False,
}
PROFILE = {
    "host": "x86_64-unknown-linux-gnu", "rust": "1.90.0",
    "attachment_authority": "worker_read_Sender_u64",
    "reactor_ownership": "exclusive_single_thread_not_Send_or_Sync",
    "cancellation": "group_state_registration_and_owned_socket_peer_close",
    "pool_charges": ["reactors", "configured_endpoint_slots_plus_two_wakeup_endpoints",
                     "configured_request_slots", "all_admitted_Vec_capacity_until_collection"],
    "maximum_pool_reactors": 256, "maximum_group_registrations": 64,
    "ordinary_Arc_OOM_or_abort_recoverable": False,
}
SOURCE_FILES = ["tools/qualify_task_io.py", "tools/fixtures/task_io_controls.rs",
                "tools/fixtures/task_io_faults.c", "hepta/runtime_task_io.py",
                "hepta/runtime_io.py", "hepta/runtime_concurrency.py", "hepta/runtime_task_tree.py",
                *[f"examples/task_io/{name}.hepta" for name in SCENARIOS]]
RUST_FLAGS = ["--edition=2021", "--crate-name=hepta_task_io", "--crate-type=bin",
              "-C", "opt-level=3", "-C", "overflow-checks=yes", "-C", "panic=abort", "-C", "codegen-units=1"]
C_FLAGS = ["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"]
MUTANTS = {
    "lost_wakeup": ("drop(socket);", "core::mem::forget(socket);", "timeout", "waiting-for-real-cancellation\n"),
    "budget_bypass": ("if total.is_none() || total.unwrap()>usage.h_byte_limit {", "if total.is_none() {", "nonzero", "shared byte budget ignored"),
    "reservation_leak": ("if let Some(task)=&io.task {task.release_bytes(operation.data.capacity())}", "// deliberately omitted shared reservation release", "nonzero", "I/O reservation leak"),
    "buffer_leak": ("let _=io_remove(io,index);", "core::mem::forget(io_remove(io,index));", "nonzero", "actual buffer leak"),
    "drop_lock_inversion": (
        'drop(self.wake_write.get_mut().expect("Hepta I/O wake poisoned").take());',
        'let _wrong_lock=self.group.state.lock().expect("deliberately inverted drop lock");\n'
        '        drop(self.wake_write.get_mut().expect("Hepta I/O wake poisoned").take());',
        "timeout", "waiting-for-canceller-owned-drop\n"),
}
EFFECTS = "alloc,block,panic,io,write"
WORKER = f"fn w(data:take Buffer<u8>,c:read Cancellation,s:read Sender<u64>)->u64 effects {{{EFFECTS}}}{{release(move data);let mut io=io_reactor(2,1,8);"
END = "io_shutdown(move io);return 0;}"
REJECTIONS = {
    "reactor_early_exit": (WORKER + "io_attach(mut io,read s);return 0;}", "E_LINEAR_UNCONSUMED"),
    "wrong_attachment_authority": (WORKER + "io_attach(mut io,read c);" + END, "E_TYPE"),
    "readonly_attachment": (WORKER + "io_attach(read io,read s);" + END, "E_BORROW_MODE"),
    "sender_copy": (WORKER + "let copy=s;" + END, "E_SENDER_TYPE"),
    "report_forgery": ("fn f()->Unit effects {}{let x=GroupIoReport{};}", "E_REPORT_CONSTRUCTION"),
    "reactor_after_shutdown": (WORKER + "io_shutdown(move io);io_report(read io);return 0;}", "E_USE_AFTER_MOVE"),
    "missing_io_effect": ((WORKER + "io_attach(mut io,read s);" + END).replace(f"effects {{{EFFECTS}}}", "effects {alloc,block,panic,write}"), "E_EFFECT"),
    "snapshot_wrong_owner": (WORKER + "group_io_snapshot(read io);" + END, "E_TYPE"),
    "opaque_group_budget_report": ("struct GroupIoReport{x:u64}", "E_DUPLICATE"),
    "attachment_wrong_arity": (WORKER + "io_attach(mut io);" + END, "E_ARITY"),
}
NATIVE_ALIAS = ("fn both(a:mut IoReactor,b:mut IoReactor)->Unit effects {}{}" + WORKER
                + "both(mut io,mut io);" + END + "fn main()->Unit effects {}{}")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def identities():
    return {name: digest((ROOT / name).read_bytes()) for name in SOURCE_FILES}


def controls_source(kind="positive"):
    source = ("#![allow(dead_code,unused,non_camel_case_types)]\n" + TASK_RUNTIME + GROUP_RUNTIME
              + IO_RUNTIME.replace("// HEPTA_IO_GROUP_INSERTION", TASK_IO_RUNTIME)
              .replace("// HEPTA_IO_TEST_INSERTION", (ROOT / "tools/fixtures/task_io_controls.rs").read_text()))
    if kind != "positive":
        old, new, _, _ = MUTANTS[kind]
        require(source.count(old) == 1, "wrong-runtime mutation boundary changed: " + kind)
        source = source.replace(old, new, 1)
    return source + f'\nfn main(){{__hepta_task_io_controls("{kind}")}}\n'


def _read(path):
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        metadata = os.fstat(fd)
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_size <= 64 * 1024 * 1024, "not a bounded regular artifact")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(64 * 1024 * 1024 + 1)
        after = os.fstat(fd)
        require(len(data) == metadata.st_size and (metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns)
                == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns), "artifact changed during read")
        return data
    finally:
        os.close(fd)


def artifact(path):
    path = Path(path).absolute(); data = _read(path)
    return {"path": str(path), "sha256": digest(data), "bytes": len(data)}


def _keys(value, expected, message):
    require(type(value) is dict and set(value) == set(expected), message)


def check_artifact(value, path=None, content=None):
    _keys(value, {"path", "sha256", "bytes"}, "artifact schema changed")
    require(type(value["path"]) is str and type(value["bytes"]) is int and value["bytes"] >= 0, "invalid artifact identity")
    if path is not None:
        require(value["path"] == str(Path(path).absolute()), "artifact path changed")
    require(strict_equal(value, artifact(value["path"])), "retained artifact bytes differ")
    if content is not None:
        require(_read(value["path"]) == content, "retained artifact is not the exact current render")


def _stream(path, data):
    Path(path).write_bytes(data)
    try:
        decoded = data.decode("utf-8")
    except UnicodeDecodeError:
        decoded = None
    return {**artifact(path), "base64": base64.b64encode(data).decode("ascii"), "text": decoded}


def _check_stream(value, path):
    _keys(value, {"path", "sha256", "bytes", "base64", "text"}, "stream schema changed")
    check_artifact({k: value[k] for k in ("path", "sha256", "bytes")}, path)
    data = _read(path)
    require(value["base64"] == base64.b64encode(data).decode("ascii"), "stream bytes/base64 differ")
    try:
        decoded = data.decode("utf-8")
    except UnicodeDecodeError:
        decoded = None
    require(strict_equal(value["text"], decoded), "stream text differs from raw bytes")
    return decoded


def _run(command, prefix, record, checkpoint, timeout=30):
    record.update(status="running", argv=list(command), timeout_seconds=timeout, returncode=None,
                  timed_out=False, elapsed_ns=None, stdout=None, stderr=None, spawn_error=None)
    checkpoint(); start = time.monotonic_ns()
    try:
        process = subprocess.run(command, cwd=ROOT, capture_output=True, timeout=timeout)
        stdout, stderr = process.stdout, process.stderr
        record.update(status="completed", returncode=process.returncode)
    except subprocess.TimeoutExpired as error:
        stdout, stderr = error.stdout or b"", error.stderr or b""
        record.update(status="timed_out", timed_out=True)
    except OSError as error:
        stdout, stderr = b"", b""
        record.update(status="start_failed", spawn_error=f"{type(error).__name__}: {error}")
    record["elapsed_ns"] = time.monotonic_ns() - start
    record["stdout"] = _stream(str(prefix) + ".stdout.bin", stdout)
    record["stderr"] = _stream(str(prefix) + ".stderr.bin", stderr)
    checkpoint()


def _check_process(value, command, prefix, timeout, outcome="zero", diagnostic=None):
    _keys(value, {"status", "argv", "timeout_seconds", "returncode", "timed_out", "elapsed_ns", "stdout", "stderr", "spawn_error"}, "process schema changed")
    require(strict_equal(value["argv"], command) and type(value["timeout_seconds"]) is int
            and value["timeout_seconds"] == timeout, "actual command or timeout changed")
    require(type(value["elapsed_ns"]) is int and value["elapsed_ns"] > 0 and value["spawn_error"] is None, "missing actual process observation")
    stdout = _check_stream(value["stdout"], str(prefix) + ".stdout.bin")
    stderr = _check_stream(value["stderr"], str(prefix) + ".stderr.bin")
    if outcome == "timeout":
        require(value["status"] == "timed_out" and value["timed_out"] is True and value["returncode"] is None
                and value["elapsed_ns"] >= timeout * 1_000_000_000, "wrong-runtime timeout was not observed")
        require(stdout == diagnostic, "timeout did not reach its native blocking control")
    else:
        require(value["status"] == "completed" and value["timed_out"] is False and type(value["returncode"]) is int, "process was not completed")
        require((value["returncode"] == 0) if outcome == "zero" else value["returncode"] != 0, "unexpected process result")
        require(type(stdout) is str and type(stderr) is str, "successful observation needs strict UTF-8 output")
        if outcome == "zero":
            require(stderr == "", "unexpected successful-process stderr")
        else:
            require(diagnostic in stderr, "wrong-runtime/compiler control failed for an unrelated reason")
    return stdout


def _metrics(stdout):
    value = json.loads(stdout)
    _keys(value, {*CONTROL_COUNTS, "tracked_allocations", "tracked_frees", "live_buffers", "real_poll_entries"}, "native case denominator changed")
    require(all(type(x) is int for x in value.values()), "native counts must be integers, never booleans")
    require(all(value[k] == n for k, n in CONTROL_COUNTS.items()), "native control denominator incomplete")
    # 208 fixed live-buffer observations, plus at most one in each of the 64
    # registration/cancellation races. Early cancellation may prevent admission.
    require(208 <= value["tracked_allocations"] <= 272 and value["tracked_allocations"] == value["tracked_frees"]
            and value["live_buffers"] == 0 and value["real_poll_entries"] >= 70, "native resource cleanup/waits were not observed")
    return value


def _plan():
    return ([{"name": name, "kind": "source"} for name in SCENARIOS]
            + [{"name": "positive", "kind": "controls"}]
            + [{"name": name, "kind": "mutant"} for name in MUTANTS]
            + [{"name": "native_alias", "kind": "native_rejection"}])


class QualificationFailed(RuntimeError):
    def __init__(self, report):
        self.report = report
        super().__init__(report.get("failure", "task/I/O qualification failed"))


def run_qualification(*, output, rustc=None, cc=None, repeats=3):
    require(type(repeats) is int and 1 <= repeats <= 20, "repeats must be 1..20")
    target = Path(output).absolute(); target.parent.mkdir(parents=True, exist_ok=True)
    directory = target.with_suffix(".files")
    report = {"schema": SCHEMA, "status": "running", "ok": False, "created_utc": datetime.now(timezone.utc).isoformat(),
              "compiler_sha256": compiler_hash(), "source_files": identities(), "profile": json.loads(canonical(PROFILE)),
              "claims": dict(CLAIMS), "host": {"system": platform.system(), "machine": platform.machine()},
              "repeats": repeats, "artifact_directory": str(directory), "tools": {}, "c_build": {},
              "cases": [{**row, "status": "not_run", "failure": None, "source": None, "analysis": None, "build": {},
                         "binary": None, "runs": [{"trial": i, "status": "not_run"} for i in range(repeats)] if row["kind"] != "native_rejection" else []}
                        for row in _plan()], "rejections": [], "failure": None}
    with target.open("x") as stream:
        json.dump(report, stream, indent=2, sort_keys=True)

    def checkpoint():
        with tempfile.NamedTemporaryFile("w", dir=target.parent, delete=False, prefix=target.name + ".") as stream:
            json.dump(report, stream, indent=2, sort_keys=True); stream.write("\n"); temporary = stream.name
        os.replace(temporary, target)

    try:
        directory.mkdir(exist_ok=False)
        require(report["host"] == {"system": "Linux", "machine": "x86_64"}, "unqualified native host")
        selected = {"rust": find_rustc(rustc), "c": shutil.which(cc or "gcc")}
        require(selected["c"] is not None, "native C compiler is missing")
        for name, command in selected.items():
            command = str(Path(command).absolute())
            tool = {"invocation_path": command, "executable": artifact(Path(command).resolve()), "version": {}}
            report["tools"][name] = tool
            _run([command, "-vV" if name == "rust" else "--version"], directory / (name + "-version"), tool["version"], checkpoint)
        rust = report["tools"]["rust"]["invocation_path"]; c = report["tools"]["c"]["invocation_path"]
        require(report["tools"]["rust"]["version"]["stdout"]["text"].startswith("rustc 1.90.0 ")
                and "host: x86_64-unknown-linux-gnu\n" in report["tools"]["rust"]["version"]["stdout"]["text"], "pinned Rust/host mismatch")
        fixture = directory / "faults.c"; fixture.write_bytes((ROOT / "tools/fixtures/task_io_faults.c").read_bytes())
        obj = directory / "faults.o"
        report["c_build"] = {"source": artifact(fixture), "process": {}, "object": None}
        _run([c, *C_FLAGS, "-c", str(fixture), "-o", str(obj)], directory / "compile-c", report["c_build"]["process"], checkpoint)
        if obj.is_file():
            report["c_build"]["object"] = artifact(obj)
        require(report["c_build"]["process"]["returncode"] == 0 and report["c_build"]["object"] is not None, "native fault-control build failed")
        for row in report["cases"]:
            name, kind = row["name"], row["kind"]; row["status"] = "running"; checkpoint()
            try:
                if kind == "source":
                    current = analyze_project(ROOT / f"examples/task_io/{name}.hepta", native=False, crate_type="bin")
                    row["analysis"] = current.report; require(current.report["ok"] is True, "source program rejected")
                    source = current.rust
                elif kind == "native_rejection":
                    current = analyze(NATIVE_ALIAS, path="<task-io-native-alias>", native=False, crate_type="bin")
                    row["analysis"] = current.report; require(current.report["ok"] is True, "native alias control did not reach Rust")
                    source = current.rust
                else:
                    source = controls_source(name)
                source_path = directory / (name + ".rs"); source_path.write_text(source)
                row["source"] = artifact(source_path); binary = directory / (name + ".bin")
                links = [] if kind in {"source", "native_rejection"} else ["-C", "link-arg=" + str(obj), "-C", "link-arg=-Wl,--wrap=poll", "-C", "link-arg=-Wl,--wrap=socketpair", "-C", "link-arg=-Wl,--wrap=ioctl"]
                command = [rust, *RUST_FLAGS, str(source_path), "-o", str(binary), *links]
                _run(command, directory / (name + "-build"), row["build"], checkpoint)
                if kind == "native_rejection":
                    _check_process(row["build"], command, directory / (name + "-build"), 30, "nonzero", "E0499")
                    require(not binary.exists(), "rejected alias control produced an executable")
                else:
                    require(row["build"]["returncode"] == 0 and row["build"]["timed_out"] is False and binary.is_file(), "native build failed")
                    row["binary"] = artifact(binary)
                    for run in row["runs"]:
                        trial = run["trial"]; run.clear(); run.update(trial=trial, binary_before=artifact(binary), binary_after=None, process={}, metrics=None)
                        timeout = 2 if kind == "mutant" and MUTANTS[name][2] == "timeout" else 30
                        _run([str(binary)], directory / f"{name}-run-{trial}", run["process"], checkpoint, timeout)
                        run["binary_after"] = artifact(binary); checkpoint()
                        outcome, diagnostic = MUTANTS[name][2:] if kind == "mutant" else ("zero", None)
                        stdout = _check_process(run["process"], [str(binary)], directory / f"{name}-run-{trial}", timeout, outcome, diagnostic)
                        if kind == "source":
                            require(stdout == SCENARIOS[name], "source result differs")
                        elif kind == "controls":
                            run["metrics"] = _metrics(stdout)
                row["status"] = "passed"
            except Exception as error:
                row["status"] = "failed"; row["failure"] = f"{type(error).__name__}: {error}"
            checkpoint()
        for name, (source, code) in REJECTIONS.items():
            observed = analyze(source, path=f"<task-io:{name}>", native=False).report
            report["rejections"].append({"name": name, "source_sha256": digest(source.encode()), "report": observed})
            checkpoint()
        require(all(row["status"] == "passed" for row in report["cases"]), "one or more planned cases failed")
        report["status"] = "passed"; report["ok"] = True
        validate_report(report, minimum_repeats=repeats); checkpoint(); return report
    except Exception as error:
        report.update(status="failed", ok=False, failure=f"{type(error).__name__}: {error}")
        checkpoint(); raise QualificationFailed(report) from error


def validate_report(report, *, minimum_repeats=3):
    """Replay source/bytes and check completed observations, without execution."""
    try:
        _validate(report, minimum_repeats)
    except (KeyError, TypeError, AttributeError, OSError, json.JSONDecodeError) as error:
        raise ValueError("malformed or unavailable task/I/O evidence: " + str(error)) from error


def _validate(report, minimum_repeats):
    _keys(report, {"schema", "status", "ok", "created_utc", "compiler_sha256", "source_files", "profile", "claims", "host", "repeats", "artifact_directory", "tools", "c_build", "cases", "rejections", "failure"}, "report schema changed")
    require(report["schema"] == SCHEMA and report["status"] == "passed" and report["ok"] is True and report["failure"] is None, "qualification did not pass")
    require(type(minimum_repeats) is int and 1 <= minimum_repeats <= 20 and type(report["repeats"]) is int
            and minimum_repeats <= report["repeats"] <= 20, "repetition denominator changed")
    require(type(report["created_utc"]) is str and datetime.fromisoformat(report["created_utc"]).utcoffset() is not None, "missing timestamp")
    require(report["compiler_sha256"] == compiler_hash() and strict_equal(report["source_files"], identities()), "current compiler/input bytes differ")
    require(strict_equal(report["profile"], PROFILE) and strict_equal(report["claims"], CLAIMS)
            and strict_equal(report["host"], {"system": "Linux", "machine": "x86_64"}), "unsupported scope/host claim")
    directory = Path(report["artifact_directory"])
    require(directory.is_absolute() and directory.is_dir() and not directory.is_symlink(), "retained artifact directory is missing")
    _keys(report["tools"], {"rust", "c"}, "tool denominator changed")
    for name, tool in report["tools"].items():
        _keys(tool, {"invocation_path", "executable", "version"}, "tool schema changed")
        require(type(tool["invocation_path"]) is str and Path(tool["invocation_path"]).is_absolute(), "tool invocation path missing")
        check_artifact(tool["executable"], Path(tool["invocation_path"]).resolve())
        stdout = _check_process(tool["version"], [tool["invocation_path"], "-vV" if name == "rust" else "--version"], directory / (name + "-version"), 30)
        if name == "rust":
            require(stdout.startswith("rustc 1.90.0 ") and "host: x86_64-unknown-linux-gnu\n" in stdout, "Rust identity/profile differs")
        else:
            require(bool(stdout.strip()), "C version observation missing")
    rust = report["tools"]["rust"]["invocation_path"]; c = report["tools"]["c"]["invocation_path"]
    cb = report["c_build"]; _keys(cb, {"source", "process", "object"}, "C build schema changed")
    check_artifact(cb["source"], directory / "faults.c", (ROOT / "tools/fixtures/task_io_faults.c").read_bytes())
    check_artifact(cb["object"], directory / "faults.o"); require(cb["object"]["bytes"] > 0, "empty native C object")
    _check_process(cb["process"], [c, *C_FLAGS, "-c", str(directory / "faults.c"), "-o", str(directory / "faults.o")], directory / "compile-c", 30)
    cases = report["cases"]
    require(type(cases) is list and len(cases) == len(_plan()), "planned case denominator changed")
    for row, planned in zip(cases, _plan()):
        _keys(row, {"name", "kind", "status", "failure", "source", "analysis", "build", "binary", "runs"}, "case schema changed")
        require(row["name"] == planned["name"] and row["kind"] == planned["kind"] and row["status"] == "passed" and row["failure"] is None, "case failed, missing or reordered")
        name, kind = row["name"], row["kind"]
        if kind == "source":
            current = analyze_project(ROOT / f"examples/task_io/{name}.hepta", native=False, crate_type="bin")
        elif kind == "native_rejection":
            current = analyze(NATIVE_ALIAS, path="<task-io-native-alias>", native=False, crate_type="bin")
        else:
            current = None
        if current is not None:
            require(current.report["ok"] is True and strict_equal(row["analysis"], current.report), "source/checker/semantic report differs on fresh replay")
            source = current.rust
        else:
            require(row["analysis"] is None, "runtime control masquerades as source analysis"); source = controls_source(name)
        source_path = directory / (name + ".rs"); binary = directory / (name + ".bin")
        check_artifact(row["source"], source_path, source.encode())
        links = [] if kind in {"source", "native_rejection"} else ["-C", "link-arg=" + str(directory / "faults.o"), "-C", "link-arg=-Wl,--wrap=poll", "-C", "link-arg=-Wl,--wrap=socketpair", "-C", "link-arg=-Wl,--wrap=ioctl"]
        _check_process(row["build"], [rust, *RUST_FLAGS, str(source_path), "-o", str(binary), *links], directory / (name + "-build"), 30,
                       "nonzero" if kind == "native_rejection" else "zero", "E0499" if kind == "native_rejection" else None)
        if kind == "native_rejection":
            require(row["binary"] is None and row["runs"] == [] and not binary.exists(), "compile rejection acquired fake execution"); continue
        check_artifact(row["binary"], binary); require(row["binary"]["bytes"] > 0, "empty native executable")
        require(type(row["runs"]) is list and len(row["runs"]) == report["repeats"], "execution trial denominator changed")
        for trial, run in enumerate(row["runs"]):
            _keys(run, {"trial", "binary_before", "binary_after", "process", "metrics"}, "run schema changed")
            require(type(run["trial"]) is int and run["trial"] == trial and strict_equal(run["binary_before"], row["binary"])
                    and strict_equal(run["binary_after"], row["binary"]), "execution does not bind the compiled binary before/after")
            outcome, diagnostic = MUTANTS[name][2:] if kind == "mutant" else ("zero", None)
            stdout = _check_process(run["process"], [str(binary)], directory / f"{name}-run-{trial}", 2 if outcome == "timeout" else 30, outcome, diagnostic)
            if kind == "controls":
                require(strict_equal(run["metrics"], _metrics(stdout)), "native metrics differ from raw output")
            else:
                require(run["metrics"] is None, "invented metrics")
                if kind == "source": require(stdout == SCENARIOS[name], "source output changed")
    rejected = report["rejections"]
    require(type(rejected) is list and len(rejected) == len(REJECTIONS), "source rejection denominator changed")
    for row, (name, (source, code)) in zip(rejected, REJECTIONS.items()):
        _keys(row, {"name", "source_sha256", "report"}, "rejection schema changed")
        current = analyze(source, path=f"<task-io:{name}>", native=False).report
        require(row["name"] == name and row["source_sha256"] == digest(source.encode()) and strict_equal(row["report"], current), "rejection source/checker identity differs")
        require(current["ok"] is False and code in {item["code"] for item in current["diagnostics"]}, "invalid source was not rejected")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--rustc", default=os.environ.get("RUSTC"))
    parser.add_argument("--cc")
    parser.add_argument("--repeats", type=int, default=3)
    args = parser.parse_args(argv)
    try:
        report = run_qualification(output=args.output, rustc=args.rustc, cc=args.cc, repeats=args.repeats)
    except (QualificationFailed, ValueError, OSError) as error:
        print(str(error), file=sys.stderr); return 1
    print(json.dumps({"ok": report["ok"], "status": report["status"], "cases": len(report["cases"]), "repeats": report["repeats"], "report": args.output})); return 0


if __name__ == "__main__":
    raise SystemExit(main())
