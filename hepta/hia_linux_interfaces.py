"""Finite native Linux eventfd/pthread qualification at Hepta's scalar C ABI.

The C host owns OS handles and threads. HIA continues to admit only its existing
scalar exported ABI; this module does not add foreign syscalls or shared-memory
operations to Core. Reference mode qualifies the real host harness only.
"""
from __future__ import annotations

import errno
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

from .clang_capture import run_bounded
from .hia_native_differential import _pin_native_artifact
from .hia_program_llvm import (build_program_native, emit_program_llvm, native_host_profile,
                               native_driver_matches_host, _read_artifact, _implementation_hash)
from .native_tool_identity import digest_executable

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "experiments/hia_linux_interfaces"
SCENARIOS = ("normal", "allocation_fail_1", "allocation_fail_3", "eventfd_fail_1",
             "eventfd_fail_2", "thread_fail_1", "thread_fail_2", "read_eintr",
             "write_eintr", "completion_error", "cooperative_cancel")
CASE_ORDER = tuple(name for index, scenario in enumerate(SCENARIOS)
                   for name in ((scenario, "recovery") if index else (scenario,)))
LENGTHS = (64, 1, 7, 0, 32, 2, 16, 3)
SCHEMA = "hepta.hia.linux-interface-qualification.v1"


class LinuxInterfaceRejected(ValueError):
    pass


def _require(condition, message):
    if not condition:
        raise LinuxInterfaceRejected(message)


def protocol():
    return {
        "schema": "hepta.hia.linux-interface-protocol.v1",
        "hosts": ["native Linux x86_64 little-endian LP64", "native Linux AArch64 little-endian LP64"],
        "workers": 3, "jobs_per_case": 16, "case_order": list(CASE_ORDER),
        "callback_abi": "uint64_t worker_checksum(size_t count, uint32_t seed)",
        "eventfd": "nonblocking CLOEXEC semaphore work/completion counters",
        "host_owns": ["eventfd handles", "pthread creation and join", "work scheduling", "cooperative cancellation"],
        "callback_owns": "one private byte buffer per nonempty call, released before return",
        "kernel_error_probes": ["empty read EAGAIN", "UINT64_MAX write EINVAL", "saturated write EAGAIN"],
        "injected_faults": ["component allocation returns NULL", "eventfd startup returns EMFILE",
                            "pthread_create returns EAGAIN", "read/write returns EINTR once",
                            "completion write returns EIO"],
        "resource_meter": "direct linked component malloc/calloc/free calls; requested payload bytes only",
        "resource_exclusions": ["libc and pthread internal allocations", "allocator metadata", "thread stacks", "RSS"],
        "concurrency_probe": "first-job pthread barrier ensures all three workers participate and job lifetimes overlap",
        "thread_quiescence": "retain the first post-join procfs task count; require one task within 1000 one-ms polls",
        "recovery": "every injected-fault/cancellation case is followed by a complete normal batch in the same process",
        "unqualified": ["physical devices", "DMA", "MMIO", "hardware interrupts", "kernel drivers",
                        "RV64 or QEMU guest execution", "preemptive cancellation", "arbitrary concurrent HIA programs",
                        "backend refinement", "performance superiority"],
    }


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result, "duplicate JSON evidence field")
        result[key] = value
    return result


def _integer_fields(row, except_fields):
    for key, value in row.items():
        if key not in except_fields:
            _require(type(value) is int, "non-integer evidence field: " + key)


def _implementation_sources():
    """Bind the whole Python package, including frontend and native helpers.

    The broad closure deliberately invalidates concurrent implementation edits.
    This is provenance evidence, not a proof of the Python interpreter or host.
    """
    paths = sorted((ROOT / "hepta").rglob("*.py")) + [ROOT / "tools/qualify_hia_linux_interfaces.py"]
    return {str(path.relative_to(ROOT)): sha256(path.read_bytes()).hexdigest() for path in paths}


def _check_native_receipt(native, core, ir, output, host):
    expected = {"schema": "hepta.hia.program.native.v1", "ok": True,
                "status": "native_compiled_not_executed", "profile": ir.profile,
                "kind": "object", "output": str(output), "core_sha256": core.sha256,
                "input_sha256": core.input_sha256, "llvm_ir_sha256": ir.sha256,
                "implementation_sha256": ir.implementation_sha256,
                "exports": ["worker_checksum"], "target": host["target"],
                "cross_target_compilation": False, "build_host": host}
    _require(type(native) is dict and all(type(native.get(key)) is type(value) and native[key] == value
                                        for key, value in expected.items()),
             "Hepta object receipt does not name the actual native callback")
    toolchain = native.get("toolchain")
    _require(type(toolchain) is dict and type(toolchain.get("path")) is str
             and type(toolchain.get("sha256")) is str
             and digest_executable(Path(toolchain["path"])) == toolchain["sha256"],
             "native compiler identity changed")
    raw = _read_artifact(output)
    _require(type(native.get("artifact_sha256")) is str and
             sha256(raw).hexdigest() == native["artifact_sha256"]
             and type(native.get("artifact_bytes")) is int and len(raw) == native["artifact_bytes"],
             "Hepta object bytes changed")
    _require(_implementation_hash() == ir.implementation_sha256, "native implementation changed")
    return raw


def validate_observations(text, host):
    """Check observations against independent arithmetic and lifecycle predicates."""
    _require(type(text) is str and len(text.encode()) <= 512 * 1024, "oversized native evidence")
    rows = [json.loads(line, object_pairs_hook=_pairs,
                       parse_constant=lambda value: (_ for _ in ()).throw(LinuxInterfaceRejected(value)))
            for line in text.splitlines()]
    _require(len(rows) == len(CASE_ORDER) + 2, "incomplete or additional native case inventory")
    expected_probe = {"schema": "hepta.hia.linux-compiled-abi.v1", "machine": host["normalized_machine"],
                      "pointer_bits": 64, "size_t_bits": 64, "long_bits": 64, "u32_bits": 32,
                      "workers": 3, "jobs": 16}
    _require(type(rows[0]) is dict and rows[0] == expected_probe, "compiled architecture/ABI differs from host")
    _integer_fields(rows[0], {"schema", "machine"})
    errors = rows[1]
    expected_errors = {"schema": "hepta.hia.linux-eventfd-errors.v1", "empty_read": -1,
                       "empty_errno": errno.EAGAIN, "invalid_write": -1, "invalid_errno": errno.EINVAL,
                       "filled": 8, "full_write": -1, "full_errno": errno.EAGAIN,
                       "drained": 8, "value": 2**64 - 2}
    _require(type(errors) is dict and set(errors) == set(expected_errors) | {"fd_before", "fd_after"},
             "eventfd kernel evidence fields differ")
    _integer_fields(errors, {"schema"})
    _require(all(errors[key] == value for key, value in expected_errors.items())
             and 0 <= errors["fd_before"] == errors["fd_after"], "real eventfd errors or FD cleanup differ")
    fields = {"schema", "case", "startup_error", "fatal", "completed", "fd_before", "fd_after",
              "threads_before", "threads_after", "opened", "closed", "created", "joined",
              "threads_after_join", "thread_quiescence_polls",
              "active_jobs", "peak_jobs", "worker_mask",
              "read_eintr_injected", "write_eintr_injected", "completion_error_injected",
              "allocation_attempts", "allocations", "frees", "allocation_failures", "failed_job",
              "live_owners", "live_bytes", "peak_bytes", "invalid_frees", "meter_overflow", "jobs"}
    results = []
    for name, row in zip(CASE_ORDER, rows[2:]):
        _require(type(row) is dict and set(row) == fields and row["case"] == name
                 and row["schema"] == "hepta.hia.linux-interface-case.v1", "native case identity differs")
        _integer_fields(row, {"schema", "case", "jobs"})
        _require(0 <= row["fd_before"] == row["fd_after"] and
                 row["threads_before"] == row["threads_after"] == 1,
                 "file descriptor or thread resources leaked")
        _require(1 <= row["threads_after_join"] <= 4 and 0 <= row["thread_quiescence_polls"] <= 1000
                 and (row["thread_quiescence_polls"] > 0) == (row["threads_after_join"] > 1),
                 "thread quiescence observations are inconsistent")
        _require(row["opened"] == row["closed"] and row["created"] == row["joined"],
                 "opened handles or created threads were not discharged")
        _require(all(row[key] == 0 for key in ("live_owners", "live_bytes", "invalid_frees", "meter_overflow")),
                 "component allocator lifecycle differs")
        startup = name.startswith(("eventfd_fail_", "thread_fail_"))
        expected_opened = int(name[-1]) - 1 if name.startswith("eventfd_fail_") else 2
        expected_created = int(name[-1]) - 1 if name.startswith("thread_fail_") else 0 if startup else 3
        expected_errno = errno.EMFILE if name.startswith("eventfd_fail_") else errno.EAGAIN if startup else 0
        _require(row["opened"] == expected_opened and row["created"] == expected_created
                 and row["startup_error"] == expected_errno, "startup failure/rollback differs")
        _require(row["active_jobs"] == 0 and row["peak_jobs"] == (0 if startup else 1 if name == "cooperative_cancel" else 3),
                 "worker jobs did not overlap or remain active")
        _require(row["fatal"] == int(name == "completion_error"), "unexpected or hidden worker failure")
        for field, expected_name in (("read_eintr_injected", "read_eintr"),
                                     ("write_eintr_injected", "write_eintr"),
                                     ("completion_error_injected", "completion_error")):
            _require(row[field] == int(name == expected_name), "fault was not exercised exactly once")
        expected_count = 0 if startup else 1 if name == "cooperative_cancel" else 16
        if name == "completion_error":
            _require(1 <= row["completed"] <= 16, "completion failure never reached the callback")
        else:
            _require(row["completed"] == expected_count, "normal/cancelled completion count differs")
        failed = name.startswith("allocation_fail_")
        _require(row["allocation_failures"] == int(failed) and
                 ((0 <= row["failed_job"] < 16) if failed else row["failed_job"] == -1),
                 "allocation refusal was missing or unexpected")
        jobs = row["jobs"]
        _require(type(jobs) is list and len(jobs) == 16, "incomplete job observations")
        completed, attempts, successful_sizes, worker_mask = 0, 0, [], 0
        for index, job in enumerate(jobs):
            _require(type(job) is dict and set(job) == {"index", "count", "seed", "state", "worker", "result"},
                     "inexact job evidence")
            _integer_fields(job, set())
            count, seed = LENGTHS[index % len(LENGTHS)], (2**32 - 1 if index % 3 == 0 else index * 73)
            _require((job["index"], job["count"], job["seed"]) == (index, count, seed)
                     and job["state"] in {0, 2}, "job input or final state differs")
            if job["state"] == 0:
                _require(job["result"] == 0 and job["worker"] == -1 and index != row["failed_job"],
                         "unexecuted job acquired a result")
                continue
            _require(0 <= job["worker"] < 3, "completed job lacks an actual worker")
            worker_mask |= 1 << job["worker"]
            completed += 1
            attempts += int(count > 0)
            if index == row["failed_job"]:
                _require(count > 0, "empty owner must not consume an allocator failure")
                expected = 1001
            else:
                expected = sum(((offset + seed) & 0xffffffff) & 255 for offset in range(count))
                if count: successful_sizes.append(count)
            _require(job["result"] == expected, "callback diverged from independent arithmetic/failure oracle")
        _require(completed == row["completed"] and attempts == row["allocation_attempts"],
                 "callback and allocation inventories disagree")
        _require(row["worker_mask"] == worker_mask and
                 ((worker_mask in {1, 2, 4}) if name == "cooperative_cancel" else worker_mask == (0 if startup else 7)),
                 "not all required native workers executed callbacks")
        _require(row["allocations"] == row["frees"] == attempts - int(failed),
                 "exact component allocation/free accounting differs")
        _require(max(successful_sizes, default=0) <= row["peak_bytes"] <= 3 * max(LENGTHS),
                 "measured component peak bytes are inconsistent")
        results.append({"case": name, "completed": completed, "cancelled_or_not_started": 16 - completed,
                        "allocation_attempts": attempts, "peak_bytes": row["peak_bytes"], "qualified": True})
    return {"compiled_abi": rows[0], "kernel_errors": errors, "cases": results,
            "completed_callbacks": sum(row["completed"] for row in results)}


_EXEC_WORKER = """import os,resource,sys
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
resource.setrlimit(resource.RLIMIT_CPU,(10,10))
resource.setrlimit(resource.RLIMIT_AS,(512*1024**2,512*1024**2))
resource.setrlimit(resource.RLIMIT_NOFILE,(64,64))
resource.setrlimit(resource.RLIMIT_FSIZE,(512*1024,512*1024))
os.execve(sys.argv[1],[sys.argv[1]],{'LC_ALL':'C'})
"""


def qualify_linux_interfaces(output, *, mode="host-reference", cc="gcc", clang="clang", expected_machine=None):
    """Compile and execute real host interfaces; Hepta mode requires actual native Core code."""
    _require(mode in {"host-reference", "hepta"}, "explicit host-reference or hepta mode required")
    host = native_host_profile()
    if expected_machine is not None:
        _require(host["normalized_machine"] == expected_machine, "requested cohort is not the executing host")
    out = Path(output).absolute()
    _require(not out.exists() and not out.is_symlink(), "new evidence directory required")
    out.mkdir(parents=True)
    report = {"schema": SCHEMA, "ok": False, "mode": mode, "host": host, "protocol": protocol(),
              "claims": {"host_interface_qualified": False, "hepta_native_abi_qualified": False,
                         "hardware_device_qualified": False, "dma_mmio_interrupt_qualified": False,
                         "cross_target_execution_qualified": False, "arbitrary_concurrent_core_proved": False,
                         "backend_refinement_proved": False, "performance_superiority": False}}
    started = time.monotonic_ns()
    commands = []
    try:
        files = {name: (FIXTURE / name).read_bytes() for name in ("host_harness.c", "reference.c", "worker.hepta")}
        hashes = {name: sha256(value).hexdigest() for name, value in files.items()}
        report["source_sha256"] = {**hashes, "qualifier.py": sha256(Path(__file__).read_bytes()).hexdigest()}
        implementation_sources = report["implementation_source_sha256"] = _implementation_sources()
        for name, value in files.items():
            (out / name).write_bytes(value)
        found = shutil.which(cc)
        _require(found is not None, "actual GNU C compiler required")
        compiler = Path(found).resolve()
        compiler_hash = digest_executable(compiler)

        def command(argv, label, *, input_text=None):
            result = run_bounded([str(arg) for arg in argv], input_text=input_text, timeout=60,
                                 stdout_limit=512 * 1024, stderr_limit=512 * 1024)
            commands.append({"label": label, "argv": [str(arg) for arg in argv], "returncode": result.returncode})
            (out / (label + ".stdout.log")).write_text(result.stdout)
            (out / (label + ".stderr.log")).write_text(result.stderr)
            _require(result.returncode == 0, label + " failed: " + result.stderr[:2000])
            return result.stdout

        version = command([compiler, "--version"], "compiler-version")
        target = command([compiler, "-dumpmachine"], "compiler-target").strip()
        macros = command([compiler, "-dM", "-E", "-x", "c", "-"], "compiler-macros", input_text="")
        _require("#define __GNUC__ " in macros and "#define __clang__ " not in macros
                 and native_driver_matches_host(target, host), "native GNU C driver identity differs")
        report["compiler"] = {"path": str(compiler), "sha256": compiler_hash,
                              "version": version.splitlines()[0], "target": target}
        inputs = [out / "reference.c"]
        if mode == "hepta":
            from .hia_program_source import lower_source
            core = lower_source(files["worker.hepta"].decode())
            expected_ir = emit_program_llvm(core, target=host["target"])
            obj = out / "worker.o"
            native = build_program_native(core, obj, clang=clang, kind="object", target=host["target"])
            object_bytes = _check_native_receipt(native, core, expected_ir, obj, host)
            (out / "CORE.json").write_bytes(core.canonical_bytes)
            (out / "HIA_NATIVE.json").write_text(json.dumps(native, indent=2, sort_keys=True) + "\n")
            report["hia_native"] = native
            inputs = [obj]
        executable = out / "host-interfaces"
        link_input_bytes = {path: path.read_bytes() for path in [out / "host_harness.c", *inputs]}
        flags = ["-std=c11", "-O2", "-fno-builtin", "-Wall", "-Wextra", "-Werror", "-pthread"]
        command([compiler, *flags, out / "host_harness.c", *inputs,
                 "-Wl,--wrap=malloc", "-Wl,--wrap=calloc", "-Wl,--wrap=free", "-o", executable], "link")
        raw = _read_artifact(executable)
        _require(len(raw) >= 64 and raw[:7] == b"\x7fELF\x02\x01\x01"
                 and int.from_bytes(raw[16:18], "little") in {2, 3}
                 and int.from_bytes(raw[18:20], "little") == host["elf_machine"],
                 "executable ELF class/machine differs from the measured host")
        report["artifact"] = {"sha256": sha256(raw).hexdigest(), "bytes": len(raw),
                              "elf_machine": host["elf_machine"], "path": str(executable)}
        report["link_inputs"] = [{"name": path.name, "sha256": sha256(value).hexdigest()}
                                 for path, value in link_input_bytes.items()]
        _require(all(path.read_bytes() == value for path, value in link_input_bytes.items()),
                 "native link input changed")
        report["reference_implementation_linked"] = mode == "host-reference"
        snapshot, _, descriptor = _pin_native_artifact(executable)
        try:
            _require(snapshot == raw, "sealed executable differs from the linked artifact")
            # Pass the sealed descriptor into the child. Its private procfs
            # view need not expose the parent's PID namespace. This fixed C
            # harness creates threads, never descendant processes; killing the
            # owned process on timeout terminates its complete worker group.
            pinned = "/proc/self/fd/" + str(descriptor)
            with (out / "RAW.jsonl").open("wb") as stdout, (out / "execution.stderr.log").open("wb") as stderr:
                observation = subprocess.run(
                    [sys.executable, "-I", "-S", "-c", _EXEC_WORKER, pinned],
                    pass_fds=(descriptor,), timeout=20, stdout=stdout, stderr=stderr,
                    env={"LC_ALL": "C"}, start_new_session=True)
        finally:
            os.close(descriptor)
        observed_stdout = (out / "RAW.jsonl").read_text()
        observed_stderr = (out / "execution.stderr.log").read_text()
        report["execution"] = {"returncode": observation.returncode, "sealed_snapshot": True,
                               "stdout_sha256": sha256(observed_stdout.encode()).hexdigest()}
        _require(observation.returncode == 0 and not observed_stderr, "native harness failed or emitted diagnostics")
        report["observations"] = validate_observations(observed_stdout, host)
        _require(digest_executable(compiler) == compiler_hash, "C compiler changed during qualification")
        _require(all((FIXTURE / name).read_bytes() == value and (out / name).read_bytes() == value
                     for name, value in files.items()), "qualification source changed")
        _require(sha256(Path(__file__).read_bytes()).hexdigest() == report["source_sha256"]["qualifier.py"],
                 "qualifier implementation changed")
        _require(_implementation_sources() == implementation_sources, "Hepta implementation source set changed")
        _require(all(path.read_bytes() == value for path, value in link_input_bytes.items()),
                 "native link input changed during execution")
        if mode == "hepta":
            _require(_check_native_receipt(native, core, expected_ir, obj, host) == object_bytes,
                     "Hepta object identity changed during qualification")
        _require(_read_artifact(executable) == raw, "linked artifact pathname changed")
        report["ok"] = True
        report["status"] = "host_reference_qualified_hepta_pending" if mode == "host-reference" else "hepta_native_host_interface_qualified"
        report["claims"].update(host_interface_qualified=True, hepta_native_abi_qualified=mode == "hepta")
    except Exception as exc:
        report.update(status="failed", error=type(exc).__name__ + ": " + str(exc))
    report["commands"] = commands
    report["elapsed_ns"] = time.monotonic_ns() - started
    (out / "REPORT.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report
