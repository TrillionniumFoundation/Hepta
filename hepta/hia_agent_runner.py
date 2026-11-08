"""A disposable scalar / owned-byte-snapshot native runner.

HIA tools pass only reverified retained images and server-derived signatures.
Every child has an address-space/CPU limit, a wall deadline, its own process
group, and Linux parent-death SIGKILL. No native program runs in the worker.
"""
from __future__ import annotations

import ctypes
from hashlib import sha256
import json
import math
import mmap
import os
from pathlib import Path
import resource
import signal
import subprocess
import sys
import tempfile
import time

from .hia_agent_store import AgentRejected, reject, stable_read, wire
from .hia_agent_buffers import (PROFILE as BUFFER_PROFILE, buffer_bytes,
                               buffer_observation, validate_cases)
from .hia_native_byte_abi import LOANS

_CTYPES = {"i8": ctypes.c_int8, "u8": ctypes.c_uint8, "i16": ctypes.c_int16,
    "u16": ctypes.c_uint16, "i32": ctypes.c_int32, "u32": ctypes.c_uint32,
    "i64": ctypes.c_int64, "u64": ctypes.c_uint64, "isize": ctypes.c_int64,
    "usize": ctypes.c_uint64, "bool": ctypes.c_uint8}


def _child_setup(parent_pid, memory_bytes, cpu_seconds):
    # Runs after exec, never in a fork preexec hook: consumer threads cannot
    # deadlock on a lock inherited from another thread. Checking PPID after
    # prctl also closes parent death before this fixed runner's initialization.
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != parent_pid:
        os._exit(125)
    resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))
    resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (8 * 1024 * 1024, 8 * 1024 * 1024))


def run_native_batch(artifact_bytes, signatures, cases, *, warmup=0, repetitions=1,
                     timeout_ms=30000, memory_bytes=256 * 1024 * 1024, _mode="native",
                     foreign_buffer_exports=(), capture_buffers=False):
    if sys.platform != "linux" or not 64 * 1024 * 1024 <= memory_bytes <= 4 * 1024 * 1024 * 1024:
        reject("E_HIA_EXECUTION_PROFILE", "native execution requires Linux and 64 MiB..4 GiB address-space budget")
    if timeout_ms <= 0:
        return {"status": "budget_exceeded", "termination_confirmed": True,
                "started": False, "wall_ns": "0", "returncode": None, "report": None}
    if _mode == "native":
        validate_cases(signatures, cases)
    if capture_buffers and len(cases) != 1:
        reject("E_HIA_BUFFER_CAPTURE", "buffer capture requires one owned synchronous invocation")
    artifact_hash = sha256(artifact_bytes).hexdigest()
    started = time.monotonic_ns()
    with tempfile.TemporaryDirectory(prefix="hia-agent-run-") as directory:
        artifact = Path(directory) / "program.so"
        with artifact.open("xb") as stream:
            stream.write(artifact_bytes)
        artifact.chmod(0o400)
        snapshot_files = []
        for index, case in enumerate(cases):
            files = []
            if _mode == "native":
                for argument, (typ, value) in enumerate(zip(signatures[case["function"]]["params"], case["arguments"])):
                    if typ not in LOANS:
                        continue
                    data = buffer_bytes(value)
                    path = Path(directory) / ("buffer-" + str(index) + "-" + str(argument))
                    with path.open("xb") as stream:
                        stream.write(data if data else b"\0")
                    path.chmod(0o600)
                    files.append({"argument": argument, "kind": typ, "byte_length": len(data), "path": str(path)})
            snapshot_files.append(files)
        request = {"artifact": str(artifact), "artifact_sha256": artifact_hash,
                   "signatures": signatures, "cases": cases,
                   "warmup": warmup, "repetitions": repetitions, "mode": _mode,
                   "foreign_buffer_exports": [list(pair) for pair in foreign_buffer_exports],
                   "snapshot_files": snapshot_files}
        payload = wire(request)
        parent_pid = os.getpid()
        proc = subprocess.Popen([sys.executable, "-B", "-E", "-s", "-m", "hepta.hia_agent_runner",
            str(parent_pid), str(memory_bytes), str(max(1, math.ceil(timeout_ms / 1000)))],
            cwd=Path(__file__).resolve().parent.parent, stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        timed_out = False
        try:
            stdout, stderr = proc.communicate(payload, timeout=timeout_ms / 1000)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            stdout, stderr = proc.communicate(timeout=5)
        except BaseException:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.communicate(timeout=5)
            raise
        # A direct Core image has no fork/exec operation. Still require the
        # owned process group to be absent before claiming terminal completion.
        try:
            os.killpg(proc.pid, 0)
        except ProcessLookupError:
            group_absent = True
        else:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            group_absent = False
        if not group_absent:
            reject("E_HIA_TERMINATION_UNKNOWN", "native process-group termination is not confirmed",
                   "execution", retry_action="observe_original")
        # Read parent-created backing files only after terminal ownership is
        # confirmed. A trap must not hide writes that happened before it.
        snapshots, captured = [], []
        for index, files in enumerate(snapshot_files):
            observed = []
            for record in files:
                size = record["byte_length"]
                data = stable_read(record["path"], max(1, size))
                if len(data) != max(1, size):
                    reject("E_HIA_NATIVE_REPORT", "owned external buffer extent changed")
                data = data[:size]
                observation = buffer_observation(record["argument"], record["kind"], data)
                observed.append(observation)
                if capture_buffers:
                    captured.append({**observation, "data": data})
            snapshots.append({"case": index, "buffers": observed})
    report = None
    if len(stdout) > 2 * 1024 * 1024 or len(stderr) > 65536:
        status = "invalid_report"
    elif timed_out or proc.returncode == -signal.SIGXCPU:
        status = "budget_exceeded"
    elif proc.returncode == -signal.SIGABRT:
        status = "trapped"
    elif proc.returncode != 0:
        status = "faulted"
    else:
        try:
            report = json.loads(stdout)
            if (type(report) is not dict or report.get("schema") != "hepta.hia.agent." + _mode + "-observation.v1"
                    or report.get("artifact_sha256") != artifact_hash
                    or report.get("planned_cases") != len(cases)
                    or report.get("repetitions") != repetitions
                    or report.get("warmup") != warmup
                    or type(report.get("complete")) is not bool
                    or _mode == "native" and report.get("complete") is not True):
                raise ValueError("native report identity differs")
            if _mode == "native":
                rows = report.get("observations")
                if type(rows) is not list or len(rows) != len(cases):
                    raise ValueError("native observation count differs")
                for row, snapshot in zip(rows, snapshots):
                    if snapshot["buffers"] and row.get("buffers") != snapshot["buffers"]:
                        raise ValueError("native external byte report differs from owned post-exit snapshot")
        except (ValueError, UnicodeError):
            status, report = "invalid_report", None
        else:
            status = "returned"
    result = {"status": status, "termination_confirmed": True, "started": True,
            "wall_ns": str(time.monotonic_ns() - started), "returncode": proc.returncode,
            "stdout_sha256": sha256(stdout).hexdigest(), "stderr_sha256": sha256(stderr).hexdigest(),
            "report": report}
    if any(snapshot["buffers"] for snapshot in snapshots):
        result["buffer_snapshots"] = snapshots
    if capture_buffers:
        result["captured_buffers"] = captured
    return result


def run_reference_batch(program, cases, *, timeout_ms, memory_bytes, foreign_buffer_exports=()):
    """Run the existing VM under the same disposable process/deadline owner."""
    return run_native_batch(program.canonical_bytes, {}, cases, timeout_ms=timeout_ms,
                            memory_bytes=memory_bytes, _mode="reference", foreign_buffer_exports=foreign_buffer_exports)


def main():
    if len(sys.argv) != 4:
        return 2
    _child_setup(int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3]))
    raw = sys.stdin.buffer.read(8 * 1024 * 1024 + 1)
    if len(raw) > 8 * 1024 * 1024:
        return 2
    request = json.loads(raw)
    artifact = request["artifact"]
    data = stable_read(artifact, 64 * 1024 * 1024)
    if sha256(data).hexdigest() != request["artifact_sha256"]:
        return 3
    if request.get("mode") == "reference":
        from .hia_agent_service import _vm_observation
        from .hia_program import verify_program
        from .hia_program_tools import decode_json
        program = verify_program(decode_json(data))
        observations = []
        for case in request["cases"]:
            observation = _vm_observation(program, case,
                foreign_buffer_exports=tuple(map(tuple, request["foreign_buffer_exports"])))
            observations.append(observation)
            if observation["status"] == "budget_exceeded":
                break
        result = {"schema": "hepta.hia.agent.reference-observation.v1",
            "artifact_sha256": request["artifact_sha256"],
            "complete": len(observations) == len(request["cases"]) and
                all(row["status"] != "budget_exceeded" for row in observations),
            "planned_cases": len(request["cases"]), "completed_cases": len(observations),
            "warmup": request["warmup"], "repetitions": request["repetitions"],
            "observations": observations, "native_code_executed": False}
        sys.stdout.buffer.write(wire(result) + b"\n")
        return 0
    if request.get("mode") != "native":
        return 2
    validate_cases(request["signatures"], request["cases"])
    # Load the exact opened inode via procfs, not a pathname that can be
    # replaced between hashing and dlopen. The fd stays live until process exit.
    fd = os.open(artifact, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        if sha256(stream.read()).hexdigest() != request["artifact_sha256"]:
            return 3
        library = ctypes.CDLL("/proc/self/fd/" + str(stream.fileno()), mode=os.RTLD_LOCAL | os.RTLD_NOW)
        functions = {}
        for name, sig in request["signatures"].items():
            fn = getattr(library, name)
            fn.argtypes = [ctype for typ in sig["params"] for ctype in
                           ([ctypes.c_void_p, ctypes.c_uint64] if typ in LOANS else [_CTYPES[typ]])]
            fn.restype = (ctypes.c_uint64 if sig.get("abi") == BUFFER_PROFILE else
                          _CTYPES[sig["returns"][0]] if sig["returns"] and sig["returns"] != ["unit"] else None)
            functions[name] = fn
        observations, total_ns, calls = [], 0, 0
        for case_index, case in enumerate(request["cases"]):
            fn = functions[case["function"]]
            signature = request["signatures"][case["function"]]
            returns = signature["returns"]
            borrowed = signature.get("abi") == BUFFER_PROFILE
            mappings, arguments = [], []
            file_map = {row["argument"]: row for row in request["snapshot_files"][case_index]}
            for index, (typ, argument) in enumerate(zip(signature["params"], case["arguments"])):
                if typ not in LOANS:
                    arguments.append(argument)
                    continue
                initial = buffer_bytes(argument)
                record = file_map[index]
                if record["kind"] != typ or record["byte_length"] != len(initial):
                    return 3
                fd = os.open(record["path"], os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
                try:
                    if os.fstat(fd).st_size != max(1, len(initial)):
                        return 3
                    mapping = mmap.mmap(fd, max(1, len(initial)), flags=mmap.MAP_SHARED,
                                        prot=mmap.PROT_READ | mmap.PROT_WRITE)
                finally:
                    os.close(fd)
                address = ctypes.addressof(ctypes.c_ubyte.from_buffer(mapping))
                mappings.append((index, typ, initial, mapping))
                arguments.extend((address, len(initial)))
            observation = None
            mismatch = False
            elapsed = 0
            for iteration in range(request["warmup"] + request["repetitions"]):
                for _index, _typ, initial, mapping in mappings:
                    mapping[:len(initial)] = initial
                start = time.perf_counter_ns()
                value = fn(*arguments)
                end = time.perf_counter_ns()
                abi_status = value >> 32 if borrowed else 0
                if borrowed:
                    value &= 0xffffffff
                elif returns == ["bool"]:
                    value = bool(value)
                values = [value] if returns else []
                observation = ({"status": "abi_rejected", "abi_status": abi_status} if abi_status else
                               {"status": "returned", "values": values})
                if borrowed:
                    observation["buffers"] = [buffer_observation(index, typ, mapping[:len(initial)])
                        for index, typ, initial, mapping in mappings]
                    if any(typ == "readbuf" and mapping[:len(initial)] != initial
                           for _index, typ, initial, mapping in mappings):
                        mismatch = True
                if "expected" in case and observation != case["expected"]:
                    mismatch = True
                if iteration >= request["warmup"]:
                    elapsed += end - start
                    calls += 1
            total_ns += elapsed
            observations.append({**observation, "mismatch": mismatch,
                                 "elapsed_ns": str(elapsed)})
            for _index, _typ, _initial, mapping in mappings:
                mapping.close()
        result = {"schema": "hepta.hia.agent.native-observation.v1",
            "artifact_sha256": request["artifact_sha256"], "complete": True,
            "planned_cases": len(request["cases"]), "completed_cases": len(observations),
            "warmup": request["warmup"], "repetitions": request["repetitions"],
            "measured_calls": calls, "total_native_ns": str(total_ns),
            "observations": observations, "timing_scope": "ctypes call including FFI overhead; snapshot reset and complete-byte hashing outside call timing, inside subprocess wall cost"}
        sys.stdout.buffer.write(wire(result) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
