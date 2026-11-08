"""A disposable scalar/copied-byte runner; never loads native code in the controller.

HIA tools pass only reverified retained images and server-derived signatures.
Every child has an address-space/CPU limit, a wall deadline, its own process
group, and Linux parent-death SIGKILL. No native program runs in the worker.
"""
from __future__ import annotations

import ctypes
from hashlib import sha256
import json
import math
import os
from pathlib import Path
import resource
import signal
import subprocess
import sys
import tempfile
import time

from .hia_agent_store import AgentRejected, reject, stable_read, wire
from .hia_agent_byte_abi import (ABI, LOANS, byte_observations, byte_value,
                                 decode_arguments, reference_observation, validate_cases)

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
                     include_buffers=False, reference_max_steps=1_000_000):
    if sys.platform != "linux" or not 64 * 1024 * 1024 <= memory_bytes <= 4 * 1024 * 1024 * 1024:
        reject("E_HIA_EXECUTION_PROFILE", "native execution requires Linux and 64 MiB..4 GiB address-space budget")
    if timeout_ms <= 0:
        return {"status": "budget_exceeded", "termination_confirmed": True,
                "started": False, "wall_ns": "0", "returncode": None, "report": None}
    if _mode == "native":
        validate_cases(signatures, cases)
    if type(include_buffers) is not bool or include_buffers and (len(cases) != 1 or repetitions != 1 or warmup != 0):
        reject("E_HIA_ARGUMENTS", "byte copies may be returned only for one consumer invocation")
    if type(reference_max_steps) is not int or not 1 <= reference_max_steps <= 10_000_000:
        reject("E_HIA_BUDGET", "reference step budget requires an exact integer in 1..10000000")
    artifact_hash = sha256(artifact_bytes).hexdigest()
    started = time.monotonic_ns()
    with tempfile.TemporaryDirectory(prefix="hia-agent-run-") as directory:
        artifact = Path(directory) / "program.so"
        with artifact.open("xb") as stream:
            stream.write(artifact_bytes)
        artifact.chmod(0o400)
        request = {"artifact": str(artifact), "artifact_sha256": artifact_hash,
                   "signatures": signatures, "cases": cases,
                   "warmup": warmup, "repetitions": repetitions, "mode": _mode,
                   "include_buffers": include_buffers, "reference_max_steps": reference_max_steps}
        payload = wire(request)
        if len(payload) > 8 * 1024 * 1024:
            reject("E_HIA_BUDGET", "native invocation exceeds the bounded input wire size")
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
    report = None
    if len(stdout) > 8 * 1024 * 1024 or len(stderr) > 65536:
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
        except (ValueError, UnicodeError):
            status, report = "invalid_report", None
        else:
            status = "returned"
    return {"status": status, "termination_confirmed": True, "started": True,
            "wall_ns": str(time.monotonic_ns() - started), "returncode": proc.returncode,
            "stdout_sha256": sha256(stdout).hexdigest(), "stderr_sha256": sha256(stderr).hexdigest(),
            "report": report}


def run_reference_batch(program, cases, *, timeout_ms, memory_bytes, signatures=None, max_steps=1_000_000):
    """Run the existing VM under the same disposable process/deadline owner."""
    return run_native_batch(program.canonical_bytes, signatures or {}, cases, timeout_ms=timeout_ms,
                            memory_bytes=memory_bytes, _mode="reference", reference_max_steps=max_steps)


def _byte_call(fn, signature, values, *, include_buffers):
    """Allocate fresh independent copies for every warmup/measured invocation."""
    buffers, arguments = {}, []
    for index, (typ, value) in enumerate(zip(signature["params"], values)):
        if typ in LOANS:
            buf = ctypes.create_string_buffer(value, max(1, len(value)))
            buffers[index] = (buf, len(value))
            arguments.extend([ctypes.addressof(buf), len(value)])
        else:
            arguments.append(value)
    started = time.perf_counter_ns()
    packed = fn(*arguments)
    elapsed = time.perf_counter_ns() - started
    after = [buffers[index][0].raw[:buffers[index][1]] if index in buffers else value
             for index, value in enumerate(values)]
    observation = {"status": "returned" if packed >> 32 == 0 else "abi_rejected",
        "values": [packed & 0xffffffff], "buffers": byte_observations(signature["params"], after)}
    unchanged = all(typ != "readbuf" or before == output
                    for typ, before, output in zip(signature["params"], values, after))
    copies = [byte_value(value) if typ in LOANS else value
              for typ, value in zip(signature["params"], after)] if include_buffers else None
    return observation, elapsed, not unchanged or packed >> 32 != 0, copies


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
            signature = request["signatures"].get(case["function"], {})
            observation = (reference_observation(program, signature, case, steps=request["reference_max_steps"])
                           if signature.get("abi") == ABI else
                           _vm_observation(program, case, steps=request["reference_max_steps"]))
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
            fn.argtypes = [ctype for typ in sig["params"]
                           for ctype in ([ctypes.c_void_p, ctypes.c_uint64] if typ in LOANS else [_CTYPES[typ]])]
            fn.restype = (ctypes.c_uint64 if sig.get("abi") == ABI else
                          _CTYPES[sig["returns"][0]] if sig["returns"] and sig["returns"] != ["unit"] else None)
            functions[name] = fn
        observations, total_ns, calls = [], 0, 0
        for case in request["cases"]:
            fn = functions[case["function"]]
            signature = request["signatures"][case["function"]]
            returns = signature["returns"]
            arguments = decode_arguments(signature, case["arguments"])
            copies = None
            observation = None
            mismatch = False
            elapsed = 0
            for iteration in range(request["warmup"] + request["repetitions"]):
                if signature.get("abi") == ABI:
                    observation, call_ns, invalid, copies = _byte_call(fn, signature, arguments,
                        include_buffers=request["include_buffers"])
                    mismatch = mismatch or invalid
                else:
                    start = time.perf_counter_ns()
                    value = fn(*arguments)
                    call_ns = time.perf_counter_ns() - start
                    if returns == ["bool"]:
                        value = bool(value)
                    values = [value] if returns else []
                    observation = {"status": "returned", "values": values}
                if "expected" in case and observation != case["expected"]:
                    mismatch = True
                if iteration >= request["warmup"]:
                    elapsed += call_ns
                    calls += 1
            total_ns += elapsed
            row = {**observation, "mismatch": mismatch, "elapsed_ns": str(elapsed)}
            if copies is not None:
                row["arguments"] = copies
            observations.append(row)
        result = {"schema": "hepta.hia.agent.native-observation.v1",
            "artifact_sha256": request["artifact_sha256"], "complete": True,
            "planned_cases": len(request["cases"]), "completed_cases": len(observations),
            "warmup": request["warmup"], "repetitions": request["repetitions"],
            "measured_calls": calls, "total_native_ns": str(total_ns),
            "observations": observations,
            "timing_scope": "ctypes call including FFI overhead; byte copies/hashes counted only in child wall time"}
        sys.stdout.buffer.write(wire(result) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
