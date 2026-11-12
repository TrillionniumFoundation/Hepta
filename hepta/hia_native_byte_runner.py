"""Disposable, source-verified direct byte invocation with caller-owned copies.

The public helper builds the supplied verified Core itself; it accepts neither
native pointers nor an arbitrary executable.  Each invocation owns separate
copies of all ranges and returns the mutable bytes explicitly.  Native code
never enters the controller process.  This is a research API, not an adoption
authority or a claim of machine-code refinement.
"""
from __future__ import annotations

import base64
import ctypes
from hashlib import sha256
import json
import math
import os
from pathlib import Path
import signal
import sys
import tempfile
import time

from .hia_native_byte_abi import LOANS, MAX_EXTENT, normalize_exports

MAX_WIRE = 12 * 1024 * 1024
_CTYPES = {"i8": ctypes.c_int8, "u8": ctypes.c_uint8, "i16": ctypes.c_int16,
    "u16": ctypes.c_uint16, "i32": ctypes.c_int32, "u32": ctypes.c_uint32,
    "i64": ctypes.c_int64, "u64": ctypes.c_uint64, "isize": ctypes.c_int64,
    "usize": ctypes.c_uint64, "bool": ctypes.c_uint8}


def _runner_identity():
    digest = sha256()
    root = Path(__file__).parent
    for name in ("hia_native_byte_runner.py", "hia_native_byte_abi.py", "hia_agent_runner.py", "clang_capture.py"):
        digest.update(name.encode("ascii") + b"\0" + (root / name).read_bytes() + b"\0")
    return digest.hexdigest()


def _failure_evidence(error):
    capture = getattr(error, "capture", None)
    cleanup_error = getattr(error, "capture_error", None)
    confirmed = capture is not None and capture.returncode is not None and not cleanup_error
    before_launch = capture is None and error.code in {
        "E_CAPTURE_ARGV", "E_CAPTURE_BUDGET", "E_CAPTURE_ENV", "E_CAPTURE_INPUT", "E_CAPTURE_INPUT_SIZE", "E_CAPTURE_EXEC"}
    return {"termination_confirmed": bool(confirmed), "leader_termination_confirmed": bool(confirmed),
            "execution_started": False if before_launch else True if capture is not None else None,
            "termination_scope": "owned child leader; verified Core has no spawn operations",
            "returncode": None if capture is None else capture.returncode,
            "capture_error": cleanup_error,
            "capture": None if capture is None else {
                "stdout_sha256": sha256(capture.stdout).hexdigest(), "stderr_sha256": sha256(capture.stderr).hexdigest(),
                "stdout_retained_bytes": len(capture.stdout), "stderr_retained_bytes": len(capture.stderr),
                "stdout_total_bytes": capture.stdout_total_bytes, "stderr_total_bytes": capture.stderr_total_bytes}}


def _arguments(function, arguments, extent):
    from .hia_program import scalar_value_valid
    if type(arguments) not in (list, tuple) or len(arguments) != len(function["params"]):
        raise ValueError("E_HIA_BYTE_ARGUMENT: exact argument arity required")
    result = []
    for param, value in zip(function["params"], arguments):
        typ = param["type"]
        if typ in LOANS:
            if type(value) not in (bytes, bytearray) or len(value) > extent:
                raise ValueError("E_HIA_BYTE_ARGUMENT: bounded bytes/bytearray required for loans")
            result.append({"type": typ, "base64": base64.b64encode(bytes(value)).decode("ascii")})
        else:
            if not scalar_value_valid(value, typ):
                raise ValueError("E_HIA_BYTE_ARGUMENT: scalar does not fit its exact Core type")
            result.append({"type": typ, "value": value})
    return result


def invoke_byte_program(document, function, arguments, *, maximum_bytes=MAX_EXTENT,
                        timeout_ms=30000, memory_bytes=256 * 1024 * 1024):
    """Compile real Core and call it in a bounded process, returning byte copies.

The deadline applies to the native invocation; measured build cost is separately
retained.  Compilation and validation are not declared free.  Failed, trapped or
timed-out invocations have no completed output.  Core application status is kept
separate from ABI status and is never interpreted as a proof of correctness.
"""
    from .clang_capture import CaptureRejected, run_bounded
    from .hia_program import verify_program
    from .hia_program_native import build_program_machine
    if (sys.platform != "linux" or type(timeout_ms) is not int or not 1 <= timeout_ms <= 60000
            or type(memory_bytes) is not int or not 64 * 1024 * 1024 <= memory_bytes <= 4 * 1024 * 1024 * 1024):
        raise ValueError("E_HIA_BYTE_BUDGET: Linux, a 1..60000 ms deadline and 64 MiB..4 GiB required")
    checked = verify_program(document)
    runner_identity = _runner_identity()
    manifest = normalize_exports(((function, maximum_bytes),), checked)
    fn = next(f for f in checked.as_dict()["functions"] if f["name"] == function)
    args = _arguments(fn, arguments, manifest[0][1])
    with tempfile.TemporaryDirectory(prefix="hia-byte-invoke-") as directory:
        library = Path(directory) / "program.so"
        build_started = time.monotonic_ns()
        receipt = build_program_machine(checked, library, linker="ld", foreign_buffer_exports=manifest)
        build_ns = time.monotonic_ns() - build_started
        request = {"schema": "hepta.hia.byte-call.v1", "artifact": str(library),
                   "artifact_sha256": receipt["artifact_sha256"], "core_sha256": checked.sha256,
                   "runner_sha256": runner_identity,
                   "function": function, "arguments": args, "maximum_bytes": maximum_bytes}
        payload = json.dumps(request, sort_keys=True, separators=(",", ":"))
        started = time.monotonic_ns()
        try:
            observed = run_bounded([sys.executable, "-B", "-E", "-s", "-m", "hepta.hia_native_byte_runner",
                str(os.getpid()), str(memory_bytes), str(max(1, math.ceil(timeout_ms / 1000)))],
                cwd=Path(__file__).resolve().parents[1], input_text=payload,
                timeout=timeout_ms / 1000, stdin_limit=MAX_WIRE, stdout_limit=MAX_WIRE, stderr_limit=65536)
        except CaptureRejected as error:
            if _runner_identity() != runner_identity:
                raise ValueError("E_HIA_BYTE_RUNNER_STALE: runner source changed during invocation") from error
            evidence = _failure_evidence(error)
            status = "budget_exceeded" if error.code == "E_CAPTURE_TIMEOUT" and evidence["leader_termination_confirmed"] else "execution_failed"
            if evidence["execution_started"] is False:
                status = "not_started"
            elif not evidence["leader_termination_confirmed"]:
                status = "termination_unknown"
            return {"status": status, "error": str(error), "error_code": error.code, **evidence,
                    "core_sha256": checked.sha256, "artifact_sha256": receipt["artifact_sha256"],
                    "runner_sha256": runner_identity, "runner_source_unchanged": True,
                    "build_ns": str(build_ns), "invocation_ns": str(time.monotonic_ns() - started),
                    "build_receipt": receipt, "report": None}
        if _runner_identity() != runner_identity:
            raise ValueError("E_HIA_BYTE_RUNNER_STALE: runner source changed during invocation")
        result = {"termination_confirmed": True, "leader_termination_confirmed": True, "execution_started": True,
                  "termination_scope": "owned child leader; verified Core has no spawn operations", "core_sha256": checked.sha256,
                  "artifact_sha256": receipt["artifact_sha256"], "build_ns": str(build_ns),
                  "runner_sha256": runner_identity, "runner_source_unchanged": True,
                  "invocation_ns": str(time.monotonic_ns() - started), "returncode": observed.returncode,
                  "stdout_sha256": sha256(observed.stdout.encode()).hexdigest(),
                  "stderr_sha256": sha256(observed.stderr.encode()).hexdigest(),
                  "build_receipt": receipt, "report": None}
        if observed.returncode:
            result["status"] = ("trapped" if observed.returncode == -signal.SIGABRT else
                                "budget_exceeded" if observed.returncode == -signal.SIGXCPU else "faulted")
            return result
        report = json.loads(observed.stdout)
        if (type(report) is not dict or report.get("schema") != "hepta.hia.byte-observation.v1"
                or report.get("artifact_sha256") != receipt["artifact_sha256"]
                or report.get("core_sha256") != checked.sha256 or report.get("runner_sha256") != runner_identity
                or report.get("function") != function
                or report.get("complete") is not True or len(report.get("arguments", [])) != len(args)):
            raise ValueError("E_HIA_BYTE_REPORT: incomplete or mismatched child report")
        outputs = []
        for param, sent, value in zip(fn["params"], args, report["arguments"]):
            if param["type"] in LOANS:
                decoded = base64.b64decode(value, validate=True)
                before = base64.b64decode(sent["base64"], validate=True)
                if len(decoded) != len(before) or param["type"] == "readbuf" and decoded != before:
                    raise ValueError("E_HIA_BYTE_REPORT: foreign range extent or read-only contents changed")
                outputs.append(decoded)
            else:
                if value != sent["value"]:
                    raise ValueError("E_HIA_BYTE_REPORT: scalar observation changed")
                outputs.append(value)
        result.update(status="returned", report=report, arguments=outputs,
                      abi_status=report["abi_status"], core_status=report["core_status"])
        return result


def main():
    if len(sys.argv) != 4:
        return 2
    from .hia_agent_runner import _child_setup
    _child_setup(int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3]))
    raw = sys.stdin.buffer.read(MAX_WIRE + 1)
    if len(raw) > MAX_WIRE:
        return 2
    request = json.loads(raw)
    if request.get("schema") != "hepta.hia.byte-call.v1":
        return 2
    if request.get("runner_sha256") != _runner_identity():
        return 3
    extent = request["maximum_bytes"]
    if type(extent) is not int or not 1 <= extent <= MAX_EXTENT:
        return 2
    fd = os.open(request["artifact"], os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        if sha256(stream.read(64 * 1024 * 1024 + 1)).hexdigest() != request["artifact_sha256"]:
            return 3
        lib = ctypes.CDLL("/proc/self/fd/" + str(stream.fileno()), mode=os.RTLD_LOCAL | os.RTLD_NOW)
        fn = getattr(lib, request["function"])
        buffers, cargs, ctypes_types = [], [], []
        for arg in request["arguments"]:
            typ = arg["type"]
            if typ in LOANS:
                data = base64.b64decode(arg["base64"], validate=True)
                if len(data) > extent:
                    return 2
                buf = ctypes.create_string_buffer(data, max(1, len(data)))
                buffers.append((buf, len(data)))
                ctypes_types.extend([ctypes.c_void_p, ctypes.c_uint64]); cargs.extend([ctypes.addressof(buf), len(data)])
            else:
                buffers.append(None); ctypes_types.append(_CTYPES[typ]); cargs.append(arg["value"])
        fn.argtypes = ctypes_types; fn.restype = ctypes.c_uint64
        value = fn(*cargs)
        outputs = []
        for arg, item in zip(request["arguments"], buffers):
            if item is None:
                outputs.append(arg["value"])
            else:
                buf, length = item
                outputs.append(base64.b64encode(buf.raw[:length]).decode("ascii"))
        report = {"schema": "hepta.hia.byte-observation.v1", "complete": True,
                  "artifact_sha256": request["artifact_sha256"], "core_sha256": request["core_sha256"],
                  "runner_sha256": request["runner_sha256"],
                  "function": request["function"], "abi_status": value >> 32,
                  "core_status": value & 0xffffffff, "arguments": outputs}
        if request["runner_sha256"] != _runner_identity():
            return 3
        sys.stdout.write(json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
