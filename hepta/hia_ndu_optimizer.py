"""Finite, proof-gated proposals ranked by the source-owned HIA NDU evaluator.

Measurements are explicit trusted-host observations, not safety certificates.
Every proposal is reverified and compared with the incumbent by the independent
translation validator. NDU is advisory; a selected proposal is proved again.
The conservative cost includes all supplied search costs and this invocation's
actual wall time. Native publication must additionally pay its preparation cost.
Proof admission and solver timeouts use the shared remaining search budget and
possible net saving. Solver/host overhead may still overshoot; final admission
then keeps the incumbent. This is not a hard physical execution-time bound.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

from .hia_ndu_scalar_selection import ScalarSelectionRejected, resolve_scalar_selection
from .hia_program import verify_program
from .hia_translation_validation import PROFILE as PROOF_PROFILE, SCHEMA as PROOF_SCHEMA, validate_translation

SCHEMA = "hepta.hia.ndu-optimization.v1"
ROOT = Path(__file__).resolve().parents[1]
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"[a-zA-Z][a-zA-Z0-9_.:-]{0,63}\Z")
_MAX_INT = (1 << 63) - 1


class OptimizationRejected(ValueError):
    """Malformed inputs or a broken proof/evaluator identity fail closed."""


class _NativeBudgetExhausted(OptimizationRejected):
    """The admitted native image was not launched before its budget expired."""


def _reject(message):
    raise OptimizationRejected("E_HIA_NDU: " + message)


def _bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def _digest(value):
    return sha256(_bytes(value)).hexdigest()


def _integer(value, name, *, minimum=0, maximum=_MAX_INT):
    if type(value) is not int or not minimum <= value <= maximum:
        _reject(name + " must be a bounded exact integer")
    return value


def ns_to_ms_q32(value):
    """Exact cost conversion performed by the packaged HIA arithmetic role."""
    from .hia_ndu_native_policy import ns_to_ms_q32 as native
    return native(value)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _reject("duplicate JSON key")
        result[key] = value
    return result


def _json(data):
    try:
        return json.loads(data, object_pairs_hook=_unique_object,
                          parse_constant=lambda value: _reject("non-finite JSON number"))
    except (TypeError, UnicodeError, json.JSONDecodeError) as error:
        _reject("invalid JSON: " + str(error))


def _read_file(path, limit):
    """Read one bounded regular inode without blocking on an unwritten FIFO."""
    if sys.platform != "linux":
        _reject("native evaluator identity requires Linux")
    fd = None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= limit:
            _reject("expected bounded regular file: " + str(path))
        chunks = []
        remaining = info.st_size + 1
        while remaining:
            chunk = os.read(fd, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        after = os.fstat(fd)
        identity = lambda value: (value.st_dev, value.st_ino, value.st_size,
                                  value.st_mtime_ns, value.st_ctime_ns)
        if identity(info) != identity(after):
            _reject("file changed during read")
        if len(data) != info.st_size:
            _reject("file length changed during read")
        return data
    except OSError as error:
        raise OptimizationRejected("E_HIA_NDU: bounded regular file read failed") from error
    finally:
        if fd is not None:
            os.close(fd)


@dataclass(frozen=True)
class _VerifiedBridgeImage:
    path: Path
    data: bytes


def _seal_bridge_image(raw):
    """Transfer ownership of a sealed descriptor for already-verified bytes.

    No pathname is reopened here. A mutable-path ABA after build admission
    therefore cannot replace the executable passed to the child. The trusted
    host's interpreter/ELF loader and libraries remain outside this byte pin.
    """
    fd = None
    transferred = False
    try:
        import fcntl
        fd = os.memfd_create("hepta-ndu-ranking", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        os.fchmod(fd, 0o700)
        remaining = memoryview(raw)
        while remaining:
            count = os.write(fd, remaining)
            if count <= 0:
                _reject("sealed native snapshot write made no progress")
            remaining = remaining[count:]
        # Linux UAPI values also support Python built against older headers;
        # the kernel operations and complete seal/byte readback are mandatory.
        seals = (getattr(fcntl, "F_SEAL_WRITE", 0x0008)
                 | getattr(fcntl, "F_SEAL_GROW", 0x0004)
                 | getattr(fcntl, "F_SEAL_SHRINK", 0x0002)
                 | getattr(fcntl, "F_SEAL_SEAL", 0x0001))
        fcntl.fcntl(fd, getattr(fcntl, "F_ADD_SEALS", 1033), seals)
        if (os.fstat(fd).st_size != len(raw)
                or fcntl.fcntl(fd, getattr(fcntl, "F_GET_SEALS", 1034)) & seals != seals
                or os.pread(fd, len(raw), 0) != raw):
            _reject("sealed executable snapshot does not retain the admitted bytes and seals")
        transferred = True
        return fd
    except (OSError, AttributeError, ImportError) as error:
        raise OptimizationRejected("E_HIA_NDU: sealed executable snapshot unavailable") from error
    finally:
        if fd is not None and not transferred:
            os.close(fd)


def _bridge_identity(bridge):
    from .hia_ndu_evaluator_native import admit_ndu_bridge, default_ndu_bridge
    if bridge is None:
        bridge = default_ndu_bridge()
    if type(bridge) is not dict or set(bridge) != {"binary", "build_receipt"}:
        _reject("bridge requires binary and build_receipt paths")
    binary = Path(bridge["binary"]).resolve()
    receipt_path = Path(bridge["build_receipt"]).resolve()
    receipt_bytes = _read_file(receipt_path, 4 * 1024 * 1024)
    receipt = _json(receipt_bytes)
    image, identity = admit_ndu_bridge(binary, receipt_bytes, receipt)
    if _read_file(receipt_path, 4 * 1024 * 1024) != receipt_bytes:
        _reject("native NDU build receipt changed during identity admission")
    return image, identity


def _native_rank(bridge, request, *, timeout_s, observer=None):
    """Optionally retain original bounded output even when admission rejects.

    The default call and its errors are unchanged. An observer is evidence
    plumbing, not another evaluator or a grant of proof authority. Its work
    belongs to the caller's outer budget. Incomplete pump output stays labelled
    as a prefix; missing pre-launch observations are never invented as empty.
    """
    if observer is None:
        return _native_rank_impl(bridge, request, timeout_s=timeout_s)
    observation = {"schema": "hepta.hia.ndu-native-observation.v1", "stdin": _bytes(request),
        "native_identity": None, "pump": None, "response_admitted": False}
    try:
        response, identity = _native_rank_impl(bridge, request, timeout_s=timeout_s,
                                               observation=observation)
        observation["response_admitted"] = True
        return response, identity
    finally:
        error = sys.exc_info()[1]
        observation["error"] = (None if error is None else
            {"type": type(error).__name__, "message": str(error)})
        observer(observation)


def _run_bounded_shadow(*args, **kwargs):
    # Preserve the same bounded pump for explicit native NDU execution without
    # importing the foreign Rust-comparison module during Agent discovery.
    from .hia_rust_crosscheck import _run_bounded_shadow as run
    return run(*args, **kwargs)


def _native_rank_impl(bridge, request, *, timeout_s, observation=None):
    # Identity admission and sealing belong to this call's budget too. Starting
    # a fresh subprocess timeout after those operations would renew spent time.
    # The shared runner's execution timer starts after ownership checks/Popen;
    # startup and scheduling are not preemptible here. All observed time still
    # reaches the final search-cost gate; this is not a hard wall-clock quota.
    deadline = time.perf_counter_ns() + int(timeout_s * 1_000_000_000)
    from .hia_rust_crosscheck import HIARustCrosscheckRejected

    def remaining_seconds():
        remaining = deadline - time.perf_counter_ns()
        if remaining <= 0:
            raise _NativeBudgetExhausted("E_HIA_NDU: native budget exhausted before process start")
        return remaining / 1_000_000_000

    image, identity = _bridge_identity(bridge)
    if observation is not None:
        observation["native_identity"] = identity
    data = _bytes(request)
    if len(data) > 1024 * 1024:
        _reject("native request exceeds byte limit")
    remaining_seconds()
    try:
        fd = _seal_bridge_image(image.data)
        try:
            options = {} if observation is None else {"observer":
                lambda value: observation.update(pump=value)}
            stdout, stderr, returncode = _run_bounded_shadow(
                ["/proc/self/fd/" + str(fd)], data, remaining_seconds(),
                maximum_output=1024 * 1024 + 1, pass_fds=(fd,), **options)
        finally:
            os.close(fd)
    except (OSError, HIARustCrosscheckRejected) as error:
        _reject("native evaluator could not complete: " + str(error))
    # The pump bounds output during execution and owns process-group cleanup.
    # This remains a trusted local bridge, not a sandbox for arbitrary code.
    if returncode or len(stdout) > 1024 * 1024 or len(stderr) > 1024 * 1024:
        _reject("native evaluator failed or exceeded output bounds")
    if sha256(_read_file(image.path, 128 * 1024 * 1024)).hexdigest() != identity["binary_sha256"]:
        _reject("native evaluator changed during invocation")
    response = _validate_native_rank_response(request, data, stdout, identity)
    return response, identity


def _validate_native_rank_response(request, data, stdout, identity):
    """Bind the response through the packaged HIA JSON and binding roles."""
    from .hia_ndu_native_policy import validate_native_rank_response
    return validate_native_rank_response(request, data, stdout, identity)


def rank_candidates(baseline, candidates, observations, *, function, bridge=None, objective,
                    generation=1, timeout_ms=2000, bridge_timeout_s=10.0):
    """Invoke the complete source-owned HIA ranking and proof policy."""
    entered_ns = time.monotonic_ns()
    from .hia_ndu_rank_native import _rank_candidates
    return _rank_candidates(baseline, candidates, observations, function=function,
                            bridge=bridge, objective=objective, generation=generation,
                            timeout_ms=timeout_ms, bridge_timeout_s=bridge_timeout_s,
                            _entered_ns=entered_ns)
