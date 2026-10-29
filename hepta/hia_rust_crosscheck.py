"""Opt-in exact-byte Rust HIA shadow comparison; never production admission.

The existing Python HIA verifier is always authoritative. The Rust shadow
only corroborates its finite scalar/Owner subprofiles for development.
Arbitrary executables and self-attested reports are NOT safety proofs.
"""
from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time

MAX_EXECUTABLE_BYTES = 32 * 1024 * 1024
MAX_OUTPUT_BYTES = 32 * 1024
MAX_EXECUTION_OUTPUT_BYTES = 512 * 1024
MAX_ARGUMENT_BYTES = 128 * 1024
MAX_ARGUMENTS = 8192
_SHA = re.compile(r"[0-9a-f]{64}\Z")

_SCALAR_CLAIMS = {
    "scalar_ssa_and_cfg_checked": True,
    "v7_chain_resources_supported": False,
    "resource_provenance_verified": False,
    "full_hia_verifier_replaced": False,
    "whole_language_soundness_proved": False,
    "backend_refinement_proved": False,
    "ffi_supported": False,
    "native_executed": False,
}
_OWNED_CLAIMS = {
    "finite_owner_loan_cfg_checked": True,
    "cross_block_owner_loan_state_checked": True,
    "v2_v6_bulk_byte_opcode_types_loans_and_effects_checked": True,
    "interprocedural_resource_calls_checked": True,
    "v7_chain_native_semantics_proved": False,
    "recursion_or_stack_bounds_proved": False,
    "general_memory_provenance_proved": False,
    "full_source_to_core_refinement_proved": False,
    "llvm_backend_refinement_proved": False,
    "whole_language_soundness_proved": False,
    "native_execution_qualified": False,
    "rust_is_production_admission_authority": False,
}


class HIARustCrosscheckRejected(ValueError):
    """Malformed policy, executable mismatch, or Rust/Python disagreement."""


def _reject(message: str):
    raise HIARustCrosscheckRejected("E_HIA_RUST_CROSSCHECK: " + message)


def _exact_keys(value, keys, label):
    if type(value) is not dict or set(value) != keys:
        _reject(f"{label}: unexpected, missing or duplicated fields")


def _unique_pairs(items):
    out = {}
    for key, value in items:
        if key in out:
            _reject("shadow report contains duplicated keys")
        out[key] = value
    return out


def _verified_executable_bytes(path: Path, expected: str):
    if sys.platform != "linux":
        _reject("exact-file shadow runner requires Linux")
    if type(expected) is not str or _SHA.fullmatch(expected) is None:
        _reject("exact lowercase executable SHA-256 is required")
    fd = None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        first = os.fstat(fd)
        if not stat.S_ISREG(first.st_mode) or not 0 < first.st_size <= MAX_EXECUTABLE_BYTES:
            _reject("executable must be a bounded ordinary file")
        chunks = []
        remaining = first.st_size + 1
        while remaining:
            part = os.read(fd, min(1024 * 1024, remaining))
            if not part:
                break
            chunks.append(part)
            remaining -= len(part)
        data = b"".join(chunks)
        last = os.fstat(fd)
        identity = lambda v: (v.st_dev, v.st_ino, v.st_size, v.st_mtime_ns, v.st_ctime_ns)
        if len(data) != first.st_size or identity(first) != identity(last):
            _reject("executable modified during bounded read")
        if sha256(data).hexdigest() != expected:
            _reject("executable SHA-256 does not match the caller's pin")
        return data
    except OSError as exc:
        raise HIARustCrosscheckRejected(
            "E_HIA_RUST_CROSSCHECK: unavailable or unsafe shadow executable"
        ) from exc
    finally:
        if fd is not None:
            os.close(fd)


def _report_line(raw: bytes, maximum=MAX_OUTPUT_BYTES):
    if not 0 < len(raw) < maximum or not raw.endswith(b"\n") or raw.count(b"\n") != 1:
        _reject("shadow must emit exactly one bounded JSON line")
    try:
        return json.loads(raw, object_pairs_hook=_unique_pairs,
                          parse_float=lambda _: _reject("floating JSON number"),
                          parse_constant=lambda _: _reject("nonfinite JSON number"))
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise HIARustCrosscheckRejected("E_HIA_RUST_CROSSCHECK: malformed shadow JSON") from exc


def _validate_report(raw: bytes, profile: str, checked):
    report = _report_line(raw)
    keys = {"schema", "ok", "program_sha256", "functions_checked", "blocks_checked", "claims"}
    if profile == "scalar":
        keys.add("source_required")
    _exact_keys(report, keys, "shadow report")
    body = checked.as_dict()
    owned_v8 = profile == "owned" and body["schema"] == "hepta.hia.program.v8"
    expected_schema = ("hepta.hia.rust-scalar-shadow.v1" if profile == "scalar"
                       else "hepta.hia.rust-owner-shadow.v2" if owned_v8
                       else "hepta.hia.rust-owner-shadow.v1")
    if (report["schema"] != expected_schema or report["ok"] is not True
            or report["program_sha256"] != checked.sha256):
        _reject("shadow report schema, outcome or canonical Core digest mismatch")
    if profile == "scalar" and report["source_required"] is not False:
        _reject("scalar shadow source contract was unexpectedly upgraded")
    if (type(report["functions_checked"]) is not int or
            report["functions_checked"] != len(body["functions"]) or
            type(report["blocks_checked"]) is not int or
            report["blocks_checked"] != sum(len(f["blocks"]) for f in body["functions"])):
        _reject("shadow report did not cover the entire canonical module")
    # These fields describe the exact grammar checked by the pinned Rust
    # producer.  They are conditional on the reverified Core version, not a
    # permission the report may grant itself.  A v7 report cannot corroborate
    # v1-v6 bytes (or vice versa), and unknown/omitted claims still reject.
    version_claim = ("v7_scalar_only_checked" if profile == "scalar"
                     else "v7_chain_owner_loan_cfg_checked")
    expected_claims = {
        **(_SCALAR_CLAIMS if profile == "scalar" else _OWNED_CLAIMS),
        version_claim: body["schema"] == "hepta.hia.program.v7" or owned_v8,
    }
    if owned_v8:
        expected_claims["v8_parameter_bound_loan_returns_checked"] = True
    _exact_keys(report["claims"], set(expected_claims), "shadow safety claims")
    for name, wanted in expected_claims.items():
        if report["claims"][name] is not wanted:
            _reject("shadow promoted or changed an unproved claim: " + name)
    return report


def _require_shadow_process_ownership():
    """Refuse hosts that cannot retain the leader PID until group cleanup."""
    if (sys.platform != "linux" or not callable(getattr(os, "waitid", None))
            or not callable(getattr(os, "killpg", None))
            or any(not hasattr(os, name) for name in ("P_PID", "WEXITED", "WNOWAIT", "WNOHANG"))):
        _reject("shadow process ownership requires Linux waitid(WNOWAIT)")
    if signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:
        _reject("shadow process ownership requires default SIGCHLD disposition")
    try:
        # Our own PID is never our child. ECHILD confirms that the kernel
        # accepts these flags without observing or reaping another child.
        os.waitid(os.P_PID, os.getpid(), os.WEXITED | os.WNOWAIT | os.WNOHANG)
    except ChildProcessError:
        return
    except OSError as exc:
        raise HIARustCrosscheckRejected(
            "E_HIA_RUST_CROSSCHECK: Linux waitid(WNOWAIT) unavailable") from exc
    _reject("shadow process ownership cannot confirm waitid(WNOWAIT)")


def _run_bounded_shadow(cmd: list[str], payload: bytes, timeout: float,
                        maximum_output=MAX_OUTPUT_BYTES):
    """Bound stdin/stdout/stderr in memory; do not spool child output to disk.

    Exact executable byte pinning is a separate precondition. This pump is not
    a malicious-binary sandbox, but it cannot buffer unlimited output and
    kills its process group on every exit, before reaping the original
    leader. WNOWAIT keeps that PID reserved even after the leader exits.
    The caller must not independently reap this runner's private child.
    """
    _require_shadow_process_ownership()
    proc = None
    try:
        proc = subprocess.Popen(
            cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            start_new_session=True,
            env={"LANG": "C", "LC_ALL": "C", "PYTHONIOENCODING": "utf-8"},
        )
        pipes = {"stdin": proc.stdin, "stdout": proc.stdout, "stderr": proc.stderr}
        collected = {"stdout": bytearray(), "stderr": bytearray()}
        offset = 0
        deadline = time.monotonic() + timeout
        with selectors.DefaultSelector() as selector:
            for kind, stream in pipes.items():
                os.set_blocking(stream.fileno(), False)
                if kind == "stdin" and not payload:
                    stream.close()
                else:
                    selector.register(stream, selectors.EVENT_WRITE if kind == "stdin"
                                      else selectors.EVENT_READ, kind)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    _reject("shadow exceeded execution deadline")
                for key, _mask in selector.select(remaining):
                    kind = key.data
                    stream = key.fileobj
                    if kind == "stdin":
                        try:
                            count = os.write(stream.fileno(), memoryview(payload)[offset:offset + 65536])
                        except BrokenPipeError:
                            count = 0
                        if count <= 0:
                            selector.unregister(stream)
                            stream.close()
                        else:
                            offset += count
                            if offset == len(payload):
                                selector.unregister(stream)
                                stream.close()
                    else:
                        try:
                            chunk = os.read(stream.fileno(), 4096)
                        except BlockingIOError:
                            continue
                        if not chunk:
                            selector.unregister(stream)
                            stream.close()
                        else:
                            buf = collected[kind]
                            if len(buf) + len(chunk) >= maximum_output:
                                _reject("shadow exceeded bounded output budget")
                            buf.extend(chunk)
            # EOF does not imply process exit. Observe without wait/poll:
            # either would release the PID before killpg could use it safely.
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    _reject("shadow exceeded execution deadline")
                if os.waitid(os.P_PID, proc.pid,
                             os.WEXITED | os.WNOWAIT | os.WNOHANG) is not None:
                    break
                time.sleep(min(0.01, remaining))
    except (subprocess.TimeoutExpired, OSError) as exc:
        raise HIARustCrosscheckRejected(
            "E_HIA_RUST_CROSSCHECK: bounded shadow child unavailable or timed out"
        ) from exc
    finally:
        if proc is not None:
            try:
                # Confirm the child is still ours (running or unreaped).
                # If another reaper consumed it, refuse without signalling
                # a numeric PGID whose original identity is no longer held.
                os.waitid(os.P_PID, proc.pid, os.WEXITED | os.WNOWAIT | os.WNOHANG)
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                finally:
                    # Signal exactly once, then reap. Even if wait reports
                    # an error after consuming the child, never retry
                    # killpg with a possibly reused PID. A signal or reap
                    # error must not manufacture successful qualification.
                    proc.wait(timeout=2)
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise HIARustCrosscheckRejected(
                    "E_HIA_RUST_CROSSCHECK: shadow process-group cleanup or leader reap unconfirmed"
                ) from exc
            finally:
                for stream in (proc.stdin, proc.stdout, proc.stderr):
                    if stream is not None and not stream.closed:
                        stream.close()
    return bytes(collected["stdout"]), bytes(collected["stderr"]), proc.returncode


def _run_pinned_shadow(raw_exe, arguments, payload, timeout, *,
                       maximum_output=MAX_OUTPUT_BYTES):
    """Reuse the exact verified bytes for both static and execution protocols."""
    with tempfile.TemporaryDirectory(prefix="hepta-hia-rust-shadow-") as root:
        destination = Path(root) / "shadow"
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o700)
        try:
            with os.fdopen(fd, "wb", closefd=False) as dest:
                dest.write(raw_exe)
                dest.flush()
                os.fsync(dest.fileno())
            os.fchmod(fd, 0o700)
        finally:
            os.close(fd)
        return _run_bounded_shadow([str(destination), *arguments], payload, timeout,
                                   maximum_output=maximum_output)


def crosscheck_rust_shadow(program, executable: str | Path, *, executable_sha256: str,
                           profile: str = "owned", timeout: float = 8.0):
    """Corroborate canonical Core with pinned opt-in Rust executable.

    The canonical Python verifier runs first. A passing response is a
    development comparison ONLY and must never grant native Final-use rights.
    """
    from .hia_program import verify_program

    if profile not in ("scalar", "owned"):
        _reject("profile must be scalar or owned")
    if type(timeout) not in (int, float) or not 0 < timeout <= 15:
        _reject("shadow subprocess timeout must be in (0, 15] seconds")
    checked = verify_program(program)
    maximum_version = 8 if profile == "owned" else 7
    if checked.as_dict()["schema"] not in {
            f"hepta.hia.program.v{version}" for version in range(1, maximum_version + 1)}:
        _reject(f"the pinned Rust {profile} profile supports only primitive v1..v{maximum_version}")
    raw_exe = _verified_executable_bytes(Path(executable), executable_sha256)
    stdout, stderr, returncode = _run_pinned_shadow(
        raw_exe, ["--owned-shadow"] if profile == "owned" else [],
        checked.canonical_bytes, timeout)
    if returncode != 0 or stderr:
        _reject("shadow rejected canonical HIA or emitted unexpected diagnostics")
    report = _validate_report(stdout, profile, checked)
    return {
        "schema": "hepta.hia.rust-crosscheck.v1", "status": "shadow_corroborated_not_authority",
        "core_sha256": checked.sha256, "shadow_executable_sha256": executable_sha256,
        "shadow_report": report,
        "claims": {"python_canonical_core_checked": True,
                   "rust_shadow_profile_corroborated": True,
                   "rust_is_production_admission_authority": False,
                   "whole_language_soundness_proved": False,
                   "native_backend_refinement_proved": False},
    }


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _execution_claims(body):
    chain = any(
        "chain" in ([p["type"] for p in fn["params"]] + fn["returns"]
                    + [p["type"] for block in fn["blocks"] for p in block["params"]]
                    + [p["type"] for block in fn["blocks"] for op in block["ops"]
                       for p in op["out"]])
        for fn in body["functions"])
    returned_loans = body["schema"] == "hepta.hia.program.v8"
    profile = ("bounded-cfg-owned-memory-v5" if chain else
               "bounded-cfg-byte-owner-loan-returns-v4" if returned_loans else
               "bounded-cfg-byte-owner-bulk-v3")
    claims = {
        "finite_scalar_execution": True, "finite_byte_owner_execution": True,
        "single_block_scalar_entry_only": False, "scalar_public_entry_and_results_only": True,
        "verified_resource_cfg_execution": True,
        "interprocedural_byte_owner_and_loan_execution": True,
        "chain_and_bulk_execution": chain, "versioned_bulk_byte_execution": True,
        "chain_execution": chain, "general_resource_execution": False,
        "production_admission_authorized": False, "whole_language_soundness_proved": False,
        "native_backend_refinement_proved": False, "abi_or_hardware_qualified": False,
    }
    if returned_loans:
        claims["parameter_bound_returned_loans_execution"] = True
    if chain:
        claims.update(interprocedural_chain_execution=True,
                      separate_logical_and_storage_identities=True,
                      distinct_call_formal_loan_identities=True)
    return profile, claims


def _validate_execution(raw, request, body, python, *, protocol_version=1):
    envelope = _report_line(raw, MAX_EXECUTION_OUTPUT_BYTES)
    _exact_keys(envelope, {"schema", "request", "request_sha256", "execution"},
                "bound execution envelope")
    if (envelope["schema"] != f"hepta.hia.rust-bound-execution.v{protocol_version}"
            or _canonical(envelope["request"]) != _canonical(request)
            or envelope["request_sha256"] != sha256(_canonical(request)).hexdigest()):
        _reject("Rust execution does not bind the exact Core, entry, arguments and policy")
    report = envelope["execution"]
    status = python["status"]
    outcome = "values" if status == "returned" else "error"
    keys = {"schema", "status", "function", "program_sha256", "steps", "max_steps",
            "max_call_depth", "claims", "profile", "resources", "max_heap_bytes",
            "allocation_fail_at", outcome}
    _exact_keys(report, keys, "Rust execution report")
    profile, claims = _execution_claims(body)
    policy = request["policy"]
    expected = {
        "schema": "hepta.hia.rust-byte-owner-execution.v1", "status": status,
        "function": request["function"], "program_sha256": request["program_sha256"],
        "steps": python["steps"], "profile": profile, "claims": claims,
        "resources": python["resources"], **policy,
        outcome: python["values"] if outcome == "values" else {"code": python["error"]["code"]},
    }
    # Canonical JSON distinguishes bool/int/float as well as field sets. Every
    # resource field and result is compared; no truthiness or subset equality.
    if _canonical(report) != _canonical(expected):
        _reject("Rust/Python execution differs in outcome, ticks, resources, profile or claims")
    return envelope


def crosscheck_rust_execution(program, function: str, arguments: list,
                              executable: str | Path, *, executable_sha256: str,
                              max_steps: int = 100_000, max_heap_bytes: int = 1024 * 1024,
                              allocation_fail_at: int | None = None, timeout: float = 8.0):
    """Run and compare one finite invocation using Python and the pinned Rust VM.

    Both independently verify the complete canonical module. Successful return,
    specified trap and evaluator stop are distinct corroborated observations.
    The existing Python verifier stays authoritative. This API is not a receipt
    importer, a native executor, a whole-language proof or an authority switch.
    """
    return _crosscheck_rust_execution(program, function, arguments, executable,
        executable_sha256=executable_sha256, max_steps=max_steps, max_heap_bytes=max_heap_bytes,
        allocation_fail_at=allocation_fail_at, timeout=timeout, max_call_depth=32, protocol_version=1)


def crosscheck_rust_execution_v2(program, function: str, arguments: list,
                                 executable: str | Path, *, executable_sha256: str,
                                 max_call_depth: int, max_steps: int = 100_000,
                                 max_heap_bytes: int = 1024 * 1024,
                                 allocation_fail_at: int | None = None, timeout: float = 8.0):
    """Compare a v2 invocation with an explicit root-inclusive depth in 1..32.

    This separate API never upgrades the fixed-depth v1 contract. It freshly
    executes both existing VMs; no imported receipt acquires admission rights.
    Step/heap limits and the scalar public boundary remain the same as v1.
    """
    return _crosscheck_rust_execution(program, function, arguments, executable,
        executable_sha256=executable_sha256, max_steps=max_steps, max_heap_bytes=max_heap_bytes,
        allocation_fail_at=allocation_fail_at, timeout=timeout, max_call_depth=max_call_depth,
        protocol_version=2)


def _crosscheck_rust_execution(program, function, arguments, executable, *,
                               executable_sha256, max_steps, max_heap_bytes,
                               allocation_fail_at, timeout, max_call_depth, protocol_version):
    from .hia_program import SCALARS, scalar_value_valid, verify_program
    from .hia_program_runtime import HIAProgramBudgetExceeded, HIAProgramTrap, execute_program

    if (type(timeout) not in (int, float) or not 0 < timeout <= 15
            or type(max_steps) is not int or not 1 <= max_steps <= 1_000_000
            or type(max_heap_bytes) is not int or not 0 <= max_heap_bytes <= 16 * 1024 * 1024
            or type(max_call_depth) is not int or not 1 <= max_call_depth <= 32
            or allocation_fail_at is not None and
               (type(allocation_fail_at) is not int or not 1 <= allocation_fail_at <= (1 << 64) - 1)):
        _reject("execution policy is outside the finite Rust contract")
    if (type(arguments) is not list or len(arguments) > MAX_ARGUMENTS
            or any(type(v) not in (int, bool, type(None)) or
                   type(v) is int and not -(1 << 63) <= v < (1 << 64) for v in arguments)):
        _reject("execution arguments must be bounded exact scalar values")
    arguments = list(arguments)
    argument_wire = _canonical(arguments)
    if len(argument_wire) > MAX_ARGUMENT_BYTES:
        _reject("execution arguments exceed the wire budget")
    checked = verify_program(program)
    body = checked.as_dict()
    if body["schema"] not in {f"hepta.hia.program.v{version}" for version in range(1, 9)}:
        _reject("bound Rust execution supports only canonical primitive v1..v8")
    # Preserve the original producer's public-entry eligibility when nominal
    # input was normalized. Flattened scalar fields do not grant a public ABI.
    if type(function) is not str or function not in checked.scalar_entrypoints:
        _reject("execution entry is not a public scalar function")
    entry = next(fn for fn in body["functions"] if fn["name"] == function)
    if (len(entry["params"]) != len(arguments) or
            any(p["type"] not in SCALARS or not scalar_value_valid(v, p["type"])
                for p, v in zip(entry["params"], arguments)) or
            any(ty not in SCALARS for ty in entry["returns"])):
        _reject("execution arguments/results do not match the exact scalar boundary")
    policy = {"max_steps": max_steps, "max_heap_bytes": max_heap_bytes,
              "allocation_fail_at": allocation_fail_at, "max_call_depth": max_call_depth}
    request = {"schema": f"hepta.hia.rust-execution-request.v{protocol_version}", "mode": "owned",
               "program_sha256": checked.sha256, "function": function,
               "arguments": arguments, "policy": policy}
    raw_exe = _verified_executable_bytes(Path(executable), executable_sha256)
    try:
        python = execute_program(checked, function, arguments, **policy)
    except (HIAProgramTrap, HIAProgramBudgetExceeded) as stopped:
        python = stopped.report
    argv = (["--owned-run-bound", function, argument_wire.decode("ascii"), str(max_steps),
             str(max_heap_bytes), "none" if allocation_fail_at is None else str(allocation_fail_at)]
            if protocol_version == 1 else
            ["--owned-run-bound-v2", function, argument_wire.decode("ascii"), _canonical(policy).decode("ascii")])
    stdout, stderr, returncode = _run_pinned_shadow(
        raw_exe, argv, checked.canonical_bytes, timeout, maximum_output=MAX_EXECUTION_OUTPUT_BYTES)
    if returncode != 0 or stderr:
        _reject("Rust execution rejected the request or emitted unexpected diagnostics")
    envelope = _validate_execution(stdout, request, body, python, protocol_version=protocol_version)
    return {
        "schema": f"hepta.hia.rust-execution-crosscheck.v{protocol_version}",
        "status": "execution_corroborated_not_authority",
        "input_sha256": checked.input_sha256, "core_sha256": checked.sha256,
        "shadow_executable_sha256": executable_sha256,
        "request_sha256": envelope["request_sha256"], "request": request,
        "python_report": python, "rust_report": envelope["execution"],
        "claims": {
            "python_canonical_core_checked": True, "rust_module_independently_checked": True,
            "exact_invocation_and_policy_bound": True, "complete_stopped_ledger_compared": True,
            "rust_is_production_admission_authority": False, "whole_language_soundness_proved": False,
            "native_backend_refinement_proved": False, "abi_or_hardware_qualified": False,
        },
    }
