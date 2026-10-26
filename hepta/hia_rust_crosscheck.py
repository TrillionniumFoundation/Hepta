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
import signal
import stat
import subprocess
import sys
import tempfile

MAX_EXECUTABLE_BYTES = 32 * 1024 * 1024
MAX_OUTPUT_BYTES = 32 * 1024
_SHA = re.compile(r"[0-9a-f]{64}\Z")

_SCALAR_CLAIMS = {
    "scalar_ssa_and_cfg_checked": True,
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


def _validate_report(raw: bytes, profile: str, checked):
    if not 0 < len(raw) < MAX_OUTPUT_BYTES or not raw.endswith(b"\n") or raw.count(b"\n") != 1:
        _reject("shadow must emit exactly one bounded JSON line")
    try:
        report = json.loads(raw, object_pairs_hook=_unique_pairs,
                            parse_constant=lambda _: _reject("nonfinite JSON number"))
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise HIARustCrosscheckRejected("E_HIA_RUST_CROSSCHECK: malformed shadow JSON") from exc
    keys = {"schema", "ok", "program_sha256", "functions_checked", "blocks_checked", "claims"}
    if profile == "scalar":
        keys.add("source_required")
    _exact_keys(report, keys, "shadow report")
    expected_schema = ("hepta.hia.rust-scalar-shadow.v1" if profile == "scalar"
                       else "hepta.hia.rust-owner-shadow.v1")
    if (report["schema"] != expected_schema or report["ok"] is not True
            or report["program_sha256"] != checked.sha256):
        _reject("shadow report schema, outcome or canonical Core digest mismatch")
    if profile == "scalar" and report["source_required"] is not False:
        _reject("scalar shadow source contract was unexpectedly upgraded")
    body = checked.as_dict()
    if (type(report["functions_checked"]) is not int or
            report["functions_checked"] != len(body["functions"]) or
            type(report["blocks_checked"]) is not int or
            report["blocks_checked"] != sum(len(f["blocks"]) for f in body["functions"])):
        _reject("shadow report did not cover the entire canonical module")
    expected_claims = _SCALAR_CLAIMS if profile == "scalar" else _OWNED_CLAIMS
    _exact_keys(report["claims"], set(expected_claims), "shadow safety claims")
    for name, wanted in expected_claims.items():
        if report["claims"][name] is not wanted:
            _reject("shadow promoted or changed an unproved claim: " + name)
    return report


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
    raw_exe = _verified_executable_bytes(Path(executable), executable_sha256)
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
        with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
            cmd = [str(destination)] + (["--owned-shadow"] if profile == "owned" else [])
            try:
                worker = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=out, stderr=err,
                                          start_new_session=True,
                                          env={"LANG": "C", "LC_ALL": "C", "PYTHONIOENCODING": "utf-8"})
                try:
                    worker.communicate(input=checked.canonical_bytes, timeout=timeout)
                except subprocess.TimeoutExpired as exc:
                    os.killpg(worker.pid, signal.SIGKILL)
                    worker.wait(timeout=2)
                    raise HIARustCrosscheckRejected(
                        "E_HIA_RUST_CROSSCHECK: shadow exceeded execution deadline") from exc
                out.seek(0)
                err.seek(0)
                stdout = out.read(MAX_OUTPUT_BYTES)
                stderr = err.read(MAX_OUTPUT_BYTES)
            except OSError as exc:
                raise HIARustCrosscheckRejected(
                    "E_HIA_RUST_CROSSCHECK: shadow executable unavailable") from exc
            if worker.returncode != 0 or stderr:
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
