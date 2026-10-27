"""Opt-in exact-byte Rust HIA shadow comparison; never production admission.

The existing Python HIA verifier is always authoritative. The Rust shadow
only corroborates its finite scalar/Owner subprofiles for development.
Arbitrary executables and self-attested reports are NOT safety proofs.
"""
from __future__ import annotations

from contextlib import contextmanager
import fcntl
from hashlib import sha256
import json
import math
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import time

MAX_EXECUTABLE_BYTES = 32 * 1024 * 1024
MAX_OUTPUT_BYTES = 32 * 1024
# Per-process limits for the pinned development shadow, not host-wide RSS
# bounds or hostile-binary confinement. Linux RLIMIT_AS limits virtual address
# space; RLIMIT_CPU limits CPU seconds (not aggregate child/group CPU).
_SHADOW_AS_LIMIT = 1024 * 1024 * 1024
_SHADOW_NOFILE_LIMIT = 64
# Run these pre-exec limits in a fresh isolated Python helper, never via
# subprocess.Popen(preexec_fn=...) from a potentially multithreaded host.
# The helper inherits the same session/process group as the actual shadow.
_SHADOW_RESOURCE_LAUNCHER = r'''import os, resource, sys
cpu = int(sys.argv[1])
for kind, value in (
    (resource.RLIMIT_AS, 1024 * 1024 * 1024),
    (resource.RLIMIT_CPU, cpu),
    (resource.RLIMIT_FSIZE, 0),
    (resource.RLIMIT_CORE, 0),
    (resource.RLIMIT_NOFILE, 64),
):
    resource.setrlimit(kind, (value, value))
os.execve(sys.argv[2], sys.argv[2:], {
    "LANG": "C", "LC_ALL": "C", "PYTHONIOENCODING": "utf-8"})
'''
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


@contextmanager
def _sealed_shadow_executable(content: bytes):
    """Bind the executed bytes to a kernel-sealed, private Linux memfd.

    A pathname in a temporary directory is insufficient for an exact-byte
    SHA-pinned execution claim: a concurrent same-user writer can exchange
    or edit it after staging, before execve. F_SEAL_WRITE/GROW/SHRINK/SEAL
    closes that content mutation window, including through /proc/<pid>/fd.

    This is byte immutability, NOT sandboxing against hostile code or a
    privileged attacker. Refuse systems without executable sealable memfds;
    never fall back to a replaceable pathname.
    """
    if (sys.platform != "linux" or type(content) is not bytes or not content
            or len(content) > MAX_EXECUTABLE_BYTES or not hasattr(os, "memfd_create")
            or not hasattr(os, "MFD_ALLOW_SEALING")
            or not all(hasattr(fcntl, name) for name in (
                "F_ADD_SEALS", "F_GET_SEALS", "F_SEAL_WRITE", "F_SEAL_GROW",
                "F_SEAL_SHRINK", "F_SEAL_SEAL"))):
        _reject("Linux sealable executable memfd is unavailable")
    fd = None
    try:
        # Intentionally omit MFD_CLOEXEC: after the resource-limit launcher
        # execs a hash-pinned SCRIPT, its shebang interpreter needs to read
        # this descriptor via /proc/self/fd. The fd is explicitly restricted
        # to the launched worker with Popen(pass_fds=(fd,)).
        fd = os.memfd_create("hepta-hia-rust-shadow", os.MFD_ALLOW_SEALING)
        os.fchmod(fd, 0o500)
        view = memoryview(content)
        offset = 0
        while offset < len(content):
            written = os.write(fd, view[offset:offset + 1024 * 1024])
            if written <= 0:
                _reject("sealed shadow image write was incomplete")
            offset += written
        required = (fcntl.F_SEAL_WRITE | fcntl.F_SEAL_SHRINK |
                    fcntl.F_SEAL_GROW | fcntl.F_SEAL_SEAL)
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, required)
        sealed = fcntl.fcntl(fd, fcntl.F_GET_SEALS)
        if (sealed & required) != required or os.fstat(fd).st_size != len(content):
            _reject("shadow image was not completely kernel-sealed")
        if os.pread(fd, len(content), 0) != content:
            _reject("sealed shadow bytes differ from the verified executable")
        yield fd
    except OSError as exc:
        raise HIARustCrosscheckRejected(
            "E_HIA_RUST_CROSSCHECK: cannot create or execute a sealed shadow image"
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


def _run_bounded_shadow(cmd: list[str], payload: bytes, timeout: float, *, pass_fds=()):
    """Bound stdin/stdout/stderr in memory; do not spool child output to disk.

    Exact executable byte pinning is a separate precondition. This pump is not
    a malicious-binary sandbox, but it cannot buffer unlimited output and
    will kill its process group on a transport violation or deadline.
    """
    proc = None
    completed = False
    try:
        proc = subprocess.Popen(
            cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            start_new_session=True, pass_fds=pass_fds,
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
                            if len(buf) + len(chunk) >= MAX_OUTPUT_BYTES:
                                _reject("shadow exceeded bounded output budget")
                            buf.extend(chunk)
            # Closing the pipes only proves that they were closed, not that
            # the child process group is empty: descendants can close their
            # copies and remain alive after their leader exits successfully.
            # Linux waitid(WNOWAIT) observes leader termination *without*
            # reaping it. Its PID/PGID therefore cannot be reused before we
            # kill any surviving members of the dedicated session group.
            if sys.platform != "linux" or not hasattr(os, "WNOWAIT"):
                _reject("post-success process group containment requires Linux waitid")
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    _reject("shadow exceeded execution deadline")
                try:
                    exit_status = os.waitid(
                        os.P_PID, proc.pid, os.WEXITED | os.WNOWAIT | os.WNOHANG)
                except InterruptedError:
                    continue
                except ChildProcessError as exc:
                    raise HIARustCrosscheckRejected(
                        "E_HIA_RUST_CROSSCHECK: shadow leader was reaped unexpectedly"
                    ) from exc
                if exit_status is not None:
                    break
                time.sleep(min(0.01, remaining))
            # Always clean up the *entire* group, including on a valid exit.
            # This is still not a sandbox against setsid()/detached children.
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait(timeout=max(0.01, deadline - time.monotonic()))
            completed = True
            return bytes(collected["stdout"]), bytes(collected["stderr"]), proc.returncode
    except (subprocess.TimeoutExpired, OSError) as exc:
        raise HIARustCrosscheckRejected(
            "E_HIA_RUST_CROSSCHECK: bounded shadow child unavailable or timed out"
        ) from exc
    finally:
        if proc is not None:
            # A process can exit while one of its descendants still holds
            # stdout/stderr open.  poll() reports the LEADER as terminated in
            # that case, but the session's process group remains alive.
            # On ANY unsuccessful transport, kill the group BEFORE reaping
            # the leader rather than consulting its exit status.
            if not completed:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    # A kernel-blocked process remains unqualified; never wait forever.
                    pass
            for stream in (proc.stdin, proc.stdout, proc.stderr):
                if stream is not None and not stream.closed:
                    stream.close()



def _limited_shadow_command(executable: Path, profile: str, timeout: float) -> list[str]:
    """Build a bounded launcher; the caller must pin the executed image.

    crosscheck_rust_shadow passes a SEALED memfd path and its inherited fd.
    Direct callers of this helper are test probes, not byte-pin authorities.
    The separate interpreter sets independent per-process RLIMITs before
    execve. These are not cgroup or hostile-code confinement guarantees.
    """
    if sys.platform != "linux":
        _reject("CPU/address-space resource limits require Linux")
    if profile not in {"scalar", "owned"} or type(timeout) not in (int, float) or not 0 < timeout <= 15:
        _reject("invalid shadow profile or deadline")
    cpu = math.ceil(timeout) + 1
    return [sys.executable, "-I", "-S", "-c", _SHADOW_RESOURCE_LAUNCHER,
            str(cpu), str(executable)] + (["--owned-shadow"] if profile == "owned" else [])


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
    with _sealed_shadow_executable(raw_exe) as image_fd:
        # /proc/self/fd/N resolves the inherited, SEALED kernel object in
        # the child, never a temp path that can be renamed after validation.
        # The launcher itself is trusted Python from this installation.
        image = Path(f"/proc/self/fd/{image_fd}")
        cmd = _limited_shadow_command(image, profile, timeout)
        stdout, stderr, returncode = _run_bounded_shadow(
            cmd, checked.canonical_bytes, timeout, pass_fds=(image_fd,))
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
