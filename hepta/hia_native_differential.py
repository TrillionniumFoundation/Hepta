"""Finite native differential qualification for source-replayed HIA scalar SSA.

One module, two boundaries: compare_oracle_with_native checks finite behavior
only; qualify_scalar_source additionally compiles through the existing Hepta
Rust-reference/Resource-IR/HIA/LLVM publisher, then replays the exact source.
Neither is a proof of whole-language soundness or arbitrary C ABI behavior.
"""
from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import re
import signal
import stat
import subprocess
import sys
import tempfile
import time

_IDENT = re.compile(r"[A-Za-z_][A-Za-z_0-9]*\Z")
_TYPES = {"i32": (-2**31, 2**31 - 1), "u32": (0, 2**32 - 1)}
_MAX_CASES = 256
_MAX_BYTES = 8 * 1024 * 1024

# No repository import or source parsing occurs in the native child. Only the
# already published shared object, an exact exported symbol and integer args.
_WORKER = r'''
import ctypes, json, resource, sys
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
# A hostile foreign constructor must not fill a host disk before timeout.
resource.setrlimit(resource.RLIMIT_FSIZE, (4096, 4096))
# Child evaluator limits: these do not prove HIA heap/RSS or OS sandboxing.
resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
resource.setrlimit(resource.RLIMIT_CPU, (10, 10))
# Fail-closed Linux x86-64 seccomp policy BEFORE loading the foreign DSO.
# Process-group cleanup alone cannot contain a forked child calling setsid().
# Keep the worker's unrestricted Python setup above this point; the native
# library and all ELF constructors run after the irreversible kernel filter.
class _BpfRule(ctypes.Structure):
    _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte),
                ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint32)]
class _BpfProgram(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort),
                ("filter", ctypes.POINTER(_BpfRule))]
# seccomp_data.nr at offset 0; arch at offset 4. Audit x86-64 0xc000003e.
# Deny the x32 syscall ABI bit to prevent alternate syscall-number bypass.
# Bad arch, x32 number and forbidden syscall all SIGSYS-kill this worker:
# returning EPERM would let native code hide an attempted escape and return 7.
_rules = [(0x20, 0, 0, 4), (0x15, 1, 0, 0xC000003E),
          (0x06, 0, 0, 0x80000000),
          (0x20, 0, 0, 0), (0x35, 0, 1, 0x40000000),
          (0x06, 0, 0, 0x80000000)]
# clone/fork/vfork/clone3, execve/execveat, process session/group escape,
# namespace escape, ptrace and io_uring kernel-worker creation.
# No socket/network channel is required for typed finite scalar observation.
# Deny direct filesystem mutation syscalls and newer openat2 (whose pointer
# flags cannot be examined by classic BPF). The worker still has read-only
# filesystem visibility and writable stdout/stderr; this is NOT a complete
# hostile-code sandbox or a proof of zero external side effects.
_FORBIDDEN_SYSCALLS = (
    56, 57, 58, 435, 59, 322, 109, 112, 272, 308, 101, 425,
    # socket, connect, accept, send/recv, bind, listen, socketpair, options
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55,
    288, 299, 307,
    # create/modify/remove/rename/link filesystem objects or metadata
    76, 77, 82, 83, 84, 85, 86, 87, 88, 90, 91, 92, 93, 94,
    132, 133, 235, 258, 259, 260, 261, 263, 264, 265, 266, 268,
    280, 316, 452,
    # openat2 takes pointer-to-flags: fail closed; also reject foreign FD
    # duplication, remote-memory writes and process-scoped signalling.
    437, 438, 311, 62, 200, 129, 297, 424,
)
if len(_FORBIDDEN_SYSCALLS) != len(set(_FORBIDDEN_SYSCALLS)):
    raise RuntimeError("duplicated native evaluator syscall policy")
for _nr in _FORBIDDEN_SYSCALLS:
    _rules += [(0x15, 0, 1, _nr), (0x06, 0, 0, 0x80000000)]
# seccomp_data.args[1] starts at byte 24 for open(), args[2] at byte 32
# for openat(). Both are little-endian low 32-bit flags on x86-64.
# Reject writable opens, O_CREAT, O_TRUNC, O_APPEND, O_TMPFILE even when
# O_ACCMODE happens to be read-only. Read-only dynamic loader opens remain.
# Each nonmatching syscall or read-only open must reload nr for the next rule.
_WRITE_OPEN_FLAGS = 0x3 | 0x40 | 0x200 | 0x400 | 0x410000
for _nr, _flags_offset in ((2, 24), (257, 32)):
    _rules += [
        (0x15, 0, 4, _nr),  # other syscall: skip to reload nr
        (0x20, 0, 0, _flags_offset),  # LD W ABS flags (low 32-bit)
        (0x54, 0, 0, _WRITE_OPEN_FLAGS),  # AND write/create/truncate flags
        (0x15, 1, 0, 0),  # zero flags: skip KILL; otherwise SIGSYS
        (0x06, 0, 0, 0x80000000),
        (0x20, 0, 0, 0),  # restore syscall number for subsequent tests
    ]
_rules.append((0x06, 0, 0, 0x7FFF0000))
_rules_array = (_BpfRule * len(_rules))(*(_BpfRule(*r) for r in _rules))
_filter = _BpfProgram(len(_rules), _rules_array)
_libc = ctypes.CDLL(None, use_errno=True)
if _libc.prctl(38, 1, 0, 0, 0) != 0:
    raise OSError(ctypes.get_errno(), "seccomp no_new_privs required")
if _libc.prctl(22, 2, ctypes.byref(_filter), 0, 0) != 0:
    raise OSError(ctypes.get_errno(), "seccomp syscall filter required")
lib, symbol, word, packed = sys.argv[1:]
args = json.loads(packed)
c = ctypes.c_int32 if word == "i32" else ctypes.c_uint32
f = getattr(ctypes.CDLL(lib), symbol)
f.argtypes = [c] * len(args)
f.restype = c
print(json.dumps({"value": int(f(*args))}, separators=(",", ":")), flush=True)
'''


class HIADifferentialRejected(ValueError):
    """Invalid corpus, corrupted source/artifact, or actual native divergence."""


def _reject(message: str) -> None:
    raise HIADifferentialRejected("E_HIA_DIFFERENTIAL: " + message)


def _canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _corpus(cases, return_words):
    if (type(cases) is not dict or type(return_words) is not tuple
            or not 1 <= len(cases) <= 32 or len(return_words) != len(cases)):
        _reject("corpus must cover every native exported function")
    words = {}
    for item in return_words:
        if (type(item) is not tuple or len(item) != 2
                or type(item[0]) is not str or _IDENT.fullmatch(item[0]) is None
                or item[0] in words or type(item[1]) is not str or item[1] not in _TYPES):
            _reject("invalid or duplicated native ABI function inventory")
        words[item[0]] = item[1]
    if set(cases) != set(words):
        _reject("missing or unreviewed native export case coverage")
    total = 0
    for fn, inputs in cases.items():
        if type(inputs) is not list or not inputs:
            _reject("each export requires a nonempty list of test vectors")
        word = words[fn]
        low, high = _TYPES[word]
        for args in inputs:
            if (type(args) is not list or len(args) > 16
                    or any(type(x) is not int or not low <= x <= high for x in args)):
                _reject("case arguments violate exact i32/u32 ABI range")
            total += 1
            if total > _MAX_CASES:
                _reject("finite corpus exceeds 256 cases")
    if len(_canonical(cases)) > 64_000:
        _reject("finite corpus exceeds byte budget")
    return words, total




def _require_exact_argument_arities(cases: dict, signatures: tuple[tuple[str, int], ...]) -> None:
    """Verify every tested vector against checked Core ABI parameter count.

    A shared-library ELF symbol alone does not authenticate the callee's
    parameter types. This is the *source/Core-derived call-site* proof,
    never an arbitrary raw oracle's trust credential.
    """
    if (type(cases) is not dict or type(signatures) is not tuple
            or not 1 <= len(signatures) <= 32):
        _reject("complete HIA native argument signature inventory required")
    arities = {}
    for entry in signatures:
        if (type(entry) is not tuple or len(entry) != 2
                or type(entry[0]) is not str or _IDENT.fullmatch(entry[0]) is None
                or type(entry[1]) is not int or not 0 <= entry[1] <= 16
                or entry[0] in arities):
            _reject("unreviewed HIA native parameter signature")
        arities[entry[0]] = entry[1]
    if set(cases) != set(arities):
        _reject("corpus differs from verified HIA ABI export inventory")
    for name, vectors in cases.items():
        if type(vectors) is not list or not vectors:
            _reject("native export requires a nonempty typed corpus")
        for index, args in enumerate(vectors):
            if type(args) is not list or len(args) != arities[name]:
                _reject(f"HIA ABI argument arity differs from verified function signature: {name} case {index}")


def _read_regular_artifact(path: Path):
    """Read exactly one no-follow regular-file inode, bounded before allocation.

    Opening with O_NONBLOCK prevents FIFOs/devices from blocking an admission
    thread; O_NOFOLLOW prevents a final-component symlink substitution.
    fstat before/after reads rejects concurrent in-place size/metadata drift.
    """
    if platform.system() != "Linux":
        _reject("native artifact identity pinning requires Linux")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | os.O_NOFOLLOW)
    except OSError as exc:
        raise HIADifferentialRejected("E_HIA_DIFFERENTIAL: cannot open no-follow native artifact") from exc
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= _MAX_BYTES:
            _reject("native artifact must be bounded regular file")
        chunks = []
        remaining = before.st_size + 1
        while remaining:
            part = os.read(fd, min(1 << 20, remaining))
            if not part:
                break
            chunks.append(part)
            remaining -= len(part)
        contents = b"".join(chunks)
        after = os.fstat(fd)
        identity = (before.st_dev, before.st_ino, before.st_size,
                    before.st_mtime_ns, before.st_ctime_ns)
        observed = (after.st_dev, after.st_ino, after.st_size,
                    after.st_mtime_ns, after.st_ctime_ns)
        if len(contents) != before.st_size or observed != identity:
            _reject("native artifact changed during identity-bound read")
        return contents, identity
    except OSError as exc:
        raise HIADifferentialRejected("E_HIA_DIFFERENTIAL: native artifact read failed") from exc
    finally:
        os.close(fd)


def _pin_native_artifact(path: Path):
    """Create a sealed Linux memfd from the exact identity-checked artifact.

    Native children load /proc/self/fd/<N>, not the mutable original pathname.
    If memfd sealing is unavailable, fail closed rather than weakening the
    differential's executable-byte identity guarantee.
    """
    original, identity = _read_regular_artifact(path)
    fd = None
    try:
        # Keep the module importable on non-Linux hosts; the execution path
        # itself still refuses anything except qualified Linux.
        import fcntl
        fd = os.memfd_create("hepta-hia-native", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        remaining = memoryview(original)
        while remaining:
            count = os.write(fd, remaining)
            if count <= 0:
                _reject("sealed native snapshot write made no progress")
            remaining = remaining[count:]
        expected_seals = (fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW |
                          fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, expected_seals)
        if (os.fstat(fd).st_size != len(original) or
                fcntl.fcntl(fd, fcntl.F_GET_SEALS) & expected_seals != expected_seals or
                os.pread(fd, len(original), 0) != original):
            _reject("sealed executable-byte snapshot differs from source")
        return original, identity, fd
    except (OSError, AttributeError, ImportError) as exc:
        raise HIADifferentialRejected("E_HIA_DIFFERENTIAL: sealed executable snapshot unavailable") from exc
    finally:
        # Ownership of a successfully sealed descriptor transfers to caller.
        if fd is not None and sys.exc_info()[0] is not None:
            os.close(fd)


def _check_artifact_unchanged(path: Path, original: bytes, identity) -> None:
    current, metadata = _read_regular_artifact(path)
    if current != original or metadata != identity:
        _reject("native artifact path/inode/bytes changed during differential execution")

def _has_in_group_descendant(pgid: int) -> bool:
    """Conservatively inspect live process-group membership before PID reap.

    Linux waitid(WNOWAIT) keeps the original worker PID from being reused.
    The worker itself is excluded; no external process may be silently
    accepted as a harmless effect of native code. Kernel-filtered fork/clone/setsid attempts SIGSYS-kill the native worker;
    the remaining process-group scan defends against unexpected descendants.
    """
    seen = 0
    try:
        with os.scandir("/proc") as entries:
            for entry in entries:
                if not entry.name.isascii() or not entry.name.isdecimal():
                    continue
                seen += 1
                if seen > 65536:
                    _reject("native evaluator process inventory exceeds bounded scan")
                pid = int(entry.name)
                if pid == pgid:
                    continue
                try:
                    member_group = os.getpgid(pid)
                except ProcessLookupError:
                    continue  # Race: the observed pid exited during /proc scan.
                except OSError as exc:
                    raise HIADifferentialRejected(
                        "E_HIA_DIFFERENTIAL: cannot inspect native evaluator process group") from exc
                if member_group == pgid:
                    return True
    except OSError as exc:
        raise HIADifferentialRejected(
            "E_HIA_DIFFERENTIAL: Linux process-group inspection unavailable") from exc
    return False


def _observe_native(library: Path, function: str, word: str, args: list[int], *,
                    timeout: float, pinned_fd: int):
    if (platform.system() != "Linux" or platform.machine().lower() not in {"x86_64", "amd64"}
            or not 0 < timeout <= 10
            or type(function) is not str or _IDENT.fullmatch(function) is None
            or type(word) is not str or word not in _TYPES
            or type(pinned_fd) is not int or pinned_fd < 0):
        _reject("bounded Linux host and sealed native fd required")
    try:
        with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
            # The sealed memfd and checked ABI come from the unchanged
            # canonical native observer. Give each finite case its own session
            # so a timed-out worker cannot leave ordinary forked children
            # running after the evaluator returns. Even a worker that exits
            # successfully may have spawned descendants: kill the process
            # group on *every* exit, before accepting its output.
            # The pre-dlopen kernel filter now blocks fork/clone/setsid;
            # other native side effects still require stronger containment.
            proc = subprocess.Popen(
                [sys.executable, "-I", "-c", _WORKER,
                 "/proc/self/fd/" + str(pinned_fd),
                 function, word, json.dumps(args, separators=(",", ":"))],
                stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                pass_fds=(pinned_fd,), start_new_session=True)
            # Linux waitid(WNOWAIT) observes direct-child termination
            # without reaping its PID. Popen.wait() would reap first, then
            # killpg(pid) could race a reused PID/PGID. Keep the zombie as
            # identity anchor until group cleanup, then reap exactly once.
            deadline = time.monotonic() + timeout
            timed_out = False
            residual_group = False
            try:
                while True:
                    status = os.waitid(os.P_PID, proc.pid,
                                       os.WEXITED | os.WNOWAIT | os.WNOHANG)
                    if status is not None:
                        break
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        timed_out = True
                        break
                    time.sleep(min(0.01, remaining))
                if not timed_out:
                    # WNOWAIT intentionally keeps the direct worker PID
                    # reserved. killpg() alone cannot reveal descendants:
                    # it also succeeds for a lone zombie group leader.
                    residual_group = _has_in_group_descendant(proc.pid)
            finally:
                # Clear the entire ordinary session/group for BOTH timeout
                # and successful or trapped native exit, before waitpid reaps
                # its leader. Seccomp blocks native fork/session escapes.
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                finally:
                    # SIGKILL cannot immediately finish an uninterruptible
                    # kernel wait. Bound the final reap; never block the
                    # evaluator indefinitely after its deadline.
                    proc.wait(timeout=2)
            if timed_out:
                _reject("native child timed out; process group terminated")
            if residual_group:
                _reject("native child left surviving in-group descendants after exit")
            out.seek(0)
            err.seek(0)
            child_stdout = out.read(4097)
            child_stderr = err.read(4097)
    except (subprocess.TimeoutExpired, OSError) as exc:
        raise HIADifferentialRejected("E_HIA_DIFFERENTIAL: native child unavailable or timed out") from exc
    # RLIMIT_FSIZE can surface as SIGXFSZ, a child write exception, or a
    # Python exit code after a partial 4096-byte write. All are refusals.
    if len(child_stdout) >= 4096 or len(child_stderr) >= 4096:
        _reject("native subprocess exceeded output budget")
    if proc.returncode == -signal.SIGABRT:
        # HIA scalar profiles have no user-visible IO. A glibc diagnostic,
        # constructor print or other output before SIGABRT cannot be accepted
        # as the VM's defined checked trap; this is still a finite oracle,
        # not a proof that a silent SIGABRT had the expected root cause.
        if child_stdout or child_stderr:
            _reject("native trap emitted unqualified stdout/stderr")
        return ("trap", None)
    if proc.returncode == -signal.SIGXFSZ:
        _reject("native subprocess exceeded output budget")
    if proc.returncode != 0:
        _reject("native child exited with unexpected error/signal " + str(proc.returncode))
    if child_stderr:
        _reject("native result emitted unexpected stderr")
    try:
        value = json.loads(child_stdout)
    except (ValueError, UnicodeError) as exc:
        raise HIADifferentialRejected("E_HIA_DIFFERENTIAL: invalid native child output") from exc
    low, high = _TYPES[word]
    if (type(value) is not dict or set(value) != {"value"}
            or type(value["value"]) is not int or not low <= value["value"] <= high):
        _reject("native child returned invalid scalar observation")
    # The checked worker prints one exact compact JSON object and newline.
    # Duplicate-key, whitespace, trailing material or native-injected output
    # must not become an apparently qualified observation through json.loads.
    # Native code capable of forging this *exact* record remains out of scope.
    if child_stdout != _canonical({"value": value["value"]}) + b"\n":
        _reject("native child output is not one canonical worker record")
    return ("value", value["value"])


def compare_oracle_with_native(oracle, library: str | Path, cases: dict, *,
                               max_steps: int = 20000, timeout: float = 3.0) -> dict:
    """Compare all exports; trap/budget/crash are deliberately distinct.

    This helper is NOT source binding. Use qualify_scalar_source for that.
    """
    from .hia_oracle import HIAOracleBudgetExceeded, HIAOracleRejected, HIAOracleTrap

    if (type(max_steps) is not int or not 1 <= max_steps <= 1_000_000
            or type(timeout) not in (float, int) or not 0 < timeout <= 10):
        _reject("invalid execution limits")
    words, total = _corpus(cases, getattr(oracle, "return_words", None))
    binary = Path(library)
    original, identity, pinned_fd = _pin_native_artifact(binary)
    artifact_sha = sha256(original).hexdigest()
    matches = traps = 0
    try:
        # Iterate canonically so receipt and first failure do not depend on map order.
        for function in sorted(cases):
            for index, args in enumerate(cases[function]):
                _check_artifact_unchanged(binary, original, identity)
                try:
                    oracle_value = oracle.run(function, args, max_steps=max_steps)
                except HIAOracleTrap:
                    expected = ("trap", None)
                except (HIAOracleBudgetExceeded, HIAOracleRejected) as exc:
                    raise HIADifferentialRejected(
                        "E_HIA_DIFFERENTIAL: oracle failed or exhausted budget, never native trap") from exc
                else:
                    # Python bool/float equality is not native ABI equivalence:
                    # True == 1 and 1.0 == 1, but neither is an exact HIA integer.
                    lo, hi = _TYPES[words[function]]
                    if type(oracle_value) is not int or not lo <= oracle_value <= hi:
                        _reject("oracle returned non-integer or out-of-range native ABI value")
                    expected = ("value", oracle_value)
                observed = _observe_native(binary, function, words[function], args,
                                           timeout=timeout, pinned_fd=pinned_fd)
                if observed != expected:
                    _reject(f"native mismatch at {function} case {index}: expected {expected}, observed {observed}")
                matches += 1
                traps += observed[0] == "trap"
        _check_artifact_unchanged(binary, original, identity)
    finally:
        os.close(pinned_fd)
    if matches != total:
        _reject("complete finite denominator not executed")
    return {
        "schema": "hepta.hia.scalar-native-differential.v0",
        "status": "finite_native_observations_match_oracle_not_proved",
        "cases_sha256": sha256(_canonical(cases)).hexdigest(),
        "artifact_sha256": artifact_sha,
        "function_count": len(words), "cases_executed": matches,
        "defined_traps_observed": traps,
        "claims": {"finite_native_oracle_match": True,
                   "checked_hepta_source_replayed": False,
                   "core_corpus_argument_arity_checked": False,
                   "backend_refinement_proved": False,
                   "whole_language_soundness_proved": False,
                   "physical_target_qualified": False},
    }


def qualify_scalar_source(source: str | Path, cases: dict, *, rustc=None,
                          clang="clang", locked=False, max_steps=20000) -> dict:
    """Actual Hepta source -> pinned Rust -> HIA/SSA -> LLVM -> child oracle.

    Separate source replay prevents a modified file with unchanged export names
    or rehashed data-only core from qualifying the published binary.
    """
    from .pipeline import analyze_project
    from .hsir import lower_checked_program
    from .cfg import lower_hsir_cfg
    from .ssa import lower_cfg_scalar_ssa
    from .ssa_verify import verify_scalar_ssa
    from .native_resource_gate import qualify_native_resource_source
    from .hia_core import seal_hia_scalar_core
    from .hia_oracle import prepare_scalar_oracle
    from .llvm_ssa_pipeline import build_llvm_ssa_source

    if platform.system() != "Linux":
        _reject("source qualification currently requires Linux host")
    with tempfile.TemporaryDirectory(prefix="hia-native-diff-") as directory:
        shared = Path(directory) / "source.so"
        compiled = build_llvm_ssa_source(source, shared, rustc=rustc,
                                         clang=clang, locked=locked)
        if compiled.get("ok") is not True:
            _reject("source LLVM qualification failed: " + str(compiled.get("diagnostics", []))[:600])
        analyzed = analyze_project(Path(source), backend="rust", native=False,
                                   crate_type="rlib", locked=locked)
        if (analyzed.report.get("ok") is not True or analyzed.program is None
                or analyzed.checked is None or analyzed.project is None
                or not analyzed.project.unchanged()):
            _reject("current source could not be independently replayed")
        h = lower_checked_program(analyzed.program, analyzed.checked)
        cfg = lower_hsir_cfg(h)
        ssa = lower_cfg_scalar_ssa(cfg)
        verified = verify_scalar_ssa(ssa, cfg)
        project_sha = analyzed.project.identity
        gate = qualify_native_resource_source(
            analyzed.program, analyzed.checked,
            canonical_hsir_sha256=h.as_dict()["source_semantic_sha256"],
            project_sha256=project_sha)
        core = seal_hia_scalar_core(h, cfg, ssa, verified, gate,
                                    project_sha256=project_sha)
        oracle = prepare_scalar_oracle(core, analyzed.program, analyzed.checked,
                                       project_sha256=project_sha)
        scalar_fns = json.loads(ssa.canonical_json).get("functions")
        if (type(scalar_fns) is not list
                or any(type(fn) is not dict or type(fn.get("name")) is not str
                       or type(fn.get("parameters")) is not list for fn in scalar_fns)):
            _reject("missing source-derived scalar parameter inventory")
        _require_exact_argument_arities(
            cases, tuple((fn["name"], len(fn["parameters"])) for fn in scalar_fns))
        record = compiled.get("identities", {})
        native = compiled.get("native_backend", {})
        if (record.get("hia_scalar_core_sha256") != core.sha256
                or record.get("canonical_ssa_sha256") != ssa.sha256
                or record.get("resource_ir_sha256") != gate["resource_ir_sha256"]
                or compiled.get("resource_verification", {}).get("project_sha256") != project_sha
                or native.get("artifact_sha256") != sha256(shared.read_bytes()).hexdigest()):
            _reject("HIA source/project, Resource IR or native artifact identity drift")
        result = compare_oracle_with_native(oracle, shared, cases, max_steps=max_steps)
        if not analyzed.project.unchanged():
            _reject("source graph changed while differential corpus ran")
        result["source_project_sha256"] = project_sha
        result["hia_core_sha256"] = core.sha256
        result["ssa_sha256"] = ssa.sha256
        result["compiler_sha256"] = record.get("compiler_sha256")
        result["claims"]["checked_hepta_source_replayed"] = True
        result["claims"]["core_corpus_argument_arity_checked"] = True
        return result


def compare_verified_hia_program(program, library: str | Path, cases: dict, *,
                                 max_steps: int = 20000, timeout: float = 3.0) -> dict:
    """Compare *the existing executable HIA v1-v6* to native scalar exports.

    This reuses hia_program.verify_program, hia_program_runtime.execute_program,
    and hia_program_llvm.emit_program_llvm. It neither creates another owner
    checker nor treats a native file passed by the caller as Core-compiled.
    For now accept only homogeneous i32/u32, one-result ABI wrappers.
    """
    from .hia_program import HIAProgramRejected, verify_program
    from .hia_program_runtime import (HIAProgramBudgetExceeded, HIAProgramTrap,
                                      execute_program)
    from .hia_program_llvm import emit_program_llvm
    from .hia_oracle import HIAOracleBudgetExceeded, HIAOracleRejected, HIAOracleTrap

    checked = verify_program(program)
    emitted = emit_program_llvm(checked)
    functions = checked.as_dict().get("functions")
    if type(functions) is not list:
        _reject("HIA Core has no verified function inventory")
    by_name = {fn.get("name"): fn for fn in functions if type(fn) is dict}
    if type(cases) is not dict:
        _reject("HIA Core native corpus must be a dictionary")
    exported = emitted.exports
    if (type(exported) is not tuple or not 1 <= len(exported) <= 32
            or len(exported) != len(set(exported)) or
            len(set(exported) - set(by_name)) or
            set(cases) != set(exported)):
        _reject("corpus must cover the exact HIA native scalar export inventory")
    words = []
    argument_arities = []
    for name in sorted(exported):
        fn = by_name[name]
        result_types = fn.get("returns")
        params = fn.get("params")
        if (type(result_types) is not list or len(result_types) != 1
                or result_types[0] not in _TYPES or type(params) is not list
                or any(type(p) is not dict or p.get("type") != result_types[0] for p in params)):
            _reject("HIA native differential supports homogeneous i32/u32 wrappers only")
        words.append((name, result_types[0]))
        argument_arities.append((name, len(params)))
    # Reuse the one strict parameter admission for both executable HIA Core
    # and historical source-qualified scalar SSA. No foreign child starts
    # before this exact signature check.
    _require_exact_argument_arities(cases, tuple(argument_arities))

    class _ExecutableHIAOracle:
        return_words = tuple(words)

        def run(self, function, arguments, *, max_steps=20000):
            try:
                result = execute_program(checked, function, arguments,
                                         max_steps=max_steps)
            except HIAProgramTrap as exc:
                raise HIAOracleTrap("verified HIA core defined trap: " + str(exc)) from exc
            except HIAProgramBudgetExceeded as exc:
                raise HIAOracleBudgetExceeded("verified HIA core resource/step limit") from exc
            except HIAProgramRejected as exc:
                raise HIAOracleRejected("HIA core evaluator rejected inputs") from exc
            if (type(result) is not dict or result.get("status") != "returned"
                    or type(result.get("values")) is not list
                    or len(result["values"]) != 1 or
                    type(result["values"][0]) is not int):
                raise HIAOracleRejected("unexpected HIA core execution result shape")
            return result["values"][0]

    report = compare_oracle_with_native(_ExecutableHIAOracle(), library, cases,
                                        max_steps=max_steps, timeout=timeout)
    report["executable_hia_program_sha256"] = checked.sha256
    report["executable_hia_llvm_sha256"] = emitted.sha256
    report["claims"]["executable_hia_program_reverified"] = True
    report["claims"]["core_corpus_argument_arity_checked"] = True
    report["claims"]["native_compiled_from_program_verified"] = False
    # This helper only compares an arbitrary provided artifact to the actual
    # Core VM. compile/qualification provenance belongs to the wrappers below.
    return report


def qualify_executable_hia_program(program, cases: dict, *, clang="clang") -> dict:
    """Actual verified HIA Core -> native LLVM -> finite VM differential.

    Standalone mode does not claim pinned Hepta source or Rust validation.
    """
    from .hia_program import verify_program
    from .hia_program_llvm import build_program_native

    core = verify_program(program)
    with tempfile.TemporaryDirectory(prefix="hia-core-native-diff-") as temp:
        shared = Path(temp) / "core.so"
        native = build_program_native(core, shared, clang=clang, kind="shared")
        if (native.get("ok") is not True or native.get("status") != "native_compiled_not_executed"
                or native.get("core_sha256") != core.sha256
                or native.get("artifact_sha256") != sha256(shared.read_bytes()).hexdigest()):
            _reject("canonical standalone Core/native artifact receipt mismatch")
        compared = compare_verified_hia_program(core, shared, cases)
        if compared["artifact_sha256"] != native["artifact_sha256"]:
            _reject("native code changed during VM differential")
        compared["claims"]["native_compiled_from_program_verified"] = True
        compared["native_toolchain_sha256"] = native.get("toolchain", {}).get("sha256")
        return compared


def qualify_checked_hia_source(source: str | Path, cases: dict, *, profile="owned",
                               rustc=None, clang="clang", locked=False,
                               static_resource_limits=None) -> dict:
    """Pinned Hepta source -> single executable HIA v1-v6 -> native LLVM -> VM.

    Unlike the historical scalar-only route, this uses hia_source_bridge's
    canonical verified Program producer and hia_program_llvm exclusively.
    """
    from .pipeline import analyze_project, compiler_hash
    from .hia_source_bridge import (HIAHeptaBridgeRejected,
                                    _validate_static_budget_receipt,
                                    build_checked_hepta_hia_native,
                                    lower_checked_scalar_hia,
                                    lower_checked_owned_hia)

    if profile not in {"scalar", "owned"} or platform.system() != "Linux":
        _reject("verified Core differential requires supported source profile and Linux")
    if static_resource_limits is not None and (
            type(static_resource_limits) is not dict or not static_resource_limits
            or not set(static_resource_limits) <= {
                "max_allocator_interactions", "max_vm_ticks",
                "max_call_depth", "max_live_heap_bytes"}
            or any(type(v) is not int or v < 0
                   for v in static_resource_limits.values())):
        _reject("invalid typed opt-in static resource policy")
    with tempfile.TemporaryDirectory(prefix="hia-checked-native-diff-") as temp:
        shared = Path(temp) / "checked.so"
        native = build_checked_hepta_hia_native(source, shared, rustc=rustc,
                                                clang=clang, locked=locked,
                                                profile=profile, kind="shared",
                                                static_resource_limits=static_resource_limits)
        if (native.get("ok") is not True
                or native.get("claims", {}).get("native_codegen_consumed_verified_hia_core") is not True):
            _reject("checked source->Core native qualification rejected")
        analyzed = analyze_project(Path(source), backend="rust", native=False,
                                   crate_type="rlib", locked=locked)
        if (analyzed.report.get("ok") is not True or analyzed.program is None
                or analyzed.checked is None or analyzed.project is None
                or not analyzed.project.unchanged()):
            _reject("checked source cannot be independently replayed")
        project = analyzed.project
        lowered = (lower_checked_owned_hia(analyzed.program, analyzed.checked,
                                           project_sha256=project.identity)
                   if profile == "owned" else
                   lower_checked_scalar_hia(analyzed.program, analyzed.checked,
                                            project_sha256=project.identity))
        # Replay the optional *numeric* resource budget against independently
        # re-derived checked-source HIA Core, before any native/VM child.
        # The established source bridge validator re-runs its original
        # analyzer; a rehashed synthetic receipt cannot justify a limit.
        qualified_budget = None
        if static_resource_limits is not None:
            qualified_budget = native.get("static_resource_budget")
            try:
                _validate_static_budget_receipt(
                    lowered.program, static_resource_limits, qualified_budget)
            except (HIAHeptaBridgeRejected, ValueError, TypeError,
                    KeyError, OverflowError, RecursionError) as exc:
                raise HIADifferentialRejected(
                    "E_HIA_DIFFERENTIAL: source static resource budget replay rejected") from exc
        elif "static_resource_budget" in native:
            _reject("unexpected unrequested static resource budget receipt")
        ids = native.get("identities", {})
        artifact = native.get("native_backend", {})
        if (ids.get("hia_program_sha256") != lowered.program.sha256
                or ids.get("project_sha256") != project.identity
                or ids.get("resource_ir_sha256") != lowered.resource_ir_sha256
                or ids.get("compiler_sha256") != compiler_hash()
                or artifact.get("artifact_sha256") != sha256(shared.read_bytes()).hexdigest()):
            _reject("source/Core/Resource IR/LLVM receipt fails exact replay")
        result = compare_verified_hia_program(lowered.program, shared, cases)
        if (result["executable_hia_program_sha256"] != ids["hia_program_sha256"]
                or result["artifact_sha256"] != artifact["artifact_sha256"]
                or not project.unchanged() or ids["compiler_sha256"] != compiler_hash()):
            _reject("source, compiler or native bytes changed during differential execution")
        result["claims"]["native_compiled_from_program_verified"] = True
        result["claims"]["checked_hepta_source_replayed"] = True
        result["claims"]["source_static_resource_budget_replayed"] = qualified_budget is not None
        if qualified_budget is not None:
            result["static_resource_budget_sha256"] = qualified_budget["sha256"]
            result["static_resource_limits"] = dict(static_resource_limits)
        result["source_project_sha256"] = project.identity
        result["source_compiler_sha256"] = ids["compiler_sha256"]
        return result
