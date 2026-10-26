"""Finite *functional* Linux Owned ABI runtime/link probe, not production libc.

Unlike owned_aarch64_link's deliberately nonfunctional synthetic stubs, this
probe links a real 4096-byte exclusive allocator, overlap-correct memory
primitives and Linux exit syscall against ONE fixed source ABI: owned_case.
Only an explicitly supplied QEMU runner can turn link evidence into emulated
execution; no physical-board, arbitrary ABI or general allocator claims.
"""
from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import os
import shutil
import stat
import tempfile

from .llvm_owned_aarch64 import TARGET_AARCH64, MAX_OBJECT_BYTES, inspect_owned_aarch64_object
from .llvm_ssa_backend import _clang_run
from .object_symbols import ObjectSymbolsRejected, inspect_object_symbols
from .owned_aarch64_link import inspect_synthetic_aarch64_elf
from .native_tool_identity import ToolIdentityRejected, digest_executable

_FIXTURE = Path(__file__).resolve().parents[1] / "examples/llvm_owned/finite_aarch64_runtime.c"
_RUNTIME_EXPORTS = frozenset({"malloc", "free", "abort", "memcpy", "memmove", "memset", "_start"})
_EXPORT = ("owned_case",)
_MAX_LINKED_BYTES = 16 * 1024 * 1024
# This is a SOURCE FILE bound, not the functional allocator's 4096-byte arena.
# The reviewed runtime is larger than 4096 source bytes; conflating the two
# made the real source-facing link probe reject before any native compilation.
_MAX_RUNTIME_SOURCE_BYTES = 8192
# Pin exact reviewed single-owner runtime semantics; editing the fixture
# without deliberately updating this identity fails before compilation.
_REVIEWED_RUNTIME_SHA256 = "5caa9cbc33df5734626ff17045159add08b850abceb021b038ddb110db6f402c"


class OwnedAArch64RuntimeRejected(ValueError):
    def __init__(self, message: str, *, execution: dict | None = None):
        super().__init__(message)
        self.execution = execution


def _reject(message: str) -> None:
    raise OwnedAArch64RuntimeRejected("E_OWNED_AARCH64_RUNTIME: " + message)


def _tool_digest(path: Path) -> str:
    """Share the bounded compiler/runner identity guard across P7 probes."""
    try:
        return digest_executable(path)
    except ToolIdentityRejected as exc:
        raise OwnedAArch64RuntimeRejected(
            "E_OWNED_AARCH64_RUNTIME: native tool identity rejected") from exc


def _source_identity(info: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def _read_reviewed_runtime() -> tuple[bytes, str]:
    """Bounded, non-symlinked source read with exact file-identity replay.

    A file-size check after read_bytes() permits an attacker to force an
    unbounded memory allocation *before* the safety gate can reject it.
    Read no more than MAX+1 bytes and compare the same fd/path identity
    before and after. This remains a local race check, not remote attestation.
    """
    try:
        previous = _FIXTURE.lstat()
        if (not stat.S_ISREG(previous.st_mode)
                or not 0 < previous.st_size <= _MAX_RUNTIME_SOURCE_BYTES):
            _reject("missing or out-of-profile reviewed finite runtime source")
        fd = os.open(_FIXTURE, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as stream:
            original = os.fstat(stream.fileno())
            if _source_identity(original) != _source_identity(previous):
                _reject("reviewed runtime source changed before reading")
            raw = stream.read(_MAX_RUNTIME_SOURCE_BYTES + 1)
            observed = os.fstat(stream.fileno())
            if (len(raw) != previous.st_size
                    or _source_identity(observed) != _source_identity(previous)):
                _reject("reviewed runtime source changed during bounded reading")
        if _source_identity(_FIXTURE.lstat()) != _source_identity(previous):
            _reject("reviewed runtime source path was replaced")
    except OSError as exc:
        raise OwnedAArch64RuntimeRejected(
            "E_OWNED_AARCH64_RUNTIME: reviewed runtime file identity unavailable") from exc
    if not raw.startswith(b"/* Experimental finite, single-owner Linux runtime"):
        _reject("missing reviewed runtime source marker")
    observed_sha = sha256(raw).hexdigest()
    if observed_sha != _REVIEWED_RUNTIME_SHA256:
        _reject("finite allocator source differs from reviewed exact bytes")
    return raw, observed_sha


def _read_bounded_artifact(path: Path, limit: int, role: str) -> bytes:
    """Read compiler-produced bytes only after bounding size and inode.

    Never call read_bytes() on an unchecked compiler output. An untrusted or
    broken native driver may write a giant object before exiting with zero.
    This local file check is not a sandbox or foreign-code safety proof.
    """
    try:
        previous = path.lstat()
        if (not stat.S_ISREG(previous.st_mode)
                or not 0 < previous.st_size <= limit):
            _reject("missing or oversized " + role)
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as stream:
            if _source_identity(os.fstat(stream.fileno())) != _source_identity(previous):
                _reject(role + " changed before reading")
            data = stream.read(limit + 1)
            if (len(data) != previous.st_size
                    or _source_identity(os.fstat(stream.fileno())) != _source_identity(previous)):
                _reject(role + " changed during bounded reading")
        if _source_identity(path.lstat()) != _source_identity(previous):
            _reject(role + " output path was replaced")
        return data
    except OSError as exc:
        raise OwnedAArch64RuntimeRejected(
            "E_OWNED_AARCH64_RUNTIME: " + role + " identity unavailable") from exc


def probe_finite_owned_aarch64_runtime(object_bytes: bytes, exports: tuple[str, ...],
                                       *, clang: str = "clang",
                                       qemu_aarch64: str | None = None) -> dict:
    """Compile/link a real bounded allocator; optionally run in QEMU-user.

    This lower-level API accepts a separately checked object, but does not
    independently bind it to Hepta source. Source-facing callers must have
    checked the exported function's *complete* C ABI and its origin first.
    """
    if (type(object_bytes) is not bytes or
            not 0 < len(object_bytes) <= MAX_OBJECT_BYTES or exports != _EXPORT or
            type(exports) is not tuple):
        _reject("requires one checked finite owned_case ABI object")
    inspect_owned_aarch64_object(object_bytes, _EXPORT)
    selected = shutil.which(clang)
    if not selected:
        _reject("Clang unavailable")
    compiler = Path(selected).resolve(strict=True)
    compiler_before = _tool_digest(compiler)
    runtime_bytes, source_sha = _read_reviewed_runtime()
    with tempfile.TemporaryDirectory(prefix=".hepta-finite-arm64-") as temp:
        folder = Path(temp)
        original = folder / "owned.o"
        runtime_c = folder / "runtime.c"
        runtime_obj = folder / "runtime.o"
        linked = folder / "finite.elf"
        original.write_bytes(object_bytes)
        runtime_c.write_bytes(runtime_bytes)
        native = _clang_run(
            [str(compiler), "--target=" + TARGET_AARCH64,
             "-x", "c", "-std=c11", "-ffreestanding", "-nostdinc",
             "-fno-builtin", "-fno-stack-protector", "-O2", "-Wall",
             "-Wextra", "-Werror", "-c", str(runtime_c), "-o", str(runtime_obj)],
            timeout=35)
        if native.returncode != 0:
            _reject("real finite runtime C compile failed: " + native.stderr[:1000])
        data = _read_bounded_artifact(runtime_obj, 1_048_576,
                                      "finite runtime object")
        try:
            symbols = inspect_object_symbols(data, "ELF64", 183)
        except ObjectSymbolsRejected as exc:
            raise OwnedAArch64RuntimeRejected("E_OWNED_AARCH64_RUNTIME: malformed runtime symbols") from exc
        if (symbols["defined"] != _RUNTIME_EXPORTS or
                symbols["undefined"] != frozenset(_EXPORT)):
            _reject("runtime exports or imports differ from exact one-owner ABI")
        link = _clang_run(
            [str(compiler), "--target=" + TARGET_AARCH64, "-fuse-ld=lld",
             "-nostdlib", "-static", "-Wl,-z,noexecstack", "-Wl,-e,_start",
             str(original), str(runtime_obj), "-o", str(linked)],
            timeout=45)
        if link.returncode != 0:
            _reject("real allocator ARM64 link failed: " + link.stderr[:1000])
        payload = _read_bounded_artifact(linked, _MAX_LINKED_BYTES, "linked ELF")
        if len(payload) < 512:
            _reject("linked image has no bounded executable content")
        shape = inspect_synthetic_aarch64_elf(payload, _EXPORT)
        if (_read_reviewed_runtime()[0] != runtime_bytes or
                _tool_digest(compiler) != compiler_before):
            _reject("compiler or finite runtime changed during link")
        ran = False
        runner_sha = None
        execution_record = None
        if qemu_aarch64 is not None:
            if type(qemu_aarch64) is not str or not qemu_aarch64:
                _reject("QEMU runner must be an explicit executable")
            candidate = shutil.which(qemu_aarch64)
            if candidate is None:
                _reject("requested QEMU AArch64 executable unavailable")
            runner_path = Path(candidate).resolve(strict=True)
            if not runner_path.is_file() or not runner_path.name.startswith("qemu-aarch64"):
                _reject("runner is not QEMU AArch64")
            runner_sha = _tool_digest(runner_path)
            execution = _clang_run([str(runner_path), str(linked)], timeout=25)
            if (_tool_digest(runner_path) != runner_sha or
                    _read_bounded_artifact(linked, _MAX_LINKED_BYTES, "linked ELF") != payload):
                _reject("runner or linked executable changed after emulation")
            execution_record = {
                "argv": [str(runner_path), str(linked)],
                "returncode": execution.returncode,
                "stdout": execution.stdout,
                "stderr": execution.stderr,
                "stdout_sha256": sha256(execution.stdout.encode("utf-8")).hexdigest(),
                "stderr_sha256": sha256(execution.stderr.encode("utf-8")).hexdigest(),
                "linked_sha256": sha256(payload).hexdigest(),
                "runner_sha256": runner_sha,
            }
            if execution.returncode != 0:
                raise OwnedAArch64RuntimeRejected(
                    "E_OWNED_AARCH64_RUNTIME: real finite test exited unsuccessfully under QEMU: "
                    + str(execution.returncode) + " " + execution.stderr[:300],
                    execution=execution_record)
            ran = True
        return {
            "schema": "hepta.owned-aarch64-finite-runtime.v1",
            "status": ("finite_qemu_userspace_execution_passed" if ran
                       else "finite_real_runtime_linked_not_executed"),
            "target": TARGET_AARCH64,
            "object_sha256": sha256(object_bytes).hexdigest(),
            "runtime_source_sha256": source_sha,
            "runtime_object_sha256": sha256(data).hexdigest(),
            "linked_sha256": sha256(payload).hexdigest(),
            "linked_bytes": len(payload),
            "compiler_sha256": compiler_before,
            "runner_sha256": runner_sha,
            "execution": execution_record,
            "symbols": shape,
            "scope": "one_selected_owned_case_C_ABI_and_4096_byte_single_live_allocation",
            "real_finite_allocator_linked": True,
            "qemu_user_mode_executed": ran,
            "real_target_device_executed": False,
            "general_allocator_qualified": False,
            "general_linux_abi_qualified": False,
            "whole_language_soundness_proved": False,
        }
