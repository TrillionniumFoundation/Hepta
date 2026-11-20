"""Opt-in kernel selection with publication gated by final-image validation.

Selection refusals may retain the existing checked Safe Core lowering. A failed
proof, a deadline or a changed artifact never triggers another implementation.
The ordinary language compiler and its runtime checks are unchanged.
"""
from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import json
import os
import platform
import shutil
import stat
import tempfile
import time

from .artifact_publication import publish_verified, verify_published, withdraw_own_link
from .clang_capture import run_bounded
from .hia_machine_x64 import native_implementation_identity
from .hia_program import verify_program
from .hia_safe_core import build_safe_core, _profile
from .native_tool_identity import digest_executable


MAX_SIMD_IMAGE_BYTES = 8 * 1024 * 1024
SIMD_SOURCE_FILES = ("hia_verified_kernel.py", "hia_verified_simd.py",
                     "hia_machine_x64.py", "hia_machine_elf.py")


class VerifiedKernelRejected(ValueError):
    pass


def _require(condition, message):
    if not condition:
        raise VerifiedKernelRejected(message)


def _simd_producer_identity():
    return {**{name: sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
               for name in SIMD_SOURCE_FILES},
            "selected_native_encoder": sha256(native_implementation_identity()).hexdigest()}


def _read_simd_image(path):
    """Read a stable regular image without an unbounded allocation or FIFO wait."""
    def identity(st):
        return (st.st_dev, st.st_ino, st.st_mode, st.st_size, st.st_mtime_ns, st.st_ctime_ns)

    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    try:
        fd = os.open(path, flags)
        try:
            stream = os.fdopen(fd, "rb")
        except BaseException:
            os.close(fd)
            raise
        with stream:
            before = os.fstat(stream.fileno())
            _require(stat.S_ISREG(before.st_mode) and 64 <= before.st_size <= MAX_SIMD_IMAGE_BYTES,
                     "linked image must be a bounded regular ELF file")
            data = stream.read(MAX_SIMD_IMAGE_BYTES + 1)
            after = os.fstat(stream.fileno())
        _require(len(data) == before.st_size and identity(before) == identity(after) == identity(path.lstat()),
                 "linked image changed during bounded read")
        return data
    except OSError as exc:
        raise VerifiedKernelRejected("linked image is unavailable or not an ordinary file") from exc


def select_verified_kernel(document, *, strategy="auto", foreign_extent=None, simd_unroll=4):
    """Choose by admitted source shape, before linking or asking the solver."""
    from .hia_verified_scalar import emit_verified_scalar, VerifiedScalarRejected
    from .hia_verified_simd import emit_verified_simd
    from .hia_verified_simd_check import VerifiedSIMDRejected

    if strategy not in {"auto", "scalar", "simd", "checked"}:
        raise VerifiedKernelRejected("unknown kernel strategy")
    _require(type(simd_unroll) is int and simd_unroll in (1, 4), "SIMD unroll must be exactly 1 or 4")
    checked = verify_program(document)
    refusals = []
    if strategy in {"auto", "scalar"} and foreign_extent is None:
        try:
            return checked, "scalar", emit_verified_scalar(checked), refusals
        except VerifiedScalarRejected as exc:
            if strategy == "scalar":
                raise
            refusals.append({"strategy": "scalar", "reason": str(exc)})
    if strategy in {"auto", "simd"} and foreign_extent is None:
        try:
            return checked, "simd", emit_verified_simd(checked, unroll=simd_unroll), refusals
        except VerifiedSIMDRejected as exc:
            if strategy == "simd":
                raise
            refusals.append({"strategy": "simd", "reason": str(exc)})
    if strategy in {"scalar", "simd"}:
        raise VerifiedKernelRejected("direct kernels do not use the packed foreign-extent ABI")
    functions = checked.as_dict()["functions"]
    if len(functions) != 1:
        raise VerifiedKernelRejected("one function is required")
    exports = () if foreign_extent is None else ((functions[0]["name"], foreign_extent),)
    _profile(checked, foreign_buffer_exports=exports, profile_version=2)
    return checked, "checked", None, refusals


def build_verified_kernel(document, output, *, strategy="auto", foreign_extent=None,
                          linker="ld", timeout_ms=15000, query_directory=None,
                          artifact_directory=None, simd_unroll=4):
    """Build privately and publish exactly the successfully validated ELF bytes."""
    producer_identity = (_simd_producer_identity()
                         if strategy in {"auto", "simd"} and foreign_extent is None else None)
    checked, selected, image, refusals = select_verified_kernel(
        document, strategy=strategy, foreign_extent=foreign_extent, simd_unroll=simd_unroll)
    if artifact_directory is not None:
        directory = Path(artifact_directory)
        if not directory.is_dir() or directory.is_symlink():
            raise VerifiedKernelRejected("artifact directory must be an existing ordinary directory")
        selection = {"selected_strategy": selected, "selection_refusals": refusals,
                     "core_sha256": checked.sha256,
                     "simd_unroll": simd_unroll if selected == "simd" else None,
                     "object_sha256": sha256(image.object_bytes).hexdigest() if image is not None else None}
        with (directory / "selection.json").open("x") as stream:
            json.dump(selection, stream, sort_keys=True, indent=2)
            stream.write("\n")
        if image is not None:
            for name, data in (("candidate.o", image.object_bytes), ("candidate.text.bin", image.text_bytes)):
                with (directory / name).open("xb") as stream:
                    stream.write(data)
    if selected == "scalar":
        from .hia_verified_scalar import build_verified_scalar
        result = build_verified_scalar(checked, output, image=image, linker=linker,
                                       timeout_ms=timeout_ms, query_directory=query_directory)
    elif selected == "checked":
        result = build_safe_core(checked, output, foreign_extent=foreign_extent,
                                linker=linker, timeout_ms=timeout_ms,
                                query_directory=query_directory, profile_version=2)
    else:
        from .hia_verified_simd_check import validate_verified_simd_artifact
        _require(platform.system() == "Linux" and platform.machine().lower() in {"x86_64", "amd64"},
                 "shared linkage requires a Linux x86-64 host")
        _require(producer_identity == _simd_producer_identity(), "producer changed during emission")
        destination = Path(os.path.abspath(output))
        if destination.exists() or destination.is_symlink() or not destination.parent.is_dir():
            raise VerifiedKernelRejected("output must be a new file in an existing directory")
        found = shutil.which(linker)
        _require(found is not None, "GNU ld is required")
        tool = Path(found).resolve()
        tool_digest = digest_executable(tool)
        version = run_bounded([str(tool), "--version"], timeout=10,
                              stdout_limit=65536, stderr_limit=65536)
        _require(version.returncode == 0 and version.stdout.startswith("GNU ld "), "GNU ld is required")
        flags = ["-m", "elf_x86_64", "-shared", "-z", "defs", "-z", "noexecstack",
                 "-z", "relro", "-z", "now", "--hash-style=both", "--build-id=none"]
        started = time.monotonic()
        with tempfile.TemporaryDirectory(prefix=".hia-verified-simd-", dir=destination.parent) as name:
            root = Path(name)
            obj, candidate = root / "candidate.o", root / "candidate.so"
            obj.write_bytes(image.object_bytes)
            command = [str(tool), *flags, str(obj), "-lc", "-o", str(candidate)]
            linked = run_bounded(command, timeout=30, stdout_limit=65536, stderr_limit=1048576)
            if linked.returncode != 0:
                raise VerifiedKernelRejected("link failed: " + linked.stderr[-8192:])
            data = _read_simd_image(candidate)
            validation = validate_verified_simd_artifact(
                checked, image.object_bytes, data,
                timeout_ms=timeout_ms, query_directory=query_directory)
            if validation.get("ok") is not True or validation.get("complete") is not True:
                raise VerifiedKernelRejected("final-image validation did not complete")
            def recheck():
                _require(producer_identity == _simd_producer_identity() and
                         tool_digest == digest_executable(tool),
                         "producer or linker changed during build")
                identity = validation["checker"]["source_identity"]
                for filename, expected in identity.items():
                    if sha256(Path(__file__).with_name(filename).read_bytes()).hexdigest() != expected:
                        raise VerifiedKernelRejected("checker changed before final publication")

            recheck()
            publication = publish_verified(candidate, destination, data)
            try:
                recheck()
                verify_published(candidate, destination, data)
            except BaseException:
                withdraw_own_link(candidate, destination)
                raise
        result = {
            "schema": "hepta.hia.verified-simd-build.v1", "ok": True,
            "status": "smt_validated_not_executed", "output": str(destination),
            "artifact_sha256": publication["sha256"], "artifact_bytes": publication["bytes"],
            "object_sha256": sha256(image.object_bytes).hexdigest(),
            "text_sha256": sha256(image.text_bytes).hexdigest(),
            "source_identity": producer_identity, "simd_unroll": simd_unroll,
            "toolchain": {"path": str(tool), "sha256": tool_digest,
                          "version": version.stdout.splitlines()[0], "flags": flags},
            "validation": validation, "elapsed_seconds": time.monotonic() - started,
        }
    return {**result, "selected_strategy": selected, "selection_refusals": refusals,
            "runtime_solver_calls": 0}
