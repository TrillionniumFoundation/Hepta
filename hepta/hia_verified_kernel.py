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
import subprocess
import tempfile
import time

from .artifact_publication import publish_verified, verify_published, withdraw_own_link
from .hia_program import verify_program
from .hia_safe_core import build_safe_core, _profile


class VerifiedKernelRejected(ValueError):
    pass


def select_verified_kernel(document, *, strategy="auto", foreign_extent=None):
    """Choose by admitted source shape, before linking or asking the solver."""
    from .hia_verified_scalar import emit_verified_scalar, VerifiedScalarRejected
    from .hia_verified_simd import emit_verified_simd
    from .hia_verified_simd_check import VerifiedSIMDRejected

    if strategy not in {"auto", "scalar", "simd", "checked"}:
        raise VerifiedKernelRejected("unknown kernel strategy")
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
            return checked, "simd", emit_verified_simd(checked), refusals
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
                          artifact_directory=None):
    """Build privately and publish exactly the successfully validated ELF bytes."""
    checked, selected, image, refusals = select_verified_kernel(
        document, strategy=strategy, foreign_extent=foreign_extent)
    if artifact_directory is not None:
        directory = Path(artifact_directory)
        if not directory.is_dir() or directory.is_symlink():
            raise VerifiedKernelRejected("artifact directory must be an existing ordinary directory")
        selection = {"selected_strategy": selected, "selection_refusals": refusals,
                     "core_sha256": checked.sha256,
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
        destination = Path(os.path.abspath(output))
        if destination.exists() or destination.is_symlink() or not destination.parent.is_dir():
            raise VerifiedKernelRejected("output must be a new file in an existing directory")
        started = time.monotonic()
        with tempfile.TemporaryDirectory(prefix=".hia-verified-simd-", dir=destination.parent) as name:
            root = Path(name)
            obj, candidate = root / "candidate.o", root / "candidate.so"
            obj.write_bytes(image.object_bytes)
            command = [linker, "-m", "elf_x86_64", "-shared", "-z", "defs", "-z", "noexecstack",
                       "-z", "relro", "-z", "now", "--hash-style=both", "--build-id=none",
                       str(obj), "-lc", "-o", str(candidate)]
            linked = subprocess.run(command, capture_output=True, text=True, timeout=30)
            if linked.returncode != 0:
                raise VerifiedKernelRejected("link failed: " + linked.stderr[-8192:])
            data = candidate.read_bytes()
            validation = validate_verified_simd_artifact(
                checked, image.object_bytes, data,
                timeout_ms=timeout_ms, query_directory=query_directory)
            if validation.get("ok") is not True or validation.get("complete") is not True:
                raise VerifiedKernelRejected("final-image validation did not complete")
            publication = publish_verified(candidate, destination, data)
            try:
                verify_published(candidate, destination, data)
                # Source identity is a point-in-time observation, independent
                # of producer byte generation or its account of success.
                identity = validation["checker"]["source_identity"]
                for filename, expected in identity.items():
                    if sha256(Path(__file__).with_name(filename).read_bytes()).hexdigest() != expected:
                        raise VerifiedKernelRejected("checker changed before final publication")
            except BaseException:
                withdraw_own_link(candidate, destination)
                raise
        result = {
            "schema": "hepta.hia.verified-simd-build.v1", "ok": True,
            "status": "smt_validated_not_executed", "output": str(destination),
            "artifact_sha256": publication["sha256"], "artifact_bytes": publication["bytes"],
            "object_sha256": sha256(image.object_bytes).hexdigest(),
            "text_sha256": sha256(image.text_bytes).hexdigest(),
            "validation": validation, "elapsed_seconds": time.monotonic() - started,
        }
    return {**result, "selected_strategy": selected, "selection_refusals": refusals,
            "runtime_solver_calls": 0}
