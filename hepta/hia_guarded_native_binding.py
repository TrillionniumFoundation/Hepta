"""Bind a freshly checked guarded rewrite to its actual native publication.

The guarded proof covers Core operations, not a compiler's self-reported
success.  Before publishing, this gate compares the complete input/IR/interface
identity, reads the staged bytes independently, and constructs the whole final
receipt.  It also withdraws its own link on any interrupted publication.

The native backend, toolchain and host remain trusted; this is a consistency
gate, not a proof of machine-code refinement or cryptographic attestation.
"""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
from pathlib import Path
import tempfile

from .hia_optimization import OptimizationRejected, _digest


def _same_json(actual, expected):
    """Do not let bool/int equality or producer-defined equality admit fields."""
    if type(actual) is not type(expected):
        return False
    if type(expected) is list:
        return len(actual) == len(expected) and all(
            _same_json(left, right) for left, right in zip(actual, expected))
    if type(expected) is dict:
        return set(actual) == set(expected) and all(
            _same_json(actual[key], value) for key, value in expected.items())
    return actual == expected


def _digest_string(value):
    return (type(value) is str and len(value) == 64 and value != "0" * 64
            and all(c in "0123456789abcdef" for c in value))


def build_guarded_native_bound(base, proposal, output, *, policy=None,
                               clang="clang", kind="shared"):
    """Reverify the actual proposal; a previously issued receipt is no authority.

    This is the implementation of ``build_guarded_native``.  Imports stay local
    so that the guarded proof module can delegate here without a module cycle.
    """
    from . import hia_guarded_optimization as guarded
    from . import hia_optimization as optimization
    from .hia_program_llvm import (build_program_native, emit_program_llvm,
                                   _read_artifact, _implementation_hash)
    from .native_tool_identity import digest_executable, ToolIdentityRejected
    from .artifact_publication import (publish_verified, verify_published,
                                       withdraw_own_link)

    if type(kind) is not str or kind not in {"shared", "object"}:
        raise OptimizationRejected("E_HIA_GUARD_OUTPUT: shared or object kind required")
    binding_source = sha256(Path(__file__).read_bytes()).hexdigest()
    original, fast, frozen = guarded._freeze(base, proposal)
    proof = deepcopy(guarded.verify_guarded_optimization(original, frozen, policy))
    if proof["status"] != "verified":
        raise OptimizationRejected("E_HIA_GUARD_NOT_VERIFIED: " + proof["status"]
                                   + ": " + proof["reason"])
    program = guarded._compose(original, fast, frozen)
    if (program.sha256 != proof["candidate_sha256"]
            or original.sha256 != proof["base_sha256"]):
        raise OptimizationRejected("E_HIA_GUARD_BINDING: final Core differs from proof")
    destination = Path(output).absolute()
    if destination.exists() or destination.is_symlink() or not destination.parent.is_dir():
        raise OptimizationRejected("E_HIA_GUARD_OUTPUT: new path in an existing directory required")
    import z3

    expected_ir = emit_program_llvm(program, target=proof["target"])

    def recheck(compiler=None, compiler_digest=None):
        if (guarded.guarded_checker_identity() != proof["checker_sha256"]
                or optimization._solver_identity(z3) != proof["solver"]
                or sha256(Path(__file__).read_bytes()).hexdigest() != binding_source
                or _implementation_hash() != expected_ir.implementation_sha256):
            raise OptimizationRejected("E_HIA_GUARD_STALE: proof or backend implementation changed during build")
        if compiler is not None:
            try:
                current = digest_executable(compiler)
            except ToolIdentityRejected as exc:
                raise OptimizationRejected("E_HIA_GUARD_STALE: compiler identity unavailable") from exc
            if current != compiler_digest:
                raise OptimizationRejected("E_HIA_GUARD_STALE: compiler identity changed during build")

    recheck()
    with tempfile.TemporaryDirectory(prefix=".hia-guarded-", dir=destination.parent) as tmp:
        stage = Path(tmp) / ("guarded.so" if kind == "shared" else "guarded.o")
        native = deepcopy(build_program_native(program, stage, clang=clang, kind=kind,
                                                target=proof["target"]))
        expected = {
            "schema": "hepta.hia.program.native.v1", "ok": True,
            "status": "native_compiled_not_executed", "kind": kind,
            "target": proof["target"], "core_sha256": program.sha256,
            "input_sha256": program.input_sha256, "output": str(stage),
            "llvm_ir_sha256": expected_ir.sha256,
            "implementation_sha256": expected_ir.implementation_sha256,
            "profile": expected_ir.profile, "exports": list(expected_ir.exports),
        }
        if (type(native) is not dict
                or any(not _same_json(native.get(key), value)
                       for key, value in expected.items())):
            raise OptimizationRejected(
                "E_HIA_GUARD_RECEIPT: native receipt names a different Core, IR, interface, target or artifact")

        toolchain = native.get("toolchain")
        if (type(toolchain) is not dict or not _digest_string(toolchain.get("sha256"))
                or any(type(toolchain.get(key)) is not str or not toolchain[key]
                       for key in ("path", "version", "default_target"))
                or not Path(toolchain["path"]).is_absolute()):
            raise OptimizationRejected("E_HIA_GUARD_RECEIPT: complete native compiler identity required")
        compiler, compiler_digest = Path(toolchain["path"]), toolchain["sha256"]
        data = _read_artifact(stage)
        if (not _digest_string(native.get("artifact_sha256"))
                or sha256(data).hexdigest() != native["artifact_sha256"]
                or type(native.get("artifact_bytes")) is not int
                or len(data) != native["artifact_bytes"]):
            raise OptimizationRejected("E_HIA_GUARD_ARTIFACT: native bytes or length changed")

        # All accesses needed by the result happen BEFORE there is a user-facing
        # path.  Missing receipt data must never fail only after publication.
        native["output"] = str(destination)
        receipt = {
            "schema": "hepta.hia.optimized-native.v1",
            "status": "verified_core_native_bound", "verification": proof, "native": native,
            "binding_sha256": _digest({
                "base": original.sha256, "candidate": program.sha256,
                "verification": proof["verification_sha256"],
                "artifact": native["artifact_sha256"],
                "compiler": compiler_digest, "target": native["target"],
            }),
            "claims": {"unverified_candidate_published": False, "final_artifact_bound": True,
                       "performance_qualified": False, "backend_refinement_proved": False},
        }
        recheck(compiler, compiler_digest)
        try:
            # Include publication itself: an interruption can occur after its
            # no-replace link is created but before it returns a receipt.
            publish_verified(stage, destination, data)
            recheck(compiler, compiler_digest)
            verify_published(stage, destination, data)
        except BaseException:
            withdraw_own_link(stage, destination)
            raise
    return receipt
