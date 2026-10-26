"""AArch64 Linux *object-only* backend for source-bound Owned LLVM.

Reuses Hepta's one checked source/Resource IR/Owned LLVM emitter, bounded Clang
runner, ELF structure/symbol scanner and verified artifact publisher.  A cross
object does NOT qualify target ABI calling behavior, Linux runtime, native
Rust borrow checks on AArch64, or physical hardware execution.
"""
from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import re
import shutil
import tempfile

from .artifact_publication import PublicationRejected, publish_verified, verify_published, withdraw_own_link
from .llvm_owned_backend import (OwnedLLVM, LLVMOwnedRejected, PROFILE, TARGET,
                                 emit_owned_llvm, reject)
from .llvm_ssa_backend import _clang_run
from .object_structure import qualified_object
from .object_symbols import ObjectSymbolsRejected, inspect_object_symbols
from .owned_target_layout import OwnedTargetLayoutRejected, probe_owned_target_layout
from .native_tool_identity import ToolIdentityRejected, digest_executable
from .pipeline import analyze_project, compiler_hash


TARGET_AARCH64 = "aarch64-unknown-linux-gnu"
MACHINE_AARCH64 = 183
MAX_OBJECT_BYTES = 16 * 1024 * 1024
# Explicit ABI *assumptions* for this object-only profile. Linker/runtime
# implementations are not checked and nothing is linked or executed.
_ALLOWED_IMPORTS = frozenset({"malloc", "free", "abort", "memset", "memcpy", "memmove"})


def retarget_owned_llvm(ir: OwnedLLVM, target: str) -> tuple[str, str]:
    """Change exactly the LLVM target-triple declaration, nothing else.

    Both supported Linux ABIs are 64-bit LP64. The existing checked source
    emitter retains the authoritative memory/value layout, which still needs
    independent target execution and refinement checks.
    """
    if type(ir) is not OwnedLLVM or target != TARGET_AARCH64:
        reject("Only the reviewed AArch64 Linux relocatable-object target is supported",
               "E_LLVM_OWNED_TARGET")
    ir.check_identity()
    lines = ir.text.splitlines(keepends=True)
    original = f'target triple = "{TARGET}"\n'
    if (sum(line.startswith("target triple") for line in lines) != 1
            or lines.count(original) != 1
            or any(line.startswith("target datalayout") for line in lines)
            or not lines or lines[0] !=
                f'; {PROFILE}: directly emitted from checked Hepta, no C/Rust codegen\n'):
        reject("Unrecognized native Owned LLVM target/layout declaration",
               "E_LLVM_OWNED_TARGET")
    index = lines.index(original)
    lines[index] = f'target triple = "{target}"\n'
    native_text = "".join(lines)
    if native_text == ir.text or not native_text.isascii():
        reject("Native target rewriting did not produce a bounded LLVM text",
               "E_LLVM_OWNED_TARGET")
    return native_text, sha256(native_text.encode("ascii")).hexdigest()


def inspect_owned_aarch64_object(data: bytes, exports: tuple[str, ...]) -> dict:
    """Require exact ELF64 AArch64 external functions and bounded imports."""
    if (type(data) is not bytes or not 0 < len(data) <= MAX_OBJECT_BYTES
            or type(exports) is not tuple or not exports
            or any(type(name) is not str or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) is None
                   for name in exports)
            or len(set(exports)) != len(exports)):
        reject("Malformed AArch64 object or requested exported function inventory",
               "E_LLVM_OWNED_TARGET_OBJECT")
    if not qualified_object(data, "ELF64", MACHINE_AARCH64):
        reject("Object is not a complete little-endian AArch64 ELF64 relocatable",
               "E_LLVM_OWNED_TARGET_OBJECT")
    try:
        symbols = inspect_object_symbols(data, "ELF64", MACHINE_AARCH64)
    except ObjectSymbolsRejected as exc:
        raise LLVMOwnedRejected("E_LLVM_OWNED_TARGET_SYMBOL: " + str(exc)) from exc
    if symbols["defined"] != frozenset(exports):
        reject("Native AArch64 export inventory differs from checked Hepta exports",
               "E_LLVM_OWNED_TARGET_EXPORT")
    if not symbols["undefined"] <= _ALLOWED_IMPORTS:
        reject("Native AArch64 object depends on unreviewed foreign symbols",
               "E_LLVM_OWNED_TARGET_IMPORT")
    return {"format": "ELF64", "machine": MACHINE_AARCH64,
            "exports": sorted(symbols["defined"]),
            "unresolved_imports": sorted(symbols["undefined"]),
            "external_libraries_verified": False}


def compile_owned_aarch64_object(ir: OwnedLLVM, *, program, checked, output,
                                 project_sha256=None, clang="clang") -> dict:
    """Compile source-bound Owned LLVM to a target object, never a binary.

    Caller must still establish a fresh pinned Rust reference. This function
    independently regenerates the checked LLVM from the given AST/resource
    model and refuses to accept a standalone attacker-supplied LLVM string.
    """
    if type(ir) is not OwnedLLVM:
        reject("Typed Owned LLVM is required", "E_LLVM_OWNED_TARGET_SOURCE")
    ir.check_identity()
    if ir != emit_owned_llvm(program, checked, project_sha256=project_sha256):
        reject("Owned LLVM differs from regenerated checked source",
               "E_LLVM_OWNED_TARGET_SOURCE")
    target_text, target_ir_hash = retarget_owned_llvm(ir, TARGET_AARCH64)
    if not ir.functions:
        reject("At least one checked C scalar export is required",
               "E_LLVM_OWNED_TARGET_EXPORT")
    selected = shutil.which(clang)
    if selected is None:
        reject("Clang backend executable unavailable", "E_LLVM_OWNED_TARGET_TOOLCHAIN")
    compiler = Path(selected).resolve()
    try:
        tool_hash = digest_executable(compiler)
    except ToolIdentityRejected as exc:
        reject("Bounded compiler identity check failed: " + str(exc),
               "E_LLVM_OWNED_TARGET_TOOLCHAIN")
    version = _clang_run([str(compiler), "--version"], timeout=10)
    if version.returncode or not version.stdout.strip():
        reject("Clang identity probe failed", "E_LLVM_OWNED_TARGET_TOOLCHAIN")
    destination = Path(os.path.abspath(output))
    if destination.is_symlink() or destination.exists() or not destination.parent.is_dir():
        reject("A new ordinary output under an existing directory is required",
               "E_LLVM_OWNED_TARGET_OUTPUT")
    # Verify target data layout with independent target-C compiler static
    # assertions. An ELF machine ID alone says nothing about ptr/len offsets.
    try:
        target_layout = probe_owned_target_layout(compiler, TARGET_AARCH64, target_text)
    except OwnedTargetLayoutRejected as exc:
        raise LLVMOwnedRejected("E_LLVM_OWNED_TARGET_LAYOUT: " + str(exc)) from exc
    with tempfile.TemporaryDirectory(prefix=".hepta-owned-aarch64-", dir=destination.parent) as folder:
        ll = Path(folder) / "native.ll"
        stage = Path(folder) / "native.o"
        ll.write_text(target_text, encoding="ascii")
        argv = [str(compiler), "--target=" + TARGET_AARCH64, "-x", "ir",
                "-O3", "-fPIC", "-c", str(ll), "-o", str(stage)]
        native = _clang_run(argv, timeout=60)
        if native.returncode:
            reject("Clang target object generation failed: " + native.stderr[:2000],
                   "E_LLVM_OWNED_TARGET_NATIVE")
        if not stage.is_file() or not 0 < stage.stat().st_size <= MAX_OBJECT_BYTES:
            reject("Clang did not produce a bounded ordinary target object",
                   "E_LLVM_OWNED_TARGET_NATIVE")
        data = stage.read_bytes()
        observed = inspect_owned_aarch64_object(data, ir.functions)
        try:
            compiler_still_identical = digest_executable(compiler) == tool_hash
        except ToolIdentityRejected:
            compiler_still_identical = False
        if (not compiler_still_identical
                or compiler_hash() != ir.compiler_sha256
                or ir != emit_owned_llvm(program, checked, project_sha256=project_sha256)):
            reject("Source or compiler changed before publication",
                   "E_LLVM_OWNED_TARGET_STALE")
        try:
            receipt = publish_verified(stage, destination, data)
            if (receipt["sha256"] != sha256(data).hexdigest()
                    or receipt["bytes"] != len(data)
                    or verify_published(stage, destination, data) != receipt):
                raise PublicationRejected("E_PUBLISH_RECEIPT: target publication changed")
            if ir != emit_owned_llvm(program, checked, project_sha256=project_sha256):
                raise PublicationRejected("E_PUBLISH_SOURCE: source changed after publication")
        except PublicationRejected as exc:
            withdraw_own_link(stage, destination)
            raise LLVMOwnedRejected("E_LLVM_OWNED_TARGET_PUBLICATION: " + str(exc)) from exc
    return {"schema": "hepta.llvm-owned-aarch64-object.v1",
            "status": "cross_object_only_not_executed",
            "profile": PROFILE, "target": TARGET_AARCH64,
            "artifact_sha256": receipt["sha256"], "artifact_bytes": receipt["bytes"],
            "llvm_source_sha256": ir.sha256, "target_llvm_sha256": target_ir_hash,
            "semantic_sha256": ir.semantic_sha256,
            "resource_ir_sha256": ir.resource_ir_sha256,
            "resource_verification_sha256": ir.resource_verification_sha256,
            "compiler_sha256": ir.compiler_sha256,
            "toolchain": {"path": str(compiler), "sha256": tool_hash,
                          "version": version.stdout.splitlines()[0]},
            "symbols": observed,
            "target_layout_probe": target_layout,
            "claims": {"source_and_resource_origin_regenerated": True,
                       "target_c_layout_compiled": True,
                       "aarch64_elf_object_compiled": True,
                       "target_object_executed": False, "target_link_succeeded": False,
                       "foreign_abi_qualified": False,
                       "target_data_layout_refinement_proved": False,
                       "aarch64_rust_borrow_equivalence_proved": False,
                       "physical_hardware_tested": False,
                       "whole_language_memory_safety_proved": False}}


def build_owned_aarch64_source(source, output, *, rustc=None, clang="clang",
                               locked=False, synthetic_link_probe=False) -> dict:
    """User-facing strict source build: Rust reference + resource checks first."""
    report = {"schema": "hepta.build-llvm-owned-aarch64.v1", "ok": False,
              "status": "rejected", "source": str(source), "output": str(output),
              "target": TARGET_AARCH64,
              "whole_project_blockers_closed": False}
    try:
        if type(locked) is not bool or type(synthetic_link_probe) is not bool:
            reject("Locked and synthetic-link flags must be booleans",
                   "E_LLVM_OWNED_TARGET_INPUT")
        analyzed = analyze_project(source, backend="rust", native=True, rustc=rustc,
                                   locked=locked, crate_type="rlib")
        report["reference_validation"] = analyzed.report
        if (analyzed.report.get("ok") is not True
                or analyzed.report.get("checks", {}).get("rust_borrows_types") != "rustc_checked"
                or analyzed.report.get("assumptions")
                or analyzed.project is None or analyzed.program is None or analyzed.checked is None):
            reject("Pinned real Rust reference checking is required",
                   "E_LLVM_OWNED_TARGET_REFERENCE")
        project = analyzed.project
        destination = Path(os.path.abspath(output))
        if (destination.is_symlink() or destination.exists() or not destination.parent.is_dir()
                or destination.resolve(strict=False) in {
                    Path(p).resolve() for p in project.sources}):
            reject("Cannot replace a source input or existing output",
                   "E_LLVM_OWNED_TARGET_OUTPUT")
        if not project.unchanged():
            reject("Input source graph was modified", "E_LLVM_OWNED_TARGET_STALE")
        ir = emit_owned_llvm(analyzed.program, analyzed.checked,
                             project_sha256=project.identity)
        # First compile into a staging directory. No requested output is
        # visible while source/ABI/receipt checks are still running.
        with tempfile.TemporaryDirectory(prefix=".hepta-owned-aarch64-source-",
                                         dir=destination.parent) as directory:
            stage = Path(directory) / "verified.o"
            backend = compile_owned_aarch64_object(
                ir, program=analyzed.program, checked=analyzed.checked, output=stage,
                project_sha256=project.identity, clang=clang)
            data = stage.read_bytes() if stage.is_file() else b""
            layout = backend.get("target_layout_probe")
            synthetic_link = None
            if synthetic_link_probe:
                # This only validates link-time relocation against deliberately
                # NONFUNCTIONAL freestanding C shims. Never publish the linked
                # synthetic image or turn its result into runtime/ABI proof.
                from .owned_aarch64_link import probe_owned_aarch64_freestanding_link
                synthetic_link = probe_owned_aarch64_freestanding_link(
                    data, ir.functions, clang=clang)
                if (synthetic_link.get("status") !=
                        "synthetic_freestanding_link_only_not_executed"
                        or synthetic_link.get("object_sha256") != sha256(data).hexdigest()
                        or synthetic_link.get("real_allocator_linked") is not False
                        or synthetic_link.get("c_abi_execution_qualified") is not False):
                    reject("Synthetic link receipt differs from checked native object",
                           "E_LLVM_OWNED_TARGET_LINK")
            if (not data or len(data) != backend.get("artifact_bytes")
                    or sha256(data).hexdigest() != backend.get("artifact_sha256")
                    or type(layout) is not dict
                    or layout.get("status") != "target_c_static_assertions_compiled_not_executed"
                    or layout.get("target") != TARGET_AARCH64
                    or layout.get("bound_llvm_sha256") != backend.get("target_llvm_sha256")
                    or layout.get("compiler_checked") is not True
                    or layout.get("native_abi_execution_qualified") is not False
                    or layout.get("llvm_layout_equivalence_proved") is not False
                    or not project.unchanged() or compiler_hash() != ir.compiler_sha256):
                reject("Source or native artifact changed before source-level publication",
                       "E_LLVM_OWNED_TARGET_STALE")
            try:
                publication = publish_verified(stage, destination, data)
                if publication["sha256"] != backend["artifact_sha256"]:
                    raise PublicationRejected("E_PUBLISH_RECEIPT: backend digest differs")
                if not project.unchanged() or compiler_hash() != ir.compiler_sha256:
                    raise PublicationRejected("E_PUBLISH_SOURCE: source/compiler changed after link")
                if verify_published(stage, destination, data) != publication:
                    raise PublicationRejected("E_PUBLISH_RECEIPT: staged/published bytes changed")
            except PublicationRejected as exc:
                withdraw_own_link(stage, destination)
                raise LLVMOwnedRejected(
                    "E_LLVM_OWNED_TARGET_PUBLICATION: " + str(exc)) from exc
        report.update(ok=True, status="cross_object_only_not_executed",
                      native_backend=backend,
                      synthetic_link_probe=synthetic_link,
                      synthetic_link_probe_attempted=synthetic_link_probe,
                      published_artifact_sha256=publication["sha256"],
                      published_artifact_bytes=publication["bytes"],
                      source_binding={"project_sha256": project.identity,
                                      "source_sha256": analyzed.report.get("source_sha256"),
                                      "compiler_sha256": ir.compiler_sha256})
    except (ValueError, OSError) as exc:
        report["diagnostics"] = [{"code": str(exc).split(":", 1)[0]
                                  if str(exc).startswith("E_") else "E_LLVM_OWNED_TARGET",
                                  "message": str(exc)}]
    return report


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source")
    parser.add_argument("--output", required=True)
    parser.add_argument("--rustc")
    parser.add_argument("--clang", default="clang")
    parser.add_argument("--locked", action="store_true")
    parser.add_argument("--synthetic-link-probe", action="store_true",
                        help="Check only ARM64 relocations against NONFUNCTIONAL dummy stubs; never run the linked image")
    args = parser.parse_args(argv)
    report = build_owned_aarch64_source(args.source, args.output,
                                        rustc=args.rustc, clang=args.clang,
                                        locked=args.locked,
                                        synthetic_link_probe=args.synthetic_link_probe)
    print(json.dumps(report, sort_keys=True, allow_nan=False))
    return 0 if report["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
