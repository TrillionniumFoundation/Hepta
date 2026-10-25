"""Hepta's human/agent command line. Reports use versioned JSON schemas."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from . import __version__
from .ast import HeptaError
from .backend import compile_rust, emit_header, find_rustc, toolchain_info
from .pipeline import analyze, analyze_project, inspect_analysis
from .protocol import apply_patch
from .cfg import CFGRejected
from .cfg_analysis import CFGAnalysisRejected
from .ssa import SSARejected
from .ssa_verify import SSAVerificationRejected
from .hsir_v1_ssa import V1SSARejected
from .source_bound_reconcile import SourceBoundReconcileRejected
from .llvm_ssa_backend import LLVMSSARejected


def output_json(value):
    print(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="hepta", description="Hepta native systems language")
    parser.add_argument("--version", action="version", version="hepta " + __version__)
    sub = parser.add_subparsers(dest="command", required=True)
    doctor = sub.add_parser("doctor", help="Inspect the actual native toolchain")
    doctor.add_argument("--rustc")
    lock = sub.add_parser("lock", help="Lock local package source and dependency bytes")
    lock.add_argument("package", nargs="?", default=".")
    importer = sub.add_parser("import-c", help="Import the supported C header subset using real compiler probes")
    importer.add_argument("header")
    importer.add_argument("--output", "-o", required=True)
    importer.add_argument("--module", default="c_imported")
    importer.add_argument("--cc")
    migrator = sub.add_parser("migrate-c", help="Fail-closed Clang AST C11 to Hepta L1 candidate")
    migrator.add_argument("source")
    migrator.add_argument("--output", "-o", required=True)
    migrator.add_argument("--clang", default="clang")
    migrator.add_argument("--module", default="c_migrated")
    cpp_migration = sub.add_parser("migrate-cpp", help="Fail-closed Clang++ C++20 to Hepta L1 candidate")
    cpp_migration.add_argument("source")
    cpp_migration.add_argument("--output", "-o", required=True)
    cpp_migration.add_argument("--clangxx", default="clang++")
    cpp_migration.add_argument("--module", default="cpp_migrated")
    bridge = sub.add_parser("bridge-cpp", help="Generate narrow L0 C++ to C ABI wrappers")
    bridge.add_argument("source")
    bridge.add_argument("--clangxx", default="clang++")
    bridge.add_argument("--output-dir", required=True)
    bridge.add_argument("--exception-mode", choices=["noexcept_only", "catch_status"],
                        default="noexcept_only")
    llvm_ssa = sub.add_parser("build-llvm-ssa", help="Build checked SSA/PHI i32 profile through native LLVM")
    llvm_ssa.add_argument("source")
    llvm_ssa.add_argument("--output", "-o", required=True)
    llvm_ssa.add_argument("--rustc")
    llvm_ssa.add_argument("--clang", default="clang")
    llvm_ssa.add_argument("--locked", action="store_true")
    llvm_ssa.add_argument("--target", choices=[
        "x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu",
        "x86_64-pc-windows-msvc",
    ], help="Compile only a target object; no target execution or external C ABI claim")
    llvm_scalar = sub.add_parser("build-llvm-scalar", help="Build strict HSIR i32 profile through LLVM, after rustc validation")
    llvm_scalar.add_argument("source")
    llvm_scalar.add_argument("--output", "-o", required=True)
    llvm_scalar.add_argument("--rustc")
    llvm_scalar.add_argument("--clang", default="clang")
    llvm_scalar.add_argument("--locked", action="store_true")
    llvm_scalar.add_argument("--target", choices=[
        "x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu",
        "x86_64-pc-windows-msvc"
    ], help="Cross-compile a machine object only; target execution and ABI remain unqualified")
    reconcile = sub.add_parser("ssa-v1-reconcile", help="Recheck a PR14 v1 snapshot against exact source via rustc before SSA")
    reconcile.add_argument("source")
    reconcile.add_argument("--envelope", required=True, help="PR14 hepta hsir-v1 JSON export or inner snapshot")
    reconcile.add_argument("--rustc")
    for cmd in ["check", "inspect", "hsir", "cfg", "cfg-analyze", "ssa", "ssa-verify", "ssa-v1-verify", "emit", "header", "build", "run", "patch"]:
        p = sub.add_parser(cmd)
        p.add_argument("source")
        p.add_argument("--rustc")
        p.add_argument("--cc")
        p.add_argument("--backend", choices=["rust", "c"], default="rust")
        p.add_argument("--target")
        p.add_argument("--locked", action="store_true")
        p.add_argument("--json", action="store_true", help="Machine-readable results (default for checks/builds)")
        if cmd != "patch":
            p.add_argument("--no-std", action="store_true")
            p.add_argument("--crate-type", choices=["bin", "staticlib", "cdylib", "rlib", "obj"], default="bin" if cmd in {"build", "run"} else "rlib")
        if cmd in {"check", "inspect"}:
            p.add_argument("--frontend-only", action="store_true", help="Explicitly skip native/borrow checks; output cannot be treated as a complete check")
        if cmd in {"emit", "header", "build"}:
            p.add_argument("--output", "-o")
        if cmd in {"build", "run"}:
            p.add_argument("--link-arg", action="append", default=[])
        if cmd == "patch":
            p.add_argument("--request", required=True, help="Path to a hepta.patch.v1 JSON request")
            p.add_argument("--apply", action="store_true", help="Atomically apply after native validation")
    args = parser.parse_args(argv)
    try:
        if args.command == "lock":
            from .packages import write_lock
            output_json(write_lock(args.package))
            return 0
        if args.command == "import-c":
            from .c_import import import_header
            imported = import_header(args.header, cc=args.cc, module=args.module)
            dest = Path(args.output).resolve()
            if dest == Path(args.header).resolve():
                raise ValueError("Output cannot overwrite the C input header")
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(imported.source)
            manifest = dest.with_suffix(dest.suffix + ".imports.json")
            manifest.write_text(json.dumps(imported.manifest, indent=2, sort_keys=True) + "\n")
            output_json({"schema": "hepta.import-c.v1", "ok": True, "output": str(dest), "manifest": str(manifest), "validation": imported.manifest})
            return 0
        if args.command == "migrate-c":
            from .c2hepta import main as migrate_c_main
            return migrate_c_main([args.source, "--output", args.output,
                                   "--clang", args.clang, "--module", args.module])
        if args.command == "migrate-cpp":
            from .cpp2hepta import main as migrate_cpp_main
            return migrate_cpp_main([args.source, "--output", args.output,
                                     "--clangxx", args.clangxx, "--module", args.module])
        if args.command == "bridge-cpp":
            from .cpp_bridge import main as bridge_cpp_main
            return bridge_cpp_main([args.source, "--output-dir", args.output_dir,
                                    "--clangxx", args.clangxx,
                                    "--exception-mode", args.exception_mode])
        if args.command == "build-llvm-ssa":
            from .cfg import lower_checked_cfg
            from .ssa import lower_cfg_scalar_ssa
            from .llvm_ssa_backend import emit_scalar_ssa_llvm, compile_scalar_ssa_llvm
            reference = analyze_project(Path(args.source).resolve(),
                                        rustc=args.rustc, native=True,
                                        backend="rust", locked=args.locked,
                                        crate_type="cdylib")
            if not reference.report["ok"]:
                output_json(reference.report)
                return 1
            dest = Path(args.output).resolve()
            if dest in {Path(p) for p in reference.project.sources}:
                raise ValueError("Output cannot overwrite any source in the checked project graph")
            cfg = lower_checked_cfg(reference.program, reference.checked)
            ssa = lower_cfg_scalar_ssa(cfg)
            generated = emit_scalar_ssa_llvm(ssa, cfg)
            if args.target:
                from .llvm_ssa_target import compile_ssa_target_object
                build = compile_ssa_target_object(generated, target=args.target,
                                                  clang=args.clang, output=dest)
            else:
                build = compile_scalar_ssa_llvm(generated, clang=args.clang, output=dest)
            output_json({"schema": "hepta.build-llvm-ssa.v0", "ok": True,
                         "status": build["status"],
                         "source_cfg_sha256": cfg.sha256,
                         "source_ssa_sha256": ssa.sha256,
                         "structural_verification_sha256": generated.verification_sha256,
                         "reference_validation": reference.report, "build": build})
            return 0
        if args.command == "build-llvm-scalar":
            # Never qualify a new backend merely from a frontend-only result.
            # The pinned real rustc reference must complete its native check.
            from .hsir import lower_checked_program
            from .llvm_scalar_backend import emit_scalar_llvm, compile_scalar_llvm, compile_scalar_object
            reference = analyze_project(Path(args.source).resolve(),
                                        rustc=args.rustc, native=True,
                                        backend="rust", locked=args.locked,
                                        crate_type="cdylib")
            if not reference.report["ok"]:
                output_json(reference.report)
                return 1
            hsir = lower_checked_program(reference.program, reference.checked)
            code = emit_scalar_llvm(hsir)
            build = (compile_scalar_object(code, clang=args.clang, target=args.target, output=args.output)
                     if args.target is not None
                     else compile_scalar_llvm(code, clang=args.clang, output=args.output))
            output_json({"schema": "hepta.build-llvm-scalar.v1" if args.target else "hepta.build-llvm-scalar.v0",
                         "ok": True, "status": build["status"],
                         "reference_scope": "host_rust_reference_not_target_execution",
                         "reference_validation": reference.report, "build": build})
            return 0
        if args.command == "doctor":
            info = toolchain_info(find_rustc(args.rustc))
            output_json({"schema": "hepta.doctor.v1", "ok": True, "toolchain": info})
            return 0
        if args.command == "ssa-v1-reconcile":
            from .hsir_v1 import decode_json, MAX_BYTES, HSIRV1Rejected
            from .source_bound_reconcile import reconcile_source_bound_to_ssa, _MAX_SOURCE
            with open(args.envelope, "rb") as reader:
                wire = decode_json(reader.read(MAX_BYTES + 1))
            if wire.get("schema") == "hepta.hsir.integration.export.v1":
                if (wire.get("ok") is not True or
                        not isinstance(wire.get("hsir"), dict)):
                    raise HSIRV1Rejected("E_HSIR_V1_EXPORT_REJECTED")
                wire = wire["hsir"]
            if wire.get("schema") != "hepta.hsir.integration.v1":
                raise HSIRV1Rejected("E_HSIR_V1_WRONG_SCHEMA")
            source_path = Path(args.source).resolve()
            with open(source_path, "rb") as reader:
                source_bytes = reader.read(_MAX_SOURCE + 1)
            if len(source_bytes) > _MAX_SOURCE:
                raise SourceBoundReconcileRejected("E_SOURCE_BOUND_SSA_SOURCE_LIMIT")
            source = source_bytes.decode("utf-8")
            output_json(reconcile_source_bound_to_ssa(wire, source,
                        path=str(source_path), rustc=args.rustc))
            return 0
        file = Path(args.source).resolve()
        if args.command == "patch":
            if args.backend != "rust" or args.locked:
                raise ValueError("patch currently validates with the Rust backend; regenerate the package lock after an applied edit")
            request = json.loads(Path(args.request).read_text())
            if isinstance(request, dict) and request.get("schema") == "hepta.patch.preview.v3":
                from .agent_preview import preview_multi_body_patch
                result = preview_multi_body_patch(file, request, apply=args.apply,
                                                  rustc=args.rustc, target=args.target)
            elif isinstance(request, dict) and request.get("schema") == "hepta.patch.v2":
                from .protocol import apply_project_patch
                result = apply_project_patch(file, request, apply=args.apply, rustc=args.rustc, target=args.target)
            else:
                result = apply_patch(file, request, apply=args.apply, rustc=args.rustc, target=args.target)
            output_json(result)
            return 0 if result["ok"] else 1
        result = analyze_project(file, rustc=args.rustc, target=args.target, no_std=args.no_std,
                                 native=not getattr(args, "frontend_only", False), crate_type=args.crate_type,
                                 backend=args.backend, cc=args.cc, locked=args.locked)
        file = result.project.entry
        protected = {Path(p) for p in result.project.sources}
        if args.command in {"hsir", "cfg", "cfg-analyze", "ssa", "ssa-verify", "ssa-v1-verify"}:
            if args.backend != "rust":
                raise ValueError("HSIR/CFG/SSA inspection requires the real Rust reference backend")
            if not result.report["ok"]:
                output_json(result.report)
                return 1
            if args.command == "hsir":
                from .hsir import lower_checked_program
                snapshot = lower_checked_program(result.program, result.checked).as_dict()
            elif args.command == "ssa-v1-verify":
                from .hsir import lower_checked_program
                from .hsir_v1 import integrate_v0
                from .hsir_v1_ssa import lower_verified_v1_scalar_ssa
                legacy = lower_checked_program(result.program, result.checked).as_dict()
                integrated = integrate_v0(legacy, expected_source_sha256=legacy["source_sha256"])
                snapshot = lower_verified_v1_scalar_ssa(integrated)
            else:
                from .cfg import lower_checked_cfg
                cfg = lower_checked_cfg(result.program, result.checked)
                if args.command == "cfg-analyze":
                    from .cfg_analysis import analyze_cfg
                    snapshot = analyze_cfg(cfg).as_dict()
                elif args.command in {"ssa", "ssa-verify"}:
                    from .ssa import lower_cfg_scalar_ssa
                    scalar_ssa = lower_cfg_scalar_ssa(cfg)
                    if args.command == "ssa":
                        snapshot = scalar_ssa.as_dict()
                    else:
                        from .ssa_verify import verify_scalar_ssa
                        snapshot = verify_scalar_ssa(scalar_ssa, cfg).as_dict()
                else:
                    snapshot = cfg.as_dict()
            snapshot["reference_validation"] = {
                "status": result.report["status"],
                "compiler_sha256": result.report["compiler_sha256"],
                "checks": result.report["checks"],
                "backend": result.report.get("backend"),
            }
            output_json(snapshot)
            return 0
        if args.command == "inspect":
            output_json(inspect_analysis(result))
            return 0 if result.report["ok"] else 1
        if not result.report["ok"] or args.command == "check":
            output_json(result.report)
            return 0 if result.report["ok"] else 1
        if args.command in {"emit", "header"}:
            content = (result.c if args.backend == "c" else result.rust) if args.command == "emit" else emit_header(result.program)
            if args.output:
                dest = Path(args.output).resolve()
                if dest in protected:
                    raise ValueError("Output cannot overwrite a Hepta source in the module graph")
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_text(content)
                output_json({"schema": "hepta.output.v1", "ok": True, "output": str(dest), "validation": result.report})
            else:
                print(content, end="")
            return 0
        if args.command == "build":
            ext = {"bin": "", "staticlib": ".a", "cdylib": ".so", "obj": ".o", "rlib": ".rlib"}[args.crate_type]
            dest = Path(args.output).resolve() if args.output else file.parent / "build" / (file.stem + ext)
            if dest in protected:
                raise ValueError("Output cannot overwrite a Hepta source in the module graph")
            if args.backend == "c":
                from .c_backend import compile_c
                native = compile_c(result.c, cc=args.cc, crate_type=args.crate_type, output=dest, link_args=args.link_arg)
            else:
                native = compile_rust(result.rust, rustc=args.rustc, target=args.target, crate_type=args.crate_type,
                                      output=dest, link_args=args.link_arg)
            output_json({"schema": "hepta.build.v1", "ok": native["ok"], "validation": result.report, "build": native})
            return 0 if native["ok"] else 1
        if args.command == "run":
            if args.crate_type != "bin":
                raise ValueError("run requires --crate-type bin")
            with tempfile.TemporaryDirectory(prefix="hepta-run-") as td:
                if args.backend == "c":
                    from .c_backend import compile_c
                    native = compile_c(result.c, cc=args.cc, crate_type="bin", output=Path(td) / "program", link_args=args.link_arg)
                else:
                    native = compile_rust(result.rust, rustc=args.rustc, target=args.target, crate_type="bin",
                                          output=Path(td) / "program", link_args=args.link_arg)
                if not native["ok"]:
                    output_json(native)
                    return 1
                try:
                    proc = subprocess.run([native["artifact"]], text=True, capture_output=True, timeout=30)
                except subprocess.TimeoutExpired:
                    output_json({"schema": "hepta.run.v1", "ok": False, "status": "timeout", "timeout_seconds": 30})
                    return 124
                if args.json:
                    output_json({"schema": "hepta.run.v1", "ok": proc.returncode == 0, "returncode": proc.returncode,
                                 "stdout": proc.stdout, "stderr": proc.stderr, "build": native})
                else:
                    print(proc.stdout, end="")
                    print(proc.stderr, file=sys.stderr, end="")
                return proc.returncode if proc.returncode >= 0 else 128 - proc.returncode
    except HeptaError as e:
        output_json({"ok": False, "status": "rejected", "diagnostics": [e.diagnostic.to_dict()]})
        return 1
    except (CFGRejected, CFGAnalysisRejected, SSARejected, SSAVerificationRejected, LLVMSSARejected, V1SSARejected, SourceBoundReconcileRejected) as e:
        message = str(e)
        code = message.split(":", 1)[0]
        if not code.startswith(("E_CFG_", "E_DOM_", "E_SSA_", "E_LLVM_SSA_", "E_V1_SSA_", "E_SOURCE_BOUND_SSA_")):
            code = "E_IR_REJECTED"
        output_json({"ok": False, "status": "rejected",
                     "diagnostics": [{"code": code, "message": message, "phase": "ir"}]})
        return 1
    except (OSError, ValueError, UnicodeError, subprocess.SubprocessError) as e:
        output_json({"ok": False, "status": "error", "diagnostics": [{"code": "E_DRIVER", "message": str(e), "phase": "driver"}]})
        return 2
    return 0
