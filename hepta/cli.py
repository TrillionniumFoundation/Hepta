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
from .pipeline import analyze, analyze_project, inspect_analysis, hsir_analysis, cfg_analysis, resource_ir_analysis, concurrent_ir_analysis
from .protocol import apply_patch


def output_json(value):
    print(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="hepta", description="Hepta native systems language")
    parser.add_argument("--version", action="version", version="hepta " + __version__)
    sub = parser.add_subparsers(dest="command", required=True)
    hia = sub.add_parser("hia", help="Independent typed HIA program verification, execution and native compilation")
    hia_actions = hia.add_subparsers(dest="hia_action", required=True)
    for action in ("verify", "inspect", "run", "emit", "build", "lower", "patch",
                   "impact", "import-executable", "import-scalar"):
        h = hia_actions.add_parser(action)
        h.add_argument("input", help="Standalone HIA JSON program; lower accepts Hepta source")
        if action in {"emit", "build", "lower", "patch", "import-executable", "import-scalar"}:
            h.add_argument("--output", "-o", required=action == "build")
        if action == "run":
            h.add_argument("--function", required=True)
            h.add_argument("--arguments", default="[]")
            h.add_argument("--max-steps", type=int, default=1000000)
            h.add_argument("--max-heap-bytes", type=int, default=1048576)
            h.add_argument("--allocation-fail-at", type=int)
        if action == "build":
            h.add_argument("--clang", default="clang")
            h.add_argument("--kind", choices=["shared", "object"], default="shared")
        if action in {"emit", "build"}:
            h.add_argument("--target", choices=["x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"],
                           default="x86_64-unknown-linux-gnu")
        if action in {"lower", "import-executable", "import-scalar"}:
            h.add_argument("--module", default="migrated")
        if action in {"import-executable", "import-scalar"}:
            h.add_argument("--source", required=True, help="Legacy origin authentication only")
            h.add_argument("--project-sha256", required=action == "import-scalar")
        if action in {"patch", "impact"}:
            h.add_argument("--request", required=True)
        if action == "verify":
            h.add_argument("--rust-shadow-bin",
                           help="opt-in exact-byte Rust shadow executable (not native admission)")
            h.add_argument("--rust-shadow-sha256",
                           help="required exact lowercase SHA-256 when Rust shadow is selected")
            h.add_argument("--rust-shadow-profile", choices=("scalar", "owned"),
                           help="scalar or Owner/Loan Rust shadow; requires both executable flags")
    doctor = sub.add_parser("doctor", help="Inspect the actual native toolchain")
    doctor.add_argument("--rustc")
    lock = sub.add_parser("lock", help="Lock local package source and dependency bytes")
    lock.add_argument("package", nargs="?", default=".")
    cpp = sub.add_parser("bridge-cpp", help="Checked C ABI bridge for one C++ scalar class")
    cpp.add_argument("header")
    cpp.add_argument("--class", dest="class_name", required=True)
    cpp.add_argument("--output", "-o", required=True)
    cpp.add_argument("--hepta-output", required=True)
    cpp.add_argument("--clang", default="clang++")
    cpp_contract = sub.add_parser("bridge-cpp-contract", help="Native-checked direct, borrowed and handle C++ interface contracts")
    cpp_contract.add_argument("header")
    cpp_contract.add_argument("--contract", required=True)
    cpp_contract.add_argument("--output-dir", required=True)
    cpp_contract.add_argument("--cxx", default="c++")
    cpp_contract.add_argument("--rustc")
    migrator = sub.add_parser("migrate-c", help="Strict Clang-AST conversion of safe scalar C functions")
    migrator.add_argument("source")
    migrator.add_argument("--output", "-o", required=True)
    migrator.add_argument("--clang", default="clang")
    cpp_migrator = sub.add_parser("migrate-cpp", help="Strict C++20 scalar implementation migration through the shared C lowerer")
    cpp_migrator.add_argument("source")
    cpp_migrator.add_argument("--output", "-o", required=True)
    cpp_migrator.add_argument("--clang", default="clang++")
    cpp_class = sub.add_parser("migrate-cpp-class", help="Translate one complete public scalar value class with a trivial lifecycle")
    cpp_class.add_argument("source")
    cpp_class.add_argument("--output", "-o", required=True)
    cpp_class.add_argument("--clang", default="clang++")
    cpp_owned = sub.add_parser("migrate-cpp-owned", help="Translate the complete checked exclusive-byte-owner C++ lifecycle profile")
    cpp_owned.add_argument("source")
    cpp_owned.add_argument("--output", "-o", required=True)
    cpp_owned.add_argument("--clang", default="clang++")
    project_migrator = sub.add_parser("migrate-c-project", help="Capture a C compilation database and migrate its supported complete declaration set")
    project_migrator.add_argument("database")
    project_migrator.add_argument("--output", "-o", required=True)
    project_migrator.add_argument("--contracts")
    project_migrator.add_argument("--clang", default="clang")
    project_migrator.add_argument("--rustc")
    project_migrator.add_argument("--frontend-only", action="store_true", help="Explicitly skip native validation")
    llvm = sub.add_parser("build-llvm-ssa", help="Native rustc-gated checked i32/u32 HSIR/SSA/LLVM compilation")
    llvm.add_argument("source")
    llvm.add_argument("--output", "-o", required=True)
    llvm.add_argument("--rustc")
    llvm.add_argument("--clang", default="clang")
    llvm.add_argument("--target", help="Optional target object (no target = host shared library)")
    llvm.add_argument("--locked", action="store_true")
    llvm_owned = sub.add_parser("build-llvm-owned", help="Direct LLVM host compilation of the checked owned-byte resource profile")
    llvm_owned.add_argument("source")
    llvm_owned.add_argument("--output", "-o", required=True)
    llvm_owned.add_argument("--rustc")
    llvm_owned.add_argument("--clang", default="clang")
    llvm_owned.add_argument("--kind", choices=["shared", "object"], default="shared")
    llvm_owned.add_argument("--locked", action="store_true")
    llvm_arm = sub.add_parser("build-llvm-owned-aarch64", help="Source-bound Owned LLVM ARM64 object with optional finite runtime execution")
    llvm_arm.add_argument("source")
    llvm_arm.add_argument("--output", "-o", required=True)
    llvm_arm.add_argument("--rustc")
    llvm_arm.add_argument("--clang", default="clang")
    llvm_arm.add_argument("--locked", action="store_true")
    llvm_arm.add_argument("--synthetic-link-probe", action="store_true")
    llvm_arm.add_argument("--finite-runtime-link-probe", action="store_true")
    llvm_arm.add_argument("--qemu-aarch64")
    core = sub.add_parser("executable-core", help="Export the source-bound executable integer/Buffer/Result core")
    core.add_argument("source")
    core.add_argument("--output", "-o", help="New JSON output file; otherwise write the core to stdout")
    core_verify = sub.add_parser("verify-executable-core", help="Replay source and recheck supplied executable core operations")
    core_verify.add_argument("source")
    core_verify.add_argument("core")
    core_run = sub.add_parser("run-executable-core", help="Interpret checked core operations with explicit execution limits")
    core_run.add_argument("source")
    core_run.add_argument("--core", help="Optional previously exported core; checked against the exact source")
    core_run.add_argument("--function", required=True)
    core_run.add_argument("--arguments", default="[]", help="JSON array of scalar arguments")
    core_run.add_argument("--max-steps", type=int, default=1000000)
    core_run.add_argument("--max-heap-bytes", type=int, default=1048576)
    core_run.add_argument("--allocation-fail-at", type=int)
    core_build = sub.add_parser("build-executable-core", help="Compile LLVM from decoded core operations after the pinned Rust gate")
    core_build.add_argument("source")
    core_build.add_argument("--output", "-o", required=True)
    core_build.add_argument("--rustc")
    core_build.add_argument("--clang", default="clang")
    core_build.add_argument("--kind", choices=["shared", "object"], default="shared")
    resource_source = sub.add_parser("verify-resource-source", help="Recheck actual source and match a complete independent resource graph")
    resource_source.add_argument("source")
    resource_source.add_argument("graph")
    resource_source.add_argument("--rustc")
    resource_source.add_argument("--target")
    resource_source.add_argument("--locked", action="store_true")
    resource_source.add_argument("--frontend-only", action="store_true")
    importer = sub.add_parser("import-c", help="Import the supported C header subset using real compiler probes")
    importer.add_argument("header")
    importer.add_argument("--output", "-o", required=True)
    importer.add_argument("--module", default="c_imported")
    importer.add_argument("--cc")
    workspace = sub.add_parser("workspace", help="Pinned immutable project snapshots and crash-recoverable Agent commits")
    actions = workspace.add_subparsers(dest="workspace_action", required=True)
    for action in ("init", "inspect", "semantics", "diff", "pin", "patch", "recover"):
        w = actions.add_parser(action)
        w.add_argument("store")
        if action == "init":
            w.add_argument("--root", required=True)
            w.add_argument("--entry", required=True)
        if action in {"init", "patch"}:
            w.add_argument("--rustc")
            w.add_argument("--target")
        if action == "patch":
            w.add_argument("--request", required=True)
            w.add_argument("--apply", action="store_true")
        if action == "pin":
            w.add_argument("--version")
        if action == "semantics":
            w.add_argument("--version", required=True, help="Exact immutable workspace version SHA-256")
        if action == "diff":
            w.add_argument("after_store", help="Second immutable workspace store")
            w.add_argument("--before-version", required=True)
            w.add_argument("--after-version", required=True)
    for cmd in ["check", "inspect", "hsir", "cfg", "hmir", "resource-ir", "concurrent-ir", "emit", "header", "build", "run", "patch"]:
        p = sub.add_parser(cmd)
        p.add_argument("source")
        p.add_argument("--rustc")
        p.add_argument("--cc")
        p.add_argument("--backend", choices=["rust", "c"], default="rust")
        p.add_argument("--c-opt", choices=["default", "unroll"], default="default",
                       help="Explicit C optimization profile; unroll may trade code size and other workloads for loop throughput")
        p.add_argument("--target")
        p.add_argument("--locked", action="store_true")
        p.add_argument("--json", action="store_true", help="Machine-readable results (default for checks/builds)")
        if cmd != "patch":
            p.add_argument("--no-std", action="store_true")
            p.add_argument("--crate-type", choices=["bin", "staticlib", "cdylib", "rlib", "obj"], default="bin" if cmd in {"build", "run"} else "rlib")
        if cmd in {"check", "inspect", "hsir", "cfg", "hmir", "resource-ir", "concurrent-ir"}:
            p.add_argument("--frontend-only", action="store_true", help="Explicitly skip native/borrow checks; output cannot be treated as a complete check")
        if cmd in {"emit", "header", "build"}:
            p.add_argument("--output", "-o")
        if cmd in {"build", "run"}:
            p.add_argument("--link-arg", action="append", default=[])
            p.add_argument("--debug", action="store_true", help="Unoptimized native debug information and retained generated source mapping")
        if cmd == "patch":
            p.add_argument("--request", required=True, help="Path to a v1/v2 or multi-file preview v3 patch JSON request")
            p.add_argument("--apply", action="store_true", help="Atomically apply after native validation")
    args = parser.parse_args(argv)
    try:
        if args.command == "hia":
            from .hia_program import verify_program
            from .hia_program_tools import (read_bounded, decode_json, inspect_program,
                                            apply_program_patch, publish_program)
            if args.hia_action in {"import-executable", "import-scalar"}:
                from .core import from_executable_core, from_scalar_core
                source = read_bounded(args.source).decode("utf-8")
                raw = read_bounded(args.input)
                if args.hia_action == "import-executable":
                    program = from_executable_core(decode_json(raw), source=source,
                        project_sha256=args.project_sha256, module=args.module)
                else:
                    from hashlib import sha256
                    from .hia_core import HIAScalarCore
                    from .checker import check
                    from .parser import parse
                    original = parse(source, str(Path(args.source).absolute()))
                    old = HIAScalarCore(raw.decode("utf-8"), sha256(raw).hexdigest())
                    program = from_scalar_core(old, program=original, checked=check(original),
                        project_sha256=args.project_sha256, module=args.module)
                output_json(publish_program(program, args.output) if args.output else program.as_dict())
                return 0
            if args.hia_action == "lower":
                from .hia_program_source import lower_source
                program = verify_program(lower_source(
                    read_bounded(args.input).decode("utf-8"), path=str(Path(args.input).absolute()),
                    module=args.module))
                result = publish_program(program, args.output) if args.output else program.as_dict()
                output_json(result)
                return 0
            program = verify_program(read_bounded(args.input))
            if args.hia_action == "verify":
                report = {**program.report(), "status": "standalone_core_checked",
                          "native_executed": False}
                selected_shadow = any(value is not None for value in (
                    args.rust_shadow_bin, args.rust_shadow_sha256, args.rust_shadow_profile))
                if selected_shadow:
                    if not args.rust_shadow_bin or not args.rust_shadow_sha256:
                        raise ValueError("Rust shadow requires both --rust-shadow-bin and --rust-shadow-sha256")
                    from .hia_rust_crosscheck import crosscheck_rust_shadow
                    report["rust_crosscheck"] = crosscheck_rust_shadow(
                        program, args.rust_shadow_bin,
                        executable_sha256=args.rust_shadow_sha256,
                        profile=args.rust_shadow_profile or "owned")
                output_json(report)
                return 0
            if args.hia_action == "inspect":
                output_json(inspect_program(program))
                return 0
            if args.hia_action == "run":
                from .hia_program_runtime import (execute_program, HIAProgramTrap,
                                                  HIAProgramBudgetExceeded)
                if len(args.arguments.encode("utf-8")) > 65536:
                    raise ValueError("HIA entry arguments exceed their byte limit")
                try:
                    result = execute_program(program, args.function, decode_json(args.arguments),
                                             max_steps=args.max_steps, max_heap_bytes=args.max_heap_bytes,
                                             allocation_fail_at=args.allocation_fail_at)
                except (HIAProgramTrap, HIAProgramBudgetExceeded) as exc:
                    output_json(exc.report)
                    return 1
                output_json(result)
                return 0 if result.get("status") == "returned" else 1
            if args.hia_action in {"emit", "build"}:
                from .hia_program_llvm import emit_program_llvm, build_program_native
                if args.hia_action == "build":
                    result = build_program_native(program, args.output, clang=args.clang,
                                                  kind=args.kind, target=args.target)
                    output_json(result)
                    return 0 if result.get("ok") is True else 1
                ir = emit_program_llvm(program, target=args.target)
                if args.output:
                    destination = Path(args.output).absolute()
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    with destination.open("x", encoding="utf-8") as stream:
                        stream.write(ir.text)
                    output_json({"schema": "hepta.hia.llvm-output.v1", "ok": True,
                                 "program_sha256": program.sha256, "output": str(destination),
                                 "status": "emitted_not_compiled"})
                else:
                    print(ir.text, end="")
                return 0
            if args.hia_action == "impact":
                # Read-only Agent advisory: same verified patch implementation,
                # with old/new exact callgraph traversal and no publication.
                from .hia_patch_impact import analyze_patch_impact
                _revised, receipt, impact = analyze_patch_impact(program, read_bounded(args.request))
                output_json({"schema": "hepta.hia.impact-query.v1", "ok": True,
                             "status": "verified_unpublished",
                             "patch": receipt, "impact": impact})
                return 0
            if args.hia_action == "patch":
                revised, receipt = apply_program_patch(program, read_bounded(args.request))
                if args.output:
                    receipt["publication"] = publish_program(revised, args.output)
                    receipt["status"] = "verified_new_snapshot_published"
                else:
                    receipt["program"] = revised.as_dict()
                output_json(receipt)
                return 0
        if getattr(args, "debug", False) and args.c_opt != "default":
            raise ValueError("--debug disables optimization and cannot use --c-opt unroll")
        if args.command == "workspace":
            from .workspace import initialize, inspect_workspace, pin, apply_workspace_patch, recover
            if args.workspace_action == "init":
                result = initialize(args.store, args.root, args.entry, rustc=args.rustc, target=args.target)
            elif args.workspace_action == "inspect":
                result = inspect_workspace(args.store)
            elif args.workspace_action == "pin":
                result = {"ok": True, "snapshot": pin(args.store, args.version)}
            elif args.workspace_action == "semantics":
                from .agent_semantics import inspect_pinned_semantics
                result = inspect_pinned_semantics(args.store, expected_version=args.version)
            elif args.workspace_action == "diff":
                from .agent_contract_diff import compare_pinned_contracts
                result = compare_pinned_contracts(
                    args.store, args.after_store,
                    expected_before_version=args.before_version,
                    expected_after_version=args.after_version)
            elif args.workspace_action == "recover":
                result = recover(args.store)
            else:
                request = json.loads(Path(args.request).read_bytes())
                result = apply_workspace_patch(args.store, request, apply=args.apply,
                                               rustc=args.rustc, target=args.target)
            output_json(result)
            if args.workspace_action == "diff":
                return 0 if (result.get("schema") == "hepta.agent-contract-diff.v1"
                             and result.get("status") == "read_only_contract_diff_not_equivalence") else 1
            if args.workspace_action == "semantics":
                return 0 if (result.get("ok") is True
                             and result.get("schema") == "hepta.agent-semantics.v1"
                             and result.get("status") == "published_native_prevalidated_read_only") else 1
            return 0 if result.get("ok") is True else 1
        if args.command == "lock":
            from .packages import write_lock
            output_json(write_lock(args.package))
            return 0
        if args.command == "bridge-cpp":
            from .cpp_bridge import bridge_cpp
            result = bridge_cpp(args.header, args.class_name, args.output, args.hepta_output, clang=args.clang)
            output_json(result)
            return 0 if result["ok"] else 1
        if args.command == "bridge-cpp-contract":
            from .cpp_contracts import bridge_cpp_contracts
            result = bridge_cpp_contracts(args.header, args.contract, args.output_dir,
                                          cxx=args.cxx, rustc=args.rustc)
            output_json(result)
            return 0 if result["ok"] else 1
        if args.command == "migrate-c":
            from .c_migrate import migrate_c
            result = migrate_c(args.source, args.output, clang=args.clang)
            output_json(result)
            return 0 if result["ok"] else 1
        if args.command == "migrate-cpp":
            from .cpp2hepta import migrate_cpp
            result = migrate_cpp(args.source, args.output, clangxx=args.clang)
            output_json(result)
            return 0 if result["ok"] else 1
        if args.command == "migrate-cpp-class":
            from .cpp_class_migrate import migrate_cpp_class
            result = migrate_cpp_class(args.source, args.output, clangxx=args.clang)
            output_json(result)
            return 0 if result["ok"] else 1
        if args.command == "migrate-cpp-owned":
            from .cpp_owned_migrate import migrate_cpp_owned
            result = migrate_cpp_owned(args.source, args.output, clangxx=args.clang)
            output_json(result)
            return 0 if result["ok"] else 1
        if args.command == "migrate-c-project":
            from .c_migrate import migrate_c_project
            contracts = json.loads(Path(args.contracts).read_bytes()) if args.contracts else None
            result = migrate_c_project(args.database, args.output, contracts=contracts,
                                       clang=args.clang, rustc=args.rustc,
                                       verify_native=not args.frontend_only)
            output_json(result)
            return 0 if result["ok"] else 1
        if args.command == "build-llvm-ssa":
            from .llvm_ssa_pipeline import build_llvm_ssa_source
            result = build_llvm_ssa_source(
                args.source, args.output, rustc=args.rustc,
                clang=args.clang, target=args.target, locked=args.locked)
            output_json(result)
            return 0 if result["ok"] else 1
        if args.command == "build-llvm-owned":
            from .llvm_owned_pipeline import build_llvm_owned_source
            result = build_llvm_owned_source(args.source, args.output, rustc=args.rustc,
                                            clang=args.clang, kind=args.kind, locked=args.locked)
            output_json(result)
            return 0 if result["ok"] else 1
        if args.command == "build-llvm-owned-aarch64":
            from .llvm_owned_aarch64 import build_owned_aarch64_source
            result = build_owned_aarch64_source(
                args.source, args.output, rustc=args.rustc, clang=args.clang,
                locked=args.locked, synthetic_link_probe=args.synthetic_link_probe,
                finite_runtime_probe=args.finite_runtime_link_probe,
                qemu_aarch64=args.qemu_aarch64)
            output_json(result)
            return 0 if result["ok"] else 1
        if args.command == "build-executable-core":
            from .executable_core import build_executable_core_source
            result = build_executable_core_source(
                args.source, args.output, rustc=args.rustc, clang=args.clang, kind=args.kind)
            output_json(result)
            return 0 if result.get("ok") is True else 1
        if args.command in {"executable-core", "verify-executable-core", "run-executable-core"}:
            from .executable_core import (
                MAX_SOURCE_BYTES, MAX_CORE_BYTES, lower_executable_core,
                verify_executable_core, execute_executable_core,
            )
            from .parser import parse
            source_path = Path(args.source).resolve()
            def read_bounded(path, limit):
                with Path(path).open("rb") as stream:
                    data = stream.read(limit + 1)
                if len(data) > limit:
                    raise ValueError("Executable-core input exceeds its byte limit")
                return data.decode("utf-8")
            source = read_bounded(source_path, MAX_SOURCE_BYTES)
            core_path = getattr(args, "core", None)
            document = (json.loads(read_bounded(core_path, MAX_CORE_BYTES)) if core_path
                        else lower_executable_core(parse(source, str(source_path))))
            if args.command == "verify-executable-core":
                result = verify_executable_core(document, source=source, path=str(source_path))
            elif args.command == "run-executable-core":
                if len(args.arguments.encode("utf-8")) > 65536:
                    raise ValueError("Executable-core arguments exceed their byte limit")
                result = execute_executable_core(
                    document, args.function, json.loads(args.arguments), source=source,
                    path=str(source_path), max_steps=args.max_steps,
                    max_heap_bytes=args.max_heap_bytes, allocation_fail_at=args.allocation_fail_at)
            elif args.output:
                destination = Path(args.output).absolute()
                # A saved core is evidence of these exact operations, never a
                # replacement for source or an existing report/artifact.
                destination.parent.mkdir(parents=True, exist_ok=True)
                with destination.open("x", encoding="utf-8") as stream:
                    stream.write(json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
                result = {"schema": "hepta.executable-core-output.v1", "ok": True,
                          "status": "exported_not_native_qualified", "output": str(destination),
                          "core_sha256": document["sha256"], "claims": document["claims"]}
            else:
                output_json(document)
                return 0
            output_json(result)
            return 0 if result.get("ok") is True else 1
        if args.command == "verify-resource-source":
            from .resource_source import main as verify_source_main
            forwarded = [args.source, args.graph]
            for option in ("rustc", "target"):
                if getattr(args, option):
                    forwarded += ["--" + option, getattr(args, option)]
            for option in ("locked", "frontend_only"):
                if getattr(args, option):
                    forwarded.append("--" + option.replace("_", "-"))
            return verify_source_main(forwarded)
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
        if args.command == "doctor":
            info = toolchain_info(find_rustc(args.rustc))
            output_json({"schema": "hepta.doctor.v1", "ok": True, "toolchain": info})
            return 0
        file = Path(args.source).resolve()
        if args.command == "patch":
            if args.backend != "rust" or args.locked or args.c_opt != "default":
                raise ValueError("patch currently validates with the Rust backend; regenerate the package lock after an applied edit")
            request = json.loads(Path(args.request).read_text())
            if isinstance(request, dict) and request.get("schema") == "hepta.patch.v3.preview":
                from .protocol_v3 import preview_project_patch
                result = preview_project_patch(file, request, apply=args.apply, rustc=args.rustc, target=args.target)
            elif isinstance(request, dict) and request.get("schema") == "hepta.patch.v2":
                from .protocol import apply_project_patch
                result = apply_project_patch(file, request, apply=args.apply, rustc=args.rustc, target=args.target)
            else:
                result = apply_patch(file, request, apply=args.apply, rustc=args.rustc, target=args.target)
            output_json(result)
            return 0 if result["ok"] else 1
        result = analyze_project(file, rustc=args.rustc, target=args.target, no_std=args.no_std,
                                 native=not getattr(args, "frontend_only", False), crate_type=args.crate_type,
                                 backend=args.backend, cc=args.cc, locked=args.locked, c_optimization=args.c_opt)
        file = result.project.entry
        protected = {Path(p) for p in result.project.sources}
        if args.command == "inspect":
            output_json(inspect_analysis(result))
            return 0 if result.report["ok"] else 1
        if args.command == "hsir":
            output_json(hsir_analysis(result))
            return 0 if result.report["ok"] else 1
        if args.command == "cfg":
            exported = cfg_analysis(result)
            output_json(exported)
            return 0 if exported["ok"] else 1
        if args.command == "hmir":
            from .hmir import hmir_analysis
            exported = hmir_analysis(result)
            output_json(exported)
            return 0 if exported["ok"] else 1
        if args.command == "resource-ir":
            exported = resource_ir_analysis(result)
            output_json(exported)
            return 0 if exported["ok"] else 1
        if args.command == "concurrent-ir":
            exported = concurrent_ir_analysis(result)
            output_json(exported)
            return 0 if exported["ok"] else 1
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
                native = compile_c(result.c, cc=args.cc, crate_type=args.crate_type, output=dest, link_args=args.link_arg,
                                   optimization_profile=args.c_opt, optimize=not args.debug, debug_info=args.debug)
            else:
                native = compile_rust(result.rust, rustc=args.rustc, target=args.target, crate_type=args.crate_type,
                                      output=dest, link_args=args.link_arg, optimize=not args.debug, debug_info=args.debug)
            output_json({"schema": "hepta.build.v1", "ok": native["ok"], "validation": result.report, "build": native})
            return 0 if native["ok"] else 1
        if args.command == "run":
            if args.crate_type != "bin":
                raise ValueError("run requires --crate-type bin")
            with tempfile.TemporaryDirectory(prefix="hepta-run-") as td:
                if args.backend == "c":
                    from .c_backend import compile_c
                    native = compile_c(result.c, cc=args.cc, crate_type="bin", output=Path(td) / "program", link_args=args.link_arg,
                                       optimization_profile=args.c_opt, optimize=not args.debug, debug_info=args.debug)
                else:
                    native = compile_rust(result.rust, rustc=args.rustc, target=args.target, crate_type="bin",
                                          output=Path(td) / "program", link_args=args.link_arg, optimize=not args.debug, debug_info=args.debug)
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
    except (OSError, ValueError, UnicodeError, subprocess.SubprocessError) as e:
        output_json({"ok": False, "status": "error", "diagnostics": [{"code": "E_DRIVER", "message": str(e), "phase": "driver"}]})
        return 2
    return 0
