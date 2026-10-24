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
from .pipeline import analyze, analyze_project, inspect_analysis, hsir_analysis, cfg_analysis, resource_ir_analysis
from .protocol import apply_patch


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
    project_migrator = sub.add_parser("migrate-c-project", help="Capture a C compilation database and migrate its supported complete declaration set")
    project_migrator.add_argument("database")
    project_migrator.add_argument("--output", "-o", required=True)
    project_migrator.add_argument("--contracts")
    project_migrator.add_argument("--clang", default="clang")
    project_migrator.add_argument("--rustc")
    project_migrator.add_argument("--frontend-only", action="store_true", help="Explicitly skip native validation")
    importer = sub.add_parser("import-c", help="Import the supported C header subset using real compiler probes")
    importer.add_argument("header")
    importer.add_argument("--output", "-o", required=True)
    importer.add_argument("--module", default="c_imported")
    importer.add_argument("--cc")
    workspace = sub.add_parser("workspace", help="Pinned immutable project snapshots and crash-recoverable Agent commits")
    actions = workspace.add_subparsers(dest="workspace_action", required=True)
    for action in ("init", "inspect", "pin", "patch", "recover"):
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
    for cmd in ["check", "inspect", "hsir", "cfg", "hmir", "resource-ir", "emit", "header", "build", "run", "patch"]:
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
        if cmd in {"check", "inspect", "hsir", "cfg", "hmir", "resource-ir"}:
            p.add_argument("--frontend-only", action="store_true", help="Explicitly skip native/borrow checks; output cannot be treated as a complete check")
        if cmd in {"emit", "header", "build"}:
            p.add_argument("--output", "-o")
        if cmd in {"build", "run"}:
            p.add_argument("--link-arg", action="append", default=[])
        if cmd == "patch":
            p.add_argument("--request", required=True, help="Path to a v1/v2 or multi-file preview v3 patch JSON request")
            p.add_argument("--apply", action="store_true", help="Atomically apply after native validation")
    args = parser.parse_args(argv)
    try:
        if args.command == "workspace":
            from .workspace import initialize, inspect_workspace, pin, apply_workspace_patch, recover
            if args.workspace_action == "init":
                result = initialize(args.store, args.root, args.entry, rustc=args.rustc, target=args.target)
            elif args.workspace_action == "inspect":
                result = inspect_workspace(args.store)
            elif args.workspace_action == "pin":
                result = {"ok": True, "snapshot": pin(args.store, args.version)}
            elif args.workspace_action == "recover":
                result = recover(args.store)
            else:
                request = json.loads(Path(args.request).read_bytes())
                result = apply_workspace_patch(args.store, request, apply=args.apply,
                                               rustc=args.rustc, target=args.target)
            output_json(result)
            return 0 if result.get("ok") else 1
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
        if args.command == "migrate-c-project":
            from .c_migrate import migrate_c_project
            contracts = json.loads(Path(args.contracts).read_bytes()) if args.contracts else None
            result = migrate_c_project(args.database, args.output, contracts=contracts,
                                       clang=args.clang, rustc=args.rustc,
                                       verify_native=not args.frontend_only)
            output_json(result)
            return 0 if result["ok"] else 1
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
            if args.backend != "rust" or args.locked:
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
                                 backend=args.backend, cc=args.cc, locked=args.locked)
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
    except (OSError, ValueError, UnicodeError, subprocess.SubprocessError) as e:
        output_json({"ok": False, "status": "error", "diagnostics": [{"code": "E_DRIVER", "message": str(e), "phase": "driver"}]})
        return 2
    return 0
