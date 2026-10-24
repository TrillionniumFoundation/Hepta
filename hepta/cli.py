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
from .pipeline import analyze, inspect_analysis
from .protocol import apply_patch


def output_json(value):
    print(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="hepta", description="Hepta 0.1 native systems language prototype")
    parser.add_argument("--version", action="version", version="hepta " + __version__)
    sub = parser.add_subparsers(dest="command", required=True)
    doctor = sub.add_parser("doctor", help="Inspect the actual native toolchain")
    doctor.add_argument("--rustc")
    for cmd in ["check", "inspect", "emit", "header", "build", "run", "patch"]:
        p = sub.add_parser(cmd)
        p.add_argument("source")
        p.add_argument("--rustc")
        p.add_argument("--target")
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
        if args.command == "doctor":
            info = toolchain_info(find_rustc(args.rustc))
            output_json({"schema": "hepta.doctor.v1", "ok": True, "toolchain": info})
            return 0
        file = Path(args.source).resolve()
        if args.command == "patch":
            request = json.loads(Path(args.request).read_text())
            result = apply_patch(file, request, apply=args.apply, rustc=args.rustc, target=args.target)
            output_json(result)
            return 0 if result["ok"] else 1
        source = file.read_bytes().decode("utf-8")
        result = analyze(source, str(file), rustc=args.rustc, target=args.target, no_std=args.no_std,
                         native=not getattr(args, "frontend_only", False), crate_type=args.crate_type)
        if args.command == "inspect":
            output_json(inspect_analysis(result))
            return 0 if result.report["ok"] else 1
        if not result.report["ok"] or args.command == "check":
            output_json(result.report)
            return 0 if result.report["ok"] else 1
        if args.command in {"emit", "header"}:
            content = result.rust if args.command == "emit" else emit_header(result.program)
            if args.output:
                dest = Path(args.output).resolve()
                if dest == file:
                    raise ValueError("Output cannot overwrite the Hepta source")
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_text(content)
                output_json({"schema": "hepta.output.v1", "ok": True, "output": str(dest), "validation": result.report})
            else:
                print(content, end="")
            return 0
        if args.command == "build":
            ext = {"bin": "", "staticlib": ".a", "cdylib": ".so", "obj": ".o", "rlib": ".rlib"}[args.crate_type]
            dest = Path(args.output).resolve() if args.output else file.parent / "build" / (file.stem + ext)
            if dest == file:
                raise ValueError("Output cannot overwrite the Hepta source")
            native = compile_rust(result.rust, rustc=args.rustc, target=args.target, crate_type=args.crate_type,
                                  output=dest, link_args=args.link_arg)
            output_json({"schema": "hepta.build.v1", "ok": native["ok"], "validation": result.report, "build": native})
            return 0 if native["ok"] else 1
        if args.command == "run":
            if args.crate_type != "bin":
                raise ValueError("run requires --crate-type bin")
            with tempfile.TemporaryDirectory(prefix="hepta-run-") as td:
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
