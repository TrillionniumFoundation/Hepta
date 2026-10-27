#!/usr/bin/env python3
"""Run real GDB breakpoints, locals, stack frames and stepping on both backends."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from hepta.pipeline import compiler_hash


def sha(data):
    return hashlib.sha256(data).hexdigest()


def qualify(gdb=None):
    debugger = shutil.which(gdb or "gdb")
    if debugger is None:
        raise ValueError("Actual GDB is required; emitting debug flags alone does not qualify")
    version = subprocess.run([debugger, "--version"], capture_output=True, text=True, timeout=20)
    if version.returncode:
        raise ValueError("GDB could not execute")
    source = ROOT / "examples/debug/main.hepta"
    source_bytes = source.read_bytes()
    source_line = next(i for i, line in enumerate(source.read_text().splitlines(), 1) if line.strip() == "assert(result == 36);")
    before = compiler_hash()
    results = []
    with tempfile.TemporaryDirectory(prefix="hepta-debug-qualification-") as temporary:
        directory = Path(temporary)
        for backend in ("rust", "c"):
            artifact = directory / ("debug-" + backend)
            command = [sys.executable, "-m", "hepta", "build", str(source), "--backend", backend,
                       "--debug", "--output", str(artifact)]
            process = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, timeout=120)
            if process.returncode:
                raise RuntimeError("Debug build failed: " + process.stdout + process.stderr)
            build = json.loads(process.stdout)
            if build.get("ok") is not True:
                raise RuntimeError("Native debug build rejected")
            native = build["build"]
            retained = native["debug_info"]
            mapping = json.loads(Path(retained["manifest"]).read_text())
            if sha(Path(retained["source"]).read_bytes()) != retained["source_sha256"]:
                raise RuntimeError("Retained source differs from debug identity")
            if backend == "rust":
                choices = [m for m in mapping["mappings"] if m["source"]["path"] == str(source)
                           and m["source"]["line"] == source_line and m["precision"] == "statement"]
                if len(choices) != 1:
                    raise RuntimeError("Expected one precise executable-statement source mapping")
                breakpoint_file, breakpoint_line = retained["source"], choices[0]["generated_start_line"]
            else:
                breakpoint_file, breakpoint_line = str(source), source_line
            gdb_script = directory / (backend + ".gdb")
            gdb_script.write_text("\n".join([
                "set pagination off", "set confirm off", "set debuginfod enabled off",
                "set auto-load off", "set startup-with-shell off", "set disable-randomization off",
                "python", "import gdb, json", "gdb.Breakpoint(" + repr(breakpoint_file + ":" + str(breakpoint_line)) + ")",
                "gdb.execute('run')", "f = gdb.selected_frame()", "s = f.find_sal()",
                "values = {name: int(gdb.parse_and_eval(name)) for name in ['h_input', 'h_base', 'h_result']}",
                "if values != {'h_input': 7, 'h_base': 12, 'h_result': 36}: raise gdb.GdbError('unexpected live locals')",
                "frames = []", "walk = f", "while walk is not None:",
                "    frames.append(walk.name())", "    walk = walk.older()",
                "if len(frames) < 2: raise gdb.GdbError('missing caller frame')",
                "observation = {'file': s.symtab.fullname(), 'line': s.line, 'locals': values, 'frames': frames}",
                "gdb.execute('next')", "after = gdb.selected_frame().find_sal()",
                "observation['step_file'] = after.symtab.fullname()", "observation['step_line'] = after.line",
                "print('HEPTA_DEBUG=' + json.dumps(observation, sort_keys=True))",
                "gdb.execute('continue')", "end", "",
            ]))
            execution = subprocess.run([debugger, "--batch", "-nx", "-nh", "-iex", "set auto-load off",
                                        str(artifact), "-x", str(gdb_script)], text=True, capture_output=True, timeout=30,
                                       env={**os.environ, "DEBUGINFOD_URLS": ""})
            observations = [line[len("HEPTA_DEBUG="):] for line in execution.stdout.splitlines() if line.startswith("HEPTA_DEBUG=")]
            if execution.returncode or len(observations) != 1 or "exited normally" not in execution.stdout or "\n36\n" not in execution.stdout:
                raise RuntimeError("Real debugger qualification failed: " + execution.stdout + execution.stderr)
            observation = json.loads(observations[0])
            if observation["file"] != breakpoint_file or observation["line"] != breakpoint_line:
                raise RuntimeError("Breakpoint stopped outside the requested source mapping")
            results.append({"backend": backend, "build": build, "mapping": mapping,
                            "source_breakpoint": {"path": str(source), "line": source_line,
                                                  "native_path": breakpoint_file, "native_line": breakpoint_line},
                            "observation": observation, "debugger_returncode": execution.returncode,
                            "stdout": execution.stdout, "stderr": execution.stderr,
                            "stdout_sha256": sha(execution.stdout.encode()), "stderr_sha256": sha(execution.stderr.encode())})
    if compiler_hash() != before or source.read_bytes() != source_bytes:
        raise ValueError("Compiler/source changed during debugger qualification")
    return {"schema": "hepta.debugger.v1", "status": "passed", "compiler_sha256": before,
            "source_sha256": sha(source_bytes), "debugger": {"version": version.stdout.strip(),
                "path": debugger, "binary_sha256": sha(Path(debugger).read_bytes())},
            "results": results,
            "claims": {"actual_source_breakpoint_executed": True, "actual_locals_and_stack_inspected": True,
                       "both_backends_executed": True, "rust_dwarf_uses_original_hepta_paths": False,
                       "optimized_debugging_qualified": False, "all_platform_debuggers_qualified": False}}


def validate_report(report):
    claims = {"actual_source_breakpoint_executed": True, "actual_locals_and_stack_inspected": True,
              "both_backends_executed": True, "rust_dwarf_uses_original_hepta_paths": False,
              "optimized_debugging_qualified": False, "all_platform_debuggers_qualified": False}
    if (report.get("schema") != "hepta.debugger.v1" or report.get("status") != "passed"
            or report.get("compiler_sha256") != compiler_hash()
            or report.get("source_sha256") != sha((ROOT / "examples/debug/main.hepta").read_bytes())
            or report.get("claims") != claims):
        raise ValueError("Debugger source identity or claims differ")
    results = report.get("results", [])
    if len(results) != 2 or {r.get("backend") for r in results} != {"rust", "c"}:
        raise ValueError("Both backends require actual debugger execution")
    for result in results:
        build = result.get("build", {})
        native = build.get("build", {})
        observed = result.get("observation", {})
        expected_break = result.get("source_breakpoint", {})
        if (build.get("ok") is not True or native.get("ok") is not True or native.get("check_only") is not False
                or native.get("artifact_sha256") != native.get("validation_artifact_sha256")
                or type(native.get("artifact_bytes")) is not int or native["artifact_bytes"] <= 0
                or result.get("debugger_returncode") != 0 or type(result.get("debugger_returncode")) is not int
                or observed.get("locals") != {"h_input": 7, "h_base": 12, "h_result": 36}
                or observed.get("file") != expected_break.get("native_path")
                or observed.get("line") != expected_break.get("native_line")
                or len(observed.get("frames", [])) < 2
                or "exited normally" not in result.get("stdout", "")
                or "\n36\n" not in result.get("stdout", "")
                or result.get("stdout_sha256") != sha(result["stdout"].encode())
                or result.get("stderr_sha256") != sha(result["stderr"].encode())):
            raise ValueError("Actual breakpoint/local/stack/run observations are incomplete")
        flags = native.get("flags", [])
        required = {"opt-level=0", "debuginfo=2", "force-frame-pointers=yes"} if result["backend"] == "rust" else {"-O0", "-g3", "-fno-omit-frame-pointer"}
        if not required.issubset(flags):
            raise ValueError("Debugger qualification must retain the actual debug compiler flags")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gdb")
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/debugger.json")
    args = parser.parse_args()
    try:
        report = qualify(args.gdb)
        validate_report(report)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        report = {"schema": "hepta.debugger.v1", "status": "failed", "error": str(exc)}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"status": report["status"], "output": str(args.output), "error": report.get("error")}))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
