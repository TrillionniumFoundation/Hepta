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
from hepta.pipeline import analyze_project
from hepta.source_map import source_markers
from tools.evidence_checks import is_sha, native_build, normalized_errors, require, strict_equal, text


def sha(data):
    return hashlib.sha256(data).hexdigest()


def debugger_script(breakpoint_file, breakpoint_line):
    return "\n".join([
        "set pagination off", "set confirm off", "set debuginfod enabled off",
        "set auto-load off", "set startup-with-shell off", "set disable-randomization off",
        "python", "import gdb, json", "gdb.Breakpoint(" + repr(breakpoint_file + ":" + str(breakpoint_line)) + ")",
        "gdb.execute('run')", "f = gdb.selected_frame()", "s = f.find_sal()",
        "values = {name: int(gdb.parse_and_eval(name)) for name in ['h_input', 'h_base', 'h_result']}",
        "if values != {'h_input': 7, 'h_base': 12, 'h_result': 36}: raise gdb.GdbError('unexpected live locals: ' + json.dumps(values))",
        "frames = []", "walk = f", "while walk is not None:",
        "    frames.append(walk.name())", "    walk = walk.older()",
        "if len(frames) < 2: raise gdb.GdbError('missing caller frame')",
        "observation = {'file': s.symtab.fullname(), 'line': s.line, 'locals': values, 'frames': frames}",
        "gdb.execute('next')", "after = gdb.selected_frame().find_sal()",
        "observation['step_file'] = after.symtab.fullname()", "observation['step_line'] = after.line",
        "print('HEPTA_DEBUG=' + json.dumps(observation, sort_keys=True))",
        "gdb.execute('continue')", "end", "",
    ])


def qualify(gdb=None):
    debugger = shutil.which(gdb or "gdb")
    if debugger is None:
        raise ValueError("Actual GDB is required; emitting debug flags alone does not qualify")
    debugger_hash = sha(Path(debugger).read_bytes())
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
            script = debugger_script(breakpoint_file, breakpoint_line)
            gdb_script.write_text(script)
            debugger_command = [debugger, "--batch", "-nx", "-nh", "-iex", "set auto-load off", str(artifact), "-x", str(gdb_script)]
            execution = subprocess.run(debugger_command, text=True, capture_output=True, timeout=30,
                                       env={**os.environ, "DEBUGINFOD_URLS": ""})
            observations = [line[len("HEPTA_DEBUG="):] for line in execution.stdout.splitlines() if line.startswith("HEPTA_DEBUG=")]
            if execution.returncode or len(observations) != 1 or "exited normally" not in execution.stdout or "\n36\n" not in execution.stdout:
                raise RuntimeError("Real debugger qualification failed: " + execution.stdout + execution.stderr)
            observation = json.loads(observations[0])
            if observation["file"] != breakpoint_file or observation["line"] != breakpoint_line:
                raise RuntimeError("Breakpoint stopped outside the requested source mapping")
            results.append({"backend": backend, "build": build, "mapping": mapping,
                            "generated_source": Path(retained["source"]).read_text(),
                            "debugger_command": debugger_command, "script_path": str(gdb_script),
                            "debugger_script": script, "script_sha256": sha(script.encode()),
                            "source_breakpoint": {"path": str(source), "line": source_line,
                                                  "native_path": breakpoint_file, "native_line": breakpoint_line},
                            "observation": observation, "debugger_returncode": execution.returncode,
                            "stdout": execution.stdout, "stderr": execution.stderr,
                            "stdout_sha256": sha(execution.stdout.encode()), "stderr_sha256": sha(execution.stderr.encode())})
    if compiler_hash() != before or source.read_bytes() != source_bytes or sha(Path(debugger).read_bytes()) != debugger_hash:
        raise ValueError("Compiler/source changed during debugger qualification")
    return {"schema": "hepta.debugger.v1", "status": "passed", "compiler_sha256": before,
            "source_sha256": sha(source_bytes), "debugger": {"version": version.stdout.strip(),
                "path": debugger, "binary_sha256": debugger_hash},
            "results": results,
            "claims": {"actual_source_breakpoint_executed": True, "actual_locals_and_stack_inspected": True,
                       "both_backends_executed": True, "rust_dwarf_uses_original_hepta_paths": False,
                       "optimized_debugging_qualified": False, "all_platform_debuggers_qualified": False}}


@normalized_errors
def validate_report(report):
    claims = {"actual_source_breakpoint_executed": True, "actual_locals_and_stack_inspected": True,
              "both_backends_executed": True, "rust_dwarf_uses_original_hepta_paths": False,
              "optimized_debugging_qualified": False, "all_platform_debuggers_qualified": False}
    source = ROOT / "examples/debug/main.hepta"
    source_line = next(i for i, line in enumerate(source.read_text().splitlines(), 1) if line.strip() == "assert(result == 36);")
    return_line = next(i for i, line in enumerate(source.read_text().splitlines(), 1) if line.strip() == "return result;")
    require(report.get("schema") == "hepta.debugger.v1" and report.get("status") == "passed"
            and report.get("compiler_sha256") == compiler_hash()
            and report.get("source_sha256") == sha(source.read_bytes()) and strict_equal(report.get("claims"), claims),
            "Debugger source identity or claims differ")
    debugger = report.get("debugger", {})
    require(text(debugger.get("path")) and text(debugger.get("version")) and "GNU gdb" in debugger["version"]
            and is_sha(debugger.get("binary_sha256")), "actual debugger identity incomplete")
    results = report.get("results", [])
    require(isinstance(results, list) and len(results) == 2 and [r.get("backend") for r in results] == ["rust", "c"],
            "Both backends require actual debugger execution")
    for result in results:
        backend = result["backend"]
        expected = analyze_project(source, backend=backend, native=False, crate_type="bin")
        require(expected.report["ok"] is True, "frozen debugger source no longer checks")
        generated = expected.rust if backend == "rust" else expected.c
        generated_hash = sha(generated.encode())
        build = result.get("build", {})
        require(build.get("schema") == "hepta.build.v1" and build.get("ok") is True, "debug build missing")
        native = build.get("build", {})
        native_build(native, backend, check_only=False, crate_type="bin", source_sha256=generated_hash)
        validation = build.get("validation", {})
        require(validation.get("ok") is True and validation.get("compiler_sha256") == report["compiler_sha256"]
                and validation.get("source_sha256") == report["source_sha256"]
                and validation.get("interface_sha256") == expected.report["interface_sha256"]
                and strict_equal(validation.get("claims"), expected.report["claims"])
                and strict_equal(validation.get("assumptions"), expected.report["assumptions"]), "debug frontend identity/scope differs")
        native_build(validation.get("backend"), backend, check_only=True, crate_type="bin", source_sha256=generated_hash)
        require(strict_equal(native["toolchain"], validation["backend"]["toolchain"])
                and native["target"] == validation["backend"]["target"], "debug toolchain differs from checked source")
        required = {"opt-level=0", "debuginfo=2", "force-frame-pointers=yes", "overflow-checks=yes", "panic=abort"} if backend == "rust" else {"-O0", "-g3", "-fno-omit-frame-pointer", "-ffp-contract=off", "-fno-strict-aliasing"}
        require(required.issubset(native["flags"]), "debug qualification did not retain required flags")
        retained = native.get("debug_info", {})
        suffix = "program.rs" if backend == "rust" else "program.c"
        artifact = Path(native["artifact"])
        directory = artifact.parent / (artifact.name + ".hepta-debug") / generated_hash
        require(retained.get("source") == str(directory / suffix) and retained.get("manifest") == str(directory / "source-map.json")
                and retained.get("source_sha256") == generated_hash, "retained debug source identity differs")
        require(result.get("generated_source") == generated, "retained source text differs from actual compiler lowering")
        markers = [{"generated_start_line": a, "generated_end_line": b, "source": span, "precision": kind}
                   for a, b, span, kind in source_markers(generated)] if backend == "rust" else []
        expected_mapping = {"schema": "hepta.debug-source.v1", "backend": backend,
                            "generated_source": retained["source"], "generated_sha256": generated_hash,
                            "mappings": markers,
                            "mapping_kind": "statement/declaration ranges" if backend == "rust" else "C #line directives",
                            "optimized_variable_visibility_guaranteed": False}
        require(strict_equal(result.get("mapping"), expected_mapping) and type(retained.get("mapping_count")) is int
                and retained["mapping_count"] == len(markers), "source map does not describe actual generated code")
        if backend == "rust":
            choices = [m for m in markers if m["source"]["path"] == str(source) and m["source"]["line"] == source_line and m["precision"] == "statement"]
            require(len(choices) == 1, "source breakpoint mapping is not unique")
            native_path, native_line = retained["source"], choices[0]["generated_start_line"]
            returns = [m for m in markers if m["source"]["path"] == str(source) and m["source"]["line"] == return_line and m["precision"] == "statement"]
            owners = [m for m in markers if m["precision"] == "declaration" and m["generated_start_line"] <= native_line <= m["generated_end_line"]]
            require(len(returns) == 1 and len(owners) == 1, "debug return/function mapping is not unique")
            # Rust may attribute the native epilogue to the closing brace.
            allowed_steps = {returns[0]["generated_start_line"], owners[0]["generated_end_line"]}
            frames = ["hepta_program::h_adjust", "hepta_program::h_main", "hepta_program::main"]
        else:
            native_path, native_line = str(source), source_line
            allowed_steps = {return_line}
            frames = ["__hepta_cb_fn_adjust", "__hepta_cb_fn_main", "main"]
        expected_break = {"path": str(source), "line": source_line, "native_path": native_path, "native_line": native_line}
        require(strict_equal(result.get("source_breakpoint"), expected_break), "breakpoint does not correspond to the frozen source statement")
        observed = result.get("observation", {})
        require(strict_equal(observed.get("locals"), {"h_input":7,"h_base":12,"h_result":36})
                and observed.get("file") == native_path and type(observed.get("line")) is int and observed["line"] == native_line
                and observed.get("step_file") == native_path and type(observed.get("step_line")) is int and observed["step_line"] in allowed_steps
                and isinstance(observed.get("frames"), list) and observed["frames"][:3] == frames
                and all(text(x) for x in observed["frames"]), "actual breakpoint/step/local/stack observation differs")
        stdout, stderr = result.get("stdout"), result.get("stderr")
        require(type(result.get("debugger_returncode")) is int and result["debugger_returncode"] == 0
                and isinstance(stdout, str) and "exited normally" in stdout and "\n36\n" in stdout and isinstance(stderr, str)
                and "Traceback" not in stdout + stderr and "Python Exception" not in stdout + stderr,
                "debuggee did not complete the actual debugger script")
        observations = [line[len("HEPTA_DEBUG="):] for line in stdout.splitlines() if line.startswith("HEPTA_DEBUG=")]
        require(len(observations) == 1 and strict_equal(json.loads(observations[0]), observed), "reported observation differs from raw debugger output")
        require(result.get("stdout_sha256") == sha(stdout.encode()) and result.get("stderr_sha256") == sha(stderr.encode()), "debugger transcript identity differs")
        script = debugger_script(native_path, native_line)
        script_path = str(artifact.parent / (backend + ".gdb"))
        require(result.get("debugger_script") == script and result.get("script_sha256") == sha(script.encode())
                and result.get("script_path") == script_path
                and result.get("debugger_command") == [debugger["path"], "--batch", "-nx", "-nh", "-iex", "set auto-load off", native["artifact"], "-x", script_path],
                "actual debugger invocation/script missing or altered")


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
