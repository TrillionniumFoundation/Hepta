#!/usr/bin/env python3
"""Execute original versus partial Hepta INIReader on two pinned real revisions.

No network, model, Rust compiler, Clang importer, or precomputed output is used.
The Hepta decisions pass the actual frontend and independent C11 backend before
linking into the real C++ component. Foreign C/C++ boundaries remain explicit.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from hepta.inih_component import FIXTURES, LATEST, PREVIOUS, PROFILE, generate, materialize
from hepta.parser import parse
from hepta.checker import check
from hepta.c_backend import emit_c

EXAMPLE = ROOT / "examples/cpp/inih_component"
OPTIONS = ["-DINI_USE_STACK=0", "-DINI_CUSTOM_ALLOCATOR=1",
           "-DINI_STOP_ON_FIRST_ERROR=1", "-DINI_HANDLER_LINENO=0",
           "-DINI_CALL_HANDLER_ON_NEW_SECTION=1", "-DINI_ALLOW_NO_VALUE=1"]


def digest(path):
    return sha256(path.read_bytes()).hexdigest()


def loaded_sources():
    paths = {Path(module.__file__).resolve() for name, module in tuple(sys.modules.items())
             if name.startswith("hepta.") and getattr(module, "__file__", "").endswith(".py")}
    paths |= {Path(__file__).resolve(), *(EXAMPLE / name for name in
        ("client.cpp", "alloc_probe.c", "inih_hepta_callback.hpp")), FIXTURES / "UPSTREAM.json"}
    paths |= {path for path in FIXTURES.rglob("*") if path.is_file()}
    return {str(path.relative_to(ROOT)): digest(path) for path in sorted(paths)}


class Qualification:
    def __init__(self, output: Path, cc: str, cxx: str):
        if output.exists() or output.is_symlink():
            raise ValueError("evidence output must be a new directory")
        if platform.system() != "Linux" or platform.machine() not in {"x86_64", "aarch64"}:
            raise ValueError("This invocation qualifies only direct Linux LP64 hosts")
        self.output = output.resolve()
        self.output.mkdir(parents=True)
        self.commands = []
        self.cc, self.cxx = (self.compiler(value) for value in (cc, cxx))
        self.tools = {tool: {"sha256": digest(Path(tool))} for tool in (self.cc, self.cxx)}
        self.observations = []

    @staticmethod
    def compiler(name):
        executable = shutil.which(name)
        if executable is None:
            raise RuntimeError("required native compiler unavailable: " + name)
        return str(Path(executable).resolve(strict=True))

    def run(self, label, args, *, require_success=True, timeout=60):
        index = len(self.commands)
        started = time.perf_counter_ns()
        process = subprocess.run(args, cwd=self.output, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, timeout=timeout, check=False)
        elapsed = time.perf_counter_ns() - started
        streams = {}
        for name, data in (("stdout", process.stdout), ("stderr", process.stderr)):
            relative = f"raw/{index:03d}-{label}.{name}"
            path = self.output / relative
            path.parent.mkdir(exist_ok=True)
            path.write_bytes(data)
            streams[name] = {"path": relative, "bytes": len(data), "sha256": sha256(data).hexdigest()}
        row = {"label": label, "argv": list(map(str, args)), "returncode": process.returncode,
               "wall_ns": elapsed, "streams": streams}
        self.commands.append(row)
        (self.output / "COMMANDS.json").write_text(json.dumps(self.commands, indent=2) + "\n")
        if require_success and process.returncode:
            raise RuntimeError(f"{label} failed ({process.returncode}): " + process.stderr.decode(errors="replace")[-3000:]
                               + process.stdout.decode(errors="replace")[-1000:])
        return process

    def frontend(self, text, path):
        path.write_text(text)
        program = parse(text, str(path))
        checked = check(program)
        if not checked.ok:
            raise RuntimeError("real Hepta checker rejected: " + json.dumps([x.to_dict() for x in checked.diagnostics]))
        c_source = emit_c(program, checked, crate_type="obj")
        c_path = path.with_suffix(".c")
        c_path.write_text(c_source)
        return c_path

    def build(self, version: str):
        short = version[:8]
        directory = self.output / short
        directory.mkdir()
        original = directory / "original"
        shutil.copytree(FIXTURES / version, original)
        migrated = directory / "migrated"
        report = materialize(version, migrated)
        shutil.copy2(EXAMPLE / "inih_hepta_callback.hpp", migrated / "cpp/inih_hepta_callback.hpp")
        c_source = self.frontend((migrated / "inih.hepta").read_text(), migrated / "inih.hepta")
        object_file = migrated / "inih-hepta.o"
        self.run(short + "-hepta-c-compile", [self.cc, "-std=c11", "-O2", "-fno-strict-aliasing",
                  "-c", str(c_source), "-o", str(object_file)])
        binaries = {}
        for arm, component in (("original", original), ("migrated", migrated)):
            ini_obj, allocator_obj = component / "ini.o", component / "alloc.o"
            self.run(short + "-" + arm + "-parser", [self.cc, "-std=c11", "-O2", *OPTIONS,
                "-c", str(component / "ini.c"), "-o", str(ini_obj)])
            self.run(short + "-" + arm + "-allocator", [self.cc, "-std=c11", "-O2", "-c",
                str(self.output / "source/alloc_probe.c"), "-o", str(allocator_obj)])
            binary = component / "component"
            args = [self.cxx, "-std=c++20", "-O2", "-pthread", *OPTIONS,
                "-I" + str(component), "-I" + str(component / "cpp"),
                str(component / "cpp/INIReader.cpp"), str(self.output / "source/client.cpp"),
                str(ini_obj), str(allocator_obj)]
            if arm == "migrated":
                args += ["-DHEPTA_INIH_MIGRATED=1", str(object_file)]
            args += ["-o", str(binary)]
            self.run(short + "-" + arm + "-link", args)
            binaries[arm] = binary
        return binaries, report

    def negative_mutation(self, version: str, binaries, report):
        directory = self.output / version[:8] / "migrated"
        program = (directory / "inih.hepta").read_text()
        state = report["hepta_automaton"]["states"]["true"]
        before = f"if state == {state} {{ return 1; }}"
        if program.count(before) != 1:
            raise RuntimeError("mutation did not bind one real Hepta acceptance rule")
        wrong = program.replace(before, f"if state == {state} {{ return 0; }}")
        wrong_c = self.frontend(wrong, directory / "wrong-boolean.hepta")
        wrong_obj = directory / "wrong-boolean.o"
        self.run(version[:8] + "-wrong-hepta-compile", [self.cc, "-std=c11", "-O2", "-c",
                 str(wrong_c), "-o", str(wrong_obj)])
        wrong_bin = directory / "wrong-component"
        self.run(version[:8] + "-wrong-link", [self.cxx, "-std=c++20", "-O2", "-pthread", *OPTIONS,
            "-DHEPTA_INIH_MIGRATED=1", "-I" + str(directory), "-I" + str(directory / "cpp"),
            str(directory / "cpp/INIReader.cpp"), str(self.output / "source/client.cpp"),
            str(directory / "ini.o"), str(directory / "alloc.o"), str(wrong_obj), "-o", str(wrong_bin)])
        baseline = self.run(version[:8] + "-negative-reference", [str(binaries["original"]), "functional"])
        mutation = self.run(version[:8] + "-negative-mutant", [str(wrong_bin), "functional"])
        if baseline.stdout == mutation.stdout:
            raise RuntimeError("Independent native reference failed to detect wrong Hepta decision")
        return {"actual_mutated_hepta_compiled": True, "both_native_programs_exited_zero": True,
                "same_native_reference_rejected_output": True,
                "source_rule": before, "not_a_compiler_failure": True}

    def qualify(self):
        started = time.perf_counter_ns()
        before_sources = loaded_sources()
        (self.output / "SOURCE_BEFORE.json").write_text(json.dumps(before_sources, indent=2) + "\n")
        (self.output / "source").mkdir()
        for name in ("client.cpp", "alloc_probe.c", "inih_hepta_callback.hpp"):
            shutil.copy2(EXAMPLE / name, self.output / "source" / name)
        for label, compiler in (("cc", self.cc), ("cxx", self.cxx)):
            self.run(label + "-version", [compiler, "--version"])
            triple = self.run(label + "-target", [compiler, "-dumpmachine"]).stdout.decode().strip()
            if not triple.startswith(platform.machine()) or "linux" not in triple:
                raise RuntimeError("Compiler target is not the executing native Linux host")
            self.tools[compiler]["target"] = triple
        records = []
        for version in (PREVIOUS, LATEST):
            binaries, report = self.build(version)
            comparisons = []
            for mode in ("functional", "lifecycle", "allocation-failure", "file-error"):
                argv = [mode] + ([str(self.output)] if mode == "file-error" else [])
                outputs = {arm: self.run(version[:8] + "-" + arm + "-" + mode, [str(binary), *argv]).stdout
                           for arm, binary in binaries.items()}
                if outputs["original"] != outputs["migrated"]:
                    raise RuntimeError("Real component behavioral mismatch: " + version + " " + mode)
                comparison = {"mode": mode, "byte_identical_stdout": True,
                    "sha256": sha256(outputs["original"]).hexdigest(),
                    "readout": outputs["original"].decode()}
                if mode == "functional":
                    count = re.search(rb"(?m)^boolean-checks=(\d+) ", outputs["original"])
                    values = re.search(rb"(?m)^boolean-results=([01]+)$", outputs["original"])
                    if count is None or values is None or len(values[1]) != int(count[1]):
                        raise RuntimeError("Every Boolean result must be retained and compared, not only its checksum")
                    comparison.update(boolean_result_count=int(count[1]), all_boolean_result_bits_retained=True)
                comparisons.append(comparison)
            exceptions = {arm: self.run(version[:8] + "-" + arm + "-callback-exception",
                          [str(binary), "callback-exception"]).stdout.decode() for arm, binary in binaries.items()}
            if "c-live=1" not in exceptions["original"] or "c-live=0" not in exceptions["migrated"]:
                raise RuntimeError("Exception repair did not expose and close the actual upstream C allocation")
            controls = self.run(version[:8] + "-lease-controls", [str(binaries["migrated"]), "lease-controls"])
            negative = self.negative_mutation(version, binaries, report)
            records.append({"version": version, "migration": report, "comparisons": comparisons,
                "callback_exception_observations": exceptions,
                "callback_exception_is_equivalence_gate": False,
                "callback_lease_controls": controls.stdout.decode(), "native_wrong_result_control": negative})
        old_file = next(c for c in records[0]["comparisons"] if c["mode"] == "file-error")["readout"]
        new_file = next(c for c in records[1]["comparisons"] if c["mode"] == "file-error")["readout"]
        if "directory-read=0:" not in old_file or "directory-read=-3:" not in new_file:
            raise RuntimeError("Actual upstream read-error maintenance change was not observed")
        after_sources = loaded_sources()
        if before_sources != after_sources:
            raise RuntimeError("Executing source dependency bytes changed during qualification")
        for compiler, identity in self.tools.items():
            if digest(Path(compiler)) != identity["sha256"]:
                raise RuntimeError("Compiler changed during qualification")
        files = []
        for path in sorted(self.output.rglob("*")):
            if path.is_file():
                data = path.read_bytes()
                files.append({"path": str(path.relative_to(self.output)), "bytes": len(data),
                              "sha256": sha256(data).hexdigest(), "binary": data.startswith(b"\x7fELF")})
        result = {"schema": "hepta.cpp.inih.native-qualification.v1", "profile": PROFILE,
            "ok": True, "host": {"system": platform.system(), "machine": platform.machine()},
            "route": "source-pinned C++ decision extraction -> actual checked Hepta -> independent C11/GCC -> real INIReader C++ component",
            "rust_or_clang_used": False, "all_executions_direct_native_host": True,
            "component_declaration_inventory": "18/18 explicit member dispositions for each revision",
            "actual_upstream_maintenance_change_observed": True,
            "source_unchanged": True, "tools": self.tools, "parser_options": OPTIONS,
            "records": records, "command_count": len(self.commands), "wall_ns": time.perf_counter_ns() - started,
            "files": files, "all_requested_cpp_conditions_closed": False,
            "whole_component_migration": False, "resource_safety_proved": False,
            "native_backend_refinement_proved": False, "low_human_migration_cost_established": False,
            "performance_advantage_measured": False,
            "limits": ["partial source-specific extraction, not a general C++ translator",
                "foreign parser/STL/callback-registry implementation remains trusted",
                "only synchronous same-thread callback leases; no arbitrary async callback support",
                "callback cleanup repair intentionally differs from original exceptional resource behavior",
                "native Linux LP64 host observation, not physical hardware or all-platform qualification",
                "only parser allocator and ordinary C++ new/delete tracked; no all-process memory bound"]}
        (self.output / "RESULT.json").write_text(json.dumps(result, indent=2) + "\n")
        return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-directory", type=Path, required=True)
    parser.add_argument("--cc", default="gcc")
    parser.add_argument("--cxx", default="g++")
    args = parser.parse_args(argv)
    qualification = Qualification(args.output_directory, args.cc, args.cxx)
    try:
        result = qualification.qualify()
    except Exception as error:
        failure = {"ok": False, "error": type(error).__name__, "message": str(error),
                   "completed_commands": len(qualification.commands)}
        (qualification.output / "FAILED.json").write_text(json.dumps(failure, indent=2) + "\n")
        print(json.dumps(failure))
        return 1
    print(json.dumps({"ok": result["ok"], "versions": len(result["records"]),
                      "commands": result["command_count"], "wall_ns": result["wall_ns"],
                      "full_cpp_migration": False, "result": str(qualification.output / "RESULT.json")}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
