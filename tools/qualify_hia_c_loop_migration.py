#!/usr/bin/env python3
"""Retain a source-bound C loop-maintenance migration and finite resource checks.

This is a small capability qualification, not a performance experiment. It
keeps the unchanged imported application separate from an authored maintenance
patch, and compiles the C reference with the exact captured semantic flags.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import difflib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hepta.hia_program import execute_program
from hepta.hia_program_llvm import build_program_native
from tools.qualify_hia_filecheck import RESOURCE_HARNESS, digest, identity, require, update, write
from tools.qualify_hia_legacy_queue import (
    ENTRY, SOURCES, LegacyTrial, populate_project, source_bindings as legacy_bindings,
)

OLD_LOOP = """  for(i = 0; i < size; i++) {
    ring_buffer_queue(buffer, data[i]);
  }"""
NEW_LOOP = """  i = 0;
  while (i < size) {
    ring_buffer_queue(buffer, data[i]);
    i++;
    if (i == size) break;
    continue;
  }"""
VARIANTS = ("original", "maintenance")
REFUSALS = (0, 1, 2, 3)


def source_bindings():
    return {**legacy_bindings(), str(Path(__file__).relative_to(ROOT)): digest(__file__)}


def inventory(directory):
    return {str(path.relative_to(directory)): digest(path)
            for path in sorted(directory.rglob("*")) if path.is_file()}


def finite_cases():
    for polynomial in (0xedb88320, 0x82f63b78):
        for count in range(12):
            packed = (0xfedcba9876543210 ^ (count * 0x0101010101010101)) & ((1 << 64) - 1)
            state = (0xffffffff ^ (count * 0x01020304)) & 0xffffffff
            result = (1 << 32 if count > 8 else
                      update(state, packed.to_bytes(8, "little")[:count], polynomial))
            yield {"arguments": [count, packed, state, polynomial], "expected": result}


def expected_resources(case, refusal):
    active = 0 < case["arguments"][0] <= 8
    attempts = (refusal or 3) if active else 0
    allocations = attempts - int(bool(refusal)) if active else 0
    return {"result": 1 << 33 if active and refusal else case["expected"],
            "attempts": attempts, "allocations": allocations, "frees": allocations, "live": 0}


def ast_inventory(directory):
    functions, jumps = [], {"BreakStmt": 0, "ContinueStmt": 0}
    for path in sorted(directory.glob("clang-ast-*.json")):
        document = json.loads(path.read_text())
        for node in document.get("inner", []):
            if node.get("kind") == "FunctionDecl" and any(
                    child.get("kind") == "CompoundStmt" for child in node.get("inner", [])):
                functions.append({"name": node["name"], "type": node["type"]["qualType"],
                    "parameters": [child["type"]["qualType"] for child in node.get("inner", [])
                                   if child.get("kind") == "ParmVarDecl"]})
        pending = [document]
        while pending:
            node = pending.pop()
            if node.get("kind") in jumps:
                jumps[node["kind"]] += 1
            pending.extend(node.get("inner", []))
    return {"function_types": sorted(functions, key=lambda row: row["name"]),
            "original_ast_jump_nodes": jumps}


class LoopMigrationTrial:
    def __init__(self, output, *, clang, source_sha):
        begin = time.perf_counter_ns()
        self.out = Path(output).absolute()
        require(not self.out.exists(), "new evidence directory required")
        self.out.mkdir(parents=True)
        self.tools = {"clang": str(Path(shutil.which(clang) or clang).absolute())}
        self.expected_sha, self.stage = source_sha, None
        self.report = {"schema": "hepta.hia.c-loop-migration.qualification.v1", "ok": False,
            "commands": [], "stages": {}, "migrations": {}, "builds": {},
            "source_bindings": source_bindings(), "human_effort_measured": False,
            "protocol": {"variants": list(VARIANTS), "finite_inputs": 24,
                "allocation_refusal_indices": list(REFUSALS), "entry": ENTRY,
                "performance_measured": False, "pgo_used": False},
            "claims": {"finite_capability_and_resource_observations": False,
                "source_equivalence_proved": False, "backend_refinement_proved": False,
                "all_c_cpp_supported": False, "runtime_performance_advantage_claimed": False,
                "whole_application_automatically_migrated": False,
                "rust_codegen_used": False, "fallback_used": False}}
        self.work = self.out / "build-work"
        self.cores, self.executables = {}, {}
        self.invocations = []
        # Observe actual Python subprocess launches, including the compiler's
        # private temporary LLVM path. This never substitutes a fake compiler.
        # Only argv/cwd are recorded: inherited environment values are omitted.
        sys.addaudithook(self.audit)
        self.report["initialization_wall_ns"] = time.perf_counter_ns() - begin

    def audit(self, event, arguments):
        if self.stage is None or event != "subprocess.Popen":
            return
        executable, argv, cwd, _environment = arguments
        row = {"stage": self.stage, "executable": str(executable),
               "argv": list(map(str, argv)), "cwd": str(cwd or Path.cwd()),
               "launch_monotonic_ns": time.perf_counter_ns()}
        self.invocations.append(row)
        with (self.out / "invocations.jsonl").open("a") as stream:
            stream.write(json.dumps(row, separators=(",", ":")) + "\n")
        require(not Path(str(executable)).name.startswith("rustc"), "Rust execution forbidden")

    @contextmanager
    def phase(self, name):
        before, self.stage = self.stage, name
        begin, first = time.perf_counter_ns(), len(self.invocations)
        try:
            yield
        finally:
            self.report["stages"][name] = {"wall_ns": time.perf_counter_ns() - begin,
                "first_invocation_index": first, "invocations": len(self.invocations) - first}
            self.stage = before

    def command(self, argv, label, *, cwd=None):
        argv = list(map(str, argv))
        row = {"argv": argv, "cwd": str(cwd or self.out), "stage": label}
        begin = time.perf_counter_ns()
        try:
            result = subprocess.run(argv, cwd=row["cwd"], capture_output=True, text=True, timeout=60)
            row.update(returncode=result.returncode, stdout=result.stdout, stderr=result.stderr)
        except subprocess.TimeoutExpired as error:
            def decoded(value):
                return value.decode(errors="replace") if isinstance(value, bytes) else value or ""
            row.update(returncode=None, timed_out=True,
                       stdout=decoded(error.stdout), stderr=decoded(error.stderr))
            raise
        finally:
            row["wall_ns"] = time.perf_counter_ns() - begin
            self.report["commands"].append(row)
            with (self.out / "processes.jsonl").open("a") as stream:
                stream.write(json.dumps(row, separators=(",", ":")) + "\n")
        require(row["returncode"] == 0, label + " failed: " + str(row)[-4000:])
        return row

    def prepare(self):
        with self.phase("source_and_tool_identity"):
            self.report["git"] = self.command(["git", "-C", ROOT, "rev-parse", "HEAD"], "git_head")["stdout"].strip()
            require(self.report["git"] == self.expected_sha and len(self.expected_sha) == 40,
                    "--source-sha must equal the full current commit")
            status = self.command(["git", "-C", ROOT, "status", "--porcelain", "--untracked-files=no"], "git_status")["stdout"]
            tracked = set(self.command(["git", "-C", ROOT, "ls-files"], "git_files")["stdout"].splitlines())
            require(not status and set(self.report["source_bindings"]) <= tracked,
                    "qualification requires clean committed implementation inputs")
            self.report["git_status"] = status
            self.report["tools"] = {"clang": {**identity(self.tools["clang"]),
                "version": self.command([self.tools["clang"], "--version"], "clang_version")["stdout"]}}
            self.report["host"] = {"platform": platform.platform(), "machine": platform.machine(),
                                   "exclusive_host": False}
            self.report["python"] = {**identity(sys.executable), "version": sys.version}
        with self.phase("project_preparation"):
            original, maintenance = (self.out / name / "project" for name in VARIANTS)
            for name in VARIANTS:
                (self.out / name).mkdir()
            self.contracts = populate_project(original)
            shutil.copytree(original, maintenance)
            edits = {"ring/ringbuffer.c": (OLD_LOOP, NEW_LOOP),
                "client.c": ("the three upstream files are unchanged",
                             "the ring maintenance patch is recorded separately"),
                "client.hepta": ("Original Ring-Buffer and musl functions",
                                  "Maintained Ring-Buffer and unchanged musl functions")}
            patches = []
            for name, (old, new) in edits.items():
                path = maintenance / name
                before = path.read_text()
                require(before.count(old) == 1, "maintenance patch context differs: " + name)
                after = before.replace(old, new)
                path.write_text(after)
                patches.extend(difflib.unified_diff(before.splitlines(keepends=True),
                    after.splitlines(keepends=True), fromfile="original/" + name, tofile="maintenance/" + name))
            patch_path = self.out / "maintenance.patch"
            patch_path.write_text("".join(patches))
            inventories = {name: inventory(self.out / name / "project") for name in VARIANTS}
            require(inventories["original"].keys() == inventories["maintenance"].keys(), "project inventory differs")
            changed = {name for name in inventories["original"]
                       if inventories["original"][name] != inventories["maintenance"][name]}
            require(changed == set(edits), "unexpected project modification")
            write(self.out / "project-inputs.json", inventories)
            self.report["projects"] = {"inventories": identity(self.out / "project-inputs.json"),
                "maintenance_patch": identity(patch_path), "changed_files": sorted(changed),
                "modified_implementation_bodies": ["ring_buffer_queue_arr"],
                "comment_only_changes": ["client.c", "client.hepta"],
                "original_project_scope": "unchanged frozen ring/musl imports plus separately authored adapters and clients",
                "maintenance_scope": "authored loop-jump patch to one imported body; not untouched upstream",
                "unchanged_headers_contracts_and_source_types": True,
                "domain": "same Linux LP64 unsigned-char C11 NDEBUG configuration and explicit pointer contracts; public entry size_t,u64,u32,u32 -> u64",
                "domain_limits": "finite checks do not prove all-input equivalence; valid pointer/extent assumptions, arithmetic and unsupported-source rejection remain required"}
            self.project_inputs = inventories
            self.work.mkdir()
            (self.out / "resource_harness.c").write_text(RESOURCE_HARNESS)

    def capture(self, name):
        directory, project = self.out / name / "capture", self.out / name / "project"
        with self.phase("capture_" + name):
            core, record = LegacyTrial.capture(self, project, directory)
            # The shared capture helper's upstream counts describe its untouched
            # fixture. Relabel the authored maintenance body explicitly here.
            del record["upstream_function_bodies"]
            record.update(unchanged_upstream_function_bodies=11 - int(name == "maintenance"),
                authored_maintenance_function_bodies=int(name == "maintenance"),
                upstream_metadata_scope="identity of frozen base fixtures; maintenance diff is separately inventoried",
                original_ast_inventory=ast_inventory(directory))
            require(record["claims"]["rust_backend_required"] is False, "migration needs Rust")
            self.report["migrations"][name], self.cores[name] = record, core

    def build(self, name):
        directory, project = self.out / name, self.out / name / "project"
        temporary = self.work / name
        temporary.mkdir()
        record = self.report["builds"][name] = {"c_compile_commands": []}
        with self.phase("build_" + name):
            database = json.loads((directory / "capture/compile_commands.json").read_text())
            objects, common = [], None
            for index, entry in enumerate(database):
                original = entry["arguments"]
                require(original[-4:] == ["-c", entry["file"], "-o", entry["file"] + ".o"],
                        "unexpected authored compilation database shape")
                flags = original[1:-4]
                require(common is None or flags == common, "different source configurations")
                common = flags
                obj = temporary / f"source-{index}.o"
                argv = [self.tools["clang"], *original[1:-1], obj]
                row = self.command(argv, "captured_c_object", cwd=entry["directory"])
                record["c_compile_commands"].append({"database_index": index, "original_arguments": original,
                    "actual_argv": row["argv"], "cwd": row["cwd"], "wall_ns": row["wall_ns"],
                    "changes": "compiler resolved to recorded Clang; only -o destination changed",
                    "semantic_flags_and_source_operand_unchanged": True})
                objects.append(obj)
            client = temporary / "authored-client.o"
            self.command([self.tools["clang"], *common, "-c", "client.c", "-o", client],
                         "authored_c_client", cwd=project)
            objects.append(client)
            obj = directory / "hia.o"
            first = len(self.invocations)
            receipt = build_program_native(self.cores[name], obj, kind="object", clang=self.tools["clang"])
            require(all(receipt["claims"][key] is False for key in
                        ("rust_codegen_used", "c_codegen_used", "fallback_used")), "native fallback forbidden")
            actual = [row for row in self.invocations[first:] if "-x" in row["argv"] and "ir" in row["argv"]]
            require(len(actual) == 1, "one actual direct LLVM compiler invocation required")
            record["direct_llvm"] = {"receipt": receipt, "actual_compiler_invocation": actual[0],
                "retained_ir": identity(directory / "capture/program.ll"), "retained_object": identity(obj),
                "temporary_input_note": "backend removed its private temporary copy; retained IR hash must match receipt"}
            require(digest(directory / "capture/program.ll") == receipt["llvm_ir_sha256"], "retained LLVM changed")
            for arm, inputs in (("c", objects), ("hia", [obj])):
                output = directory / ("resource_" + arm)
                self.command([self.tools["clang"], self.work / "resource-harness.o", *inputs,
                    "-Wl,--wrap=malloc", "-Wl,--wrap=calloc", "-Wl,--wrap=free", "-o", output], "resource_link")
                self.executables[name + "_" + arm] = output
                record[arm + "_executable"] = identity(output)

    def validate(self):
        with self.phase("finite_validation"):
            report = self.report["validation"] = {"completed_cases": 0, "native_calls": 0,
                "vm_calls": 0, "input_cases": 24, "refusal_modes": list(REFUSALS),
                "runtime_cleanup_observed": "allocation attempts, successes, frees, live owners and balanced loans; process wall includes cleanup, individual free time is not isolated"}
            path = self.out / "cases.jsonl"
            with path.open("x") as stream:
                for case in finite_cases():
                    for refusal in REFUSALS:
                        row = {**case, "refuse_at": refusal, "resource_expected": expected_resources(case, refusal),
                               "native": {}, "vm": {}}
                        report["pending_case"] = {"arguments": case["arguments"], "refuse_at": refusal}
                        for arm, executable in self.executables.items():
                            observed = self.command([executable, *case["arguments"], refusal], "native_resource_case")
                            row["native"][arm] = {"observation": json.loads(observed["stdout"]),
                                "process_wall_ns": observed["wall_ns"], "command_index": len(self.report["commands"]) - 1}
                            report["native_calls"] += 1
                        for name, core in self.cores.items():
                            begin = time.perf_counter_ns()
                            row["vm"][name] = {"observation": execute_program(core, ENTRY, case["arguments"],
                                allocation_fail_at=refusal or None), "wall_ns": time.perf_counter_ns() - begin}
                            report["vm_calls"] += 1
                        stream.write(json.dumps(row, separators=(",", ":")) + "\n")
                        stream.flush()
                        require(all(item["observation"] == row["resource_expected"] for item in row["native"].values()),
                                "native output/allocation/refusal/cleanup mismatch")
                        for item in row["vm"].values():
                            observation, expected = item["observation"], row["resource_expected"]
                            stats = observation["resources"]
                            require(observation["result"] == expected["result"] and stats["live_owners"] == 0
                                and stats["loans_started"] == stats["loans_ended"]
                                and all(stats[key] == expected[value] for key, value in
                                    (("allocation_attempts", "attempts"), ("allocations", "allocations"), ("frees", "frees"))),
                                "VM output/allocation/refusal/cleanup mismatch")
                        report["completed_cases"] += 1
                        report["pending_case"] = None
            report["ledger"] = identity(path)

    def run(self):
        begin = time.perf_counter_ns()
        try:
            self.prepare()
            with self.phase("observer_build"):
                self.command([self.tools["clang"], "-std=c11", "-O3", "-DENTRY=" + ENTRY,
                    "-c", self.out / "resource_harness.c", "-o", self.work / "resource-harness.o"], "observer_build")
            for name in VARIANTS:
                self.capture(name)
                self.build(name)
            inventories = [self.report["migrations"][name]["original_ast_inventory"] for name in VARIANTS]
            require(inventories[0]["function_types"] == inventories[1]["function_types"], "captured source function types changed")
            require(all(inventories[1]["original_ast_jump_nodes"][kind] == inventories[0]["original_ast_jump_nodes"][kind] + 1
                        for kind in ("BreakStmt", "ContinueStmt")), "maintenance jumps missing from actual Clang AST")
            self.validate()
            require(all(inventory(self.out / name / "project") == self.project_inputs[name] for name in VARIANTS), "project input drift")
            require(source_bindings() == self.report["source_bindings"], "implementation source drift")
            require(identity(self.tools["clang"]) == {key: self.report["tools"]["clang"][key]
                    for key in ("path", "bytes", "sha256")}, "Clang changed")
            require(self.report["validation"]["completed_cases"] == 96, "incomplete finite matrix")
            self.report["claims"]["finite_capability_and_resource_observations"] = True
            self.report.update(ok=True, status="completed_finite_capability_qualification")
        except Exception as error:
            self.report.update(ok=False, status="failed", error={"type": type(error).__name__, "message": str(error)})
        finally:
            try:
                with self.phase("temporary_build_cleanup"):
                    files = [identity(path) for path in sorted(self.work.rglob("*")) if path.is_file()]
                    existed = self.work.exists()
                    if existed:
                        shutil.rmtree(self.work)
                    self.report["cleanup"] = {"temporary_directory_existed": existed, "removed_files": files,
                        "temporary_directory_absent": not self.work.exists(),
                        "retained_artifacts": "project copies, licenses/pins, patch, capture/AST/Hepta/Core/LLVM, HIA objects, native executables and ledgers"}
            except Exception as error:
                self.report["claims"]["finite_capability_and_resource_observations"] = False
                self.report.update(ok=False, status="failed", cleanup_error=str(error))
            self.stage = None
            self.report["run_wall_ns"] = time.perf_counter_ns() - begin
            self.report["whole_qualification_wall_ns"] = self.report["initialization_wall_ns"] + self.report["run_wall_ns"]
            for label, filename in (("process_ledger", "processes.jsonl"), ("invocation_ledger", "invocations.jsonl")):
                if (self.out / filename).exists():
                    self.report[label] = identity(self.out / filename)
            for row in self.report["commands"]:
                row.pop("stdout", None)
                row.pop("stderr", None)
            write(self.out / "qualification.json", self.report)
        return self.report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--source-sha", required=True, help="full frozen implementation commit")
    parser.add_argument("--clang", default=os.environ.get("CLANG", "clang"))
    args = parser.parse_args(argv)
    report = LoopMigrationTrial(args.output, clang=args.clang, source_sha=args.source_sha).run()
    print(json.dumps({key: report[key] for key in ("ok", "status", "error", "whole_qualification_wall_ns") if key in report}))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
