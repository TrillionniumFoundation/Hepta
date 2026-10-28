#!/usr/bin/env python3
"""Captured C ownership migration and whole file-application LTO/PGO trial.

This qualification never turns a timing win into a safety receipt. All outputs
are retained in a new directory, including failures and the complete process
ledger. The frozen protocol distinguishes the small migrated component from
the common, unconverted host and from the independently written baselines.
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import random
import shutil
import statistics
import subprocess
import sys
import time
import zlib

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hepta.c_project import verify_capture
from hepta.hia_program import execute_program, verify_program
from hepta.hia_program_llvm import build_program_native, emit_program_llvm
from hepta.hia_program_source import lower_c_multi_owner
from hepta.elf_shared_abi import inspect_owned_shared_elf

FIXTURE = ROOT / "examples/hia_filecheck"
PROTOCOL_PATH = ROOT / "experiments/hia_filecheck/PROTOCOL_20261028.json"
PROTOCOL = json.loads(PROTOCOL_PATH.read_text())
SOURCES = ("checksum.c", "chunk.c")


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write(path, value):
    with Path(path).open("x") as stream:
        json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write("\n")


def require(condition, message):
    if not condition:
        raise ValueError("E_HIA_FILECHECK: " + message)


def identity(path):
    path = Path(path).resolve()
    return {"path": str(path), "bytes": path.stat().st_size, "sha256": digest(path)}


def source_bindings():
    paths = [Path(__file__), PROTOCOL_PATH, *FIXTURE.iterdir(), *sorted((ROOT / "hepta").glob("*.py"))]
    return {str(p.relative_to(ROOT)): digest(p) for p in paths if p.is_file()}


def corpus(seed, length):
    """Reproducible mixed input, with no dependence on a library PRNG version."""
    value = seed & 0xffffffff
    text = b"Hepta file checksum application: ownership, ABI, migration.\n"
    result = bytearray()
    for index in range(length):
        value ^= (value << 13) & 0xffffffff
        value ^= value >> 17
        value ^= (value << 5) & 0xffffffff
        region = (index // 4096) % 3
        result.append(0 if region == 0 else text[index % len(text)] if region == 1 else value & 255)
    return bytes(result)


def update(state, data, polynomial):
    for byte in data:
        state ^= byte
        for _ in range(8):
            state = (state >> 1) ^ (polynomial if state & 1 else 0)
    return state


def checksum(data, polynomial):
    # IEEE uses an independent standard-library implementation; CRC32C uses
    # this small mathematical recurrence, checked against the published vector.
    return (zlib.crc32(data) & 0xffffffff) if polynomial == 0xedb88320 else update(0xffffffff, data, polynomial) ^ 0xffffffff


def cases():
    rng = random.Random(20261028)
    for index in range(PROTOCOL["differential_cases"]):
        count = index % 12
        packed = rng.getrandbits(64)
        state = rng.getrandbits(32)
        polynomial = list(PROTOCOL["algorithms"].values())[index % 2]
        expected = 1 << 32 if count > 8 else update(state, packed.to_bytes(8, "little")[:count], polynomial)
        yield {"arguments": [count, packed, state, polynomial], "expected": expected}


def order():
    arms = PROTOCOL["arms"]
    for group in range(PROTOCOL["paired_groups"]):
        for index, algorithm in enumerate(PROTOCOL["algorithms"]):
            shift = (group + index) % len(arms)
            rotated = arms[shift:] + arms[:shift]
            if group % 2:
                rotated = list(reversed(rotated))
            for arm in rotated:
                yield group, algorithm, arm


def quantile(values, fraction):
    require(values and 0 < fraction <= 1, "nonempty quantile sample required")
    return sorted(values)[math.ceil(fraction * len(values)) - 1]


RESOURCE_HARNESS = r'''
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
void *__real_calloc(size_t,size_t); void *__real_malloc(size_t); void __real_free(void*);
static unsigned long attempts, allocations, frees, live, refuse;
void *__wrap_calloc(size_t n,size_t m) {
    ++attempts; if(refuse && attempts==refuse)return NULL;
    void *p=__real_calloc(n,m); if(p){++allocations;++live;} return p;
}
void *__wrap_malloc(size_t n) {
    ++attempts; if(refuse && attempts==refuse)return NULL;
    void *p=__real_malloc(n); if(p){++allocations;++live;} return p;
}
void __wrap_free(void *p) {if(p){++frees;--live;} __real_free(p);}
extern unsigned long long ENTRY(size_t,unsigned long long,unsigned int,unsigned int);
int main(int argc,char **argv) {
    if(argc!=6)return 80;
    refuse=strtoul(argv[5],NULL,10);
    unsigned long long result=ENTRY(strtoul(argv[1],NULL,10),strtoull(argv[2],NULL,10),
        (unsigned int)strtoul(argv[3],NULL,10),(unsigned int)strtoul(argv[4],NULL,10));
    printf("{\"result\":%llu,\"attempts\":%lu,\"allocations\":%lu,\"frees\":%lu,\"live\":%lu}\n",
        result,attempts,allocations,frees,live);
    return live?81:0;
}
'''


class Trial:
    def __init__(self, directory, *, clang, clangxx, rustc, profdata, linker):
        self.out = Path(directory).absolute()
        require(not self.out.exists(), "new evidence directory required")
        self.out.mkdir(parents=True)
        # clang++ and ld.lld select their driver mode using argv[0]. Keep the
        # executable spelling while identity() hashes the resolved bytes.
        self.tools = {key: str(Path(shutil.which(value) or value).absolute())
                      for key, value in dict(clang=clang, clangxx=clangxx, rustc=rustc,
                                              profdata=profdata, linker=linker).items()}
        self.report = {"schema": "hepta.hia.filecheck.qualification.v1", "ok": False,
                       "protocol": PROTOCOL, "protocol_sha256": digest(PROTOCOL_PATH),
                       "source_bindings": source_bindings(), "commands": [], "builds": {},
                       "resource_cases": [], "samples": [], "claims": dict(PROTOCOL["claims"])}
        self.libraries = {}
        self.runtime_images = {}
        self.project = self.out / "project"
        shutil.copytree(FIXTURE, self.project)

    def command(self, argv, stage, *, env=None, expected=0, timeout=180):
        argv = list(map(str, argv))
        begin = time.perf_counter_ns()
        row = {"argv": argv, "cwd": str(self.out), "stage": stage}
        try:
            p = subprocess.run(argv, cwd=self.out, text=True, capture_output=True,
                               timeout=timeout, env=env)
            row.update(returncode=p.returncode, stdout=p.stdout, stderr=p.stderr)
        except subprocess.TimeoutExpired as error:
            row.update(returncode=None, timed_out=True,
                       stdout=str(error.stdout or ""), stderr=str(error.stderr or ""))
            raise
        finally:
            row["wall_ns"] = time.perf_counter_ns() - begin
            self.report["commands"].append(row)
            with (self.out / "processes.jsonl").open("a") as stream:
                stream.write(json.dumps(row, separators=(",", ":")) + "\n")
        require(row["returncode"] == expected, stage + " failed: " + row["stderr"][-4000:])
        return row

    def application(self, arm, algorithm, file="held-out.bin", *, env=None, alternate=None, stage="application"):
        library = self.libraries[arm]
        require(identity(library) == self.runtime_images[str(library)], "actual library changed before load")
        require(identity(self.out / "filecheck") == self.driver_identity, "actual host driver changed")
        expected_input = self.report["inputs"][file]
        require(identity(self.out / file) == {k: expected_input[k] for k in ("path", "bytes", "sha256")}, "input changed before execution")
        symbol = "c_checksum_chunk" if arm.startswith("hia") else "checksum_chunk"
        argv = [self.out / "filecheck", self.libraries[arm], symbol, self.out / file,
                str(PROTOCOL["algorithms"][algorithm])]
        if alternate is not None:
            argv.append(alternate)
        row = self.command(argv, stage, env=env)
        require(identity(library) == self.runtime_images[str(library)], "library changed during execution")
        observation = json.loads(row["stdout"])
        data = (self.out / file).read_bytes()
        expected = self.report["inputs"][file]["checksums"][algorithm]
        require(observation["checksum"] == expected and observation["bytes"] == len(data),
                "whole application result differs from independent oracle")
        require(observation["calls"] == (len(data) + 7) // 8 and
                observation["batches"] == (len(data) + 4095) // 4096 and
                len(observation["batch_ns"]) == observation["batches"], "incomplete work or latency ledger")
        return {"observation": observation, "process_wall_ns": row["wall_ns"],
                "command_index": len(self.report["commands"]) - 1}

    def capture(self, project, directory, sources=SOURCES):
        directory.mkdir()
        database = directory / "compile_commands.json"
        write(database, [{"directory": str(project), "file": name,
            "arguments": ["clang", "-std=c11", "-O3", "-I.", "-c", name, "-o", name + ".o"]}
            for name in sources])
        begin = time.perf_counter_ns()
        migrated = lower_c_multi_owner(database, clang=self.tools["clang"])
        elapsed = time.perf_counter_ns() - begin
        core = migrated.pop("program")
        (directory / "migrated.hepta").write_text(migrated["source"])
        (directory / "program.hia.json").write_bytes(core.canonical_bytes)
        (directory / "program.ll").write_text(emit_program_llvm(core).text)
        begin = time.perf_counter_ns()
        verify_program(core.canonical_bytes)
        admission_ns = time.perf_counter_ns() - begin
        verify_capture(migrated["capture"])
        write(directory / "capture.json", migrated)
        report = {"capture_and_lower_wall_ns": elapsed, "fresh_admission_wall_ns": admission_ns,
                  "core_sha256": core.sha256, "source_files": list(sources),
                  "translated_implementation_bodies": len(migrated["functions"]),
                  "functions": migrated["functions"], "owners_lowered": migrated["owners_lowered"],
                  "declaration_inventory_complete": migrated["declaration_inventory_complete"],
                  "active_project_declarations": migrated["active_project_declarations"],
                  "c_implementation_bytes": sum((project / name).stat().st_size for name in sources),
                  "c_implementation_lines": sum(len((project / name).read_text().splitlines()) for name in sources),
                  "generated_source_bytes": len(migrated["source"].encode()),
                  "capture": identity(directory / "capture.json"),
                  "assumptions": migrated["allocation_contract"], "claims": migrated["claims"]}
        return core, report

    def build(self):
        for name, path in self.tools.items():
            version = self.command([path, "--version"], "tool_identity")
            self.report.setdefault("tools", {})[name] = {**identity(path), "version": version["stdout"]}
        self.report["host"] = {"platform": platform.platform(), "machine": platform.machine(),
                               "cpu_count": os.cpu_count(), "exclusive_host": False}
        for name in ("/proc/cpuinfo", "/sys/fs/cgroup/cpu.max", "/sys/fs/cgroup/memory.max"):
            if Path(name).is_file():
                self.report["host"][name] = Path(name).read_text()[:12000]
        self.report["git"] = self.command(["git", "-C", ROOT, "rev-parse", "HEAD"], "source_identity")["stdout"].strip()
        self.report["git_status"] = self.command(["git", "-C", ROOT, "status", "--porcelain", "--untracked-files=no"], "source_identity")["stdout"]
        tracked = set(self.command(["git", "-C", ROOT, "ls-files"], "source_identity")["stdout"].splitlines())
        self.report["source_files_tracked"] = set(self.report["source_bindings"]).issubset(tracked)
        self.report["inputs"] = {}
        for name, spec in (("training.bin", PROTOCOL["training"]), ("held-out.bin", PROTOCOL["held_out"])):
            data = corpus(spec["seed"], spec["bytes"])
            (self.out / name).write_bytes(data)
            self.report["inputs"][name] = {**identity(self.out / name),
                "checksums": {key: checksum(data, poly) for key, poly in PROTOCOL["algorithms"].items()}}
        require(checksum(b"123456789", 0xedb88320) == 0xcbf43926 and
                checksum(b"123456789", 0x82f63b78) == 0xe3069283, "oracle known vector failed")
        self.command([self.tools["clang"], "-std=c11", "-O3", "-Wall", "-Wextra", "-Werror",
                      self.project / "app_driver.c", "-ldl", "-o", self.out / "filecheck"], "host_build")
        self.driver_identity = identity(self.out / "filecheck")
        self.core, self.report["migration"] = self.capture(self.project, self.out / "migration")
        self.libraries = {name: self.out / (name + ".so") for name in PROTOCOL["arms"]}
        begin = time.perf_counter_ns()
        receipt = build_program_native(self.core, self.libraries["hia_default"], clang=self.tools["clang"])
        self.report["builds"]["hia_default"] = {"wall_ns": time.perf_counter_ns() - begin, "receipt": receipt}
        self.flags = ["-O3", "-flto=full", "-fuse-ld=" + self.tools["linker"], "-march=native", "-fPIC", "-shared"]
        row = self.command([self.tools["clang"], *self.flags, self.out / "migration/program.ll",
                            "-o", self.libraries["hia_native_lto"]], "hia_research_native_build")
        # This research build is independently inspected; it is not substituted
        # for a default backend receipt with different flags.
        inventory = inspect_owned_shared_elf(self.libraries["hia_native_lto"].read_bytes(),
                                             emit_program_llvm(self.core).exports)
        self.report["builds"]["hia_native_lto"] = {"wall_ns": row["wall_ns"], "binary_inventory": inventory,
            "default_backend_receipt": False, "scope": "research build of freshly verified exact emitted IR"}
        self.rust_flags = ["--edition=2021", "--crate-type=cdylib", "-Copt-level=3", "-Clto=fat",
                           "-Ccodegen-units=1", "-Cpanic=abort", "-Ctarget-cpu=native"]
        for label in ("c", "cpp", "rust"):
            self.baseline(label, pgo=False)
            self.baseline(label, pgo=True)
        self.report["artifacts"] = {name: identity(path) for name, path in self.libraries.items()}
        self.report["artifacts"]["host_driver"] = self.driver_identity
        self.runtime_images.update({str(path): identity(path) for path in self.libraries.values()})

    def baseline(self, label, *, pgo):
        arm = label + ("_native_pgo" if pgo else "_native_lto")
        begin = time.perf_counter_ns()
        if label == "rust":
            compiler, flags = self.tools["rustc"], self.rust_flags
            sources = [self.project / "reference.rs"]
        else:
            compiler = self.tools["clangxx" if label == "cpp" else "clang"]
            flags = ["-std=" + ("c++20" if label == "cpp" else "c11"), *self.flags]
            sources = [self.project / "checksum.c", self.project / ("reference.cpp" if label == "cpp" else "chunk.c")]
            if label == "cpp":
                flags = ["-x", "c++", *flags]
        row = {"stage_indices": []}
        self.report["builds"][arm] = row
        if not pgo:
            self.command([compiler, *flags, *sources, "-o", self.libraries[arm]], "baseline_build")
        else:
            profiles = self.out / (label + "_profiles")
            profiles.mkdir()
            instrumented = self.out / (label + "_instrumented.so")
            instrumentation = ["-Cprofile-generate=" + str(profiles)] if label == "rust" else ["-fprofile-instr-generate"]
            self.command([compiler, *flags, *instrumentation, *sources, "-o", instrumented], "profile_build")
            self.runtime_images[str(instrumented)] = identity(instrumented)
            original = self.libraries[arm]
            self.libraries[arm] = instrumented
            try:
                row["training"] = []
                for algorithm in PROTOCOL["algorithms"]:
                    env = dict(os.environ, LLVM_PROFILE_FILE=str(profiles / (algorithm + "-%p.profraw")))
                    row["training"].append(self.application(arm, algorithm, "training.bin", env=env, stage="profile_training"))
            finally:
                self.libraries[arm] = original
            raw = sorted(profiles.glob("*.profraw"))
            require(len(raw) == 2 and all(p.stat().st_size for p in raw), "two real training profiles required")
            merged = profiles / "training.profdata"
            self.command([self.tools["profdata"], "merge", "-o", merged, *raw], "profile_merge")
            use = ["-Cprofile-use=" + str(merged), "-Cllvm-args=-pgo-warn-missing-function"] if label == "rust" else [
                "-fprofile-instr-use=" + str(merged), "-Werror=profile-instr-out-of-date", "-Werror=profile-instr-unprofiled"]
            self.command([compiler, *flags, *use, *sources, "-o", original], "profile_use_build")
            row["profiles"] = [identity(path) for path in raw]
            row["merged_profile"] = identity(merged)
        row["wall_ns"] = time.perf_counter_ns() - begin

    def differential(self):
        libraries = {}
        for arm, path in self.libraries.items():
            library = ctypes.CDLL(str(path))
            fn = getattr(library, "c_checksum_chunk" if arm.startswith("hia") else "checksum_chunk")
            fn.argtypes = [ctypes.c_size_t, ctypes.c_ulonglong, ctypes.c_uint, ctypes.c_uint]
            fn.restype = ctypes.c_ulonglong
            libraries[arm] = fn
        rows = []
        ledger = self.out / "differential.jsonl"
        for case in cases():
            observed = {arm: int(fn(*case["arguments"])) for arm, fn in libraries.items()}
            row = {**case, "observed": observed}
            rows.append(row)
            with ledger.open("a") as stream:
                stream.write(json.dumps(row, separators=(",", ":")) + "\n")
            require(all(value == case["expected"] for value in observed.values()), "native ABI differential failed")
        self.report["differential"] = {"cases": len(rows), "routes": len(libraries),
            "native_calls": len(rows) * len(libraries), "ledger": identity(ledger)}

    def resources(self):
        (self.out / "resource_harness.c").write_text(RESOURCE_HARNESS)
        obj = self.out / "resource_hia.o"
        receipt = build_program_native(self.core, obj, kind="object", clang=self.tools["clang"])
        self.report["resource_native_build"] = receipt
        wrap = ["-Wl,--wrap=malloc", "-Wl,--wrap=calloc", "-Wl,--wrap=free"]
        for label in ("c", "hia"):
            entry = "c_checksum_chunk" if label == "hia" else "checksum_chunk"
            inputs = [obj] if label == "hia" else [self.project / name for name in SOURCES]
            self.command([self.tools["clang"], "-std=c11", "-O2", "-fno-builtin", "-DENTRY=" + entry,
                          self.out / "resource_harness.c", *inputs, *wrap, "-o", self.out / ("resource_" + label)],
                         "resource_observer_build")
        for index, case in enumerate(cases()):
            if index == PROTOCOL["resource_cases"]:
                break
            args = case["arguments"]
            # Cover refusal and normal success independently for identical inputs.
            for refusal in (0, 1):
                vm = execute_program(self.core, "c_checksum_chunk", args, allocation_fail_at=refusal or None)
                expected = dict(result=vm["result"], attempts=vm["resources"]["allocation_attempts"],
                                allocations=vm["resources"]["allocations"], frees=vm["resources"]["frees"], live=0)
                native = {}
                for label in ("c", "hia"):
                    row = self.command([self.out / ("resource_" + label), *args, refusal], "resource_execution")
                    native[label] = json.loads(row["stdout"])
                self.report["resource_cases"].append({**case, "refuse_at": refusal, "vm": vm, "native": native})
                require(vm["resources"]["live_owners"] == 0 and all(row == expected for row in native.values()),
                        "native/interpreter resource differential failed")

    def maintenance(self):
        begin = time.perf_counter_ns()
        project = self.out / "maintained-project"
        shutil.copytree(self.project, project)
        # A real additive API upgrade: callers select a named algorithm, while
        # the old ABI remains available. New source participates in capture.
        (project / "api_v2.c").write_text('''#include "checksum.h"
unsigned long long checksum_chunk_v2(size_t count, unsigned long long packed,
                                    unsigned int state, unsigned int algorithm) {
    if (algorithm == 1) { return checksum_chunk(count, packed, state, 0xedb88320U); }
    if (algorithm == 2) { return checksum_chunk(count, packed, state, 0x82f63b78U); }
    return 12884901888ULL;
}
''')
        header = project / "checksum.h"
        declaration = ('\n/* Additive C API v2; the original entry remains available. */\n'
            'unsigned long long checksum_chunk_v2(size_t count, unsigned long long packed,\n'
            '    unsigned int state, unsigned int algorithm);\n')
        header.write_text(header.read_text().replace('#ifdef __cplusplus\n}\n', declaration + '#ifdef __cplusplus\n}\n'))
        core, capture = self.capture(project, self.out / "maintenance", (*SOURCES, "api_v2.c"))
        output = self.out / "maintenance.so"
        build = build_program_native(core, output, clang=self.tools["clang"])
        original = self.out / "maintenance-c.so"
        self.command([self.tools["clang"], "-std=c11", *self.flags,
                      *[project / name for name in (*SOURCES, "api_v2.c")], "-o", original], "maintenance_original_build")
        observations = []
        for algorithm, polynomial in ((1, 0xedb88320), (2, 0x82f63b78), (0, None), (3, None)):
            args = [8, int.from_bytes(b"12345678", "little"), 0xffffffff, algorithm]
            expected = 3 << 32 if polynomial is None else update(args[2], b"12345678", polynomial)
            values = {}
            for route, path, symbol in (("c", original, "checksum_chunk_v2"), ("hia", output, "c_checksum_chunk_v2")):
                fn = getattr(ctypes.CDLL(str(path)), symbol)
                fn.argtypes = [ctypes.c_size_t, ctypes.c_ulonglong, ctypes.c_uint, ctypes.c_uint]
                fn.restype = ctypes.c_ulonglong
                values[route] = int(fn(*args))
            observations.append({"arguments": args, "expected": expected, "values": values})
            with (self.out / "maintenance-cases.jsonl").open("a") as stream:
                stream.write(json.dumps(observations[-1], separators=(",", ":")) + "\n")
            require(all(value == expected for value in values.values()), "maintenance ABI upgrade failed")
        # Exercise the upgraded ABI in the same real file-reading application.
        full = []
        for algorithm, name in ((1, "ieee"), (2, "castagnoli")):
            row = self.command([self.out / "filecheck", output, "c_checksum_chunk_v2", self.out / "held-out.bin", algorithm],
                               "maintenance_application")
            observed = json.loads(row["stdout"])
            require(observed["checksum"] == self.report["inputs"]["held-out.bin"]["checksums"][name], "upgraded application failed")
            full.append({"algorithm": name, "observation": observed})
        self.report["maintenance"] = {"task": "add named algorithm API across a third translation unit and callers",
            "capture": capture, "build": build, "cases": observations, "application": full,
            "wall_ns": time.perf_counter_ns() - begin, "manual_target_edits": 0,
            "authored_source_files_added": 1, "authored_source_files_modified": 1,
            "human_effort_or_agent_productivity_measured": False}

    def measure(self):
        require(not self.report["git_status"] and self.report["source_files_tracked"], "formal trial requires committed, clean source")
        require(source_bindings() == self.report["source_bindings"], "source changed before trial")
        self.verify_artifacts()
        for group, algorithm, arm in order():
            observation = self.application(arm, algorithm, stage="measured_application")
            self.report["samples"].append({"group": group, "algorithm": algorithm, "arm": arm, **observation})
        switch_path = self.out / "hia-switch-copy.so"
        shutil.copyfile(self.libraries["hia_default"], switch_path)
        self.report["switch_recovery"] = {}
        for label, alternate in (("successful_switch", switch_path), ("rejected_switch", self.out / "missing-candidate.so")):
            row = self.application("hia_default", "ieee", alternate=alternate, stage=label)
            observation = row["observation"]
            require(observation["switches"] == (label == "successful_switch") and
                    observation["refused_switches"] == (label == "rejected_switch"), "switch/refusal was not exercised")
            self.report["switch_recovery"][label] = row
        summary = {}
        for algorithm in PROTOCOL["algorithms"]:
            table = {}
            for arm in PROTOCOL["arms"]:
                samples = [r for r in self.report["samples"] if r["algorithm"] == algorithm and r["arm"] == arm]
                rows = [r["observation"] for r in samples]
                require(len(rows) == PROTOCOL["paired_groups"], "missing or duplicated arm samples")
                runtime = statistics.median(row["process_wall_ns"] for row in samples)
                batches = [ns for row in rows for ns in row["batch_ns"]]
                table[arm] = {"median_process_wall_ns": runtime,
                    "median_internal_main_through_dlclose_ns": statistics.median(row["elapsed_ns"] for row in rows),
                    "mib_per_second": PROTOCOL["held_out"]["bytes"] * 1e9 / runtime / 2**20,
                    "batch_p95_ns": quantile(batches, .95), "batch_p99_ns": quantile(batches, .99),
                    "peak_rss_kib_max": max(row["peak_rss_kib"] for row in rows),
                    "samples": len(rows), "batch_observations": len(batches)}
            strong = min((arm for arm in table if not arm.startswith("hia")), key=lambda arm: table[arm]["median_process_wall_ns"])
            candidate = "hia_native_lto"
            summary[algorithm] = {"arms": table, "fastest_strong_reference": strong,
                "hia_runtime_ratio": table[candidate]["median_process_wall_ns"] / table[strong]["median_process_wall_ns"],
                "hia_p99_ratio": table[candidate]["batch_p99_ns"] / table[strong]["batch_p99_ns"]}
        self.report["summary"] = summary
        self.report["performance_advantage_gate"] = all(row["hia_runtime_ratio"] <= 1 and row["hia_p99_ratio"] <= 1 for row in summary.values())
        self.report["samples_excluded"] = 0
        self.report["performance_scope"] = "descriptive nonexclusive host; no significance or universal dominance claim"

    def verify_artifacts(self):
        for name, observed in self.report["artifacts"].items():
            path = self.out / "filecheck" if name == "host_driver" else self.libraries[name]
            require(identity(path) == observed, "artifact drift: " + name)
        for name, observed in self.report["tools"].items():
            require(identity(self.tools[name]) == {k: observed[k] for k in ("path", "bytes", "sha256")}, "tool drift: " + name)
        for name, observed in self.report["inputs"].items():
            require(identity(self.out / name) == {k: observed[k] for k in ("path", "bytes", "sha256")}, "input drift: " + name)
        self.report["artifact_drift_checks"] = "observed file identities checked before measurement and after qualification; library and input also checked at application boundaries; trusted-host pathname loading, not a sealed-mapping certificate"

    def run(self, *, prepare_only=False):
        begin = time.perf_counter_ns()
        try:
            self.build()
            self.differential()
            self.resources()
            self.maintenance()
            if not prepare_only:
                self.measure()
            self.verify_artifacts()
            require(source_bindings() == self.report["source_bindings"], "source changed during qualification")
            self.report.update(ok=True, status="prepared_not_measured" if prepare_only else "completed",
                               prepare_only=prepare_only)
        except Exception as error:
            self.report.update(ok=False, status="failed", error={"type": type(error).__name__, "message": str(error)})
        finally:
            self.report["whole_qualification_wall_ns"] = time.perf_counter_ns() - begin
            # Process stdout remains in the append-only JSONL ledger. Retaining
            # just the indexed summaries here prevents accidental double counts.
            for row in self.report["commands"]:
                row.pop("stdout", None)
                row.pop("stderr", None)
            self.report["process_ledger"] = identity(self.out / "processes.jsonl")
            write(self.out / "qualification.json", self.report)
        return self.report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--clang", default=os.environ.get("CLANG", "clang"))
    parser.add_argument("--clangxx", default=os.environ.get("CLANGXX", "clang++"))
    parser.add_argument("--rustc", default=os.environ.get("RUSTC", "rustc"))
    parser.add_argument("--profdata", default="llvm-profdata")
    parser.add_argument("--linker", default="ld.lld")
    parser.add_argument("--prepare-only", action="store_true")
    args = parser.parse_args(argv)
    report = Trial(args.output, clang=args.clang, clangxx=args.clangxx, rustc=args.rustc,
                   profdata=args.profdata, linker=args.linker).run(prepare_only=args.prepare_only)
    print(json.dumps({key: report[key] for key in ("ok", "status", "error", "summary", "performance_advantage_gate") if key in report}, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
