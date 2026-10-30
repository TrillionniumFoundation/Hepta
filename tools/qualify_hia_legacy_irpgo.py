#!/usr/bin/env python3
"""Prospective IR PGO follow-up; preserves the original legacy trial unchanged.

Every PGO arm is trained on both algorithms, with real counters and retained
profiles. The HIA arm keeps the same verified Core, allocation attempts and
failure behavior. Compiler profiles do not constitute safety certificates.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hepta.elf_shared_abi import inspect_owned_shared_elf
from hepta.hia_program_llvm import emit_program_llvm
from tools.qualify_hia_legacy_queue import LegacyTrial, ENTRY, source_bindings as legacy_bindings
from tools.qualify_hia_filecheck import digest, identity, require

PROTOCOL_PATH = ROOT / "experiments/hia_legacy_queue/IRPGO_PROTOCOL_20261029.json"
PROTOCOL = json.loads(PROTOCOL_PATH.read_text())


def inspect_ir_counters(shown, entry=ENTRY):
    """Require positive counters in the unique target function's IR profile.

    LLVM may report entry_first=0. The first stored block counter is therefore
    not an entry invocation count; retain the full named-function counter list.
    """
    require(type(shown) is str, "expected llvm-profdata text")
    starts = list(re.finditer(r"^  " + re.escape(entry) + r":$", shown, re.M))
    require(len(starts) == 1, "exactly one actual entry profile is required")
    section = re.split(r"(?m)^  \S[^\r\n]*:$|^Instrumentation level:",
                       shown[starts[0].end():], maxsplit=1)[0]
    sizes = re.findall(r"^    Counters:[^\r\n]*$", section, re.M)
    lists = re.findall(r"^    Block counts:[^\r\n]*$", section, re.M)
    require(len(sizes) == len(lists) == 1, "one complete actual entry counter list is required")
    size = re.fullmatch(r"    Counters: ([0-9]{1,10})", sizes[0])
    values = re.fullmatch(r"    Block counts: \[([^\]\r\n]*)\]", lists[0])
    require(size is not None and values is not None, "malformed actual entry counter list")
    tokens = [part.strip() for part in values[1].split(",")] if values[1].strip() else []
    require(all(re.fullmatch(r"(?:0|[1-9][0-9]{0,19})", token) for token in tokens),
            "actual entry counters must be unsigned 64-bit decimal values")
    counts = [int(token) for token in tokens]
    require(len(counts) == int(size[1]) and all(value < 2**64 for value in counts),
            "actual entry counter count or unsigned width differs")
    require(any(counts), "actual entry function counters must be nonzero")
    functions = re.findall(r"^Total functions: ([0-9]{1,10})$", shown, re.M)
    total = re.findall(r"^Total count: ([0-9]{1,30})$", shown, re.M)
    require(re.search(r"^Instrumentation level: IR(?:\s|$)", shown, re.M) is not None
            and len(functions) == len(total) == 1 and int(functions[0]) > 0 and int(total[0]) > 0,
            "positive actual LLVM IR counter inventory is required")
    return {"profiled_functions": int(functions[0]), "total_profile_count": int(total[0]),
            "entry_function": entry, "entry_function_counters": len(counts),
            "entry_function_block_counts": counts, "entry_function_block_count_sum": sum(counts),
            "entry_counter_interpretation": "stored block counters, not entry invocation counts"}


def source_bindings():
    result = legacy_bindings()
    for path in (Path(__file__), PROTOCOL_PATH):
        result[str(path.relative_to(ROOT))] = digest(path)
    return result


class IRPGOTrial(LegacyTrial):
    protocol = PROTOCOL
    protocol_path = PROTOCOL_PATH
    schema = "hepta.hia.legacy-queue-irpgo.qualification.v1"
    performance_arm = "hia_native_irpgo"
    source_bindings = staticmethod(source_bindings)

    def sample_order(self):
        arms = self.protocol["arms"]
        for group in range(self.protocol["paired_groups"]):
            for index, algorithm in enumerate(self.protocol["algorithms"]):
                shift = (group + index) % len(arms)
                rotated = arms[shift:] + arms[:shift]
                if group % 2:
                    rotated = list(reversed(rotated))
                for arm in rotated:
                    yield group, algorithm, arm

    def extra_builds(self):
        for label in ("hia", "c", "cpp"):
            self.irpgo(label)

    def irpgo_build(self, label, output, flags, stage):
        if label == "hia":
            self.build_native_ir(output, flags, stage)
        else:
            self.build_reference(label, output, flags, stage)

    def irpgo(self, label):
        arm = label + "_native_irpgo"
        begin = time.perf_counter_ns()
        record = {"instrumentation": "LLVM IR", "training_only": True}
        if label == "hia":
            record["generated_program"] = self.require_core_ir()
        self.report["builds"][arm] = record
        profiles = self.out / (label + "_ir_profiles")
        profiles.mkdir()
        instrumented = self.out / (label + "_ir_instrumented.so")
        self.irpgo_build(label, instrumented, ["-fprofile-generate"], "ir_profile_build")
        record["instrumented_image"] = identity(instrumented)
        self.runtime_images[str(instrumented)] = identity(instrumented)
        final = self.libraries[arm]
        self.libraries[arm] = instrumented
        try:
            record["training"] = [self.application(arm, algorithm, "training.bin",
                env=dict(os.environ, LLVM_PROFILE_FILE=str(profiles/(algorithm+"-%p.profraw"))),
                stage="ir_profile_training") for algorithm in self.protocol["algorithms"]]
        finally:
            self.libraries[arm] = final
        raw = sorted(profiles.glob("*.profraw"))
        require(len(raw) == len(self.protocol["algorithms"]) and all(p.stat().st_size for p in raw),
                "every training algorithm must produce a real nonempty profile")
        merged = profiles / "training.profdata"
        self.command([self.tools["profdata"], "merge", "-o", merged, *raw], "ir_profile_merge")
        shown = self.command([self.tools["profdata"], "show", "--all-functions", "--counts", merged],
                             "ir_profile_inspection")["stdout"]
        inspection = profiles / "profile-counters.txt"
        inspection.write_text(shown)
        counters = inspect_ir_counters(shown)
        use_flags = ["-fprofile-use=" + str(merged), "-Werror=profile-instr-out-of-date",
                     "-Werror=profile-instr-unprofiled"]
        self.irpgo_build(label, final, use_flags, "ir_profile_use_build")
        record.update(profiles=[identity(p) for p in raw], merged_profile=identity(merged),
                      counter_inspection=identity(inspection), use_flags=use_flags, **counters)
        if label == "hia":
            record["binary_inventory"] = inspect_owned_shared_elf(
                final.read_bytes(), emit_program_llvm(self.core).exports)
            record["default_backend_receipt"] = False
            record["backend_refinement_proved"] = False
        record["wall_ns"] = time.perf_counter_ns()-begin

    def resources(self):
        super().resources()
        # Recompile the same IR/profile to an object so real malloc/calloc/free
        # refusal can be injected at all three allocation positions. These are
        # extra observations of the PGO lowering, not a new owner policy or
        # an injection into the exact shared object used by performance runs.
        obj = self.out / "resource_hia_irpgo.o"
        profile = self.report["builds"]["hia_native_irpgo"]
        generated = self.require_core_ir()
        self.build_native_ir(obj, profile["use_flags"], "ir_pgo_resource_object", object_file=True)
        exe = self.out / "resource_hia_irpgo"
        self.command([self.tools["clang"], "-O3", "-march=native", "-flto=full", "-fuse-ld="+self.tools["linker"],
                      "-std=c11", "-fno-builtin", "-DENTRY="+ENTRY,
                      self.out/"resource_harness.c", obj, "-Wl,--wrap=malloc",
                      "-Wl,--wrap=calloc", "-Wl,--wrap=free", "-o", exe], "ir_pgo_resource_link")
        for case in self.report["resource_cases"]:
            observed = json.loads(self.command([exe, *case["arguments"], case["refuse_at"]],
                                              "ir_pgo_resource_execution")["stdout"])
            case["native"]["hia_irpgo"] = observed
            stats = case["vm"]["resources"]
            expected = dict(result=case["vm"]["result"], attempts=stats["allocation_attempts"],
                            allocations=stats["allocations"], frees=stats["frees"], live=0)
            require(observed == expected, "IR PGO changed allocation/refusal/cleanup semantics")
        self.report["irpgo_resource_artifacts"] = [identity(obj), identity(exe)]
        self.report["irpgo_resource_scope"] = {"generated_program": generated,
            "optimization": "O3, full LTO, native CPU; same LLVM/profile, separate observer binary",
            "performance_dso_injected": False}

    def verify_artifacts(self):
        super().verify_artifacts()
        retained = list(self.report.get("irpgo_resource_artifacts", []))
        for arm in ("hia_native_irpgo", "c_native_irpgo", "cpp_native_irpgo"):
            record = self.report["builds"][arm]
            retained.extend(record["profiles"])
            retained.extend(record[key] for key in ("merged_profile", "counter_inspection", "instrumented_image"))
        for observed in retained:
            require(identity(observed["path"]) == observed, "IR PGO evidence drift")

    def measure(self):
        super().measure()
        self.report["selected_hia_arm"] = self.performance_arm
        self.report["performance_scope"] = "descriptive shared host, no significance or universal dominance claim"
        for row in self.report["summary"].values():
            hia = row["arms"][self.performance_arm]
            strong = row["arms"][row["fastest_strong_reference"]]
            row["hia_rss_ratio"] = hia["child_wait4_peak_rss_kib_median"] / strong["child_wait4_peak_rss_kib_median"]
        self.report["performance_and_rss_gate"] = self.report["performance_advantage_gate"] and all(
            row["hia_rss_ratio"] <= 1 for row in self.report["summary"].values())


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--prepare-only", action="store_true")
    for name, default in (("clang", os.environ.get("CLANG", "clang")),
            ("clangxx", os.environ.get("CLANGXX", "clang++")), ("rustc", os.environ.get("RUSTC", "rustc")),
            ("profdata", "llvm-profdata"), ("linker", "ld.lld")):
        parser.add_argument("--"+name, default=default)
    args = parser.parse_args(argv)
    report = IRPGOTrial(args.output, clang=args.clang, clangxx=args.clangxx, rustc=args.rustc,
                       profdata=args.profdata, linker=args.linker).run(prepare_only=args.prepare_only)
    print(json.dumps({key: report.get(key) for key in ("schema", "ok", "status", "error",
          "performance_advantage_gate", "performance_and_rss_gate")}, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
