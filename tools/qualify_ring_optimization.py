#!/usr/bin/env python3
"""Frozen new-trace comparison against strong static C implementations.

This measures a newly generated Hepta/Rust implementation of a real upstream
module. It does not ascribe this backend's behavior or cost to standalone HIA.
"""
from __future__ import annotations

import argparse
import json
import math
import os
from pathlib import Path
import platform
import random
import re
import shutil
import statistics
import struct
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from hepta.c_contracts import decode_contracts
from hepta.c_migrate import migrate_c_project
from tools.qualify_c_ring_buffer import FLAGS, QualificationEvidence, checkpoint, run_sequences
from tools.qualify_ring_maintenance import (
    CONTRACT, SUPERVISOR_SOURCE, digest, identity, materialize, quantile, require,
    source_bindings as maintenance_bindings, verify_committed_sources, verify_upstream,
)

PROTOCOL_PATH = ROOT / "experiments/ring_optimization/PROTOCOL_20261030.json"
HOST_SOURCE = ROOT / "tools/fixtures/ring_optimization_host.c"
SYMBOLS = ("init", "queue", "queue_arr", "dequeue", "dequeue_arr", "peek", "is_empty", "is_full", "num_items")


def source_bindings():
    result = maintenance_bindings()
    paths = [Path(__file__), PROTOCOL_PATH, HOST_SOURCE]
    for path in paths:
        result[str(path.relative_to(ROOT))] = digest(path)
    return result


def inspect_ir_counters(shown, entry):
    """Require the named actual IR profile, not a nonempty profile filename."""
    starts = list(re.finditer(r"^  " + re.escape(entry) + r":$", shown, re.M))
    require(len(starts) == 1, "one exact function profile required")
    section = re.split(r"(?m)^  \S[^\r\n]*:$|^Instrumentation level:", shown[starts[0].end():], maxsplit=1)[0]
    sizes = re.findall(r"^    Counters: ([0-9]{1,10})$", section, re.M)
    lists = re.findall(r"^    Block counts: (\[[^\r\n]*\])$", section, re.M)
    require(len(sizes) == len(lists) == 1, "missing actual IR counter list")
    counts = json.loads(lists[0])
    require(type(counts) is list and len(counts) == int(sizes[0])
            and all(type(x) is int and 0 <= x < 2**64 for x in counts) and any(counts), "invalid actual IR counter inventory")
    total = re.findall(r"^Total count: ([0-9]{1,30})$", shown, re.M)
    functions = re.findall(r"^Total functions: ([0-9]{1,10})$", shown, re.M)
    require(re.search(r"^Instrumentation level: IR(?:\s|$)", shown, re.M) is not None
            and len(total) == len(functions) == 1 and int(total[0]) > 0 and int(functions[0]) > 0, "actual IR instrumentation required")
    return {"entry_function": entry, "block_counts": counts, "profiled_functions": int(functions[0]),
            "total_profile_count": int(total[0]), "interpretation": "block counters; not an inferred function entry count"}


def write_trace(path, protocol, profile, seed):
    require(profile in protocol["profiles"], "unregistered trace profile")
    randomizer = random.Random(seed + protocol["profiles"].index(profile))
    ranges = {"small": (0, 8), "burst": (32, 128), "near_capacity": (128, 256)}
    low, high = ranges[profile]
    payload = bytearray(b"HRBT0001" + struct.pack("<I", protocol["records_per_trace"]))
    total_bytes = checksum = 0
    for _ in range(protocol["records_per_trace"]):
        count = randomizer.randrange(low, high)
        data = randomizer.randbytes(256)
        payload.extend(bytes([count]) + data)
        total_bytes += count
        checksum += sum(data[:count])
    with path.open("xb") as stream:
        stream.write(payload)
    return {**identity(path), "profile": profile, "seed": seed,
            "records": protocol["records_per_trace"], "one_pass_bytes": total_bytes,
            "one_pass_checksum": checksum}


def validate_observation(value, trace, repeats):
    require(value.get("records") == trace["records"] and value.get("repeats") == repeats
            and value.get("transactions") == trace["records"] * repeats, "missing trace work")
    require(value.get("bytes") == trace["one_pass_bytes"] * repeats
            and value.get("checksum") == trace["one_pass_checksum"] * repeats, "trace output oracle mismatch")
    batches = value.get("batch_ns")
    require(type(batches) is list and len(batches) == trace["records"] * repeats // 128
            and all(type(x) is int and x > 0 for x in batches), "missing batch observations")
    for key in ("setup_ns", "run_ns", "cleanup_ns", "total_main_ns"):
        require(type(value.get(key)) is int and value[key] > 0, "invalid native phase timing")
    require(value["setup_ns"] + value["run_ns"] + value["cleanup_ns"] == value["total_main_ns"], "native phase ledger mismatch")
    return value


def summarize(samples, protocol, elapsed_seconds):
    expected_keys = {(group, profile, arm) for group in range(protocol["paired_groups"])
                     for profile in protocol["profiles"] for arm in protocol["arms"]}
    keys = [(x["group"], x["profile"], x["arm"]) for x in samples]
    require(len(keys) == len(expected_keys) and set(keys) == expected_keys, "missing or duplicate paired observation")
    require(len({x["process_index"] for x in samples}) == len(samples), "one process cannot count as multiple observations")
    require(all(type(x["process_seconds"]) in (int, float) and math.isfinite(x["process_seconds"])
                and x["process_seconds"] > 0 for x in samples), "invalid process timing")
    summaries = []
    for profile in protocol["profiles"]:
        for arm in protocol["arms"]:
            rows = [x for x in samples if x["profile"] == profile and x["arm"] == arm]
            require(len(rows) == protocol["paired_groups"], "incomplete paired campaign")
            latencies = [t for row in rows for t in row["observation"]["batch_ns"]]
            summaries.append({"profile": profile, "arm": arm, "processes": len(rows),
                "median_process_seconds": statistics.median(x["process_seconds"] for x in rows),
                "median_native_run_ns": statistics.median(x["observation"]["run_ns"] for x in rows),
                "batch_p99_ns": quantile(latencies, 99), "batch_samples": len(latencies),
                "median_peak_rss_kib": statistics.median(x["memory"]["child_wait4_ru_maxrss_kib"] for x in rows),
                "peak_rss_kib_samples": [x["memory"]["child_wait4_ru_maxrss_kib"] for x in rows]})
    scores = {arm: sum(x["median_process_seconds"] for x in summaries if x["arm"] == arm)
              for arm in protocol["strong_static_baselines"]}
    strongest = min(scores, key=lambda arm: (scores[arm], arm))
    by_key = {(x["group"], x["profile"], x["arm"]): x for x in samples}
    differences = []
    for group in range(protocol["paired_groups"]):
        for profile in protocol["profiles"]:
            baseline = by_key[group, profile, strongest]
            candidate = by_key[group, profile, "hepta_rust_native_lto"]
            differences.append({"group": group, "profile": profile,
                "baseline_process_index": baseline["process_index"], "candidate_process_index": candidate["process_index"],
                "seconds_saved": baseline["process_seconds"] - candidate["process_seconds"]})
    sample_seconds = sum(x["process_seconds"] for x in samples)
    overhead = elapsed_seconds - sample_seconds
    require(overhead >= 0, "overlapping campaign ledger")
    gross = sum(x["seconds_saved"] for x in differences)
    return summaries, {"selected_strong_static_arm": strongest, "selection_scores_seconds": scores,
        "observed_candidate_transactions": protocol["records_per_trace"] * protocol["held_out_repeats"]
            * len(protocol["profiles"]) * protocol["paired_groups"],
        "paired_process_wall_differences": differences, "gross_observed_seconds_saved": gross,
        "campaign_wall_seconds_until_result_publication": elapsed_seconds,
        "all_holdout_process_wall_seconds": sample_seconds, "charged_non_holdout_campaign_seconds": overhead,
        "net_benefit_upper_bound_seconds": gross - overhead,
        "cost_accounting": "All preparation, training, baseline builds, checking, host preparation, comparison, observation and listed scratch cleanup charged once; each sample includes actual load/free/dlclose",
        "unmeasured_additional_costs": {"human_hours": None, "end_to_end_formal_refinement_proof": None,
            "final_result_publication_and_archive_after_timer": None},
        "future_amortization_counted": False}


class OptimizationTrial:
    def __init__(self, evidence, report, *, clang, rustc, profdata, linker, source_sha):
        self.evidence, self.report = evidence, report
        self.protocol = report["protocol"]
        self.source_sha = source_sha
        self.work = evidence.retained / "workspace"
        self.work.mkdir()
        # Driver basename selects the LLD flavor (ld.lld vs lld); retain the
        # observed invocation path while hashing its actual executable bytes.
        self.tools = {name: str(Path(shutil.which(path) or path).absolute()) for name, path in
            {"clang": clang, "rustc": rustc, "profdata": profdata, "linker": linker, "gcc": "gcc"}.items()}
        self.host, self.supervisor = self.work / "trace-host", self.work / "rss-supervisor"
        self.libraries = {arm: self.work / (arm + ".so") for arm in self.protocol["arms"]}
        self.serial = 0

    def command(self, argv, role, **kwargs):
        return self.evidence.command([os.fspath(x) for x in argv], role=role, **kwargs)

    def stage(self, stage):
        checkpoint(self.report, self.evidence, stage)

    def compile_c(self, output, arm, extra=()):
        compiler = self.tools["gcc" if arm == "gcc_native_lto" else "clang"]
        flags = [*FLAGS, "-O3", "-march=native", "-flto", "-fPIC", "-shared", "-fno-semantic-interposition"]
        if arm != "gcc_native_lto":
            flags += ["-fuse-ld=" + self.tools["linker"]]
        return self.command([compiler, *flags, *extra, self.work / "project/ringbuffer.c", "-o", output], "compile." + arm, timeout=120)

    def application(self, library, trace, repeats, role, *, env=None):
        receipt = self.work / f"rss-{self.serial:04d}.json"
        self.serial += 1
        argv = [str(self.supervisor), str(receipt), str(self.host), str(library), trace["path"], str(repeats)]
        require(identity(trace["path"]) == {k: trace[k] for k in ("path", "bytes", "sha256")}, "trace identity drift")
        process, index = self.evidence.process(argv, role=role, capture_output=True, timeout=120, require_success=True, env=env)
        observed = validate_observation(json.loads(process.stdout), trace, repeats)
        memory = json.loads(receipt.read_text())
        require(memory["child_exit_code"] == 0 and memory["child_signal"] == 0 and memory["child_wait4_ru_maxrss_kib"] > 0, "native sample failed")
        return {"process_index": index, "process_seconds": self.evidence._process_elapsed_seconds[index],
                "observation": observed, "memory": memory, "memory_receipt": identity(receipt),
                "environment_overrides": {"LLVM_PROFILE_FILE": env["LLVM_PROFILE_FILE"]} if env else {}}

    def run(self):
        self.report["source_bindings"] = source_bindings()
        head = self.command(["git", "rev-parse", "HEAD"], "source.head", cwd=ROOT)["stdout"].strip()
        self.report["git"] = {"head": head, "status": self.command(["git", "status", "--short"], "source.status", cwd=ROOT)["stdout"]}
        require(self.source_sha is None or self.source_sha == head, "--source-sha mismatch")
        if self.source_sha is not None:
            self.report["committed_source_inventory"] = verify_committed_sources(self.command, self.report["source_bindings"], self.source_sha)
        require(sys.platform == "linux" and platform.machine() == "x86_64", "unqualified host")
        self.report["host"] = {"platform": platform.platform(), "machine": platform.machine(), "exclusive": False,
            "cpu_info_first_processor": Path("/proc/cpuinfo").read_text().split("\n\n", 1)[0]}
        self.report["tools"] = {name: {**identity(path), "version": self.command([path, "--version"], "tools." + name)["stdout"]}
                                for name, path in self.tools.items()}
        version = verify_upstream()["versions"][1]
        materialize(version, self.work / "project")
        self.report["upstream"] = version
        self.stage("fresh_implementation_migration_and_native_checks")
        database = self.work / "compile_commands.json"
        database.write_text(json.dumps([{"directory": str(self.work / "project"), "file": "ringbuffer.c",
            "arguments": [self.tools["clang"], *FLAGS, "-O2", "-c", "ringbuffer.c"]}], indent=2) + "\n")
        begin = time.perf_counter_ns()
        with self.evidence.backend_processes("fresh_migration"):
            migration = migrate_c_project(database, self.work / "translation", contracts=decode_contracts(CONTRACT.read_bytes()),
                clang=self.tools["clang"], rustc=self.tools["rustc"], verify_native=True)
        self.report["migration"] = migration
        self.report["fresh_migration_wall_ns"] = time.perf_counter_ns() - begin
        require(migration["ok"] and migration["declaration_inventory_complete"]
                and migration["coverage"]["status_counts"]["function_converted"] == 9, "migration incomplete")
        self.stage("strong_static_and_candidate_builds")
        self.report["builds"] = {}
        for arm in ("clang_native_lto", "gcc_native_lto"):
            self.report["builds"][arm] = self.compile_c(self.libraries[arm], arm)
        generated = self.work / "translation/generated.rs"
        self.report["builds"]["hepta_rust_native_lto"] = self.command([self.tools["rustc"], generated,
            "--edition=2021", "--crate-name=hepta_ring_candidate", "--crate-type=cdylib", "-C", "opt-level=3",
            "-C", "overflow-checks=yes", "-C", "panic=abort", "-C", "codegen-units=1", "-C", "lto=fat",
            "-C", "target-cpu=native", "-C", "linker=" + self.tools["gcc"], "-o", self.libraries["hepta_rust_native_lto"]],
            "compile.hepta_rust_native_lto", timeout=120)
        self.report["host_build"] = self.command([self.tools["gcc"], "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
            "-I" + str(self.work / "project"), HOST_SOURCE, "-pthread", "-ldl", "-o", self.host], "host.build")
        self.report["supervisor_build"] = self.command([self.tools["gcc"], "-std=c11", "-O2", SUPERVISOR_SOURCE, "-o", self.supervisor], "supervisor.build")
        self.stage("separate_irpgo_training_and_profile_validation")
        profiles = self.work / "profiles"
        profiles.mkdir()
        instrumented = self.work / "instrumented.so"
        self.report["instrumented_build"] = self.compile_c(instrumented, "clang_native_irpgo_lto", ["-fprofile-generate"])
        self.report["training"] = []
        for profile in self.protocol["profiles"]:
            trace = write_trace(self.work / ("training-" + profile + ".bin"), self.protocol, profile, self.protocol["training_seed"])
            observed = self.application(instrumented, trace, self.protocol["training_repeats"], "training." + profile,
                env=dict(os.environ, LLVM_PROFILE_FILE=str(profiles / (profile + "-%p.profraw"))))
            self.report["training"].append({"trace": trace, **observed})
        raw = sorted(profiles.glob("*.profraw"))
        require(len(raw) == len(self.protocol["profiles"]) and all(x.stat().st_size > 0 for x in raw), "missing actual training profiles")
        merged = profiles / "training.profdata"
        self.report["profile_merge"] = self.command([self.tools["profdata"], "merge", "-o", merged, *raw], "profile.merge")
        shown = self.command([self.tools["profdata"], "show", "--all-functions", "--counts", merged], "profile.inspect")
        self.report["profile_counters"] = [inspect_ir_counters(shown["stdout"], "ring_buffer_" + name) for name in SYMBOLS]
        self.report["profile_artifacts"] = [identity(x) for x in [*raw, merged]]
        self.report["builds"]["clang_native_irpgo_lto"] = self.compile_c(self.libraries["clang_native_irpgo_lto"], "clang_native_irpgo_lto",
            ["-fprofile-use=" + str(merged), "-Werror=profile-instr-out-of-date", "-Werror=profile-instr-unprofiled"])
        self.stage("finite_api_validation_before_unseen_trace_generation")
        self.report["validation"] = {}
        for arm in self.protocol["strong_static_baselines"]:
            self.report["validation"][arm] = run_sequences(self.libraries[arm], self.libraries["hepta_rust_native_lto"],
                seed=30192026, steps=256, evidence=self.evidence, run_name=arm)
        self.report["validation_scope"] = "Hepta checker, Rust compiler and finite full-state API differentials; no end-to-end equivalence theorem"
        bindings = {str(path): identity(path) for path in [*self.libraries.values(), self.host, self.supervisor]}
        self.report["frozen_final_artifacts_before_holdout"] = bindings
        self.stage("new_held_out_trace_generation_after_all_candidates_frozen")
        traces = {profile: write_trace(self.work / ("heldout-" + profile + ".bin"), self.protocol, profile, self.protocol["held_out_seed"])
                  for profile in self.protocol["profiles"]}
        self.report["held_out_traces"] = traces
        training_hashes = {x["trace"]["sha256"] for x in self.report["training"]}
        require(all(trace["sha256"] not in training_hashes for trace in traces.values()), "training/heldout collision")
        self.stage("frozen_paired_comparison")
        for group in range(self.protocol["paired_groups"]):
            for profile_index, profile in enumerate(self.protocol["profiles"]):
                arms = self.protocol["arms"]
                shift = (group + profile_index) % len(arms)
                order = arms[shift:] + arms[:shift]
                if group % 2:
                    order = list(reversed(order))
                for arm in order:
                    require(all(identity(path) == bound for path, bound in bindings.items()), "candidate/host artifact drift")
                    row = self.application(self.libraries[arm], traces[profile], self.protocol["held_out_repeats"], "holdout." + arm + "." + profile)
                    self.report["samples"].append({"group": group, "profile": profile, "arm": arm, **row})
        self.stage("selection_observation_and_scratch_cleanup")
        require(all(identity(path) == bound for path, bound in bindings.items()), "post-execution artifact drift")
        require(source_bindings() == self.report["source_bindings"], "qualification source changed during execution")
        cleanup = [instrumented, self.work / "translation/libtranslated.so", *raw]
        begin = time.perf_counter_ns()
        removed = [identity(path) for path in cleanup]
        for path in cleanup:
            path.unlink()
        self.report["scratch_cleanup"] = {"removed": removed, "wall_ns": time.perf_counter_ns() - begin,
            "retained_final_candidates_and_source_evidence": True}
        # Account once for every measured campaign operation before publication.
        elapsed = time.perf_counter() - self.evidence.started
        summary, ledger = summarize(self.report["samples"], self.protocol, elapsed)
        elapsed = time.perf_counter() - self.evidence.started
        ledger["campaign_wall_seconds_until_result_publication"] = elapsed
        ledger["charged_non_holdout_campaign_seconds"] = elapsed - ledger["all_holdout_process_wall_seconds"]
        ledger["net_benefit_upper_bound_seconds"] = ledger["gross_observed_seconds_saved"] - ledger["charged_non_holdout_campaign_seconds"]
        self.report["summary"], self.report["ledger"] = summary, ledger
        self.report["claims"]["strong_static_comparison_executed"] = True
        self.report["conclusion"] = ("No net benefit can be established: the observed finite-horizon upper bound is nonpositive"
            if ledger["net_benefit_upper_bound_seconds"] <= 0 else
            "Positive measured-scope upper bound only; omitted human/proof/publication costs prevent a completed all-cost net-benefit claim")
        self.report["ok"] = True
        self.stage("complete")
        return self.report


def qualify(output, *, clang, rustc, profdata, linker, source_sha=None):
    path = Path(output).absolute()
    path.parent.mkdir(parents=True, exist_ok=True)
    protocol = json.loads(PROTOCOL_PATH.read_text())
    with path.open("x", encoding="utf-8") as stream:
        evidence = QualificationEvidence(path, stream)
        report = {"schema": "hepta.ring-optimization.qualification.v1", "ok": False, "stage": "source_and_tool_identity",
            "protocol": protocol, "protocol_sha256": digest(PROTOCOL_PATH), "claims": dict(protocol["claims"]),
            "samples": [], "cost": {"automatic_tool_stages": [], "human_hours": None}}
        evidence.write(report)
        try:
            evidence.retained.mkdir()
            evidence.retained_owned = True
            return OptimizationTrial(evidence, report, clang=clang, rustc=rustc, profdata=profdata, linker=linker, source_sha=source_sha).run()
        except BaseException as error:
            report.update(ok=False, error={"type": type(error).__name__, "message": str(error)}, failed_stage=report["stage"], claims=dict(protocol["claims"]))
            checkpoint(report, evidence, "failed")
            raise


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--clang", default="clang-20")
    parser.add_argument("--rustc", required=True)
    parser.add_argument("--profdata", default="llvm-profdata-20")
    parser.add_argument("--linker", default="ld.lld-20")
    parser.add_argument("--source-sha")
    args = parser.parse_args()
    try:
        result = qualify(args.output, clang=args.clang, rustc=args.rustc, profdata=args.profdata, linker=args.linker, source_sha=args.source_sha)
        print(json.dumps({"ok": result["ok"], "conclusion": result["conclusion"], "ledger": result["ledger"], "summary": result["summary"]}, indent=2))
        return 0
    except Exception as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
