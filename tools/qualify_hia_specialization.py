#!/usr/bin/env python3
"""Frozen paired native experiment for guarded scalar specialization.

This is a deliberately constructed research kernel, not a production workload.
All arms pay the same actual shared training work and execute fresh native
publication/holdout calls. The original ranking NDU is built and called; its
cold build is separately charged to its arm. No failed or negative rows vanish.
"""
from __future__ import annotations

import argparse
import copy
from datetime import datetime, timezone
from hashlib import sha256
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

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

from hepta.hia_background_optimizer import BackgroundOptimizer
from hepta.hia_multiversion import PublicationCancellation, ScalarMultiversionRuntime
from hepta.hia_native_differential import _pin_native_artifact
from hepta.hia_program import SCHEMA, verify_program
from hepta.hia_program_llvm import TARGET, build_program_native
from hepta.hia_specialization import propose_guarded_specializations
from hepta.hia_translation_validation import validate_translation
from tools.build_hia_ndu_bridge import build as build_ndu
from tools.qualify_hia_ndu_search import _schedule, _summary

MASK = (1 << 32) - 1
OFFSETS = (1, 3, 5, 7, 11, 13, 17, 19)
PROTOCOL = {
    "schema": "hepta.hia.guarded-specialization-protocol.v1",
    "workload": "constructed_u32_eight_round_add_xor",
    "production_workload": False, "function": "calculate", "round_offsets": list(OFFSETS),
    "assumptions": [{"parameter": "mask", "value": value} for value in (0, MASK)],
    "profiles": ["hot_zero", "hot_ones", "mixed"],
    "case_count": 64, "hot_cases": 62, "training_seed": 20261027,
    "holdout_seed": 20261028, "training_trials": 5, "training_calls": 500000,
    "warmup_calls": 20000, "holdout_calls": 250000000, "repetitions": 2,
    "arms": ["fixed_stop", "fixed_zero", "fixed_ones", "fixed_selected", "light", "ndu"],
    "resource_cap_ns": 10000000000, "proof_timeout_ms": 5000,
    "target": TARGET, "measurement_profile": "sealed-native-u32-u32-loop-v1",
    "uncertainty": "ceil(max absolute batch deviation from median / calls), minimum 1 ns; not a confidence interval",
    "order": "rotating order, reversed on odd rounds; profiles rotate with repetition",
    "shared_training": "all arms receive and pay the same full observed candidate/proof/build/training corpus per episode",
    "control": "fixed_selected minimizes summed training upper costs across all profiles; light minimizes current-profile upper cost",
    "publication": "fresh all-input proof, real native build/probe, generation-and-epoch compare-and-swap, actual preparation budget",
    "costs": "episode wall through runtime cleanup plus measured shared setup; NDU additionally reports fresh cold bridge build amortized over its frozen episodes",
    "primary_metric": "paired cold-amortized full-cost saving of NDU versus every declared fixed control and light; median over six matched profile/repetition pairs",
    "no_increment_threshold": {"absolute_ns": 1000000, "relative_control_median": 0.01},
    "descriptive_increment_rule": "saving must exceed the threshold versus every control and have positive median saving in every profile; no statistical inference",
    "direct_deployment_control": "fixed_stop observed episode wall without shared corpus charge; same native baseline preparation, input checks, holdout calls and cleanup",
    "shared_cost_denominator": "full shared work is conservatively charged once per standalone arm episode (denominator 1); it physically executes once per campaign",
    "ndu_cold_build_denominator": 6,
    "cold_build_admission": "publication gate uses installed-bridge warm cost; cold cost is additionally reported, including losses; warm admission is not a claim of cold-deployment gain",
    "cost_exclusions": "already installed Python/Z3/Clang/Rust and dependency download/cache creation; experiment source authoring, prior development attempts and final evidence serialization are not deployment work",
    "failures": "retain every attempted row; no retries, sample dropping or parameter tuning after freeze",
    "claims": {"online_learning": False, "global_optimality": False, "general_ndu_advantage": False},
}
INPUTS = (
    "hepta/hia_specialization.py", "hepta/hia_program.py", "hepta/hia_program_runtime.py",
    "hepta/hia_program_llvm.py", "hepta/hia_translation_validation.py", "hepta/hia_ndu_optimizer.py",
    "hepta/hia_multiversion.py", "hepta/hia_background_optimizer.py", "hepta/hia_native_differential.py",
    "hepta/elf_shared_abi.py", "hepta/clang_capture.py", "hepta/native_mapping_identity.py", "tools/qualify_hia_specialization.py",
    "tools/qualify_hia_ndu_search.py", "tools/build_hia_ndu_bridge.py",
    "rust/hia-ndu-bridge/upstream.json", "rust/hia-ndu-bridge/src/main.rs",
    "rust/hia-ndu-bridge/Cargo.toml", "rust/hia-ndu-bridge/Cargo.lock",
)

DRIVER = r'''#define _POSIX_C_SOURCE 200809L
#include <dlfcn.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <time.h>
typedef uint32_t (*kernel_t)(uint32_t, uint32_t);
struct input { uint32_t x, mask, expected; };
static uint64_t now(clockid_t clock) {
    struct timespec t;
    if (clock_gettime(clock, &t)) exit(81);
    return (uint64_t)t.tv_sec * UINT64_C(1000000000) + (uint64_t)t.tv_nsec;
}
int main(int argc, char **argv) {
    if (argc != 5) return 82;
    uint64_t calls = strtoull(argv[3], NULL, 10), warmup = strtoull(argv[4], NULL, 10);
    if (!calls || calls > UINT64_C(250000000) || warmup > UINT64_C(20000)) return 83;
    FILE *file = fopen(argv[2], "r");
    struct input inputs[64];
    if (!file) return 84;
    for (int n = 0; n != 64; ++n)
        if (fscanf(file, "%" SCNu32 " %" SCNu32 " %" SCNu32,
                   &inputs[n].x, &inputs[n].mask, &inputs[n].expected) != 3) return 85;
    if (fclose(file)) return 86;
    void *library = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!library) { fprintf(stderr, "%s\n", dlerror()); return 87; }
    kernel_t kernel = (kernel_t)dlsym(library, "calculate");
    if (!kernel) return 88;
    for (int n = 0; n != 64; ++n)
        if (kernel(inputs[n].x, inputs[n].mask) != inputs[n].expected) return 89;
    volatile uint64_t warm_checksum = 0;
    for (uint64_t n = 0; n != warmup; ++n)
        warm_checksum += kernel(inputs[n & 63].x, inputs[n & 63].mask);
    (void)warm_checksum;
    struct rusage before, after;
    if (getrusage(RUSAGE_SELF, &before)) return 90;
    uint64_t checksum = 0, cpu = now(CLOCK_PROCESS_CPUTIME_ID), start = now(CLOCK_MONOTONIC);
    for (uint64_t n = 0; n != calls; ++n)
        checksum += kernel(inputs[n & 63].x, inputs[n & 63].mask);
    uint64_t elapsed = now(CLOCK_MONOTONIC) - start, cpu_ns = now(CLOCK_PROCESS_CPUTIME_ID) - cpu;
    if (getrusage(RUSAGE_SELF, &after)) return 91;
    printf("{\"elapsed_ns\":%" PRIu64 ",\"process_cpu_ns\":%" PRIu64
           ",\"iterations\":%" PRIu64 ",\"checksum\":%" PRIu64
           ",\"voluntary_context_switches\":%ld,\"involuntary_context_switches\":%ld"
           ",\"minor_page_faults\":%ld,\"major_page_faults\":%ld}\n",
           elapsed, cpu_ns, calls, checksum, after.ru_nvcsw-before.ru_nvcsw,
           after.ru_nivcsw-before.ru_nivcsw, after.ru_minflt-before.ru_minflt,
           after.ru_majflt-before.ru_majflt);
    if (dlclose(library)) return 92;
    return 0;
}
'''


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(path):
    return sha256(Path(path).read_bytes()).hexdigest()


def require(condition, message):
    if not condition:
        raise RuntimeError("E_HIA_SPECIALIZATION_EXPERIMENT: " + message)


def workload():
    params = [{"name": "x", "type": "u32"}, {"name": "mask", "type": "u32"}]
    ops, previous = [], "x"
    for n, offset in enumerate(OFFSETS):
        ops.append({"op": "const", "args": [], "out": [{"name": f"c{n}", "type": "u32"}],
                    "attrs": {"value": offset}})
        for op, args, out in (("int.add.wrap", [previous, f"c{n}"], f"a{n}"),
                              ("bit.xor", [f"a{n}", "mask"], f"r{n}")):
            ops.append({"op": op, "args": args, "out": [{"name": out, "type": "u32"}], "attrs": {}})
        previous = f"r{n}"
    return {"schema": SCHEMA, "module": "guarded_specialization_research", "functions": [{
        "name": "calculate", "params": params, "returns": ["u32"], "effects": [],
        "entry": "entry", "blocks": [{"id": "entry", "params": params, "ops": ops,
            "term": {"op": "ret", "values": [previous]}}]}]}


def oracle(x, mask):
    # Independently written numeric specification, without interpreting HIA.
    for increment in (1, 3, 5, 7, 11, 13, 17, 19):
        x = ((x + increment) % (1 << 32)) ^ mask
    return x


def cases(profile, seed):
    rng = random.Random(seed + PROTOCOL["profiles"].index(profile))
    rows = []
    for n in range(PROTOCOL["case_count"]):
        x = rng.getrandbits(32)
        mask = rng.getrandbits(32)
        if n < PROTOCOL["hot_cases"] and profile != "mixed":
            mask = 0 if profile == "hot_zero" else MASK
        rows.append([x, mask, oracle(x, mask)])
    return rows


def checksum(rows, calls):
    whole, tail = divmod(calls, len(rows))
    return (whole * sum(row[2] for row in rows) + sum(row[2] for row in rows[:tail])) % (1 << 64)


def sample(driver, library, input_file, rows, calls, *, hashes):
    """Pin all three consumed files, then execute the exact C ABI in a child."""
    started, descriptors = time.perf_counter_ns(), []
    result = {"status": "failed", "iterations": calls, "expected_checksum": checksum(rows, calls),
              "input_sha256": hashes[2], "artifact_sha256": hashes[1], "driver_sha256": hashes[0]}
    try:
        for path, expected in zip((driver, library, input_file), hashes):
            data, identity, descriptor = _pin_native_artifact(Path(path))
            descriptors.append(descriptor)
            require(sha256(data).hexdigest() == expected, "actual sealed input differs from bound bytes")
        command = [f"/proc/self/fd/{descriptors[0]}", f"/proc/self/fd/{descriptors[1]}",
                   f"/proc/self/fd/{descriptors[2]}", str(calls), str(PROTOCOL["warmup_calls"])]
        result.update(argv=command, source_paths=[str(driver), str(library), str(input_file)])
        run = subprocess.run(command,
                             pass_fds=tuple(descriptors), capture_output=True, timeout=20)
        result.update(returncode=run.returncode, stdout=run.stdout.decode(errors="replace"),
                      stderr=run.stderr.decode(errors="replace"), consumed_files_sealed=True)
        require(run.returncode == 0, "native child rejected an input, output or artifact")
        observed = json.loads(run.stdout)
        require(observed.get("iterations") == calls and observed.get("checksum") == result["expected_checksum"],
                "native checksum does not match the independent numeric specification")
        require(all(type(observed.get(k)) is int and observed[k] > 0 for k in ("elapsed_ns", "process_cpu_ns")),
                "native timing is missing or invalid")
        result.update(observed, status="observed")
    except Exception as error:
        result["error"] = f"{type(error).__name__}: {error}"
    finally:
        for descriptor in descriptors:
            os.close(descriptor)
    result["outer_wall_ns"] = time.perf_counter_ns() - started
    return result


def measure(ledger, name, operation):
    started = time.perf_counter_ns()
    row = {"stage": name, "status": "failed"}
    ledger.append(row)
    try:
        value = operation()
        row["status"] = "completed"
        return value
    finally:
        row["wall_ns"] = time.perf_counter_ns() - started


def episode(arm, profile, repetition, *, directory, baseline, candidates, observations,
            fixed_selected, bridge, clang, driver, holdout, shared_ns):
    started = time.perf_counter_ns()
    result = {"arm": arm, "profile": profile, "repetition": repetition, "status": "failed",
              "selected_id": "abstain", "shared_training_charged_ns": shared_ns}
    try:
        with ScalarMultiversionRuntime(baseline, directory, clang=clang,
                                      validation_timeout_ms=PROTOCOL["proof_timeout_ms"]) as runtime:
            result["baseline_native_prepare_wall_ns"] = time.perf_counter_ns() - started
            with runtime.lease() as original:
                selection_started = time.perf_counter_ns()
                if arm == "ndu":
                    objective = {"expected_calls": PROTOCOL["holdout_calls"],
                        "resource_cap_ns": PROTOCOL["resource_cap_ns"], "target": TARGET,
                        "measurement_profile": PROTOCOL["measurement_profile"]}
                    with BackgroundOptimizer(runtime, baseline, function="calculate", bridge=bridge,
                                             timeout_ms=PROTOCOL["proof_timeout_ms"]) as optimizer:
                        decision = optimizer.submit(candidates, observations, objective).result(timeout=25)
                    result["decision"] = decision
                    if decision["status"] == "published":
                        result["selected_id"] = decision["selected_id"]
                else:
                    ids = [row["id"] for row in candidates]
                    proposed = {"fixed_stop": "abstain", "fixed_zero": ids[0], "fixed_ones": ids[1],
                                "fixed_selected": fixed_selected}.get(arm)
                    if arm == "light":
                        proposed = min(observations, key=lambda cid: (
                            observations[cid]["runtime_ns"] + observations[cid]["uncertainty_ns"], cid))
                    result["decision"] = {"proposed_id": proposed, "status": "abstained"}
                    if proposed != "abstain":
                        lower = max(0, observations["abstain"]["runtime_ns"] - observations["abstain"]["uncertainty_ns"])
                        upper = observations[proposed]["runtime_ns"] + observations[proposed]["uncertainty_ns"]
                        spent = shared_ns + time.perf_counter_ns() - selection_started
                        budget = min((lower - upper) * PROTOCOL["holdout_calls"] - spent - 1,
                                     PROTOCOL["resource_cap_ns"] - spent)
                        if budget > 0:
                            candidate = next(row["program"] for row in candidates if row["id"] == proposed)
                            try:
                                result["decision"]["publication"] = runtime.publish_if_current(candidate, 0,
                                    expected_epoch=0, max_prepare_ns=budget,
                                    cancellation=PublicationCancellation())
                                result["decision"]["status"] = "published"
                                result["selected_id"] = proposed
                            except Exception as error:
                                result["decision"].update(status="rejected", error=f"{type(error).__name__}: {error}")
                        else:
                            result["decision"]["reason"] = "no_compile_inclusive_robust_margin"
                result["selection_and_publication_wall_ns"] = time.perf_counter_ns() - selection_started
                snapshot = runtime.snapshot()
                selected = next(row for row in snapshot["generations"] if row["generation"] == snapshot["current_generation"])
                result["selected_generation"] = selected
                with runtime.lease() as selected_lease:
                    checks_started = time.perf_counter_ns()
                    rows, path = holdout[profile]
                    for x, mask, expected in rows:
                        require(original.call("calculate", [x, mask]) == expected, "old generation lease changed")
                        require(selected_lease.call("calculate", [x, mask]) == expected, "selected native generation is wrong")
                    result["lease_observations_wall_ns"] = time.perf_counter_ns() - checks_started
                    # The benchmark re-pins exactly the bytes admitted by the runtime.
                    library = runtime._directory / f"generation-{selected['generation']}.so"
                    result["execution"] = sample(driver, library, path, rows, PROTOCOL["holdout_calls"],
                        hashes=(digest(driver), selected["artifact_sha256"], digest(path)))
                    require(result["execution"]["status"] == "observed", "holdout execution failed")
                    lifecycle_started = time.perf_counter_ns()
                    if selected["generation"] != 0:
                        runtime.rollback()
                        require(runtime.snapshot()["current_generation"] == 0, "rollback did not restore baseline")
                        x, mask, expected = rows[-1]
                        require(selected_lease.call("calculate", [x, mask]) == expected, "rollback invalidated a live lease")
                    result["lifecycle"] = {"old_lease_observations": len(rows), "selected_lease_observations": len(rows),
                        "rollback_executed": selected["generation"] != 0,
                        "pinned_selected_lease_survived_rollback": selected["generation"] != 0}
                    result["post_execution_lifecycle_wall_ns"] = time.perf_counter_ns() - lifecycle_started
        result["status"] = "completed"
    except Exception as error:
        result["error"] = f"{type(error).__name__}: {error}"
    result["episode_wall_ns"] = time.perf_counter_ns() - started
    result["warm_full_cost_ns"] = shared_ns + result["episode_wall_ns"]
    result["remaining_episode_overhead_ns"] = result["episode_wall_ns"] - sum(result.get(key, 0)
        for key in ("baseline_native_prepare_wall_ns", "selection_and_publication_wall_ns",
                    "lease_observations_wall_ns", "post_execution_lifecycle_wall_ns")) - result.get("execution", {}).get("outer_wall_ns", 0)
    return result


def run(directory, *, clang, cargo, upstream):
    directory = Path(directory).resolve()
    directory.mkdir(mode=0o700)
    report = {"schema": "hepta.hia.guarded-specialization-experiment.v1", "protocol": copy.deepcopy(PROTOCOL),
        "utc": datetime.now(timezone.utc).isoformat(), "host": {"system": platform.system(),
        "machine": platform.machine(), "python": sys.version}, "qualified": False,
        "source_sha256": {name: digest(ROOT / name) for name in INPUTS},
        "claims": {"backend_refinement_proved": False, "global_optimality_established": False,
                   "ndu_incremental_advantage_established": False, "production_workload_qualified": False}}
    started = time.perf_counter_ns()
    report["source_commit"] = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    report["tracked_worktree_status"] = subprocess.check_output(
        ["git", "status", "--porcelain", "--untracked-files=no"], cwd=ROOT, text=True)
    freeze_started = time.perf_counter_ns()
    report["frozen_inputs"] = {split: {profile: cases(profile, seed) for profile in PROTOCOL["profiles"]}
        for split, seed in (("training", PROTOCOL["training_seed"]), ("holdout", PROTOCOL["holdout_seed"]))}
    report["input_freeze_wall_ns"] = time.perf_counter_ns() - freeze_started
    (directory / "PROTOCOL.json").write_bytes(wire(report) + b"\n")
    ledger = report["shared_ledger"] = []
    try:
        # Fresh target directory: dependency cache is allowed; executable reuse is not.
        prior_target = os.environ.get("CARGO_TARGET_DIR")
        os.environ["CARGO_TARGET_DIR"] = str(directory / "ndu-target")
        bridge_started = time.perf_counter_ns()
        report["ndu_cold_build_argv"] = [cargo, "build", "--manifest-path", str(directory / "ndu-build/Cargo.toml"),
                                         "-p", "hia-ndu-bridge", "--locked"]
        try:
            build_ndu(upstream, directory / "ndu-build", cargo=cargo)
        finally:
            report["ndu_cold_build_wall_ns"] = time.perf_counter_ns() - bridge_started
            if prior_target is None:
                os.environ.pop("CARGO_TARGET_DIR", None)
            else:
                os.environ["CARGO_TARGET_DIR"] = prior_target
        bridge = {"binary": directory / "ndu-target/debug/hia-ndu-bridge",
                  "build_receipt": directory / "ndu-build/build-receipt.json"}
        report["bridge"] = {name: {"path": str(path), "sha256": digest(path)} for name, path in bridge.items()}
        report["bridge_upstream"] = json.loads((ROOT / "rust/hia-ndu-bridge/upstream.json").read_text())
        report["recursive_ndu_used"] = False
        shared_started = time.perf_counter_ns()
        baseline = workload()
        candidates = measure(ledger, "proposals", lambda: propose_guarded_specializations(baseline,
            function="calculate", assumptions=PROTOCOL["assumptions"]))
        report.update(baseline=baseline, candidates=candidates)
        programs = {"abstain": baseline, **{row["id"]: row["program"] for row in candidates}}
        labels = list(programs)
        artifacts = report["native_builds"] = {}
        proofs = report["proofs"] = {}
        code = report["native_function_code"] = {}
        objdump = shutil.which("objdump")
        require(objdump is not None, "native disassembler is required")
        for label, program in programs.items():
            (directory / f"{label}.hia.json").write_bytes(wire(program) + b"\n")
            if label != "abstain":
                proof = measure(ledger, "proof." + label, lambda p=program: validate_translation(
                    baseline, p, function="calculate", timeout_ms=PROTOCOL["proof_timeout_ms"]))
                proofs[label] = proof
                require(proof["status"] == "proved", "unproved candidate remains rejected")
            library = directory / f"{label}.so"
            artifacts[label] = measure(ledger, "build." + label, lambda p=program, path=library:
                                       build_program_native(p, path, clang=clang, kind="shared"))
            assembly = subprocess.run([objdump, "-d", "--disassemble=calculate", str(library)],
                                      text=True, capture_output=True, timeout=10, check=True).stdout
            (directory / f"{label}.assembly.txt").write_text(assembly)
            body = assembly.split("<calculate>:", 1)[1].split("Disassembly of section", 1)[0]
            code[label] = {"function_disassembly": body, "sha256": sha256(body.encode()).hexdigest()}
        report["distinct_native_functions"] = len({row["sha256"] for row in code.values()})
        require(report["distinct_native_functions"] == len(programs), "candidate actions did not change actual function code")
        source, driver = directory / "driver.c", directory / "driver"
        source.write_text(DRIVER, encoding="ascii")
        driver_argv = [clang, "-std=c11", "-O3", str(source), "-ldl", "-o", str(driver)]
        measure(ledger, "driver-build", lambda: subprocess.run(driver_argv, capture_output=True, timeout=30, check=True))
        report["driver"] = {"source_sha256": digest(source), "binary_sha256": digest(driver), "argv": driver_argv}
        training, holdout = {}, {}
        report["inputs"] = {}
        for split, target, seed in (("training", training, PROTOCOL["training_seed"]),
                                     ("holdout", holdout, PROTOCOL["holdout_seed"])):
            report["inputs"][split] = {}
            for profile in PROTOCOL["profiles"]:
                rows, path = report["frozen_inputs"][split][profile], directory / f"{split}-{profile}.tsv"
                path.write_text("".join(" ".join(map(str, row)) + "\n" for row in rows), encoding="ascii")
                target[profile] = rows, path
                report["inputs"][split][profile] = {"rows": rows, "sha256": digest(path)}
        samples = report["training_samples"] = []
        for profile in PROTOCOL["profiles"]:
            rows, path = training[profile]
            for trial, label in _schedule(labels, PROTOCOL["training_trials"]):
                row = measure(ledger, f"training.{profile}.{trial}.{label}", lambda:
                    sample(driver, directory / f"{label}.so", path, rows, PROTOCOL["training_calls"],
                           hashes=(digest(driver), artifacts[label]["artifact_sha256"], digest(path))))
                samples.append({"profile": profile, "trial": trial, "candidate_id": label, **row})
        summaries = report["training_summaries"] = {profile: {
            label: _summary([row for row in samples if row["profile"] == profile and row["candidate_id"] == label],
                            PROTOCOL["training_calls"]) for label in labels} for profile in PROTOCOL["profiles"]}
        shared_ns = report["input_freeze_wall_ns"] + time.perf_counter_ns() - shared_started
        report["shared_training_wall_ns"] = shared_ns
        require(shared_ns < PROTOCOL["resource_cap_ns"], "shared corpus exhausted the frozen search budget")
        observations = report["observations"] = {profile: {label: {
            "runtime_ns": summaries[profile][label]["runtime_ns"],
            "uncertainty_ns": summaries[profile][label]["uncertainty_ns"],
            "search_ns": shared_ns if label == "abstain" else 0,
            "program_sha256": verify_program(program).sha256} for label, program in programs.items()}
            for profile in PROTOCOL["profiles"]}
        fixed_selected = min(labels, key=lambda label: (sum(summaries[p][label]["runtime_ns"]
            + summaries[p][label]["uncertainty_ns"] for p in PROTOCOL["profiles"]), label))
        report["fixed_selected_training_choice"] = fixed_selected
        episodes = report["episodes"] = []
        for repetition in range(PROTOCOL["repetitions"]):
            profiles = PROTOCOL["profiles"][repetition:] + PROTOCOL["profiles"][:repetition]
            for profile in profiles:
                order = list(_schedule(PROTOCOL["arms"], PROTOCOL["repetitions"]))
                for _, arm in (row for row in order if row[0] == repetition):
                    row = episode(arm, profile, repetition, directory=directory, baseline=baseline,
                        candidates=candidates, observations=observations[profile], fixed_selected=fixed_selected,
                        bridge=bridge, clang=clang, driver=driver, holdout=holdout, shared_ns=shared_ns)
                    episodes.append(row)
                    with (directory / "EPISODES.jsonl").open("ab") as stream:
                        stream.write(wire(row) + b"\n")
                    print(json.dumps({"arm": arm, "profile": profile, "repetition": repetition,
                        "status": row["status"], "selected_id": row["selected_id"],
                        "warm_full_cost_ns": row["warm_full_cost_ns"]}), flush=True)
        ndu_count = sum(row["arm"] == "ndu" for row in episodes)
        require(ndu_count == PROTOCOL["ndu_cold_build_denominator"], "frozen cold-build amortization denominator changed")
        direct = {(row["profile"], row["repetition"]): row["episode_wall_ns"]
                  for row in episodes if row["arm"] == "fixed_stop"}
        for row in episodes:
            row["cold_amortized_full_cost_ns"] = row["warm_full_cost_ns"] + (
                math.ceil(report["ndu_cold_build_wall_ns"] / ndu_count) if row["arm"] == "ndu" else 0)
            row["direct_baseline_observed_cost_ns"] = direct[(row["profile"], row["repetition"])]
            row["warm_deployment_saving_vs_direct_ns"] = row["direct_baseline_observed_cost_ns"] - row["warm_full_cost_ns"]
            row["cold_deployment_saving_vs_direct_ns"] = row["direct_baseline_observed_cost_ns"] - row["cold_amortized_full_cost_ns"]
        report["arm_summary"] = {arm: {"episodes": len([row for row in episodes if row["arm"] == arm]),
            "published": sum(row["selected_id"] != "abstain" for row in episodes if row["arm"] == arm),
            "failures": sum(row["status"] != "completed" for row in episodes if row["arm"] == arm),
            **{field: statistics.median(row[field] for row in episodes if row["arm"] == arm)
               for field in ("warm_full_cost_ns", "cold_amortized_full_cost_ns")}} for arm in PROTOCOL["arms"]}
        by_pair = {(row["arm"], row["profile"], row["repetition"]): row for row in episodes}
        comparisons = report["primary_paired_comparisons"] = {}
        for control in PROTOCOL["arms"][:-1]:
            pairs = [{"profile": p, "repetition": n,
                      "saving_ns": by_pair[(control, p, n)]["cold_amortized_full_cost_ns"]
                                   - by_pair[("ndu", p, n)]["cold_amortized_full_cost_ns"]}
                     for n in range(PROTOCOL["repetitions"]) for p in PROTOCOL["profiles"]]
            threshold = max(PROTOCOL["no_increment_threshold"]["absolute_ns"], math.ceil(
                report["arm_summary"][control]["cold_amortized_full_cost_ns"]
                * PROTOCOL["no_increment_threshold"]["relative_control_median"]))
            savings = statistics.median(row["saving_ns"] for row in pairs)
            comparisons[control] = {"pairs": pairs, "median_saving_ns": savings,
                "no_increment_threshold_ns": threshold,
                "descriptive_increment": savings > threshold and all(statistics.median(
                    row["saving_ns"] for row in pairs if row["profile"] == p) > 0 for p in PROTOCOL["profiles"])}
        report["descriptive_increment_over_all_controls"] = all(row["descriptive_increment"] for row in comparisons.values())
        report["qualified"] = all(row["status"] == "completed" for row in episodes)
        report["interpretation"] = "One paired shared-training replay on a constructed workload. Actual preparation, cold bridge build and independent holdout are retained. No statistical/general advantage follows from medians. Shared cost is a per-arm standalone accounting charge, not repeated actual campaign work."
    except Exception as error:
        report["error"] = f"{type(error).__name__}: {error}"
    report["campaign_wall_ns"] = time.perf_counter_ns() - started
    report["source_inputs_unchanged"] = report["source_sha256"] == {name: digest(ROOT / name) for name in INPUTS}
    report["qualified"] &= report["source_inputs_unchanged"]
    (directory / "RESULT.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--clang", required=True)
    parser.add_argument("--cargo", required=True)
    parser.add_argument("--upstream", required=True, type=Path)
    parser.add_argument("--artifacts", required=True, type=Path)
    args = parser.parse_args()
    report = run(args.artifacts, clang=args.clang, cargo=args.cargo, upstream=args.upstream)
    print(json.dumps({"qualified": report["qualified"], "error": report.get("error"),
                      "artifacts": str(args.artifacts), "arm_summary": report.get("arm_summary")}))
    return 0 if report["qualified"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
