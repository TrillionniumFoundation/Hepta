#!/usr/bin/env python3
"""One frozen native experiment: finite search, real publication, complete cost.

The byte recurrence is authored research code. Calibration forecasts are host
models, never measured future results. Every arm receives the same calibration
and budget; arithmetic evaluates exactly the recursive NDU's supplied model.
Direct baseline deployment is separately charged no unnecessary search corpus.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from hashlib import sha256
import json
import math
import os
from pathlib import Path
import platform
import random
import re
import statistics
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

from hepta.hia_economic_search import RECURSIVE_PIN, choose_measurement
from hepta.hia_multiversion import PublicationCancellation, ScalarMultiversionRuntime
from hepta.hia_native_differential import _pin_native_artifact
from hepta.hia_ndu import NduBridge
from hepta.hia_program import SCHEMA, verify_program
from hepta.hia_program_llvm import build_program_native
from hepta.hia_scalar_totality import validate_scalar_totality
from hepta.hia_specialization import propose_guarded_specializations
from hepta.hia_translation_validation import validate_translation
from tools.build_hia_recursive_ndu_bridge import build as build_bridge

PROTOCOL = {
    "schema": "hepta.hia.economic-search-protocol.v1",
    "workload": "authored_total_u8_divrem_serial_byte_recurrence",
    "production_workload": False,
    "function": "calculate(x,d)= x if d==0 else ((x/d)+(x%d)) modulo 256",
    "recurrence": "state=calculate(state XOR input[n modulo 64].x,input[n modulo 64].d)",
    "state_scope": "one uint8_t C harness local in a child process; no ScalarStateSession host commits or heap/loan/stack migration are measured",
    "assumptions": [3, 10, 16], "profiles": ["hot_three", "hot_sixteen", "mixed"],
    "case_count": 64, "hot_cases": 60, "initial_state": 91,
    "hot_cases_semantics": "60-case fixed hot prefix plus one hot denominator in the forced [0,3,10,16] tail: 61/64 hot in each hot profile",
    "calibration_seed": 2026102801, "online_seed": 2026102802, "holdout_seed": 2026102803,
    "calibration_trials": 5, "measurement_calls": 250000, "sample_quorum": 2,
    "maximum_candidate_samples": 6, "warmup_calls": 4096,
    "holdout_calls": 64000000, "repetitions": 2,
    "arms": ["fixed_stop", "fixed_three", "fixed_ten", "fixed_sixteen", "fixed_selected",
             "exhaustive", "arithmetic", "ndu"],
    "search_budget_ns": 2000000000, "proof_timeout_ms": 5000,
    "search_budget_scope": "cooperative stage/selection admission, not hard real time; proof and compiler have their own finite timeouts; overruns remain charged and cannot publish",
    "order": "rotate arms by profile+repetition; reverse on odd repetitions; rotate profiles",
    "calibration": "all candidates are freshly proved, compiled, and measured in every training profile; same bank for all informed arms",
    "minimal_strategy_setup": "fixed_three/ten/sixteen and exhaustive do not use calibration: deployment charges only catalogue generation and online input setup; fixed_selected/arithmetic/NDU require full calibration; same-information table separately equalizes this cost",
    "online": "own baseline and attempted candidates measured on the same per-profile online input, never holdout timing",
    "interval": "min/max observed batch ns per call, integer picoseconds; empirical envelope only, not a confidence bound",
    "forecast": "calibration candidate upper rate scaled by current/calibration baseline median; after one sample retain max of prediction and observation, after quorum use observed upper rate",
    "publication_estimate": "twice the largest actually observed calibration prepare cost; a declared host estimate, never a measured future cost",
    "continuation": "fresh proof/build if needed, remaining sample quorum, fresh publication; execute only one measurement then replan",
    "native_ndu": {"pin": RECURSIVE_PIN, "request_schema": "hepta.hia.ndu.request.v1",
                   "authority": "DENY_ALL", "unit_discount": True, "learned_model": False},
    "ranking_bridge_used": False,
    "control": "arithmetic computes exactly the same supplied no-discount scalar continuation model; exhaustive measures all three candidates within the same budget",
    "fixed_selected": "one global action minimizes summed calibration upper runtime over all profiles, including baseline",
    "publication_gate": "fresh canonical/totality/equivalence, observed baseline lower versus measured candidate upper times holdout calls, subtract all amortized shared and actual online work, bound actual preparation",
    "amortization_denominator": 6,
    "amortization_scope": "each standalone strategy serves the declared six episodes; its calibration/driver/cold-build setup is charged once across those six; physical study shares calibration once across strategies",
    "single_episode_cost": "also report full unamortized required setup per episode; it is a counterfactual accounting charge, not repeatedly executed setup",
    "direct_baseline": "fixed_stop actual episode plus required common driver/input setup only; no candidate calibration or bridge cost",
    "same_information": "a separate table brings every arm's required search-setup charge up to the same full calibration cost; this is not the direct-deployment ledger",
    "primary_incremental_metric": "all episodes complete and NDU publishes at least once; in actual required deployment costs AND independently in same-information costs, paired median cold full-cost saving versus every control exceeds its threshold and every profile median is positive",
    "primary_mechanism_metric": "aggregate full-cost saving for six episodes against direct baseline, reported separately warm and cold; runtime-only savings do not establish deployment benefit",
    "threshold": {"absolute_ns": 1000000, "relative_control_cost": 0.01},
    "no_retry": "one campaign, every sample/failed action retained; no post-freeze tuning, resampling, or outlier deletion",
    "cleanup_completion": "after runtime close, require observed native release complete, no pending retirement, and owned directory absent; this is a current observation, never permanent absence",
    "cost_exclusions": "existing Python/Z3/Clang/Rust installation and dependency cache creation; authoring/development and final evidence serialization",
    "claims": {"global_optimality": False, "general_ndu_advantage": False,
               "backend_refinement_proved": False, "statistical_significance": False},
}
INPUTS = (
    "tools/qualify_hia_economic_search.py", "hepta/hia_economic_search.py", "hepta/hia_ndu.py",
    "hepta/hia_specialization.py", "hepta/hia_program.py", "hepta/hia_program_runtime.py",
    "hepta/hia_program_llvm.py", "hepta/hia_translation_validation.py", "hepta/hia_scalar_totality.py",
    "hepta/hia_multiversion.py", "hepta/hia_native_retirement.py", "hepta/hia_native_differential.py", "hepta/elf_shared_abi.py",
    "hepta/clang_capture.py", "tools/build_hia_recursive_ndu_bridge.py",
)

DRIVER = r'''#define _POSIX_C_SOURCE 200809L
#include <dlfcn.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <time.h>
typedef uint8_t (*kernel_t)(uint8_t,uint8_t);
struct row { unsigned x,d; };
static uint64_t now(clockid_t c) { struct timespec t; if(clock_gettime(c,&t)) exit(81); return (uint64_t)t.tv_sec*1000000000+(uint64_t)t.tv_nsec; }
int main(int argc,char **argv) {
 if(argc!=5) return 82;
 uint64_t calls=strtoull(argv[3],0,10),warmup=strtoull(argv[4],0,10);
 if(!calls||calls>64000000||warmup>4096) return 83;
 FILE *f=fopen(argv[2],"r"); struct row rows[64]; if(!f) return 84;
 for(int k=0;k<64;k++) if(fscanf(f,"%u %u",&rows[k].x,&rows[k].d)!=2||rows[k].x>255||rows[k].d>255) return 85;
 if(fclose(f)) return 86;
 void *lib=dlopen(argv[1],RTLD_NOW|RTLD_LOCAL); if(!lib) { fprintf(stderr,"%s\n",dlerror()); return 87; }
 kernel_t fn=(kernel_t)dlsym(lib,"calculate"); if(!fn) return 88;
 for(unsigned x=0;x<256;x++) for(unsigned d=0;d<256;d++) {
   unsigned expected=d==0?x:((x/d+x%d)&255);
   if(fn((uint8_t)x,(uint8_t)d)!=(uint8_t)expected) return 89;
 }
 volatile uint8_t warm=91;
 for(uint64_t k=0;k<warmup;k++) warm=fn((uint8_t)(warm^rows[k&63].x),(uint8_t)rows[k&63].d);
 struct rusage before,after; if(getrusage(RUSAGE_SELF,&before)) return 90;
 uint8_t state=91; uint64_t checksum=0,cpu=now(CLOCK_PROCESS_CPUTIME_ID),start=now(CLOCK_MONOTONIC);
 for(uint64_t k=0;k<calls;k++) { state=fn((uint8_t)(state^rows[k&63].x),(uint8_t)rows[k&63].d); checksum+=state; }
 uint64_t elapsed=now(CLOCK_MONOTONIC)-start,cpu_ns=now(CLOCK_PROCESS_CPUTIME_ID)-cpu;
 if(getrusage(RUSAGE_SELF,&after)) return 91;
 printf("{\"elapsed_ns\":%" PRIu64 ",\"process_cpu_ns\":%" PRIu64 ",\"iterations\":%" PRIu64 ",\"checksum\":%" PRIu64 ",\"final_state\":%u,\"oracle_pair_checks\":65536,\"voluntary_context_switches\":%ld,\"involuntary_context_switches\":%ld,\"minor_page_faults\":%ld,\"major_page_faults\":%ld}\n",elapsed,cpu_ns,calls,checksum,(unsigned)state,after.ru_nvcsw-before.ru_nvcsw,after.ru_nivcsw-before.ru_nivcsw,after.ru_minflt-before.ru_minflt,after.ru_majflt-before.ru_majflt);
 return dlclose(lib)?92:0;
}'''


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(path):
    return sha256(Path(path).read_bytes()).hexdigest()


def save(path, value):
    Path(path).write_bytes(wire(value) + b"\n")


def require(condition, message):
    if not condition:
        raise RuntimeError("E_HIA_ECONOMIC_EXPERIMENT: " + message)


def workload():
    def param(name):
        return {"name": name, "type": "u8"}
    def op(name, args, out, typ="u8", **attrs):
        return {"op": name, "args": args, "out": [{"name": out, "type": typ}], "attrs": attrs}
    params = [param("x"), param("denominator")]
    return {"schema": SCHEMA, "module": "total_byte_recurrence_research", "functions": [{
        "name": "calculate", "params": params, "returns": ["u8"], "effects": ["trap"],
        "entry": "entry", "blocks": [
            {"id": "entry", "params": params, "ops": [op("const", [], "zero", value=0),
                op("compare.eq", ["denominator", "zero"], "is_zero", "bool")],
             "term": {"op": "branch", "cond": "is_zero", "then": {"target": "zero_case", "args": ["x"]},
                      "else": {"target": "nonzero", "args": ["x", "denominator"]}}},
            {"id": "zero_case", "params": [param("z")], "ops": [], "term": {"op": "ret", "values": ["z"]}},
            {"id": "nonzero", "params": [param("n"), param("d")], "ops": [
                op("int.div.checked", ["n", "d"], "q"), op("int.rem.checked", ["n", "d"], "r"),
                op("int.add.wrap", ["q", "r"], "answer")], "term": {"op": "ret", "values": ["answer"]}},
        ]}]}


def cases(profile, seed):
    rng = random.Random(seed + PROTOCOL["profiles"].index(profile))
    rows = [[rng.randrange(256), rng.randrange(256)] for _ in range(64)]
    if profile != "mixed":
        for row in rows[:PROTOCOL["hot_cases"]]:
            row[1] = 3 if profile == "hot_three" else 16
    # Zero and both specialized denominators are present in every input ring.
    for row, value in zip(rows[-4:], (0, 3, 10, 16)):
        row[1] = value
    return rows


def oracle(rows, calls):
    """Independent integer transition; cycle acceleration on 64*256 states."""
    state, index, total, seen = 91, 0, 0, {}
    while index < calls:
        key = (index % len(rows), state)
        if key in seen:
            old_index, old_total = seen[key]
            cycles = (calls - index) // (index - old_index)
            if cycles:
                total += cycles * (total - old_total)
                index += cycles * (index - old_index)
                continue
        else:
            seen[key] = (index, total)
        x, denominator = rows[index % len(rows)]
        x ^= state
        state = x if denominator == 0 else (x // denominator + x % denominator) % 256
        total += state
        index += 1
    return {"checksum": total % (1 << 64), "final_state": state}


def sample(driver, library, input_path, rows, calls, *, expected_artifact, timeout=20):
    start, descriptors = time.perf_counter_ns(), []
    deadline = start + max(0, int(timeout*1e9))
    row = {"status": "failed", "iterations": calls, "source_paths": list(map(str, (driver, library, input_path))),
           "driver_sha256": digest(driver), "artifact_sha256": expected_artifact,
           "input_sha256": digest(input_path), "expected": oracle(rows, calls)}
    try:
        for path, expected in zip((driver, library, input_path),
                                 (row["driver_sha256"], expected_artifact, row["input_sha256"])):
            data, _identity, fd = _pin_native_artifact(Path(path))
            descriptors.append(fd)
            require(sha256(data).hexdigest() == expected, "sealed bytes differ from recorded identity")
        command = [*(f"/proc/self/fd/{fd}" for fd in descriptors), str(calls), str(PROTOCOL["warmup_calls"])]
        remaining = deadline-time.perf_counter_ns()
        require(remaining > 0, "native sample deadline exhausted before process launch")
        row["argv"] = command
        row["child_timeout_ns"] = remaining
        completed = subprocess.run(command, capture_output=True, pass_fds=tuple(descriptors), timeout=remaining/1e9)
        row.update(returncode=completed.returncode, stdout=completed.stdout.decode(errors="replace"),
                   stderr=completed.stderr.decode(errors="replace"), consumed_files_sealed=True)
        require(completed.returncode == 0, "native child failed")
        observed = json.loads(completed.stdout)
        require(all(observed.get(k) == v for k, v in row["expected"].items()), "recurrence oracle disagreement")
        require(observed.get("iterations") == calls and observed.get("oracle_pair_checks") == 65536,
                "driver did not complete the requested workload and finite ABI checks")
        require(all(type(observed.get(k)) is int and observed[k] > 0 for k in ("elapsed_ns", "process_cpu_ns")),
                "invalid native timer")
        row.update(observed, status="observed")
    except Exception as error:
        row["error"] = f"{type(error).__name__}: {error}"
        if isinstance(error, subprocess.TimeoutExpired):
            row["stdout"] = (error.stdout or b"").decode(errors="replace")
            row["stderr"] = (error.stderr or b"").decode(errors="replace")
    finally:
        for fd in descriptors:
            os.close(fd)
    row["outer_wall_ns"] = time.perf_counter_ns() - start
    return row


def summarize(samples):
    require(samples and all(row["status"] == "observed" for row in samples), "failed samples have no usable summary")
    calls = samples[0]["iterations"]
    require(all(row["iterations"] == calls for row in samples), "heterogeneous measurement call counts")
    values = sorted(row["elapsed_ns"] for row in samples)
    n = len(values)
    central_twice = values[n//2]*2 if n % 2 else values[n//2-1]+values[n//2]
    return {"lower_ps": values[0]*1000//calls, "upper_ps": (values[-1]*1000+calls-1)//calls,
            "median_ps": (central_twice*1000+2*calls-1)//(2*calls), "samples": n,
            "sample_outer_ns": math.ceil(statistics.median(row["outer_wall_ns"] for row in samples))}


def prepare(baseline, document, path, clang, *, deadline_ns=None):
    started = time.perf_counter_ns()
    receipt = {"status": "failed", "artifact": str(path), "stages": {}}
    def admission():
        if deadline_ns is None:
            return PROTOCOL["proof_timeout_ms"]
        remaining = deadline_ns-time.perf_counter_ns()
        require(remaining > 0, "search deadline exhausted before "+active_stage)
        return min(PROTOCOL["proof_timeout_ms"], max(1, remaining//1_000_000))
    try:
        active_stage = "canonical"
        start = time.perf_counter_ns()
        admission()
        before, after = verify_program(baseline), verify_program(document)
        receipt.update(program_sha256=after.sha256, input_sha256=after.input_sha256)
        receipt["stages"]["canonical_ns"] = time.perf_counter_ns()-start
        active_stage = "totality"
        start = time.perf_counter_ns()
        total = validate_scalar_totality(after, function="calculate", timeout_ms=admission())
        receipt["totality"] = total
        receipt["stages"]["totality_ns"] = time.perf_counter_ns()-start
        require(total["status"] == "proved" and total["program_sha256"] == after.sha256
                and total["input_sha256"] == after.input_sha256, "fresh candidate totality failed")
        active_stage = "equivalence"
        start = time.perf_counter_ns()
        proof = validate_translation(before, after, function="calculate", timeout_ms=admission())
        receipt["equivalence"] = proof
        receipt["stages"]["equivalence_ns"] = time.perf_counter_ns()-start
        require(proof["status"] == "proved" and proof["before_sha256"] == before.sha256
                and proof["after_sha256"] == after.sha256, "fresh candidate equivalence failed")
        active_stage = "native_build"
        start = time.perf_counter_ns()
        admission()
        receipt["native"] = build_program_native(after, path, clang=clang, kind="shared")
        receipt["artifact_sha256"] = digest(path)
        receipt["stages"]["native_build_ns"] = time.perf_counter_ns()-start
        require(deadline_ns is None or time.perf_counter_ns() < deadline_ns,
                "search deadline exhausted after native build")
        receipt["status"] = "prepared"
    except Exception as error:
        receipt["error"] = f"{type(error).__name__}: {error}"
        receipt["failed_stage"] = active_stage
        receipt["stages"][active_stage+"_ns"] = time.perf_counter_ns()-start
        raise
    finally:
        receipt["wall_ns"] = time.perf_counter_ns()-started
        save(path.with_suffix(".prepare.json"), receipt)
    return receipt


def episode(arm, profile, repetition, *, folder, baseline, candidates, bank, fixed_selected,
            shared_charge_ns, bridge_charge_ns, bridge, clang, driver, inputs):
    started = time.perf_counter_ns()
    record = {"arm": arm, "profile": profile, "repetition": repetition, "status": "failed",
              "selected_id": "abstain", "attempts": [], "controls": [], "shared_charge_ns": shared_charge_ns,
              "bridge_charge_ns": bridge_charge_ns, "publication": None, "failed_samples_retained": []}
    folder.mkdir()
    try:
        with ScalarMultiversionRuntime(baseline, folder, clang=clang, prove_total=True,
                                      validation_timeout_ms=PROTOCOL["proof_timeout_ms"]) as runtime:
            record["initial_snapshot"] = runtime.snapshot()
            record["baseline_prepare_ns"] = time.perf_counter_ns() - started
            with runtime.lease() as original:
                initial = runtime.snapshot()["generations"][0]
                library = runtime._directory / "generation-0.so"
                rows, path = inputs["online"][profile]
                search_started = time.perf_counter_ns()
                deadline = search_started+PROTOCOL["search_budget_ns"]-shared_charge_ns-bridge_charge_ns
                def spent():
                    return shared_charge_ns + bridge_charge_ns + time.perf_counter_ns() - search_started
                active = arm != "fixed_stop" and not (arm == "fixed_selected" and fixed_selected == "abstain")
                baseline_samples = []
                if active:
                    for _ in range(PROTOCOL["sample_quorum"]):
                        remaining = deadline-time.perf_counter_ns()
                        if remaining <= 0:
                            active = False
                            record["stop_reason"] = "budget_exhausted_before_baseline_sample"
                            break
                        observed = sample(driver, library, path, rows, PROTOCOL["measurement_calls"],
                                          expected_artifact=initial["artifact_sha256"], timeout=remaining/1e9)
                        baseline_samples.append(observed)
                        if observed["status"] != "observed":
                            active = False
                            record["stop_reason"] = "baseline_measurement_failed"
                            record["failed_samples_retained"].append(observed)
                            break
                        if time.perf_counter_ns() >= deadline:
                            active = False
                            record["stop_reason"] = "budget_exhausted_after_baseline_sample"
                            break
                    record["baseline_samples"] = baseline_samples
                    current_baseline = (summarize(baseline_samples) if active and len(baseline_samples) == PROTOCOL["sample_quorum"]
                                        else bank["profiles"][profile]["abstain"])
                else:
                    current_baseline = bank["profiles"][profile]["abstain"]
                observations = {row["id"]: [] for row in candidates}
                prepared, blocked = {}, set()
                measurements, proposed = 0, "abstain"
                ids = [row["id"] for row in candidates]
                fixed = {"fixed_three": ids[0], "fixed_ten": ids[1], "fixed_sixteen": ids[2],
                         "fixed_selected": fixed_selected}.get(arm)

                def best_ready():
                    ready = [cid for cid in ids if len(observations[cid]) >= PROTOCOL["sample_quorum"] and cid not in blocked]
                    return min(ready, key=lambda cid: (summarize(observations[cid])["upper_ps"], cid), default="abstain")

                while active and measurements < PROTOCOL["maximum_candidate_samples"]:
                    remaining = PROTOCOL["search_budget_ns"] - spent()
                    if remaining <= 0:
                        record["stop_reason"] = "observed_search_budget_exhausted"
                        break
                    if arm in ("ndu", "arithmetic"):
                        model_rows = []
                        for row in candidates:
                            cid = row["id"]
                            predicted = (bank["profiles"][profile][cid]["upper_ps"] * current_baseline["median_ps"]
                                + bank["profiles"][profile]["abstain"]["median_ps"] - 1) // bank["profiles"][profile]["abstain"]["median_ps"]
                            if observations[cid]:
                                observed_upper = summarize(observations[cid])["upper_ps"]
                                predicted = observed_upper if len(observations[cid]) >= PROTOCOL["sample_quorum"] else max(predicted, observed_upper)
                            model_rows.append({"id": cid, "program_sha256": verify_program(row["program"]).sha256,
                                "support_sha256": sha256(wire({"bank": bank["sha256"], "observations": observations[cid]})).hexdigest(),
                                "runtime_upper_ps": predicted, "prepare_estimate_ns": bank["prepare"][cid]["wall_ns"],
                                "sample_estimate_ns": bank["profiles"][profile][cid]["sample_outer_ns"],
                                "successful_samples": len(observations[cid]), "prepared": cid in prepared, "blocked": cid in blocked})
                        snapshot = {"baseline_sha256": verify_program(baseline).sha256,
                            "objective_sha256": sha256(wire(PROTOCOL)).hexdigest(), "baseline_lower_ps": current_baseline["lower_ps"],
                            "expected_calls": PROTOCOL["holdout_calls"], "spent_search_ns": spent(),
                            "remaining_budget_ns": max(0, PROTOCOL["search_budget_ns"]-spent()),
                            "remaining_measurements": PROTOCOL["maximum_candidate_samples"]-measurements,
                            "sample_quorum": PROTOCOL["sample_quorum"], "publication_estimate_ns": bank["publication_estimate_ns"],
                            "generation": len(record["controls"])+1, "candidates": model_rows}
                        control_started = time.perf_counter_ns()
                        old_timeout = bridge.timeout if arm == "ndu" else None
                        try:
                            remaining = deadline-time.perf_counter_ns()
                            require(remaining > 0, "budget exhausted before controller")
                            if arm == "ndu":
                                bridge.timeout = min(old_timeout, remaining/1e9)
                            decision = choose_measurement(snapshot, backend="ndu" if arm == "ndu" else "arithmetic",
                                                          bridge=bridge if arm == "ndu" else None)
                        except Exception as error:
                            record["controls"].append({"status": "failed", "error": f"{type(error).__name__}: {error}",
                                "snapshot": snapshot, "control_wall_ns": time.perf_counter_ns()-control_started})
                            record["stop_reason"] = "controller_failed_or_exhausted_budget"
                            break
                        finally:
                            if arm == "ndu":
                                bridge.timeout = old_timeout
                        record["controls"].append(decision)
                        if time.perf_counter_ns() >= deadline:
                            record["stop_reason"] = "budget_exhausted_after_controller"
                            break
                        if decision["action"]["kind"] == "stop":
                            proposed = decision["action"]["candidate_id"]
                            record["stop_reason"] = decision["reason"]
                            break
                        selected = decision["action"]["candidate_id"]
                    elif arm == "exhaustive":
                        selected = next((cid for cid in ids if len(observations[cid]) < PROTOCOL["sample_quorum"] and cid not in blocked), None)
                        if selected is None:
                            break
                    else:
                        selected = fixed
                        if selected == "abstain" or selected in blocked or len(observations[selected]) >= PROTOCOL["sample_quorum"]:
                            break
                    attempt = {"id": selected, "status": "failed", "measurement_index": measurements,
                               "preparation_receipt_path": str(folder/(selected+".prepare.json"))}
                    record["attempts"].append(attempt)
                    action_start = time.perf_counter_ns()
                    try:
                        require(time.perf_counter_ns() < deadline, "budget exhausted before candidate preparation")
                        candidate = next(row for row in candidates if row["id"] == selected)
                        if selected not in prepared:
                            prepared[selected] = prepare(baseline, candidate["program"], folder/(selected+".so"), clang,
                                                         deadline_ns=deadline)
                            attempt["preparation"] = prepared[selected]
                        require(spent() < PROTOCOL["search_budget_ns"], "budget exhausted during candidate preparation")
                        native = prepared[selected]
                        observed = sample(driver, Path(native["artifact"]), path, rows, PROTOCOL["measurement_calls"],
                            expected_artifact=native["artifact_sha256"], timeout=max(0, (deadline-time.perf_counter_ns())/1e9))
                        attempt["measurement"] = observed
                        require(observed["status"] == "observed", "measurement failed")
                        observations[selected].append(observed)
                        attempt["status"] = "measured"
                    except Exception as error:
                        blocked.add(selected)
                        attempt["error"] = f"{type(error).__name__}: {error}"
                    attempt["wall_ns"] = time.perf_counter_ns() - action_start
                    measurements += 1
                if proposed == "abstain":
                    proposed = best_ready()
                if "stop_reason" not in record:
                    record["stop_reason"] = ("measurement_limit_reached" if measurements >= PROTOCOL["maximum_candidate_samples"]
                                             else "fixed_action_or_candidate_inventory_complete")
                record["proposed_id"] = proposed
                record["online_candidate_summaries"] = {cid: summarize(values) for cid, values in observations.items() if values}
                if proposed != "abstain":
                    lower, upper = current_baseline["lower_ps"], summarize(observations[proposed])["upper_ps"]
                    gross = (lower-upper)*PROTOCOL["holdout_calls"]//1000
                    budget = min(gross-spent()-1, PROTOCOL["search_budget_ns"]-spent())
                    record["publication_economic_gate"] = {"baseline_lower_ps": lower, "candidate_upper_ps": upper,
                        "empirical_gross_saving_ns": gross, "already_spent_ns": spent(), "max_prepare_ns": budget,
                        "cold_bridge_build_included": False}
                    if budget > 0:
                        candidate = next(row for row in candidates if row["id"] == proposed)
                        try:
                            record["publication"] = runtime.publish_if_current(candidate["program"], 0,
                                expected_epoch=0, max_prepare_ns=budget, cancellation=PublicationCancellation())
                            record["selected_id"] = proposed
                        except Exception as error:
                            record["publication_rejected"] = f"{type(error).__name__}: {error}"
                    else:
                        record["publication_rejected"] = "no_compile_inclusive_empirical_margin"
                record["search_and_publication_ns"] = time.perf_counter_ns() - search_started
                snapshot = runtime.snapshot()
                record["published_snapshot"] = snapshot
                selected = next(row for row in snapshot["generations"] if row["generation"] == snapshot["current_generation"])
                with runtime.lease() as current:
                    for x, d in rows:
                        expected = x if d == 0 else (x//d+x%d) % 256
                        require(original.call("calculate", [x,d]) == expected, "original lease changed during publication")
                        require(current.call("calculate", [x,d]) == expected, "new lease has incorrect behavior")
                    holdout_rows, holdout_path = inputs["holdout"][profile]
                    library = runtime._directory / f"generation-{selected['generation']}.so"
                    record["execution"] = sample(driver, library, holdout_path, holdout_rows, PROTOCOL["holdout_calls"],
                        expected_artifact=selected["artifact_sha256"])
                    require(record["execution"]["status"] == "observed", "holdout failed")
                    # Preserve exact executable bytes outside the runtime's private lifecycle.
                    artifact = folder/"selected-artifact.so"
                    artifact.write_bytes(library.read_bytes())
                    require(digest(artifact) == selected["artifact_sha256"], "selected artifact archive changed")
                    record["archived_selected_artifact"] = str(artifact)
                    switched = selected["generation"] != 0
                    if switched:
                        runtime.rollback()
                        require(runtime.snapshot()["current_generation"] == 0, "rollback did not restore baseline")
                        require(current.call("calculate", [255,0]) == 255, "live selected lease did not survive rollback")
                    record["lifecycle"] = {"published": switched, "old_lease_checks": len(rows),
                        "selected_lease_checks": len(rows), "rollback": switched, "live_lease_survived_rollback": switched}
        record["closed_snapshot"] = runtime.snapshot()
        cleanup = record["closed_snapshot"]["cleanup"]
        require(cleanup.get("owned_native_release_complete") is True and not cleanup.get("pending")
                and cleanup.get("observed_closed_and_directory_absent") is True,
                "runtime cleanup did not observe complete native release and directory absence")
        record["status"] = "completed"
    except Exception as error:
        record["error"] = f"{type(error).__name__}: {error}"
    record["episode_wall_ns"] = time.perf_counter_ns() - started
    save(folder/"RESULT.json", record)
    print(json.dumps({"arm": arm, "profile": profile, "repetition": repetition, "status": record["status"],
                      "selected": record["selected_id"], "episode_wall_ns": record["episode_wall_ns"]}), flush=True)
    return record


def source_state(root, expected_head):
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    status = subprocess.check_output(["git", "status", "--porcelain=v1", "--untracked-files=all"], cwd=root, text=True)
    require(head == expected_head and not status, "source pin or clean worktree requirement failed: "+str(root))
    return {"head": head, "status_porcelain": status, "worktree_clean": True}


def verify_bridge_source_blobs(root, identity):
    """Match every recorded native/adapter input to the actual pinned Git blob."""
    inventory = {**identity["native_sources"], **identity["bridge_sources"]}
    for relative, expected in inventory.items():
        canonical = subprocess.check_output(["git", "cat-file", "blob", RECURSIVE_PIN+":"+relative], cwd=root)
        require(sha256(canonical).hexdigest() == expected == digest(root/relative),
                "compiled source differs from pinned Git blob: "+relative)
    return {"source_pin": RECURSIVE_PIN, "checked_inputs": len(inventory),
            "actual_recorded_and_git_blob_sha256_equal": True,
            "source_inventory_sha256": sha256(wire(inventory)).hexdigest()}


def run(args):
    output = args.output_directory.resolve()
    # Existing evidence must remain byte-for-byte untouched, even on a mistaken
    # second invocation. Only the invocation that creates this directory owns
    # the right to write its terminal failure receipt.
    output.mkdir(parents=True, exist_ok=False)
    try:
        return _run(args)
    except Exception as error:
        save(output/"FAILURE.json", {"status": "failed", "error": f"{type(error).__name__}: {error}",
                                    "partial_evidence_retained": True})
        raise


def _run(args):
    started = time.perf_counter_ns()
    output = args.output_directory.resolve()
    admitted_source = source_state(ROOT, args.expected_head)
    head = admitted_source["head"]
    fingerprints = {path: digest(ROOT/path) for path in INPUTS}
    save(output/"PROTOCOL.json", PROTOCOL)
    save(output/"SOURCE.json", {"head": head, "git": admitted_source, "files": fingerprints, "platform": platform.platform(),
        "started_utc": datetime.now(timezone.utc).isoformat(), "python": sys.version,
        "clang": str(args.clang), "clang_sha256": digest(args.clang)})
    common_start = time.perf_counter_ns()
    source = output/"driver.c"
    source.write_text(DRIVER)
    driver = output/"driver"
    command = [str(args.clang), "-O2", "-std=c11", str(source), "-ldl", "-o", str(driver)]
    build = subprocess.run(command, capture_output=True, text=True)
    save(output/"DRIVER_BUILD.json", {"argv": command, "returncode": build.returncode,
                                      "stdout": build.stdout, "stderr": build.stderr})
    require(build.returncode == 0, "driver build failed")
    inputs = {}
    def create_inputs(kind):
        inputs[kind] = {}
        for profile in PROTOCOL["profiles"]:
            rows = cases(profile, PROTOCOL[kind+"_seed"])
            path = output/f"{kind}-{profile}.txt"
            path.write_text("".join(f"{x} {d}\n" for x,d in rows))
            inputs[kind][profile] = (rows,path)
    create_inputs("holdout")
    baseline = workload()
    common_ns = time.perf_counter_ns()-common_start
    calibration_start = time.perf_counter_ns()
    setup_start = time.perf_counter_ns()
    create_inputs("online")
    online_input_setup_ns = time.perf_counter_ns()-setup_start
    create_inputs("calibration")
    setup_start = time.perf_counter_ns()
    candidates = propose_guarded_specializations(baseline, function="calculate",
        assumptions=[{"parameter": "denominator", "value": n} for n in PROTOCOL["assumptions"]])
    save(output/"BASELINE.json", baseline)
    save(output/"CANDIDATES.json", candidates)
    catalogue_setup_ns = time.perf_counter_ns()-setup_start
    programs = {"abstain": baseline, **{row["id"]: row["program"] for row in candidates}}
    bank = {"prepare": {}, "profiles": {p: {} for p in PROTOCOL["profiles"]}, "samples": []}
    for cid, program in programs.items():
        artifact = output/("calibration-"+cid+".so")
        bank["prepare"][cid] = prepare(baseline, program, artifact, str(args.clang))
        disassembly = subprocess.run(["objdump", "-d", str(artifact)], capture_output=True, text=True)
        require(disassembly.returncode == 0, "native disassembly failed")
        (output/("calibration-"+cid+".disassembly.txt")).write_text(disassembly.stdout)
        body = disassembly.stdout.split("<calculate>:\n", 1)[1].split("\n\n", 1)[0]
        code = b"".join(bytes.fromhex(match.group(1)) for line in body.splitlines()
                         if (match := re.match(r"\s*[0-9a-f]+:\s*((?:[0-9a-f]{2}\s+)+)", line)))
        require(code, "exported calculate body bytes are missing")
        bank["prepare"][cid]["calculate_code_sha256"] = sha256(code).hexdigest()
        bank["prepare"][cid]["calculate_code_bytes"] = len(code)
    bank["distinct_calculate_machine_code_bodies"] = len({row["calculate_code_sha256"] for row in bank["prepare"].values()})
    require(bank["distinct_calculate_machine_code_bodies"] > 1, "no actual instruction-level optimization space")
    ids = list(programs)
    for trial in range(PROTOCOL["calibration_trials"]):
        for pi, profile in enumerate(PROTOCOL["profiles"]):
            order = ids[(trial+pi)%len(ids):]+ids[:(trial+pi)%len(ids)]
            if trial % 2:
                order.reverse()
            for cid in order:
                rows,path = inputs["calibration"][profile]
                native = bank["prepare"][cid]
                observed = sample(driver, Path(native["artifact"]), path, rows, PROTOCOL["measurement_calls"],
                                  expected_artifact=native["artifact_sha256"])
                bank["samples"].append({"profile": profile, "candidate_id": cid, "trial": trial, **observed})
                save(output/"CALIBRATION-PARTIAL.json", bank)
                require(observed["status"] == "observed", "calibration sample failed; campaign retained and stopped")
    for profile in PROTOCOL["profiles"]:
        for cid in ids:
            bank["profiles"][profile][cid] = summarize([row for row in bank["samples"]
                if row["profile"] == profile and row["candidate_id"] == cid])
    bank["publication_estimate_ns"] = 2*max(row["wall_ns"] for row in bank["prepare"].values())
    bank["sha256"] = sha256(wire(bank)).hexdigest()
    save(output/"CALIBRATION.json", bank)
    calibration_ns = time.perf_counter_ns()-calibration_start
    minimal_search_setup_ns = online_input_setup_ns+catalogue_setup_ns
    bridge_start = time.perf_counter_ns()
    upstream_before = source_state(args.recursive_upstream, RECURSIVE_PIN)
    identity_path = build_bridge(argparse.Namespace(ndu_source=args.recursive_upstream,
        output=output/"recursive-build", cargo=args.cargo, rustc=args.rustc,
        cargo_home=args.cargo_home, expected_source=RECURSIVE_PIN, offline=True))
    identity = json.loads(identity_path.read_text())
    source_alignment = verify_bridge_source_blobs(args.recursive_upstream, identity)
    upstream_after = source_state(args.recursive_upstream, RECURSIVE_PIN)
    save(output/"UPSTREAM_SOURCE.json", {"before": upstream_before, "after": upstream_after,
                                       "compiled_input_alignment": source_alignment})
    cold_ns = time.perf_counter_ns()-bridge_start
    bridge_start = time.perf_counter_ns()
    bridge = NduBridge(identity["binary"], identity_path)
    bridge_init_ns = time.perf_counter_ns()-bridge_start
    denominator = PROTOCOL["amortization_denominator"]
    calibration_charge = (calibration_ns+denominator-1)//denominator
    bridge_charge = (bridge_init_ns+denominator-1)//denominator
    fixed = min(ids, key=lambda cid: (sum(bank["profiles"][p][cid]["upper_ps"] for p in PROTOCOL["profiles"]), cid))
    costs = {"common_setup_ns": common_ns, "calibration_setup_ns": calibration_ns,
             "online_input_setup_ns": online_input_setup_ns, "catalogue_setup_ns": catalogue_setup_ns,
             "minimal_search_setup_ns": minimal_search_setup_ns,
             "recursive_cold_build_ns": cold_ns, "recursive_identity_setup_ns": bridge_init_ns,
             "amortization_denominator": denominator, "fixed_selected_id": fixed}
    save(output/"SETUP_COSTS.json", costs)
    episodes = []
    for rep in range(PROTOCOL["repetitions"]):
        profiles = PROTOCOL["profiles"][rep:]+PROTOCOL["profiles"][:rep]
        for pi, profile in enumerate(profiles):
            arms = PROTOCOL["arms"][(rep+pi)%len(PROTOCOL["arms"]):]+PROTOCOL["arms"][:(rep+pi)%len(PROTOCOL["arms"])]
            if rep % 2:
                arms.reverse()
            for arm in arms:
                needed_setup_ns = (0 if arm == "fixed_stop" else minimal_search_setup_ns
                    if arm in {"fixed_three", "fixed_ten", "fixed_sixteen", "exhaustive"} else calibration_ns)
                needed_charge_ns = (needed_setup_ns+denominator-1)//denominator
                record = episode(arm, profile, rep, folder=output/f"episode-{rep}-{profile}-{arm}",
                    baseline=baseline, candidates=candidates, bank=bank, fixed_selected=fixed,
                    shared_charge_ns=needed_charge_ns,
                    bridge_charge_ns=bridge_charge if arm == "ndu" else 0,
                    bridge=bridge, clang=str(args.clang), driver=driver, inputs=inputs)
                record["warm_deployment_ns"] = record["episode_wall_ns"] + (common_ns+denominator-1)//denominator + record["shared_charge_ns"] + record["bridge_charge_ns"]
                record["cold_deployment_ns"] = record["warm_deployment_ns"] + ((cold_ns+denominator-1)//denominator if arm == "ndu" else 0)
                record["required_strategy_setup_ns"] = needed_setup_ns
                record["same_information_cold_ns"] = record["cold_deployment_ns"] + calibration_charge-needed_charge_ns
                record["single_episode_warm_ns"] = record["episode_wall_ns"]+common_ns+needed_setup_ns+(bridge_init_ns if arm == "ndu" else 0)
                record["single_episode_cold_ns"] = record["single_episode_warm_ns"]+(cold_ns if arm == "ndu" else 0)
                episodes.append(record)
                save(output/"EPISODES-PARTIAL.json", episodes)
    pairs = {(e["arm"],e["profile"],e["repetition"]): e for e in episodes}
    table, comparisons = {}, {}
    for arm in PROTOCOL["arms"]:
        selected = [e for e in episodes if e["arm"] == arm]
        table[arm] = {"episodes": len(selected), "completed": sum(e["status"] == "completed" for e in selected),
            "published": sum(e["selected_id"] != "abstain" for e in selected),
            "measurements_attempted": sum(len(e["attempts"]) for e in selected),
            "controller_attempts": sum(len(e["controls"]) for e in selected),
            "successful_native_decisions": sum(c.get("native_response") is not None
                and c.get("claims", {}).get("native_recursive_utility_invoked") is True
                for e in selected for c in e["controls"]),
            "failed_controller_attempts": sum(c.get("status") == "failed" for e in selected for c in e["controls"]),
            **{field: {"sum": sum(e[field] for e in selected), "median": statistics.median(e[field] for e in selected)}
               for field in ("warm_deployment_ns", "cold_deployment_ns", "same_information_cold_ns", "single_episode_cold_ns")}}
        if arm != "fixed_stop":
            table[arm]["direct_baseline_aggregate_saving_ns"] = {
                label: sum(pairs[("fixed_stop",e["profile"],e["repetition"])][label]-e[label] for e in selected)
                for label in ("warm_deployment_ns", "cold_deployment_ns")}
        if arm != "ndu":
            deltas = [e["same_information_cold_ns"]-pairs[("ndu",e["profile"],e["repetition"])]["same_information_cold_ns"] for e in selected]
            threshold = max(1000000, math.ceil(0.01*table[arm]["same_information_cold_ns"]["median"]))
            by_profile = {p: statistics.median(e["same_information_cold_ns"]-pairs[("ndu",p,e["repetition"])]["same_information_cold_ns"]
                for e in selected if e["profile"] == p) for p in PROTOCOL["profiles"]}
            comparisons[arm] = {"paired_cold_saving_ns": deltas, "median_paired_saving_ns": statistics.median(deltas),
                "threshold_ns": threshold, "profile_medians_ns": by_profile,
                "increment_condition_met": statistics.median(deltas)>threshold and all(v>0 for v in by_profile.values())}
            direct_deltas = [e["cold_deployment_ns"]-pairs[("ndu",e["profile"],e["repetition"])]["cold_deployment_ns"] for e in selected]
            comparisons[arm]["direct_deployment_paired_cold_saving_ns"] = direct_deltas
            comparisons[arm]["direct_deployment_median_cold_saving_ns"] = statistics.median(direct_deltas)
            direct_threshold = max(1000000, math.ceil(0.01*table[arm]["cold_deployment_ns"]["median"]))
            direct_profiles = {p: statistics.median(e["cold_deployment_ns"]-pairs[("ndu",p,e["repetition"])]["cold_deployment_ns"]
                for e in selected if e["profile"] == p) for p in PROTOCOL["profiles"]}
            comparisons[arm]["direct_deployment_threshold_ns"] = direct_threshold
            comparisons[arm]["direct_deployment_profile_medians_ns"] = direct_profiles
            comparisons[arm]["same_information_condition_met"] = comparisons[arm]["increment_condition_met"]
            comparisons[arm]["required_deployment_condition_met"] = statistics.median(direct_deltas)>direct_threshold and all(v>0 for v in direct_profiles.values())
            comparisons[arm]["increment_condition_met"] = (comparisons[arm]["same_information_condition_met"]
                                                            and comparisons[arm]["required_deployment_condition_met"])
    final_source = source_state(ROOT, head)
    save(output/"SOURCE-AFTER.json", final_source)
    unchanged = all(digest(ROOT/path)==value for path,value in fingerprints.items())
    completed = unchanged and all(e["status"] == "completed" for e in episodes)
    for arm, row in table.items():
        if arm == "fixed_stop":
            continue
        threshold = max(1000000, math.ceil(0.01*table["fixed_stop"]["warm_deployment_ns"]["sum"]))
        row["mechanism_net_benefit_condition_met"] = {
            key: completed and row["published"] > 0 and value > threshold
            for key, value in row["direct_baseline_aggregate_saving_ns"].items()}
        row["mechanism_threshold_ns"] = threshold
    result = {"schema": "hepta.hia.economic-search-result.v1", "source_head": head, "protocol_sha256": sha256(wire(PROTOCOL)).hexdigest(),
        "source_unchanged": unchanged, "costs": costs, "table": table, "ndu_comparisons": comparisons,
        "episodes": episodes, "wall_ns": time.perf_counter_ns()-started,
        "completed": completed,
        "incremental_ndu_condition_met": completed and table["ndu"]["published"] > 0 and all(c["increment_condition_met"] for c in comparisons.values()),
        "claims": PROTOCOL["claims"]}
    save(output/"RESULT.json", result)
    print(json.dumps({"completed": result["completed"], "source_head": head,
                      "incremental_ndu_condition_met": result["incremental_ndu_condition_met"], "table": table}), flush=True)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ("output-directory", "clang", "cargo", "rustc", "cargo-home", "recursive-upstream"):
        parser.add_argument("--"+flag, type=Path, required=True)
    parser.add_argument("--expected-head", required=True)
    args = parser.parse_args()
    result = run(args)
    return 0 if result["completed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
