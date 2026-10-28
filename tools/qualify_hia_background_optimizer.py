#!/usr/bin/env python3
"""Run real NDU -> proof -> conditional native publication, with bounded claims."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from hepta.hia_background_optimizer import BackgroundOptimizer
from hepta.hia_multiversion import ScalarMultiversionRuntime
from hepta.hia_program import SCHEMA as PROGRAM_SCHEMA, verify_program
from hepta.hia_program_llvm import TARGET


SCHEMA = "hepta.hia.background-optimization-qualification.v1"
ROOT = Path(__file__).resolve().parents[1]
_SOURCES = ("hepta/hia_background_optimizer.py", "hepta/hia_multiversion.py",
            "hepta/hia_native_retirement.py", "hepta/native_mapping_identity.py",
            "hepta/hia_ndu_optimizer.py", "hepta/hia_translation_validation.py",
            "hepta/hia_program.py", "hepta/hia_program_runtime.py", "hepta/hia_program_llvm.py",
            "hepta/elf_shared_abi.py", "tools/build_hia_ndu_bridge.py",
            "tools/qualify_hia_background_optimizer.py", "rust/hia-ndu-bridge/upstream.json",
            "rust/hia-ndu-bridge/Cargo.toml", "rust/hia-ndu-bridge/Cargo.lock",
            "rust/hia-ndu-bridge/src/main.rs")


def source_identity():
    return {name: sha256((ROOT / name).read_bytes()).hexdigest() for name in _SOURCES}


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def program(*, identity=False, constant=0):
    parameter = {"name": "x", "type": "u64"}
    operations = [] if identity else [
        {"op": "const", "args": [], "out": [{"name": "zero", "type": "u64"}],
         "attrs": {"value": constant}},
        {"op": "int.add.wrap", "args": ["x", "zero"],
         "out": [{"name": "result", "type": "u64"}], "attrs": {}}]
    return {"schema": PROGRAM_SCHEMA, "module": "background_qualification", "functions": [
        {"name": "calculate", "params": [parameter], "returns": ["u64"], "effects": [],
         "entry": "entry", "blocks": [{"id": "entry", "params": [parameter], "ops": operations,
                                       "term": {"op": "ret", "values": ["x" if identity else "result"]}}]}]}


def measure(runtime):
    """Host lease-call timing samples; empirical spread is not a proven bound."""
    started = time.perf_counter_ns()
    samples, calls = [], 0
    with runtime.lease() as lease:
        for value in range(128):
            require(lease.call("calculate", [value]) == value, "warmup native result differs")
            calls += 1
        for batch in range(7):
            sample_started = time.perf_counter_ns()
            for index in range(1024):
                value = (batch * 1024 + index) * 0x100000001
                require(lease.call("calculate", [value]) == value, "timed native result differs")
            elapsed = time.perf_counter_ns() - sample_started
            samples.append({"calls": 1024, "wall_ns": elapsed,
                            "ceil_ns_per_call": (elapsed + 1023) // 1024})
            calls += 1024
    median = int(statistics.median(row["ceil_ns_per_call"] for row in samples))
    radius = max(abs(row["ceil_ns_per_call"] - median) for row in samples)
    return {"runtime_ns": median, "uncertainty_ns": radius,
            "measurement_wall_ns": time.perf_counter_ns() - started,
            "native_calls": calls, "samples": samples,
            "scope": "Python lease validation plus native scalar call host elapsed time",
            "uncertainty_is_formal_bound": False}


def observation(document, runtime_ns, *, uncertainty_ns=0, search_ns=0):
    return {"runtime_ns": runtime_ns, "uncertainty_ns": uncertainty_ns,
            "search_ns": search_ns, "program_sha256": verify_program(document).sha256}


def goal(profile, calls):
    return {"expected_calls": calls, "resource_cap_ns": 30_000_000_000,
            "target": TARGET, "measurement_profile": profile}


def qualify(clang, bridge, bridge_build_receipt):
    started = time.perf_counter_ns()
    sources_before = source_identity()
    clang_version = subprocess.run([clang, "--version"], check=True, capture_output=True,
                                   text=True, timeout=30).stdout.splitlines()[0]
    import z3
    bridge_spec = {"binary": Path(bridge).resolve(), "build_receipt": Path(bridge_build_receipt).resolve()}
    baseline, candidate, wrong = program(), program(identity=True), program(constant=1)
    candidates = [{"id": "remove_identity", "action": "remove_wrapping_add_zero", "program": candidate}]
    native_observations = []
    with tempfile.TemporaryDirectory(prefix="hia-background-qualification-") as directory:
        build_started = time.perf_counter_ns()
        with ScalarMultiversionRuntime(baseline, directory, clang=clang) as runtime:
            baseline_build_ns = time.perf_counter_ns() - build_started
            measured_baseline = measure(runtime)
            build_started = time.perf_counter_ns()
            with ScalarMultiversionRuntime(candidate, directory, clang=clang) as measured_runtime:
                candidate_build_ns = time.perf_counter_ns() - build_started
                measured_candidate = measure(measured_runtime)
                measured_candidate_generation = measured_runtime.snapshot()["generations"][0]
            measured_candidate_closed = measured_runtime.snapshot()
            require(measured_candidate_closed["closed"] and not measured_candidate_closed["generations"],
                    "measurement candidate generations survived close")
            require(measured_candidate_closed["cleanup"]["observed_closed_and_directory_absent"]
                    and measured_candidate_closed["cleanup"]["pending_resource_count"] == 0,
                    "measurement candidate post-close cleanup was not observed complete")
            setup_started = time.perf_counter_ns()
            with BackgroundOptimizer(runtime, baseline, function="calculate", bridge=bridge_spec,
                                     max_pending=2) as coordinator:
                coordinator_setup_ns = time.perf_counter_ns() - setup_started
                measured = {
                    "abstain": observation(baseline, measured_baseline["runtime_ns"],
                                            uncertainty_ns=measured_baseline["uncertainty_ns"],
                                            search_ns=baseline_build_ns + measured_baseline["measurement_wall_ns"]
                                            + coordinator_setup_ns),
                    "remove_identity": observation(candidate, measured_candidate["runtime_ns"],
                                                    uncertainty_ns=measured_candidate["uncertainty_ns"],
                                                    search_ns=candidate_build_ns + measured_candidate["measurement_wall_ns"])}
                actual_trial = coordinator.submit(candidates, measured,
                                                  goal("measured_host_lease_7x1024_finite_horizon", 1)).result(60)
                require(actual_trial["status"] == "abstained", "one-call measured horizon did not abstain")
                require(actual_trial["ranking"]["native_response"]["authority"] == "ADVISORY_ONLY",
                        "measured trial did not execute the original NDU bridge")
                require(runtime.snapshot()["current_generation"] == 0, "measured abstention changed selection")

                # These economic inputs intentionally exercise publication.
                # They are explicitly synthetic and establish no real speedup.
                controls = candidates + [{"id": "wrong_behavior", "action": "invalid_add_one", "program": wrong}]
                controlled = {"abstain": observation(baseline, 1_000_000),
                              "remove_identity": observation(candidate, 1),
                              "wrong_behavior": observation(wrong, 0)}
                controlled_trial = coordinator.submit(controls, controlled,
                                                       goal("synthetic_cost_lifecycle_control_not_speedup", 100_000)).result(60)
                require(controlled_trial["status"] == "published", "controlled candidate did not publish: " + str(controlled_trial))
                require(controlled_trial["selected_id"] == "remove_identity", "wrong candidate was selected")
                publication = controlled_trial["publication"]
                require(publication["generation"]["translation_proofs"] == 1,
                        "publication omitted its independent proof")
                require(0 < publication["prepare_ns"] <= publication["max_prepare_ns"],
                        "actual publication cost exceeded its pre-swap budget")
                require(controlled_trial["costs"]["net_margin_before_postcommit_reporting_ns"] > 0,
                        "publication had no positive modeled pre-report margin")
                reports = {row["id"]: row for row in controlled_trial["ranking"]["candidate_reports"]}
                require(reports["wrong_behavior"]["proof"]["status"] == "disproved",
                        "cheap behavior-changing candidate lacked an actual counterexample")
                for value in (0, 1, 2**63, 2**64 - 1):
                    actual = runtime.call("calculate", [value])
                    require(type(actual) is int and actual == value, "published native output differs")
                    native_observations.append({"generation": publication["generation"]["generation"],
                                                "argument": value, "result": actual})

                before_rejection = runtime.snapshot()
                bad_candidate = [{"id": "wrong_behavior", "action": "invalid_add_one", "program": wrong}]
                refused = coordinator.submit(bad_candidate,
                                              {"abstain": observation(candidate, 1_000_000),
                                               "wrong_behavior": observation(wrong, 0)},
                                              goal("synthetic_cost_invalid_behavior_control", 100_000)).result(60)
                require(refused["status"] == "abstained", "wrong behavior was not refused")
                require(refused["ranking"]["candidate_reports"][0]["proof"]["status"] == "disproved",
                        "subsequent wrong behavior lacked a fresh counterexample")
                after_rejection = runtime.snapshot()
                require((before_rejection["current_generation"], before_rejection["selection_epoch"])
                        == (after_rejection["current_generation"], after_rejection["selection_epoch"]),
                        "rejected background decision replaced the incumbent")
                coordinator.shutdown(cancel_pending=False)
                drained = coordinator.snapshot()
                require(drained["outstanding"] == 0 and not drained["worker_alive"], "worker did not drain")
                require(runtime.call("calculate", [113]) == 113, "coordinator shutdown closed caller runtime")
                final = runtime.snapshot()
        closed = runtime.snapshot()
        require(closed["closed"] and not closed["generations"], "native generations survived final close")
        require(closed["cleanup"]["observed_closed_and_directory_absent"],
                "post-close owned native/file/directory cleanup was not observed complete")
    sources_after = source_identity()
    require(sources_before == sources_after, "qualification source changed during execution")
    trials = [actual_trial, controlled_trial, refused]
    require(len({trial["ranking"]["request_sha256"] for trial in trials}) == 3,
            "fresh NDU decisions did not bind three distinct requests")
    return {"schema": SCHEMA, "ok": True, "observed_utc": datetime.now(timezone.utc).isoformat(),
            "host": {"system": platform.system(), "machine": platform.machine(),
                     "python": sys.version.split()[0], "z3": z3.get_version_string(), "clang": clang_version},
            "source_sha256": sources_before, "source_unchanged": True,
            "programs": {"baseline": baseline, "candidate": candidate, "wrong_behavior": wrong},
            "measurements": {"baseline": measured_baseline, "candidate": measured_candidate,
                             "baseline_build_ns": baseline_build_ns, "candidate_build_ns": candidate_build_ns,
                             "coordinator_setup_ns": coordinator_setup_ns,
                             "measurement_candidate_generation": measured_candidate_generation,
                             "measurement_candidate_after_close": measured_candidate_closed,
                             "cold_build_cost_charged_once_to_first_horizon": True},
            "trials": {"measured_finite_horizon": actual_trial,
                       "synthetic_cost_lifecycle": controlled_trial,
                       "subsequent_behavior_change": refused},
            "actual_native_ndu_invocations": 3,
            "native_measurement_calls": measured_baseline["native_calls"] + measured_candidate["native_calls"],
            "native_observations": native_observations,
            "snapshot_after_rejection": after_rejection, "snapshot_after_drain": drained,
            "snapshot_before_runtime_close": final, "snapshot_after_runtime_close": closed,
            "wall_ns": time.perf_counter_ns() - started,
            "claims": {"actual_ndu_execution": True, "actual_native_publication": True,
                       "fresh_publication_proof": True, "measured_finite_horizon_abstention": True,
                       "performance_improvement_established": False, "measurements_independently_attested": False,
                       "synthetic_costs_are_benchmark_results": False, "resource_state_migration": False,
                       "general_live_code_patch": False, "backend_refinement_proved": False,
                       "whole_language_soundness_proved": False, "global_optimality_established": False}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--clang", default=os.environ.get("HEPTA_CLANG", "clang"))
    parser.add_argument("--bridge", required=True, type=Path)
    parser.add_argument("--bridge-build-receipt", required=True, type=Path)
    parser.add_argument("--output", type=Path, help="new JSON receipt path; existing files are never replaced")
    options = parser.parse_args()
    result = qualify(options.clang, options.bridge, options.bridge_build_receipt)
    packed = json.dumps(result, sort_keys=True, indent=2) + "\n"
    if options.output:
        with options.output.open("x", encoding="utf-8") as stream:
            stream.write(packed)
        print(json.dumps({"schema": SCHEMA, "ok": True, "output": str(options.output),
                          "sha256": sha256(packed.encode()).hexdigest()}, sort_keys=True))
    else:
        print(packed, end="")


if __name__ == "__main__":
    main()
