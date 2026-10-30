"""Read-only identity/arithmetic audit; never compiles, solves, or executes code."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from fractions import Fraction
from hashlib import sha256
import json
from pathlib import Path
import statistics


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(value):
    return sha256(wire(value)).hexdigest()


def exact(value):
    if type(value) not in (int, float):
        raise ValueError("Expected an exact finite recorded numeric cost")
    return Fraction(str(value))


def rational(value):
    value = exact(value) if type(value) in (int, float) else value
    return {"numerator": value.numerator, "denominator": value.denominator}


def run(raw_path, repository, output):
    raw_path, repository, output = map(Path, (raw_path, repository, output))
    run_root = raw_path.parent
    raw_bytes = raw_path.read_bytes()
    result = json.loads(raw_bytes)
    protocol_path = output / "PROTOCOL.json"
    registration_path = output / "REGISTRATION.json"
    protocol = json.loads(protocol_path.read_bytes())
    registration = json.loads(registration_path.read_bytes())
    checks = []

    def check(name, condition):
        checks.append({"check": name, "passed": bool(condition)})

    check("completed registered runtime run", result["status"] == "completed" and result["kind"] == "prepared-runtime")
    check("registration self binding", digest({k: v for k, v in registration.items() if k != "registration_sha256"})
          == registration["registration_sha256"] == result["registration_sha256"])
    check("retained registration bytes", (run_root / "REGISTRATION.json").read_bytes() == registration_path.read_bytes())
    check("protocol equals registration", registration["inputs"]["protocol"] == protocol)
    check("registration precedes workload start", registration["registered_before_workloads"] is True
          and registration["registered_utc_ns"] < result["host"]["started_utc_ns"])
    check("same predeclared three groups", len(protocol["queues"]) == len(result["samples"]) == 3)
    prior = repository / "experiments/hia_stateful_eval/round3_20261028/PROTOCOL.json"
    check("queue horizon unchanged from round3", json.loads(prior.read_bytes())["queues"] == protocol["queues"])
    check("shared hardware limitation retained", result["host"]["physical_machine_exclusive"] is False)
    check("unknown global costs retained", result["all_costs_known"] is False
          and registration["manual_development_cost_ns"] is None)

    bindings = registration["inputs"]["source_bindings"]
    sources = []
    for name, expected in bindings.items():
        retained = run_root / "sources" / name
        measured = retained.read_bytes()
        same = sha256(measured).hexdigest() == expected
        current = sha256((repository / name).read_bytes()).hexdigest() == expected
        check("retained source " + name, same)
        check("current source " + name, current)
        sources.append({"path": name, "bytes": len(measured), "sha256": expected,
                        "retained_matches": same, "current_matches": current})
    check("retained source count", len(sources) == result["retained_sources"]["files"])
    check("retained source bytes", sum(row["bytes"] for row in sources) == result["retained_sources"]["bytes"])
    check("source unchanged flags", result["bound_inputs_unchanged"] is True
          and result["retained_sources"]["all_bytes_match_registration"] is True)

    tool_byte_checks = []
    for name, item in (("clang executable", registration["inputs"]["clang"]),
                       ("python executable", registration["inputs"]["python"]["executable"])):
        path = Path(item["path"])
        data = path.read_bytes()
        matched = len(data) == item["bytes"] and sha256(data).hexdigest() == item["sha256"]
        check(name + " actual bytes", matched)
        tool_byte_checks.append({"tool": name, "path": str(path), "bytes": len(data), "matches": matched})
    checker_names = ("hia_optimization.py", "hia_program.py", "hia_schema.py",
                     "hia_program_composite.py", "hia_json_preflight.py",
                     "hia_program_runtime.py", "hia_bounded_memory.py")
    checker = sha256()
    for name in checker_names:
        checker.update(name.encode() + b"\0" + (run_root / "sources/hepta" / name).read_bytes() + b"\0")

    share = Fraction(result["shared_wrapper_ns"], len(result["samples"]))
    check("shared overhead nonnegative", share >= 0)
    rows, artifact_checks = [], []
    for index, sample in enumerate(result["samples"]):
        label = "group " + str(index + 1) + ": "
        profile, execution, audit, snapshot = (sample[key] for key in ("profile", "execution", "audit", "snapshot"))
        check(label + "registered profile", profile == protocol["queues"][index])
        check(label + "completed", sample["status"] == "measured" and execution["status"] == "completed")
        total = sum(item["iterations"] for item in profile["items"])
        values = list(profile["initial"])
        for item in profile["items"]:
            values[item["slot"]] = (values[item["slot"]] + 4 * item["delta"] * item["iterations"]) % 2**64
        check(label + "independent u64 oracle", execution["final_values"] == values == snapshot["state_values"])
        check(label + "full progress", execution["executed_steps"] == execution["committed_steps"] == total
              == snapshot["actual_progress"] == snapshot["state_revision"] == snapshot["completed_native_calls"])
        check(label + "zero replay", execution["replayed_steps"] == 0
              and all(item["replayed"] == 0 and item["committed"] == item["requested"] for item in execution["item_progress"]))
        check(label + "item progress", [item["committed"] for item in execution["item_progress"]]
              == [item["iterations"] for item in profile["items"]])
        queue_sha = digest(profile["items"])
        check(label + "queue identity", queue_sha == execution["queue_sha256"] == audit["queue_sha256"])
        check(label + "owner identity", execution["owner_id"] == snapshot["owner_id"]
              and execution["allocation_identity"] == snapshot["allocation_identity"])
        check(label + "known costs and unpoisoned state", execution["cost_accounting_complete"] is True
              and snapshot["cost_accounting_complete"] is True and snapshot["state_poisoned"] is False)
        check(label + "no execution or diagnostic error", execution["error"] is None and execution["diagnostic_errors"] == [])
        check(label + "quiescent owner", snapshot["active_calls"] == snapshot["preparing"] == snapshot["live_loans"] == 0)
        for stage, ledger in (("execution", execution["native_ledger"]), ("post-audit", snapshot["native_ledger"]),
                              ("closed", sample["final_native_ledger"])):
            check(label + stage + " resource conservation", ledger["allocations"] - ledger["frees"] == ledger["live"])
        check(label + "closed balanced resources", sample["final_native_ledger"] == {"allocations": 24, "frees": 24, "live": 0, "refusals": 0})
        check(label + "counterfactual is separate", audit["application_work_replayed"] is False
              and audit["decision_authority"] is False and audit["final_state_matches"] is True)
        check(label + "external search not executed", sample["unexecuted_external_llm_ndu_search_cost_ns"] is None)

        native_sum = sum(execution[key] for key in ("unamortized_preparation_ns", "calibration_verification_switch_ns",
                                                     "application_execution_ns", "commit_bookkeeping_ns")) + execution.get("restoration_cost_ns", 0)
        check(label + "internal receipt arithmetic", native_sum == execution["deployment_cost_ns"]
              == execution["cumulative_deployment_cost_ns"] == audit["deployment_cost_ns"])
        check(label + "entire API arithmetic", sample["total_experiment_api_ns"] - sample["audit_entire_api_ns"]
              == sample["deployment_entire_api_ns"])
        check(label + "outer API covers receipt", sample["deployment_entire_api_ns"] - native_sum
              == sample["additional_outer_overhead_ns"] >= 0)
        baseline = sample["baseline_native_execution_ns"]
        check(label + "baseline identity and audit envelope", baseline == audit["baseline_native_execution_ns"]
              <= audit["audit_experiment_cost_ns"] <= sample["audit_entire_api_ns"])
        check(label + "counterfactual receipt arithmetic", baseline - native_sum == audit["measured_deployment_net_ns"]
              and native_sum + audit["audit_experiment_cost_ns"] == audit["total_experiment_cost_ns"])
        check(label + "API net arithmetic", baseline - sample["deployment_entire_api_ns"] == sample["measured_net_ns"])
        checked_cost = sample["runner_complete_sample_ns"] - sample["audit_entire_api_ns"]
        check(label + "validation and evidence envelope", checked_cost == sample["deployment_plus_validation_and_evidence_ns"]
              >= sample["deployment_entire_api_ns"])
        check(label + "evidence timer nesting", sample["runner_complete_sample_ns"] >=
              sample["runner_until_record_ns"] + sample["sample_report_encoding_write_ns"])
        check(label + "validation and evidence net", baseline - checked_cost == sample["net_after_validation_and_evidence_ns"])
        complete_cost = Fraction(checked_cost) + share
        net = Fraction(baseline) - complete_cost
        check(label + "equal rational wrapper share", exact(sample["shared_wrapper_allocated_ns"]) == share)
        check(label + "complete cost arithmetic", exact(sample["complete_measured_deployment_ns"]) == complete_cost)
        check(label + "complete net arithmetic", exact(sample["complete_measured_net_ns"]) == net)
        check(label + "net sign", sample["deployment_net_positive"] is (sample["measured_net_ns"] > 0))

        measurement = execution["measurement"]
        rounds = measurement["rounds"]
        check(label + "five registered calibration pairs", len(rounds) == profile["calibration_rounds"] == 5)
        sample_steps = sum(min(item["iterations"], max(1, profile["calibration_sample_steps"] * item["iterations"] // total))
                           for item in profile["items"])
        check(label + "calibration sample extent", sample_steps == measurement["sample_steps"])
        saving = min(pair["baseline_ns"] - pair["candidate_ns"] for pair in rounds) * total // sample_steps
        estimate = min(pair["baseline_ns"] for pair in rounds) * total // sample_steps
        check(label + "forecast recomputed from every pair", saving == measurement["projected_saving_ns"]
              and estimate == measurement["baseline_estimate_ns"])
        check(label + "forecast net arithmetic", estimate - native_sum == execution["observed_net_against_baseline_forecast_ns"])
        selected = saving > execution["unamortized_preparation_ns"] + measurement["measurement_cost_ns"]
        check(label + "actual no-selection reason", selected is False and sample["automatic_selected"] is False
              and execution["automatic_selection"] is False and execution["selection_reason"] == "nonpositive_empirical_queue_forecast"
              and execution["version"] == execution["original_version"] == snapshot["current"] == "baseline")

        saved_sample = json.loads((run_root / ("sample-" + str(index) + ".json")).read_bytes())
        check(label + "earlier per-sample raw record retained", all(sample[key] == value for key, value in saved_sample.items()))
        for token, build in sample["builds"].items():
            verification, native = build["verification"], build["native"]
            check(label + token + " verification digest", digest({k: v for k, v in verification.items() if k != "verification_sha256"})
                  == verification["verification_sha256"])
            check(label + token + " verified obligations", verification["status"] == "verified"
                  and verification["checker_sha256"] == checker.hexdigest()
                  and verification["solver"] == registration["inputs"]["solver"]
                  and all(obligation["result"] == "unsat" for obligation in verification["obligations"]))
            check(label + token + " SMT text hashes", all(sha256(obligation["smt2"].encode()).hexdigest() == obligation["smt2_sha256"]
                  for obligation in verification["obligations"]))
            check(label + token + " Core and policy binding", native["core_sha256"] == verification["candidate_sha256"]
                  and digest(verification["policy"]) == verification["policy_sha256"])
            check(label + token + " artifact receipt binding", build["binding_sha256"] == digest({
                "base": verification["base_sha256"], "candidate": native["core_sha256"],
                "verification": verification["verification_sha256"], "artifact": native["artifact_sha256"],
                "compiler": native["toolchain"]["sha256"], "target": native["target"]}))
            path = run_root / ("runtime-" + str(index)) / (token + ".so")
            data = path.read_bytes()
            matched = len(data) == native["artifact_bytes"] and sha256(data).hexdigest() == native["artifact_sha256"]
            check(label + token + " actual ELF", matched and data.startswith(b"\x7fELF"))
            check(label + token + " compiler identity", native["toolchain"]["sha256"] == registration["inputs"]["clang"]["sha256"])
            artifact_checks.append({"path": str(path.relative_to(run_root)), "bytes": len(data),
                                    "sha256": sha256(data).hexdigest(), "matches_receipt": matched})
        candidate_native = sample["builds"][measurement["candidate"]]["native"]
        check(label + "measured candidate identity", measurement["artifact_sha256"] == candidate_native["artifact_sha256"])
        driver = run_root / ("runtime-" + str(index)) / "owned-driver.so"
        driver_source = driver.with_suffix(".c")
        data = driver.read_bytes()
        matched = sha256(data).hexdigest() == sample["driver"]["artifact_sha256"]
        check(label + "actual owner driver ELF", matched and data.startswith(b"\x7fELF"))
        check(label + "actual owner driver source", sha256(driver_source.read_bytes()).hexdigest() == sample["driver"]["source_sha256"])
        artifact_checks.append({"path": str(driver.relative_to(run_root)), "bytes": len(data),
                                "sha256": sha256(data).hexdigest(), "matches_receipt": matched})
        rows.append({"group": index + 1, "updates": total, "baseline_native_execution_ns": baseline,
                     "deployment_entire_api_ns": sample["deployment_entire_api_ns"],
                     "deployment_plus_validation_and_evidence_ns": checked_cost,
                     "shared_wrapper_allocated_ns_exact": rational(share),
                     "complete_measured_deployment_ns_exact": rational(complete_cost),
                     "complete_measured_net_ns_exact": rational(net),
                     "automatic_selected": sample["automatic_selected"], "forecast_saving_ns": saving,
                     "cost_accounting_complete": True, "state_poisoned": False, "replayed_steps": 0,
                     "final_native_ledger": sample["final_native_ledger"]})

    samples = result["samples"]
    gate = all(row["automatic_selected"] and row["deployment_net_positive"] and exact(row["complete_measured_net_ns"]) > 0
               for row in samples)
    check("scientific gate recomputed and negative", gate is False and result["finite_net_benefit_gate_passed"] is gate)
    check("implementation gate recomputed", all(row["status"] == "measured" for row in samples) is result["implementation_gate_passed"])
    check("wrapper allocation conserved", sum(exact(row["shared_wrapper_allocated_ns"]) for row in samples) == result["shared_wrapper_ns"])
    for field, sample_field in (("median_baseline_execution_ns", "baseline_native_execution_ns"),
                                ("median_deployment_api_ns", "deployment_entire_api_ns"),
                                ("median_measured_net_ns", "measured_net_ns")):
        check(field + " recomputed", statistics.median(row[sample_field] for row in samples) == result[field])
    tail = result["runner_wall_ns_before_final_report"] - sum(row["runner_complete_sample_ns"] for row in samples) - result["shared_wrapper_ns"]
    check("post-gate timing tail nonnegative", tail >= 0)
    totals = {
        "updates": sum(row["updates"] for row in rows),
        "baseline_native_execution_ns": sum(row["baseline_native_execution_ns"] for row in rows),
        "complete_measured_deployment_ns_exact": rational(sum(exact(row["complete_measured_deployment_ns"]) for row in samples)),
        "complete_measured_net_ns_exact": rational(sum(exact(row["complete_measured_net_ns"]) for row in samples)),
        "automatic_selections": sum(row["automatic_selected"] for row in rows),
        "allocations": sum(row["final_native_ledger"]["allocations"] for row in rows),
        "frees": sum(row["final_native_ledger"]["frees"] for row in rows),
        "live_after_close": sum(row["final_native_ledger"]["live"] for row in rows),
        "separate_counterfactual_audit_api_ns": sum(row["audit_entire_api_ns"] for row in samples),
        "shared_wrapper_ns": result["shared_wrapper_ns"],
        "runner_wall_ns_before_final_report": result["runner_wall_ns_before_final_report"],
        "post_gate_unallocated_timing_tail_ns": tail,
    }
    audit = {"schema": "hepta.hia.runtime.round4.independent-cost-audit.v1",
             "recorded_utc": datetime.now(timezone.utc).isoformat(),
             "audit_authority": "independent read-only arithmetic/source/artifact review; no deployment authority",
             "passed": all(row["passed"] for row in checks), "check_count": len(checks),
             "failed_checks": [row["check"] for row in checks if not row["passed"]],
             "raw_result": {"path": str(raw_path), "bytes": len(raw_bytes), "sha256": sha256(raw_bytes).hexdigest()},
             "registration_sha256": registration["registration_sha256"],
             "registration_file_sha256": sha256(registration_path.read_bytes()).hexdigest(),
             "protocol_file_sha256": sha256(protocol_path.read_bytes()).hexdigest(),
             "audit_script_sha256": sha256(Path(__file__).read_bytes()).hexdigest(),
             "source_checks": sources, "tool_byte_checks": tool_byte_checks, "artifact_byte_checks": artifact_checks,
             "checks": checks, "groups": rows, "totals": totals,
             "implementation_gate_passed": result["implementation_gate_passed"],
             "finite_net_benefit_gate_passed": gate,
             "scope": {"native_or_solver_execution_performed": False, "large_archives_read_or_compressed": False,
                       "solver_library_rehashed_by_this_audit": False,
                       "solver_identity_checked_against_registration_and_six_verification_receipts": True,
                       "live_loaded_mappings_revalidated_after_process_exit": False,
                       "serialized_receipts_grant_authority": False,
                       "whole_sysroot_os_hardware_closure_verified": False,
                       "all_global_costs_known": False}}
    audit_path = output / "ROOT_COST_AUDIT.json"
    audit_path.write_text(json.dumps(audit, indent=2, sort_keys=True) + "\n")
    readout = {"schema": "hepta.hia.runtime.round4.readout.v1",
               "recorded_utc": audit["recorded_utc"], "status": result["status"],
               "raw_result_sha256": audit["raw_result"]["sha256"],
               "registration_sha256": registration["registration_sha256"],
               "audit_sha256": sha256(audit_path.read_bytes()).hexdigest(),
               "integrity_and_arithmetic_audit_passed": audit["passed"],
               "implementation_gate_passed": result["implementation_gate_passed"],
               "finite_net_benefit_gate_passed": gate,
               "automatic_selections": totals["automatic_selections"], "groups": rows, "totals": totals,
               "qualification": "All three unchanged registered queues execute correctly with zero replay and balanced native owners; all three automatic selections are false and complete measured net benefits are negative.",
               "host": result["host"],
               "scope": {"workload_horizon_changed": False, "reruns_or_exclusions_used": False,
                         "three_observations_establish_population_superiority": False,
                         "replication_overrides_prior_positive_or_negative_evidence": False,
                         "replication_identifies_causal_effect_of_runtime_repairs": False,
                         "general_heap_or_external_io_migration_proved": False,
                         "performance_advantage_established": False, "deployment_authority": False,
                         "all_global_costs_known": False,
                         "excluded_costs": protocol["excluded_costs"],
                         "unexecuted_external_llm_ndu_search_cost_ns": None,
                         "cost_note": "Nested phase costs are not added twice. The separate initial-owner counterfactual audit is not application replay. Shared wrapper cost is equally charged. The observed post-gate tail remains explicit; charging it worsens the already negative aggregate net."}}
    (output / "READOUT.json").write_text(json.dumps(readout, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"passed": audit["passed"], "checks": len(checks), "failed_checks": audit["failed_checks"],
                      "totals": totals, "audit_sha256": readout["audit_sha256"],
                      "readout_sha256": sha256((output / "READOUT.json").read_bytes()).hexdigest()}))
    return 0 if audit["passed"] else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw", type=Path, required=True)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path(__file__).parent)
    args = parser.parse_args()
    raise SystemExit(run(args.raw, args.repository, args.output))
