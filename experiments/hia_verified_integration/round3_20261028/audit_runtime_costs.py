"""Independently audit retained runtime arithmetic; never execute a workload.

Uses only the standard library and arithmetic over existing JSON/source bytes.
It does not import the evaluator, compile, invoke a solver, load native code,
decompress archives, or change any recorded outcome.
"""
from __future__ import annotations

import argparse
from fractions import Fraction
from hashlib import sha256
import json
from pathlib import Path
import statistics
import time

ROOT = Path(__file__).resolve().parents[3]
STUDY = ROOT / "experiments/hia_stateful_eval/round3_20261028"


def read(path):
    return json.loads(Path(path).read_bytes())


def digest(value):
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                             allow_nan=False).encode()).hexdigest()


def identity(path):
    path = Path(path)
    data = path.read_bytes()
    return {"bytes": len(data), "sha256": sha256(data).hexdigest()}


def fraction_record(value):
    value = Fraction(value)
    return {"numerator": value.numerator, "denominator": value.denominator}


def audit(source, output, summary=None):
    started = time.monotonic_ns()
    source = Path(source).resolve(strict=True)
    output = Path(output).absolute()
    if output.exists():
        raise FileExistsError("Do not overwrite an independent audit")
    raw = (source / "RESULT.json").read_bytes()
    result = json.loads(raw)
    checks, groups = {}, []
    report = {
        "schema": "hepta.hia.prepared-runtime.independent-cost-audit.v1",
        "kind": "prepared-runtime", "reviewer": "/root/agent_protocol",
        "raw_result_sha256": sha256(raw).hexdigest(), "raw_result_bytes": len(raw),
        "source": str(source), "audit_source": identity(__file__),
        "checks": checks, "groups": groups, "native_calls": 0,
        "model_calls": 0, "compilations": 0, "solver_calls": 0,
        "archive_compression_or_extraction": False,
        "raw_results_or_scores_modified": False,
        "scope": "Independent arithmetic and evidence-identity review of retained finite results; not independent native re-execution or a proof of timer coverage, compiler soundness, or hardware behavior.",
    }

    def check(name, condition):
        checks[name] = bool(condition)
        if not condition:
            raise ValueError(name)

    def equal_ns(name, recorded, expected):
        # A shared integral duration divided across three groups is rational.
        # Recorded JSON floats may round below one nanosecond; gate signs are
        # also recomputed from exact rationals independently below.
        check(name, abs(Fraction(recorded) - Fraction(expected)) <= 1)

    try:
        check("raw_schema_and_kind", result["schema"] == "hepta.hia.registered-followup.result.v1"
              and result["kind"] == "prepared-runtime")
        registration = read(source / "REGISTRATION.json")
        declared = read(STUDY / "REGISTRATION.json")
        protocol = read(STUDY / "PROTOCOL.json")
        report["registration_file"] = identity(STUDY / "REGISTRATION.json")
        report["protocol_file"] = identity(STUDY / "PROTOCOL.json")
        check("registration_identical_to_declared", registration == declared)
        check("registration_self_digest", registration["registration_sha256"] == digest(
            {k: v for k, v in registration.items() if k != "registration_sha256"}))
        check("raw_registration_identity", result["registration_sha256"] == registration["registration_sha256"])
        check("registered_protocol", registration["inputs"]["protocol"] == protocol
              and protocol["kind"] == "prepared-runtime")
        check("registered_before_workloads", registration["registered_before_workloads"] is True
              and registration["registered_utc_ns"] < result["host"]["started_utc_ns"])
        bindings = registration["inputs"]["source_bindings"]
        source_bytes = 0
        for name, wanted in bindings.items():
            relative = Path(name)
            check("source_path:" + name, not relative.is_absolute() and ".." not in relative.parts)
            observed = identity(source / "sources" / relative)
            source_bytes += observed["bytes"]
            check("retained_source:" + name, observed["sha256"] == wanted)
        check("retained_source_census", result["retained_sources"] == {
            "files": len(bindings), "bytes": source_bytes, "all_bytes_match_registration": True})
        report["registered_source_files_checked"] = len(bindings)
        check("completed_bound_observation", result["status"] == "completed"
              and result["bound_inputs_unchanged"] is True)
        check("unknown_whole_economic_cost_retained", result["all_costs_known"] is False)
        profiles, rows = protocol["queues"], result["samples"]
        check("complete_registered_three_group_denominator", len(rows) == len(profiles) == 3)
        common = result["shared_wrapper_ns"]
        check("shared_wrapper_nonnegative_integral", type(common) is int and common >= 0)
        allocated = Fraction(common, len(rows))
        official_gate_parts, exact_gate_parts = [], []
        for index, (profile, row) in enumerate(zip(profiles, rows)):
            prefix = f"group{index}:"
            check(prefix + "same_profile", row["profile"] == profile and row["status"] == "measured")
            prefix_record = read(source / f"sample-{index}.json")
            check(prefix + "raw_sample_prefix_unchanged", all(row.get(k) == v for k, v in prefix_record.items()))
            execution, counterfactual = row["execution"], row["audit"]
            steps = sum(item["iterations"] for item in profile["items"])
            values = list(profile["initial"])
            for item in profile["items"]:
                # The registered transition calls add_step four times.
                slot = item["slot"]
                values[slot] = (values[slot] + 4 * item["delta"] * item["iterations"]) % (1 << 64)
            check(prefix + "complete_queue_without_replay", execution["status"] == "completed"
                  and execution["committed_steps"] == execution["executed_steps"] == steps
                  and execution["replayed_steps"] == 0)
            check(prefix + "per_item_progress", execution["item_progress"] == [
                {"item": i, "requested": item["iterations"], "committed": item["iterations"], "replayed": 0}
                for i, item in enumerate(profile["items"])])
            check(prefix + "independent_modular_final_state", execution["final_values"] == values)
            snapshot = row["snapshot"]
            check(prefix + "owner_and_allocation_identity_preserved", snapshot["owner_id"] == execution["owner_id"]
                  and snapshot["allocation_identity"] == execution["allocation_identity"]
                  and snapshot["state_values"] == values and snapshot["active_calls"] == 0 and snapshot["live_loans"] == 0)
            check(prefix + "separate_baseline_matches_queue", counterfactual["queue_sha256"] == execution["queue_sha256"]
                  and counterfactual["final_state_matches"] is True
                  and counterfactual["decision_authority"] is False
                  and counterfactual["application_work_replayed"] is False)
            ledger = row["final_native_ledger"]
            check(prefix + "balanced_recorded_native_ledger", ledger["live"] == 0
                  and ledger["allocations"] == ledger["frees"])
            check(prefix + "automatic_selection_field", type(row["automatic_selected"]) is bool
                  and row["automatic_selected"] == execution["automatic_selection"])
            check(prefix + "selected_version_is_different", not row["automatic_selected"]
                  or execution["version"] != execution["original_version"])
            inner_components = {name: execution.get(name, 0) for name in (
                "unamortized_preparation_ns", "calibration_verification_switch_ns",
                "application_execution_ns", "commit_bookkeeping_ns", "restoration_cost_ns")}
            check(prefix + "nonnegative_integral_inner_costs", all(type(v) is int and v >= 0 for v in inner_components.values()))
            inner = sum(inner_components.values())
            check(prefix + "inner_deployment_components", execution["deployment_cost_ns"] == inner
                  and execution["cumulative_deployment_cost_ns"] == inner
                  and counterfactual["deployment_cost_ns"] == inner)
            baseline = counterfactual["baseline_native_execution_ns"]
            check(prefix + "baseline_time_identity", row["baseline_native_execution_ns"] == baseline)
            check(prefix + "baseline_internal_audit_arithmetic", counterfactual["measured_deployment_net_ns"] == baseline - inner
                  and counterfactual["total_experiment_cost_ns"] == inner + counterfactual["audit_experiment_cost_ns"])
            audit_api = row["audit_entire_api_ns"]
            check(prefix + "audit_time_nesting", audit_api >= counterfactual["audit_experiment_cost_ns"] >= baseline >= 0)
            deployment = row["total_experiment_api_ns"] - audit_api
            check(prefix + "full_api_deployment", row["deployment_entire_api_ns"] == deployment
                  and deployment >= inner and row["additional_outer_overhead_ns"] == deployment - inner)
            net = baseline - deployment
            check(prefix + "full_api_net", row["measured_net_ns"] == net
                  and row["deployment_net_positive"] == (net > 0))
            complete_sample = row["runner_complete_sample_ns"]
            check(prefix + "runner_time_nesting", complete_sample >= row["runner_until_record_ns"] + row["sample_report_encoding_write_ns"]
                  and row["runner_until_record_ns"] >= row["total_experiment_api_ns"])
            strict = complete_sample - audit_api
            check(prefix + "validation_evidence_cost", row["deployment_plus_validation_and_evidence_ns"] == strict
                  and row["net_after_validation_and_evidence_ns"] == baseline - strict)
            equal_ns(prefix + "shared_allocation", row["shared_wrapper_allocated_ns"], allocated)
            complete = Fraction(strict) + allocated
            complete_net = Fraction(baseline) - complete
            equal_ns(prefix + "complete_deployment", row["complete_measured_deployment_ns"], complete)
            equal_ns(prefix + "complete_net", row["complete_measured_net_ns"], complete_net)
            official_gate_parts.append(row["automatic_selected"] and row["deployment_net_positive"]
                                       and row["complete_measured_net_ns"] > 0)
            exact_gate_parts.append(row["automatic_selected"] and net > 0 and complete_net > 0)
            selected_events = [event for event in row["snapshot"].get("events", [])
                if event.get("event") == "selected" and event.get("proof_reuse", {}).get("new_solver_call") is False]
            groups.append({"index": index, "profile": profile, "raw_sample_file": identity(source / f"sample-{index}.json"),
                "executed_steps": steps, "replayed_steps": 0, "expected_final_values": values,
                "final_native_ledger": ledger, "automatic_selected": row["automatic_selected"],
                "restored_after_forecast_loss": execution.get("restored_after_forecast_loss", False),
                "observed_net_against_baseline_forecast_ns": execution["observed_net_against_baseline_forecast_ns"],
                "final_current_version": snapshot["current"],
                "proof_reuse_selection_count": len(selected_events), "inner_components_ns": inner_components,
                "inner_deployment_ns": inner, "baseline_native_execution_ns": baseline,
                "audit_entire_api_ns": audit_api, "deployment_entire_api_ns": deployment,
                "measured_net_ns": net, "runner_complete_sample_ns": complete_sample,
                "deployment_plus_validation_and_evidence_ns": strict,
                "shared_wrapper_allocated_rational_ns": fraction_record(allocated),
                "complete_measured_deployment_ns": row["complete_measured_deployment_ns"],
                "complete_measured_net_ns": row["complete_measured_net_ns"],
                "exact_complete_deployment_rational_ns": fraction_record(complete),
                "exact_complete_net_rational_ns": fraction_record(complete_net),
                "exact_complete_gate_passed": exact_gate_parts[-1]})
        implementation = all(row["status"] == "measured" for row in rows)
        finite_gate = all(official_gate_parts)
        check("recorded_implementation_gate", result["implementation_gate_passed"] == implementation)
        check("recorded_finite_net_benefit_gate", result["finite_net_benefit_gate_passed"] == finite_gate)
        check("rational_gate_agrees_with_registered_float_gate", all(exact_gate_parts) == finite_gate)
        for key, field in (("median_deployment_api_ns", "deployment_entire_api_ns"),
                           ("median_baseline_execution_ns", "baseline_native_execution_ns"),
                           ("median_measured_net_ns", "measured_net_ns")):
            check(key, result[key] == statistics.median(row[field] for row in rows))
        sum_sample = sum(row["runner_complete_sample_ns"] for row in rows)
        post_gate_tail = result["runner_wall_ns_before_final_report"] - sum_sample - common
        check("nonnegative_post_gate_runner_tail", post_gate_tail >= 0)
        total_strict = sum(row["deployment_plus_validation_and_evidence_ns"] for row in rows) + common
        total_baseline = sum(row["baseline_native_execution_ns"] for row in rows)
        report.update(
            recorded_implementation_gate=result["implementation_gate_passed"],
            recomputed_implementation_gate=implementation,
            recorded_finite_net_benefit_gate=result["finite_net_benefit_gate_passed"],
            recomputed_finite_net_benefit_gate=finite_gate,
            planned_groups=len(profiles), observed_groups=len(rows),
            executed_steps_total=sum(g["executed_steps"] for g in groups),
            shared_wrapper_ns=common, total_baseline_native_execution_ns=total_baseline,
            total_complete_measured_deployment_ns=total_strict,
            total_complete_measured_net_ns=total_baseline - total_strict,
            runner_wall_ns_before_final_report=result["runner_wall_ns_before_final_report"],
            post_gate_runner_tail_ns=post_gate_tail,
            conservative_diagnostic_net_after_remaining_runner_tail_ns=total_baseline - total_strict - post_gate_tail,
            tail_diagnostic_is_not_a_rescore=True,
            all_economic_costs_known=False,
            excluded_or_unknown_costs=["separate post-decision baseline audit API is experiment overhead",
                "Python process startup/imports", "final aggregate report serialization and affinity restoration",
                "tool acquisition and installation", "manual engineering", "unexecuted external model/NDU search"],
            nested_intervals_not_added_twice=True)
        if summary is not None:
            summary_path = Path(summary)
            reported = read(summary_path)
            report["summary"] = {"path": str(summary_path), **identity(summary_path)}
            check("summary_identity_and_outcomes", reported["schema"] == "hepta.hia.registered-followup.readout.v1"
                  and reported["kind"] == "prepared-runtime" and reported["raw_result_sha256"] == report["raw_result_sha256"]
                  and reported["registration_sha256"] == result["registration_sha256"]
                  and reported["implementation_gate_passed"] == implementation
                  and reported["finite_net_benefit_gate_passed"] == finite_gate)
            for index, (original, retained) in enumerate(zip(rows, reported["samples"])):
                # The collector deliberately leaves driver/build/snapshot in
                # the raw archive and adds a proof-reuse event convenience view.
                expected = {k: v for k, v in original.items() if k not in {"driver", "builds", "snapshot"}}
                check(f"summary_group{index}:same_retained_fields", all(retained.get(k) == v for k, v in expected.items()))
            check("summary_group_denominator", len(reported["samples"]) == len(rows))
        report["passed"] = all(checks.values())
    except Exception as error:
        report.update(passed=False, error={"type": type(error).__name__, "message": str(error)})
    report["audit_wall_ns"] = time.monotonic_ns() - started
    with output.open("x") as stream:
        json.dump(report, stream, sort_keys=True, indent=2)
        stream.write("\n")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True)
    parser.add_argument("--output", default=str(STUDY / "ROOT_COST_AUDIT.json"))
    parser.add_argument("--summary")
    value = audit(**vars(parser.parse_args()))
    print(json.dumps({k: value.get(k) for k in (
        "kind", "passed", "raw_result_sha256", "planned_groups", "observed_groups",
        "recomputed_finite_net_benefit_gate", "error")}), flush=True)
