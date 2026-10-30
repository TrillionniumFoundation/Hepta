"""Read-only seven-track ledger; no result can confer deployment authority."""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent


def evidence(name):
    path = ROOT / name
    raw = path.read_bytes()
    return json.loads(raw), {"path": name, "bytes": len(raw), "sha256": sha256(raw).hexdigest()}


def assemble():
    paths = {
        "source_ci": "experiments/hia_verified_integration/round3_20261028/source-ci-5b66/20261028T111507_371780Z.actual-artifact-readout.json",
        "performance": "experiments/hia_optimizer_eval/round3_20261028/READOUT.json",
        "performance_raw": "experiments/hia_optimizer_eval/round3_20261028/benchmark-results.json",
        "performance_numeric_audit": "experiments/hia_optimizer_eval/round3_20261028/ROOT_NUMERIC_AUDIT.json",
        "migration": "experiments/cpp_unique_project_eval/round3_20261028/RESULT.json",
        "agent": "experiments/hia_agent_matched_v3_readout_20261028/READOUT.json",
        "agent_review": "experiments/hia_verified_integration/round3_20261028/agent_readout_review.json",
        "ndu": "experiments/hia_ndu_graph_eval/round3_20261028/trial01.summary.json",
        "ndu_manifest": "experiments/hia_ndu_graph_eval/round3_20261028/trial01.manifest.json",
        "ndu_cost_audit": "experiments/hia_ndu_graph_eval/round3_20261028/ROOT_COST_AUDIT.json",
        "runtime": "experiments/hia_stateful_eval/round3_20261028/trial01.summary.json",
        "runtime_manifest": "experiments/hia_stateful_eval/round3_20261028/trial01.manifest.json",
        "runtime_cost_audit": "experiments/hia_stateful_eval/round3_20261028/ROOT_COST_AUDIT.json",
        "private_ci": "experiments/hia_private_ci/round3_c4a1bbed_20261028/latest-readout.json",
    }
    records, references = {}, {}
    for name, path in paths.items():
        records[name], references[name] = evidence(path)
    ci, perf, migration, agent, ndu, runtime = (records[k] for k in (
        "source_ci", "performance", "migration", "agent", "ndu", "runtime"))
    assert ci["public_head_sha"] == "5b66f96af480d6f599d8646cff6ef7e542de1072"
    assert ci["regression"]["tests"] == 327 and ci["regression"]["passed"]
    assert ci["regression"]["source_unchanged"] and not ci["regression"]["skipped"]
    assert ci["narrowing_cli"]["observations"] == 56 and ci["narrowing_cli"]["passed"]
    assert ci["narrowing_cli"]["timeout_and_unknown_never_published"]
    assert agent["complete_valid_coverage"] and agent["totals"]["attempted_cells"] == 16
    assert sum(agent["totals"]["failure_subtypes"].values()) == agent["totals"]["submissions"]
    assert not agent["gates"]["full_agent_advantage"]
    review = records["agent_review"]
    assert review["reviewed_result_bindings"]["READOUT.json"] == {
        key: references["agent"][key] for key in ("bytes", "sha256")}
    assert review["claims"]["blocking_findings_remaining"] is False
    assert review["actual_current_evidence_checks"]["status"] == "passed"
    numeric = records["performance_numeric_audit"]
    assert numeric["passed"] and numeric["all_pairs_recomputed"]
    assert numeric["raw_sample_count"] == 112 and len(numeric["comparisons"]) == 14
    assert numeric["source_report_sha256"] == perf["raw_report_sha256"]
    assert references["performance_raw"]["sha256"] == perf["raw_report_sha256"]
    assert perf["counts"]["actual_samples"] == perf["counts"]["scheduled_samples"] == 112
    assert perf["counts"]["samples_excluded"] == 0 and perf["counts"]["retries"] == 0
    for record, scope, kind, audit_name in ((ndu, "hia_ndu_graph_eval", "stream-ndu", "ndu_cost_audit"),
            (runtime, "hia_stateful_eval", "prepared-runtime", "runtime_cost_audit")):
        assert record["schema"] == "hepta.hia.registered-followup.readout.v1"
        assert record["kind"] == kind
        registration, _ = evidence("experiments/" + scope + "/round3_20261028/REGISTRATION.json")
        assert record["registration_sha256"] == registration["registration_sha256"]
        assert records[audit_name]["kind"] == kind and records[audit_name]["passed"]
        assert records[audit_name]["raw_result_sha256"] == record["raw_result_sha256"]
        assert records[audit_name]["recomputed_implementation_gate"] == record["implementation_gate_passed"]
        assert records[audit_name]["recomputed_finite_net_benefit_gate"] == record["finite_net_benefit_gate_passed"]
        manifest_name = "ndu_manifest" if kind == "stream-ndu" else "runtime_manifest"
        manifest = records[manifest_name]
        assert manifest["sha256"] == record["archive"]["sha256"]
        raw_members = [m for m in manifest["members"] if m["path"] == "RESULT.json"]
        assert len(raw_members) == 1 and raw_members[0]["sha256"] == record["raw_result_sha256"]
        archive = ROOT / "experiments" / scope / "round3_20261028" / record["archive"]["file"]
        assert archive.stat().st_size == record["archive"]["bytes"]
        assert sha256(archive.read_bytes()).hexdigest() == record["archive"]["sha256"]
        assert record["archive"]["all_member_hashes_verified"]
        assert record["samples_excluded"] == 0
    ndu_episodes = [row for row in ndu.get("episodes", []) if row["arm"] == "ndu"]
    ndu_transitions = sum(len(row["transitions"]) for row in ndu_episodes)
    tracks = [
        {"item": 1, "name": "unified-execution-core", "bounded_implementation_gate_passed": True,
         "status": "qualified_with_explicit_frontend_and_target_limits", "evidence": ["source_ci"],
         "executed_core": "standalone HIA values/resources/errors/effects",
         "unsupported_source_frontends": ["Rust", "TypeScript", "Python", "Go", "raw assembly"],
         "actual_new_native_target": "Linux x86-64", "all_language_frontends_implemented": False},
        {"item": 2, "name": "independent-optimization-obligations", "bounded_implementation_gate_passed": True,
         "status": "qualified_for_registered_guard_and_modular_narrowing_profiles", "evidence": ["source_ci", "performance"],
         "unknown_timeout_failure_deployable": False, "final_native_bytes_bound": True,
         "full_source_to_machine_code_refinement_proved": False},
        {"item": 3, "name": "actual-native-ndu-compiler-loop", "bounded_implementation_gate_passed": ndu["implementation_gate_passed"],
         "finite_full_cost_gate_passed": ndu["finite_net_benefit_gate_passed"],
         "actual_ndu_selected_transitions": ndu_transitions,
         "measured_loop_and_net_benefit_requirement_passed": bool(ndu["finite_net_benefit_gate_passed"] and ndu_transitions > 0),
         "status": ndu["status"], "evidence": ["ndu", "ndu_cost_audit"], "same_information_and_budget": True,
         "all_economic_costs_known": ndu["all_costs_known"], "global_optimality_claim": False},
        {"item": 4, "name": "multi-config-cross-module-cpp-migration", "bounded_implementation_gate_passed": migration["ok"],
         "status": "qualified_default_unique_array_deleter_and_composite_owner_profile", "evidence": ["migration", "source_ci"],
         "configurations": [{"name": row["name"], "observations": row["observations"],
                             "project_declaration_occurrences": row["project_declaration_occurrences"],
                             "standard_library_declaration_occurrences": row["standard_library_declaration_occurrences"],
                             "separate_accounting": row["accounting"]} for row in migration["variant_results"]],
         "standard_library_semantics_trusted": migration["standard_library_semantics_trusted"],
         "general_cpp_source_equivalence_proved": migration["general_cpp_source_equivalence_proved"],
         "general_low_cost_migration_qualified": migration["general_low_cost_migration_qualified"]},
        {"item": 5, "name": "strong-native-performance-baselines", "finite_registered_gate_passed": perf["joint14_noninferiority_passed"],
         "strong_language_gate_passed": perf["strong10_noninferiority_passed"],
         "status": perf["status"], "evidence": ["performance", "performance_numeric_audit"],
         "counts": perf["counts"], "nongated_batch_p99_regressions": perf["nongated_batch_p99_regressions"],
         "universal_rust_or_language_superiority": False, "all_economic_costs_known": False},
        {"item": 6, "name": "actual-matched-agent-maintenance-and-upgrade", "evidence_collection_complete": True,
         "finite_registered_gate_passed": agent["gates"]["registered_joint_gate"],
         "full_requirement_satisfied": agent["gates"]["user_item6_full_requirement_satisfied"],
         "status": "completed_negative_result", "evidence": ["agent", "agent_review"],
         "totals": agent["totals"], "gates": agent["gates"],
         "controls_counted_as_model_successes": False, "posthoc_rescoring_or_reruns": False},
        {"item": 7, "name": "owned-state-runtime-adaptation", "bounded_implementation_gate_passed": runtime["implementation_gate_passed"],
         "finite_full_cost_gate_passed": runtime["finite_net_benefit_gate_passed"], "status": runtime["status"],
         "evidence": ["runtime", "runtime_cost_audit", "source_ci"], "all_economic_costs_known": runtime["all_costs_known"],
         "general_heap_migration": False, "external_io_crash_exactly_once": False},
    ]
    return {"schema": "hepta.hia.seven-track.round3.acceptance.v1", "all_seven_user_deliverables_accepted": False,
        "deployment_authority": False, "safety_certificate": False, "tracks": tracks, "evidence": references,
        "production_source_checkpoint": ci["public_head_sha"],
        "production_source_tree": "66672e8bc4e45c5243211448fc538593c8eae3a7",
        "native_ndu_source_commit": "c4a1bbed3a39beba43a6abf1a18b6f75c5725c21",
        "public_source_ci": {"run_id": ci["run_id"], "regression": ci["regression"],
                             "narrowing_cli": ci["narrowing_cli"]},
        "private_ci": records["private_ci"], "previous_rounds_and_negative_results_preserved": True,
        "final_evidence_commit_ci": "Reported separately at the exact final PR head; this ledger references the already completed source checkpoint and does not relabel it.",
        "cost_policy": "Within-scope observed costs are retained, including failed work. Nested intervals are not added twice; unknown acquisition, labor and whole economic costs remain unknown.",
        "scope": "Finite registered host/profile experiments and implemented fail-closed controls; no universal safety, global optimum, arbitrary C++ migration or general Agent/Rust superiority.",
        "assembler_sha256": sha256(Path(__file__).read_bytes()).hexdigest()}


if __name__ == "__main__":
    result = assemble()
    with (HERE / "acceptance.json").open("x") as stream:
        json.dump(result, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print(json.dumps({"all_seven_user_deliverables_accepted": result["all_seven_user_deliverables_accepted"],
                      "evidence_files": len(result["evidence"])}))
