"""Malformed evidence must not become a passing release qualification.

Historical reports are structural unit fixtures only; these tests never claim
new native execution or current-source qualification from those observations.
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import release_check


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/fixtures/release_evidence"


def fixture(name):
    return json.loads((FIXTURES / (name + ".json")).read_text())


class ReleaseEvidenceTests(unittest.TestCase):
    def check_report(self, gate, report):
        if gate == "stateful_c_module":
            # Unit-only structural replay. Do not relabel historical source as
            # the current snapshot or assert new qualification from this call.
            with patch.object(release_check, "snapshot", return_value=self.stateful["source_snapshot_before"]):
                release_check.require_qualification(gate, report)
        else:
            release_check.require_qualification(gate, report)

    @classmethod
    def setUpClass(cls):
        cls.stateful = json.loads((ROOT / "evidence/next_blockers_audits/c-ring-fixed-feature/report.json").read_text())

    def rejects(self, gate, report, changes):
        self.check_report(gate, report)
        for label, mutate in changes.items():
            changed = copy.deepcopy(report)
            mutate(changed)
            with self.subTest(case=label), self.assertRaises(ValueError):
                self.check_report(gate, changed)

    def test_native_build_failures_cannot_hide_behind_stateful_success(self):
        self.rejects("stateful_c_module", self.stateful, {
            "original_missing": lambda r: r.pop("original_build"),
            "original_failed": lambda r: r["original_build"].update(exit_code=1),
            "translated_not_run": lambda r: r["migration"]["native_build"].update(ok=False, status="not_run"),
            "owned_client_missing": lambda r: r["owned_client"].pop("native_build"),
            "timing_build_failed": lambda r: r["performance"]["build"].update(exit_code=1),
            "missing_artifact": lambda r: r["owned_client"]["native_build"].pop("artifact_sha256"),
        })

    def test_failure_receive_bound_counts_messages_instead_of_worker_return_sum(self):
        report = fixture("groups")
        worker = next(row for row in report["scenarios"] if row["scenario"] == "worker_failure")
        # One worker sends two values before failing; the other three each send
        # 64. A legal schedule can drain all 194 before group_fail takes effect.
        # Worker return values sum to 193 and are a different observation.
        for run in worker["runs"]:
            run["metrics"]["received_before_close"] = 194
        self.check_report("bounded_concurrency", report)
        worker["runs"][0]["metrics"]["received_before_close"] = 195
        with self.assertRaises(ValueError):
            self.check_report("bounded_concurrency", report)

    def test_stateful_inventory_layout_and_actual_inputs_are_required(self):
        self.rejects("stateful_c_module", self.stateful, {
            "inventory_erased": lambda r: r["migration"].update(declarations=[]),
            "null_layout": lambda r: r.update(layout_probe={k: {"gcc": None, "rust": None} for k in r["layout_probe"]}),
            "string_layout": lambda r: r["layout_probe"].update(size={"gcc": "32", "rust": "32"}),
            "overlapping_offsets": lambda r: r["layout_probe"].update(tail_index={"gcc": 8, "rust": 8}),
            "no_storage_oracle": lambda r: r["execution"].update(checks=[]),
            "owner_no_refusal_input": lambda r: r["owned_client"]["calls"][2].update(size=8),
            "wrong_control_no_mismatch": lambda r: r["wrong_implementation_control"].pop("first_mismatch"),
        })

    def test_stateful_cost_samples_and_claims_cannot_be_inflated(self):
        self.rejects("stateful_c_module", self.stateful, {
            "nested_full_C_claim": lambda r: r["migration"]["claims"].update(all_c_or_cpp_supported=True),
            "nested_ownership_claim": lambda r: r["migration"]["record_views"].update(ownership_inference=True),
            "nested_refinement_claim": lambda r: r["execution"].update(source_equivalence_proved=True),
            "one_timing_arm_only": lambda r: r["performance"]["measurements"][0].update(execution_order=["original_C"] * 14),
            "erased_cost_regression": lambda r: r["performance"]["measurements"][0].update(observed_Hepta_over_C_ratio=0.1),
            "summary_not_raw_samples": lambda r: r["performance"]["measurements"][0].update(Hepta_C_ABI_median_ns_per_iteration=0.01),
        })

    def test_performance_requires_every_profile_kernel_count_and_trial(self):
        self.rejects("representative_performance", fixture("performance"), {
            "one_raw_profile_repeated": lambda r: r["measurements"].update(samples=[copy.deepcopy(r["measurements"]["samples"][0])] * len(r["measurements"]["samples"])),
            "missing_sample": lambda r: r["measurements"]["samples"].pop(),
            "duplicate_trial": lambda r: r["measurements"]["samples"][0].update(trial=1),
            "missing_correctness_count": lambda r: r["correctness"].update(counts=[]),
            "missing_zero_check": lambda r: r["correctness"].pop("zero_length_also_checked"),
            "duplicate_profile": lambda r: r["correctness"]["implementations"].append("rust"),
            "missing_unroll": lambda r: r["correctness"]["implementations"].remove("hepta_c_unroll"),
        })

    def test_performance_requires_native_build_and_concrete_function_sections(self):
        self.rejects("representative_performance", fixture("performance"), {
            "C_build_failed": lambda r: r["builds"]["hepta_c"].update(ok=False, status="not_run"),
            "rust_build_missing": lambda r: r["builds"]["hepta_rust"].pop("build"),
            "language_check_not_run": lambda r: r["builds"]["hepta_rust"]["validation"]["checks"].update(types_effects_resources="not_run"),
            "wrong_profile": lambda r: r["builds"]["hepta_c_unroll"].update(optimization_profile="default"),
            "function_bytes_erased": lambda r: r["function_bytes"].update(functions={}),
            "function_size_null": lambda r: r["function_bytes"]["functions"]["dot"]["implementations"]["rust"].update(bytes=None),
            "function_identity_false": lambda r: r["function_bytes"]["functions"]["dot"].update(identical_function_bytes=False),
        })

    def test_performance_statistics_and_slowdowns_are_recomputed(self):
        self.rejects("representative_performance", fixture("performance"), {
            "negative_time": lambda r: r["measurements"]["samples"][0].update(elapsed_ns=-1),
            "NaN_time": lambda r: r["measurements"]["samples"][0].update(ns_per_operation=float("nan")),
            "changed_denominator": lambda r: r["measurements"]["samples"][0].update(iterations=1),
            "wrong_checksum": lambda r: r["measurements"]["samples"][0].update(reference_checksum=0),
            "empty_stats": lambda r: r["measurements"]["summary"][0]["implementations"].update(rust={}),
            "invented_ratio": lambda r: r["measurements"]["summary"][0]["time_relative_to_independent_rust"].update(hepta_c=0.01),
            "erased_regressions": lambda r: r["measurements"].update(all_observed_slowdowns=[]),
        })

    def test_groups_require_real_cleanup_budgets_and_deadlines(self):
        self.rejects("bounded_concurrency", fixture("groups"), {
            "live_tasks_after_cancel": lambda r: r["scenarios"][2]["runs"][0]["metrics"].update(active_tasks=3),
            "empty_pipeline": lambda r: r["scenarios"][0]["runs"][0]["metrics"].update(received_sum=0),
            "unbounded_queue": lambda r: r["scenarios"][0]["runs"][0]["metrics"].update(peak_queued=1000),
            "budget_not_rejected": lambda r: r["scenarios"][1]["runs"][0]["metrics"].update(input_budget_rejections=0),
            "negative_wall_time": lambda r: r["scenarios"][0]["runs"][0].update(elapsed_ms=-1),
            "deadlines_not_observed": lambda r: r["scenarios"][4]["runs"][0]["metrics"].update(send_timeouts=0),
            "duplicate_scenario": lambda r: r["scenarios"].__setitem__(4, copy.deepcopy(r["scenarios"][0])),
            "native_build_not_checked": lambda r: r["scenarios"][0]["backend_validation"].update(rust_borrows_types="not_run"),
        })

    def test_resources_require_distinct_controls_and_honest_claims(self):
        self.rejects("independent_resource_ir", fixture("resources"), {
            "eleven_identical_controls": lambda r: r.update(adversarial_checks=[copy.deepcopy(r["adversarial_checks"][0])] * 11),
            "controls_no_actual_diagnostics": lambda r: r.update(adversarial_checks=[{"ok": True}] * 11),
            "wrong_actual_diagnostic": lambda r: r["adversarial_checks"][0].update(actual="E_RIR_GENERIC"),
            "source_refinement_claim": lambda r: r.update(source_to_ir_refinement_proved=True),
            "native_codegen_claim": lambda r: r.update(native_codegen_uses_resource_ir=True),
            "external_proof_claim": lambda r: r["projects"][0]["resource_verifier"]["claims"].update(external_contracts_proved=True),
        })

    def test_resources_require_native_build_execution_and_exact_replay(self):
        self.rejects("independent_resource_ir", fixture("resources"), {
            "native_gate_backend_failed": lambda r: r["projects"][0]["native_gate"]["backend"].update(ok=False, status="not_run"),
            "native_language_check_not_run": lambda r: r["projects"][0]["native_gate"]["checks"].update(types_effects_resources="not_run"),
            "native_execution_not_bound": lambda r: r["projects"][0]["execution"].pop("executable_sha256"),
            "different_executable": lambda r: r["projects"][0]["execution"].update(executable_sha256="0" * 64),
            "verifier_not_run": lambda r: r["projects"][0]["resource_verifier"].update(status="not_run"),
            "functions_erased": lambda r: r["projects"][0]["resource_verifier"].update(functions=[]),
            "fabricated_operation_count": lambda r: r["projects"][0]["resource_verifier"].update(operations_checked=1),
            "generic_functions_underchecked": lambda r: r["projects"][2]["resource_verifier"].update(generic_functions_checked=5),
        })

    def test_resource_graph_bytes_canonical_identity_and_paths_are_required(self):
        self.rejects("independent_resource_ir", fixture("resources"), {
            "graph_erased": lambda r: r["projects"][0].pop("resource_ir"),
            "graph_nonexistent": lambda r: r["projects"][0]["resource_ir"].update(path=str(FIXTURES / "absent.json")),
            "graph_empty": lambda r: r["projects"][0]["resource_ir"].update(bytes=0),
            "graph_truncated": lambda r: r["projects"][0]["resource_ir"].update(bytes=1),
            "graph_checksum_false": lambda r: r["projects"][0]["resource_ir"].update(sha256="0" * 64),
            "graph_canonical_false": lambda r: r["projects"][0]["resource_ir"].update(canonical_sha256="0" * 64),
            "graph_substituted": lambda r: r["projects"][0].update(resource_ir=copy.deepcopy(r["projects"][1]["resource_ir"])),
        })

    def test_rehashed_invalid_graphs_are_rejected_by_strict_reader_and_verifier(self):
        base = fixture("resources")
        graph = (ROOT / base["projects"][0]["resource_ir"]["path"]).read_bytes()
        invalid_claim = json.loads(graph)
        invalid_claim["claims"]["external_contracts_proved"] = True
        # A duplicate equal key disappears under ordinary json.loads; the
        # strict reader must reject even though the canonical identity agrees.
        cases = {"duplicate_equal_key": b'{"schema":"hepta.resource-ir.v2",' + graph.lstrip()[1:],
                 "nonfinite_constant": graph.replace(b'"source_sha256":', b'"unused":NaN,"source_sha256":', 1),
                 "rehashed_invalid_claim": json.dumps(invalid_claim).encode()}
        for label, data in cases.items():
            with self.subTest(case=label), tempfile.TemporaryDirectory(prefix="hepta-release-graph-") as td:
                changed = copy.deepcopy(base)
                project = changed["projects"][0]
                path = Path(td) / "changed.json"
                path.write_bytes(data)
                project["resource_ir"].update(path=str(path), bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
                if label == "rehashed_invalid_claim":
                    canonical = hashlib.sha256(json.dumps(invalid_claim, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
                    project["resource_ir"]["canonical_sha256"] = canonical
                    project["resource_verifier"]["ir_sha256"] = canonical
                    project["resource_verifier"]["claims"]["external_contracts_proved"] = True
                with self.assertRaises(ValueError):
                    self.check_report("independent_resource_ir", changed)

    def test_malformed_nested_schema_fails_closed(self):
        for gate, report, key in [("representative_performance", fixture("performance"), "measurements"),
                                  ("independent_resource_ir", fixture("resources"), "projects"),
                                  ("bounded_concurrency", fixture("groups"), "scenarios"),
                                  ("stateful_c_module", self.stateful, "migration")]:
            with self.subTest(gate=gate):
                changed = copy.deepcopy(report)
                changed[key] = None
                with self.assertRaises(ValueError):
                    self.check_report(gate, changed)


if __name__ == "__main__":
    unittest.main()
