"""Pure arithmetic and refusal gates, never fabricated image-performance PASS.

Synthetic durations below exercise deterministic arithmetic only. These tests
never invoke calibrate, execute-next, run_guest, QEMU, or the guest executable.
"""
import copy
from fractions import Fraction
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("comparison_under_test", ROOT / "tools/qualify_hia_kernel_comparison.py")
c = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(c)
Q = c.Q32


def training_rows():
    """Explicit synthetic algebra inputs: not collector/build receipts."""
    rows = []
    for i, image in enumerate(c.IMAGES):
        for j, seed in enumerate(c.protocol()["training_seeds"]):
            for k, phase in enumerate(c.PHASES):
                rows.append({"partition": "calibration", "image_id": image, "phase": phase,
                    "run_id": f"synthetic-{i}-{j}", "seed": seed, "median_ns": 10000 + i * 1000 + k * 100 + j,
                    "completed_unix_ns": 100 + j * 4 + i})
    return rows


def model_and_candidates():
    p = c.protocol()
    model = c.build_model(training_rows(), [], current_phase=c.PHASES[0], episode_index=0, protocol_value=p)
    images = [{"id": image, "backend": backend, "artifact_sha256": c.digest(image),
               "verification_digest": c.digest([image, "synthetic-arithmetic-only"]),
               "image_bytes": size, "stock_image_bytes": 10000}
              for image, backend, size in zip(c.HIA_IMAGES, ("O2", "O3", "Os"), (10000, 12000, 8000))]
    return model, c.make_candidates(model, images, c.digest(model), c.digest(p["objective"])), images


class ExactArithmetic(unittest.TestCase):
    def test_round_ties_even_signed(self):
        self.assertEqual([c.round_even_ratio(v, 2) for v in (-7, -5, -3, -1, 1, 3, 5, 7)],
                         [-4, -2, -2, 0, 0, 2, 2, 4])

    def test_q32_fractional_products(self):
        self.assertEqual(c.mul_q32(Q // 4, Q // 2), Q // 8)
        self.assertEqual(c.mul_q32(-Q // 4, Q // 2), -Q // 8)
        self.assertEqual(c.mul_q32(3, Q // 2), 2)

    def test_ratio_preserves_large_integer_precision(self):
        n = (1 << 60) + 17
        expected = c.round_even_ratio(100 * n * Q, n + 1)
        self.assertEqual(c.ratio_q32(100 * n, n + 1), expected)

    def test_q32_never_silently_clips(self):
        with self.assertRaises(ValueError):
            c.mul_q32((1 << 63) - 1, 2 * Q)
        with self.assertRaises(ValueError):
            c.ratio_q32(1_000_001, 1)

    def test_bool_is_not_numeric_evidence(self):
        with self.assertRaises(ValueError):
            c.integer(True, "timing")
        with self.assertRaises(ValueError):
            c.mul_q32(True, Q)

    def test_exact_even_median(self):
        self.assertEqual(c.median_fraction([2, 1, 4, 3]), Fraction(5, 2))
        self.assertEqual(c.median_fraction([9, 1, 5]), 5)

    def test_dynamic_preference_stops_at_registered_residual(self):
        initial = {"latency": 3 * Q // 4, "image_size": Q // 4}
        target = {"latency": Q, "image_size": 0}
        solved = c.preference_reference(initial, target)
        self.assertLessEqual(solved["residual_raw"], 4096)
        self.assertGreater(solved["iterations"][-2]["residual_raw"], 4096)
        self.assertLessEqual(len(solved["iterations"]), 64)
        current = dict(initial)
        for step in solved["iterations"]:
            # Fraction arithmetic independent of the implementation's mul_q32.
            current = {axis: value + round(Fraction(target[axis] - value, 4)) for axis, value in current.items()}
            self.assertEqual(current, step["values"])

    def test_fixed_preference_ignores_new_public_target(self):
        initial = {"latency": 3 * Q // 4, "image_size": Q // 4}
        solved = c.preference_reference(initial, {"latency": 0, "image_size": Q}, mode="fixed")
        self.assertEqual(solved["values"], initial)
        self.assertEqual(solved["iterations"], [])

    def test_duplicate_or_nonfinite_json_rejected(self):
        for value in ('{"x":1,"x":2}', '{"x":NaN}', '{"x":Infinity}'):
            with self.assertRaises(ValueError):
                c.strict_json(value)

    def test_duplicate_axes_rejected(self):
        with self.assertRaises(ValueError):
            c.axis_map([{"axis": "latency", "value_q32": 1}] * 2)


class ForecastAndBudget(unittest.TestCase):
    def test_complete_cartesian_inventory(self):
        _, candidates, _ = model_and_candidates()
        self.assertEqual(len(candidates), 82)
        self.assertEqual(len({tuple(p["image_id"] for p in x["path"]) for x in candidates if x["path"]}), 81)
        self.assertEqual(candidates[-1]["id"], "abstain")

    def test_microsecond_budget_matches_incumbent(self):
        model, candidates, _ = model_and_candidates()
        expected = 0
        for distribution in model["phase_distributions"]:
            ns = sum(c.as_fraction(distribution[p]) * c.as_fraction(model["cells"]["hia-original"][p]["median_ns"])
                     for p in c.PHASES)
            expected += round(ns * Q / 1000)
        self.assertEqual(c.incumbent_budget(candidates), expected)
        self.assertNotEqual(expected, 4 * Q)

    def test_real_budget_excludes_slow_paths_without_pruning(self):
        _, candidates, _ = model_and_candidates()
        result = c.evaluate_paths(candidates, {"latency": Q, "image_size": 0}, budget=c.incumbent_budget(candidates))
        self.assertEqual(len(result["paths"]), 82)
        self.assertTrue(result["paths"]["path-000"]["feasible"])
        self.assertFalse(result["paths"]["path-080"]["feasible"])

    def test_budget_boundary_is_one_raw_unit(self):
        _, candidates, _ = model_and_candidates()
        budget = c.incumbent_budget(candidates)
        valid = c.evaluate_paths(candidates, {"latency": Q, "image_size": 0}, budget=budget)
        invalid = c.evaluate_paths(candidates, {"latency": Q, "image_size": 0}, budget=budget - 1)
        self.assertTrue(valid["paths"]["path-000"]["feasible"])
        self.assertFalse(invalid["paths"]["path-000"]["feasible"])

    def test_greedy_only_actions_with_feasible_suffix(self):
        _, candidates, _ = model_and_candidates()
        result = c.greedy_reference(candidates, {"latency": 0, "image_size": Q}, budget=c.incumbent_budget(candidates))
        # Synthetic Os is smallest but every path starting with it is too slow.
        self.assertNotIn("hia-os", result["feasible_first_images"])
        self.assertEqual(result["executed_image"], "hia-original")

    def test_frontier_tie_abstains_and_runs_incumbent(self):
        _, candidates, _ = model_and_candidates()
        for candidate in candidates:
            candidate["resource_cost_q32"] = 0
            for phase in candidate["path"]:
                phase["components"] = c.axis_list({"latency": 100 * Q, "image_size": 100 * Q})
        result = c.evaluate_paths(candidates, {"latency": Q, "image_size": 0}, budget=0)
        self.assertEqual(len(result["frontier"]), 81)
        self.assertIsNone(result["selected_image"])
        self.assertEqual(result["executed_image"], "hia-original")

    def test_infeasible_better_path_does_not_enter_frontier(self):
        _, candidates, _ = model_and_candidates()
        chosen = candidates[1]
        chosen["resource_cost_q32"] = (1 << 63) - 1
        for phase in chosen["path"]:
            phase["components"] = c.axis_list({"latency": 200 * Q, "image_size": 200 * Q})
        result = c.evaluate_paths(candidates, {"latency": Q, "image_size": 0}, budget=c.incumbent_budget(candidates))
        self.assertNotIn(chosen["id"], result["frontier"])

    def test_phase_distributions_are_exact_and_past_only(self):
        model, _, _ = model_and_candidates()
        for dist in model["phase_distributions"]:
            self.assertEqual(sum(c.as_fraction(v) for v in dist.values()), 1)
        self.assertEqual(c.as_fraction(model["phase_distributions"][0][c.PHASES[0]]), 1)
        self.assertFalse(model["future_observations_used"])

    def test_future_history_rejected(self):
        with self.assertRaises(ValueError):
            c.build_model(training_rows(), [{}], current_phase=c.PHASES[0], episode_index=0, protocol_value=c.protocol())

    def test_partial_cell_rejected(self):
        history = [{"status": "PASS", "index": 0, "phase": c.PHASES[0], "observations": []}]
        with self.assertRaises(ValueError):
            c.build_model(training_rows(), history, current_phase=c.PHASES[1], episode_index=1, protocol_value=c.protocol())

    def test_qualification_never_training(self):
        rows = training_rows()
        rows[0]["partition"] = "qualification"
        with self.assertRaises(ValueError):
            c.assert_training_partition(rows, c.protocol())

    def test_five_within_boot_repeats_not_three_boots(self):
        rows = training_rows()
        for row in rows:
            if row["image_id"] == "stock":
                row["run_id"] = "one-boot"
        with self.assertRaises(ValueError):
            c.assert_training_partition(rows, c.protocol())

    def test_duplicate_image_run_rejected(self):
        rows = training_rows()
        for row in rows:
            if row["image_id"] == "hia-original":
                row["run_id"] = row["run_id"].replace("synthetic-1", "synthetic-0")
        with self.assertRaises(ValueError):
            c.assert_training_partition(rows, c.protocol())

    def test_schedule_160_distinct_boots_same_seed_per_cell(self):
        rows = c.make_schedule(c.protocol(), "pure-test")
        self.assertEqual(len(rows), 20)
        self.assertEqual(len({rid for row in rows for rid in row["run_ids"].values()}), 160)
        self.assertEqual(rows, c.make_schedule(c.protocol(), "pure-test"))
        self.assertTrue(all(set(row["arm_order"]) == set(c.ARMS) for row in rows))

    def test_heldout_training_seed_collision_rejected(self):
        p = c.protocol()
        p["heldout_seed_start"] = p["training_seeds"][0]
        with self.assertRaises(ValueError):
            c.make_schedule(p, "pure-test")


class EvidenceAndStateGates(unittest.TestCase):
    def test_original_symlink_spelling_keeps_actual_content_binding(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target, alias = root / "lld", root / "ld.lld"
            target.write_bytes(b"qualified tool bytes")
            alias.symlink_to(target.name)
            binding = {**c.identity(target), "path": str(alias)}
            self.assertEqual(c.check_binding(binding), binding)
            target.write_bytes(b"different tool bytes")
            with self.assertRaises(ValueError):
                c.check_binding(binding)

    def test_serial_crlf_is_not_normalized_before_hash_parser(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "raw.stdout"
            raw = b'prefix\r\n{"event":"synthetic-parser-fixture"}\r\n'
            path.write_bytes(raw)
            binding = c.identity(path)
            text = c.read_utf8_bound_log(binding)
            self.assertEqual(text.encode("utf-8"), raw)
            self.assertEqual(len(text.encode()), binding["bytes"])

    def test_pass_word_is_not_whole_build_evidence(self):
        for image in c.IMAGES:
            with self.assertRaises(ValueError):
                c.build_gate_header({"status": "PASS"}, image, c.protocol())

    def test_hia_declared_fallback_refused_before_file_access(self):
        value = {"schema": "hepta.hia.linux.full-system-build.v1", "status": "PASS",
                 "build_status": "PASS", "boot_status": "PASS", "kernel_version": "6.18.60",
                 "upstream_commit": c.protocol()["kernel"]["upstream_commit"],
                 "source_before": {"clean": True}, "source_after": {"clean": True},
                 "linux_source_unchanged": True, "scope": "complete_frozen_x86_64_configuration",
                 "all_configured_target_units_rewritten": True, "fallback_c_units": 1, "mode": "import"}
        with self.assertRaises(ValueError):
            c.build_gate_header(value, "hia-original", c.protocol())

    def test_changed_bound_file_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "raw"
            path.write_bytes(b"first\r\n")
            binding = c.identity(path)
            path.write_bytes(b"second\n")
            with self.assertRaises(ValueError):
                c.check_binding(binding)

    def test_boot_reuse_across_partition_rejected(self):
        row = {"run_id": "a", "output": "/fake/a", "stdout_sha256": "b"}
        with self.assertRaises(ValueError):
            c.require_independent_boots([row], forbidden=[row])

    def test_pid_is_not_a_global_independence_key(self):
        a = {"run_id": "a", "output": "/fake/a", "stdout_sha256": "a", "pid": 10}
        b = {"run_id": "b", "output": "/fake/b", "stdout_sha256": "b", "pid": 10}
        c.require_independent_boots([a, b])

    def test_compiler_load_rejected_for_measurement(self):
        with self.assertRaises(ValueError):
            c.require_quiet_host({"visible_build_or_qemu_processes": [{"pid": 1, "comm": "clang"}]})

    def test_incomplete_process_receipt_rejected(self):
        with self.assertRaises(ValueError):
            c.success_command({"exit_code": 0, "timed_out": False})

    def test_failed_register_cannot_claim_boot_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            spec = root / "spec.json"
            calibration = root / "cal.json"
            spec.write_text('{"schema":"wrong"}')
            calibration.write_text('{"status":"PASS"}')
            result = c.register(spec, calibration, root / "registration")
            self.assertEqual(result["status"], "FAIL")
            self.assertEqual(result["heldout_boots_started"], 0)
            self.assertFalse((root / "registration/REGISTRY.json").exists())

    def test_failure_is_terminal_and_records_pending(self):
        with tempfile.TemporaryDirectory() as directory:
            state = {"pending": {"inflight": {"arm": "stock"}}, "status": "EXECUTING"}
            result = c.fail_campaign(directory, state, ValueError("interrupted"), "execute-next")
            self.assertFalse(result["retry_allowed"])
            self.assertEqual(c.load(Path(directory) / "STATE.json")["status"], "FAIL")
            self.assertEqual(result["retained_pending"]["inflight"]["arm"], "stock")

    def test_ordinary_control_cannot_be_a_native_response(self):
        with self.assertRaises(ValueError):
            c.check_ordinary_response({"request": {}}, {"schema": "hepta.hia.kernel-ndu.response.v1"}, {}, {})


class StatisticsAndAccounting(unittest.TestCase):
    def test_block_bootstrap_uses_five_clusters(self):
        result = c.paired_cluster_bootstrap([(100, 90)] * 5)
        self.assertEqual(result["bootstrap_replicates"], 3125)
        self.assertEqual(result["relative_change_percent"]["value"], -10.0)
        self.assertEqual([v["value"] for v in result["relative_change_ci95_percent"]], [-10.0, -10.0])
        self.assertFalse(result["within_boot_samples_used_as_clusters"])

    def test_twenty_phase_cells_are_not_twenty_clusters(self):
        with self.assertRaises(ValueError):
            c.paired_cluster_bootstrap([(100, 90)] * 20)

    def test_bootstrap_retains_paired_block_effects(self):
        result = c.paired_cluster_bootstrap([(n, n) for n in (10, 100, 1000, 10000, 100000)])
        self.assertEqual([v["value"] for v in result["difference_ci95"]], [0, 0])

    def test_static_arms_do_not_pay_for_search(self):
        for arm, image in (("stock", "stock"), ("hia-static", "hia-original")):
            cost = c.cost_requirements(arm)
            self.assertEqual(cost["images"], [image])
            self.assertFalse(cost["calibration"] or cost["native_adapter"] or cost["ordinary_control"])

    def test_native_preparation_owned_by_actual_implementation(self):
        self.assertTrue(c.cost_requirements("dynamic-ndu")["native_adapter"])
        self.assertFalse(c.cost_requirements("independent-same-objective")["native_adapter"])
        self.assertTrue(c.cost_requirements("independent-same-objective")["ordinary_control"])
        self.assertFalse(c.cost_requirements("ordinary-mpc")["ordinary_control"])

    def test_nonpositive_savings_never_reach_break_even(self):
        self.assertFalse(c.break_even(1000, 100, 100)["reachable"])
        self.assertFalse(c.break_even(1000, 100, 101)["reachable"])

    def test_positive_break_even_uses_ceiling(self):
        self.assertEqual(c.break_even(1001, 100, 90)["minimum_four_phase_cycles"], 101)


if __name__ == "__main__":
    unittest.main()
