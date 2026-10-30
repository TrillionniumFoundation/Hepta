"""Accounting/admission checks; synthetic fixtures are not performance evidence."""
from copy import deepcopy
import json
import unittest

from tools.qualify_hia_candidate_amortization import (
    ARMS, PROTOCOL, complete_episode_cost, paired_gates, validate_protocol)


class CandidateAmortizationTests(unittest.TestCase):
    def setUp(self):
        self.protocol = json.loads(PROTOCOL.read_bytes())

    def test_fixed_horizon_fits_existing_execution_limit_and_cannot_be_retimed(self):
        p = validate_protocol(self.protocol)
        self.assertEqual(len(p["trace_unit"]) * p["trace_repetitions"], p["session_limits"]["max_executions"])
        self.assertEqual((p["trace_unit"] * p["trace_repetitions"]).count(4097), 32)
        for field, value in (("trace_repetitions", 33), ("holdout_seed", 113), ("groups", 4)):
            changed = dict(p, **{field: value})
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate_protocol(changed)

    def rows(self):
        return [{"group": group, "target": target, "admitted": True,
            "wall_ns": {"base": 1000, "guarded": 900, "guarded-narrowed": 800}[target],
            "nested_execution_ns": {"delivery_observation_ns": 500}}
            for group in range(3) for target in ARMS]

    def test_one_nonpositive_pair_cannot_be_hidden_by_a_favorable_mean(self):
        rows = self.rows()
        self.assertTrue(paired_gates(rows, self.protocol, True)["observed_complete_cost_gate"])
        next(row for row in rows if row["group"] == 1 and row["target"] == "guarded")["wall_ns"] = 1001
        result = paired_gates(rows, self.protocol, True)
        self.assertTrue(result["functional_gate"])
        self.assertLess(sum(row["wall_ns"] for row in rows if row["target"] == "guarded"), 3000)
        self.assertFalse(result["all_pairs_positive_by_candidate"]["guarded"])
        self.assertTrue(result["all_pairs_positive_by_candidate"]["guarded-narrowed"])
        self.assertFalse(result["observed_complete_cost_gate"])

    def test_incomplete_or_duplicate_group_or_changed_identity_cannot_pass(self):
        for rows, unchanged in ((self.rows()[:-1], True),
                (self.rows() + [self.rows()[0]], True), (self.rows(), False)):
            with self.subTest(count=len(rows), unchanged=unchanged):
                self.assertFalse(paired_gates(rows, self.protocol, unchanged)["functional_gate"])

    def admitted_fixture(self):
        return {"target": "guarded", "group": 0, "status": "completed",
            "ledger": [{"label": label, "wall_ns": ns} for label, ns in (
                ("session.create", 5), ("prepare.base", 50), ("prepare.guarded", 50),
                ("native.text.base", 5), ("native.text.guarded", 5), ("deliver.0", 256),
                ("record.sample.0", 64), ("session.close", 10))],
            "observations": [{"status": "measured", "delivery_cost_ns": 1,
                "output": {"elapsed_ns": 1, "process_cpu_ns": 1}} for _ in range(256)],
            "admissions": [{"receipt": {"verification": {"status": "verified"}},
                "native_text": {"sha256": target}} for target in ("base-fixture", "candidate-fixture")],
            "session_closed": {"execution_attempts": 256, "proof_attempts": 2,
                "successful_admissions": 2, "owned_native_release_complete": True,
                "charged_retained_bytes": 0, "reserved_bytes": 0, "outstanding_leases": 0,
                "pending_release_debt": []}}

    def test_cost_partition_does_not_double_count_nested_native_time(self):
        row = complete_episode_cost(self.admitted_fixture(), 1000, self.protocol)
        self.assertTrue(row["admitted"])
        self.assertEqual(sum(row["components_ns"].values()), 1000)
        self.assertEqual(row["nested_execution_ns"]["native_driver_elapsed_ns"], 256)
        self.assertEqual(row["components_ns"]["prepare_prove_build_seal_ns"], 100)

    def test_partial_execution_missing_fresh_proof_or_release_debt_fails(self):
        for key, value in (("execution_attempts", 255), ("proof_attempts", 1),
                ("pending_release_debt", ["uncertain-close"]), ("charged_retained_bytes", 1)):
            row = deepcopy(self.admitted_fixture())
            row["session_closed"][key] = value
            with self.subTest(key=key):
                self.assertFalse(complete_episode_cost(row, 1000, self.protocol)["admitted"])


if __name__ == "__main__":
    unittest.main()
