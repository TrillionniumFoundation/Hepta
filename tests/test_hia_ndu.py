"""Integration tests against the identity-bound original Rust NDU executable."""

from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

from hepta.hia_ndu import NduBridge, NduBridgeError, Q32, REQUEST_SCHEMA, candidate, event


def digest(text):
    return hashlib.sha256(text.encode()).hexdigest()


def plan(name, values, *, terminal=0, verified=True, cost=0, risk=0):
    return candidate(candidate_id=name, verified=verified,
                     verification_digest=digest("verification:" + name),
                     support_digest=digest("observation:" + name),
                     events=[event(identity=f"{name}:event:{index}", instant_q32=value * Q32,
                                   preference_digest=digest("fixed-preference"))
                             for index, value in enumerate(values)],
                     terminal_q32=terminal * Q32, resource_cost_q32=cost * Q32,
                     risk_q32=risk)


def request(*plans):
    return {"schema": REQUEST_SCHEMA, "objective_digest": digest("frozen-compiler-objective"),
            "snapshot_digest": digest("IR+target+proof+owner+remaining-budget"),
            "generation": 1, "utility_unit": "normalized-net-benefit",
            "resource_unit": "modeled-work", "risk_unit": "probability",
            "resource_budget_q32": 10 * Q32, "risk_ceiling_q32": Q32 // 4,
            "candidates": [plan("abstain", [0]), *plans]}


@unittest.skipUnless(os.environ.get("HEPTA_RECURSIVE_NDU_IDENTITY")
                     and os.environ.get("HEPTA_RECURSIVE_NDU_BRIDGE"),
                     "set HEPTA_RECURSIVE_NDU_IDENTITY and HEPTA_RECURSIVE_NDU_BRIDGE for native recursion")
class NativeNduIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest_path = Path(os.environ["HEPTA_RECURSIVE_NDU_IDENTITY"])
        cls.manifest = json.loads(cls.manifest_path.read_text())
        cls.bridge = NduBridge.from_environment()

    def test_native_hard_resource_risk_filters_precede_value(self):
        result = self.bridge.evaluate(request(
            plan("legal", [-1, 4]), plan("unsafe", [100], verified=False),
            plan("over-budget", [200], cost=11), plan("over-risk", [300], risk=Q32 // 2)))
        self.assertEqual(result["advisory_candidate_id"], "legal")
        self.assertEqual(result["rejected"], [
            {"id": "over-budget", "reasons": ["ResourceCeilingExceeded"]},
            {"id": "over-risk", "reasons": ["RiskCeilingExceeded"]},
            {"id": "unsafe", "reasons": ["HardConstraintViolation"]}])
        self.assertEqual(result["authority"], "DENY_ALL")
        self.assertFalse(result["safety_certificate"])

    def test_native_two_step_continuation_beats_greedy_and_accounts_refusal(self):
        original = request(plan("greedy", [3, 0]), plan("continue", [-1, -2], terminal=10),
                           plan("stop", [2, 0]))
        result = self.bridge.evaluate(original)
        self.assertEqual(result["advisory_candidate_id"], "continue")
        continuation = next(row for row in result["paths"] if row["id"] == "continue")
        self.assertEqual(continuation["values_q32"], [7 * Q32, 8 * Q32, 10 * Q32])
        # The actual future refuses work: retain both paid steps, remove the
        # unattainable terminal gain, and make the previously good root worse.
        refused = copy.deepcopy(original)
        refused["candidates"][2]["terminal_q32"] = 0
        refused["candidates"][2]["support_digest"] = digest("actual-future-refusal")
        result = self.bridge.evaluate(refused)
        self.assertEqual(result["advisory_candidate_id"], "greedy")
        stop_request = request(plan("continue", [-1, -2]), plan("stop", [2, 0]))
        self.assertEqual(self.bridge.evaluate(stop_request)["advisory_candidate_id"], "stop")

    def test_abstain_and_ties_are_explicit(self):
        result = self.bridge.evaluate(request(plan("unsafe", [100], verified=False)))
        self.assertEqual((result["disposition"], result["advisory_candidate_id"]),
                         ("InfeasibleExplicitAbstain", "abstain"))
        result = self.bridge.evaluate(request(plan("a", [2]), plan("b", [2])))
        self.assertEqual((result["disposition"], result["advisory_candidate_id"],
                          result["pareto_candidate_ids"]),
                         ("ParetoSetRequiresSlowPath", None, ["a", "b"]))

    def test_native_fixed_point_discount_matches_independent_integer_recursion(self):
        sample = plan("discounted", [1, -2, 4], terminal=3)
        discounts = [Q32 // 2, 3 * Q32 // 4, Q32 // 3]
        for item, discount in zip(sample["events"], discounts):
            item["discount_q32"] = discount
        expected = [sample["terminal_q32"]]
        for item in reversed(sample["events"]):
            product = item["discount_q32"] * expected[0]
            quotient, remainder = divmod(abs(product), Q32)
            quotient += remainder > Q32 // 2 or (remainder == Q32 // 2 and quotient % 2 == 1)
            expected.insert(0, item["instant_q32"] + (quotient if product >= 0 else -quotient))
        response = self.bridge.evaluate(request(sample))
        observed = next(row for row in response["paths"] if row["id"] == "discounted")
        self.assertEqual(observed["values_q32"], expected)

    def test_invalid_candidate_evidence_and_event_reuse_reject(self):
        malformed = request(plan("candidate", [1, 2]))
        malformed["candidates"][1]["verification_digest"] = "0" * 64
        with self.assertRaises(NduBridgeError):
            self.bridge.evaluate(malformed)
        reused = request(plan("candidate", [1, 2]))
        reused["candidates"][1]["events"][1]["event_digest"] = reused["candidates"][1]["events"][0]["event_digest"]
        with self.assertRaisesRegex(NduBridgeError, "DuplicateEvent"):
            self.bridge.evaluate(reused)

    def test_unknown_fields_negative_cost_float_and_horizon_reject(self):
        base = request(plan("candidate", [1, 2]))
        invalids = []
        extra = copy.deepcopy(base)
        extra["activate"] = True
        invalids.append(extra)
        cost = copy.deepcopy(base)
        cost["candidates"][1]["resource_cost_q32"] = -1
        invalids.append(cost)
        floating = copy.deepcopy(base)
        floating["candidates"][1]["terminal_q32"] = 1.5
        invalids.append(floating)
        invalids.append(request(plan("candidate", [1] * 513)))
        for value in invalids:
            with self.subTest(value=next(iter(value))), self.assertRaises(NduBridgeError):
                self.bridge.evaluate(value)

    def test_snapshot_and_objective_change_receipt_identity(self):
        original = request(plan("candidate", [2, 3]))
        first = self.bridge.evaluate(original)
        for key in ("snapshot_digest", "objective_digest"):
            changed = copy.deepcopy(original)
            changed[key] = digest("different:" + key)
            second = self.bridge.evaluate(changed)
            self.assertNotEqual(first["evaluation_digest"], second["evaluation_digest"])
            self.assertEqual(second[key], changed[key])

    def test_identity_manifest_drift_rejects_before_planning(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "identity.json"
            changed = copy.deepcopy(self.manifest)
            changed["binary_sha256"] = "0" * 64
            path.write_text(json.dumps(changed))
            with self.assertRaisesRegex(NduBridgeError, "executable digest mismatch"):
                NduBridge(self.manifest["binary"], path)
            changed = copy.deepcopy(self.manifest)
            changed["identity"]["source_commit"] = "0" * 40
            path.write_text(json.dumps(changed))
            with self.assertRaisesRegex(NduBridgeError, "source identity"):
                NduBridge(self.manifest["binary"], path)


if __name__ == "__main__":
    unittest.main()
