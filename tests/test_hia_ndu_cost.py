"""Independent exhaustive checks for the explicitly bounded v2 cost profile."""
from copy import deepcopy
import itertools
import random
import unittest

from hepta.hia_ndu_cost import (SCHEMA, AdvisoryController, CostModelError, build_request,
    digest, exact_control, invocation_gate, skip_schedule, validate_model)


def fixture(horizon=3):
    return {"schema": SCHEMA, "objective_digest": digest("objective"), "generation": 1,
        "baseline": {"source_sha256": digest("base"), "verification_sha256": digest("base-proof"),
                     "latency_ns": [1000] * horizon},
        "variants": [{"id": name, "source_sha256": digest(name), "verification_sha256": digest(name+"proof"),
            "support_sha256": digest("support"), "status": "verified", "valid": [True] * horizon,
            "prepare_ns": 100, "proof_ns": 80, "retire_ns": 20, "holding_ns": 10,
            "resident_bytes": 1, "latency_ns": [latency] * horizon}
            for name, latency in (("a", 100), ("b", 200))],
        "ready": [], "memory_budget_bytes": 1, "budget_ns": 1000000,
        "sunk_cost_ns": 0, "completion_value_ns": 10000000,
        "decision": {"gate_ns": 5, "search_ns": 7, "native_ns": 11,
                     "transport_ns": 13, "validation_ns": 17, "startup_ns": 19, "close_ns": 23},
        "session_ready": False, "observation_sha256": digest("observations")}


def independent_exhaustive(model):
    """Enumerate modes and residency sequences without calling production steps."""
    names = [v["id"] for v in model["variants"]]
    rows = {v["id"]: v for v in model["variants"]}
    horizon = len(model["baseline"]["latency_ns"])
    sets = [set(c) for n in range(len(names)+1) for c in itertools.combinations(names,n)
            if sum(rows[x]["resident_bytes"] for x in c) <= model["memory_budget_bytes"]]
    choices = [None, *sets]  # None means skip the planner and keep valid objects.
    best = None
    for schedule in itertools.product(choices, repeat=horizon):
        ready = set(model["ready"])
        session = model["session_ready"]
        total = 0
        valid = True
        for batch, target in enumerate(schedule):
            available = {n for n in names if rows[n]["valid"][batch] and rows[n]["status"] == "verified"}
            live = ready & available
            destination = live if target is None else target
            if not destination <= available:
                valid = False
                break
            total += model["decision"]["gate_ns"]
            total += sum(rows[n]["retire_ns"] for n in ready-destination)
            total += sum(rows[n]["prepare_ns"]+rows[n]["proof_ns"] for n in destination-live)
            total += sum(rows[n]["holding_ns"] for n in destination)
            if target is not None:
                total += sum(model["decision"][k] for k in ("search_ns","native_ns","transport_ns","validation_ns"))
                if not session:
                    total += model["decision"]["startup_ns"]
                session = True
            total += min([model["baseline"]["latency_ns"][batch]]+[rows[n]["latency_ns"][batch] for n in destination])
            ready = destination
        if session:
            total += model["decision"]["close_ns"]
        if valid and total <= model["budget_ns"] and (best is None or total < best):
            best = total
    return best


class FullCostTests(unittest.TestCase):
    def test_exact_matches_independent_enumeration(self):
        rng = random.Random(104729)
        for case in range(96):
            model = fixture(1+case%4)
            horizon = len(model["baseline"]["latency_ns"])
            model["baseline"]["latency_ns"] = [rng.randrange(50,1500) for _ in range(horizon)]
            model["budget_ns"] = rng.randrange(100,10000)
            model["session_ready"] = bool(case%2)
            model["memory_budget_bytes"] = case%3
            for row in model["variants"]:
                row["latency_ns"] = [rng.randrange(50,1500) for _ in range(horizon)]
                row["valid"] = [rng.randrange(4) != 0 for _ in range(horizon)]
                row["prepare_ns"] = rng.randrange(500)
                row["proof_ns"] = rng.randrange(500)
                row["retire_ns"] = rng.randrange(500)
                row["holding_ns"] = rng.randrange(100)
            with self.subTest(case=case):
                best = exact_control(model)["best"]
                self.assertEqual(best["total_ns"] if best else None, independent_exhaustive(model))
                gate = invocation_gate(model)
                if gate["mode"] == "skip":
                    self.assertEqual(best["total_ns"],gate["skip"]["total_ns"])

    def test_future_decisions_can_cancel_short_lived_gain(self):
        model = fixture(3)
        model["variants"][0]["latency_ns"] = [1, 900, 1]
        model["variants"][1]["latency_ns"] = [900, 1, 900]
        model["decision"]["native_ns"] = 2000
        self.assertTrue(all(a["mode"] == "skip" for a in exact_control(model)["best"]["actions"]))
        self.assertEqual(invocation_gate(model)["mode"], "consider")

    def test_skip_does_not_create_session(self):
        model = fixture()
        model["decision"]["startup_ns"] = 100000
        created = []
        controller = AdvisoryController(lambda: created.append(True))
        action, row = controller.decide(model)
        self.assertEqual(action["mode"], "skip")
        self.assertFalse(row["native_invoked"])
        self.assertEqual(created, [])

    def test_invalidation_retires_even_on_skip(self):
        model = fixture(3)
        model["ready"] = ["a"]
        model["variants"][0]["valid"] = [True, False, True]
        plan = skip_schedule(model)
        self.assertEqual([a["dispatch"] for a in plan["actions"]], ["a", "baseline", "baseline"])
        self.assertEqual(plan["actions"][1]["invalidated"], ["a"])
        self.assertEqual(plan["actions"][1]["costs"]["retire_ns"], 20)
        self.assertEqual(plan["actions"][2]["acquired"], [])

    def test_budget_and_sunk_cost_are_not_double_charged(self):
        model = fixture()
        before = exact_control(model)
        model["sunk_cost_ns"] = 999999
        self.assertEqual(before, exact_control(model))
        model["budget_ns"] = 1
        self.assertIsNone(exact_control(model)["best"])
        self.assertEqual(invocation_gate(model)["mode"], "refuse")

    def test_rejected_variant_not_recovered_by_digest(self):
        model = fixture()
        model["ready"] = ["a"]
        model["variants"][0]["status"] = "rejected"
        for witness in exact_control(model)["witnesses"]:
            self.assertTrue(all(a["dispatch"] != "a" for a in witness["actions"]))

    def test_proof_prepare_holding_and_session_close_are_charged(self):
        model = fixture()
        best = exact_control(model)["best"]
        self.assertEqual(best["actions"][0]["acquired"], ["a"])
        expected = 3*(5+10+100)+100+80+7+11+13+17+19+23
        self.assertEqual(best["total_ns"], expected)
        self.assertEqual([a["mode"] for a in best["actions"]], ["invoke","skip","skip"])

    def test_native_request_charges_committed_current_call(self):
        model = fixture()
        bundle = build_request(model)
        self.assertEqual(bundle["authority"], "DENY_ALL")
        self.assertFalse(bundle["safety_certificate"])
        call = sum(model["decision"][k] for k in ("search_ns","native_ns","transport_ns","validation_ns","startup_ns"))
        for plan in bundle["plans"].values():
            if plan["actions"][0]["mode"] == "skip":
                self.assertEqual(plan["current_committed_ns"], call)
            self.assertEqual(plan["total_ns"], sum(a["total_ns"] for a in plan["actions"])+plan["close_ns"]+plan["current_committed_ns"])

    def test_strict_model_rejects_unbounded_or_implicit_fields(self):
        for key, value in (("generation", True), ("budget_ns", -1), ("session_ready", 1)):
            model = fixture()
            model[key] = value
            with self.subTest(key=key), self.assertRaises(CostModelError):
                validate_model(model)
        model = fixture()
        model["decision"].pop("native_ns")
        with self.assertRaises(CostModelError):
            validate_model(model)


if __name__ == "__main__":
    unittest.main()
