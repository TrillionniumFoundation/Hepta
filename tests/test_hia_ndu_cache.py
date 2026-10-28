"""Advisory reuse boundaries; native tests separately require the real bridge."""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from hashlib import sha256
import json
import importlib.util
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_ndu import NduBridge, NduBridgeError, finite_plan_request
from hepta.hia_ndu_cache import NduDecisionCache, _wire
from tests.test_hia_ndu_graph import fixture

CLANG = os.environ.get("CLANG", os.environ.get("HEPTA_CLANG", "clang"))


class CountingBridge(NduBridge):
    """Explicit nonnative boundary double; never performance/native evidence."""
    def __init__(self, root):
        self.executable = root / "test-double.bin"
        self.executable.write_bytes(b"not a native NDU executable")
        self.identity_manifest = root / "identity.json"
        self.manifest = {"schema": "hepta.hia.ndu.build.v1",
            "binary_sha256": sha256(self.executable.read_bytes()).hexdigest(),
            "identity": {"source_commit": "1" * 40, "authority": "DENY_ALL", "safety_certificate": False}}
        self.identity_manifest.write_bytes(_wire(self.manifest))
        self.timeout, self.calls, self.bad_response = 10, 0, None

    def evaluate(self, request):
        self.calls += 1
        result = {"schema": "hepta.hia.ndu.response.v1", "status": "advisory",
                  "authority": "DENY_ALL", "safety_certificate": False,
                  "objective_digest": request["objective_digest"],
                  "snapshot_digest": request["snapshot_digest"], "generation": request["generation"],
                  "request_digest": sha256(_wire(request)).hexdigest(),
                  "identity": deepcopy(self.manifest["identity"]),
                  "advisory_candidate_id": request["candidates"][0]["id"],
                  "optimality_scope": "bounded-supplied-candidate-paths-only", "disposition": "UniqueParetoRecommendation",
                  "evaluated_candidate_ids": [row["id"] for row in request["candidates"]],
                  "pareto_candidate_ids": [request["candidates"][0]["id"]], "rejected": [],
                  "evaluation_digest": "a" * 64, "evaluation_policy_digest": "b" * 64,
                  "utility_profile_digest": "c" * 64,
                  "paths": [{"id": row["id"], "verification_digest": row["verification_digest"],
                      "support_digest": row["support_digest"], "resource_cost_q32": row["resource_cost_q32"],
                      "risk_q32": row["risk_q32"], "projection_count": 0,
                      "recursive_evidence_digest": "d" * 64,
                      "values_q32": [1] * (len(row["events"]) + 1)} for row in request["candidates"]]}
        if self.bad_response:
            result.update(self.bad_response)
        return result


class DecisionReuseBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.bridge = CountingBridge(Path(self.temporary.name))
        self.request = finite_plan_request(**fixture())["request"]

    def test_exact_repeat_is_detached_and_does_not_claim_fresh_native_work(self):
        cache = NduDecisionCache(self.bridge)
        before = deepcopy(self.request)
        first, first_receipt = cache.evaluate_with_receipt(self.request)
        expected = deepcopy(first)
        first["authority"] = "ALLOW_ALL"
        first["paths"][0]["values_q32"][0] = 99
        self.request["candidates"][0]["events"][0]["instant_q32"] += 1
        second, second_receipt = cache.evaluate_with_receipt(before)
        self.assertEqual(second, expected)
        self.assertEqual(self.bridge.calls, 1)
        self.assertTrue(first_receipt["native_invoked"])
        self.assertTrue(second_receipt["reused_exact_response"])
        self.assertFalse(second_receipt["fresh_native_evaluation_claim"])
        self.assertFalse(second_receipt["compiler_publication_authorized"])
        self.assertEqual(second_receipt["authority"], "DENY_ALL")

    def test_generation_objective_snapshot_budget_support_and_proof_changes_miss(self):
        cache = NduDecisionCache(self.bridge)
        cache.evaluate(self.request)
        mutations = [lambda x: x.update(generation=x["generation"] + 1),
            lambda x: x.update(objective_digest="8" * 64),
            lambda x: x.update(snapshot_digest="9" * 64),
            lambda x: x.update(resource_budget_q32=x["resource_budget_q32"] - 1),
            lambda x: x["candidates"][0].update(support_digest="a" * 64),
            lambda x: x["candidates"][0].update(verification_digest="b" * 64),
            lambda x: x["candidates"][0]["events"][0].update(instant_q32=-42)]
        for change in mutations:
            request = deepcopy(self.request)
            change(request)
            _, receipt = cache.evaluate_with_receipt(request)
            self.assertFalse(receipt["reused_exact_response"])
        self.assertEqual(self.bridge.calls, 1 + len(mutations))

    def test_lru_and_byte_bounds_do_not_silently_reuse_evicted_entries(self):
        cache = NduDecisionCache(self.bridge, max_entries=2)
        for generation in (1, 2, 1, 3, 2):
            cache.evaluate(dict(self.request, generation=generation))
        self.assertEqual(cache.statistics()["hits"], 1)
        self.assertEqual(cache.statistics()["native_evaluation_attempts"], 4)
        self.assertEqual(cache.statistics()["entries"], 2)
        self.assertEqual(cache.statistics()["evictions"], 2)
        tiny = NduDecisionCache(self.bridge, max_bytes=1)
        tiny.evaluate(self.request)
        tiny.evaluate(self.request)
        self.assertEqual(tiny.statistics()["entries"], 0)
        self.assertEqual(tiny.statistics()["oversize_not_retained"], 2)
        self.assertEqual(tiny.statistics()["retained_payload_bytes"], 0)

    def test_manifest_and_binary_drift_reject_before_reusing_a_result(self):
        cache = NduDecisionCache(self.bridge)
        cache.evaluate(self.request)
        for target in (self.bridge.identity_manifest, self.bridge.executable):
            original = target.read_bytes()
            target.write_bytes(original + b" ")
            with self.assertRaises(NduBridgeError):
                cache.evaluate(self.request)
            target.write_bytes(original)
        old = self.bridge.manifest["identity"]["source_commit"]
        self.bridge.manifest["identity"]["source_commit"] = "2" * 40
        with self.assertRaisesRegex(NduBridgeError, "drift"):
            cache.evaluate(self.request)
        self.bridge.manifest["identity"]["source_commit"] = old
        self.assertEqual(self.bridge.calls, 1)

    def test_corrupt_entry_refuses_without_native_fallback(self):
        cache = NduDecisionCache(self.bridge)
        cache.evaluate(self.request)
        key, row = next(iter(cache._entries.items()))
        cache._entries[key] = (row[0], row[1] + b" ", row[2], row[3])
        with self.assertRaisesRegex(NduBridgeError, "corrupted entry"):
            cache.evaluate(self.request)
        self.assertEqual(self.bridge.calls, 1)
        self.assertEqual(cache.statistics()["entries"], 0)
        self.assertEqual(cache.statistics()["retained_payload_bytes"], 0)

    def test_hit_revalidates_schema_authority_and_binding(self):
        for change in ({"schema": "other"}, {"authority": "ALLOW_ALL"},
                       {"safety_certificate": True}, {"generation": 999},
                       {"advisory_candidate_id": "unknown"}):
            cache = NduDecisionCache(self.bridge)
            cache.evaluate(self.request)
            key, row = next(iter(cache._entries.items()))
            response = json.loads(row[1])
            response.update(change)
            poisoned = _wire(response)
            cache._entries[key] = (row[0], poisoned, sha256(poisoned).hexdigest(), row[3])
            before = self.bridge.calls
            with self.assertRaises(NduBridgeError):
                cache.evaluate(self.request)
            self.assertEqual(self.bridge.calls, before)

    def test_bad_fresh_response_never_enters_cache(self):
        for change in ({"authority": "ALLOW_ALL"}, {"request_digest": "0" * 64},
                       {"identity": {}}, {"status": "proved"}):
            self.bridge.bad_response = change
            cache = NduDecisionCache(self.bridge)
            with self.assertRaises(NduBridgeError):
                cache.evaluate(self.request)
            self.assertEqual(cache.statistics()["entries"], 0)

    def test_hit_rejects_boolean_costs_and_inconsistent_dispositions(self):
        mutations = [lambda x: next(p for p in x["paths"] if p["id"] == "abstain").update(resource_cost_q32=False),
                     lambda x: x["paths"][0].update(risk_q32=False),
                     lambda x: x.update(disposition="UnknownDisposition"),
                     lambda x: x.update(disposition="ParetoSetRequiresSlowPath"),
                     lambda x: x.update(disposition="InfeasibleExplicitAbstain"),
                     lambda x: x.update(advisory_candidate_id=None)]
        for change in mutations:
            cache = NduDecisionCache(self.bridge)
            cache.evaluate(self.request)
            key, row = next(iter(cache._entries.items()))
            response = json.loads(row[1])
            change(response)
            poisoned = _wire(response)
            cache._entries[key] = (row[0], poisoned, sha256(poisoned).hexdigest(), row[3])
            previous = self.bridge.calls
            with self.assertRaises(NduBridgeError):
                cache.evaluate(self.request)
            self.assertEqual(self.bridge.calls, previous)

    def test_identity_drift_during_hit_response_validation_refuses(self):
        from hepta import hia_ndu_cache as module
        cache = NduDecisionCache(self.bridge)
        cache.evaluate(self.request)
        original = module._validate_response
        def drift(*args):
            original(*args)
            with self.bridge.executable.open("ab") as stream:
                stream.write(b"changed while validating cached response")
        with patch.object(module, "_validate_response", side_effect=drift):
            with self.assertRaisesRegex(NduBridgeError, "digest mismatch"):
                cache.evaluate(self.request)
        self.assertEqual(self.bridge.calls, 1)

    def test_concurrent_identical_requests_share_one_native_result(self):
        cache = NduDecisionCache(self.bridge)
        with ThreadPoolExecutor(max_workers=8) as executor:
            answers = list(executor.map(cache.evaluate_with_receipt, [self.request] * 16))
        self.assertEqual(self.bridge.calls, 1)
        self.assertEqual(sum(receipt["reused_exact_response"] for _, receipt in answers), 15)
        self.assertTrue(all(result == answers[0][0] for result, _ in answers))

    def test_closed_owner_rejects_and_releases_all_retained_payloads(self):
        cache = NduDecisionCache(self.bridge)
        cache.evaluate(self.request)
        report = cache.close()
        self.assertTrue(report["closed"])
        self.assertEqual((report["entries"], report["retained_payload_bytes"]), (0, 0))
        self.assertEqual(cache.close(), report)
        with self.assertRaisesRegex(NduBridgeError, "closed"):
            cache.evaluate(self.request)

    def test_invalid_limits_json_and_nonregular_receipts_refuse(self):
        for kwargs in ({"max_entries": True}, {"max_entries": 0}, {"max_entries": 129},
                       {"max_bytes": 0}, {"max_bytes": 1.5}):
            with self.assertRaises(NduBridgeError):
                NduDecisionCache(self.bridge, **kwargs)
        cache = NduDecisionCache(self.bridge)
        for value in ([], {"value": float("nan")}, {"payload": "x" * 1048576}):
            with self.assertRaises(NduBridgeError):
                cache.evaluate(value)
        self.bridge.identity_manifest.unlink()
        self.bridge.identity_manifest.symlink_to(self.bridge.executable)
        with self.assertRaises(NduBridgeError):
            cache.evaluate(self.request)


@unittest.skipUnless(os.environ.get("HEPTA_FINITE_NDU_IDENTITY")
                     and os.environ.get("HEPTA_FINITE_NDU_BRIDGE"),
                     "requires the actual pinned finite Rust NDU bridge")
class NativeDecisionReuseTests(unittest.TestCase):
    def setUp(self):
        self.bridge = NduBridge.from_finite_environment()
        self.cache = NduDecisionCache(self.bridge, max_entries=4)
        self.addCleanup(self.cache.close)

    def test_original_native_result_is_reused_only_for_exact_request(self):
        request = finite_plan_request(**fixture())["request"]
        native = self.bridge.evaluate(request)
        first, a = self.cache.evaluate_with_receipt(request)
        second, b = self.cache.evaluate_with_receipt(request)
        self.assertEqual(first, native)
        self.assertEqual(second, native)
        self.assertEqual((a["native_invoked"], b["native_invoked"]), (True, False))
        changed = dict(request, resource_budget_q32=1)
        result, receipt = self.cache.evaluate_with_receipt(changed)
        self.assertTrue(receipt["native_invoked"])
        self.assertEqual(result["advisory_candidate_id"], "abstain")

    def test_actual_native_refusal_is_never_cached(self):
        request = finite_plan_request(**fixture())["request"]
        request["candidate_execution_authorized"] = True
        for _ in range(2):
            with self.assertRaises(NduBridgeError):
                self.cache.evaluate(request)
        self.assertEqual(self.cache.statistics()["entries"], 0)
        self.assertEqual(self.cache.statistics()["native_evaluation_attempts"], 2)

    def test_existing_compiler_graph_consumer_reuses_advice_without_authority(self):
        from tools.qualify_hia_ndu_graph import choose_native_graph_plan
        bundle = finite_plan_request(**fixture())
        self.cache.evaluate(bundle["request"])
        selected, response, receipt = choose_native_graph_plan(bundle, self.bridge, decision_cache=self.cache)
        self.assertEqual(selected["id"], response["advisory_candidate_id"])
        self.assertTrue(receipt["reused_exact_response"])
        self.assertFalse(receipt["compiler_publication_authorized"])
        self.assertEqual(self.cache.statistics()["native_evaluation_attempts"], 1)
        self.assertTrue(selected["verified"])


class DecisionReuseProtocolTests(unittest.TestCase):
    def test_registered_traces_provide_exact_reuse_and_changed_identity_controls(self):
        from tools.qualify_hia_ndu_reuse import PROTOCOL_PATH, make_trace, validate_protocol
        protocol = validate_protocol(json.loads(PROTOCOL_PATH.read_bytes()))
        for profile, unique in (("identical-retries", 8), ("changed-generation", 64)):
            trace = make_trace(protocol, profile, 0)
            self.assertEqual(len(trace), 64)
            self.assertEqual(len({_wire(x["arguments"]) for x in trace}), unique)
        for name, value in (("groups", True), ("keys_per_trace", 999), ("cache_entries", 1),
                            ("episode_budget_ns", 0), ("arms", ["native-exact-reuse"])):
            with self.assertRaises(ValueError):
                validate_protocol(dict(protocol, **{name: value}))

    def test_strong_control_gets_same_exact_reuse_capacity_and_changed_input_misses(self):
        from tools.qualify_hia_ndu_reuse import (PROTOCOL_PATH, PlanReuseControl, load_bank,
                                               make_trace, validate_protocol)
        from tools.qualify_hia_ndu_graph import arithmetic_choice, graph_bundle, light_bundle
        protocol = validate_protocol(json.loads(PROTOCOL_PATH.read_bytes()))
        bank = load_bank(protocol)
        for profile in protocol["trace_profiles"]:
            cache, constructions = PlanReuseControl(protocol), []
            for item in make_trace(protocol, profile, 0):
                arguments = item["arguments"]
                def construct():
                    constructions.append(1)
                    return arithmetic_choice(light_bundle(bank, **arguments),
                        remaining_ns=arguments["remaining_ns"], completion_ns=protocol["graph_completion_value_ns"])
                result, _ = cache.evaluate(bank, arguments, construct)
                expected = arithmetic_choice(graph_bundle(bank, **arguments),
                    remaining_ns=arguments["remaining_ns"], completion_ns=protocol["graph_completion_value_ns"])
                for field in ("id", "actions", "estimated_cost_ns", "verified"):
                    self.assertEqual(result[field], expected[field])
            closed = cache.close()
            self.assertEqual(len(constructions), 8 if profile == "identical-retries" else 64)
            self.assertEqual(closed["hits"], 56 if profile == "identical-retries" else 0)
            self.assertEqual((closed["entries"], closed["retained_payload_bytes"]), (0, 0))


@unittest.skipUnless(os.environ.get("HEPTA_FINITE_NDU_IDENTITY")
                     and os.environ.get("HEPTA_FINITE_NDU_BRIDGE")
                     and shutil.which(CLANG) and importlib.util.find_spec("z3"),
                     "requires actual finite NDU, Clang and Z3 for compiler integration")
class NativeReuseCompilerIntegrationTests(unittest.TestCase):
    def test_existing_graph_opt_in_still_proves_builds_and_executes_candidates(self):
        from tools.qualify_hia_ndu_graph import PROTOCOL, qualify
        with tempfile.TemporaryDirectory() as temporary:
            protocol = dict(PROTOCOL, groups=1, calls=16, probe_size=3, batch_sizes=[3, 17, 33],
                            guard_limits={"guard-small": 8, "guard-wide": 64})
            result = qualify(Path(temporary) / "graph", identity=Path(os.environ["HEPTA_FINITE_NDU_IDENTITY"]),
                             clang=CLANG, protocol=protocol, decision_cache_entries=8)
            self.assertTrue(result["all_episodes_completed"])
            self.assertTrue(result["all_outputs_correct"])
            self.assertGreaterEqual(result["actual_transitions"], 2)
            reused = result["exact_advisory_reuse"]
            self.assertTrue(reused["closed"])
            self.assertEqual((reused["entries"], reused["retained_payload_bytes"]), (0, 0))
            # Calibration uses native misses; observed episode snapshots differ
            # and must not inherit an artificially cheap calibration-hit cost.
            self.assertEqual(reused["hits"], 0)
            self.assertGreaterEqual(reused["native_evaluation_attempts"], 1)
            self.assertFalse(result["safety_from_ndu_claim"])


if __name__ == "__main__":
    unittest.main()
