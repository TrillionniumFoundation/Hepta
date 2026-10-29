"""Actual native replies, then explicitly injected response-contract faults.

The faults modify replies after the original executable has evaluated the real
request. They test host rejection, not a faulty upstream implementation or
performance. Session tests reuse the same faults and additionally check reaping.
"""
from contextlib import closing
from copy import deepcopy
from hashlib import sha256
import os
from pathlib import Path
import unittest
from unittest.mock import patch

from hepta.hia_ndu import NduBridge, NduBridgeError, Q32, _read_json
from hepta.hia_ndu_cache import NduDecisionCache, _wire
from hepta.hia_ndu_response import NduResponseError, RESPONSE_PROFILE, validate_response
from tests.test_hia_ndu import plan, request


def response_faults():
    return {
        "unknown-field": lambda x: x.update(future_authority="ALLOW_ALL"),
        "missing-paths": lambda x: x.pop("paths"),
        "boolean-generation": lambda x: x.update(generation=True),
        "identity-boolean-alias": lambda x: x["identity"].update(safety_certificate=0),
        "non-scalar-choice": lambda x: x.update(advisory_candidate_id=[]),
        "unevaluated-frontier": lambda x: x.update(evaluated_candidate_ids=["abstain"]),
        "chosen-outside-frontier": lambda x: x.update(pareto_candidate_ids=["abstain"]),
        "duplicate-evaluation": lambda x: x["evaluated_candidate_ids"].append("candidate"),
        "missing-evaluation": lambda x: x.update(evaluated_candidate_ids=["candidate"]),
        "overlapping-rejection": lambda x: x["rejected"].append({"id": "candidate", "reasons": ["HardConstraintViolation"]}),
        "duplicate-rejection": lambda x: x["rejected"].append(deepcopy(x["rejected"][0])),
        "unknown-rejection-field": lambda x: x["rejected"][0].update(extra=True),
        "non-scalar-rejection-id": lambda x: x["rejected"][0].update(id=[]),
        "empty-rejection-reasons": lambda x: x["rejected"][0].update(reasons=[]),
        "empty-rejection-reason": lambda x: x["rejected"][0].update(reasons=[""]),
        "boolean-cost": lambda x: x["paths"][0].update(resource_cost_q32=False),
        "excess-cost": lambda x: x["paths"][0].update(resource_cost_q32=1 << 63),
        "unbound-cost": lambda x: x["paths"][0].update(resource_cost_q32=1),
        "boolean-risk": lambda x: x["paths"][0].update(risk_q32=False),
        "excess-risk": lambda x: x["paths"][0].update(risk_q32=Q32 + 1),
        "unbound-risk": lambda x: x["paths"][0].update(risk_q32=1),
        "unbound-verification": lambda x: x["paths"][0].update(verification_digest="a" * 64),
        "unbound-support": lambda x: x["paths"][0].update(support_digest="b" * 64),
        "duplicate-path": lambda x: x["paths"][0].update(id=x["paths"][1]["id"]),
        "non-scalar-path-id": lambda x: x["paths"][0].update(id=[]),
        "unknown-path-field": lambda x: x["paths"][0].update(extra=True),
        "floating-value": lambda x: x["paths"][0]["values_q32"].__setitem__(0, 0.5),
        "boolean-value": lambda x: x["paths"][0]["values_q32"].__setitem__(0, False),
        "truncated-path": lambda x: x["paths"][0]["values_q32"].pop(),
        "boolean-projection": lambda x: x["paths"][0].update(projection_count=False),
        "unsupported-projection": lambda x: x["paths"][0].update(projection_count=1),
        "bad-recursive-digest": lambda x: x["paths"][0].update(recursive_evidence_digest="0" * 64),
        "bad-evaluation-digest": lambda x: x.update(evaluation_digest="0" * 64),
        "unknown-disposition": lambda x: x.update(disposition="UnknownDisposition"),
        "null-unique-choice": lambda x: x.update(advisory_candidate_id=None),
    }


def fault_request():
    return request(plan("candidate", [3]), plan("unsafe", [99], verified=False))


@unittest.skipUnless(all(os.environ.get(name) for name in (
    "HEPTA_RECURSIVE_NDU_IDENTITY", "HEPTA_RECURSIVE_NDU_BRIDGE",
    "HEPTA_FINITE_NDU_IDENTITY", "HEPTA_FINITE_NDU_BRIDGE")),
    "requires the actual pinned recursive and finite native NDU bridges")
class NativeResponseContractTests(unittest.TestCase):
    def bridges(self):
        return (("recursive", NduBridge.from_environment()),
                ("finite", NduBridge.from_finite_environment()))

    def test_original_native_unique_tie_and_abstain_replies_match_cached_routes(self):
        cases = (fault_request(), request(plan("a", [2]), plan("b", [2])),
                 request(plan("unsafe", [99], verified=False)))
        for profile, bridge in self.bridges():
            for value in cases:
                with self.subTest(profile=profile, candidates=value["candidates"]):
                    native = bridge.evaluate(value)
                    with closing(NduDecisionCache(bridge)) as cache:
                        fresh, first = cache.evaluate_with_receipt(value)
                        reused, second = cache.evaluate_with_receipt(value)
                    self.assertEqual((fresh, reused), (native, native))
                    self.assertEqual((first["native_invoked"], second["native_invoked"]), (True, False))
                    self.assertFalse(second["compiler_publication_authorized"])

    def test_malformed_actual_replies_refuse_with_and_without_caching(self):
        value = fault_request()
        for profile, bridge in self.bridges():
            for name, mutate in response_faults().items():
                for cached in (False, True):
                    with self.subTest(profile=profile, fault=name, cached=cached):
                        invoke = bridge._invoke
                        def malformed(arguments, payload):
                            reply = invoke(arguments, payload)
                            mutate(reply)
                            return reply
                        with closing(NduDecisionCache(bridge)) as cache:
                            with patch.object(bridge, "_invoke", side_effect=malformed):
                                with self.assertRaises(NduBridgeError):
                                    (cache if cached else bridge).evaluate(value)
                            self.assertEqual(cache.statistics()["entries"], 0)

    def test_malformed_retained_native_replies_refuse_without_fresh_native_fallback(self):
        value = fault_request()
        for profile, bridge in self.bridges():
            for name, mutate in response_faults().items():
                with self.subTest(profile=profile, fault=name), closing(NduDecisionCache(bridge)) as cache:
                    cache.evaluate(value)
                    key, row = next(iter(cache._entries.items()))
                    response = _read_json(row[1])
                    mutate(response)
                    raw = _wire(response)
                    cache._entries[key] = (row[0], raw, sha256(raw).hexdigest(), row[3])
                    with patch.object(bridge, "_invoke", side_effect=AssertionError("unexpected native fallback")):
                        with self.assertRaises(NduBridgeError):
                            cache.evaluate(value)

    def test_unknown_response_profile_cannot_inherit_admission_of_an_actual_reply(self):
        bridge = NduBridge.from_finite_environment()
        value = fault_request()
        response = bridge.evaluate(value)
        validate_response(response, value, _wire(value), bridge.manifest, profile=RESPONSE_PROFILE)
        with self.assertRaisesRegex(NduResponseError, "unsupported validation profile"):
            validate_response(response, value, _wire(value), bridge.manifest, profile=RESPONSE_PROFILE + ".future")

    def test_shared_validator_source_drift_invalidates_already_cached_native_advice(self):
        from hepta import hia_ndu_response
        bridge = NduBridge.from_finite_environment()
        value = fault_request()
        with closing(NduDecisionCache(bridge)) as cache:
            cache.evaluate(value)
            validator = Path(hia_ndu_response.__file__)
            read = Path.read_bytes
            def drift(path):
                raw = read(path)
                return raw + b"\n# simulated source drift\n" if path == validator else raw
            with patch.object(Path, "read_bytes", drift):
                with self.assertRaisesRegex(NduBridgeError, "implementation drift"):
                    cache.evaluate(value)


if __name__ == "__main__":
    unittest.main()
