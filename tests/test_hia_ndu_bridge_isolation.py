"""Three native profiles and two wire schemas keep separate build identities."""
from __future__ import annotations

import json
import os
from pathlib import Path
import unittest
import tempfile
from unittest.mock import patch

from hepta.hia_ndu import FINITE_SOURCE_PIN, NduBridge, NduBridgeError
from hepta.hia_ndu_optimizer import OptimizationRejected, _bridge_identity, _native_rank
from tests.test_hia_ndu import plan as recursive_plan, request as recursive_request
from tests.test_hia_ndu_bridge import candidate as ranking_candidate, request as ranking_request


class RecursiveBridgeConfigurationTests(unittest.TestCase):
    def test_ranking_and_legacy_variables_are_not_recursive_fallbacks(self):
        with patch.dict(os.environ, {"HEPTA_NDU_BRIDGE": "ranking-binary",
                                     "HEPTA_NDU_BUILD": "ranking-build",
                                     "HEPTA_NDU_IDENTITY": "legacy-identity"}, clear=True):
            with self.assertRaisesRegex(NduBridgeError, "HEPTA_RECURSIVE_NDU_BRIDGE"):
                NduBridge.from_environment()

    def test_partial_recursive_configuration_never_borrows_the_ranking_pair(self):
        for configured in ("HEPTA_RECURSIVE_NDU_BRIDGE", "HEPTA_RECURSIVE_NDU_IDENTITY"):
            with self.subTest(configured=configured), patch.dict(os.environ, {
                    configured: "partial-recursive-path", "HEPTA_NDU_BRIDGE": "ranking-binary",
                    "HEPTA_NDU_IDENTITY": "legacy-identity"}, clear=True):
                with self.assertRaisesRegex(NduBridgeError, "are required"):
                    NduBridge.from_environment()


class FiniteBridgeConfigurationTests(unittest.TestCase):
    def test_no_other_profile_or_legacy_variable_is_a_finite_fallback(self):
        other = {"HEPTA_NDU_BRIDGE": "ranking", "HEPTA_NDU_BUILD": "ranking-build",
                 "HEPTA_NDU_IDENTITY": "legacy", "HEPTA_RECURSIVE_NDU_BRIDGE": "recursive",
                 "HEPTA_RECURSIVE_NDU_IDENTITY": "recursive-identity"}
        for partial in ({}, {"HEPTA_FINITE_NDU_BRIDGE": "partial"},
                        {"HEPTA_FINITE_NDU_IDENTITY": "partial"}):
            with self.subTest(partial=partial), patch.dict(os.environ, {**other, **partial}, clear=True):
                with self.assertRaisesRegex(NduBridgeError, "HEPTA_FINITE_NDU_BRIDGE.*are required"):
                    NduBridge.from_finite_environment()

    def test_wrong_source_or_compiler_is_rejected_before_native_execution(self):
        for pin, compiler in (("2" * 40, "rustc 1.95.0 (fixture)"),
                              (FINITE_SOURCE_PIN, "rustc 1.90.0 (fixture)"),
                              (FINITE_SOURCE_PIN, "rustc 1.95.01 (fixture)")):
            with self.subTest(pin=pin, compiler=compiler), tempfile.TemporaryDirectory() as directory:
                identity = Path(directory) / "identity.json"
                identity.write_text(json.dumps({"schema": "hepta.hia.ndu.build.v1",
                    "identity": {"source_commit": pin, "rustc": compiler}}))
                with patch.object(NduBridge, "_invoke", side_effect=AssertionError("must not execute")):
                    with self.assertRaisesRegex(NduBridgeError, "exact source pin"):
                        NduBridge.for_finite_profile("absent-native-binary", identity)


_VARIABLES = ("HEPTA_NDU_BRIDGE", "HEPTA_NDU_BUILD",
              "HEPTA_RECURSIVE_NDU_BRIDGE", "HEPTA_RECURSIVE_NDU_IDENTITY")
_READY = all(os.environ.get(name) for name in _VARIABLES)


@unittest.skipUnless(_READY, "both actual NDU binaries and their distinct build receipts are required")
class NativeBridgeIsolationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ranking = {"binary": os.environ["HEPTA_NDU_BRIDGE"],
                       "build_receipt": str(Path(os.environ["HEPTA_NDU_BUILD"]) / "build-receipt.json")}
        cls.recursive_identity = Path(os.environ["HEPTA_RECURSIVE_NDU_IDENTITY"])
        cls.recursive = NduBridge.from_environment()
        cls.ranking_manifest = json.loads(Path(cls.ranking["build_receipt"]).read_bytes())

    def test_same_process_executes_distinct_source_bound_native_protocols(self):
        ranking, identity = _native_rank(
            self.ranking, ranking_request(ranking_candidate("fast", 1 << 32)), timeout_s=10)
        recursive = self.recursive.evaluate(recursive_request(recursive_plan("continue", [-1, 4])))
        self.assertEqual(ranking["advisory_recommendation"], "fast")
        self.assertEqual(recursive["advisory_candidate_id"], "continue")
        self.assertEqual(ranking["schema"], "hepta.hia.ndu-response.v1")
        self.assertEqual(recursive["schema"], "hepta.hia.ndu.response.v1")
        self.assertEqual(identity["upstream_commit"], self.ranking_manifest["upstream"]["commit"])
        self.assertEqual(recursive["identity"], self.recursive.manifest["identity"])
        self.assertNotEqual(identity["upstream_commit"], recursive["identity"]["source_commit"])
        self.assertNotEqual(identity["binary_sha256"], self.recursive.manifest["binary_sha256"])
        self.assertIs(ranking["proves_program_safety"], False)
        self.assertIs(recursive["safety_certificate"], False)

    def test_each_consumer_rejects_the_other_build_receipt(self):
        with self.assertRaisesRegex(NduBridgeError, "unsupported build identity schema"):
            NduBridge(self.recursive.executable, self.ranking["build_receipt"])
        with self.assertRaisesRegex(OptimizationRejected, "wrong source, scope or build gates"):
            _bridge_identity({"binary": self.ranking["binary"],
                              "build_receipt": str(self.recursive_identity)})

    def test_each_actual_native_protocol_rejects_the_other_request_shape(self):
        with self.assertRaises(NduBridgeError):
            self.recursive.evaluate(ranking_request(ranking_candidate("fast", 1 << 32)))
        with self.assertRaisesRegex(OptimizationRejected, "native evaluator failed"):
            _native_rank(self.ranking, recursive_request(recursive_plan("continue", [-1, 4])), timeout_s=10)


_FINITE_READY = _READY and all(os.environ.get(name) for name in
    ("HEPTA_FINITE_NDU_BRIDGE", "HEPTA_FINITE_NDU_IDENTITY"))


@unittest.skipUnless(_FINITE_READY, "all three actual pinned native profiles are required")
class NativeThreeProfileIsolationTests(unittest.TestCase):
    def test_native_recursive_and_finite_identity_remain_distinct_with_shared_wire(self):
        recursive = NduBridge.from_environment()
        finite = NduBridge.from_finite_environment()
        request = recursive_request(recursive_plan("continue", [-1, 4]))
        older, newer = recursive.evaluate(request), finite.evaluate(request)
        self.assertEqual(older["advisory_candidate_id"], newer["advisory_candidate_id"])
        self.assertEqual(older["schema"], newer["schema"])
        self.assertEqual(newer["identity"]["source_commit"], FINITE_SOURCE_PIN)
        self.assertNotEqual(older["identity"]["source_commit"], FINITE_SOURCE_PIN)
        self.assertNotEqual(recursive.manifest["binary_sha256"], finite.manifest["binary_sha256"])
        self.assertIs(newer["safety_certificate"], False)
        with self.assertRaisesRegex(NduBridgeError, "exact source pin"):
            NduBridge.for_finite_profile(recursive.executable, recursive.identity_manifest)

    def test_finite_profile_cannot_consume_ranking_receipt_or_wire(self):
        finite = NduBridge.from_finite_environment()
        receipt = Path(os.environ["HEPTA_NDU_BUILD"]) / "build-receipt.json"
        with self.assertRaisesRegex(NduBridgeError, "exact source pin"):
            NduBridge.for_finite_profile(finite.executable, receipt)
        with self.assertRaises(NduBridgeError):
            finite.evaluate(ranking_request(ranking_candidate("fast", 1 << 32)))


if __name__ == "__main__":
    unittest.main()
