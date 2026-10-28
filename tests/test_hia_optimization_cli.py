"""Agent-facing CLI contracts over actual translation proof and native NDU."""
from contextlib import redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from hepta.cli import main
from hepta.hia_program import verify_program
from tests.test_hia_multiversion import cyclic_program, scalar_program


_Z3 = importlib.util.find_spec("z3") is not None
_BRIDGE = os.environ.get("HEPTA_NDU_BRIDGE")
_BUILD = os.environ.get("HEPTA_NDU_BUILD")


class CLIInputs(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="hia-optimization-cli-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.before = self.write("before.hia.json", scalar_program())

    def write(self, name, value):
        path = self.directory / name
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def call(self, arguments):
        with redirect_stdout(io.StringIO()) as output:
            code = main(arguments)
        return code, json.loads(output.getvalue())


class OptionalProofCLITests(CLIInputs):
    def test_existing_core_verification_does_not_require_z3(self):
        with patch.dict(sys.modules, {"z3": None}):
            code, report = self.call(["hia", "verify", str(self.before)])
        self.assertEqual(code, 0)
        self.assertEqual(report["status"], "standalone_core_checked")

    def test_missing_z3_returns_nonzero_unknown_translation(self):
        after = self.write("after.hia.json", scalar_program(None))
        with patch.dict(sys.modules, {"z3": None}):
            code, report = self.call(["hia", "verify-translation", str(self.before), str(after),
                                     "--function", "calculate", "--json"])
        self.assertNotEqual(code, 0)
        self.assertEqual(report["status"], "unknown")
        self.assertFalse(report["claims"]["all_input_behavior_equivalence_proved"])

    def test_translation_input_uses_existing_nofollow_bounded_reader(self):
        after = self.write("after.hia.json", scalar_program(None))
        alias = self.directory / "alias.json"
        alias.symlink_to(after)
        code, report = self.call(["hia", "verify-translation", str(self.before), str(alias),
                                 "--function", "calculate"])
        self.assertNotEqual(code, 0)
        self.assertEqual(report["status"], "error")


@unittest.skipUnless(_Z3, "actual Z3 is required")
class TranslationCLITests(CLIInputs):
    def test_proved_equivalence_has_zero_exit_and_exact_input_identities(self):
        after = self.write("after.hia.json", scalar_program(None))
        code, report = self.call(["hia", "verify-translation", str(self.before), str(after),
                                 "--function", "calculate", "--timeout-ms", "2000", "--json"])
        self.assertEqual(code, 0)
        self.assertEqual(report["status"], "proved")
        self.assertEqual(report["before_sha256"], verify_program(self.before.read_bytes()).sha256)
        self.assertEqual(report["after_sha256"], verify_program(after.read_bytes()).sha256)
        self.assertFalse(report["claims"]["backend_refinement_proved"])

    def test_counterexample_and_unknown_are_both_nonzero(self):
        after = self.write("different.hia.json", scalar_program(value=1))
        code, report = self.call(["hia", "verify-translation", str(self.before), str(after),
                                 "--function", "calculate"])
        self.assertEqual(code, 1)
        self.assertEqual(report["status"], "disproved")
        self.assertIsNotNone(report["counterexample"])
        loop = self.write("loop.hia.json", cyclic_program())
        code, report = self.call(["hia", "verify-translation", str(loop), str(loop),
                                 "--function", "calculate"])
        self.assertEqual(code, 1)
        self.assertEqual(report["status"], "unknown")


@unittest.skipUnless(_Z3 and _BRIDGE and _BUILD and Path(_BRIDGE).is_file(),
                     "actual Z3 and pinned native NDU build are required")
class OptimizationCLITests(CLIInputs):
    def inputs(self, *, slower=False):
        from hepta.hia_finite_actions import propose_candidates
        base = verify_program(self.before.read_bytes())
        proposals = propose_candidates(base, function="calculate", max_candidates=8)
        self.assertTrue(proposals)
        observations = {"abstain": {"runtime_ns": 10_000_000, "uncertainty_ns": 0,
                                    "search_ns": 13, "program_sha256": base.sha256}}
        for index, proposed in enumerate(proposals):
            observations[proposed["id"]] = {
                "runtime_ns": 20_000_000 if slower else (index + 1) * 1_000_000,
                "uncertainty_ns": 0, "search_ns": 17,
                "program_sha256": verify_program(proposed["program"]).sha256}
        objective = {"expected_calls": 1000, "resource_cap_ns": 5_000_000_000,
                     "target": "x86_64-unknown-linux-gnu", "measurement_profile": "cli-contract-test-synthetic-costs"}
        observed_file = self.write("observations.json", observations)
        objective_file = self.write("objective.json", objective)
        arguments = ["hia", "optimize", str(self.before), "--function", "calculate",
                     "--bridge", _BRIDGE, "--bridge-build-receipt", str(Path(_BUILD) / "build-receipt.json"),
                     "--observations", str(observed_file), "--objective", str(objective_file),
                     "--max-candidates", "8", "--timeout-ms", "2000", "--json"]
        return arguments, observations, observed_file, proposals

    def test_actual_native_decision_requires_proof_and_charges_real_cli_preparation_once(self):
        arguments, observations, observed_file, proposals = self.inputs()
        original_bytes = observed_file.read_bytes()
        code, report = self.call(arguments)
        self.assertEqual(code, 0)
        self.assertTrue(report["admitted"])
        self.assertEqual(report["selected_id"], proposals[0]["id"])
        self.assertEqual(report["selected_fresh_proof"]["status"], "proved")
        self.assertEqual(report["native_response"]["authority"], "ADVISORY_ONLY")
        measured = report["cli_preparation_cost"]["measured_ns"]
        self.assertGreater(measured, 0)
        self.assertEqual(report["costs"]["supplied_search_ns"],
                         sum(v["search_ns"] for v in observations.values()) + measured)
        self.assertEqual(observed_file.read_bytes(), original_bytes)
        self.assertFalse(report["claims"]["measurements_independently_attested"])

    def test_baseline_retention_is_a_successful_decision(self):
        arguments, _, _, _ = self.inputs(slower=True)
        code, report = self.call(arguments)
        self.assertEqual(code, 0)
        self.assertEqual(report["selected_id"], "abstain")
        self.assertFalse(report["admitted"])
        self.assertEqual(verify_program(report["selected_program"]).sha256,
                         verify_program(self.before.read_bytes()).sha256)

    def test_stale_or_incomplete_observations_return_structured_nonzero_errors(self):
        for failure in ("stale", "missing"):
            arguments, observations, observed_file, proposals = self.inputs()
            if failure == "stale":
                observations[proposals[0]["id"]]["program_sha256"] = "0" * 64
            else:
                observations.pop(proposals[0]["id"])
            observed_file.write_text(json.dumps(observations))
            code, report = self.call(arguments)
            with self.subTest(failure=failure):
                self.assertNotEqual(code, 0)
                self.assertEqual(report["status"], "error")

    def test_duplicate_observation_keys_and_excessive_input_are_not_decoded(self):
        arguments, _, observed_file, _ = self.inputs()
        observed_file.write_text('{"abstain":{},"abstain":{}}')
        code, report = self.call(arguments)
        self.assertNotEqual(code, 0)
        self.assertEqual(report["status"], "error")
        observed_file.write_bytes(b" " * (1024 * 1024 + 1))
        code, report = self.call(arguments)
        self.assertNotEqual(code, 0)
        self.assertEqual(report["status"], "error")


if __name__ == "__main__":
    unittest.main()
