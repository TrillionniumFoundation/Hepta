"""Finite lifecycle versions, resource exclusions and measured publication."""
from __future__ import annotations

import copy
import importlib.util
import os
from pathlib import Path
import shutil
import tempfile
import unittest

from hepta.hia_multiversion import (MultiversionRejected, PublicationCancellation,
    ScalarMultiversionRuntime, _admissible, _assess_measurement, _measurement_snapshot)
from hepta.hia_program import HIAProgramRejected, verify_program
from hepta.hia_program_llvm import build_program_native
from hepta.hia_program_runtime import execute_program
from hepta.hia_specialization import propose_guarded_specializations
from hepta.hia_translation_validation import validate_translation
from tests.test_hia_program import b, c, f, i, m, resource_program, ret
from tools.qualify_hia_native_lifecycle_convergence import measurement_for, run, transition_program


def policy_input():
    return measurement_for(transition_program(), transition_program(1), "a" * 64, "b" * 64,
        [{"baseline_ns": 1_000_000, "candidate_ns": 1} for _ in range(31)]) | {
            "calls_per_sample": 1, "horizon_calls": 1_000_000}


class NativeProfileBoundaryTests(unittest.TestCase):
    def test_v8_keeps_core_execution_but_refuses_lifecycle_and_specialization(self):
        source = transition_program(version=8)
        self.assertEqual(execute_program(source, "transition", [7, 5])["result"], 12)
        self.assertEqual(validate_translation(source, source, function="transition")["status"], "unknown")
        with self.assertRaisesRegex(MultiversionRejected, "primitive v1-v7"):
            _admissible(source)
        with self.assertRaisesRegex(HIAProgramRejected, "primitive v1-v7"):
            propose_guarded_specializations(source, function="transition", assumptions=[{"parameter": "delta", "value": 0}])
        for version in (1, 7):
            self.assertEqual(_admissible(transition_program(version=version))[0].as_dict()["schema"],
                             f"hepta.hia.program.v{version}")

    def test_v7_chain_and_byte_resources_do_not_pass_a_version_allowlist_alone(self):
        chain = transition_program()
        fn = chain["functions"][0]
        fn["effects"] = ["alloc"]
        fn["blocks"][0]["ops"][:0] = [i("chain.empty", out=[("chain", "chain")]), i("owner.drop", ["chain"])]
        byte = resource_program()
        byte["schema"] = "hepta.hia.program.v7"
        for source, function, parameter in ((chain, "transition", "delta"), (byte, "owned", "n")):
            with self.subTest(function=function):
                verify_program(source)
                with self.assertRaises(MultiversionRejected):
                    _admissible(source)
                with self.assertRaises(HIAProgramRejected):
                    propose_guarded_specializations(source, function=function, assumptions=[{"parameter": parameter, "value": 1}])

    def test_unused_resource_helper_is_not_a_total_scalar_native_module(self):
        source = transition_program()
        helper = f("release", [("owner", "chain")], [], ["alloc"],
                   [b("entry", [("owner", "chain")], [i("owner.drop", ["owner"])], ret())])
        source["functions"].append(helper)
        source["exports"] = ["transition"]
        verify_program(source)
        with self.assertRaisesRegex(MultiversionRejected, "every function"):
            _admissible(source)
        # A proposal touches only its selected scalar function. It cannot
        # convert the untouched helper into native lifecycle qualification.
        proposal = propose_guarded_specializations(source, function="transition",
            assumptions=[{"parameter": "delta", "value": 0}])[0]["program"]
        self.assertEqual(proposal["functions"][1], helper)
        with self.assertRaises(MultiversionRejected):
            _admissible(proposal)

    def test_v7_calls_and_traps_remain_outside_live_scalar_execution(self):
        helper = f("helper", [("value", "u64")], ["u64"], [],
                   [b("entry", [("value", "u64")], [], ret("value"))])
        caller = f("caller", [("value", "u64")], ["u64"], [],
                   [b("entry", [("value", "u64")], [i("call", ["value"], [("result", "u64")], function="helper")], ret("result"))])
        source = m(caller, helper)
        source["schema"] = "hepta.hia.program.v7"
        verify_program(source)
        with self.assertRaisesRegex(MultiversionRejected, "instruction"):
            _admissible(source)
        with self.assertRaises(HIAProgramRejected):
            propose_guarded_specializations(source, function="caller", assumptions=[{"parameter": "value", "value": 0}])
        trap = transition_program()
        trap["functions"][0]["effects"] = ["trap"]
        trap["functions"][0]["blocks"][0]["ops"][0]["op"] = "int.add.checked"
        verify_program(trap)
        with self.assertRaisesRegex(MultiversionRejected, "effect-free"):
            _admissible(trap)


class NativeMeasurementPolicyTests(unittest.TestCase):
    def test_strict_envelope_numbers_keys_limits_and_detached_snapshot(self):
        value = policy_input()
        frozen = _measurement_snapshot(value)
        value["samples"][0]["baseline_ns"] = 1
        self.assertEqual(frozen["samples"][0]["baseline_ns"], 1_000_000)
        changes = [lambda v: v.update(maximum_mad_ppm=1_000_000),
                   lambda v: v.update(calls_per_sample=True),
                   lambda v: v.update(horizon_calls=1.0),
                   lambda v: v.update(search_cost_ns=-1),
                   lambda v: v.update(samples=v["samples"][:14]),
                   lambda v: v.update(samples=v["samples"][:16]),
                   lambda v: v.update(after_artifact_sha256=None),
                   lambda v: v["samples"][0].update(candidate_ns=False),
                   lambda v: v["samples"][0].update(native_verified=True)]
        for mutate in changes:
            altered = policy_input()
            mutate(altered)
            with self.subTest(altered=altered), self.assertRaises(MultiversionRejected):
                _measurement_snapshot(altered)

    def test_fixed_identity_noise_and_paid_cost_refusals_preserve_all_pairs(self):
        value = policy_input()
        ordinary = _assess_measurement(_measurement_snapshot(value), prepare_ns=100)
        self.assertTrue(ordinary["eligible"])
        self.assertFalse(ordinary["claims"]["core_authority_granted"])
        self.assertFalse(ordinary["claims"]["measurements_independently_attested"])
        self.assertEqual(ordinary["samples"], 31)
        identical = copy.deepcopy(value)
        identical["after_artifact_sha256"] = identical["before_artifact_sha256"]
        self.assertIn("identical_native_artifacts", _assess_measurement(identical, prepare_ns=0)["reasons"])
        noisy = copy.deepcopy(value)
        noisy["samples"] = [{"baseline_ns": (n % 3 + 1) * 1_000_000,
                             "candidate_ns": (n % 3 + 1) * 500_000} for n in range(31)]
        result = _assess_measurement(_measurement_snapshot(noisy), prepare_ns=0)
        self.assertIn("baseline_timing_noise", result["reasons"])
        self.assertIn("candidate_timing_noise", result["reasons"])
        no_gain = copy.deepcopy(value)
        no_gain["horizon_calls"] = 1
        self.assertIn("experiment_cost_not_recovered", _assess_measurement(no_gain, prepare_ns=0)["reasons"])
        final_cost = _assess_measurement(value, prepare_ns=value["maximum_search_ns"])
        self.assertIn("search_cost_budget", final_cost["reasons"])


class NativeLifecycleConvergenceTests(unittest.TestCase):
    def setUp(self):
        self.clang = shutil.which(os.environ.get("CLANG", "clang"))
        self.rustc = shutil.which(os.environ.get("RUSTC", "rustc"))
        self.assertIsNotNone(self.clang, "actual Clang required")
        self.assertIsNotNone(self.rustc, "actual Rust reference compiler required")
        self.assertIsNotNone(importlib.util.find_spec("z3"), "actual Z3 required")
        temporary = tempfile.TemporaryDirectory(prefix="hia-native-convergence-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)

    def test_actual_c_rust_llvm_state_lifecycle_and_frozen_native_no_change(self):
        result = run(self.directory / "evidence", clang=self.clang, rustc=self.rustc)
        self.assertTrue(result["ok"])
        self.assertEqual(result["denominators"]["state_calls_per_language"], 12)
        self.assertEqual(result["denominators"]["timing_total_native_calls"], 3_100_000)
        self.assertIn("identical_native_artifacts", result["actual_measurement_policy"]["reasons"])
        self.assertEqual(result["runtime_after_close"]["generations"], [])
        self.assertFalse(result["claims"]["performance_improvement_established"])

    def test_measured_gate_still_uses_real_proof_build_and_one_publication_point(self):
        # Controlled timing numbers exercise the success branch. They are not
        # measurements and must not be reported as performance evidence.
        from tools.qualify_hia_specialization import workload, oracle
        baseline = workload()
        candidate = propose_guarded_specializations(baseline, function="calculate",
            assumptions=[{"parameter": "mask", "value": 0}])[0]["program"]
        built = build_program_native(candidate, self.directory / "measured-candidate.so", clang=self.clang)
        with ScalarMultiversionRuntime(baseline, self.directory, clang=self.clang, validation_timeout_ms=5000) as runtime:
            old = runtime.snapshot()["generations"][0]
            self.assertNotEqual(old["artifact_sha256"], built["artifact_sha256"])
            measurement = policy_input()
            measurement.update(before_sha256=verify_program(baseline).sha256,
                               after_sha256=verify_program(candidate).sha256,
                               before_artifact_sha256=old["artifact_sha256"],
                               after_artifact_sha256=built["artifact_sha256"], function="calculate")
            token = PublicationCancellation()
            result = runtime.publish_if_current(candidate, 0, expected_epoch=0,
                max_prepare_ns=10_000_000_000, cancellation=token, measurement=measurement)
            self.assertTrue(token.committed())
            self.assertTrue(result["measurement_admission"]["eligible"])
            self.assertEqual(result["generation"]["translation_proofs"], 1)
            self.assertGreater(result["generation"]["native_probe_calls"], 0)
            self.assertFalse(result["measurement_admission"]["claims"]["general_performance_improvement_proved"])
            for args in ((0, 0), (0xFFFFFFFF, 0), (17, 29)):
                self.assertEqual(runtime.call("calculate", list(args)), oracle(*args))


if __name__ == "__main__":
    unittest.main()
