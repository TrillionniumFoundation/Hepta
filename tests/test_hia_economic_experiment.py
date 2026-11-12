"""Independent recurrence oracle and exact native driver ABI, without a campaign."""
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from hepta.hia_multiversion import PublicationCancellation, ScalarMultiversionRuntime
from hepta.hia_specialization import propose_guarded_specializations
from tools.qualify_hia_economic_search import DRIVER, cases, oracle, prepare, sample, summarize, workload


class EconomicExperimentArithmeticTests(unittest.TestCase):
    def test_cycle_acceleration_agrees_with_independent_naive_integer_execution(self):
        for profile in ("hot_three", "hot_sixteen", "mixed"):
            rows = cases(profile, 17)
            checkpoints = {1, 63, 64, 65, 1024, 20003}
            total, state = 0, 91
            for index in range(max(checkpoints)):
                x, divisor = rows[index % 64]
                numerator = x ^ state
                if divisor:
                    quotient, remainder = divmod(numerator, divisor)
                    state = (quotient+remainder) & 255
                else:
                    state = numerator
                total += state
                if index+1 in checkpoints:
                    self.assertEqual(oracle(rows, index+1), {"checksum": total, "final_state": state})
        # A fixed point exercises a very long skipped continuation exactly.
        self.assertEqual(oracle([[0,0]]*64, 64_000_000),
                         {"checksum": 91*64_000_000, "final_state": 91})

    def test_empirical_envelope_does_not_round_per_call_uncertainty_to_one_ns(self):
        rows = [dict(status="observed", iterations=250000, elapsed_ns=value, outer_wall_ns=value+1000)
                for value in (700000, 710001)]
        observed = summarize(rows)
        self.assertEqual(observed["lower_ps"], 2800)
        self.assertEqual(observed["upper_ps"], 2841)
        self.assertEqual(observed["median_ps"], 2821)
        self.assertEqual(observed["samples"], 2)
        rows[1]["status"] = "failed"
        with self.assertRaises(RuntimeError):
            summarize(rows)


CLANG = os.environ.get("CLANG") or shutil.which("clang")


@unittest.skipUnless(CLANG and importlib.util.find_spec("z3"), "actual Clang and Z3 required")
class EconomicExperimentNativeTests(unittest.TestCase):
    def test_actual_byte_abi_driver_matches_cycle_oracle_and_published_generation(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            source, driver = folder/"driver.c", folder/"driver"
            source.write_text(DRIVER)
            subprocess.run([CLANG, "-O2", "-std=c11", str(source), "-ldl", "-o", str(driver)],
                           check=True, capture_output=True)
            baseline = workload()
            candidate = propose_guarded_specializations(baseline, function="calculate",
                assumptions=[{"parameter": "denominator", "value": 16}])[0]["program"]
            rows = cases("hot_sixteen", 19)
            inputs = folder/"inputs.txt"
            inputs.write_text("".join(f"{x} {d}\n" for x,d in rows))
            with ScalarMultiversionRuntime(baseline, folder, clang=CLANG, prove_total=True) as runtime:
                runtime.publish_if_current(candidate, 0, expected_epoch=0,
                    max_prepare_ns=5_000_000_000, cancellation=PublicationCancellation())
                current = runtime.snapshot()["current_generation"]
                info = next(row for row in runtime.snapshot()["generations"] if row["generation"] == current)
                artifact = runtime._directory/f"generation-{current}.so"
                result = sample(driver, artifact, inputs, rows, 4096, expected_artifact=info["artifact_sha256"])
                self.assertEqual(result["status"], "observed", result)
                self.assertEqual(result["oracle_pair_checks"], 65536)
                self.assertEqual((result["checksum"], result["final_state"]),
                                 (result["expected"]["checksum"], result["expected"]["final_state"]))
                refused = sample(driver, artifact, inputs, rows, 4096, expected_artifact="0"*64)
                self.assertEqual(refused["status"], "failed")
                self.assertNotIn("argv", refused)
            rejected = propose_guarded_specializations(baseline, function="calculate",
                assumptions=[{"parameter": "denominator", "value": 16}])[0]["program"]
            rejected["functions"][0]["blocks"][0]["ops"][-1]["op"] = "compare.ne"
            output = folder/"wrong.so"
            with self.assertRaises(RuntimeError):
                prepare(baseline, rejected, output, CLANG)
            self.assertFalse(output.exists())
            self.assertTrue(output.with_suffix(".prepare.json").exists())


if __name__ == "__main__":
    unittest.main()
