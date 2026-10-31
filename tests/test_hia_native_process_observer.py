"""Real ELF subprocess and adversarial controls for the P5/P6 observation bridge."""
from __future__ import annotations

import base64
from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest

from hepta.hia_full_cost_gate import assess_full_cost
from tools.hia_native_process_observer import (
    ARMS, COST_KEYS, NativeObservationRejected, SCHEMA, observe,
)


def digest(value):
    return sha256(value).hexdigest()


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


ECHO_SOURCE = r"""
#include <stdio.h>
int main(int argc, char **argv) {
    unsigned char buffer[4096];
    size_t n;
    if (argc != 1) return 12;
    while ((n = fread(buffer, 1, sizeof buffer, stdin)) != 0) {
        if (fwrite(buffer, 1, n, stdout) != n) return 13;
    }
    return (ferror(stdin) || ferror(stdout)) ? 14 : 0;
}
"""
LOOP_SOURCE = "int main(void) { for (;;) {} }\n"


@unittest.skipUnless(sys.platform == "linux" and hasattr(os, "wait4"),
                     "Linux wait4 native process observations required")
class HIANNativeProcessObservationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cc = shutil.which("gcc") or shutil.which("clang")
        if cls.cc is None:
            raise RuntimeError("a real C compiler is mandatory for this qualification")
        cls.directory = tempfile.TemporaryDirectory(prefix="hia-observer-corpus-")
        cls.path = Path(cls.directory.name)
        cls.binaries = []
        for index in range(4):
            source = cls.path / ("echo" + str(index) + ".c")
            source.write_text(ECHO_SOURCE, encoding="utf-8")
            binary = cls.path / ("echo" + str(index))
            subprocess.run([cls.cc, "-std=c11", "-O2" if index % 2 else "-O0",
                            str(source), "-o", str(binary)], check=True,
                           capture_output=True, timeout=30)
            cls.binaries.append(binary)
        cls.loop = cls.path / "loop"
        loop_src = cls.path / "loop.c"
        loop_src.write_text(LOOP_SOURCE, encoding="utf-8")
        subprocess.run([cls.cc, "-std=c11", "-O0", str(loop_src), "-o", str(cls.loop)],
                       check=True, capture_output=True, timeout=30)

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def registration(self):
        trials = []
        for n in range(8):
            payload = ("trial-%02d\n" % n).encode()
            trials.append({"id": "task%02d" % n,
                           "stdin_base64": base64.b64encode(payload).decode(),
                           "input_digest": digest(payload),
                           "expected_result_digest": digest(payload)})
        arms = []
        for strategy, binary in zip(ARMS, self.binaries):
            arms.append({
                "strategy": strategy, "binary_path": str(binary),
                "binary_digest": digest(binary.read_bytes()),
                "core_digest": "1" * 64, "toolchain_digest": "2" * 64,
                "argv": [], "one_time_ns": {key: 0 for key in COST_KEYS},
                "unknown_costs": ["external_planning_unmeasured"],
            })
        return {"schema": SCHEMA, "source_digest": "3" * 64,
                "objective_digest": "4" * 64, "hardware_digest": "5" * 64,
                "workload_digest": "6" * 64, "candidate_bank_digest": "7" * 64,
                "generation": 1, "trials": trials, "arms": arms,
                "repetitions": 2, "timeout_ms": 1000, "max_output_bytes": 2048,
                "minimum_gain_ppm": 10000, "minimum_gain_ns": 100,
                "maximum_peak_rss_bytes": 1 << 39,
                "maximum_p99_ns": 10**12}

    def test_real_four_arm_elf_receipts_bind_every_sample_and_keep_deny_all(self):
        report = observe(wire(self.registration()))
        self.assertTrue(report["complete"])
        self.assertEqual(report["failures"], [])
        self.assertEqual(report["authority"], "DENY_ALL")
        self.assertFalse(report["claims"]["process_tree_resource_accounting"])
        self.assertFalse(report["claims"]["one_time_costs_independently_attested"])
        self.assertEqual(len(report["frozen_binaries"]), 4)
        self.assertEqual(
            sum(len(rows) for arm in report["raw_samples"].values() for rows in arm.values()), 64)
        for arm in report["full_cost_input"]["arms"]:
            self.assertEqual(len(arm["observations"]), 8)
            self.assertGreater(arm["observations"][0]["peak_rss_bytes"], 0)
            self.assertGreater(arm["observations"][0]["p99_ns"], 0)
            self.assertGreater(arm["one_time_ns"]["measurement"], 0)
        verdict = report["full_cost_verdict"]
        self.assertFalse(verdict["economic_scope_positive"])
        self.assertIn("unaccounted_costs", verdict["reasons"])
        self.assertEqual(verdict["authority"], "DENY_ALL")
        self.assertFalse(verdict["production_activation_allowed"])
        self.assertEqual(
            assess_full_cost(wire(report["full_cost_input"]))["arm_total_ns"],
            verdict["arm_total_ns"])

    def test_mismatched_output_is_retained_as_failure_and_not_trimmed(self):
        data = self.registration()
        data["trials"][0]["expected_result_digest"] = "9" * 64
        report = observe(wire(data))
        self.assertFalse(report["complete"])
        self.assertEqual(len(report["failures"]), 1)
        self.assertEqual(report["failures"][0]["trial_id"], "task00")
        self.assertNotIn("full_cost_input", report)
        self.assertNotIn("full_cost_verdict", report)
        self.assertEqual(len(report["raw_samples"]["baseline"]["task00"]), 1)

    def test_timeout_is_failed_trial_not_fast_candidate(self):
        data = self.registration()
        data["arms"][0]["binary_path"] = str(self.loop)
        data["arms"][0]["binary_digest"] = digest(self.loop.read_bytes())
        data["timeout_ms"] = 50
        report = observe(wire(data))
        self.assertFalse(report["complete"])
        self.assertTrue(report["failures"][0]["timed_out"])
        self.assertNotIn("full_cost_verdict", report)

    def test_symlink_digest_drift_and_non_elf_refuse_before_execution(self):
        data = self.registration()
        alias = self.path / "linked"
        alias.symlink_to(self.binaries[0])
        data["arms"][0]["binary_path"] = str(alias)
        with self.assertRaises(NativeObservationRejected):
            observe(wire(data))
        alias.unlink()
        data = self.registration()
        data["arms"][0]["binary_digest"] = "a" * 64
        with self.assertRaises(NativeObservationRejected):
            observe(wire(data))
        data = self.registration()
        source = self.path / "not-an-elf.txt"
        source.write_text("this is not ELF" * 5)
        data["arms"][0]["binary_path"] = str(source)
        data["arms"][0]["binary_digest"] = digest(source.read_bytes())
        with self.assertRaises(NativeObservationRejected):
            observe(wire(data))

    def test_registration_is_strict_and_immutable(self):
        original = self.registration()
        bad_cases = [
            original, b'{"schema":"x","schema":"x"}', b'{"schema":NaN}',
            b"\xff", b" " * 262145,
        ]
        for bad in bad_cases:
            with self.subTest(kind=type(bad).__name__):
                with self.assertRaises(NativeObservationRejected):
                    observe(bad)
        mutations = [
            lambda x: x["arms"][1].update(strategy="ndu"),
            lambda x: x["arms"][2]["one_time_ns"].pop("verification"),
            lambda x: x["arms"][0].update(binary_path="relative.elf"),
            lambda x: x["arms"][0].update(argv=["bad\x00argument"]),
            lambda x: x["trials"][0].update(input_digest="f" * 64),
            lambda x: x["trials"][0].update(stdin_base64="!?"),
            lambda x: x.update(repetitions=True),
            lambda x: x["arms"][3].update(unknown_costs=["dup", "dup"]),
            lambda x: x["trials"][1].update(id="task00"),
        ]
        for change in mutations:
            state = deepcopy(original)
            change(state)
            with self.subTest(mutation=str(change)):
                with self.assertRaises(NativeObservationRejected):
                    observe(wire(state))


if __name__ == "__main__":
    unittest.main()
