"""Separate timed xor-fold admission, legacy compatibility and actual events."""
from __future__ import annotations

import base64
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from hepta import hia_finite_context as fc
from hepta.hia_crc_kernel import POLYNOMIALS, kernel, step
from tests.test_hia_finite_context import request, result, shift_oracle, shift_program
from tests.test_hia_finite_context_map_repeat import events as legacy_events


def timed(**extra):
    values = {"mode": "timed_xor_fold", "parameter": 4}
    values.update(extra)
    return request(**values)


def owner(*, enabled=True, map_repeat=False):
    bank = fc.FiniteU32Bank(fc._CONSTRUCTION, fc.checked_profile(shift_program()),
        ("baseline",), shift_oracle, {}, reuse_oracle=True,
        allow_map_repeat=map_repeat, allow_timed_xor_fold=enabled)
    bank._bank_sha256 = "b" * 64
    bank._driver = {"path": "unit-test-driver"}
    bank._images = ({"path": "unit-test-image", "sha256": "0" * 64},)
    return bank


def events(trace):
    rows = legacy_events(trace)
    for row in rows:
        if row["kind"] == "result" and row["mode"] == 3:
            row["kernel_ns"] = 11
    return rows


class TimedXorFoldTests(unittest.TestCase):
    def test_exact_opt_in_is_required_and_extended_profiles_are_mutually_exclusive(self):
        with self.assertRaises(fc.FiniteContextRejected):
            fc._requests([timed()], ("baseline",))
        with self.assertRaises(fc.FiniteContextRejected):
            fc._requests([timed()], ("baseline",), allow_map_repeat=True)
        for bad in (1, None, "true"):
            with self.assertRaises(fc.FiniteContextRejected):
                owner(enabled=bad)
        with self.assertRaises(fc.FiniteContextRejected):
            owner(enabled=True, map_repeat=True)
        with self.assertRaises(fc.FiniteContextRejected):
            fc._requests([timed()], ("baseline",), allow_map_repeat=True, allow_timed_xor_fold=True)

    def test_legacy_wire_and_map_wire_are_unchanged(self):
        for row in (request(), request(mode="xor_fold", parameter=4)):
            original = fc._requests([row], ("baseline",))
            self.assertEqual(original, fc._requests([row], ("baseline",), allow_timed_xor_fold=True))
            self.assertEqual(len(original[0][0]), 6)
        mapped = request(mode="map_repeat", parameter=4, repetitions=3, seed=0)
        normalized, payload = fc._requests([mapped], ("baseline",), allow_map_repeat=True)
        self.assertEqual(payload, "1\n3 0 2 0 4 3 3 1 2 0\n")
        self.assertEqual(len(normalized[0]), 7)

    def test_same_xor_recurrence_without_repetition_or_byte_budget_extension(self):
        before, _ = fc._requests([request(mode="xor_fold", parameter=4)], ("baseline",))
        after, payload = fc._requests([timed()], ("baseline",), allow_timed_xor_fold=True)
        self.assertEqual(payload, "1\n3 0 3 7 4 3 1 2 0\n")
        self.assertEqual(len(after[0]), 6)
        self.assertEqual(fc._expected(before, shift_oracle), fc._expected(after, shift_oracle))
        for changed in (timed(values=[256]), timed(values=[True]), timed(repetitions=1),
                        timed(values=[0] * (fc.MAX_CALLS + 1)), timed(parameter=True)):
            with self.assertRaises(fc.FiniteContextRejected):
                fc._requests([changed], ("baseline",), allow_timed_xor_fold=True)
        self.assertEqual((fc.MAX_CALLS, fc.MAX_REQUESTS, fc.WALL_SECONDS, fc.CPU_SECONDS), (65536, 256, 5, 3))

    def test_reference_cache_separates_timed_mode_and_never_reuses_execution(self):
        bank = owner()
        ordinary = bank.prepare_trace([request(mode="xor_fold", parameter=4)])
        first = bank.prepare_trace([timed()])
        second = bank.prepare_trace([timed(ident=4)])
        self.assertEqual(ordinary.expected, first.expected)
        self.assertEqual(first.expected, second.expected)
        self.assertIsNot(first.token, second.token)
        self.assertEqual((bank.oracle_reference_statistics()["misses"], bank.oracle_reference_statistics()["hits"]), (2, 1))
        with patch.object(fc, "run_bounded", side_effect=[result(events(first)), result(events(second))]) as run:
            self.assertEqual(bank.run(first)["status"], "completed")
            self.assertEqual(bank.run(second)["status"], "completed")
            self.assertEqual(run.call_count, 2)
            with self.assertRaises(fc.FiniteContextRejected):
                bank.run(first)
        bank.cancel(ordinary)
        self.assertTrue(bank.close()["complete"])

    def test_actual_retained_legacy_event_has_no_kernel_timer(self):
        fixture = Path(__file__).parent / "fixtures/hia_crc_linear"
        raw = (fixture / "legacy_xor_fold_7e69323.json").read_bytes()
        provenance = json.loads((fixture / "LEGACY_NATIVE_PROVENANCE.json").read_bytes())
        self.assertEqual(sha256(raw).hexdigest(), provenance["native_sha256"])
        native = json.loads(raw)
        events_raw = base64.b64decode(native["raw_stdout_base64"], validate=True)
        rows = [json.loads(line) for line in events_raw.splitlines()]
        completed = [row for row in rows if row["kind"] == "result"]
        self.assertEqual(len(completed), 18)
        self.assertEqual(completed, native["prefix"]["completed_requests"])
        for row in completed:
            self.assertEqual(row["mode"], 1)
            self.assertNotIn("kernel_ns", row)
            state, checksum = row["seed"], 0
            for byte in b"123456789":
                state = step(state ^ byte, row["parameter"])
                checksum = (checksum * 1099511628211 + state) & fc.MASK64
            self.assertEqual((row["state"], row["checksum"], row["calls"]), (state, checksum, 9))

    def test_missing_unknown_zero_negative_and_extra_timing_fields_poison_without_replay(self):
        mutations = [None, 0, -1, True, "11", "missing", "extra_repetitions"]
        for mutation in mutations:
            bank = owner()
            trace = bank.prepare_trace([timed()])
            rows = events(trace)
            observed = next(row for row in rows if row["kind"] == "result")
            if mutation == "missing":
                del observed["kernel_ns"]
            elif mutation == "extra_repetitions":
                observed["repetitions"] = 1
            else:
                observed["kernel_ns"] = mutation
            report = {}
            with self.subTest(mutation=mutation), patch.object(fc, "run_bounded", return_value=result(rows)):
                with self.assertRaises(fc.FiniteContextRejected):
                    bank.run(trace, report=report)
                with self.assertRaises(fc.FiniteContextRejected):
                    bank.run(trace)
            self.assertTrue(bank.state()["poisoned"])
            self.assertEqual(report["prefix"]["completed_requests"], [])
            self.assertIsNotNone(report["prefix"]["pending_request_seq"])
            self.assertTrue(bank.close()["complete"])

    def test_legacy_result_does_not_silently_accept_a_timer_field(self):
        bank = owner()
        trace = bank.prepare_trace([request(mode="xor_fold", parameter=4)])
        rows = events(trace)
        next(row for row in rows if row["kind"] == "result")["kernel_ns"] = 11
        with patch.object(fc, "run_bounded", return_value=result(rows)):
            with self.assertRaises(fc.FiniteContextRejected):
                bank.run(trace)
        self.assertTrue(bank.close()["complete"])

    def test_post_preparation_mode_mutation_is_not_execution_authority(self):
        bank = owner()
        trace = bank.prepare_trace([timed()])
        value = list(trace.requests[0])
        value[2] = 1
        object.__setattr__(trace, "requests", (tuple(value),))
        with patch.object(fc, "run_bounded") as run:
            with self.assertRaises(fc.FiniteContextRejected):
                bank.run(trace)
            run.assert_not_called()
        self.assertTrue(bank.close()["complete"])


@unittest.skipUnless(os.environ.get("CLANG") or shutil.which("clang"), "actual Clang required")
class TimedXorFoldNativeTests(unittest.TestCase):
    def test_actual_crc_legacy_and_timed_events_agree_and_invalid_byte_rejects_before_load(self):
        with tempfile.TemporaryDirectory(prefix="hia-timed-crc-") as temporary:
            report = {}
            bank = fc.build_bank(kernel(), {"baseline": kernel()}, Path(temporary),
                clang=os.environ.get("CLANG", "clang"), cases=[[0, POLYNOMIALS[0]], [0xFFFFFFFF, POLYNOMIALS[1]], [7, 0]],
                oracle=step, report=report, allow_timed_xor_fold=True)
            try:
                self.assertEqual(report["profile"], fc.TIMED_XOR_FOLD_PROFILE)
                rows = [request(ident=index * 2 + timed_flag, mode="timed_xor_fold" if timed_flag else "xor_fold",
                    seed=0xFFFFFFFF, parameter=polynomial, values=list(range(256)))
                    for index, polynomial in enumerate(POLYNOMIALS) for timed_flag in (0, 1)]
                trace = bank.prepare_trace(rows)
                observed = bank.run(trace)
                results = observed["prefix"]["completed_requests"]
                self.assertEqual(sum(row["calls"] for row in results), 1024)
                for old, new in zip(results[::2], results[1::2]):
                    self.assertNotIn("kernel_ns", old)
                    self.assertEqual((old["mode"], new["mode"]), (1, 3))
                    self.assertEqual(type(new["kernel_ns"]), int)
                    self.assertGreater(new["kernel_ns"], 0)
                    for key in ("calls", "seed", "parameter", "state", "checksum"):
                        self.assertEqual(old[key], new[key], key)
                invalid = fc.run_bounded([bank._driver["path"], "a" * 64, bank._images[0]["path"]],
                    input_text="1\n0 0 3 0 0 1 256\n", timeout=5, stdout_limit=4096, stderr_limit=4096)
                self.assertEqual((invalid.returncode, invalid.stdout, invalid.stderr), (84, "", ""))
            finally:
                self.assertTrue(bank.close()["complete"])

    def test_actual_timed_trap_prefix_does_not_invent_a_completed_timer(self):
        with tempfile.TemporaryDirectory(prefix="hia-timed-trap-") as temporary:
            bank = fc.build_bank(shift_program(), {"baseline": shift_program()}, Path(temporary),
                clang=os.environ.get("CLANG", "clang"), cases=[[1, 4], [1, 32]],
                oracle=shift_oracle, allow_timed_xor_fold=True)
            try:
                trace = bank.prepare_trace([timed(ident=1), timed(ident=2, parameter=32), timed(ident=3)])
                report = {}
                with self.assertRaises(fc.FiniteContextRejected):
                    bank.run(trace, report=report)
                self.assertEqual(trace.expected[1], ("trapped", "overflow", 0))
                completed = report["prefix"]["completed_requests"]
                self.assertEqual([row["id"] for row in completed], [1])
                self.assertGreater(completed[0]["kernel_ns"], 0)
                self.assertEqual(report["prefix"]["pending_request_seq"], 1)
                self.assertFalse(report["prefix"]["complete"])
                self.assertEqual([row["id"] for row in report["prefix"]["events"] if row["kind"] == "result"], [1])
                self.assertTrue(bank.state()["poisoned"])
                with self.assertRaises(fc.FiniteContextRejected):
                    bank.run(trace)
            finally:
                self.assertTrue(bank.close()["complete"])


if __name__ == "__main__":
    unittest.main()
