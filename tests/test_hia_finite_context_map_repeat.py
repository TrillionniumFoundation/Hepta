"""Map repetition preserves finite ownership, exact work counts and old folds."""
from __future__ import annotations

import copy
import unittest
from unittest.mock import patch

from hepta import hia_finite_context as fc
from tests.test_hia_finite_context import request, result, shift_oracle, shift_program


def mapped(*, repetitions=3, parameter=4, values=(1, 2, 3), candidate="baseline", ident=7):
    return request(ident=ident, candidate=candidate, seed=0, values=values,
                   mode="map_repeat", parameter=parameter, repetitions=repetitions)


def owner(*, enabled=True):
    bank = fc.FiniteU32Bank(fc._CONSTRUCTION, fc.checked_profile(shift_program()),
        ("baseline", "shift_4"), shift_oracle, {}, reuse_oracle=True, allow_map_repeat=enabled)
    bank._bank_sha256 = "b" * 64
    bank._driver = {"path": "unit-test-driver"}
    bank._images = tuple({"path": f"unit-test-image-{i}", "sha256": str(i) * 64} for i in range(2))
    return bank


def events(trace):
    rows = [{"as_bytes": fc.ADDRESS_SPACE_BYTES, "core_bytes": 0, "cpu_seconds": fc.CPU_SECONDS,
             "fsize_bytes": fc.MAX_OUTPUT_BYTES, "kind": "limits", "trace": trace.sha256}]
    for image in range(len(trace.images)):
        rows.extend({"image": image, "kind": kind, "trace": trace.sha256} for kind in ("opened", "ready"))
    for seq, raw in enumerate(trace.requests):
        ident, image, mode, seed, parameter, values, repetitions = fc._parts(raw)
        rows.append({"candidate": image, "id": ident, "kind": "start", "seq": seq, "trace": trace.sha256})
        row = {"calls": len(values) * repetitions, "candidate": image, "checksum": trace.expected[seq][2],
               "id": ident, "kind": "result", "mode": mode, "parameter": parameter,
               "seed": seed, "seq": seq, "state": trace.expected[seq][1], "trace": trace.sha256}
        if mode == 2:
            row.update(repetitions=repetitions, kernel_ns=11)
        rows.append(row)
    for image in reversed(range(len(trace.images))):
        rows.append({"image": image, "kind": "closed", "ok": True, "trace": trace.sha256})
    rows.append({"acquired": len(trace.images), "closed": len(trace.images), "kind": "finish", "ok": True, "trace": trace.sha256})
    return rows


class MapRepeatTests(unittest.TestCase):
    def test_legacy_modes_keep_six_fields_and_wire_bytes(self):
        normalized, payload = fc._requests([request()], ("baseline",))
        self.assertEqual(len(normalized[0]), 6)
        self.assertEqual(payload, "1\n3 0 0 7 0 3 1 2 0\n")
        self.assertEqual(fc._requests([request()], ("baseline",), allow_map_repeat=True), (normalized, payload))

    def test_new_profile_requires_exact_explicit_opt_in(self):
        bank = owner(enabled=False)
        with self.assertRaises(fc.FiniteContextRejected):
            bank.prepare_trace([mapped()])
        bank.close()
        for value in (1, None, "true"):
            with self.assertRaises(fc.FiniteContextRejected): owner(enabled=value)

    def test_reference_composition_matches_literal_independent_map(self):
        for repetitions in (1, 2, 3, 17, 4096):
            with self.subTest(repetitions=repetitions):
                normalized, _ = fc._requests([mapped(repetitions=repetitions)], ("baseline",), allow_map_repeat=True)
                checksum = 0
                for _ in range(repetitions):
                    for value in (1, 2, 3):
                        checksum = (checksum * 1099511628211 + shift_oracle(value, 4)) & fc.MASK64
                self.assertEqual(fc._expected(normalized, shift_oracle), (("returned", 48, checksum),))

    def test_first_pass_trap_does_not_become_completed_repetitions(self):
        normalized, _ = fc._requests([mapped(parameter=32)], ("baseline",), allow_map_repeat=True)
        self.assertEqual(fc._expected(normalized, shift_oracle), (("trapped", "overflow", 0),))

    def test_repetition_and_total_actual_work_caps_are_independent_of_input_storage(self):
        for repeats in (0, -1, True, 4097):
            with self.subTest(repeats=repeats), self.assertRaises(fc.FiniteContextRejected):
                fc._requests([mapped(repetitions=repeats)], ("baseline",), allow_map_repeat=True)
        rows = [mapped(values=[1] * 4096, repetitions=4096)]
        fc._requests(rows, ("baseline",), allow_map_repeat=True)
        with self.assertRaisesRegex(fc.FiniteContextRejected, "executed-call"):
            fc._requests([*rows, mapped(ident=8, values=[1], repetitions=1)], ("baseline",), allow_map_repeat=True)
        with self.assertRaises(fc.FiniteContextRejected):
            fc._requests([mapped(values=[1] * (fc.MAX_CALLS + 1), repetitions=1)], ("baseline",), allow_map_repeat=True)

    def test_seed_fields_and_exact_input_types_remain_closed(self):
        row = mapped()
        mutations = [dict(row, seed=1), dict(row, seed=False), dict(row, parameter=True),
                     dict(row, repetitions=1.0), dict(row, values=[True]), dict(row, unknown=0)]
        for mutation in mutations:
            with self.subTest(mutation=mutation), self.assertRaises(fc.FiniteContextRejected):
                fc._requests([mutation], ("baseline",), allow_map_repeat=True)

    def test_cache_binds_repetitions_and_does_not_cache_native_calls_or_nonces(self):
        bank = owner()
        first = bank.prepare_trace([mapped(repetitions=3)])
        second = bank.prepare_trace([mapped(repetitions=4)])
        third = bank.prepare_trace([mapped(repetitions=3, ident=9, candidate="shift_4")])
        self.assertNotEqual(first.expected, second.expected)
        self.assertEqual(first.expected, third.expected)
        self.assertIsNot(first.token, third.token)
        with patch.object(fc, "run_bounded", side_effect=[result(events(first)), result(events(third))]) as launch:
            self.assertEqual(bank.run(first)["status"], "completed")
            self.assertEqual(bank.run(third)["status"], "completed")
            self.assertEqual(launch.call_count, 2)
            with self.assertRaises(fc.FiniteContextRejected): bank.run(first)
        stats = bank.oracle_reference_statistics()
        self.assertEqual((stats["misses"], stats["hits"]), (2, 1))
        bank.cancel(second)
        self.assertTrue(bank.close()["complete"])

    def test_actual_call_count_repeat_and_timing_receipt_mutations_reject(self):
        for key, value in (("calls", 3), ("repetitions", 1), ("kernel_ns", 0), ("checksum", 0)):
            bank = owner()
            trace = bank.prepare_trace([mapped()])
            rows = events(trace)
            next(r for r in rows if r["kind"] == "result")[key] = value
            with self.subTest(key=key), patch.object(fc, "run_bounded", return_value=result(rows)):
                with self.assertRaises(fc.FiniteContextRejected): bank.run(trace)
            self.assertTrue(bank.state()["poisoned"])
            self.assertTrue(bank.close()["complete"])

    def test_post_preparation_repeat_mutation_is_not_replay_authority(self):
        bank = owner()
        trace = bank.prepare_trace([mapped()])
        object.__setattr__(trace, "requests", ((*trace.requests[0][:-1], 4),))
        with patch.object(fc, "run_bounded") as launch:
            with self.assertRaises(fc.FiniteContextRejected): bank.run(trace)
            launch.assert_not_called()
        bank.close()


if __name__ == "__main__":
    unittest.main()
