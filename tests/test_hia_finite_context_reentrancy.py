"""Reference callbacks cannot change the owner whose trace they are preparing."""
from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from hepta import hia_finite_context as fc
from tests.test_hia_finite_context import CLANG, NATIVE, events, request, result, shift_oracle, shift_program
from tests.test_hia_finite_context_oracle_reuse import bank as unit_bank


class OracleReentrancyTests(unittest.TestCase):
    def test_nested_preparation_cannot_overbook_trace_cap_or_replenish_consumed_nonce(self):
        for reuse in (False, True):
            with self.subTest(reuse=reuse), patch.object(fc, "MAX_TRACES", 1):
                owner = unit_bank(reuse=reuse)
                attempted = []
                def oracle(x, y):
                    with self.assertRaisesRegex(fc.FiniteContextRejected, "reentrant mutation"):
                        owner.prepare_trace([request(values=[0])])
                    attempted.append(True)
                    return shift_oracle(x, y)
                owner._oracle = oracle
                trace = owner.prepare_trace([request(values=[0])])
                self.assertEqual(attempted, [True])
                self.assertEqual(owner.state()["registered_traces"], 1)
                owner.cancel(trace)
                with self.assertRaisesRegex(fc.FiniteContextRejected, "trace budget"):
                    owner.prepare_trace([request(values=[0])])
                self.assertEqual(owner.state()["pending_input_bytes"], 0)
                self.assertTrue(owner.close()["complete"])

    def test_baseexception_does_not_leave_preparation_active_or_register_a_trace(self):
        for reuse in (False, True):
            for exception in (RuntimeError, KeyboardInterrupt, MemoryError):
                with self.subTest(reuse=reuse, exception=exception):
                    owner = unit_bank(reuse=reuse)
                    def oracle(_x, _y):
                        raise exception("reference computation failed")
                    owner._oracle = oracle
                    with self.assertRaises(exception):
                        owner.prepare_trace([request(values=[0])])
                    self.assertEqual(owner.state()["registered_traces"], 0)
                    self.assertEqual(owner.state()["pending_input_bytes"], 0)
                    self.assertFalse(owner.state()["poisoned"])
                    if reuse:
                        self.assertEqual(owner.oracle_reference_statistics()["failed_computations"], 1)
                        self.assertEqual(owner.oracle_reference_statistics()["entries"], 0)
                    owner._oracle = shift_oracle
                    trace = owner.prepare_trace([request(values=[0])])
                    with patch.object(fc, "run_bounded", return_value=result(events(trace))):
                        self.assertEqual(owner.run(trace)["status"], "completed")
                    self.assertTrue(owner.close()["complete"])

    def test_diagnostics_and_caught_reentry_do_not_turn_reference_hits_into_execution(self):
        owner = unit_bank(reuse=True)
        calls = []
        def oracle(x, y):
            calls.append((owner.state(), owner.oracle_reference_statistics()))
            with self.assertRaisesRegex(fc.FiniteContextRejected, "reentrant mutation"):
                owner.close()
            return shift_oracle(x, y)
        owner._oracle = oracle
        first = owner.prepare_trace([request(values=[0])])
        second = owner.prepare_trace([request(ident=19, values=[0])])
        self.assertEqual(len(calls), 1)
        self.assertFalse(calls[0][0]["closed"])
        self.assertFalse(owner.oracle_reference_statistics()["closed"])
        self.assertEqual(owner.oracle_reference_statistics()["hits"], 1)
        self.assertIsNot(first.token, second.token)
        with patch.object(fc, "run_bounded", side_effect=[result(events(first)), result(events(second))]) as launch:
            self.assertEqual(owner.run(first)["status"], "completed")
            self.assertEqual(owner.run(second)["status"], "completed")
            self.assertEqual(launch.call_count, 2)
        release = owner.close()
        self.assertTrue(release["complete"])
        self.assertEqual(release["oracle_references"]["entries"], 0)
        self.assertEqual(release["oracle_references"]["retained_canonical_bytes"], 0)


@unittest.skipUnless(NATIVE, "actual Linux x86-64 Clang20+, Z3 and memfd seals required")
class OracleReentrancyNativeTests(unittest.TestCase):
    def test_real_bank_rejects_callback_mutation_before_tokens_pins_or_child_are_consumed(self):
        for reuse in (False, True):
            with self.subTest(reuse=reuse), tempfile.TemporaryDirectory(prefix="hia-oracle-reentry-") as directory:
                callback = {"operation": None, "swallow": False, "rejections": 0}
                def oracle(x, y):
                    operation = callback["operation"]
                    if operation is not None:
                        try:
                            operation()
                        except fc.FiniteContextRejected as error:
                            self.assertIn("reentrant mutation", str(error))
                            callback["rejections"] += 1
                            if not callback["swallow"]:
                                raise
                        else:
                            self.fail("oracle performed a nested owner mutation")
                    return shift_oracle(x, y)
                preparation = {}
                owner = fc.build_bank(shift_program(), {"baseline": shift_program()}, Path(directory),
                    clang=CLANG, cases=[[1, 0], [1, 4], [2, 1]], oracle=oracle,
                    report=preparation, reuse_oracle=reuse)
                try:
                    reserved = owner.prepare_trace([request(seed=1, values=[0])])
                    operations = (lambda: owner.prepare_trace([request(seed=2, values=[0])]),
                                  lambda: owner.run(reserved), lambda: owner.cancel(reserved), owner.close)
                    for index, operation in enumerate(operations):
                        callback.update(operation=operation, swallow=False)
                        before = owner.state()
                        with self.assertRaisesRegex(fc.FiniteContextRejected, "reentrant mutation"):
                            owner.prepare_trace([request(seed=20 + index, values=[0])])
                        self.assertEqual(owner.state(), before)
                        self.assertTrue(all(not pin["release"].attempted for pin in owner._pins))
                        callback["swallow"] = True
                        trace = owner.prepare_trace([request(seed=40 + index, values=[0])])
                        self.assertEqual(owner.state()["pending_traces"], 2)
                        callback["operation"] = None
                        observation = owner.run(trace)
                        self.assertEqual(observation["status"], "completed")
                        self.assertEqual(observation["prefix"]["completed_requests"][0]["state"], 40 + index)
                    self.assertEqual(callback["rejections"], 8)
                    self.assertEqual(owner.run(reserved)["status"], "completed")
                    self.assertFalse(owner.state()["poisoned"])
                    self.assertEqual(owner.state()["pending_input_bytes"], 0)
                    with self.assertRaisesRegex(fc.FiniteContextRejected, "consumed"):
                        owner.run(reserved)
                finally:
                    callback["operation"] = None
                    release = owner.close()
                    self.assertTrue(release["complete"])
                    self.assertEqual(release["pending_input_bytes"], 0)
                    self.assertEqual(len(release["descriptors"]), 2)
                    if reuse:
                        self.assertEqual(release["oracle_references"]["entries"], 0)

    def test_real_production_byte_quota_cannot_be_overbooked_during_reference_computation(self):
        huge = [fc.MASK32] * fc.MAX_CALLS
        for reuse in (False, True):
            with self.subTest(reuse=reuse), tempfile.TemporaryDirectory(prefix="hia-oracle-quota-") as directory:
                callback = {"armed": False, "rejections": 0}
                def oracle(x, y):
                    if callback["armed"]:
                        with self.assertRaisesRegex(fc.FiniteContextRejected, "reentrant mutation"):
                            owner.prepare_trace([request(ident=2, seed=1, values=huge)])
                        callback["rejections"] += 1
                    return shift_oracle(x, y)
                owner = fc.build_bank(shift_program(), {"baseline": shift_program()}, Path(directory),
                    clang=CLANG, cases=[[1, 0], [1, 4]], oracle=oracle, reuse_oracle=reuse)
                try:
                    callback["armed"] = True
                    trace = owner.prepare_trace([request(ident=1, seed=1, values=huge)])
                    self.assertEqual(callback["rejections"], 1)
                    state = owner.state()
                    self.assertEqual(state["pending_traces"], 1)
                    self.assertGreater(state["pending_input_bytes"], fc.MAX_PENDING_INPUT_BYTES // 2)
                    self.assertLessEqual(state["pending_input_bytes"], fc.MAX_PENDING_INPUT_BYTES)
                    callback["armed"] = False
                    with self.assertRaisesRegex(fc.FiniteContextRejected, "input-byte budget"):
                        owner.prepare_trace([request(ident=3, seed=1, values=huge)])
                    self.assertEqual(owner.state(), state)
                    owner.cancel(trace)
                    self.assertEqual(owner.state()["pending_input_bytes"], 0)
                    observation = owner.run(owner.prepare_trace([request(values=[1])]))
                    self.assertEqual(observation["status"], "completed")
                    self.assertEqual(observation["prefix"]["completed_requests"][0]["state"], 14)
                finally:
                    callback["armed"] = False
                    self.assertTrue(owner.close()["complete"])


if __name__ == "__main__":
    unittest.main()
