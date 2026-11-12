"""Independent fault-injection checks for feedback workload receipts.

The transport below is deliberately a test double. These tests establish
failure accounting and action/result binding, never native performance or
successful execution of the actual Rust worker.
"""
from copy import deepcopy
import unittest
from unittest.mock import patch

from experiments.hia_ndu_feedback_20261106.workload import NativeCache
from hepta.hia_ndu_dynamic import DynamicError


class ScriptedTransport:
    """Small stateful transport whose replies can be corrupted independently."""

    def __init__(self, *args, **kwargs):
        self.calls = []
        self.returncode = 0
        self.close_calls = 0
        self.close_error = None
        self.fail_command = None
        self.transform = lambda command, response: response
        self.state = None

    def ask(self, command):
        self.calls.append(deepcopy(command))
        name = command["command"]
        if name == self.fail_command:
            raise DynamicError("injected transport failure at " + name)
        if name == "init":
            n = command["n"]
            self.state = {
                "n": n, "quota_bytes": command["quota_bytes"],
                "resident_bytes": 0, "baseline_bytes": 2 * n * n * 4,
                "ready": [], "epochs": [1, 1], "allocations": 0,
                "retirements": 0, "reuses": 0, "invalidations": 0,
                "executions": 0, "closed": False,
            }
            body = {"initialized": True}
        elif name == "retire":
            existed = command["id"] in self.state["ready"]
            self.state["ready"] = []
            self.state["resident_bytes"] = 0
            self.state["retirements"] += int(existed)
            body = {"retired": command["id"], "existed": existed}
        elif name == "prepare":
            reused = command["id"] in self.state["ready"]
            self.state["ready"] = [command["id"]]
            self.state["resident_bytes"] = self.state["n"] ** 2 * 4
            self.state["allocations"] += int(not reused)
            body = {"prepared": command["id"], "reused": reused}
        elif name == "run":
            self.state["executions"] += 1
            body = {
                "matrix": command["id"],
                "epoch": self.state["epochs"][command["id"]],
                "dispatch": command["dispatch"], "repeats": command["repeats"],
                "checksum": 12345, "kernel_ns": 7, "oracle_ns": 3,
                "all_outputs_checked": self.state["n"],
            }
        elif name == "close":
            self.state["retirements"] += len(self.state["ready"])
            self.state["ready"] = []
            self.state["resident_bytes"] = 0
            self.state["baseline_bytes"] = 0
            self.state["closed"] = True
            body = {"closed": True}
        else:
            raise AssertionError("Unexpected test command: " + name)
        response = {
            "schema": "hepta.hia.ndu.dynamic-cache.workload.response.v1",
            "state": deepcopy(self.state), "result": body, "service_ns": 13,
        }
        response = self.transform(command, deepcopy(response))
        return response, {"wire_roundtrip_ns": 17}

    def close(self):
        self.close_calls += 1
        if self.close_error is not None:
            raise self.close_error


class FeedbackWorkloadBoundaryTests(unittest.TestCase):
    def worker(self):
        with patch("experiments.hia_ndu_feedback_20261106.workload.JsonProcess",
                   ScriptedTransport):
            return NativeCache("test-binary", "test-manifest", "test-log",
                               n=2, seed=19)

    @staticmethod
    def execute(worker, *, desired=0, target=0, repeats=4, vector_seed=7,
                expected_state_digest=None):
        return worker.execute(
            desired, target, repeats=repeats, vector_seed=vector_seed,
            expected_state_digest=(worker.state_digest if expected_state_digest is None
                                   else expected_state_digest))

    def test_partial_retirement_failure_keeps_spent_work_and_invalidates_advice(self):
        worker = self.worker()
        self.execute(worker)
        before_digest = worker.state_digest
        previous_generation = worker.generation
        worker.process.fail_command = "prepare"
        before_calls = len(worker.process.calls)

        with self.assertRaisesRegex(DynamicError, "injected transport failure"):
            self.execute(worker, desired=1, target=1)

        self.assertEqual([row["command"] for row in worker.process.calls[before_calls:]],
                         ["retire", "prepare"])
        self.assertEqual(len(worker.rows), 2)
        row = worker.rows[-1]
        self.assertEqual(row["status"], "failed")
        self.assertEqual(row["selected_resident"], 1)
        self.assertEqual(row["executed_resident"], -1)
        self.assertEqual(row["before_digest"], before_digest)
        self.assertNotEqual(row["after_digest"], before_digest)
        self.assertEqual(worker.generation, previous_generation + 1)
        self.assertEqual(row["native_service_ns"], 13)
        self.assertGreater(row["workload_wall_ns"], 0)
        self.assertEqual(row["pending_command"]["command"], "prepare")
        self.assertEqual([part["command"]["command"] for part in row["commands"]],
                         ["retire"])
        self.assertEqual(row["output_elements_checked"], 0)
        self.assertIsNone(row["checksum"])
        calls_after_failure = len(worker.process.calls)
        with self.assertRaisesRegex(DynamicError, "stale"):
            self.execute(worker, expected_state_digest=before_digest)
        self.assertEqual(len(worker.process.calls), calls_after_failure)

    def test_run_failure_keeps_successful_load_and_pending_run(self):
        worker = self.worker()
        worker.process.fail_command = "run"
        with self.assertRaisesRegex(DynamicError, "injected transport failure"):
            self.execute(worker)
        self.assertEqual(worker.resident, 0)
        self.assertEqual(worker.rows[-1]["status"], "failed")
        self.assertEqual(worker.rows[-1]["pending_command"]["command"], "run")
        self.assertEqual(worker.rows[-1]["native_service_ns"], 13)
        self.assertGreater(worker.rows[-1]["workload_wall_ns"], 0)

    def test_stale_snapshot_refuses_without_any_transport_command(self):
        worker = self.worker()
        stale = worker.state_digest
        self.execute(worker)
        snapshot = (deepcopy(worker.state), worker.generation, len(worker.rows),
                    len(worker.process.calls))
        with self.assertRaisesRegex(DynamicError, "stale"):
            self.execute(worker, desired=1, target=1, expected_state_digest=stale)
        self.assertEqual((worker.state, worker.generation, len(worker.rows),
                          len(worker.process.calls)), snapshot)

    def test_invalid_advice_is_rejected_before_transport(self):
        cases = ({"desired": True}, {"desired": 2}, {"target": False},
                 {"target": -1}, {"repeats": True}, {"repeats": 0},
                 {"repeats": 65}, {"vector_seed": True},
                 {"vector_seed": -1}, {"vector_seed": 1 << 32})
        for values in cases:
            with self.subTest(values=values):
                worker = self.worker()
                before = (len(worker.process.calls), worker.state_digest)
                with self.assertRaises(DynamicError):
                    self.execute(worker, **values)
                self.assertEqual((len(worker.process.calls), worker.state_digest), before)
                self.assertEqual(worker.rows, [])

    def test_wrong_run_identity_or_output_count_cannot_be_success(self):
        corruptions = {"matrix": 1, "epoch": 2, "dispatch": "direct",
                       "repeats": 5, "all_outputs_checked": 1}
        for field, value in corruptions.items():
            with self.subTest(field=field):
                worker = self.worker()

                def transform(command, response):
                    if command["command"] == "run":
                        response["result"][field] = value
                    return response

                worker.process.transform = transform
                with self.assertRaisesRegex(DynamicError, "selected/executed"):
                    self.execute(worker)
                self.assertEqual(worker.rows[-1]["status"], "failed")
                self.assertEqual(worker.rows[-1]["output_elements_checked"], 0)
                self.assertEqual(worker.rows[-1]["commands"][-1]["command"]["command"], "run")

    def test_replayed_run_receipt_with_old_execution_counter_is_rejected(self):
        worker = self.worker()
        first = self.execute(worker)
        old_response = deepcopy(first["commands"][-1]["result"])

        def replay(command, response):
            return deepcopy(old_response) if command["command"] == "run" else response

        worker.process.transform = replay
        with self.assertRaisesRegex(DynamicError, "selected/executed"):
            self.execute(worker)
        self.assertEqual(len(worker.rows), 2)
        self.assertEqual(worker.rows[-1]["status"], "failed")
        self.assertNotEqual(worker.rows[-1]["before_digest"], worker.rows[-1]["after_digest"])

    def test_selected_resident_mismatch_is_rejected(self):
        worker = self.worker()

        def corrupt(command, response):
            if command["command"] == "run":
                response["state"]["ready"] = [1]
            return response

        worker.process.transform = corrupt
        with self.assertRaisesRegex(DynamicError, "selected/executed"):
            self.execute(worker)
        row = worker.rows[-1]
        self.assertEqual(row["status"], "failed")
        self.assertEqual((row["selected_resident"], row["executed_resident"]), (0, 1))

    def test_prepare_wrong_identity_or_epoch_stops_before_run(self):
        for field in ("identity", "epoch"):
            with self.subTest(field=field):
                worker = self.worker()

                def corrupt(command, response):
                    if command["command"] == "prepare":
                        if field == "identity":
                            response["result"]["prepared"] = 1
                        else:
                            response["state"]["epochs"][0] = 2
                    return response

                worker.process.transform = corrupt
                with self.assertRaisesRegex(DynamicError, "prepare receipt mismatch"):
                    self.execute(worker)
                self.assertEqual([c["command"] for c in worker.process.calls],
                                 ["init", "prepare"])
                self.assertEqual(worker.rows[-1]["status"], "failed")
                self.assertEqual(worker.rows[-1]["pending_command"]["command"], "prepare")

    def test_retire_wrong_identity_stops_before_loading_replacement(self):
        worker = self.worker()
        self.execute(worker)
        before_calls = len(worker.process.calls)

        def corrupt(command, response):
            if command["command"] == "retire":
                response["result"]["retired"] = 1
            return response

        worker.process.transform = corrupt
        with self.assertRaisesRegex(DynamicError, "retire receipt mismatch"):
            self.execute(worker, desired=1, target=1)
        self.assertEqual([c["command"] for c in worker.process.calls[before_calls:]],
                         ["retire"])
        self.assertEqual(worker.rows[-1]["status"], "failed")
        self.assertEqual(worker.rows[-1]["pending_command"]["command"], "retire")

    def test_ready_slot_cannot_claim_zero_resident_bytes(self):
        worker = self.worker()

        def corrupt(command, response):
            if command["command"] == "prepare":
                response["state"]["resident_bytes"] = 0
            return response

        worker.process.transform = corrupt
        with self.assertRaisesRegex(DynamicError, "one-slot quota"):
            self.execute(worker)
        self.assertEqual(worker.rows[-1]["status"], "failed")
        self.assertEqual([c["command"] for c in worker.process.calls], ["init", "prepare"])

    def test_malformed_state_is_rejected_and_attempt_remains_accounted(self):
        corruptions = {"n": 3, "resident_bytes": 17, "ready": [0, 1],
                       "epochs": [1], "executions": True}
        for field, value in corruptions.items():
            with self.subTest(field=field):
                worker = self.worker()

                def corrupt(command, response):
                    if command["command"] == "run":
                        response["state"][field] = value
                    return response

                worker.process.transform = corrupt
                with self.assertRaisesRegex(DynamicError, "one-slot quota"):
                    self.execute(worker)
                self.assertEqual(worker.rows[-1]["status"], "failed")
                self.assertEqual(worker.rows[-1]["pending_command"]["command"], "run")

    def test_malformed_result_does_not_break_failure_accounting(self):
        for malformed in (None, [], "not-a-result"):
            with self.subTest(malformed=malformed):
                worker = self.worker()

                def corrupt(command, response):
                    if command["command"] == "run":
                        response["result"] = malformed
                    return response

                worker.process.transform = corrupt
                with self.assertRaises((DynamicError, TypeError, KeyError, AttributeError)):
                    self.execute(worker)
                self.assertEqual(len(worker.rows), 1,
                                 "Malformed result masked the failed attempt ledger")
                self.assertEqual(worker.rows[0]["status"], "failed")
                self.assertEqual(worker.rows[0]["output_elements_checked"], 0)
                self.assertGreater(worker.rows[0]["workload_wall_ns"], 0)

    def test_process_close_exception_is_retained_and_repeat_cannot_look_successful(self):
        worker = self.worker()
        self.execute(worker)
        worker.process.close_error = RuntimeError("injected cleanup failure")
        with self.assertRaisesRegex(RuntimeError, "injected cleanup failure"):
            worker.close()
        receipt = deepcopy(worker.close_receipt)
        self.assertIn("injected cleanup failure", receipt["error"])
        self.assertGreater(receipt["close_ns"], 0)
        calls = len(worker.process.calls)
        with self.assertRaisesRegex(DynamicError, "previous close failed"):
            worker.close()
        self.assertEqual(worker.close_receipt, receipt)
        self.assertEqual(len(worker.process.calls), calls)
        self.assertEqual(worker.process.close_calls, 1)

    def test_nonzero_close_exit_stays_failed_on_repeated_close(self):
        worker = self.worker()
        worker.process.returncode = 7
        with self.assertRaisesRegex(DynamicError, "exited unsuccessfully"):
            worker.close()
        self.assertEqual(worker.close_receipt["returncode"], 7)
        self.assertTrue(worker.close_receipt["error"])
        with self.assertRaisesRegex(DynamicError, "previous close failed"):
            worker.close()
        self.assertEqual(worker.process.close_calls, 1)

    def test_close_imbalance_cannot_be_reported_as_success(self):
        worker = self.worker()
        self.execute(worker)

        def corrupt(command, response):
            if command["command"] == "close":
                response["state"]["retirements"] = 0
            return response

        worker.process.transform = corrupt
        with self.assertRaisesRegex(DynamicError, "lifecycle imbalance"):
            worker.close()
        self.assertTrue(worker.close_receipt["error"])
        self.assertEqual(worker.process.close_calls, 1)

    def test_successful_close_is_idempotent_and_rejects_further_actions(self):
        worker = self.worker()
        self.execute(worker)
        receipt = worker.close()
        calls = len(worker.process.calls)
        self.assertIsNone(receipt["error"])
        self.assertEqual(receipt["returncode"], 0)
        self.assertEqual(receipt["final_state"]["resident_bytes"], 0)
        self.assertEqual(receipt["final_state"]["baseline_bytes"], 0)
        self.assertEqual(worker.close(), receipt)
        with self.assertRaisesRegex(DynamicError, "closed"):
            self.execute(worker)
        self.assertEqual(len(worker.process.calls), calls)
        self.assertEqual(worker.process.close_calls, 1)

    def test_cost_ledger_preserves_nesting_instead_of_double_counting_components(self):
        worker = self.worker()
        row = self.execute(worker)
        self.assertEqual([r["command"]["command"] for r in row["commands"]],
                         ["prepare", "run"])
        self.assertEqual(row["kernel_ns"], 7)
        self.assertEqual(row["output_validation_ns"], 3)
        self.assertEqual(row["native_service_ns"], 26)
        self.assertEqual(sum(part["wire_ns"] for part in row["commands"]), 34)
        self.assertGreater(row["workload_wall_ns"], 0)
        self.assertEqual(row["status"], "success")


if __name__ == "__main__":
    unittest.main()
