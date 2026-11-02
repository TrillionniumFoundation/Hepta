"""Actual native concurrent submitters on one durable pure-state owner."""
from concurrent.futures import ThreadPoolExecutor
import copy
import tempfile
from pathlib import Path
import threading
import unittest
from unittest.mock import patch

from hepta.hia_durable_queue import DurableOwnedQueue, DurableQueueRejected
from tests.test_hia_durable_queue import CLANG, NATIVE, WORK
from tools.qualify_hia_stateful import programs, expected


@unittest.skipUnless(NATIVE, "Actual Linux Clang20, Z3 and native seals required")
class DurableRevisionNativeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="hia-revision-native-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.owner = DurableOwnedQueue.create(programs()[0], self.root / "journal",
            self.root / "native", [11, 17], clang=CLANG)
        self.addCleanup(self.owner.close)
        self.journal_id = self.owner.snapshot()["journal"]["journal_id"]

    def reopen(self):
        self.owner.close()
        self.owner = DurableOwnedQueue.recover(programs()[0], self.root / "journal",
            self.root / "recovered", journal_id=self.journal_id, clang=CLANG)
        self.addCleanup(self.owner.close)
        return self.owner

    def test_competing_producers_have_one_linearized_native_commit(self):
        barrier = threading.Barrier(4)
        def submit(index):
            barrier.wait(timeout=10)
            try:
                return self.owner.execute("request-" + str(index), WORK, expected_committed_steps=0)
            except DurableQueueRejected as error:
                return str(error)
        with ThreadPoolExecutor(max_workers=4) as pool:
            rows = list(pool.map(submit, range(4)))
        winners = [row for row in rows if type(row) is dict]
        rejected = [row for row in rows if type(row) is str]
        self.assertEqual(len(winners), 1)
        self.assertEqual(len(rejected), 3)
        self.assertTrue(all("stale expected committed revision" in row for row in rejected))
        result = winners[0]
        self.assertEqual((result["input_committed_steps"], result["output_committed_steps"]), (0, 5))
        journal = self.owner.snapshot()["journal"]
        self.assertEqual((journal["attempts_used"], journal["admitted_steps"], journal["committed_steps"]), (1, 5, 5))
        self.assertEqual(journal["values"], expected([11, 17], WORK))
        self.assertEqual(len(journal["records"]), 1)

    def test_concurrent_same_id_retries_execute_once(self):
        barrier = threading.Barrier(3)
        def submit(_):
            barrier.wait(timeout=10)
            return self.owner.execute("same-request", WORK, expected_committed_steps=0)
        with ThreadPoolExecutor(max_workers=3) as pool:
            results = list(pool.map(submit, range(3)))
        self.assertEqual(sum(row["native_executed"] for row in results), 1)
        self.assertEqual(sum(row["duplicate_ack"] for row in results), 2)
        self.assertTrue(all(row["final_values"] == expected([11, 17], WORK) for row in results))
        self.assertEqual(self.owner.snapshot()["journal"]["attempts_used"], 1)

    def test_historical_ack_uses_original_revision_after_later_commit_and_restart(self):
        first = self.owner.execute("a", WORK, expected_committed_steps=0)
        second = self.owner.execute("b", WORK, expected_committed_steps=5)
        owner = self.reopen()
        before = copy.deepcopy(owner.snapshot()["journal"])
        with patch.object(owner._owner, "submit_queue", side_effect=AssertionError("duplicate replayed")):
            duplicate = owner.execute("a", WORK, expected_committed_steps=0)
            self.assertTrue(duplicate["duplicate_ack"])
            self.assertEqual(duplicate["final_values"], first["final_values"])
            self.assertEqual(duplicate["output_committed_steps"], 5)
            for revision in (5, 10):
                with self.assertRaisesRegex(DurableQueueRejected, "request input revision"):
                    owner.execute("a", WORK, expected_committed_steps=revision)
        self.assertEqual(owner.snapshot()["journal"], before)
        self.assertEqual(before["values"], second["final_values"])
        self.assertEqual(before["committed_steps"], 10)

    def test_stale_or_invalid_revision_never_charges_or_writes(self):
        class Integer(int):
            pass
        before = self.owner.snapshot()["journal"]
        with patch.object(self.owner, "_store", side_effect=AssertionError("rejection wrote journal")):
            for revision in (True, Integer(0), -1, 1_000_000_001, 0.0, "0"):
                with self.subTest(revision=repr(revision)):
                    with self.assertRaisesRegex(DurableQueueRejected, "expected committed revision"):
                        self.owner.execute("bad", WORK, expected_committed_steps=revision)
            with self.assertRaisesRegex(DurableQueueRejected, "stale expected committed revision"):
                self.owner.execute("future", WORK, expected_committed_steps=5)
        self.assertEqual(self.owner.snapshot()["journal"], before)
        self.assertFalse(self.owner.snapshot()["uncertain"])

    def test_pending_intent_precondition_survives_failed_submission_and_recovery(self):
        with patch.object(self.owner._owner, "submit_queue", side_effect=RuntimeError("before native launch")):
            with self.assertRaisesRegex(RuntimeError, "before native launch"):
                self.owner.execute("pending", WORK, expected_committed_steps=0)
        owner = self.reopen()
        before = owner.snapshot()["journal"]
        self.assertEqual((before["attempts_used"], before["committed_steps"]), (1, 0))
        with self.assertRaisesRegex(DurableQueueRejected, "request input revision"):
            owner.execute("pending", WORK, expected_committed_steps=5)
        self.assertEqual(owner.snapshot()["journal"], before)
        result = owner.execute("pending", WORK, expected_committed_steps=0)
        self.assertEqual(result["final_values"], expected([11, 17], WORK))
        self.assertEqual((result["input_committed_steps"], result["output_committed_steps"]), (0, 5))
        self.assertEqual(owner.snapshot()["journal"]["attempts_used"], 2)

    def test_legacy_unconditional_requests_and_empty_device_capabilities_remain_explicit(self):
        first = self.owner.execute("legacy", WORK)
        second = self.owner.execute("conditional", WORK, expected_committed_steps=5)
        self.assertEqual(second["final_values"], expected(first["final_values"], WORK))
        report = self.owner.snapshot()
        self.assertEqual(report["device_permissions"], [])
        self.assertFalse(report["external_pointer_borrow_supported"])
        self.assertFalse(report["device_recovery_supported"])
        self.assertFalse(report["power_loss_certified"])


if __name__ == "__main__":
    unittest.main()
