"""P7 negative regression: a duplicate queue token must not erase old receipts.

This intentionally uses the production submit_queue method with a narrow
state/lock fixture; no mocked native execution is economic or hardware proof.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

import hepta.hia_stateful as stateful
from hepta.hia_adaptive import AdaptiveRejected
from tests.test_hia_stateful_queue_capture import fake_runtime


class QueueTokenUniquenessTests(unittest.TestCase):
    def test_existing_completed_queue_token_is_never_overwritten(self):
        runtime = fake_runtime()
        prior = {
            "items": (), "sha256": "immutable-previous-queue-hash",
            "status": "completed", "revision": 0, "owner": "frozen-owner",
            "receipt": {"executed_steps": 3, "queue_sha256": "immutable-previous-queue-hash"},
        }
        runtime._queues["forced-repeat-token"] = prior
        work = [{"slot": 0, "delta": 1, "iterations": 1}]
        with patch.object(stateful.secrets, "token_hex", return_value="forced-repeat-token"):
            with self.assertRaisesRegex(AdaptiveRejected, "collision"):
                runtime.submit_queue(work)
        self.assertEqual(list(runtime._queues), ["forced-repeat-token"])
        self.assertIs(runtime._queues["forced-repeat-token"], prior)
        self.assertEqual(prior["receipt"]["executed_steps"], 3)

    def test_distinct_token_keeps_standard_bounded_admission(self):
        runtime = fake_runtime()
        with patch.object(stateful.secrets, "token_hex", return_value="unique-new-token"):
            token = runtime.submit_queue([{"slot": 1, "delta": 7, "iterations": 2}])
        self.assertEqual(token, "unique-new-token")
        self.assertEqual(runtime._queues[token]["status"], "submitted")
        self.assertEqual(runtime._queues[token]["items"][0].iterations, 2)


if __name__ == "__main__":
    unittest.main()
