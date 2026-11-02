"""Real fork/lock boundaries for the finite foreign-call checkpoint owner.

No fake worker in these protocol tests is counted as native C++ evidence.
The existing two-version qualification runs actual upstream allocation faults.
"""
import json
import os
import select
import signal
import threading
import unittest
from unittest.mock import patch

import hepta.cpp_json_checkpoint as checkpoint
from tests.test_cpp_json_checkpoint import fake_image, response


class JsonCheckpointCaptureTests(unittest.TestCase):
    def test_mutation_between_extent_check_and_snapshot_cannot_enlarge_or_empty_state(self):
        for replacement in ([], [1] * 65, [1] * 100000):
            values = [1]
            original = checkpoint._require
            calls = [0]
            def mutate(condition, message):
                original(condition, message)
                calls[0] += 1
                if calls[0] == 1:
                    values[:] = replacement
            with self.subTest(size=len(replacement)), patch.object(checkpoint, "_require", side_effect=mutate):
                with self.assertRaisesRegex(checkpoint.CheckpointRejected, "extent changed"):
                    checkpoint._state(values)

    def test_context_entry_does_not_reopen_closed_or_uncertain_owner(self):
        owner = checkpoint.JsonCheckpoint(fake_image(), [1])
        owner.close()
        with self.assertRaisesRegex(checkpoint.CheckpointRejected, "closed or poisoned"):
            owner.__enter__()
        owner = checkpoint.JsonCheckpoint(fake_image(), [1])
        owner._poisoned = True
        with self.assertRaisesRegex(checkpoint.CheckpointRejected, "closed or poisoned"):
            owner.__enter__()


@unittest.skipUnless(hasattr(os, "fork"), "actual fork semantics required")
class JsonCheckpointForkTests(unittest.TestCase):
    def child_probe(self, owner, request):
        """Fork an actual process; a missing pre-lock guard fails on SIGALRM."""
        read_fd, write_fd = os.pipe()
        child = os.fork()
        if child == 0:
            try:
                os.close(read_fd)
                signal.alarm(3)
                rejected = []
                actions = (
                    ("snapshot", owner.snapshot), ("history", owner.history),
                    ("prepare", lambda: owner.prepare(0, 9, revision=0)),
                    ("cancel", lambda: owner.cancel(request)),
                    ("execute", lambda: owner.execute(request)),
                    ("enter", owner.__enter__),
                )
                with patch.object(checkpoint, "run_bounded", side_effect=AssertionError("fork launched worker")) as launch:
                    for name, action in actions:
                        try:
                            action()
                        except checkpoint.CheckpointRejected as error:
                            if "forked checkpoint" in str(error):
                                rejected.append(name)
                    owner.close()
                    output = {"rejected": rejected, "closed": owner._closed,
                              "pending_cleared": owner._pending is None,
                              "launches": launch.call_count}
                os.write(write_fd, json.dumps(output).encode())
                os.close(write_fd)
                os._exit(0)
            except BaseException:
                os._exit(3)
        os.close(write_fd)
        try:
            ready, _, _ = select.select([read_fd], [], [], 5)
            if not ready:
                os.kill(child, signal.SIGKILL)
                self.fail("forked owner blocked before rejecting inherited lock")
            data = os.read(read_fd, 4096)
        finally:
            os.close(read_fd)
            waited, status = os.waitpid(child, 0)
        self.assertEqual(waited, child)
        self.assertTrue(os.WIFEXITED(status), f"child died on signal; likely inherited-lock deadlock: {status}")
        self.assertEqual(os.WEXITSTATUS(status), 0, data)
        result = json.loads(data)
        self.assertEqual(result["rejected"], ["snapshot", "history", "prepare", "cancel", "execute", "enter"])
        self.assertTrue(result["closed"] and result["pending_cleared"])
        self.assertEqual(result["launches"], 0)
        return result

    def test_idle_fork_cannot_duplicate_one_use_request_or_close_parent(self):
        owner = checkpoint.JsonCheckpoint(fake_image(), [1, 2, 3])
        self.addCleanup(owner.close)
        request = owner.prepare(1, 5, revision=0)
        before = owner.snapshot()
        self.child_probe(owner, request)
        self.assertEqual(owner.snapshot(), before)
        with patch.object(checkpoint, "run_bounded", side_effect=lambda argv, **kw: response(kw)) as launch:
            result = owner.execute(request)
            self.assertTrue(result["committed"])
            self.assertEqual(result["after"]["values"], [1, 5, 3])
            launch.assert_called_once()
        with self.assertRaises(checkpoint.CheckpointRejected):
            owner.execute(request)

    def test_fork_while_other_thread_holds_lock_rejects_without_waiting_or_launching(self):
        owner = checkpoint.JsonCheckpoint(fake_image(), [1, 2, 3])
        self.addCleanup(owner.close)
        request = owner.prepare(1, 5, revision=0)
        held, release = threading.Event(), threading.Event()
        def hold():
            with owner._lock:
                held.set()
                release.wait(10)
        thread = threading.Thread(target=hold)
        thread.start()
        self.assertTrue(held.wait(2))
        try:
            self.child_probe(owner, request)
        finally:
            release.set()
            thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertTrue(owner.snapshot()["pending"])
        owner.cancel(request)
        self.assertEqual(owner.snapshot()["revision"], 0)


if __name__ == "__main__":
    unittest.main()
