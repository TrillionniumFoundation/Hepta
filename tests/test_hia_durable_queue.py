"""Native pure-owner journal: real SIGKILL recovery and finite restart credit.

Fault injection chooses process/file-system boundaries; it does not fabricate
native success, a proof receipt, a kernel result or an elapsed-time advantage.
"""
from __future__ import annotations

import copy
from dataclasses import replace
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import select
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from hepta.hia_durable_queue import DurableOwnedQueue, DurableQueueRejected, _digest, _wire
from tools.qualify_hia_stateful import programs, expected

CLANG = os.environ.get("CLANG", "/usr/bin/clang-20")
NATIVE = (sys.platform == "linux" and shutil.which(CLANG) and hasattr(os, "memfd_create")
          and importlib.util.find_spec("z3") is not None)
WORK = [{"slot": 0, "delta": 7, "iterations": 5}]


def _crash_worker(directory, build, journal_id, mode, clang):
    owner = DurableOwnedQueue.recover(programs()[0], directory, build,
                                     journal_id=journal_id, clang=clang)

    def die(stage):
        evidence = {"stage": stage, "attempts": owner._data["attempts_used"],
                    "durable_values": owner._data["values"],
                    "actual_native_values": list(owner._owner._values()),
                    "actual_native_progress": int(owner._owner._driver.hs_progress(owner._owner._state))}
        with (Path(directory) / "crash-observation.json").open("w") as stream:
            json.dump(evidence, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.kill(os.getpid(), signal.SIGKILL)

    if mode == "before_launch":
        owner._owner.submit_queue = lambda unused: die("before_native_launch")
    elif mode == "partial_native":
        original = owner._owner._apply_items

        def partial(state, items, image):
            # Execute a genuine prefix using the already independently loaded
            # scalar native transition; terminate before any result checkpoint.
            original(state, (replace(items[0], iterations=2),), image)
            die("after_two_actual_native_steps")

        owner._owner._apply_items = partial
    elif mode == "lost_ack":
        original = owner._store

        def committed(data):
            original(data)
            if data["records"] and data["records"][-1]["status"] == "committed":
                die("after_directory_fsync_before_ack")

        owner._store = committed
    else:
        raise ValueError("unknown fault stage")
    owner.execute("request-a", WORK)
    raise AssertionError("crash boundary did not terminate the process")


@unittest.skipUnless(NATIVE, "Actual Linux Clang20, Z3 and native seals required")
class DurableQueueNativeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="hia-durable-native-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.build_index = 0

    def build(self):
        self.build_index += 1
        return self.root / ("build-" + str(self.build_index))

    def create(self, **limits):
        owner = DurableOwnedQueue.create(programs()[0], self.root / "journal", self.build(),
                                          [11, 17], clang=CLANG, **limits)
        self.addCleanup(owner.close)
        self.journal_id = owner.snapshot()["journal"]["journal_id"]
        return owner

    def recover(self, **overrides):
        options = {"journal_id": self.journal_id, "clang": CLANG, **overrides}
        owner = DurableOwnedQueue.recover(programs()[0], self.root / "journal", self.build(), **options)
        self.addCleanup(owner.close)
        return owner

    def read(self):
        return json.loads((self.root / "journal/checkpoint.json").read_bytes())["payload"]

    def rewrite(self, update):
        data = self.read()
        update(data)
        (self.root / "journal/checkpoint.json").write_bytes(_wire({"payload": data, "sha256": _digest(data)}))

    def crash(self, mode):
        script = "from tests.test_hia_durable_queue import _crash_worker; import sys; _crash_worker(*sys.argv[1:])"
        result = subprocess.run([sys.executable, "-c", script, str(self.root / "journal"),
            str(self.build()), self.journal_id, mode, CLANG], capture_output=True, timeout=30)
        self.assertEqual(result.returncode, -signal.SIGKILL, result.stderr.decode(errors="replace"))
        return json.loads((self.root / "journal/crash-observation.json").read_text())

    def test_native_commit_and_lost_ack_retry_survive_reopen(self):
        owner = self.create()
        first = owner.execute("request-a", WORK)
        self.assertEqual(first["final_values"], expected([11, 17], WORK))
        self.assertTrue(first["durable_ack"])
        owner.close()
        restored = self.recover()
        with patch.object(restored._owner, "submit_queue", side_effect=AssertionError("duplicate ran native")):
            again = restored.execute("request-a", WORK)
        self.assertTrue(again["duplicate_ack"])
        self.assertFalse(again["native_executed"])
        self.assertEqual(again["final_values"], first["final_values"])
        self.assertEqual(restored.snapshot()["journal"]["attempts_used"], 1)
        self.assertEqual(restored.snapshot()["journal"]["owner_starts_used"], 2)
        with self.assertRaisesRegex(DurableQueueRejected, "different work"):
            restored.execute("request-a", [{"slot": 0, "delta": 8, "iterations": 5}])

    def test_sigkill_before_launch_consumes_attempt_without_progress(self):
        self.create().close()
        observed = self.crash("before_launch")
        self.assertEqual(observed["attempts"], 1)
        self.assertEqual(observed["actual_native_progress"], 0)
        owner = self.recover()
        self.assertEqual(owner.snapshot()["journal"]["values"], [11, 17])
        resumed = owner.resume()
        self.assertEqual(resumed["final_values"], expected([11, 17], WORK))
        self.assertEqual(owner.snapshot()["journal"]["attempts_used"], 2)

    def test_sigkill_after_real_native_prefix_restores_committed_input(self):
        self.create().close()
        observed = self.crash("partial_native")
        self.assertEqual(observed["actual_native_progress"], 2)
        self.assertEqual(observed["actual_native_values"], expected([11, 17], WORK, progress=2))
        self.assertEqual(observed["durable_values"], [11, 17])
        owner = self.recover()
        resumed = owner.resume()
        self.assertEqual(resumed["final_values"], expected([11, 17], WORK))
        self.assertEqual(owner.snapshot()["journal"]["committed_steps"], 5)
        self.assertEqual(owner.snapshot()["journal"]["attempts_used"], 2)
        self.assertEqual(owner.snapshot()["journal"]["owner_starts_used"], 3)

    def test_sigkill_after_commit_before_ack_does_not_repeat_native_work(self):
        self.create().close()
        observed = self.crash("lost_ack")
        self.assertEqual(observed["stage"], "after_directory_fsync_before_ack")
        self.assertEqual(observed["actual_native_progress"], 5)
        self.assertEqual(observed["durable_values"], expected([11, 17], WORK))
        owner = self.recover()
        with patch.object(owner._owner, "execute_committed", side_effect=AssertionError("native replay after commit")):
            result = owner.execute("request-a", WORK)
        self.assertTrue(result["duplicate_ack"])
        self.assertEqual(owner.snapshot()["journal"]["attempts_used"], 1)

    def test_crash_restart_cannot_refresh_exhausted_attempt_credit(self):
        self.create(max_attempts=1).close()
        self.crash("partial_native")
        for _ in range(2):
            owner = self.recover()
            with self.assertRaisesRegex(DurableQueueRejected, "attempt budget exhausted"):
                owner.resume()
            self.assertEqual(owner.snapshot()["journal"]["attempts_used"], 1)
            self.assertEqual(owner.snapshot()["journal"]["values"], [11, 17])
            owner.close()

    def test_restart_cannot_refresh_owner_or_request_or_step_budget(self):
        owner = self.create(max_requests=1, max_owner_starts=2, max_total_steps=5)
        owner.execute("request-a", WORK)
        owner.close()
        restored = self.recover()
        with self.assertRaisesRegex(DurableQueueRejected, "budget exhausted"):
            restored.execute("request-b", [{"slot": 1, "delta": 1, "iterations": 1}])
        restored.close()
        with self.assertRaisesRegex(DurableQueueRejected, "owner-start budget exhausted"):
            self.recover()
        self.assertEqual(self.read()["owner_starts_used"], 2)

    def test_live_writer_lock_excludes_second_recovery_before_build(self):
        owner = self.create()
        before = self.read()["owner_starts_used"]
        with self.assertRaisesRegex(DurableQueueRejected, "live owner"):
            self.recover()
        self.assertEqual(self.read()["owner_starts_used"], before)
        self.assertEqual(owner.execute("request-a", WORK)["final_values"], expected([11, 17], WORK))

    def test_world_accessible_journal_directory_refuses_before_native_build(self):
        self.create().close()
        directory = self.root / "journal"
        directory.chmod(0o777)
        build = self.build()
        try:
            with self.assertRaisesRegex(DurableQueueRejected, "directory must be private"):
                DurableOwnedQueue.recover(programs()[0], directory, build,
                                          journal_id=self.journal_id, clang=CLANG)
            self.assertFalse(build.exists())
            self.assertEqual(self.read()["owner_starts_used"], 1)
        finally:
            directory.chmod(0o700)

    def test_forked_owner_refuses_before_inherited_locked_mutex(self):
        owner = self.create()
        entered, release = threading.Event(), threading.Event()

        def hold():
            with owner._mutex:
                entered.set()
                release.wait(10)

        thread = threading.Thread(target=hold)
        thread.start()
        self.assertTrue(entered.wait(5))
        readfd, writefd = os.pipe()
        child = os.fork()
        if child == 0:
            os.close(readfd)
            try:
                try:
                    owner.execute("child-request", WORK)
                    os._exit(10)
                except DurableQueueRejected as error:
                    if "forked owner" not in str(error):
                        os._exit(11)
                owner.close()  # no inherited mutex or native destructor
                try:
                    DurableOwnedQueue.recover(programs()[0], self.root / "journal", self.root / "child-build",
                                              journal_id=self.journal_id, clang=CLANG)
                    os._exit(12)
                except DurableQueueRejected as error:
                    if "live owner" not in str(error):
                        os._exit(13)
                os.write(writefd, b"refused_without_deadlock")
                os._exit(0)
            except BaseException:
                os._exit(14)
        os.close(writefd)
        try:
            ready = select.select([readfd], [], [], 5)[0]
            if not ready:
                os.kill(child, signal.SIGKILL)
            _, status = os.waitpid(child, 0)
            self.assertTrue(ready, "forked wrapper blocked on its inherited mutex")
            self.assertEqual(os.waitstatus_to_exitcode(status), 0)
            self.assertEqual(os.read(readfd, 100), b"refused_without_deadlock")
        finally:
            release.set()
            thread.join(5)
            os.close(readfd)
        self.assertEqual(owner.execute("parent-request", WORK)["final_values"], expected([11, 17], WORK))

    def test_truncated_duplicate_key_and_noncanonical_journals_refuse(self):
        self.create().close()
        path = self.root / "journal/checkpoint.json"
        original = path.read_bytes()
        invalid = [original[:len(original)//2], original + b"\n", b'{"payload":{},"payload":{},"sha256":"x"}',
                   b"[" * 100 + b"]" * 100]
        for raw in invalid:
            with self.subTest(raw=raw[:30]):
                path.write_bytes(raw)
                with self.assertRaisesRegex(DurableQueueRejected, "malformed|schema"):
                    self.recover()
        path.write_bytes(original)
        self.assertEqual(self.recover().snapshot()["journal"]["values"], [11, 17])

    def test_checksummed_invalid_budget_or_request_shape_refuses(self):
        owner = self.create()
        owner.execute("request-a", WORK)
        owner.close()
        original = (self.root / "journal/checkpoint.json").read_bytes()
        updates = [lambda d: d.update(attempts_used=0), lambda d: d.update(owner_starts_used=True),
                   lambda d: d["records"].append(copy.deepcopy(d["records"][0])),
                   lambda d: d["records"][0]["result"].update(serialized_proof_authority=True)]
        for update in updates:
            (self.root / "journal/checkpoint.json").write_bytes(original)
            self.rewrite(update)
            with self.assertRaises(DurableQueueRejected):
                self.recover()

    def test_identity_changes_refuse_without_replaying_native(self):
        self.create().close()
        with self.assertRaisesRegex(DurableQueueRejected, "identity changed"):
            DurableOwnedQueue.recover(programs()[1], self.root / "journal", self.build(),
                                      journal_id=self.journal_id, clang=CLANG)
        with self.assertRaisesRegex(DurableQueueRejected, "identity changed"):
            self.recover(journal_id="0" * 32)
        from hepta.hia_optimization import DEFAULT_POLICY
        policy = {**DEFAULT_POLICY, "timeout_ms": DEFAULT_POLICY["timeout_ms"] + 1}
        with self.assertRaisesRegex(DurableQueueRejected, "identity changed"):
            self.recover(policy=policy)
        self.rewrite(lambda d: d.update(source_sha256="0" * 64))
        with self.assertRaisesRegex(DurableQueueRejected, "identity changed"):
            self.recover()

    def test_changed_native_artifact_binding_refuses_and_charges_rebuild(self):
        self.create().close()
        self.rewrite(lambda d: d["native_binding"].update(artifact_sha256="0" * 64))
        with self.assertRaisesRegex(DurableQueueRejected, "native artifact"):
            self.recover()
        self.assertEqual(self.read()["owner_starts_used"], 2)
        self.assertEqual(self.read()["attempts_used"], 0)

    def test_failed_recovery_build_still_consumes_persisted_owner_credit(self):
        self.create(max_owner_starts=2).close()
        with self.assertRaises((OSError, ValueError)):
            self.recover(clang=str(self.root / "missing-clang"))
        self.assertEqual(self.read()["owner_starts_used"], 2)
        with self.assertRaisesRegex(DurableQueueRejected, "owner-start budget exhausted"):
            self.recover()

    def test_failed_rename_poison_requires_recovery_without_native_progress(self):
        owner = self.create()
        with patch("hepta.hia_durable_queue.os.replace", side_effect=OSError("injected rename refusal")):
            with self.assertRaisesRegex(OSError, "rename refusal"):
                owner.execute("request-a", WORK)
        self.assertTrue(owner.snapshot()["uncertain"])
        with self.assertRaisesRegex(DurableQueueRejected, "uncertain"):
            owner.execute("request-a", WORK)
        owner.close()
        restored = self.recover()
        self.assertEqual(restored.snapshot()["journal"]["attempts_used"], 0)
        self.assertEqual(restored.execute("request-a", WORK)["final_values"], expected([11, 17], WORK))

    def test_directory_fsync_failure_after_commit_is_reconciled_by_recovery(self):
        owner = self.create()
        original = os.fsync
        calls = 0

        def fail_commit_directory(fd):
            nonlocal calls
            if fd == owner._dirfd:
                calls += 1
                if calls == 3:  # intent, attempt reservation, completed state
                    raise OSError("injected post-rename fsync failure")
            return original(fd)

        with patch("hepta.hia_durable_queue.os.fsync", side_effect=fail_commit_directory):
            with self.assertRaisesRegex(OSError, "post-rename"):
                owner.execute("request-a", WORK)
        self.assertTrue(owner.snapshot()["uncertain"])
        owner.close()
        restored = self.recover()
        result = restored.execute("request-a", WORK)
        self.assertTrue(result["duplicate_ack"])
        self.assertEqual(result["final_values"], expected([11, 17], WORK))
        self.assertEqual(restored.snapshot()["journal"]["attempts_used"], 1)

    def test_explicit_profile_rejects_effects_and_pointer_or_general_state(self):
        bad = copy.deepcopy(programs()[0])
        bad["functions"][0]["effects"] = ["trap"]
        with self.assertRaises(ValueError):
            DurableOwnedQueue.create(bad, self.root / "journal", self.build(), [1], clang=CLANG)
        self.assertFalse((self.root / "journal").exists())
        owner = self.create()
        report = owner.snapshot()
        for key in ("serialized_proof_authority", "external_effect_exactly_once", "power_loss_certified",
                    "device_recovery_supported", "hostile_storage_rollback_resistant", "full_cost_advantage_proved"):
            self.assertFalse(report[key])


if __name__ == "__main__":
    unittest.main()
