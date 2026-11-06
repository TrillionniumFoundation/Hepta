"""Business oracle, committed-prefix recovery and real native differential."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import random
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from hepta.apps.quota import (
    CommitUnknown, HIAEngine, LIMIT, QuotaLedger, QuotaRejected, canonical, unpack,
)

CLANG = os.environ.get("CLANG", "/usr/lib/llvm-20/bin/clang")


def reference(version, available, held, amount, operation):
    """Independent Python integer specification; never imported by the app."""
    if available + held > LIMIT:
        return 3, {"available": 0, "held": 0}
    current = {"available": available, "held": held}
    if amount > LIMIT:
        return 3, current
    if operation not in range(5 if version == "v2" else 4):
        return 2, current
    if operation == 0:
        if available + held + amount > LIMIT:
            return 3, current
        available += amount
    elif operation == 1:
        if amount > available:
            return 1, current
        available, held = available - amount, held + amount
    elif operation == 2:
        if amount > held:
            return 1, current
        held -= amount
    elif operation == 3:
        if amount > held:
            return 1, current
        available, held = available + amount, held - amount
    elif operation == 4:
        if amount > available:
            return 1, current
        available -= amount
    return 0, {"available": available, "held": held}


def cases():
    boundaries = (0, 1, 7, LIMIT, LIMIT + 1, (1 << 32) - 1)
    for a in boundaries:
        for h in boundaries:
            for n in boundaries:
                for op in (0, 1, 2, 3, 4, 5, (1 << 32) - 1):
                    yield a, h, n, op
    rng = random.Random(20261106)
    for _ in range(256):
        a = rng.randrange(LIMIT + 1)
        h = rng.randrange(LIMIT - a + 1)
        yield a, h, rng.randrange(LIMIT + 1), rng.randrange(5)


class QuotaApplicationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hia-quota-tests-")
        self.path = Path(self.temp.name) / "ledger"

    def tearDown(self):
        self.temp.cleanup()

    def test_hia_all_boundary_and_registered_random_inputs_match_independent_oracle(self):
        with HIAEngine() as engine:
            for version in ("v1", "v2"):
                for a, h, n, op in cases():
                    self.assertEqual(unpack(engine.transition(version, {"available": a, "held": h}, n, op)),
                                     reference(version, a, h, n, op), (version, a, h, n, op))

    def test_complete_reserve_consume_release_error_and_reopen(self):
        with QuotaLedger(self.path, initial=100) as ledger:
            self.assertEqual(ledger.apply("reserve-1", 1, 70)["state"], {"available": 30, "held": 70})
            self.assertEqual(ledger.apply("consume-1", 2, 40)["state"], {"available": 30, "held": 30})
            self.assertEqual(ledger.apply("release-1", 3, 30)["state"], {"available": 60, "held": 0})
            refused = ledger.apply("reserve-error", 1, 61)
            self.assertEqual((refused["status"], refused["code"]), ("rejected", 1))
            expected = ledger.snapshot()
        with QuotaLedger(self.path) as ledger:
            self.assertEqual(ledger.snapshot(), expected)
            self.assertEqual(ledger.apply("next-task", 1, 50)["state"], {"available": 10, "held": 50})

    def test_duplicate_request_retains_original_receipt_and_conflict_rejects(self):
        with QuotaLedger(self.path, initial=100) as ledger:
            first = ledger.apply("task", 1, 25)
            second = ledger.apply("task", 1, 25)
            self.assertTrue(second.pop("replayed"))
            first.pop("replayed")
            self.assertEqual(first, second)
            with self.assertRaises(QuotaRejected):
                ledger.apply("task", 1, 26)
            self.assertEqual(ledger.snapshot()["committed_records"], 2)

    def test_cancel_before_and_after_pure_hia_never_commits_computed_transition(self):
        with QuotaLedger(self.path, initial=100) as ledger:
            before = ledger.apply("before", 1, 20, cancelled=lambda: True)
            flags = iter((False, True))
            after = ledger.apply("after", 1, 40, cancelled=lambda: next(flags))
            self.assertEqual(before["status"], "cancelled")
            self.assertEqual(after["status"], "cancelled")
            self.assertEqual(ledger.snapshot()["state"], {"available": 100, "held": 0})
            self.assertEqual(ledger.apply("after", 1, 40)["status"], "cancelled")
            self.assertEqual(ledger.apply("new-task", 1, 40)["status"], "applied")

    def test_upgrade_is_durable_preserves_state_and_new_hia_behavior_runs(self):
        with QuotaLedger(self.path, initial=100) as ledger:
            self.assertEqual(ledger.apply("old-debit", 4, 10)["code"], 2)
            ledger.apply("hold", 1, 40)
            ledger.upgrade("upgrade")
            self.assertEqual(ledger.apply("new-debit", 4, 20)["state"], {"available": 40, "held": 40})
        with QuotaLedger(self.path) as ledger:
            self.assertEqual(ledger.snapshot()["version"], "v2")
            self.assertTrue(ledger.upgrade("upgrade")["replayed"])
            self.assertEqual(ledger.apply("after-restart", 4, 10)["state"], {"available": 30, "held": 40})
            with self.assertRaises(QuotaRejected):
                ledger.upgrade("downgrade", "v1")

    def test_actual_process_death_after_record_publication_reconciles_same_request_once(self):
        with QuotaLedger(self.path, initial=100):
            pass
        code = """import os,sys
from hepta.apps.quota import QuotaLedger
with QuotaLedger(sys.argv[1]) as ledger:
    ledger._sync_directory=lambda: os._exit(77)
    ledger.apply('interrupted-task',1,30)
"""
        result = subprocess.run([sys.executable, "-c", code, str(self.path)], timeout=30, capture_output=True)
        self.assertEqual(result.returncode, 77, result.stderr)
        with QuotaLedger(self.path) as ledger:
            self.assertEqual(ledger.snapshot()["state"], {"available": 70, "held": 30})
            receipt = ledger.apply("interrupted-task", 1, 30)
            self.assertTrue(receipt["replayed"])
            self.assertEqual(ledger.snapshot()["committed_records"], 2)

    def test_directory_sync_failure_retains_unknown_and_reconciles(self):
        with QuotaLedger(self.path, initial=100) as ledger:
            with patch.object(ledger, "_sync_directory", side_effect=OSError("injected directory fsync failure")):
                with self.assertRaises(CommitUnknown):
                    ledger.apply("unknown", 1, 30)
            receipt = ledger.apply("unknown", 1, 30)
            self.assertTrue(receipt["replayed"])
            self.assertEqual(receipt["state"], {"available": 70, "held": 30})

    def test_lost_link_acknowledgment_is_unknown_not_a_clean_failure(self):
        original = os.link
        def lost_ack(*args, **kwargs):
            original(*args, **kwargs)
            raise OSError("link acknowledgment lost")
        with QuotaLedger(self.path, initial=100) as ledger:
            with patch("hepta.apps.quota.os.link", side_effect=lost_ack):
                with self.assertRaises(CommitUnknown):
                    ledger.apply("unknown-link", 1, 10)
            self.assertTrue(ledger.apply("unknown-link", 1, 10)["replayed"])
            self.assertEqual(ledger.snapshot()["state"], {"available": 90, "held": 10})

    def test_postcommit_readback_failure_is_unknown_and_retry_does_not_repeat(self):
        with QuotaLedger(self.path, initial=100) as ledger:
            original = ledger._reload
            calls = 0
            def fail_readback():
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise OSError("readback unavailable after commit")
                return original()
            with patch.object(ledger, "_reload", side_effect=fail_readback):
                with self.assertRaises(CommitUnknown):
                    ledger.apply("readback", 1, 10)
            self.assertTrue(ledger.apply("readback", 1, 10)["replayed"])
            self.assertEqual(ledger.snapshot()["state"], {"available": 90, "held": 10})

    def test_postpublication_interrupt_is_unknown_and_same_request_reconciles(self):
        with QuotaLedger(self.path, initial=100) as ledger:
            with patch.object(ledger, "_sync_directory", side_effect=KeyboardInterrupt):
                with self.assertRaises(CommitUnknown):
                    ledger.apply("interrupted", 1, 10)
            self.assertTrue(ledger.apply("interrupted", 1, 10)["replayed"])
            self.assertEqual(ledger.snapshot()["state"], {"available": 90, "held": 10})

    def test_hostile_version_object_rejects_before_journal_publication(self):
        class ForgedVersion(str):
            def __ne__(self, other):
                return False
        with QuotaLedger(self.path, initial=100) as ledger:
            before = ledger.snapshot()
            with self.assertRaises(QuotaRejected):
                ledger.upgrade("bad-upgrade", ForgedVersion("v1"))
            self.assertEqual(ledger.snapshot(), before)
            self.assertEqual(ledger.upgrade("valid-upgrade")["status"], "upgraded")

    def test_wrong_well_typed_backend_result_cannot_poison_new_or_existing_journal(self):
        with HIAEngine() as engine:
            original = engine.transition
            def wrong_live_result(*args, **kwargs):
                value = original(*args, **kwargs)
                return value if kwargs.get("replay") else value ^ 1
            with patch.object(engine, "transition", side_effect=wrong_live_result):
                with self.assertRaises(QuotaRejected):
                    QuotaLedger(self.path, initial=100, engine=engine)
            self.assertEqual(list(self.path.glob("*.json")), [])
            with QuotaLedger(self.path, initial=100, engine=engine) as ledger:
                with patch.object(engine, "transition", side_effect=wrong_live_result):
                    with self.assertRaises(QuotaRejected):
                        ledger.apply("wrong-output", 1, 10)
                    with self.assertRaises(QuotaRejected):
                        ledger.upgrade("wrong-migration")
                self.assertEqual(ledger.snapshot()["committed_records"], 1)
                self.assertEqual(ledger.apply("right-output", 1, 10)["state"], {"available": 90, "held": 10})

    def test_cleanup_interrupt_after_link_is_unknown(self):
        original = os.unlink
        def interrupt_stage(path, *args, **kwargs):
            if str(path).startswith(".stage-"):
                raise KeyboardInterrupt
            return original(path, *args, **kwargs)
        with QuotaLedger(self.path, initial=100) as ledger:
            with patch("hepta.apps.quota.os.unlink", side_effect=interrupt_stage):
                with self.assertRaises(CommitUnknown):
                    ledger.apply("cleanup", 1, 10)
            self.assertTrue(ledger.apply("cleanup", 1, 10)["replayed"])
            self.assertEqual(ledger.snapshot()["state"], {"available": 90, "held": 10})

    def test_forked_handle_cannot_inherit_parent_execution_authority(self):
        with QuotaLedger(self.path, initial=100) as ledger:
            pid = os.fork()
            if pid == 0:
                try:
                    ledger.apply("forked", 1, 10)
                except QuotaRejected:
                    os._exit(0)
                except BaseException:
                    os._exit(2)
                os._exit(1)
            _, status = os.waitpid(pid, 0)
            self.assertEqual(os.waitstatus_to_exitcode(status), 0)
            self.assertEqual(ledger.snapshot()["committed_records"], 1)
            self.assertEqual(ledger.apply("parent", 1, 10)["state"], {"available": 90, "held": 10})

    def test_corrupt_committed_bytes_are_never_discarded_or_repaired(self):
        with QuotaLedger(self.path, initial=100) as ledger:
            ledger.apply("task", 1, 20)
        path = self.path / "00000001.json"
        path.chmod(0o600)
        broken = path.read_bytes().replace(b'"available":80', b'"available":81')
        path.write_bytes(broken)
        with self.assertRaises(QuotaRejected):
            QuotaLedger(self.path)
        self.assertEqual(path.read_bytes(), broken)

    def test_missing_record_and_changed_program_identity_reject(self):
        with QuotaLedger(self.path, initial=100) as ledger:
            ledger.apply("first", 1, 20)
            ledger.apply("second", 2, 10)
        missing = self.path / "00000001.json"
        original = missing.read_bytes()
        missing.unlink()
        with self.assertRaises(QuotaRejected):
            QuotaLedger(self.path)
        missing.write_bytes(original)
        with HIAEngine() as engine, patch.object(engine, "identity", return_value="0" * 64):
            with self.assertRaises(QuotaRejected):
                QuotaLedger(self.path, engine=engine)

    def test_single_owner_lock_and_thread_serialization(self):
        with QuotaLedger(self.path, initial=100) as ledger:
            with self.assertRaises(QuotaRejected):
                QuotaLedger(self.path)
            with ThreadPoolExecutor(max_workers=4) as pool:
                results = list(pool.map(lambda i: ledger.apply(f"thread-{i}", 1, 1), range(12)))
            self.assertEqual(len({row["sequence"] for row in results}), 12)
            self.assertEqual(ledger.snapshot()["state"], {"available": 88, "held": 12})

    def test_type_budget_reentrancy_symlink_and_closed_owner_rejections(self):
        with QuotaLedger(self.path, initial=100) as ledger:
            for amount in (True, 0.5, -1, 1 << 32):
                with self.assertRaises(QuotaRejected):
                    ledger.apply("invalid", 1, amount)
            with self.assertRaises(QuotaRejected):
                ledger.apply("nested", 1, 1, cancelled=lambda: ledger.snapshot())
            with patch("hepta.apps.quota.MAX_RECORDS", 1):
                with self.assertRaises(QuotaRejected):
                    ledger.apply("too-many", 1, 1)
        with self.assertRaises(QuotaRejected):
            ledger.apply("closed", 1, 1)
        alias = Path(self.temp.name) / "alias"
        alias.symlink_to(self.path, target_is_directory=True)
        with self.assertRaises(OSError):
            QuotaLedger(alias)

    def test_real_cli_restart_uses_the_same_hia_module(self):
        command = [sys.executable, "-m", "hepta.apps.quota", "--ledger", str(self.path)]
        for args, expected in ((["init", "--initial", "90"], {"available": 90, "held": 0}),
                               (["apply", "cli-task", "reserve", "35"], {"available": 55, "held": 35}),
                               (["status"], {"available": 55, "held": 35})):
            result = subprocess.run(command + args, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            self.assertEqual(json.loads(result.stdout)["state"], expected)


@unittest.skipUnless(shutil.which(CLANG), "actual Clang 20+ native toolchain required")
class QuotaNativeTests(unittest.TestCase):
    def test_real_native_versions_match_independent_oracle_and_durable_application(self):
        with HIAEngine(clang=CLANG) as engine, tempfile.TemporaryDirectory(prefix="hia-quota-native-tests-") as directory:
            for version in ("v1", "v2"):
                for a, h, n, op in cases():
                    self.assertEqual(unpack(engine.transition(version, {"available": a, "held": h}, n, op)),
                                     reference(version, a, h, n, op))
                receipt = engine.build_receipts[version]
                self.assertFalse(receipt["claims"]["rust_codegen_used"])
                self.assertFalse(receipt["claims"]["c_codegen_used"])
                self.assertFalse(receipt["claims"]["fallback_used"])
            path = Path(directory) / "ledger"
            with QuotaLedger(path, initial=100, engine=engine) as ledger:
                ledger.apply("native-hold", 1, 40)
                ledger.upgrade("native-upgrade")
                receipt = ledger.apply("native-debit", 4, 10)
                self.assertEqual(receipt["state"], {"available": 50, "held": 40})
            with QuotaLedger(path) as ledger:
                self.assertEqual(ledger.snapshot()["state"], receipt["state"])


if __name__ == "__main__":
    unittest.main()
