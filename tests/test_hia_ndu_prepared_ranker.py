"""Real Linux transport controls; fixture executables are not native NDU.

The separate frozen mechanism experiment runs the original CI NDU executable.
These tests deliberately control its wire peer to exercise identity, resource
ownership, rejection, exact charging and failure retention.
"""
from __future__ import annotations

from copy import deepcopy
import errno
import os
import signal
import subprocess
import sys
import threading
import time
import unittest
from unittest.mock import patch

from hepta import hia_ndu_prepared_ranker as prepared
from hepta.hia_ndu_optimizer import OptimizationRejected, _native_rank
from tests import test_hia_ndu_optimizer_transport as transport_fixture


@unittest.skipUnless(sys.platform == "linux", "requires actual Linux sealing and owned child cleanup")
class PreparedRankingTransportTests(unittest.TestCase):
    def setUp(self):
        self.fixture = transport_fixture.NDUOptimizerTransportTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.bridge = self.fixture.bridge
        self.request = self.fixture.request

    def owner(self, **kwargs):
        owner = prepared.PreparedNduRanker(self.bridge, **kwargs)
        self.addCleanup(owner.close)
        return owner

    def test_admission_and_sealing_once_but_every_request_executes(self):
        children = []
        real_popen = subprocess.Popen

        def capture(*args, **kwargs):
            child = real_popen(*args, **kwargs)
            children.append(child)
            return child

        outer = time.perf_counter_ns()
        with patch.object(prepared, "_bridge_identity", wraps=prepared._bridge_identity) as admit, \
                patch.object(prepared, "_seal_bridge_image", wraps=prepared._seal_bridge_image) as seal, \
                patch("subprocess.Popen", side_effect=capture):
            owner = self.owner(max_requests=2)
            descriptor = owner._fd
            first, identity = owner.rank(self.request)
            self.assertFalse(owner.receipt()["complete"])
            identity["binary_sha256"] = "0" * 64
            second, second_identity = owner.rank(self.request)
            owner.close()
            owner.close()
        outer = time.perf_counter_ns() - outer
        self.assertEqual(admit.call_count, 1)
        self.assertEqual(seal.call_count, 1)
        self.assertEqual(first, second)
        self.assertNotEqual(second_identity["binary_sha256"], identity["binary_sha256"])
        self.assertEqual(second_identity["transport_profile"], prepared.PROFILE)
        self.assertEqual(len(children), 2)
        self.assertNotEqual(children[0].pid, children[1].pid)
        for child in children:
            self.assertEqual(child.returncode, 0)
            with self.assertRaises(ChildProcessError):
                os.waitpid(child.pid, os.WNOHANG)
        with self.assertRaises(OSError) as closed:
            os.fstat(descriptor)
        self.assertEqual(closed.exception.errno, errno.EBADF)
        receipt = owner.receipt()
        self.assertTrue(receipt["complete"])
        self.assertTrue(receipt["all_native_cleanup_confirmed"])
        self.assertEqual(receipt["original_native_calls"], 2)
        self.assertEqual(receipt["result_cache_hits"], 0)
        self.assertFalse(receipt["native_process_reuse"])
        self.assertFalse(receipt["whole_lifecycle_cost_complete"])
        self.assertFalse(receipt["economic_benefit_established"])
        self.assertFalse(receipt["safety_certificate"])
        total = (receipt["preparation"]["preparation_wall_ns"] + receipt["close_wall_ns"]
                 + sum(row["wall_ns"] for row in receipt["attempts"]))
        self.assertEqual(total, receipt["observed_disjoint_wall_ns"])
        self.assertGreater(total, 0)
        self.assertLess(total, outer)
        for row in receipt["attempts"]:
            self.assertEqual(row["caller_wall_ns"], row["queue_wait_ns"] + row["wall_ns"])
        receipt["attempts"][0]["status"] = "forged"
        self.assertEqual(owner.receipt()["attempts"][0]["status"], "completed")

    def test_explicit_snapshot_is_unchanged_after_origin_paths_are_replaced(self):
        owner = self.owner()
        self.fixture.binary.write_bytes(self.fixture.image_bytes("replacement"))
        self.fixture.receipt.write_bytes(b"unadmitted later receipt")
        response, identity = owner.rank(self.request)
        self.assertEqual(self.fixture.marker.read_text(), "admitted")
        self.assertEqual(response["advisory_recommendation"], "abstain")
        self.assertEqual(identity["transport_profile"], prepared.PROFILE)
        self.assertFalse(owner.receipt()["preparation"]["origin_path_reopened_for_calls"])
        # The old pathname-bound API retains its stricter per-call contract.
        with patch("subprocess.Popen") as spawn:
            with self.assertRaises(OptimizationRejected):
                _native_rank(self.bridge, self.request, timeout_s=1)
            spawn.assert_not_called()

    def test_each_response_binds_actual_frozen_request_and_is_not_cached(self):
        owner = self.owner()
        owner.rank(self.request)
        changed = deepcopy(self.request)
        changed["objective_sha256"] = "9" * 64
        with patch("subprocess.Popen", wraps=subprocess.Popen) as spawn:
            with self.assertRaisesRegex(OptimizationRejected, "exact request"):
                owner.rank(changed)
            self.assertEqual(spawn.call_count, 1)
        receipt = owner.receipt()
        self.assertEqual(receipt["original_native_calls"], 2)
        self.assertEqual([row["status"] for row in receipt["attempts"]], ["completed", "rejected"])
        self.assertNotEqual(receipt["attempts"][0]["request_sha256"], receipt["attempts"][1]["request_sha256"])
        self.assertTrue(receipt["closed"])
        self.assertGreater(receipt["attempts"][1]["wall_ns"], 0)

    def test_caller_mutation_cannot_rebind_submitted_request(self):
        owner = self.owner()
        original = deepcopy(self.request)
        real_popen = subprocess.Popen

        def mutate_then_spawn(*args, **kwargs):
            self.request["objective_sha256"] = "9" * 64
            return real_popen(*args, **kwargs)

        with patch("subprocess.Popen", side_effect=mutate_then_spawn):
            response, _ = owner.rank(self.request)
        self.assertEqual(response["objective_sha256"], original["objective_sha256"])
        self.assertNotEqual(response["objective_sha256"], self.request["objective_sha256"])

    def test_missing_seal_readback_refuses_before_process_start(self):
        import fcntl
        owner = self.owner()
        real_fcntl = fcntl.fcntl

        def missing_seal(fd, operation, *args):
            if operation == getattr(fcntl, "F_GET_SEALS", 1034):
                return 7
            return real_fcntl(fd, operation, *args)

        with patch("fcntl.fcntl", side_effect=missing_seal), patch("subprocess.Popen") as spawn:
            with self.assertRaisesRegex(OptimizationRejected, "mandatory seals"):
                owner.rank(self.request)
            spawn.assert_not_called()
        receipt = owner.receipt()
        self.assertTrue(receipt["closed"])
        self.assertEqual(receipt["original_native_calls"], 0)
        self.assertEqual(receipt["attempts"][0]["status"], "rejected")
        self.assertGreater(receipt["attempts"][0]["wall_ns"], 0)

    def test_reused_numeric_descriptor_is_never_closed_as_owned(self):
        owner = self.owner()
        descriptor = owner._fd
        os.close(descriptor)
        replacement = os.open("/dev/null", os.O_RDONLY)
        if replacement != descriptor:
            os.dup2(replacement, descriptor)
            os.close(replacement)
        self.addCleanup(os.close, descriptor)
        with patch("subprocess.Popen") as spawn:
            with self.assertRaisesRegex(OptimizationRejected, "ownership changed"):
                owner.rank(self.request)
            spawn.assert_not_called()
        os.fstat(descriptor)  # The unrelated reused descriptor remains open.
        receipt = owner.receipt()
        self.assertFalse(receipt["complete"])
        self.assertFalse(receipt["close_confirmed"])
        self.assertIsNotNone(receipt["close_error"])

    def test_native_failure_is_retained_with_cleanup_and_no_automatic_retry(self):
        self.fixture.write_fixture(action="raise SystemExit(7)")
        owner = self.owner()
        with patch("subprocess.Popen", wraps=subprocess.Popen) as spawn:
            with self.assertRaisesRegex(OptimizationRejected, "native evaluator failed"):
                owner.rank(self.request)
            with self.assertRaisesRegex(OptimizationRejected, "closed"):
                owner.rank(self.request)
            self.assertEqual(spawn.call_count, 1)
        receipt = owner.receipt()
        self.assertEqual(receipt["attempts"][0]["status"], "rejected")
        self.assertTrue(receipt["attempts"][0]["cleanup_confirmed"])
        self.assertGreater(receipt["attempts"][0]["wall_ns"], 0)
        self.assertTrue(receipt["complete"])

    def test_timeout_kills_and_reaps_actual_native_child(self):
        self.fixture.write_fixture(action="time.sleep(30)")
        owner = self.owner()
        children = []
        real_popen = subprocess.Popen

        def capture(*args, **kwargs):
            child = real_popen(*args, **kwargs)
            children.append(child)
            return child

        with patch("subprocess.Popen", side_effect=capture):
            with self.assertRaisesRegex(OptimizationRejected, "deadline"):
                owner.rank(self.request, timeout_s=0.15)
        self.assertEqual(len(children), 1)
        self.assertEqual(children[0].returncode, -signal.SIGKILL)
        with self.assertRaises(ChildProcessError):
            os.waitpid(children[0].pid, os.WNOHANG)
        self.assertTrue(owner.receipt()["all_native_cleanup_confirmed"])
        self.assertEqual(owner.receipt()["attempts"][0]["status"], "rejected")

    def test_output_overflow_retains_actual_prefix_and_failure_cost(self):
        self.fixture.write_fixture(action="os.write(1, b'x' * (1024 * 1024 + 8192)); time.sleep(30)")
        owner = self.owner()
        observations = []
        with self.assertRaisesRegex(OptimizationRejected, "output budget"):
            owner.rank(self.request, timeout_s=1, observer=observations.append)
        self.assertEqual(len(observations), 1)
        pump = observations[0]["pump"]
        self.assertTrue(pump["cleanup_confirmed"])
        self.assertFalse(pump["streams_complete"])
        self.assertGreater(len(pump["stdout"]), prepared.MAX_WIRE_BYTES)
        self.assertLessEqual(len(pump["stdout"]), prepared.MAX_WIRE_BYTES + 4096)
        self.assertFalse(observations[0]["response_admitted"])
        self.assertEqual(owner.receipt()["attempts"][0]["stdout_bytes"], len(pump["stdout"]))

    def test_request_allowance_and_closed_owner_cannot_launch_more_processes(self):
        owner = self.owner(max_requests=1)
        owner.rank(self.request)
        with patch("subprocess.Popen") as spawn:
            with self.assertRaisesRegex(OptimizationRejected, "allowance exhausted"):
                owner.rank(self.request)
            with self.assertRaisesRegex(OptimizationRejected, "closed"):
                owner.rank(self.request)
            spawn.assert_not_called()
        self.assertTrue(owner.receipt()["closed"])
        self.assertEqual(owner.receipt()["original_native_calls"], 1)

    def test_request_byte_limit_and_elapsed_timeout_refuse_before_spawn(self):
        owner = self.owner()
        with patch("subprocess.Popen") as spawn:
            with self.assertRaisesRegex(OptimizationRejected, "byte limit"):
                owner.rank({"padding": "x" * prepared.MAX_WIRE_BYTES})
            spawn.assert_not_called()
        owner = self.owner()
        with patch.object(prepared.time, "perf_counter_ns", side_effect=[0, 1, 20_000_000, 21_000_000, 22_000_000, 23_000_000]), \
                patch("subprocess.Popen") as spawn:
            with self.assertRaisesRegex(OptimizationRejected, "budget exhausted"):
                owner.rank(self.request, timeout_s=0.01)
            spawn.assert_not_called()
        receipt = owner.receipt()
        self.assertEqual(receipt["attempts"][0]["wall_ns"], 20_999_999)
        self.assertEqual(receipt["attempts"][0]["queue_wait_ns"], 1)
        self.assertEqual(receipt["close_wall_ns"], 1_000_000)

    def test_serialized_call_queue_is_not_charged_twice(self):
        owner = self.owner(max_requests=2)
        observer_entered, release = threading.Event(), threading.Event()
        errors = []

        def first_observer(_value):
            observer_entered.set()
            if not release.wait(2):
                raise AssertionError("test handoff timed out")

        def run(observer=None):
            try:
                owner.rank(self.request, observer=observer)
            except BaseException as error:
                errors.append(error)

        first = threading.Thread(target=run, args=(first_observer,))
        second = threading.Thread(target=run)
        first.start()
        self.assertTrue(observer_entered.wait(2))
        second.start()
        time.sleep(0.02)
        release.set()
        first.join(2)
        second.join(2)
        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertEqual(errors, [])
        owner.close()
        receipt = owner.receipt()
        self.assertGreater(receipt["attempts"][1]["queue_wait_ns"], 0)
        self.assertEqual(receipt["observed_disjoint_wall_ns"],
                         receipt["preparation"]["preparation_wall_ns"] + receipt["close_wall_ns"]
                         + sum(row["wall_ns"] for row in receipt["attempts"]))

    def test_reentrant_observer_cannot_hide_a_nested_attempt_or_close(self):
        for action in ("rank", "close"):
            with self.subTest(action=action):
                owner = self.owner()

                def observer(_value):
                    owner.rank(self.request) if action == "rank" else owner.close()

                with patch("subprocess.Popen", wraps=subprocess.Popen) as spawn:
                    with self.assertRaisesRegex(OptimizationRejected, "reentrant|active"):
                        owner.rank(self.request, observer=observer)
                    self.assertEqual(spawn.call_count, 1)
                self.assertTrue(owner.receipt()["closed"])
                self.assertEqual(len(owner.receipt()["attempts"]), 1)
                self.assertEqual(owner.receipt()["attempts"][0]["status"], "rejected")

    def test_context_entry_failure_retires_the_admitted_descriptor(self):
        owner = self.owner()
        descriptor = owner._fd
        with patch("fcntl.fcntl", side_effect=OSError(errno.EIO, "readback unavailable")):
            with self.assertRaisesRegex(OptimizationRejected, "sealed descriptor unavailable"):
                with owner:
                    self.fail("failed entry admitted the body")
        with self.assertRaises(OSError) as closed:
            os.fstat(descriptor)
        self.assertEqual(closed.exception.errno, errno.EBADF)
        self.assertTrue(owner.receipt()["closed"])
        self.assertTrue(owner.receipt()["close_confirmed"])
        self.assertEqual(owner.receipt()["original_native_calls"], 0)

    def test_invalid_allowances_and_unadmitted_binary_refuse(self):
        for value in (0, True, 257, 1.5):
            with self.subTest(value=value), self.assertRaises(OptimizationRejected):
                self.owner(max_requests=value)
        self.fixture.binary.write_bytes(b"wrong bytes")
        with patch("subprocess.Popen") as spawn, self.assertRaisesRegex(OptimizationRejected, "recorded build"):
            self.owner()
        spawn.assert_not_called()


if __name__ == "__main__":
    unittest.main()
