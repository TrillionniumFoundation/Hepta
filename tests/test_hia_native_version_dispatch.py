"""Real compiled Core images across background-build and child-call lifetimes."""
from __future__ import annotations

import errno
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import tempfile
from threading import Event, Thread, current_thread
import unittest
from unittest import mock

import hepta.hia_native_differential as native
import hepta.hia_native_version_dispatch as dispatch
from hepta.hia_program import verify_program
from hepta.hia_program_runtime import execute_program
from hepta.hia_swap_opt import rewrite_byte_swap
from tests.test_hia_program import arithmetic, b, f, i, jump, m, ret
from tests.test_hia_swap_opt import source_program

CLANG = shutil.which("clang-20")


def programs():
    document = source_program()
    names = ("length", "left", "right", "probe")
    params = [(name, "u32") for name in names]
    operations = [i("int.cast", [name], [(name + "64", "usize")], mode="checked") for name in names]
    operations += [i("call", [name + "64" for name in names], [("byte", "u8")],
                     function="swap_candidate"),
                   i("int.cast", ["byte"], [("answer", "u32")], mode="checked")]
    document["functions"].append(f("native_swap", params, ["u32"],
        ["alloc", "read", "write", "trap"], [b("entry", params, operations, ret("answer"))]))
    document["exports"] = ["native_swap"]
    baseline = verify_program(document)
    return baseline, rewrite_byte_swap(baseline).program


@unittest.skipUnless(platform.system() == "Linux" and platform.machine().lower() in {"x86_64", "amd64"}
                     and CLANG and hasattr(os, "memfd_create"), "requires Linux x86-64, sealed memfd and Clang 20")
class NativeVersionDispatchTests(unittest.TestCase):
    def host(self, *, baseline=None, **kwargs):
        baseline = programs()[0] if baseline is None else baseline
        host = dispatch.NativeVersionDispatcher(baseline.canonical_bytes, clang=CLANG, **kwargs)
        self.addCleanup(host.close)
        return host

    def stage(self, host, candidate=None):
        candidate = programs()[1] if candidate is None else candidate
        queued = host.stage_candidate_async(candidate.canonical_bytes)
        done = host.wait_candidate(queued["job_id"], timeout=20)
        self.assertEqual(done["status"], "staged", done)
        return done

    def assert_descriptor_closed(self, fd):
        with self.assertRaises(OSError) as raised:
            os.fstat(fd)
        self.assertEqual(raised.exception.errno, errno.EBADF)

    def test_real_background_compile_native_results_traps_cas_and_no_change(self):
        baseline, candidate = programs()
        with self.host() as host:
            no_change = self.stage(host, baseline)
            self.assertTrue(no_change["already_staged"])
            self.assertFalse(no_change["build_attempt_started"])
            self.assertFalse(host.activate(baseline.sha256, expected_generation=0)["changed"])
            staged = self.stage(host)
            self.assertTrue(staged["native_artifact_built"])
            self.assertTrue(staged["build_attempt_started"])
            self.assertFalse(staged["activated"])
            self.assertEqual(staged["native_receipt"]["core_sha256"], candidate.sha256)
            self.assertEqual(host.snapshot()["active_sha256"], baseline.sha256)
            host.activate(candidate.sha256, expected_generation=0)
            for args in ([5, 0, 4, 0], [5, 4, 0, 4], [5, 2, 2, 2], [7, 1, 3, 3]):
                expected = execute_program(candidate, "native_swap", args)["result"]
                observed = host.execute("native_swap", args)
                self.assertEqual(observed["status"], "returned")
                self.assertEqual(observed["value"], expected)
                self.assertEqual(observed["program_sha256"], candidate.sha256)
                self.assertTrue(observed["claims"]["actual_native_child_executed"])
            # The last request cannot allocate a 4 GiB owner under the
            # existing worker's 512 MiB address-space cap. A silent SIGABRT
            # is recorded as a native trap, not as a proven trap cause.
            for args in ([4, 0, 3, 0], [5, 5, 0, 0], [5, 0, 5, 0], [5, 0, 4, 5],
                         [2**32 - 1, 0, 4, 0]):
                self.assertEqual(host.execute("native_swap", args)["status"], "trapped")
                self.assertEqual(host.snapshot()["in_flight"], 0)
            for generation in (0, True, -1, "1"):
                with self.assertRaisesRegex(dispatch.HIANativeDispatchRejected, "generation"):
                    host.rollback(expected_generation=generation)
            self.assertEqual(host.rollback(expected_generation=1)["generation"], 2)
            self.assertEqual(host.snapshot()["retired_versions"], 1)
            with self.assertRaisesRegex(dispatch.HIANativeDispatchRejected, "retired"):
                host.activate(candidate.sha256, expected_generation=2)
            self.assertEqual(host.execute("native_swap", [5, 0, 4, 0])["value"], 55)
        self.assertTrue(host.snapshot()["drained"])
        self.assertEqual(host.snapshot()["released_artifacts"], 2)

    def test_wrong_core_unsupported_abi_and_exact_arguments_reject(self):
        baseline, candidate = programs()
        with self.host() as host:
            wrong = candidate.as_dict()
            next(op for op in wrong["functions"][0]["blocks"][0]["ops"]
                 if op["op"] == "const" and op["out"][0]["name"] == "byte4")["attrs"]["value"] = 99
            wrong = verify_program(wrong)
            with self.assertRaisesRegex(dispatch.HIANativeDispatchRejected, "exact reproduced"):
                host.stage_candidate_async(wrong.canonical_bytes)
            for function, arguments in (("swap_candidate", [5, 0, 4, 0]), ("native_swap", [5, 0, 4]),
                                        ("native_swap", [True, 0, 4, 0]), ("native_swap", [-1, 0, 4, 0]),
                                        ("native_swap", [2**32, 0, 4, 0])):
                with self.assertRaises(dispatch.HIANativeDispatchRejected):
                    host.execute(function, arguments)
                self.assertEqual(host.snapshot()["in_flight"], 0)
            for bad in (True, -1, float("nan"), float("inf"), 11):
                with self.assertRaises(dispatch.HIANativeDispatchRejected):
                    host.execute("native_swap", [5, 0, 4, 0], timeout=bad)
        raw = verify_program(source_program())
        with self.assertRaisesRegex(dispatch.HIANativeDispatchRejected, "homogeneous"):
            dispatch.NativeVersionDispatcher(raw.canonical_bytes, clang=CLANG)
        for payload in (baseline, baseline.as_dict(), bytearray(baseline.canonical_bytes)):
            with self.assertRaisesRegex(dispatch.HIANativeDispatchRejected, "immutable"):
                dispatch.NativeVersionDispatcher(payload, clang=CLANG)
        version7 = baseline.as_dict()
        version7["schema"] = "hepta.hia.program.v7"
        with self.assertRaisesRegex(dispatch.HIANativeDispatchRejected, "v1-v6"):
            dispatch.NativeVersionDispatcher(verify_program(version7).canonical_bytes, clang=CLANG)

    def _hold_actual_child(self, host):
        """Suspend an actual spawned child by PID FD; never substitute a result."""
        entered = Event()
        outcome = {}
        pidfds = []
        original = native.subprocess.Popen

        def spawn(*args, **kwargs):
            process = original(*args, **kwargs)
            if current_thread().name == "held-native-version-call":
                fd = os.pidfd_open(process.pid)
                pidfds.append(fd)
                signal.pidfd_send_signal(fd, signal.SIGSTOP)
                entered.set()
            return process

        def work():
            try:
                outcome["result"] = host.execute("native_swap", [5, 0, 4, 0], timeout=8)
            except BaseException as error:
                outcome["error"] = error

        patcher = mock.patch.object(native.subprocess, "Popen", side_effect=spawn)
        patcher.start()
        thread = Thread(target=work, name="held-native-version-call", daemon=True)
        thread.start()

        def release():
            for fd in pidfds:
                try:
                    signal.pidfd_send_signal(fd, signal.SIGCONT)
                except ProcessLookupError:
                    pass
                finally:
                    os.close(fd)
            pidfds.clear()
            thread.join(10)
            patcher.stop()

        self.addCleanup(release)
        self.assertTrue(entered.wait(5), "actual native child did not start")
        self.assertEqual(host.snapshot()["in_flight"], 1)
        return thread, outcome, release

    def test_old_actual_child_remains_pinned_across_activation_and_rollback(self):
        baseline, candidate = programs()
        with self.host() as host:
            self.stage(host)
            # An actual baseline child spans the transition to candidate.
            thread, result, release = self._hold_actual_child(host)
            try:
                host.activate(candidate.sha256, expected_generation=0)
                current = host.execute("native_swap", [5, 0, 4, 0])
                self.assertEqual(current["generation"], 1)
                self.assertEqual(current["program_sha256"], candidate.sha256)
                old = next(v for v in host.snapshot()["versions"] if v["sha256"] == baseline.sha256)
                self.assertEqual(old["in_flight"], 1)
            finally:
                release()
            self.assertFalse(thread.is_alive())
            self.assertNotIn("error", result)
            self.assertEqual(result["result"]["generation"], 0)
            self.assertEqual(result["result"]["program_sha256"], baseline.sha256)
            self.assertEqual(result["result"]["value"], 55)
            # A distinct actual candidate child spans rollback and retirement.
            held_fd = host._versions[candidate.sha256].descriptor
            thread, result, release = self._hold_actual_child(host)
            try:
                host.rollback(expected_generation=1)
                old = next(v for v in host.snapshot()["versions"] if v["sha256"] == candidate.sha256)
                self.assertEqual(old["state"], "draining")
                self.assertEqual(old["in_flight"], 1)
                self.assertEqual(host.snapshot()["retired_versions"], 0)
                self.assertGreater(os.fstat(held_fd).st_size, 0)
                current = host.execute("native_swap", [5, 0, 4, 0])
                self.assertEqual(current["generation"], 2)
                self.assertEqual(current["program_sha256"], baseline.sha256)
            finally:
                release()
            self.assertFalse(thread.is_alive())
            self.assertNotIn("error", result)
            self.assertEqual(result["result"]["generation"], 1)
            self.assertEqual(result["result"]["program_sha256"], candidate.sha256)
            self.assertEqual(result["result"]["value"], 55)
            self.assert_descriptor_closed(held_fd)
            self.assertEqual(host.snapshot()["retired_versions"], 1)

    def test_close_and_concurrent_budget_keep_an_admitted_native_child_alive(self):
        _, candidate = programs()
        with self.host(max_in_flight=1) as host:
            self.stage(host)
            host.activate(candidate.sha256, expected_generation=0)
            fd = host._versions[candidate.sha256].descriptor
            thread, result, release = self._hold_actual_child(host)
            try:
                with self.assertRaisesRegex(dispatch.HIANativeDispatchRejected, "call budget"):
                    host.execute("native_swap", [5, 0, 4, 0])
                closed = host.close(wait=False)
                self.assertEqual(closed["status"], "closing")
                self.assertFalse(closed["drained"])
                self.assertGreater(os.fstat(fd).st_size, 0)
                for operation in (lambda: host.execute("native_swap", [5, 0, 4, 0]),
                                  lambda: host.activate(candidate.sha256, expected_generation=1),
                                  lambda: host.stage_candidate_async(candidate.canonical_bytes)):
                    with self.assertRaisesRegex(dispatch.HIANativeDispatchRejected, "closed"):
                        operation()
            finally:
                release()
            self.assertNotIn("error", result)
            self.assertEqual(result["result"]["value"], 55)
            self.assertTrue(host.close(timeout=1)["drained"])
            self.assert_descriptor_closed(fd)

    def _hold_real_build(self, host):
        entered, release = Event(), Event()
        original = dispatch._build_version
        artifacts = []

        def build(*args):
            entered.set()
            if not release.wait(10):
                raise AssertionError("test did not release the real compiler")
            version = original(*args)
            artifacts.append(version)
            return version

        patcher = mock.patch.object(dispatch, "_build_version", side_effect=build)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(release.set)
        queued = host.stage_candidate_async(programs()[1].canonical_bytes)
        self.assertTrue(entered.wait(5))
        return queued["job_id"], release, artifacts

    def test_cancel_in_progress_build_discards_real_compiled_image_and_can_retry(self):
        _, candidate = programs()
        with self.host() as host:
            job_id, release, artifacts = self._hold_real_build(host)
            with self.assertRaisesRegex(dispatch.HIANativeDispatchRejected, "background compilation"):
                host.stage_candidate_async(candidate.canonical_bytes)
            self.assertEqual(host.wait_candidate(job_id, timeout=0)["status"], "compiling")
            cancelled = host.cancel_candidate(job_id)
            self.assertTrue(cancelled["cancel_requested"])
            self.assertFalse(cancelled["compiler_preempted"])
            release.set()
            done = host.wait_candidate(job_id, timeout=20)
            self.assertEqual(done["status"], "cancelled", done)
            self.assertTrue(done["native_artifact_built"])
            self.assertFalse(done["published"])
            self.assertEqual(host.snapshot()["generation"], 0)
            self.assertEqual(len(host.snapshot()["versions"]), 1)
            self.assertEqual(host.snapshot()["discarded_build_artifacts"], 1)
            self.assertEqual(len(artifacts), 1)
            self.assert_descriptor_closed(artifacts[0].descriptor)
            self.assertEqual(host.execute("native_swap", [5, 0, 4, 0])["value"], 55)
            self.stage(host)
            host.activate(candidate.sha256, expected_generation=0)
            self.assertEqual(host.execute("native_swap", [5, 0, 4, 0])["value"], 55)

    def test_close_during_real_build_withdraws_publication_and_releases_all_images(self):
        host = self.host()
        job_id, release, artifacts = self._hold_real_build(host)
        closed = host.close(wait=False)
        self.assertFalse(closed["drained"])
        self.assertTrue(host.snapshot()["build_job"]["cancel_requested"])
        release.set()
        done = host.wait_candidate(job_id, timeout=20)
        self.assertEqual(done["status"], "cancelled", done)
        self.assertTrue(done["native_artifact_built"])
        self.assertFalse(done["published"])
        self.assertTrue(host.close(timeout=2)["drained"])
        self.assertEqual(len(artifacts), 1)
        self.assert_descriptor_closed(artifacts[0].descriptor)
        self.assertEqual(host.snapshot()["versions"], [])

    def test_real_compiler_failure_keeps_the_previous_native_entry_available(self):
        baseline, candidate = programs()
        with tempfile.TemporaryDirectory(prefix="hia-dispatch-compiler-control-") as work:
            directory = Path(work)
            marker, compiler = directory / "reject-next-build", directory / "clang-control"
            compiler.write_text("#!/usr/bin/python3\nimport os,sys\nfrom pathlib import Path\n"
                + "real=" + repr(CLANG) + "\nmarker=" + repr(str(marker)) + "\n"
                + "if Path(marker).exists() and '--version' not in sys.argv and '-dumpmachine' not in sys.argv:\n"
                + " sys.stderr.write('controlled native compiler failure\\n');sys.exit(42)\n"
                + "os.execv(real,[real,*sys.argv[1:]])\n")
            compiler.chmod(0o700)
            with dispatch.NativeVersionDispatcher(baseline.canonical_bytes, clang=str(compiler)) as host:
                marker.write_text("fail subsequent compiler command\n")
                queued = host.stage_candidate_async(candidate.canonical_bytes)
                done = host.wait_candidate(queued["job_id"], timeout=20)
                self.assertEqual(done["status"], "failed", done)
                self.assertTrue(done["build_attempt_started"])
                self.assertFalse(done["published"])
                self.assertIn("controlled native compiler failure", done["diagnostic"]["message"])
                self.assertEqual(host.snapshot()["active_sha256"], baseline.sha256)
                self.assertEqual(host.snapshot()["generation"], 0)
                self.assertEqual(host.execute("native_swap", [5, 0, 4, 0])["value"], 55)
                with self.assertRaisesRegex(dispatch.HIANativeDispatchRejected, "not compiled"):
                    host.activate(candidate.sha256, expected_generation=0)

    def test_actual_native_timeout_releases_pin_and_preserves_close(self):
        infinite = verify_program(m(f("forever", [("x", "u32")], ["u32"], [], [
            b("entry", [("x", "u32")], [], jump("loop", "x")),
            b("loop", [("state", "u32")], [], jump("loop", "state"))])))
        with self.host(baseline=infinite) as host:
            with self.assertRaisesRegex(native.HIADifferentialRejected, "timed out"):
                host.execute("forever", [1], timeout=1)
            self.assertEqual(host.snapshot()["in_flight"], 0)
            self.assertTrue(host.close(timeout=1)["drained"])

    def test_signed_checked_native_trap_and_detached_build_receipts(self):
        baseline = verify_program(arithmetic())
        with self.host(baseline=baseline) as host:
            self.assertEqual(host.execute("calculate", [-7, 3])["value"], -4)
            self.assertEqual(host.execute("calculate", [2**31 - 1, 1])["status"], "trapped")
            done = self.stage(host, baseline)
            done["candidate_sha256"] = "0" * 64
            snapshot = host.snapshot()
            snapshot["build_job"]["status"] = "failed"
            self.assertEqual(host.snapshot()["build_job"]["status"], "staged")
            self.assertEqual(host.snapshot()["build_job"]["candidate_sha256"], baseline.sha256)
            for value in (True, -1, float("nan"), float("inf"), 61):
                with self.assertRaises(dispatch.HIANativeDispatchRejected):
                    host.wait_candidate(1, timeout=value)
            with self.assertRaisesRegex(dispatch.HIANativeDispatchRejected, "unknown"):
                host.cancel_candidate(True)


if __name__ == "__main__":
    unittest.main()
