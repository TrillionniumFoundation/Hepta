"""Real owner/image release uncertainty, fd reuse and independent profiles."""
from __future__ import annotations

import _ctypes
import errno
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_adaptive import AdaptiveRejected, AdaptiveRuntime, _profile
from hepta.hia_stateful import OwnedAdaptiveRuntime
from tests.test_hia_adaptive import CLANG, NATIVE
from tools.qualify_hia_adaptive import programs as scalar_programs
from tools.qualify_hia_stateful import programs as owner_programs


class AdapterProfileIsolationTests(unittest.TestCase):
    def test_actual_v8_returned_loans_do_not_enter_scalar_or_owner_adapters(self):
        from hepta.hia_program import verify_program
        from tests.test_hia_returned_loans import returned_program
        adapter = object.__new__(OwnedAdaptiveRuntime)
        for mutable in (False, True):
            document = verify_program(returned_program(mutable=mutable))
            for admit in (_profile, adapter._admit_profile):
                with self.subTest(mutable=mutable, admit=admit.__qualname__):
                    with self.assertRaises(AdaptiveRejected):
                        admit(document)


@unittest.skipUnless(NATIVE, "qualified Linux sealing, Clang and Z3 required")
class AdapterReleaseTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="hia-adapter-retirement-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def scalar(self, name="scalar"):
        runtime = AdaptiveRuntime(scalar_programs()[0], self.root / name, clang=CLANG)
        self.addCleanup(runtime.close)
        return runtime

    def owner(self, name="owner"):
        runtime = OwnedAdaptiveRuntime(owner_programs()[0], self.root / name, [11, 17], clang=CLANG)
        self.addCleanup(runtime.close)
        return runtime

    def reuse(self, descriptor, real_close):
        marker = self.root / ("marker-" + str(descriptor))
        marker.write_bytes(b"unrelated marker remains owned by the test")
        opened = os.open(marker, os.O_RDONLY)
        if opened != descriptor:
            os.dup2(opened, descriptor, inheritable=False)
            real_close(opened)
        return descriptor

    def test_partial_image_close_never_replays_prior_release_or_reused_fd(self):
        runtime = self.scalar()
        token = runtime.prepare(scalar_programs()[1])
        descriptor = runtime._images[token].fd
        first = runtime._images["baseline"]
        first_descriptor = first.fd
        real_close, real_unload = os.close, _ctypes.dlclose
        reused = []

        def close_then_reuse(fd):
            real_close(fd)
            if fd == descriptor:
                reused.append(self.reuse(fd, real_close))
                raise OSError(errno.EINTR, "controlled error after actual close and fd reuse")

        try:
            with patch("hepta.hia_adaptive.os.close", close_then_reuse), \
                 patch("_ctypes.dlclose", wraps=real_unload) as unload:
                runtime.close()
                self.assertEqual(unload.call_count, 2)
            self.assertIsNone(first.function)
            with self.assertRaises(OSError):
                os.fstat(first_descriptor)
            state = runtime.snapshot()["cleanup"]
            self.assertEqual(state["pending_resource_count"], 1)
            self.assertFalse(state["owned_native_release_complete"])
            self.assertEqual(state["pending"][0]["native"]["library"]["status"], "closed")
            self.assertEqual(state["pending"][0]["native"]["fd"]["status"], "unknown")
            with patch("hepta.hia_adaptive.os.close") as close, patch("_ctypes.dlclose") as unload:
                runtime.close()
                runtime.snapshot()
                close.assert_not_called()
                unload.assert_not_called()
            self.assertEqual(reused, [descriptor])
            self.assertEqual(os.pread(descriptor, 9, 0), b"unrelated")
        finally:
            if reused:
                real_close(descriptor)

    def test_loader_failure_still_closes_image_fd_and_never_retries_handle(self):
        runtime = self.scalar()
        image = runtime._images["baseline"]
        handle, descriptor = image.library._handle, image.fd
        real_unload = _ctypes.dlclose
        try:
            with patch("_ctypes.dlclose", side_effect=OSError(errno.EIO, "controlled pre-unload error")) as unload:
                runtime.close()
                runtime.close()
                self.assertEqual(unload.call_count, 1)
            with self.assertRaises(OSError):
                os.fstat(descriptor)
            state = runtime.snapshot()["cleanup"]
            self.assertEqual(state["pending"][0]["native"]["library"]["status"], "unknown")
            self.assertEqual(state["pending"][0]["native"]["fd"]["status"], "closed")
            self.assertFalse(state["native_release_failures_are_retried"])
        finally:
            # Only the test knows its injection ran before the real unload.
            real_unload(handle)

    def test_failed_admission_unknown_release_consumes_image_capacity(self):
        import hepta.hia_adaptive as adaptive
        from hepta.native_mapping_identity import NativeMappingRejected
        runtime = self.scalar()
        real_pin, real_close = adaptive._pin_native_artifact, os.close
        descriptors = []

        def pin(path):
            result = real_pin(path)
            descriptors.append(result[2])
            return result

        def uncertain_close(fd):
            real_close(fd)
            if descriptors and fd == descriptors[-1]:
                raise OSError(errno.EINTR, "controlled post-close unknown outcome")

        with patch.object(adaptive, "_MAX_IMAGES", 2):
            with patch.object(adaptive, "_pin_native_artifact", pin), \
                 patch.object(adaptive, "verify_loaded_symbols", side_effect=NativeMappingRejected("controlled mapping refusal")), \
                 patch("hepta.hia_adaptive.os.close", uncertain_close):
                with self.assertRaisesRegex(AdaptiveRejected, "E_ADAPT_MAPPING"):
                    runtime.prepare(scalar_programs()[1])
            self.assertEqual(len(descriptors), 1)
            cleanup = runtime.snapshot()["cleanup"]
            self.assertEqual(cleanup["pending_resource_count"], 1)
            pending_token = cleanup["pending"][0]["token"]
            with patch.object(adaptive, "_MAX_IMAGES", 3), \
                 patch.object(adaptive.secrets, "token_hex", return_value=pending_token), \
                 patch.object(adaptive, "build_optimized_native") as build:
                with self.assertRaisesRegex(AdaptiveRejected, "E_ADAPT_TOKEN"):
                    runtime.prepare(scalar_programs()[1])
                build.assert_not_called()
            self.assertEqual(runtime.snapshot()["cleanup"], cleanup)
            self.assertEqual(runtime.snapshot()["preparing"], 0)
            with patch.object(adaptive, "build_optimized_native") as build:
                with self.assertRaisesRegex(AdaptiveRejected, "E_ADAPT_BUDGET"):
                    runtime.prepare(scalar_programs()[1])
                build.assert_not_called()
        self.assertEqual(runtime.call(7, 2), 9)

    def test_owner_driver_post_close_error_never_calls_unloaded_ledger_or_fd(self):
        runtime = self.owner()
        descriptor = runtime._driver_fd
        real_close = os.close
        reused = []

        def close_then_reuse(fd):
            real_close(fd)
            if fd == descriptor:
                reused.append(self.reuse(fd, real_close))
                raise OSError(errno.EINTR, "controlled owner-driver fd reuse after close")

        try:
            with patch("hepta.hia_adaptive.os.close", close_then_reuse):
                runtime.close()
            self.assertIsNone(runtime._driver)
            self.assertIsNone(runtime._state)
            snapshot = runtime.snapshot()
            self.assertEqual(snapshot["native_ledger"]["live"], 0)
            self.assertEqual(snapshot["cleanup"]["owner_release"]["status"], "freed")
            self.assertEqual(snapshot["cleanup"]["pending_resource_count"], 1)
            with patch.object(runtime, "_ledger", side_effect=AssertionError("must not call unloaded driver")), \
                 patch("hepta.hia_adaptive.os.close") as close, patch("_ctypes.dlclose") as unload:
                runtime.close()
                again = runtime.snapshot()
                close.assert_not_called()
                unload.assert_not_called()
            self.assertEqual(again["native_ledger"], snapshot["native_ledger"])
            self.assertEqual(os.pread(descriptor, 9, 0), b"unrelated")
        finally:
            if reused:
                real_close(descriptor)

    def test_owner_loader_error_keeps_cached_ledger_and_fd_release_independent(self):
        runtime = self.owner()
        handle, descriptor = runtime._driver._handle, runtime._driver_fd
        real_unload = _ctypes.dlclose

        def failed_driver_unload(value):
            if value == handle:
                raise OSError(errno.EIO, "controlled before driver unload")
            return real_unload(value)

        try:
            with patch("_ctypes.dlclose", failed_driver_unload):
                runtime.close()
            with self.assertRaises(OSError):
                os.fstat(descriptor)
            snapshot = runtime.snapshot()
            self.assertEqual(snapshot["native_ledger"]["live"], 0)
            self.assertEqual(snapshot["cleanup"]["driver_release"]["native"]["library"]["status"], "unknown")
            self.assertEqual(snapshot["cleanup"]["driver_release"]["native"]["fd"]["status"], "closed")
            with patch("_ctypes.dlclose") as unload, patch("hepta.hia_adaptive.os.close") as close:
                runtime.close()
                runtime.snapshot()
                unload.assert_not_called()
                close.assert_not_called()
        finally:
            real_unload(handle)

    def test_unknown_owner_free_retains_driver_without_reading_or_replaying(self):
        for after_real_free in (False, True):
            with self.subTest(after_real_free=after_real_free):
                runtime = self.owner("owner-" + str(after_real_free))
                driver, pointer, descriptor = runtime._driver, runtime._state, runtime._driver_fd
                handle, free = driver._handle, driver.hs_free
                real_close, real_unload = os.close, _ctypes.dlclose

                def fail_free(value):
                    if after_real_free:
                        free(value)
                    raise OSError(errno.EIO, "controlled ambiguous native owner free")

                try:
                    with patch.object(driver, "hs_free", side_effect=fail_free) as observed:
                        runtime.close()
                        self.assertEqual(observed.call_count, 1)
                    snapshot = runtime.snapshot()
                    self.assertIsNone(snapshot["native_ledger"])
                    self.assertEqual(snapshot["cleanup"]["owner_release"]["status"], "unknown")
                    self.assertTrue(snapshot["cleanup"]["driver_release_blocked_by_owner_uncertainty"])
                    self.assertEqual(snapshot["cleanup"]["pending_resource_count"], 2)
                    self.assertFalse(snapshot["cleanup"]["owned_native_release_complete"])
                    os.fstat(descriptor)
                    with patch.object(runtime, "_ledger", side_effect=AssertionError("unknown owner ledger")), \
                         patch.object(driver, "hs_free") as release, patch("_ctypes.dlclose") as unload, \
                         patch("hepta.hia_adaptive.os.close") as close:
                        runtime.close()
                        runtime.snapshot()
                        release.assert_not_called()
                        unload.assert_not_called()
                        close.assert_not_called()
                    with self.assertRaises(AdaptiveRejected):
                        runtime.borrow()
                finally:
                    # The injection establishes which side of free completed;
                    # production code cannot infer it from an exception.
                    if not after_real_free:
                        free(pointer)
                    real_unload(handle)
                    real_close(descriptor)

    def test_successful_owner_close_caches_zero_ledger_and_complete_cleanup(self):
        runtime = self.owner()
        with runtime.borrow() as loan:
            self.assertEqual(loan.read(0), 11)
            with self.assertRaisesRegex(AdaptiveRejected, "live aliases"):
                runtime.close()
        runtime.close()
        snapshot = runtime.snapshot()
        self.assertTrue(snapshot["cleanup"]["owned_native_release_complete"])
        self.assertEqual(snapshot["cleanup"]["pending_resource_count"], 0)
        self.assertEqual(snapshot["native_ledger"]["live"], 0)
        self.assertEqual(snapshot["native_ledger"]["allocations"], snapshot["native_ledger"]["frees"])


if __name__ == "__main__":
    unittest.main()
