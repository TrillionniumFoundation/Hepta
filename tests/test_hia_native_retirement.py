"""Real native lifetime and bounded, non-replayed cleanup failure controls."""
import _ctypes
import errno
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_multiversion import (MultiversionRejected, PublicationCancellation,
                                   ScalarMultiversionRuntime)
from hepta.hia_native_retirement import NativeRetirement, PathIdentityPin
from tests.test_hia_multiversion import _CLANG, _NATIVE, scalar_program


@unittest.skipUnless(_NATIVE, "actual Clang, Z3 and Linux sealed memfd are required")
class NativeRetirementTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="hia-retirement-")
        self.addCleanup(self.cleanup_fixture)
        self.root = Path(self.temporary.name)
        self.runtime = ScalarMultiversionRuntime(scalar_program(), self.root, clang=_CLANG,
                                                max_live_generations=3)

    def cleanup_fixture(self):
        # Only test-owned paths are removed here. Once they are absent, the
        # production retry releases any still-held identity pins without
        # retrying a failed native close. Deliberately uncertain native handles
        # are explicitly resolved by the individual test that injected them.
        if hasattr(self, "runtime"):
            self.runtime.close()
        self.temporary.cleanup()
        if hasattr(self, "runtime"):
            self.runtime.retry_cleanup()

    def deny_unlink(self, target):
        real = Path.unlink
        def unlink(path, *args, **kwargs):
            if path == target: raise OSError(errno.EACCES, "injected owned-file deletion failure")
            return real(path, *args, **kwargs)
        return patch.object(Path, "unlink", unlink)

    def test_close_observation_waits_for_actual_last_lease_release(self):
        first = self.runtime.publish(scalar_program(None))
        lease = self.runtime.lease()
        self.addCleanup(lease.close)
        state = self.runtime._states[first.generation]
        self.runtime.publish(scalar_program("bit.or"))
        self.runtime.close()
        while_leased = self.runtime.snapshot()["cleanup"]
        self.assertFalse(while_leased["owned_native_release_complete"])
        self.assertFalse(while_leased["observed_closed_and_directory_absent"])
        os.fstat(state.fd)
        self.assertEqual(lease.call("calculate", [91]), 91)
        lease.close()
        final = self.runtime.snapshot()["cleanup"]
        self.assertTrue(final["owned_native_release_complete"])
        self.assertTrue(final["observed_closed_and_directory_absent"])
        self.assertEqual(final["directory_observation"]["status"], "absent")
        self.assertEqual(final["pending"], [])
        self.assertEqual(len(final["recent_attempts"]), 3)
        with self.assertRaises(OSError): os.fstat(state.fd)
        self.assertFalse(final["absence_is_a_permanent_filesystem_guarantee"])

    def test_failed_file_cleanup_is_charged_and_retry_does_not_reclose_native_handles(self):
        first = self.runtime.publish(scalar_program(None))
        state = self.runtime._states[first.generation]
        with self.deny_unlink(state.artifact):
            second = self.runtime.publish(scalar_program("bit.or"))
        self.assertEqual(self.runtime.snapshot()["current_generation"], second.generation)
        self.assertEqual(self.runtime.call("calculate", [23]), 23)
        pending = self.runtime.snapshot()["cleanup"]["pending"]
        self.assertEqual(len(pending), 1)
        self.assertTrue(pending[0]["native_release_succeeded"])
        self.assertEqual(pending[0]["disk"]["error"]["errno"], errno.EACCES)
        with patch("hepta.hia_multiversion.build_program_native") as build:
            with self.assertRaisesRegex(MultiversionRejected, "budget exhausted"):
                self.runtime.publish(scalar_program("bit.xor"))
            build.assert_not_called()
        with patch("hepta.hia_native_retirement.os.close", wraps=os.close) as close, \
             patch("_ctypes.dlclose") as unload:
            retried = self.runtime.retry_cleanup()
            close.assert_called_once_with(state.identity_pin.fd); unload.assert_not_called()
        self.assertEqual(retried["pending"], [])
        self.assertFalse(state.artifact.exists())
        self.assertTrue(self.runtime._states[0].artifact.exists())
        self.assertTrue(self.runtime._states[second.generation].artifact.exists())
        self.runtime.publish(scalar_program("bit.xor"))
        self.assertEqual(self.runtime.call("calculate", [29]), 29)

    def test_fd_error_after_real_close_never_closes_a_reused_descriptor(self):
        state = self.runtime._states[0]
        descriptor = state.fd
        marker = self.root / "unrelated-marker"
        marker.write_bytes(b"owned by the test, not by the runtime")
        real_close = os.close
        reused = []
        def close_then_raise(fd):
            real_close(fd)
            if fd == descriptor:
                other = os.open(marker, os.O_RDONLY)
                if other != descriptor:
                    os.dup2(other, descriptor); real_close(other)
                reused.append(descriptor)
                raise OSError(errno.EINTR, "injected error after actual close and fd reuse")
        try:
            with patch("hepta.hia_native_retirement.os.close", close_then_raise):
                self.runtime.close()
            self.assertEqual(reused, [descriptor])
            observation = self.runtime.snapshot()["cleanup"]
            self.assertFalse(observation["owned_native_release_complete"])
            self.assertEqual(observation["pending"][0]["native"]["fd"]["status"], "unknown")
            with patch("hepta.hia_native_retirement.os.close") as close, \
                 patch("_ctypes.dlclose") as unload:
                self.runtime.retry_cleanup(); self.runtime.close()
                close.assert_not_called(); unload.assert_not_called()
            self.assertEqual(os.pread(descriptor, 5, 0), b"owned")
        finally:
            if reused: real_close(descriptor)

    def test_loader_release_error_still_closes_memfd_and_is_not_replayed(self):
        state = self.runtime._states[0]
        handle = state.library._handle
        real_unload = _ctypes.dlclose
        try:
            with patch("_ctypes.dlclose", side_effect=OSError(errno.EIO, "injected before loader release")) as unload:
                self.runtime.close(); self.runtime.retry_cleanup(); self.runtime.close()
                self.assertEqual(unload.call_count, 1)
            with self.assertRaises(OSError): os.fstat(state.fd)
            pending = self.runtime.snapshot()["cleanup"]["pending"][0]
            self.assertEqual(pending["native"]["library"]["status"], "unknown")
            self.assertEqual(pending["native"]["fd"]["status"], "closed")
            self.assertFalse(pending["native_retry_permitted"])
        finally:
            # This test knows its injected exception occurred before dlclose.
            # The production runtime cannot infer that and must not retry it.
            real_unload(handle)

    def test_replaced_artifact_is_preserved_and_reported_until_caller_resolves_it(self):
        state = self.runtime._states[0]
        saved = state.artifact.with_name("saved-original.so")
        state.artifact.rename(saved)
        state.artifact.write_bytes(b"unrelated replacement")
        self.runtime.close()
        report = self.runtime.snapshot()["cleanup"]
        self.assertTrue(report["owned_native_release_complete"])
        self.assertFalse(report["observed_closed_and_directory_absent"])
        self.assertEqual(report["pending"][0]["disk"]["status"], "refused_unowned")
        self.runtime.retry_cleanup()
        self.assertEqual(state.artifact.read_bytes(), b"unrelated replacement")
        state.artifact.unlink(); saved.unlink()
        self.assertTrue(self.runtime.retry_cleanup()["observed_closed_and_directory_absent"])

    def test_replaced_runtime_directory_is_never_removed_as_the_original_directory(self):
        original = self.runtime._directory
        moved = self.root / "moved-runtime"
        original.rename(moved)
        original.mkdir()
        self.assertEqual(self.runtime.call("calculate", [51]), 51)
        self.runtime.close()
        report = self.runtime.snapshot()["cleanup"]
        self.assertEqual(report["directory_observation"]["status"], "replaced")
        self.assertEqual(report["directory_cleanup"]["status"], "refused_unowned_or_unobservable")
        self.assertFalse(report["observed_closed_and_directory_absent"])
        self.assertTrue(original.is_dir())
        self.assertTrue((moved / "generation-0.so").is_file())

    def test_foreign_directory_entry_is_retained_and_errno_is_observable(self):
        foreign = self.runtime._directory / "caller-owned"
        foreign.write_bytes(b"keep")
        self.runtime.close()
        report = self.runtime.snapshot()["cleanup"]
        self.assertTrue(report["owned_native_release_complete"])
        self.assertEqual(report["pending"], [])
        self.assertEqual(report["directory_cleanup"]["status"], "error")
        self.assertIn(report["directory_cleanup"]["error"]["errno"], {errno.ENOTEMPTY, errno.EEXIST})
        self.assertEqual(foreign.read_bytes(), b"keep")
        foreign.unlink()
        self.assertTrue(self.runtime.retry_cleanup()["observed_closed_and_directory_absent"])

    def test_cancelled_prepared_candidate_keeps_original_error_and_records_disk_failure(self):
        token = PublicationCancellation()
        real_prepare = self.runtime._prepare
        target = self.runtime._directory / "generation-1.so"
        def prepare_and_cancel(*args, **kwargs):
            state = real_prepare(*args, **kwargs); token.cancel(); return state
        with patch.object(self.runtime, "_prepare", prepare_and_cancel), self.deny_unlink(target):
            with self.assertRaisesRegex(MultiversionRejected, "cancelled"):
                self.runtime.publish_if_current(scalar_program(None), 0, expected_epoch=0,
                    max_prepare_ns=30_000_000_000, cancellation=token)
        self.assertEqual(self.runtime.snapshot()["current_generation"], 0)
        row = self.runtime.snapshot()["cleanup"]["pending"][0]
        self.assertEqual(row["cause"], "prepared_but_not_selected")
        self.assertTrue(row["native_release_succeeded"])
        self.assertEqual(self.runtime.call("calculate", [61]), 61)
        self.assertEqual(self.runtime.retry_cleanup()["pending"], [])

    def test_prepare_failure_reports_unacquired_handles_and_preserves_original_exception(self):
        target = self.runtime._directory / "generation-1.so"
        with patch("hepta.hia_multiversion._read_artifact", side_effect=OSError(errno.EIO, "original read failure")), \
             self.deny_unlink(target):
            with self.assertRaisesRegex(OSError, "original read failure"):
                self.runtime.publish(scalar_program(None))
        report = self.runtime.snapshot()["cleanup"]["pending"][0]
        self.assertEqual(report["cause"], "preparation_failed")
        self.assertEqual(report["native"]["library"]["status"], "not_acquired")
        self.assertEqual(report["native"]["fd"]["status"], "not_acquired")
        self.assertEqual(self.runtime.retry_cleanup()["pending"], [])
        self.assertEqual(self.runtime.call("calculate", [67]), 67)

    def test_constructor_failure_exposes_cleanup_and_snapshots_are_detached(self):
        with patch("hepta.hia_multiversion._read_artifact", side_effect=OSError(errno.EIO, "constructor failure")):
            with self.assertRaisesRegex(OSError, "constructor failure") as caught:
                ScalarMultiversionRuntime(scalar_program(), self.root, clang=_CLANG)
        self.assertTrue(caught.exception.hia_cleanup["observed_closed_and_directory_absent"])
        self.runtime.publish(scalar_program(None)); self.runtime.rollback()
        report = self.runtime.snapshot()["cleanup"]
        report["recent_attempts"][0]["native"]["fd"]["status"] = "forged"
        self.assertEqual(self.runtime.snapshot()["cleanup"]["recent_attempts"][0]["native"]["fd"]["status"], "closed")

    def test_constructor_directory_identity_failure_is_observable_and_not_deleted_blindly(self):
        real_stat = Path.lstat
        failed = []
        def fail_first_runtime_stat(path, *args, **kwargs):
            if path.name.startswith("hia-multiversion-") and not failed:
                failed.append(path)
                raise OSError(errno.EIO, "initial directory identity unavailable")
            return real_stat(path, *args, **kwargs)
        with patch.object(Path, "lstat", fail_first_runtime_stat):
            with self.assertRaisesRegex(OSError, "initial directory identity") as caught:
                ScalarMultiversionRuntime(scalar_program(), self.root, clang=_CLANG)
        report = caught.exception.hia_cleanup
        self.assertEqual(report["directory_observation"]["status"], "unbound")
        self.assertFalse(report["observed_closed_and_directory_absent"])
        self.assertEqual(report["pending"], [])
        self.assertTrue(failed[0].is_dir())

    def test_artifact_unlink_recreate_cannot_reuse_a_pinned_original_inode(self):
        state = self.runtime._states[0]
        pinned = state.identity_pin.fd
        original = os.pread(pinned, 4, 0)
        self.assertEqual(original, b"\x7fELF")
        state.artifact.unlink()
        state.artifact.write_bytes(b"caller replacement must survive")
        replacement = state.artifact.stat()
        self.assertNotEqual((replacement.st_dev, replacement.st_ino), state.inode)
        self.runtime.close()
        self.assertEqual(state.artifact.read_bytes(), b"caller replacement must survive")
        row = self.runtime.snapshot()["cleanup"]["pending"][0]
        self.assertEqual(row["disk"]["before"]["status"], "replaced")
        self.assertTrue(row["artifact_identity_pin"]["identity_fd_held"])
        self.assertEqual(os.pread(pinned, 4, 0), original)
        state.artifact.unlink()
        self.assertTrue(self.runtime.retry_cleanup()["observed_closed_and_directory_absent"])
        with self.assertRaises(OSError): os.fstat(pinned)

    def test_directory_rmdir_recreate_cannot_reuse_a_pinned_original_inode(self):
        state = self.runtime._states[0]
        directory, pinned = self.runtime._directory, self.runtime._directory_pin.fd
        state.artifact.unlink()
        directory.rmdir()
        directory.mkdir()
        replacement = directory.stat()
        self.assertNotEqual((replacement.st_dev, replacement.st_ino), self.runtime._directory_inode)
        self.runtime.close()
        report = self.runtime.snapshot()["cleanup"]
        self.assertEqual(report["directory_observation"]["status"], "replaced")
        self.assertTrue(directory.is_dir())
        self.assertFalse(report["owned_identity_release_complete"])
        self.assertEqual(report["pending_resource_count"], 1)
        os.fstat(pinned)
        directory.rmdir()
        self.assertTrue(self.runtime.retry_cleanup()["observed_closed_and_directory_absent"])
        with self.assertRaises(OSError): os.fstat(pinned)

    def test_artifact_identity_close_error_is_charged_and_never_recloses_reused_fd(self):
        first = self.runtime.publish(scalar_program(None))
        state = self.runtime._states[first.generation]
        descriptor = state.identity_pin.fd
        marker = self.root / "identity-marker"
        marker.write_bytes(b"separate caller descriptor")
        real_close = os.close
        reused = []
        def close_then_raise(fd):
            real_close(fd)
            if fd == descriptor:
                other = os.open(marker, os.O_RDONLY)
                if other != descriptor:
                    os.dup2(other, descriptor); real_close(other)
                reused.append(descriptor)
                raise OSError(errno.EINTR, "identity close completed before reported failure")
        try:
            with patch("hepta.hia_native_retirement.os.close", close_then_raise):
                second = self.runtime.publish(scalar_program("bit.or"))
            self.assertEqual(reused, [descriptor])
            self.assertEqual(self.runtime.snapshot()["current_generation"], second.generation)
            self.assertEqual(self.runtime.call("calculate", [23]), 23)
            row = self.runtime.snapshot()["cleanup"]["pending"][0]
            self.assertEqual(row["artifact_identity_pin"]["close"]["status"], "unknown")
            self.assertFalse(row["complete"])
            state.artifact.write_bytes(b"new file after identity release")
            with patch("hepta.hia_native_retirement.os.close") as close, patch("_ctypes.dlclose") as unload:
                report = self.runtime.retry_cleanup()
                close.assert_not_called(); unload.assert_not_called()
            self.assertEqual(report["pending"][0]["disk"]["before"]["status"], "recreated_after_release")
            self.assertEqual(state.artifact.read_bytes(), b"new file after identity release")
            self.assertEqual(os.pread(descriptor, 8, 0), b"separate")
            with patch("hepta.hia_multiversion.build_program_native") as build:
                with self.assertRaisesRegex(MultiversionRejected, "budget exhausted"):
                    self.runtime.publish(scalar_program("bit.xor"))
                build.assert_not_called()
        finally:
            if reused: real_close(descriptor)

    def test_directory_identity_close_error_stays_pending_and_refuses_recreation(self):
        directory, descriptor = self.runtime._directory, self.runtime._directory_pin.fd
        marker = self.root / "directory-marker"
        marker.write_bytes(b"caller directory marker")
        real_close, reused = os.close, []
        def close_then_raise(fd):
            real_close(fd)
            if fd == descriptor:
                other = os.open(marker, os.O_RDONLY)
                if other != descriptor:
                    os.dup2(other, descriptor); real_close(other)
                reused.append(descriptor)
                raise OSError(errno.EINTR, "directory identity close completed before reported failure")
        try:
            with patch("hepta.hia_native_retirement.os.close", close_then_raise):
                self.runtime.close()
            self.assertEqual(reused, [descriptor])
            report = self.runtime.snapshot()["cleanup"]
            self.assertEqual(report["directory_observation"]["status"], "absent")
            self.assertTrue(report["owned_native_release_complete"])
            self.assertFalse(report["owned_identity_release_complete"])
            self.assertFalse(report["observed_closed_and_directory_absent"])
            self.assertEqual(report["pending_resource_count"], 1)
            self.assertEqual(report["pending_identity_releases"][0]["kind"], "directory")
            directory.mkdir()
            with patch("hepta.hia_native_retirement.os.close") as close, patch("_ctypes.dlclose") as unload:
                report = self.runtime.retry_cleanup()
                close.assert_not_called(); unload.assert_not_called()
            self.assertEqual(report["directory_observation"]["status"], "recreated_after_release")
            self.assertTrue(directory.is_dir())
            self.assertEqual(os.pread(descriptor, 6, 0), b"caller")
        finally:
            if reused: real_close(descriptor)

    def test_artifact_pin_open_failure_cannot_authorize_unpinned_cleanup(self):
        target = self.runtime._directory / "generation-1.so"
        real_acquire = PathIdentityPin.acquire
        def fail_acquire(pin, inode):
            if pin.path == target:
                # Inject at this ownership boundary, after the compiler's own
                # exact publication reads have completed successfully.
                with patch("hepta.hia_native_retirement.os.open",
                           side_effect=OSError(errno.EACCES, "artifact identity open unavailable")):
                    return real_acquire(pin, inode)
            return real_acquire(pin, inode)
        with patch.object(PathIdentityPin, "acquire", fail_acquire):
            with self.assertRaisesRegex(OSError, "identity open unavailable"):
                self.runtime.publish(scalar_program(None))
        row = self.runtime.snapshot()["cleanup"]["pending"][0]
        self.assertEqual(row["artifact_identity_pin"]["acquisition_error"]["errno"], errno.EACCES)
        self.assertFalse(row["artifact_identity_pin"]["identity_bound"])
        self.assertEqual(row["disk"]["status"], "refused_unowned")
        target.unlink(); target.write_bytes(b"sequential replacement after pin failure")
        self.runtime.retry_cleanup()
        self.assertEqual(target.read_bytes(), b"sequential replacement after pin failure")
        self.assertEqual(self.runtime.call("calculate", [17]), 17)
        target.unlink()
        self.assertEqual(self.runtime.retry_cleanup()["pending"], [])

    def test_directory_pin_open_failure_exposes_unbound_directory_without_deleting(self):
        real_open = os.open
        failed = []
        def fail_open(path, flags, *args, **kwargs):
            if flags & os.O_DIRECTORY and Path(path).name.startswith("hia-multiversion-"):
                failed.append(Path(path))
                raise OSError(errno.EACCES, "directory identity open unavailable")
            return real_open(path, flags, *args, **kwargs)
        with patch("hepta.hia_native_retirement.os.open", fail_open):
            with self.assertRaisesRegex(OSError, "directory identity open unavailable") as caught:
                ScalarMultiversionRuntime(scalar_program(), self.root, clang=_CLANG)
        report = caught.exception.hia_cleanup
        self.assertEqual(report["directory_identity_pin"]["acquisition_error"]["errno"], errno.EACCES)
        self.assertEqual(report["directory_observation"]["status"], "unbound")
        self.assertFalse(report["observed_closed_and_directory_absent"])
        self.assertTrue(failed[0].is_dir())

    def test_pin_validation_failure_releases_acquired_fd_once_without_delete_authority(self):
        target = self.root / "pin-validation"
        target.write_bytes(b"must remain")
        info = target.lstat()
        pin = PathIdentityPin(target)
        with patch("hepta.hia_native_retirement.os.fstat", side_effect=OSError(errno.EIO, "pin fstat failed")):
            with self.assertRaisesRegex(OSError, "pin fstat failed"):
                pin.acquire((info.st_dev, info.st_ino))
        self.assertTrue(pin.close_attempted)
        self.assertTrue(pin.release_succeeded)
        with self.assertRaises(OSError): os.fstat(pin.fd)
        task = NativeRetirement(99, "test", target, (info.st_dev, info.st_ino), None, {}, None, pin)
        with patch("hepta.hia_native_retirement.os.close") as close:
            report = task.attempt()
            task.attempt()
            close.assert_not_called()
        self.assertEqual(report["disk"]["status"], "refused_unowned")
        self.assertEqual(target.read_bytes(), b"must remain")

    def test_successfully_closed_directory_pin_never_rebinds_a_later_path(self):
        directory = self.runtime._directory
        self.runtime.close()
        self.assertTrue(self.runtime.snapshot()["cleanup"]["observed_closed_and_directory_absent"])
        directory.mkdir()
        with patch("hepta.hia_native_retirement.os.close") as close:
            report = self.runtime.retry_cleanup()
            close.assert_not_called()
        self.assertEqual(report["directory_observation"]["status"], "recreated_after_release")
        self.assertFalse(report["observed_closed_and_directory_absent"])
        self.assertTrue(directory.is_dir())


if __name__ == "__main__": unittest.main()
