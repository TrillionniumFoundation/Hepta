"""Actual native and adversarial lifetime checks for prepared artifact reuse."""
from copy import copy, deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch

from hepta import hia_artifact_session as session_module
from hepta import hia_guarded_optimization as guarded_module
from hepta.hia_artifact_session import PreparedArtifactSession, ArtifactSessionRejected
from hepta.hia_guarded_optimization import propose_guarded_reduction
from hepta.hia_multiversion import PublicationCancellation
from hepta.hia_program_source import lower_source
from hepta.native_tool_identity import MAX_EXECUTABLE_BYTES, ToolIdentityRejected
from tools.qualify_hia_ndu_activation import checksum, PROFILE as WORKLOADS, DRIVER


@unittest.skipUnless(os.environ.get("HEPTA_RUN_ARTIFACT_SESSION") == "1"
                     and platform.system() == "Linux", "requires actual Linux native compiler/solver")
class PreparedArtifactSessionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workspace = tempfile.TemporaryDirectory()
        cls.root = Path(cls.workspace.name)
        cls.clang = os.environ.get("CLANG", "clang")
        (cls.root / "driver.c").write_text(DRIVER)
        cls.driver = cls.root / "driver"
        subprocess.run([cls.clang, "-O3", "-std=c11", str(cls.root / "driver.c"), "-ldl", "-o", str(cls.driver)],
                       check=True, capture_output=True, timeout=60)
        cls.driver_sha = sha256(cls.driver.read_bytes()).hexdigest()
        cls.base = lower_source((WORKLOADS / "byte_sum.hepta").read_text())
        cls.other = lower_source((WORKLOADS / "packet_xor.hepta").read_text())

    @classmethod
    def tearDownClass(cls):
        cls.workspace.cleanup()

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(dir=self.root)
        self.addCleanup(self.directory.cleanup)
        self.counter = 0

    def owner(self, **limits):
        self.counter += 1
        owner = PreparedArtifactSession(Path(self.directory.name) / str(self.counter), clang=self.clang, **limits)
        self.addCleanup(owner.close)
        owner.bind_driver(self.driver, self.driver_sha)
        return owner

    def check_output(self, row, module="byte_sum", n=127, calls=3, seed=113):
        self.assertEqual(row["status"], "completed", row)
        value = json.loads(row["stdout"])
        self.assertTrue(value["loaded_mapping_verified"])
        self.assertEqual(value["checksum"], checksum(module, n, calls, seed))
        self.assertFalse(row["new_solver_call"])

    def test_independent_proof_once_then_actual_native_reuse_without_new_solver(self):
        owner = self.owner()
        base = owner.prepare_base(self.base)
        proposal = propose_guarded_reduction(self.base, maximum=128)
        real_proof = guarded_module.verify_guarded_optimization
        with patch.object(guarded_module, "verify_guarded_optimization", wraps=real_proof) as prove:
            candidate = owner.prepare_guarded(base["token"], proposal)
            self.assertEqual(prove.call_count, 1)
            for n in (0, 127, 4093):
                with owner.lease(candidate["token"]) as lease:
                    row = lease.run(n, 3, 113)
                    self.check_output(row, n=n)
            self.assertEqual(prove.call_count, 1)
        self.assertEqual(owner.snapshot()["proof_attempts"], 2)
        self.assertEqual(owner.snapshot()["execution_attempts"], 3)
        owner.close()
        self.assertTrue(owner.snapshot()["owned_native_release_complete"])
        self.assertEqual(owner.snapshot()["charged_retained_bytes"], 0)

    def test_two_semantic_programs_and_fallback_keep_their_own_identity(self):
        owner = self.owner()
        first = owner.prepare_base(self.base)
        second = owner.prepare_base(self.other)
        self.assertNotEqual(first["core_sha256"], second["core_sha256"])
        for entry, module in ((first, "byte_sum"), (second, "packet_xor")):
            with owner.lease(entry["token"]) as lease:
                self.check_output(lease.run(4093, 3, 113), module=module, n=4093)

    def test_serialized_receipt_foreign_token_and_changed_core_cannot_authorize(self):
        owner, foreign = self.owner(), self.owner()
        base = owner.prepare_base(self.base)
        with self.assertRaises(ArtifactSessionRejected):
            foreign.lease(base["token"])
        with self.assertRaises(Exception):
            foreign.prepare_base(owner._entries[base["token"]].image.receipt)
        image = owner._entries[base["token"]].image
        image.program = self.other
        with patch.object(session_module.subprocess, "run") as launch:
            with self.assertRaises(ArtifactSessionRejected):
                owner.lease(base["token"])
            launch.assert_not_called()

    def test_receipt_mutation_is_detected_before_native_execution(self):
        owner = self.owner()
        base = owner.prepare_base(self.base)
        owner._entries[base["token"]].image.receipt["native"]["artifact_sha256"] = "0" * 64
        with self.assertRaises(ArtifactSessionRejected):
            owner.lease(base["token"])
        self.assertEqual(owner.snapshot()["execution_attempts"], 0)

    def test_changed_publication_path_does_not_replace_sealed_admission(self):
        owner = self.owner()
        base = owner.prepare_base(self.base)
        (owner._directory / "generation-1.so").write_bytes(b"not the admitted executable")
        with owner.lease(base["token"]) as lease:
            self.check_output(lease.run(127, 3, 113))
        self.assertEqual(owner.snapshot()["successful_admissions"], 1)

    def test_source_or_policy_drift_permanently_refuses_reuse(self):
        owner = self.owner()
        base = owner.prepare_base(self.base)
        old = owner._policy["timeout_ms"]
        owner._policy["timeout_ms"] = old - 1
        with self.assertRaises(ArtifactSessionRejected):
            owner.lease(base["token"])
        owner._policy["timeout_ms"] = old
        with self.assertRaises(ArtifactSessionRejected):
            owner.lease(base["token"])
        self.assertTrue(owner.snapshot()["invalidated"])

    def test_entry_byte_lease_and_execution_limits_refuse_without_extra_build(self):
        owner = self.owner(max_entries=1, max_leases=1, max_executions=1)
        base = owner.prepare_base(self.base)
        with patch.object(session_module, "build_optimized_native") as build:
            with self.assertRaises(ArtifactSessionRejected):
                owner.prepare_base(self.base)
            build.assert_not_called()
        with owner.lease(base["token"]) as lease:
            with self.assertRaises(ArtifactSessionRejected):
                owner.lease(base["token"])
            self.check_output(lease.run(127, 3, 113))
            with self.assertRaises(ArtifactSessionRejected):
                lease.run(127, 3, 113)
        tight = self.owner(max_retained_bytes=1024*1024)
        with patch.object(session_module, "build_optimized_native") as build:
            with self.assertRaises(ArtifactSessionRejected):
                tight.prepare_base(self.base)
            build.assert_not_called()

    def test_close_preserves_existing_lease_and_parent_until_it_finishes(self):
        owner = self.owner()
        base = owner.prepare_base(self.base)
        candidate = owner.prepare_guarded(base["token"], propose_guarded_reduction(self.base, maximum=128))
        lease = owner.lease(candidate["token"])
        self.addCleanup(lease.close)
        owner.close()
        state = owner.snapshot()
        self.assertEqual(len(state["entries"]), 2)
        self.assertFalse(state["owned_native_release_complete"])
        with self.assertRaises(ArtifactSessionRejected):
            owner.lease(candidate["token"])
        self.check_output(lease.run(127, 3, 113))
        lease.close()
        state = owner.snapshot()
        self.assertTrue(state["owned_native_release_complete"])
        self.assertEqual(state["charged_retained_bytes"], 0)
        with self.assertRaises(ArtifactSessionRejected):
            lease.run(127, 3, 113)

    def test_close_racing_actual_child_execution_never_releases_its_image(self):
        owner = self.owner()
        base = owner.prepare_base(self.base)
        lease = owner.lease(base["token"])
        self.addCleanup(lease.close)
        entered, resume = threading.Event(), threading.Event()
        native_run = session_module.subprocess.run
        output, errors = [], []
        def held(*args, **kwargs):
            entered.set()
            if not resume.wait(10):
                raise RuntimeError("test handshake deadline")
            return native_run(*args, **kwargs)
        def worker():
            try: output.append(lease.run(127, 3, 113))
            except BaseException as error: errors.append(error)
        with patch.object(session_module.subprocess, "run", side_effect=held):
            thread = threading.Thread(target=worker)
            thread.start()
            self.assertTrue(entered.wait(10))
            owner.close()
            self.assertEqual(owner.snapshot()["outstanding_leases"], 1)
            resume.set()
            thread.join(10)
            self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.check_output(output[0])
        lease.close()
        self.assertTrue(owner.snapshot()["owned_native_release_complete"])

    def test_cancellation_during_build_never_mints_a_prepared_token(self):
        owner = self.owner()
        token = PublicationCancellation()
        real_build = session_module.build_optimized_native
        def cancel_after(*args, **kwargs):
            result = real_build(*args, **kwargs)
            self.assertTrue(token.cancel())
            return result
        with patch.object(session_module, "build_optimized_native", side_effect=cancel_after):
            with self.assertRaises(ArtifactSessionRejected):
                owner.prepare_base(self.base, cancellation=token)
        state = owner.snapshot()
        self.assertEqual(state["successful_admissions"], 0)
        self.assertEqual(state["entries"], [])
        self.assertEqual(state["reserved_bytes"], 0)

    def test_uncertain_retirement_is_charged_and_never_retries_reused_fd(self):
        owner = self.owner(max_entries=1)
        base = owner.prepare_base(self.base)
        target = owner._entries[base["token"]].fd
        close = os.close
        attempts = []
        def close_then_error(fd):
            if fd == target:
                attempts.append(fd)
                close(fd)
                raise OSError("injected unknown close result after actual close")
            close(fd)
        with patch.object(session_module.os, "close", side_effect=close_then_error):
            owner.retire(base["token"])
        state = owner.snapshot()
        self.assertEqual(len(state["pending_release_debt"]), 1)
        self.assertGreater(state["charged_retained_bytes"], 0)
        with self.assertRaises(ArtifactSessionRejected):
            owner.prepare_base(self.base)
        reused = os.open("/dev/null", os.O_RDONLY)
        try:
            owner.close(); owner.close()
            os.fstat(reused)
            self.assertEqual(attempts, [target])
            self.assertFalse(owner.snapshot()["owned_native_release_complete"])
        finally:
            os.close(reused)

    def test_uncertain_read_fd_close_during_pinning_has_an_owner_and_no_retry(self):
        self.counter += 1
        owner = PreparedArtifactSession(Path(self.directory.name) / str(self.counter), clang=self.clang)
        self.addCleanup(owner.close)
        original_open, original_close = os.open, os.close
        watched, attempted = [], []
        def watch(path, *args, **kwargs):
            fd = original_open(path, *args, **kwargs)
            if Path(path) == self.driver:
                watched.append(fd)
            return fd
        def close_then_error(fd):
            if watched and fd == watched[-1] and not attempted:
                attempted.append(fd)
                original_close(fd)
                raise OSError("uncertain read descriptor close")
            original_close(fd)
        with patch.object(session_module.os, "open", side_effect=watch), patch.object(session_module.os, "close", side_effect=close_then_error):
            with self.assertRaises(ArtifactSessionRejected):
                owner.bind_driver(self.driver, self.driver_sha)
        state = owner.snapshot()
        self.assertEqual(len(state["pending_release_debt"]), 1)
        self.assertEqual(state["reserved_bytes"], 0)
        reused = os.open("/dev/null", os.O_RDONLY)
        try:
            owner.close(); owner.close()
            os.fstat(reused)
            self.assertEqual(attempted, watched)
            self.assertFalse(owner.snapshot()["owned_native_release_complete"])
        finally:
            os.close(reused)

    def test_foreign_or_unverified_program_and_copy_do_not_expand_authority(self):
        owner = self.owner()
        with self.assertRaises(ArtifactSessionRejected):
            copy(owner)
        with self.assertRaises(Exception):
            owner.prepare_base({"schema": "forged", "verified": True})
        base = owner.prepare_base(self.base)
        with owner.lease(base["token"]) as lease:
            with self.assertRaises(ArtifactSessionRejected):
                deepcopy(lease)
        self.assertEqual(owner.snapshot()["authority"], "DENY_ALL")
        self.assertFalse(owner.snapshot()["safety_certificate"])

    def test_driver_identity_failure_after_pin_releases_its_unpublished_owner(self):
        self.counter += 1
        owner = PreparedArtifactSession(Path(self.directory.name) / str(self.counter), clang=self.clang)
        self.addCleanup(owner.close)
        real_pin, acquired = session_module._pin_native_artifact, []
        def pin(*args, **kwargs):
            value = real_pin(*args, **kwargs)
            acquired.append(value[2])
            return value
        with patch.object(session_module, "_pin_native_artifact", side_effect=pin), \
             patch.object(owner, "_fd_identity", side_effect=RuntimeError("identity failure after acquire")):
            with self.assertRaises(RuntimeError):
                owner.bind_driver(self.driver, self.driver_sha)
        self.assertEqual(len(acquired), 1)
        with self.assertRaises(OSError):
            os.fstat(acquired[0])
        state = owner.snapshot()
        self.assertEqual(state["reserved_bytes"], 0)
        self.assertEqual(state["charged_retained_bytes"], 0)
        self.assertTrue(state["owned_native_release_complete"])

    def test_hostile_compiler_paths_refuse_before_artifact_admission(self):
        for kind in ("fifo", "oversized"):
            with self.subTest(kind=kind):
                compiler = Path(self.directory.name) / ("compiler-" + kind)
                if kind == "fifo":
                    os.mkfifo(compiler, 0o700)
                else:
                    with compiler.open("wb") as stream:
                        stream.truncate(MAX_EXECUTABLE_BYTES + 1)
                    compiler.chmod(0o700)
                destination = Path(self.directory.name) / ("uncreated-" + kind)
                with self.assertRaises(ToolIdentityRejected):
                    PreparedArtifactSession(destination, clang=str(compiler))
                self.assertFalse(destination.exists())

    def test_driver_identity_failure_with_unknown_close_retains_budget_debt(self):
        self.counter += 1
        owner = PreparedArtifactSession(Path(self.directory.name) / str(self.counter), clang=self.clang)
        self.addCleanup(owner.close)
        real_pin, real_close, acquired, attempted = session_module._pin_native_artifact, os.close, [], []
        def pin(*args, **kwargs):
            value = real_pin(*args, **kwargs)
            acquired.append(value[2])
            return value
        def close_then_error(fd):
            if acquired and fd == acquired[0] and not attempted:
                attempted.append(fd)
                real_close(fd)
                raise OSError("unpublished driver close outcome unknown")
            return real_close(fd)
        with patch.object(session_module, "_pin_native_artifact", side_effect=pin), \
             patch.object(owner, "_fd_identity", side_effect=RuntimeError("identity failure after acquire")), \
             patch.object(session_module.os, "close", side_effect=close_then_error):
            with self.assertRaises(RuntimeError):
                owner.bind_driver(self.driver, self.driver_sha)
        state = owner.snapshot()
        self.assertEqual(state["reserved_bytes"], 0)
        self.assertEqual(state["charged_retained_bytes"], owner._limits["artifact"])
        self.assertEqual(len(state["pending_release_debt"]), 1)
        reused = os.open("/dev/null", os.O_RDONLY)
        try:
            owner.close(); owner.close()
            os.fstat(reused)
            self.assertEqual(attempted, acquired)
            self.assertFalse(owner.snapshot()["owned_native_release_complete"])
        finally:
            os.close(reused)

    def test_distinct_read_and_memfd_failures_keep_distinct_debt_and_block_more_entries(self):
        owner = self.owner(max_entries=2)
        real_open, real_close, real_memfd = os.open, os.close, os.memfd_create
        real_fcntl = session_module.fcntl.fcntl
        real_pin = session_module._pin_native_artifact
        attempts = []
        for phase in ("read", "memfd"):
            watched, pinning = [], []
            def pin(*args, **kwargs):
                pinning.append(True)
                try:
                    return real_pin(*args, **kwargs)
                finally:
                    pinning.clear()
            def watch_open(path, *args, **kwargs):
                fd = real_open(path, *args, **kwargs)
                if phase == "read" and pinning and Path(path).parent == owner._directory and str(path).endswith(".so"):
                    watched.append(fd)
                return fd
            def watch_memfd(*args, **kwargs):
                fd = real_memfd(*args, **kwargs)
                if phase == "memfd": watched.append(fd)
                return fd
            def fail_seal(fd, operation, *args):
                if phase == "memfd" and watched and fd == watched[-1] and operation == 1033:
                    raise OSError("injected real memfd seal refusal")
                return real_fcntl(fd, operation, *args)
            def close_then_error(fd):
                if watched and fd == watched[-1]:
                    watched.clear()
                    attempts.append((phase, fd))
                    real_close(fd)
                    raise OSError("uncertain independently owned " + phase + " close")
                return real_close(fd)
            with patch.object(session_module, "_pin_native_artifact", side_effect=pin), \
                 patch.object(session_module.os, "open", side_effect=watch_open), \
                 patch.object(session_module.os, "memfd_create", side_effect=watch_memfd), \
                 patch.object(session_module.fcntl, "fcntl", side_effect=fail_seal), \
                 patch.object(session_module.os, "close", side_effect=close_then_error):
                with self.assertRaises(ArtifactSessionRejected):
                    owner.prepare_base(self.base)
        state = owner.snapshot()
        self.assertEqual([kind for kind, _ in attempts], ["read", "memfd"])
        self.assertEqual(len(state["pending_release_debt"]), 2)
        self.assertEqual(len({row["token"] for row in state["pending_release_debt"]}), 2)
        self.assertEqual(state["reserved_bytes"], 0)
        self.assertEqual(state["entries"], [])
        self.assertEqual(sum(row["charged_bytes"] for row in state["pending_release_debt"]),
                         2 * (owner._limits["artifact"] + owner._limits["metadata"]))
        with patch.object(session_module, "build_optimized_native") as build:
            with self.assertRaises(ArtifactSessionRejected):
                owner.prepare_base(self.base)
            build.assert_not_called()
        reused = os.open("/dev/null", os.O_RDONLY)
        try:
            owner.close(); owner.close()
            os.fstat(reused)
            self.assertFalse(owner.snapshot()["owned_native_release_complete"])
            self.assertEqual(owner.snapshot()["charged_retained_bytes"],
                             2 * (owner._limits["artifact"] + owner._limits["metadata"]))
        finally:
            os.close(reused)

    def test_publication_interruption_rolls_back_parent_counters_and_visibility(self):
        # Each fault happens AFTER the underlying state transition. Actual
        # native builds therefore reach the hazardous publication interval.
        class Interrupted(BaseException): pass
        for point in ("parent", "charge", "admissions", "dictionary", "cancellation"):
            with self.subTest(point=point):
                owner = self.owner()
                base = owner.prepare_base(self.base)
                before = owner.snapshot()
                parent = owner._entries[base["token"]]
                cancellation = PublicationCancellation()
                fired = []
                owner_set = PreparedArtifactSession.__setattr__
                entry_set = session_module._Entry.__setattr__
                cancel_set = PublicationCancellation.__setattr__
                class InterruptingDict(dict):
                    def __setitem__(this, key, value):
                        super().__setitem__(key, value)
                        if point == "dictionary" and key != base["token"] and not fired:
                            fired.append(point); raise Interrupted(point)
                owner._entries = InterruptingDict(owner._entries)
                def changed_owner(obj, name, value):
                    owner_set(obj, name, value)
                    key = "_charged" if point == "charge" else "_admissions" if point == "admissions" else None
                    if obj is owner and name == key and not fired and value > before[
                            "charged_retained_bytes" if point == "charge" else "successful_admissions"]:
                        fired.append(point); raise Interrupted(point)
                def changed_entry(obj, name, value):
                    entry_set(obj, name, value)
                    if point == "parent" and obj is parent and name == "dependents" and value == 1 and not fired:
                        fired.append(point); raise Interrupted(point)
                def changed_cancel(obj, name, value):
                    cancel_set(obj, name, value)
                    if point == "cancellation" and obj is cancellation and name == "_committed" and value and not fired:
                        fired.append(point); raise Interrupted(point)
                with patch.object(PreparedArtifactSession, "__setattr__", changed_owner), \
                     patch.object(session_module._Entry, "__setattr__", changed_entry), \
                     patch.object(PublicationCancellation, "__setattr__", changed_cancel):
                    with self.assertRaises(Interrupted):
                        owner.prepare_guarded(base["token"], propose_guarded_reduction(self.base, maximum=128),
                                              cancellation=cancellation)
                after = owner.snapshot()
                self.assertEqual(fired, [point])
                self.assertEqual(after["successful_admissions"], before["successful_admissions"])
                self.assertEqual(after["charged_retained_bytes"], before["charged_retained_bytes"])
                self.assertEqual(after["reserved_bytes"], 0)
                self.assertEqual(len(after["entries"]), 1)
                self.assertEqual(parent.dependents, 0)
                self.assertFalse(cancellation.committed())
                with owner.lease(base["token"]) as lease:
                    self.check_output(lease.run(127, 3, 113))


if __name__ == "__main__":
    unittest.main()
