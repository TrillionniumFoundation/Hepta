"""Actual admission reuse retains Core/artifact/state and safe-point barriers."""
from __future__ import annotations

import copy
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from hepta import hia_adaptive
from hepta.hia_adaptive import AdaptiveRejected
from hepta.hia_program import verify_program
from hepta.hia_stateful import OwnedAdaptiveRuntime
from tools.qualify_hia_stateful import programs
from tests.test_hia_adaptive import CLANG, NATIVE


class PreparationReservationTests(unittest.TestCase):
    def test_token_failure_releases_reservation_before_any_build(self):
        # A minimal dispatcher avoids loading any native image in this control.
        for error in (OSError("entropy unavailable"), KeyboardInterrupt("cancel token generation")):
            with self.subTest(error=type(error).__name__):
                runtime = hia_adaptive.AdaptiveRuntime.__new__(hia_adaptive.AdaptiveRuntime)
                runtime._lock = threading.RLock()
                runtime._closed = False
                runtime._current = "baseline"
                runtime._images = {"baseline": object()}
                runtime._admissions = {"baseline": object()}
                runtime._pending_native_releases = {}
                runtime._preparing_tokens = set()
                runtime._measurements = {}
                runtime._active = runtime._preparing = 0
                before_images, before_proofs = dict(runtime._images), dict(runtime._admissions)
                with patch("hepta.hia_adaptive.secrets.token_hex", side_effect=error):
                    with patch("hepta.hia_adaptive.build_optimized_native") as build:
                        with patch.object(runtime, "_event"), patch.object(runtime, "_retire_image") as dispose:
                            with self.assertRaises(type(error)):
                                runtime.prepare(None)
                            build.assert_not_called()
                            dispose.assert_not_called()
                            self.assertEqual(runtime._images, before_images)
                            self.assertEqual(runtime._admissions, before_proofs)
                            self.assertEqual(runtime._preparing, 0)
                            runtime.close()
                            dispose.assert_called_once_with("baseline", before_images["baseline"])
                            self.assertTrue(runtime._closed)


@unittest.skipUnless(NATIVE, "Pinned Z3, real LLVM and Linux seals required")
class PreparedNativeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="hia-prepared-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        base, self.candidate = programs()
        self.runtime = OwnedAdaptiveRuntime(base, self.root / "runtime", [11, 17], clang=CLANG)
        self.addCleanup(self.runtime.close)

    def test_internal_proofs_reused_across_three_actual_images_without_solving_again(self):
        first = self.runtime.prepare(self.candidate)
        self.assertTrue(self.runtime.select(first, mode="explicit")["selected"])
        base, _ = programs()
        third = self.runtime.prepare(base)
        original_owner = self.runtime.snapshot()["allocation_identity"]
        with patch("hepta.hia_optimization.verify_optimization", side_effect=AssertionError("selection re-solved")):
            for token in (third, "baseline", first):
                result = self.runtime.select(token, mode="explicit")
                self.assertTrue(result["selected"])
                self.assertFalse(result["proof_reuse"]["new_solver_call"])
                queue = self.runtime.submit_queue([{"slot": 0, "delta": 3, "iterations": 2}])
                result = self.runtime.execute_committed(queue)
                self.assertEqual(result["executed_steps"], 2)
                self.assertEqual(result["replayed_steps"], 0)
        snapshot = self.runtime.snapshot()
        self.assertEqual(snapshot["state_values"], [83, 17])
        self.assertEqual(snapshot["allocation_identity"], original_owner)
        self.assertEqual(snapshot["native_ledger"]["live"], 2)

    def test_changed_core_state_or_internal_build_record_cannot_use_an_old_proof(self):
        token = self.runtime.prepare(self.candidate)
        image = self.runtime._images[token]
        for field, replacement in (
            ("program", verify_program(programs()[0])),
            ("state", {**image.state, "target": "foreign"}),
            ("receipt", {**image.receipt, "binding_sha256": "0" * 64}),
        ):
            original = getattr(image, field)
            setattr(image, field, replacement)
            try:
                result = self.runtime.select(token, mode="explicit")
                self.assertFalse(result["selected"])
                self.assertEqual(self.runtime.snapshot()["current"], "baseline")
            finally:
                setattr(image, field, original)
        original = self.runtime._admissions[token]
        self.runtime._admissions[token] = {"verified": True, "root_core": original.root_core}
        try:
            self.assertFalse(self.runtime.select(token, mode="explicit")["selected"])
        finally:
            self.runtime._admissions[token] = original

    def test_actual_function_address_cannot_be_swapped_with_another_loaded_image(self):
        token = self.runtime.prepare(self.candidate)
        image = self.runtime._images[token]
        original = image.function
        image.function = self.runtime._images["baseline"].function
        try:
            result = self.runtime.select(token, mode="explicit")
            self.assertFalse(result["selected"])
            self.assertEqual(result["reason"], "loaded_function_mapping_changed")
        finally:
            image.function = original

    def test_admitted_rollback_checks_actual_function_mapping_without_reproof(self):
        token = self.runtime.prepare(self.candidate)
        self.assertTrue(self.runtime.select(token, mode="explicit")["selected"])
        image = self.runtime._images["baseline"]
        original = image.function
        image.function = self.runtime._images[token].function
        try:
            with self.runtime._lock, self.assertRaisesRegex(AdaptiveRejected, "sealed image"):
                self.runtime._restore_admitted("baseline")
            self.assertEqual(self.runtime.snapshot()["current"], token)
        finally:
            image.function = original
        with patch("hepta.hia_optimization.verify_optimization", side_effect=AssertionError("rollback re-solved")):
            with self.runtime._lock:
                self.assertTrue(self.runtime._restore_admitted("baseline")["selected"])

    def test_new_candidate_still_needs_real_proof_and_live_loan_still_blocks_switch(self):
        wrong = copy.deepcopy(self.candidate)
        wrong["functions"][0]["blocks"][0]["ops"][0]["op"] = "int.sub.wrap"
        before = set(self.runtime._images)
        with self.assertRaises(ValueError):
            self.runtime.prepare(wrong)
        self.assertEqual(set(self.runtime._images), before)
        token = self.runtime.prepare(self.candidate)
        with self.runtime.borrow() as loan:
            self.assertEqual(loan.read(0), 11)
            self.assertEqual(self.runtime.select(token, mode="explicit")["reason"], "live_state_loan")
        self.assertTrue(self.runtime.select(token, mode="explicit")["selected"])

    def test_proof_from_another_runtime_cannot_match_its_native_build(self):
        token = self.runtime.prepare(self.candidate)
        base, _ = programs()
        other = OwnedAdaptiveRuntime(base, self.root / "other", [11, 17], clang=CLANG)
        self.addCleanup(other.close)
        foreign = other.prepare(self.candidate)
        original = self.runtime._admissions[token]
        self.runtime._admissions[token] = other._admissions[foreign]
        try:
            self.assertFalse(self.runtime.select(token, mode="explicit")["selected"])
        finally:
            self.runtime._admissions[token] = original

    def test_interrupt_after_actual_load_releases_unpublished_candidate(self):
        before_images, before_proofs = set(self.runtime._images), set(self.runtime._admissions)
        loaded = []
        original_load = hia_adaptive._load_image

        def observed_load(*args, **kwargs):
            image = original_load(*args, **kwargs)
            loaded.append((image, image.fd))
            return image

        with patch("hepta.hia_adaptive._load_image", side_effect=observed_load):
            with patch("hepta.hia_adaptive._issue", side_effect=KeyboardInterrupt("cancel after native load")):
                with patch.object(self.runtime, "_event", side_effect=RuntimeError("telemetry unavailable")):
                    with self.assertRaisesRegex(KeyboardInterrupt, "cancel after native load"):
                        self.runtime.prepare(self.candidate)
        self.assertEqual(len(loaded), 1)
        self.assertEqual(set(self.runtime._images), before_images)
        self.assertEqual(set(self.runtime._admissions), before_proofs)
        self.assertEqual(self.runtime._preparing, 0)
        with self.assertRaises(OSError):
            os.fstat(loaded[0][1])
        self.assertIsNone(loaded[0][0].function)
        self.runtime.close()

    def test_event_failure_rolls_back_both_registries_before_disposal(self):
        before_images, before_proofs = set(self.runtime._images), set(self.runtime._admissions)
        loaded = []
        original_load, original_event = hia_adaptive._load_image, self.runtime._event

        def observed_load(*args, **kwargs):
            image = original_load(*args, **kwargs)
            loaded.append((image, image.fd))
            return image

        def failing_event(kind, **fields):
            if kind == "prepared":
                self.assertIn(fields["token"], self.runtime._images)
                self.assertIn(fields["token"], self.runtime._admissions)
                raise RuntimeError("event publication failed")
            return original_event(kind, **fields)

        with patch("hepta.hia_adaptive._load_image", side_effect=observed_load):
            with patch.object(self.runtime, "_event", side_effect=failing_event):
                with self.assertRaisesRegex(RuntimeError, "event publication failed"):
                    self.runtime.prepare(self.candidate)
        self.assertEqual(len(loaded), 1)
        self.assertEqual(set(self.runtime._images), before_images)
        self.assertEqual(set(self.runtime._admissions), before_proofs)
        self.assertEqual(self.runtime._preparing, 0)
        with self.assertRaises(OSError):
            os.fstat(loaded[0][1])
        self.assertIsNone(loaded[0][0].function)
        # A disposed entry left in either registry would make this close unsafe.
        self.runtime.close()

    def test_interrupt_after_publication_keeps_committed_image_owned_and_callable(self):
        runtime, original_lock = self.runtime, self.runtime._lock
        original_tokens = set(runtime._images)

        class InterruptOnCommittedRelease:
            interrupted = False

            def __enter__(self):
                original_lock.acquire()
                return self

            def __exit__(self, kind, value, traceback):
                original_lock.release()
                if kind is None and not self.interrupted and set(runtime._images) != original_tokens:
                    self.interrupted = True
                    raise KeyboardInterrupt("return interrupted after publication")
                return False

        with patch.object(runtime, "_lock", InterruptOnCommittedRelease()):
            with self.assertRaisesRegex(KeyboardInterrupt, "after publication"):
                runtime.prepare(self.candidate)
        tokens = set(runtime._images) - original_tokens
        self.assertEqual(len(tokens), 1)
        token = next(iter(tokens))
        image = runtime._images[token]
        self.assertIn(token, runtime._admissions)
        self.assertEqual(runtime._preparing, 0)
        descriptor = image.fd
        os.fstat(descriptor)
        self.assertTrue(runtime.select(token, mode="explicit")["selected"])
        queue = runtime.submit_queue([{"slot": 0, "delta": 3, "iterations": 2}])
        self.assertEqual(runtime.execute_committed(queue)["executed_steps"], 2)
        self.assertEqual(runtime.snapshot()["state_values"], [35, 17])
        runtime.close()
        with self.assertRaises(OSError):
            os.fstat(descriptor)
        self.assertIsNone(image.function)

    def test_constructor_proof_interrupt_and_event_failure_release_actual_baseline(self):
        base, _ = programs()
        original_load, original_event = hia_adaptive._load_image, hia_adaptive.AdaptiveRuntime._event
        for fault in ("proof", "event"):
            with self.subTest(fault=fault):
                loaded = []

                def observed_load(*args, **kwargs):
                    image = original_load(*args, **kwargs)
                    loaded.append((image, image.fd))
                    return image

                def failing_event(runtime, kind, **fields):
                    if kind == "baseline_loaded":
                        raise RuntimeError("baseline event failed")
                    return original_event(runtime, kind, **fields)

                target = self.root / ("constructor-" + fault)
                with patch("hepta.hia_adaptive._load_image", side_effect=observed_load):
                    if fault == "proof":
                        with patch("hepta.hia_adaptive._issue", side_effect=KeyboardInterrupt("baseline proof interrupted")):
                            with self.assertRaises(KeyboardInterrupt):
                                OwnedAdaptiveRuntime(base, target, [1, 2], clang=CLANG)
                    else:
                        with patch.object(hia_adaptive.AdaptiveRuntime, "_event", failing_event):
                            with self.assertRaisesRegex(RuntimeError, "baseline event failed"):
                                OwnedAdaptiveRuntime(base, target, [1, 2], clang=CLANG)
                self.assertEqual(len(loaded), 1)
                with self.assertRaises(OSError):
                    os.fstat(loaded[0][1])
                self.assertIsNone(loaded[0][0].function)


if __name__ == "__main__":
    unittest.main()
