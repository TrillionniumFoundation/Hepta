"""Finite context correctness and failure ownership; no performance campaign."""
from __future__ import annotations

from base64 import b64decode
import copy
import importlib.util
import json
import os
from pathlib import Path
import pickle
import platform
import shutil
import signal
import tempfile
import unittest
from unittest.mock import patch

from hepta import hia_finite_context as fc
from hepta.clang_capture import CaptureFailure, CaptureRejected, CaptureResult
from hepta.hia_program import SCHEMA
from hepta.hia_specialization import propose_guarded_specializations


def shift_program():
    params = [{"name": "x", "type": "u32"}, {"name": "shift", "type": "u32"}]
    return {"schema": SCHEMA, "module": "finite_context_test", "functions": [{
        "name": "calculate", "params": params, "returns": ["u32"], "effects": ["trap"],
        "entry": "entry", "blocks": [{"id": "entry", "params": params, "ops": [{
            "op": "int.shl.checked", "args": ["x", "shift"], "out": [{"name": "r", "type": "u32"}],
            "attrs": {}}], "term": {"op": "ret", "values": ["r"]}}]}]}


def shift_oracle(x, shift):
    return {"status": "trapped", "code": "overflow"} if shift >= 32 else (x << shift) & fc.MASK32


def request(ident=3, candidate="baseline", seed=7, values=(1, 2, 0), mode="fold", **extra):
    return {"id": ident, "candidate": candidate, "seed": seed, "values": list(values), "mode": mode, **extra}


def fake_bank(labels=("baseline", "shift_4")):
    # Unit-only owner with mocked launch.  The public factory never imports
    # these dictionaries, serialized receipts, or external native artifacts.
    bank = fc.FiniteU32Bank(fc._CONSTRUCTION, fc.checked_profile(shift_program()), labels, shift_oracle, {})
    bank._bank_sha256 = "b" * 64
    bank._driver = {"path": "unit-test-driver"}
    bank._images = tuple({"path": f"unit-test-image-{i}", "sha256": str(i) * 64} for i in range(len(labels)))
    return bank


def events(trace, images=None):
    images = len(trace.images) if images is None else images
    rows = [{"as_bytes": fc.ADDRESS_SPACE_BYTES, "core_bytes": 0, "cpu_seconds": fc.CPU_SECONDS,
             "fsize_bytes": fc.MAX_OUTPUT_BYTES, "kind": "limits", "trace": trace.sha256}]
    for image in range(images):
        for kind in ("opened", "ready"):
            rows.append({"image": image, "kind": kind, "trace": trace.sha256})
    for seq, (ident, image, mode, seed, parameter, values) in enumerate(trace.requests):
        rows.append({"candidate": image, "id": ident, "kind": "start", "seq": seq, "trace": trace.sha256})
        expected = trace.expected[seq]
        if expected[0] == "trapped":
            return rows
        rows.append({"calls": len(values), "candidate": image, "checksum": expected[2], "id": ident,
                     "kind": "result", "mode": mode, "parameter": parameter, "seed": seed, "seq": seq,
                     "state": expected[1], "trace": trace.sha256})
    for image in reversed(range(images)):
        rows.append({"image": image, "kind": "closed", "ok": True, "trace": trace.sha256})
    rows.append({"acquired": images, "closed": images, "kind": "finish", "ok": True, "trace": trace.sha256})
    return rows


def wire_rows(rows):
    return b"".join(fc._wire(row) + b"\n" for row in rows)


def result(rows, returncode=0):
    raw = wire_rows(rows)
    return CaptureResult(returncode, raw.decode(), "", raw, b"")


class FiniteContextTests(unittest.TestCase):
    def test_integer_oracle_observations_are_exact_fresh_and_need_no_json_roundtrip(self):
        with patch.object(fc, "_wire", side_effect=AssertionError("redundant integer encoding")), \
             patch.object(fc.json, "loads", side_effect=AssertionError("redundant integer decoding")):
            for value in (0, 1, 2**31, fc.MASK32):
                left, right = fc._observation(value), fc._observation(value)
                self.assertEqual(left, {"status": "returned", "values": [value]})
                self.assertIsNot(left, right)
                self.assertIsNot(left["values"], right["values"])
                left["values"].clear()
                self.assertEqual(right, {"status": "returned", "values": [value]})
        class IntSubclass(int):
            pass
        for value in (-1, fc.MASK32 + 1, True, False, 0.0, IntSubclass(1), None):
            with self.subTest(value=value), self.assertRaises(fc.FiniteContextRejected):
                fc._observation(value)
        original = {"status": "returned", "values": [7]}
        snapshot = fc._observation(original)
        original["values"][0] = 9
        self.assertEqual(snapshot, {"status": "returned", "values": [7]})
        trap = {"status": "trapped", "code": "overflow"}
        self.assertEqual(fc._observation(trap), trap)
        self.assertIsNot(fc._observation(trap), trap)
        for value in ({"status": "returned", "values": [True]},
                      {"status": "returned", "values": [fc.MASK32 + 1]},
                      {"status": "returned", "values": [0], "extra": 0},
                      {"status": "trapped", "code": "unknown-trap"}):
            with self.subTest(value=value), self.assertRaises(fc.FiniteContextRejected):
                fc._observation(value)

    def test_oracle_still_runs_for_each_step_and_keeps_the_first_trap_prefix(self):
        calls = []
        def repeated(state, value):
            calls.append((state, value))
            return 0
        self.assertEqual(fc._expected(((1, 0, 0, 0, 0, (1, 1, 1)),), repeated),
                         (("returned", 0, 0),))
        self.assertEqual(calls, [(0, 1), (0, 1), (0, 1)])
        calls.clear()
        def trap(state, value):
            calls.append((state, value))
            return {"status": "trapped", "code": "overflow"} if value == 2 else state + value
        self.assertEqual(fc._expected(((1, 0, 0, 7, 0, (1, 2, 3)),), trap),
                         (("trapped", "overflow", 1),))
        self.assertEqual(calls, [(7, 1), (8, 2)])

    def test_public_factory_requires_actual_source_profile_and_no_receipt_constructor(self):
        fc.checked_profile(shift_program())
        with self.assertRaisesRegex(fc.FiniteContextRejected, "use build_bank"):
            fc.FiniteU32Bank({}, None, (), None, {})
        program = shift_program()
        program["functions"][0]["name"] = "full_lifecycle"
        with self.assertRaisesRegex(fc.FiniteContextRejected, "only pure calculate"):
            fc.checked_profile(program)

    def test_exact_request_modes_types_and_total_budget_before_launch(self):
        bank = fake_bank()
        invalid = [request(ident=True), request(seed=True), request(values=[False]), request(values=[]),
                   request(values=[fc.MASK32 + 1]), request(mode="online"), request(candidate="foreign"),
                   request(mode="xor_fold", parameter=4, values=[256]),
                   request(mode="xor_fold", parameter=True), request(parameter=1)]
        missing = request()
        del missing["mode"]
        invalid.append(missing)
        with patch.object(fc, "run_bounded") as run:
            for item in invalid:
                with self.subTest(request=item), self.assertRaises(fc.FiniteContextRejected):
                    bank.prepare_trace([item])
            with self.assertRaisesRegex(fc.FiniteContextRejected, "unique"):
                bank.prepare_trace([request(), request()])
            with self.assertRaisesRegex(fc.FiniteContextRejected, "budget"):
                bank.prepare_trace([request(values=[1] * fc.MAX_CALLS), request(ident=4, values=[1])])
            run.assert_not_called()
        bank.close()

    def test_fold_and_xor_fold_are_explicit_immutable_and_bound(self):
        bank = fake_bank()
        first = bank.prepare_trace([request(values=[1, 2])])
        second = bank.prepare_trace([request(mode="xor_fold", parameter=1, values=[1, 2])])
        self.assertEqual(first.expected, (("returned", 56, (14 * 1099511628211 + 56) & fc.MASK64),))
        self.assertEqual(second.expected[0][1], ((7 ^ 1) << 1 ^ 2) << 1)
        self.assertNotEqual(first.sha256, second.sha256)
        self.assertNotEqual(first.payload, second.payload)
        with self.assertRaises(TypeError):
            first.expected[0][1] = 0
        bank.close()

    def test_owner_cannot_be_copied_or_serialized(self):
        bank = fake_bank()
        for operation in (copy.copy, copy.deepcopy, pickle.dumps):
            with self.assertRaises(fc.FiniteContextRejected):
                operation(bank)
        bank.close()

    def test_success_consumes_trace_and_requires_exact_whole_context_limits(self):
        bank = fake_bank()
        trace = bank.prepare_trace([request(), request(ident=4, candidate="shift_4", mode="xor_fold", parameter=4)])
        with patch.object(fc, "run_bounded", return_value=result(events(trace))) as run:
            report = bank.run(trace)
            self.assertEqual(report["status"], "completed")
            self.assertEqual([r["id"] for r in report["prefix"]["completed_requests"]], [3, 4])
            self.assertTrue(report["prefix"]["native_limits_observed"])
            self.assertFalse(report["replay_permitted"])
            self.assertGreater(report["outer_wall_ns"], 0)
            kwargs = run.call_args.kwargs
            self.assertEqual(kwargs["timeout"], fc.WALL_SECONDS)
            self.assertEqual(kwargs["stdout_limit"], fc.MAX_OUTPUT_BYTES)
            self.assertEqual(kwargs["stderr_limit"], fc.MAX_ERROR_BYTES)
            self.assertEqual(kwargs["stdin_limit"], fc.MAX_INPUT_BYTES)
            self.assertEqual(kwargs["env"], {"PATH": os.defpath, "LANG": "C", "LC_ALL": "C"})
            with self.assertRaisesRegex(fc.FiniteContextRejected, "consumed"):
                bank.run(trace)
            self.assertEqual(run.call_count, 1)
        bank.close()

    def test_static_and_dispatch_plans_load_only_referenced_images(self):
        bank = fake_bank(("baseline", "shift_4", "shift_8"))
        static = bank.prepare_trace([request(candidate="shift_8")])
        self.assertEqual(static.images, (2,))
        self.assertEqual(static.requests[0][1], 0)
        with patch.object(fc, "run_bounded", return_value=result(events(static))) as run:
            report = bank.run(static)
            self.assertEqual(run.call_args.args[0], ["unit-test-driver", static.sha256, "unit-test-image-2"])
            self.assertEqual([i["candidate"] for i in report["loaded_inventory"]], ["shift_8"])
        dispatch = bank.prepare_trace([request(candidate="shift_8"), request(ident=4, candidate="shift_4")])
        self.assertEqual(dispatch.images, (1, 2))
        self.assertEqual([r[1] for r in dispatch.requests], [1, 0])
        with patch.object(fc, "run_bounded", return_value=result(events(dispatch))) as run:
            report = bank.run(dispatch)
            self.assertEqual(run.call_args.args[0][2:], ["unit-test-image-1", "unit-test-image-2"])
            self.assertEqual([i["candidate"] for i in report["loaded_inventory"]], ["shift_4", "shift_8"])
        bank.close()

    def test_input_snapshot_cancel_and_pending_budget_release(self):
        bank = fake_bank()
        original = request()
        trace = bank.prepare_trace([original])
        digest, payload = trace.sha256, trace.payload
        original["values"][0] = 32
        original["seed"] = 0
        original["candidate"] = "foreign"
        self.assertEqual(trace.requests[0][3], 7)
        self.assertEqual(trace.requests[0][-1], (1, 2, 0))
        self.assertEqual((trace.sha256, trace.payload), (digest, payload))
        self.assertGreater(bank.state()["pending_input_bytes"], 0)
        with patch.object(fc, "run_bounded") as run:
            cancelled = bank.cancel(trace)
            self.assertFalse(cancelled["execution_attempted"])
            self.assertEqual(bank.state()["pending_input_bytes"], 0)
            with self.assertRaisesRegex(fc.FiniteContextRejected, "consumed"):
                bank.run(trace)
            run.assert_not_called()
        large = bank.prepare_trace([request(values=[fc.MASK32] * fc.MAX_CALLS)])
        self.assertGreater(bank.state()["pending_input_bytes"], fc.MAX_PENDING_INPUT_BYTES // 2)
        with self.assertRaisesRegex(fc.FiniteContextRejected, "pending trace input-byte budget"):
            bank.prepare_trace([request(ident=4, values=[fc.MASK32] * fc.MAX_CALLS)])
        bank.cancel(large)
        bank.prepare_trace([request(ident=5, values=[fc.MASK32] * fc.MAX_CALLS)])
        closed = bank.close()
        self.assertEqual(closed["pending_traces_cancelled"], 1)
        self.assertEqual(closed["pending_input_bytes"], 0)

    def test_cancelled_and_consumed_nonces_still_count_towards_bank_cap(self):
        bank = fake_bank()
        with patch.object(fc, "MAX_TRACES", 2):
            for ident in (1, 2):
                bank.cancel(bank.prepare_trace([request(ident=ident)]))
            self.assertEqual(bank.state()["registered_traces"], 2)
            self.assertEqual(bank.state()["pending_traces"], 0)
            with self.assertRaisesRegex(fc.FiniteContextRejected, "trace budget"):
                bank.prepare_trace([request(ident=3)])
        bank.close()

    def test_altered_trace_or_foreign_bank_cannot_launch(self):
        bank, other = fake_bank(), fake_bank()
        trace = bank.prepare_trace([request()])
        with patch.object(fc, "run_bounded") as run:
            with self.assertRaisesRegex(fc.FiniteContextRejected, "foreign"):
                other.run(trace)
            object.__setattr__(trace, "payload", trace.payload + "0\n")
            with self.assertRaisesRegex(fc.FiniteContextRejected, "altered"):
                bank.run(trace)
            run.assert_not_called()
        bank.close()
        other.close()

    def test_bad_canonical_records_do_not_promote_a_forged_completed_prefix(self):
        bank = fake_bank()
        trace = bank.prepare_trace([request()])
        good = events(trace)
        result_index = next(i for i, r in enumerate(good) if r["kind"] == "result")
        for change in ({"checksum": 0}, {"seq": False}, {"calls": True}, {"trace": "f" * 64},
                       {"parameter": 1}, {"id": 4}):
            bad = copy.deepcopy(good)
            bad[result_index].update(change)
            row = fc._parse_prefix(wire_rows(bad), trace, len(trace.images))
            self.assertFalse(row["complete"])
            self.assertEqual(row["completed_requests"], [])
            self.assertIsNotNone(row["prefix_error"])
        for raw in (wire_rows(good).replace(b"\n", b"\r\n"),
                    wire_rows(good[:result_index]) + fc._wire(good[result_index])[:-1] + b',"calls":3}\n'):
            row = fc._parse_prefix(raw, trace, len(trace.images))
            self.assertFalse(row["complete"])
            self.assertEqual(row["completed_requests"], [])
        bank.close()

    def test_order_duplicate_trailing_and_changed_limit_events_cannot_pass(self):
        bank = fake_bank()
        trace = bank.prepare_trace([request()])
        good = events(trace)
        cases = [good + [good[-1]], good[:-1], good[1:], good[:2] + [good[1]] + good[2:]]
        changed_limit = copy.deepcopy(good)
        changed_limit[0]["cpu_seconds"] += 1
        cases.append(changed_limit)
        for rows in cases:
            self.assertFalse(fc._parse_prefix(wire_rows(rows), trace, len(trace.images))["complete"])
        self.assertFalse(fc._parse_prefix(wire_rows(good) + b"\n", trace, len(trace.images))["complete"])
        bank.close()

    def test_signal_keeps_completed_prefix_and_poison_prevents_any_replay(self):
        bank = fake_bank()
        trace = bank.prepare_trace([request(), request(ident=4, values=[32]), request(ident=5)])
        native = result(events(trace), returncode=-signal.SIGABRT)
        pending = bank.prepare_trace([request(ident=10)])
        report = {}
        with patch.object(fc, "run_bounded", return_value=native) as run:
            with self.assertRaisesRegex(fc.FiniteContextRejected, "native context failed"):
                bank.run(trace, report=report)
            self.assertEqual([r["id"] for r in report["prefix"]["completed_requests"]], [3])
            self.assertEqual(report["prefix"]["pending_request_seq"], 1)
            self.assertEqual(report["status"], "failed-no-replay")
            self.assertEqual(report["pending_traces_cancelled"], 1)
            self.assertEqual(bank.state()["pending_input_bytes"], 0)
            self.assertEqual(bank.state()["registered_traces"], 2)
            for action in (lambda: bank.run(trace), lambda: bank.prepare_trace([request(ident=6)])):
                with self.assertRaisesRegex(fc.FiniteContextRejected, "poisoned"):
                    action()
            self.assertEqual(run.call_count, 1)
        bank.close()

    def test_timeout_output_and_cleanup_failures_keep_raw_prefix_and_no_replay(self):
        for code in ("E_CAPTURE_TIMEOUT", "E_CAPTURE_OUTPUT_SIZE", "E_CAPTURE_CLEANUP"):
            bank = fake_bank()
            trace = bank.prepare_trace([request(), request(ident=4)])
            all_rows = events(trace)
            end = next(i for i, r in enumerate(all_rows) if r["kind"] == "start" and r["seq"] == 1)
            partial_rows = all_rows[:end + 1]  # One complete result, then second request start.
            raw = wire_rows(partial_rows) + b'{"incomplete":'
            failure = CaptureRejected(code, "injected bounded capture failure")
            failure.capture = CaptureFailure(("owned-context",), -9, raw, b"diagnostic\x00", len(raw) + 20, 11)
            if code == "E_CAPTURE_CLEANUP":
                failure.capture_error = "leader cleanup remains uncertain"
            report = {}
            with patch.object(fc, "run_bounded", side_effect=failure) as run:
                with self.assertRaises(CaptureRejected):
                    bank.run(trace, report=report)
                self.assertEqual(b64decode(report["raw_stdout_base64"]), raw)
                self.assertEqual(b64decode(report["raw_stderr_base64"]), b"diagnostic\x00")
                self.assertEqual(report["capture_failure"]["stdout_total_bytes"], len(raw) + 20)
                self.assertEqual([r["id"] for r in report["prefix"]["completed_requests"]], [3])
                self.assertIsNotNone(report["prefix"]["prefix_error"])
                with self.assertRaisesRegex(fc.FiniteContextRejected, "poisoned"):
                    bank.run(trace)
                self.assertEqual(run.call_count, 1)
            if code == "E_CAPTURE_CLEANUP":
                self.assertEqual(report["owned_child_cleanup"], "uncertain")
            bank.close()

    def test_partial_load_fault_closes_acquired_images_once_in_reverse_order(self):
        bank = fake_bank()
        trace = bank.prepare_trace([request(), request(ident=4, candidate="shift_4")])
        good = events(trace)
        prefix = good[:3] + [{"code": 86, "image": 1, "kind": "fault", "trace": trace.sha256},
            {"image": 0, "kind": "closed", "ok": True, "trace": trace.sha256},
            {"acquired": 1, "closed": 1, "kind": "finish", "ok": False, "trace": trace.sha256}]
        parsed = fc._parse_prefix(wire_rows(prefix), trace, len(trace.images))
        self.assertIsNone(parsed["prefix_error"])
        self.assertEqual(parsed["opened_images"], [0])
        self.assertEqual(len(parsed["close_attempts"]), 1)
        self.assertTrue(parsed["finish_observed"])
        self.assertFalse(parsed["complete"])
        self.assertFalse(fc._parse_prefix(wire_rows(prefix[:-1] + [prefix[-2], prefix[-1]]), trace, len(trace.images))["complete"])
        bank.close()

    def test_uncertain_descriptor_close_retains_debt_and_never_retries_number(self):
        bank = fake_bank()
        bank._pins.append({"release": fc._NativeRelease(library=None, fd=123456)})
        with patch.object(fc.os, "close", side_effect=OSError("close outcome unknown")) as close:
            first = bank.close()
            second = bank.close()
            self.assertEqual(first, second)
            self.assertFalse(first["complete"])
            self.assertEqual(first["descriptors"][0]["native"]["fd"]["status"], "unknown")
            self.assertFalse(first["retry_permitted"])
            self.assertEqual(close.call_count, 1)
            first["complete"] = True
            bank._report["release"]["complete"] = True
            self.assertFalse(bank.close()["complete"])

    def test_unpublished_pin_close_uncertainty_is_retained_and_never_retried(self):
        bank = fake_bank()
        def failed_pin(path, *, maximum_bytes, close_owner):
            close_owner(123456)
        with patch.object(fc, "_pin_native_artifact", side_effect=failed_pin), \
             patch.object(fc.os, "close", side_effect=OSError("unknown early close")) as close:
            with self.assertRaisesRegex(fc.FiniteContextRejected, "unpublished descriptor"):
                bank._pin("unused.so", "a" * 64)
            report = bank.close()
            self.assertFalse(report["complete"])
            self.assertEqual(report["unpublished_descriptors"][0]["native"]["fd"]["status"], "unknown")
            bank.close()
            self.assertEqual(close.call_count, 1)

    def test_uncertain_child_cleanup_retains_image_pins_after_close(self):
        bank = fake_bank()
        trace = bank.prepare_trace([request()])
        release = fc._NativeRelease(library=None, fd=123456)
        bank._pins.append({"release": release})
        failure = CaptureRejected("E_CAPTURE_CLEANUP", "owned leader reap uncertain")
        failure.capture = CaptureFailure(("owned-context",), None, b"", b"", 0, 0)
        with patch.object(bank, "_open"), patch.object(fc, "run_bounded", side_effect=failure), \
             patch.object(fc.os, "close") as close:
            with self.assertRaises(CaptureRejected) as caught:
                bank.run(trace)
            self.assertIs(caught.exception.finite_context_owner, bank)
            first = bank.close()
            second = bank.close()
            self.assertEqual(first, second)
            self.assertFalse(first["complete"])
            self.assertTrue(first["pins_retained_for_uncertain_child"])
            self.assertFalse(release.attempted)
            close.assert_not_called()

    def test_diagnostic_depth_or_allocation_failure_cannot_erase_cleanup_debt(self):
        for diagnostic in ("deep-json", "memory-error"):
            bank = fake_bank()
            trace = bank.prepare_trace([request()])
            release = fc._NativeRelease(library=None, fd=123456)
            bank._pins.append({"release": release})
            raw = b"[" * 10000 + b"]" * 10000 + b"\n"
            failure = CaptureRejected("E_CAPTURE_CLEANUP", "owned leader reap uncertain")
            failure.capture = CaptureFailure(("owned-context",), None, raw, b"", len(raw), 0)
            report = {}
            parse = fc._parse_prefix
            def parse_or_fail(*args):
                if diagnostic == "memory-error":
                    raise MemoryError("injected diagnostic allocation failure")
                return parse(*args)
            with patch.object(bank, "_open"), patch.object(fc, "run_bounded", side_effect=failure), \
                 patch.object(fc, "_parse_prefix", side_effect=parse_or_fail), patch.object(fc.os, "close") as close:
                with self.assertRaises(CaptureRejected) as caught:
                    bank.run(trace, report=report)
                self.assertIs(caught.exception, failure)
                self.assertIs(caught.exception.finite_context_owner, bank)
                self.assertEqual(report["owned_child_cleanup"], "uncertain")
                self.assertEqual(b64decode(report["raw_stdout_base64"]), raw)
                if diagnostic == "memory-error":
                    self.assertEqual(report["diagnostic_error"], "MemoryError")
                else:
                    self.assertIn("oversized", report["prefix"]["prefix_error"]["message"])
                self.assertFalse(bank.close()["complete"])
                self.assertFalse(release.attempted)
                close.assert_not_called()

    def test_unknown_or_disproved_translation_cannot_emit_compile_or_execute(self):
        root = fc.checked_profile(shift_program())
        for status in ("unknown", "disproved"):
            report = {}
            with patch.object(fc, "validate_translation", return_value={"status": status}):
                with patch.object(fc, "emit_program_llvm") as emit, patch.object(fc, "compile_program_llvm") as compile:
                    with self.assertRaisesRegex(fc.FiniteContextRejected, "first-trap proof"):
                        fc._build_image(root, root, Path("unused.so"), clang="unused", cases=[[0, 0]],
                                        oracle=shift_oracle, report=report)
                    emit.assert_not_called()
                    compile.assert_not_called()
            self.assertGreater(report["preparation_wall_ns"], 0)

    def test_unverified_lowering_cannot_reach_compiler(self):
        root = fc.checked_profile(shift_program())
        proof = {"status": "proved", "before_sha256": root.sha256, "after_sha256": root.sha256}
        with patch.object(fc, "validate_translation", return_value=proof), \
             patch.object(fc, "verify_scalar_lowering", return_value={"status": "unknown"}), \
             patch.object(fc, "compile_program_llvm") as compile:
            with self.assertRaisesRegex(fc.FiniteContextRejected, "LLVM check"):
                fc._build_image(root, root, Path("unused.so"), clang="unused", cases=[[0, 0]],
                                oracle=shift_oracle, report={})
            compile.assert_not_called()

    def test_bank_report_edits_are_not_execution_authority(self):
        bank = fake_bank()
        bank._report["bank_sha256"] = "forged-exported-report"
        trace = bank.prepare_trace([request()])
        with patch.object(fc, "run_bounded", return_value=result(events(trace))):
            report = bank.run(trace)
        self.assertEqual(report["bank_sha256"], "b" * 64)
        bank.close()


CLANG = os.environ.get("CLANG") or shutil.which("clang-20") or shutil.which("clang")
NATIVE = bool(CLANG and platform.system() == "Linux" and platform.machine().lower() in {"x86_64", "amd64"}
              and importlib.util.find_spec("z3"))


@unittest.skipUnless(NATIVE, "actual Linux x86-64 Clang20+, Z3 and memfd seals required")
class FiniteContextNativeTests(unittest.TestCase):
    def test_real_bank_context_switch_seals_limits_partial_load_and_first_trap_prefix(self):
        # A few scalar calls establish correctness only.  There is no economic
        # protocol, cost comparison, timing selection, or native benchmark.
        program = shift_program()
        proposals = propose_guarded_specializations(program, function="calculate", assumptions=[
            {"parameter": "shift", "value": 4}, {"parameter": "shift", "value": 8}])
        candidates = {"baseline": program, "shift_4": proposals[0]["program"], "shift_8": proposals[1]["program"]}
        cases = [[0, 0], [1, 1], [7, 4], [7, 8], [fc.MASK32, 31], [1, 32], [fc.MASK32, fc.MASK32]]
        with tempfile.TemporaryDirectory(prefix="hia-finite-context-correctness-") as temporary:
            preparation = {}
            with fc.build_bank(program, candidates, temporary, clang=CLANG, cases=cases,
                               oracle=shift_oracle, report=preparation) as bank:
                self.assertEqual(len(bank.labels), 3)
                # Clang can merge equivalent shift specializations into the same
                # code; labels and contexts do not establish an optimization win.
                self.assertTrue(all(r["code"]["bytes"] > 0 for r in preparation["candidates"].values()))
                for entry in preparation["candidates"].values():
                    self.assertEqual(entry["translation"]["status"], "proved")
                    self.assertEqual(entry["lowering"]["status"], "verified")
                    self.assertEqual(entry["native_differential"]["cases_executed"], len(cases))
                # Original pathnames cease to designate executable bytes;
                # execution still uses the held, identity-checked sealed copies.
                for path in Path(temporary).glob("*.so"):
                    path.write_bytes(b"pathname replaced after internal admission")
                Path(preparation["driver"]["path"]).write_bytes(b"driver pathname replaced")
                trace = bank.prepare_trace([request(), request(ident=4, candidate="shift_4", seed=9,
                    mode="xor_fold", parameter=4, values=[2, 3, 255]),
                    request(ident=5, candidate="shift_8", seed=1, values=[8, 1])])
                # First establish that the real harmless interposer runs under
                # inherited/explicit hostile loader configuration.  The context
                # must exclude it before exec, not after the constructor ran.
                marker = Path(temporary) / "foreign-constructor.txt"
                interposer_source = Path(temporary) / "preload.c"
                interposer = Path(temporary) / "preload.so"
                interposer_source.write_text('#include <stdio.h>\n'
                    '__attribute__((constructor)) static void marker(void) {\n'
                    f'FILE *f = fopen({json.dumps(str(marker))}, "w");\n'
                    'if (f) { fputs("foreign-constructor-ran", f); fclose(f); }\n}\n', encoding="ascii")
                compiled = fc.run_bounded([CLANG, "-std=c11", "-shared", "-fPIC", str(interposer_source),
                                           "-o", str(interposer)], timeout=30)
                self.assertEqual(compiled.returncode, 0)
                control = fc.run_bounded([shutil.which("true")], timeout=3,
                    env={"PATH": os.defpath, "LANG": "C", "LC_ALL": "C", "LD_PRELOAD": str(interposer)})
                self.assertEqual(control.returncode, 0)
                self.assertEqual(marker.read_text(), "foreign-constructor-ran")
                marker.unlink()
                with patch.dict(os.environ, {"LD_PRELOAD": str(interposer), "LD_AUDIT": str(interposer),
                                             "LD_LIBRARY_PATH": temporary, "GLIBC_TUNABLES": "glibc.malloc.check=1"}):
                    observation = bank.run(trace)
                self.assertFalse(marker.exists())
                self.assertEqual(observation["child_environment"], {"PATH": os.defpath, "LANG": "C", "LC_ALL": "C"})
                self.assertEqual(observation["returncode"], 0)
                self.assertEqual([r["id"] for r in observation["prefix"]["completed_requests"]], [3, 4, 5])
                self.assertEqual(observation["prefix"]["opened_images"], [0, 1, 2])
                self.assertEqual([r["image"] for r in observation["prefix"]["close_attempts"]], [2, 1, 0])
                self.assertTrue(observation["prefix"]["native_limits_observed"])
                with self.assertRaisesRegex(fc.FiniteContextRejected, "consumed"):
                    bank.run(trace)

                # Fault injection is below the public admission API: the same
                # fixed sealed driver sees a missing second path and must close
                # the first mapping, without running/replaying any request.
                low_trace = bank.prepare_trace([request(ident=10), request(ident=11, candidate="shift_4"),
                                                request(ident=12, candidate="shift_8")])
                command = [bank._driver["path"], low_trace.sha256, bank._images[0]["path"],
                           str(Path(temporary) / "missing-image"), bank._images[2]["path"]]
                partial = fc.run_bounded(command, input_text=low_trace.payload, timeout=fc.WALL_SECONDS,
                                         stdout_limit=fc.MAX_OUTPUT_BYTES, stderr_limit=fc.MAX_ERROR_BYTES)
                self.assertEqual(partial.returncode, 86)
                prefix = fc._parse_prefix(partial.raw_stdout, low_trace, 3)
                self.assertIsNone(prefix["prefix_error"])
                self.assertEqual(prefix["opened_images"], [0])
                self.assertEqual([r["image"] for r in prefix["close_attempts"]], [0])
                self.assertEqual(prefix["completed_requests"], [])
                self.assertFalse(prefix["complete"])

                # Actual capture quota, not mocked cleanup or decoded stdout.
                command = [bank._driver["path"], low_trace.sha256, *(p["path"] for p in bank._images)]
                with self.assertRaises(CaptureRejected) as overflow:
                    fc.run_bounded(command, input_text=low_trace.payload, timeout=fc.WALL_SECONDS,
                                   stdout_limit=1, stderr_limit=fc.MAX_ERROR_BYTES)
                self.assertEqual(overflow.exception.code, "E_CAPTURE_OUTPUT_SIZE")
                self.assertEqual(len(overflow.exception.capture.stdout), 1)
                self.assertGreater(overflow.exception.capture.stdout_total_bytes, 1)

                invalid = fc.run_bounded(command, input_text="1\n10 0 0 7 0 65537 1\n",
                                         timeout=fc.WALL_SECONDS, stdout_limit=fc.MAX_OUTPUT_BYTES,
                                         stderr_limit=fc.MAX_ERROR_BYTES)
                self.assertEqual(invalid.returncode, 84)
                self.assertEqual(invalid.raw_stdout, b"")

                # A real Core-defined shift trap terminates the child after one
                # completed request.  Its signal is not an exact trap-code proof.
                trap_trace = bank.prepare_trace([request(ident=20), request(ident=21, values=[32]), request(ident=22)])
                failed = {}
                with self.assertRaisesRegex(fc.FiniteContextRejected, "native context failed"):
                    bank.run(trap_trace, report=failed)
                self.assertEqual(failed["returncode"], -signal.SIGABRT)
                self.assertEqual([r["id"] for r in failed["prefix"]["completed_requests"]], [20])
                self.assertEqual(failed["prefix"]["pending_request_seq"], 1)
                self.assertEqual(failed["owned_child_cleanup"], "confirmed_by_bounded_capture")
                with self.assertRaisesRegex(fc.FiniteContextRejected, "poisoned"):
                    bank.run(trap_trace)
            self.assertTrue(preparation["release"]["complete"])
            self.assertEqual(len(preparation["release"]["descriptors"]), 4)
            self.assertFalse(preparation["economic_benefit_proved"])


if __name__ == "__main__":
    unittest.main()
