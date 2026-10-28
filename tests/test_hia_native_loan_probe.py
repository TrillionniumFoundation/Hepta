"""Actual native loan handshakes across version activation, rollback and drain."""
from __future__ import annotations

import errno
from hashlib import sha256
import os
from pathlib import Path
import platform
import shutil
import struct
import tempfile
import unittest
from unittest import mock

from hepta.hia_fill_loop_opt import PASS_ID as FILL_PASS, rewrite_full_view_fill_loop
from hepta.hia_native_differential import HIADifferentialRejected
from hepta.hia_native_loan_probe import CONFIGURE, checked_site, compile_probe, emit_probe
import hepta.hia_native_loan_probe as probe
from hepta.hia_native_version_dispatch import HIANativeDispatchRejected, NativeVersionDispatcher
from hepta.hia_ndu import HIANDURejected
from hepta.hia_program import verify_program
from hepta.hia_program_llvm import emit_program_llvm
from hepta.hia_program_runtime import execute_program
from tests.test_hia_fill_loop_opt import fill_loop_program
from tests.test_hia_native_version_dispatch import programs
from tests.test_hia_program import b, f, i, m, ret

CLANG = shutil.which("clang-20")
SITE = ("swap_candidate", "entry", "loan")


def fill_programs():
    document = fill_loop_program()
    names = ("size", "value", "probe", "mask")
    params = [(name, "u32") for name in names]
    operations = [i("int.cast", [name], [(name + "64", "usize")], mode="checked") for name in names]
    operations += [i("call", [name + "64" for name in names], [("byte", "u8")], function="fill_probe"),
                   i("int.cast", ["byte"], [("answer", "u32")], mode="checked")]
    document["functions"].append(f("native_fill", params, ["u32"], ["alloc", "read", "write", "trap"],
        [b("entry", params, operations, ret("answer"))]))
    document["exports"] = ["native_fill"]
    core = verify_program(document)
    return core, rewrite_full_view_fill_loop(core).program


def length_only_program():
    params = [("length", "u32")]
    document = m(f("native_length", params, ["u32"], ["alloc", "read", "trap"], [
        b("entry", params, [
            i("int.cast", ["length"], [("size", "usize")], mode="checked"),
            i("buffer.new", ["size"], [("owner", "buffer")]),
            i("borrow.read", ["owner"], [("loan", "readbuf")]),
            i("buffer.len", ["loan"], [("observed", "usize")]),
            i("loan.end", ["loan"]), i("owner.drop", ["owner"]),
            i("int.cast", ["observed"], [("answer", "u32")], mode="checked"),
        ], ret("answer")),
    ]))
    document["exports"] = ["native_length"]
    return verify_program(document)


class NativeLoanEmissionTests(unittest.TestCase):
    def test_exact_site_identity_and_diagnostic_only_emission(self):
        baseline, candidate = programs()
        normal = emit_program_llvm(baseline)
        before = emit_probe(baseline, SITE)
        after = emit_probe(candidate, SITE)
        self.assertEqual(emit_program_llvm(baseline), normal)
        self.assertEqual(before["ordinary_llvm_sha256"], normal.sha256)
        self.assertEqual(before["core_sha256"], baseline.sha256)
        self.assertNotEqual(before["sha256"], normal.sha256)
        self.assertNotEqual(before["sha256"], after["sha256"])
        self.assertEqual(before["exports"], (CONFIGURE, "native_swap"))
        self.assertEqual(before["site"]["borrow_index"], 1)
        self.assertEqual(before["site"]["borrow_operation"], "borrow.mut")
        self.assertEqual(before["text"].count("call void @__hia_probe_begin(%hia.buffer"), 1)
        self.assertEqual(before["text"].count("call void @__hia_probe_end(%hia.buffer"), 1)
        self.assertNotIn("__hia_probe_", normal.text)
        self.assertNotIn("declare i64 @read", before["text"])
        self.assertNotIn("declare i64 @write", before["text"])
        self.assertIn(str(probe._MAGIC), before["text"])

    def test_diagnostic_reads_force_core_zero_initialization(self):
        core = length_only_program()
        normal = emit_program_llvm(core)
        instrumented = emit_probe(core, ("native_length", "entry", "loan"))
        self.assertIn("i1 false)", normal.text)
        self.assertIn("call %hia.alloc @__hia_allocate(i64 %t1, i1 true)", instrumented["text"])
        self.assertEqual(instrumented["site"]["borrow_operation"], "borrow.read")

    def test_invalid_sites_absent_borrows_and_nonlocal_owners_refuse(self):
        core = programs()[0]
        for site in (None, [], list(SITE), ("f", "b"), ("f", "b", True), ("f", "b", "../loan")):
            with self.subTest(site=site), self.assertRaises(HIADifferentialRejected):
                checked_site(site)
        for site in (("absent", "entry", "loan"), ("swap_candidate", "absent", "loan"),
                     ("swap_candidate", "entry", "owner"), ("swap_candidate", "entry", "answer")):
            with self.subTest(site=site), self.assertRaises(HIADifferentialRejected):
                emit_probe(core, site)
        structured = core.as_dict()
        structured["schema"] = "hepta.hia.program.v7"
        with self.assertRaisesRegex(HIADifferentialRejected, "v1-v6"):
            emit_probe(verify_program(structured), SITE)
        owner_params = [("owner", "buffer")]
        consumer = f("consume", owner_params, ["u32"], ["alloc", "read", "trap"], [
            b("entry", owner_params, [
                i("borrow.read", ["owner"], [("loan", "readbuf")]),
                i("buffer.len", ["loan"], [("size", "usize")]),
                i("loan.end", ["loan"]), i("owner.drop", ["owner"]),
                i("int.cast", ["size"], [("answer", "u32")], mode="checked"),
            ], ret("answer")),
        ])
        outer = length_only_program().as_dict()["functions"][0]
        outer["blocks"][0]["ops"] = outer["blocks"][0]["ops"][:2] + [
            i("call", ["owner"], [("answer", "u32")], function="consume")]
        data = m(consumer, outer)
        data["exports"] = ["native_length"]
        with self.assertRaisesRegex(HIADifferentialRejected, "local allocation"):
            emit_probe(verify_program(data), ("consume", "entry", "loan"))

    def test_recursive_selected_function_refuses_instead_of_misattributing_loan_end(self):
        data = length_only_program().as_dict()
        data["functions"][0]["blocks"][0]["ops"].insert(3,
            i("call", ["length"], [("recursive_result", "u32")], function="native_length"))
        core = verify_program(data)
        with self.assertRaisesRegex(HIADifferentialRejected, "recursively re-enter"):
            emit_probe(core, ("native_length", "entry", "loan"))

    def test_records_fail_closed_without_claiming_native_execution(self):
        # Synthetic protocol negatives are separate from real native controls.
        class Version:
            core_sha256 = "a" * 64
            artifact_sha256 = "b" * 64
            @staticmethod
            def receipt():
                return {"loan_probe_site": {"loan": "x"}}
        with mock.patch.object(probe.Thread, "start"):
            handle = probe.NativeLoanExecution(version=Version(), generation=0, function="f", word="u32",
                                               arguments=(), timeout=1, release=lambda: None)
        for values in ((0, 1, 5, 0, 0), (probe._MAGIC, 2, 5, 0, 0),
                       (probe._MAGIC, 1, 0, 1, 0), (probe._MAGIC, 1, 5, 256, 0),
                       (probe._MAGIC, 1, 2**63, 0, 0)):
            with self.subTest(values=values), self.assertRaises(HIADifferentialRejected):
                handle._record(struct.pack("<QQQQQ", *values))
        handle._record(struct.pack("<QQQQQ", probe._MAGIC, 1, 5, 0, 0))
        with self.assertRaisesRegex(HIADifferentialRejected, "out-of-order"):
            handle._record(struct.pack("<QQQQQ", probe._MAGIC, 1, 5, 0, 0))
        with self.assertRaisesRegex(HIADifferentialRejected, "out-of-order"):
            handle._record(struct.pack("<QQQQQ", probe._MAGIC, 2, 5, 0, 0))
        handle._ack_sent = True
        with self.assertRaisesRegex(HIADifferentialRejected, "out-of-order"):
            handle._record(struct.pack("<QQQQQ", probe._MAGIC, 2, 6, 0, 0))


@unittest.skipUnless(platform.system() == "Linux" and platform.machine().lower() in {"x86_64", "amd64"}
                     and CLANG and hasattr(os, "memfd_create"), "requires Linux x86-64, sealed memfd and Clang 20")
class NativeLoanExecutionTests(unittest.TestCase):
    def host(self, baseline=None, site=SITE, **kwargs):
        baseline = programs()[0] if baseline is None else baseline
        host = NativeVersionDispatcher(baseline.canonical_bytes, clang=CLANG,
                                       diagnostic_loan_site=site, **kwargs)
        self.addCleanup(host.close)
        return host

    def stage(self, host, candidate=None, **kwargs):
        candidate = programs()[1] if candidate is None else candidate
        queued = host.stage_candidate_async(candidate.canonical_bytes, **kwargs)
        completed = host.wait_candidate(queued["job_id"], timeout=20)
        self.assertEqual(completed["status"], "staged", completed)
        return completed

    def finish(self, call, expected=55):
        call.resume()
        result = call.wait()
        self.assertEqual(result["status"], "returned", result)
        self.assertEqual(result["value"], expected)
        self.assertEqual([event["event"] for event in result["observation"]["events"]],
                         ["loan_started", "loan_ended"])
        self.assertFalse(result["claims"]["full_resource_ledger_observed"])
        return result

    def test_actual_compile_receipt_binds_core_location_ir_and_artifact(self):
        baseline, _ = programs()
        with tempfile.TemporaryDirectory() as directory:
            artifact = Path(directory) / "probe.so"
            ir, receipt = compile_probe(baseline, SITE, artifact, CLANG)
            self.assertEqual(sha256(artifact.read_bytes()).hexdigest(), receipt["artifact_sha256"])
            self.assertEqual(sha256(receipt["llvm_ir"].encode()).hexdigest(), receipt["llvm_ir_sha256"])
            self.assertEqual(ir["site"], receipt["loan_probe_site"])
            self.assertEqual(receipt["core_sha256"], baseline.sha256)
            self.assertEqual(receipt["exports"], [CONFIGURE, "native_swap"])
            self.assertFalse(receipt["claims"]["production_artifact"])
            with self.assertRaisesRegex(HIADifferentialRejected, "new diagnostic output"):
                compile_probe(baseline, SITE, artifact, CLANG)

    def test_real_loan_keeps_old_image_alive_across_activation_and_rollback(self):
        baseline, candidate = programs()
        with self.host() as host:
            self.stage(host)
            old = host.start_loan_probe("native_swap", [5, 0, 4, 0])
            held = old.wait_active()
            self.assertTrue(held["held"])
            self.assertEqual(held["events"], [{"event": "loan_started", "bytes": 5,
                "first_byte": 0, "last_byte": 0, "selected_loan_active": True}])
            self.assertEqual(held["program_sha256"], baseline.sha256)
            host.activate(candidate.sha256, expected_generation=0)
            self.assertEqual(host.snapshot()["in_flight"], 1)
            current = host.start_loan_probe("native_swap", [5, 0, 4, 0])
            self.assertEqual(current.wait_active()["generation"], 1)
            self.finish(current)
            result = self.finish(old)
            self.assertEqual(result["generation"], 0)
            self.assertEqual(result["observation"]["events"][1]["first_byte"], 55)
            self.assertEqual(result["observation"]["events"][1]["last_byte"], 11)
            candidate_fd = host._versions[candidate.sha256].descriptor
            candidate_call = host.start_loan_probe("native_swap", [5, 0, 4, 0])
            self.assertEqual(candidate_call.wait_active()["program_sha256"], candidate.sha256)
            host.rollback(expected_generation=1)
            draining = next(row for row in host.snapshot()["versions"] if row["sha256"] == candidate.sha256)
            self.assertEqual((draining["state"], draining["in_flight"]), ("draining", 1))
            self.assertGreater(os.fstat(candidate_fd).st_size, 0)
            self.assertEqual(host.snapshot()["retired_versions"], 0)
            result = self.finish(candidate_call)
            self.assertEqual(result["generation"], 1)
            with self.assertRaises(OSError) as error:
                os.fstat(candidate_fd)
            self.assertEqual(error.exception.errno, errno.EBADF)
            self.assertEqual(host.snapshot()["retired_versions"], 1)
            self.assertEqual(host.snapshot()["in_flight"], 0)

    def test_real_loan_survives_close_until_ack_and_exact_call_budget(self):
        _, candidate = programs()
        host = self.host(max_in_flight=1)
        self.stage(host)
        host.activate(candidate.sha256, expected_generation=0)
        call = host.start_loan_probe("native_swap", [5, 0, 4, 0])
        call.wait_active()
        candidate_fd = host._versions[candidate.sha256].descriptor
        with self.assertRaisesRegex(HIANativeDispatchRejected, "call budget"):
            host.start_loan_probe("native_swap", [5, 0, 4, 0])
        self.assertFalse(host.close(wait=False)["drained"])
        self.assertGreater(os.fstat(candidate_fd).st_size, 0)
        with self.assertRaisesRegex(HIANativeDispatchRejected, "closed"):
            host.start_loan_probe("native_swap", [5, 0, 4, 0])
        self.finish(call)
        self.assertTrue(host.snapshot()["drained"])
        self.assertEqual(host.snapshot()["released_artifacts"], 2)

    def test_withheld_ack_times_out_and_preserves_partial_loan_observation(self):
        with self.host() as host:
            call = host.start_loan_probe("native_swap", [5, 0, 4, 0], timeout=0.5)
            call.wait_active(timeout=0.4)
            with self.assertRaisesRegex(HIADifferentialRejected, "timed out"):
                call.wait(timeout=3)
            snapshot = call.snapshot()
            self.assertTrue(snapshot["done"])
            self.assertFalse(snapshot["held"])
            self.assertFalse(snapshot["ack_sent"])
            self.assertEqual(len(snapshot["events"]), 1)
            self.assertTrue(snapshot["events"][0]["selected_loan_active"])
            self.assertEqual(host.snapshot()["in_flight"], 0)
            with self.assertRaisesRegex(HIADifferentialRejected, "currently held"):
                call.resume()

    def test_actual_trap_during_loan_retains_no_fabricated_loan_end(self):
        with self.host() as host:
            call = host.start_loan_probe("native_swap", [5, 5, 0, 0])
            call.wait_active()
            call.resume()
            result = call.wait()
            self.assertEqual(result["status"], "trapped")
            self.assertFalse(result["claims"]["native_trap_reason_proved"])
            self.assertEqual(len(result["observation"]["events"]), 1)
            self.assertEqual(host.snapshot()["in_flight"], 0)

    def test_real_read_loan_observes_empty_and_initialized_unread_buffers(self):
        core = length_only_program()
        with self.host(core, ("native_length", "entry", "loan")) as host:
            for length in (0, 1, 4096):
                with self.subTest(length=length):
                    call = host.start_loan_probe("native_length", [length])
                    held = call.wait_active()
                    self.assertEqual(held["events"][0]["bytes"], length)
                    self.assertEqual(held["events"][0]["first_byte"], 0)
                    self.assertEqual(held["events"][0]["last_byte"], 0)
                    self.finish(call, length)

    def test_allocation_refusal_before_loan_never_claims_observed_loan(self):
        with self.host() as host:
            call = host.start_loan_probe("native_swap", [2**32 - 1, 0, 4, 0])
            result = call.wait()
            self.assertEqual(result["status"], "trapped")
            self.assertEqual(result["observation"]["events"], [])
            with self.assertRaisesRegex(HIADifferentialRejected, "no longer held"):
                call.wait_active()
            self.assertEqual(host.snapshot()["in_flight"], 0)

    def test_registered_fill_candidate_with_cross_call_loan_has_real_handshake(self):
        baseline, candidate = fill_programs()
        with self.host(baseline, ("fill_probe", "entry", "view")) as host:
            with self.assertRaisesRegex(HIANativeDispatchRejected, "exact reproduced"):
                host.stage_candidate_async(candidate.canonical_bytes)
            staged = self.stage(host, candidate, pass_id=FILL_PASS)
            self.assertEqual(staged["pass_id"], FILL_PASS)
            self.assertEqual(staged["rewrite_replacements"], 1)
            host.activate(candidate.sha256, expected_generation=0)
            call = host.start_loan_probe("native_fill", [512, 173, 511, 7])
            held = call.wait_active()
            self.assertEqual(held["events"][0]["bytes"], 512)
            self.assertEqual(held["events"][0]["first_byte"], 0)
            result = self.finish(call, execute_program(candidate, "native_fill", [512, 173, 511, 7])["result"])
            self.assertEqual(result["observation"]["events"][1]["first_byte"], 173)
            self.assertEqual(result["observation"]["events"][1]["last_byte"], 173)
            self.assertEqual(host.snapshot()["in_flight"], 0)

    def test_registered_fill_runs_without_instrumentation_and_bad_pass_refuses(self):
        baseline, candidate = fill_programs()
        with NativeVersionDispatcher(baseline.canonical_bytes, clang=CLANG) as host:
            for pass_id in ("not-registered", True, None, "full-view-fill-loop.v2"):
                with self.subTest(pass_id=pass_id), self.assertRaises(HIANDURejected):
                    host.stage_candidate_async(candidate.canonical_bytes, pass_id=pass_id)
            self.stage(host, candidate, pass_id=FILL_PASS)
            host.activate(candidate.sha256, expected_generation=0)
            self.assertEqual(host.execute("native_fill", [7, 173, 6, 7])["value"], 170)
            self.assertFalse(host.snapshot()["claims"]["diagnostic_loan_instrumentation"])
            with self.assertRaisesRegex(HIANativeDispatchRejected, "diagnostic images"):
                host.start_loan_probe("native_fill", [7, 173, 6, 7])

    def test_diagnostic_images_cannot_enter_ordinary_execute_and_invalid_args_refuse(self):
        with self.host() as host:
            with self.assertRaisesRegex(HIANativeDispatchRejected, "explicit acknowledgement"):
                host.execute("native_swap", [5, 0, 4, 0])
            for args in ([5, 0, 4], [True, 0, 4, 0], [2**32, 0, 4, 0]):
                with self.assertRaises(HIANativeDispatchRejected):
                    host.start_loan_probe("native_swap", args)
                self.assertEqual(host.snapshot()["in_flight"], 0)

    def test_observer_setup_reuses_the_complete_pre_dlopen_policy(self):
        prefix = probe.native._WORKER.split(probe._ENTRY_MARKER, 1)[0]
        self.assertTrue(probe._WORKER.startswith(prefix))
        self.assertIn("seccomp syscall filter required", prefix)
        self.assertIn("resource.setrlimit(resource.RLIMIT_AS", prefix)
