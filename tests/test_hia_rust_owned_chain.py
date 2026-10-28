"""Independent Rust v7 chain execution, full ledgers and selected native controls.

Primitive Core is the Rust input; direct nominal/composite documents continue
to reject. Explicitly normalized composite examples are separately reverified
as primitive Core. Finite parity is not a whole-language refinement proof.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import signal
import tempfile
import unittest

from hepta.hia_program import HIAProgramRejected, verify_program
from hepta.hia_program_runtime import execute_program
from tests import test_hia_rust_owned_vm as owned_tests
from tests.test_hia_program import b, c, f, i, m, ret
from tests.test_hia_rust_chain_shadow import chain_primitive
from tools.qualify_hia_recursive_chain import EXAMPLES, independent_spec, vm_ledger

ROOT = Path(__file__).resolve().parents[1]
CLANG = os.environ.get("CLANG", "clang")


def payload_extent():
    document = m(f("extent", [("size", "usize")], ["usize"], ["alloc"], [
        b("entry", [("size", "usize")], [
            i("buffer.try_new", ["size"], [("payload", "buffer"), ("allocated", "bool")]),
            i("chain.empty", out=[("empty", "chain")]),
            i("chain.try_push", ["empty", "payload"],
              [("built", "chain"), ("fallback", "buffer"), ("ok", "bool")]),
            i("owner.move", ["built"], [("moved", "chain")]),
            i("chain.pop", ["moved"], [("rest", "chain"), ("popped", "buffer"), ("present", "bool")]),
            i("buffer.len", ["popped"], [("popped_len", "usize")]),
            i("buffer.len", ["fallback"], [("fallback_len", "usize")]),
            i("int.add.wrap", ["popped_len", "fallback_len"], [("length", "usize")]),
            i("owner.drop", ["rest"]), i("owner.drop", ["popped"]), i("owner.drop", ["fallback"]),
        ], ret("length"))]))
    document["schema"] = "hepta.hia.program.v7"
    return document


def chain_formal_siblings():
    # A child of one read-only call formal must not suspend an aliased sibling
    # formal. The actual mutable head loan resumes after both call witnesses end.
    helper_params = [("left", "readbuf"), ("right", "readbuf")]
    helper = f("reader", helper_params, ["u8"], ["read", "trap"], [
        b("read", helper_params, [
            c("zero", "usize", 0), i("borrow.read", ["left"], [("child", "readbuf")]),
            i("buffer.load", ["right", "zero"], [("answer", "u8")]),
            i("loan.end", ["child"]),
        ], ret("answer"))])
    ops = [
        c("size", "usize", 1), c("zero", "usize", 0), c("byte", "u8", 173),
        i("buffer.new", ["size"], [("payload", "buffer")]),
        i("chain.empty", out=[("empty", "chain")]),
        i("chain.try_push", ["empty", "payload"],
          [("built", "chain"), ("fallback", "buffer"), ("ok", "bool")]),
        i("owner.drop", ["fallback"]),
        i("chain.head_mut", ["built"], [("head", "mutbuf")]),
        i("buffer.fill", ["head", "byte"]),
        i("call", ["head", "head"], [("answer", "u8")], function="reader"),
        i("buffer.swap", ["head", "zero", "zero"]), i("loan.end", ["head"]),
        i("owner.drop", ["built"]),
    ]
    document = m(helper, f("probe", [], ["u8"], ["alloc", "read", "write", "trap"], [
        b("entry", [], ops, ret("answer"))]))
    document["schema"] = "hepta.hia.program.v7"
    document["exports"] = ["probe"]
    return document


@unittest.skipUnless(shutil.which("cargo"), "Cargo unavailable: NO Rust chain execution qualification")
class RustOwnedChainParity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        owned_tests.RustByteOwnerVmParity.setUpClass.__func__(cls)
        cls.program = verify_program((EXAMPLES / "core_v7.json").read_bytes())
        structured = verify_program((EXAMPLES / "composite_v2.json").read_bytes())
        # This second independent admission takes canonical primitive bytes.
        cls.normalized = verify_program(structured.canonical_bytes)
        cls.native_observations = 0

    @classmethod
    def tearDownClass(cls):
        print(f"Rust chain/Python full-ledger parity observations: {cls.parity_observations}")
        print(f"Rust chain/native result and allocator observations: {cls.native_observations}")

    raw_run = owned_tests.RustByteOwnerVmParity.raw_run

    def parity(self, document, entry, args, *, steps=1_000_000, heap=16 * 1024 * 1024, fail=None):
        report = owned_tests.RustByteOwnerVmParity.parity(
            self, document, entry, args, steps=steps, heap=heap, fail=fail)
        self.assertEqual(report["profile"], "cfg-call-byte-owner-chain-v4")
        self.assertTrue(report["claims"]["v7_recursive_buffer_chain_execution"])
        self.assertFalse(report["claims"]["general_recursive_adts"])
        if report["status"] == "returned":
            for name in ("live_chains", "live_chain_nodes", "live_bytes"):
                self.assertEqual(report["resources"][name], 0)
        return report

    def model_parity(self, entry, n=0, mode=0, fail=None):
        normalized = entry in {"chain_task", "chain_stored_loan"}
        program = self.normalized if normalized else self.program
        args = [] if entry == "chain_empty_pop" else [n, mode] if entry == "chain_task" else [n]
        report = self.parity(program, entry, args, fail=fail)
        # The closed arithmetic/list specification is a third oracle for
        # values, physical allocation attempts, node/payload frees and peak.
        observation = dict(report, result=report["values"][0])
        self.assertEqual(vm_ledger(observation), independent_spec(entry, n, mode, fail or 0))
        return report

    def test_dynamic_chains_cfg_calls_and_normalized_composition(self):
        for n in (0, 1, 2, 17, 257, 4097):
            for entry in ("chain_checksum", "chain_cancel", "chain_head_update",
                          "chain_empty_payloads", "chain_stored_loan"):
                with self.subTest(entry=entry, n=n):
                    self.model_parity(entry, n)
            for mode in range(3):
                self.model_parity("chain_task", n, mode)
        self.model_parity("chain_empty_pop")

    def test_each_payload_and_node_refusal_and_recoverable_tail(self):
        for fail in range(1, 18):
            for entry in ("chain_checksum", "chain_cancel", "chain_head_update"):
                with self.subTest(entry=entry, fail=fail):
                    self.model_parity(entry, 8, fail=fail)
            for mode in range(3):
                self.model_parity("chain_task", 8, mode, fail)
        for fail in range(1, 10):
            self.model_parity("chain_empty_payloads", 8, fail=fail)
        for n in (0, 1, 17, 257):
            for fail in (None, 2 * n + 2):
                self.model_parity("chain_recover", n, fail=fail)

    def test_node_storage_is_in_same_heap_budget_before_refusal_injection(self):
        for heap in (0, 1, 24, 25, 26, 49, 50, 74, 75, 76):
            for fail in (None, 1, 2, 3):
                with self.subTest(heap=heap, fail=fail):
                    self.parity(self.program, "chain_cancel", [3], heap=heap, fail=fail)
        stopped = self.parity(self.program, "chain_cancel", [3], heap=25, fail=3)
        self.assertEqual(stopped["error"]["code"], "heap")
        self.assertEqual(stopped["resources"]["allocation_attempts"], 2)
        self.assertEqual(stopped["resources"]["live_chain_nodes"], 1)

    def test_every_step_boundary_includes_partially_completed_iterative_drop(self):
        full = self.parity(self.program, "chain_cancel", [4])
        partial_destructors = []
        for steps in range(1, full["steps"]):
            report = self.parity(self.program, "chain_cancel", [4], steps=steps)
            resources = report["resources"]
            if (resources["live_chains"] == 0 and resources["live_chain_nodes"] > 0
                    and resources["chain_nodes_dropped"] > 0):
                partial_destructors.append(report)
                self.assertEqual(report["status"], "budget_exceeded")
                self.assertEqual(report["error"]["code"], "steps")
                self.assertEqual(resources["chain_nodes_created"], 4)
                self.assertEqual(resources["live_chain_nodes"], 4 - resources["chain_nodes_dropped"])
                self.assertEqual(resources["live_bytes"], 25 * resources["live_chain_nodes"])
        self.assertEqual(len(partial_destructors), 3)

    def test_dynamic_payload_extent_empty_owners_and_oversized_refusal(self):
        program = payload_extent()
        for size in (0, 1, 7, 24, 1025, 2**63, 2**64 - 1):
            for failure in (None, 1, 2):
                with self.subTest(size=size, failure=failure):
                    report = self.parity(program, "extent", [size], fail=failure)
                    expected = 0 if size >= 2**63 or (size and failure == 1) else size
                    self.assertEqual(report["values"], [expected])

    def test_head_reborrow_call_siblings_and_stopped_live_loans(self):
        document = chain_formal_siblings()
        full = self.parity(document, "probe", [])
        self.assertEqual(full["values"], [173])
        self.assertEqual(full["resources"]["loans_started"], 2)
        for steps in range(1, full["steps"]):
            self.parity(document, "probe", [], steps=steps)
        for failure in (1, 2, 3):
            self.parity(document, "probe", [], fail=failure)
        empty = self.parity(self.program, "chain_empty_head", [])
        self.assertEqual(empty["error"]["code"], "bounds")
        self.assertEqual(empty["resources"]["live_chains"], 1)
        self.assertEqual(empty["resources"]["loans_started"], 0)

    def test_consuming_recursive_call_preserves_chain_at_depth_stop(self):
        recurse = f("recurse", [("chain", "chain")], [], [], [
            b("again", [("chain", "chain")], [i("call", ["chain"], function="recurse")], ret())])
        outer = f("probe", [], [], [], [b("entry", [], [
            i("chain.empty", out=[("chain", "chain")]), i("call", ["chain"], function="recurse")], ret())])
        document = m(recurse, outer)
        document["schema"] = "hepta.hia.program.v7"
        document["exports"] = ["probe"]
        report = self.parity(document, "probe", [])
        self.assertEqual(report["error"]["code"], "calls")
        self.assertEqual(report["resources"]["live_chains"], 1)
        self.assertEqual(report["resources"]["chains_consumed"], 0)

    def test_illegal_chain_ownership_alias_and_old_version_refuse_before_execution(self):
        variants = []
        for opcode in ("owner.drop", "owner.move", "chain.pop", "chain.try_push"):
            doc = chain_primitive()
            ops = doc["functions"][0]["blocks"][0]["ops"]
            op = {"owner.drop": i("owner.drop", ["full"]),
                  "owner.move": i("owner.move", ["full"], [("moved", "chain")]),
                  "chain.pop": i("chain.pop", ["full"], [("x", "chain"), ("y", "buffer"), ("z", "bool")]),
                  "chain.try_push": i("chain.try_push", ["full", "unused"],
                      [("x", "chain"), ("y", "buffer"), ("z", "bool")])}[opcode]
            ops.insert(5, op)  # head loan is still live
            variants.append(doc)
        borrowed_payload = chain_primitive()
        borrowed_payload["functions"][0]["blocks"][0]["ops"].insert(
            3, i("borrow.read", ["payload"], [("payload_view", "readbuf")]))
        variants.append(borrowed_payload)
        for version in range(1, 7):
            doc = chain_primitive()
            doc["schema"] = f"hepta.hia.program.v{version}"
            variants.append(doc)
        for index, bad in enumerate(variants):
            with self.subTest(index=index):
                with self.assertRaises(HIAProgramRejected):
                    verify_program(bad)
                observed = self.raw_run(json.dumps(bad).encode(), "entrypoint", [], fail=1)
                self.assertNotEqual(observed.returncode, 0)
                self.assertEqual(observed.stdout, b"")
        raw = self.program.canonical_bytes
        for entry, args in (("build_chain", [0]), ("drain_chain", [{"chain": 1}])):
            observed = self.raw_run(raw, entry, args)
            self.assertNotEqual(observed.returncode, 0)
            self.assertTrue(observed.stderr.startswith(b"E_HIA_INPUT:"), observed.stderr)
            self.assertEqual(observed.stdout, b"")
        # No direct nominal/composite execution was enabled by this work.
        observed = self.raw_run((EXAMPLES / "composite_v2.json").read_bytes(), "chain_task", [1, 0])
        self.assertNotEqual(observed.returncode, 0)
        self.assertTrue(observed.stderr.startswith(b"E_HIA_FORMAT:"), observed.stderr)

    @unittest.skipUnless(shutil.which(CLANG), "Clang unavailable: NO native chain controls")
    def test_actual_native_node_payload_allocator_and_abort_controls(self):
        from hepta.clang_capture import run_bounded
        from hepta.hia_program_llvm import build_program_native

        cases = [(entry, n, 0, 0) for n in (0, 1, 17, 257)
                 for entry in ("chain_checksum", "chain_cancel", "chain_head_update", "chain_empty_payloads")]
        cases += [(entry, 8, 0, failure) for failure in (1, 2, 8)
                  for entry in ("chain_checksum", "chain_cancel", "chain_head_update")]
        cases += [("chain_recover", 17, 0, 36), ("chain_empty_pop", 0, 0, 0),
                  ("chain_stored_loan", 8, 0, 0)]
        cases += [("chain_task", 8, mode, fail) for mode in range(3) for fail in (0, 2)]
        with tempfile.TemporaryDirectory(prefix="hia-rust-chain-native-") as directory:
            directory = Path(directory)
            core_obj, composite_obj = directory / "core.o", directory / "composite.o"
            for program, output in ((self.program, core_obj), (self.normalized, composite_obj)):
                built = build_program_native(program, output, clang=CLANG, kind="object")
                self.assertTrue(built["ok"])
            binary = directory / "chain"
            linked = run_bounded([CLANG, "-O2", str(EXAMPLES / "allocator_driver.c"),
                str(core_obj), str(composite_obj), "-Wl,--wrap=malloc", "-Wl,--wrap=calloc",
                "-Wl,--wrap=free", "-o", str(binary)])
            self.assertEqual(linked.returncode, 0, linked.stderr)
            for entry, n, mode, fail in cases:
                with self.subTest(entry=entry, n=n, mode=mode, fail=fail):
                    rust = self.model_parity(entry, n, mode, fail or None)
                    native = run_bounded([str(binary), entry, str(n), str(mode), str(fail)])
                    self.assertEqual(native.returncode, 0, native.stderr)
                    self.assertEqual(json.loads(native.stdout),
                                     vm_ledger(dict(rust, result=rust["values"][0])))
                    type(self).native_observations += 1
            rust = self.parity(self.program, "chain_empty_head", [])
            native = run_bounded([str(binary), "chain_empty_head", "0", "0", "0"])
            self.assertEqual(native.returncode, -signal.SIGABRT, native.stderr)
            self.assertEqual(rust["error"]["code"], "bounds")
            type(self).native_observations += 1


if __name__ == "__main__":
    unittest.main()
