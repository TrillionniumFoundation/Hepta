"""v7 recursive owners: actual dynamic lengths, ownership negatives and native ABI."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from hepta.hia_program import HIAProgramRejected, verify_program
from hepta.hia_program_llvm import build_program_native
from hepta.hia_program_runtime import HIAProgramBudgetExceeded, HIAProgramTrap, execute_program
from hepta.hia_schema import (COMPOSITE_SCHEMA, COMPOSITE_SCHEMA_V2, SCHEMA_V6,
                              SCHEMA_V7, SCHEMA_V8, composite_core_schema, profile_for_schema,
                              schema_registry, supports_feature)
from tests.test_hia_program import b, c, f, i, ret
from tools.qualify_hia_recursive_chain import (EXAMPLES, independent_spec,
                                              load_examples, sum_bytes, vm_ledger)


def doc(name="core_v7"):
    return json.loads((EXAMPLES / (name + ".json")).read_text())


def function(document, name):
    return next(fn for fn in document["functions"] if fn["name"] == name)


def block(fn, name):
    return next(item for item in fn["blocks"] if item["id"] == name)


def one_function(operations, returns=()):
    return {"schema": SCHEMA_V7, "module": "chain_negative", "functions": [
        f("entrypoint", [], list(returns), ["alloc", "read", "write", "trap"],
          [b("entry", [], operations, ret())])]}


class HIARecursiveChainTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.programs = load_examples()

    def assert_clean(self, report):
        ledger = report["resources"]
        for field in ("live_bytes", "live_owners", "live_chains", "live_chain_nodes", "live_local_loans"):
            self.assertEqual(ledger[field], 0, field)
        self.assertEqual(ledger["allocations"], ledger["frees"])
        self.assertEqual(ledger["owners_created"], ledger["owners_dropped"])
        self.assertEqual(ledger["chains_created"], ledger["chains_consumed"])

    def test_versioned_admission_and_nominal_normalization(self):
        self.assertEqual(composite_core_schema(COMPOSITE_SCHEMA), SCHEMA_V6)
        self.assertEqual(composite_core_schema(COMPOSITE_SCHEMA_V2), SCHEMA_V7)
        self.assertTrue(supports_feature(SCHEMA_V7, "recursive_chain"))
        self.assertFalse(supports_feature(SCHEMA_V6, "recursive_chain"))
        self.assertEqual(schema_registry()["latest_core_schema"], SCHEMA_V8)
        self.assertFalse(supports_feature(SCHEMA_V7, "parameter_loan_returns"))
        self.assertTrue(supports_feature(SCHEMA_V8, "parameter_loan_returns"))
        self.assertIn("v7", profile_for_schema(COMPOSITE_SCHEMA_V2))
        for name, program in self.programs.items():
            with self.subTest(name=name):
                self.assertEqual(verify_program(program).canonical_bytes, program.canonical_bytes)
                self.assertEqual(program.as_dict()["schema"], SCHEMA_V7)
                self.assertTrue(program.report()["claims"]["recursive_buffer_chains_supported"])
                self.assertFalse(program.report()["claims"]["recursive_heap_adts_supported"])

    def test_old_schemas_reject_new_types_and_ops(self):
        for version in range(1, 7):
            source = doc()
            source["schema"] = f"hepta.hia.program.v{version}"
            with self.subTest(version=version), self.assertRaises(HIAProgramRejected):
                verify_program(source)
        old = doc("composite_v2")
        old["schema"] = COMPOSITE_SCHEMA
        with self.assertRaisesRegex(HIAProgramRejected, "require composite v2"):
            verify_program(old)
        unused = {"schema": COMPOSITE_SCHEMA, "module": "unused_chain", "types": [
            {"name": "Unused", "params": [], "kind": "record",
             "fields": [{"name": "value", "type": "chain"}]}],
            "functions": [f("scalar", [], ["u8"], [], [b("entry", [], [c("value", "u8", 1)], ret("value"))])]}
        with self.assertRaises(HIAProgramRejected):
            verify_program(unused)
        unknown = one_function([i("chain.unknown")])
        with self.assertRaisesRegex(HIAProgramRejected, "unsupported opcode"):
            verify_program(unknown)

    def test_v1_existing_chain_nominal_name_and_parameter_keep_their_meaning(self):
        # v7 must not retroactively reserve a previously valid v1 nominal name.
        from tests.test_hia_program_composite import record, ref
        for definition, typ in [(record("chain", [("value", "u8")]), "chain"),
                                (record("Box", [("value", "chain")], ["chain"]), ref("Box", "u8"))]:
            source = {"schema": COMPOSITE_SCHEMA, "module": "legacy_name", "types": [definition],
                      "functions": [f("main", [], ["u8"], [], [b("entry", [], [
                          c("value", "u8", 71), i("record.make", ["value"], [("wrapped", typ)]),
                          i("record.unpack", ["wrapped"], [("answer", "u8")])], ret("answer"))])]}
            with self.subTest(definition=definition["name"]):
                checked = verify_program(source)
                self.assertEqual(checked.as_dict()["schema"], SCHEMA_V6)
                self.assertEqual(execute_program(checked, "main", [])["result"], 71)
                source["schema"] = COMPOSITE_SCHEMA_V2
                with self.assertRaises(HIAProgramRejected):
                    verify_program(source)

    def test_dynamic_lengths_cross_function_return_and_iterative_drop(self):
        program = self.programs["core_v7"]
        for n in (0, 1, 2, 257, 4097):
            with self.subTest(n=n):
                result = execute_program(program, "chain_checksum", [n], max_call_depth=2)
                self.assertEqual(result["result"], sum_bytes(n))
                self.assertEqual(result["resources"]["chain_nodes_created"], n)
                self.assertEqual(result["resources"]["peak_bytes"], n * 25)
                self.assert_clean(result)
                cancelled = execute_program(program, "chain_cancel", [n], max_call_depth=2)
                self.assertTrue(cancelled["result"])
                self.assert_clean(cancelled)

    def test_every_payload_and_node_failure_preserves_tail_and_releases_payload(self):
        program = self.programs["core_v7"]
        for failure in range(1, 36):
            for name in ("chain_checksum", "chain_cancel"):
                with self.subTest(failure=failure, name=name):
                    observed = execute_program(program, name, [17], allocation_fail_at=failure)
                    self.assertEqual(vm_ledger(observed), independent_spec(name, 17, fail=failure))
                    self.assert_clean(observed)

    def test_failed_push_returns_unchanged_readable_payload_and_original_tail(self):
        for n in (0, 1, 17, 257):
            for failure in (None, 2 * n + 2):
                with self.subTest(n=n, failure=failure):
                    observed = execute_program(self.programs["core_v7"], "chain_recover", [n],
                                               allocation_fail_at=failure)
                    self.assertEqual(vm_ledger(observed), independent_spec("chain_recover", n, fail=failure or 0))
                    self.assert_clean(observed)

    def test_empty_payloads_have_real_headers_without_payload_allocations(self):
        for n in (0, 1, 17):
            for failure in (None, 1, 3, 18):
                observed = execute_program(self.programs["core_v7"], "chain_empty_payloads", [n],
                                           allocation_fail_at=failure)
                self.assertEqual(vm_ledger(observed), independent_spec("chain_empty_payloads", n, fail=failure or 0))
                self.assert_clean(observed)
        empty = execute_program(self.programs["core_v7"], "chain_empty_pop", [])
        self.assertFalse(empty["result"])
        self.assertEqual(empty["resources"]["allocation_attempts"], 0)
        self.assert_clean(empty)

    def test_generic_records_stored_reborrows_error_enums_and_task_cancel(self):
        program = self.programs["composite_v2"]
        for n in (0, 1, 17, 257):
            for failure in (None, 1, 2, 3, 34):
                for mode in range(3):
                    with self.subTest(n=n, failure=failure, mode=mode):
                        observed = execute_program(program, "chain_task", [n, mode], allocation_fail_at=failure)
                        self.assertEqual(vm_ledger(observed), independent_spec("chain_task", n, mode, failure or 0))
                        self.assert_clean(observed)
                stored = execute_program(program, "chain_stored_loan", [n], allocation_fail_at=failure)
                self.assertEqual(vm_ledger(stored), independent_spec("chain_stored_loan", n, fail=failure or 0))
                self.assert_clean(stored)

    def test_node_bytes_are_charged_to_heap_budget_before_allocation_attempt(self):
        with self.assertRaises(HIAProgramBudgetExceeded) as caught:
            execute_program(self.programs["core_v7"], "chain_cancel", [2], max_heap_bytes=25)
        report = caught.exception.report
        self.assertEqual(report["error"]["code"], "heap")
        self.assertEqual(report["resources"]["peak_bytes"], 25)
        self.assertEqual(report["resources"]["allocation_attempts"], 2)
        self.assertEqual(report["resources"]["live_chain_nodes"], 1)
        self.assertEqual(report["resources"]["frees"], 0)

    def test_budget_stop_in_iterative_destruction_is_not_reported_as_cleanup(self):
        complete = execute_program(self.programs["core_v7"], "chain_cancel", [17])
        with self.assertRaises(HIAProgramBudgetExceeded) as caught:
            execute_program(self.programs["core_v7"], "chain_cancel", [17], max_steps=complete["steps"] - 10)
        report = caught.exception.report
        self.assertEqual(report["error"]["code"], "steps")
        self.assertGreater(report["resources"]["live_chain_nodes"], 0)
        self.assertGreater(report["resources"]["live_bytes"], 0)
        self.assertLess(report["resources"]["frees"], report["resources"]["allocations"])

    def test_empty_head_traps_without_fabricating_a_view(self):
        with self.assertRaises(HIAProgramTrap) as caught:
            execute_program(self.programs["core_v7"], "chain_empty_head", [])
        self.assertEqual(caught.exception.code, "bounds")
        self.assertEqual(caught.exception.report["resources"]["loans_started"], 0)
        self.assertEqual(caught.exception.report["resources"]["live_chains"], 1)

    def test_borrowed_chain_cannot_move_drop_pop_or_push(self):
        for operation in (i("owner.drop", ["owned"]), i("owner.move", ["owned"], [("moved", "chain")]),
                          i("chain.pop", ["owned"], [("tail", "chain"), ("item", "buffer"), ("ok", "bool")]),
                          i("chain.try_push", ["owned", "payload"], [("tail", "chain"), ("item", "buffer"), ("ok", "bool")])):
            source = one_function([i("chain.empty", out=[("owned", "chain")]), c("zero", "usize", 0),
                                   i("buffer.new", ["zero"], [("payload", "buffer")]),
                                   i("chain.head_read", ["owned"], [("reader", "readbuf")]), operation])
            with self.subTest(op=operation["op"]), self.assertRaisesRegex(HIAProgramRejected, "while borrowed"):
                verify_program(source)

    def test_borrowed_payload_cannot_be_hidden_in_a_node(self):
        source = one_function([i("chain.empty", out=[("tail", "chain")]), c("zero", "usize", 0),
                               i("buffer.new", ["zero"], [("payload", "buffer")]),
                               i("borrow.read", ["payload"], [("reader", "readbuf")]),
                               i("chain.try_push", ["tail", "payload"], [("built", "chain"), ("fallback", "buffer"), ("ok", "bool")])])
        with self.assertRaisesRegex(HIAProgramRejected, "while borrowed"):
            verify_program(source)

    def test_chain_head_loan_conflicts_and_suspended_reborrow(self):
        for second in (i("chain.head_mut", ["owned"], [("other", "mutbuf")]),
                       i("chain.head_read", ["owned"], [("other", "readbuf")])):
            source = one_function([i("chain.empty", out=[("owned", "chain")]),
                                   i("chain.head_mut", ["owned"], [("writer", "mutbuf")]), second])
            with self.subTest(op=second["op"]), self.assertRaisesRegex(HIAProgramRejected, "conflicting live borrow"):
                verify_program(source)
        source = doc()
        some = block(function(source, "chain_head_update"), "some")
        some["ops"] = [op for op in some["ops"] if op != i("loan.end", ["child"])]
        with self.assertRaisesRegex(HIAProgramRejected, "suspended"):
            verify_program(source)

    def test_chain_descriptor_is_never_a_byte_buffer(self):
        for operation in (i("buffer.len", ["owned"], [("size", "usize")]),
                          i("borrow.read", ["owned"], [("reader", "readbuf")])):
            source = one_function([i("chain.empty", out=[("owned", "chain")]), operation])
            with self.subTest(op=operation["op"]), self.assertRaises(HIAProgramRejected):
                verify_program(source)

    def test_lost_and_reused_chain_are_rejected(self):
        source = one_function([i("chain.empty", out=[("owned", "chain")])])
        with self.assertRaisesRegex(HIAProgramRejected, "leaves live owner"):
            verify_program(source)
        source = one_function([i("chain.empty", out=[("owned", "chain")]),
                               i("owner.drop", ["owned"]), i("owner.drop", ["owned"])])
        with self.assertRaisesRegex(HIAProgramRejected, "consumed resource"):
            verify_program(source)
        source = one_function([i("chain.empty", out=[("owned", "chain")])])
        source["functions"][0]["returns"] = ["chain", "chain"]
        source["functions"][0]["blocks"][0]["term"] = ret("owned", "owned")
        with self.assertRaisesRegex(HIAProgramRejected, "returned twice"):
            verify_program(source)

    def test_consuming_call_cannot_alias_chain_arguments(self):
        consume = f("consume", [("left", "chain"), ("right", "chain")], [], ["alloc"], [
            b("entry", [("left", "chain"), ("right", "chain")],
              [i("owner.drop", ["left"]), i("owner.drop", ["right"])], ret())])
        source = one_function([i("chain.empty", out=[("owned", "chain")]),
                               i("call", ["owned", "owned"], function="consume")])
        source["functions"].append(consume)
        with self.assertRaisesRegex(HIAProgramRejected, "supplied twice"):
            verify_program(source)

    def test_payload_descriptor_preserves_dynamic_extent(self):
        source = {"schema": SCHEMA_V7, "module": "dynamic_payload", "functions": [
            f("extent", [("size", "usize")], ["usize"], ["alloc"], [
                b("entry", [("size", "usize")], [
                    i("buffer.try_new", ["size"], [("payload", "buffer"), ("allocated", "bool")]),
                    i("chain.empty", out=[("empty", "chain")]),
                    i("chain.try_push", ["empty", "payload"], [("built", "chain"), ("fallback", "buffer"), ("ok", "bool")]),
                    i("chain.pop", ["built"], [("rest", "chain"), ("popped", "buffer"), ("present", "bool")]),
                    i("buffer.len", ["popped"], [("popped_len", "usize")]),
                    i("buffer.len", ["fallback"], [("fallback_len", "usize")]),
                    i("int.add.wrap", ["popped_len", "fallback_len"], [("length", "usize")]),
                    i("owner.drop", ["rest"]), i("owner.drop", ["popped"]), i("owner.drop", ["fallback"]),
                ], ret("length"))])]}
        checked = verify_program(source)
        for n in (0, 1, 7, 24, 1025):
            for failure in (None, 1, 2):
                with self.subTest(n=n, failure=failure):
                    observed = execute_program(checked, "extent", [n], allocation_fail_at=failure)
                    self.assertEqual(observed["result"], 0 if n and failure == 1 else n)
                    self.assert_clean(observed)

    def test_stored_loan_cannot_outlive_its_chain_root(self):
        source = doc("composite_v2")
        use = block(function(source, "chain_stored_loan"), "use")
        use["ops"].insert(1, i("owner.drop", ["owned"]))
        with self.assertRaises(HIAProgramRejected):
            verify_program(source)

    def test_mutated_push_cannot_duplicate_tail_or_payload(self):
        for position in (0, 1):
            source = doc()
            fill = block(function(source, "build_chain"), "fill")
            push_index = next(k for k, ins in enumerate(fill["ops"]) if ins["op"] == "chain.try_push")
            old_name = fill["ops"][push_index]["args"][position]
            fill["ops"].insert(push_index + 1, i("owner.drop", [old_name]))
            with self.subTest(position=position), self.assertRaisesRegex(HIAProgramRejected, "consumed resource"):
                verify_program(source)

    def test_structured_identity_and_illegal_public_chain_exports(self):
        checked = self.programs["composite_v2"]
        self.assertNotEqual(checked.input_sha256, checked.sha256)
        self.assertEqual(checked.scalar_entrypoints, frozenset({"chain_task", "chain_stored_loan"}))
        source = doc()
        source["exports"] = ["build_chain"]
        with self.assertRaisesRegex(HIAProgramRejected, "resource descriptors"):
            verify_program(source)


class HIARecursiveChainNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.clang = os.environ.get("HEPTA_NATIVE_CLANG") or shutil.which("clang") or "/usr/lib/llvm-20/bin/clang"
        if not Path(cls.clang).is_file():
            raise unittest.SkipTest("actual Clang 20+ is unavailable")
        cls.temp = tempfile.TemporaryDirectory(prefix="hia-recursive-native-")
        cls.directory = Path(cls.temp.name)
        cls.programs = load_examples()
        for name, program in cls.programs.items():
            build_program_native(program, cls.directory / (name + ".o"), clang=cls.clang, kind="object")
        cls.executable = cls.directory / "observer"
        subprocess.run([cls.clang, "-O2", "-Wl,--wrap=malloc", "-Wl,--wrap=calloc", "-Wl,--wrap=free",
                        str(EXAMPLES / "allocator_driver.c"), str(cls.directory / "core_v7.o"),
                        str(cls.directory / "composite_v2.o"), "-o", str(cls.executable)],
                       check=True, capture_output=True, timeout=30)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_real_native_results_and_independent_node_payload_ledger(self):
        cases = [("chain_checksum", 257, 0, 0), ("chain_cancel", 4097, 0, 0),
                 ("chain_checksum", 17, 0, 17), ("chain_checksum", 17, 0, 18),
                 ("chain_recover", 17, 0, 36), ("chain_empty_payloads", 17, 0, 0),
                 ("chain_empty_payloads", 17, 0, 3), ("chain_empty_pop", 0, 0, 0),
                 ("chain_stored_loan", 17, 0, 0), ("chain_task", 17, 0, 0),
                 ("chain_task", 17, 1, 0), ("chain_task", 17, 2, 0),
                 ("chain_task", 17, 2, 18)]
        for name, n, mode, fail in cases:
            with self.subTest(name=name, n=n, mode=mode, fail=fail):
                completed = subprocess.run([str(self.executable), name, str(n), str(mode), str(fail)],
                                           check=True, capture_output=True, text=True, timeout=10)
                self.assertEqual(json.loads(completed.stdout), independent_spec(name, n, mode, fail))


if __name__ == "__main__":
    unittest.main()
