"""Pure HIA recursive owners: VM semantics and checked ownership failures.

These controls exercise the retained v7/v2 fixtures directly, with independent
arithmetic expectations. They are not a recovered historical native receipt;
the existing selected-owner caller gate can run the same controls separately.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import unittest

from hepta.hia_program import HIAProgramRejected, verify_program
from hepta.hia_program_runtime import HIAProgramBudgetExceeded, HIAProgramTrap, execute_program
from hepta.hia_schema import COMPOSITE_SCHEMA, SCHEMA_V6, SCHEMA_V7
from tests.test_hia_program import b, c, f, i, ret


ROOT = Path(__file__).resolve().parents[1]


def function(document, name):
    return next(fn for fn in document["functions"] if fn["name"] == name)


def block(fn, name):
    return next(item for item in fn["blocks"] if item["id"] == name)


def one_function(operations, returns=()):
    return {"schema": SCHEMA_V7, "module": "chain_negative", "functions": [
        f("entrypoint", [], list(returns), ["alloc", "read", "write", "trap"],
          [b("entry", [], operations, ret())])]}


def checksum(count):
    """The fixture stores each insertion index as one unsigned byte."""
    cycles, remainder = divmod(count, 256)
    return cycles * 32640 + remainder * (remainder - 1) // 2


class RecursiveChainV7Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.core_bytes = (ROOT / "examples/hia_recursive_chain/core_v7.hepta").read_bytes()
        cls.composite_bytes = (ROOT / "examples/hia_recursive_chain/composite_v2.hepta").read_bytes()
        cls.core = verify_program(cls.core_bytes)
        cls.composite = verify_program(cls.composite_bytes)

    def assert_closed(self, report, nodes):
        self.assertEqual(report["status"], "returned")
        ledger = report["resources"]
        for name in ("live_bytes", "live_owners", "live_local_loans", "live_chains", "live_chain_nodes"):
            self.assertEqual(ledger[name], 0, name)
        for created, consumed in (("allocations", "frees"),
                                  ("owners_created", "owners_dropped"),
                                  ("loans_started", "loans_ended"),
                                  ("chains_created", "chains_consumed")):
            self.assertEqual(ledger[created], ledger[consumed], created)
        self.assertEqual(ledger["chain_nodes_created"], nodes)
        self.assertEqual(ledger["chain_nodes_dropped"], nodes)
        return ledger

    def test_dynamic_checksum_and_iterative_cancel_preserve_all_resources(self):
        for count in (0, 1, 2, 17, 255, 256, 257, 4097):
            for name, expected in (("chain_checksum", checksum(count)), ("chain_cancel", True)):
                with self.subTest(count=count, function=name):
                    # A long chain must not consume one call frame per node.
                    report = execute_program(self.core, name, [count], max_call_depth=4)
                    self.assertEqual(report["result"], expected)
                    ledger = self.assert_closed(report, count)
                    self.assertEqual(ledger["allocation_attempts"], 2 * count)
                    self.assertEqual(ledger["allocations"], 2 * count)
                    self.assertEqual(ledger["peak_bytes"], 25 * count)

    def test_head_reborrow_updates_only_the_last_inserted_byte(self):
        for count in (0, 1, 2, 17, 256, 257):
            with self.subTest(count=count):
                report = execute_program(self.core, "chain_head_update", [count])
                expected = checksum(count) - ((count - 1) % 256) + 255 if count else 0
                self.assertEqual(report["result"], expected)
                self.assert_closed(report, count)

    def test_every_payload_and_header_refusal_preserves_the_built_prefix(self):
        count = 17
        for failure in range(1, 2 * count + 1):
            built = (failure - 1) // 2
            for name, expected in (("chain_checksum", 1000000 + checksum(built)),
                                   ("chain_cancel", False)):
                with self.subTest(failure=failure, function=name):
                    report = execute_program(self.core, name, [count], allocation_fail_at=failure)
                    self.assertEqual(report["result"], expected)
                    ledger = self.assert_closed(report, built)
                    self.assertEqual(ledger["allocation_attempts"], failure)
                    self.assertEqual(ledger["allocations"], failure - 1)

    def test_failed_final_push_returns_the_original_payload_and_tail(self):
        for count in (0, 1, 17, 257):
            for refused in (False, True):
                failure = 2 * count + 2 if refused else None
                with self.subTest(count=count, refused=refused):
                    report = execute_program(self.core, "chain_recover", [count],
                                             allocation_fail_at=failure)
                    self.assertEqual(report["result"], checksum(count) + 73 + 1000000 * refused)
                    ledger = self.assert_closed(report, count if refused else count + 1)
                    self.assertEqual(ledger["allocation_attempts"], 2 * count + 2)
                    self.assertEqual(ledger["allocations"], 2 * count + (1 if refused else 2))

    def test_zero_length_payloads_allocate_and_release_only_headers(self):
        for count in (0, 1, 17, 257):
            with self.subTest(count=count):
                report = execute_program(self.core, "chain_empty_payloads", [count])
                self.assertIs(report["result"], True)
                ledger = self.assert_closed(report, count)
                self.assertEqual(ledger["allocation_attempts"], count)
                self.assertEqual(ledger["allocations"], count)
                self.assertEqual(ledger["peak_bytes"], 24 * count)
        for failure in range(1, 18):
            with self.subTest(failure=failure):
                report = execute_program(self.core, "chain_empty_payloads", [17],
                                         allocation_fail_at=failure)
                self.assertIs(report["result"], False)
                ledger = self.assert_closed(report, failure - 1)
                self.assertEqual(ledger["allocation_attempts"], failure)
                self.assertEqual(ledger["allocations"], failure - 1)

    def test_empty_pop_returns_two_consumable_empty_owners(self):
        report = execute_program(self.core, "chain_empty_pop", [])
        self.assertIs(report["result"], False)
        ledger = self.assert_closed(report, 0)
        self.assertEqual(ledger["allocation_attempts"], 0)
        self.assertEqual(ledger["owners_created"], 1)

    def test_empty_head_traps_before_creating_a_loan(self):
        with self.assertRaises(HIAProgramTrap) as caught:
            execute_program(self.core, "chain_empty_head", [])
        self.assertEqual(caught.exception.code, "bounds")
        report = caught.exception.report
        self.assertEqual(report["status"], "trapped")
        ledger = report["resources"]
        self.assertEqual(ledger["live_chains"], 1)
        self.assertEqual(ledger["chains_consumed"], 0)
        self.assertEqual(ledger["live_chain_nodes"], 0)
        self.assertEqual(ledger["loans_started"], 0)
        self.assertEqual(ledger["live_bytes"], 0)

    def test_heap_budget_stop_is_not_allocator_failure_or_claimed_cleanup(self):
        with self.assertRaises(HIAProgramBudgetExceeded) as caught:
            execute_program(self.core, "chain_checksum", [2], max_heap_bytes=25)
        self.assertEqual(caught.exception.code, "heap")
        report = caught.exception.report
        self.assertEqual(report["status"], "budget_exceeded")
        ledger = report["resources"]
        self.assertEqual(ledger["allocation_attempts"], 2)
        self.assertEqual(ledger["live_bytes"], 25)
        self.assertEqual(ledger["live_chain_nodes"], 1)
        self.assertEqual(ledger["live_owners"], 2)
        self.assertEqual(ledger["frees"], 0)

    def test_composite_task_polling_and_cancellation_release_the_same_chain(self):
        for count in (0, 1, 2, 17, 257):
            for mode in (0, 1, 2):
                with self.subTest(count=count, mode=mode):
                    report = execute_program(self.composite, "chain_task", [count, mode])
                    expected = (3000000 if mode == 0 else
                                (2000000 if count else 0) if mode == 1 else checksum(count))
                    self.assertEqual(report["result"], expected)
                    ledger = self.assert_closed(report, count)
                    self.assertEqual(ledger["allocation_attempts"], 2 * count)
                    self.assertEqual(ledger["allocations"], 2 * count)

    def test_composite_error_enum_consumes_each_partial_construction(self):
        for failure in range(1, 35):
            with self.subTest(failure=failure):
                report = execute_program(self.composite, "chain_task", [17, 2],
                                         allocation_fail_at=failure)
                self.assertEqual(report["result"], 1000000)
                ledger = self.assert_closed(report, (failure - 1) // 2)
                self.assertEqual(ledger["allocation_attempts"], failure)
                self.assertEqual(ledger["allocations"], failure - 1)

    def test_composite_stored_child_loan_resumes_the_parent_for_mutation(self):
        for count in (0, 1, 2, 17, 256, 257):
            with self.subTest(count=count):
                report = execute_program(self.composite, "chain_stored_loan", [count])
                expected = checksum(count) - ((count - 1) % 256) + 99 if count else 0
                self.assertEqual(report["result"], expected)
                self.assert_closed(report, count)

    def test_chain_opcodes_do_not_silently_upgrade_older_schemas(self):
        for raw, schema in ((self.core_bytes, SCHEMA_V6), (self.composite_bytes, COMPOSITE_SCHEMA)):
            document = json.loads(raw)
            document["schema"] = schema
            with self.subTest(schema=schema), self.assertRaises(HIAProgramRejected):
                verify_program(document)

    def test_live_head_loan_refuses_chain_consumption(self):
        actions = (
            i("owner.drop", ["some_chain"]),
            i("owner.move", ["some_chain"], [("illegal", "chain")]),
            i("chain.pop", ["some_chain"],
              [("rest", "chain"), ("item", "buffer"), ("present", "bool")]),
            i("call", ["some_chain"], [("illegal_sum", "u64")], function="drain_chain"),
        )
        for operation in actions:
            document = json.loads(self.core_bytes)
            block(function(document, "chain_head_update"), "some")["ops"].insert(1, operation)
            with self.subTest(operation=operation["op"]), self.assertRaisesRegex(HIAProgramRejected, "E_HIA_LOAN"):
                verify_program(document)

    def test_live_child_refuses_parent_write_and_early_parent_end(self):
        actions = (i("buffer.store", ["writer", "zero", "before"]), i("loan.end", ["writer"]))
        for operation in actions:
            document = json.loads(self.core_bytes)
            operations = block(function(document, "chain_head_update"), "some")["ops"]
            operations.insert(4, operation)
            with self.subTest(operation=operation["op"]), self.assertRaisesRegex(HIAProgramRejected, "E_HIA_LOAN"):
                verify_program(document)

    def test_borrowed_payload_cannot_transfer_into_a_chain(self):
        document = one_function([
            c("size", "usize", 1), i("buffer.new", ["size"], [("payload", "buffer")]),
            i("borrow.read", ["payload"], [("reader", "readbuf")]),
            i("chain.empty", out=[("tail", "chain")]),
            i("chain.try_push", ["tail", "payload"],
              [("pushed", "chain"), ("fallback", "buffer"), ("ok", "bool")]),
            i("loan.end", ["reader"]), i("owner.drop", ["pushed"]), i("owner.drop", ["fallback"]),
        ])
        with self.assertRaisesRegex(HIAProgramRejected, "E_HIA_LOAN"):
            verify_program(document)

    def test_chain_owner_cannot_be_duplicated_or_exposed_as_a_scalar(self):
        consumer = f("consume_pair", [("left", "chain"), ("right", "chain")], [], ["alloc"], [
            b("entry", [("left", "chain"), ("right", "chain")],
              [i("owner.drop", ["left"]), i("owner.drop", ["right"])], ret())])
        document = one_function([i("chain.empty", out=[("owned", "chain")]),
                                 i("call", ["owned", "owned"], function="consume_pair")])
        document["functions"].append(consumer)
        with self.assertRaisesRegex(HIAProgramRejected, "E_HIA_RESOURCE"):
            verify_program(document)
        for name, arguments in (("build_chain", [1]), ("drain_chain", [0])):
            with self.subTest(function=name), self.assertRaisesRegex(HIAProgramRejected, "E_HIA_INPUT"):
                execute_program(self.core, name, arguments)

    def test_chain_effects_and_attributes_remain_checked(self):
        original = json.loads(self.core_bytes)
        missing_effect = copy.deepcopy(original)
        function(missing_effect, "build_chain")["effects"].remove("alloc")
        with self.assertRaisesRegex(HIAProgramRejected, "E_HIA_EFFECT"):
            verify_program(missing_effect)
        forged = copy.deepcopy(original)
        operations = block(function(forged, "build_chain"), "fill")["ops"]
        next(op for op in operations if op["op"] == "chain.try_push")["attrs"]["unchecked"] = True
        with self.assertRaisesRegex(HIAProgramRejected, "E_HIA_FORMAT"):
            verify_program(forged)


if __name__ == "__main__":
    unittest.main()
