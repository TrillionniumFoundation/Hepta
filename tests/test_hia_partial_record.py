"""Explicit partial-record construction, movement and cleanup in composite v3."""
from __future__ import annotations

import json
import unittest

from hepta.hia_program import HIAProgramRejected, verify_core
from hepta.hia_program_runtime import HIAProgramBudgetExceeded, execute_program
from hepta.hia_schema import (COMPOSITE_SCHEMA, COMPOSITE_SCHEMA_V2,
                              COMPOSITE_SCHEMA_V3, SCHEMA_V7, schema_registry)
from tests.test_hia_program import b, branch, c, f, i, jump, ret
from tests.test_hia_program_composite import enum, module, record, ref


def partial(base, *initialized):
    return {"partial": base, "initialized": list(initialized)}


def v3(types, *functions):
    result = module(types, *functions)
    result["schema"] = COMPOSITE_SCHEMA_V3
    return json.loads(json.dumps(result))


def roundtrip_program():
    """Cross-call construction, CFG error/cancel cleanup, take and reinitialize."""
    pair = ref("Pair", "buffer", "usize")
    empty, first, second, both = (partial(pair, *names) for names in
                                  [(), ("first",), ("second",), ("first", "second")])
    types = [record("Pair", [("first", "T"), ("second", "U")], ["T", "U"])]
    complete = f("complete", [("state", first)], [pair], ["alloc"], [
        b("entry", [("state", first)], [
            c("count", "usize", 17),
            i("record.insert", ["state", "count"], [("ready", both)], field="second"),
            i("record.finish", ["ready"], [("done", pair)]),
        ], ret("done"))])
    cleanup = f("cleanup", [("state", first)], [], ["alloc"], [
        b("entry", [("state", first)], [
            i("record.take", ["state"], [("owned", "buffer"), ("empty", empty)], field="first"),
            i("owner.drop", ["owned"]), i("record.abandon", ["empty"]),
        ], ret())])
    main = f("roundtrip", [("size", "usize"), ("cancel", "bool")], ["usize"], ["alloc", "trap"], [
        b("entry", [("size", "usize"), ("cancel", "bool")], [
            i("record.begin", out=[("empty", empty)]),
            i("buffer.try_new", ["size"], [("initial", "buffer"), ("ok", "bool")]),
            i("record.insert", ["empty", "initial"], [("first", first)], field="first"),
        ], branch("ok", ("ready", "first", "size", "cancel"), ("error", "first"))),
        b("error", [("failed", first)], [
            i("call", ["failed"], function="cleanup"), c("failure", "usize", 250),
        ], ret("failure")),
        b("ready", [("state", first), ("length", "usize"), ("cancelled", "bool")], [],
          branch("cancelled", ("cancel_path", "state"), ("work", "state", "length"))),
        b("cancel_path", [("stopped", first)], [
            i("call", ["stopped"], function="cleanup"), c("cancelled_value", "usize", 33),
        ], ret("cancelled_value")),
        b("work", [("working", first), ("new_size", "usize")], [
            i("call", ["working"], [("whole", pair)], function="complete"),
            i("record.take", ["whole"], [("old", "buffer"), ("remaining", second)], field="first"),
            i("buffer.len", ["old"], [("old_length", "usize")]),
            i("owner.drop", ["old"]),
            i("buffer.try_new", ["new_size"], [("replacement", "buffer"), ("replaced", "bool")]),
            i("record.insert", ["remaining", "replacement"], [("refilled", both)], field="first"),
            i("record.finish", ["refilled"], [("restored", pair)]),
            i("record.unpack", ["restored"], [("final", "buffer"), ("count", "usize")]),
            i("buffer.len", ["final"], [("final_length", "usize")]), i("owner.drop", ["final"]),
            i("int.add.checked", ["old_length", "final_length"], [("length_sum", "usize")]),
            i("int.add.checked", ["length_sum", "count"], [("answer", "usize")]),
        ], ret("answer")),
    ])
    return v3(types, complete, cleanup, main)


def task_partial_program():
    """Partial initialized state through pending/running/ready/cancel paths."""
    pair = ref("Pair", "buffer", "usize")
    empty, first, second, both = (partial(pair, *names) for names in
                                  [(), ("first",), ("second",), ("first", "second")])
    types = [record("Pair", [("first", "T"), ("second", "U")], ["T", "U"]),
             enum("Step", [("pending", [("state", both)]), ("ready", [("result", "buffer")])]),
             {"name": "Work", "kind": "task", "params": [], "state": both,
              "result": "buffer", "poll": "poll", "cancel": "cancel_state"}]
    poll = f("poll", [("state", both)], ["Step"], ["alloc"], [
        b("entry", [("state", both)], [
            i("record.get", ["state"], [("count", "usize")], field="second"),
            c("zero", "usize", 0), i("compare.eq", ["count", "zero"], [("ready", "bool")]),
        ], branch("ready", ("done", "state"), ("yield", "state"))),
        b("done", [("finished", both)], [
            i("record.take", ["finished"], [("result", "buffer"), ("count_state", second)], field="first"),
            i("record.take", ["count_state"], [("done_count", "usize"), ("done_empty", empty)], field="second"),
            i("record.abandon", ["done_empty"]),
            i("enum.make", ["result"], [("done_step", "Step")], variant="ready"),
        ], ret("done_step")),
        b("yield", [("pending", both)], [
            i("record.take", ["pending"], [("old_count", "usize"), ("owner_state", first)], field="second"),
            c("next_count", "usize", 0),
            i("record.insert", ["owner_state", "next_count"], [("next_state", both)], field="second"),
            i("enum.make", ["next_state"], [("pending_step", "Step")], variant="pending"),
        ], ret("pending_step")),
    ])
    cancel = f("cancel_state", [("state", both)], [], ["alloc"], [
        b("entry", [("state", both)], [
            i("record.take", ["state"], [("owned", "buffer"), ("count_state", second)], field="first"),
            i("owner.drop", ["owned"]),
            i("record.take", ["count_state"], [("count", "usize"), ("empty", empty)], field="second"),
            i("record.abandon", ["empty"]),
        ], ret())])
    main = f("partial_task", [("size", "usize"), ("mode", "u8")], ["usize"], ["alloc", "trap"], [
        b("entry", [("size", "usize"), ("mode", "u8")], [
            i("record.begin", out=[("empty", empty)]),
            i("buffer.try_new", ["size"], [("owned", "buffer"), ("ok", "bool")]),
            i("record.insert", ["empty", "owned"], [("first", first)], field="first"),
            c("count", "usize", 1),
            i("record.insert", ["first", "count"], [("state", both)], field="second"),
            i("task.create", ["state"], [("task", "Work")]),
            c("zero_mode", "u8", 0), i("compare.eq", ["mode", "zero_mode"], [("pending_cancel", "bool")]),
        ], branch("pending_cancel", ("cancel_pending", "task"), ("begin", "task", "mode"))),
        b("cancel_pending", [("pending", "Work")], [
            i("task.cancel", ["pending"], [("cancelled", "Work")]), i("task.close", ["cancelled"]),
            c("pending_answer", "usize", 30),
        ], ret("pending_answer")),
        b("begin", [("initial", "Work"), ("begin_mode", "u8")], [
            i("task.start", ["initial"], [("running", "Work")]),
            i("task.poll", ["running"], [("yielded", "Work")]),
            c("one_mode", "u8", 1), i("compare.eq", ["begin_mode", "one_mode"], [("running_cancel", "bool")]),
        ], branch("running_cancel", ("cancel_running", "yielded"), ("complete", "yielded"))),
        b("cancel_running", [("live", "Work")], [
            i("task.cancel", ["live"], [("stopped", "Work")]), i("task.close", ["stopped"]),
            c("running_answer", "usize", 10),
        ], ret("running_answer")),
        b("complete", [("last", "Work")], [
            i("task.poll", ["last"], [("finished", "Work")]),
            i("task.cancel", ["finished"], [("retained", "Work")]),
            i("task.join", ["retained"], [("result", "buffer")]),
            i("buffer.len", ["result"], [("length", "usize")]), i("owner.drop", ["result"]),
            c("twenty", "usize", 20), i("int.add.checked", ["twenty", "length"], [("answer", "usize")]),
        ], ret("answer")),
    ])
    return v3(types, poll, cancel, main)


def nested_record_program():
    pair = ref("Pair", "buffer", "usize")
    inner_empty, inner_second = partial(pair), partial(pair, "second")
    outer_empty, outer_tail = partial("Outer"), partial("Outer", "tail")
    types = [record("Pair", [("first", "T"), ("second", "U")], ["T", "U"]),
             record("Outer", [("inner", pair), ("tail", "u8")])]
    return v3(types, f("nested", [("size", "usize")], ["usize"], ["alloc", "trap"], [
        b("entry", [("size", "usize")], [
            i("buffer.try_new", ["size"], [("payload", "buffer"), ("ok", "bool")]),
            c("count", "usize", 9), c("tail", "u8", 5),
            i("record.make", ["payload", "count"], [("pair", pair)]),
            i("record.make", ["pair", "tail"], [("outer", "Outer")]),
            i("record.take", ["outer"], [("inner", pair), ("outer_rest", outer_tail)], field="inner"),
            i("record.take", ["inner"], [("owned", "buffer"), ("inner_rest", inner_second)], field="first"),
            i("buffer.len", ["owned"], [("length", "usize")]), i("owner.drop", ["owned"]),
            i("record.take", ["inner_rest"], [("inner_count", "usize"), ("empty_inner", inner_empty)], field="second"),
            i("record.abandon", ["empty_inner"]),
            i("record.take", ["outer_rest"], [("outer_tail", "u8"), ("empty_outer", outer_empty)], field="tail"),
            i("record.abandon", ["empty_outer"]),
            i("int.cast", ["outer_tail"], [("tail_usize", "usize")], mode="checked"),
            i("int.add.checked", ["length", "inner_count"], [("subtotal", "usize")]),
            i("int.add.checked", ["subtotal", "tail_usize"], [("answer", "usize")]),
        ], ret("answer"))]))


def chain_partial_program():
    empty, present = partial("ChainBox"), partial("ChainBox", "nodes")
    return v3([record("ChainBox", [("nodes", "chain")])],
              f("chain_case", [], ["bool"], ["alloc"], [b("entry", [], [
                  i("chain.empty", out=[("tail", "chain")]), c("size", "usize", 3),
                  i("buffer.try_new", ["size"], [("payload", "buffer"), ("allocated", "bool")]),
                  i("chain.try_push", ["tail", "payload"],
                    [("head", "chain"), ("unused", "buffer"), ("pushed", "bool")]),
                  i("owner.drop", ["unused"]),
                  i("record.begin", out=[("empty", empty)]),
                  i("record.insert", ["empty", "head"], [("state", present)], field="nodes"),
                  i("record.take", ["state"], [("nodes", "chain"), ("rest", empty)], field="nodes"),
                  i("record.abandon", ["rest"]),
                  i("chain.is_empty", ["nodes"], [("answer", "bool")]),
                  i("owner.drop", ["nodes"]),
              ], ret("answer"))]))


class PartialRecordExecutionTests(unittest.TestCase):
    def test_roundtrip_cross_call_and_reinitialization(self):
        for size in [0, 1, 13, 257]:
            report = execute_program(roundtrip_program(), "roundtrip", [size, False])
            self.assertEqual(report["result"], size * 2 + 17)
            self.assertEqual(report["resources"]["owners_created"], 4)
            self.assertEqual(report["resources"]["owners_dropped"], 4)
            self.assertEqual(report["resources"]["allocations"], 2 if size else 0)
            self.assertEqual(report["resources"]["frees"], 2 if size else 0)

    def test_error_and_cancel_only_clean_initialized_fields(self):
        for cancel, fail, expected in [(True, None, 33), (False, 1, 250), (True, 1, 250)]:
            report = execute_program(roundtrip_program(), "roundtrip", [13, cancel], allocation_fail_at=fail)
            self.assertEqual(report["result"], expected)
            self.assertEqual(report["resources"]["owners_created"], 2)
            self.assertEqual(report["resources"]["owners_dropped"], 2)
            self.assertEqual(report["resources"]["live_owners"], 0)
            self.assertEqual(report["resources"]["live_local_loans"], 0)

    def test_empty_tokens_do_not_consume_failure_index(self):
        report = execute_program(roundtrip_program(), "roundtrip", [13, False], allocation_fail_at=2)
        self.assertEqual(report["result"], 30)
        self.assertEqual(report["resources"]["allocations"], 1)
        self.assertEqual(report["resources"]["frees"], 1)
        self.assertEqual(report["resources"]["owners_created"], 4)
        self.assertEqual(report["resources"]["owners_dropped"], 4)

    def test_partial_states_compose_with_cooperative_tasks(self):
        for mode, expected in [(0, 30), (1, 10), (2, 33), (255, 33)]:
            for fail in [None, 1]:
                report = execute_program(task_partial_program(), "partial_task", [13, mode], allocation_fail_at=fail)
                self.assertEqual(report["result"], expected if fail is None or mode < 2 else 20)
                self.assertEqual(report["resources"]["live_owners"], 0)
                self.assertEqual(report["resources"]["live_local_loans"], 0)
                self.assertEqual(report["resources"]["allocations"], 1 if fail is None else 0)
                self.assertEqual(report["resources"]["frees"], 1 if fail is None else 0)
                self.assertEqual(report["resources"]["owners_created"], report["resources"]["owners_dropped"])

    def test_core_erases_only_present_fields_and_retains_linearity(self):
        checked = verify_core(roundtrip_program())
        core = checked.as_dict()
        self.assertEqual(core["schema"], SCHEMA_V7)
        self.assertEqual(core["exports"], ["roundtrip"])
        complete = next(fn for fn in core["functions"] if fn["name"] == "complete")
        self.assertEqual([p["type"] for p in complete["params"]], ["buffer", "buffer"])
        self.assertFalse(any(op["op"].startswith("record.") for fn in core["functions"]
                             for block in fn["blocks"] for op in block["ops"]))
        self.assertEqual(execute_program(core, "roundtrip", [13, False])["result"], 43)

    def test_initialized_field_borrow_and_get(self):
        source = roundtrip_program()
        work = source["functions"][2]["blocks"][4]
        work["ops"][:0] = [
            i("record.borrow", ["working"], [("view", "mutbuf")], field="first", mode="mut"),
            c("index", "usize", 0), c("byte", "u8", 91),
            i("buffer.store", ["view", "index", "byte"]), i("loan.end", ["view"]),
        ]
        source["functions"][2]["effects"] += ["read", "write"]
        report = execute_program(source, "roundtrip", [13, False])
        self.assertEqual(report["result"], 43)
        self.assertEqual(report["resources"]["live_local_loans"], 0)

    def test_step_stop_does_not_invent_partial_cleanup(self):
        with self.assertRaises(HIAProgramBudgetExceeded) as caught:
            execute_program(roundtrip_program(), "roundtrip", [13, False], max_steps=3)
        self.assertGreater(caught.exception.report["resources"]["live_owners"], 0)
        self.assertEqual(caught.exception.report["resources"]["frees"], 0)

    def test_nested_generic_record_fields_are_moved_and_cleaned(self):
        for size in [0, 7, 129]:
            report = execute_program(nested_record_program(), "nested", [size])
            self.assertEqual(report["result"], size + 14)
            self.assertEqual(report["resources"]["owners_created"], 3)
            self.assertEqual(report["resources"]["owners_dropped"], 3)
            self.assertEqual(report["resources"]["live_owners"], 0)

    def test_chain_fields_keep_headers_and_payload_accounting(self):
        for failure in [None, 2]:
            report = execute_program(chain_partial_program(), "chain_case", [], allocation_fail_at=failure)
            self.assertEqual(report["result"], failure == 2)
            ledger = report["resources"]
            self.assertEqual(ledger["allocations"], 2 if failure is None else 1)
            self.assertEqual(ledger["allocations"], ledger["frees"])
            for name in ["live_owners", "live_chains", "live_chain_nodes", "live_bytes"]:
                self.assertEqual(ledger[name], 0, name)

    def test_empty_and_scalar_records_retain_real_linear_tokens(self):
        for fields, ops in [([], []), ([("value", "u8")], [
                c("byte", "u8", 71), i("record.insert", ["empty", "byte"],
                    [("filled", partial("Scalar", "value"))], field="value")])]:
            finish = "filled" if fields else "empty"
            source = v3([record("Scalar", fields)], f("scalar", [], [], ["alloc"], [b("entry", [], [
                i("record.begin", out=[("empty", partial("Scalar"))]), *ops,
                i("record.finish", [finish], [("record", "Scalar")]),
            ], ret())]))
            result = execute_program(source, "scalar", [])
            self.assertEqual(result["resources"]["owners_created"], 1)
            self.assertEqual(result["resources"]["owners_dropped"], 1)
            self.assertEqual(result["resources"]["allocation_attempts"], 0)
            self.assertEqual(result["resources"]["frees"], 0)


class PartialRecordRejectionTests(unittest.TestCase):
    def reject(self, source, code=None):
        with self.assertRaises(HIAProgramRejected) as caught:
            verify_core(source)
        if code is not None:
            self.assertEqual(caught.exception.code, code)

    def test_old_schemas_reject_partial_types(self):
        for schema in [COMPOSITE_SCHEMA, COMPOSITE_SCHEMA_V2]:
            source = roundtrip_program()
            source["schema"] = schema
            self.reject(source, "E_HIA_FORMAT")

    def test_old_schemas_reject_new_operations_even_without_partial_types(self):
        for schema in [COMPOSITE_SCHEMA, COMPOSITE_SCHEMA_V2]:
            source = v3([], f("main", [], [], ["alloc"], [b("entry", [], [i("record.begin")], ret())]))
            source["schema"] = schema
            self.reject(source, "E_HIA_OPCODE")

    def test_registry_keeps_versions_separate(self):
        versions = {item["schema"]: item for item in schema_registry()["composite_versions"]}
        for schema in [COMPOSITE_SCHEMA, COMPOSITE_SCHEMA_V2]:
            self.assertNotIn("record.take", versions[schema]["nominal_operations"])
        self.assertIn("record.take", versions[COMPOSITE_SCHEMA_V3]["nominal_operations"])
        self.assertEqual(versions[COMPOSITE_SCHEMA_V3]["normalizes_to"], SCHEMA_V7)

    def test_uninitialized_read_and_borrow_reject(self):
        for op in [i("record.get", ["state"], [("missing", "usize")], field="second"),
                   i("record.borrow", ["state"], [("missing", "readbuf")], field="second", mode="read")]:
            source = roundtrip_program()
            source["functions"][0]["blocks"][0]["ops"].insert(0, op)
            self.reject(source, "E_HIA_INIT")

    def test_duplicate_initialization_rejects(self):
        source = roundtrip_program()
        source["functions"][0]["blocks"][0]["ops"][1]["attrs"]["field"] = "first"
        self.reject(source, "E_HIA_INIT")

    def test_finish_missing_field_rejects(self):
        source = roundtrip_program()
        complete = source["functions"][0]
        complete["blocks"][0]["ops"] = [i("record.finish", ["state"], [("done", complete["returns"][0])])]
        self.reject(source, "E_HIA_INIT")

    def test_abandon_live_field_rejects(self):
        source = roundtrip_program()
        source["functions"][1]["blocks"][0]["ops"] = [i("record.abandon", ["state"])]
        self.reject(source, "E_HIA_INIT")

    def test_begin_cannot_assert_initialized_field(self):
        source = roundtrip_program()
        source["functions"][2]["blocks"][0]["ops"][0]["out"][0]["type"]["initialized"] = ["first"]
        self.reject(source, "E_HIA_INIT")

    def test_use_after_take_and_insert_rejects(self):
        source = roundtrip_program()
        ops = source["functions"][1]["blocks"][0]["ops"]
        ops.insert(1, i("record.borrow", ["state"], [("old", "readbuf")], field="first", mode="read"))
        self.reject(source, "E_HIA_RESOURCE")

    def test_lost_partial_token_rejects(self):
        source = roundtrip_program()
        source["functions"][1]["blocks"][0]["ops"].pop()
        self.reject(source, "E_HIA_RESOURCE")

    def test_edge_different_initialization_state_rejects(self):
        source = roundtrip_program()
        source["functions"][2]["blocks"][1]["params"][0]["type"]["initialized"] = []
        self.reject(source, "E_HIA_TYPE")

    def test_taking_borrowed_owner_rejects(self):
        source = roundtrip_program()
        ops = source["functions"][2]["blocks"][4]["ops"]
        ops.insert(1, i("record.borrow", ["whole"], [("loan", "readbuf")], field="first", mode="read"))
        ops.insert(3, i("loan.end", ["loan"]))
        self.reject(source, "E_HIA_LOAN")

    def test_transfer_partial_owner_with_live_loan_rejects(self):
        source = roundtrip_program()
        ops = source["functions"][2]["blocks"][4]["ops"]
        ops.insert(0, i("record.borrow", ["working"], [("loan", "readbuf")], field="first", mode="read"))
        ops.insert(2, i("loan.end", ["loan"]))
        self.reject(source, "E_HIA_LOAN")

    def test_state_inventory_must_exist_be_unique_and_ordered(self):
        for fields in [["missing"], ["first", "first"], ["second", "first"]]:
            source = roundtrip_program()
            source["functions"][0]["params"][0]["type"]["initialized"] = fields
            self.reject(source, "E_HIA_INIT")

    def test_stored_loan_partial_record_is_rejected(self):
        state = partial("Stored")
        source = v3([record("Stored", [("view", "readbuf")])],
                    f("main", [], [], ["alloc"], [b("entry", [], [
                        i("record.begin", out=[("state", state)]),
                        i("record.abandon", ["state"]),
                    ], ret())]))
        self.reject(source, "E_HIA_LOAN")

    def test_cycles_through_partial_types_reject_even_unused(self):
        source = v3([record("Cycle", [("next", partial("Cycle"))])],
                    f("main", [], [], [], [b("entry", [], [], ret())]))
        self.reject(source, "E_HIA_TYPE")

    def test_empty_token_still_requires_alloc_effect(self):
        source = v3([record("Empty", [])], f("main", [], [], [], [b("entry", [], [
            i("record.begin", out=[("empty", partial("Empty"))]),
            i("record.abandon", ["empty"]),
        ], ret())]))
        self.reject(source, "E_HIA_EFFECT")

    def test_erased_token_cannot_be_removed_without_core_rejection(self):
        core = verify_core(roundtrip_program()).as_dict()
        cleanup = next(fn for fn in core["functions"] if fn["name"] == "cleanup")
        cleanup["blocks"][0]["ops"].pop()
        self.reject(core, "E_HIA_RESOURCE")

    def test_nested_owner_move_rejects_live_borrow(self):
        source = nested_record_program()
        ops = source["functions"][0]["blocks"][0]["ops"]
        ops.insert(3, i("borrow.read", ["payload"], [("loan", "readbuf")]))
        ops.insert(7, i("loan.end", ["loan"]))
        self.reject(source, "E_HIA_LOAN")

    def test_partial_typestates_consume_instantiation_budget(self):
        fields = [("f" + str(index), "u8") for index in range(8)]
        params = [("state" + str(mask), partial("Many", *[name for index, (name, _) in enumerate(fields)
                                                        if mask & (1 << index)])) for mask in range(128)]
        source = v3([record("Many", fields)], f("states", params, [], ["trap"],
                    [b("entry", params, [], {"op": "trap", "code": "user"})]))
        self.reject(source, "E_HIA_LIMIT")

    def test_partial_token_counts_against_flattened_layout_budget(self):
        small = record("Eight", [("f" + str(index), "u8") for index in range(8)])
        big = record("Big", [("g" + str(index), "Eight") for index in range(64)])
        typ = partial("Big", *["g" + str(index) for index in range(64)])
        source = v3([small, big], f("layout", [("state", typ)], [], ["trap"],
                    [b("entry", [("state", typ)], [], {"op": "trap", "code": "user"})]))
        self.reject(source, "E_HIA_LIMIT")

    def test_unused_concrete_partial_references_are_not_erased_unchecked(self):
        cases = [
            ([record("Unused", [("field", partial("u8"))])], "E_HIA_TYPE"),
            ([record("Base", [("field", "u8")]),
              record("Unused", [("field", partial("Base", "missing"))])], "E_HIA_INIT"),
            ([record("Base", [("first", "u8"), ("second", "u8")]),
              record("Unused", [("field", partial("Base", "second", "first"))])], "E_HIA_INIT"),
            ([enum("Choice", [("yes", [])]),
              record("Unused", [("field", partial("Choice"))])], "E_HIA_TYPE"),
            ([record("Base", [("field", "readbuf")]),
              record("Unused", [("field", partial("Base"))])], "E_HIA_LOAN"),
            ([record("Base", [("field", "u8")]),
              record("Unused", [("field", partial(partial("Base")))])], "E_HIA_TYPE"),
        ]
        for types, code in cases:
            source = v3(types, f("main", [], [], [], [b("entry", [], [], ret())]))
            self.reject(source, code)

    def test_partial_of_unconstrained_generic_parameter_rejects(self):
        source = v3([record("Generic", [("field", partial("T"))], ["T"])],
                    f("main", [], [], [], [b("entry", [], [], ret())]))
        self.reject(source, "E_HIA_TYPE")

    def test_generic_partial_declarations_check_known_fields_and_loans(self):
        cases = [
            ([record("Box", [("value", "T")], ["T"]),
              record("Generic", [("state", partial(ref("Box", "U"), "missing"))], ["U"])], "E_HIA_INIT"),
            ([record("Box", [("value", "T"), ("view", "readbuf")], ["T"]),
              record("Generic", [("state", partial(ref("Box", "U")))], ["U"])], "E_HIA_LOAN"),
            ([record("Inner", [("value", "T"), ("view", "mutbuf")], ["T"]),
              record("Box", [("inside", ref("Inner", "U"))], ["U"]),
              record("Generic", [("state", partial(ref("Box", "V")))], ["V"])], "E_HIA_LOAN"),
            ([record("Concrete", [("view", "readbuf")]),
              record("Generic", [("state", partial("Concrete"))], ["Unused"])], "E_HIA_LOAN"),
        ]
        for types, code in cases:
            source = v3(types, f("main", [], [], [], [b("entry", [], [], ret())]))
            self.reject(source, code)

    def test_unknown_generic_loan_free_condition_is_checked_at_instantiation(self):
        types = [record("Box", [("value", "T")], ["T"]),
                 record("Generic", [("state", partial(ref("Box", "U"), "value"))], ["U"])]
        main = f("main", [], [], [], [b("entry", [], [], ret())])
        # There is no chosen fake T: this uninstantiated template retains its
        # condition, and both an owning/scalar instance and a loan instance are
        # resolved using their actual declared arguments below.
        verify_core(v3(types, main))
        for argument in ["buffer", "u8", "readbuf", "mutbuf"]:
            typ = ref("Generic", argument)
            consume = f("consume", [("value", typ)], [], ["trap"],
                        [b("entry", [("value", typ)], [], {"op": "trap", "code": "user"})])
            source = v3(types, main, consume)
            if argument in {"readbuf", "mutbuf"}:
                self.reject(source, "E_HIA_LOAN")
            else:
                verify_core(source)

    def test_repeated_symbolic_constraints_share_proof_work(self):
        nested = "U"
        for _ in range(8):
            nested = ref("Repeated", nested)
        types = [record("Repeated", [("f" + str(index), "T") for index in range(4)], ["T"]),
                 record("Unused", [("state", partial(nested))], ["U"])]
        source = v3(types, f("main", [], [], [], [b("entry", [], [], ret())]))
        verify_core(source)
        # The symbolic condition is finite after deduplication; the concrete
        # instance still exceeds the independent flattened layout bound.
        typ = ref("Unused", "u8")
        source["functions"].append(f("instance", [("state", typ)], [], ["trap"],
            [b("entry", [("state", typ)], [], {"op": "trap", "code": "user"})]))
        self.reject(source, "E_HIA_LIMIT")

    def test_distinct_symbolic_constraints_have_a_total_work_budget(self):
        types = [record("Wrap" + str(index), [("value", "T")], ["T"]) for index in range(4)]
        for level in range(8):
            fields = [("f" + str(index), ref("Level" + str(level + 1), ref("Wrap" + str(index), "T")))
                      for index in range(4)]
            types.append(record("Level" + str(level), fields, ["T"]))
        types += [record("Level8", [("value", "T")], ["T"]),
                  record("Unused", [("state", partial(ref("Level0", "U")))], ["U"])]
        source = v3(types, f("main", [], [], [], [b("entry", [], [], ret())]))
        with self.assertRaisesRegex(HIAProgramRejected, "partial declaration analysis budget exceeded"):
            verify_core(source)

    def test_symbolic_argument_substitution_has_a_nesting_budget(self):
        nested = "T"
        for _ in range(25):
            nested = ref("Wrap", nested)
        types = [record("Wrap", [("value", "T")], ["T"])]
        for level in range(3):
            types.append(record("Layer" + str(level), [("value", ref("Layer" + str(level + 1), nested))], ["T"]))
        types += [record("Layer3", [("value", "T")], ["T"]),
                  record("Unused", [("state", partial(ref("Layer0", "U")))], ["U"])]
        source = v3(types, f("main", [], [], [], [b("entry", [], [], ret())]))
        with self.assertRaisesRegex(HIAProgramRejected, "symbolic type argument nesting exceeds budget"):
            verify_core(source)


class PartialRecordCompatibilityTests(unittest.TestCase):
    def test_existing_nominal_canonical_bytes_keep_frozen_fingerprints(self):
        # Exact outputs of the pre-v3 elaborator in e6379178, independently
        # compared before these constants were added. v3 must not relabel v1/v2.
        from tests.test_hia_program_composite import (stored_loan_program, enum_owner_program,
            task_program, scalar_task_program, owned_result_task_program)
        fixtures = [
            (stored_loan_program, "4aeea8c7c520cc51578a9faadd1a600dbc630cc0368b413e5654a3dee9cfaa90",
             "72202887ef0bc02d66a75005afd65e0f7474caf8fe984b0a2a9dfc81f4b5248f"),
            (enum_owner_program, "efed208507c65dcc8457b4453d952169da3f9b500f014de482342516d7216be5",
             "1bcd0df9315d4bf0a19074615ccc477fb94e3fed8475484762adcc4e1dbbbc7c"),
            (task_program, "52f2bf4bcd36c76f234f81cae6af2002f2ab229d502d908111e4fd54807aec1c",
             "3e1478ff7fd5f0fadd0e7a775ab6d8347c126957e4776fdf12008b9bfe27f4f4"),
            (scalar_task_program, "ebf3b93fd9d47965fec65bf40820f7b491cfdb041a9785faf993eb02a745a018",
             "7f375b62b690f163d7c4bac9e662c762fa476b6d70578464d9c215cfd7a2e3f8"),
            (owned_result_task_program, "1e842ca70d53ee426768cbb761ec09ffe672347a0b0cd271e0514bb0682d5a3f",
             "9af2f1ce6825db2f03672770feffb2731881e75d6d8bde32efc7c68ee7ecbccb"),
        ]
        for factory, first, second in fixtures:
            for schema, expected in [(COMPOSITE_SCHEMA, first), (COMPOSITE_SCHEMA_V2, second)]:
                with self.subTest(factory=factory.__name__, schema=schema):
                    source = factory()
                    source["schema"] = schema
                    self.assertEqual(verify_core(source).sha256, expected)


if __name__ == "__main__":
    unittest.main()
