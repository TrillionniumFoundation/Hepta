"""Actual source-free nominal resources, stored loans and cooperative tasks."""
from __future__ import annotations

import copy
import json
import unittest

from hepta.hia_program import HIAProgramRejected, VerifiedProgram, verify_core
from hepta.hia_program_runtime import HIAProgramTrap, execute_program
from tests.test_hia_program import b, branch, c, f, i, jump, p, ret


def ref(name, *args):
    return {"name": name, "args": list(args)}


def field(name, typ):
    return {"name": name, "type": typ}


def record(name, fields, params=()):
    return {"name": name, "params": list(params), "kind": "record",
            "fields": [field(*x) for x in fields]}


def enum(name, variants, params=()):
    return {"name": name, "params": list(params), "kind": "enum",
            "variants": [{"name": tag, "fields": [field(*x) for x in fields]}
                         for tag, fields in variants]}


def module(types, *functions):
    return {"schema": "hepta.hia.program.v2", "module": "composite_test",
            "types": types, "functions": list(functions)}


def match(value, *cases):
    return {"op": "match", "value": value, "cases": [
        {"variant": variant, "target": target, "args": list(args)}
        for variant, target, args in cases]}


def stored_loan_program():
    stored = record("Stored", [("owner", "buffer"), ("writer", "mutbuf"), ("reader", "readbuf")])
    return module([stored], f("stored", [("flag", "bool")], ["u8"], ["alloc", "read", "write", "trap"], [
        b("entry", [("flag", "bool")], [
            c("one", "usize", 1), i("buffer.new", ["one"], [("owner", "buffer")]),
            i("borrow.mut", ["owner"], [("writer", "mutbuf")]),
            i("borrow.read", ["writer"], [("reader", "readbuf")]),
            i("record.make", ["owner", "writer", "reader"], [("stored_value", "Stored")]),
        ], branch("flag", ("use", "stored_value"), ("use", "stored_value"))),
        b("use", [("bundle", "Stored")], [
            i("record.unpack", ["bundle"], [("moved", "buffer"), ("parent", "mutbuf"), ("child", "readbuf")]),
            c("zero", "usize", 0), i("buffer.load", ["child", "zero"], [("before", "u8")]),
            i("loan.end", ["child"]), c("byte", "u8", 91),
            i("buffer.store", ["parent", "zero", "byte"]), i("loan.end", ["parent"]),
            i("borrow.read", ["moved"], [("last", "readbuf")]),
            i("buffer.load", ["last", "zero"], [("after", "u8")]),
            i("loan.end", ["last"]), i("owner.drop", ["moved"]),
        ], ret("after")),
    ]))


def enum_owner_program():
    choice = ref("Choice", "buffer", "buffer")
    types = [enum("Choice", [("ok", [("value", "T")]), ("error", [("error", "E")])], ["T", "E"])]
    return module(types, f("choose", [("flag", "bool"), ("size", "usize")], ["usize"], ["alloc", "trap"], [
        b("entry", [("flag", "bool"), ("size", "usize")], [
            i("buffer.try_new", ["size"], [("owned", "buffer"), ("ok", "bool")]),
        ], branch("flag", ("left", "owned"), ("right", "owned"))),
        b("left", [("left_owner", "buffer")], [
            i("enum.make", ["left_owner"], [("left_value", choice)], variant="ok"),
        ], jump("inspect", "left_value")),
        b("right", [("right_owner", "buffer")], [
            i("enum.make", ["right_owner"], [("right_value", choice)], variant="error"),
        ], jump("inspect", "right_value")),
        b("inspect", [("value", choice)], [], match("value", ("ok", "yes", []), ("error", "no", []))),
        b("yes", [("yes_owner", "buffer")], [
            i("buffer.len", ["yes_owner"], [("yes_length", "usize")]), i("owner.drop", ["yes_owner"]),
        ], ret("yes_length")),
        b("no", [("no_owner", "buffer")], [
            i("buffer.len", ["no_owner"], [("no_length", "usize")]), i("owner.drop", ["no_owner"]),
            c("ten", "usize", 10), i("int.add.checked", ["no_length", "ten"], [("with_error", "usize")]),
        ], ret("with_error")),
    ]))


def task_program():
    state = ref("Pair", "buffer", "usize")
    step = ref("Step", state, "usize")
    types = [record("Pair", [("first", "T"), ("second", "U")], ["T", "U"]),
             enum("Step", [("pending", [("state", "S")]), ("ready", [("result", "R")])], ["S", "R"]),
             {"name": "Work", "params": [], "kind": "task", "state": state,
              "result": "usize", "poll": "poll_owned", "cancel": "cancel_owned"},
             record("LoanFrame", [("owner", "buffer"), ("writer", "mutbuf"), ("reader", "readbuf")])]
    poll = f("poll_owned", [("state", state)], [step], ["alloc", "read", "write", "trap"], [
        b("entry", [("state", state)], [
            i("record.unpack", ["state"], [("owned", "buffer"), ("remaining", "usize")]),
            c("zero", "usize", 0), i("compare.eq", ["remaining", "zero"], [("done", "bool")]),
        ], branch("done", ("ready", "owned"), ("yield", "owned", "remaining"))),
        b("ready", [("completed_owner", "buffer")], [
            i("buffer.len", ["completed_owner"], [("length", "usize")]),
            i("borrow.read", ["completed_owner"], [("final_reader", "readbuf")]),
            c("final_index", "usize", 0), i("buffer.load", ["final_reader", "final_index"], [("last_byte", "u8")]),
            i("loan.end", ["final_reader"]),
            i("int.cast", ["last_byte"], [("last_usize", "usize")], mode="checked"),
            i("int.add.checked", ["length", "last_usize"], [("observed_length", "usize")]),
            i("owner.drop", ["completed_owner"]),
            i("enum.make", ["observed_length"], [("ready_step", step)], variant="ready"),
        ], ret("ready_step")),
        b("yield", [("yielded_owner", "buffer"), ("count", "usize")], [
            i("borrow.mut", ["yielded_owner"], [("yield_writer", "mutbuf")]),
            i("borrow.read", ["yield_writer"], [("yield_reader", "readbuf")]),
            i("record.make", ["yielded_owner", "yield_writer", "yield_reader"], [("frame", "LoanFrame")]),
            i("record.unpack", ["frame"], [("frame_owner", "buffer"), ("frame_writer", "mutbuf"), ("frame_reader", "readbuf")]),
            c("yield_index", "usize", 0), i("buffer.load", ["frame_reader", "yield_index"], [("previous_byte", "u8")]),
            i("loan.end", ["frame_reader"]),
            i("int.cast", ["count"], [("current_byte", "u8")], mode="wrap"),
            i("buffer.store", ["frame_writer", "yield_index", "current_byte"]),
            i("loan.end", ["frame_writer"]),
            c("one", "usize", 1), i("int.sub.checked", ["count", "one"], [("remaining_count", "usize")]),
            i("record.make", ["frame_owner", "remaining_count"], [("next_state", state)]),
            i("enum.make", ["next_state"], [("pending_step", step)], variant="pending"),
        ], ret("pending_step")),
    ])
    cancel = f("cancel_owned", [("state", state)], [], ["alloc"], [
        b("entry", [("state", state)], [
            i("record.unpack", ["state"], [("owned", "buffer"), ("count", "usize")]),
            i("owner.drop", ["owned"]),
        ], ret()),
    ])
    main = f("task_case", [("mode", "u8")], ["usize"], ["alloc", "read", "write", "trap"], [
        b("entry", [("mode", "u8")], [
            c("size", "usize", 7), i("buffer.try_new", ["size"], [("owned", "buffer"), ("allocated", "bool")]),
        ], branch("allocated", ("make", "owned", "mode"), ("error", "owned"))),
        b("error", [("empty", "buffer")], [i("owner.drop", ["empty"]), c("failure", "usize", 250)], ret("failure")),
        b("make", [("owner", "buffer"), ("mode_copy", "u8")], [
            c("count", "usize", 2), i("record.make", ["owner", "count"], [("state", state)]),
            i("task.create", ["state"], [("pending", "Work")]),
            c("mode_zero", "u8", 0), i("compare.eq", ["mode_copy", "mode_zero"], [("cancel_pending", "bool")]),
        ], branch("cancel_pending", ("pending_cancel", "pending"), ("begin", "pending", "mode_copy"))),
        b("pending_cancel", [("pending_task", "Work")], [
            i("task.cancel", ["pending_task"], [("cancelled_once", "Work")]),
            i("task.cancel", ["cancelled_once"], [("cancelled_twice", "Work")]),
            i("task.state", ["cancelled_twice"], [("cancelled_status", "u8")]),
            i("task.close", ["cancelled_twice"]),
            i("int.cast", ["cancelled_status"], [("cancelled_usize", "usize")], mode="checked"),
            c("thirty", "usize", 30), i("int.add.checked", ["thirty", "cancelled_usize"], [("pending_answer", "usize")]),
        ], ret("pending_answer")),
        b("begin", [("created_task", "Work"), ("begin_mode", "u8")], [
            i("task.start", ["created_task"], [("running", "Work")]),
            i("task.poll", ["running"], [("yielded", "Work")]),
            c("mode_one", "u8", 1), i("compare.eq", ["begin_mode", "mode_one"], [("cancel_running", "bool")]),
        ], branch("cancel_running", ("running_cancel", "yielded"), ("loop", "yielded"))),
        b("running_cancel", [("live_task", "Work")], [
            i("task.cancel", ["live_task"], [("stopped", "Work")]),
            i("task.state", ["stopped"], [("stopped_status", "u8")]), i("task.close", ["stopped"]),
            i("int.cast", ["stopped_status"], [("stopped_usize", "usize")], mode="checked"),
            c("ten", "usize", 10), i("int.add.checked", ["ten", "stopped_usize"], [("running_answer", "usize")]),
        ], ret("running_answer")),
        b("loop", [("loop_task", "Work")], [
            i("task.state", ["loop_task"], [("status", "u8")]), c("complete", "u8", 2),
            i("compare.eq", ["status", "complete"], [("finished", "bool")]),
        ], branch("finished", ("finish", "loop_task"), ("poll", "loop_task"))),
        b("poll", [("poll_task", "Work")], [i("task.poll", ["poll_task"], [("next_task", "Work")])], jump("loop", "next_task")),
        b("finish", [("done_task", "Work")], [
            i("task.cancel", ["done_task"], [("too_late", "Work")]),
            i("task.state", ["too_late"], [("success_status", "u8")]),
            i("task.join", ["too_late"], [("result", "usize")]),
            i("int.cast", ["success_status"], [("success_usize", "usize")], mode="checked"),
            c("scale", "usize", 10), i("int.mul.checked", ["success_usize", "scale"], [("prefix", "usize")]),
            i("int.add.checked", ["prefix", "result"], [("completed_answer", "usize")]),
        ], ret("completed_answer")),
    ])
    return module(types, poll, cancel, main)


def scalar_task_program():
    types = [enum("ScalarStep", [("pending", [("state", "usize")]), ("ready", [("result", "usize")])]),
             {"name": "ScalarWork", "kind": "task", "params": [], "state": "usize", "result": "usize",
              "poll": "scalar_poll", "cancel": "scalar_cancel"}]
    poll = f("scalar_poll", [("n", "usize")], ["ScalarStep"], [], [
        b("entry", [("n", "usize")], [i("enum.make", ["n"], [("step", "ScalarStep")], variant="ready")], ret("step"))])
    cancel = f("scalar_cancel", [("n", "usize")], [], [], [b("entry", [("n", "usize")], [], ret())])
    main = f("scalar_task", [], ["u8"], ["alloc", "trap"], [
        b("entry", [], [c("zero", "usize", 0), i("task.create", ["zero"], [("task", "ScalarWork")]),
                        i("task.cancel", ["task"], [("cancelled", "ScalarWork")]),
                        i("task.state", ["cancelled"], [("status", "u8")]), i("task.close", ["cancelled"])], ret("status"))])
    return module(types, poll, cancel, main)


def owned_result_task_program():
    types = [enum("OwnedStep", [("pending", [("state", "buffer")]), ("ready", [("result", "buffer")])]),
             {"name": "OwnedWork", "kind": "task", "params": [], "state": "buffer", "result": "buffer",
              "poll": "owned_poll", "cancel": "owned_cancel"}]
    poll = f("owned_poll", [("owned", "buffer")], ["OwnedStep"], ["alloc"], [
        b("entry", [("owned", "buffer")], [i("enum.make", ["owned"], [("step", "OwnedStep")], variant="ready")], ret("step"))])
    cancel = f("owned_cancel", [("owned", "buffer")], [], ["alloc"], [
        b("entry", [("owned", "buffer")], [i("owner.drop", ["owned"])], ret())])
    main = f("owned_result", [("size", "usize")], ["usize"], ["alloc", "trap"], [
        b("entry", [("size", "usize")], [
            i("buffer.try_new", ["size"], [("owned", "buffer"), ("ok", "bool")]),
            i("task.create", ["owned"], [("created", "OwnedWork")]),
            i("task.start", ["created"], [("started", "OwnedWork")]),
            i("task.poll", ["started"], [("completed", "OwnedWork")]),
            i("task.cancel", ["completed"], [("retained", "OwnedWork")]),
            i("task.join", ["retained"], [("result", "buffer")]),
            i("buffer.len", ["result"], [("length", "usize")]), i("owner.drop", ["result"]),
        ], ret("length"))])
    return module(types, poll, cancel, main)


class CompositeExecutionTests(unittest.TestCase):
    def test_stored_owner_parent_child_survive_aggregate_branch(self):
        for flag in [False, True]:
            report = execute_program(stored_loan_program(), "stored", [flag])
            self.assertEqual(report["result"], 91)
            self.assertEqual(report["resources"]["allocations"], 1)
            self.assertEqual(report["resources"]["frees"], 1)
            self.assertEqual(report["resources"]["live_owners"], 0)
            self.assertEqual(report["resources"]["live_local_loans"], 0)

    def test_generic_enum_both_owner_variants_failure_and_empty_padding(self):
        for flag in [False, True]:
            for size, fail, length in [(0, None, 0), (7, None, 7), (7, 1, 0), ((1 << 64) - 1, None, 0)]:
                with self.subTest(flag=flag, size=size, fail=fail):
                    report = execute_program(enum_owner_program(), "choose", [flag, size], allocation_fail_at=fail)
                    self.assertEqual(report["result"], length + (0 if flag else 10))
                    self.assertEqual(report["resources"]["live_owners"], 0)
                    self.assertEqual(report["resources"]["owners_created"], report["resources"]["owners_dropped"])

    def test_cooperative_task_pending_running_complete_and_refusal(self):
        for mode, expected in [(0, 33), (1, 13), (2, 28), (255, 28)]:
            report = execute_program(task_program(), "task_case", [mode])
            self.assertEqual(report["result"], expected)
            self.assertEqual(report["resources"]["allocations"], 1)
            self.assertEqual(report["resources"]["frees"], 1)
            self.assertEqual(report["resources"]["live_owners"], 0)
            self.assertEqual(report["resources"]["owners_created"], report["resources"]["owners_dropped"])
            failed = execute_program(task_program(), "task_case", [mode], allocation_fail_at=1)
            self.assertEqual(failed["result"], 250)
            self.assertEqual(failed["resources"]["allocation_attempts"], 1)
            self.assertEqual(failed["resources"]["live_owners"], 0)

    def test_canonical_core_and_input_identity_rechecked(self):
        original = task_program()
        checked = verify_core(original)
        self.assertNotEqual(checked.sha256, checked.input_sha256)
        self.assertEqual(checked, verify_core(checked))
        self.assertEqual(checked, verify_core(json.dumps(original, indent=2)))
        self.assertEqual(checked.scalar_entrypoints, frozenset({"task_case"}))
        self.assertTrue(checked.normalization_report["structured_elaboration_rechecked"])
        self.assertEqual(execute_program(checked.as_dict(), "task_case", [2])["result"], 28)
        report = checked.report()
        self.assertTrue(report["claims"]["cooperative_task_protocol_checked"])
        self.assertFalse(report["claims"]["concurrency_supported"])

    def test_changed_origin_and_changed_core_cannot_reuse_verified_object(self):
        checked = verify_core(task_program())
        for forged in [VerifiedProgram(checked.canonical_bytes, checked.structured_bytes.replace(b'"value":7', b'"value":8')),
                       VerifiedProgram(checked.canonical_bytes.replace(b'"value":7', b'"value":8'), checked.structured_bytes),
                       VerifiedProgram(checked.canonical_bytes, b"{}"),
                       VerifiedProgram(checked.canonical_bytes, "not bytes")]:
            with self.subTest(origin=type(forged.structured_bytes)), self.assertRaises(HIAProgramRejected):
                execute_program(forged, "task_case", [2])

    def test_nominal_internal_signatures_are_not_public_interpreter_inputs(self):
        program = verify_core(task_program())
        for name in ["poll_owned", "cancel_owned"] + [f["name"] for f in program.as_dict()["functions"] if f["name"].startswith("h2internal_")]:
            with self.subTest(function=name), self.assertRaises(HIAProgramRejected):
                execute_program(program, name, [0])

    def test_normalized_module_preserves_explicit_public_entrypoints(self):
        original = verify_core(task_program())
        normalized = verify_core(original.canonical_bytes)
        self.assertEqual(original.scalar_entrypoints, normalized.scalar_entrypoints)
        self.assertEqual(normalized.as_dict()["exports"], ["task_case"])
        for candidate in (original, normalized):
            for fn in candidate.as_dict()["functions"]:
                if fn["name"].startswith("h2internal_"):
                    with self.assertRaises(HIAProgramRejected):
                        execute_program(candidate, fn["name"], [])

    def test_scalar_task_has_primitive_linear_token_without_allocator_calls(self):
        original = verify_core(scalar_task_program())
        for candidate in (original, original.as_dict()):
            report = execute_program(candidate, "scalar_task", [])
            self.assertEqual(report["result"], 3)
            self.assertEqual(report["resources"]["allocation_attempts"], 0)
            self.assertEqual(report["resources"]["allocations"], 0)
            self.assertEqual(report["resources"]["owners_created"], 1)
            self.assertEqual(report["resources"]["owners_dropped"], 1)
        # Removing the token consumer from already-normalized source-free
        # input is rejected by the primitive resource verifier itself.
        mutated = original.as_dict()
        removed = False
        for fn in mutated["functions"]:
            if fn["name"].startswith("h2internal_"):
                for block in fn["blocks"]:
                    for index, operation in enumerate(block["ops"]):
                        if operation["op"] == "owner.drop":
                            block["ops"].pop(index)
                            removed = True
                            break
                    if removed:
                        break
            if removed:
                break
        self.assertTrue(removed)
        with self.assertRaises(HIAProgramRejected) as caught:
            verify_core(mutated)
        self.assertEqual(caught.exception.code, "E_HIA_RESOURCE")

    def test_completed_owned_result_survives_cancel_and_moves_out_once(self):
        for size, fail, expected in [(0, None, 0), (9, None, 9), (9, 1, 0)]:
            for candidate in (owned_result_task_program(), verify_core(owned_result_task_program()).as_dict()):
                report = execute_program(candidate, "owned_result", [size], allocation_fail_at=fail)
                self.assertEqual(report["result"], expected)
                self.assertEqual(report["resources"]["live_owners"], 0)
                self.assertEqual(report["resources"]["owners_created"], report["resources"]["owners_dropped"])

    def test_stored_external_loan_can_be_borrowed_by_checked_callee(self):
        reader_type = record("Reader", [("view", "readbuf")])
        callee = f("length", [("reader", "Reader")], ["usize"], [], [
            b("entry", [("reader", "Reader")], [
                i("record.unpack", ["reader"], [("external", "readbuf")]),
                i("buffer.len", ["external"], [("size", "usize")]),
            ], ret("size"))])
        caller = f("borrowed_call", [], ["usize"], ["alloc", "trap"], [
            b("entry", [], [c("size", "usize", 9), i("buffer.new", ["size"], [("owned", "buffer")]),
                             i("borrow.read", ["owned"], [("view", "readbuf")]),
                             i("record.make", ["view"], [("stored", "Reader")]),
                             i("call", ["stored"], [("answer", "usize")], function="length"),
                             i("record.unpack", ["stored"], [("restored", "readbuf")]),
                             i("loan.end", ["restored"]), i("owner.drop", ["owned"])], ret("answer"))])
        report = execute_program(module([reader_type], callee, caller), "borrowed_call", [])
        self.assertEqual(report["result"], 9)
        self.assertEqual(report["resources"]["live_owners"], 0)
        self.assertEqual(report["resources"]["live_local_loans"], 0)


class CompositeRejectionTests(unittest.TestCase):
    def rejects(self, program, code=None):
        with self.assertRaises(HIAProgramRejected) as caught:
            verify_core(program)
        if code:
            self.assertEqual(caught.exception.code, code)

    def test_pack_cannot_copy_owner_or_access_consumed_source(self):
        program = stored_loan_program()
        program["functions"][0]["blocks"][0]["ops"].append(i("owner.drop", ["owner"]))
        self.rejects(program, "E_HIA_RESOURCE")
        program = task_program()
        block = program["functions"][2]["blocks"][2]
        block["ops"].append(i("record.make", ["owner", "count"], [("copy", ref("Pair", "buffer", "usize"))]))
        self.rejects(program, "E_HIA_RESOURCE")

    def test_stored_parent_must_wait_for_child_and_owner_for_both(self):
        for operation in [i("owner.drop", ["moved"]), i("loan.end", ["parent"]),
                          i("buffer.store", ["parent", "zero", "before"])]:
            program = stored_loan_program()
            program["functions"][0]["blocks"][1]["ops"].insert(3, operation)
            self.rejects(program)

    def test_borrowed_record_cannot_escape_or_expose_linear_field_by_copy(self):
        program = stored_loan_program()
        program["functions"][0]["returns"] = ["Stored"]
        self.rejects(program, "E_HIA_LOAN")
        program = stored_loan_program()
        program["functions"][0]["blocks"][1]["ops"].insert(0, i("record.get", ["bundle"], [("copy", "buffer")], field="owner"))
        self.rejects(program, "E_HIA_RESOURCE")

    def test_exhaustive_match_rejects_missing_duplicate_and_wrong_nominal_payload(self):
        for mutation in ["missing", "duplicate", "wrong_payload", "extra_key", "malformed_args"]:
            program = enum_owner_program()
            term = program["functions"][0]["blocks"][3]["term"]
            if mutation == "missing":
                term["cases"].pop()
            elif mutation == "duplicate":
                term["cases"].append(copy.deepcopy(term["cases"][0]))
            elif mutation == "wrong_payload":
                program["functions"][0]["blocks"][4]["params"][0]["type"] = "usize"
            elif mutation == "extra_key":
                term["cases"][0]["unchecked"] = True
            else:
                term["cases"][0]["args"] = None
            with self.subTest(mutation=mutation):
                self.rejects(program)

    def test_enum_tag_cannot_be_fabricated_or_reinterpreted(self):
        program = enum_owner_program()
        outtype = program["functions"][0]["blocks"][1]["ops"][0]["out"][0]["type"]
        program["functions"][0]["blocks"][1]["ops"][0] = c("left_value", outtype, 99)
        self.rejects(program, "E_HIA_TYPE")

    def test_normalized_core_invalid_discriminant_traps(self):
        program = verify_core(enum_owner_program()).as_dict()
        left = next(b for b in program["functions"][0]["blocks"] if b["id"] == "left")
        tag = next(op for op in left["ops"] if op["op"] == "const" and op["out"][0]["type"] == "u32")
        tag["attrs"]["value"] = 99
        with self.assertRaises(HIAProgramTrap) as caught:
            execute_program(program, "choose", [True, 7])
        self.assertEqual(caught.exception.code, "user")
        self.assertEqual(caught.exception.report["resources"]["frees"], 0)

    def test_tasks_are_linear_even_if_all_fields_are_scalars(self):
        types = [enum("Step", [("pending", [("state", "usize")]), ("ready", [("result", "usize")])]),
                 {"name": "Work", "kind": "task", "params": [], "state": "usize", "result": "usize",
                  "poll": "poll", "cancel": "cancel"}]
        poll = f("poll", [("n", "usize")], ["Step"], [], [b("entry", [("n", "usize")], [i("enum.make", ["n"], [("s", "Step")], variant="ready")], ret("s"))])
        cancel = f("cancel", [("n", "usize")], [], [], [b("entry", [("n", "usize")], [], ret())])
        leak = f("leak", [], ["usize"], [], [b("entry", [], [c("zero", "usize", 0), i("task.create", ["zero"], [("task", "Work")])], ret("zero"))])
        self.rejects(module(types, poll, cancel, leak), "E_HIA_RESOURCE")

    def test_task_protocol_signature_and_loan_captures_rejected(self):
        for mutation in ["missing_cancel", "wrong_poll_result", "borrowed_state", "leak_cancel"]:
            program = task_program()
            if mutation == "missing_cancel":
                program["types"][2]["cancel"] = "not_found"
            elif mutation == "wrong_poll_result":
                program["functions"][0]["returns"] = ["usize"]
            elif mutation == "borrowed_state":
                program["types"][2]["state"] = "readbuf"
            else:
                program["functions"][1]["blocks"][0]["ops"].pop()
            with self.subTest(mutation=mutation):
                self.rejects(program)

    def test_invalid_runtime_task_transitions_trap(self):
        # Starting an already running task, closing before cancel, joining a
        # pending task, and polling after success all have specified traps.
        for mutation, mode in [("double_start", 2), ("join_pending", 0), ("close_running", 1), ("poll_complete", 2)]:
            program = task_program()
            blocks = {b["id"]: b for b in program["functions"][2]["blocks"]}
            if mutation == "double_start":
                blocks["begin"]["ops"][1]["op"] = "task.start"
            elif mutation == "join_pending":
                blocks["pending_cancel"]["ops"] = [i("task.join", ["pending_task"], [("answer", "usize")])]
                blocks["pending_cancel"]["term"] = ret("answer")
            elif mutation == "close_running":
                blocks["running_cancel"]["ops"] = [i("task.close", ["live_task"]), c("answer", "usize", 0)]
                blocks["running_cancel"]["term"] = ret("answer")
            else:
                blocks["finish"]["ops"][0]["op"] = "task.poll"
            with self.subTest(mutation=mutation), self.assertRaises(HIAProgramTrap) as caught:
                execute_program(program, "task_case", [mode])
            self.assertEqual(caught.exception.code, "user")

    def test_missing_effects_generic_cycles_expansion_and_unknown_fields(self):
        program = enum_owner_program()
        program["functions"][0]["effects"] = ["trap"]
        self.rejects(program, "E_HIA_EFFECT")
        program = enum_owner_program()
        program["types"].append(record("Cycle", [("self", "Cycle")]))
        self.rejects(program, "E_HIA_TYPE")
        program = enum_owner_program()
        program["types"][0]["unchecked"] = True
        self.rejects(program, "E_HIA_FORMAT")
        program = enum_owner_program()
        program["types"][0]["variants"][0]["fields"][0]["type"] = "readbuf"
        self.rejects(program, "E_HIA_LOAN")

    def test_expansion_is_bounded_during_elaboration(self):
        pair = record("Pair", [("left", "T"), ("right", "T")], ["T"])
        wide = "u8"
        for _ in range(8):
            wide = ref("Pair", wide)
        choice = enum("Large", [("empty", []), ("full", [("bytes", wide)])])
        ops = [i("enum.make", [], [("unused" + str(index), "Large")], variant="empty") for index in range(40)]
        ops.append(c("answer", "usize", 0))
        program = module([pair, choice], f("expanded", [], ["usize"], [], [b("entry", [], ops, ret("answer"))]))
        with self.assertRaises(HIAProgramRejected) as caught:
            verify_core(program)
        self.assertEqual(caught.exception.code, "E_HIA_LIMIT")
        self.assertIn("expansion budget", str(caught.exception))

    def test_alias_only_product_expansion_has_an_independent_budget(self):
        pair = record("Pair", [("left", "T"), ("right", "T")], ["T"])
        half = "u8"
        for _ in range(8):
            half = ref("Pair", half)
        whole = ref("Pair", half)
        ops = [i("record.unpack", ["value"], [("left", half), ("right", half)])]
        ops += [i("record.make", ["left", "right"], [("copy" + str(index), whole)]) for index in range(70)]
        program = module([pair], f("aliases", [("value", whole)], [], [], [b("entry", [("value", whole)], ops, ret())]))
        with self.assertRaises(HIAProgramRejected) as caught:
            verify_core(program)
        self.assertEqual(caught.exception.code, "E_HIA_LIMIT")
        self.assertIn("value-slot budget", str(caught.exception))

    def test_explicit_primitive_exports_are_strict(self):
        base = verify_core(task_program()).as_dict()
        for exports in [["absent"], ["task_case", "task_case"], ["poll_owned"], None, [False]]:
            program = copy.deepcopy(base)
            program["exports"] = exports
            with self.subTest(exports=exports):
                self.rejects(program)

    def test_equal_nominal_types_do_not_mask_different_loan_roots_at_join(self):
        stored = record("Stored", [("first", "buffer"), ("second", "buffer"), ("view", "readbuf")])
        fn = f("join", [("flag", "bool")], [], ["alloc", "trap"], [
            b("entry", [("flag", "bool")], [
                c("size", "usize", 1), i("buffer.new", ["size"], [("first", "buffer")]),
                i("buffer.new", ["size"], [("second", "buffer")]),
            ], branch("flag", ("left", "first", "second"), ("right", "first", "second"))),
            b("left", [("left_a", "buffer"), ("left_b", "buffer")], [
                i("borrow.read", ["left_a"], [("left_view", "readbuf")]),
                i("record.make", ["left_a", "left_b", "left_view"], [("left_stored", "Stored")]),
            ], jump("done", "left_stored")),
            b("right", [("right_a", "buffer"), ("right_b", "buffer")], [
                i("borrow.read", ["right_b"], [("right_view", "readbuf")]),
                i("record.make", ["right_a", "right_b", "right_view"], [("right_stored", "Stored")]),
            ], jump("done", "right_stored")),
            b("done", [("stored", "Stored")], [
                i("record.unpack", ["stored"], [("a", "buffer"), ("b", "buffer"), ("v", "readbuf")]),
                i("loan.end", ["v"]), i("owner.drop", ["a"]), i("owner.drop", ["b"]),
            ], ret()),
        ])
        bad = module([stored], fn)
        self.rejects(bad, "E_HIA_LOAN")
        good = copy.deepcopy(bad)
        good["functions"][0]["blocks"][2]["ops"][0]["args"] = ["right_a"]
        for flag in [False, True]:
            result = execute_program(good, "join", [flag])
            self.assertEqual(result["resources"]["frees"], 2)

    def test_same_layout_different_nominal_type_is_not_interchangeable(self):
        types = [record("First", [("value", "usize")]), record("Second", [("value", "usize")])]
        callee = f("take_first", [("value", "First")], ["usize"], [], [
            b("entry", [("value", "First")], [i("record.get", ["value"], [("scalar", "usize")], field="value")], ret("scalar"))])
        caller = f("wrong", [], ["usize"], [], [
            b("entry", [], [c("zero", "usize", 0), i("record.make", ["zero"], [("second", "Second")]),
                             i("call", ["second"], [("answer", "usize")], function="take_first")], ret("answer"))])
        self.rejects(module(types, callee, caller), "E_HIA_CALL")


if __name__ == "__main__":
    unittest.main()
