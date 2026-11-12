"""Standalone execution and adversarial resource/CFG rejection."""
from __future__ import annotations
import copy
from dataclasses import FrozenInstanceError
import json
import unittest

from hepta.hia_program import (SCHEMA, HIAProgramRejected, VerifiedProgram,
                               integer_range, verify_core, verify_program)
from hepta.hia_program_runtime import (HIAProgramBudgetExceeded, HIAProgramTrap,
                                       execute_program)


def p(name, typ):
    return {"name": name, "type": typ}


def i(op, args=(), out=(), **attrs):
    return {"op": op, "args": list(args), "out": [p(*x) for x in out], "attrs": attrs}


def c(name, typ, value):
    return i("const", out=[(name, typ)], value=value)


def b(ident, params, ops, term):
    return {"id": ident, "params": [p(*x) for x in params], "ops": ops, "term": term}


def f(name, params, returns, effects, blocks):
    return {"name": name, "params": [p(*x) for x in params], "returns": returns,
            "effects": effects, "entry": blocks[0]["id"], "blocks": blocks}


def m(*functions):
    return {"schema": SCHEMA, "module": "standalone_test", "functions": list(functions)}


def ret(*names):
    return {"op": "ret", "values": list(names)}


def jump(target, *args):
    return {"op": "jump", "target": target, "args": list(args)}


def branch(cond, left, right):
    return {"op": "branch", "cond": cond,
            "then": {"target": left[0], "args": list(left[1:])},
            "else": {"target": right[0], "args": list(right[1:])}}


def arithmetic(op="int.add.checked", typ="i32"):
    return m(f("calculate", [("a", typ), ("z", typ)], [typ], ["trap"], [
        b("entry", [("a", typ), ("z", typ)], [i(op, ["a", "z"], [("r", typ)])], ret("r"))]))


def resource_program():
    return m(f("owned", [("n", "usize"), ("value", "u8")], ["u8"],
               ["alloc", "read", "write", "trap"], [
        b("entry", [("n", "usize"), ("value", "u8")], [
            i("buffer.new", ["n"], [("owner", "buffer")]),
            i("borrow.mut", ["owner"], [("writer", "mutbuf")]),
            c("zero", "usize", 0), i("buffer.store", ["writer", "zero", "value"]),
            i("loan.end", ["writer"]),
            i("borrow.read", ["owner"], [("reader", "readbuf")]),
            i("buffer.load", ["reader", "zero"], [("readback", "u8")]),
            i("loan.end", ["reader"]),
            i("owner.move", ["owner"], [("moved", "buffer")]),
            i("owner.drop", ["moved"]),
        ], ret("readback"))]))


def joined_loan_program():
    return m(f("join", [("condition", "bool")], ["u8"], ["alloc", "read", "trap"], [
        b("entry", [("condition", "bool")], [
            c("size", "usize", 1), i("buffer.new", ["size"], [("a", "buffer")]),
            i("buffer.new", ["size"], [("z", "buffer")]),
            i("borrow.read", ["a"], [("view", "readbuf")]),
        ], branch("condition", ("joined", "a", "z", "view"), ("joined", "a", "z", "view"))),
        b("joined", [("ja", "buffer"), ("jz", "buffer"), ("jv", "readbuf")], [
            c("index", "usize", 0), i("buffer.load", ["jv", "index"], [("v", "u8")]),
            i("loan.end", ["jv"]), i("owner.drop", ["ja"]), i("owner.drop", ["jz"]),
        ], ret("v")),
    ]))


class ScalarExecutionTests(unittest.TestCase):
    def test_checked_and_wrapping_at_every_integer_width(self):
        for typ in ("i8", "u8", "i16", "u16", "i32", "u32", "i64", "u64", "isize", "usize"):
            lo, hi = integer_range(typ)
            with self.subTest(type=typ):
                self.assertEqual(execute_program(arithmetic(typ=typ), "calculate", [hi - 1, 1])["result"], hi)
                with self.assertRaises(HIAProgramTrap) as caught:
                    execute_program(arithmetic(typ=typ), "calculate", [hi, 1])
                self.assertEqual(caught.exception.code, "overflow")
                self.assertEqual(caught.exception.report["status"], "trapped")
                self.assertEqual(execute_program(arithmetic("int.add.wrap", typ), "calculate", [hi, 1])["result"], lo)

    def test_signed_division_remainder_and_shift_semantics(self):
        self.assertEqual(execute_program(arithmetic("int.div.checked"), "calculate", [-7, 3])["result"], -2)
        self.assertEqual(execute_program(arithmetic("int.rem.checked"), "calculate", [-7, 3])["result"], -1)
        self.assertEqual(execute_program(arithmetic("int.shl.checked"), "calculate", [1, 31])["result"], -(1 << 31))
        self.assertEqual(execute_program(arithmetic("int.shr.checked"), "calculate", [-8, 2])["result"], -2)
        for op, args in [("int.div.checked", [1, 0]), ("int.rem.checked", [-(1 << 31), -1]),
                         ("int.shl.checked", [1, 32]), ("int.shr.checked", [1, -1])]:
            with self.subTest(op=op, args=args), self.assertRaises(HIAProgramTrap):
                execute_program(arithmetic(op), "calculate", args)

    def test_closed_block_loop_and_calls(self):
        add = arithmetic()["functions"][0]
        sumfn = f("sum_to", [("n", "i32")], ["i32"], ["trap"], [
            b("entry", [("n", "i32")], [c("zero", "i32", 0)], jump("loop", "n", "zero", "zero")),
            b("loop", [("ln", "i32"), ("index", "i32"), ("sum", "i32")], [
                i("compare.lt", ["index", "ln"], [("more", "bool")]),
            ], branch("more", ("body", "ln", "index", "sum"), ("done", "sum"))),
            b("body", [("bn", "i32"), ("bi", "i32"), ("bs", "i32")], [
                c("one", "i32", 1), i("call", ["bs", "bi"], [("nextsum", "i32")], function="calculate"),
                i("int.add.checked", ["bi", "one"], [("nextindex", "i32")]),
            ], jump("loop", "bn", "nextindex", "nextsum")),
            b("done", [("answer", "i32")], [], ret("answer")),
        ])
        for n in (0, 1, 2, 10, 77):
            self.assertEqual(execute_program(m(add, sumfn), "sum_to", [n])["result"], n * (n - 1) // 2)

    def test_step_heap_and_call_budgets_are_not_semantic_traps(self):
        loop = m(f("forever", [], [], [], [b("entry", [], [], jump("loop")), b("loop", [], [], jump("loop"))]))
        with self.assertRaises(HIAProgramBudgetExceeded) as limited:
            execute_program(loop, "forever", [], max_steps=12)
        self.assertEqual(limited.exception.report["status"], "budget_exceeded")
        with self.assertRaises(HIAProgramBudgetExceeded) as memory:
            execute_program(resource_program(), "owned", [100, 7], max_heap_bytes=10)
        self.assertEqual(memory.exception.code, "heap")
        self.assertEqual(memory.exception.report["resources"]["allocation_attempts"], 0)
        recursive = m(f("again", [("x", "i32")], ["i32"], [], [
            b("entry", [("x", "i32")], [i("call", ["x"], [("y", "i32")], function="again")], ret("y"))]))
        with self.assertRaises(HIAProgramBudgetExceeded) as calls:
            execute_program(recursive, "again", [0], max_call_depth=5)
        self.assertEqual(calls.exception.code, "calls")

    def test_exact_arguments_and_no_host_fabricated_capabilities(self):
        for value in (True, 1.0, "1", 1 << 40):
            with self.subTest(value=value), self.assertRaises(HIAProgramRejected):
                execute_program(arithmetic(), "calculate", [value, 0])
        internal = m(f("identity_owner", [("o", "buffer")], ["buffer"], [], [
            b("entry", [("o", "buffer")], [], ret("o"))]))
        verify_program(internal)
        with self.assertRaises(HIAProgramRejected):
            execute_program(internal, "identity_owner", [bytearray(1)])


class ResourceExecutionTests(unittest.TestCase):
    def test_loop_carries_owner_and_mutable_loan_identity(self):
        fill = m(f("fill", [("n", "usize")], ["usize"], ["alloc", "write", "trap"], [
            b("entry", [("n", "usize")], [
                c("zero", "usize", 0),
                i("buffer.new", ["n"], [("owned", "buffer")]),
                i("borrow.mut", ["owned"], [("view", "mutbuf")]),
            ], jump("loop", "n", "owned", "view", "zero")),
            b("loop", [("ln", "usize"), ("lb", "buffer"), ("lv", "mutbuf"), ("li", "usize")], [
                i("compare.lt", ["li", "ln"], [("more", "bool")]),
            ], branch("more", ("body", "ln", "lb", "lv", "li"), ("done", "lb", "lv", "ln"))),
            b("body", [("bn", "usize"), ("bb", "buffer"), ("bv", "mutbuf"), ("bi", "usize")], [
                c("byte", "u8", 7), c("one", "usize", 1),
                i("buffer.store", ["bv", "bi", "byte"]),
                i("int.add.checked", ["bi", "one"], [("next", "usize")]),
            ], jump("loop", "bn", "bb", "bv", "next")),
            b("done", [("db", "buffer"), ("dv", "mutbuf"), ("count", "usize")], [
                i("loan.end", ["dv"]), i("owner.drop", ["db"]),
            ], ret("count")),
        ]))
        for n in (0, 1, 31):
            report = execute_program(fill, "fill", [n])
            self.assertEqual(report["result"], n)
            self.assertEqual(report["resources"]["live_owners"], 0)
            self.assertEqual(report["resources"]["live_local_loans"], 0)
        broken = copy.deepcopy(fill)
        # A loop back-edge may not silently drop its loan even when it will
        # never be exercised for a particular zero-length test invocation.
        broken["functions"][0]["blocks"][2]["term"]["args"][2] = "bb"
        with self.assertRaises(HIAProgramRejected):
            verify_program(broken)

    def test_write_read_move_drop_and_bounds(self):
        for n, value in ((1, 0), (1, 255), (17, 97)):
            report = execute_program(resource_program(), "owned", [n, value])
            self.assertEqual(report["result"], value)
            self.assertEqual(report["resources"]["allocations"], 1)
            self.assertEqual(report["resources"]["frees"], 1)
            self.assertEqual(report["resources"]["live_owners"], 0)
            self.assertEqual(report["resources"]["live_local_loans"], 0)
        with self.assertRaises(HIAProgramTrap) as trapped:
            execute_program(resource_program(), "owned", [0, 1])
        self.assertEqual(trapped.exception.code, "bounds")
        self.assertEqual(trapped.exception.report["resources"]["live_owners"], 1)
        self.assertEqual(trapped.exception.report["resources"]["owners_dropped"], 0)

    def test_allocation_failure_empty_owner_multireturn_and_error_cleanup(self):
        maker = f("make", [("size", "usize")], ["buffer", "bool"], ["alloc"], [
            b("entry", [("size", "usize")], [i("buffer.try_new", ["size"], [("made", "buffer"), ("ok", "bool")])], ret("made", "ok"))])
        use = f("use", [("n", "usize")], ["usize", "bool"], ["alloc", "trap"], [
            b("entry", [("n", "usize")], [
                c("zero", "usize", 0), i("buffer.new", ["zero"], [("empty", "buffer")]),
                i("owner.drop", ["empty"]),
                i("call", ["n"], [("owned", "buffer"), ("succeeded", "bool")], function="make"),
            ], branch("succeeded", ("yes", "owned", "succeeded"), ("no", "owned", "succeeded"))),
            b("yes", [("yb", "buffer"), ("flag", "bool")], [i("buffer.len", ["yb"], [("length", "usize")]), i("owner.drop", ["yb"])], ret("length", "flag")),
            b("no", [("nb", "buffer"), ("nflag", "bool")], [i("buffer.len", ["nb"], [("nlength", "usize")]), i("owner.drop", ["nb"])], ret("nlength", "nflag")),
        ])
        for size, fail, values, attempts in [(5, None, [5, True], 1), (5, 1, [0, False], 1),
                                             (0, 1, [0, True], 0), ((1 << 64) - 1, 1, [0, False], 0)]:
            report = execute_program(m(maker, use), "use", [size], allocation_fail_at=fail)
            self.assertEqual(report["values"], values)
            self.assertEqual(report["resources"]["allocation_attempts"], attempts)
            self.assertEqual(report["resources"]["live_owners"], 0)

    def test_borrowed_call_reborrow_and_resume_parent(self):
        reader = f("peek", [("view", "readbuf")], ["u8"], ["read", "trap"], [
            b("entry", [("view", "readbuf")], [c("zero", "usize", 0), i("buffer.load", ["view", "zero"], [("v", "u8")])], ret("v"))])
        outer = f("outer", [], ["u8"], ["alloc", "read", "write", "trap"], [
            b("entry", [], [c("size", "usize", 1), c("index", "usize", 0), c("byte", "u8", 99),
                i("buffer.new", ["size"], [("owned", "buffer")]),
                i("borrow.mut", ["owned"], [("parent", "mutbuf")]),
                i("buffer.store", ["parent", "index", "byte"]),
                i("borrow.read", ["parent"], [("child", "readbuf")]),
                i("call", ["child"], [("a", "u8")], function="peek"),
                i("loan.end", ["child"]),
                i("call", ["parent"], [("answer", "u8")], function="peek"),
                i("loan.end", ["parent"]), i("owner.drop", ["owned"]),
            ], ret("answer"))])
        report = execute_program(m(reader, outer), "outer", [])
        self.assertEqual(report["result"], 99)
        self.assertEqual(report["resources"]["loans_started"], 2)
        self.assertEqual(report["resources"]["loans_ended"], 2)

    def test_local_stored_view_and_owner_cross_blocks_together(self):
        for condition in (True, False):
            report = execute_program(joined_loan_program(), "join", [condition])
            self.assertEqual(report["result"], 0)
            self.assertEqual(report["resources"]["frees"], 2)


class StaticRejectionTests(unittest.TestCase):
    def reject_modified(self, change, base=None):
        program = copy.deepcopy(base or resource_program())
        change(program)
        with self.assertRaises(HIAProgramRejected):
            verify_program(program)

    def test_consumed_owners_borrows_and_silent_loss(self):
        changes = [
            lambda ops: ops.append(i("owner.drop", ["moved"])),
            lambda ops: ops.append(i("buffer.len", ["owner"], [("badlen", "usize")])),
            lambda ops: ops.insert(4, i("owner.drop", ["owner"])),
            lambda ops: ops.insert(5, i("loan.end", ["writer"])),
            lambda ops: ops.insert(6, i("buffer.store", ["reader", "zero", "value"])),
            lambda ops: ops.__setitem__(0, c("owner", "buffer", 0)),
            lambda ops: ops.pop(),
            lambda ops: ops.insert(4, i("borrow.read", ["owner"], [("conflict", "readbuf")])),
        ]
        for change in changes:
            program = resource_program()
            change(program["functions"][0]["blocks"][0]["ops"])
            with self.subTest(program=program), self.assertRaises(HIAProgramRejected):
                verify_program(program)

    def test_join_cannot_change_loan_root_despite_matching_types(self):
        program = joined_loan_program()
        program["functions"][0]["blocks"][0]["term"]["else"]["args"] = ["z", "a", "view"]
        with self.assertRaises(HIAProgramRejected) as rejected:
            verify_program(program)
        self.assertEqual(rejected.exception.code, "E_HIA_LOAN")

    def test_duplicate_edge_owner_and_missing_parent_reject(self):
        self.reject_modified(lambda x: x["functions"][0]["blocks"][0]["term"]["then"]["args"].__setitem__(1, "a"), joined_loan_program())
        self.reject_modified(lambda x: x["functions"][0]["blocks"][0]["term"]["then"]["args"].pop(), joined_loan_program())

    def test_callee_cannot_end_or_return_external_loan(self):
        external = m(f("bad", [("borrowed", "readbuf")], [], [], [
            b("entry", [("borrowed", "readbuf")], [i("loan.end", ["borrowed"])], ret())]))
        with self.assertRaises(HIAProgramRejected):
            verify_program(external)
        external["functions"][0]["returns"] = ["readbuf"]
        external["functions"][0]["blocks"][0]["ops"] = []
        external["functions"][0]["blocks"][0]["term"] = ret("borrowed")
        with self.assertRaises(HIAProgramRejected):
            verify_program(external)

    def test_exclusive_call_arguments_must_not_alias(self):
        callee = f("twice", [("a", "mutbuf"), ("b", "mutbuf")], [], [], [
            b("entry", [("a", "mutbuf"), ("b", "mutbuf")], [], ret())])
        program = resource_program()
        program["functions"].append(callee)
        program["functions"][0]["blocks"][0]["ops"].insert(2, i("call", ["writer", "writer"], function="twice"))
        with self.assertRaises(HIAProgramRejected):
            verify_program(program)

    def test_suspended_parent_cannot_be_accessed_or_ended_first(self):
        for wrong in (i("buffer.store", ["writer", "zero", "value"]), i("loan.end", ["writer"])):
            program = resource_program()
            program["functions"][0]["blocks"][0]["ops"][3:3] = [
                i("borrow.read", ["writer"], [("child", "readbuf")]), wrong, i("loan.end", ["child"])]
            with self.subTest(wrong=wrong["op"]), self.assertRaises(HIAProgramRejected):
                verify_program(program)


class CanonicalInputAndCFGTests(unittest.TestCase):
    def test_immutable_snapshot_and_rechecked_public_constructor(self):
        source = arithmetic()
        verified = verify_core(source)
        source["functions"][0]["blocks"][0]["ops"][0]["op"] = "int.mul.checked"
        decoded = verified.as_dict()
        decoded["functions"][0]["blocks"][0]["ops"][0]["op"] = "int.sub.checked"
        self.assertEqual(execute_program(verified, "calculate", [8, 3])["result"], 11)
        with self.assertRaises(FrozenInstanceError):
            verified.canonical_bytes = b"{}"
        forged = VerifiedProgram(b"{}")
        with self.assertRaises(HIAProgramRejected):
            execute_program(forged, "calculate", [1, 2])
        with self.assertRaises(HIAProgramRejected):
            forged.report()

    def test_canonical_input_and_duplicate_keys(self):
        canonical = verify_program(arithmetic())
        pretty = verify_program(json.dumps(arithmetic(), indent=2))
        self.assertEqual(canonical.canonical_bytes, pretty.canonical_bytes)
        with self.assertRaises(HIAProgramRejected):
            verify_program('{"schema":"x","schema":"y"}')
        with self.assertRaises(HIAProgramRejected):
            verify_program('{"schema":NaN}')
        self.assertFalse(canonical.report()["source_required"])
        self.assertFalse(canonical.report()["claims"]["whole_language_soundness_proved"])

    def test_ssa_cfg_effect_and_unknown_claim_rejections(self):
        changes = [
            lambda x: x.update(claims={"safe": True}),
            lambda x: x["functions"][0].update(effects=[]),
            lambda x: x["functions"][0].update(name="abort"),
            lambda x: x.update(module="bad\"; injected"),
            lambda x: x["functions"][0]["blocks"][0]["ops"][0].update(args=["not_defined", "z"]),
            lambda x: x["functions"][0]["blocks"][0]["ops"][0]["out"][0].update(name="a"),
            lambda x: x["functions"][0]["blocks"][0].update(term=jump("missing")),
            lambda x: x["functions"][0]["blocks"][0].update(term=jump("entry", "a", "z")),
            lambda x: x["functions"][0]["blocks"].append(b("dead", [], [], ret())),
        ]
        for change in changes:
            document = arithmetic()
            change(document)
            with self.subTest(document=document), self.assertRaises(HIAProgramRejected):
                verify_program(document)

    def test_malformed_values_reject_with_controlled_errors(self):
        cast = m(f("cast", [("a", "u32")], ["u8"], ["trap"], [
            b("entry", [("a", "u32")], [i("int.cast", ["a"], [("r", "u8")], mode="checked")], ret("r"))]))
        for mode in ([], {}, None, 1, True):
            bad = copy.deepcopy(cast)
            bad["functions"][0]["blocks"][0]["ops"][0]["attrs"]["mode"] = mode
            with self.subTest(mode=mode), self.assertRaises(HIAProgramRejected):
                verify_program(bad)
        for malformed in (None, [], 3, True, {"schema": SCHEMA}, b"\xff"):
            with self.subTest(malformed=malformed), self.assertRaises(HIAProgramRejected):
                verify_program(malformed)

    def test_wrong_json_container_at_each_schema_position_is_rejected(self):
        good = resource_program()
        paths = []
        def collect(value, path=()):
            paths.append(path)
            if type(value) is dict:
                for key, child in value.items():
                    collect(child, path + (key,))
            elif type(value) is list:
                for index, child in enumerate(value):
                    collect(child, path + (index,))
        collect(good)
        for path in paths:
            old = good
            for key in path:
                old = old[key]
            # Change container/string/bool/integer category; preserve no valid
            # type or optional field by accident.
            replacement = [] if type(old) is dict else {} if type(old) is list else ["invalid"]
            document = copy.deepcopy(good)
            if not path:
                document = replacement
            else:
                target = document
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = replacement
            with self.subTest(path=path), self.assertRaises(HIAProgramRejected):
                verify_program(document)


if __name__ == "__main__":
    unittest.main()
