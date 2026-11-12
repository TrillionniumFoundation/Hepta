"""Compare the prior guarded-phi encoding with the single-arrival reduction.

The frozen reference differs only at block-parameter encoding. The tests ask
Z3 about every typed input, including false reachability and first traps; they
do not accept a syntactically generated specialization as a proof authority.
"""
from __future__ import annotations

import copy
import importlib.util
import unittest

from hepta.hia_program import HIAProgramRejected, verify_program
from hepta.hia_translation_validation import _Encoder, _TRAP_TAGS, _profile, validate_translation
from hepta.hia_specialization import propose_guarded_specializations
from tests.test_hia_program import b, branch, c, f, i, jump, m, ret


def previous_encoding(encoder, fn, inputs, blocks, order):
    """Frozen pre-change function encoding, with guarded parameters everywhere."""
    z = encoder.z
    incoming = {ident: [] for ident in blocks}
    incoming[fn["entry"]].append((z.BoolVal(True, encoder.context), inputs))
    outcomes = []
    for ident in order:
        block = blocks[ident]
        arrivals = incoming[ident]
        guard = encoder.any(g for g, _ in arrivals)
        types = {p["name"]: p["type"] for p in block["params"]}
        env = {}
        for index, param in enumerate(block["params"]):
            value = encoder.zero(param["type"])
            for edge_guard, values in arrivals:
                value = encoder.choose(edge_guard, values[index], value, param["type"])
            env[param["name"]] = value
        for op in block["ops"]:
            value, traps = encoder.operation(op, env, types)
            for code, condition in traps:
                outcomes.append((z.And(guard, condition), _TRAP_TAGS[code], None))
                guard = z.And(guard, z.Not(condition))
            output = op["out"][0]
            env[output["name"]], types[output["name"]] = value, output["type"]
        term = block["term"]
        if term["op"] == "ret":
            outcomes.append((guard, 0, [env[name] for name in term["values"]]))
        elif term["op"] == "trap":
            outcomes.append((guard, _TRAP_TAGS[term["code"]], None))
        else:
            edges = [(guard, term)] if term["op"] == "jump" else [
                (z.And(guard, env[term["cond"]]), term["then"]),
                (z.And(guard, z.Not(env[term["cond"]])), term["else"])]
            for edge_guard, edge in edges:
                incoming[edge["target"]].append((edge_guard, [env[n] for n in edge["args"]]))
    tag = z.IntVal(-1, encoder.context)
    values = [encoder.zero(typ) for typ in fn["returns"]]
    for guard, code, returned in outcomes:
        tag = z.If(guard, code, tag)
        if returned is not None:
            values = [encoder.choose(guard, val, old, typ)
                      for val, old, typ in zip(returned, values, fn["returns"])]
    return tag, values


@unittest.skipUnless(importlib.util.find_spec("z3"), "actual Z3 is required")
class SingleArrivalEncodingTests(unittest.TestCase):
    def assert_encoding_equivalent(self, document, *, structurally_valid=True):
        import z3
        if structurally_valid:
            verify_program(document)
        fn = document["functions"][0]
        encoder = _Encoder(z3)
        inputs = [encoder.input(n, p["type"]) for n, p in enumerate(fn["params"])]
        graph = _profile(fn)
        ltag, left = previous_encoding(encoder, fn, inputs, *graph)
        rtag, right = encoder.function(fn, inputs, *graph)
        solver = z3.Solver(ctx=encoder.context)
        solver.set(timeout=2000)
        mismatch = encoder.any(a != b for a, b, typ in zip(left, right, fn["returns"]) if typ != "unit")
        solver.add(z3.Or(ltag < 0, rtag < 0, ltag != rtag, z3.And(ltag == 0, rtag == 0, mismatch)))
        self.assertEqual(solver.check(), z3.unsat)

    def test_single_entry_chain_keeps_complete_all_input_encoding(self):
        source = m(f("calculate", [("x", "u32")], ["u32"], [], [
            b("entry", [("x", "u32")], [], jump("a", "x")),
            b("a", [("ax", "u32")], [c("one", "u32", 1),
                i("int.add.wrap", ["ax", "one"], [("next", "u32")])], jump("z", "next")),
            b("z", [("zx", "u32")], [], ret("zx")),
        ]))
        self.assert_encoding_equivalent(source)

    def test_false_reachability_keeps_values_and_traps_unobservable(self):
        params = [("x", "i8")]
        source = m(f("calculate", params, ["i8"], ["trap"], [
            b("entry", params, [c("never", "bool", False)], branch("never", ("bad", "x"), ("good", "x"))),
            b("bad", [("bx", "i8")], [c("zero", "i8", 0),
                i("int.div.checked", ["bx", "zero"], [("undefined", "i8")])], ret("undefined")),
            b("good", [("gx", "i8")], [], ret("gx")),
        ]))
        self.assert_encoding_equivalent(source)
        target = m(f("calculate", params, ["i8"], ["trap"], [b("entry", params, [], ret("x"))]))
        self.assertEqual(validate_translation(source, target)["status"], "proved")

    def test_first_trap_before_branch_dominates_later_traps(self):
        params = [("flag", "bool"), ("x", "i8"), ("denominator", "i8")]
        source = m(f("calculate", params, ["i8"], ["trap"], [
            b("entry", params, [i("int.div.checked", ["x", "denominator"], [("q", "i8")])],
              branch("flag", ("yes", "q"), ("no", "x"))),
            b("yes", [("yq", "i8")], [c("one", "i8", 1),
                i("int.add.checked", ["yq", "one"], [("answer", "i8")])], ret("answer")),
            b("no", [("nx", "i8")], [], {"op": "trap", "code": "overflow"}),
        ]))
        self.assert_encoding_equivalent(source)
        wrong = copy.deepcopy(source)
        wrong["functions"][0]["blocks"][0]["ops"] = [c("q", "i8", 0)]
        receipt = validate_translation(source, wrong)
        self.assertEqual(receipt["status"], "disproved", receipt)
        self.assertNotEqual(receipt["counterexample"]["before"], receipt["counterexample"]["after"])

    def test_multiple_arrivals_keep_their_original_guarded_phi_merge(self):
        params = [("flag", "bool"), ("x", "u8"), ("y", "u8")]
        source = m(f("calculate", params, ["u8"], [], [
            b("entry", params, [], branch("flag", ("yes", "x"), ("no", "y"))),
            b("yes", [("yx", "u8")], [], jump("join", "yx")),
            b("no", [("ny", "u8")], [], jump("join", "ny")),
            b("join", [("value", "u8")], [], ret("value")),
        ]))
        self.assert_encoding_equivalent(source)

    def test_zero_arrival_is_still_unobservable_and_not_canonically_admitted(self):
        params = [("x", "u8")]
        source = m(f("calculate", params, ["u8"], ["trap"], [
            b("entry", params, [], ret("x")),
            b("orphan", [("unused", "u8")], [c("zero", "u8", 0),
                i("int.div.checked", ["unused", "zero"], [("bad", "u8")])], ret("bad")),
        ]))
        with self.assertRaises(HIAProgramRejected):
            verify_program(source)
        self.assertEqual(validate_translation(source, source)["status"], "unknown")
        # Internal regression only; this graph remains outside canonical admission.
        self.assert_encoding_equivalent(source, structurally_valid=False)

    def test_research_specialization_is_proved_and_changed_output_is_rejected(self):
        from tools.qualify_hia_specialization import workload
        source = workload()
        choices = propose_guarded_specializations(source, function="calculate",
            assumptions=[{"parameter": "mask", "value": value} for value in (0, (1 << 32) - 1)])
        for candidate in choices:
            receipt = validate_translation(source, candidate["program"], timeout_ms=5000)
            self.assertEqual(receipt["status"], "proved", receipt)
        wrong = copy.deepcopy(choices[0]["program"])
        wrong["functions"][0]["blocks"][0]["ops"][-1] = c("hia_match_0", "bool", True)
        receipt = validate_translation(source, wrong, timeout_ms=5000)
        self.assertEqual(receipt["status"], "disproved", receipt)
        self.assertIsNotNone(receipt["counterexample"])


if __name__ == "__main__":
    unittest.main()
