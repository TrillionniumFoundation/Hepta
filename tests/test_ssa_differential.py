"""Finite CFG-vs-SSA execution oracle for a strict pure scalar subset.

Independent test interpreter only; not a production execution engine,
Rust/LLVM backend qualification, or semantic correctness proof.
"""
from __future__ import annotations

import json
import random
import unittest

from hepta.ssa import lower_cfg_scalar_ssa
from hepta.ssa_verify import verify_scalar_ssa
from tests.test_ssa_scalar import snapshot, block, let, assign, i, n, expr


def evaluate(expression, env):
    op = expression["operation"]
    if op in ("int", "float", "bool"):
        return expression["value"]
    if op == "name":
        return env[expression.get("ssa_ref", expression["value"])]
    args = [evaluate(x, env) for x in expression["operands"]]
    if op == "binary":
        lhs, rhs = args
        return {"+": lambda: lhs+rhs, "-": lambda: lhs-rhs, "*": lambda: lhs*rhs,
                "<": lambda: lhs<rhs, "==": lambda: lhs==rhs,
                ">": lambda: lhs>rhs}[expression["value"]]()
    if op == "unary":
        return {"-": lambda: -args[0], "!": lambda: not args[0]}[expression["value"]]()
    raise ValueError("Unsupported oracle expression")


def execute_source(fn, args, *, max_steps=300):
    env = dict(args)
    blocks = {b["id"]: b for b in fn["blocks"]}
    pc = fn["entry"]
    for _ in range(max_steps):
        b = blocks[pc]
        for ins in b["instructions"]:
            value = evaluate(ins["fields"]["expr"], env)
            name = (ins["fields"].get("name") if ins["operation"] == "let" else
                    ins["fields"]["target"]["value"])
            env[name] = value
        term = b["terminator"]
        if term["kind"] == "return":
            return evaluate(term["value"], env)
        if term["kind"] == "goto":
            pc = term["target"]
        elif term["kind"] == "branch":
            pc = term["then"] if evaluate(term["condition"], env) else term["else"]
        else:
            raise ValueError("Unsupported source oracle control")
    raise TimeoutError("Source CFG exceeded finite execution budget")


def execute_ssa(fn, args, *, max_steps=300):
    env = {p["ssa_name"]: args[p["variable"]] for p in fn["parameters"]}
    blocks = {b["id"]: b for b in fn["blocks"]}
    pc, previous = fn["entry"], None
    for _ in range(max_steps):
        b = blocks[pc]
        phi_values = {}
        for phi in b["phis"]:
            [edge] = [e for e in phi["incoming"] if e["from"] == previous]
            phi_values[phi["result"]["ssa_name"]] = env[edge["ssa_ref"]]
        env.update(phi_values)
        for ins in b["instructions"]:
            value = evaluate(ins["ssa_value"], env)
            if "definition" in ins:
                env[ins["definition"]["ssa_name"]] = value
        term = b["terminator"]
        if term["kind"] == "return":
            return evaluate(term["value"], env)
        if term["kind"] == "goto":
            next_pc = term["target"]
        elif term["kind"] == "branch":
            next_pc = term["then"] if evaluate(term["condition"], env) else term["else"]
        else:
            raise ValueError("Unsupported SSA oracle control")
        previous, pc = pc, next_pc
    raise TimeoutError("SSA exceeded finite execution budget")


def branching_fixture():
    return snapshot([
        block(0, [let("x", i(5))], kind="branch", condition=n("flag", "bool"),
              **{"then": "b0001", "else": "b0002"}),
        block(1, [assign("x", expr("binary", "+", "i32", n("x"), i(7)))],
              kind="goto", target="b0003"),
        block(2, [assign("x", expr("binary", "-", "i32", n("x"), i(9)))],
              kind="goto", target="b0003"),
        block(3, kind="return", value=n("x"))], params=[("flag", "bool")])


def nested_loop_fixture():
    return snapshot([
        block(0, [let("total", i(0)), let("x", i(0))], kind="goto", target="b0001"),
        block(1, kind="branch", condition=expr("binary", "<", "bool", n("x"), n("bound")),
              **{"then": "b0002", "else": "b0006"}),
        block(2, kind="branch", condition=expr("binary", "<", "bool", n("x"), i(4)),
              **{"then": "b0003", "else": "b0004"}),
        block(3, [assign("total", expr("binary", "+", "i32", n("total"), n("x")))],
              kind="goto", target="b0005"),
        block(4, [assign("total", expr("binary", "+", "i32", n("total"), i(1)))],
              kind="goto", target="b0005"),
        block(5, [assign("x", expr("binary", "+", "i32", n("x"), i(1)))],
              kind="goto", target="b0001"),
        block(6, kind="return", value=n("total"))],
        params=[("bound", "i32")], effects=["panic"])


class DifferentialSSATests(unittest.TestCase):
    def test_branch_and_bounded_loop_execution_differential(self):
        rng = random.Random(20261024)
        cases = [(branching_fixture(), [{"flag": False}, {"flag": True}]),
                 (nested_loop_fixture(),
                  [{"bound": x} for x in range(-4, 31)] +
                  [{"bound": rng.randrange(-10, 40)} for _ in range(64)])]
        for cfg, input_cases in cases:
            ssa = lower_cfg_scalar_ssa(cfg)
            verify_scalar_ssa(ssa, cfg)
            original = json.loads(cfg.canonical_json)["functions"][0]
            lowered = ssa.as_dict()["functions"][0]
            for sample in input_cases:
                with self.subTest(args=sample):
                    self.assertEqual(execute_source(original, sample),
                                     execute_ssa(lowered, sample))

    def test_negative_mutation_catches_value_divergence(self):
        cfg = branching_fixture()
        original = json.loads(cfg.canonical_json)["functions"][0]
        altered = lower_cfg_scalar_ssa(cfg).as_dict()
        altered["functions"][0]["blocks"][1]["instructions"][0]["ssa_value"]["operands"][1]["value"] = 99
        self.assertNotEqual(execute_source(original, {"flag": True}),
                            execute_ssa(altered["functions"][0], {"flag": True}))


if __name__ == "__main__":
    unittest.main()
