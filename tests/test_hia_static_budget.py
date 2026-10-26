"""Real Core verifier + conservative static budget and native refusal tests.

The resource analyzer is opt-in and never certifies native time, RSS or general
source equivalence. It must reject cycles instead of inventing finite numbers.
"""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_program import verify_program
from hepta.hia_program_runtime import execute_program
from hepta.hia_static_budget import HIAStaticBudgetRejected, analyze_static_budget
from hepta.hia_source_bridge import build_checked_hepta_hia_native
from tests.test_hia_program import b, branch, c, f, i, jump, m, resource_program, ret


def acyclic_choice():
    return m(f("choose", [("cond", "bool"), ("n", "usize")], ["usize"],
               ["alloc"], [
        b("entry", [("cond", "bool"), ("n", "usize")], [],
          branch("cond", ("then", "n"), ("otherwise", "n"))),
        b("then", [("num_t", "usize")], [
            i("buffer.try_new", ["num_t"], [("owner", "buffer"), ("ok", "bool")]),
            i("owner.drop", ["owner"]),
        ], ret("num_t")),
        b("otherwise", [("num_f", "usize")], [], ret("num_f")),
    ]))


def acyclic_calls():
    inner = f("inner", [("n", "usize")], ["usize"], ["alloc", "trap"], [
        b("inner_entry", [("n", "usize")], [
            i("buffer.new", ["n"], [("a", "buffer")]),
            i("owner.drop", ["a"]),
        ], ret("n")),
    ])
    outer = f("outer", [("count", "usize")], ["usize"], ["alloc", "trap"], [
        b("outer_entry", [("count", "usize")], [
            i("call", ["count"], [("x", "usize")], function="inner"),
            i("call", ["count"], [("y", "usize")], function="inner"),
        ], ret("count")),
    ])
    return m(inner, outer)


def cyclic_control_flow():
    return m(f("cycle", [("choose", "bool"), ("n", "i32")], ["i32"], [], [
        b("entry", [("choose", "bool"), ("n", "i32")], [],
          jump("loop", "choose", "n")),
        b("loop", [("condition", "bool"), ("value", "i32")], [],
          branch("condition", ("loop", "condition", "value"), ("exit", "value"))),
        b("exit", [("result", "i32")], [], ret("result")),
    ]))


def cyclic_calls():
    return m(
        f("one", [("x", "i32")], ["i32"], [], [
            b("a", [("x", "i32")], [i("call", ["x"], [("y", "i32")], function="two")], ret("y"))]),
        f("two", [("x", "i32")], ["i32"], [], [
            b("b", [("x", "i32")], [i("call", ["x"], [("y", "i32")], function="one")], ret("y"))]),
    )


class HIAStaticBudgetTests(unittest.TestCase):
    def test_live_owner_counters_and_actual_vm_ticks_are_bounded(self):
        core = verify_program(resource_program())
        row = analyze_static_budget(core)["functions"][0]
        self.assertEqual(row["max_allocator_interactions"], 2)
        self.assertEqual(row["max_vm_ticks"], 12)
        self.assertEqual(row["max_call_depth"], 1)
        observed = execute_program(core, "owned", [1, 19])
        self.assertEqual(observed["result"], 19)
        self.assertLessEqual(observed["steps"], row["max_vm_ticks"])
        self.assertLessEqual(observed["resources"]["allocations"] + observed["resources"]["frees"],
                             row["max_allocator_interactions"])

    def test_diamond_budget_takes_conservative_maximum(self):
        core = verify_program(acyclic_choice())
        row = analyze_static_budget(core, max_allocator_interactions=2)["functions"][0]
        self.assertEqual(row["max_allocator_interactions"], 2)
        self.assertEqual(row["max_call_depth"], 1)
        for decision in (False, True):
            observed = execute_program(core, "choose", [decision, 1])
            self.assertEqual(observed["result"], 1)
            self.assertLessEqual(observed["steps"], row["max_vm_ticks"])

    def test_nested_call_counts_include_every_invocation(self):
        core = verify_program(acyclic_calls())
        rows = {r["function"]: r for r in analyze_static_budget(core)["functions"]}
        self.assertEqual(rows["inner"]["max_allocator_interactions"], 2)
        self.assertEqual(rows["outer"]["max_allocator_interactions"], 4)
        self.assertEqual(rows["outer"]["max_call_depth"], 2)
        observed = execute_program(core, "outer", [1])
        self.assertEqual(observed["result"], 1)
        self.assertLessEqual(observed["steps"], rows["outer"]["max_vm_ticks"])
        with self.assertRaisesRegex(HIAStaticBudgetRejected, "E_HIA_BUDGET_EXCEEDED"):
            analyze_static_budget(core, max_call_depth=1)

    def test_loop_and_mutual_recursion_fail_closed(self):
        for document in (cyclic_control_flow(), cyclic_calls()):
            with self.subTest(functions=[x["name"] for x in document["functions"]]):
                # A program can be a valid HIA Core while lacking a finite
                # static invocation budget under this deliberately strict mode.
                core = verify_program(document)
                with self.assertRaisesRegex(HIAStaticBudgetRejected, "E_HIA_BUDGET_UNBOUNDED"):
                    analyze_static_budget(core)

    def test_policy_rejects_bool_negative_and_deterministic_replay(self):
        core = verify_program(resource_program())
        for invalid in (-1, True, False, "0", 0.0, [], {}):
            with self.subTest(invalid=repr(invalid)):
                with self.assertRaisesRegex(HIAStaticBudgetRejected, "E_HIA_BUDGET_POLICY"):
                    analyze_static_budget(core, max_allocator_interactions=invalid)
        one = analyze_static_budget(core, max_allocator_interactions=2)
        two = analyze_static_budget(core, max_allocator_interactions=2)
        self.assertEqual(one, two)
        self.assertFalse(one["claims"]["native_cpu_time_or_rss_proved"])
        with self.assertRaisesRegex(HIAStaticBudgetRejected, "E_HIA_BUDGET_EXCEEDED"):
            analyze_static_budget(core, max_allocator_interactions=1)

    def test_source_native_rejects_before_any_llvm_on_budget_failure(self):
        with tempfile.TemporaryDirectory() as root:
            src, dst = Path(root) / "program.hepta", Path(root) / "result.so"
            src.write_text("module budget;", encoding="utf-8")
            project = SimpleNamespace(identity="a" * 64,
                                      sources={str(src): "pinned"}, unchanged=lambda: True)
            analysis = SimpleNamespace(program=object(), checked=object(), project=project,
                                       report={"ok": True,
                                               "checks": {"rust_borrows_types": "rustc_checked"},
                                               "compiler_sha256": "b" * 64})
            derived = SimpleNamespace(program=verify_program(resource_program()))
            with (patch("hepta.pipeline.analyze_project", return_value=analysis),
                  patch("hepta.pipeline.compiler_hash", return_value="b" * 64),
                  patch("hepta.hia_source_bridge.lower_checked_scalar_hia", return_value=derived),
                  patch("hepta.hia_program_llvm.emit_program_llvm") as native):
                report = build_checked_hepta_hia_native(src, dst,
                    static_resource_limits={"max_allocator_interactions": 1})
            self.assertFalse(report["ok"], report)
            self.assertEqual(report["diagnostics"][0]["code"], "E_HIA_BUDGET_EXCEEDED")
            native.assert_not_called()
            self.assertFalse(dst.exists())


if __name__ == "__main__":
    unittest.main()
