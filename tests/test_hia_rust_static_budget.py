"""Real independent Rust static bounds and exact Python consumer controls.

The Rust analyzer, Python analyzer, and both VMs are actual implementations.
Tampered-reply tests explicitly replace only transport output after obtaining a
real report. They test refusal, never qualify an artificial producer as Rust.
"""
from copy import deepcopy
import json
import platform
import shutil
import subprocess
import unittest
from unittest.mock import patch

from hepta import hia_rust_crosscheck as crosscheck
from hepta.hia_program import HIAProgramRejected, verify_program
from hepta.hia_static_budget import HIAStaticBudgetRejected, analyze_static_budget
from tests.test_hia_program import b, branch, c, f, i, jump, m, ret
from tests import test_hia_rust_crosscheck as static_crosscheck
from tests.test_hia_rust_crosscheck import owned_program, scalar_program
from tests.test_hia_static_budget import acyclic_calls, cyclic_control_flow, cyclic_calls
from tests.test_hia_bulk_memory import bulk_program
from tests.test_hia_overlap_move import move_program
from tests.test_hia_swap_v4 import swap_program
from tests.test_hia_offset_copy_v5 import copy_program
from tests.test_hia_range_fill_v6 import fill_program
from tests.test_hia_composite_abi import nominal_identity_program


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def metric_diamond():
    return m(f("choose", [("condition", "bool"), ("n", "usize")], [], ["alloc"], [
        b("entry", [("condition", "bool"), ("n", "usize")], [],
          branch("condition", ("allocates", "n"), ("longer",))),
        b("allocates", [("size", "usize")], [
            i("buffer.try_new", ["size"], [("owner", "buffer"), ("ok", "bool")]),
            i("owner.drop", ["owner"]),
        ], ret()),
        b("longer", [], [c("c" + str(n), "u8", n) for n in range(4)], ret()),
    ]))


def multiple_return_loan():
    helper = f("inspect", [("view", "readbuf")], ["readbuf", "u8"], ["read", "trap"], [
        b("entry", [("view", "readbuf")], [
            c("zero", "usize", 0), i("buffer.load", ["view", "zero"], [("byte", "u8")]),
        ], ret("view", "byte")),
    ])
    helper["return_loans"] = ["view", None]
    caller = f("run", [("size", "usize"), ("value", "u8")], ["u8"],
               ["alloc", "read", "write", "trap"], [
        b("entry", [("size", "usize"), ("value", "u8")], [
            i("buffer.new", ["size"], [("owner", "buffer")]),
            i("borrow.mut", ["owner"], [("parent", "mutbuf")]),
            c("zero", "usize", 0), i("buffer.store", ["parent", "zero", "value"]),
            i("call", ["parent"], [("returned", "readbuf"), ("answer", "u8")], function="inspect"),
            i("loan.end", ["returned"]), i("loan.end", ["parent"]), i("owner.drop", ["owner"]),
        ], ret("answer")),
    ])
    result = m(helper, caller)
    result["schema"] = "hepta.hia.program.v8"
    result["exports"] = ["run"]
    return result


def expanding_calls(count):
    return m(*(f("f" + str(n), [], [], [], [b("entry", [], [] if n + 1 == count else [
        i("call", function="f" + str(n + 1)), i("call", function="f" + str(n + 1)),
    ], ret())]) for n in range(count)))


@unittest.skipUnless(platform.system() == "Linux" and shutil.which("cargo"),
                     "Actual static-bound comparison requires Linux/Cargo; NOT qualified")
class RustStaticBudgetNative(unittest.TestCase):
    setUpClass = classmethod(static_crosscheck.RustShadowCrosscheckNative.setUpClass.__func__)

    def compare(self, source, **limits):
        result = crosscheck.crosscheck_rust_static_budget(source, self.executable,
            executable_sha256=self.digest, **limits)
        self.assertEqual(result["status"], "finite_budget_corroborated_not_authority")
        self.assertEqual(result["python_report"]["functions"], result["rust_report"]["functions"])
        self.assertIs(result["claims"]["rust_is_production_admission_authority"], False)
        self.assertIs(result["claims"]["exact_feasible_path_maxima_proved"], False)
        return result

    def execution(self, source, entry, args, bound, **policy):
        result = crosscheck.crosscheck_rust_execution_v4(source, entry, args, self.executable,
            executable_sha256=self.digest, max_steps=bound["max_vm_ticks"],
            max_call_depth=bound["max_call_depth"], **policy)
        run = result["rust_report"]
        self.assertIn(run["status"], ("returned", "trapped"))
        self.assertLessEqual(run["steps"], bound["max_vm_ticks"])
        self.assertLessEqual(run["resources"]["allocation_attempts"] + run["resources"]["frees"],
                             bound["max_allocator_interactions"])
        return run

    def raw(self, source):
        return subprocess.run([str(self.executable), "--owned-static-budget"],
            input=wire(source), capture_output=True, timeout=15)

    def test_all_primitive_versions_and_exact_limits_preserve_legacy_execution(self):
        for version in range(1, 9):
            source = owned_program()
            source["schema"] = "hepta.hia.program.v" + str(version)
            result = self.compare(source, max_allocator_interactions=2, max_vm_ticks=4, max_call_depth=1)
            bound = result["rust_report"]["functions"][0]
            self.assertEqual(bound, {"function": "allocate_release", "max_allocator_interactions": 2,
                                     "max_vm_ticks": 4, "max_call_depth": 1})
            for size, failure in ((0, None), (3, None), (3, 1)):
                with self.subTest(version=version, size=size, fail=failure):
                    self.execution(source, "allocate_release", [size], bound, allocation_fail_at=failure)

    def test_branch_metrics_need_not_have_one_common_maximizing_path(self):
        source = metric_diamond()
        bound = self.compare(source)["rust_report"]["functions"][0]
        self.assertEqual((bound["max_allocator_interactions"], bound["max_vm_ticks"]), (2, 7))
        yes = self.execution(source, "choose", [True, 1], bound)
        no = self.execution(source, "choose", [False, 1], bound)
        self.assertEqual((yes["steps"], no["steps"]), (5, 7))
        self.assertEqual((yes["resources"]["allocation_attempts"], no["resources"]["allocation_attempts"]), (1, 0))
        # The scalar condition is not evaluated by structural bound inference.
        # Fixing it to false does not authorize deleting the other branch cost.
        fixed = deepcopy(source)
        fn = fixed["functions"][0]
        fn["params"].pop(0)
        fn["blocks"][0]["params"].pop(0)
        fn["blocks"][0]["ops"] = [c("condition", "bool", False)]
        fixed_bound = self.compare(fixed)["rust_report"]["functions"][0]
        self.assertEqual(fixed_bound["max_allocator_interactions"], 2)
        self.assertEqual(self.execution(fixed, "choose", [1], fixed_bound)["resources"]["allocation_attempts"], 0)

    def test_sequential_calls_multi_return_and_parameter_loan_costs_compose(self):
        source = acyclic_calls()
        rows = {x["function"]: x for x in self.compare(source)["rust_report"]["functions"]}
        self.assertEqual(rows["outer"]["max_vm_ticks"], 12)
        self.assertEqual(rows["outer"]["max_allocator_interactions"], 4)
        self.assertEqual(rows["outer"]["max_call_depth"], 2)
        self.execution(source, "outer", [1], rows["outer"])
        source = multiple_return_loan()
        rows = {x["function"]: x for x in self.compare(source)["rust_report"]["functions"]}
        self.assertEqual(rows["run"]["max_vm_ticks"], 14)
        for arguments in ([1, 37], [0, 37]):
            observed = self.execution(source, "run", arguments, rows["run"])
            self.assertEqual(observed["status"], "returned" if arguments[0] else "trapped")
        wrong = deepcopy(source)
        wrong["functions"][0]["return_loans"][0] = "missing"
        self.assertNotEqual(self.raw(wrong).returncode, 0)

    def test_reconverging_diamond_charges_shared_tail_once_per_execution(self):
        source = m(f("join", [("condition", "bool")], [], ["alloc", "trap"], [
            b("entry", [("condition", "bool")], [],
              branch("condition", ("left",), ("right",))),
            b("left", [], [c("small", "usize", 1)], jump("tail", "small")),
            b("right", [], [c("unused", "u8", 7), c("large", "usize", 2)], jump("tail", "large")),
            b("tail", [("size", "usize")], [
                i("buffer.new", ["size"], [("owner", "buffer")]),
                i("owner.drop", ["owner"]),
            ], ret()),
        ]))
        bound = self.compare(source)["rust_report"]["functions"][0]
        self.assertEqual(bound, {"function": "join", "max_allocator_interactions": 2,
                                 "max_vm_ticks": 8, "max_call_depth": 1})
        for decision, ticks in ((False, 8), (True, 7)):
            self.assertEqual(self.execution(source, "join", [decision], bound)["steps"], ticks)

    def test_bulk_byte_operations_count_vm_events_without_claiming_cpu_or_heap(self):
        cases = (
            (bulk_program(), "bulk", [8, 8, 37]),
            (move_program(), "move_bytes", [5, 1, 0, 4, 2]),
            (swap_program(), "swap_bytes", [5, 0, 4, 0]),
            (copy_program(), "copy_offset", [5, 1, 2, 2, 1]),
            (fill_program(), "fill_range", [8, 2, 3, 37, 2]),
        )
        for source, entry, arguments in cases:
            with self.subTest(entry=entry):
                result = self.compare(source)
                self.execution(source, entry, arguments, result["rust_report"]["functions"][0])
                self.assertIs(result["rust_report"]["claims"]["live_heap_or_process_rss_bounded"], False)
                self.assertIs(result["rust_report"]["claims"]["native_time_or_stack_bytes_bounded"], False)

    def test_nominal_normalization_retains_input_identity_and_cannot_grant_public_abi(self):
        source = nominal_identity_program()
        core = verify_program(source)
        result = self.compare(source)
        self.assertEqual(result["input_sha256"], core.input_sha256)
        self.assertEqual(result["core_sha256"], core.sha256)
        self.assertEqual(len(result["rust_report"]["functions"]), 2)
        self.assertNotIn("inspect_packet", core.scalar_entrypoints)

    def test_unsupported_hidden_graphs_and_invalid_resources_reject_before_transport(self):
        hidden_chain = scalar_program()
        hidden_chain["schema"] = "hepta.hia.program.v8"
        hidden_chain["exports"] = ["identity"]
        hidden_chain["functions"].append(f("destroy", [("chain", "chain")], [], ["alloc"], [
            b("entry", [("chain", "chain")], [i("owner.drop", ["chain"])], ret())]))
        invalid = owned_program()
        invalid["functions"][0]["blocks"][0]["ops"].pop()
        for source in (cyclic_control_flow(), cyclic_calls(), hidden_chain, invalid):
            with self.subTest(source=source["module"]):
                self.assertNotEqual(self.raw(source).returncode, 0)
                with patch.object(crosscheck, "_verified_executable_bytes") as launch:
                    with self.assertRaises((HIAStaticBudgetRejected, HIAProgramRejected)):
                        self.compare(source)
                    launch.assert_not_called()

    def test_finite_cost_overflow_declines_instead_of_truncating_python_big_integer(self):
        large = expanding_calls(63)
        python = analyze_static_budget(large)
        self.assertGreater(python["functions"][0]["max_vm_ticks"], (1 << 64) - 1)
        raw = self.raw(large)
        self.assertNotEqual(raw.returncode, 0)
        self.assertIn(b"E_HIA_BUDGET_OVERFLOW", raw.stderr)
        with self.assertRaises(crosscheck.HIARustCrosscheckRejected):
            self.compare(large)
        admitted = self.compare(expanding_calls(62))
        self.assertEqual(admitted["rust_report"]["functions"][0]["max_vm_ticks"], 13_835_058_055_282_163_708)

    def test_large_complete_function_inventory_is_not_silently_truncated(self):
        source = m(*(f("f" + str(index) + "x" * 110, [], [], [], [b("entry", [], [], ret())])
                     for index in range(400)))
        result = self.compare(source)
        self.assertGreater(len(wire(result["rust_report"])), crosscheck.MAX_OUTPUT_BYTES)
        self.assertEqual(len(result["rust_report"]["functions"]), 400)

    def test_changed_complete_receipts_and_claims_are_refused(self):
        source = acyclic_calls()
        real = self.compare(source)["rust_report"]
        variants = []
        for field in ("max_allocator_interactions", "max_vm_ticks", "max_call_depth"):
            for change in (-1, 1):
                changed = deepcopy(real)
                changed["functions"][0][field] += change
                variants.append(changed)
        for mutate in (
            lambda x: x["functions"].pop(),
            lambda x: x["functions"].append(deepcopy(x["functions"][0])),
            lambda x: x["functions"][0].update(max_call_depth=True),
            lambda x: x["functions"][0].update(function="forged"),
            lambda x: x.update(program_sha256="0" * 64),
            lambda x: x.update(core_schema="hepta.hia.program.v8"),
            lambda x: x.update(profile="unreviewed"),
            lambda x: x["claims"].update(rust_is_production_admission_authority=True),
            lambda x: x["claims"].update(exact_feasible_path_maxima_proved=True),
            lambda x: x["claims"].update(per_metric_conservative_upper_bounds=1),
        ):
            changed = deepcopy(real)
            mutate(changed)
            variants.append(changed)
        for changed in variants:
            with self.subTest(changed=changed):
                with patch.object(crosscheck, "_run_pinned_shadow", return_value=(wire(changed) + b"\n", b"", 0)):
                    with self.assertRaises(crosscheck.HIARustCrosscheckRejected):
                        self.compare(source)
        for raw in (wire(real) + b"\n{}\n", wire(real)[:-1] + b',"functions":[]}\n'):
            with patch.object(crosscheck, "_run_pinned_shadow", return_value=(raw, b"", 0)):
                with self.assertRaises(crosscheck.HIARustCrosscheckRejected):
                    self.compare(source)

    def test_limit_policy_is_enforced_before_rust_and_never_becomes_host_time(self):
        for policy in ({"max_allocator_interactions": 1}, {"max_vm_ticks": 3},
                       {"max_call_depth": 0}, {"max_vm_ticks": True}, {"timeout": float("nan")}):
            with self.subTest(policy=policy), patch.object(crosscheck, "_verified_executable_bytes") as launch:
                with self.assertRaises((HIAStaticBudgetRejected, crosscheck.HIARustCrosscheckRejected)):
                    self.compare(owned_program(), **policy)
                launch.assert_not_called()


if __name__ == "__main__":
    unittest.main()
