"""Finite v8 payload qualification composes ownership and returned borrow roots.

Actual Rust/native cases are separate from pure admission tests. Exact input
qualification never grants production/native optimization or unwind authority.
"""
from __future__ import annotations

from copy import deepcopy
from contextlib import nullcontext
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_heap_bound import (HIAHeapBoundRejected,
    qualify_entry_live_heap_budget, qualify_finite_entry_live_heap_budget,
    qualify_finite_entry_live_heap_budget_v8)
from hepta.hia_program import HIAProgramRejected, verify_program
from hepta.hia_program_runtime import HIAProgramBudgetExceeded, HIAProgramTrap, execute_program
from tests.test_hia_program import b, branch, c, f, i, jump, m, ret
from tests.test_hia_composite_returned_loans import pair_program, task_program
from tests import test_hia_rust_owned_cfg as cfg
from tests import test_hia_rust_returned_loans as rust_returns

ROOT = Path(__file__).resolve().parents[1]
CLANG = os.environ.get("CLANG") or shutil.which("clang")
EVIDENCE = os.environ.get("HEPTA_FINITE_V8_EVIDENCE_DIR")


def retain(name, value):
    if EVIDENCE:
        directory = Path(EVIDENCE)
        directory.mkdir(parents=True, exist_ok=True)
        (directory / name).write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")


def mixed_transfer_program():
    leaf = f("leaf", [("input", "readbuf")], ["readbuf"], [], [
        b("start", [("input", "readbuf")], [
            i("borrow.read", ["input"], [("child", "readbuf")])], ret("child"))])
    leaf["return_loans"] = ["input"]
    relay = f("relay", [("view", "readbuf")], ["readbuf"], [], [
        b("start", [("view", "readbuf")], [
            i("call", ["view"], [("child", "readbuf")], function="leaf")], ret("child"))])
    relay["return_loans"] = ["view"]
    params = [("incoming", "buffer"), ("held", "readbuf"),
              ("replacement", "usize"), ("cancel", "bool")]
    exchange = f("exchange", params, ["buffer", "readbuf", "bool"], ["alloc"], [
        b("start", params, [
            i("call", ["held"], [("child", "readbuf")], function="relay")],
          branch("cancel", ("cancelled", "incoming", "held", "child"),
                            ("work", "incoming", "held", "child", "replacement"))),
        b("cancelled", [("original", "buffer"), ("cancel_parent", "readbuf"),
                         ("cancel_child", "readbuf")], [c("not_changed", "bool", False)],
          ret("original", "cancel_child", "not_changed")),
        b("work", [("old", "buffer"), ("work_parent", "readbuf"),
                    ("work_child", "readbuf"), ("size", "usize")], [
            i("buffer.try_new", ["size"], [("new", "buffer"), ("ok", "bool")])],
          branch("ok", ("accepted", "old", "new", "work_parent", "work_child"),
                       ("failed", "old", "new", "work_parent", "work_child"))),
        b("accepted", [("old_good", "buffer"), ("new_good", "buffer"),
                        ("good_parent", "readbuf"), ("good_child", "readbuf")], [
            i("owner.drop", ["old_good"]), c("changed", "bool", True)],
          ret("new_good", "good_child", "changed")),
        b("failed", [("old_back", "buffer"), ("empty", "buffer"),
                      ("failed_parent", "readbuf"), ("failed_child", "readbuf")], [
            i("owner.drop", ["empty"]), c("unchanged", "bool", False)],
          ret("old_back", "failed_child", "unchanged")),
    ])
    exchange["return_loans"] = [None, "held", None]
    params = [("requested", "usize"), ("cancel", "bool")]
    entry = f("entry", params, ["u8"], ["alloc", "read", "trap"], [
        b("start", params, [
            c("three", "usize", 3), i("buffer.new", ["three"], [("kept", "buffer")]),
            c("four", "usize", 4), i("buffer.new", ["four"], [("passed", "buffer")]),
            i("borrow.read", ["kept"], [("parent", "readbuf")]),
            i("call", ["passed", "parent", "requested", "cancel"],
                [("owned", "buffer"), ("returned", "readbuf"), ("changed", "bool")], function="exchange"),
            i("buffer.len", ["owned"], [("owned_size", "usize")]),
            i("buffer.len", ["returned"], [("retained_size", "usize")]),
            i("buffer.try_new", ["retained_size"], [("scratch", "buffer"), ("scratch_ok", "bool")]),
            i("owner.drop", ["scratch"]),
            i("loan.end", ["returned"]), i("loan.end", ["parent"]),
            i("owner.move", ["owned"], [("moved", "buffer")]),
            i("owner.drop", ["moved"]), i("owner.drop", ["kept"]),
            i("int.add.checked", ["owned_size", "retained_size"], [("sum", "usize")]),
            i("int.cast", ["sum"], [("answer", "u8")], mode="checked")], ret("answer"))])
    document = m(leaf, relay, exchange, entry)
    document["schema"] = "hepta.hia.program.v8"
    document["exports"] = ["entry"]
    return document


def qualify(source, entry="entry", arguments=(9, False), limit=1024):
    return qualify_finite_entry_live_heap_budget_v8(
        source, entry, arguments, max_live_heap_bytes=limit)


def asymmetric_return_program():
    """The first returned loan comes from the larger second caller root."""
    params = [("owned", "buffer"), ("left", "readbuf"), ("right", "readbuf")]
    helper = f("swap", params, ["buffer", "readbuf", "readbuf"], [], [
        b("start", params, [], ret("owned", "right", "left"))])
    helper["return_loans"] = [None, "right", "left"]
    entry = f("entry", [], ["usize"], ["alloc", "trap"], [b("start", [], [
        c("three", "usize", 3), c("eleven", "usize", 11), c("four", "usize", 4),
        i("buffer.new", ["three"], [("small", "buffer")]),
        i("buffer.new", ["eleven"], [("large", "buffer")]),
        i("buffer.new", ["four"], [("moved", "buffer")]),
        i("borrow.read", ["small"], [("left", "readbuf")]),
        i("borrow.read", ["large"], [("right", "readbuf")]),
        i("call", ["moved", "left", "right"], [("owned", "buffer"),
            ("first", "readbuf"), ("second", "readbuf")], function="swap"),
        i("owner.drop", ["owned"]),
        i("buffer.len", ["first"], [("extent", "usize")]),
        i("buffer.try_new", ["extent"], [("scratch", "buffer"), ("ok", "bool")]),
        i("owner.drop", ["scratch"]), i("loan.end", ["first"]), i("loan.end", ["second"]),
        i("loan.end", ["left"]), i("loan.end", ["right"]),
        i("owner.drop", ["small"]), i("owner.drop", ["large"])], ret("extent"))])
    document = m(helper, entry)
    document["schema"], document["exports"] = "hepta.hia.program.v8", ["entry"]
    return document


def observe(source, entry, arguments, **policy):
    try:
        return execute_program(source, entry, arguments, **policy)
    except (HIAProgramBudgetExceeded, HIAProgramTrap) as stopped:
        return stopped.report


class FiniteV8HeapTests(unittest.TestCase):
    def assert_bound(self, report, observed):
        self.assertLessEqual(observed["resources"]["peak_bytes"], report["peak_bound_bytes"])
        self.assertLessEqual(observed["steps"], report["max_vm_ticks"])
        self.assertLessEqual(observed["resources"]["allocation_attempts"] + observed["resources"]["frees"],
                             report["max_allocator_interactions"])

    def test_mixed_owner_and_returned_loan_calls_get_a_new_explicit_bound(self):
        core = verify_program(mixed_transfer_program())
        report = qualify(core, limit=16)
        self.assertEqual(report["schema"], "hepta.hia.finite-entry-live-heap-admission.v2")
        self.assertEqual(report["profile"], "acyclic-byte-owner-transfer-parameter-loans-v8")
        self.assertEqual(report["core_sha256"], core.sha256)
        self.assertEqual(report["peak_bound_bytes"], 16)
        self.assertTrue(report["claims"]["owned_call_transfer_accounted"])
        self.assertTrue(report["claims"]["returned_loan_caller_roots_preserved"])
        self.assertFalse(report["claims"]["cleanup_after_trap_or_budget_stop_proved"])
        unsigned = {key: value for key, value in report.items() if key != "sha256"}
        self.assertEqual(report["sha256"], sha256(json.dumps(unsigned, sort_keys=True,
            separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()).hexdigest())
        actual = execute_program(core, "entry", [9, False])
        self.assertEqual(actual["values"], [12])
        self.assertEqual(actual["resources"]["peak_bytes"], 16)
        self.assert_bound(report, actual)
        with self.assertRaisesRegex(HIAHeapBoundRejected, "E_HIA_BUDGET_EXCEEDED"):
            qualify(core, limit=15)

    def test_legacy_admissions_keep_their_exact_version_and_boundary(self):
        source = mixed_transfer_program()
        with self.assertRaisesRegex(HIAHeapBoundRejected, "E_HIA_BUDGET_PROFILE"):
            qualify_finite_entry_live_heap_budget(source, "entry", [9, False], max_live_heap_bytes=16)
        with self.assertRaises(HIAHeapBoundRejected):
            qualify_entry_live_heap_budget(source, "entry", max_live_heap_bytes=16)
        from tests.test_hia_partial_finite_bounds import nested_owned
        old = qualify_finite_entry_live_heap_budget(nested_owned(), "entry", [], max_live_heap_bytes=19)
        self.assertEqual(old["schema"], "hepta.hia.finite-entry-live-heap-admission.v1")
        self.assertEqual(old["profile"], "acyclic-byte-owner-transfer-v7")
        self.assertNotIn("returned_loan_caller_roots_preserved", old["claims"])
        with self.assertRaisesRegex(HIAHeapBoundRejected, "E_HIA_BUDGET_PROFILE"):
            qualify(nested_owned(), arguments=[])

    def test_returned_loan_length_uses_its_retained_caller_extent(self):
        source = mixed_transfer_program()
        for size, bound in ((0, 10), (1, 10), (9, 16), (23, 30), (1 << 63, 10)):
            for cancel in (False, True):
                with self.subTest(size=size, cancel=cancel):
                    report = qualify(source, arguments=[size, cancel], limit=bound)
                    self.assertEqual(report["peak_bound_bytes"], bound)
                    for fail_at in (None, 1, 2, 3, 4):
                        actual = observe(source, "entry", [size, cancel], allocation_fail_at=fail_at)
                        self.assert_bound(report, actual)
                        if actual["status"] == "returned":
                            self.assertEqual(actual["resources"]["live_owners"], 0)
                            self.assertEqual(actual["resources"]["live_local_loans"], 0)
                            self.assertEqual(actual["resources"]["live_bytes"], 0)

    def test_explicit_cancellation_and_allocation_failure_keep_distinct_values(self):
        source = mixed_transfer_program()
        for args, failure, expected, peak in (([9, False], None, 12, 16),
                ([9, True], None, 7, 10), ([9, False], 3, 7, 10), ([9, False], 4, 12, 16)):
            report = qualify(source, arguments=args, limit=16)
            actual = observe(source, "entry", args, allocation_fail_at=failure)
            self.assertEqual(actual["values"], [expected])
            self.assertEqual(actual["resources"]["peak_bytes"], peak)
            self.assert_bound(report, actual)
        stopped = observe(source, "entry", [9, False], allocation_fail_at=2)
        self.assertEqual(stopped["status"], "trapped")
        self.assertEqual(stopped["resources"]["live_bytes"], 3)
        self.assertEqual(stopped["resources"]["frees"], 0)

    def test_every_step_heap_and_call_stop_is_bounded_without_unwinding(self):
        source = mixed_transfer_program()
        report = qualify(source, limit=16)
        completed = observe(source, "entry", [9, False])
        for steps in range(1, completed["steps"] + 1):
            stopped = observe(source, "entry", [9, False], max_steps=steps)
            self.assert_bound(report, stopped)
            self.assertEqual(stopped["status"], "returned" if steps == completed["steps"] else "budget_exceeded")
        for policy in ({"max_heap_bytes": 6}, {"max_heap_bytes": 15}, {"max_call_depth": 1},
                       {"max_call_depth": 2}, {"max_call_depth": 3}):
            stopped = observe(source, "entry", [9, False], **policy)
            self.assertEqual(stopped["status"], "budget_exceeded")
            self.assertGreater(stopped["resources"]["live_bytes"], 0)
            self.assert_bound(report, stopped)

    def test_existing_composite_partial_owners_and_task_cleanup_use_same_analysis(self):
        for mode in ("read", "mut"):
            source = pair_program(mode)
            core = verify_program(source)
            report = qualify(core, "probe", [3, 37, True], limit=6)
            self.assertEqual(report["input_sha256"], core.input_sha256)
            self.assertEqual(report["peak_bound_bytes"], 6)
            for failure in (None, 1, 2):
                actual = observe(core, "probe", [3, 37, True], allocation_fail_at=failure)
                self.assert_bound(report, actual)
        source = task_program()
        for mode in (0, 1, 2):
            report = qualify(source, "task_probe", [3, mode], limit=32)
            for failure in (None, 1, 2):
                actual = observe(source, "task_probe", [3, mode], allocation_fail_at=failure)
                self.assert_bound(report, actual)
                if actual["status"] == "returned":
                    self.assertEqual(actual["resources"]["live_bytes"], 0)
                    self.assertEqual(actual["resources"]["live_local_loans"], 0)

    def test_external_extent_is_unknown_inside_callee_and_cannot_be_promised(self):
        source = mixed_transfer_program()
        work = source["functions"][2]["blocks"][2]["ops"]
        work.insert(0, i("buffer.len", ["work_child"], [("external_length", "usize")]))
        work[1]["args"] = ["external_length"]
        verify_program(source)
        with self.assertRaisesRegex(HIAHeapBoundRejected, "allocator extent"):
            qualify(source)

    def test_shared_actual_aliases_do_not_double_count_and_swapped_roots_stay_distinct(self):
        from tests.test_hia_returned_loans import multiple_shared, swapped_mutable
        for construction in ("forward", "children", "mixed"):
            source = multiple_shared(construction)
            report = qualify(source, "shared", [37], limit=1)
            self.assertEqual(report["peak_bound_bytes"], 1)
            self.assert_bound(report, observe(source, "shared", [37]))
        source = swapped_mutable()
        report = qualify(source, "swapped", [], limit=2)
        self.assertEqual(report["peak_bound_bytes"], 2)
        self.assert_bound(report, observe(source, "swapped", []))

    def test_asymmetric_reordered_loan_results_select_the_correct_retained_root(self):
        source = asymmetric_return_program()
        bound = qualify(source, arguments=[], limit=25)
        self.assertEqual(bound["peak_bound_bytes"], 25)
        actual = execute_program(source, "entry", [])
        self.assertEqual(actual["values"], [11])
        self.assertEqual(actual["resources"]["peak_bytes"], 25)
        self.assert_bound(bound, actual)
        with self.assertRaisesRegex(HIAHeapBoundRejected, "E_HIA_BUDGET_EXCEEDED"):
            qualify(source, arguments=[], limit=24)

    def test_wrong_origins_early_parent_end_and_hidden_bad_helper_reject_first(self):
        for mutation in ("origin", "parent", "hidden"):
            source = mixed_transfer_program()
            if mutation == "origin":
                source["functions"][2]["return_loans"][1] = "incoming"
            elif mutation == "parent":
                ops = source["functions"][-1]["blocks"][0]["ops"]
                at = next(n for n, op in enumerate(ops) if op["op"] == "call") + 1
                ops.insert(at, i("loan.end", ["parent"]))
            else:
                hidden = deepcopy(source["functions"][0]); hidden["name"] = "hidden"
                hidden["return_loans"] = [None]; source["functions"].append(hidden)
            with self.subTest(mutation=mutation), self.assertRaises(HIAProgramRejected):
                qualify(source, limit=0)

    def test_unknown_profiles_cycles_and_analysis_work_limits_refuse(self):
        source = mixed_transfer_program()
        source["functions"].append(f("hidden_chain", [("owner", "chain")], [], ["alloc"], [
            b("start", [("owner", "chain")], [i("owner.drop", ["owner"])], ret())]))
        with self.assertRaisesRegex(HIAHeapBoundRejected, "E_HIA_BUDGET_PROFILE"):
            qualify(source)
        for kind in ("cfg", "calls"):
            source = mixed_transfer_program()
            fn = f("hidden", [], [], [], [b("start", [], [], jump("loop")),
                b("loop", [], [], jump("loop"))]) if kind == "cfg" else f("hidden", [], [], [], [
                    b("start", [], [i("call", function="hidden")], ret())])
            source["functions"].append(fn)
            with self.subTest(kind=kind), self.assertRaisesRegex(HIAHeapBoundRejected, "E_HIA_BUDGET_UNBOUNDED"):
                qualify(source)
        for variable in ("_FINITE_MAX_CONTEXTS", "_FINITE_MAX_TRANSFER_STEPS", "_FINITE_MAX_ANALYSIS_DEPTH"):
            with self.subTest(variable=variable), patch("hepta.hia_heap_bound." + variable, 1):
                with self.assertRaisesRegex(HIAHeapBoundRejected, "E_HIA_BUDGET_LIMIT"):
                    qualify(mixed_transfer_program())

    def test_exact_arguments_policy_and_captured_snapshot_remain_bound(self):
        source = mixed_transfer_program()
        for args in ([True, False], [9, 0], [9.0, False], [1 << 64, False], [9], "args"):
            with self.subTest(args=args), self.assertRaisesRegex(HIAHeapBoundRejected, "E_HIA_BUDGET_INPUT"):
                qualify(source, arguments=args)
        for limit in (True, -1, 1.0, None):
            with self.subTest(limit=limit), self.assertRaisesRegex(HIAHeapBoundRejected, "E_HIA_BUDGET_POLICY"):
                qualify(source, limit=limit)
        from hepta.hia_heap_bound import _FiniteInvocationAnalysis
        arguments = [9, False]
        original = _FiniteInvocationAnalysis.invoke
        def modify(analysis, fn, bounds):
            arguments[0] = 123
            return original(analysis, fn, bounds)
        with patch.object(_FiniteInvocationAnalysis, "invoke", modify):
            report = qualify(source, arguments=arguments, limit=16)
        self.assertEqual(arguments, [123, False])
        self.assertEqual(report["arguments"], [9, False])
        self.assertEqual(report["peak_bound_bytes"], 16)


@unittest.skipUnless(shutil.which("cargo"), "Actual Cargo required: v8 resource comparison NOT qualified")
class FiniteV8HeapRust(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cfg.RustByteOwnerCfgParity.setUpClass.__func__(cls)
        cls.rejections = []
        cls.bound_observations = []

    @classmethod
    def tearDownClass(cls):
        retain("rust.json", {"build": cls.build, "executable_sha256": sha256(Path(cls.executable).read_bytes()).hexdigest(),
            "programs": cls.sources, "observations": cls.observations,
            "bound_v2_observations": cls.bound_observations, "refusals": cls.rejections})
        print(f"Finite v8 Python/Rust parity observations: {len(cls.observations)}; "
              f"bound v2 observations: {len(cls.bound_observations)}; negative programs: {len(cls.rejections)}")

    raw_run = cfg.RustByteOwnerCfgParity.raw_run
    parity = cfg.RustByteOwnerCfgParity.parity
    shadow = rust_returns.RustReturnedLoansParity.shadow
    wire = staticmethod(rust_returns.RustReturnedLoansParity.wire)
    reject_both = rust_returns.RustReturnedLoansParity.reject_both
    execution_profile = "bounded-cfg-byte-owner-loan-returns-v4"

    def test_actual_rust_matches_mixed_owner_loans_failure_cancel_and_each_stop(self):
        source = mixed_transfer_program()
        for cancel in (False, True):
            bound = qualify(source, arguments=[9, cancel], limit=16)
            for failure in (None, 1, 2, 3, 4):
                row = self.parity(source, "entry", [9, cancel], fail=failure)
                self.assertLessEqual(row["resources"]["peak_bytes"], bound["peak_bound_bytes"])
            full = self.parity(source, "entry", [9, cancel])
            for limit in range(1, full["steps"] + 1):
                self.parity(source, "entry", [9, cancel], steps=limit)
        for heap in (0, 2, 3, 6, 7, 15, 16):
            row = self.parity(source, "entry", [9, False], heap=heap)
            self.assertEqual(row["status"], "returned" if heap == 16 else "budget_exceeded")

    def test_actual_rust_bound_v2_rejects_small_depth_and_observes_stopped_resources(self):
        from hepta.hia_rust_crosscheck import crosscheck_rust_execution_v2
        core = verify_program(mixed_transfer_program())
        digest = sha256(Path(self.executable).read_bytes()).hexdigest()
        bound = qualify(core, limit=16)
        self.assertEqual(bound["max_call_depth"], 4)
        for depth in (1, 2, 3, 4):
            row = crosscheck_rust_execution_v2(core, "entry", [9, False], self.executable,
                executable_sha256=digest, max_call_depth=depth, max_heap_bytes=16,
                max_steps=bound["max_vm_ticks"])
            type(self).bound_observations.append(row)
            result = row["rust_report"]
            self.assertEqual(result["status"], "returned" if depth == 4 else "budget_exceeded")
            if depth < 4:
                self.assertEqual(result["error"], {"code": "calls"})
                self.assertGreater(result["resources"]["live_bytes"], 0)
                self.assertEqual(result["resources"]["frees"], 0)

    def test_actual_rust_asymmetric_reordered_returns_keep_the_larger_root(self):
        source = asymmetric_return_program()
        bound = qualify(source, arguments=[], limit=25)
        for failure in (None, 1, 2, 3, 4):
            report = self.parity(source, "entry", [], fail=failure)
            self.assertLessEqual(report["resources"]["peak_bytes"], bound["peak_bound_bytes"])
        report = self.parity(source, "entry", [], heap=24)
        self.assertEqual(report["status"], "budget_exceeded")
        self.assertEqual(report["resources"]["live_bytes"], 14)

    def test_actual_rust_composite_tasks_and_partial_returned_views(self):
        for mode in ("read", "mut"):
            core = verify_program(pair_program(mode))
            bound = qualify(core, "probe", [3, 37, True], limit=6)
            for failure in (None, 1, 2):
                report = self.parity(core, "probe", [3, 37, True], fail=failure)
                self.assertLessEqual(report["resources"]["peak_bytes"], bound["peak_bound_bytes"])
        core = verify_program(task_program())
        for mode in (0, 1, 2):
            bound = qualify(core, "task_probe", [3, mode], limit=32)
            for failure in (None, 1, 2):
                report = self.parity(core, "task_probe", [3, mode], fail=failure)
                self.assertLessEqual(report["resources"]["peak_bytes"], bound["peak_bound_bytes"])

    def test_invalid_origins_and_early_parent_end_reject_independently(self):
        source = mixed_transfer_program()
        source["functions"][2]["return_loans"][1] = "incoming"
        self.reject_both(source)
        source = mixed_transfer_program()
        ops = source["functions"][-1]["blocks"][0]["ops"]
        at = next(n for n, op in enumerate(ops) if op["op"] == "call") + 1
        ops.insert(at, i("loan.end", ["parent"]))
        self.reject_both(source)


@unittest.skipUnless(CLANG and sys.platform == "linux", "Actual Linux Clang required: allocator observation NOT qualified")
class FiniteV8HeapNative(unittest.TestCase):
    def test_native_success_failure_and_cancellation_obey_actual_allocator_bound(self):
        from hepta.hia_program_llvm import build_program_native
        source = mixed_transfer_program()
        report = qualify(source, limit=16)
        text = (ROOT / "examples/hia_recursive_chain/allocator_driver.c").read_text().split("int main(", 1)[0]
        text += r'''
uint8_t entry(uint64_t, _Bool);
int main(int argc, char **argv) {
    if (argc != 3) return 64;
    refuse_at = strtoull(argv[1], NULL, 10);
    uint8_t value = entry(9, strtoull(argv[2], NULL, 10) != 0);
    printf("{\"value\":%u,\"attempts\":%llu,\"allocations\":%llu,\"frees\":%llu,"
           "\"live_bytes\":%llu,\"peak_bytes\":%llu,\"bad_frees\":%llu,\"null_frees\":%llu}\n",
           value, (unsigned long long)attempts, (unsigned long long)allocations,
           (unsigned long long)frees, (unsigned long long)live_bytes, (unsigned long long)peak_bytes,
           (unsigned long long)bad_frees, (unsigned long long)null_frees);
    return live_bytes || bad_frees || null_frees ? 65 : 0;
}
'''
        if EVIDENCE:
            Path(EVIDENCE).mkdir(parents=True, exist_ok=True)
        allocation = (nullcontext(tempfile.mkdtemp(prefix="native-", dir=EVIDENCE))
                      if EVIDENCE else tempfile.TemporaryDirectory())
        with allocation as temporary:
            directory = Path(temporary)
            obj, driver, exe = directory / "core.o", directory / "observer.c", directory / "observer"
            build = build_program_native(source, output=obj, clang=CLANG, kind="object")
            self.assertTrue(build["ok"], build)
            driver.write_text(text)
            linked = subprocess.run([CLANG, "-O2", "-Wl,--wrap=malloc", "-Wl,--wrap=calloc",
                "-Wl,--wrap=free", str(driver), str(obj), "-o", str(exe)], capture_output=True, timeout=30)
            self.assertEqual(linked.returncode, 0, linked.stderr.decode())
            records = {"core": verify_program(source).as_dict(), "bound": report, "build": build,
                "link": {"argv": linked.args, "returncode": linked.returncode,
                         "stdout": linked.stdout.decode(), "stderr": linked.stderr.decode()},
                "files": {str(path): sha256(path.read_bytes()).hexdigest() for path in (obj, driver, exe)},
                "observations": []}
            for failure, cancel in ((0, 0), (3, 0), (4, 0), (0, 1), (3, 1)):
                actual = subprocess.run([str(exe), str(failure), str(cancel)], capture_output=True, timeout=10)
                self.assertEqual(actual.returncode, 0, actual.stderr.decode())
                native = json.loads(actual.stdout)
                vm = execute_program(source, "entry", [9, bool(cancel)], allocation_fail_at=failure or None)
                records["observations"].append({"argv": actual.args, "returncode": actual.returncode,
                    "stdout": actual.stdout.decode(), "stderr": actual.stderr.decode(), "python": vm})
                self.assertEqual(native["value"], vm["values"][0])
                for field in ("allocation_attempts", "allocations", "frees", "live_bytes", "peak_bytes"):
                    self.assertEqual(native["attempts" if field == "allocation_attempts" else field], vm["resources"][field])
                self.assertLessEqual(native["peak_bytes"], report["peak_bound_bytes"])
            retain("native.json", records)


if __name__ == "__main__":
    unittest.main()
