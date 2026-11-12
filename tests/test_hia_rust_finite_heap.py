"""Independent Rust finite-entry heap admission on the existing v4 Machine.

All positive observations launch the actual pinned binary. Python analyses and
VM execution are separate differential oracles, never admission dependencies.
Optional development evidence captures every actual process, including refused
inputs; deliberate replay mutation occurs only in negative consumer controls.
"""
from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import time
import unittest
from unittest.mock import patch

from hepta import hia_rust_byte_dag as route
from hepta import hia_rust_crosscheck as transport
from hepta.hia_heap_bound import (qualify_finite_entry_live_heap_budget,
    qualify_finite_entry_live_heap_budget_v8_with_borrowed_extents)
from hepta.hia_program import verify_program
from hepta.hia_program_runtime import HIAProgramBudgetExceeded, HIAProgramTrap, execute_program
from hepta.hia_static_budget import analyze_static_budget
from tests import test_hia_rust_bound_depth as native
from tests.test_hia_program import b, branch, c, f, i, jump, m, ret
from tests.test_hia_partial_finite_bounds import v7, nested_owned, borrowed_owned
from tests.test_hia_borrowed_extent_heap import (borrowed_exchange_program, context_program,
    aliased_extent_program, reordered_extent_program, joined_extent_program, interval_program,
    borrowed_pair_program, borrowed_task_program, invalid_programs)
from tests.test_hia_finite_v8_heap import mixed_transfer_program
from tests.test_hia_rust_crosscheck import owned_program, scalar_program
from tests.test_hia_static_budget import cyclic_calls, cyclic_control_flow
from tools.qualify_hia_partial_records import program, cases, budget_cases, independent_spec

wire = native.wire
METRICS = ("max_allocator_interactions", "max_vm_ticks", "max_call_depth")
MAX_LIMITS = {metric: (1 << 64) - 1 for metric in METRICS}


def context_work(count, helper_ops=0):
    child = f("helper", [("n", "usize")], [], [], [b("start", [("n", "usize")],
        [c(f"constant{n}", "usize", n) for n in range(helper_ops)], ret())])
    ops = []
    for n in range(count):
        ops += [c(f"arg{n}", "usize", n), i("call", [f"arg{n}"], function="helper")]
    return v7(child, f("entry", [], [], [], [b("start", [], ops, ret())]))


def depth_work(count):
    functions = []
    for n in reversed(range(count)):
        name = "entry" if n == 0 else f"depth{n}"
        ops = [] if n + 1 == count else [i("call", function=f"depth{n + 1}")]
        functions.append(f(name, [], [], [], [b("start", [], ops, ret())]))
    return v7(*functions)


def wide_state_work(calls):
    """Small instruction count, large actual abstract edge/cached inventories."""
    def params(block):
        return [(f"p{block}_{column}", "usize") for column in range(256)]
    blocks = []
    for n in range(64):
        edge = ret() if n == 63 else jump(f"b{n + 1}", *(p[0] for p in params(n)))
        blocks.append(b(f"b{n}", params(n), [], edge))
    helper = f("wide", params(0), [], [], blocks)
    ops = [c("zero", "usize", 0)]
    for n in range(calls):
        ops += [c(f"tag{n}", "usize", n),
                i("call", [f"tag{n}", *(["zero"] * 255)], function="wide")]
    return v7(helper, f("entry", [], [], [], [b("start", [], ops, ret())]))


@unittest.skipUnless(platform.system() == "Linux" and shutil.which("cargo"),
                     "Actual finite heap Rust admission requires Linux/Cargo; NOT qualified")
class RustFiniteHeapAdmission(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        native.RustBoundDepthParity.setUpClass.__func__(cls)
        cls.native_processes, cls.isolated_children = [], []
        cls.addClassCleanup(cls.retain)

    @classmethod
    def retain(cls):
        target = os.environ.get("HEPTA_RUST_FINITE_HEAP_EVIDENCE_DIR")
        if target:
            directory = Path(target)
            directory.mkdir(parents=True, exist_ok=True)
            result = {"build": cls.build, "executable_sha256": cls.digest,
                "programs": cls.programs, "processes": cls.native_processes,
                "isolated_child_processes": cls.isolated_children,
                "observations": cls.observations, "refusals": cls.refusals,
                "claims": {"positive_native_responses_are_actual": True,
                           "new_holdout": False, "whole_language_soundness_proved": False}}
            (directory / "actual.json").write_bytes(wire(result) + b"\n")
        print(f"Rust finite heap actual processes: {len(cls.native_processes)}; "
              f"matched bound+Machine observations: {len(cls.observations)}; "
              f"raw refusal controls: {len(cls.refusals)}")

    def process(self, raw, argv):
        started = time.monotonic_ns()
        completed = subprocess.run([str(self.executable), *argv], input=raw,
            cwd=native.ROOT, capture_output=True, timeout=60)
        observed = {"test": self.id(), "argv_after_executable": argv,
            "input_sha256": sha256(raw).hexdigest(), "executable_sha256": self.digest,
            "stdout": completed.stdout.decode(), "stderr": completed.stderr.decode(),
            "returncode": completed.returncode, "outer_wall_ns": time.monotonic_ns() - started}
        type(self).programs[observed["input_sha256"]] = raw.decode()
        type(self).native_processes.append(observed)
        return completed

    def analysis(self, source, entry="entry", arguments=(), limit=(1 << 63) - 1):
        raw = source if type(source) is bytes else wire(source)
        completed = self.process(raw, ["--owned-finite-heap", entry, wire(arguments).decode(),
            wire({"max_live_heap_bytes": limit}).decode()])
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        self.assertEqual(completed.stderr, b"")
        report = json.loads(completed.stdout)
        self.assertNotIn("runtime", report)
        self.assertFalse(report["claims"]["execution_used_to_establish_bound"])
        return report

    def refuse(self, source, entry="entry", arguments=(), *, code=None, limit=(1 << 63) - 1):
        raw = source if type(source) is bytes else wire(source)
        completed = self.process(raw, ["--byte-dag-heap-admit-run", entry, wire(arguments).decode(),
            wire(MAX_LIMITS).decode(), wire({"max_live_heap_bytes": limit}).decode(),
            wire({"max_steps": 1, "max_heap_bytes": 0, "max_call_depth": 1,
                  "allocation_fail_at": "0x1"}).decode()])
        self.assertEqual(completed.returncode, 1, completed.stdout.decode())
        self.assertEqual(completed.stdout, b"")
        self.assertTrue(completed.stderr.startswith(b"E_HIA_"), completed.stderr)
        self.assertNotIn(b"panicked", completed.stderr)
        if code:
            self.assertTrue(completed.stderr.startswith(code.encode() + b":"), completed.stderr)
        type(self).refusals.append(type(self).native_processes[-1])

    def invoke(self, raw, entry, arguments, *, limit, static=MAX_LIMITS, **policy):
        actual_transport = transport._run_pinned_shadow
        def record(binary, argv, stdin, timeout, **kwargs):
            started = time.monotonic_ns()
            stdout, stderr, returncode = actual_transport(binary, argv, stdin, timeout, **kwargs)
            digest = sha256(stdin).hexdigest()
            type(self).programs[digest] = stdin.decode()
            type(self).native_processes.append({"test": self.id(),
                "argv_after_executable": argv, "input_sha256": digest,
                "executable_sha256": sha256(binary).hexdigest(), "stdout": stdout.decode(),
                "stderr": stderr.decode(), "returncode": returncode,
                "outer_wall_ns": time.monotonic_ns() - started})
            return stdout, stderr, returncode
        with patch.object(transport, "_run_pinned_shadow", record):
            return route.execute_rust_byte_dag(raw, entry, arguments, self.executable,
                executable_sha256=self.digest, static_policy=static,
                max_static_live_heap_bytes=limit, **policy)["rust_report"]

    def compare(self, source, entry="entry", arguments=(), *, expected_bound=None, **policy):
        core = verify_program(source)
        body = core.as_dict()
        oracle = (qualify_finite_entry_live_heap_budget_v8_with_borrowed_extents
                  if body["schema"] == "hepta.hia.program.v8"
                  else qualify_finite_entry_live_heap_budget)
        bound = oracle(core, entry, arguments, max_live_heap_bytes=(1 << 63) - 1)
        static = analyze_static_budget(core)
        limits = {metric: max(row[metric] for row in static["functions"]) for metric in METRICS}
        report = self.invoke(core.canonical_bytes, entry, arguments,
            limit=bound["peak_bound_bytes"], static=limits, **policy)
        rust_bound, observed = report["heap_bound"], report["runtime"]["execution"]
        for field in ("peak_bound_bytes", *METRICS):
            self.assertEqual(rust_bound[field], bound[field], field)
        if expected_bound is not None:
            self.assertEqual(rust_bound["peak_bound_bytes"], expected_bound)
        full_policy = {"max_steps": 1_000_000, "max_heap_bytes": 16 * 1024 * 1024,
                       "max_call_depth": 256, "allocation_fail_at": None, **policy}
        try:
            python = execute_program(core, entry, arguments, **full_policy)
        except (HIAProgramBudgetExceeded, HIAProgramTrap) as stopped:
            python = stopped.report
        # The established Rust wire contains the stable error code; Python also
        # has a human diagnostic. Reuse the existing exact v4 contract checker,
        # which compares every result/ledger/tick/policy/claim and the trap code.
        transport._validate_execution(wire(report["runtime"]) + b"\n", report["runtime"]["request"],
                                      body, python, protocol_version=4)
        self.assertLessEqual(observed["resources"]["peak_bytes"], rust_bound["peak_bound_bytes"])
        self.assertFalse(rust_bound["claims"]["cleanup_after_trap_or_budget_stop_proved"])
        self.assertFalse(rust_bound["claims"]["native_execution_authorized"])
        self.assertFalse(report["claims"]["default_production_admission_changed"])
        type(self).observations.append({"test": self.id(), "rust_report": report,
            "python_bound": bound, "python_execution": python, "matched": True})
        return report

    def test_partial_initialization_and_task_failure_matrix_reuses_normalized_core(self):
        core = verify_program(program())
        self.assertEqual(core.as_dict()["schema"], "hepta.hia.program.v7")
        corpus = cases()
        self.assertEqual(len(corpus), 121)
        for row in corpus:
            with self.subTest(row=row):
                report = self.compare(core, row["function"], row["arguments"],
                    allocation_fail_at=row["fail_at"] or None)
                actual = report["runtime"]["execution"]
                self.assertEqual(actual["values"], [independent_spec(row)["result"]])
                self.assertEqual(actual["resources"]["live_owners"], 0)
                self.assertEqual(actual["resources"]["live_bytes"], 0)
        for policy in budget_cases():
            with self.subTest(policy=policy):
                self.compare(core, "partial_case", [0, 7, 73], expected_bound=14, **policy)

    def test_transfer_multi_return_alias_and_every_allocator_failure_keep_peak(self):
        for source, bound in ((nested_owned(), 19), (borrowed_owned(), 18)):
            for failure in (None, 1, 2, 3, 4, 5, (1 << 64) + 1):
                with self.subTest(bound=bound, failure=failure):
                    self.compare(source, expected_bound=bound, allocation_fail_at=failure)

    def test_v8_nested_returned_loans_mutability_and_cancel_keep_caller_roots(self):
        for mode in ("read", "mut"):
            source = borrowed_exchange_program(mode)
            for cancel in (False, True):
                for failure in (None, 1, 2, 3, 4, 5):
                    with self.subTest(mode=mode, cancel=cancel, fail=failure):
                        self.compare(source, arguments=[cancel], expected_bound=36,
                                     allocation_fail_at=failure)
        for source, arguments, expected in (
                (context_program(), [], 29), (aliased_extent_program(), [], 31),
                (reordered_extent_program(), [], 36),
                (joined_extent_program(), [False], 25), (joined_extent_program(), [True], 25)):
            report = self.compare(source, arguments=arguments, expected_bound=expected)
            if expected == 29:
                self.assertEqual(report["heap_bound"]["analysis_work"]["contexts"], 3)

    def test_empty_owner_and_scalar_returns_are_intervals_not_success_samples(self):
        for extent in (0, 8):
            for failure in (None, 1, 2):
                report = self.compare(interval_program(extent), expected_bound=100,
                    allocation_fail_at=failure)
                if extent == 8 and failure == 1:
                    self.assertEqual(report["runtime"]["execution"]["resources"]["peak_bytes"], 100)
        source = nested_owned()
        self.refuse(source, limit=18, code="E_HIA_BUDGET_EXCEEDED")
        stopped = self.compare(source, expected_bound=19, max_heap_bytes=18)
        self.assertEqual(stopped["runtime"]["execution"]["error"], {"code": "heap"})
        self.assertGreater(stopped["runtime"]["execution"]["resources"]["live_bytes"], 0)

    def test_v8_normalized_partial_records_and_tasks_preserve_failure_cleanup(self):
        for mode in ("read", "mut"):
            core = verify_program(borrowed_pair_program(mode))
            for flag in (False, True):
                for failure in (None, 1, 2, 3):
                    with self.subTest(mode=mode, flag=flag, fail=failure):
                        self.compare(core, "probe", [3, 37, flag], expected_bound=25,
                                     allocation_fail_at=failure)
        core = verify_program(borrowed_task_program())
        for mode in (0, 1, 2):
            for failure in (None, 1, 2, 3):
                self.compare(core, "task_probe", [3, mode], expected_bound=6,
                             allocation_fail_at=failure)

    def test_every_tick_stop_heap_stop_and_call_stop_is_bounded_without_unwind(self):
        source = mixed_transfer_program()
        returned = self.compare(source, arguments=[9, False], expected_bound=16)
        for step in range(1, returned["runtime"]["execution"]["steps"]):
            report = self.compare(source, arguments=[9, False], expected_bound=16, max_steps=step)
            self.assertEqual(report["runtime"]["execution"]["status"], "budget_exceeded")
        for policy in ({"max_call_depth": 1}, {"max_call_depth": 2}, {"max_call_depth": 3},
                       {"max_heap_bytes": 0}, {"max_heap_bytes": 7}, {"allocation_fail_at": 1}):
            self.compare(source, arguments=[9, False], expected_bound=16, **policy)

    def test_analysis_only_can_bound_unexecuted_large_requests_and_gate_before_vm(self):
        source = owned_program()
        source["schema"] = "hepta.hia.program.v7"
        size = 1 << 40  # no test attempts to allocate this amount
        bound = self.analysis(source, "allocate_release", [size], limit=size)
        self.assertEqual(bound["peak_bound_bytes"], size)
        observed = self.invoke(wire(source), "allocate_release", [size], limit=size,
                               max_steps=1, max_heap_bytes=0)
        self.assertEqual(observed["runtime"]["execution"]["error"], {"code": "steps"})
        self.assertEqual(observed["runtime"]["execution"]["resources"]["peak_bytes"], 0)
        self.refuse(source, "allocate_release", [size], limit=size - 1, code="E_HIA_BUDGET_EXCEEDED")

    def test_branch_and_return_joins_keep_unselected_larger_owner(self):
        child = f("choose", [("flag", "bool")], ["buffer"], ["alloc", "trap"], [
            b("start", [("flag", "bool")], [], branch("flag", ("small",), ("large",))),
            b("small", [], [c("two", "usize", 2), i("buffer.new", ["two"], [("a", "buffer")])], ret("a")),
            b("large", [], [c("nine", "usize", 9), i("buffer.new", ["nine"], [("z", "buffer")])], ret("z"))])
        entry = f("entry", [("flag", "bool")], [], ["alloc", "trap"], [
            b("start", [("flag", "bool")], [c("three", "usize", 3),
                i("buffer.new", ["three"], [("kept", "buffer")]),
                i("call", ["flag"], [("selected", "buffer")], function="choose"),
                i("owner.drop", ["selected"]), i("owner.drop", ["kept"])], ret())])
        source = v7(child, entry)
        for flag, actual in ((True, 5), (False, 12)):
            report = self.compare(source, arguments=[flag], expected_bound=12)
            self.assertEqual(report["runtime"]["execution"]["resources"]["peak_bytes"], actual)
        self.refuse(source, arguments=[True], limit=5, code="E_HIA_BUDGET_EXCEEDED")

    def test_infallible_oversize_and_no_return_calls_keep_earlier_payload(self):
        for extent in (1 << 63, (1 << 64) - 1):
            child = f("stop", [], [], ["alloc", "trap"], [b("start", [], [
                c("four", "usize", 4), i("buffer.new", ["four"], [("held", "buffer")]),
                c("huge", "usize", extent), i("buffer.new", ["huge"], [("never", "buffer")]),
                i("owner.drop", ["never"]), i("owner.drop", ["held"])], ret())])
            entry = f("entry", [], [], ["alloc", "trap"], [b("start", [], [
                c("three", "usize", 3), i("buffer.new", ["three"], [("retained", "buffer")]),
                i("call", function="stop"), i("owner.drop", ["retained"])], ret())])
            report = self.compare(v7(child, entry), expected_bound=7)
            self.assertEqual(report["runtime"]["execution"]["error"], {"code": "allocation"})
            self.assertEqual(report["runtime"]["execution"]["resources"]["live_bytes"], 7)

    def test_whole_module_cycles_chains_invalid_origins_and_nominal_inputs_refuse(self):
        for name, source in invalid_programs():
            entry = next(fn for fn in source["functions"] if fn["name"] == "entry")
            with self.subTest(name=name):
                self.refuse(source, arguments=[False] * len(entry["params"]))
        for hidden in (cyclic_calls(), cyclic_control_flow()):
            source = scalar_program()
            source.update(schema="hepta.hia.program.v7", exports=["identity"])
            source["functions"].extend(hidden["functions"])
            self.refuse(source, "identity", [0], code="E_HIA_BUDGET_UNBOUNDED")
        source = scalar_program()
        source.update(schema="hepta.hia.program.v7", exports=["identity"])
        source["functions"].append(f("hidden", [("root", "chain")], [], ["alloc"], [
            b("start", [("root", "chain")], [i("owner.drop", ["root"])], ret())]))
        self.refuse(source, "identity", [0], code="E_HIA_BUDGET_PROFILE")
        # Nominal descriptors carry additional keys; the exact primitive object
        # shape rejects them before schema-specific semantic validation.
        self.refuse(program(), "partial_case", [0, 7, 73], code="E_HIA_FORMAT")

    def test_unknown_sizes_overflow_and_object_domain_crossing_never_become_zero(self):
        borrowed = borrowed_owned()
        borrowed["functions"][0]["blocks"][0]["ops"][2]["args"] = ["ignored"]
        self.refuse(borrowed, code="E_HIA_BUDGET_UNBOUNDED")
        crossing = f("entry", [], [], ["alloc", "trap"], [b("start", [], [
            c("one", "usize", 1), i("buffer.try_new", ["one"], [("held", "buffer"), ("ok", "bool")]),
            i("buffer.len", ["held"], [("length", "usize")]), c("maximum", "usize", (1 << 63) - 1),
            i("int.add.checked", ["maximum", "length"], [("request", "usize")]),
            i("buffer.try_new", ["request"], [("other", "buffer"), ("other_ok", "bool")]),
            i("owner.drop", ["other"]), i("owner.drop", ["held"])], ret())])
        self.refuse(v7(crossing), code="E_HIA_BUDGET_UNBOUNDED")
        overflow = f("entry", [], [], ["alloc", "trap"], [b("start", [], [
            c("maximum", "usize", (1 << 64) - 1), c("one", "usize", 1),
            i("int.add.checked", ["maximum", "one"], [("request", "usize")]),
            i("buffer.try_new", ["request"], [("other", "buffer"), ("ok", "bool")]),
            i("owner.drop", ["other"])], ret())])
        self.refuse(v7(overflow), code="E_HIA_BUDGET_UNBOUNDED")
        loaded = borrowed_exchange_program()
        child = loaded["functions"][2]["blocks"][2]
        child["ops"][:1] = [c("offset", "usize", 0),
            i("buffer.load", ["work_child", "offset"], [("loaded", "u8")]),
            i("int.cast", ["loaded"], [("borrowed_length", "usize")], mode="checked")]
        loaded["functions"][2]["effects"] = ["alloc", "read", "trap"]
        self.refuse(loaded, arguments=[False], code="E_HIA_BUDGET_UNBOUNDED")

    def test_actual_fixed_analysis_context_depth_transfer_and_value_work_limits(self):
        for kind, positive, negative, counter, expected in (
                ("contexts", context_work(1023), context_work(1024), "contexts", 1024),
                ("depth", depth_work(64), depth_work(65), "peak_analysis_call_depth", 64),
                ("transfers", context_work(32, 1000), context_work(33, 1000), None, None),
                ("values", wide_state_work(3), wide_state_work(4), None, None)):
            with self.subTest(kind=kind):
                admitted = self.analysis(positive, limit=0)
                self.assertEqual(admitted["peak_bound_bytes"], 0)
                if counter:
                    self.assertEqual(admitted["analysis_work"][counter], expected)
                self.refuse(negative, code="E_HIA_BUDGET_LIMIT")

    def test_heap_policy_exact_types_raw_bytes_and_public_scalar_boundary(self):
        source = owned_program()
        source.update(schema="hepta.hia.program.v8", exports=["allocate_release"])
        for bad in (True, -1, 1.0, "8", 1 << 63):
            with patch.object(transport, "_verified_executable_bytes") as launch:
                with self.assertRaises(route.HIARustByteDagRejected):
                    self.invoke(wire(source), "allocate_release", [3], limit=bad)
                launch.assert_not_called()
        bad_policies = ('{"max_live_heap_bytes":8,"max_live_heap_bytes":8}',
                        '{"max_live_heap_bytes":8.0}', '{"max_live_heap_bytes":true}',
                        '{"max_live_heap_bytes":8,"trust_caller":true}',
                        '{"max_live_heap_bytes":8}{}', " " * 1025)
        for raw_policy in bad_policies:
            completed = self.process(wire(source), ["--owned-finite-heap", "allocate_release", "[3]", raw_policy])
            self.assertEqual(completed.returncode, 1)
            self.assertEqual(completed.stdout, b"")
        for entry, arguments in (("allocate_release", [True]), ("allocate_release", [-1]),
                                 ("allocate_release", [3, 4]), ("private", [3])):
            self.refuse(source, entry, arguments, code="E_HIA_INPUT")
        source["exports"] = []
        self.refuse(source, "allocate_release", [3], code="E_HIA_INPUT")
        self.refuse(nested_owned(), "inner", [3], code="E_HIA_INPUT")
        source = owned_program()  # legacy profile remains v1..v8; heap profile is v7/v8 only
        self.refuse(source, "allocate_release", [3], code="E_HIA_BUDGET_PROFILE")

    def test_no_python_semantic_modules_are_required_for_admission_or_refusal(self):
        code = """
import sys, json
for name in ('hia_program', 'hia_program_composite', 'hia_program_runtime', 'hia_heap_bound',
             'hia_static_budget', 'hia_source_bridge', 'hia_program_llvm'):
    sys.modules['hepta.' + name] = None
from hepta.hia_rust_byte_dag import execute_rust_byte_dag
result = execute_rust_byte_dag(sys.stdin.buffer.read(), 'entry', [], sys.argv[1],
    executable_sha256=sys.argv[2], static_policy={
        'max_allocator_interactions': 1000, 'max_vm_ticks': 1000, 'max_call_depth': 64},
    max_static_live_heap_bytes=19)
print(json.dumps(result, sort_keys=True))
"""
        started = time.monotonic_ns()
        completed = subprocess.run([sys.executable, "-B", "-c", code, str(self.executable), self.digest],
            cwd=native.ROOT, input=wire(nested_owned()), capture_output=True, timeout=30)
        type(self).isolated_children.append({"test": self.id(), "driver": code,
            "input": nested_owned(), "rust_executable_sha256": self.digest,
            "returncode": completed.returncode, "stdout": completed.stdout.decode(),
            "stderr": completed.stderr.decode(), "outer_wall_ns": time.monotonic_ns() - started})
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        self.assertEqual(completed.stderr, b"")
        report = json.loads(completed.stdout)["rust_report"]
        self.assertEqual(report["heap_bound"]["peak_bound_bytes"], 19)
        self.assertEqual(report["runtime"]["execution"]["values"], [9])
        with patch("hepta.hia_program.verify_program", side_effect=AssertionError("Python forbidden")), \
             patch("hepta.hia_heap_bound.qualify_finite_entry_live_heap_budget", side_effect=AssertionError("Python forbidden")), \
             patch("hepta.hia_program_runtime.execute_program", side_effect=AssertionError("Python forbidden")):
            self.invoke(wire(nested_owned()), "entry", [], limit=19)
            bad = nested_owned()
            bad["functions"][-1]["blocks"][0]["ops"].pop()
            with self.assertRaisesRegex(route.HIARustByteDagRejected, "Rust rejected"):
                self.invoke(wire(bad), "entry", [], limit=19)

    def test_rehashed_replay_wrong_bounds_policies_arguments_and_authority_reject(self):
        raw = wire(interval_program())
        captured = self.invoke(raw, "entry", [], limit=100)
        variants = []
        for path, value in ((["heap_bound", "peak_bound_bytes"], 91),
                            (["heap_bound", "limit_bytes"], 101),
                            (["heap_bound", "arguments"], [1]),
                            (["heap_bound", "static_budget_sha256"], "0" * 64),
                            (["heap_bound", "max_call_depth"], 1),
                            (["heap_bound", "claims", "native_execution_authorized"], True),
                            (["heap_bound", "claims", "execution_used_to_establish_bound"], True),
                            (["heap_bound", "analysis_work", "contexts"], True),
                            (["heap_bound", "analysis_work", "max_contexts"], 1025),
                            (["heap_bound", "analysis_work", "transfer_steps"], 32769),
                            (["claims", "successful_return_or_cleanup_guaranteed"], True),
                            (["profile"], route.PROFILE)):
            bad = deepcopy(captured)
            target = bad
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = value
            variants.append(bad)
        bad = deepcopy(captured)
        bad["request"]["heap_policy"]["max_live_heap_bytes"] = 101
        bad["request_sha256"] = sha256(wire(bad["request"])).hexdigest()
        variants.append(bad)
        for bad in variants:
            with patch.object(transport, "_run_pinned_shadow", return_value=(wire(bad) + b"\n", b"", 0)):
                with self.assertRaises(route.HIARustByteDagRejected):
                    route.execute_rust_byte_dag(raw, "entry", [], self.executable,
                        executable_sha256=self.digest, static_policy=MAX_LIMITS,
                        max_static_live_heap_bytes=100)


if __name__ == "__main__":
    unittest.main()
