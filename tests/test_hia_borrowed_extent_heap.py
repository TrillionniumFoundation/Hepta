"""Caller-derived borrowed extents: admission, independent Rust, native ledger.

The new v3 receipt is opt-in and proves requested payload for one invocation.
Actual Rust parses normalized Core itself; native observations do not certify
native RSS, VM fuel enforcement, foreign allocators or backend refinement.
"""
from contextlib import nullcontext
from copy import deepcopy
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

from hepta.hia_heap_bound import (
    HIAHeapBoundRejected, qualify_finite_entry_live_heap_budget,
    qualify_finite_entry_live_heap_budget_v8,
    qualify_finite_entry_live_heap_budget_v8_with_borrowed_extents,
)
from hepta.hia_program import HIAProgramRejected, verify_program
from hepta.hia_program_runtime import execute_program
from tests.test_hia_program import b, branch, c, f, i, jump, m, ret
from tests.test_hia_finite_v8_heap import mixed_transfer_program, asymmetric_return_program, observe
from tests.test_hia_partial_finite_bounds import borrowed_owned
from tests.test_hia_composite_returned_loans import pair_program, task_program, expected
from tests import test_hia_rust_owned_cfg as cfg
from tests import test_hia_rust_returned_loans as rust_returns

ROOT = Path(__file__).resolve().parents[1]
CLANG = os.environ.get("CLANG") or shutil.which("clang")
EVIDENCE = os.environ.get("HEPTA_BORROWED_EXTENT_EVIDENCE_DIR")


def retain(name, value):
    if EVIDENCE:
        target = Path(EVIDENCE) / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")


def qualify(source, entry="entry", arguments=(), limit=1024):
    return qualify_finite_entry_live_heap_budget_v8_with_borrowed_extents(
        source, entry, arguments, max_live_heap_bytes=limit)


def baseline_program():
    source = borrowed_owned()
    source["schema"] = "hepta.hia.program.v8"
    source["functions"][0]["blocks"][0]["ops"][2]["args"] = ["ignored"]
    return source


def borrowed_exchange_program(mode="read", extent=11):
    """Three owners, nested returned view, replacement/error/cancel cleanup.

    The callee no longer receives a scalar replacement size. It derives the
    request exclusively from a nested returned loan after a CFG edge rename.
    """
    source = mixed_transfer_program()
    exchange = source["functions"][2]
    exchange["params"].pop(2)
    exchange["blocks"][0]["params"].pop(2)
    exchange["blocks"][0]["term"]["else"]["args"].remove("replacement")
    work = exchange["blocks"][2]
    work["params"].pop()
    work["ops"][0]["args"] = ["borrowed_length"]
    work["ops"].insert(0, i("buffer.len", ["work_child"], [("borrowed_length", "usize")]))
    entry = source["functions"][-1]
    entry["params"].pop(0)
    entry["blocks"][0]["params"].pop(0)
    ops = entry["blocks"][0]["ops"]
    next(op for op in ops if op["op"] == "call")["args"].remove("requested")
    next(op for op in ops if op["op"] == "const" and op["out"][0]["name"] == "three")["attrs"]["value"] = extent
    ops[:0] = [c("unrelated_size", "usize", 3),
               i("buffer.new", ["unrelated_size"], [("unrelated", "buffer")])]
    ops.append(i("owner.drop", ["unrelated"]))
    if mode == "mut":
        source = json.loads(json.dumps(source).replace('"readbuf"', '"mutbuf"')
                            .replace('"borrow.read"', '"borrow.mut"'))
    return source


def reordered_extent_program():
    source = asymmetric_return_program()
    helper = source["functions"][0]
    helper["effects"] = ["alloc"]
    helper["blocks"][0]["ops"] = [
        i("buffer.len", ["right"], [("borrowed_size", "usize")]),
        i("buffer.try_new", ["borrowed_size"], [("temporary", "buffer"), ("ok", "bool")]),
        i("owner.drop", ["temporary"]),
    ]
    ops = source["functions"][-1]["blocks"][0]["ops"]
    at = next(n for n, op in enumerate(ops) if op["op"] == "buffer.try_new")
    ops[at]["args"] = ["doubled_extent"]
    ops[at:at] = [c("two", "usize", 2),
        i("int.mul.checked", ["extent", "two"], [("doubled_extent", "usize")])]
    return source


def context_program():
    helper = f("copy_extent", [("view", "readbuf"), ("old", "buffer")],
               ["buffer", "usize"], ["alloc"], [
        b("start", [("view", "readbuf"), ("old", "buffer")], [
            i("buffer.len", ["view"], [("length", "usize")]),
            i("buffer.try_new", ["length"], [("new", "buffer"), ("ok", "bool")]),
            i("owner.drop", ["old"]),
        ], ret("new", "length"))])
    ops = [c("three", "usize", 3), c("eleven", "usize", 11), c("four", "usize", 4),
        i("buffer.new", ["three"], [("small", "buffer")]),
        i("buffer.new", ["eleven"], [("large", "buffer")]),
        i("borrow.read", ["small"], [("left", "readbuf")]),
        i("borrow.read", ["large"], [("right", "readbuf")])]
    for n, view in enumerate(("left", "right", "left")):
        ops += [i("buffer.new", ["four"], [(f"old{n}", "buffer")]),
            i("call", [view, f"old{n}"], [(f"new{n}", "buffer"), (f"length{n}", "usize")], function="copy_extent"),
            i("owner.drop", [f"new{n}"])]
    ops += [i("loan.end", ["left"]), i("loan.end", ["right"]),
        i("owner.drop", ["small"]), i("owner.drop", ["large"]),
        i("int.add.checked", ["length0", "length1"], [("sum", "usize")]),
        i("int.add.checked", ["sum", "length2"], [("total", "usize")]),
        i("int.cast", ["total"], [("answer", "u8")], mode="checked")]
    source = m(helper, f("entry", [], ["u8"], ["alloc", "trap"], [b("start", [], ops, ret("answer"))]))
    source.update(schema="hepta.hia.program.v8", exports=["entry"])
    return source


def aliased_extent_program():
    source = baseline_program()
    source["functions"][0]["blocks"][0]["ops"] = [
        i("buffer.len", ["left"], [("a", "usize")]),
        i("buffer.len", ["right"], [("z", "usize")]),
        i("int.add.checked", ["a", "z"], [("sum", "usize")]),
        i("buffer.try_new", ["sum"], [("scratch", "buffer"), ("ok", "bool")]),
        i("owner.drop", ["scratch"]),
    ]
    entry = source["functions"][-1]
    entry["returns"] = ["u8"]
    entry["blocks"][0]["ops"].append(c("answer", "u8", 7))
    entry["blocks"][0]["term"] = ret("answer")
    return source


def joined_extent_program():
    """A helper may locally select either external root without returning it."""
    params = [("left", "readbuf"), ("right", "readbuf"), ("which", "bool")]
    helper = f("choose", params, [], ["alloc"], [
        b("start", params, [], branch("which", ("joined", "left"), ("joined", "right"))),
        b("joined", [("selected", "readbuf")], [
            i("buffer.len", ["selected"], [("length", "usize")]),
            i("buffer.try_new", ["length"], [("scratch", "buffer"), ("ok", "bool")]),
            i("owner.drop", ["scratch"]),
        ], ret())])
    entry = f("entry", [("which", "bool")], ["u8"], ["alloc", "trap"], [
        b("start", [("which", "bool")], [
            c("three", "usize", 3), c("eleven", "usize", 11),
            i("buffer.new", ["three"], [("small", "buffer")]),
            i("buffer.new", ["eleven"], [("large", "buffer")]),
            i("borrow.read", ["small"], [("left", "readbuf")]),
            i("borrow.read", ["large"], [("right", "readbuf")]),
            i("call", ["left", "right", "which"], function="choose"),
            i("loan.end", ["left"]), i("loan.end", ["right"]),
            i("owner.drop", ["small"]), i("owner.drop", ["large"]), c("answer", "u8", 7),
        ], ret("answer"))])
    source = m(helper, entry)
    source.update(schema="hepta.hia.program.v8", exports=["entry"])
    return source


def interval_program(extent=8):
    """Empty-owner failure must permit a later 100B request, not just 92B."""
    helper = f("length", [("view", "readbuf")], ["usize"], [], [
        b("start", [("view", "readbuf")], [
            i("buffer.len", ["view"], [("size", "usize")]),
        ], ret("size"))])
    entry = f("entry", [], ["u8"], ["alloc", "trap"], [b("start", [], [
        c("eight", "usize", extent), c("hundred", "usize", 100),
        i("buffer.try_new", ["eight"], [("owner", "buffer"), ("ok", "bool")]),
        i("borrow.read", ["owner"], [("view", "readbuf")]),
        i("call", ["view"], [("observed", "usize")], function="length"),
        i("loan.end", ["view"]), i("owner.drop", ["owner"]),
        i("int.sub.checked", ["hundred", "observed"], [("request", "usize")]),
        i("buffer.try_new", ["request"], [("later", "buffer"), ("later_ok", "bool")]),
        i("owner.drop", ["later"]),
        i("int.cast", ["request"], [("answer", "u8")], mode="checked"),
    ], ret("answer"))])
    source = m(helper, entry)
    source.update(schema="hepta.hia.program.v8", exports=["entry"])
    return source


def borrowed_pair_program(mode="read"):
    source = pair_program(mode)
    helper, relay = source["functions"][:2]
    helper["effects"] = relay["effects"] = ["alloc"]
    helper["blocks"][1]["ops"] += [
        i("buffer.len", ["right_child"], [("scratch_size", "usize")]),
        i("buffer.try_new", ["scratch_size"], [("scratch", "buffer"), ("scratch_ok", "bool")]),
        i("owner.drop", ["scratch"]),
    ]
    second = source["functions"][-1]["blocks"][2]["ops"]
    second[0]["args"] = ["right_size"]
    second.insert(0, c("right_size", "usize", 11))
    return source


def borrowed_task_program():
    source = task_program()
    helper = next(fn for fn in source["functions"] if fn["name"] == "task_view")
    helper["effects"] = ["alloc"]
    helper["blocks"][0]["ops"] += [
        i("buffer.len", ["child"], [("scratch_size", "usize")]),
        i("buffer.try_new", ["scratch_size"], [("scratch", "buffer"), ("scratch_ok", "bool")]),
        i("owner.drop", ["scratch"]),
    ]
    return source


def invalid_programs():
    source = borrowed_exchange_program()
    source["functions"][2]["return_loans"][1] = "incoming"
    yield "owned_origin", source
    source = borrowed_exchange_program()
    ops = source["functions"][-1]["blocks"][0]["ops"]
    at = next(n for n, op in enumerate(ops) if op["op"] == "call") + 1
    ops.insert(at, i("loan.end", ["parent"]))
    yield "early_parent_end", source
    source = reordered_extent_program()
    source = json.loads(json.dumps(source).replace('"readbuf"', '"mutbuf"')
                        .replace('"borrow.read"', '"borrow.mut"'))
    call = next(op for op in source["functions"][-1]["blocks"][0]["ops"] if op["op"] == "call")
    call["args"][2] = call["args"][1]
    yield "aliased_mutable_actuals", source
    source = borrowed_exchange_program()
    hidden = deepcopy(source["functions"][0])
    hidden["name"] = "hidden"
    hidden["return_loans"] = [None]
    source["functions"].append(hidden)
    yield "hidden_invalid_origin", source
    source = baseline_program()
    source["functions"][0]["params"][0]["extent_bytes"] = 9
    yield "forged_parameter_extent", source
    source = joined_extent_program()
    source["functions"][0]["returns"] = ["readbuf"]
    source["functions"][0]["return_loans"] = ["left"]
    source["functions"][0]["blocks"][1]["term"] = ret("selected")
    ops = source["functions"][1]["blocks"][0]["ops"]
    call = next(op for op in ops if op["op"] == "call")
    call["out"] = [{"name": "child", "type": "readbuf"}]
    ops.insert(ops.index(call) + 1, i("loan.end", ["child"]))
    yield "inconsistent_return_origin_at_join", source


class BorrowedExtentHeapTests(unittest.TestCase):
    def assert_bound(self, bound, observed):
        self.assertLessEqual(observed["resources"]["peak_bytes"], bound["peak_bound_bytes"])
        self.assertLessEqual(observed["steps"], bound["max_vm_ticks"])
        self.assertLessEqual(observed["resources"]["allocation_attempts"] + observed["resources"]["frees"],
                             bound["max_allocator_interactions"])

    def test_explicit_v3_closes_recorded_gap_and_legacy_apis_stay_strict(self):
        source = baseline_program()
        core = verify_program(source)
        bound = qualify(core, limit=22)
        self.assertEqual(bound["schema"], "hepta.hia.finite-entry-live-heap-admission.v3")
        self.assertEqual(bound["profile"], "acyclic-byte-owner-transfer-caller-borrowed-extents-v8")
        self.assertEqual(bound["peak_bound_bytes"], 22)
        self.assertEqual(bound["core_sha256"], core.sha256)
        self.assertEqual(bound["input_sha256"], core.input_sha256)
        self.assertFalse(bound["claims"]["borrowed_lengths_assumed_exact"])
        self.assertFalse(bound["claims"]["caller_supplied_resource_extents_trusted"])
        self.assertFalse(bound["claims"]["process_rss_or_native_stack_bytes_bounded"])
        unsigned = dict(bound); unsigned.pop("sha256")
        self.assertEqual(bound["sha256"], sha256(json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()).hexdigest())
        observed = execute_program(core, "entry", [])
        self.assertEqual(observed["resources"]["peak_bytes"], 22)
        self.assert_bound(bound, observed)
        with self.assertRaisesRegex(HIAHeapBoundRejected, "E_HIA_BUDGET_EXCEEDED"):
            qualify(core, limit=21)
        with self.assertRaisesRegex(HIAHeapBoundRejected, "allocator extent"):
            qualify_finite_entry_live_heap_budget_v8(core, "entry", [], max_live_heap_bytes=22)
        source["schema"] = "hepta.hia.program.v7"
        with self.assertRaisesRegex(HIAHeapBoundRejected, "allocator extent"):
            qualify_finite_entry_live_heap_budget(source, "entry", [], max_live_heap_bytes=22)
        old = qualify_finite_entry_live_heap_budget_v8(mixed_transfer_program(), "entry", [9, False], max_live_heap_bytes=16)
        self.assertEqual(old["schema"], "hepta.hia.finite-entry-live-heap-admission.v2")
        self.assertNotIn("borrowed_extents_in_call_context_key", old["claims"])
        retain("admission-baseline.json", {"bound": bound, "python": observed, "legacy_v2": old})

    def test_nested_read_mut_borrows_owner_returns_failure_and_cancel(self):
        records = []
        for mode in ("read", "mut"):
            source = borrowed_exchange_program(mode)
            for cancel in (False, True):
                bound = qualify(source, arguments=[cancel], limit=36)
                self.assertEqual(bound["peak_bound_bytes"], 36)
                for fail in (None, 1, 2, 3, 4, 5):
                    observed = observe(source, "entry", [cancel], allocation_fail_at=fail)
                    self.assert_bound(bound, observed)
                    if observed["status"] == "returned":
                        self.assertEqual(observed["values"], [15 if cancel or fail == 4 else 22])
                        self.assertEqual(observed["resources"]["live_bytes"], 0)
                        self.assertEqual(observed["resources"]["live_local_loans"], 0)
                    records.append({"mode": mode, "cancel": cancel, "fail_at": fail,
                                    "bound": bound, "python": observed})
                with self.assertRaisesRegex(HIAHeapBoundRejected, "E_HIA_BUDGET_EXCEEDED"):
                    qualify(source, arguments=[cancel], limit=35)
        retain("admission-exchange.json", records)

    def test_different_borrowed_extents_are_distinct_memo_contexts(self):
        source = context_program()
        bound = qualify(source, limit=29)
        self.assertEqual(bound["analysis_work"]["contexts"], 3)  # entry + 3B + 11B
        self.assertEqual(bound["peak_bound_bytes"], 29)
        observed = execute_program(source, "entry", [])
        self.assertEqual(observed["values"], [17])
        self.assertEqual(observed["resources"]["peak_bytes"], 29)
        self.assert_bound(bound, observed)
        with self.assertRaisesRegex(HIAHeapBoundRejected, "E_HIA_BUDGET_EXCEEDED"):
            qualify(source, limit=28)

    def test_shared_alias_payload_is_charged_once_and_reordered_origins_keep_size(self):
        for source, peak, result in ((aliased_extent_program(), 31, 7), (reordered_extent_program(), 36, 11)):
            bound = qualify(source, limit=peak)
            observed = execute_program(source, "entry", [])
            self.assertEqual(bound["peak_bound_bytes"], peak)
            self.assertEqual(observed["resources"]["peak_bytes"], peak)
            self.assertEqual(observed["values"], [result])
            self.assert_bound(bound, observed)

    def test_external_root_cfg_join_keeps_maximum_extent_without_return_authority(self):
        source = joined_extent_program()
        for which in (False, True):
            bound = qualify(source, arguments=[which], limit=25)
            self.assertEqual(bound["peak_bound_bytes"], 25)
            observed = execute_program(source, "entry", [which])
            self.assertEqual(observed["resources"]["peak_bytes"], 17 if which else 25)
            self.assert_bound(bound, observed)

    def test_fallible_and_zero_length_are_intervals_never_assumed_maxima(self):
        records = []
        for extent in (0, 8):
            source = interval_program(extent)
            bound = qualify(source, limit=100)
            self.assertEqual(bound["peak_bound_bytes"], 100)
            for fail in (None, 1, 2):
                observed = execute_program(source, "entry", [], allocation_fail_at=fail)
                self.assertEqual(observed["values"], [100 if extent == 0 or fail == 1 else 92])
                self.assert_bound(bound, observed)
                records.append({"extent": extent, "failure": fail, "bound": bound, "python": observed})
        self.assertEqual(records[4]["python"]["resources"]["peak_bytes"], 100)
        retain("admission-intervals.json", records)

    def test_nominal_partial_composite_and_tasks_use_existing_normalized_contract(self):
        for mode in ("read", "mut"):
            source = borrowed_pair_program(mode)
            core = verify_program(source)
            self.assertEqual(core.as_dict()["schema"], "hepta.hia.program.v8")
            for condition in (False, True):
                bound = qualify(core, "probe", [3, 37, condition], limit=25)
                self.assertEqual(bound["peak_bound_bytes"], 25)
                for fail in (None, 1, 2, 3):
                    observed = execute_program(core, "probe", [3, 37, condition], allocation_fail_at=fail)
                    self.assert_bound(bound, observed)
                    self.assertEqual(observed["values"], [241 if fail == 1 else 242 if fail == 2 else expected(mode, 37)])
                    self.assertEqual(observed["resources"]["live_owners"], 0)
                    self.assertEqual(observed["resources"]["live_local_loans"], 0)
        core = verify_program(borrowed_task_program())
        for mode in (0, 1, 2):
            bound = qualify(core, "task_probe", [3, mode], limit=6)
            self.assertEqual(bound["peak_bound_bytes"], 6)
            for fail in (None, 1, 2, 3):
                observed = execute_program(core, "task_probe", [3, mode], allocation_fail_at=fail)
                self.assert_bound(bound, observed)
                self.assertEqual(observed["resources"]["live_owners"], 0)
                self.assertEqual(observed["resources"]["live_local_loans"], 0)

    def test_bad_origins_aliases_hidden_helpers_and_extent_annotations_reject_first(self):
        records = []
        for name, source in invalid_programs():
            with self.subTest(case=name):
                # The hidden-invalid fixture's public entry precedes its
                # deliberately malformed uncalled helper.
                entry = next(fn for fn in source["functions"] if fn["name"] == "entry")
                arguments = [False for _ in entry["params"]]
                codes = []
                for _ in range(2):
                    with self.assertRaises(HIAProgramRejected) as error:
                        qualify(source, arguments=arguments, limit=0)
                    codes.append(error.exception.code)
                self.assertEqual(codes[0], codes[1])
                records.append({"case": name, "source": source, "codes": codes})
        retain("canonical-refusals.json", records)

    def test_public_resource_promises_unknown_lengths_and_uncertified_graphs_refuse(self):
        source = borrowed_exchange_program()
        for entry, arguments in (("exchange", [4, {"extent": 11}, False]),
                                 ("entry", [{"extent": 11}]), ("entry", [1]), ("entry", [])):
            with self.subTest(entry=entry, arguments=arguments), self.assertRaisesRegex(HIAHeapBoundRejected, "E_HIA_BUDGET_INPUT"):
                qualify(source, entry, arguments)
        unknown = baseline_program()
        ops = unknown["functions"][0]["blocks"][0]["ops"]
        ops[:0] = [c("zero", "usize", 0), i("buffer.load", ["left", "zero"], [("byte", "u8")]),
                   i("int.cast", ["byte"], [("unproved_size", "usize")], mode="checked")]
        next(op for op in ops if op["op"] == "buffer.new")["args"] = ["unproved_size"]
        verify_program(unknown)
        with self.assertRaisesRegex(HIAHeapBoundRejected, "allocator extent"):
            qualify(unknown)
        for kind in ("cfg", "calls", "chain"):
            source = borrowed_exchange_program()
            hidden = (f("hidden", [], [], [], [b("start", [], [], jump("loop")), b("loop", [], [], jump("loop"))])
                if kind == "cfg" else f("hidden", [], [], [], [b("start", [], [i("call", function="hidden")], ret())])
                if kind == "calls" else f("hidden", [("value", "chain")], [], ["alloc"], [
                    b("start", [("value", "chain")], [i("owner.drop", ["value"])], ret())]))
            source["functions"].append(hidden)
            with self.subTest(kind=kind), self.assertRaises(HIAHeapBoundRejected):
                qualify(source, arguments=[False])
        for cap in ("_FINITE_MAX_CONTEXTS", "_FINITE_MAX_TRANSFER_STEPS", "_FINITE_MAX_ANALYSIS_DEPTH"):
            with self.subTest(cap=cap), patch("hepta.hia_heap_bound." + cap, 1):
                with self.assertRaisesRegex(HIAHeapBoundRejected, "E_HIA_BUDGET_LIMIT"):
                    qualify(context_program())


@unittest.skipUnless(shutil.which("cargo"), "Actual Cargo required: borrowed-extent Rust execution NOT qualified")
class BorrowedExtentHeapRust(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cfg.RustByteOwnerCfgParity.setUpClass.__func__(cls)
        cls.rejections, cls.bound_observations = [], []

    @classmethod
    def tearDownClass(cls):
        retain("rust.json", {"build": cls.build,
            "executable_sha256": sha256(Path(cls.executable).read_bytes()).hexdigest(),
            "programs": cls.sources, "observations": cls.observations,
            "bound_v2_observations": cls.bound_observations, "refusals": cls.rejections})
        print(f"Borrowed extent Python/Rust observations: {len(cls.observations)}; "
              f"bound v2: {len(cls.bound_observations)}; negative programs: {len(cls.rejections)}")

    raw_run = cfg.RustByteOwnerCfgParity.raw_run
    parity = cfg.RustByteOwnerCfgParity.parity
    shadow = rust_returns.RustReturnedLoansParity.shadow
    wire = staticmethod(rust_returns.RustReturnedLoansParity.wire)
    reject_both = rust_returns.RustReturnedLoansParity.reject_both
    execution_profile = "bounded-cfg-byte-owner-loan-returns-v4"

    def test_actual_rust_nested_borrows_fail_cancel_and_every_step_stop(self):
        for mode in ("read", "mut"):
            source = borrowed_exchange_program(mode)
            for cancel in (False, True):
                bound = qualify(source, arguments=[cancel], limit=36)
                for fail in (None, 1, 2, 3, 4, 5):
                    observed = self.parity(source, "entry", [cancel], fail=fail)
                    self.assertLessEqual(observed["resources"]["peak_bytes"], bound["peak_bound_bytes"])
                completed = self.parity(source, "entry", [cancel])
                for steps in range(1, completed["steps"] + 1):
                    stopped = self.parity(source, "entry", [cancel], steps=steps)
                    self.assertLessEqual(stopped["resources"]["peak_bytes"], bound["peak_bound_bytes"])
            for heap in (0, 2, 3, 13, 17, 18, 28, 35, 36):
                observed = self.parity(source, "entry", [False], heap=heap)
                self.assertEqual(observed["status"], "returned" if heap == 36 else "budget_exceeded")

    def test_actual_rust_alias_cache_origin_and_fallible_interval_cases(self):
        for source, attempts in ((aliased_extent_program(), 3), (context_program(), 8),
                (reordered_extent_program(), 5), (interval_program(), 2), (interval_program(0), 1)):
            bound = qualify(source)
            for fail in (None, *range(1, attempts + 1)):
                observed = self.parity(source, "entry", [], fail=fail)
                self.assertLessEqual(observed["resources"]["peak_bytes"], bound["peak_bound_bytes"])
        source = joined_extent_program()
        for which in (False, True):
            bound = qualify(source, arguments=[which], limit=25)
            for fail in (None, 1, 2, 3):
                observed = self.parity(source, "entry", [which], fail=fail)
                self.assertLessEqual(observed["resources"]["peak_bytes"], bound["peak_bound_bytes"])

    def test_actual_rust_partial_fields_tasks_and_closed_loans_before_cancel(self):
        for mode in ("read", "mut"):
            core = verify_program(borrowed_pair_program(mode))
            for condition in (False, True):
                bound = qualify(core, "probe", [3, 37, condition], limit=25)
                for fail in (None, 1, 2, 3):
                    row = self.parity(core, "probe", [3, 37, condition], fail=fail)
                    self.assertLessEqual(row["resources"]["peak_bytes"], bound["peak_bound_bytes"])
        core = verify_program(borrowed_task_program())
        for mode in (0, 1, 2):
            bound = qualify(core, "task_probe", [3, mode], limit=6)
            for fail in (None, 1, 2, 3):
                row = self.parity(core, "task_probe", [3, mode], fail=fail)
                self.assertLessEqual(row["resources"]["peak_bytes"], bound["peak_bound_bytes"])
            full = self.parity(core, "task_probe", [3, mode])
            for steps in range(1, full["steps"] + 1):
                self.parity(core, "task_probe", [3, mode], steps=steps)

    def test_actual_rust_bound_transport_call_stops_preserve_live_resources(self):
        from hepta.hia_rust_crosscheck import crosscheck_rust_execution_v2
        core = verify_program(borrowed_exchange_program())
        bound = qualify(core, arguments=[False], limit=36)
        digest = sha256(Path(self.executable).read_bytes()).hexdigest()
        self.assertEqual(bound["max_call_depth"], 4)
        for depth in (1, 2, 3, 4):
            row = crosscheck_rust_execution_v2(core, "entry", [False], self.executable,
                executable_sha256=digest, max_call_depth=depth, max_heap_bytes=36,
                max_steps=bound["max_vm_ticks"])
            type(self).bound_observations.append(row)
            observed = row["rust_report"]
            self.assertEqual(observed["status"], "returned" if depth == 4 else "budget_exceeded")
            if depth < 4:
                self.assertEqual(observed["error"], {"code": "calls"})
                self.assertEqual(observed["resources"]["live_bytes"], 18)
                self.assertEqual(observed["resources"]["frees"], 0)

    def test_invalid_resources_reject_in_both_parsers_even_with_immediate_stop(self):
        for name, source in invalid_programs():
            with self.subTest(case=name):
                self.reject_both(source)


@unittest.skipUnless(CLANG and sys.platform == "linux", "Actual Linux Clang required: borrowed-extent native observation NOT qualified")
class BorrowedExtentHeapNative(unittest.TestCase):
    def test_actual_native_allocator_observes_borrow_contexts_failure_and_cleanup(self):
        from hepta.hia_program_llvm import build_program_native
        specs = [
            ("exchange_read", borrowed_exchange_program(), "entry", "_Bool", [(False,), (True,)], [0, 4, 5], 36),
            ("exchange_mut", borrowed_exchange_program("mut"), "entry", "_Bool", [(False,), (True,)], [0, 4, 5], 36),
            ("cache", context_program(), "entry", "", [()], [0, 4, 6, 8], 29),
            ("aliases", aliased_extent_program(), "entry", "", [()], [0, 3], 31),
            ("cfg_join", joined_extent_program(), "entry", "_Bool", [(False,), (True,)], [0, 3], 25),
            ("interval", interval_program(), "entry", "", [()], [0, 1, 2], 100),
            ("partial_read", borrowed_pair_program(), "probe", "uint64_t,uint8_t,_Bool", [(3, 37, False), (3, 37, True)], [0, 1, 2, 3], 25),
            ("partial_mut", borrowed_pair_program("mut"), "probe", "uint64_t,uint8_t,_Bool", [(3, 37, False), (3, 37, True)], [0, 1, 2, 3], 25),
            ("tasks", borrowed_task_program(), "task_probe", "uint64_t,uint8_t", [(3, 0), (3, 1), (3, 2)], [0, 1, 2, 3], 6),
        ]
        prefix = (ROOT / "examples/hia_recursive_chain/allocator_driver.c").read_text().split("int main(", 1)[0]
        for name, source, entry, types, arguments, failures, limit in specs:
            if EVIDENCE:
                Path(EVIDENCE).mkdir(parents=True, exist_ok=True)
            directory_context = (nullcontext(tempfile.mkdtemp(prefix=name + "-", dir=EVIDENCE))
                                 if EVIDENCE else tempfile.TemporaryDirectory())
            with self.subTest(case=name), directory_context as temporary:
                directory = Path(temporary)
                obj, driver, exe = directory / "core.o", directory / "observer.c", directory / "observer"
                build = build_program_native(source, output=obj, clang=CLANG, kind="object")
                self.assertTrue(build["ok"], build)
                call = ",".join(f"strtoull(argv[{n + 2}],NULL,10)" for n in range(len(arguments[0])))
                text = prefix + f"\nuint8_t {entry}({types or 'void'});\n"
                text += "int main(int argc, char **argv) {\n"
                text += f"if (argc != {len(arguments[0]) + 2}) return 64;\n"
                text += f"refuse_at = strtoull(argv[1],NULL,10); uint8_t value = {entry}({call});\n"
                text += r'''
    printf("{\"value\":%u,\"attempts\":%llu,\"allocations\":%llu,\"frees\":%llu,"
           "\"live_bytes\":%llu,\"peak_bytes\":%llu,\"bad_frees\":%llu,\"null_frees\":%llu}\n",
           value, (unsigned long long)attempts, (unsigned long long)allocations,
           (unsigned long long)frees, (unsigned long long)live_bytes, (unsigned long long)peak_bytes,
           (unsigned long long)bad_frees, (unsigned long long)null_frees);
    return live_bytes || bad_frees || null_frees ? 65 : 0;
}
'''
                driver.write_text(text)
                linked = subprocess.run([CLANG, "-O2", "-Wl,--wrap=malloc", "-Wl,--wrap=calloc", "-Wl,--wrap=free",
                    str(driver), str(obj), "-o", str(exe)], capture_output=True, timeout=30)
                self.assertEqual(linked.returncode, 0, linked.stderr.decode())
                records = {"core": verify_program(source).as_dict(), "build": build,
                    "link": {"argv": linked.args, "returncode": linked.returncode,
                             "stdout": linked.stdout.decode(), "stderr": linked.stderr.decode()},
                    "files": {str(path): sha256(path.read_bytes()).hexdigest() for path in (obj, driver, exe)},
                    "observations": []}
                for args in arguments:
                    bound = qualify(source, entry, args, limit=limit)
                    for failure in failures:
                        actual = subprocess.run([str(exe), str(failure), *(str(int(value)) for value in args)],
                                                capture_output=True, timeout=10)
                        self.assertEqual(actual.returncode, 0, actual.stderr.decode())
                        native = json.loads(actual.stdout)
                        python = execute_program(source, entry, args, allocation_fail_at=failure or None)
                        self.assertEqual(native["value"], python["values"][0])
                        for field in ("allocation_attempts", "allocations", "frees", "live_bytes", "peak_bytes"):
                            self.assertEqual(native["attempts" if field == "allocation_attempts" else field], python["resources"][field])
                        self.assertLessEqual(native["peak_bytes"], bound["peak_bound_bytes"])
                        records["observations"].append({"arguments": list(args), "failure": failure,
                            "bound": bound, "argv": actual.args, "returncode": actual.returncode,
                            "stdout": actual.stdout.decode(), "stderr": actual.stderr.decode(), "python": python})
                retain("native-" + name + ".json", records)


if __name__ == "__main__":
    unittest.main()
