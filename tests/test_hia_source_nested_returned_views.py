"""Nested returned byte origins retain the actual linear v8 capability chain."""
from __future__ import annotations

import copy
import ctypes
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from hepta.ast import HeptaError
from hepta.checker import check
from hepta.hia_program import HIAProgramRejected, verify_program
from hepta.hia_program_runtime import HIAProgramBudgetExceeded, execute_program
from hepta.hia_program_source import HIAProgramSourceRejected, lower_source
from hepta.hia_routes import admit_route
from hepta.hia_schema import SCHEMA, SCHEMA_V8
from hepta.parser import parse
from hepta.resource_ir import verify_resource_ir
from hepta.resource_lowering import lower_resource_ir
import tests.test_hia_source_returned_local_views as previous

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "examples/hia_program/source_nested_returned_views.hepta").read_text()
CLANG = os.environ.get("CLANG") or shutil.which("clang")
FORMER_REFUSAL = previous.VIEW + previous.SHARE + "fn f(b:read [u8])->u64 effects{}{let v=View{data:read shared(read shared(read b)),tag:7};return v.tag;}"
CONTROL_SOURCE = previous.CONTROL_SOURCE.replace(
    "read shared(read data)", "read shared(read shared(read shared(read data)))")
MUTABLE_CONTROL_SOURCE = previous.MUTABLE_CONTROL_SOURCE.replace(
    "mut edited(mut data)", "mut edited(mut edited(mut edited(mut data)))")
# Allocation 1 owns the result byte; 2/3/4 distinguish prefix/origin/suffix.
ORDER_CASES = ((None, 15, 4, 8), (2, 113, 3, 8), (3, 61, 3, 8), (4, 109, 3, 6))


def cases():
    return [*previous.cases(), ("ordering_case", [], 15), ("stamp", [3], 3)]


def chain(document):
    function = next(fn for fn in document["functions"] if fn["name"] == "probe")
    for block in function["blocks"]:
        calls = [(index, op) for index, op in enumerate(block["ops"])
                 if op["op"] == "call" and op["attrs"]["function"] in {"shared", "edited"}]
        if len(calls) == 3:
            names = [calls[0][1]["args"][0], *[op["out"][0]["name"] for _, op in calls]]
            assert all(op["args"] == [names[index]] for index, (_, op) in enumerate(calls))
            return function, block, calls[-1][0], names
    raise AssertionError("fixture did not emit its actual three-call linear chain")


def balanced_parent_reborrow(*, exclusive=False):
    document = lower_source(MUTABLE_CONTROL_SOURCE if exclusive else CONTROL_SOURCE,
                            core_schema=SCHEMA_V8).as_dict()
    _, block, index, names = chain(document)
    block["ops"][index + 1:index + 1] = [
        {"op": "borrow.read", "args": [names[1]],
         "out": [{"name": "additional_read", "type": "readbuf"}], "attrs": {}},
        {"op": "loan.end", "args": ["additional_read"], "out": [], "attrs": {}},
    ]
    return document


def corruptions():
    original = lower_source(CONTROL_SOURCE, core_schema=SCHEMA_V8).as_dict()
    for label, level in (("end_root_parent_before_descendants", 0),
                         ("end_middle_parent_before_descendants", 1)):
        document = copy.deepcopy(original)
        _, block, index, names = chain(document)
        block["ops"].insert(index + 1, {"op": "loan.end", "args": [names[level]], "out": [], "attrs": {}})
        yield label, document
    document = copy.deepcopy(original)
    _, block, index, _ = chain(document)
    owner = next(param["name"] for param in block["params"] if param["type"] == "buffer")
    block["ops"].insert(index + 1, {"op": "owner.drop", "args": [owner], "out": [], "attrs": {}})
    yield "drop_root_owner_with_live_descendants", document
    yield "reborrow_exclusive_middle_with_live_mutable_child", balanced_parent_reborrow(exclusive=True)
    document = copy.deepcopy(original)
    function, _, _, _ = chain(document)
    cleanup = next(block for block in function["blocks"]
                   if sum(op["op"] == "loan.end" for op in block["ops"]) == 4)
    ends = [index for index, op in enumerate(cleanup["ops"]) if op["op"] == "loan.end"]
    cleanup["ops"].pop(ends[1])
    yield "omit_middle_end_before_ancestor_cleanup", document
    document = copy.deepcopy(original)
    _, block, _, names = chain(document)
    edge = block["term"]["then"]
    left, right = edge["args"].index(names[1]), edge["args"].index(names[2])
    edge["args"][left], edge["args"][right] = edge["args"][right], edge["args"][left]
    yield "swap_intermediate_ancestors_on_one_cfg_edge", document


def refusals():
    view, shared, edit, edited = previous.VIEW, previous.SHARE, previous.EDIT, previous.EDIT_FN
    frozen = "fn frozen(b:mut [u8])->read [u8] from b effects{}{return read b;} "
    return {
        "nested_mode_change": view + shared + frozen + "fn f(b:mut [u8])->u64 effects{}{let v=View{data:read shared(read frozen(mut b)),tag:7};return v.tag;}",
        "outer_mode_change": view + edited + frozen + "fn f(b:mut [u8])->u64 effects{}{let v=View{data:read frozen(mut edited(mut b)),tag:7};return v.tag;}",
        "nested_two_borrowed_formals": view + shared + "fn both(b:read [u8],other:read [u8])->read [u8] from b effects{}{return read b;} fn f(b:read [u8])->u64 effects{}{let v=View{data:read shared(read both(read b,read b)),tag:7};return v.tag;}",
        "nested_borrowed_record_formal": view + shared + "struct Pair{left:Buffer<u8>,right:Buffer<u8>} fn field(p:read Pair)->read [u8] from p effects{}{return read p.left;} fn f(p:read Pair)->u64 effects{}{let v=View{data:read shared(read field(read p)),tag:7};return v.tag;}",
        "nested_local_view_origin": view + shared + "fn f(b:read [u8])->u64 effects{}{let first=View{data:read b,tag:7};let v=View{data:read shared(read shared(read first.data)),tag:7};return v.tag;}",
        "readless_constructor": view + shared + "fn f(b:read [u8])->u64 effects{}{let v=View{data:shared(read shared(read b)),tag:7};return v.tag;}",
        "mutable_missing_drop": edit + edited + "fn f(b:mut [u8])->Unit effects{}{let v=Edit{data:mut edited(mut edited(mut b)),tag:7};}",
        "mutable_copy": edit + edited + "fn f(b:mut [u8])->Unit effects{}{let v=Edit{data:mut edited(mut edited(mut b)),tag:7};let copy=v;drop(move copy);drop(move v);}",
        "mutable_one_branch_drop": edit + edited + "fn f(b:mut [u8],flag:bool)->Unit effects{}{let v=Edit{data:mut edited(mut edited(mut b)),tag:7};if flag{drop(move v);}}",
        "owner_write_with_live_mutable_chain": edit + edited + "fn f()->Unit effects{alloc,block,panic,write}{let mut b=buffer(1);let v=Edit{data:mut edited(mut edited(mut b)),tag:7};b[0]=9;drop(move v);drop(move b);}",
        "owner_drop_with_live_shared_alias": view + shared + "fn f()->u64 effects{alloc,block,panic}{let b=buffer(1);let v=View{data:read shared(read shared(read b)),tag:7};let copy=v;drop(move b);return copy.tag;}",
        "immediate_non_view_nested_argument": shared + "fn f(b:read [u8])->usize effects{}{return len(shared(read shared(read b)));}",
        "standalone_returned_storage": shared + "fn f(b:read [u8])->usize effects{}{let v=shared(read shared(read b));return len(v);}",
        "escaping_view": view + shared + "fn f<'a>(b:read 'a [u8])->View<'a> effects{}{return View{data:read shared(read shared(read b)),tag:7};}",
    }


class HIASourceNestedReturnedViews(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.core = lower_source(SOURCE, core_schema=SCHEMA_V8)
        cls.source_refusals, cls.core_refusals, cls.order_observations = [], [], []

    clean = previous.HIASourceReturnedLocalViews.clean

    def test_checked_call_chains_reuse_existing_v8_core_without_reparse(self):
        for source in (SOURCE, FORMER_REFUSAL):
            ast = parse(source)
            checked = check(ast)
            self.assertTrue(checked.ok, checked.diagnostics)
            self.assertTrue(verify_resource_ir(lower_resource_ir(ast, checked))["ok"])
            lower_source(source, core_schema=SCHEMA_V8)
        with self.assertRaises(HIAProgramSourceRejected):
            lower_source(SOURCE, core_schema=SCHEMA)
        self.assertEqual(self.core.as_dict()["exports"], sorted({entry for entry, _, _ in cases()}))
        self.assertEqual(admit_route("hepta-source", SOURCE, core_schema=SCHEMA_V8).canonical_bytes,
                         self.core.canonical_bytes)
        with patch("hepta.parser.parse", side_effect=AssertionError("Core consumers must not parse source")):
            canonical = verify_program(self.core.canonical_bytes)
            self.clean(execute_program(canonical, "shared_case", [3, 19, 0]), 57)

    def test_copies_moves_field_origins_cfg_loops_and_early_returns_end_deepest_first(self):
        for entry, arguments, expected in cases():
            with self.subTest(entry=entry, arguments=arguments):
                self.clean(execute_program(self.core, entry, arguments), expected)
        for source, expected in ((CONTROL_SOURCE, 8), (MUTABLE_CONTROL_SOURCE, 7)):
            core = lower_source(source, core_schema=SCHEMA_V8)
            function, _, _, _ = chain(core.as_dict())
            cleanup = next(block for block in function["blocks"]
                           if sum(op["op"] == "loan.end" for op in block["ops"]) == 4)
            loans = [p["name"] for p in cleanup["params"] if p["type"] in {"readbuf", "mutbuf"}]
            self.assertEqual([op["args"][0] for op in cleanup["ops"] if op["op"] == "loan.end"], loans[::-1])
            for flag in (0, 1):
                self.clean(execute_program(core, "probe", [flag]), expected)

    def test_scalar_arguments_keep_left_to_right_order_across_nested_origin_and_failures(self):
        function = next(fn for fn in self.core.as_dict()["functions"] if fn["name"] == "ordering_case")
        self.assertEqual([op["attrs"]["function"] for block in function["blocks"] for op in block["ops"]
                          if op["op"] == "call"], ["stamp", "stamped_origin", "stamp", "ordered_origin"])
        for failure, expected, allocations, peak in ORDER_CASES:
            report = execute_program(self.core, "ordering_case", [], allocation_fail_at=failure)
            type(self).order_observations.append({"failure": failure, "report": report})
            self.clean(report, expected)
            self.assertEqual(report["resources"]["allocation_attempts"], 4)
            self.assertEqual(report["resources"]["allocations"], allocations)
            self.assertEqual(report["resources"]["peak_bytes"], peak)

    def test_error_branches_and_every_step_prefix_keep_full_chain_ledger_without_unwind(self):
        self.clean(execute_program(self.core, "failure_case", [7], allocation_fail_at=2), 41)
        self.clean(execute_program(self.core, "shared_case", [7, 99, 0], allocation_fail_at=1), 1001)
        completed = execute_program(self.core, "mutable_case", [2, 91, 1])
        saw_four_live_loans = False
        for limit in range(1, completed["steps"]):
            with self.assertRaises(HIAProgramBudgetExceeded) as caught:
                execute_program(self.core, "mutable_case", [2, 91, 1], max_steps=limit)
            ledger = caught.exception.report["resources"]
            self.assertEqual(ledger["owners_created"] - ledger["owners_dropped"], ledger["live_owners"])
            self.assertEqual(ledger["loans_started"] - ledger["loans_ended"], ledger["live_local_loans"])
            saw_four_live_loans |= ledger["live_local_loans"] >= 4
        self.assertTrue(saw_four_live_loans)

    def test_source_permissions_origins_escapes_and_existing_compile_limits_still_reject(self):
        legal_exclusions = {"nested_mode_change", "outer_mode_change", "nested_two_borrowed_formals",
                            "nested_borrowed_record_formal"}
        for label, source in refusals().items():
            with self.subTest(label=label):
                if label in legal_exclusions:
                    ast = parse(source)
                    checked = check(ast)
                    self.assertTrue(checked.ok, checked.diagnostics)
                    self.assertTrue(verify_resource_ir(lower_resource_ir(ast, checked))["ok"])
                with self.assertRaises((HIAProgramSourceRejected, HIAProgramRejected)) as caught:
                    lower_source(source, core_schema=SCHEMA_V8)
                type(self).source_refusals.append({"name": label, "source": source,
                    "checked_frontend_and_resource_legal": True if label in legal_exclusions else None,
                    "type": type(caught.exception).__name__, "message": str(caught.exception)})
        with self.assertRaisesRegex(HIAProgramSourceRejected, "one MiB limit"):
            lower_source(SOURCE + " " * (1024 * 1024), core_schema=SCHEMA_V8)
        origin = "read b"
        for _ in range(100):
            origin = "read shared(" + origin + ")"
        with self.assertRaises(HeptaError) as caught:
            lower_source(previous.VIEW + previous.SHARE +
                         "fn f(b:read [u8])->u64 effects{}{let v=View{data:" + origin + ",tag:7};return v.tag;}",
                         core_schema=SCHEMA_V8)
        self.assertEqual(caught.exception.diagnostic.code, "E_PARSE_DEPTH")

    def test_primitive_core_refuses_actual_ancestor_order_owner_and_cfg_corruptions(self):
        neighbour = verify_program(balanced_parent_reborrow())
        self.clean(execute_program(neighbour, "probe", [0]), 8)
        for name, document in corruptions():
            with self.subTest(name=name), self.assertRaises(HIAProgramRejected) as caught:
                verify_program(document)
            type(self).core_refusals.append({"name": name, "document": document,
                "type": type(caught.exception).__name__, "message": str(caught.exception)})
            expected = {
                "end_root_parent_before_descendants": "end child loans before their parent",
                "end_middle_parent_before_descendants": "end child loans before their parent",
                "drop_root_owner_with_live_descendants": "owner moved/dropped/returned while borrowed",
                "reborrow_exclusive_middle_with_live_mutable_child": "conflicting live borrow",
                "omit_middle_end_before_ancestor_cleanup": "end child loans before their parent",
                "swap_intermediate_ancestors_on_one_cfg_edge": "predecessors disagree on loan origins/permissions",
            }[name]
            self.assertIn("E_HIA_LOAN: " + expected, str(caught.exception))


@unittest.skipUnless(shutil.which("cargo") or os.environ.get("HIA_RETURNED_VIEW_RUST_BIN"),
                     "Rust Machine unavailable: nested-returned-view parity NOT qualified")
class HIASourceNestedReturnedViewsRust(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        previous.HIASourceReturnedLocalViewsRust.setUpClass.__func__(cls)
        cls.core = lower_source(SOURCE, core_schema=SCHEMA_V8)

    @classmethod
    def tearDownClass(cls):
        previous.HIASourceReturnedLocalViewsRust.tearDownClass.__func__(cls)

    def test_same_rust_machine_matches_nested_chains_order_failures_and_every_step(self):
        for entry, arguments, _ in cases():
            self.harness.parity(self.core, entry, arguments)
        self.harness.parity(self.core, "failure_case", [7], fail=2)
        self.harness.parity(self.core, "shared_case", [7, 99, 0], fail=1)
        for failure, expected, _, _ in ORDER_CASES[1:]:
            self.assertEqual(self.harness.parity(self.core, "ordering_case", [], fail=failure)["values"], [expected])
        for heap in (1, 3):
            self.harness.parity(self.core, "failure_case", [7], heap=heap)
        completed = self.harness.parity(self.core, "mutable_case", [2, 91, 1])
        type(self).prefix_complete_steps = completed["steps"]
        for limit in range(1, completed["steps"] + 1):
            self.harness.parity(self.core, "mutable_case", [2, 91, 1], steps=limit)

    def test_raw_rust_rejects_actual_six_ancestor_capability_corruptions(self):
        self.assertEqual(self.harness.parity(balanced_parent_reborrow(), "probe", [0])["values"], [8])
        for name, document in corruptions():
            raw = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
            result = self.harness.raw_run(raw, "probe", [0])
            type(self).refusals.append({"name": name, "raw": raw.decode(), "argv": result.args,
                "returncode": result.returncode, "stdout": result.stdout.decode(), "stderr": result.stderr.decode()})
            self.assertNotEqual(result.returncode, 0, name)
            if name == "reborrow_exclusive_middle_with_live_mutable_child":
                self.assertIn(b"E_HIA_LOAN: overlapping incompatible loans", result.stderr)


@unittest.skipUnless(CLANG, "Clang unavailable: nested-returned-view LLVM execution NOT qualified")
class HIASourceNestedReturnedViewsNative(unittest.TestCase):
    records = []

    def test_direct_llvm_executes_source_selected_exports_with_nested_origins(self):
        from hepta.hia_program_llvm import build_program_native
        core = lower_source(SOURCE, core_schema=SCHEMA_V8)
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            output = directory / "nested-returned-views.so"
            with patch("hepta.parser.parse", side_effect=AssertionError("LLVM consumer must use Core")):
                receipt = build_program_native(core.canonical_bytes, output, clang=CLANG)
            self.assertTrue(receipt["ok"], receipt)
            library = ctypes.CDLL(str(output))
            record = {"core_sha256": core.sha256, "receipt": receipt, "observations": []}
            type(self).records = [record]
            for entry, arguments, expected in cases():
                types = {"shared_case": [ctypes.c_size_t, ctypes.c_uint8, ctypes.c_uint8],
                         "mutable_case": [ctypes.c_size_t, ctypes.c_uint8, ctypes.c_size_t],
                         "branch_case": [ctypes.c_size_t, ctypes.c_uint8, ctypes.c_uint8],
                         "failure_case": [ctypes.c_size_t], "mutable_early_case": [ctypes.c_uint8],
                         "ordering_case": [], "stamp": [ctypes.c_size_t]}[entry]
                function = getattr(library, entry)
                function.argtypes, function.restype = types, ctypes.c_uint64
                actual = function(*arguments)
                record["observations"].append({"entry": entry, "arguments": arguments,
                                               "expected": expected, "actual": actual})
                self.assertEqual(actual, expected)
            retained = os.environ.get("HIA_NESTED_VIEW_NATIVE_DIR")
            if retained:
                shutil.copytree(directory, Path(retained) / "direct-llvm")

    def test_real_llvm_allocator_distinguishes_argument_order_and_cleans_nested_views(self):
        from hepta.hia_program_llvm import compile_program_llvm, emit_program_llvm
        from tests.test_hia_source_partial import RESTORE_OBSERVER
        core = lower_source(SOURCE, core_schema=SCHEMA_V8)
        observer = RESTORE_OBSERVER.replace("extern size_t restore_try(void);",
            "extern uint64_t ordering_case(void); extern uint64_t failure_case(size_t);")
        observer = observer.replace("argc!=2", "argc!=3").replace("size_t value=restore_try();",
            "size_t value=(size_t)(argv[2][0]=='o' ? ordering_case() : failure_case(7));")
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            source, object_path, executable = directory / "observer.c", directory / "core.o", directory / "observer"
            source.write_text(observer)
            receipt = compile_program_llvm(emit_program_llvm(core), program=core,
                                           output=object_path, clang=CLANG, kind="object")
            self.assertTrue(receipt["ok"], receipt)
            command = [CLANG, "-std=c11", "-O2", str(source), str(object_path),
                       "-Wl,--wrap=malloc", "-Wl,--wrap=calloc", "-Wl,--wrap=free", "-o", str(executable)]
            built = subprocess.run(command, capture_output=True, text=True, timeout=60)
            self.assertEqual(built.returncode, 0, built.stderr)
            record = {"core_sha256": core.sha256, "object_receipt": receipt, "observer": observer,
                      "link": {"argv": command, "returncode": built.returncode, "stdout": built.stdout, "stderr": built.stderr},
                      "observations": []}
            type(self).allocator = record
            selected = [("ordering", failure or 0, expected, allocations, peak, 4)
                        for failure, expected, allocations, peak in ORDER_CASES]
            selected += [("failure", 0, 50, 2, 10, 2), ("failure", 2, 41, 1, 3, 2)]
            for entry, failure, expected, allocations, peak, attempts in selected:
                run = subprocess.run([str(executable), str(failure), entry], capture_output=True, text=True, timeout=20)
                record["observations"].append({"entry": entry, "failure": failure, "argv": run.args,
                    "returncode": run.returncode, "stdout": run.stdout, "stderr": run.stderr})
                self.assertEqual(run.returncode, 0, run.stderr)
                self.assertEqual(json.loads(run.stdout), {"value": expected, "attempts": attempts,
                    "allocations": allocations, "frees": allocations, "live_bytes": 0, "peak_bytes": peak})
            retained = os.environ.get("HIA_NESTED_VIEW_NATIVE_DIR")
            if retained:
                shutil.copytree(directory, Path(retained) / "allocator")


if __name__ == "__main__":
    unittest.main()
