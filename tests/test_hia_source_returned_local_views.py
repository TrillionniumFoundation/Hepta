"""Returned byte loans compose with the existing v8 local-view source route."""
from __future__ import annotations

import copy
import ctypes
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from hepta.checker import check
from hepta.hia_program import HIAProgramRejected, verify_program
from hepta.hia_program_runtime import HIAProgramBudgetExceeded, execute_program
from hepta.hia_program_source import HIAProgramSourceRejected, lower_source, source_report
from hepta.hia_routes import admit_route
from hepta.hia_schema import SCHEMA, SCHEMA_V8
from hepta.parser import parse
from hepta.resource_ir import verify_resource_ir
from hepta.resource_lowering import lower_resource_ir
from tests.test_hia_source_local_views import cases as direct_cases

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "examples/hia_program/source_returned_local_views.hepta").read_text()
CLANG = os.environ.get("CLANG") or shutil.which("clang")
VIEW = "struct View<'a>{data:read 'a [u8],tag:u64}\n"
EDIT = "struct Edit<'a>{data:mut 'a [u8],tag:u64}\n"
SHARE = "fn shared(b:read [u8])->read [u8] from b effects{}{return read b;}\n"
EDIT_FN = "fn edited(b:mut [u8])->mut [u8] from b effects{}{return mut b;}\n"
CONTROL_SOURCE = VIEW + SHARE + """
export "C" fn probe(flag:u8)->u64 effects{alloc,block,panic}{
    let data=buffer(1);
    let mut answer:u64=0;
    if true {
        let first=View{data:read shared(read data),tag:7};
        let copy=first;
        if flag!=0 {let nested=copy;answer=nested.tag;} else {answer=first.tag;}
        answer=answer+len(copy.data) as u64;
    }
    drop(move data);
    return answer;
}
"""
MUTABLE_CONTROL_SOURCE = EDIT + EDIT_FN + """
export "C" fn probe(flag:u8)->u64 effects{alloc,block,panic,write}{
    let mut data=buffer(1);
    let first=Edit{data:mut edited(mut data),tag:7};
    let mut moved=move first;
    if flag!=0 {moved.data[0]=9;}
    let answer=moved.tag;
    drop(move moved);
    drop(move data);
    return answer;
}
"""


def cases():
    return [*direct_cases(), ("mutable_early_case", [0], 23), ("mutable_early_case", [1], 5)]


def locate_returned_call(document):
    fn = next(f for f in document["functions"] if f["name"] == "probe")
    for block in fn["blocks"]:
        for index, op in enumerate(block["ops"]):
            if op["op"] == "call" and op["attrs"]["function"] in {"shared", "edited"}:
                return fn, block, index, op["args"][0], op["out"][0]["name"]
    raise AssertionError("source fixture did not emit its returned-loan call")


def balanced_parent_reborrow(*, exclusive=False):
    source = MUTABLE_CONTROL_SOURCE if exclusive else CONTROL_SOURCE
    document = lower_source(source, core_schema=SCHEMA_V8).as_dict()
    _, block, index, parent, _ = locate_returned_call(document)
    block["ops"][index + 1:index + 1] = [
        {"op": "borrow.read", "args": [parent],
         "out": [{"name": "additional_read", "type": "readbuf"}], "attrs": {}},
        {"op": "loan.end", "args": ["additional_read"], "out": [], "attrs": {}},
    ]
    return document


def corruptions():
    """Mutate the actual emitted parent/child capabilities, not a model."""
    original = lower_source(CONTROL_SOURCE, core_schema=SCHEMA_V8).as_dict()

    for name, operation in (
        ("end_parent_before_child", "loan.end"),
        ("drop_owner_with_live_child", "owner.drop"),
    ):
        document = copy.deepcopy(original)
        _, block, index, parent, _ = locate_returned_call(document)
        operand = (next(p["name"] for p in block["params"] if p["type"] == "buffer")
                   if operation == "owner.drop" else parent)
        block["ops"].insert(index + 1, {"op": operation, "args": [operand],
            "out": [], "attrs": {}})
        yield name, document
    yield "reborrow_exclusive_parent_with_live_mutable_child", balanced_parent_reborrow(exclusive=True)
    document = copy.deepcopy(original)
    fn, _, _, _, _ = locate_returned_call(document)
    cleanup = next(block for block in fn["blocks"]
                   if sum(op["op"] == "loan.end" for op in block["ops"]) == 2)
    cleanup["ops"].pop(max(i for i, op in enumerate(cleanup["ops"]) if op["op"] == "loan.end"))
    yield "omit_final_parent_end", document
    document = copy.deepcopy(original)
    _, block, _, parent, child = locate_returned_call(document)
    edge = block["term"]["then"]
    parent_index, child_index = edge["args"].index(parent), edge["args"].index(child)
    edge["args"][parent_index], edge["args"][child_index] = edge["args"][child_index], edge["args"][parent_index]
    yield "swap_parent_child_on_one_cfg_edge", document


def refusals():
    rows = {
        "readless_constructor": VIEW + SHARE + "fn f(b:read [u8])->u64 effects{}{let v=View{data:shared(read b),tag:7};return v.tag;}",
        "owner_drop_while_shared_alias_lives": VIEW + SHARE + "fn f()->u64 effects{alloc,block,panic}{let b=buffer(1);let v=View{data:read shared(read b),tag:7};let copy=v;drop(move b);return copy.tag;}",
        "mutable_owner_reborrow": EDIT + EDIT_FN + "fn f()->Unit effects{alloc,block,panic,write}{let mut b=buffer(1);let v=Edit{data:mut edited(mut b),tag:7};b[0]=9;drop(move v);drop(move b);}",
        "shared_to_mutable_overlap": VIEW + SHARE + "fn f()->Unit effects{alloc,block,panic,write}{let mut b=buffer(1);let v=View{data:read shared(read b),tag:7};b[0]=9;assert(v.tag==7);drop(move b);}",
        "mutable_missing_drop": EDIT + EDIT_FN + "fn f(b:mut [u8])->Unit effects{}{let v=Edit{data:mut edited(mut b),tag:7};}",
        "mutable_copy": EDIT + EDIT_FN + "fn f(b:mut [u8])->Unit effects{}{let v=Edit{data:mut edited(mut b),tag:7};let copy=v;drop(move copy);drop(move v);}",
        "mutable_one_branch_drop": EDIT + EDIT_FN + "fn f(b:mut [u8],flag:bool)->Unit effects{}{let v=Edit{data:mut edited(mut b),tag:7};if flag{drop(move v);}}",
        "escaping_view_return": VIEW + SHARE + "fn f<'a>(b:read 'a [u8])->View<'a> effects{}{return View{data:read shared(read b),tag:7};}",
        "view_parameter": VIEW + "fn f<'a>(v:View<'a>)->u64 effects{}{return v.tag;}",
        "nested_view_record": VIEW + "struct Nested<'a>{view:View<'a>} fn f()->Unit effects{}{}",
        "two_stored_loans": "struct Two<'a>{a:read 'a [u8],b:read 'a [u8]} fn f()->Unit effects{}{}",
        "nested_returned_mode_change": VIEW + SHARE + "fn frozen(b:mut [u8])->read [u8] from b effects{}{return read b;} fn f(b:mut [u8])->u64 effects{}{let v=View{data:read shared(read frozen(mut b)),tag:7};return v.tag;}",
        "origin_is_local_view": VIEW + SHARE + "fn f(b:read [u8])->u64 effects{}{let first=View{data:read b,tag:7};let v=View{data:read shared(read first.data),tag:7};return v.tag;}",
        "two_borrowed_formals": VIEW + "fn shared(b:read [u8],other:read [u8])->read [u8] from b effects{}{return read b;} fn f(b:read [u8])->u64 effects{}{let v=View{data:read shared(read b,read b),tag:7};return v.tag;}",
        "borrowed_record_formal": VIEW + "struct Pair{left:Buffer<u8>,right:Buffer<u8>} fn shared(p:read Pair)->read [u8] from p effects{}{return read p.left;} fn f(p:read Pair)->u64 effects{}{let v=View{data:read shared(read p),tag:7};return v.tag;}",
        "mutable_to_shared_mode_change": VIEW + EDIT_FN + "fn f(b:mut [u8])->u64 effects{}{let v=View{data:read edited(mut b),tag:7};return v.tag;}",
        "borrowed_public_export": VIEW + "export \"C\" " + SHARE,
        "standalone_returned_storage": SHARE + "fn f(b:read [u8])->u64 effects{panic}{let v=shared(read b);return len(v) as u64;}",
    }
    return rows


class HIASourceReturnedLocalViews(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.core = lower_source(SOURCE, core_schema=SCHEMA_V8)
        cls.source_refusals, cls.core_refusals = [], []

    def clean(self, report, expected):
        self.assertEqual(report["status"], "returned")
        self.assertEqual(report["result"], expected)
        resources = report["resources"]
        for created, ended in (("allocations", "frees"), ("owners_created", "owners_dropped"),
                               ("loans_started", "loans_ended")):
            self.assertEqual(resources[created], resources[ended])
        for field in ("live_owners", "live_bytes", "live_local_loans"):
            self.assertEqual(resources[field], 0)

    def test_checked_resource_profile_enters_existing_v8_without_source_reparse(self):
        ast = parse(SOURCE)
        checked = check(ast)
        self.assertTrue(checked.ok, checked.diagnostics)
        self.assertTrue(verify_resource_ir(lower_resource_ir(ast, checked))["ok"])
        with self.assertRaises(HIAProgramSourceRejected):
            lower_source(SOURCE)
        with self.assertRaises(HIAProgramSourceRejected):
            lower_source(SOURCE, core_schema=SCHEMA)
        self.assertEqual(self.core.as_dict()["schema"], SCHEMA_V8)
        self.assertEqual(self.core.as_dict()["exports"], sorted(["shared_case", "mutable_case", "branch_case",
                                                                "failure_case", "mutable_early_case"]))
        self.assertEqual(admit_route("hepta-source", SOURCE, core_schema=SCHEMA_V8).canonical_bytes,
                         self.core.canonical_bytes)
        self.assertTrue(source_report(SOURCE, core_schema=SCHEMA_V8)["local_borrowed_views"]["returned_call_storage"])
        with patch("hepta.parser.parse", side_effect=AssertionError("Core consumers must not parse source")):
            canonical = verify_program(self.core.canonical_bytes)
            self.clean(execute_program(canonical, "shared_case", [3, 19, 0]), 57)

    def test_copy_move_branches_loops_and_each_early_exit_keep_parent_until_last_alias(self):
        for entry, arguments, expected in cases():
            with self.subTest(entry=entry, arguments=arguments):
                self.clean(execute_program(self.core, entry, arguments), expected)
        control = lower_source(CONTROL_SOURCE, core_schema=SCHEMA_V8)
        for flag in (0, 1):
            self.clean(execute_program(control, "probe", [flag]), 8)

    def test_fallible_paths_and_each_step_prefix_preserve_actual_resource_ledger(self):
        self.clean(execute_program(self.core, "failure_case", [7], allocation_fail_at=2), 41)
        self.clean(execute_program(self.core, "shared_case", [7, 99, 0], allocation_fail_at=1), 1001)
        completed = execute_program(self.core, "mutable_case", [2, 91, 1])
        saw_parent_and_child = False
        for limit in range(1, completed["steps"]):
            with self.assertRaises(HIAProgramBudgetExceeded) as caught:
                execute_program(self.core, "mutable_case", [2, 91, 1], max_steps=limit)
            ledger = caught.exception.report["resources"]
            self.assertEqual(ledger["owners_created"] - ledger["owners_dropped"], ledger["live_owners"])
            self.assertEqual(ledger["loans_started"] - ledger["loans_ended"], ledger["live_local_loans"])
            saw_parent_and_child |= ledger["live_local_loans"] >= 2
        self.assertTrue(saw_parent_and_child)

    def test_original_checker_and_finite_origin_storage_export_limits_still_reject(self):
        for name, source in refusals().items():
            with self.subTest(name=name):
                with self.assertRaises((HIAProgramSourceRejected, HIAProgramRejected)) as caught:
                    lower_source(source, core_schema=SCHEMA_V8)
                type(self).source_refusals.append({"name": name, "source": source,
                    "type": type(caught.exception).__name__, "message": str(caught.exception)})

    def test_actual_core_rejects_parent_owner_and_cfg_corruptions(self):
        # A shared parent can have another shared child when that child is
        # correctly ended. Do not mistake a dropped-loan edge for exclusivity.
        neighbour = verify_program(balanced_parent_reborrow())
        self.clean(execute_program(neighbour, "probe", [0]), 8)
        for name, document in corruptions():
            with self.subTest(name=name):
                with self.assertRaises(HIAProgramRejected) as caught:
                    verify_program(document)
                type(self).core_refusals.append({"name": name, "document": document,
                    "type": type(caught.exception).__name__, "message": str(caught.exception)})
                if name == "reborrow_exclusive_parent_with_live_mutable_child":
                    self.assertIn("E_HIA_LOAN: conflicting live borrow", str(caught.exception))


@unittest.skipUnless(shutil.which("cargo") or os.environ.get("HIA_RETURNED_VIEW_RUST_BIN"),
                     "Rust Machine unavailable: returned-local-view parity NOT qualified")
class HIASourceReturnedLocalViewsRust(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tests.test_hia_rust_owned_cfg import RustByteOwnerCfgParity

        class Parity(unittest.TestCase):
            raw_run = RustByteOwnerCfgParity.raw_run
            parity = RustByteOwnerCfgParity.parity
            execution_profile = "bounded-cfg-byte-owner-loan-returns-v4"

        selected = os.environ.get("HIA_RETURNED_VIEW_RUST_BIN")
        if selected:
            executable = Path(selected).resolve(strict=True)
            expected = os.environ.get("HIA_RETURNED_VIEW_RUST_SHA256")
            digest = hashlib.sha256(executable.read_bytes()).hexdigest()
            if expected != digest:
                raise AssertionError("explicit reused Rust Machine requires its exact SHA256")
            Parity.executable = str(executable)
            Parity.build = {"reused_existing_binary": True, "path": str(executable), "sha256": digest,
                            "bytes": executable.stat().st_size, "built_by_this_test": False}
            Parity.observations, Parity.sources = [], {}
        else:
            RustByteOwnerCfgParity.setUpClass.__func__(Parity)
        cls.harness = Parity()
        cls.build, cls.observations, cls.programs = Parity.build, Parity.observations, Parity.sources
        cls.refusals = []
        cls.core = lower_source(SOURCE, core_schema=SCHEMA_V8)
        cls.binary_sha256 = hashlib.sha256(Path(Parity.executable).read_bytes()).hexdigest()

    @classmethod
    def tearDownClass(cls):
        digest = hashlib.sha256(Path(cls.harness.executable).read_bytes()).hexdigest()
        if digest != cls.binary_sha256:
            raise AssertionError("Rust Machine bytes changed during returned-local-view execution")

    def test_actual_same_rust_machine_matches_values_loans_failures_and_every_step(self):
        for entry, arguments, _ in cases():
            self.harness.parity(self.core, entry, arguments)
        self.harness.parity(self.core, "failure_case", [7], fail=2)
        self.harness.parity(self.core, "shared_case", [7, 99, 0], fail=1)
        for heap in (1, 3):
            self.harness.parity(self.core, "failure_case", [7], heap=heap)
        completed = self.harness.parity(self.core, "mutable_case", [2, 91, 1])
        for limit in range(1, completed["steps"] + 1):
            self.harness.parity(self.core, "mutable_case", [2, 91, 1], steps=limit)

    def test_raw_rust_refuses_the_same_five_emitted_capability_corruptions(self):
        accepted = self.harness.parity(balanced_parent_reborrow(), "probe", [0])
        self.assertEqual(accepted["values"], [8])
        for name, document in corruptions():
            raw = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
            result = self.harness.raw_run(raw, "probe", [0])
            type(self).refusals.append({"name": name, "raw": raw.decode(), "argv": result.args,
                "returncode": result.returncode, "stdout": result.stdout.decode(), "stderr": result.stderr.decode()})
            self.assertNotEqual(result.returncode, 0, name)
            if name == "reborrow_exclusive_parent_with_live_mutable_child":
                self.assertIn(b"E_HIA_LOAN: overlapping incompatible loans", result.stderr)


@unittest.skipUnless(CLANG, "Clang unavailable: returned-local-view LLVM execution NOT qualified")
class HIASourceReturnedLocalViewsNative(unittest.TestCase):
    records = []

    def test_direct_llvm_executes_actual_source_selected_scalar_exports(self):
        from hepta.hia_program_llvm import build_program_native
        core = lower_source(SOURCE, core_schema=SCHEMA_V8)
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            output = directory / "returned-local-views.so"
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
                         "failure_case": [ctypes.c_size_t], "mutable_early_case": [ctypes.c_uint8]}[entry]
                function = getattr(library, entry)
                function.argtypes, function.restype = types, ctypes.c_uint64
                actual = function(*arguments)
                record["observations"].append({"entry": entry, "arguments": arguments,
                                               "expected": expected, "actual": actual})
                self.assertEqual(actual, expected)
            retained = os.environ.get("HIA_RETURNED_VIEW_NATIVE_DIR")
            if retained:
                shutil.copytree(directory, Path(retained) / "direct-llvm")

    def test_actual_llvm_allocator_failure_keeps_returned_view_cleanup(self):
        from hepta.hia_program_llvm import compile_program_llvm, emit_program_llvm
        from tests.test_hia_source_partial import RESTORE_OBSERVER
        core = lower_source(SOURCE, core_schema=SCHEMA_V8)
        observer = RESTORE_OBSERVER.replace("extern size_t restore_try(void);", "extern uint64_t failure_case(size_t);")
        observer = observer.replace("size_t value=restore_try();", "size_t value=(size_t)failure_case(7);")
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
            for failure, expected, allocations, peak in ((0, 50, 2, 10), (2, 41, 1, 3)):
                run = subprocess.run([str(executable), str(failure)], capture_output=True, text=True, timeout=20)
                record["observations"].append({"failure": failure, "argv": run.args, "returncode": run.returncode,
                                              "stdout": run.stdout, "stderr": run.stderr})
                self.assertEqual(run.returncode, 0, run.stderr)
                self.assertEqual(json.loads(run.stdout), {"value": expected, "attempts": 2,
                    "allocations": allocations, "frees": allocations, "live_bytes": 0, "peak_bytes": peak})
            retained = os.environ.get("HIA_RETURNED_VIEW_NATIVE_DIR")
            if retained:
                shutil.copytree(directory, Path(retained) / "allocator")


if __name__ == "__main__":
    unittest.main()
