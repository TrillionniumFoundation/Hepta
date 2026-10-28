"""Canonical v8 parameter-bound loans and retained source/native evidence.

Both returned-loan suites remain discoverable. The retained ten-method source,
Rust and native qualification uses the single canonical return_loans contract;
its smaller corpus does not replace the multi-result and cross-target tests.
"""
from __future__ import annotations

import copy
from copy import deepcopy
import ctypes
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from hepta.hia_core_upgrade import upgrade_core_to_v6, upgrade_core_to_v7
from hepta.hia_program import HIAProgramRejected, verify_program
from hepta.hia_program_runtime import HIAProgramBudgetExceeded, HIAProgramTrap, execute_program
from hepta.hia_program_source import HIAProgramSourceRejected, lower_source, source_report
from hepta.hia_program_llvm import (
    HIAProgramLLVMRejected, TARGET_AARCH64, TARGET_RISCV64, build_program_native,
    compile_program_llvm, emit_program_llvm,
)
from hepta.hia_rust_crosscheck import crosscheck_rust_shadow, HIARustCrosscheckRejected
from hepta.hia_schema import (
    SCHEMA_V8, LATEST_CORE_SCHEMA, CANONICAL_CORE_SCHEMA, schema_registry, supports_feature,
)
from hepta.hia_static_budget import HIAStaticBudgetRejected, qualify_vm_call_depth
from tests.test_hia_program import b, branch, c, f, i, jump, m, ret


def document(*functions):
    return {"schema": SCHEMA_V8, "module": "parameter_returns", "functions": list(functions)}


def helper(mode="read", construction="forward"):
    typ = mode + "buf"
    name = "return_" + mode + "_" + construction
    params = [("input", typ)]
    if construction == "recursive":
        params += [("depth", "u32")]
        blocks = [
            b("entry", params, [c("zero", "u32", 0), i("compare.eq", ["depth", "zero"], [("done", "bool")])],
              branch("done", ("base", "input"), ("step", "input", "depth"))),
            b("base", [("base_input", typ)], [], ret("base_input")),
            b("step", [("step_input", typ), ("step_depth", "u32")], [
                c("one", "u32", 1), i("int.sub.checked", ["step_depth", "one"], [("next_depth", "u32")]),
                i("call", ["step_input", "next_depth"], [("recursive_view", typ)], function=name),
            ], ret("recursive_view")),
        ]
        effects = ["trap"]
    elif construction == "cfg":
        blocks = [b("entry", params, [], jump("renamed", "input")),
                  b("renamed", [("renamed_input", typ)], [], ret("renamed_input"))]
        effects = []
    else:
        ops = [i("borrow." + mode, ["input"], [("child", typ)])] if construction == "child" else []
        blocks = [b("entry", params, ops, ret("child" if ops else "input"))]
        effects = []
    fn = f(name, params, [typ], effects, blocks)
    fn["return_loans"] = ["input"]
    return fn


def loan_program(mode="read", construction="forward"):
    get_view = helper(mode, construction)
    typ = mode + "buf"
    name = "entry_" + mode + "_" + construction
    ops = [i("buffer.new", ["length"], [("owner", "buffer")]),
           i("borrow.mut", ["owner"], [("initial", "mutbuf")]), c("index", "usize", 0),
           i("buffer.store", ["initial", "index", "byte"]), i("loan.end", ["initial"]),
           i("borrow." + mode, ["owner"], [("parent", typ)])]
    arguments = ["parent"]
    if construction == "recursive":
        ops += [c("depth", "u32", 3)]
        arguments += ["depth"]
    ops += [i("call", arguments, [("returned", typ)], function=get_view["name"])]
    if mode == "mut":
        ops += [c("delta", "u8", 5), i("int.add.wrap", ["byte", "delta"], [("changed", "u8")]),
                i("buffer.store", ["returned", "index", "changed"])]
    ops += [i("buffer.load", ["returned", "index"], [("answer", "u8")]),
            i("loan.end", ["returned"]), i("buffer.load", ["parent", "index"], [("parent_read", "u8")]),
            i("loan.end", ["parent"]), i("owner.drop", ["owner"])]
    main = f(name, [("length", "usize"), ("byte", "u8")], ["u8"], ["alloc", "read", "write", "trap"],
             [b("entry", [("length", "usize"), ("byte", "u8")], ops, ret("answer"))])
    source = document(get_view, main)
    source["exports"] = [name]
    return source


def multiple_shared(construction="forward"):
    params = [("left", "readbuf"), ("right", "readbuf")]
    ops, values = [], ["left", "right"]
    for index, name in enumerate(("left", "right")):
        if construction == "children" or construction == "mixed" and index == 1:
            ops += [i("borrow.read", [name], [(name + "_child", "readbuf")])]
            values[index] += "_child"
    get_pair = f("pair", params, ["readbuf", "readbuf"], [], [b("entry", params, ops, ret(*values))])
    get_pair["return_loans"] = ["left", "right"]
    caller = f("shared", [("byte", "u8")], ["u8"], ["alloc", "read", "write", "trap"], [
        b("entry", [("byte", "u8")], [c("size", "usize", 1), c("index", "usize", 0),
          i("buffer.new", ["size"], [("owner", "buffer")]), i("borrow.mut", ["owner"], [("parent", "mutbuf")]),
          i("buffer.store", ["parent", "index", "byte"]),
          i("call", ["parent", "parent"], [("first", "readbuf"), ("second", "readbuf")], function="pair"),
          i("buffer.load", ["first", "index"], [("a", "u8")]), i("loan.end", ["first"]),
          i("buffer.load", ["second", "index"], [("z", "u8")]), i("loan.end", ["second"]),
          i("loan.end", ["parent"]), i("owner.drop", ["owner"]),
          i("int.add.wrap", ["a", "z"], [("answer", "u8")])], ret("answer"))])
    source = document(get_pair, caller)
    source["exports"] = ["shared"]
    return source


def swapped_mutable():
    params = [("left", "mutbuf"), ("right", "mutbuf")]
    swap = f("swap_sources", params, ["mutbuf", "mutbuf"], [], [b("entry", params, [], ret("right", "left"))])
    swap["return_loans"] = ["right", "left"]
    ops = [c("size", "usize", 1), c("index", "usize", 0), c("first_value", "u8", 43), c("second_value", "u8", 71)]
    for name in ("left", "right"):
        ops += [i("buffer.new", ["size"], [(name + "_owner", "buffer")]),
                i("borrow.mut", [name + "_owner"], [(name, "mutbuf")])]
    ops += [i("call", ["left", "right"], [("from_right", "mutbuf"), ("from_left", "mutbuf")], function="swap_sources"),
            i("buffer.store", ["from_right", "index", "first_value"]), i("buffer.store", ["from_left", "index", "second_value"]),
            i("loan.end", ["from_right"]), i("loan.end", ["from_left"]),
            i("buffer.load", ["left", "index"], [("left_read", "u8")]),
            i("buffer.load", ["right", "index"], [("right_read", "u8")]),
            i("loan.end", ["left"]), i("loan.end", ["right"]),
            i("owner.drop", ["left_owner"]), i("owner.drop", ["right_owner"]),
            i("int.sub.wrap", ["left_read", "right_read"], [("answer", "u8")])]
    main = f("swapped", [], ["u8"], ["alloc", "read", "write", "trap"], [b("entry", [], ops, ret("answer"))])
    result = document(swap, main)
    result["exports"] = ["swapped"]
    return result


def fallible_return_program():
    params = [("input", "readbuf"), ("size", "usize")]
    get = f("fallible", params, ["readbuf", "bool"], ["alloc"], [b("entry", params, [
        i("buffer.try_new", ["size"], [("temporary", "buffer"), ("ok", "bool")]),
        i("owner.drop", ["temporary"]),
    ], ret("input", "ok"))])
    get["return_loans"] = ["input", None]
    main = f("fallible_entry", [], ["u8"], ["alloc", "read", "trap"], [b("entry", [], [
        c("size", "usize", 1), c("index", "usize", 0), c("yes", "u8", 1), c("no", "u8", 0),
        i("buffer.new", ["size"], [("owner", "buffer")]), i("borrow.read", ["owner"], [("parent", "readbuf")]),
        i("call", ["parent", "size"], [("returned", "readbuf"), ("ok", "bool")], function="fallible"),
        i("buffer.load", ["returned", "index"], [("byte", "u8")]),
        i("loan.end", ["returned"]), i("loan.end", ["parent"]), i("owner.drop", ["owner"]),
        i("select", ["ok", "yes", "no"], [("answer", "u8")]),
    ], ret("answer"))])
    result = document(get, main)
    result["exports"] = ["fallible_entry"]
    return result


def build_allocator_observer(source, directory, calls):
    """Reuse the independent native allocator observer; calls are test constants."""
    directory = Path(directory)
    obj, driver, binary = directory / "observed.o", directory / "observer.c", directory / "observer"
    receipt = build_program_native(source, output=obj, clang=CANONICAL_CLANG, kind="object")
    root = Path(__file__).resolve().parents[1]
    text = (root / "examples/hia_recursive_chain/allocator_driver.c").read_text().split("int main(", 1)[0]
    text += "\n".join("uint8_t " + name + "(" + signature + ");" for name, (signature, _) in calls.items())
    text += '\nint main(int argc, char **argv) { if (argc != 3) return 64; refuse_at = strtoull(argv[2], NULL, 10); uint64_t result;\n'
    for index, (name, (_, expression)) in enumerate(calls.items()):
        text += ('if' if index == 0 else 'else if') + ' (!strcmp(argv[1], "' + name + '")) result = ' + expression + ';\n'
    text += 'else return 65;\n'
    fields = {"result": "result", "attempts": "attempts", "allocations": "allocations", "frees": "frees",
              "node_allocations": "node_allocations", "node_frees": "node_frees",
              "payload_allocations": "payload_allocations", "payload_frees": "payload_frees",
              "live_bytes": "live_bytes", "peak_bytes": "peak_bytes", "null_frees": "null_frees",
              "bad_frees": "bad_frees", "unknown_sizes": "unknown_sizes"}
    format_string = '{' + ','.join('\\"' + name + '\\":%llu' for name in fields) + '}\\n'
    text += 'printf("' + format_string + '", ' + ','.join('(unsigned long long)' + name for name in fields.values()) + '); return 0; }\n'
    driver.write_text(text)
    subprocess.run([CANONICAL_CLANG, "-O2", "-Wl,--wrap=malloc", "-Wl,--wrap=calloc", "-Wl,--wrap=free",
                    str(driver), str(obj), "-o", str(binary)], check=True, capture_output=True, timeout=30)
    return binary, receipt


class ReturnedLoans(unittest.TestCase):
    def clean(self, report):
        resources = report["resources"]
        for name in ("live_owners", "live_bytes", "live_local_loans", "live_chains", "live_chain_nodes"):
            self.assertEqual(resources[name], 0, name)
        self.assertEqual(resources["allocations"], resources["frees"])
        self.assertEqual(resources["loans_started"], resources["loans_ended"])

    def test_explicit_new_schema_and_legacy_refusal(self):
        self.assertEqual(LATEST_CORE_SCHEMA, SCHEMA_V8)
        self.assertEqual(CANONICAL_CORE_SCHEMA, "hepta.hia.program.v6")
        self.assertTrue(supports_feature(SCHEMA_V8, "parameter_loan_returns"))
        for version in range(1, 8):
            source = loan_program()
            source["schema"] = "hepta.hia.program.v" + str(version)
            with self.subTest(version=version), self.assertRaises(HIAProgramRejected):
                verify_program(source)
            del source["functions"][0]["return_loans"]
            with self.assertRaisesRegex(HIAProgramRejected, "E_HIA_LOAN"):
                verify_program(source)

    def test_forward_child_cfg_recursion_execute_with_balanced_resources(self):
        for mode in ("read", "mut"):
            for construction in ("forward", "child", "cfg", "recursive"):
                source = loan_program(mode, construction)
                for length, byte in ((1, 0), (2, 37), (19, 253)):
                    with self.subTest(mode=mode, construction=construction, length=length, byte=byte):
                        report = execute_program(source, source["exports"][0], [length, byte])
                        self.assertEqual(report["result"], (byte + (5 if mode == "mut" else 0)) & 255)
                        self.clean(report)
                        self.assertEqual(report["resources"]["loans_started"], 3)

    def test_contract_shape_bound_input_and_permissions(self):
        for annotation in (None, [], [None], ["missing"], ["input", None], [["input"]], [{"input": True}]):
            source = loan_program()
            if annotation is None:
                del source["functions"][0]["return_loans"]
            else:
                source["functions"][0]["return_loans"] = annotation
            with self.subTest(annotation=annotation), self.assertRaisesRegex(HIAProgramRejected, "E_HIA_LOAN"):
                verify_program(source)
        source = loan_program()
        source["functions"][0]["returns"] = ["mutbuf"]
        with self.assertRaisesRegex(HIAProgramRejected, "E_HIA_LOAN"):
            verify_program(source)
        source = loan_program()
        source["functions"][1]["return_loans"] = ["length"]
        with self.assertRaisesRegex(HIAProgramRejected, "E_HIA_LOAN"):
            verify_program(source)

    def test_wrong_origin_owner_escape_and_deeper_child_refuse(self):
        source = multiple_shared()
        source["functions"][0]["return_loans"] = ["right", "left"]
        with self.assertRaisesRegex(HIAProgramRejected, "E_HIA_LOAN"):
            verify_program(source)
        for kind in ("owner", "deeper", "active_child"):
            source = loan_program("read", "child")
            fn = source["functions"][0]
            operations = fn["blocks"][0]["ops"]
            if kind == "owner":
                fn["effects"] = ["alloc", "trap"]
                operations[:] = [c("size", "usize", 1), i("buffer.new", ["size"], [("local", "buffer")]),
                                 i("borrow.read", ["local"], [("child", "readbuf")])]
            elif kind == "deeper":
                operations += [i("borrow.read", ["child"], [("deeper", "readbuf")])]
                fn["blocks"][0]["term"] = ret("deeper")
            else:
                fn["blocks"][0]["term"] = ret("input")
            with self.subTest(kind=kind), self.assertRaisesRegex(HIAProgramRejected, "E_HIA_LOAN"):
                verify_program(source)

    def test_multi_result_aliases_create_independent_runtime_views(self):
        for construction in ("forward", "children", "mixed"):
            for byte in (0, 37, 255):
                source = multiple_shared(construction)
                report = execute_program(source, "shared", [byte])
                self.assertEqual(report["result"], (2 * byte) & 255)
                self.clean(report)
                self.assertEqual(report["resources"]["loans_started"], 3)
        report = execute_program(swapped_mutable(), "swapped", [])
        self.assertEqual(report["result"], 28)
        self.clean(report)

    def test_duplicate_return_and_exclusive_call_alias_refuse(self):
        source = multiple_shared()
        source["functions"][0]["blocks"][0]["term"] = ret("left", "left")
        with self.assertRaisesRegex(HIAProgramRejected, "E_HIA_LOAN"):
            verify_program(source)
        source = swapped_mutable()
        call = next(op for op in source["functions"][1]["blocks"][0]["ops"] if op["op"] == "call")
        call["args"] = ["left", "left"]
        with self.assertRaisesRegex(HIAProgramRejected, "E_HIA_LOAN"):
            verify_program(source)

    def test_parent_and_owner_remain_suspended_until_returned_child_ends(self):
        for op in (i("loan.end", ["parent"]), i("owner.drop", ["owner"]),
                   i("owner.move", ["owner"], [("illegal_move", "buffer")]),
                   i("buffer.store", ["parent", "index", "byte"])):
            source = loan_program("mut")
            ops = source["functions"][1]["blocks"][0]["ops"]
            index = next(n for n, ins in enumerate(ops) if ins["op"] == "call") + 1
            ops.insert(index, op)
            with self.subTest(op=op["op"]), self.assertRaisesRegex(HIAProgramRejected, "E_HIA_LOAN"):
                verify_program(source)
        source = multiple_shared()
        ops = source["functions"][1]["blocks"][0]["ops"]
        index = next(n for n, ins in enumerate(ops) if ins["op"] == "loan.end" and ins["args"] == ["first"]) + 1
        ops.insert(index, i("loan.end", ["parent"]))
        with self.assertRaisesRegex(HIAProgramRejected, "E_HIA_LOAN"):
            verify_program(source)

    def test_error_as_value_cleans_actual_allocations(self):
        for fail_at, expected in ((None, 1), (2, 0)):
            report = execute_program(fallible_return_program(), "fallible_entry", [], allocation_fail_at=fail_at)
            self.assertEqual(report["result"], expected)
            self.assertEqual(report["resources"]["allocations"], 2 if fail_at is None else 1)
            self.clean(report)

    def test_traps_and_budget_stops_retain_stopped_resource_ledger(self):
        source = loan_program("read", "child")
        source["functions"][0]["effects"] = ["trap"]
        source["functions"][0]["blocks"][0]["term"] = {"op": "trap", "code": "user"}
        with self.assertRaises(HIAProgramTrap) as caught:
            execute_program(source, source["exports"][0], [1, 37])
        ledger = caught.exception.report["resources"]
        self.assertEqual(ledger["live_owners"], 1)
        self.assertEqual(ledger["live_local_loans"], 2)
        self.assertEqual(ledger["frees"], 0)
        source = loan_program("read", "recursive")
        with self.assertRaises(HIAProgramBudgetExceeded) as caught:
            execute_program(source, source["exports"][0], [1, 37], max_call_depth=2)
        self.assertEqual(caught.exception.report["resources"]["live_owners"], 1)
        self.assertGreater(caught.exception.report["resources"]["live_local_loans"], 0)

    def test_partial_multi_result_failure_and_caller_trap_keep_live_loans(self):
        source = multiple_shared("children")
        get = source["functions"][0]
        get["effects"] = ["alloc", "trap"]
        get["blocks"][0]["ops"][1:1] = [c("temporary_size", "usize", 1),
            i("buffer.new", ["temporary_size"], [("temporary_owner", "buffer")]),
            i("owner.drop", ["temporary_owner"])]
        with self.assertRaises(HIAProgramTrap) as caught:
            execute_program(source, "shared", [37], allocation_fail_at=2)
        ledger = caught.exception.report["resources"]
        self.assertEqual(ledger["live_owners"], 1)
        self.assertEqual(ledger["live_local_loans"], 2)
        self.assertEqual(ledger["loans_started"], 2)
        self.assertEqual(ledger["frees"], 0)
        source = multiple_shared()
        main = source["functions"][1]["blocks"][0]
        index = next(n for n, ins in enumerate(main["ops"]) if ins["op"] == "call")
        main["ops"] = main["ops"][:index + 1]
        main["term"] = {"op": "trap", "code": "user"}
        with self.assertRaises(HIAProgramTrap) as caught:
            execute_program(source, "shared", [37])
        self.assertEqual(caught.exception.report["resources"]["live_local_loans"], 3)
        self.assertEqual(caught.exception.report["resources"]["loans_ended"], 0)

    def test_exported_resource_descriptor_is_refused(self):
        source = loan_program()
        source["exports"] = [source["functions"][0]["name"]]
        with self.assertRaisesRegex(HIAProgramRejected, "public exports cannot carry"):
            verify_program(source)

    def test_resource_analyses_keep_separate_v8_qualification_profiles(self):
        from hepta.hia_heap_bound import analyze_constant_live_heap, HIAHeapBoundRejected
        from hepta.hia_static_budget import analyze_static_budget, qualify_vm_call_depth
        source = loan_program()
        self.assertEqual(analyze_static_budget(source)["schema"], "hepta.hia.static-budget.v2")
        self.assertEqual(qualify_vm_call_depth(source, max_call_depth=3)["schema"],
                         "hepta.hia.vm-call-depth-budget.v2")
        # The legacy all-function heap meaning is not widened by either
        # finite event counting or the separately named v8 entry admission.
        with self.assertRaises(HIAHeapBoundRejected):
            analyze_constant_live_heap(source)

    def test_read_child_can_return_from_mutable_parameter_without_escalation(self):
        source = loan_program("read", "child")
        fn = source["functions"][0]
        fn["params"][0]["type"] = fn["blocks"][0]["params"][0]["type"] = "mutbuf"
        parent = next(ins for ins in source["functions"][1]["blocks"][0]["ops"] if ins["op"] == "borrow.read")
        parent["op"], parent["out"][0]["type"] = "borrow.mut", "mutbuf"
        report = execute_program(source, source["exports"][0], [1, 37])
        self.assertEqual(report["result"], 37)
        self.clean(report)

    def test_legacy_and_v8_nonreturning_loan_cfg_join_still_agree(self):
        params = [("left", "readbuf"), ("right", "readbuf"), ("which", "bool")]
        consumer = f("consume", params, [], [], [
            b("entry", params, [], branch("which", ("joined", "left"), ("joined", "right"))),
            b("joined", [("selected", "readbuf")], [], ret())])
        for version in range(1, 9):
            source = document(consumer)
            source["schema"] = "hepta.hia.program.v" + str(version)
            verify_program(source)


CANONICAL_CLANG = os.environ.get("CLANG") or shutil.which("clang")


@unittest.skipUnless(CANONICAL_CLANG, "actual native Clang required")
class ReturnedLoanCanonicalNative(unittest.TestCase):
    def test_actual_llvm_values_match_vm_across_return_forms(self):
        programs = [loan_program(mode, form) for mode in ("read", "mut")
                    for form in ("forward", "child", "cfg", "recursive")]
        source = document(*(fn for program in programs for fn in program["functions"]))
        source["exports"] = [program["exports"][0] for program in programs]
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "loans.so"
            receipt = build_program_native(source, output=output, clang=CANONICAL_CLANG)
            self.assertIn("v8", receipt["profile"])
            native = ctypes.CDLL(str(output))
            for program in programs:
                name = program["exports"][0]
                function = getattr(native, name)
                function.argtypes, function.restype = [ctypes.c_uint64, ctypes.c_uint8], ctypes.c_uint8
                for length in (1, 3, 17):
                    for byte in (0, 17, 250, 255):
                        with self.subTest(name=name, length=length, byte=byte):
                            expected = (byte + (5 if "_mut_" in name else 0)) & 255
                            self.assertEqual(function(length, byte), expected)
                            self.assertEqual(execute_program(source, name, [length, byte])["result"], expected)

    def test_actual_multi_result_shared_aliases_and_swapped_mutable_origins(self):
        with tempfile.TemporaryDirectory() as temporary:
            for form in ("forward", "children", "mixed"):
                source = multiple_shared(form)
                output = Path(temporary) / (form + ".so")
                build_program_native(source, output=output, clang=CANONICAL_CLANG)
                native = ctypes.CDLL(str(output)).shared
                native.argtypes, native.restype = [ctypes.c_uint8], ctypes.c_uint8
                for byte in (0, 37, 128, 255):
                    self.assertEqual(native(byte), (byte * 2) & 255)
            output = Path(temporary) / "swapped.so"
            build_program_native(swapped_mutable(), output=output, clang=CANONICAL_CLANG)
            native = ctypes.CDLL(str(output)).swapped
            native.argtypes, native.restype = [], ctypes.c_uint8
            self.assertEqual(native(), 28)

    def test_explicit_v8_cross_target_object_profiles(self):
        source = loan_program("mut", "recursive")
        with tempfile.TemporaryDirectory() as temporary:
            for target in ("aarch64-unknown-linux-gnu", "riscv64-unknown-linux-gnu"):
                receipt = build_program_native(source, output=Path(temporary) / (target + ".o"),
                                               clang=CANONICAL_CLANG, kind="object", target=target)
                self.assertIn("v8", receipt["profile"])
                self.assertEqual(receipt["status"], "native_compiled_not_executed")

    def test_actual_allocator_success_and_second_allocation_failure_cleanup(self):
        source = fallible_return_program()
        with tempfile.TemporaryDirectory() as temporary:
            binary, _ = build_allocator_observer(source, temporary, {"fallible_entry": ("void", "fallible_entry()")})
            for fail_at in (0, 2):
                result = subprocess.run([str(binary), "fallible_entry", str(fail_at)], check=True,
                                        capture_output=True, text=True, timeout=10)
                actual = json.loads(result.stdout)
                vm = execute_program(source, "fallible_entry", [], allocation_fail_at=fail_at or None)
                count = 1 if fail_at else 2
                expected = {"result": 0 if fail_at else 1, "attempts": 2, "allocations": count, "frees": count,
                            "node_allocations": 0, "node_frees": 0, "payload_allocations": count, "payload_frees": count,
                            "live_bytes": 0, "peak_bytes": count, "null_frees": 0, "bad_frees": 0, "unknown_sizes": 0}
                self.assertEqual(actual, expected)
                for field in ("allocations", "frees", "live_bytes", "peak_bytes"):
                    self.assertEqual(actual[field], vm["resources"][field])


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "rust/hia-core-shadow/Cargo.toml"
# Preserve the historical import used by returned-chain native tests.
CLANG = CANONICAL_CLANG

SOURCE_PATH = ROOT / "examples/hia_returned_loans/returned_views.hepta"
SOURCE = SOURCE_PATH.read_text()
RECORD_SOURCE = (ROOT / "examples/hia_returned_loans/returned_record_views.hepta").read_text()


def borrowed_function(name, params, returns, blocks, *, origin="p", effects=("read",)):
    result = f(name, params, returns, list(effects), blocks)
    result["return_loans"] = [origin if t in {"readbuf", "mutbuf"} else None for t in returns]
    return result


def returned_program(form="identity", *, mutable=False, shared_from_mut=False, scalar=False):
    view = "mutbuf" if mutable else "readbuf"
    params = [("p", view), ("choose", "bool")]
    results = [view] + (["usize"] if scalar else [])
    extra = [i("buffer.len", ["p"], [("length", "usize")])] if scalar else []
    ret_extra = ["length"] if scalar else []
    if form == "identity":
        blocks = [b("entry", params, extra, ret("p", *ret_extra))]
    elif form == "child":
        blocks = [b("entry", params, extra + [i("borrow.mut" if mutable else "borrow.read", ["p"], [("local", view)])],
                    ret("local", *ret_extra))]
    elif form == "join":
        if scalar:
            raise ValueError("join fixture uses one view result")
        blocks = [b("entry", params, [], branch("choose", ("joined", "p"), ("joined", "p"))),
                  b("joined", [("renamed", view)], [], ret("renamed"))]
    elif form == "relay":
        blocks = [b("entry", params, [i("call", ["p", "choose"], [("relayed", view)], function="leaf")], ret("relayed"))]
    elif form in {"scratch", "trap"}:
        ops = [c("scratch_size", "usize", 2), i("buffer.new", ["scratch_size"], [("scratch", "buffer")]),
               i("borrow.mut", ["scratch"], [("temporary", "mutbuf")]),
               i("loan.end", ["temporary"]), i("owner.drop", ["scratch"])]
        blocks = [b("entry", params, ops, {"op": "trap", "code": "user"} if form == "trap" else ret("p"))]
    else:
        raise ValueError(form)
    effects = ["read", "alloc", "trap"] if form in {"scratch", "trap"} else ["read"]
    helper = borrowed_function("loan", params, results, blocks, effects=effects)
    main_params = [("size", "usize"), ("byte", "u8"), ("condition", "bool")]
    parent_type = "mutbuf" if mutable or shared_from_mut else "readbuf"
    ops = [i("buffer.new", ["size"], [("owner", "buffer")]),
           c("zero", "usize", 0), i("borrow.mut", ["owner"], [("init", "mutbuf")]),
           i("buffer.store", ["init", "zero", "byte"]), i("loan.end", ["init"]),
           i("borrow.mut" if parent_type == "mutbuf" else "borrow.read", ["owner"], [("parent", parent_type)]),
           i("call", ["parent", "condition"], [("child", view)] + ([("extent", "usize")] if scalar else []), function="loan")]
    if mutable:
        ops += [c("mask", "u8", 90), i("bit.xor", ["byte", "mask"], [("changed", "u8")]),
                i("buffer.store", ["child", "zero", "changed"])]
    ops += [i("borrow.read", ["child"], [("grandchild", "readbuf")]),
            i("buffer.load", ["grandchild", "zero"], [("inside", "u8")]),
            i("loan.end", ["grandchild"]), i("loan.end", ["child"]),
            i("buffer.load", ["parent", "zero"], [("after", "u8")]),
            i("loan.end", ["parent"]), i("owner.drop", ["owner"])]
    main = f("probe", main_params, ["u8"], ["alloc", "read", "write", "trap"], [b("entry", main_params, ops, ret("after"))])
    functions = [helper, main]
    if form == "relay":
        functions.insert(0, borrowed_function("leaf", params, [view], [b("entry", params, [], ret("p"))]))
    result = m(*functions)
    result["schema"], result["exports"] = SCHEMA_V8, ["probe"]
    return result


def recursive_program():
    result = returned_program()
    params = [("p", "readbuf"), ("depth", "usize")]
    result["functions"][0] = borrowed_function("loan", params, ["readbuf"], [
        b("entry", params, [c("zero_depth", "usize", 0), i("compare.eq", ["depth", "zero_depth"], [("done", "bool")])],
          branch("done", ("returned", "p"), ("again", "p", "depth"))),
        b("returned", [("leaf_view", "readbuf")], [], ret("leaf_view")),
        b("again", [("view", "readbuf"), ("left", "usize")], [c("one", "usize", 1),
          i("int.sub.checked", ["left", "one"], [("next", "usize")]),
          i("call", ["view", "next"], [("output", "readbuf")], function="loan")], ret("output")),
    ], effects=("read", "trap"))
    main = result["functions"][1]
    main["params"][2]["type"] = main["blocks"][0]["params"][2]["type"] = "usize"
    return result


def chain_program():
    view = borrowed_function("loan", [("p", "mutbuf")], ["mutbuf"],
                             [b("entry", [("p", "mutbuf")], [], ret("p"))])
    params = [("size", "usize"), ("byte", "u8")]
    main = f("probe", params, ["u8"], ["alloc", "read", "write", "trap"], [b("entry", params, [
        i("buffer.new", ["size"], [("payload", "buffer")]), i("chain.empty", out=[("empty", "chain")]),
        i("chain.try_push", ["empty", "payload"], [("chain", "chain"), ("fallback", "buffer"), ("ok", "bool")]),
        i("owner.drop", ["fallback"]), i("chain.head_mut", ["chain"], [("parent", "mutbuf")]),
        i("call", ["parent"], [("child", "mutbuf")], function="loan"),
        c("zero", "usize", 0), i("buffer.store", ["child", "zero", "byte"]),
        i("buffer.load", ["child", "zero"], [("readback", "u8")]),
        i("loan.end", ["child"]), i("loan.end", ["parent"]), i("owner.drop", ["chain"]),
    ], ret("readback"))])
    result = m(view, main)
    result["schema"], result["exports"] = SCHEMA_V8, ["probe"]
    return result


def negative_programs():
    rows = []
    def change(label, transform, *, mutable=False):
        doc = returned_program(mutable=mutable)
        transform(doc)
        rows.append((label, doc))
    change("missing_origin", lambda d: d["functions"][0].pop("return_loans"))
    change("unknown_origin", lambda d: d["functions"][0].update(return_loans=["missing"]))
    change("scalar_origin", lambda d: d["functions"][0].update(return_loans=["choose"]))
    change("origin_arity", lambda d: d["functions"][0].update(return_loans=[]))
    change("scalar_result_with_origin", lambda d: d["functions"][1].update(return_loans=["size"]))
    change("return_read_as_mut", lambda d: d["functions"][0].update(returns=["mutbuf"]))
    change("multiple_returned_loans", lambda d: d["functions"][0].update(returns=["readbuf", "readbuf"], return_loans=["p", "p"]))
    change("loan_and_owner_result", lambda d: d["functions"][0].update(returns=["readbuf", "buffer"], return_loans=["p", None]))
    def helper_ops(doc, ops, returned):
        fn = doc["functions"][0]
        fn["effects"] = ["alloc", "read", "write", "trap"]
        fn["blocks"][0].update(ops=ops, term=ret(returned))
    change("local_owner_origin", lambda d: helper_ops(d, [c("n", "usize", 1),
        i("buffer.new", ["n"], [("local", "buffer")]), i("borrow.read", ["local"], [("dangling", "readbuf")])], "dangling"))
    change("local_intermediate_parent", lambda d: helper_ops(d, [i("borrow.read", ["p"], [("temporary", "readbuf")]),
        i("borrow.read", ["temporary"], [("deep", "readbuf")])], "deep"))
    change("unreturned_sibling", lambda d: helper_ops(d, [i("borrow.read", ["p"], [("left", "readbuf")]),
        i("borrow.read", ["p"], [("right", "readbuf")])], "left"))
    change("mutable_sibling", lambda d: helper_ops(d, [i("borrow.mut", ["p"], [("left", "mutbuf")]),
        i("borrow.read", ["p"], [("right", "readbuf")])], "left"), mutable=True)
    change("end_incoming_parameter", lambda d: helper_ops(d, [i("loan.end", ["p"])], "p"))
    change("return_ended_loan", lambda d: helper_ops(d, [i("borrow.read", ["p"], [("gone", "readbuf")]),
        i("loan.end", ["gone"])], "gone"))
    change("return_suspended_parameter", lambda d: helper_ops(d, [i("borrow.read", ["p"], [("local", "readbuf")])], "p"))
    def missing_read_effect(doc):
        # Capability forwarding alone does not read memory in the canonical v8
        # contract. Preserve this effect counterexample with an actual read.
        fn = doc["functions"][0]
        fn["effects"] = ["trap"]
        fn["blocks"][0]["ops"] = [c("read_index", "usize", 0),
                                    i("buffer.load", ["p", "read_index"], [("read_byte", "u8")])]
    change("missing_return_effect", missing_read_effect)
    def caller_after_call(doc, operation):
        ops = doc["functions"][1]["blocks"][0]["ops"]
        pos = next(n for n, op in enumerate(ops) if op["op"] == "call")
        ops.insert(pos + 1, operation)
    change("read_frozen_parent", lambda d: caller_after_call(d, i("buffer.load", ["parent", "zero"], [("forbidden", "u8")])))
    change("write_frozen_parent", lambda d: caller_after_call(d, i("buffer.store", ["parent", "zero", "byte"])), mutable=True)
    change("end_frozen_parent", lambda d: caller_after_call(d, i("loan.end", ["parent"])))
    change("drop_borrowed_owner", lambda d: caller_after_call(d, i("owner.drop", ["owner"])))
    change("move_borrowed_owner", lambda d: caller_after_call(d, i("owner.move", ["owner"], [("moved", "buffer")])))
    change("write_shared_return", lambda d: caller_after_call(d, i("buffer.store", ["child", "zero", "byte"])))
    change("export_borrowed_helper", lambda d: d.update(exports=["probe", "loan"]))
    for version in range(1, 8):
        doc = returned_program()
        doc["schema"] = f"hepta.hia.program.v{version}"
        rows.append((f"v{version}_explicit_origin_not_supported", doc))
        doc = copy.deepcopy(doc)
        del doc["functions"][0]["return_loans"]
        rows.append((f"v{version}_loan_return_not_supported", doc))
    for version in (1, 2):
        doc = returned_program()
        doc["schema"] = f"hepta.hia.composite.v{version}"
        doc["types"] = []
        rows.append((f"nominal_v{version}_does_not_gain_returned_loan", doc))
    for swap in (False, True):
        doc = returned_program()
        params = [("p", "readbuf"), ("q", "readbuf"), ("choose", "bool")]
        bad = borrowed_function("unused", params, ["readbuf"], [
            b("entry", params, [], branch("choose", ("joined", "p"), ("joined", "q" if swap else "p"))),
            b("joined", [("renamed_q" if not swap else "same_spelling", "readbuf")], [], ret("renamed_q" if not swap else "same_spelling")),
        ], origin="p" if swap else "q")
        doc["functions"].append(bad)
        rows.append(("join_origin_mismatch" if swap else "ssa_name_cannot_forge_origin", doc))
    for place in ("suffix", "unused_helper"):
        doc = returned_program()
        fn = doc["functions"][1] if place == "suffix" else copy.deepcopy(doc["functions"][0])
        if place == "unused_helper":
            fn["name"] = "unused"
            doc["functions"].append(fn)
        fn["blocks"][0]["ops"].append(i("unqualified.future.loan"))
        rows.append(("unknown_" + place, doc))
    return rows


class ReturnedLoanSemantics(unittest.TestCase):
    def test_source_retains_functions_calls_and_explicit_origin(self):
        core = lower_source(SOURCE, core_schema=SCHEMA_V8)
        body = core.as_dict()
        self.assertEqual(body["schema"], SCHEMA_V8)
        self.assertEqual({fn["name"] for fn in body["functions"]}, {"view", "edit", "probe"})
        self.assertTrue(all(fn.get("return_loans") for fn in body["functions"] if fn["name"] in {"view", "edit"}))
        calls = [op["attrs"]["function"] for fn in body["functions"] for bb in fn["blocks"] for op in bb["ops"] if op["op"] == "call"]
        self.assertEqual(calls, ["edit", "view"])
        report = source_report(SOURCE, core_schema=SCHEMA_V8)
        self.assertTrue(report["claims"]["primitive_returned_loans"])
        self.assertTrue(all(row["status"] == "lowered" for row in report["functions"]))
        for choose in (False, True):
            result = execute_program(core, "probe", [1, 19, choose])
            self.assertEqual(result["values"], [73])
            self.assertEqual(result["resources"]["live_local_loans"], 0)

    def test_existing_source_default_and_unsupported_stored_origin_contracts(self):
        legacy = (ROOT / "examples/hia_resource_core/borrowed_projection.hepta").read_text()
        self.assertEqual(lower_source(legacy).as_dict()["schema"], "hepta.hia.program.v1")
        with self.assertRaises(HIAProgramSourceRejected):
            lower_source(legacy, core_schema=SCHEMA_V8)  # record-to-field return origin is not this source profile
        for source in (SOURCE.replace(" from value", ""),
                       SOURCE.replace("let answer = view(read bytes, choose)[0];", "let held = view(read bytes, choose);\n let answer = held[0];"),
                       SOURCE.replace("fn edit", "export \"C\" fn edit")):
            with self.subTest(source=source), self.assertRaises((HIAProgramSourceRejected, ValueError)):
                lower_source(source, core_schema=SCHEMA_V8)

    def test_identity_child_relay_join_and_original_parent_survives(self):
        for form in ("identity", "child", "relay", "join"):
            for mutable in (False, True):
                for choose in (False, True):
                    result = execute_program(returned_program(form, mutable=mutable), "probe", [2, 19, choose])
                    self.assertEqual(result["result"], 73 if mutable else 19)
                    self.assertEqual(result["resources"]["loans_started"], 4)
                    self.assertEqual(result["resources"]["loans_ended"], 4)
                    self.assertEqual(result["resources"]["live_owners"], 0)

    def test_invalid_origins_lifetimes_suffixes_and_unused_helpers_reject(self):
        for label, doc in negative_programs():
            with self.subTest(label=label), self.assertRaises(HIAProgramRejected):
                verify_program(doc)

    def test_other_version_consumers_fail_closed(self):
        core = verify_program(returned_program())
        for convert in (upgrade_core_to_v6, upgrade_core_to_v7):
            with self.assertRaises(HIAProgramRejected):
                convert(core)
        # Current v8 has independently qualified finite frame analysis and
        # object emitters. Older schema conversions and broad proof consumers
        # still refuse or return unknown instead of silently dropping loans.
        frames = qualify_vm_call_depth(core, max_call_depth=2)
        self.assertEqual(frames["schema"], "hepta.hia.vm-call-depth-budget.v2")
        self.assertEqual(frames["core_schema"], SCHEMA_V8)
        self.assertEqual({row["function"]: row["max_call_depth"] for row in frames["functions"]},
                         {"loan": 1, "probe": 2})
        self.assertFalse(frames["claims"]["vm_ticks_bounded"])
        with self.assertRaisesRegex(HIAStaticBudgetRejected, "E_HIA_BUDGET_EXCEEDED"):
            qualify_vm_call_depth(core, max_call_depth=1)
        profiles = {
            TARGET_AARCH64: "hepta.hia.program.llvm-linux-aarch64-parameter-loan-returns-object.v8",
            TARGET_RISCV64: "hepta.hia.program.llvm-linux-riscv64-lp64d-object.v8",
        }
        for target, profile in profiles.items():
            ir = emit_program_llvm(core, target=target)
            self.assertEqual(ir.target, target)
            self.assertEqual(ir.profile, profile)
        from hepta.hia_translation_validation import validate_translation
        receipt = validate_translation(core, core, function="probe")
        self.assertEqual(receipt["status"], "unknown")
        self.assertFalse(receipt["claims"]["all_input_behavior_equivalence_proved"])


@unittest.skipUnless(shutil.which("cargo"), "Cargo unavailable: returned-loan Rust execution NOT qualified")
class ReturnedLoanRust(unittest.TestCase):
    observations, admissions, sources, programs = [], [], {}, {}

    @classmethod
    def setUpClass(cls):
        cls.observations, cls.admissions, cls.sources, cls.programs = [], [], {}, {}
        proc = subprocess.run(["cargo", "build", "--locked", "--offline", "--message-format=json", "--manifest-path", str(MANIFEST)],
                              cwd=ROOT, capture_output=True, text=True, timeout=240)
        cls.build = {"returncode": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr}
        if proc.returncode:
            raise AssertionError(proc.stderr)
        bins = [row["executable"] for line in proc.stdout.splitlines() if (row := json.loads(line)).get("reason") == "compiler-artifact"
                and row.get("executable") and "bin" in row.get("target", {}).get("kind", [])]
        if len(bins) != 1:
            raise AssertionError("Cargo must identify the actual executable")
        cls.executable = bins[0]
        cls.executable_sha256 = hashlib.sha256(Path(cls.executable).read_bytes()).hexdigest()

    def raw(self, core, entry, arguments, *, steps=1000, heap=32768, fail=None, mode="--owned-run"):
        wire = core.canonical_bytes if hasattr(core, "canonical_bytes") else json.dumps(core).encode()
        argv = [self.executable, mode]
        if mode == "--owned-run":
            argv += [entry, json.dumps(arguments), str(steps), str(heap), "none" if fail is None else str(fail)]
        elif mode == "--scalar-run":
            argv += [entry, json.dumps(arguments), str(steps)]
        proc = subprocess.run(argv, cwd=ROOT, input=wire, capture_output=True, timeout=20)
        record = {"argv": argv, "returncode": proc.returncode, "stdout": proc.stdout.decode(), "stderr": proc.stderr.decode(),
                  "stdin_sha256": hashlib.sha256(wire).hexdigest()}
        if not hasattr(core, "canonical_bytes"):
            # Preserve the exact negative wire bytes. Re-serializing a sorted
            # receipt dictionary would otherwise lose original JSON ordering.
            record["stdin_utf8"] = wire.decode()
        return record

    def parity(self, document, arguments, *, steps=1000, heap=32768, fail=None):
        core = verify_program(document)
        type(self).programs[core.sha256] = core.as_dict()
        raw = self.raw(core, "probe", arguments, steps=steps, heap=heap, fail=fail)
        try:
            python = execute_program(core, "probe", arguments, max_steps=steps, max_heap_bytes=heap, allocation_fail_at=fail, max_call_depth=32)
        except (HIAProgramTrap, HIAProgramBudgetExceeded) as stopped:
            python = stopped.report
        row = {"program_sha256": core.sha256, "arguments": arguments, "entry": "probe", "policy": {
            "max_steps": steps, "max_heap_bytes": heap, "allocation_fail_at": fail, "max_call_depth": 32}, "rust_process": raw, "python": python}
        type(self).observations.append(row)
        self.assertEqual(raw["returncode"], 0, raw["stderr"])
        self.assertEqual(raw["stderr"], "")
        rust = row["rust"] = json.loads(raw["stdout"])
        self.assertEqual(raw["stdin_sha256"], core.sha256)
        self.assertEqual(rust["program_sha256"], core.sha256)
        body = core.as_dict()
        has_chain = any(
            "chain" in [*(p["type"] for p in fn["params"]), *fn["returns"],
                        *(p["type"] for bb in fn["blocks"] for p in bb["params"]),
                        *(p["type"] for bb in fn["blocks"] for op in bb["ops"] for p in op["out"])]
            or any(op["op"].startswith("chain.") for bb in fn["blocks"] for op in bb["ops"])
            for fn in body["functions"])
        self.assertEqual(rust["profile"], "bounded-cfg-owned-memory-v5" if has_chain
                         else "bounded-cfg-byte-owner-loan-returns-v4")
        for key in ("status", "steps", "resources"):
            self.assertEqual(rust[key], python[key], key)
        if python["status"] == "returned":
            self.assertEqual(rust["values"], python["values"])
            for key in ("live_owners", "live_bytes", "live_local_loans", "live_chains", "live_chain_nodes"):
                self.assertEqual(rust["resources"][key], 0)
        else:
            self.assertEqual(rust["error"]["code"], python["error"]["code"])
            self.assertNotIn("values", rust)
        row["matched"] = True
        return rust

    def test_read_mut_identity_child_join_relay_and_scalar_result(self):
        for form in ("identity", "child", "join", "relay"):
            for mutable in (False, True):
                for condition in (False, True):
                    for size, byte in ((1, 0), (3, 19), (7, 255)):
                        self.parity(returned_program(form, mutable=mutable), [size, byte, condition])
        self.parity(returned_program(scalar=True), [2, 19, False])
        self.parity(returned_program(shared_from_mut=True), [2, 19, False])
        mutable_origin = returned_program("child", shared_from_mut=True)
        mutable_origin["functions"][0]["params"][0]["type"] = "mutbuf"
        mutable_origin["functions"][0]["blocks"][0]["params"][0]["type"] = "mutbuf"
        self.parity(mutable_origin, [2, 19, False])
        # Origin positions refer to named entry parameters and result slots,
        # not an accidental assumption that a view is always argument/result 0.
        reordered = returned_program(scalar=True)
        fn = reordered["functions"][0]
        fn["params"].reverse()
        fn["blocks"][0]["params"].reverse()
        fn["returns"].reverse()
        fn["return_loans"].reverse()
        fn["blocks"][0]["term"]["values"].reverse()
        call = next(op for op in reordered["functions"][1]["blocks"][0]["ops"] if op["op"] == "call")
        call["args"].reverse()
        call["out"].reverse()
        self.parity(reordered, [2, 19, False])

    def test_real_source_frontend_and_every_step_boundary(self):
        core = lower_source(SOURCE, core_schema=SCHEMA_V8)
        type(self).sources[hashlib.sha256(SOURCE.encode()).hexdigest()] = {"text": SOURCE, "core_sha256": core.sha256,
                                                                       "report": source_report(SOURCE, core_schema=SCHEMA_V8)}
        for condition in (False, True):
            successful = self.parity(core, [2, 19, condition])
            for steps in range(1, successful["steps"] + 2):
                self.parity(core, [2, 19, condition], steps=steps)
        for arguments, heap, fail in (([0, 0, False], 100, None), ([2, 19, True], 1, None), ([2, 19, True], 100, 1)):
            self.parity(core, arguments, heap=heap, fail=fail)
        record_core = lower_source(RECORD_SOURCE, core_schema=SCHEMA_V8)
        type(self).sources[hashlib.sha256(RECORD_SOURCE.encode()).hexdigest()] = {
            "text": RECORD_SOURCE, "core_sha256": record_core.sha256,
            "report": source_report(RECORD_SOURCE, core_schema=SCHEMA_V8)}
        for condition in (False, True):
            self.parity(record_core, [2, 19, condition])

    def test_return_tick_budgets_allocations_traps_recursion_and_chain(self):
        for form in ("identity", "child", "scratch", "trap"):
            doc = returned_program(form, mutable=True)
            completed = self.parity(doc, [3, 29, False])
            for steps in range(1, completed["steps"] + 2):
                self.parity(doc, [3, 29, False], steps=steps)
            for heap, fail in ((2, None), (3, None), (16, 1), (16, 2)):
                self.parity(doc, [3, 29, False], heap=heap, fail=fail)
        for depth in (0, 1, 7, 29, 30, 31, 32, 100):
            self.parity(recursive_program(), [1, 91, depth])
        doc = chain_program()
        completed = self.parity(doc, [2, 81])
        for steps in range(1, completed["steps"] + 2):
            self.parity(doc, [2, 81], steps=steps)
        for heap, fail in ((1, None), (2, None), (26, None), (27, None), (100, 1), (100, 2)):
            self.parity(doc, [2, 81], heap=heap, fail=fail)

    def test_all_invalid_modules_before_any_execution_and_pinned_shadow(self):
        for label, doc in negative_programs():
            row = {"label": label, "input": doc, "rust_attempts": []}
            type(self).admissions.append(row)
            with self.assertRaises(HIAProgramRejected) as caught:
                verify_program(doc)
            row["python_error"] = str(caught.exception)
            codes = []
            for steps, fail in ((1000, None), (1, 1)):
                raw = self.raw(doc, "probe", [2, 19, False], steps=steps, fail=fail)
                row["rust_attempts"].append(raw)
                self.assertNotEqual(raw["returncode"], 0, label)
                self.assertEqual(raw["stdout"], "", label)
                self.assertTrue(raw["stderr"].startswith("E_HIA_"), raw)
                codes.append(raw["stderr"].split(":", 1)[0])
            self.assertEqual(*codes)
            row["rejected"] = True
        core = verify_program(returned_program())
        digest = hashlib.sha256(Path(self.executable).read_bytes()).hexdigest()
        report = crosscheck_rust_shadow(core, self.executable, executable_sha256=digest)
        self.assertTrue(report["shadow_report"]["claims"]["v8_parameter_bound_loan_returns_checked"])
        with self.assertRaises(HIARustCrosscheckRejected):
            crosscheck_rust_shadow(core, self.executable, executable_sha256=digest, profile="scalar")
        raw = self.raw(core, "probe", [2, 19, False], mode="--scalar-run")
        self.assertNotEqual(raw["returncode"], 0)
        self.assertTrue(raw["stderr"].startswith("E_HIA_SCHEMA"))


@unittest.skipUnless(CLANG and shutil.which(CLANG), "Clang unavailable: returned-loan native execution NOT qualified")
class ReturnedLoanNative(unittest.TestCase):
    records = []

    @classmethod
    def setUpClass(cls):
        cls.records = []

    def test_actual_native_calls_private_helpers_and_allocator_observer(self):
        # A source-derived real call boundary and primitive identity/forwarding
        # returns both reach an actual linked executable. The observer checks
        # allocator balance separately from functional output.
        for name, core, nargs, expected_xor in (
            ("source", lower_source(SOURCE, core_schema=SCHEMA_V8), 3, 90),
            ("source-record", lower_source(RECORD_SOURCE, core_schema=SCHEMA_V8), 3, 90),
            ("primitive", verify_program(returned_program("relay", mutable=True)), 3, 90),
            ("scratch", verify_program(returned_program("scratch", mutable=True)), 3, 90),
            ("chain", verify_program(chain_program()), 2, 0),
        ):
            root_dir = os.environ.get("HIA_RETURNED_LOAN_NATIVE_DIR")
            temporary = tempfile.TemporaryDirectory(prefix="hia-returned-", dir=root_dir)
            folder = Path(temporary.name)
            try:
                ir = emit_program_llvm(core)
                self.assertEqual(ir.profile, "hepta.hia.program.llvm-linux-x86_64-parameter-loan-returns.v8")
                self.assertEqual(ir.exports, ("probe",))
                self.assertIn("define internal", ir.text)
                object_path, driver, binary = folder / "program.o", folder / "driver.c", folder / "probe"
                receipt = compile_program_llvm(ir, program=core, output=object_path, clang=CLANG, kind="object")
                arguments = "size, byte, choose" if nargs == 3 else "size, byte"
                signature = "size_t, uint8_t, bool" if nargs == 3 else "size_t, uint8_t"
                driver.write_text("""#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
static size_t allocated, freed, live, live_bytes, calls, attempts, fail_at;
static void *addresses[8]; static size_t extents[8];
void *__real_calloc(size_t,size_t);
void *__real_malloc(size_t);
void __real_free(void*);
static void *track(void *p, size_t size) {
  if(!p) return p;
  for(unsigned j=0;j<8;j++) if(!addresses[j]) {
    addresses[j]=p; extents[j]=size; allocated++; live++; live_bytes+=size; return p;
  }
  exit(74);
}
void *__wrap_calloc(size_t n,size_t s) { attempts++; if(attempts==fail_at)return NULL; return track(__real_calloc(n,s),n*s); }
void *__wrap_malloc(size_t n) { attempts++; if(attempts==fail_at)return NULL; return track(__real_malloc(n),n); }
void __wrap_free(void *p) {
  if(!p) return;
  for(unsigned j=0;j<8;j++) if(addresses[j]==p) {
    addresses[j]=NULL; freed++; live--; live_bytes-=extents[j]; __real_free(p); return;
  }
  exit(71);
}
static void report(void) {
  printf("{\\"calls\\":%zu,\\"allocations\\":%zu,\\"frees\\":%zu,\\"live\\":%zu,\\"live_bytes\\":%zu,\\"attempts\\":%zu}\\n",calls,allocated,freed,live,live_bytes,attempts);
}
_Noreturn void __wrap_abort(void) { report(); fflush(stdout); _Exit(88); }
extern uint8_t probe(""" + signature + """);
int main(int argc, char **argv) {
  if(argc==3) {
    size_t size=(size_t)strtoull(argv[1],NULL,10); uint8_t byte=19; bool choose=false;
    fail_at=(size_t)strtoull(argv[2],NULL,10);
    (void)probe(""" + arguments + """); calls++;
    report(); return 0;
  }
  for(size_t size=1;size<=7;size++) for(unsigned v=0;v<256;v++) for(unsigned flag=0;flag<2;flag++) {
    uint8_t byte=(uint8_t)v; bool choose=(bool)flag;
    uint8_t got=probe(""" + arguments + """); calls++;
    if(got != (uint8_t)(byte ^ """ + str(expected_xor) + """)) return 72;
    if(live || allocated != freed) return 73;
  }
  report();
  return 0;
}
""")
                argv = [CLANG, "-O2", str(driver), str(object_path), "-Wl,--wrap=calloc", "-Wl,--wrap=malloc",
                        "-Wl,--wrap=free", "-Wl,--wrap=abort", "-o", str(binary)]
                built = subprocess.run(argv, capture_output=True, text=True, timeout=60)
                record = {"name": name, "program_sha256": core.sha256, "program": core.as_dict(), "llvm": ir.text,
                          "object_receipt": receipt, "driver": driver.read_text(),
                          "link": {"argv": argv, "returncode": built.returncode, "stdout": built.stdout, "stderr": built.stderr}}
                type(self).records.append(record)
                self.assertEqual(built.returncode, 0, built.stderr)
                run = subprocess.run([str(binary)], capture_output=True, text=True, timeout=20)
                record["run"] = {"returncode": run.returncode, "stdout": run.stdout, "stderr": run.stderr}
                record["binary_sha256"] = hashlib.sha256(binary.read_bytes()).hexdigest()
                self.assertEqual(run.returncode, 0, run.stderr)
                report = record["observations"] = json.loads(run.stdout)
                self.assertEqual(report["calls"], 7 * 256 * 2)
                self.assertEqual(report["live"], 0)
                self.assertEqual(report["allocations"], report["frees"])
                record["failure_observations"] = []
                for size, fail in ((0, 0), (2, 1), (2, 2)):
                    call_args = [size, 19, False] if nargs == 3 else [size, 19]
                    try:
                        python = execute_program(core, "probe", call_args, allocation_fail_at=fail or None)
                    except HIAProgramTrap as stopped:
                        python = stopped.report
                    process = subprocess.run([str(binary), str(size), str(fail)], capture_output=True, text=True, timeout=20)
                    row = {"arguments": call_args, "allocation_fail_at": fail or None, "python": python,
                           "process": {"returncode": process.returncode, "stdout": process.stdout, "stderr": process.stderr}}
                    record["failure_observations"].append(row)
                    self.assertEqual(process.returncode, 88 if python["status"] == "trapped" else 0)
                    observed = row["native"] = json.loads(process.stdout)
                    for native, reference in (("allocations", "allocations"), ("frees", "frees"),
                                              ("live_bytes", "live_bytes"), ("attempts", "allocation_attempts")):
                        self.assertEqual(observed[native], python["resources"][reference], (name, size, fail, native))
                    row["matched"] = True
                if name == "source":
                    record["oracle_controls"] = []
                    wrong_programs = (
                        ("wrong_value", ir.text.replace(", 90", ", 91"), 72),
                        ("missing_free", "\n".join(line for line in ir.text.splitlines() if "call void @free(" not in line) + "\n", 73),
                    )
                    for label, wrong_ir, expected_exit in wrong_programs:
                        self.assertNotEqual(wrong_ir, ir.text)
                        with self.assertRaises(HIAProgramLLVMRejected):
                            compile_program_llvm(replace(ir, text=wrong_ir, sha256=hashlib.sha256(wrong_ir.encode()).hexdigest()),
                                                 program=core, output=folder / (label + "-inadmissible.o"), clang=CLANG, kind="object")
                        wrong_source, wrong_object, wrong_binary = (folder / (label + suffix) for suffix in (".ll", ".o", ""))
                        wrong_source.write_text(wrong_ir)
                        compile_argv = [CLANG, "-O3", "-c", "-x", "ir", str(wrong_source), "-o", str(wrong_object)]
                        compiled = subprocess.run(compile_argv, capture_output=True, text=True, timeout=60)
                        control = {"label": label, "canonical_native_admission_rejected": True, "expected_exit": expected_exit,
                                   "compile": {"argv": compile_argv, "returncode": compiled.returncode, "stdout": compiled.stdout, "stderr": compiled.stderr}}
                        record["oracle_controls"].append(control)
                        self.assertEqual(compiled.returncode, 0, compiled.stderr)
                        link_argv = [part.replace(str(object_path), str(wrong_object)).replace(str(binary), str(wrong_binary)) for part in argv]
                        linked = subprocess.run(link_argv, capture_output=True, text=True, timeout=60)
                        control["link"] = {"argv": link_argv, "returncode": linked.returncode, "stdout": linked.stdout, "stderr": linked.stderr}
                        self.assertEqual(linked.returncode, 0, linked.stderr)
                        wrong_run = subprocess.run([str(wrong_binary)], capture_output=True, text=True, timeout=20)
                        control["run"] = {"returncode": wrong_run.returncode, "stdout": wrong_run.stdout, "stderr": wrong_run.stderr}
                        control["binary_sha256"] = hashlib.sha256(wrong_binary.read_bytes()).hexdigest()
                        self.assertEqual(wrong_run.returncode, expected_exit)
                        control["oracle_rejected"] = True
                if root_dir:
                    destination = Path(root_dir) / name
                    shutil.copytree(folder, destination)
                    record["retained_artifacts"] = str(destination)
                record["passed"] = True
            finally:
                temporary.cleanup()


if __name__ == "__main__":
    unittest.main()
