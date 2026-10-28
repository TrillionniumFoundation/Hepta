"""Finite parameter-bound return loans, including real native differential calls."""
from copy import deepcopy
import ctypes
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from hepta.hia_program import HIAProgramRejected, verify_program
from hepta.hia_program_llvm import build_program_native, emit_program_llvm
from hepta.hia_program_runtime import HIAProgramBudgetExceeded, HIAProgramTrap, execute_program
from hepta.hia_schema import (SCHEMA_V8, LATEST_CORE_SCHEMA, CANONICAL_CORE_SCHEMA,
                              schema_registry, supports_feature)
from tests.test_hia_program import b, c, f, i, ret, jump, branch


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
    receipt = build_program_native(source, output=obj, clang=CLANG, kind="object")
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
    subprocess.run([CLANG, "-O2", "-Wl,--wrap=malloc", "-Wl,--wrap=calloc", "-Wl,--wrap=free",
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


CLANG = os.environ.get("CLANG") or shutil.which("clang")


@unittest.skipUnless(CLANG, "actual native Clang required")
class ReturnedLoanNative(unittest.TestCase):
    def test_actual_llvm_values_match_vm_across_return_forms(self):
        programs = [loan_program(mode, form) for mode in ("read", "mut")
                    for form in ("forward", "child", "cfg", "recursive")]
        source = document(*(fn for program in programs for fn in program["functions"]))
        source["exports"] = [program["exports"][0] for program in programs]
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "loans.so"
            receipt = build_program_native(source, output=output, clang=CLANG)
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
                build_program_native(source, output=output, clang=CLANG)
                native = ctypes.CDLL(str(output)).shared
                native.argtypes, native.restype = [ctypes.c_uint8], ctypes.c_uint8
                for byte in (0, 37, 128, 255):
                    self.assertEqual(native(byte), (byte * 2) & 255)
            output = Path(temporary) / "swapped.so"
            build_program_native(swapped_mutable(), output=output, clang=CLANG)
            native = ctypes.CDLL(str(output)).swapped
            native.argtypes, native.restype = [], ctypes.c_uint8
            self.assertEqual(native(), 28)

    def test_explicit_v8_cross_target_object_profiles(self):
        source = loan_program("mut", "recursive")
        with tempfile.TemporaryDirectory() as temporary:
            for target in ("aarch64-unknown-linux-gnu", "riscv64-unknown-linux-gnu"):
                receipt = build_program_native(source, output=Path(temporary) / (target + ".o"),
                                               clang=CLANG, kind="object", target=target)
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


if __name__ == "__main__":
    unittest.main()
