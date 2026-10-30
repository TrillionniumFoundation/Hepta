"""One nominal partial-state adapter into the existing v8 checker and Machine.

The frontend admits primitive parameter-bound loan results only. Full/partial
record fields containing stored loans do not gain an escaping lifetime. Native
tests execute actual emitted objects; Rust tests use the pinned real process.
"""
from contextlib import contextmanager
from copy import deepcopy
import ctypes
import json
import os
import platform
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_program import HIAProgramRejected, verify_program
from hepta.hia_program_composite import elaborate_program
from hepta.hia_program_llvm import build_program_native, emit_program_llvm
from hepta.hia_program_runtime import execute_program
from hepta import hia_rust_crosscheck as crosscheck
from hepta.hia_routes import route_inventory
from hepta.hia_schema import (COMPOSITE_SCHEMA, COMPOSITE_SCHEMA_V2,
    COMPOSITE_SCHEMA_V3, COMPOSITE_SCHEMA_V4, SCHEMA_V7, SCHEMA_V8, schema_registry)
from tests.test_hia_program import b, branch, c, f, i, ret
from tests.test_hia_program_composite import module, record, ref
from tests.test_hia_partial_record import (partial, roundtrip_program,
    task_partial_program, nested_record_program, chain_partial_program)
from tests import test_hia_returned_loans as returned
from tests import test_hia_rust_api_v4 as api_v4
from tests import test_hia_rust_bound_depth as depth_v2


def v4(types, *functions):
    source = module(types, *functions)
    source["schema"] = COMPOSITE_SCHEMA_V4
    return json.loads(json.dumps(source))


def partial_borrow_program(mode="read", construction="forward"):
    """Keep a partially initialized owner in its caller while a child escapes.

    After child and parent end, take/reinsert the same owner, initialize the
    remaining scalar, finish, unpack and drop. Allocation failure is explicit
    and cleans the actual initialized prefix only.
    """
    pair = ref("Pair", "buffer", "usize")
    empty, first, both = (partial(pair, *names) for names in
                           [(), ("first",), ("first", "second")])
    get = returned.helper(mode, construction)
    name, loan_type = "partial_" + mode + "_" + construction, mode + "buf"
    call_args = ["parent"]
    ops = [i("record.borrow", ["state"], [("initial", "mutbuf")], field="first", mode="mut"),
           c("index", "usize", 0), i("buffer.store", ["initial", "index", "value"]),
           i("loan.end", ["initial"]),
           i("record.borrow", ["state"], [("parent", loan_type)], field="first", mode=mode)]
    if construction == "recursive":
        ops += [c("depth", "u32", 3)]
        call_args += ["depth"]
    ops += [i("call", call_args, [("returned", loan_type)], function=get["name"])]
    if mode == "mut":
        ops += [c("delta", "u8", 5), i("int.add.wrap", ["value", "delta"], [("changed", "u8")]),
                i("buffer.store", ["returned", "index", "changed"])]
    ops += [i("buffer.load", ["returned", "index"], [("answer", "u8")]),
            i("loan.end", ["returned"]),
            i("buffer.load", ["parent", "index"], [("parent_read", "u8")]), i("loan.end", ["parent"]),
            i("record.take", ["state"], [("owned", "buffer"), ("rest", empty)], field="first"),
            i("record.insert", ["rest", "owned"], [("refilled", first)], field="first"),
            c("count", "usize", 7),
            i("record.insert", ["refilled", "count"], [("complete", both)], field="second"),
            i("record.finish", ["complete"], [("whole", pair)]),
            i("record.unpack", ["whole"], [("final", "buffer"), ("final_count", "usize")]),
            i("owner.drop", ["final"])]
    main = f(name, [("length", "usize"), ("byte", "u8")], ["u8"],
             ["alloc", "read", "write", "trap"], [
        b("entry", [("length", "usize"), ("byte", "u8")], [
            i("record.begin", out=[("empty", empty)]),
            i("buffer.try_new", ["length"], [("payload", "buffer"), ("ok", "bool")]),
            i("record.insert", ["empty", "payload"], [("first", first)], field="first"),
        ], branch("ok", ("work", "first", "byte"), ("failed", "first"))),
        b("work", [("state", first), ("value", "u8")], ops, ret("answer")),
        b("failed", [("failed_state", first)], [
            i("record.take", ["failed_state"], [("failed_owner", "buffer"), ("failed_empty", empty)], field="first"),
            i("owner.drop", ["failed_owner"]), i("record.abandon", ["failed_empty"]),
            c("failure", "u8", 250),
        ], ret("failure")),
    ])
    return v4([record("Pair", [("first", "T"), ("second", "U")], ["T", "U"])], get, main)


def partial_result_program():
    """A nominal result before the loan must expand its null origin positions.

    The returned partial state is unrelated to the retained buffer owner. The
    primitive borrowed formal follows an expanded nominal formal, preserving
    its named origin even though its primitive parameter position changes.
    """
    empty, first, second = (partial("Pair", *names) for names in [(), ("first",), ("second",)])
    params = [("state", second), ("input", "readbuf")]
    get = f("partial_and_view", params, [second, "readbuf"], [], [
        b("entry", params, [i("borrow.read", ["input"], [("child", "readbuf")])], ret("state", "child"))])
    get["return_loans"] = [None, "input"]
    main = f("partial_result", [("byte", "u8")], ["u8"], ["alloc", "read", "write", "trap"], [
        b("entry", [("byte", "u8")], [
            c("one", "usize", 1), c("zero", "usize", 0),
            i("buffer.new", ["one"], [("owner", "buffer")]),
            i("record.begin", out=[("owner_empty", empty)]),
            i("record.insert", ["owner_empty", "owner"], [("retained", first)], field="first"),
            i("record.borrow", ["retained"], [("writer", "mutbuf")], field="first", mode="mut"),
            i("buffer.store", ["writer", "zero", "byte"]), i("loan.end", ["writer"]),
            i("record.borrow", ["retained"], [("parent", "readbuf")], field="first", mode="read"),
            i("record.begin", out=[("tag_empty", empty)]),
            i("record.insert", ["tag_empty", "one"], [("tag", second)], field="second"),
            i("call", ["tag", "parent"], [("returned_state", second), ("returned", "readbuf")],
              function="partial_and_view"),
            i("buffer.load", ["returned", "zero"], [("answer", "u8")]),
            i("loan.end", ["returned"]), i("loan.end", ["parent"]),
            i("record.take", ["returned_state"], [("tag_value", "usize"), ("empty_tag", empty)], field="second"),
            i("record.abandon", ["empty_tag"]),
            i("record.take", ["retained"], [("final", "buffer"), ("empty_owner", empty)], field="first"),
            i("owner.drop", ["final"]), i("record.abandon", ["empty_owner"]),
        ], ret("answer"))])
    return v4([record("Pair", [("first", "buffer"), ("second", "usize")])], get, main)


def invalid_core_cases():
    """Structurally lowerable candidates independently refused by Core."""
    parent = partial_borrow_program()
    operations = parent["functions"][1]["blocks"][1]["ops"]
    operations[:] = [op for op in operations if not any(out["name"] == "parent_read" for out in op["out"])]
    at = next(n for n, op in enumerate(operations) if op["op"] == "loan.end" and op["args"] == ["returned"])
    ending = operations.pop(next(n for n, op in enumerate(operations)
                                  if op["op"] == "loan.end" and op["args"] == ["parent"]))
    operations.insert(at, ending)

    moving = partial_borrow_program()
    operations = moving["functions"][1]["blocks"][1]["ops"]
    at = next(n for n, op in enumerate(operations) if op["op"] == "record.take")
    transfers = operations[at:at + 2]
    del operations[at:at + 2]
    at = next(n for n, op in enumerate(operations) if op["op"] == "call")
    operations[at + 1:at + 1] = transfers

    wrong = partial_result_program()
    get = wrong["functions"][0]
    get["params"].append({"name": "other", "type": "readbuf"})
    get["blocks"][0]["params"] = deepcopy(get["params"])
    get["return_loans"] = [None, "other"]
    call = next(op for op in wrong["functions"][1]["blocks"][0]["ops"] if op["op"] == "call")
    call["args"].append("parent")
    return {"parent_ends_before_child": parent, "partial_field_moves_while_borrowed": moving,
            "returned_loan_has_wrong_formal_origin": wrong}


@contextmanager
def native_directory(label):
    retained = os.environ.get("HIA_COMPOSITE_V4_NATIVE_DIR")
    if retained:
        directory = Path(retained) / label
        directory.mkdir(parents=True, exist_ok=False)
        yield directory
    else:
        with tempfile.TemporaryDirectory() as temporary:
            yield Path(temporary)


def retain_native_input(source, directory, receipt):
    core = verify_program(source)
    ir = emit_program_llvm(core)
    if core.sha256 != receipt["core_sha256"] or ir.sha256 != receipt["llvm_ir_sha256"]:
        raise AssertionError("retained native source differs from actual build receipt")
    (directory / "source.json").write_text(json.dumps(source, sort_keys=True, indent=2) + "\n")
    (directory / "core.json").write_bytes(core.canonical_bytes)
    (directory / "program.ll").write_text(ir.text)


class CompositeReturnedLoanSemantics(unittest.TestCase):
    def clean(self, report):
        resources = report["resources"]
        for name in ("live_owners", "live_bytes", "live_local_loans", "live_chains", "live_chain_nodes"):
            self.assertEqual(resources[name], 0, name)
        self.assertEqual(resources["allocations"], resources["frees"])
        self.assertEqual(resources["loans_started"], resources["loans_ended"])

    def test_explicit_profile_preserves_legacy_normalization_and_rejections(self):
        versions = {row["schema"]: row for row in schema_registry()["composite_versions"]}
        self.assertEqual(versions[COMPOSITE_SCHEMA_V3]["normalizes_to"], SCHEMA_V7)
        self.assertEqual(versions[COMPOSITE_SCHEMA_V4]["normalizes_to"], SCHEMA_V8)
        self.assertIn("composite v1-v4", route_inventory()["inputs"][0]["input"])
        for schema in (COMPOSITE_SCHEMA, COMPOSITE_SCHEMA_V2, COMPOSITE_SCHEMA_V3):
            source = partial_borrow_program()
            source["schema"] = schema
            with self.subTest(schema=schema), self.assertRaises(HIAProgramRejected):
                verify_program(source)
            del source["functions"][0]["return_loans"]
            with self.assertRaises(HIAProgramRejected):
                verify_program(source)
        for builder, entry, args in ((roundtrip_program, "roundtrip", [5, False]),
                                     (task_partial_program, "partial_task", [5, 2]),
                                     (nested_record_program, "nested", [5]),
                                     (chain_partial_program, "chain_case", [])):
            old, new = builder(), builder()
            new["schema"] = COMPOSITE_SCHEMA_V4
            old_core, new_core = elaborate_program(old), elaborate_program(new)
            new_core["schema"] = old_core["schema"]
            for fn in new_core["functions"]:
                fn.pop("return_loans", None)
            self.assertEqual(old_core, new_core)
            legacy, current = execute_program(old, entry, args), execute_program(new, entry, args)
            for field in ("result", "resources", "steps"):
                self.assertEqual(legacy[field], current[field])

    def test_partial_borrow_return_end_take_restore_with_cfg_and_recursion(self):
        for mode in ("read", "mut"):
            for form in ("forward", "child", "cfg", "recursive"):
                source = partial_borrow_program(mode, form)
                for size, byte in ((1, 0), (7, 37), (19, 253)):
                    with self.subTest(mode=mode, form=form, size=size, byte=byte):
                        report = execute_program(source, "partial_" + mode + "_" + form, [size, byte])
                        self.assertEqual(report["result"], (byte + (5 if mode == "mut" else 0)) & 255)
                        self.assertEqual(report["resources"]["loans_started"], 3)
                        self.clean(report)
                failed = execute_program(source, "partial_" + mode + "_" + form, [7, 37], allocation_fail_at=1)
                self.assertEqual(failed["result"], 250)
                self.assertEqual(failed["resources"]["allocations"], 0)
                self.clean(failed)

    def test_partial_result_expands_null_origins_before_named_primitive_loan(self):
        source = partial_result_program()
        normalized = elaborate_program(source)
        get = normalized["functions"][0]
        self.assertEqual(normalized["schema"], SCHEMA_V8)
        self.assertEqual(get["returns"], ["buffer", "usize", "readbuf"])
        self.assertEqual(get["return_loans"], [None, None, "input"])
        self.assertEqual(get["params"][-1], {"name": "input", "type": "readbuf"})
        self.assertEqual(normalized["exports"], ["partial_result"])
        self.assertEqual(verify_program(source).canonical_bytes, verify_program(normalized).canonical_bytes)
        for byte in (0, 37, 128, 255):
            report = execute_program(source, "partial_result", [byte])
            self.assertEqual(report["result"], byte)
            self.clean(report)

    def test_contract_shape_permission_and_generated_name_origins_reject(self):
        for origins in (None, [], [None], ["missing"], ["input", None], [["input"]], ["h2internal_1"]):
            source = partial_borrow_program()
            if origins is None:
                del source["functions"][0]["return_loans"]
            else:
                source["functions"][0]["return_loans"] = origins
            with self.subTest(origins=origins), self.assertRaisesRegex(HIAProgramRejected, "E_HIA_LOAN"):
                verify_program(source)
        source = partial_borrow_program()
        source["functions"][0]["returns"] = ["mutbuf"]
        with self.assertRaisesRegex(HIAProgramRejected, "E_HIA_LOAN"):
            verify_program(source)
        source = partial_result_program()
        source["functions"][0]["return_loans"] = ["input", "input"]
        with self.assertRaisesRegex(HIAProgramRejected, "E_HIA_LOAN"):
            verify_program(source)

    def test_stored_loan_results_partial_fields_and_nominal_origins_reject(self):
        types = [record("View", [("loan", "readbuf")])]
        retained = f("retained", [("view", "View")], ["View"], [], [b("entry", [("view", "View")], [], ret("view"))])
        retained["return_loans"] = [None]
        with self.assertRaisesRegex(HIAProgramRejected, "stored loans may not escape"):
            verify_program(v4(types, retained))
        for initialized in ((), ("loan",)):
            bad_type = partial("View", *initialized)
            bad = f("stored_partial", [("value", bad_type)], [], [], [b("entry", [("value", bad_type)], [], ret())])
            with self.assertRaisesRegex(HIAProgramRejected, "partial record fields may not contain stored loans"):
                verify_program(v4(types, bad))
        nominal = f("nominal_origin", [("view", "View")], ["readbuf"], [], [
            b("entry", [("view", "View")], [i("record.unpack", ["view"], [("loan", "readbuf")])], ret("loan"))])
        nominal["return_loans"] = ["view"]
        with self.assertRaisesRegex(HIAProgramRejected, "primitive input loan"):
            verify_program(v4(types, nominal))

    def test_independent_core_rejects_owner_motion_parent_end_and_wrong_origin(self):
        for name, source in invalid_core_cases().items():
            with self.subTest(name=name):
                normalized = elaborate_program(source)
                with self.assertRaisesRegex(HIAProgramRejected, "E_HIA_LOAN"):
                    verify_program(normalized)
                with self.assertRaisesRegex(HIAProgramRejected, "E_HIA_LOAN"):
                    verify_program(source)

    def test_uninitialized_finish_and_local_owner_escape_remain_rejected(self):
        for operation in ("get", "borrow", "finish"):
            source = partial_borrow_program()
            operations = source["functions"][1]["blocks"][1]["ops"]
            if operation == "finish":
                operations.insert(0, i("record.finish", ["state"], [("illegal", ref("Pair", "buffer", "usize"))]))
            else:
                operations.insert(0, i("record." + operation, ["state"], [("illegal", "usize" if operation == "get" else "readbuf")],
                    **({"field": "second"} if operation == "get" else {"field": "second", "mode": "read"})))
            with self.subTest(operation=operation), self.assertRaisesRegex(HIAProgramRejected, "E_HIA_INIT"):
                verify_program(source)
        source = partial_borrow_program("read", "child")
        get = source["functions"][0]
        get["effects"] = ["alloc", "trap"]
        get["blocks"][0]["ops"] = [c("one", "usize", 1), i("buffer.new", ["one"], [("local", "buffer")]),
                                    i("borrow.read", ["local"], [("child", "readbuf")])]
        with self.assertRaises(HIAProgramRejected):
            verify_program(source)

    def test_public_scalar_entries_and_unused_invalid_functions_stay_closed(self):
        source = partial_result_program()
        core = verify_program(source)
        self.assertEqual(core.as_dict()["exports"], ["partial_result"])
        with self.assertRaises(HIAProgramRejected):
            execute_program(source, "partial_and_view", [])
        forged = deepcopy(source)
        forged["exports"] = ["partial_and_view"]
        with self.assertRaises(HIAProgramRejected):
            verify_program(forged)
        invalid = invalid_core_cases()["returned_loan_has_wrong_formal_origin"]
        invalid["functions"].append(f("unrelated", [], ["u8"], [],
            [b("entry", [], [c("answer", "u8", 1)], ret("answer"))]))
        with self.assertRaisesRegex(HIAProgramRejected, "E_HIA_LOAN"):
            execute_program(invalid, "unrelated", [], max_steps=1)


@unittest.skipUnless(platform.system() == "Linux" and shutil.which("cargo"),
                     "Actual composite-v4 Rust qualification requires Linux/Cargo; NOT qualified")
class CompositeReturnedLoanRust(unittest.TestCase):
    setUpClass = classmethod(depth_v2.RustBoundDepthParity.setUpClass.__func__)
    compare = api_v4.RustApiV4Parity.compare
    raw = api_v4.RustApiV4Parity.raw
    reject_raw = depth_v2.RustBoundDepthParity.reject_raw

    def test_actual_same_machine_partial_fields_return_forms_and_flat_results(self):
        for mode in ("read", "mut"):
            for form in ("forward", "child", "cfg", "recursive"):
                source, entry = partial_borrow_program(mode, form), "partial_" + mode + "_" + form
                for byte in (0, 37, 253):
                    actual = self.compare(source, entry, [7, byte])
                    self.assertEqual(actual["rust_report"]["values"], [(byte + (5 if mode == "mut" else 0)) & 255])
        for byte in (0, 37, 128, 255):
            actual = self.compare(partial_result_program(), "partial_result", (byte,))
            self.assertEqual(actual["rust_report"]["values"], [byte])

    def test_exact_stopped_prefixes_allocation_failure_and_recursive_depth(self):
        for mode in ("read", "mut"):
            source, entry = partial_borrow_program(mode, "recursive"), "partial_" + mode + "_recursive"
            normal = execute_program(source, entry, [7, 37])
            for steps in range(1, normal["steps"] + 1):
                self.compare(source, entry, [7, 37], max_steps=steps)
            for fail in (1, 2, (1 << 2048) + 1):
                self.compare(source, entry, (7, 37), allocation_fail_at=fail)
            for depth in (1, 2, 3, 4, 5):
                self.compare(source, entry, [7, 37], max_call_depth=depth)
            for heap in (1, 6, 7):
                self.compare(source, entry, [7, 37], max_heap_bytes=heap)

    def test_raw_core_rejection_and_original_nominal_entry_before_launch(self):
        for name, source in invalid_core_cases().items():
            normalized = elaborate_program(source)
            self.reject_raw(depth_v2.wire(normalized), normalized["exports"][0], "[7,37]" if name != "returned_loan_has_wrong_formal_origin" else "[37]",
                            depth_v2.wire(api_v4.policy(steps=1, depth=1)).decode(), reason=name)
        source = partial_result_program()
        with patch.object(crosscheck, "_run_pinned_shadow", side_effect=AssertionError("must reject before native launch")):
            with self.assertRaisesRegex(crosscheck.HIARustCrosscheckRejected, "public scalar function"):
                crosscheck.crosscheck_rust_execution_v4(source, "partial_and_view", [], self.executable,
                                                      executable_sha256=self.digest)
        # Raw Rust accepts the verified primitive v8 route, not nominal input.
        self.reject_raw(depth_v2.wire(source), "partial_result", "[37]",
                        depth_v2.wire(api_v4.policy()).decode(), reason="unlowered nominal input")


@unittest.skipUnless(returned.CANONICAL_CLANG, "Actual composite-v4 LLVM execution requires Clang; NOT qualified")
class CompositeReturnedLoanNative(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.observations = []

    def test_actual_llvm_calls_all_return_forms_and_expanded_partial_result(self):
        for mode in ("read", "mut"):
            for form in ("forward", "child", "cfg", "recursive"):
                source, entry = partial_borrow_program(mode, form), "partial_" + mode + "_" + form
                with native_directory(entry) as temporary:
                    output = temporary / "partial.so"
                    receipt = build_program_native(source, output=output, clang=returned.CANONICAL_CLANG)
                    retain_native_input(source, temporary, receipt)
                    library = ctypes.CDLL(str(output))
                    function = getattr(library, entry)
                    function.argtypes, function.restype = [ctypes.c_uint64, ctypes.c_uint8], ctypes.c_uint8
                    self.assertFalse(hasattr(library, source["functions"][0]["name"]))
                    values = []
                    for length, byte in ((1, 0), (7, 37), (19, 253)):
                        value = function(length, byte)
                        self.assertEqual(value, execute_program(source, entry, [length, byte])["result"])
                        values.append({"arguments": [length, byte], "result": value})
                    type(self).observations.append({"test": self.id(), "source": source, "build": receipt, "native_calls": values})
        with native_directory("partial_result") as temporary:
            source, output = partial_result_program(), temporary / "multiple.so"
            receipt = build_program_native(source, output=output, clang=returned.CANONICAL_CLANG)
            retain_native_input(source, temporary, receipt)
            library = ctypes.CDLL(str(output))
            function = library.partial_result
            function.argtypes, function.restype = [ctypes.c_uint8], ctypes.c_uint8
            self.assertFalse(hasattr(library, "partial_and_view"))
            values = []
            for byte in (0, 37, 128, 255):
                self.assertEqual(function(byte), byte)
                values.append({"arguments": [byte], "result": byte})
            type(self).observations.append({"test": self.id(), "source": source, "build": receipt, "native_calls": values})

    def test_actual_allocator_normal_and_failed_initialized_prefix_cleanup(self):
        source = partial_borrow_program("mut", "recursive")
        entry = "partial_mut_recursive"
        with native_directory("allocator_observer") as temporary:
            # The existing independent observer classifies one-byte payloads
            # and 24-byte chain nodes. Stay inside that declared fixture scope.
            binary, receipt = returned.build_allocator_observer(source, temporary,
                {entry: ("uint64_t, uint8_t", entry + "(1, 37)")})
            retain_native_input(source, temporary, receipt)
            for fail in (0, 1, 2):
                argv = [str(binary), entry, str(fail)]
                process = subprocess.run(argv, capture_output=True, text=True, timeout=10, check=True)
                actual = json.loads(process.stdout)
                python = execute_program(source, entry, [1, 37], allocation_fail_at=fail or None)
                self.assertEqual(actual["result"], python["result"])
                self.assertEqual(actual["attempts"], 1)
                for field in ("allocations", "frees", "live_bytes", "peak_bytes"):
                    self.assertEqual(actual[field], python["resources"][field])
                self.assertEqual(actual["payload_allocations"], actual["allocations"])
                self.assertEqual(actual["payload_frees"], actual["frees"])
                for field in ("node_allocations", "node_frees", "null_frees", "bad_frees", "unknown_sizes"):
                    self.assertEqual(actual[field], 0)
                type(self).observations.append({"test": self.id(), "source": source, "build": receipt,
                    "process": {"argv": argv, "returncode": process.returncode,
                                "stdout": process.stdout, "stderr": process.stderr}, "matched": True})


if __name__ == "__main__":
    unittest.main()
