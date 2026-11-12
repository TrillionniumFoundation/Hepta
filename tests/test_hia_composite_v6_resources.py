"""Cross-construct resource checks on the unified composite/v6 semantics.

These cases combine generic owners, field borrowing, retained/reborrowed
views, all memory instruction generations, CFG transfer, task cancellation,
allocation failure and source-free execution. Native checks execute the
actual emitted LLVM, including an allocator-refusal path.
"""
from __future__ import annotations

import copy
import ctypes
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import unittest

from hepta.hia_program import HIAProgramRejected, VerifiedProgram, verify_core
from hepta.hia_program_runtime import HIAProgramTrap, execute_program
from hepta.hia_schema import COMPOSITE_SCHEMA, SCHEMA_V6
from tests.test_hia_program import b, branch, c, f, i, jump, ret
from tests.test_hia_program_composite import module, record, ref, task_program


def composite_bulk_program():
    pair = ref("Pair", "buffer", "buffer")
    frame = ref("Frame", pair)
    types = [record("Pair", [("source", "S"), ("destination", "D")], ["S", "D"]),
             record("Frame", [("owners", "O"), ("source", "readbuf"),
                               ("destination", "mutbuf")], ["O"])]
    return module(types, f("record_bulk", [("probe", "usize")], ["u8"],
        ["alloc", "read", "write", "trap"], [
        b("entry", [("probe", "usize")], [
            c("size", "usize", 6),
            i("buffer.try_new", ["size"], [("source", "buffer"), ("source_ok", "bool")]),
            i("buffer.try_new", ["size"], [("destination", "buffer"), ("destination_ok", "bool")]),
            i("bool.and", ["source_ok", "destination_ok"], [("ok", "bool")]),
            i("record.make", ["source", "destination"], [("owners", pair)]),
        ], branch("ok", ("write", "owners", "probe"), ("failure", "owners"))),
        b("failure", [("failed", pair)], [
            i("record.unpack", ["failed"], [("failed_source", "buffer"), ("failed_destination", "buffer")]),
            i("owner.drop", ["failed_source"]), i("owner.drop", ["failed_destination"]),
            c("failure_code", "u8", 250),
        ], ret("failure_code")),
        b("write", [("pair", pair), ("index", "usize")], [
            i("record.borrow", ["pair"], [("writer", "mutbuf")], field="source", mode="mut"),
            c("base", "u8", 13), c("special", "u8", 91), c("padding", "u8", 5),
            c("zero", "usize", 0), c("one", "usize", 1), c("two", "usize", 2),
            c("three", "usize", 3), c("four", "usize", 4),
            i("buffer.fill", ["writer", "base"]),
            i("buffer.fill_range", ["writer", "one", "three", "special"]),
            i("buffer.swap", ["writer", "zero", "two"]),
            i("buffer.move_within", ["writer", "two", "zero", "four"]),
            i("loan.end", ["writer"]),
            i("record.borrow", ["pair"], [("reader", "readbuf")], field="source", mode="read"),
            i("record.borrow", ["pair"], [("target", "mutbuf")], field="destination", mode="mut"),
            i("buffer.fill", ["target", "padding"]),
            i("buffer.copy", ["target", "reader", "two"]),
            i("buffer.copy_range", ["target", "reader", "three", "two", "three"]),
            i("record.make", ["pair", "reader", "target"], [("retained", frame)]),
        ], jump("inspect", "retained", "index")),
        b("inspect", [("stored", frame), ("probe_index", "usize")], [
            i("record.borrow", ["stored"], [("child", "readbuf")], field="destination", mode="read"),
            i("buffer.load", ["child", "probe_index"], [("answer", "u8")]),
            i("loan.end", ["child"]),
            i("record.unpack", ["stored"], [("unpacked", pair), ("source_view", "readbuf"),
                                             ("destination_view", "mutbuf")]),
            i("loan.end", ["destination_view"]), i("loan.end", ["source_view"]),
            i("record.unpack", ["unpacked"], [("last_source", "buffer"), ("last_destination", "buffer")]),
            i("owner.drop", ["last_source"]), i("owner.drop", ["last_destination"]),
        ], ret("answer")),
    ]))


def composite_range_task_program():
    program = task_program()
    program["types"].append(record("StoredPollLoan", [("view", "T")], ["T"]))
    stored = ref("StoredPollLoan", "mutbuf")
    entry = program["functions"][0]["blocks"][0]
    entry["ops"][:0] = [
        i("record.borrow", ["state"], [("poll_writer", "mutbuf")], field="first", mode="mut"),
        i("record.make", ["poll_writer"], [("poll_stored", stored)]),
        i("record.borrow", ["poll_stored"], [("poll_reader", "readbuf")], field="view", mode="read"),
        i("buffer.len", ["poll_reader"], [("poll_length", "usize")]),
        i("loan.end", ["poll_reader"]),
        i("record.unpack", ["poll_stored"], [("poll_recovered", "mutbuf")]),
        c("poll_zero", "usize", 0), c("poll_one", "usize", 1), c("poll_mark", "u8", 21),
        i("buffer.fill_range", ["poll_recovered", "poll_zero", "poll_one", "poll_mark"]),
        i("loan.end", ["poll_recovered"]),
    ]
    return program


class UnifiedResourceTests(unittest.TestCase):
    def test_all_memory_generations_compose_with_generic_records_and_stored_loans(self):
        checked = verify_core(composite_bulk_program())
        self.assertEqual(checked.as_dict()["schema"], SCHEMA_V6)
        self.assertEqual(checked.normalization_report["input_schema"], COMPOSITE_SCHEMA)
        self.assertEqual(checked.scalar_entrypoints, frozenset({"record_bulk"}))
        operations = {op["op"] for fn in checked.as_dict()["functions"]
                      for block in fn["blocks"] for op in block["ops"]}
        self.assertTrue({"buffer.fill", "buffer.copy", "buffer.move_within", "buffer.swap",
                         "buffer.copy_range", "buffer.fill_range"}.issubset(operations))
        self.assertNotIn("record.borrow", operations)
        for candidate in (checked, checked.canonical_bytes):
            for index, expected in enumerate((91, 91, 5, 91, 91, 13)):
                with self.subTest(source_free=type(candidate) is bytes, index=index):
                    observed = execute_program(candidate, "record_bulk", [index])
                    self.assertEqual(observed["result"], expected)
                    self.assertEqual(observed["resources"]["allocations"], 2)
                    self.assertEqual(observed["resources"]["frees"], 2)
                    self.assertEqual(observed["resources"]["live_owners"], 0)
                    self.assertEqual(observed["resources"]["live_local_loans"], 0)

    def test_each_allocation_failure_releases_other_owner_and_returns_error_value(self):
        for fail_at in (1, 2):
            for candidate in (composite_bulk_program(), verify_core(composite_bulk_program()).as_dict()):
                with self.subTest(fail_at=fail_at):
                    observed = execute_program(candidate, "record_bulk", [0], allocation_fail_at=fail_at)
                    self.assertEqual(observed["result"], 250)
                    self.assertEqual(observed["resources"]["allocations"], 1)
                    self.assertEqual(observed["resources"]["frees"], 1)
                    self.assertEqual(observed["resources"]["owners_created"], 2)
                    self.assertEqual(observed["resources"]["owners_dropped"], 2)

    def test_generic_state_range_mutation_stored_loan_enum_result_and_cancellation(self):
        checked = verify_core(composite_range_task_program())
        for candidate in (checked, checked.canonical_bytes):
            for mode, expected in ((0, 33), (1, 13), (2, 48), (255, 48)):
                observed = execute_program(candidate, "task_case", [mode])
                self.assertEqual(observed["result"], expected)
                self.assertEqual(observed["resources"]["live_owners"], 0)
                self.assertEqual(observed["resources"]["live_local_loans"], 0)
                self.assertEqual(observed["resources"]["allocations"], observed["resources"]["frees"])
                failed = execute_program(candidate, "task_case", [mode], allocation_fail_at=1)
                self.assertEqual(failed["result"], 250)
                self.assertEqual(failed["resources"]["live_owners"], 0)

    def test_field_permission_and_parent_suspension_cannot_be_bypassed(self):
        bad = []
        doc = composite_bulk_program()
        write = doc["functions"][0]["blocks"][2]
        write["ops"].insert(1, i("record.borrow", ["pair"], [("duplicate", "mutbuf")], field="source", mode="mut"))
        bad.append(doc)
        doc = composite_bulk_program()
        write = doc["functions"][0]["blocks"][2]
        next(op for op in write["ops"] if op["out"] and op["out"][0]["name"] == "target")["attrs"]["field"] = "source"
        bad.append(doc)
        doc = composite_bulk_program()
        inspect = doc["functions"][0]["blocks"][3]
        inspect["ops"].insert(1, i("record.borrow", ["stored"], [("parent_write", "mutbuf")], field="destination", mode="mut"))
        bad.append(doc)
        doc = composite_range_task_program()
        entry = doc["functions"][0]["blocks"][0]
        entry["ops"] = [op for op in entry["ops"] if op != i("loan.end", ["poll_reader"])]
        bad.append(doc)
        for index, doc in enumerate(bad):
            with self.subTest(index=index), self.assertRaises(HIAProgramRejected):
                verify_core(doc)

    def test_record_field_borrow_requires_exact_types_modes_and_known_fields(self):
        for mutation in ("field", "mode", "out", "attrs", "aggregate_field"):
            doc = composite_bulk_program()
            operation = doc["functions"][0]["blocks"][2]["ops"][0]
            if mutation == "field":
                operation["attrs"]["field"] = "absent"
            elif mutation == "mode":
                operation["attrs"]["mode"] = {"unchecked": True}
            elif mutation == "out":
                operation["out"][0]["type"] = "buffer"
            elif mutation == "attrs":
                operation["attrs"]["verified"] = True
            else:
                operation = doc["functions"][0]["blocks"][3]["ops"][0]
                operation["attrs"]["field"] = "owners"
            with self.subTest(mutation=mutation), self.assertRaises(HIAProgramRejected):
                verify_core(doc)

    def test_loan_end_and_required_effects_remain_checked_after_erasure(self):
        for mutation in ("erase_loan_end", "erase_drop", "remove_effect"):
            doc = verify_core(composite_bulk_program()).as_dict()
            if mutation == "remove_effect":
                doc["functions"][0]["effects"].remove("write")
            else:
                op = "loan.end" if mutation == "erase_loan_end" else "owner.drop"
                block = doc["functions"][0]["blocks"][3]
                block["ops"].remove(next(item for item in block["ops"] if item["op"] == op))
            with self.subTest(mutation=mutation), self.assertRaises(HIAProgramRejected):
                verify_core(doc)

    def test_forged_structured_pair_and_out_of_bounds_never_become_success(self):
        checked = verify_core(composite_bulk_program())
        forged = VerifiedProgram(checked.canonical_bytes,
                                 checked.structured_bytes.replace(b'"value":91', b'"value":92'))
        with self.assertRaises(HIAProgramRejected):
            execute_program(forged, "record_bulk", [0])
        with self.assertRaises(HIAProgramTrap) as caught:
            execute_program(checked, "record_bulk", [6])
        self.assertEqual(caught.exception.code, "bounds")

    def test_recursive_heap_adt_is_still_explicitly_outside_the_profile(self):
        doc = composite_bulk_program()
        doc["types"].append(record("Recursive", [("next", "Recursive")]))
        with self.assertRaisesRegex(HIAProgramRejected, "recursive by-value"):
            verify_core(doc)


CLANG = os.environ.get("CLANG", "/usr/lib/llvm-20/bin/clang")


@unittest.skipUnless(shutil.which(CLANG) and platform.machine() in ("x86_64", "amd64")
                     and platform.system() == "Linux", "Linux x86-64 and real Clang required")
class UnifiedResourceNativeTests(unittest.TestCase):
    def test_emitted_v6_native_bytes_tasks_and_real_allocation_refusal(self):
        from hepta.hia_program_llvm import emit_program_llvm

        with tempfile.TemporaryDirectory(prefix="hia-unified-resource-") as temporary:
            root = Path(temporary)
            for name, document, function, cases, ctype in (
                ("bulk", composite_bulk_program(), "record_bulk", list(range(6)), ctypes.c_uint64),
                ("tasks", composite_range_task_program(), "task_case", [0, 1, 2, 255], ctypes.c_uint8),
            ):
                checked = verify_core(document)
                ir = root / (name + ".ll")
                ir.write_text(emit_program_llvm(checked).text, encoding="ascii")
                library = root / (name + ".so")
                result = subprocess.run([CLANG, "-O2", "-shared", "-fPIC", str(ir), "-o", str(library)],
                                        capture_output=True, text=True, timeout=60)
                self.assertEqual(result.returncode, 0, result.stderr)
                native = getattr(ctypes.CDLL(str(library)), function)
                native.argtypes = [ctype]
                native.restype = ctypes.c_uint8 if name == "bulk" else ctypes.c_uint64
                for argument in cases:
                    self.assertEqual(native(argument), execute_program(checked, function, [argument])["result"])
            driver = root / "refusal.c"
            driver.write_text(r'''
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
void *__real_malloc(size_t); void *__real_calloc(size_t,size_t); void __real_free(void *);
static unsigned attempt, fail_at, live;
void *__wrap_malloc(size_t n) {
    if (++attempt == fail_at) return NULL;
    void *p = __real_malloc(n); if (p) live++; return p;
}
void *__wrap_calloc(size_t n,size_t z) {
    if (++attempt == fail_at) return NULL;
    void *p = __real_calloc(n,z); if (p) live++; return p;
}
void __wrap_free(void *p) {if (p) {if (!live) abort(); live--;} __real_free(p);}
uint8_t record_bulk(uint64_t);
int main(void) {
    for (unsigned failure=1; failure<=2; failure++) {
        attempt=0; fail_at=failure;
        if(record_bulk(0)!=250 || live!=0 || attempt!=2) return 80+failure;
    }
    return 0;
}
''', encoding="ascii")
            executable = root / "refusal"
            built = subprocess.run([CLANG, "-O2", str(root / "bulk.ll"), str(driver),
                                    "-Wl,--wrap=malloc", "-Wl,--wrap=calloc", "-Wl,--wrap=free",
                                    "-o", str(executable)], capture_output=True, text=True, timeout=60)
            self.assertEqual(built.returncode, 0, built.stderr)
            observed = subprocess.run([str(executable)], capture_output=True, timeout=30)
            self.assertEqual(observed.returncode, 0, observed.stdout + observed.stderr)


if __name__ == "__main__":
    unittest.main()
