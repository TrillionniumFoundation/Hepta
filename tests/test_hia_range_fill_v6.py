"""v6: partial byte fill through a verified unique loan, VM and emitted LLVM."""
from __future__ import annotations

import copy
import ctypes
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import tempfile
import unittest

from hepta.hia_program import (
    SCHEMA, SCHEMA_V2, SCHEMA_V3, SCHEMA_V4, SCHEMA_V5, SCHEMA_V6,
    HIAProgramRejected, verify_program,
)
from hepta.hia_program_runtime import HIAProgramTrap, execute_program
from hepta.hia_program_llvm import (
    PROFILE_V6, PROFILE_AARCH64_V6, TARGET_AARCH64,
    emit_program_llvm, _can_elide_zero_initialization,
)


def param(name, typ):
    return {"name": name, "type": typ}


def ins(op, args=(), out=(), **attrs):
    return {"op": op, "args": list(args),
            "out": [param(*p) for p in out], "attrs": attrs}


def fill_program(schema=SCHEMA_V6, *, read=True):
    params = [param(name, typ) for name, typ in (
        ("length", "usize"), ("offset", "usize"), ("count", "usize"),
        ("value", "u8"), ("probe", "usize"))]
    ops = [
        ins("buffer.new", ["length"], [("owner", "buffer")]),
        ins("borrow.mut", ["owner"], [("writer", "mutbuf")]),
        ins("buffer.fill_range", ["writer", "offset", "count", "value"]),
    ]
    if read:
        ops.append(ins("buffer.load", ["writer", "probe"], [("answer", "u8")]))
    else:
        ops.append(ins("const", out=[("answer", "u8")], value=9))
    ops += [
        ins("loan.end", ["writer"]),
        ins("owner.drop", ["owner"]),
    ]
    return {
        "schema": schema, "module": "range_fill_v6",
        "functions": [{
            "name": "fill_range", "params": params, "returns": ["u8"],
            "effects": ["alloc", "write", "trap"] + (["read"] if read else []),
            "entry": "entry",
            "blocks": [{"id": "entry", "params": copy.deepcopy(params),
                        "ops": ops, "term": {"op": "ret", "values": ["answer"]}}],
        }],
    }


class V6RangeFillTests(unittest.TestCase):
    def test_exact_partial_mutation_and_cleanup(self):
        checked = verify_program(fill_program())
        self.assertEqual(checked.as_dict()["schema"], SCHEMA_V6)
        for n, offset, count, value, probe, expected in (
            (5, 1, 3, 7, 0, 0),
            (5, 1, 3, 7, 1, 7),
            (5, 1, 3, 7, 3, 7),
            (5, 1, 3, 7, 4, 0),
            (5, 5, 0, 7, 4, 0),
            (1, 0, 0, 99, 0, 0),
            (1, 0, 1, 99, 0, 99),
        ):
            with self.subTest(n=n,offset=offset,count=count,probe=probe):
                receipt = execute_program(checked, "fill_range", [n, offset, count, value, probe])
                self.assertEqual(receipt["result"], expected)
                self.assertEqual(receipt["resources"]["live_owners"], 0)
                self.assertEqual(receipt["resources"]["live_local_loans"], 0)
                self.assertEqual(receipt["resources"]["allocations"], receipt["resources"]["frees"])

    def test_zero_length_owner_never_dereferenced(self):
        candidate = fill_program(read=False)
        result = execute_program(candidate, "fill_range", [0, 0, 0, 71, 0])
        self.assertEqual(result["result"], 9)
        self.assertEqual(result["resources"]["allocations"], 0)
        self.assertEqual(result["resources"]["frees"], 0)

    def test_rejected_oob_and_overflow_before_writes(self):
        for n, offset, count in ((0, 1, 0), (5, 6, 0), (5, 4, 2),
                                  (5, 2, 2**64 - 1)):
            with self.subTest(n=n,offset=offset,count=count):
                with self.assertRaises(HIAProgramTrap) as trap:
                    execute_program(fill_program(read=False), "fill_range",
                                    [n, offset, count, 7, 0])
                self.assertEqual(trap.exception.code, "bounds")

    def test_all_old_schema_versions_reject_new_instruction(self):
        for schema in (SCHEMA, SCHEMA_V2, SCHEMA_V3, SCHEMA_V4, SCHEMA_V5):
            with self.subTest(schema=schema):
                with self.assertRaisesRegex(HIAProgramRejected, "E_HIA_OPCODE"):
                    verify_program(fill_program(schema))

    def test_permission_types_effects_and_unknown_attributes_fail_closed(self):
        templates = []
        doc = fill_program()
        doc["functions"][0]["blocks"][0]["ops"][2]["args"][0] = "owner"
        templates.append(doc)
        doc = fill_program()
        doc["functions"][0]["blocks"][0]["ops"][2]["args"][3] = "count"
        templates.append(doc)
        doc = fill_program()
        doc["functions"][0]["effects"].remove("write")
        templates.append(doc)
        doc = fill_program()
        doc["functions"][0]["effects"].remove("trap")
        templates.append(doc)
        doc = fill_program()
        doc["functions"][0]["blocks"][0]["ops"][2]["attrs"]["assumed_in_bounds"] = True
        templates.append(doc)
        for index, doc in enumerate(templates):
            with self.subTest(index=index):
                with self.assertRaises(HIAProgramRejected):
                    verify_program(doc)

    def test_native_llvm_origin_profile_and_bounds_structure(self):
        checked = verify_program(fill_program())
        result = emit_program_llvm(checked)
        self.assertEqual(result.profile, PROFILE_V6)
        self.assertEqual(result.core_sha256, checked.sha256)
        self.assertIn("declare void @llvm.memset.p0.i64(", result.text)
        self.assertIn("fill_nonempty_", result.text)
        self.assertIn("fill_after_", result.text)
        self.assertIn("call void @llvm.memset.p0.i64(", result.text)
        self.assertIn("icmp ule i64 ", result.text)
        self.assertFalse(_can_elide_zero_initialization(fill_program()["functions"][0]))
        target = emit_program_llvm(checked, target=TARGET_AARCH64)
        self.assertEqual(target.profile, PROFILE_AARCH64_V6)

    def test_fixed_aarch64_v6_driver_has_exact_checked_abi(self):
        # Builds the reviewed C driver from verified Core. No QEMU or physical
        # execution is claimed by inspecting its generated source.
        from hepta.hia_program_aarch64 import _runtime_source, _RANGE_FILL_CASES
        candidate = verify_program(fill_program())
        runtime, required = _runtime_source(candidate.as_dict(), "range_fill")
        self.assertEqual(required, {"fill_range"})
        self.assertEqual(len(_RANGE_FILL_CASES), 8)
        self.assertIn("extern hepta_u8 fill_range(", runtime)
        self.assertIn("successful_allocations != 8", runtime)
        self.assertIn("outstanding != 0", runtime)
        self.assertIn("_start(void)", runtime)

    def test_real_emitted_llvm_native_and_abort(self):
        compiler = shutil.which("clang")
        if compiler is None or platform.system() != "Linux" or platform.machine() not in ("x86_64", "amd64"):
            self.skipTest("native x86-64 LLVM execution requires Clang")
        for read in (True, False):
            checked = verify_program(fill_program(read=read))
            llvm = emit_program_llvm(checked)
            with tempfile.TemporaryDirectory(prefix="hia-v6-native-") as temporary:
                root = Path(temporary)
                ir = root / "input.ll"
                library = root / "libfill.so"
                ir.write_text(llvm.text, encoding="ascii")
                compiled = subprocess.run(
                    [compiler, "-x", "ir", "-O2", "-shared", "-fPIC",
                     str(ir), "-o", str(library)],
                    capture_output=True, text=True, timeout=60)
                self.assertEqual(compiled.returncode, 0, compiled.stderr)
                native = ctypes.CDLL(str(library)).fill_range
                native.argtypes = [ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64,
                                   ctypes.c_uint8, ctypes.c_uint64]
                native.restype = ctypes.c_uint8
                cases = ([(0, 0, 0, 7, 0), (5, 1, 3, 7, 1),
                          (5, 1, 3, 7, 4), (5, 5, 0, 7, 4),
                          (1, 0, 1, 99, 0)] if not read
                         else [(5, 1, 3, 7, 0), (5, 1, 3, 7, 1),
                               (5, 1, 3, 7, 4), (5, 5, 0, 7, 4),
                               (1, 0, 1, 99, 0)])
                for args in cases:
                    with self.subTest(read=read, args=args):
                        expected = execute_program(checked, "fill_range", list(args))["result"]
                        self.assertEqual(native(*args), expected)
                if read:
                    continue
                negative = root / "negative.c"
                executable = root / "negative"
                negative.write_text(
                    "#include <stdint.h>\n"
                    "uint8_t fill_range(uint64_t,uint64_t,uint64_t,uint8_t,uint64_t);\n"
                    "int main(void){return fill_range(5,4,2,7,0);}\n",
                    encoding="utf-8")
                linked = subprocess.run([compiler, str(negative), str(library),
                                         "-Wl,-rpath," + str(root), "-o", str(executable)],
                                        capture_output=True, text=True, timeout=60)
                self.assertEqual(linked.returncode, 0, linked.stderr)
                observed = subprocess.run([str(executable)], capture_output=True, timeout=30)
                self.assertEqual(observed.returncode, -signal.SIGABRT)


if __name__ == "__main__":
    unittest.main()
