"""Actual RV64GC/LP64D ABI, execution and fail-closed target controls."""
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
import re
import shutil
import tempfile
import unittest
from unittest.mock import patch

from hepta.clang_capture import run_bounded
from hepta.hia_program import verify_program
from hepta.hia_program_llvm import (HIAProgramLLVMRejected, TARGET_RISCV64,
                                    compile_program_llvm, emit_program_llvm)
from tools.qualify_hia_program import block, function, ret
from tools.qualify_hia_riscv64 import (C_TYPES, TYPES, expected_counts, qualify,
                                       raw_oracle, validate_qualification)

CLANG = "/usr/lib/llvm-20/bin/clang"
LINKER = "/usr/lib/llvm-20/bin/ld.lld"
READOBJ = "/usr/lib/llvm-20/bin/llvm-readobj"
QEMU = "/usr/bin/qemu-riscv64-static"


def identities(version=6):
    return {"schema": "hepta.hia.program.v" + str(version), "module": "riscv_abi",
            "functions": [function("abi_" + t, [("v", t)], [t], [],
                             [block("entry", [("v", t)], [], ret("v"))]) for t in TYPES]}


class Riscv64EmissionTests(unittest.TestCase):
    def test_all_admitted_versions_have_explicit_riscv_profiles(self):
        for version in range(1, 8):
            with self.subTest(version=version):
                core = verify_program(identities(version))
                ir = emit_program_llvm(core, target=TARGET_RISCV64)
                self.assertEqual(ir.profile, f"hepta.hia.program.llvm-linux-riscv64-lp64d-object.v{version}")
                self.assertEqual(ir.core_sha256, core.sha256)
                self.assertEqual(ir.input_sha256, core.input_sha256)
                self.assertIn('target triple = "riscv64-unknown-linux-gnu"', ir.text)

    def test_32_bit_or_unreviewed_targets_still_reject(self):
        core = verify_program(identities())
        for target in ("riscv32-unknown-linux-gnu", "riscv64-unknown-none-elf", "x86_64-pc-windows-msvc"):
            with self.subTest(target=target), self.assertRaisesRegex(HIAProgramLLVMRejected, "unsupported"):
                emit_program_llvm(core, target=target)

    def test_cross_target_shared_library_and_forged_origin_reject_before_compiler(self):
        core = verify_program(identities())
        rv = emit_program_llvm(core, target=TARGET_RISCV64)
        x86 = emit_program_llvm(core)
        with patch("hepta.hia_program_llvm.run_bounded", side_effect=AssertionError("compiler must not run")):
            with self.assertRaisesRegex(HIAProgramLLVMRejected, "relocatable"):
                compile_program_llvm(rv, program=core, output="unused.so", kind="shared")
            with self.assertRaisesRegex(HIAProgramLLVMRejected, "ORIGIN"):
                compile_program_llvm(replace(x86, target=TARGET_RISCV64), program=core,
                                     output="unused.o", kind="object")

    def test_register_oracle_distinguishes_rv64_unsigned_word_from_unsigned_byte(self):
        self.assertEqual(raw_oracle("u32", 0x80000000), 0xffffffff80000000)
        self.assertEqual(raw_oracle("u32", 0xffffffff), 0xffffffffffffffff)
        self.assertEqual(raw_oracle("u8", 255), 255)
        self.assertEqual(raw_oracle("i8", -128), 0xffffffffffffff80)


@unittest.skipUnless(all(shutil.which(x) for x in (CLANG, LINKER, READOBJ, QEMU)),
                     "actual Clang 20, LLD, LLVM reader and RV64 QEMU required")
class Riscv64NativeTests(unittest.TestCase):
    def test_integer_boundary_attributes_match_real_clang_target(self):
        text = "\n".join(f"{C_TYPES[t]} abi_{t}({C_TYPES[t]} v) {{return v;}}" for t in TYPES)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, output = root / "probe.c", root / "probe.ll"
            source.write_text(text)
            observed = run_bounded([CLANG, "--target=" + TARGET_RISCV64, "-march=rv64gc", "-mabi=lp64d",
                                    "-O1", "-S", "-emit-llvm", str(source), "-o", str(output)])
            self.assertEqual(observed.returncode, 0, observed.stderr)
            real = output.read_text()
        generated = emit_program_llvm(verify_program(identities()), target=TARGET_RISCV64).text

        def attributes(ir, name):
            header = next(line for line in ir.splitlines() if line.startswith("define ") and " @" + name + "(" in line)
            before, after = header.split(" @" + name + "(", 1)
            return re.findall(r"\b(?:signext|zeroext)\b", before), re.findall(r"\b(?:signext|zeroext)\b", after.split(")", 1)[0])

        for typ in TYPES:
            with self.subTest(typ=typ):
                self.assertEqual(attributes(generated, "abi_" + typ), attributes(real, "abi_" + typ))

    def test_altered_float_abi_flag_fails_native_publication(self):
        from hepta.hia_program_llvm import _read_artifact
        core = verify_program(identities())
        ir = emit_program_llvm(core, target=TARGET_RISCV64)

        def altered(path):
            data = bytearray(_read_artifact(path))
            data[48:52] = (1).to_bytes(4, "little")  # RVC with soft-float is a different ABI.
            return bytes(data)

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "program.o"
            with patch("hepta.hia_program_llvm._read_artifact", side_effect=altered):
                with self.assertRaisesRegex(HIAProgramLLVMRejected, "LP64D"):
                    compile_program_llvm(ir, program=core, output=output, clang=CLANG, kind="object")
            self.assertFalse(output.exists())

    def test_actual_targets_and_negative_controls_are_retained(self):
        with tempfile.TemporaryDirectory() as directory:
            report = qualify(directory=Path(directory) / "qualification", clang=CLANG,
                             linker=LINKER, qemu=QEMU, readobj=READOBJ)
            self.assertTrue(report["ok"], report.get("error"))
            self.assertEqual(report["counts"], expected_counts())
            self.assertEqual(report["counts"]["actual_c_to_hia_calls"], 212)
            self.assertEqual(report["counts"]["all_actual_c_to_hia_calls"], 233)
            self.assertEqual(len(report["recursive"]["cases"]), 21)
            self.assertEqual(report["recursive"]["negative_controls"][0]["execution"]["returncode"], 134)
            self.assertEqual([r["execution"]["returncode"] for r in report["negative_controls"]],
                             [41, 42, 91, 134, 134, 134])
            self.assertTrue(validate_qualification(report)["ok"])
            changed_ledger = deepcopy(report)
            changed_ledger["recursive"]["cases"][0]["expected"]["allocations"] = 1
            with self.assertRaisesRegex(ValueError, "recursive VM"):
                validate_qualification(changed_ledger)
            forged = deepcopy(report)
            forged["claims"]["physical_hardware_executed"] = True
            with self.assertRaises(ValueError):
                validate_qualification(forged)
            executable = Path(report["workdir"]) / "composite" / "program.elf"
            executable.write_bytes(executable.read_bytes() + b"altered")
            with self.assertRaisesRegex(ValueError, "artifact"):
                validate_qualification(report)


if __name__ == "__main__":
    unittest.main()
