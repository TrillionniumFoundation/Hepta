"""Real kernel-profile boundaries; native tests inspect the actual HIA object.

These local tests are development validation, not a Linux boot qualification.
"""
from __future__ import annotations

import copy
import gzip
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import struct
import tempfile
import unittest

from hepta.hia_program_source import lower_source
from hepta.hia_program_llvm import emit_program_llvm
from hepta.clang_capture import run_bounded
from hepta.hia_linux_kernel import (KernelProfileRejected, build_kernel_object,
                                   config_profile, inspect_kernel_object, kernel_ir, qualify_leaf,
                                   reinspect_kernel_object, _sections)
from tools.qualify_hia_linux_component import (ASSETS, CALLS, WRAPPER, expected_digest, inputs,
                                               overlays, prove_arithmetic, verify_linked_route, verify_boot_payload,
                                               binding, apply_overlay, validate_applied_overlay)

CONFIG = b"""CONFIG_X86_64=y
CONFIG_64BIT=y
CONFIG_CC_IS_CLANG=y
CONFIG_MITIGATION_RETHUNK=y
CONFIG_X86_KERNEL_IBT=y
CONFIG_CALL_PADDING=y
CONFIG_FUNCTION_ALIGNMENT=16
CONFIG_FUNCTION_PADDING_BYTES=16
"""
CLANG = os.environ.get("HIA_KERNEL_CLANG", os.environ.get("CLANG", "/usr/lib/llvm-20/bin/clang"))
OBJDUMP = os.environ.get("HIA_KERNEL_OBJDUMP", "llvm-objdump")


def source(expression):
    return 'module t; export "C" fn f(w:u32)->u32 effects {panic} {return ' + expression + ';}'


class KernelLeafAdmissionTests(unittest.TestCase):
    def test_hweight_enters_independent_core_with_exact_u32_interface(self):
        core = qualify_leaf(lower_source((ASSETS / "hweight32.hepta").read_text()))
        self.assertEqual(core.as_dict()["exports"], ["hia_sw_hweight32"])
        self.assertEqual(core.as_dict()["functions"][0]["returns"], ["u32"])

    def test_variable_or_out_of_range_shift_does_not_become_a_kernel_trap(self):
        for expression in ("w >> w", "w >> 32", "w + 1"):
            with self.subTest(expression=expression), self.assertRaises(KernelProfileRejected):
                qualify_leaf(lower_source(source(expression)))
        qualify_leaf(lower_source(source("w >> 31")))

    def test_memory_and_calls_reject_instead_of_using_a_hosted_runtime(self):
        program = lower_source('''module t;
export "C" fn f(w:u32)->u32 effects {panic} {return g(w);}
export "C" fn g(w:u32)->u32 effects {} {return w;}
''')
        with self.assertRaises(KernelProfileRejected):
            qualify_leaf(program)

    def test_exact_configuration_rejects_unimplemented_instrumentation(self):
        for extra in (b"CONFIG_CFI=y\n", b"CONFIG_LTO_CLANG=y\n", b"CONFIG_KMSAN=y\n", b"CONFIG_X86_64=y\n"):
            with self.subTest(extra=extra), self.assertRaises(KernelProfileRejected):
                config_profile(CONFIG + extra)

    def test_kernel_attributes_are_separate_from_hosted_llvm(self):
        core = lower_source(source("w >> 1"))
        old = emit_program_llvm(core)
        ir = kernel_ir(core, CONFIG)
        self.assertIn("noredzone", ir["text"])
        self.assertIn("fn_ret_thunk_extern", ir["text"])
        self.assertIn('!"cf-protection-branch"', ir["text"])
        self.assertIn('"patchable-function-prefix"="16"', ir["text"])
        self.assertEqual(emit_program_llvm(core), old)
        self.assertNotIn("noredzone", old.text)

    def test_full_registered_differential_denominator_is_deterministic(self):
        rows = list(inputs())
        self.assertEqual(len(rows), CALLS)
        self.assertEqual(rows[:65536], list(range(65536)))
        self.assertEqual(rows[65536:131072], [0xffffffff ^ i for i in range(65536)])
        self.assertEqual(len(expected_digest()), 16)

    def test_formula_rejects_a_wrong_body_and_records_the_actual_smt_query(self):
        with tempfile.TemporaryDirectory() as temp:
            result = prove_arithmetic(lower_source(source("w")), Path(temp))
            self.assertEqual(result["status"], "FAIL")
            self.assertEqual(result["verdict"], "sat")
            self.assertTrue((Path(temp) / "popcount-equivalence.smt2").is_file())
            self.assertFalse(result["backend_or_source_refinement_proved"])

    def test_overlay_replaces_real_x86_route_and_preserves_64bit_body(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            linux, out = root / "linux", root / "out"
            (linux / "arch/x86/lib").mkdir(parents=True)
            original = """SYM_FUNC_START(__sw_hweight32)
old_arithmetic
SYM_FUNC_END(__sw_hweight32)
SYM_FUNC_START(__sw_hweight64)
unchanged64
SYM_FUNC_END(__sw_hweight64)
"""
            (linux / "arch/x86/lib/hweight.S").write_text(original)
            (linux / "arch/x86/lib/Makefile").write_text("obj-y += hweight.o\n")
            obj = root / "prepared.o"
            obj.write_bytes(b"only-a-fixture-not-native-evidence")
            artifact = {"path": str(obj), "sha256": sha256(obj.read_bytes()).hexdigest(), "config": {"sha256": "c" * 64}}
            manifest = overlays(linux, out, artifact, "a" * 64)
            patched = (out / "hybrid-overlay/arch/x86/lib/hweight.S").read_text()
            self.assertNotIn("old_arithmetic", patched)
            self.assertIn("call hia_sw_hweight32", patched)
            self.assertIn("unchanged64", patched)
            self.assertIn("\tRET", patched)
            self.assertEqual((linux / "arch/x86/lib/hweight.S").read_text(), original)
            makefile = (out / "hybrid-overlay/arch/x86/lib/Makefile").read_text()
            self.assertIn("$(cmd_objtool)", makefile)
            self.assertNotIn("OBJECT_FILES_NON_STANDARD", makefile)
            for arm in ("control", "hybrid"):
                self.assertEqual((out / (arm + "-overlay/arch/x86/lib/hia_component_selftest.c")).read_bytes(),
                                 (ASSETS / "guest_selftest.c").read_bytes())
            self.assertEqual(set(manifest), {"control", "hybrid"})
            # Overlay-only fixture: no assertion that its placeholder object
            # is native code or that a kernel was booted.
            component = {"status": "PASS", "overlays": manifest, "artifact": artifact,
                         "source": {"linux_source": str(linux), "files": {
                             path: binding(linux / path) for path in ("arch/x86/lib/hweight.S", "arch/x86/lib/Makefile")}}}
            prepared = root / "PREPARED.json"
            prepared.write_text(json.dumps(component))
            copied = root / "source-copy"
            shutil.copytree(linux, copied)
            applied = root / "APPLIED.json"
            result = apply_overlay(prepared, "hybrid", copied, applied)
            self.assertEqual(validate_applied_overlay(component, binding(applied))["file_count"], 7)
            for name, files in (("empty", []), ("missing", result["files"][:-1]),
                                ("duplicated", result["files"] + result["files"][:1])):
                false_receipt = root / (name + ".json")
                false_receipt.write_text(json.dumps({**result, "files": files}))
                with self.subTest(name=name), self.assertRaises(KernelProfileRejected):
                    validate_applied_overlay(component, binding(false_receipt))


@unittest.skipUnless(shutil.which(CLANG) and shutil.which(OBJDUMP), "actual Clang20+ / llvm-objdump required")
class ActualKernelObjectTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.folder = Path(cls.temporary.name)
        cls.program = lower_source((ASSETS / "hweight32.hepta").read_text())
        cls.log = []
        cls.receipt = build_kernel_object(cls.program, cls.folder / "hia.o", config=CONFIG,
                                          clang=CLANG, objdump=OBJDUMP, command_log=cls.log)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_real_object_has_required_mitigations_and_no_hosted_fallback(self):
        receipt = self.receipt
        self.assertEqual(receipt["inspection"]["undefined"], ["__x86_return_thunk"])
        self.assertEqual(receipt["inspection"]["return_thunk_relocations"], 1)
        self.assertEqual(sum(i["op"] == "endbr64" for i in receipt["inspection"]["instructions"]), 1)
        self.assertFalse(receipt["claims"]["c_codegen_used"])
        self.assertFalse(receipt["claims"]["fallback_used"])
        self.assertFalse(receipt["claims"]["guest_execution_qualified"])
        self.assertGreaterEqual(len(self.log), 3)

    def test_disassembly_cannot_hide_a_changed_stack_instruction_or_missing_bytes(self):
        data = (self.folder / "hia.o").read_bytes()
        text = self.receipt["disassembly"]
        damaged = text.replace("%edi, %eax", "(%rsp), %eax", 1)
        with self.assertRaises(KernelProfileRejected):
            inspect_kernel_object(data, damaged, ["hia_sw_hweight32"], self.receipt["config"])
        lines = text.splitlines()
        removed = next(i for i, line in enumerate(lines) if "shrl" in line)
        with self.assertRaises(KernelProfileRejected):
            inspect_kernel_object(data, "\n".join(lines[:removed] + lines[removed + 1:]),
                                  ["hia_sw_hweight32"], self.receipt["config"])

    def test_saved_mnemonic_or_relocation_labels_cannot_qualify_changed_bytes(self):
        raw = (self.folder / "hia.o").read_bytes()
        sections = _sections(raw)
        for name in ("privileged", "relocation"):
            forged, data = copy.deepcopy(self.receipt), bytearray(raw)
            if name == "privileged":
                mov = next(i for i in forged["inspection"]["instructions"] if i["bytes"] == "89f8")
                at = sections[".text"]["offset"] + mov["offset"]
                data[at:at + 2] = b"\xfa\xfb"  # CLI; STI, never executed.
                old = next(line for line in forged["disassembly"].splitlines() if "89 f8" in line)
                forged["disassembly"] = forged["disassembly"].replace(old, f' {mov["offset"]:x}: fa fb  nop', 1)
            else:
                # Change the actual ELF relocation while retaining a saved
                # R_X86_64_PLT32 text label. Fresh objdump must see PC32.
                at = sections[".rela.text"]["offset"] + 8
                data[at:at + 4] = (2).to_bytes(4, "little")
            path = self.folder / (name + ".o")
            path.write_bytes(data)
            forged.update(path=str(path), sha256=sha256(data).hexdigest(), bytes=len(data))
            with self.subTest(name=name), self.assertRaises(KernelProfileRejected):
                reinspect_kernel_object(forged)

    def test_fresh_native_memory_trap_and_callee_saved_mutants_reject(self):
        raw = (self.folder / "hia.o").read_bytes()
        start = next(i["offset"] for i in self.receipt["inspection"]["instructions"] if i["bytes"] == "89f8")
        text_at = _sections(raw)[".text"]["offset"]
        # Exact machine mutations are only disassembled, never executed.
        mutants = {"absolute-memory": b"\x8b\x04\x25\0\0\0\0",
                   "entry-int3": b"\xcc", "callee-saved": b"\x89\xfb",
                   "return-pop": b"\xc2\x08\x00"}
        for name, mutation in mutants.items():
            covered = 0
            for instruction in self.receipt["inspection"]["instructions"]:
                if instruction["offset"] >= start:
                    covered += len(bytes.fromhex(instruction["bytes"]))
                    if covered >= len(mutation):
                        break
            data = bytearray(raw)
            data[text_at + start:text_at + start + covered] = mutation + b"\x90" * (covered - len(mutation))
            path = self.folder / (name + ".o")
            path.write_bytes(data)
            forged = {**self.receipt, "path": str(path), "sha256": sha256(data).hexdigest(), "bytes": len(data)}
            with self.subTest(name=name), self.assertRaises(KernelProfileRejected):
                reinspect_kernel_object(forged)

    def test_core_math_all_u32_matches_independent_popcount_formula(self):
        target = self.folder / "formula"
        target.mkdir()
        result = prove_arithmetic(self.program, target)
        self.assertEqual(result["verdict"], "unsat")
        self.assertEqual(result["status"], "PASS")

    def test_actual_linked_bridge_calls_the_hia_bytes_and_wrong_route_rejects(self):
        # A host ELF fixture validates byte/relocation readback, not Linux boot.
        macros = """#define SYM_FUNC_START(n) .globl n; .type n,@function; n:
#define SYM_FUNC_END(n) .size n,.-n
#define ANNOTATE_NOENDBR
#define RET jmp __x86_return_thunk
.text
"""
        stubs = """
SYM_FUNC_START(__sw_hweight64)
xorl %eax,%eax
ret
SYM_FUNC_END(__sw_hweight64)
SYM_FUNC_START(hia_hweight_abi_probe)
xorl %eax,%eax
ret
SYM_FUNC_END(hia_hweight_abi_probe)
.section .note.GNU-stack,"",@progbits
"""
        main = self.folder / "driver.c"
        main.write_text('extern unsigned int __sw_hweight32(unsigned int); int main(void){return __sw_hweight32(0x80000003u)!=3;}\n')
        for name, bridge in (("correct", WRAPPER), ("misrouted", WRAPPER.replace("call hia_sw_hweight32", "call __sw_hweight64"))):
            assembly, executable = self.folder / (name + ".S"), self.folder / name
            assembly.write_text(macros + bridge + stubs)
            built = run_bounded([CLANG, "-no-pie", str(main), str(assembly), str(self.folder / "hia.o"),
                                 str(ASSETS / "host_return_thunk.S"), "-o", str(executable)])
            self.assertEqual(built.returncode, 0, built.stderr)
            observed = run_bounded([str(executable)])
            component = {"artifact": self.receipt}
            if name == "correct":
                self.assertEqual(observed.returncode, 0, observed.stderr)
                linked = verify_linked_route(component, executable, self.folder / "hia.o")
                self.assertTrue(linked["actual_kernel_symbol_calls_hia_body"])
            else:
                self.assertNotEqual(observed.returncode, 0)
                with self.assertRaises(KernelProfileRejected):
                    verify_linked_route(component, executable, self.folder / "hia.o")
        # The compressed fixture is not booted and is not a Linux image claim.
        # It checks boot-header payload addressing and loaded ELF code identity,
        # including refusal of a stale declared payload plus unused good bytes.
        def image(payload, extra=b""):
            compressed = gzip.compress(payload, mtime=0)
            header = bytearray(3072)
            header[0x1f1] = 4
            header[0x1fe:0x200] = b"\x55\xaa"
            header[0x202:0x206] = b"HdrS"
            struct.pack_into("<H", header, 0x206, 0x20f)
            struct.pack_into("<II", header, 0x248, 512, len(compressed))
            return header + compressed + extra
        observed = self.folder / "payload.fixture"
        good = (self.folder / "correct").read_bytes()
        observed.write_bytes(image(good))
        self.assertEqual(verify_boot_payload(observed, linked["linked_functions"])["status"], "PASS")
        observed.write_bytes(image((self.folder / "misrouted").read_bytes(), gzip.compress(good, mtime=0)))
        with self.assertRaises(KernelProfileRejected):
            verify_boot_payload(observed, linked["linked_functions"])


if __name__ == "__main__":
    unittest.main()
