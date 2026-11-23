"""Independent stage oracle; NEVER runs privileged bytes on the host."""
from __future__ import annotations
from dataclasses import replace
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from experiments.hia_x86_privileged_effect_lowering import (
    KernelEffectRejected, LeafRevoke, QuiescentOwner, admit_leaf_revoke,
    lower_leaf_revoke,
)

OWNER = QuiescentOwner(
    cpl=0, cpu_count=1, max_physical_address_bits=48,
    interrupts_masked=True, preemption_disabled=True,
    exclusive_page_table_owner=True, dma_quiescent=True,
    pcid_disabled=True, global_pages_disabled=True, la57_disabled=True,
    upper_table_links_checked=True, pte_slot_identity_mapped=True,
)
REQUEST = LeafRevoke(
    active_cr3=0x100000, pte_slot_phys=0x203008,
    virtual_page=0xffff800000400000, expected_old_pte=0x500067,
    replacement_pte=0x500066,
)

class GuardedLeafRevokeStage(unittest.TestCase):
    def test_valid_plan_deterministic_and_no_relocations(self):
        admit_leaf_revoke(OWNER, REQUEST)
        machine = lower_leaf_revoke(OWNER, REQUEST)
        self.assertEqual(machine, lower_leaf_revoke(OWNER, REQUEST))
        self.assertGreater(len(machine), 70)
        self.assertLess(len(machine), 150)
        self.assertTrue(machine.endswith(b"\xc3\x0f\x0b"))

    def test_quiescence_is_exact_and_fail_closed(self):
        for name, value in vars(OWNER).items():
            invalid = (1 if type(value) is bool else
                       (3 if name in ("cpu_count", "cpl") else 35))
            for change in (invalid, "true", None):
                with self.subTest(field=name, invalid=repr(change)):
                    with self.assertRaises(KernelEffectRejected):
                        lower_leaf_revoke(replace(OWNER, **{name: change}), REQUEST)
        for wrong in (0, 35, 53, True, "48"):
            with self.subTest(physical_width=repr(wrong)):
                with self.assertRaises(KernelEffectRejected):
                    lower_leaf_revoke(replace(OWNER, max_physical_address_bits=wrong), REQUEST)
        for obj in (None, {}, [], object()):
            with self.assertRaises(KernelEffectRejected):
                admit_leaf_revoke(obj, REQUEST)

    def test_target_faults_and_stale_word_refusals(self):
        variants = {
            "active_cr3": (0, 0x12345, 1 << 48, True, -1, "4096"),
            "pte_slot_phys": (0, 0x100000, 0x203009, 1 << 47,
                              1 << 48, True, -1),
            "virtual_page": (0x0000800000000000, 0xffff800000400001,
                             0x00007fffffffffff, -1, 1 << 64, False),
            "expected_old_pte": (0, 0x500066, 0x500167, True, -1, 1 << 64),
            "replacement_pte": (0x500067, 0x500064, 0x600066, True, -1, 1 << 64),
        }
        for field, values in variants.items():
            for value in values:
                with self.subTest(field=field, invalid=repr(value)):
                    with self.assertRaises(KernelEffectRejected):
                        lower_leaf_revoke(OWNER, replace(REQUEST, **{field: value}))
        for authority, req in ((OWNER, object()), (object(), REQUEST)):
            with self.assertRaises(KernelEffectRejected):
                lower_leaf_revoke(authority, req)
        with self.assertRaises(KernelEffectRejected):
            lower_leaf_revoke(replace(OWNER, max_physical_address_bits=40),
                              replace(REQUEST, expected_old_pte=(1 << 42) | 0x500067,
                                      replacement_pte=(1 << 42) | 0x500066))
        with self.assertRaises(KernelEffectRejected):
            lower_leaf_revoke(OWNER, replace(REQUEST, expected_old_pte=0x500167,
                                             replacement_pte=0x500166))

    @unittest.skipUnless(all(shutil.which(cmd) for cmd in ("as", "objcopy", "objdump")),
                         "GNU binutils required for independent ISA oracle")
    def test_original_direct_encoder_matches_gnu_assembler_full_sequence(self):
        req = REQUEST
        # GNU as otherwise relaxes JNE to rel8; force the existing rel32
        # branch width in the independent assembly reference.
        assembly = f""".text
.global effect_oracle
effect_oracle:
    mov %cr3, %rcx
    movabs {chr(36)}{req.active_cr3:#x}, %r8
    cmp %r8, %rcx
    .byte 0x0f, 0x85
    .long reject - . - 4
    movabs {chr(36)}{req.pte_slot_phys - 4096:#x}, %rax
    mov 4096(%rax), %r9
    movabs {chr(36)}{req.expected_old_pte:#x}, %rdx
    cmp %rdx, %r9
    .byte 0x0f, 0x85
    .long reject - . - 4
    movabs {chr(36)}{req.replacement_pte:#x}, %rdx
    mov %rdx, 4096(%rax)
    movabs {chr(36)}{req.virtual_page:#x}, %rax
    invlpg (%rax)
    ret
reject:
    ud2
"""
        with tempfile.TemporaryDirectory(prefix="hia-x86-effect-oracle-") as d:
            base = Path(d)
            (base / "ref.s").write_text(assembly)
            subprocess.run(["as", "--64", "-o", str(base / "ref.o"),
                            str(base / "ref.s")], check=True, capture_output=True)
            subprocess.run(["objcopy", "-O", "binary", "--only-section=.text",
                            str(base / "ref.o"), str(base / "ref.bin")],
                           check=True, capture_output=True)
            emitted = lower_leaf_revoke(OWNER, req)
            self.assertEqual(emitted, (base / "ref.bin").read_bytes())
            asm = subprocess.run(["objdump", "-d", "-M", "intel",
                                  str(base / "ref.o")], check=True,
                                 capture_output=True, text=True).stdout
            for mnemonic in ("cr3", "cmp", "jne", "invlpg", "ud2", "ret"):
                self.assertIn(mnemonic, asm)
            self.assertEqual(asm.count("ud2"), 1)
            self.assertEqual(asm.count("jne"), 2)

    def test_regular_core_still_rejects_all_privileged_effects(self):
        from hepta.hia_machine_x64 import Code, PrivilegedCode
        from hepta.hia_opcodes import EFFECTS, OPCODES
        self.assertEqual(EFFECTS, {"alloc", "read", "write", "trap"})
        self.assertFalse(hasattr(Code(), "read_cr3"))
        self.assertTrue(hasattr(PrivilegedCode(), "read_cr3"))
        for name in ("read_cr3", "write_cr3", "invlpg", "write_pte"):
            self.assertNotIn("x86." + name, OPCODES)

if __name__ == "__main__":
    unittest.main()
