"""Independent refusal controls for the isolated x86 TLB effect admission."""
from __future__ import annotations

import copy
import unittest

from experiments.hia_kernel_tlb_effects_staging import (
    KernelEffectRejected, PageTableEffectSummary, admit_single_cpu_tlb_sequence,
)


ROOT = 0x1000
VA = 0x400000
HI = 0xffff800000001000


def sequence(va=VA):
    return [
        {"op": "irq.disable"},
        {"op": "pte.write", "va": va, "expected_old": 0x23,
         "observed_old": 0x23, "candidate": 0x21},
        {"op": "tlb.invlpg", "va": va},
        {"op": "irq.enable"},
    ]


def admit(steps, **overrides):
    opts = {"active_cr3": ROOT, "owned_root": ROOT, "cpl": 0,
            "cpu_count": 1, "pcid_enabled": False, "global_pages": False}
    opts.update(overrides)
    return admit_single_cpu_tlb_sequence(steps, **opts)


class SingleCpuKernelTlbStaging(unittest.TestCase):
    def test_balanced_user_and_kernel_addresses(self):
        for va in (VA, HI):
            with self.subTest(va=hex(va)):
                self.assertEqual(admit(sequence(va)),
                                 PageTableEffectSummary(1, 1, 1, (va,)))

    def test_multiple_distinct_pages_and_multiple_mask_windows(self):
        steps = sequence(VA) + sequence(HI)
        self.assertEqual(admit(steps),
                         PageTableEffectSummary(2, 2, 2, (VA, HI)))
        mixed = [sequence(VA)[0], sequence(VA)[1],
                 {"op": "pte.write", "va": HI, "expected_old": 1,
                  "observed_old": 1, "candidate": 0},
                 {"op": "tlb.invlpg", "va": HI}, sequence(VA)[2], sequence(VA)[3]]
        self.assertEqual(admit(mixed).invalidations, 2)

    def test_order_and_refusal_controls(self):
        base = sequence()
        variations = {
            "write-before-mask": base[1:],
            "missing-flush": [base[0], base[1], base[3]],
            "wrong-flush": [base[0], base[1],
                            {"op": "tlb.invlpg", "va": HI}, base[3]],
            "unmask-before-flush": [base[0], base[1], base[3], base[2]],
            "extra-flush": base[:3] + [base[2], base[3]],
            "double-mask": [base[0]] + base,
            "double-unmask": base + [base[3]],
            "missing-unmask": base[:3],
            "repeated-write-before-flush": [base[0], base[1], base[1], base[2], base[3]],
            "no-change": [base[0], base[3]],
            "unapproved-cr3": [base[0], {"op": "cr3.write", "value": ROOT}, base[3]],
            "iretq": [base[0], {"op": "iretq"}, base[3]],
        }
        for label, steps in variations.items():
            with self.subTest(label=label):
                with self.assertRaises(KernelEffectRejected):
                    admit(steps)

    def test_repeated_page_requires_exact_plan_dataflow(self):
        # The intervening invalidation does not restore the old PTE word.
        second = sequence(VA)
        second[1]["expected_old"] = 0x21
        second[1]["observed_old"] = 0x21
        second[1]["candidate"] = 0x01
        chained = sequence(VA) + second
        self.assertEqual(admit(chained),
                         PageTableEffectSummary(2, 2, 2, (VA,)))

        # A different page can still be edited between these two writes.
        separated = sequence(VA) + sequence(HI) + second
        self.assertEqual(admit(separated),
                         PageTableEffectSummary(3, 3, 3, (VA, HI)))

        # A repeated caller-supplied snapshot remains stale after INVLPG.
        for bad in (
            sequence(VA) + sequence(VA),
            sequence(VA)[:3] + sequence(VA)[1:],
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(KernelEffectRejected):
                    admit(bad)

    def test_replayed_old_word_cannot_be_cured_by_forged_readback(self):
        second = sequence(VA)
        second[1]["expected_old"] = 0x23
        second[1]["observed_old"] = 0x23
        second[1]["candidate"] = 0x01
        with self.assertRaises(KernelEffectRejected):
            admit(sequence(VA) + second)

        # Also refuse a claimant that merely relabels the observed word
        # without updating the requested expected old word.
        second[1]["observed_old"] = 0x21
        with self.assertRaises(KernelEffectRejected):
            admit(sequence(VA) + second)

    def test_stale_full_old_and_untrusted_fields(self):
        for field, replacement in (
            ("expected_old", 0x22), ("observed_old", 0x22),
            ("candidate", 0x23), ("candidate", -1),
            ("candidate", 1 << 64), ("expected_old", True),
            ("va", VA + 1), ("va", 0x0000800000000000),
            ("va", "0x400000"), ("va", True),
        ):
            with self.subTest(field=field, replacement=replacement):
                bad = copy.deepcopy(sequence())
                bad[1][field] = replacement
                with self.assertRaises(KernelEffectRejected):
                    admit(bad)
        for value in (None, True, -1, 1 << 64):
            with self.subTest(value=value):
                with self.assertRaises(KernelEffectRejected):
                    admit(sequence(), active_cr3=value)
        for bad in ([], [{}], "not-steps", tuple(sequence() * 33)):
            with self.subTest(steps=str(bad)[:20]):
                with self.assertRaises(KernelEffectRejected):
                    admit(bad)

    def test_false_authority_and_unsupported_cpu_modes(self):
        variants = (
            {"active_cr3": 0x2000}, {"owned_root": 0x2000},
            {"active_cr3": 0}, {"active_cr3": ROOT + 1},
            {"active_cr3": 1 << 52},
            {"cpl": 3}, {"cpl": True}, {"cpu_count": 2},
            {"cpu_count": 0}, {"cpu_count": True},
            {"pcid_enabled": True}, {"global_pages": True},
            {"pcid_enabled": 0}, {"global_pages": 0},
        )
        for opts in variants:
            with self.subTest(opts=opts):
                with self.assertRaises(KernelEffectRejected):
                    admit(sequence(), **opts)

    def test_fail_closed_on_extra_fields_and_unbounded_plans(self):
        for index, key in ((0, "unexpected"), (1, "external"), (2, "root"), (3, "value")):
            bad = copy.deepcopy(sequence())
            bad[index][key] = ROOT
            with self.subTest(step=index):
                with self.assertRaises(KernelEffectRejected):
                    admit(bad)
        bad = copy.deepcopy(sequence())
        bad[2] = {"op": "tlb.invlpg", "va": VA + 0x1000}
        with self.assertRaises(KernelEffectRejected):
            admit(bad)


if __name__ == "__main__":
    unittest.main()
