"""Parameter identity is separate from a view's graph position and byte contents."""
from __future__ import annotations

import unittest

from hepta.hia_agent_assembly import assemble_program
from hepta.hia_program import HIAProgramRejected, execute_program
from tools.hia_selfhost_loans import reference_source
from tools.hia_selfhost_returned_loans import cases, refusals


class SelfhostReturnedLoanSourceTests(unittest.TestCase):
    def test_real_views_survive_calls_cfg_and_tail_renaming_with_closed_ledgers(self):
        rows = cases()
        self.assertEqual(len(rows), 36)
        self.assertEqual({r["program"] for r in rows}, {
            "loan-" + mode + "-" + shape for mode in ("read", "mut")
            for shape in ("forward", "child", "cfg", "tail")} | {"loan-backward",
                "loan-shared-three-slots", "loan-swapped-formals", "loan-caller-owned-parent"})
        for row in rows:
            with self.subTest(case=row["id"]):
                observed = execute_program(assemble_program(reference_source(row)), "reference_entry", [])
                self.assertEqual(observed["values"], [0, *bytes.fromhex(row["expected_hex"])])
                self.assertEqual(observed["resources"]["live_owners"], 0)
                self.assertEqual(observed["resources"]["live_local_loans"], 0)
        # One source per native compiled-program cache key, regardless of input.
        for name in {row["program"] for row in rows}:
            self.assertEqual(len({row["source"] for row in rows if row["program"] == name}), 1)

    def test_malformed_or_unbound_contracts_are_real_core_refusals(self):
        for row in refusals():
            with self.subTest(case=row["id"]), self.assertRaises(HIAProgramRejected):
                assemble_program(row["source"].encode())

    def test_origin_tables_do_not_overlap_or_expand_workspace(self):
        from tools.generate_hia_selfhost import QBASE, ORIGINBASE, BLOCKORIGIN
        self.assertEqual(QBASE + 256 * 8, ORIGINBASE)
        self.assertEqual(ORIGINBASE + 2048, BLOCKORIGIN)
        self.assertLessEqual(BLOCKORIGIN + 1536 * 16, 1048576)


if __name__ == "__main__":
    unittest.main()
