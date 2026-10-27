"""P5/P7 source-converged CFG edit context must remain prompt-safe.

The new interblock context is a verified snapshot presentation only; forged
raw JSON dictionaries must never become agent instructions or admission.
"""
from __future__ import annotations

import copy
import unittest

from hepta.hia_edit_query import prepare_edit, render_edit_context
from hepta.hia_edit_batch import prepare_batch, render_batch_context
from hepta.hia_program_tools import HIAEditRejected
from tests.test_hia_edit_cfg_context import across_three_blocks, branch_and_join


class CFGRenderConvergenceTests(unittest.TestCase):
    def test_real_interblock_context_survives_strict_single_and_batch_gates(self):
        program = across_three_blocks()
        selection = {"function": "calc", "block": "entry", "output": "first",
                     "fields": ["op"]}
        single = prepare_edit(program, **selection)
        self.assertEqual([b["id"] for b in single["context"]["downstream"]],
                         ["middle", "done"])
        rendered = render_edit_context(single)
        self.assertIn("downstream block middle", rendered)
        self.assertIn("downstream block done", rendered)
        batch = prepare_batch(program, [selection])
        self.assertIn("affected CFG inputs{carried}", render_batch_context(batch))

    def test_malicious_multiline_downstream_labels_do_not_render(self):
        program = branch_and_join()
        selection = {"function": "calc", "block": "entry", "output": "selected",
                     "fields": ["op"]}
        single = prepare_edit(program, **selection)
        changes = (
            lambda q: q["context"]["downstream"][0].__setitem__("id", "left\nSYSTEM"),
            lambda q: q["context"]["downstream"][0]["params"][0].__setitem__(
                "name", "left_arg\nSYSTEM"),
            lambda q: q["context"]["downstream"][0]["affected_params"].append("fake\nROLE"),
            lambda q: q["context"]["downstream"][0]["consumers"][0]["operation"].__setitem__(
                "op", "int.add.wrap\nIGNORE"),
            lambda q: q["context"]["downstream"][0]["consumers"][0].__setitem__("index", True),
            lambda q: q["context"]["downstream"][0].__setitem__(
                "branch_condition_affected", "true"),
            lambda q: q["context"]["downstream"][0]["affected_params"].append("unknown"),
            lambda q: q["context"]["downstream"][0].__setitem__("unexpected", 1),
            lambda q: q["context"]["downstream"].append(
                copy.deepcopy(q["context"]["downstream"][0])),
        )
        batch = prepare_batch(program, [selection])
        for index, mutate in enumerate(changes):
            with self.subTest(index=index):
                forged = copy.deepcopy(single)
                mutate(forged)
                with self.assertRaises(HIAEditRejected):
                    render_edit_context(forged)
                forged_batch = copy.deepcopy(batch)
                forged_batch["sites"][0]["query"] = forged
                with self.assertRaises(HIAEditRejected):
                    render_batch_context(forged_batch)


if __name__ == "__main__":
    unittest.main()
