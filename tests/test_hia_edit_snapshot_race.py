"""Caller mutation cannot rebind a prepared query after the input is frozen.

The hooks arrange an actual mutable-dict interleaving; the verifier, query
builder and patch verifier all execute their real implementations.
"""
from copy import deepcopy
import unittest
from unittest.mock import patch

import hepta.hia_edit_batch as batch
import hepta.hia_edit_query as single
from hepta.hia_program import execute_program, verify_program
from hepta.hia_program_tools import HIAEditRejected
from tools.qualify_hia_program import block, function, operation, ret


def source(bias=10):
    return {"schema": "hepta.hia.program.v6", "module": "mutable_snapshot", "functions": [
        function("work", [], ["u32"], [], [block("entry", [], [
            operation("const", out=[("factor", "u32")], value=1),
            operation("const", out=[("bias", "u32")], value=bias),
            operation("int.add.wrap", ["factor", "bias"], [("result", "u32")]),
        ], ret("result"))])
    ]}


SELECTION = {"function": "work", "block": "entry", "output": "factor", "fields": ["attrs"]}


class EditSnapshotRaceTests(unittest.TestCase):
    def exercise(self, *, atomic, query_bias, should_reject):
        document = source(10)
        original = verify_program(document)
        module = batch if atomic else single
        prepare_name = "prepare_batch" if atomic else "prepare_edit"
        real_prepare = getattr(module, prepare_name)
        query = (real_prepare(source(query_bias), [deepcopy(SELECTION)]) if atomic
                 else real_prepare(source(query_bias), **deepcopy(SELECTION)))
        response = ({"edits": [{"site": 0, "changes": {"attrs": {"value": 3}}}]} if atomic
                    else {"attrs": {"value": 3}})
        mutations = []

        def concurrent_mutation(*args, **kwargs):
            # apply_* has already frozen its input when it reconstructs a query.
            document["functions"][0]["blocks"][0]["ops"][1]["attrs"]["value"] = 20
            mutations.append(verify_program(document).sha256)
            return real_prepare(*args, **kwargs)

        apply = batch.apply_batch if atomic else single.apply_edit
        with patch.object(module, prepare_name, side_effect=concurrent_mutation):
            if should_reject:
                with self.assertRaisesRegex(HIAEditRejected, "stale|modified|altered"):
                    apply(document, query, response)
            else:
                changed, receipt = apply(document, query, response)
                self.assertEqual(receipt["before_sha256"], original.sha256)
                self.assertEqual(receipt["before_sha256"], query["base_sha256"])
                self.assertEqual(execute_program(changed, "work", [])["result"], 13)
        self.assertEqual(len(mutations), 1)
        self.assertNotEqual(mutations[0], original.sha256)

    def test_single_rejects_new_query_attached_to_old_frozen_input(self):
        self.exercise(atomic=False, query_bias=20, should_reject=True)

    def test_batch_rejects_new_query_attached_to_old_frozen_input(self):
        self.exercise(atomic=True, query_bias=20, should_reject=True)

    def test_single_applies_only_the_original_consistent_snapshot(self):
        self.exercise(atomic=False, query_bias=10, should_reject=False)

    def test_batch_applies_only_the_original_consistent_snapshot(self):
        self.exercise(atomic=True, query_bias=10, should_reject=False)


if __name__ == "__main__":
    unittest.main()
