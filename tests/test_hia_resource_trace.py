"""Finite CFG resource-state replay; values and branch outcomes are abstract."""
from copy import deepcopy
import unittest

from hepta.hia_resource_trace import HIAResourceTraceRejected, replay_resource_path
from hepta.resource_ir import _CLAIMS, verify_resource_ir


def fixture(*, loop=False, borrow=False):
    owned = [{"op": "acquire", "dest": "v0", "kind": "buffer"}]
    if borrow:
        owned.extend([
            {"op": "borrow", "id": "loan0", "place": {"root": "v0", "path": []},
             "mode": "read", "type": "Buffer<u8>"},
            {"op": "use", "loan": "loan0", "mode": "read"},
            {"op": "end_borrow", "id": "loan0"},
        ])
    drop = {"op": "drop", "src": "v0"}
    ret = {"op": "return", "value": None, "loan": None}
    if loop:
        blocks = [
            {"id": "entry", "ops": owned, "term": {"op": "jump", "target": "header"}},
            {"id": "header", "ops": [], "term": {"op": "branch", "condition": "p0",
                                                   "then": "body", "else": "exit"}},
            {"id": "body", "ops": [], "term": {"op": "jump", "target": "header"}},
            {"id": "exit", "ops": [drop], "term": ret},
        ]
    else:
        blocks = [
            {"id": "entry", "ops": owned, "term": {"op": "branch", "condition": "p0",
                                                  "then": "yes", "else": "no"}},
            {"id": "yes", "ops": [drop], "term": {"op": "jump", "target": "done"}},
            {"id": "no", "ops": [drop], "term": {"op": "jump", "target": "done"}},
            {"id": "done", "ops": [], "term": ret},
        ]
    graph = {
        "schema": "hepta.resource-ir.v3", "source_sha256": "a" * 64,
        "project_sha256": None, "value_semantics": "copied_values_abstract_not_executable",
        "types": {"Unit": {"kind": "scalar", "name": "Unit"},
                  "bool": {"kind": "scalar", "name": "bool"},
                  "u8": {"kind": "scalar", "name": "u8"},
                  "Buffer<u8>": {"kind": "buffer", "element": "u8"}},
        "functions": [{"name": "f", "external": False, "obligation": None,
                       "params": [{"id": "p0", "type": "bool", "mode": "value"}],
                       "returns": {"type": "Unit", "mode": "value", "origin": None},
                       "locals": [{"id": "v0", "type": "Buffer<u8>", "mutable": False}],
                       "entry": "entry", "blocks": blocks}],
        "obligations": {}, "claims": dict(_CLAIMS),
    }
    return graph, verify_resource_ir(graph)


class HIAResourceTraceTests(unittest.TestCase):
    def test_valid_true_false_branches_each_drop_once(self):
        graph, receipt = fixture()
        self.assertTrue(receipt["ok"], receipt)
        for choice, target in ((0, "yes"), (1, "no")):
            with self.subTest(choice=choice):
                report = replay_resource_path(graph, receipt, "f", choices=(choice,))
                self.assertEqual(report["status"], "finite_resource_path_replayed_values_abstract")
                self.assertEqual(report["blocks_visited"], ["entry", target, "done"])
                self.assertEqual(report["counts"]["drop"], 1)
                self.assertFalse(report["claims"]["memory_byte_semantics_proved"])
                self.assertFalse(report["claims"]["source_to_ir_refinement_proved"])

    def test_loop_revisit_and_borrow_loan_lifecycle(self):
        graph, receipt = fixture(loop=True, borrow=True)
        self.assertTrue(receipt["ok"], receipt)
        r = replay_resource_path(graph, receipt, "f", choices=(0, 0, 1), fuel=10)
        self.assertEqual(r["blocks_visited"], ["entry", "header", "body", "header",
                                                "body", "header", "exit"])
        self.assertEqual({k: r["counts"][k] for k in ("acquire", "borrow", "end_borrow", "drop")},
                         {"acquire": 1, "borrow": 1, "end_borrow": 1, "drop": 1})
        self.assertTrue(any("loan0" in x["live_loans"] for x in r["events"]))

    def test_tampered_receipt_or_rehashed_invalid_graph_rejects(self):
        graph, verified = fixture()
        for mutate in (
            lambda g, r: r.update(ir_sha256="b" * 64),
            lambda g, r: r["claims"].update(whole_language_soundness_proved=0),
            lambda g, r: g["functions"][0]["blocks"][1]["ops"].append({"op": "drop", "src": "v0"}),
            lambda g, r: g.update(obligations={"fake": {}}),
        ):
            g, r = deepcopy(graph), deepcopy(verified)
            mutate(g, r)
            with self.assertRaisesRegex(HIAResourceTraceRejected, "E_HIA_RESOURCE_TRACE"):
                replay_resource_path(g, r, "f", choices=(0,))

    def test_missing_extra_oversized_or_invalid_decisions_reject(self):
        graph, verified = fixture()
        for choices, fuel in (((), 12), ((2,), 12), ((True,), 12), ((0, 1), 12),
                              ((0,), 1), ((0,), 0)):
            with self.subTest(choices=choices, fuel=fuel):
                with self.assertRaisesRegex(HIAResourceTraceRejected, "E_HIA_RESOURCE_TRACE"):
                    replay_resource_path(graph, verified, "f", choices=choices, fuel=fuel)

    def test_false_claims_never_become_safety_attestations(self):
        graph, verified = fixture()
        report = replay_resource_path(graph, verified, "f", choices=(0,))
        self.assertEqual(set(report["claims"]), {
            "numeric_value_execution_proved", "memory_byte_semantics_proved",
            "source_to_ir_refinement_proved", "native_backend_refinement_proved",
            "pointer_provenance_proved", "independent_source_binding_proved",
            "whole_language_soundness_proved"})
        self.assertTrue(all(v is False for v in report["claims"].values()))


if __name__ == "__main__":
    unittest.main()
