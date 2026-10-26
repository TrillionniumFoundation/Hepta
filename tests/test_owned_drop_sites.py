"""Bounded checked-Resource-IR static Drop site authorization tests."""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
import unittest

from hepta.owned_drop_sites import DropSiteRejected, qualify_drop_sites
from hepta.resource_ir import _CLAIMS


def fixture():
    graph = {
        "schema": "hepta.resource-ir.v3",
        "source_sha256": "a" * 64,
        "project_sha256": None,
        "value_semantics": "copied_values_abstract_not_executable",
        "types": {"u8": {"kind": "scalar", "name": "u8"},
                  "Buffer<u8>": {"kind": "buffer", "element": "u8"}},
        "functions": [{"name": "consume", "external": False, "type_params": [],
                       "params": [], "locals": [{"id": "v0", "type": "Buffer<u8>", "mutable": False}],
                       "blocks": [{"id": "b0", "ops": [
                           {"op": "acquire", "dest": "v0", "kind": "buffer"},
                           {"op": "drop", "src": "v0"}],
                           "term": {"op": "return", "value": None, "loan": None}}]}],
        "obligations": {}, "claims": dict(_CLAIMS),
    }
    digest = sha256(json.dumps(graph, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()
    receipt = {"ok": True, "status": "resource_cfg_verified", "ir_sha256": digest,
               "external_obligations": {}, "claims": dict(_CLAIMS),
               "functions": [{"function": "consume", "normal_exits": 1}]}
    return graph, receipt


class DropSiteTests(unittest.TestCase):
    def test_verified_source_graph_exposes_exact_drop_type_count(self):
        graph, verified = fixture()
        sites = qualify_drop_sites(graph, verified)
        self.assertEqual(sites.resource_ir_sha256, verified["ir_sha256"])
        self.assertEqual(sites.for_function("consume"), {"Buffer<u8>": 1})
        self.assertEqual(qualify_drop_sites(graph, verified), sites)
        with self.assertRaisesRegex(DropSiteRejected, "E_DROP_SITE"):
            sites.for_function("not_checked")

    def test_verified_multi_block_static_sites_counted_independently(self):
        graph, verified = fixture()
        graph["functions"][0]["blocks"].append({"id": "b1", "ops": [
            {"op": "drop", "src": "v0"}], "term": {"op": "return", "value": None, "loan": None}})
        verified["ir_sha256"] = sha256(json.dumps(graph, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()
        self.assertEqual(qualify_drop_sites(graph, verified).for_function("consume"), {"Buffer<u8>": 2})
        # Counts are static sites, not dynamic path or lifetime proofs.

    def test_forged_receipts_and_proof_types_rejected(self):
        original_graph, original_receipt = fixture()
        mutations = {
            "bad_digest": lambda g, r: r.update(ir_sha256="0" * 64),
            "promoted_proof": lambda g, r: r["claims"].update(native_codegen_uses_this_ir=True),
            "bool_as_zero": lambda g, r: r["claims"].update(whole_language_soundness_proved=0),
            "extra_obligation": lambda g, r: g.update(obligations={"unknown": "unsafe"}),
            "foreign": lambda g, r: r.update(external_obligations={"foreign": True}),
            "unknown_function": lambda g, r: r["functions"][0].update(function="different"),
            "extra_source_function": lambda g, r: g["functions"].append(deepcopy(g["functions"][0])),
            "missing_slot": lambda g, r: g["functions"][0]["blocks"][0]["ops"][1].update(src="v9"),
            "missing_type": lambda g, r: g["functions"][0]["locals"][0].update(type="wrong"),
            "oversized_function": lambda g, r: g.update(functions=[None] * 513),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                graph, receipt = deepcopy(original_graph), deepcopy(original_receipt)
                mutate(graph, receipt)
                # Rehash the graph even for mutations: hashing isn't source authentication.
                receipt["ir_sha256"] = sha256(json.dumps(graph, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest() if name != "bad_digest" else "0" * 64
                with self.assertRaisesRegex(DropSiteRejected, "E_DROP_SITE"):
                    qualify_drop_sites(graph, receipt)

    def test_drop_site_must_be_well_typed(self):
        for invalid in ([], {}, None, True):
            with self.subTest(value=repr(invalid)):
                graph, receipt = fixture()
                graph["functions"][0]["blocks"][0]["ops"][1]["src"] = invalid
                receipt["ir_sha256"] = sha256(json.dumps(graph, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()
                with self.assertRaises(DropSiteRejected):
                    qualify_drop_sites(graph, receipt)


if __name__ == "__main__":
    unittest.main()
