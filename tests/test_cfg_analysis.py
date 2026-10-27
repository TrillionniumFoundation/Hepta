"""Deterministic dominance/loop facts; SSA remains unimplemented."""
from __future__ import annotations

from hashlib import sha256
import json
import unittest

from hepta.cfg import CFGSnapshot
from hepta.cfg_analysis import CFGAnalysisRejected, analyze_cfg


def case(blocks, entry="b0000") -> CFGSnapshot:
    edges = []
    for block in blocks:
        term = block["terminator"]
        kind = term["kind"]
        if kind == "goto":
            targets = [term["target"]]
        elif kind == "branch":
            targets = [term["then"], term["else"]]
        elif kind == "range_next":
            targets = [term["body"], term["exit"]]
        elif kind == "switch":
            targets = [arm["target"] for arm in term["arms"]]
        elif kind in {"return", "fallthrough"}:
            targets = []
        else:
            targets = []
        edges.extend({"from": block["id"], "to": target} for target in targets)
    payload = {"schema": "hepta.cfg.v0", "status": "structural_cfg_only_not_proved",
               "functions": [{"name": "f", "entry": entry, "blocks": blocks, "edges": edges}]}
    encoded = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return CFGSnapshot("hepta.cfg.v0", encoded, sha256(encoded.encode()).hexdigest())


def block(i: int, **term) -> dict:
    return {"id": f"b{i:04d}", "instructions": [], "terminator": term}


class DominanceTests(unittest.TestCase):
    def test_diamond_frontier_and_proofs_not_claimed(self):
        graph = case([block(0, kind="branch", **{"then": "b0001", "else": "b0002"}),
                      block(1, kind="goto", target="b0003"),
                      block(2, kind="goto", target="b0003"),
                      block(3, kind="return")])
        analysis = analyze_cfg(graph)
        a = analysis.as_dict()
        self.assertEqual(a, analyze_cfg(graph).as_dict())
        self.assertEqual(a["schema"], "hepta.cfg.analysis.v0")
        self.assertEqual(a["cfg_sha256"], graph.sha256)
        self.assertFalse(a["claims"]["ssa_constructed"])
        self.assertFalse(a["claims"]["phi_nodes_generated"])
        self.assertFalse(a["claims"]["backend_refinement_proved"])
        fn = a["functions"][0]
        self.assertEqual(fn["immediate_dominators"]["b0003"], "b0000")
        self.assertEqual(fn["dominators"]["b0003"], ["b0000", "b0003"])
        self.assertEqual(fn["dominance_frontiers"]["b0001"], ["b0003"])
        self.assertEqual(fn["dominance_frontiers"]["b0002"], ["b0003"])
        self.assertEqual(fn["backedges"], [])
        mutated = analysis.as_dict()
        mutated["functions"].clear()
        self.assertTrue(analysis.as_dict()["functions"])

    def test_loop_backedge_and_natural_loop(self):
        graph = case([block(0, kind="goto", target="b0001"),
                      block(1, kind="branch", **{"then": "b0002", "else": "b0003"}),
                      block(2, kind="goto", target="b0001"),
                      block(3, kind="return")])
        fn = analyze_cfg(graph).as_dict()["functions"][0]
        self.assertEqual(fn["immediate_dominators"]["b0002"], "b0001")
        self.assertEqual(fn["dominance_frontiers"]["b0002"], ["b0001"])
        self.assertEqual(fn["backedges"], [{"header": "b0001", "tail": "b0002",
                                             "natural_loop": ["b0001", "b0002"]}])

    def test_switch_and_range_next_edges(self):
        graph = case([block(0, kind="switch", arms=[{"target": "b0001"}, {"target": "b0002"}]),
                      block(1, kind="goto", target="b0003"),
                      block(2, kind="goto", target="b0003"),
                      block(3, kind="range_next", body="b0004", exit="b0005"),
                      block(4, kind="goto", target="b0003"),
                      block(5, kind="return")])
        fn = analyze_cfg(graph).as_dict()["functions"][0]
        self.assertEqual(fn["successors"]["b0000"], ["b0001", "b0002"])
        self.assertEqual(fn["backedges"], [{"header": "b0003", "tail": "b0004",
                                             "natural_loop": ["b0003", "b0004"]}])

    def test_wrong_digest_wrong_schema_rejected(self):
        graph = case([block(0, kind="return")])
        with self.assertRaisesRegex(CFGAnalysisRejected, "digest mismatch"):
            analyze_cfg(CFGSnapshot(graph.schema, graph.canonical_json, "0" * 64))
        with self.assertRaisesRegex(CFGAnalysisRejected, "requires structural"):
            analyze_cfg(CFGSnapshot("unknown", graph.canonical_json, graph.sha256))

    def test_invalid_edge_duplicate_unreachable_and_terminator_rejected(self):
        diamond = [block(0, kind="branch", **{"then": "b0001", "else": "b0002"}),
                   block(1, kind="goto", target="b0003"),
                   block(2, kind="goto", target="b0003"), block(3, kind="return")]
        graph = case(diamond)
        data = json.loads(graph.canonical_json)
        data["functions"][0]["edges"].pop()
        encoded = json.dumps(data, sort_keys=True, separators=(",", ":"))
        with self.assertRaisesRegex(CFGAnalysisRejected, "EDGES"):
            analyze_cfg(CFGSnapshot("hepta.cfg.v0", encoded, sha256(encoded.encode()).hexdigest()))
        with self.assertRaisesRegex(CFGAnalysisRejected, "BLOCKS"):
            analyze_cfg(case([block(0, kind="goto", target="b0000"),
                              block(0, kind="return")]))
        with self.assertRaisesRegex(CFGAnalysisRejected, "UNREACHABLE"):
            analyze_cfg(case([block(0, kind="return"), block(1, kind="return")]))
        with self.assertRaisesRegex(CFGAnalysisRejected, "TERMINATOR"):
            analyze_cfg(case([block(0, kind="unknown")]))
        with self.assertRaisesRegex(CFGAnalysisRejected, "dangling"):
            analyze_cfg(case([block(0, kind="goto", target="b0002")]))

    def test_explicit_resource_limit(self):
        blocks = [block(i, kind="goto", target=f"b{i+1:04d}") for i in range(512)]
        blocks.append(block(512, kind="return"))
        with self.assertRaisesRegex(CFGAnalysisRejected, "LIMIT"):
            analyze_cfg(case(blocks))


if __name__ == "__main__":
    unittest.main()
