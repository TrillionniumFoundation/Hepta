"""P0: caller-owned Core must not change between size gate and encoding."""
from __future__ import annotations

from copy import deepcopy
import json
import unittest
from unittest.mock import patch

from hepta import hia_program
from hepta.hia_program import (
    HIAProgramRejected, MAX_BYTES, MAX_DEPTH, MAX_NODES, _decode, verify_program,
)
from tests.test_hia_program import arithmetic, resource_program


class HIAMutableSnapshotTests(unittest.TestCase):
    def test_real_scalar_and_owned_core_canonical_bytes_unchanged(self):
        for core in (arithmetic(), resource_program()):
            with self.subTest(module=core["module"]):
                source = deepcopy(core)
                from_dict = verify_program(source)
                from_wire = verify_program(json.dumps(source))
                self.assertEqual(from_dict.canonical_bytes, from_wire.canonical_bytes)
                self.assertEqual(from_dict.sha256, from_wire.sha256)

    def test_external_mutation_after_budget_check_cannot_change_core_bytes(self):
        original = {"a": [1, {"v": "old"}], "notes": "ok"}
        expected = json.dumps(original, sort_keys=True,
                              separators=(",", ":"), ensure_ascii=False).encode()
        measure = hia_program._structure
        events = []

        def adversarial_after_validation(detached):
            events.append(detached is original)
            length = measure(detached)
            # Deterministic check/use switch: this is executed after a
            # successful structure check but before the caller's encode.
            original["a"][1]["v"] = "corrupted-after-check"
            original["notes"] = "y" * (MAX_BYTES + 1)
            original["late"] = [1] * 1024
            return length

        with patch.object(hia_program, "_structure",
                          side_effect=adversarial_after_validation):
            checked, raw = _decode(original)
        self.assertEqual(events, [False])
        self.assertEqual(raw, expected)
        self.assertEqual(checked, {"a": [1, {"v": "old"}], "notes": "ok"})
        self.assertGreater(len(original["notes"]), MAX_BYTES)

    def test_external_fanout_growth_cannot_bypass_node_budget(self):
        original = {"a": [3]}
        expected = json.dumps(original, sort_keys=True,
                              separators=(",", ":"), ensure_ascii=False).encode()
        measure = hia_program._structure

        def grow_old_source_after_preflight(snapshot):
            size = measure(snapshot)
            original["a"].extend([0] * (MAX_NODES + 2))
            return size

        with patch.object(hia_program, "_structure",
                          side_effect=grow_old_source_after_preflight):
            checked, encoded = _decode(original)
        self.assertEqual(encoded, expected)
        self.assertEqual(checked, {"a": [3]})
        self.assertGreater(len(original["a"]), MAX_NODES)

    def test_caller_cycle_shared_subtree_and_original_independence(self):
        loop = []
        loop.append(loop)
        with self.assertRaises(HIAProgramRejected) as caught:
            _decode(loop)
        self.assertEqual(caught.exception.code, "E_HIA_FORMAT")

        shared = ["hello", {"k": "v"}]
        original = {"left": shared, "right": shared}
        detached, encoded = _decode(original)
        self.assertEqual(detached["left"], detached["right"])
        self.assertIsNot(detached["left"], detached["right"])
        shared[1]["k"] = "other"
        self.assertEqual(detached["left"][1]["k"], "v")
        self.assertEqual(
            json.loads(encoded), {"left": ["hello", {"k": "v"}],
                                  "right": ["hello", {"k": "v"}]})

    def test_out_of_budget_nodes_depth_and_scalar_rejections(self):
        oversized = [None] * MAX_NODES
        with self.assertRaises(HIAProgramRejected) as caught:
            _decode(oversized)
        self.assertEqual(caught.exception.code, "E_HIA_LIMIT")

        deep = None
        for _ in range(MAX_DEPTH + 2):
            deep = [deep]
        with self.assertRaises(HIAProgramRejected) as caught:
            _decode(deep)
        self.assertEqual(caught.exception.code, "E_HIA_LIMIT")

        for wrong in ({"x": object()}, {"x": 1.5}, {7: "not-a-string-key"}):
            with self.subTest(wrong=repr(wrong)):
                with self.assertRaises(HIAProgramRejected):
                    _decode(wrong)

    def test_text_bytes_and_caller_dict_use_same_semantics(self):
        source = {"a": [1, None, True, -9], "z": {"a": "🌊", "b": "\t"}}
        encoded = json.dumps(source, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=False).encode("utf-8")
        for input_value in (source, encoded, encoded.decode("utf-8")):
            detached, raw = _decode(input_value)
            self.assertEqual(raw, encoded)
            self.assertEqual(detached, source)


if __name__ == "__main__":
    unittest.main()
