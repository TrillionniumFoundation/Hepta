"""Actual CFG observations must remain data for an independent kernel check."""
from copy import deepcopy
from dataclasses import asdict
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from hepta import hia_program as core
from hepta.hia_capability_flow import Capability as C, rename_capabilities
from hepta.hia_program_source import lower_source
from tests.test_hia_program import arithmetic, b, c, f, jump, m, ret
from tools import verify_hia_capabilities as proof


class ProductionCapabilityWitnessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = []
        cls.modules = []
        for _, path, mode, _, _ in proof.PRODUCTION_INPUTS:
            raw = (proof.ROOT / path).read_bytes()
            initial = lower_source(raw.decode(), core_schema="hepta.hia.program.v8") if mode == "source-v8" else core.verify_program(raw)
            checked, rows = proof.capture_core_edges(initial.canonical_bytes)
            if checked.canonical_bytes != initial.canonical_bytes:
                raise AssertionError("observed production Core changed")
            cls.rows.extend(rows)
            cls.modules.append((checked, rows))

    def test_actual_production_edges_cover_nested_parents_and_parameter_origins(self):
        original = rename_capabilities
        self.assertIs(core.rename_capabilities, original)
        self.assertEqual(len(self.rows), 4)
        self.assertTrue(all(row["function"] and row["block"] and row["edge"] for row in self.rows))
        self.assertTrue(any(cap["parent"] is not None for row in self.rows for cap in row["capabilities"].values()))
        self.assertTrue(any(cap["origin"] is not None for row in self.rows for cap in row["capabilities"].values()))
        generated, names, maps = proof.export_observed_edges(self.rows)
        self.assertEqual(len(names) - len(proof.NAMES), len(maps) * len(proof.EDGE_THEOREMS))
        self.assertEqual(len(maps), 4)
        self.assertIn("After = edge0Before.map (rename edge0Map) := by decide", generated)
        self.assertIs(core.rename_capabilities, original)

    def test_existing_profile_callback_is_chained_and_restored(self):
        original = sys.getprofile()
        observed = []
        def previous(frame, event, _arg):
            if frame.f_code is rename_capabilities.__code__ and event == "call":
                observed.append(event)
        try:
            sys.setprofile(previous)
            with proof.production_edge_trace() as rows:
                rename_capabilities({"a": C("buffer", "a")}, {"a": "b"})
            self.assertIs(sys.getprofile(), previous)
            self.assertEqual(observed, ["call"])
            self.assertEqual(len(rows), 1)
        finally:
            sys.setprofile(original)

    def test_exception_also_restores_the_callers_profile(self):
        original = sys.getprofile()
        def previous(_frame, _event, _arg): pass
        try:
            sys.setprofile(previous)
            with self.assertRaises(ValueError):
                with proof.production_edge_trace():
                    rename_capabilities({"a": C("buffer", "a")}, {})
            self.assertIs(sys.getprofile(), previous)
        finally:
            sys.setprofile(original)

    def test_opaque_existing_profiler_refuses_before_replacement(self):
        with patch.object(proof.sys, "getprofile", return_value=object()), \
                patch.object(proof.sys, "setprofile") as replace:
            with self.assertRaisesRegex(ValueError, "opaque existing profiler"):
                with proof.production_edge_trace():
                    self.fail("opaque profiler cannot be safely chained")
            replace.assert_not_called()

    def test_all_five_mutations_change_observed_output_without_repairing_it(self):
        original = deepcopy(self.rows)
        baseline, _, _ = proof.export_observed_edges(original)
        mutants = proof.observed_mutations(self.rows)
        self.assertEqual(set(mutants), {"root_rebound", "parent_discarded", "kind_changed", "external_flipped", "origin_discarded"})
        for mutated, expected in mutants.values():
            self.assertEqual([row["capabilities"] for row in mutated], [row["capabilities"] for row in original])
            self.assertEqual([row["remap"] for row in mutated], [row["remap"] for row in original])
            generated, names, _ = proof.export_observed_edges(mutated)
            self.assertIn(expected, names)
            self.assertNotEqual(generated, baseline)
        self.assertEqual(original, self.rows)

    def test_noninjective_map_and_missing_selected_root_refuse_export(self):
        duplicate = deepcopy(self.rows[0])
        names = list(duplicate["remap"])
        duplicate["remap"][names[1]] = duplicate["remap"][names[0]]
        with self.assertRaisesRegex(ValueError, "inventory"):
            proof.export_observed_edges([duplicate])
        caps = {"root": C("readbuf", "root", external=True),
                "loan": C("readbuf", "root", "root")}
        missing = {"capabilities": {k: asdict(v) for k, v in caps.items()},
                   "remap": {"loan": "new"}, "result": {"new": asdict(caps["loan"])}}
        with self.assertRaisesRegex(ValueError, "omits its root or parent"):
            proof.export_observed_edges([missing])

    def test_parent_cycle_is_not_mistaken_for_a_valid_production_witness(self):
        # Closed alone permits this synthetic cycle. The helper's arguments
        # are normally verifier-owned; its relation theorem is not a theorem
        # that arbitrary user-constructed graphs are safe or acyclic.
        caps = {"a": C("readbuf", "a", "b", external=True),
                "b": C("readbuf", "a", "a", external=True)}
        remap = {"a": "x", "b": "y"}
        result = rename_capabilities(caps, remap)
        row = {"capabilities": {k: asdict(v) for k, v in caps.items()}, "remap": remap,
               "result": {k: asdict(v) for k, v in result.items()}}
        with self.assertRaisesRegex(ValueError, "parent cycle"):
            proof.export_observed_edges([row])

    def test_forgotten_external_names_do_not_rename_formal_parameter_origin(self):
        caps = {"one": C("readbuf", "one", external=True, origin="one"),
                "two": C("readbuf", "two", external=True, origin="two")}
        remap = {"one": "two"}
        result = rename_capabilities(caps, remap)
        row = {"capabilities": {k: asdict(v) for k, v in caps.items()}, "remap": remap,
               "result": {k: asdict(v) for k, v in result.items()}}
        _, _, mappings = proof.export_observed_edges([row])
        self.assertEqual(mappings[0]["dropped_external"], ["two"])
        self.assertEqual(result["two"].origin, "one")
        # The kernel input must include the forgotten source capability;
        # proving only the selected graph cannot prove legal selection.
        self.assertEqual(set(mappings[0]["source_names"]), set(caps))
        self.assertEqual(len(mappings[0]["full_before"]), len(caps))
        self.assertEqual(len(mappings[0]["before"]), len(remap))
        self.assertEqual(mappings[0]["selected_names"], [mappings[0]["source_names"]["one"]])

    def test_projection_cannot_hide_local_capability_loss(self):
        caps = {"root": C("buffer", "root"),
                "forgotten": C("buffer", "forgotten")}
        row = {"capabilities": {name: asdict(cap) for name, cap in caps.items()},
               "remap": {"root": "new"},
               "result": {"new": asdict(C("buffer", "new"))}}
        with self.assertRaisesRegex(ValueError, "omits a local capability"):
            proof.export_observed_edges([row])

    def test_parent_rank_witness_covers_the_full_input_before_projection(self):
        caps = {"root": C("readbuf", "root", external=True),
                "parent": C("readbuf", "root", "root", True, "formal"),
                "child": C("readbuf", "root", "parent", False, "formal"),
                "unused": C("readbuf", "unused", external=True)}
        remap = {"root": "z", "parent": "y", "child": "x"}
        result = rename_capabilities(caps, remap)
        row = {"capabilities": {name: asdict(cap) for name, cap in caps.items()},
               "remap": remap, "result": {name: asdict(cap) for name, cap in result.items()}}
        _, names, (mapping,) = proof.export_observed_edges([row])
        ranks = {name: mapping["parent_ranks"][code] for name, code in mapping["source_names"].items()}
        self.assertEqual(ranks, {"root": 0, "parent": 1, "child": 2, "unused": 0})
        self.assertIn("HiaCapabilityRenaming.edge0_local_inventory", names)
        self.assertIn("HiaCapabilityRenaming.edge0_no_parent_cycle", names)
        # A cycle in an omitted external subgraph cannot disappear from
        # the evidence for the full input parent-rank premise.
        broken = deepcopy(row)
        broken["capabilities"]["unused"]["parent"] = "unused"
        with self.assertRaisesRegex(ValueError, "parent cycle"):
            proof.export_observed_edges([broken])

    def test_empty_selected_projection_retains_full_external_input(self):
        caps = {"external": C("readbuf", "external", external=True, origin="formal")}
        row = {"capabilities": {name: asdict(cap) for name, cap in caps.items()},
               "remap": {}, "result": {}}
        generated, names, (mapping,) = proof.export_observed_edges([row])
        self.assertEqual(mapping["before"], [])
        self.assertEqual(mapping["after"], [])
        self.assertEqual(len(mapping["full_before"]), 1)
        self.assertEqual(mapping["dropped_external"], ["external"])
        self.assertIn("edge0_selected_projection", generated)
        self.assertIn("HiaCapabilityRenaming.edge0_transfer", names)

    def test_new_proof_controls_alter_only_selector_or_rank_not_observed_caps(self):
        original = deepcopy(self.rows)
        generated, names, _ = proof.export_observed_edges(self.rows)
        mutants = proof.proof_input_mutations(self.rows)
        self.assertEqual(set(mutants), {"selector_drops_local", "parent_ranks_flattened"})
        for name, (changed, changed_names, expected) in mutants.items():
            self.assertEqual(changed_names, names)
            self.assertIn(expected, names)
            self.assertNotEqual(changed, generated)
            # Neither changing the assumed selector nor a supplied rank is
            # allowed to rebuild the supposedly observed input/output lists.
            lists = lambda text: [line for line in text.splitlines()
                                  if line.startswith("def edge") and "List Capability" in line]
            self.assertEqual(lists(changed), lists(generated))
        self.assertEqual(self.rows, original)

    def test_identical_branch_destinations_are_two_independent_occurrences(self):
        checked, rows = self.modules[0]
        inventory = proof.validate_edge_coverage(checked.as_dict(), rows)
        self.assertEqual(len(inventory), 2)
        self.assertEqual({row["edge_slot"] for row in inventory}, {"then", "else"})
        self.assertEqual(inventory[0]["edge"], inventory[1]["edge"])

    def test_production_edge_omission_cannot_inherit_the_static_inventory(self):
        checked, _ = self.modules[0]
        original = core._edges
        def omit_else(term):
            edges = original(term)
            return edges[:1] if term["op"] == "branch" else edges
        # This real producer mutation still reaches the same joined block;
        # an inventory based on that producer would miss the omitted else.
        with patch.object(core, "_edges", omit_else):
            with self.assertRaisesRegex(ValueError, "coverage is incomplete"):
                proof.capture_core_edges(checked.canonical_bytes)

    def test_missing_duplicate_foreign_and_rebound_trace_rows_refuse(self):
        checked, rows = self.modules[0]
        for changed in ([], rows[:-1], rows + rows[:1]):
            with self.assertRaisesRegex(ValueError, "coverage|duplicate"):
                proof.validate_edge_coverage(checked.as_dict(), changed)
        for field, value in (("caller", "another.verifier"), ("function", "other_function"),
                             ("edge_slot", "jump"), ("target_params", []), ("remap", {}),
                             ("edge", {"target": "other_block", "args": []})):
            changed = deepcopy(rows)
            changed[0][field] = value
            with self.assertRaises(ValueError):
                proof.validate_edge_coverage(checked.as_dict(), changed)

    def test_zero_edges_and_only_empty_capability_edges_refuse(self):
        with self.assertRaisesRegex(ValueError, "nonempty static CFG edge"):
            proof.capture_core_edges(arithmetic("int.add.wrap", "u8"))
        scalar = m(f("scalar", [], ["u8"], [], [b("entry", [], [], jump("finish")),
            b("finish", [], [c("answer", "u8", 1)], ret("answer"))]))
        with self.assertRaisesRegex(ValueError, "nonempty selected capability graph"):
            proof.capture_core_edges(scalar)

    def test_static_edge_and_live_capability_budgets_refuse(self):
        checked, _ = self.modules[0]
        with patch.object(proof, "MAX_OBSERVED_EDGES", 1):
            with self.assertRaisesRegex(ValueError, "over-budget static edge"):
                proof.capture_core_edges(checked.canonical_bytes)
        before = sys.getprofile()
        with patch.object(proof, "MAX_EDGE_CAPABILITIES", 1):
            with self.assertRaisesRegex(ValueError, "capability graph exceeds budget"):
                proof.capture_core_edges(checked.canonical_bytes)
        self.assertIs(sys.getprofile(), before)

    def test_generic_input_is_a_bounded_explicit_primitive_snapshot(self):
        checked, _ = self.modules[0]
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "program.json"
            path.write_bytes(checked.canonical_bytes)
            raw, restored = proof.read_primitive_program(path)
            self.assertEqual(raw, checked.canonical_bytes)
            self.assertEqual(restored.sha256, checked.sha256)
            with path.open("wb") as stream:
                stream.truncate(core.MAX_BYTES + 1)
            with self.assertRaisesRegex(ValueError, "byte budget"):
                proof.read_primitive_program(path)
        with self.assertRaisesRegex(ValueError, "explicit primitive Core"):
            proof.read_primitive_program(proof.ROOT / "examples/hia_program/stored_loan_record.hia")

    def test_generic_arguments_and_absent_mutation_fields_remain_explicit(self):
        self.assertEqual(proof.parse_arguments('[1,true,null]'), [1, True, None])
        for text in ('{}', '[1.5]', '[[1]]', '["one"]', '[NaN]', '[' + str(2**64) + ']'):
            with self.assertRaises(ValueError):
                proof.parse_arguments(text)
        with self.assertRaises(ValueError):
            proof.parse_arguments('[0]' * 10_000)
        _, rows = self.modules[0]
        mutants = proof.observed_mutations(rows, require_all=False)
        self.assertIn("kind_changed", mutants)
        self.assertIn("external_flipped", mutants)
        self.assertNotIn("origin_discarded", mutants)


if __name__ == "__main__":
    unittest.main()
