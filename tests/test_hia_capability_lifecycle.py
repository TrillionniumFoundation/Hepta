"""Instruction evidence observes production, preserves data, and fails closed."""
from copy import deepcopy
import sys
import unittest
from unittest.mock import patch

from hepta import hia_program as core
from hepta.hia_program_source import lower_source
from hepta.hia_program_runtime import execute_program
from tests.test_hia_program import arithmetic, b, f, i, m, ret
from tools import verify_hia_capabilities as edges
from tools import verify_hia_capability_lifecycle as proof


class CapabilityLifecycleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.modules, cls.rows = [], []
        for _, path, mode, _, _ in edges.PRODUCTION_INPUTS:
            raw = (proof.ROOT / path).read_bytes()
            initial = lower_source(raw.decode(), core_schema="hepta.hia.program.v8") if mode == "source-v8" else core.verify_program(raw)
            checked, rows = proof.capture_core_instructions(initial.canonical_bytes)
            cls.modules.append((checked, rows))
            cls.rows.extend(row for row in rows if row["instruction"]["op"] in proof.SUPPORTED)
        cls.explicit = core.verify_program((proof.ROOT / "examples/hia_program/capability_lifecycle.hia").read_bytes())
        checked, rows = proof.capture_core_instructions(cls.explicit.canonical_bytes)
        cls.modules.append((checked, rows))
        cls.rows.extend(rows)

    def test_real_occurrences_cover_every_selected_operation_and_all_static_ops(self):
        self.assertEqual({row["instruction"]["op"] for row in self.rows}, proof.SUPPORTED)
        self.assertTrue(any(cap["origin"] is not None for row in self.rows for cap in row["after"].values()))
        self.assertTrue(any(cap["parent"] is not None and row["before"][cap["parent"]]["parent"] is not None
                            for row in self.rows for cap in row["before"].values() if cap["parent"] is not None))
        for checked, rows in self.modules:
            inventory = proof.validate_instruction_coverage(checked.as_dict(), rows)
            self.assertEqual(len(inventory), sum(len(b["ops"]) for f in checked.as_dict()["functions"] for b in f["blocks"]))
            self.assertEqual(sum(row["modelled"] for row in inventory),
                             sum(row["instruction"]["op"] in proof.SUPPORTED for row in rows))

    def test_explicit_lifecycle_runs_with_empty_and_nonempty_buffers(self):
        for size in (0, 1, 4):
            self.assertTrue(execute_program(self.explicit, "lifecycle", [size])["result"])

    def test_capture_preserves_production_bindings_and_canonical_input(self):
        original = core._BlockCheck.instruction
        verified, rows = proof.capture_core_instructions(self.explicit)
        self.assertIs(core._BlockCheck.instruction, original)
        self.assertEqual(verified.canonical_bytes, self.explicit.canonical_bytes)
        self.assertEqual(len(rows), 12)
        self.assertEqual(rows[0]["before"], {})
        self.assertEqual(rows[-1]["after"], {})

    def test_existing_profile_is_chained_and_restored(self):
        previous, calls = sys.getprofile(), []
        def observe(frame, event, _arg):
            if frame.f_code is core._BlockCheck.instruction.__code__ and event == "call":
                calls.append(event)
        try:
            sys.setprofile(observe)
            with proof.production_instruction_trace() as rows:
                core.verify_program(self.explicit)
            self.assertIs(sys.getprofile(), observe)
            self.assertEqual(len(calls), len(rows))
            self.assertEqual(len(rows), 12)
        finally:
            sys.setprofile(previous)

    def test_rejected_program_restores_existing_profile(self):
        previous = sys.getprofile()
        def observe(_frame, _event, _arg): pass
        bad = self.explicit.as_dict()
        bad["functions"][0]["blocks"][0]["ops"][1] = i("owner.drop", ["owner"])
        try:
            sys.setprofile(observe)
            with self.assertRaises(core.HIAProgramRejected):
                with proof.production_instruction_trace():
                    core.verify_program(bad)
            self.assertIs(sys.getprofile(), observe)
        finally:
            sys.setprofile(previous)

    def test_opaque_profiler_is_not_replaced(self):
        with patch.object(proof.sys, "getprofile", return_value=object()), patch.object(proof.sys, "setprofile") as replace:
            with self.assertRaisesRegex(ValueError, "opaque existing profiler"):
                with proof.production_instruction_trace():
                    self.fail("opaque profiler cannot be chained")
            replace.assert_not_called()

    def test_foreign_direct_instruction_call_cannot_be_production_evidence(self):
        block = self.explicit.as_dict()["functions"][0]["blocks"][0]
        owner = core._BlockCheck({"name": "foreign"}, block, {}, {}, schema="hepta.hia.program.v8")
        with self.assertRaisesRegex(ValueError, "outside the actual function verifier"):
            with proof.production_instruction_trace():
                owner.instruction(block["ops"][0])

    def test_missing_duplicate_foreign_or_rebound_occurrences_refuse(self):
        checked, rows = self.modules[-1]
        for changed in ([], rows[:-1], rows + rows[:1]):
            with self.assertRaisesRegex(ValueError, "coverage|duplicate"):
                proof.validate_instruction_coverage(checked.as_dict(), changed)
        for field, value in (("caller", "another.verifier"), ("function", "wrong"),
                             ("block", "wrong"), ("operation_index", 999), ("instruction", {})):
            changed = deepcopy(rows)
            changed[0][field] = value
            with self.assertRaisesRegex(ValueError, "unexpected|differs"):
                proof.validate_instruction_coverage(checked.as_dict(), changed)

    def test_whole_inventory_must_fit_before_observation_starts(self):
        with patch.object(proof, "MAX_INSTRUCTIONS", 1), patch.object(proof.sys, "setprofile") as observe:
            with self.assertRaisesRegex(ValueError, "over-budget"):
                proof.capture_core_instructions(self.explicit)
            observe.assert_not_called()

    def test_semantic_mutations_keep_inputs_fixed_and_reach_the_kernel_input(self):
        original = deepcopy(self.rows)
        baseline, names, maps = proof.export_observed_instructions(self.rows)
        self.assertEqual(len(names), len(proof.NAMES | edges.NAMES) + len(self.rows) * len(proof.INSTANCE_THEOREMS))
        self.assertEqual(len(maps), len(self.rows))
        mutants = proof.observed_mutations(self.rows)
        self.assertEqual(set(mutants), {"root_rebound", "parent_discarded", "kind_changed", "external_flipped",
                                        "origin_discarded", "ended_loan_retained", "dropped_owner_retained"})
        for changed, expected in mutants.values():
            self.assertEqual([row["before"] for row in changed], [row["before"] for row in original])
            self.assertEqual([row["instruction"] for row in changed], [row["instruction"] for row in original])
            generated, mutant_names, _ = proof.export_observed_instructions(changed)
            self.assertEqual(names, mutant_names)
            self.assertIn(expected, names)
            self.assertNotEqual(baseline, generated)
        self.assertEqual(original, self.rows)

    def test_unexpected_lost_or_extra_capability_is_not_repaired_by_export(self):
        row = next(row for row in self.rows if row["instruction"]["op"] == "borrow.mut")
        _, _, (baseline,) = proof.export_observed_instructions([row])
        missing = deepcopy(row)
        source = row["instruction"]["args"][0]
        del missing["after"][source]
        _, _, (changed,) = proof.export_observed_instructions([missing])
        self.assertEqual(len(changed["after"]), len(baseline["after"]) - 1)
        added = deepcopy(row)
        added["after"]["unexpected_owner"] = {"typ": "buffer", "root": "unexpected_owner", "parent": None,
                                                "external": False, "origin": None}
        _, _, (changed,) = proof.export_observed_instructions([added])
        self.assertEqual(len(changed["after"]), len(baseline["after"]) + 1)

    def test_dangling_output_root_is_encoded_as_observed_not_reconstructed(self):
        row = deepcopy(next(row for row in self.rows if row["instruction"]["op"] == "borrow.read"))
        output = row["instruction"]["out"][0]["name"]
        row["after"][output]["root"] = "not_a_live_root"
        _, _, (mapping,) = proof.export_observed_instructions([row])
        self.assertIn("not_a_live_root", mapping["names"])
        self.assertIn(", " + str(mapping["names"]["not_a_live_root"]) + ",", mapping["after"][0])

    def test_invalid_input_parent_graph_and_untyped_fields_refuse(self):
        row = deepcopy(next(row for row in self.rows if row["before"]))
        name = next(iter(row["before"]))
        row["before"][name]["parent"] = name
        with self.assertRaisesRegex(ValueError, "parent cycle"):
            proof.export_observed_instructions([row])
        row["before"][name]["parent"] = "absent"
        with self.assertRaisesRegex(ValueError, "omits a root or parent"):
            proof.export_observed_instructions([row])
        row["before"][name]["parent"] = None
        row["before"][name]["external"] = 1
        with self.assertRaisesRegex(ValueError, "fields"):
            proof.export_observed_instructions([row])

    def test_model_mutations_have_unique_sites_and_no_exported_trust_shortcut(self):
        source = proof.model_source()
        for old, _new, expected in proof.MODEL_MUTATIONS.values():
            self.assertEqual(source.count(old), 1)
            self.assertIn("HiaCapabilityLifecycle." + expected, proof.NAMES)
        self.assertIn("Step before after", source)
        self.assertNotIn("native_decide", source)

    def test_unmodelled_instructions_remain_visible_and_cannot_be_proved_as_noops(self):
        checked, rows = proof.capture_core_instructions(arithmetic())
        inventory = proof.validate_instruction_coverage(checked.as_dict(), rows)
        self.assertEqual(len(inventory), 1)
        self.assertFalse(inventory[0]["modelled"])
        with self.assertRaisesRegex(ValueError, "supported instruction"):
            proof.export_observed_instructions(rows)

    def test_production_rejects_ending_external_or_parent_loan_and_borrowed_drop(self):
        external = m(f("bad", [("view", "readbuf")], [], [],
                       [b("entry", [("view", "readbuf")], [i("loan.end", ["view"])], ret())]))
        with self.assertRaises(core.HIAProgramRejected):
            proof.capture_core_instructions(external)
        for op, resource in (("loan.end", "parent"), ("owner.drop", "owner")):
            bad = self.explicit.as_dict()
            bad["functions"][0]["blocks"][0]["ops"][3] = i(op, [resource])
            with self.assertRaises(core.HIAProgramRejected):
                proof.capture_core_instructions(bad)


if __name__ == "__main__":
    unittest.main()
