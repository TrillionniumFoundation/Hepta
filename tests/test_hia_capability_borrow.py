"""Borrow/access evidence observes the real guards and rejects altered admissions."""
from copy import deepcopy
from dataclasses import replace
import inspect
import sys
import textwrap
import unittest
from unittest.mock import patch

from hepta import hia_program as core
from hepta.hia_capability_flow import Capability, CapabilityFlowRejected, rename_capabilities
from hepta.hia_program_runtime import execute_program
from hepta.hia_program_source import lower_source
from tools import verify_hia_capability_borrow as proof


class CapabilityBorrowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.modules, cls.rows = [], []
        for _, path, mode, _, _ in proof.edges.PRODUCTION_INPUTS:
            raw = (proof.ROOT / path).read_bytes()
            initial = lower_source(raw.decode(), core_schema="hepta.hia.program.v8") if mode == "source-v8" else raw
            checked, rows, guards = proof.capture_core_instructions(initial)
            cls.modules.append((checked, rows, guards))
            cls.rows.extend(row for row in rows if row["instruction"]["op"] in proof.SUPPORTED)
        for path in ("examples/hia_program/capability_lifecycle.hia", proof.FIXTURE):
            checked, rows, guards = proof.capture_core_instructions((proof.ROOT / path).read_bytes())
            cls.modules.append((checked, rows, guards))
            cls.rows.extend(rows)
        cls.fixture, cls.fixture_rows, cls.fixture_guards = cls.modules[-1]

    def test_retains_full_legacy_cohort_and_observes_every_selected_guard(self):
        self.assertEqual([len(rows) for _, rows, _ in self.modules], [14, 32, 12, 28])
        self.assertEqual(len(self.rows), 74)
        self.assertEqual({row["instruction"]["op"] for row in self.rows}, proof.SUPPORTED)
        self.assertEqual(sum(len(guards) for _, _, guards in self.modules), 40)
        for checked, rows, guards in self.modules:
            inventory = proof.validate_guard_coverage(checked.as_dict(), rows, guards)
            self.assertEqual(sum(row["modelled"] for row in inventory),
                             sum(row["instruction"]["op"] in proof.SUPPORTED for row in rows))
            self.assertEqual(len(guards), sum(row["instruction"]["op"] in proof.GUARDED for row in rows))

    def test_shared_siblings_and_mutable_reborrow_execute_with_restored_parent_access(self):
        for function in ("shared_siblings", "mutable_reborrow"):
            for size, index, byte in ((1, 0, 0), (1, 0, 255), (8, 7, 79)):
                result = execute_program(self.fixture, function, [size, index, byte])
                self.assertEqual(result["result"], byte)
        shared = [row for row in self.fixture_guards if row["function"] == "shared_siblings"]
        second_shared = next(row for row in shared if row.get("output") == "right")
        self.assertEqual([cap["typ"] for cap in second_shared["others"]], ["readbuf"])
        nested_shared = next(row for row in shared if row.get("output") == "nested")
        self.assertEqual(nested_shared["allowed_ancestors"], ["left", "owner", "parent"])
        self.assertTrue(any(row["guard"] == "access" and row["source"] == "parent"
                            and row["operation_index"] > 3 and row["children"] == [] for row in shared))

    def test_capture_chains_profile_and_preserves_all_production_bindings(self):
        originals = [core._BlockCheck.borrow, core._BlockCheck.access, core._BlockCheck.children, core._BlockCheck.instruction]
        previous, calls = sys.getprofile(), []
        def profile(frame, event, _arg):
            if frame.f_code in (originals[0].__code__, originals[1].__code__) and event == "call":
                calls.append(event)
        try:
            sys.setprofile(profile)
            with proof.production_guard_trace() as guards:
                checked = core.verify_program(self.fixture)
            self.assertIs(sys.getprofile(), profile)
            self.assertEqual(checked.canonical_bytes, self.fixture.canonical_bytes)
            self.assertEqual(len(guards), len(calls))
            self.assertEqual(len(guards), 17)
        finally:
            sys.setprofile(previous)
        self.assertEqual(originals, [core._BlockCheck.borrow, core._BlockCheck.access,
                                     core._BlockCheck.children, core._BlockCheck.instruction])

    def test_rejection_restores_profile_and_opaque_profiler_refuses(self):
        bad = proof.rejected_program_controls()[1]["input"]
        previous = sys.getprofile()
        def profile(_frame, _event, _arg): pass
        try:
            sys.setprofile(profile)
            with self.assertRaises(core.HIAProgramRejected):
                with proof.production_guard_trace():
                    core.verify_program(bad)
            self.assertIs(sys.getprofile(), profile)
        finally:
            sys.setprofile(previous)
        with patch.object(proof.sys, "getprofile", return_value=object()), patch.object(proof.sys, "setprofile") as change:
            with self.assertRaisesRegex(ValueError, "opaque"):
                with proof.production_guard_trace():
                    self.fail("opaque profiler cannot be chained")
            change.assert_not_called()

    def test_foreign_direct_guard_calls_cannot_be_actual_instruction_evidence(self):
        block = self.fixture.as_dict()["functions"][0]["blocks"][0]
        owner = core._BlockCheck({"name": "foreign"}, block, {}, {}, schema="hepta.hia.program.v8")
        with self.assertRaisesRegex(ValueError, "outside the actual instruction"):
            with proof.production_guard_trace():
                owner.access("parent")

    def test_missing_duplicate_and_rebound_actual_guards_refuse(self):
        checked, rows, guards = self.modules[-1]
        for changed in ([], guards[:-1], guards + guards[:1]):
            with self.assertRaisesRegex(ValueError, "coverage|duplicate"):
                proof.validate_guard_coverage(checked.as_dict(), rows, changed)
        for field, value in (("caller", "fake"), ("function", "foreign"), ("block", "absent"),
                             ("operation_index", 999), ("instruction", {}), ("source", "foreign"),
                             ("mutable", 1), ("guard", "access"), ("before", {}), ("after", {}),
                             ("output", "foreign"), ("chain_head", True), ("allowed_ancestors", []),
                             ("others", [{"typ": "readbuf"}])):
            changed = deepcopy(guards)
            changed[0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                proof.validate_guard_coverage(checked.as_dict(), rows, changed)
        changed = deepcopy(guards)
        access = next(row for row in changed if row["guard"] == "access")
        del access["children"]
        with self.assertRaisesRegex(ValueError, "child loan"):
            proof.validate_guard_coverage(checked.as_dict(), rows, changed)

    def test_removed_production_borrow_conflict_guard_cannot_create_accepted_evidence(self):
        bad = next(row["input"] for row in proof.rejected_program_controls() if row["name"] == "second_mutable_sibling")
        original = textwrap.dedent(inspect.getsource(core._BlockCheck.borrow))
        guard = ('    if mutable and others or not mutable and any(c.typ == "mutbuf" for c in others):\n'
                 '        _reject("conflicting live borrow", "E_HIA_LOAN")\n')
        self.assertEqual(original.count(guard), 1)
        altered = {}
        exec(compile(original.replace(guard, "", 1), "<controlled-removed-borrow-guard>", "exec"),
             core.__dict__, altered)
        with patch.object(core._BlockCheck, "borrow", altered["borrow"]):
            # The invalid program reaches admission when the exact guard is removed.
            core.verify_program(bad)
            with self.assertRaisesRegex(ValueError, "admitted a conflicting"):
                proof.capture_core_instructions(bad)

    def test_removed_production_child_query_cannot_create_accepted_access_evidence(self):
        bad = next(row["input"] for row in proof.rejected_program_controls()
                   if row["name"] == "parent_access_before_child_end")
        with patch.object(core._BlockCheck, "children", lambda self, name: []):
            core.verify_program(bad)
            with self.assertRaisesRegex(ValueError, "child loan"):
                proof.capture_core_instructions(bad)

    def test_production_rejects_mutable_siblings_early_access_remaining_sibling_and_escalation(self):
        rejected = proof.rejected_program_controls()
        self.assertEqual({row["name"] for row in rejected}, {"second_mutable_sibling", "parent_access_before_child_end",
                         "parent_access_with_shared_sibling_remaining", "shared_to_mutable_escalation"})
        self.assertTrue(all(row["code"] == "E_HIA_LOAN" for row in rejected))
        for row in rejected:
            with self.subTest(control=row["name"]), self.assertRaises(core.HIAProgramRejected):
                proof.capture_core_instructions(row["input"])

    def test_injective_alpha_rename_retains_suspension_and_forgets_only_closed_external_graph(self):
        row = next(row for row in self.fixture_rows if row["function"] == "mutable_reborrow"
                   and row["instruction"]["op"] == "borrow.mut" and row["instruction"]["args"] == ["parent"])
        caps = {name: Capability(**cap) for name, cap in row["after"].items()}
        caps["unused"] = Capability("readbuf", "unused", external=True, origin="parameter")
        mapping = {name: "alpha_" + name for name in caps if name != "unused"}
        renamed = rename_capabilities(caps, mapping)
        self.assertEqual(set(renamed), set(mapping.values()))
        self.assertEqual(renamed["alpha_child"].parent, "alpha_parent")
        self.assertEqual(renamed["alpha_child"].root, "alpha_owner")
        block = {"id": "renamed", "params": [{"name": name, "type": cap.typ} for name, cap in renamed.items()]}
        checker = core._BlockCheck({"name": "check"}, block, renamed, {}, schema="hepta.hia.program.v8")
        checker.access("alpha_child", True)
        with self.assertRaises(core.HIAProgramRejected):
            checker.access("alpha_parent", True)
        # Retain a grandchild while projecting away its external middle parent.
        projected = dict(caps)
        projected["parent"] = replace(projected["parent"], external=True)
        with self.assertRaisesRegex(CapabilityFlowRejected, "parent capability"):
            rename_capabilities(projected, {key: val for key, val in mapping.items() if key != "parent"})

    def test_export_proves_before_guards_and_derives_after_compatibility(self):
        generated, names, mappings = proof.export_observed_instructions(self.rows)
        self.assertEqual(len(mappings), 74)
        self.assertEqual(len(names), 1100)
        self.assertTrue(proof.NAMES | proof.lifecycle.NAMES | proof.edges.NAMES <= names)
        self.assertIn("_borrow_guard : BorrowGuard instruction", generated)
        self.assertIn("_access : Access instruction", generated)
        self.assertIn("step_compatible instruction", generated)
        self.assertNotIn("native_decide", generated)
        self.assertNotIn("sorry", generated)
        self.assertLess(len(generated.encode()), proof.MAX_SOURCE_BYTES)

    def test_preserves_output_mutations_and_does_not_reconstruct_access_state(self):
        original = deepcopy(self.rows)
        mutants = proof.lifecycle.observed_mutations(self.rows)
        self.assertEqual(len(mutants), 7)
        for changed, expected in mutants.values():
            index = int(expected.split("instruction")[1].split("_")[0])
            baseline, _, _ = proof.export_observed_instructions([self.rows[index]], start_index=index)
            mutated, _, _ = proof.export_observed_instructions([changed[index]], start_index=index)
            self.assertNotEqual(baseline, mutated)
            self.assertEqual([row["before"] for row in changed], [row["before"] for row in original])
        row = deepcopy(next(row for row in self.rows if row["instruction"]["op"] == "buffer.store"))
        source = row["instruction"]["args"][0]
        del row["after"][source]
        generated, _, (mapping,) = proof.export_observed_instructions([row])
        self.assertEqual(len(mapping["after"]), len(row["before"]) - 1)
        self.assertIn("instruction0After = instruction0Before", generated)
        self.assertEqual(self.rows, original)

    def test_each_new_countermodel_has_an_independent_invalid_admission(self):
        controls = proof.counterexample_rows(self.rows)
        self.assertEqual(len(controls), 3)
        for name, (row, expected) in controls.items():
            generated, names, _ = proof.export_observed_instructions([row])
            self.assertIn("HiaCapabilityBorrow." + expected, names)
            self.assertIn("theorem " + expected, generated)
            source = row["instruction"]["args"][0]
            children = [cap for cap in row["before"].values() if cap["parent"] == source]
            self.assertTrue(children)
            if name == "second_mutable_sibling":
                self.assertTrue(any(cap["typ"] == "mutbuf" for cap in children))
            else:
                self.assertEqual(row["before"], row["after"])
        with self.assertRaisesRegex(ValueError, "required invalid-admission"):
            proof.counterexample_rows(self.rows[:1])
        self.assertEqual(proof.counterexample_rows(self.rows[:1], require_all=False), {})

    def test_model_mutations_are_unique_and_old_models_remain_intact(self):
        source = proof.model_source()
        for namespace, mutations in (("HiaCapabilityBorrow", proof.MODEL_MUTATIONS),
                                      ("HiaCapabilityLifecycle", proof.lifecycle.MODEL_MUTATIONS)):
            for old, _new, expected in mutations.values():
                self.assertEqual(source.count(old), 1)
                self.assertIn(namespace + "." + expected, proof.NAMES | proof.lifecycle.NAMES)
        self.assertEqual(len(proof.NAMES), 32)
        self.assertEqual(len(proof.lifecycle.NAMES), 22)
        self.assertEqual(len(proof.edges.NAMES), 31)

    def test_path_byte_instruction_and_foreign_opcode_budgets_fail_closed(self):
        row = next(row for row in self.rows if any(cap["parent"] is not None for cap in row["before"].values()))
        with patch.object(proof, "MAX_PATH_STEPS", 0), self.assertRaisesRegex(ValueError, "path proof budget"):
            proof.export_observed_instructions([row])
        with patch.object(proof, "MAX_SOURCE_BYTES", 100), self.assertRaisesRegex(ValueError, "byte budget"):
            proof.export_observed_instructions([row])
        for index in (-1, True, proof.lifecycle.MAX_INSTRUCTIONS):
            with self.assertRaisesRegex(ValueError, "numbering"):
                proof.export_observed_instructions([row], start_index=index)
        with patch.object(proof.lifecycle, "MAX_INSTRUCTIONS", 1), patch.object(proof.sys, "setprofile") as observe:
            with self.assertRaisesRegex(ValueError, "over-budget"):
                proof.capture_core_instructions(self.fixture)
            observe.assert_not_called()
        foreign = deepcopy(row)
        foreign["instruction"]["op"] = "owner.move"
        with self.assertRaisesRegex(ValueError, "supported instruction"):
            proof.export_observed_instructions([foreign])


if __name__ == "__main__":
    unittest.main()
