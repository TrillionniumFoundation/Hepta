"""Independent Core controls for the research-only initialization frontier check.

These tests never compile, execute native code, or authorize zero elision.
The ordinary VM and production initialization/emission rules remain untouched.
"""
from copy import deepcopy
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from hepta.hia_initialization import verify_initialization_coverage
from hepta.hia_program import VerifiedProgram, verify_program
from hepta.hia_program_source import lower_source
from hepta.hia_reduction import _compose, _freeze_pipeline, propose_reduction_pipeline
from tests.test_hia_initialization import initialized_program
from tests.test_hia_program import b, branch, c, f, i, m, ret
from tools.experimental_deferred_guard_proposer import propose_deferred_guard
from tools import check_initialization_frontiers as checker


ROOT = Path(__file__).resolve().parents[1]
DEFERRED_HASHES = {
    "linear": "c7b8b9ef7619700fd9c5ec0dedb06fbf7ecc801563813b6cb7abaf7e08a467d3",
    "affine": "91f11c6cf67610dc0682640d0c24cbd2572a0fcbdea25fdf94ff7671cf1cc861",
}


def blocks(program):
    return {block["id"]: block for block in program["functions"][0]["blocks"]}


def alpha_rename_and_shuffle(program):
    """Rename all binders/uses, then reverse block order, retaining the entry."""
    renamed = deepcopy(program)
    for function in renamed["functions"]:
        block_names = {block["id"]: "block_" + str(index)
                       for index, block in enumerate(reversed(function["blocks"]))}
        bindings = [parameter["name"] for block in function["blocks"]
                    for parameter in block["params"]]
        bindings += [output["name"] for block in function["blocks"]
                     for operation in block["ops"] for output in operation["out"]]
        names = {name: "value_" + str(index) for index, name in enumerate(bindings)}
        function["entry"] = block_names[function["entry"]]
        for parameter in function["params"]:
            parameter["name"] = names[parameter["name"]]
        for block in function["blocks"]:
            block["id"] = block_names[block["id"]]
            for parameter in block["params"]:
                parameter["name"] = names[parameter["name"]]
            for operation in block["ops"]:
                operation["args"] = [names[name] for name in operation["args"]]
                for output in operation["out"]:
                    output["name"] = names[output["name"]]
            term = block["term"]
            if term["op"] == "ret":
                term["values"] = [names[name] for name in term["values"]]
            elif term["op"] == "branch":
                term["cond"] = names[term["cond"]]
            edges = ([term] if term["op"] == "jump" else
                     [term["then"], term["else"]] if term["op"] == "branch" else [])
            for edge in edges:
                edge["target"] = block_names[edge["target"]]
                edge["args"] = [names[name] for name in edge["args"]]
        function["blocks"].reverse()
    return renamed


def duplicate_header_ingress(*, bad_extent=False, bad_seed=False):
    """Two different edges from the same predecessor must both be checked."""
    program = initialized_program()
    function = program["functions"][0]
    function["params"].append({"name": "choose", "type": "bool"})
    entry = blocks(program)["entry"]
    entry["params"].append({"name": "choose", "type": "bool"})
    good = list(entry["term"]["args"])
    bad = list(good)
    if bad_extent:
        bad[1] = "probe"
    if bad_seed:
        entry["ops"].append(c("bad_seed", "usize", 1))
        bad[2] = "bad_seed"
    entry["term"] = branch("choose", ("head", *good), ("head", *bad))
    return program


def body_seed_program():
    """A generic zero-based direct-body seed with an exact range guard."""
    program = initialized_program()
    entry = blocks(program)["entry"]
    args = list(entry["term"]["args"])
    entry["ops"].append(i("compare.lt", ["start", "n"], [("initial_more", "bool")]))
    entry["term"] = branch("initial_more", ("body", *args), ("exit", *args))
    return program


class InitializationFrontierCheckerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cores = {}
        for workload in ("linear", "affine"):
            base = lower_source((ROOT / "benchmarks/hia_reduction_release" /
                                 (workload + ".hepta")).read_text())
            proposal = propose_reduction_pipeline(base, include_induction=True)
            _, narrowed, fast, frozen = _freeze_pipeline(base, proposal)
            # Construct the real entry-selected reference. Construction itself
            # conveys no proof/admission authority; this checker rechecks Core.
            reference = _compose(narrowed, fast, frozen["guarded"])
            deferred = propose_deferred_guard(base, proposal)["candidate_core"]
            cls.cores[workload] = {"reference": reference.as_dict(), "deferred": deferred}

    def assert_deny_all(self, report):
        self.assertIn(report["status"], {"checked", "rejected", "unknown"}, report)
        self.assertEqual(report["authority"], "DENY_ALL", report)
        self.assertIs(report["initialization_elision_authorized"], False, report)
        for field in ("production_admission", "native_admission", "performance_qualified",
                      "quota_equivalence", "vm_steps_preserved", "whole_language_proof",
                      "backend_refinement_proof"):
            if field in report:
                self.assertIs(report[field], False, report)

    def check(self, program, expected="checked", **kwargs):
        report = checker.check_initialization_frontiers(program, **kwargs)
        self.assert_deny_all(report)
        self.assertEqual(report["status"], expected, report)
        return report

    def reject_valid_core(self, program):
        verified = verify_program(program)
        return self.check(verified, "rejected")

    def test_actual_reference_and_deferred_ci_cores_are_checked(self):
        for workload, arms in self.cores.items():
            for arm, program in arms.items():
                with self.subTest(workload=workload, arm=arm):
                    checked = verify_program(program)
                    if arm == "deferred":
                        self.assertEqual(checked.sha256, DEFERRED_HASHES[workload])
                    self.check(checked)

    def test_generic_header_and_guarded_body_seeds_are_checked(self):
        for program in (initialized_program(), duplicate_header_ingress(), body_seed_program()):
            with self.subTest(entry=blocks(program)["entry"]["term"]):
                self.check(verify_program(program))

    def test_alpha_renaming_and_block_order_do_not_supply_authority(self):
        for arms in self.cores.values():
            for program in arms.values():
                renamed = verify_program(alpha_rename_and_shuffle(program))
                self.assertNotEqual(renamed.sha256, verify_program(program).sha256)
                self.check(renamed)
        self.check(verify_program(alpha_rename_and_shuffle(body_seed_program())))

    def test_deleted_stores_and_repeated_zero_store_index_reject(self):
        for workload, arms in self.cores.items():
            for mutation in ("delete_stores", "repeated_zero"):
                with self.subTest(workload=workload, mutation=mutation):
                    mutant = deepcopy(arms["deferred"])
                    for number, block in enumerate(mutant["functions"][0]["blocks"]):
                        stores = [op for op in block["ops"] if op["op"] == "buffer.store"]
                        if mutation == "delete_stores":
                            block["ops"] = [op for op in block["ops"] if op["op"] != "buffer.store"]
                        elif stores:
                            name = "zero_store_index_" + str(number)
                            block["ops"].insert(0, c(name, "usize", 0))
                            for store in stores:
                                store["args"][1] = name
                    self.reject_valid_core(mutant)

    def test_actual_start_stride_predicate_and_short_extent_mutants_reject(self):
        for workload, arms in self.cores.items():
            for mutation in ("start_one", "stride_two", "wrong_predicate", "short_extent"):
                with self.subTest(workload=workload, mutation=mutation):
                    mutant = deepcopy(arms["deferred"])
                    mapping = blocks(mutant)
                    if mutation == "start_one":
                        next(op for op in mapping["dg_shared_1"]["ops"]
                             if op["op"] == "const")["attrs"]["value"] = 1
                    elif mutation == "stride_two":
                        for side in ("fast", "slow"):
                            next(op for op in mapping["dg_" + side + "_1"]["ops"]
                                 if op["op"] == "const" and op["out"][0]["type"] == "usize")["attrs"]["value"] = 2
                    elif mutation == "wrong_predicate":
                        mapping["dg_shared_3"]["ops"][0]["op"] = "compare.eq"
                    else:
                        entry = mapping["dg_shared_1"]
                        entry["ops"] += [c("extent_one", "usize", 1),
                            i("int.sub.checked", ["dg_v_3", "extent_one"], [("short_extent", "usize")])]
                        entry["term"]["args"][3] = "short_extent"
                    self.reject_valid_core(mutant)

    def test_extent_phi_zero_preserving_cfg_roots_and_opcodes_rejects(self):
        for workload, arms in self.cores.items():
            with self.subTest(workload=workload):
                mutant = deepcopy(arms["deferred"])
                entry = blocks(mutant)["dg_shared_1"]
                zero = next(op["out"][0]["name"] for op in entry["ops"]
                            if op["op"] == "const" and op["attrs"]["value"] == 0)
                entry["term"]["args"][3] = zero
                original_blocks = blocks(arms["deferred"])
                for name, block in blocks(mutant).items():
                    self.assertEqual(block["ops"], original_blocks[name]["ops"])
                    self.assertEqual(block["params"], original_blocks[name]["params"])
                self.reject_valid_core(mutant)

    def test_stores_for_another_root_cannot_cover_a_load(self):
        self.reject_valid_core(initialized_program(wrong_owner=True))
        swapped = initialized_program(wrong_owner=True)
        mapping = blocks(swapped)
        mapping["exit"]["ops"][0]["args"] = ["eo"]
        edge = mapping["head"]["term"]["else"]["args"]
        edge[0], edge[4] = edge[4], edge[0]
        self.reject_valid_core(swapped)

    def test_every_parallel_header_ingress_must_preserve_extent_and_seed(self):
        for changes in ({"bad_extent": True}, {"bad_seed": True},
                        {"bad_extent": True, "bad_seed": True}):
            with self.subTest(changes=changes):
                self.reject_valid_core(duplicate_header_ingress(**changes))

    def test_direct_body_seed_requires_exact_extent_and_zero_seed(self):
        for mutation in ("wrong_comparison", "wrong_extent", "nonzero_seed"):
            with self.subTest(mutation=mutation):
                program = body_seed_program()
                entry = blocks(program)["entry"]
                if mutation == "wrong_comparison":
                    entry["ops"][-1]["op"] = "compare.eq"
                elif mutation == "wrong_extent":
                    entry["term"]["then"]["args"][1] = "probe"
                elif mutation == "nonzero_seed":
                    next(op for op in entry["ops"] if op["op"] == "const")["attrs"]["value"] = 1
                self.reject_valid_core(program)

    def test_unguarded_zero_body_seed_uses_successful_store_bounds(self):
        # Both branch arms enter the zero-index body. N=0 traps at the store;
        # for N>0 the successful checked store supplies the required bound.
        program = body_seed_program()
        blocks(program)["entry"]["term"]["else"]["target"] = "body"
        report = self.check(verify_program(program))
        fills = [certificate for row in report["functions"]
                 for certificate in row["certificates"] if certificate["kind"] == "counted_fill"]
        self.assertEqual(len(fills), 1)
        self.assertEqual({row["side"] for row in fills[0]["seed_edges"]}, {"then", "else"})

    def test_each_actual_direct_body_seed_edge_binds_exact_extent_and_zero(self):
        for workload, arms in self.cores.items():
            for side in ("then", "else"):
                for mutation in ("extent", "index"):
                    with self.subTest(workload=workload, side=side, mutation=mutation):
                        program = deepcopy(arms["deferred"])
                        guard = blocks(program)["dg_guard_0"]
                        guard["ops"].insert(0, c("wrong_ingress", "usize", 0 if mutation == "extent" else 1))
                        guard["term"][side]["args"][3 if mutation == "extent" else 4] = "wrong_ingress"
                        self.reject_valid_core(program)

    def test_backedge_extent_step_and_store_order_are_checked(self):
        for mutation in ("backedge_extent", "zero_step", "double_step", "step_before_store"):
            with self.subTest(mutation=mutation):
                program = initialized_program()
                body = blocks(program)["body"]
                if mutation == "backedge_extent":
                    body["term"]["args"][1] = "bp"
                elif mutation in {"zero_step", "double_step"}:
                    next(op for op in body["ops"] if op["op"] == "const" and
                         op["out"][0]["name"] == "step")["attrs"]["value"] = 0 if mutation == "zero_step" else 2
                else:
                    step_ops = body["ops"][-2:]
                    body["ops"] = step_ops + body["ops"][:-2]
                self.reject_valid_core(program)

    def test_an_entry_to_load_path_without_completion_rejects(self):
        report = self.reject_valid_core(initialized_program(skip=True))
        # The real loop is certified even though its exit has another incoming
        # edge. That direct entry->exit path is not an empty/completed interval,
        # so cutting only head->exit must still leave the load reachable.
        fills = [certificate for row in report["functions"]
                 for certificate in row["certificates"] if certificate["kind"] == "counted_fill"]
        self.assertEqual(len(fills), 1)
        self.assertEqual(fills[0]["completion_edge"], ["head", "else", "exit"])
        self.assertEqual(report["functions"][0]["reason"], "read_path_without_same_root_completion")
        early = initialized_program()
        blocks(early)["body"]["ops"][:0] = [
            i("borrow.read", ["bo"], [("early_reader", "readbuf")]),
            i("buffer.load", ["early_reader", "bi"], [("early_value", "u8")]),
            i("loan.end", ["early_reader"])]
        self.reject_valid_core(early)

    def test_empty_completion_cuts_only_false_arm_even_with_same_target(self):
        program = body_seed_program()
        mapping = blocks(program)
        mapping["entry"]["term"]["then"]["target"] = "exit"
        program["functions"][0]["blocks"] = [mapping["entry"], mapping["exit"]]
        report = self.reject_valid_core(program)
        certificates = report["functions"][0]["certificates"]
        self.assertEqual(len(certificates), 1)
        self.assertEqual(certificates[0]["kind"], "empty_extent")
        self.assertEqual(certificates[0]["completion_edge"], ["entry", "else", "exit"])
        self.assertEqual(report["functions"][0]["reason"], "read_path_without_same_root_completion")

    def test_repeated_dynamic_allocation_sites_reject(self):
        program = initialized_program()
        blocks(program)["body"]["ops"][:0] = [
            i("buffer.new", ["bn"], [("dynamic_owner", "buffer")]),
            i("owner.drop", ["dynamic_owner"])]
        self.reject_valid_core(program)

    def test_calls_and_missing_witnesses_fail_closed(self):
        program = initialized_program()
        blocks(program)["body"]["ops"].insert(1,
            i("call", ["value"], [("called", "u8")], function="identity"))
        program["functions"].append(f("identity", [("input", "u8")], ["u8"], [], [
            b("entry", [("input", "u8")], [], ret("input"))]))
        self.reject_valid_core(program)
        self.reject_valid_core(m(f("nothing", [], [], [], [b("entry", [], [], ret())])))

    def test_each_bounded_analysis_budget_fails_closed(self):
        program = verify_program(initialized_program())
        for name in ("MAX_BLOCKS", "MAX_OPERATIONS", "MAX_VALUES", "MAX_FLOW_STEPS", "MAX_FLOW_WORK"):
            with self.subTest(budget=name), patch.object(checker, name, 0):
                self.check(program, "rejected")

    def test_changed_checker_identity_or_unexpected_failure_is_unknown(self):
        program = verify_program(initialized_program())
        with patch.object(checker, "checker_identity", side_effect=["a" * 64, "b" * 64]):
            self.check(program, "unknown")
        with patch.object(checker, "checker_identity", side_effect=OSError("unavailable")):
            self.check(program, "unknown")
        with patch.object(checker, "_analyze", side_effect=RuntimeError("analysis failed")):
            self.check(program, "unknown")

    def test_malformed_core_and_forged_verified_wrappers_are_reverified(self):
        malformed = initialized_program()
        blocks(malformed)["body"]["ops"].insert(0,
            {"op": "future.memory.operation", "args": [], "out": [], "attrs": {}})
        for program in (None, {}, {"status": "checked", "authority": "DENY_ALL"}, malformed,
                        VerifiedProgram(json.dumps(malformed).encode("utf-8"))):
            with self.subTest(type=type(program).__name__):
                self.check(program, "rejected")

    def test_checker_never_mutates_core_or_calls_vm_or_native_emitter(self):
        from hepta import hia_program_llvm, hia_program_runtime
        program = deepcopy(self.cores["linear"]["deferred"])
        original = deepcopy(program)
        production_before = verify_initialization_coverage(verify_program(program))
        with patch.object(hia_program_llvm, "emit_program_llvm", side_effect=AssertionError("no emission")) as emitter, \
             patch.object(hia_program_llvm, "compile_program_llvm", side_effect=AssertionError("no compiler")) as compiler, \
             patch.object(hia_program_runtime, "execute_program", side_effect=AssertionError("not finite execution")) as vm:
            report = self.check(program)
        self.assertEqual(program, original)
        emitter.assert_not_called()
        compiler.assert_not_called()
        vm.assert_not_called()
        self.assertEqual(verify_initialization_coverage(verify_program(program)), production_before)
        self.assertFalse(production_before["functions"][0]["eligible"])
        self.assert_deny_all(report)

    def test_old_or_modified_report_is_not_an_input_certificate(self):
        report = self.check(initialized_program())
        report["status"] = "checked"
        report["initialization_elision_authorized"] = True
        self.check(report, "rejected")
        self.reject_valid_core(initialized_program(start=1))


if __name__ == "__main__":
    unittest.main()
