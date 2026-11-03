"""Empty specialization retains complete resource CFGs and actual input guards."""
from __future__ import annotations

import copy
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from hepta.hia_empty_reduction import (empty_reduction_program,
    propose_empty_reduction, verify_empty_reduction)
from hepta.hia_optimization import DEFAULT_POLICY, OptimizationRejected
from hepta.hia_program import verify_program
from hepta.hia_program_runtime import (HIAProgramBudgetExceeded, HIAProgramTrap,
                                       execute_program)
from hepta.hia_program_source import lower_source
from hepta.hia_reduction import propose_reduction_pipeline, reduction_program


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "benchmarks/hia_reduction_release"


class EmptyReductionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = {}
        for workload in ("linear", "affine"):
            base = lower_source((FIXTURES / (workload + ".hepta")).read_text())
            reduction = propose_reduction_pipeline(base, maximum=16, include_induction=True)
            proposal = propose_empty_reduction(base, reduction)
            reduced = reduction_program(base, reduction)
            candidate = empty_reduction_program(base, proposal)
            cls.cases[workload] = base, reduction, proposal, reduced, candidate

    def test_fresh_reduction_and_all_input_guard_proofs_are_required(self):
        for workload, (base, _, proposal, reduced, candidate) in self.cases.items():
            with self.subTest(workload=workload):
                report = verify_empty_reduction(base, proposal)
                self.assertEqual(report["status"], "verified", report)
                self.assertEqual(report["candidate_sha256"], candidate.sha256)
                self.assertEqual(report["reduction_sha256"], reduced.sha256)
                self.assertEqual(report["reduction_verification"]["status"], "verified")
                self.assertEqual([p["result"] for p in report["guard_proofs"]], ["unsat"])
                self.assertTrue(report["claims"]["all_scalar_inputs_checked"])
                self.assertTrue(report["claims"]["core_resource_trace_equivalence_checked"])
                self.assertFalse(report["claims"]["vm_steps_preserved"])
                self.assertFalse(report["claims"]["performance_qualified"])
                self.assertFalse(report["claims"]["backend_refinement_proved"])
                self.assertEqual(report["input_assumptions"], [])
                self.assertEqual(report["added_steps_per_specialized_invocation"], 3)

    def test_vm_values_resources_guard_sides_and_failure_sequence(self):
        for workload, (base, _, _, reduced, candidate) in self.cases.items():
            for n in (0, 1, 15, 16, 17, 73):
                for seed in (0, 255, 2**32 - 1):
                    for failure in (None, 1, 2):
                        with self.subTest(workload=workload, n=n, seed=seed, fail_at=failure):
                            observations = [execute_program(program, "calculate", [n, seed],
                                                            allocation_fail_at=failure)
                                            for program in (base, reduced, candidate)]
                            oracle = sum(((i + seed) if workload == "linear"
                                          else (i * seed + 17)) % 256 for i in range(n))
                            self.assertEqual(observations[-1]["result"],
                                             1001 if n and failure == 1 else oracle)
                            self.assertEqual([r["result"] for r in observations],
                                             [observations[0]["result"]] * 3)
                            self.assertEqual([r["resources"] for r in observations],
                                             [observations[0]["resources"]] * 3)
                            self.assertEqual(observations[-1]["steps"], observations[-2]["steps"] + 3)

    def test_zero_still_creates_and_drops_owner_without_allocator_or_heap(self):
        for workload, (_, _, _, reduced, candidate) in self.cases.items():
            for seed in (0, 2**32 - 1):
                for failure in (None, 1, 2):
                    with self.subTest(workload=workload, seed=seed, fail_at=failure):
                        left, right = [execute_program(program, "calculate", [0, seed],
                                                       max_heap_bytes=0, allocation_fail_at=failure)
                                       for program in (reduced, candidate)]
                        self.assertEqual(left["resources"], right["resources"])
                        expected = {key: 0 for key in right["resources"]}
                        expected.update(owners_created=1, owners_dropped=1)
                        self.assertEqual(right["resources"], expected)
                        self.assertEqual(right["result"], 0)

    def test_over_object_limit_rejection_preserves_empty_failed_owner(self):
        for workload, (base, _, _, _, candidate) in self.cases.items():
            for n in (2**63, 2**64 - 1):
                with self.subTest(workload=workload, n=n):
                    left, right = [execute_program(program, "calculate", [n, 2**32 - 1],
                                                   max_heap_bytes=0, allocation_fail_at=1)
                                   for program in (base, candidate)]
                    self.assertEqual(left["result"], 1001)
                    self.assertEqual(left["result"], right["result"])
                    self.assertEqual(left["resources"], right["resources"])
                    self.assertEqual(right["resources"]["allocation_attempts"], 0)
                    self.assertEqual(right["resources"]["owners_dropped"], 1)

    def test_step_budget_is_explicitly_not_equivalent(self):
        base, _, proposal, reduced, candidate = self.cases["linear"]
        baseline = execute_program(reduced, "calculate", [0, 0])
        self.assertEqual(execute_program(reduced, "calculate", [0, 0],
                                        max_steps=baseline["steps"])["result"], 0)
        with self.assertRaises(HIAProgramBudgetExceeded) as stopped:
            execute_program(candidate, "calculate", [0, 0], max_steps=baseline["steps"])
        self.assertEqual(stopped.exception.code, "steps")
        report = verify_empty_reduction(base, proposal, {**DEFAULT_POLICY, "timeout_ms": 0})
        self.assertNotEqual(report["status"], "verified")
        with self.assertRaises(OptimizationRejected):
            empty_reduction_program(base, proposal, {**DEFAULT_POLICY, "timeout_ms": 0})

    def test_empty_path_keeps_a_specified_trap_after_owner_drop(self):
        source = (FIXTURES / "linear.hepta").read_text().replace(
            "return total;", "return total / (seed as u64);")
        base = lower_source(source)
        reduction = propose_reduction_pipeline(base, maximum=16, include_induction=True)
        candidate = empty_reduction_program(base, propose_empty_reduction(base, reduction))
        for n in (0, 1, 17):
            stopped = []
            for program in (base, candidate):
                with self.assertRaises(HIAProgramTrap) as error:
                    execute_program(program, "calculate", [n, 0])
                stopped.append(error.exception)
            self.assertEqual(stopped[0].code, stopped[1].code)
            self.assertEqual(stopped[0].report["resources"], stopped[1].report["resources"])
            self.assertEqual(stopped[1].report["resources"]["owners_dropped"], 1)

    def test_well_typed_wrong_guards_and_changed_clones_are_rejected(self):
        base, _, proposal, _, _ = self.cases["linear"]
        for mutation in ("nonzero_constant", "inequality", "generic_substitution",
                         "changed_nonempty", "changed_empty"):
            bad = copy.deepcopy(proposal)
            fn = bad["candidate_core"]["functions"][0]
            guard = fn["blocks"][0]
            if mutation == "nonzero_constant":
                guard["ops"][0]["attrs"]["value"] = 1
            elif mutation == "inequality":
                guard["ops"][1]["op"] = "compare.ne"
            elif mutation == "generic_substitution":
                guard["term"]["else"]["args"][0] = guard["ops"][0]["out"][0]["name"]
            elif mutation == "changed_nonempty":
                count = (len(fn["blocks"]) - 1) // 2
                op = next(op for block in fn["blocks"][1:count + 1]
                          for op in block["ops"] if op["op"] == "int.add.wrap")
                op["op"] = "int.sub.wrap"
            else:
                count = (len(fn["blocks"]) - 1) // 2
                op = next(op for block in fn["blocks"][count + 1:]
                          for op in block["ops"] if op["op"] == "const"
                          and op["out"][0]["type"] == "u64" and op["attrs"]["value"] == 0)
                op["attrs"]["value"] = 1
            with self.subTest(mutation=mutation):
                verify_program(bad["candidate_core"])
                self.assertEqual(verify_empty_reduction(base, bad)["status"], "rejected")
                with self.assertRaises(OptimizationRejected):
                    empty_reduction_program(base, bad)

    def test_bare_zero_return_cannot_erase_resource_trace(self):
        base, _, proposal, _, _ = self.cases["linear"]
        bad = copy.deepcopy(proposal)
        fn = bad["candidate_core"]["functions"][0]
        count = (len(fn["blocks"]) - 1) // 2
        empty = {"id": "bare_empty", "params": [], "ops": [
            {"op": "const", "args": [], "out": [{"name": "bare_zero", "type": "u64"}],
             "attrs": {"value": 0}}], "term": {"op": "ret", "values": ["bare_zero"]}}
        fn["blocks"][0]["term"]["then"] = {"target": "bare_empty", "args": []}
        fn["blocks"] = fn["blocks"][:count + 1] + [empty]
        verify_program(bad["candidate_core"])
        self.assertEqual(execute_program(bad["candidate_core"], "calculate", [0, 0])["resources"]["owners_created"], 0)
        self.assertEqual(verify_empty_reduction(base, bad)["status"], "rejected")

    def test_proposal_is_detached_deterministic_and_source_bound(self):
        base, reduction, proposal, _, _ = self.cases["linear"]
        saved = copy.deepcopy(reduction)
        self.assertEqual(propose_empty_reduction(base, reduction), proposal)
        self.assertEqual(reduction, saved)
        changed = copy.deepcopy(proposal)
        changed["base_sha256"] = "0" * 64
        self.assertEqual(verify_empty_reduction(base, changed)["status"], "rejected")

    def test_other_functions_are_preserved_and_checked(self):
        base = self.cases["linear"][0].as_dict()
        other = {"name": "other", "params": [], "returns": ["u64"], "effects": [],
                 "entry": "other_entry", "blocks": [{"id": "other_entry", "params": [],
                 "ops": [{"op": "const", "args": [],
                          "out": [{"name": "answer", "type": "u64"}], "attrs": {"value": 7}}],
                 "term": {"op": "ret", "values": ["answer"]}}]}
        base["functions"].append(other)
        reduction = propose_reduction_pipeline(base, maximum=16, include_induction=True)
        proposal = propose_empty_reduction(base, reduction)
        self.assertEqual(proposal["candidate_core"]["functions"][-1], other)
        self.assertEqual(verify_empty_reduction(base, proposal)["status"], "verified")
        proposal["candidate_core"]["functions"][-1]["blocks"][0]["ops"][0]["attrs"]["value"] = 8
        verify_program(proposal["candidate_core"])
        self.assertEqual(verify_empty_reduction(base, proposal)["status"], "rejected")

    def test_independent_clone_names_still_verify(self):
        base, _, proposal, _, candidate = self.cases["linear"]
        renamed = copy.deepcopy(proposal)
        function = renamed["candidate_core"]["functions"][0]
        blocks, values = {}, {}
        for index, block in enumerate(function["blocks"][1:]):
            blocks[block["id"]] = "independent_block_" + str(index)
            definitions = block["params"] + [out for op in block["ops"] for out in op["out"]]
            for definition in definitions:
                values[definition["name"]] = "independent_value_" + str(len(values))
        for block in function["blocks"]:
            block["id"] = blocks.get(block["id"], block["id"])
            for parameter in block["params"]:
                parameter["name"] = values.get(parameter["name"], parameter["name"])
            for op in block["ops"]:
                op["args"] = [values.get(a, a) for a in op["args"]]
                for output in op["out"]:
                    output["name"] = values.get(output["name"], output["name"])
            term = block["term"]
            if term["op"] == "ret":
                term["values"] = [values.get(a, a) for a in term["values"]]
            elif term["op"] in {"jump", "branch"}:
                edges = [term] if term["op"] == "jump" else [term["then"], term["else"]]
                if term["op"] == "branch":
                    term["cond"] = values.get(term["cond"], term["cond"])
                for edge in edges:
                    edge["target"] = blocks[edge["target"]]
                    edge["args"] = [values.get(a, a) for a in edge["args"]]
        self.assertNotEqual(verify_program(renamed["candidate_core"]).sha256, candidate.sha256)
        self.assertEqual(verify_empty_reduction(base, renamed)["status"], "verified")


CLANG = os.environ.get("HEPTA_TEST_CLANG", os.environ.get("CLANG", "clang"))
_NATIVE_OBSERVER = r"""
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
uint64_t calculate(uint64_t, uint32_t);
void *__real_malloc(size_t);
void *__real_calloc(size_t, size_t);
void __real_free(void *);
static unsigned attempts, frees, null_frees;
static int refuse;
void *__wrap_malloc(size_t n) { attempts++; return refuse ? NULL : __real_malloc(n); }
void *__wrap_calloc(size_t n, size_t m) { attempts++; return refuse ? NULL : __real_calloc(n, m); }
void __wrap_free(void *p) { frees++; null_frees += p == NULL; __real_free(p); }
int main(void) {
    const uint64_t lengths[] = {0, 1, 15, 16, 17, 73, UINT64_C(1) << 63, UINT64_MAX};
    const uint32_t seeds[] = {0, 255, UINT32_MAX};
    unsigned checked = 0;
    for (unsigned i = 0; i < sizeof(lengths) / sizeof(lengths[0]); i++)
      for (unsigned j = 0; j < sizeof(seeds) / sizeof(seeds[0]); j++)
        for (int fail = 0; fail <= 1; fail++) {
          uint64_t n = lengths[i], expected = 0;
          uint32_t seed = seeds[j];
          int outside = n > INT64_MAX;
          if (outside || (n && fail)) expected = 1001;
          else for (uint64_t k = 0; k < n; k++)
            expected += (uint8_t)(AFFINE ? (uint32_t)k * seed + 17 : (uint32_t)k + seed);
          attempts = frees = null_frees = 0;
          refuse = fail;
          uint64_t actual = calculate(n, seed);
          if (actual != expected || attempts != (unsigned)(n && !outside)
              || frees != (unsigned)(n && !outside && !fail) || null_frees) return 11;
          checked++;
        }
    printf("correctness_cases=%u\n", checked);
    return 0;
}
"""


@unittest.skipUnless(shutil.which(CLANG), "actual Clang required for non-timed native correctness")
class EmptyReductionNativeTests(unittest.TestCase):
    def test_existing_native_gate_values_and_wrapped_allocator_calls(self):
        from hepta.hia_program_llvm import build_program_native
        with tempfile.TemporaryDirectory(prefix="hia-empty-reduction-") as folder:
            directory = Path(folder)
            observer = directory / "observer.c"
            observer.write_text(_NATIVE_OBSERVER)
            for workload in ("linear", "affine"):
                base = lower_source((FIXTURES / (workload + ".hepta")).read_text())
                reduction = propose_reduction_pipeline(base, maximum=16, include_induction=True)
                candidate = empty_reduction_program(base, propose_empty_reduction(base, reduction))
                obj, binary = directory / (workload + ".o"), directory / workload
                receipt = build_program_native(candidate, obj, clang=CLANG, kind="object")
                self.assertEqual(receipt["core_sha256"], candidate.sha256)
                linked = subprocess.run([CLANG, "-O3", "-DAFFINE=" + str(int(workload == "affine")),
                    str(observer), str(obj), "-Wl,--wrap=malloc", "-Wl,--wrap=calloc", "-Wl,--wrap=free",
                    "-o", str(binary)], capture_output=True, text=True, timeout=60)
                self.assertEqual(linked.returncode, 0, linked.stderr)
                ran = subprocess.run([str(binary)], capture_output=True, text=True, timeout=30)
                self.assertEqual(ran.returncode, 0, ran.stdout + ran.stderr)
                self.assertEqual(ran.stdout.strip(), "correctness_cases=48")


if __name__ == "__main__":
    unittest.main()
