"""Independently submitted Core and poison-malloc initialization controls."""
from __future__ import annotations

from copy import deepcopy
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_initialization import initialization_coverage, verify_initialization_coverage
from hepta.hia_program import verify_program
from hepta.hia_program_llvm import compile_program_llvm, emit_program_llvm
from hepta.hia_program_runtime import execute_program
from tests.test_hia_program import b, branch, c, f, i, jump, m, ret

CLANG = os.environ.get("CLANG", "clang")


def initialized_program(*, start=0, step=1, wrong_index=False, skip=False, wrong_owner=False):
    parameters = [("n", "usize"), ("probe", "usize")] + ([("skip", "bool")] if skip else [])
    suffix = [("other", "buffer")] if wrong_owner else []
    hp = [("ho", "buffer"), ("hn", "usize"), ("hi", "usize"), ("hp", "usize")] + suffix
    bp = [("bo", "buffer"), ("bn", "usize"), ("bi", "usize"), ("bp", "usize")] + ([("bo2", "buffer")] if wrong_owner else [])
    ep = [("eo", "buffer"), ("en", "usize"), ("ei", "usize"), ("ep", "usize")] + ([("eo2", "buffer")] if wrong_owner else [])
    entry_ops = [i("buffer.new", ["n"], [("owner", "buffer")]), c("start", "usize", start)]
    if wrong_owner:
        entry_ops.append(i("buffer.new", ["n"], [("other_owner", "buffer")]))
    entry_args = ["owner", "n", "start", "probe"] + (["other_owner"] if wrong_owner else [])
    body_args = [p[0] for p in hp]
    body_ops = [c("value", "u8", 7), i("borrow.mut", ["bo"], [("writer", "mutbuf")])]
    if wrong_index:
        body_ops.append(c("zero_index", "usize", 0))
    body_ops += [i("buffer.store", ["writer", "zero_index" if wrong_index else "bi", "value"]),
                 i("loan.end", ["writer"]), c("step", "usize", step),
                 i("int.add.checked", ["bi", "step"], [("next", "usize")])]
    body_back = ["bo", "bn", "next", "bp"] + (["bo2"] if wrong_owner else [])
    exit_ops = [i("borrow.read", ["eo2" if wrong_owner else "eo"], [("reader", "readbuf")]),
                i("buffer.load", ["reader", "ep"], [("answer", "u8")]),
                i("loan.end", ["reader"]), i("owner.drop", ["eo"])]
    if wrong_owner:
        exit_ops.append(i("owner.drop", ["eo2"]))
    entry_term = (branch("skip", ("exit", *entry_args), ("head", *entry_args)) if skip else jump("head", *entry_args))
    return m(f("initialized", parameters, ["u8"], ["alloc", "read", "write", "trap"], [
        b("entry", parameters, entry_ops, entry_term),
        b("head", hp, [i("compare.lt", ["hi", "hn"], [("more", "bool")])],
          branch("more", ("body", *body_args), ("exit", *body_args))),
        b("body", bp, body_ops, jump("head", *body_back)),
        b("exit", ep, exit_ops, ret("answer")),
    ]))


class InitializationCoverageTests(unittest.TestCase):
    def report(self, program):
        checked = verify_program(program)
        return verify_initialization_coverage(checked)["functions"][0]

    def test_complete_zero_based_loop_has_same_root_and_exact_coverage_witness(self):
        program = initialized_program()
        result = self.report(program)
        self.assertTrue(result["eligible"], result)
        self.assertEqual(len(result["witnesses"]), 1)
        witness = result["witnesses"][0]
        self.assertEqual((witness["header"], witness["completed_exit"], witness["allocation"]), ("head", "exit", "owner"))
        self.assertFalse(result["claims"]["backend_refinement_proved"])
        self.assertIn("@__hia_allocate(i64 %p_0_0, i1 false)", emit_program_llvm(verify_program(program)).text)

    def test_partial_stride_skipped_and_different_owner_reads_keep_zero_initialization(self):
        cases = (initialized_program(start=1), initialized_program(step=2),
                 initialized_program(wrong_index=True), initialized_program(skip=True),
                 initialized_program(wrong_owner=True))
        for program in cases:
            with self.subTest(program=program):
                result = self.report(program)
                self.assertFalse(result["eligible"], result)
                self.assertIn("@__hia_allocate(i64 %p_0_0, i1 true)", emit_program_llvm(verify_program(program)).text)
        self.assertEqual(execute_program(cases[0], "initialized", [7, 0])["result"], 0)
        self.assertEqual(execute_program(cases[1], "initialized", [7, 1])["result"], 0)
        self.assertEqual(execute_program(cases[-1], "initialized", [7, 6])["result"], 0)

    def test_read_before_store_and_repeated_dynamic_allocation_sites_refuse(self):
        for extra in ("read", "allocation"):
            program = initialized_program()
            ops = program["functions"][0]["blocks"][2]["ops"]
            if extra == "read":
                ops[:0] = [i("borrow.read", ["bo"], [("early", "readbuf")]),
                           i("buffer.load", ["early", "bi"], [("old", "u8")]), i("loan.end", ["early"])]
            else:
                ops[:0] = [i("buffer.new", ["bn"], [("dynamic", "buffer")]), i("owner.drop", ["dynamic"])]
            self.assertFalse(self.report(program)["eligible"])

    def test_requested_extent_mismatch_and_unknown_operations_refuse(self):
        program = initialized_program()
        entry = program["functions"][0]["blocks"][0]
        entry["ops"] += [c("one", "usize", 1), i("int.sub.checked", ["n", "one"], [("short", "usize")])]
        entry["term"]["args"][1] = "short"
        self.assertFalse(self.report(program)["eligible"])
        raw = initialized_program()["functions"][0]
        raw["blocks"][2]["ops"].insert(0, {"op": "future.memory.operation", "args": [], "out": [], "attrs": {}})
        self.assertFalse(initialization_coverage(raw)["eligible"])

    def test_narrowed_extent_and_exit_owner_substitution_are_not_name_proofs(self):
        narrowed = initialized_program()
        entry = narrowed["functions"][0]["blocks"][0]
        entry["ops"] += [i("int.cast", ["n"], [("small", "u8")], mode="wrap"),
                         i("int.cast", ["small"], [("short", "usize")], mode="wrap")]
        entry["term"]["args"][1] = "short"
        self.assertFalse(self.report(narrowed)["eligible"])
        self.assertEqual(execute_program(narrowed, "initialized", [257, 256])["result"], 0)
        swapped = initialized_program(wrong_owner=True)
        header, exit_block = swapped["functions"][0]["blocks"][1], swapped["functions"][0]["blocks"][3]
        exit_block["ops"][0]["args"] = ["eo"]
        arguments = header["term"]["else"]["args"]
        arguments[0], arguments[4] = arguments[4], arguments[0]
        self.assertFalse(self.report(swapped)["eligible"])
        self.assertEqual(execute_program(swapped, "initialized", [7, 6])["result"], 0)

    def test_saved_or_mutated_witness_is_not_native_admission_authority(self):
        program = initialized_program(start=1)
        receipt = self.report(program)
        receipt.update(eligible=True, witnesses=[{"claim": "all initialized"}])
        text = emit_program_llvm(verify_program(program)).text
        self.assertIn("@__hia_allocate(i64 %p_0_0, i1 true)", text)

    def test_analysis_budget_exhaustion_and_calls_keep_initialized_allocation(self):
        from hepta import hia_initialization as checker
        program = initialized_program()
        with patch.object(checker, "MAX_FLOW_STEPS", 0):
            self.assertFalse(self.report(program)["eligible"])
            self.assertIn("@__hia_allocate(i64 %p_0_0, i1 true)", emit_program_llvm(verify_program(program)).text)
        function = program["functions"][0]
        function["blocks"][2]["ops"].insert(1, i("call", ["value"], [("called", "u8")], function="identity"))
        program["functions"].append(f("identity", [("input", "u8")], ["u8"], [], [
            b("entry", [("input", "u8")], [], ret("input"))]))
        self.assertFalse(self.report(program)["eligible"])

    def test_existing_guarded_and_narrowed_source_retains_both_complete_fill_witnesses(self):
        from hepta.hia_program_source import lower_source
        from hepta.hia_narrowing import propose_guarded_narrowing
        root = Path(__file__).resolve().parents[1]
        base = lower_source((root / "benchmarks/hia_native_ndu/kernel.hepta").read_text())
        proposal = propose_guarded_narrowing(base, maximum=65536, include_induction=True)
        candidate = verify_program(proposal["narrowing"]["candidate_core"])
        result = verify_initialization_coverage(candidate)["functions"][0]
        self.assertTrue(result["eligible"], result)
        self.assertEqual(len(result["witnesses"]), 2)


DRIVER = r'''
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
void *__real_malloc(size_t); void *__real_calloc(size_t,size_t); void __real_free(void *);
static size_t plain, zeroed, released, live;
void *__wrap_malloc(size_t n) { if(n==12281)return NULL; void *p=__real_malloc(n); if(p){memset(p,0xa5,n);plain++;live++;}return p; }
void *__wrap_calloc(size_t n,size_t z) {if(n*z==12281)return NULL;void *p=__real_calloc(n,z);if(p){zeroed++;live++;}return p;}
void __wrap_free(void *p) {if(p){released++;live--;}__real_free(p);}
uint8_t complete(size_t,size_t); uint8_t starts_one(size_t,size_t); uint8_t stride_two(size_t,size_t);
uint8_t wrong_index(size_t,size_t); uint8_t wrong_owner(size_t,size_t); uint8_t skip_fill(size_t,size_t,_Bool);
int main(int argc,char **argv) {
  int mode=argc>1?atoi(argv[1]):0;
  if(mode==1)return complete(0,0);
  if(mode==2)return complete(7,7);
  if(mode==3)return complete(12281,0);
  if(mode==4)return complete(SIZE_MAX,0);
  const size_t sizes[]={1,2,3,37,83,193,1153};
  for(size_t i=0;i<sizeof(sizes)/sizeof(sizes[0]);i++)if(complete(sizes[i],sizes[i]-1)!=7)return 81;
  if(starts_one(7,0)!=0 || stride_two(7,1)!=0 || wrong_index(7,6)!=0 || wrong_owner(7,6)!=0 || skip_fill(7,0,1)!=0)return 82;
  printf("plain=%zu zeroed=%zu freed=%zu live=%zu\n",plain,zeroed,released,live);
  return plain!=7 || zeroed!=6 || released!=13 || live!=0;
}
'''


@unittest.skipUnless(shutil.which(CLANG), "actual Clang required for poison-malloc controls")
class InitializationNativeTests(unittest.TestCase):
    def test_poison_malloc_positive_partial_fill_negative_and_bounds_refusal_paths(self):
        rows = [("complete", initialized_program()), ("starts_one", initialized_program(start=1)),
                ("stride_two", initialized_program(step=2)), ("wrong_index", initialized_program(wrong_index=True)),
                ("wrong_owner", initialized_program(wrong_owner=True)), ("skip_fill", initialized_program(skip=True))]
        functions = []
        for name, program in rows:
            fn = deepcopy(program["functions"][0]); fn["name"] = name; functions.append(fn)
        core = verify_program(m(*functions))
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder)
            obj, source, driver = directory / "core.o", directory / "driver.c", directory / "driver"
            compile_program_llvm(emit_program_llvm(core), program=core, output=obj, clang=CLANG, kind="object")
            source.write_text(DRIVER)
            linked = subprocess.run([CLANG, "-O2", str(source), str(obj), "-Wl,--wrap=malloc", "-Wl,--wrap=calloc", "-Wl,--wrap=free", "-o", str(driver)], capture_output=True, text=True, timeout=60)
            self.assertEqual(linked.returncode, 0, linked.stderr)
            normal = subprocess.run([str(driver)], capture_output=True, text=True, timeout=10)
            self.assertEqual(normal.returncode, 0, normal.stdout + normal.stderr)
            self.assertEqual(normal.stdout.strip(), "plain=7 zeroed=6 freed=13 live=0")
            for mode in range(1, 5):
                result = subprocess.run([str(driver), str(mode)], capture_output=True, timeout=10)
                self.assertEqual(result.returncode, -signal.SIGABRT)
            # Independent unsound-candidate control: bypassing the witness
            # changes an actually observed byte from Core's 0 to poisoned 165.
            bad = verify_program(initialized_program(start=1))
            with patch("hepta.hia_program_llvm._can_elide_zero_initialization", return_value=True):
                text = emit_program_llvm(bad).text
            poisoned_ir = directory / "unverified-control.ll"
            poisoned_ir.write_text(text)
            minimal = directory / "negative.c"
            minimal.write_text('#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\nvoid *__real_malloc(size_t);void *__wrap_malloc(size_t n){void*p=__real_malloc(n);if(p)memset(p,165,n);return p;}\nunsigned char initialized(size_t,size_t);int main(void){printf("%u\\n",initialized(7,0));return 0;}\n')
            negative = directory / "negative"
            result = subprocess.run([CLANG, "-O2", str(minimal), str(poisoned_ir), "-Wl,--wrap=malloc", "-o", str(negative)], capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stderr)
            result = subprocess.run([str(negative)], capture_output=True, text=True, timeout=10)
            self.assertEqual(result.stdout.strip(), "165")
            self.assertEqual(execute_program(bad, "initialized", [7, 0])["result"], 0)


if __name__ == "__main__":
    unittest.main()
