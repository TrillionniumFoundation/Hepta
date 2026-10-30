"""Production consumers of shared CFG/resource rules and independent outcomes."""
from copy import deepcopy
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from hepta import hia_semantic_kernel as kernel
from hepta.hia_incremental import IncrementalVerifier
from hepta.hia_program import HIAProgramRejected, verify_program
from hepta.hia_program_llvm import build_program_native, emit_program_llvm, native_host_profile
from hepta.hia_program_runtime import HIAProgramBudgetExceeded, HIAProgramTrap, execute_program
from tests.test_hia_program import b, branch, c, f, i, jump, m, p, ret, resource_program
from tools.qualify_hia_program_resources import build_resource_program, negative_cases


def rotating_owner_loop():
    return m(f("rotate", [("n", "u32")], ["u32"], ["alloc", "read", "write", "trap"], [
        b("entry", [("n", "u32")], [c("size", "usize", 1), c("a", "u32", 13),
            c("z", "u32", 29), i("buffer.new", ["size"], [("owner", "buffer")]),
            i("borrow.mut", ["owner"], [("view", "mutbuf")])],
          jump("loop", "n", "a", "z", "owner", "view")),
        b("loop", [("ln", "u32"), ("la", "u32"), ("lz", "u32"),
            ("lo", "buffer"), ("lv", "mutbuf")], [c("zero", "u32", 0),
            i("compare.gt", ["ln", "zero"], [("more", "bool")])],
          branch("more", ("body", "ln", "la", "lz", "lo", "lv"), ("done", "la", "lo", "lv"))),
        b("body", [("bn", "u32"), ("ba", "u32"), ("bz", "u32"),
            ("bo", "buffer"), ("bv", "mutbuf")], [c("one", "u32", 1),
            c("index", "usize", 0), i("int.cast", ["ba"], [("byte", "u8")], mode="checked"),
            i("buffer.store", ["bv", "index", "byte"]),
            i("int.sub.checked", ["bn", "one"], [("next", "u32")])],
          jump("loop", "next", "bz", "ba", "bo", "bv")),
        b("done", [("answer", "u32"), ("do", "buffer"), ("dv", "mutbuf")],
          [i("loan.end", ["dv"]), i("owner.drop", ["do"])], ret("answer")),
    ]))


class SemanticKernelTests(unittest.TestCase):
    def test_loop_parallel_swap_and_owner_loan_edges(self):
        doc = rotating_owner_loop()
        for n in range(40):
            result = execute_program(doc, "rotate", [n])
            self.assertEqual(result["result"], 29 if n % 2 else 13)
            self.assertEqual(result["resources"]["live_bytes"], 0)
            self.assertEqual(result["resources"]["live_local_loans"], 0)

    def test_independent_failure_cancel_and_cleanup_observations(self):
        doc = build_resource_program()
        for n in (0, 1, 17, 257):
            for stop in (False, True):
                for fail in (None, 1, 2):
                    result = execute_program(doc, "pipeline", [n, 23, stop], allocation_fail_at=fail)
                    failure = fail == 1 or fail == 2 and n != 0
                    self.assertEqual(result["result"], 99 if failure else 77 if stop else n + 23)
                    self.assertEqual(result["resources"]["live_owners"], 0)
                    self.assertEqual(result["resources"]["live_bytes"], 0)
                    self.assertEqual(result["resources"]["live_local_loans"], 0)

    def test_rejects_resource_errors_on_unexecuted_cfg_arms(self):
        for row in negative_cases():
            with self.subTest(case=row["case"]):
                self.assertTrue(row["ok"], row)

    def test_every_step_stop_retains_stopped_ledger(self):
        doc = rotating_owner_loop()
        complete = execute_program(doc, "rotate", [3])
        stops_with_loan = 0
        for limit in range(1, complete["steps"]):
            with self.assertRaises(HIAProgramBudgetExceeded) as stop:
                execute_program(doc, "rotate", [3], max_steps=limit)
            report = stop.exception.report
            self.assertEqual(report["status"], "budget_exceeded")
            self.assertEqual(report["steps"], limit + 1)
            self.assertGreaterEqual(report["resources"]["live_bytes"], 0)
            stops_with_loan += report["resources"]["live_local_loans"] > 0
        self.assertGreater(stops_with_loan, 0)
        self.assertEqual(execute_program(doc, "rotate", [3], max_steps=complete["steps"])["result"], 29)

    def test_heap_stop_precedes_allocator_failure_schedule(self):
        doc = build_resource_program()
        with self.assertRaises(HIAProgramBudgetExceeded) as stop:
            execute_program(doc, "pipeline", [17, 7, False], max_heap_bytes=1, allocation_fail_at=2)
        self.assertEqual(stop.exception.code, "heap")
        self.assertEqual(stop.exception.report["resources"]["allocation_attempts"], 1)
        self.assertEqual(stop.exception.report["resources"]["live_bytes"], 1)
        returned = execute_program(doc, "pipeline", [17, 7, False], max_heap_bytes=18, allocation_fail_at=2)
        self.assertEqual(returned["result"], 99)
        self.assertEqual(returned["resources"]["live_bytes"], 0)

    def test_trap_retains_owner_and_loan_without_unwind_claim(self):
        with self.assertRaises(HIAProgramTrap) as stop:
            execute_program(resource_program(), "owned", [0, 19])
        self.assertEqual(stop.exception.code, "bounds")
        r = stop.exception.report["resources"]
        self.assertEqual((r["live_owners"], r["live_local_loans"], r["owners_dropped"]), (1, 1, 0))
        self.assertFalse(stop.exception.report["semantic_contract"]["claims"]["native_VM_budget_equivalence"])

    def test_clean_return_failure_does_not_partially_consume_state(self):
        caps = {"o": kernel.Capability("buffer", "o"), "leak": kernel.Capability("buffer", "leak")}
        before = dict(caps)
        with self.assertRaises(kernel.SemanticRejected):
            kernel.require_clean_return(["o"], ["buffer"], [None], caps)
        self.assertEqual(caps, before)

    def test_kernel_rejects_truncation_duplicate_destinations_and_nonbool(self):
        with self.assertRaises(kernel.SemanticRejected):
            kernel.require_clean_return([], [], [None], {})
        with self.assertRaises(kernel.SemanticRejected):
            kernel.parallel_edge_values(["a"], [], lambda _: 0)
        with self.assertRaises(kernel.SemanticRejected):
            kernel.transfer_capabilities(["a", "b"], ["buffer", "buffer"],
                [p("same", "buffer"), p("same", "buffer")],
                {"a": kernel.Capability("buffer", "a"), "b": kernel.Capability("buffer", "b")})
        with self.assertRaises(kernel.SemanticRejected):
            kernel.selected_successor(branch("c", ("yes",), ("no",)), 1)

    def test_external_origin_survives_rename(self):
        caps = {"parent": kernel.Capability("mutbuf", "parent", external=True, origin="formal"),
                "child": kernel.Capability("readbuf", "parent", "parent", origin="formal")}
        result = kernel.transfer_capabilities(["child", "parent"], ["readbuf", "mutbuf"],
            [p("new_child", "readbuf"), p("new_parent", "mutbuf")], caps)
        self.assertEqual(result["new_child"].root, "new_parent")
        self.assertEqual(result["new_child"].parent, "new_parent")
        self.assertEqual(result["new_child"].origin, "formal")
        self.assertEqual(result["new_parent"].origin, "formal")

    def test_cache_rechecks_after_live_kernel_rule_replacement(self):
        doc = rotating_owner_loop()
        session = IncrementalVerifier(doc)
        def refuse(*args, **kwargs):
            raise kernel.SemanticRejected("changed rule refuses", "E_HIA_LOAN")
        with patch.object(kernel, "borrowed_capability", refuse):
            with self.assertRaisesRegex(HIAProgramRejected, "changed rule refuses"):
                session.verify(doc)
        self.assertEqual(session.base_sha256, verify_program(doc).sha256)

    def test_cache_rechecks_after_live_kernel_constant_replacement(self):
        doc = rotating_owner_loop()
        session = IncrementalVerifier(doc)
        with patch.object(kernel, "OWNERS", frozenset({"chain"})):
            with self.assertRaises(HIAProgramRejected):
                session.verify(doc)

    def test_vm_and_llvm_use_shared_cfg_relation(self):
        doc = rotating_owner_loop()
        original = kernel.parallel_edge_values
        with patch.object(kernel, "parallel_edge_values", wraps=original) as observed:
            execute_program(doc, "rotate", [5])
            self.assertGreater(observed.call_count, 5)
        with patch.object(kernel, "parallel_edge_values", wraps=original) as observed:
            ir = emit_program_llvm(verify_program(doc))
            self.assertEqual(observed.call_count, 4)
            self.assertIn("phi i32", ir.text)

    def test_chain_layout_and_object_limit_are_shared_with_native_ir(self):
        from hepta.hia_program_llvm import _BUFFER_RUNTIME, _CHAIN_RUNTIME
        self.assertIn("i64 " + str(kernel.CHAIN_NODE_BYTES), _CHAIN_RUNTIME)
        self.assertIn(str(kernel.MAX_OBJECT_BYTES), _BUFFER_RUNTIME)
        self.assertNotIn("HIA_CHAIN_NODE_BYTES", _CHAIN_RUNTIME)
        self.assertEqual(kernel.allocation_admission(0, 0, 0), "empty")
        self.assertEqual(kernel.allocation_admission(1 << 63, 0, 0), "object_size")


CLANG = os.environ.get("CLANG", "/usr/lib/llvm-20/bin/clang")


@unittest.skipUnless(shutil.which(CLANG) and shutil.which("gcc"), "actual native Clang and GCC required")
class SemanticKernelNativeTests(unittest.TestCase):
    def test_actual_c_abi_loop_and_failure_cancel_resource_ledger(self):
        source = r'''
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
extern uint64_t pipeline(size_t, uint8_t, bool);
extern uint32_t rotate(uint32_t);
void *__real_malloc(size_t); void *__real_calloc(size_t,size_t); void __real_free(void*);
static size_t attempts, live, fail_at, active, peak;
static void *addresses[8]; static size_t lengths[8];
static void *record(void *p, size_t n) {
  if(p) { for(size_t i=0;i<8;i++) if(!addresses[i]) {addresses[i]=p;lengths[i]=n;live+=n;if(live>peak)peak=live;return p;} _Exit(92); }
  return p;
}
void *__wrap_malloc(size_t n){if(!active)return __real_malloc(n);if(++attempts==fail_at)return NULL;return record(__real_malloc(n),n);}
void *__wrap_calloc(size_t n,size_t z){if(!active)return __real_calloc(n,z);if(++attempts==fail_at)return NULL;return record(__real_calloc(n,z),n*z);}
void __wrap_free(void *p){if(active && p){bool found=false;for(size_t i=0;i<8;i++)if(addresses[i]==p){live-=lengths[i];addresses[i]=NULL;found=true;break;}if(!found)_Exit(93);}__real_free(p);}
int main(int argc,char **argv){if(argc!=5)return 2;size_t n=strtoull(argv[1],0,10);fail_at=strtoull(argv[3],0,10);active=1;
  uint64_t answer=atoi(argv[4]) ? rotate((uint32_t)n) : pipeline(n,23,atoi(argv[2])!=0);
  active=0; printf("%llu %zu %zu %zu\n",(unsigned long long)answer,attempts,live,peak);return 0;}
'''
        with tempfile.TemporaryDirectory(prefix="hia-semantic-native-") as tmp:
            root = Path(tmp)
            doc = build_resource_program()
            doc["functions"].extend(rotating_owner_loop()["functions"])
            obj, driver, exe = root / "program.o", root / "driver.c", root / "run"
            receipt = build_program_native(doc, obj, kind="object", clang=CLANG,
                                           target=native_host_profile()["target"])
            self.assertEqual(receipt["core_sha256"], verify_program(doc).sha256)
            driver.write_text(source)
            subprocess.run(["gcc", "-std=c11", "-O2", str(driver), str(obj), "-o", str(exe),
                "-Wl,--wrap=malloc", "-Wl,--wrap=calloc", "-Wl,--wrap=free"],
                check=True, capture_output=True, timeout=30)
            cases = [(n, stop, fail, 0) for n in (0, 1, 17, 257) for stop in (0, 1) for fail in (0, 1, 2)]
            cases += [(n, 0, 0, 1) for n in (0, 1, 2, 7, 32, 63)]
            for n, stop, fail, rotate in cases:
                args = [n] if rotate else [n, 23, bool(stop)]
                vm = execute_program(doc, "rotate" if rotate else "pipeline", args,
                                     allocation_fail_at=fail or None)
                run = subprocess.run([str(exe), str(n), str(stop), str(fail), str(rotate)],
                                     capture_output=True, text=True, timeout=5, check=True)
                self.assertEqual([int(v) for v in run.stdout.split()], [vm["result"],
                    vm["resources"]["allocation_attempts"], 0, vm["resources"]["peak_bytes"]])


if __name__ == "__main__":
    unittest.main()
