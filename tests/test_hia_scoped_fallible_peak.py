"""Independent failure/cleanup controls for the narrow fallible cyclic peak.

The admission bounds requested live payload only. Native observations below
cover a finite two-owner loop and cannot prove LLVM refinement, allocator
metadata bounds, process RSS, termination or a general heap invariant.
"""
from __future__ import annotations

import os
from pathlib import Path
import platform
import shutil
import tempfile
import unittest

from hepta.clang_capture import run_bounded
from hepta.hia_heap_bound import analyze_constant_live_heap, qualify_live_heap_budget
from hepta.hia_program import verify_program
from hepta.hia_program_llvm import compile_program_llvm, emit_program_llvm
from hepta.hia_program_runtime import execute_program
from hepta.hia_static_budget import HIAStaticBudgetRejected
from tests.test_hia_program import b, c, i, jump
from tests.test_hia_scoped_alloc_loops import scoped_loop


CLANG = os.environ.get("CLANG", "/usr/lib/llvm-20/bin/clang")


def two_fallible_owners():
    source = scoped_loop(two_allocations=True)
    for block in source["functions"][0]["blocks"]:
        for operation in block["ops"]:
            if operation["op"] == "buffer.new":
                operation["op"] = "buffer.try_new"
                operation["out"].append({"name": operation["out"][0]["name"] + "_ok",
                                         "type": "bool"})
    return source


def expected_peak(iterations, fail_at):
    # Independent arithmetic for two overlapping requests of 9 and 4 bytes
    # in each iteration. Either successful owner is released before the edge.
    return max((sum(amount for number, amount in ((2 * turn + 1, 9), (2 * turn + 2, 4))
                    if number != fail_at) for turn in range(iterations)), default=0)


class FalliblePeakBoundaryTests(unittest.TestCase):
    def test_two_overlapping_fallible_requests_are_summed_on_every_failure_path(self):
        core = verify_program(two_fallible_owners())
        self.assertEqual(analyze_constant_live_heap(core), {"count_down": 13})
        qualify_live_heap_budget(core, max_live_heap_bytes=13)
        for count in (0, 1, 3, 7):
            for fail_at in (None, 1, 2, 5, 14):
                with self.subTest(count=count, fail_at=fail_at):
                    observed = execute_program(core, "count_down", [count], allocation_fail_at=fail_at)
                    resource = observed["resources"]
                    successful = 2 * count - int(fail_at is not None and fail_at <= 2 * count)
                    self.assertEqual(resource["allocation_attempts"], 2 * count)
                    self.assertEqual(resource["allocations"], successful)
                    self.assertEqual(resource["frees"], successful)
                    self.assertEqual(resource["owners_created"], 2 * count)
                    self.assertEqual(resource["owners_dropped"], 2 * count)
                    self.assertEqual(resource["peak_bytes"], expected_peak(count, fail_at))
                    self.assertEqual(resource["live_bytes"], 0)
                    self.assertEqual(resource["live_owners"], 0)

    def test_fallible_owner_crossing_an_edge_still_requires_a_separate_invariant(self):
        source = scoped_loop()
        fn = source["functions"][0]
        body = next(block for block in fn["blocks"] if block["id"] == "body")
        body["ops"] = [
            c("request", "usize", 9),
            i("buffer.try_new", ["request"], [("pending", "buffer"), ("ok", "bool")]),
        ]
        body["term"] = jump("release", "pending", "r", "s")
        fn["blocks"].insert(3, b("release", [
            ("carried", "buffer"), ("carry_n", "u32"), ("carry_step", "u32"),
        ], [
            i("owner.drop", ["carried"]),
            i("int.sub.checked", ["carry_n", "carry_step"], [("next_n", "u32")]),
        ], jump("head", "next_n", "carry_step")))
        verified = verify_program(source)
        self.assertEqual(execute_program(verified, "count_down", [3], allocation_fail_at=1)
                         ["resources"]["live_bytes"], 0)
        with self.assertRaisesRegex(HIAStaticBudgetRejected, "E_HIA_BUDGET_UNBOUNDED"):
            analyze_constant_live_heap(verified)

    def test_fallible_allocation_does_not_turn_unknown_wrapping_extents_into_bounds(self):
        source = scoped_loop()
        body = next(block for block in source["functions"][0]["blocks"] if block["id"] == "body")
        body["ops"] = [
            i("int.cast", ["r"], [("wide", "usize")], mode="checked"),
            c("large", "usize", (1 << 64) - 1),
            i("int.add.wrap", ["wide", "large"], [("unknown", "usize")]),
            i("buffer.try_new", ["unknown"], [("pending", "buffer"), ("ok", "bool")]),
            i("owner.drop", ["pending"]),
            *body["ops"][4:],
        ]
        verified = verify_program(source)
        with self.assertRaisesRegex(HIAStaticBudgetRejected, "E_HIA_BUDGET_UNBOUNDED"):
            analyze_constant_live_heap(verified)


_OBSERVER = r"""
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
void *__real_malloc(size_t);
void *__real_calloc(size_t,size_t);
void __real_free(void *);
extern uint32_t count_down(uint32_t);
static void *addresses[64];
static size_t sizes[64], attempts, allocations, frees, live, peak, null_frees, fail_at;
static void *remember(void *p, size_t n) {
    if (!p) return NULL;
    size_t slot;
    for (slot=0; slot<64 && addresses[slot]; slot++) {}
    if (slot==64) exit(89);
    addresses[slot]=p; sizes[slot]=n; allocations++; live+=n;
    if (live>peak) peak=live;
    return p;
}
void *__wrap_malloc(size_t n) {
    attempts++;
    if (fail_at && attempts==fail_at) return NULL;
    return remember(__real_malloc(n), n);
}
void *__wrap_calloc(size_t n, size_t width) {
    attempts++;
    if (fail_at && attempts==fail_at) return NULL;
    if (width && n>SIZE_MAX/width) exit(88);
    return remember(__real_calloc(n,width), n*width);
}
void __wrap_free(void *p) {
    if (!p) { null_frees++; return; }
    size_t slot;
    for (slot=0; slot<64 && addresses[slot]!=p; slot++) {}
    if (slot==64) exit(90);
    live-=sizes[slot]; addresses[slot]=NULL; frees++; __real_free(p);
}
int main(int argc, char **argv) {
    if (argc!=3) return 87;
    unsigned count=(unsigned)strtoul(argv[1],NULL,10);
    fail_at=(size_t)strtoul(argv[2],NULL,10);
    uint32_t result=count_down(count);
    printf("%u %zu %zu %zu %zu %zu %zu\n", result, attempts, allocations,
           frees, live, peak, null_frees);
    if (result) return 86;
    return live || null_frees || allocations!=frees ? 91 : 0;
}
"""


@unittest.skipUnless(shutil.which(CLANG) and platform.system() == "Linux"
                     and platform.machine() in {"x86_64", "amd64"},
                     "pinned Clang20 Linux x86-64 native observer unavailable")
class FalliblePeakNativeTests(unittest.TestCase):
    def link_observer(self, root, obj):
        driver, binary = root / "observer.c", root / "observer"
        driver.write_text(_OBSERVER, encoding="ascii")
        linked = run_bounded([CLANG, "-O2", str(driver), str(obj),
                              "-Wl,--wrap=malloc", "-Wl,--wrap=calloc", "-Wl,--wrap=free",
                              "-o", str(binary)])
        self.assertEqual(linked.returncode, 0, linked.stderr)
        return binary

    def test_real_native_peak_failure_and_cleanup_match_independent_request_accounting(self):
        core = verify_program(two_fallible_owners())
        admitted = qualify_live_heap_budget(core, max_live_heap_bytes=13)
        emitted = emit_program_llvm(core)
        with tempfile.TemporaryDirectory(prefix="hia-fallible-peak-") as temporary:
            root = Path(temporary)
            obj = root / "core.o"
            receipt = compile_program_llvm(emitted, program=core, output=obj, clang=CLANG, kind="object")
            self.assertEqual(receipt["core_sha256"], admitted["program_sha256"])
            binary = self.link_observer(root, obj)
            for count, fail_at in ((0, 0), (1, 0), (1, 1), (1, 2),
                                   (3, 0), (3, 1), (3, 2), (7, 14)):
                with self.subTest(count=count, fail_at=fail_at):
                    observed = run_bounded([str(binary), str(count), str(fail_at)])
                    self.assertEqual(observed.returncode, 0, observed.stdout + observed.stderr)
                    successful = 2 * count - int(0 < fail_at <= 2 * count)
                    expected = [0, 2 * count, successful, successful, 0,
                                expected_peak(count, fail_at), 0]
                    self.assertEqual([int(x) for x in observed.stdout.split()], expected)

    def test_native_observer_rejects_missing_drops_despite_identical_return_value(self):
        emitted = emit_program_llvm(verify_program(two_fallible_owners()))
        wrong = "\n".join(line for line in emitted.text.splitlines()
                          if "call void @free(" not in line) + "\n"
        self.assertNotEqual(wrong, emitted.text)
        # This deliberate backend mutation is built outside the production
        # admission path: it qualifies the observer's sensitivity, not a Core.
        with tempfile.TemporaryDirectory(prefix="hia-fallible-leak-control-") as temporary:
            root = Path(temporary)
            llvm, obj = root / "wrong.ll", root / "wrong.o"
            llvm.write_text(wrong, encoding="ascii")
            compiled = run_bounded([CLANG, "-O3", "-c", "-x", "ir", str(llvm), "-o", str(obj)])
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            binary = self.link_observer(root, obj)
            observed = run_bounded([str(binary), "2", "0"])
            self.assertEqual(observed.returncode, 91, observed.stdout + observed.stderr)
            self.assertEqual([int(x) for x in observed.stdout.split()], [0, 4, 4, 0, 26, 26, 0])


if __name__ == "__main__":
    unittest.main()
