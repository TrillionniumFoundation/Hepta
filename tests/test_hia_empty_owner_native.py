"""P1/P2: empty/failed Owners must NOT emit observable free(NULL) calls.

The standalone verifier, Python VM and actual HIA->LLVM object are reused.
This test proves only a finite, observable allocator-call equivalence profile.
"""
from __future__ import annotations

import platform
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

from hepta.hia_program import SCHEMA_V6, verify_program
from hepta.hia_program_runtime import execute_program
from hepta.hia_program_llvm import emit_program_llvm, TARGET_AARCH64


def _param(name, typ):
    return {"name": name, "type": typ}


def _ins(op, args=(), outputs=(), **attrs):
    return {"op": op, "args": list(args),
            "out": [_param(*pair) for pair in outputs], "attrs": attrs}


def _program():
    # A zero-size owner and a rejected fallible owner each store (null, 0)
    # but are still linear capabilities requiring a normal-path Drop.
    size = _param("size", "usize")
    entry = [size]
    drop_owner = {
        "name": "drop_owner", "params": entry, "returns": ["u64"],
        "effects": ["alloc", "trap"], "entry": "entry",
        "blocks": [{"id": "entry", "params": entry,
                    "ops": [
                        _ins("buffer.new", ["size"], [("owner", "buffer")]),
                        _ins("owner.drop", ["owner"]),
                        _ins("const", outputs=[("value", "u64")], value=9),
                    ],
                    "term": {"op": "ret", "values": ["value"]}}],
    }
    try_drop = {
        "name": "try_drop", "params": entry, "returns": ["bool"],
        "effects": ["alloc"], "entry": "entry",
        "blocks": [{"id": "entry", "params": entry,
                    "ops": [
                        _ins("buffer.try_new", ["size"],
                             [("owned", "buffer"), ("succeeded", "bool")]),
                        _ins("owner.drop", ["owned"]),
                    ],
                    "term": {"op": "ret", "values": ["succeeded"]}}],
    }
    return {"schema": SCHEMA_V6, "module": "empty_owner_no_external_free",
            "functions": [drop_owner, try_drop]}


_DRIVER = r"""
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>

uint64_t drop_owner(uint64_t);
bool try_drop(uint64_t);

void *__real_malloc(size_t);
void *__real_calloc(size_t, size_t);
void __real_free(void *);

static unsigned long malloc_calls, calloc_calls, free_calls, null_frees;
static int refuse;
void *__wrap_malloc(size_t n) {
    malloc_calls++;
    if (refuse) return NULL;
    return __real_malloc(n);
}
void *__wrap_calloc(size_t n, size_t size) {
    calloc_calls++;
    if (refuse) return NULL;
    return __real_calloc(n, size);
}
void __wrap_free(void *p) {
    free_calls++;
    if (p == NULL) null_frees++;
    __real_free(p);
}
int main(void) {
    // Both zero-size and error-result Owners must undergo a logical Drop,
    // but neither owns native storage. No allocator calls of any kind.
    if (drop_owner(0) != 9 || !try_drop(0)) return 11;
    if (malloc_calls || calloc_calls || free_calls || null_frees) return 12;

    // An actual allocation must still have exactly one real deallocation.
    if (drop_owner(17) != 9) return 13;
    if (malloc_calls + calloc_calls != 1 || free_calls != 1 || null_frees) return 14;

    // Reject the next allocation and require fallible construction to return
    // an empty owner; its Drop is NOT an extra free(NULL) interaction.
    refuse = 1;
    if (try_drop(17)) return 15;
    refuse = 0;
    if (malloc_calls + calloc_calls != 2 || free_calls != 1 || null_frees) return 16;
    printf("%lu %lu %lu %lu\n", malloc_calls, calloc_calls, free_calls, null_frees);
    return 0;
}
"""


class HIAEmptyOwnerDropTests(unittest.TestCase):
    def test_vm_resource_ledger_exact_empty_vs_positive(self):
        verified = verify_program(_program())
        cases = [
            ("drop_owner", 0, None, 9, 0, 0),
            ("drop_owner", 17, None, 9, 1, 1),
            ("try_drop", 0, 1, True, 0, 0),
            ("try_drop", 17, 1, False, 0, 0),
        ]
        for name, n, failure, expected, allocs, frees in cases:
            with self.subTest(function=name, size=n, fail_at=failure):
                vm = execute_program(verified, name, [n],
                                     allocation_fail_at=failure)
                self.assertEqual(vm["result"], expected)
                self.assertEqual(vm["resources"]["allocations"], allocs)
                self.assertEqual(vm["resources"]["frees"], frees)
                self.assertEqual(vm["resources"]["live_owners"], 0)
                self.assertEqual(vm["resources"]["live_local_loans"], 0)

    def test_real_hia_emitter_guards_each_native_free_for_two_targets(self):
        verified = verify_program(_program())
        for target in ("x86_64-unknown-linux-gnu", TARGET_AARCH64):
            with self.subTest(target=target):
                ir = emit_program_llvm(verified, target=target)
                self.assertEqual(ir.core_sha256, verified.sha256)
                self.assertEqual(ir.text.count("call void @free(ptr "), 2)
                # The allocator runtime also contains its own nonnull test.
                # Match each Owner Drop's local guard, not module-wide counts.
                self.assertGreaterEqual(ir.text.count("icmp ne ptr "), 3)
                for match in re.finditer(r"(?m)^(drop_nonnull_(\d+)):$", ir.text):
                    label, suffix = match.groups()
                    after = "drop_after_" + suffix
                    start = match.start()
                    end = ir.text.find(after + ":\n", start)
                    self.assertGreater(end, start)
                    body = ir.text[start:end]
                    self.assertIn("call void @free(ptr ", body)
                    self.assertRegex(body, r"br label %" + re.escape(after))
                    self.assertIn("label %" + label + ", label %" + after, ir.text)
                self.assertEqual(len(re.findall(r"(?m)^drop_nonnull_\d+:$", ir.text)), 2)

    @unittest.skipUnless(shutil.which("clang") and platform.system() == "Linux"
                         and platform.machine() in {"x86_64", "amd64"},
                         "native Linux x86-64 Clang and ELF GNU ld needed")
    def test_real_emitted_llvm_has_zero_external_null_frees(self):
        verified = verify_program(_program())
        emitted = emit_program_llvm(verified)
        with tempfile.TemporaryDirectory(prefix="hia-empty-drop-") as temporary:
            root = Path(temporary)
            llvm, obj, driver, executable = (root / "program.ll", root / "program.o",
                                             root / "observer.c", root / "observer")
            llvm.write_text(emitted.text, encoding="ascii")
            driver.write_text(_DRIVER, encoding="utf-8")
            clang = shutil.which("clang")
            compiled = subprocess.run(
                [clang, "-O2", "-x", "ir", "-c", str(llvm), "-o", str(obj)],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            linked = subprocess.run(
                [clang, "-O2", str(driver), str(obj),
                 "-Wl,--wrap=malloc", "-Wl,--wrap=calloc", "-Wl,--wrap=free",
                 "-o", str(executable)],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(linked.returncode, 0, linked.stderr)
            executed = subprocess.run(
                [str(executable)], capture_output=True, text=True, timeout=15)
            self.assertEqual(executed.returncode, 0,
                             executed.stdout + executed.stderr)
            counts = [int(item) for item in executed.stdout.split()]
            self.assertEqual(len(counts), 4)
            self.assertEqual(sum(counts[:2]), 2)  # 1 accepted, 1 rejected
            self.assertEqual(counts[2:], [1, 0])  # no free(NULL)


if __name__ == "__main__":
    unittest.main()
