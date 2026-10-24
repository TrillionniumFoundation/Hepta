"""Reproduce bounded C migration and native differential/failure evidence.

Includes one frozen pre-existing repository module and separately labelled
authored conformance modules. Finite execution is not an equivalence proof.
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import random
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from hepta.backend import compile_rust
from hepta.c_migrate import migrate_c_project

FIXTURES = ROOT / "tests/fixtures/c_migration"
REFUSE_SIZE = 65519

RUST_FAULT_ALLOCATOR = r'''
struct MigrationFaultAllocator;
static MIGRATION_LIVE: core::sync::atomic::AtomicIsize = core::sync::atomic::AtomicIsize::new(0);
unsafe impl std::alloc::GlobalAlloc for MigrationFaultAllocator {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        if layout.size() == 65519 { return core::ptr::null_mut(); }
        let result = std::alloc::System.alloc(layout);
        if !result.is_null() { MIGRATION_LIVE.fetch_add(1, core::sync::atomic::Ordering::SeqCst); }
        result
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: std::alloc::Layout) {
        std::alloc::System.dealloc(ptr, layout);
        MIGRATION_LIVE.fetch_sub(1, core::sync::atomic::Ordering::SeqCst);
    }
}
#[global_allocator] static MIGRATION_ALLOCATOR: MigrationFaultAllocator = MigrationFaultAllocator;
#[no_mangle] pub extern "C" fn migration_live_allocations() -> isize {
    MIGRATION_LIVE.load(core::sync::atomic::Ordering::SeqCst)
}
'''

C_FAULT_ALLOCATOR = r'''
#include <stddef.h>
#include <stdatomic.h>
void *__real_malloc(size_t);
void *__real_calloc(size_t, size_t);
void __real_free(void *);
static _Atomic long live_allocations;
void *__wrap_malloc(size_t n) {
    if (n == 65519) return NULL;
    void *result = __real_malloc(n);
    if (result) atomic_fetch_add(&live_allocations, 1);
    return result;
}
void *__wrap_calloc(size_t n, size_t size) {
    if (n == 65519 && size == 1) return NULL;
    void *result = __real_calloc(n, size);
    if (result) atomic_fetch_add(&live_allocations, 1);
    return result;
}
void __wrap_free(void *value) {
    if (value) atomic_fetch_sub(&live_allocations, 1);
    __real_free(value);
}
long migration_live_allocations(void) { return atomic_load(&live_allocations); }
'''


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def command(argv: list[str], *, timeout=60) -> dict:
    started = time.perf_counter()
    process = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    result = {"argv": argv, "exit_code": process.returncode, "seconds": time.perf_counter() - started,
              "stdout": process.stdout, "stderr": process.stderr}
    if process.returncode:
        raise RuntimeError(json.dumps(result))
    return result


class Point(ctypes.Structure):
    _fields_ = [("x", ctypes.c_int32), ("y", ctypes.c_double)]


def configure(path: Path, *, faults=False):
    library = ctypes.CDLL(str(path))
    declarations = {
        "native_add": ([ctypes.c_int32, ctypes.c_int32], ctypes.c_int32),
        "native_transform": ([Point, ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t], Point),
        "sum_bytes": ([ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t], ctypes.c_uint32),
        "mutate_bytes": ([ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t, ctypes.c_uint8], ctypes.c_uint32),
        "owned_malloc_sum": ([ctypes.c_size_t], ctypes.c_int64),
        "owned_calloc_sum": ([ctypes.c_size_t], ctypes.c_int64),
    }
    if faults:
        declarations["migration_live_allocations"] = ([], ctypes.c_long)
    for name, (arguments, returns) in declarations.items():
        function = getattr(library, name)
        function.argtypes, function.restype = arguments, returns
    return library


def qualify(*, clang: str, rustc: str | None, output: Path, seed: int = 90261024) -> dict:
    before = time.perf_counter()
    report = {"schema": "hepta.c-migration-qualification.v1", "ok": False,
              "scope": "finite_native_differential_execution_on_defined_annotated_inputs",
              "source_equivalence_proved": False, "performance_parity_claimed": False,
              "seed": seed, "runtime_artifacts_retained": False,
              "fixture_kinds": {"native": "frozen_pre_existing_repository_example",
                                "buffer_ops": "authored_conformance_fixture", "owned_bytes": "authored_conformance_fixture"}}
    compiler = shutil.which("gcc")
    if compiler is None:
        raise RuntimeError("GCC is required as the independent original C compiler")
    report["original_compiler"] = {"path": compiler, "sha256": sha(Path(compiler)),
                                   "version": command([compiler, "--version"])["stdout"].splitlines()[0]}
    input_files = [FIXTURES / "native/native.c", FIXTURES / "native/native.h", FIXTURES / "buffer_ops.c", FIXTURES / "owned_bytes.c"]
    report["inputs"] = [{"path": str(path.relative_to(ROOT)), "sha256": sha(path), "bytes": path.stat().st_size} for path in input_files]
    frozen_blobs = {"native.c": "b0218e98bda265e51f72f2aa5f555aa0fba362f5", "native.h": "16122ca85d740b2e9db78b0bfc134decc275f15b"}
    for path in input_files[:2]:
        data = path.read_bytes()
        blob = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        if blob != frozen_blobs[path.name]:
            raise RuntimeError("Frozen in-repository module diverged from its Git blob: " + str(path))
    report["frozen_origin"] = {"repository": "TrillionniumFoundation/Hepta", "commit": "d29a246cabaec5ddd8c5f6043b6b234b56ae8b67", "git_blobs": frozen_blobs}
    git = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True)
    report["implementation_commit"] = git.stdout.strip() if git.returncode == 0 else None
    report["implementation_files"] = {str(path.relative_to(ROOT)): sha(path) for path in [
        ROOT / "hepta/c_project.py", ROOT / "hepta/c_translation.py", ROOT / "hepta/c_allocation.py", ROOT / "hepta/c_aliases.py",
        ROOT / "hepta/c_migration_project.py", ROOT / "hepta/c_migrate.py", Path(__file__).resolve()]}
    with tempfile.TemporaryDirectory(prefix="hepta-c-qualification-") as temporary:
        work = Path(temporary)
        for path in input_files:
            shutil.copyfile(path, work / path.name)
        database = work / "compile_commands.json"
        database.write_text(json.dumps([{"directory": str(work), "file": name,
                                         "arguments": ["clang", "-std=c11", "-O2", "-c", name, "-o", name + ".o"]}
                                        for name in ("native.c", "buffer_ops.c", "owned_bytes.c")]))
        contract = {"schema": "hepta.c-contracts.v1", "functions": {
            "native_transform": {"slices": {"data": {"length": "count", "access": "read"}}},
            "sum_bytes": {"slices": {"data": {"length": "count", "access": "read"}}},
            "mutate_bytes": {"slices": {"data": {"length": "count", "access": "mut"}}}}}
        bundle = work / "translated"
        migration = migrate_c_project(database, bundle, contracts=contract, clang=clang, rustc=rustc, verify_native=True)
        report["migration"] = migration
        if not migration["ok"]:
            raise RuntimeError("Migration failed: " + json.dumps(migration["diagnostics"]))
        original = work / "original.so"
        base = [compiler, "-std=c11", "-O2", "-fPIC", "-shared", *[str(work / name) for name in ("native.c", "buffer_ops.c", "owned_bytes.c")]]
        report["original_build"] = command([*base, "-o", str(original)])
        c, h = configure(original), configure(bundle / "libtranslated.so")
        rng, comparisons = random.Random(seed), {"native_add": 0, "native_transform": 0, "sum_bytes": 0, "mutate_bytes": 0, "owned_malloc_sum": 0, "owned_calloc_sum": 0}
        for _ in range(256):
            x, y = rng.randrange(-1000000, 1000000), rng.randrange(-1000000, 1000000)
            if c.native_add(x, y) != h.native_add(x, y):
                raise AssertionError("native_add mismatch")
            comparisons["native_add"] += 1
            size = rng.randrange(1025)
            data = bytes(rng.randrange(256) for _ in range(size))
            a, b = (ctypes.c_uint8 * size)(*data), (ctypes.c_uint8 * size)(*data)
            point = Point(rng.randrange(-1000000, 1000000), rng.random() * 1000)
            p, q = c.native_transform(point, a, size), h.native_transform(point, b, size)
            if (p.x, p.y) != (q.x, q.y) or bytes(a) != bytes(b):
                raise AssertionError("native_transform mismatch")
            comparisons["native_transform"] += 1
            if c.sum_bytes(a, size) != h.sum_bytes(b, size):
                raise AssertionError("sum_bytes mismatch")
            comparisons["sum_bytes"] += 1
            modifier = rng.randrange(256)
            if c.mutate_bytes(a, size, modifier) != h.mutate_bytes(b, size, modifier) or bytes(a) != bytes(b):
                raise AssertionError("mutate_bytes result or written-buffer mismatch")
            comparisons["mutate_bytes"] += 1
        for size in [0, 1, 2, 31, 32, 127, 251, 256, 1024, 4096, ctypes.c_size_t(-1).value]:
            for name in ("owned_malloc_sum", "owned_calloc_sum"):
                if getattr(c, name)(size) != getattr(h, name)(size):
                    raise AssertionError(name + " mismatch")
                comparisons[name] += 1
        # Allocation outcome is an external choice. Give both implementations
        # the same explicit refusal policy and check both failure and cleanup.
        shim = work / "allocator.c"
        shim.write_text(C_FAULT_ALLOCATOR)
        fault_c = work / "fault-original.so"
        report["fault_original_build"] = command([*base, str(shim), "-Wl,--wrap=malloc", "-Wl,--wrap=calloc", "-Wl,--wrap=free", "-o", str(fault_c)])
        fault_h = work / "fault-translated.so"
        rust = (bundle / "generated.rs").read_text() + "\n" + RUST_FAULT_ALLOCATOR
        report["fault_translated_build"] = compile_rust(rust, output=fault_h, rustc=rustc, crate_type="cdylib")
        if not report["fault_translated_build"]["ok"]:
            raise RuntimeError(json.dumps(report["fault_translated_build"]["diagnostics"]))
        c_fault, h_fault = configure(fault_c, faults=True), configure(fault_h, faults=True)
        fault_results = []
        for name in ("owned_malloc_sum", "owned_calloc_sum"):
            for size in [REFUSE_SIZE, 32, REFUSE_SIZE, 0, 251]:
                a, b = getattr(c_fault, name)(size), getattr(h_fault, name)(size)
                c_live, h_live = c_fault.migration_live_allocations(), h_fault.migration_live_allocations()
                if a != b or (size == REFUSE_SIZE and a != -1) or c_live != 0 or h_live != 0:
                    raise AssertionError((name, size, a, b, c_live, h_live))
                fault_results.append({"function": name, "size": size, "result": a,
                                      "c_live_allocations": c_live, "hepta_live_allocations": h_live})
        # A deliberately corrupted finite result must be detected by the same
        # comparison predicate; this is an oracle negative control.
        negative = c.native_add(13, 29) != h.native_add(13, 29) + 1
        if not negative:
            raise AssertionError("Differential oracle failed its wrong-result control")
        report["execution"] = {"differential_cases": comparisons, "total_differential_cases": sum(comparisons.values()),
                               "fault_injection": fault_results, "wrong_result_control_rejected": negative,
                               "allocator_fault_shim_sha256": hashlib.sha256(C_FAULT_ALLOCATOR.encode()).hexdigest(),
                               "rust_allocator_fault_shim_sha256": hashlib.sha256(RUST_FAULT_ALLOCATOR.encode()).hexdigest(),
                               "checks": ["return values", "struct values", "mutated buffer contents", "allocation refusal returns", "allocation/free balance"]}
        generated_directory = output.parent / "c-migration-generated"
        generated_directory.mkdir(parents=True, exist_ok=True)
        for name in ("source.hepta", "bridge.rs"):
            shutil.copyfile(bundle / name, generated_directory / name)
        report["reviewable_generated_source"] = {name: str((generated_directory / name).relative_to(ROOT)) if (generated_directory / name).is_relative_to(ROOT) else str(generated_directory / name)
                                                 for name in ("source.hepta", "bridge.rs")}
    report.update(ok=True, status="finite_differential_and_fault_injection_passed", elapsed_seconds=time.perf_counter() - before)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--clang", default="clang")
    parser.add_argument("--rustc")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=90261024)
    args = parser.parse_args()
    try:
        result = qualify(clang=args.clang, rustc=args.rustc, output=args.output.absolute(), seed=args.seed)
    except Exception as exc:
        print(json.dumps({"ok": False, "error": str(exc)}))
        return 1
    print(json.dumps({"ok": result["ok"], "output": str(args.output), "execution": result["execution"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
