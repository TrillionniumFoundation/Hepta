"""Allocator witness for actual direct/LLVM word-memory object code.

The generated Core, including its word guards and endian operations, is the
subject under test. The tiny C shim only supplies fresh zeroed mmap storage and
observes the existing calloc/free boundary; it implements no Core operation.
"""
from __future__ import annotations

import ctypes
import mmap
import signal

from hepta.hia_program import verify_program
from hepta.hia_program_llvm import build_program_native
from hepta.hia_program_native import build_program_machine
from tools.hia_word_memory_cases import (ORDERS, SCHEMA, block, instruction,
                                         literal, owned_program, param, ret)


SHIM = r"""
typedef __SIZE_TYPE__ size_t;
typedef unsigned long long u64;
extern void abort(void);
static unsigned char *storage;
static u64 capacity, allocations, releases;
void hia_test_bind(void *p, u64 n) {
    storage = p; capacity = n; allocations = 0; releases = 0;
}
void *__wrap_calloc(size_t count, size_t size) {
    if (count != 1 || size != capacity || allocations != 0) abort();
    allocations += 1;
    return storage;
}
void __wrap_free(void *p) {
    if (p != 0) {
        if (p != storage || allocations != 1 || releases != 0) abort();
        releases += 1;
    }
}
u64 hia_test_allocations(void) { return allocations; }
u64 hia_test_releases(void) { return releases; }
"""


def initialized_program():
    """A byte initializer independent of the word value exposes partial writes."""
    document = owned_program()
    for function in document["functions"]:
        fill = next(item for item in function["blocks"] if item["id"] == "fill")
        fill["ops"].insert(0, literal("seed", "u64", 0xA5))
        pattern = next(item for item in fill["ops"] if item["out"]
                       and item["out"][0]["name"] == "pattern")
        pattern["args"][1] = "seed"
    return document


def sparse_program():
    """Initialize only sixteen bytes with old byte operations before each word.

    A sparse fresh allocation can therefore exercise offsets above 4 GiB
    without touching or allocating all intervening physical pages.
    """
    functions = []
    for mode in ("load", "store"):
        for order in ORDERS:
            args = [param("n", "usize"), param("offset", "usize"),
                    param("value", "u64"), param("probe", "usize")]
            ops = [instruction("buffer.new", ["n"], [("owner", "buffer")]),
                   instruction("borrow.mut", ["owner"], [("view", "mutbuf")])]
            for index in range(8):
                ops.extend([
                    literal(f"low{index}", "usize", index),
                    literal(f"marker{index}", "u8", 0xB0 + index),
                    instruction("buffer.store", ["view", f"low{index}", f"marker{index}"]),
                    instruction("int.add.checked", ["offset", f"low{index}"],
                                [(f"high{index}", "usize")]),
                    literal(f"data{index}", "u8", 0xC0 + index),
                    instruction("buffer.store", ["view", f"high{index}", f"data{index}"]),
                ])
            if mode == "load":
                ops.append(instruction(f"buffer.load.u64.{order}", ["view", "offset"],
                                       [("answer", "u64")]))
            else:
                ops.extend([
                    instruction(f"buffer.store.u64.{order}", ["view", "offset", "value"]),
                    instruction("buffer.load", ["view", "probe"], [("observed", "u8")]),
                    instruction("int.cast", ["observed"], [("answer", "u64")], mode="wrap"),
                ])
            ops.extend([instruction("loan.end", ["view"]), instruction("owner.drop", ["owner"])])
            functions.append({"name": f"{mode}_{order}", "params": args, "returns": ["u64"],
                              "effects": ["alloc", "read", "write", "trap"], "entry": "entry",
                              "blocks": [block("entry", args, ops, ret("answer"))]})
    return {"schema": SCHEMA, "module": "word_memory_sparse",
            "exports": [function["name"] for function in functions], "functions": functions}


def library(output, name, document, backend, clang, command, sha):
    checked = verify_program(document)
    obj, so = output / (name + ".o"), output / (name + ".so")
    if backend == "direct":
        receipt = build_program_machine(checked, obj, kind="object")
    else:
        receipt = build_program_native(checked, obj, clang=clang, kind="object")
    source = output / "allocator-witness.c"
    source.write_text(SHIM)
    link = command([clang, "-shared", "-fPIC", str(source), str(obj),
                    "-Wl,--wrap=calloc", "-Wl,--wrap=free", "-Wl,-z,defs", "-o", str(so)])
    owner = ctypes.CDLL(str(so))
    owner.hia_test_bind.argtypes = [ctypes.c_void_p, ctypes.c_uint64]
    owner.hia_test_bind.restype = None
    for symbol in ("hia_test_allocations", "hia_test_releases"):
        fn = getattr(owner, symbol)
        fn.argtypes = []
        fn.restype = ctypes.c_uint64
    for mode in ("load", "store"):
        for order in ORDERS:
            fn = getattr(owner, mode + "_" + order)
            fn.argtypes = [ctypes.c_uint64] * 4
            fn.restype = ctypes.c_uint64
    return owner, {"object": receipt, "link": link, "library_sha256": sha(so),
                   "shim_sha256": sha(source), "core_sha256": checked.sha256}


def qualify_allocator(output, clang, command, sha, shared_buffer, pointer, child_trap):
    """Run no-write traps and full-u64 valid ranges in both production backends."""
    report = {"scope": "test-only calloc/free witness; actual generated Core guards and operations",
              "fresh_zeroed_storage": True, "backends": []}
    for backend in ("direct", "llvm"):
        owner, receipt = library(output, "allocator-" + backend, initialized_program(),
                                 backend, clang, command, sha)
        valid_count = failures = 0
        for mode in ("load", "store"):
            for order, endian in ORDERS.items():
                fn = getattr(owner, mode + "_" + order)
                # A real successful allocation/free confirms --wrap binding.
                for n, offset in ((8, 0), (9, 1), (31, 23)):
                    with shared_buffer(n + 32) as target:
                        target[:] = b"\xD7" * 16 + bytes(n) + b"\xD7" * 16
                        owner.hia_test_bind(pointer(target, 16), n)
                        value = 0x0123456789ABCDEF
                        observed = fn(n, offset, value, offset)
                        wanted = bytearray((i * 17 + 0xA5) & 255 for i in range(n))
                        if mode == "load":
                            assert observed == int.from_bytes(wanted[offset:offset + 8], endian)
                        else:
                            wanted[offset:offset + 8] = value.to_bytes(8, endian)
                            assert observed == wanted[offset]
                        assert target[:] == b"\xD7" * 16 + wanted + b"\xD7" * 16
                        assert owner.hia_test_allocations() == owner.hia_test_releases() == 1
                        valid_count += 1
                cases = [(n, 0) for n in range(8)] + [
                    (8, 1), (9, 2), (31, 24), (31, 31), (31, 32),
                    (31, 1 << 32), (31, (1 << 32) + 1),
                    (31, 1 << 63), (31, (1 << 64) - 1)]
                for n, offset in cases:
                    with shared_buffer(n + 32) as target:
                        # Bind only actually zeroed fresh storage. After the old
                        # byte initializer, the independently known pattern must
                        # survive the failed word operation without any change.
                        target[:] = b"\xD7" * 16 + bytes(n) + b"\xD7" * 16
                        owner.hia_test_bind(pointer(target, 16), n)
                        child_trap(lambda: fn(n, offset, 0x0123456789ABCDEF, 0), signal.SIGABRT)
                        wanted = bytes((i * 17 + 0xA5) & 255 for i in range(n))
                        assert target[:] == b"\xD7" * 16 + wanted + b"\xD7" * 16
                        failures += 1
        high_owner, high_receipt = library(output, "high-offset-" + backend, sparse_program(),
                                           backend, clang, command, sha)
        high, value = (1 << 32) + 1, 0x0123456789ABCDEF
        high_count = 0
        for mode in ("load", "store"):
            for order, endian in ORDERS.items():
                n = high + 8
                with mmap.mmap(-1, n + 32, flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS |
                               getattr(mmap, "MAP_NORESERVE", 0),
                               prot=mmap.PROT_READ | mmap.PROT_WRITE) as target:
                    # All bytes offered to calloc are initially zero. Canaries
                    # live outside that allocation and low markers are written
                    # by old Core byte operations, not by the allocator shim.
                    target[:16] = target[n + 16:] = b"\xD7" * 16
                    high_owner.hia_test_bind(pointer(target, 16), n)
                    observed = getattr(high_owner, mode + "_" + order)(n, high, value, 0)
                    expected_word = bytes(range(0xC0, 0xC8))
                    if mode == "load":
                        assert observed == int.from_bytes(expected_word, endian)
                    else:
                        expected_word = value.to_bytes(8, endian)
                        assert observed == 0xB0
                    assert target[16:24] == bytes(range(0xB0, 0xB8))
                    assert target[16 + high:24 + high] == expected_word
                    assert target[15 + high] == 0
                    assert target[:16] == target[n + 16:] == b"\xD7" * 16
                    assert high_owner.hia_test_allocations() == high_owner.hia_test_releases() == 1
                    high_count += 1
        report["backends"].append({"backend": backend, "valid_calls": valid_count,
                                   "trap_cases": failures, "failed_word_zero_writes": True,
                                   "high_offset": high, "high_offset_calls": high_count,
                                   "build": receipt, "high_build": high_receipt})
    return report
