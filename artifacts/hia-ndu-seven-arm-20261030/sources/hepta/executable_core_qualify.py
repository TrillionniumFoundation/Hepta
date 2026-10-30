"""Repeatable native qualification of a fixed executable-core corpus.

Run ``python -m hepta.executable_core_qualify --report result.json`` with
RUSTC, CLANG and CC pointing to the qualification toolchain. All comparisons
execute real compiled artifacts in child processes. No mocked or skipped
native check can produce an ``ok`` receipt.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile

from .backend import compile_rust
from .c_backend import compile_c
from .executable_core import (PROFILE, build_executable_core_source,
                              execute_executable_core, lower_executable_core)
from .pipeline import analyze, compiler_hash


QUALIFICATION_SOURCE = r'''
fn read_byte(bytes: read [u8], index: usize) -> u8 effects {panic} {
    return bytes[index];
}
fn fill(bytes: mut Buffer<u8>, seed: u8) -> Unit effects {panic,write} {
    let mut index: usize = 0;
    while index < len(bytes) {
        bytes[index] = wrapping_add(seed, index as u8);
        index = index + 1;
    }
}
fn checksum(bytes: read Buffer<u8>) -> u64 effects {panic} {
    let mut total: u64 = 0;
    for index in 0..len(bytes) {
        total = total + read_byte(read bytes, index) as u64;
    }
    return total;
}
fn transfer(bytes: take Buffer<u8>) -> Buffer<u8> effects {} {
    return move bytes;
}
export "C" fn lifecycle(size: usize, seed: u8, early: u32) -> u64
effects {alloc,block,panic,write} {
    match try_buffer(size) {
        Result::Err(code) => { return 1000 + code as u64; },
        Result::Ok(initial) => {
            let mut bytes = move initial;
            fill(mut bytes, seed);
            if early != 0 { drop(move bytes); return 777; }
            let total = checksum(read bytes);
            let moved = transfer(move bytes);
            drop(move moved);
            return total;
        },
    }
}
export "C" fn second_allocation(size:usize) -> u64 effects {alloc,block,panic,write} {
    let mut first = buffer(3);
    first[0] = 41;
    match try_buffer(size) {
        Result::Err(code) => { drop(move first); return 100 + code as u64; },
        Result::Ok(second) => {
            let result = first[0] as u64 + len(second) as u64;
            drop(move second); drop(move first); return result;
        },
    }
}
export "C" fn signed_math(a:i32,b:i32) -> i32 effects {panic} {
    return wrapping_add(a / b, a % b);
}
export "C" fn short_circuit(value:u32) -> u32 effects {panic} {
    if value == 0 || 100 / value > 2 { return 1; }
    return 0;
}
export "C" fn cast_byte(value:i64) -> i8 effects {} { return value as i8; }
export "C" fn shift(value:i32,count:i32) -> i32 effects {panic} { return value << count; }
export "C" fn trap_index() -> u8 effects {alloc,block,panic} {
    let bytes=buffer(1);let result=bytes[1];drop(move bytes);return result;
}
export "C" fn trap_overflow(value:u8) -> u8 effects {panic} { return value + 1; }
'''


ALLOCATOR_HARNESS = r'''
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
void *__real_calloc(size_t, size_t);
void *__real_malloc(size_t);
void __real_free(void *);
static volatile size_t allocations=0, frees=0, live=0, refusals=0;
static volatile int fail_second=0;
void *__wrap_calloc(size_t count, size_t size) {
    if (fail_second && ((count==12281 && size==1) || (count==1 && size==12281))) {
        refusals++; return NULL;
    }
    void *value=__real_calloc(count,size);
    if(value) { allocations++; live++; }
    return value;
}
void *__wrap_malloc(size_t size) {
    if (fail_second && size==12281) { refusals++; return NULL; }
    void *value=__real_malloc(size);
    if(value) { allocations++; live++; }
    return value;
}
void __wrap_free(void *value) {
    if(value) { frees++; live--; }
    __real_free(value);
}
extern uint64_t second_allocation(size_t);
int main(void) {
    if(second_allocation(5)!=46) return 11;
    if(second_allocation(0)!=41) return 12;
    fail_second=1;
    if(second_allocation(12281)!=101) return 13;
    if(second_allocation((size_t)-1)!=101) return 14;
    printf("%zu %zu %zu %zu\n",allocations,frees,live,refusals);
    return allocations!=5 || frees!=5 || live!=0 || refusals!=1;
}
'''


_CHILD = r'''
import ctypes, json, resource, sys
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
payload = json.load(sys.stdin)
types = {"u8":ctypes.c_uint8, "i8":ctypes.c_int8,
         "u16":ctypes.c_uint16, "i16":ctypes.c_int16,
         "u32":ctypes.c_uint32, "i32":ctypes.c_int32,
         "u64":ctypes.c_uint64, "i64":ctypes.c_int64,
         "usize":ctypes.c_size_t, "isize":ctypes.c_ssize_t,
         "bool":ctypes.c_bool, "Unit":None}
out = {}
for backend, path in payload["libraries"].items():
    library = ctypes.CDLL(path)
    values = []
    for case in payload["cases"]:
        function = getattr(library, case["function"])
        signature = payload["signatures"][case["function"]]
        function.argtypes = [types[t] for t in signature["parameters"]]
        function.restype = types[signature["returns"]]
        values.append(function(*case["arguments"]))
    out[backend] = values
print(json.dumps(out, sort_keys=True))
'''


def _sha(value):
    return hashlib.sha256(value).hexdigest()


def _wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def qualification_cases():
    cases = [("lifecycle", [size, seed, early]) for size in (0, 1, 7, 31, 65)
             for seed in (0, 13, 249) for early in (0, 1)]
    cases += [("second_allocation", [size]) for size in (0, 7, 19, (1 << 64) - 1)]
    cases += [("signed_math", [a, b]) for a, b in [(-19, 4), (19, -4), (-19, -4), (0, 1), (123456, 17)]]
    cases += [("short_circuit", [x]) for x in (0, 1, 33, 34, 100, 101)]
    cases += [("cast_byte", [x]) for x in (-1000, -129, -128, 127, 128, 255, 256)]
    cases += [("shift", [x, y]) for x, y in [(1, 0), (1, 30), (1 << 30, 1), (-1, 3)]]
    return [{"function": name, "arguments": args} for name, args in cases]


def _run(payload):
    return subprocess.run([sys.executable, "-I", "-c", _CHILD], input=json.dumps(payload),
                          text=True, capture_output=True, timeout=30)


def qualify_executable_core(*, rustc, clang, cc):
    """Execute the fixed corpus; return a hashed finite-evidence receipt.

    This is a regression qualification, not a proof or a performance result.
    Tool failures, crashes, mismatches and stale compiler identities reject.
    """
    initial_compiler = compiler_hash()
    source = QUALIFICATION_SOURCE
    cases = qualification_cases()
    with tempfile.TemporaryDirectory(prefix="hepta-core-qualification-") as td:
        directory = Path(td)
        source_path = directory / "input.hepta"
        source_path.write_text(source)
        llvm = directory / "core.so"
        native = build_executable_core_source(source_path, llvm, rustc=rustc, clang=clang)
        original = analyze(source, str(source_path), native=False, crate_type="cdylib")
        if original.report.get("ok") is not True:
            raise ValueError("Original source reference analysis failed")
        core = lower_executable_core(original.program, original.checked)
        reference = [execute_executable_core(core, case["function"], case["arguments"], source=source)
                     for case in cases]
        if any(item["status"] != "returned" for item in reference):
            raise ValueError("Core reference corpus did not return normally")
        signatures = {fn["name"]: {"parameters": [p["type"]["name"] for p in fn["params"]],
                                     "returns": fn["returns"]["name"]} for fn in core["functions"]}
        rust, cfile = directory / "rust.so", directory / "c.so"
        rust_build = compile_rust(original.rust, rustc=rustc, crate_type="cdylib", output=rust)
        if rust_build.get("ok") is not True:
            raise ValueError("Native Rust reference build failed: " + str(rust_build))
        csource = analyze(source, str(source_path), native=False, backend="c", crate_type="cdylib")
        if csource.report.get("ok") is not True:
            raise ValueError("C reference generation failed")
        c_build = compile_c(csource.c, cc=cc, crate_type="cdylib", output=cfile)
        if c_build.get("ok") is not True:
            raise ValueError("Native C reference build failed: " + str(c_build))
        payload = {"libraries": {"decoded_core_llvm": str(llvm), "original_rust": str(rust),
                                  "original_c": str(cfile)}, "cases": cases, "signatures": signatures}
        artifact_hashes = {name: _sha(Path(path).read_bytes()) for name, path in payload["libraries"].items()}
        if artifact_hashes["decoded_core_llvm"] != native["artifact_sha256"]:
            raise ValueError("Decoded-core artifact changed before native execution")
        run = _run(payload)
        if run.returncode:
            raise ValueError("Native corpus execution failed: " + repr((run.returncode, run.stderr[:4000])))
        observed = json.loads(run.stdout)
        expected = [item["result"] for item in reference]
        if set(observed) != set(payload["libraries"]) or any(values != expected for values in observed.values()):
            raise ValueError("Native result differs from independently executed core")
        native_execution = {"runner": sys.executable, "script_sha256": _sha(_CHILD.encode()),
                            "input_sha256": _sha(_wire(payload)), "returncode": run.returncode,
                            "stdout": run.stdout, "stderr": run.stderr,
                            "stdout_sha256": _sha(run.stdout.encode()), "stderr_sha256": _sha(run.stderr.encode())}
        traps = []
        for case in [{"function": "trap_index", "arguments": []},
                     {"function": "trap_overflow", "arguments": [255]}]:
            reference_trap = execute_executable_core(core, case["function"], case["arguments"], source=source)
            run = _run({**payload, "libraries": {"decoded_core_llvm": str(llvm)}, "cases": [case]})
            if reference_trap["status"] != "trapped" or run.returncode != -signal.SIGABRT:
                raise ValueError("Expected checked guard abort was not observed")
            traps.append({**case, "reference_status": reference_trap["status"],
                          "observed_returncode": run.returncode, "expected_signal": "SIGABRT",
                          "stdout_sha256": _sha(run.stdout.encode()), "stderr_sha256": _sha(run.stderr.encode())})
        obj = directory / "core.o"
        object_receipt = build_executable_core_source(source_path, obj, rustc=rustc, clang=clang, kind="object")
        harness, executable = directory / "allocator.c", directory / "allocator"
        harness.write_text(ALLOCATOR_HARNESS)
        command = [str(cc), "-O2", str(harness), str(obj), "-Wl,--wrap=malloc", "-Wl,--wrap=calloc",
                   "-Wl,--wrap=free", "-o", str(executable)]
        linked = subprocess.run(command, text=True, capture_output=True, timeout=30)
        if linked.returncode:
            raise ValueError("Allocator observation link failed: " + linked.stderr[:4000])
        allocator = subprocess.run([str(executable)], text=True, capture_output=True, timeout=10)
        if allocator.returncode or allocator.stdout.strip() != "5 5 0 1":
            raise ValueError("Allocator observation failed: " + repr((allocator.returncode, allocator.stdout, allocator.stderr)))
        resource_cases = [{"size": 5, "allocation_fail_at": None},
                          {"size": 0, "allocation_fail_at": None},
                          {"size": 12281, "allocation_fail_at": 2},
                          {"size": (1 << 64) - 1, "allocation_fail_at": None}]
        resource_reference = [execute_executable_core(core, "second_allocation", [case["size"]],
                              source=source, allocation_fail_at=case["allocation_fail_at"]) for case in resource_cases]
        if ([r["result"] for r in resource_reference] != [46, 41, 101, 101]
                or sum(r["resources"]["allocations"] for r in resource_reference) != 5
                or sum(r["resources"]["frees"] for r in resource_reference) != 5
                or any(r["resources"]["live_owners"] for r in resource_reference)):
            raise ValueError("Reference resource protocol differs from native observations")
        if compiler_hash() != initial_compiler:
            raise ValueError("Compiler changed during executable-core qualification")
        if any(_sha(Path(path).read_bytes()) != artifact_hashes[name]
               for name, path in payload["libraries"].items()):
            raise ValueError("A qualified native library changed during execution")
        report = {"schema": "hepta.executable-core-qualification.v1", "ok": True,
            "profile": PROFILE, "status": "finite_native_corpus_passed",
            "source_sha256": _sha(source.encode()), "inputs_sha256": _sha(_wire(cases)),
            "compiler_sha256": initial_compiler, "core_sha256": core["sha256"],
            "host_target": native["target"], "input_cases": len(cases),
            "native_result_executions": len(cases) * len(observed), "mocked_native_executions": 0,
            "skipped_native_executions": 0,
            "results": [{**case, "reference": ref["result"], "resources": ref["resources"],
                         "native": {name: values[i] for name, values in observed.items()}}
                        for i, (case, ref) in enumerate(zip(cases, reference))],
            "native_receipt": native, "rust_build": rust_build, "c_build": c_build,
            "native_execution": native_execution,
            "generated_rust_sha256": _sha(original.rust.encode()),
            "generated_c_sha256": _sha(csource.c.encode()),
            "artifact_sha256": artifact_hashes,
            "guard_observations": traps,
            "allocator_observation": {"native_object": object_receipt,
                "harness_sha256": _sha(ALLOCATOR_HARNESS.encode()), "executable_sha256": _sha(executable.read_bytes()),
                "inputs_sha256": _sha(_wire(resource_cases)), "cases": resource_cases,
                "return_values": [r["result"] for r in resource_reference],
                "allocations": 5, "frees": 5, "live_allocations": 0,
                "observed_allocator_refusals": 1, "capacity_refusal_cases": 1,
                "process": {"returncode": allocator.returncode, "stdout": allocator.stdout,
                            "stderr": allocator.stderr, "stdout_sha256": _sha(allocator.stdout.encode()),
                            "stderr_sha256": _sha(allocator.stderr.encode())},
                "reference_failure_injection_used": True,
                "native_failure_source": "real linked malloc/calloc wrapper returned NULL for size 12281"},
            "claims": {"actual_core_operations_executed": True, "native_artifacts_executed": True,
                "native_codegen_consumes_decoded_core": True, "same_inputs_across_backends": True,
                "native_allocation_cleanup_observed": True, "real_os_out_of_memory_observed": False,
                "source_to_ir_refinement_proved": False, "backend_refinement_proved": False,
                "whole_language_soundness_proved": False, "universal_performance_advantage_proved": False,
                "general_lifetimes_supported": False, "concurrency_supported": False}}
        report["sha256"] = _sha(_wire(report))
        return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rustc", default=os.environ.get("RUSTC", "rustc"))
    parser.add_argument("--clang", default=os.environ.get("CLANG", "clang"))
    parser.add_argument("--cc", default=os.environ.get("CC", "cc"))
    parser.add_argument("--report", type=Path)
    args = parser.parse_args(argv)
    if args.report is not None and (args.report.exists() or args.report.is_symlink()):
        parser.error("--report requires a new path")
    try:
        report = qualify_executable_core(rustc=args.rustc, clang=args.clang, cc=args.cc)
    except (ValueError, OSError, subprocess.TimeoutExpired) as exc:
        report = {"schema": "hepta.executable-core-qualification.v1", "ok": False,
                  "status": "rejected", "diagnostic": str(exc), "claims": {"native_qualified": False}}
    encoded = json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n"
    if args.report is not None:
        with args.report.open("x") as stream:
            stream.write(encoded)
    else:
        print(encoded, end="")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
