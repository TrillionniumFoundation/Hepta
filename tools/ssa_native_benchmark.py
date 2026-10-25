#!/usr/bin/env python3
"""Finite host-only SSA/PHI LLVM-versus-C benchmark, never a global speed claim.

A real SSA library must be compiled separately with a pinned native reference
check. This tool compiles an independent C baseline, checks valid-domain
answers, and measures native calls in separate processes. Peak process RSS is
NOT attributed to the Hepta function, and timings are NOT service p99.
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import platform
import random
import re
import shutil
import statistics
import subprocess
import tempfile
import time


C_REFERENCE = """#include <stdint.h>
int32_t SYMBOL(int32_t n) {
    int32_t total=0, i=0;
    while(i<n) { if(i<4) total+=i; else total+=1; ++i; }
    return total;
}
"""

NATIVE_DRIVER = r"""#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <time.h>
#include <sys/resource.h>
typedef int32_t (*Fn)(int32_t);
static int64_t nanos(struct timespec x) {
    return (int64_t)x.tv_sec*1000000000LL+x.tv_nsec;
}
int main(int argc, char** argv) {
    if(argc!=5) return 19;
    void* handle=dlopen(argv[1],RTLD_NOW|RTLD_LOCAL);
    if(!handle) { fprintf(stderr,"dlopen %s\n",dlerror()); return 20; }
    dlerror();
    Fn fn=(Fn)dlsym(handle,argv[2]);
    if(dlerror()||!fn) return 21;
    long iterations=strtol(argv[3],0,10), bound=strtol(argv[4],0,10);
    if(iterations<1 || iterations>100000000 || bound<0 || bound>10000) return 22;
    struct timespec a,b;
    if(clock_gettime(CLOCK_MONOTONIC,&a)) return 23;
    volatile int64_t sum=0;
    for(long i=0;i<iterations;i++) sum+=fn((int32_t)bound);
    if(clock_gettime(CLOCK_MONOTONIC,&b)) return 24;
    struct rusage usage;
    if(getrusage(RUSAGE_SELF,&usage)) return 25;
    int64_t elapsed=nanos(b)-nanos(a);
    if(elapsed<=0) return 26;
    printf("{\"elapsed_ns\":%lld,\"ns_per_call\":%.9f,\"process_peak_rss_kib\":%ld,\"checksum\":%lld}\n",
           (long long)elapsed,(double)elapsed/iterations,
           usage.ru_maxrss,(long long)sum);
    return 0;
}
"""


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(args, timeout=30):
    proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if proc.returncode:
        raise RuntimeError(f"E_SSA_BENCH_COMMAND: exit {proc.returncode}: "
                           + str(args[0]) + ": " + proc.stderr[:1000])
    return proc.stdout


def qualify(library: Path, *, symbol: str, output: Path, clang="clang",
            iterations=100000, trials=7, bound=20, seed=20261024):
    """C-bound finite qualification, with raw samples and negative claims."""
    if platform.system() != "Linux" or os.name != "posix":
        raise ValueError("E_SSA_BENCH_HOST: Linux POSIX profile required")
    library, output = library.resolve(), output.resolve()
    if not library.is_file() or library.stat().st_size == 0:
        raise ValueError("E_SSA_BENCH_LIBRARY: nonempty native library required")
    if not re.fullmatch("[A-Za-z][A-Za-z0-9_]{0,100}", symbol):
        raise ValueError("E_SSA_BENCH_SYMBOL: malformed symbol")
    if (iterations < 100 or iterations > 100000000 or
            trials < 3 or trials > 40 or bound < 0 or bound > 10000):
        raise ValueError("E_SSA_BENCH_LIMIT: invalid trial/iteration/bound")
    if not output.parent.is_dir() or output.exists() or output == library:
        raise ValueError("E_SSA_BENCH_OUTPUT: parent must exist and output must be new")
    selected = shutil.which(clang)
    if selected is None:
        raise ValueError("E_SSA_BENCH_TOOLCHAIN: missing Clang")
    compiler = Path(selected).resolve()
    source_hash = digest(library)
    flags = ["-O3", "-fPIC", "-fno-fast-math"]
    reference = C_REFERENCE.replace("SYMBOL", symbol)
    with tempfile.TemporaryDirectory(prefix="hepta-ssa-bench-") as directory:
        root = Path(directory)
        c_src, c_lib, driver_src, driver = (root / name for name in
                                            ("baseline.c", "baseline.so", "driver.c", "driver"))
        c_src.write_text(reference)
        driver_src.write_text(NATIVE_DRIVER)
        run([str(compiler), *flags, "-shared", "-x", "c", str(c_src), "-o", str(c_lib)])
        run([str(compiler), *flags, "-x", "c", str(driver_src), "-ldl", "-o", str(driver)])
        candidate = ctypes.CDLL(str(library))
        baseline = ctypes.CDLL(str(c_lib))
        funcs = [getattr(obj, symbol) for obj in (candidate, baseline)]
        for fn in funcs:
            fn.argtypes = [ctypes.c_int32]
            fn.restype = ctypes.c_int32
        domain = [-6, -1, 0, 1, 2, 3, 4, 5, 8, 12, 20, 40, 100]
        for n in domain:
            if funcs[0](n) != funcs[1](n):
                raise RuntimeError(f"E_SSA_BENCH_CORRECTNESS: mismatch for {n}")
        randomizer = random.Random(seed)
        raw = []
        for trial in range(trials):
            order = ["hepta_llvm_ssa", "independent_c"]
            randomizer.shuffle(order)
            for implementation in order:
                target = library if implementation == "hepta_llvm_ssa" else c_lib
                row = json.loads(run([str(driver), str(target), symbol,
                                      str(iterations), str(bound)]))
                if row["checksum"] != iterations * funcs[1](bound):
                    raise RuntimeError("E_SSA_BENCH_CORRECTNESS: timed native checksum mismatch")
                raw.append({"trial": trial, "implementation": implementation, **row})
        summary = {}
        for implementation in ("hepta_llvm_ssa", "independent_c"):
            samples = [r["ns_per_call"] for r in raw if r["implementation"] == implementation]
            summary[implementation] = {"min_ns_per_call": min(samples),
                                       "median_ns_per_call": statistics.median(samples),
                                       "max_ns_per_call": max(samples)}
        result = {
            "schema": "hepta.p6.ssa-perf.v0",
            "status": "completed_host_sample_not_proof",
            "measured_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "host": {"system": platform.system(), "machine": platform.machine()},
            "parameters": {"symbol": symbol, "iterations": iterations, "trials": trials,
                           "bound": bound, "seed": seed, "correctness_inputs": domain},
            "library_sha256": source_hash,
            "reference_c_source_sha256": hashlib.sha256(reference.encode()).hexdigest(),
            "driver_source_sha256": hashlib.sha256(NATIVE_DRIVER.encode()).hexdigest(),
            "compiler": {"version": run([str(compiler), "--version"]).splitlines()[0],
                         "path": str(compiler), "sha256": digest(compiler), "flags": flags},
            "raw_samples": raw, "summary": summary,
            "observed_median_hepta_over_c": (summary["hepta_llvm_ssa"]["median_ns_per_call"] /
                                             summary["independent_c"]["median_ns_per_call"]),
            "claims": {"correct_on_finite_domain": True,
                       "whole_language_faster_than_rust_or_c": False,
                       "function_heap_allocation_qualified": False,
                       "service_p99_qualified": False,
                       "physical_hardware_or_cross_target_qualified": False,
                       "semantic_equivalence_proved": False},
        }
        if digest(library) != source_hash:
            raise RuntimeError("E_SSA_BENCH_SOURCE_RACE: library mutated during benchmark")
        with output.open("x", encoding="utf-8") as out:
            json.dump(result, out, indent=2, sort_keys=True)
            out.write("\n")
        return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--symbol", default="hepta_accumulate")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--clang", default="clang")
    parser.add_argument("--iterations", type=int, default=100000)
    parser.add_argument("--trials", type=int, default=7)
    parser.add_argument("--bound", type=int, default=20)
    parser.add_argument("--seed", type=int, default=20261024)
    args = parser.parse_args(argv)
    try:
        report = qualify(args.library, symbol=args.symbol, output=args.output,
                         clang=args.clang, iterations=args.iterations,
                         trials=args.trials, bound=args.bound, seed=args.seed)
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        print(json.dumps({"ok": False, "status": "rejected", "error": str(error)}))
        return 1
    print(json.dumps({"ok": True, "status": report["status"],
                      "ratio": report["observed_median_hepta_over_c"],
                      "output": str(args.output)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
