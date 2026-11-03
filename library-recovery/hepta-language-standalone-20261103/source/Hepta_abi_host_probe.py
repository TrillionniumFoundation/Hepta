"""Independent GCC<->Clang host C ABI execution matrix for the Hepta P2 roadmap.

This is a host-only C/C test instrument. It does *not* qualify the Hepta ABI,
C++ ABI, cross-target object generation, or hardware execution.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile


HEADER = r'''#pragma once
#include <stddef.h>
#include <stdint.h>
typedef struct { uint32_t tag; uint64_t count; } AbiPair;
typedef struct { double score; uint16_t minor; uint8_t status; } AbiMixed;
typedef struct { AbiPair pair; AbiMixed mixed; uint8_t extra[3]; } AbiNested;
AbiPair abi_pair(AbiPair value);
AbiMixed abi_mixed(AbiMixed value);
AbiNested abi_nested(AbiNested value);
uint64_t abi_layout_signature(void);
uint64_t abi_callback(uint64_t (*handler)(uint64_t), uint64_t input);
uint64_t abi_many(uint32_t a, uint64_t b, uint32_t c, uint64_t d,
                  uint32_t e, uint64_t f, uint32_t g, uint64_t h);
'''

SIGNATURE = r'''static uint64_t abi_local_layout_signature(void) {
    const uint64_t parts[] = {
        sizeof(AbiPair), _Alignof(AbiPair), offsetof(AbiPair, tag), offsetof(AbiPair, count),
        sizeof(AbiMixed), _Alignof(AbiMixed), offsetof(AbiMixed, score),
        offsetof(AbiMixed, minor), offsetof(AbiMixed, status),
        sizeof(AbiNested), _Alignof(AbiNested), offsetof(AbiNested, pair),
        offsetof(AbiNested, mixed), offsetof(AbiNested, extra)
    };
    uint64_t hash = UINT64_C(1469598103934665603);
    size_t i;
    for (i = 0; i < sizeof(parts)/sizeof(parts[0]); ++i)
        hash = (hash ^ parts[i]) * UINT64_C(1099511628211);
    return hash;
}
'''

PRODUCER = r'''#include "abi.h"
''' + SIGNATURE + r'''
AbiPair abi_pair(AbiPair v) {
    v.tag += 7;
#ifdef HEPTA_ABI_FAULT
    v.tag += 1;
#endif
    v.count ^= UINT64_C(0x12345678);
    return v;
}
AbiMixed abi_mixed(AbiMixed v) {
    v.score += 2.5;
    v.minor += 4;
    v.status ^= 2;
    return v;
}
AbiNested abi_nested(AbiNested v) {
    v.pair = abi_pair(v.pair);
    v.mixed = abi_mixed(v.mixed);
    v.extra[1] ^= 0x5a;
    return v;
}
uint64_t abi_layout_signature(void) { return abi_local_layout_signature(); }
uint64_t abi_callback(uint64_t (*handler)(uint64_t), uint64_t input) {
    return handler(input) + 11;
}
uint64_t abi_many(uint32_t a, uint64_t b, uint32_t c, uint64_t d,
                  uint32_t e, uint64_t f, uint32_t g, uint64_t h) {
    return (uint64_t)a + b + c + d + e + f + g + h;
}
'''

CONSUMER = r'''#include "abi.h"
#include <stdio.h>
''' + SIGNATURE + r'''
static uint64_t callback(uint64_t x) { return x * 3; }
int main(void) {
    AbiPair p = {17, UINT64_C(0xabcdef12345678)};
    AbiPair r = abi_pair(p);
    if (r.tag != 24 || r.count != (p.count ^ UINT64_C(0x12345678))) return 11;
    AbiMixed m = {7.5, 42, 5};
    AbiMixed t = abi_mixed(m);
    if (t.score != 10.0 || t.minor != 46 || t.status != 7) return 12;
    AbiNested n = {{17, UINT64_C(0xabcdef12345678)}, {7.5, 42, 5}, {1, 2, 3}};
    AbiNested v = abi_nested(n);
    if (v.pair.tag != 24 || v.pair.count != (n.pair.count ^ UINT64_C(0x12345678))
        || v.mixed.score != 10.0 || v.mixed.minor != 46 || v.mixed.status != 7
        || v.extra[0] != 1 || v.extra[1] != (2 ^ 0x5a) || v.extra[2] != 3)
        return 13;
    if (abi_layout_signature() != abi_local_layout_signature()) return 14;
    if (abi_callback(callback, 9) != 38) return 15;
    if (abi_many(1, 2, 3, 4, 5, 6, 7, 8) != 36) return 16;
    printf("ABI_OK layout=%llu\n", (unsigned long long)abi_local_layout_signature());
    return 0;
}
'''


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _run(cmd: list[str | Path], *, timeout: int = 30) -> subprocess.CompletedProcess:
    return subprocess.run([str(x) for x in cmd], capture_output=True, text=True, timeout=timeout)


def run_matrix(directory: Path, gcc: str, clang: str) -> dict:
    directory.mkdir(parents=True, exist_ok=True)
    paths = {"abi.h": HEADER, "producer.c": PRODUCER, "consumer.c": CONSUMER}
    for filename, content in paths.items():
        (directory / filename).write_text(content)
    identity = {}
    for name, compiler in (("gcc", gcc), ("clang", clang)):
        ver = _run([compiler, "--version"])
        triple = _run([compiler, "-dumpmachine"])
        if ver.returncode or triple.returncode:
            raise RuntimeError("Could not identify compiler: " + name)
        identity[name] = {"path": str(Path(compiler).resolve()),
                          "sha256": _digest(Path(compiler).resolve()),
                          "version": ver.stdout.splitlines()[0], "target": triple.stdout.strip()}
    entries = []
    for producer_name, producer_compiler in (("gcc", gcc), ("clang", clang)):
        for consumer_name, consumer_compiler in (("gcc", gcc), ("clang", clang)):
            for producer_opt in ("-O0", "-O2"):
                for consumer_opt in ("-O0", "-O2"):
                    base = f"{producer_name}_{consumer_name}_{producer_opt}_{consumer_opt}".replace("-", "")
                    object_file = directory / (base + "_producer.o")
                    executable = directory / (base + "_caller")
                    compile_producer = _run([producer_compiler, "-std=c11", producer_opt,
                                             "-Wall", "-Wextra", "-Werror", "-c",
                                             directory / "producer.c", "-o", object_file])
                    if compile_producer.returncode:
                        raise RuntimeError(f"Producer {base}: {compile_producer.stderr[:500]}")
                    compile_caller = _run([consumer_compiler, "-std=c11", consumer_opt,
                                           "-Wall", "-Wextra", "-Werror", directory / "consumer.c",
                                           object_file, "-o", executable])
                    if compile_caller.returncode:
                        raise RuntimeError(f"Consumer {base}: {compile_caller.stderr[:500]}")
                    test = _run([executable], timeout=10)
                    entry = {"producer": producer_name, "consumer": consumer_name,
                             "producer_opt": producer_opt, "consumer_opt": consumer_opt,
                             "exit_code": test.returncode, "stdout": test.stdout.strip(),
                             "artifact_sha256": _digest(executable), "passed": test.returncode == 0}
                    entries.append(entry)
                    if test.returncode:
                        raise RuntimeError(f"C ABI roundtrip failed: {entry}")
    # A deliberately broken producer must be detected by the independent C consumer.
    bad = directory / "negative_producer.o"
    bad_bin = directory / "negative_caller"
    first = _run([gcc, "-std=c11", "-O2", "-DHEPTA_ABI_FAULT", "-c",
                  directory / "producer.c", "-o", bad])
    second = _run([clang, "-std=c11", "-O2", directory / "consumer.c", bad,
                   "-o", bad_bin]) if first.returncode == 0 else first
    neg = _run([bad_bin], timeout=10) if second.returncode == 0 else second
    if first.returncode or second.returncode or neg.returncode == 0:
        raise RuntimeError("Negative ABI mutation was not correctly detected")
    return {"schema": "hepta.host-c-abi.v1", "status": "passed_host_only",
            "host": {"os": platform.system(), "architecture": platform.machine()},
            "compiler_identity": identity,
            "fixtures_sha256": {name: _digest(directory / name) for name in paths},
            "executions": entries,
            "negative_control": {"expected_nonzero_exit": True, "exit_code": neg.returncode,
                                 "detected": neg.returncode != 0},
            "claims": {"hepta_abi_validated": False, "cross_target_abi_validated": False,
                       "cpp_abi_validated": False, "physical_hardware_validated": False}}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gcc", default="gcc")
    parser.add_argument("--clang", default="clang")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    gcc, clang = shutil.which(args.gcc), shutil.which(args.clang)
    if not gcc or not clang:
        parser.error("Both GCC and Clang must be available for the independent matrix")
    with tempfile.TemporaryDirectory(prefix="hepta-host-abi-") as td:
        try:
            report = run_matrix(Path(td), gcc, clang)
        except (RuntimeError, OSError, subprocess.SubprocessError) as exc:
            report = {"schema": "hepta.host-c-abi.v1", "status": "failed",
                      "error": str(exc), "claims": {"hepta_abi_validated": False,
                                                       "cross_target_abi_validated": False}}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"status": report["status"], "output": str(args.output)}, sort_keys=True))
    return 0 if report["status"] == "passed_host_only" else 1


if __name__ == "__main__":
    raise SystemExit(main())
