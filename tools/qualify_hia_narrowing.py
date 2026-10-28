#!/usr/bin/env python3
"""Native and assembly qualification of certified modular narrowing, no timing race.

This tool records actual proof/build costs but does not measure workload speed
or grant a performance result. A separately registered fixed baseline study is
required. Every output directory is new; failures are retained without retry.
"""
from __future__ import annotations

import argparse
import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hepta.hia_program import verify_program
from hepta.hia_program_source import lower_source
from hepta.hia_program_llvm import emit_program_llvm
from hepta.hia_native_differential import _pin_native_artifact
from hepta.native_mapping_identity import verify_loaded_symbols
from hepta.hia_guarded_optimization import (propose_guarded_reduction, build_guarded_native,
                                          _freeze as guard_freeze, _compose)
from hepta.hia_narrowing import propose_guarded_narrowing, build_guarded_narrowed_native


def wire(value):
    return json.dumps(value, indent=2, sort_keys=True, allow_nan=False).encode() + b"\n"


def identity(path):
    path = Path(path).resolve(strict=True)
    return {"path": str(path), "bytes": path.stat().st_size,
            "sha256": sha256(path.read_bytes()).hexdigest()}


def source_bindings():
    paths = {Path(__file__), ROOT / "experiments/hia_optimizer_eval/kernels.hepta"}
    for module in tuple(sys.modules.values()):
        path = getattr(module, "__file__", None)
        if path and Path(path).resolve().is_relative_to(ROOT / "hepta") and path.endswith(".py"):
            paths.add(Path(path))
    return {str(path.resolve().relative_to(ROOT)): identity(path)["sha256"] for path in sorted(paths)}


def oracle(name, length, seed):
    first = [(i + seed) % 256 for i in range(256)] if name == "full_lifecycle" else [
        ((13 * i + seed) % 256) ^ ((i + (seed ^ 90)) % 256) for i in range(256)]
    return (length // 256) * sum(first) + sum(first[:length % 256])


def qualify(output, clang, objdump):
    out = Path(output).absolute()
    out.mkdir(parents=True, exist_ok=False)
    started = time.monotonic_ns()
    cases = [{"function": function, "size": size, "seed": seed,
              "expected": oracle(function, size, seed)}
             for function in ("full_lifecycle", "packet_xor")
             for size in (0, 1, 15, 16, 17, 31, 32, 33, 255, 256, 257, 4096)
             for seed in (0, 1, 255, 256, 2**31, 2**32 - 1)]
    record = {"schema": "hepta.hia.narrowing-native-qualification.v1", "status": "running",
              "passed": False, "performance_qualified": False, "native_observations": [],
              "cost_ns": {}, "scope": "finite native correctness and actual loaded-image identity; no workload timing"}
    clang = str(Path(shutil.which(clang) or clang).resolve(strict=True))
    objdump = str(Path(shutil.which(objdump) or objdump).resolve(strict=True))
    try:
        source = (ROOT / "experiments/hia_optimizer_eval/kernels.hepta").read_bytes()
        base = lower_source(source.decode())
        original = propose_guarded_reduction(base, maximum=32)
        left, fast, frozen = guard_freeze(base, original)
        guarded = _compose(left, fast, frozen)
        chain = propose_guarded_narrowing(base, maximum=32)
        narrowed = verify_program(chain["narrowing"]["candidate_core"])
        plan = {"schema": "hepta.hia.narrowing-native-plan.v1", "base_sha256": base.sha256,
                "guarded_sha256": guarded.sha256, "narrowed_sha256": narrowed.sha256,
                "cases": cases, "guard_maximum": 32, "source_bindings": source_bindings(),
                "tools": {"clang": identity(clang), "objdump": identity(objdump)},
                "no_performance_samples": True}
        (out / "plan.json").write_bytes(wire(plan))
        (out / "kernels.hepta").write_bytes(source)
        record["plan_sha256"] = sha256((out / "plan.json").read_bytes()).hexdigest()
        for name, program, proposal, build in (("guarded", guarded, original, build_guarded_native),
                                               ("narrowed", narrowed, chain, build_guarded_narrowed_native)):
            (out / (name + ".hia")).write_bytes(program.canonical_bytes)
            (out / (name + ".ll")).write_text(emit_program_llvm(program).text)
            (out / (name + "-proposal.json")).write_bytes(wire(proposal))
            begin = time.monotonic_ns()
            receipt = build(base, proposal, out / (name + ".so"), clang=clang)
            record["cost_ns"][name + "_proof_build"] = time.monotonic_ns() - begin
            (out / (name + "-receipt.json")).write_bytes(wire(receipt))
            argv = [objdump, "-d", "--no-show-raw-insn", str(out / (name + ".so"))]
            disassembly = subprocess.run(argv, capture_output=True, timeout=30)
            (out / (name + ".asm")).write_bytes(disassembly.stdout)
            (out / (name + "-objdump.json")).write_bytes(wire({"argv": argv,
                "returncode": disassembly.returncode, "stderr": disassembly.stderr.decode(errors="replace")}))
            if disassembly.returncode:
                raise RuntimeError("objdump failed")
            _, _, descriptor = _pin_native_artifact(out / (name + ".so"))
            library = None
            try:
                library = ctypes.CDLL(f"/proc/self/fd/{descriptor}", mode=os.RTLD_NOW | os.RTLD_LOCAL)
                exports = {function: getattr(library, function) for function in ("full_lifecycle", "packet_xor")}
                mapping = verify_loaded_symbols(descriptor, exports)
                (out / (name + "-loaded-mapping.json")).write_bytes(wire(mapping))
                for call in exports.values():
                    call.argtypes, call.restype = [ctypes.c_uint64, ctypes.c_uint32], ctypes.c_uint64
                for case in cases:
                    observed = {**case, "variant": name,
                                "actual": exports[case["function"]](case["size"], case["seed"])}
                    record["native_observations"].append(observed)
                    if observed["actual"] != case["expected"]:
                        raise RuntimeError("actual native output differs from independent oracle")
            finally:
                if library is not None:
                    import _ctypes
                    _ctypes.dlclose(library._handle)
                os.close(descriptor)
        record["source_unchanged"] = all(identity(ROOT / name)["sha256"] == digest
                                          for name, digest in plan["source_bindings"].items())
        record["tools_unchanged"] = all(identity(path) == plan["tools"][name]
                                         for name, path in (("clang", clang), ("objdump", objdump)))
        if not record["source_unchanged"] or not record["tools_unchanged"]:
            raise RuntimeError("source or tool identity changed")
        record.update(status="qualified_finite_native_scope", passed=True)
    except Exception as error:
        record.update(status="failed", error={"type": type(error).__name__, "message": str(error)})
    finally:
        record["cost_ns"]["whole_qualification"] = time.monotonic_ns() - started
        record["files"] = {p.name: identity(p) for p in sorted(out.iterdir()) if p.is_file()}
        (out / "RESULT.json").write_bytes(wire(record))
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True)
    parser.add_argument("--clang", default=os.environ.get("CLANG", "clang"))
    parser.add_argument("--objdump", default="objdump")
    args = parser.parse_args()
    result = qualify(args.out, args.clang, args.objdump)
    print(json.dumps({"status": result["status"], "passed": result["passed"],
                      "native_observations": len(result["native_observations"]),
                      "performance_qualified": False}))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
