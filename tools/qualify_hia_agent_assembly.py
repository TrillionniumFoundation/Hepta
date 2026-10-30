#!/usr/bin/env python3
"""Qualify compact Core spelling; controls are never Agent model successes."""
from __future__ import annotations

import argparse
import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from hepta.hia_agent_assembly import assemble_program, diagnose_assembly, render_assembly
from hepta.hia_core_upgrade import upgrade_core_to_v6
from hepta.hia_native_differential import _pin_native_artifact
from hepta.hia_program import HIAProgramRejected, verify_program
from hepta.hia_program_llvm import build_program_native, emit_program_llvm
from hepta.hia_program_runtime import HIAProgramTrap, execute_program
from hepta.hia_program_source import lower_source
from hepta.native_mapping_identity import verify_loaded_symbols


def wire(value):
    return json.dumps(value, sort_keys=True, indent=2, allow_nan=False).encode() + b"\n"


def identity(path):
    path = Path(path).resolve(strict=True)
    return {"bytes": path.stat().st_size, "sha256": sha256(path.read_bytes()).hexdigest()}


def bindings():
    paths = {Path(__file__), ROOT / "experiments/hia_optimizer_eval/kernels.hepta",
             ROOT / "examples/hia_recursive_chain/core_v7.json"}
    for module in tuple(sys.modules.values()):
        name = getattr(module, "__file__", None)
        if name and name.endswith(".py") and Path(name).resolve().is_relative_to(ROOT / "hepta"):
            paths.add(Path(name).resolve())
    return {str(p.relative_to(ROOT)): identity(p) for p in sorted(paths)}


def observe(program, name, arguments, **kwargs):
    try:
        return execute_program(program, name, arguments, **kwargs)
    except HIAProgramTrap as error:
        return error.report


def oracle(name, length, seed):
    return sum(((i + seed) % 256 if name == "full_lifecycle" else
                ((13 * i + seed) % 256) ^ ((i + (seed ^ 90)) % 256))
               for i in range(length))


def qualify(output, *, clang=None):
    out = Path(output).absolute()
    out.mkdir(parents=True, exist_ok=False)
    started = time.monotonic_ns()
    record = {"schema": "hepta.hia.agent-assembly.qualification.v1", "passed": False,
              "model_completion_requests": 0, "agent_advantage_qualified": False,
              "deployment_authority": False, "safety_certificate": False,
              "representations": [], "vm_observations": [], "native_observations": [],
              "native_requested": clang is not None, "cost_ns": {}}
    try:
        kernels, adaptation = upgrade_core_to_v6(lower_source(
            (ROOT / "experiments/hia_optimizer_eval/kernels.hepta").read_text()))
        chain = verify_program((ROOT / "examples/hia_recursive_chain/core_v7.json").read_bytes())
        plan = {"source_bindings": bindings(), "explicit_kernel_adapter": adaptation,
                "cases": [{"function": name, "size": size, "seed": seed,
                           "expected": oracle(name, size, seed)}
                          for name in ("full_lifecycle", "packet_xor")
                          for size in (0, 1, 31, 257) for seed in (0, 255, 2**32 - 1)],
                "native_requested": clang is not None, "performance_measurement": False}
        if clang is not None:
            clang = str(Path(shutil.which(clang) or clang).resolve(strict=True))
            plan["compiler"] = {"path": clang, **identity(clang)}
        (out / "PLAN.json").write_bytes(wire(plan))
        restored = {}
        for name, program in (("kernels", kernels), ("chain", chain)):
            begin = time.monotonic_ns()
            text = render_assembly(program)
            other = assemble_program(text)
            if other.canonical_bytes != program.canonical_bytes:
                raise RuntimeError("assembly changed exact canonical Core")
            if emit_program_llvm(other).text != emit_program_llvm(program).text:
                raise RuntimeError("assembly changed LLVM emitted from the same Core")
            restored[name] = other
            (out / (name + ".hiaasm")).write_text(text)
            (out / (name + ".hia.json")).write_bytes(program.canonical_bytes)
            record["representations"].append({"name": name, "core_sha256": program.sha256,
                "assembly_sha256": sha256(text.encode()).hexdigest(),
                "json_bytes": len(program.canonical_bytes), "assembly_bytes": len(text.encode()),
                "roundtrip_and_llvm_equal": True,
                "token_count": None, "no_token_savings_claim": True})
            record["cost_ns"][name + "_roundtrip_and_llvm"] = time.monotonic_ns() - begin
        for case in plan["cases"]:
            args = [case["size"], case["seed"]]
            for fail in (None, 1, 2):
                original = observe(kernels, case["function"], args, allocation_fail_at=fail)
                actual = observe(restored["kernels"], case["function"], args, allocation_fail_at=fail)
                row = {**case, "allocation_fail_at": fail, "original": original, "actual": actual}
                record["vm_observations"].append(row)
                if original != actual or (fail is None and actual["result"] != case["expected"]):
                    raise RuntimeError("actual values/resources/traps differ")
        for count in (0, 1, 7):
            for fail in (None, 1, 3):
                original = observe(chain, "chain_checksum", [count], allocation_fail_at=fail)
                actual = observe(restored["chain"], "chain_checksum", [count], allocation_fail_at=fail)
                record["vm_observations"].append({"function": "chain_checksum", "count": count,
                    "allocation_fail_at": fail, "original": original, "actual": actual})
                if original != actual:
                    raise RuntimeError("recursive chain values/resources differ")
        bad = render_assembly(kernels).replace("int.add.checked", "guess.add", 1)
        if bad == render_assembly(kernels):
            raise RuntimeError("negative control did not change an actual instruction")
        diagnostic = diagnose_assembly(bad)
        record["negative_control"] = diagnostic
        if diagnostic["accepted"] or diagnostic["deployment_authority"]:
            raise RuntimeError("unknown instruction acquired authority")
        if clang is not None:
            begin = time.monotonic_ns()
            artifact = out / "kernels.so"
            receipt = build_program_native(restored["kernels"], artifact, clang=clang)
            record["cost_ns"]["native_build"] = time.monotonic_ns() - begin
            (out / "native-receipt.json").write_bytes(wire(receipt))
            _, _, descriptor = _pin_native_artifact(artifact)
            library = None
            try:
                library = ctypes.CDLL(f"/proc/self/fd/{descriptor}", mode=os.RTLD_NOW | os.RTLD_LOCAL)
                exports = {name: getattr(library, name) for name in ("full_lifecycle", "packet_xor")}
                (out / "loaded-mapping.json").write_bytes(wire(verify_loaded_symbols(descriptor, exports)))
                for function in exports.values():
                    function.argtypes, function.restype = [ctypes.c_uint64, ctypes.c_uint32], ctypes.c_uint64
                for case in plan["cases"]:
                    value = exports[case["function"]](case["size"], case["seed"])
                    record["native_observations"].append({**case, "actual": value})
                    if value != case["expected"]:
                        raise RuntimeError("native output differs from independent arithmetic oracle")
            finally:
                try:
                    if library is not None:
                        import _ctypes
                        _ctypes.dlclose(library._handle)
                finally:
                    os.close(descriptor)
            if identity(clang) != {k: v for k, v in plan["compiler"].items() if k != "path"}:
                raise RuntimeError("compiler drift during qualification")
        record["sources_unchanged"] = all(identity(ROOT / p) == value for p, value in plan["source_bindings"].items())
        if not record["sources_unchanged"]:
            raise RuntimeError("source drift during qualification")
        record.update(passed=True, status="qualified_native" if clang else "qualified_vm_only")
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
    parser.add_argument("--clang", help="require actual native qualification with this compiler")
    args = parser.parse_args()
    result = qualify(args.out, clang=args.clang)
    print(json.dumps({"passed": result["passed"], "status": result["status"],
                      "vm_pairs": len(result["vm_observations"]),
                      "native_observations": len(result["native_observations"]),
                      "model_completion_requests": 0, "agent_advantage_qualified": False}))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
