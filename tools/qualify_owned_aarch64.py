#!/usr/bin/env python3
"""Execute the actual Hepta Owned module in QEMU with compiled negatives.

This qualifies the selected finite ABI/runtime on an emulator. It is neither
physical hardware qualification nor a benchmark. No C stand-in replaces the
Hepta implementation, and failed candidates must never be published.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from hepta.llvm_owned_aarch64 import build_owned_aarch64_source
from hepta.pipeline import compiler_hash

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ROOT / "examples/llvm_owned"
QEMU_SHA256 = "e4f8d99e9ff69c3cefffab71cee358ce2af1ecba1282d04c3eeb44ef76f5a71e"
CASES = {"correct": (None, None, 0),
         "wrong_result": ("return answer;", "return wrapping_add(answer, 1);", 11),
         "wrong_early_exit": ("return 2002;", "return 2004;", 13)}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def qualify(*, qemu, clang="clang", rustc=None):
    executable = shutil.which(qemu)
    require(executable is not None, "A real QEMU AArch64 runner is required")
    runner = Path(executable).resolve()
    require(sha(runner.read_bytes()) == QEMU_SHA256,
            "This qualification uses the checksum-locked QEMU from bootstrap_verification")
    version = subprocess.run([str(runner), "--version"], capture_output=True, text=True,
                             timeout=10, check=True)
    originals = {name: (SOURCES / name).read_bytes() for name in ("main.hepta", "owned.hepta")}
    identity = compiler_hash()
    cases = []
    with tempfile.TemporaryDirectory(prefix="hepta-owned-arm64-qualification-") as temporary:
        for name, (before, after, expected) in CASES.items():
            directory = Path(temporary) / name
            directory.mkdir()
            text = originals["owned.hepta"].decode("utf-8")
            if before is not None:
                require(text.count(before) == 1, "Frozen negative-control source site changed")
                text = text.replace(before, after)
            (directory / "main.hepta").write_bytes(originals["main.hepta"])
            (directory / "owned.hepta").write_text(text, encoding="utf-8")
            output = directory / "owner.o"
            report = build_owned_aarch64_source(
                directory / "main.hepta", output, rustc=rustc, clang=clang,
                finite_runtime_probe=True, qemu_aarch64=str(runner))
            if expected == 0:
                require(report.get("ok") is True and report.get("status") ==
                        "finite_qemu_userspace_execution_passed", "Actual Hepta ARM64 execution failed")
                require(report.get("artifact_kind") == "relocatable_object"
                        and report.get("published_artifact_executed") is False
                        and report.get("linked_image_executed") is True,
                        "Object and linked-image execution claims differ")
                runtime = report["finite_runtime_probe"]
                execution = runtime["execution"]
                require(runtime["real_target_device_executed"] is False
                        and runtime["general_allocator_qualified"] is False,
                        "Finite runtime must not overclaim physical/general qualification")
                require(output.is_file() and sha(output.read_bytes()) ==
                        runtime["object_sha256"] == report["published_artifact_sha256"],
                        "Executed image is not bound to the published source object")
            else:
                require(report.get("ok") is False and report.get("status") == "rejected",
                        "Compiled wrong implementation was accepted")
                require(not output.exists(), "Rejected execution published an object")
                execution = report.get("failed_execution")
            require(type(execution) is dict and type(execution.get("returncode")) is int
                    and execution["returncode"] == expected
                    and execution.get("runner_sha256") == QEMU_SHA256,
                    "Missing actual process result for the expected independent oracle")
            require(report["reference_validation"]["checks"]["rust_borrows_types"] == "rustc_checked",
                    "Every positive and negative source must pass the native reference gate")
            cases.append({"name": name, "expected_exit": expected,
                          "source_sha256": {"main.hepta": sha(originals["main.hepta"]),
                                            "owned.hepta": sha(text.encode("utf-8"))},
                          "implementation": "actual_hepta_module_through_direct_LLVM",
                          "build": report, "execution": execution,
                          "object_published": output.exists(),
                          "temporary_artifacts_retained": False})
    require(identity == compiler_hash(), "Compiler changed during qualification")
    require(all((SOURCES / name).read_bytes() == data for name, data in originals.items()),
            "Qualification source changed during execution")
    return {"schema": "hepta.owned-aarch64-qualification.v1", "status": "passed",
            "created_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "compiler_sha256": identity,
            "input_sources": {name: sha(data) for name, data in originals.items()},
            "runner": {"path": str(runner), "sha256": QEMU_SHA256, "version": version.stdout.strip()},
            "cases": cases,
            "denominator": {"compiled_hepta_programs": 3, "actual_qemu_executions": 3,
                            "positive_executions": 1, "compiled_negative_controls": 2,
                            "checks_in_successful_runtime": 7},
            "claims": {"actual_hepta_source_executed": True, "finite_C_ABI_emulated": True,
                       "physical_hardware_qualified": False, "general_allocator_qualified": False,
                       "aarch64_rust_reference_executed": False, "performance_measured": False,
                       "source_or_backend_refinement_proved": False},
            "limitations": ["Rust reference checking runs on the host; the LLVM object executes on QEMU AArch64.",
                            "Runtime supports one live allocation of at most 4096 bytes and one exact exported signature.",
                            "The seven successful call cases also check allocator accounting and memory primitives.",
                            "Negative controls change real Hepta return paths; no modified C stand-in is used."]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qemu", required=True)
    parser.add_argument("--clang", default="clang")
    parser.add_argument("--rustc", default=os.environ.get("RUSTC"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    require(not args.output.exists() and not args.output.is_symlink(), "New output report required")
    report = qualify(qemu=args.qemu, clang=args.clang, rustc=args.rustc)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n")
    print(json.dumps({"status": report["status"], "output": str(args.output),
                      "denominator": report["denominator"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
