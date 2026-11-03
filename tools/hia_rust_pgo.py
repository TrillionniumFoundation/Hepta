"""Training-only, source-bound Rust PGO preparation for release parity.

This produces a stronger comparison artifact, never a HIA safety certificate.
No holdout input is accepted by the preparation interface. Every generated
profile, tool, compiler command and paid preparation stage remains observable.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import time

from tools.qualify_hia_native_ndu import (
    FIXTURES, driver, file_identity, protocol, require, run_command,
)


PROFILE = "verified-reduction-narrowed-rust-pgo-release-v1"
RUST_FLAGS = ("opt-level=3", "lto=fat", "codegen-units=1", "panic=abort",
              "overflow-checks=off", "force-frame-pointers=no")
MAX_PROFILE_FILES = 128
MAX_PROFILE_BYTES = 256 * 1024 * 1024


def training_registration():
    source = protocol()
    return {"schema": "hepta.hia.rust-pgo-training.v1",
            "sizes": list(source["sizes"]), "seeds": list(source["training_seeds"]),
            "batch_calls": source["batch_calls"],
            "samples": source["training_samples_per_request"],
            "warmup_calls": source["warmup_calls"],
            "rust_flags": list(RUST_FLAGS),
            "rust_source": "benchmarks/hia_native_ndu/kernel.rs",
            "profile_format": "LLVM IR instrumentation; exact Rust LLVM/llvm-profdata version match",
            "warning_policy": "enable pgo-warn-missing-function; reject every profile/build warning",
            "holdout_inputs_used": 0,
            "preparation_cost": "initial baseline build, instrumentation build, all training calls, cleanup, merge and profile-use rebuild are retained and charged"}


def _no_warnings(command):
    stderr = Path(command["stderr"]["path"]).read_text(errors="replace")
    require(re.search(r"warning|error|missing|mismatch|out.of.date", stderr, re.I) is None,
            "E_RUST_PGO_WARNING: profile preparation/build emitted a warning or missing-profile diagnostic")


def profile_inventory(directory):
    paths = sorted(Path(directory).glob("*.profraw"))
    require(1 <= len(paths) <= MAX_PROFILE_FILES, "E_RUST_PGO_PROFILE: missing or excessive raw profiles")
    values = [file_identity(path) for path in paths]
    require(all(0 < row["bytes"] <= MAX_PROFILE_BYTES for row in values)
            and sum(row["bytes"] for row in values) <= MAX_PROFILE_BYTES,
            "E_RUST_PGO_PROFILE: empty or oversized raw profile")
    return values


def check_pgo_identities(preparation):
    """Check every actual preparation input/output again after measurement."""
    required = {"llvm_profdata", "rustc", "clang", "rust_source", "driver", "metrics_object",
                "unprofiled_rust", "instrumented_rust", "training_transcript", "used_profile",
                "optimized_rust", "optimized_assembly", "optimized_disassembly"}
    if (type(preparation.get("identities")) is not dict
            or not required <= set(preparation["identities"])
            or type(preparation.get("raw_profiles")) is not list or not preparation["raw_profiles"]
            or preparation.get("profile_use_argument") != preparation["identities"]["used_profile"]["path"]):
        preparation["identities_unchanged"] = False
        return False
    actual, stable = {}, True
    for name, expected in preparation.get("identities", {}).items():
        try:
            value = file_identity(expected["path"])
            matches = all(value[key] == expected[key] for key in ("path", "bytes", "sha256"))
            actual[name] = value
        except OSError as error:
            matches = False
            actual[name] = {"error": type(error).__name__}
        stable &= matches
    raw = preparation.get("raw_profiles", [])
    raw_paths = {row["path"] for row in raw}
    raw_directory = preparation.get("raw_directory")
    if raw_directory is not None:
        stable &= {str(path.resolve()) for path in Path(raw_directory).glob("*.profraw")} == raw_paths
    else:
        stable = False
    preparation["identities_after"] = actual
    preparation["identities_unchanged"] = bool(stable and preparation.get("status") == "passed")
    return preparation["identities_unchanged"]


def prepare_rust_pgo(directory, clang, rustc, llvm_profdata, products, report, *, registration):
    """Build/train/merge/use once; replace only the Rust comparison artifact."""
    require(type(registration) is dict and registration == training_registration(),
            "E_RUST_PGO_REGISTRATION: exact source-bound training-only plan required")
    require(llvm_profdata is not None, "E_RUST_PGO_TOOL: explicit llvm-profdata path required")
    started = time.monotonic_ns()
    directory = Path(directory).resolve()
    work = directory / "rust-pgo"
    work.mkdir(exist_ok=False)
    raw = work / "raw"
    raw.mkdir()
    generated, optimized = work / "instrumented", work / "optimized"
    generated.mkdir()
    optimized.mkdir()
    ledger = report["build_commands"]
    prep = {"schema": "hepta.hia.rust-pgo-preparation.v1", "status": "running",
            "registration": registration, "raw_directory": str(raw),
            "training_requests": [], "stage_wall_ns": {}, "identities": {},
            "holdout_inputs_used": 0, "missing_function_warnings_enabled": True,
            "initial_unprofiled_rust_build_retained_and_charged": True,
            "performance_qualified": False, "production_authority": False}
    report["rust_pgo"] = prep

    def remember(name, path):
        prep["identities"][name] = file_identity(path)
        return prep["identities"][name]

    def command(arguments, *, cwd=None):
        result = run_command(arguments, directory, ledger, cwd=cwd)
        _no_warnings(ledger[-1])
        for stream in ("stdout", "stderr"):
            remember("command:" + str(len(ledger) - 1) + ":" + stream,
                     ledger[-1][stream]["path"])
        return result

    def compile_rust(destination, profile_flag):
        arguments = [str(rustc), "--edition=2021", "--crate-type=cdylib",
                     "--emit=link=" + str(destination / "rust.so") + ",asm=" + str(destination / "rust.s")]
        for flag in RUST_FLAGS:
            arguments += ["-C", flag]
        arguments += ["-C", "linker=" + str(clang), "-C", "link-arg=" + str(directory / "metrics.o"),
                      "-C", profile_flag]
        if profile_flag.startswith("profile-use="):
            arguments += ["-C", "llvm-args=-pgo-warn-missing-function"]
        for name in ("malloc", "calloc", "realloc", "free"):
            arguments += ["-C", "link-arg=-Wl,--wrap=" + name]
        command([*arguments, FIXTURES / "kernel.rs"], cwd=destination)

    try:
        stage = time.monotonic_ns()
        profdata = Path(llvm_profdata).resolve(strict=True)
        profdata_version = command([profdata, "--version"])
        rust_version = command([rustc, "--version", "--verbose"])
        version = re.search(r"LLVM version: (\d+\.\d+\.\d+)", rust_version)
        tool_version = re.search(r"LLVM version\s+(\d+\.\d+\.\d+)", profdata_version)
        require(version is not None and tool_version is not None
                and version[1].startswith("20.") and version[1] == tool_version[1],
                "E_RUST_PGO_TOOL: Rust and LLVM20 profile tool versions differ")
        report["toolchains"]["llvm_profdata"] = {**remember("llvm_profdata", profdata),
                                                "version": profdata_version.strip()}
        remember("rustc", rustc)
        remember("clang", clang)
        remember("rust_source", FIXTURES / "kernel.rs")
        remember("driver", directory / "driver")
        remember("metrics_object", directory / "metrics.o")
        remember("unprofiled_rust", products["rust"]["path"])
        remember("unprofiled_rust_disassembly", report["stack_evidence"]["disassembly"]["rust"]["path"])
        prep["stage_wall_ns"]["tool_and_input_binding"] = time.monotonic_ns() - stage

        stage = time.monotonic_ns()
        compile_rust(generated, "profile-generate=" + str(raw))
        instrumented = remember("instrumented_rust", generated / "rust.so")
        prep["stage_wall_ns"]["instrumented_build"] = time.monotonic_ns() - stage

        stage = time.monotonic_ns()
        training_products = {"rust": instrumented}
        environment = {**os.environ, "LLVM_PROFILE_FILE": str(raw / "rust-%m-%p.profraw")}
        transcript = work / "training.jsonl"
        with driver(directory / "driver", transcript, env=environment) as child:
            prep["training_load"] = child.load("rust", training_products)
            for seed in registration["seeds"]:
                for n in registration["sizes"]:
                    row = child.measure("rust", n, seed, registration["batch_calls"],
                                        registration["samples"], registration["warmup_calls"])
                    require(type(row.get("calls")) is int and row["calls"] == registration["batch_calls"]
                            and type(row.get("samples")) is int and row["samples"] == registration["samples"],
                            "E_RUST_PGO_TRAINING: driver work differs from frozen training")
                    prep["training_requests"].append(row)
        remember("training_transcript", transcript)
        prep["stage_wall_ns"]["training_and_shutdown"] = time.monotonic_ns() - stage
        prep["raw_profiles"] = profile_inventory(raw)
        for index, identity in enumerate(prep["raw_profiles"]):
            prep["identities"]["raw_profile:" + str(index)] = identity

        stage = time.monotonic_ns()
        merged = work / "training.profdata"
        command([profdata, "merge", "-o", merged, *[row["path"] for row in prep["raw_profiles"]]])
        remember("used_profile", merged)
        profile_dump = command([profdata, "show", "--all-functions", "--counts", merged])
        require(re.search(r"(?m)^\s*calculate:\s*$", profile_dump) is not None,
                "E_RUST_PGO_PROFILE: exported calculate has no observed profile")
        prep["profile_dump"] = ledger[-1]["stdout"]
        prep["stage_wall_ns"]["profile_merge_and_inspection"] = time.monotonic_ns() - stage

        stage = time.monotonic_ns()
        compile_rust(optimized, "profile-use=" + str(merged))
        optimized_identity = remember("optimized_rust", optimized / "rust.so")
        remember("optimized_assembly", optimized / "rust.s")
        disassembly = command(["/usr/bin/objdump", "-d", "--disassemble=calculate", optimized / "rust.so"])
        disassembly_path = optimized / "rust.calculate.asm"
        disassembly_path.write_text(disassembly)
        report["stack_evidence"]["disassembly"]["rust"] = remember("optimized_disassembly", disassembly_path)
        prep["profile_use_argument"] = str(merged)
        prep["stage_wall_ns"]["profile_use_rebuild"] = time.monotonic_ns() - stage
        products["rust"] = optimized_identity
        report["native_artifacts"]["rust"] = optimized_identity
        report["build_profile"].update(id=PROFILE, rust_pgo=True,
                                      rust_pgo_training_only=True)
        prep["status"] = "passed"
        require(check_pgo_identities(prep), "E_RUST_PGO_IDENTITY: preparation artifact changed")
        return products
    except BaseException as error:
        prep.update(status="failed", error={"type": type(error).__name__, "message": str(error)})
        raise
    finally:
        prep["actual_total_ns"] = time.monotonic_ns() - started
        prep["other_preparation_ns"] = prep["actual_total_ns"] - sum(prep["stage_wall_ns"].values())
