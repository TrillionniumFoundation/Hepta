#!/usr/bin/env python3
"""Build and boot every target unit of a frozen Linux configuration through HIA.

This is the explicit unsafe systems dialect. It neither invokes the bounded
safe-Core checker for unsupported pointer operations nor reuses original target
objects. Replay mode reconstructs the image from retained HIA programs.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sys
import time

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hepta import hia_system
from tools import hia_linux_full_inventory as inventory
from tools import qualify_hia_linux_baseline as baseline

SCHEMA = "hepta.hia.linux.full-system-build.v1"
SOURCE_FILES = (
    "hepta/hia_system.py",
    "tools/hia_system_cc.py",
    "tools/hia_system_host_cc.py",
    "tools/hia_system_host_cxx.py",
    "tools/hia_linux_full_inventory.py",
    "tools/qualify_hia_linux_full.py",
    "tools/qualify_hia_linux_baseline.py",
    "tools/hia_system/system_module.cpp",
    "tools/hia_system/system_instructions.cpp",
    "tools/hia_system/system_wire.h",
    "tools/hia_system/CMakeLists.txt",
    "schemas/hia_system.v1.schema.json",
    "experiments/hia_linux_kernel_20261106/guest_init.c",
    "benchmarks/hia_linux_full/PROTOCOL.json",
)


def require(condition, message):
    baseline.require(condition, message)


def file_matches(binding):
    return isinstance(binding, dict) and baseline.identity(binding["path"]) == binding


def source_identity(commit):
    identity = baseline.source_identity(commit)
    identity["system_sources"] = {name: baseline.identity(ROOT / name) for name in SOURCE_FILES}
    return identity


def validate_stock(path, llvm, source):
    value = json.loads(path.read_bytes())
    require(value.get("schema") == "hepta.hia.linux.stock-baseline.v1", "actual stock baseline receipt required")
    require(value.get("status") == value.get("build_status") == value.get("boot_status") == "PASS",
            "complete stock build and boot must pass first")
    require(value.get("kernel_version") == baseline.KERNEL_VERSION and
            value.get("upstream_commit") == baseline.UPSTREAM_COMMIT and
            value.get("source_archive_sha256") == baseline.ARCHIVE_SHA256,
            "stock baseline differs from frozen Linux source")
    require(value.get("linux_source_unchanged") is True, "stock source identity not closed")
    require(file_matches(value["config"]) and value["config"]["sha256"] == value["config_sha256"],
            "stock exact config changed")
    require(file_matches(value["kernel_image"]) and file_matches(value["vmlinux"]),
            "stock kernel artifacts changed")
    require(baseline.sha(llvm / "clang") == value["compiler"]["sha256"], "different stock and HIA Clang")
    require(baseline.sha(llvm / "ld.lld") == value["llvm_tools"]["ld.lld"]["sha256"],
            "different stock and HIA linker")
    values = baseline.parse_config(Path(value["config"]["path"]).read_text())
    require(values.get("CONFIG_CC_IS_CLANG") == "y" and values.get("CONFIG_LD_IS_LLD") == "y",
            "frozen config does not use the required LLVM toolchain")
    require(values.get("CONFIG_RUST") != "y", "Rust target units require a separately registered frontend")
    # Debug metadata is not discarded to force a pass. The current codec
    # explicitly rejects unsupported specialized debug metadata.
    require(values.get("CONFIG_DEBUG_INFO") != "y", "this registered full profile has no debug-info lowering")
    return value


def verify_codec_receipt(path, codec):
    receipt = json.loads(path.read_bytes())
    require(receipt.get("status") == "PASS" and receipt.get("sources_unchanged") is True,
            "native codec build receipt must pass with unchanged sources")
    qualification = receipt.get("qualification", {})
    require(qualification.get("status") == "PASS" and qualification.get("checks") == 53 and
            qualification.get("opcodes") == 65 and receipt.get("canonical_ir_status") == "PASS" and
            receipt.get("old_environment_loader_status") == "PASS",
            "native codec semantic, canonical IR and runtime qualification required")
    for key in ("report",):
        row = qualification.get(key)
        require(isinstance(row, dict) and baseline.sha(row["path"]) == row.get("sha256"),
                "native codec qualification report changed")
    executable = receipt.get("executable") or receipt.get("binary") or receipt.get("codec")
    require(isinstance(executable, dict) and executable.get("sha256") == baseline.sha(codec),
            "codec build receipt does not bind the executing binary")
    source_map = receipt.get("sources")
    require(isinstance(source_map, dict), "native codec sources missing from build receipt")
    for name in ("system_module.cpp", "system_instructions.cpp", "system_wire.h"):
        row = source_map.get(name) or source_map.get("tools/hia_system/" + name)
        require(isinstance(row, dict) and row.get("sha256") == baseline.sha(ROOT / "tools/hia_system" / name),
                "native codec source differs from clean Git checkout: " + name)
    return receipt


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stock-result", type=Path, required=True)
    parser.add_argument("--kernel-source", type=Path, required=True)
    parser.add_argument("--source-archive", type=Path, required=True)
    parser.add_argument("--llvm-bin", type=Path, required=True)
    parser.add_argument("--codec", type=Path, required=True)
    parser.add_argument("--codec-build-receipt", type=Path, required=True)
    parser.add_argument("--qemu", type=Path, required=True)
    parser.add_argument("--qemu-data", type=Path, required=True)
    parser.add_argument("--bios", type=Path, required=True)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--replay-programs", type=Path)
    parser.add_argument("--jobs", type=int, default=8)
    parser.add_argument("--build-timeout", type=int, default=14400)
    parser.add_argument("--boot-timeout", type=int, default=180)
    args = parser.parse_args(argv)
    require(re.fullmatch(r"[a-f0-9]{40}", args.expected_head) is not None, "exact source commit required")
    require(1 <= args.jobs <= 64 and 0 < args.build_timeout <= 86400 and 0 < args.boot_timeout <= 1800,
            "invalid finite execution budget")
    source, output, llvm = args.kernel_source.resolve(), args.output.resolve(), args.llvm_bin.resolve()
    protected = (ROOT, source, llvm, args.source_archive.resolve().parent, args.stock_result.resolve().parent)
    for path in protected:
        require(not output.is_relative_to(path) and not path.is_relative_to(output), "output overlaps input: " + str(path))
    output.mkdir(parents=True, exist_ok=False)
    result = {
        "schema": SCHEMA, "status": "FAIL", "started_at_utc": baseline.utc(),
        "kernel_version": baseline.KERNEL_VERSION, "upstream_commit": baseline.UPSTREAM_COMMIT,
        "source_commit": args.expected_head, "scope": "complete_frozen_x86_64_configuration",
        "mode": "replay" if args.replay_programs else "import",
        "image_kind": "hia_system_linux", "build_status": "NOT_RUN", "boot_status": "NOT_RUN",
        "all_configured_target_units_rewritten": False, "all_linux_configurations": False,
        "fallback_c_units": None, "legacy_safe_core_memory_proof": False,
        "ndu_calls": 0, "ndu_gain_established": False, "production_activation": False,
    }
    runner, before, code_before = None, None, None
    started = time.monotonic_ns()
    try:
        code_before = source_identity(args.expected_head)
        result["source_before"] = code_before
        stock = validate_stock(args.stock_result.resolve(), llvm, source)
        result["stock_baseline"] = baseline.identity(args.stock_result)
        result["source_archive"] = baseline.identity(args.source_archive)
        before = baseline.verify_kernel_source(source, args.source_archive)
        result["linux_source_inventory"] = baseline.write_gzip_json(output / "source-before.json.gz", before)
        result["linux_source_denominators"] = stock["linux_source_denominators"]
        codec_receipt = verify_codec_receipt(args.codec_build_receipt, args.codec)
        baseline.write_json(output / "codec-build-receipt.json", codec_receipt)
        result["codec_build_receipt"] = baseline.identity(output / "codec-build-receipt.json")
        build, ledger = output / "build", output / "compiler-ledger"
        build.mkdir()
        ledger.mkdir()
        programs = args.replay_programs.resolve(strict=True) if args.replay_programs else output / "hia-programs"
        if args.replay_programs:
            require((programs / "index").is_dir(), "replay requires the complete retained HIA program index")
        else:
            programs.mkdir()
        tools = {name: baseline.identity(path) for name, path in {
            "clang": llvm / "clang", "clangxx": llvm / "clang++",
            "llvm_dis": llvm / "llvm-dis", "codec": args.codec.resolve(),
        }.items()}
        manifest = {
            "schema": hia_system.MANIFEST_SCHEMA, "mode": result["mode"],
            "source_commit": args.expected_head, "source_root": str(source), "build_root": str(build),
            "program_root": str(programs), "ledger_root": str(ledger), "tools": tools,
        }
        manifest_path = output / "system-build-environment.json"
        baseline.write_json(manifest_path, manifest)
        result["system_manifest"] = baseline.identity(manifest_path)
        env = baseline.build_environment(llvm)
        stock_env = json.loads(Path(stock["build_environment"]["path"]).read_bytes())
        require(env == stock_env, "stock and HIA target build environments differ")
        env["HIA_SYSTEM_MANIFEST"] = str(manifest_path)
        baseline.write_json(output / "build-environment.json", env)
        runner = baseline.CommandRunner(output, env)
        wrappers = {
            "target": ROOT / "tools/hia_system_cc.py",
            "host_c": ROOT / "tools/hia_system_host_cc.py",
            "host_cxx": ROOT / "tools/hia_system_host_cxx.py",
        }
        for path in wrappers.values():
            require(path.is_file() and os.access(path, os.X_OK), "compiler driver must be executable: " + str(path))
        make = [
            "make", "-C", str(source), "O=" + str(build), "ARCH=x86_64", "LLVM=" + str(llvm) + "/", "V=1",
            "CC=" + str(wrappers["target"]), "HOSTCC=" + str(wrappers["host_c"]),
            "HOSTCXX=" + str(wrappers["host_cxx"]),
        ]
        shutil.copyfile(stock["config"]["path"], build / ".config")
        shutil.copyfile(stock["config"]["path"], output / "exact.config")
        result["config"] = baseline.identity(output / "exact.config")
        result["config_sha256"] = stock["config_sha256"]
        runner.run("hia-olddefconfig", [*make, "olddefconfig"], timeout=600)
        require(baseline.sha(build / ".config") == stock["config_sha256"],
                "HIA compiler changed the frozen stock config")
        result["build_status"] = "FAIL"
        runner.run("full-hia-kbuild", [*make, "-j" + str(args.jobs), "vmlinux", "bzImage", "modules"],
                   timeout=args.build_timeout)
        require(baseline.sha(build / ".config") == stock["config_sha256"], "Kbuild changed exact config")
        meta, coverage = inventory.collect(build, source, ledger, manifest_path, wrappers, output)
        result["full_build_inventory"], result["coverage"] = meta, coverage["counts"]
        result["all_configured_target_units_rewritten"], result["fallback_c_units"] = True, 0
        result["kernel_image"] = baseline.identity(build / "arch/x86/boot/bzImage")
        result["vmlinux"] = baseline.identity(build / "vmlinux")
        result["modules"] = [baseline.identity(p) for p in sorted(build.rglob("*.ko"))]
        result["hia_program_root"] = str(programs)
        result["build_status"] = "PASS"
        guest = output / "guest"
        guest.mkdir()
        require(file_matches(stock["guest_init"]) and file_matches(stock["initramfs"]), "stock guest test payload changed")
        shutil.copyfile(stock["guest_init"]["path"], guest / "init")
        shutil.copyfile(stock["initramfs"]["path"], guest / "initramfs.cpio.gz")
        result["guest_init"] = baseline.identity(guest / "init")
        result["initramfs"] = baseline.identity(guest / "initramfs.cpio.gz")
        require(baseline.sha(args.qemu) == stock["qemu"]["sha256"] and
                baseline.sha(args.bios) == stock["qemu"]["bios"]["sha256"], "QEMU/BIOS differs from stock")
        runtime_modules = baseline.qemu_runtime_modules(env)
        require(runtime_modules == {key: stock["qemu"][key] for key in ("module_dir", "modules") if key in stock["qemu"]},
                "QEMU runtime differs from stock")
        result["qemu"] = stock["qemu"]
        release = (build / "include/config/kernel.release").read_text().strip()
        require(release == baseline.KERNEL_VERSION, "unexpected kernel release")
        run_id = hashlib.sha256((str(output) + baseline.utc()).encode()).hexdigest()[:24]
        result["run_id"] = run_id
        command = baseline.qemu_command(args.qemu, args.qemu_data, args.bios,
                                       result["kernel_image"]["path"], guest / "initramfs.cpio.gz", run_id, release)
        rec = runner.run("boot-full-hia-kernel-tcg", command, timeout=args.boot_timeout, check=False)
        serial = Path(rec["stdout"]["path"]).read_text(errors="replace")
        verdict = baseline.parse_guest_serial(serial, run_id, rec["exit_code"], rec["timed_out"], command_receipt=rec)
        baseline.write_json(output / "guest-verdict.json", verdict)
        result["boot"], result["boot_status"], result["guest_tests"] = verdict, verdict["status"], verdict["guest_tests"]
        require(verdict["status"] == "PASS", "full HIA kernel guest checks failed")
        require(baseline.qemu_runtime_modules(env) == runtime_modules, "QEMU runtime changed during boot")
        result["status"] = "PASS"
    except Exception as error:
        result["status"] = "FAIL"
        result["error"] = {"type": type(error).__name__, "message": str(error)}
    finally:
        if before is not None:
            try:
                after = baseline.inventory_tree(source)
                result["linux_source_after_inventory"] = baseline.write_gzip_json(output / "source-after.json.gz", after)
                result["linux_source_unchanged"] = after == before
                require(after == before, "Linux source changed during build")
            except Exception as error:
                result["status"], result["source_error"] = "FAIL", str(error)
        if code_before is not None:
            try:
                result["source_after"] = source_identity(args.expected_head)
                require(result["source_after"] == code_before, "compiler source changed during build")
            except Exception as error:
                result["status"], result["wrapper_source_error"] = "FAIL", str(error)
        result["commands"] = runner.records if runner else []
        result["elapsed_ns"], result["completed_at_utc"] = time.monotonic_ns() - started, baseline.utc()
        baseline.write_json(output / "RESULT.json", result)
        print(json.dumps({"result": str(output / "RESULT.json"), "status": result["status"],
                          "build_status": result["build_status"], "boot_status": result["boot_status"],
                          "all_configured_target_units_rewritten": result["all_configured_target_units_rewritten"]}), flush=True)
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
