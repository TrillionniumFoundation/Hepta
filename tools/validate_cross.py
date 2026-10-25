#!/usr/bin/env python3
"""Execute AArch64 no_std Hepta kernels under a pinned QEMU user emulator."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from hepta.pipeline import analyze, compiler_hash
from hepta.backend import compile_rust, find_rustc, toolchain_info

TARGET = "aarch64-unknown-linux-gnu"
HARNESS = r'''#![no_std]
#![no_main]
extern crate hepta_program;
fn exit(code: u64) -> ! {
    unsafe { core::arch::asm!("mov x8, #93", "svc #0", in("x0") code, options(noreturn)) }
}
#[panic_handler] fn panic(_: &core::panic::PanicInfo<'_>) -> ! { exit(99) }
#[no_mangle] pub extern "C" fn _start() -> ! {
    let input = [u64::MAX, 2, 3, 4];
    let mut output = [123u64; 4];
    let expected = [0u64, u64::MAX, 1, 4, 8];
    for count in 0..=4 {
        // The arrays cover count initialized elements and never overlap.
        unsafe {
            hepta_program::h_hepta_copy(output.as_mut_ptr(), input.as_ptr(), count);
            if hepta_program::h_hepta_sum(output.as_ptr(), count) != expected[count] { exit(10 + count as u64) }
        }
        for index in 0..count { if output[index] != input[index] { exit(20 + index as u64) } }
        for index in count..4 { if output[index] != 123 { exit(30 + index as u64) } }
    }
    exit(0)
}
'''


def sha(data):
    return hashlib.sha256(data).hexdigest()


def validate(qemu, output):
    compiler = find_rustc()
    rust_info = toolchain_info(compiler)
    lld = Path(compiler).parent.parent / "lib/rustlib" / rust_info["host"] / "bin/rust-lld"
    qemu = Path(qemu).resolve()
    qemu_version = subprocess.run([str(qemu), "--version"], capture_output=True, text=True, check=True, timeout=10).stdout.strip()
    source = (ROOT / "benchmarks/kernels.hepta").read_text()
    identity = compiler_hash()
    cases = []
    with tempfile.TemporaryDirectory(prefix="hepta-cross-execute-") as td:
        directory = Path(td)
        harness = directory / "driver.rs"
        harness.write_text(HARNESS)
        for name, text, expected_success in [("correct", source, True), ("wrong_sum_negative_control", source.replace("return sum;", "return 0;"), False)]:
            checked = analyze(text, str(ROOT / "benchmarks/kernels.hepta"), target=TARGET, no_std=True)
            if not checked.report["ok"]:
                raise RuntimeError(json.dumps(checked.report))
            lib = directory / "libhepta_program.rlib"
            built = compile_rust(checked.rust, target=TARGET, crate_type="rlib", output=lib)
            if not built["ok"]:
                raise RuntimeError(json.dumps(built))
            executable = directory / name
            command = [compiler, str(harness), "--edition=2021", "--target=" + TARGET,
                       "-C", "linker=" + str(lld), "-C", "link-arg=-static", "-C", "panic=abort",
                       "-C", "opt-level=2", "--extern", "hepta_program=" + str(lib), "-o", str(executable)]
            link = subprocess.run(command, capture_output=True, text=True, timeout=60)
            if link.returncode or not executable.is_file():
                raise RuntimeError(link.stdout + link.stderr)
            execution = subprocess.run([str(qemu), str(executable)], capture_output=True, text=True, timeout=10)
            if expected_success and execution.returncode != 0 or not expected_success and execution.returncode != 11:
                raise RuntimeError(f"Unexpected AArch64 execution {name}: {execution.returncode}: {execution.stderr}")
            cases.append({"case": name, "source_sha256": sha(text.encode()), "generated_rust_sha256": sha(checked.rust.encode()),
                          "artifact_sha256": sha(executable.read_bytes()), "returncode": execution.returncode,
                          "status": "passed" if expected_success else "failed_as_expected",
                          "object_identity": subprocess.run(["file", str(executable)], capture_output=True, text=True, check=True).stdout.strip()})
    if compiler_hash() != identity:
        raise RuntimeError("Compiler changed during cross execution")
    report = {"schema": "hepta.cross-execution.v1", "status": "passed", "target": TARGET,
              "compiler_sha256": identity, "rustc": rust_info, "qemu": qemu_version,
              "qemu_binary_sha256": sha(qemu.read_bytes()), "harness_sha256": sha(HARNESS.encode()),
              "cases": cases, "qualification": "AArch64 ISA execution under QEMU user-mode Linux emulation",
              "physical_hardware_executed": False, "cross_c_compiler_abi_qualified": False,
              "scope": "sum/copy at lengths 0..4, wrapping-u64 edge values, untouched destination suffix; Rust no_std syscall harness",
              "limitations": ["No physical CPU/board, IRQ, DMA, GPU, Windows or timing qualification.", "The ABI caller is a Rust extern-C harness, not an independent AArch64 C compiler."]}
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--qemu", default=str(ROOT.parent / "toolchains/qemu-8.2.2/qemu-aarch64-static"))
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/cross-execution.json")
    args = parser.parse_args()
    report = validate(args.qemu, args.output)
    print(json.dumps({"status": report["status"], "target": TARGET, "physical_hardware_executed": False, "output": str(args.output)}))


if __name__ == "__main__":
    main()
