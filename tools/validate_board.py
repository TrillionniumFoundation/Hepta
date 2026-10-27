#!/usr/bin/env python3
"""Execute actual Cortex-M4 boot, volatile UART MMIO and timer IRQs in QEMU.

Qualification is for the pinned system model, not a physical board. Retained
ELF bytes, source identities, raw device output and compiled negative controls
are checked together. Validation is structural replay, not report signing.
"""
from __future__ import annotations

import argparse
import base64
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from hepta.backend import RUST_VERSION, compile_rust, find_rustc, toolchain_info
from hepta.pipeline import analyze, compiler_hash, hsir_analysis, cfg_analysis
from tools.evidence_checks import command, is_sha, native_build, normalized_errors, require, strict_equal, text

BOARD = ROOT / "examples/boards/mps2_an386"
TARGET = "thumbv7em-none-eabi"
CASES = ("correct", "wrong_irq_checksum", "disabled_irq", "missing_data_copy")
CLAIMS = {"system_emulator_executed": True, "reset_and_mmio_and_external_irq_executed": True,
          "physical_board_qualified": False, "dma_qualified": False, "gpu_qualified": False,
          "interrupt_resource_soundness_proved": False, "device_timing_qualified": False,
          "c_freestanding_backend_qualified": False}
QEMU_OPTIONS = ["-M", "mps2-an386", "-cpu", "cortex-m4", "-display", "none", "-monitor", "none",
                "-serial", "stdio", "-nic", "none", "-no-reboot", "-semihosting-config",
                "enable=on,target=native", "-icount", "shift=0,align=off,sleep=off"]
LIMITATIONS = ["This is QEMU system-model execution, not physical hardware or hardware timing qualification.",
               "Rust BSP startup, vector table, raw MMIO addresses and barriers remain trusted external obligations.",
               "Volatile access is neither atomic synchronization nor a DMA ownership or interrupt-resource proof.",
               "Only the Rust no_std backend and the pinned Cortex-M4 model execute this profile."]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def inputs():
    return {name: (BOARD / name).read_bytes() for name in ("kernel.hepta", "startup.rs", "link.ld", "board.json")}


def case_inputs(name, data):
    require(name in CASES, "Unknown board qualification case")
    source, startup = data["kernel.hepta"].decode(), data["startup.rs"].decode()
    if name == "wrong_irq_checksum":
        needle = "return wrapping_mul(ordinal, ordinal);"
        require(source.count(needle) == 1, "IRQ negative-control site changed")
        source = source.replace(needle, "return wrapping_add(wrapping_mul(ordinal, ordinal), 1);")
    elif name == "missing_data_copy":
        needle = "    ldr r3, [r0], #4\n    str r3, [r1], #4"
        require(startup.count(needle) == 1, "Reset negative-control site changed")
        startup = startup.replace(needle, "    movs r3, #0\n    str r3, [r1], #4")
    flags = ["--cfg", "disable_timer_irq"] if name == "disabled_irq" else []
    return source, startup, flags


def elf_evidence(data):
    """Parse the retained ELF32 bytes independently of the compiler's report."""
    require(52 <= len(data) <= 512 * 1024 and data[:7] == b"\x7fELF\x01\x01\x01", "Expected bounded ELF32 little-endian artifact")
    header = struct.unpack_from("<HHIIIIIHHHHHH", data, 16)
    kind, machine, version, entry, phoff, shoff, flags, ehsize, phsize, phnum, shsize, shnum, shstr = header
    require((kind, machine, version, ehsize, phsize, shsize) == (2, 40, 1, 52, 32, 40), "Expected ARM executable ELF layout")
    require(1 <= phnum <= 32 and 1 <= shnum <= 128 and 0 < shstr < shnum, "Invalid ELF table bounds")
    require(phoff + phnum * phsize <= len(data) and shoff + shnum * shsize <= len(data), "Truncated ELF tables")
    sections_raw = [struct.unpack_from("<IIIIIIIIII", data, shoff + i * shsize) for i in range(shnum)]
    def contents(section):
        offset, size = section[4:6]
        require(offset <= len(data) and size <= len(data) - offset, "Truncated ELF section")
        return data[offset:offset + size]
    names = contents(sections_raw[shstr])
    def string(table, offset):
        require(offset < len(table) and b"\0" in table[offset:], "Invalid ELF string offset")
        return table[offset:table.index(b"\0", offset)].decode("ascii")
    sections = {string(names, row[0]): row for row in sections_raw}
    require(len(sections) == shnum, "Duplicated ELF section names")
    retained = {}
    for name in (".vector_table", ".text", ".data", ".bss"):
        require(name in sections, "Missing required ELF section " + name)
        row = sections[name]
        payload = b"" if row[1] == 8 else contents(row)
        retained[name] = {"type": row[1], "flags": row[2], "address": row[3], "bytes": row[5],
                          "sha256": None if row[1] == 8 else sha(payload)}
    symtab = sections[".symtab"]
    require(symtab[9] == 16 and symtab[5] % 16 == 0 and symtab[6] < shnum, "Malformed symbol table")
    symbols = {}
    table, names = contents(symtab), contents(sections_raw[symtab[6]])
    wanted = {"Reset", "board_main", "Default_Handler", "Timer0_Handler", "SysTick_Handler", "DATA_MARKER",
              "uart_init", "uart_putc", "timer_start", "timer_irq", "timer_stopped",
              "__stack_top", "__data_start", "__data_end", "__data_load", "__bss_start", "__bss_end"}
    for offset in range(0, len(table), 16):
        name, value, size, info, other, index = struct.unpack_from("<IIIBBH", table, offset)
        name = string(names, name)
        if name in wanted:
            require(name not in symbols and index != 0, "Missing/duplicate defined board symbol")
            symbols[name] = value
    require(set(symbols) == wanted, "Required actual startup, data and Hepta symbols missing")
    vectors = list(struct.unpack("<48I", contents(sections[".vector_table"])))
    segments = []
    for i in range(phnum):
        values = struct.unpack_from("<8I", data, phoff + i * phsize)
        if values[0] == 1:
            _, offset, vaddr, paddr, filesz, memsz, perms, alignment = values
            require(filesz <= memsz and offset + filesz <= len(data), "Invalid ELF load segment")
            segments.append({"virtual": vaddr, "physical": paddr, "file_bytes": filesz,
                             "memory_bytes": memsz, "flags": perms, "alignment": alignment})
    return {"bytes": len(data), "sha256": sha(data), "machine": machine, "entry": entry, "flags": flags,
            "sections": retained, "symbols": symbols, "vectors": vectors, "load_segments": segments,
            "data_hex": contents(sections[".data"]).hex()}


def validate_elf(elf):
    sections, symbols, vectors = elf["sections"], elf["symbols"], elf["vectors"]
    require(elf["machine"] == 40 and elf["flags"] == 0x05000200 and elf["entry"] == symbols["Reset"], "Wrong ARM EABI/entry profile")
    require(sections[".vector_table"]["address"] == 0 and sections[".vector_table"]["bytes"] == 192,
            "Reset vector table must reside at the actual board reset address")
    require(vectors[0] == symbols["__stack_top"] == 0x20010000 and vectors[1] == symbols["Reset"]
            and vectors[15] == symbols["SysTick_Handler"] and vectors[24] == symbols["Timer0_Handler"],
            "Stack/reset/SysTick/external IRQ8 vectors differ")
    expected_vectors = [symbols["__stack_top"], symbols["Reset"]] + [symbols["Default_Handler"]] * 5
    expected_vectors += [0] * 4 + [symbols["Default_Handler"], symbols["Default_Handler"], 0,
                                  symbols["Default_Handler"], symbols["SysTick_Handler"]]
    expected_vectors += [symbols["Default_Handler"]] * 8 + [symbols["Timer0_Handler"]] + [symbols["Default_Handler"]] * 23
    require(vectors == expected_vectors, "Complete Cortex-M vector inventory differs")
    require(all(symbols[name] & 1 and 192 <= symbols[name] < 4 * 1024 * 1024 for name in
                ("Reset", "board_main", "Default_Handler", "Timer0_Handler", "SysTick_Handler",
                 "uart_init", "uart_putc", "timer_start", "timer_irq", "timer_stopped")), "Expected actual Thumb code symbols")
    require(sections[".data"]["address"] == symbols["__data_start"] == symbols["DATA_MARKER"] == 0x20000000
            and sections[".data"]["bytes"] == 4 and elf["data_hex"] == "df9b5713"
            and symbols["__data_end"] == 0x20000004, "Real writable .data canary was omitted/folded")
    require(sections[".bss"]["type"] == 8 and sections[".bss"]["bytes"] == 16
            and sections[".bss"]["address"] == symbols["__bss_start"] == symbols["__data_end"]
            and symbols["__bss_end"] == 0x20000014, "Atomic ISR/main zero-initialized storage differs")
    require(any(s["virtual"] == symbols["__data_start"] and s["physical"] == symbols["__data_load"]
                and s["file_bytes"] == 4 and s["flags"] == 6 for s in elf["load_segments"]), "Missing writable RAM segment with FLASH load address")


def observed(stdout):
    require(isinstance(stdout, str) and stdout.startswith("HEPTA_BOARD ") and stdout.endswith("\n")
            and stdout.count("\n") == 1, "Missing exact UART device transcript")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "Duplicated UART JSON field")
            result[key] = value
        return result
    return json.loads(stdout[len("HEPTA_BOARD "):], object_pairs_hook=unique)


def validate_observation(name, value, returncode):
    expected_code = {"correct": 0, "wrong_irq_checksum": 43, "disabled_irq": 42, "missing_data_copy": 41}[name]
    expected = {"status": "passed" if name == "correct" else "rejected", "code": expected_code,
                "data_marker": 0 if name == "missing_data_copy" else 0x13579bdf,
                "irq_count": 5 if name in {"correct", "wrong_irq_checksum"} else 0,
                "checksum": 55 if name == "correct" else 60 if name == "wrong_irq_checksum" else 0,
                "watchdog_ticks": value.get("watchdog_ticks"), "bad_irq": 0,
                "timer_stopped": name in {"correct", "wrong_irq_checksum"}}
    require(strict_equal(value, expected) and type(returncode) is int and returncode == expected_code,
            "Actual board output or exit code differs from independent oracle")
    ticks = value["watchdog_ticks"]
    require(type(ticks) is int and ((0 < ticks < 20) if name in {"correct", "wrong_irq_checksum"}
                                  else ticks == (20 if name == "disabled_irq" else 0)),
            "Actual SysTick watchdog did not distinguish missing external IRQs")


def link_command(rustc, lld, directory, flags):
    return [rustc, str(directory / "startup.rs"), "--edition=2021", "--target=" + TARGET,
            "-C", "linker=" + lld, "-C", "link-arg=-T" + str(directory / "link.ld"),
            "-C", "panic=abort", "-C", "opt-level=2", *flags, "--extern",
            "hepta_program=" + str(directory / "libhepta_program.rlib"), "-o", str(directory / "board.elf")]


def qualify(*, qemu=None, rustc=None):
    data, identity = inputs(), compiler_hash()
    rustc = find_rustc(rustc)
    rust_info = toolchain_info(rustc)
    lld = Path(rustc).parent.parent / "lib/rustlib" / rust_info["host"] / "bin/rust-lld"
    qemu = shutil.which(qemu or "qemu-system-arm")
    require(qemu is not None, "qemu-system-arm is required; no object-only fallback")
    qemu = str(Path(qemu).resolve())
    commands = []
    def run(argv, *, expected=0, timeout=30):
        start = time.monotonic()
        result = subprocess.run(list(map(str, argv)), capture_output=True, text=True, timeout=timeout)
        record = {"argv": list(map(str, argv)), "returncode": result.returncode,
                  "stdout": result.stdout, "stderr": result.stderr, "seconds": time.monotonic() - start}
        commands.append(record)
        require(result.returncode == expected, "Actual board command failed: " + json.dumps(record))
        return record
    qemu_version = run([qemu, "--version"])["stdout"].strip()
    require(qemu_version.startswith("QEMU emulator version 8.2.2 "), "Only QEMU 8.2.2 is qualified by this board profile")
    lld_version = run([lld, "-flavor", "gnu", "--version"])["stdout"].strip()
    cases = []
    with tempfile.TemporaryDirectory(prefix="hepta-system-board-") as td:
        for name in CASES:
            directory = Path(td) / name
            directory.mkdir()
            source, startup, flags = case_inputs(name, data)
            source_path = directory / "kernel.hepta"
            source_path.write_text(source)
            (directory / "startup.rs").write_text(startup)
            (directory / "link.ld").write_bytes(data["link.ld"])
            frontend = analyze(source, str(source_path), rustc=rustc, target=TARGET, no_std=True)
            require(frontend.report["ok"], "Board frontend/native check rejected: " + json.dumps(frontend.report))
            hsir, cfg = hsir_analysis(frontend), cfg_analysis(frontend)
            native = compile_rust(frontend.rust, rustc=rustc, target=TARGET, crate_type="rlib",
                                  output=directory / "libhepta_program.rlib")
            require(native["ok"], "Actual no_std library did not build")
            linked = run(link_command(rustc, str(lld), directory, flags), timeout=60)
            elf_bytes = (directory / "board.elf").read_bytes()
            elf = elf_evidence(elf_bytes)
            validate_elf(elf)
            runs = []
            for repeat in range(3 if name == "correct" else 1):
                result = run([qemu, *QEMU_OPTIONS, "-kernel", directory / "board.elf"],
                             expected={"correct": 0, "wrong_irq_checksum": 43, "disabled_irq": 42, "missing_data_copy": 41}[name], timeout=15)
                observation = observed(result["stdout"])
                validate_observation(name, observation, result["returncode"])
                runs.append({"repeat": repeat, "observation": observation, "command": result})
            cases.append({"name": name, "source_sha256": sha(source.encode()), "startup_sha256": sha(startup.encode()),
                          "generated_rust_sha256": sha(frontend.rust.encode()), "frontend": frontend.report,
                          "hsir": hsir["hsir"], "cfg": cfg["cfg"], "native_library": native,
                          "link": linked, "elf": elf, "elf_base64": base64.b64encode(elf_bytes).decode(), "runs": runs})
    require(identity == compiler_hash() and data == inputs(), "Board/compiler source changed during execution")
    report = {"schema": "hepta.system-board.v1", "status": "passed",
              "created_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(), "compiler_sha256": identity,
              "target": TARGET, "source_files": {name: sha(content) for name, content in data.items()},
              "board_profile": json.loads(data["board.json"]), "rustc": rust_info,
              "linker": {"path": str(lld), "sha256": sha(lld.read_bytes()), "version": lld_version},
              "qemu": {"path": qemu, "sha256": sha(Path(qemu).read_bytes()), "version": qemu_version},
              "cases": cases, "commands": commands, "claims": dict(CLAIMS),
              "denominator": {"compiled_board_images": 4, "cold_boot_executions": 6, "positive_boots": 3,
                              "compiled_negative_controls": 3, "external_timer_irqs_per_positive_boot": 5},
              "limitations": list(LIMITATIONS)}
    validate_report(report)
    return report


@normalized_errors
def validate_report(report):
    require(isinstance(report, dict) and set(report) == {"schema", "status", "created_utc", "compiler_sha256",
            "target", "source_files", "board_profile", "rustc", "linker", "qemu", "cases", "commands", "claims", "denominator", "limitations"},
            "Unexpected system-board report fields")
    require(report.get("schema") == "hepta.system-board.v1" and report.get("status") == "passed"
            and report.get("compiler_sha256") == compiler_hash() and report.get("target") == TARGET, "Stale or unqualified board report")
    require(strict_equal(report.get("claims"), CLAIMS), "Board report overclaims hardware, DMA, GPU or proof qualification")
    require(strict_equal(report.get("denominator"), {"compiled_board_images": 4, "cold_boot_executions": 6,
                "positive_boots": 3, "compiled_negative_controls": 3, "external_timer_irqs_per_positive_boot": 5}), "Complete actual board denominator required")
    data = inputs()
    require(strict_equal(report["source_files"], {name: sha(content) for name, content in data.items()})
            and strict_equal(report["board_profile"], json.loads(data["board.json"])), "Board manifest or source identity differs")
    require(text(report.get("created_utc")) and strict_equal(report.get("limitations"), LIMITATIONS),
            "Missing execution scope")
    qemu, linker, rust = report["qemu"], report["linker"], report["rustc"]
    require(rust.get("version", "").startswith("rustc " + RUST_VERSION + " ")
            and ("release: " + RUST_VERSION) in rust.get("version", "").splitlines(),
            "Pinned actual Rust release is required")
    for tool in (qemu, linker):
        require(text(tool.get("path")) and is_sha(tool.get("sha256")) and text(tool.get("version")), "Missing actual system tool identity")
    require(qemu["version"].startswith("QEMU emulator version 8.2.2 ") and "LLD" in linker["version"], "Wrong board toolchain/model version")
    trace = report["commands"]
    require(isinstance(trace, list) and len(trace) == 12, "Complete version/link/boot trace required")
    for item in trace:
        command(item)
    for entry, tool, extra in zip(trace[:2], (qemu, linker), ([], ["-flavor", "gnu"])):
        require(entry["argv"] == [tool["path"], *extra, "--version"] and entry["returncode"] == 0
                and entry["stdout"].strip() == tool["version"] and entry["stderr"] == "", "Tool version trace differs")
    cases = report["cases"]
    require(isinstance(cases, list) and [case.get("name") for case in cases] == list(CASES), "Missing or duplicate compiled board case")
    expected_trace, artifact_hashes = trace[:2].copy(), set()
    for case in cases:
        name = case["name"]
        source, startup, flags = case_inputs(name, data)
        require(case["source_sha256"] == sha(source.encode()) and case["startup_sha256"] == sha(startup.encode()), "Changed negative-control source identity")
        frontend = case["frontend"]
        generated = analyze(source, frontend["path"], target=TARGET, no_std=True, native=False)
        require(set(frontend) == set(generated.report) | {"backend"}, "Unexpected frontend qualification fields")
        for key in generated.report:
            if key not in {"checks", "ok", "status"}:
                require(strict_equal(frontend[key], generated.report[key]), "Frontend metadata/claims differ at " + key)
        require(generated.report["ok"] and frontend["ok"] is True and frontend["status"] == "checked_with_external_assumptions"
                and frontend["diagnostics"] == [] and frontend["source_sha256"] == sha(source.encode())
                and frontend["compiler_sha256"] == report["compiler_sha256"] and frontend["interface_sha256"] == generated.report["interface_sha256"]
                and strict_equal(frontend["checks"], {"syntax": "passed", "types_effects_resources": "passed_in_supported_subset", "rust_borrows_types": "rustc_checked"})
                and strict_equal(frontend["assumptions"], generated.report["assumptions"])
                and strict_equal(frontend["effects"], generated.report["effects"])
                and strict_equal(frontend["profile"], generated.report["profile"]), "Board source did not receive the actual declared native validation")
        digest = sha(generated.rust.encode())
        require(case["generated_rust_sha256"] == frontend["rust_sha256"] == digest
                and strict_equal(case["hsir"], hsir_analysis(generated)["hsir"])
                and strict_equal(case["cfg"], cfg_analysis(generated)["cfg"]), "Board generated code or external obligation graph differs")
        require(len(case["hsir"]["volatile_accesses"]) == 14 and all(not v for v in case["hsir"]["claims"].values()), "Volatile obligation inventory must remain descriptive")
        for built, check_only in ((frontend["backend"], True), (case["native_library"], False)):
            native_build(built, "rust", check_only=check_only, crate_type="rlib", source_sha256=digest)
            require(built["target"] == TARGET and strict_equal(built["toolchain"], rust), "Board Rust target/compiler differs")
            require({"panic=abort", "overflow-checks=yes", "codegen-units=1", "opt-level=3"}.issubset(built["flags"]), "Native board library flags changed")
        library = Path(case["native_library"]["artifact"])
        directory = library.parent
        require(library.name == "libhepta_program.rlib" and directory.name == name
                and frontend["path"] == str(directory / "kernel.hepta"), "Board native source/artifact binding differs")
        link = case["link"]
        command(link)
        require(link["argv"] == link_command(rust["path"], linker["path"], directory, flags)
                and link["returncode"] == 0 and link["stdout"] == "" and link["stderr"] == "", "Actual board link flags/control differ")
        encoded = case["elf_base64"]
        require(isinstance(encoded, str) and len(encoded) <= 700000, "Retained board ELF must be bounded")
        try:
            raw = base64.b64decode(encoded, validate=True)
            parsed = elf_evidence(raw)
        except (ValueError, struct.error, UnicodeError) as error:
            raise ValueError("Malformed retained board ELF") from error
        require(strict_equal(case["elf"], parsed), "Retained ELF bytes disagree with parsed artifact identity")
        validate_elf(parsed)
        artifact_hashes.add(parsed["sha256"])
        runs = case["runs"]
        require(isinstance(runs, list) and len(runs) == (3 if name == "correct" else 1), "Missing actual cold boot executions")
        expected_trace.append(link)
        for repeat, run in enumerate(runs):
            require(type(run["repeat"]) is int and run["repeat"] == repeat, "Duplicate/out-of-order board execution")
            executed = run["command"]
            command(executed)
            require(executed["argv"] == [qemu["path"], *QEMU_OPTIONS, "-kernel", str(directory / "board.elf")]
                    and executed["stderr"] in {"", "qemu-system-arm: warning: nic lan9118.0 has no peer\n"}, "Not the declared system emulator or unexpected emulator fault")
            value = observed(executed["stdout"])
            require(strict_equal(value, run["observation"]), "Summary differs from actual UART output")
            validate_observation(name, value, executed["returncode"])
            expected_trace.append(executed)
    require(len(artifact_hashes) == 4 and strict_equal(expected_trace, trace), "Control images or complete executed trace omitted/reused")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qemu")
    parser.add_argument("--rustc", default=os.environ.get("RUSTC"))
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/system-board.json")
    args = parser.parse_args()
    report = qualify(qemu=args.qemu, rustc=args.rustc)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
    print(json.dumps({"status": report["status"], "denominator": report["denominator"],
                      "physical_board_qualified": False, "output": str(args.output)}))


if __name__ == "__main__":
    main()
