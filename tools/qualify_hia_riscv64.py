"""Execute verified HIA integer/resource programs on RV64GC LP64D under QEMU.

Checks C-to-HIA integer arguments/returns (including twelve-argument stack
passing and raw RV64 return-register extension) and HIA-to-C finite allocator
calls. This does not expose general foreign imports, qualify RV32, or provide
physical-device evidence. Every failed build/run remains in the output folder.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import sys
import time
import traceback

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hepta.clang_capture import run_bounded
from hepta.hia_program import execute_program, verify_program
from hepta.hia_program_llvm import TARGET_RISCV64, compile_program_llvm, emit_program_llvm
from hepta.hia_program_aarch64 import COMPOSITE_BULK_CASES, COMPOSITE_BULK_TRAPS
from hepta.hia_program_runtime import HIAProgramTrap
from hepta.native_tool_identity import digest_executable
from hepta.object_symbols import inspect_object_symbols
from tools.qualify_hia_composite_bulk import byte_oracle, composite_bulk_program
from tools.qualify_hia_program import block, function, operation, ret
from tools.qualify_hia_recursive_chain import load_examples, independent_spec, vm_ledger


RUNTIME = ROOT / "examples/hia_program/finite_riscv64_runtime.c"
TYPES = ("i8", "u8", "i16", "u16", "i32", "u32", "i64", "u64", "isize", "usize", "bool")
C_TYPES = {"i8": "signed char", "u8": "unsigned char", "i16": "short", "u16": "unsigned short",
           "i32": "int", "u32": "unsigned int", "i64": "long long", "u64": "unsigned long long",
           "isize": "__PTRDIFF_TYPE__", "usize": "__SIZE_TYPE__", "bool": "_Bool"}
RUNTIME_EXPORTS = {"malloc", "calloc", "free", "memset", "memcpy", "memmove", "abort", "_start",
                   "raw_u32", "raw_i8", "raw_u8"}
STACK_CASES = ([0] * 12, [1] * 12, list(range(12)), [(1 << 32) - 1] * 12,
               [(1 << 31) + i for i in range(12)],
               [0, 1, 0xffffffff, 0x80000000, 7, 31, 0x7fffffff, 23, 0x12345678, 97, 13, 0xfeedbeef])
RAW_CASES = (("u32", 0), ("u32", 1), ("u32", 0x7fffffff), ("u32", 0x80000000),
             ("u32", 0xffffffff), ("i8", -128), ("i8", -1), ("i8", 127),
             ("u8", 128), ("u8", 255))
CHAIN_CASES = (
    *(("chain_checksum", n, 0, 0) for n in (0, 1, 17, 32)),
    ("chain_cancel", 32, 0, 0), ("chain_head_update", 17, 0, 0),
    *(("chain_checksum", 17, 0, fail) for fail in (1, 2, 17, 18)),
    ("chain_recover", 17, 0, 0), ("chain_recover", 17, 0, 36),
    ("chain_empty_payloads", 17, 0, 0), ("chain_empty_payloads", 17, 0, 3),
    ("chain_empty_pop", 0, 0, 0),
    ("chain_stored_loan", 17, 0, 0), ("chain_stored_loan", 17, 0, 18),
    *(("chain_task", 17, mode, 0) for mode in (0, 1, 2)),
    ("chain_task", 17, 2, 18),
)
CHAIN_RUNTIME_EXPORTS = RUNTIME_EXPORTS - {"raw_u32", "raw_i8", "raw_u8"}


def scalar_cases():
    rows = []
    for typ in TYPES:
        if typ == "bool":
            values = (False, True)
        else:
            bits = 64 if typ in {"usize", "isize"} else int(typ[1:])
            if typ.startswith("i"):
                low, high = -(1 << (bits - 1)), (1 << (bits - 1)) - 1
                values = (low, low + 1, -1, 0, 1, high - 1, high)
            else:
                high = (1 << bits) - 1
                values = (0, 1, 42, (1 << (bits - 1)) - 1, 1 << (bits - 1), high - 1, high)
        rows.extend((typ, value) for value in values)
    return tuple(rows)


def stack_oracle(arguments):
    return sum((index + 1) * value for index, value in enumerate(arguments)) % (1 << 32)


def raw_oracle(typ, value):
    # The C int32/uint32 RV64 ABI both sign-extend the 32-bit representation.
    if typ == "u32" and value >= (1 << 31):
        value -= 1 << 32
    return value % (1 << 64)


def program_document(*, wrong_value=False):
    document = composite_bulk_program()
    document["module"] = "riscv64_abi_and_resources"
    for typ in TYPES:
        params = [("value", typ)]
        ops = []
        answer = "value"
        if wrong_value and typ == "u32":
            ops = [operation("const", out=[("one", typ)], value=1),
                   operation("int.add.wrap", ["value", "one"], [("wrong", typ)])]
            answer = "wrong"
        document["functions"].append(function("abi_" + typ, params, [typ], [],
                                               [block("entry", params, ops, ret(answer))]))
    params = [("a" + str(i), "u32") for i in range(12)]
    ops = [operation("const", out=[("sum0", "u32")], value=0)]
    for i in range(12):
        ops += [operation("const", out=[("weight" + str(i), "u32")], value=i + 1),
                operation("int.mul.wrap", ["a" + str(i), "weight" + str(i)], [("part" + str(i), "u32")]),
                operation("int.add.wrap", ["sum" + str(i), "part" + str(i)], [("sum" + str(i + 1), "u32")])]
    document["functions"].append(function("abi_stack12", params, ["u32"], [],
                                           [block("entry", params, ops, ret("sum12"))]))
    return document


def _literal(typ, value):
    if typ == "bool":
        return "1" if value else "0"
    if value < 0:
        return f"(({C_TYPES[typ]})(-{-value - 1}LL - 1LL))"
    return f"(({C_TYPES[typ]}){value}ULL)"


def driver_source(mode="positive"):
    if mode not in {"positive", "wrong_return_extension", *COMPOSITE_BULK_TRAPS}:
        raise ValueError("unknown target driver mode")
    result = [RUNTIME.read_text()]
    result += [f"extern {C_TYPES[t]} abi_{t}({C_TYPES[t]});" for t in TYPES]
    result += ["extern unsigned int abi_stack12(" + ",".join(["unsigned int"] * 12) + ");",
               "extern hepta_u8 aggregate_bulk(hepta_size,hepta_size,hepta_size,hepta_u8,hepta_size);"]
    for typ in ("u32", "i8", "u8"):
        result.append(f"extern unsigned long long raw_{typ}({C_TYPES[typ]});")
        assembly = [".text", f".globl raw_{typ}", f".type raw_{typ},@function", f"raw_{typ}:",
                    "addi sp,sp,-16", "sd ra,8(sp)", f"call abi_{typ}"]
        if mode == "wrong_return_extension" and typ == "u32":
            # Deliberate assembly-transport mutation; never a qualified HIA artifact.
            assembly += ["slli a0,a0,32", "srli a0,a0,32"]
        assembly += ["ld ra,8(sp)", "addi sp,sp,16", "ret", f".size raw_{typ},.-raw_{typ}"]
        result.append("__asm__(" + json.dumps("\n".join(assembly) + "\n") + ");")
    result.append("__attribute__((noreturn)) void _start(void) {")
    result.append("    if (!memory_primitives_ok()) hepta_exit(39);")
    if mode in COMPOSITE_BULK_TRAPS:
        values = COMPOSITE_BULK_TRAPS[mode]
        result += ["    (void)aggregate_bulk(" + ",".join(str(x) for x in values) + ");",
                   "    write_resources();", "    hepta_exit(99);", "}"]
        return "\n".join(result) + "\n"
    result.append("    hepta_u64 calls = 0;")
    for typ, value in scalar_cases():
        literal = _literal(typ, value)
        result.append(f"    if (abi_{typ}({literal}) != {literal}) hepta_exit(41); ++calls;")
    for arguments in STACK_CASES:
        args = ",".join(_literal("u32", x) for x in arguments)
        result.append(f"    if (abi_stack12({args}) != {stack_oracle(arguments)}U) hepta_exit(41); ++calls;")
    for typ, value in RAW_CASES:
        result.append(f"    if (raw_{typ}({_literal(typ,value)}) != {raw_oracle(typ,value)}ULL) hepta_exit(42); ++calls;")
    result.append('    write_values("HIA_RISCV64 scalar ", &calls, 1);')
    for index, (arguments, failure, expected) in enumerate(COMPOSITE_BULK_CASES):
        result += [f"    failure_countdown = {failure or 0};",
                   f"    hepta_u64 row{index}[] = {{{index}, aggregate_bulk(" + ",".join(str(x) for x in arguments) + ")};",
                   f'    write_values("HIA_RISCV64 case ", row{index}, 2);',
                   f"    if (row{index}[1] != {expected}) hepta_exit(41);",
                   "    if (outstanding) {write_resources(); hepta_exit(91);}"]
    result += ["    write_resources();",
               "    if (successful_allocations != 31 || releases != 31 || denied_allocations != 2 || peak_outstanding != 2) hepta_exit(92);",
               "    hepta_exit(0);", "}"]
    return "\n".join(result) + "\n"


def expected_counts():
    scalar = len(scalar_cases()) + len(STACK_CASES) + len(RAW_CASES)
    return {"positive_binaries": 2, "scalar_calls_per_binary": scalar,
            "bulk_calls_per_binary": len(COMPOSITE_BULK_CASES),
            "actual_c_to_hia_calls": 2 * (scalar + len(COMPOSITE_BULK_CASES)),
            "vm_results": 2 * (len(scalar_cases()) + len(STACK_CASES) + len(COMPOSITE_BULK_CASES)),
            "allocations_per_positive_binary": 31, "frees_per_positive_binary": 31,
            "allocation_refusals_per_positive_binary": 2, "peak_live_per_positive_binary": 2,
            "actual_negative_executions": 3 + len(COMPOSITE_BULK_TRAPS),
            "recursive_positive_binaries": 1, "recursive_c_to_hia_calls": len(CHAIN_CASES),
            "recursive_vm_results": len(CHAIN_CASES), "recursive_negative_executions": 1,
            "all_actual_c_to_hia_calls": 2 * (scalar + len(COMPOSITE_BULK_CASES)) + len(CHAIN_CASES),
            "all_actual_negative_executions": 4 + len(COMPOSITE_BULK_TRAPS)}


def expected_stdout():
    scalar = len(scalar_cases()) + len(STACK_CASES) + len(RAW_CASES)
    return (f"HIA_RISCV64 scalar {scalar}\n" +
            "".join(f"HIA_RISCV64 case {i} {row[2]}\n" for i, row in enumerate(COMPOSITE_BULK_CASES)) +
            "HIA_RISCV64 resources 31 31 0 2 2\n")


def _sha(path):
    return sha256(Path(path).read_bytes()).hexdigest()


def _write(path, document):
    Path(path).write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")


def _source_bindings():
    selected = [*sorted((ROOT / "hepta").glob("*.py")), Path(__file__).resolve(), RUNTIME,
                ROOT / "tools/qualify_hia_composite_bulk.py", ROOT / "tools/qualify_hia_program.py",
                ROOT / "tools/qualify_hia_recursive_chain.py",
                ROOT / "examples/hia_recursive_chain/core_v7.json",
                ROOT / "examples/hia_recursive_chain/composite_v2.json"]
    return {str(p.relative_to(ROOT)): _sha(p) for p in selected}


def _run(argv, report, directory, *, require_zero=False):
    argv = [str(x) for x in argv]
    index = len(report["processes"])
    start = time.monotonic()
    observed = run_bounded(argv, timeout=60, stdout_limit=4 * 1024 * 1024, stderr_limit=1024 * 1024)
    record = {"argv": argv, "returncode": observed.returncode, "seconds": time.monotonic() - start}
    for stream in ("stdout", "stderr"):
        path = directory / f"process-{index:03d}.{stream}"
        path.write_text(getattr(observed, stream))
        record[stream] = str(path)
        record[stream + "_sha256"] = _sha(path)
    report["processes"].append(record)
    if require_zero and observed.returncode:
        raise ValueError("target command failed: " + observed.stderr[-3000:])
    return index, observed


def inspect_linked_riscv64(path, exports, readobj, report, directory, *, runtime_exports=RUNTIME_EXPORTS):
    """Check the actual file using a hash-bound LLVM reader and strict finite policy."""
    payload = Path(path).read_bytes()
    if (not 512 <= len(payload) <= 16 * 1024 * 1024 or payload[:6] != b"\x7fELF\x02\x01"
            or int.from_bytes(payload[16:18], "little") != 2
            or int.from_bytes(payload[18:20], "little") != 243
            or int.from_bytes(payload[48:52], "little") != 5):
        raise ValueError("expected static little-endian RV64GC LP64D ELF64 executable")
    process, observed = _run([readobj, "--elf-output-style=JSON", "--file-headers", "--program-headers",
                              "--symbols", path], report, directory, require_zero=True)
    parsed = json.loads(observed.stdout)
    if type(parsed) is not list or len(parsed) != 1:
        raise ValueError("unexpected LLVM ELF reader result")
    row = parsed[0]
    header = row["ElfHeader"]
    if (header["Machine"]["Value"] != 243 or header["Ident"]["Class"]["Value"] != 2
            or header["Flags"]["Value"] != 5 or row["FileSummary"]["Arch"] != "riscv64"):
        raise ValueError("LLVM reader disagrees with RV64 header")
    segments = [x["ProgramHeader"] for x in row["ProgramHeaders"]]
    executable = []
    stacks = 0
    for segment in segments:
        kind, flags = segment["Type"]["Value"], segment["Flags"]["Value"]
        offset, size = segment["Offset"], segment["FileSize"]
        if kind in {2, 3, 7} or offset + size > len(payload) or size > segment["MemSize"]:
            raise ValueError("dynamic/TLS or unbacked target segment")
        if kind == 1:
            if flags not in {4, 5, 6}:
                raise ValueError("unsupported target load permissions")
            if flags == 5:
                executable.append((segment["VirtualAddress"], size))
        if kind == 0x6474e551:
            stacks += 1
            if flags != 6:
                raise ValueError("target GNU stack must be non-executable RW")
    if stacks != 1:
        raise ValueError("target must have exactly one explicit non-executable stack")
    functions = {}
    for item in row["Symbols"]:
        symbol = item["Symbol"]
        if symbol["Binding"]["Value"] == 0:
            continue
        name, value, size = symbol["Name"]["Name"], symbol["Value"], symbol["Size"]
        if (symbol["Binding"]["Value"] != 1 or symbol["Type"]["Value"] != 2
                or symbol["Section"]["Value"] == 0 or name in functions or size <= 0
                or not any(start <= value and value + size <= start + length for start, length in executable)):
            raise ValueError("unresolved, weak, duplicate or unbacked external target function")
        functions[name] = {"address": value, "bytes": size}
    if set(functions) != set(exports) | set(runtime_exports) or functions["_start"]["address"] != header["Entry"]:
        raise ValueError("linked export or entrypoint inventory differs")
    if Path(path).read_bytes() != payload:
        raise ValueError("linked target changed during independent inspection")
    return {"format": "ELF64", "machine": 243, "riscv_flags": 5, "entrypoint": header["Entry"],
            "external_functions": sorted(functions), "reader_process": process,
            "artifact_sha256": sha256(payload).hexdigest(), "no_unresolved_symbols": True}


def _build_run(core, name, report, directory, tools, *, mode="positive", remove_free=False):
    folder = directory / name
    folder.mkdir()
    _write(folder / "core.json", core.as_dict())
    ir = emit_program_llvm(core, target=TARGET_RISCV64)
    (folder / "program.ll").write_text(ir.text)
    obj = folder / "program.o"
    if remove_free:
        changed = "\n".join(x for x in ir.text.splitlines() if "call void @free(" not in x) + "\n"
        if changed == ir.text:
            raise ValueError("removed-free negative did not change native IR")
        (folder / "removed-free.ll").write_text(changed)
        _run([tools["clang"], "--target=" + TARGET_RISCV64, "-march=rv64gc", "-mabi=lp64d",
              "-x", "ir", "-O3", "-fPIC", "-c", folder / "removed-free.ll", "-o", obj],
             report, directory, require_zero=True)
        build = {"qualified_hia_artifact": False, "reason": "deliberate removal of actual native free calls",
                 "artifact_sha256": _sha(obj), "unqualified_ir_sha256": _sha(folder / "removed-free.ll")}
    else:
        build = compile_program_llvm(ir, program=core, output=obj, clang=tools["clang"], kind="object")
    symbols = inspect_object_symbols(obj.read_bytes(), "ELF64", 243)
    if symbols["defined"] != frozenset(ir.exports):
        raise ValueError("RISC-V object export inventory differs from verified Core")
    driver = folder / "driver.c"
    driver.write_text(driver_source(mode))
    driver_obj = folder / "driver.o"
    _run([tools["clang"], "--target=" + TARGET_RISCV64, "-march=rv64gc", "-mabi=lp64d", "-mno-relax",
          "-x", "c", "-std=c11", "-ffreestanding", "-nostdinc", "-fno-builtin", "-fno-pic",
          "-fno-stack-protector", "-O2", "-Wall", "-Wextra", "-Werror", "-c", driver, "-o", driver_obj],
         report, directory, require_zero=True)
    driver_symbols = inspect_object_symbols(driver_obj.read_bytes(), "ELF64", 243)
    # Trap-only drivers keep the raw-register shims, but do not call other scalar exports.
    needed = {"aggregate_bulk", "abi_u32", "abi_u8", "abi_i8"} if mode in COMPOSITE_BULK_TRAPS else set(ir.exports)
    if driver_symbols["defined"] != frozenset(RUNTIME_EXPORTS) or driver_symbols["undefined"] != frozenset(needed):
        raise ValueError("C caller/runtime does not expose the exact bidirectional interface")
    executable = folder / "program.elf"
    _run([tools["linker"], "-flavor", "gnu", "-m", "elf64lriscv", "--no-relax", "-static",
          "-z", "noexecstack", "-e", "_start", obj, driver_obj, "-o", executable],
         report, directory, require_zero=True)
    inventory = inspect_linked_riscv64(executable, ir.exports, tools["readobj"], report, directory)
    payload = executable.read_bytes()
    process, observed = _run([tools["qemu"], executable], report, directory)
    if executable.read_bytes() != payload or emit_program_llvm(core, target=TARGET_RISCV64) != ir:
        raise ValueError("HIA source or native target changed during actual execution")
    return {"name": name, "mode": mode, "input_sha256": core.input_sha256, "core_sha256": core.sha256,
            "llvm_ir_sha256": ir.sha256, "build": build, "driver_sha256": _sha(driver),
            "executable_sha256": sha256(payload).hexdigest(), "binary_inventory": inventory,
            "run_process": process, "execution": {"returncode": observed.returncode,
                "stdout": observed.stdout, "stderr": observed.stderr}}


def chain_expected_stdout():
    lines = []
    for index, (name, n, mode, fail) in enumerate(CHAIN_CASES):
        expected = independent_spec(name, n, mode, fail)
        values = [index, expected["result"], expected["attempts"], expected["allocations"],
                  expected["frees"], 0, expected["null_frees"]]
        lines.append("HIA_RISCV64 chain " + " ".join(map(str, values)) + "\n")
    return "".join(lines)


def _chain_driver(programs, *, trap=False):
    result = [RUNTIME.read_text()]
    for program in programs.values():
        exports = emit_program_llvm(program, target=TARGET_RISCV64).exports
        for fn in program.as_dict()["functions"]:
            if fn["name"] in exports:
                result.append("extern " + C_TYPES[fn["returns"][0]] + " " + fn["name"] + "(" +
                              (", ".join(C_TYPES[p["type"]] for p in fn["params"]) or "void") + ");")
    result += ["__attribute__((noreturn)) void _start(void) {",
               "    if (!memory_primitives_ok()) hepta_exit(39);"]
    if trap:
        result += ["    (void)chain_empty_head();", "    write_resources();", "    hepta_exit(99);", "}"]
        return "\n".join(result) + "\n"
    for index, (name, n, mode, fail) in enumerate(CHAIN_CASES):
        expected = independent_spec(name, n, mode, fail)
        arguments = "" if name == "chain_empty_pop" else str(n) + (", " + str(mode) if name == "chain_task" else "")
        result += ["    if (outstanding) {write_resources(); hepta_exit(91);}",
                   "    successful_allocations = releases = denied_allocations = peak_outstanding = null_frees = 0;",
                   f"    failure_countdown = {fail};",
                   f"    hepta_u64 answer{index} = {name}({arguments});",
                   f"    hepta_u64 row{index}[] = {{{index}, answer{index}, successful_allocations + denied_allocations, successful_allocations, releases, outstanding, null_frees}};",
                   f'    write_values("HIA_RISCV64 chain ", row{index}, 7);',
                   f"    if (answer{index} != {expected['result']}ULL) hepta_exit(41);",
                   f"    if (successful_allocations + denied_allocations != {expected['attempts']} || successful_allocations != {expected['allocations']} || releases != {expected['frees']} || outstanding || null_frees) hepta_exit(92);"]
    result += ["    hepta_exit(0);", "}"]
    return "\n".join(result) + "\n"


def _recursive_qualification(report, directory, tools):
    programs = load_examples()
    result = {"cases": [], "objects": [], "native": [], "negative_controls": []}
    report["recursive"] = result  # Preserve partial observations if a later step fails.
    folder = directory / "recursive_objects"
    folder.mkdir()
    objects, exports = [], set()
    for name, core in programs.items():
        _write(folder / (name + ".json"), core.as_dict())
        ir = emit_program_llvm(core, target=TARGET_RISCV64)
        (folder / (name + ".ll")).write_text(ir.text)
        obj = folder / (name + ".o")
        build = compile_program_llvm(ir, program=core, output=obj, clang=tools["clang"], kind="object")
        symbols = inspect_object_symbols(obj.read_bytes(), "ELF64", 243)
        if symbols["defined"] != frozenset(ir.exports) or exports.intersection(ir.exports):
            raise ValueError("recursive target export inventory differs")
        objects.append(obj)
        exports.update(ir.exports)
        result["objects"].append({"name": name, "input_sha256": core.input_sha256,
                                  "core_sha256": core.sha256, "llvm_ir_sha256": ir.sha256, "build": build})
    for name, n, mode, fail in CHAIN_CASES:
        core = programs["composite_v2" if name in {"chain_task", "chain_stored_loan"} else "core_v7"]
        arguments = [] if name == "chain_empty_pop" else [n, mode] if name == "chain_task" else [n]
        observed = execute_program(core, name, arguments, allocation_fail_at=fail or None)
        expected = independent_spec(name, n, mode, fail)
        if vm_ledger(observed) != expected:
            raise ValueError("recursive target VM disagrees with arithmetic/resource specification")
        result["cases"].append({"function": name, "arguments": arguments, "failure": fail,
                                "expected": expected, "vm": observed})
    try:
        execute_program(programs["core_v7"], "chain_empty_head", [])
    except HIAProgramTrap as error:
        if error.code != "bounds":
            raise
        result["empty_head_vm"] = error.report
    else:
        raise ValueError("recursive empty-head VM trap did not occur")
    for name, trap, expected_code, expected_text in (
            ("recursive", False, 0, chain_expected_stdout()), ("recursive_empty_head", True, 134, "")):
        folder = directory / name
        folder.mkdir()
        driver, driver_obj, executable = folder / "driver.c", folder / "driver.o", folder / "program.elf"
        driver.write_text(_chain_driver(programs, trap=trap))
        _run([tools["clang"], "--target=" + TARGET_RISCV64, "-march=rv64gc", "-mabi=lp64d", "-mno-relax",
              "-x", "c", "-std=c11", "-ffreestanding", "-nostdinc", "-fno-builtin", "-fno-pic",
              "-fno-stack-protector", "-O2", "-Wall", "-Wextra", "-Werror", "-c", driver, "-o", driver_obj],
             report, directory, require_zero=True)
        symbols = inspect_object_symbols(driver_obj.read_bytes(), "ELF64", 243)
        needed = {"chain_empty_head"} if trap else {case[0] for case in CHAIN_CASES}
        if symbols["defined"] != frozenset(CHAIN_RUNTIME_EXPORTS) or symbols["undefined"] != frozenset(needed):
            raise ValueError("recursive C caller/runtime bidirectional interface differs")
        _run([tools["linker"], "-flavor", "gnu", "-m", "elf64lriscv", "--no-relax", "-static",
              "-z", "noexecstack", "-e", "_start", *objects, driver_obj, "-o", executable],
             report, directory, require_zero=True)
        inventory = inspect_linked_riscv64(executable, exports, tools["readobj"], report, directory,
                                          runtime_exports=CHAIN_RUNTIME_EXPORTS)
        before = executable.read_bytes()
        process, observed = _run([tools["qemu"], executable], report, directory)
        row = {"name": name, "driver_sha256": _sha(driver), "executable_sha256": sha256(before).hexdigest(),
               "binary_inventory": inventory, "run_process": process,
               "execution": {"returncode": observed.returncode, "stdout": observed.stdout, "stderr": observed.stderr}}
        result["negative_controls" if trap else "native"].append(row)
        if executable.read_bytes() != before or row["execution"] != {
                "returncode": expected_code, "stdout": expected_text, "stderr": ""}:
            raise ValueError("recursive RV64 target execution differs")


def _inventory(directory):
    return {str(p.relative_to(directory)): {"bytes": p.stat().st_size, "sha256": _sha(p)}
            for p in sorted(directory.rglob("*")) if p.is_file() and p.name != "qualification.json"}


def validate_qualification(report):
    if (report.get("schema") != "hepta.hia.riscv64-qualification.v1" or report.get("ok") is not True
            or report.get("counts") != expected_counts() or report.get("source_bindings") != _source_bindings()):
        raise ValueError("RV64 qualification scope, count or source mismatch")
    directory = Path(report["workdir"])
    if report["artifacts"] != _inventory(directory):
        raise ValueError("retained target artifact or log changed")
    if len(report["native"]) != 2 or len(report["negative_controls"]) != expected_counts()["actual_negative_executions"]:
        raise ValueError("native execution denominator differs")
    for tool in report["tools"].values():
        if digest_executable(Path(tool["path"])) != tool["sha256"]:
            raise ValueError("target tool identity changed")
    rows = [*( (row, 0, expected_stdout()) for row in report["native"] )]
    scalar = len(scalar_cases()) + len(STACK_CASES) + len(RAW_CASES)
    negative_outputs = ["", "", f"HIA_RISCV64 scalar {scalar}\nHIA_RISCV64 case 0 11\nHIA_RISCV64 resources 2 0 2 0 2\n", "", "", ""]
    for row, code, output in zip(report["negative_controls"], (41, 42, 91, 134, 134, 134), negative_outputs):
        rows.append((row, code, output))
    recursive = report["recursive"]
    if (len(recursive["cases"]) != len(CHAIN_CASES) or len(recursive["native"]) != 1
            or len(recursive["negative_controls"]) != 1):
        raise ValueError("recursive target execution denominator differs")
    for row, (name, n, mode, fail) in zip(recursive["cases"], CHAIN_CASES):
        expected = independent_spec(name, n, mode, fail)
        arguments = [] if name == "chain_empty_pop" else [n, mode] if name == "chain_task" else [n]
        if (row["function"] != name or row["arguments"] != arguments or row["failure"] != fail
                or row["expected"] != expected or vm_ledger(row["vm"]) != expected):
            raise ValueError("recursive VM case or resource specification differs")
    if recursive["empty_head_vm"]["error"]["code"] != "bounds":
        raise ValueError("recursive empty-head VM trap differs")
    rows += [(recursive["native"][0], 0, chain_expected_stdout()),
             (recursive["negative_controls"][0], 134, "")]
    for row, code, output in rows:
        process = report["processes"][row["run_process"]]
        actual = {"returncode": process["returncode"], "stdout": Path(process["stdout"]).read_text(),
                  "stderr": Path(process["stderr"]).read_text()}
        if (actual != row["execution"] or actual != {"returncode": code, "stdout": output, "stderr": ""}
                or process["argv"] != [report["tools"]["qemu"]["path"], str(directory / row["name"] / "program.elf")]):
            raise ValueError("native target execution or negative-control observation differs")
    if report["claims"]["physical_hardware_executed"] is not False:
        raise ValueError("QEMU must not be reported as physical hardware")
    return {"ok": True, "counts": expected_counts(), "scope": "record/artifact identity, not new execution"}


def qualify(*, directory, clang, linker, qemu, readobj):
    directory = Path(directory).resolve()
    directory.mkdir()
    tools = {key: str(Path(value).resolve()) for key, value in
             {"clang": clang, "linker": linker, "qemu": qemu, "readobj": readobj}.items()}
    report = {"schema": "hepta.hia.riscv64-qualification.v1", "ok": False, "status": "rejected",
              "target": TARGET_RISCV64, "abi": "RV64GC LP64D integer slice", "workdir": str(directory),
              "processes": [], "reference": [], "native": [], "negative_controls": [],
              "claims": {"physical_hardware_executed": False, "rv32_supported": False,
                         "general_foreign_calls_supported": False, "general_allocator_qualified": False,
                         "whole_language_soundness_proved": False, "backend_refinement_proved": False},
              "limits": ["QEMU Linux userspace, not a board, kernel or device protocol",
                         "C calls scalar HIA exports; HIA calls only the existing explicit C runtime imports",
                         "64 independent 4096-byte allocator slots; no concurrency or production claim",
                         "traps abort without a promise of resource cleanup"],
              "abi_reference": "https://github.com/riscv-non-isa/riscv-elf-psabi-doc/blob/master/riscv-cc.adoc"}
    try:
        report["source_bindings"] = _source_bindings()
        report["tools"] = {key: {"path": path, "sha256": digest_executable(Path(path))} for key, path in tools.items()}
        for key, flags in (("clang", ["--version"]), ("linker", ["-flavor", "gnu", "--version"]),
                           ("readobj", ["--version"]), ("qemu", ["--version"])):
            _, version = _run([tools[key], *flags], report, directory, require_zero=True)
            report["tools"][key]["version"] = version.stdout.splitlines()[0]
        original = program_document()
        _write(directory / "input.json", original)
        core = verify_program(original)
        normalized = verify_program(core.canonical_bytes)
        _write(directory / "normalized.json", normalized.as_dict())
        for candidate in (core, normalized):
            for typ, value in scalar_cases():
                observed = execute_program(candidate, "abi_" + typ, [value])
                if observed["result"] != value:
                    raise ValueError("scalar reference differs")
                report["reference"].append(observed)
            for args in STACK_CASES:
                observed = execute_program(candidate, "abi_stack12", args)
                if observed["result"] != stack_oracle(args):
                    raise ValueError("stack-call reference differs")
                report["reference"].append(observed)
            for args, failure, expected in COMPOSITE_BULK_CASES:
                observed = execute_program(candidate, "aggregate_bulk", list(args), allocation_fail_at=failure)
                if (byte_oracle(args, failure) != expected or observed["result"] != expected
                        or observed["resources"]["live_owners"] or observed["resources"]["live_local_loans"]):
                    raise ValueError("resource reference differs")
                report["reference"].append(observed)
        for label, candidate in (("composite", core), ("normalized", normalized)):
            row = _build_run(candidate, label, report, directory, tools)
            report["native"].append(row)
            if row["execution"] != {"returncode": 0, "stdout": expected_stdout(), "stderr": ""}:
                raise ValueError("positive RV64 target result differs")
        controls = [("wrong_value", verify_program(program_document(wrong_value=True)), "positive", False, 41),
                    ("wrong_return_extension", core, "wrong_return_extension", False, 42),
                    ("removed_free", core, "positive", True, 91)]
        for mode, args in COMPOSITE_BULK_TRAPS.items():
            try:
                execute_program(core, "aggregate_bulk", list(args))
            except HIAProgramTrap as error:
                if error.code != "bounds":
                    raise
            else:
                raise ValueError("expected reference bounds trap did not occur")
            controls.append((mode, core, mode, False, 134))
        for name, candidate, mode, remove_free, code in controls:
            row = _build_run(candidate, name, report, directory, tools, mode=mode, remove_free=remove_free)
            report["negative_controls"].append(row)
            if row["execution"]["returncode"] != code:
                raise ValueError("native negative control did not detect " + name)
        _recursive_qualification(report, directory, tools)
        if report["source_bindings"] != _source_bindings():
            raise ValueError("compiler or target qualification changed during execution")
        if len(report["reference"]) != expected_counts()["vm_results"]:
            raise ValueError("VM observation denominator differs")
        report.update(ok=True, status="finite_rv64gc_lp64d_qemu_abi_and_resource_execution_passed", counts=expected_counts())
        report["artifacts"] = _inventory(directory)
        validate_qualification(report)
    except Exception as error:
        report.update(ok=False, status="rejected")
        report["error"] = {"type": type(error).__name__, "message": str(error), "traceback": traceback.format_exc()[-6000:]}
        report["artifacts"] = _inventory(directory)
    report["record_sha256"] = sha256(json.dumps(report, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    _write(directory / "qualification.json", report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-directory", required=True)
    parser.add_argument("--clang", default="/usr/lib/llvm-20/bin/clang")
    parser.add_argument("--linker", default="/usr/lib/llvm-20/bin/ld.lld")
    parser.add_argument("--readobj", default="/usr/lib/llvm-20/bin/llvm-readobj")
    parser.add_argument("--qemu-riscv64", default="/usr/bin/qemu-riscv64-static")
    args = parser.parse_args()
    report = qualify(directory=args.output_directory, clang=args.clang, linker=args.linker,
                     qemu=args.qemu_riscv64, readobj=args.readobj)
    print(json.dumps({key: report.get(key) for key in ("ok", "status", "counts", "error", "record_sha256")}, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
