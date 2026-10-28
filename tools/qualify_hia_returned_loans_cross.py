#!/usr/bin/env python3
"""Execute a fixed v8 returned-loan corpus on AArch64 and RV64 QEMU.

The existing Core verifier, LLVM emitter/compiler, finite RV64 allocator and
ELF inspectors remain the implementation path. This qualifies the declared
scalar public boundary and finite internal loan corpus, not a foreign-loan ABI,
physical hardware, a general allocator, or a whole-language refinement proof.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import stat
import sys
import time
import traceback

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hepta.clang_capture import run_bounded
from hepta.hia_program import HIAProgramRejected, verify_program
from hepta.hia_program_llvm import (TARGET_AARCH64, TARGET_RISCV64,
                                   compile_program_llvm, emit_program_llvm)
from hepta.hia_program_runtime import HIAProgramTrap, execute_program
from hepta.native_tool_identity import digest_executable
from hepta.object_symbols import inspect_object_symbols
from hepta.owned_aarch64_link import inspect_synthetic_aarch64_elf
from tools.qualify_hia_riscv64 import inspect_linked_riscv64

FIXTURE = ROOT / "examples/hia_program/returned_loans_cross_target_v8.hia"
RUNTIME = ROOT / "examples/hia_program/finite_riscv64_runtime.c"
SCHEMA = "hepta.hia.returned-loans-cross-qualification.v1"
STATUS = "finite_v8_aarch64_and_rv64_returned_loans_executed"
TARGETS = {"aarch64": TARGET_AARCH64, "riscv64": TARGET_RISCV64}
MACHINES = {"aarch64": 183, "riscv64": 243}
RUNTIME_EXPORTS = {"malloc", "calloc", "free", "memset", "memcpy", "memmove", "abort", "_start"}
RESOURCE_FIELDS = ("attempts", "allocations", "frees", "outstanding", "live_bytes", "peak_bytes", "null_frees")
C_TYPES = {"u8": "hepta_u8", "usize": "hepta_size"}
CLAIMS = {"physical_hardware_executed": False, "general_foreign_lifetimes_qualified": False,
          "native_loan_objects_instrumented": False, "general_allocator_qualified": False,
          "performance_superiority_established": False, "backend_refinement_proved": False,
          "whole_language_soundness_proved": False}


def _same(left, right):
    """JSON type-sensitive equality: a boolean never stands for a counter."""
    encode = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return encode(left) == encode(right)


def _sha(path):
    return sha256(Path(path).read_bytes()).hexdigest()


def _write(path, value):
    Path(path).write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")


def corpus_document(*, wrong_value=False):
    document = json.loads(FIXTURE.read_bytes())
    if wrong_value:
        fn = next(row for row in document["functions"] if row["name"] == "loan_entry_mut_forward")
        constant = next(row for row in fn["blocks"][0]["ops"]
                        if row["op"] == "const" and row["out"][0]["name"] == "delta")
        if constant["attrs"]["value"] != 5:
            raise ValueError("wrong-value control requires the original increment")
        constant["attrs"]["value"] = 6
    return document


def case_plan():
    result = []

    def add(family, function, arguments, failure=0):
        result.append({"index": len(result), "family": family, "function": function,
                       "arguments": list(arguments), "failure": failure})

    for mode in ("read", "mut"):
        for form in ("forward", "child", "cfg", "recursive"):
            for length in (1, 3, 17):
                for byte in (0, 17, 250, 255):
                    add("loan_" + mode, "loan_entry_" + mode + "_" + form, (length, byte))
    for form in ("forward", "children", "mixed"):
        for byte in (0, 37, 128, 255):
            add("shared", "multi_" + form + "_shared", (byte,))
    add("swapped", "origin_swapped", ())
    add("fallible", "allocation_fallible_entry", ())
    add("fallible", "allocation_fallible_entry", (), 2)
    for mode in ("read", "mut"):
        for form in ("forward", "child"):
            for byte in (0, 37, 250, 255):
                add("chain_" + mode + "_" + form, "head_chain_" + mode + "_" + form, (byte,))
    add("partial", "partial_shared", (37,))
    return result


def trap_plan():
    rows = (
        ("returned_bounds", "bounds_entry_read_child", [1, 37], 0, "bounds"),
        ("partial_result_allocation", "partial_shared", [37], 2, "allocation"),
        ("initial_allocation", "allocation_fallible_entry", [], 1, "allocation"),
        ("failed_chain_node", "head_chain_read_child", [37], 2, "bounds"),
    )
    return [{"index": index, "family": name, "function": fn, "arguments": args,
             "failure": fail, "trap_code": code}
            for index, (name, fn, args, fail, code) in enumerate(rows)]


def independent_spec(case):
    """Arithmetic/allocator specification independent of Core and VM results."""
    family, arguments, failure = case["family"], case["arguments"], case["failure"]
    attempts = allocations = frees = 1
    peak = 1
    live = 0
    if family in {"loan_read", "loan_mut"}:
        peak = arguments[0]
        answer = (arguments[1] + (5 if family == "loan_mut" else 0)) % 256
    elif family in {"shared", "partial"}:
        answer = 2 * arguments[0] % 256
        if family == "partial":
            attempts = allocations = frees = peak = 2
    elif family == "swapped":
        answer = 28
        attempts = allocations = frees = peak = 2
    elif family == "fallible":
        attempts = 2
        allocations = frees = peak = 1 if failure == 2 else 2
        answer = 0 if failure == 2 else 1
    elif family.startswith("chain_"):
        _, mode, form = family.split("_")
        answer = (arguments[0] + (5 if mode == "mut" else 0)) % 256
        answer = answer * (2 if form == "forward" else 1) % 256
        attempts = allocations = frees = 2
        peak = 25
    elif family == "returned_bounds":
        answer, frees, live = None, 0, 1
    elif family == "partial_result_allocation":
        answer, attempts, allocations, frees, live = None, 2, 1, 0, 1
    elif family == "initial_allocation":
        answer, attempts, allocations, frees, live, peak = None, 1, 0, 0, 0, 0
    elif family == "failed_chain_node":
        answer, attempts, allocations, frees, live, peak = None, 2, 1, 1, 0, 1
    else:
        raise ValueError("unknown returned-loan observation family")
    return {"result": answer, "attempts": attempts, "allocations": allocations,
            "frees": frees, "outstanding": allocations - frees, "live_bytes": live,
            "peak_bytes": peak, "null_frees": 0}


def vm_projection(report):
    resource = report["resources"]
    return {"result": report.get("result"), "attempts": resource["allocation_attempts"],
            "allocations": resource["allocations"], "frees": resource["frees"],
            "outstanding": resource["allocations"] - resource["frees"],
            "live_bytes": resource["live_bytes"], "peak_bytes": resource["peak_bytes"]}


def _line(case, expected):
    if case.get("trap_code"):
        prefix = "HIA_V8 trap "
        values = [case["index"], *(expected[key] for key in RESOURCE_FIELDS)]
    else:
        prefix = "HIA_V8 case "
        values = [case["index"], expected["result"], *(expected[key] for key in RESOURCE_FIELDS)]
    return prefix + " ".join(map(str, values)) + "\n"


def expected_counts():
    return {"targets": 2, "positive_binaries": 2, "positive_calls_per_target": len(case_plan()),
            "positive_native_calls": 2 * len(case_plan()), "vm_returned_results": len(case_plan()),
            "vm_trap_results": len(trap_plan()), "trap_executions_per_target": len(trap_plan()),
            "mutation_executions_per_target": 2, "negative_native_executions": 2 * (len(trap_plan()) + 2),
            "all_native_execution_processes": 2 * (1 + len(trap_plan()) + 2),
            "static_rejections": 5,
            "native_resource_fields_per_row": len(RESOURCE_FIELDS), "vm_comparable_resource_fields": 6}


def _source_bindings():
    # The imported RV64 inspector has further tools imports. Bind the complete
    # local Python tool/compiler surface, the actual corpus and runtime bytes.
    paths = [*sorted((ROOT / "hepta").glob("*.py")), *sorted((ROOT / "tools").glob("*.py")), FIXTURE, RUNTIME]
    return {str(path.relative_to(ROOT)): _sha(path) for path in paths}


def _inventory(directory):
    result = {}
    for path in sorted(directory.rglob("*")):
        if path.name == "qualification.json":
            continue
        mode = path.lstat().st_mode
        if stat.S_ISDIR(mode):
            continue
        if not stat.S_ISREG(mode):
            raise ValueError("retained evidence must contain only regular files")
        result[str(path.relative_to(directory))] = {
            "bytes": path.stat().st_size, "sha256": _sha(path), "mode": stat.S_IMODE(mode)}
    return result


def _run(argv, report, directory, *, require_zero=False):
    argv = [str(value) for value in argv]
    index = len(report["processes"])
    started = time.monotonic()
    observed = run_bounded(argv, timeout=60, stdout_limit=4 * 1024 * 1024, stderr_limit=1024 * 1024)
    record = {"argv": argv, "returncode": observed.returncode, "seconds": time.monotonic() - started}
    for stream in ("stdout", "stderr"):
        path = directory / f"process-{index:03d}.{stream}"
        path.write_text(getattr(observed, stream))
        record[stream] = str(path)
        record[stream + "_sha256"] = _sha(path)
    report["processes"].append(record)
    if require_zero and observed.returncode:
        raise ValueError("target command failed: " + observed.stderr[-3000:])
    return index, observed


def _compiler_flags(label):
    return ["-march=rv64gc", "-mabi=lp64d", "-mno-relax"] if label == "riscv64" else []


def _object(core, label, variant, report, directory, tools):
    folder = directory / label / ("object_" + variant)
    folder.mkdir(parents=True)
    _write(folder / "core.json", core.as_dict())
    ir = emit_program_llvm(core, target=TARGETS[label])
    text = ir.text
    if variant == "removed_free":
        text = "\n".join(line for line in text.splitlines() if "call void @free(" not in line) + "\n"
        if text == ir.text:
            raise ValueError("native missing-free mutation changed no instructions")
    source = folder / "program.ll"
    source.write_text(text)
    obj = folder / "program.o"
    flags = ["--target=" + TARGETS[label], "-x", "ir", "-O3", "-fPIC", "-c"]
    if label == "riscv64":
        flags += ["-march=rv64gc", "-mabi=lp64d"]
    if variant == "removed_free":
        process, _ = _run([tools["clang"], *flags, source, "-o", obj], report, directory, require_zero=True)
        build = {"qualified_hia_artifact": False, "reason": "deliberately removed native free calls",
                 "artifact_sha256": _sha(obj)}
        byte_equal = False
    else:
        build = compile_program_llvm(ir, program=core, output=obj, clang=tools["clang"], kind="object")
        # Keep a complete actual compiler argv/stdout/stderr for the retained
        # input. Require the replay to reproduce the canonical published object.
        replay = folder / "replayed.o"
        process, _ = _run([tools["clang"], *flags, source, "-o", replay], report, directory, require_zero=True)
        byte_equal = replay.read_bytes() == obj.read_bytes()
        if not byte_equal:
            raise ValueError("retained LLVM command did not reproduce the canonical object bytes")
    symbols = inspect_object_symbols(obj.read_bytes(), "ELF64", MACHINES[label])
    if symbols["defined"] != frozenset(ir.exports) or not symbols["undefined"] <= RUNTIME_EXPORTS - {"_start"}:
        raise ValueError("returned-loan object does not have the exact closed scalar ABI")
    return {"variant": variant, "path": str(obj), "target": TARGETS[label], "core_sha256": core.sha256,
            "llvm_ir_sha256": _sha(source), "artifact_sha256": _sha(obj), "build": build,
            "exports": list(ir.exports), "replay_process": process, "replay_byte_equal": byte_equal}


def _driver(core, cases):
    functions = {row["name"]: row for row in core.as_dict()["functions"]}
    text = ["#define HEPTA_RETURNED_LOAN_OBSERVER 1", RUNTIME.read_text(),
            "static hepta_u64 active_case;",
            "static void report_abort(void) {",
            "    hepta_u64 values[] = {active_case, successful_allocations + denied_allocations,",
            "        successful_allocations, releases, outstanding, live_bytes, peak_bytes, null_frees};",
            '    write_values("HIA_V8 trap ", values, 8);', "}"]
    for name in sorted({case["function"] for case in cases}):
        fn = functions[name]
        if fn["returns"] != ["u8"] or name not in core.as_dict()["exports"]:
            raise ValueError("cross-target fixture must use a scalar u8 public wrapper")
        params = ", ".join(C_TYPES[p["type"]] for p in fn["params"]) or "void"
        text.append("extern hepta_u8 " + name + "(" + params + ");")
    text += ["__attribute__((noreturn)) void _start(void) {",
             "    if (!memory_primitives_ok()) hepta_exit(39);"]
    for ordinal, case in enumerate(cases):
        expected = independent_spec(case)
        expression = case["function"] + "(" + ", ".join(str(x) for x in case["arguments"]) + ")"
        text += ["    if (outstanding || live_bytes) {write_resources(); hepta_exit(91);}",
                 "    successful_allocations = releases = denied_allocations = peak_outstanding = null_frees = 0;",
                 "    live_bytes = peak_bytes = 0;",
                 f"    active_case = {case['index']}; failure_countdown = {case['failure']};"]
        if case.get("trap_code"):
            text += ["    (void)" + expression + ";", "    hepta_exit(99);"]
            continue
        text += [f"    hepta_u64 answer{ordinal} = {expression};",
                 f"    hepta_u64 row{ordinal}[] = {{active_case, answer{ordinal}, successful_allocations + denied_allocations,",
                 "        successful_allocations, releases, outstanding, live_bytes, peak_bytes, null_frees};",
                 f'    write_values("HIA_V8 case ", row{ordinal}, 9);',
                 f"    if (answer{ordinal} != {expected['result']}) hepta_exit(41);"]
        fields = ("successful_allocations + denied_allocations", "successful_allocations", "releases",
                  "outstanding", "live_bytes", "peak_bytes", "null_frees")
        conditions = [f"({field}) != {expected[key]}" for field, key in zip(fields, RESOURCE_FIELDS)]
        text.append("    if (" + " || ".join(conditions) + ") hepta_exit(92);")
    text += ["    hepta_exit(0);", "}"]
    return "\n".join(text) + "\n"


def _execution_plan():
    wrong = next(row for row in case_plan() if row["function"] == "loan_entry_mut_forward"
                 and row["arguments"] == [1, 17])
    missing_free = next(row for row in case_plan() if row["function"] == "loan_entry_read_forward"
                        and row["arguments"] == [1, 17])
    return [("positive", "positive", case_plan(), 0),
            *((case["family"], "positive", [case], 134) for case in trap_plan()),
            ("wrong_value", "wrong_value", [wrong], 41),
            ("removed_free", "removed_free", [missing_free], 92)]


def _expected_execution(name, cases, code):
    values = []
    for case in cases:
        expected = independent_spec(case)
        if name == "wrong_value":
            expected["result"] = (expected["result"] + 1) % 256
        elif name == "removed_free":
            expected.update(frees=0, outstanding=1, live_bytes=case["arguments"][0])
        values.append(_line(case, expected))
    return {"returncode": code, "stdout": "".join(values), "stderr": ""}


def _build_execute(core, obj, label, name, cases, report, directory, tools):
    folder = directory / label / name
    folder.mkdir()
    driver, driver_obj, executable = folder / "driver.c", folder / "driver.o", folder / "program.elf"
    driver.write_text(_driver(core, cases))
    compile_index, _ = _run([tools["clang"], "--target=" + TARGETS[label], *_compiler_flags(label),
                            "-x", "c", "-std=c11", "-ffreestanding", "-nostdinc", "-fno-builtin",
                            "-fno-pic", "-fno-stack-protector", "-O2", "-Wall", "-Wextra", "-Werror",
                            "-c", driver, "-o", driver_obj], report, directory, require_zero=True)
    symbols = inspect_object_symbols(driver_obj.read_bytes(), "ELF64", MACHINES[label])
    if (symbols["defined"] != frozenset(RUNTIME_EXPORTS)
            or symbols["undefined"] != frozenset(case["function"] for case in cases)):
        raise ValueError("C driver/runtime does not expose the exact bidirectional interface")
    flags = ["-m", "elf64lriscv", "--no-relax"] if label == "riscv64" else ["-m", "aarch64linux"]
    link_index, _ = _run([tools["linker"], "-flavor", "gnu", *flags, "-static", "-z", "noexecstack",
                         "-e", "_start", obj["path"], driver_obj, "-o", executable],
                        report, directory, require_zero=True)
    if label == "riscv64":
        inventory = inspect_linked_riscv64(executable, obj["exports"], tools["readobj"], report, directory,
                                          runtime_exports=RUNTIME_EXPORTS)
    else:
        inventory = inspect_synthetic_aarch64_elf(executable.read_bytes(), tuple(obj["exports"]) + ("calloc",))
    payload = executable.read_bytes()
    process, observed = _run([tools["qemu_" + label], executable], report, directory)
    if executable.read_bytes() != payload:
        raise ValueError("target executable changed during execution")
    return {"name": name, "object_variant": obj["variant"], "target": TARGETS[label], "cases": cases,
            "executable_sha256": sha256(payload).hexdigest(), "driver_sha256": _sha(driver),
            "binary_inventory": inventory, "compile_process": compile_index, "link_process": link_index,
            "run_process": process, "execution": {"returncode": observed.returncode,
                "stdout": observed.stdout, "stderr": observed.stderr}}


def _rejection_documents():
    for kind in ("wrong_origin", "mutable_alias", "parent_end", "public_loan", "legacy_schema"):
        doc = corpus_document()
        by_name = {fn["name"]: fn for fn in doc["functions"]}
        if kind == "wrong_origin":
            by_name["origin_swap_sources"]["return_loans"] = ["left", "right"]
        elif kind == "mutable_alias":
            call = next(op for op in by_name["origin_swapped"]["blocks"][0]["ops"] if op["op"] == "call")
            call["args"] = ["left", "left"]
        elif kind == "parent_end":
            operations = by_name["loan_entry_mut_forward"]["blocks"][0]["ops"]
            index = next(n for n, op in enumerate(operations) if op["op"] == "call") + 1
            operations.insert(index, {"op": "loan.end", "args": ["parent"], "out": [], "attrs": {}})
        elif kind == "public_loan":
            doc["exports"].append("loan_return_read_forward")
        else:
            doc["schema"] = "hepta.hia.program.v7"
        yield kind, doc


def validate_qualification(report):
    if (report.get("schema") != SCHEMA or report.get("ok") is not True or report.get("status") != STATUS
            or not _same(report.get("counts"), expected_counts())
            or not _same(report.get("source_bindings"), _source_bindings())):
        raise ValueError("returned-loan qualification scope, count or source differs")
    directory = Path(report["workdir"])
    if not _same(report["artifacts"], _inventory(directory)):
        raise ValueError("retained returned-loan artifact or raw log changed")
    for tool in report["tools"].values():
        if digest_executable(Path(tool["path"])) != tool["sha256"]:
            raise ValueError("cross-target tool changed")
    if set(report["native"]) != set(TARGETS):
        raise ValueError("missing target observations")
    positive = case_plan()
    traps = trap_plan()
    if len(report["reference"]) != len(positive) + len(traps):
        raise ValueError("VM observation denominator differs")
    original = verify_program(corpus_document())
    for row, case in zip(report["reference"], positive + traps):
        expected = independent_spec(case)
        comparable = {key: value for key, value in expected.items() if key != "null_frees"}
        if (not _same(row["case"], case) or not _same(row["expected"], expected)
                or not _same(vm_projection(row["vm"]), comparable)
                or row["vm"]["function"] != case["function"]
                or row["vm"]["status"] != ("trapped" if case.get("trap_code") else "returned")
                or row["vm"]["program_sha256"] != original.sha256):
            raise ValueError("VM value/resource observation differs from fixed independent oracle")
        if case.get("trap_code") and row["vm"]["error"]["code"] != case["trap_code"]:
            raise ValueError("VM trap code differs")
    if [row["name"] for row in report["rejections"]] != [name for name, _ in _rejection_documents()]:
        raise ValueError("static rejection denominator differs")
    for row, (name, doc) in zip(report["rejections"], _rejection_documents()):
        try:
            verify_program(doc)
        except HIAProgramRejected as error:
            if row != {"name": name, "diagnostic": str(error)}:
                raise ValueError("rejection diagnostic differs")
        else:
            raise ValueError("illegal returned-loan input was admitted")
    for label in TARGETS:
        target = report["native"][label]
        if set(target["objects"]) != {"positive", "wrong_value", "removed_free"}:
            raise ValueError("native object denominator differs")
        for variant, record in target["objects"].items():
            core = verify_program(corpus_document(wrong_value=variant == "wrong_value"))
            ir = emit_program_llvm(core, target=TARGETS[label])
            text = ir.text if variant != "removed_free" else "\n".join(
                line for line in ir.text.splitlines() if "call void @free(" not in line) + "\n"
            folder = directory / label / ("object_" + variant)
            symbols = inspect_object_symbols((folder / "program.o").read_bytes(), "ELF64", MACHINES[label])
            flags = ["--target=" + TARGETS[label], "-x", "ir", "-O3", "-fPIC", "-c"]
            if label == "riscv64":
                flags += ["-march=rv64gc", "-mabi=lp64d"]
            replay = report["processes"][record["replay_process"]]
            output = folder / ("program.o" if variant == "removed_free" else "replayed.o")
            if (record["core_sha256"] != core.sha256 or record["target"] != TARGETS[label]
                    or record["path"] != str(folder / "program.o") or record["exports"] != list(ir.exports)
                    or (folder / "program.ll").read_text() != text
                    or record["llvm_ir_sha256"] != _sha(folder / "program.ll")
                    or record["artifact_sha256"] != _sha(folder / "program.o")
                    or symbols["defined"] != frozenset(ir.exports)
                    or not symbols["undefined"] <= RUNTIME_EXPORTS - {"_start"}
                    or replay["returncode"] != 0
                    or replay["argv"] != [report["tools"]["clang"]["path"], *flags,
                                          str(folder / "program.ll"), "-o", str(output)]
                    or not _same(json.loads((folder / "core.json").read_bytes()), core.as_dict())):
                raise ValueError("native object or emitted Core binding differs")
            if variant == "removed_free":
                if record["build"].get("qualified_hia_artifact") is not False or record["replay_byte_equal"] is not False:
                    raise ValueError("mutated native artifact cannot carry Core qualification")
            elif (record["replay_byte_equal"] is not True
                  or (folder / "program.o").read_bytes() != (folder / "replayed.o").read_bytes()
                  or record["build"].get("ok") is not True
                  or record["build"]["status"] != "native_compiled_not_executed"
                  or record["build"]["profile"] != ir.profile or record["build"]["target"] != ir.target
                  or record["build"]["llvm_ir_sha256"] != ir.sha256
                  or record["build"]["artifact_sha256"] != record["artifact_sha256"]
                  or record["build"]["core_sha256"] != core.sha256):
                raise ValueError("canonical object and retained compiler replay differ")
        plan = _execution_plan()
        if len(target["executions"]) != len(plan):
            raise ValueError("native execution denominator differs")
        for row, (name, variant, cases, code) in zip(target["executions"], plan):
            process = report["processes"][row["run_process"]]
            executable = directory / label / name / "program.elf"
            driver = directory / label / name / "driver.c"
            compiled = report["processes"][row["compile_process"]]
            linked = report["processes"][row["link_process"]]
            driver_obj = driver.with_suffix(".o")
            compile_argv = [report["tools"]["clang"]["path"], "--target=" + TARGETS[label], *_compiler_flags(label),
                            "-x", "c", "-std=c11", "-ffreestanding", "-nostdinc", "-fno-builtin",
                            "-fno-pic", "-fno-stack-protector", "-O2", "-Wall", "-Wextra", "-Werror",
                            "-c", str(driver), "-o", str(driver_obj)]
            link_flags = ["-m", "elf64lriscv", "--no-relax"] if label == "riscv64" else ["-m", "aarch64linux"]
            link_argv = [report["tools"]["linker"]["path"], "-flavor", "gnu", *link_flags, "-static", "-z", "noexecstack",
                         "-e", "_start", target["objects"][variant]["path"], str(driver_obj), "-o", str(executable)]
            actual = {"returncode": process["returncode"], "stdout": Path(process["stdout"]).read_text(),
                      "stderr": Path(process["stderr"]).read_text()}
            if (row["name"] != name or row["object_variant"] != variant
                    or row["target"] != TARGETS[label] or not _same(row["cases"], cases)
                    or not _same(row["execution"], actual)
                    or not _same(actual, _expected_execution(name, cases, code))
                    or process["argv"] != [report["tools"]["qemu_" + label]["path"], str(executable)]
                    or compiled["argv"] != compile_argv or compiled["returncode"] != 0
                    or linked["argv"] != link_argv or linked["returncode"] != 0
                    or row["executable_sha256"] != _sha(executable) or row["driver_sha256"] != _sha(driver)
                    or driver.read_text() != _driver(original, cases)):
                raise ValueError("native execution, driver or independent observation differs")
            payload = executable.read_bytes()
            inventory = row["binary_inventory"]
            if (inventory["machine"] != MACHINES[label] or inventory["format"] != "ELF64"
                    or inventory["no_unresolved_symbols"] is not True
                    or inventory["external_functions"] != sorted(set(original.as_dict()["exports"]) | RUNTIME_EXPORTS)
                    or inventory["entrypoint"] != int.from_bytes(payload[24:32], "little")
                    or int.from_bytes(payload[18:20], "little") != MACHINES[label]):
                raise ValueError("linked target identity or interface inventory differs")
            if label == "aarch64":
                actual_inventory = inspect_synthetic_aarch64_elf(payload, tuple(original.as_dict()["exports"]) + ("calloc",))
                if not _same(inventory, actual_inventory):
                    raise ValueError("AArch64 executable inventory differs")
            elif inventory["riscv_flags"] != 5 or int.from_bytes(payload[48:52], "little") != 5:
                raise ValueError("RV64 ABI flags differ")
    for process in report["processes"]:
        for stream in ("stdout", "stderr"):
            if _sha(process[stream]) != process[stream + "_sha256"]:
                raise ValueError("native raw process stream changed")
    if not _same(report["claims"], CLAIMS):
        raise ValueError("finite QEMU evidence cannot expand the stated safety/platform claims")
    return {"ok": True, "counts": expected_counts(), "scope": "record/artifact verification; no native reexecution"}


def qualify(*, directory, clang, linker, readobj, qemu_aarch64, qemu_riscv64):
    directory = Path(directory).resolve()
    directory.mkdir(parents=True, exist_ok=False)
    tools = {name: str(Path(value).resolve()) for name, value in {
        "clang": clang, "linker": linker, "readobj": readobj,
        "qemu_aarch64": qemu_aarch64, "qemu_riscv64": qemu_riscv64}.items()}
    report = {"schema": SCHEMA, "ok": False, "status": "rejected", "workdir": str(directory),
              "processes": [], "reference": [], "rejections": [], "native": {},
              "claims": dict(CLAIMS),
              "limits": ["QEMU Linux userspace on little-endian AArch64 LP64 and RV64GC LP64D",
                         "scalar C public exports; loan/multiple-result descriptors remain internal",
                         "64 fixed 4096-byte observer slots; payload byte peaks exclude observer arena/process RSS",
                         "normal/error-value paths clean up; abort reports stopped allocation counters without unwinding",
                         "six resource quantities compare with the VM; native null-free count has its own zero oracle",
                         "compiler receipts retain their original compiled-not-executed status; this is separate finite execution evidence"]}
    try:
        report["source_bindings"] = _source_bindings()
        report["tools"] = {name: {"path": path, "sha256": digest_executable(Path(path))} for name, path in tools.items()}
        for name, path in tools.items():
            args = ["-flavor", "gnu", "--version"] if name == "linker" else ["--version"]
            _, observed = _run([path, *args], report, directory, require_zero=True)
            report["tools"][name]["version"] = observed.stdout.splitlines()[0]
        original = verify_program(corpus_document())
        for case in case_plan() + trap_plan():
            try:
                vm = execute_program(original, case["function"], case["arguments"], allocation_fail_at=case["failure"] or None)
            except HIAProgramTrap as error:
                if case.get("trap_code") != error.code:
                    raise
                vm = error.report
            else:
                if case.get("trap_code"):
                    raise ValueError("expected VM trap did not occur")
            expected = independent_spec(case)
            if not _same(vm_projection(vm), {key: value for key, value in expected.items() if key != "null_frees"}):
                raise ValueError("VM disagrees with independent returned-loan value/resource specification")
            report["reference"].append({"case": case, "expected": expected, "vm": vm})
        for name, document in _rejection_documents():
            try:
                verify_program(document)
            except HIAProgramRejected as error:
                report["rejections"].append({"name": name, "diagnostic": str(error)})
            else:
                raise ValueError("illegal returned-loan input was admitted")
        for label in TARGETS:
            target = {"objects": {}, "executions": []}
            report["native"][label] = target
            for variant in ("positive", "wrong_value", "removed_free"):
                core = verify_program(corpus_document(wrong_value=variant == "wrong_value"))
                target["objects"][variant] = _object(core, label, variant, report, directory, tools)
            for name, variant, cases, code in _execution_plan():
                row = _build_execute(original, target["objects"][variant], label, name, cases, report, directory, tools)
                target["executions"].append(row)
                if not _same(row["execution"], _expected_execution(name, cases, code)):
                    raise ValueError("actual " + label + " execution differs: " + name)
        if not _same(report["source_bindings"], _source_bindings()):
            raise ValueError("compiler/corpus/runtime changed during qualification")
        report.update(ok=True, status=STATUS, counts=expected_counts())
        report["artifacts"] = _inventory(directory)
        validate_qualification(report)
    except Exception as error:
        report.update(ok=False, status="rejected", error={"type": type(error).__name__, "message": str(error),
                      "traceback": traceback.format_exc()[-7000:]})
        report["artifacts"] = _inventory(directory)
    _write(directory / "qualification.json", report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-directory", required=True)
    parser.add_argument("--clang", required=True)
    parser.add_argument("--linker", required=True)
    parser.add_argument("--readobj", required=True)
    parser.add_argument("--qemu-aarch64", required=True)
    parser.add_argument("--qemu-riscv64", required=True)
    args = parser.parse_args()
    report = qualify(directory=args.output_directory, clang=args.clang, linker=args.linker,
                     readobj=args.readobj, qemu_aarch64=args.qemu_aarch64, qemu_riscv64=args.qemu_riscv64)
    print(json.dumps({key: report.get(key) for key in ("ok", "status", "counts", "error")}, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
