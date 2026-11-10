"""Qualify actual owned-buffer source admission in the libc-bound ELF profile.

The native selfhost compiler creates all object bytes and relocations. The
inspector only reads them; ordinary ld or an explicitly selected native HIA
linker binds the two closed allocator imports. The independent host oracle
retains ld. A selected native linker failure never falls back to ld.
The existing child loads the linked artifact without importing HIA modules.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def digest(data):
    return sha256(data).hexdigest()


def inspect_owned_object(data):
    if len(data) < 64:
        raise ValueError("truncated owned ELF")
    header = struct.unpack_from("<16sHHIQQQIHHHHHH", data)
    ident, kind, machine, version, entry, phoff, shoff, flags, ehsize, phsize, phnum, shsize, shnum, name_index = header
    if (ident != b"\x7fELF\x02\x01\x01\x00" + b"\0" * 8
            or (kind, machine, version, entry, phoff, flags, ehsize, phsize, phnum, shsize, shnum, name_index)
            != (1, 62, 1, 0, 0, 0, 64, 0, 0, 64, 7, 4)
            or shoff % 8 or shoff + 7 * 64 != len(data)):
        raise ValueError("outside the closed allocator-import ELF header")
    sections = [struct.unpack_from("<IIQQQQIIQQ", data, shoff + i * 64) for i in range(7)]
    if any(sections[0]):
        raise ValueError("nonzero null section")
    for row in sections[1:]:
        if row[3] or row[4] < 64 or row[4] + row[5] > shoff:
            raise ValueError("section outside object payload")
    text, sym, strings, names, stack, rela = sections[1:]
    expected_names = b"\0.text\0.symtab\0.strtab\0.shstrtab\0.note.GNU-stack\0.rela.text\0"
    if data[names[4]:names[4] + names[5]] != expected_names or [row[0] for row in sections] != [0, 1, 7, 15, 23, 33, 49]:
        raise ValueError("section name inventory differs")
    if ((text[1], text[2], text[4], text[6], text[7], text[8], text[9]) != (1, 6, 64, 0, 0, 16, 0)
            or (sym[1], sym[2], sym[5], sym[6], sym[7], sym[8], sym[9]) != (2, 0, 120, 3, 2, 8, 24)
            or (strings[1], strings[2], strings[5], strings[6], strings[7], strings[8], strings[9]) != (3, 0, 16, 0, 0, 1, 0)
            or (names[1], names[2], names[5], names[6], names[7], names[8], names[9]) != (3, 0, 60, 0, 0, 1, 0)
            or (stack[1], stack[2], stack[5], stack[6], stack[7], stack[8], stack[9]) != (1, 0, 0, 0, 0, 1, 0)
            or (rela[1], rela[2], rela[6], rela[7], rela[8], rela[9]) != (4, 0, 2, 1, 8, 24)
            or not 24 <= rela[5] <= 12000 * 24 or rela[5] % 24):
        raise ValueError("section shape or links differ")
    if (sym[4] != ((64 + text[5] + 7) & ~7) or strings[4] != sym[4] + 120
            or names[4] != strings[4] + 16 or stack[4] != names[4] + 60
            or rela[4] != ((names[4] + 60 + 7) & ~7) or shoff != rela[4] + rela[5]):
        raise ValueError("object payload order differs")
    symbols = [struct.unpack_from("<IBBHQQ", data, sym[4] + i * 24) for i in range(5)]
    if (any(symbols[0]) or symbols[1] != (0, 3, 0, 1, 0, 0)
            or symbols[2][:5] != (1, 18, 0, 1, 0) or not 0 < symbols[2][5] <= text[5]
            or symbols[3] != (4, 18, 0, 0, 0, 0) or symbols[4] != (11, 18, 0, 0, 0, 0)
            or data[strings[4]:strings[4] + 16] != b"\0f0\0calloc\0free\0"):
        raise ValueError("symbol inventory differs")
    records, previous = [], -1
    for i in range(rela[5] // 24):
        offset, info, addend = struct.unpack_from("<QQq", data, rela[4] + i * 24)
        symbol = info >> 32
        if (not previous + 4 < offset or not 1 <= offset <= text[5] - 4
                or info & 0xffffffff != 4 or symbol not in (3, 4) or addend != -4
                or data[64 + offset - 1] != 0xe8 or data[64 + offset:64 + offset + 4] != bytes(4)):
            raise ValueError("relocation is outside a closed allocator call")
        records.append({"offset": offset, "type": "R_X86_64_PLT32", "symbol": "calloc" if symbol == 3 else "free", "addend": -4})
        previous = offset
    return {"schema": "hepta.hia.selfhost-owned-elf-inspection.v1", "format": "ELF64-ET_REL",
        "exports": ["f0"], "undefined_symbols": ["calloc", "free"], "external_relocations": records,
        "nonexecuting_stack_note": True, "text_sha256": digest(data[64:64 + text[5]]),
        "object_sha256": digest(data), "object_bytes": len(data), "inspection_only": True}


def qualify(directory, compiler, *, linker_manifest=None):
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program import HIAProgramRejected
    from hepta.hia_program_native import emit_program_machine, compile_program_machine
    from tools.hia_selfhost_owned_elf_cases import cases, refusals, reference, expanded_name_cases as owned_name_cases
    from tools.hia_selfhost_owned_flow_cases import cases as flow_cases, refusals as flow_refusals, expanded_name_cases as flow_name_cases
    from tools.qualify_hia_selfhost import compile_stage, invoke, observe_native_tool, INVALID, NO_SPACE
    directory, compiler = Path(directory), Path(compiler)
    directory.mkdir(parents=True, exist_ok=False)
    report = {"schema": "hepta.hia.selfhost-owned-elf-qualification.v1", "status": "started",
        "compiler_sha256": digest(compiler.read_bytes()),
        "selected_linker": "external-ld" if linker_manifest is None else "explicit-native-HIA",
        "scope": "four owned-buffer operations in explicit linked ELF output; flat allocator calls remain refused",
        "allocator_contract": "ordinary calloc/free: fresh zeroed nonaliasing allocations or null; free releases valid live storage",
        "global_core_or_machine_refinement_proved": False,
        "general_multi_result_call_return_abi_supported": False, "chain_operations_qualified_by_this_suite": False,
        "cases": [], "refusals": []}
    try:
        all_cases = [*cases(), *flow_cases(), *owned_name_cases(), *flow_name_cases()]
        if len({case["id"] for case in all_cases}) != len(all_cases):
            raise ValueError("owned fixture identifiers must be unique")
        for case in all_cases:
            label = case["id"]
            source = case["source"].encode()
            (directory / (label + ".hiaasm")).write_bytes(source)
            ref = reference(case)
            obj, compilation = compile_stage(directory, label + "-object", compiler, source, output_extension=".o")
            inventory = inspect_owned_object(obj.read_bytes())
            tool_rows = [observe_native_tool(directory, label + "-readelf", "readelf", ["-W", "-h", "-S", "-s", "-r", obj])]
            linked = directory / (label + ".so")
            if linker_manifest is None:
                tool_rows.append(observe_native_tool(directory, label + "-link", "ld", ["-m", "elf_x86_64", "-shared",
                    "-z", "defs", "-z", "noexecstack", "-z", "relro", "-z", "now", "--build-id=none", obj, "-lc", "-o", linked]))
            else:
                from tools.link_hia_elf import link as native_link
                link_receipt = native_link([obj], Path(linker_manifest), linked,
                    expected_compiler_sha256=report["compiler_sha256"])
                tool_rows.append(link_receipt)
                (directory / (label + "-native-link.json")).write_text(json.dumps(link_receipt, indent=2, sort_keys=True) + "\n")
            if not all(row["returncode"] == 0 for row in tool_rows):
                raise AssertionError(tool_rows)
            observed, output = invoke(directory, label + "-run", linked, b"", image_format="linked-selfhost",
                capacity=8, workspace_size=0, output_initial=bytes([0xa5] * 8), observe_trap_writes=True)
            checked = assemble_program(source)
            direct_image = emit_program_machine(checked, foreign_buffer_exports=(("f0", 1 << 20),))
            direct = directory / (label + "-direct.so")
            direct_build = compile_program_machine(direct_image, program=checked, output=direct, linker="ld")
            oracle, oracle_output = invoke(directory, label + "-direct-run", direct, b"", image_format="seed-shared",
                capacity=8, workspace_size=0, output_initial=bytes([0xa5] * 8), observe_trap_writes=True)
            if "expected_trap" in case:
                good = (observed.get("status") == "child_failed" and observed.get("returncode") == -4
                        and oracle.get("status") == "child_failed" and oracle.get("returncode") == -6)
            else:
                good = (observed.get("status") == oracle.get("status") == "returned"
                        and observed.get("core_u32") == oracle.get("core_u32") == case["expected_result"]
                        and observed.get("source_unchanged") and oracle.get("source_unchanged"))
            good = bool(good and output.hex() == oracle_output.hex() == case["expected_output_hex"])
            report["cases"].append({"case": case, "reference": ref, "compilation": compilation,
                "inspection": inventory, "tools": tool_rows, "native": observed, "output_hex": output.hex(),
                "independent_direct_build": direct_build, "independent_direct_native": oracle, "pass": good})
            if not good:
                raise AssertionError(report["cases"][-1])
            if label in {"try-8", "owned-call-consumes-input"}:
                short, _ = invoke(directory, label + "-short", compiler, source, capacity=obj.stat().st_size - 1)
                if not (short.get("status") == "returned" and short.get("core_u32") == NO_SPACE and short.get("output_unchanged")):
                    raise AssertionError(short)
                report["cases"][-1]["short_output_transactional"] = short
        basic_refusals, control_refusals = refusals(), flow_refusals()
        if set(basic_refusals) & set(control_refusals):
            raise ValueError("owned refusal identifiers must be unique")
        for name, source in {**basic_refusals, **control_refusals}.items():
            canonical = "accepted_general_core"
            try:
                assemble_program(source)
            except HIAProgramRejected as error:
                canonical = error.code
            observed, _ = invoke(directory, "reject-" + name, compiler, source)
            good = bool(observed.get("status") == "returned" and observed.get("core_u32") == INVALID
                        and observed.get("output_unchanged") and observed.get("source_unchanged"))
            report["refusals"].append({"name": name, "source": source.decode(), "canonical": canonical,
                                       "observation": observed, "pass": good})
            if not good:
                raise AssertionError(report["refusals"][-1])
        report["status"] = "PASS_SCOPED_OWNED_BUFFER_ELF"
    finally:
        report["source_files"] = {path: digest((ROOT / path).read_bytes()) for path in (
            "tools/generate_hia_selfhost.py", "tools/hia_selfhost_owned_elf.py", "tools/hia_selfhost_owned_elf_cases.py",
            "tools/hia_selfhost_owned_flow_cases.py",
            "tools/qualify_hia_selfhost_owned_elf.py", "examples/hia_bootstrap/selfhost.hiaasm")}
        (directory / "qualification.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compiler", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--linker-manifest", type=Path)
    args = parser.parse_args()
    report = qualify(args.output, args.compiler, linker_manifest=args.linker_manifest)
    print(json.dumps({"status": report["status"], "cases": len(report["cases"]), "refusals": len(report["refusals"])}))


if __name__ == "__main__":
    main()
