#!/usr/bin/env python3
"""Exercise actual typed HIA lowering, including native semantic mutations.

This suite needs the built hia-system executable and LLVM 20.1.8 binaries.
It deletes the native probe's original LLVM inputs before decoding HIA.
No C/LLVM instruction-text fallback can satisfy the 24 -> 14 execution check.
"""
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
import shutil
import subprocess
import sys

EXPECTED_OPS = set("""
ret br switch indirectbr invoke resume unreachable cleanupret catchret
catchswitch callbr fneg add fadd sub fsub mul fmul udiv sdiv fdiv urem srem
frem shl lshr ashr and or xor alloca load store getelementptr fence cmpxchg
atomicrmw trunc zext sext fptoui fptosi uitofp sitofp fptrunc fpext ptrtoint
inttoptr bitcast addrspacecast cleanuppad catchpad icmp fcmp phi call select
va_arg extractelement insertelement shufflevector extractvalue insertvalue
landingpad freeze
""".split())


def instructions(value):
    if isinstance(value, dict):
        if {"op", "result_type", "operands"} <= value.keys():
            yield value
        else:
            for child in value.values():
                yield from instructions(child)
    elif isinstance(value, list):
        for child in value:
            yield from instructions(child)


def descriptors(document):
    nodes = list(instructions(document))
    ids = [node["id"] for node in nodes]
    if len(ids) != len(set(ids)):
        raise AssertionError("duplicate instruction result IDs")
    return {node["id"]: node for node in nodes}


def normalized_document(document):
    result = copy.deepcopy(document)
    module = result.get("module", {})
    if isinstance(module, dict):
        module.pop("identifier", None)  # Bitcode readers replace this with input path.
    return result


def first(document, op, **properties):
    for node in instructions(document):
        if node["op"] == op and all(node.get(k) == v for k, v in properties.items()):
            return node
    raise AssertionError(f"missing fixture instruction {op}: {properties}")


def run(command, *, expected=0):
    process = subprocess.run([str(x) for x in command], capture_output=True,
                             text=True, check=False)
    if process.returncode != expected:
        raise AssertionError(
            f"command returned {process.returncode}, expected {expected}: "
            f"{command}\nstdout:\n{process.stdout}\nstderr:\n{process.stderr}")
    return process


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--codec", required=True, type=Path)
    parser.add_argument("--llvm-bin", required=True, type=Path)
    parser.add_argument("--work-dir", required=True, type=Path)
    parser.add_argument("--fixtures", type=Path,
                        default=Path(__file__).resolve().parent / "fixtures")
    args = parser.parse_args()
    work = args.work_dir.resolve()
    work.mkdir(parents=True, exist_ok=False)
    codec = args.codec.resolve()
    clang = args.llvm_bin.resolve() / "clang"
    assembler = args.llvm_bin.resolve() / "llvm-as"
    report = {"schema": "hia.system.semantic-tests.v1", "status": "running",
              "checks": [], "tool_versions": {}, "opcode_coverage": []}
    report_path = work / "report.json"

    def record(name, **details):
        report["checks"].append({"name": name, "status": "passed", **details})
        report_path.write_text(json.dumps(report, indent=2) + "\n")

    def encode(path, name):
        output = work / (name + ".hia.json")
        run([codec, "encode", path, output])
        return json.loads(output.read_text())

    def lower(document, name):
        source = work / (name + ".hia.json")
        result = work / (name + ".bc")
        source.write_text(json.dumps(document, sort_keys=True) + "\n")
        run([codec, "decode", source, result])
        return result

    def roundtrip(document, name):
        rebuilt = lower(document, name)
        reencoded = encode(rebuilt, name + ".reencoded")
        before, after = descriptors(document), descriptors(reencoded)
        if before != after:
            differing = sorted(k for k in before.keys() | after.keys()
                               if before.get(k) != after.get(k))
            raise AssertionError(f"{name}: typed instruction descriptors changed: "
                                 f"{differing[:12]}")
        if normalized_document(document) != normalized_document(reencoded):
            raise AssertionError(f"{name}: module/type/constant/metadata roundtrip changed; "
                                 "only module.identifier may differ")
        return rebuilt

    def rejected(document, name):
        source = work / (name + ".hia.json")
        output = work / (name + ".bc")
        source.write_text(json.dumps(document, sort_keys=True) + "\n")
        process = subprocess.run([str(codec), "decode", str(source), str(output)],
                                 text=True, capture_output=True, check=False)
        (work / (name + ".stderr.txt")).write_text(process.stderr)
        if process.returncode == 0:
            raise AssertionError(f"{name}: malformed HIA was accepted")
        if output.exists():
            raise AssertionError(f"{name}: failure produced a backend artifact")
        record(name, exit_code=process.returncode, output_absent=True)

    try:
        for name, program in [("clang", clang), ("llvm-as", assembler)]:
            version = run([program, "--version"]).stdout
            if "20.1.8" not in version:
                raise AssertionError(f"{name} is not pinned LLVM 20.1.8: {version}")
            report["tool_versions"][name] = version.splitlines()[0]

        probe_ll = work / "original_probe.ll"
        probe_bc = work / "original_probe.bc"
        shutil.copyfile(args.fixtures / "native_mutation.ll", probe_ll)
        run([assembler, probe_ll, "-o", probe_bc])
        probe = encode(probe_bc, "probe")
        probe_ll.unlink()
        probe_bc.unlink()
        rebuilt = roundtrip(probe, "probe_from_hia")
        program = work / "probe_native"
        run([clang, rebuilt, "-O0", "-o", program])
        run([program], expected=24)
        record("original_inputs_removed_before_native_lowering", native_exit=24)

        changed = copy.deepcopy(probe)
        first(changed, "add")["op"] = "sub"
        rebuilt = roundtrip(changed, "probe_add_to_sub")
        program = work / "probe_native_mutated"
        run([clang, rebuilt, "-O0", "-o", program])
        run([program], expected=14)
        record("HIA_opcode_mutation_changes_native_execution",
               before_exit=24, after_exit=14)

        property_bc = work / "instruction_properties.bc"
        run([assembler, args.fixtures / "instruction_properties.ll",
             "-o", property_bc])
        properties = encode(property_bc, "instruction_properties")
        roundtrip(properties, "instruction_properties_rebuilt")
        record("all_instruction_properties_roundtrip_exactly",
               instruction_count=len(descriptors(properties)))

        module_bc = work / "module_properties.bc"
        run([assembler, args.fixtures / "module_properties.ll", "-o", module_bc])
        module_properties = encode(module_bc, "module_properties")
        roundtrip(module_properties, "module_properties_rebuilt")
        record("module_graph_constants_aliases_ifuncs_attributes_and_cyclic_metadata")

        asm_bc = work / "asm_goto.bc"
        run([clang, "-std=gnu11", "-O1", "-Xclang", "-disable-llvm-passes",
             "-g0", "-emit-llvm", "-c", args.fixtures / "asm_goto.c",
             "-o", asm_bc])
        asm = encode(asm_bc, "asm_goto")
        roundtrip(asm, "asm_goto_rebuilt")
        first(asm, "callbr")
        record("real_GNU_asm_goto_callbr_and_inline_asm_roundtrip")

        covered = {n["op"] for d in [probe, properties, asm] for n in instructions(d)}
        missing = EXPECTED_OPS - covered
        if missing:
            raise AssertionError(f"missing executable opcode fixtures: {sorted(missing)}")
        report["opcode_coverage"] = sorted(covered)
        record("all_65_executable_LLVM20_opcodes_covered",
               count=len(covered), reserved_user_ops_excluded=True)

        mutations = [
            ("add_nuw", "add", "nuw", False, {"nuw": True}),
            ("add_nsw", "add", "nsw", False, {"nsw": True}),
            ("udiv_exact", "udiv", "exact", False, {}),
            ("trunc_nuw", "trunc", "nuw", False, {}),
            ("trunc_nsw", "trunc", "nsw", False, {}),
            ("zext_nneg", "zext", "nneg", False, {}),
            ("uitofp_nneg", "uitofp", "nneg", False, {}),
            ("or_disjoint", "or", "disjoint", False, {}),
            ("icmp_samesign", "icmp", "samesign", False, {"samesign": True}),
            ("icmp_predicate", "icmp", "predicate", "sge", {"predicate": "sgt"}),
            ("load_volatile", "load", "volatile", False, {"ordering": "not_atomic"}),
            ("store_volatile", "store", "volatile", False, {"ordering": "not_atomic"}),
            ("load_align", "load", "align", 16, {"ordering": "not_atomic"}),
            ("load_ordering", "load", "ordering", "monotonic", {"ordering": "acquire"}),
            ("load_scope", "load", "sync_scope", "hia.fixture.scope", {"ordering": "acquire"}),
            ("cmpxchg_weak", "cmpxchg", "weak", False, {}),
            ("cmpxchg_volatile", "cmpxchg", "volatile", False, {}),
            ("cmpxchg_success", "cmpxchg", "success_ordering", "seq_cst", {}),
            ("cmpxchg_failure", "cmpxchg", "failure_ordering", "monotonic", {}),
            ("atomicrmw_operation", "atomicrmw", "operation", "xor", {}),
            ("atomicrmw_volatile", "atomicrmw", "volatile", False, {}),
            ("fence_ordering", "fence", "ordering", "acq_rel", {}),
            ("gep_inbounds", "getelementptr", "inbounds", False, {"inbounds": True}),
            ("gep_nuw", "getelementptr", "nuw", False, {"nuw": True}),
            ("gep_nusw", "getelementptr", "nusw", False, {"inbounds": False}),
            ("tail_kind", "call", "tail_kind", "none", {"tail_kind": "notail"}),
        ]
        for name, op, field, value, where in mutations:
            mutation = copy.deepcopy(properties)
            node = first(mutation, op, **where)
            if node[field] == value:
                raise AssertionError(f"ineffective fixture mutation {name}")
            node[field] = value
            roundtrip(mutation, "mutation_" + name)
            record("typed_property_mutation_" + name)

        mutation = copy.deepcopy(properties)
        first(mutation, "fadd")["fast_math"]["nnan"] = False
        roundtrip(mutation, "mutation_fast_math")
        record("typed_property_mutation_fast_math")
        mutation = copy.deepcopy(properties)
        first(mutation, "shufflevector")["mask"][1] = 4
        roundtrip(mutation, "mutation_shuffle_mask")
        record("typed_property_mutation_shuffle_mask")
        mutation = copy.deepcopy(properties)
        first(mutation, "insertvalue")["indices"][-1] = 1
        roundtrip(mutation, "mutation_aggregate_indices")
        record("typed_property_mutation_aggregate_indices")
        mutation = copy.deepcopy(properties)
        first(mutation, "call", argument_count=1)["bundles"][0]["tag"] = "hia.fixture"
        roundtrip(mutation, "mutation_operand_bundle")
        record("typed_property_mutation_operand_bundle")

        for op, field in [
                ("add", "nuw"), ("call", "function_type"), ("call", "attributes"),
                ("call", "bundles"), ("load", "sync_scope"), ("load", "align"),
                ("cmpxchg", "failure_ordering"), ("getelementptr", "source_element_type"),
                ("shufflevector", "mask"), ("phi", "incoming_blocks"),
                ("catchswitch", "has_unwind")]:
            invalid = copy.deepcopy(properties)
            del first(invalid, op)[field]
            rejected(invalid, "reject_missing_" + op + "_" + field)
        invalid = copy.deepcopy(probe)
        first(invalid, "add")["op"] = "unimplemented.future.operation"
        rejected(invalid, "reject_unknown_opcode")
        invalid = copy.deepcopy(probe)
        first(invalid, "add")["unimplemented_semantic_refinement"] = True
        rejected(invalid, "reject_unknown_property")
        invalid = copy.deepcopy(probe)
        first(invalid, "add")["operands"].pop()
        rejected(invalid, "reject_wrong_operand_count")
        invalid = copy.deepcopy(probe)
        first(invalid, "add")["operands"][0] = None
        rejected(invalid, "reject_null_operand")
        invalid = copy.deepcopy(properties)
        first(invalid, "getelementptr", inbounds=True)["nusw"] = False
        rejected(invalid, "reject_inconsistent_gep_flags")
        invalid = copy.deepcopy(properties)
        first(invalid, "load")["align"] = 3
        rejected(invalid, "reject_non_power_of_two_alignment")

        report["status"] = "passed"
        report_path.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({"status": "passed", "checks": len(report["checks"]),
                          "opcodes": len(covered), "report": str(report_path)}))
        return 0
    except Exception as error:
        report["status"] = "failed"
        report["error"] = str(error)
        report_path.write_text(json.dumps(report, indent=2) + "\n")
        print(str(error), file=sys.stderr)
        print(f"failure report: {report_path}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
