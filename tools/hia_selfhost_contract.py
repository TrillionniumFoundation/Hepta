"""Pinned support and source identities for the bounded native HIA compiler.

The contract is generated from checked-in source bytes. It is an input identity
and a support declaration, not a successful execution or correctness receipt.
"""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
from tools.hia_selfhost_limits import (MAX_INSTRUCTIONS, MAX_CORE_NODES,
    MAX_FUNCTIONS, MAX_BLOCKS, MAX_RELOCATIONS, RELOCATION_UPPER_BOUND, CORE_BYTES_UPPER_BOUND)

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = "docs/HIA_SELFHOST_CORE_SUPPORT.json"
PROFILE = "selfhost-core-linux-x86_64-v11"
SOURCE_FILES = (
    "tools/generate_hia_selfhost.py",
    "tools/generate_hia_selfhost_contract.py",
    "tools/hia_selfhost_contract.py",
    "tools/hia_selfhost_cases.py",
    "tools/hia_selfhost_resources.py",
    "tools/hia_selfhost_bulk.py",
    "tools/hia_selfhost_loans.py",
    "tools/hia_selfhost_select.py",
    "tools/hia_selfhost_tailcalls.py",
    "tools/hia_selfhost_limits.py",
    "tools/hia_selfhost_capacity.py",
    "tools/qualify_hia_selfhost.py",
    "tools/replay_hia_selfhost_cold.py",
    "tools/replay_hia_selfhost_upgrade.py",
    "tools/hia_selfhost_child.py",
    "examples/hia_bootstrap/selfhost.hiaasm",
    "examples/hia_bootstrap/bytesum.hiaasm",
    "docs/HIA_SELF_HOSTING_CORE.md",
    "tests/test_hia_selfhost.py",
    "tests/test_hia_selfhost_contract.py",
    "tests/test_hia_selfhost_language_coverage.py",
    "docs/HIA_SELFHOST_LANGUAGE_COVERAGE.json",
)


def file_digests(root=ROOT):
    root = Path(root)
    # Include the complete Python seed package, not a hand-maintained subset
    # that can omit a transitively imported checker or native ABI dependency.
    paths = sorted(set(SOURCE_FILES) | {
        p.relative_to(root).as_posix() for p in (root / "hepta").rglob("*.py")
    })
    return {path: sha256((root / path).read_bytes()).hexdigest() for path in paths}


def support_contract(root=ROOT):
    return {
        "schema": "hepta.hia.selfhost-core-support.v1",
        "profile": PROFILE,
        "target": {"triple": "x86_64-unknown-linux-gnu", "system": "Linux",
                   "isa": "x86-64", "endianness": "little", "pointer_bits": 64},
        "syntax": {"header": "hia-asm.v1", "core": "hepta.hia.program.v8",
                   "module": "selfhost", "object_module": "selfhost_elf",
                   "function_names": "contiguous f0..f127",
                   "block_names": "contiguous b0..b255 per function",
                   "value_names": "unique per function v0..v2047",
                   "whitespace": "ASCII space and LF; shared assembly adjacency rules"},
        "abi": {
            "entry": "f0", "calling_convention": "SysV AMD64",
            "parameters": ["source_ptr", "source_len_u64", "output_ptr",
                           "output_len_u64", "workspace_ptr", "workspace_len_u64"],
            "core_types": ["readbuf", "mutbuf", "mutbuf"],
            "core_return": "u32",
            "seed_return": "u64: ABI status in high 32 bits, Core u32 in low 32 bits",
            "successor_return": "zero-extended Core u32",
            "invalid_source": 4294967295, "insufficient_capacity": 4294967294,
            "success": "positive generated flat-image or ELF object byte count",
            "caller_obligations": ["live private source allocation",
                "live disjoint output and workspace allocations",
                "no concurrent input modification", "entry buffers do not escape"],
            "native_runtime_trap": "UD2 for failed bounds, checked shift, unsigned checked arithmetic or zero divisor",
        },
        "compiler_symbols": {"entry": "f0", "mutation_wrapper": "f13",
                             "call_graph_checker": "f12"},
        "limits": {
            "source_bytes": 1048576, "output_capacity_bytes": 1048576,
            "workspace_required_bytes": 1048576, "functions": MAX_FUNCTIONS,
            "blocks_per_function": 256, "blocks_total": MAX_BLOCKS,
            "parameters_or_arguments": 16, "ssa_index_max": 2047,
            "instructions": MAX_INSTRUCTIONS, "core_structural_nodes": MAX_CORE_NODES,
            "relative_relocations": MAX_RELOCATIONS,
            "acyclic_call_depth_max": 128,
            "tail_self_call_additional_frames": 0,
            "resource_graph_parse_rounds_max": MAX_BLOCKS,
        },
        "capacity_derivation": {
            "relative_relocations_upper_bound": RELOCATION_UPPER_BOUND,
            "relative_relocations_formula": "one wrapper call + instructions + two edges per block",
            "canonical_core_bytes_upper_bound": CORE_BYTES_UPPER_BOUND,
            "canonical_core_byte_budget": 8388608,
            "structural_node_counter_workspace_offset": 248,
            "structural_node_gate": "exact Core JSON value/container nodes, checked in every native parse pass",
            "capacity_growth_changes_source_output_workspace_bytes": False,
        },
        "support": [
            {"area": "scalar_types", "status": "supported",
             "items": ["u64", "usize", "u32", "u8", "bool"]},
            {"area": "resources", "status": "bounded_subset",
             "items": ["borrowed readbuf/mutbuf parameters", "buffer.len",
                       "buffer.load", "buffer.store", "buffer.swap with both bounds before access",
                       "buffer.fill", "buffer.fill_range", "buffer.copy",
                       "buffer.copy_range", "buffer.move_within with overlap handling",
                       "borrow.read from readbuf/mutbuf", "borrow.mut from mutbuf",
                       "loan.end for live local childless loans",
                       "nested loan parent suspension and shared/exclusive root checks",
                       "exact capability graph joins and closed loop/edge transfers",
                       "linear edge transfers",
                       "readonly call aliases", "mutable alias rejection"]},
            {"area": "integer_operations", "status": "bounded_subset",
             "items": ["const", "int.add.wrap", "int.sub.wrap", "int.mul.wrap",
                       "int.add.checked", "int.sub.checked", "int.mul.checked",
                       "int.div.checked", "int.rem.checked", "int.neg.checked", "bit.not",
                       "bit.and", "bit.or", "bit.xor", "int.shl.checked",
                       "int.shr.checked", "int.cast wrap", "unsigned comparisons",
                       "bool.and", "bool.or", "bool.not", "select (bool condition, matching scalars)"]},
            {"area": "control_flow", "status": "supported",
             "items": ["typed ret", "typed jump", "typed branch", "loops",
                       "block reachability", "no inbound entry edges"]},
            {"area": "calls", "status": "bounded_subset",
             "items": ["scalar return", "exact signatures", "forward direct calls",
                       "backward direct calls", "HIA-checked non-self acyclic call graph"]},
            {"area": "recursion", "status": "bounded_subset",
             "items": ["direct self call immediately returned by the same block",
                       "parallel argument staging and same-frame entry jump",
                       "non-tail self calls and mutual recursion rejected",
                       "non-tail cycles in non-entry-reachable functions rejected"],
             "limits": {"additional_frames_per_self_tail_call": 0,
                        "runtime_termination_proved": False,
                        "iteration_bound": "external CPU/wall budget, as for accepted loops",
                        "pending_result_workspace_offset": 256}},
            {"area": "owned_resources", "status": "not_implemented",
             "items": ["allocation", "deallocation", "owner transfer",
                       "returned loans", "recursive owner chains"]},
            {"area": "general_core_checker", "status": "not_implemented",
             "items": ["full HIA v8 operation set", "module graph",
                       "arbitrary identifiers", "all resource and effect combinations"]},
            {"area": "successor_output", "status": "bounded_subset",
             "items": ["flat position-independent x86-64 image",
                       "HIA-written relative call and branch relocations"]},
            {"area": "successor_object_output", "status": "bounded_subset",
             "profile": "hepta.hia.selfhost.elf64-relocatable.v1",
             "items": ["HIA-written ELF64 ET_REL", "one f0 SysV entry symbol",
                       "position-independent .text with resolved internal relocations",
                       "nonexecuting stack note", "no external symbols or relocations"]},
            {"area": "general_object_linking", "status": "not_implemented",
             "items": ["external symbols and relocations", "multiple public functions",
                       "general linker", "additional ELF targets"]},
        ],
        "required_replay": {
            "generation_order": ["B0", "B1", "B2", "B3"],
            "fixed_point": "B1 == B2 == B3 bytes",
            "modified_order": ["M1", "M2", "M3"],
            "modified_fixed_point": "M1 != M2; M2 == M3; M3 != B3",
            "source_modification": "HIA wrapper reservation 64 -> 80 bytes",
            "cold_command": "python -B tools/replay_hia_selfhost_cold.py --output <new-report.json>",
        },
        "source_identity": {
            "roles": {
                "compiler_source": "examples/hia_bootstrap/selfhost.hiaasm",
                "authoring_aid": "tools/generate_hia_selfhost.py",
                "seed_entry": "tools/qualify_hia_selfhost.py:build_seed",
                "successor_loader": "tools/hia_selfhost_child.py",
                "seed_package": "hepta/**/*.py",
                "qualification": "tools/qualify_hia_selfhost.py",
                "cold_replay": "tools/replay_hia_selfhost_cold.py",
            },
            "files": file_digests(root),
            "seed_external_dependencies": ["CPython standard library", "GNU ld",
                                           "libc and the system dynamic loader"],
            "successor_trusted_dependencies": ["stdlib-only ctypes/mmap loader",
                "Linux kernel", "x86-64 hardware", "caller-owned private buffers"],
        },
        "claims": {"support_declaration_is_execution_evidence": False,
                   "whole_HIA_language_self_hosted": False,
                   "compiler_correctness_formally_proved": False,
                   "native_execution_is_security_sandboxed": False},
    }


def validate_contract(root=ROOT):
    root = Path(root)
    path = root / CONTRACT_PATH
    declared = json.loads(path.read_text())
    expected = support_contract(root)
    if declared != expected:
        raise ValueError("Selfhost-Core support contract differs from the current source closure")
    return declared
