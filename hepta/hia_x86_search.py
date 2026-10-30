"""Finite offline x86-64 register search with all-input HIA model validation.

The complete grammar has 146 recipes, one u64 argument in RDI and one u64
result in RAX.  A successful finite minimum concerns encoded byte count in
this grammar, not runtime or unrestricted program optimization.  The closed
encoder, instruction-to-HIA model, canonical verifier, Z3, assembler/linker,
ELF loader and host ISA remain trusted.  This is not an ISA refinement proof.

Serialized candidates and search receipts are never execution authority:
building reconstructs the model and bytes, re-proves equivalence, assembles
locally, and checks the actual exported entry and its executable segment.
"""
from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import re
import shutil
import struct
import tempfile
import time

from .artifact_publication import publish_verified, verify_published, withdraw_own_link
from .clang_capture import run_bounded
from .elf_shared_abi import inspect_owned_shared_elf
from .hia_program import SCHEMA as PROGRAM_SCHEMA, verify_program
from .hia_program_llvm import TARGET, _read_artifact
from .hia_translation_validation import (
    PROFILE as PROOF_PROFILE, SCHEMA as PROOF_SCHEMA, validate_translation,
)
from .native_tool_identity import digest_executable

SCHEMA = "hepta.hia.x86-finite-search.v1"
PROFILE = "x86_64-sysv-u64-register-affine-146.v1"
BOUNDED_AFFINE_SCHEMA = "hepta.hia.x86-bounded-affine-search.v1"
BOUNDED_AFFINE_PROFILE = "u64-wrapping-affine-multipliers-minus1-to4-offsets-minus16-to16.v1"
FUNCTION = "calculate"
_MASK = (1 << 64) - 1
_K = tuple(range(-16, 17))
_M = (-1, 0, 1, 2, 3, 4)
_MK = (-16, -12, 0, 12, 16)
_KK = (-12, -1, 0, 1, 4, 8, 12)
# The final ret is implicit and mandatory in every recipe. Each tuple is a
# closed instruction form, never assembler text or user-selected registers.
_RECIPES = (
    (("mov", None),),
    *((("lea", k),) for k in _K),
    *((("mov", None), ("add", k)) for k in _K),
    *((("imul", m), ("add", k)) for m in _M for k in _MK),
    *((("mov", None), ("add", a), ("add", b)) for a in _KK for b in _KK),
)
GRAMMAR = {
    "profile": PROFILE, "complete_recipe_count": 146,
    "forms": ["mov;ret", "lea(k);ret", "mov;add(k);ret",
              "imul(m);add(k);ret", "mov;add(a);add(b);ret"],
    "lea_and_single_add_k": list(_K), "imul_m": list(_M),
    "imul_add_k": list(_MK), "two_add_a_and_b": list(_KK),
    "instruction_limit_including_ret": 4,
    "abi": "Linux x86-64 SysV calculate(uint64_t) -> uint64_t",
    "registers": {"argument_read_only": "rdi", "result_and_scratch": "rax"},
    "effects": {
        "mov_lea": "write RAX, preserve flags; LEA computes an address without dereferencing it",
        "add": "write RAX and arithmetic CF/PF/AF/ZF/SF/OF flags",
        "imul": "write RAX and CF/OF; PF/AF/ZF/SF become undefined",
        "ret": "read the ABI caller return address, transfer RIP, advance RSP by 8",
        "unchanged": "RDI, callee-saved registers and DF; no other explicit memory/stack operation",
    },
    "observable": "u64 return value under the SysV ABI; arithmetic flags are not outputs",
    "cost": "exact encoded function body bytes including ret; excludes ELF metadata/alignment",
}
_IMPLEMENTATION_INPUTS = (
    "hia_x86_search.py", "hia_program.py", "hia_program_composite.py", "hia_schema.py",
    "hia_translation_validation.py", "hia_program_runtime.py", "hia_program_llvm.py",
    "elf_shared_abi.py", "artifact_publication.py", "clang_capture.py", "native_tool_identity.py",
)


class X86SearchRejected(ValueError):
    pass


def _require(condition, message):
    if not condition:
        raise X86SearchRejected("E_HIA_X86_SEARCH: " + message)


def _wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _implementation_hash():
    digest = sha256()
    root = Path(__file__).parent
    for name in _IMPLEMENTATION_INPUTS:
        digest.update(name.encode() + b"\0" + (root / name).read_bytes() + b"\0")
    return digest.hexdigest()


def _program(operations, result):
    parameter = {"name": "x", "type": "u64"}
    return {"schema": PROGRAM_SCHEMA, "module": "x86_finite_affine", "functions": [{
        "name": FUNCTION, "params": [parameter], "returns": ["u64"], "effects": [],
        "entry": "entry", "blocks": [{"id": "entry", "params": [parameter],
            "ops": operations, "term": {"op": "ret", "values": [result]}}],
    }]}


def _literal(name, value):
    return {"op": "const", "args": [], "out": [{"name": name, "type": "u64"}],
            "attrs": {"value": value & _MASK}}


def _operation(op, left, right, name):
    return {"op": op, "args": [left, right], "out": [{"name": name, "type": "u64"}], "attrs": {}}


def affine_program(offset=12):
    """The frozen finite specification is x+offset, wrapping modulo 2**64."""
    _require(type(offset) is int and -16 <= offset <= 16, "offset must be an integer in [-16,16]")
    return _program([_literal("k", offset), _operation("int.add.wrap", "x", "k", "result")], "result")


def bounded_affine_program(multiplier, offset):
    """Specify a*x+b modulo 2**64, without adding an encoder instruction.

    The existing grammar does not represent every target in this bounded
    domain. Search must decide every recipe and can legitimately find none.
    The legacy x+offset constructor retains its original canonical bytes.
    """
    _require(type(multiplier) is int and multiplier in _M,
             "multiplier must be an integer in {-1,0,1,2,3,4}")
    _require(type(offset) is int and -16 <= offset <= 16,
             "offset must be an integer in [-16,16]")
    return _program([
        _literal("multiplier", multiplier),
        _operation("int.mul.wrap", "x", "multiplier", "scaled"),
        _literal("offset", offset),
        _operation("int.add.wrap", "scaled", "offset", "result"),
    ], "result")


def _model(recipe):
    operations, value = [], None
    for index, (op, immediate) in enumerate(recipe):
        if op == "mov":
            value = "x"
            continue
        constant, result = f"k{index}", f"r{index}"
        operations.append(_literal(constant, immediate))
        source = value if op == "add" else "x"
        _require(source is not None, "read of uninitialized RAX")
        operations.append(_operation("int.mul.wrap" if op == "imul" else "int.add.wrap",
                                     source, constant, result))
        value = result
    return _program(operations, value)


def _encode(recipe):
    result = bytearray()
    for op, immediate in recipe:
        if op == "mov":
            result.extend(b"\x48\x89\xf8")  # mov %rdi,%rax
        elif op == "lea":
            # The assembler uses no displacement for zero, signed disp8 otherwise.
            result.extend(b"\x48\x8d\x07" if immediate == 0 else b"\x48\x8d\x47" + bytes([immediate & 255]))
        elif op == "add":
            result.extend(b"\x48\x83\xc0" + bytes([immediate & 255]))
        elif op == "imul":
            result.extend(b"\x48\x6b\xc7" + bytes([immediate & 255]))
        else:
            _require(False, "instruction outside closed encoder")
    result.append(0xC3)  # ret, fixed ABI epilogue
    return bytes(result)


def _candidate(recipe):
    encoded = _encode(recipe)
    record = [{"op": op, **({} if immediate is None else {"imm": immediate})} for op, immediate in recipe]
    program = verify_program(_model(recipe)).as_dict()
    return {"id": "x" + sha256(_wire(record)).hexdigest()[:31], "recipe": record,
            "program": program, "expected_code_hex": encoded.hex(), "encoded_bytes": len(encoded)}


def enumerate_candidates():
    """Return the complete, ordered 146-recipe corpus; no candidate is approved."""
    _require(len(_RECIPES) == 146 and len(set(_RECIPES)) == 146, "internal grammar cardinality changed")
    return [_candidate(recipe) for recipe in _RECIPES]


def _checked_candidate(candidate):
    _require(type(candidate) is dict and set(candidate) ==
             {"id", "recipe", "program", "expected_code_hex", "encoded_bytes"}, "unknown candidate fields")
    records = candidate["recipe"]
    _require(type(records) is list and 1 <= len(records) <= 3, "invalid finite recipe")
    recipe = []
    for row in records:
        _require(type(row) is dict and type(row.get("op")) is str, "invalid instruction record")
        op = row["op"]
        if op == "mov":
            _require(set(row) == {"op"}, "mov has no configurable operands")
            recipe.append((op, None))
        else:
            _require(set(row) == {"op", "imm"} and type(row["imm"]) is int, "invalid immediate or register override")
            recipe.append((op, row["imm"]))
    recipe = tuple(recipe)
    _require(recipe in _RECIPES, "recipe outside the complete finite grammar")
    rebuilt = _candidate(recipe)
    # Strict wire equality avoids Python's bool == int identity ambiguity.
    _require(_wire(candidate) == _wire(rebuilt), "candidate bytes, identity or HIA model do not match its recipe")
    return recipe, rebuilt


def _proof(before, after, timeout_ms):
    before, after = verify_program(before), verify_program(after)
    receipt = validate_translation(before, after, function=FUNCTION, timeout_ms=timeout_ms)
    expected = {"schema": PROOF_SCHEMA, "profile": PROOF_PROFILE,
                "scope": "selected_public_scalar_function", "function": FUNCTION,
                "before_sha256": before.sha256, "after_sha256": after.sha256,
                "before_input_sha256": before.input_sha256, "after_input_sha256": after.input_sha256}
    _require(all(receipt.get(k) == v for k, v in expected.items()), "fresh proof does not bind exact canonical inputs")
    _require(receipt.get("status") in {"proved", "disproved", "unknown"}, "invalid fresh proof status")
    return receipt


def search_affine_candidates(offset=12, *, timeout_ms=2000):
    """Exhaust the declared grammar using actual all-input SMT comparisons.

    Every candidate, including the wrong ones, is checked. Any unknown denies
    the finite minimum certificate. A serialized certificate is evidence only.
    """
    _require(type(timeout_ms) is int and 1 <= timeout_ms <= 60000, "invalid solver timeout")
    before = verify_program(affine_program(offset))
    return _search_program(before, timeout_ms, {"offset": offset})


def search_bounded_affine_candidates(multiplier, offset, *, timeout_ms=2000):
    """Prove a byte minimum for a*x+b within the unchanged 146 recipes.

    An unknown or an empty equivalent set yields no finite minimum. Native
    construction still requires the existing independent fresh proof/byte gate.
    """
    _require(type(timeout_ms) is int and 1 <= timeout_ms <= 60000, "invalid solver timeout")
    before = verify_program(bounded_affine_program(multiplier, offset))
    result = _search_program(before, timeout_ms, {
        "target_profile": BOUNDED_AFFINE_PROFILE, "multiplier": multiplier, "offset": offset})
    result["schema"] = BOUNDED_AFFINE_SCHEMA
    return result


def _search_program(before, timeout_ms, target_fields):
    """One exhaustive search implementation for the two explicit target APIs."""
    implementation_hash = _implementation_hash()
    rows, started = [], time.perf_counter_ns()
    for candidate in enumerate_candidates():
        begin = time.perf_counter_ns()
        proof = _proof(before, candidate["program"], timeout_ms)
        rows.append({"candidate": candidate, "proof": proof, "proof_wall_ns": time.perf_counter_ns() - begin})
    complete = all(row["proof"]["status"] in {"proved", "disproved"} for row in rows)
    accepted = [row["candidate"] for row in rows if row["proof"]["status"] == "proved"]
    selected = min(accepted, key=lambda c: (c["encoded_bytes"], c["id"])) if accepted else None
    unchanged = _implementation_hash() == implementation_hash
    minimum_proved = complete and selected is not None and unchanged
    return {"schema": SCHEMA, "profile": PROFILE, "grammar": json.loads(_wire(GRAMMAR)),
            "grammar_sha256": sha256(_wire(GRAMMAR)).hexdigest(), **target_fields,
            "baseline": before.as_dict(), "baseline_sha256": before.sha256,
            "implementation_sha256": implementation_hash, "source_inputs_unchanged": unchanged,
            "candidates": rows, "candidate_count": len(rows), "accepted_count": len(accepted),
            "decided_count": sum(row["proof"]["status"] != "unknown" for row in rows),
            "selected_candidate": selected,
            "minimum_encoded_bytes": selected["encoded_bytes"] if minimum_proved else None,
            "finite_minimum_encoded_bytes_proved": minimum_proved,
            "wall_ns": time.perf_counter_ns() - started,
            "claims": {"complete_declared_grammar_enumerated": len(rows) == 146,
                       "all_input_model_equivalence_checked": complete,
                       "finite_minimum_encoded_bytes_proved": minimum_proved,
                       "native_backend_refinement_proved": False,
                       "serialized_receipt_authorizes_execution": False,
                       "runtime_optimality_established": False, "global_optimality_established": False}}


def assembly_source(candidate):
    """Regenerate assembly only from a fully checked member of the grammar."""
    recipe, _ = _checked_candidate(candidate)
    lines = [".text", ".globl calculate", ".type calculate,@function", ".p2align 0", "calculate:"]
    for op, immediate in recipe:
        if op == "mov":
            line = "movq %rdi, %rax"
        elif op == "lea":
            line = f"leaq {immediate}(%rdi), %rax"
        elif op == "imul":
            line = f"imulq ${immediate}, %rdi, %rax"
        else:
            line = f"addq ${immediate}, %rax"
        lines.append("  " + line)
    lines += ["  ret", ".size calculate, .-calculate", '.section .note.GNU-stack,"",@progbits', ""]
    return "\n".join(lines)


def _elf_layout(data):
    # Callers first run the existing bounded ELF64 ABI inspector.
    shoff = int.from_bytes(data[40:48], "little")
    shnum = int.from_bytes(data[60:62], "little")
    phoff = int.from_bytes(data[32:40], "little")
    phnum = int.from_bytes(data[56:58], "little")
    sections = []
    for index in range(shnum):
        name, typ, flags, addr, off, size, link, info, align, entsize = struct.unpack_from("<IIQQQQIIQQ", data, shoff + 64 * index)
        sections.append({"type": typ, "flags": flags, "addr": addr, "offset": off,
                         "size": size, "link": link, "entsize": entsize, "index": index})
    segments = []
    for index in range(phnum):
        typ, flags, off, va, pa, filesz, memsz, align = struct.unpack_from("<IIQQQQQQ", data, phoff + 56 * index)
        segments.append({"type": typ, "flags": flags, "offset": off, "addr": va,
                         "filesz": filesz, "memsz": memsz, "align": align})
    sym = next(section for section in sections if section["type"] == 11)
    strings = sections[sym["link"]]
    matches = []
    for at in range(sym["offset"], sym["offset"] + sym["size"], 24):
        noff, info, other, ndx, value, size = struct.unpack_from("<IBBHQQ", data, at)
        if not noff:
            continue
        start = strings["offset"] + noff
        name = data[start:data.find(b"\0", start, strings["offset"] + strings["size"])]
        if name == FUNCTION.encode():
            matches.append({"value": value, "size": size, "section": ndx, "info": info, "other": other})
    _require(len(matches) == 1, "expected exactly one entry symbol")
    return sections, segments, matches[0]


def exported_code(data):
    """Extract the actual exported bytes and check their loader mapping.

    Also used for observing the LLVM baseline, which may contain trusted CRT
    code. This helper alone does not admit arbitrary machine code or libraries.
    """
    inspect_owned_shared_elf(data, (FUNCTION,))
    sections, segments, symbol = _elf_layout(data)
    section = sections[symbol["section"]]
    offset = section["offset"] + symbol["value"] - section["addr"]
    loads = [p for p in segments if p["type"] == 1 and p["flags"] == 5
             and p["addr"] <= symbol["value"]
             and symbol["value"] + symbol["size"] <= p["addr"] + p["filesz"]]
    _require(len(loads) == 1 and loads[0]["offset"] + symbol["value"] - loads[0]["addr"] == offset,
             "symbol section and executable loader mapping disagree")
    code = data[offset:offset + symbol["size"]]
    _require(len(code) == symbol["size"], "truncated exported body")
    return {"code_hex": code.hex(), "encoded_bytes": len(code), "code_sha256": sha256(code).hexdigest(),
            "entry_va": symbol["value"], "file_offset": offset, "symbol_type": "STT_FUNC"}


def _check_symbol_lookup(data, sections, symbols, tags):
    """Keep loader hash lookups inside the exact two-entry symbol inventory.

    Merely checking a hash table's pointer is insufficient: a hostile bucket
    could index beyond the section inspected as DYNSYM. This closed profile
    permits the mandatory null symbol followed by calculate, and reconstructs
    every bloom/bucket/chain entry rather than trusting lookup metadata.
    """
    strings = sections[symbols["link"]]
    symbol_bytes = data[symbols["offset"]:symbols["offset"] + symbols["size"]]
    string_bytes = data[strings["offset"]:strings["offset"] + strings["size"]]
    _require(len(symbol_bytes) == 48 and symbol_bytes[:24] == bytes(24)
             and int.from_bytes(symbol_bytes[24:28], "little") == 1
             and string_bytes == b"\0calculate\0", "closed symbol inventory must be null followed by calculate")
    _require(4 in tags or 0x6FFFFEF5 in tags, "missing reviewed dynamic symbol lookup table")
    gnu_hash, elf_hash = 5381, 0
    for byte in FUNCTION.encode("ascii"):
        gnu_hash = (gnu_hash * 33 + byte) & 0xFFFFFFFF
        elf_hash = (elf_hash << 4) + byte
        high = elf_hash & 0xF0000000
        if high:
            elf_hash ^= high >> 24
        elf_hash &= ~high
    for tag, typ in ((4, 5), (0x6FFFFEF5, 0x6FFFFFF6)):
        if tag not in tags:
            continue
        matches = [s for s in sections if s["type"] == typ and s["addr"] == tags[tag]]
        _require(len(matches) == 1, "dynamic symbol hash table points outside its mapped section")
        table = matches[0]
        raw = data[table["offset"]:table["offset"] + table["size"]]
        if tag == 4:
            _require(len(raw) >= 8, "truncated SysV symbol lookup table")
            buckets, chains = struct.unpack_from("<II", raw)
            _require(1 <= buckets <= 64 and chains == 2, "unbounded SysV lookup inventory")
            values = [0] * buckets
            values[elf_hash % buckets] = 1
            expected = struct.pack("<" + "I" * (4 + buckets), buckets, 2, *values, 0, 0)
        else:
            _require(len(raw) >= 16, "truncated GNU symbol lookup table")
            buckets, first_symbol, bloom_size, shift = struct.unpack_from("<IIII", raw)
            _require(1 <= buckets <= 64 and first_symbol == 1 and bloom_size == 1 and shift < 32,
                     "unbounded GNU lookup inventory")
            bloom = (1 << (gnu_hash % 64)) | (1 << ((gnu_hash >> shift) % 64))
            values = [0] * buckets
            values[gnu_hash % buckets] = 1
            expected = (struct.pack("<IIIIQ", buckets, 1, 1, shift, bloom)
                        + struct.pack("<" + "I" * (buckets + 1), *values, gnu_hash | 1))
        _require(raw == expected, "dynamic lookup table could resolve outside the checked symbol inventory")


def inspect_candidate_artifact(data, candidate):
    """Check one local generated artifact against a freshly reconstructed recipe.

    This deliberately admits much less than general ELF. There is exactly one
    executable segment/body, no imports, dependencies, relocations, initializer
    or finalizer, and no configurable assembler. It is still not a general ELF
    sandbox or a formal model of loader/hardware behavior.
    """
    recipe, rebuilt = _checked_candidate(candidate)
    inventory = inspect_owned_shared_elf(data, (FUNCTION,))
    _require(not inventory["unresolved_imports"], "pure register artifact must have no imports")
    _require(data[7:9] == b"\0\0" and int.from_bytes(data[24:32], "little") == 0
             and int.from_bytes(data[48:52], "little") == 0, "unexpected ELF OS ABI, entry or flags")
    sections, segments, symbol = _elf_layout(data)
    _require(symbol["info"] == 0x12 and symbol["other"] == 0, "entry must be a global default STT_FUNC")
    symbols = next(s for s in sections if s["type"] == 11)
    authority_sections = [symbols, sections[symbols["link"]]] + [
        s for s in sections if s["type"] in {5, 6, 0x6FFFFFF6}]
    # Loader metadata cannot be a harmless nonallocated shadow of a different
    # mapped table. DT_SYMTAB/DT_STRTAB/hash pointers bind virtual addresses;
    # require these section inventories to describe the same loaded bytes.
    _require(all(s["flags"] & 2 and s["size"] for s in authority_sections),
             "dynamic authority tables must be allocated and nonempty")
    executable = [s for s in sections if s["flags"] & 4 and s["size"]]
    section = sections[symbol["section"]]
    _require(executable == [section] and section["flags"] == 6 and section["type"] == 1
             and symbol["value"] == section["addr"] and symbol["size"] == section["size"],
             "the exported entry must cover the only executable section")
    loads = [p for p in segments if p["type"] == 1]
    allowed_segments = {1, 2, 4, 0x6474E551, 0x6474E552}  # LOAD,DYNAMIC,NOTE,STACK,RELRO
    _require(all(p["type"] in allowed_segments for p in segments), "unreviewed loader segment")
    for load in loads:
        _require(load["filesz"] == load["memsz"] and load["addr"] + load["memsz"] <= 1 << 64,
                 "unexpected zero-fill or overflowing loader mapping")
        alignment = load["align"]
        _require(alignment == 4096 and load["addr"] % alignment == load["offset"] % alignment,
                 "unsupported load alignment")
    nonempty = sorted((p for p in loads if p["memsz"]), key=lambda p: p["addr"])
    for left, right in zip(nonempty, nonempty[1:]):
        _require((left["addr"] + left["memsz"] + 4095) // 4096 * 4096 <= right["addr"] // 4096 * 4096,
                 "overlapping load pages could replace checked executable bytes")
    code_loads = [p for p in loads if p["flags"] & 1]
    _require(len(code_loads) == 1 and code_loads[0]["addr"] == symbol["value"]
             and code_loads[0]["filesz"] == symbol["size"]
             and code_loads[0]["offset"] == section["offset"],
             "only the exact exported body may occupy the executable load segment")
    for item in [s for s in sections if s["flags"] & 2 and s["size"]]:
        _require(item["type"] != 8 and item["flags"] & ~7 == 0, "unreviewed allocated section")
        mappings = [p for p in loads if p["addr"] <= item["addr"]
                    and item["addr"] + item["size"] <= p["addr"] + p["filesz"]
                    and p["offset"] + item["addr"] - p["addr"] == item["offset"]]
        _require(len(mappings) == 1, "allocated section does not map to its actual loaded bytes")
    _require(not any(s["type"] in {4, 9, 14, 15, 16} and s["size"] for s in sections),
             "relocations or constructor/destructor arrays are forbidden")
    dynamic = [p for p in segments if p["type"] == 2]
    _require(len(dynamic) == 1, "expected one loader dynamic table")
    d = dynamic[0]
    dsections = [s for s in sections if s["type"] == 6]
    _require(len(dsections) == 1 and all(dsections[0][a] == d[b] for a, b in
             (("offset", "offset"), ("addr", "addr"), ("size", "filesz"))), "dynamic table mapping differs")
    # A closed whitelist excludes DT_NEEDED, init/fini, relocation, audit,
    # filtering, symbol versioning and implicit code-execution hooks.
    allowed_tags = {4, 5, 6, 10, 11, 30, 0x6FFFFEF5, 0x6FFFFFFB}
    tags, ended = {}, False
    for at in range(d["offset"], d["offset"] + d["filesz"], 16):
        tag, value = struct.unpack_from("<QQ", data, at)
        if ended or tag == 0:
            _require(tag == 0 and value == 0, "nonzero dynamic data after terminator")
            ended = True
            continue
        _require(tag in allowed_tags and tag not in tags, "unreviewed or duplicate dynamic loader tag")
        tags[tag] = value
    _require(ended and tags.get(30) == 8 and tags.get(0x6FFFFFFB) == 1,
             "expected eager binding without additional dynamic flags")
    _check_symbol_lookup(data, sections, symbols, tags)
    body = exported_code(data)
    _require(body["code_hex"] == rebuilt["expected_code_hex"] and body["encoded_bytes"] == rebuilt["encoded_bytes"],
             "actual exported machine bytes differ from the closed encoder")
    return {"schema": "hepta.hia.x86-encoded-artifact.v1", "profile": PROFILE,
            "candidate_id": rebuilt["id"], "artifact_sha256": sha256(data).hexdigest(),
            "artifact_bytes": len(data), **body, "binary_inventory": inventory,
            "exact_encoder_bytes_checked": True, "no_other_executable_body": True,
            "imports_relocations_initializers_absent": True,
            "native_backend_refinement_proved": False, "arbitrary_elf_safety_proved": False}


def build_candidate(baseline, candidate, output, *, clang="clang", timeout_ms=2000):
    """Freshly prove and locally assemble one closed recipe, then check its bytes."""
    recipe, candidate = _checked_candidate(candidate)
    baseline = verify_program(baseline)
    proof = _proof(baseline, candidate["program"], timeout_ms)
    _require(proof["status"] == "proved", "candidate is not freshly proved equivalent to the baseline")
    _require(platform.system() == "Linux" and platform.machine() in {"x86_64", "amd64"},
             "native search profile requires Linux x86-64")
    found = shutil.which(clang)
    _require(found is not None, "actual Clang 20+ required")
    compiler = Path(found).resolve()
    compiler_hash, implementation_hash = digest_executable(compiler), _implementation_hash()
    version = run_bounded([str(compiler), "--version"], timeout=10, stdout_limit=65536, stderr_limit=65536)
    target = run_bounded([str(compiler), "-dumpmachine"], timeout=10, stdout_limit=65536, stderr_limit=65536)
    _require(not version.returncode and not target.returncode
             and re.search(r"clang version (?:2[0-9]|[3-9][0-9])\.", version.stdout) is not None
             and target.stdout.strip() in {TARGET, "x86_64-pc-linux-gnu"}, "unsupported assembler driver or target")
    destination = Path(os.path.abspath(output))
    _require(not destination.exists() and not destination.is_symlink() and destination.parent.is_dir(),
             "output must be a new file in an existing directory")
    assembly = assembly_source(candidate)
    flags = ["--target=" + TARGET, "-x", "assembler", "-shared", "-nostdlib",
             "-Wl,-z,noexecstack,-z,relro,-z,now"]
    with tempfile.TemporaryDirectory(prefix=".hia-x86-", dir=destination.parent) as temporary:
        source, artifact = Path(temporary) / "candidate.S", Path(temporary) / "candidate.so"
        source.write_text(assembly, encoding="ascii")
        run = run_bounded([str(compiler), *flags, str(source), "-o", str(artifact)],
                          timeout=30, stdout_limit=65536, stderr_limit=1048576)
        _require(run.returncode == 0, "assembler/linker rejected closed recipe: " + run.stderr[:3000])
        data = _read_artifact(artifact)
        inventory = inspect_candidate_artifact(data, candidate)
        _require(digest_executable(compiler) == compiler_hash and _implementation_hash() == implementation_hash,
                 "compiler or implementation changed during assembly")
        publish_verified(artifact, destination, data)
        try:
            _require(digest_executable(compiler) == compiler_hash and _implementation_hash() == implementation_hash,
                     "compiler or implementation changed during publication")
            verify_published(artifact, destination, data)
        except Exception:
            withdraw_own_link(artifact, destination)
            raise
    return {"schema": "hepta.hia.x86-candidate-native.v1", "profile": PROFILE,
            "status": "model_proved_and_native_bytes_checked_not_executed", "output": str(destination),
            "candidate": candidate, "translation_receipt": proof, "artifact_sha256": inventory["artifact_sha256"],
            "artifact_bytes": inventory["artifact_bytes"], "inspection": inventory,
            "assembly_source": assembly, "assembly_sha256": sha256(assembly.encode()).hexdigest(),
            "implementation_sha256": implementation_hash, "flags": flags,
            "toolchain": {"path": str(compiler), "sha256": compiler_hash,
                          "version": version.stdout.splitlines()[0], "default_target": target.stdout.strip()},
            "claims": {"fresh_all_input_model_equivalence_proved": True, "exact_native_encoder_bytes_checked": True,
                       "native_execution_qualified": False, "native_backend_refinement_proved": False,
                       "whole_language_safety_proved": False, "global_optimality_established": False}}
