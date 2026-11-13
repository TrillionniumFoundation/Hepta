"""Reproduce the fixed-Core HIA bootstrap and retain every native generation.

build_seed creates B0 with the Python assembler/verifier/direct backend. From B1
onward a disposable stdlib-only child executes the previous HIA-generated flat
image. Independent host-oracle qualification also uses Python after B0; it never
translates a successor or substitutes for a native generation.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, FIRST_COMPLETED, wait
from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import shutil
import struct
import subprocess
import sys
from threading import BoundedSemaphore
import time

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))
from tools.hia_selfhost_contract import CONTRACT_PATH, file_digests, validate_contract
from tools.hia_selfhost_cases import (backward_bytesum_source, backward_chain_source,
                                     call_graph_invalid_sources, recursion_refusals)
SOURCE = ROOT / "examples/hia_bootstrap/selfhost.hepta"
SAMPLE = ROOT / "examples/hia_bootstrap/bytesum.hepta"
CHILD = ROOT / "tools/hia_selfhost_child.py"
CAPACITY = 1 << 20
INVALID, NO_SPACE = 0xffffffff, 0xfffffffe
# Explicit per-phase transport; never enabled for seed or generation controls.
NATIVE_OBSERVER = None
NATIVE_LINKED_OBSERVER = None
QUALIFICATION_WORKERS = 2
QUALIFICATION_FAMILIES = ("capacity", "cfg", "elf", "chain", "owned", "bulk",
                          "loan", "resource", "tail", "select", "effects", "multi", "keyword", "signed", "scalar-casts", "explicit-traps", "cli", "names", "exports")
PHASE_REFERENCE_FILES = {
    "exports": "independent-exports-reference.json",
    "names": "independent-names-reference.json",
    "cli": "independent-cli-reference.json",
    "explicit-traps": "independent-explicit-traps-reference.json",
    "resource": "independent-resource-reference.json",
    "bulk": "independent-bulk-reference.json",
    "loan": "independent-loan-reference.json",
    "cfg": "independent-cfg-worklist-reference.json",
    "capacity": "independent-capacity-reference.json",
    "tail": "independent-tail-reference.json",
    "select": "independent-select-reference.json",
    "effects": "independent-effect-reference.json",
    "multi": "independent-multi-result-reference.json",
    "keyword": "independent-keyword-reference.json",
    "signed": "independent-signed-reference.json",
    "scalar-casts": "independent-scalar-cast-reference.json",
}


def digest(data):
    return sha256(data).hexdigest()


def source_manifest():
    return {**file_digests(), CONTRACT_PATH: digest((ROOT / CONTRACT_PATH).read_bytes())}


def checkout_identity():
    """Do not attribute a source-only cold export to an ancestor git checkout."""
    try:
        root = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "--show-toplevel"],
                              capture_output=True, text=True, timeout=5)
        if root.returncode or Path(root.stdout.strip()).resolve() != ROOT:
            return {"kind": "source_export", "identity_authority": "source_manifest"}
        values = {}
        for label, args in (("commit", ["rev-parse", "HEAD"]),
                            ("tree", ["rev-parse", "HEAD^{tree}"]),
                            ("status", ["status", "--porcelain", "--untracked-files=all"])):
            result = subprocess.run(["git", "-C", str(ROOT), *args],
                                    capture_output=True, text=True, timeout=5, check=True)
            values[label] = result.stdout.strip()
        return {"kind": "git_checkout", "commit": values["commit"],
                "tree": values["tree"], "worktree_clean": not values["status"],
                "identity_authority": "source_manifest; git metadata is supplemental"}
    except (OSError, subprocess.SubprocessError):
        return {"kind": "source_export", "identity_authority": "source_manifest"}


def build_seed(directory, source=None):
    """The explicit B0 trust boundary; never called for a later generation."""
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program_native import emit_program_machine, compile_program_machine
    source = SOURCE.read_bytes() if source is None else source
    checked = assemble_program(source)
    machine = emit_program_machine(checked, foreign_buffer_exports=(("f0", CAPACITY),))
    output = Path(directory) / "B0.so"
    receipt = compile_program_machine(machine, program=checked, output=output, linker="ld")
    receipt["source_sha256"] = digest(source)
    receipt["seed_only"] = True
    document = checked.as_dict()
    receipt["source_structure"] = {
        "functions": len(document["functions"]),
        "instructions": sum(len(block["ops"]) for fn in document["functions"] for block in fn["blocks"]),
        "blocks": sum(len(fn["blocks"]) for fn in document["functions"]),
        "backward_direct_calls": [
            {"caller": fn["name"], "callee": op["attrs"]["function"]}
            for fn in document["functions"] for block in fn["blocks"] for op in block["ops"]
            if op["op"] == "call" and int(op["attrs"]["function"][1:]) < int(fn["name"][1:])],
        "direct_tail_self_calls": [
            {"caller": fn["name"], "block": block["id"]}
            for fn in document["functions"] for block in fn["blocks"]
            if block["ops"] and block["ops"][-1]["op"] == "call"
            and block["ops"][-1]["attrs"]["function"] == fn["name"]
            and block["term"] == {"op": "ret", "values": [block["ops"][-1]["out"][0]["name"]]}],
    }
    receipt["support_contract_sha256"] = digest((ROOT / CONTRACT_PATH).read_bytes())
    receipt["python"] = {"path": str(Path(sys.executable).resolve()),
                         "sha256": digest(Path(sys.executable).read_bytes()),
                         "version": sys.version, "isolated": bool(sys.flags.isolated),
                         "no_site": bool(sys.flags.no_site)}
    module_files = {}
    for name, module in tuple(sys.modules.items()):
        if name == "hepta" or name.startswith("hepta."):
            path = Path(module.__file__).resolve()
            relative = path.relative_to(ROOT).as_posix()
            module_files[relative] = digest(path.read_bytes())
    receipt["loaded_seed_modules"] = module_files
    (Path(directory) / "B0.receipt.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    return output, receipt


def invoke(directory, label, image, source, *, image_format="flat-x86-64",
           capacity=CAPACITY, workspace_size=CAPACITY, workspace_fill=0,
           output_initial=None, observe_trap_writes=False):
    """Copy private inputs and run one pinned artifact under fixed limits."""
    if NATIVE_LINKED_OBSERVER is not None and image_format == 'linked-selfhost':
        from tools.hia_selfhost_linked_observer import invoke as observe_linked_native
        return observe_linked_native(directory,label,NATIVE_LINKED_OBSERVER,image,source,capacity=capacity,
            workspace_size=workspace_size,workspace_fill=workspace_fill,
            output_initial=output_initial,observe_trap_writes=observe_trap_writes)
    if NATIVE_OBSERVER is not None and image_format == 'flat-x86-64':
        from tools.hia_selfhost_native_observer import invoke as observe_native
        return observe_native(directory,label,NATIVE_OBSERVER,image,source,capacity=capacity,
            workspace_size=workspace_size,workspace_fill=workspace_fill,
            output_initial=output_initial,observe_trap_writes=observe_trap_writes)
    directory, image = Path(directory), Path(image)
    source_path, output_path = directory / (label + ".input.bin"), directory / (label + ".output.bin")
    request_path = directory / (label + ".request.json")
    source_path.write_bytes(source)
    child_hash = digest(CHILD.read_bytes())
    request = {"format": image_format, "image": str(image.resolve()),
               "image_sha256": digest(image.read_bytes()), "source": str(source_path.resolve()),
               "source_sha256": digest(source), "capacity": capacity,
               "workspace_size": workspace_size, "workspace_fill": workspace_fill,
               "output": str(output_path.resolve())}
    if output_initial is not None:
        if not isinstance(output_initial, bytes) or len(output_initial) != capacity:
            raise ValueError("output preimage must match the capacity")
        request["output_initial_hex"] = output_initial.hex()
    if observe_trap_writes:
        request["observe_trap_writes"] = True
    request_path.write_text(json.dumps(request, sort_keys=True) + "\n")
    started = time.monotonic_ns()
    try:
        process = subprocess.run([sys.executable, "-I", "-S", "-B", str(CHILD), str(request_path.resolve())],
                                 cwd=directory, capture_output=True, text=True, timeout=20)
    except subprocess.TimeoutExpired as exc:
        (directory / (label + ".stdout.log")).write_bytes(exc.stdout or b"")
        (directory / (label + ".stderr.log")).write_bytes(exc.stderr or b"")
        result = {"status": "timeout", "wall_limit_seconds": 20}
    else:
        (directory / (label + ".stdout.log")).write_text(process.stdout)
        (directory / (label + ".stderr.log")).write_text(process.stderr)
        if process.returncode:
            result = {"status": "child_failed", "returncode": process.returncode,
                      "stderr": process.stderr[-4096:]}
        else:
            result = json.loads(process.stdout)
    result.update({"case": label, "input_sha256": digest(source), "input_bytes": len(source),
                   "artifact_sha256": request["image_sha256"], "format": image_format,
                   "runner_sha256": child_hash, "wall_elapsed_ns": time.monotonic_ns() - started})
    if digest(CHILD.read_bytes()) != child_hash or digest(image.read_bytes()) != request["image_sha256"]:
        raise AssertionError("runner or artifact changed during invocation")
    output_exists = output_path.exists()
    output = output_path.read_bytes()[:capacity] if output_exists else b""
    if observe_trap_writes:
        initial = output_initial if output_initial is not None else bytes([0xa5]) * capacity
        result["shared_output_observation"] = {
            "available": output_exists and len(output) == capacity,
            "initial_sha256": digest(initial), "observed_sha256": digest(output),
            "observed_bytes": len(output), "unchanged": output == initial,
        }
    (directory / (label + ".receipt.json")).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result, output


def compile_stage(directory, label, image, source, *, image_format="flat-x86-64", workspace_fill=0,
                  output_extension=".image.bin"):
    compiler_bytes = Path(image).read_bytes()
    result, output = invoke(directory, label, image, source, image_format=image_format,
                            workspace_fill=workspace_fill)
    # These are publication conditions, including under Python -O.  In
    # particular, bool/float zero is not a successful native integer status,
    # and a missing/truthy custody observation is not an unchanged-source
    # receipt.  Validate the captured invocation before creating an image.
    if (type(result) is not dict or type(output) is not bytes
            or result.get("status") != "returned"
            or type(result.get("abi_status")) is not int or result["abi_status"] != 0
            or type(result.get("core_u32")) is not int
            or not 0 < result["core_u32"] <= min(CAPACITY, len(output))
            or result.get("source_unchanged") is not True
            or type(result.get("forbidden_compiler_modules_loaded")) is not list
            or result["forbidden_compiler_modules_loaded"] != []
            or result.get("input_sha256") != digest(source)
            or type(result.get("input_bytes")) is not int or result["input_bytes"] != len(source)
            or result.get("artifact_sha256") != digest(compiler_bytes)
            or result.get("format") != image_format
            or Path(image).read_bytes() != compiler_bytes):
        raise AssertionError({"compile_failed": label, "receipt": result})
    size = result["core_u32"]
    produced = output[:size]
    path = Path(directory) / (label + output_extension)
    path.write_bytes(produced)
    result.update({"produced_image": str(path), "produced_bytes": size,
                   "produced_sha256": digest(produced)})
    (Path(directory) / (label + ".receipt.json")).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return path, result


def mutate_compiler(source):
    """An explicit source edit to code generation, not a source translator.

    The wrapper reserves 80 bytes instead of 64 while retaining 16-byte stack
    alignment. M1 still has its predecessor's 64-byte outer wrapper; M2 acquires
    the changed wrapper and M3 must reproduce M2 exactly.
    """
    contract = json.loads((ROOT / CONTRACT_PATH).read_text())
    wrapper = contract["compiler_symbols"]["mutation_wrapper"].encode("ascii")
    start = source.index(b"\nfn " + wrapper + b"(")
    end = source.index(b"\nend\n", start)
    section = source[start:end]
    old, new = b'{"value":64}', b'{"value":80}'
    assert section.count(old) == 1
    return source[:start] + section.replace(old, new) + source[end:]


def hash_reference(data):
    value = 5381
    for byte in data:
        value = ((value * 33) ^ byte) & 0xffffffff
    return value


def readonly_call_source():
    """Readonly aliases are legal call arguments, unlike edge transfers."""
    return (b"hia-asm.v1 hepta.hia.program.v8 selfhost\n"
        b"fn f0(v0:readbuf,v1:mutbuf,v2:mutbuf) -> (u32) effects(read,write,trap) entry(b0)\n"
        b"block b0(v0:readbuf,v1:mutbuf,v2:mutbuf)\n"
        b'  v3:u32 = call(v0,v0) {"function":"f1"}\n  ret(v3)\nend\n'
        b"fn f1(v0:readbuf,v1:readbuf) -> (u32) effects(read,write,trap) entry(b0)\n"
        b"block b0(v0:readbuf,v1:readbuf)\n"
        b"  v2:usize = buffer.len(v0)\n  v3:usize = buffer.len(v1)\n"
        b"  v4:usize = int.add.wrap(v2,v3)\n"
        b'  v5:u32 = int.cast(v4) {"mode":"wrap"}\n  ret(v5)\nend\n')


def invalid_sources(sample):
    extra = (b"block b4()\n  v28:u32 = const() {\"value\":0}\n  ret(v28)\n")
    header = (b"hia-asm.v1 hepta.hia.program.v8 selfhost\n"
        b"fn f0(v0:readbuf,v1:mutbuf,v2:mutbuf) -> (u32) effects(read,write,trap) entry(b0)\n"
        b"block b0(v0:readbuf,v1:mutbuf,v2:mutbuf)\n")
    invalid = {
        "unknown-opcode": sample.replace(b"int.mul.wrap", b"int.bad.wrap", 1),
        "missing-end": sample.rsplit(b"end\n", 1)[0],
        "overflow-u64": sample.replace(b'{"value":5381}', b'{"value":18446744073709551616}', 1),
        "overflow-u32": sample.replace(b'{"value":5381}', b'{"value":4294967296}', 1),
        "duplicate-ssa": sample.replace(b"v20:u32 = call", b"v17:u32 = call", 1),
        "out-of-scope": sample.replace(b"call(v17,v19)", b"call(v10,v19)", 1),
        "absent-block": sample.replace(b"jump b1(", b"jump b99(", 1),
        "edge-type": sample.replace(b"b1(v0,v1,v2,v3,v4,v5)", b"b1(v0,v1,v2,v3,v3,v5)", 1),
        "call-type": sample.replace(b"call(v17,v19)", b"call(v19,v17)", 1),
        "recursive-call-signature": sample.replace(b'{"function":"f1"}', b'{"function":"f0"}', 1),
        "mutable-alias": sample.replace(b"b1(v0,v1,v2,v3,v4,v5)", b"b1(v0,v1,v1,v3,v4,v5)", 1),
        "readonly-jump-alias": header + b"  jump b1(v0,v0)\nblock b1(v3:readbuf,v4:readbuf)\n"
            b'  v5:u32 = const() {"value":0}\n  ret(v5)\nend\n',
        "readonly-branch-alias": header + b'  v3:bool = const() {"value":false}\n'
            b"  branch v3 b1(v0,v0) b2()\nblock b1(v4:readbuf,v5:readbuf)\n"
            b'  v6:u32 = const() {"value":0}\n  ret(v6)\nblock b2()\n'
            b'  v7:u32 = const() {"value":0}\n  ret(v7)\nend\n',
        "readonly-write": sample.replace(b"  v20:u32 = call", b"  _ = buffer.store(v13,v16,v19)\n  v20:u32 = call", 1),
        "unreachable-block": sample.replace(b"end\nfn f1", extra + b"end\nfn f1", 1),
        "duplicate-function": sample.replace(b"fn f1(", b"fn f0(", 1),
        "quoted-declaration": sample.replace(b"fn f1(", b'fn "f1"(', 1),
        "unquoted-call": sample.replace(b'{"function":"f1"}', b'{"function":f1}', 1),
        "leading-zero": sample.replace(b'{"value":5381}', b'{"value":05381}', 1),
        "invalid-byte": sample + b"\x00",
        "empty-source": b"",
    }
    # These are required boundaries in the existing hia-asm.v1 regex grammar,
    # not just a preference for the renderer's whitespace spelling.
    spacing = {
        "function-adjacency": (b"fn f0(", b"fn f0 ("),
        "block-adjacency": (b"block b0(", b"block b0 ("),
        "effects-adjacency": (b"effects(", b"effects ("),
        "entry-adjacency": (b"entry(b0)", b"entry (b0)"),
        "entry-open-adjacency": (b"entry(b0)", b"entry( b0)"),
        "entry-close-adjacency": (b"entry(b0)", b"entry(b0 )"),
        "arrow-adjacency": (b"->", b"- >"),
        "return-adjacency": (b"ret(v25)", b"ret (v25)"),
        "edge-adjacency": (b"jump b1(", b"jump b1 ("),
        "branch-separation": (b") b3(v7,v8,v10)", b")b3(v7,v8,v10)"),
        "opcode-adjacency": (b"buffer.len(v0)", b"buffer.len (v0)"),
        "constant-attribute-separation": (b"const() {", b"const(){"),
        "call-attribute-separation": (b"call(v17,v19) {", b"call(v17,v19){"),
        "cast-attribute-separation": (b"int.cast(v25) {", b"int.cast(v25){"),
        "effects-separation": (b"(u32) effects", b"(u32)effects"),
        "entry-separation": (b"trap) entry", b"trap)entry"),
    }
    for name, (old, new) in spacing.items():
        assert old in sample, name
        invalid[name] = sample.replace(old, new, 1)
    return invalid


def independent_call_reference(sample):
    """Record the general Core's distinct acceptance and scalar-execution view.

    Called before B0. The non-tail/mutual fixtures are legal general Core but
    refused by this native profile; never label that as Core invalidity.
    """
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program import HIAProgramRejected, execute_program
    backward = assemble_program(backward_bytesum_source(sample))
    chain = assemble_program(backward_chain_source())
    observations = []
    for left, right in ((0, 0), (5381, 255), (0xffffffff, 1), (0x80000000, 128)):
        observation = execute_program(backward, "f2", [left, right])
        assert observation["result"] == ((left * 33) ^ right) & 0xffffffff
        observations.append(observation)
    observation = execute_program(chain, "f127", [1], max_call_depth=128)
    assert observation["result"] == 127
    observations.append(observation)
    refusals = []
    for label, source in call_graph_invalid_sources(sample).items():
        try:
            assemble_program(source)
        except HIAProgramRejected as exc:
            refusals.append({"case": label, "source_sha256": digest(source),
                             "general_core": "rejected", "code": exc.code})
        else:
            raise AssertionError("invalid call source passed general Core: " + label)
    for label, source in recursion_refusals().items():
        checked = assemble_program(source)
        refusals.append({"case": label, "source_sha256": digest(source),
                         "general_core": "accepted", "core_sha256": checked.sha256,
                         "selfhost_profile_expected": "rejected: acyclic call graph required"})
    return {"general_core_observations": observations, "admission_differences": refusals}


def inspect_selfhost_object(data):
    """Read-only independent inspection; never constructs or repairs an object."""
    if len(data) < 64:
        raise ValueError("truncated HIA ELF object")
    header = struct.unpack_from("<16sHHIQQQIHHHHHH", data)
    ident, kind, machine, version, entry, phoff, shoff, flags, ehsize, phsize, phnum, shsize, shnum, names_index = header
    if (ident != b"\x7fELF\x02\x01\x01\x00" + b"\0" * 8
            or (kind, machine, version, entry, phoff, flags, ehsize, phsize, phnum, shsize, shnum, names_index)
            != (1, 62, 1, 0, 0, 0, 64, 0, 0, 64, 6, 4)
            or shoff % 8 or shoff + 6 * 64 != len(data)):
        raise ValueError("ELF header is outside the closed HIA ET_REL profile")
    sections = [struct.unpack_from("<IIQQQQIIQQ", data, shoff + i * 64) for i in range(6)]
    if any(sections[0]):
        raise ValueError("non-null ELF null section")
    for row in sections[1:]:
        if row[3] != 0 or row[4] < 64 or row[4] + row[5] > shoff:
            raise ValueError("ELF section outside the object payload")
    names = data[sections[4][4]:sections[4][4] + sections[4][5]]
    expected_names = b"\0.text\0.symtab\0.strtab\0.shstrtab\0.note.GNU-stack\0"
    if names != expected_names or [row[0] for row in sections] != [0, 1, 7, 15, 23, 33]:
        raise ValueError("ELF section-name inventory differs")
    text, sym, strings, shstrings, stack = sections[1:]
    if ((text[1], text[2], text[4], text[6], text[7], text[8], text[9]) != (1, 6, 64, 0, 0, 16, 0)
            or (sym[1], sym[2], sym[5], sym[6], sym[7], sym[8], sym[9]) != (2, 0, 72, 3, 2, 8, 24)
            or (strings[1], strings[2], strings[5], strings[6], strings[7], strings[8], strings[9]) != (3, 0, 4, 0, 0, 1, 0)
            or (shstrings[1], shstrings[2], shstrings[5], shstrings[6], shstrings[7], shstrings[8], shstrings[9]) != (3, 0, 49, 0, 0, 1, 0)
            or (stack[1], stack[2], stack[5], stack[6], stack[7], stack[8], stack[9]) != (1, 0, 0, 0, 0, 1, 0)):
        raise ValueError("ELF section flags or links differ")
    if (sym[4] != ((64 + text[5] + 7) & ~7) or strings[4] != sym[4] + 72
            or shstrings[4] != strings[4] + 4 or stack[4] != shstrings[4] + 49):
        raise ValueError("ELF payload layout differs")
    symbols = [struct.unpack_from("<IBBHQQ", data, sym[4] + i * 24) for i in range(3)]
    if (any(symbols[0]) or symbols[1] != (0, 3, 0, 1, 0, 0)
            or symbols[2][:5] != (1, 18, 0, 1, 0) or not 0 < symbols[2][5] <= text[5]
            or data[strings[4]:strings[4] + 4] != b"\0f0\0"):
        raise ValueError("ELF symbol inventory differs")
    return {"format": "ELF64-ET_REL", "machine": "EM_X86_64", "exports": ["f0"],
            "undefined_symbols": [], "external_relocations": [], "nonexecuting_stack_note": True,
            "text_offset": 64, "text_bytes": text[5], "text_sha256": digest(data[64:64 + text[5]]),
            "entry_wrapper_bytes": symbols[2][5], "object_sha256": digest(data)}


def observe_native_tool(directory, label, tool_name, arguments):
    path = shutil.which(tool_name)
    if path is None:
        raise RuntimeError("ELF qualification requires " + tool_name)
    path = Path(path).resolve()
    before = digest(path.read_bytes())
    command = [str(path), *map(str, arguments)]
    started = time.monotonic_ns()
    completed = subprocess.run(command, capture_output=True, timeout=20)
    (directory / (label + ".stdout.log")).write_bytes(completed.stdout)
    (directory / (label + ".stderr.log")).write_bytes(completed.stderr)
    receipt = {"command": command, "tool_sha256": before, "returncode": completed.returncode,
               "stdout_sha256": digest(completed.stdout), "stderr_sha256": digest(completed.stderr),
               "wall_elapsed_ns": time.monotonic_ns() - started}
    (directory / (label + ".command.json")).write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    if digest(path.read_bytes()) != before or completed.returncode:
        raise AssertionError({"native_tool_failed": label, "receipt": receipt})
    return receipt


def qualify_elf_outputs(directory, compilers, sample, checks):
    observations = []
    def object_source(source):
        return source.replace(b"hepta.hia.program.v8 selfhost\n",
                              b"hepta.hia.program.v8 selfhost_elf\n", 1)
    for label, compiler, own_source in compilers:
        for subject, source, flat in (("compiler", own_source, compiler),
                                     ("bytesum", sample, directory / (label + "-bytesum.image.bin"))):
            case = label + "-elf-" + subject
            obj, compilation = compile_stage(directory, case, compiler, object_source(source), output_extension=".o")
            inventory = inspect_selfhost_object(obj.read_bytes())
            checks[case + "_text_matches_flat"] = inventory["text_sha256"] == digest(flat.read_bytes())
            tools = [observe_native_tool(directory, case + "-readelf", "readelf", ["-W", "-h", "-S", "-s", "-r", obj]),
                     observe_native_tool(directory, case + "-objdump", "objdump", ["-d", "--disassemble=f0", obj])]
            linked = directory / (case + ".so")
            tools.append(observe_native_tool(directory, case + "-link", "ld",
                ["-m", "elf_x86_64", "-shared", "-z", "defs", "-z", "noexecstack",
                 "-z", "relro", "-z", "now", "--build-id=none", obj, "-o", linked]))
            checks[case + "_independent_tools_accept"] = all(row["returncode"] == 0 for row in tools)
            observations.append({"case": case, "compilation": compilation, "inventory": inventory,
                                 "tool_observations": tools, "linked_sha256": digest(linked.read_bytes())})
            if subject == "compiler":
                rebuilt, result = compile_stage(directory, case + "-rebuild", linked, own_source,
                                                 image_format="linked-selfhost")
                checks[case + "_linked_self_rebuild"] = rebuilt.read_bytes() == flat.read_bytes()
                observations.append(result)
            else:
                for index, data in enumerate((b"", bytes(range(256)) * 4)):
                    result, output = invoke(directory, case + "-run-" + str(index), linked, data,
                                            image_format="linked-selfhost", capacity=1, workspace_size=1)
                    checks[case + "_behavior_" + str(index)] = (result.get("status") == "returned"
                        and result.get("core_u32") == hash_reference(data) and result.get("source_unchanged")
                        and output == bytes([hash_reference(data) & 255]))
                    observations.append(result)
            result, _ = invoke(directory, case + "-short-output", compiler, object_source(source),
                               capacity=compilation["produced_bytes"] - 1)
            checks[case + "_short_output_transactional"] = (result.get("status") == "returned"
                and result.get("core_u32") == NO_SPACE and result.get("output_unchanged"))
            observations.append(result)
        rejected = {"bad-call": call_graph_invalid_sources(sample)["backward-signature"],
                    "recursive": recursion_refusals()["mutual-recursion"]}
        for name, bad in rejected.items():
            result, _ = invoke(directory, label + "-elf-reject-" + name, compiler, object_source(bad))
            checks[label + "_elf_reject_" + name] = (result.get("status") == "returned"
                and result.get("core_u32") == INVALID and result.get("output_unchanged")
                and result.get("source_unchanged"))
            observations.append(result)
    return observations


def _phase_manifest_digest(manifest):
    return digest(json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode())


def _phase_inputs(directory, family, compiler, label):
    paths = {"native_observer": directory / "native-observer.elf",
             "linked_observer": directory / "linked-observer.elf",
             "compiler": compiler, "source": SOURCE, "sample": SAMPLE,
             "modified_source": directory / "modified-selfhost.hepta"}
    if family in PHASE_REFERENCE_FILES:
        paths["reference"] = directory / PHASE_REFERENCE_FILES[family]
    if family == "elf":
        paths["sample_image"] = directory / (label + "-bytesum.image.bin")
    return {name: {"path": str(Path(path).resolve()), "sha256": digest(Path(path).read_bytes())}
            for name, path in paths.items()}


def _read_phase_inputs(inputs):
    result = {}
    for name, identity in inputs.items():
        data = Path(identity["path"]).read_bytes()
        if digest(data) != identity["sha256"]:
            raise ValueError("qualification phase input changed: " + name)
        result[name] = data
    return result


def qualification_phase(request_path):
    """Run one closed family in a fresh host-oracle process, never a successor."""
    request = json.loads(Path(request_path).read_text())
    if (set(request) != {"schema", "family", "compiler_label", "directory", "inputs", "source_manifest_sha256"}
            or request["schema"] != "hepta.hia.selfhost-phase-request.v1"
            or request["family"] not in QUALIFICATION_FAMILIES
            or request["compiler_label"] not in {"original", "modified"}):
        raise ValueError("unknown qualification phase request")
    family, label = request["family"], request["compiler_label"]
    expected_inputs = {"native_observer", "linked_observer", "compiler", "source", "sample", "modified_source"}
    if family in PHASE_REFERENCE_FILES:
        expected_inputs.add("reference")
    if family == "elf":
        expected_inputs.add("sample_image")
    if set(request["inputs"]) != expected_inputs:
        raise ValueError("qualification phase input inventory differs")
    validate_contract()
    before = source_manifest()
    if _phase_manifest_digest(before) != request["source_manifest_sha256"]:
        raise ValueError("qualification phase source identity differs")
    data = _read_phase_inputs(request["inputs"])
    directory = Path(request["directory"])
    compiler = Path(request["inputs"]["compiler"]["path"])
    # This is a content-bound, freshly HIA-emitted adapter, not a cached child.
    # The module imported by family helpers must share this explicit binding.
    import tools.qualify_hia_selfhost as runtime
    runtime.NATIVE_OBSERVER = Path(request['inputs']['native_observer']['path'])
    runtime.NATIVE_LINKED_OBSERVER = Path(request['inputs']['linked_observer']['path'])
    global NATIVE_OBSERVER, NATIVE_LINKED_OBSERVER
    NATIVE_OBSERVER = runtime.NATIVE_OBSERVER
    NATIVE_LINKED_OBSERVER = runtime.NATIVE_LINKED_OBSERVER
    compilers = ((label, compiler),)
    reference = json.loads(data["reference"]) if "reference" in data else None
    checks = {}
    started = time.monotonic_ns()
    if family == "elf":
        source = data["source"] if label == "original" else data["modified_source"]
        # This is the pinned bytesum artifact produced earlier by this same
        # fresh generation chain, transported into this worker's own directory.
        (directory / (label + "-bytesum.image.bin")).write_bytes(data["sample_image"])
        observations = qualify_elf_outputs(directory, ((label, compiler, source),), data["sample"], checks)
    elif family == "exports":
        from tools.qualify_hia_selfhost_exports import qualify as qualify_exports
        observations = qualify_exports(directory, compiler, checks, reference, label)
    elif family == "names":
        from tools.hia_selfhost_names import qualify as qualify_names
        observations = qualify_names(directory, compiler, checks, reference, label)
    elif family == "cli":
        from tools.qualify_hia_selfhost_cli import qualify as qualify_cli
        source = data["source"] if label == "original" else data["modified_source"]
        observations = qualify_cli(directory, compiler, source, checks, reference, label)
    elif family == "resource":
        from tools.hia_selfhost_resources import qualify_resources
        observations = qualify_resources(directory, compilers, checks, reference)
    elif family == "bulk":
        from tools.hia_selfhost_bulk import qualify_bulk
        observations = qualify_bulk(directory, compilers, checks, reference)
    elif family == "loan":
        from tools.hia_selfhost_loans import qualify_loans
        observations = qualify_loans(directory, compilers, checks, reference)
    elif family == "cfg":
        from tools.hia_selfhost_cfg_worklist import qualify as qualify_cfg
        observations = qualify_cfg(directory, compilers, checks, reference)
    elif family == "effects":
        from tools.hia_selfhost_effects import qualify as qualify_effects
        observations = qualify_effects(directory, compilers, checks, reference)
    elif family == "multi":
        from tools.hia_selfhost_multi_results import qualify as qualify_multi
        observations = qualify_multi(directory, compilers, checks, reference)
    elif family == "explicit-traps":
        from tools.hia_selfhost_traps import qualify as qualify_traps
        observations = qualify_traps(directory, compilers, checks, reference)
    elif family == "signed":
        from tools.hia_selfhost_signed_cases import qualify as qualify_signed
        observations = qualify_signed(directory, compilers, checks, reference)
    elif family == "scalar-casts":
        from tools.hia_selfhost_scalar_casts import qualify as qualify_casts
        observations = qualify_casts(directory, compilers, checks, reference)
    elif family == "keyword":
        from tools.hia_selfhost_keywords import qualify as qualify_keyword
        observations = qualify_keyword(directory, compilers, checks, reference)
    elif family == "owned":
        from tools.qualify_hia_selfhost_owned_elf import qualify as qualify_owned_elf
        owned = qualify_owned_elf(directory / (label + "-owned-elf"), compiler)
        checks[label + "_owned_elf_report_pass"] = owned["status"] == "PASS_SCOPED_OWNED_BUFFER_ELF"
        for row in owned["cases"]:
            checks[label + "_owned_elf_" + row["case"]["id"]] = row["pass"]
        for row in owned["refusals"]:
            checks[label + "_owned_elf_reject_" + row["name"]] = row["pass"]
        observations = [{"compiler": label, "report": owned}]
    elif family == "chain":
        from tools.qualify_hia_selfhost_chain_elf import qualify as qualify_chain_elf
        from tools.qualify_hia_selfhost_chain_flow import qualify as qualify_chain_allocator
        chain = qualify_chain_elf(directory / (label + "-chain-elf"), compiler)
        checks[label + "_chain_elf_report_pass"] = chain["status"] == "PASS_SCOPED_CHAIN_ELF"
        for row in chain["cases"]:
            checks[label + "_chain_elf_" + row["case"]["id"]] = row["pass"]
        for row in chain["refusals"]:
            checks[label + "_chain_elf_reject_" + row["name"]] = row["pass"]
        allocator = qualify_chain_allocator(directory / (label + "-chain-allocator"), compiler)
        checks[label + "_chain_allocator_report_pass"] = (allocator["status"] == "PASS_SCOPED_CHAIN_ALLOCATOR_CONTRACT"
            and allocator["source_files_unchanged"])
        for row in allocator["cases"]:
            checks[label + "_chain_allocator_" + row["case"]["id"]] = row["pass"]
        observations = {"chain": [{"compiler": label, "report": chain}],
                        "allocator": [{"compiler": label, "report": allocator}]}
    elif family == "capacity":
        from tools.hia_selfhost_capacity import qualify_capacity
        observations = qualify_capacity(directory, compilers, checks, reference)
    elif family == "tail":
        from tools.hia_selfhost_tailcalls import qualify_tailcalls
        observations = qualify_tailcalls(directory, compilers, checks, reference)
    else:
        from tools.hia_selfhost_select import qualify_select
        observations = qualify_select(directory, compilers, checks, reference)
    _read_phase_inputs(request["inputs"])
    if source_manifest() != before:
        raise ValueError("qualification phase source changed")
    return {"schema": "hepta.hia.selfhost-phase.v1", "family": family, "compiler_label": label,
            "source_manifest_sha256": request["source_manifest_sha256"],
            "input_sha256": {key: value["sha256"] for key, value in request["inputs"].items()},
            "checks": checks, "observations": observations,
            "status": "PASS" if all(checks.values()) else "FAIL",
            "elapsed_ns": time.monotonic_ns() - started,
            "worker_pid": os.getpid(),
            "python": {"isolated": bool(sys.flags.isolated), "no_site": bool(sys.flags.no_site),
                       "dont_write_bytecode": bool(sys.flags.dont_write_bytecode)},
            "fresh_host_oracle_process": True, "successor_process_reuse": False}


@dataclass(frozen=True)
class _PendingPhaseArchive:
    future: object


class _PhaseArchivePool:
    """One archiver, at most two unsealed completed phases, no native calls.

    Holding an oracle slot while archiving a stopped child unnecessarily
    serializes native work behind filesystem/compression work. The separate
    bounded lane retains every byte and all seal/replay checks. Its queue can
    add at most two phase directories to the two currently executing phases;
    a phase is not completed in the index until its archive succeeds.
    """
    def __init__(self):
        self._slots = BoundedSemaphore(2)
        self._pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="hia-stage-archive")

    def __enter__(self):
        return self

    def __exit__(self, *exception):
        self._pool.shutdown(wait=True)

    def submit(self, function, *arguments):
        self._slots.acquire()
        try:
            future = self._pool.submit(function, *arguments)
        except BaseException:
            self._slots.release()
            raise
        future.add_done_callback(lambda completed: self._slots.release())
        return _PendingPhaseArchive(future)


def _seal_qualification_phase(phase_directory, archive_token, receipt_path, report, receipt):
    from tools.hia_evidence_archive import archive_completed_stage
    receipt["raw_artifacts"] = archive_completed_stage(phase_directory, archive_token)
    receipt["archive_completed_monotonic_ns"] = time.monotonic_ns()
    receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    return report, receipt


def _run_qualification_phase(directory, family, label, compiler, manifest_digest, archives=None):
    stem = "phase-" + family + "-" + label
    phase_directory = directory / "phase-runs" / (family + "-" + label)
    phase_directory.mkdir(parents=True, exist_ok=False, mode=0o700)
    # Only this newly constructed stage may be losslessly packed after its
    # direct worker exits. Existing/frozen evidence is never swept or mutated.
    import secrets
    from tools.hia_evidence_archive import OWNER
    archive_token = secrets.token_hex(32)
    (phase_directory / OWNER).write_text(archive_token)
    request = {"schema": "hepta.hia.selfhost-phase-request.v1", "family": family,
               "compiler_label": label, "directory": str(phase_directory),
               "inputs": _phase_inputs(directory, family, compiler, label),
               "source_manifest_sha256": manifest_digest}
    request_path, report_path = directory / (stem + ".request.json"), directory / (stem + ".json")
    request_path.write_text(json.dumps(request, indent=2, sort_keys=True) + "\n")
    command = [sys.executable, "-I", "-S", "-B", str(Path(__file__).resolve()),
               "--phase-request", str(request_path), "--output", str(report_path)]
    started = time.monotonic_ns()
    with (directory / (stem + ".stdout.log")).open("wb") as stdout, (directory / (stem + ".stderr.log")).open("wb") as stderr:
        # At most two host-oracle workers run concurrently. Their native calls
        # remain individual resource-limited children; ordinary flat ABI calls
        # now exec a sealed HIA-emitted observer without a Python child runtime.
        with subprocess.Popen(command, cwd=phase_directory, stdin=subprocess.DEVNULL,
                              stdout=stdout, stderr=stderr) as process:
            returncode = process.wait()
            worker_pid = process.pid
    receipt = {"schema": "hepta.hia.selfhost-phase-process.v1", "family": family,
               "compiler_label": label, "command": command, "returncode": returncode,
               "worker_pid": worker_pid, "started_monotonic_ns": started,
               "completed_monotonic_ns": time.monotonic_ns(),
               "wall_elapsed_ns": time.monotonic_ns() - started,
               "report_sha256": digest(report_path.read_bytes()) if report_path.exists() else None}
    (directory / (stem + ".process.json")).write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    if returncode or not report_path.exists():
        raise AssertionError({"qualification_phase_failed": stem, "receipt": receipt})
    report = json.loads(report_path.read_text())
    _read_phase_inputs(request["inputs"])
    if (report.get("schema") != "hepta.hia.selfhost-phase.v1"
            or report.get("family") != family or report.get("compiler_label") != label
            or report.get("worker_pid") != worker_pid
            or report.get("source_manifest_sha256") != manifest_digest
            or report.get("input_sha256") != {key: value["sha256"] for key, value in request["inputs"].items()}
            or report.get("python") != {"isolated": True, "no_site": True, "dont_write_bytecode": True}
            or report.get("fresh_host_oracle_process") is not True
            or report.get("successor_process_reuse") is not False):
        raise AssertionError("qualification phase receipt identity differs: " + stem)
    arguments = (phase_directory, archive_token, directory / (stem + ".process.json"), report, receipt)
    if archives is not None:
        return archives.submit(_seal_qualification_phase, *arguments)
    return _seal_qualification_phase(*arguments)


def _merge_qualification_phases(results, checks):
    expected = {(family, label) for family in QUALIFICATION_FAMILIES for label in ("original", "modified")}
    if len(results) != len(expected):
        raise AssertionError("incomplete qualification phase inventory")
    phases, pending_checks = {}, {}
    for report, receipt in results:
        key = report["family"], report["compiler_label"]
        if key not in expected or key in phases or type(report.get("checks")) is not dict or not report["checks"]:
            raise AssertionError("duplicate, unknown or empty qualification phase")
        if any(type(value) is not bool for value in report["checks"].values()):
            raise AssertionError("qualification phase checks must be booleans")
        if report.get("status") != ("PASS" if all(report["checks"].values()) else "FAIL"):
            raise AssertionError("qualification phase status differs from checks")
        if set(report["checks"]) & (set(checks) | set(pending_checks)):
            raise AssertionError("qualification phase would overwrite an existing check")
        pending_checks.update(report["checks"])
        phases[key] = (report, receipt)
    checks.update(pending_checks)
    return phases


def _collect_qualification_phases(directory, scheduled):
    """Observe every future, retaining all failures before refusing the batch."""
    index_path = directory / "phase-index.json"
    entries = [{"family": family, "compiler_label": label, "state": "pending",
                "request": str(directory / ("phase-" + family + "-" + label + ".request.json")),
                "report": str(directory / ("phase-" + family + "-" + label + ".json")),
                "process_receipt": str(directory / ("phase-" + family + "-" + label + ".process.json"))}
               for family, label, _ in scheduled]
    order = {future: position for position, (_, _, future) in enumerate(scheduled)}
    observed = set(order)
    results, failures, control_exceptions = {}, [], []

    def retain():
        value = {"schema": "hepta.hia.selfhost-phase-index.v1", "phases": entries,
                 "completed": sum(row["state"] != "pending" for row in entries),
                 "exceptions": len(failures)}
        temporary = index_path.with_suffix(".json.tmp")
        temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
        temporary.replace(index_path)

    retain()
    while order:
        done, _ = wait(order, return_when=FIRST_COMPLETED)
        for future in done:
            position = order.pop(future)
            entry = entries[position]
            try:
                result = future.result()
                if type(result) is _PendingPhaseArchive:
                    if result.future in observed:
                        raise AssertionError("qualification archive future reused")
                    observed.add(result.future)
                    order[result.future] = position
                    # The actual native work has ended, but raw evidence is
                    # not sealed yet. Keep the same pending index entry.
                    continue
            except BaseException as error:
                # Worker/seal exceptions are data until all known futures
                # have been observed. Control exceptions remain exceptions.
                entry.update(state="exception", exception_type=type(error).__module__ + "." + type(error).__qualname__,
                             exception_message=str(error))
                failures.append(entry.copy())
                if not isinstance(error, Exception):
                    control_exceptions.append(error)
            else:
                results[position] = result
                entry.update(state="completed", report_status=result[0].get("status"))
            retain()
    if control_exceptions:
        raise control_exceptions[0]
    if failures:
        raise AssertionError({"qualification_phase_exceptions": failures, "phase_index": str(index_path)})
    return [results[position] for position in range(len(scheduled))]


def qualify(output):
    output = Path(output).resolve()
    if platform.system() != "Linux" or platform.machine().lower() not in {"x86_64", "amd64"} or not shutil.which("ld"):
        raise RuntimeError("the explicit B0 profile requires Linux x86-64 and GNU ld")
    contract = validate_contract()
    before = source_manifest()
    started = time.monotonic_ns()
    directory = output.with_suffix(".evidence")
    directory.mkdir(parents=True, exist_ok=False, mode=0o700)
    source, sample = SOURCE.read_bytes(), SAMPLE.read_bytes()
    from tools.hia_selfhost_references import build_references
    references, reference_receipts = build_references(directory, before, PHASE_REFERENCE_FILES, QUALIFICATION_WORKERS)
    resource_reference, bulk_reference, loan_reference, cfg_reference = [references[f] for f in ("resource", "bulk", "loan", "cfg")]
    capacity_reference, tail_reference, select_reference = [references[f] for f in ("capacity", "tail", "select")]
    effect_reference, multi_reference, keyword_reference = [references[f] for f in ("effects", "multi", "keyword")]
    signed_reference, cast_reference, independent = [references[f] for f in ("signed", "scalar-casts", "core")]
    from tools.hia_selfhost_native_observer import independent_reference as observer_reference, build as build_observer
    native_observer_reference = observer_reference()
    (directory / 'independent-native-observer-reference.json').write_text(
        json.dumps(native_observer_reference,indent=2,sort_keys=True)+'\n')
    from tools.hia_selfhost_linked_observer import independent_reference as linked_observer_reference, build as build_linked_observer
    linked_observer_reference = linked_observer_reference(before_B0=True)
    (directory / 'independent-linked-observer-reference.json').write_text(
        json.dumps(linked_observer_reference,indent=2,sort_keys=True)+'\n')
    seed_started_monotonic_ns = time.monotonic_ns()
    seed, seed_receipt = build_seed(directory, source)
    stages = []
    previous = seed
    for label in ("B1", "B2", "B3"):
        previous, receipt = compile_stage(directory, label, previous, source,
            image_format="seed-shared" if label == "B1" else "flat-x86-64",
            workspace_fill=0x5a if label == "B3" else 0)
        stages.append(receipt)
    original = previous
    checks = {"support_contract_matches_source": True, "three_native_self_compilations": True,
              "own_compiler_uses_backward_direct_calls": bool(seed_receipt["source_structure"]["backward_direct_calls"]),
              "own_compiler_uses_direct_tail_self_calls": bool(seed_receipt["source_structure"]["direct_tail_self_calls"]),
              "B1_B2_B3_byte_identical": len({x["produced_sha256"] for x in stages}) == 1,
              "no_host_compiler_modules_in_successors": all(not x["forbidden_compiler_modules_loaded"] for x in stages)}
    changed = mutate_compiler(source)
    (directory / "modified-selfhost.hepta").write_bytes(changed)
    modified_stages = []
    for label in ("M1", "M2", "M3"):
        previous, receipt = compile_stage(directory, label, previous, changed)
        modified_stages.append(receipt)
    checks["modified_codegen_changes_successor"] = modified_stages[0]["produced_sha256"] != modified_stages[1]["produced_sha256"]
    checks["modified_compiler_rebuilds_itself"] = modified_stages[1]["produced_sha256"] == modified_stages[2]["produced_sha256"]
    checks["modified_compiler_differs_from_original"] = modified_stages[2]["produced_sha256"] != stages[2]["produced_sha256"]
    # The generated wrapper's actual stack reservation is part of the change.
    checks["modified_wrapper_machine_bytes"] = original.read_bytes()[:8] == bytes.fromhex("554889e54883ec40") and previous.read_bytes()[:8] == bytes.fromhex("554889e54883ec50")
    native_observer, native_observer_build = build_observer(directory, original, native_observer_reference)
    checks['native_observer_independent_VM_reference_before_B0'] = native_observer_reference['before_B0']
    checks['native_observer_exact_HIA_emission'] = (
        digest(native_observer.read_bytes()) == native_observer_reference['expected_image_sha256'])
    linked_observer, linked_observer_build = build_linked_observer(
        directory, original, linked_observer_reference)
    checks['linked_observer_independent_VM_reference_before_B0'] = (
        linked_observer_reference['before_B0'])
    checks['linked_observer_exact_HIA_object_emission'] = (
        linked_observer_build['object_sha256']
        == linked_observer_build['actual_policy_vm_packing']['output_sha256'])
    checks['linked_observer_real_dynamic_linker'] = (
        digest(linked_observer.read_bytes()) == linked_observer_build['executable_sha256']
        and all(row['returncode'] == 0 for row in linked_observer_build['native_tool_observations']))
    observations = []
    for label, compiler in (("original", original), ("modified", previous)):
        executable, compilation = compile_stage(directory, label + "-bytesum", compiler, sample)
        observations.append(compilation)
        for index, data in enumerate((b"", b"HIA native bootstrap", bytes(range(256)) * 4)):
            result, raw = invoke(directory, label + "-sample-" + str(index), executable, data, capacity=1, workspace_size=1)
            correct = result.get("status") == "returned" and result.get("core_u32") == hash_reference(data) and raw == bytes([hash_reference(data) & 255]) and result.get("source_unchanged")
            checks[label + "_behavior_" + str(index)] = bool(correct)
            observations.append(result)
    rejected = []
    for label, bad in invalid_sources(sample).items():
        result, raw = invoke(directory, "reject-" + label, original, bad)
        good = result.get("status") == "returned" and result.get("core_u32") == INVALID and result.get("output_unchanged") and result.get("source_unchanged")
        checks["reject_" + label] = bool(good)
        rejected.append(result)
    readonly_image, readonly_build = compile_stage(directory, "readonly-call-code", original, readonly_call_source())
    readonly, _ = invoke(directory, "readonly-call", readonly_image, b"readonly alias", capacity=0, workspace_size=0)
    checks["readonly_call_alias_remains_legal"] = (readonly.get("status") == "returned"
        and readonly.get("core_u32") == 2 * len(b"readonly alias") and readonly.get("source_unchanged"))
    call_observations = []
    for label, compiler in (("original", original), ("modified", previous)):
        executable, compilation = compile_stage(directory, label + "-backward-bytesum",
                                                compiler, backward_bytesum_source(sample))
        call_observations.append(compilation)
        for index, data in enumerate((b"", b"HIA backward calls", bytes(range(256)) * 4)):
            result, raw = invoke(directory, label + "-backward-sample-" + str(index),
                                 executable, data, capacity=1, workspace_size=1)
            checks[label + "_backward_call_behavior_" + str(index)] = (
                result.get("status") == "returned" and result.get("core_u32") == hash_reference(data)
                and raw == bytes([hash_reference(data) & 255]) and result.get("source_unchanged"))
            call_observations.append(result)
        executable, compilation = compile_stage(directory, label + "-full-call-depth",
                                                compiler, backward_chain_source())
        call_observations.append(compilation)
        result, _ = invoke(directory, label + "-full-call-depth-run", executable, b"",
                           capacity=0, workspace_size=0)
        checks[label + "_128_function_backward_chain"] = (
            result.get("status") == "returned" and result.get("core_u32") == 127)
        call_observations.append(result)
        for case, bad in {**call_graph_invalid_sources(sample), **recursion_refusals()}.items():
            result, _ = invoke(directory, label + "-reject-" + case, compiler, bad)
            checks[label + "_reject_" + case] = (result.get("status") == "returned"
                and result.get("core_u32") == INVALID and result.get("output_unchanged")
                and result.get("source_unchanged"))
            call_observations.append(result)
    small, _ = invoke(directory, "short-output", original, source, capacity=stages[2]["produced_bytes"] - 1)
    checks["short_output_is_transactional"] = small.get("status") == "returned" and small.get("core_u32") == NO_SPACE and small.get("output_unchanged")
    workspace, _ = invoke(directory, "short-workspace", original, source, workspace_size=1024)
    checks["short_workspace_rejected"] = workspace.get("status") == "returned" and workspace.get("core_u32") == NO_SPACE and workspace.get("output_unchanged")
    # B0 and both three-generation chains above remain strictly sequential.
    # Only independent qualification families are scheduled concurrently, and
    # each family gets a new Python process so VM/reference instrumentation and
    # globals cannot leak between families. Every native invocation stays fresh.
    manifest_digest = _phase_manifest_digest(before)
    # Original remote timeout 43347872271 left names/exports at the end.
    # Start long independent work first so sealing can overlap later short
    # work. This changes neither the inventory nor the two-worker budget.
    priority = ("names", "exports", "chain", "signed", "scalar-casts", "cli", "owned", "capacity")
    phase_order = (*priority, *(family for family in QUALIFICATION_FAMILIES if family not in priority))
    with _PhaseArchivePool() as archives:
        with ThreadPoolExecutor(max_workers=QUALIFICATION_WORKERS) as pool:
            scheduled = [(family, label, pool.submit(_run_qualification_phase, directory, family, label, compiler, manifest_digest, archives))
                         for family in phase_order
                         for label, compiler in (("original", original), ("modified", previous))]
            phase_results = _collect_qualification_phases(directory, scheduled)
    phases = _merge_qualification_phases(phase_results, checks)

    def phase_observations(family):
        return [row for label in ("original", "modified")
                for row in phases[family, label][0]["observations"]]

    elf_observations = phase_observations("elf")
    resource_observations = phase_observations("resource")
    bulk_observations = phase_observations("bulk")
    loan_observations = phase_observations("loan")
    cfg_observations = phase_observations("cfg")
    owned_observations = phase_observations("owned")
    chain_observations = [row for label in ("original", "modified")
                          for row in phases["chain", label][0]["observations"]["chain"]]
    allocator_observations = [row for label in ("original", "modified")
                              for row in phases["chain", label][0]["observations"]["allocator"]]
    expanded_capacity = phase_observations("capacity")
    tail_observations = phase_observations("tail")
    select_observations = phase_observations("select")
    effect_observations = phase_observations("effects")
    multi_observations = phase_observations("multi")
    keyword_observations = phase_observations("keyword")
    checks["source_closure_unchanged"] = source_manifest() == before
    report = {
        "schema": "hepta.hia.selfhost-qualification.v6",
        "status": "SELF_HOSTED_FIXED_CORE_PASS" if all(checks.values()) else "FAIL",
        "profile": contract["profile"],
        "native_observer_build": native_observer_build,
        "native_observer_reference": native_observer_reference,
        "linked_observer_build": linked_observer_build,
        "linked_observer_reference": linked_observer_reference,
        "target": contract["target"], "abi": contract["abi"],
        "support_contract": {"path": CONTRACT_PATH, "sha256": before[CONTRACT_PATH]},
        "checkout": checkout_identity(),
        "source_manifest": before, "source_bytes": len(source), "source_sha256": digest(source),
        "checks": checks, "seed": seed_receipt, "generations": stages,
        "modified_source_sha256": digest(changed), "modified_generations": modified_stages,
        "behavior_observations": observations, "rejection_observations": rejected,
        "readonly_call_observations": [readonly_build, readonly],
        "call_graph_observations": call_observations, "independent_core_reference": independent,
        "elf_object_observations": elf_observations,
        "bulk_observations": bulk_observations, "independent_bulk_reference": bulk_reference,
        "loan_observations": loan_observations, "independent_loan_reference": loan_reference,
        "cfg_worklist_observations": cfg_observations, "independent_cfg_worklist_reference": cfg_reference,
        "owned_elf_observations": owned_observations,
        "chain_elf_observations": chain_observations,
        "chain_allocator_observations": allocator_observations,
        "resource_observations": resource_observations, "independent_resource_reference": resource_reference,
        "expanded_capacity_observations": expanded_capacity, "independent_capacity_reference": capacity_reference,
        "tail_call_observations": tail_observations, "independent_tail_reference": tail_reference,
        "select_observations": select_observations, "independent_select_reference": select_reference,
        "effect_observations": effect_observations, "independent_effect_reference": effect_reference,
        "multi_result_observations": multi_observations, "independent_multi_result_reference": multi_reference,
        "keyword_observations": keyword_observations, "independent_keyword_reference": keyword_reference,
        "signed_observations": phase_observations("signed"), "independent_signed_reference": signed_reference,
        "scalar_cast_observations": phase_observations("scalar-casts"), "independent_scalar_cast_reference": cast_reference,
        "explicit_export_observations": phase_observations("exports"),
        "independent_explicit_export_reference": references["exports"],
        "function_name_observations": phase_observations("names"),
        "independent_function_name_reference": references["names"],
        "executable_cli_observations": phase_observations("cli"),
        "independent_executable_cli_reference": references["cli"],
        "explicit_trap_observations": phase_observations("explicit-traps"),
        "independent_explicit_trap_reference": references["explicit-traps"],
        "capacity_observations": [small, workspace], "elapsed_ns": time.monotonic_ns() - started,
        "qualification_scheduling": {
            "maximum_host_oracle_workers": QUALIFICATION_WORKERS,
            "maximum_archive_workers": 1,
            "maximum_pending_archives": 2,
            "maximum_unsealed_phase_directories": QUALIFICATION_WORKERS + 2,
            "phase_completed_only_after_verified_archive": True,
            "fresh_seed_and_generation_chain_sequential": True,
            "independent_references_completed_before_B0": all(r["completed_monotonic_ns"] <= seed_started_monotonic_ns for r in reference_receipts),
            "seed_started_monotonic_ns": seed_started_monotonic_ns,
            "reference_processes": reference_receipts,
            "native_child_processes_reused": False,
            "phase_flat_ABI_transport": "fresh sealed HIA-emitted syscall-only ELF",
            "phase_linked_ABI_transport": "fresh sealed HIA-policy-directed dynamic ELF; complete sealed target dlopen/dlsym",
            "shared_ELF_and_generation_controls": "seed/shared direct references and generation controls retain the independent stdlib loader",
            "phase_inventory": [family + "-" + label for family in QUALIFICATION_FAMILIES
                                for label in ("original", "modified")],
            "phases": [receipt for report, receipt in phase_results],
        },
        "claims": {"HIA_parser_used_after_seed": True, "HIA_validator_used_after_seed": True,
                   "HIA_x86_generator_used_after_seed": True, "own_source_compiled": True,
                   "modified_own_source_rebuilt": all(checks[k] for k in ("modified_compiler_rebuilds_itself", "modified_codegen_changes_successor", "modified_wrapper_machine_bytes")),
                   "precompiled_successor_blob_used": False, "source_hash_dispatch_used": False,
                   "python_parser_or_codegen_after_B0": True,
                   "python_parser_or_codegen_in_successor_compilation": False,
                   "host_reference_codegen_after_B0": True, "external_assembler_after_B0": True,
                   "external_assembler_in_successor_compilation": False,
                   "host_native_fixture_compilation_after_B0": True,
                   "external_assembler_scope": "host allocator qualification witness C object only; no successor compilation",
                   "external_linker_after_B0": True, "external_linker_in_flat_bootstrap_chain": False,
                   "external_linker_scope": "HIA-emitted linked observer, explicit successor ELF qualification, host allocator witness and independent host direct-backend references",
                   "HIA_successor_ELF_writer_used": True, "Python_successor_ELF_writer_used": False,
                   "whole_HIA_language_self_hosted": False,
                   "compiler_correctness_formally_proved": False},
        "trusted_dependencies": ["B0 Python HIA assembler, Core verifier, direct x86 emitter and ELF writer",
            "B0 GNU ld, libc and dynamic loader", "fresh HIA-emitted static ELF observer and operating system for phase flat ABI calls",
            "stdlib ctypes/mmap retained for generation controls and independent seed/shared direct references",
            "fresh HIA-emitted dynamic ELF observer, libc startup/exit and complete sealed target dlopen/dlsym for phase linked HIA ABI calls",
            "owned ELF qualification uses GNU ld, the system dynamic loader and libc calloc/free",
            "host C compiler and assembler compile the separate allocator qualification witness only",
            "Linux x86-64 hardware, caller-owned exclusive buffers and resource limits"],
        "scope": "fixed canonical HIA v8 subset documented in docs/HIA_SELF_HOSTING_CORE.md",
    }
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--phase-request", type=Path)
    arguments = parser.parse_args()
    if arguments.phase_request is not None:
        report = qualification_phase(arguments.phase_request)
        arguments.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        print(json.dumps({"status": report["status"], "family": report["family"],
                          "compiler_label": report["compiler_label"],
                          "checks_passed": sum(report["checks"].values()), "checks_total": len(report["checks"])}))
        return
    report = qualify(arguments.output)
    print(json.dumps({"status": report["status"], "output": str(arguments.output),
                      "checks_passed": sum(report["checks"].values()), "checks_total": len(report["checks"]),
                      "generation_sha256": [x["produced_sha256"] for x in report["generations"]],
                      "modified_generation_sha256": [x["produced_sha256"] for x in report["modified_generations"]]}, sort_keys=True))
    raise SystemExit(0 if report["status"] == "SELF_HOSTED_FIXED_CORE_PASS" else 1)


if __name__ == "__main__":
    main()
