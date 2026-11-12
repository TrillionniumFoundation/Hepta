#!/usr/bin/env python3
"""Validate copied select fragments from the exact frozen compiler's output.

This is a conditional local lemma, not a whole-program compiler-extension
receipt. The original Agent's four claims, evaluation and adoption remain HOLD.
No instruction in a selected fragment is regenerated, repaired or mutated.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import importlib.machinery
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
WIDTHS = {"u8": 8, "u32": 32, "u64": 64, "usize": 64, "bool": 1}
SCHEMA = "hepta.hia.original-select-copied-fragments.v1"
HASHES = {
    "original": "85288cfc4b649b2be13175675880f5372f16bf3d9c5d4b78ba21ffa2c90b6b44",
    "candidate": "2dd847d9df46392e4ef4b99c781b45f56c9841ae61127a260be6e8523f042845",
    "patch": "e74f3c27d6ea7e7ccfc1c9e2a4e7674fecabef08ee0e05236e5a6e2b5bd75cb4",
}
MARKER = bytes.fromhex("4885d2480f45c1")


def digest(data):
    return sha256(data).hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def validate_complete_output_observation(receipt, actual, *, image_bytes, input_bytes, expected):
    """Bind a finite whole-program observation to its actual byte-ABI result.

    A correct low u32 and output buffer do not imply ABI success: the upper
    status word must also be zero. These are observation checks, not a proof of
    the complete generated program or its surrounding compiler context.
    """
    require(type(receipt) is dict and type(actual) is bytes
            and type(image_bytes) is bytes and type(input_bytes) is bytes
            and type(expected) is int and 0 <= expected < 1 << 64,
            "invalid complete-program observation inputs")
    image_sha, input_sha = digest(image_bytes), digest(input_bytes)
    low_return = expected & 0xffffffff
    require(receipt.get("status") == "returned"
            and type(receipt.get("abi_status")) is int and receipt["abi_status"] == 0
            and type(receipt.get("result_u64")) is int and receipt["result_u64"] == low_return
            and type(receipt.get("core_u32")) is int and receipt["core_u32"] == low_return
            and receipt.get("return_encoding") == "zero-extended-u32"
            and receipt.get("format") == "flat-x86-64"
            and receipt.get("source_unchanged") is True
            and receipt.get("forbidden_compiler_modules_loaded") == []
            and receipt.get("image_sha256") == image_sha
            and receipt.get("artifact_sha256") == image_sha
            and receipt.get("source_sha256") == input_sha
            and receipt.get("input_sha256") == input_sha
            and type(receipt.get("input_bytes")) is int and receipt["input_bytes"] == len(input_bytes)
            and actual == expected.to_bytes(8, "little")
            and receipt.get("output_sha256") == digest(actual),
            "complete-program native observation violates its ABI or byte identities")
    limits = receipt.get("limits")
    require(type(limits) is dict and type(limits.get("output_capacity")) is int
            and limits["output_capacity"] == 8 and type(limits.get("workspace_bytes")) is int
            and limits["workspace_bytes"] == 0,
            "complete-program native observation used a different buffer contract")


def replay_complete_output_observation(directory, label, witness, *, image_bytes, input_bytes, expected):
    """Rebind the retained raw child output and invocation receipt separately."""
    directory = Path(directory)
    actual_input = (directory / (label + ".input.bin")).read_bytes()
    actual_output = (directory / (label + ".output.bin")).read_bytes()
    raw = json.loads((directory / (label + ".stdout.log")).read_bytes())
    receipt = json.loads((directory / (label + ".receipt.json")).read_bytes())
    require(actual_input == input_bytes, "retained complete-program input differs")
    validate_complete_output_observation(receipt, actual_output, image_bytes=image_bytes,
                                         input_bytes=input_bytes, expected=expected)
    # invoke() adds custody metadata to the original child's JSON. Neither a
    # summary row nor that augmented receipt may replace the raw observation.
    required_raw = {"status", "abi_status", "result_u64", "core_u32", "return_encoding",
        "source_unchanged", "forbidden_compiler_modules_loaded", "image_sha256",
        "source_sha256", "output_sha256", "limits"}
    def wire(value):
        # JSON booleans and integers compare equal in Python; an original
        # observation's field types are part of its retained identity too.
        return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    require(type(raw) is dict and required_raw <= raw.keys()
            and all(key in receipt for key in raw)
            and wire(raw) == wire({key: receipt[key] for key in raw})
            and receipt.get("case") == label
            and type(witness) is dict and wire(witness.get("receipt")) == wire(receipt)
            and witness.get("observed_output_sha256") == digest(actual_output)
            and witness.get("finite_observation_only") is True,
            "retained complete-program raw output, receipt or witness differs")


def source_inventory():
    files = [*(ROOT / "hepta").glob("*.py"), *(ROOT / "tools").glob("*.py"),
             ROOT / "docs/HIA_SELFHOST_CORE_SUPPORT.json"]
    return {p.relative_to(ROOT).as_posix(): digest(p.read_bytes()) for p in sorted(files)}


def select_fragment(source, image):
    """Bind one actual byte interval to the admitted fixture's SSA slot layout.

    Recognizing this layout grants no proof. The supplied-artifact checker must
    still decide every semantic, memory, ABI and termination obligation.
    """
    from hepta.hia_agent_assembly import assemble_program
    require(type(source) is bytes and type(image) is bytes, "immutable source/image bytes required")
    require(0 < len(source) <= 1 << 20 and 0 < len(image) <= 1 << 20,
            "source/image exceeds the frozen compiler output budget")
    checked = assemble_program(source)
    sites = [(fn["name"], block["id"], op) for fn in checked.as_dict()["functions"]
             for block in fn["blocks"] for op in block["ops"] if op["op"] == "select"]
    require(len(sites) == 1, "exactly one select site required")
    function, block, op = sites[0]
    typ = op["out"][0]["type"]
    require(function == "f0" and typ in WIDTHS and len(op["args"]) == 3 and len(op["out"]) == 1,
            "select site is outside the copied-fragment profile")
    variables = [*op["args"], op["out"][0]["name"]]
    require(all(re.fullmatch(r"v[0-9]+", v) for v in variables), "numeric SSA slots required")
    indices = [int(v[1:]) for v in variables]
    require(max(indices) <= 2047 and len(set(indices)) == 4, "distinct bounded SSA slots required")
    slots = [-32 - 16 * index for index in indices]
    require(image.count(MARKER) == 1, "the compiler output must contain exactly one selection marker")
    marker = image.index(MARKER)
    start, end = marker - 21, marker + 14
    require(0 <= start < end <= len(image), "selection interval is truncated")
    fragment = image[start:end]
    require(len(fragment) == 35 and fragment[:3] == bytes.fromhex("488b95")
            and fragment[7:10] == bytes.fromhex("488b8d")
            and fragment[14:17] == bytes.fromhex("488b85")
            and fragment[28:31] == bytes.fromhex("488985"), "actual operand/load/store shape differs")
    actual_slots = [struct.unpack_from("<i", fragment, at)[0] for at in (3, 10, 17, 31)]
    require(actual_slots == slots, "actual compiler output uses different source/result SSA slots")
    return {"type": typ, "source_sha256": digest(source), "source_core_sha256": checked.sha256,
        "compiler_output_sha256": digest(image), "compiler_output_bytes": len(image),
        "function": function, "block": block, "operation": op, "variables": variables,
        "rbp_displacements": slots, "start": start, "end": end,
        "fragment_sha256": digest(fragment), "fragment_hex": fragment.hex(),
        "fragment_instructions_reemitted": False, "entire_compiler_output_validated": False}


def projection_object(site):
    """Expose the copied bytes under explicit normalized-slot preconditions.

    The wrapper is new proof scaffolding. It does not claim that the original
    compiler establishes these preconditions in every surrounding context.
    """
    from hepta.hia_machine_elf import write_elf_object
    from hepta.hia_machine_x64 import Code
    typ, slots = site["type"], site["rbp_displacements"]
    fragment = bytes.fromhex(site["fragment_hex"])
    require(digest(fragment) == site["fragment_sha256"] and len(fragment) == 35,
            "copied fragment changed before projection")
    frame = (-min(slots) + 31) & ~15
    require(0 < frame <= 4096, "projected stack frame exceeds this lemma's budget")
    code = Code()
    code.push("rbp")
    code.mov_rr("rbp", "rsp")
    code.alu_imm("sub", "rsp", frame)
    code.alu_imm("and", "rdi", 1)
    for register in ("rsi", "rdx"):
        if WIDTHS[typ] < 32:
            code.alu_imm("and", register, (1 << WIDTHS[typ]) - 1)
        elif WIDTHS[typ] == 32:
            code.shl(register, 32)
            code.shr(register, 32)
    for offset, register in zip(slots[:3], ("rdi", "rsi", "rdx")):
        code.store("rbp", offset, register)
    start = code.offset
    code.emit(fragment)
    end = code.offset
    code.load("rax", "rbp", slots[3])
    code.emit(bytes.fromhex("c9c3"))
    # Ordinary unreachable abort import and wrapper retain the existing strict
    # ELF contract. Neither binder metadata nor its checks are weakened.
    code.call("abort")
    code.emit(bytes.fromhex("0f0b"))
    entry = code.offset
    code.push("rbp")
    code.mov_rr("rbp", "rsp")
    code.call("__hia_native_fn_0")
    code.emit(bytes.fromhex("c9c3"))
    text, relocations = code.finalize()
    obj = write_elf_object(text, [
        {"name": "__hia_native_fn_0", "offset": 0, "size": entry, "global": False},
        {"name": "choose", "offset": entry, "size": len(text) - entry, "global": True}], relocations)
    return obj, {"copied_text_start": start, "copied_text_end": end, "stack_frame_bytes": frame,
        "slot_condition": "three live, disjoint, initialized normalized scalar slots; private result slot",
        "scaffolding_is_new": True, "scaffolding_proves_original_context": False}


def freeze_inputs(paths, output):
    frozen = output / "frozen-inputs"
    frozen.mkdir()
    data = {}
    for name, path in paths.items():
        raw = path.read_bytes()
        require(digest(raw) == HASHES[name], "frozen original input differs: " + name)
        data[name] = raw
        target = frozen / (name + (".patch" if name == "patch" else ".hiaasm"))
        target.write_bytes(raw)
        target.chmod(0o400)
    tree = output / "patch-reconstruction"
    source = tree / "examples/hia_bootstrap/selfhost.hiaasm"
    source.parent.mkdir(parents=True)
    source.write_bytes(data["original"])
    command = ["git", "apply", "--include=examples/hia_bootstrap/selfhost.hiaasm",
               str(frozen / "patch.patch")]
    process = subprocess.run(command, cwd=tree, capture_output=True, timeout=30, check=False)
    save(output / "patch-apply.json", {"command": command, "returncode": process.returncode,
        "stdout": process.stdout.decode(errors="replace"), "stderr": process.stderr.decode(errors="replace")})
    require(process.returncode == 0 and source.read_bytes() == data["candidate"],
            "exact original patch does not reconstruct the candidate")
    return data


def disassembly_witness(image, site, directory):
    """Finite read-only instruction-boundary witness, outside the SMT theorem."""
    tool = shutil.which("objdump")
    require(tool is not None, "GNU objdump is required for the boundary witness")
    tool = Path(tool).resolve()
    identity = digest(tool.read_bytes())
    command = [str(tool), "-D", "-z", "-b", "binary", "-m", "i386:x86-64", "--insn-width=16", str(image)]
    process = subprocess.run(command, capture_output=True, timeout=15, check=False)
    (directory / "output-disassembly.stdout.log").write_bytes(process.stdout)
    (directory / "output-disassembly.stderr.log").write_bytes(process.stderr)
    require(process.returncode == 0 and digest(tool.read_bytes()) == identity,
            "read-only disassembly failed or its tool changed")
    selected = []
    for line in process.stdout.decode("utf-8", errors="strict").splitlines():
        match = re.match(r"^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)\s*(\S.*)$", line)
        if match and site["start"] <= int(match[1], 16) < site["end"]:
            selected.append({"offset": int(match[1], 16), "bytes": bytes.fromhex(match[2]).hex(),
                             "disassembly": match[3]})
    expected = [(site["start"] + at, length) for at, length in ((0, 7), (7, 7), (14, 7), (21, 3), (24, 4), (28, 7))]
    require([(row["offset"], len(bytes.fromhex(row["bytes"]))) for row in selected] == expected
            and "".join(row["bytes"] for row in selected) == site["fragment_hex"],
            "whole-output disassembly does not place the copied bytes at the recorded instruction boundaries")
    receipt = {"command": command, "tool_sha256": identity, "compiler_output_sha256": digest(image.read_bytes()),
        "selected_instructions": selected, "stdout_sha256": digest(process.stdout),
        "scope": "finite GNU disassembly witness; no whole-image semantic or reachability proof"}
    save(directory / "output-disassembly.json", receipt)
    return receipt


def qualify_case(typ, output, seed, linker):
    from hepta.hia_safe_core import validate_safe_core_artifact
    from hepta.hia_safe_core_elf import bind_final_artifact
    from tools.hia_selfhost_select import select_source, select_cases
    from tools.qualify_hia_selfhost import compile_stage, invoke
    from tools.qualify_hia_safe_core_cmovne import (LINK_FLAGS, selection_core, witness_vectors,
                                                   mathematical_result)
    directory = output / typ
    directory.mkdir()
    source = select_source(typ)
    image, build = compile_stage(directory, "actual-c1-output", seed, source, image_format="seed-shared")
    image_bytes = image.read_bytes()
    site = select_fragment(source, image_bytes)
    save(directory / "source-binding.json", site)
    disassembly = disassembly_witness(image, site, directory)
    whole_program_observations = []
    for index, case in enumerate(row for row in select_cases() if row["type"] == typ):
        data = (bytes([int(case["condition"])]) + int(case["left"]).to_bytes(8, "little")
                + int(case["right"]).to_bytes(8, "little"))
        receipt, actual = invoke(directory, "whole-output-case-" + str(index), image, data,
                                 capacity=8, workspace_size=0)
        expected = int(case["expected"])
        validate_complete_output_observation(receipt, actual, image_bytes=image_bytes,
                                             input_bytes=data, expected=expected)
        whole_program_observations.append({"case": case, "receipt": receipt,
            "observed_output_sha256": digest(actual), "finite_observation_only": True})
    save(directory / "whole-output-finite-witnesses.json", whole_program_observations)
    fragment = bytes.fromhex(site["fragment_hex"])
    (directory / "copied-fragment.bin").write_bytes(fragment)
    core = selection_core(typ)
    (directory / "specification.core.json").write_bytes(core.canonical_bytes)
    obj, projection = projection_object(site)
    object_path, final_path = directory / "projection.o", directory / "projection.so"
    object_path.write_bytes(obj)
    command = [linker, *LINK_FLAGS, str(object_path), "-lc", "-o", str(final_path)]
    process = subprocess.run(command, capture_output=True, timeout=30, check=False)
    save(directory / "link.json", {"command": command, "returncode": process.returncode,
        "stdout": process.stdout.decode(errors="replace"), "stderr": process.stderr.decode(errors="replace")})
    require(process.returncode == 0, "projection link failed")
    final = final_path.read_bytes()
    binding = bind_final_artifact(obj, final, "choose")
    require(binding["text"][projection["copied_text_start"]:projection["copied_text_end"]] == fragment,
            "linking altered the copied compiler bytes")
    proof = validate_safe_core_artifact(core, obj, final, query_directory=directory / "queries")
    require(proof["status"] == "smt_validated" and proof["complete"] and proof["ok"],
            "the supplied artifact did not discharge its independent obligations")
    save(directory / "validation.json", proof)
    case = {"type": typ, "kind": "frozen-c1-copied-fragment"}
    vectors = witness_vectors(case)
    request = {"image": str(final_path), "image_sha256": digest(final), "argument_count": 3, "vectors": vectors}
    save(directory / "native-request.json", request)
    command = [sys.executable, "-B", str(ROOT / "tools/hia_safe_core_cmovne_child.py")]
    native = subprocess.run(command, input=json.dumps(request), text=True, capture_output=True,
                            timeout=15, check=False)
    save(directory / "native-process.json", {"command": command, "returncode": native.returncode,
        "stdout": native.stdout, "stderr": native.stderr})
    require(native.returncode == 0, "finite native witness failed")
    observed = json.loads(native.stdout)
    expected = [mathematical_result(case, vector) for vector in vectors]
    require(observed["image_sha256"] == digest(final) and observed["vectors"] == vectors
            and observed["results"] == expected, "finite native values differ from scalar selection")
    save(directory / "native-mathematics.json", {"results": expected, "finite_witnesses_only": True})
    row = {"type": typ, "status": "smt_validated", "compiler_build_observation": build,
        "source_binding": site, "projection": projection, "projection_object_sha256": digest(obj),
        "projection_image_sha256": digest(final), "specification_core_sha256": core.sha256,
        "validation_sha256": digest((directory / "validation.json").read_bytes()),
        "native_calls": len(vectors), "whole_generated_program_finite_calls": len(whole_program_observations),
        "output_disassembly": disassembly, "agent_proof_receipt_issued": False}
    save(directory / "result.json", row)
    return row


def worker(args, output, linker):
    prefix = output / "empty-bytecode-cache"
    require(sys.dont_write_bytecode and sys.pycache_prefix is not None
            and Path(sys.pycache_prefix).resolve() == prefix.resolve() and not list(prefix.rglob("*")),
            "a fresh isolated source-only import prefix is required")
    before = source_inventory()
    save(output / "source-before.json", before)
    sys.path.insert(0, str(ROOT))
    from tools.qualify_hia_selfhost import build_seed, checkout_identity
    started = time.monotonic()
    frozen = freeze_inputs({name: getattr(args, name).resolve() for name in HASHES}, output)
    seed_directory = output / "frozen-c1-seed"
    seed_directory.mkdir()
    seed, seed_receipt = build_seed(seed_directory, frozen["candidate"])
    rows = []
    for typ in WIDTHS:
        rows.append(qualify_case(typ, output, seed, linker))
        save(output / "progress.json", rows)
    imports = {}
    for name, module in sorted(sys.modules.items()):
        if name == "hepta" or name.startswith(("hepta.", "tools.", "z3.")) or name == "z3":
            if not getattr(module, "__file__", None):
                continue
            path = Path(module.__file__).resolve()
            require(path.suffix == ".py" and isinstance(module.__loader__, importlib.machinery.SourceFileLoader),
                    "an imported checker/producer module did not come from source")
            imports[name] = {"path": str(path), "sha256": digest(path.read_bytes())}
    require(source_inventory() == before, "qualification sources changed")
    require(not list(prefix.rglob("*")), "unexpected bytecode in the isolated cache")
    save(output / "source-imports.json", imports)
    report = {"schema": SCHEMA, "status": "PASS_SCOPED_COPIED_FRAGMENTS",
        "original_agent_four_claim_gate": "HOLD", "agent_proof_receipt_issued": False,
        "evaluation_performed": False, "adoption_authorized": False,
        "original_provider_history_available": False, "provider_tokens": None, "provider_fees": None,
        "exact_frozen_input_sha256": HASHES, "patch_reconstruction_exact": True,
        "candidate_seed_image_sha256": digest(seed.read_bytes()), "seed_receipt": seed_receipt,
        "subject": {"frozen_candidate_source_sha256": HASHES["candidate"],
                    "per_output_fragments": [r["source_binding"] for r in rows]},
        "checker": {"name": "existing independent Safe Core supplied-ELF validator",
                    "per_case_exact_checker_identity": "validation.json in each scalar directory"},
        "property": "copied select load/condition/choice/store fragment under normalized live SSA-slot preconditions",
        "profile": "five exact frozen-C1 outputs; existing unsigned acyclic supplied-ELF checker",
        "assumptions": ["The seed compiler and native invocation faithfully execute the recorded frozen C1 source; that compiler-to-machine bridge is unproved.",
            "The displayed Core SSA slot relation and new projection scaffolding describe this local lemma only.",
            "All unchanged Safe Core ISA/ELF/loader/solver assumptions in each validation apply."],
        "unproved_obligations": ["original source-domain preservation", "compiler parser/type/SSA slot establishment in every context",
            "whole-image semantic and contextual composition proof of the selected interval",
            "complete generated program behavior and capacity/refusal semantics", "general compiler Core-to-machine refinement",
            "original strict Agent verification/evaluation/adoption", "original provider transcript and full cost"],
        "whole_compiler_or_original_agent_delta_proved": False, "source_identity": before,
        "source_checkout": checkout_identity(),
        "cases": rows, "counts": {"actual_compiler_outputs": len(rows), "smt_validated_fragments": len(rows),
            "smt_obligations": 5 * len(rows), "native_calls": sum(r["native_calls"] for r in rows),
            "whole_generated_program_finite_calls": sum(r["whole_generated_program_finite_calls"] for r in rows)},
        "elapsed_seconds": time.monotonic() - started}
    save(output / "qualification.json", report)
    save(output / "artifact-manifest.json", {p.relative_to(output).as_posix(): digest(p.read_bytes())
        for p in sorted(output.rglob("*")) if p.is_file()})
    print(json.dumps({"status": report["status"], "counts": report["counts"],
        "original_agent_four_claim_gate": "HOLD", "qualification_sha256": digest((output / "qualification.json").read_bytes())}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in HASHES:
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--linker", default="ld")
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    output = args.output.resolve()
    linker = shutil.which(args.linker)
    require(linker is not None, "linker is unavailable")
    if args.worker:
        worker(args, output, linker)
        return
    output.mkdir(parents=True, exist_ok=False)
    prefix = output / "empty-bytecode-cache"
    prefix.mkdir()
    command = [sys.executable, "-B", str(Path(__file__).resolve()), "--worker", "--output", str(output),
               "--linker", linker]
    for name in HASHES:
        command.extend(["--" + name, str(getattr(args, name).resolve())])
    process = subprocess.run(command, capture_output=True, text=True, timeout=180, check=False, cwd=ROOT,
        env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONPYCACHEPREFIX=str(prefix)))
    save(output / "worker-process.json", {"command": command, "returncode": process.returncode,
        "stdout": process.stdout, "stderr": process.stderr})
    print(process.stdout, end="")
    if process.returncode:
        print(process.stderr, end="", file=sys.stderr)
        raise SystemExit(process.returncode)


if __name__ == "__main__":
    main()
