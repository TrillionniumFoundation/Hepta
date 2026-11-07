"""Reproduce the fixed-Core HIA bootstrap and retain every native generation.

Only build_seed invokes the Python assembler/verifier/direct backend. From B1
onward a disposable stdlib-only child executes the previous HIA-generated flat
image. The parent transports and hashes bytes; it never translates a successor.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))
SOURCE = ROOT / "examples/hia_bootstrap/selfhost.hiaasm"
SAMPLE = ROOT / "examples/hia_bootstrap/bytesum.hiaasm"
CHILD = ROOT / "tools/hia_selfhost_child.py"
CAPACITY = 1 << 20
INVALID, NO_SPACE = 0xffffffff, 0xfffffffe


def digest(data):
    return sha256(data).hexdigest()


def source_manifest():
    paths = ["tools/generate_hia_selfhost.py", "tools/qualify_hia_selfhost.py",
             "tools/hia_selfhost_child.py", "examples/hia_bootstrap/selfhost.hiaasm",
             "examples/hia_bootstrap/bytesum.hiaasm", "docs/HIA_SELF_HOSTING_CORE.md",
             "tests/test_hia_selfhost.py", "hepta/hia_program_native.py",
             "hepta/hia_native_byte_abi.py", "hepta/hia_program.py",
             "hepta/hia_agent_assembly.py", "hepta/hia_machine_x64.py",
             "hepta/hia_machine_elf.py", "hepta/hia_machine_plan.py"]
    return {name: digest((ROOT / name).read_bytes()) for name in paths}


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
    (Path(directory) / "B0.receipt.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    return output, receipt


def invoke(directory, label, image, source, *, image_format="flat-x86-64",
           capacity=CAPACITY, workspace_size=CAPACITY, workspace_fill=0):
    """Copy private inputs and run one pinned artifact under fixed limits."""
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
    request_path.write_text(json.dumps(request, sort_keys=True) + "\n")
    started = time.monotonic_ns()
    try:
        process = subprocess.run([sys.executable, "-I", "-B", str(CHILD), str(request_path.resolve())],
                                 cwd=directory, capture_output=True, text=True, timeout=20)
    except subprocess.TimeoutExpired:
        result = {"status": "timeout", "wall_limit_seconds": 20}
    else:
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
    output = output_path.read_bytes() if output_path.exists() else b""
    (directory / (label + ".receipt.json")).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result, output


def compile_stage(directory, label, image, source, *, image_format="flat-x86-64", workspace_fill=0):
    result, output = invoke(directory, label, image, source, image_format=image_format,
                            workspace_fill=workspace_fill)
    if result.get("status") != "returned" or result.get("abi_status") != 0 or result["core_u32"] > len(output):
        raise AssertionError({"compile_failed": label, "receipt": result})
    assert result["source_unchanged"] and not result["forbidden_compiler_modules_loaded"]
    size = result["core_u32"]
    assert 0 < size <= CAPACITY
    produced = output[:size]
    path = Path(directory) / (label + ".image.bin")
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
    start = source.index(b"\nfn f3(")
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
        "backward-call": sample.replace(b'{"function":"f1"}', b'{"function":"f0"}', 1),
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


def qualify(output):
    output = Path(output).resolve()
    if platform.system() != "Linux" or platform.machine().lower() not in {"x86_64", "amd64"} or not shutil.which("ld"):
        raise RuntimeError("the explicit B0 profile requires Linux x86-64 and GNU ld")
    before = source_manifest()
    started = time.monotonic_ns()
    directory = output.with_suffix(".evidence")
    directory.mkdir(parents=True, exist_ok=False, mode=0o700)
    source, sample = SOURCE.read_bytes(), SAMPLE.read_bytes()
    seed, seed_receipt = build_seed(directory, source)
    stages = []
    previous = seed
    for label in ("B1", "B2", "B3"):
        previous, receipt = compile_stage(directory, label, previous, source,
            image_format="seed-shared" if label == "B1" else "flat-x86-64",
            workspace_fill=0x5a if label == "B3" else 0)
        stages.append(receipt)
    original = previous
    checks = {"three_native_self_compilations": True,
              "B1_B2_B3_byte_identical": len({x["produced_sha256"] for x in stages}) == 1,
              "no_host_compiler_modules_in_successors": all(not x["forbidden_compiler_modules_loaded"] for x in stages)}
    changed = mutate_compiler(source)
    (directory / "modified-selfhost.hiaasm").write_bytes(changed)
    modified_stages = []
    for label in ("M1", "M2", "M3"):
        previous, receipt = compile_stage(directory, label, previous, changed)
        modified_stages.append(receipt)
    checks["modified_codegen_changes_successor"] = modified_stages[0]["produced_sha256"] != modified_stages[1]["produced_sha256"]
    checks["modified_compiler_rebuilds_itself"] = modified_stages[1]["produced_sha256"] == modified_stages[2]["produced_sha256"]
    checks["modified_compiler_differs_from_original"] = modified_stages[2]["produced_sha256"] != stages[2]["produced_sha256"]
    # The generated wrapper's actual stack reservation is part of the change.
    checks["modified_wrapper_machine_bytes"] = original.read_bytes()[:8] == bytes.fromhex("554889e54883ec40") and previous.read_bytes()[:8] == bytes.fromhex("554889e54883ec50")
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
    small, _ = invoke(directory, "short-output", original, source, capacity=stages[2]["produced_bytes"] - 1)
    checks["short_output_is_transactional"] = small.get("status") == "returned" and small.get("core_u32") == NO_SPACE and small.get("output_unchanged")
    workspace, _ = invoke(directory, "short-workspace", original, source, workspace_size=1024)
    checks["short_workspace_rejected"] = workspace.get("status") == "returned" and workspace.get("core_u32") == NO_SPACE and workspace.get("output_unchanged")
    checks["source_closure_unchanged"] = source_manifest() == before
    report = {
        "schema": "hepta.hia.selfhost-qualification.v1",
        "status": "SELF_HOSTED_FIXED_CORE_PASS" if all(checks.values()) else "FAIL",
        "source_manifest": before, "source_bytes": len(source), "source_sha256": digest(source),
        "checks": checks, "seed": seed_receipt, "generations": stages,
        "modified_source_sha256": digest(changed), "modified_generations": modified_stages,
        "behavior_observations": observations, "rejection_observations": rejected,
        "readonly_call_observations": [readonly_build, readonly],
        "capacity_observations": [small, workspace], "elapsed_ns": time.monotonic_ns() - started,
        "claims": {"HIA_parser_used_after_seed": True, "HIA_validator_used_after_seed": True,
                   "HIA_x86_generator_used_after_seed": True, "own_source_compiled": True,
                   "modified_own_source_rebuilt": all(checks[k] for k in ("modified_compiler_rebuilds_itself", "modified_codegen_changes_successor", "modified_wrapper_machine_bytes")),
                   "precompiled_successor_blob_used": False, "source_hash_dispatch_used": False,
                   "python_parser_or_codegen_after_B0": False, "external_assembler_after_B0": False,
                   "external_linker_after_B0": False, "whole_HIA_language_self_hosted": False,
                   "compiler_correctness_formally_proved": False},
        "trusted_dependencies": ["B0 Python HIA assembler, Core verifier, direct x86 emitter and ELF writer",
            "B0 GNU ld, libc and dynamic loader", "successor stdlib ctypes/mmap loader and operating system",
            "Linux x86-64 hardware, caller-owned exclusive buffers and resource limits"],
        "scope": "fixed canonical HIA v8 subset documented in docs/HIA_SELF_HOSTING_CORE.md",
    }
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    report = qualify(arguments.output)
    print(json.dumps({"status": report["status"], "output": str(arguments.output),
                      "checks_passed": sum(report["checks"].values()), "checks_total": len(report["checks"]),
                      "generation_sha256": [x["produced_sha256"] for x in report["generations"]],
                      "modified_generation_sha256": [x["produced_sha256"] for x in report["modified_generations"]]}, sort_keys=True))
    raise SystemExit(0 if report["status"] == "SELF_HOSTED_FIXED_CORE_PASS" else 1)


if __name__ == "__main__":
    main()
