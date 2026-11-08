#!/usr/bin/env python3
"""Retain one five-type, bidirectional C1/Safe Core admission boundary replay.

The exact original select candidate compiles the machine subjects. No Python
producer substitutes for its leaf output. No source, ABI, object metadata or
checker profile is changed to seek a positive proof.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
CAPACITY = 1 << 20
TYPES = ("u8", "u32", "u64", "usize", "bool")
C1_SHA = "2dd847d9df46392e4ef4b99c781b45f56c9841ae61127a260be6e8523f042845"
C1_CORE = "10284cea893a06091e3bb1de5c9e593148915469f820993d49952386503c428b"
LINK_FLAGS = ["-m", "elf_x86_64", "-shared", "-z", "defs", "-z", "noexecstack",
              "-z", "relro", "-z", "now", "--hash-style=both", "--build-id=none"]


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def digest(data):
    return sha256(data).hexdigest()


def selfhost_source(typ):
    """A single, small function with the C1-required three-buffer signature.

    All three select inputs are data-dependent. Mutable buffers are unused but
    retained in the exact Core and ABI. Removing them would change the subject.
    """
    lines = ["hia-asm.v1 hepta.hia.program.v8 selfhost_elf",
        "fn f0(v0:readbuf,v1:mutbuf,v2:mutbuf)->(u32) effects(read,write,trap) entry(b0)",
        "block b0(v0:readbuf,v1:mutbuf,v2:mutbuf)",
        '  v3:usize = const() {"value":0}',
        "  v4:u8 = buffer.load(v0,v3)",
        '  v5:u8 = const() {"value":0}',
        "  v6:bool = compare.ne(v4,v5)",
        '  v7:usize = const() {"value":1}',
        "  v8:u8 = buffer.load(v0,v7)",
        '  v9:usize = const() {"value":2}',
        "  v10:u8 = buffer.load(v0,v9)"]
    if typ == "bool":
        lines += ["  v11:bool = compare.ne(v8,v5)", "  v12:bool = compare.ne(v10,v5)",
            "  v13:bool = select(v6,v11,v12)", "  branch v13 b1() b2()",
            "block b1()", '  v14:u32 = const() {"value":1}', "  ret(v14)",
            "block b2()", '  v15:u32 = const() {"value":0}', "  ret(v15)"]
    elif typ == "u8":
        lines += ["  v11:u8 = select(v6,v8,v10)",
            '  v12:u32 = int.cast(v11) {"mode":"wrap"}', "  ret(v12)"]
    else:
        lines += [f'  v11:{typ} = int.cast(v8) {{"mode":"wrap"}}',
            f'  v12:{typ} = int.cast(v10) {{"mode":"wrap"}}',
            f"  v13:{typ} = select(v6,v11,v12)"]
        if typ == "u32":
            lines.append("  ret(v13)")
        else:
            lines += ['  v14:u32 = int.cast(v13) {"mode":"wrap"}', "  ret(v14)"]
    return ("\n".join(lines) + "\nend\n").encode()


def scalar_source(typ):
    return ("hia-asm.v1 hepta.hia.program.v8 selfhost_elf\n"
        f"fn f0(v0:bool,v1:{typ},v2:{typ})->({typ}) effects(read,write,trap) entry(b0)\n"
        f"block b0(v0:bool,v1:{typ},v2:{typ})\n"
        f"  v3:{typ} = select(v0,v1,v2)\n  ret(v3)\nend\n").encode()


def source_inventory():
    paths = list((ROOT / "hepta").glob("*.py")) + [Path(__file__).resolve(), ROOT / "tools/hia_selfhost_child.py"]
    return {p.relative_to(ROOT).as_posix(): digest(p.read_bytes()) for p in sorted(paths)}


def run_native_compiler(directory, label, image, source, image_format):
    directory.mkdir()
    source_path, output_path = directory / "input.hiaasm", directory / "output-full.bin"
    source_path.write_bytes(source)
    child = ROOT / "tools/hia_selfhost_child.py"
    request = {"format": image_format, "image": str(image), "image_sha256": digest(image.read_bytes()),
        "source": str(source_path), "source_sha256": digest(source), "capacity": CAPACITY,
        "workspace_size": CAPACITY, "workspace_fill": 0, "output": str(output_path)}
    request_path = directory / "request.json"
    save(request_path, request)
    command = [sys.executable, "-I", "-B", str(child), str(request_path)]
    started = time.monotonic()
    try:
        process = subprocess.run(command, cwd=directory, capture_output=True, timeout=25, check=False)
    except subprocess.TimeoutExpired as exc:
        (directory / "stdout.json").write_bytes(exc.stdout or b"")
        (directory / "stderr.log").write_bytes(exc.stderr or b"")
        save(directory / "process.json", {"command": command, "status": "timeout", "wall_limit_seconds": 25})
        raise
    (directory / "stdout.json").write_bytes(process.stdout)
    (directory / "stderr.log").write_bytes(process.stderr)
    saved = {"label": label, "command": command, "returncode": process.returncode,
        "elapsed_seconds": time.monotonic() - started, "runner_sha256": digest(child.read_bytes()),
        "image_sha256": request["image_sha256"], "source_sha256": request["source_sha256"]}
    save(directory / "process.json", saved)
    if process.returncode:
        raise AssertionError("native C1 invocation failed: " + label)
    row = json.loads(process.stdout)
    if (row["status"] != "returned" or row["abi_status"] != 0 or not row["source_unchanged"] or
            row["forbidden_compiler_modules_loaded"] or row["image_sha256"] != request["image_sha256"]):
        raise AssertionError("native C1 execution contract differs: " + label)
    raw = output_path.read_bytes()
    if len(raw) != CAPACITY or digest(raw) != row["output_sha256"]:
        raise AssertionError("native C1 output bytes differ from its retained receipt")
    return row, raw


def structure(checked):
    functions = checked.as_dict()["functions"]
    calls = []
    cyclic_functions = []
    opcodes = set()
    for fn in functions:
        graph = {}
        for block in fn["blocks"]:
            term = block["term"]
            graph[block["id"]] = ([term["target"]] if term["op"] == "jump" else
                [term["then"]["target"], term["else"]["target"]] if term["op"] == "branch" else [])
            for op in block["ops"]:
                opcodes.add(op["op"])
                if op["op"] == "call":calls.append({"caller": fn["name"], "callee": op["attrs"]["function"]})
        visited, active = set(), set()
        def cycle(name):
            if name in active:return True
            if name in visited:return False
            visited.add(name);active.add(name)
            found = any(cycle(target) for target in graph[name])
            active.remove(name)
            return found
        if any(cycle(name) for name in graph):cyclic_functions.append(fn["name"])
    return {"functions": len(functions), "blocks": sum(len(f["blocks"]) for f in functions),
        "operations": sum(len(b["ops"]) for f in functions for b in f["blocks"]),
        "maximum_function_parameters": max(len(f["params"]) for f in functions),
        "functions_with_cfg_cycles": cyclic_functions, "direct_calls": calls,
        "self_calls": [row for row in calls if row["caller"] == row["callee"]], "opcodes": sorted(opcodes)}


def worker(candidate, output, linker):
    prefix = output / "empty-bytecode-cache"
    if (not sys.dont_write_bytecode or sys.pycache_prefix is None or
            Path(sys.pycache_prefix).resolve() != prefix or any(prefix.rglob("*.pyc"))):
        raise RuntimeError("new worker needs -B and its fresh bytecode cache prefix")
    sys.path.insert(0, str(ROOT))
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program_native import emit_program_machine, compile_program_machine
    from hepta.hia_safe_core import _profile, validate_safe_core_artifact, SafeCoreRejected
    before = source_inventory()
    save(output / "source-identity.json", before)
    source = candidate.read_bytes()
    if digest(source) != C1_SHA:raise AssertionError("not the original frozen C1 source")
    (output / "candidate-selfhost.hiaasm").write_bytes(source)
    c1 = assemble_program(source)
    if c1.sha256 != C1_CORE:raise AssertionError("original C1 canonical Core changed")
    (output / "candidate.core.json").write_bytes(c1.canonical_bytes)
    programs = {}
    for typ in TYPES:
        for kind, builder in (("c1_input", selfhost_source), ("safe_core_input", scalar_source)):
            raw = builder(typ)
            checked = assemble_program(raw)
            if kind == "safe_core_input":_profile(checked)
            programs[typ, kind] = (raw, checked)
    summary = {"schema": "hepta.hia.original-c1-safe-core-boundary.v1", "status": "STARTED",
        "c1_source_sha256": C1_SHA, "c1_core_sha256": C1_CORE, "c1_structure": structure(c1),
        "checker_source_commit": "aad3bbb4f3cb7d08362d197704b3c99a4eb651c2",
        "original_agent_four_claim_gate": "HOLD", "provider_history_costs": "unavailable",
        "source_identity": before, "observations": []}
    save(output / "boundary.json", summary)
    try:
        # This is the explicit Python seed boundary, applied to C1 itself. It is
        # never used to emit any of the five leaf machine subjects.
        machine = emit_program_machine(c1, foreign_buffer_exports=(("f0", CAPACITY),))
        (output / "B0.o").write_bytes(machine.object_bytes)
        seed = output / "B0.so"
        receipt = compile_program_machine(machine, program=c1, output=seed, linker=linker)
        save(output / "B0-build.json", {"build": receipt, "source_sha256": C1_SHA,
            "core_sha256": C1_CORE, "object_sha256": digest(machine.object_bytes),
            "image_sha256": digest(seed.read_bytes()), "scope": "unproved Python seed compilation of exact C1"})
        built, raw = run_native_compiler(output / "C1-self-compile", "C1-self-compile", seed, source, "seed-shared")
        size = built["core_u32"]
        if not 0 < size <= CAPACITY:raise AssertionError("C1 did not self-compile to a flat image")
        compiler = output / "C1.image.bin"
        compiler.write_bytes(raw[:size])
        summary["actual_c1_execution_image"] = {"bytes": size, "sha256": digest(compiler.read_bytes()),
            "provenance": "exact C1 source, emitted by native execution of the explicitly identified B0 seed",
            "self_hosted_successor_count": 1, "fixed_point_claimed": False, "lowering_refinement_proved": False}
        for typ in TYPES:
            asm, checked = programs[typ, "c1_input"]
            directory = output / ("c1-output-" + typ)
            produced, raw = run_native_compiler(directory, "c1-output-" + typ, compiler, asm, "flat-x86-64")
            size = produced["core_u32"]
            if not 0 < size <= CAPACITY:raise AssertionError("C1 rejected its declared select input: " + typ)
            obj, final = directory / "subject.o", directory / "subject.so"
            obj.write_bytes(raw[:size])
            (directory / "core.json").write_bytes(checked.canonical_bytes)
            command = [linker, *LINK_FLAGS, str(obj), "-lc", "-o", str(final)]
            link = subprocess.run(command, text=True, capture_output=True, timeout=20, check=False)
            save(directory / "link.json", {"command": command, "returncode": link.returncode,
                "stdout": link.stdout, "stderr": link.stderr})
            if link.returncode:raise AssertionError("normal C1 output link failed: " + typ)
            record = {"type": typ, "direction": "C1_output_to_Safe_Core", "source_sha256": digest(asm),
                "core_sha256": checked.sha256, "object_sha256": digest(obj.read_bytes()),
                "final_image_sha256": digest(final.read_bytes()), "compiler_image_sha256": digest(compiler.read_bytes()),
                "core_functions": len(checked.as_dict()["functions"]), "borrowed_ranges": 3,
                "native_leaf_executed": False, "python_leaf_codegen_used": False}
            try:
                validate_safe_core_artifact(checked, obj.read_bytes(), final.read_bytes(),
                    foreign_buffer_exports=(("f0", CAPACITY),), query_directory=directory / "queries")
            except SafeCoreRejected as exc:
                record.update(status="unsupported_profile", error=str(exc),
                    validation=exc.validation, counterexample=exc.counterexample, proof_issued=False)
                if (str(exc) != "E_HIA_SAFE_CORE: one borrowed range and at most six ABI argument words are admitted" or
                        exc.validation is not None or exc.counterexample is not None):
                    save(directory / "validation.json", record)
                    raise AssertionError("unexpected validation outcome") from exc
            else:
                raise AssertionError("unchanged Safe Core admitted three borrowed ranges")
            save(directory / "validation.json", record)
            summary["observations"].append(record)
            asm, checked = programs[typ, "safe_core_input"]
            directory = output / ("safe-core-input-" + typ)
            refused, raw = run_native_compiler(directory, "safe-core-input-" + typ, compiler, asm, "flat-x86-64")
            (directory / "core.json").write_bytes(checked.canonical_bytes)
            record = {"type": typ, "direction": "Safe_Core_scalar_input_to_C1", "source_sha256": digest(asm),
                "core_sha256": checked.sha256, "safe_core_syntax_profile_admitted": True,
                "machine_proof_issued": False, "compiler_image_sha256": digest(compiler.read_bytes()),
                "native_compiler_result": refused["core_u32"], "source_unchanged": refused["source_unchanged"],
                "output_unchanged": refused["output_unchanged"], "status": "C1_INVALID"}
            save(directory / "admission.json", record)
            if refused["core_u32"] != 0xffffffff or not refused["output_unchanged"]:
                raise AssertionError("scalar input did not hit C1's declared entry restriction")
            summary["observations"].append(record)
            save(output / "boundary.json", summary)
        if before != source_inventory() or any(prefix.rglob("*.pyc")):
            raise AssertionError("source/cache identity changed")
        summary.update(status="HOLD_C1_SAFE_CORE_CONTRACT_DISJOINT", evidence_checks_passed=True,
            counts={"native_compiler_invocations": 11, "actual_C1_objects_linked": 5,
                "actual_artifact_profile_refusals": 5, "scalar_C1_refusals": 5,
                "machine_proofs_issued": 0, "native_leaf_calls": 0},
            subject_transformation_used=False, new_wrapper_used=False, binder_or_profile_modified=False,
            host_reference_parsing_after_B0=True, host_codegen_after_B0=False,
            ordinary_host_linker_after_B0=True,
            conclusion="C1 requires three borrowed entry parameters; the unchanged Safe Core profile permits at most one. These exact entry contracts have no direct intersection.")
    except BaseException as exc:
        summary.update(status="FAILED_BOUNDARY_REPLAY", evidence_checks_passed=False,
                       failure={"type": type(exc).__name__, "message": str(exc)})
        save(output / "boundary.json", summary)
        raise
    save(output / "boundary.json", summary)
    print(json.dumps({"status": summary["status"], "counts": summary["counts"]}, sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--linker", default="ld")
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    output, candidate = args.output.resolve(), args.candidate.resolve()
    linker = shutil.which(args.linker)
    if not linker or platform.system() != "Linux" or platform.machine().lower() not in {"x86_64", "amd64"}:
        raise RuntimeError("this precise evidence profile requires Linux x86-64 and GNU ld")
    if args.worker:
        worker(candidate, output, linker)
        return
    output.mkdir(parents=True, exist_ok=False)
    (output / "empty-bytecode-cache").mkdir()
    command = [sys.executable, "-B", str(Path(__file__).resolve()), "--worker", "--candidate", str(candidate),
               "--output", str(output), "--linker", linker]
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONPYCACHEPREFIX=str(output / "empty-bytecode-cache"))
    process = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True, timeout=180, check=False)
    save(output / "worker-process.json", {"command": command, "returncode": process.returncode,
         "stdout": process.stdout, "stderr": process.stderr})
    print(process.stdout, end="")
    if process.returncode:
        print(process.stderr, end="", file=sys.stderr)
        raise SystemExit(process.returncode)


if __name__ == "__main__":
    main()
