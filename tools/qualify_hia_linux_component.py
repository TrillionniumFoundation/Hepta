#!/usr/bin/env python3
"""Prepare, apply and read back one real HIA hweight32 kernel replacement.

This is a manually authored checked-Hepta -> HIA Core -> LLVM object pipeline.
The original x86 assembly ABI is retained in an explicit non-HIA bridge. No C
implementation body or hosted allocator is linked into the HIA implementation.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import mmap
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import time
import zlib

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from hepta.hia_linux_kernel import (build_kernel_object, config_profile, reinspect_kernel_object,
                                   kernel_ir, qualify_leaf, require)
from hepta.hia_program import execute_program, verify_program
from hepta.hia_program_source import lower_source
from hepta.hia_program_llvm import _run_logged

ASSETS = ROOT / "examples/hia_linux_kernel"
LINUX_COMMIT = "f45ed76d6791cf72ff1265ee93511175bbbc2f18"
UPSTREAM = ("lib/hweight.c", "arch/x86/lib/hweight.S", "arch/x86/lib/Makefile",
            "arch/x86/include/asm/arch_hweight.h", "Makefile")
UPSTREAM_SHA256 = dict(zip(UPSTREAM, (
    "c4da85f3aab22244a6029b5745e3d74efdc310a5227951ef82df4219af4f9931",
    "12cc569b2a6022f9cad115c34139dad681f783be7c0f6c411297f428db08633d",
    "001f0ca3635a898f4559f3eafee6b2c625f305b25ce76cc3ca2d414233944315",
    "8857cf7d5c782c3fba1ab5dadc55949eadd19ac454078d03c58aaf484366c5f2",
    "b2bd95161a18643785ce5a5975ba5b156d9af2c12b6451584e92d3ee57bcbc3c")))
CALLS = 135168
PREFIX = "HIA_LINUX_COMPONENT_TEST "
WRAPPER = """SYM_FUNC_START(__sw_hweight32)
\tANNOTATE_NOENDBR
\t/* Explicit ASM ABI bridge, not translated arithmetic or HIA state. */
\tpushq %rdi
\tpushq %rsi
\tpushq %rdx
\tpushq %rcx
\tpushq %r8
\tpushq %r9
\tpushq %r10
\tpushq %r11
\tsubq $8, %rsp
\tcall hia_sw_hweight32
\taddq $8, %rsp
\tpopq %r11
\tpopq %r10
\tpopq %r9
\tpopq %r8
\tpopq %rcx
\tpopq %rdx
\tpopq %rsi
\tpopq %rdi
\tRET
SYM_FUNC_END(__sw_hweight32)"""


def binding(path):
    path = Path(path).absolute()
    data = path.read_bytes()
    return {"path": str(path), "bytes": len(data), "sha256": sha256(data).hexdigest()}


def write(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = value if type(value) is bytes else (value.encode() if type(value) is str else
             (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode())
    with path.open("xb") as stream:
        stream.write(data)


def source_identity(expected, development=False):
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    def git(*args):
        return subprocess.check_output(["git", "--no-replace-objects", "-C", str(ROOT), *args], env=env, text=True).strip()
    head, status = git("rev-parse", "HEAD"), git("status", "--porcelain")
    require(head == expected and re.fullmatch("[0-9a-f]{40}", expected), "exact source commit required")
    require(development or not status, "formal component preparation requires a clean committed checkout")
    hashes = implementation_files()
    if not development:
        tracked = set(git("ls-files").splitlines())
        require(set(hashes) <= tracked, "all component inputs and tests must be committed before formal execution")
    return {"commit": head, "status": status, "files": hashes, "development_only": development}


def implementation_files():
    paths = [Path(__file__), ROOT / "hepta/hia_linux_kernel.py", ROOT / "tests/test_hia_linux_component.py",
             *sorted(ASSETS.iterdir())]
    return {str(p.relative_to(ROOT)): binding(p)["sha256"] for p in paths if p.is_file()}


def inputs():
    state = 0x6a09e667
    for i in range(CALLS):
        if i < 65536:
            yield i
        elif i < 131072:
            yield (~(i - 65536)) & 0xffffffff
        else:
            state ^= (state << 13) & 0xffffffff
            state ^= state >> 17
            state ^= (state << 5) & 0xffffffff
            yield state


def expected_digest():
    digest = 1469598103934665603
    for value in inputs():
        digest = ((digest ^ value ^ (value.bit_count() << 32)) * 1099511628211) & ((1 << 64) - 1)
    return f"{digest:016x}"


def prove_arithmetic(program, folder):
    """All-u32 formula equality; neither a native proof nor C refinement."""
    import z3
    from hepta.hia_optimization import PINNED_Z3_VERSION, _solver_identity
    require(z3.get_version_string() == PINNED_Z3_VERSION, "pinned Z3 4.15.4 is required for this formula receipt")
    solver_identity = _solver_identity(z3)
    core = qualify_leaf(program).as_dict()
    require(len(core["functions"]) == 1, "one hweight implementation required for this formula")
    fn = core["functions"][0]
    require(len(fn["params"]) == 1, "one u32 input required")
    x = z3.BitVec("input_u32", 32)
    values = {fn["params"][0]["name"]: x}
    binary = {"int.add.wrap": lambda a, b: a + b, "int.sub.wrap": lambda a, b: a - b,
              "int.mul.wrap": lambda a, b: a * b, "bit.and": lambda a, b: a & b,
              "bit.or": lambda a, b: a | b, "bit.xor": lambda a, b: a ^ b,
              "int.shr.checked": z3.LShR, "int.shl.checked": lambda a, b: a << b}
    block = fn["blocks"][0]
    for op in block["ops"]:
        args = [values[name] for name in op["args"]]
        if op["op"] == "const":
            value = z3.BitVecVal(op["attrs"]["value"], 32)
        elif op["op"] == "bit.not":
            value = ~args[0]
        else:
            value = binary[op["op"]](*args)
        values[op["out"][0]["name"]] = value
    oracle = sum((z3.ZeroExt(31, z3.Extract(i, i, x)) for i in range(32)), z3.BitVecVal(0, 32))
    solver = z3.SolverFor("QF_BV")
    solver.set(timeout=30000, random_seed=0)
    solver.add(values[block["term"]["values"][0]] != oracle)
    formula = solver.to_smt2()
    write(folder / "popcount-equivalence.smt2", formula)
    start = time.perf_counter_ns()
    verdict = str(solver.check())
    require(_solver_identity(z3) == solver_identity, "actual SMT library/binding changed during the query")
    return {"status": "PASS" if verdict == "unsat" else "FAIL", "verdict": verdict,
            "solver": z3.get_version_string(), "solver_identity": solver_identity,
            "formula": binding(folder / "popcount-equivalence.smt2"), "wall_ns": time.perf_counter_ns() - start,
            "scope": "verified pure-u32 Core arithmetic vs independent sum of 32 bits, all 2^32 inputs",
            "backend_or_source_refinement_proved": False}


def overlays(linux, folder, artifact, core_sha):
    original = (linux / "arch/x86/lib/hweight.S").read_text()
    pattern = r"SYM_FUNC_START\(__sw_hweight32\).*?SYM_FUNC_END\(__sw_hweight32\)"
    require(len(re.findall(pattern, original, re.S)) == 1, "exact original x86 body required")
    hybrid = re.sub(pattern, lambda _: WRAPPER, original, flags=re.S)
    # The unmodified 64-bit body must remain byte-identical.
    tail = "SYM_FUNC_START(__sw_hweight64)"
    require(hybrid.split(tail)[1] == original.split(tail)[1], "64-bit assembly must be retained")
    base_makefile = (linux / "arch/x86/lib/Makefile").read_text()
    common = "\n# Common component observation, identical control and hybrid driver.\nobj-y += hia_component_selftest.o hia_abi_probe.o\n"
    build_rule = """
# Source-bound precompiled HIA; normal Kbuild objtool remains active/delayed.
obj-y += hia_hweight.o
targets += hia_hweight.o
quiet_cmd_hia_object = HIAOBJ  $@
      cmd_hia_object = $(PYTHON3) $(src)/hia_copy_object.py $(src)/hia_hweight.input.bin $@ OBJECT_SHA$(cmd_objtool)
$(obj)/hia_hweight.o: $(src)/hia_hweight.input.bin $(src)/hia_copy_object.py FORCE
\t$(call if_changed,hia_object)
\t$(call cmd,gen_objtooldep)
""".replace("OBJECT_SHA", artifact["sha256"])
    manifests = {}
    for arm in ("control", "hybrid"):
        target = folder / (arm + "-overlay")
        identity = ('/* Explicit arm identity only; the test algorithm is identical. */\n'
                    f'#define HIA_COMPONENT_ARM "{arm}"\n'
                    f'#define HIA_COMPONENT_CORE_SHA256 "{core_sha if arm == "hybrid" else "0" * 64}"\n'
                    f'#define HIA_COMPONENT_OBJECT_SHA256 "{artifact["sha256"] if arm == "hybrid" else "0" * 64}"\n')
        files = {"arch/x86/lib/Makefile": (base_makefile + common + (build_rule if arm == "hybrid" else "")).encode(),
                 "arch/x86/lib/hia_component_selftest.c": (ASSETS / "guest_selftest.c").read_bytes(),
                 "arch/x86/lib/hia_abi_probe.S": (ASSETS / "abi_probe.S").read_bytes(),
                 "arch/x86/lib/hia_component_identity.h": identity.encode()}
        if arm == "hybrid":
            files.update({"arch/x86/lib/hweight.S": hybrid.encode(),
                          "arch/x86/lib/hia_hweight.input.bin": Path(artifact["path"]).read_bytes(),
                          "arch/x86/lib/hia_copy_object.py": (ASSETS / "copy_object.py").read_bytes()})
        entries = []
        for name, data in files.items():
            write(target / name, data)
            entries.append({"relative_path": name, "before_sha256": binding(linux / name)["sha256"] if (linux / name).exists() else None,
                            "after": binding(target / name)})
        manifest = {"schema": "hepta.hia.kernel-component-overlay.v1", "arm": arm, "files": entries,
                    "configuration_sha256": artifact["config"]["sha256"], "stock_source_untouched": True,
                    "whole_kernel_rewrite": False}
        write(target / "OVERLAY.json", manifest)
        manifests[arm] = binding(target / "OVERLAY.json")
    return manifests


def prepare(linux, config, output, source_sha, clang, objdump, *, development=False):
    started = time.perf_counter_ns()
    linux, output, config = Path(linux).resolve(), Path(output).absolute(), Path(config).resolve()
    require(not output.exists() and not output.is_relative_to(linux) and not output.is_relative_to(ROOT), "new output outside all source trees required")
    output.mkdir(parents=True)
    report = {"schema": "hepta.hia.linux-component.v1", "status": "FAIL", "commands": [], "artifact": None,
              "oracle_diff": {"status": "NOT_RUN", "planned_cases": CALLS}, "native_gate": {"status": "NOT_RUN"},
              "guest_gate": {"status": "NOT_RUN"}, "whole_kernel_rewrite": False}
    def command(argv, *, success=True):
        begin = time.perf_counter_ns()
        result = _run_logged([str(a) for a in argv], command_log=report["commands"], timeout=60,
                             stdout_limit=2_000_000, stderr_limit=2_000_000)
        report["commands"][-1]["wall_ns"] = time.perf_counter_ns() - begin
        require(not success or result.returncode == 0, "native command failed: " + result.stderr[-2000:])
        return result
    try:
        report["implementation_source"] = source_identity(source_sha, development)
        upstream = {name: binding(linux / name) for name in UPSTREAM}
        require({name: row["sha256"] for name, row in upstream.items()} == UPSTREAM_SHA256,
                "component inputs differ from the frozen official Linux 6.18.60 archive")
        report["source"] = {"linux_commit": LINUX_COMMIT, "linux_source": str(linux), "files": upstream,
                            "configuration": binding(config), "translation_kind": "authored_checked_hepta_to_hia_core",
                            "automatic_c_translation": False}
        raw_config = config.read_bytes()
        write(output / "kernel.config", raw_config)
        source = (ASSETS / "hweight32.hepta").read_text()
        program = lower_source(source)
        write(output / "hweight32.hepta", source)
        write(output / "hweight32.core.json", program.as_dict())
        ir = kernel_ir(program, raw_config)
        write(output / "hweight32.kernel.ll", ir["text"])
        report["core"] = binding(output / "hweight32.core.json")
        report["hepta_source"] = binding(output / "hweight32.hepta")
        report["llvm_ir"] = binding(output / "hweight32.kernel.ll")
        report["translation_stages"] = {"c_capture": "NOT_RUN_AUTHORED_TRANSLATION", "hepta_checked": "PASS",
                                        "rust_bridge": "NOT_USED", "hia_core_verified": "PASS", "hia_native_object": "NOT_RUN"}
        report["translated_body"] = {"upstream_function": "__sw_hweight32", "target": "hia_sw_hweight32",
                                     "core_sha256": program.sha256, "authored_translation": True,
                                     "original_x86_assembly_arithmetic_replaced": True}
        artifact = build_kernel_object(program, output / "hia_hweight.o", config=raw_config,
                                       clang=clang, objdump=objdump, command_log=report["commands"])
        report["artifact"] = artifact
        report["translation_stages"]["hia_native_object"] = "PASS"
        report["arithmetic_proof"] = prove_arithmetic(program, output)
        require(report["arithmetic_proof"]["status"] == "PASS", "all-u32 arithmetic formula did not prove equivalent")
        vm_inputs = [0, 0xffffffff, 0xaaaaaaaa, 0x55555555] + [1 << i for i in range(32)] + [0xffffffff ^ (1 << i) for i in range(32)] + list(inputs())[-64:]
        vm_rows = []
        for value in vm_inputs:
            observed = execute_program(program, "hia_sw_hweight32", [value])
            require(observed["status"] == "returned" and observed["values"] == [value.bit_count()], "independent Core VM oracle mismatch")
            vm_rows.append({"input": value, "result": observed["values"][0]})
        write(output / "core-vm-observations.json", vm_rows)
        oracle = output / "oracle"
        write(oracle / "linux/export.h", "#define EXPORT_SYMBOL(symbol)\n")
        write(oracle / "linux/bitops.h", "#define BITS_PER_LONG 64\n")
        write(oracle / "asm/types.h", "typedef unsigned long long __u64;\n")
        write(oracle / "upstream_hweight.c", (linux / "lib/hweight.c").read_bytes())
        command([clang, "-std=c11", "-O2", "-fno-lto", "-fno-builtin", "-DCONFIG_ARCH_HAS_FAST_MULTIPLIER=1", "-I", oracle,
                 "-c", oracle / "upstream_hweight.c", "-o", oracle / "original.o"])
        def native_driver(obj, name):
            exe = output / name
            command([clang, "-std=c11", "-O2", "-fno-lto", "-fno-builtin", "-no-pie", "-mgeneral-regs-only", "-mno-popcnt",
                     ASSETS / "host_diff.c", obj, oracle / "original.o", ASSETS / "host_return_thunk.S", "-o", exe])
            return command([exe], success=False), binding(exe)
        positive, driver = native_driver(output / "hia_hweight.o", "native-diff")
        record = json.loads(positive.stdout.removeprefix("HIA_LINUX_NATIVE_DIFF ").strip())
        require(positive.returncode == 0 and record == {"cases": CALLS, "failures": 0, "result_digest": expected_digest()},
                "actual HIA object, unchanged C oracle and independent bit-count differential failed")
        report["oracle_diff"] = {"status": "PASS", **record, "native_driver": driver,
                                 "original_c": binding(oracle / "upstream_hweight.c"),
                                 "platform_header_scope": "authored standalone u32/u64 scalar ABI stubs; not full kernel preprocessing",
                                 "core_vm_cases": len(vm_rows), "raw_observations": binding(output / "core-vm-observations.json")}
        wrong = lower_source('module wrong; export "C" fn hia_sw_hweight32(w:u32)->u32 effects {} {return 0;}')
        negative = build_kernel_object(wrong, output / "wrong_hia.o", config=raw_config, clang=clang, objdump=objdump,
                                       command_log=report["commands"])
        bad, bad_driver = native_driver(output / "wrong_hia.o", "wrong-body-diff")
        bad_record = json.loads(bad.stdout.removeprefix("HIA_LINUX_NATIVE_DIFF ").strip())
        require(bad.returncode != 0 and bad_record["cases"] == CALLS and bad_record["failures"] > 0,
                "the same actual-object driver must reject a wrong HIA body")
        report["native_gate"] = {"status": "PASS", "correct_object_executed": True,
                                 "wrong_body_negative": {"status": "EXPECTED_FAILURE", "returncode": bad.returncode,
                                                         "observation": bad_record, "object": negative, "driver": bad_driver}}
        report["routing"] = {"replaced_symbols": ["__sw_hweight32"], "hia_body_symbols": ["hia_sw_hweight32"],
                             "retained": ["__sw_hweight64", "remaining Linux C/assembly/Rust"],
                             "asm_bridge_count": 1, "hia_implementation_bodies": 1, "whole_kernel_rewrite": False,
                             "register_contract": "all x86 GPRs except RAX preserved by explicit ASM bridge",
                             "direct_selftest_and_natural_hweight_calls_separately_recorded": True}
        report["overlays"] = overlays(linux, output, artifact, program.sha256)
        require({name: binding(linux / name) for name in UPSTREAM} == upstream, "upstream source changed")
        require(source_identity(source_sha, development) == report["implementation_source"], "component source changed")
        report.update(status="PASS", stage="native_component_prepared_guest_not_run", formal_evidence=not development)
    except BaseException as error:
        report["error"] = {"type": type(error).__name__, "message": str(error)}
    finally:
        report["outer_wall_ns"] = time.perf_counter_ns() - started
        write(output / "RESULT.json", report)
    return report


def apply_overlay(component, arm, source_copy, receipt):
    report = json.loads(Path(component).read_text())
    require(report["status"] == "PASS" and arm in {"control", "hybrid"}, "prepared component and explicit arm required")
    overlay_binding = report["overlays"][arm]
    require(binding(overlay_binding["path"]) == overlay_binding, "overlay manifest identity changed")
    manifest = json.loads(Path(overlay_binding["path"]).read_text())
    root = Path(source_copy).resolve()
    require(root.is_dir() and root != Path(report["source"]["linux_source"]).resolve(), "a separate ordinary source copy is required")
    for name, item in report["source"]["files"].items():
        require(binding(root / name)["sha256"] == item["sha256"], "upstream copy differs before overlay: " + name)
    planned = []
    for entry in manifest["files"]:
        relative = Path(entry["relative_path"])
        require(not relative.is_absolute() and ".." not in relative.parts, "relative overlay path required")
        dst = root / relative
        require(not dst.is_symlink() and (not dst.exists() or dst.stat().st_nlink == 1), "do not modify symlinks or hardlinked source copies")
        require((binding(dst)["sha256"] if dst.exists() else None) == entry["before_sha256"], "overlay before-image mismatch")
        require(binding(entry["after"]["path"]) == entry["after"], "overlay payload changed")
        planned.append((dst, Path(entry["after"]["path"]).read_bytes()))
    require(not Path(receipt).exists(), "new application receipt required")
    for dst, data in planned:
        dst.parent.mkdir(parents=True, exist_ok=True)
        temporary = dst.with_name(dst.name + ".hia-new")
        write(temporary, data)
        os.replace(temporary, dst)
    result = {"schema": "hepta.hia.kernel-component-applied.v1", "status": "PASS", "arm": arm,
              "component": binding(component), "overlay": overlay_binding, "source_copy": str(root),
              "configuration_sha256": manifest["configuration_sha256"],
              "files": [binding(dst) for dst, _ in planned], "whole_kernel_rewrite": False}
    write(receipt, result)
    return result


def elf_functions(path, names):
    """Read exact named function bytes from a real ELF64 object or vmlinux.

    No nm labels, self-reported receipt or disassembler text substitutes for
    symbol/section bounds and actual linked bytes. Only this bounded ELF subset
    is admitted; extended numbering and duplicate definitions reject.
    """
    path = Path(path)
    require(0 < path.stat().st_size <= 1_000_000_000, "bounded ELF file required")
    with path.open("rb") as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
        require(data[:6] == b"\x7fELF\x02\x01" and struct.unpack_from("<H", data, 18)[0] == 62, "x86-64 little-endian ELF required")
        kind = struct.unpack_from("<H", data, 16)[0]
        require(kind in (1, 2), "relocatable object or executable vmlinux required")
        table = struct.unpack_from("<Q", data, 40)[0]
        width, count = struct.unpack_from("<HH", data, 58)
        require(width == 64 and 0 < count < 65536 and table + count * width <= len(data), "bounded ordinary ELF section table required")
        sections = [struct.unpack_from("<IIQQQQIIQQ", data, table + i * width) for i in range(count)]
        found = {}
        for sec in sections:
            if sec[1] != 2:
                continue
            offset, size, link, entsize = sec[4], sec[5], sec[6], sec[9]
            require(entsize == 24 and size % 24 == 0 and offset + size <= len(data) and link < count,
                    "complete ELF symbol table required")
            strings = sections[link]
            require(strings[1] == 3 and strings[4] + strings[5] <= len(data), "bounded ELF symbol names required")
            for at in range(offset, offset + size, 24):
                name, info, other, index, value, length = struct.unpack_from("<IBBHQQ", data, at)
                if not name or name >= strings[5] or not index:
                    continue
                start = strings[4] + name
                end = data.find(b"\0", start, strings[4] + strings[5])
                require(end >= start, "unterminated ELF symbol")
                label = data[start:end].decode("utf-8", errors="strict")
                if label not in names:
                    continue
                # Linux declares its return thunk with SYM_CODE_START (NOTYPE),
                # whereas the component/bridge/probe use real function types.
                permitted_kind = (info & 15) == 2 or (label == "__x86_return_thunk" and (info & 15) == 0)
                require(label not in found and permitted_kind and 0 < index < count, "unique declared code/function symbol required: " + label)
                section = sections[index]
                relative = value if kind == 1 else value - section[3]
                require(section[1] == 1 and section[2] & 6 == 6 and 0 < length <= 65536
                        and 0 <= relative and relative + length <= section[5], "function must lie wholly inside executable bytes")
                begin = section[4] + relative
                require(begin + length <= len(data), "function bytes outside ELF")
                code = bytes(data[begin:begin + length])
                found[label] = {"address": value, "bytes": code.hex(), "length": length, "sha256": sha256(code).hexdigest()}
        require(set(found) == set(names), "required native function symbols are missing: " + ", ".join(sorted(set(names) - set(found))))
    return found


def verify_linked_route(component, vmlinux, build_object):
    raw = elf_functions(component["artifact"]["path"], {"hia_sw_hweight32"})["hia_sw_hweight32"]
    built = elf_functions(build_object, {"hia_sw_hweight32"})["hia_sw_hweight32"]
    cfg = component["artifact"]["config"]
    wanted = {"hia_sw_hweight32", "__sw_hweight32", "__sw_hweight64", "hia_hweight_abi_probe"}
    if cfg["rethunk"]:
        wanted.add("__x86_return_thunk")
    linked = elf_functions(vmlinux, wanted)
    require(built["bytes"] == raw["bytes"], "objtool-built HIA arithmetic bytes differ from the admitted object")
    expected = bytearray.fromhex(raw["bytes"])
    actual = bytearray.fromhex(linked["hia_sw_hweight32"]["bytes"])
    require(len(expected) == len(actual), "linked HIA function size differs")
    sealed = False
    if cfg["ibt"] and actual[:4] != expected[:4]:
        require(expected[:4] == bytes.fromhex("f30f1efa") and actual[:4] in
                (bytes.fromhex("0f1f4000"), bytes.fromhex("660f1f00")), "unrecognized IBT sealing transformation")
        actual[:4] = expected[:4]
        sealed = True
    if cfg["rethunk"]:
        require(expected[-5] == actual[-5] == 0xe9 and expected[-4:] == b"\0" * 4, "expected actual leaf return-thunk relocation")
        target = linked["hia_sw_hweight32"]["address"] + len(actual) + int.from_bytes(actual[-4:], "little", signed=True)
        require(target == linked["__x86_return_thunk"]["address"], "linked HIA return goes to an unapproved target")
        actual[-4:] = expected[-4:]
    require(actual == expected, "linked HIA arithmetic differs from admitted bytes")
    bridge = bytes.fromhex(linked["__sw_hweight32"]["bytes"])
    before = bytes.fromhex("5756525141504151415241534883ec08")
    after = bytes.fromhex("4883c408415b415a41594158595a5e5f")
    at = len(before)
    require(bridge[:at] == before and bridge[at] == 0xe8 and bridge[at + 5:at + 5 + len(after)] == after,
            "actual __sw_hweight32 is not the registered all-register-preserving ASM bridge")
    target = linked["__sw_hweight32"]["address"] + at + 5 + int.from_bytes(bridge[at + 1:at + 5], "little", signed=True)
    require(target == linked["hia_sw_hweight32"]["address"], "actual kernel bridge does not call the HIA body")
    tail_at = at + 5 + len(after)
    tail = bridge[tail_at:]
    if cfg["rethunk"]:
        require(len(tail) == 5 and tail[0] == 0xe9, "registered kernel RET thunk required in bridge")
        destination = linked["__sw_hweight32"]["address"] + len(bridge) + int.from_bytes(tail[1:], "little", signed=True)
        require(destination == linked["__x86_return_thunk"]["address"], "bridge return thunk target differs")
    else:
        require(tail == (b"\xc3\xcc" if cfg["sls"] else b"\xc3"), "registered kernel RET macro required")
    return {"status": "PASS", "raw_object_function": raw, "objtool_object_function": built,
            "linked_functions": linked, "ibt_entry_sealed": sealed,
            "arithmetic_bytes_identical_except_validated_ibt_seal_and_thunk_relocation": True,
            "actual_kernel_symbol_calls_hia_body": True, "asm_bridge_is_hia": False}


def verify_boot_payload(kernel_image, linked_functions):
    """Bind analyzed linked code to the actual gzip bzImage passed to QEMU.

    Linux's compressed vmlinux.bin retains ELF program headers after symbols
    are stripped. Compare each relevant code range through its PT_LOAD virtual
    address, rather than trusting that two paths came from the same build.
    """
    image = Path(kernel_image).read_bytes()
    require(0x250 <= len(image) <= 128_000_000 and image[0x1fe:0x200] == b"\x55\xaa"
            and image[0x202:0x206] == b"HdrS", "actual bounded Linux bzImage header required")
    require(struct.unpack_from("<H", image, 0x206)[0] >= 0x208, "boot protocol must declare its actual payload")
    relative, length = struct.unpack_from("<II", image, 0x248)
    offset = ((image[0x1f1] or 4) + 1) * 512 + relative
    require(relative > 0 and 18 <= length and offset + length <= len(image)
            and image[offset:offset + 3] == b"\x1f\x8b\x08", "declared protected-mode payload must be the actual gzip stream")
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    payload = decoder.decompress(image[offset:offset + length], 256_000_000)
    require(decoder.eof and not decoder.unconsumed_tail and len(payload) >= 64
            and payload[:6] == b"\x7fELF\x02\x01", "complete bounded gzip ELF payload required")
    require(struct.unpack_from("<H", payload, 18)[0] == 62, "kernel payload architecture differs")
    table = struct.unpack_from("<Q", payload, 32)[0]
    width, count = struct.unpack_from("<HH", payload, 54)
    require(width == 56 and 0 < count < 1024 and table + width * count <= len(payload), "complete ELF payload load table required")
    segments = [struct.unpack_from("<IIQQQQQQ", payload, table + i * width) for i in range(count)]
    for name, fn in linked_functions.items():
        ranges = [p for p in segments if p[0] == 1 and p[3] <= fn["address"]
                  and fn["address"] + fn["length"] <= p[3] + p[5]]
        require(len(ranges) == 1, "unique payload load mapping required for " + name)
        start = ranges[0][2] + fn["address"] - ranges[0][3]
        require(start + fn["length"] <= len(payload)
                and payload[start:start + fn["length"]].hex() == fn["bytes"],
                "actual bzImage payload differs from analyzed vmlinux code: " + name)
    return {"status": "PASS", "gzip_offset": offset, "declared_payload_bytes": length,
            "uncompressed_bytes": len(payload), "uncompressed_sha256": sha256(payload).hexdigest(),
            "matched_functions": sorted(linked_functions), "runtime_kaslr_or_alternatives_not_read_back": True}


def validate_applied_overlay(component: dict, reference: dict) -> dict:
    """Replay the entire seven-file hybrid overlay, not a supplied subset."""
    require(binding(reference["path"]) == reference, "application receipt changed")
    applied = json.loads(Path(reference["path"]).read_text())
    require(applied["status"] == "PASS" and applied["arm"] == "hybrid"
            and applied["overlay"] == component["overlays"]["hybrid"]
            and applied["configuration_sha256"] == component["artifact"]["config"]["sha256"],
            "wrong or incomplete component overlay application")
    require(binding(applied["component"]["path"]) == applied["component"]
            and json.loads(Path(applied["component"]["path"]).read_text()) == component,
            "application does not bind the exact prepared component receipt")
    require(binding(applied["overlay"]["path"]) == applied["overlay"], "bound overlay manifest changed")
    overlay = json.loads(Path(applied["overlay"]["path"]).read_text())
    require(overlay["arm"] == "hybrid" and overlay["configuration_sha256"] == component["artifact"]["config"]["sha256"],
            "overlay identity differs")
    root = Path(applied["source_copy"]).resolve()
    require(root != Path(component["source"]["linux_source"]).resolve(), "guest must use a distinct modified source tree")
    expected_files, seen = [], set()
    for entry in overlay["files"]:
        relative = Path(entry["relative_path"])
        require(not relative.is_absolute() and ".." not in relative.parts and str(relative) not in seen,
                "overlay must contain unique confined relative paths")
        seen.add(str(relative))
        require(binding(entry["after"]["path"]) == entry["after"], "original overlay payload changed")
        dst = root / relative
        require(dst.resolve().is_relative_to(root), "applied source escaped the copied tree")
        expected = {"path": str(dst), "sha256": entry["after"]["sha256"], "bytes": entry["after"]["bytes"]}
        require(binding(dst) == expected, "applied source or HIA input changed before guest readback")
        expected_files.append(expected)
    require(seen == {"arch/x86/lib/Makefile", "arch/x86/lib/hia_component_selftest.c", "arch/x86/lib/hia_abi_probe.S",
                     "arch/x86/lib/hia_component_identity.h", "arch/x86/lib/hweight.S",
                     "arch/x86/lib/hia_hweight.input.bin", "arch/x86/lib/hia_copy_object.py"},
            "registered seven-file hybrid overlay inventory differs")
    require(expected_files and applied["files"] == expected_files, "complete applied overlay file denominator differs")
    return {"status": "PASS", "application": reference, "overlay": applied["overlay"],
            "source_copy": str(root), "file_count": len(expected_files), "files": expected_files}


def validate_guest_readback(component: dict, observed_inputs: dict) -> dict:
    """Read-only replay, including a fresh invocation of bound llvm-objdump."""
    if "prepared_receipt" in component:
        reference = component["prepared_receipt"]
        require(binding(reference["path"]) == reference, "original prepared component receipt changed")
        prepared = json.loads(Path(reference["path"]).read_text())
        changed = {"stage", "status", "guest_gate", "prepared_receipt", "readback_wall_ns"}
        require({k: v for k, v in component.items() if k not in changed} ==
                {k: v for k, v in prepared.items() if k not in changed}, "final receipt changed prepared inputs or native outcomes")
        component = prepared
    require(component.get("status") == "PASS" and component.get("formal_evidence") is True,
            "formal prepared component is required")
    require(implementation_files() == component["implementation_source"]["files"], "complete registered implementation source inventory differs")
    for key in ("serial_log", "kernel_image", "vmlinux", "build_object", "boot_report", "applied", "kernel_config"):
        require(binding(observed_inputs[key]["path"]) == observed_inputs[key], "readback file identity differs: " + key)
    for key in ("core", "hepta_source", "llvm_ir"):
        require(binding(component[key]["path"]) == component[key], "prepared source artifact changed: " + key)
    artifact = component["artifact"]
    require(component["source"]["linux_commit"] == LINUX_COMMIT
            and {name: row["sha256"] for name, row in component["source"]["files"].items()} == UPSTREAM_SHA256,
            "component upstream identities differ from the registered Linux source")
    require({key: binding(artifact["path"])[key] for key in ("path", "bytes", "sha256")} ==
            {key: artifact[key] for key in ("path", "bytes", "sha256")}, "prepared native object changed")
    raw_config = Path(observed_inputs["kernel_config"]["path"]).read_bytes()
    require(config_profile(raw_config) == artifact["config"], "actual candidate configuration differs from native target admission")
    require(binding(component["source"]["configuration"]["path"]) == component["source"]["configuration"], "original configuration changed")
    require(sha256(raw_config).hexdigest() == component["source"]["configuration"]["sha256"], "control/candidate configuration drift")
    program = verify_program(json.loads(Path(component["core"]["path"]).read_text()))
    ir = kernel_ir(program, raw_config)
    require(ir["core_sha256"] == artifact["core_sha256"] == component["translated_body"]["core_sha256"]
            and ir["sha256"] == artifact["llvm_sha256"] and ir["text"] == Path(component["llvm_ir"]["path"]).read_text(),
            "Core/LLVM/source-qualified kernel artifact identity differs")
    require(all(ir[key] == artifact["implementation"][key]
                for key in ("base_implementation_sha256", "profile_implementation_sha256")), "native compiler implementation identity differs")
    reinspection = reinspect_kernel_object(artifact)
    application = validate_applied_overlay(component, observed_inputs["applied"])
    serial = Path(observed_inputs["serial_log"]["path"]).read_text(errors="strict")
    records = [json.loads(line.split(PREFIX, 1)[1]) for line in serial.splitlines() if PREFIX in line]
    require(len(records) == 1, "exactly one complete component guest observation is required")
    observation = records[0]
    expected = {"arm": "hybrid", "core_sha256": program.sha256, "object_sha256": artifact["sha256"],
                "direct_calls": CALLS, "natural_calls": CALLS, "abi_calls": 32, "popcnt": 0,
                "failures": 0, "result_digest": expected_digest()}
    require(type(observation) is dict and observation.keys() == expected.keys()
            and all(type(observation[key]) is type(value) for key, value in expected.items())
            and observation == expected, "actual guest component/ABI/oracle/CPU-route observation failed")
    require(component["oracle_diff"]["status"] == "PASS" and component["native_gate"]["status"] == "PASS", "host gates must be complete")
    link = verify_linked_route(component, observed_inputs["vmlinux"]["path"], observed_inputs["build_object"]["path"])
    require(b"CONFIG_KERNEL_GZIP=y\n" in raw_config, "this readback profile requires the registered gzip kernel image")
    payload = verify_boot_payload(observed_inputs["kernel_image"]["path"], link["linked_functions"])
    return {"status": "PASS", **observed_inputs, "observation": observation, "linked_route": link,
            "boot_payload_match": payload, "native_object_reinspection": reinspection,
            "overlay_application": application,
            "executed_symbols": ["hia_sw_hweight32"], "execution_count": CALLS,
            "execution_count_kind": "completed_driver_direct_calls",
            "natural_driver_calls": CALLS, "abi_driver_calls": 32,
            "natural_whole_system_hotpath_counter_observed": False,
            "boot_report_bound_not_reinterpreted": True, "whole_kernel_rewrite": False}


def readback(component_path, output, **paths):
    started = time.perf_counter_ns()
    component = json.loads(Path(component_path).read_text())
    inputs_bound = {key: binding(path) for key, path in paths.items()}
    result = {**component, "prepared_receipt": binding(component_path)}
    try:
        result["guest_gate"] = validate_guest_readback(component, inputs_bound)
        result["stage"] = "named_hia_component_executed_in_mixed_linux_kernel"
    except BaseException as error:
        result["status"] = "FAIL"
        result["guest_gate"] = {"status": "FAIL", **inputs_bound, "error": {"type": type(error).__name__, "message": str(error)}}
    result["readback_wall_ns"] = time.perf_counter_ns() - started
    write(output, result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    p = commands.add_parser("prepare")
    for name in ("linux-source", "kernel-config", "output", "source-sha", "clang", "objdump"):
        p.add_argument("--" + name, required=True)
    p.add_argument("--development", action="store_true", help="explicit nonformal dirty-source development observation")
    p = commands.add_parser("apply")
    for name in ("component", "arm", "source-copy", "receipt"):
        p.add_argument("--" + name, required=True)
    p = commands.add_parser("readback")
    for name in ("component", "output", "serial-log", "kernel-image", "vmlinux", "build-object", "boot-report", "applied", "kernel-config"):
        p.add_argument("--" + name, required=True)
    args = parser.parse_args()
    if args.command == "prepare":
        result = prepare(args.linux_source, args.kernel_config, args.output, args.source_sha,
                         args.clang, args.objdump, development=args.development)
    elif args.command == "apply":
        result = apply_overlay(args.component, args.arm, args.source_copy, args.receipt)
    else:
        result = readback(args.component, args.output, **{key: getattr(args, key) for key in
                          ("serial_log", "kernel_image", "vmlinux", "build_object", "boot_report", "applied", "kernel_config")})
    print(json.dumps({key: result[key] for key in ("status", "stage", "error") if key in result}))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
