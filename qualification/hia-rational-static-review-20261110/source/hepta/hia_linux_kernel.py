"""A separate, deliberately small Linux x86-64 HIA kernel-object profile.

Only total u32 straight-line leaves are admitted.  The existing standalone
Core verifier and LLVM emitter remain the semantic authority; this module adds
kernel target attributes, exact configuration binding and machine-code gates.
It is not a C kernel importer, memory model, device backend or OS qualification.
"""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import re
import shutil
import tempfile

from .artifact_publication import publish_verified, verify_published, withdraw_own_link
from .hia_program import verify_program
from .hia_program_llvm import emit_program_llvm, TARGET, _run_logged, _read_artifact
from .native_tool_identity import digest_executable
from .object_symbols import inspect_object_symbols

PROFILE = "hepta.hia.linux-x86_64-kernel-u32-leaf.v1"
_SAFE = {"const", "int.add.wrap", "int.sub.wrap", "int.mul.wrap",
         "bit.and", "bit.or", "bit.xor", "bit.not"}
_SHIFTS = {"int.shl.checked", "int.shr.checked"}
_CONFIG_KEYS = ("CONFIG_X86_64", "CONFIG_64BIT", "CONFIG_CC_IS_CLANG",
                "CONFIG_MITIGATION_RETHUNK", "CONFIG_X86_KERNEL_IBT",
                "CONFIG_MITIGATION_SLS", "CONFIG_CALL_PADDING", "CONFIG_CALL_THUNKS",
                "CONFIG_FUNCTION_ALIGNMENT", "CONFIG_FUNCTION_PADDING_BYTES",
                "CONFIG_CFI", "CONFIG_CFI_CLANG", "CONFIG_LTO_CLANG", "CONFIG_KMSAN",
                "CONFIG_FUNCTION_TRACER", "CONFIG_UNWINDER_ORC", "CONFIG_OBJTOOL")


class KernelProfileRejected(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise KernelProfileRejected("E_HIA_KERNEL: " + message)


def config_profile(raw: bytes) -> dict:
    require(type(raw) is bytes and 0 < len(raw) <= 4_000_000, "bounded real .config required")
    values = {}
    for line in raw.decode("utf-8").splitlines():
        match = re.fullmatch(r"(CONFIG_[A-Z0-9_]+)=(.*)", line)
        absent = re.fullmatch(r"# (CONFIG_[A-Z0-9_]+) is not set", line)
        if match or absent:
            key, value = (match.group(1), match.group(2)) if match else (absent.group(1), "n")
            require(key not in values, "duplicate Kconfig option " + key)
            values[key] = value
    require(all(values.get(key) == "y" for key in _CONFIG_KEYS[:3]),
            "this profile requires a real Clang x86-64/64-bit kernel configuration")
    require(all(values.get(key, "n") == "n" for key in
                ("CONFIG_CFI", "CONFIG_CFI_CLANG", "CONFIG_LTO_CLANG", "CONFIG_KMSAN")),
            "CFI, LTO and KMSAN shadow ABI need a separate profile; no options are removed")
    alignment = int(values.get("CONFIG_FUNCTION_ALIGNMENT", "16"))
    padding = int(values.get("CONFIG_FUNCTION_PADDING_BYTES", "0")) if values.get("CONFIG_CALL_PADDING") == "y" else 0
    require(alignment in (1, 2, 4, 8, 16, 32, 64) and padding in (0, 16, 32, 64),
            "unqualified function alignment/padding")
    return {"sha256": sha256(raw).hexdigest(), "bytes": len(raw),
            "options": {key: values.get(key, "n") for key in _CONFIG_KEYS},
            "rethunk": values.get("CONFIG_MITIGATION_RETHUNK") == "y",
            "ibt": values.get("CONFIG_X86_KERNEL_IBT") == "y",
            "sls": values.get("CONFIG_MITIGATION_SLS") == "y",
            "alignment": alignment, "padding": padding}


def qualify_leaf(document):
    """Prove absence of semantic traps in this finite, total scalar subset.

    Checked shifts are admitted only with a directly preceding known constant
    in [0, 31].  No optimizer observation is used to justify source admission.
    """
    verified = verify_program(document)
    core = verified.as_dict()
    functions = core["functions"]
    require(0 < len(functions) <= 16 and set(core.get("exports", [])) == {f["name"] for f in functions},
            "all 1..16 leaf definitions must have explicit scalar exports")
    for fn in functions:
        require(fn["returns"] == ["u32"] and 0 < len(fn["params"]) <= 6
                and all(p["type"] == "u32" for p in fn["params"]), "only u32 scalar ABI leaves")
        require(len(fn["blocks"]) == 1 and fn["blocks"][0]["id"] == fn["entry"]
                and set(fn["effects"]) <= {"trap"}, "no memory, allocation, call, loop or external effects")
        block = fn["blocks"][0]
        require(block["term"]["op"] == "ret" and len(block["ops"]) <= 128, "one bounded returning block required")
        constants = {}
        for op in block["ops"]:
            require(op["op"] in _SAFE | _SHIFTS and all(o["type"] == "u32" for o in op["out"]),
                    "operation outside total u32 leaf profile: " + op["op"])
            if op["op"] == "const":
                constants[op["out"][0]["name"]] = op["attrs"]["value"]
            if op["op"] in _SHIFTS:
                require(op["args"][1] in constants and 0 <= constants[op["args"][1]] < 32,
                        "shift count must be a known safe u32 constant")
    return verified


def kernel_ir(document, raw_config: bytes) -> dict:
    verified = qualify_leaf(document)
    cfg = config_profile(raw_config)
    original = emit_program_llvm(verified, target=TARGET)
    features = "-mmx,-sse,-sse2,-avx,-avx2,-avx512f,-x87,-popcnt"
    if cfg["sls"]:
        features += ",+harden-sls-ijmp,+harden-sls-ret"
    attrs = ' noredzone "target-cpu"="x86-64" "target-features"="' + features + '"'
    if cfg["rethunk"]:
        attrs += " fn_ret_thunk_extern"
    if cfg["padding"]:
        attrs += ' "patchable-function-entry"="0" "patchable-function-prefix"="' + str(cfg["padding"]) + '"'
    # Only target attributes change. The checked arithmetic/guards/calls are
    # still the exact regenerated standalone backend output, including dead
    # allocator helpers that must disappear before object admission.
    lines = []
    for line in original.text.splitlines():
        if line.startswith("define "):
            require(line.endswith(" {"), "unreviewed canonical LLVM definition shape")
            line = line[:-2] + attrs + " align " + str(cfg["alignment"]) + " {"
        lines.append(line)
    metadata = [(1, "Code Model", 2)]
    if cfg["rethunk"]:
        metadata.append((4, "function_return_thunk_extern", 1))
    if cfg["ibt"]:
        metadata.append((8, "cf-protection-branch", 1))
    require("!llvm.module.flags" not in original.text and not re.search(r"^!\d", original.text, re.M),
            "canonical scalar profile unexpectedly contains metadata")
    lines += ["!llvm.module.flags = !{" + ", ".join("!" + str(i) for i in range(len(metadata))) + "}"]
    lines += [f'!{i} = !{{i32 {mode}, !"{name}", i32 {value}}}' for i, (mode, name, value) in enumerate(metadata)]
    text = "\n".join(lines) + "\n"
    flags = ["--target=" + TARGET, "-x", "ir", "-O2", "-c", "-mcmodel=kernel",
             "-fno-pic", "-fno-pie", "-mno-red-zone", "-mgeneral-regs-only", "-mno-popcnt",
             "-fno-stack-protector", "-fno-asynchronous-unwind-tables", "-fno-unwind-tables"]
    if cfg["rethunk"]:
        flags += ["-mfunction-return=thunk-extern"]
    if cfg["ibt"]:
        flags += ["-fcf-protection=branch"]
    if cfg["sls"]:
        flags += ["-mharden-sls=all"]
    return {"profile": PROFILE, "text": text, "sha256": sha256(text.encode()).hexdigest(),
            "core_sha256": verified.sha256, "base_llvm_sha256": original.sha256,
            "base_implementation_sha256": original.implementation_sha256,
            "profile_implementation_sha256": sha256(Path(__file__).read_bytes()).hexdigest(),
            "config": cfg, "exports": list(original.exports), "flags": flags}


def _sections(data):
    at, count, strings = (int.from_bytes(data[a:b], "little") for a, b in ((40, 48), (60, 62), (62, 64)))
    headers = [data[at + i * 64:at + (i + 1) * 64] for i in range(count)]
    names_header = headers[strings]
    start, size = (int.from_bytes(names_header[a:b], "little") for a, b in ((24, 32), (32, 40)))
    names = data[start:start + size]
    result = {}
    for index, h in enumerate(headers):
        offset = int.from_bytes(h[:4], "little")
        name = names[offset:names.index(b"\0", offset)].decode("ascii")
        result[name] = {"index": index, "type": int.from_bytes(h[4:8], "little"),
                        "flags": int.from_bytes(h[8:16], "little"), "offset": int.from_bytes(h[24:32], "little"),
                        "size": int.from_bytes(h[32:40], "little"), "link": int.from_bytes(h[40:44], "little")}
    return result


def _function_ranges(data, sections, exports):
    """Read already structure-validated ELF function intervals, not labels."""
    tables = [s for s in sections.values() if s["type"] == 2]
    require(len(tables) == 1, "one exact ELF function table required")
    table = tables[0]
    names_section = next(s for s in sections.values() if s["index"] == table["link"])
    names = data[names_section["offset"]:names_section["offset"] + names_section["size"]]
    ranges = {}
    for at in range(table["offset"], table["offset"] + table["size"], 24):
        row = data[at:at + 24]
        if row[4] & 15 != 2 or int.from_bytes(row[6:8], "little") == 0:
            continue
        name_at = int.from_bytes(row[:4], "little")
        name = names[name_at:names.index(b"\0", name_at)].decode("ascii")
        require(name in exports and name not in ranges
                and int.from_bytes(row[6:8], "little") == sections[".text"]["index"],
                "unexpected or duplicated local/exported native function")
        start, size = int.from_bytes(row[8:16], "little"), int.from_bytes(row[16:24], "little")
        require(size > 0 and start + size <= sections[".text"]["size"], "function range outside native text")
        ranges[name] = {"offset": start, "bytes": size}
    require(set(ranges) == set(exports), "exact native function interval inventory required")
    ordered = sorted(ranges.values(), key=lambda row: row["offset"])
    require(all(a["offset"] + a["bytes"] <= b["offset"] for a, b in zip(ordered, ordered[1:])),
            "native exported functions overlap")
    return ranges


_GPR32 = {"%" + name for name in ("eax", "ecx", "edx", "esi", "edi", "r8d", "r9d", "r10d", "r11d")}
_GPR64 = {"%" + name for name in ("rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11")}


def _nop(instruction):
    return instruction["op"] in {"nop", "nopl", "nopw"} or (
        instruction["op"] in {"data16", "cs"} and re.search(r"\bnop[lw]?\b", instruction["operands"]))


def _scalar_operands(mnemonic, operands):
    """Accept explicit GPR/immediate operands; bare addresses are memory too.

    The closed no-stack profile cannot preserve callee-saved registers, so
    those registers are not admitted even for an otherwise valid MOV/LEA.
    LLVM is the decoder; this is only a narrow operand-class policy.
    """
    if mnemonic in {"leal", "lea"}:
        if "," not in operands:
            return False
        address, destination = operands.rsplit(",", 1)
        registers = re.findall(r"%[a-z0-9]+", address)
        return (destination.strip() in _GPR32 and registers
                and all(r in _GPR32 | _GPR64 for r in registers)
                and re.fullmatch(r"(?:-?(?:0x[0-9a-f]+|[0-9]+))?\((?:%[a-z0-9]+)?(?:,\s*%[a-z0-9]+(?:,\s*[1248])?)?\)", address))
    registers = _GPR64 if mnemonic == "movq" else _GPR32
    parts = [part.strip() for part in operands.split(",")]
    counts = {1} if mnemonic == "notl" else ({1, 2} if mnemonic in {"shrl", "shll"} else ({2, 3} if mnemonic == "imull" else {2}))
    return (len(parts) in counts and parts[-1] in registers
            and all(part in registers or re.fullmatch(r"\$-?(?:0x[0-9a-f]+|[0-9]+)", part) for part in parts[:-1]))


def inspect_kernel_object(data: bytes, disassembly: str, exports: list[str], cfg: dict) -> dict:
    """Parse bytes plus freshly obtained trusted-tool output, not a receipt.

    Mnemonic decoding is performed by the actual pinned LLVM disassembler.
    Callers evaluating stored evidence must use reinspect_kernel_object; a
    caller-supplied/editable disassembly string cannot qualify an object.
    """
    symbols = inspect_object_symbols(data, "ELF64", 62)
    allowed_imports = {"__x86_return_thunk"} if cfg["rethunk"] else set()
    require(symbols["defined"] == frozenset(exports) and symbols["undefined"] == frozenset(allowed_imports),
            "exact leaf exports and only configuration-required return-thunk imports are allowed")
    sections = _sections(data)
    executable = {name: s for name, s in sections.items() if s["flags"] & 4 and s["size"]}
    require(set(executable) == {".text"}, "one fully inspected executable text section required")
    for name, section in sections.items():
        if section["flags"] & 2 and section["size"] and name != ".text":
            require(name in {"__patchable_function_entries", ".note.gnu.property"},
                    "unexpected allocated data/runtime section: " + name)
    text = data[executable[".text"]["offset"]:executable[".text"]["offset"] + executable[".text"]["size"]]
    ranges = _function_ranges(data, sections, exports)
    instructions, relocations, cursor = [], [], 0
    for line in disassembly.splitlines():
        relocation = re.fullmatch(r"\s*([0-9a-f]+):\s+(R_X86_64_[A-Z0-9_]+)\s+(.+?)\s*", line)
        if relocation:
            relocations.append((int(relocation[1], 16), relocation[2], relocation[3]))
            continue
        instruction = re.fullmatch(r"\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)\s*([a-z][a-z0-9]*)\s*(.*?)\s*", line)
        if not instruction:
            require(not re.match(r"\s*[0-9a-f]+:", line), "unparsed disassembler instruction")
            continue
        address, code = int(instruction[1], 16), bytes.fromhex(instruction[2])
        mnemonic, operands = instruction[3], instruction[4].split("#", 1)[0].strip()
        require(address == cursor and code == text[address:address + len(code)], "complete exact text-byte disassembly required")
        cursor += len(code)
        item = {"offset": address, "bytes": code.hex(), "op": mnemonic, "operands": operands}
        if not _nop(item):
            require(mnemonic in {"movl", "movq", "shrl", "shll", "andl", "orl", "xorl", "notl",
                                 "subl", "addl", "imull", "leal", "lea", "retq", "ret", "jmp", "endbr64", "int3"},
                    "instruction outside inspected integer leaf profile: " + mnemonic)
            if mnemonic in {"retq", "ret", "endbr64", "int3"}:
                exact = {"retq": b"\xc3", "ret": b"\xc3", "endbr64": b"\xf3\x0f\x1e\xfa", "int3": b"\xcc"}
                require(not operands and code == exact[mnemonic], "unexpected return/entry/padding encoding")
                require(mnemonic not in {"retq", "ret"} or not cfg["rethunk"], "bare return in a RETHUNK kernel")
            elif mnemonic == "jmp":
                require(len(code) == 5 and code[0] == 0xe9, "only direct rel32 kernel return jumps are admitted")
            else:
                require(_scalar_operands(mnemonic, operands),
                        "only caller-saved scalar GPR/immediate ALU operands; memory and callee-saved clobbers are forbidden")
        instructions.append(item)
    require(cursor == len(text) and instructions, "every executable byte must be decoded")
    covered = set()
    for function in ranges.values():
        start, end = function["offset"], function["offset"] + function["bytes"]
        body = [i for i in instructions if start <= i["offset"] < end]
        require(body and body[0]["offset"] == start and body[-1]["offset"] + len(bytes.fromhex(body[-1]["bytes"])) == end,
                "function boundaries must coincide with decoded instructions")
        require((body[0]["op"] == "endbr64") == cfg["ibt"], "each function entry must match IBT configuration")
        terminals = [n for n, i in enumerate(body) if i["op"] in {"retq", "ret", "jmp"}]
        require(len(terminals) == 1, "every total leaf requires exactly one explicit terminal return")
        terminal = terminals[0]
        require(all(i["op"] != "int3" for i in body[:terminal])
                and all(_nop(i) or i["op"] == "int3" for i in body[terminal + 1:]),
                "INT3 is only unreachable padding after the leaf return")
        covered.update(i["offset"] for i in body)
    first_entry = min(f["offset"] for f in ranges.values())
    require(all(_nop(i) or (i["offset"] >= first_entry and i["op"] == "int3")
                for i in instructions if i["offset"] not in covered), "only unreachable inter-function padding outside leaf bodies")
    jumps = [i for i in instructions if i["op"] == "jmp"]
    expected_relocations = [(i["offset"] + 1, "R_X86_64_PLT32", "__x86_return_thunk-0x4") for i in jumps]
    require(relocations == expected_relocations and (len(jumps) == len(exports) if cfg["rethunk"] else not jumps),
            "only actual direct kernel return-thunk relocations are admitted")
    require(sum(i["op"] == "endbr64" for i in instructions) == (len(exports) if cfg["ibt"] else 0),
            "IBT entry instructions must match the bound configuration")
    return {"defined": sorted(symbols["defined"]), "undefined": sorted(symbols["undefined"]),
            "text_sha256": sha256(text).hexdigest(), "text_bytes": len(text),
            "instructions": instructions, "function_ranges": ranges, "return_thunk_relocations": len(relocations),
            "no_stack_redzone_simd_fpu_popcnt_or_hosted_imports": True,
            "kernel_objtool_gate": "NOT_RUN"}


def reinspect_kernel_object(artifact, *, command_log=None):
    """Re-execute the bound disassembler over actual bytes before admission.

    This deliberately does not use artifact['disassembly'] as authority.
    Replaying saved mnemonic/relocation labels could hide changed instructions
    (for example CLI/STI mislabeled as NOP) or changed ELF relocations.
    """
    require(artifact.get("profile") == PROFILE, "registered kernel object profile required")
    path = Path(artifact["path"])
    original = _read_artifact(path)
    require(len(original) == artifact["bytes"] and sha256(original).hexdigest() == artifact["sha256"], "object bytes differ before reinspection")
    descriptor = artifact["disassembler"]
    tool = Path(descriptor["path"])
    require(tool.is_absolute() and tool.name == "llvm-objdump" and
            artifact["tools"].get(str(tool)) == descriptor["sha256"] == digest_executable(tool),
            "actual selected LLVM disassembler identity differs")
    log = [] if command_log is None else command_log
    observed = _run_logged([str(tool), "--disassemble", "--reloc", "--x86-asm-syntax=att", str(path)],
                           command_log=log, cwd=str(path.parent.resolve()), timeout=30, stdout_limit=2_000_000)
    require(observed.returncode == 0, "actual LLVM object reinspection failed")
    inventory = inspect_kernel_object(original, observed.stdout, artifact["exports"], artifact["config"])
    require(_read_artifact(path) == original and digest_executable(tool) == descriptor["sha256"],
            "object or disassembler changed during readback")
    return {"status": "PASS", "object_sha256": artifact["sha256"], "disassembler": descriptor,
            "inspection": inventory, "commands": log}


def build_kernel_object(document, output, *, config: bytes, clang: str, objdump: str, command_log=None) -> dict:
    """Regenerate from Core, compile, inspect and publish a new object only."""
    ir = kernel_ir(document, config)
    compiler, inspector = (shutil.which(tool) for tool in (clang, objdump))
    require(compiler is not None and inspector is not None, "real Clang 20+ and llvm-objdump required")
    compiler, inspector = Path(compiler).resolve(), Path(inspector).resolve()
    identities = {str(p): digest_executable(p) for p in (compiler, inspector)}
    version = _run_logged([str(compiler), "--version"], command_log=command_log, timeout=10)
    require(version.returncode == 0 and re.search(r"clang version (?:2[0-9]|[3-9][0-9])\.", version.stdout),
            "real Clang 20+ is required")
    disassembler_version = _run_logged([str(inspector), "--version"], command_log=command_log, timeout=10, stdout_limit=65536)
    require(disassembler_version.returncode == 0 and re.search(r"LLVM version (?:2[0-9]|[3-9][0-9])\.", disassembler_version.stdout),
            "real LLVM 20+ disassembler is required")
    destination = Path(output).absolute()
    require(not destination.exists() and not destination.is_symlink() and destination.parent.is_dir(), "new object output required")
    with tempfile.TemporaryDirectory(prefix=".hia-kernel-", dir=destination.parent) as temporary:
        source, artifact = Path(temporary) / "kernel.ll", Path(temporary) / "kernel.o"
        source.write_text(ir["text"])
        built = _run_logged([str(compiler), *ir["flags"], str(source), "-o", str(artifact)], command_log=command_log, timeout=60)
        require(built.returncode == 0, "kernel LLVM compilation failed: " + built.stderr[-3000:])
        data = _read_artifact(artifact)
        disassembled = _run_logged([str(inspector), "--disassemble", "--reloc", "--x86-asm-syntax=att", str(artifact)],
                                   command_log=command_log, timeout=30, stdout_limit=2_000_000)
        require(disassembled.returncode == 0, "actual object disassembly failed")
        inventory = inspect_kernel_object(data, disassembled.stdout, ir["exports"], ir["config"])
        require(kernel_ir(document, config) == ir and all(digest_executable(Path(p)) == h for p, h in identities.items()),
                "Core, compiler or profile changed during compilation")
        published = publish_verified(artifact, destination, data)
        try:
            require(kernel_ir(document, config) == ir and all(digest_executable(Path(p)) == h for p, h in identities.items()),
                    "profile or tool changed during publication")
            verify_published(artifact, destination, data)
        except BaseException:
            withdraw_own_link(artifact, destination)
            raise
    return {"schema": "hepta.hia.kernel-object.v1", "status": "PASS", "profile": PROFILE,
            "path": str(destination), **published, "exports": ir["exports"], "config": ir["config"],
            "core_sha256": ir["core_sha256"], "llvm_sha256": ir["sha256"],
            "base_llvm_sha256": ir["base_llvm_sha256"], "implementation": {
                k: ir[k] for k in ("base_implementation_sha256", "profile_implementation_sha256")},
            "flags": ir["flags"], "tools": identities, "compiler_version": version.stdout,
            "disassembler": {"path": str(inspector), "sha256": identities[str(inspector)], "version": disassembler_version.stdout},
            "inspection": inventory, "disassembly": disassembled.stdout,
            "claims": {"actual_hia_core_to_native_object": True, "c_codegen_used": False,
                       "rust_codegen_used": False, "fallback_used": False, "native_execution_qualified": False,
                       "guest_execution_qualified": False, "whole_kernel_rewrite": False,
                       "backend_refinement_proved": False}}
