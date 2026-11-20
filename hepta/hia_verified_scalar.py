"""Opt-in register-only scalar kernels checked against their final ELF bytes.

The producer accepts one straight-line unsigned Core function. It allocates
only SysV caller-saved registers and exports that function directly. The
existing independent Safe Core consumer proves the linked bytes; it never
imports this producer. Unsupported programs raise a typed refusal so callers
can retain their ordinary checked lowering.
"""
from __future__ import annotations

from .hia_loaded_source import loaded_source_identity

from collections import Counter
from dataclasses import dataclass
from hashlib import sha256
import os
from pathlib import Path
import platform
import shutil
import tempfile

from .artifact_publication import publish_verified, verify_published, withdraw_own_link
from .clang_capture import run_bounded
from .hia_machine_elf import write_elf_object
from .hia_machine_x64 import Code, native_implementation_identity
from .hia_program import verify_program
from .hia_safe_core import (SafeCoreRejected, _checker_source_identity, _profile,
                           _unsigned_profile_version, validate_safe_core_artifact)
from .hia_safe_core_elf import _ELF
from .hia_verified_image import VerifiedImageRejected, read_bounded_elf_image
from .native_tool_identity import digest_executable


PROFILE = "hia.verified-scalar.register-leaf.x86_64.v2"
PROFILE_V3 = "hia.verified-scalar.register-leaf.x86_64.v3"
PROFILE_V4 = "hia.verified-scalar.register-leaf.x86_64.v4"
PROFILE_V5 = "hia.verified-scalar.register-leaf.x86_64.v5"
WIDTHS = {"bool": 1, "u8": 8, "u16": 16, "u32": 32, "u64": 64, "usize": 64}
ARGUMENTS = ("rdi", "rsi", "rdx", "rcx", "r8", "r9")
REGISTERS = ("rax", "rdi", "rsi", "rdx", "rcx", "r8", "r9", "r10", "r11")
BINARY = {"int.add.wrap": "add", "int.sub.wrap": "sub", "int.mul.wrap": "imul",
          "int.add.checked": "add", "int.sub.checked": "sub",
          "bit.and": "and_", "bit.or": "or_", "bit.xor": "xor",
          "bool.and": "and_", "bool.or": "or_"}
COMMUTATIVE = frozenset(BINARY) - {"int.sub.wrap", "int.sub.checked"}
CONDITIONS = {"eq": "e", "ne": "ne", "lt": "b", "le": "be", "gt": "a", "ge": "ae"}
SHIFTS = frozenset(("int.shl.checked", "int.shr.checked"))
DIVISIONS = frozenset(("int.div.checked", "int.rem.checked"))
IMPLICIT_ARITHMETIC = DIVISIONS | {"int.mul.checked"}
OPERATIONS = frozenset(BINARY) | SHIFTS | IMPLICIT_ARITHMETIC | {"int.neg.checked", "const", "int.cast", "bit.not", "bool.not", "select"} | {
    "compare." + relation for relation in CONDITIONS}
SOURCE_FILES = ("hia_verified_scalar.py", "hia_machine_x64.py", "hia_machine_elf.py", "hia_verified_image.py")


class VerifiedScalarRejected(ValueError):
    """The source lies outside the register-only producer's explicit profile."""


def _require(condition, message):
    if not condition:
        raise VerifiedScalarRejected("E_HIA_VERIFIED_SCALAR: " + message)


def _producer_identity():
    return {**loaded_source_identity(__name__, SOURCE_FILES),
            "selected_native_encoder": sha256(native_implementation_identity()).hexdigest()}


@dataclass(frozen=True)
class VerifiedScalarImage:
    object_bytes: bytes
    text_bytes: bytes
    export: str
    core_sha256: str
    profile: str
    hot_text_bytes: int
    source_identity: tuple
    core_profile_version: int = 2


def emit_verified_scalar(document):
    """Emit a direct SysV leaf without spills, entry wrappers or solver calls.

    Admission here is producer capability selection. Only subsequent
    ``validate_safe_core_artifact`` validates the actual linked machine code.
    """
    checked = verify_program(document)
    profile_version = _unsigned_profile_version(checked)
    try:
        fn, blocks = _profile(checked, profile_version=profile_version)
    except SafeCoreRejected as exc:
        raise VerifiedScalarRejected("E_HIA_VERIFIED_SCALAR: " + str(exc)) from exc
    _require(len(blocks) == 1, "only one straight-line block is supported")
    _require(all(p["type"] in WIDTHS for p in fn["params"]), "borrowed memory uses a separate kernel profile")
    _require(fn["name"] not in {"_init", "_fini", "__gmon_start__", "__cxa_finalize", "__dso_handle",
                                "_ITM_registerTMCloneTable", "_ITM_deregisterTMCloneTable", "abort"},
             "loader and imported symbol names cannot be exported")
    block = blocks[fn["entry"]]
    _require(block["term"]["op"] == "ret" and len(block["term"]["values"]) == 1,
             "a scalar return is required")
    _require(all(op["op"] in OPERATIONS for op in block["ops"]),
             "operation requires the ordinary checked lowering")
    identity = tuple(sorted(_producer_identity().items()))
    code = Code(alu_immediate="imm8_if_exact")
    uses = Counter(name for op in block["ops"] for name in op["args"])
    uses.update(block["term"]["values"])
    locations = {p["name"]: reg for p, reg in zip(block["params"], ARGUMENTS) if uses[p["name"]]}
    types = {p["name"]: p["type"] for p in block["params"]}

    def normalize(reg, typ):
        width = WIDTHS[typ]
        if width < 32:
            code.alu_imm("and", reg, (1 << width) - 1)
        elif width == 32:
            # The independent decoder deliberately admits only wide ordinary
            # moves. Two shifts implement zero extension without a scratch.
            code.shl(reg, 32)
            code.shr(reg, 32)

    for parameter in block["params"]:
        if parameter["name"] in locations:
            normalize(locations[parameter["name"]], parameter["type"])

    def check_fits(reg, typ, dead):
        """Check the untruncated value; scratch may reuse only dead inputs."""
        width = WIDTHS[typ]
        if width < 32:
            code.alu_imm("cmp", reg, (1 << width) - 1)
            code.jcc("a", "abort")
        elif width == 32:
            # CMP imm32 sign-extends, so 0xffffffff would compare against -1.
            # Inspect the high word in a liveness-approved scratch instead.
            available = [r for r in REGISTERS if r != reg and r not in locations.values()]
            dying = [locations[name] for name in sorted(dead) if locations[name] != reg]
            _require(bool(available or dying), "checked range needs a free caller-saved register budget")
            scratch = (available or dying)[0]
            code.mov_rr(scratch, reg)
            code.shr(scratch, 32)
            code.test(scratch, scratch)
            code.jcc("ne", "abort")

    for op in block["ops"]:
        names, operation = op["args"], op["op"]
        counts = Counter(names)
        dead = {name for name, count in counts.items() if uses[name] == count}
        if operation in IMPLICIT_ARITHMETIC:
            # Unsigned MUL/DIV have two implicit output registers. Save every
            # still-live SSA occupant before overwriting either; dying input
            # operands may stay because MUL reads them before its writes.
            for register in ("rax", "rdx"):
                occupied = [name for name, location in locations.items()
                            if location == register and name not in dead]
                if occupied:
                    free = [reg for reg in REGISTERS
                            if reg not in ("rax", "rdx") and reg not in locations.values()]
                    _require(bool(free), ("DIV" if operation in DIVISIONS else "MUL") +
                             " needs a free caller-saved register budget")
                    code.mov_rr(free[0], register)
                    for name in occupied:
                        locations[name] = free[0]
            if operation in DIVISIONS and locations[names[1]] in ("rax", "rdx"):
                # Unlike MUL, division is not commutative, and clearing the
                # dividend high word must never erase a dying divisor. Move
                # an implicit-register divisor even when it has no later use.
                free = [reg for reg in REGISTERS
                        if reg not in ("rax", "rdx") and reg not in locations.values()]
                _require(bool(free), "DIV divisor needs a free caller-saved register budget")
                code.mov_rr(free[0], locations[names[1]])
                locations[names[1]] = free[0]
        if operation in SHIFTS and locations[names[1]] != "rcx":
            # CL is an implicit x86 operand. Preserve any still-live RCX
            # value before installing the count, including a dying left
            # operand needed by this very shift. A lack of scratch is a
            # pre-proof selection refusal, never permission to clobber it.
            occupied = [name for name, register in locations.items() if register == "rcx"]
            if occupied:
                free = [reg for reg in REGISTERS if reg not in locations.values()]
                _require(bool(free), "CL shift needs a free caller-saved register budget")
                code.mov_rr(free[0], "rcx")
                for name in occupied:
                    locations[name] = free[0]
            code.mov_rr("rcx", locations[names[1]])
            locations[names[1]] = "rcx"
        args = [locations[name] for name in names]
        output = op["out"][0]
        # A binary instruction may overwrite its dying left operand. Only
        # commutative operations may instead overwrite the right operand.
        reusable = []
        if operation in BINARY:
            reusable = names[:1]
            if operation in COMMUTATIVE:
                reusable += names[1:2]
        elif operation in SHIFTS or operation in {"int.neg.checked", "int.cast", "bit.not", "bool.not"}:
            reusable = names[:1]
        elif operation.startswith("compare."):
            reusable = names
        elif operation == "select":
            reusable = names[2:3]
        candidates = [locations[name] for name in reusable if name in dead]
        available = [reg for reg in REGISTERS if reg not in locations.values()]
        if operation in SHIFTS:
            # Keep the count's logical location valid across the instruction,
            # even when both Core operands are the same SSA value.
            candidates = [reg for reg in candidates if reg != "rcx"]
            available = [reg for reg in available if reg != "rcx"]
        if operation in IMPLICIT_ARITHMETIC:
            destination = "rax"
        else:
            _require(bool(candidates or available), "live values exceed the caller-saved register budget")
            destination = (candidates or available)[0]

        if operation == "const":
            code.mov_imm(destination, int(op["attrs"]["value"]))
        elif operation in DIVISIONS:
            left, right = args
            code.test(right, right)
            code.jcc("e", "abort")
            if left != "rax":
                code.mov_rr("rax", left)
            code.xor("rdx", "rdx")
            code.div(right)
            if operation == "int.rem.checked":
                code.mov_rr("rax", "rdx")
        elif operation == "int.mul.checked":
            left, right = args
            # Commutativity lets an existing RAX operand become the implicit
            # left operand without overwriting the explicit right operand.
            if right == "rax":
                left, right = right, left
            if left != "rax":
                code.mov_rr("rax", left)
            code.mul(right)
            code.jcc("b", "abort")
            check_fits("rax", output["type"], dead)
        elif operation in SHIFTS:
            if destination != args[0]:
                code.mov_rr(destination, args[0])
            # Core checks the complete normalized count, before x86 masks
            # CL to six bits. A left shift may discard high result bits;
            # count overflow alone is the checked shift's trap condition.
            code.alu_imm("cmp", "rcx", WIDTHS[output["type"]])
            code.jcc("ae", "abort")
            code.shift_cl("shl" if operation == "int.shl.checked" else "shr", destination)
        elif operation == "int.neg.checked":
            if destination != args[0]:
                code.mov_rr(destination, args[0])
            # In the unsigned domain, zero is the only representable
            # arithmetic negation. Its successful value is already zero.
            code.test(destination, destination)
            code.jcc("ne", "abort")
        elif operation in BINARY:
            left, right = args
            if destination == right and operation in COMMUTATIVE:
                left, right = right, left
            if destination != left:
                code.mov_rr(destination, left)
            getattr(code, BINARY[operation])(destination, right)
            if operation == "int.sub.checked" or (operation == "int.add.checked" and
                                                  WIDTHS[output["type"]] == 64):
                code.jcc("b", "abort")
            elif operation == "int.add.checked":
                check_fits(destination, output["type"], dead)
        elif operation in {"int.cast", "bit.not", "bool.not"}:
            if destination != args[0]:
                code.mov_rr(destination, args[0])
            if operation == "bit.not":
                code.bitnot(destination)
            elif operation == "bool.not":
                code.alu_imm("xor", destination, 1)
            elif op["attrs"]["mode"] == "checked" and WIDTHS[types[names[0]]] > WIDTHS[output["type"]]:
                check_fits(destination, output["type"], dead)
        elif operation.startswith("compare."):
            code.cmp(*args)
            code.setcc(CONDITIONS[operation.split(".")[1]], destination)
        elif operation == "select":
            condition, yes, no = args
            code.test(condition, condition)
            if destination != no:
                code.mov_rr(destination, no)
            code.cmov("ne", destination, yes)
        normalize(destination, output["type"])
        for name, count in counts.items():
            uses[name] -= count
            if uses[name] == 0:
                del locations[name]
        if uses[output["name"]]:
            locations[output["name"]] = destination
        types[output["name"]] = output["type"]

    returned = locations[block["term"]["values"][0]]
    if returned != "rax":
        code.mov_rr("rax", returned)
    code.ret()
    hot_text_bytes = code.offset
    # Preserve the closed libc/loader contract checked by the ELF consumer.
    # Checked arithmetic may reach this stub. PUSH aligns the SysV entry
    # stack before the nonreturning CALL, whose stack write is also modeled.
    code.label("abort")
    code.push("rbp")
    code.call("abort")
    code.ud2()
    text, relocations = code.finalize()
    obj = write_elf_object(text, [{"name": fn["name"], "offset": 0,
                                  "size": len(text), "global": True}], relocations)
    _require(identity == tuple(sorted(_producer_identity().items())), "producer changed during emission")
    profile = {2: PROFILE, 3: PROFILE_V3, 4: PROFILE_V4, 5: PROFILE_V5}[profile_version]
    return VerifiedScalarImage(obj, text, fn["name"], checked.sha256, profile,
                               hot_text_bytes, identity, profile_version)


def build_verified_scalar(document, output, *, linker="ld", timeout_ms=15000, query_directory=None, image=None):
    """Link privately, check all inputs on the final ELF, and publish on success."""
    from .hia_elf_verified_linker_native import selected_verified_linker, verified_linker_matches

    checked = verify_program(document)
    profile_version = _unsigned_profile_version(checked)
    profile = {2: PROFILE, 3: PROFILE_V3, 4: PROFILE_V4, 5: PROFILE_V5}[profile_version]
    if image is None:
        image = emit_verified_scalar(checked)
    else:
        _require(type(image) is VerifiedScalarImage and type(image.object_bytes) is bytes and
                 type(image.text_bytes) is bytes and image.core_sha256 == checked.sha256 and
                 image.profile == profile and type(image.core_profile_version) is int and
                 image.core_profile_version == profile_version and
                 image.source_identity == tuple(sorted(_producer_identity().items())),
                 "selected image does not match the current immutable source and producer")
        _require(image.export == checked.as_dict()["functions"][0]["name"] and
                 _ELF(image.object_bytes, 1).section(".text", 1)["data"] == image.text_bytes,
                 "selected image text or export differs from the supplied Core/object")
    _require(platform.system() == "Linux" and platform.machine().lower() in {"x86_64", "amd64"},
             "shared linkage requires a Linux x86-64 host")
    destination = Path(os.path.abspath(output))
    _require(not destination.exists() and not destination.is_symlink() and destination.parent.is_dir(),
             "output must be a new path in an existing directory")
    selected = selected_verified_linker()
    if selected is None:
        found = shutil.which(linker)
        _require(found is not None, "GNU ld is required")
        tool = Path(found).resolve()
        tool_digest = digest_executable(tool)
        version = run_bounded([str(tool), "--version"], timeout=10, stdout_limit=65536, stderr_limit=65536)
        _require(version.returncode == 0 and version.stdout.startswith("GNU ld "), "GNU ld is required")
        flags = ["-m", "elf_x86_64", "-shared", "-z", "defs", "-z", "noexecstack",
                 "-z", "relro", "-z", "now", "--hash-style=both", "--build-id=none"]
        toolchain = {"path": str(tool), "sha256": tool_digest, "version": version.stdout.splitlines()[0], "flags": flags}
    else:
        linkage = selected.identity()
        toolchain = selected.toolchain(linkage)
    with tempfile.TemporaryDirectory(prefix=".hia-verified-scalar-", dir=destination.parent) as temporary:
        obj, candidate = Path(temporary) / "kernel.o", Path(temporary) / "kernel.so"
        if selected is None:
            obj.write_bytes(image.object_bytes)
            result = run_bounded([str(tool), *flags, str(obj), "-lc", "-o", str(candidate)],
                                 timeout=30, stdout_limit=65536, stderr_limit=1048576)
            _require(result.returncode == 0, "linker rejected kernel: " + result.stderr[:3000])
        else:
            try:
                selected.link(image.object_bytes, candidate)
            except ValueError as error:
                raise VerifiedScalarRejected("E_HIA_VERIFIED_SCALAR: " + str(error)) from error
        try:
            data = read_bounded_elf_image(candidate)
        except VerifiedImageRejected as exc:
            raise VerifiedScalarRejected("E_HIA_VERIFIED_SCALAR: " + str(exc)) from exc
        validation = validate_safe_core_artifact(checked, image.object_bytes, data,
            timeout_ms=timeout_ms, query_directory=query_directory, profile_version=profile_version)
        _require(validation.get("ok") is True and validation.get("complete") is True,
                 "final-image validation did not complete")

        def recheck():
            linker_matches = (tool_digest == digest_executable(tool) if selected is None
                              else verified_linker_matches(linkage))
            _require(image.source_identity == tuple(sorted(_producer_identity().items())) and
                     linker_matches, "producer or linker changed during build")
            _require(validation["checker"]["source_identity"] == _checker_source_identity(),
                     "checker changed before final publication")

        recheck()
        published = publish_verified(candidate, destination, data)
        try:
            recheck()
            verify_published(candidate, destination, data)
        except BaseException:
            withdraw_own_link(candidate, destination)
            raise
    return {"schema": "hepta.hia.verified-scalar-build.v1", "profile": profile, "ok": True,
            "core_profile_version": profile_version,
            "status": "smt_validated_not_executed", "output": str(destination),
            "artifact_sha256": published["sha256"], "artifact_bytes": published["bytes"],
            "object_sha256": sha256(image.object_bytes).hexdigest(), "core_sha256": checked.sha256,
            "machine_text_sha256": sha256(image.text_bytes).hexdigest(), "hot_text_bytes": image.hot_text_bytes,
            "source_identity": dict(image.source_identity), "export": image.export,
            "toolchain": toolchain,
            "validation": validation, "claims": dict(validation["claims"]),
            "register_abi": "SysV AMD64 direct entry; caller-saved registers only on return paths",
            "wrapper_calls": 0, "hot_stack_bytes": 0,
            "maximum_observed_stack_bytes": validation["model_counts"]["maximum_observed_stack_bytes"]}

# Bind this executing module, including its top-level constants, to retained source.
from .hia_loaded_source import register_loaded_module as _register_loaded_source
_register_loaded_source(__name__)
