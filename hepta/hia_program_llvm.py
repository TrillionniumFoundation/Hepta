"""Direct LLVM for standalone verified HIA programs.

This backend consumes the immutable canonical program accepted by
``hia_program.verify_program``.  It has no source AST, source replay, Rust
borrow-checking gate, or C/Rust implementation fallback.  Its finite profile is
64-bit checked/wrapping integer block-argument SSA, internal calls, versioned
byte-owner operations and v7 recursive chains. Linux x86-64 admits shared
libraries/objects; AArch64 and RV64GC/LP64D admit objects only. Verification and
finite native comparisons are not a compiler-refinement or soundness proof.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import tempfile

from .artifact_publication import publish_verified, verify_published, withdraw_own_link
from .clang_capture import run_bounded
from .elf_shared_abi import inspect_owned_shared_elf
from .native_tool_identity import digest_executable
from .object_symbols import inspect_object_symbols
from .hia_schema import supports_feature


PROFILE = "hepta.hia.program.llvm-linux-x86_64.v1"
TARGET = "x86_64-unknown-linux-gnu"
TARGET_AARCH64 = "aarch64-unknown-linux-gnu"
TARGET_RISCV64 = "riscv64-unknown-linux-gnu"
# RV64GC, LP64D: only the integer scalar ABI and explicit allocator/runtime imports.
_RISCV64_PROFILES = {version: f"hepta.hia.program.llvm-linux-riscv64-lp64d-object.v{version}"
                     for version in range(1, 8)}
PROFILE_AARCH64 = "hepta.hia.program.llvm-linux-aarch64-object.v1"
PROFILE_V2 = "hepta.hia.program.llvm-linux-x86_64-bulk.v2"
PROFILE_AARCH64_V2 = "hepta.hia.program.llvm-linux-aarch64-bulk-object.v2"
PROFILE_V3 = "hepta.hia.program.llvm-linux-x86_64-overlap.v3"
PROFILE_AARCH64_V3 = "hepta.hia.program.llvm-linux-aarch64-overlap-object.v3"
PROFILE_V4 = "hepta.hia.program.llvm-linux-x86_64-byte-swap.v4"
PROFILE_AARCH64_V4 = "hepta.hia.program.llvm-linux-aarch64-byte-swap-object.v4"
PROFILE_V5 = "hepta.hia.program.llvm-linux-x86_64-offset-copy.v5"
PROFILE_AARCH64_V5 = "hepta.hia.program.llvm-linux-aarch64-offset-copy-object.v5"
PROFILE_V6 = "hepta.hia.program.llvm-linux-x86_64-range-fill.v6"
PROFILE_AARCH64_V6 = "hepta.hia.program.llvm-linux-aarch64-range-fill-object.v6"
PROFILE_V7 = "hepta.hia.program.llvm-linux-x86_64-recursive-chain.v7"
PROFILE_AARCH64_V7 = "hepta.hia.program.llvm-linux-aarch64-recursive-chain-object.v7"
MAX_LLVM_BYTES = 16 * 1024 * 1024
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
_WIDTHS = {**{f"{sign}{bits}": bits for sign in ("i", "u")
             for bits in (8, 16, 32, 64)}, "usize": 64, "isize": 64}
_BUFFERS = {"buffer", "readbuf", "mutbuf"}
_RUNTIME_NAMES = {"abort", "calloc", "free", "malloc", "memset", "memcpy", "memmove"}
_IMPORTS = {"abort", "calloc", "free", "malloc", "memset", "memcpy", "memmove"}

# This is a closed optimization whitelist, not a blacklist of known readers.
# New instructions must be audited before they can omit zero initialization.
_UNREAD_ALLOCATION_OPS = frozenset({
    "const", "int.cast", "int.neg.checked", "select",
    "bool.not", "bool.and", "bool.or", "bit.and", "bit.or", "bit.xor", "bit.not",
    "compare.eq", "compare.ne", "compare.lt", "compare.le", "compare.gt", "compare.ge",
    "int.add.checked", "int.sub.checked", "int.mul.checked", "int.div.checked",
    "int.rem.checked", "int.shl.checked", "int.shr.checked",
    "int.add.wrap", "int.sub.wrap", "int.mul.wrap",
    "buffer.new", "buffer.try_new", "buffer.len", "borrow.read", "borrow.mut",
    "loan.end", "owner.move", "owner.drop",
})


def _can_elide_zero_initialization(function):
    """Prove bytes of all local allocations unobservable in this function.

    Resource arguments/results, every call, every byte load/store, and unknown
    instructions reject this optimization. Scan every block, including loops
    and branches. Only zero writes disappear: allocation attempts, failure,
    live storage and explicit drops still execute. This does not admit a new
    uninitialized-buffer operation to Core or expose bytes to external code.
    """
    scalars = set(_WIDTHS) | {"bool", "unit"}
    return (all(param["type"] in scalars for param in function["params"])
            and all(typ in scalars for typ in function["returns"])
            and all(block["term"]["op"] in {"ret", "jump", "branch", "trap"}
                    and all(operation["op"] in _UNREAD_ALLOCATION_OPS for operation in block["ops"])
                    for block in function["blocks"]))


class HIAProgramLLVMRejected(ValueError):
    """The standalone program or requested native build is not admitted."""


def _reject(message, code="E_HIA_PROGRAM_LLVM"):
    raise HIAProgramLLVMRejected(code + ": " + message)


def _implementation_hash():
    """Bind the actual verifier/emitter and the native boundary helpers."""
    digest = sha256()
    root = Path(__file__).parent
    for name in ("hia_schema.py", "hia_program.py", "hia_program_composite.py", "hia_program_llvm.py", "artifact_publication.py",
                 "clang_capture.py", "elf_shared_abi.py", "object_symbols.py",
                 "object_structure.py", "native_tool_identity.py"):
        content = (root / name).read_bytes()
        digest.update(name.encode() + b"\0" + content + b"\0")
    return digest.hexdigest()


def _verified(program):
    from .hia_program import VerifiedProgram, verify_program
    if not isinstance(program, VerifiedProgram):
        _reject("an immutable VerifiedProgram from verify_program is required")
    # A public dataclass instance/digest is not itself authority. Re-run the
    # independent verifier over its exact bytes before emitting machine code.
    current = verify_program(program)
    if (current.canonical_bytes != program.canonical_bytes or current.sha256 != program.sha256
            or current.input_sha256 != program.input_sha256):
        _reject("verified program bytes changed")
    return current


def _llvm_type(typ):
    if typ in _WIDTHS:
        return "i" + str(_WIDTHS[typ])
    if typ == "bool":
        return "i1"
    if typ == "unit":
        return "i8"
    if typ in _BUFFERS:
        return "%hia.buffer"
    if typ == "chain":
        return "ptr"
    _reject("unsupported type " + repr(typ))


def _return_type(types):
    if not types:
        return "void"
    if len(types) == 1:
        return _llvm_type(types[0])
    return "{ " + ", ".join(_llvm_type(t) for t in types) + " }"


def _abi_attr(typ, target=TARGET):
    # AAPCS64 narrows integer arguments/results at the ABI boundary without
    # the SysV x86-64 signext/zeroext LLVM parameter attributes.
    if target == TARGET_AARCH64:
        return ""
    # RISC-V psABI widens to 32 bits by signedness, then sign-extends to XLEN.
    # In particular unsigned i32 also requires signext at both C ABI boundaries.
    if target == TARGET_RISCV64 and typ in {"i32", "u32"}:
        return "signext "
    if typ in {"i8", "i16"}:
        return "signext "
    if typ in {"u8", "u16", "bool"}:
        return "zeroext "
    return ""


def _signed(typ):
    return typ.startswith("i")


def _bounds(typ):
    bits = _WIDTHS[typ]
    return (-(1 << (bits - 1)), (1 << (bits - 1)) - 1) if _signed(typ) else (0, (1 << bits) - 1)


@dataclass(frozen=True)
class HIAProgramLLVM:
    text: str
    sha256: str
    core_sha256: str
    implementation_sha256: str
    exports: tuple[str, ...]
    profile: str = PROFILE
    target: str = TARGET
    input_sha256: str | None = None


class _FunctionEmitter:
    def __init__(self, parent, function, number):
        self.parent = parent
        self.function = function
        self.zero_bytes = "false" if _can_elide_zero_initialization(function) else "true"
        self.number = number
        self.serial = 0
        self.lines = []
        self.values = {}
        self.block_ids = {block["id"]: "b" + str(i)
                          for i, block in enumerate(function["blocks"])}
        self.param_ids = {}
        self.edges = []
        self.blocks = []
        for bindex, block in enumerate(function["blocks"]):
            for pindex, param in enumerate(block["params"]):
                self.param_ids[param["name"]] = ("%p_" + str(bindex) + "_" + str(pindex), param["type"])

    def tmp(self):
        self.serial += 1
        return "%t" + str(self.serial)

    def line(self, text):
        self.lines.append("  " + text)

    def instruction(self, text):
        dest = self.tmp()
        self.line(dest + " = " + text)
        return dest

    def argument(self, name):
        if name not in self.values:
            _reject("undefined local value in native lowering: " + name)
        return self.values[name]

    def scalar(self, name):
        value, typ = self.argument(name)
        return _llvm_type(typ) + " " + value

    def guard(self, ok):
        self.serial += 1
        suffix = str(self.serial)
        good, bad = "ok_" + suffix, "trap_" + suffix
        self.line("br i1 " + ok + ", label %" + good + ", label %" + bad)
        self.lines.append(bad + ":")
        self.line("call void @abort()")
        self.line("unreachable")
        self.lines.append(good + ":")

    def bulk_if_nonempty(self, count, emit):
        """Skip even pointer formation for a verified zero-byte memory operation.

        Guarded range checks must be emitted *before* entering this helper.
        No value defined inside the write block may escape the join.
        The verifier admits only bulk operations with no SSA outputs.
        """
        positive = self.instruction("icmp ne i64 " + count + ", 0")
        self.serial += 1
        suffix = str(self.serial)
        nonempty, after = "bulk_nonzero_" + suffix, "bulk_after_" + suffix
        self.line("br i1 " + positive + ", label %" + nonempty + ", label %" + after)
        self.lines.append(nonempty + ":")
        emit()
        self.line("br label %" + after)
        self.lines.append(after + ":")

    def cast(self, value, source, destination):
        old, new = _WIDTHS[source], _WIDTHS[destination]
        if old == new:
            return value
        op = "trunc" if old > new else ("sext" if _signed(source) else "zext")
        return self.instruction(op + " i" + str(old) + " " + value + " to i" + str(new))

    def buffer_parts(self, value):
        ptr = self.instruction("extractvalue %hia.buffer " + value + ", 0")
        size = self.instruction("extractvalue %hia.buffer " + value + ", 1")
        return ptr, size

    def checked_binary(self, op, left, right, typ):
        bits = _WIDTHS[typ]
        intrinsic = "llvm." + ("s" if _signed(typ) else "u") + op + ".with.overflow.i" + str(bits)
        self.parent.intrinsics.add((intrinsic, bits))
        pair = self.instruction("call { i" + str(bits) + ", i1 } @" + intrinsic
                                + "(i" + str(bits) + " " + left + ", i" + str(bits) + " " + right + ")")
        result = self.instruction("extractvalue { i" + str(bits) + ", i1 } " + pair + ", 0")
        overflow = self.instruction("extractvalue { i" + str(bits) + ", i1 } " + pair + ", 1")
        ok = self.instruction("xor i1 " + overflow + ", true")
        self.guard(ok)
        return result

    def operation(self, instruction):
        op, args, outputs, attrs = (instruction["op"], instruction["args"], instruction["out"], instruction["attrs"])
        arguments = [self.argument(name) for name in args]
        out_types = [out["type"] for out in outputs]
        results = []
        if op == "const":
            typ, value = out_types[0], attrs["value"]
            results = ["true" if value is True else "false" if value is False else "0" if typ == "unit" else str(value)]
        elif op.startswith("int.") and op.split(".")[1] in {"add", "sub", "mul"}:
            action, mode = op.split(".")[1:]
            left, typ = arguments[0]
            right = arguments[1][0]
            if mode == "checked":
                results = [self.checked_binary(action, left, right, typ)]
            elif mode == "wrap":
                results = [self.instruction(action + " " + _llvm_type(typ) + " " + left + ", " + right)]
            else:
                _reject("unknown arithmetic mode")
        elif op in {"int.div.checked", "int.rem.checked"}:
            left, typ = arguments[0]
            right = arguments[1][0]
            lt = _llvm_type(typ)
            self.guard(self.instruction("icmp ne " + lt + " " + right + ", 0"))
            if _signed(typ):
                minimum = str(_bounds(typ)[0])
                bad_left = self.instruction("icmp eq " + lt + " " + left + ", " + minimum)
                bad_right = self.instruction("icmp eq " + lt + " " + right + ", -1")
                bad = self.instruction("and i1 " + bad_left + ", " + bad_right)
                self.guard(self.instruction("xor i1 " + bad + ", true"))
            action = ("s" if _signed(typ) else "u") + ("div" if op == "int.div.checked" else "rem")
            results = [self.instruction(action + " " + lt + " " + left + ", " + right)]
        elif op in {"int.shl.checked", "int.shr.checked"}:
            left, typ = arguments[0]
            count, count_type = arguments[1]
            self.guard(self.instruction("icmp ult " + _llvm_type(count_type) + " " + count + ", " + str(_WIDTHS[typ])))
            amount = self.cast(count, count_type, typ)
            action = "shl" if op == "int.shl.checked" else "ashr" if _signed(typ) else "lshr"
            results = [self.instruction(action + " " + _llvm_type(typ) + " " + left + ", " + amount)]
        elif op == "int.neg.checked":
            value, typ = arguments[0]
            results = [self.checked_binary("sub", "0", value, typ)]
        elif op in {"bit.and", "bit.or", "bit.xor", "bit.not"}:
            value, typ = arguments[0]
            other = "-1" if op == "bit.not" else arguments[1][0]
            action = "xor" if op == "bit.not" else op.split(".")[1]
            results = [self.instruction(action + " " + _llvm_type(typ) + " " + value + ", " + other)]
        elif op.startswith("compare."):
            left, typ = arguments[0]
            predicate = op.split(".")[1]
            if predicate not in {"eq", "ne"}:
                predicate = ("s" if _signed(typ) else "u") + predicate
            results = [self.instruction("icmp " + predicate + " " + _llvm_type(typ) + " " + left + ", " + arguments[1][0])]
        elif op in {"bool.not", "bool.and", "bool.or"}:
            action = "xor" if op == "bool.not" else op.split(".")[1]
            other = "true" if op == "bool.not" else arguments[1][0]
            results = [self.instruction(action + " i1 " + arguments[0][0] + ", " + other)]
        elif op == "int.cast":
            value, source = arguments[0]
            destination = out_types[0]
            if attrs["mode"] == "checked":
                before_low, before_high = _bounds(source)
                after_low, after_high = _bounds(destination)
                prefix = "s" if _signed(source) else "u"
                if after_low > before_low:
                    self.guard(self.instruction("icmp " + prefix + "ge " + _llvm_type(source) + " " + value + ", " + str(after_low)))
                if after_high < before_high:
                    self.guard(self.instruction("icmp " + prefix + "le " + _llvm_type(source) + " " + value + ", " + str(after_high)))
            results = [self.cast(value, source, destination)]
        elif op == "select":
            results = [self.instruction("select i1 " + arguments[0][0] + ", " + self.scalar(args[1]) + ", " + self.scalar(args[2]))]
        elif op == "call":
            callee = self.parent.functions[attrs["function"]]
            returns = callee["returns"]
            call = "call " + _return_type(returns) + " @__hia_fn_" + str(self.parent.indices[callee["name"]])
            call += "(" + ", ".join(self.scalar(arg) for arg in args) + ")"
            if not returns:
                self.line(call)
            else:
                value = self.instruction(call)
                if len(returns) == 1:
                    results = [value]
                else:
                    results = [self.instruction("extractvalue " + _return_type(returns) + " " + value + ", " + str(index))
                               for index in range(len(returns))]
        elif op in {"buffer.new", "buffer.try_new"}:
            pair = self.instruction("call %hia.alloc @__hia_allocate(i64 " + arguments[0][0] + ", i1 " + self.zero_bytes + ")")
            owner = self.instruction("extractvalue %hia.alloc " + pair + ", 0")
            success = self.instruction("extractvalue %hia.alloc " + pair + ", 1")
            # Expose the allocation helper's exact length invariant to LLVM:
            # success implies requested length (including zero), failure an
            # empty owner.  Returning both fields through an aggregate PHI can
            # hide this correlation from downstream loop bounds analysis.
            # Reconstruct only the length, retaining the actual allocator's
            # pointer and success flag.  Every byte access below still emits
            # its ordinary runtime guard; no trust in source-loop patterns or
            # unverified assumptions is introduced by this normalization.
            if op == "buffer.new":
                self.guard(success)
                length = arguments[0][0]
            else:
                length = self.instruction("select i1 " + success + ", i64 " + arguments[0][0] + ", i64 0")
            owner = self.instruction("insertvalue %hia.buffer " + owner + ", i64 " + length + ", 1")
            if op == "buffer.new":
                results = [owner]
            else:
                results = [owner, success]
        elif op == "buffer.len":
            results = [self.instruction("extractvalue %hia.buffer " + arguments[0][0] + ", 1")]
        elif op == "chain.empty":
            results = ["null"]
        elif op == "chain.is_empty":
            results = [self.instruction("icmp eq ptr " + arguments[0][0] + ", null")]
        elif op in {"chain.try_push", "chain.pop"}:
            operand_text = "ptr " + arguments[0][0]
            if op == "chain.try_push":
                operand_text += ", %hia.buffer " + arguments[1][0]
            helper = "__hia_chain_push" if op == "chain.try_push" else "__hia_chain_pop"
            result = self.instruction("call %hia.chain.result @" + helper + "(" + operand_text + ")")
            results = [self.instruction("extractvalue %hia.chain.result " + result + ", " + str(i))
                       for i in range(3)]
        elif op in {"chain.head_read", "chain.head_mut"}:
            self.guard(self.instruction("icmp ne ptr " + arguments[0][0] + ", null"))
            results = [self.instruction("load %hia.buffer, ptr " + arguments[0][0] + ", align 8")]
        elif op in {"owner.move", "borrow.read", "borrow.mut"}:
            results = [arguments[0][0]]
        elif op == "loan.end":
            pass
        elif op == "owner.drop" and arguments[0][1] == "chain":
            self.line("call void @__hia_chain_drop(ptr " + arguments[0][0] + ")")
        elif op == "owner.drop":
            ptr = self.instruction("extractvalue %hia.buffer " + arguments[0][0] + ", 0")
            # HIA's zero-size and failed try_new owners contain a null pointer
            # and do not own a native allocation. The Python Core VM therefore
            # observes zero frees for these owners. Calling free(NULL) is legal
            # C but still observable by an allocator wrapper: avoid that call.
            # Non-null pointers must retain their real, nobuiltin free event.
            nonnull = self.instruction("icmp ne ptr " + ptr + ", null")
            self.serial += 1
            suffix = str(self.serial)
            release, after = "drop_nonnull_" + suffix, "drop_after_" + suffix
            self.line("br i1 " + nonnull + ", label %" + release + ", label %" + after)
            self.lines.append(release + ":")
            self.line("call void @free(ptr " + ptr + ") nobuiltin")
            self.line("br label %" + after)
            self.lines.append(after + ":")
        elif op in {"buffer.load", "buffer.store"}:
            pointer, length = self.buffer_parts(arguments[0][0])
            index = arguments[1][0]
            self.guard(self.instruction("icmp ult i64 " + index + ", " + length))
            address = self.instruction("getelementptr i8, ptr " + pointer + ", i64 " + index)
            if op == "buffer.load":
                results = [self.instruction("load i8, ptr " + address + ", align 1")]
            else:
                self.line("store i8 " + arguments[2][0] + ", ptr " + address + ", align 1")
        elif op == "buffer.fill":
            pointer, length = self.buffer_parts(arguments[0][0])
            # The allocator's valid empty owner may contain a null pointer.
            # Even for count=0, do not pass it to a memory intrinsic.
            def fill_nonempty():
                self.line("call void @llvm.memset.p0.i64(ptr align 1 " + pointer +
                          ", i8 " + arguments[1][0] + ", i64 " + length + ", i1 false)")
            self.bulk_if_nonempty(length, fill_nonempty)
        elif op == "buffer.copy":
            destination, dest_len = self.buffer_parts(arguments[0][0])
            source, source_len = self.buffer_parts(arguments[1][0])
            size = arguments[2][0]
            self.guard(self.instruction("icmp ule i64 " + size + ", " + dest_len))
            self.guard(self.instruction("icmp ule i64 " + size + ", " + source_len))
            # Independent owner roots permit memcpy. Zero count is a no-op,
            # including two distinct null zero-size owners.
            def copy_nonempty():
                self.line("call void @llvm.memcpy.p0.p0.i64(ptr align 1 " + destination +
                          ", ptr align 1 " + source + ", i64 " + size + ", i1 false)")
            self.bulk_if_nonempty(size, copy_nonempty)
        elif op == "buffer.move_within":
            # v3 overlap-safe memmove within one uniquely borrowed owner.
            # Validate each offset before subtracting from the extent, then
            # each remaining capacity before producing either byte address.
            pointer, extent = self.buffer_parts(arguments[0][0])
            destination, source, size = (arg[0] for arg in arguments[1:])
            self.guard(self.instruction("icmp ule i64 " + destination + ", " + extent))
            self.guard(self.instruction("icmp ule i64 " + source + ", " + extent))
            dst_available = self.instruction("sub i64 " + extent + ", " + destination)
            src_available = self.instruction("sub i64 " + extent + ", " + source)
            self.guard(self.instruction("icmp ule i64 " + size + ", " + dst_available))
            self.guard(self.instruction("icmp ule i64 " + size + ", " + src_available))
            # Offset==extent, count==0 is legal, even for a null empty owner.
            # Do not compute GEPs at all until a nonzero range is established.
            def move_nonempty():
                dst_pointer = self.instruction(
                    "getelementptr i8, ptr " + pointer + ", i64 " + destination)
                src_pointer = self.instruction(
                    "getelementptr i8, ptr " + pointer + ", i64 " + source)
                # One owner can overlap itself: always use memmove.
                self.line("call void @llvm.memmove.p0.p0.i64(ptr align 1 " + dst_pointer +
                          ", ptr align 1 " + src_pointer + ", i64 " + size + ", i1 false)")
            self.bulk_if_nonempty(size, move_nonempty)
        elif op == "buffer.fill_range":
            # v6 partial memset: both guards dominate the address and write.
            # A zero count needs no derived pointer (zero-size owners use null).
            pointer, extent = self.buffer_parts(arguments[0][0])
            offset, size, value = (arg[0] for arg in arguments[1:])
            self.guard(self.instruction("icmp ule i64 " + offset + ", " + extent))
            remaining = self.instruction("sub i64 " + extent + ", " + offset)
            self.guard(self.instruction("icmp ule i64 " + size + ", " + remaining))
            self.serial += 1
            suffix = str(self.serial)
            nonempty, after = "fill_nonempty_" + suffix, "fill_after_" + suffix
            positive = self.instruction("icmp ne i64 " + size + ", 0")
            self.line("br i1 " + positive + ", label %" + nonempty + ", label %" + after)
            self.lines.append(nonempty + ":")
            dest = self.instruction("getelementptr i8, ptr " + pointer + ", i64 " + offset)
            self.line("call void @llvm.memset.p0.i64(ptr align 1 " + dest +
                      ", i8 " + value + ", i64 " + size + ", i1 false)")
            self.line("br label %" + after)
            self.lines.append(after + ":")
        elif op == "buffer.copy_range":
            # Two independently owned allocations permit memcpy rather than memmove.
            destination, dst_size = self.buffer_parts(arguments[0][0])
            source, src_size = self.buffer_parts(arguments[1][0])
            dst_offset, src_offset, size = (arg[0] for arg in arguments[2:])
            # Four dominating guards: subtraction never underflows, writes are atomic on trap.
            self.guard(self.instruction("icmp ule i64 " + dst_offset + ", " + dst_size))
            self.guard(self.instruction("icmp ule i64 " + src_offset + ", " + src_size))
            dst_remaining = self.instruction("sub i64 " + dst_size + ", " + dst_offset)
            src_remaining = self.instruction("sub i64 " + src_size + ", " + src_offset)
            self.guard(self.instruction("icmp ule i64 " + size + ", " + dst_remaining))
            self.guard(self.instruction("icmp ule i64 " + size + ", " + src_remaining))
            # Skip both GEPs and memcpy for a zero-size range, even when
            # either owner has zero capacity and is represented by null.
            def copy_range_nonempty():
                dst_ptr = self.instruction(
                    "getelementptr i8, ptr " + destination + ", i64 " + dst_offset)
                src_ptr = self.instruction(
                    "getelementptr i8, ptr " + source + ", i64 " + src_offset)
                self.line("call void @llvm.memcpy.p0.p0.i64(ptr align 1 " + dst_ptr +
                          ", ptr align 1 " + src_ptr + ", i64 " + size + ", i1 false)")
            self.bulk_if_nonempty(size, copy_range_nonempty)
        elif op == "buffer.swap":
            # v4: finite same-owner byte exchange. Two independent guards must
            # dominate BOTH loads/stores. Same-index swap is well defined.
            pointer, extent = self.buffer_parts(arguments[0][0])
            left, right = arguments[1][0], arguments[2][0]
            self.guard(self.instruction("icmp ult i64 " + left + ", " + extent))
            self.guard(self.instruction("icmp ult i64 " + right + ", " + extent))
            left_ptr = self.instruction("getelementptr i8, ptr " + pointer + ", i64 " + left)
            right_ptr = self.instruction("getelementptr i8, ptr " + pointer + ", i64 " + right)
            left_byte = self.instruction("load i8, ptr " + left_ptr + ", align 1")
            right_byte = self.instruction("load i8, ptr " + right_ptr + ", align 1")
            self.line("store i8 " + right_byte + ", ptr " + left_ptr + ", align 1")
            self.line("store i8 " + left_byte + ", ptr " + right_ptr + ", align 1")
        else:
            _reject("unimplemented verified operation " + op)
        if len(results) != len(outputs):
            _reject("native output arity disagrees with verified operation " + op)
        for output, value in zip(outputs, results):
            self.values[output["name"]] = (value, output["type"])

    def edge(self, target, arguments):
        name = "edge_" + str(len(self.edges))
        values = [self.argument(arg) for arg in arguments]
        self.edges.append((name, target, values))
        return name

    def terminal(self, term):
        op = term["op"]
        if op == "jump":
            edge = self.edge(term["target"], term["args"])
            self.line("br label %" + edge)
        elif op == "branch":
            yes = self.edge(term["then"]["target"], term["then"]["args"])
            no = self.edge(term["else"]["target"], term["else"]["args"])
            condition = self.argument(term["cond"])[0]
            self.line("br i1 " + condition + ", label %" + yes + ", label %" + no)
        elif op == "trap":
            self.line("call void @abort()")
            self.line("unreachable")
        elif op == "ret":
            returns = self.function["returns"]
            values = term["values"]
            if not returns:
                self.line("ret void")
            elif len(returns) == 1:
                self.line("ret " + self.scalar(values[0]))
            else:
                combined = "zeroinitializer"
                typ = _return_type(returns)
                for index, value in enumerate(values):
                    combined = self.instruction("insertvalue " + typ + " " + combined + ", " + self.scalar(value) + ", " + str(index))
                self.line("ret " + typ + " " + combined)
        else:
            _reject("unknown terminator " + op)

    def render(self):
        fn = self.function
        entry = next(block for block in fn["blocks"] if block["id"] == fn["entry"])
        ordered = [entry] + [block for block in fn["blocks"] if block["id"] != fn["entry"]]
        for block in ordered:
            self.lines = []
            self.values = {param["name"]: self.param_ids[param["name"]] for param in block["params"]}
            for operation in block["ops"]:
                self.operation(operation)
            self.terminal(block["term"])
            self.blocks.append((block, list(self.lines)))
        params = ", ".join(_llvm_type(param["type"]) + " " + self.param_ids[param["name"]][0]
                           for param in entry["params"])
        result = ["define internal " + _return_type(fn["returns"]) + " @__hia_fn_" + str(self.number) + "(" + params + ") {"]
        for block, body in self.blocks:
            result.append(self.block_ids[block["id"]] + ":")
            if block["id"] != fn["entry"]:
                incoming = [(name, values) for name, target, values in self.edges if target == block["id"]]
                for index, param in enumerate(block["params"]):
                    parts = ["[ " + values[index][0] + ", %" + name + " ]" for name, values in incoming]
                    if not parts:
                        _reject("native lowering received unreachable parameterized block")
                    result.append("  " + self.param_ids[param["name"]][0] + " = phi " + _llvm_type(param["type"]) + " " + ", ".join(parts))
            result.extend(body)
        for name, target, _values in self.edges:
            result += [name + ":", "  br label %" + self.block_ids[target]]
        result.append("}")
        return "\n".join(result)


_BUFFER_RUNTIME = r"""
; A failed allocation is an empty, valid owner plus false. Zero length succeeds.
; The independent verifier still requires every resulting owner to be consumed.
define internal %hia.alloc @__hia_allocate(i64 %length, i1 %zero_bytes) {
entry:
  %zero = icmp eq i64 %length, 0
  br i1 %zero, label %empty, label %nonempty
empty:
  %empty_result = insertvalue %hia.alloc zeroinitializer, i1 true, 1
  ret %hia.alloc %empty_result
nonempty:
  %valid = icmp ule i64 %length, 9223372036854775807
  br i1 %valid, label %allocate, label %failed
allocate:
  br i1 %zero_bytes, label %zeroed, label %unread
zeroed:
  %zero_pointer = call ptr @calloc(i64 1, i64 %length) nobuiltin
  br label %allocated
unread:
  %unread_pointer = call ptr @malloc(i64 %length) nobuiltin
  br label %allocated
allocated:
  %pointer = phi ptr [ %zero_pointer, %zeroed ], [ %unread_pointer, %unread ]
  %success = icmp ne ptr %pointer, null
  br i1 %success, label %ready, label %failed
ready:
  %b0 = insertvalue %hia.buffer zeroinitializer, ptr %pointer, 0
  %b1 = insertvalue %hia.buffer %b0, i64 %length, 1
  %r0 = insertvalue %hia.alloc zeroinitializer, %hia.buffer %b1, 0
  %r1 = insertvalue %hia.alloc %r0, i1 true, 1
  ret %hia.alloc %r1
failed:
  ret %hia.alloc zeroinitializer
}
"""


_CHAIN_RUNTIME = r"""
; v7 inductive owner: Nil | Node(buffer payload, chain tail).
; No raw pointer constructor is admitted. push consumes both input owners.
; Its failure returns both unchanged, while success returns an empty fallback.
define internal %hia.chain.result @__hia_chain_push(ptr %tail, %hia.buffer %payload) {
entry:
  %node = call ptr @malloc(i64 24) nobuiltin
  %ok = icmp ne ptr %node, null
  br i1 %ok, label %ready, label %failed
ready:
  store %hia.buffer %payload, ptr %node, align 8
  %tail_slot = getelementptr %hia.chain.node, ptr %node, i32 0, i32 1
  store ptr %tail, ptr %tail_slot, align 8
  %r0 = insertvalue %hia.chain.result zeroinitializer, ptr %node, 0
  %r1 = insertvalue %hia.chain.result %r0, i1 true, 2
  ret %hia.chain.result %r1
failed:
  %f0 = insertvalue %hia.chain.result zeroinitializer, ptr %tail, 0
  %f1 = insertvalue %hia.chain.result %f0, %hia.buffer %payload, 1
  ret %hia.chain.result %f1
}

; Empty pop returns Nil, an empty payload owner, and false. Nonempty pop
; deallocates exactly the header and transfers payload/tail ownership out.
define internal %hia.chain.result @__hia_chain_pop(ptr %head) {
entry:
  %empty = icmp eq ptr %head, null
  br i1 %empty, label %none, label %some
none:
  ret %hia.chain.result zeroinitializer
some:
  %payload = load %hia.buffer, ptr %head, align 8
  %tail_slot = getelementptr %hia.chain.node, ptr %head, i32 0, i32 1
  %tail = load ptr, ptr %tail_slot, align 8
  call void @free(ptr %head) nobuiltin
  %r0 = insertvalue %hia.chain.result zeroinitializer, ptr %tail, 0
  %r1 = insertvalue %hia.chain.result %r0, %hia.buffer %payload, 1
  %r2 = insertvalue %hia.chain.result %r1, i1 true, 2
  ret %hia.chain.result %r2
}

; Explicit loop bounds native stack usage independently of recursive length.
; Every nonempty payload and node receives one real free; empty payloads do not.
define internal void @__hia_chain_drop(ptr %initial) {
entry:
  br label %loop
loop:
  %head = phi ptr [ %initial, %entry ], [ %tail, %release_node ]
  %empty = icmp eq ptr %head, null
  br i1 %empty, label %done, label %read_node
read_node:
  %payload = load %hia.buffer, ptr %head, align 8
  %payload_ptr = extractvalue %hia.buffer %payload, 0
  %tail_slot = getelementptr %hia.chain.node, ptr %head, i32 0, i32 1
  %tail = load ptr, ptr %tail_slot, align 8
  %has_payload = icmp ne ptr %payload_ptr, null
  br i1 %has_payload, label %release_payload, label %release_node
release_payload:
  call void @free(ptr %payload_ptr) nobuiltin
  br label %release_node
release_node:
  call void @free(ptr %head) nobuiltin
  br label %loop
done:
  ret void
}
"""


class _Emitter:
    def __init__(self, document, target, allowed_exports):
        self.document = document
        self.target = target
        self.functions = {fn["name"]: fn for fn in document["functions"]}
        self.bulk_operations = {operation["op"] for fn in document["functions"]
                                for block in fn["blocks"] for operation in block["ops"]
                                if operation["op"] in {"buffer.fill", "buffer.fill_range", "buffer.copy", "buffer.move_within", "buffer.copy_range"}}
        self.indices = {fn["name"]: index for index, fn in enumerate(document["functions"])}
        self.intrinsics = set()
        self.exports = []
        self.allowed_exports = allowed_exports

    def wrapper(self, fn, number):
        # External entrypoints never accept forged owner/loan descriptors.
        # An erased nominal aggregate or task is still not a scalar public
        # signature.  Its tags/padding/protocol helpers cannot be constructed
        # by callers through the scalar C ABI.
        if (fn["name"] not in self.allowed_exports
                or any(param["type"] not in set(_WIDTHS) | {"bool"} for param in fn["params"])
                or len(fn["returns"]) > 1 or
                any(typ not in set(_WIDTHS) | {"bool", "unit"} for typ in fn["returns"])):
            return ""
        name = fn["name"]
        if name in _RUNTIME_NAMES or name.startswith("__hia_"):
            _reject("function name conflicts with the closed runtime ABI")
        if re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", name) is None:
            _reject("function name cannot be represented by the native C ABI")
        self.exports.append(name)
        returns = fn["returns"]
        is_void = not returns or returns == ["unit"]
        native_return = "void" if is_void else _abi_attr(returns[0], self.target) + _llvm_type(returns[0])
        parameters = ", ".join(_llvm_type(p["type"]) + " " + _abi_attr(p["type"], self.target) + "%a" + str(i)
                               for i, p in enumerate(fn["params"]))
        args = ", ".join(_llvm_type(p["type"]) + " %a" + str(i) for i, p in enumerate(fn["params"]))
        call = "call " + _return_type(returns) + " @__hia_fn_" + str(number) + "(" + args + ")"
        lines = ["define " + native_return + " @" + name + "(" + parameters + ") {", "entry:"]
        lines += ["  " + (("%result = ") if returns else "") + call]
        lines += ["  ret void" if is_void else "  ret " + _llvm_type(returns[0]) + " %result", "}"]
        return "\n".join(lines)

    def render(self):
        bodies = [_FunctionEmitter(self, fn, index).render()
                  for index, fn in enumerate(self.document["functions"])]
        wrappers = [self.wrapper(fn, index) for index, fn in enumerate(self.document["functions"])]
        if not 1 <= len(self.exports) <= 128:
            _reject("native profile requires between 1 and 128 scalar entrypoints")
        # Call-site nobuiltin alone does not stop LLVM 20's declaration-level
        # InferFunctionAttrs from assigning libc alloc-family/memory effects.
        # Keep both boundaries explicit: our language exposes allocation
        # refusal and cleanup, including calls later observed by link wrappers.
        # The existing runtime contract already requires fresh, disjoint live
        # allocations. Express only that return-value fact. Keep calls opaque
        # and nullable: no alloc-family/memory/nonnull attributes may erase a
        # visible allocation attempt, refusal, allocator trace or free.
        declarations = ["declare void @abort() noreturn",
                        'declare noalias ptr @calloc(i64, i64) "no-builtins"',
                        'declare noalias ptr @malloc(i64) "no-builtins"',
                        'declare void @free(ptr) "no-builtins"']
        if "buffer.fill" in self.bulk_operations or "buffer.fill_range" in self.bulk_operations:
            declarations.append("declare void @llvm.memset.p0.i64(ptr, i8, i64, i1 immarg)")
        if "buffer.copy" in self.bulk_operations or "buffer.copy_range" in self.bulk_operations:
            declarations.append("declare void @llvm.memcpy.p0.p0.i64(ptr, ptr, i64, i1 immarg)")
        if "buffer.move_within" in self.bulk_operations:
            declarations.append("declare void @llvm.memmove.p0.p0.i64(ptr, ptr, i64, i1 immarg)")
        declarations += ["declare { i" + str(bits) + ", i1 } @" + name + "(i" + str(bits) + ", i" + str(bits) + ")"
                         for name, bits in sorted(self.intrinsics)]
        recursive = supports_feature(self.document["schema"], "recursive_chain")
        chain_types = ("%hia.chain.node = type { %hia.buffer, ptr }\n"
                       "%hia.chain.result = type { ptr, %hia.buffer, i1 }\n") if recursive else ""
        return ("; Standalone HIA: verified core -> LLVM. No source AST or Rust safety gate.\n"
                'target triple = "' + self.target + '"\n'
                "%hia.buffer = type { ptr, i64 }\n%hia.alloc = type { %hia.buffer, i1 }\n"
                + chain_types + "\n".join(declarations) + "\n" + _BUFFER_RUNTIME + "\n"
                + (_CHAIN_RUNTIME if recursive else "")
                + "\n\n".join(bodies + [wrapper for wrapper in wrappers if wrapper]) + "\n")


def emit_program_llvm(program, *, target=TARGET):
    """Emit LLVM from an independently verified immutable standalone program."""
    if target not in {TARGET, TARGET_AARCH64, TARGET_RISCV64}:
        _reject("unsupported 64-bit native target")
    before = _implementation_hash()
    verified = _verified(program)
    from .hia_program import SCHEMA, SCHEMA_V2, SCHEMA_V3, SCHEMA_V4, SCHEMA_V5, SCHEMA_V6, SCHEMA_V7
    document = verified.as_dict()
    emitter = _Emitter(document, target, verified.scalar_entrypoints)
    text = emitter.render()
    if not text.isascii() or len(text.encode()) > MAX_LLVM_BYTES:
        _reject("generated LLVM exceeds the closed textual profile")
    if _implementation_hash() != before:
        _reject("verifier/emitter implementation changed during generation", "E_HIA_PROGRAM_STALE")
    if target == TARGET_RISCV64:
        # The verifier has already selected a known primitive schema; never infer
        # a layout/ABI from an arbitrary version suffix before verification.
        versions = {SCHEMA: 1, SCHEMA_V2: 2, SCHEMA_V3: 3, SCHEMA_V4: 4,
                    SCHEMA_V5: 5, SCHEMA_V6: 6, SCHEMA_V7: 7}
        profile = _RISCV64_PROFILES[versions[document["schema"]]]
    elif document["schema"] == SCHEMA_V7:
        profile = PROFILE_V7 if target == TARGET else PROFILE_AARCH64_V7
    elif document["schema"] == SCHEMA_V6:
        profile = PROFILE_V6 if target == TARGET else PROFILE_AARCH64_V6
    elif document["schema"] == SCHEMA_V5:
        profile = PROFILE_V5 if target == TARGET else PROFILE_AARCH64_V5
    elif document["schema"] == SCHEMA_V4:
        profile = PROFILE_V4 if target == TARGET else PROFILE_AARCH64_V4
    elif document["schema"] == SCHEMA_V3:
        profile = PROFILE_V3 if target == TARGET else PROFILE_AARCH64_V3
    elif document["schema"] == SCHEMA_V2:
        profile = PROFILE_V2 if target == TARGET else PROFILE_AARCH64_V2
    else:
        profile = PROFILE if target == TARGET else PROFILE_AARCH64
    return HIAProgramLLVM(text, sha256(text.encode()).hexdigest(), verified.sha256,
                          before, tuple(sorted(emitter.exports)), profile, target, verified.input_sha256)


def _read_artifact(path):
    """Bound ordinary file bytes before allocating an in-memory copy."""
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= MAX_ARTIFACT_BYTES:
        _reject("native artifact must be a bounded ordinary nonempty file")
    key = lambda st: (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
    # The lstat/open gap can replace a regular artifact with a FIFO. A
    # blocking O_RDONLY would hang before fstat can reject the wrong inode.
    # O_NONBLOCK is inert for legitimate regular files, but fail-closes that
    # name race without changing digest, size or provenance validation.
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC |
                           getattr(os, "O_NOFOLLOW", 0)), "rb") as stream:
        if key(os.fstat(stream.fileno())) != key(before):
            _reject("artifact changed before reading")
        data = stream.read(before.st_size + 1)
        if len(data) != before.st_size or key(os.fstat(stream.fileno())) != key(before):
            _reject("artifact changed during reading")
    if key(path.lstat()) != key(before):
        _reject("artifact pathname changed during reading")
    return data


def compile_program_llvm(ir, *, program, output, clang="clang", kind="shared"):
    """Compile only regenerated verified Core LLVM, then inspect and publish it.

    The returned receipt is compilation evidence. Executing it, comparing it
    against the interpreter, and observing allocator/guard behavior are separate
    qualification steps; this entry does not claim to have done those steps.
    """
    if not isinstance(ir, HIAProgramLLVM) or ir != emit_program_llvm(program, target=ir.target):
        _reject("LLVM differs from independently reverified standalone program", "E_HIA_PROGRAM_ORIGIN")
    if kind not in {"shared", "object"}:
        _reject("only shared libraries and relocatable objects are supported")
    if ir.target in {TARGET_AARCH64, TARGET_RISCV64} and kind != "object":
        _reject("cross-target builds produce relocatable objects; execution requires a separate target runtime")
    if platform.system() != "Linux" or platform.machine() not in {"x86_64", "amd64"}:
        _reject("native profile requires a Linux x86-64 host")
    found = shutil.which(clang)
    if found is None:
        _reject("actual Clang 20+ is required")
    compiler = Path(found).resolve()
    compiler_digest = digest_executable(compiler)
    version = run_bounded([str(compiler), "--version"], timeout=10, stdout_limit=65536, stderr_limit=65536)
    target = run_bounded([str(compiler), "-dumpmachine"], timeout=10, stdout_limit=65536, stderr_limit=65536)
    if (version.returncode or target.returncode
            or re.search(r"clang version (?:2[0-9]|[3-9][0-9])\.", version.stdout) is None
            or target.stdout.strip() not in {TARGET, "x86_64-pc-linux-gnu"}):
        _reject("expected an actual Clang 20+ Linux x86-64 driver")
    destination = Path(os.path.abspath(output))
    if destination.exists() or destination.is_symlink() or not destination.parent.is_dir():
        _reject("a new output path in an existing directory is required")
    with tempfile.TemporaryDirectory(prefix=".hia-native-", dir=destination.parent) as directory:
        source = Path(directory) / "program.ll"
        artifact = Path(directory) / ("program.so" if kind == "shared" else "program.o")
        source.write_text(ir.text, encoding="ascii")
        flags = ["--target=" + ir.target, "-x", "ir", "-O3", "-fPIC", "-shared" if kind == "shared" else "-c"]
        if ir.target == TARGET_RISCV64:
            flags += ["-march=rv64gc", "-mabi=lp64d"]
        command = [str(compiler), *flags, str(source), "-o", str(artifact)]
        compiled = run_bounded(command, timeout=60, stdout_limit=65536, stderr_limit=1048576)
        if compiled.returncode:
            _reject("Clang rejected independently verified HIA LLVM: " + compiled.stderr[:3000], "E_HIA_PROGRAM_NATIVE")
        data = _read_artifact(artifact)
        if kind == "shared":
            inventory = inspect_owned_shared_elf(data, ir.exports)
        else:
            machine = {TARGET: 62, TARGET_AARCH64: 183, TARGET_RISCV64: 243}[ir.target]
            symbols = inspect_object_symbols(data, "ELF64", machine)
            if ir.target == TARGET_RISCV64 and int.from_bytes(data[48:52], "little") != 5:
                _reject("RISC-V object requires the reviewed RV64GC LP64D ELF flags")
            exports = symbols.get("defined")
            imports = symbols.get("undefined")
            if exports != frozenset(ir.exports) or imports is None or not imports <= _IMPORTS:
                _reject("object import/export inventory differs from the closed core ABI")
            inventory = {key: sorted(value) for key, value in symbols.items()}
        if digest_executable(compiler) != compiler_digest or _implementation_hash() != ir.implementation_sha256:
            _reject("native compiler or HIA implementation changed during compilation", "E_HIA_PROGRAM_STALE")
        published = publish_verified(artifact, destination, data)
        try:
            if digest_executable(compiler) != compiler_digest or _implementation_hash() != ir.implementation_sha256:
                _reject("native compiler or HIA implementation changed during publication", "E_HIA_PROGRAM_STALE")
            verify_published(artifact, destination, data)
        except Exception:
            withdraw_own_link(artifact, destination)
            raise
    return {"schema": "hepta.hia.program.native.v1", "ok": True,
            "status": "native_compiled_not_executed", "profile": ir.profile, "target": ir.target,
            "kind": kind, "output": str(destination), "core_sha256": ir.core_sha256,
            "input_sha256": ir.input_sha256,
            "llvm_ir_sha256": ir.sha256, "implementation_sha256": ir.implementation_sha256,
            "artifact_sha256": published["sha256"], "artifact_bytes": published["bytes"],
            "exports": list(ir.exports), "binary_inventory": inventory,
            "external_abi": "scalar-only C functions; resource and multiple-result functions are internal",
            "runtime_assumptions": ["Linux LP64 target with 64-bit pointers and size_t",
                                    "C calloc returns null or an initialized nonaliasing allocation of the requested size",
                                    "C malloc returns null or a fresh nonaliasing allocation of the requested size; bytes are initialized before read or remain unobserved",
                                    "C free accepts a live allocation from calloc or malloc, or null",
                                    "abort terminates execution; no cleanup after traps is promised",
                                    "native compiler, linker, loader, libc and host hardware are trusted"],
            "toolchain": {"path": str(compiler), "sha256": compiler_digest,
                          "version": version.stdout.splitlines()[0], "default_target": target.stdout.strip()},
            "flags": flags,
            "claims": {"standalone_core_reverified": True, "source_ast_required": False,
                       "rust_reference_required": False, "rust_codegen_used": False,
                       "c_codegen_used": False, "fallback_used": False,
                       "native_execution_qualified": False, "backend_refinement_proved": False,
                       "cross_target_execution_qualified": False,
                       "whole_language_soundness_proved": False,
                       "foreign_buffer_entrypoints_exposed": False}}


def build_program_native(document, output, *, clang="clang", kind="shared", target=TARGET):
    """Convenience path: verify standalone document, emit LLVM, compile it."""
    from .hia_program import verify_program
    program = verify_program(document)
    ir = emit_program_llvm(program, target=target)
    return compile_program_llvm(ir, program=program, output=output, clang=clang, kind=kind)
