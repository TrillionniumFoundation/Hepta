"""Verified standalone HIA Core -> x86-64 instructions -> ELF, without LLVM.

The emitter owns instruction selection, stack locations, control-flow fixups,
the internal calling convention, C entry wrappers and relocatable ELF output.
Only shared-library linkage invokes an external tool, on an already generated
object. Core v1-v8 operations keep the existing verifier and abort semantics.
This finite backend is not self-hosted and makes no refinement/performance claim.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import ctypes
import os
from pathlib import Path
import platform
import shutil
import stat
import sys
import tempfile

from .artifact_publication import publish_verified, verify_published, withdraw_own_link
from .clang_capture import run_bounded
from .elf_shared_abi import inspect_owned_shared_elf
from .native_tool_identity import digest_executable
from .object_symbols import inspect_object_symbols
from .hia_machine_x64 import Code
from .hia_machine_elf import write_elf_object


TARGET = "x86_64-unknown-linux-gnu"
PROFILE = "hepta.hia.program.direct-linux-x86_64.v1"
MAX_TEXT_BYTES = 16 * 1024 * 1024
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
MAX_FRAME_BYTES = 64 * 1024
IMPORTS = frozenset({"abort", "calloc", "malloc", "free", "memset", "memcpy", "memmove"})
# Linkers/CRT can invoke these names during loading or unloading, without an
# explicit HIA call. In particular GNU ld promotes a public _init to DT_INIT.
# They may remain private Core function names, never external entrypoints.
_LOADER_HOOKS = frozenset({"_init", "_fini", "__gmon_start__", "__cxa_finalize", "__dso_handle",
                          "_ITM_registerTMCloneTable", "_ITM_deregisterTMCloneTable"})
CORE_SCHEMAS = frozenset(f"hepta.hia.program.v{v}" for v in range(1, 9))
WIDTHS = {**{f"{s}{n}": n for s in ("i", "u") for n in (8, 16, 32, 64)},
          "isize": 64, "usize": 64}
BYTE_RESOURCES = frozenset({"buffer", "readbuf", "mutbuf"})
_TYPES = frozenset(WIDTHS) | BYTE_RESOURCES | {"bool", "unit", "chain"}
SUPPORTED_OPCODES = frozenset({
    "const", "int.cast", "int.neg.checked", "select", "bool.not", "bool.and", "bool.or",
    "bit.and", "bit.or", "bit.xor", "bit.not",
    "compare.eq", "compare.ne", "compare.lt", "compare.le", "compare.gt", "compare.ge",
    "int.add.checked", "int.sub.checked", "int.mul.checked",
    "int.add.wrap", "int.sub.wrap", "int.mul.wrap",
    "int.div.checked", "int.rem.checked", "int.shl.checked", "int.shr.checked",
    "buffer.new", "buffer.try_new", "buffer.len", "borrow.read", "borrow.mut",
    "loan.end", "owner.move", "owner.drop", "buffer.load", "buffer.store",
    "buffer.fill", "buffer.copy", "buffer.move_within", "buffer.swap",
    "buffer.copy_range", "buffer.fill_range", "call",
    "chain.empty", "chain.try_push", "chain.pop", "chain.is_empty", "chain.head_read", "chain.head_mut",
})
_ARG_REGS = ("rdi", "rsi", "rdx", "rcx", "r8", "r9")


class HIAProgramNativeRejected(ValueError):
    """The exact program, target, object or publication is not admitted."""


def _reject(message, code="E_HIA_PROGRAM_NATIVE"):
    raise HIAProgramNativeRejected(code + ": " + message)


def _implementation_hash():
    digest = sha256()
    root = Path(__file__).parent
    for name in (
        "hia_schema.py", "hia_program.py", "hia_capability_flow.py", "hia_opcodes.py",
        "hia_json_preflight.py", "hia_program_composite.py", "hia_program_native.py",
        "hia_machine_x64.py", "hia_machine_elf.py", "hia_static_budget.py",
        "hia_heap_bound.py", "artifact_publication.py",
        "clang_capture.py", "elf_shared_abi.py", "object_symbols.py",
        "object_structure.py", "native_tool_identity.py",
    ):
        digest.update(name.encode() + b"\0" + (root / name).read_bytes() + b"\0")
    return digest.hexdigest()


def _words(typ):
    return 2 if typ in BYTE_RESOURCES else 1


def _bounds(typ):
    bits = WIDTHS[typ]
    return (-(1 << (bits - 1)), (1 << (bits - 1)) - 1) if typ.startswith("i") else (0, (1 << bits) - 1)


def _normalize(code, reg, typ):
    """Canonical full-register representation, including dirty incoming highs."""
    if typ == "unit":
        code.mov_imm(reg, 0)
    elif typ == "bool":
        code.alu_imm("and", reg, 1)
    elif typ in WIDTHS and WIDTHS[typ] < 64:
        count = 64 - WIDTHS[typ]
        code.shift_imm("shl", reg, count)
        code.shift_imm("sar" if typ.startswith("i") else "shr", reg, count)


def _prologue(code, frame):
    code.push("rbp")
    code.mov_rr("rbp", "rsp")
    # Touch each 4-KiB interval so a large frame cannot jump a stack guard.
    remaining = frame
    while remaining:
        amount = min(4096, remaining)
        code.alu_imm("sub", "rsp", amount)
        code.load("r11", "rsp", 0)
        remaining -= amount


@dataclass(frozen=True)
class HIAProgramMachine:
    object_bytes: bytes
    text_bytes: bytes
    sha256: str
    core_sha256: str
    implementation_sha256: str
    exports: tuple[str, ...]
    profile: str
    target: str
    input_sha256: str
    function_frames: tuple[tuple[str, int], ...]


class _Function:
    def __init__(self, parent, fn, index):
        self.parent, self.fn, self.index = parent, fn, index
        self.c = parent.c
        self.cursor = 8  # saved output-array pointer at rbp-8
        self.slots, self.types = {}, {}
        self.blocks = {b["id"]: b for b in fn["blocks"]}
        for block in fn["blocks"]:
            definitions = block["params"] + [out for op in block["ops"] for out in op["out"]]
            for value in definitions:
                name, typ = value["name"], value["type"]
                self.slots[name] = self.allocate(_words(typ))
                self.types[name] = typ
        self.edge_words = max((sum(_words(p["type"]) for p in b["params"]) for b in fn["blocks"]), default=0)
        calls = [op for b in fn["blocks"] for op in b["ops"] if op["op"] == "call"]
        self.call_words = max((sum(_words(self.types[a]) for a in op["args"]) for op in calls), default=0)
        self.result_words = max((sum(_words(v["type"]) for v in op["out"]) for op in calls), default=0)
        self.edge_slot = self.allocate(max(1, self.edge_words))
        self.call_slot = self.allocate(max(1, self.call_words))
        self.result_slot = self.allocate(max(1, self.result_words))
        self.temporary = self.allocate(4)
        self.frame = (self.cursor + 15) & -16
        if self.frame > MAX_FRAME_BYTES:
            _reject("function stack frame exceeds 64 KiB: " + fn["name"], "E_HIA_PROGRAM_LIMIT")
        self.trap = self.label("trap")

    def allocate(self, words):
        self.cursor += 8 * words
        return -self.cursor

    def label(self, suffix):
        return self.parent.label("fn" + str(self.index) + "_" + suffix)

    def block_label(self, name):
        return "fn" + str(self.index) + "_block_" + name

    def load(self, name, reg="rax", word=0):
        self.c.load(reg, "rbp", self.slots[name] + word * 8)

    def store(self, name, reg="rax", word=0):
        self.c.store("rbp", self.slots[name] + word * 8, reg)

    def immediate(self, name, value, word=0):
        self.c.mov_imm("rax", int(value) & ((1 << 64) - 1))
        self.store(name, word=word)

    def copy(self, source, destination):
        for i in range(_words(self.types[source])):
            self.load(source, word=i)
            self.store(destination, word=i)

    def fail_if(self, condition):
        self.c.jcc(condition, self.trap)

    def compare_imm(self, register, value):
        self.c.mov_imm("r11", value & ((1 << 64) - 1))
        self.c.cmp(register, "r11")

    def range_check(self, register, typ, source=None):
        source = typ if source is None else source
        lo, hi = _bounds(typ)
        before_lo, before_hi = _bounds(source)
        signed = source.startswith("i")
        if lo > before_lo:
            self.compare_imm(register, lo)
            self.fail_if("l" if signed else "b")
        if hi < before_hi:
            self.compare_imm(register, hi)
            self.fail_if("g" if signed else "a")

    def narrow_result(self, typ, checked=False):
        if checked and WIDTHS[typ] < 64:
            # Arithmetic used full-width canonical registers; enforce original width.
            self.range_check("rax", typ, "i64" if typ.startswith("i") else "u64")
        _normalize(self.c, "rax", typ)

    def condition_value(self, condition):
        self.c.setcc(condition, "rax")

    def edge(self, target, arguments):
        # All sources are staged first. Backedges may permute their own slots.
        n = 0
        for arg in arguments:
            for word in range(_words(self.types[arg])):
                self.load(arg, word=word)
                self.c.store("rbp", self.edge_slot + n * 8, "rax")
                n += 1
        n = 0
        for param in self.blocks[target]["params"]:
            for word in range(_words(param["type"])):
                self.c.load("rax", "rbp", self.edge_slot + n * 8)
                self.store(param["name"], word=word)
                n += 1
        self.c.jmp(self.block_label(target))

    def operation(self, ins):
        c = self.c
        op, args, attrs = ins["op"], ins["args"], ins["attrs"]
        out = [v["name"] for v in ins["out"]]
        typ = self.types[args[0]] if args else None
        if op == "const":
            self.immediate(out[0], 0 if attrs["value"] is None else attrs["value"])
        elif op.startswith("int.") and op.split(".")[1] in {"add", "sub", "mul"}:
            action, mode = op.split(".")[1:]
            checked = mode == "checked"
            self.load(args[0]); self.load(args[1], "rcx")
            if action == "mul":
                if checked and not typ.startswith("i"):
                    c.mul("rcx")
                    c.test("rdx", "rdx"); self.fail_if("ne")
                else:
                    c.imul_rr("rax", "rcx")
                    if checked:
                        self.fail_if("o")
            else:
                getattr(c, action)("rax", "rcx")
                if checked:
                    self.fail_if("o" if typ.startswith("i") else "b")
            self.narrow_result(typ, checked)
            self.store(out[0])
        elif op in {"int.div.checked", "int.rem.checked"}:
            self.load(args[0]); self.load(args[1], "rcx")
            c.test("rcx", "rcx"); self.fail_if("e")
            if typ.startswith("i"):
                safe = self.label("division")
                self.compare_imm("rax", _bounds(typ)[0]); c.jcc("ne", safe)
                self.compare_imm("rcx", -1); self.fail_if("e")
                c.label(safe); c.cqo(); c.idiv("rcx")
            else:
                c.xor("rdx", "rdx"); c.div("rcx")
            if op == "int.rem.checked":
                c.mov_rr("rax", "rdx")
            self.store(out[0])
        elif op in {"int.shl.checked", "int.shr.checked"}:
            self.load(args[0]); self.load(args[1], "rcx")
            self.compare_imm("rcx", WIDTHS[typ]); self.fail_if("ae")
            c.shift_cl("shl" if op == "int.shl.checked" else "sar" if typ.startswith("i") else "shr", "rax")
            self.narrow_result(typ); self.store(out[0])
        elif op == "int.neg.checked":
            self.load(args[0])
            if typ.startswith("i"):
                c.neg("rax"); self.fail_if("o")
                self.narrow_result(typ, True)
            else:
                c.test("rax", "rax"); self.fail_if("ne")
            self.store(out[0])
        elif op.startswith("bit."):
            self.load(args[0])
            action = op.split(".")[1]
            if action == "not":
                c.bitnot("rax")
            else:
                self.load(args[1], "rcx")
                getattr(c, {"and": "and_", "or": "or_", "xor": "xor"}[action])("rax", "rcx")
            self.narrow_result(typ); self.store(out[0])
        elif op.startswith("compare."):
            self.load(args[0]); self.load(args[1], "rcx"); c.cmp("rax", "rcx")
            predicates = ({"eq": "e", "ne": "ne", "lt": "l", "le": "le", "gt": "g", "ge": "ge"}
                          if typ.startswith("i") else
                          {"eq": "e", "ne": "ne", "lt": "b", "le": "be", "gt": "a", "ge": "ae"})
            self.condition_value(predicates[op.split(".")[1]]); self.store(out[0])
        elif op.startswith("bool."):
            self.load(args[0])
            if op == "bool.not":
                c.alu_imm("xor", "rax", 1)
            else:
                self.load(args[1], "rcx")
                getattr(c, "and_" if op == "bool.and" else "or_")("rax", "rcx")
            self.store(out[0])
        elif op == "int.cast":
            self.load(args[0]); dest = self.types[out[0]]
            if attrs["mode"] == "checked":
                self.range_check("rax", dest, typ)
            _normalize(c, "rax", dest); self.store(out[0])
        elif op == "select":
            yes, done = self.label("select_yes"), self.label("select_done")
            self.load(args[0]); c.test("rax", "rax"); c.jcc("ne", yes)
            self.copy(args[2], out[0]); c.jmp(done)
            c.label(yes); self.copy(args[1], out[0]); c.label(done)
        elif op == "call":
            n = 0
            for arg in args:
                for word in range(_words(self.types[arg])):
                    self.load(arg, word=word); c.store("rbp", self.call_slot + n * 8, "rax"); n += 1
            c.lea("rdi", "rbp", self.call_slot)
            c.lea("rsi", "rbp", self.result_slot)
            c.call(self.parent.function_symbol(attrs["function"]))
            n = 0
            for name in out:
                for word in range(_words(self.types[name])):
                    c.load("rax", "rbp", self.result_slot + n * 8); self.store(name, word=word); n += 1
        elif op in {"owner.move", "borrow.read", "borrow.mut"}:
            self.copy(args[0], out[0])
        elif op == "loan.end":
            pass  # Permission/lifetime transitions were independently verified.
        elif op in {"buffer.new", "buffer.try_new"}:
            self.allocate_buffer(args[0], out, op == "buffer.new")
        elif op == "buffer.len":
            self.load(args[0], word=1); self.store(out[0])
        elif op == "owner.drop":
            if typ == "chain":
                self.drop_chain(args[0])
            else:
                done = self.label("drop_done")
                self.load(args[0], "rdi"); c.test("rdi", "rdi"); c.jcc("e", done)
                c.call("free"); c.label(done)
        elif op in {"buffer.load", "buffer.store"}:
            self.load(args[0], "rdx", 1); self.load(args[1], "rcx")
            c.cmp("rcx", "rdx"); self.fail_if("ae")
            self.load(args[0]); c.add("rax", "rcx")
            if op == "buffer.load":
                c.load_u8("rax", "rax"); self.store(out[0])
            else:
                self.load(args[2], "rcx"); c.store_u8("rax", 0, "rcx")
        elif op == "buffer.swap":
            # Both checks precede either write, including equal-index operations.
            self.load(args[0], "rdx", 1)
            self.load(args[1], "rcx"); c.cmp("rcx", "rdx"); self.fail_if("ae")
            self.load(args[2], "r8"); c.cmp("r8", "rdx"); self.fail_if("ae")
            self.load(args[0], "rdi"); c.mov_rr("rsi", "rdi")
            c.add("rdi", "rcx"); c.add("rsi", "r8")
            c.load_u8("rax", "rdi"); c.load_u8("rcx", "rsi")
            c.store_u8("rdi", 0, "rcx"); c.store_u8("rsi", 0, "rax")
        elif op in {"buffer.fill", "buffer.copy", "buffer.move_within", "buffer.copy_range", "buffer.fill_range"}:
            self.bulk(op, args)
        elif op == "chain.empty":
            self.immediate(out[0], 0)
        elif op == "chain.is_empty":
            self.load(args[0]); c.test("rax", "rax"); self.condition_value("e"); self.store(out[0])
        elif op in {"chain.head_read", "chain.head_mut"}:
            self.load(args[0], "rdx"); c.test("rdx", "rdx"); self.fail_if("e")
            for word in range(2):
                c.load("rax", "rdx", word * 8); self.store(out[0], word=word)
        elif op == "chain.try_push":
            self.push_chain(args, out)
        elif op == "chain.pop":
            self.pop_chain(args[0], out)
        else:
            _reject("opcode lacks a direct machine lowering: " + op)

    def allocate_buffer(self, size, out, trapping):
        c = self.c
        empty, failed, done = self.label("alloc_empty"), self.label("alloc_failed"), self.label("alloc_done")
        self.load(size, "rsi")
        c.test("rsi", "rsi"); c.jcc("e", empty)
        self.compare_imm("rsi", (1 << 63) - 1); c.jcc("a", failed)
        c.mov_imm("rdi", 1); c.call("calloc")
        c.test("rax", "rax"); c.jcc("e", failed)
        self.store(out[0]); self.load(size); self.store(out[0], word=1)
        if not trapping:
            self.immediate(out[1], 1)
        c.jmp(done)
        c.label(empty)
        self.immediate(out[0], 0); self.immediate(out[0], 0, 1)
        if not trapping:
            self.immediate(out[1], 1)
        c.jmp(done)
        c.label(failed)
        if trapping:
            c.jmp(self.trap)
        else:
            self.immediate(out[0], 0); self.immediate(out[0], 0, 1); self.immediate(out[1], 0)
        c.label(done)

    def range_guard(self, buffer, offset, size):
        c = self.c
        self.load(buffer, "rax", 1)
        self.load(offset, "rcx"); c.cmp("rcx", "rax"); self.fail_if("a")
        c.sub("rax", "rcx")
        self.load(size, "rcx"); c.cmp("rcx", "rax"); self.fail_if("a")

    def bulk(self, op, args):
        c = self.c
        done = self.label("bulk_done")
        if op == "buffer.fill":
            self.load(args[0], "rdx", 1)
        elif op == "buffer.copy":
            self.load(args[2], "rdx")
            for owner in args[:2]:
                self.load(owner, "rax", 1); c.cmp("rdx", "rax"); self.fail_if("a")
        elif op == "buffer.fill_range":
            self.range_guard(args[0], args[1], args[2]); self.load(args[2], "rdx")
        elif op == "buffer.move_within":
            self.range_guard(args[0], args[1], args[3]); self.range_guard(args[0], args[2], args[3])
            self.load(args[3], "rdx")
        else:
            self.range_guard(args[0], args[2], args[4]); self.range_guard(args[1], args[3], args[4])
            self.load(args[4], "rdx")
        c.test("rdx", "rdx"); c.jcc("e", done)
        # Empty operations skip even derived pointer formation and libc calls.
        self.load(args[0], "rdi")
        if op in {"buffer.fill", "buffer.fill_range"}:
            if op == "buffer.fill_range":
                self.load(args[1], "rax"); c.add("rdi", "rax")
            self.load(args[1] if op == "buffer.fill" else args[3], "rsi")
            c.call("memset")
        else:
            self.load(args[0] if op == "buffer.move_within" else args[1], "rsi")
            if op in {"buffer.move_within", "buffer.copy_range"}:
                i = 1 if op == "buffer.move_within" else 2
                self.load(args[i], "rax"); c.add("rdi", "rax")
                self.load(args[i + 1], "rax"); c.add("rsi", "rax")
            c.call("memmove" if op == "buffer.move_within" else "memcpy")
        c.label(done)

    def push_chain(self, args, out):
        c = self.c
        failed, done = self.label("push_failed"), self.label("push_done")
        c.mov_imm("rdi", 24); c.call("malloc")
        c.test("rax", "rax"); c.jcc("e", failed)
        self.store(out[0]); c.mov_rr("rdx", "rax")
        self.load(args[1]); c.store("rdx", 0, "rax")
        self.load(args[1], word=1); c.store("rdx", 8, "rax")
        self.load(args[0]); c.store("rdx", 16, "rax")
        self.immediate(out[1], 0); self.immediate(out[1], 0, 1); self.immediate(out[2], 1)
        c.jmp(done)
        c.label(failed)
        self.copy(args[0], out[0]); self.copy(args[1], out[1]); self.immediate(out[2], 0)
        c.label(done)

    def pop_chain(self, arg, out):
        c = self.c
        empty, done = self.label("pop_empty"), self.label("pop_done")
        self.load(arg, "rdi"); c.test("rdi", "rdi"); c.jcc("e", empty)
        for word in range(2):
            c.load("rax", "rdi", word * 8); self.store(out[1], word=word)
        c.load("rax", "rdi", 16); self.store(out[0])
        c.call("free"); self.immediate(out[2], 1); c.jmp(done)
        c.label(empty)
        self.immediate(out[0], 0); self.immediate(out[1], 0); self.immediate(out[1], 0, 1); self.immediate(out[2], 0)
        c.label(done)

    def drop_chain(self, arg):
        c = self.c
        loop, node, done = self.label("chain_drop_loop"), self.label("chain_drop_node"), self.label("chain_drop_done")
        self.load(arg); c.store("rbp", self.temporary, "rax")
        c.label(loop)
        c.load("rdx", "rbp", self.temporary); c.test("rdx", "rdx"); c.jcc("e", done)
        c.load("rax", "rdx", 16); c.store("rbp", self.temporary + 8, "rax")
        c.load("rdi", "rdx", 0); c.test("rdi", "rdi"); c.jcc("e", node)
        c.call("free")
        c.label(node)
        c.load("rdi", "rbp", self.temporary); c.call("free")
        c.load("rax", "rbp", self.temporary + 8); c.store("rbp", self.temporary, "rax")
        c.jmp(loop); c.label(done)

    def render(self):
        c = self.c
        begin = len(c.data)
        _prologue(c, self.frame)
        c.store("rbp", -8, "rsi")
        n = 0
        for param in self.fn["params"]:
            for word in range(_words(param["type"])):
                c.load("rax", "rdi", n * 8); self.store(param["name"], word=word); n += 1
        c.jmp(self.block_label(self.fn["entry"]))
        for block in self.fn["blocks"]:
            c.label(self.block_label(block["id"]))
            for ins in block["ops"]:
                self.operation(ins)
            term = block["term"]
            if term["op"] == "jump":
                self.edge(term["target"], term["args"])
            elif term["op"] == "branch":
                other = self.label("branch_else")
                self.load(term["cond"]); c.test("rax", "rax"); c.jcc("e", other)
                self.edge(term["then"]["target"], term["then"]["args"])
                c.label(other); self.edge(term["else"]["target"], term["else"]["args"])
            elif term["op"] == "trap":
                c.jmp(self.trap)
            elif term["op"] == "ret":
                c.load("r10", "rbp", -8)
                n = 0
                for arg in term["values"]:
                    for word in range(_words(self.types[arg])):
                        self.load(arg, word=word); c.store("r10", n * 8, "rax"); n += 1
                c.leave(); c.ret()
            else:
                _reject("unknown native terminator")
            if len(c.data) > MAX_TEXT_BYTES:
                _reject("direct code exceeds the 16 MiB text budget", "E_HIA_PROGRAM_LIMIT")
        c.label(self.trap); c.call("abort"); c.ud2()
        self.parent.symbols.append({"name": self.parent.function_symbol(self.fn["name"]),
                                    "offset": begin, "size": len(c.data) - begin, "global": False})
        self.parent.frames.append((self.fn["name"], self.frame))


class _Emitter:
    def __init__(self, document, allowed_exports):
        self.document, self.allowed_exports = document, allowed_exports
        self.c, self.symbols, self.exports, self.frames = Code(), [], [], []
        self.indices = {fn["name"]: i for i, fn in enumerate(document["functions"])}
        self.serial = 0

    def label(self, suffix):
        self.serial += 1
        return suffix + "_" + str(self.serial)

    def function_symbol(self, name):
        return "__hia_native_fn_" + str(self.indices[name])

    def wrapper(self, fn):
        name = fn["name"]
        if (name not in self.allowed_exports
                or any(p["type"] not in set(WIDTHS) | {"bool"} for p in fn["params"])
                or len(fn["returns"]) > 1
                or any(t not in set(WIDTHS) | {"bool", "unit"} for t in fn["returns"])):
            return
        if name in IMPORTS or name in _LOADER_HOOKS or name.startswith("__hia_"):
            _reject("export conflicts with the closed runtime or loader ABI", "E_HIA_PROGRAM_ABI")
        count = len(fn["params"])
        frame = ((count + 1) * 8 + 15) & -16
        if frame > MAX_FRAME_BYTES:
            _reject("entry wrapper exceeds the stack budget", "E_HIA_PROGRAM_LIMIT")
        c = self.c
        begin = len(c.data)
        _prologue(c, frame)
        input_slot, result_slot = -frame, -8
        # rax is the only scratch until every incoming argument is saved.
        for i, param in enumerate(fn["params"]):
            if i < len(_ARG_REGS):
                c.mov_rr("rax", _ARG_REGS[i])
            else:
                c.load("rax", "rbp", 16 + 8 * (i - len(_ARG_REGS)))
            _normalize(c, "rax", param["type"])
            c.store("rbp", input_slot + i * 8, "rax")
        c.lea("rdi", "rbp", input_slot); c.lea("rsi", "rbp", result_slot)
        c.call(self.function_symbol(name))
        if fn["returns"] and fn["returns"] != ["unit"]:
            c.load("rax", "rbp", result_slot)
            _normalize(c, "rax", fn["returns"][0])
        c.leave(); c.ret()
        self.symbols.append({"name": name, "offset": begin, "size": len(c.data) - begin, "global": True})
        self.exports.append(name)

    def render(self):
        # Future Core additions require an explicit lowering review. A growing
        # verifier registry cannot silently widen this backend through prefixes.
        if self.document["schema"] not in CORE_SCHEMAS:
            _reject("Core schema lacks a reviewed direct lowering", "E_HIA_PROGRAM_PROFILE")
        for fn in self.document["functions"]:
            types = [p["type"] for p in fn["params"]] + fn["returns"]
            for block in fn["blocks"]:
                types.extend(p["type"] for p in block["params"])
                if block["term"]["op"] not in {"ret", "jump", "branch", "trap"}:
                    _reject("terminator lacks a reviewed direct lowering", "E_HIA_PROGRAM_PROFILE")
                for instruction in block["ops"]:
                    if instruction["op"] not in SUPPORTED_OPCODES:
                        _reject("opcode lacks a reviewed direct lowering", "E_HIA_PROGRAM_PROFILE")
                    types.extend(p["type"] for p in instruction["out"])
            if any(typ not in _TYPES for typ in types):
                _reject("type lacks a reviewed direct lowering", "E_HIA_PROGRAM_PROFILE")
        for i, fn in enumerate(self.document["functions"]):
            _Function(self, fn, i).render()
        for fn in self.document["functions"]:
            self.wrapper(fn)
        missing = set(self.document.get("exports", [])) - set(self.exports)
        if missing:
            _reject("explicit exports have signatures outside the native C ABI: " + ", ".join(sorted(missing)), "E_HIA_PROGRAM_ABI")
        if not 1 <= len(self.exports) <= 128:
            _reject("native profile requires between 1 and 128 scalar entrypoints")
        if len(self.c.data) > MAX_TEXT_BYTES:
            _reject("direct code exceeds the text budget", "E_HIA_PROGRAM_LIMIT")
        text, relocations = self.c.finalize()
        obj = write_elf_object(text, self.symbols, relocations)
        return text, obj


def emit_program_machine(program, *, target=TARGET):
    """Recheck immutable Core and emit deterministic native object bytes."""
    from .hia_program import VerifiedProgram, verify_program
    if target != TARGET:
        _reject("direct machine backend supports only x86_64 Linux", "E_HIA_PROGRAM_TARGET")
    before = _implementation_hash()
    if not isinstance(program, VerifiedProgram):
        _reject("an immutable VerifiedProgram from verify_program is required")
    checked = verify_program(program)
    if (checked.canonical_bytes != program.canonical_bytes
            or checked.input_sha256 != program.input_sha256):
        _reject("verified program identity changed", "E_HIA_PROGRAM_ORIGIN")
    emitter = _Emitter(checked.as_dict(), checked.scalar_entrypoints)
    text, obj = emitter.render()
    if len(obj) > MAX_ARTIFACT_BYTES:
        _reject("object exceeds artifact byte budget", "E_HIA_PROGRAM_LIMIT")
    exports = tuple(sorted(emitter.exports))
    _inspect_object(obj, exports)
    if _implementation_hash() != before:
        _reject("verifier/emitter changed during generation", "E_HIA_PROGRAM_STALE")
    return HIAProgramMachine(obj, text, sha256(obj).hexdigest(), checked.sha256,
                             before, exports, PROFILE, target, checked.input_sha256,
                             tuple(emitter.frames))


def _inspect_object(data, exports):
    inventory = inspect_object_symbols(data, "ELF64", 62)
    if (inventory.get("defined") != frozenset(exports)
            or inventory.get("undefined") is None
            or not inventory["undefined"] <= IMPORTS):
        _reject("object import/export inventory differs from the closed ABI")
    return {name: sorted(values) for name, values in inventory.items()}


def _read_artifact(path):
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= MAX_ARTIFACT_BYTES:
        _reject("artifact must be a bounded ordinary nonempty file")
    key = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW), "rb") as stream:
        if key(os.fstat(stream.fileno())) != key(before):
            _reject("artifact changed before reading")
        data = stream.read(before.st_size + 1)
        if len(data) != before.st_size or key(os.fstat(stream.fileno())) != key(before):
            _reject("artifact changed during reading")
    if key(path.lstat()) != key(before):
        _reject("artifact pathname changed during reading")
    return data


def _run_logged(argv, *, command_log=None, **kwargs):
    if command_log is not None and type(command_log) is not list:
        _reject("command log must be a plain list", "E_HIA_COMMAND_LOG")
    row = {"argv": list(argv), "status": "attempted", "returncode": None}
    if command_log is not None:
        command_log.append(row)
    try:
        result = run_bounded(argv, **kwargs)
    except BaseException as error:
        row.update(status="capture_failed", error={"type": type(error).__name__, "message": str(error)})
        capture = getattr(error, "capture", None)
        if capture is not None:
            row["returncode"] = capture.returncode
            for name in ("stdout", "stderr"):
                raw = getattr(capture, name)
                row[name + "_hex"] = raw.hex()
                row[name + "_total_bytes"] = getattr(capture, name + "_total_bytes")
                row[name + "_complete"] = len(raw) == row[name + "_total_bytes"]
        raise
    row.update(status="completed", returncode=result.returncode)
    for name in ("stdout", "stderr"):
        raw = getattr(result, "raw_" + name)
        if raw is not None:
            row[name + "_hex"] = raw.hex()
            row[name + "_total_bytes"] = len(raw)
            row[name + "_complete"] = True
        else:
            row[name + "_text_fallback"] = getattr(result, name)
    return result


def _host():
    widths = {"pointer_bits": ctypes.sizeof(ctypes.c_void_p) * 8,
              "long_bits": ctypes.sizeof(ctypes.c_long) * 8,
              "size_t_bits": ctypes.sizeof(ctypes.c_size_t) * 8}
    return {"system": platform.system(), "machine": platform.machine(), "byteorder": sys.byteorder, **widths}


def compile_program_machine(image, *, program, output, kind="shared", linker="cc", command_log=None):
    """Publish a rederived object, or link and inspect a native shared library."""
    if command_log is not None and type(command_log) is not list:
        _reject("command log must be a plain list", "E_HIA_COMMAND_LOG")
    if not isinstance(image, HIAProgramMachine) or image != emit_program_machine(program, target=image.target):
        _reject("machine image differs from independently reverified Core", "E_HIA_PROGRAM_ORIGIN")
    if kind not in {"object", "shared"}:
        _reject("only relocatable objects and shared libraries are supported")
    host = _host()
    if kind == "shared" and (host["system"] != "Linux" or host["machine"].lower() not in {"x86_64", "amd64"}
                             or host["byteorder"] != "little" or any(host[k] != 64 for k in ("pointer_bits", "long_bits", "size_t_bits"))):
        _reject("shared linkage requires a Linux x86-64 LP64 host", "E_HIA_PROGRAM_TARGET")
    destination = Path(os.path.abspath(output))
    if destination.exists() or destination.is_symlink() or not destination.parent.is_dir():
        _reject("a new output path in an existing directory is required")
    tool = None
    tool_digest = None
    toolchain = None
    linker_mode = None
    flags = []
    if kind == "shared":
        found = shutil.which(linker)
        if found is None:
            _reject("GNU ld or a native C linker driver is required for shared linkage")
        tool = Path(found).resolve(); tool_digest = digest_executable(tool)
        version = _run_logged([str(tool), "--version"], command_log=command_log, timeout=10, stdout_limit=65536, stderr_limit=65536)
        if version.returncode:
            _reject("cannot identify the native linker")
        if version.stdout.startswith("GNU ld "):
            linker_mode, default_target = "gnu-ld", "elf_x86_64 (explicit emulation)"
        else:
            linker_mode = "c-driver"
            triple = _run_logged([str(tool), "-dumpmachine"], command_log=command_log, timeout=10, stdout_limit=65536, stderr_limit=65536)
            if (triple.returncode or triple.stdout.strip() not in
                    {"x86_64-linux-gnu", "x86_64-pc-linux-gnu", "x86_64-unknown-linux-gnu"}):
                _reject("linker driver must target x86_64 GNU/Linux")
            default_target = triple.stdout.strip()
        toolchain = {"path": str(tool), "sha256": tool_digest,
                     "version": version.stdout.splitlines()[0] if version.stdout else "",
                     "default_target": default_target, "mode": linker_mode,
                     "role": "link_generated_object_only"}
    with tempfile.TemporaryDirectory(prefix=".hia-direct-", dir=destination.parent) as directory:
        obj = Path(directory) / "program.o"
        obj.write_bytes(image.object_bytes)
        artifact = obj
        if kind == "shared":
            artifact = Path(directory) / "program.so"
            flags = (["-m", "elf_x86_64", "-shared", "-z", "defs", "-z", "noexecstack", "-z", "relro", "-z", "now", "--build-id=none"]
                     if linker_mode == "gnu-ld" else
                     ["-shared", "-Wl,-z,defs", "-Wl,-z,noexecstack", "-Wl,-z,relro", "-Wl,-z,now", "-Wl,--build-id=none"])
            libraries = ["-lc"] if linker_mode == "gnu-ld" else []
            result = _run_logged([str(tool), *flags, str(obj), *libraries, "-o", str(artifact)],
                                 command_log=command_log, timeout=60, stdout_limit=65536, stderr_limit=1048576)
            if result.returncode:
                _reject("linker rejected generated machine object: " + result.stderr[:3000])
        data = _read_artifact(artifact)
        inventory = inspect_owned_shared_elf(data, image.exports) if kind == "shared" else _inspect_object(data, image.exports)
        def recheck():
            if _implementation_hash() != image.implementation_sha256 or (tool is not None and digest_executable(tool) != tool_digest):
                _reject("implementation or linker driver changed during build", "E_HIA_PROGRAM_STALE")
        recheck()
        published = publish_verified(artifact, destination, data)
        try:
            recheck(); verify_published(artifact, destination, data)
        except BaseException:
            withdraw_own_link(artifact, destination)
            raise
    return {"schema": "hepta.hia.program.direct-native.v1", "ok": True,
            "status": "native_emitted_not_executed", "profile": image.profile,
            "target": image.target, "kind": kind, "output": str(destination),
            "supported_core_schemas": sorted(CORE_SCHEMAS), "supported_opcodes": sorted(SUPPORTED_OPCODES),
            "input_sha256": image.input_sha256, "core_sha256": image.core_sha256,
            "implementation_sha256": image.implementation_sha256,
            "machine_text_sha256": sha256(image.text_bytes).hexdigest(), "object_sha256": image.sha256,
            "artifact_sha256": published["sha256"], "artifact_bytes": published["bytes"],
            "machine_text_bytes": len(image.text_bytes), "exports": list(image.exports),
            "binary_inventory": inventory, "build_host": host, "toolchain": toolchain, "flags": flags,
            "function_frames": dict(image.function_frames),
            "external_abi": "SysV AMD64 scalar C functions; resources and multiple results are internal",
            "runtime_assumptions": ["Linux x86-64 LP64 runtime and ordinary C scalar ABI",
                "calloc/malloc return null or fresh nonaliasing allocations; calloc initializes every byte",
                "free releases a live allocation; libc memory functions implement their standard byte semantics",
                "abort terminates execution; traps do not promise cleanup",
                "linker, loader, libc and host hardware are trusted; native execution has no VM step/heap/call quotas"],
            "claims": {"standalone_core_reverified": True, "direct_machine_code": True,
                "llvm_ir_used": False, "llvm_codegen_used": False, "assembler_used": False,
                "source_ast_required": False, "rust_reference_required": False,
                "rust_codegen_used": False, "c_codegen_used": False, "fallback_used": False,
                "external_linker_used": kind == "shared", "native_execution_qualified": False,
                "backend_refinement_proved": False, "whole_language_soundness_proved": False,
                "self_hosted": False, "foreign_buffer_entrypoints_exposed": False}}


def build_program_machine(document, output, *, kind="shared", linker="cc", target=TARGET,
                          command_log=None, bounded_resource_limits=None):
    from .hia_program import verify_program
    program = verify_program(document)
    budget = None
    if bounded_resource_limits is not None:
        from .hia_static_budget import qualify_bounded_resources
        budget = qualify_bounded_resources(program, limits=bounded_resource_limits)
    image = emit_program_machine(program, target=target)
    result = compile_program_machine(image, program=program, output=output, kind=kind,
                                     linker=linker, command_log=command_log)
    if budget is not None:
        result["bounded_resources"] = budget
    return result
