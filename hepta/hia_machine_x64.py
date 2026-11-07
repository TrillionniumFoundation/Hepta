"""Small, deterministic x86-64 encoder used by the direct HIA backend.

The supported instructions are encoded here as bytes. No assembler, LLVM or
other code generator is invoked. This is an implementation, not an ISA proof;
the executable/disassembly tests check its admitted instruction surface.
"""
from __future__ import annotations

import re
import struct

_REGISTERS = {name: i for i, name in enumerate((
    "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"))}
_CONDITIONS = {
    "o": 0, "no": 1, "b": 2, "c": 2, "nae": 2,
    "ae": 3, "nb": 3, "nc": 3, "e": 4, "z": 4,
    "ne": 5, "nz": 5, "be": 6, "na": 6, "a": 7, "nbe": 7,
    "s": 8, "ns": 9, "p": 10, "pe": 10, "np": 11, "po": 11,
    "l": 12, "nge": 12, "ge": 13, "nl": 13, "le": 14,
    "ng": 14, "g": 15, "nle": 15,
}
_SYMBOL = re.compile(r"[A-Za-z_][A-Za-z_0-9]{0,191}\Z")
MAX_CODE_BYTES = 64 * 1024 * 1024


class MachineEncodingError(ValueError):
    """An operand cannot be represented by the admitted x86-64 profile."""


def _reg(value):
    if type(value) is not str or value not in _REGISTERS:
        raise MachineEncodingError("unknown x86-64 register")
    return _REGISTERS[value]


def _s32(value):
    if type(value) is not int or not -(1 << 31) <= value < 1 << 31:
        raise MachineEncodingError("operand is outside signed disp32/imm32")
    return struct.pack("<i", value)


def _condition(value):
    if type(value) is not str or value not in _CONDITIONS:
        raise MachineEncodingError("unknown x86-64 condition")
    return _CONDITIONS[value]


class Code:
    """One .text image with bounded rel32 labels and symbol call relocations.

    Operands are register names. All ordinary arithmetic uses 64 bits. Every
    memory address uses an explicit base and signed displacement, with no
    implicit indexed addressing. ``finalize`` does not mutate the image and
    therefore produces identical bytes on repeated calls.
    """

    def __init__(self, *, scratch_registers=None, move_immediate="movabs", alu_immediate="imm32"):
        # Both registers are explicit scratch operands, never implicit ISA or
        # SysV argument/result registers. Only a complete bijection is admitted.
        mapping = {"r10": "r10", "r11": "r11"} if scratch_registers is None else scratch_registers
        if (type(mapping) is not dict or set(mapping) != {"r10", "r11"}
                or any(type(value) is not str for value in mapping.values())
                or set(mapping.values()) != {"r10", "r11"}):
            raise MachineEncodingError("scratch registers must bijectively rename r10/r11")
        if type(move_immediate) is not str or move_immediate not in {"movabs", "mov32_if_exact"}:
            raise MachineEncodingError("unreviewed immediate move selection")
        if type(alu_immediate) is not str or alu_immediate not in {"imm32", "imm8_if_exact"}:
            raise MachineEncodingError("unreviewed immediate arithmetic selection")
        self.scratch_registers = dict(mapping)
        self.move_immediate, self.alu_immediate = move_immediate, alu_immediate
        self.data = bytearray()
        self.labels = {}
        self.fixups = []
        self.relocations = []

    def _reg(self, value):
        # Check type first so malformed/unhashable operands retain typed errors.
        if type(value) is not str:
            raise MachineEncodingError("unknown x86-64 register")
        return _reg(self.scratch_registers.get(value, value))

    def align(self, boundary):
        if type(boundary) is not int or boundary not in {1, 16, 32, 64}:
            raise MachineEncodingError("unreviewed function alignment")
        self.emit(b"\x90" * ((-len(self.data)) % boundary))

    @property
    def offset(self):
        return len(self.data)

    def emit(self, value):
        if type(value) not in (bytes, bytearray):
            raise MachineEncodingError("encoded instructions must be bytes")
        if len(value) > MAX_CODE_BYTES - len(self.data):
            raise MachineEncodingError("x86-64 image exceeds code byte limit")
        self.data.extend(value)

    def _rr(self, opcode, reg, rm, *, wide=True):
        r, m = self._reg(reg), self._reg(rm)
        rex = 0x40 | (8 if wide else 0) | ((r >> 3) << 2) | (m >> 3)
        self.emit(bytes([rex]) + opcode + bytes([0xc0 | ((r & 7) << 3) | (m & 7)]))

    def _mem(self, opcode, reg, base, disp=0, *, wide=True):
        r, b = self._reg(reg), self._reg(base)
        displacement = _s32(disp)
        rex = 0x40 | (8 if wide else 0) | ((r >> 3) << 2) | (b >> 3)
        modrm = 0x80 | ((r & 7) << 3) | (b & 7)
        sib = b"\x24" if b & 7 == 4 else b""
        self.emit(bytes([rex]) + opcode + bytes([modrm]) + sib + displacement)

    def label(self, name):
        if type(name) is not str or not name or len(name) > 512 or name in self.labels:
            raise MachineEncodingError("empty, oversized or duplicate machine label")
        self.labels[name] = len(self.data)

    def _branch(self, prefix, target):
        if type(target) is not str or not target or len(target) > 512:
            raise MachineEncodingError("invalid branch target")
        self.emit(prefix)
        self.fixups.append((len(self.data), target))
        self.emit(b"\0" * 4)

    def jmp(self, target):
        self._branch(b"\xe9", target)

    def jcc(self, condition, target):
        self._branch(bytes([0x0f, 0x80 + _condition(condition)]), target)

    def call(self, symbol):
        if type(symbol) is not str or _SYMBOL.fullmatch(symbol) is None:
            raise MachineEncodingError("invalid call symbol")
        self.emit(b"\xe8")
        self.relocations.append({"offset": len(self.data), "symbol": symbol,
                                 "type": 4, "addend": -4})
        self.emit(b"\0" * 4)

    def mov_rr(self, dst, src):
        self._rr(b"\x89", src, dst)

    def mov_imm(self, dst, value):
        reg = self._reg(dst)
        if type(value) is not int or not -(1 << 63) <= value < 1 << 64:
            raise MachineEncodingError("immediate is outside the 64-bit word")
        if self.move_immediate == "mov32_if_exact" and 0 <= value < 1 << 32:
            # A 32-bit destination write zero-extends and MOV leaves flags alone.
            prefix = b"\x41" if reg >= 8 else b""
            self.emit(prefix + bytes([0xb8 + (reg & 7)]) + struct.pack("<I", value))
        else:
            self.emit(bytes([0x48 | (reg >> 3), 0xb8 + (reg & 7)]) +
                      struct.pack("<Q", value & ((1 << 64) - 1)))

    def load(self, dst, base, disp=0):
        self._mem(b"\x8b", dst, base, disp)

    def store(self, base, disp, src):
        self._mem(b"\x89", src, base, disp)

    def lea(self, dst, base, disp=0):
        self._mem(b"\x8d", dst, base, disp)

    def load_u8(self, dst, base, disp=0):
        self._mem(b"\x0f\xb6", dst, base, disp)

    def store_u8(self, base, disp, src):
        # Even low registers 4..7 need a REX prefix to name spl/bpl/sil/dil.
        self._mem(b"\x88", src, base, disp, wide=False)

    def add(self, dst, src): self._rr(b"\x01", src, dst)
    def sub(self, dst, src): self._rr(b"\x29", src, dst)
    def and_(self, dst, src): self._rr(b"\x21", src, dst)
    def or_(self, dst, src): self._rr(b"\x09", src, dst)
    def xor(self, dst, src): self._rr(b"\x31", src, dst)
    def cmp(self, left, right): self._rr(b"\x39", right, left)
    def test(self, left, right): self._rr(b"\x85", right, left)

    def alu_imm(self, op, dst, value):
        groups = {"add": 0, "or": 1, "and": 4, "sub": 5, "xor": 6, "cmp": 7}
        if type(op) is not str or op not in groups:
            raise MachineEncodingError("unsupported immediate ALU operation")
        r = self._reg(dst)
        immediate = _s32(value)
        compact = self.alu_immediate == "imm8_if_exact" and -128 <= value <= 127
        if compact:
            immediate = struct.pack("<b", value)
        self.emit(bytes([0x48 | (r >> 3), 0x83 if compact else 0x81,
                         0xc0 | (groups[op] << 3) | (r & 7)]) + immediate)

    def shift(self, op, dst, count):
        groups = {"shl": 4, "shr": 5, "sar": 7}
        if type(op) is not str or op not in groups:
            raise MachineEncodingError("unsupported shift operation")
        r = self._reg(dst)
        prefix = bytes([0x48 | (r >> 3)])
        modrm = bytes([0xc0 | (groups[op] << 3) | (r & 7)])
        if count == "cl":
            self.emit(prefix + b"\xd3" + modrm)
        elif type(count) is int and 0 <= count < 64:
            self.emit(prefix + b"\xc1" + modrm + bytes([count]))
        else:
            raise MachineEncodingError("shift count must be 0..63 or cl")

    def shift_imm(self, op, dst, count): self.shift(op, dst, count)
    def shift_cl(self, op, dst): self.shift(op, dst, "cl")

    def shl(self, dst, count): self.shift("shl", dst, count)
    def shr(self, dst, count): self.shift("shr", dst, count)
    def sar(self, dst, count): self.shift("sar", dst, count)

    def imul(self, dst, src):
        self._rr(b"\x0f\xaf", dst, src)

    def imul_rr(self, dst, src): self.imul(dst, src)

    def _unary(self, group, src):
        r = self._reg(src)
        self.emit(bytes([0x48 | (r >> 3), 0xf7, 0xc0 | (group << 3) | (r & 7)]))

    def mul(self, src): self._unary(4, src)
    def imul_full(self, src): self._unary(5, src)
    def div(self, src): self._unary(6, src)
    def idiv(self, src): self._unary(7, src)
    def neg(self, src): self._unary(3, src)
    def bitnot(self, src): self._unary(2, src)
    def cqo(self): self.emit(b"\x48\x99")

    def setcc(self, condition, dst):
        condition = _condition(condition)
        r = self._reg(dst)
        # MOV preserves flags; this creates the canonical zero-extended bool.
        self.mov_imm(dst, 0)
        self.emit(bytes([0x40 | (r >> 3), 0x0f, 0x90 + condition, 0xc0 | (r & 7)]))

    def cmov(self, condition, dst, src):
        # The reviewed form has register operands only. It preserves flags and
        # cannot introduce a speculative memory access to an unselected input.
        self._rr(bytes([0x0f, 0x40 + _condition(condition)]), dst, src)

    def push(self, reg):
        r = self._reg(reg)
        self.emit((b"\x41" if r >= 8 else b"") + bytes([0x50 + (r & 7)]))

    def pop(self, reg):
        r = self._reg(reg)
        self.emit((b"\x41" if r >= 8 else b"") + bytes([0x58 + (r & 7)]))

    def ret(self): self.emit(b"\xc3")
    def leave(self): self.emit(b"\xc9")
    def ud2(self): self.emit(b"\x0f\x0b")

    def finalize(self):
        if len(self.data) > MAX_CODE_BYTES:
            raise MachineEncodingError("x86-64 image exceeds code byte limit")
        result = bytearray(self.data)
        for offset, target in self.fixups:
            if target not in self.labels:
                raise MachineEncodingError("unresolved machine label: " + target)
            result[offset:offset + 4] = _s32(self.labels[target] - (offset + 4))
        return bytes(result), [dict(row) for row in self.relocations]
