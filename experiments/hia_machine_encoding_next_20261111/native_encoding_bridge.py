"""Development bridge for HIA-owned x86-64 instruction bytes.

Python still owns public operand admission, mutable Code storage, labels,
relocations, method dispatch and foreign effects. Every generated instruction
byte in NativeEncodedCode's public instruction methods comes from HIA.
This experiment is not a complete backend, default selector or release gate.
"""
from __future__ import annotations

from collections import Counter
import ctypes
import struct

from hepta import hia_machine_x64 as reference
from hepta.hia_json_preflight_native import NativeHiaJsonImage

COMMANDS = (
    'align', 'mov_rr', 'mov_imm', 'load', 'store', 'lea', 'load_u8', 'store_u8',
    'add', 'sub', 'and_', 'or_', 'xor', 'cmp', 'test', 'alu_imm', 'shift',
    'imul', 'mul', 'imul_full', 'div', 'idiv', 'neg', 'bitnot', 'cqo',
    'set_byte', 'cmov', 'push', 'pop', 'ret', 'leave', 'ud2',
    'jmp_prefix', 'jcc_prefix', 'call_prefix', 'zero_rel32', 'rel32',
)
COMMAND_IDS = {name: index for index, name in enumerate(COMMANDS, 1)}
MAGIC = int.from_bytes(b'HIAX6401', 'little')
MASK = (1 << 64) - 1


class NativeMachineEncoding(NativeHiaJsonImage):
    def __init__(self, image, expected_sha256):
        super().__init__(image, expected_sha256)
        self.calls = Counter()

    def encode(self, command, *, r=0, m=0, value=0, auxiliary=0, mode=0, offset=0):
        packet = struct.pack('<8Q', MAGIC, COMMAND_IDS[command], r, m,
                             value & MASK, auxiliary, mode, offset)
        source = ctypes.create_string_buffer(packet, len(packet))
        output = ctypes.create_string_buffer(b'\xa5' * 80, 80)
        workspace = ctypes.create_string_buffer(b'\x5a' * 8, 8)
        status = self._entry(source, len(packet), output, 80, workspace, 8)
        self.calls[command] += 1
        if status != 0:
            raise RuntimeError('native machine encoding packet refused: ' + hex(status))
        length, = struct.unpack_from('<Q', output)
        cursor, = struct.unpack_from('<Q', workspace)
        if (length > 63 or cursor != length + 8 or source.raw != packet
                or output.raw[8 + length:] != b'\xa5' * (72 - length)):
            raise RuntimeError('native machine encoding output contract differs')
        return output.raw[8:8 + length]


def _displacement(value):
    # Public operand admission is deliberately still a hosted boundary. Do not
    # call the retained struct-packing helper merely to validate an operand.
    if type(value) is not int or not -(1 << 31) <= value < 1 << 31:
        raise reference.MachineEncodingError('operand is outside signed disp32/imm32')
    return value


class NativeEncodedCode(reference.Code):
    """Code-compatible experimental byte owner; no production activation."""
    def __init__(self, encoding, *, scratch_registers=None,
                 move_immediate='movabs', alu_immediate='imm32'):
        super().__init__(scratch_registers=scratch_registers,
                         move_immediate=move_immediate, alu_immediate=alu_immediate)
        self.encoding = encoding

    def _bytes(self, command, **values):
        return self.encoding.encode(command, **values)

    def align(self, boundary):
        if type(boundary) is not int or boundary not in {1, 16, 32, 64}:
            raise reference.MachineEncodingError('unreviewed function alignment')
        self.emit(self._bytes('align', auxiliary=boundary, offset=len(self.data)))

    def _pair(self, command, dst, src, *, destination_first=False):
        if destination_first:
            destination, source = self._reg(dst), self._reg(src)
        else:
            source, destination = self._reg(src), self._reg(dst)
        self.emit(self._bytes(command, r=destination, m=source))

    def mov_rr(self, dst, src):
        self._pair('mov_rr', dst, src)

    def mov_imm(self, dst, value):
        register = self._reg(dst)
        if type(value) is not int or not -(1 << 63) <= value < 1 << 64:
            raise reference.MachineEncodingError('immediate is outside the 64-bit word')
        mode = bool(self.move_immediate == 'mov32_if_exact')
        self.emit(self._bytes('mov_imm', r=register, value=value, mode=int(mode)))

    def _memory(self, command, reg, base, disp):
        register, address = self._reg(reg), self._reg(base)
        value = _displacement(disp)
        self.emit(self._bytes(command, r=register, m=address, value=value))

    def load(self, dst, base, disp=0):
        self._memory('load', dst, base, disp)

    def store(self, base, disp, src):
        self._memory('store', src, base, disp)

    def lea(self, dst, base, disp=0):
        self._memory('lea', dst, base, disp)

    def load_u8(self, dst, base, disp=0):
        self._memory('load_u8', dst, base, disp)

    def store_u8(self, base, disp, src):
        self._memory('store_u8', src, base, disp)

    def add(self, dst, src): self._pair('add', dst, src)
    def sub(self, dst, src): self._pair('sub', dst, src)
    def and_(self, dst, src): self._pair('and_', dst, src)
    def or_(self, dst, src): self._pair('or_', dst, src)
    def xor(self, dst, src): self._pair('xor', dst, src)
    def cmp(self, left, right): self._pair('cmp', left, right)
    def test(self, left, right): self._pair('test', left, right)

    def alu_imm(self, op, dst, value):
        choices = {'add': 0, 'or': 1, 'and': 2, 'sub': 3, 'xor': 4, 'cmp': 5}
        if type(op) is not str or op not in choices:
            raise reference.MachineEncodingError('unsupported immediate ALU operation')
        register = self._reg(dst)
        value = _displacement(value)
        mode = bool(self.alu_immediate == 'imm8_if_exact')
        self.emit(self._bytes('alu_imm', r=register, value=value,
                              auxiliary=choices[op], mode=int(mode)))

    def shift(self, op, dst, count):
        choices = {'shl': 0, 'shr': 1, 'sar': 2}
        if type(op) is not str or op not in choices:
            raise reference.MachineEncodingError('unsupported shift operation')
        register = self._reg(dst)
        if count == 'cl':
            self.emit(self._bytes('shift', r=register, auxiliary=choices[op], mode=1))
        elif type(count) is int and 0 <= count < 64:
            self.emit(self._bytes('shift', r=register, value=count, auxiliary=choices[op]))
        else:
            raise reference.MachineEncodingError('shift count must be 0..63 or cl')

    def shift_imm(self, op, dst, count): self.shift(op, dst, count)
    def shift_cl(self, op, dst): self.shift(op, dst, 'cl')
    def shl(self, dst, count): self.shift('shl', dst, count)
    def shr(self, dst, count): self.shift('shr', dst, count)
    def sar(self, dst, count): self.shift('sar', dst, count)

    def imul(self, dst, src):
        self._pair('imul', dst, src, destination_first=True)

    def imul_rr(self, dst, src): self.imul(dst, src)

    def _one(self, command, value):
        register = self._reg(value)
        self.emit(self._bytes(command, r=register))

    def mul(self, src): self._one('mul', src)
    def imul_full(self, src): self._one('imul_full', src)
    def div(self, src): self._one('div', src)
    def idiv(self, src): self._one('idiv', src)
    def neg(self, src): self._one('neg', src)
    def bitnot(self, src): self._one('bitnot', src)
    def cqo(self): self.emit(self._bytes('cqo'))

    def setcc(self, condition, dst):
        condition = reference._condition(condition)
        register = self._reg(dst)
        # Keep the original second register observation inside mov_imm. A
        # foreign mapping can change between that observation and SETcc.
        self.mov_imm(dst, 0)
        self.emit(self._bytes('set_byte', r=register, auxiliary=condition))

    def cmov(self, condition, dst, src):
        condition = reference._condition(condition)
        destination, source = self._reg(dst), self._reg(src)
        self.emit(self._bytes('cmov', r=destination, m=source, auxiliary=condition))

    def push(self, reg): self._one('push', reg)
    def pop(self, reg): self._one('pop', reg)
    def ret(self): self.emit(self._bytes('ret'))
    def leave(self): self.emit(self._bytes('leave'))
    def ud2(self): self.emit(self._bytes('ud2'))

    def _branch_bytes(self, prefix, target):
        if type(target) is not str or not target or len(target) > 512:
            raise reference.MachineEncodingError('invalid branch target')
        self.emit(prefix)
        self.fixups.append((len(self.data), target))
        self.emit(self._bytes('zero_rel32'))

    def jmp(self, target):
        self._branch_bytes(self._bytes('jmp_prefix'), target)

    def jcc(self, condition, target):
        condition = reference._condition(condition)
        self._branch_bytes(self._bytes('jcc_prefix', auxiliary=condition), target)

    def call(self, symbol):
        if type(symbol) is not str or reference._SYMBOL.fullmatch(symbol) is None:
            raise reference.MachineEncodingError('invalid call symbol')
        self.emit(self._bytes('call_prefix'))
        self.relocations.append({'offset': len(self.data), 'symbol': symbol, 'type': 4, 'addend': -4})
        self.emit(self._bytes('zero_rel32'))

    def finalize(self):
        if len(self.data) > reference.MAX_CODE_BYTES:
            raise reference.MachineEncodingError('x86-64 image exceeds code byte limit')
        result = bytearray(self.data)
        for offset, target in self.fixups:
            if target not in self.labels:
                raise reference.MachineEncodingError('unresolved machine label: ' + target)
            value = _displacement(self.labels[target] - (offset + 4))
            result[offset:offset + 4] = self._bytes('rel32', value=value)
        return bytes(result), [dict(row) for row in self.relocations]


def selected_code_class(encoding):
    class SelectedCode(NativeEncodedCode):
        def __init__(self, *, scratch_registers=None,
                     move_immediate='movabs', alu_immediate='imm32'):
            super().__init__(encoding, scratch_registers=scratch_registers,
                             move_immediate=move_immediate, alu_immediate=alu_immediate)
    return SelectedCode
