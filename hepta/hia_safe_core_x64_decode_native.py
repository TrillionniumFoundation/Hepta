"""Build the HIA x86 decoder interface for the independent Safe Core checker."""
from __future__ import annotations

import ctypes
import os
import struct

from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image, _source_resource_path
from .hia_safe_core_x64 import Instruction, SafeCoreMachineRejected

SOURCE = _source_resource_path('examples/hia_bootstrap/safe_core_x64_decode.hepta')
SCHEMA = 'hepta.hia.safe-core-x64-decode-native.v1'
SELECTOR = 'HEPTA_HIA_SAFE_CORE_X64_DECODE_MANIFEST'
MAX_TEXT = 65536
MAX_INSTRUCTIONS = 8192
WORKSPACE = 128 + MAX_TEXT
HEADER = struct.Struct('<3Q')
ROW = struct.Struct('<6Q')
OPERATIONS = (
    ('push', ('u',)), ('pop', ('u',)), ('imm', ('u', 'u')), ('ret', ()),
    ('leave', ()), ('nop', ()), ('call', ('i',)), ('jmp', ('i',)),
    ('jcc', ('u', 'i')), ('setcc', ('u', 'u')), ('cmovne', ('u', 'u')),
    ('imul', ('u', 'u')), ('load8', ('u', 'u', 'i')), ('ud2', ()),
    ('store8', ('u', 'i', 'u')), ('mov', ('u', 'u')), ('store', ('u', 'i', 'u')),
    ('load', ('u', 'u', 'i')), ('lea', ('u', 'u', 'i')),
    ('add', ('u', 'u')), ('sub', ('u', 'u')), ('and', ('u', 'u')), ('or', ('u', 'u')),
    ('xor', ('u', 'u')), ('cmp', ('u', 'u')), ('test', ('u', 'u')),
    ('immediate_alu', ('a', 'u', 'i')), ('shl', ('u', 'u')), ('shr', ('u', 'u')),
    ('not', ('u',)),
)
OPERATION_IDS = {name: code for code, (name, _) in enumerate(OPERATIONS, 1)}
ALU_GROUPS = {0: 'add', 1: 'or', 4: 'and', 5: 'sub', 6: 'xor', 7: 'cmp'}
REFUSALS = (
    ('text_budget', 'machine text budget exceeded'),
    ('truncated', 'truncated machine instruction'),
    ('indexed', 'indexed memory addressing is outside the profile'),
    ('mode', 'only register or explicit base/disp32 addressing is admitted'),
    ('sib', 'unknown SIB addressing'),
    ('stack_prefix', 'unreviewed stack instruction prefix'),
    ('imm_prefix', 'unreviewed immediate prefix'),
    ('single_prefix', 'unreviewed single-byte prefix'),
    ('branch_prefix', 'unreviewed direct branch prefix'),
    ('conditional_prefix', 'unreviewed conditional branch prefix'),
    ('setcc', 'unreviewed SETcc byte register'),
    ('cmovne', 'only 64-bit register-register CMOVNE is admitted'),
    ('imul', 'only 64-bit register-register IMUL is admitted'),
    ('load8', 'unreviewed zero-extending byte load'),
    ('ud2_prefix', 'unreviewed UD2 prefix'),
    ('opcode_0f', 'unsupported 0F opcode'),
    ('store8', 'unreviewed byte store'),
    ('move_width', 'non-64-bit ordinary move is outside the profile'),
    ('move_mode', 'unreviewed move/LEA register form'),
    ('alu_width', 'unreviewed ALU memory or narrow operand'),
    ('immediate_alu', 'unreviewed immediate ALU instruction'),
    ('shift', 'unreviewed shift instruction'),
    ('unary', 'unreviewed unary instruction'),
    ('opcode', 'unsupported machine opcode at byte {}'),
    ('instruction_budget', 'decoded instruction budget exceeded'),
    ('target', 'branch is not an exact instruction boundary'),
    ('condition', 'only reviewed unsigned/equality conditions are admitted'),
)
REFUSAL_IDS = {name: code for code, (name, _) in enumerate(REFUSALS, 1)}


def _operand(kind, word):
    if kind == 'a':
        if word not in ALU_GROUPS:
            raise RuntimeError('invalid native Safe Core ALU group')
        return ALU_GROUPS[word]
    if kind == 'i' and word >= 1 << 63:
        return word - (1 << 64)
    return word


class NativeSafeCoreX64Decode(NativeHiaJsonImage):
    def decode(self, data):
        from .hia_safe_core_x64 import require

        require(type(data) is bytes and 0 < len(data) <= MAX_TEXT, REFUSALS[0][1])
        source = ctypes.create_string_buffer(data, len(data))
        capacity = HEADER.size + min(len(data), MAX_INSTRUCTIONS) * ROW.size
        output = ctypes.create_string_buffer(capacity)
        scratch = ctypes.create_string_buffer(WORKSPACE)
        size = self._entry(source, len(data), output, capacity, scratch, WORKSPACE)
        if not HEADER.size <= size <= capacity:
            raise RuntimeError('invalid native Safe Core decoder response size')
        status, detail, count = HEADER.unpack_from(output)
        if status:
            if status > len(REFUSALS) or size != HEADER.size or count or detail >= len(data):
                raise RuntimeError('invalid native Safe Core decoder refusal')
            name, message = REFUSALS[status - 1]
            if name in ('opcode', 'opcode_0f'):
                raise SafeCoreMachineRejected(message.format(detail))
            require(False, message)
        if (detail or not 0 < count <= min(len(data), MAX_INSTRUCTIONS)
                or size != HEADER.size + count * ROW.size):
            raise RuntimeError('invalid native Safe Core instruction inventory')
        result, pc = {}, 0
        for offset in range(HEADER.size, size, ROW.size):
            at, code, width, *words = ROW.unpack_from(output, offset)
            if at != pc or not 1 <= code <= len(OPERATIONS) or not 1 <= width <= len(data) - pc:
                raise RuntimeError('invalid native Safe Core instruction row')
            name, roles = OPERATIONS[code - 1]
            args = tuple(_operand(role, word) for role, word in zip(roles, words))
            result[pc] = Instruction(name, args, width)
            pc += width
        if pc != len(data):
            raise RuntimeError('native Safe Core decoder left unconsumed machine bytes')
        return result


def installed_safe_core_x64_decode(path):
    return _installed_json_image(path, SOURCE, SCHEMA, NativeSafeCoreX64Decode)


def selected_safe_core_x64_decode():
    selected = os.environ.get(SELECTOR)
    return None if selected is None else installed_safe_core_x64_decode(selected)
