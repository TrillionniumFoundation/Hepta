"""Author HIA's ordinary Code state, label and fixup continuation.

The checked-in HIA source owns policy and observation order. Python object
storage, primitive object operations and foreign method effects are explicit
continuations. Instruction bytes use the independently selected HIA encoder.
"""
from __future__ import annotations

import ast
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ''}:
    sys.path.insert(0, str(ROOT))

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
from tools.hia_exception_delivery import BODY as EXCEPTION_DELIVERY_BODY

LITERALS = (
    'scratch_registers', 'move_immediate', 'alu_immediate', 'data',
    'labels', 'fixups', 'relocations', 'values', 'get', 'extend',
    'r10', 'r11', 'movabs', 'mov32_if_exact', 'imm32', 'imm8_if_exact',
    'scratch registers must bijectively rename r10/r11',
    'unreviewed immediate move selection',
    'unreviewed immediate arithmetic selection',
    'encoded instructions must be bytes',
    'x86-64 image exceeds code byte limit',
    'empty, oversized or duplicate machine label',
    'unknown x86-64 register',
    'operand is outside signed disp32/imm32',
    'unresolved machine label: ',
)
CONSTANTS = {
    'MAGIC': int.from_bytes(b'HIACST01', 'little'), 'ABI': 0xfffffffd,
    'MAX_CODE': 64 * 1024 * 1024, 'TERMINAL': (1 << 64) - 1,
    'TYPE': 1, 'LEN': 2, 'GETATTR': 3, 'SETATTR': 4, 'CONST': 5,
    'DICT_NEW': 6, 'LIST_NEW': 7, 'BYTEARRAY_NEW': 8, 'BYTES_COPY': 9,
    'DICT_COPY': 10, 'SET_COPY': 11, 'SET_PAIR': 12, 'NOT_EQUAL': 13,
    'GET_ITER': 14, 'NEXT': 15, 'UNPACK_TWO': 16, 'CONTAINS': 17,
    'GET_ITEM': 18, 'SET_ITEM': 19, 'ADD': 20, 'SUB': 21,
    'SET_SLICE': 22, 'CALL0': 23, 'CALL1': 24, 'CALL2': 25,
    'LIST_APPEND': 26, 'NEW_INT': 27, 'ENCODE_REL32': 28,
    'RAISE_ERROR': 29, 'STR_SUMMARY': 30, 'INT_SUMMARY': 31,
    'TUPLE_TWO': 32, 'DICT_TWO': 33, 'BYTEARRAY_COPY': 34,
    'TYPE_COMPARE': 35,
    'E_SCRATCH': 16, 'E_MOVE': 17, 'E_ALU': 18, 'E_BYTES': 19,
    'E_LIMIT': 20, 'E_LABEL': 21, 'E_REG': 22, 'E_DISP': 23,
}

SOURCE = r'''
def machine_state(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) == 64:
        return emit_exception_delivery(s, o, w)
    if length(s) != 80 or length(o) < 8 or length(w) != 2048:
        return ABI
    if word(s, 0) != MAGIC:
        return ABI
    if get(w, 0) == 0:
        if word(s, 8) != 0 or word(s, 16) != 0 or word(s, 24) < 1 or word(s, 24) > 6:
            return ABI
        if word(s, 32) == 0 or word(s, 64) == 0 or word(s, 72) != 0:
            return ABI
        put(w, 0, MAGIC)
        put(w, 8, 0)
        put(w, 16, 0)
        put(w, 24, word(s, 24))
        put(w, 32, 0)
        put(w, 40, word(s, 32))
        put(w, 48, word(s, 40))
        put(w, 56, word(s, 48))
        put(w, 64, word(s, 56))
        put(w, 72, word(s, 64))
    else:
        if get(w, 0) != MAGIC or get(w, 32) == TERMINAL or get(w, 32) == 991:
            return ABI
        if word(s, 8) != get(w, 8) or word(s, 16) != get(w, 16):
            return ABI
        if word(s, 24) != 0 or word(s, 64) != 0 or word(s, 72) != 0:
            return ABI
    put(w, 640, 0)
    put(w, 776, 0)
    put(w, 912, 0)
    if get(w, 32) == 990:
        return ask(w, RAISE_ERROR, word(s, 32), 0, 0, 0, 991)
    mode = get(w, 24)
    if mode == 1:
        return initialize(s, o, w)
    if mode == 2:
        return emit_state(s, o, w)
    if mode == 3:
        return label_state(s, o, w)
    if mode == 4:
        return finalize_state(s, o, w)
    if mode == 5:
        return offset_state(s, o, w)
    if mode == 6:
        return register_state(s, o, w)
    return ABI

def initialize(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    pc = get(w, 32)
    x = word(s, 32)
    if pc == 0:
        return ask(w, TYPE, get(w, 48), 0, 0, 0, 1)
    if pc == 1:
        if x != 0 and x != 6:
            return error(w, E_SCRATCH)
        put(w, 80, get(w, 48))
        put(w, 200, choose(x == 0, 1, 0))
        return ask_literal(w, 10, 2)
    if pc == 2:
        put(w, 88, x)
        return ask_literal(w, 11, 3)
    if pc == 3:
        put(w, 96, x)
        if get(w, 200) == 1:
            return ask(w, DICT_TWO, get(w, 88), get(w, 88), x, x, 4)
        return ask(w, SET_COPY, get(w, 80), 0, 0, 0, 5)
    if pc == 4:
        put(w, 80, x)
        return ask(w, SET_COPY, x, 0, 0, 0, 5)
    if pc == 5:
        put(w, 120, x)
        return ask(w, SET_PAIR, get(w, 88), get(w, 96), 0, 0, 6)
    if pc == 6:
        put(w, 104, x)
        return ask_owned(w, NOT_EQUAL, get(w, 120), x, 0, 0, 7, 1)
    if pc == 7:
        if x != 0:
            return error(w, E_SCRATCH)
        return ask_attribute(w, get(w, 80), 7, 8)
    if pc == 8:
        return ask_owned(w, CALL0, x, 0, 0, 0, 9, 1)
    if pc == 9:
        return ask_owned(w, GET_ITER, x, 0, 0, 0, 10, 1)
    if pc == 10:
        put(w, 112, x)
        return ask(w, NEXT, x, 0, 0, 0, 11)
    if pc == 11:
        if word(s, 40) == 0:
            release_before(w, get(w, 112))
            return ask_attribute(w, get(w, 80), 7, 14)
        return ask_owned(w, TYPE, x, 0, 0, 0, 12, 1)
    if pc == 12:
        if x != 3:
            return error(w, E_SCRATCH)
        return ask(w, NEXT, get(w, 112), 0, 0, 0, 11)
    if pc == 14:
        return ask_owned(w, CALL0, x, 0, 0, 0, 15, 1)
    if pc == 15:
        return ask_owned(w, SET_COPY, x, 0, 0, 0, 16, 1)
    if pc == 16:
        return ask_owned(w, NOT_EQUAL, x, get(w, 104), 0, 0, 17, 1)
    if pc == 17:
        if x != 0:
            return error(w, E_SCRATCH)
        return ask(w, TYPE, get(w, 56), 0, 0, 0, 18)
    if pc == 18:
        if x != 3:
            return error(w, E_MOVE)
        return ask_literal(w, 12, 19)
    if pc == 19:
        put(w, 120, x)
        return ask_literal(w, 13, 20)
    if pc == 20:
        return ask(w, SET_PAIR, get(w, 120), x, 0, 0, 21)
    if pc == 21:
        return ask(w, CONTAINS, x, get(w, 56), 0, 0, 22)
    if pc == 22:
        if x == 0:
            return error(w, E_MOVE)
        return ask(w, TYPE, get(w, 64), 0, 0, 0, 23)
    if pc == 23:
        if x != 3:
            return error(w, E_ALU)
        return ask_literal(w, 14, 24)
    if pc == 24:
        put(w, 120, x)
        return ask_literal(w, 15, 25)
    if pc == 25:
        return ask(w, SET_PAIR, get(w, 120), x, 0, 0, 26)
    if pc == 26:
        return ask(w, CONTAINS, x, get(w, 64), 0, 0, 27)
    if pc == 27:
        if x == 0:
            return error(w, E_ALU)
        return ask(w, DICT_COPY, get(w, 80), 0, 0, 0, 28)
    if pc == 28:
        release_after(w, x)
        return set_attribute(w, 0, x, 29)
    if pc == 29:
        return set_attribute(w, 1, get(w, 56), 30)
    if pc == 30:
        return set_attribute(w, 2, get(w, 64), 31)
    if pc == 31:
        return ask(w, BYTEARRAY_NEW, 0, 0, 0, 0, 32)
    if pc == 32:
        release_after(w, x)
        return set_attribute(w, 3, x, 33)
    if pc == 33:
        return ask(w, DICT_NEW, 0, 0, 0, 0, 34)
    if pc == 34:
        release_after(w, x)
        return set_attribute(w, 4, x, 35)
    if pc == 35:
        return ask(w, LIST_NEW, 0, 0, 0, 0, 36)
    if pc == 36:
        release_after(w, x)
        return set_attribute(w, 5, x, 37)
    if pc == 37:
        return ask(w, LIST_NEW, 0, 0, 0, 0, 38)
    if pc == 38:
        release_after(w, x)
        return set_attribute(w, 6, x, 39)
    if pc == 39:
        return done(w, o, get(w, 72))
    return ABI

def emit_state(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    pc = get(w, 32)
    x = word(s, 32)
    if pc == 0:
        return ask(w, TYPE, get(w, 48), 0, 0, 0, 1)
    if pc == 1:
        if x != 4 and x != 5:
            put(w, 208, word(s, 40))
            return ask(w, TYPE_COMPARE, get(w, 208), 4, 0, 0, 8)
        return ask(w, LEN, get(w, 48), 0, 0, 0, 2)
    if pc == 8:
        if x != 0:
            return ask(w, LEN, get(w, 48), 0, 0, 0, 2)
        return ask(w, TYPE_COMPARE, get(w, 208), 5, 0, 0, 9)
    if pc == 9:
        if x == 0:
            return error(w, E_BYTES)
        return ask(w, LEN, get(w, 48), 0, 0, 0, 2)
    if pc == 2:
        put(w, 80, word(s, 40))
        return ask_attribute(w, get(w, 40), 3, 3)
    if pc == 3:
        return ask_owned(w, LEN, x, 0, 0, 0, 4, 1)
    if pc == 4:
        size = word(s, 40)
        if size > MAX_CODE or get(w, 80) > MAX_CODE - size:
            return error(w, E_LIMIT)
        return ask_attribute(w, get(w, 40), 3, 5)
    if pc == 5:
        return attribute_owned(w, x, 9, 6)
    if pc == 6:
        return ask_discard(w, CALL1, x, get(w, 48), 0, 0, 7, 1)
    if pc == 7:
        return done(w, o, get(w, 72))
    return ABI

def label_state(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    pc = get(w, 32)
    x = word(s, 32)
    if pc == 0:
        return ask(w, TYPE, get(w, 48), 0, 0, 0, 1)
    if pc == 1:
        if x != 3:
            return error(w, E_LABEL)
        return ask(w, LEN, get(w, 48), 0, 0, 0, 2)
    if pc == 2:
        if word(s, 40) == 0 or word(s, 40) > 512:
            return error(w, E_LABEL)
        return ask_attribute(w, get(w, 40), 4, 3)
    if pc == 3:
        return ask_owned(w, CONTAINS, x, get(w, 48), 0, 0, 4, 1)
    if pc == 4:
        if x != 0:
            return error(w, E_LABEL)
        return ask_attribute(w, get(w, 40), 3, 5)
    if pc == 5:
        return ask_owned(w, LEN, x, 0, 0, 0, 6, 1)
    if pc == 6:
        put(w, 80, x)
        return ask_attribute(w, get(w, 40), 4, 7)
    if pc == 7:
        return ask_owned(w, SET_ITEM, x, get(w, 48), get(w, 80), 0, 8, 5)
    if pc == 8:
        return done(w, o, get(w, 72))
    return ABI

def offset_state(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    pc = get(w, 32)
    if pc == 0:
        return ask_attribute(w, get(w, 40), 3, 1)
    if pc == 1:
        return ask_owned(w, LEN, word(s, 32), 0, 0, 0, 2, 1)
    if pc == 2:
        return done(w, o, word(s, 32))
    return ABI

def register_state(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    pc = get(w, 32)
    x = word(s, 32)
    if pc == 0:
        return ask(w, TYPE, get(w, 48), 0, 0, 0, 1)
    if pc == 1:
        if x != 3:
            return error(w, E_REG)
        return ask_attribute(w, get(w, 40), 0, 2)
    if pc == 2:
        return attribute_owned(w, x, 8, 3)
    if pc == 3:
        return ask_owned(w, CALL2, x, get(w, 48), get(w, 48), 0, 4, 1)
    if pc == 4:
        put(w, 80, x)
        return ask(w, TYPE, x, 0, 0, 0, 5)
    if pc == 5:
        if x != 3:
            return error(w, E_REG)
        return ask(w, STR_SUMMARY, get(w, 80), 0, 0, 0, 6)
    if pc == 6:
        result = register_number(x, word(s, 40), word(s, 48), word(s, 56))
        if result == 16:
            return error(w, E_REG)
        return ask(w, NEW_INT, result, 0, 0, 0, 7)
    if pc == 7:
        return done(w, o, x)
    return ABI

def register_number(n:u64, a:u64, b:u64, c:u64) -> u64:
    if a != 114:
        return 16
    if n == 2 and (b == 56 or b == 57):
        return b - 48
    if n != 3:
        return 16
    if b == 49 and c >= 48 and c <= 53:
        return c - 38
    if c == 120:
        if b == 97:
            return 0
        if b == 99:
            return 1
        if b == 100:
            return 2
        if b == 98:
            return 3
    if c == 112:
        if b == 115:
            return 4
        if b == 98:
            return 5
    if c == 105:
        if b == 115:
            return 6
        if b == 100:
            return 7
    return 16

def finalize_state(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    pc = get(w, 32)
    x = word(s, 32)
    if pc == 0:
        return ask_attribute(w, get(w, 40), 3, 1)
    if pc == 1:
        return ask_owned(w, LEN, x, 0, 0, 0, 2, 1)
    if pc == 2:
        if word(s, 40) > MAX_CODE:
            return error(w, E_LIMIT)
        return ask_attribute(w, get(w, 40), 3, 3)
    if pc == 3:
        return ask_owned(w, BYTEARRAY_COPY, x, 0, 0, 0, 4, 1)
    if pc == 4:
        put(w, 136, x)
        return ask_attribute(w, get(w, 40), 5, 5)
    if pc == 5:
        return ask_owned(w, GET_ITER, x, 0, 0, 0, 6, 1)
    if pc == 6:
        put(w, 112, x)
        return ask(w, NEXT, x, 0, 0, 0, 7)
    if pc == 7:
        if word(s, 40) == 0:
            release_before(w, get(w, 112))
            return ask(w, BYTES_COPY, get(w, 136), 0, 0, 0, 20)
        return ask_owned(w, UNPACK_TWO, x, 0, 0, 0, 8, 1)
    if pc == 8:
        release_before(w, get(w, 144))
        release_before(w, get(w, 152))
        put(w, 144, x)
        put(w, 152, word(s, 40))
        return ask_attribute(w, get(w, 40), 4, 9)
    if pc == 9:
        return ask_owned(w, CONTAINS, x, get(w, 152), 0, 0, 10, 1)
    if pc == 10:
        if x == 0:
            return ask_literal(w, 24, 30)
        return ask_attribute(w, get(w, 40), 4, 11)
    if pc == 11:
        return ask_owned(w, GET_ITEM, x, get(w, 152), 0, 0, 12, 1)
    if pc == 12:
        put(w, 168, x)
        return ask(w, NEW_INT, 4, 0, 0, 0, 13)
    if pc == 13:
        put(w, 120, x)
        return ask(w, ADD, get(w, 144), x, 0, 0, 14)
    if pc == 14:
        return ask_owned(w, SUB, get(w, 168), x, 0, 0, 15, 3)
    if pc == 15:
        put(w, 168, x)
        return ask(w, TYPE, x, 0, 0, 0, 16)
    if pc == 16:
        if x != 2:
            return error(w, E_DISP)
        return ask(w, INT_SUMMARY, get(w, 168), 0, 0, 0, 17)
    if pc == 17:
        if word(s, 40) == 0:
            if word(s, 48) > 31:
                return error(w, E_DISP)
        else:
            if word(s, 48) > 31 and (word(s, 48) != 32 or x != 18446744071562067968):
                return error(w, E_DISP)
        return ask_owned(w, ENCODE_REL32, get(w, 168), 0, 0, 0, 18, 1)
    if pc == 18:
        put(w, 168, x)
        return ask(w, ADD, get(w, 144), get(w, 120), 0, 0, 19)
    if pc == 19:
        return ask_owned(w, SET_SLICE, get(w, 136), get(w, 144), x, get(w, 168), 24, 12)
    if pc == 24:
        return ask(w, NEXT, get(w, 112), 0, 0, 0, 7)
    if pc == 20:
        put(w, 184, x)
        return ask_attribute(w, get(w, 40), 6, 21)
    if pc == 21:
        return ask_owned(w, GET_ITER, x, 0, 0, 0, 22, 1)
    if pc == 22:
        put(w, 112, x)
        return ask(w, LIST_NEW, 0, 0, 0, 0, 23)
    if pc == 23:
        put(w, 192, x)
        return ask(w, NEXT, get(w, 112), 0, 0, 0, 25)
    if pc == 25:
        if word(s, 40) == 0:
            release_before(w, get(w, 112))
            release_before(w, get(w, 200))
            return ask(w, TUPLE_TWO, get(w, 184), get(w, 192), 0, 0, 28)
        release_before(w, get(w, 200))
        put(w, 200, x)
        return ask(w, DICT_COPY, x, 0, 0, 0, 26)
    if pc == 26:
        return ask_owned(w, LIST_APPEND, get(w, 192), x, 0, 0, 27, 2)
    if pc == 27:
        return ask(w, NEXT, get(w, 112), 0, 0, 0, 25)
    if pc == 28:
        release_before(w, get(w, 136))
        release_before(w, get(w, 144))
        release_before(w, get(w, 152))
        return done(w, o, x)
    if pc == 30:
        return ask_owned(w, ADD, x, get(w, 152), 0, 0, 31, 1)
    if pc == 31:
        return ask(w, RAISE_ERROR, x, 0, 0, 0, 32)
    return ABI

def ask(w:mutbuf, opcode:u64, a:u64, b:u64, c:u64, d:u64, pc:u64) -> u32:
    put(w, 8, opcode)
    put(w, 16, get(w, 16) + 1)
    put(w, 32, pc)
    put(w, 512, a)
    put(w, 520, b)
    put(w, 528, c)
    put(w, 536, d)
    return 1

def ask_literal(w:mutbuf, which:u64, pc:u64) -> u32:
    n = literal(w, which)
    return ask(w, CONST, 1024, n, 0, 0, pc)

def ask_attribute(w:mutbuf, object:u64, which:u64, pc:u64) -> u32:
    n = literal(w, which)
    return ask(w, GETATTR, object, 1024, n, 0, pc)

def set_attribute(w:mutbuf, which:u64, value:u64, pc:u64) -> u32:
    n = literal(w, which)
    return ask(w, SETATTR, get(w, 40), value, 1024, n, pc)

def error(w:mutbuf, which:u64) -> u32:
    return ask_literal(w, which, 990)

def done(w:mutbuf, o:mutbuf, value:u64) -> u32:
    put(w, 32, TERMINAL)
    put(o, 0, value)
    return 0


def release_before(w:mutbuf, handle:u64) -> u64:
    if handle != 0 and handle != get(w, 72):
        count = get(w, 640)
        if count < 16:
            put(w, 648 + count * 8, handle)
        put(w, 640, count + 1)
    return 0

def release_after(w:mutbuf, handle:u64) -> u64:
    if handle != 0 and handle != get(w, 72):
        count = get(w, 776)
        if count < 16:
            put(w, 784 + count * 8, handle)
        put(w, 776, count + 1)
    return 0

def ask_owned(w:mutbuf, opcode:u64, a:u64, b:u64, c:u64, d:u64, pc:u64, mask:u64) -> u32:
    if mask & 1 != 0:
        release_after(w, a)
    if mask & 2 != 0:
        release_after(w, b)
    if mask & 4 != 0:
        release_after(w, c)
    if mask & 8 != 0:
        release_after(w, d)
    return ask(w, opcode, a, b, c, d, pc)

def ask_discard(w:mutbuf, opcode:u64, a:u64, b:u64, c:u64, d:u64, pc:u64, mask:u64) -> u32:
    put(w, 912, 1)
    return ask_owned(w, opcode, a, b, c, d, pc, mask)

def attribute_owned(w:mutbuf, object:u64, which:u64, pc:u64) -> u32:
    n = literal(w, which)
    return ask_owned(w, GETATTR, object, 1024, n, 0, pc, 1)

def word(s:readbuf, at:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(s, at + i) << (i * 8))
        i = i + 1
    return value

def get(w:mutbuf, at:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(w, at + i) << (i * 8))
        i = i + 1
    return value

def put(w:mutbuf, at:u64, value:u64) -> u64:
    i = 0
    while i < 8:
        store(w, at + i, (value >> (i * 8)) & 255)
        i = i + 1
    return 0
'''


def literal_functions():
    lines = ['def literal(w:mutbuf, which:u64) -> u64:']
    for group in range((len(LITERALS) + 3) // 4):
        lines.extend([f'    if which < {(group + 1) * 4}:',
                      f'        return literal_{group}(w, which)'])
    lines.append('    return 0')
    for group in range((len(LITERALS) + 3) // 4):
        lines.extend(['', f'def literal_{group}(w:mutbuf, which:u64) -> u64:'])
        for index in range(group * 4, min((group + 1) * 4, len(LITERALS))):
            raw = LITERALS[index].encode('utf-8')
            lines.append(f'    if which == {index}:')
            lines.extend(f'        store(w, {1024 + i}, {value})' for i, value in enumerate(raw))
            lines.append(f'        return {len(raw)}')
        lines.append('    return 0')
    return '\n'.join(lines) + '\n'


def source_program():
    class Expand(ast.NodeTransformer):
        def visit_Name(self, node):
            if node.id in CONSTANTS:
                return ast.copy_location(ast.Constant(CONSTANTS[node.id]), node)
            return node
    module = ast.parse(SOURCE + '\n' + literal_functions() + '\n' + EXCEPTION_DELIVERY_BODY)
    return ast.unparse(ast.fix_missing_locations(Expand().visit(module))) + '\n'


def document():
    nodes = ast.parse(source_program()).body
    names = {node.name: 'f' + str(i) for i, node in enumerate(nodes)}
    signatures = {node.name: ([a.annotation.id for a in node.args.args], node.returns.id) for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = Builder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(v) for v in builder.params],
                          'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
                          'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8',
                                  'module': 'machine_state', 'functions': functions})


if __name__ == '__main__':
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / 'examples/hia_bootstrap/machine_state.hiaasm'
    path.write_text(render_assembly(document()))
    print(path.name, path.stat().st_size)
