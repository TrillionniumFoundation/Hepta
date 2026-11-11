"""Author the artifact-page continuation, byte policy and cursor digest in HIA.

This development-time generator does not execute the product policy. The
adapter transports requested Store/SQL/object effects; HIA owns their order,
cursor binding, whole-artifact UTF-8 classification, page boundaries, encoding,
the double-wire budget, and cursor issuance. The admitted wire owner remains a
separate HIA executable. Store persistence itself is an explicit foreign seam.
"""
from __future__ import annotations

import ast
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
from tools.generate_hia_sha256 import source_program as sha_source
from tools.generate_hia_worker_request import renamed, replace_once

SOURCE_PATH = 'examples/hia_bootstrap/artifact_page.hiaasm'
MAGIC = int.from_bytes(b'HIAAPG01', 'little')
HIGH = 1 << 63
LITERALS = {
    'ARTIFACT': 'artifact', 'CURSOR': 'cursor', 'MAX_BYTES': 'max_bytes',
    'ID': 'id', 'SHA': 'sha256', 'ARTIFACT_ID': 'artifact_id', 'OFFSET': 'offset',
    'UTF8': 'utf8', 'BASE64': 'base64', 'ENCODING': 'encoding',
    'CONTENT': 'content', 'NEXT_CURSOR': 'next_cursor',
    'CURSOR_CODE': 'E_HIA_CURSOR', 'CURSOR_MESSAGE': 'cursor is not bound to this exact artifact',
}
HANDLES = {name: HIGH + n for n, name in enumerate(LITERALS, 1)}
HANDLES.update({name: HIGH + len(LITERALS) + n for n, name in enumerate(
    ('ZERO', 'CONTENT_NODE', 'NEXT_OFFSET_NODE', 'CURSOR_NODE', 'SEED_NODE', 'RESULT_NODE', 'NONE_NODE'), 1)})
FIELDS = {
    'MAGIC': MAGIC, 'HIGH': HIGH, 'AWAIT': 8, 'SEQ': 16, 'PHASE': 24,
    'ARGS': 32, 'REF': 40, 'DATA': 48, 'ROW': 56, 'OFFSET_HANDLE': 64,
    'OFFSET_MAG': 72, 'OFFSET_SIGN': 80, 'LIMIT': 88, 'DATA_SIZE': 96,
    'PAGE_START': 104, 'PAGE_SIZE': 112, 'BINARY': 120, 'STREAM': 128,
    'UTF8_NEED': 136, 'UTF8_LOW': 144, 'UTF8_HIGH': 152,
    'CONTENT_BYTES': 160, 'CONTENT_POINTS': 168, 'FIRST_WIRE': 176,
    'NEXT_MAG': 184, 'NEXT_SIGN': 192,
    'REQ_A': 200, 'REQ_B': 208, 'REQ_C': 216, 'REQ_D': 224,
    'LEFT': 232, 'RIGHT': 240, 'EQ_SIZE': 248, 'EQ_AT': 256,
    'EQ_COUNT': 264, 'EQ_NEXT': 272, 'EQ_RESULT': 280, 'EPOCH': 288,
    'REF_ID': 296, 'REF_SHA': 304, 'HAS_NEXT': 312,
    'NODE_BASE': 4096, 'TEXT_BASE': 8192, 'PAIR_BASE': 12288,
    'EQ_A': 16384, 'EQ_B': 20480, 'PAGE_BASE': 32768,
    'CURSOR_OUTPUT': 98304,
}
FIELDS.update({'L_' + k: v for k, v in HANDLES.items()})

SOURCE = r'''
def artifact_page(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) != 131072 or length(o) != 131072:
        return 199
    if get(w, 0) == 0:
        if length(s) != 32 or read64(s, 0) != MAGIC or read64(s, 8) != 0 or read64(s, 16) != 0 or read64(s, 24) == 0:
            return 199
        put(w, 0, MAGIC)
        put(w, ARGS, read64(s, 24))
        put(w, OFFSET_HANDLE, L_ZERO)
        constants(w)
        put(w, PHASE, 1)
    else:
        if get(w, 0) != MAGIC or get(w, AWAIT) == 0 or length(s) < 64:
            return 199
        opcode = get(w, AWAIT)
        if read64(s, 0) != MAGIC or read64(s, 8) != get(w, SEQ) or read64(s, 16) != opcode or read64(s, 56) != 0:
            return 199
        extent = 64
        if opcode == 8 or opcode == 15:
            if read64(s, 24) != get(w, REQ_C) or read64(s, 24) > 1024:
                return 199
            extent = extent + read64(s, 24) * 4
        elif opcode == 10:
            if read64(s, 24) != get(w, REQ_C) or read64(s, 24) > 65536:
                return 199
            extent = extent + read64(s, 24)
        elif opcode == 14:
            if read64(s, 24) > 8388608:
                return 199
            extent = extent + read64(s, 24)
        if length(s) != extent:
            return 199
        put(w, AWAIT, 0)
    while True:
        phase = get(w, PHASE)
        result = 199
        if phase < 40:
            result = control(s, o, w, phase)
        elif phase >= 100 and phase < 110:
            result = equality(s, w, phase)
        if result != 0:
            if result != 1:
                put(w, PHASE, 4294967295)
            return result
    return 199

def ask(w:mutbuf, opcode:u64, a:u64, b:u64, c:u64, d:u64, next:u64) -> u64:
    put(w, AWAIT, opcode)
    put(w, SEQ, get(w, SEQ) + 1)
    put(w, REQ_A, a)
    put(w, REQ_B, b)
    put(w, REQ_C, c)
    put(w, REQ_D, d)
    put(w, PHASE, next)
    return 1

def control(s:readbuf, o:mutbuf, w:mutbuf, phase:u64) -> u64:
    if phase == 1:
        return ask(w, 1, get(w, ARGS), L_ARTIFACT, 0, 0, 2)
    if phase == 2:
        put(w, REF, read64(s, 24))
        return ask(w, 2, read64(s, 24), 0, 0, 0, 3)
    if phase == 3:
        put(w, DATA, read64(s, 24))
        return ask(w, 3, get(w, ARGS), L_CURSOR, 0, 0, 4)
    if phase == 4:
        if read64(s, 24) > 1:
            return 199
        if read64(s, 24) == 0:
            return ask(w, 5, get(w, ARGS), L_MAX_BYTES, 65536, 0, 20)
        return ask(w, 1, get(w, ARGS), L_CURSOR, 0, 0, 5)
    if phase == 5:
        return ask(w, 4, read64(s, 24), 0, 0, 0, 6)
    if phase == 6:
        put(w, ROW, read64(s, 24))
        return ask(w, 7, read64(s, 24), 0, 0, 0, 7)
    if phase == 7:
        if read64(s, 24) == 0:
            return 100
        return ask(w, 1, get(w, ROW), L_ARTIFACT_ID, 0, 0, 8)
    if phase == 8:
        put(w, LEFT, read64(s, 24))
        return ask(w, 1, get(w, REF), L_ID, 0, 0, 9)
    if phase == 9:
        return equal_begin(w, read64(s, 24), 10)
    if phase == 10:
        if get(w, EQ_RESULT) == 0:
            return 100
        return ask(w, 1, get(w, ROW), L_SHA, 0, 0, 11)
    if phase == 11:
        put(w, LEFT, read64(s, 24))
        return ask(w, 1, get(w, REF), L_SHA, 0, 0, 12)
    if phase == 12:
        return equal_begin(w, read64(s, 24), 13)
    if phase == 13:
        if get(w, EQ_RESULT) == 0:
            return 100
        return ask(w, 1, get(w, ROW), L_OFFSET, 0, 0, 14)
    if phase == 14:
        put(w, OFFSET_HANDLE, read64(s, 24))
        return ask(w, 5, get(w, ARGS), L_MAX_BYTES, 65536, 0, 20)
    if phase == 20:
        return ask(w, 6, read64(s, 24), 0, 0, 0, 21)
    if phase == 21:
        put(w, RIGHT, read64(s, 24))
        return ask(w, 7, read64(s, 24), 0, 0, 0, 22)
    if phase == 22:
        if read64(s, 24) != 2 or read64(s, 40) != 0 or read64(s, 32) > 17:
            return 101
        return ask(w, 15, get(w, RIGHT), 0, choose(read64(s, 32) == 0, 0, 1), 0, 23)
    if phase == 23:
        limit = 0
        if read64(s, 24) != 0:
            limit = read32(s, 64)
        if limit > 65536:
            return 101
        put(w, LIMIT, limit)
        return ask(w, 7, get(w, OFFSET_HANDLE), 0, 0, 0, 24)
    if phase == 24:
        if read64(s, 24) != 2 or read64(s, 32) > 64 or read64(s, 40) > 1:
            return 102
        put(w, OFFSET_SIGN, read64(s, 40))
        return ask(w, 15, get(w, OFFSET_HANDLE), 0, (read64(s, 32) + 31) >> 5, 0, 25)
    if phase == 25:
        magnitude = 0
        if read64(s, 24) > 0:
            magnitude = read32(s, 64)
        if read64(s, 24) > 1:
            magnitude = magnitude | (read32(s, 68) << 32)
        if magnitude > 9223372036854775808 or (get(w, OFFSET_SIGN) == 0 and magnitude > 9223372036854775807):
            return 102
        put(w, OFFSET_MAG, magnitude)
        return ask(w, 7, get(w, DATA), 0, 0, 0, 26)
    if phase == 26:
        if read64(s, 24) != 9 or read64(s, 32) > 67108864:
            return 103
        put(w, DATA_SIZE, read64(s, 32))
        page_slice(w)
        put(w, STREAM, 0)
        put(w, UTF8_LOW, 128)
        put(w, UTF8_HIGH, 191)
        return next_bytes(w)
    if phase == 27:
        count = read64(s, 24)
        at = 0
        start = get(w, STREAM)
        left = get(w, PAGE_START)
        right = left + get(w, PAGE_SIZE)
        while at < count:
            value = byte(s, 64 + at)
            position = start + at
            if position >= left and position < right:
                store(w, PAGE_BASE + position - left, value)
            if get(w, BINARY) == 0:
                utf8_byte(w, value)
            at = at + 1
        put(w, STREAM, start + count)
        return next_bytes(w)
    if phase == 30:
        make_content(o, w)
        return ask(w, 11, L_CONTENT_NODE, 0, 0, 0, 31)
    if phase == 31:
        if read64(s, 32) > 8388608:
            return 199
        put(w, FIRST_WIRE, read64(s, 32))
        return ask(w, 11, L_CONTENT_NODE, 0, 0, 0, 32)
    if phase == 32:
        return ask(w, 12, read64(s, 24), 0, 0, 0, 33)
    if phase == 33:
        return ask(w, 11, read64(s, 24), 0, 0, 0, 34)
    if phase == 34:
        if read64(s, 32) > 8388608:
            return 199
        if get(w, FIRST_WIRE) + read64(s, 32) > 230000:
            count = get(w, PAGE_SIZE) >> 1
            put(w, PAGE_SIZE, choose(count == 0, 1, count))
            put(w, PHASE, 30)
            return 0
        next_offset(w)
        if get(w, HAS_NEXT) == 0:
            return done(w)
        seed(w)
        return ask(w, 14, L_SEED_NODE, 0, 0, 0, 35)
    if phase == 35:
        if widen(hash_sha256(s, w, read64(s, 24))) != 32:
            return 199
        store(o, CURSOR_OUTPUT, 112)
        store(o, CURSOR_OUTPUT + 1, 97)
        store(o, CURSOR_OUTPUT + 2, 103)
        store(o, CURSOR_OUTPUT + 3, 101)
        store(o, CURSOR_OUTPUT + 4, 45)
        at = 0
        while at < 32:
            value = byte(w, length(w) - 4096 + 1088 + at)
            store(o, CURSOR_OUTPUT + 5 + at * 2, hex(value >> 4))
            store(o, CURSOR_OUTPUT + 6 + at * 2, hex(value & 15))
            at = at + 1
        node(w, L_CURSOR_NODE, 4, 69, 1, CURSOR_OUTPUT, 69, 0)
        return ask(w, 1, get(w, REF), L_ID, 0, 0, 36)
    if phase == 36:
        put(w, REF_ID, read64(s, 24))
        return ask(w, 1, get(w, REF), L_SHA, 0, 0, 37)
    if phase == 37:
        put(w, REF_SHA, read64(s, 24))
        return ask(w, 13, L_CURSOR_NODE, get(w, REF_ID), read64(s, 24), L_NEXT_OFFSET_NODE, 38)
    if phase == 38:
        return done(w)
    return 199

def page_slice(w:mutbuf) -> u64:
    size = get(w, DATA_SIZE)
    offset = get(w, OFFSET_MAG)
    limit = get(w, LIMIT)
    first = 0
    last = 0
    if get(w, OFFSET_SIGN) == 0:
        first = choose(offset < size, offset, size)
        end = offset + limit
        last = choose(end < size, end, size)
    else:
        if offset < size:
            first = size - offset
        if limit >= offset:
            end = limit - offset
            last = choose(end < size, end, size)
        else:
            end = offset - limit
            if end < size:
                last = size - end
    put(w, PAGE_START, first)
    put(w, PAGE_SIZE, choose(last > first, last - first, 0))
    return 0

def next_bytes(w:mutbuf) -> u64:
    count = get(w, DATA_SIZE) - get(w, STREAM)
    if count != 0:
        return ask(w, 10, get(w, DATA), get(w, STREAM), choose(count < 65536, count, 65536), 0, 27)
    if get(w, UTF8_NEED) != 0:
        put(w, BINARY, 1)
    put(w, PHASE, 30)
    return 0

def utf8_byte(w:mutbuf, value:u64) -> u64:
    need = get(w, UTF8_NEED)
    if need != 0:
        if value < get(w, UTF8_LOW) or value > get(w, UTF8_HIGH):
            put(w, BINARY, 1)
        else:
            put(w, UTF8_NEED, need - 1)
            put(w, UTF8_LOW, 128)
            put(w, UTF8_HIGH, 191)
        return 0
    if value < 128:
        return 0
    if value >= 194 and value <= 223:
        put(w, UTF8_NEED, 1)
    elif value >= 224 and value <= 239:
        put(w, UTF8_NEED, 2)
        if value == 224:
            put(w, UTF8_LOW, 160)
        if value == 237:
            put(w, UTF8_HIGH, 159)
    elif value >= 240 and value <= 244:
        put(w, UTF8_NEED, 3)
        if value == 240:
            put(w, UTF8_LOW, 144)
        if value == 244:
            put(w, UTF8_HIGH, 143)
    else:
        put(w, BINARY, 1)
    return 0

def make_content(o:mutbuf, w:mutbuf) -> u64:
    size = get(w, PAGE_SIZE)
    points = 0
    at = 0
    count = 0
    if get(w, BINARY) == 0:
        last = 0
        need = 0
        invalid = False
        while at < size and invalid == False:
            value = byte(w, PAGE_BASE + at)
            if need == 0:
                if value < 128:
                    last = at + 1
                    points = points + 1
                elif value >= 194 and value <= 244:
                    need = choose(value < 224, 1, choose(value < 240, 2, 3))
                else:
                    invalid = True
            else:
                if value < 128 or value > 191:
                    invalid = True
                need = need - 1
                if need == 0:
                    last = at + 1
                    points = points + 1
            at = at + 1
        if invalid:
            last = 0
            points = 0
        size = last
        put(w, PAGE_SIZE, size)
        at = 0
        while at < size:
            store(o, at, byte(w, PAGE_BASE + at))
            at = at + 1
        count = size
    else:
        while at < size:
            a = byte(w, PAGE_BASE + at)
            b = 0
            c = 0
            if at + 1 < size:
                b = byte(w, PAGE_BASE + at + 1)
            if at + 2 < size:
                c = byte(w, PAGE_BASE + at + 2)
            store(o, count, base64(a >> 2))
            store(o, count + 1, base64(((a & 3) << 4) | (b >> 4)))
            store(o, count + 2, choose(at + 1 < size, base64(((b & 15) << 2) | (c >> 6)), 61))
            store(o, count + 3, choose(at + 2 < size, base64(c & 63), 61))
            at = at + 3
            count = count + 4
        points = count
    put(w, CONTENT_BYTES, count)
    put(w, CONTENT_POINTS, points)
    put(w, EPOCH, get(w, EPOCH) + 1)
    node(w, L_CONTENT_NODE, 4, points, 1, 0, count, 0)
    return 0

def next_offset(w:mutbuf) -> u64:
    offset = get(w, OFFSET_MAG)
    count = get(w, PAGE_SIZE)
    sign = get(w, OFFSET_SIGN)
    value = 0
    if sign == 0:
        value = offset + count
    elif count >= offset:
        value = count - offset
        sign = 0
    else:
        value = offset - count
    put(w, NEXT_MAG, value)
    put(w, NEXT_SIGN, sign)
    more = sign != 0 or value < get(w, DATA_SIZE)
    put(w, HAS_NEXT, choose(more, 1, 0))
    return 0

def seed(w:mutbuf) -> u64:
    value = get(w, NEXT_MAG)
    bits = 0
    while value != 0:
        value = value >> 1
        bits = bits + 1
    node(w, L_NEXT_OFFSET_NODE, 2, bits, 0, get(w, NEXT_SIGN), get(w, NEXT_MAG), 0)
    pair(w, PAIR_BASE, L_ARTIFACT, get(w, REF))
    pair(w, PAIR_BASE + 16, L_OFFSET, L_NEXT_OFFSET_NODE)
    node(w, L_SEED_NODE, 7, 2, 0, PAIR_BASE, 0, 0)
    return 0

def done(w:mutbuf) -> u64:
    pair(w, PAIR_BASE + 64, L_ARTIFACT, get(w, REF))
    pair(w, PAIR_BASE + 80, L_ENCODING, choose(get(w, BINARY) == 0, L_UTF8, L_BASE64))
    pair(w, PAIR_BASE + 96, L_CONTENT, L_CONTENT_NODE)
    pair(w, PAIR_BASE + 112, L_NEXT_CURSOR, choose(get(w, HAS_NEXT) == 0, L_NONE_NODE, L_CURSOR_NODE))
    node(w, L_RESULT_NODE, 7, 4, 0, PAIR_BASE + 64, 0, 0)
    return 2

def equal_begin(w:mutbuf, right:u64, next:u64) -> u64:
    put(w, RIGHT, right)
    put(w, EQ_NEXT, next)
    return ask(w, 7, get(w, LEFT), 0, 0, 0, 100)

def equal_done(w:mutbuf, result:u64) -> u64:
    put(w, EQ_RESULT, result)
    put(w, PHASE, get(w, EQ_NEXT))
    return 0

def equality(s:readbuf, w:mutbuf, phase:u64) -> u64:
    if phase == 100:
        if read64(s, 24) != 4:
            return ask(w, 9, get(w, LEFT), get(w, RIGHT), 0, 0, 108)
        put(w, EQ_SIZE, read64(s, 32))
        return ask(w, 7, get(w, RIGHT), 0, 0, 0, 101)
    if phase == 101:
        if read64(s, 24) != 4:
            return ask(w, 9, get(w, LEFT), get(w, RIGHT), 0, 0, 108)
        if read64(s, 32) != get(w, EQ_SIZE):
            return equal_done(w, 0)
        put(w, EQ_AT, 0)
        put(w, PHASE, 102)
        return 0
    if phase == 102:
        size = get(w, EQ_SIZE) - get(w, EQ_AT)
        if size == 0:
            return equal_done(w, 1)
        size = choose(size < 1024, size, 1024)
        put(w, EQ_COUNT, size)
        return ask(w, 8, get(w, LEFT), get(w, EQ_AT), size, 0, 103)
    if phase == 103:
        at = 0
        while at < get(w, EQ_COUNT):
            put32(w, EQ_A + at * 4, read32(s, 64 + at * 4))
            at = at + 1
        return ask(w, 8, get(w, RIGHT), get(w, EQ_AT), get(w, EQ_COUNT), 0, 104)
    if phase == 104:
        at = 0
        while at < get(w, EQ_COUNT):
            if get32(w, EQ_A + at * 4) != read32(s, 64 + at * 4):
                return equal_done(w, 0)
            at = at + 1
        put(w, EQ_AT, get(w, EQ_AT) + at)
        put(w, PHASE, 102)
        return 0
    if phase == 108:
        if read64(s, 24) > 1:
            return 199
        return equal_done(w, 1 - read64(s, 24))
    return 199

def node(w:mutbuf, handle:u64, kind:u64, size:u64, subtype:u64, a:u64, b:u64, c:u64) -> u64:
    at = NODE_BASE + (handle - HIGH) * 48
    put(w, at, kind)
    put(w, at + 8, size)
    put(w, at + 16, subtype)
    put(w, at + 24, a)
    put(w, at + 32, b)
    put(w, at + 40, c)
    return 0

def pair(w:mutbuf, at:u64, key:u64, value:u64) -> u64:
    put(w, at, key)
    put(w, at + 8, value)
    return 0

def base64(value:u64) -> u64:
    if value < 26:
        return value + 65
    if value < 52:
        return value + 71
    if value < 62:
        return value - 4
    return choose(value == 62, 43, 47)

def hex(value:u64) -> u64:
    return choose(value < 10, value + 48, value + 87)

def read64(s:readbuf, at:u64) -> u64:
    value = 0
    index = 0
    while index < 8:
        value = value | (byte(s, at + index) << (index * 8))
        index = index + 1
    return value

def read32(s:readbuf, at:u64) -> u64:
    value = 0
    index = 0
    while index < 4:
        value = value | (byte(s, at + index) << (index * 8))
        index = index + 1
    return value

def get(w:mutbuf, at:u64) -> u64:
    value = 0
    index = 0
    while index < 8:
        value = value | (byte(w, at + index) << (index * 8))
        index = index + 1
    return value

def get32(w:mutbuf, at:u64) -> u64:
    value = 0
    index = 0
    while index < 4:
        value = value | (byte(w, at + index) << (index * 8))
        index = index + 1
    return value

def put(w:mutbuf, at:u64, value:u64) -> u64:
    index = 0
    while index < 8:
        store(w, at + index, value & 255)
        value = value >> 8
        index = index + 1
    return 0

def put32(w:mutbuf, at:u64, value:u64) -> u64:
    index = 0
    while index < 4:
        store(w, at + index, value & 255)
        value = value >> 8
        index = index + 1
    return 0

def widen(value:u32) -> u64:
    return value
'''


def constant_program():
    lines = ['def constants(w:mutbuf) -> u64:']
    offset = FIELDS['TEXT_BASE']
    for name, text in LITERALS.items():
        lines.append(f'    node(w, {HANDLES[name]}, 4, {len(text)}, 0, {offset}, 0, 0)')
        for point in map(ord, text):
            lines.append(f'    put32(w, {offset}, {point})')
            offset += 4
    if offset >= FIELDS['PAIR_BASE']:
        raise ValueError('artifact-page literal extent crossed its private boundary')
    lines.append(f'    node(w, {HANDLES["ZERO"]}, 2, 0, 0, 0, 0, 0)')
    lines.append(f'    node(w, {HANDLES["NONE_NODE"]}, 0, 0, 0, 0, 0, 0)')
    return '\n'.join(lines + ['    return 0', ''])


def hash_program():
    source = sha_source()
    source = replace_once(source, 'def sha256(s:readbuf, o:mutbuf, w:mutbuf) -> u32:',
                          'def sha256(s:readbuf, w:mutbuf, n:u64) -> u32:')
    source = replace_once(source, ' or length(o) < 32', '')
    source = source.replace('length(s)', 'n')
    source = replace_once(source, 'padded_byte(s, block + i * 4 + j, padded)',
                          'padded_byte(s, block + i * 4 + j, padded, n)')
    source = replace_once(source, 'def padded_byte(s:readbuf, index:u64, total:u64)',
                          'def padded_byte(s:readbuf, index:u64, total:u64, n:u64)')
    source = replace_once(source, 'return byte(s, index)', 'return byte(s, 64 + index)')
    source = replace_once(source, 'store(o, i * 4 + j,', 'store(w, 1088 + i * 4 + j,')
    return renamed(source, 'hash_', scratch=4096)


def source_program():
    class Constants(ast.NodeTransformer):
        def visit_Name(self, node):
            return ast.copy_location(ast.Constant(FIELDS[node.id]), node) if node.id in FIELDS else node
    tree = Constants().visit(ast.parse(SOURCE + constant_program()))
    return ast.unparse(ast.fix_missing_locations(tree)) + '\n' + hash_program()


def document():
    nodes = ast.parse(source_program()).body
    names = {node.name: 'f' + str(i) for i, node in enumerate(nodes)}
    signatures = {n.name: ([arg.annotation.id for arg in n.args.args], n.returns.id) for n in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node_ in nodes:
        builder = Builder(node_, names, signatures, total)
        builder.statements(node_.body)
        functions.append({'name': names[node_.name], 'params': [builder.param(v) for v in builder.params],
                          'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
                          'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8', 'module': 'artifact_page', 'functions': functions})


if __name__ == '__main__':
    path = Path(__file__).resolve().parents[1] / SOURCE_PATH
    path.write_text(render_assembly(document()))
    print(path.name, path.stat().st_size)
