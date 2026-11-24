"""Author the HIA decoder and exact serializer of the retained root Jobctl Record.

The original Record permits unknown fields, rejects duplicate known fields, and
has a full unsigned 128-bit timestamp.  Retained identity strings are copied out
of the shared JSON arena before a subsequent file can reuse that arena.
"""
from __future__ import annotations

import argparse
import ast
import re
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_system_jobctl_request import document, POLICY as REQUEST_POLICY
from tools.generate_hia_json_preflight import SOURCE as PREFLIGHT_SOURCE
from tools.generate_hia_json_decode import _WIRE_NUMBER_SOURCE

ROOT = Path(__file__).resolve().parents[1]
FIELDS = ('job_id', 'unit', 'request_digest', 'boot_id', 'nonce', 'invocation_id',
          'launch_state', 'created_unix_ms', 'terminal_protocol')
CONSTANTS = dict(STATE_BYTES=128 << 20, ARENA=4 << 20, ARENA_BYTES=64 << 20,
                 ARENA_MAGIC=5208772604367785521, NONE=(1 << 64)-1,
                 RECORD_TABLE=41088, RECORD_FIELDS=41216, RECORD_PROTOCOL=41376,
                 RECORD_MODE=41384, RECORD_SIZE=41392, RECORD_DATA=118 << 20,
                 RECORD_OUT=120 << 20, RECORD_CAP=2 << 20, QUOTE_END=124 << 20,
                 SCAN_NEXT=41408, SCAN_SIZE=41416, KEY=45056, STACK=68 << 20)

POLICY = r'''
def record(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) != STATE_BYTES or length(o) != 128:
        return 0
    mode = get(w, RECORD_MODE)
    if mode == 0:
        if length(s) > 1048577:
            return 0
        if decode_record(s, w) == 0:
            return 0
    elif mode != 1:
        return 0
    at = render_record(w, RECORD_OUT)
    if at == NONE or at > RECORD_OUT + RECORD_CAP:
        return 0
    put(w, RECORD_SIZE, at - RECORD_OUT)
    return 1

def decode_record(s:readbuf, w:mutbuf) -> u64:
    index = 0
    while index < 9:
        put(w, RECORD_FIELDS + index * 16, NONE)
        put(w, RECORD_FIELDS + index * 16 + 8, 0)
        index = index + 1
    put(w, RECORD_PROTOCOL, 0)
    cursor = whitespace(s, 0)
    if cursor == length(s):
        return 0
    shape = byte(s, cursor)
    if shape != 123 and shape != 91:
        return 0
    closing = choose(shape == 123, 125, 93)
    cursor = whitespace(s, cursor + 1)
    if cursor == length(s) or byte(s, cursor) == closing:
        return 0
    mask = 0
    at = RECORD_DATA
    going = True
    ordinal = 0
    while going:
        ordinal = ordinal + 1
        if shape == 91:
            if ordinal > 9:
                return 0
            field = ordinal
        else:
            if cursor == length(s) or byte(s, cursor) != 34:
                return 0
            field = read_key(s, w, cursor)
            if field == NONE:
                return 0
            cursor = whitespace(s, get(w, SCAN_NEXT))
            if cursor == length(s) or byte(s, cursor) != 58:
                return 0
            cursor = whitespace(s, cursor + 1)
        if cursor == length(s):
            return 0
        if field == 0:
            cursor = skip_value(s, w, cursor)
            if cursor == NONE:
                return 0
        else:
            if mask & (1 << (field - 1)) != 0:
                return 0
            mask = mask | (1 << (field - 1))
            index = field - 1
            if (index == 5 or index == 8) and cursor + 4 <= length(s) and word_null(s, cursor) == 1:
                cursor = cursor + 4
            elif index == 7:
                end = atom(s, cursor)
                if end == 4294967295 or unsigned128(s, cursor, end - cursor) == 0:
                    return 0
                size = end - cursor
                put(w, RECORD_FIELDS + index * 16, at)
                put(w, RECORD_FIELDS + index * 16 + 8, size)
                input_copy(s, w, at, cursor, size)
                at = at + size
                cursor = end
            else:
                if index == 8 and byte(s, cursor) == 123:
                    if read_protocol(s, w, cursor, at) == 0:
                        return 0
                elif byte(s, cursor) != 34 or read_text(s, w, cursor, at) == 0:
                    return 0
                size = get(w, SCAN_SIZE)
                cursor = get(w, SCAN_NEXT)
                if index == 8:
                    protocol = protocol_id(w, at, size)
                    if protocol == 0:
                        return 0
                    put(w, RECORD_PROTOCOL, protocol)
                put(w, RECORD_FIELDS + index * 16, at)
                put(w, RECORD_FIELDS + index * 16 + 8, size)
                at = at + size
        cursor = whitespace(s, cursor)
        if cursor == length(s):
            return 0
        point = byte(s, cursor)
        if point == closing:
            going = False
        elif point != 44:
            return 0
        cursor = whitespace(s, cursor + 1)
    if cursor != length(s) or mask & 223 != 223:
        return 0
    return 1

def word_null(s:readbuf, at:u64) -> u64:
    return choose(byte(s, at) == 110 and byte(s, at + 1) == 117 and byte(s, at + 2) == 108 and byte(s, at + 3) == 108, 1, 0)

def read_key(s:readbuf, w:mutbuf, index:u64) -> u64:
    index = index + 1
    count = 0
    ascii = 1
    while True:
        unit = decoded(s, index)
        point = unit & 4294967295
        if point == 1114113:
            return NONE
        index = unit >> 32
        if point == 1114112:
            put(w, SCAN_NEXT, index)
            if ascii == 0 or count > 64:
                return 0
            return field_id(w, KEY, count)
        if point > 127:
            ascii = 0
        if count < 64:
            store(w, KEY + count, point & 255)
        count = count + 1
    return NONE

def read_text(s:readbuf, w:mutbuf, index:u64, at:u64) -> u64:
    index = index + 1
    start = at
    while True:
        unit = decoded(s, index)
        point = unit & 4294967295
        if point == 1114113:
            return 0
        index = unit >> 32
        if point == 1114112:
            put(w, SCAN_NEXT, index)
            put(w, SCAN_SIZE, at - start)
            return 1
        if at > RECORD_DATA + RECORD_CAP - 4:
            return 0
        if point < 128:
            store(w, at, point)
            at = at + 1
        elif point < 2048:
            store(w, at, 192 | (point >> 6))
            store(w, at + 1, 128 | (point & 63))
            at = at + 2
        elif point < 65536:
            store(w, at, 224 | (point >> 12))
            store(w, at + 1, 128 | ((point >> 6) & 63))
            store(w, at + 2, 128 | (point & 63))
            at = at + 3
        else:
            store(w, at, 240 | (point >> 18))
            store(w, at + 1, 128 | ((point >> 12) & 63))
            store(w, at + 2, 128 | ((point >> 6) & 63))
            store(w, at + 3, 128 | (point & 63))
            at = at + 4
    return 0

def read_protocol(s:readbuf, w:mutbuf, index:u64, at:u64) -> u64:
    index = whitespace(s, index + 1)
    if index == length(s) or byte(s, index) != 34 or read_text(s, w, index, at) == 0:
        return 0
    if protocol_id(w, at, get(w, SCAN_SIZE)) == 0:
        return 0
    index = whitespace(s, get(w, SCAN_NEXT))
    if index == length(s) or byte(s, index) != 58:
        return 0
    index = whitespace(s, index + 1)
    if index + 4 > length(s) or word_null(s, index) == 0:
        return 0
    index = whitespace(s, index + 4)
    if index == length(s) or byte(s, index) != 125:
        return 0
    put(w, SCAN_NEXT, index + 1)
    return 1

def ignored_string(s:readbuf, index:u64) -> u64:
    index = index + 1
    while index < length(s):
        point = byte(s, index)
        index = index + 1
        if point == 34:
            return index
        if point < 32:
            return NONE
        if point == 92:
            if index == length(s):
                return NONE
            point = byte(s, index)
            index = index + 1
            if point == 117:
                if hex4(s, index) == 4294967295:
                    return NONE
                index = index + 4
            elif point != 34 and point != 92 and point != 47 and point != 98 and point != 102 and point != 110 and point != 114 and point != 116:
                return NONE
    return NONE

def skip_value(s:readbuf, w:mutbuf, index:u64) -> u64:
    depth = 0
    want = True
    while True:
        index = whitespace(s, index)
        if index == length(s):
            return NONE
        point = byte(s, index)
        if want:
            if point == 91 or point == 123:
                if depth >= 524288:
                    return NONE
                store(w, STACK + depth * 2, choose(point == 91, 1, 2))
                store(w, STACK + depth * 2 + 1, 0)
                depth = depth + 1
                index = index + 1
            else:
                if point == 34:
                    index = ignored_string(s, index)
                    if index == NONE:
                        return NONE
                else:
                    index = wire_atom(s, index)
                    if index == 4294967295:
                        return NONE
                if depth == 0:
                    return index
                store(w, STACK + (depth - 1) * 2 + 1, 5)
            want = False
        else:
            slot = STACK + (depth - 1) * 2
            kind = byte(w, slot)
            state = byte(w, slot + 1)
            closing = False
            if kind == 1:
                if state == 0 or state == 1:
                    if state == 0 and point == 93:
                        closing = True
                    else:
                        store(w, slot + 1, 4)
                        want = True
                elif state == 5:
                    if point == 44:
                        store(w, slot + 1, 1)
                        index = index + 1
                    elif point == 93:
                        closing = True
                    else:
                        return NONE
                else:
                    return NONE
            else:
                if state == 0 or state == 1:
                    if state == 0 and point == 125:
                        closing = True
                    else:
                        if point != 34:
                            return NONE
                        index = ignored_string(s, index)
                        if index == NONE:
                            return NONE
                        store(w, slot + 1, 2)
                elif state == 2:
                    if point != 58:
                        return NONE
                    index = index + 1
                    store(w, slot + 1, 3)
                elif state == 3:
                    store(w, slot + 1, 4)
                    want = True
                elif state == 5:
                    if point == 44:
                        store(w, slot + 1, 1)
                        index = index + 1
                    elif point == 125:
                        closing = True
                    else:
                        return NONE
                else:
                    return NONE
            if closing:
                depth = depth - 1
                index = index + 1
                if depth == 0:
                    return index
                store(w, STACK + (depth - 1) * 2 + 1, 5)
    return NONE

def unsigned128(s:readbuf, at:u64, size:u64) -> u64:
    if size == 0 or size > 39 or at > length(s) or size > length(s) - at:
        return 0
    if size > 1 and byte(s, at) == 48:
        return 0
    less = 0
    index = 0
    while index < size:
        point = byte(s, at + index)
        if point < 48 or point > 57:
            return 0
        if size == 39 and less == 0:
            maximum = maximum_digit(index)
            if point > maximum:
                return 0
            if point < maximum:
                less = 1
        index = index + 1
    return 1

def render_record(w:mutbuf, at:u64) -> u64:
    store(w, at, 123)
    at = at + 1
    index = 0
    while index < 9:
        if index != 8 or get(w, RECORD_PROTOCOL) != 0:
            if index != 0:
                store(w, at, 44)
                at = at + 1
            at = field_text(w, index, at)
            source = get(w, RECORD_FIELDS + index * 16)
            size = get(w, RECORD_FIELDS + index * 16 + 8)
            if index == 5 and source == NONE:
                at = null(w, at)
            elif index == 7:
                if size == 0 or size > 39 or source > length(w) or size > length(w) - source:
                    return NONE
                copy(w, at, source, size)
                at = at + size
            else:
                at = quote(w, at, source, size)
            if at == NONE or at > RECORD_OUT + RECORD_CAP - 64:
                return NONE
        index = index + 1
    store(w, at, 125)
    return at + 1

def input_copy(s:readbuf, w:mutbuf, target:u64, source:u64, size:u64) -> u64:
    index = 0
    while index + 8 <= size:
        word_store(w, target + index, word_load(s, source + index))
        index = index + 8
    while index < size:
        store(w, target + index, byte(s, source + index))
        index = index + 1
    return 0

def copy(w:mutbuf, target:u64, source:u64, size:u64) -> u64:
    index = 0
    while index + 8 <= size:
        word_store(w, target + index, word_load(w, source + index))
        index = index + 8
    while index < size:
        store(w, target + index, byte(w, source + index))
        index = index + 1
    return 0
'''


def matcher(name, values):
    source = f'\ndef {name}(w:mutbuf, at:u64, size:u64) -> u64:\n'
    for index, text in enumerate(values, 1):
        raw = text.encode()
        condition = ' and '.join(
            f'getn(w, at + {i}, {len(raw[i:i+8])}) == {int.from_bytes(raw[i:i+8], "little")}'
            for i in range(0, len(raw), 8))
        source += f'    if size == {len(raw)} and {condition}:\n        return {index}\n'
    return source + '    return 0\n'


def texts(name, values):
    source = f'\ndef {name}(w:mutbuf, field:u64, at:u64) -> u64:\n'
    for index, value in enumerate(values):
        raw = value.encode()
        source += f'    if field == {index}:\n'
        for i in range(0, len(raw), 8):
            chunk = raw[i:i+8]
            source += f'        putn(w, at + {i}, {int.from_bytes(chunk, "little")}, {len(chunk)})\n'
        source += f'        return at + {len(raw)}\n'
    return source + '    return at\n'


def source_program():
    source = POLICY
    helpers = {n.name: ast.get_source_segment(REQUEST_POLICY, n)
               for n in ast.parse(REQUEST_POLICY).body if isinstance(n, ast.FunctionDef)}
    for name in ['get', 'getn', 'put', 'putn', 'quote', 'null', 'hexadecimal']:
        source += '\n' + helpers[name].replace('REQUEST_OUT + REQUEST_CAP', 'QUOTE_END') + '\n'
    lexical = {n.name: ast.get_source_segment(PREFLIGHT_SOURCE, n)
               for n in ast.parse(PREFLIGHT_SOURCE).body if isinstance(n, ast.FunctionDef)}
    for name in ['whitespace', 'atom', 'decoded', 'hex4']:
        source += '\n' + lexical[name] + '\n'
    source += _WIRE_NUMBER_SOURCE
    source += matcher('field_id', FIELDS)
    source += matcher('protocol_id', ['captured_v1', 'pty_v1'])
    source += texts('field_text', ['"' + field + '":' for field in FIELDS])
    source += '\ndef maximum_digit(index:u64) -> u64:\n'
    for index, digit in enumerate(str((1 << 128)-1)):
        source += f'    if index == {index}:\n        return {ord(digit)}\n'
    source += '    return 0\n'
    for key in sorted(CONSTANTS, key=len, reverse=True):
        source = re.sub(r'\b' + key + r'\b', str(CONSTANTS[key]), source)
    return source


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    doc = document(source_program(), 'system_jobctl_record')
    path = ROOT / 'examples/hia_bootstrap/system_jobctl_record.hepta'
    text = render_assembly(doc)
    if args.check:
        assert path.read_text() == text
    else:
        path.write_text(text)
    print(path.name, len(text), 'functions', len(doc['functions']), 'blocks',
          sum(len(f['blocks']) for f in doc['functions']), 'ops',
          sum(len(b['ops']) for f in doc['functions'] for b in f['blocks']), flush=True)


if __name__ == '__main__':
    main()
