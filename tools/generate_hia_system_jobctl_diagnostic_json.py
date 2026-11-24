"""Exact typed serde_json diagnostics for the frozen system Jobctl schemas.

The generated HIA function is a pure six-word span call. It walks the original
bytes in typed visitor order, including ignored unknown values and struct
sequences. No whole-document prevalidation changes the first reported error.
"""
from __future__ import annotations

import argparse
import ast
import re
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_system_jobctl_request import document
from tools.generate_hia_worker_request import decimal_program, format_program, replace_once

ROOT = Path(__file__).resolve().parents[1]
SOURCE = 'examples/hia_bootstrap/system_jobctl_diagnostic_json.hepta'
WORKSPACE = 44 << 20
OUTPUT = 8 << 20
STRING = 1 << 20
IGNORE_STACK = 4 << 20
META = 65536
RANGES = 32768
RANGE_DATA = 49152

# Primitive tags: Value, IgnoredAny, String, bool, u8, u16, u64, i32, u128,
# Vec<String>, BTreeMap<String,String>, TerminalProtocol, unit, PathBuf.
# An option adds 1000. Structs start at 100.
SCHEMAS = (
    ('Request', 2, True, (
        ('op', 2, True), ('job_id', 2, True), ('executable', 2, False),
        ('args', 9, False), ('cwd', 1002, False), ('env', 10, False),
        ('stdin', 1002, False), ('timeout_seconds', 1006, False),
        ('nice', 1004, False), ('cpu_quota_percent', 1005, False),
        ('memory_max_bytes', 1006, False), ('stdout_offset', 6, False),
        ('stderr_offset', 6, False), ('limit', 1006, False))),
    ('Policy', 1, True, (
        ('workspace', 13, True), ('allow_network', 3, False),
        ('max_timeout_seconds', 6, False), ('max_cpu_percent', 5, False),
        ('max_memory_bytes', 6, False))),
    ('Record', 8, False, (
        ('job_id', 2, True), ('unit', 2, True), ('request_digest', 2, True),
        ('boot_id', 2, True), ('nonce', 2, True), ('invocation_id', 1002, False),
        ('launch_state', 2, True), ('created_unix_ms', 8, True),
        ('terminal_protocol', 1011, False))),
    ('Spec', 4, False, (
        ('request', 100, True), ('nonce', 2, True), ('boot_id', 2, True),
        ('workspace', 2, True), ('terminal_protocol', 1011, False))),
    ('Exit', 6, False, (
        ('job_id', 2, True), ('nonce', 2, True), ('exit_code', 7, True),
        ('timed_out', 3, True), ('cancelled', 3, True), ('at_unix_ms', 8, True),
        ('terminal_protocol', 1011, False), ('output_complete', 1003, False),
        ('output_durable', 1003, False), ('capture', 1106, False),
        ('scratch_cleanup', 1000, False))),
    ('TerminalWitness', 4, False, (
        ('job_id', 2, True), ('nonce', 2, True),
        ('terminal_protocol', 11, True), ('exit_sha256', 2, True))),
    ('OutputCapture', 2, False, (
        ('stdout', 107, True), ('stderr', 107, True))),
    ('StreamCapture', 9, False, (
        ('seen', 6, True), ('saved', 6, True), ('eof', 3, True),
        ('truncated', 3, True), ('drain_timeout', 3, True),
        ('read_error', 1002, False), ('write_error', 1002, False),
        ('sync_error', 1002, False), ('synced', 3, True))),
)
KEYS = tuple(dict.fromkeys(k for _, _, _, fields in SCHEMAS for k, _, _ in fields))
KEY_ID = {k: i + 1 for i, k in enumerate(KEYS)}
ERRORS = {
    1: 'EOF while parsing a list', 2: 'EOF while parsing an object',
    3: 'EOF while parsing a string', 4: 'EOF while parsing a value',
    5: 'expected `:`', 6: 'expected `,` or `]`', 7: 'expected `,` or `}`',
    8: 'expected ident', 9: 'expected value', 10: 'expected `"`',
    11: 'invalid escape', 12: 'invalid number', 13: 'number out of range',
    14: 'invalid unicode code point',
    15: 'control character (\\u0000-\\u001F) found while parsing a string',
    16: 'key must be a string', 17: 'lone leading surrogate in hex escape',
    18: 'trailing comma', 19: 'trailing characters',
    20: 'unexpected end of hex escape', 21: 'recursion limit exceeded',
}

POLICY = r'''
def diagnostic_json(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) > 1048577 or length(o) != OUTPUT or length(w) != WORKSPACE:
        return 4294967293
    mode = get(o, 0)
    reader = get(o, 8)
    if mode > 10 or reader > 1:
        return 4294967293
    put(w, 16384, 0)
    put(w, 16392, 0)
    put(w, 16400, reader)
    put(w, 16408, 0)
    put(w, 16416, NONE)
    put(w, 16424, 0)
    put(w, 16432, 0)
    put(w, 16440, 0)
    put(w, 16448, 0)
    put(w, 16456, 0)
    put(w, 16464, 0)
    metadata(w)
    if mode == 10:
        index = 0
        while index < length(s):
            store(w, STRING + index, byte(s, index))
            index = index + 1
        put(w, 16448, length(s))
        return debug_string(o, w, literal(o, 0, 59))
    kind = mode + 100
    if mode == 8:
        kind = 0
    elif mode == 9:
        kind = 11
    parse(s, w, kind, 0)
    if get(w, 16408) == 0:
        point = space(s, w)
        if point != NONE:
            failure(s, w, 19, 1)
    if get(w, 16408) == 0:
        return 0
    fix_position(w)
    return render_error(s, o, w)

def peek(s:readbuf, w:mutbuf) -> u64:
    at = get(w, 16384)
    if at == length(s):
        return NONE
    if at + 1 > get(w, 16392):
        put(w, 16392, at + 1)
    return byte(s, at)

def take(s:readbuf, w:mutbuf) -> u64:
    point = peek(s, w)
    if point != NONE:
        put(w, 16384, get(w, 16384) + 1)
    return point

def space(s:readbuf, w:mutbuf) -> u64:
    point = peek(s, w)
    while point == 32 or point == 9 or point == 10 or point == 13:
        put(w, 16384, get(w, 16384) + 1)
        point = peek(s, w)
    return point

def failure(s:readbuf, w:mutbuf, code:u64, ahead:u64) -> u64:
    if get(w, 16408) != 0:
        return 0
    put(w, 16408, code)
    at = get(w, 16384)
    if ahead != 0 and at < length(s):
        at = at + 1
    if get(w, 16400) == 1:
        at = get(w, 16392)
    put(w, 16416, at)
    return 0

def data_error(w:mutbuf, code:u64, expected:u64, detail:u64) -> u64:
    if get(w, 16408) == 0:
        put(w, 16408, code)
        put(w, 16424, expected)
        put(w, 16432, detail)
        put(w, 16416, NONE)
    return 0

def fix_position(w:mutbuf) -> u64:
    if get(w, 16408) != 0 and get(w, 16416) == NONE:
        at = get(w, 16384)
        if get(w, 16400) == 1:
            at = get(w, 16392)
        put(w, 16416, at)
    return 0

def ident(s:readbuf, w:mutbuf, word:u64, size:u64) -> u64:
    index = 0
    while index < size:
        point = take(s, w)
        if point == NONE:
            return failure(s, w, 4, 0)
        if point != ((word >> (index * 8)) & 255):
            return failure(s, w, 8, 0)
        index = index + 1
    return 1

def hex(point:u64) -> u64:
    if point >= 48 and point <= 57:
        return point - 48
    if point >= 65 and point <= 70:
        return point - 55
    if point >= 97 and point <= 102:
        return point - 87
    return NONE

def hex4(s:readbuf, w:mutbuf) -> u64:
    value = 0
    invalid = False
    index = 0
    while index < 4:
        point = take(s, w)
        if point == NONE:
            failure(s, w, 3, 0)
            return NONE
        digit = hex(point)
        if digit == NONE:
            invalid = True
            digit = 0
        value = (value << 4) | digit
        index = index + 1
    if invalid:
        failure(s, w, 11, 0)
        return NONE
    return value

def utf8_emit(w:mutbuf, at:u64, point:u64) -> u64:
    if point < 128:
        store(w, at, point)
        return at + 1
    if point < 2048:
        store(w, at, 192 | (point >> 6))
        store(w, at + 1, 128 | (point & 63))
        return at + 2
    if point < 65536:
        store(w, at, 224 | (point >> 12))
        store(w, at + 1, 128 | ((point >> 6) & 63))
        store(w, at + 2, 128 | (point & 63))
        return at + 3
    store(w, at, 240 | (point >> 18))
    store(w, at + 1, 128 | ((point >> 12) & 63))
    store(w, at + 2, 128 | ((point >> 6) & 63))
    store(w, at + 3, 128 | (point & 63))
    return at + 4

def string(s:readbuf, w:mutbuf, strict:u64) -> u64:
    take(s, w)
    at = STRING
    while True:
        point = take(s, w)
        if point == NONE:
            return failure(s, w, 3, 0)
        if point == 34:
            put(w, 16448, at - STRING)
            if strict != 0 and utf8_valid(w, STRING, at - STRING) == 0:
                return failure(s, w, 14, 0)
            return 1
        if point < 32:
            if strict == 0 and get(w, 16400) == 0:
                put(w, 16384, get(w, 16384) - 1)
            return failure(s, w, 15, 0)
        if point == 92:
            point = take(s, w)
            if point == NONE:
                return failure(s, w, 3, 0)
            if point == 117:
                point = hex4(s, w)
                if point == NONE:
                    return 0
                if strict == 0:
                    point = 32
                elif point >= 56320 and point <= 57343:
                    return failure(s, w, 17, 0)
                elif point >= 55296 and point <= 56319:
                    first = point
                    point = take(s, w)
                    if point == NONE:
                        return failure(s, w, 3, 0)
                    if point != 92:
                        return failure(s, w, 20, 0)
                    point = take(s, w)
                    if point == NONE:
                        return failure(s, w, 3, 0)
                    if point != 117:
                        return failure(s, w, 20, 0)
                    point = hex4(s, w)
                    if point == NONE:
                        return 0
                    if point < 56320 or point > 57343:
                        return failure(s, w, 17, 0)
                    point = 65536 + ((first - 55296) << 10) + point - 56320
                at = utf8_emit(w, at, point)
                point = NONE
            elif point == 98:
                point = 8
            elif point == 102:
                point = 12
            elif point == 110:
                point = 10
            elif point == 114:
                point = 13
            elif point == 116:
                point = 9
            elif point != 34 and point != 47 and point != 92:
                return failure(s, w, 11, 0)
        if point != NONE:
            store(w, at, point)
            at = at + 1
        if at > STRING + 1048577:
            return failure(s, w, 14, 0)
    return 0

def utf8_valid(w:mutbuf, at:u64, size:u64) -> u64:
    end = at + size
    while at < end:
        first = byte(w, at)
        width = 1
        if first >= 194 and first <= 223:
            width = 2
        elif first >= 224 and first <= 239:
            width = 3
        elif first >= 240 and first <= 244:
            width = 4
        elif first >= 128:
            return 0
        if width > end - at:
            return 0
        index = 1
        while index < width:
            point = byte(w, at + index)
            if point < 128 or point > 191:
                return 0
            if index == 1:
                if (first == 224 and point < 160) or (first == 237 and point >= 160):
                    return 0
                if (first == 240 and point < 144) or (first == 244 and point >= 144):
                    return 0
            index = index + 1
        at = at + width
    return 1

def number(s:readbuf, w:mutbuf, ignored:u64) -> u64:
    start = get(w, 16384)
    negative = peek(s, w) == 45
    if negative:
        take(s, w)
    point = take(s, w)
    if point == NONE:
        return failure(s, w, 4, 0)
    if point < 48 or point > 57:
        return failure(s, w, 12, 0)
    value = point - 48
    nonzero = point != 48
    overflow = False
    floating = False
    if point == 48:
        point = peek(s, w)
        if point >= 48 and point <= 57:
            return failure(s, w, 12, 1)
    else:
        point = peek(s, w)
        while point >= 48 and point <= 57:
            take(s, w)
            digit = point - 48
            if digit != 0:
                nonzero = True
            if value > 1844674407370955161 or (value == 1844674407370955161 and digit > 5):
                overflow = True
            value = value * 10 + digit
            point = peek(s, w)
    if point == 46:
        floating = True
        take(s, w)
        point = peek(s, w)
        if point == NONE:
            return failure(s, w, 4, 1)
        if point < 48 or point > 57:
            return failure(s, w, 12, 1)
        while point >= 48 and point <= 57:
            if point != 48:
                nonzero = True
            take(s, w)
            point = peek(s, w)
    if point == 101 or point == 69:
        floating = True
        take(s, w)
        point = peek(s, w)
        positive_exponent = point != 45
        if point == 43 or point == 45:
            take(s, w)
        point = take(s, w)
        if point == NONE:
            return failure(s, w, 4, 0)
        if point < 48 or point > 57:
            return failure(s, w, 12, 0)
        exponent = point - 48
        point = peek(s, w)
        while point >= 48 and point <= 57:
            take(s, w)
            digit = point - 48
            if exponent > 214748364 or (exponent == 214748364 and digit > 7):
                if ignored == 0 and nonzero and positive_exponent:
                    return failure(s, w, 13, 0)
                exponent = 2147483647
            else:
                exponent = exponent * 10 + digit
            point = peek(s, w)
    size = get(w, 16384) - start
    put(w, 16456, start)
    put(w, 16464, size)
    put(w, 16472, value)
    put(w, 16480, choose(negative, 1, 0))
    if floating or overflow or (negative and (value == 0 or value > 9223372036854775808)):
        put(w, 16440, 4)
        if ignored == 0:
            if widen(decimal_convert(s, w, start, size)) != 8:
                return failure(s, w, 13, 0)
    else:
        put(w, 16440, 3)
    return 1

def unsigned128(s:readbuf, w:mutbuf) -> u64:
    point = space(s, w)
    if point == NONE:
        return failure(s, w, 4, 1)
    if point == 45:
        return failure(s, w, 13, 1)
    start = get(w, 16384)
    point = take(s, w)
    if point < 48 or point > 57:
        return failure(s, w, 12, 0)
    if point == 48:
        point = peek(s, w)
        if point >= 48 and point <= 57:
            return failure(s, w, 12, 1)
    else:
        point = peek(s, w)
        while point >= 48 and point <= 57:
            take(s, w)
            point = peek(s, w)
    size = get(w, 16384) - start
    if size > 39:
        return failure(s, w, 13, 0)
    if size == 39:
        index = 0
        while index < 39:
            digit = byte(s, start + index)
            limit = maximum128(index)
            if digit < limit:
                return 1
            if digit > limit:
                return failure(s, w, 13, 0)
            index = index + 1
    return 1

def end_container(s:readbuf, w:mutbuf, closing:u64) -> u64:
    point = space(s, w)
    if point == closing:
        take(s, w)
    elif point == NONE:
        failure(s, w, choose(closing == 93, 1, 2), 1)
    elif point == 44:
        if closing == 93:
            take(s, w)
            point = space(s, w)
            failure(s, w, choose(point == 93, 18, 19), 1)
        else:
            failure(s, w, 18, 1)
    else:
        failure(s, w, 19, 1)
    fix_position(w)
    return choose(get(w, 16408) == 0, 1, 0)

def parse(s:readbuf, w:mutbuf, kind:u64, depth:u64) -> u64:
    point = space(s, w)
    if point == NONE:
        return failure(s, w, 4, 1)
    if kind >= 1000:
        if point == 110:
            return ident(s, w, 1819047278, 4)
        kind = kind - 1000
    if kind == 1:
        return ignore(s, w)
    if kind == 8:
        return unsigned128(s, w)
    if kind == 11:
        return protocol(s, w, depth)
    container = (point == 91 and (kind == 0 or kind == 9 or kind >= 100)) or (point == 123 and (kind == 0 or kind == 10 or kind >= 100))
    if container:
        if depth >= 127:
            return failure(s, w, 21, 1)
        sequence = point == 91
        closing = choose(sequence, 93, 125)
        take(s, w)
        count = 0
        mask = 0
        meta = 0
        fields = NONE
        if kind >= 100:
            meta = META + (kind - 100) * 160
            fields = get(w, meta)
        while get(w, 16408) == 0:
            point = space(s, w)
            if point == NONE:
                failure(s, w, choose(sequence, 1, 2), 1)
                return end_container(s, w, closing)
            if point == closing:
                if kind >= 100:
                    if sequence and count < get(w, meta + 16):
                        data_error(w, 35, kind, count)
                    elif sequence == False and (mask & get(w, meta + 8)) != get(w, meta + 8):
                        index = 0
                        while index < fields:
                            if ((get(w, meta + 8) >> index) & 1) != 0 and ((mask >> index) & 1) == 0:
                                data_error(w, 32, kind, get(w, meta + 32 + index * 8) & 4294967295)
                                return end_container(s, w, closing)
                            index = index + 1
                return end_container(s, w, closing)
            if sequence and count == fields:
                return end_container(s, w, closing)
            if count != 0:
                if point != 44:
                    failure(s, w, choose(sequence, 6, 7), 1)
                    return end_container(s, w, closing)
                take(s, w)
                point = space(s, w)
                if point == closing:
                    failure(s, w, 18, 1)
                    return end_container(s, w, closing)
                if point == NONE:
                    failure(s, w, 4, 1)
                    return end_container(s, w, closing)
            child = 0
            if kind == 9 or kind == 10:
                child = 2
            if sequence:
                if kind >= 100:
                    child = get(w, meta + 32 + count * 8) >> 32
            else:
                if point != 34:
                    failure(s, w, 16, 1)
                    return end_container(s, w, closing)
                if string(s, w, 1) == 0:
                    return end_container(s, w, closing)
                if kind >= 100:
                    key = key_id(w)
                    ordinal = 0
                    while ordinal < fields and (get(w, meta + 32 + ordinal * 8) & 4294967295) != key:
                        ordinal = ordinal + 1
                    if ordinal == fields:
                        if get(w, meta + 24) == 1:
                            data_error(w, 34, kind, 0)
                            return end_container(s, w, closing)
                        child = 1
                    else:
                        if ((mask >> ordinal) & 1) != 0:
                            data_error(w, 33, kind, key)
                            return end_container(s, w, closing)
                        mask = mask | (1 << ordinal)
                        child = get(w, meta + 32 + ordinal * 8) >> 32
                point = space(s, w)
                if point != 58:
                    failure(s, w, choose(point == NONE, 2, 5), 1)
                    return end_container(s, w, closing)
                take(s, w)
            if parse(s, w, child, depth + 1) == 0:
                return end_container(s, w, closing)
            count = count + 1
        return end_container(s, w, closing)
    if point == 34:
        if string(s, w, 1) == 0:
            return 0
        put(w, 16440, 5)
        if kind == 0 or kind == 2 or kind == 13:
            return 1
    elif point == 110:
        if ident(s, w, 1819047278, 4) == 0:
            return 0
        put(w, 16440, 0)
        if kind == 0 or kind == 12:
            return 1
    elif point == 116 or point == 102:
        if point == 116:
            result = ident(s, w, 1702195828, 4)
            actual = 2
        else:
            result = ident(s, w, 435728179558, 5)
            actual = 1
        if result == 0:
            return 0
        put(w, 16440, actual)
        if kind == 0 or kind == 3:
            return 1
    elif point == 45 or (point >= 48 and point <= 57):
        if number(s, w, 0) == 0:
            return 0
        if kind == 0:
            return 1
        if kind >= 4 and kind <= 7 and get(w, 16440) == 3:
            value = get(w, 16472)
            negative = get(w, 16480) == 1
            maximum = 18446744073709551615
            if kind == 4:
                maximum = 255
            elif kind == 5:
                maximum = 65535
            elif kind == 7:
                maximum = choose(negative, 2147483648, 2147483647)
            if value <= maximum and (kind == 7 or negative == False):
                return 1
            data_error(w, 31, kind, 0)
            fix_position(w)
            return 0
    elif point == 91:
        put(w, 16440, 6)
    elif point == 123:
        put(w, 16440, 7)
    else:
        return failure(s, w, 9, 1)
    data_error(w, 30, kind, 0)
    fix_position(w)
    return 0

def protocol(s:readbuf, w:mutbuf, depth:u64) -> u64:
    point = space(s, w)
    object = point == 123
    if object:
        if depth >= 127:
            return failure(s, w, 21, 1)
        take(s, w)
        point = space(s, w)
        if point != 34:
            code = 16
            if point == NONE:
                code = 2
            elif point == 125:
                code = 9
            return failure(s, w, code, 1)
    if point != 34:
        return failure(s, w, 9, 1)
    if string(s, w, 1) == 0:
        return 0
    valid = get(w, 16448) == 11 and getn(w, STRING, 8) == 7234314225230831971 and getn(w, STRING + 8, 3) == 3241567
    if get(w, 16448) == 6 and getn(w, STRING, 6) == 54384477697136:
        valid = True
    if valid == False:
        data_error(w, 36, 11, 0)
        fix_position(w)
        return 0
    if object:
        point = space(s, w)
        if point != 58:
            return failure(s, w, choose(point == NONE, 2, 5), 1)
        take(s, w)
        if parse(s, w, 12, depth + 1) == 0:
            return 0
        point = space(s, w)
        if point != 125:
            return failure(s, w, choose(point == NONE, 2, 9), 0)
        take(s, w)
    return 1

def ignore(s:readbuf, w:mutbuf) -> u64:
    depth = 1
    store(w, IGNORE_STACK, 0)
    while depth != 0 and get(w, 16408) == 0:
        state = byte(w, IGNORE_STACK + depth - 1)
        if state == 9:
            return 1
        point = space(s, w)
        if point == NONE:
            code = 4
            if state == 1 or state == 2:
                code = 1
            elif state == 4 or state == 6 or state == 8:
                code = 2
            return failure(s, w, code, 1)
        if state == 2 or state == 8:
            closing = choose(state == 2, 93, 125)
            if point == closing:
                take(s, w)
                depth = depth - 1
            elif point == 44:
                take(s, w)
                store(w, IGNORE_STACK + depth - 1, choose(state == 2, 3, 5))
            else:
                return failure(s, w, choose(state == 2, 6, 7), 1)
        elif state == 4 or state == 5:
            if state == 4 and point == 125:
                take(s, w)
                depth = depth - 1
            elif point != 34:
                return failure(s, w, 16, 1)
            elif string(s, w, 0) == 0:
                return 0
            else:
                store(w, IGNORE_STACK + depth - 1, 6)
        elif state == 6:
            if point != 58:
                return failure(s, w, 5, 1)
            take(s, w)
            store(w, IGNORE_STACK + depth - 1, 7)
        elif state == 1 and point == 93:
            take(s, w)
            depth = depth - 1
        else:
            store(w, IGNORE_STACK + depth - 1, choose(state == 0, 9, choose(state == 7, 8, 2)))
            if point == 91 or point == 123:
                store(w, IGNORE_STACK + depth, choose(point == 91, 1, 4))
                depth = depth + 1
                take(s, w)
            elif point == 34:
                if string(s, w, 0) == 0:
                    return 0
            elif point == 110:
                if ident(s, w, 1819047278, 4) == 0:
                    return 0
            elif point == 116:
                if ident(s, w, 1702195828, 4) == 0:
                    return 0
            elif point == 102:
                if ident(s, w, 435728179558, 5) == 0:
                    return 0
            elif point == 45 or (point >= 48 and point <= 57):
                if number(s, w, 1) == 0:
                    return 0
            else:
                return failure(s, w, 9, 1)
    return choose(get(w, 16408) == 0, 1, 0)
'''

RENDER = r'''
def render_error(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    code = get(w, 16408)
    kind = get(w, 16424)
    detail = get(w, 16432)
    at = 0
    if code <= 21:
        at = literal(o, at, code)
    elif code == 30 or code == 31:
        at = literal(o, at, choose(code == 30, 30, 31))
        at = unexpected(s, o, w, at)
        at = literal(o, at, 40)
        at = expected(o, at, kind)
    elif code == 32 or code == 33:
        at = literal(o, at, code)
        at = literal(o, at, 1000 + detail)
        at = emit(o, at, 96)
    elif code == 34:
        at = literal(o, at, 34)
        at = copy_error(w, o, STRING, at, get(w, 16448))
        at = literal(o, at, 41)
        meta = META + (kind - 100) * 160
        index = 0
        while index < get(w, meta):
            if index != 0:
                at = literal(o, at, 42)
            at = emit(o, at, 96)
            at = literal(o, at, 1000 + (get(w, meta + 32 + index * 8) & 4294967295))
            at = emit(o, at, 96)
            index = index + 1
    elif code == 35:
        at = literal(o, at, 35)
        at = unsigned(o, w, at, detail)
        at = literal(o, at, 40)
        at = expected(o, at, kind)
        at = literal(o, at, 43)
        at = unsigned(o, w, at, get(w, META + (kind - 100) * 160))
        at = literal(o, at, 44)
    elif code == 36:
        at = literal(o, at, 36)
        at = copy_error(w, o, STRING, at, get(w, 16448))
        at = literal(o, at, 45)
    else:
        return 4294967293
    line = 1
    column = 0
    index = 0
    while index < get(w, 16416):
        if byte(s, index) == 10:
            line = line + 1
            column = 0
        else:
            column = column + 1
        index = index + 1
    at = literal(o, at, 46)
    at = unsigned(o, w, at, line)
    at = literal(o, at, 47)
    return unsigned(o, w, at, column)

def unexpected(s:readbuf, o:mutbuf, w:mutbuf, at:u64) -> u64:
    actual = get(w, 16440)
    if actual < 3:
        return literal(o, at, 50 + actual)
    if actual == 3:
        at = literal(o, at, 53)
        index = 0
        while index < get(w, 16464):
            at = emit(o, at, byte(s, get(w, 16456) + index))
            index = index + 1
        return emit(o, at, 96)
    if actual == 4:
        at = literal(o, at, 54)
        size = widen(format_render_binary64(w))
        if size > 128:
            return OUTPUT + 1
        at = copy_error(w, o, length(w) - 8192 + 6144, at, size)
        return emit(o, at, 96)
    if actual == 5:
        at = literal(o, at, 55)
        return debug_string(o, w, at)
    return literal(o, at, 50 + actual)

def debug_string(o:mutbuf, w:mutbuf, at:u64) -> u64:
    at = emit(o, at, 34)
    index = 0
    while index < get(w, 16448):
        first = byte(w, STRING + index)
        point = first
        width = 1
        valid = first < 128
        if first >= 194 and first <= 223:
            width = 2
            point = first & 31
            valid = True
        elif first >= 224 and first <= 239:
            width = 3
            point = first & 15
            valid = True
        elif first >= 240 and first <= 244:
            width = 4
            point = first & 7
            valid = True
        if width > get(w, 16448) - index:
            valid = False
        digit = 1
        while valid and digit < width:
            next = byte(w, STRING + index + digit)
            if next < 128 or next > 191:
                valid = False
            elif digit == 1 and ((first == 224 and next < 160) or (first == 237 and next >= 160) or (first == 240 and next < 144) or (first == 244 and next >= 144)):
                valid = False
            point = (point << 6) | (next & 63)
            digit = digit + 1
        if valid == False:
            at = emit(o, at, 92)
            at = emit(o, at, 120)
            high = first >> 4
            low = first & 15
            at = emit(o, at, choose(high < 10, high + 48, high + 55))
            at = emit(o, at, choose(low < 10, low + 48, low + 55))
            width = 1
        elif point == 0 or point == 9 or point == 10 or point == 13 or point == 34 or point == 92:
            at = emit(o, at, 92)
            escaped = point
            if point == 0:
                escaped = 48
            elif point == 9:
                escaped = 116
            elif point == 10:
                escaped = 110
            elif point == 13:
                escaped = 114
            at = emit(o, at, escaped)
        elif point < 32 or point == 127 or printable(point, w) == 0:
            at = literal(o, at, 58)
            digits = 0
            value = point
            while value >= 16:
                store(w, 18000 + digits, hex_text(value & 15))
                value = value >> 4
                digits = digits + 1
            at = emit(o, at, hex_text(value))
            while digits != 0:
                digits = digits - 1
                at = emit(o, at, byte(w, 18000 + digits))
            at = emit(o, at, 125)
        else:
            at = copy_error(w, o, STRING + index, at, width)
        index = index + width
    return emit(o, at, 34)

def printable(point:u64, w:mutbuf) -> u64:
    low = 0
    high = get(w, RANGES)
    while low < high:
        middle = low + (high - low) // 2
        packed = get(w, RANGES + 8 + middle * 8)
        start = packed & 2097151
        end = packed >> 21
        if point < start:
            high = middle
        elif point > end:
            low = middle + 1
        else:
            return 0
    return 1

def load_ranges(w:mutbuf) -> u64:
    put(w, 18064, RANGE_DATA)
    previous = 127
    index = 0
    while index < get(w, RANGES):
        start = previous + 1 + range_varint(w)
        end = start + range_varint(w)
        put(w, RANGES + 8 + index * 8, start | (end << 21))
        previous = end
        index = index + 1
    return 0

def range_varint(w:mutbuf) -> u64:
    value = 0
    shift = 0
    point = 128
    while point >= 128:
        at = get(w, 18064)
        point = byte(w, at)
        put(w, 18064, at + 1)
        value = value | ((point & 127) << shift)
        shift = shift + 7
    return value

def hex_text(value:u64) -> u64:
    return choose(value < 10, value + 48, value + 87)

def unsigned(o:mutbuf, w:mutbuf, at:u64, value:u64) -> u64:
    size = 0
    while value >= 10:
        store(w, 18000 + size, value % 10 + 48)
        value = value // 10
        size = size + 1
    at = emit(o, at, value + 48)
    while size != 0:
        size = size - 1
        at = emit(o, at, byte(w, 18000 + size))
    return at

def copy_error(w:mutbuf, o:mutbuf, source:u64, at:u64, size:u64) -> u64:
    index = 0
    while index < size:
        at = emit(o, at, byte(w, source + index))
        index = index + 1
    return at

def emit(o:mutbuf, at:u64, value:u64) -> u64:
    if at < length(o):
        store(o, at, value)
    return at + 1

def get(w:mutbuf, at:u64) -> u64:
    return word_load(w, at)

def getn(w:mutbuf, at:u64, size:u64) -> u64:
    if size == 8:
        return word_load(w, at)
    value = 0
    index = 0
    while index < size:
        value = value | (byte(w, at + index) << (index * 8))
        index = index + 1
    return value

def put(w:mutbuf, at:u64, value:u64) -> u64:
    word_store(w, at, value)
    return 0

def putn(w:mutbuf, at:u64, value:u64, size:u64) -> u64:
    index = 0
    while index < size:
        store(w, at + index, (value >> (index * 8)) & 255)
        index = index + 1
    return 0

def widen(value:u32) -> u64:
    return value
'''


def literal_function(values):
    source = '\ndef literal(o:mutbuf, at:u64, identity:u64) -> u64:\n'
    for identity, text in sorted(values.items()):
        raw = text.encode('utf8')
        source += f'    if identity == {identity}:\n'
        for offset in range(0, len(raw), 8):
            chunk = raw[offset:offset + 8]
            source += f'        putn(o, at + {offset}, {int.from_bytes(chunk, "little")}, {len(chunk)})\n'
        source += f'        return at + {len(raw)}\n'
    return source + '    return at\n'


def source_program():
    values = dict(ERRORS)
    values.update({30:'invalid type: ',31:'invalid value: ',32:'missing field `',33:'duplicate field `',
        34:'unknown field `',35:'invalid length ',36:'unknown variant `',40:', expected ',
        41:'`, expected one of ',42:', ',43:' with ',44:' elements',
        45:'`, expected `captured_v1` or `pty_v1`',46:' at line ',47:' column ',
        50:'null',51:'boolean `false`',52:'boolean `true`',53:'integer `',54:'floating point `',
        55:'string ',56:'sequence',57:'map',58:'\\u{',59:'environment variable was not valid unicode: '})
    values.update({1000+i:name for name,i in KEY_ID.items()})
    expect = {2:'a string',3:'a boolean',4:'u8',5:'u16',6:'u64',7:'i32',8:'u128',
              9:'a sequence',10:'a map',11:'string or map',12:'unit',13:'path string'}
    expect.update({100+i:'struct '+name for i,(name,_,_,_) in enumerate(SCHEMAS)})
    values.update({2000+i:text for i,text in expect.items()})
    generated = '\ndef expected(o:mutbuf, at:u64, kind:u64) -> u64:\n    return literal(o, at, 2000 + kind)\n'
    generated += '\ndef key_id(w:mutbuf) -> u64:\n'
    for key, identity in KEY_ID.items():
        raw = key.encode()
        condition = ' and '.join(f'getn(w, STRING + {i}, {len(raw[i:i+8])}) == {int.from_bytes(raw[i:i+8], "little")}' for i in range(0, len(raw), 8))
        generated += f'    if get(w, 16448) == {len(raw)} and {condition}:\n        return {identity}\n'
    generated += '    return 0\n\ndef metadata(w:mutbuf) -> u64:\n'
    for index, (_, minimum, denied, fields) in enumerate(SCHEMAS):
        at = META + index * 160
        required = sum(1 << i for i, (_, _, req) in enumerate(fields) if req)
        words = [len(fields), required, minimum, int(denied)] + [(kind << 32) | KEY_ID[name] for name, kind, _ in fields]
        for offset, value in enumerate(words):
            generated += f'    put(w, {at + offset * 8}, {value})\n'
    # Derived by the exact Rust 1.95 char/string Debug oracle. All Unicode
    # scalar values are represented; no locale-dependent printability lookup.
    ranges_path = ROOT/'tools/hia_system_jobctl_debug_ranges.txt'
    ranges = ast.literal_eval(ranges_path.read_text())
    generated += f'    put(w, RANGES, {len(ranges)})\n'
    encoded = bytearray()
    previous = 127
    for start, end in ranges:
        for value in (start - previous - 1, end - start):
            while value >= 128:
                encoded.append((value & 127) | 128)
                value >>= 7
            encoded.append(value)
        previous = end
    assert len(encoded) < META - RANGE_DATA
    for i in range(0, len(encoded), 8):
        generated += f'    put(w, RANGE_DATA + {i}, {int.from_bytes(encoded[i:i+8], "little")})\n'
    generated += '    load_ranges(w)\n    return 0\n\ndef maximum128(index:u64) -> u64:\n'
    for i, value in enumerate(b'340282366920938463463374607431768211455'):
        generated += f'    if index == {i}:\n        return {value}\n'
    generated += '    return 0\n'
    formatter = format_program()
    formatter = replace_once(formatter, 'order < 2044 or order >= 2064', 'order < 2043 or order >= 2064')
    formatter = replace_once(formatter, '            cursor = format_emit(w, cursor, tens + 48)',
        '            if hundreds != 0 or tens != 0:\n                cursor = format_emit(w, cursor, tens + 48)')
    source = '\n'.join((POLICY, RENDER, generated, literal_function(values), decimal_program(), formatter))
    constants = {key:value for key,value in globals().items() if key.isupper() and type(value) is int}
    constants['NONE'] = (1 << 64) - 1
    for key in sorted(constants, key=len, reverse=True):
        source = re.sub(r'\b'+key+r'\b', str(constants[key]), source)
    return source


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--check',action='store_true');args=parser.parse_args()
    program=document(source_program(),'system_jobctl_diagnostic_json')
    result=render_assembly(program)
    target=ROOT/SOURCE
    if args.check:
        assert target.read_text()==result,target
    else:
        target.write_text(result)
    print(len(result),len(program['functions']),sum(len(f['blocks']) for f in program['functions']),sum(len(b['ops']) for f in program['functions'] for b in f['blocks']))


if __name__=='__main__':
    main()
