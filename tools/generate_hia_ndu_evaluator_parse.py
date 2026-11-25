"""Specialized Request/Candidate serde-shape parser authored in HIA."""
import ast
from tools.generate_hia_json_preflight import SOURCE as JSON_SOURCE
PARSE=r'''
def peek(s:readbuf, w:mutbuf) -> u64:
    at = get(w, 56)
    while at < length(s):
        ch = byte(s, at)
        if ch != 32 and ch != 9 and ch != 10 and ch != 13:
            put(w, 56, at)
            return ch
        at = at + 1
    put(w, 56, at)
    return 256

def scan_string(s:readbuf, w:mutbuf) -> u64:
    start = get(w, 48)
    at = get(w, 56) + 1
    out = start
    while at < length(s):
        ch = byte(s, at)
        if ch == 34:
            size = out - start
            valid = utf8_check(w, start, size)
            if valid != size:
                return error(w, 17, at + 1 - (size - valid), 0, 0)
            put(w, 32, start)
            put(w, 40, size)
            put(w, 48, out)
            put(w, 56, at + 1)
            return 1
        if ch < 32:
            return error(w, 12, at + 1, 0, 0)
        if ch == 92:
            unit = scan_escape(s, w, at + 1)
            if get(w, 0) != 0:
                return 0
            out = emit_utf8(w, out, unit & 4294967295)
            at = unit >> 32
        else:
            store(w, out, ch)
            out = out + 1
            at = at + 1
    return error(w, 13, length(s), 0, 0)

def scan_hex(s:readbuf, w:mutbuf, at:u64) -> u64:
    if at > length(s) or length(s) - at < 4:
        error(w, 13, length(s), 0, 0)
        return 65536
    value = 0
    bad = 0
    i = 0
    while i < 4:
        ch = byte(s, at + i)
        digit = 16
        if ch >= 48 and ch <= 57:
            digit = ch - 48
        if ch >= 65 and ch <= 70:
            digit = ch - 55
        if ch >= 97 and ch <= 102:
            digit = ch - 87
        bad = bad | (digit >> 4)
        value = (value << 4) | digit
        i = i + 1
    if bad != 0:
        error(w, 14, at + 4, 0, 0)
        return 65536
    return value

def scan_escape(s:readbuf, w:mutbuf, at:u64) -> u64:
    if at >= length(s):
        return error(w, 13, length(s), 0, 0)
    ch = byte(s, at)
    at = at + 1
    if ch == 34 or ch == 92 or ch == 47:
        return (at << 32) | ch
    if ch == 98:
        return (at << 32) | 8
    if ch == 102:
        return (at << 32) | 12
    if ch == 110:
        return (at << 32) | 10
    if ch == 114:
        return (at << 32) | 13
    if ch == 116:
        return (at << 32) | 9
    if ch != 117:
        return error(w, 14, at, 0, 0)
    value = scan_hex(s, w, at)
    if value > 65535:
        return 0
    at = at + 4
    if value >= 56320 and value <= 57343:
        return error(w, 16, at, 0, 0)
    if value < 55296 or value > 56319:
        return (at << 32) | value
    if at >= length(s):
        return error(w, 13, at, 0, 0)
    if byte(s, at) != 92:
        return error(w, 18, at + 1, 0, 0)
    at = at + 1
    if at >= length(s):
        return error(w, 13, at, 0, 0)
    if byte(s, at) != 117:
        return error(w, 18, at + 1, 0, 0)
    at = at + 1
    second = scan_hex(s, w, at)
    if second > 65535:
        return 0
    at = at + 4
    if second < 56320 or second > 57343:
        return error(w, 16, at, 0, 0)
    value = 65536 + ((value - 55296) << 10) + second - 56320
    return (at << 32) | value

def utf8_check(w:mutbuf, start:u64, size:u64) -> u64:
    i = 0
    while i < size:
        ch = byte(w, start + i)
        if ch < 128:
            i = i + 1
        else:
            count = 0
            low = 128
            high = 191
            if ch >= 194 and ch <= 223:
                count = 2
            if ch >= 224 and ch <= 239:
                count = 3
                if ch == 224:
                    low = 160
                if ch == 237:
                    high = 159
            if ch >= 240 and ch <= 244:
                count = 4
                if ch == 240:
                    low = 144
                if ch == 244:
                    high = 143
            if count == 0 or count > size - i:
                return i
            first = byte(w, start + i + 1)
            if first < low or first > high:
                return i
            j = 2
            while j < count:
                next = byte(w, start + i + j)
                if next < 128 or next > 191:
                    return i
                j = j + 1
            i = i + count
    return size

def parse_atom(s:readbuf, w:mutbuf, kind:u64) -> u64:
    at = get(w, 56)
    end = literal(w, 44032, kind)
    size = end - 44032
    i = 0
    while i < size:
        if at + i >= length(s):
            return error(w, 2, at + i, 0, 0)
        if byte(s, at + i) != byte(w, 44032 + i):
            return error(w, 20, at + i + 1, 0, 0)
        i = i + 1
    put(w, 56, at + size)
    return 1

def scan_number(s:readbuf, w:mutbuf) -> u64:
    at = get(w, 56)
    start = at
    put(w, 136, start)
    negative = 0
    if byte(s, at) == 45:
        negative = 1
        at = at + 1
    if at >= length(s):
        return error(w, 2, at, 0, 0)
    ch = byte(s, at)
    if ch < 48 or ch > 57:
        return error(w, 3, at + 1, 0, 0)
    value = 0
    overflow = 0
    first = ch
    at = at + 1
    value = ch - 48
    if first == 48 and at < length(s):
        ch = byte(s, at)
        if ch >= 48 and ch <= 57:
            return error(w, 3, at + 1, 0, 0)
    going = True
    while going and at < length(s) and first != 48:
        ch = byte(s, at)
        if ch >= 48 and ch <= 57:
            digit = ch - 48
            if value > 1844674407370955161 or (value == 1844674407370955161 and digit > 5):
                overflow = 1
            value = value * 10 + digit
            at = at + 1
        else:
            going = False
    floating = overflow
    if at < length(s) and byte(s, at) == 46:
        floating = 1
        at = at + 1
        if at >= length(s):
            return error(w, 2, at, 0, 0)
        ch = byte(s, at)
        if ch < 48 or ch > 57:
            return error(w, 3, at + 1, 0, 0)
        going = True
        while going and at < length(s):
            ch = byte(s, at)
            if ch >= 48 and ch <= 57:
                at = at + 1
            else:
                going = False
    if at < length(s) and (byte(s, at) == 101 or byte(s, at) == 69):
        floating = 1
        at = at + 1
        if at < length(s) and (byte(s, at) == 43 or byte(s, at) == 45):
            at = at + 1
        if at >= length(s):
            return error(w, 2, at, 0, 0)
        ch = byte(s, at)
        if ch < 48 or ch > 57:
            return error(w, 3, at + 1, 0, 0)
        going = True
        while going and at < length(s):
            ch = byte(s, at)
            if ch >= 48 and ch <= 57:
                at = at + 1
            else:
                going = False
    if negative == 1 and (value == 0 or value > 9223372036854775808):
        floating = 1
    put(w, 56, at)
    put(w, 72, value)
    put(w, 80, negative)
    put(w, 88, floating)
    put(w, 96, get(w, 48))
    put(w, 104, at - start)
    put(w, 48, input_copy(s, w, get(w, 48), start, at - start))
    return 1

def unexpected(s:readbuf, w:mutbuf, expected:u64) -> u64:
    ch = peek(s, w)
    kind = 0
    if ch == 256:
        return error(w, 2, get(w, 56), 0, 0)
    if ch == 34:
        if scan_string(s, w) == 0:
            return 0
        put(w, 96, get(w, 32))
        put(w, 104, get(w, 40))
        kind = 4
    else:
        if ch == 116 or ch == 102:
            if parse_atom(s, w, choose(ch == 116, L_TRUE, L_FALSE)) == 0:
                return 0
            put(w, 72, choose(ch == 116, 1, 0))
            kind = 1
        else:
            if ch == 110:
                if parse_atom(s, w, L_NULL) == 0:
                    return 0
                kind = 0
            else:
                if ch == 91 or ch == 123:
                    kind = choose(ch == 91, 5, 6)
                else:
                    if ch == 45 or (ch >= 48 and ch <= 57):
                        if scan_number(s, w) == 0:
                            return 0
                        kind = choose(get(w, 88) == 0, 2, 3)
                    else:
                        return error(w, 1, get(w, 56) + 1, 0, 0)
    return error(w, 120, get(w, 56), kind, expected)

def typed_string(s:readbuf, w:mutbuf, target:u64) -> u64:
    if peek(s, w) != 34:
        return unexpected(s, w, 1)
    if scan_string(s, w) == 0:
        return 0
    put(w, target, get(w, 32))
    put(w, target + 8, get(w, 40))
    return 1

def typed_integer(s:readbuf, w:mutbuf, target:u64, signed:u64) -> u64:
    ch = peek(s, w)
    if ch != 45 and (ch < 48 or ch > 57):
        return unexpected(s, w, 2 + signed)
    if scan_number(s, w) == 0:
        return 0
    if get(w, 88) != 0:
        return error(w, 120, get(w, 56), 3, 2 + signed)
    value = get(w, 72)
    negative = get(w, 80)
    if (signed == 0 and negative == 1) or (signed == 1 and negative == 0 and value > 9223372036854775807):
        return error(w, 121, get(w, 56), 2, 2 + signed)
    put(w, target, choose(negative == 1, 0 - value, value))
    return 1

def typed_bool(s:readbuf, w:mutbuf, target:u64) -> u64:
    ch = peek(s, w)
    if ch != 116 and ch != 102:
        return unexpected(s, w, 4)
    if parse_atom(s, w, choose(ch == 116, L_TRUE, L_FALSE)) == 0:
        return 0
    put(w, target, choose(ch == 116, 1, 0))
    return 1

def read_candidate_field(s:readbuf, w:mutbuf, row:u64, field:u64) -> u64:
    if field == 0:
        return typed_string(s, w, row)
    if field == 1:
        return typed_integer(s, w, row + 16, 1)
    if field == 2:
        return typed_integer(s, w, row + 24, 1)
    if field == 3:
        return typed_integer(s, w, row + 32, 1)
    if field == 4:
        return typed_bool(s, w, row + 40)
    return typed_string(s, w, row + 48)

def parse_candidate(s:readbuf, w:mutbuf, row:u64) -> u64:
    ch = peek(s, w)
    if ch != 91 and ch != 123:
        return unexpected(s, w, 7)
    array = choose(ch == 91, 1, 0)
    close = choose(array == 1, 93, 125)
    put(w, 56, get(w, 56) + 1)
    seen = 0
    index = 0
    while True:
        ch = peek(s, w)
        if ch == close:
            put(w, 56, get(w, 56) + 1)
            if seen != 63:
                if array == 1:
                    return error(w, 104, get(w, 56), index, 1)
                i = 0
                while i < 6:
                    if (seen & (1 << i)) == 0:
                        return error(w, 103, get(w, 56), i, 1)
                    i = i + 1
            return 1
        if ch == 256:
            return error(w, choose(array == 1, 4, 5), get(w, 56), 0, 0)
        if index > 0:
            if ch != 44:
                return error(w, choose(array == 1, 6, 7), get(w, 56) + 1, 0, 0)
            put(w, 56, get(w, 56) + 1)
            ch = peek(s, w)
            if ch == close:
                return error(w, 8, get(w, 56) + 1, 0, 0)
        field = index
        if array == 1:
            if field >= 6:
                return error(w, 105, get(w, 56) + 1, 0, 0)
        else:
            if ch == 256:
                return error(w, 2, get(w, 56), 0, 0)
            if ch != 34:
                return error(w, 9, get(w, 56) + 1, 0, 0)
            if scan_string(s, w) == 0:
                return 0
            field = key_field(w, get(w, 32), get(w, 40), 1)
            if field == 255:
                return error(w, 101, get(w, 56), get(w, 32), get(w, 40))
            if (seen & (1 << field)) != 0:
                return error(w, 102, get(w, 56), field, 1)
            ch = peek(s, w)
            if ch == 256:
                return error(w, 5, get(w, 56), 0, 0)
            if ch != 58:
                return error(w, 11, get(w, 56) + 1, 0, 0)
            put(w, 56, get(w, 56) + 1)
        seen = seen | (1 << field)
        if read_candidate_field(s, w, row, field) == 0:
            return 0
        index = index + 1
    return 0

def parse_candidates(s:readbuf, w:mutbuf) -> u64:
    if peek(s, w) != 91:
        return unexpected(s, w, 5)
    put(w, 56, get(w, 56) + 1)
    count = 0
    while True:
        ch = peek(s, w)
        if ch == 93:
            put(w, 56, get(w, 56) + 1)
            put(w, 304, count)
            return 1
        if ch == 256:
            return error(w, 4, get(w, 56), 0, 0)
        if count > 0:
            if ch != 44:
                return error(w, 6, get(w, 56) + 1, 0, 0)
            put(w, 56, get(w, 56) + 1)
            if peek(s, w) == 93:
                return error(w, 8, get(w, 56) + 1, 0, 0)
        row = 4096 + choose(count < 128, count, 128) * 192
        if parse_candidate(s, w, row) == 0:
            return 0
        count = count + 1
    return 0

def read_request_field(s:readbuf, w:mutbuf, field:u64) -> u64:
    if field == 0:
        return typed_string(s, w, 256)
    if field == 1:
        return typed_string(s, w, 272)
    if field == 2:
        return typed_integer(s, w, 288, 0)
    if field == 3:
        return typed_integer(s, w, 296, 1)
    return parse_candidates(s, w)

def parse_request(s:readbuf, w:mutbuf) -> u64:
    ch = peek(s, w)
    if ch != 91 and ch != 123:
        return unexpected(s, w, 6)
    array = choose(ch == 91, 1, 0)
    close = choose(array == 1, 93, 125)
    put(w, 56, get(w, 56) + 1)
    seen = 0
    index = 0
    while True:
        ch = peek(s, w)
        if ch == close:
            put(w, 56, get(w, 56) + 1)
            if seen != 31:
                if array == 1:
                    return error(w, 104, get(w, 56), index, 0)
                i = 0
                while i < 5:
                    if (seen & (1 << i)) == 0:
                        return error(w, 103, get(w, 56), i, 0)
                    i = i + 1
            if peek(s, w) != 256:
                return error(w, 105, get(w, 56) + 1, 0, 0)
            return 1
        if ch == 256:
            return error(w, choose(array == 1, 4, 5), get(w, 56), 0, 0)
        if index > 0:
            if ch != 44:
                return error(w, choose(array == 1, 6, 7), get(w, 56) + 1, 0, 0)
            put(w, 56, get(w, 56) + 1)
            ch = peek(s, w)
            if ch == close:
                return error(w, 8, get(w, 56) + 1, 0, 0)
        field = index
        if array == 1:
            if field >= 5:
                return error(w, 105, get(w, 56) + 1, 0, 0)
        else:
            if ch == 256:
                return error(w, 2, get(w, 56), 0, 0)
            if ch != 34:
                return error(w, 9, get(w, 56) + 1, 0, 0)
            if scan_string(s, w) == 0:
                return 0
            field = key_field(w, get(w, 32), get(w, 40), 0)
            if field == 255:
                return error(w, 100, get(w, 56), get(w, 32), get(w, 40))
            if (seen & (1 << field)) != 0:
                return error(w, 102, get(w, 56), field, 0)
            ch = peek(s, w)
            if ch == 256:
                return error(w, 5, get(w, 56), 0, 0)
            if ch != 58:
                return error(w, 11, get(w, 56) + 1, 0, 0)
            put(w, 56, get(w, 56) + 1)
        seen = seen | (1 << field)
        if read_request_field(s, w, field) == 0:
            return 0
        index = index + 1
    return 0
'''
def helpers():
    return ''
