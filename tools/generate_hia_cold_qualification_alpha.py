"""Author source-dependent alpha renaming of the canonical compiler syntax.

The current source is independently admitted before and after this operation.
No code body or successor bytes are stored here. Function labels are input data;
every local/block label is derived from this invocation's actual definitions.
"""
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_cold_document import document

ROOT = Path(__file__).resolve().parents[1]

SOURCE = r'''def alpha(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 33 or word_load(s, 0) != MAGIC or length(w) < 262144:
        return 4294967295
    count = word_load(s, 8)
    size = word_load(s, 16)
    if count == 0 or count > 128 or size == 0 or size > 1048576 or word_load(s, 24) != 0:
        return 4294967295
    pos = 32
    index = 0
    while index < count:
        if length(s) - pos < 8:
            return 4294967295
        n = word_load(s, pos)
        pos = pos + 8
        if n == 0 or n > 128 or n > length(s) - pos:
            return 4294967295
        i = 0
        while i < n:
            if ident(byte(s, pos + i)) == 0 or (i == 0 and byte(s, pos + i) >= 48 and byte(s, pos + i) <= 57):
                return 4294967295
            i = i + 1
        put(w, 200000 + index * 16, pos)
        put(w, 200008 + index * 16, n)
        pos = pos + n
        index = index + 1
    if size != length(s) - pos:
        return 4294967295
    end = length(s)
    first = pos
    while first < end and byte(s, first) != 10:
        first = first + 1
    if first == end:
        return 4294967295
    put(w, 16, 0)
    if emit(s, o, w, pos, first + 1 - pos) == 0:
        return 4294967294
    begin = first + 1
    index = 0
    while begin < end:
        if index == count or end - begin < 7 or uint(s, begin, 4) != 1713409638:
            return 4294967295
        number = decimal(s, w, begin + 4, end)
        if number != index or get(w, 24) >= end or byte(s, get(w, 24)) != 40:
            return 4294967295
        finish = begin + 1
        while finish + 5 <= end and uint(s, finish, 5) != 44701466122:
            finish = finish + 1
        if finish + 5 > end:
            return 4294967295
        finish = finish + 5
        fill_range(w, 4096, 65536 + 2048, 0)
        if definitions(s, w, begin, finish) == 0:
            return 4294967295
        pos = begin
        while pos < finish:
            c = byte(s, pos)
            token = 0
            after = pos + 1
            ordinal = 0
            prefix = 0
            if (c == 102 or c == 118 or c == 98) and pos + 1 < finish:
                if (pos == begin or ident(byte(s, pos - 1)) == 0) and byte(s, pos + 1) >= 48 and byte(s, pos + 1) <= 57:
                    number = decimal(s, w, pos + 1, finish)
                    after = get(w, 24)
                    if after == finish or ident(byte(s, after)) == 0:
                        token = 1
            if token == 0:
                if emit(s, o, w, pos, 1) == 0:
                    return 4294967294
                pos = pos + 1
            else:
                if c == 102:
                    if number >= count or emit(s, o, w, get(w, 200000 + number * 16), get(w, 200008 + number * 16)) == 0:
                        return 4294967295
                else:
                    if c == 118:
                        if number > 8191 or get(w, 4096 + number * 8) == 0:
                            return 4294967295
                        ordinal = get(w, 4096 + number * 8) - 1
                        put(w, 1000, 104875570490988)
                        prefix = 6
                    else:
                        if number > 255 or get(w, 69632 + number * 8) == 0:
                            return 4294967295
                        ordinal = get(w, 69632 + number * 8) - 1
                        put(w, 1000, 407575195502)
                        prefix = 5
                    if emit_word(o, w, 1000, prefix) == 0 or emit_number(o, w, index) == 0 or emit_char(o, w, 95) == 0 or emit_number(o, w, ordinal) == 0:
                        return 4294967294
                pos = after
        begin = finish
        index = index + 1
    if index != count:
        return 4294967295
    return get(w, 16)

def definitions(s:readbuf, w:mutbuf, begin:u64, end:u64) -> u64:
    pos = begin
    locals = 0
    blocks = 0
    while pos < end:
        c = byte(s, pos)
        if (c == 118 or c == 98) and pos + 1 < end and (pos == begin or ident(byte(s, pos - 1)) == 0):
            if byte(s, pos + 1) >= 48 and byte(s, pos + 1) <= 57:
                number = decimal(s, w, pos + 1, end)
                after = get(w, 24)
                if c == 118 and after < end and byte(s, after) == 58:
                    if number > 8191:
                        return 0
                    if get(w, 4096 + number * 8) == 0:
                        put(w, 4096 + number * 8, locals + 1)
                        locals = locals + 1
                if c == 98 and pos >= begin + 6 and uint(s, pos - 6, 6) == 35414008179810 and after < end and byte(s, after) == 40:
                    if number > 255 or get(w, 69632 + number * 8) != 0:
                        return 0
                    put(w, 69632 + number * 8, blocks + 1)
                    blocks = blocks + 1
        pos = pos + 1
    return choose(blocks > 0, 1, 0)

def decimal(s:readbuf, w:mutbuf, at:u64, end:u64) -> u64:
    value = 0
    while at < end and byte(s, at) >= 48 and byte(s, at) <= 57:
        if value > 8191:
            return 18446744073709551615
        value = value * 10 + byte(s, at) - 48
        at = at + 1
    put(w, 24, at)
    return value

def ident(c:u64) -> u64:
    return choose((c >= 65 and c <= 90) or (c >= 97 and c <= 122) or (c >= 48 and c <= 57) or c == 95, 1, 0)

def emit(s:readbuf, o:mutbuf, w:mutbuf, at:u64, count:u64) -> u64:
    dest = get(w, 16)
    if dest > length(o) or count > length(o) - dest or dest + count > 1048576:
        return 0
    i = 0
    while i < count:
        store(o, dest + i, byte(s, at + i))
        i = i + 1
    put(w, 16, dest + count)
    return 1

def emit_word(o:mutbuf, w:mutbuf, at:u64, count:u64) -> u64:
    i = 0
    while i < count:
        if emit_char(o, w, byte(w, at + i)) == 0:
            return 0
        i = i + 1
    return 1

def emit_char(o:mutbuf, w:mutbuf, value:u64) -> u64:
    dest = get(w, 16)
    if dest >= length(o) or dest >= 1048576:
        return 0
    store(o, dest, value)
    put(w, 16, dest + 1)
    return 1

def emit_number(o:mutbuf, w:mutbuf, value:u64) -> u64:
    divisor = 10000
    started = 0
    while divisor > 0:
        digit = 0
        while value >= divisor:
            value = value - divisor
            digit = digit + 1
        if digit > 0 or started == 1 or divisor == 1:
            if emit_char(o, w, 48 + digit) == 0:
                return 0
            started = 1
        if divisor == 10000:
            divisor = 1000
        else:
            if divisor == 1000:
                divisor = 100
            else:
                if divisor == 100:
                    divisor = 10
                else:
                    if divisor == 10:
                        divisor = 1
                    else:
                        divisor = 0
    return 1

def uint(s:readbuf, at:u64, size:u64) -> u64:
    result = 0
    i = 0
    while i < size:
        result = result | (byte(s, at + i) << (8 * i))
        i = i + 1
    return result

def get(w:mutbuf, at:u64) -> u64:
    return word_load(w, at)

def put(w:mutbuf, at:u64, value:u64) -> u64:
    i = 0
    while i < 8:
        store(w, at + i, (value >> (8 * i)) & 255)
        i = i + 1
    return 0
'''


def source():
    text=SOURCE.replace('MAGIC',str(int.from_bytes(b'HIAQAL01','little')))
    for old,raw in [(1713409638,b'fn f'),(44701466122,b'\nend\n'),(104875570490988,b'local_'),(407575195502,b'node_'),(35414008179810,b'block ')]:
        text=text.replace(str(old),str(int.from_bytes(raw,'little')))
    return text


if __name__=='__main__':
    path=ROOT/'examples/hia_bootstrap/cold_qualification_alpha.hepta'
    path.write_text(render_assembly(document(source(),'cold_qualification_alpha')))
    print(path.name,path.stat().st_size)
