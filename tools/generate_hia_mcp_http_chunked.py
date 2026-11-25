"""Incremental HTTP/1 chunked-body decoding in HIA.

The caller owns connection IO and its total request-body limit. The emitted
module owns byte consumption, chunk grammar, extension/trailer limits and
trailer syntax. This Python file only authors the checked-in HIA program.
"""
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_mcp_service import document

STATE_MAGIC=int.from_bytes(b'HIAHCS01','little')
REPLY_MAGIC=int.from_bytes(b'HIAHCK01','little')
ERRORS={
1:'Invalid chunk size line: missing size digit',
2:'Invalid chunk size line: Invalid Size',
3:'Invalid chunk size linear white space',
4:'invalid chunk size: overflow',
5:'invalid chunk extension contains newline',
6:'chunk extensions over limit',
7:'Invalid chunk size LF',
8:'Invalid chunk body CR',
9:'Invalid chunk body LF',
10:'chunk trailers bytes over limit',
11:'chunk trailers count overflow',
12:'Invalid trailer end LF',
13:'Invalid chunk end LF',
14:'invalid header name',
15:'invalid header value',
16:'invalid newline',
17:'too many headers',
18:'Partial header',
19:'unexpected EOF during chunk size line',
20:'end of file before message length reached',
}
SOURCE=r'''
def chunked(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) > 65536 or length(o) < 128 + length(s) or length(w) != 32768:
        return 4294967293
    control = get(o, 0)
    if control > 2:
        return 4294967293
    if control == 1:
        index = 0
        while index < 128:
            put(w, index, 0)
            index = index + 8
        put(w, 0, STATE_MAGIC)
    if get(w, 0) != STATE_MAGIC or get(w, 8) > 12 or get(w, 24) > 16384 or get(w, 32) > 16384 or get(w, 40) > 100 or get(w, 48) > 20:
        return 4294967293
    consumed = 0
    produced = 0
    while consumed < length(s) and get(w, 8) != 12 and get(w, 48) == 0:
        if get(w, 8) == 5:
            count = length(s) - consumed
            remaining = get(w, 16)
            if count > remaining:
                count = remaining
            index = 0
            while index < count:
                store(o, 128 + produced + index, byte(s, consumed + index))
                index = index + 1
            consumed = consumed + count
            produced = produced + count
            put(w, 16, remaining - count)
            if count == remaining:
                put(w, 8, 6)
        else:
            ch = byte(s, consumed)
            consumed = consumed + 1
            error = step(w, ch)
            if error != 0:
                put(w, 48, error)
    if control == 2 and get(w, 48) == 0 and get(w, 8) != 12:
        put(w, 48, choose(get(w, 8) == 5, 20, 19))
    status = 0
    if get(w, 48) != 0:
        status = 2
    elif get(w, 8) == 12:
        status = 1
    put(o, 0, REPLY_MAGIC)
    put(o, 8, status)
    put(o, 16, consumed)
    put(o, 24, produced)
    put(o, 32, get(w, 48))
    put(o, 40, get(w, 24))
    put(o, 48, get(w, 40))
    put(o, 56, get(w, 32))
    index = 64
    while index < 128:
        put(o, index, 0)
        index = index + 8
    return 128 + produced

def step(w:mutbuf, ch:u64) -> u64:
    phase = get(w, 8)
    if phase == 0 or phase == 1:
        value = hex_digit(ch)
        if value < 16:
            size = get(w, 16)
            if size > 1152921504606846975:
                return 4
            put(w, 16, size * 16 + value)
            put(w, 8, 1)
            return 0
        if phase == 0:
            return 1
        if ch == 9 or ch == 32:
            put(w, 8, 2)
            return 0
        if ch == 59:
            put(w, 8, 3)
            return 0
        if ch == 13:
            put(w, 8, 4)
            return 0
        return 2
    if phase == 2:
        if ch == 9 or ch == 32:
            return 0
        if ch == 59:
            put(w, 8, 3)
            return 0
        if ch == 13:
            put(w, 8, 4)
            return 0
        return 3
    if phase == 3:
        if ch == 13:
            put(w, 8, 4)
            return 0
        if ch == 10:
            return 5
        count = get(w, 24) + 1
        put(w, 24, count)
        if count >= 16384:
            return 6
        return 0
    if phase == 4:
        if ch != 10:
            return 7
        put(w, 8, choose(get(w, 16) == 0, 10, 5))
        return 0
    if phase == 6:
        if ch != 13:
            return 8
        put(w, 8, 7)
        return 0
    if phase == 7:
        if ch != 10:
            return 9
        put(w, 8, 0)
        return 0
    if phase == 8:
        result = trailer_byte(w, ch)
        if result != 0:
            return result
        if ch == 13:
            put(w, 8, 9)
        return 0
    if phase == 9:
        if ch != 10:
            return 12
        count = get(w, 40)
        if count >= 100:
            return 11
        put(w, 40, count + 1)
        result = trailer_byte(w, ch)
        if result != 0:
            return result
        put(w, 8, 10)
        return 0
    if phase == 10:
        if ch == 13:
            if get(w, 32) != 0:
                result = trailer_byte(w, ch)
                if result != 0:
                    return result
            put(w, 8, 11)
            return 0
        result = trailer_byte(w, ch)
        if result != 0:
            return result
        put(w, 8, 8)
        return 0
    if phase == 11:
        if ch != 10:
            return 13
        if get(w, 32) != 0:
            result = trailer_byte(w, ch)
            if result != 0:
                return result
            result = trailers(w)
            if result != 0:
                return result
        put(w, 8, 12)
        return 0
    return 19

def trailer_byte(w:mutbuf, ch:u64) -> u64:
    size = get(w, 32)
    if size >= 16384:
        return 10
    store(w, 128 + size, ch)
    put(w, 32, size + 1)
    if size + 1 >= 16384:
        return 10
    return 0

def trailers(w:mutbuf) -> u64:
    at = 0
    size = get(w, 32)
    count = 0
    maximum = get(w, 40)
    while at < size:
        ch = byte(w, 128 + at)
        if ch == 10:
            return 0
        if ch == 13:
            if at + 1 == size:
                return 18
            if byte(w, 129 + at) != 10:
                return 16
            return 0
        if count == maximum:
            return 17
        begin = at
        while at < size and token(byte(w, 128 + at)):
            at = at + 1
        if at == size:
            return 18
        if at == begin or byte(w, 128 + at) != 58:
            return 14
        at = at + 1
        while at < size and (byte(w, 128 + at) == 9 or byte(w, 128 + at) == 32):
            at = at + 1
        while at < size and byte(w, 128 + at) != 13 and byte(w, 128 + at) != 10:
            ch = byte(w, 128 + at)
            if (ch < 32 and ch != 9) or ch == 127:
                return 15
            at = at + 1
        if at == size:
            return 18
        if byte(w, 128 + at) == 13:
            if at + 1 == size:
                return 18
            if byte(w, 129 + at) != 10:
                return 16
            at = at + 2
        else:
            at = at + 1
        count = count + 1
    return 18

def hex_digit(ch:u64) -> u64:
    if ch >= 48 and ch <= 57:
        return ch - 48
    if ch >= 65 and ch <= 70:
        return ch - 55
    if ch >= 97 and ch <= 102:
        return ch - 87
    return 16

def token(ch:u64) -> bool:
    if ch >= 48 and ch <= 57:
        return True
    if ch >= 65 and ch <= 90:
        return True
    if ch >= 97 and ch <= 122:
        return True
    return ch == 33 or ch == 35 or ch == 36 or ch == 37 or ch == 38 or ch == 39 or ch == 42 or ch == 43 or ch == 45 or ch == 46 or ch == 94 or ch == 95 or ch == 96 or ch == 124 or ch == 126

def get(w:mutbuf, at:u64) -> u64:
    return word_load(w, at)

def put(w:mutbuf, at:u64, value:u64) -> u64:
    word_store(w, at, value)
    return 0
'''

def program():
    source=SOURCE.replace('STATE_MAGIC',str(STATE_MAGIC)).replace('REPLY_MAGIC',str(REPLY_MAGIC))
    return document(source,'mcp_http_chunked')

if __name__=='__main__':
    (Path(__file__).resolve().parents[1]/'examples/hia_bootstrap/mcp_http_chunked.hepta').write_text(render_assembly(program()))
