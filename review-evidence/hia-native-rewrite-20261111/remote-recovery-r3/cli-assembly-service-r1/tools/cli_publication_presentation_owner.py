"""Native publication path quoting and Linux CLI error text, new revision 1.
Assembly policy adds two fixed messages without renumbering old codes.
Tables are generated under the exact CPython 3.12.14 / Unicode 15 C-locale
development profile. All decoding, quoting and final text executes as HIA.
This is not a locale-selection owner, traceback renderer or arbitrary foreign
Python-object formatter. Caller owns the immutable source and command leases.
"""
import sys,os,locale,unicodedata
from hashlib import sha256
CONSTANTS={
 "BAD":0xfffffffd,"GROW":0xfffffffe,"MAX":(1<<64)-1,
 "COMMAND":int.from_bytes(b"HIAPSC01","little"),"STATE":int.from_bytes(b"HIAPSS01","little"),
 "EVENT":int.from_bytes(b"HIAPSE01","little"),
 "PHASE":16,"LEASE":24,"SEQ":32,"KIND":40,"NUMBER":48,"HAS_PATH":56,
 "SOURCE_N":64,"USED":72,"OUT":80,"CURSOR":88,"MODE":96,"NEXT":104,
 "FAULT":112,"NEEDED":120,"QUOTE":128,"ENCODE_ERROR":136,
 "ENCODE_START":144,"ENCODE_END":152,"ENCODE_POINT":160,"HEADER":384,"DIGITS":512,
 "ERROR_INDEX":1024,"RANGE_BASE":4096,
}
FIXED=(
 b"E_HIA_EDIT: destination must be a new file",
 b"E_HIA_EDIT: output parent must not traverse symlinks",
 b"JSON output must be a new file",
 b"JSON output parent must not traverse a symlink",
 b"No usable temporary directory name found",
 b"invalid buffering size",
 b"Cannot call rmtree on a symbolic link",
 b"Symlink loop from ",
 b"write could not complete without blocking",
 b"[Errno ",
 b"] ",
 b": ",
 b"Unknown error ",
 b"\'utf-8\' codec can\'t encode ",
 b"character \'",
 b"\' in position ",
 b"characters in position ",
 b": surrogates not allowed",
 b"Assembly output must be a new file",
 b"Assembly output parent must not traverse a symlink",
)
BODY=r'''
def entry(s:readbuf, r:readbuf, w:mutbuf) -> u32:
    if length(w) < BASE:
        return BAD
    if get(w, 8) != 0:
        return BAD
    if valid(s, r) == 0:
        return refused(w)
    if get(w, 0) == 0:
        put(w, 0, STATE)
        put(w, PHASE, 1)
        put(w, LEASE, uint(r, 16))
        put(w, SEQ, uint(r, 24))
        put(w, KIND, uint(r, 32))
        put(w, NUMBER, uint(r, 40))
        put(w, HAS_PATH, uint(r, 48))
        put(w, SOURCE_N, length(s))
        put(w, OUT, BASE + length(s))
        copy_read(w, r, HEADER, 0, 96)
        tables(w)
    else:
        if get(w, 0) != STATE or get(w, PHASE) == 3 or get(w, PHASE) == 0:
            return refused(w)
        if get(w, PHASE) > 2 or get(w, SOURCE_N) != length(s) or get(w, OUT) != BASE + length(s):
            return refused(w)
        i = 0
        while i < 96:
            if byte(r, i) != byte(w, HEADER + i):
                return refused(w)
            i = i + 1
    if length(w) < get(w, OUT):
        return growing(w, get(w, OUT))
    if get(w, PHASE) == 1:
        copy_read(w, s, BASE, 0, length(s))
        put(w, MODE, 0)
        if render(s, w) == 0:
            return refused(w)
        put(w, NEEDED, get(w, CURSOR))
        put(w, PHASE, 2)
    else:
        i = 0
        while i < length(s):
            if byte(s, i) != byte(w, BASE + i):
                return refused(w)
            i = i + 1
    if get(w, NEEDED) > length(w):
        return growing(w, get(w, NEEDED))
    put(w, MODE, 1)
    if render(s, w) == 0 or get(w, CURSOR) != get(w, NEEDED):
        return refused(w)
    put(w, PHASE, 3)
    emit(w, 0, get(w, NEEDED))
    return 128

def valid(s:readbuf, r:readbuf) -> u64:
    if length(r) != 96 or uint(r, 0) != COMMAND or uint(r, 8) != 1:
        return 0
    if uint(r, 16) == 0 or uint(r, 24) == 0 or uint(r, 56) != length(s) or length(s) > MAX - BASE:
        return 0
    kind = uint(r, 32)
    n = uint(r, 40)
    path = uint(r, 48)
    if kind < 1 or kind > 7 or path > 1:
        return 0
    if kind == 1 or kind == 5 or kind == 6 or kind == 7:
        if n != 0 or path != 0:
            return 0
    elif kind == 2:
        if n == 0 or n > 4095 or (path == 0 and length(s) != 0):
            return 0
    elif kind == 3:
        if n == 0 or n > 4095 or path != 0 or length(s) != 0:
            return 0
    else:
        if n == 0 or (n > 8 and n != 19 and n != 20):
            return 0
        if path != 0 and n != 7:
            return 0
        if n != 8 and (n != 7 or path == 0) and length(s) != 0:
            return 0
    i = 64
    while i < 96:
        if uint(r, i) != 0:
            return 0
        i = i + 8
    return 1

def refused(w:mutbuf) -> u32:
    put(w, 8, 1)
    emit(w, 6, 0)
    return BAD

def growing(w:mutbuf, need:u64) -> u32:
    emit(w, 1, need)
    return GROW

def emit(w:mutbuf, action:u64, need:u64) -> u64:
    zero(w, 256, 128)
    put(w, 256, EVENT)
    put(w, 264, action)
    put(w, 272, get(w, LEASE))
    put(w, 280, get(w, SEQ))
    put(w, 288, get(w, KIND))
    if action == 0:
        put(w, 296, get(w, OUT))
        put(w, 304, get(w, CURSOR) - get(w, OUT))
    put(w, 312, need)
    if action == 0:
        put(w, 320, get(w, ENCODE_ERROR))
    return 0

def append(w:mutbuf, value:u64) -> u64:
    at = get(w, CURSOR)
    if at == MAX:
        put(w, FAULT, 1)
        return 0
    if get(w, MODE) != 0:
        if at >= length(w) or at >= get(w, NEEDED):
            put(w, FAULT, 1)
            return 0
        store(w, at, value)
    put(w, CURSOR, at + 1)
    return 1

def span(w:mutbuf, at:u64, n:u64) -> u64:
    i = 0
    while i < n:
        if append(w, byte(w, at + i)) == 0:
            return 0
        i = i + 1
    return 1

def fixed(w:mutbuf, code:u64) -> u64:
    if code == 0 or code > 20:
        return 0
    at = FIXED_INDEX + (code - 1) * 16
    return span(w, get(w, at), get(w, at + 8))

def decimal(w:mutbuf, value:u64) -> u64:
    count = 0
    if value == 0:
        return append(w, 48)
    while value != 0:
        q = divide10(value)
        store(w, DIGITS + count, 48 + value - q * 10)
        count = count + 1
        value = q
    while count != 0:
        count = count - 1
        if append(w, byte(w, DIGITS + count)) == 0:
            return 0
    return 1

def divide10(value:u64) -> u64:
    q = 0
    rem = 0
    bit = 64
    while bit != 0:
        bit = bit - 1
        rem = (rem << 1) | ((value >> bit) & 1)
        if rem >= 10:
            rem = rem - 10
            q = q | (1 << bit)
    return q

def render(s:readbuf, w:mutbuf) -> u64:
    put(w, CURSOR, get(w, OUT))
    put(w, FAULT, 0)
    kind = get(w, KIND)
    if kind == 6 or kind == 7:
        return encoded_text(s, w)
    if kind == 1:
        return quoted_json(s, w)
    if kind == 5:
        return quoted_repr(s, w)
    if kind == 4:
        code = get(w, NUMBER)
        if code == 7 and get(w, HAS_PATH) == 1:
            if fixed(w, 10) == 0:
                return 0
            if append(w, 78) == 0 or append(w, 111) == 0 or append(w, 110) == 0 or append(w, 101) == 0:
                return 0
            if fixed(w, 11) == 0:
                return 0
            if append(w, 78) == 0 or append(w, 111) == 0 or append(w, 110) == 0 or append(w, 101) == 0:
                return 0
            if fixed(w, 12) == 0:
                return 0
            return quoted_repr(s, w)
        if code == 5:
            if fixed(w, 10) == 0 or decimal(w, 17) == 0 or fixed(w, 11) == 0:
                return 0
        if fixed(w, code) == 0:
            return 0
        if code == 8:
            return quoted_repr(s, w)
        return 1
    if fixed(w, 10) == 0 or decimal(w, get(w, NUMBER)) == 0 or fixed(w, 11) == 0:
        return 0
    if kind == 3:
        return fixed(w, 9)
    number = get(w, NUMBER)
    if number <= 133:
        at = ERROR_INDEX + number * 16
        if span(w, get(w, at), get(w, at + 8)) == 0:
            return 0
    else:
        if fixed(w, 13) == 0 or decimal(w, number) == 0:
            return 0
    if get(w, HAS_PATH) != 0:
        if fixed(w, 12) == 0:
            return 0
        return quoted_repr(s, w)
    return 1


def encoded_text(s:readbuf, w:mutbuf) -> u64:
    put(w, ENCODE_ERROR, 0)
    at = 0
    position = 0
    while at < length(s):
        cp = point(s, w, at, 0)
        if cp == MAX:
            return 0
        at = get(w, NEXT)
        if cp >= 55296 and cp <= 57343:
            if get(w, KIND) == 6 and (cp < 56448 or cp > 56575):
                put(w, ENCODE_ERROR, 1)
                put(w, ENCODE_START, position)
                put(w, ENCODE_POINT, cp)
                position = position + 1
                while at < length(s):
                    cp = point(s, w, at, 0)
                    if cp == MAX:
                        return 0
                    if cp < 55296 or cp > 57343:
                        put(w, ENCODE_END, position)
                        return encode_error(w)
                    at = get(w, NEXT)
                    position = position + 1
                put(w, ENCODE_END, position)
                return encode_error(w)
        position = position + 1
    at = 0
    while at < length(s):
        cp = point(s, w, at, 0)
        if cp == MAX:
            return 0
        at = get(w, NEXT)
        if cp >= 55296 and cp <= 57343:
            if get(w, KIND) == 6:
                if cp < 56448 or cp > 56575 or append(w, cp - 56320) == 0:
                    return 0
            elif escape(w, 117, cp, 4) == 0:
                return 0
        elif unicode_out(w, cp) == 0:
            return 0
    return 1

def encode_error(w:mutbuf) -> u64:
    if fixed(w, 14) == 0:
        return 0
    begin = get(w, ENCODE_START)
    end = get(w, ENCODE_END)
    if end == begin + 1:
        if fixed(w, 15) == 0 or escape(w, 117, get(w, ENCODE_POINT), 4) == 0 or fixed(w, 16) == 0:
            return 0
        if decimal(w, begin) == 0:
            return 0
    else:
        if fixed(w, 17) == 0 or decimal(w, begin) == 0 or append(w, 45) == 0 or decimal(w, end - 1) == 0:
            return 0
    return fixed(w, 18)

def point(s:readbuf, w:mutbuf, at:u64, raw:u64) -> u64:
    first = byte(s, at)
    put(w, NEXT, at + 1)
    if first < 128:
        return first
    count = 0
    result = 0
    if first >= 194 and first <= 223:
        count = 2
        result = first & 31
    elif first >= 224 and first <= 239:
        count = 3
        result = first & 15
    elif first >= 240 and first <= 244:
        count = 4
        result = first & 7
    if count != 0 and count <= length(s) - at:
        i = 1
        while i < count:
            part = byte(s, at + i)
            if part < 128 or part > 191:
                count = 0
            else:
                result = (result << 6) | (part & 63)
                i = i + 1
        if count != 0:
            minimum = 128
            if count == 3:
                minimum = 2048
            elif count == 4:
                minimum = 65536
            if result < minimum or result > 1114111:
                count = 0
            elif raw != 0 and result >= 55296 and result <= 57343:
                count = 0
            if count != 0:
                put(w, NEXT, at + count)
                return result
    if raw != 0:
        return 56320 + first
    return MAX

def unicode_out(w:mutbuf, cp:u64) -> u64:
    if cp < 128:
        return append(w, cp)
    if cp < 2048:
        if append(w, 192 | (cp >> 6)) == 0:
            return 0
    elif cp < 65536:
        if append(w, 224 | (cp >> 12)) == 0 or append(w, 128 | ((cp >> 6) & 63)) == 0:
            return 0
    else:
        if append(w, 240 | (cp >> 18)) == 0 or append(w, 128 | ((cp >> 12) & 63)) == 0 or append(w, 128 | ((cp >> 6) & 63)) == 0:
            return 0
    return append(w, 128 | (cp & 63))

def escape(w:mutbuf, code:u64, cp:u64, digits:u64) -> u64:
    if append(w, 92) == 0 or append(w, code) == 0:
        return 0
    while digits != 0:
        digits = digits - 1
        part = (cp >> (digits * 4)) & 15
        value = part + 48
        if part >= 10:
            value = part + 87
        if append(w, value) == 0:
            return 0
    return 1

def short_escape(w:mutbuf, code:u64) -> u64:
    if append(w, 92) == 0:
        return 0
    return append(w, code)

def quoted_json(s:readbuf, w:mutbuf) -> u64:
    if append(w, 34) == 0:
        return 0
    at = 0
    while at < length(s):
        cp = point(s, w, at, 0)
        if cp == MAX:
            return 0
        at = get(w, NEXT)
        ok = 0
        if cp == 34 or cp == 92:
            ok = short_escape(w, cp)
        elif cp == 8:
            ok = short_escape(w, 98)
        elif cp == 12:
            ok = short_escape(w, 102)
        elif cp == 10:
            ok = short_escape(w, 110)
        elif cp == 13:
            ok = short_escape(w, 114)
        elif cp == 9:
            ok = short_escape(w, 116)
        elif cp < 32 or cp >= 127:
            if cp < 65536:
                ok = escape(w, 117, cp, 4)
            else:
                cp = cp - 65536
                if escape(w, 117, 55296 + (cp >> 10), 4) == 0:
                    return 0
                ok = escape(w, 117, 56320 + (cp & 1023), 4)
        else:
            ok = append(w, cp)
        if ok == 0:
            return 0
    return append(w, 34)

def printable(cp:u64, w:mutbuf) -> u64:
    lo = 0
    hi = RANGE_COUNT
    while lo < hi:
        mid = (lo + hi) >> 1
        pair = get(w, RANGE_BASE + mid * 8)
        start = pair & 4294967295
        end = pair >> 32
        if cp < start:
            hi = mid
        elif cp > end:
            lo = mid + 1
        else:
            return 1
    return 0

def quoted_repr(s:readbuf, w:mutbuf) -> u64:
    at = 0
    singles = 0
    doubles = 0
    while at < length(s):
        cp = point(s, w, at, 1)
        if cp == 39:
            singles = 1
        elif cp == 34:
            doubles = 1
        at = get(w, NEXT)
    quote = 39
    if singles != 0 and doubles == 0:
        quote = 34
    put(w, QUOTE, quote)
    if append(w, quote) == 0:
        return 0
    at = 0
    while at < length(s):
        cp = point(s, w, at, 1)
        at = get(w, NEXT)
        ok = 0
        if cp == quote or cp == 92:
            ok = short_escape(w, cp)
        elif cp == 9:
            ok = short_escape(w, 116)
        elif cp == 10:
            ok = short_escape(w, 110)
        elif cp == 13:
            ok = short_escape(w, 114)
        elif printable(cp, w) == 0:
            if cp < 256:
                ok = escape(w, 120, cp, 2)
            elif cp < 65536:
                ok = escape(w, 117, cp, 4)
            else:
                ok = escape(w, 85, cp, 8)
        else:
            ok = unicode_out(w, cp)
        if ok == 0:
            return 0
    return append(w, quote)

def copy_read(w:mutbuf, s:readbuf, target:u64, at:u64, count:u64) -> u64:
    i = 0
    while i < count:
        store(w, target + i, byte(s, at + i))
        i = i + 1
    return 0

def zero(w:mutbuf, at:u64, count:u64) -> u64:
    i = 0
    while i < count:
        store(w, at + i, 0)
        i = i + 1
    return 0

def uint(s:readbuf, at:u64) -> u64:
    result = 0
    i = 0
    while i < 8:
        result = result | (byte(s, at + i) << (i * 8))
        i = i + 1
    return result

def get(w:mutbuf, at:u64) -> u64:
    result = 0
    i = 0
    while i < 8:
        result = result | (byte(w, at + i) << (i * 8))
        i = i + 1
    return result

def put(w:mutbuf, at:u64, value:u64) -> u64:
    i = 0
    while i < 8:
        store(w, at + i, (value >> (i * 8)) & 255)
        i = i + 1
    return 0
'''
def source():
    assert sys.version_info[:3]==(3,12,14),sys.version
    assert unicodedata.unidata_version=="15.0.0"
    assert locale.setlocale(locale.LC_MESSAGES) in ("C","C.UTF-8","C.utf8","POSIX")
    ranges=[];start=None
    for cp in range(0x110000):
        yes=chr(cp).isprintable()
        if yes and start is None:start=cp
        if start is not None and (not yes or cp==0x10ffff):
            ranges.append((start,cp-1 if not yes else cp));start=None
    constants=dict(CONSTANTS);constants["RANGE_COUNT"]=len(ranges)
    constants["FIXED_INDEX"]=constants["RANGE_BASE"]+len(ranges)*8
    text_base=(constants["FIXED_INDEX"]+len(FIXED)*16+7)&~7
    raw=bytearray(text_base)
    for i,(a,b) in enumerate(ranges):
        raw[constants["RANGE_BASE"]+i*8:constants["RANGE_BASE"]+i*8+8]=(a|(b<<32)).to_bytes(8,"little")
    messages=[]
    for n in range(134):
        value=os.strerror(n).encode("ascii");messages.append(value.decode("ascii"))
        at=len(raw);raw.extend(value)
        row=constants["ERROR_INDEX"]+n*16
        raw[row:row+8]=at.to_bytes(8,"little");raw[row+8:row+16]=len(value).to_bytes(8,"little")
    for i,value in enumerate(FIXED):
        at=len(raw);raw.extend(value);row=constants["FIXED_INDEX"]+i*16
        raw[row:row+8]=at.to_bytes(8,"little");raw[row+8:row+16]=len(value).to_bytes(8,"little")
    constants["BASE"]=(len(raw)+255)&~255
    data=bytes(raw)
    writes=[(at,int.from_bytes(data[at:at+8].ljust(8,b"\0"),"little")) for at in range(1024,len(data),8)]
    # Twenty-four literal words per helper are checked by the original profile/compiler gates.
    chunks=[];calls=[]
    for begin in range(0,len(writes),24):
        index=begin//24;name=f"table_{index}";calls.append(f"    {name}(w)")
        lines=[f"def {name}(w:mutbuf) -> u64:"]
        lines += [f"    put(w, {at}, {value})" for at,value in writes[begin:begin+24]]
        lines += ["    return 0"];chunks.append("\n".join(lines)+"\n")
    tables="def tables(w:mutbuf) -> u64:\n"+"\n".join(calls)+"\n    return 0\n"
    meta=dict(python=sys.version,unicode=unicodedata.unidata_version,
        locale=locale.setlocale(locale.LC_MESSAGES),ranges=ranges,errno=messages,
        table_bytes=len(data),table_sha256=sha256(data).hexdigest(),base=constants["BASE"])
    return BODY+tables+"\n".join(chunks),constants,meta
