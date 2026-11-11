"""Reconstructed CLI pretty renderer. New identity; no old-run qualification.
Input is private issued compact JSON with canonical scalar spellings and sorted
keys. This owner expands indentation and string escaping without a byte quota.
"""
BODY=r'''
def entry(s:readbuf, r:readbuf, w:mutbuf) -> u32:
    if length(w) < 1024:
        return BAD
    if get(w, 8) != 0:
        return BAD
    if length(r) != 96 or uint(r, 0) != COMMAND or uint(r, 8) != 1:
        return refused(w)
    if uint(r, 16) == 0 or uint(r, 24) == 0 or uint(r, 32) != length(s) or uint(r, 40) != 1 or uint(r, 48) > 1:
        return refused(w)
    i = 56
    while i < 96:
        if uint(r, i) != 0:
            return refused(w)
        i = i + 8
    if length(s) > MAX - STACK:
        return refused(w)
    base = STACK + length(s)
    if get(w, 0) == 0:
        put(w, 0, MAGIC)
        put(w, 16, 1)
        put(w, 24, length(s))
        put(w, 32, uint(r, 16))
        put(w, 40, uint(r, 24))
        put(w, 48, uint(r, 48))
        put(w, OUTBASE, base)
        i = 0
        while i < 96:
            store(w, 512 + i, byte(r, i))
            i = i + 1
    else:
        if get(w, 0) != MAGIC or (get(w, 16) != 1 and get(w, 16) != 2):
            return refused(w)
        if get(w, 24) != length(s) or get(w, OUTBASE) != base or get(w, 32) != uint(r, 16) or get(w, 40) != uint(r, 24) or get(w, 48) != uint(r, 48):
            return refused(w)
        i = 0
        while i < 96:
            if byte(r, i) != byte(w, 512 + i):
                return refused(w)
            i = i + 1
    if length(w) < base:
        return grow(w, base)
    if get(w, 16) == 1:
        put(w, MODE, 0)
        if walk(s, w) == 0:
            return refused(w)
        put(w, NEEDED, get(w, CURSOR))
        put(w, 16, 2)
    needed = get(w, NEEDED)
    if needed <= base:
        return refused(w)
    if needed > length(w):
        return grow(w, needed)
    put(w, MODE, 1)
    if walk(s, w) == 0 or get(w, CURSOR) != needed:
        return refused(w)
    put(w, 16, 3)
    event(w, 0, needed)
    return 128

def refused(w:mutbuf) -> u32:
    put(w, 8, 1)
    put(w, 256, EVENT)
    put(w, 264, 2)
    return BAD

def event(w:mutbuf, action:u64, needed:u64) -> u64:
    i = 0
    while i < 128:
        store(w, 256 + i, 0)
        i = i + 1
    put(w, 256, EVENT)
    put(w, 264, action)
    put(w, 272, get(w, 32))
    put(w, 280, get(w, 40))
    if action == 0:
        put(w, 288, get(w, OUTBASE))
        put(w, 296, needed - get(w, OUTBASE))
    put(w, 304, needed)
    return 0

def grow(w:mutbuf, needed:u64) -> u32:
    event(w, 1, needed)
    return GROW

def fault(w:mutbuf) -> u64:
    put(w, FAULT, 1)
    return 0

def append(w:mutbuf, value:u64) -> u64:
    cursor = get(w, CURSOR)
    if cursor == MAX:
        return fault(w)
    if get(w, MODE) != 0:
        if cursor >= length(w) or cursor >= get(w, NEEDED):
            return fault(w)
        store(w, cursor, value)
    put(w, CURSOR, cursor + 1)
    return 1

def indent(w:mutbuf, depth:u64) -> u64:
    if append(w, 10) == 0:
        return 0
    i = 0
    while i < depth:
        if append(w, 32) == 0 or append(w, 32) == 0:
            return 0
        i = i + 1
    return 1

def walk(s:readbuf, w:mutbuf) -> u64:
    put(w, POS, 0)
    put(w, DEPTH, 0)
    put(w, ROOT, 0)
    put(w, FAULT, 0)
    put(w, CURSOR, get(w, OUTBASE))
    while get(w, POS) < length(s) and get(w, FAULT) == 0:
        ch = byte(s, get(w, POS))
        if ch == 32 or ch == 9 or ch == 10 or ch == 13:
            put(w, POS, get(w, POS) + 1)
        else:
            if step(s, w) == 0:
                return 0
    if get(w, FAULT) != 0 or get(w, DEPTH) != 0 or get(w, ROOT) != 1:
        return 0
    return append(w, 10)

def close(w:mutbuf, value:u64, filled:u64) -> u64:
    depth = get(w, DEPTH)
    if depth == 0:
        return fault(w)
    if filled != 0:
        if indent(w, depth - 1) == 0:
            return 0
    if append(w, value) == 0:
        return 0
    put(w, DEPTH, depth - 1)
    put(w, POS, get(w, POS) + 1)
    return 1

def step(s:readbuf, w:mutbuf) -> u64:
    at = get(w, POS)
    ch = byte(s, at)
    depth = get(w, DEPTH)
    if depth == 0:
        if get(w, ROOT) != 0:
            return fault(w)
        return value(s, w)
    state = byte(w, STACK + depth - 1)
    if state == 2 or state == 7:
        if ch == 44:
            if append(w, 44) == 0 or indent(w, depth) == 0:
                return 0
            store(w, STACK + depth - 1, choose(state == 2, 3, 8))
            put(w, POS, at + 1)
            return 1
        if ch == choose(state == 2, 93, 125):
            return close(w, ch, 1)
        return fault(w)
    if state == 5:
        if ch != 58 or append(w, 58) == 0 or append(w, 32) == 0:
            return fault(w)
        store(w, STACK + depth - 1, 6)
        put(w, POS, at + 1)
        return 1
    if state == 4 or state == 8:
        if state == 4 and ch == 125:
            return close(w, ch, 0)
        if ch != 34:
            return fault(w)
        if state == 4 and indent(w, depth) == 0:
            return 0
        if string(s, w) == 0:
            return 0
        store(w, STACK + depth - 1, 5)
        return 1
    if state == 1 or state == 3:
        if state == 1 and ch == 93:
            return close(w, ch, 0)
        if state == 1 and indent(w, depth) == 0:
            return 0
        return value(s, w)
    if state == 6:
        return value(s, w)
    return fault(w)

def parent_done(w:mutbuf) -> u64:
    depth = get(w, DEPTH)
    if depth == 0:
        put(w, ROOT, 1)
        return 1
    at = STACK + depth - 1
    state = byte(w, at)
    if state == 1 or state == 3:
        store(w, at, 2)
        return 1
    if state == 6:
        store(w, at, 7)
        return 1
    return fault(w)

def value(s:readbuf, w:mutbuf) -> u64:
    if parent_done(w) == 0:
        return 0
    at = get(w, POS)
    ch = byte(s, at)
    if ch == 123 or ch == 91:
        depth = get(w, DEPTH)
        if depth >= length(s) or append(w, ch) == 0:
            return fault(w)
        store(w, STACK + depth, choose(ch == 123, 4, 1))
        put(w, DEPTH, depth + 1)
        put(w, POS, at + 1)
        return 1
    if ch == 34:
        return string(s, w)
    end = MAX
    if ch == 110:
        end = match(s, at, 1819047278, 4)
    elif ch == 116:
        end = match(s, at, 1702195828, 4)
    elif ch == 102:
        end = match(s, at, 435728179558, 5)
    elif ch == 78:
        end = match(s, at, NAN, 3)
    elif ch == 73:
        end = match(s, at, INFINITY, 8)
    elif ch == 45 and length(s) - at >= 2 and byte(s, at + 1) == 73:
        end = match(s, at + 1, INFINITY, 8)
    else:
        end = number(s, at)
    if end == MAX:
        return fault(w)
    while at < end:
        if append(w, byte(s, at)) == 0:
            return 0
        at = at + 1
    put(w, POS, end)
    return 1

def match(s:readbuf, at:u64, bits:u64, count:u64) -> u64:
    if at > length(s) or count > length(s) - at:
        return MAX
    i = 0
    while i < count:
        if byte(s, at + i) != ((bits >> (i * 8)) & 255):
            return MAX
        i = i + 1
    return at + count

def digit_byte(value:u64) -> u64:
    if value >= 48 and value <= 57:
        return 1
    return 0

def number(s:readbuf, at:u64) -> u64:
    end = length(s)
    if byte(s, at) == 45:
        at = at + 1
    if at >= end:
        return MAX
    if byte(s, at) == 48:
        at = at + 1
        if at < end and digit_byte(byte(s, at)) != 0:
            return MAX
    else:
        if byte(s, at) < 49 or byte(s, at) > 57:
            return MAX
        while at < end and digit_byte(byte(s, at)) != 0:
            at = at + 1
    if at < end and byte(s, at) == 46:
        at = at + 1
        first = at
        while at < end and digit_byte(byte(s, at)) != 0:
            at = at + 1
        if at == first:
            return MAX
    if at < end and (byte(s, at) == 101 or byte(s, at) == 69):
        at = at + 1
        if at < end and (byte(s, at) == 43 or byte(s, at) == 45):
            at = at + 1
        first = at
        while at < end and digit_byte(byte(s, at)) != 0:
            at = at + 1
        if at == first:
            return MAX
    return at

def hex4(s:readbuf, at:u64) -> u64:
    if at > length(s) or length(s) - at < 4:
        return MAX
    result = 0
    i = 0
    while i < 4:
        ch = byte(s, at + i)
        v = MAX
        if ch >= 48 and ch <= 57:
            v = ch - 48
        elif ch >= 65 and ch <= 70:
            v = ch - 55
        elif ch >= 97 and ch <= 102:
            v = ch - 87
        if v == MAX:
            return MAX
        result = result * 16 + v
        i = i + 1
    return result

def escape(w:mutbuf, cp:u64) -> u64:
    if append(w, 92) == 0 or append(w, 117) == 0:
        return 0
    i = 4
    while i > 0:
        i = i - 1
        v = (cp >> (i * 4)) & 15
        if append(w, choose(v < 10, v + 48, v + 87)) == 0:
            return 0
    return 1

def encode(w:mutbuf, cp:u64) -> u64:
    if cp == 34 or cp == 92:
        if append(w, 92) == 0:
            return 0
        return append(w, cp)
    if cp == 8 or cp == 9 or cp == 10 or cp == 12 or cp == 13:
        letter = 98
        if cp == 9:
            letter = 116
        elif cp == 10:
            letter = 110
        elif cp == 12:
            letter = 102
        elif cp == 13:
            letter = 114
        if append(w, 92) == 0:
            return 0
        return append(w, letter)
    if cp < 32 or (get(w, 48) != 0 and cp >= 127):
        if cp <= 65535:
            return escape(w, cp)
        cp = cp - 65536
        if escape(w, 55296 + (cp >> 10)) == 0:
            return 0
        return escape(w, 56320 + (cp & 1023))
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

def string(s:readbuf, w:mutbuf) -> u64:
    at = get(w, POS) + 1
    if append(w, 34) == 0:
        return 0
    done = 0
    while at < length(s) and done == 0:
        ch = byte(s, at)
        cp = MAX
        if ch == 34:
            at = at + 1
            done = 1
        elif ch == 92:
            at = at + 1
            if at >= length(s):
                return fault(w)
            ch = byte(s, at)
            at = at + 1
            if ch == 34 or ch == 92 or ch == 47:
                cp = ch
            elif ch == 98:
                cp = 8
            elif ch == 102:
                cp = 12
            elif ch == 110:
                cp = 10
            elif ch == 114:
                cp = 13
            elif ch == 116:
                cp = 9
            elif ch == 117:
                cp = hex4(s, at)
                if cp == MAX:
                    return fault(w)
                at = at + 4
                if cp >= 55296 and cp <= 56319 and length(s) - at >= 6:
                    if byte(s, at) == 92 and byte(s, at + 1) == 117:
                        low = hex4(s, at + 2)
                        if low >= 56320 and low <= 57343:
                            cp = 65536 + ((cp - 55296) << 10) + low - 56320
                            at = at + 6
            if cp == MAX:
                return fault(w)
        else:
            if ch < 32:
                return fault(w)
            cp = point(s, w, at, length(s))
            if cp == MAX:
                return fault(w)
            at = get(w, 168)
        if done == 0 and encode(w, cp) == 0:
            return 0
    if done == 0 or append(w, 34) == 0:
        return fault(w)
    put(w, POS, at)
    return 1
'''
