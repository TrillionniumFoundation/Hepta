"""RECONSTRUCTED after environment loss; new source, never old-run identity.
HIA owns UTF-8 filesystem decoding, COLUMNS/int parsing and argv packet layout.
The fixed issuer captures OS bytes only. No public foreign-packet authentication.
"""
BODY=r'''
def entry(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < 1024:
        return BAD
    if get(w, 8) != 0:
        return BAD
    if get(w, 0) == 0:
        put(w, 0, C_MAGIC)
        put(w, 16, 1)
        put(w, 24, length(s))
        if source_valid(s, w) == 0:
            return refused(w)
        copy_source(s, w, 0, 512, 96)
        put(w, 32, uint(s, 16))
        put(w, 40, uint(s, 24))
    else:
        if get(w, 0) != C_MAGIC or get(w, 16) != 1 or length(s) != get(w, 24) or length(s) < 96:
            return refused(w)
        i = 0
        while i < 96:
            if byte(s, i) != byte(w, 512 + i):
                return refused(w)
            i = i + 1
        if source_valid(s, w) == 0:
            return refused(w)
    if length(w) < BASE:
        return grow(w, BASE)
    nd_initialize(w)
    columns = effective_columns(s, w)
    argc = get(w, 32)
    output_count = 0
    if argc != 0:
        output_count = argc - 1
    if output_count > (MAX - BASE - 64) >> 4:
        return refused(w)
    data = BASE + 64 + output_count * 16
    put(w, 48, 0)
    put(w, 56, data)
    put(w, 64, 0)
    argv_values(s, w, argc)
    if get(w, 64) != 0:
        return refused(w)
    needed = get(w, 56)
    put(w, 72, needed)
    put(w, 80, columns)
    if needed > length(w):
        return grow(w, needed)
    put(w, BASE, ARG_MAGIC)
    put(w, BASE + 8, 1)
    put(w, BASE + 16, output_count)
    put(w, BASE + 24, 64)
    put(w, BASE + 32, data - BASE)
    put(w, BASE + 40, needed - BASE)
    put(w, BASE + 48, columns)
    put(w, BASE + 56, 0)
    put(w, 48, 1)
    put(w, 56, data)
    argv_values(s, w, argc)
    if get(w, 64) != 0 or get(w, 56) != needed:
        return refused(w)
    put(w, 16, 2)
    event(w, 0, needed)
    return 128

def refused(w:mutbuf) -> u32:
    put(w, 8, 1)
    put(w, 256, C_EVENT)
    put(w, 264, 2)
    return BAD

def event(w:mutbuf, action:u64, needed:u64) -> u64:
    i = 0
    while i < 128:
        store(w, 256 + i, 0)
        i = i + 1
    put(w, 256, C_EVENT)
    put(w, 264, action)
    if action == 0:
        put(w, 272, BASE)
        put(w, 280, needed - BASE)
        argc = get(w, 32)
        if argc != 0:
            put(w, 288, argc - 1)
        put(w, 296, get(w, 80))
    put(w, 304, needed)
    return 0

def grow(w:mutbuf, needed:u64) -> u32:
    event(w, 1, needed)
    return GROW

def copy_source(s:readbuf, w:mutbuf, at:u64, out:u64, size:u64) -> u64:
    i = 0
    while i < size:
        store(w, out + i, byte(s, at + i))
        i = i + 1
    return 0

def source_valid(s:readbuf, w:mutbuf) -> u64:
    if length(s) < 96 or uint(s, 0) != SOURCE_MAGIC or uint(s, 8) != 1 or uint(s, 32) != 96 or uint(s, 48) != length(s):
        return 0
    if uint(s, 80) != 0 or uint(s, 88) != 0:
        return 0
    count = uint(s, 16)
    envc = uint(s, 24)
    if envc > MAX - count:
        return 0
    count = count + envc
    if count > (length(s) - 96) >> 4 or uint(s, 40) != 96 + count * 16:
        return 0
    at = uint(s, 40)
    i = 0
    while i < count:
        row = 96 + i * 16
        size = uint(s, row + 8)
        if uint(s, row) != at or at > length(s) or size > length(s) - at:
            return 0
        end = at + size
        while at < end:
            if byte(s, at) == 0:
                return 0
            at = at + 1
        i = i + 1
    if at != length(s):
        return 0
    return 1

def filesystem_point(s:readbuf, w:mutbuf, at:u64, end:u64) -> u64:
    value = point(s, w, at, end)
    if value == MAX or (value >= 55296 and value <= 57343):
        put(w, 168, at + 1)
        return 56320 + byte(s, at)
    return value

def append(w:mutbuf, value:u64) -> u64:
    at = get(w, 56)
    if at == MAX:
        put(w, 64, 1)
        return 0
    if get(w, 48) != 0:
        if at >= length(w):
            put(w, 64, 1)
            return 0
        store(w, at, value)
    put(w, 56, at + 1)
    return 0

def encode_point(w:mutbuf, cp:u64) -> u64:
    if cp < 128:
        append(w, cp)
    elif cp < 2048:
        append(w, 192 | (cp >> 6))
        append(w, 128 | (cp & 63))
    elif cp < 65536:
        append(w, 224 | (cp >> 12))
        append(w, 128 | ((cp >> 6) & 63))
        append(w, 128 | (cp & 63))
    else:
        append(w, 240 | (cp >> 18))
        append(w, 128 | ((cp >> 12) & 63))
        append(w, 128 | ((cp >> 6) & 63))
        append(w, 128 | (cp & 63))
    return 0

def argv_values(s:readbuf, w:mutbuf, argc:u64) -> u64:
    i = 1
    while i < argc:
        row = 96 + i * 16
        at = uint(s, row)
        end = at + uint(s, row + 8)
        start = get(w, 56)
        while at < end:
            value = filesystem_point(s, w, at, end)
            at = get(w, 168)
            encode_point(w, value)
        if get(w, 48) != 0:
            out = BASE + 64 + (i - 1) * 16
            put(w, out, start - BASE)
            put(w, out + 8, get(w, 56) - start)
        i = i + 1
    return 0

def whitespace(cp:u64) -> u64:
    if (cp >= 9 and cp <= 13) or cp == 32 or cp == 133 or cp == 160 or cp == 5760:
        return 1
    if (cp >= 8192 and cp <= 8202) or cp == 8232 or cp == 8233 or cp == 8239 or cp == 8287 or cp == 12288:
        return 1
    return 0

def digit(w:mutbuf, cp:u64) -> u64:
    i = 0
    while i < NDCOUNT:
        begin = get(w, NDTAB + i * 16)
        if cp >= begin and cp <= get(w, NDTAB + i * 16 + 8):
            value = cp - begin
            while value >= 10:
                value = value - 10
            return value
        i = i + 1
    return MAX

def columns_value(s:readbuf, w:mutbuf, at:u64, end:u64) -> u64:
    start = at
    last = at
    seen = 0
    while at < end:
        cp = filesystem_point(s, w, at, end)
        if whitespace(cp) == 0:
            if seen == 0:
                start = at
                seen = 1
            last = get(w, 168)
        at = get(w, 168)
    if seen == 0:
        return 0
    at = start
    negative = 0
    if byte(s, at) == 43 or byte(s, at) == 45:
        if byte(s, at) == 45:
            negative = 1
        at = at + 1
    total = 0
    digits = 0
    previous_digit = 0
    saturated = 0
    while at < last:
        cp = filesystem_point(s, w, at, last)
        at = get(w, 168)
        if cp == 95:
            if previous_digit == 0:
                return 0
            previous_digit = 0
        else:
            d = digit(w, cp)
            if d == MAX:
                return 0
            digits = digits + 1
            if digits > 4300:
                return 0
            previous_digit = 1
            if saturated == 0:
                if total > 1844674407370955161 or (total == 1844674407370955161 and d > 5):
                    saturated = 1
                    total = MAX
                else:
                    total = total * 10 + d
    if previous_digit == 0 or digits == 0 or negative != 0:
        return 0
    return total

def effective_columns(s:readbuf, w:mutbuf) -> u64:
    argc = get(w, 32)
    envc = get(w, 40)
    i = 0
    selected = 0
    found = 0
    while i < envc and found == 0:
        row = 96 + (argc + i) * 16
        at = uint(s, row)
        size = uint(s, row + 8)
        if size >= 8:
            if uint(s, at) == COLUMNS:
                found = 1
                selected = columns_value(s, w, at + 8, at + size)
        i = i + 1
    if selected != 0:
        return selected
    if uint(s, 72) == 0 and uint(s, 56) != 0:
        return uint(s, 56)
    return 80
'''
