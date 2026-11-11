"""Shared HIA authoring for the complete GraphLease bounded-wire owner.

The Python module only authors fixed HIA functions and constants. It never
receives a foreign value or chooses a serialization result.
"""
CONSTANTS = {
    'GRAPH_MAGIC': int.from_bytes(b'HIAGRF01','little'),
    'COMMAND_MAGIC': int.from_bytes(b'HIAGWC01','little'),
    'EVENT_MAGIC': int.from_bytes(b'HIAGWE01','little'),
    'STATE_MAGIC': int.from_bytes(b'HIAGWS01','little'),
    'BAD': 0xfffffffd, 'MAX': (1 << 64)-1,
    'MIN_WORK': 32768, 'FRAME_BASE': 16384, 'FLOAT_BASE': 8192,
    'LITERAL_BASE': 1024, 'CLI_MAXIMUM': (1 << 61)-1,
    'S_CLI_MODE': 568, 'S_CLI_MEASURED': 576,
}
_NAMES = ('MAGIC','PHASE','ERROR','BAD','NEED','LEASE','SEQ','ROOT','MAXIMUM',
          'FLAGS','DIGITS','NODES','EDGES','SCALARS','TOTAL','EDGEBASE','DATABASE',
          'CUR','DEPTH','LEVEL','STAGE','VISITED','QUEUED','ARENA','BUDGET',
          'KEYBASE','HASHBASE','HASHMASK','KEYINDEX','KEYMARK','TMPKIND',
          'TMPOFF','TMPSIZE','CHARS','OUTLEN','OUTBASE','NEXT','SCANEND','CAUSE')
CONSTANTS.update({'S_'+name:256+8*i for i,name in enumerate(_NAMES)})

COMMON = r'''
def read(s:readbuf, at:u64) -> u64:
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

def abi(w:mutbuf, reason:u64) -> u64:
    if get(w, S_BAD) == 0:
        put(w, S_BAD, reason)
    return 0

def error(w:mutbuf, code:u64, cause:u64) -> u64:
    if get(w, S_ERROR) == 0:
        put(w, S_ERROR, code)
        put(w, S_CAUSE, cause)
    return 0

def event(w:mutbuf, action:u64) -> u32:
    put(w, 0, EVENT_MAGIC)
    put(w, 8, action)
    put(w, 16, get(w, S_LEASE))
    put(w, 24, get(w, S_SEQ))
    put(w, 32, get(w, S_ROOT))
    put(w, 40, get(w, S_MAXIMUM))
    put(w, 48, get(w, S_FLAGS))
    put(w, 56, get(w, S_DIGITS))
    put(w, 64, get(w, S_ERROR))
    put(w, 72, get(w, S_CAUSE))
    put(w, 80, get(w, S_NEED))
    put(w, 88, choose(action == 0, get(w, S_OUTBASE), 0))
    put(w, 96, choose(action == 0, get(w, S_OUTLEN), 0))
    put(w, 104, choose(action == 2, 2, 0))
    put(w, 112, get(w, S_PHASE))
    put(w, 120, get(w, S_BAD))
    return 128

def refused(w:mutbuf, reason:u64) -> u32:
    abi(w, reason)
    put(w, S_PHASE, 99)
    event(w, 3)
    return BAD

def pending(w:mutbuf) -> u32:
    if get(w, S_BAD) != 0:
        return refused(w, get(w, S_BAD))
    if get(w, S_ERROR) != 0:
        put(w, S_PHASE, 99)
        return event(w, 3)
    if get(w, S_NEED) > length(w):
        return event(w, 1)
    return refused(w, 90)

def reserve(w:mutbuf, size:u64) -> u64:
    at = get(w, S_ARENA)
    if size > MAX - at:
        return abi(w, 2)
    end = at + size
    if end > length(w):
        put(w, S_NEED, end)
        return 0
    put(w, S_ARENA, end)
    return at

def graph(s:readbuf, r:readbuf, w:mutbuf) -> u64:
    if get(w, S_BAD) != 0 or get(w, S_PHASE) >= 90:
        return 0
    if length(s) < 64 or length(r) != 64:
        return 0
    if read(s, 0) != GRAPH_MAGIC or read(s, 8) == 0 or read(s, 56) != 0:
        return 0
    nodes = read(s, 16)
    edges = read(s, 32)
    if nodes == 0 or nodes > (MAX - 64) >> 6:
        return 0
    edgebase = 64 + nodes * 64
    if edges > (MAX - edgebase) >> 3:
        return 0
    database = edgebase + edges * 8
    if database > length(s) or read(s, 48) != length(s):
        return 0
    if read(s, 40) != length(s) - database:
        return 0
    if read(s, 24) == 0 or read(s, 24) > nodes:
        return 0
    if read(r, 0) != COMMAND_MAGIC or read(r, 8) != read(s, 8):
        return 0
    if read(r, 16) == 0 or read(r, 24) == 0 or read(r, 24) > nodes:
        return 0
    if read(r, 56) != 0:
        return 0
    if read(r, 40) > 3:
        if read(r, 40) != 6 or read(r, 32) != CLI_MAXIMUM:
            return 0
    if get(w, S_MAGIC) == 0:
        fill_range(w, 256, 512, 0)
        put(w, S_MAGIC, STATE_MAGIC)
        put(w, S_PHASE, 1)
        put(w, S_LEASE, read(r, 8))
        put(w, S_SEQ, read(r, 16))
        put(w, S_ROOT, read(r, 24))
        put(w, S_MAXIMUM, read(r, 32))
        put(w, S_FLAGS, read(r, 40))
        put(w, S_DIGITS, read(r, 48))
        put(w, S_NODES, nodes)
        put(w, S_EDGES, edges)
        put(w, S_SCALARS, read(s, 40))
        put(w, S_TOTAL, length(s))
        put(w, S_EDGEBASE, edgebase)
        put(w, S_DATABASE, database)
        put(w, S_CUR, read(r, 24))
        put(w, S_QUEUED, 1)
        put(w, S_ARENA, MIN_WORK)
        maximum = read(r, 32)
        if read(r, 40) == 6:
            put(w, S_BUDGET, MAX)
        else:
            if maximum > 8388608:
                error(w, 1, 0)
            put(w, S_BUDGET, choose(maximum < 262144, maximum, 262144))
    else:
        if get(w, S_MAGIC) != STATE_MAGIC or get(w, S_PHASE) >= 90:
            return 0
        if get(w, S_LEASE) != read(r, 8) or get(w, S_SEQ) != read(r, 16):
            return 0
        if get(w, S_ROOT) != read(r, 24) or get(w, S_MAXIMUM) != read(r, 32):
            return 0
        if get(w, S_FLAGS) != read(r, 40) or get(w, S_DIGITS) != read(r, 48):
            return 0
        if get(w, S_NODES) != nodes or get(w, S_EDGES) != edges:
            return 0
        if get(w, S_SCALARS) != read(s, 40) or get(w, S_TOTAL) != length(s):
            return 0
    put(w, S_NEED, 0)
    return 1

def node(s:readbuf, w:mutbuf, identifier:u64) -> u64:
    if identifier == 0 or identifier > get(w, S_NODES):
        return abi(w, 3)
    at = 64 + (identifier - 1) * 64
    kind = read(s, at)
    if kind > 9 or read(s, at + 56) != 0:
        return abi(w, 4)
    if kind == 5 or kind == 6 or kind == 7:
        if read(s, at + 8) != 0 or read(s, at + 16) != 0:
            return abi(w, 5)
        if read(s, at + 40) == 0 or read(s, at + 48) != 0:
            return abi(w, 6)
        first = read(s, at + 24)
        count = read(s, at + 32)
        if kind == 6:
            if count > MAX >> 1:
                return abi(w, 7)
            count = count * 2
        if first > get(w, S_EDGES) or count > get(w, S_EDGES) - first:
            return abi(w, 8)
        return at
    if read(s, at + 24) != 0 or read(s, at + 32) != 0 or read(s, at + 40) != 0:
        return abi(w, 9)
    begin = read(s, at + 8)
    size = read(s, at + 16)
    aux = read(s, at + 48)
    if kind == 0 or kind == 1 or kind == 8:
        if begin != 0 or size != 0:
            return abi(w, 10)
        if kind == 1:
            if aux > 1:
                return abi(w, 11)
        elif aux != 0:
            return abi(w, 12)
        return at
    if begin < get(w, S_DATABASE) or begin > length(s) or size > length(s) - begin:
        return abi(w, 13)
    if kind == 2:
        if aux > 1 or (size == 0 and aux != 0):
            return abi(w, 14)
        if size > 0 and byte(s, begin + size - 1) == 0:
            return abi(w, 15)
    elif kind == 3:
        if size != 8 or aux != 0:
            return abi(w, 16)
    elif kind == 9 and aux != 0:
        return abi(w, 17)
    return at

def edge(s:readbuf, w:mutbuf, at:u64, index:u64) -> u64:
    total = read(s, at + 32)
    if read(s, at) == 6:
        total = total * 2
    if index >= total:
        return abi(w, 18)
    value = read(s, get(w, S_EDGEBASE) + (read(s, at + 24) + index) * 8)
    if value == 0 or value > get(w, S_NODES):
        return abi(w, 19)
    return value

def bit_length(s:readbuf, at:u64) -> u64:
    size = read(s, at + 16)
    if size == 0:
        return 0
    result = (size - 1) * 8
    value = byte(s, read(s, at + 8) + size - 1)
    while value != 0:
        value = value >> 1
        result = result + 1
    return result

def unit(s:readbuf, w:mutbuf, at:u64, end:u64) -> u64:
    if at >= end:
        abi(w, 20)
        return MAX
    first = byte(s, at)
    if first < 128:
        put(w, S_NEXT, at + 1)
        return first
    count = 0
    point = 0
    minimum = 0
    if first >= 194 and first <= 223:
        count = 2
        point = first & 31
        minimum = 128
    elif first >= 224 and first <= 239:
        count = 3
        point = first & 15
        minimum = 2048
    elif first >= 240 and first <= 244:
        count = 4
        point = first & 7
        minimum = 65536
    else:
        abi(w, 21)
        return MAX
    if count > end - at:
        abi(w, 22)
        return MAX
    i = 1
    while i < count:
        value = byte(s, at + i)
        if value < 128 or value > 191:
            abi(w, 23)
            return MAX
        point = (point << 6) | (value & 63)
        i = i + 1
    if point < minimum or point > 1114111:
        abi(w, 24)
        return MAX
    put(w, S_NEXT, at + count)
    return point

def string_size(s:readbuf, w:mutbuf, at:u64) -> u64:
    maximum = get(w, S_MAXIMUM)
    if maximum < 2 or read(s, at + 48) > maximum - 2:
        return error(w, 2, 0)
    pos = read(s, at + 8)
    end = pos + read(s, at + 16)
    size = 2
    chars = 0
    while pos < end:
        point = unit(s, w, pos, end)
        if point == MAX:
            return 0
        chars = chars + 1
        width = 1
        if point < 32:
            width = choose(point == 8 or point == 9 or point == 10 or point == 12 or point == 13, 2, 6)
        elif point == 34 or point == 92:
            width = 2
        elif point < 128:
            width = choose(point == 127 and (get(w, S_FLAGS) & 1) != 0, 6, 1)
        elif point >= 55296 and point <= 57343:
            return error(w, 3, 0)
        elif (get(w, S_FLAGS) & 1) != 0:
            width = choose(point <= 65535, 6, 12)
        else:
            width = get(w, S_NEXT) - pos
        size = size + width
        if size > maximum:
            return error(w, 2, 0)
        pos = get(w, S_NEXT)
    if chars != read(s, at + 48):
        return abi(w, 25)
    return 1

def literal(w:mutbuf, kind:u64) -> u64:
    value = 1819047278
    size = 4
    if kind == 1:
        value = 435728179558
        size = 5
    elif kind == 2:
        value = 1702195828
    i = 0
    while i < size:
        store(w, LITERAL_BASE + i, (value >> (i * 8)) & 255)
        i = i + 1
    put(w, S_TMPKIND, 2)
    put(w, S_TMPOFF, LITERAL_BASE)
    put(w, S_TMPSIZE, size)
    return 1

def integer_text(s:readbuf, w:mutbuf, at:u64) -> u64:
    size = read(s, at + 16)
    digit_limit = get(w, S_DIGITS)
    bits = bit_length(s, at)
    if digit_limit != 0 and digit_limit <= MAX >> 2:
        if bits > digit_limit * 4:
            return error(w, 15, 1)
    if size > (MAX - 64) >> 3:
        return abi(w, 26)
    base = reserve(w, size * 7 + 64)
    if base == 0:
        return 0
    begin = read(s, at + 8)
    i = 0
    while i < size:
        store(w, base + i, byte(s, begin + i))
        i = i + 1
    reverse = base + size + 16
    used = size
    digits = 0
    while used != 0:
        carry = 0
        i = used
        while i > 0:
            i = i - 1
            value = carry * 256 + byte(w, base + i)
            quotient = (value * 52429) >> 19
            carry = value - quotient * 10
            store(w, base + i, quotient)
        while used > 0 and byte(w, base + used - 1) == 0:
            used = used - 1
        store(w, reverse + digits, 48 + carry)
        digits = digits + 1
    if digits == 0:
        store(w, reverse, 48)
        digits = 1
    if digit_limit != 0 and digits > digit_limit:
        return error(w, 15, 1)
    text = reverse + size * 3 + 8
    cursor = 0
    if read(s, at + 48) != 0:
        store(w, text, 45)
        cursor = 1
    i = digits
    while i > 0:
        i = i - 1
        store(w, text + cursor, byte(w, reverse + i))
        cursor = cursor + 1
    put(w, S_TMPKIND, 2)
    put(w, S_TMPOFF, text)
    put(w, S_TMPSIZE, cursor)
    return 1

def floating(s:readbuf, w:mutbuf, at:u64, key:u64) -> u64:
    bits = read(s, read(s, at + 8))
    if ((bits >> 52) & 2047) == 2047:
        if key != 0:
            return error(w, 10, 0)
        return error(w, 15, 1)
    fill_range(w, FLOAT_BASE, 8192, 0)
    size = fp_render_binary64(w, bits)
    if size == 0 or size > 32:
        return abi(w, 27)
    put(w, S_TMPKIND, 2)
    put(w, S_TMPOFF, FLOAT_BASE + 6144)
    put(w, S_TMPSIZE, size)
    return 1

def key_text(s:readbuf, w:mutbuf, at:u64) -> u64:
    kind = read(s, at)
    if kind == 4:
        if string_size(s, w, at) == 0:
            return 0
        put(w, S_TMPKIND, 1)
        put(w, S_TMPOFF, read(s, at + 8))
        put(w, S_TMPSIZE, read(s, at + 16))
        return 1
    if kind == 0:
        literal(w, 0)
    elif kind == 1:
        literal(w, read(s, at + 48) + 1)
    elif kind == 2:
        if bit_length(s, at) > get(w, S_MAXIMUM) * 4:
            return error(w, 9, 0)
        if integer_text(s, w, at) == 0:
            return 0
    elif kind == 3:
        if floating(s, w, at, 1) == 0:
            return 0
    else:
        return error(w, 8, 0)
    if get(w, S_MAXIMUM) < 2 or get(w, S_TMPSIZE) > get(w, S_MAXIMUM) - 2:
        return error(w, 11, 0)
    return 1

def text_byte(s:readbuf, w:mutbuf, kind:u64, at:u64, i:u64) -> u64:
    if kind == 1:
        return byte(s, at + i)
    return byte(w, at + i)

def text_hash(s:readbuf, w:mutbuf, kind:u64, at:u64, size:u64) -> u64:
    result = 14695981039346656037
    i = 0
    while i < size:
        result = (result ^ text_byte(s, w, kind, at, i)) * 1099511628211
        i = i + 1
    return result

def text_equal(s:readbuf, w:mutbuf, record:u64) -> u64:
    size = get(w, S_TMPSIZE)
    if get(w, record + 24) != size:
        return 0
    i = 0
    while i < size:
        a = text_byte(s, w, get(w, S_TMPKIND), get(w, S_TMPOFF), i)
        b = text_byte(s, w, get(w, record + 8), get(w, record + 16), i)
        if a != b:
            return 0
        i = i + 1
    return 1
'''

