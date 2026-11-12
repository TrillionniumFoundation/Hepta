"""Private Graph operations and complete read result construction.

All offsets are relative to a source-bound HIAGRF01 lease. The read business
returns a complete native Graph value; the host never reconstructs a dictionary.
Unreachable private shapes are ABI refusals, not new public language errors.
"""
GRAPH=r'''
def rd_graph_valid(g:readbuf, w:mutbuf, lease:u64) -> u64:
    if length(g) < 64 or rd_word(g, 0) != RD_GRAPH_MAGIC:
        return rd_badset(w, 100)
    if rd_word(g, 8) != lease or lease == 0 or rd_word(g, 56) != 0:
        return rd_badset(w, 101)
    n = rd_word(g, 16)
    e = rd_word(g, 32)
    if n == 0 or n > (RD_MAX - 64) >> 6:
        return rd_badset(w, 102)
    base = 64 + n * 64
    if e > (RD_MAX - base) >> 3:
        return rd_badset(w, 103)
    base = base + e * 8
    if base > length(g) or rd_word(g, 48) != length(g):
        return rd_badset(w, 104)
    if rd_word(g, 40) != length(g) - base or rd_word(g, 24) == 0 or rd_word(g, 24) > n:
        return rd_badset(w, 105)
    return 1

def rd_node(g:readbuf, w:mutbuf, identifier:u64) -> u64:
    if identifier == 0 or identifier > rd_word(g, 16):
        return rd_badset(w, 106)
    at = 64 + (identifier - 1) * 64
    kind = rd_word(g, at)
    if kind > 9 or rd_word(g, at + 56) != 0:
        return rd_badset(w, 107)
    begin = rd_word(g, at + 8)
    size = rd_word(g, at + 16)
    if kind == 5 or kind == 6 or kind == 7:
        if begin != 0 or size != 0 or rd_word(g, at + 40) == 0 or rd_word(g, at + 48) != 0:
            return rd_badset(w, 108)
        first = rd_word(g, at + 24)
        count = rd_word(g, at + 32)
        if kind == 6:
            if count > RD_MAX >> 1:
                return rd_badset(w, 109)
            count = count * 2
        if first > rd_word(g, 32) or count > rd_word(g, 32) - first:
            return rd_badset(w, 110)
        return at
    if rd_word(g, at + 24) != 0 or rd_word(g, at + 32) != 0 or rd_word(g, at + 40) != 0:
        return rd_badset(w, 111)
    aux = rd_word(g, at + 48)
    if kind == 0 or kind == 1 or kind == 8:
        if begin != 0 or size != 0:
            return rd_badset(w, 112)
        if kind == 1:
            if aux > 1:
                return rd_badset(w, 113)
        elif aux != 0:
            return rd_badset(w, 114)
        return at
    base = 64 + rd_word(g, 16) * 64 + rd_word(g, 32) * 8
    if begin < base or begin > length(g) or size > length(g) - begin:
        return rd_badset(w, 115)
    if kind == 2:
        if aux > 1 or (size == 0 and aux != 0):
            return rd_badset(w, 116)
        if size != 0:
            if byte(g, begin + size - 1) == 0:
                return rd_badset(w, 117)
    elif kind == 3:
        if size != 8 or aux != 0:
            return rd_badset(w, 118)
    elif kind == 9 and aux != 0:
        return rd_badset(w, 119)
    return at

def rd_kind(g:readbuf, w:mutbuf, identifier:u64) -> u64:
    if identifier == 0:
        return RD_MAX
    at = rd_node(g, w, identifier)
    if at == 0:
        return RD_MAX
    return rd_word(g, at)

def rd_edge(g:readbuf, w:mutbuf, at:u64, index:u64) -> u64:
    count = rd_word(g, at + 32)
    if rd_word(g, at) == 6:
        count = count * 2
    if index >= count:
        return rd_badset(w, 120)
    base = 64 + rd_word(g, 16) * 64
    value = rd_word(g, base + (rd_word(g, at + 24) + index) * 8)
    if value == 0 or value > rd_word(g, 16):
        return rd_badset(w, 121)
    return value

def rd_field(g:readbuf, w:mutbuf, identifier:u64, literal:u64) -> u64:
    at = rd_node(g, w, identifier)
    if at == 0 or rd_word(g, at) != 6:
        return rd_badset(w, 122)
    result = 0
    i = 0
    while i < rd_word(g, at + 32):
        key = rd_edge(g, w, at, i * 2)
        value = rd_edge(g, w, at, i * 2 + 1)
        key_at = rd_node(g, w, key)
        if key_at == 0 or rd_word(g, key_at) != 4:
            return rd_badset(w, 123)
        if rd_matches(g, key_at, literal) != 0:
            if result != 0:
                return rd_badset(w, 124)
            result = value
        i = i + 1
    return result

def rd_string_equal(a:readbuf, b:readbuf, w:mutbuf, left:u64, right:u64) -> u64:
    x = rd_node(a, w, left)
    y = rd_node(b, w, right)
    if x == 0 or y == 0:
        return 0
    if rd_word(a, x) != 4 or rd_word(b, y) != 4:
        return 0
    n = rd_word(a, x + 16)
    if n != rd_word(b, y + 16):
        return 0
    i = 0
    while i < n:
        if byte(a, rd_word(a, x + 8) + i) != byte(b, rd_word(b, y + 8) + i):
            return 0
        i = i + 1
    return 1

def rd_string_bytes(g:readbuf, w:mutbuf, identifier:u64) -> u64:
    at = rd_node(g, w, identifier)
    if at == 0 or rd_word(g, at) != 4:
        rd_badset(w, 125)
        return 0
    return rd_word(g, at + 16)

def rd_ref_bytes(g:readbuf, w:mutbuf) -> u64:
    at = rd_node(g, w, rd_get(w, R_REF))
    if at == 0:
        return 0
    total = 0
    i = 0
    while i < 6:
        identifier = rd_edge(g, w, at, i)
        size = rd_string_bytes(g, w, identifier)
        if size > RD_MAX - total:
            rd_badset(w, 126)
            return 0
        total = total + size
        i = i + 1
    return total

def rd_graph_begin(w:mutbuf, nodes:u64, edges:u64, pool:u64) -> u64:
    base = 64 + nodes * 64 + edges * 8
    if pool > RD_MAX - base or base + pool > RD_MAX - RD_GRAPH_BASE:
        return rd_badset(w, 127)
    needed = RD_GRAPH_BASE + base + pool
    if needed > length(w):
        rd_put(w, R_NEED, needed)
        return 0
    if rd_get(w, R_GRAPH_GENERATION) == RD_MAX:
        return rd_badset(w, 128)
    rd_put(w, R_GRAPH_GENERATION, rd_get(w, R_GRAPH_GENERATION) + 1)
    fill_range(w, RD_GRAPH_BASE, base, 0)
    rd_put(w, R_GRAPH_NODES, nodes)
    rd_put(w, R_GRAPH_EDGES, edges)
    rd_put(w, R_GRAPH_DATABASE, base)
    rd_put(w, R_GRAPH_USED, 0)
    rd_put(w, R_GRAPH_ROOT, 1)
    return 1

def rd_graph_finish(w:mutbuf) -> u64:
    total = rd_get(w, R_GRAPH_DATABASE) + rd_get(w, R_GRAPH_USED)
    rd_put(w, RD_GRAPH_BASE, RD_GRAPH_MAGIC)
    rd_put(w, RD_GRAPH_BASE + 8, rd_get(w, R_OUT_LEASE))
    rd_put(w, RD_GRAPH_BASE + 16, rd_get(w, R_GRAPH_NODES))
    rd_put(w, RD_GRAPH_BASE + 24, 1)
    rd_put(w, RD_GRAPH_BASE + 32, rd_get(w, R_GRAPH_EDGES))
    rd_put(w, RD_GRAPH_BASE + 40, rd_get(w, R_GRAPH_USED))
    rd_put(w, RD_GRAPH_BASE + 48, total)
    rd_put(w, RD_GRAPH_BASE + 56, 0)
    rd_put(w, R_GRAPH_BYTES, total)
    return choose(rd_get(w, R_BAD_REASON) == 0, 1, 0)

def rd_graph_node(w:mutbuf, id:u64, kind:u64, begin:u64, size:u64, first:u64, count:u64, aux:u64) -> u64:
    if id == 0 or id > rd_get(w, R_GRAPH_NODES):
        return rd_badset(w, 129)
    at = RD_GRAPH_BASE + 64 + (id - 1) * 64
    rd_put(w, at, kind)
    rd_put(w, at + 8, begin)
    rd_put(w, at + 16, size)
    rd_put(w, at + 24, first)
    rd_put(w, at + 32, count)
    rd_put(w, at + 40, choose(kind == 5 or kind == 6, id, 0))
    rd_put(w, at + 48, aux)
    rd_put(w, at + 56, 0)
    return 1

def rd_graph_edge(w:mutbuf, index:u64, id:u64) -> u64:
    if index >= rd_get(w, R_GRAPH_EDGES) or id == 0 or id > rd_get(w, R_GRAPH_NODES):
        return rd_badset(w, 130)
    at = RD_GRAPH_BASE + 64 + rd_get(w, R_GRAPH_NODES) * 64 + index * 8
    rd_put(w, at, id)
    return 1

def rd_graph_pool(w:mutbuf, size:u64) -> u64:
    begin = rd_get(w, R_GRAPH_DATABASE) + rd_get(w, R_GRAPH_USED)
    if begin > length(w) - RD_GRAPH_BASE or size > length(w) - RD_GRAPH_BASE - begin:
        rd_badset(w, 131)
        return 0
    rd_put(w, R_GRAPH_USED, rd_get(w, R_GRAPH_USED) + size)
    return begin

def rd_graph_string(g:readbuf, w:mutbuf, id:u64, start:u64, size:u64, chars:u64) -> u64:
    begin = rd_graph_pool(w, size)
    if begin == 0:
        return 0
    copy_bytes(w, g, RD_GRAPH_BASE + begin, start, size)
    return rd_graph_node(w, id, 4, begin, size, 0, 0, chars)

def rd_graph_existing(g:readbuf, w:mutbuf, id:u64, source:u64) -> u64:
    at = rd_node(g, w, source)
    if at == 0 or rd_word(g, at) != 4:
        return rd_badset(w, 132)
    return rd_graph_string(g, w, id, rd_word(g, at + 8), rd_word(g, at + 16), rd_word(g, at + 48))

def rd_graph_literal(w:mutbuf, id:u64, code:u64) -> u64:
    size = rd_literal_size(code)
    begin = rd_graph_pool(w, size)
    if begin == 0:
        return 0
    if rd_literal(w, code, RD_GRAPH_BASE + begin) != size:
        return rd_badset(w, 133)
    return rd_graph_node(w, id, 4, begin, size, 0, 0, size)

def rd_graph_cursor(w:mutbuf, id:u64) -> u64:
    begin = rd_graph_pool(w, 69)
    if begin == 0:
        return 0
    i = 0
    while i < 69:
        store(w, RD_GRAPH_BASE + begin + i, byte(w, RD_CURSOR + i))
        i = i + 1
    return rd_graph_node(w, id, 4, begin, 69, 0, 0, 69)

def rd_graph_integer(w:mutbuf, id:u64, sign:u64, magnitude:u64) -> u64:
    size = 0
    value = magnitude
    while value != 0:
        size = size + 1
        value = value >> 8
    begin = rd_graph_pool(w, size)
    if begin == 0:
        return 0
    i = 0
    while i < size:
        store(w, RD_GRAPH_BASE + begin + i, (magnitude >> (i * 8)) & 255)
        i = i + 1
    return rd_graph_node(w, id, 2, begin, size, 0, 0, choose(size == 0, 0, sign))

def rd_graph_ref(g:readbuf, w:mutbuf, id:u64, firstnode:u64, firstedge:u64) -> u64:
    at = rd_node(g, w, rd_get(w, R_REF))
    if at == 0:
        return 0
    rd_graph_node(w, id, 6, 0, 0, firstedge, 3, 0)
    i = 0
    while i < 6:
        source = rd_edge(g, w, at, i)
        if rd_graph_existing(g, w, firstnode + i, source) == 0:
            return 0
        rd_graph_edge(w, firstedge + i, firstnode + i)
        i = i + 1
    return 1

def rd_build_cursor_select(g:readbuf, w:mutbuf) -> u64:
    source = rd_get(w, R_CURSOR)
    size = rd_string_bytes(g, w, source)
    if rd_get(w, R_BAD_REASON) != 0:
        return 0
    if rd_graph_begin(w, 2, 1, size) == 0:
        return 0
    rd_graph_node(w, 1, 5, 0, 0, 0, 1, 0)
    rd_graph_edge(w, 0, 2)
    if rd_graph_existing(g, w, 2, source) == 0:
        return 0
    return rd_graph_finish(w)

def rd_build_digest(g:readbuf, w:mutbuf) -> u64:
    pool = rd_ref_bytes(g, w)
    if rd_get(w, R_BAD_REASON) != 0 or pool > RD_MAX - 22:
        return rd_badset(w, 134)
    if rd_graph_begin(w, 11, 10, pool + 22) == 0:
        return 0
    rd_graph_node(w, 1, 6, 0, 0, 0, 2, 0)
    rd_graph_literal(w, 2, 1)
    rd_graph_ref(g, w, 3, 6, 4)
    rd_graph_literal(w, 4, 7)
    rd_graph_integer(w, 5, rd_get(w, R_NEXT_SIGN), rd_get(w, R_NEXT_MAG))
    i = 0
    while i < 4:
        rd_graph_edge(w, i, i + 2)
        i = i + 1
    return rd_graph_finish(w)

def rd_build_cursor_insert(g:readbuf, w:mutbuf) -> u64:
    x = rd_string_bytes(g, w, rd_get(w, R_REF_ID))
    y = rd_string_bytes(g, w, rd_get(w, R_REF_SHA))
    if rd_get(w, R_BAD_REASON) != 0 or x > RD_MAX - 77 or y > RD_MAX - 77 - x:
        return rd_badset(w, 135)
    if rd_graph_begin(w, 5, 4, x + y + 77) == 0:
        return 0
    rd_graph_node(w, 1, 5, 0, 0, 0, 4, 0)
    rd_graph_cursor(w, 2)
    rd_graph_existing(g, w, 3, rd_get(w, R_REF_ID))
    rd_graph_existing(g, w, 4, rd_get(w, R_REF_SHA))
    rd_graph_integer(w, 5, rd_get(w, R_NEXT_SIGN), rd_get(w, R_NEXT_MAG))
    i = 0
    while i < 4:
        rd_graph_edge(w, i, i + 2)
        i = i + 1
    return rd_graph_finish(w)

def rd_build_wire_string(r:readbuf, w:mutbuf) -> u64:
    start = rd_get(w, R_REPLY_AT)
    size = rd_get(w, R_REPLY_SIZE)
    end = rd_prefix(r, w, start, size)
    if end != start + size:
        return rd_badset(w, 136)
    chars = rd_get(w, R_UTF8_CHARS)
    if rd_graph_begin(w, 1, 0, size) == 0:
        return 0
    rd_graph_string(r, w, 1, start, size, chars)
    return rd_graph_finish(w)

def rd_build_result(g:readbuf, w:mutbuf) -> u64:
    pool = rd_ref_bytes(g, w)
    extra = rd_get(w, R_CONTENT_BYTES) + 40
    if rd_get(w, R_HAS_CURSOR) != 0:
        extra = extra + 69
    if rd_get(w, R_BAD_REASON) != 0 or pool > RD_MAX - extra:
        return rd_badset(w, 137)
    if rd_graph_begin(w, 15, 14, pool + extra) == 0:
        return 0
    rd_graph_node(w, 1, 6, 0, 0, 0, 4, 0)
    rd_graph_literal(w, 2, 1)
    rd_graph_ref(g, w, 3, 10, 8)
    rd_graph_literal(w, 4, 8)
    rd_graph_literal(w, 5, choose(rd_get(w, R_ENCODING) == 0, 11, 12))
    rd_graph_literal(w, 6, 9)
    rd_graph_content(w, 7)
    rd_graph_literal(w, 8, 10)
    if rd_get(w, R_HAS_CURSOR) != 0:
        rd_graph_cursor(w, 9)
    i = 0
    while i < 8:
        rd_graph_edge(w, i, i + 2)
        i = i + 1
    return rd_graph_finish(w)
'''
