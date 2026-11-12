"""The complete release-kit admission state machine, authored as HIA."""
BODY=r'''
def gate(s:readbuf, r:readbuf, w:mutbuf) -> u32:
    if length(w) < MIN_WORK:
        return BAD
    if get(w, 8) != 0:
        return BAD
    if get(w, 0) == 0:
        return begin(s, r, w)
    if get(w, 0) != WMAGIC:
        return bad(w, 1)
    if length(s) != get(w, 40) or length(s) < 128:
        return bad(w, 2)
    if equal_read_work(s, w, 0, 256, 64) == 0:
        return bad(w, 3)
    phase = get(w, 16)
    if phase == 1:
        if length(r) != 0:
            return bad(w, 4)
        return inventory(s, w)
    if phase == 2 or phase == 3:
        return accept_json(s, r, w, phase)
    if phase == 4:
        return bad(w, 5)
    return bad(w, 6)

def begin(s:readbuf, r:readbuf, w:mutbuf) -> u32:
    if length(s) < 128 or length(r) != 0:
        return bad(w, 7)
    if uint(s, 0) != IMAGIC or uint(s, 8) != 1 or uint(s, 56) != 0:
        return bad(w, 8)
    if uint(s, 48) != length(s) - 64:
        return bad(w, 9)
    if uint(s, 64) != KMAGIC or uint(s, 72) != 1:
        return bad(w, 10)
    if uint(s, 80) > 2 or uint(s, 112) != 0 or uint(s, 120) != 0:
        return bad(w, 11)
    count = uint(s, 88)
    compiler = uint(s, 96)
    cold = uint(s, 104)
    if compiler == 0 or compiler > 1048576 or cold == 0 or cold > 8388608:
        return bad(w, 12)
    if compiler > length(s) - 128 or cold > length(s) - 128 - compiler:
        return bad(w, 13)
    if count == 0 or count > ((length(s) - 128 - compiler - cold) >> 5):
        return bad(w, 14)
    if count > 192153584101141077:
        return bad(w, 15)
    put(w, 0, WMAGIC)
    put(w, 16, 1)
    put(w, 24, 0)
    put(w, 40, length(s))
    put(w, 48, 128)
    put(w, 56, compiler)
    put(w, 64, 128 + compiler)
    put(w, 72, cold)
    put(w, 80, 0)
    put(w, 88, 0)
    put(w, 96, count)
    put(w, 104, 128 + compiler + cold)
    put(w, 336, TABLE + count * 96)
    put(w, 392, uint(s, 80))
    copy_read(s, w, 0, 256, 64)
    hash_range(s, 64, length(s) - 64, w, 640)
    if equal_read_work(s, w, 16, 640, 32) == 0:
        return refused(w, 1)
    hash_range(s, 128, compiler, w, 448)
    return inventory(s, w)

def inventory(s:readbuf, w:mutbuf) -> u32:
    if length(w) < get(w, 336):
        return grow(w, get(w, 336))
    count = get(w, 96)
    index = 0
    cursor = get(w, 104)
    while index < count:
        if cursor > length(s) or length(s) - cursor < 32:
            return bad(w, 16)
        name = uint(s, cursor)
        size = uint(s, cursor + 8)
        if uint(s, cursor + 16) != 0 or uint(s, cursor + 24) != 0 or name == 0:
            return bad(w, 17)
        cursor = cursor + 32
        if name > length(s) - cursor:
            return bad(w, 18)
        start = cursor + name
        if size > length(s) - start:
            return bad(w, 19)
        previous = 0
        while previous < index:
            prior = TABLE + previous * 96
            if get(w, prior + 8) == name:
                if equal_source(s, cursor, get(w, prior), name) == 1:
                    return bad(w, 20)
            previous = previous + 1
        row = TABLE + index * 96
        put(w, row, cursor)
        put(w, row + 8, name)
        put(w, row + 16, start)
        put(w, row + 24, size)
        hash_range(s, start, size, w, row + 32)
        put(w, row + 64, NONE)
        put(w, row + 72, NONE)
        put(w, row + 80, 0)
        put(w, row + 88, 0)
        if literal_source(s, cursor, name, 0) == 1:
            put(w, 80, start)
            put(w, 88, size)
            put(w, 408, index)
        role = 24
        while role <= 30:
            if literal_source(s, cursor, name, role) == 1:
                put(w, 512 + (role - 24) * 16, start)
                put(w, 520 + (role - 24) * 16, size)
            role = role + 1
        cursor = start + size
        index = index + 1
    if cursor != length(s) or get(w, 80) == 0 or get(w, 88) == 0 or get(w, 88) > 8388608:
        return bad(w, 21)
    index = 0
    while index < 7:
        if get(w, 512 + index * 16) == 0:
            return refused(w, 6)
        index = index + 1
    return decode_request(w, get(w, 64), get(w, 72), 2)

def accept_json(s:readbuf, r:readbuf, w:mutbuf, phase:u64) -> u32:
    if length(r) < 64:
        return bad(w, 22)
    if uint(r, 0) != RMAGIC or uint(r, 8) != get(w, 24) or uint(r, 16) != 1:
        return bad(w, 23)
    if uint(r, 40) != 0 or uint(r, 48) != 0 or uint(r, 56) != 0:
        return bad(w, 24)
    result = uint(r, 24)
    size = uint(r, 32)
    if size != length(r) - 64:
        return bad(w, 25)
    if result >= 4294967292:
        if size != 0 or result > 4294967295:
            return bad(w, 26)
        return refused(w, 2)
    if result != size or size < 64:
        return bad(w, 27)
    if arena_valid(s, r, get(w, 376), get(w, 384)) == 0:
        return bad(w, 28)
    cursor = get(w, 336)
    if size > NONE - cursor - 15:
        return bad(w, 29)
    needed = (cursor + size + 15) & 18446744073709551600
    if length(w) < needed:
        return grow(w, needed)
    copy_read(r, w, 64, cursor, size)
    put(w, 336, needed)
    if phase == 2:
        put(w, 344, cursor)
        put(w, 352, size)
        if cold_valid(s, w, cursor) == 0:
            return refused(w, 3)
        return decode_request(w, get(w, 80), get(w, 88), 3)
    put(w, 360, cursor)
    put(w, 368, size)
    if contract_valid(s, w, cursor) == 0:
        return refused(w, 4)
    put(w, 16, 4)
    return event(w, 0, 0, 0, 0, 0)

def arena_valid(s:readbuf, r:readbuf, wire:u64, wire_size:u64) -> u64:
    size = length(r) - 64
    if uint(r, 64) != JMAGIC or uint(r, 104) != wire_size:
        return 0
    count = uint(r, 72)
    base = uint(r, 80)
    if count == 0 or count > 1048576 or base != 64 + count * 56:
        return 0
    if base > size or uint(r, 88) != size or uint(r, 96) != size:
        return 0
    if uint(r, 112) != 1 or uint(r, 120) != 0:
        return 0
    id = 0
    children = 0
    while id < count:
        at = 128 + id * 56
        kind = uint(r, at)
        parent = uint(r, at + 8)
        sibling = uint(r, at + 16)
        start = uint(r, at + 24)
        extent = uint(r, at + 32)
        key = uint(r, at + 40)
        keysz = uint(r, at + 48)
        if kind > 7:
            return 0
        if id == 0:
            if parent != NONE or sibling != NONE or key != 0 or keysz != 0 or kind != 6:
                return 0
        else:
            if parent >= id:
                return 0
            pk = uint(r, 128 + parent * 56)
            if pk != 5 and pk != 6:
                return 0
            if pk == 6:
                if key < base or key > size or keysz > size - key:
                    return 0
            else:
                if key != 0 or keysz != 0:
                    return 0
        if sibling != NONE:
            if sibling <= id or sibling >= count or uint(r, 136 + sibling * 56) != parent:
                return 0
        if kind == 4:
            if start < base or start > size or extent > size - start:
                return 0
        else:
            if kind == 5 or kind == 6:
                if extent == 0:
                    if start != NONE:
                        return 0
                else:
                    if extent > count or start <= id or start >= count:
                        return 0
                    child = start
                    n = 0
                    while child != NONE:
                        if child >= count or n >= extent:
                            return 0
                        cat = 128 + child * 56
                        if uint(r, cat + 8) != id:
                            return 0
                        next = uint(r, cat + 16)
                        if next != NONE and next <= child:
                            return 0
                        child = next
                        n = n + 1
                    if n != extent:
                        return 0
                    children = children + n
            else:
                if start > wire_size or extent == 0 or extent > wire_size - start:
                    return 0
        id = id + 1
    if children != count - 1:
        return 0
    return 1

def cold_valid(s:readbuf, w:mutbuf, base:u64) -> u64:
    if text_is(w, base, field(w, base, 0, 1), 10) == 0:
        return 0
    if text_is(w, base, field(w, base, 0, 2), 12) == 0:
        return 0
    if text_is(w, base, field(w, base, 0, 3), 11) == 0:
        return 0
    value = field(w, base, 0, 4)
    if value == NONE:
        return 0
    at = node(w, base, value)
    if get(w, at) != 3:
        return 0
    start = get(w, 64) + get(w, at + 24)
    size = get(w, at + 32)
    if size == 1:
        if byte(s, start) != 48:
            return 0
    else:
        if size != 2 or byte(s, start) != 45 or byte(s, start + 1) != 48:
            return 0
    checks = field(w, base, 0, 5)
    if checks == NONE:
        return 0
    at = node(w, base, checks)
    if get(w, at) != 6 or get(w, at + 32) != 11:
        return 0
    key = 13
    while key <= 23:
        value = field(w, base, checks, key)
        if value == NONE or get(w, node(w, base, value)) != 2:
            return 0
        key = key + 1
    generations = field(w, base, 0, 6)
    if generations == NONE:
        return 0
    at = node(w, base, generations)
    if get(w, at) != 5 or get(w, at + 32) != 3:
        return 0
    value = get(w, at + 24)
    while value != NONE:
        if digest_is(w, base, value, 448) == 0:
            return 0
        value = get(w, node(w, base, value) + 16)
    sources = field(w, base, 0, 7)
    if sources == NONE:
        return 0
    return source_map_valid(s, w, base, sources, 0)

def contract_valid(s:readbuf, w:mutbuf, base:u64) -> u64:
    if text_is(w, base, field(w, base, 0, 2), 12) == 0:
        return 0
    identity = field(w, base, 0, 8)
    if identity == NONE or get(w, node(w, base, identity)) != 6:
        return 0
    sources = field(w, base, identity, 9)
    if sources == NONE:
        return 0
    return source_map_valid(s, w, base, sources, 1)

def source_map_valid(s:readbuf, w:mutbuf, base:u64, map:u64, exclude:u64) -> u64:
    at = node(w, base, map)
    count = get(w, 96)
    if get(w, at) != 6 or get(w, at + 32) != count - exclude:
        return 0
    index = 0
    while index < count:
        row = TABLE + index * 96
        included = True
        if exclude == 1 and index == get(w, 408):
            included = False
        if included:
            found = NONE
            value = get(w, at + 24)
            while value != NONE:
                entry = node(w, base, value)
                if get(w, entry + 48) == get(w, row + 8):
                    if equal_read_work(s, w, get(w, row), base + get(w, entry + 40), get(w, row + 8)) == 1:
                        if found != NONE:
                            return 0
                        found = value
                value = get(w, entry + 16)
            if digest_is(w, base, found, row + 32) == 0:
                return 0
            put(w, row + 64 + exclude * 8, found)
        index = index + 1
    return 1
'''
