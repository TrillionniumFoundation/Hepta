"""Static HIA page-source selection and raw pread accumulation.

Selection is the walFindFrame expensive-assert reverse lookup over the held
wal-index's aPgno, not a search for a commit at the physical WAL tail. Arbitrary
SHM region numbers are mapped one at a time after fd/size checks. No Python
page provider or SQL implementation is present.
"""
SOURCE = r'''
def page_begin(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if word(s, 64) == 0 or word(s, 64) > get(w, 136) or get(w, 280) == 18446744073709551615:
        return ABI
    put(w, 224, word(s, 64))
    put(w, 232, 0)
    put(w, 280, get(w, 280) + 1)
    put(w, 360, 0)
    put(w, 200, get(w, 144))
    if get(w, 160) == 0 or get(w, 144) == 0:
        return database_page(o, w)
    return index_prepare(o, w)

def index_prepare(o:mutbuf, w:mutbuf) -> u32:
    if get(w, 200) == 0 or get(w, 200) < get(w, 152):
        return database_page(o, w)
    # WALINDEX_HDR_SIZE=136; first aPgno array has 4096-34=4062 entries.
    # For later regions each aPgno array has exactly 4096 entries.
    region = (get(w, 200) + 33) >> 12
    zero = 0
    start = 136
    if region != 0:
        zero = region * 4096 - 34
        start = 0
    first = zero + 1
    if first < get(w, 152):
        first = get(w, 152)
    put(w, 192, region)
    put(w, 208, first)
    put(w, 216, get(w, 200) - first + 1)
    put(w, 344, start + (first - zero - 1) * 4)
    if region == 0:
        return index_copy(o, w, 0)
    if (get(w, 96) & 16) != 0:
        if get(w, 184) == region:
            return index_copy(o, w, 1)
        return issue(o, w, 41, 8, 2, 1, 0, 0)
    return issue(o, w, 40, 2, 2, 0, 0, 0)

def index_copy(o:mutbuf, w:mutbuf, slot:u64) -> u32:
    return issue(o, w, 43, 6, 2, get(w, 344), get(w, 216) * 4, slot)

def index_return(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    phase = get(w, 8)
    if phase == 41:
        if word(s, 48) != 0 or word(s, 56) != 0:
            return fail(o, w, 1, word(s, 48))
        put(w, 96, get(w, 96) & 239)
        return issue(o, w, 40, 2, 2, 0, 0, 0)
    if phase == 40:
        if regular_stat(s) == 0:
            return fail(o, w, 1, word(s, 48))
        if word(s, 128) != get(w, 328) or word(s, 136) != get(w, 336):
            return fail(o, w, 5, 0)
        if word(s, 176) < (get(w, 192) + 1) * 32768:
            return fail(o, w, 5, 0)
        return issue(o, w, 42, 5, 2, get(w, 192), 1, 0)
    if phase == 42:
        if word(s, 48) > 9223372036854775807 or word(s, 56) != 0:
            return fail(o, w, 1, word(s, 48))
        put(w, 96, get(w, 96) | 16)
        put(w, 184, get(w, 192))
        return index_copy(o, w, 1)
    if word(s, 48) != 0 or word(s, 56) != get(w, 216) * 4:
        return fail(o, w, 1, word(s, 48))
    index = get(w, 216)
    while index > 0:
        index = index - 1
        if le(s, 128 + index * 4, 4) == get(w, 224):
            put(w, 232, get(w, 208) + index)
            return start_read(o, w, 1, 56 + (get(w, 232) - 1) * (get(w, 128) + 24), get(w, 128), 2)
    put(w, 200, get(w, 208) - 1)
    return index_prepare(o, w)

def database_page(o:mutbuf, w:mutbuf) -> u32:
    put(w, 232, 0)
    return start_read(o, w, 0, (get(w, 224) - 1) * get(w, 128), get(w, 128), 2)

def start_read(o:mutbuf, w:mutbuf, handle:u64, offset:u64, count:u64, purpose:u64) -> u32:
    if count == 0 or count > 65536 or offset > 9223372036854775807 - count:
        return fail(o, w, 7, 0)
    put(w, 240, handle)
    put(w, 248, offset)
    put(w, 256, count)
    put(w, 264, 0)
    put(w, 272, purpose)
    return issue(o, w, 60, 3, handle, offset, count, 0)

def read_return(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    raw = word(s, 48)
    if raw > 9223372036854775807:
        # Prior successful reads remain in state[4096:4096+done]. Failure is
        # recorded before cleanup; no rollback or invented complete page.
        return fail(o, w, 1, raw)
    if raw != word(s, 56) or raw > get(w, 256) - get(w, 264):
        return fail(o, w, 7, raw)
    if raw == 0:
        if get(w, 240) == 1:
            return fail(o, w, 6, 0)
        # Match unixRead zero-fill then readDbPage SHORT_READ->OK for DB.
        # This does not apply to WAL frames.
        index = get(w, 264)
        while index < get(w, 256):
            store(w, 4096 + index, 0)
            index = index + 1
        put(w, 360, 1)
        put(w, 264, get(w, 256))
    else:
        # Exact packet and complete dst/src range are admitted before copy.
        copy_range(w, s, 4096 + get(w, 264), 128, raw)
        put(w, 264, get(w, 264) + raw)
    if get(w, 264) < get(w, 256):
        return issue(o, w, 60, 3, get(w, 240), get(w, 248) + get(w, 264), get(w, 256) - get(w, 264), 0)
    if get(w, 272) == 1:
        return after_db_header(o, w)
    put(w, 8, 201)
    return outcome(o, w, 129)
'''
