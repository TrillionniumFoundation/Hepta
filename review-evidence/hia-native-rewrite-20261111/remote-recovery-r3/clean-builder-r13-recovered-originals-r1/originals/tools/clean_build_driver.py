"""HIA-owned fixed clean release recipes after the full kit gate."""
CONSTANTS={'B_CURSOR':1536,'B_INDEX':1544,'B_SEEN':1560,'B_RECEIPT':1568,'B_RECEIPT_BYTES':1576,
 'B_FINAL':1584,'B_FINAL_BYTES':1592,'B_AGENT':1600,'B_AGENT_BYTES':1608,'B_INSTALL':1616,'B_INSTALL_BYTES':1624,
 'B_FRAME':1632,'B_FRAME_BYTES':1640,'B_SELF':1648,'B_SELF_BYTES':1656,'B_SEEN_RESULT':1664,
 'B_ROWS':1792,'B_HEADER':3200,'B_HASH':3264,'B_TEMP':672,'IMAGE_CAP':1048576,
 'AGENT_MAGIC':int.from_bytes(b'HIAAGNT1','little'),'INSTALL_MAGIC':int.from_bytes(b'HIAINS01','little'),
 'RELEASE_MAGIC':int.from_bytes(b'HIAREL01','little'),'ARG_MAGIC':int.from_bytes(b'HIABAR01','little')}
BODY=r'''
def driver(s:readbuf, r:readbuf, w:mutbuf) -> u32:
    if length(w) < MIN_WORK:
        return BAD
    if get(w, 8) != 0:
        return BAD
    if length(s) >= 8 and uint(s, 0) == ARG_MAGIC:
        return arguments(s, w)
    phase = get(w, 16)
    if get(w, 0) == WMAGIC and phase >= 4:
        if length(s) != get(w, 40) or length(s) < 128 or equal_read_work(s, w, 0, 256, 64) == 0:
            return bad(w, 100)
        if phase == 4:
            return build_begin(w)
        return build_step(s, r, w)
    result = widen(gate(s, r, w))
    if result == 128 and get(w, 8) == 0 and get(w, 16) == 4:
        return build_begin(w)
    return result

def widen(value:u64) -> u64:
    return value

def build_begin(w:mutbuf) -> u32:
    put(w, B_CURSOR, get(w, 336))
    put(w, B_INDEX, 0)
    put(w, B_SEEN, 0)
    i = 0
    while i < 9 * 96:
        store(w, B_ROWS + i, 0)
        i = i + 1
    return request_compile(w)

def build_call(w:mutbuf, action:u64, source:u64, size:u64, code_owner:u64, code:u64, code_size:u64, phase:u64) -> u32:
    if get(w, 24) == NONE:
        return bad(w, 101)
    put(w, 24, get(w, 24) + 1)
    put(w, 16, phase)
    put(w, B_SEEN, 0)
    event(w, action, source, size, IMAGE_CAP, IMAGE_CAP)
    put(w, EVENT + 64, code)
    put(w, EVENT + 72, code_size)
    put(w, EVENT + 80, code_owner)
    return 128

def request_compile(w:mutbuf) -> u32:
    index = get(w, B_INDEX)
    if index > 6:
        return bad(w, 102)
    source = get(w, 512 + index * 16)
    size = get(w, 520 + index * 16)
    if size == 0 or size > IMAGE_CAP:
        return refused(w, 7)
    row = B_ROWS + index * 96
    put(w, row, source)
    put(w, row + 8, size)
    i = 0
    found = 0
    while i < get(w, 96):
        source_row = TABLE + i * 96
        if get(w, source_row + 16) == source and get(w, source_row + 24) == size:
            copy_work(w, source_row + 32, row + 64, 32)
            found = found + 1
        i = i + 1
    if found != 1:
        return bad(w, 103)
    code_owner = 1
    code = get(w, 48)
    code_size = get(w, 56)
    if index != 0:
        code_owner = 2
        code = get(w, B_ROWS + 16)
        code_size = get(w, B_ROWS + 24)
    return build_call(w, 5, source, size, code_owner, code, code_size, 10)

def build_step(s:readbuf, r:readbuf, w:mutbuf) -> u32:
    phase = get(w, 16)
    if phase == 10:
        return compiled(s, r, w)
    if phase == 11:
        return agent_frame(w)
    if phase == 12:
        return packed(r, w, 7)
    if phase == 13:
        return install_frame(w)
    if phase == 14:
        return packed(r, w, 8)
    if phase == 15:
        return self_reply(r, w)
    if phase == 16:
        return package(s, w)
    return bad(w, 104)

def reply_size(r:readbuf, w:mutbuf, kind:u64, capacity:u64) -> u64:
    if length(r) < 64:
        bad(w, 105)
        return 0
    if get(w, B_SEEN) == 1 and equal_read_work(r, w, 0, B_HEADER, 64) == 0:
        bad(w, 106)
        return 0
    if uint(r, 0) != RMAGIC or uint(r, 8) != get(w, 24) or uint(r, 16) != kind:
        bad(w, 107)
        return 0
    if uint(r, 32) != length(r) - 64 or uint(r, 56) != 0:
        bad(w, 108)
        return 0
    if uint(r, 40) != 0:
        if uint(r, 32) != 0:
            bad(w, 109)
        else:
            refused(w, 8)
        return 0
    result = uint(r, 24)
    if uint(r, 32) != capacity:
        bad(w, 110)
        return 0
    if result == 0 or result > capacity:
        refused(w, 9)
        return 0
    hash_range(r, 64, result, w, B_TEMP)
    if get(w, B_SEEN) == 1:
        i = 0
        while i < 32:
            if byte(w, B_HASH + i) != byte(w, B_TEMP + i):
                bad(w, 111)
                return 0
            i = i + 1
    else:
        copy_read(r, w, 0, B_HEADER, 64)
        copy_work(w, B_TEMP, B_HASH, 32)
        put(w, B_SEEN, 1)
        put(w, B_SEEN_RESULT, result)
    return result

def reply_failure(w:mutbuf) -> u32:
    if get(w, EVENT + 8) == 4:
        return BAD
    return 128

def compiled(s:readbuf, r:readbuf, w:mutbuf) -> u32:
    size = reply_size(r, w, 2, IMAGE_CAP)
    if size == 0:
        return reply_failure(w)
    index = get(w, B_INDEX)
    if index == 0:
        if size != get(w, 56):
            return refused(w, 10)
        i = 0
        while i < size:
            if byte(r, 64 + i) != byte(s, get(w, 48) + i):
                return refused(w, 10)
            i = i + 1
    cursor = get(w, B_CURSOR)
    if size > NONE - cursor - 15:
        return bad(w, 112)
    needed = (cursor + size + 15) & 18446744073709551600
    if needed > length(w):
        return grow(w, needed)
    row = B_ROWS + index * 96
    copy_read(r, w, 64, cursor, size)
    put(w, row + 16, cursor)
    put(w, row + 24, size)
    copy_work(w, B_TEMP, row + 32, 32)
    put(w, B_CURSOR, needed)
    put(w, B_SEEN, 0)
    put(w, B_INDEX, index + 1)
    if index < 6:
        return request_compile(w)
    put(w, 16, 11)
    return agent_frame(w)

def agent_frame(w:mutbuf) -> u32:
    dispatch = get(w, B_ROWS + 2 * 96 + 24)
    frontend = get(w, B_ROWS + 96 + 24)
    compiler = get(w, B_ROWS + 24)
    size = 40 + dispatch + frontend + compiler
    if size > IMAGE_CAP:
        return refused(w, 11)
    cursor = get(w, B_CURSOR)
    if size > NONE - cursor - 15:
        return bad(w, 113)
    needed = (cursor + size + 15) & 18446744073709551600
    if needed > length(w):
        return grow(w, needed)
    put(w, cursor, AGENT_MAGIC)
    put(w, cursor + 8, dispatch)
    put(w, cursor + 16, frontend)
    put(w, cursor + 24, compiler)
    put(w, cursor + 32, get(w, 392))
    copy_work(w, get(w, B_ROWS + 2 * 96 + 16), cursor + 40, dispatch)
    copy_work(w, get(w, B_ROWS + 96 + 16), cursor + 40 + dispatch, frontend)
    copy_work(w, get(w, B_ROWS + 16), cursor + 40 + dispatch + frontend, compiler)
    put(w, B_FRAME, cursor)
    put(w, B_FRAME_BYTES, size)
    put(w, B_CURSOR, needed)
    hash_work(w, cursor, size, B_ROWS + 7 * 96 + 64)
    return build_call(w, 6, cursor, size, 2, get(w, B_ROWS + 3 * 96 + 16), get(w, B_ROWS + 3 * 96 + 24), 12)

def install_frame(w:mutbuf) -> u32:
    policy = get(w, B_ROWS + 4 * 96 + 24)
    sha = get(w, B_ROWS + 6 * 96 + 24)
    size = 24 + policy + sha
    if size > IMAGE_CAP:
        return refused(w, 11)
    cursor = get(w, B_CURSOR)
    if size > NONE - cursor - 15:
        return bad(w, 114)
    needed = (cursor + size + 15) & 18446744073709551600
    if needed > length(w):
        return grow(w, needed)
    put(w, cursor, INSTALL_MAGIC)
    put(w, cursor + 8, policy)
    put(w, cursor + 16, sha)
    copy_work(w, get(w, B_ROWS + 4 * 96 + 16), cursor + 24, policy)
    copy_work(w, get(w, B_ROWS + 6 * 96 + 16), cursor + 24 + policy, sha)
    put(w, B_FRAME, cursor)
    put(w, B_FRAME_BYTES, size)
    put(w, B_CURSOR, needed)
    hash_work(w, cursor, size, B_ROWS + 8 * 96 + 64)
    return build_call(w, 6, cursor, size, 2, get(w, B_ROWS + 5 * 96 + 16), get(w, B_ROWS + 5 * 96 + 24), 14)

def packed(r:readbuf, w:mutbuf, index:u64) -> u32:
    size = reply_size(r, w, 3, IMAGE_CAP)
    if size == 0:
        return reply_failure(w)
    if elf_valid(r, 64, size) == 0:
        return refused(w, 12)
    cursor = get(w, B_CURSOR)
    if size > NONE - cursor - 15:
        return bad(w, 115)
    needed = (cursor + size + 15) & 18446744073709551600
    if needed > length(w):
        return grow(w, needed)
    copy_read(r, w, 64, cursor, size)
    row = B_ROWS + index * 96
    put(w, row, get(w, B_FRAME))
    put(w, row + 8, get(w, B_FRAME_BYTES))
    put(w, row + 16, cursor)
    put(w, row + 24, size)
    copy_work(w, B_TEMP, row + 32, 32)
    put(w, B_CURSOR, needed)
    put(w, B_SEEN, 0)
    if index == 7:
        put(w, B_AGENT, cursor)
        put(w, B_AGENT_BYTES, size)
        put(w, 16, 13)
        return install_frame(w)
    put(w, B_INSTALL, cursor)
    put(w, B_INSTALL_BYTES, size)
    return build_call(w, 7, 0, 0, 0, 0, 0, 15)

def self_reply(r:readbuf, w:mutbuf) -> u32:
    if length(r) < 64:
        return bad(w, 116)
    size = reply_size(r, w, 4, length(r) - 64)
    if size == 0:
        return reply_failure(w)
    if elf_valid(r, 64, size) == 0:
        return refused(w, 13)
    cursor = get(w, B_CURSOR)
    if size > NONE - cursor - 15:
        return bad(w, 117)
    needed = (cursor + size + 15) & 18446744073709551600
    if needed > length(w):
        return grow(w, needed)
    copy_read(r, w, 64, cursor, size)
    put(w, B_SELF, cursor)
    put(w, B_SELF_BYTES, size)
    put(w, B_CURSOR, needed)
    put(w, B_SEEN, 0)
    put(w, 16, 16)
    return event(w, 8, 0, 0, 0, 0)

def copy_work(w:mutbuf, source:u64, target:u64, size:u64) -> u64:
    i = 0
    while i < size:
        store(w, target + i, byte(w, source + i))
        i = i + 1
    return 0

def elf_valid(s:readbuf, start:u64, size:u64) -> u64:
    if size <= 176 or start > length(s) or size > length(s) - start:
        return 0
    if uint(s, start) != 282584257676671 or uint(s, start + 8) != 0:
        return 0
    if uint(s, start + 16) != 4299030530 or uint(s, start + 24) != 4194480:
        return 0
    if uint(s, start + 32) != 64 or uint(s, start + 40) != 0:
        return 0
    if uint(s, start + 48) != 15762873573703680 or uint(s, start + 56) != 2:
        return 0
    if uint(s, start + 64) != 21474836481 or uint(s, start + 72) != 0:
        return 0
    if uint(s, start + 80) != 4194304 or uint(s, start + 88) != 4194304:
        return 0
    if uint(s, start + 96) != size or uint(s, start + 104) != size:
        return 0
    if uint(s, start + 112) != 4096 or uint(s, start + 120) != 27455186257:
        return 0
    if uint(s, start + 128) != 0 or uint(s, start + 136) != 0 or uint(s, start + 144) != 0:
        return 0
    if uint(s, start + 152) != 0 or uint(s, start + 160) != 0 or uint(s, start + 168) != 16:
        return 0
    return 1

def arguments(s:readbuf, w:mutbuf) -> u32:
    if get(w, 0) != 0 or get(w, 416) != 0:
        return bad(w, 121)
    if length(s) != 96 or uint(s, 8) != 2 or uint(s, 16) != 64:
        return refused(w, 15)
    put(w, 2048, IMAGIC)
    put(w, 2056, 1)
    put(w, 2096, uint(s, 24))
    put(w, 2104, 0)
    i = 0
    while i < 32:
        high = unhex(byte(s, 32 + i * 2))
        low = unhex(byte(s, 33 + i * 2))
        if high > 15 or low > 15:
            return refused(w, 15)
        store(w, 2064 + i, high * 16 + low)
        i = i + 1
    put(w, 416, 1)
    return event(w, 9, 2048, 64, 0, 0)

def unhex(value:u64) -> u64:
    if value >= 48 and value <= 57:
        return value - 48
    if value >= 97 and value <= 102:
        return value - 87
    return 16

def decoder_event(w:mutbuf, source:u64, size:u64) -> u32:
    nodes = ((size + 1) >> 1) + 1
    if nodes > 1048576:
        nodes = 1048576
    output = 64 + nodes * 56 + size
    if output < 4256:
        output = 4256
    bound = (size >> 2) + 1
    if bound > 1048576:
        bound = 1048576
    slots = 2
    while slots < bound * 2:
        slots = slots * 2
    scratch = slots * 8
    if scratch < 6320:
        scratch = 6320
    event(w, 1, source, size, output, scratch)
    put(w, EVENT + 64, 1048576)
    put(w, EVENT + 72, 128)
    return 128
'''
