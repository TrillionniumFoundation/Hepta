"""Native Linux publication TemporaryDirectory creation, assembly policy revision 2.
Only private normalized absolute parent bytes are admitted. Eight random name
characters preserve the tempfile alphabet and original TMP_MAX collision bound.
The random generator itself is private: actual OS entropy is used, with the same
no-exception time/pid fallback category as CPython Random(None).
No filesystem or descriptor work occurs in this development authoring module.
"""
CONSTANTS={
 "BAD":0xfffffffd,"GROW":0xfffffffe,"MAX":(1<<64)-1,"BASE":1024,"TMP_MAX":238328,
 "COMMAND":int.from_bytes(b"HIATDC01","little"),
 "STATE":int.from_bytes(b"HIATDS01","little"),
 "EVENT":int.from_bytes(b"HIATDE01","little"),
 "ACK":int.from_bytes(b"HIATDA01","little"),
 "PHASE":16,"LEASE":24,"SEQ":32,"OP":40,"PENDING":48,
 "SOURCE_N":56,"PARENT_N":64,"DIR_AT":72,"DIR_N":80,"STAGE_AT":88,"STAGE_N":96,
 "NEEDED":104,"TRIES":112,"RANDOM_N":120,"SEED":128,
 "ERROR_CODE":136,"ERROR_ERRNO":144,"HAS_PARENT":152,"CREATED":160,"POLICY":168,
 "HEADER":512,"RANDOM":576
}
BODY=r'''
def entry(s:readbuf, r:readbuf, w:mutbuf) -> u32:
    if length(w) < BASE:
        return BAD
    if get(w, 8) != 0:
        return BAD
    if get(w, 0) == 0:
        if length(r) != 0 or source_valid(s) == 0:
            return refused(w)
        put(w, 0, STATE)
        put(w, PHASE, 1)
        put(w, LEASE, uint(s, 16))
        put(w, SEQ, uint(s, 24))
        put(w, SOURCE_N, length(s))
        put(w, PARENT_N, uint(s, 32))
        put(w, POLICY, uint(s, 48))
        copy_read(w, s, HEADER, 0, 64)
    elif get(w, 0) != STATE or source_same(s, w) == 0:
        return refused(w)
    if get(w, PHASE) == 99:
        return refused(w)
    if get(w, PHASE) == 1:
        if length(r) != 0 or get(w, PENDING) != 0:
            return refused(w)
        return initial(s, w)
    if reply_valid(r, w) == 0:
        return refused(w)
    put(w, PENDING, 0)
    phase = get(w, PHASE)
    if phase == 2:
        return random_reply(r, w)
    if phase == 3:
        return mkdir_reply(r, w)
    if phase == 4:
        seed = 11400714819323198485
        if uint(r, 32) == 0:
            seed = seed ^ uint(r, 64) ^ (uint(r, 72) << 1)
        put(w, SEED, seed)
        return issue(w, 25, 5)
    if phase == 5:
        if uint(r, 32) == 0:
            put(w, SEED, get(w, SEED) ^ (uint(r, 40) << 17))
        return issue(w, 24, 6)
    if phase == 6:
        seed = get(w, SEED)
        if uint(r, 32) == 0:
            seed = seed ^ (uint(r, 64) << 23) ^ uint(r, 72)
        if seed == 0:
            seed = 11400714819323198485
        i = 0
        while i < 8:
            seed = seed ^ (seed >> 12)
            seed = seed ^ (seed << 25)
            seed = seed ^ (seed >> 27)
            put(w, RANDOM + i * 8, seed * 2685821657736338717)
            i = i + 1
        put(w, SEED, seed)
        put(w, RANDOM_N, 64)
        return make_name(w)
    return refused(w)

def source_valid(s:readbuf) -> u64:
    if length(s) < 66 or uint(s, 0) != COMMAND or uint(s, 8) != 1:
        return 0
    if uint(s, 16) == 0 or uint(s, 24) == 0 or uint(s, 32) != length(s) - 65:
        return 0
    if uint(s, 40) != length(s) or (uint(s, 48) != 1 and uint(s, 48) != 2 and uint(s, 48) != 3) or uint(s, 56) != 0:
        return 0
    if byte(s, 64) != 47 or byte(s, length(s) - 1) != 0:
        return 0
    if length(s) > (MAX - BASE - 128) >> 1:
        return 0
    i = 64
    while i + 1 < length(s):
        if byte(s, i) == 0:
            return 0
        i = i + 1
    return 1

def source_same(s:readbuf, w:mutbuf) -> u64:
    if length(s) != get(w, SOURCE_N) or length(s) < 64 or byte(s, length(s) - 1) != 0:
        return 0
    i = 0
    while i < 64:
        if byte(s, i) != byte(w, HEADER + i):
            return 0
        i = i + 1
    if get(w, HAS_PARENT) != 0:
        i = 0
        while i < get(w, PARENT_N):
            if byte(s, 64 + i) != byte(w, BASE + i):
                return 0
            i = i + 1
    return 1

def initial(s:readbuf, w:mutbuf) -> u32:
    n = get(w, PARENT_N)
    sep = 1
    if byte(s, 63 + n) == 47:
        sep = 0
    tail = temp_prefix_bytes(w) + 8
    file = temp_stage_bytes(w)
    directory = n + sep + tail
    need = BASE + directory * 2 + file + 2
    put(w, NEEDED, need)
    if length(w) < need:
        emit(w, 1)
        return GROW
    copy_read(w, s, BASE, 64, n)
    if sep != 0:
        store(w, BASE + n, 47)
    put(w, DIR_AT, BASE)
    put(w, DIR_N, directory)
    put(w, STAGE_AT, BASE + directory + 1)
    put(w, STAGE_N, directory + file)
    put(w, HAS_PARENT, 1)
    put(w, RANDOM_N, 0)
    return issue(w, 15, 2)

def random_reply(r:readbuf, w:mutbuf) -> u32:
    if uint(r, 32) != 0:
        if uint(r, 48) == 4:
            return issue(w, 15, 2)
        return issue(w, 24, 4)
    n = uint(r, 56)
    copy_read(w, r, RANDOM + get(w, RANDOM_N), 64, n)
    put(w, RANDOM_N, get(w, RANDOM_N) + n)
    if get(w, RANDOM_N) != 64:
        return issue(w, 15, 2)
    return make_name(w)

def temp_prefix_bytes(w:mutbuf) -> u64:
    if get(w, POLICY) == 1:
        return 13
    if get(w, POLICY) == 2:
        return 17
    return 16

def temp_stage_bytes(w:mutbuf) -> u64:
    if get(w, POLICY) == 1:
        return 12
    if get(w, POLICY) == 2:
        return 10
    return 15

def temp_prefix(w:mutbuf, at:u64) -> u64:
    if get(w, POLICY) == 1:
        store(w, at, 46)
        store(w, at + 1, 104)
        store(w, at + 2, 105)
        store(w, at + 3, 97)
        store(w, at + 4, 45)
        store(w, at + 5, 112)
        store(w, at + 6, 117)
        store(w, at + 7, 98)
        store(w, at + 8, 108)
        store(w, at + 9, 105)
        store(w, at + 10, 115)
        store(w, at + 11, 104)
        store(w, at + 12, 45)
    elif get(w, POLICY) == 2:
        store(w, at, 46)
        store(w, at + 1, 104)
        store(w, at + 2, 101)
        store(w, at + 3, 112)
        store(w, at + 4, 116)
        store(w, at + 5, 97)
        store(w, at + 6, 45)
        store(w, at + 7, 106)
        store(w, at + 8, 115)
        store(w, at + 9, 111)
        store(w, at + 10, 110)
        store(w, at + 11, 45)
        store(w, at + 12, 118)
        store(w, at + 13, 105)
        store(w, at + 14, 101)
        store(w, at + 15, 119)
        store(w, at + 16, 45)
    else:
        store(w, at, 46)
        store(w, at + 1, 104)
        store(w, at + 2, 101)
        store(w, at + 3, 112)
        store(w, at + 4, 116)
        store(w, at + 5, 97)
        store(w, at + 6, 45)
        store(w, at + 7, 97)
        store(w, at + 8, 115)
        store(w, at + 9, 115)
        store(w, at + 10, 101)
        store(w, at + 11, 109)
        store(w, at + 12, 98)
        store(w, at + 13, 108)
        store(w, at + 14, 121)
        store(w, at + 15, 45)
    return 0

def temp_stage(w:mutbuf, at:u64) -> u64:
    if get(w, POLICY) == 1:
        store(w, at, 47)
        store(w, at + 1, 112)
        store(w, at + 2, 114)
        store(w, at + 3, 111)
        store(w, at + 4, 103)
        store(w, at + 5, 114)
        store(w, at + 6, 97)
        store(w, at + 7, 109)
        store(w, at + 8, 46)
        store(w, at + 9, 104)
        store(w, at + 10, 105)
        store(w, at + 11, 97)
    elif get(w, POLICY) == 2:
        store(w, at, 47)
        store(w, at + 1, 118)
        store(w, at + 2, 105)
        store(w, at + 3, 101)
        store(w, at + 4, 119)
        store(w, at + 5, 46)
        store(w, at + 6, 106)
        store(w, at + 7, 115)
        store(w, at + 8, 111)
        store(w, at + 9, 110)
    else:
        store(w, at, 47)
        store(w, at + 1, 112)
        store(w, at + 2, 114)
        store(w, at + 3, 111)
        store(w, at + 4, 103)
        store(w, at + 5, 114)
        store(w, at + 6, 97)
        store(w, at + 7, 109)
        store(w, at + 8, 46)
        store(w, at + 9, 104)
        store(w, at + 10, 105)
        store(w, at + 11, 97)
        store(w, at + 12, 97)
        store(w, at + 13, 115)
        store(w, at + 14, 109)
    store(w, at + temp_stage_bytes(w), 0)
    return 0

def make_name(w:mutbuf) -> u32:
    if get(w, RANDOM_N) != 64 or get(w, TRIES) >= TMP_MAX:
        return refused(w)
    prefix = temp_prefix_bytes(w)
    at = get(w, DIR_AT) + get(w, DIR_N) - prefix - 8
    temp_prefix(w, at)
    i = 0
    while i < 8:
        value = ((get(w, RANDOM + i * 8) >> 11) * 37) >> 53
        cp = 95
        if value < 26:
            cp = 97 + value
        elif value < 36:
            cp = 48 + value - 26
        store(w, at + prefix + i, cp)
        i = i + 1
    store(w, get(w, DIR_AT) + get(w, DIR_N), 0)
    copy_local(w, get(w, STAGE_AT), get(w, DIR_AT), get(w, DIR_N))
    temp_stage(w, get(w, STAGE_AT) + get(w, DIR_N))
    return issue(w, 11, 3)

def mkdir_reply(r:readbuf, w:mutbuf) -> u32:
    if uint(r, 32) == 0:
        put(w, CREATED, 1)
        return done(w, 0, 0)
    err = uint(r, 48)
    if err != 17:
        return done(w, 1, err)
    put(w, TRIES, get(w, TRIES) + 1)
    if get(w, TRIES) == TMP_MAX:
        return done(w, 2, 17)
    put(w, RANDOM_N, 0)
    return issue(w, 15, 2)

def issue(w:mutbuf, op:u64, phase:u64) -> u32:
    if get(w, SEQ) == MAX:
        return refused(w)
    put(w, SEQ, get(w, SEQ) + 1)
    put(w, PHASE, phase)
    put(w, OP, op)
    put(w, PENDING, 1)
    emit(w, 2)
    return 128

def reply_valid(r:readbuf, w:mutbuf) -> u64:
    if get(w, PENDING) != 1 or length(r) < 64 or uint(r, 0) != ACK:
        return 0
    if uint(r, 8) != get(w, LEASE) or uint(r, 16) != get(w, SEQ) or uint(r, 24) != get(w, OP):
        return 0
    if uint(r, 32) > 1 or uint(r, 56) != length(r) - 64:
        return 0
    phase = get(w, PHASE)
    op = 0
    if phase == 2:
        op = 15
        if get(w, RANDOM_N) >= 64:
            return 0
    elif phase == 3:
        op = 11
    elif phase == 4 or phase == 6:
        op = 24
    elif phase == 5:
        op = 25
    if op == 0 or get(w, OP) != op or get(w, CREATED) != 0:
        return 0
    if uint(r, 32) != 0:
        if uint(r, 40) != 0 or uint(r, 48) == 0 or uint(r, 48) > 4095 or uint(r, 56) != 0:
            return 0
        return 1
    if uint(r, 48) != 0:
        return 0
    if op == 15:
        if uint(r, 40) != uint(r, 56) or uint(r, 56) > 64 - get(w, RANDOM_N):
            return 0
    elif op == 24:
        if uint(r, 40) != 0 or uint(r, 56) != 16 or uint(r, 72) >= 1000000000:
            return 0
    elif op == 25:
        if uint(r, 40) == 0 or uint(r, 40) > 2147483647 or uint(r, 56) != 0:
            return 0
    elif uint(r, 40) != 0 or uint(r, 56) != 0:
        return 0
    return 1

def emit(w:mutbuf, action:u64) -> u64:
    zero(w, 256, 128)
    put(w, 256, EVENT)
    put(w, 264, action)
    put(w, 272, get(w, LEASE))
    put(w, 280, get(w, SEQ))
    put(w, 288, get(w, OP))
    put(w, 296, get(w, ERROR_CODE))
    put(w, 304, get(w, ERROR_ERRNO))
    put(w, 312, get(w, CREATED))
    if action == 2:
        if get(w, OP) == 11:
            put(w, 320, get(w, DIR_AT))
            put(w, 328, get(w, DIR_N) + 1)
            put(w, 344, 448)
        elif get(w, OP) == 15:
            put(w, 336, 64 - get(w, RANDOM_N))
            put(w, 344, 1)
        elif get(w, OP) == 24:
            put(w, 336, 16)
            if get(w, PHASE) == 6:
                put(w, 344, 1)
    elif action == 0:
        if get(w, ERROR_CODE) != 2:
            put(w, 320, get(w, DIR_AT))
            put(w, 328, get(w, DIR_N))
        if get(w, CREATED) != 0:
            put(w, 336, get(w, STAGE_AT))
            put(w, 344, get(w, STAGE_N))
    put(w, 352, get(w, TRIES))
    put(w, 368, get(w, NEEDED))
    put(w, 376, get(w, PHASE))
    return 0

def done(w:mutbuf, code:u64, error:u64) -> u32:
    put(w, ERROR_CODE, code)
    put(w, ERROR_ERRNO, error)
    put(w, PHASE, 99)
    put(w, PENDING, 0)
    emit(w, 0)
    return 128

def refused(w:mutbuf) -> u32:
    put(w, 8, 1)
    emit(w, 6)
    return BAD

def copy_read(w:mutbuf, s:readbuf, at:u64, start:u64, n:u64) -> u64:
    i = 0
    while i < n:
        store(w, at + i, byte(s, start + i))
        i = i + 1
    return 0

def copy_local(w:mutbuf, at:u64, start:u64, n:u64) -> u64:
    i = 0
    while i < n:
        store(w, at + i, byte(w, start + i))
        i = i + 1
    return 0

def zero(w:mutbuf, at:u64, n:u64) -> u64:
    i = 0
    while i < n:
        store(w, at + i, 0)
        i = i + 1
    return 0

def uint(s:readbuf, at:u64) -> u64:
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
'''
