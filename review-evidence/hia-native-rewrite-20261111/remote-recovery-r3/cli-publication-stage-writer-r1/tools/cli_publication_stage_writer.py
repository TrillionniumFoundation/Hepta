"""New native staging-file write owner, unexecuted draft revision 1.
This models the freshly exclusive-opened binary file block of publish_program:
write(payload), flush(), fsync(), close(), including buffered-write errors and
close-error priority. Directory creation/cleanup is a separate parent owner.
It borrows already issued normalized absolute filesystem bytes and payload.
"""
CONSTANTS={
 "BAD":0xfffffffd,"MAX":(1<<64)-1,
 "COMMAND":int.from_bytes(b"HIASWC01","little"),
 "STATE":int.from_bytes(b"HIASWS01","little"),
 "EVENT":int.from_bytes(b"HIASWE01","little"),
 "ACK":int.from_bytes(b"HIASWA01","little"),
 "PHASE":16,"LEASE":24,"SEQ":32,"OP":40,"LIVE":48,
 "PATH_AT":56,"PATH_N":64,"DATA_AT":72,"DATA_N":80,"SOURCE_N":88,
 "BLOCK":96,"POS":104,"BUFFER_AT":112,"BUFFER_END":120,
 "ERROR_KIND":128,"ERROR_ERRNO":136,"ERROR_PATH":144,"CHARACTERS":152,
 "REQUEST_AT":160,"REQUEST_N":168,"RAW_MODE":176,"WRITTEN":184,
}
BODY=r'''
def entry(s:readbuf, r:readbuf, w:mutbuf) -> u32:
    if length(w) < 1024:
        return BAD
    if get(w, 8) != 0:
        return BAD
    if get(w, 0) == 0:
        if length(r) != 0 or source_valid(s) == 0:
            return refused(w)
        put(w, 0, STATE)
        put(w, LEASE, uint(s, 16))
        put(w, SEQ, uint(s, 24))
        put(w, PATH_AT, 64)
        put(w, PATH_N, uint(s, 32))
        put(w, DATA_AT, 65 + uint(s, 32))
        put(w, DATA_N, uint(s, 40))
        put(w, SOURCE_N, length(s))
        copy(w, s, 512, 0, 64)
        return issue(w, 1, 2)
    if get(w, 0) != STATE or source_same(s, w) == 0 or get(w, PHASE) == 99:
        return refused(w)
    if reply_valid(r, w) == 0:
        return refused(w)
    phase = get(w, PHASE)
    if phase == 2:
        return opened(r, w)
    if phase == 3:
        return stated(r, w)
    if phase == 4:
        return direct_written(r, w)
    if phase == 5 or phase == 7:
        return flushed(r, w, phase)
    if phase == 6:
        return synced(r, w)
    if phase == 8:
        return closed(r, w)
    if phase == 9:
        return raw_written(r, w)
    return refused(w)

def source_valid(s:readbuf) -> u64:
    if length(s) < 66 or uint(s, 0) != COMMAND or uint(s, 8) != 1:
        return 0
    if uint(s, 16) == 0 or uint(s, 24) == 0 or uint(s, 48) != length(s) or uint(s, 56) != 0:
        return 0
    path = uint(s, 32)
    if path == 0 or path > length(s) - 65 or uint(s, 40) != length(s) - 65 - path:
        return 0
    if byte(s, 64) != 47 or byte(s, 64 + path) != 0:
        return 0
    at = 0
    while at < path:
        if byte(s, 64 + at) == 0:
            return 0
        at = at + 1
    return 1

def source_same(s:readbuf, w:mutbuf) -> u64:
    if length(s) != get(w, SOURCE_N) or length(s) < 64:
        return 0
    i = 0
    while i < 64:
        if byte(s, i) != byte(w, 512 + i):
            return 0
        i = i + 1
    return 1

def refused(w:mutbuf) -> u32:
    put(w, 8, 1)
    emit(w, 6)
    return BAD

def emit(w:mutbuf, action:u64) -> u64:
    zero(w, 256, 128)
    put(w, 256, EVENT)
    put(w, 264, action)
    put(w, 272, get(w, LEASE))
    put(w, 280, get(w, SEQ))
    put(w, 288, get(w, OP))
    put(w, 296, get(w, ERROR_KIND))
    put(w, 304, get(w, ERROR_ERRNO))
    put(w, 312, get(w, CHARACTERS))
    if action == 2:
        if get(w, OP) == 1:
            put(w, 328, get(w, PATH_AT))
            put(w, 336, get(w, PATH_N) + 1)
            put(w, 344, 524481)
            put(w, 352, 438)
        elif get(w, OP) == 3:
            put(w, 336, 144)
        elif get(w, OP) == 5:
            put(w, 328, get(w, DATA_AT) + get(w, REQUEST_AT))
            put(w, 336, get(w, REQUEST_N))
    elif action == 0:
        if get(w, ERROR_PATH) != 0:
            put(w, 328, get(w, PATH_AT))
            put(w, 336, get(w, PATH_N))
        put(w, 344, get(w, WRITTEN))
        put(w, 352, get(w, DATA_AT))
        put(w, 360, get(w, DATA_N))
    put(w, 368, get(w, LIVE))
    put(w, 376, get(w, PHASE))
    return 0

def issue(w:mutbuf, op:u64, phase:u64) -> u32:
    if get(w, SEQ) == MAX:
        return refused(w)
    put(w, SEQ, get(w, SEQ) + 1)
    put(w, OP, op)
    put(w, PHASE, phase)
    emit(w, 2)
    return 128

def finish(w:mutbuf) -> u32:
    if get(w, LIVE) != 0:
        return refused(w)
    put(w, PHASE, 99)
    emit(w, 0)
    return 128

def error(w:mutbuf, kind:u64, err:u64, path:u64, characters:u64) -> u64:
    put(w, ERROR_KIND, kind)
    put(w, ERROR_ERRNO, err)
    put(w, ERROR_PATH, path)
    put(w, CHARACTERS, characters)
    return 0

def close(w:mutbuf) -> u32:
    if get(w, LIVE) != 1:
        return refused(w)
    put(w, LIVE, 0)
    return issue(w, 2, 8)

def reply_valid(r:readbuf, w:mutbuf) -> u64:
    if length(r) < 64 or uint(r, 0) != ACK or uint(r, 8) != get(w, LEASE) or uint(r, 16) != get(w, SEQ):
        return 0
    if uint(r, 24) != get(w, OP) or uint(r, 32) > 1 or uint(r, 56) != length(r) - 64:
        return 0
    phase = get(w, PHASE)
    op = 0
    live = 1
    if phase == 2:
        op = 1
        live = 0
    elif phase == 3:
        op = 3
    elif phase == 4 or phase == 5 or phase == 7 or phase == 9:
        op = 5
    elif phase == 6:
        op = 6
    elif phase == 8:
        op = 2
        live = 0
    if op == 0 or op != get(w, OP) or get(w, LIVE) != live:
        return 0
    if uint(r, 32) != 0:
        if uint(r, 40) != 0 or uint(r, 48) == 0 or uint(r, 48) > 4095 or uint(r, 56) != 0:
            return 0
        return 1
    if uint(r, 48) != 0:
        return 0
    if op == 3:
        if uint(r, 40) != 0 or uint(r, 56) != 144:
            return 0
    elif op == 1:
        if uint(r, 40) != 1 or uint(r, 56) != 0:
            return 0
    elif op == 5:
        if uint(r, 40) > get(w, REQUEST_N) or uint(r, 56) != 0:
            return 0
    elif uint(r, 40) != 0 or uint(r, 56) != 0:
        return 0
    return 1

def opened(r:readbuf, w:mutbuf) -> u32:
    if uint(r, 32) != 0:
        if uint(r, 48) == 4:
            return issue(w, 1, 2)
        error(w, 1, uint(r, 48), 1, 0)
        return finish(w)
    put(w, LIVE, 1)
    put(w, BLOCK, 8192)
    return issue(w, 3, 3)

def stated(r:readbuf, w:mutbuf) -> u32:
    if uint(r, 32) != 0:
        if uint(r, 48) == 9:
            error(w, 1, 9, 0, 0)
            return close(w)
    else:
        if (uint(r, 88) & 61440) == 16384:
            error(w, 1, 21, 1, 0)
            return close(w)
        block = uint(r, 120)
        if block > 1 and block < 9223372036854775808:
            put(w, BLOCK, block & 4294967295)
    block = get(w, BLOCK)
    if block >= 2147483648:
        error(w, 3, 0, 0, 0)
        return close(w)
    if block == 0:
        put(w, RAW_MODE, 1)
        return writing(w, 0, get(w, DATA_N), 9)
    return begin_direct(w)

def writing(w:mutbuf, at:u64, count:u64, phase:u64) -> u32:
    if at > get(w, DATA_N) or count > get(w, DATA_N) - at:
        return refused(w)
    put(w, REQUEST_AT, at)
    put(w, REQUEST_N, count)
    return issue(w, 5, phase)

def begin_direct(w:mutbuf) -> u32:
    remaining = get(w, DATA_N) - get(w, POS)
    if remaining > get(w, BLOCK):
        return writing(w, get(w, POS), remaining, 4)
    put(w, BUFFER_AT, get(w, POS))
    put(w, BUFFER_END, get(w, DATA_N))
    return flush_or_finish(w, 5)

def flush_or_finish(w:mutbuf, phase:u64) -> u32:
    start = get(w, BUFFER_AT)
    end = get(w, BUFFER_END)
    if start > end or end > get(w, DATA_N):
        return refused(w)
    if start != end:
        return writing(w, start, end - start, phase)
    if phase == 7:
        return close(w)
    return issue(w, 6, 6)

def direct_written(r:readbuf, w:mutbuf) -> u32:
    if uint(r, 32) != 0:
        err = uint(r, 48)
        if err == 4:
            return writing(w, get(w, REQUEST_AT), get(w, REQUEST_N), 4)
        if err == 11:
            size = get(w, BLOCK)
            if size > get(w, DATA_N) - get(w, POS):
                return refused(w)
            put(w, BUFFER_AT, get(w, POS))
            put(w, BUFFER_END, get(w, POS) + size)
            error(w, 2, err, 0, get(w, POS) + size)
            return flush_or_finish(w, 7)
        error(w, 1, err, 0, 0)
        return close(w)
    count = uint(r, 40)
    put(w, POS, get(w, POS) + count)
    put(w, WRITTEN, get(w, WRITTEN) + count)
    return begin_direct(w)

def flushed(r:readbuf, w:mutbuf, phase:u64) -> u32:
    if uint(r, 32) != 0:
        err = uint(r, 48)
        if err == 4:
            return writing(w, get(w, REQUEST_AT), get(w, REQUEST_N), phase)
        kind = 1
        if err == 11:
            kind = 2
        error(w, kind, err, 0, 0)
        if phase == 7:
            return close(w)
        return flush_or_finish(w, 7)
    count = uint(r, 40)
    put(w, BUFFER_AT, get(w, BUFFER_AT) + count)
    put(w, WRITTEN, get(w, WRITTEN) + count)
    return flush_or_finish(w, phase)

def synced(r:readbuf, w:mutbuf) -> u32:
    if uint(r, 32) != 0:
        if uint(r, 48) == 4:
            return issue(w, 6, 6)
        error(w, 1, uint(r, 48), 0, 0)
    return close(w)

def raw_written(r:readbuf, w:mutbuf) -> u32:
    if uint(r, 32) != 0:
        if uint(r, 48) == 4:
            return writing(w, 0, get(w, DATA_N), 9)
        if uint(r, 48) != 11:
            error(w, 1, uint(r, 48), 0, 0)
            return close(w)
    else:
        put(w, WRITTEN, uint(r, 40))
    return issue(w, 6, 6)

def closed(r:readbuf, w:mutbuf) -> u32:
    if uint(r, 32) != 0:
        error(w, 1, uint(r, 48), 0, 0)
    return finish(w)

def copy(w:mutbuf, s:readbuf, at:u64, begin:u64, count:u64) -> u64:
    i = 0
    while i < count:
        store(w, at + i, byte(s, begin + i))
        i = i + 1
    return 0

def zero(w:mutbuf, at:u64, count:u64) -> u64:
    i = 0
    while i < count:
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
