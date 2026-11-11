"""Complete HIA stream visitor and original-order final Core admission."""
from __future__ import annotations

BODY = r'''
def core_final(s:readbuf, r:readbuf, w:mutbuf) -> u32:
    if length(w) < MIN_WORK:
        return BAD
    if get(w, S_STATUS) == 3:
        return BAD
    if length(s) < 8:
        return refuse(w, 1)
    tag = word(s, 0)
    if tag == INIT_MAGIC:
        return initialize(s, r, w)
    if get(w, S_MAGIC) != STATE_MAGIC or get(w, S_STATUS) == 0:
        return refuse(w, 2)
    if source_same(r, w) == 0:
        return refuse(w, 3)
    if tag == ADMIT_MAGIC:
        return admission(s, w)
    if get(w, S_STATUS) != 1:
        return refuse(w, 4)
    if tag == CONT_MAGIC:
        return continuation(s, r, w)
    if tag == OPAQUE_MAGIC:
        return opaque_reply(s, r, w)
    return producer(s, r, w)

def initialize(s:readbuf, r:readbuf, w:mutbuf) -> u32:
    if length(s) != 80 or get(w, S_MAGIC) != 0 or get(w, S_STATUS) != 0:
        return refuse(w, 5)
    if source_header(r) == 0:
        return refuse(w, 6)
    if word(s, 8) == 0 or word(s, 16) == 0 or word(s, 24) == 0:
        return refuse(w, 7)
    producer_magic = word(s, 24)
    if producer_magic == INIT_MAGIC or producer_magic == CONT_MAGIC or producer_magic == OPAQUE_MAGIC or producer_magic == ADMIT_MAGIC:
        return refuse(w, 8)
    mode = word(s, 64)
    if (mode != 1 and mode != 2) or word(s, 72) != 0:
        return refuse(w, 9)
    fill_range(w, 0, 1024, 0)
    put(w, S_MAGIC, STATE_MAGIC)
    put(w, S_STATUS, 1)
    put(w, S_PHASE, 1)
    put(w, S_LEASE, word(s, 8))
    put(w, S_STREAM, word(s, 16))
    put(w, S_PRODUCER, producer_magic)
    put(w, S_ACTION, word(s, 32))
    put(w, S_REQUEST, word(s, 40))
    put(w, S_SERIAL, word(s, 48))
    put(w, S_SLOTS, word(s, 56))
    put(w, S_MODE, mode)
    put(w, S_SOURCE_SIZE, word(r, 8))
    put(w, S_INDEX_SIZE, word(r, 16))
    put(w, S_INDEX_AT, word(r, 32))
    put(w, S_SOURCE_EXTENT, length(r))
    put(w, S_HEAP, ARENA_BASE)
    put(w, S_FIRST, U64_MAX)
    put(w, S_DEPTH_LIMIT, choose(mode == 1, 62, 64))
    return event(w, 1)

def continuation(s:readbuf, r:readbuf, w:mutbuf) -> u32:
    if length(s) != 32 or correlation(s, w) == 0:
        return refuse(w, 10)
    if get(w, S_PHASE) != 3 or get(w, S_INPUT_ACTIVE) != 1 or get(w, S_NEED) == 0:
        return refuse(w, 11)
    if get(w, S_NEED) > length(w):
        return event(w, 3)
    put(w, S_NEED, 0)
    put(w, S_PHASE, 2)
    return pump(r, w)

def producer(s:readbuf, r:readbuf, w:mutbuf) -> u32:
    if get(w, S_PHASE) != 1 or get(w, S_INPUT_ACTIVE) != 0 or get(w, S_NEED) != 0:
        return refuse(w, 12)
    if length(s) < 64 or length(s) > 65536:
        return refuse(w, 13)
    if word(s, 0) != get(w, S_PRODUCER) or word(s, 8) != get(w, S_ACTION):
        return refuse(w, 14)
    if word(s, 16) != get(w, S_PSEQ) or word(s, 24) > 1:
        return refuse(w, 15)
    if word(s, 32) != get(w, S_SERIAL) or word(s, 40) != get(w, S_SLOTS):
        return refuse(w, 16)
    if word(s, 48) != get(w, S_REQUEST) or word(s, 56) != length(s) - 64:
        return refuse(w, 17)
    if get(w, S_PSEQ) == U64_MAX:
        return refuse(w, 18)
    copy_input(s, 0, w, INPUT_BASE, length(s))
    put(w, S_INPUT_SIZE, length(s))
    put(w, S_INPUT_AT, 64)
    put(w, S_INPUT_FINAL, word(s, 24))
    put(w, S_INPUT_ACTIVE, 1)
    put(w, S_PHASE, 2)
    return pump(r, w)

def reset_token(w:mutbuf) -> u64:
    put(w, T_DATA_AT, 0)
    put(w, T_DATA_LEN, 0)
    put(w, T_DATA_KIND, 0)
    put(w, T_SOURCE, 0)
    put(w, T_END, 0)
    return 1

def token_shape(r:readbuf, w:mutbuf) -> u64:
    cursor = get(w, S_INPUT_AT)
    stop = get(w, S_INPUT_SIZE)
    if cursor > stop or stop - cursor < 16:
        return failed(w, 20)
    raw_kind = get(w, INPUT_BASE + cursor)
    value = get(w, INPUT_BASE + cursor + 8)
    reset_token(w)
    put(w, T_RAW_KIND, raw_kind)
    put(w, T_VALUE, value)
    put(w, T_NEXT, cursor + 16)
    if raw_kind == 0:
        # Source offsets and opaque handles are dispatched by pump. They do
        # not consume a structural node until their actual value is visited.
        return 1
    if raw_kind == 1:
        if value > stop - cursor - 16:
            return failed(w, 21)
        if utf8(w, INPUT_BASE + cursor + 16, INPUT_BASE + cursor + 16 + value) == 0:
            return failed(w, 22)
        put(w, T_KIND, 4)
        put(w, T_DATA_KIND, 2)
        put(w, T_DATA_AT, INPUT_BASE + cursor + 16)
        put(w, T_DATA_LEN, value)
        put(w, T_NEXT, cursor + 16 + value)
    elif raw_kind == 2:
        put(w, T_KIND, 2)
    elif raw_kind == 3:
        if value > 1:
            return failed(w, 23)
        put(w, T_KIND, 1)
    elif raw_kind == 4:
        if value != 0:
            return failed(w, 24)
        put(w, T_KIND, 0)
    elif raw_kind == 5 or raw_kind == 6:
        put(w, T_KIND, raw_kind)
    else:
        return failed(w, 25)
    return 1

def source_shape(r:readbuf, w:mutbuf) -> u64:
    offset = get(w, S_SOURCE_POS)
    if source_node(r, w, offset) == 0:
        return failed(w, 26)
    node = 64 + offset
    kind = word(r, node)
    size = word(r, node + 8)
    stop = offset + 16 + size
    if stop > get(w, S_SOURCE_STOP):
        return failed(w, 27)
    reset_token(w)
    put(w, T_RAW_KIND, 7)
    put(w, T_SOURCE, 1)
    put(w, T_KIND, kind)
    put(w, T_VALUE, 0)
    put(w, T_NEXT, stop)
    put(w, T_END, stop)
    if kind == 4:
        put(w, T_DATA_KIND, 1)
        put(w, T_DATA_AT, node + 16)
        put(w, T_DATA_LEN, size)
    elif kind == 5 or kind == 6:
        if size < 8:
            return failed(w, 28)
        count = word(r, node + 16)
        bound = (size - 8) >> choose(kind == 5, 4, 5)
        if count > bound:
            return failed(w, 29)
        put(w, T_VALUE, count)
        put(w, T_NEXT, offset + 24)
    return 1

def consume(r:readbuf, w:mutbuf) -> u64:
    if position(w) == 0:
        return 0
    if get(w, T_IS_KEY) != 0:
        if prepare_key(r, w, get(w, S_TOP)) == 0:
            return 0
        save_key(r, w, get(w, S_TOP))
    else:
        if get(w, T_KIND) >= 5 and ensure(w, FRAME_BYTES) == 0:
            return 0
        count_value(w)
        attach_value(w)
        if get(w, T_KIND) >= 5:
            push_container(w)
    if get(w, T_SOURCE) != 0:
        put(w, S_SOURCE_POS, get(w, T_NEXT))
    else:
        put(w, S_INPUT_AT, get(w, T_NEXT))
    return close_containers(w)

def begin_source(r:readbuf, w:mutbuf) -> u64:
    offset = get(w, T_VALUE)
    if source_node(r, w, offset) == 0:
        return failed(w, 30)
    put(w, S_SOURCE_ACTIVE, 1)
    put(w, S_SOURCE_POS, offset)
    put(w, S_SOURCE_STOP, offset + 16 + word(r, 64 + offset + 8))
    put(w, S_INPUT_AT, get(w, T_NEXT))
    return 1

def request_opaque(w:mutbuf) -> u32:
    if position(w) == 0:
        return BAD
    if get(w, S_MODE) != 2 or get(w, T_DEPTH) != 2 or get(w, T_IS_KEY) != 0:
        return refuse(w, 31)
    if get(w, S_OPAQUE_QUERY) == U64_MAX:
        return refuse(w, 32)
    put(w, S_OPAQUE_HANDLE, get(w, T_VALUE))
    put(w, S_OPAQUE_QUERY, get(w, S_OPAQUE_QUERY) + 1)
    put(w, S_OPAQUE_PENDING, 1)
    put(w, S_PHASE, 4)
    return event(w, 4)

def opaque_reply(s:readbuf, r:readbuf, w:mutbuf) -> u32:
    if length(s) != 128 or correlation(s, w) == 0:
        return refuse(w, 33)
    if get(w, S_PHASE) != 4 or get(w, S_OPAQUE_PENDING) != 1 or get(w, S_INPUT_ACTIVE) != 1:
        return refuse(w, 34)
    if word(s, 32) != get(w, S_OPAQUE_HANDLE) or word(s, 40) != 6:
        return refuse(w, 35)
    if word(s, 104) != 0 or word(s, 112) != 0 or word(s, 120) != 0:
        return refuse(w, 36)
    nodes = word(s, 48)
    first = word(s, 56)
    if nodes == 0 or nodes > CAP or word(s, 64) == 0:
        return refuse(w, 37)
    if first != U64_MAX and (first > CAP or (nodes < CAP and first >= nodes)):
        return refuse(w, 38)
    if position(w) == 0:
        return BAD
    if get(w, T_DEPTH) != 2 or get(w, T_IS_KEY) != 0:
        return refuse(w, 39)
    if get(w, S_FIRST) == U64_MAX and first != U64_MAX:
        put(w, S_FIRST, sat(get(w, S_ARITY), first))
    put(w, S_NODES, sat(get(w, S_NODES), nodes))
    put(w, S_ARITY, sat(get(w, S_ARITY), nodes - 1))
    put(w, T_KIND, 6)
    attach_value(w)
    put(w, S_INPUT_AT, get(w, S_INPUT_AT) + 16)
    put(w, S_OPAQUE_PENDING, 0)
    put(w, S_PHASE, 2)
    if close_containers(w) == 0:
        return BAD
    return pump(r, w)

def complete_chunk(w:mutbuf) -> u32:
    if get(w, S_INPUT_AT) != get(w, S_INPUT_SIZE) or get(w, S_SOURCE_ACTIVE) != 0:
        return refuse(w, 40)
    if get(w, S_INPUT_FINAL) != 0 and (get(w, S_ROOT_HAVE) == 0 or get(w, S_TOP) != 0):
        return refuse(w, 41)
    put(w, S_PSEQ, get(w, S_PSEQ) + 1)
    put(w, S_INPUT_ACTIVE, 0)
    if get(w, S_INPUT_FINAL) == 0:
        put(w, S_PHASE, 1)
        return event(w, 1)
    if get(w, S_NODES) != sat(get(w, S_ARITY), 1):
        return refuse(w, 42)
    if get(w, S_MODE) == 2:
        if get(w, S_FIRST) != U64_MAX and get(w, S_FIRST) <= MAX_NODES - 1:
            put(w, S_LATE, 1)
        elif get(w, S_NODES) > MAX_NODES:
            put(w, S_LATE, 2)
    put(w, S_STATUS, 2)
    put(w, S_PHASE, 5)
    return event(w, 5)

def pump(r:readbuf, w:mutbuf) -> u32:
    while True:
        if get(w, S_SOURCE_ACTIVE) != 0:
            if get(w, S_SOURCE_POS) == get(w, S_SOURCE_STOP):
                put(w, S_SOURCE_ACTIVE, 0)
            elif get(w, S_SOURCE_POS) > get(w, S_SOURCE_STOP):
                return refuse(w, 43)
            else:
                if source_shape(r, w) == 0:
                    return BAD
                if consume(r, w) == 0:
                    return suspended(w)
        elif get(w, S_INPUT_AT) == get(w, S_INPUT_SIZE):
            return complete_chunk(w)
        else:
            if token_shape(r, w) == 0:
                return BAD
            if get(w, T_RAW_KIND) == 0:
                if get(w, T_VALUE) >= OBJECTS:
                    return request_opaque(w)
                if begin_source(r, w) == 0:
                    return BAD
            elif consume(r, w) == 0:
                return suspended(w)
    return refuse(w, 44)

def admission(s:readbuf, w:mutbuf) -> u32:
    if length(s) != 80 or correlation(s, w) == 0:
        return refuse(w, 45)
    if get(w, S_MODE) != 2 or get(w, S_STATUS) != 2 or get(w, S_PHASE) != 5:
        return refuse(w, 46)
    if get(w, S_INPUT_ACTIVE) != 0 or get(w, S_OPAQUE_PENDING) != 0 or get(w, S_TOP) != 0:
        return refuse(w, 47)
    if word(s, 72) != 0 or word(s, 32) == 0:
        return refuse(w, 48)
    put(w, S_JSON_BYTES, word(s, 32))
    put(w, S_DIGEST0, word(s, 40))
    put(w, S_DIGEST1, word(s, 48))
    put(w, S_DIGEST2, word(s, 56))
    put(w, S_DIGEST3, word(s, 64))
    if get(w, S_LATE) == 0 and word(s, 32) > MAX_BYTES:
        put(w, S_LATE, 3)
    put(w, S_PHASE, 6)
    return event(w, 7)
'''
