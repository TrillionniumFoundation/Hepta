"""Fixed HIA state, source leases and bounded-memory key inventory.

Development authoring only. No source/descriptor/Core value is interpreted in
Python. All per-stream counting, dictionary membership and continuation state
execute in the generated HIA kernel.
"""
from __future__ import annotations

CONSTANTS = {
    'INIT_MAGIC': int.from_bytes(b'HIACSB01', 'little'),
    'CONT_MAGIC': int.from_bytes(b'HIACSC01', 'little'),
    'OPAQUE_MAGIC': int.from_bytes(b'HIACSO01', 'little'),
    'ADMIT_MAGIC': int.from_bytes(b'HIACSA01', 'little'),
    'EVENT_MAGIC': int.from_bytes(b'HIACSE01', 'little'),
    'STATE_MAGIC': int.from_bytes(b'HIACSS01', 'little'),
    'SOURCE_MAGIC': int.from_bytes(b'HIASIL01', 'little'),
    'BAD': 0xfffffffd, 'U64_MAX': (1 << 64) - 1, 'OBJECTS': 1 << 63,
    'MAX_NODES': 262144, 'CAP': 262145, 'MAX_BYTES': 8388608,
    'PACKET_MAX': 64 << 20, 'MIN_WORK': 131328, 'ARENA_BASE': 131328,
    'INPUT_BASE': 65536, 'EVENT_BASE': 1024, 'FRAME_BYTES': 96,
}
FIELDS = (
    'MAGIC', 'STATUS', 'PHASE', 'LEASE', 'STREAM', 'PRODUCER', 'ACTION',
    'REQUEST', 'SERIAL', 'SLOTS', 'MODE', 'PSEQ', 'ESEQ', 'SOURCE_SIZE',
    'INDEX_AT', 'INDEX_SIZE', 'SOURCE_EXTENT', 'TOP', 'HEAP', 'ROOT_HAVE',
    'ROOT_KIND', 'NODES', 'ARITY', 'FIRST', 'DEPTH_LIMIT', 'NEED',
    'INPUT_SIZE', 'INPUT_AT', 'INPUT_FINAL', 'INPUT_ACTIVE', 'SOURCE_ACTIVE',
    'SOURCE_POS', 'SOURCE_STOP', 'OPAQUE_HANDLE', 'OPAQUE_QUERY',
    'OPAQUE_PENDING', 'LATE', 'ROOT_MASK', 'ROOT_UNKNOWN', 'DETAIL',
    'JSON_BYTES', 'DIGEST0', 'DIGEST1', 'DIGEST2', 'DIGEST3',
)
CONSTANTS.update({'S_' + name: i * 8 for i, name in enumerate(FIELDS)})
TEMPORARIES = ('KIND', 'VALUE', 'NEXT', 'DATA_AT', 'DATA_LEN', 'DATA_KIND',
               'SOURCE', 'END', 'IS_KEY', 'DEPTH', 'HASH', 'BUCKETS',
               'TABLE_BYTES', 'RECORD_BYTES', 'RAW_KIND')
CONSTANTS.update({'T_' + name: 384 + i * 8 for i, name in enumerate(TEMPORARIES)})
assert 384 + 8 * len(TEMPORARIES) <= 1024

KEYS = ('name', 'params', 'returns', 'effects', 'entry', 'blocks',
        'return_loans', 'schema', 'module', 'exports', 'functions')

COMMON = r'''
def sat(left:u64, right:u64) -> u64:
    if left >= CAP or right >= CAP - left:
        return CAP
    return left + right

def align8(value:u64) -> u64:
    return (value + 7) & 18446744073709551608

def event(w:mutbuf, action:u64) -> u32:
    if get(w, S_ESEQ) == U64_MAX:
        put(w, S_STATUS, 3)
        put(w, S_PHASE, 7)
        return BAD
    put(w, S_ESEQ, get(w, S_ESEQ) + 1)
    put(w, EVENT_BASE, EVENT_MAGIC)
    put(w, EVENT_BASE + 8, action)
    put(w, EVENT_BASE + 16, get(w, S_STATUS))
    put(w, EVENT_BASE + 24, get(w, S_LEASE))
    put(w, EVENT_BASE + 32, get(w, S_STREAM))
    put(w, EVENT_BASE + 40, get(w, S_PSEQ))
    put(w, EVENT_BASE + 48, get(w, S_ESEQ))
    put(w, EVENT_BASE + 56, get(w, S_ROOT_KIND))
    put(w, EVENT_BASE + 64, get(w, S_NODES))
    put(w, EVENT_BASE + 72, get(w, S_FIRST))
    put(w, EVENT_BASE + 80, choose(action == 3, get(w, S_NEED), 0))
    put(w, EVENT_BASE + 88, choose(action == 4, get(w, S_OPAQUE_HANDLE), 0))
    put(w, EVENT_BASE + 96, choose(action == 4, get(w, S_OPAQUE_QUERY), 0))
    put(w, EVENT_BASE + 104, get(w, S_LATE))
    put(w, EVENT_BASE + 112, get(w, S_ROOT_MASK))
    put(w, EVENT_BASE + 120, get(w, S_ROOT_UNKNOWN))
    return EVENT_BASE + 128

def refuse(w:mutbuf, reason:u64) -> u32:
    put(w, S_MAGIC, STATE_MAGIC)
    if get(w, S_STATUS) != 3:
        put(w, S_DETAIL, reason)
    put(w, S_STATUS, 3)
    put(w, S_PHASE, 7)
    event(w, 6)
    return BAD

def failed(w:mutbuf, reason:u64) -> u64:
    refuse(w, reason)
    return 0

def ensure(w:mutbuf, extra:u64) -> u64:
    heap = get(w, S_HEAP)
    if heap < ARENA_BASE or heap > length(w) or extra > U64_MAX - heap:
        return failed(w, 60)
    needed = heap + extra
    if needed <= length(w):
        return 1
    doubled = length(w)
    if doubled <= U64_MAX >> 1:
        doubled = doubled << 1
    put(w, S_NEED, choose(needed > doubled, needed, doubled))
    return 0

def suspended(w:mutbuf) -> u32:
    if get(w, S_STATUS) == 3:
        return BAD
    if get(w, S_NEED) <= length(w):
        return refuse(w, 61)
    put(w, S_PHASE, 3)
    return event(w, 3)

def correlation(s:readbuf, w:mutbuf) -> u64:
    if word(s, 8) != get(w, S_LEASE) or word(s, 16) != get(w, S_STREAM):
        return 0
    return choose(word(s, 24) == get(w, S_ESEQ), 1, 0)

def position(w:mutbuf) -> u64:
    parent = get(w, S_TOP)
    put(w, T_IS_KEY, 0)
    put(w, T_DEPTH, 0)
    if parent == 0:
        if get(w, S_ROOT_HAVE) != 0:
            return failed(w, 62)
        return 1
    if parent < ARENA_BASE or parent > get(w, S_HEAP) - FRAME_BYTES:
        return failed(w, 63)
    if get(w, parent + 16) == 0 or get(w, parent + 32) == U64_MAX:
        return failed(w, 64)
    put(w, T_DEPTH, get(w, parent + 32) + 1)
    if get(w, parent + 8) == 6 and get(w, parent + 24) == 0:
        put(w, T_IS_KEY, 1)
    return 1

def key_byte(r:readbuf, w:mutbuf, kind:u64, at:u64) -> u64:
    if kind == 1:
        return byte(r, at)
    return byte(w, at)

def candidate_byte(r:readbuf, w:mutbuf, at:u64) -> u64:
    return key_byte(r, w, get(w, T_DATA_KIND), get(w, T_DATA_AT) + at)

def key_equal(r:readbuf, w:mutbuf, record:u64) -> u64:
    size = get(w, T_DATA_LEN)
    if get(w, record + 40) != size:
        return 0
    i = 0
    while i < size:
        if key_byte(r, w, get(w, record + 24), get(w, record + 32) + i) != candidate_byte(r, w, i):
            return 0
        i = i + 1
    return 1

def prepare_key(r:readbuf, w:mutbuf, frame:u64) -> u64:
    if get(w, T_KIND) != 4:
        return failed(w, 65)
    hash = 1469598103934665603
    i = 0
    while i < get(w, T_DATA_LEN):
        hash = (hash ^ candidate_byte(r, w, i)) * 1099511628211
        i = i + 1
    put(w, T_HASH, hash)
    buckets = get(w, frame + 64)
    if buckets != 0:
        previous = get(w, get(w, frame + 72) + (hash & (buckets - 1)) * 8)
        while previous != 0:
            if previous < frame + FRAME_BYTES or previous > get(w, S_HEAP) - 48:
                return failed(w, 66)
            if get(w, previous + 16) == hash and key_equal(r, w, previous) != 0:
                return failed(w, 67)
            previous = get(w, previous + 8)
    fresh = 0
    if buckets == 0:
        fresh = 8
    elif get(w, frame + 80) >= buckets >> 1:
        if buckets > U64_MAX >> 4:
            return failed(w, 68)
        fresh = buckets << 1
    put(w, T_BUCKETS, fresh)
    table_bytes = fresh << 3
    put(w, T_TABLE_BYTES, table_bytes)
    size = 48
    if get(w, T_DATA_KIND) == 2:
        if get(w, T_DATA_LEN) > U64_MAX - 55:
            return failed(w, 69)
        size = 48 + align8(get(w, T_DATA_LEN))
    if table_bytes > U64_MAX - size:
        return failed(w, 70)
    put(w, T_RECORD_BYTES, size)
    return ensure(w, table_bytes + size)

def save_key(r:readbuf, w:mutbuf, frame:u64) -> u64:
    fresh = get(w, T_BUCKETS)
    if fresh != 0:
        table = get(w, S_HEAP)
        fill_range(w, table, get(w, T_TABLE_BYTES), 0)
        put(w, S_HEAP, table + get(w, T_TABLE_BYTES))
        record = get(w, frame + 40)
        while record != 0:
            bucket = table + (get(w, record + 16) & (fresh - 1)) * 8
            put(w, record + 8, get(w, bucket))
            put(w, bucket, record)
            record = get(w, record)
        put(w, frame + 64, fresh)
        put(w, frame + 72, table)
    record = get(w, S_HEAP)
    bucket = get(w, frame + 72) + (get(w, T_HASH) & (get(w, frame + 64) - 1)) * 8
    put(w, record, get(w, frame + 40))
    put(w, record + 8, get(w, bucket))
    put(w, record + 16, get(w, T_HASH))
    put(w, record + 24, get(w, T_DATA_KIND))
    put(w, record + 32, get(w, T_DATA_AT))
    put(w, record + 40, get(w, T_DATA_LEN))
    if get(w, T_DATA_KIND) == 2:
        move_output(w, get(w, T_DATA_AT), record + 48, get(w, T_DATA_LEN))
        put(w, record + 32, record + 48)
    put(w, frame + 40, record)
    put(w, bucket, record)
    put(w, frame + 80, get(w, frame + 80) + 1)
    put(w, S_HEAP, record + get(w, T_RECORD_BYTES))
    put(w, frame + 24, 1)
    if get(w, frame) == 0:
        bit = root_key_bit(r, w)
        if bit == 0:
            put(w, S_ROOT_UNKNOWN, 1)
        else:
            put(w, S_ROOT_MASK, get(w, S_ROOT_MASK) | bit)
    return 1

def attach_value(w:mutbuf) -> u64:
    parent = get(w, S_TOP)
    if parent == 0:
        put(w, S_ROOT_HAVE, 1)
        put(w, S_ROOT_KIND, get(w, T_KIND))
    elif get(w, parent + 8) == 5:
        put(w, parent + 16, get(w, parent + 16) - 1)
    else:
        put(w, parent + 24, 0)
        put(w, parent + 16, get(w, parent + 16) - 1)
    return 1

def count_value(w:mutbuf) -> u64:
    if get(w, T_DEPTH) > get(w, S_DEPTH_LIMIT) and get(w, S_FIRST) == U64_MAX:
        put(w, S_FIRST, get(w, S_ARITY))
    put(w, S_NODES, sat(get(w, S_NODES), 1))
    if get(w, T_KIND) >= 5:
        put(w, S_ARITY, sat(get(w, S_ARITY), get(w, T_VALUE)))
    return 1

def push_container(w:mutbuf) -> u64:
    frame = get(w, S_HEAP)
    fill_range(w, frame, FRAME_BYTES, 0)
    put(w, frame, get(w, S_TOP))
    put(w, frame + 8, get(w, T_KIND))
    put(w, frame + 16, get(w, T_VALUE))
    put(w, frame + 32, get(w, T_DEPTH))
    put(w, frame + 48, get(w, T_END))
    put(w, frame + 56, get(w, T_SOURCE))
    put(w, S_TOP, frame)
    put(w, S_HEAP, frame + FRAME_BYTES)
    return 1

def close_containers(w:mutbuf) -> u64:
    frame = get(w, S_TOP)
    while frame != 0:
        if get(w, frame + 16) != 0:
            return 1
        if get(w, frame + 24) != 0:
            return failed(w, 71)
        if get(w, frame + 56) != 0 and get(w, S_SOURCE_POS) != get(w, frame + 48):
            return failed(w, 72)
        parent = get(w, frame)
        put(w, S_TOP, parent)
        put(w, S_HEAP, frame)
        frame = parent
    return 1
'''

def literals_source():
    lines = ['def root_key_bit(r:readbuf, w:mutbuf) -> u64:']
    for bit, key in enumerate(KEYS):
        conditions = [f'get(w, T_DATA_LEN) == {len(key)}']
        conditions += [f'candidate_byte(r, w, {i}) == {value}' for i, value in enumerate(key.encode('ascii'))]
        lines += ['    if ' + ' and '.join(conditions) + ':', f'        return {1 << bit}']
    lines += ['    return 0']
    return '\n'.join(lines) + '\n'
