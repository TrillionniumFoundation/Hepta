"""Bounded native pending cohorts for the retained-original index owner.

The queue bounds unpublished changes, never retained archive rows. A claimed
cohort keeps its slots until the actual cache writer relinquishes custody.
This module contains state policy; disk-image and reader ownership are separate.
"""

BASE = (22 << 20) + 32768
C = {
    'I_BASE': BASE,
    'I_SORT': BASE + 4096,
    'I_FREE': BASE + 4096 + 8192 * 8,
    'I_CLAIM': BASE + 4096 + 8192 * 8 + 16384 * 8,
    'I_POOL_FIRST': (25 << 20) + 528384,
    'I_POOL_SECOND': 20 << 20,
    'I_FIRST_SLOTS': 12272,
    'I_POOL_SLOTS': 16384,
    'I_ENTRY_BYTES': 384,
    'I_PENDING_LIMIT': 8192,
    'I_SMALL_WATERMARK': 4096,
    'I_LARGE_WATERMARK': 128,
    'I_LARGE_WRITE_CHUNK': 256,
    'I_QUERY_WRITE_CHUNK': 128,
    'I_LARGE_ROWS': 16384,
}

SOURCE = r'''
def index_slot(slot:u64) -> u64:
    if slot < I_FIRST_SLOTS:
        return I_POOL_FIRST+slot*I_ENTRY_BYTES
    return I_POOL_SECOND+(slot-I_FIRST_SLOTS)*I_ENTRY_BYTES

def index_init(w:mutbuf) -> u64:
    fill_range(w,I_BASE,256,0)
    return 0

def index_key_order(w:mutbuf,left:u64,right:u64) -> u64:
    at = 0
    while at < 64:
        a = byte(w,left+at)
        b = byte(w,right+at)
        if a < b:
            return 0
        if a > b:
            return 2
        at = at+1
    return 1

def index_find(w:mutbuf,key:u64) -> u64:
    low = 0
    high = get(w,I_BASE)
    while low < high:
        middle = low+(high-low)//2
        slot = get(w,I_SORT+middle*8)
        if index_key_order(w,index_slot(slot),key) == 0:
            low = middle+1
        else:
            high = middle
    return low

def index_free(w:mutbuf,slot:u64) -> u64:
    count = get(w,I_BASE+96)
    put(w,I_FREE+count*8,slot)
    return put(w,I_BASE+96,count+1)

def index_allocate(w:mutbuf) -> u64:
    count = get(w,I_BASE+96)
    if count != 0:
        put(w,I_BASE+96,count-1)
        return get(w,I_FREE+(count-1)*8)
    next = get(w,I_BASE+104)
    if next == I_POOL_SLOTS:
        return NONE
    put(w,I_BASE+104,next+1)
    return next

def index_invalidate(w:mutbuf) -> u64:
    count = get(w,I_BASE)
    at = 0
    while at < count:
        index_free(w,get(w,I_SORT+at*8))
        at = at+1
    put(w,I_BASE,0)
    put(w,I_BASE+24,0)
    put(w,I_BASE+32,1)
    put(w,I_BASE+64,0)
    return put(w,I_BASE+8,get(w,I_BASE+8)+1)

def index_watch_equal(w:mutbuf,present:u64,identity:u64,generation:u64) -> bool:
    if get(w,I_BASE+72) != present:
        return False
    if present == 0:
        return True
    return get(w,I_BASE+80) == identity and get(w,I_BASE+88) == generation

def index_publication_before(w:mutbuf,present:u64,identity:u64,generation:u64) -> u64:
    if index_watch_equal(w,present,identity,generation) == False:
        return index_invalidate(w)
    return 0

def index_note(w:mutbuf,record:u64,stamp:u64) -> bool:
    if get(w,I_BASE+32) != 0:
        return False
    count = get(w,I_BASE)
    at = index_find(w,record)
    slot = NONE
    if at < count:
        candidate = get(w,I_SORT+at*8)
        if index_key_order(w,index_slot(candidate),record) == 1:
            slot = candidate
    if slot == NONE:
        if count == I_PENDING_LIMIT:
            index_invalidate(w)
            return False
        slot = index_allocate(w)
        if slot == NONE:
            index_invalidate(w)
            return False
        move = count
        while move > at:
            put(w,I_SORT+move*8,get(w,I_SORT+(move-1)*8))
            move = move-1
        put(w,I_SORT+at*8,slot)
        count = count+1
        put(w,I_BASE,count)
    target = index_slot(slot)
    copy_state(w,record,target,240)
    copy_state(w,stamp,target+240,144)
    return True

def index_watermark(w:mutbuf) -> u64:
    return choose(get(w,I_BASE+56) != 0,I_LARGE_WATERMARK,I_SMALL_WATERMARK)

def index_wake_needed(w:mutbuf) -> bool:
    return get(w,I_BASE) >= index_watermark(w)

def index_publication_after(w:mutbuf,count:u64,present:u64,identity:u64,generation:u64,seconds:u64,nanos:u64,succeeded:bool) -> u64:
    if succeeded == False:
        return index_invalidate(w)
    put(w,I_BASE+72,present)
    put(w,I_BASE+80,identity)
    put(w,I_BASE+88,generation)
    put(w,I_BASE+128,seconds)
    put(w,I_BASE+136,nanos)
    return put(w,I_BASE+8,get(w,I_BASE+8)+count)

def index_claim(w:mutbuf,in_flight:bool,present:u64,identity:u64,generation:u64) -> bool:
    if get(w,I_BASE+32) != 0 or get(w,I_BASE+40) != 0:
        return False
    if get(w,I_BASE+72) != 0 and index_watch_equal(w,present,identity,generation) == False:
        return False
    if get(w,I_BASE+144) != 0:
        return False
    # A zero-sized cohort still has a live owner. Busy precedes queue removal.
    put(w,I_BASE+144,1)
    if in_flight:
        put(w,I_BASE+48,1)
    count = get(w,I_BASE)
    take = count
    if in_flight and get(w,I_BASE+56) != 0 and take > I_LARGE_WRITE_CHUNK:
        take = I_LARGE_WRITE_CHUNK
    put(w,I_BASE+112,take)
    put(w,I_BASE+120,get(w,I_BASE+8))
    at = 0
    while at < take:
        put(w,I_CLAIM+at*8,get(w,I_SORT+at*8))
        at = at+1
    at = take
    while at < count:
        put(w,I_SORT+(at-take)*8,get(w,I_SORT+at*8))
        at = at+1
    put(w,I_BASE,count-take)
    return True

def index_release_claim(w:mutbuf) -> u64:
    count = get(w,I_BASE+112)
    at = 0
    while at < count:
        index_free(w,get(w,I_CLAIM+at*8))
        at = at+1
    put(w,I_BASE+112,0)
    return put(w,I_BASE+144,0)

def index_complete_claim(w:mutbuf,succeeded:bool,rows:u64) -> bool:
    if get(w,I_BASE+144) == 0:
        return False
    generation = get(w,I_BASE+120)
    index_release_claim(w)
    put(w,I_BASE+48,0)
    if succeeded == False:
        index_invalidate(w)
        return False
    if get(w,I_BASE+32) != 0:
        return False
    put(w,I_BASE+16,generation)
    put(w,I_BASE+56,choose(rows > I_LARGE_ROWS,1,0))
    # The original worker releases the request after this exact generation
    # and its entire pending tail have both been applied.
    if get(w,I_BASE+8) == generation and get(w,I_BASE) == 0:
        put(w,I_BASE+64,0)
    return True

def index_query_allowed(w:mutbuf,allow_pending:bool,present:u64,identity:u64,generation:u64) -> bool:
    count = get(w,I_BASE)
    complete = get(w,I_BASE+16) == get(w,I_BASE+8)
    if count != 0:
        complete = allow_pending and get(w,I_BASE+56) != 0 and get(w,I_BASE+72) != 0 and count <= I_QUERY_WRITE_CHUNK
    return index_watch_equal(w,present,identity,generation) and get(w,I_BASE+32) == 0 and get(w,I_BASE+48) == 0 and complete and get(w,I_BASE+24) != 0

def index_drain_action(w:mutbuf,present:u64,identity:u64,generation:u64) -> u64:
    if get(w,I_BASE+32) != 0 or get(w,I_BASE+40) != 0 or index_watch_equal(w,present,identity,generation) == False:
        return 0
    if get(w,I_BASE+48) != 0:
        return 1
    count = get(w,I_BASE)
    if count == 0:
        return choose(get(w,I_BASE+16) == get(w,I_BASE+8),2,1)
    if get(w,I_BASE+56) != 0 and count > I_QUERY_WRITE_CHUNK:
        put(w,I_BASE+64,1)
        return 1
    if get(w,I_BASE+56) != 0 and get(w,I_BASE+72) != 0:
        put(w,I_BASE+64,1)
        return 2
    if get(w,I_BASE+24) == 0:
        return 0
    return 3

def index_transition(w:mutbuf,old:u64,new:u64) -> u64:
    if record_equal(w,old,new) and stamp_equal(w,old+240,new+240):
        return 0
    if record_identity(w,old,new) == False:
        return 2
    if get(w,old+200) != 0 and get(w,new+200) == 0:
        return 0
    if get(w,old+200) != 0 and record_equal(w,old,new) == False:
        return 3
    return 1
'''


def check_layout():
    """The two bounded cohorts fit in unused areas of the existing 32 MiB owner."""
    assert C['I_POOL_FIRST'] >= (25 << 20) + 8 * 65664
    assert C['I_POOL_FIRST'] + C['I_FIRST_SLOTS'] * C['I_ENTRY_BYTES'] <= 30 << 20
    assert C['I_POOL_SECOND'] + (C['I_POOL_SLOTS'] - C['I_FIRST_SLOTS']) * C['I_ENTRY_BYTES'] <= 22 << 20
    assert C['I_CLAIM'] + C['I_PENDING_LIMIT'] * 8 < 23 << 20
    assert C['I_POOL_SLOTS'] == 2 * C['I_PENDING_LIMIT']


check_layout()
