"""Epoch-bound HIA admission for new effects, preserving predecessor roots."""
from tools.generate_hia_mcp_job_bridge_common import authored, FIELD

TEXT={'lock':'.owner.lock','owner':'.owner.json'}
SOURCE=r'''
def advance(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    phase = get(w, 0)
    result = get(w, 8)
    if phase == 0:
        if get(w, S_FENCE_ROOT + 8) == 0:
            return enter(w, 2, 60)
        return walk(w, 6, 1, get(w, S_FENCE_ROOT), get(w, S_FENCE_ROOT + 8), 0)
    if phase == 1:
        put(w, 1704, get(w, 1040))
        copy_state(w, 9216, 17408, 144)
        at = text_lock(w, 16384)
        store(w, at, 0)
        return call(o, w, 2, 257, get(w, 1704), 16384, 657410, 0, 0, 0, 12)
    if phase == 2:
        if failed(result) or result < 3:
            return 0
        put(w, 1712, result)
        return call(o, w, 3, 5, result, 9216, 0, 0, 0, 0, 12)
    if phase == 3:
        if failed(result) or safe_regular(w, 9216, 1) == False:
            return 0
        copy_state(w, 9216, 17552, 144)
        return call(o, w, 4, 73, get(w, 1712), 5, 0, 0, 0, 0, 0)
    if phase == 4:
        if result == NEG11:
            return call(o, w, 5, 228, 1, 9216, 0, 0, 0, 0, 12)
        if failed(result):
            return 0
        at = text_owner(w, 16384)
        store(w, at, 0)
        return capture(w, 6, 7, get(w, 1704), 16384, 4096, JSON, 1, 0)
    if phase == 5:
        if failed(result) or get(w, 9216) * 1000000000 + get(w, 9224) >= get(w, 48):
            return 0
        put(w, 9248, 0)
        put(w, 9256, 100000000)
        return call(o, w, 6, 35, 9248, 0, 0, 0, 0, 0, 3)
    if phase == 6:
        if failed(result) and result != NEG4:
            return 0
        return call(o, w, 4, 73, get(w, 1712), 5, 0, 0, 0, 0, 0)
    if phase == 7:
        if get(w, 1112) == 0:
            return 0
        return decode(o, w, 8, JSON, get(w, 1112))
    if phase == 8:
        if result >= 4294967292 or get(w, ARENA + 64) != 6 or owner_document(w) == 0:
            return 0
        return walk(w, 6, 9, get(w, S_STATE_ROOT), get(w, S_STATE_ROOT + 8), 0)
    if phase == 9:
        if get(w, 9216) != get(w, 14848) or get(w, 9224) != get(w, 14856):
            return 0
        return call(o, w, 10, 3, get(w, 1040), 0, 0, 0, 0, 0, 0)
    if phase == 10:
        if failed(result):
            return 0
        if get(w, S_PREDECESSOR + 8) != 0:
            return walk(w, 6, 11, get(w, S_PREDECESSOR), get(w, S_PREDECESSOR + 8), 0)
        return verify_lock(o, w)
    if phase == 11:
        if get(w, 9216) == get(w, 14848) and get(w, 9224) == get(w, 14856):
            return 0
        put(w, 1720, get(w, 1040))
        copy_state(w, 9216, 17792, 144)
        return verify_lock(o, w)
    if phase == 12:
        if failed(result) or result < 3:
            return 0
        put(w, 1728, result)
        return call(o, w, 13, 5, result, 9216, 0, 0, 0, 0, 12)
    if phase == 13:
        if failed(result) or safe_regular(w, 9216, 1) == False or get(w, 9216) != get(w, 17552) or get(w, 9224) != get(w, 17560):
            return 0
        return call(o, w, 14, 3, get(w, 1728), 0, 0, 0, 0, 0, 0)
    if phase == 14:
        if failed(result):
            return 0
        put(w, 1736, 0)
        return verify_paths(w)
    if phase == 20:
        if get(w, 9216) != get(w, 17408) or get(w, 9224) != get(w, 17416):
            return 0
        return call(o, w, 21, 3, get(w, 1040), 0, 0, 0, 0, 0, 0)
    if phase == 21:
        if failed(result):
            return 0
        if get(w, S_PREDECESSOR + 8) != 0:
            return walk(w, 6, 22, get(w, S_PREDECESSOR), get(w, S_PREDECESSOR + 8), 0)
        return done(w)
    if phase == 22:
        if get(w, 9216) != get(w, 17792) or get(w, 9224) != get(w, 17800):
            return 0
        return call(o, w, 23, 3, get(w, 1040), 0, 0, 0, 0, 0, 0)
    if phase == 23:
        if failed(result):
            return 0
        return done(w)
    if phase == 40:
        put(w, 1736, 1)
        return verify_paths(w)
    return 0

def verify_lock(o:mutbuf, w:mutbuf) -> u32:
    at = text_lock(w, 16384)
    store(w, at, 0)
    return call(o, w, 12, 257, get(w, 1704), 16384, 657410, 0, 0, 0, 12)

def verify_paths(w:mutbuf) -> u32:
    return walk(w, 6, 20, get(w, S_FENCE_ROOT), get(w, S_FENCE_ROOT + 8), 0)

def done(w:mutbuf) -> u32:
    if get(w, 1736) == 0:
        return enter(w, 2, 60)
    put(w, 1408, 1)
    return enter(w, 2, 7)

def owner_document(w:mutbuf) -> u64:
    seen = 0
    child = get(w, ARENA + 88)
    while child != NONE:
        row = ARENA + 64 + child * 72
        name = key_id(w, ARENA + get(w, row + 40), get(w, row + 48))
        if name >= 64 or (OWNER_FIELDS >> name) & 1 == 0 or seen & (1 << name) != 0:
            return 0
        seen = seen | (1 << name)
        child = get(w, row + 16)
    if str_is(w, field(w, F_SCHEMA), 0) == False or str_is(w, field(w, F_PHASE), 1) == False or string_eq(w, field(w, F_OWNER), S_SELF_OWNER) == False:
        return 0
    epoch = number(w, field(w, F_EPOCH))
    if epoch == 0 or valid_uint(w, field(w, F_EPOCH)) == False:
        return 0
    put(w, 1744, epoch)
    root = field(w, F_STATE_ROOT)
    if root == NONE or get(w, root) != 4 or path_equal(w, ARENA + get(w, root + 24), get(w, root + 32), get(w, S_STATE_ROOT), get(w, S_STATE_ROOT + 8)) == False:
        return 0
    prior = field(w, F_PREDECESSOR_STATE_ROOT)
    if text_is(w, get(w, S_SELF_OWNER), get(w, S_SELF_OWNER + 8), 2):
        if prior != NONE and is_null(w, prior) == False:
            return 0
    else:
        if freeze_string(w, prior, S_PREDECESSOR) == False or filesystem_path_ok(w, get(w, S_PREDECESSOR), get(w, S_PREDECESSOR + 8)) == False:
            return 0
    return 1
'''

def source():
    return authored(SOURCE,text=TEXT,extra={
      'OWNER_FIELDS':sum(1<<FIELD[n] for n in ('schema','owner','epoch','phase','state_root','predecessor_state_root')),
      '_checks':('hepta-effect-owner-fence-v1','admitting','v4')})
