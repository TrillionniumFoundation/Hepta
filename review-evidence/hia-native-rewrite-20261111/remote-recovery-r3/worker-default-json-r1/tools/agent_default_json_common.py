"""Complete default decode_data prefix: shared native protocol and custody.

NEW UNEXECUTED DEVELOPMENT. Raw input and every peer arena/workspace are
immutable private issued leases in a fixed same-context coordinator. Matching
headers are correlation only, never authentication of an arbitrary supplied
arena. A BAD return always retires the invocation, including short-workspace
and event-counter overflow cases which cannot publish a fresh poison frame.
"""
CONSTANTS={
 'GC_COMMAND':int.from_bytes(b'HIAGDC01','little'),
 'GC_REPLY':int.from_bytes(b'HIAGDA01','little'),
 'GC_EVENT':int.from_bytes(b'HIAGDE01','little'),
 'GC_STATE':int.from_bytes(b'HIAGDS01','little'),
 'GC_ARENA':int.from_bytes(b'HIADATA1','little'),
 'GC_GRAPH':int.from_bytes(b'HIAGRF01','little'),
 'GC_VALUES_COMMAND':int.from_bytes(b'HIADGC01','little'),
 'GC_VALUES_EVENT':int.from_bytes(b'HIADGE01','little'),
 'GC_BAD':0xfffffffd,'GC_MAX':(1<<64)-1,'GC_MIN':8192,
 'GC_CONFIG':128,'GC_ACK':256,'GC_SAVED_CONFIG':1152,
 'GC_PEER_CONFIG':1280,'GC_EVENT_BASE':2048,
 'GC_TEXT':3072,'GC_TEXT_CAP':1024,'GC_STACK':4096,
 'GC_DECIMAL':7680,'GC_MASK':8192,
}
_FIELDS=('MAGIC','PHASE','SEQ','BAD','RAW_BYTES','NEED','MASK_BYTES',
 'PEER','PENDING','INPUT_OWNER','INPUT_AT','INPUT_SIZE','OUTPUT_CAP','WORK_CAP',
 'CONFIG_AT','CONFIG_SIZE','RESULT_OWNER','RESULT_AT','RESULT_SIZE',
 'ERROR_DOMAIN','ERROR_REASON','ERROR_START','ERROR_END','ERROR_AUX',
 'ERROR_LINE','ERROR_COLUMN','TEXT_SIZE','UTF8_NEXT','UTF8_VALUE',
 'UTF8_REASON','UTF8_END','TOKEN_FLOAT','TOKEN_DIGITS','TOKEN_END',
 'CURSOR','DEPTH','ROOT_DONE','NUMBER_START','NUMBER_SIZE','ARENA_EXTENT',
 'ACTUAL_STATUS','ACTUAL_EXTENT','VALUES_SEQ','VALUES_WORK_EXTENT',
 'NUMBER_COUNT','PREFLIGHT_PASSED','DECODE_ATTEMPTS','BINARY_ATTEMPTS')
CONSTANTS.update({'G_'+name:512+i*8 for i,name in enumerate(_FIELDS)})
COMMON=r'''
def gc_entry(s:readbuf, r:readbuf, w:mutbuf, role:u64) -> u32:
    if length(w) < GC_MIN:
        return GC_BAD
    if gc_get(w, G_PHASE) >= 90:
        return GC_BAD
    if gc_get(w, G_MAGIC) == 0:
        if role != 1 or length(r) != 0 or gc_initial(s, w) == 0:
            gc_bad(w, 1)
            return GC_BAD
    elif gc_get(w, G_MAGIC) != GC_STATE or gc_same(s, w) == 0:
        gc_bad(w, 2)
        return GC_BAD
    if gc_role(w) != role:
        gc_bad(w, 3)
        return GC_BAD
    action = gc_step(s, r, w)
    if gc_get(w, G_PHASE) == 99:
        gc_event(w, 4)
        return GC_BAD
    if action > 5:
        gc_bad(w, 4)
        return GC_BAD
    return gc_event(w, action)

def gc_initial(s:readbuf, w:mutbuf) -> u64:
    if gc_get(w, GC_CONFIG) != GC_COMMAND:
        return 0
    if gc_get(w, 136) == 0 or gc_get(w, 144) == 0:
        return 0
    if gc_get(w, 152) == 0 or gc_get(w, 160) == 0:
        return 0
    if gc_get(w, 184) == 0 or gc_get(w, 192) == 0:
        return 0
    if gc_get(w, 200) != length(s):
        return 0
    if gc_get(w, 176) != 0 and gc_get(w, 176) < 640:
        return 0
    at = 208
    while at < 256:
        if gc_get(w, at) != 0:
            return 0
        at = at + 8
    at = 0
    while at < GC_MIN:
        if at < GC_CONFIG or at >= 256:
            if byte(w, at) != 0:
                return 0
        at = at + 1
    at = 0
    while at < 128:
        store(w, GC_SAVED_CONFIG + at, byte(w, GC_CONFIG + at))
        at = at + 1
    gc_put(w, G_MAGIC, GC_STATE)
    gc_put(w, G_RAW_BYTES, length(s))
    gc_put(w, G_PHASE, 1)
    return 1

def gc_same(s:readbuf, w:mutbuf) -> u64:
    if length(s) != gc_get(w, G_RAW_BYTES):
        return 0
    at = 0
    while at < 128:
        if byte(w, GC_CONFIG + at) != byte(w, GC_SAVED_CONFIG + at):
            return 0
        at = at + 1
    return 1

def gc_role(w:mutbuf) -> u64:
    phase = gc_get(w, G_PHASE)
    if phase == 1 or phase == 10:
        return 1
    if phase == 20 or phase == 30 or phase == 40:
        return 2
    if phase == 50 or phase == 51:
        return 3
    return 0

def gc_bad(w:mutbuf, reason:u64) -> u64:
    gc_put(w, G_BAD, reason)
    gc_put(w, G_PHASE, 99)
    return 4

def gc_error(w:mutbuf, domain:u64, reason:u64) -> u64:
    if gc_get(w, G_PHASE) == 99:
        return 4
    gc_put(w, G_ERROR_DOMAIN, domain)
    gc_put(w, G_ERROR_REASON, reason)
    gc_put(w, G_RESULT_OWNER, 1)
    gc_put(w, G_RESULT_AT, GC_TEXT)
    gc_put(w, G_RESULT_SIZE, gc_get(w, G_TEXT_SIZE))
    gc_put(w, G_PHASE, 91)
    gc_put(w, G_PEER, 0)
    gc_put(w, G_PENDING, 0)
    return 3

def gc_simple_error(w:mutbuf, domain:u64, reason:u64, text:u64) -> u64:
    gc_put(w, G_TEXT_SIZE, 0)
    gc_text(w, text)
    if gc_get(w, G_PHASE) == 99:
        return 4
    return gc_error(w, domain, reason)

def gc_request(w:mutbuf, peer:u64, phase:u64) -> u64:
    gc_put(w, G_PEER, peer)
    gc_put(w, G_PENDING, 0)
    gc_put(w, G_PHASE, phase)
    fill_range(w, GC_ACK, 128, 0)
    return 2

def gc_ack(r:readbuf, w:mutbuf, peer:u64) -> u64:
    if gc_get(w, G_PEER) != peer or gc_get(w, G_PENDING) == 0:
        return 0
    if gc_get(w, GC_ACK) != GC_REPLY:
        return 0
    if gc_get(w, 264) != gc_get(w, 136) or gc_get(w, 272) != gc_get(w, 144):
        return 0
    if gc_get(w, 280) != gc_get(w, G_PENDING) or gc_get(w, 288) != peer:
        return 0
    if gc_get(w, 296) > 4294967295 or gc_get(w, 304) != length(r):
        return 0
    if gc_get(w, 336) != gc_get(w, 152):
        return 0
    if gc_get(w, 344) != gc_get(w, G_OUTPUT_CAP):
        return 0
    if gc_get(w, 352) != gc_get(w, G_INPUT_SIZE):
        return 0
    at = 360
    while at < 384:
        if gc_get(w, at) != 0:
            return 0
        at = at + 8
    if peer == 3:
        if gc_get(w, 320) != gc_get(w, 192) or gc_get(w, 328) != gc_get(w, 192):
            return 0
        if gc_get(w, 312) != length(r) or length(r) < 4096:
            return 0
    else:
        if gc_get(w, 328) != gc_get(w, 136) or gc_get(w, 312) != gc_get(w, G_WORK_CAP):
            return 0
        if peer == 2:
            if gc_get(w, 320) != gc_get(w, 184):
                return 0
        elif gc_get(w, 320) != 0:
            return 0
    gc_put(w, G_ACTUAL_STATUS, gc_get(w, 296))
    gc_put(w, G_ACTUAL_EXTENT, length(r))
    return 1

def gc_event(w:mutbuf, action:u64) -> u32:
    if gc_get(w, G_SEQ) == GC_MAX:
        gc_put(w, G_PHASE, 99)
        return GC_BAD
    gc_put(w, G_SEQ, gc_get(w, G_SEQ) + 1)
    if action == 2:
        gc_put(w, G_PENDING, gc_get(w, G_SEQ))
    fill_range(w, GC_EVENT_BASE, 256, 0)
    gc_put(w, GC_EVENT_BASE, GC_EVENT)
    gc_put(w, GC_EVENT_BASE + 8, action)
    gc_put(w, GC_EVENT_BASE + 16, gc_get(w, 136))
    gc_put(w, GC_EVENT_BASE + 24, gc_get(w, 144))
    gc_put(w, GC_EVENT_BASE + 32, gc_get(w, G_SEQ))
    gc_put(w, GC_EVENT_BASE + 40, gc_get(w, 152))
    gc_put(w, GC_EVENT_BASE + 48, gc_get(w, 160))
    gc_put(w, GC_EVENT_BASE + 56, gc_get(w, 168))
    gc_put(w, GC_EVENT_BASE + 64, gc_get(w, 176))
    gc_put(w, GC_EVENT_BASE + 72, gc_get(w, G_PHASE))
    gc_put(w, GC_EVENT_BASE + 80, gc_role(w))
    if action == 1:
        gc_put(w, GC_EVENT_BASE + 88, gc_get(w, G_NEED))
    if action == 2:
        gc_put(w, GC_EVENT_BASE + 96, gc_get(w, G_PEER))
        gc_put(w, GC_EVENT_BASE + 104, gc_get(w, G_PENDING))
        gc_put(w, GC_EVENT_BASE + 112, gc_get(w, G_INPUT_OWNER))
        gc_put(w, GC_EVENT_BASE + 120, gc_get(w, G_INPUT_AT))
        gc_put(w, GC_EVENT_BASE + 128, gc_get(w, G_INPUT_SIZE))
        gc_put(w, GC_EVENT_BASE + 136, gc_get(w, G_OUTPUT_CAP))
        gc_put(w, GC_EVENT_BASE + 144, gc_get(w, G_WORK_CAP))
        gc_put(w, GC_EVENT_BASE + 152, gc_get(w, G_CONFIG_AT))
        gc_put(w, GC_EVENT_BASE + 160, gc_get(w, G_CONFIG_SIZE))
    if action == 0 or action == 3:
        gc_put(w, GC_EVENT_BASE + 168, gc_get(w, G_RESULT_OWNER))
        gc_put(w, GC_EVENT_BASE + 176, gc_get(w, G_RESULT_AT))
        gc_put(w, GC_EVENT_BASE + 184, gc_get(w, G_RESULT_SIZE))
    gc_put(w, GC_EVENT_BASE + 192, gc_get(w, G_ERROR_DOMAIN))
    gc_put(w, GC_EVENT_BASE + 200, gc_get(w, G_ERROR_REASON))
    gc_put(w, GC_EVENT_BASE + 208, gc_get(w, G_ERROR_START))
    gc_put(w, GC_EVENT_BASE + 216, gc_get(w, G_ERROR_END))
    gc_put(w, GC_EVENT_BASE + 224, gc_get(w, G_ERROR_AUX))
    gc_put(w, GC_EVENT_BASE + 232, gc_get(w, G_ERROR_LINE))
    gc_put(w, GC_EVENT_BASE + 240, gc_get(w, G_ERROR_COLUMN))
    return 2304

def gc_word(s:readbuf, at:u64) -> u64:
    value = byte(s, at)
    value = value | (byte(s, at + 1) << 8)
    value = value | (byte(s, at + 2) << 16)
    value = value | (byte(s, at + 3) << 24)
    value = value | (byte(s, at + 4) << 32)
    value = value | (byte(s, at + 5) << 40)
    value = value | (byte(s, at + 6) << 48)
    return value | (byte(s, at + 7) << 56)

def gc_get(w:mutbuf, at:u64) -> u64:
    value = byte(w, at)
    value = value | (byte(w, at + 1) << 8)
    value = value | (byte(w, at + 2) << 16)
    value = value | (byte(w, at + 3) << 24)
    value = value | (byte(w, at + 4) << 32)
    value = value | (byte(w, at + 5) << 40)
    value = value | (byte(w, at + 6) << 48)
    return value | (byte(w, at + 7) << 56)

def gc_put(w:mutbuf, at:u64, value:u64) -> u64:
    store(w, at, value & 255)
    store(w, at + 1, (value >> 8) & 255)
    store(w, at + 2, (value >> 16) & 255)
    store(w, at + 3, (value >> 24) & 255)
    store(w, at + 4, (value >> 32) & 255)
    store(w, at + 5, (value >> 40) & 255)
    store(w, at + 6, (value >> 48) & 255)
    store(w, at + 7, (value >> 56) & 255)
    return value
'''
