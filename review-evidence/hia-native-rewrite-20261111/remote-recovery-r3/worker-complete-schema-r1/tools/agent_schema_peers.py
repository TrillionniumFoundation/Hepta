"""Actual Graph-wire and fixed-pattern continuation for the schema owner.

The fixed caller must return the actual source-bound image result and immutable
workspace. The HIA owner creates every request and validates all association,
actual extent, error and output fields. No host wire/regex fallback is permitted.
"""
PEERS=r'''
def sv_peer_begin(w:mutbuf, peer:u64, root:u64, command:u64, size:u64, next_stage:u64) -> u64:
    if sv_get(w, V_RESPONSE_ACTIVE) != 0:
        return sv_badset(w, 40)
    sequence = sv_get(w, V_REQ_SEQ)
    if sequence == SV_MAX:
        return sv_badset(w, 41)
    sv_put(w, V_REQ_SEQ, sequence + 1)
    sv_put(w, V_PEER, peer)
    sv_put(w, V_PEER_ROOT, root)
    sv_put(w, V_PEER_WIRE, command)
    sv_put(w, V_PEER_WIRE_BYTES, size)
    sv_put(w, sv_get(w, V_FRAME) + F_STAGE, next_stage)
    sv_put(w, V_STATUS, 2)
    return 1

def sv_wire_request(w:mutbuf, identifier:u64, next_stage:u64) -> u64:
    if identifier == 0 or identifier > sv_get(w, V_NODES):
        return sv_badset(w, 42)
    if sv_get(w, V_REQ_SEQ) == SV_MAX:
        return sv_badset(w, 43)
    sv_put(w, SV_WIRE, SV_WIRE_COMMAND)
    sv_put(w, SV_WIRE + 8, sv_get(w, V_GRAPH_LEASE))
    sv_put(w, SV_WIRE + 16, sv_get(w, V_REQ_SEQ) + 1)
    sv_put(w, SV_WIRE + 24, identifier)
    sv_put(w, SV_WIRE + 32, 8388608)
    sv_put(w, SV_WIRE + 40, 2)
    sv_put(w, SV_WIRE + 48, sv_get(w, V_DIGITS))
    sv_put(w, SV_WIRE + 56, 0)
    return sv_peer_begin(w, 1, identifier, SV_WIRE, 64, next_stage)

def sv_pattern_request(g:readbuf, w:mutbuf, pattern:u64, value:u64, next_stage:u64) -> u64:
    if sv_get(w, V_RESPONSE_ACTIVE) != 0 or sv_get(w, V_REQ_SEQ) == SV_MAX:
        return sv_badset(w, 44)
    pp = sv_node(g, w, pattern)
    vp = sv_node(g, w, value)
    if pp == 0 or vp == 0:
        return 0
    if sn_word(g, pp) != 4 or sn_word(g, vp) != 4:
        return sv_badset(w, 45)
    kind = 1
    found = 0
    while kind <= 5:
        if sv_named(g, w, pattern, 200 + kind) != 0:
            found = kind
        kind = kind + 1
    if found == 0:
        return sv_badset(w, 46)
    ps = sn_word(g, pp + 16)
    vs = sn_word(g, vp + 16)
    if ps > SV_MAX - 64 or vs > SV_MAX - 64 - ps:
        return sv_badset(w, 47)
    total = 64 + ps + vs
    if sv_require(w, total) == 0:
        return 0
    command = sv_alloc(w, total)
    sv_put(w, command, SV_PATTERN_COMMAND)
    sv_put(w, command + 8, sv_get(w, V_LEASE))
    sv_put(w, command + 16, sv_get(w, V_REQ_SEQ) + 1)
    sv_put(w, command + 24, ps)
    sv_put(w, command + 32, vs)
    sv_put(w, command + 40, total)
    sv_put(w, command + 48, 0)
    sv_put(w, command + 56, 0)
    copy_bytes(w, g, command + 64, sn_word(g, pp + 8), ps)
    copy_bytes(w, g, command + 64 + ps, sn_word(g, vp + 8), vs)
    sv_put(w, V_PATTERN_ID, found)
    sv_put(w, V_PATTERN_BYTES, vs)
    return sv_peer_begin(w, 2, value, command, total, next_stage)

def sv_receive(r:readbuf, w:mutbuf) -> u64:
    if sv_get(w, SV_ACK_BASE) != SV_ACK:
        return 0
    if sv_get(w, SV_ACK_BASE + 8) != sv_get(w, V_LEASE):
        return 0
    if sv_get(w, SV_ACK_BASE + 16) != sv_get(w, V_CALL):
        return 0
    if sv_get(w, SV_ACK_BASE + 24) != sv_get(w, V_REQ_SEQ):
        return 0
    if sv_get(w, SV_ACK_BASE + 32) != sv_get(w, V_PEER):
        return 0
    if sv_get(w, SV_ACK_BASE + 48) != length(r) or sv_get(w, SV_ACK_BASE + 56) != 0:
        return 0
    status = sv_get(w, SV_ACK_BASE + 40)
    peer = sv_get(w, V_PEER)
    header = 0
    if peer == 1:
        if status != 128 or length(r) < 128:
            return 0
        if sv_wire_response(r, w) == 0:
            return 0
        header = 128
    elif peer == 2:
        if status != 64 or length(r) != 64:
            return 0
        if sn_word(r, 0) != SV_PATTERN_EVENT or sn_word(r, 8) != sv_get(w, V_LEASE):
            return 0
        if sn_word(r, 16) != sv_get(w, V_REQ_SEQ) or sn_word(r, 24) > 1:
            return 0
        if sn_word(r, 32) != sv_get(w, V_PATTERN_ID) or sn_word(r, 40) != sv_get(w, V_PATTERN_BYTES):
            return 0
        if sn_word(r, 48) != 0 or sn_word(r, 56) != 0:
            return 0
        sv_put(w, V_PATTERN_MATCH, sn_word(r, 24))
        header = 64
    else:
        return 0
    index = 0
    while index < 64:
        store(w, SV_SAVED_ACK + index, byte(w, SV_ACK_BASE + index))
        index = index + 1
    copy_bytes(w, r, SV_SAVED_PEER_HEADER, 0, header)
    sv_put(w, V_RESPONSE_ACTIVE, 1)
    sv_put(w, V_RESPONSE_BYTES, length(r))
    sv_put(w, V_RESPONSE_HEADER_BYTES, header)
    sv_put(w, V_STATUS, 1)
    return 1

def sv_wire_response(r:readbuf, w:mutbuf) -> u64:
    if sn_word(r, 0) != SV_WIRE_EVENT or sn_word(r, 16) != sv_get(w, V_GRAPH_LEASE):
        return 0
    if sn_word(r, 24) != sv_get(w, V_REQ_SEQ) or sn_word(r, 32) != sv_get(w, V_PEER_ROOT):
        return 0
    if sn_word(r, 40) != 8388608 or sn_word(r, 48) != 2 or sn_word(r, 56) != sv_get(w, V_DIGITS):
        return 0
    if sn_word(r, 104) != 0 or sn_word(r, 120) != 0:
        return 0
    action = sn_word(r, 8)
    if action == 0:
        if sn_word(r, 64) != 0 or sn_word(r, 72) != 0:
            return 0
        start = sn_word(r, 88)
        size = sn_word(r, 96)
        if start > length(r) or size == 0 or size > length(r) - start or size > 8388608:
            return 0
        sv_put(w, V_RESPONSE_OUT, start)
        sv_put(w, V_RESPONSE_SIZE, size)
        return 1
    if action == 3:
        if sn_word(r, 88) != 0 or sn_word(r, 96) != 0:
            return 0
        reason = sn_word(r, 64)
        if reason == 0 or reason > 16:
            return 0
        sv_put(w, V_RESPONSE_OUT, 0)
        sv_put(w, V_RESPONSE_SIZE, 0)
        sv_failure(w, 2, reason, sn_word(r, 72))
        return 1
    return 0

def sv_same_peer(r:readbuf, w:mutbuf) -> u64:
    if length(r) != sv_get(w, V_RESPONSE_BYTES):
        return 0
    index = 0
    while index < 64:
        if byte(w, SV_ACK_BASE + index) != byte(w, SV_SAVED_ACK + index):
            return 0
        index = index + 1
    header = sv_get(w, V_RESPONSE_HEADER_BYTES)
    if header > length(r):
        return 0
    index = 0
    while index < header:
        if byte(r, index) != byte(w, SV_SAVED_PEER_HEADER + index):
            return 0
        index = index + 1
    return 1

def sv_clear_response(w:mutbuf) -> u64:
    sv_put(w, V_RESPONSE_ACTIVE, 0)
    sv_put(w, V_RESPONSE_BYTES, 0)
    sv_put(w, V_RESPONSE_HEADER_BYTES, 0)
    sv_put(w, V_RESPONSE_OUT, 0)
    sv_put(w, V_RESPONSE_SIZE, 0)
    return 0

def sv_copy_wire(r:readbuf, w:mutbuf) -> u64:
    if sv_get(w, V_RESPONSE_ACTIVE) == 0 or sv_get(w, V_PEER) != 1:
        return sv_badset(w, 48)
    size = sv_get(w, V_RESPONSE_SIZE)
    if size == 0:
        return sv_badset(w, 49)
    if sv_require(w, size) == 0:
        return 0
    target = sv_alloc(w, size)
    copy_bytes(w, r, target, sv_get(w, V_RESPONSE_OUT), size)
    frame = sv_get(w, V_FRAME)
    sv_put(w, frame + F_WIRE_AT, target)
    sv_put(w, frame + F_WIRE_BYTES, size)
    sv_clear_response(w)
    return 1

def sv_compare_wire(r:readbuf, w:mutbuf) -> u64:
    if sv_get(w, V_RESPONSE_ACTIVE) == 0 or sv_get(w, V_PEER) != 1:
        sv_badset(w, 50)
        return 0
    frame = sv_get(w, V_FRAME)
    size = sv_get(w, V_RESPONSE_SIZE)
    if size != sv_get(w, frame + F_WIRE_BYTES):
        return 0
    previous = sv_get(w, frame + F_WIRE_AT)
    current = sv_get(w, V_RESPONSE_OUT)
    index = 0
    while index < size:
        if byte(w, previous + index) != byte(r, current + index):
            return 0
        index = index + 1
    return 1

def sv_event(w:mutbuf, action:u64, role:u64) -> u32:
    sequence = sv_get(w, V_SEQ)
    if sequence == SV_MAX:
        sv_put(w, V_STATUS, 6)
        return SV_BAD
    sv_put(w, V_SEQ, sequence + 1)
    sv_put(w, V_ALLOWED_ROLE, role)
    frame = sv_get(w, V_FRAME)
    stage = 0
    value = 0
    schema = 0
    if frame != 0:
        stage = sv_get(w, frame + F_STAGE)
        value = sv_get(w, frame + F_VALUE)
        schema = sv_get(w, frame + F_SCHEMA)
    sv_put(w, SV_EVENT_BASE, SV_EVENT)
    sv_put(w, SV_EVENT_BASE + 8, action)
    sv_put(w, SV_EVENT_BASE + 16, sv_get(w, V_LEASE))
    sv_put(w, SV_EVENT_BASE + 24, sv_get(w, V_CALL))
    sv_put(w, SV_EVENT_BASE + 32, sv_get(w, V_SEQ))
    sv_put(w, SV_EVENT_BASE + 40, sv_get(w, V_GRAPH_LEASE))
    sv_put(w, SV_EVENT_BASE + 48, sv_get(w, V_REQ_SEQ))
    sv_put(w, SV_EVENT_BASE + 56, sv_get(w, V_PEER))
    sv_put(w, SV_EVENT_BASE + 64, sv_get(w, V_PEER_ROOT))
    sv_put(w, SV_EVENT_BASE + 72, role)
    sv_put(w, SV_EVENT_BASE + 80, choose(action == 1, sv_get(w, V_NEED), 0))
    sv_put(w, SV_EVENT_BASE + 88, choose(action == 3, sv_get(w, V_PEER_WIRE), 0))
    sv_put(w, SV_EVENT_BASE + 96, choose(action == 3, sv_get(w, V_PEER_WIRE_BYTES), 0))
    sv_put(w, SV_EVENT_BASE + 104, frame)
    sv_put(w, SV_EVENT_BASE + 112, stage)
    sv_put(w, SV_EVENT_BASE + 120, sv_get(w, V_RESPONSE_ACTIVE))
    sv_put(w, SV_EVENT_BASE + 128, sv_get(w, V_RESPONSE_BYTES))
    sv_put(w, SV_EVENT_BASE + 136, sv_get(w, V_ERROR_DOMAIN))
    sv_put(w, SV_EVENT_BASE + 144, sv_get(w, V_ERROR_REASON))
    sv_put(w, SV_EVENT_BASE + 152, choose(action == 2, sv_get(w, V_ERROR_PTR), 0))
    sv_put(w, SV_EVENT_BASE + 160, choose(action == 2, sv_get(w, V_ERROR_BYTES), 0))
    sv_put(w, SV_EVENT_BASE + 168, value)
    sv_put(w, SV_EVENT_BASE + 176, schema)
    sv_put(w, SV_EVENT_BASE + 184, sv_get(w, V_DIGITS))
    sv_put(w, SV_EVENT_BASE + 192, sv_get(w, V_BAD))
    sv_put(w, SV_EVENT_BASE + 200, sv_get(w, V_FLOW))
    sv_put(w, SV_EVENT_BASE + 208, sv_get(w, V_MODE))
    sv_put(w, SV_EVENT_BASE + 216, sv_get(w, V_STATUS))
    sv_put(w, SV_EVENT_BASE + 224, sv_get(w, V_PEAK_HEAP))
    sv_put(w, SV_EVENT_BASE + 232, 0)
    sv_put(w, SV_EVENT_BASE + 240, 0)
    sv_put(w, SV_EVENT_BASE + 248, 0)
    return SV_EVENT_END
'''
