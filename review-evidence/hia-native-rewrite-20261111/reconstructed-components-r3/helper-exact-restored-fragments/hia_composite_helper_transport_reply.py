"""HIA validation of the complete actual helper result and exact continuation."""
from __future__ import annotations

BODY = r'''
def helper_reply(s:readbuf, r:readbuf, w:mutbuf) -> u32:
    if length(w) < CONTROL_BYTES:
        return BAD
    if get(w, H_BROKEN) != 0:
        return BAD
    if get(w, H_MAGIC) != STATE_MAGIC:
        return refused(w, 60)
    phase = get(w, H_PHASE)
    if phase != 9 and phase != 19 and phase != 20:
        return refused(w, 61)
    if length(r) != HELPER_WORKSPACE or length(s) < 64 or length(s) > HELPER_OUTPUT:
        return refused(w, 62)
    if helper_header(s, w, choose(phase == 9, 0, 1)) == 0:
        return refused(w, 63)
    put(w, H_GROW, 0)
    if phase == 9:
        # No request or descriptor borrow survives the completed actual helper
        # invocation. Reuse its temporary arena instead of retaining queries.
        put(w, S_SCRATCH_BASE, CONTROL_BYTES)
        put(w, S_SCRATCH_USED, 0)
        put(w, S_JSON_DEPTH, 0)
        put(w, S_MEMORY_BYTES, length(w))
        put(w, S_JSON_STACK_END, length(w))
        put(w, H_PHASE, 19)
        continuation(w)
    if resume_memory(w) == 0:
        return pending(w)
    if get(w, H_PHASE) == 19:
        if json_prepare(s, w) == 0:
            return pending(w)
        put(w, S_JSON_POS, get(w, S_ENCODING_START))
        put(w, S_JSON_OUT_REL, get(w, S_SCRATCH_USED))
        put(w, S_JSON_AT, get(w, S_SCRATCH_USED))
        put(w, S_JSON_ROOT, get(w, S_SCRATCH_USED))
        put(w, S_JSON_DEPTH, 0)
        put(w, S_JSON_STACK_END, length(w))
        put(w, S_JSON_STRING_NODE, MAX)
        put(w, S_JSON_COMPLETE, 0)
        put(w, H_PHASE, 20)
    if json_scan(s, w) == 0:
        return pending(w)
    put(w, H_HEAP, get(w, S_SCRATCH_BASE) + get(w, S_SCRATCH_USED))
    if helper_payload(w) == 0:
        return refused(w, 64)
    # Match the old generated-result boundary before admitting the separate
    # borrowed-workspace association used by the outer owner.
    if read(r, 4096) != get(w, H_FINAL) or read(r, 4104) != get(w, H_ERROR):
        return refused(w, 65)
    if read(r, 4120) != length(s) or read(r, 4128) != 0 or read(r, 4152) != get(w, H_NAMEID):
        return refused(w, 66)
    copy_bytes(w, s, HEADER_COPY, 0, 64)
    put(w, H_PHASE, 21)
    return event(w, 4)

def helper_header(s:readbuf, w:mutbuf, repeated:u64) -> u64:
    if read(s, 0) != HELPER_MAGIC or read(s, 40) != 0 or read(s, 48) != 0 or read(s, 56) != 0:
        return 0
    if read(s, 32) != length(s) - 64:
        return 0
    error = read(s, 8)
    final = read(s, 16)
    name = read(s, 24)
    start = get(w, H_STARTSERIAL)
    if error > 3 or final < start or final > 8192:
        return 0
    expected = choose(start < 8192, start + 1, 0)
    if name != expected or (error == 1 and final != 8192):
        return 0
    if error != 1 and (name == 0 or final < name):
        return 0
    if repeated != 0:
        if error != get(w, H_ERROR) or final != get(w, H_FINAL) or name != get(w, H_NAMEID):
            return 0
        if length(s) != get(w, H_FRAMEBYTES):
            return 0
    else:
        put(w, H_ERROR, error)
        put(w, H_FINAL, final)
        put(w, H_NAMEID, name)
        put(w, H_FRAMEBYTES, length(s))
    return 1

def continuation(w:mutbuf) -> u64:
    put(w, CONT_WIRE, CONT_MAGIC)
    put(w, CONT_WIRE + 8, get(w, H_REQUEST))
    put(w, CONT_WIRE + 16, 6)
    put(w, CONT_WIRE + 24, get(w, H_ERROR))
    put(w, CONT_WIRE + 32, 0)
    put(w, CONT_WIRE + 40, get(w, H_FINAL))
    put(w, CONT_WIRE + 56, 0)
    name = get(w, H_NAMEID)
    size = 0
    if name != 0:
        # h2internal_ followed by the exact bounded decimal fresh-name ID.
        put(w, CONT_WIRE + 64, NAME_PREFIX)
        store(w, CONT_WIRE + 72, 97)
        store(w, CONT_WIRE + 73, 108)
        store(w, CONT_WIRE + 74, 95)
        digits = 1
        while digits < 4 and name >= power(digits):
            digits = digits + 1
        i = 0
        while i < digits:
            divisor = power(digits - i - 1)
            digit = 0
            while name >= divisor:
                name = name - divisor
                digit = digit + 1
            store(w, CONT_WIRE + 75 + i, 48 + digit)
            i = i + 1
        size = 11 + digits
    put(w, CONT_WIRE + 48, size)
    put(w, H_NAMEBYTES, size)
    put(w, H_CONTBYTES, 64 + size)
    return 1

def helper_name(w:mutbuf, node:u64) -> u64:
    if node == MAX or get(w, node) != 4 or get(w, node + 8) != get(w, H_NAMEBYTES):
        return 0
    i = 0
    while i < get(w, H_NAMEBYTES):
        if byte(w, node + 16 + i) != byte(w, CONT_WIRE + 64 + i):
            return 0
        i = i + 1
    return 1

def helper_payload(w:mutbuf) -> u64:
    root = scratch_node(w, get(w, S_REPLY_REL))
    if get(w, root) != 6 or get(w, root + 16) != 1:
        return 0
    helper = field(w, root, K_helper)
    if helper == MAX:
        return 0
    if get(w, H_ERROR) != 0:
        return choose(get(w, helper) == 0, 1, 0)
    if get(w, helper) != 6 or get(w, helper + 16) != 6:
        return 0
    if helper_name(w, field(w, helper, K_name)) == 0:
        return 0
    entry = field(w, helper, K_entry)
    params = field(w, helper, K_params)
    returns = field(w, helper, K_returns)
    effects = field(w, helper, K_effects)
    blocks = field(w, helper, K_blocks)
    if entry == MAX or params == MAX or returns == MAX or effects == MAX or blocks == MAX:
        return 0
    if get(w, entry) != 4 or get(w, params) != 5 or get(w, returns) != 5 or get(w, effects) != 5 or get(w, blocks) != 5:
        return 0
    put(w, H_HELPERPTR, helper)
    put(w, H_HELPERBYTES, 16 + get(w, helper + 8))
    return 1
'''
