"""Private native value registry/configuration peer, new unexecuted revision.

This image shares only the pinned initializer-pure workspace ABI. Actual foreign
Graph issuance, immutable byte custody and the fixed image table remain caller
obligations. Registry value handles never confer namespace or file authority.
"""
BODY=r'''
def wr_event(w:mutbuf, action:u64) -> u32:
    previous = iv_get(w, B_SEQUENCE)
    if previous == IV_MAX:
        iv_put(w, B_PHASE, 99)
        return IV_BAD
    iv_put(w, B_SEQUENCE, previous + 1)
    fill_range(w, WR_EVENT_AT, 256, 0)
    iv_put(w, WR_EVENT_AT, WR_EVENT)
    iv_put(w, WR_EVENT_AT + 8, action)
    iv_put(w, WR_EVENT_AT + 16, iv_get(w, B_INV))
    iv_put(w, WR_EVENT_AT + 24, iv_get(w, B_CALL))
    iv_put(w, WR_EVENT_AT + 32, previous + 1)
    iv_put(w, WR_EVENT_AT + 40, iv_get(w, B_ACTIVE_COMMAND))
    iv_put(w, WR_EVENT_AT + 48, iv_get(w, B_LEASE))
    iv_put(w, WR_EVENT_AT + 56, iv_get(w, B_BYTES))
    iv_put(w, WR_EVENT_AT + 64, iv_get(w, B_NEED))
    iv_put(w, WR_EVENT_AT + 72, iv_get(w, R_FOREIGN))
    iv_put(w, WR_EVENT_AT + 80, iv_get(w, R_OUTPUT))
    iv_put(w, WR_EVENT_AT + 88, iv_get(w, R_CHILD_SEQ))
    iv_put(w, WR_EVENT_AT + 96, iv_get(w, R_CHILD_NEED))
    if action == 3 or action == 4:
        iv_put(w, WR_EVENT_AT + 104, iv_get(w, R_WIRE_AT))
        iv_put(w, WR_EVENT_AT + 112, iv_get(w, R_WIRE_BYTES))
        iv_put(w, WR_EVENT_AT + 120, 128)
        iv_put(w, WR_EVENT_AT + 128, iv_get(w, R_RIGHT_BYTES))
    if action == 0 or action == 5 or action == 6:
        iv_put(w, WR_EVENT_AT + 136, choose(action == 6, 3, 1))
        iv_put(w, WR_EVENT_AT + 144, choose(action == 6, 128 + iv_get(w, R_RIGHT_BYTES) + 512, 0))
        iv_put(w, WR_EVENT_AT + 152, iv_get(w, B_BYTES))
        iv_put(w, WR_EVENT_AT + 160, iv_get(w, R_ROOT))
        iv_put(w, WR_EVENT_AT + 168, choose(action == 0, 0, iv_get(w, B_HANDLE0)))
    if action == 0 or action == 5:
        iv_put(w, WR_EVENT_AT + 176, PJ_WIRE)
        iv_put(w, WR_EVENT_AT + 184, choose(action == 0, 192, 64))
    iv_put(w, WR_EVENT_AT + 192, iv_get(w, B_ISSUED))
    iv_put(w, WR_EVENT_AT + 200, iv_get(w, B_ORIGIN))
    iv_put(w, WR_EVENT_AT + 208, iv_get(w, B_NODES))
    iv_put(w, WR_EVENT_AT + 216, iv_get(w, V_BAD))
    iv_put(w, WR_EVENT_AT + 232, iv_get(w, B_LAST_COMMAND))
    iv_put(w, WR_EVENT_AT + 240, iv_get(w, B_PHASE))
    return 768

def wr_fail(w:mutbuf, reason:u64) -> u32:
    iv_bad(w, reason)
    iv_put(w, B_PHASE, 99)
    wr_event(w, 7)
    return IV_BAD

def wr_boot(s:readbuf, r:readbuf, w:mutbuf) -> u32:
    if iv_word(r, 8) != 1 or length(r) != 128 or iv_word(r, 32) != 1 or iv_word(r, 40) != 0:
        return wr_fail(w, 300)
    if iv_word(r, 64) != 0 or iv_word(r, 72) != 0 or iv_word(r, 80) != 0:
        return wr_fail(w, 301)
    digits = iv_word(r, 88)
    if digits != 0 and digits < 640:
        return wr_fail(w, 302)
    if iv_word(r, 104) != 0 or iv_word(r, 112) != 0 or iv_word(r, 48) != iv_word(r, 96):
        return wr_fail(w, 303)
    index = 0
    while index < PJ_MIN:
        if byte(w, index) != 0:
            return wr_fail(w, 304)
        index = index + 1
    if iv_shape(s, w, 0, length(s), iv_word(r, 48)) == 0:
        return wr_fail(w, 305)
    iv_put(w, B_MAGIC, PJ_STATE)
    iv_put(w, B_INV, iv_word(r, 16))
    iv_put(w, B_CALL, iv_word(r, 24))
    iv_put(w, B_ORIGIN, iv_word(r, 96))
    iv_put(w, B_LEASE, iv_word(s, 8))
    iv_put(w, B_NEXT_LEASE, iv_word(s, 8))
    iv_put(w, B_BYTES, length(s))
    iv_put(w, B_NODES, iv_word(s, 16))
    iv_put(w, B_EDGES, iv_word(s, 32))
    iv_put(w, B_POOL, iv_word(s, 40))
    iv_put(w, B_LAST_COMMAND, 1)
    iv_put(w, B_ACTIVE_COMMAND, 1)
    iv_put(w, R_MAGIC, WR_STATE)
    iv_put(w, R_DIGITS, digits)
    iv_put(w, R_ROOT, iv_word(s, 24))
    copy_bytes(w, s, PJ_SOURCE_HEADER, 0, 64)
    fill_range(w, PJ_WIRE, 192, 0)
    iv_put(w, PJ_WIRE, WR_INITIALIZER_CONFIG)
    iv_put(w, PJ_WIRE + 8, iv_word(r, 16))
    iv_put(w, PJ_WIRE + 16, iv_word(r, 24))
    iv_put(w, PJ_WIRE + 24, iv_word(s, 8))
    iv_put(w, PJ_WIRE + 32, length(s))
    iv_put(w, PJ_WIRE + 40, iv_word(s, 24))
    iv_put(w, PJ_WIRE + 48, digits)
    return wr_event(w, 0)

def wr_current(s:readbuf, r:readbuf, w:mutbuf) -> u64:
    if iv_get(w, B_MAGIC) != PJ_STATE or iv_get(w, R_MAGIC) != WR_STATE:
        return iv_bad(w, 306)
    if iv_word(r, 16) != iv_get(w, B_INV) or iv_word(r, 24) != iv_get(w, B_CALL):
        return iv_bad(w, 307)
    if iv_word(r, 40) != iv_get(w, B_SEQUENCE) or iv_word(r, 48) != iv_get(w, B_LEASE):
        return iv_bad(w, 308)
    if iv_word(r, 96) != iv_get(w, B_ORIGIN) or pj_source(s, w) == 0:
        return iv_bad(w, 309)
    if iv_word(r, 88) != 0:
        return iv_bad(w, 310)
    return 1

def wr_new_command(r:readbuf, w:mutbuf) -> u64:
    if iv_get(w, B_PHASE) != 0 or iv_get(w, B_LAST_COMMAND) == IV_MAX:
        return iv_bad(w, 311)
    if iv_word(r, 32) != iv_get(w, B_LAST_COMMAND) + 1:
        return iv_bad(w, 312)
    if length(r) != 128 or iv_word(r, 64) != 0 or iv_word(r, 72) != 0:
        return iv_bad(w, 313)
    if iv_word(r, 104) != 0 or iv_word(r, 112) != 0:
        return iv_bad(w, 314)
    iv_put(w, B_ACTIVE_COMMAND, iv_word(r, 32))
    return 1

def wr_reserve(r:readbuf, w:mutbuf) -> u32:
    if wr_new_command(r, w) == 0 or iv_word(r, 80) != 0:
        return wr_fail(w, 315)
    if iv_get(w, B_NEXT_LEASE) > IV_MAX - 2:
        return wr_fail(w, 316)
    iv_put(w, R_FOREIGN, iv_get(w, B_NEXT_LEASE) + 1)
    iv_put(w, R_OUTPUT, iv_get(w, B_NEXT_LEASE) + 2)
    iv_put(w, B_NEXT_LEASE, iv_get(w, B_NEXT_LEASE) + 2)
    iv_put(w, B_PHASE, 10)
    iv_put(w, B_NEED, 0)
    iv_put(w, R_RIGHT_BYTES, 0)
    iv_put(w, R_CHILD_SEQ, 0)
    iv_put(w, R_CHILD_NEED, 0)
    iv_put(w, R_ROOT, 0)
    iv_put(w, B_HANDLE0, 0)
    iv_put(w, B_HANDLE1, 0)
    return wr_event(w, 2)

def wr_borrow(r:readbuf, w:mutbuf) -> u32:
    if wr_new_command(r, w) == 0:
        return wr_fail(w, 317)
    root = pj_lookup(w, iv_word(r, 80))
    if root == 0:
        return wr_fail(w, 318)
    iv_put(w, B_HANDLE0, iv_word(r, 80))
    iv_put(w, B_HANDLE1, 0)
    iv_put(w, R_ROOT, root)
    iv_put(w, B_NEED, 0)
    fill_range(w, PJ_WIRE, 64, 0)
    iv_put(w, PJ_WIRE, WR_WIRE_COMMAND)
    iv_put(w, PJ_WIRE + 8, iv_get(w, B_LEASE))
    iv_put(w, PJ_WIRE + 16, iv_get(w, B_ACTIVE_COMMAND))
    iv_put(w, PJ_WIRE + 24, root)
    iv_put(w, PJ_WIRE + 32, 8388608)
    iv_put(w, PJ_WIRE + 40, 3)
    iv_put(w, PJ_WIRE + 48, iv_get(w, R_DIGITS))
    iv_put(w, B_LAST_COMMAND, iv_get(w, B_ACTIVE_COMMAND))
    return wr_event(w, 5)

def wr_foreign(r:readbuf, w:mutbuf, size:u64) -> u64:
    if size < 128 or size > length(r) - 128:
        return iv_bad(w, 319)
    if iv_shape(r, w, 128, size, iv_get(w, R_FOREIGN)) == 0:
        return 0
    if iv_get(w, B_PHASE) != 10:
        if size != iv_get(w, R_RIGHT_BYTES):
            return iv_bad(w, 320)
        index = 0
        while index < 64:
            if byte(r, 128 + index) != byte(w, WR_FOREIGN_HEADER + index):
                return iv_bad(w, 321)
            index = index + 1
    return 1

def wr_import_prepare(s:readbuf, r:readbuf, w:mutbuf) -> u64:
    if iv_word(r, 32) != iv_get(w, B_ACTIVE_COMMAND) or iv_word(r, 72) != 0 or iv_word(r, 80) != 0:
        return iv_bad(w, 322)
    size = iv_word(r, 104)
    if iv_word(r, 112) != 0 or size != length(r) - 128:
        return iv_bad(w, 323)
    if iv_word(r, 8) == 3:
        if iv_get(w, B_PHASE) != 10 or wr_foreign(r, w, size) == 0:
            return iv_bad(w, 324)
        iv_put(w, R_RIGHT_BYTES, size)
        iv_put(w, R_RIGHT_NODES, iv_word(r, 144))
        iv_put(w, R_RIGHT_EDGES, iv_word(r, 160))
        iv_put(w, R_RIGHT_POOL, iv_word(r, 168))
        iv_put(w, R_RIGHT_ROOT, iv_word(r, 152))
        copy_bytes(w, r, WR_FOREIGN_HEADER, 128, 64)
        copy_bytes(w, r, WR_SAVED_COMMAND, 0, 128)
        iv_put(w, B_PHASE, 11)
    else:
        if iv_get(w, B_PHASE) != 11 or wr_foreign(r, w, size) == 0:
            return iv_bad(w, 325)
        index = 0
        while index < 128:
            if (index < 8 or index >= 16) and (index < 40 or index >= 48):
                if byte(r, index) != byte(w, WR_SAVED_COMMAND + index):
                    return iv_bad(w, 326)
            index = index + 1
    if pj_reserve(w, 1) == 0:
        return 0
    iv_put(w, R_WIRE_AT, iv_get(w, B_NEED))
    if length(s) > IV_MAX - 128:
        return iv_bad(w, 327)
    iv_put(w, R_WIRE_BYTES, length(s) + 128)
    if iv_get(w, R_WIRE_BYTES) > IV_MAX - iv_get(w, R_WIRE_AT):
        return iv_bad(w, 328)
    iv_put(w, B_NEED, iv_get(w, R_WIRE_AT) + iv_get(w, R_WIRE_BYTES))
    return 1

def wr_import_wire(s:readbuf, w:mutbuf) -> u64:
    at = iv_get(w, R_WIRE_AT)
    fill_range(w, at, 128, 0)
    iv_put(w, at, WR_MERGE_COMMAND)
    iv_put(w, at + 8, 1)
    iv_put(w, at + 16, iv_get(w, R_OUTPUT))
    iv_put(w, at + 24, iv_get(w, B_ACTIVE_COMMAND))
    iv_put(w, at + 40, iv_word(s, 24))
    iv_put(w, at + 48, iv_get(w, R_RIGHT_ROOT))
    copy_bytes(w, s, at + 128, 0, length(s))
    iv_put(w, R_CHILD_SEQ, 0)
    iv_put(w, R_CHILD_NEED, 512)
    iv_put(w, B_PHASE, 12)
    return 1

def initializer_registry(s:readbuf, r:readbuf, w:mutbuf) -> u32:
    if length(w) < PJ_MIN:
        return IV_BAD
    if iv_get(w, B_PHASE) == 99:
        return IV_BAD
    if length(r) < 128 or iv_word(r, 0) != WR_COMMAND:
        return wr_fail(w, 329)
    if iv_word(r, 16) == 0 or iv_word(r, 24) == 0 or iv_word(r, 96) == 0:
        return wr_fail(w, 330)
    if iv_word(r, 56) != length(s) or iv_word(r, 64) != length(r) - 128 or iv_word(r, 120) != 0:
        return wr_fail(w, 331)
    mode = iv_word(r, 8)
    if mode == 1:
        return wr_boot(s, r, w)
    if wr_current(s, r, w) == 0:
        return wr_fail(w, 332)
    if mode == 2:
        return wr_reserve(r, w)
    if mode == 6:
        return wr_borrow(r, w)
    if mode == 3 or mode == 5:
        if wr_import_prepare(s, r, w) == 0:
            return wr_fail(w, 333)
        if iv_get(w, B_NEED) > length(w):
            return wr_event(w, 1)
        wr_import_wire(s, w)
        return wr_event(w, 3)
    if mode == 4:
        return wr_merge_result(s, r, w)
    return wr_fail(w, 334)
'''
