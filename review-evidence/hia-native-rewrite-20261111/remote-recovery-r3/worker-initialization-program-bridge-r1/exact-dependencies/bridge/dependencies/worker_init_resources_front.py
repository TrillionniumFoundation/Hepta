"""P12 resource peer front, revision 3: exact completed pure/registry events.

Only source-bound finite resources are copied. Actual current Graph, initializer
workspace and registry/metadata outputs must be immutable privately issued views.
Correlation fields and the constant-pool hash do not authenticate foreign peers.
"""
BODY=r'''
def rs_event(w:mutbuf, action:u64) -> u32:
    sequence = iv_get(w, R_SEQUENCE)
    if sequence == IV_MAX:
        iv_put(w, R_PHASE, 99)
        return IV_BAD
    iv_put(w, R_SEQUENCE, sequence + 1)
    fill_range(w, RS_EVENT_AT, 256, 0)
    iv_put(w, RS_EVENT_AT, RS_EVENT)
    iv_put(w, RS_EVENT_AT + 8, action)
    iv_put(w, RS_EVENT_AT + 16, iv_get(w, R_INV))
    iv_put(w, RS_EVENT_AT + 24, iv_get(w, R_CALL))
    iv_put(w, RS_EVENT_AT + 32, iv_get(w, R_LEASE))
    iv_put(w, RS_EVENT_AT + 40, sequence + 1)
    iv_put(w, RS_EVENT_AT + 48, iv_get(w, R_PHASE))
    iv_put(w, RS_EVENT_AT + 56, iv_get(w, V_BAD))
    iv_put(w, RS_EVENT_AT + 64, iv_get(w, R_PENDING))
    iv_put(w, RS_EVENT_AT + 72, iv_get(w, R_OPERATION))
    iv_put(w, RS_EVENT_AT + 80, iv_get(w, R_ORIGIN))
    iv_put(w, RS_EVENT_AT + 88, iv_get(w, R_DIGITS))
    iv_put(w, RS_EVENT_AT + 96, iv_get(w, R_NEED))
    if action == 2 or action == 4:
        iv_put(w, RS_EVENT_AT + 104, 1)
        iv_put(w, RS_EVENT_AT + 112, RS_REG_COMMAND)
        iv_put(w, RS_EVENT_AT + 120, 128)
    elif action == 3:
        iv_put(w, RS_EVENT_AT + 104, 2)
        iv_put(w, RS_EVENT_AT + 112, RS_META_COMMAND)
        iv_put(w, RS_EVENT_AT + 120, 96)
        iv_put(w, RS_EVENT_AT + 128, iv_get(w, R_META_NEED))
        iv_put(w, RS_EVENT_AT + 136, choose(iv_get(w, R_META_STARTED) == 0, 1, 0))
    if action == 4:
        iv_put(w, RS_EVENT_AT + 144, iv_get(w, R_PACKET_AT))
        iv_put(w, RS_EVENT_AT + 152, iv_get(w, R_PACKET_BYTES))
    iv_put(w, RS_EVENT_AT + 160, iv_get(w, R_FOREIGN))
    iv_put(w, RS_EVENT_AT + 168, iv_get(w, R_GRAPH_LEASE))
    iv_put(w, RS_EVENT_AT + 176, iv_get(w, R_GRAPH_BYTES))
    iv_put(w, RS_EVENT_AT + 184, iv_get(w, R_REG_SEQUENCE))
    iv_put(w, RS_EVENT_AT + 192, iv_get(w, R_REG_ACTIVE))
    if action == 0:
        iv_put(w, RS_EVENT_AT + 200, RS_REPLY)
        iv_put(w, RS_EVENT_AT + 208, 256)
        iv_put(w, RS_EVENT_AT + 216, iv_get(w, R_HANDLE))
    return RS_EVENT_END

def rs_fail(w:mutbuf, reason:u64) -> u32:
    iv_bad(w, reason)
    iv_put(w, R_PHASE, 99)
    rs_event(w, 6)
    return IV_BAD

def rs_source_same(s:readbuf, w:mutbuf) -> u64:
    if length(s) != iv_get(w, R_GRAPH_BYTES):
        return iv_bad(w, 700)
    index = 0
    while index < 64:
        if byte(s, index) != byte(w, RS_SOURCE_HEADER + index):
            return iv_bad(w, 701)
        index = index + 1
    return 1

def rs_initializer(r:readbuf, w:mutbuf) -> u64:
    size = iv_word(r, 80)
    if iv_word(r, 72) != 2304 or size < 8192 or size > length(r) - 128:
        return iv_bad(w, 702)
    if iv_word(r, 88) != 768 or iv_word(r, 96) != 256 or iv_word(r, 104) != RS_POOL_BYTES:
        return iv_bad(w, 703)
    if length(r) - 128 - size != 256 + RS_POOL_BYTES:
        return iv_bad(w, 704)
    base = 128
    event = base + 2048
    if iv_word(r, base + I_MAGIC) != IS_STATE or iv_word(r, base + I_STATUS) != 2:
        return iv_bad(w, 705)
    if iv_word(r, base + I_PHASE) != 41 or iv_word(r, base + I_PEER) != 12:
        return iv_bad(w, 706)
    if iv_word(r, base + I_INV) != iv_word(r, 16) or iv_word(r, base + I_CALL) != iv_word(r, 24):
        return iv_bad(w, 707)
    sequence = iv_word(r, base + I_SEQ)
    operation = iv_word(r, base + I_OP)
    if sequence == 0 or iv_word(r, base + I_PENDING) != sequence:
        return iv_bad(w, 708)
    if operation < 1 or operation > 6 or iv_word(r, base + I_RESOURCE_INDEX) != operation - 1:
        return iv_bad(w, 709)
    if iv_word(r, base + I_HAVE_REPLY) != 0 or iv_word(r, base + I_BAD_REASON) != 0:
        return iv_bad(w, 710)
    origin = iv_word(r, base + I_SOURCE_LEASE)
    digits = iv_word(r, base + I_DIGITS)
    if origin == 0 or (digits != 0 and digits < 640):
        return iv_bad(w, 711)
    if iv_word(r, base + I_SOURCE_ROOT) == 0:
        return iv_bad(w, 712)
    index = 0
    while index < 6:
        if iv_word(r, base + I_ARG0 + index * 8) != 0:
            return iv_bad(w, 713)
        index = index + 1
    if iv_word(r, base + I_VIEW_OWNER) != 0 or iv_word(r, base + I_VIEW_AT) != 0:
        return iv_bad(w, 714)
    if iv_word(r, base + I_VIEW_BYTES) != 0 or iv_word(r, base + I_LITERAL_BYTES) != 0:
        return iv_bad(w, 715)
    index = 0
    while index < 32:
        expected = 0
        if index == 0:
            expected = IS_EVENT
        elif index == 1:
            expected = 2
        elif index == 2:
            expected = iv_word(r, 16)
        elif index == 3:
            expected = iv_word(r, 24)
        elif index == 4 or index == 7:
            expected = sequence
        elif index == 5:
            expected = 41
        elif index == 6:
            expected = 12
        elif index == 9:
            expected = origin
        elif index == 10:
            expected = iv_word(r, base + I_SOURCE_ROOT)
        elif index == 11:
            expected = digits
        elif index == 12:
            expected = iv_word(r, base + I_STORE)
        elif index == 13:
            expected = operation
        elif index == 23:
            expected = 5120
        elif index == 25:
            expected = 4096
        elif index == 26:
            expected = 512
        if iv_word(r, event + index * 8) != expected:
            return iv_bad(w, 716)
        index = index + 1
    iv_put(w, R_PENDING, sequence)
    iv_put(w, R_OPERATION, operation)
    iv_put(w, R_ORIGIN, origin)
    iv_put(w, R_DIGITS, digits)
    iv_put(w, R_INITIALIZER_BYTES, size)
    copy_bytes(w, r, RS_INITIALIZER_EVENT, event, 256)
    return 1

def rs_previous_pure(s:readbuf, r:readbuf, w:mutbuf, at:u64) -> u64:
    if iv_word(r, at + 8) != 4:
        return iv_bad(w, 780)
    if iv_word(r, at + 16) != iv_get(w, R_INV) or iv_word(r, at + 24) != iv_get(w, R_CALL):
        return iv_bad(w, 781)
    sequence = iv_word(r, at + 32)
    command = iv_word(r, at + 40)
    if sequence == 0 or sequence == IV_MAX or command == 0 or command == IV_MAX:
        return iv_bad(w, 782)
    pending = iv_word(r, at + 56)
    if pending == 0 or pending >= iv_get(w, R_PENDING):
        return iv_bad(w, 783)
    peer = iv_word(r, at + 48)
    kind = iv_word(r, at + 72)
    mode = iv_word(r, at + 240)
    valid = (peer == 9 and kind == 2 and mode >= 1 and mode <= 6)
    valid = valid or (peer == 2 and kind == 1 and mode == 1)
    valid = valid or (peer == 19 and kind == 1 and mode == 6)
    valid = valid or (peer == 10 and kind == 1 and mode >= 2 and mode <= 5)
    if valid == False:
        return iv_bad(w, 784)
    if iv_word(r, at + 80) == 0 or iv_word(r, at + 88) < 4096:
        return iv_bad(w, 785)
    index = 96
    while index < 136:
        if iv_word(r, at + index) != 0:
            return iv_bad(w, 786)
        index = index + 8
    owner = iv_word(r, at + 136)
    offset = iv_word(r, at + 144)
    borrowed = kind == 1 and mode == 6
    if owner != choose(borrowed, 1, 3):
        return iv_bad(w, 787)
    if borrowed:
        if offset != 0:
            return iv_bad(w, 788)
    elif offset < 128 or offset > IV_MAX - length(s):
        return iv_bad(w, 789)
    if iv_word(r, at + 152) != length(s) or iv_word(r, at + 160) != iv_word(s, 8):
        return iv_bad(w, 790)
    if iv_word(r, at + 168) != length(s) or iv_word(r, at + 176) != 1280 or iv_word(r, at + 184) != 256:
        return iv_bad(w, 791)
    if iv_word(r, at + 208) != 0 or iv_word(r, at + 248) != 0:
        return iv_bad(w, 792)
    if iv_word(r, at + 224) != iv_get(w, R_ORIGIN) or iv_word(r, at + 232) != iv_word(s, 16):
        return iv_bad(w, 793)
    issued = iv_word(r, at + 216)
    if issued == 0 or issued >= RS_HANDLE - 1 or issued > (IV_MAX - 8192) >> 4:
        return iv_bad(w, 794)
    if iv_word(r, at + 64) != 8192 + issued * 16:
        return iv_bad(w, 795)
    first = iv_word(r, at + 192)
    second = iv_word(r, at + 200)
    if first <= RS_HANDLE or first > RS_HANDLE + issued:
        return iv_bad(w, 796)
    two = kind == 1 and (mode == 2 or mode == 3)
    if two:
        if second <= RS_HANDLE or second > RS_HANDLE + issued or second == first:
            return iv_bad(w, 797)
    elif second != 0:
        return iv_bad(w, 798)
    iv_put(w, R_REG_SEQUENCE, sequence)
    iv_put(w, R_REG_PREVIOUS, command)
    iv_put(w, R_REG_ACTIVE, command + 1)
    iv_put(w, R_ISSUED, issued)
    copy_bytes(w, r, RS_REG_EVENT_COPY, at, 256)
    return 1

def rs_previous_registry(s:readbuf, r:readbuf, w:mutbuf) -> u64:
    at = 128 + iv_get(w, R_INITIALIZER_BYTES)
    if iv_word(r, at) == RS_PURE_EVENT:
        return rs_previous_pure(s, r, w, at)
    action = iv_word(r, at + 8)
    if iv_word(r, at) != RS_REG_EVENT or (action != 0 and action != 5 and action != 6):
        return iv_bad(w, 717)
    if iv_word(r, at + 16) != iv_get(w, R_INV) or iv_word(r, at + 24) != iv_get(w, R_CALL):
        return iv_bad(w, 718)
    sequence = iv_word(r, at + 32)
    command = iv_word(r, at + 40)
    if sequence == 0 or sequence == IV_MAX or command == 0 or command == IV_MAX:
        return iv_bad(w, 719)
    if iv_word(r, at + 48) != iv_word(s, 8) or iv_word(r, at + 56) != length(s):
        return iv_bad(w, 720)
    if iv_word(r, at + 152) != length(s) or iv_word(r, at + 160) == 0 or iv_word(r, at + 160) > iv_word(s, 16):
        return iv_bad(w, 721)
    if iv_word(r, at + 200) != iv_get(w, R_ORIGIN) or iv_word(r, at + 208) != iv_word(s, 16):
        return iv_bad(w, 722)
    if iv_word(r, at + 216) != 0 or iv_word(r, at + 224) != 0 or iv_word(r, at + 232) != command:
        return iv_bad(w, 723)
    if iv_word(r, at + 240) != 0 or iv_word(r, at + 248) != 0 or iv_word(r, at + 64) != 0:
        return iv_bad(w, 724)
    issued = iv_word(r, at + 192)
    if issued >= RS_HANDLE - 1:
        return iv_bad(w, 725)
    iv_put(w, R_REG_SEQUENCE, sequence)
    iv_put(w, R_REG_PREVIOUS, command)
    iv_put(w, R_REG_ACTIVE, command + 1)
    iv_put(w, R_ISSUED, issued)
    copy_bytes(w, r, RS_REG_EVENT_COPY, at, 256)
    return 1

def rs_reserve_command(w:mutbuf) -> u64:
    fill_range(w, RS_REG_COMMAND, 128, 0)
    iv_put(w, RS_REG_COMMAND, RS_REG_MAGIC)
    iv_put(w, RS_REG_COMMAND + 8, 2)
    iv_put(w, RS_REG_COMMAND + 16, iv_get(w, R_INV))
    iv_put(w, RS_REG_COMMAND + 24, iv_get(w, R_CALL))
    iv_put(w, RS_REG_COMMAND + 32, iv_get(w, R_REG_ACTIVE))
    iv_put(w, RS_REG_COMMAND + 40, iv_get(w, R_REG_SEQUENCE))
    iv_put(w, RS_REG_COMMAND + 48, iv_get(w, R_GRAPH_LEASE))
    iv_put(w, RS_REG_COMMAND + 56, iv_get(w, R_GRAPH_BYTES))
    iv_put(w, RS_REG_COMMAND + 96, iv_get(w, R_ORIGIN))
    return 1

def rs_pool(r:readbuf, w:mutbuf) -> u32:
    if length(w) < iv_get(w, R_NEED):
        return rs_event(w, 1)
    at = 128 + iv_get(w, R_INITIALIZER_BYTES) + 256
    copy_bytes(w, r, RS_POOL, at, RS_POOL_BYTES)
    if digest(w, RS_POOL, RS_POOL_BYTES) != 32:
        return rs_fail(w, 726)
    if iv_get(w, 1152) != RS_HASH0 or iv_get(w, 1160) != RS_HASH1:
        return rs_fail(w, 727)
    if iv_get(w, 1168) != RS_HASH2 or iv_get(w, 1176) != RS_HASH3:
        return rs_fail(w, 728)
    if rs_select(w, iv_get(w, R_OPERATION)) == 0:
        return rs_fail(w, 729)
    rs_reserve_command(w)
    iv_put(w, R_NEED, 0)
    iv_put(w, R_PHASE, 10)
    return rs_event(w, 2)

def rs_begin(s:readbuf, r:readbuf, w:mutbuf) -> u32:
    if iv_word(r, 40) != 0:
        return rs_fail(w, 730)
    if iv_get(w, R_PHASE) == 1:
        if iv_get(w, R_MAGIC) != RS_STATE:
            return rs_fail(w, 751)
        index = 0
        while index < 128:
            if byte(r, index) != byte(w, RS_BEGIN_COPY + index):
                return rs_fail(w, 731)
            index = index + 1
        if rs_source_same(s, w) == 0:
            return rs_fail(w, 732)
        if iv_word(r, 80) != iv_get(w, R_INITIALIZER_BYTES):
            return rs_fail(w, 733)
        if length(r) != 128 + iv_get(w, R_INITIALIZER_BYTES) + 256 + RS_POOL_BYTES:
            return rs_fail(w, 734)
        index = 0
        while index < 256:
            if byte(r, 128 + 2048 + index) != byte(w, RS_INITIALIZER_EVENT + index):
                return rs_fail(w, 735)
            if byte(r, 128 + iv_get(w, R_INITIALIZER_BYTES) + index) != byte(w, RS_REG_EVENT_COPY + index):
                return rs_fail(w, 736)
            index = index + 1
        return rs_pool(r, w)
    if iv_get(w, R_MAGIC) != 0 or iv_get(w, R_PHASE) != 0:
        return rs_fail(w, 737)
    index = 0
    while index < RS_MIN:
        if byte(w, index) != 0:
            return rs_fail(w, 738)
        index = index + 1
    if iv_shape(s, w, 0, length(s), iv_word(r, 48)) == 0:
        return rs_fail(w, 739)
    iv_put(w, R_MAGIC, RS_STATE)
    iv_put(w, R_INV, iv_word(r, 16))
    iv_put(w, R_CALL, iv_word(r, 24))
    iv_put(w, R_LEASE, iv_word(r, 32))
    iv_put(w, R_GRAPH_LEASE, iv_word(s, 8))
    iv_put(w, R_GRAPH_BYTES, length(s))
    iv_put(w, R_OLD_NODES, iv_word(s, 16))
    iv_put(w, R_OLD_EDGES, iv_word(s, 32))
    iv_put(w, R_OLD_POOL, iv_word(s, 40))
    if rs_initializer(r, w) == 0 or rs_previous_registry(s, r, w) == 0:
        return rs_fail(w, 740)
    copy_bytes(w, s, RS_SOURCE_HEADER, 0, 64)
    copy_bytes(w, r, RS_BEGIN_COPY, 0, 128)
    iv_put(w, R_NEED, RS_POOL + RS_POOL_BYTES)
    iv_put(w, R_PHASE, 1)
    return rs_pool(r, w)

def initializer_resources(s:readbuf, r:readbuf, w:mutbuf) -> u32:
    if length(w) < RS_MIN:
        return IV_BAD
    if iv_get(w, R_PHASE) == 99:
        return IV_BAD
    if length(r) < 128 or length(s) < 64:
        return rs_fail(w, 741)
    if iv_word(r, 0) != RS_COMMAND or iv_word(r, 16) == 0 or iv_word(r, 24) == 0 or iv_word(r, 32) == 0:
        return rs_fail(w, 742)
    if iv_word(r, 56) != length(s) or iv_word(r, 64) != length(r) - 128:
        return rs_fail(w, 743)
    if iv_word(r, 48) != iv_word(s, 8) or iv_word(r, 112) != 0 or iv_word(r, 120) != 0:
        return rs_fail(w, 744)
    mode = iv_word(r, 8)
    if mode == 1:
        return rs_begin(s, r, w)
    if iv_get(w, R_MAGIC) != RS_STATE or iv_get(w, R_PHASE) == 90:
        return rs_fail(w, 745)
    if iv_word(r, 16) != iv_get(w, R_INV) or iv_word(r, 24) != iv_get(w, R_CALL):
        return rs_fail(w, 746)
    if iv_word(r, 32) != iv_get(w, R_LEASE) or iv_word(r, 40) != iv_get(w, R_SEQUENCE):
        return rs_fail(w, 747)
    if iv_word(r, 96) != 0 or iv_word(r, 104) != 0:
        return rs_fail(w, 748)
    if mode == 4:
        return rs_bound(s, r, w)
    if rs_source_same(s, w) == 0:
        return rs_fail(w, 749)
    if mode == 2:
        return rs_reserved(r, w)
    if mode == 3:
        return rs_metadata(r, w)
    return rs_fail(w, 750)
'''
