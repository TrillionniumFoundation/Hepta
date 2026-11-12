"""Native complete Store.wire -> incremental SHA controller, new source.

The command inputs are private immutable actual peer outputs. Correlation
headers do not authenticate arbitrary externally supplied Graphs or workspaces.
"""
BODY=r'''
def wd_equal(r:readbuf, w:mutbuf, source:u64, target:u64, count:u64) -> u64:
    if source > length(r) or count > length(r) - source or target > length(w) or count > length(w) - target:
        return 0
    index = 0
    while index < count:
        if byte(r, source + index) != byte(w, target + index):
            return 0
        index = index + 1
    return 1

def wd_event(w:mutbuf, action:u64) -> u32:
    previous = iv_get(w, D_SEQ)
    if previous == IV_MAX:
        iv_put(w, D_PHASE, 99)
        return IV_BAD
    iv_put(w, D_SEQ, previous + 1)
    fill_range(w, WD_EVENT_AT, 256, 0)
    iv_put(w, WD_EVENT_AT, WD_EVENT)
    iv_put(w, WD_EVENT_AT + 8, action)
    iv_put(w, WD_EVENT_AT + 16, iv_get(w, D_INV))
    iv_put(w, WD_EVENT_AT + 24, iv_get(w, D_CALL))
    iv_put(w, WD_EVENT_AT + 32, iv_get(w, D_LEASE))
    iv_put(w, WD_EVENT_AT + 40, previous + 1)
    iv_put(w, WD_EVENT_AT + 48, iv_get(w, D_PHASE))
    iv_put(w, WD_EVENT_AT + 56, iv_get(w, V_BAD))
    iv_put(w, WD_EVENT_AT + 64, iv_get(w, D_SOURCE_LEASE))
    iv_put(w, WD_EVENT_AT + 72, iv_get(w, D_SOURCE_BYTES))
    iv_put(w, WD_EVENT_AT + 80, iv_get(w, D_HANDLE))
    iv_put(w, WD_EVENT_AT + 88, iv_get(w, D_ROOT))
    iv_put(w, WD_EVENT_AT + 96, iv_get(w, D_NEED))
    iv_put(w, WD_EVENT_AT + 104, iv_get(w, D_ROLE))
    iv_put(w, WD_EVENT_AT + 112, iv_get(w, D_PEER_NEED))
    iv_put(w, WD_EVENT_AT + 120, iv_get(w, D_ACTION))
    if action == 1:
        iv_put(w, WD_EVENT_AT + 128, WD_CONFIG)
        iv_put(w, WD_EVENT_AT + 136, 64)
    elif action == 3:
        iv_put(w, WD_EVENT_AT + 128, WD_SHA_INPUT)
        iv_put(w, WD_EVENT_AT + 136, iv_get(w, D_CHUNK) + 1)
    if action == 4 or action == 5:
        iv_put(w, WD_EVENT_AT + 144, WD_WIRE)
        iv_put(w, WD_EVENT_AT + 152, iv_get(w, D_WIRE_BYTES))
        iv_put(w, WD_EVENT_AT + 160, WD_DIGEST)
        iv_put(w, WD_EVENT_AT + 168, 32)
        iv_put(w, WD_EVENT_AT + 176, WD_GRAPH)
        iv_put(w, WD_EVENT_AT + 184, 192)
    iv_put(w, WD_EVENT_AT + 192, iv_get(w, D_FOREIGN))
    iv_put(w, WD_EVENT_AT + 200, iv_get(w, D_OUTPUT))
    iv_put(w, WD_EVENT_AT + 208, iv_get(w, D_REG_COMMAND))
    iv_put(w, WD_EVENT_AT + 216, iv_get(w, D_REG_SEQ))
    if action == 5 or action == 6:
        iv_put(w, WD_EVENT_AT + 224, WD_REPLY)
        iv_put(w, WD_EVENT_AT + 232, iv_get(w, D_REPLY_BYTES))
    iv_put(w, WD_EVENT_AT + 240, iv_get(w, D_ERROR))
    iv_put(w, WD_EVENT_AT + 248, iv_get(w, D_CAUSE))
    return 768

def wd_fail(w:mutbuf, reason:u64) -> u32:
    iv_bad(w, reason)
    iv_put(w, D_PHASE, 99)
    wd_event(w, 7)
    return IV_BAD

def wd_next(w:mutbuf, role:u64, need:u64) -> u64:
    if iv_get(w, D_ACTION) == IV_MAX:
        return iv_bad(w, 601)
    iv_put(w, D_ACTION, iv_get(w, D_ACTION) + 1)
    iv_put(w, D_ROLE, role)
    iv_put(w, D_PEER_NEED, need)
    return 1

def wd_borrow(s:readbuf, r:readbuf, w:mutbuf) -> u64:
    at = 128
    if iv_word(r, at) != WD_REG_EVENT or iv_word(r, at + 8) != 5:
        return iv_bad(w, 602)
    if iv_word(r, at + 16) != iv_get(w, D_INV) or iv_word(r, at + 24) != iv_get(w, D_CALL):
        return iv_bad(w, 603)
    if iv_word(r, at + 48) != iv_get(w, D_SOURCE_LEASE) or iv_word(r, at + 56) != length(s):
        return iv_bad(w, 604)
    if iv_word(r, at + 64) != 0 or iv_word(r, at + 136) != 1 or iv_word(r, at + 144) != 0:
        return iv_bad(w, 605)
    if iv_word(r, at + 152) != length(s) or iv_word(r, at + 200) != iv_get(w, D_ORIGIN):
        return iv_bad(w, 606)
    if iv_word(r, at + 176) != 1024 or iv_word(r, at + 184) != 64:
        return iv_bad(w, 607)
    if iv_word(r, at + 208) != iv_word(s, 16) or iv_word(r, at + 216) != 0 or iv_word(r, at + 224) != 0:
        return iv_bad(w, 608)
    if iv_word(r, at + 240) != 0 or iv_word(r, at + 248) != 0:
        return iv_bad(w, 609)
    sequence = iv_word(r, at + 32)
    command = iv_word(r, at + 40)
    root = iv_word(r, at + 160)
    handle = iv_word(r, at + 168)
    count = iv_word(r, at + 192)
    if sequence == 0 or sequence == IV_MAX or command == 0 or command == IV_MAX:
        return iv_bad(w, 610)
    if iv_word(r, at + 232) != command or root == 0 or root > iv_word(s, 16):
        return iv_bad(w, 611)
    if count == 0 or count >= WD_HANDLE - 1 or handle <= WD_HANDLE or handle - WD_HANDLE > count:
        return iv_bad(w, 612)
    at = 384
    if iv_word(r, at) != WD_WIRE_COMMAND or iv_word(r, at + 8) != iv_get(w, D_SOURCE_LEASE):
        return iv_bad(w, 613)
    if iv_word(r, at + 16) != command or iv_word(r, at + 24) != root:
        return iv_bad(w, 614)
    if iv_word(r, at + 32) != 8388608 or iv_word(r, at + 40) != 2 or iv_word(r, at + 56) != 0:
        return iv_bad(w, 615)
    digits = iv_word(r, at + 48)
    if digits != 0 and digits < 640:
        return iv_bad(w, 616)
    iv_put(w, D_DIGITS, digits)
    iv_put(w, D_HANDLE, handle)
    iv_put(w, D_ROOT, root)
    iv_put(w, D_ISSUED, count)
    iv_put(w, D_BORROW_COMMAND, command)
    iv_put(w, D_BORROW_SEQ, sequence)
    copy_bytes(w, r, WD_CONFIG, at, 64)
    return 1

def wd_reserve(r:readbuf, w:mutbuf) -> u64:
    at = 448
    if iv_word(r, at) != WD_REG_EVENT or iv_word(r, at + 8) != 2:
        return iv_bad(w, 617)
    if iv_word(r, at + 16) != iv_get(w, D_INV) or iv_word(r, at + 24) != iv_get(w, D_CALL):
        return iv_bad(w, 618)
    if iv_word(r, at + 32) != iv_get(w, D_BORROW_SEQ) + 1 or iv_word(r, at + 40) != iv_get(w, D_BORROW_COMMAND) + 1:
        return iv_bad(w, 619)
    if iv_word(r, at + 48) != iv_get(w, D_SOURCE_LEASE) or iv_word(r, at + 56) != iv_get(w, D_SOURCE_BYTES):
        return iv_bad(w, 620)
    if iv_word(r, at + 64) != 0 or iv_word(r, at + 88) != 0 or iv_word(r, at + 96) != 0:
        return iv_bad(w, 621)
    index = 104
    while index < 192:
        if iv_word(r, at + index) != 0:
            return iv_bad(w, 622)
        index = index + 8
    if iv_word(r, at + 192) != iv_get(w, D_ISSUED) or iv_word(r, at + 200) != iv_get(w, D_ORIGIN):
        return iv_bad(w, 623)
    if iv_word(r, at + 208) != iv_get(w, D_SOURCE_NODES) or iv_word(r, at + 216) != 0 or iv_word(r, at + 224) != 0:
        return iv_bad(w, 624)
    if iv_word(r, at + 232) != iv_get(w, D_BORROW_COMMAND) or iv_word(r, at + 240) != 10 or iv_word(r, at + 248) != 0:
        return iv_bad(w, 625)
    foreign = iv_word(r, at + 72)
    if foreign <= iv_get(w, D_SOURCE_LEASE) or foreign == IV_MAX or iv_word(r, at + 80) != foreign + 1:
        return iv_bad(w, 626)
    iv_put(w, D_FOREIGN, foreign)
    iv_put(w, D_OUTPUT, foreign + 1)
    iv_put(w, D_REG_COMMAND, iv_word(r, at + 40))
    iv_put(w, D_REG_SEQ, iv_word(r, at + 32))
    return 1

def wd_initializer(r:readbuf, w:mutbuf) -> u64:
    at = 704
    if iv_word(r, at) != WD_INIT_EVENT or iv_word(r, at + 8) != 2:
        return iv_bad(w, 627)
    if iv_word(r, at + 16) != iv_get(w, D_INV) or iv_word(r, at + 24) != iv_get(w, D_CALL):
        return iv_bad(w, 628)
    pending = iv_word(r, at + 32)
    if pending == 0 or iv_word(r, at + 40) != 14 or iv_word(r, at + 48) != 8 or iv_word(r, at + 56) != pending:
        return iv_bad(w, 629)
    if iv_word(r, at + 64) != 0 or iv_word(r, at + 72) != iv_get(w, D_ORIGIN):
        return iv_bad(w, 630)
    if iv_word(r, at + 80) == 0 or iv_word(r, at + 88) != iv_get(w, D_DIGITS) or iv_word(r, at + 96) == 0:
        return iv_bad(w, 631)
    if iv_word(r, at + 104) != 0 or iv_word(r, at + 112) != iv_get(w, D_HANDLE):
        return iv_bad(w, 632)
    index = 120
    while index < 184:
        if iv_word(r, at + index) != 0:
            return iv_bad(w, 633)
        index = index + 8
    if iv_word(r, at + 184) != 5120 or iv_word(r, at + 192) != 0:
        return iv_bad(w, 634)
    if iv_word(r, at + 200) != 4096 or iv_word(r, at + 208) != 512:
        return iv_bad(w, 635)
    index = 216
    while index < 256:
        if iv_word(r, at + index) != 0:
            return iv_bad(w, 636)
        index = index + 8
    iv_put(w, D_INIT_PENDING, pending)
    return 1

def wd_begin(s:readbuf, r:readbuf, w:mutbuf) -> u32:
    kind = iv_word(r, 96)
    if kind > 1 or length(r) != 704 + kind * 256:
        return wd_fail(w, 637)
    if iv_word(r, 40) != 0 or iv_word(r, 72) != 768 or iv_word(r, 80) != 4 or iv_word(r, 88) != 768 or iv_word(r, 112) != 0:
        return wd_fail(w, 638)
    index = 0
    while index < WD_MIN:
        if byte(w, index) != 0:
            return wd_fail(w, 639)
        index = index + 1
    if iv_shape(s, w, 0, length(s), iv_word(r, 48)) == 0:
        return wd_fail(w, 640)
    iv_put(w, D_MAGIC, WD_STATE)
    iv_put(w, D_INV, iv_word(r, 16))
    iv_put(w, D_CALL, iv_word(r, 24))
    iv_put(w, D_LEASE, iv_word(r, 32))
    iv_put(w, D_ORIGIN, iv_word(r, 104))
    iv_put(w, D_SOURCE_LEASE, iv_word(s, 8))
    iv_put(w, D_SOURCE_BYTES, length(s))
    iv_put(w, D_SOURCE_NODES, iv_word(s, 16))
    iv_put(w, D_KIND, kind)
    if wd_borrow(s, r, w) == 0 or wd_reserve(r, w) == 0:
        return wd_fail(w, 641)
    if kind == 1:
        if wd_initializer(r, w) == 0:
            return wd_fail(w, 642)
    copy_bytes(w, s, WD_SOURCE_HEADER, 0, 64)
    copy_bytes(w, r, WD_BORROW, 128, 256)
    copy_bytes(w, r, WD_RESERVE, 448, 256)
    if kind == 1:
        copy_bytes(w, r, WD_INITIALIZER, 704, 256)
    iv_put(w, D_PHASE, 10)
    if wd_next(w, 1, 32768) == 0:
        return wd_fail(w, 643)
    return wd_event(w, 1)

def wd_current(s:readbuf, r:readbuf, w:mutbuf) -> u64:
    if iv_get(w, D_MAGIC) != WD_STATE or iv_word(r, 16) != iv_get(w, D_INV) or iv_word(r, 24) != iv_get(w, D_CALL):
        return iv_bad(w, 644)
    if iv_word(r, 32) != iv_get(w, D_LEASE) or iv_word(r, 40) != iv_get(w, D_SEQ):
        return iv_bad(w, 645)
    if iv_word(r, 96) != 0 or iv_word(r, 104) != iv_get(w, D_ORIGIN) or iv_word(r, 112) != iv_get(w, D_ACTION):
        return iv_bad(w, 646)
    if iv_word(r, 8) != 5:
        if length(s) != iv_get(w, D_SOURCE_BYTES) or wd_equal(s, w, 0, WD_SOURCE_HEADER, 64) == 0:
            return iv_bad(w, 647)
    return 1

def store_wire_digest(s:readbuf, r:readbuf, w:mutbuf) -> u32:
    if length(w) < WD_MIN:
        return IV_BAD
    if iv_get(w, D_PHASE) == 99 or iv_get(w, D_PHASE) == 90 or iv_get(w, V_BAD) != 0:
        return IV_BAD
    if length(r) < 128 or iv_word(r, 0) != WD_COMMAND or iv_word(r, 120) != 0:
        return wd_fail(w, 648)
    op = iv_word(r, 8)
    if op < 1 or op > 5 or iv_word(r, 16) == 0 or iv_word(r, 24) == 0 or iv_word(r, 32) == 0 or iv_word(r, 104) == 0:
        return wd_fail(w, 649)
    if iv_word(r, 64) != length(r) - 128 or iv_word(r, 56) != length(s) or length(s) < 64:
        return wd_fail(w, 650)
    if iv_word(r, 48) != iv_word(s, 8):
        return wd_fail(w, 651)
    if iv_get(w, D_MAGIC) == 0:
        if op != 1:
            return wd_fail(w, 652)
        return wd_begin(s, r, w)
    if op == 1 or wd_current(s, r, w) == 0:
        return wd_fail(w, 653)
    if op == 2:
        if iv_get(w, D_PHASE) != 10:
            return wd_fail(w, 654)
        return wd_wire_result(r, w)
    if op == 4:
        if iv_get(w, D_PHASE) != 20:
            return wd_fail(w, 655)
        return wd_wire_copy(r, w, 1)
    if op == 3:
        if iv_get(w, D_PHASE) < 30 or iv_get(w, D_PHASE) > 32:
            return wd_fail(w, 656)
        return wd_sha_result(r, w)
    if iv_get(w, D_PHASE) != 50:
        return wd_fail(w, 657)
    return wd_bind(s, r, w)
'''
