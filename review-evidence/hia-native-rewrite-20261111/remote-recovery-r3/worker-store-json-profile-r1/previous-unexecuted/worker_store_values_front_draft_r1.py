"""Worker initializer Store.json/profile call owner, NEW UNEXECUTED source.

Native wire/projection and call order are owned here. Namespace put and SQL
are typed pending services; no arbitrary Graph or callback proves durability.
"""
BODY=r'''
def sv_equal(r:readbuf, w:mutbuf, at:u64, target:u64, size:u64) -> u64:
    if at > length(r) or size > length(r) - at or target > length(w) or size > length(w) - target:
        return 0
    index = 0
    while size - index >= 8:
        if iv_word(r, at + index) != iv_get(w, target + index):
            return 0
        index = index + 8
    while index < size:
        if byte(r, at + index) != byte(w, target + index):
            return 0
        index = index + 1
    return 1

def sv_event(w:mutbuf, action:u64) -> u32:
    sequence = iv_get(w, S_SEQ)
    if sequence == IV_MAX:
        iv_put(w, S_PHASE, 99)
        return IV_BAD
    iv_put(w, S_SEQ, sequence + 1)
    fill_range(w, SV_EVENT_AT, 256, 0)
    iv_put(w, SV_EVENT_AT, SV_EVENT)
    iv_put(w, SV_EVENT_AT + 8, action)
    iv_put(w, SV_EVENT_AT + 16, iv_get(w, S_INV))
    iv_put(w, SV_EVENT_AT + 24, iv_get(w, S_CALL))
    iv_put(w, SV_EVENT_AT + 32, iv_get(w, S_LEASE))
    iv_put(w, SV_EVENT_AT + 40, sequence + 1)
    iv_put(w, SV_EVENT_AT + 48, iv_get(w, S_PHASE))
    iv_put(w, SV_EVENT_AT + 56, iv_get(w, V_BAD))
    iv_put(w, SV_EVENT_AT + 64, iv_get(w, S_PEER))
    iv_put(w, SV_EVENT_AT + 72, iv_get(w, S_PENDING))
    iv_put(w, SV_EVENT_AT + 80, iv_get(w, S_STORE))
    iv_put(w, SV_EVENT_AT + 88, iv_get(w, S_ACTION))
    iv_put(w, SV_EVENT_AT + 96, iv_get(w, S_NEED))
    iv_put(w, SV_EVENT_AT + 104, iv_get(w, S_ROLE))
    iv_put(w, SV_EVENT_AT + 112, iv_get(w, S_PEER_NEED))
    if action == 1:
        iv_put(w, SV_EVENT_AT + 120, SV_CONFIG)
        iv_put(w, SV_EVENT_AT + 128, 64)
    elif action == 6 or action == 7:
        iv_put(w, SV_EVENT_AT + 120, SV_REG_COMMAND)
        iv_put(w, SV_EVENT_AT + 128, 128)
    if action == 3:
        iv_put(w, SV_EVENT_AT + 136, SV_WIRE)
        iv_put(w, SV_EVENT_AT + 144, iv_get(w, S_WIRE_BYTES))
        iv_put(w, SV_EVENT_AT + 152, choose(iv_get(w, S_PEER) == 11, SV_PROFILE_KIND, SV_NAME))
        iv_put(w, SV_EVENT_AT + 160, choose(iv_get(w, S_PEER) == 11, 7, iv_get(w, S_NAME_BYTES)))
    if action == 4 or action == 7:
        iv_put(w, SV_EVENT_AT + 168, iv_get(w, S_GRAPH_AT))
        iv_put(w, SV_EVENT_AT + 176, iv_get(w, S_GRAPH_BYTES))
        iv_put(w, SV_EVENT_AT + 184, choose(action == 4, 6, 1))
        iv_put(w, SV_EVENT_AT + 192, iv_get(w, S_GRAPH_LEASE))
    iv_put(w, SV_EVENT_AT + 200, iv_get(w, S_SOURCE_LEASE))
    iv_put(w, SV_EVENT_AT + 208, iv_get(w, S_SOURCE_BYTES))
    if action == 0 or action == 5:
        iv_put(w, SV_EVENT_AT + 216, iv_get(w, S_REPLY_AT))
        iv_put(w, SV_EVENT_AT + 224, iv_get(w, S_REPLY_BYTES))
    iv_put(w, SV_EVENT_AT + 232, iv_get(w, S_REG_COMMAND))
    iv_put(w, SV_EVENT_AT + 240, iv_get(w, S_REG_SEQ))
    iv_put(w, SV_EVENT_AT + 248, iv_get(w, S_REF_HANDLE))
    return 768

def sv_fail(w:mutbuf, reason:u64) -> u32:
    iv_bad(w, reason)
    iv_put(w, S_PHASE, 99)
    sv_event(w, 8)
    return IV_BAD

def sv_action(w:mutbuf, role:u64, size:u64) -> u64:
    if iv_get(w, S_ACTION) == IV_MAX:
        return iv_bad(w, 801)
    iv_put(w, S_ACTION, iv_get(w, S_ACTION) + 1)
    iv_put(w, S_ROLE, role)
    iv_put(w, S_PEER_NEED, size)
    return 1

def sv_source(s:readbuf, w:mutbuf) -> u64:
    if length(s) != iv_get(w, S_SOURCE_BYTES) or sv_equal(s, w, 0, SV_SOURCE_HEADER, 64) == 0:
        return iv_bad(w, 802)
    return 1

def sv_borrow(s:readbuf, r:readbuf, w:mutbuf, at:u64, handle:u64) -> u64:
    if at > length(r) or length(r) - at != 320:
        return iv_bad(w, 803)
    if iv_word(r, at) != SV_REG_EVENT or iv_word(r, at + 8) != 5:
        return iv_bad(w, 804)
    if iv_word(r, at + 16) != iv_get(w, S_INV) or iv_word(r, at + 24) != iv_get(w, S_CALL):
        return iv_bad(w, 805)
    if iv_word(r, at + 48) != iv_word(s, 8) or iv_word(r, at + 56) != length(s):
        return iv_bad(w, 806)
    if iv_word(r, at + 64) != 0 or iv_word(r, at + 136) != 1 or iv_word(r, at + 144) != 0:
        return iv_bad(w, 807)
    if iv_word(r, at + 152) != length(s) or iv_word(r, at + 168) != handle:
        return iv_bad(w, 808)
    if iv_word(r, at + 176) != 1024 or iv_word(r, at + 184) != 64 or iv_word(r, at + 200) != iv_get(w, S_ORIGIN):
        return iv_bad(w, 809)
    if iv_word(r, at + 208) != iv_word(s, 16) or iv_word(r, at + 216) != 0 or iv_word(r, at + 224) != 0:
        return iv_bad(w, 810)
    if iv_word(r, at + 240) != 0 or iv_word(r, at + 248) != 0:
        return iv_bad(w, 811)
    sequence = iv_word(r, at + 32)
    command = iv_word(r, at + 40)
    root = iv_word(r, at + 160)
    issued = iv_word(r, at + 192)
    if sequence == 0 or command == 0 or iv_word(r, at + 232) != command:
        return iv_bad(w, 812)
    if root == 0 or root > iv_word(s, 16) or handle <= SV_HANDLE or handle - SV_HANDLE > issued:
        return iv_bad(w, 813)
    cfg = at + 256
    if iv_word(r, cfg) != SV_WIRE_COMMAND or iv_word(r, cfg + 8) != iv_word(s, 8):
        return iv_bad(w, 814)
    if iv_word(r, cfg + 16) != command or iv_word(r, cfg + 24) != root:
        return iv_bad(w, 815)
    if iv_word(r, cfg + 32) != 8388608 or iv_word(r, cfg + 40) != 2 or iv_word(r, cfg + 48) != iv_get(w, S_DIGITS) or iv_word(r, cfg + 56) != 0:
        return iv_bad(w, 816)
    if iv_shape(s, w, 0, length(s), iv_word(s, 8)) == 0:
        return 0
    copy_bytes(w, s, SV_SOURCE_HEADER, 0, 64)
    copy_bytes(w, r, SV_BORROW, at, 256)
    copy_bytes(w, r, SV_CONFIG, cfg, 64)
    iv_put(w, S_SOURCE_LEASE, iv_word(s, 8))
    iv_put(w, S_SOURCE_BYTES, length(s))
    iv_put(w, S_SOURCE_NODES, iv_word(s, 16))
    iv_put(w, S_SOURCE_EDGES, iv_word(s, 32))
    iv_put(w, S_SOURCE_POOL, iv_word(s, 40))
    iv_put(w, S_REG_SEQ, sequence)
    iv_put(w, S_REG_COMMAND, command)
    iv_put(w, S_ISSUED, issued)
    iv_put(w, S_ROOT, root)
    return 1

def sv_initializer(r:readbuf, w:mutbuf, size:u64) -> u64:
    if size < 8192 or size > length(r) - 128 or length(r) - 128 - size != 320:
        return iv_bad(w, 817)
    at = 128 + 2048
    if iv_word(r, at) != SV_INIT_EVENT or iv_word(r, at + 8) != 2:
        return iv_bad(w, 818)
    if iv_word(r, at + 16) != iv_get(w, S_INV) or iv_word(r, at + 24) != iv_get(w, S_CALL):
        return iv_bad(w, 819)
    pending = iv_word(r, at + 32)
    peer = iv_word(r, at + 48)
    if pending == 0 or iv_word(r, at + 56) != pending or iv_word(r, at + 64) != 0:
        return iv_bad(w, 820)
    if peer != 11 and peer != 15:
        return iv_bad(w, 821)
    phase = iv_word(r, at + 40)
    if peer == 11:
        if phase != 34:
            return iv_bad(w, 822)
    elif phase != 42 and phase != 61 and phase != 68 and phase != 71 and phase != 74:
        return iv_bad(w, 823)
    origin = iv_word(r, at + 72)
    digits = iv_word(r, at + 88)
    if origin == 0 or iv_word(r, at + 80) == 0 or (digits != 0 and digits < 640):
        return iv_bad(w, 824)
    authority = iv_word(r, at + 96)
    if authority == 0 or iv_word(r, at + 104) != 0 or iv_word(r, at + 120) != authority:
        return iv_bad(w, 825)
    if iv_word(r, at + 112) <= SV_HANDLE:
        return iv_bad(w, 826)
    index = 128
    while index < 184:
        if iv_word(r, at + index) != 0:
            return iv_bad(w, 827)
        index = index + 8
    name_bytes = iv_word(r, at + 192)
    if iv_word(r, at + 184) != 5120 or name_bytes == 0 or name_bytes > 32:
        return iv_bad(w, 828)
    if iv_word(r, at + 200) != 4096 or iv_word(r, at + 208) != 512:
        return iv_bad(w, 829)
    index = 216
    while index < 256:
        if iv_word(r, at + index) != 0:
            return iv_bad(w, 830)
        index = index + 8
    if iv_word(r, 128 + IS_I_MAGIC) != SV_INIT_STATE or iv_word(r, 128 + IS_I_STATUS) != 2:
        return iv_bad(w, 831)
    if iv_word(r, 128 + IS_I_SEQ) != pending or iv_word(r, 128 + IS_I_PENDING) != pending:
        return iv_bad(w, 832)
    if iv_word(r, 128 + IS_I_INV) != iv_get(w, S_INV) or iv_word(r, 128 + IS_I_CALL) != iv_get(w, S_CALL):
        return iv_bad(w, 833)
    if iv_word(r, 128 + IS_I_PEER) != peer or iv_word(r, 128 + IS_I_PHASE) != phase:
        return iv_bad(w, 834)
    if iv_word(r, 128 + IS_I_STORE) != authority or iv_word(r, 128 + IS_I_LITERAL_BYTES) != name_bytes:
        return iv_bad(w, 835)
    if peer == 15:
        if name_bytes != 9 or iv_word(r, 128 + 5120) != SV_DISCOVERY_PREFIX or byte(r, 128 + 5128) != 121:
            return iv_bad(w, 836)
    iv_put(w, S_PEER, peer)
    iv_put(w, S_PENDING, pending)
    iv_put(w, S_ORIGIN, origin)
    iv_put(w, S_DIGITS, digits)
    iv_put(w, S_STORE, authority)
    iv_put(w, S_INPUT_HANDLE, iv_word(r, at + 112))
    iv_put(w, S_NAME_BYTES, name_bytes)
    copy_bytes(w, r, SV_INITIALIZER, at, 256)
    copy_bytes(w, r, SV_NAME, 128 + 5120, name_bytes)
    return 1

def sv_begin(s:readbuf, r:readbuf, w:mutbuf) -> u32:
    if iv_word(r, 40) != 0 or iv_word(r, 72) != 2304 or iv_word(r, 80) != 1 or iv_word(r, 96) != 768 or iv_word(r, 104) != 0 or iv_word(r, 112) != 0:
        return sv_fail(w, 837)
    index = 0
    while index < SV_MIN:
        if byte(w, index) != 0:
            return sv_fail(w, 838)
        index = index + 1
    iv_put(w, S_MAGIC, SV_STATE)
    iv_put(w, S_INV, iv_word(r, 16))
    iv_put(w, S_CALL, iv_word(r, 24))
    iv_put(w, S_LEASE, iv_word(r, 32))
    size = iv_word(r, 88)
    if sv_initializer(r, w, size) == 0:
        return sv_fail(w, 839)
    if sv_borrow(s, r, w, 128 + size, iv_get(w, S_INPUT_HANDLE)) == 0:
        return sv_fail(w, 840)
    iv_put(w, S_WIRE_STAGE, 0)
    iv_put(w, S_PHASE, 10)
    iv_put(w, SV_PROFILE_KIND, SV_PROFILE_LITERAL)
    if sv_action(w, 1, 32768) == 0:
        return sv_fail(w, 841)
    return sv_event(w, 1)

def sv_reply_base(w:mutbuf) -> u64:
    fill_range(w, SV_REPLY, 1024, 0)
    iv_put(w, SV_REPLY, SV_INIT_REPLY)
    iv_put(w, SV_REPLY + 8, iv_get(w, S_INV))
    iv_put(w, SV_REPLY + 16, iv_get(w, S_CALL))
    iv_put(w, SV_REPLY + 24, iv_get(w, S_PENDING))
    iv_put(w, SV_REPLY + 32, iv_get(w, S_PEER))
    iv_put(w, SV_REPLY + 120, 256)
    iv_put(w, S_REPLY_AT, SV_REPLY)
    iv_put(w, S_REPLY_BYTES, 256)
    return 1

def sv_success(w:mutbuf) -> u32:
    sv_reply_base(w)
    iv_put(w, SV_REPLY + 48, choose(iv_get(w, S_PEER) == 11, 9, 2))
    iv_put(w, SV_REPLY + 64, choose(iv_get(w, S_PEER) == 11, iv_get(w, S_GRAPH_HANDLE), iv_get(w, S_REF_HANDLE)))
    if iv_get(w, S_PEER) == 11:
        iv_put(w, SV_REPLY + 72, iv_get(w, S_REF_HANDLE))
    iv_put(w, S_PHASE, 90)
    return sv_event(w, 0)

def sv_wire_error(r:readbuf, w:mutbuf) -> u32:
    sv_reply_base(w)
    code = iv_word(r, 128 + 64)
    cause = iv_word(r, 128 + 72)
    text_size = sv_error_literal(w, code)
    if text_size == 0:
        return sv_fail(w, 842)
    iv_put(w, SV_REPLY + 40, 1)
    iv_put(w, SV_REPLY + 96, iv_get(w, S_LEASE))
    iv_put(w, SV_REPLY + 104, 256)
    iv_put(w, SV_REPLY + 112, 64 + text_size)
    iv_put(w, SV_REPLY + 120, 320 + text_size)
    iv_put(w, SV_REPLY + 256, SV_EXCEPTION)
    iv_put(w, SV_REPLY + 264, 1)
    iv_put(w, SV_REPLY + 272, 1)
    iv_put(w, SV_REPLY + 280, code)
    iv_put(w, SV_REPLY + 288, cause)
    iv_put(w, SV_REPLY + 296, text_size)
    iv_put(w, SV_REPLY + 304, 64 + text_size)
    iv_put(w, S_REPLY_BYTES, 320 + text_size)
    iv_put(w, S_PHASE, 90)
    return sv_event(w, 5)

def sv_wire_reply(s:readbuf, r:readbuf, w:mutbuf, continuing:u64) -> u32:
    if sv_wire_check(r, w) == 0:
        return sv_fail(w, 843)
    action = iv_word(r, 136)
    if continuing == 0:
        if action == 3:
            return sv_wire_error(r, w)
        if action == 1:
            need = iv_word(r, 208)
            if need <= iv_word(r, 88) or iv_word(r, 240) >= 90 or sv_action(w, iv_get(w, S_ROLE), need) == 0:
                return sv_fail(w, 844)
            return sv_event(w, 1)
        if action == 2:
            if iv_get(w, S_ROLE) != 1 or iv_word(r, 208) > iv_word(r, 88) or iv_word(r, 240) >= 90:
                return sv_fail(w, 845)
            if sv_action(w, 2, iv_word(r, 88)) == 0:
                return sv_fail(w, 846)
            return sv_event(w, 1)
    if action != 0 or iv_get(w, S_ROLE) != 2:
        return sv_fail(w, 847)
    at = iv_word(r, 216)
    size = iv_word(r, 224)
    whole = iv_word(r, 88)
    if at < 32768 or at > whole or size == 0 or size > whole - at or size > 8388608:
        return sv_fail(w, 848)
    if iv_word(r, 208) > whole or iv_word(r, 128 + 536) != at or iv_word(r, 128 + 528) != size:
        return sv_fail(w, 849)
    if continuing == 0:
        iv_put(w, S_WIRE_AT, at)
        iv_put(w, S_WIRE_BYTES, size)
        iv_put(w, S_WIRE_WHOLE, whole)
        copy_bytes(w, r, SV_WIRE_HEADER, 128, 128)
        iv_put(w, S_PHASE, 20)
        iv_put(w, S_NEED, SV_WIRE + size)
        if iv_get(w, S_WIRE_STAGE) == 1:
            if sv_profile_size(s, w, size) == 0:
                return sv_fail(w, 850)
    elif at != iv_get(w, S_WIRE_AT) or size != iv_get(w, S_WIRE_BYTES) or whole != iv_get(w, S_WIRE_WHOLE) or sv_equal(r, w, 128, SV_WIRE_HEADER, 128) == 0:
        return sv_fail(w, 851)
    if length(w) < iv_get(w, S_NEED):
        return sv_event(w, 2)
    copy_bytes(w, r, SV_WIRE, 128 + at, size)
    iv_put(w, S_NEED, 0)
    if iv_get(w, S_WIRE_STAGE) == 0:
        iv_put(w, S_PHASE, 30)
        if sv_action(w, 3, 256) == 0:
            return sv_fail(w, 852)
        return sv_event(w, 3)
    if sv_profile_graph(s, w) == 0:
        return sv_fail(w, 853)
    iv_put(w, S_PHASE, 40)
    if sv_action(w, 4, 256) == 0:
        return sv_fail(w, 854)
    return sv_event(w, 4)

def sv_current(s:readbuf, r:readbuf, w:mutbuf) -> u64:
    if iv_get(w, S_MAGIC) != SV_STATE or iv_word(r, 16) != iv_get(w, S_INV) or iv_word(r, 24) != iv_get(w, S_CALL):
        return iv_bad(w, 855)
    if iv_word(r, 32) != iv_get(w, S_LEASE) or iv_word(r, 40) != iv_get(w, S_SEQ):
        return iv_bad(w, 856)
    if iv_word(r, 112) != iv_get(w, S_ACTION):
        return iv_bad(w, 857)
    op = iv_word(r, 8)
    if op != 3 and op != 6 and sv_source(s, w) == 0:
        return 0
    return 1

def worker_store_values(s:readbuf, r:readbuf, w:mutbuf) -> u32:
    if length(w) < SV_MIN:
        return IV_BAD
    if iv_get(w, S_PHASE) == 90 or iv_get(w, S_PHASE) == 99 or iv_get(w, V_BAD) != 0:
        return IV_BAD
    if length(r) < 128 or iv_word(r, 0) != SV_COMMAND or iv_word(r, 120) != 0:
        return sv_fail(w, 858)
    op = iv_word(r, 8)
    if op < 1 or op > 6 or iv_word(r, 16) == 0 or iv_word(r, 24) == 0 or iv_word(r, 32) == 0:
        return sv_fail(w, 859)
    if length(s) < 128 or iv_word(r, 48) != iv_word(s, 8) or iv_word(r, 56) != length(s) or iv_word(r, 64) != length(r) - 128:
        return sv_fail(w, 860)
    if iv_get(w, S_MAGIC) == 0:
        if op != 1:
            return sv_fail(w, 861)
        return sv_begin(s, r, w)
    if op == 1 or sv_current(s, r, w) == 0:
        return sv_fail(w, 862)
    if op == 2:
        if iv_get(w, S_PHASE) != 10 or iv_word(r, 96) != 0 or iv_word(r, 104) != 0:
            return sv_fail(w, 863)
        return sv_wire_reply(s, r, w, 0)
    if op == 4:
        if iv_get(w, S_PHASE) == 20:
            if iv_word(r, 96) != 0 or iv_word(r, 104) != 0:
                return sv_fail(w, 864)
            return sv_wire_reply(s, r, w, 1)
        if iv_get(w, S_PHASE) == 80:
            return sv_namespace_error(r, w, 1)
        return sv_fail(w, 865)
    if op == 3:
        if iv_get(w, S_PHASE) != 30 and iv_get(w, S_PHASE) != 40:
            return sv_fail(w, 866)
        return sv_namespace_reply(s, r, w)
    if op == 5:
        if iv_get(w, S_PHASE) != 50:
            return sv_fail(w, 867)
        return sv_reserved(s, r, w)
    if iv_get(w, S_PHASE) != 60:
        return sv_fail(w, 868)
    return sv_bound(s, r, w)
'''
