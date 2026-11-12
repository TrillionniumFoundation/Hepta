"""Native initializer pure-value session control, NEW UNEXECUTED source."""
BODY=r'''
def pj_source(s:readbuf, w:mutbuf) -> u64:
    if length(s) != iv_get(w, B_BYTES):
        return iv_bad(w, 101)
    index = 0
    while index < 64:
        if byte(s, index) != byte(w, PJ_SOURCE_HEADER + index):
            return iv_bad(w, 102)
        index = index + 1
    return 1

def pj_initial(s:readbuf, r:readbuf, w:mutbuf) -> u64:
    if iv_word(r, 8) != 1:
        return iv_bad(w, 103)
    index = 0
    while index < PJ_MIN:
        if byte(w, index) != 0:
            return iv_bad(w, 104)
        index = index + 1
    if iv_shape(s, w, 0, length(s), iv_word(r, 48)) == 0:
        return 0
    iv_put(w, B_MAGIC, PJ_STATE)
    iv_put(w, B_INV, iv_word(r, 16))
    iv_put(w, B_CALL, iv_word(r, 24))
    iv_put(w, B_ORIGIN, iv_word(r, 88))
    iv_put(w, B_LEASE, iv_word(s, 8))
    iv_put(w, B_NEXT_LEASE, iv_word(s, 8))
    iv_put(w, B_BYTES, length(s))
    iv_put(w, B_NODES, iv_word(s, 16))
    iv_put(w, B_EDGES, iv_word(s, 32))
    iv_put(w, B_POOL, iv_word(s, 40))
    copy_bytes(w, s, PJ_SOURCE_HEADER, 0, 64)
    return 1

def pj_command(s:readbuf, r:readbuf, w:mutbuf) -> u64:
    if length(r) < 128 or iv_word(r, 0) != PJ_COMMAND:
        return iv_bad(w, 105)
    mode = iv_word(r, 8)
    if mode < 1 or mode > 4 or iv_word(r, 16) == 0 or iv_word(r, 24) == 0:
        return iv_bad(w, 106)
    if iv_word(r, 64) != length(r) - 128 or iv_word(r, 88) == 0:
        return iv_bad(w, 107)
    index = 96
    while index < 128:
        if iv_word(r, index) != 0:
            return iv_bad(w, 108)
        index = index + 8
    if iv_get(w, B_MAGIC) == 0:
        if pj_initial(s, r, w) == 0:
            return 0
    if iv_get(w, B_MAGIC) != PJ_STATE or pj_source(s, w) == 0:
        return iv_bad(w, 109)
    if iv_word(r, 16) != iv_get(w, B_INV) or iv_word(r, 24) != iv_get(w, B_CALL):
        return iv_bad(w, 110)
    if iv_word(r, 40) != iv_get(w, B_SEQUENCE) or iv_word(r, 48) != iv_get(w, B_LEASE):
        return iv_bad(w, 111)
    if iv_word(r, 56) != length(s) or iv_word(r, 88) != iv_get(w, B_ORIGIN):
        return iv_bad(w, 112)
    phase = iv_get(w, B_PHASE)
    if mode == 1 or mode == 2:
        if phase != 0 or iv_get(w, B_LAST_COMMAND) == IV_MAX:
            return iv_bad(w, 113)
        if iv_word(r, 32) != iv_get(w, B_LAST_COMMAND) + 1:
            return iv_bad(w, 114)
        if mode == 1:
            if length(r) != 128 or iv_word(r, 72) != 0:
                return iv_bad(w, 115)
            identifier = iv_word(r, 80)
            if identifier == 0 or identifier > iv_get(w, B_NODES):
                return iv_bad(w, 116)
        else:
            if iv_word(r, 72) != 2304 or iv_word(r, 64) < 8192 or iv_word(r, 80) != 0:
                return iv_bad(w, 117)
        iv_put(w, B_ACTIVE_COMMAND, iv_word(r, 32))
        iv_put(w, B_PHASE, mode)
        iv_put(w, B_ORIGINAL_MODE, mode)
        copy_bytes(w, r, PJ_SAVED_COMMAND, 0, 128)
        return 1
    if mode == 4:
        if phase != 3 or iv_word(r, 32) != iv_get(w, B_ACTIVE_COMMAND):
            return iv_bad(w, 118)
        if iv_word(r, 72) != 640 or iv_word(r, 64) < 640 or iv_word(r, 80) != 0:
            return iv_bad(w, 119)
        iv_put(w, B_PHASE, 4)
        iv_put(w, B_ORIGINAL_MODE, 4)
        copy_bytes(w, r, PJ_SAVED_COMMAND, 0, 128)
        copy_bytes(w, r, PJ_SAVED_CHILD, 128 + 512, 128)
        return 1
    if phase != 1 and phase != 2 and phase != 4:
        return iv_bad(w, 120)
    if iv_word(r, 32) != iv_get(w, B_ACTIVE_COMMAND):
        return iv_bad(w, 121)
    index = 0
    while index < 128:
        if (index < 8 or index >= 16) and (index < 40 or index >= 48):
            if byte(r, index) != byte(w, PJ_SAVED_COMMAND + index):
                return iv_bad(w, 122)
        index = index + 1
    if phase == 4:
        index = 0
        while index < 128:
            if byte(r, 128 + 512 + index) != byte(w, PJ_SAVED_CHILD + index):
                return iv_bad(w, 123)
            index = index + 1
    return 1

def pj_lookup(w:mutbuf, handle:u64) -> u64:
    if handle <= PJ_HANDLE_BASE:
        iv_bad(w, 124)
        return 0
    index = handle - PJ_HANDLE_BASE - 1
    if index >= iv_get(w, B_ISSUED):
        iv_bad(w, 125)
        return 0
    root = iv_get(w, PJ_REGISTRY + index * 16)
    if root == 0 or root > iv_get(w, B_NODES):
        iv_bad(w, 126)
        return 0
    return root

def pj_existing(w:mutbuf, root:u64) -> u64:
    index = 0
    while index < iv_get(w, B_ISSUED):
        if iv_get(w, PJ_REGISTRY + index * 16) == root:
            return PJ_HANDLE_BASE + index + 1
        index = index + 1
    return 0

def pj_reserve(w:mutbuf, extra:u64) -> u64:
    count = iv_get(w, B_ISSUED)
    if extra > IV_MAX - count:
        return iv_bad(w, 127)
    count = count + extra
    if count > IV_MAX - PJ_HANDLE_BASE or count > (IV_MAX - PJ_REGISTRY) >> 4:
        return iv_bad(w, 128)
    iv_put(w, B_NEED, PJ_REGISTRY + count * 16)
    return 1

def pj_issue(w:mutbuf, root:u64, nodes:u64) -> u64:
    handle = pj_existing(w, root)
    if handle != 0:
        return handle
    count = iv_get(w, B_ISSUED)
    iv_put(w, PJ_REGISTRY + count * 16, root)
    iv_put(w, PJ_REGISTRY + count * 16 + 8, nodes)
    iv_put(w, B_ISSUED, count + 1)
    return PJ_HANDLE_BASE + count + 1

def pj_event(w:mutbuf, action:u64) -> u32:
    sequence = iv_get(w, B_SEQUENCE)
    if sequence == IV_MAX:
        iv_put(w, B_PHASE, 99)
        return IV_BAD
    iv_put(w, B_SEQUENCE, sequence + 1)
    fill_range(w, PJ_EVENT_AT, 256, 0)
    iv_put(w, PJ_EVENT_AT, PJ_EVENT)
    iv_put(w, PJ_EVENT_AT + 8, action)
    iv_put(w, PJ_EVENT_AT + 16, iv_get(w, B_INV))
    iv_put(w, PJ_EVENT_AT + 24, iv_get(w, B_CALL))
    iv_put(w, PJ_EVENT_AT + 32, sequence + 1)
    iv_put(w, PJ_EVENT_AT + 40, iv_get(w, B_ACTIVE_COMMAND))
    iv_put(w, PJ_EVENT_AT + 48, iv_get(w, B_PEER))
    iv_put(w, PJ_EVENT_AT + 56, iv_get(w, B_PENDING))
    iv_put(w, PJ_EVENT_AT + 64, iv_get(w, B_NEED))
    iv_put(w, PJ_EVENT_AT + 72, iv_get(w, B_CHILD_KIND))
    iv_put(w, PJ_EVENT_AT + 80, iv_get(w, B_CHILD_SEQUENCE))
    iv_put(w, PJ_EVENT_AT + 88, iv_get(w, B_CHILD_NEED))
    if action == 2 or action == 3:
        iv_put(w, PJ_EVENT_AT + 96, iv_get(w, B_SOURCE_OWNER))
        iv_put(w, PJ_EVENT_AT + 104, choose(iv_get(w, B_SOURCE_OWNER) == 2, iv_get(w, B_PREP_AT), 0))
        iv_put(w, PJ_EVENT_AT + 112, choose(iv_get(w, B_SOURCE_OWNER) == 2, iv_get(w, B_PREP_BYTES), iv_get(w, B_BYTES)))
        iv_put(w, PJ_EVENT_AT + 120, PJ_WIRE)
        iv_put(w, PJ_EVENT_AT + 128, 192)
    if action == 0 or action == 4:
        iv_put(w, PJ_EVENT_AT + 136, iv_get(w, B_GRAPH_OWNER))
        iv_put(w, PJ_EVENT_AT + 144, iv_get(w, B_GRAPH_AT))
        iv_put(w, PJ_EVENT_AT + 152, iv_get(w, B_GRAPH_BYTES))
        iv_put(w, PJ_EVENT_AT + 192, iv_get(w, B_HANDLE0))
        iv_put(w, PJ_EVENT_AT + 200, iv_get(w, B_HANDLE1))
    iv_put(w, PJ_EVENT_AT + 160, iv_get(w, B_LEASE))
    iv_put(w, PJ_EVENT_AT + 168, iv_get(w, B_BYTES))
    if action == 4:
        iv_put(w, PJ_EVENT_AT + 176, PJ_REPLY_AT)
        iv_put(w, PJ_EVENT_AT + 184, 256)
    iv_put(w, PJ_EVENT_AT + 208, iv_get(w, V_BAD))
    iv_put(w, PJ_EVENT_AT + 216, iv_get(w, B_ISSUED))
    iv_put(w, PJ_EVENT_AT + 224, iv_get(w, B_ORIGIN))
    iv_put(w, PJ_EVENT_AT + 232, iv_get(w, B_NODES))
    iv_put(w, PJ_EVENT_AT + 240, iv_get(w, B_MODE))
    return 768

def pj_fail(w:mutbuf) -> u32:
    iv_put(w, B_PHASE, 99)
    pj_event(w, 5)
    return IV_BAD

def pj_issue_command(r:readbuf, w:mutbuf) -> u32:
    root = iv_word(r, 80)
    extra = choose(pj_existing(w, root) == 0, 1, 0)
    if pj_reserve(w, extra) == 0:
        return pj_fail(w)
    if iv_get(w, B_NEED) > length(w):
        return pj_event(w, 1)
    iv_put(w, B_HANDLE0, pj_issue(w, root, iv_get(w, B_NODES)))
    iv_put(w, B_HANDLE1, 0)
    iv_put(w, B_GRAPH_OWNER, 1)
    iv_put(w, B_GRAPH_AT, 0)
    iv_put(w, B_GRAPH_BYTES, iv_get(w, B_BYTES))
    iv_put(w, B_PEER, 0)
    iv_put(w, B_PENDING, 0)
    iv_put(w, B_MODE, 0)
    iv_put(w, B_CHILD_KIND, 0)
    iv_put(w, B_CHILD_SEQUENCE, 0)
    iv_put(w, B_CHILD_NEED, 0)
    iv_put(w, B_PHASE, 0)
    iv_put(w, B_LAST_COMMAND, iv_get(w, B_ACTIVE_COMMAND))
    return pj_event(w, 0)

def initializer_pure(s:readbuf, r:readbuf, w:mutbuf) -> u32:
    if length(w) < PJ_MIN:
        return IV_BAD
    if iv_get(w, B_PHASE) == 99:
        return IV_BAD
    if pj_command(s, r, w) == 0:
        return pj_fail(w)
    phase = iv_get(w, B_PHASE)
    if phase == 1:
        return pj_issue_command(r, w)
    if phase == 2:
        if pj_prepare(s, r, w) == 0:
            return pj_fail(w)
        if iv_get(w, B_NEED) > length(w):
            return pj_event(w, 1)
        if pj_prepare_graph(s, r, w) == 0:
            return pj_fail(w)
        iv_put(w, B_CHILD_SEQUENCE, 0)
        pj_wire(w)
        iv_put(w, B_CHILD_NEED, 4096)
        iv_put(w, B_PHASE, 3)
        return pj_event(w, 2)
    if phase == 4:
        return pj_result(s, r, w)
    iv_bad(w, 129)
    return pj_fail(w)
'''
