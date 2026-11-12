"""Native maps/values completion custody and initializer replies, UNEXECUTED."""
BODY=r'''
def pj_child_source(s:readbuf, r:readbuf, w:mutbuf) -> u64:
    index = 0
    while index < 64:
        expected = byte(s, index)
        if iv_get(w, B_SOURCE_OWNER) == 2:
            expected = byte(w, iv_get(w, B_PREP_AT) + index)
        if byte(r, 128 + 960 + index) != expected:
            return iv_bad(w, 220)
        index = index + 1
    return 1

def pj_child_header(s:readbuf, r:readbuf, w:mutbuf) -> u64:
    at = 128 + 512
    action = iv_word(r, at + 8)
    if action > 1:
        return iv_bad(w, 221)
    if iv_word(r, at + 16) != iv_get(w, B_INV) or iv_word(r, at + 24) != iv_get(w, B_PENDING):
        return iv_bad(w, 222)
    previous = iv_get(w, B_CHILD_SEQUENCE)
    if previous == IV_MAX or iv_word(r, at + 32) != previous + 1:
        return iv_bad(w, 223)
    if iv_word(r, at + 40) != iv_get(w, B_MODE) or iv_word(r, at + 104) != 0 or iv_word(r, at + 120) != 0:
        return iv_bad(w, 224)
    if iv_word(r, 64) < 4096:
        return iv_bad(w, 225)
    if iv_word(r, 128 + 8) != choose(action == 0, 2, 1):
        return iv_bad(w, 226)
    if iv_word(r, 128 + 16) != iv_word(r, at + 32) or iv_word(r, 128 + 24) != iv_word(r, at + 48):
        return iv_bad(w, 227)
    if iv_word(r, 128 + 32) != 0 or iv_word(r, 128 + 40) != iv_get(w, B_MODE):
        return iv_bad(w, 228)
    if iv_get(w, B_CHILD_KIND) == 1:
        if iv_word(r, 128) != PJ_MAPS_STATE or iv_word(r, at) != PJ_MAPS_EVENT:
            return iv_bad(w, 229)
        if iv_word(r, 128 + 72) != iv_get(w, B_PREP_BYTES):
            return iv_bad(w, 230)
        if iv_word(r, 128 + 144) != choose(iv_get(w, B_MODE) == 6, 0, iv_get(w, B_OUTPUT_LEASE)):
            return iv_bad(w, 231)
        lease = choose(iv_get(w, B_SOURCE_OWNER) == 2, iv_get(w, B_PREP_LEASE), iv_get(w, B_LEASE))
        if iv_word(r, 128 + 152) != lease or iv_word(r, 128 + 160) != iv_get(w, B_INV):
            return iv_bad(w, 232)
        if iv_word(r, 128 + 168) != iv_get(w, B_PENDING):
            return iv_bad(w, 233)
        index = 0
        while index < 192:
            if (index < 8 or index >= 16) and (index < 32 or index >= 40):
                if byte(r, 128 + 768 + index) != byte(w, PJ_WIRE + index):
                    return iv_bad(w, 234)
            index = index + 1
    else:
        if iv_word(r, 128) != PJ_VALUES_STATE or iv_word(r, at) != PJ_VALUES_EVENT:
            return iv_bad(w, 235)
        if iv_word(r, 128 + 368) != iv_get(w, B_BYTES):
            return iv_bad(w, 236)
        if iv_word(r, at + 56) != 4096 or iv_word(r, at + 80) != iv_get(w, B_OUTPUT_LEASE):
            return iv_bad(w, 237)
        if iv_word(r, at + 88) != iv_get(w, B_NODES) or iv_word(r, at + 96) != iv_word(r, 128 + 88):
            return iv_bad(w, 238)
        if iv_word(r, at + 112) != 0:
            return iv_bad(w, 239)
        index = 0
        while index < 192:
            if byte(r, 128 + 128 + index) != byte(w, PJ_WIRE + index):
                return iv_bad(w, 240)
            index = index + 1
    return pj_child_source(s, r, w)

def pj_range_equal(s:readbuf, r:readbuf, a:u64, b:u64, count:u64) -> u64:
    index = 0
    while count - index >= 8:
        if iv_word(s, a + index) != iv_word(r, b + index):
            return 0
        index = index + 8
    while index < count:
        if byte(s, a + index) != byte(r, b + index):
            return 0
        index = index + 1
    return 1

def pj_prefix(s:readbuf, r:readbuf, w:mutbuf, base:u64, size:u64) -> u64:
    if iv_shape(r, w, base, size, iv_get(w, B_OUTPUT_LEASE)) == 0:
        return 0
    nodes = iv_get(w, B_NODES)
    edges = iv_get(w, B_EDGES)
    pool = iv_get(w, B_POOL)
    newnodes = iv_word(r, base + 16)
    newedges = iv_word(r, base + 32)
    newpool = iv_word(r, base + 40)
    if newnodes < nodes or newedges < edges or newpool < pool:
        return iv_bad(w, 241)
    olddata = 64 + nodes * 64 + edges * 8
    newdata = 64 + newnodes * 64 + newedges * 8
    identifier = 1
    while identifier <= nodes:
        kind = iv_word(s, identifier * 64)
        field = 0
        while field < 8:
            expected = iv_word(s, identifier * 64 + field * 8)
            if field == 1 and (kind == 2 or kind == 3 or kind == 4 or kind == 9):
                expected = newdata + expected - olddata
            if iv_word(r, base + identifier * 64 + field * 8) != expected:
                return iv_bad(w, 242)
            field = field + 1
        identifier = identifier + 1
    if pj_range_equal(s, r, 64 + nodes * 64, base + 64 + newnodes * 64, edges * 8) == 0:
        return iv_bad(w, 243)
    if pj_range_equal(s, r, olddata, base + newdata, pool) == 0:
        return iv_bad(w, 244)
    iv_put(w, B_RESULT_NODES, newnodes)
    iv_put(w, B_RESULT_EDGES, newedges)
    iv_put(w, B_RESULT_POOL, newpool)
    iv_put(w, B_RESULT_LEASE, iv_word(r, base + 8))
    return 1

def pj_result_roots(s:readbuf, r:readbuf, w:mutbuf) -> u64:
    at = 128 + 512
    root = 0
    second = 0
    begin = 0
    size = 0
    if iv_get(w, B_CHILD_KIND) == 1:
        root = iv_word(r, at + 80)
        second = iv_word(r, at + 88)
        if iv_get(w, B_MODE) == 6:
            if iv_word(r, at + 56) != 1 or iv_word(r, at + 64) != 0 or second != 0:
                return iv_bad(w, 245)
            lease = choose(iv_get(w, B_SOURCE_OWNER) == 2, iv_get(w, B_PREP_LEASE), iv_get(w, B_LEASE))
            if iv_word(r, at + 72) != iv_get(w, B_PREP_BYTES) or iv_word(r, at + 96) != lease:
                return iv_bad(w, 246)
            if root == 0 or root > iv_get(w, B_NODES):
                return iv_bad(w, 247)
            iv_put(w, B_GRAPH_OWNER, 1)
            iv_put(w, B_GRAPH_AT, 0)
            iv_put(w, B_GRAPH_BYTES, iv_get(w, B_BYTES))
            iv_put(w, B_RESULT_NODES, iv_get(w, B_NODES))
            iv_put(w, B_RESULT_EDGES, iv_get(w, B_EDGES))
            iv_put(w, B_RESULT_POOL, iv_get(w, B_POOL))
            iv_put(w, B_RESULT_LEASE, iv_get(w, B_LEASE))
            iv_put(w, B_ROOT0, root)
            iv_put(w, B_ROOT1, 0)
            return 1
        if iv_word(r, at + 56) != 2 or iv_word(r, at + 96) != iv_get(w, B_OUTPUT_LEASE):
            return iv_bad(w, 248)
        begin = iv_word(r, at + 64)
        size = iv_word(r, at + 72)
        two = iv_get(w, B_MODE) == 2 or iv_get(w, B_MODE) == 3
        if (two and (second == 0 or second == root)) or (not two and second != 0):
            return iv_bad(w, 249)
    else:
        begin = iv_word(r, at + 56)
        size = iv_word(r, at + 64)
        root = iv_word(r, at + 72)
    if begin > iv_word(r, 64) or size > iv_word(r, 64) - begin:
        return iv_bad(w, 250)
    if iv_word(r, at + 48) != begin + size:
        return iv_bad(w, 251)
    base = 128 + begin
    if pj_prefix(s, r, w, base, size) == 0:
        return 0
    if root == 0 or root > iv_get(w, B_RESULT_NODES) or iv_word(r, base + 24) != root:
        return iv_bad(w, 252)
    if iv_word(r, base + root * 64) != 6:
        return iv_bad(w, 253)
    if second != 0:
        if second > iv_get(w, B_RESULT_NODES) or iv_word(r, base + second * 64) != 6:
            return iv_bad(w, 254)
    iv_put(w, B_GRAPH_OWNER, 3)
    iv_put(w, B_GRAPH_AT, base)
    iv_put(w, B_GRAPH_BYTES, size)
    iv_put(w, B_ROOT0, root)
    iv_put(w, B_ROOT1, second)
    return 1

def pj_reply(w:mutbuf) -> u64:
    fill_range(w, PJ_REPLY_AT, 256, 0)
    iv_put(w, PJ_REPLY_AT, PJ_REPLY)
    iv_put(w, PJ_REPLY_AT + 8, iv_get(w, B_INV))
    iv_put(w, PJ_REPLY_AT + 16, iv_get(w, B_CALL))
    iv_put(w, PJ_REPLY_AT + 24, iv_get(w, B_PENDING))
    iv_put(w, PJ_REPLY_AT + 32, iv_get(w, B_PEER))
    iv_put(w, PJ_REPLY_AT + 48, choose(iv_get(w, B_HANDLE1) != 0, 8, 2))
    iv_put(w, PJ_REPLY_AT + 56, 640)
    iv_put(w, PJ_REPLY_AT + 64, iv_get(w, B_HANDLE0))
    iv_put(w, PJ_REPLY_AT + 72, iv_get(w, B_HANDLE1))
    iv_put(w, PJ_REPLY_AT + 120, 256)
    return 0

def pj_result(s:readbuf, r:readbuf, w:mutbuf) -> u32:
    if pj_child_header(s, r, w) == 0:
        return pj_fail(w)
    at = 128 + 512
    if iv_word(r, at + 8) == 1:
        needed = iv_word(r, at + 48)
        if needed <= iv_word(r, 64):
            iv_bad(w, 255)
            return pj_fail(w)
        if iv_get(w, B_CHILD_KIND) == 1:
            index = 56
            while index < 104:
                if iv_word(r, at + index) != 0:
                    iv_bad(w, 256)
                    return pj_fail(w)
                index = index + 8
        iv_put(w, B_CHILD_NEED, needed)
        iv_put(w, B_CHILD_SEQUENCE, iv_word(r, at + 32))
        pj_wire(w)
        iv_put(w, B_PHASE, 3)
        return pj_event(w, 3)
    if pj_result_roots(s, r, w) == 0:
        return pj_fail(w)
    first = iv_get(w, B_ROOT0)
    second = iv_get(w, B_ROOT1)
    extra = choose(pj_existing(w, first) == 0, 1, 0)
    if second != 0 and pj_existing(w, second) == 0:
        extra = extra + 1
    if pj_reserve(w, extra) == 0:
        return pj_fail(w)
    if iv_get(w, B_NEED) > length(w):
        return pj_event(w, 1)
    iv_put(w, B_HANDLE0, pj_issue(w, first, iv_get(w, B_RESULT_NODES)))
    iv_put(w, B_HANDLE1, 0)
    if second != 0:
        iv_put(w, B_HANDLE1, pj_issue(w, second, iv_get(w, B_RESULT_NODES)))
    if iv_get(w, B_GRAPH_OWNER) == 3:
        copy_bytes(w, r, PJ_SOURCE_HEADER, iv_get(w, B_GRAPH_AT), 64)
        iv_put(w, B_LEASE, iv_get(w, B_RESULT_LEASE))
        iv_put(w, B_BYTES, iv_get(w, B_GRAPH_BYTES))
        iv_put(w, B_NODES, iv_get(w, B_RESULT_NODES))
        iv_put(w, B_EDGES, iv_get(w, B_RESULT_EDGES))
        iv_put(w, B_POOL, iv_get(w, B_RESULT_POOL))
    pj_reply(w)
    iv_put(w, B_CHILD_SEQUENCE, iv_word(r, at + 32))
    iv_put(w, B_LAST_PENDING, iv_get(w, B_PENDING))
    iv_put(w, B_LAST_COMMAND, iv_get(w, B_ACTIVE_COMMAND))
    iv_put(w, B_PHASE, 0)
    return pj_event(w, 4)
'''
