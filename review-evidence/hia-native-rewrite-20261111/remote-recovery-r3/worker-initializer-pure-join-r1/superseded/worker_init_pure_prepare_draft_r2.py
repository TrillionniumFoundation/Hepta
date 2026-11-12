"""Actual initializer event to complete maps/values requests, NEW UNEXECUTED."""
BODY=r'''
def pj_seq(r:readbuf, index:u64) -> u64:
    return iv_word(r, 128 + 2048 + index * 8)

def pj_sequence(r:readbuf, w:mutbuf) -> u64:
    if iv_word(r, 64) < 8192 or iv_word(r, 72) != 2304:
        return iv_bad(w, 150)
    if iv_word(r, 128 + SI_MAGIC) != PJ_SEQUENCE_STATE or iv_word(r, 128 + SI_STATUS) != 2:
        return iv_bad(w, 151)
    if pj_seq(r, 0) != PJ_SEQUENCE_EVENT or pj_seq(r, 1) != 2:
        return iv_bad(w, 152)
    if pj_seq(r, 2) != iv_get(w, B_INV) or pj_seq(r, 3) != iv_get(w, B_CALL):
        return iv_bad(w, 153)
    if pj_seq(r, 2) != iv_word(r, 128 + SI_INV) or pj_seq(r, 3) != iv_word(r, 128 + SI_CALL):
        return iv_bad(w, 154)
    if pj_seq(r, 4) == 0 or pj_seq(r, 4) != iv_word(r, 128 + SI_SEQ):
        return iv_bad(w, 155)
    if pj_seq(r, 5) != iv_word(r, 128 + SI_PHASE) or pj_seq(r, 6) != iv_word(r, 128 + SI_PEER):
        return iv_bad(w, 156)
    if pj_seq(r, 7) != pj_seq(r, 4) or pj_seq(r, 7) != iv_word(r, 128 + SI_PENDING):
        return iv_bad(w, 157)
    if pj_seq(r, 8) != iv_word(r, 128 + SI_NEED):
        return iv_bad(w, 205)
    if pj_seq(r, 9) != iv_get(w, B_ORIGIN) or pj_seq(r, 9) != iv_word(r, 128 + SI_SOURCE_LEASE):
        return iv_bad(w, 158)
    if pj_seq(r, 10) != iv_word(r, 128 + SI_SOURCE_ROOT) or pj_seq(r, 10) == 0:
        return iv_bad(w, 159)
    if pj_seq(r, 11) != iv_word(r, 128 + SI_DIGITS) or pj_seq(r, 12) != iv_word(r, 128 + SI_STORE):
        return iv_bad(w, 160)
    if pj_seq(r, 13) != iv_word(r, 128 + SI_OP):
        return iv_bad(w, 161)
    index = 0
    while index < 6:
        if pj_seq(r, 14 + index) != iv_word(r, 128 + SI_ARG0 + index * 8):
            return iv_bad(w, 162)
        index = index + 1
    if pj_seq(r, 20) != iv_word(r, 128 + SI_VIEW_OWNER) or pj_seq(r, 21) != iv_word(r, 128 + SI_VIEW_AT):
        return iv_bad(w, 163)
    if pj_seq(r, 22) != iv_word(r, 128 + SI_VIEW_BYTES) or pj_seq(r, 23) != 5120:
        return iv_bad(w, 164)
    if pj_seq(r, 24) != iv_word(r, 128 + SI_LITERAL_BYTES) or pj_seq(r, 25) != 4096 or pj_seq(r, 26) != 512:
        return iv_bad(w, 165)
    index = 27
    while index < 32:
        if pj_seq(r, index) != 0:
            return iv_bad(w, 166)
        index = index + 1
    if pj_seq(r, 7) <= iv_get(w, B_LAST_PENDING):
        return iv_bad(w, 167)
    if iv_word(r, 8) == 2:
        copy_bytes(w, r, PJ_SAVED_SEQUENCE, 128 + 2048, 256)
    else:
        index = 0
        while index < 256:
            if byte(r, 128 + 2048 + index) != byte(w, PJ_SAVED_SEQUENCE + index):
                return iv_bad(w, 168)
            index = index + 1
    iv_put(w, B_PEER, pj_seq(r, 6))
    iv_put(w, B_PENDING, pj_seq(r, 7))
    iv_put(w, B_INITIALIZER_PHASE, pj_seq(r, 5))
    return 1

def pj_empty_args(r:readbuf, w:mutbuf, first:u64) -> u64:
    while first < 6:
        if pj_seq(r, 14 + first) != 0:
            return iv_bad(w, 169)
        first = first + 1
    return 1

def pj_argument(w:mutbuf, index:u64, handle:u64, required:u64) -> u64:
    root = 0
    if handle != 0:
        root = pj_lookup(w, handle)
        if root == 0:
            return 0
    elif required != 0:
        return iv_bad(w, 170)
    iv_put(w, B_ARG0 + index * 8, root)
    return 1

def pj_key(r:readbuf, w:mutbuf, index:u64, at:u64, bytes:u64, value:u64) -> u64:
    if at > length(r) or bytes > length(r) - at:
        return iv_bad(w, 171)
    position = 0
    while position < bytes:
        if byte(r, at + position) > 127:
            return iv_bad(w, 172)
        position = position + 1
    iv_put(w, PJ_KEYS_AT + index * 32, at)
    iv_put(w, PJ_KEYS_AT + index * 32 + 8, bytes)
    iv_put(w, PJ_KEYS_AT + index * 32 + 16, value)
    iv_put(w, PJ_KEYS_AT + index * 32 + 24, 0)
    if bytes > IV_MAX - iv_get(w, B_EXTRA_POOL):
        return iv_bad(w, 173)
    iv_put(w, B_EXTRA_POOL, iv_get(w, B_EXTRA_POOL) + bytes)
    return 1

def pj_named(r:readbuf, w:mutbuf) -> u64:
    if pj_seq(r, 20) != 0 or pj_seq(r, 21) != 0 or pj_seq(r, 22) != 0:
        return iv_bad(w, 174)
    at = pj_seq(r, 23)
    size = pj_seq(r, 24)
    if at > iv_word(r, 64) or size > iv_word(r, 64) - at:
        return iv_bad(w, 175)
    if pj_key(r, w, 0, 128 + at, size, 0) == 0:
        return 0
    iv_put(w, B_KEYS, 1)
    iv_put(w, B_EXTRA_NODES, 1)
    if iv_get(w, B_NODES) == IV_MAX:
        return iv_bad(w, 176)
    iv_put(w, B_ARG0 + 32, iv_get(w, B_NODES) + 1)
    return 1

def pj_bindings(r:readbuf, w:mutbuf) -> u64:
    if pj_seq(r, 14) != 6 or pj_empty_args(r, w, 1) == 0:
        return iv_bad(w, 177)
    if pj_seq(r, 20) != 2 or pj_seq(r, 24) != 0:
        return iv_bad(w, 178)
    begin = pj_seq(r, 21)
    size = pj_seq(r, 22)
    if begin > iv_word(r, 64) or size > iv_word(r, 64) - begin or size < 192:
        return iv_bad(w, 179)
    begin = begin + 128
    end = 192
    index = 0
    while index < 6:
        row = begin + index * 32
        at = iv_word(r, row)
        bytes = iv_word(r, row + 8)
        if at != end or at > size or bytes > size - at or iv_word(r, row + 24) != 0:
            return iv_bad(w, 180)
        root = pj_lookup(w, iv_word(r, row + 16))
        if root == 0 or pj_key(r, w, index, begin + at, bytes, root) == 0:
            return 0
        end = end + bytes
        index = index + 1
    if end != size:
        return iv_bad(w, 181)
    iv_put(w, B_KEYS, 6)
    iv_put(w, B_EXTRA_NODES, 13)
    iv_put(w, B_EXTRA_EDGES, 18)
    if iv_get(w, B_NODES) > IV_MAX - 13:
        return iv_bad(w, 182)
    iv_put(w, B_ARG0, iv_get(w, B_NODES) + 13)
    return 1

def pj_values_request(r:readbuf, w:mutbuf) -> u64:
    mode = pj_seq(r, 13)
    phase = pj_seq(r, 5)
    valid = (mode == 1 and phase == 30) or (mode == 2 and phase == 70)
    valid = valid or (mode == 3 and phase == 73) or (mode == 4 and phase == 63)
    valid = valid or (mode == 5 and phase == 67) or (mode == 6 and phase == 60)
    if not valid or pj_seq(r, 24) != 0:
        return iv_bad(w, 183)
    iv_put(w, B_CHILD_KIND, 2)
    iv_put(w, B_MODE, mode)
    index = 0
    while index < 4:
        if pj_argument(w, index, pj_seq(r, 14 + index), 1) == 0:
            return 0
        index = index + 1
    if pj_argument(w, 7, pj_seq(r, 18), choose(mode == 5, 1, 0)) == 0:
        return 0
    if pj_argument(w, 8, pj_seq(r, 19), choose(mode == 5, 1, 0)) == 0:
        return 0
    if mode == 3:
        begin = pj_seq(r, 21)
        if pj_seq(r, 20) != 2 or pj_seq(r, 22) != 24:
            return iv_bad(w, 184)
        if begin > iv_word(r, 64) or 24 > iv_word(r, 64) - begin:
            return iv_bad(w, 185)
        index = 0
        while index < 3:
            if pj_argument(w, 4 + index, iv_word(r, 128 + begin + index * 8), 1) == 0:
                return 0
            index = index + 1
    elif pj_seq(r, 20) != 0 or pj_seq(r, 21) != 0 or pj_seq(r, 22) != 0:
        return iv_bad(w, 186)
    return 1

def pj_maps_request(r:readbuf, w:mutbuf) -> u64:
    peer = pj_seq(r, 6)
    operation = pj_seq(r, 13)
    phase = pj_seq(r, 5)
    iv_put(w, B_CHILD_KIND, 1)
    if peer == 2:
        if operation != 0 or phase != 3 or pj_empty_args(r, w, 1) == 0:
            return iv_bad(w, 187)
        if pj_seq(r, 20) != 0 or pj_seq(r, 21) != 0 or pj_seq(r, 22) != 0 or pj_seq(r, 24) != 0:
            return iv_bad(w, 188)
        iv_put(w, B_MODE, 1)
        return pj_argument(w, 0, pj_seq(r, 14), 1)
    if peer == 19:
        if operation != 0 or phase != 33 or pj_empty_args(r, w, 1) == 0:
            return iv_bad(w, 189)
        iv_put(w, B_MODE, 6)
        if pj_argument(w, 0, pj_seq(r, 14), 1) == 0:
            return 0
        return pj_named(r, w)
    if peer != 10:
        return iv_bad(w, 190)
    if operation == 1:
        if phase != 31 or pj_empty_args(r, w, 0) == 0:
            return iv_bad(w, 191)
        if pj_seq(r, 20) != 0 or pj_seq(r, 21) != 0 or pj_seq(r, 22) != 0 or pj_seq(r, 24) != 0:
            return iv_bad(w, 192)
        iv_put(w, B_MODE, 2)
        return 1
    if operation == 2:
        if phase != 35 or pj_empty_args(r, w, 4) == 0:
            return iv_bad(w, 193)
        iv_put(w, B_MODE, 3)
        index = 0
        while index < 4:
            if pj_argument(w, index, pj_seq(r, 14 + index), 1) == 0:
                return 0
            index = index + 1
        return pj_named(r, w)
    if operation == 3:
        if phase != 43:
            return iv_bad(w, 194)
        iv_put(w, B_MODE, 4)
        return pj_bindings(r, w)
    if operation != 4 or (phase != 47 and phase != 62 and phase != 69 and phase != 72):
        return iv_bad(w, 195)
    if pj_empty_args(r, w, 2) == 0:
        return 0
    iv_put(w, B_MODE, 5)
    if pj_argument(w, 0, pj_seq(r, 14), 1) == 0 or pj_argument(w, 2, pj_seq(r, 15), 1) == 0:
        return 0
    return pj_named(r, w)

def pj_prepare_size(w:mutbuf) -> u64:
    if pj_reserve(w, 0) == 0:
        return 0
    iv_put(w, B_PREP_AT, iv_get(w, B_NEED))
    iv_put(w, B_PREP_BYTES, iv_get(w, B_BYTES))
    iv_put(w, B_SOURCE_OWNER, 1)
    if iv_get(w, B_KEYS) == 0:
        return 1
    nodes = iv_get(w, B_NODES)
    edges = iv_get(w, B_EDGES)
    pool = iv_get(w, B_POOL)
    if iv_get(w, B_EXTRA_NODES) > IV_MAX - nodes:
        return iv_bad(w, 196)
    nodes = nodes + iv_get(w, B_EXTRA_NODES)
    if nodes > (IV_MAX - 64) >> 6:
        return iv_bad(w, 197)
    if iv_get(w, B_EXTRA_EDGES) > IV_MAX - edges:
        return iv_bad(w, 198)
    edges = edges + iv_get(w, B_EXTRA_EDGES)
    end = 64 + nodes * 64
    if edges > (IV_MAX - end) >> 3:
        return iv_bad(w, 199)
    end = end + edges * 8
    if iv_get(w, B_EXTRA_POOL) > IV_MAX - pool:
        return iv_bad(w, 200)
    pool = pool + iv_get(w, B_EXTRA_POOL)
    if pool > IV_MAX - end:
        return iv_bad(w, 201)
    total = end + pool
    if total > IV_MAX - iv_get(w, B_PREP_AT):
        return iv_bad(w, 202)
    iv_put(w, B_PREP_BYTES, total)
    iv_put(w, B_PREP_NODES, nodes)
    iv_put(w, B_PREP_EDGES, edges)
    iv_put(w, B_PREP_POOL, pool)
    iv_put(w, B_NEED, iv_get(w, B_PREP_AT) + total)
    iv_put(w, B_SOURCE_OWNER, 2)
    return 1

def pj_prepare(s:readbuf, r:readbuf, w:mutbuf) -> u64:
    if pj_sequence(r, w) == 0:
        return 0
    fill_range(w, B_ARG0, 72, 0)
    fill_range(w, PJ_KEYS_AT, 192, 0)
    iv_put(w, B_KEYS, 0)
    iv_put(w, B_EXTRA_NODES, 0)
    iv_put(w, B_EXTRA_EDGES, 0)
    iv_put(w, B_EXTRA_POOL, 0)
    iv_put(w, B_HANDLE0, 0)
    iv_put(w, B_HANDLE1, 0)
    iv_put(w, B_GRAPH_OWNER, 0)
    iv_put(w, B_GRAPH_AT, 0)
    iv_put(w, B_GRAPH_BYTES, 0)
    if iv_word(r, 8) == 2:
        if iv_get(w, B_NEXT_LEASE) > IV_MAX - 2:
            return iv_bad(w, 203)
        iv_put(w, B_PREP_LEASE, iv_get(w, B_NEXT_LEASE) + 1)
        iv_put(w, B_OUTPUT_LEASE, iv_get(w, B_NEXT_LEASE) + 2)
        iv_put(w, B_NEXT_LEASE, iv_get(w, B_NEXT_LEASE) + 2)
    if pj_seq(r, 6) == 9:
        if pj_values_request(r, w) == 0:
            return 0
    elif pj_maps_request(r, w) == 0:
        return 0
    return pj_prepare_size(w)

def pj_append_node(w:mutbuf, identifier:u64, kind:u64, data:u64, size:u64, first:u64, amount:u64, aux:u64) -> u64:
    at = iv_get(w, B_PREP_AT) + identifier * 64
    iv_put(w, at, kind)
    iv_put(w, at + 8, data)
    iv_put(w, at + 16, size)
    iv_put(w, at + 24, first)
    iv_put(w, at + 32, amount)
    iv_put(w, at + 40, choose(kind == 5, identifier, 0))
    iv_put(w, at + 48, aux)
    return 0

def pj_prep_edge(w:mutbuf, index:u64, value:u64) -> u64:
    at = iv_get(w, B_PREP_AT) + 64 + iv_get(w, B_PREP_NODES) * 64 + index * 8
    iv_put(w, at, value)
    return 0

def pj_prepare_graph(s:readbuf, r:readbuf, w:mutbuf) -> u64:
    if iv_get(w, B_KEYS) == 0:
        return 1
    base = iv_get(w, B_PREP_AT)
    nodes = iv_get(w, B_NODES)
    edges = iv_get(w, B_EDGES)
    newnodes = iv_get(w, B_PREP_NODES)
    olddata = 64 + nodes * 64 + edges * 8
    newdata = 64 + newnodes * 64 + iv_get(w, B_PREP_EDGES) * 8
    copy_bytes(w, s, base + 64, 64, nodes * 64)
    identifier = 1
    while identifier <= nodes:
        kind = iv_word(s, identifier * 64)
        if kind == 2 or kind == 3 or kind == 4 or kind == 9:
            offset = iv_word(s, identifier * 64 + 8) - olddata
            iv_put(w, base + identifier * 64 + 8, newdata + offset)
        identifier = identifier + 1
    fill_range(w, base + (nodes + 1) * 64, (newnodes - nodes) * 64, 0)
    copy_bytes(w, s, base + 64 + newnodes * 64, 64 + nodes * 64, edges * 8)
    copy_bytes(w, s, base + newdata, olddata, iv_get(w, B_POOL))
    end = newdata + iv_get(w, B_POOL)
    index = 0
    while index < iv_get(w, B_KEYS):
        row = PJ_KEYS_AT + index * 32
        bytes = iv_get(w, row + 8)
        pj_append_node(w, nodes + index + 1, 4, end, bytes, 0, 0, bytes)
        copy_bytes(w, r, base + end, iv_get(w, row), bytes)
        end = end + bytes
        index = index + 1
    root = iv_word(s, 24)
    if iv_get(w, B_KEYS) == 6:
        index = 0
        while index < 6:
            pair = nodes + 7 + index
            pj_append_node(w, pair, 5, 0, 0, edges + index * 2, 2, 0)
            pj_prep_edge(w, edges + index * 2, nodes + index + 1)
            pj_prep_edge(w, edges + index * 2 + 1, iv_get(w, PJ_KEYS_AT + index * 32 + 16))
            pj_prep_edge(w, edges + 12 + index, pair)
            index = index + 1
        root = nodes + 13
        pj_append_node(w, root, 5, 0, 0, edges + 12, 6, 0)
    if end != iv_get(w, B_PREP_BYTES):
        return iv_bad(w, 204)
    iv_put(w, base, IV_GRAPH)
    iv_put(w, base + 8, iv_get(w, B_PREP_LEASE))
    iv_put(w, base + 16, newnodes)
    iv_put(w, base + 24, root)
    iv_put(w, base + 32, iv_get(w, B_PREP_EDGES))
    iv_put(w, base + 40, iv_get(w, B_PREP_POOL))
    iv_put(w, base + 48, iv_get(w, B_PREP_BYTES))
    iv_put(w, base + 56, 0)
    return 1

def pj_wire(w:mutbuf) -> u64:
    fill_range(w, PJ_WIRE, 192, 0)
    if iv_get(w, B_CHILD_KIND) == 2:
        iv_put(w, PJ_WIRE, PJ_VALUES_COMMAND)
        iv_put(w, PJ_WIRE + 8, iv_get(w, B_INV))
        iv_put(w, PJ_WIRE + 16, iv_get(w, B_PENDING))
        iv_put(w, PJ_WIRE + 24, iv_get(w, B_LEASE))
        iv_put(w, PJ_WIRE + 32, iv_get(w, B_BYTES))
        iv_put(w, PJ_WIRE + 40, iv_get(w, B_MODE))
        iv_put(w, PJ_WIRE + 48, iv_get(w, B_OUTPUT_LEASE))
        index = 0
        while index < 9:
            iv_put(w, PJ_WIRE + 56 + index * 8, iv_get(w, B_ARG0 + index * 8))
            index = index + 1
    else:
        iv_put(w, PJ_WIRE, PJ_MAPS_COMMAND)
        iv_put(w, PJ_WIRE + 8, choose(iv_get(w, B_CHILD_SEQUENCE) == 0, 1, 2))
        iv_put(w, PJ_WIRE + 16, iv_get(w, B_INV))
        iv_put(w, PJ_WIRE + 24, iv_get(w, B_PENDING))
        iv_put(w, PJ_WIRE + 32, iv_get(w, B_CHILD_SEQUENCE))
        iv_put(w, PJ_WIRE + 40, iv_get(w, B_MODE))
        iv_put(w, PJ_WIRE + 48, choose(iv_get(w, B_SOURCE_OWNER) == 2, iv_get(w, B_PREP_LEASE), iv_get(w, B_LEASE)))
        iv_put(w, PJ_WIRE + 56, iv_get(w, B_PREP_BYTES))
        iv_put(w, PJ_WIRE + 64, choose(iv_get(w, B_MODE) == 6, 0, iv_get(w, B_OUTPUT_LEASE)))
        index = 0
        while index < 5:
            iv_put(w, PJ_WIRE + 72 + index * 8, iv_get(w, B_ARG0 + index * 8))
            index = index + 1
    return 0
'''
