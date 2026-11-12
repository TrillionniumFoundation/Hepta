"""Complete original hia_read order and continuations.

The three wire calls in each page-budget condition remain three separate
service entries. Store.get completion includes metadata decoding. SQL is a
fixed operation binding, not arbitrary SQL interpreted by the runtime host.
"""
FLOW=r'''
def rd_flow(g:readbuf, r:readbuf, w:mutbuf) -> u64:
    phase = rd_get(w, R_PHASE)
    if phase == 1:
        return rd_request(w, P_STORE_GET, 10, 1, 0, length(g),
            rd_get(w, R_REF), rd_get(w, R_ARGS_LEASE), 0)
    if phase == 10:
        if rd_get(w, R_PEER) != P_STORE_GET or rd_get(w, R_REPLY_AT) != 0:
            return rd_badset(w, 300)
        if rd_get(w, R_REPLY_SIZE) != length(r) or length(r) > RD_MAX_ARTIFACT:
            return rd_badset(w, 301)
        rd_put(w, R_ARTIFACT_LEASE, rd_get(w, R_REPLY_LEASE))
        rd_put(w, R_ARTIFACT_SIZE, length(r))
        rd_put(w, R_OFFSET_KIND, 2)
        rd_put(w, R_HAVE_REPLY, 0)
        rd_put(w, R_PHASE, choose(rd_get(w, R_CURSOR) == 0, 14, 11))
        return 0
    if phase == 11:
        if rd_build_cursor_select(g, w) == 0:
            return 0
        return rd_request(w, P_CURSOR_SELECT, 12, 3, RD_GRAPH_BASE,
            rd_get(w, R_GRAPH_BYTES), 1, rd_get(w, R_OUT_LEASE), OP_CURSOR_SELECT)
    if phase == 12:
        if rd_cursor_row(g, r, w) == 0:
            return 0
        rd_put(w, R_HAVE_REPLY, 0)
        rd_put(w, R_PHASE, 14)
        return 0
    if phase == 14:
        return rd_request(w, P_ARTIFACT_VIEW, 20, 4, 0,
            rd_get(w, R_ARTIFACT_SIZE), 0, rd_get(w, R_ARTIFACT_LEASE), 0)
    if phase == 22:
        return rd_wire_start(w, 23)
    if phase == 23:
        if rd_wire_result(r, w) == 0:
            return 0
        rd_put(w, R_WIRE_FIRST, rd_get(w, R_REPLY_SIZE))
        return rd_wire_start(w, 24)
    if phase == 24:
        if rd_wire_result(r, w) == 0:
            return 0
        if rd_build_wire_string(r, w) == 0:
            return 0
        rd_put(w, R_HAVE_REPLY, 0)
        rd_put(w, R_PHASE, 25)
        return 0
    if phase == 25:
        return rd_wire_start(w, 26)
    if phase == 26:
        if rd_wire_result(r, w) == 0:
            return 0
        if rd_get(w, R_WIRE_FIRST) + rd_get(w, R_REPLY_SIZE) > 230000:
            size = rd_get(w, R_CHUNK_BYTES)
            limit = size >> 1
            if limit < 1:
                limit = 1
            if limit < size:
                rd_put(w, R_CHUNK_BYTES, limit)
            rd_put(w, R_PHASE, 21)
        else:
            rd_put(w, R_PHASE, 30)
        rd_put(w, R_HAVE_REPLY, 0)
        return 0
    if phase == 30:
        if rd_sum(w, rd_get(w, R_CHUNK_BYTES)) == 0:
            return 0
        more = 0
        if rd_get(w, R_NEXT_SIGN) != 0 or rd_get(w, R_NEXT_MAG) < rd_get(w, R_ARTIFACT_SIZE):
            more = 1
        rd_put(w, R_HAS_CURSOR, more)
        rd_put(w, R_PHASE, choose(more == 0, 40, 31))
        return 0
    if phase == 31:
        if rd_build_digest(g, w) == 0:
            return 0
        return rd_wire_start(w, 32)
    if phase == 32:
        if rd_wire_result(r, w) == 0:
            return 0
        return rd_request(w, P_SHA256, 33, 2, rd_get(w, R_REPLY_AT),
            rd_get(w, R_REPLY_SIZE), 0, rd_get(w, R_REPLY_LEASE), 0)
    if phase == 33:
        if rd_get(w, R_PEER) != P_SHA256 or rd_get(w, R_REPLY_SIZE) != 32:
            return rd_badset(w, 302)
        if rd_get(w, RD_RESPONSE + 48) != 32:
            return rd_badset(w, 303)
        if rd_cursor_digest(r, w) == 0:
            return 0
        if rd_build_cursor_insert(g, w) == 0:
            return 0
        return rd_request(w, P_CURSOR_INSERT, 34, 3, RD_GRAPH_BASE,
            rd_get(w, R_GRAPH_BYTES), 1, rd_get(w, R_OUT_LEASE), OP_CURSOR_INSERT)
    if phase == 34:
        if rd_get(w, R_PEER) != P_CURSOR_INSERT:
            return rd_badset(w, 304)
        rd_put(w, R_HAVE_REPLY, 0)
        rd_put(w, R_PHASE, 40)
        return 0
    if phase == 40:
        if rd_build_result(g, w) == 0:
            return 0
        rd_put(w, R_STATUS, 3)
        return 0
    return rd_badset(w, 305)

def rd_cursor_row(g:readbuf, r:readbuf, w:mutbuf) -> u64:
    if rd_get(w, R_PEER) != P_CURSOR_SELECT:
        return rd_badset(w, 306)
    if rd_get(w, R_REPLY_AT) != 0 or rd_get(w, R_REPLY_SIZE) != length(r):
        return rd_badset(w, 307)
    if rd_graph_valid(r, w, rd_get(w, R_REPLY_LEASE)) == 0:
        return 0
    root = rd_word(r, 24)
    at = rd_node(r, w, root)
    if at == 0:
        return 0
    kind = rd_word(r, at)
    if kind == 0:
        return rd_error(w, 1, 20)
    if (kind != 5 and kind != 7) or rd_word(r, at + 32) != 4:
        return rd_badset(w, 308)
    # The high-level row peer must have materialized every SQLite column
    # before it issues this complete row Graph. No TEXT-affinity coercion.
    i = 0
    while i < 4:
        id = rd_edge(r, w, at, i)
        if rd_node(r, w, id) == 0:
            return 0
        i = i + 1
    left = rd_edge(r, w, at, 1)
    if rd_string_equal(g, r, w, rd_get(w, R_REF_ID), left) == 0:
        if rd_get(w, R_BAD_REASON) != 0:
            return 0
        return rd_error(w, 1, 20)
    left = rd_edge(r, w, at, 2)
    if rd_string_equal(g, r, w, rd_get(w, R_REF_SHA), left) == 0:
        if rd_get(w, R_BAD_REASON) != 0:
            return 0
        return rd_error(w, 1, 20)
    offset = rd_node(r, w, rd_edge(r, w, at, 3))
    if offset == 0:
        return 0
    kind = rd_word(r, offset)
    rd_put(w, R_OFFSET_KIND, kind)
    if kind == 2:
        size = rd_word(r, offset + 16)
        sign = rd_word(r, offset + 48)
        if size > 8:
            return rd_badset(w, 309)
        magnitude = 0
        i = 0
        while i < size:
            magnitude = magnitude | (byte(r, rd_word(r, offset + 8) + i) << (i * 8))
            i = i + 1
        if sign == 0:
            if magnitude > 9223372036854775807:
                return rd_badset(w, 310)
        elif magnitude > 9223372036854775808:
            return rd_badset(w, 311)
        rd_put(w, R_OFFSET_SIGN, sign)
        rd_put(w, R_OFFSET_MAG, magnitude)
    elif kind != 0 and kind != 3 and kind != 4 and kind != 9:
        return rd_badset(w, 312)
    return 1

def rd_wire_start(w:mutbuf, phase:u64) -> u64:
    if rd_get(w, R_SEQ) == RD_MAX:
        return rd_badset(w, 313)
    rd_put(w, RD_WIRE, RD_WIRE_COMMAND)
    rd_put(w, RD_WIRE + 8, rd_get(w, R_OUT_LEASE))
    rd_put(w, RD_WIRE + 16, rd_get(w, R_SEQ) + 1)
    rd_put(w, RD_WIRE + 24, 1)
    rd_put(w, RD_WIRE + 32, 8388608)
    rd_put(w, RD_WIRE + 40, 2)
    rd_put(w, RD_WIRE + 48, rd_get(w, R_DIGITS))
    rd_put(w, RD_WIRE + 56, 0)
    rd_request(w, P_WIRE, phase, 3, RD_GRAPH_BASE, rd_get(w, R_GRAPH_BYTES),
        1, rd_get(w, R_OUT_LEASE), 0)
    rd_put(w, R_REQUEST_CONFIG_AT, RD_WIRE)
    rd_put(w, R_REQUEST_CONFIG_BYTES, 64)
    return 0

def rd_wire_result(r:readbuf, w:mutbuf) -> u64:
    if rd_get(w, R_PEER) != P_WIRE or length(r) < 128:
        return rd_badset(w, 314)
    if rd_get(w, RD_RESPONSE + 48) != 128 or rd_word(r, 0) != RD_WIRE_EVENT:
        return rd_badset(w, 315)
    if rd_word(r, 8) != 0:
        return rd_badset(w, 316)
    i = 16
    while i < 64:
        if rd_word(r, i) != rd_get(w, RD_WIRE + i - 8):
            return rd_badset(w, 317)
        i = i + 8
    if rd_word(r, 64) != 0 or rd_word(r, 72) != 0 or rd_word(r, 104) != 0 or rd_word(r, 120) != 0:
        return rd_badset(w, 318)
    begin = rd_word(r, 88)
    size = rd_word(r, 96)
    if begin > length(r) or size == 0 or size > length(r) - begin:
        return rd_badset(w, 319)
    if size > 8388608 or begin != rd_get(w, R_REPLY_AT) or size != rd_get(w, R_REPLY_SIZE):
        return rd_badset(w, 320)
    if rd_word(r, 24) != rd_get(w, R_PENDING):
        return rd_badset(w, 321)
    return 1

def rd_cursor_digest(r:readbuf, w:mutbuf) -> u64:
    store(w, RD_CURSOR, 112)
    store(w, RD_CURSOR + 1, 97)
    store(w, RD_CURSOR + 2, 103)
    store(w, RD_CURSOR + 3, 101)
    store(w, RD_CURSOR + 4, 45)
    i = 0
    while i < 32:
        value = byte(r, rd_get(w, R_REPLY_AT) + i)
        store(w, RD_CURSOR + 5 + i * 2, rd_hex_digit(value >> 4))
        store(w, RD_CURSOR + 6 + i * 2, rd_hex_digit(value & 15))
        i = i + 1
    return 1

def rd_hex_digit(value:u64) -> u64:
    if value < 10:
        return value + 48
    return value + 87
'''
