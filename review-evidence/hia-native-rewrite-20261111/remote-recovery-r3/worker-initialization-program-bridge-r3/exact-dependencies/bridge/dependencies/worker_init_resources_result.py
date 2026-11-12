"""Actual metadata and registry results for resource peer, NEW revision 2.

No metadata value or successful import is synthesized by the mechanical caller.
All returned bytes remain privately issued immutable views, not public tokens.
"""
BODY=r'''
def rs_import_command(w:mutbuf) -> u32:
    fill_range(w, RS_REG_COMMAND, 128, 0)
    iv_put(w, RS_REG_COMMAND, RS_REG_MAGIC)
    iv_put(w, RS_REG_COMMAND + 8, 3)
    iv_put(w, RS_REG_COMMAND + 16, iv_get(w, R_INV))
    iv_put(w, RS_REG_COMMAND + 24, iv_get(w, R_CALL))
    iv_put(w, RS_REG_COMMAND + 32, iv_get(w, R_REG_ACTIVE))
    iv_put(w, RS_REG_COMMAND + 40, iv_get(w, R_REG_SEQUENCE))
    iv_put(w, RS_REG_COMMAND + 48, iv_get(w, R_GRAPH_LEASE))
    iv_put(w, RS_REG_COMMAND + 56, iv_get(w, R_GRAPH_BYTES))
    iv_put(w, RS_REG_COMMAND + 64, iv_get(w, R_PACKET_BYTES))
    iv_put(w, RS_REG_COMMAND + 96, iv_get(w, R_ORIGIN))
    iv_put(w, RS_REG_COMMAND + 104, iv_get(w, R_PACKET_BYTES))
    iv_put(w, R_PHASE, 30)
    return rs_event(w, 4)

def rs_reserved(r:readbuf, w:mutbuf) -> u32:
    if iv_get(w, R_PHASE) != 10 or length(r) != 384:
        return rs_fail(w, 760)
    if iv_word(r, 72) != 768 or iv_word(r, 80) != 1 or iv_word(r, 88) != 256:
        return rs_fail(w, 761)
    foreign = iv_word(r, 128 + 72)
    output = iv_word(r, 128 + 80)
    if foreign <= iv_get(w, R_GRAPH_LEASE) or foreign == IV_MAX or output != foreign + 1:
        return rs_fail(w, 762)
    index = 0
    while index < 32:
        expected = 0
        if index == 0:
            expected = RS_REG_EVENT
        elif index == 1:
            expected = 2
        elif index == 2:
            expected = iv_get(w, R_INV)
        elif index == 3:
            expected = iv_get(w, R_CALL)
        elif index == 4:
            expected = iv_get(w, R_REG_SEQUENCE) + 1
        elif index == 5:
            expected = iv_get(w, R_REG_ACTIVE)
        elif index == 6:
            expected = iv_get(w, R_GRAPH_LEASE)
        elif index == 7:
            expected = iv_get(w, R_GRAPH_BYTES)
        elif index == 9:
            expected = foreign
        elif index == 10:
            expected = output
        elif index == 24:
            expected = iv_get(w, R_ISSUED)
        elif index == 25:
            expected = iv_get(w, R_ORIGIN)
        elif index == 26:
            expected = iv_get(w, R_OLD_NODES)
        elif index == 29:
            expected = iv_get(w, R_REG_PREVIOUS)
        elif index == 30:
            expected = 10
        if iv_word(r, 128 + index * 8) != expected:
            return rs_fail(w, 763)
        index = index + 1
    iv_put(w, R_FOREIGN, foreign)
    iv_put(w, R_OUTPUT, output)
    iv_put(w, R_REG_SEQUENCE, iv_word(r, 160))
    iv_put(w, iv_get(w, R_PACKET_AT) + 8, foreign)
    if iv_get(w, R_OPERATION) != 1:
        return rs_import_command(w)
    fill_range(w, RS_META_COMMAND, 96, 0)
    iv_put(w, RS_META_COMMAND, RS_META_MAGIC)
    iv_put(w, RS_META_COMMAND + 8, 1)
    iv_put(w, RS_META_COMMAND + 16, iv_get(w, R_LEASE))
    iv_put(w, RS_META_COMMAND + 24, iv_get(w, R_PENDING))
    iv_put(w, RS_META_COMMAND + 32, 3)
    iv_put(w, R_META_NEED, 3072)
    iv_put(w, R_META_STARTED, 0)
    iv_put(w, R_PHASE, 20)
    return rs_event(w, 3)

def rs_metadata_header(r:readbuf, w:mutbuf) -> u64:
    extent = length(r) - 128
    if iv_word(r, 80) != 2 or iv_word(r, 88) != extent or extent < iv_get(w, R_META_NEED):
        return iv_bad(w, 764)
    if extent < 3072 or iv_word(r, 128 + 2048) != RS_META_STATE:
        return iv_bad(w, 765)
    if iv_word(r, 128 + 2064) != iv_get(w, R_LEASE) or iv_word(r, 128 + 2072) != iv_get(w, R_PENDING):
        return iv_bad(w, 766)
    if iv_word(r, 128 + 2080) != 3 or iv_word(r, 128 + 2088) != 0:
        return iv_bad(w, 767)
    if iv_word(r, 128 + 2096) != 0 or iv_word(r, 128 + 2104) != 8:
        return iv_bad(w, 768)
    index = 0
    while index < 96:
        if byte(r, 128 + 2560 + index) != byte(w, RS_META_COMMAND + index):
            return iv_bad(w, 769)
        index = index + 1
    event = 128 + 2304
    action = iv_word(r, event + 8)
    if action > 1:
        return iv_bad(w, 770)
    if action == 1:
        if iv_word(r, 72) != RS_GROW or extent >= RS_META_REQUIRED or iv_word(r, 128 + 2056) != 1:
            return iv_bad(w, 771)
    else:
        if iv_word(r, 72) != 128 or extent < RS_META_REQUIRED or iv_word(r, 128 + 2056) != 2:
            return iv_bad(w, 772)
    index = 0
    while index < 16:
        expected = 0
        if index == 0:
            expected = RS_META_EVENT
        elif index == 1:
            expected = action
        elif index == 2:
            expected = iv_get(w, R_LEASE)
        elif index == 3:
            expected = iv_get(w, R_PENDING)
        elif index == 4:
            expected = 3
        elif index == 5 and action == 0:
            expected = RS_META_OUTPUT
        elif index == 6 and action == 0:
            expected = RS_CANON_BYTES
        elif index == 7 and action == 1:
            expected = RS_META_REQUIRED
        if iv_word(r, event + index * 8) != expected:
            return iv_bad(w, 773)
        index = index + 1
    return 1

def rs_metadata(r:readbuf, w:mutbuf) -> u32:
    if iv_get(w, R_PHASE) != 20 or iv_get(w, R_OPERATION) != 1:
        return rs_fail(w, 774)
    if rs_metadata_header(r, w) == 0:
        return rs_fail(w, 775)
    iv_put(w, R_META_STARTED, 1)
    if iv_word(r, 128 + 2304 + 8) == 1:
        iv_put(w, R_META_NEED, RS_META_REQUIRED)
        return rs_event(w, 3)
    extent = length(r) - 128
    if RS_META_OUTPUT > extent or RS_CANON_BYTES > extent - RS_META_OUTPUT:
        return rs_fail(w, 776)
    index = 0
    while index < RS_CANON_BYTES:
        actual = byte(r, 128 + RS_META_OUTPUT + index)
        if index >= RS_CANON_DIGEST and index < RS_CANON_DIGEST + 64:
            if (actual < 48 or actual > 57) and (actual < 97 or actual > 102):
                return rs_fail(w, 777)
        elif actual != byte(w, RS_POOL + RS_CANON_AT + index):
            return rs_fail(w, 778)
        index = index + 1
    copy_bytes(w, r, iv_get(w, R_PACKET_AT) + RS_GRAPH_DIGEST,
        128 + RS_META_OUTPUT + RS_CANON_DIGEST, 64)
    return rs_import_command(w)

def rs_plan(w:mutbuf) -> u64:
    oldn = iv_get(w, R_OLD_NODES)
    olde = iv_get(w, R_OLD_EDGES)
    oldp = iv_get(w, R_OLD_POOL)
    at = iv_get(w, R_PACKET_AT)
    n = iv_get(w, at + 16)
    e = iv_get(w, at + 32)
    p = iv_get(w, at + 40)
    if oldn >= IV_MAX - n or olde > IV_MAX - 2 or e > IV_MAX - 2 - olde:
        return iv_bad(w, 779)
    n = oldn + n + 1
    e = olde + e + 2
    if n > (IV_MAX - 64) >> 6:
        return iv_bad(w, 780)
    size = 64 + n * 64
    if e > (IV_MAX - size) >> 3:
        return iv_bad(w, 781)
    size = size + e * 8
    if oldp > IV_MAX - p or oldp + p > IV_MAX - size:
        return iv_bad(w, 782)
    p = oldp + p
    size = size + p
    if size > IV_MAX - 512:
        return iv_bad(w, 783)
    iv_put(w, R_NEW_NODES, n)
    iv_put(w, R_NEW_EDGES, e)
    iv_put(w, R_NEW_POOL, p)
    iv_put(w, R_NEW_BYTES, size)
    return 1

def rs_bound_header(s:readbuf, r:readbuf, w:mutbuf) -> u64:
    if iv_word(r, 72) != 768 or iv_word(r, 80) != 1 or iv_word(r, 88) != 256 or length(r) != 384:
        return iv_bad(w, 784)
    if rs_plan(w) == 0:
        return 0
    if iv_get(w, R_REG_SEQUENCE) > IV_MAX - 2:
        return iv_bad(w, 785)
    sequence = iv_word(r, 160)
    if sequence < iv_get(w, R_REG_SEQUENCE) + 2:
        return iv_bad(w, 786)
    child = iv_word(r, 128 + 88)
    if child == 0:
        return iv_bad(w, 787)
    index = 0
    while index < 32:
        expected = 0
        if index == 0:
            expected = RS_REG_EVENT
        elif index == 1:
            expected = 6
        elif index == 2:
            expected = iv_get(w, R_INV)
        elif index == 3:
            expected = iv_get(w, R_CALL)
        elif index == 4:
            expected = sequence
        elif index == 5 or index == 29:
            expected = iv_get(w, R_REG_ACTIVE)
        elif index == 6 or index == 10:
            expected = iv_get(w, R_OUTPUT)
        elif index == 7 or index == 19:
            expected = iv_get(w, R_NEW_BYTES)
        elif index == 9:
            expected = iv_get(w, R_FOREIGN)
        elif index == 11:
            expected = child
        elif index == 12:
            expected = 512 + iv_get(w, R_NEW_BYTES)
        elif index == 17:
            expected = 3
        elif index == 18:
            expected = 640 + iv_get(w, R_PACKET_BYTES)
        elif index == 20:
            expected = iv_get(w, R_OLD_NODES) + 1 + iv_get(w, iv_get(w, R_PACKET_AT) + 24)
        elif index == 21:
            expected = RS_HANDLE + iv_get(w, R_ISSUED) + 1
        elif index == 24:
            expected = iv_get(w, R_ISSUED) + 1
        elif index == 25:
            expected = iv_get(w, R_ORIGIN)
        elif index == 26:
            expected = iv_get(w, R_NEW_NODES)
        if iv_word(r, 128 + index * 8) != expected:
            return iv_bad(w, 788)
        index = index + 1
    if length(s) != iv_get(w, R_NEW_BYTES) or iv_word(s, 8) != iv_get(w, R_OUTPUT):
        return iv_bad(w, 789)
    if iv_shape(s, w, 0, length(s), iv_get(w, R_OUTPUT)) == 0:
        return 0
    if iv_word(s, 16) != iv_get(w, R_NEW_NODES) or iv_word(s, 24) != 1:
        return iv_bad(w, 790)
    if iv_word(s, 32) != iv_get(w, R_NEW_EDGES) or iv_word(s, 40) != iv_get(w, R_NEW_POOL):
        return iv_bad(w, 791)
    return 1

def rs_bound_node(s:readbuf, w:mutbuf, identifier:u64) -> u64:
    at = iv_get(w, R_PACKET_AT)
    delta = iv_get(w, R_OLD_NODES) + 1
    edge_delta = iv_get(w, R_OLD_EDGES) + 2
    olddata = 64 + iv_get(w, at + 16) * 64 + iv_get(w, at + 32) * 8
    newdata = 64 + iv_get(w, R_NEW_NODES) * 64 + iv_get(w, R_NEW_EDGES) * 8
    kind = iv_get(w, at + identifier * 64)
    field = 0
    while field < 8:
        expected = iv_get(w, at + identifier * 64 + field * 8)
        if field == 1 and (kind == 2 or kind == 3 or kind == 4 or kind == 9):
            expected = newdata + iv_get(w, R_OLD_POOL) + expected - olddata
        elif field == 3 and (kind == 5 or kind == 6 or kind == 7):
            expected = expected + edge_delta
        elif field == 5 and (kind == 5 or kind == 6 or kind == 7):
            expected = expected + delta
        if iv_word(s, (identifier + delta) * 64 + field * 8) != expected:
            return iv_bad(w, 792)
        field = field + 1
    return 1

def rs_bound_bytes(s:readbuf, w:mutbuf) -> u64:
    at = iv_get(w, R_PACKET_AT)
    n = iv_get(w, at + 16)
    e = iv_get(w, at + 32)
    p = iv_get(w, at + 40)
    identifier = 1
    while identifier <= n:
        if rs_bound_node(s, w, identifier) == 0:
            return 0
        identifier = identifier + 1
    source_edges = at + 64 + n * 64
    target_edges = 64 + iv_get(w, R_NEW_NODES) * 64
    index = 0
    while index < e:
        expected = iv_get(w, source_edges + index * 8) + iv_get(w, R_OLD_NODES) + 1
        where = target_edges + (index + iv_get(w, R_OLD_EDGES) + 2) * 8
        if iv_word(s, where) != expected:
            return iv_bad(w, 793)
        index = index + 1
    target_data = target_edges + iv_get(w, R_NEW_EDGES) * 8 + iv_get(w, R_OLD_POOL)
    source_data = source_edges + e * 8
    index = 0
    while index < p:
        if byte(s, target_data + index) != byte(w, source_data + index):
            return iv_bad(w, 794)
        index = index + 1
    return 1

def rs_bound(s:readbuf, r:readbuf, w:mutbuf) -> u32:
    if iv_get(w, R_PHASE) != 30:
        return rs_fail(w, 795)
    if rs_bound_header(s, r, w) == 0 or rs_bound_bytes(s, w) == 0:
        return rs_fail(w, 796)
    handle = RS_HANDLE + iv_get(w, R_ISSUED) + 1
    iv_put(w, R_HANDLE, handle)
    iv_put(w, R_REG_SEQUENCE, iv_word(r, 160))
    iv_put(w, R_GRAPH_LEASE, iv_get(w, R_OUTPUT))
    iv_put(w, R_GRAPH_BYTES, length(s))
    fill_range(w, RS_REPLY, 256, 0)
    iv_put(w, RS_REPLY, IS_REPLY)
    iv_put(w, RS_REPLY + 8, iv_get(w, R_INV))
    iv_put(w, RS_REPLY + 16, iv_get(w, R_CALL))
    iv_put(w, RS_REPLY + 24, iv_get(w, R_PENDING))
    iv_put(w, RS_REPLY + 32, 12)
    iv_put(w, RS_REPLY + 48, 2)
    iv_put(w, RS_REPLY + 64, handle)
    iv_put(w, RS_REPLY + 120, 256)
    iv_put(w, R_PHASE, 90)
    return rs_event(w, 0)
'''
