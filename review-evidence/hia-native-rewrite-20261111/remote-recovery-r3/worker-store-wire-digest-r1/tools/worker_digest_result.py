"""Actual GraphWire and SHA replies and issued digest result, new source."""
BODY=r'''
def wd_copy_inside(w:mutbuf, target:u64, source:u64, size:u64) -> u64:
    index = 0
    while size - index >= 8:
        iv_put(w, target + index, iv_get(w, source + index))
        index = index + 8
    while index < size:
        store(w, target + index, byte(w, source + index))
        index = index + 1
    return 1

def wd_wire_check(r:readbuf, w:mutbuf) -> u64:
    size = iv_word(r, 88)
    if iv_word(r, 72) != 128 or iv_word(r, 80) != iv_get(w, D_ROLE):
        return iv_bad(w, 660)
    if size != length(r) - 128 or size < 32768 or size < iv_get(w, D_PEER_NEED):
        return iv_bad(w, 661)
    base = 128
    if iv_word(r, base) != WD_WIRE_EVENT or iv_word(r, base + 120) != 0:
        return iv_bad(w, 662)
    index = 16
    while index < 64:
        if iv_word(r, base + index) != iv_get(w, WD_CONFIG + index - 8):
            return iv_bad(w, 663)
        index = index + 8
    if iv_word(r, base + 256) != WD_WIRE_STATE or iv_word(r, base + 280) != 0:
        return iv_bad(w, 664)
    if iv_word(r, base + 112) != iv_word(r, base + 264):
        return iv_bad(w, 665)
    if iv_word(r, base + 64) != iv_word(r, base + 272) or iv_word(r, base + 72) != iv_word(r, base + 560):
        return iv_bad(w, 666)
    if iv_word(r, base + 80) != iv_word(r, base + 288):
        return iv_bad(w, 667)
    index = 0
    while index < 6:
        if iv_word(r, base + 16 + index * 8) != iv_word(r, base + 296 + index * 8):
            return iv_bad(w, 668)
        index = index + 1
    if iv_word(r, base + 344) != iv_get(w, D_SOURCE_NODES):
        return iv_bad(w, 669)
    if iv_word(r, base + 368) != iv_get(w, D_SOURCE_BYTES):
        return iv_bad(w, 670)
    action = iv_word(r, base + 8)
    if action > 3:
        return iv_bad(w, 671)
    if action != 0:
        if iv_word(r, base + 88) != 0 or iv_word(r, base + 96) != 0:
            return iv_bad(w, 672)
    if iv_word(r, base + 104) != choose(action == 2, 2, 0):
        return iv_bad(w, 673)
    if action == 3:
        code = iv_word(r, base + 64)
        if code == 0 or code > 16 or iv_word(r, base + 112) != 99:
            return iv_bad(w, 674)
    elif iv_word(r, base + 64) != 0 or iv_word(r, base + 72) != 0:
        return iv_bad(w, 675)
    return 1

def wd_reply_base(w:mutbuf) -> u64:
    fill_range(w, WD_REPLY, 1024, 0)
    iv_put(w, WD_REPLY, WD_INIT_REPLY)
    iv_put(w, WD_REPLY + 8, iv_get(w, D_INV))
    iv_put(w, WD_REPLY + 16, iv_get(w, D_CALL))
    iv_put(w, WD_REPLY + 24, iv_get(w, D_INIT_PENDING))
    iv_put(w, WD_REPLY + 32, 8)
    iv_put(w, WD_REPLY + 120, 256)
    iv_put(w, D_REPLY_BYTES, 256)
    return 1

def wd_wire_error(r:readbuf, w:mutbuf) -> u32:
    iv_put(w, D_ERROR, iv_word(r, 192))
    iv_put(w, D_CAUSE, iv_word(r, 200))
    copy_bytes(w, r, WD_WIRE_HEADER, 128, 128)
    wd_reply_base(w)
    text_size = wd_error_literal(w, iv_get(w, D_ERROR))
    if text_size == 0:
        return wd_fail(w, 676)
    iv_put(w, WD_REPLY + 40, 1)
    iv_put(w, WD_REPLY + 96, iv_get(w, D_LEASE))
    iv_put(w, WD_REPLY + 104, 256)
    iv_put(w, WD_REPLY + 112, 64 + text_size)
    iv_put(w, WD_REPLY + 120, 320 + text_size)
    iv_put(w, WD_REPLY + 256, WD_EXCEPTION)
    iv_put(w, WD_REPLY + 264, 1)
    iv_put(w, WD_REPLY + 272, 1)
    iv_put(w, WD_REPLY + 280, iv_get(w, D_ERROR))
    iv_put(w, WD_REPLY + 288, iv_get(w, D_CAUSE))
    iv_put(w, WD_REPLY + 296, text_size)
    iv_put(w, WD_REPLY + 304, 64 + text_size)
    iv_put(w, D_REPLY_BYTES, 320 + text_size)
    iv_put(w, D_PHASE, 90)
    return wd_event(w, 6)

def wd_wire_result(r:readbuf, w:mutbuf) -> u32:
    if wd_wire_check(r, w) == 0:
        return wd_fail(w, 677)
    action = iv_word(r, 136)
    if action == 3:
        return wd_wire_error(r, w)
    if action == 1:
        need = iv_word(r, 208)
        if need <= iv_word(r, 88) or iv_word(r, 240) >= 90:
            return wd_fail(w, 678)
        if wd_next(w, iv_get(w, D_ROLE), need) == 0:
            return wd_fail(w, 679)
        return wd_event(w, 1)
    if action == 2:
        if iv_get(w, D_ROLE) != 1 or iv_word(r, 208) > iv_word(r, 88) or iv_word(r, 240) >= 90:
            return wd_fail(w, 680)
        if wd_next(w, 2, iv_word(r, 88)) == 0:
            return wd_fail(w, 681)
        return wd_event(w, 1)
    if iv_get(w, D_ROLE) != 2:
        return wd_fail(w, 682)
    return wd_wire_copy(r, w, 0)

def wd_wire_copy(r:readbuf, w:mutbuf, continuing:u64) -> u32:
    if wd_wire_check(r, w) == 0 or iv_word(r, 136) != 0:
        return wd_fail(w, 683)
    at = iv_word(r, 216)
    size = iv_word(r, 224)
    whole = iv_word(r, 88)
    if at < 32768 or at > whole or size == 0 or size > whole - at or size > 8388608:
        return wd_fail(w, 684)
    if iv_word(r, 208) > whole or iv_word(r, 128 + 536) != at or iv_word(r, 128 + 528) != size:
        return wd_fail(w, 685)
    if continuing == 0:
        iv_put(w, D_WIRE_BYTES, size)
        iv_put(w, D_WIRE_AT, at)
        iv_put(w, D_WIRE_WHOLE, whole)
        copy_bytes(w, r, WD_WIRE_HEADER, 128, 128)
        iv_put(w, D_PHASE, 20)
        iv_put(w, D_NEED, WD_WIRE + size)
    else:
        if size != iv_get(w, D_WIRE_BYTES) or at != iv_get(w, D_WIRE_AT) or whole != iv_get(w, D_WIRE_WHOLE):
            return wd_fail(w, 686)
        if wd_equal(r, w, 128, WD_WIRE_HEADER, 128) == 0:
            return wd_fail(w, 687)
    if length(w) < iv_get(w, D_NEED):
        return wd_event(w, 2)
    copy_bytes(w, r, WD_WIRE, 128 + at, size)
    iv_put(w, D_NEED, 0)
    iv_put(w, D_CURSOR, 0)
    iv_put(w, D_CHUNK, 0)
    iv_put(w, D_PHASE, 30)
    store(w, WD_SHA_INPUT, 0)
    if wd_next(w, 3, 1184) == 0:
        return wd_fail(w, 688)
    return wd_event(w, 3)

def wd_sha_next(w:mutbuf) -> u32:
    cursor = iv_get(w, D_CURSOR)
    count = iv_get(w, D_WIRE_BYTES) - cursor
    if count != 0:
        if count > 65536:
            count = 65536
        iv_put(w, D_CHUNK, count)
        iv_put(w, D_PHASE, 31)
        store(w, WD_SHA_INPUT, 1)
        wd_copy_inside(w, WD_SHA_INPUT + 1, WD_WIRE + cursor, count)
    else:
        iv_put(w, D_CHUNK, 0)
        iv_put(w, D_PHASE, 32)
        store(w, WD_SHA_INPUT, 2)
    if wd_next(w, 3, 1184) == 0:
        return wd_fail(w, 689)
    return wd_event(w, 3)

def wd_hex(value:u64) -> u64:
    if value < 10:
        return value + 48
    return value + 87

def wd_digest_graph(r:readbuf, w:mutbuf) -> u32:
    copy_bytes(w, r, WD_DIGEST, 128, 32)
    fill_range(w, WD_GRAPH, 192, 0)
    iv_put(w, WD_GRAPH, IV_GRAPH)
    iv_put(w, WD_GRAPH + 8, iv_get(w, D_FOREIGN))
    iv_put(w, WD_GRAPH + 16, 1)
    iv_put(w, WD_GRAPH + 24, 1)
    iv_put(w, WD_GRAPH + 40, 64)
    iv_put(w, WD_GRAPH + 48, 192)
    iv_put(w, WD_GRAPH + 64, 4)
    iv_put(w, WD_GRAPH + 72, 128)
    iv_put(w, WD_GRAPH + 80, 64)
    iv_put(w, WD_GRAPH + 112, 64)
    index = 0
    while index < 32:
        value = byte(w, WD_DIGEST + index)
        store(w, WD_GRAPH + 128 + index * 2, wd_hex(value >> 4))
        store(w, WD_GRAPH + 129 + index * 2, wd_hex(value & 15))
        index = index + 1
    iv_put(w, D_PHASE, 50)
    return wd_event(w, 4)

def wd_sha_result(r:readbuf, w:mutbuf) -> u32:
    if length(r) != 1344 or iv_word(r, 80) != 3 or iv_word(r, 88) != 1184:
        return wd_fail(w, 690)
    phase = iv_get(w, D_PHASE)
    if iv_word(r, 72) != choose(phase == 32, 32, 0):
        return wd_fail(w, 691)
    base = 160
    if iv_word(r, base + 1176) != WD_SHA_STATE or iv_word(r, base + 1104) != choose(phase == 32, 2, 1):
        return wd_fail(w, 692)
    total = iv_get(w, D_CURSOR)
    if phase == 31:
        total = total + iv_get(w, D_CHUNK)
    if iv_word(r, base + 1088) != total or iv_word(r, base + 1096) != (total & 63):
        return wd_fail(w, 693)
    if phase == 30:
        if total != 0 or iv_get(w, D_CHUNK) != 0:
            return wd_fail(w, 694)
        copy_bytes(w, r, WD_SHA_PREFIX, base, 512)
    else:
        if wd_equal(r, w, base, WD_SHA_PREFIX, 512) == 0:
            return wd_fail(w, 695)
    if phase == 32:
        if total != iv_get(w, D_WIRE_BYTES):
            return wd_fail(w, 696)
        index = 0
        while index < 8:
            value = iv_word(r, base + 1024 + index * 8)
            if value > 4294967295:
                return wd_fail(w, 697)
            part = 0
            while part < 4:
                if byte(r, 128 + index * 4 + part) != ((value >> ((3 - part) * 8)) & 255):
                    return wd_fail(w, 698)
                part = part + 1
            index = index + 1
        return wd_digest_graph(r, w)
    iv_put(w, D_CURSOR, total)
    return wd_sha_next(w)

def wd_bind(s:readbuf, r:readbuf, w:mutbuf) -> u32:
    if length(r) != 384 or iv_word(r, 72) != 768 or iv_word(r, 80) != 4 or iv_word(r, 88) != 256:
        return wd_fail(w, 699)
    if iv_word(s, 8) != iv_get(w, D_OUTPUT) or iv_shape(s, w, 0, length(s), iv_get(w, D_OUTPUT)) == 0:
        return wd_fail(w, 700)
    at = 128
    if iv_word(r, at) != WD_REG_EVENT or iv_word(r, at + 8) != 6:
        return wd_fail(w, 701)
    if iv_word(r, at + 16) != iv_get(w, D_INV) or iv_word(r, at + 24) != iv_get(w, D_CALL):
        return wd_fail(w, 702)
    if iv_word(r, at + 32) <= iv_get(w, D_REG_SEQ) or iv_word(r, at + 40) != iv_get(w, D_REG_COMMAND):
        return wd_fail(w, 703)
    if iv_word(r, at + 48) != iv_get(w, D_OUTPUT) or iv_word(r, at + 56) != length(s):
        return wd_fail(w, 704)
    if iv_word(r, at + 64) != 0 or iv_word(r, at + 72) != iv_get(w, D_FOREIGN) or iv_word(r, at + 80) != iv_get(w, D_OUTPUT):
        return wd_fail(w, 705)
    if iv_word(r, at + 88) == 0 or iv_word(r, at + 96) != 512 + length(s):
        return wd_fail(w, 717)
    index = 104
    while index < 136:
        if iv_word(r, at + index) != 0:
            return wd_fail(w, 706)
        index = index + 8
    if iv_word(r, at + 136) != 3 or iv_word(r, at + 144) != 832 or iv_word(r, at + 152) != length(s):
        return wd_fail(w, 707)
    root = iv_get(w, D_SOURCE_NODES) + 2
    handle = WD_HANDLE + iv_get(w, D_ISSUED) + 1
    if iv_word(r, at + 160) != root or iv_word(r, at + 168) != handle:
        return wd_fail(w, 708)
    if iv_word(r, at + 176) != 0 or iv_word(r, at + 184) != 0:
        return wd_fail(w, 709)
    if iv_word(r, at + 192) != iv_get(w, D_ISSUED) + 1 or iv_word(r, at + 200) != iv_get(w, D_ORIGIN):
        return wd_fail(w, 710)
    if iv_word(r, at + 208) != root or iv_word(r, at + 216) != 0 or iv_word(r, at + 224) != 0:
        return wd_fail(w, 711)
    if iv_word(r, at + 232) != iv_get(w, D_REG_COMMAND) or iv_word(r, at + 240) != 0 or iv_word(r, at + 248) != 0:
        return wd_fail(w, 712)
    if iv_word(s, 16) != root or iv_word(s, 24) != 1 or iv_word(s, 32) != iv_get(w, WD_SOURCE_HEADER + 32) + 2:
        return wd_fail(w, 713)
    if iv_word(s, 40) != iv_get(w, WD_SOURCE_HEADER + 40) + 64:
        return wd_fail(w, 714)
    node = root * 64
    if iv_word(s, node) != 4 or iv_word(s, node + 16) != 64:
        return wd_fail(w, 715)
    if wd_equal(s, w, iv_word(s, node + 8), WD_GRAPH + 128, 64) == 0:
        return wd_fail(w, 716)
    iv_put(w, D_REG_SEQ, iv_word(r, at + 32))
    iv_put(w, D_BOUND_HANDLE, handle)
    wd_reply_base(w)
    iv_put(w, WD_REPLY + 48, 7)
    iv_put(w, WD_REPLY + 64, handle)
    wd_copy_inside(w, WD_REPLY + 128, WD_DIGEST, 32)
    iv_put(w, D_PHASE, 90)
    return wd_event(w, 5)
'''
