"""Worker Store.json/profile result ownership, NEW UNEXECUTED source.

The namespace response is a new pending private interface, not an implemented
physical Store. All value projection, wire requests and fixed SQL binding are
native. The fixed issuer must supply actual immutable peer replies.
"""
BODY=r'''
def sv_copy(w:mutbuf, target:u64, source:u64, size:u64) -> u64:
    index = 0
    while size - index >= 8:
        iv_put(w, target + index, iv_get(w, source + index))
        index = index + 8
    while index < size:
        store(w, target + index, byte(w, source + index))
        index = index + 1
    return 1

def sv_namespace_request(w:mutbuf, operation:u64) -> u64:
    fill_range(w, SV_NS_REQUEST, 128, 0)
    iv_put(w, SV_NS_REQUEST, SV_NS_COMMAND)
    iv_put(w, SV_NS_REQUEST + 8, operation)
    iv_put(w, SV_NS_REQUEST + 16, iv_get(w, S_INV))
    iv_put(w, SV_NS_REQUEST + 24, iv_get(w, S_CALL))
    iv_put(w, SV_NS_REQUEST + 32, iv_get(w, S_STORE))
    iv_put(w, SV_NS_REQUEST + 40, iv_get(w, S_LEASE))
    iv_put(w, SV_NS_REQUEST + 48, iv_get(w, S_ACTION))
    if operation == 1:
        iv_put(w, SV_NS_REQUEST + 56, 2)
        iv_put(w, SV_NS_REQUEST + 64, choose(iv_get(w, S_PEER) == 11, SV_PROFILE_KIND, SV_NAME))
        iv_put(w, SV_NS_REQUEST + 72, choose(iv_get(w, S_PEER) == 11, 7, iv_get(w, S_NAME_BYTES)))
        iv_put(w, SV_NS_REQUEST + 80, SV_WIRE)
        iv_put(w, SV_NS_REQUEST + 88, iv_get(w, S_WIRE_BYTES))
    else:
        iv_put(w, SV_NS_REQUEST + 96, iv_get(w, S_GRAPH_AT))
        iv_put(w, SV_NS_REQUEST + 104, iv_get(w, S_GRAPH_BYTES))
        iv_put(w, SV_NS_REQUEST + 112, 6)
        iv_put(w, SV_NS_REQUEST + 120, SV_PROFILE_INSERT)
    return 1

def sv_namespace_header(r:readbuf, w:mutbuf) -> u64:
    if length(r) < 384 or iv_word(r, 72) != 256 or iv_word(r, 80) != iv_get(w, S_ROLE):
        return iv_bad(w, 900)
    if iv_word(r, 88) != length(r) - 128 or iv_word(r, 96) != 0 or iv_word(r, 104) != 0:
        return iv_bad(w, 901)
    operation = choose(iv_get(w, S_ROLE) == 3, 1, 2)
    if iv_get(w, S_ROLE) != 3 and iv_get(w, S_ROLE) != 4:
        return iv_bad(w, 902)
    if iv_word(r, 128) != SV_NS_REPLY or iv_word(r, 136) != operation:
        return iv_bad(w, 903)
    if iv_word(r, 144) != iv_get(w, S_INV) or iv_word(r, 152) != iv_get(w, S_CALL):
        return iv_bad(w, 904)
    if iv_word(r, 160) != iv_get(w, S_STORE) or iv_word(r, 168) != iv_get(w, S_LEASE) or iv_word(r, 176) != iv_get(w, S_ACTION):
        return iv_bad(w, 905)
    if iv_word(r, 184) > 1 or iv_word(r, 232) == 0 or iv_word(r, 240) == 0 or iv_word(r, 248) != length(r) - 128:
        return iv_bad(w, 906)
    if sv_equal(r, w, 256, SV_NS_REQUEST, 128) == 0:
        return iv_bad(w, 907)
    if iv_word(r, 184) == 1:
        if iv_word(r, 192) != 0 or iv_word(r, 200) != 0 or iv_word(r, 208) != 0:
            return iv_bad(w, 908)
        if iv_word(r, 216) == 0 or iv_word(r, 224) != length(r) - 384:
            return iv_bad(w, 909)
    elif iv_word(r, 216) != 0 or iv_word(r, 224) != 0:
        return iv_bad(w, 910)
    return 1

def sv_namespace_error(r:readbuf, w:mutbuf, continuing:u64) -> u32:
    if sv_namespace_header(r, w) == 0 or iv_word(r, 184) != 1:
        return sv_fail(w, 911)
    size = iv_word(r, 224)
    if size > IV_MAX - SV_MIN - 256:
        return sv_fail(w, 912)
    if continuing == 0:
        copy_bytes(w, r, SV_NS_HEADER, 128, 256)
        iv_put(w, S_ERROR_BYTES, size)
        iv_put(w, S_ERROR_LEASE, iv_word(r, 216))
        iv_put(w, S_NEED, SV_MIN + 256 + size)
        iv_put(w, S_PHASE, 80)
    elif size != iv_get(w, S_ERROR_BYTES) or sv_equal(r, w, 128, SV_NS_HEADER, 256) == 0:
        return sv_fail(w, 913)
    if length(w) < iv_get(w, S_NEED):
        return sv_event(w, 2)
    fill_range(w, SV_MIN, 256, 0)
    iv_put(w, SV_MIN, SV_INIT_REPLY)
    iv_put(w, SV_MIN + 8, iv_get(w, S_INV))
    iv_put(w, SV_MIN + 16, iv_get(w, S_CALL))
    iv_put(w, SV_MIN + 24, iv_get(w, S_PENDING))
    iv_put(w, SV_MIN + 32, iv_get(w, S_PEER))
    iv_put(w, SV_MIN + 40, 1)
    iv_put(w, SV_MIN + 96, iv_get(w, S_ERROR_LEASE))
    iv_put(w, SV_MIN + 104, 256)
    iv_put(w, SV_MIN + 112, size)
    iv_put(w, SV_MIN + 120, 256 + size)
    copy_bytes(w, r, SV_MIN + 256, 384, size)
    iv_put(w, S_REPLY_AT, SV_MIN)
    iv_put(w, S_REPLY_BYTES, 256 + size)
    iv_put(w, S_NEED, 0)
    iv_put(w, S_PHASE, 90)
    return sv_event(w, 5)

def sv_ref_sha(s:readbuf, w:mutbuf) -> u64:
    root = iv_get(w, S_ROOT)
    if iv_word(s, root * 64) != 6:
        return iv_bad(w, 914)
    first = iv_word(s, root * 64 + 24)
    count = iv_word(s, root * 64 + 32)
    edges = 64 + iv_word(s, 16) * 64
    index = 0
    found = 0
    while index < count:
        key = iv_word(s, edges + (first + index * 2) * 8)
        if iv_word(s, key * 64) == 4 and iv_word(s, key * 64 + 16) == 6:
            at = iv_word(s, key * 64 + 8)
            part = 0
            same = 1
            while part < 6:
                if byte(s, at + part) != ((SV_SHA_LITERAL >> (part * 8)) & 255):
                    same = 0
                part = part + 1
            if same != 0:
                if found != 0:
                    return iv_bad(w, 915)
                found = iv_word(s, edges + (first + index * 2 + 1) * 8)
        index = index + 1
    if found == 0:
        return iv_bad(w, 916)
    kind = iv_word(s, found * 64)
    if kind == 5 or kind == 6 or kind == 7 or kind == 8:
        return iv_bad(w, 917)
    iv_put(w, S_SHA_ROOT, found)
    copy_bytes(w, s, SV_SHA_HEADER, found * 64, 64)
    return 1

def sv_registry_request(w:mutbuf, mode:u64) -> u64:
    command = iv_get(w, S_REG_COMMAND)
    if mode == 2:
        if command == IV_MAX or iv_get(w, S_REG_SEQ) == IV_MAX:
            return iv_bad(w, 918)
        command = command + 1
    fill_range(w, SV_REG_COMMAND, 128, 0)
    iv_put(w, SV_REG_COMMAND, SV_REG_COMMAND_MAGIC)
    iv_put(w, SV_REG_COMMAND + 8, mode)
    iv_put(w, SV_REG_COMMAND + 16, iv_get(w, S_INV))
    iv_put(w, SV_REG_COMMAND + 24, iv_get(w, S_CALL))
    iv_put(w, SV_REG_COMMAND + 32, command)
    iv_put(w, SV_REG_COMMAND + 40, iv_get(w, S_REG_SEQ))
    iv_put(w, SV_REG_COMMAND + 48, iv_get(w, S_SOURCE_LEASE))
    iv_put(w, SV_REG_COMMAND + 56, iv_get(w, S_SOURCE_BYTES))
    iv_put(w, SV_REG_COMMAND + 96, iv_get(w, S_ORIGIN))
    if mode == 3:
        iv_put(w, SV_REG_COMMAND + 64, iv_get(w, S_GRAPH_BYTES))
        iv_put(w, SV_REG_COMMAND + 104, iv_get(w, S_GRAPH_BYTES))
    return 1

def sv_namespace_reply(s:readbuf, r:readbuf, w:mutbuf) -> u32:
    if sv_namespace_header(r, w) == 0:
        return sv_fail(w, 919)
    if iv_word(r, 184) != 0:
        if sv_source(s, w) == 0:
            return sv_fail(w, 920)
        return sv_namespace_error(r, w, 0)
    if iv_get(w, S_PHASE) == 40:
        if length(r) != 384 or iv_word(r, 192) != 0 or iv_word(r, 200) != 0 or iv_word(r, 208) != 0:
            return sv_fail(w, 921)
        if sv_source(s, w) == 0 or sv_registry_request(w, 2) == 0:
            return sv_fail(w, 922)
        iv_put(w, S_PHASE, 50)
        if sv_action(w, 5, 256) == 0:
            return sv_fail(w, 923)
        return sv_event(w, 6)
    if length(r) != 704 or iv_word(r, 200) != iv_word(s, 8) or iv_word(r, 208) != length(s):
        return sv_fail(w, 924)
    handle = iv_word(r, 192)
    if handle <= SV_HANDLE:
        return sv_fail(w, 925)
    old_sequence = iv_get(w, S_REG_SEQ)
    old_command = iv_get(w, S_REG_COMMAND)
    old_issued = iv_get(w, S_ISSUED)
    if sv_borrow(s, r, w, 384, handle) == 0:
        return sv_fail(w, 926)
    if iv_get(w, S_REG_SEQ) <= old_sequence or iv_get(w, S_REG_COMMAND) <= old_command or iv_get(w, S_ISSUED) < old_issued:
        return sv_fail(w, 927)
    iv_put(w, S_REF_HANDLE, handle)
    iv_put(w, S_REF_ROOT, iv_get(w, S_ROOT))
    if iv_get(w, S_PEER) == 15:
        return sv_success(w)
    if sv_ref_sha(s, w) == 0:
        return sv_fail(w, 928)
    iv_put(w, S_WIRE_STAGE, 1)
    iv_put(w, S_PHASE, 10)
    if sv_action(w, 1, 32768) == 0:
        return sv_fail(w, 929)
    return sv_event(w, 9)

def sv_profile_size(s:readbuf, w:mutbuf, wire_size:u64) -> u64:
    if sv_equal(s, w, iv_get(w, S_SHA_ROOT) * 64, SV_SHA_HEADER, 64) == 0:
        return iv_bad(w, 930)
    amount = iv_word(s, iv_get(w, S_SHA_ROOT) * 64 + 16)
    if amount > IV_MAX - 568 - 8 - iv_get(w, S_NAME_BYTES) - wire_size:
        return iv_bad(w, 931)
    size = 568 + 8 + iv_get(w, S_NAME_BYTES) + amount + wire_size
    at = (SV_WIRE + wire_size + 7) & (IV_MAX - 7)
    if size > IV_MAX - at:
        return iv_bad(w, 932)
    iv_put(w, S_GRAPH_AT, at)
    iv_put(w, S_GRAPH_BYTES, size)
    iv_put(w, S_GRAPH_LEASE, iv_get(w, S_LEASE))
    iv_put(w, S_NEED, at + size)
    return 1

def sv_graph_node(w:mutbuf, at:u64, identifier:u64, kind:u64, data:u64, count:u64, first:u64, amount:u64, identity:u64, aux:u64) -> u64:
    node = at + identifier * 64
    iv_put(w, node, kind)
    iv_put(w, node + 8, data)
    iv_put(w, node + 16, count)
    iv_put(w, node + 24, first)
    iv_put(w, node + 32, amount)
    iv_put(w, node + 40, identity)
    iv_put(w, node + 48, aux)
    return 1

def sv_profile_graph(s:readbuf, w:mutbuf) -> u64:
    at = iv_get(w, S_GRAPH_AT)
    size = iv_get(w, S_GRAPH_BYTES)
    sha = iv_get(w, S_SHA_ROOT) * 64
    sha_size = iv_word(s, sha + 16)
    name_size = iv_get(w, S_NAME_BYTES)
    wire_size = iv_get(w, S_WIRE_BYTES)
    if at < SV_WIRE + wire_size or at > length(w) or size > length(w) - at:
        return iv_bad(w, 933)
    fill_range(w, at, 568, 0)
    iv_put(w, at, IV_GRAPH)
    iv_put(w, at + 8, iv_get(w, S_GRAPH_LEASE))
    iv_put(w, at + 16, 7)
    iv_put(w, at + 24, 1)
    iv_put(w, at + 32, 7)
    iv_put(w, at + 40, size - 568)
    iv_put(w, at + 48, size)
    sv_graph_node(w, at, 1, 6, 0, 0, 0, 2, 1, 0)
    sv_graph_node(w, at, 2, 4, 568, 2, 0, 0, 0, 2)
    sv_graph_node(w, at, 3, 4, 576, name_size, 0, 0, 0, name_size)
    sv_graph_node(w, at, 4, 4, 570, 6, 0, 0, 0, 6)
    kind = iv_word(s, sha)
    sha_at = choose(kind == 0 or kind == 1, 0, 576 + name_size)
    sv_graph_node(w, at, 5, kind, sha_at, sha_size, 0, 0, 0, iv_word(s, sha + 48))
    sv_graph_node(w, at, 6, 5, 0, 0, 4, 3, 6, 0)
    points = 0
    index = 0
    while index < wire_size:
        if (byte(w, SV_WIRE + index) & 192) != 128:
            points = points + 1
        index = index + 1
    sv_graph_node(w, at, 7, 4, 576 + name_size + sha_size, wire_size, 0, 0, 0, points)
    iv_put(w, at + 512, 2)
    iv_put(w, at + 520, 3)
    iv_put(w, at + 528, 4)
    iv_put(w, at + 536, 5)
    iv_put(w, at + 544, 3)
    iv_put(w, at + 552, 5)
    iv_put(w, at + 560, 7)
    store(w, at + 568, 105)
    store(w, at + 569, 100)
    index = 0
    while index < 6:
        store(w, at + 570 + index, (SV_SHA_LITERAL >> (index * 8)) & 255)
        index = index + 1
    sv_copy(w, at + 576, SV_NAME, name_size)
    if sha_size != 0:
        copy_bytes(w, s, at + 576 + name_size, iv_word(s, sha + 8), sha_size)
    sv_copy(w, at + 576 + name_size + sha_size, SV_WIRE, wire_size)
    return 1

def sv_reserved(s:readbuf, r:readbuf, w:mutbuf) -> u32:
    if length(r) != 384 or iv_word(r, 72) != 768 or iv_word(r, 80) != 5 or iv_word(r, 88) != 256 or iv_word(r, 96) != 0 or iv_word(r, 104) != 0:
        return sv_fail(w, 934)
    at = 128
    if iv_word(r, at) != SV_REG_EVENT or iv_word(r, at + 8) != 2:
        return sv_fail(w, 935)
    if iv_word(r, at + 16) != iv_get(w, S_INV) or iv_word(r, at + 24) != iv_get(w, S_CALL):
        return sv_fail(w, 936)
    if iv_get(w, S_REG_SEQ) == IV_MAX or iv_get(w, S_REG_COMMAND) == IV_MAX:
        return sv_fail(w, 937)
    if iv_word(r, at + 32) != iv_get(w, S_REG_SEQ) + 1 or iv_word(r, at + 40) != iv_get(w, S_REG_COMMAND) + 1:
        return sv_fail(w, 938)
    if iv_word(r, at + 48) != iv_get(w, S_SOURCE_LEASE) or iv_word(r, at + 56) != iv_get(w, S_SOURCE_BYTES):
        return sv_fail(w, 939)
    if iv_word(r, at + 64) != 0 or iv_word(r, at + 88) != 0 or iv_word(r, at + 96) != 0:
        return sv_fail(w, 940)
    index = 104
    while index < 192:
        if iv_word(r, at + index) != 0:
            return sv_fail(w, 941)
        index = index + 8
    if iv_word(r, at + 192) != iv_get(w, S_ISSUED) or iv_word(r, at + 200) != iv_get(w, S_ORIGIN) or iv_word(r, at + 208) != iv_get(w, S_SOURCE_NODES):
        return sv_fail(w, 942)
    if iv_word(r, at + 216) != 0 or iv_word(r, at + 224) != 0 or iv_word(r, at + 232) != iv_get(w, S_REG_COMMAND) or iv_word(r, at + 240) != 10 or iv_word(r, at + 248) != 0:
        return sv_fail(w, 943)
    foreign = iv_word(r, at + 72)
    if foreign <= iv_get(w, S_SOURCE_LEASE) or foreign == IV_MAX or iv_word(r, at + 80) != foreign + 1:
        return sv_fail(w, 944)
    iv_put(w, S_GRAPH_FOREIGN, foreign)
    iv_put(w, S_GRAPH_OUTPUT, foreign + 1)
    iv_put(w, S_GRAPH_LEASE, foreign)
    iv_put(w, iv_get(w, S_GRAPH_AT) + 8, foreign)
    iv_put(w, S_REG_SEQ, iv_word(r, at + 32))
    iv_put(w, S_REG_COMMAND, iv_word(r, at + 40))
    if sv_registry_request(w, 3) == 0 or sv_action(w, 5, 256) == 0:
        return sv_fail(w, 945)
    iv_put(w, S_PHASE, 60)
    return sv_event(w, 7)

def sv_bound_graph(s:readbuf, w:mutbuf) -> u64:
    nodes = iv_get(w, S_SOURCE_NODES)
    edges = iv_get(w, S_SOURCE_EDGES)
    pool = iv_get(w, S_SOURCE_POOL)
    at = iv_get(w, S_GRAPH_AT)
    if nodes > IV_MAX - 8 or edges > IV_MAX - 9 or pool > IV_MAX - iv_get(w, S_GRAPH_BYTES) + 568:
        return iv_bad(w, 946)
    if iv_word(s, 16) != nodes + 8 or iv_word(s, 24) != 1 or iv_word(s, 32) != edges + 9 or iv_word(s, 40) != pool + iv_get(w, S_GRAPH_BYTES) - 568:
        return iv_bad(w, 947)
    base = 64 + (nodes + 8) * 64 + (edges + 9) * 8 + pool
    identifier = 1
    while identifier <= 7:
        kind = iv_get(w, at + identifier * 64)
        field = 0
        while field < 8:
            value = iv_get(w, at + identifier * 64 + field * 8)
            if field == 1 and (kind == 2 or kind == 3 or kind == 4 or kind == 9):
                value = base + (value - 568)
            elif field == 3 and (kind == 5 or kind == 6 or kind == 7):
                value = edges + 2 + value
            elif field == 5 and (kind == 5 or kind == 6 or kind == 7):
                value = nodes + 1 + value
            if iv_word(s, (nodes + 1 + identifier) * 64 + field * 8) != value:
                return iv_bad(w, 948)
            field = field + 1
        identifier = identifier + 1
    index = 0
    while index < 7:
        target = 64 + (nodes + 8) * 64 + (edges + 2 + index) * 8
        if iv_word(s, target) != iv_get(w, at + 512 + index * 8) + nodes + 1:
            return iv_bad(w, 949)
        index = index + 1
    if sv_equal(s, w, base, at + 568, iv_get(w, S_GRAPH_BYTES) - 568) == 0:
        return iv_bad(w, 950)
    return 1

def sv_bound(s:readbuf, r:readbuf, w:mutbuf) -> u32:
    if length(r) != 384 or iv_word(r, 72) != 768 or iv_word(r, 80) != 5 or iv_word(r, 88) != 256 or iv_word(r, 96) != 0 or iv_word(r, 104) != 0:
        return sv_fail(w, 951)
    if iv_word(s, 8) != iv_get(w, S_GRAPH_OUTPUT) or iv_shape(s, w, 0, length(s), iv_get(w, S_GRAPH_OUTPUT)) == 0:
        return sv_fail(w, 952)
    at = 128
    if iv_word(r, at) != SV_REG_EVENT or iv_word(r, at + 8) != 6 or iv_word(r, at + 16) != iv_get(w, S_INV) or iv_word(r, at + 24) != iv_get(w, S_CALL):
        return sv_fail(w, 953)
    if iv_word(r, at + 32) <= iv_get(w, S_REG_SEQ) or iv_word(r, at + 40) != iv_get(w, S_REG_COMMAND):
        return sv_fail(w, 954)
    if iv_word(r, at + 48) != iv_get(w, S_GRAPH_OUTPUT) or iv_word(r, at + 56) != length(s) or iv_word(r, at + 64) != 0:
        return sv_fail(w, 955)
    if iv_word(r, at + 72) != iv_get(w, S_GRAPH_FOREIGN) or iv_word(r, at + 80) != iv_get(w, S_GRAPH_OUTPUT):
        return sv_fail(w, 956)
    if iv_word(r, at + 88) == 0 or length(s) > IV_MAX - 512 or iv_word(r, at + 96) != 512 + length(s):
        return sv_fail(w, 957)
    index = 104
    while index < 136:
        if iv_word(r, at + index) != 0:
            return sv_fail(w, 958)
        index = index + 8
    if iv_word(r, at + 136) != 3 or iv_word(r, at + 144) != 640 + iv_get(w, S_GRAPH_BYTES) or iv_word(r, at + 152) != length(s):
        return sv_fail(w, 959)
    if iv_get(w, S_ISSUED) >= SV_HANDLE - 1:
        return sv_fail(w, 960)
    handle = SV_HANDLE + iv_get(w, S_ISSUED) + 1
    if iv_word(r, at + 160) != iv_get(w, S_SOURCE_NODES) + 2 or iv_word(r, at + 168) != handle:
        return sv_fail(w, 961)
    if iv_word(r, at + 176) != 0 or iv_word(r, at + 184) != 0 or iv_word(r, at + 192) != iv_get(w, S_ISSUED) + 1 or iv_word(r, at + 200) != iv_get(w, S_ORIGIN):
        return sv_fail(w, 962)
    if iv_word(r, at + 208) != iv_get(w, S_SOURCE_NODES) + 8 or iv_word(r, at + 216) != 0 or iv_word(r, at + 224) != 0:
        return sv_fail(w, 963)
    if iv_word(r, at + 232) != iv_get(w, S_REG_COMMAND) or iv_word(r, at + 240) != 0 or iv_word(r, at + 248) != 0:
        return sv_fail(w, 964)
    if sv_bound_graph(s, w) == 0:
        return sv_fail(w, 965)
    iv_put(w, S_REG_SEQ, iv_word(r, at + 32))
    iv_put(w, S_GRAPH_HANDLE, handle)
    return sv_success(w)
'''
