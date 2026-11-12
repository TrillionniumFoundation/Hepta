"""Native Emitter late semantic gates and actual Code-finalizer to ELF Graph bridge.
No host constructs symbol records, missing-export messages or ELF input values.
The registry is issued by the native Emitter continuation, never a public frame.
"""
import ast
def magic(s):return int.from_bytes(s.encode("ascii"),"little")
FRAME_SHA="27a817d4cb0d3c8131efa4c8474779f55d74d618124a987a551cb26b3e18ddbd"
ELF_SHA="84bbd81168ca645807ce0095755bb6e74efb1ffd9419cec3473a439e34dca985"
REFERENCE_SHA="bf953a8b85d1ebc6b9d7a90fbbcaa4137e40ed214c2ede2af1a13cfc01b1c07c"
LITERALS={"functions":"functions","name":"name","exports":"exports",
 "missing":"E_HIA_PROGRAM_ABI: explicit exports have signatures outside the native C ABI: ",
 "count":"E_HIA_PROGRAM_NATIVE: native profile requires between 1 and 128 admitted entrypoints",
 "text":"E_HIA_PROGRAM_LIMIT: direct code exceeds the text budget",
 "key_name":"name","key_offset":"offset","key_size":"size","key_global":"global"}
BODY=r'''
def finish_emitter(s:readbuf, r:readbuf, w:mutbuf) -> u32:
    if length(w) < MIN_WORK:
        return BAD
    fill_range(w, 0, MIN_WORK, 0)
    literal_table(w)
    if length(s) < 64 or length(r) < 128:
        abi(w, 301)
    elif word(s, 0) == GRAPH and word(r, 0) == REGISTRY:
        put(w, F_MODE, 1)
        if registry(r, w) != 0:
            late_gate(s, r, w)
    elif word(s, 0) == REGISTRY and word(r, 0) == FINAL_EVENT:
        put(w, F_MODE, 2)
        if registry(s, w) != 0:
            if final_input(r, w) != 0:
                bridge_measure(s, r, w)
                if get(w, S_BAD) == 0 and get(w, F_NEED) <= length(w):
                    bridge(s, r, w)
    else:
        abi(w, 302)
    if get(w, S_BAD) != 0:
        finish_event(w, 3)
        return BAD
    if get(w, F_NEED) > length(w):
        finish_event(w, 1)
        return GROW
    if get(w, F_ERROR) != 0:
        finish_event(w, 2)
    else:
        finish_event(w, 0)
    return 128

def finish_event(w:mutbuf, action:u64) -> u64:
    at = 0
    count = 0
    if action == 0 and get(w, F_MODE) == 2:
        at = BASE
        count = get(w, F_NEED) - BASE
    elif action == 2:
        at = get(w, F_RESULT)
        count = get(w, F_RESULT_N)
    put(w, 0, EVENT)
    put(w, 8, 1)
    put(w, 16, action)
    put(w, 24, get(w, F_LEASE))
    put(w, 32, get(w, F_REQUEST))
    put(w, 40, get(w, F_MODE))
    put(w, 48, get(w, F_ERROR))
    put(w, 56, get(w, F_NEED))
    put(w, 64, at)
    put(w, 72, count)
    put(w, 80, get(w, F_CODE_LEASE))
    put(w, 88, get(w, F_CODE_SEQ))
    put(w, 96, get(w, F_TEXT_N))
    put(w, 104, get(w, F_RECORD_N))
    put(w, 112, get(w, F_GLOBAL_N))
    put(w, 120, get(w, S_BAD))
    return 0

def span(s:readbuf, begin:u64, count:u64) -> u64:
    return choose(begin <= length(s) and count <= length(s) - begin, 1, 0)

def registry(s:readbuf, w:mutbuf) -> u64:
    if length(s) < 256 or word(s, 0) != REGISTRY or word(s, 8) != 1:
        return abi(w, 303)
    if word(s, 16) == 0 or word(s, 24) == 0 or word(s, 32) == 0 or word(s, 40) == 0:
        return abi(w, 304)
    if word(s, 48) < 64 or word(s, 56) == 0 or word(s, 64) == 0:
        return abi(w, 305)
    count = word(s, 72)
    if count > (MAX - 256) >> 6 or word(s, 80) != 256:
        return abi(w, 306)
    pool = 256 + count * 64
    if pool > length(s) or word(s, 88) != pool or word(s, 96) != length(s):
        return abi(w, 307)
    functions = word(s, 120)
    globals = word(s, 128)
    if functions > count or globals != count - functions or globals > functions:
        return abi(w, 308)
    if word(s, 104) > 67108864:
        return abi(w, 309)
    align = word(s, 136)
    if align != 1 and align != 16 and align != 32 and align != 64:
        return abi(w, 310)
    cursor = 144
    while cursor < 256:
        if word(s, cursor) != 0:
            return abi(w, 311)
        cursor = cursor + 8
    put(w, F_LEASE, word(s, 16))
    put(w, F_REQUEST, word(s, 24))
    put(w, F_GRAPH_LEASE, word(s, 32))
    put(w, F_ROOT, word(s, 40))
    put(w, F_SOURCE_N, word(s, 48))
    put(w, F_CODE_LEASE, word(s, 56))
    put(w, F_CODE_SEQ, word(s, 64))
    put(w, F_RECORD_N, count)
    put(w, F_TEXT_N, word(s, 104))
    put(w, F_SERIAL, word(s, 112))
    put(w, F_FUNCTION_N, functions)
    put(w, F_GLOBAL_N, globals)
    put(w, F_ALIGN, align)
    i = 0
    last = 0
    while i < count:
        at = 256 + i * 64
        index = word(s, at)
        kind = word(s, at + 8)
        name = word(s, at + 16)
        size = word(s, at + 24)
        begin = word(s, at + 32)
        end = word(s, at + 40)
        frame = word(s, at + 48)
        if index >= functions or name < pool or span(s, name, size) == 0 or size == 0:
            return abi(w, 312)
        if begin < last or begin >= end or end > get(w, F_TEXT_N):
            return abi(w, 313)
        if frame == 0 or frame > 65536 or (frame & 15) != 0 or word(s, at + 56) != 0:
            return abi(w, 314)
        if (i < functions and kind != 0) or (i >= functions and kind != 1 and kind != 2):
            return abi(w, 315)
        j = 0
        if i >= functions:
            j = functions
        while j < i:
            if word(s, 256 + j * 64) == index:
                return abi(w, 316)
            j = j + 1
        last = end
        i = i + 1
    return 1

def graph_input(s:readbuf, w:mutbuf) -> u64:
    if word(s, 0) != GRAPH or word(s, 8) != get(w, F_GRAPH_LEASE) or word(s, 56) != 0:
        return abi(w, 317)
    if length(s) != get(w, F_SOURCE_N) or word(s, 24) != get(w, F_ROOT):
        return abi(w, 318)
    nodes = word(s, 16)
    edges = word(s, 32)
    if nodes == 0 or nodes > (MAX - 64) >> 6:
        return abi(w, 319)
    pool = 64 + nodes * 64
    if edges > (MAX - pool) >> 3:
        return abi(w, 320)
    pool = pool + edges * 8
    if pool > length(s) or word(s, 40) != length(s) - pool or word(s, 48) != length(s):
        return abi(w, 321)
    put(w, S_NODES, nodes)
    put(w, S_EDGES, edges)
    put(w, S_DATA, pool)
    put(w, S_ROOT, word(s, 24))
    root = typed(s, w, get(w, S_ROOT), 5)
    if root == 0 or word(s, root + 32) != 3:
        return abi(w, 322)
    core = edge(s, w, root, 0)
    put(w, S_CORE, core)
    functions = typed(s, w, field(s, w, core, L_FUNCTIONS, 1), 5)
    if functions == 0 or word(s, functions + 32) != get(w, F_FUNCTION_N):
        return abi(w, 323)
    return 1

def same_name(s:readbuf, r:readbuf, w:mutbuf, identifier:u64, begin:u64, count:u64) -> u64:
    node_at = typed(s, w, identifier, 4)
    if node_at == 0:
        return 0
    if word(s, node_at + 16) != count:
        return 0
    i = 0
    while i < count:
        if byte(s, word(s, node_at + 8) + i) != byte(r, begin + i):
            return 0
        i = i + 1
    return 1

def exported(s:readbuf, r:readbuf, w:mutbuf, name:u64) -> u64:
    i = get(w, F_FUNCTION_N)
    while i < get(w, F_RECORD_N):
        at = 256 + i * 64
        if same_name(s, r, w, name, word(r, at + 16), word(r, at + 24)) != 0:
            return 1
        if get(w, S_BAD) != 0:
            return 0
        i = i + 1
    return 0

def less_name(s:readbuf, w:mutbuf, left:u64, right:u64) -> u64:
    a = typed(s, w, left, 4)
    b = typed(s, w, right, 4)
    if a == 0 or b == 0:
        return 0
    an = word(s, a + 16)
    bn = word(s, b + 16)
    i = 0
    while i < an and i < bn:
        x = byte(s, word(s, a + 8) + i)
        y = byte(s, word(s, b + 8) + i)
        if x < y:
            return 1
        if x > y:
            return 0
        i = i + 1
    return choose(an < bn, 1, 0)

def copy_literal(w:mutbuf, index:u64, target:u64) -> u64:
    row = INDEX + index * 16
    i = 0
    while i < get(w, row + 8):
        store(w, target + i, byte(w, get(w, row) + i))
        i = i + 1
    return i

def static_error(w:mutbuf, reason:u64, literal_id:u64) -> u64:
    row = INDEX + literal_id * 16
    put(w, F_ERROR, reason)
    put(w, F_RESULT, get(w, row))
    put(w, F_RESULT_N, get(w, row + 8))
    return 0

def missing_message(s:readbuf, w:mutbuf) -> u64:
    count = get(w, F_MISSING_N)
    i = 1
    while i < count:
        j = i
        while j > 0:
            left = get(w, BASE + (j - 1) * 8)
            right = get(w, BASE + j * 8)
            if less_name(s, w, right, left) == 0:
                j = 0
            else:
                put(w, BASE + (j - 1) * 8, right)
                put(w, BASE + j * 8, left)
                j = j - 1
        i = i + 1
    target = get(w, F_MISSING_LIMIT)
    cursor = target + copy_literal(w, L_MISSING, target)
    i = 0
    while i < count:
        if i != 0:
            store(w, cursor, 44)
            store(w, cursor + 1, 32)
            cursor = cursor + 2
        name = typed(s, w, get(w, BASE + i * 8), 4)
        size = word(s, name + 16)
        copy_bytes(w, s, cursor, word(s, name + 8), size)
        cursor = cursor + size
        i = i + 1
    if cursor != get(w, F_NEED):
        return abi(w, 324)
    put(w, F_ERROR, 1)
    put(w, F_RESULT, target)
    put(w, F_RESULT_N, cursor - target)
    return 0

def missing_gate(s:readbuf, r:readbuf, w:mutbuf, array:u64) -> u64:
    count = word(s, array + 32)
    if count > (MAX - BASE) >> 3:
        return abi(w, 325)
    limit = BASE + count * 8
    put(w, F_MISSING_LIMIT, limit)
    put(w, F_NEED, limit)
    if limit > length(w):
        return 0
    missing = 0
    characters = 0
    i = 0
    while i < count:
        name = edge(s, w, array, i)
        if exported(s, r, w, name) == 0:
            duplicate = 0
            j = 0
            while j < missing:
                if equal(s, w, name, get(w, BASE + j * 8)) != 0:
                    duplicate = 1
                j = j + 1
            if get(w, S_BAD) != 0:
                return 0
            if duplicate == 0:
                at = typed(s, w, name, 4)
                if at == 0:
                    return 0
                extra = word(s, at + 16)
                if missing != 0:
                    if extra > MAX - 2:
                        return abi(w, 326)
                    extra = extra + 2
                if characters > MAX - extra:
                    return abi(w, 327)
                characters = characters + extra
                put(w, BASE + missing * 8, name)
                missing = missing + 1
        i = i + 1
    put(w, F_MISSING_N, missing)
    if missing == 0:
        return 1
    prefix = get(w, INDEX + L_MISSING * 16 + 8)
    if characters > MAX - prefix or limit > MAX - characters - prefix:
        return abi(w, 328)
    put(w, F_NEED, limit + characters + prefix)
    if get(w, F_NEED) > length(w):
        return 0
    return missing_message(s, w)

def late_gate(s:readbuf, r:readbuf, w:mutbuf) -> u64:
    put(w, F_NEED, BASE)
    if graph_input(s, w) == 0:
        return 0
    id = field(s, w, get(w, S_CORE), L_EXPORTS, 0)
    if get(w, S_BAD) != 0:
        return 0
    if id != 0:
        array = typed(s, w, id, 5)
        if array == 0 or missing_gate(s, r, w, array) == 0:
            return 0
    if get(w, F_GLOBAL_N) == 0 or get(w, F_GLOBAL_N) > 128:
        return static_error(w, 2, L_COUNT)
    if get(w, F_TEXT_N) > 16777216:
        return static_error(w, 3, L_TEXT)
    return 1

def final_input(r:readbuf, w:mutbuf) -> u64:
    if word(r, 0) != FINAL_EVENT or word(r, 8) != 1 or word(r, 16) != 0:
        return abi(w, 329)
    if word(r, 24) != get(w, F_CODE_LEASE) or word(r, 32) != get(w, F_CODE_SEQ) or word(r, 40) != 0:
        return abi(w, 330)
    graph = word(r, 56)
    count = word(r, 64)
    if graph != 4096 or span(r, graph, count) == 0 or count < 64 or word(r, 48) != graph + count:
        return abi(w, 331)
    if word(r, 96) != 0 or word(r, 104) != 0 or word(r, 112) != 0 or word(r, 120) != 0:
        return abi(w, 332)
    if word(r, graph) != GRAPH or word(r, graph + 8) != get(w, F_CODE_LEASE) or word(r, graph + 56) != 0:
        return abi(w, 333)
    nodes = word(r, graph + 16)
    edges = word(r, graph + 32)
    if nodes == 0 or nodes > (MAX - 64) >> 6:
        return abi(w, 334)
    pool = 64 + nodes * 64
    if edges > (MAX - pool) >> 3:
        return abi(w, 335)
    pool = pool + edges * 8
    if pool > count or word(r, graph + 40) != count - pool or word(r, graph + 48) != count:
        return abi(w, 336)
    # This exact root is part of the frozen actual Code finalizer ABI.
    if word(r, graph + 24) != 1 or nodes < 3 or edges < 2:
        return abi(w, 337)
    root = graph + 64
    if word(r, root) != 5 or word(r, root + 24) != 0 or word(r, root + 32) != 2:
        return abi(w, 338)
    edge_at = graph + 64 + nodes * 64
    if word(r, edge_at) != 2 or word(r, edge_at + 8) != 3:
        return abi(w, 339)
    code = graph + 128
    reloc = graph + 192
    if word(r, code) != 9 or word(r, code + 8) < pool or word(r, code + 8) > count or word(r, code + 16) > count - word(r, code + 8):
        return abi(w, 340)
    if word(r, code + 16) != word(r, 72) or word(r, code + 16) < get(w, F_TEXT_N) or word(r, code + 16) - get(w, F_TEXT_N) > 4:
        return abi(w, 341)
    if word(r, reloc) != 5 or word(r, reloc + 32) != word(r, 88):
        return abi(w, 342)
    put(w, F_OLD_GRAPH, graph)
    put(w, F_OLD_NODES, nodes)
    put(w, F_OLD_EDGES, edges)
    put(w, F_OLD_POOL, pool)
    put(w, F_OLD_BYTES, count)
    put(w, F_CODE_AT, word(r, code + 8))
    put(w, F_FINAL_N, word(r, code + 16))
    return 1

def magnitude_bytes(value:u64) -> u64:
    size = 0
    while value != 0:
        size = size + 1
        value = value >> 8
    return size

def bridge_measure(s:readbuf, r:readbuf, w:mutbuf) -> u64:
    count = get(w, F_RECORD_N)
    nodes = get(w, F_OLD_NODES)
    edges = get(w, F_OLD_EDGES)
    if nodes > MAX - 9 or count > (MAX - nodes - 9) >> 2:
        return abi(w, 343)
    nodes = nodes + 9 + count * 4
    if edges > MAX - 4 or count * 9 > MAX - edges - 4:
        return abi(w, 344)
    edges = edges + 4 + count * 9
    if nodes > (MAX - 64) >> 6:
        return abi(w, 345)
    pool = 64 + nodes * 64
    if edges > (MAX - pool) >> 3:
        return abi(w, 346)
    pool = pool + edges * 8
    scalar = get(w, F_OLD_BYTES) - get(w, F_OLD_POOL)
    # One-byte alignment plus the four complete ASCII symbol field names.
    if scalar > MAX - 21:
        return abi(w, 347)
    scalar = scalar + 21
    i = 0
    while i < count:
        at = 256 + i * 64
        integers = magnitude_bytes(word(s, at + 32)) + magnitude_bytes(word(s, at + 40) - word(s, at + 32))
        if word(s, at + 24) > MAX - integers:
            return abi(w, 348)
        extra = word(s, at + 24) + integers
        if scalar > MAX - extra:
            return abi(w, 348)
        scalar = scalar + extra
        i = i + 1
    if scalar > MAX - pool:
        return abi(w, 349)
    total = pool + scalar
    if total > MAX - BASE - 128 - 96:
        return abi(w, 350)
    put(w, F_NEW_NODES, nodes)
    put(w, F_NEW_EDGES, edges)
    put(w, F_NEW_POOL, pool)
    put(w, F_GRAPH_BYTES, total)
    put(w, F_NEED, BASE + 128 + total + 96)
    return 1

def out_node(w:mutbuf, identifier:u64, kind:u64, begin:u64, count:u64, first:u64, children:u64, object_id:u64, aux:u64) -> u64:
    at = BASE + 128 + 64 + (identifier - 1) * 64
    put(w, at, kind)
    put(w, at + 8, begin)
    put(w, at + 16, count)
    put(w, at + 24, first)
    put(w, at + 32, children)
    put(w, at + 40, object_id)
    put(w, at + 48, aux)
    return 0

def out_edge(w:mutbuf, index:u64, value:u64) -> u64:
    put(w, BASE + 128 + 64 + get(w, F_NEW_NODES) * 64 + index * 8, value)
    return 0

def out_integer(w:mutbuf, identifier:u64, cursor:u64, value:u64) -> u64:
    size = magnitude_bytes(value)
    out_node(w, identifier, 2, cursor, size, 0, 0, 0, 0)
    i = 0
    while i < size:
        store(w, BASE + 128 + cursor + i, (value >> (i * 8)) & 255)
        i = i + 1
    return cursor + size

def out_literal(w:mutbuf, identifier:u64, cursor:u64, literal_id:u64) -> u64:
    size = get(w, INDEX + literal_id * 16 + 8)
    out_node(w, identifier, 4, cursor, size, 0, 0, 0, size)
    copy_literal(w, literal_id, BASE + 128 + cursor)
    return cursor + size

def old_graph_copy(r:readbuf, w:mutbuf) -> u64:
    graph = get(w, F_OLD_GRAPH)
    count = get(w, F_OLD_NODES)
    delta = get(w, F_NEW_POOL) - get(w, F_OLD_POOL)
    copy_bytes(w, r, BASE + 128 + 64, graph + 64, count * 64)
    copy_bytes(w, r, BASE + 128 + 64 + get(w, F_NEW_NODES) * 64,
               graph + 64 + count * 64, get(w, F_OLD_EDGES) * 8)
    copy_bytes(w, r, BASE + 128 + get(w, F_NEW_POOL), graph + get(w, F_OLD_POOL),
               get(w, F_OLD_BYTES) - get(w, F_OLD_POOL))
    i = 0
    while i < count:
        source = graph + 64 + i * 64
        target = BASE + 128 + 64 + i * 64
        kind = word(r, source)
        if word(r, source + 56) != 0 or kind > 9:
            return abi(w, 351)
        if kind == 2 or kind == 3 or kind == 4 or kind == 9:
            begin = word(r, source + 8)
            size = word(r, source + 16)
            if begin < get(w, F_OLD_POOL) or begin > get(w, F_OLD_BYTES) or size > get(w, F_OLD_BYTES) - begin:
                return abi(w, 352)
            put(w, target + 8, begin + delta)
        elif kind == 5 or kind == 6 or kind == 7:
            start = word(r, source + 24)
            size = word(r, source + 32)
            if kind == 6:
                if size > MAX >> 1:
                    return abi(w, 353)
                size = size * 2
            if start > get(w, F_OLD_EDGES) or size > get(w, F_OLD_EDGES) - start:
                return abi(w, 354)
        i = i + 1
    return 1

def graph_symbols(s:readbuf, w:mutbuf, cursor:u64) -> u64:
    oldnodes = get(w, F_OLD_NODES)
    edges = get(w, F_OLD_EDGES)
    count = get(w, F_RECORD_N)
    names = oldnodes + 4
    offsets = oldnodes + 5
    sizes = oldnodes + 6
    globals = oldnodes + 7
    i = 0
    while i < count:
        row = 256 + i * 64
        identifier = oldnodes + 10 + i * 4
        first = edges + 4 + count + i * 8
        out_node(w, identifier, 6, 0, 0, first, 4, identifier, 0)
        out_edge(w, edges + 4 + i, identifier)
        out_edge(w, first, names)
        out_edge(w, first + 1, identifier + 1)
        out_edge(w, first + 2, offsets)
        out_edge(w, first + 3, identifier + 2)
        out_edge(w, first + 4, sizes)
        out_edge(w, first + 5, identifier + 3)
        out_edge(w, first + 6, globals)
        out_edge(w, first + 7, oldnodes + choose(word(s, row + 8) == 0, 8, 9))
        name_n = word(s, row + 24)
        out_node(w, identifier + 1, 4, cursor, name_n, 0, 0, 0, name_n)
        copy_bytes(w, s, BASE + 128 + cursor, word(s, row + 16), name_n)
        cursor = cursor + name_n
        cursor = out_integer(w, identifier + 2, cursor, word(s, row + 32))
        cursor = out_integer(w, identifier + 3, cursor, word(s, row + 40) - word(s, row + 32))
        i = i + 1
    return cursor

def bridge_header(w:mutbuf) -> u64:
    graph = BASE + 128
    total = get(w, F_GRAPH_BYTES)
    command = graph + total
    oldnodes = get(w, F_OLD_NODES)
    put(w, graph, GRAPH)
    put(w, graph + 8, get(w, F_LEASE))
    put(w, graph + 16, get(w, F_NEW_NODES))
    put(w, graph + 24, oldnodes + 1)
    put(w, graph + 32, get(w, F_NEW_EDGES))
    put(w, graph + 40, total - get(w, F_NEW_POOL))
    put(w, graph + 48, total)
    put(w, command, ELF_COMMAND)
    put(w, command + 8, 1)
    put(w, command + 16, get(w, F_LEASE))
    put(w, command + 24, get(w, F_REQUEST))
    put(w, command + 32, total)
    put(w, command + 40, oldnodes + 1)
    put(w, BASE, BRIDGE)
    put(w, BASE + 8, 1)
    put(w, BASE + 16, get(w, F_LEASE))
    put(w, BASE + 24, get(w, F_REQUEST))
    put(w, BASE + 32, get(w, F_CODE_LEASE))
    put(w, BASE + 40, get(w, F_CODE_SEQ))
    put(w, BASE + 48, graph)
    put(w, BASE + 56, total)
    put(w, BASE + 64, command)
    put(w, BASE + 72, 96)
    put(w, BASE + 80, 2)
    put(w, BASE + 88, graph + get(w, F_CODE_AT) + get(w, F_NEW_POOL) - get(w, F_OLD_POOL))
    put(w, BASE + 96, get(w, F_FINAL_N))
    put(w, BASE + 104, get(w, F_RECORD_N))
    put(w, BASE + 112, choose(get(w, F_ALIGN) > 16, get(w, F_ALIGN), 16))
    return 1

def bridge(s:readbuf, r:readbuf, w:mutbuf) -> u64:
    fill_range(w, BASE, get(w, F_NEED) - BASE, 0)
    if old_graph_copy(r, w) == 0:
        return 0
    oldnodes = get(w, F_OLD_NODES)
    oldedges = get(w, F_OLD_EDGES)
    count = get(w, F_RECORD_N)
    out_node(w, oldnodes + 1, 5, 0, 0, oldedges, 4, oldnodes + 1, 0)
    out_node(w, oldnodes + 3, 5, 0, 0, oldedges + 4, count, oldnodes + 3, 0)
    out_node(w, oldnodes + 8, 1, 0, 0, 0, 0, 0, 0)
    out_node(w, oldnodes + 9, 1, 0, 0, 0, 0, 0, 1)
    out_edge(w, oldedges, oldnodes + 2)
    out_edge(w, oldedges + 1, 2)
    out_edge(w, oldedges + 2, oldnodes + 3)
    out_edge(w, oldedges + 3, 3)
    cursor = get(w, F_NEW_POOL) + get(w, F_OLD_BYTES) - get(w, F_OLD_POOL)
    cursor = out_integer(w, oldnodes + 2, cursor, choose(get(w, F_ALIGN) > 16, get(w, F_ALIGN), 16))
    cursor = out_literal(w, oldnodes + 4, cursor, L_KEY_NAME)
    cursor = out_literal(w, oldnodes + 5, cursor, L_KEY_OFFSET)
    cursor = out_literal(w, oldnodes + 6, cursor, L_KEY_SIZE)
    cursor = out_literal(w, oldnodes + 7, cursor, L_KEY_GLOBAL)
    cursor = graph_symbols(s, w, cursor)
    if cursor != get(w, F_GRAPH_BYTES):
        return abi(w, 355)
    return bridge_header(w)
'''
def source(frame_owner,elf_owner):
    shared_names=("abi","word","get","put","typed","edge","literal","equal","field")
    shared={n.name:n for n in ast.parse(frame_owner.BODY).body}
    elf={n.name:n for n in ast.parse(elf_owner.BODY).body}
    constants=dict(frame_owner.CONSTANTS)
    constants.update(MIN_WORK=8192,BASE=8192,INDEX=2048,DATA=4096,
        EVENT=magic("HIAEMF01"),REGISTRY=magic("HIAEMR01"),FINAL_EVENT=magic("HIAXFE01"),
        ELF_COMMAND=magic("HIAELC01"),BRIDGE=magic("HIAEMG01"))
    constants["S_DATABASE"]=constants["S_DATA"]
    fields=("MODE","ERROR","LEASE","REQUEST","GRAPH_LEASE","ROOT","SOURCE_N","CODE_LEASE",
        "CODE_SEQ","RECORD_N","TEXT_N","SERIAL","FUNCTION_N","GLOBAL_N","ALIGN","NEED","RESULT","RESULT_N",
        "MISSING_N","MISSING_LIMIT","OLD_GRAPH","OLD_NODES","OLD_EDGES","OLD_POOL","OLD_BYTES","CODE_AT",
        "FINAL_N","NEW_NODES","NEW_EDGES","NEW_POOL","GRAPH_BYTES")
    constants.update({"F_"+n:1024+i*8 for i,n in enumerate(fields)})
    data=bytearray(constants["DATA"]);helpers=[]
    for i,(name,text) in enumerate(LITERALS.items()):
        constants["L_"+name.upper()]=i;raw=text.encode("ascii");at=len(data);data.extend(raw)
        row=constants["INDEX"]+i*16
        data[row:row+8]=at.to_bytes(8,"little");data[row+8:row+16]=len(raw).to_bytes(8,"little")
    assert constants["INDEX"]+len(LITERALS)*16<=constants["DATA"] and len(data)<constants["MIN_WORK"]
    writes=[(at,int.from_bytes(data[at:at+8].ljust(8,b"\0"),"little"))
        for at in range(constants["INDEX"],len(data),8) if any(data[at:at+8])]
    calls=[]
    for start in range(0,len(writes),16):
        name="literal_"+str(start//16);calls.append("    "+name+"(w)")
        helpers.append("def "+name+"(w:mutbuf)->u64:\n"+
            "\n".join("    put(w,%d,%d)"%row for row in writes[start:start+16])+"\n    return 0")
    helpers.append("def literal_table(w:mutbuf)->u64:\n"+"\n".join(calls)+"\n    return 0")
    nodes=ast.parse(BODY+"\n"+"\n".join(helpers)).body+[shared[n] for n in shared_names]+[elf["node"]]
    names={n.name:n for n in nodes};assert len(names)==len(nodes)
    live={"finish_emitter"};pending=["finish_emitter"]
    while pending:
        for call in ast.walk(names[pending.pop()]):
            if isinstance(call,ast.Call) and isinstance(call.func,ast.Name):
                name=call.func.id
                if name in names and name not in live:live.add(name);pending.append(name)
    nodes=[n for n in nodes if n.name in live]
    for node in nodes:
        if node.name in("word","get"):
            arg="s" if node.name=="word" else "w"
            node.body=ast.parse("return "+" | ".join("(byte(%s,at+%d)<<%d)"%(arg,i,8*i) for i in range(8))).body
        elif node.name=="put":
            node.body=ast.parse("\n".join("store(w,at+%d,(value>>%d)&255)"%(i,8*i) for i in range(8))+"\nreturn 0").body
    return "\n".join(ast.unparse(ast.fix_missing_locations(n)) for n in nodes)+"\n",constants,dict(
        status="NEW_UNEXECUTED",scope="EMITTER_LATE_GATES_AND_ACTUAL_FINALIZER_ELF_VALUE_BRIDGE",
        backend_reference_sha256=REFERENCE_SHA,frame_dependency_sha256=FRAME_SHA,elf_graph_dependency_sha256=ELF_SHA,
        actual_private_Emitter_registry_and_Code_finalizer_required=True,header_is_authentication=False,
        missing_exports_then_count_then_text_order=True,original_missing_set_sort_and_full_message=True,
        finalizer_fixup_extension_not_hidden_by_new_text_gate=True,
        symbols_and_relocations_encoded_as_complete_native_Graph=True,actual_ELF_writer_still_required=True,
        no_host_symbol_plan_or_ELF_input_construction=True,
        whole_Emitter=False,outer_emit_program_machine=False,installed=False,cold=False)
