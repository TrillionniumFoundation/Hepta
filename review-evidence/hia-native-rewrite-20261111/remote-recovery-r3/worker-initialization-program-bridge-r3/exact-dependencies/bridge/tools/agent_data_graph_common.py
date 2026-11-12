"""Native complete materialization of an issued Agent-data decoder arena.

NEW UNEXECUTED. The arena and original wire must be the same immutable private
leases produced by the actual decoder. Header equality is not authentication.
The result is the existing HIAGRF01 representation, with integer magnitudes,
IEEE bits, ordered object edges and strings; no Python value is materialized.
Event bytes [2048,2240) never overlap the immutable config [128,256).
Integer scratch reserves at most three trailing bytes for 32-bit limbs.
"""
CONSTANTS={
 'DG_COMMAND':int.from_bytes(b'HIADGC01','little'),
 'DG_REPLY':int.from_bytes(b'HIADGR01','little'),
 'DG_EVENT':int.from_bytes(b'HIADGE01','little'),
 'DG_STATE':int.from_bytes(b'HIADGW01','little'),
 'DG_ARENA':int.from_bytes(b'HIADATA1','little'),
 'DG_GRAPH':int.from_bytes(b'HIAGRF01','little'),
 'DG_BAD':0xfffffffd,'DG_MAX':(1<<64)-1,'DG_MIN':4096,
 'DG_CONFIG':128,'DG_RESPONSE':256,'DG_RESPONSE_VALUE':320,
 'DG_SAVED_CONFIG':1024,'DG_SAVED_HEADER':1152,
 'DG_TEXT':1536,'DG_DECIMAL':1920,'DG_EVENT_BASE':2048,
}
_NAMES=('MAGIC','PHASE','SEQ','BAD_REASON','ERROR','ERROR_SIZE','NEED','NODES','BASE',
        'KEYS','EDGES','POOL_BOUND','LINKED','KEYMAP','EDGEMAP','STACK','SP','HASH','MASK',
        'GRAPH','GRAPH_MAX','DATABASE','POOL_USED','KEY_USED','CURRENT','PENDING_NODE',
        'NUMBER_START','NUMBER_BYTES','ACTUAL_DIGITS','BINARY_STATUS','TEXT_SIZE',
        'NEXT','CHARS','PLAN_EDGES','PLAN_KEYS','PLAN_POOL','GRAPH_TOTAL','UTF8_NEXT')
CONSTANTS.update({'D_'+name:512+8*i for i,name in enumerate(_NAMES)})
COMMON=r'''
def dg_entry(s:readbuf, r:readbuf, w:mutbuf) -> u32:
    if length(w) < DG_MIN:
        return DG_BAD
    if dg_get(w, D_PHASE) >= 90:
        return DG_BAD
    if dg_get(w, D_MAGIC) == 0:
        if dg_initial(s, r, w) == 0:
            return dg_refuse(w, 1)
    else:
        if dg_get(w, D_MAGIC) != DG_STATE or dg_same(s, r, w) == 0:
            return dg_refuse(w, 2)
    if dg_get(w, D_PHASE) == 10:
        if dg_get(w, D_NEED) > length(w):
            return dg_event(w, 1)
        if dg_structure(s, r, w) == 0:
            return dg_refuse(w, 3)
        if dg_plan(s, r, w) == 0:
            return dg_refuse(w, 4)
        dg_put(w, D_PHASE, 20)
    if dg_get(w, D_PHASE) == 20:
        if dg_get(w, D_NEED) > length(w):
            return dg_event(w, 1)
        if dg_initialize_graph(s, w) == 0:
            return dg_refuse(w, 5)
        dg_put(w, D_PHASE, 30)
    if dg_get(w, D_PHASE) == 31:
        result = dg_binary_reply(s, r, w)
        if result != 0:
            return result
    if dg_get(w, D_PHASE) != 30:
        return dg_refuse(w, 6)
    return dg_walk(s, r, w)

def dg_initial(s:readbuf, r:readbuf, w:mutbuf) -> u64:
    if dg_get(w, DG_CONFIG) != DG_COMMAND:
        return 0
    i = 136
    while i < 176:
        if dg_get(w, i) == 0:
            return 0
        i = i + 8
    if dg_get(w, 184) != length(s) or dg_get(w, 192) != length(r):
        return 0
    i = 200
    while i < 256:
        if dg_get(w, i) != 0:
            return 0
        i = i + 8
    i = 0
    while i < DG_MIN:
        if i < 128 or i >= 256:
            if byte(w, i) != 0:
                return 0
        i = i + 1
    if length(s) < 64:
        return 0
    if dg_word(s, 0) != DG_ARENA:
        return 0
    nodes = dg_word(s, 8)
    if nodes == 0 or nodes > 262144:
        return 0
    base = 64 + nodes * 56
    if dg_word(s, 16) != base or base > length(s):
        return 0
    if dg_word(s, 24) != length(s) or dg_word(s, 32) != length(s):
        return 0
    if dg_word(s, 40) != length(r) or dg_word(s, 48) != 1 or dg_word(s, 56) != 0:
        return 0
    dg_put(w, D_MAGIC, DG_STATE)
    dg_put(w, D_NODES, nodes)
    dg_put(w, D_BASE, base)
    i = 0
    while i < 128:
        store(w, DG_SAVED_CONFIG + i, byte(w, DG_CONFIG + i))
        i = i + 1
    copy_bytes(w, s, DG_SAVED_HEADER, 0, 64)
    i = 0
    while i < nodes:
        at = 64 + i * 56
        kind = dg_word(s, at)
        if kind > 7:
            return 0
        if kind == 3 or kind == 7:
            begin = dg_word(s, at + 24)
            size = dg_word(s, at + 32)
            if begin > length(r) or size == 0 or size > length(r) - begin:
                return 0
            fractional = 0
            p = begin
            end = begin + size
            while p < end:
                ch = byte(r, p)
                if ch == 46 or ch == 69 or ch == 101:
                    fractional = 1
                p = p + 1
            if (kind == 7 and fractional == 0) or (kind == 3 and fractional != 0):
                return 0
        i = i + 1
    dg_put(w, D_LINKED, DG_MIN)
    dg_put(w, D_NEED, DG_MIN + nodes)
    dg_put(w, D_PHASE, 10)
    return 1

def dg_same(s:readbuf, r:readbuf, w:mutbuf) -> u64:
    if length(s) != dg_get(w, 184) or length(r) != dg_get(w, 192):
        return 0
    i = 0
    while i < 128:
        if byte(w, DG_CONFIG + i) != byte(w, DG_SAVED_CONFIG + i):
            return 0
        i = i + 1
    i = 0
    while i < 64:
        if byte(s, i) != byte(w, DG_SAVED_HEADER + i):
            return 0
        i = i + 1
    return 1

def dg_structure(s:readbuf, r:readbuf, w:mutbuf) -> u64:
    nodes = dg_get(w, D_NODES)
    linked = dg_get(w, D_LINKED)
    fill_range(w, linked, nodes, 0)
    store(w, linked, 1)
    if dg_word(s, 72) != DG_MAX or dg_word(s, 80) != DG_MAX:
        return 0
    i = 0
    while i < nodes:
        at = 64 + i * 56
        kind = dg_word(s, at)
        parent = dg_word(s, at + 8)
        sibling = dg_word(s, at + 16)
        begin = dg_word(s, at + 24)
        size = dg_word(s, at + 32)
        if i != 0:
            if parent >= i:
                return 0
        if sibling != DG_MAX:
            if sibling <= i or sibling >= nodes:
                return 0
        if kind == 5 or kind == 6:
            if size > nodes:
                return 0
            child = begin
            j = 0
            while j < size:
                if child <= i or child >= nodes:
                    return 0
                if byte(w, linked + child) != 0 or dg_word(s, 64 + child * 56 + 8) != i:
                    return 0
                store(w, linked + child, 1)
                child = dg_word(s, 64 + child * 56 + 16)
                j = j + 1
            if child != DG_MAX:
                return 0
        elif kind == 4:
            if begin < dg_get(w, D_BASE) or begin > length(s) or size > length(s) - begin:
                return 0
        elif kind == 3 or kind == 7:
            if begin > length(r) or size == 0 or size > length(r) - begin:
                return 0
        key = dg_word(s, at + 40)
        key_size = dg_word(s, at + 48)
        in_map = 0
        if i != 0:
            if dg_word(s, 64 + parent * 56) == 6:
                in_map = 1
        if in_map != 0:
            if key < dg_get(w, D_BASE) or key > length(s) or key_size > length(s) - key:
                return 0
        elif key != 0 or key_size != 0:
            return 0
        i = i + 1
    i = 0
    while i < nodes:
        if byte(w, linked + i) == 0:
            return 0
        i = i + 1
    return 1

def dg_add(w:mutbuf, field:u64, amount:u64) -> u64:
    prior = dg_get(w, field)
    if amount > DG_MAX - prior:
        return 0
    dg_put(w, field, prior + amount)
    return 1

def dg_plan(s:readbuf, r:readbuf, w:mutbuf) -> u64:
    nodes = dg_get(w, D_NODES)
    i = 0
    while i < nodes:
        at = 64 + i * 56
        kind = dg_word(s, at)
        size = dg_word(s, at + 32)
        if kind == 5:
            if dg_add(w, D_PLAN_EDGES, size) == 0:
                return 0
        elif kind == 6:
            if dg_add(w, D_PLAN_EDGES, size * 2) == 0:
                return 0
        elif kind == 4:
            if dg_add(w, D_PLAN_POOL, size) == 0:
                return 0
        elif kind == 3:
            if size > DG_MAX - 7:
                return 0
            if dg_add(w, D_PLAN_POOL, ((size + 1) >> 1) + 3) == 0:
                return 0
        elif kind == 7:
            if dg_add(w, D_PLAN_POOL, 8) == 0:
                return 0
        if i != 0:
            parent = dg_word(s, at + 8)
            if dg_word(s, 64 + parent * 56) == 6:
                if dg_add(w, D_PLAN_KEYS, 1) == 0 or dg_add(w, D_PLAN_POOL, dg_word(s, at + 48)) == 0:
                    return 0
        i = i + 1
    keys = dg_get(w, D_PLAN_KEYS)
    dg_put(w, D_KEYS, keys)
    dg_put(w, D_EDGES, dg_get(w, D_PLAN_EDGES))
    dg_put(w, D_POOL_BOUND, dg_get(w, D_PLAN_POOL))
    position = (DG_MIN + nodes + 7) & 18446744073709551608
    dg_put(w, D_KEYMAP, position)
    position = position + nodes * 8
    dg_put(w, D_EDGEMAP, position)
    position = position + nodes * 8
    dg_put(w, D_STACK, position)
    position = position + nodes * 24
    slots = 1
    while slots < keys * 2:
        slots = slots << 1
    dg_put(w, D_HASH, position)
    dg_put(w, D_MASK, slots - 1)
    position = position + slots * 32
    dg_put(w, D_GRAPH, position)
    graph_nodes = nodes + keys
    edgebase = 64 + graph_nodes * 64
    database = edgebase + dg_get(w, D_EDGES) * 8
    dg_put(w, D_DATABASE, database)
    if dg_get(w, D_POOL_BOUND) > DG_MAX - database:
        return 0
    total = database + dg_get(w, D_POOL_BOUND)
    if total > DG_MAX - position:
        return 0
    dg_put(w, D_GRAPH_MAX, total)
    dg_put(w, D_NEED, position + total)
    return 1

def dg_initialize_graph(s:readbuf, w:mutbuf) -> u64:
    slots = dg_get(w, D_MASK) + 1
    i = 0
    while i < slots:
        dg_put(w, dg_get(w, D_HASH) + i * 32, 0)
        i = i + 1
    nodes = dg_get(w, D_NODES)
    i = 0
    key = nodes
    edge = 0
    while i < nodes:
        at = 64 + i * 56
        kind = dg_word(s, at)
        dg_put(w, dg_get(w, D_EDGEMAP) + i * 8, edge)
        if kind == 5:
            edge = edge + dg_word(s, at + 32)
        elif kind == 6:
            edge = edge + dg_word(s, at + 32) * 2
        if i != 0:
            parent = dg_word(s, at + 8)
            if dg_word(s, 64 + parent * 56) == 6:
                key = key + 1
                dg_put(w, dg_get(w, D_KEYMAP) + i * 8, key)
        i = i + 1
    if key != nodes + dg_get(w, D_KEYS) or edge != dg_get(w, D_EDGES):
        return 0
    dg_put(w, D_SP, 0)
    return dg_push(w, 0)

def dg_push(w:mutbuf, node:u64) -> u64:
    sp = dg_get(w, D_SP)
    if sp >= dg_get(w, D_NODES):
        return 0
    at = dg_get(w, D_STACK) + sp * 24
    dg_put(w, at, node)
    dg_put(w, at + 8, 0)
    dg_put(w, at + 16, DG_MAX)
    dg_put(w, D_SP, sp + 1)
    return 1

def dg_node_zero(w:mutbuf, identifier:u64) -> u64:
    at = dg_get(w, D_GRAPH) + 64 + (identifier - 1) * 64
    i = 0
    while i < 64:
        dg_put(w, at + i, 0)
        i = i + 8
    return at

def dg_event(w:mutbuf, action:u64) -> u32:
    if dg_get(w, D_SEQ) == DG_MAX:
        dg_put(w, D_PHASE, 99)
        return DG_BAD
    dg_put(w, D_SEQ, dg_get(w, D_SEQ) + 1)
    dg_put(w, DG_EVENT_BASE + 0, DG_EVENT)
    dg_put(w, DG_EVENT_BASE + 8, action)
    dg_put(w, DG_EVENT_BASE + 16, dg_get(w, 136))
    dg_put(w, DG_EVENT_BASE + 24, dg_get(w, 144))
    dg_put(w, DG_EVENT_BASE + 32, dg_get(w, D_SEQ))
    dg_put(w, DG_EVENT_BASE + 40, dg_get(w, 168))
    dg_put(w, DG_EVENT_BASE + 48, dg_get(w, 152))
    dg_put(w, DG_EVENT_BASE + 56, dg_get(w, 160))
    dg_put(w, DG_EVENT_BASE + 64, choose(action == 1, dg_get(w, D_NEED), 0))
    dg_put(w, DG_EVENT_BASE + 72, choose(action == 0, dg_get(w, D_GRAPH), 0))
    dg_put(w, DG_EVENT_BASE + 80, choose(action == 0, dg_get(w, D_GRAPH_TOTAL), 0))
    dg_put(w, DG_EVENT_BASE + 88, choose(action == 2, dg_get(w, D_NUMBER_START), 0))
    dg_put(w, DG_EVENT_BASE + 96, choose(action == 2, dg_get(w, D_NUMBER_BYTES), 0))
    dg_put(w, DG_EVENT_BASE + 104, dg_get(w, D_CURRENT))
    dg_put(w, DG_EVENT_BASE + 112, dg_get(w, D_ERROR))
    dg_put(w, DG_EVENT_BASE + 120, choose(action == 3, DG_TEXT, 0))
    dg_put(w, DG_EVENT_BASE + 128, choose(action == 3, dg_get(w, D_TEXT_SIZE), 0))
    dg_put(w, DG_EVENT_BASE + 136, dg_get(w, 176))
    dg_put(w, DG_EVENT_BASE + 144, dg_get(w, D_ACTUAL_DIGITS))
    dg_put(w, DG_EVENT_BASE + 152, dg_get(w, D_BINARY_STATUS))
    dg_put(w, DG_EVENT_BASE + 160, dg_get(w, D_BAD_REASON))
    dg_put(w, DG_EVENT_BASE + 168, dg_get(w, D_PHASE))
    dg_put(w, DG_EVENT_BASE + 176, 0)
    dg_put(w, DG_EVENT_BASE + 184, 0)
    return 2240

def dg_refuse(w:mutbuf, reason:u64) -> u32:
    dg_put(w, D_BAD_REASON, reason)
    dg_put(w, D_PHASE, 99)
    dg_event(w, 4)
    return DG_BAD

def dg_word(s:readbuf, at:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(s, at + i) << (i * 8))
        i = i + 1
    return value

def dg_get(w:mutbuf, at:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(w, at + i) << (i * 8))
        i = i + 1
    return value

def dg_put(w:mutbuf, at:u64, value:u64) -> u64:
    i = 0
    while i < 8:
        store(w, at + i, (value >> (i * 8)) & 255)
        i = i + 1
    return value
'''
