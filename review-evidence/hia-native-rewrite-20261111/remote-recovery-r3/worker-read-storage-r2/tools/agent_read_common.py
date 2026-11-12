"""Complete hia_read business owner: shared issued-state protocol.

NEW UNEXECUTED DEVELOPMENT. Inputs are private immutable Graph/value leases
issued by the fixed Worker and namespace peers. Header checks correlate those
leases; they do not authenticate arbitrary foreign bytes. This component owns
the complete read algorithm, but the ordinary high-level namespace peer remains
a separate, unfinished integration boundary.
"""
def magic(value):
    assert len(value)==8
    return int.from_bytes(value.encode('ascii'),'little')

CONSTANTS={
 'RD_COMMAND':magic('HIARDC01'),'RD_ACK':magic('HIARDA01'),
 'RD_EVENT':magic('HIARDE01'),'RD_STATE':magic('HIARDW01'),
 'RD_GRAPH_MAGIC':magic('HIAGRF01'),'RD_WIRE_COMMAND':magic('HIAGWC01'),
 'RD_WIRE_EVENT':magic('HIAGWE01'),'RD_BAD':0xfffffffd,
 'RD_MAX':(1<<64)-1,'RD_MIN':8192,'RD_CONFIG':128,'RD_RESPONSE':256,
 'RD_SAVED_CONFIG':1280,'RD_SAVED_SOURCE':1408,'RD_TEXT':1536,
 'RD_EVENT_BASE':2048,'RD_WIRE':2304,'RD_SAVED_ACK':2432,
 'RD_SAVED_REPLY':2560,'RD_CURSOR':3072,'RD_PAGE':8192,
 'RD_GRAPH_BASE':73728,'RD_MAX_ARTIFACT':67108864,
 'R_OFFSET_KIND':1200,'R_REQUEST_CONFIG_AT':1208,'R_REQUEST_CONFIG_BYTES':1216,
 'P_STORE_GET':1,'P_ARTIFACT_VIEW':2,'P_CURSOR_SELECT':3,
 'P_WIRE':4,'P_SHA256':5,'P_CURSOR_INSERT':6,
}
_NAMES=('MAGIC','STATUS','PHASE','SEQ','NEED','BAD_REASON','INV','CALL',
 'ARGS_LEASE','ROOT','OUT_LEASE','DIGITS','NODES','EDGES','EDGEBASE','DATABASE',
 'SOURCE_BYTES','REF','REF_ID','REF_SHA','CURSOR','MAX_BYTES','PEER','PENDING',
 'HAVE_REPLY','REPLY_BYTES','REPLY_LEASE','REPLY_AT','REPLY_SIZE','REPLY_PREFIX',
 'ARTIFACT_LEASE','ARTIFACT_SIZE','OFFSET_SIGN','OFFSET_MAG','LIMIT',
 'SLICE_START','CHUNK_BYTES','ENCODING','CONTENT_BYTES','CONTENT_CHARS',
 'WIRE_FIRST','NEXT_SIGN','NEXT_MAG','HAS_CURSOR','GRAPH_NODES','GRAPH_EDGES',
 'GRAPH_DATABASE','GRAPH_USED','GRAPH_BYTES','GRAPH_ROOT','GRAPH_GENERATION',
 'REQUEST_OWNER','REQUEST_AT','REQUEST_BYTES','REQUEST_ROOT','REQUEST_LEASE',
 'REQUEST_OP','NEXT_UTF8','UTF8_CHARS','ERROR_CLASS','ERROR_BYTES',
 'ERROR_OWNER','ERROR_LEASE','ERROR_AT','ALLOWED_ROLE','ACTIVE_ROLE')
CONSTANTS.update({'R_'+name:512+8*i for i,name in enumerate(_NAMES)})
# The two fixed namespace operation numbers are deliberately not guessed here.
# The generator requires a separate exact-ABI compile-time binding.
NAMESPACE_SQL={
 'OP_CURSOR_SELECT':('SELECT * FROM cursors WHERE id=?',1),
 'OP_CURSOR_INSERT':('INSERT OR IGNORE INTO cursors VALUES (?,?,?,?)',4),
}
LITERALS={
 1:b'artifact',2:b'id',3:b'sha256',4:b'uri',5:b'cursor',6:b'max_bytes',
 7:b'offset',8:b'encoding',9:b'content',10:b'next_cursor',
 11:b'utf8',12:b'base64',
 20:b'cursor is not bound to this exact artifact',
 21:b"unsupported operand type(s) for +: 'NoneType' and 'int'",
 22:b'slice indices must be integers or None or have an __index__ method',
 23:b'can only concatenate str (not "int") to str',
 24:b"can't concat int to bytes",
}

COMMON=r'''
def rd_entry(g:readbuf, r:readbuf, w:mutbuf, role:u64) -> u32:
    if length(w) < RD_MIN:
        return RD_BAD
    if rd_get(w, R_STATUS) >= 3:
        return RD_BAD
    if rd_get(w, R_MAGIC) == 0:
        if role != 1 or rd_initial(g, r, w) == 0:
            return rd_refuse(w, 1)
    else:
        if rd_get(w, R_MAGIC) != RD_STATE or rd_get(w, R_ALLOWED_ROLE) != role:
            return rd_refuse(w, 2)
        if rd_same_source(g, w) == 0:
            return rd_refuse(w, 3)
    rd_put(w, R_ACTIVE_ROLE, role)
    if rd_get(w, R_STATUS) == 2:
        if rd_receive(r, w) == 0:
            return rd_refuse(w, 4)
    elif rd_get(w, R_HAVE_REPLY) != 0:
        if rd_same_reply(r, w) == 0:
            return rd_refuse(w, 5)
    while rd_get(w, R_STATUS) == 1:
        if rd_get(w, R_BAD_REASON) != 0:
            return rd_refuse(w, rd_get(w, R_BAD_REASON))
        wanted = rd_wanted(w)
        if wanted != role:
            rd_put(w, R_ALLOWED_ROLE, wanted)
            return rd_event(w, 4)
        rd_put(w, R_NEED, 0)
        rd_step(g, r, w)
        if rd_get(w, R_NEED) > length(w):
            return rd_event(w, 1)
    if rd_get(w, R_STATUS) == 2:
        return rd_event(w, 2)
    if rd_get(w, R_STATUS) == 3:
        return rd_event(w, 0)
    if rd_get(w, R_STATUS) == 4 or rd_get(w, R_STATUS) == 5:
        return rd_event(w, 3)
    return rd_refuse(w, rd_get(w, R_BAD_REASON))

def rd_wanted(w:mutbuf) -> u64:
    phase = rd_get(w, R_PHASE)
    if phase == 20 or phase == 21:
        return 2
    return 1

def rd_initial(g:readbuf, r:readbuf, w:mutbuf) -> u64:
    if length(r) != 0 or length(g) < 64:
        return 0
    if rd_get(w, RD_CONFIG) != RD_COMMAND:
        return 0
    i = 0
    while i < RD_MIN:
        if i < RD_CONFIG or i >= RD_CONFIG + 128:
            if byte(w, i) != 0:
                return 0
        i = i + 1
    i = 136
    while i < 176:
        if rd_get(w, i) == 0:
            return 0
        i = i + 8
    digits = rd_get(w, 176)
    if digits != 0 and digits < 640:
        return 0
    i = 184
    while i < 256:
        if rd_get(w, i) != 0:
            return 0
        i = i + 8
    if rd_word(g, 0) != RD_GRAPH_MAGIC or rd_word(g, 56) != 0:
        return 0
    if rd_word(g, 8) != rd_get(w, 152):
        return 0
    nodes = rd_word(g, 16)
    edges = rd_word(g, 32)
    if nodes == 0 or nodes > (RD_MAX - 64) >> 6:
        return 0
    edgebase = 64 + nodes * 64
    if edges > (RD_MAX - edgebase) >> 3:
        return 0
    database = edgebase + edges * 8
    if database > length(g) or rd_word(g, 48) != length(g):
        return 0
    if rd_word(g, 40) != length(g) - database:
        return 0
    if rd_word(g, 24) == 0 or rd_word(g, 24) > nodes:
        return 0
    root = rd_get(w, 160)
    if root == 0 or root > nodes:
        return 0
    rd_put(w, R_MAGIC, RD_STATE)
    rd_put(w, R_STATUS, 1)
    rd_put(w, R_PHASE, 1)
    rd_put(w, R_ALLOWED_ROLE, 1)
    rd_put(w, R_INV, rd_get(w, 136))
    rd_put(w, R_CALL, rd_get(w, 144))
    rd_put(w, R_ARGS_LEASE, rd_get(w, 152))
    rd_put(w, R_ROOT, root)
    rd_put(w, R_OUT_LEASE, rd_get(w, 168))
    rd_put(w, R_DIGITS, digits)
    rd_put(w, R_NODES, nodes)
    rd_put(w, R_EDGES, edges)
    rd_put(w, R_EDGEBASE, edgebase)
    rd_put(w, R_DATABASE, database)
    rd_put(w, R_SOURCE_BYTES, length(g))
    copy_bytes(w, g, RD_SAVED_SOURCE, 0, 64)
    i = 0
    while i < 128:
        store(w, RD_SAVED_CONFIG + i, byte(w, RD_CONFIG + i))
        i = i + 1
    if rd_kind(g, w, root) != 6:
        return 0
    ref = rd_field(g, w, root, 1)
    if rd_kind(g, w, ref) != 6:
        return 0
    at = rd_node(g, w, ref)
    if rd_word(g, at + 32) != 3:
        return 0
    ident = rd_field(g, w, ref, 2)
    digest = rd_field(g, w, ref, 3)
    uri = rd_field(g, w, ref, 4)
    if rd_kind(g, w, ident) != 4 or rd_kind(g, w, digest) != 4 or rd_kind(g, w, uri) != 4:
        return 0
    rd_put(w, R_REF, ref)
    rd_put(w, R_REF_ID, ident)
    rd_put(w, R_REF_SHA, digest)
    rd_put(w, R_CURSOR, rd_field(g, w, root, 5))
    rd_put(w, R_MAX_BYTES, rd_field(g, w, root, 6))
    return choose(rd_get(w, R_BAD_REASON) == 0, 1, 0)

def rd_same_source(g:readbuf, w:mutbuf) -> u64:
    if length(g) != rd_get(w, R_SOURCE_BYTES):
        return 0
    i = 0
    while i < 64:
        if byte(g, i) != byte(w, RD_SAVED_SOURCE + i):
            return 0
        i = i + 1
    i = 0
    while i < 128:
        if byte(w, RD_CONFIG + i) != byte(w, RD_SAVED_CONFIG + i):
            return 0
        i = i + 1
    return 1

def rd_receive(r:readbuf, w:mutbuf) -> u64:
    if rd_get(w, RD_RESPONSE) != RD_ACK:
        return 0
    if rd_get(w, RD_RESPONSE + 8) != rd_get(w, R_INV) or rd_get(w, RD_RESPONSE + 16) != rd_get(w, R_CALL):
        return 0
    if rd_get(w, RD_RESPONSE + 24) != rd_get(w, R_PENDING):
        return 0
    if rd_get(w, RD_RESPONSE + 32) != rd_get(w, R_PEER):
        return 0
    if rd_get(w, RD_RESPONSE + 40) > 1 or rd_get(w, RD_RESPONSE + 120) != 0:
        return 0
    if rd_get(w, RD_RESPONSE + 56) == 0 or rd_get(w, RD_RESPONSE + 64) != length(r):
        return 0
    begin = rd_get(w, RD_RESPONSE + 72)
    size = rd_get(w, RD_RESPONSE + 80)
    if begin > length(r) or size > length(r) - begin:
        return 0
    i = 88
    while i < 120:
        if rd_get(w, RD_RESPONSE + i) != 0:
            return 0
        i = i + 8
    rd_put(w, R_REPLY_BYTES, length(r))
    rd_put(w, R_REPLY_LEASE, rd_get(w, RD_RESPONSE + 56))
    rd_put(w, R_REPLY_AT, begin)
    rd_put(w, R_REPLY_SIZE, size)
    prefix = choose(length(r) < 64, length(r), 64)
    rd_put(w, R_REPLY_PREFIX, prefix)
    copy_bytes(w, r, RD_SAVED_REPLY, 0, prefix)
    i = 0
    while i < 128:
        store(w, RD_SAVED_ACK + i, byte(w, RD_RESPONSE + i))
        i = i + 1
    rd_put(w, R_HAVE_REPLY, 1)
    rd_put(w, R_STATUS, 1)
    if rd_get(w, RD_RESPONSE + 40) != 0:
        rd_put(w, R_ERROR_CLASS, 0)
        rd_put(w, R_ERROR_OWNER, 2)
        rd_put(w, R_ERROR_LEASE, rd_get(w, R_REPLY_LEASE))
        rd_put(w, R_ERROR_AT, begin)
        rd_put(w, R_ERROR_BYTES, size)
        rd_put(w, R_STATUS, 5)
    return 1

def rd_same_reply(r:readbuf, w:mutbuf) -> u64:
    if length(r) != rd_get(w, R_REPLY_BYTES):
        return 0
    i = 0
    while i < 128:
        if byte(w, RD_RESPONSE + i) != byte(w, RD_SAVED_ACK + i):
            return 0
        i = i + 1
    i = 0
    while i < rd_get(w, R_REPLY_PREFIX):
        if byte(r, i) != byte(w, RD_SAVED_REPLY + i):
            return 0
        i = i + 1
    return 1

def rd_request(w:mutbuf, peer:u64, phase:u64, owner:u64, begin:u64, size:u64, root:u64, lease:u64, op:u64) -> u64:
    rd_put(w, R_PEER, peer)
    rd_put(w, R_PHASE, phase)
    rd_put(w, R_STATUS, 2)
    rd_put(w, R_HAVE_REPLY, 0)
    rd_put(w, R_REQUEST_OWNER, owner)
    rd_put(w, R_REQUEST_AT, begin)
    rd_put(w, R_REQUEST_BYTES, size)
    rd_put(w, R_REQUEST_ROOT, root)
    rd_put(w, R_REQUEST_LEASE, lease)
    rd_put(w, R_REQUEST_OP, op)
    rd_put(w, R_REQUEST_CONFIG_AT, 0)
    rd_put(w, R_REQUEST_CONFIG_BYTES, 0)
    return 0

def rd_event(w:mutbuf, action:u64) -> u32:
    if rd_get(w, R_SEQ) == RD_MAX:
        rd_put(w, R_STATUS, 6)
        return RD_BAD
    rd_put(w, R_SEQ, rd_get(w, R_SEQ) + 1)
    if action == 2:
        rd_put(w, R_PENDING, rd_get(w, R_SEQ))
    rd_put(w, RD_EVENT_BASE, RD_EVENT)
    rd_put(w, RD_EVENT_BASE + 8, action)
    rd_put(w, RD_EVENT_BASE + 16, rd_get(w, R_INV))
    rd_put(w, RD_EVENT_BASE + 24, rd_get(w, R_CALL))
    rd_put(w, RD_EVENT_BASE + 32, rd_get(w, R_SEQ))
    rd_put(w, RD_EVENT_BASE + 40, rd_get(w, R_ARGS_LEASE))
    rd_put(w, RD_EVENT_BASE + 48, rd_get(w, R_PHASE))
    rd_put(w, RD_EVENT_BASE + 56, rd_get(w, R_ALLOWED_ROLE))
    rd_put(w, RD_EVENT_BASE + 64, choose(action == 1, rd_get(w, R_NEED), 0))
    rd_put(w, RD_EVENT_BASE + 72, choose(action == 2, rd_get(w, R_PEER), 0))
    rd_put(w, RD_EVENT_BASE + 80, choose(action == 2, rd_get(w, R_PENDING), 0))
    rd_put(w, RD_EVENT_BASE + 88, choose(action == 2, rd_get(w, R_REQUEST_OWNER), 0))
    rd_put(w, RD_EVENT_BASE + 96, choose(action == 2, rd_get(w, R_REQUEST_AT), 0))
    rd_put(w, RD_EVENT_BASE + 104, choose(action == 2, rd_get(w, R_REQUEST_BYTES), 0))
    rd_put(w, RD_EVENT_BASE + 112, choose(action == 2, rd_get(w, R_REQUEST_ROOT), 0))
    rd_put(w, RD_EVENT_BASE + 120, choose(action == 2, rd_get(w, R_REQUEST_LEASE), 0))
    rd_put(w, RD_EVENT_BASE + 128, choose(action == 2, rd_get(w, R_REQUEST_OP), 0))
    rd_put(w, RD_EVENT_BASE + 136, choose(action == 0, RD_GRAPH_BASE, 0))
    rd_put(w, RD_EVENT_BASE + 144, choose(action == 0, rd_get(w, R_GRAPH_BYTES), 0))
    rd_put(w, RD_EVENT_BASE + 152, rd_get(w, R_OUT_LEASE))
    rd_put(w, RD_EVENT_BASE + 160, rd_get(w, R_GRAPH_GENERATION))
    rd_put(w, RD_EVENT_BASE + 168, choose(action == 3, rd_get(w, R_ERROR_CLASS), 0))
    rd_put(w, RD_EVENT_BASE + 176, choose(action == 3, rd_get(w, R_ERROR_OWNER), 0))
    rd_put(w, RD_EVENT_BASE + 184, choose(action == 3, rd_get(w, R_ERROR_LEASE), 0))
    rd_put(w, RD_EVENT_BASE + 192, choose(action == 3, rd_get(w, R_ERROR_AT), 0))
    rd_put(w, RD_EVENT_BASE + 200, choose(action == 3, rd_get(w, R_ERROR_BYTES), 0))
    rd_put(w, RD_EVENT_BASE + 208, rd_get(w, R_BAD_REASON))
    rd_put(w, RD_EVENT_BASE + 216, rd_get(w, R_ARTIFACT_LEASE))
    rd_put(w, RD_EVENT_BASE + 224, rd_get(w, R_ARTIFACT_SIZE))
    rd_put(w, RD_EVENT_BASE + 232, choose(action == 2, rd_get(w, R_REQUEST_CONFIG_AT), 0))
    rd_put(w, RD_EVENT_BASE + 240, choose(action == 2, rd_get(w, R_REQUEST_CONFIG_BYTES), 0))
    rd_put(w, RD_EVENT_BASE + 248, 0)
    return 2304

def rd_badset(w:mutbuf, reason:u64) -> u64:
    if rd_get(w, R_BAD_REASON) == 0:
        rd_put(w, R_BAD_REASON, reason)
    rd_put(w, R_STATUS, 6)
    return 0

def rd_refuse(w:mutbuf, reason:u64) -> u32:
    rd_badset(w, reason)
    rd_event(w, 5)
    return RD_BAD

def rd_error(w:mutbuf, kind:u64, literal:u64) -> u64:
    size = rd_literal(w, literal, RD_TEXT)
    rd_put(w, R_ERROR_CLASS, kind)
    rd_put(w, R_ERROR_OWNER, 3)
    rd_put(w, R_ERROR_LEASE, rd_get(w, R_INV))
    rd_put(w, R_ERROR_AT, RD_TEXT)
    rd_put(w, R_ERROR_BYTES, size)
    rd_put(w, R_STATUS, 4)
    return 0

def rd_word(s:readbuf, at:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(s, at + i) << (i * 8))
        i = i + 1
    return value

def rd_get(w:mutbuf, at:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(w, at + i) << (i * 8))
        i = i + 1
    return value

def rd_put(w:mutbuf, at:u64, value:u64) -> u64:
    i = 0
    while i < 8:
        store(w, at + i, (value >> (i * 8)) & 255)
        i = i + 1
    return value
'''
