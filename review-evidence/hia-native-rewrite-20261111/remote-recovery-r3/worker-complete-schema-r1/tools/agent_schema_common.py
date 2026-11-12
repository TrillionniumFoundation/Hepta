"""Shared state and transport for the complete fixed-catalog schema owner.

r3 changes only the ASCII span inside complete initial UTF-8 validation. Every
byte and codepoint is still checked; V_NEXT is the exact last completed character
offset before a Unicode refusal, and the complete old/new workspace is compared.
Pending peers publish their actual request event. The four HIA images share one private growable workspace.
Only HIA chooses validation stages, peer requests, catch scopes and outcomes.
The caller supplies a private immutable issued HIAGRF01 containing both value
and catalog schemas. No host schema walker or generic semantic plan is allowed.
"""
CONSTANTS={
 'SV_COMMAND':int.from_bytes(b'HIASVC01','little'),
 'SV_ACK':int.from_bytes(b'HIASVA01','little'),
 'SV_EVENT':int.from_bytes(b'HIASVE01','little'),
 'SV_STATE':int.from_bytes(b'HIASVS01','little'),
 'SV_GRAPH':int.from_bytes(b'HIAGRF01','little'),
 'SV_WIRE_COMMAND':int.from_bytes(b'HIAGWC01','little'),
 'SV_WIRE_EVENT':int.from_bytes(b'HIAGWE01','little'),
 'SV_PATTERN_COMMAND':int.from_bytes(b'HIARXC01','little'),
 'SV_PATTERN_EVENT':int.from_bytes(b'HIARXR01','little'),
 'SV_BAD':0xfffffffd,'SV_MAX':(1<<64)-1,'SV_MIN':4096,
 'SV_FRAME_BYTES':192,'SV_EVENT_BASE':2048,'SV_EVENT_END':2304,
 'SV_SAVED_COMMAND':1024,'SV_SAVED_HEADER':1152,'SV_SAVED_ACK':1216,
 'SV_SAVED_PEER_HEADER':1280,'SV_WIRE':1536,'SV_ACK_BASE':256,
}
_NAMES=('MAGIC','STATUS','FLOW','BAD','NEED','LEASE','CALL','GRAPH_LEASE','DIGITS',
        'NODES','EDGES','EDGEBASE','DATABASE','TOTAL','ROOT_VALUE','ROOT_SCHEMA',
        'ROOT_LABEL','MODE','HEAP','FRAME','SEQ','REQ_SEQ','PEER','PEER_ROOT',
        'PEER_WIRE','PEER_WIRE_BYTES','RESPONSE_ACTIVE','RESPONSE_BYTES',
        'RESPONSE_HEADER_BYTES','RESPONSE_OUT','RESPONSE_SIZE','PATTERN_MATCH',
        'ALLOWED_ROLE','ROLE','ERROR_DOMAIN','ERROR_REASON','ERROR_FRAME','ERROR_ARG',
        'ERROR_PTR','ERROR_BYTES','NEXT','TEMP','INITIALIZED','PEAK_HEAP','PATTERN_ID','PATTERN_BYTES')
CONSTANTS.update({'V_'+name:512+8*i for i,name in enumerate(_NAMES)})
_FRAME_NAMES=('PARENT','MARK','VALUE','SCHEMA','PATH','STAGE','INDEX','LIST','MATCHES',
              'SELECTED','WIRE_AT','WIRE_BYTES','TEMP_MARK','AUX','AUX2','AUX3',
              'CATCH','SUBRESULT','EXTRA','EXTRA2','EXTRA3','EXTRA4','EXTRA5','EXTRA6')
CONSTANTS.update({'F_'+name:i*8 for i,name in enumerate(_FRAME_NAMES)})
KEYWORDS=('type','const','enum','oneOf','anyOf','allOf','not','if','then','else',
          'required','properties','additionalProperties','minProperties','maxProperties',
          'minItems','maxItems','uniqueItems','items','contains','minLength','maxLength',
          'pattern','minimum','maximum','$schema','description','title')
CONSTANTS.update({'K_'+name.replace('$',''):i+1 for i,name in enumerate(KEYWORDS)})
TYPE_NAMES=('object','array','string','integer','number','boolean','null')
CONSTANTS.update({'T_'+name:101+i for i,name in enumerate(TYPE_NAMES)})
GRAPH_FUNCTIONS=('node','edge','unit')
GRAPH_RENAMES={'node':'sv_node','edge':'sv_edge','unit':'sv_unit','read':'sn_word',
               'get':'sv_get','put':'sv_put','abi':'sv_badset','MAX':'SV_MAX',
               'S_NODES':'V_NODES','S_EDGES':'V_EDGES','S_DATABASE':'V_DATABASE',
               'S_EDGEBASE':'V_EDGEBASE','S_NEXT':'V_NEXT'}

COMMON=r'''
def sv_entry(g:readbuf, r:readbuf, w:mutbuf, role:u64) -> u32:
    if length(w) < SV_MIN:
        return SV_BAD
    if sv_get(w, V_STATUS) >= 3:
        return SV_BAD
    if sv_get(w, V_MAGIC) == 0:
        if role != 1 or sv_initial(g, r, w) == 0:
            return sv_refuse(w, 1)
    else:
        if sv_get(w, V_MAGIC) != SV_STATE or sv_get(w, V_ALLOWED_ROLE) != role:
            return sv_refuse(w, 2)
        if sv_same_graph(g, w) == 0:
            return sv_refuse(w, 3)
    sv_put(w, V_ROLE, role)
    if sv_get(w, V_STATUS) == 2:
        if sv_receive(r, w) == 0:
            return sv_refuse(w, 4)
    elif sv_get(w, V_RESPONSE_ACTIVE) != 0:
        if sv_same_peer(r, w) == 0:
            return sv_refuse(w, 5)
    while sv_get(w, V_STATUS) == 1:
        if sv_get(w, V_BAD) != 0:
            return sv_refuse(w, sv_get(w, V_BAD))
        if sv_get(w, V_INITIALIZED) == 0:
            if sv_root(g, w) == 0:
                return sv_pending(w)
        wanted = sv_wanted(w)
        if wanted != role:
            return sv_event(w, 4, wanted)
        result = sv_step(g, r, w)
        if result != 0:
            return result
        if sv_get(w, V_NEED) > length(w):
            return sv_pending(w)
    if sv_get(w, V_STATUS) == 2:
        return sv_event(w, 3, role)
    if sv_get(w, V_STATUS) == 3:
        return sv_event(w, 0, 0)
    if sv_get(w, V_STATUS) == 4 or sv_get(w, V_STATUS) == 5:
        return sv_event(w, 2, 0)
    return sv_refuse(w, 6)

def sv_initial(g:readbuf, r:readbuf, w:mutbuf) -> u64:
    if length(g) < 64 or length(r) != 128:
        return 0
    if sn_word(r, 0) != SV_COMMAND or sn_word(r, 8) == 0 or sn_word(r, 16) == 0:
        return 0
    if sn_word(g, 0) != SV_GRAPH or sn_word(g, 8) == 0 or sn_word(g, 56) != 0:
        return 0
    if sn_word(r, 24) != sn_word(g, 8) or sn_word(r, 64) > 1:
        return 0
    position = 72
    while position < 128:
        if sn_word(r, position) != 0:
            return 0
        position = position + 8
    position = 0
    while position < SV_MIN:
        if byte(w, position) != 0:
            return 0
        position = position + 1
    nodes = sn_word(g, 16)
    edges = sn_word(g, 32)
    if nodes == 0 or nodes > (SV_MAX - 64) >> 6:
        return 0
    edgebase = 64 + nodes * 64
    if edges > (SV_MAX - edgebase) >> 3:
        return 0
    database = edgebase + edges * 8
    if database > length(g) or sn_word(g, 48) != length(g):
        return 0
    if sn_word(g, 40) != length(g) - database:
        return 0
    if sn_word(g, 24) == 0 or sn_word(g, 24) > nodes:
        return 0
    if sn_word(r, 40) == 0 or sn_word(r, 40) > nodes or sn_word(r, 48) > nodes:
        return 0
    if sn_word(r, 64) == 0:
        if sn_word(r, 32) == 0 or sn_word(r, 32) > nodes:
            return 0
    sv_put(w, V_MAGIC, SV_STATE)
    sv_put(w, V_STATUS, 1)
    sv_put(w, V_LEASE, sn_word(r, 8))
    sv_put(w, V_CALL, sn_word(r, 16))
    sv_put(w, V_GRAPH_LEASE, sn_word(r, 24))
    sv_put(w, V_ROOT_VALUE, sn_word(r, 32))
    sv_put(w, V_ROOT_SCHEMA, sn_word(r, 40))
    sv_put(w, V_ROOT_LABEL, sn_word(r, 48))
    sv_put(w, V_DIGITS, sn_word(r, 56))
    sv_put(w, V_MODE, sn_word(r, 64))
    sv_put(w, V_NODES, nodes)
    sv_put(w, V_EDGES, edges)
    sv_put(w, V_EDGEBASE, edgebase)
    sv_put(w, V_DATABASE, database)
    sv_put(w, V_TOTAL, length(g))
    sv_put(w, V_HEAP, SV_MIN)
    sv_put(w, V_ALLOWED_ROLE, 1)
    copy_bytes(w, r, SV_SAVED_COMMAND, 0, 128)
    copy_bytes(w, g, SV_SAVED_HEADER, 0, 64)
    identifier = 1
    while identifier <= nodes:
        at = sv_node(g, w, identifier)
        if at == 0:
            return 0
        kind = sn_word(g, at)
        if kind == 4:
            if sv_string_valid(g, w, at) == 0:
                return 0
        elif kind == 5 or kind == 6 or kind == 7:
            count = sn_word(g, at + 32)
            if kind == 6:
                count = count * 2
            index = 0
            while index < count:
                if sv_edge(g, w, at, index) == 0:
                    return 0
                index = index + 1
        identifier = identifier + 1
    if sv_get(w, V_ROOT_LABEL) != 0:
        if sv_kind(g, w, sv_get(w, V_ROOT_LABEL)) != 4:
            return 0
    return 1

def sv_same_graph(g:readbuf, w:mutbuf) -> u64:
    if length(g) != sv_get(w, V_TOTAL):
        return 0
    index = 0
    while index < 64:
        if byte(g, index) != byte(w, SV_SAVED_HEADER + index):
            return 0
        index = index + 1
    return 1

def sv_string_valid(g:readbuf, w:mutbuf, at:u64) -> u64:
    position = sn_word(g, at + 8)
    end = position + sn_word(g, at + 16)
    count = 0
    while position < end:
        if byte(g, position) < 128:
            while position < end and byte(g, position) < 128:
                count = count + 1
                position = position + 1
            sv_put(w, V_NEXT, position)
        else:
            if sv_unit(g, w, position, end) == SV_MAX:
                return 0
            count = count + 1
            position = sv_get(w, V_NEXT)
    return choose(count == sn_word(g, at + 48), 1, 0)

def sv_kind(g:readbuf, w:mutbuf, identifier:u64) -> u64:
    at = sv_node(g, w, identifier)
    if at == 0:
        return SV_MAX
    return sn_word(g, at)

def sv_item(g:readbuf, w:mutbuf, identifier:u64, index:u64) -> u64:
    at = sv_node(g, w, identifier)
    if at == 0:
        return 0
    return sv_edge(g, w, at, index)

def sv_count(g:readbuf, w:mutbuf, identifier:u64) -> u64:
    at = sv_node(g, w, identifier)
    if at == 0:
        return 0
    kind = sn_word(g, at)
    if kind == 5 or kind == 6 or kind == 7:
        return sn_word(g, at + 32)
    return sv_badset(w, 20)

def sv_field(g:readbuf, w:mutbuf, identifier:u64, key:u64) -> u64:
    at = sv_node(g, w, identifier)
    if at == 0:
        return 0
    if sn_word(g, at) != 6:
        return 0
    count = sn_word(g, at + 32)
    index = 0
    while index < count:
        name = sv_edge(g, w, at, index * 2)
        if name == 0:
            return 0
        if sv_named(g, w, name, key) != 0:
            return sv_edge(g, w, at, index * 2 + 1)
        index = index + 1
    return 0

def sv_string_equal(g:readbuf, w:mutbuf, left:u64, right:u64) -> u64:
    a = sv_node(g, w, left)
    b = sv_node(g, w, right)
    if a == 0 or b == 0:
        return 0
    if sn_word(g, a) != 4 or sn_word(g, b) != 4:
        return 0
    size = sn_word(g, a + 16)
    if size != sn_word(g, b + 16):
        return 0
    ap = sn_word(g, a + 8)
    bp = sn_word(g, b + 8)
    index = 0
    while index < size:
        if byte(g, ap + index) != byte(g, bp + index):
            return 0
        index = index + 1
    return 1

def sv_find_key(g:readbuf, w:mutbuf, object:u64, key:u64) -> u64:
    at = sv_node(g, w, object)
    if at == 0:
        return 0
    if sn_word(g, at) != 6:
        return 0
    count = sn_word(g, at + 32)
    index = 0
    while index < count:
        other = sv_edge(g, w, at, index * 2)
        if other == 0:
            return 0
        if sv_string_equal(g, w, other, key) != 0:
            return sv_edge(g, w, at, index * 2 + 1)
        index = index + 1
    return 0

def sv_truth(g:readbuf, w:mutbuf, identifier:u64) -> u64:
    at = sv_node(g, w, identifier)
    if at == 0:
        return 0
    kind = sn_word(g, at)
    if kind == 0:
        return 0
    if kind == 1:
        return sn_word(g, at + 48)
    if kind == 2 or kind == 4 or kind == 9:
        return choose(sn_word(g, at + 16) != 0, 1, 0)
    if kind == 3:
        return choose((sn_word(g, sn_word(g, at + 8)) & 9223372036854775807) != 0, 1, 0)
    if kind == 5 or kind == 6 or kind == 7:
        return choose(sn_word(g, at + 32) != 0, 1, 0)
    return 1

def sv_require(w:mutbuf, size:u64) -> u64:
    current = sv_get(w, V_HEAP)
    if size > SV_MAX - current:
        return sv_badset(w, 21)
    needed = current + size
    if needed > length(w):
        sv_put(w, V_NEED, needed)
        return 0
    sv_put(w, V_NEED, 0)
    return 1

def sv_alloc(w:mutbuf, size:u64) -> u64:
    if sv_require(w, size) == 0:
        return 0
    start = sv_get(w, V_HEAP)
    sv_put(w, V_HEAP, start + size)
    if start + size > sv_get(w, V_PEAK_HEAP):
        sv_put(w, V_PEAK_HEAP, start + size)
    return start

def sv_root(g:readbuf, w:mutbuf) -> u64:
    if sv_require(w, SV_FRAME_BYTES + 32) == 0:
        return 0
    mark = sv_get(w, V_HEAP)
    path = sv_alloc(w, 32)
    label = sv_get(w, V_ROOT_LABEL)
    sv_put(w, path, 0)
    sv_put(w, path + 8, choose(label == 0, 3, 0))
    sv_put(w, path + 16, label)
    size = 9
    if label != 0:
        at = sv_node(g, w, label)
        if at == 0:
            return 0
        size = sn_word(g, at + 16)
    sv_put(w, path + 24, size)
    frame = sv_alloc(w, SV_FRAME_BYTES)
    fill_range(w, frame, SV_FRAME_BYTES, 0)
    sv_put(w, frame + F_MARK, mark)
    sv_put(w, frame + F_VALUE, sv_get(w, V_ROOT_VALUE))
    sv_put(w, frame + F_SCHEMA, sv_get(w, V_ROOT_SCHEMA))
    sv_put(w, frame + F_PATH, path)
    sv_put(w, frame + F_STAGE, choose(sv_get(w, V_MODE) == 0, 100, 800))
    sv_put(w, V_FRAME, frame)
    sv_put(w, V_INITIALIZED, 1)
    return 1

def sv_push(g:readbuf, w:mutbuf, value:u64, schema:u64, path_mode:u64, key:u64, catching:u64, next_stage:u64, start_stage:u64) -> u64:
    if schema == 0 or schema > sv_get(w, V_NODES):
        return sv_badset(w, 22)
    if start_stage < 800:
        if value == 0 or value > sv_get(w, V_NODES):
            return sv_badset(w, 23)
    extra = choose(path_mode == 0, 0, 32)
    if sv_require(w, SV_FRAME_BYTES + extra) == 0:
        return 0
    parent = sv_get(w, V_FRAME)
    mark = sv_get(w, V_HEAP)
    path = sv_get(w, parent + F_PATH)
    if path_mode != 0:
        path = sv_new_path(g, w, path, path_mode, key)
        if path == 0:
            return 0
    frame = sv_alloc(w, SV_FRAME_BYTES)
    fill_range(w, frame, SV_FRAME_BYTES, 0)
    sv_put(w, frame + F_PARENT, parent)
    sv_put(w, frame + F_MARK, mark)
    sv_put(w, frame + F_VALUE, value)
    sv_put(w, frame + F_SCHEMA, schema)
    sv_put(w, frame + F_PATH, path)
    sv_put(w, frame + F_CATCH, catching)
    sv_put(w, frame + F_STAGE, start_stage)
    sv_put(w, parent + F_STAGE, next_stage)
    sv_put(w, V_FRAME, frame)
    return 1

def sv_new_path(g:readbuf, w:mutbuf, parent:u64, kind:u64, value:u64) -> u64:
    size = 0
    if kind == 1:
        at = sv_node(g, w, value)
        if at == 0 or sn_word(g, at) != 4:
            return sv_badset(w, 24)
        size = sn_word(g, at + 16) + 1
    elif kind == 2:
        size = sv_decimal_size(value) + 2
    elif kind == 3:
        size = 9
    else:
        return sv_badset(w, 25)
    total = size
    if kind != 3:
        previous = sv_get(w, parent + 24)
        if size > SV_MAX - previous:
            return sv_badset(w, 26)
        total = previous + size
    path = sv_alloc(w, 32)
    if path == 0:
        return 0
    sv_put(w, path, choose(kind == 3, 0, parent))
    sv_put(w, path + 8, kind)
    sv_put(w, path + 16, value)
    sv_put(w, path + 24, total)
    return path

def sv_pop(w:mutbuf, accepted:u64) -> u64:
    frame = sv_get(w, V_FRAME)
    parent = sv_get(w, frame + F_PARENT)
    mark = sv_get(w, frame + F_MARK)
    if parent == 0:
        sv_put(w, V_STATUS, 3)
        return 0
    sv_put(w, V_FRAME, parent)
    sv_put(w, V_HEAP, mark)
    sv_put(w, parent + F_SUBRESULT, accepted)
    return 0

def sv_wanted(w:mutbuf) -> u64:
    if sv_get(w, V_FLOW) == 80:
        return 4
    phase = sv_get(w, sv_get(w, V_FRAME) + F_STAGE)
    if phase >= 100 and phase < 200:
        return 1
    if phase >= 200 and phase < 400:
        return 2
    if phase >= 400 and phase < 600:
        return 3
    if phase >= 600 and phase < 700:
        return 1
    if phase >= 800 and phase < 900:
        return 2
    sv_badset(w, 27)
    return 0

def sv_failure(w:mutbuf, domain:u64, reason:u64, argument:u64) -> u64:
    sv_put(w, V_ERROR_DOMAIN, domain)
    sv_put(w, V_ERROR_REASON, reason)
    sv_put(w, V_ERROR_FRAME, sv_get(w, V_FRAME))
    sv_put(w, V_ERROR_ARG, argument)
    sv_put(w, V_FLOW, 80)
    return 0

def sv_after_error(w:mutbuf) -> u64:
    if sv_get(w, V_ERROR_DOMAIN) == 1:
        frame = sv_get(w, V_FRAME)
        while frame != 0:
            if sv_get(w, frame + F_CATCH) != 0:
                parent = sv_get(w, frame + F_PARENT)
                if parent == 0:
                    return sv_badset(w, 28)
                mark = sv_get(w, frame + F_MARK)
                sv_put(w, V_FRAME, parent)
                sv_put(w, V_HEAP, mark)
                sv_put(w, parent + F_SUBRESULT, 0)
                sv_put(w, V_FLOW, 0)
                sv_put(w, V_ERROR_DOMAIN, 0)
                sv_put(w, V_ERROR_REASON, 0)
                sv_put(w, V_ERROR_PTR, 0)
                sv_put(w, V_ERROR_BYTES, 0)
                return 0
            frame = sv_get(w, frame + F_PARENT)
        sv_put(w, V_STATUS, 4)
    else:
        sv_put(w, V_STATUS, 5)
    return 0

def sv_badset(w:mutbuf, reason:u64) -> u64:
    if sv_get(w, V_BAD) == 0:
        sv_put(w, V_BAD, reason)
    return 0

def sv_refuse(w:mutbuf, reason:u64) -> u32:
    sv_badset(w, reason)
    sv_put(w, V_STATUS, 6)
    sv_event(w, 5, 0)
    return SV_BAD

def sv_pending(w:mutbuf) -> u32:
    if sv_get(w, V_BAD) != 0:
        return sv_refuse(w, sv_get(w, V_BAD))
    if sv_get(w, V_NEED) > length(w):
        return sv_event(w, 1, sv_get(w, V_ROLE))
    return sv_refuse(w, 29)

def sv_get(w:mutbuf, at:u64) -> u64:
    value = 0
    index = 0
    while index < 8:
        value = value | (byte(w, at + index) << (index * 8))
        index = index + 1
    return value

def sv_put(w:mutbuf, at:u64, value:u64) -> u64:
    index = 0
    while index < 8:
        store(w, at + index, (value >> (index * 8)) & 255)
        index = index + 1
    return value
'''
