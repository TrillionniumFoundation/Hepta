"""First-pass continuation body for the complete function-owner candidate.

This module is authoring input only. The production bridge does not import it.
Admission is not advertised or selected as an independent migrated owner: the
complete lowering pass and generic renderer are required for final selection.
"""

KEYS = ('schema', 'functions', 'name', 'params', 'returns', 'effects', 'entry',
        'blocks', 'id', 'ops', 'term', 'op', 'args', 'out', 'attrs', 'type',
        'target', 'cond', 'then', 'else', 'values', 'code', 'value', 'cases',
        'variant', 'field', 'mode', 'function', 'return_loans')
PRIMITIVES = ('bool', 'unit', 'i8', 'i16', 'i32', 'i64', 'u8', 'u16',
              'u32', 'u64', 'isize', 'usize', 'buffer', 'readbuf', 'mutbuf', 'chain')
LITERALS = tuple(dict.fromkeys((*KEYS, *PRIMITIVES,
    'record.make', 'record.unpack', 'record.get', 'record.borrow',
    'record.begin', 'record.take', 'record.insert', 'record.finish', 'record.abandon',
    'enum.make', 'enum.tag', 'task.create', 'task.state', 'task.start', 'task.poll',
    'task.cancel', 'task.join', 'task.close', 'call', 'const', 'owner.move',
    'owner.drop', 'loan.end', 'chain.try_push', 'chain.pop', 'buffer.try_new',
    'chain.empty', 'borrow.read', 'borrow.mut', 'compare.eq', 'jump', 'branch',
    'ret', 'trap', 'match', 'user', 'read', 'mut', 'start', 'poll', 'cancel',
    'join', 'close')))
ERRORS = {
    1: ('E_HIA_CFG', 'invalid nominal block inventory'),
    2: ('E_HIA_FORMAT', 'nominal block: expected exactly id, ops, params, term'),
    3: ('E_HIA_NAME', 'block: invalid/reserved ASCII identifier'),
    4: ('E_HIA_NAME', 'block: identifier uses the elaborator namespace'),
    5: ('E_HIA_CFG', 'duplicate nominal block'),
    6: ('E_HIA_FORMAT', 'block operations must be a list'),
    7: ('E_HIA_FORMAT', 'nominal instruction: expected exactly args, attrs, op, out'),
    8: ('E_HIA_FORMAT', 'invalid nominal instruction'),
    9: ('E_HIA_OPCODE', 'nominal operation is outside the selected input profile'),
    10: ('E_HIA_FORMAT', 'instruction arguments: expected value list'),
    11: ('E_HIA_NAME', 'instruction arguments: invalid/reserved ASCII identifier'),
    12: ('E_HIA_SSA', 'nominal SSA value defined twice'),
    13: ('E_HIA_NAME', 'entry: invalid/reserved ASCII identifier'),
    14: ('E_HIA_NAME', 'entry: identifier uses the elaborator namespace'),
    15: ('E_HIA_CFG', 'nominal entry parameters differ from signature'),
    16: ('E_HIA_LIMIT', 'nominal elaboration expansion budget exceeded'),
    17: ('E_HIA_LIMIT', 'nominal elaborated value-slot budget exceeded'),
}
CONSTANTS = {
    'ADMIT_MAGIC': int.from_bytes(b'HIAFAD01', 'little'),
    'RESPONSE_MAGIC': int.from_bytes(b'HIAFRS01', 'little'),
    'NEXT_MAGIC': int.from_bytes(b'HIAFNX01', 'little'),
    'TYPE_MAGIC': int.from_bytes(b'HIATYS01', 'little'),
    'TYPE_BYTES': 128 << 20, 'TS': 96 << 20, 'TYPES': (96 << 20) + 65536,
    'LIT_TABLE': 32768,
    **{'K_' + key: 1 << i for i, key in enumerate(KEYS)},
    **{'C_' + value.replace('.', '_'): i + 1 for i, value in enumerate(LITERALS)},
}

BODY = r'''
def function_admit(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < W_BYTES:
        return ABI
    if length(o) < 64 or get(w, S + 96) != 0:
        return fatal(w)
    if length(s) >= 16 and word(s, 0) == NEXT_MAGIC:
        if get(w, S) != STATE_MAGIC or get(w, S + 312) != 0:
            return fatal(w)
        if begin_next(s, w) == 0:
            return fatal(w)
        return admit_frame(o, w, 0)
    if length(s) == TYPE_BYTES:
        if get(w, S) != STATE_MAGIC or word(s, TS) != TYPE_MAGIC or word(s, TS + 48) != 1:
            return fatal(w)
        if get(w, S + 312) != 0 or get(w, S + 112) != 0 or get(w, S + 120) >= 100:
            return fatal(w)
        action = admit_run(s, w)
        return admit_frame(o, w, action)
    if length(s) >= 32 and word(s, 0) == RESPONSE_MAGIC:
        if get(w, S) != STATE_MAGIC or get(w, S + 312) != 2:
            return fatal(w)
        if word(s, 8) != get(w, S + 88) or word(s, 16) > 1:
            return fatal(w)
        count = word(s, 24)
        if count > 262144 or length(s) != 32 + count * 8:
            return fatal(w)
        if word(s, 16) == 1:
            if count != 0:
                return fatal(w)
            put(w, S + 112, 999)
            put(w, S + 312, 0)
            return admit_frame(o, w, 1)
        if count != g_count(w, get(w, S + 192)):
            return fatal(w)
        ids = allocate(w, count * 8)
        i = 0
        while i < count:
            identifier = word(s, 32 + i * 8)
            if identifier == 0 or identifier > 144:
                return fatal(w)
            put(w, ids + i * 8, identifier)
            i = i + 1
        put(w, S + 200, ids)
        put(w, S + 208, count)
        put(w, S + 312, 0)
        return admit_frame(o, w, 0)
    if get(w, S) != 0 or length(s) > I_BYTES:
        return fatal(w)
    if validate_packet(s, w) == 0:
        return fatal(w)
    i = 0
    while i < 384:
        put(w, S + i, 0)
        i = i + 8
    i = 0
    while i < length(s):
        store(w, SOURCE_BASE + i, byte(s, i))
        i = i + 1
    put(w, S, STATE_MAGIC)
    put(w, S + 8, ARENA)
    put(w, S + 16, length(s))
    put(w, S + 24, SOURCE_BASE)
    if initialize(w) == 0:
        return fatal(w)
    return admit_frame(o, w, 0)

def admit_frame(o:mutbuf, w:mutbuf, action:u64) -> u32:
    if get(w, S + 96) != 0:
        return ABI
    put(o, 0, ADMIT_MAGIC)
    put(o, 8, action)
    put(o, 16, get(w, S + 112))
    put(o, 24, get(w, S + 120))
    put(o, 32, get(w, S + 72))
    put(o, 40, get(w, S + 80))
    put(o, 48, get(w, S + 88))
    put(o, 56, 0)
    return 64

def initialize(w:mutbuf) -> u64:
    root = SOURCE_BASE
    if g_kind(w, root) != 5 or g_count(w, root) != 7:
        return 0
    document = g_at(w, root, 0)
    registry = g_at(w, root, 1)
    serial = g_integer(w, g_at(w, root, 3))
    slots = g_integer(w, g_at(w, root, 4))
    legacy = g_at(w, root, 5)
    index = g_integer(w, g_at(w, root, 6))
    functions = g_field(w, document, K_functions)
    if serial > 8192 or slots > 134250496 or g_kind(w, legacy) != 1:
        return 0
    if g_kind(w, functions) != 5 or index >= g_count(w, functions) or g_count(w, functions) > 1024:
        return 0
    if g_kind(w, registry) != 5 or g_count(w, registry) != g_count(w, functions):
        return 0
    put(w, S + 72, serial)
    put(w, S + 80, slots)
    put(w, S + 264, profile(w, g_field(w, document, K_schema)))
    put(w, S + 272, byte(w, legacy + 16))
    put(w, S + 288, registry)
    put(w, S + 296, g_at(w, root, 2))
    put(w, S + 352, document)
    if get(w, S + 264) == 0:
        return 0
    return select_function(w, index)

def select_function(w:mutbuf, index:u64) -> u64:
    functions = g_field(w, get(w, S + 352), K_functions)
    fn = g_at(w, functions, index)
    signature = g_at(w, get(w, S + 288), index)
    if g_kind(w, signature) != 5 or g_count(w, signature) != 3:
        return 0
    if same_text(w, g_field(w, fn, K_name), g_at(w, signature, 0)) == 0:
        return 0
    put(w, S + 128, fn)
    put(w, S + 136, signature)
    put(w, S + 144, g_field(w, fn, K_blocks))
    put(w, S + 280, index)
    put(w, S + 304, g_field(w, fn, K_name))
    put(w, S + 232, allocate(w, 8192 * 16))
    put(w, S + 240, allocate(w, 262144 * 16))
    return 1

def begin_next(s:readbuf, w:mutbuf) -> u64:
    size = word(s, 8)
    if size == 0 or size > 128 or length(s) != 16 + size:
        return 0
    ready = get(w, S + 120) == 0 and get(w, S + 88) == 0
    completed = get(w, S + 120) == 2000 and get(w, S + 48) == 1
    if ready == False and completed == False and get(w, S + 112) == 0:
        return 0
    if ready == False and get(w, S + 728) != 1:
        return 0
    functions = g_field(w, get(w, S + 352), K_functions)
    item = functions + 24
    index = 0
    selected = N
    while index < g_count(w, functions):
        if input_name_equal(s, w, g_field(w, item, K_name), size) != 0:
            selected = index
        item = g_end(w, item)
        index = index + 1
    if selected == N:
        return 0
    put(w, S + 8, ARENA)
    fill_range(w, S + 32, 40, 0)
    fill_range(w, S + 104, 160, 0)
    put(w, S + 280, 0)
    fill_range(w, S + 304, 48, 0)
    fill_range(w, S + 360, 688, 0)
    fill_range(w, LIT_TABLE, 1024, 0)
    fill_range(w, 34816, 1160, 0)
    return select_function(w, selected)

def input_name_equal(s:readbuf, w:mutbuf, node:u64, size:u64) -> u64:
    if g_kind(w, node) != 4 or g_size(w, node) != size:
        return 0
    i = 0
    while i < size:
        if byte(s, 16 + i) != byte(w, node + 16 + i):
            return 0
        i = i + 1
    return 1

def admit_run(s:readbuf, w:mutbuf) -> u64:
    while get(w, S + 112) == 0 and get(w, S + 96) == 0:
        phase = get(w, S + 120)
        if phase == 0:
            blocks = get(w, S + 144)
            if g_kind(w, blocks) != 5 or g_count(w, blocks) == 0 or g_count(w, blocks) > 4096:
                return fail(w, 1)
            put(w, S + 152, blocks + 24)
            put(w, S + 160, g_count(w, blocks))
            put(w, S + 120, 1)
        elif phase == 1:
            if get(w, S + 160) == 0:
                put(w, S + 120, 5)
            else:
                if begin_block(w) == 0:
                    return 1
                return request_parameters(w, g_field(w, get(w, S + 152), K_params), 2)
        elif phase == 2:
            if reserve_response(s, w) == 0:
                return 1
            if add_response_values(s, w, 1) == 0:
                return 1
            ops = g_field(w, get(w, S + 152), K_ops)
            if g_kind(w, ops) != 5:
                return fail(w, 6)
            put(w, S + 176, ops + 24)
            put(w, S + 184, g_count(w, ops))
            put(w, S + 120, 3)
        elif phase == 3:
            if get(w, S + 184) == 0:
                if commit_definitions(w) == 0:
                    return 1
                put(w, S + 152, g_end(w, get(w, S + 152)))
                put(w, S + 160, get(w, S + 160) - 1)
                put(w, S + 120, 1)
            else:
                if admit_instruction(w, get(w, S + 176)) == 0:
                    return 1
                return request_parameters(w, g_field(w, get(w, S + 176), K_out), 4)
        elif phase == 4:
            if reserve_response(s, w) == 0:
                return 1
            if add_response_values(s, w, 0) == 0:
                return 1
            put(w, S + 176, g_end(w, get(w, S + 176)))
            put(w, S + 184, get(w, S + 184) - 1)
            put(w, S + 120, 3)
        elif phase == 5:
            if admit_entry(w) == 0:
                return 1
            put(w, S + 120, 100)
            return 10
        else:
            put(w, S + 96, 1)
            return 1
    return 1

def fail(w:mutbuf, code:u64) -> u64:
    if get(w, S + 112) == 0:
        put(w, S + 112, code)
    return 1

def request_parameters(w:mutbuf, node:u64, resume:u64) -> u64:
    root = ir_list(w)
    ir_append(w, root, ir_integer(w, 2))
    ir_append(w, root, ir_source(w, node))
    put(w, S + 192, node)
    put(w, S + 312, 2)
    put(w, S + 88, get(w, S + 88) + 1)
    put(w, S + 120, resume)
    stream_begin(w, root, 2)
    return 2

def begin_block(w:mutbuf) -> u64:
    node = get(w, S + 152)
    if g_shape(w, node, K_id | K_params | K_ops | K_term) == 0:
        fail(w, 2)
        return 0
    name = g_field(w, node, K_id)
    status = name_status(w, name)
    if status != 0:
        fail(w, choose(status == 2, 4, 3))
        return 0
    if table_get(w, get(w, S + 232), 8191, name) != 0:
        fail(w, 5)
        return 0
    block = allocate(w, 96)
    put(w, block, name)
    put(w, block + 8, g_field(w, node, K_params))
    put(w, block + 16, g_field(w, node, K_ops))
    put(w, block + 24, g_field(w, node, K_term))
    put(w, block + 48, ir_list(w))
    put(w, block + 72, node)
    tail = get(w, S + 224)
    if tail == 0:
        put(w, S + 216, block)
    else:
        put(w, tail + 80, block)
    put(w, S + 224, block)
    put(w, S + 168, block)
    table_put(w, get(w, S + 232), 8191, name, block)
    return 1

def reserve_response(s:readbuf, w:mutbuf) -> u64:
    i = 0
    total = get(w, S + 80)
    while i < get(w, S + 208):
        identifier = get(w, get(w, S + 200) + i * 8)
        if issued(s, identifier) == 0:
            put(w, S + 96, 1)
            return 0
        total = total + word(s, type_at(identifier) + 152)
        i = i + 1
    put(w, S + 80, total)
    if total > 32768:
        fail(w, 17)
        return 0
    return 1

def add_response_values(s:readbuf, w:mutbuf, parameter:u64) -> u64:
    block = get(w, S + 168)
    item = get(w, S + 192) + 24
    i = 0
    while i < get(w, S + 208):
        identifier = get(w, get(w, S + 200) + i * 8)
        typ = type_at(identifier)
        width = word(s, typ + 152)
        record = allocate(w, 80)
        put(w, record, g_field(w, item, K_name))
        put(w, record + 8, identifier)
        put(w, record + 24, width)
        put(w, record + 56, block)
        put(w, record + 72, item)
        tail = get(w, block + 64)
        if tail == 0:
            put(w, block + 56, record)
        else:
            put(w, tail + 48, record)
        put(w, block + 64, record)
        if parameter == 1:
            put(w, block + 88, get(w, block + 88) + 1)
            put(w, record + 64, 1)
            external = choose(word(s, typ + 37848) != 0 and word(s, typ + 37856) == 0, 1, 0)
            put(w, record + 32, external)
            names = allocate(w, width * 8)
            put(w, record + 16, names)
            j = 0
            while j < width:
                name = 0
                if identifier <= 16:
                    name = ir_source(w, get(w, record))
                else:
                    name = fresh(w)
                    if name == 0:
                        return 0
                put(w, names + j * 8, name)
                param = ir_object(w)
                ir_pair(w, param, literal(w, C_name), name)
                ir_pair(w, param, literal(w, C_type), primitive_ir(w, word(s, typ + 160 + j * 8)))
                ir_append(w, get(w, block + 48), param)
                j = j + 1
        item = g_end(w, item)
        i = i + 1
    return 1

def fresh(w:mutbuf) -> u64:
    serial = get(w, S + 72)
    if serial >= 8192:
        fail(w, 16)
        return 0
    put(w, S + 72, serial + 1)
    return ir_generated(w, serial + 1)

def commit_definitions(w:mutbuf) -> u64:
    value = get(w, get(w, S + 168) + 56)
    while value != 0:
        name = get(w, value)
        if table_get(w, get(w, S + 240), 262143, name) != 0:
            fail(w, 12)
            return 0
        table_put(w, get(w, S + 240), 262143, name, value)
        value = get(w, value + 48)
    return 1

def admit_instruction(w:mutbuf, ins:u64) -> u64:
    if g_shape(w, ins, K_op | K_args | K_out | K_attrs) == 0:
        fail(w, 7)
        return 0
    op = g_field(w, ins, K_op)
    if g_kind(w, op) != 4 or g_kind(w, g_field(w, ins, K_attrs)) != 6:
        fail(w, 8)
        return 0
    if nominal_prefix(w, op) != 0 and allowed_operation(w, op) == 0:
        fail(w, 9)
        return 0
    args = g_field(w, ins, K_args)
    if g_kind(w, args) != 5:
        fail(w, 10)
        return 0
    item = args + 24
    i = 0
    while i < g_count(w, args):
        if name_status(w, item) == 1:
            fail(w, 11)
            return 0
        item = g_end(w, item)
        i = i + 1
    return 1

def admit_entry(w:mutbuf) -> u64:
    entry = g_field(w, get(w, S + 128), K_entry)
    status = name_status(w, entry)
    if status != 0:
        fail(w, choose(status == 2, 14, 13))
        return 0
    block = table_get(w, get(w, S + 232), 8191, entry)
    params = g_at(w, get(w, S + 136), 1)
    if block == 0 or g_count(w, params) != get(w, block + 88):
        fail(w, 15)
        return 0
    item = params + 24
    value = get(w, block + 56)
    i = 0
    while i < g_count(w, params):
        if same_text(w, get(w, value), g_at(w, item, 0)) == 0 or get(w, value + 8) != g_integer(w, g_at(w, item, 1)):
            fail(w, 15)
            return 0
        item = g_end(w, item)
        value = get(w, value + 48)
        i = i + 1
    return 1

def type_at(identifier:u64) -> u64:
    return TYPES + (identifier - 1) * 40960

def issued(s:readbuf, identifier:u64) -> u64:
    if identifier == 0 or identifier > word(s, TS + 16) or identifier > 144:
        return 0
    return choose(word(s, type_at(identifier) + 37872) == 1, 1, 0)

def g_kind(w:mutbuf, node:u64) -> u64:
    if node == N:
        return N
    return get(w, node)

def g_size(w:mutbuf, node:u64) -> u64:
    if node == N:
        return 0
    return get(w, node + 8)

def g_count(w:mutbuf, node:u64) -> u64:
    if g_kind(w, node) != 5 and g_kind(w, node) != 6:
        return 0
    return get(w, node + 16)

def g_end(w:mutbuf, node:u64) -> u64:
    return node + 16 + g_size(w, node)

def g_at(w:mutbuf, node:u64, index:u64) -> u64:
    if index >= g_count(w, node):
        return N
    item = node + 24
    i = 0
    while i < index:
        item = g_end(w, item)
        i = i + 1
    return item

def g_field(w:mutbuf, node:u64, key:u64) -> u64:
    if g_kind(w, node) != 6:
        return N
    item = node + 24
    i = 0
    while i < g_count(w, node):
        value = g_end(w, item)
        if key_id(w, item) == key:
            return value
        item = g_end(w, value)
        i = i + 1
    return N

def g_shape(w:mutbuf, node:u64, expected:u64) -> u64:
    if g_kind(w, node) != 6:
        return 0
    item = node + 24
    i = 0
    seen = 0
    while i < g_count(w, node):
        key = key_id(w, item)
        if key == 0 or (key & expected) == 0 or (key & seen) != 0:
            return 0
        seen = seen | key
        item = g_end(w, g_end(w, item))
        i = i + 1
    return choose(seen == expected, 1, 0)

def g_integer(w:mutbuf, node:u64) -> u64:
    if g_kind(w, node) != 2 or g_size(w, node) == 0 or g_size(w, node) > 20:
        return N
    i = 0
    value = 0
    while i < g_size(w, node):
        digit = byte(w, node + 16 + i)
        if digit < 48 or digit > 57 or value > 1844674407370955161:
            return N
        if value == 1844674407370955161 and digit > 53:
            return N
        value = value * 10 + digit - 48
        i = i + 1
    return value

def text_is(w:mutbuf, node:u64, n:u64, a:u64, b:u64, c:u64) -> u64:
    if g_kind(w, node) != 4 or g_size(w, node) != n:
        return 0
    return prefix(w, node, n, a, b, c)

def prefix(w:mutbuf, node:u64, n:u64, a:u64, b:u64, c:u64) -> u64:
    if g_kind(w, node) != 4 or g_size(w, node) < n:
        return 0
    i = 0
    while i < n:
        part = a
        shift = i * 8
        if i >= 8:
            part = b
            shift = (i - 8) * 8
        if i >= 16:
            part = c
            shift = (i - 16) * 8
        if byte(w, node + 16 + i) != ((part >> shift) & 255):
            return 0
        i = i + 1
    return 1

def same_text(w:mutbuf, left:u64, right:u64) -> u64:
    if g_kind(w, left) != 4 or g_kind(w, right) != 4 or g_size(w, left) != g_size(w, right):
        return 0
    i = 0
    while i < g_size(w, left):
        if byte(w, left + 16 + i) != byte(w, right + 16 + i):
            return 0
        i = i + 1
    return 1

def name_status(w:mutbuf, node:u64) -> u64:
    if g_kind(w, node) != 4 or g_size(w, node) == 0 or g_size(w, node) > 128:
        return 1
    i = 0
    while i < g_size(w, node):
        ch = byte(w, node + 16 + i)
        if (ch < 65 or ch > 90) and (ch < 97 or ch > 122) and ch != 95:
            if i == 0 or ch < 48 or ch > 57:
                return 1
        i = i + 1
    if prefix(w, node, L_reserved_core) != 0:
        return 1
    if prefix(w, node, L_reserved_nominal) != 0:
        return 2
    return 0

def hash_name(w:mutbuf, node:u64) -> u64:
    value = 14695981039346656037
    i = 0
    while i < g_size(w, node):
        value = (value ^ byte(w, node + 16 + i)) * 1099511628211
        i = i + 1
    return value

def table_slot(w:mutbuf, table:u64, mask:u64, name:u64) -> u64:
    index = hash_name(w, name) & mask
    while get(w, table + index * 16) != 0:
        if same_text(w, get(w, table + index * 16), name) != 0:
            return table + index * 16
        index = (index + 1) & mask
    return table + index * 16

def table_get(w:mutbuf, table:u64, mask:u64, name:u64) -> u64:
    slot = table_slot(w, table, mask, name)
    return get(w, slot + 8)

def table_put(w:mutbuf, table:u64, mask:u64, name:u64, value:u64) -> u64:
    slot = table_slot(w, table, mask, name)
    put(w, slot, name)
    put(w, slot + 8, value)
    return 0

def nominal_prefix(w:mutbuf, node:u64) -> u64:
    return choose(prefix(w, node, L_record_prefix) != 0 or prefix(w, node, L_enum_prefix) != 0 or prefix(w, node, L_task_prefix) != 0, 1, 0)
'''


def suffix(packed):
    lines = ['def key_id(w:mutbuf, node:u64) -> u64:']
    for i, value in enumerate(KEYS):
        lines += ['    if text_is(w, node, ' + ', '.join(map(str, packed(value))) + ') != 0:',
                  '        return ' + str(1 << i)]
    lines += ['    return 0', '', 'def literal(w:mutbuf, identifier:u64) -> u64:',
              '    value = get(w, LIT_TABLE + identifier * 8)',
              '    if value != 0:', '        return value']
    for i, value in enumerate(LITERALS, 1):
        lines += ['    if identifier == ' + str(i) + ':',
                  '        value = ir_text(w, ' + ', '.join(map(str, packed(value))) + ')']
    lines += ['    if value == 0:', '        put(w, S + 96, 1)',
              '    put(w, LIT_TABLE + identifier * 8, value)', '    return value', '',
              'def primitive_ir(w:mutbuf, identifier:u64) -> u64:']
    for i, value in enumerate(PRIMITIVES, 1):
        lines += ['    if identifier == ' + str(i) + ':',
                  '        return literal(w, ' + str(LITERALS.index(value) + 1) + ')']
    lines += ['    put(w, S + 96, 1)', '    return 0', '',
              'def profile(w:mutbuf, node:u64) -> u64:']
    for i in range(1, 5):
        text = ', '.join(map(str, packed('hepta.hia.composite.v' + str(i))))
        lines += ['    if text_is(w, node, ' + text + ') != 0:', '        return ' + str(i)]
    lines += ['    return 0', '', 'def allowed_operation(w:mutbuf, node:u64) -> u64:']
    legacy = ('record.make', 'record.unpack', 'record.get', 'enum.make', 'enum.tag',
              'task.create', 'task.state', 'task.start', 'task.poll', 'task.cancel', 'task.join', 'task.close')
    for value in legacy:
        lines += ['    if text_is(w, node, ' + ', '.join(map(str, packed(value))) + ') != 0:',
                  '        return 1']
    lines += ['    if get(w, S + 272) != 0:', '        return 0',
              '    if text_is(w, node, ' + ', '.join(map(str, packed('record.borrow'))) + ') != 0:',
              '        return 1', '    if get(w, S + 264) < 3:', '        return 0']
    for value in ('record.begin', 'record.take', 'record.insert', 'record.finish', 'record.abandon'):
        lines += ['    if text_is(w, node, ' + ', '.join(map(str, packed(value))) + ') != 0:',
                  '        return 1']
    lines += ['    return 0']
    return '\n'.join(lines) + '\n'
