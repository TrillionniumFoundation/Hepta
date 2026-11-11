"""Second-pass HIA function lowering, part of the indivisible owner candidate."""

OPCODES = ('record.begin', 'record.take', 'record.insert', 'record.finish',
    'record.abandon', 'record.make', 'record.unpack', 'record.get', 'record.borrow',
    'enum.make', 'enum.tag', 'task.create', 'task.state', 'task.start', 'task.poll',
    'task.cancel', 'task.join', 'task.close', 'call')
CONSTANTS = {
    'LOWER_RESPONSE_MAGIC': int.from_bytes(b'HIAFLR01', 'little'),
    'METADATA_REQUEST_MAGIC': int.from_bytes(b'HIAFMQ01', 'little'),
    'METADATA_MAGIC': int.from_bytes(b'HIAFMD01', 'little'),
    'FLAT_CACHE': 34816, 'HELPER_CACHE': 49152,
}
ERRORS = {
    20: ('E_HIA_NAME', 'value reference: invalid/reserved ASCII identifier'),
    21: ('E_HIA_NAME', 'value reference: identifier uses the elaborator namespace'),
    22: ('E_HIA_SSA', 'undefined/nonlocal nominal value'),
    23: ('E_HIA_RESOURCE', 'use of consumed nominal value'),
    24: ('E_HIA_TYPE', 'nominal output type/arity mismatch'),
    25: ('E_HIA_NAME', 'projected record field: invalid/reserved ASCII identifier'),
    26: ('E_HIA_NAME', 'projected record field: identifier uses the elaborator namespace'),
    27: ('E_HIA_TYPE', 'field access requires a record'),
    28: ('E_HIA_INIT', 'use of an uninitialized record field'),
    29: ('E_HIA_TYPE', 'unknown nominal field'),
    30: ('E_HIA_TYPE', 'record.begin requires one empty partial-record output'),
    31: ('E_HIA_INIT', 'record.begin cannot initialize a field'),
    32: ('E_HIA_TYPE', 'record.take requires one record'),
    33: ('E_HIA_TYPE', 'record.insert requires partial record and field value'),
    34: ('E_HIA_NAME', 'initialized record field: invalid/reserved ASCII identifier'),
    35: ('E_HIA_NAME', 'initialized record field: identifier uses the elaborator namespace'),
    36: ('E_HIA_INIT', 'record field is already initialized'),
    37: ('E_HIA_TYPE', 'inserted record field type differs'),
    38: ('E_HIA_TYPE', 'record.finish requires one partial record'),
    39: ('E_HIA_INIT', 'record.finish requires every field initialized'),
    40: ('E_HIA_TYPE', 'record.abandon requires one partial record'),
    41: ('E_HIA_INIT', 'record.abandon requires every field moved out'),
    42: ('E_HIA_TYPE', 'record.make needs one nominal record output'),
    43: ('E_HIA_TYPE', 'record fields differ from nominal declaration'),
    44: ('E_HIA_TYPE', 'record.unpack requires a record'),
    45: ('E_HIA_TYPE', 'record.get requires a record'),
    46: ('E_HIA_RESOURCE', 'linear fields require consuming record.unpack/take'),
    47: ('E_HIA_TYPE', 'record.borrow requires a record'),
    48: ('E_HIA_LOAN', 'record.borrow mode must be read or mut'),
    49: ('E_HIA_TYPE', 'record.borrow requires a primitive owner/view field'),
    50: ('E_HIA_TYPE', 'enum.make needs an enum output'),
    51: ('E_HIA_NAME', 'constructed variant: invalid/reserved ASCII identifier'),
    52: ('E_HIA_NAME', 'constructed variant: identifier uses the elaborator namespace'),
    53: ('E_HIA_TYPE', 'enum payload differs from selected variant'),
    54: ('E_HIA_TYPE', 'enum.tag requires an enum'),
    55: ('E_HIA_TYPE', 'task.create needs state and one task output'),
    56: ('E_HIA_TYPE', 'task state type differs from protocol'),
    57: ('E_HIA_TYPE', 'task operation requires one task'),
    58: ('E_HIA_OPCODE', 'unknown task operation'),
    59: ('E_HIA_NAME', 'callee: invalid/reserved ASCII identifier'),
    60: ('E_HIA_NAME', 'callee: identifier uses the elaborator namespace'),
    61: ('E_HIA_CALL', 'unknown nominal callee'),
    62: ('E_HIA_CALL', 'nominal call argument types differ'),
    63: ('E_HIA_TYPE', 'primitive instruction cannot reinterpret a nominal value'),
    64: ('E_HIA_LOAN', 'cannot invent an inactive loan'),
    65: ('E_HIA_LOAN', 'inactive padding contains a loan'),
}
for index, operation in enumerate(OPCODES, 1):
    attrs = ('field, mode' if operation == 'record.borrow' else
             'field' if operation in {'record.take', 'record.insert', 'record.get'} else
             'variant' if operation == 'enum.make' else
             'function' if operation == 'call' else '')
    ERRORS[1000 + index] = ('E_HIA_FORMAT', operation + ': expected exactly ' + attrs)

# State after the first pass: 384 current source block record; 392 Core blocks;
# 400 current Core block; 408 current instruction list; 416 op cursor;
# 424 operations left; 432 instruction; 440 source arguments; 448 attributes;
# 456 actual value-record vector; 464 actual count; 472 expected type vector;
# 480 expected count; 488 operation; 504 returned type; 512..632 operation temps;
# 640 pending helper starting serial; 648 helper result name id;
# 720 newly appended helper handles. All semantic decisions stay in these HIA
# state transitions. The renderer only visits concrete generic object nodes.

COMMON = r'''
def invalid(w:mutbuf) -> u64:
    put(w, S + 96, 1)
    return ABI

def type_kind(s:readbuf, identifier:u64) -> u64:
    return word(s, type_at(identifier))

def type_width(s:readbuf, identifier:u64) -> u64:
    return word(s, type_at(identifier) + 152)

def type_linear(s:readbuf, identifier:u64) -> u64:
    return word(s, type_at(identifier) + 37840)

def type_owns(s:readbuf, identifier:u64) -> u64:
    return word(s, type_at(identifier) + 37856)

def type_name_data(s:readbuf, node:u64) -> u64:
    base = 67108864
    if node < 67108864:
        base = 33554432
    return base + word(s, node + 24)

def type_name_equal(s:readbuf, w:mutbuf, left:u64, right:u64) -> u64:
    if g_kind(w, right) != 4 or word(s, left + 32) != g_size(w, right):
        return 0
    i = 0
    data = type_name_data(s, left)
    while i < g_size(w, right):
        if byte(s, data + i) != byte(w, right + 16 + i):
            return 0
        i = i + 1
    return 1

def ir_type_name(s:readbuf, w:mutbuf, node:u64) -> u64:
    size = word(s, node + 32)
    if size > 128:
        invalid(w)
        return 0
    data = allocate(w, size)
    source = type_name_data(s, node)
    i = 0
    while i < size:
        store(w, data + i, byte(s, source + i))
        i = i + 1
    return ir_node(w, 1, data, size, 0)

def flat_vector(s:readbuf, w:mutbuf, identifier:u64) -> u64:
    if issued(s, identifier) == 0:
        invalid(w)
        return 0
    cached = get(w, FLAT_CACHE + identifier * 8)
    if cached != 0:
        return cached
    width = type_width(s, identifier)
    values = allocate(w, width * 8)
    i = 0
    while i < width:
        value = primitive_ir(w, word(s, type_at(identifier) + 160 + i * 8))
        put(w, values + i * 8, value)
        i = i + 1
    put(w, FLAT_CACHE + identifier * 8, values)
    return values

def actual(w:mutbuf, index:u64) -> u64:
    if index >= get(w, S + 464):
        return 0
    return get(w, get(w, S + 456) + index * 8)

def declared_type(w:mutbuf, index:u64) -> u64:
    if index >= get(w, S + 208):
        return 0
    return get(w, get(w, S + 200) + index * 8)

def output_value(w:mutbuf, index:u64) -> u64:
    item = g_at(w, get(w, S + 192), index)
    if item == N:
        invalid(w)
        return 0
    name = g_field(w, item, K_name)
    value = table_get(w, get(w, S + 240), 262143, name)
    if value == 0 or get(w, value + 56) != get(w, S + 384):
        invalid(w)
        return 0
    return value

def value_of(w:mutbuf, name:u64) -> u64:
    status = name_status(w, name)
    if status != 0:
        fail(w, choose(status == 2, 21, 20))
        return 0
    value = table_get(w, get(w, S + 240), 262143, name)
    if value == 0:
        fail(w, 22)
        return 0
    if get(w, value + 56) != get(w, S + 384) or get(w, value + 64) == 0:
        fail(w, 22)
        return 0
    if get(w, value + 40) != 0:
        fail(w, 23)
        return 0
    return value

def consume_source(s:readbuf, w:mutbuf, name:u64) -> u64:
    value = value_of(w, name)
    if value == 0:
        return 0
    if type_linear(s, get(w, value + 8)) != 0:
        put(w, value + 40, 1)
    return 1

def consume_argument(s:readbuf, w:mutbuf, index:u64) -> u64:
    return consume_source(s, w, g_at(w, get(w, S + 440), index))

def activate(w:mutbuf, value:u64, names:u64, external:u64) -> u64:
    put(w, value + 16, names)
    put(w, value + 32, external)
    put(w, value + 40, 0)
    put(w, value + 64, 1)
    return 0

def copy_names(w:mutbuf, target:u64, source:u64, count:u64) -> u64:
    i = 0
    while i < count:
        put(w, target + i * 8, get(w, source + i * 8))
        i = i + 1
    return 0

def singleton(w:mutbuf, item:u64) -> u64:
    values = allocate(w, 8)
    put(w, values, item)
    return values

def pair_types(w:mutbuf, first:u64, second:u64) -> u64:
    values = allocate(w, 16)
    put(w, values, first)
    put(w, values + 8, second)
    return values

def attrs_are(w:mutbuf, fields:u64) -> u64:
    if g_shape(w, get(w, S + 448), fields) == 0:
        fail(w, 1000 + get(w, S + 488))
        return 0
    return 1

def expect_outputs(w:mutbuf, values:u64, count:u64, phase:u64) -> u64:
    put(w, S + 472, values)
    put(w, S + 480, count)
    return request_parameters(w, g_field(w, get(w, S + 432), K_out), phase)

def check_outputs(w:mutbuf) -> u64:
    if get(w, S + 208) != get(w, S + 480):
        fail(w, 24)
        return 0
    i = 0
    while i < get(w, S + 208):
        if get(w, get(w, S + 200) + i * 8) != get(w, get(w, S + 472) + i * 8):
            fail(w, 24)
            return 0
        i = i + 1
    return 1

def request_type(w:mutbuf, reference:u64, phase:u64) -> u64:
    root = ir_list(w)
    ir_append(w, root, ir_integer(w, 3))
    ir_append(w, root, reference)
    return service_request(w, root, 3, phase)

def request_partial(w:mutbuf, base:u64, fields:u64, phase:u64) -> u64:
    root = ir_list(w)
    ir_append(w, root, ir_integer(w, 4))
    ir_append(w, root, ir_integer(w, base))
    ir_append(w, root, fields)
    return service_request(w, root, 4, phase)

def request_protocol(w:mutbuf, typ:u64, phase:u64) -> u64:
    root = ir_list(w)
    ir_append(w, root, ir_integer(w, 5))
    ir_append(w, root, ir_integer(w, typ))
    return service_request(w, root, 5, phase)

def service_request(w:mutbuf, root:u64, kind:u64, phase:u64) -> u64:
    put(w, S + 312, kind)
    put(w, S + 88, get(w, S + 88) + 1)
    put(w, S + 120, phase)
    stream_begin(w, root, kind)
    return 2

def parameter(w:mutbuf, name:u64, typ:u64) -> u64:
    result = ir_object(w)
    ir_pair(w, result, literal(w, C_name), name)
    ir_pair(w, result, literal(w, C_type), primitive_ir(w, typ))
    return result

def instruction(w:mutbuf, opcode:u64, args:u64, outputs:u64, attrs:u64) -> u64:
    result = ir_object(w)
    ir_pair(w, result, literal(w, C_op), opcode)
    ir_pair(w, result, literal(w, C_args), args)
    ir_pair(w, result, literal(w, C_out), outputs)
    ir_pair(w, result, literal(w, C_attrs), attrs)
    ir_append(w, get(w, S + 408), result)
    return result

def flat_instruction(w:mutbuf, op:u64, names:u64, count:u64, output:u64, typ:u64) -> u64:
    args = ir_list(w)
    ir_extend(w, args, names, count)
    out = ir_list(w)
    if output != 0:
        ir_append(w, out, parameter(w, output, typ))
    return instruction(w, literal(w, op), args, out, ir_object(w))

def constant(w:mutbuf, typ:u64, value:u64) -> u64:
    name = fresh(w)
    if name == 0:
        return 0
    out = ir_list(w)
    ir_append(w, out, parameter(w, name, typ))
    attrs = ir_object(w)
    ir_pair(w, attrs, literal(w, C_value), value)
    instruction(w, literal(w, C_const), ir_list(w), out, attrs)
    return name

def zero_primitive(w:mutbuf, typ:u64) -> u64:
    if typ == 13:
        zero = constant(w, 12, ir_integer(w, 0))
        if zero == 0:
            return 0
        owner = fresh(w)
        if owner == 0:
            return 0
        ok = fresh(w)
        if ok == 0:
            return 0
        args = ir_list(w)
        ir_append(w, args, zero)
        out = ir_list(w)
        ir_append(w, out, parameter(w, owner, 13))
        ir_append(w, out, parameter(w, ok, 1))
        instruction(w, literal(w, C_buffer_try_new), args, out, ir_object(w))
        return owner
    if typ == 16:
        name = fresh(w)
        if name == 0:
            return 0
        flat_instruction(w, C_chain_empty, 0, 0, name, 16)
        return name
    if typ == 14 or typ == 15:
        fail(w, 64)
        return 0
    value = ir_integer(w, 0)
    if typ == 1:
        value = ir_bool(w, 0)
    elif typ == 2:
        value = ir_null(w)
    return constant(w, typ, value)

def zero_range(s:readbuf, w:mutbuf, types:u64, count:u64) -> u64:
    names = allocate(w, count * 8)
    i = 0
    while i < count:
        value = zero_primitive(w, word(s, types + i * 8))
        if value == 0:
            return 0
        put(w, names + i * 8, value)
        i = i + 1
    return names

def move_field(s:readbuf, w:mutbuf, names:u64, typ:u64) -> u64:
    count = type_width(s, typ)
    result = allocate(w, count * 8)
    i = 0
    while i < count:
        part = word(s, type_at(typ) + 160 + i * 8)
        name = get(w, names + i * 8)
        if part == 13 or part == 16:
            name = fresh(w)
            if name == 0:
                return 0
            flat_instruction(w, C_owner_move, names + i * 8, 1, name, part)
        put(w, result + i * 8, name)
        i = i + 1
    return result

def find_record_field(s:readbuf, w:mutbuf, typ:u64, name:u64) -> u64:
    record = type_at(typ)
    i = 0
    while i < word(s, record + 4256):
        field = record + 4264 + i * 16
        if type_name_equal(s, w, word(s, field), name) != 0:
            return i + 1
        i = i + 1
    return 0

def record_field(s:readbuf, w:mutbuf, value:u64, name:u64) -> u64:
    status = name_status(w, name)
    if status != 0:
        fail(w, choose(status == 2, 26, 25))
        return 0
    typ = get(w, value + 8)
    category = type_kind(s, typ)
    if category != 1 and category != 4:
        fail(w, 27)
        return 0
    offset = choose(category == 4, 1, 0)
    record = type_at(typ)
    i = 0
    while i < word(s, record + 4256):
        field = record + 4264 + i * 16
        nested = word(s, field + 8)
        if type_name_equal(s, w, word(s, field), name) != 0:
            put(w, S + 600, offset)
            put(w, S + 608, nested)
            return 1
        offset = offset + type_width(s, nested)
        i = i + 1
    if category == 4:
        if find_record_field(s, w, word(s, record + 37864), name) != 0:
            fail(w, 28)
            return 0
    fail(w, 29)
    return 0

def fields_types(s:readbuf, w:mutbuf, typ:u64) -> u64:
    record = type_at(typ)
    count = word(s, record + 4256)
    result = allocate(w, count * 8)
    i = 0
    while i < count:
        put(w, result + i * 8, word(s, record + 4272 + i * 16))
        i = i + 1
    return result

def fields_equal(s:readbuf, left:u64, right:u64) -> u64:
    a = type_at(left)
    b = type_at(right)
    if word(s, a + 4256) != word(s, b + 4256):
        return 0
    i = 0
    while i < word(s, a + 4256):
        if word(s, a + 4264 + i * 16) != word(s, b + 4264 + i * 16) or word(s, a + 4272 + i * 16) != word(s, b + 4272 + i * 16):
            return 0
        i = i + 1
    return 1
'''

RECORDS = r'''
def record_begin(s:readbuf, w:mutbuf) -> u64:
    if attrs_are(w, 0) == 0:
        return 1
    if get(w, S + 464) != 0 or get(w, S + 208) != 1:
        return fail(w, 30)
    typ = declared_type(w, 0)
    if type_kind(s, typ) != 4:
        return fail(w, 30)
    if word(s, type_at(typ) + 4256) != 0:
        return fail(w, 31)
    name = zero_primitive(w, 13)
    if name == 0:
        return 1
    activate(w, output_value(w, 0), singleton(w, name), 0)
    return 0

def record_take(s:readbuf, w:mutbuf) -> u64:
    if attrs_are(w, K_field) == 0:
        return 1
    if get(w, S + 464) != 1:
        return fail(w, 32)
    value = actual(w, 0)
    typ = get(w, value + 8)
    category = type_kind(s, typ)
    if category != 1 and category != 4:
        return fail(w, 32)
    name = g_field(w, get(w, S + 448), K_field)
    if record_field(s, w, value, name) == 0:
        return 1
    base = typ
    if category == 4:
        base = word(s, type_at(typ) + 37864)
    fields = ir_list(w)
    i = 0
    while i < word(s, type_at(typ) + 4256):
        item = word(s, type_at(typ) + 4264 + i * 16)
        if type_name_equal(s, w, item, name) == 0:
            ir_append(w, fields, ir_type_name(s, w, item))
        i = i + 1
    return request_partial(w, base, fields, 110)

def record_take_done(s:readbuf, w:mutbuf) -> u64:
    if check_outputs(w) == 0:
        return 1
    if consume_argument(s, w, 0) == 0:
        return 1
    value = actual(w, 0)
    original = get(w, value + 16)
    category = type_kind(s, get(w, value + 8))
    token = get(w, original)
    if category != 4:
        token = zero_primitive(w, 13)
        if token == 0:
            return 1
    offset = get(w, S + 600)
    typ = get(w, S + 608)
    width = type_width(s, typ)
    selected = move_field(s, w, original + offset * 8, typ)
    if get(w, S + 112) != 0:
        return 1
    activate(w, output_value(w, 0), selected, 0)
    rest = output_value(w, 1)
    names = allocate(w, get(w, rest + 24) * 8)
    put(w, names, token)
    start = choose(category == 4, 1, 0)
    before = offset - start
    copy_names(w, names + 8, original + start * 8, before)
    copy_names(w, names + (before + 1) * 8, original + (offset + width) * 8,
        get(w, value + 24) - offset - width)
    activate(w, rest, names, 0)
    return 0

def record_insert(s:readbuf, w:mutbuf) -> u64:
    if attrs_are(w, K_field) == 0:
        return 1
    if get(w, S + 464) != 2:
        return fail(w, 33)
    value = actual(w, 0)
    typ = get(w, value + 8)
    if type_kind(s, typ) != 4:
        return fail(w, 33)
    name = g_field(w, get(w, S + 448), K_field)
    status = name_status(w, name)
    if status != 0:
        return fail(w, choose(status == 2, 35, 34))
    base = word(s, type_at(typ) + 37864)
    found = find_record_field(s, w, base, name)
    if found == 0:
        return fail(w, 29)
    if find_record_field(s, w, typ, name) != 0:
        return fail(w, 36)
    if get(w, actual(w, 1) + 8) != word(s, type_at(base) + 4272 + (found - 1) * 16):
        return fail(w, 37)
    fields = ir_list(w)
    i = 0
    before = 1
    while i < word(s, type_at(base) + 4256):
        field = type_at(base) + 4264 + i * 16
        field_name = word(s, field)
        selected = choose(i + 1 == found, 1, 0)
        j = 0
        while j < word(s, type_at(typ) + 4256):
            if word(s, type_at(typ) + 4264 + j * 16) == field_name:
                selected = 1
                if i + 1 < found:
                    before = before + type_width(s, word(s, field + 8))
            j = j + 1
        if selected != 0:
            ir_append(w, fields, ir_type_name(s, w, field_name))
        i = i + 1
    put(w, S + 600, before)
    return request_partial(w, base, fields, 120)

def record_insert_done(s:readbuf, w:mutbuf) -> u64:
    if check_outputs(w) == 0:
        return 1
    if consume_argument(s, w, 0) == 0:
        return 1
    if consume_argument(s, w, 1) == 0:
        return 1
    value = actual(w, 0)
    supplied = actual(w, 1)
    out = output_value(w, 0)
    names = allocate(w, get(w, out + 24) * 8)
    before = get(w, S + 600)
    width = get(w, supplied + 24)
    copy_names(w, names, get(w, value + 16), before)
    copy_names(w, names + before * 8, get(w, supplied + 16), width)
    copy_names(w, names + (before + width) * 8, get(w, value + 16) + before * 8,
        get(w, value + 24) - before)
    activate(w, out, names, 0)
    return 0

def record_finish(s:readbuf, w:mutbuf) -> u64:
    if attrs_are(w, 0) == 0:
        return 1
    if get(w, S + 464) != 1:
        return fail(w, 38)
    typ = get(w, actual(w, 0) + 8)
    if type_kind(s, typ) != 4:
        return fail(w, 38)
    base = word(s, type_at(typ) + 37864)
    if fields_equal(s, typ, base) == 0:
        return fail(w, 39)
    return expect_outputs(w, singleton(w, base), 1, 130)

def record_finish_done(s:readbuf, w:mutbuf) -> u64:
    if check_outputs(w) == 0 or consume_argument(s, w, 0) == 0:
        return 1
    names = get(w, actual(w, 0) + 16)
    flat_instruction(w, C_owner_drop, names, 1, 0, 0)
    activate(w, output_value(w, 0), names + 8, 0)
    return 0

def record_abandon(s:readbuf, w:mutbuf) -> u64:
    if attrs_are(w, 0) == 0:
        return 1
    if get(w, S + 464) != 1:
        return fail(w, 40)
    typ = get(w, actual(w, 0) + 8)
    if type_kind(s, typ) != 4:
        return fail(w, 40)
    if word(s, type_at(typ) + 4256) != 0:
        return fail(w, 41)
    return expect_outputs(w, 0, 0, 140)

def record_abandon_done(s:readbuf, w:mutbuf) -> u64:
    if check_outputs(w) == 0 or consume_argument(s, w, 0) == 0:
        return 1
    flat_instruction(w, C_owner_drop, get(w, actual(w, 0) + 16), 1, 0, 0)
    return 0

def record_make(s:readbuf, w:mutbuf) -> u64:
    if attrs_are(w, 0) == 0:
        return 1
    if get(w, S + 208) != 1:
        return fail(w, 42)
    typ = declared_type(w, 0)
    if type_kind(s, typ) != 1:
        return fail(w, 42)
    if get(w, S + 464) != word(s, type_at(typ) + 4256):
        return fail(w, 43)
    i = 0
    while i < get(w, S + 464):
        if get(w, actual(w, i) + 8) != word(s, type_at(typ) + 4272 + i * 16):
            return fail(w, 43)
        i = i + 1
    i = 0
    while i < get(w, S + 464):
        if consume_argument(s, w, i) == 0:
            return 1
        i = i + 1
    names = allocate(w, type_width(s, typ) * 8)
    offset = 0
    external = choose(type_owns(s, typ) == 0, 1, 0)
    i = 0
    while i < get(w, S + 464):
        value = actual(w, i)
        width = get(w, value + 24)
        copy_names(w, names + offset * 8, get(w, value + 16), width)
        offset = offset + width
        if get(w, value + 32) == 0 and type_linear(s, get(w, value + 8)) != 0:
            external = 0
        i = i + 1
    activate(w, output_value(w, 0), names, external)
    return 0

def record_unpack(s:readbuf, w:mutbuf) -> u64:
    if attrs_are(w, 0) == 0:
        return 1
    if get(w, S + 464) != 1:
        return fail(w, 44)
    typ = get(w, actual(w, 0) + 8)
    if type_kind(s, typ) != 1:
        return fail(w, 44)
    return expect_outputs(w, fields_types(s, w, typ), word(s, type_at(typ) + 4256), 150)

def record_unpack_done(s:readbuf, w:mutbuf) -> u64:
    if check_outputs(w) == 0 or consume_argument(s, w, 0) == 0:
        return 1
    value = actual(w, 0)
    offset = 0
    i = 0
    while i < get(w, S + 208):
        out = output_value(w, i)
        activate(w, out, get(w, value + 16) + offset * 8, get(w, value + 32))
        offset = offset + get(w, out + 24)
        i = i + 1
    return 0

def record_get(s:readbuf, w:mutbuf) -> u64:
    if attrs_are(w, K_field) == 0:
        return 1
    if get(w, S + 464) != 1:
        return fail(w, 45)
    value = actual(w, 0)
    category = type_kind(s, get(w, value + 8))
    if category != 1 and category != 4:
        return fail(w, 45)
    if record_field(s, w, value, g_field(w, get(w, S + 448), K_field)) == 0:
        return 1
    typ = get(w, S + 608)
    if type_linear(s, typ) != 0:
        return fail(w, 46)
    return expect_outputs(w, singleton(w, typ), 1, 160)

def record_get_done(w:mutbuf) -> u64:
    if check_outputs(w) == 0:
        return 1
    activate(w, output_value(w, 0), get(w, actual(w, 0) + 16) + get(w, S + 600) * 8, 0)
    return 0

def record_borrow(s:readbuf, w:mutbuf) -> u64:
    if attrs_are(w, K_field | K_mode) == 0:
        return 1
    if get(w, S + 464) != 1:
        return fail(w, 47)
    value = actual(w, 0)
    category = type_kind(s, get(w, value + 8))
    if category != 1 and category != 4:
        return fail(w, 47)
    mode = g_field(w, get(w, S + 448), K_mode)
    mut = text_is(w, mode, L_mut)
    if mut == 0 and text_is(w, mode, L_read) == 0:
        return fail(w, 48)
    if record_field(s, w, value, g_field(w, get(w, S + 448), K_field)) == 0:
        return 1
    typ = get(w, S + 608)
    if typ != 13 and typ != 14 and typ != 15:
        return fail(w, 49)
    put(w, S + 512, mut)
    wanted = C_readbuf
    if mut != 0:
        wanted = C_mutbuf
    return request_type(w, literal(w, wanted), 170)

def record_borrow_done(w:mutbuf) -> u64:
    if check_outputs(w) == 0:
        return 1
    out = output_value(w, 0)
    name = ir_source(w, get(w, out))
    activate(w, out, singleton(w, name), 0)
    op = C_borrow_read
    if get(w, S + 512) != 0:
        op = C_borrow_mut
    flat_instruction(w, op, get(w, actual(w, 0) + 16) + get(w, S + 600) * 8,
        1, name, get(w, out + 8))
    return 0
'''

CONTROLLER = r'''
def function_records(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < W_BYTES:
        return ABI
    if length(o) < 64 or get(w, S) != STATE_MAGIC or get(w, S + 96) != 0:
        return invalid(w)
    if length(s) == 16 and word(s, 0) == METADATA_REQUEST_MAGIC:
        if word(s, 8) != 0:
            return invalid(w)
        return state_report(o, w)
    if get(w, S + 112) != 0:
        return invalid(w)
    if length(s) != TYPE_BYTES:
        action = lower_response(s, w)
        if action == ABI:
            return ABI
        return admit_frame(o, w, action)
    if word(s, TS) != TYPE_MAGIC or word(s, TS + 48) != 1 or get(w, S + 312) != 0:
        return invalid(w)
    action = records_run(s, w)
    return admit_frame(o, w, action)

def state_report(o:mutbuf, w:mutbuf) -> u32:
    completed = get(w, S + 120) == 2000 and get(w, S + 48) == 1
    if get(w, S + 728) != 0 or get(w, S + 312) != 0:
        return invalid(w)
    if get(w, S + 112) == 0 and completed == False:
        return invalid(w)
    count = 0
    i = 5
    while i < 725:
        if get(w, HELPER_CACHE + i * 16) != 0:
            count = count + 1
        i = i + 1
    handles = get(w, S + 720)
    appended = 0
    if handles != 0:
        appended = get(w, handles + 24)
    extent = 64 + count * 24 + appended * 8
    if extent > length(o) or appended > 720:
        return invalid(w)
    put(o, 0, METADATA_MAGIC)
    put(o, 8, get(w, S + 72))
    put(o, 16, get(w, S + 80))
    put(o, 24, count)
    put(o, 32, appended)
    put(o, 40, get(w, S + 112))
    put(o, 48, get(w, S + 88))
    put(o, 56, 0)
    previous = 0
    index = 0
    while index < count:
        selected = 0
        minimum = 8193
        i = 5
        while i < 725:
            name = get(w, HELPER_CACHE + i * 16)
            if name > previous and name < minimum:
                selected = i
                minimum = name
            i = i + 1
        if selected == 0:
            return invalid(w)
        typ = 0
        operation = selected
        while operation >= 5:
            operation = operation - 5
            typ = typ + 1
        at = 64 + index * 24
        put(o, at, typ)
        put(o, at + 8, operation)
        put(o, at + 16, minimum)
        previous = minimum
        index = index + 1
    if handles != 0:
        item = get(w, handles + 8)
        i = 0
        while item != 0:
            value = get(w, item + 16)
            if get(w, item + 8) != 0 or get(w, item + 24) != 1 or get(w, value) != 2 or i >= appended:
                return invalid(w)
            put(o, 64 + count * 24 + i * 8, get(w, value + 8))
            item = get(w, item)
            i = i + 1
        if i != appended:
            return invalid(w)
    put(w, S + 728, 1)
    return extent

def lower_response(s:readbuf, w:mutbuf) -> u64:
    if length(s) < 64 or word(s, 0) != LOWER_RESPONSE_MAGIC or word(s, 8) != get(w, S + 88):
        return invalid(w)
    kind = get(w, S + 312)
    error = word(s, 24)
    count = word(s, 32)
    if kind == 0 or word(s, 16) != kind or word(s, 56) != 0:
        return invalid(w)
    if kind == 6:
        return helper_response(s, w)
    if kind > 5 or kind < 2 or error > 1 or word(s, 40) != 0 or word(s, 48) != 0:
        return invalid(w)
    if count > 262144 or length(s) != 64 + count * 8:
        return invalid(w)
    if error != 0:
        if count != 0:
            return invalid(w)
        put(w, S + 112, 999)
        put(w, S + 312, 0)
        return 1
    if kind == 2:
        if count != g_count(w, get(w, S + 192)):
            return invalid(w)
    elif count != 1:
        return invalid(w)
    ids = allocate(w, count * 8)
    i = 0
    while i < count:
        identifier = word(s, 64 + i * 8)
        if identifier == 0 or identifier > 144:
            return invalid(w)
        put(w, ids + i * 8, identifier)
        i = i + 1
    if kind == 2:
        put(w, S + 200, ids)
        put(w, S + 208, count)
    else:
        put(w, S + 504, get(w, ids))
    put(w, S + 312, 0)
    return 0

def helper_response(s:readbuf, w:mutbuf) -> u64:
    error = word(s, 24)
    final = word(s, 40)
    size = word(s, 48)
    start = get(w, S + 640)
    if error > 3 or word(s, 32) != 0 or size > 15 or length(s) != 64 + size:
        return invalid(w)
    if final < start or final > 8192:
        return invalid(w)
    name = 0
    if start == 8192:
        if size != 0 or error != 1 or final != 8192:
            return invalid(w)
    else:
        if size < 12 or word(s, 64) != 7958535042260087400 or byte(s, 72) != 97 or byte(s, 73) != 108 or byte(s, 74) != 95:
            return invalid(w)
        i = 11
        while i < size:
            ch = byte(s, 64 + i)
            if ch < 48 or ch > 57:
                return invalid(w)
            name = name * 10 + ch - 48
            i = i + 1
        if name != start + 1 or final < name:
            return invalid(w)
    if error == 1 and final != 8192:
        return invalid(w)
    put(w, S + 72, final)
    put(w, S + 648, name)
    if name != 0:
        slot = get(w, S + 656)
        put(w, slot, name)
    if error != 0:
        put(w, S + 112, 999)
    else:
        ir_append(w, get(w, S + 720), ir_integer(w, get(w, S + 88)))
    put(w, S + 312, 0)
    return choose(error == 0, 0, 1)

def records_run(s:readbuf, w:mutbuf) -> u64:
    while get(w, S + 112) == 0 and get(w, S + 96) == 0:
        phase = get(w, S + 120)
        if phase == 100:
            begin_core_block(w)
        elif phase == 101:
            if get(w, S + 424) == 0:
                put(w, S + 120, 1000)
                return 20
            if prepare_instruction(w) == 0:
                return 1
            return request_parameters(w, g_field(w, get(w, S + 432), K_out), 102)
        elif phase == 102:
            if validate_declared(s, w) == 0:
                return 1
            operation = get(w, S + 488)
            if operation == 0 or operation > 9:
                return 30
            action = start_record(s, w, operation)
            if action != 0:
                return action
            advance_instruction(w)
        elif phase >= 110 and phase <= 171:
            action = resume_record(s, w, phase)
            if action != 0:
                return action
            advance_instruction(w)
        else:
            return invalid(w)
    return 1

def begin_core_block(w:mutbuf) -> u64:
    if get(w, S + 392) == 0:
        put(w, S + 392, ir_list(w))
        put(w, S + 384, get(w, S + 216))
        put(w, S + 720, ir_list(w))
    block = get(w, S + 384)
    current = ir_object(w)
    ops = ir_list(w)
    ir_pair(w, current, literal(w, C_id), ir_source(w, get(w, block)))
    ir_pair(w, current, literal(w, C_params), get(w, block + 48))
    ir_pair(w, current, literal(w, C_ops), ops)
    ir_append(w, get(w, S + 392), current)
    put(w, S + 400, current)
    put(w, S + 408, ops)
    source_ops = get(w, block + 16)
    put(w, S + 416, source_ops + 24)
    put(w, S + 424, g_count(w, source_ops))
    put(w, S + 120, 101)
    return 0

def prepare_instruction(w:mutbuf) -> u64:
    ins = get(w, S + 416)
    args = g_field(w, ins, K_args)
    count = g_count(w, args)
    values = allocate(w, count * 8)
    item = args + 24
    i = 0
    while i < count:
        value = value_of(w, item)
        if value == 0:
            return 0
        put(w, values + i * 8, value)
        item = g_end(w, item)
        i = i + 1
    put(w, S + 432, ins)
    put(w, S + 440, args)
    put(w, S + 448, g_field(w, ins, K_attrs))
    put(w, S + 456, values)
    put(w, S + 464, count)
    put(w, S + 488, operation_id(w, g_field(w, ins, K_op)))
    return 1

def validate_declared(s:readbuf, w:mutbuf) -> u64:
    i = 0
    while i < get(w, S + 208):
        identifier = declared_type(w, i)
        if issued(s, identifier) == 0:
            invalid(w)
            return 0
        value = output_value(w, i)
        if value == 0 or get(w, value + 8) != identifier:
            invalid(w)
            return 0
        i = i + 1
    return 1

def advance_instruction(w:mutbuf) -> u64:
    put(w, S + 416, g_end(w, get(w, S + 416)))
    put(w, S + 424, get(w, S + 424) - 1)
    put(w, S + 120, 101)
    return 0

def start_record(s:readbuf, w:mutbuf, operation:u64) -> u64:
    if operation == 1:
        return record_begin(s, w)
    if operation == 2:
        return record_take(s, w)
    if operation == 3:
        return record_insert(s, w)
    if operation == 4:
        return record_finish(s, w)
    if operation == 5:
        return record_abandon(s, w)
    if operation == 6:
        return record_make(s, w)
    if operation == 7:
        return record_unpack(s, w)
    if operation == 8:
        return record_get(s, w)
    return record_borrow(s, w)

def resume_record(s:readbuf, w:mutbuf, phase:u64) -> u64:
    if phase == 110:
        if issued(s, get(w, S + 504)) == 0:
            return invalid(w)
        return expect_outputs(w, pair_types(w, get(w, S + 608), get(w, S + 504)), 2, 111)
    if phase == 111:
        return record_take_done(s, w)
    if phase == 120:
        if issued(s, get(w, S + 504)) == 0:
            return invalid(w)
        return expect_outputs(w, singleton(w, get(w, S + 504)), 1, 121)
    if phase == 121:
        return record_insert_done(s, w)
    if phase == 130:
        return record_finish_done(s, w)
    if phase == 140:
        return record_abandon_done(s, w)
    if phase == 150:
        return record_unpack_done(s, w)
    if phase == 160:
        return record_get_done(w)
    if phase == 170:
        if issued(s, get(w, S + 504)) == 0:
            return invalid(w)
        return expect_outputs(w, singleton(w, get(w, S + 504)), 1, 171)
    if phase == 171:
        return record_borrow_done(w)
    return invalid(w)
'''

ADVANCED = r'''
def function_advanced(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < W_BYTES:
        return ABI
    if length(o) < 64 or get(w, S) != STATE_MAGIC or get(w, S + 96) != 0 or get(w, S + 112) != 0:
        return invalid(w)
    if length(s) != TYPE_BYTES:
        action = lower_response(s, w)
        if action == ABI:
            return ABI
        return admit_frame(o, w, action)
    if word(s, TS) != TYPE_MAGIC or word(s, TS + 48) != 1 or get(w, S + 312) != 0:
        return invalid(w)
    phase = get(w, S + 120)
    action = 0
    if phase == 102:
        action = start_advanced(s, w)
    else:
        action = resume_advanced(s, w, phase)
    if action == 0:
        advance_instruction(w)
        return admit_frame(o, w, 21)
    return admit_frame(o, w, action)

def start_advanced(s:readbuf, w:mutbuf) -> u64:
    operation = get(w, S + 488)
    if operation == 10:
        return enum_make(s, w)
    if operation == 11:
        return enum_tag(s, w)
    if operation == 12:
        return task_create(s, w)
    if operation >= 13 and operation <= 18:
        return task_operation(s, w)
    if operation == 19:
        return call_operation(s, w)
    if operation == 0:
        return primitive_operation(s, w)
    return invalid(w)

def resume_advanced(s:readbuf, w:mutbuf, phase:u64) -> u64:
    if phase == 180:
        if get(w, S + 504) != 9:
            return invalid(w)
        return expect_outputs(w, singleton(w, 9), 1, 181)
    if phase == 181:
        if check_outputs(w) == 0:
            return 1
        return request_type(w, literal(w, C_u32), 182)
    if phase == 182:
        if get(w, S + 504) != 9:
            return invalid(w)
        activate(w, output_value(w, 0), get(w, actual(w, 0) + 16), 0)
        return 0
    if phase == 190:
        if issued(s, get(w, S + 504)) == 0:
            return invalid(w)
        return task_create_done(s, w)
    if phase == 200:
        if get(w, S + 504) != 7:
            return invalid(w)
        return expect_outputs(w, singleton(w, 7), 1, 201)
    if phase == 201:
        if check_outputs(w) == 0:
            return 1
        return request_type(w, literal(w, C_u8), 202)
    if phase == 202:
        if get(w, S + 504) != 7:
            return invalid(w)
        activate(w, output_value(w, 0), get(w, actual(w, 0) + 16), 0)
        return 0
    if phase == 210:
        return task_operation_outputs(s, w)
    if phase == 211:
        if issued(s, get(w, S + 504)) == 0:
            return invalid(w)
        return request_helper(s, w, get(w, S + 520), get(w, S + 504))
    if phase == 212:
        return task_call_done(w, get(w, S + 648))
    if phase == 220:
        return call_operation_done(s, w)
    return invalid(w)

def enum_make(s:readbuf, w:mutbuf) -> u64:
    if attrs_are(w, K_variant) == 0:
        return 1
    if get(w, S + 208) != 1:
        return fail(w, 50)
    typ = declared_type(w, 0)
    if type_kind(s, typ) != 2:
        return fail(w, 50)
    name = g_field(w, get(w, S + 448), K_variant)
    status = name_status(w, name)
    if status != 0:
        return fail(w, choose(status == 2, 52, 51))
    record = type_at(typ)
    selected = N
    i = 0
    while i < word(s, record + 37032):
        variant = record + 37040 + i * 24
        if type_name_equal(s, w, word(s, variant), name) != 0:
            selected = i
        i = i + 1
    if selected == N:
        return fail(w, 53)
    variant = record + 37040 + selected * 24
    if get(w, S + 464) != word(s, variant + 16):
        return fail(w, 53)
    start = word(s, variant + 8)
    i = 0
    while i < get(w, S + 464):
        if get(w, actual(w, i) + 8) != word(s, record + 4272 + (start + i) * 16):
            return fail(w, 53)
        i = i + 1
    i = 0
    while i < get(w, S + 464):
        if consume_argument(s, w, i) == 0:
            return 1
        i = i + 1
    tag = constant(w, 9, ir_integer(w, selected))
    if tag == 0:
        return 1
    names = allocate(w, type_width(s, typ) * 8)
    put(w, names, tag)
    offset = 1
    i = 0
    while i < word(s, record + 37032):
        variant = record + 37040 + i * 24
        width = 0
        j = 0
        while j < word(s, variant + 16):
            field = word(s, record + 4272 + (word(s, variant + 8) + j) * 16)
            width = width + type_width(s, field)
            j = j + 1
        if i == selected:
            j = 0
            while j < get(w, S + 464):
                value = actual(w, j)
                copy_names(w, names + offset * 8, get(w, value + 16), get(w, value + 24))
                offset = offset + get(w, value + 24)
                j = j + 1
        else:
            zeros = zero_range(s, w, record + 160 + offset * 8, width)
            if get(w, S + 112) != 0:
                return 1
            copy_names(w, names + offset * 8, zeros, width)
            offset = offset + width
        i = i + 1
    activate(w, output_value(w, 0), names, 0)
    return 0

def enum_tag(s:readbuf, w:mutbuf) -> u64:
    if attrs_are(w, 0) == 0:
        return 1
    if get(w, S + 464) != 1:
        return fail(w, 54)
    if type_kind(s, get(w, actual(w, 0) + 8)) != 2:
        return fail(w, 54)
    return request_type(w, literal(w, C_u32), 180)

def task_create(s:readbuf, w:mutbuf) -> u64:
    if attrs_are(w, 0) == 0:
        return 1
    if get(w, S + 208) != 1:
        return fail(w, 55)
    typ = declared_type(w, 0)
    if type_kind(s, typ) != 3 or get(w, S + 464) != 1:
        return fail(w, 55)
    put(w, S + 520, typ)
    return request_protocol(w, typ, 190)

def task_create_done(s:readbuf, w:mutbuf) -> u64:
    typ = get(w, S + 520)
    state = word(s, type_at(typ) + 37808)
    result = word(s, type_at(typ) + 37816)
    if get(w, actual(w, 0) + 8) != state:
        return fail(w, 56)
    if consume_argument(s, w, 0) == 0:
        return 1
    tag = constant(w, 7, ir_integer(w, 0))
    if tag == 0:
        return 1
    token = zero_primitive(w, 13)
    if token == 0:
        return 1
    inactive = zero_range(s, w, type_at(result) + 160, type_width(s, result))
    if get(w, S + 112) != 0:
        return 1
    names = allocate(w, type_width(s, typ) * 8)
    put(w, names, tag)
    put(w, names + 8, token)
    copy_names(w, names + 16, get(w, actual(w, 0) + 16), type_width(s, state))
    copy_names(w, names + (2 + type_width(s, state)) * 8, inactive, type_width(s, result))
    activate(w, output_value(w, 0), names, 0)
    return 0

def task_operation(s:readbuf, w:mutbuf) -> u64:
    if attrs_are(w, 0) == 0:
        return 1
    if get(w, S + 464) != 1:
        return fail(w, 57)
    typ = get(w, actual(w, 0) + 8)
    if type_kind(s, typ) != 3:
        return fail(w, 57)
    operation = get(w, S + 488)
    if operation == 13:
        return request_type(w, literal(w, C_u8), 200)
    put(w, S + 520, typ)
    if operation == 17:
        return expect_outputs(w, singleton(w, word(s, type_at(typ) + 37816)), 1, 210)
    if operation == 18:
        return expect_outputs(w, 0, 0, 210)
    return expect_outputs(w, singleton(w, typ), 1, 210)

def task_operation_outputs(s:readbuf, w:mutbuf) -> u64:
    if check_outputs(w) == 0 or consume_argument(s, w, 0) == 0:
        return 1
    out = ir_list(w)
    i = 0
    while i < get(w, S + 208):
        value = output_value(w, i)
        typ = get(w, value + 8)
        count = type_width(s, typ)
        names = allocate(w, count * 8)
        j = 0
        while j < count:
            name = fresh(w)
            if name == 0:
                return 1
            put(w, names + j * 8, name)
            ir_append(w, out, parameter(w, name, word(s, type_at(typ) + 160 + j * 8)))
            j = j + 1
        activate(w, value, names, 0)
        i = i + 1
    put(w, S + 512, out)
    typ = get(w, S + 520)
    slot = HELPER_CACHE + (typ * 5 + get(w, S + 488) - 14) * 16
    put(w, S + 656, slot)
    cached = get(w, slot)
    if cached != 0:
        return task_call_done(w, cached)
    return request_protocol(w, typ, 211)

def protocol_function(s:readbuf, w:mutbuf, typ:u64, cancel:u64) -> u64:
    name = word(s, type_at(typ) + 37824 + cancel * 8)
    functions = g_field(w, get(w, S + 352), K_functions)
    item = functions + 24
    i = 0
    while i < g_count(w, functions):
        if type_name_equal(s, w, name, g_field(w, item, K_name)) != 0:
            return item
        item = g_end(w, item)
        i = i + 1
    invalid(w)
    return 0

def request_helper(s:readbuf, w:mutbuf, typ:u64, step:u64) -> u64:
    poll = protocol_function(s, w, typ, 0)
    cancel = protocol_function(s, w, typ, 1)
    if poll == 0 or cancel == 0:
        return invalid(w)
    root = ir_list(w)
    ir_append(w, root, ir_integer(w, 6))
    ir_append(w, root, ir_integer(w, typ))
    ir_append(w, root, ir_integer(w, step))
    operation = C_start
    code = get(w, S + 488)
    if code == 15:
        operation = C_poll
    elif code == 16:
        operation = C_cancel
    elif code == 17:
        operation = C_join
    elif code == 18:
        operation = C_close
    ir_append(w, root, literal(w, operation))
    ir_append(w, root, ir_integer(w, get(w, S + 72)))
    ir_append(w, root, ir_source(w, g_field(w, poll, K_effects)))
    ir_append(w, root, ir_source(w, g_field(w, cancel, K_effects)))
    put(w, S + 640, get(w, S + 72))
    return service_request(w, root, 6, 212)

def task_call_done(w:mutbuf, identifier:u64) -> u64:
    if identifier == 0 or identifier > 8192:
        return invalid(w)
    args = ir_list(w)
    value = actual(w, 0)
    ir_extend(w, args, get(w, value + 16), get(w, value + 24))
    attrs = ir_object(w)
    ir_pair(w, attrs, literal(w, C_function), ir_generated(w, identifier))
    instruction(w, literal(w, C_call), args, get(w, S + 512), attrs)
    return 0

def find_signature(w:mutbuf, name:u64) -> u64:
    registry = get(w, S + 288)
    item = registry + 24
    i = 0
    while i < g_count(w, registry):
        if same_text(w, g_at(w, item, 0), name) != 0:
            return item
        item = g_end(w, item)
        i = i + 1
    return 0

def registry_types(w:mutbuf, row:u64, field:u64) -> u64:
    source = g_at(w, row, field)
    values = allocate(w, g_count(w, source) * 8)
    item = source + 24
    i = 0
    while i < g_count(w, source):
        selected = item
        if field == 1:
            selected = g_at(w, item, 1)
        put(w, values + i * 8, g_integer(w, selected))
        item = g_end(w, item)
        i = i + 1
    return values

def call_operation(s:readbuf, w:mutbuf) -> u64:
    if attrs_are(w, K_function) == 0:
        return 1
    name = g_field(w, get(w, S + 448), K_function)
    status = name_status(w, name)
    if status != 0:
        return fail(w, choose(status == 2, 60, 59))
    signature = find_signature(w, name)
    if signature == 0:
        return fail(w, 61)
    params = g_at(w, signature, 1)
    if get(w, S + 464) != g_count(w, params):
        return fail(w, 62)
    item = params + 24
    i = 0
    while i < get(w, S + 464):
        if get(w, actual(w, i) + 8) != g_integer(w, g_at(w, item, 1)):
            return fail(w, 62)
        item = g_end(w, item)
        i = i + 1
    put(w, S + 520, signature)
    return expect_outputs(w, registry_types(w, signature, 2), g_count(w, g_at(w, signature, 2)), 220)

def call_operation_done(s:readbuf, w:mutbuf) -> u64:
    if check_outputs(w) == 0:
        return 1
    i = 0
    while i < get(w, S + 464):
        if type_owns(s, get(w, actual(w, i) + 8)) != 0:
            if consume_argument(s, w, i) == 0:
                return 1
        i = i + 1
    out = ir_list(w)
    i = 0
    while i < get(w, S + 208):
        value = output_value(w, i)
        typ = get(w, value + 8)
        count = type_width(s, typ)
        names = allocate(w, count * 8)
        j = 0
        while j < count:
            name = 0
            if typ <= 16:
                name = ir_source(w, get(w, value))
            else:
                name = fresh(w)
                if name == 0:
                    return 1
            put(w, names + j * 8, name)
            ir_append(w, out, parameter(w, name, word(s, type_at(typ) + 160 + j * 8)))
            j = j + 1
        activate(w, value, names, 0)
        i = i + 1
    args = ir_list(w)
    i = 0
    while i < get(w, S + 464):
        value = actual(w, i)
        ir_extend(w, args, get(w, value + 16), get(w, value + 24))
        i = i + 1
    attrs = ir_object(w)
    ir_pair(w, attrs, literal(w, C_function), ir_source(w, g_field(w, get(w, S + 448), K_function)))
    instruction(w, literal(w, C_call), args, out, attrs)
    return 0

def primitive_operation(s:readbuf, w:mutbuf) -> u64:
    i = 0
    while i < get(w, S + 464):
        if get(w, actual(w, i) + 8) > 16:
            return fail(w, 63)
        i = i + 1
    i = 0
    while i < get(w, S + 208):
        if declared_type(w, i) > 16:
            return fail(w, 63)
        i = i + 1
    op = g_field(w, get(w, S + 432), K_op)
    consuming = primitive_consumes(w, op)
    if consuming != 0:
        i = 0
        while i < get(w, S + 464):
            if consume_argument(s, w, i) == 0:
                return 1
            i = i + 1
    out = ir_list(w)
    i = 0
    while i < get(w, S + 208):
        value = output_value(w, i)
        name = ir_source(w, get(w, value))
        activate(w, value, singleton(w, name), 0)
        ir_append(w, out, parameter(w, name, get(w, value + 8)))
        i = i + 1
    args = ir_list(w)
    i = 0
    while i < get(w, S + 464):
        value = actual(w, i)
        ir_extend(w, args, get(w, value + 16), get(w, value + 24))
        i = i + 1
    instruction(w, ir_source(w, op), args, out, ir_source(w, get(w, S + 448)))
    return 0
'''


def suffix(packed):
    lines = ['def operation_id(w:mutbuf, node:u64) -> u64:']
    for index, opcode in enumerate(OPCODES, 1):
        lines += ['    if text_is(w, node, ' + ', '.join(map(str, packed(opcode))) + ') != 0:',
                  '        return ' + str(index)]
    lines += ['    return 0', '', 'def primitive_consumes(w:mutbuf, node:u64) -> u64:']
    for opcode in ('owner.move', 'owner.drop', 'loan.end', 'chain.try_push', 'chain.pop'):
        lines += ['    if text_is(w, node, ' + ', '.join(map(str, packed(opcode))) + ') != 0:',
                  '        return 1']
    lines += ['    return 0']
    return '\n'.join(lines) + '\n'
