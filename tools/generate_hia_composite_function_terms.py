"""Complete HIA terminator/CFG and function-envelope owner candidate.

This is authoring input for the indivisible function bundle. No hosted bridge
uses these routines to interpret a lowering plan. Arrays remain concrete native
IR views, including repeated wide returns and match-edge arguments.
"""

CONSTANTS = {}
ERRORS = {
    200: ('E_HIA_CFG', 'missing nominal terminator'),
    201: ('E_HIA_CFG', 'unknown nominal terminator'),
    202: ('E_HIA_CFG', 'nominal branch condition must be bool'),
    203: ('E_HIA_TYPE', 'nominal return types differ'),
    204: ('E_HIA_RESOURCE', 'return leaves a live nominal value'),
    205: ('E_HIA_TYPE', 'match requires a nominal enum'),
    206: ('E_HIA_CFG', 'match cases must be a list'),
    207: ('E_HIA_NAME', 'matched variant: invalid/reserved ASCII identifier'),
    208: ('E_HIA_NAME', 'matched variant: identifier uses the elaborator namespace'),
    209: ('E_HIA_CFG', 'duplicate match case'),
    210: ('E_HIA_RESOURCE', 'matched linear enum cannot also escape on its case edge'),
    211: ('E_HIA_CFG', 'enum match must be exhaustive'),
    212: ('E_HIA_NAME', 'edge target: invalid/reserved ASCII identifier'),
    213: ('E_HIA_NAME', 'edge target: identifier uses the elaborator namespace'),
    214: ('E_HIA_FORMAT', 'edge arguments: expected value list'),
    215: ('E_HIA_NAME', 'edge arguments: invalid/reserved ASCII identifier'),
    216: ('E_HIA_CFG', 'nominal edge names a missing block'),
    217: ('E_HIA_RESOURCE', 'nominal linear value duplicated on edge'),
    218: ('E_HIA_RESOURCE', 'edge drops a live nominal value'),
    219: ('E_HIA_TYPE', 'nominal edge types differ'),
    220: ('E_HIA_FORMAT', 'return values: expected value list'),
    221: ('E_HIA_NAME', 'return values: invalid/reserved ASCII identifier'),
    222: ('E_HIA_FORMAT', 'match case arguments: expected value list'),
    223: ('E_HIA_NAME', 'match case arguments: invalid/reserved ASCII identifier'),
    1200: ('E_HIA_FORMAT', 'jump: expected exactly args, op, target'),
    1201: ('E_HIA_FORMAT', 'branch: expected exactly cond, else, op, then'),
    1202: ('E_HIA_FORMAT', 'return: expected exactly op, values'),
    1203: ('E_HIA_FORMAT', 'trap: expected exactly code, op'),
    1204: ('E_HIA_FORMAT', 'enum match: expected exactly cases, op, value'),
    1205: ('E_HIA_FORMAT', 'match case: expected exactly args, target, variant'),
    1206: ('E_HIA_FORMAT', 'nominal edge: expected exactly args, target'),
}

# Match-local scratch, shared only within one terms invocation:
# 768 term, 776 matched Value, 784 enum descriptor, 792 carry table,
# 800 ordered cases, 808 payload offset, 816 variant index, 824 variants,
# 832 current name mapping, 840 current decision block, 848 decision ops,
# 856 payload vector, 864 payload width, 872 first native field descriptor,
# 880 field count, 888 current case, 896 arm names, 904 arm block, 912 arm ops.
# These are function-local native pointers. NEXT must reset them with the arena.

BODY = r'''
def function_terms(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < W_BYTES:
        return ABI
    if length(o) < 64 or length(s) != TYPE_BYTES:
        return invalid(w)
    if get(w, S) != STATE_MAGIC or word(s, TS) != TYPE_MAGIC or word(s, TS + 48) != 1:
        return invalid(w)
    if get(w, S + 96) != 0 or get(w, S + 112) != 0 or get(w, S + 312) != 0 or get(w, S + 120) != 1000:
        return invalid(w)
    if terms_lower(s, w) == 0:
        return admit_frame(o, w, 1)
    block = get(w, S + 384)
    put(w, S + 384, get(w, block + 80))
    if get(w, S + 384) != 0:
        put(w, S + 120, 100)
        return admit_frame(o, w, 21)
    complete = terms_function(s, w)
    if complete == 0:
        return admit_frame(o, w, 1)
    put(w, S + 120, 2000)
    stream_begin(w, complete, 0)
    return admit_frame(o, w, 2)

def terms_shape(w:mutbuf, node:u64, fields:u64, error:u64) -> u64:
    if g_shape(w, node, fields) == 0:
        fail(w, error)
        return 0
    return 1

def terms_names(w:mutbuf, node:u64, list_error:u64, name_error:u64) -> u64:
    if g_kind(w, node) != 5:
        fail(w, list_error)
        return 0
    item = node + 24
    i = 0
    while i < g_count(w, node):
        if name_status(w, item) == 1:
            fail(w, name_error)
            return 0
        item = g_end(w, item)
        i = i + 1
    return 1

def terms_source_literal(w:mutbuf, node:u64, identifier:u64) -> u64:
    text = literal(w, identifier)
    if g_kind(w, node) != 4 or g_size(w, node) != get(w, text + 16):
        return 0
    i = 0
    while i < g_size(w, node):
        if byte(w, node + 16 + i) != byte(w, get(w, text + 8) + i):
            return 0
        i = i + 1
    return 1

def terms_lower(s:readbuf, w:mutbuf) -> u64:
    term = get(w, get(w, S + 384) + 24)
    if g_kind(w, term) != 6 or g_kind(w, g_field(w, term, K_op)) != 4:
        fail(w, 200)
        return 0
    op = g_field(w, term, K_op)
    if terms_source_literal(w, op, C_jump) != 0:
        return terms_jump(s, w, term)
    if terms_source_literal(w, op, C_branch) != 0:
        return terms_branch(s, w, term)
    if terms_source_literal(w, op, C_ret) != 0:
        return terms_return(s, w, term)
    if terms_source_literal(w, op, C_trap) != 0:
        if terms_shape(w, term, K_op | K_code, 1203) == 0:
            return 0
        result = ir_object(w)
        ir_pair(w, result, literal(w, C_op), ir_source(w, op))
        ir_pair(w, result, literal(w, C_code), ir_source(w, g_field(w, term, K_code)))
        ir_pair(w, get(w, S + 400), literal(w, C_term), result)
        return 1
    if terms_source_literal(w, op, C_match) != 0:
        return terms_match(s, w, term)
    fail(w, 201)
    return 0

def terms_table_slots(count:u64) -> u64:
    slots = 1
    while slots < count * 2:
        slots = slots * 2
    return slots

def terms_pointer_slot(w:mutbuf, table:u64, mask:u64, value:u64) -> u64:
    index = (value >> 3) & mask
    while get(w, table + index * 16) != 0:
        if get(w, table + index * 16) == value:
            return table + index * 16
        index = (index + 1) & mask
    return table + index * 16

def terms_live(s:readbuf, w:mutbuf, value:u64) -> u64:
    if get(w, value + 64) == 0 or get(w, value + 40) != 0 or get(w, value + 32) != 0:
        return 0
    return type_linear(s, get(w, value + 8))

def terms_transfer(s:readbuf, w:mutbuf, args:u64, exempt:u64) -> u64:
    mark = get(w, S + 8)
    slots = terms_table_slots(g_count(w, args))
    table = allocate(w, slots * 16)
    item = args + 24
    i = 0
    while i < g_count(w, args):
        value = value_of(w, item)
        if value == 0:
            put(w, S + 8, mark)
            return 0
        if type_linear(s, get(w, value + 8)) != 0:
            slot = terms_pointer_slot(w, table, slots - 1, value)
            if get(w, slot) != 0:
                fail(w, 217)
                put(w, S + 8, mark)
                return 0
            put(w, slot, value)
        item = g_end(w, item)
        i = i + 1
    value = get(w, get(w, S + 384) + 56)
    while value != 0:
        if value != exempt and terms_live(s, w, value) != 0:
            if get(w, terms_pointer_slot(w, table, slots - 1, value)) == 0:
                fail(w, 218)
                put(w, S + 8, mark)
                return 0
        value = get(w, value + 48)
    put(w, S + 8, mark)
    return 1

def terms_edge_types(s:readbuf, w:mutbuf, block:u64, args:u64, fields:u64, count:u64) -> u64:
    if count + g_count(w, args) != get(w, block + 88):
        fail(w, 219)
        return 0
    formal = get(w, block + 56)
    i = 0
    while i < count:
        if word(s, fields + i * 16 + 8) != get(w, formal + 8):
            fail(w, 219)
            return 0
        formal = get(w, formal + 48)
        i = i + 1
    item = args + 24
    i = 0
    while i < g_count(w, args):
        value = value_of(w, item)
        if value == 0:
            return 0
        if get(w, value + 8) != get(w, formal + 8):
            fail(w, 219)
            return 0
        formal = get(w, formal + 48)
        item = g_end(w, item)
        i = i + 1
    return 1

def terms_edge_check(s:readbuf, w:mutbuf, target:u64, args:u64, fields:u64, count:u64, exempt:u64) -> u64:
    status = name_status(w, target)
    if status != 0:
        fail(w, choose(status == 2, 213, 212))
        return 0
    if terms_names(w, args, 214, 215) == 0:
        return 0
    block = table_get(w, get(w, S + 232), 8191, target)
    if block == 0:
        fail(w, 216)
        return 0
    if terms_transfer(s, w, args, exempt) == 0:
        return 0
    return terms_edge_types(s, w, block, args, fields, count)

def terms_flat_arguments(w:mutbuf, args:u64) -> u64:
    result = ir_list(w)
    item = args + 24
    i = 0
    while i < g_count(w, args):
        value = value_of(w, item)
        if value == 0:
            return 0
        ir_extend(w, result, get(w, value + 16), get(w, value + 24))
        item = g_end(w, item)
        i = i + 1
    return result

def terms_edge_object(w:mutbuf, target:u64, args:u64) -> u64:
    result = ir_object(w)
    ir_pair(w, result, literal(w, C_target), target)
    ir_pair(w, result, literal(w, C_args), args)
    return result

def terms_jump_object(w:mutbuf, target:u64, args:u64) -> u64:
    result = ir_object(w)
    ir_pair(w, result, literal(w, C_op), literal(w, C_jump))
    ir_pair(w, result, literal(w, C_target), target)
    ir_pair(w, result, literal(w, C_args), args)
    return result

def terms_branch_object(w:mutbuf, condition:u64, left:u64, right:u64) -> u64:
    result = ir_object(w)
    ir_pair(w, result, literal(w, C_op), literal(w, C_branch))
    ir_pair(w, result, literal(w, C_cond), condition)
    ir_pair(w, result, literal(w, C_then), left)
    ir_pair(w, result, literal(w, C_else), right)
    return result

def terms_jump(s:readbuf, w:mutbuf, term:u64) -> u64:
    if terms_shape(w, term, K_op | K_target | K_args, 1200) == 0:
        return 0
    target = g_field(w, term, K_target)
    args = g_field(w, term, K_args)
    if terms_edge_check(s, w, target, args, 0, 0, 0) == 0:
        return 0
    result = terms_jump_object(w, ir_source(w, target), terms_flat_arguments(w, args))
    ir_pair(w, get(w, S + 400), literal(w, C_term), result)
    return 1

def terms_source_edge(s:readbuf, w:mutbuf, edge:u64) -> u64:
    if terms_shape(w, edge, K_target | K_args, 1206) == 0:
        return 0
    target = g_field(w, edge, K_target)
    args = g_field(w, edge, K_args)
    if terms_edge_check(s, w, target, args, 0, 0, 0) == 0:
        return 0
    return terms_edge_object(w, ir_source(w, target), terms_flat_arguments(w, args))

def terms_branch(s:readbuf, w:mutbuf, term:u64) -> u64:
    if terms_shape(w, term, K_op | K_cond | K_then | K_else, 1201) == 0:
        return 0
    condition = value_of(w, g_field(w, term, K_cond))
    if condition == 0:
        return 0
    if get(w, condition + 8) != 1:
        fail(w, 202)
        return 0
    left = terms_source_edge(s, w, g_field(w, term, K_then))
    if left == 0:
        return 0
    right = terms_source_edge(s, w, g_field(w, term, K_else))
    if right == 0:
        return 0
    result = terms_branch_object(w, get(w, get(w, condition + 16)), left, right)
    ir_pair(w, get(w, S + 400), literal(w, C_term), result)
    return 1

def terms_return_values(w:mutbuf, args:u64) -> u64:
    result = allocate(w, g_count(w, args) * 8)
    item = args + 24
    i = 0
    while i < g_count(w, args):
        value = value_of(w, item)
        if value == 0:
            return 0
        put(w, result + i * 8, value)
        item = g_end(w, item)
        i = i + 1
    return result

def terms_return_types(w:mutbuf, values:u64, count:u64) -> u64:
    returns = g_at(w, get(w, S + 136), 2)
    if count != g_count(w, returns):
        fail(w, 203)
        return 0
    item = returns + 24
    i = 0
    while i < count:
        if get(w, get(w, values + i * 8) + 8) != g_integer(w, item):
            fail(w, 203)
            return 0
        item = g_end(w, item)
        i = i + 1
    return 1

def terms_return(s:readbuf, w:mutbuf, term:u64) -> u64:
    if terms_shape(w, term, K_op | K_values, 1202) == 0:
        return 0
    args = g_field(w, term, K_values)
    if terms_names(w, args, 220, 221) == 0:
        return 0
    values = terms_return_values(w, args)
    if values == 0 or terms_return_types(w, values, g_count(w, args)) == 0:
        return 0
    item = args + 24
    i = 0
    while i < g_count(w, args):
        if consume_source(s, w, item) == 0:
            return 0
        item = g_end(w, item)
        i = i + 1
    value = get(w, get(w, S + 384) + 56)
    while value != 0:
        if terms_live(s, w, value) != 0:
            fail(w, 204)
            return 0
        value = get(w, value + 48)
    flattened = ir_list(w)
    i = 0
    while i < g_count(w, args):
        value = get(w, values + i * 8)
        ir_extend(w, flattened, get(w, value + 16), get(w, value + 24))
        i = i + 1
    result = ir_object(w)
    ir_pair(w, result, literal(w, C_op), literal(w, C_ret))
    ir_pair(w, result, literal(w, C_values), flattened)
    ir_pair(w, get(w, S + 400), literal(w, C_term), result)
    return 1

def terms_function_returns(s:readbuf, w:mutbuf, returns:u64) -> u64:
    result = ir_list(w)
    item = returns + 24
    i = 0
    while i < g_count(w, returns):
        typ = g_integer(w, item)
        values = flat_vector(s, w, typ)
        if values == 0:
            return 0
        ir_extend(w, result, values, type_width(s, typ))
        item = g_end(w, item)
        i = i + 1
    return result

def terms_origin_name(w:mutbuf, origin:u64, entry:u64) -> u64:
    if g_kind(w, origin) != 5 or g_count(w, origin) != 2:
        invalid(w)
        return 0
    formal = g_at(w, origin, 0)
    offset = g_integer(w, g_at(w, origin, 1))
    if g_kind(w, formal) != 4:
        invalid(w)
        return 0
    value = table_get(w, get(w, S + 240), 262143, formal)
    if value == 0:
        invalid(w)
        return 0
    if get(w, value + 56) != entry or offset >= get(w, value + 24):
        invalid(w)
        return 0
    return get(w, get(w, value + 16) + offset * 8)

def terms_origins(s:readbuf, w:mutbuf, returns:u64, entry:u64) -> u64:
    row = g_at(w, get(w, S + 296), get(w, S + 280))
    if g_kind(w, row) != 5 or g_count(w, row) != 2:
        invalid(w)
        return 0
    if same_text(w, g_at(w, row, 0), g_field(w, get(w, S + 128), K_name)) == 0:
        invalid(w)
        return 0
    origins = g_at(w, row, 1)
    if g_kind(w, origins) != 5 or g_count(w, origins) != g_count(w, returns):
        invalid(w)
        return 0
    result = ir_list(w)
    nulls = allocate(w, 512 * 8)
    null = ir_null(w)
    i = 0
    while i < 512:
        put(w, nulls + i * 8, null)
        i = i + 1
    item = returns + 24
    origin = origins + 24
    i = 0
    while i < g_count(w, returns):
        typ = g_integer(w, item)
        if issued(s, typ) == 0:
            invalid(w)
            return 0
        width = type_width(s, typ)
        if g_kind(w, origin) == 0:
            ir_extend(w, result, nulls, width)
        else:
            name = terms_origin_name(w, origin, entry)
            if name == 0 or width != 1:
                invalid(w)
                return 0
            ir_append(w, result, name)
        item = g_end(w, item)
        origin = g_end(w, origin)
        i = i + 1
    return result

def terms_function(s:readbuf, w:mutbuf) -> u64:
    fn = get(w, S + 128)
    entry = table_get(w, get(w, S + 232), 8191, g_field(w, fn, K_entry))
    if entry == 0:
        invalid(w)
        return 0
    returns = g_at(w, get(w, S + 136), 2)
    flat_returns = terms_function_returns(s, w, returns)
    if flat_returns == 0:
        return 0
    result = ir_object(w)
    ir_pair(w, result, literal(w, C_name), ir_source(w, g_field(w, fn, K_name)))
    ir_pair(w, result, literal(w, C_params), get(w, entry + 48))
    ir_pair(w, result, literal(w, C_returns), flat_returns)
    ir_pair(w, result, literal(w, C_effects), ir_source(w, g_field(w, fn, K_effects)))
    ir_pair(w, result, literal(w, C_entry), ir_source(w, g_field(w, fn, K_entry)))
    ir_pair(w, result, literal(w, C_blocks), get(w, S + 392))
    if get(w, S + 264) == 4 and g_field(w, fn, K_return_loans) != N:
        origins = terms_origins(s, w, returns, entry)
        if origins == 0:
            return 0
        ir_pair(w, result, literal(w, C_return_loans), origins)
    return result
'''

BODY += r'''
def terms_ir_size(w:mutbuf, node:u64) -> u64:
    kind = get(w, node)
    if kind == 0:
        source = SOURCE_BASE + get(w, node + 8)
        if g_kind(w, source) == 4 and g_size(w, source) <= 128:
            return g_size(w, source)
    elif kind == 1:
        if get(w, node + 16) <= 128:
            return get(w, node + 16)
    invalid(w)
    return 0

def terms_ir_byte(w:mutbuf, node:u64, index:u64) -> u64:
    if get(w, node) == 0:
        return byte(w, SOURCE_BASE + get(w, node + 8) + 16 + index)
    return byte(w, get(w, node + 8) + index)

def terms_ir_hash(w:mutbuf, node:u64) -> u64:
    size = terms_ir_size(w, node)
    result = 14695981039346656037
    i = 0
    while i < size:
        result = (result ^ terms_ir_byte(w, node, i)) * 1099511628211
        i = i + 1
    return result

def terms_ir_same(w:mutbuf, left:u64, right:u64) -> u64:
    size = terms_ir_size(w, left)
    if size != terms_ir_size(w, right):
        return 0
    i = 0
    while i < size:
        if terms_ir_byte(w, left, i) != terms_ir_byte(w, right, i):
            return 0
        i = i + 1
    return 1

def terms_carry_slot(w:mutbuf, carry:u64, name:u64) -> u64:
    table = get(w, carry + 24)
    mask = get(w, carry + 32)
    index = terms_ir_hash(w, name) & mask
    while get(w, table + index * 16) != 0:
        if terms_ir_same(w, get(w, table + index * 16), name) != 0:
            return table + index * 16
        index = (index + 1) & mask
    return table + index * 16

def terms_carry_index(w:mutbuf, carry:u64, name:u64) -> u64:
    slot = terms_carry_slot(w, carry, name)
    if get(w, slot) == 0:
        invalid(w)
        return N
    return get(w, slot + 8) - 1

def terms_map_name(w:mutbuf, carry:u64, mapping:u64, name:u64) -> u64:
    index = terms_carry_index(w, carry, name)
    if index == N:
        return 0
    return get(w, mapping + index * 8)

def terms_carry_insert(w:mutbuf, carry:u64, name:u64, typ:u64) -> u64:
    slot = terms_carry_slot(w, carry, name)
    if get(w, slot) == 0:
        count = get(w, carry)
        put(w, get(w, carry + 8) + count * 8, name)
        put(w, get(w, carry + 16) + count * 8, typ)
        put(w, slot, name)
        put(w, slot + 8, count + 1)
        put(w, carry, count + 1)
    return 0

def terms_carry_capacity(w:mutbuf) -> u64:
    value = get(w, get(w, S + 384) + 56)
    total = 0
    while value != 0:
        if get(w, value + 64) != 0 and get(w, value + 40) == 0:
            total = total + get(w, value + 24)
        value = get(w, value + 48)
    if total > 32768:
        invalid(w)
        return 0
    return total

def terms_carry(s:readbuf, w:mutbuf) -> u64:
    capacity = terms_carry_capacity(w)
    result = allocate(w, 48)
    put(w, result + 8, allocate(w, capacity * 8))
    put(w, result + 16, allocate(w, capacity * 8))
    slots = terms_table_slots(capacity)
    put(w, result + 24, allocate(w, slots * 16))
    put(w, result + 32, slots - 1)
    put(w, result + 40, allocate(w, capacity * 8))
    value = get(w, get(w, S + 384) + 56)
    while value != 0:
        if get(w, value + 64) != 0 and get(w, value + 40) == 0:
            i = 0
            while i < get(w, value + 24):
                terms_carry_insert(w, result, get(w, get(w, value + 16) + i * 8),
                    word(s, type_at(get(w, value + 8)) + 160 + i * 8))
                i = i + 1
        value = get(w, value + 48)
    return result

def terms_cases_check(s:readbuf, w:mutbuf, cases:u64, matched:u64, term:u64) -> u64:
    mark = get(w, S + 8)
    slots = terms_table_slots(g_count(w, cases))
    table = allocate(w, slots * 16)
    item = cases + 24
    i = 0
    while i < g_count(w, cases):
        if terms_shape(w, item, K_variant | K_target | K_args, 1205) == 0:
            put(w, S + 8, mark)
            return 0
        name = g_field(w, item, K_variant)
        status = name_status(w, name)
        if status != 0:
            fail(w, choose(status == 2, 208, 207))
            put(w, S + 8, mark)
            return 0
        args = g_field(w, item, K_args)
        if terms_names(w, args, 222, 223) == 0:
            put(w, S + 8, mark)
            return 0
        if table_get(w, table, slots - 1, name) != 0:
            fail(w, 209)
            put(w, S + 8, mark)
            return 0
        table_put(w, table, slots - 1, name, item)
        if type_linear(s, get(w, matched + 8)) != 0:
            if terms_contains(w, args, g_field(w, term, K_value)) != 0:
                fail(w, 210)
                put(w, S + 8, mark)
                return 0
        item = g_end(w, item)
        i = i + 1
    put(w, S + 8, mark)
    return 1

def terms_contains(w:mutbuf, args:u64, name:u64) -> u64:
    item = args + 24
    i = 0
    while i < g_count(w, args):
        if same_text(w, item, name) != 0:
            return 1
        item = g_end(w, item)
        i = i + 1
    return 0

def terms_order_cases(s:readbuf, w:mutbuf, cases:u64, descriptor:u64) -> u64:
    count = word(s, descriptor + 37032)
    if g_count(w, cases) != count:
        fail(w, 211)
        return 0
    result = allocate(w, count * 8)
    i = 0
    while i < count:
        name = word(s, descriptor + 37040 + i * 24)
        item = cases + 24
        j = 0
        found = 0
        while j < count:
            if type_name_equal(s, w, name, g_field(w, item, K_variant)) != 0:
                found = item
            item = g_end(w, item)
            j = j + 1
        if found == 0:
            fail(w, 211)
            return 0
        put(w, result + i * 8, found)
        i = i + 1
    return result

def terms_match_prepare(s:readbuf, w:mutbuf, term:u64) -> u64:
    if terms_shape(w, term, K_op | K_value | K_cases, 1204) == 0:
        return 0
    matched = value_of(w, g_field(w, term, K_value))
    if matched == 0:
        return 0
    if type_kind(s, get(w, matched + 8)) != 2:
        fail(w, 205)
        return 0
    cases = g_field(w, term, K_cases)
    if g_kind(w, cases) != 5:
        fail(w, 206)
        return 0
    if terms_cases_check(s, w, cases, matched, term) == 0:
        return 0
    descriptor = type_at(get(w, matched + 8))
    ordered = terms_order_cases(s, w, cases, descriptor)
    if ordered == 0:
        return 0
    carry = terms_carry(s, w)
    put(w, S + 768, term)
    put(w, S + 776, matched)
    put(w, S + 784, descriptor)
    put(w, S + 792, carry)
    put(w, S + 800, ordered)
    put(w, S + 808, 1)
    put(w, S + 816, 0)
    put(w, S + 824, word(s, descriptor + 37032))
    put(w, S + 832, get(w, carry + 8))
    put(w, S + 840, get(w, S + 400))
    put(w, S + 848, get(w, S + 408))
    return 1

def terms_fresh_vector(w:mutbuf, count:u64) -> u64:
    result = allocate(w, count * 8)
    i = 0
    while i < count:
        name = fresh(w)
        if name == 0:
            return 0
        put(w, result + i * 8, name)
        i = i + 1
    return result

def terms_block(w:mutbuf, name:u64, names:u64, types:u64, count:u64, ops:u64, term:u64) -> u64:
    params = ir_list(w)
    i = 0
    while i < count:
        ir_append(w, params, parameter(w, get(w, names + i * 8), get(w, types + i * 8)))
        i = i + 1
    result = ir_object(w)
    ir_pair(w, result, literal(w, C_id), name)
    ir_pair(w, result, literal(w, C_params), params)
    ir_pair(w, result, literal(w, C_ops), ops)
    if term != 0:
        ir_pair(w, result, literal(w, C_term), term)
    return result

def terms_map_vector(w:mutbuf, carry:u64, mapping:u64, source:u64, count:u64) -> u64:
    result = allocate(w, count * 8)
    i = 0
    while i < count:
        name = terms_map_name(w, carry, mapping, get(w, source + i * 8))
        if name == 0:
            return 0
        put(w, result + i * 8, name)
        i = i + 1
    return result

def terms_map_arguments(w:mutbuf, args:u64, payload:u64, width:u64, carry:u64, mapping:u64) -> u64:
    result = ir_list(w)
    if width != 0:
        names = terms_map_vector(w, carry, mapping, payload, width)
        if names == 0:
            return 0
        ir_extend(w, result, names, width)
    slots = terms_table_slots(g_count(w, args))
    cache = allocate(w, slots * 16)
    item = args + 24
    i = 0
    while i < g_count(w, args):
        value = value_of(w, item)
        if value == 0:
            return 0
        count = get(w, value + 24)
        if count != 0:
            slot = terms_pointer_slot(w, cache, slots - 1, value)
            names = get(w, slot + 8)
            if get(w, slot) == 0:
                names = terms_map_vector(w, carry, mapping, get(w, value + 16), count)
                if names == 0:
                    return 0
                put(w, slot, value)
                put(w, slot + 8, names)
            ir_extend(w, result, names, count)
        item = g_end(w, item)
        i = i + 1
    return result

def terms_select_payload(w:mutbuf) -> u64:
    carry = get(w, S + 792)
    names = get(w, S + 856)
    i = 0
    while i < get(w, S + 864):
        index = terms_carry_index(w, carry, get(w, names + i * 8))
        if index == N:
            return 0
        put(w, get(w, carry + 40) + index * 8, get(w, S + 816) + 1)
        i = i + 1
    return 1

def terms_drop_padding(s:readbuf, w:mutbuf) -> u64:
    carry = get(w, S + 792)
    matched = get(w, S + 776)
    i = 1
    while i < get(w, matched + 24):
        index = terms_carry_index(w, carry, get(w, get(w, matched + 16) + i * 8))
        if index == N:
            return 0
        if get(w, get(w, carry + 40) + index * 8) != get(w, S + 816) + 1:
            typ = word(s, get(w, S + 784) + 160 + i * 8)
            if typ == 13 or typ == 16:
                flat_instruction(w, C_owner_drop, get(w, S + 896) + index * 8, 1, 0, 0)
            elif typ == 14 or typ == 15:
                fail(w, 65)
                return 0
        i = i + 1
    return 1

def terms_match_fields(s:readbuf, w:mutbuf) -> u64:
    descriptor = get(w, S + 784)
    variant = descriptor + 37040 + get(w, S + 816) * 24
    fields = descriptor + 4264 + word(s, variant + 8) * 16
    count = word(s, variant + 16)
    put(w, S + 872, fields)
    put(w, S + 880, count)
    i = 0
    width = 0
    while i < count:
        width = width + type_width(s, word(s, fields + i * 16 + 8))
        i = i + 1
    put(w, S + 856, get(w, get(w, S + 776) + 16) + get(w, S + 808) * 8)
    put(w, S + 864, width)
    put(w, S + 888, get(w, get(w, S + 800) + get(w, S + 816) * 8))
    return 0

def terms_match_arm(s:readbuf, w:mutbuf) -> u64:
    carry = get(w, S + 792)
    case = get(w, S + 888)
    if terms_edge_check(s, w, g_field(w, case, K_target), g_field(w, case, K_args),
            get(w, S + 872), get(w, S + 880), get(w, S + 776)) == 0:
        return 0
    names = terms_fresh_vector(w, get(w, carry))
    if names == 0:
        return 0
    name = fresh(w)
    if name == 0:
        return 0
    ops = ir_list(w)
    arm = terms_block(w, name, names, get(w, carry + 16), get(w, carry), ops, 0)
    put(w, S + 896, names)
    put(w, S + 904, arm)
    put(w, S + 912, ops)
    put(w, S + 920, name)
    if terms_select_payload(w) == 0:
        return 0
    put(w, S + 408, ops)
    if terms_drop_padding(s, w) == 0:
        put(w, S + 408, get(w, S + 848))
        return 0
    args = terms_map_arguments(w, g_field(w, case, K_args), get(w, S + 856),
        get(w, S + 864), carry, names)
    put(w, S + 408, get(w, S + 848))
    if args == 0:
        return 0
    target = terms_jump_object(w, ir_source(w, g_field(w, case, K_target)), args)
    ir_pair(w, arm, literal(w, C_term), target)
    ir_append(w, get(w, S + 392), arm)
    return 1

def terms_name_view(w:mutbuf, names:u64, count:u64) -> u64:
    result = ir_list(w)
    ir_extend(w, result, names, count)
    return result

def terms_user_trap(w:mutbuf) -> u64:
    result = ir_object(w)
    ir_pair(w, result, literal(w, C_op), literal(w, C_trap))
    ir_pair(w, result, literal(w, C_code), literal(w, C_user))
    return result

def terms_match_decision(w:mutbuf, matches:u64) -> u64:
    carry = get(w, S + 792)
    names = terms_fresh_vector(w, get(w, carry))
    if names == 0:
        return 0
    name = fresh(w)
    if name == 0:
        return 0
    last = choose(get(w, S + 816) + 1 == get(w, S + 824), 1, 0)
    term = 0
    if last != 0:
        term = terms_user_trap(w)
    ops = ir_list(w)
    block = terms_block(w, name, names, get(w, carry + 16), get(w, carry), ops, term)
    left = terms_edge_object(w, get(w, S + 920),
        terms_name_view(w, get(w, S + 832), get(w, carry)))
    right = terms_edge_object(w, name,
        terms_name_view(w, get(w, S + 832), get(w, carry)))
    if last != 0:
        ir_append(w, get(w, S + 392), block)
    ir_pair(w, get(w, S + 840), literal(w, C_term), terms_branch_object(w, matches, left, right))
    if last == 0:
        ir_append(w, get(w, S + 392), block)
        put(w, S + 832, names)
        put(w, S + 840, block)
        put(w, S + 848, ops)
        put(w, S + 400, block)
        put(w, S + 408, ops)
    return 1

def terms_match_step(s:readbuf, w:mutbuf) -> u64:
    terms_match_fields(s, w)
    if terms_match_arm(s, w) == 0:
        return 0
    expected = constant(w, 9, ir_integer(w, get(w, S + 816)))
    if expected == 0:
        return 0
    matches = fresh(w)
    if matches == 0:
        return 0
    tag = terms_map_name(w, get(w, S + 792), get(w, S + 832),
        get(w, get(w, get(w, S + 776) + 16)))
    if tag == 0:
        return 0
    flat_instruction(w, C_compare_eq, pair_types(w, tag, expected), 2, matches, 1)
    if terms_match_decision(w, matches) == 0:
        return 0
    put(w, S + 808, get(w, S + 808) + get(w, S + 864))
    put(w, S + 816, get(w, S + 816) + 1)
    return 1

def terms_match(s:readbuf, w:mutbuf, term:u64) -> u64:
    if terms_match_prepare(s, w, term) == 0:
        return 0
    while get(w, S + 816) < get(w, S + 824):
        if terms_match_step(s, w) == 0:
            return 0
    return 1
'''
