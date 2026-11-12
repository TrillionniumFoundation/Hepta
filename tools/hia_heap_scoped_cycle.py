"""Pure HIA block-local cyclic allocation proof for the heap state owner.

This authoring component is never a hosted policy fallback. The caller supplies
the canonical verified function's ordinary typed transport, graph arena/maps,
the shared signed bigints and heap interval transfers. ``cycle_peak(w, fn)``
returns N for the original None, a positive immutable bigint pointer for a
bound (including mathematical zero), or zero for arena/ABI/interval failure.
Arena words 64/72/80 retain the graph contract; word 88 holds the first original
interval error code. The caller must inspect errors before growing the arena.
No other global word is reserved. Unknown is the caller's zero value at 768.

Only const, int.cast and the six original checked/wrapping add/sub/mul transfers
refine size knowledge. Other allowed scalar operations are deliberately ignored,
including operations that would trap if executed. Every block starts with only
its intrinsic parameter bounds and zero live owners; all ordinary exits must
consume those owners. This proves neither loop termination nor cleanup on trap.
"""
from tools.generate_hia_program_execution import OP_IDS

SCOPED_OPS = tuple(('const int.cast int.neg.checked select bool.not bool.and bool.or '
    'bit.and bit.or bit.xor bit.not compare.eq compare.ne compare.lt compare.le compare.gt compare.ge '
    'int.add.checked int.sub.checked int.mul.checked int.add.wrap int.sub.wrap int.mul.wrap '
    'int.div.checked int.rem.checked int.shl.checked int.shr.checked '
    'buffer.new buffer.try_new owner.move owner.drop').split())
INTERVAL_OPS = tuple(('int.add.checked int.sub.checked int.mul.checked '
                      'int.add.wrap int.sub.wrap int.mul.wrap').split())

_BODY = r'''
def cycle_error(w:mutbuf, error:u64) -> u64:
    if get(w, 88) == 0:
        put(w, 88, error)
    return 0

def cycle_big(w:mutbuf, capacity:u64) -> u64:
    if capacity > 2305843009213693948:
        put(w, 80, 3)
        return 0
    value = heap_alloc(w, 24 + capacity * 8)
    if value == 0:
        return 0
    if big_init(w, value, capacity) == 0:
        put(w, 80, 3)
        return 0
    return value

def cycle_amount(w:mutbuf, amount:u64) -> u64:
    value = cycle_big(w, 2)
    if value == 0:
        return 0
    if big_set_u64(w, value, 0, amount) == 0:
        put(w, 80, 3)
        return 0
    return value

def cycle_total(w:mutbuf, previous:u64, amount:u64, subtract:u64) -> u64:
    operand = cycle_amount(w, amount)
    if operand == 0:
        return 0
    count = get(w, previous + 8)
    if count < 2:
        count = 2
    result = cycle_big(w, count + 1)
    if result == 0:
        return 0
    if big_add_signed(w, result, previous, operand, subtract) == 0:
        put(w, 80, 3)
        return 0
    return result

def cycle_lookup(w:mutbuf, known:u64, name:u64) -> u64:
    value = heap_map_get(w, known, name)
    return choose(value == 18446744073709551615, 768, value)

def cycle_scalar(w:mutbuf, node:u64) -> u64:
    if tag(w, node) != 2:
        return 18446744073709551615
    at = node + 16
    stop = end(w, node)
    sign = 0
    if at < stop and byte(w, at) == 45:
        sign = 1
        at = at + 1
    if at == stop:
        return cycle_error(w, 16)
    value = 0
    while at < stop:
        digit = byte(w, at)
        if digit < 48 or digit > 57:
            return cycle_error(w, 16)
        digit = digit - 48
        if value > (18446744073709551615 - digit) // 10:
            return cycle_error(w, 16)
        value = value * 10 + digit
        at = at + 1
    result = heap_alloc(w, 40)
    if result == 0:
        return 0
    sign = choose(value == 0, 0, sign)
    heap_emit(w, result, 2, sign, value, sign, value)
    return result

def cycle_seed(w:mutbuf, params:u64, known:u64) -> u64:
    index = 0
    while index < total(w, params):
        param = element(w, params, index)
        typ = type_id(w, field(w, param, 19))
        value = heap_alloc(w, 40)
        if value == 0:
            return 0
        status = heap_entry_value(w, typ, value)
        if status != 0:
            return cycle_error(w, status)
        if get(w, value) != 0:
            if heap_map_put(w, known, field(w, param, 5), value) == 0:
                return 0
        index = index + 1
    return 1

def cycle_const(w:mutbuf, instruction:u64, state:u64) -> u64:
    outputs = field(w, instruction, 17)
    if total(w, outputs) != 1:
        return 1
    value = field(w, field(w, instruction, 18), 20)
    if value == 18446744073709551615:
        return 1
    scalar = cycle_scalar(w, value)
    if scalar == 0:
        return 0
    if scalar != 18446744073709551615:
        if heap_map_put(w, get(w, state + 16), field(w, element(w, outputs, 0), 5), scalar) == 0:
            return 0
    return 1

def cycle_refine(w:mutbuf, instruction:u64, state:u64, op:u64) -> u64:
    args = field(w, instruction, 16)
    output = element(w, field(w, instruction, 17), 0)
    known = get(w, state + 16)
    left = cycle_lookup(w, known, element(w, args, 0))
    right = 768
    mode = 0
    if op == @INT_CAST@:
        mode = cast_id(w, field(w, field(w, instruction, 18), 21))
    else:
        right = cycle_lookup(w, known, element(w, args, 1))
    value = heap_alloc(w, 40)
    if value == 0:
        return 0
    status = heap_fold(w, op, type_id(w, field(w, output, 19)), mode, left, right, 768, value)
    if status != 0:
        return cycle_error(w, status)
    if get(w, value) != 0:
        if heap_map_put(w, known, field(w, output, 5), value) == 0:
            return 0
    return 1

def cycle_allocate(w:mutbuf, instruction:u64, state:u64, op:u64) -> u64:
    args = field(w, instruction, 16)
    outputs = field(w, instruction, 17)
    expected = choose(op == @BUFFER_NEW@, 1, 2)
    if total(w, args) != 1 or total(w, outputs) != expected:
        return 18446744073709551615
    extent = cycle_lookup(w, get(w, state + 16), element(w, args, 0))
    if heap_numeric(w, extent) == 0 or get(w, extent + 8) != 0 or get(w, extent + 24) != 0:
        return 18446744073709551615
    amount = get(w, extent + 32)
    if amount == 0 or amount > 9223372036854775807:
        return 18446744073709551615
    key = field(w, element(w, outputs, 0), 5)
    live = get(w, state + 24)
    if heap_map_entry(w, live, key) != 0:
        return 18446744073709551615
    if heap_map_put(w, live, key, amount) == 0:
        return 0
    value = cycle_total(w, get(w, state + 32), amount, 0)
    if value == 0:
        return 0
    put(w, state + 32, value)
    if big_cmp(w, get(w, state), value) == 1:
        put(w, state, value)
    put(w, state + 8, 1)
    return 1

def cycle_move(w:mutbuf, instruction:u64, state:u64) -> u64:
    args = field(w, instruction, 16)
    outputs = field(w, instruction, 17)
    if total(w, args) != 1 or total(w, outputs) != 1:
        return 18446744073709551615
    live = get(w, state + 24)
    source = element(w, args, 0)
    entry = heap_map_entry(w, live, source)
    if entry == 0:
        return 18446744073709551615
    key = field(w, element(w, outputs, 0), 5)
    if heap_map_entry(w, live, key) != 0:
        return 18446744073709551615
    amount = get(w, entry + 16)
    heap_map_drop(w, live, source)
    if heap_map_put(w, live, key, amount) == 0:
        return 0
    return 1

def cycle_drop(w:mutbuf, instruction:u64, state:u64) -> u64:
    args = field(w, instruction, 16)
    if total(w, args) != 1:
        return 18446744073709551615
    live = get(w, state + 24)
    key = element(w, args, 0)
    entry = heap_map_entry(w, live, key)
    if entry == 0:
        return 18446744073709551615
    amount = get(w, entry + 16)
    heap_map_drop(w, live, key)
    value = cycle_total(w, get(w, state + 32), amount, 1)
    if value == 0:
        return 0
    put(w, state + 32, value)
    return 1

def cycle_instruction(w:mutbuf, instruction:u64, state:u64) -> u64:
    op = opcode_id(w, field(w, instruction, 15))
    if op == 0 or op >= 64:
        return 18446744073709551615
    if (1 << op) & @SCOPED_MASK@ == 0:
        return 18446744073709551615
    if op == @CONST@:
        return cycle_const(w, instruction, state)
    if op == @INT_CAST@ or (1 << op) & @INTERVAL_MASK@ != 0:
        return cycle_refine(w, instruction, state, op)
    if op == @BUFFER_NEW@ or op == @BUFFER_TRY_NEW@:
        return cycle_allocate(w, instruction, state, op)
    if op == @OWNER_MOVE@:
        return cycle_move(w, instruction, state)
    if op == @OWNER_DROP@:
        return cycle_drop(w, instruction, state)
    return 1

def cycle_block(w:mutbuf, block:u64, state:u64) -> u64:
    known = heap_map(w)
    live = heap_map(w)
    value = cycle_amount(w, 0)
    if known == 0 or live == 0 or value == 0:
        return 0
    put(w, state + 16, known)
    put(w, state + 24, live)
    put(w, state + 32, value)
    if cycle_seed(w, field(w, block, 6), known) == 0:
        return 0
    ops = field(w, block, 13)
    index = 0
    while index < total(w, ops):
        result = cycle_instruction(w, element(w, ops, index), state)
        if result != 1:
            return result
        index = index + 1
    if get(w, live + 8) != 0 and term_id(w, field(w, field(w, block, 14), 15)) != 4:
        return 18446744073709551615
    if get(w, get(w, state + 32)) != 0:
        return 18446744073709551615
    return 1

def cycle_peak(w:mutbuf, fn:u64) -> u64:
    if get(w, 80) != 0 or get(w, 88) != 0:
        return 0
    blocks = field(w, fn, 10)
    index = 0
    while index < total(w, blocks):
        params = field(w, element(w, blocks, index), 6)
        param_index = 0
        while param_index < total(w, params):
            typ = type_id(w, field(w, element(w, params, param_index), 19))
            if typ == 13 or typ == 14 or typ == 15:
                return 18446744073709551615
            param_index = param_index + 1
        index = index + 1
    state = heap_alloc(w, 40)
    peak = cycle_amount(w, 0)
    if state == 0 or peak == 0:
        return 0
    put(w, state, peak)
    index = 0
    while index < total(w, blocks):
        result = cycle_block(w, element(w, blocks, index), state)
        if result == 0 or result == 18446744073709551615:
            return result
        index = index + 1
    if get(w, state + 8) == 0:
        return 18446744073709551615
    return get(w, state)
'''

BODY = _BODY.replace('@SCOPED_MASK@', str(sum(1 << OP_IDS[name] for name in SCOPED_OPS)))
BODY = BODY.replace('@INTERVAL_MASK@', str(sum(1 << OP_IDS[name] for name in INTERVAL_OPS)))
for _name, _value in OP_IDS.items():
    BODY = BODY.replace('@' + _name.upper().replace('.', '_') + '@', str(_value))
if '@' in BODY:
    raise ValueError('unresolved scoped heap cycle authoring constant')
