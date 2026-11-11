"""Author explicit machine-plan gates and closed-block register lifetimes in HIA.

Host replies contain exact built-in kinds, bounded text observations and the
already verified immutable Core tree. They do not contain admission answers,
opcode classifications, live intervals, conflicts or witness ordering.
"""
import ast
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_instruction_policy import SOURCE as TYPED_SOURCE
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

NONE = (1 << 64) - 1
ABI = 0xfffffffd
ERROR = 0x80000000
REGISTERS = ('rbx', 'r12', 'r13', 'r14', 'r15', 'r8', 'r9')
SCALAR_TYPES = ('i8', 'i16', 'i32', 'i64', 'u8', 'u16', 'u32', 'u64', 'isize', 'usize', 'bool')
LEAF_OPS = tuple(sorted((
    'const', 'int.add.wrap', 'int.add.checked', 'int.sub.wrap', 'int.sub.checked',
    'int.mul.wrap', 'int.mul.checked', 'int.div.checked', 'int.rem.checked',
    'int.shl.checked', 'int.shr.checked', 'int.neg.checked', 'int.cast',
    'bit.and', 'bit.or', 'bit.xor', 'bit.not', 'compare.eq', 'compare.ne',
    'compare.lt', 'compare.le', 'compare.gt', 'compare.ge', 'bool.and',
    'bool.or', 'bool.not', 'select', 'buffer.len', 'buffer.load', 'buffer.store')))
KEYS = ('schema', 'core_sha256', 'block_order', 'function_order',
        'scratch_registers', 'instruction_selection', 'function_alignment',
        'value_registers', 'move_immediate', 'alu_immediate', 'scalar_select',
        'functions', 'name', 'blocks', 'id', 'params', 'returns', 'ops', 'out',
        'type', 'args', 'term', 'op', 'values', 'cond', 'then', 'else')
SCHEMAS = ('hepta.hia.agent.block-layout.v1', 'hepta.hia.agent.machine-plan.v2',
           'hepta.hia.agent.machine-plan.v3', 'hepta.hia.agent.machine-plan.v4')

# Persistent private state begins at 64, validation frames at 4096 and copied
# typed trees at 8192. Request slots 0..55 are the only host-written state.
SOURCE = r'''
def machine_plan(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < 8192 or length(o) < 128:
        return ABI
    command = get(w, 0)
    stage = get(w, 64)
    if command == 0:
        if stage != 0:
            return ABI
        mode = get(w, 8)
        if mode > 1:
            return ABI
        if get(w, 16) != 6:
            return ERROR + choose(mode == 0, 1, 16)
        put(w, 72, mode)
        put(w, 80, NONE)
        put(w, 104, 8192)
        put(w, 64, choose(mode == 0, 1, 4))
        return choose(mode == 0, 1, 4)
    if command == 1:
        if stage != 1:
            return ABI
        if validate(s, w) == 0 or tag(s, 0) != 6:
            return ABI
        if length(s) > length(w) - 8192:
            return ABI
        copy_in(s, w, 8192)
        put(w, 80, 8192)
        put(w, 104, align8(8192 + length(s)))
        version = schema_id(w, field(w, 8192, 1))
        if version == 0:
            return ERROR + 3
        if plan_fields(w, 8192, version) == 0:
            return ERROR + 4
        put(w, 96, version)
        put(w, 64, 3)
        return 3
    if command == 2:
        if stage != 1:
            return ABI
        return ERROR + 2
    if command == 3:
        if stage != 3:
            return ABI
        if validate(s, w) == 0:
            return ABI
        at = get(w, 104)
        if length(s) > length(w) - at:
            return ABI
        copy_in(s, w, at)
        if same(w, field(w, get(w, 80), 2), at) == 0:
            return ERROR + 5
        put(w, 64, 4)
        return 4
    if command == 4:
        if stage != 4:
            return ABI
        if validate(s, w) == 0 or tag(s, 0) != 6:
            return ABI
        at = get(w, 104)
        if at > length(w) or length(s) > length(w) - at:
            return ABI
        copy_in(s, w, at)
        put(w, 88, at)
        put(w, 104, align8(at + length(s)))
        functions = field(w, at, 12)
        if functions == NONE or wtag(w, functions) != 5:
            return ABI
        put(w, 112, functions)
        if get(w, 72) == 0:
            answer = plan_choices(w)
            if answer != 0:
                return ERROR + answer
            if get(w, 96) < 3:
                put(w, 64, 99)
                return 99
            put(w, 64, 15)
            return 15
        put(w, 136, 0)
        put(w, 64, 6)
        return 6
    if command == 5:
        if stage != 15:
            return ABI
        put(w, 64, 99)
        return 99
    if command == 6:
        if stage != 6:
            return ABI
        if validate(s, w) == 0:
            return ABI
        at = get(w, 104)
        if length(s) > length(w) - at:
            return ABI
        copy_in(s, w, at)
        if get(w, 8) > 128 or find_function(w, at) == NONE:
            return ERROR + 17
        put(w, 136, get(w, 136) + 1)
        return 6
    if command == 7:
        if stage != 6:
            return ABI
        put(w, 64, 8)
        return 8
    if command == 8:
        if stage != 8 or get(w, 8) > 1:
            return ABI
        put(w, 128, get(w, 8))
        put(w, 152, 0)
        put(o, 0, choose(get(w, 8) != 0, 7, 5))
        put(w, 64, 9)
        return 9
    if command == 9:
        if stage != 9:
            return ABI
        if get(w, 8) != 6:
            return ERROR + 18
        put(w, 64, 10)
        return 10
    if command == 10:
        if stage != 10:
            return ABI
        if validate(s, w) == 0 or tag(s, 0) != 5 or total(s, 0) != 2:
            return ABI
        at = get(w, 104)
        if length(s) > length(w) - at:
            return ABI
        copy_in(s, w, at)
        value = welement(w, at, 0)
        reg = welement(w, at, 1)
        register = register_id(w, reg)
        if wtag(w, value) != 4 or register == 0 or get(w, 16) > 3:
            return ERROR + 18
        if register > 5 and get(w, 128) == 0:
            return ERROR + 18
        return 10
    if command == 11:
        if stage != 10:
            return ABI
        put(w, 64, 16)
        return 16
    if command == 16:
        if stage != 16 or validate(s, w) == 0:
            return ABI
        at = get(w, 104)
        if length(s) > length(w) - at:
            return ABI
        copy_in(s, w, at)
        fn = find_function(w, at)
        if fn == NONE:
            return ABI
        put(w, 120, fn)
        put(w, 224, 0)
        put(w, 232, 0)
        put(w, 240, 1)
        put(w, 288, 0)
        if prepare_rows(w, fn) == 0:
            return ABI
        put(w, 352, 6)
        put(o, 0, 6)
        put(w, 64, 17)
        return 17
    if command == 17:
        if stage != 17 or get(w, 8) > 1:
            return ABI
        index = get(w, 352)
        if get(w, 8) != 0:
            put(w, 288, get(w, 288) | (1 << (index - 1)))
        if index == 6:
            put(w, 352, 7)
            put(o, 0, 7)
            return 17
        if get(w, 288) != 0:
            if get(w, 240) == 0:
                return ERROR + 19
            if leaf_signature(w, get(w, 120)) == 0:
                return ERROR + 20
        put(w, 64, 18)
        return 18
    if command == 18:
        if stage != 18 or validate(s, w) == 0:
            return ABI
        at = get(w, 304)
        if length(s) > length(w) - at:
            return ABI
        copy_in(s, w, at)
        if wtag(w, at) != 4:
            put(w, 64, 118)
            return 118
        row = lookup(w, at)
        if get(w, 8) > 128 or row == NONE:
            return ERROR + 21
        if scalar_type(w, get(w, row + 8)) == 0:
            return ERROR + 21
        return 18
    if command == 118:
        if stage != 118 or get(w, 8) > 1:
            return ABI
        if get(w, 8) == 0:
            return ERROR + 21
        put(w, 64, 119)
        return 119
    if command == 119:
        if stage != 119 or validate(s, w) == 0:
            return ABI
        at = get(w, 304)
        if length(s) > length(w) - at:
            return ABI
        copy_in(s, w, at)
        if scalar_type(w, at) == 0:
            return ERROR + 21
        put(w, 64, 18)
        return 18
    if command == 20:
        if stage != 18:
            return ABI
        sort_rows(w, 0)
        put(w, 328, get(w, 264))
        put(w, 256, 0)
        put(w, 344, 0)
        return next_row(w, o)
    if command == 25:
        if stage != 25 or get(w, 8) > 1:
            return ABI
        if get(w, 8) == 0:
            put(w, 256, get(w, 256) + 1)
            return next_row(w, o)
        put(w, 64, 26)
        return 26
    if command == 26:
        if stage != 26 or get(w, 8) == 0 or get(w, 8) > get(w, 168):
            return ABI
        row = get(w, get(w, 328) + get(w, 256) * 8)
        put(w, row + 56, get(w, 8))
        put(w, 64, 27)
        return 27
    if command == 27:
        if stage != 27 or get(w, 8) == 0 or get(w, 8) > choose(get(w, 128) != 0, 7, 5):
            return ABI
        row = get(w, get(w, 328) + get(w, 256) * 8)
        put(w, row + 48, get(w, 8))
        put(w, 256, get(w, 256) + 1)
        return next_row(w, o)
    if command == 28:
        if stage != 28 or get(w, 8) > 1:
            return ABI
        index = get(w, 352)
        if get(w, 8) != 0:
            put(w, 224, get(w, 224) | (1 << (index - 1)))
        if index < 5:
            put(w, 352, index + 1)
            put(o, 0, index + 1)
            return 28
        collect_selected(w)
        sort_rows(w, 0)
        put(o, 0, field(w, get(w, 120), 13))
        put(o, 8, get(w, 224))
        put(o, 16, get(w, 288))
        put(o, 24, choose(get(w, 288) != 0, get(w, 232), 0))
        put(o, 32, get(w, 208))
        put(w, 256, 0)
        put(w, 64, 13)
        return 13
    if command == 13:
        if stage != 13:
            return ABI
        index = get(w, 256)
        if index == get(w, 208):
            put(w, 64, 30)
            return 30
        row = get(w, get(w, 264) + index * 8)
        put(o, 0, get(w, row + 16))
        put(o, 8, get(w, row))
        put(o, 16, get(w, row + 8))
        put(o, 24, get(w, row + 56))
        put(o, 32, get(w, row + 32))
        put(o, 40, get(w, row + 40))
        put(w, 256, index + 1)
        return 14
    if command == 30:
        if stage != 30:
            return ABI
        put(w, 64, 12)
        return 12
    if command == 12:
        if stage != 12 or get(w, 8) > 1:
            return ABI
        if get(w, 8) != 0:
            put(w, 64, 31)
            return 31
        put(w, 64, 9)
        return 9
    if command == 31:
        if stage != 31:
            return ABI
        put(w, 64, 9)
        return 9
    if command == 14:
        if stage != 9:
            return ABI
        put(w, 64, 99)
        return 99
    return ABI

def next_row(w:mutbuf, o:mutbuf) -> u64:
    index = get(w, 256)
    start = get(w, 344)
    count = get(w, 168)
    ordered = get(w, 328)
    boundary = index == count
    if index > start and index < count:
        before = get(w, ordered + (index - 1) * 8)
        after = get(w, ordered + index * 8)
        boundary = get(w, before + 24) != get(w, after + 24)
    if boundary and index > start:
        first = get(w, 192)
        second = get(w, 200)
        left = get(w, 312)
        right = get(w, 320)
        i = start
        chosen = 0
        while i < index:
            row = get(w, ordered + i * 8)
            if get(w, row + 48) != 0:
                put(w, left + chosen * 8, row)
                chosen = chosen + 1
            i = i + 1
        put(w, 192, left)
        put(w, 200, right)
        put(w, 264, left)
        put(w, 208, chosen)
        sort_rows(w, 1)
        if conflicts(w, o) != 0:
            return ERROR + 22
        put(w, 192, first)
        put(w, 200, second)
        put(w, 264, ordered)
        put(w, 208, count)
        put(w, 344, index)
    if index == count:
        put(w, 352, 1)
        put(w, 224, 0)
        put(o, 0, 1)
        put(w, 64, 28)
        return 28
    row = get(w, ordered + index * 8)
    put(o, 0, get(w, row))
    put(w, 64, 25)
    return 25

def plan_fields(w:mutbuf, plan:u64, version:u64) -> u64:
    expected = 7
    if version >= 2:
        expected = 127
    if version >= 3:
        expected = 255
    mask = 0
    node = plan + 24
    index = 0
    while index < wtotal(w, plan):
        key = key_id(w, node)
        if key == 0 or key > 8:
            return 0
        mask = mask | (1 << (key - 1))
        node = wend(w, wend(w, node))
        index = index + 1
    return choose(mask == expected and wtotal(w, plan) == choose(version == 1, 3, choose(version == 2, 7, 8)), 1, 0)

def plan_choices(w:mutbuf) -> u64:
    plan = get(w, 80)
    version = get(w, 96)
    orders = field(w, plan, 3)
    if wtag(w, orders) != 6:
        return 6
    if version == 1 and wtotal(w, orders) == 0:
        return 6
    item = orders + 24
    index = 0
    while index < wtotal(w, orders):
        fn = find_function(w, item)
        if fn == NONE:
            return 7
        if permutation(w, wend(w, item), field(w, fn, 14), 15) == 0:
            return 8
        item = wend(w, wend(w, item))
        index = index + 1
    if version == 1:
        return 0
    if permutation(w, field(w, plan, 4), get(w, 112), 13) == 0:
        return 9
    scratch = field(w, plan, 5)
    if wtag(w, scratch) != 6 or wtotal(w, scratch) != 2:
        return 10
    a = scratch + 24
    av = wend(w, a)
    b = wend(w, av)
    bv = wend(w, b)
    ak = scratch_id(w, a)
    bk = scratch_id(w, b)
    ai = scratch_id(w, av)
    bi = scratch_id(w, bv)
    if ak == 0 or bk == 0 or ak == bk or ai == 0 or bi == 0 or ai == bi:
        return 10
    choices = field(w, plan, 6)
    if wtag(w, choices) != 6 or wtotal(w, choices) != choose(version >= 3, 3, 2):
        return 11
    mask = 0
    item = choices + 24
    index = 0
    while index < wtotal(w, choices):
        key = key_id(w, item)
        if key < 9 or key > choose(version >= 3, 11, 10):
            return 11
        mask = mask | (1 << (key - 9))
        item = wend(w, wend(w, item))
        index = index + 1
    if mask != choose(version >= 3, 7, 3):
        return 11
    if move_id(w, field(w, choices, 9)) == 0:
        return 12
    if alu_id(w, field(w, choices, 10)) == 0:
        return 13
    alignment = field(w, plan, 7)
    if wtag(w, alignment) != 2 or alignment_id(w, alignment) == 0:
        return 14
    if version >= 3 and select_id(w, field(w, choices, 11)) == 0:
        return 15
    return 0

def permutation(w:mutbuf, order:u64, members:u64, name_key:u64) -> u64:
    if wtag(w, order) != 5 or wtotal(w, order) != wtotal(w, members):
        return 0
    count = wtotal(w, order)
    base = get(w, 104)
    if count > 4096 or count * 24 > length(w) - base:
        return 0
    left = base
    right = left + count * 8
    temporary = right + count * 8
    item = order + 24
    member = members + 24
    i = 0
    while i < count:
        if wtag(w, item) != 4:
            return 0
        put(w, left + i * 8, field(w, member, name_key))
        put(w, right + i * 8, item)
        member = wend(w, member)
        item = wend(w, item)
        i = i + 1
    ordered_left = sort_texts(w, left, temporary, count)
    free = choose(ordered_left == left, temporary, left)
    ordered_right = sort_texts(w, right, free, count)
    i = 0
    while i < count:
        if same(w, get(w, ordered_left + i * 8), get(w, ordered_right + i * 8)) == 0:
            return 0
        i = i + 1
    return 1

def sort_texts(w:mutbuf, source:u64, target:u64, count:u64) -> u64:
    width = 1
    while width < count:
        start = 0
        while start < count:
            middle = choose(start + width < count, start + width, count)
            finish = choose(start + 2 * width < count, start + 2 * width, count)
            left = start
            right = middle
            out = start
            while out < finish:
                take_left = right == finish
                if left < middle and right < finish:
                    take_left = text_before(w, get(w, source + left * 8), get(w, source + right * 8)) != 0
                if left == middle:
                    take_left = False
                if take_left:
                    put(w, target + out * 8, get(w, source + left * 8))
                    left = left + 1
                else:
                    put(w, target + out * 8, get(w, source + right * 8))
                    right = right + 1
                out = out + 1
            start = finish
        old = source
        source = target
        target = old
        width = width * 2
    return source

def find_function(w:mutbuf, name:u64) -> u64:
    if wtag(w, name) != 4:
        return NONE
    functions = get(w, 112)
    item = functions + 24
    i = 0
    while i < wtotal(w, functions):
        if same(w, name, field(w, item, 13)) != 0:
            return item
        item = wend(w, item)
        i = i + 1
    return NONE

def prepare_rows(w:mutbuf, fn:u64) -> u64:
    blocks = field(w, fn, 14)
    block = blocks + 24
    b = 0
    count = 0
    while b < wtotal(w, blocks):
        count = count + wtotal(w, field(w, block, 16))
        ops = field(w, block, 18)
        op = ops + 24
        i = 0
        while i < wtotal(w, ops):
            count = count + wtotal(w, field(w, op, 19))
            op = wend(w, op)
            i = i + 1
        block = wend(w, block)
        b = b + 1
    rows = get(w, 104)
    first = rows + count * 64
    second = first + count * 8
    third = second + count * 8
    fourth = third + count * 8
    input = fourth + count * 8
    if input > length(w) or length(w) - input < 2048:
        return 0
    put(w, 160, rows)
    put(w, 168, count)
    put(w, 184, count)
    put(w, 192, first)
    put(w, 200, second)
    put(w, 312, third)
    put(w, 320, fourth)
    put(w, 304, input)
    block = blocks + 24
    b = 0
    next_row = rows
    while b < wtotal(w, blocks):
        next_row = add_definitions(w, field(w, block, 16), next_row, field(w, block, 15), b, 0)
        ops = field(w, block, 18)
        op = ops + 24
        position = 1
        while position <= wtotal(w, ops):
            next_row = add_definitions(w, field(w, op, 19), next_row, field(w, block, 15), b, position)
            op = wend(w, op)
            position = position + 1
        block = wend(w, block)
        b = b + 1
    i = 0
    while i < count:
        put(w, first + i * 8, rows + i * 64)
        i = i + 1
    put(w, 208, count)
    put(w, 264, first)
    sort_rows(w, 2)
    put(w, 176, get(w, 264))
    block = blocks + 24
    b = 0
    while b < wtotal(w, blocks):
        ops = field(w, block, 18)
        op = ops + 24
        position = 1
        while position <= wtotal(w, ops):
            operation = leaf_op_id(w, field(w, op, 23))
            if operation == 0:
                put(w, 240, 0)
            else:
                put(w, 232, get(w, 232) | (1 << (operation - 1)))
            use_list(w, field(w, op, 21), position)
            op = wend(w, op)
            position = position + 1
        term = field(w, block, 22)
        operation = term_id(w, field(w, term, 23))
        if operation == 1:
            use_list(w, field(w, term, 24), position)
        if operation == 2:
            use_list(w, field(w, term, 21), position)
        if operation == 3:
            use_value(w, field(w, term, 25), position)
            use_list(w, field(w, field(w, term, 26), 21), position)
            use_list(w, field(w, field(w, term, 27), 21), position)
        block = wend(w, block)
        b = b + 1
    return 1

def add_definitions(w:mutbuf, values:u64, row:u64, block:u64, index:u64, position:u64) -> u64:
    item = values + 24
    i = 0
    while i < wtotal(w, values):
        name = field(w, item, 13)
        put(w, row, name)
        put(w, row + 8, field(w, item, 20))
        put(w, row + 16, block)
        put(w, row + 24, index)
        put(w, row + 32, position)
        put(w, row + 40, position)
        put(w, row + 48, 0)
        put(w, row + 56, 0)
        row = row + 64
        item = wend(w, item)
        i = i + 1
    return row

def lookup(w:mutbuf, name:u64) -> u64:
    low = 0
    high = get(w, 184)
    index = get(w, 176)
    while low < high:
        middle = low + ((high - low) >> 1)
        row = get(w, index + middle * 8)
        key = get(w, row)
        if same(w, name, key) != 0:
            return row
        if text_before(w, key, name) != 0:
            low = middle + 1
        else:
            high = middle
    return NONE

def use_value(w:mutbuf, name:u64, position:u64) -> u64:
    row = lookup(w, name)
    if row != NONE:
        put(w, row + 40, position)
    return 0

def use_list(w:mutbuf, values:u64, position:u64) -> u64:
    item = values + 24
    i = 0
    while i < wtotal(w, values):
        use_value(w, item, position)
        item = wend(w, item)
        i = i + 1
    return 0

def leaf_signature(w:mutbuf, fn:u64) -> u64:
    params = field(w, fn, 16)
    item = params + 24
    i = 0
    while i < wtotal(w, params):
        typ = field(w, item, 20)
        if scalar_type(w, typ) == 0 and borrowed_type(w, typ) == 0:
            return 0
        item = wend(w, item)
        i = i + 1
    returns = field(w, fn, 17)
    item = returns + 24
    i = 0
    while i < wtotal(w, returns):
        if scalar_type(w, item) == 0:
            return 0
        item = wend(w, item)
        i = i + 1
    return 1

def collect_selected(w:mutbuf) -> u64:
    i = 0
    count = 0
    while i < get(w, 168):
        row = get(w, 160) + i * 64
        if get(w, row + 48) != 0:
            put(w, get(w, 192) + count * 8, row)
            count = count + 1
        i = i + 1
    put(w, 208, count)
    put(w, 264, get(w, 192))
    return 0

def before(w:mutbuf, left:u64, right:u64, mode:u64) -> u64:
    if mode == 2:
        return text_before(w, get(w, left), get(w, right))
    lb = get(w, left + 24)
    rb = get(w, right + 24)
    if lb != rb:
        return choose(lb < rb, 1, 0)
    if mode == 1:
        lr = get(w, left + 48)
        rr = get(w, right + 48)
        if lr != rr:
            return choose(lr < rr, 1, 0)
        lf = get(w, left + 32)
        rf = get(w, right + 32)
        if lf != rf:
            return choose(lf < rf, 1, 0)
    return text_before(w, get(w, left), get(w, right))

def sort_rows(w:mutbuf, mode:u64) -> u64:
    count = get(w, 208)
    source = get(w, 264)
    target = choose(source == get(w, 192), get(w, 200), get(w, 192))
    width = 1
    while width < count:
        start = 0
        while start < count:
            middle = choose(start + width < count, start + width, count)
            finish = choose(start + 2 * width < count, start + 2 * width, count)
            left = start
            right = middle
            out = start
            while out < finish:
                take_left = right == finish
                if left < middle and right < finish:
                    take_left = before(w, get(w, source + left * 8), get(w, source + right * 8), mode) != 0
                if left == middle:
                    take_left = False
                if take_left:
                    put(w, target + out * 8, get(w, source + left * 8))
                    left = left + 1
                else:
                    put(w, target + out * 8, get(w, source + right * 8))
                    right = right + 1
                out = out + 1
            start = finish
        old = source
        source = target
        target = old
        width = width * 2
    put(w, 264, source)
    return 0

def conflicts(w:mutbuf, o:mutbuf) -> u64:
    i = 1
    while i < get(w, 208):
        left = get(w, get(w, 264) + (i - 1) * 8)
        right = get(w, get(w, 264) + i * 8)
        if get(w, left + 24) == get(w, right + 24) and get(w, left + 48) == get(w, right + 48):
            if get(w, left + 40) >= get(w, right + 32):
                put(o, 0, field(w, get(w, 120), 13))
                put(o, 8, get(w, left + 16))
                put(o, 16, get(w, left))
                put(o, 24, get(w, right))
                put(o, 32, get(w, left + 48))
                return 1
        i = i + 1
    return 0

def align8(value:u64) -> u64:
    return (value + 7) & 18446744073709551608

def copy_in(s:readbuf, w:mutbuf, at:u64) -> u64:
    i = 0
    while i < length(s):
        store(w, at + i, byte(s, i))
        i = i + 1
    return 0

def wtag(w:mutbuf, node:u64) -> u64:
    if node == NONE:
        return 7
    return get(w, node)

def wsize(w:mutbuf, node:u64) -> u64:
    return get(w, node + 8)

def wend(w:mutbuf, node:u64) -> u64:
    return node + 16 + wsize(w, node)

def wtotal(w:mutbuf, node:u64) -> u64:
    return get(w, node + 16)

def welement(w:mutbuf, node:u64, index:u64) -> u64:
    item = node + 24
    while index != 0:
        item = wend(w, item)
        index = index - 1
    return item

def field(w:mutbuf, node:u64, key:u64) -> u64:
    if wtag(w, node) != 6:
        return NONE
    i = 0
    item = node + 24
    while i < wtotal(w, node):
        value = wend(w, item)
        if key_id(w, item) == key:
            return value
        item = wend(w, value)
        i = i + 1
    return NONE

def same(w:mutbuf, left:u64, right:u64) -> u64:
    if wtag(w, left) != 4 or wtag(w, right) != 4:
        return 0
    if wsize(w, left) != wsize(w, right):
        return 0
    i = 0
    while i < wsize(w, left):
        if byte(w, left + 16 + i) != byte(w, right + 16 + i):
            return 0
        i = i + 1
    return 1

def text_before(w:mutbuf, left:u64, right:u64) -> u64:
    n = choose(wsize(w, left) < wsize(w, right), wsize(w, left), wsize(w, right))
    i = 0
    while i < n:
        a = byte(w, left + 16 + i)
        b = byte(w, right + 16 + i)
        if a != b:
            return choose(a < b, 1, 0)
        i = i + 1
    return choose(wsize(w, left) <= wsize(w, right), 1, 0)

def literal(w:mutbuf, node:u64, kind:u64, n:u64, a:u64, b:u64, c:u64, d:u64, e:u64, f:u64) -> u64:
    if wtag(w, node) != kind or wsize(w, node) != n:
        return 0
    i = 0
    while i < n:
        value = a
        if i >= 8:
            value = b
        if i >= 16:
            value = c
        if i >= 24:
            value = d
        if i >= 32:
            value = e
        if i >= 40:
            value = f
        if byte(w, node + 16 + i) != ((value >> ((i & 7) * 8)) & 255):
            return 0
        i = i + 1
    return 1
'''


def packed(text):
    raw = text.encode('ascii')
    assert len(raw) <= 48
    return ', '.join(map(str, [len(raw), *[int.from_bytes(raw[i:i+8], 'little') for i in range(0, 48, 8)]]))


def source_program():
    source = SOURCE
    helpers = {'validate', 'word', 'put', 'get', 'tag', 'size_of', 'end', 'total', 'element'}
    nodes = [n for n in ast.parse(TYPED_SOURCE).body if isinstance(n, ast.FunctionDef) and n.name in helpers]
    # The typed protocol's stack must not overlap this session's native state.
    for n in nodes:
        if n.name == 'validate':
            # Keep maximum nesting at 128; only relocate the frame base.
            text = ast.unparse(n).replace('put(w, 128,', 'put(w, 4096,').replace('put(w, 136,', 'put(w, 4104,').replace('128 + depth * 24', '4096 + depth * 24')
            source += '\n' + text + '\n'
        else:
            source += '\n' + ast.unparse(n) + '\n'
    for name, words, kind in (
            ('key_id', KEYS, 4), ('schema_id', SCHEMAS, 4),
            ('register_id', REGISTERS, 4), ('scalar_type', SCALAR_TYPES, 4),
            ('borrowed_type', ('readbuf', 'mutbuf'), 4), ('leaf_op_id', LEAF_OPS, 4),
            ('term_id', ('ret', 'jump', 'branch'), 4), ('scratch_id', ('r10', 'r11'), 4),
            ('move_id', ('movabs', 'mov32_if_exact'), 4), ('alu_id', ('imm32', 'imm8_if_exact'), 4),
            ('select_id', ('branch', 'cmov_scalar'), 4), ('alignment_id', ('1', '16', '32', '64'), 2)):
        source += '\ndef ' + name + '(w:mutbuf, node:u64) -> u64:\n'
        for i, word in enumerate(words, 1):
            source += '    if literal(w, node, ' + str(kind) + ', ' + packed(word) + ') != 0:\n        return ' + str(i) + '\n'
        source += '    return 0\n'
    constants = {'NONE': NONE, 'ABI': ABI, 'ERROR': ERROR}
    class Expand(ast.NodeTransformer):
        def visit_Name(self, node):
            return ast.copy_location(ast.Constant(constants[node.id]), node) if node.id in constants else node
    return ast.unparse(ast.fix_missing_locations(Expand().visit(ast.parse(source)))) + '\n'


def document():
    nodes = ast.parse(source_program()).body
    names = {n.name: 'f' + str(i) for i, n in enumerate(nodes)}
    signatures = {n.name: ([a.annotation.id for a in n.args.args], n.returns.id) for n in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        b = Builder(node, names, signatures, total)
        b.statements(node.body)
        functions.append({'name': names[node.name], 'params': [b.param(v) for v in b.params],
                          'returns': [b.returns], 'effects': ['read', 'write', 'trap'],
                          'entry': 'b0', 'blocks': b.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8', 'module': 'machine_plan', 'functions': functions})


if __name__ == '__main__':
    import sys
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap/machine_plan.hiaasm'
    path.write_text(render_assembly(document()))
    print(path.name, path.stat().st_size)
