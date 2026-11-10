"""Author whole primitive Core admission: declarations and complete bodies.

The full document is decoded once. Definitions and capability state are indexed
by bounded arena node identities, never by a reduced compiler arity/profile.
"""
import ast
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from hepta.hia_opcodes import OPCODES
from tools.generate_hia_core_json_frontend import KEYS,packed
from tools.generate_hia_program_shape import source_program as declaration_source
from tools.generate_hia_instruction_policy import rules,GROUPS
from tools.generate_hia_selfhost import Builder,compact_authoring_cfg,total_scalar_functions

ERRORS={'NONE':(1<<64)-1,'ABI':0xfffffffd,'FORMAT':0xfffffffb,'NAME':0xfffffffa,
        'TYPE':0xfffffff9,'LOAN':0xfffffff8,'EFFECT':0xfffffff7,'CFG':0xfffffff6,
        'SSA':0xfffffff5,'CALL':0xfffffff3,'OPCODE':0xfffffff0,'RESOURCE':0xffffffef,
        'RETURN_LOAN':0xffffffee}
TRANSITIONS=('none','allocate','empty_chain','chain_transfer','chain_borrow','borrow','end_loan','drop_owner','move_owner','call')

BODY=r'''
def core_admission(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    status = widen(program_shape(s, o, w))
    if status != 0:
        return status
    nodes = get(w, 8)
    state = get(o, 32) + 4096 * 40
    if length(o) < state + nodes * 120:
        return ABI
    put(o, 0, 0)
    put(o, 24, schema_version(w, field(w, 0, K_schema)))
    put(o, 40, state)
    put(o, 48, state + nodes * 112)
    put(o, 112, 1)
    i = 0
    while i < nodes:
        put(o, state + i * 112, 0)
        put(o, state + i * 112 + 8, 0)
        put(o, state + i * 112 + 80, 0)
        put(o, state + i * 112 + 96, 0)
        i = i + 1
    fn = child(w, field(w, 0, K_functions))
    index = 1
    while fn != NONE:
        put(o, 96, index << 32)
        function_body(s, w, o, fn)
        if get(o, 0) != 0:
            return get(o, 0)
        fn = next_node(w, fn)
        index = index + 1
    return 0

def rec(o:mutbuf, definition:u64) -> u64:
    return get(o, 40) + definition * 112

def definition(w:mutbuf, o:mutbuf, name:u64) -> u64:
    return symbol(w, o, name, 3, 0, 0)

def value(w:mutbuf, o:mutbuf, name:u64) -> u64:
    result = definition(w, o, name)
    if result == NONE:
        put(o, 0, SSA)
        return NONE
    if get(o, rec(o, result)) != get(o, 56):
        put(o, 0, SSA)
        return NONE
    if value_type(w, result) > 12 and get(o, rec(o, result) + 8) == 0:
        put(o, 0, RESOURCE)
        return NONE
    return result

def value_type(w:mutbuf, definition:u64) -> u64:
    return type_id(w, field(w, definition, K_type))

def active(o:mutbuf, definition:u64) -> u64:
    if definition == NONE:
        return 0
    return choose(get(o, rec(o, definition)) == get(o, 56) and get(o, rec(o, definition) + 8) != 0, 1, 0)

def cap(o:mutbuf, definition:u64, offset:u64) -> u64:
    return get(o, rec(o, definition) + offset)

def new_cap(o:mutbuf, definition:u64, root:u64, parent:u64, external:u64, origin:u64) -> u64:
    at = rec(o, definition)
    put(o, at, get(o, 56))
    put(o, at + 8, 1)
    put(o, at + 16, root)
    put(o, at + 24, parent)
    put(o, at + 32, external)
    put(o, at + 40, origin)
    return 0

def append_live(o:mutbuf, definition:u64) -> u64:
    put(o, get(o, 48) + get(o, 64) * 8, definition)
    put(o, 64, get(o, 64) + 1)
    return 0

def live_item(o:mutbuf, index:u64) -> u64:
    return get(o, get(o, 48) + index * 8)

def children(o:mutbuf, definition:u64) -> u64:
    i = 0
    while i < get(o, 64):
        other = live_item(o, i)
        if active(o, other) != 0 and cap(o, other, 24) == definition:
            return 1
        i = i + 1
    return 0

def owner_free(w:mutbuf, o:mutbuf, definition:u64) -> u64:
    typ = value_type(w, definition)
    if typ != 13 and typ != 14:
        put(o, 0, TYPE)
        return 0
    i = 0
    while i < get(o, 64):
        other = live_item(o, i)
        if active(o, other) != 0 and other != definition and cap(o, other, 16) == definition:
            put(o, 0, LOAN)
            return 0
        i = i + 1
    return 1

def access(w:mutbuf, o:mutbuf, definition:u64, mutable:u64) -> u64:
    typ = value_type(w, definition)
    if (mutable != 0 and typ != 16) or (mutable == 0 and typ != 15 and typ != 16):
        put(o, 0, TYPE)
        return 0
    if children(o, definition) != 0:
        put(o, 0, LOAN)
        return 0
    return 1

def borrow(w:mutbuf, o:mutbuf, source:u64, output:u64, mutable:u64, chain_head:u64) -> u64:
    typ = value_type(w, source)
    permission = typ == 14
    if chain_head == 0:
        permission = typ == 13 or typ == 16 or (mutable == 0 and typ == 15)
    if permission == False:
        put(o, 0, LOAN)
        return 0
    mark = get(o, 112)
    put(o, 112, mark + 1)
    put(o, rec(o, source) + 96, mark)
    parent = cap(o, source, 24)
    while parent != NONE:
        if active(o, parent) == 0:
            put(o, 0, LOAN)
            return 0
        if get(o, rec(o, parent) + 96) == mark:
            put(o, 0, LOAN)
            return 0
        put(o, rec(o, parent) + 96, mark)
        parent = cap(o, parent, 24)
    root = cap(o, source, 16)
    i = 0
    while i < get(o, 64):
        other = live_item(o, i)
        if active(o, other) != 0 and cap(o, other, 16) == root and get(o, rec(o, other) + 96) != mark:
            if mutable != 0 or value_type(w, other) == 16:
                put(o, 0, LOAN)
                return 0
        i = i + 1
    new_cap(o, output, root, source, 0, cap(o, source, 40))
    return 1

def item(w:mutbuf, array:u64, index:u64) -> u64:
    node = child(w, array)
    while index != 0 and node != NONE:
        node = next_node(w, node)
        index = index - 1
    return node

def output_id(w:mutbuf, o:mutbuf, ins:u64, index:u64) -> u64:
    return definition(w, o, field(w, item(w, field(w, ins, K_out), index), K_name))

def argument(w:mutbuf, o:mutbuf, ins:u64, index:u64) -> u64:
    return definition(w, o, item(w, field(w, ins, K_args), index))

def local_types(s:readbuf, w:mutbuf, o:mutbuf, ins:u64, a:u64, r:u64, policy:u64) -> u64:
    attrs = field(w, ins, K_attrs)
    attr = (r >> 40) & 255
    if count(w, attrs) != choose(attr == 0, 0, 1):
        put(o, 0, FORMAT)
        return 0
    attrval = child(w, attrs)
    if attr != 0:
        if attribute_name(w, attrval) != attr:
            put(o, 0, FORMAT)
            return 0
    args = field(w, ins, K_args)
    out = field(w, ins, K_out)
    ac = a >> 56
    rc = (r >> 32) & 255
    if ac != 255:
        if count(w, args) != ac:
            put(o, 0, TYPE)
            return 0
        i = 0
        while i < ac:
            typ = value_type(w, argument(w, o, ins, i))
            if rule_match(w, o, ins, typ, (a >> (i * 8)) & 255) == 0:
                put(o, 0, choose((a & 281474976710656) != 0, LOAN, TYPE))
                return 0
            i = i + 1
    if rc != 255:
        if count(w, out) != rc:
            put(o, 0, TYPE)
            return 0
        i = 0
        while i < rc:
            typ = value_type(w, output_id(w, o, ins, i))
            if rule_match(w, o, ins, typ, (r >> (i * 8)) & 255) == 0:
                put(o, 0, TYPE)
                return 0
            i = i + 1
    special = r >> 56
    effects = (r >> 48) & 255
    if special == 1:
        if literal(s, w, attrval, value_type(w, output_id(w, o, ins, 0))) == 0:
            put(o, 0, TYPE)
            return 0
    if special == 2:
        mode = cast_mode(w, attrval)
        if mode == 0:
            put(o, 0, TYPE)
            return 0
        if mode == 1:
            effects = effects | 8
    put(o, 72, get(o, 72) | effects)
    guards(w, o, ins, policy >> 16)
    if get(o, 0) != 0:
        return 0
    transition(w, o, ins, policy & 255, (policy >> 8) & 1)
    return 0

def rule_match(w:mutbuf, o:mutbuf, ins:u64, typ:u64, rule:u64) -> u64:
    if rule >= 32:
        return choose(typ == value_type(w, argument(w, o, ins, rule - 32)), 1, 0)
    if rule >= 17:
        return type_group(typ, rule)
    return choose(typ == rule, 1, 0)

def literal(s:readbuf, w:mutbuf, node:u64, typ:u64) -> u64:
    if typ == 11:
        return choose(kind(w, node) == 1 or kind(w, node) == 2, 1, 0)
    if typ == 12:
        return choose(kind(w, node) == 0, 1, 0)
    if kind(w, node) != 3 or typ == 0 or typ > 10:
        return 0
    at = get(w, 64 + node * 56 + 24)
    stop = at + count(w, node)
    negative = byte(s, at) == 45
    if negative:
        at = at + 1
    tenth = literal_bound(typ, negative, 0)
    final_digit = literal_bound(typ, negative, 1)
    value = 0
    while at < stop:
        digit = byte(s, at) - 48
        if digit > 9 or value > tenth or (value == tenth and digit > final_digit):
            return 0
        value = value * 10 + digit
        at = at + 1
    if negative and typ > 4 and typ != 9 and value != 0:
        return 0
    return 1

def guards(w:mutbuf, o:mutbuf, ins:u64, rules:u64) -> u64:
    while rules != 0:
        code = rules & 255
        name = argument(w, o, ins, (code >> 4) & 3)
        kind = code & 15
        if kind == 1:
            owner_free(w, o, name)
        if kind == 2:
            if cap(o, name, 32) != 0 or children(o, name) != 0:
                put(o, 0, LOAN)
        if kind == 3 or kind == 4:
            access(w, o, name, choose(kind == 4, 1, 0))
        if kind == 5:
            other = argument(w, o, ins, (code >> 6) & 3)
            if cap(o, name, 16) == cap(o, other, 16):
                put(o, 0, LOAN)
        if get(o, 0) != 0:
            return 0
        rules = rules >> 8
    return 0

def transition(w:mutbuf, o:mutbuf, ins:u64, action:u64, mutable:u64) -> u64:
    if action == 1 or action == 2:
        result = output_id(w, o, ins, 0)
        new_cap(o, result, result, NONE, 0, NONE)
    if action == 3:
        arg = child(w, field(w, ins, K_args))
        while arg != NONE:
            put(o, rec(o, definition(w, o, arg)) + 8, 0)
            arg = next_node(w, arg)
        out = child(w, field(w, ins, K_out))
        while out != NONE:
            if type_id(w, field(w, out, K_type)) == 13 or type_id(w, field(w, out, K_type)) == 14:
                result = definition(w, o, field(w, out, K_name))
                new_cap(o, result, result, NONE, 0, NONE)
            out = next_node(w, out)
    if action == 4 or action == 5:
        borrow(w, o, argument(w, o, ins, 0), output_id(w, o, ins, 0), mutable, choose(action == 4, 1, 0))
    if action == 6 or action == 7 or action == 8:
        put(o, rec(o, argument(w, o, ins, 0)) + 8, 0)
        if action == 8:
            result = output_id(w, o, ins, 0)
            new_cap(o, result, result, NONE, 0, NONE)
    if action == 9:
        call_instruction(w, o, ins)
    return 0

def callee(w:mutbuf, o:mutbuf, name:u64) -> u64:
    if identifier(w, name) == 0:
        put(o, 0, NAME)
        return NONE
    context = get(o, 96)
    put(o, 96, 0)
    result = symbol(w, o, name, 1, 0, 0)
    put(o, 96, context)
    if result == NONE:
        put(o, 0, CALL)
    return result

def call_instruction(w:mutbuf, o:mutbuf, ins:u64) -> u64:
    fn = callee(w, o, child(w, field(w, ins, K_attrs)))
    if get(o, 0) != 0:
        return 0
    args = field(w, ins, K_args)
    params = field(w, fn, K_params)
    if count(w, args) != count(w, params):
        put(o, 0, CALL)
        return 0
    i = 0
    while i < count(w, args):
        actual = argument(w, o, ins, i)
        typ = value_type(w, actual)
        formal = type_id(w, field(w, item(w, params, i), K_type))
        if typ != formal and (formal != 15 or typ != 16):
            put(o, 0, CALL)
            return 0
        if typ == 13 or typ == 14:
            owner_free(w, o, actual)
        if typ == 15 or typ == 16:
            access(w, o, actual, choose(formal == 16, 1, 0))
        if get(o, 0) != 0:
            return 0
        j = 0
        while j < i:
            previous = argument(w, o, ins, j)
            previous_type = value_type(w, previous)
            if (typ == 13 or typ == 14) and previous == actual:
                put(o, 0, RESOURCE)
                return 0
            if (typ == 15 or typ == 16) and (previous_type == 15 or previous_type == 16):
                previous_formal = type_id(w, field(w, item(w, params, j), K_type))
                if cap(o, previous, 16) == cap(o, actual, 16) and (previous_formal == 16 or formal == 16):
                    put(o, 0, LOAN)
                    return 0
            j = j + 1
        i = i + 1
    out = field(w, ins, K_out)
    returns = field(w, fn, K_returns)
    if count(w, out) != count(w, returns):
        put(o, 0, TYPE)
        return 0
    i = 0
    while i < count(w, returns):
        if value_type(w, output_id(w, o, ins, i)) != type_id(w, item(w, returns, i)):
            put(o, 0, TYPE)
            return 0
        i = i + 1
    effects = child(w, field(w, fn, K_effects))
    while effects != NONE:
        put(o, 72, get(o, 72) | effect_id(w, effects))
        effects = next_node(w, effects)
    i = 0
    while i < count(w, args):
        actual = argument(w, o, ins, i)
        if value_type(w, actual) == 13 or value_type(w, actual) == 14:
            put(o, rec(o, actual) + 8, 0)
        i = i + 1
    i = 0
    while i < count(w, out):
        actual = output_id(w, o, ins, i)
        typ = value_type(w, actual)
        if typ == 13 or typ == 14:
            new_cap(o, actual, actual, NONE, 0, NONE)
        if typ == 15 or typ == 16:
            origin = item(w, field(w, fn, K_return_loans), i)
            j = 0
            while same_text(w, origin, field(w, item(w, params, j), K_name)) == 0:
                j = j + 1
            borrow(w, o, argument(w, o, ins, j), actual, choose(typ == 16, 1, 0), 0)
            if get(o, 0) != 0:
                return 0
        i = i + 1
    return 0

def check_block(s:readbuf, w:mutbuf, o:mutbuf, block:u64) -> u64:
    put(o, 56, block + 1)
    put(o, 64, 0)
    put(o, 72, 0)
    parameter = child(w, field(w, block, K_params))
    while parameter != NONE:
        name = definition(w, o, field(w, parameter, K_name))
        put(o, rec(o, name), get(o, 56))
        if value_type(w, name) > 12:
            at = rec(o, name)
            new_cap(o, name, get(o, at + 48), get(o, at + 56), get(o, at + 64), get(o, at + 72))
            append_live(o, name)
        parameter = next_node(w, parameter)
    ins = child(w, field(w, block, K_ops))
    while ins != NONE:
        arg = child(w, field(w, ins, K_args))
        while arg != NONE:
            value(w, o, arg)
            if get(o, 0) != 0:
                return 0
            arg = next_node(w, arg)
        instruction(s, w, o, ins)
        if get(o, 0) != 0:
            return 0
        out = child(w, field(w, ins, K_out))
        while out != NONE:
            name = definition(w, o, field(w, out, K_name))
            put(o, rec(o, name), get(o, 56))
            if value_type(w, name) > 12:
                append_live(o, name)
            out = next_node(w, out)
        ins = next_node(w, ins)
    finish(w, o, field(w, block, K_term))
    return 0

def finish(w:mutbuf, o:mutbuf, term:u64) -> u64:
    op = field(w, term, K_op)
    if text_is(w, op, L_branch) != 0:
        cond = value(w, o, field(w, term, K_cond))
        if get(o, 0) != 0:
            return 0
        if value_type(w, cond) != 11:
            put(o, 0, CFG)
            return 0
    if text_is(w, op, L_ret) != 0:
        finish_return(w, o, term)
        if get(o, 0) != 0:
            return 0
    if text_is(w, op, L_trap) != 0:
        put(o, 72, get(o, 72) | 8)
    mask = 0
    effect = child(w, field(w, get(o, 80), K_effects))
    while effect != NONE:
        mask = mask | effect_id(w, effect)
        effect = next_node(w, effect)
    if (get(o, 72) | mask) != mask:
        put(o, 0, EFFECT)
    return 0

def finish_return(w:mutbuf, o:mutbuf, term:u64) -> u64:
    values = field(w, term, K_values)
    actual = child(w, values)
    while actual != NONE:
        value(w, o, actual)
        if get(o, 0) != 0:
            return 0
        actual = next_node(w, actual)
    fn = get(o, 80)
    returns = field(w, fn, K_returns)
    if count(w, values) != count(w, returns):
        put(o, 0, TYPE)
        return 0
    i = 0
    while i < count(w, values):
        if value_type(w, definition(w, o, item(w, values, i))) != type_id(w, item(w, returns, i)):
            put(o, 0, TYPE)
            return 0
        i = i + 1
    mark = get(o, 112)
    put(o, 112, mark + 1)
    i = 0
    while i < count(w, values):
        name = definition(w, o, item(w, values, i))
        if value_type(w, name) >= 15:
            if get(o, rec(o, name) + 96) == mark:
                put(o, 0, LOAN)
                return 0
            put(o, rec(o, name) + 96, mark)
        i = i + 1
    i = 0
    while i < count(w, values):
        name = definition(w, o, item(w, values, i))
        if value_type(w, name) >= 15:
            origin = item(w, field(w, fn, K_return_loans), i)
            parent = cap(o, name, 24)
            direct = cap(o, name, 32) != 0
            if active(o, parent) != 0:
                direct = direct or cap(o, parent, 32) != 0
            stored_origin = cap(o, name, 40)
            if stored_origin == NONE or origin == NONE:
                put(o, 0, RETURN_LOAN)
                return 0
            if same_text(w, stored_origin, origin) == 0 or children(o, name) != 0 or direct == False:
                put(o, 0, RETURN_LOAN)
                return 0
        i = i + 1
    i = 0
    while i < count(w, values):
        name = definition(w, o, item(w, values, i))
        if value_type(w, name) >= 15:
            put(o, rec(o, name) + 8, 0)
        i = i + 1
    mark = get(o, 112)
    put(o, 112, mark + 1)
    i = 0
    while i < count(w, values):
        name = definition(w, o, item(w, values, i))
        typ = value_type(w, name)
        if typ == 13 or typ == 14:
            if get(o, rec(o, name) + 96) == mark:
                put(o, 0, RESOURCE)
                return 0
            put(o, rec(o, name) + 96, mark)
        i = i + 1
    i = 0
    while i < count(w, values):
        name = definition(w, o, item(w, values, i))
        typ = value_type(w, name)
        if typ == 13 or typ == 14:
            if owner_free(w, o, name) == 0:
                return 0
            put(o, rec(o, name) + 8, 0)
        i = i + 1
    i = 0
    while i < get(o, 64):
        name = live_item(o, i)
        if active(o, name) != 0 and cap(o, name, 32) == 0:
            put(o, 0, RESOURCE)
            return 0
        i = i + 1
    return 0

def function_body(s:readbuf, w:mutbuf, o:mutbuf, fn:u64) -> u64:
    put(o, 80, fn)
    blocks = field(w, fn, K_blocks)
    base = get(o, 32)
    block = child(w, blocks)
    index = 0
    while block != NONE:
        put(o, base + index * 32, block)
        put(o, base + index * 32 + 8, 0)
        index = index + 1
        block = next_node(w, block)
    track = 0
    result = child(w, field(w, fn, K_returns))
    while result != NONE:
        if type_id(w, result) >= 15:
            track = 1
        result = next_node(w, result)
    parameter = child(w, field(w, fn, K_params))
    while parameter != NONE:
        name = field(w, parameter, K_name)
        definition_id = definition(w, o, name)
        typ = type_id(w, field(w, parameter, K_type))
        if typ > 12:
            at = rec(o, definition_id)
            put(o, at + 48, definition_id)
            put(o, at + 56, NONE)
            put(o, at + 64, choose(typ >= 15, 1, 0))
            origin = NONE
            if track != 0 and typ >= 15:
                origin = name
            put(o, at + 72, origin)
        parameter = next_node(w, parameter)
    entry = symbol(w, o, field(w, fn, K_entry), 2, 0, 0)
    queue = base + 4096 * 32
    put(o, queue, entry)
    put(o, base + entry * 32 + 8, 1)
    first = 0
    last = 1
    while first < last:
        index = get(o, queue + first * 8)
        block = get(o, base + index * 32)
        check_block(s, w, o, block)
        if get(o, 0) != 0:
            return 0
        term = field(w, block, K_term)
        op = field(w, term, K_op)
        if text_is(w, op, L_jump) != 0:
            last = transfer(w, o, term, queue, last)
        if text_is(w, op, L_branch) != 0:
            last = transfer(w, o, field(w, term, K_then), queue, last)
            if get(o, 0) == 0:
                last = transfer(w, o, field(w, term, K_else), queue, last)
        if get(o, 0) != 0:
            return 0
        first = first + 1
    if first != count(w, blocks):
        put(o, 0, CFG)
    return 0

def transfer(w:mutbuf, o:mutbuf, edge:u64, queue:u64, last:u64) -> u64:
    target = symbol(w, o, field(w, edge, K_target), 2, 0, 0)
    base = get(o, 32)
    target_block = get(o, base + target * 32)
    args = field(w, edge, K_args)
    params = field(w, target_block, K_params)
    arg = child(w, args)
    while arg != NONE:
        value(w, o, arg)
        if get(o, 0) != 0:
            return last
        arg = next_node(w, arg)
    i = 0
    while i < count(w, args):
        name = definition(w, o, item(w, args, i))
        if value_type(w, name) != type_id(w, field(w, item(w, params, i), K_type)):
            put(o, 0, CFG)
            return last
        i = i + 1
    stamp = edge + 1
    i = 0
    while i < count(w, args):
        name = definition(w, o, item(w, args, i))
        if value_type(w, name) > 12:
            at = rec(o, name)
            if get(o, at + 80) == stamp:
                put(o, 0, RESOURCE)
                return last
            put(o, at + 80, stamp)
            put(o, at + 88, definition(w, o, field(w, item(w, params, i), K_name)))
        i = i + 1
    i = 0
    while i < get(o, 64):
        name = live_item(o, i)
        if active(o, name) != 0 and cap(o, name, 32) == 0 and get(o, rec(o, name) + 80) != stamp:
            put(o, 0, RESOURCE)
            return last
        i = i + 1
    i = 0
    while i < count(w, args):
        name = definition(w, o, item(w, args, i))
        if value_type(w, name) > 12:
            root = cap(o, name, 16)
            parent = cap(o, name, 24)
            if get(o, rec(o, root) + 80) != stamp:
                put(o, 0, LOAN)
                return last
            root = get(o, rec(o, root) + 88)
            if parent != NONE:
                if get(o, rec(o, parent) + 80) != stamp:
                    put(o, 0, LOAN)
                    return last
                parent = get(o, rec(o, parent) + 88)
            destination = get(o, rec(o, name) + 88)
            at = rec(o, destination)
            if get(o, base + target * 32 + 8) != 0:
                if get(o, at + 48) != root or get(o, at + 56) != parent or get(o, at + 64) != cap(o, name, 32) or get(o, at + 72) != cap(o, name, 40):
                    put(o, 0, LOAN)
                    return last
            else:
                put(o, at + 48, root)
                put(o, at + 56, parent)
                put(o, at + 64, cap(o, name, 32))
                put(o, at + 72, cap(o, name, 40))
        i = i + 1
    if get(o, base + target * 32 + 8) == 0:
        put(o, base + target * 32 + 8, 1)
        put(o, queue + last * 8, target)
        last = last + 1
    return last
'''


def source_program():
    declarations=ast.parse(declaration_source()).body
    # Retain the complete declarations policy; only its already-admitted SSA
    # symbol value becomes the original parameter node for body-state lookup.
    defs=next(n for n in declarations if n.name=='definitions')
    call=next(n for n in ast.walk(defs) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id=='symbol')
    assert isinstance(call.args[-1],ast.Constant) and call.args[-1].value==0
    call.args[-1]=ast.Name(id='item',ctx=ast.Load())
    text=BODY
    text+='\ndef instruction(s:readbuf, w:mutbuf, o:mutbuf, ins:u64) -> u64:\n    op = field(w, ins, K_op)\n'
    for spec in OPCODES.values():
        a=rules(spec.operands)|((1<<48) if spec.name in {'borrow.read','borrow.mut'} else 0)
        r=rules(spec.results);r=(r&((1<<32)-1))|((r>>56)<<32)
        attr={'value':1,'mode':2,'function':3}.get(spec.attributes[0],0) if spec.attributes else 0
        effects=sum(1<<('alloc','read','write','trap').index(v) for v in spec.effects)
        special=1 if spec.name=='const' else 2 if spec.name=='int.cast' else 0
        r|=attr<<40|effects<<48|special<<56
        guards=[]
        for guard in spec.guards:
            fields=guard.split(':')
            if fields[0]=='callee_interface':continue
            code={'free':1,'end_local_loan':2,'read':3,'write':4,'distinct':5}[fields[0]]|int(fields[1])<<4
            if len(fields)==3:code|=int(fields[2])<<6
            guards.append(code)
        policy=TRANSITIONS.index(spec.resource_transition)|(int(spec.name in {'borrow.mut','chain.head_mut'})<<8)|sum(code<<(16+i*8) for i,code in enumerate(guards))
        text+='    if text_is(w, op, '+', '.join(map(str,packed(spec.name)))+') != 0:\n'
        text+='        if get(o, 24) < '+str(spec.since)+':\n            put(o, 0, OPCODE)\n            return 0\n'
        text+='        return local_types(s, w, o, ins, '+str(a)+', '+str(r)+', '+str(policy)+')\n'
    text+='    put(o, 0, OPCODE)\n    return 0\n'
    text+='\ndef attribute_name(w:mutbuf, node:u64) -> u64:\n'
    for i,name in enumerate(('value','mode','function')):
        text+='    if same(w, get(w, 64 + node * 56 + 40), get(w, 64 + node * 56 + 48), '+', '.join(map(str,packed(name)))+') != 0:\n        return '+str(i+1)+'\n'
    text+='    return 0\n\ndef cast_mode(w:mutbuf, node:u64) -> u64:\n'
    for i,name in enumerate(('checked','wrap')):
        text+='    if text_is(w, node, '+', '.join(map(str,packed(name)))+') != 0:\n        return '+str(i+1)+'\n'
    text+='    return 0\n'
    # Reuse exact scalar group and decimal-bound authorship, not its transport.
    from tools.generate_hia_instruction_policy import source_program as local_source
    extra=[]
    for fn in ast.parse(local_source()).body:
        if fn.name=='group':fn.name='type_group';extra.append(fn)
        if fn.name=='literal_bound':extra.append(fn)
    constants={**ERRORS,**{'K_'+name:1<<i for i,name in enumerate(KEYS)}}
    literals={'L_'+name:packed(name) for name in ('branch','ret','trap','jump')}
    class Expand(ast.NodeTransformer):
        def visit_Name(self,node):return ast.copy_location(ast.Constant(constants[node.id]),node) if node.id in constants else node
        def visit_Call(self,node):
            node=self.generic_visit(node);args=[]
            for arg in node.args:
                args.extend(ast.Constant(x) for x in literals[arg.id]) if isinstance(arg,ast.Name) and arg.id in literals else args.append(arg)
            node.args=args;return node
    body=Expand().visit(ast.parse(text)).body
    root=body.pop(0)
    return ast.unparse(ast.fix_missing_locations(ast.Module(body=[root,*declarations,*body,*extra],type_ignores=[])))+'\n'


def document():
    nodes=ast.parse(source_program()).body;names={n.name:'f'+str(i) for i,n in enumerate(nodes)}
    assert len(names)==len(nodes)
    signatures={n.name:([a.annotation.id for a in n.args.args],n.returns.id) for n in nodes}
    total=total_scalar_functions(nodes);functions=[]
    for node in nodes:
        b=Builder(node,names,signatures,total);b.statements(node.body)
        functions.append({'name':names[node.name],'params':[b.param(v) for v in b.params],
            'returns':[b.returns],'effects':['read','write','trap'],'entry':'b0','blocks':b.blocks})
    return compact_authoring_cfg({'schema':'hepta.hia.program.v8','module':'core_admission','functions':functions})


if __name__=='__main__':
    path=Path(__file__).resolve().parents[1]/'examples/hia_bootstrap/core_admission.hiaasm'
    path.write_text(render_assembly(document()));print(path.name,path.stat().st_size)
