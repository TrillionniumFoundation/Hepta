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
    if length(s) > 8388608 or length(o) < diagnostic_state_bytes(length(s)):
        return ABI
    diagnostic_reset(o)
    status = widen(program_shape(s, o, w))
    if status != 0:
        return diagnostic_status(w, o, status, 17)
    nodes = get(w, 8)
    state = get(o, 32) + 4096 * 40
    if length(o) < state + nodes * 120 + 576:
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
            return diagnostic_status(w, o, get(o, 0), 16)
        fn = next_node(w, fn)
        index = index + 1
    return diagnostic_status(w, o, 0, 16)

def rec(o:mutbuf, definition:u64) -> u64:
    return get(o, 40) + definition * 112

def definition(w:mutbuf, o:mutbuf, name:u64) -> u64:
    return symbol(w, o, name, 3, 0, 0)

def value(w:mutbuf, o:mutbuf, name:u64) -> u64:
    result = definition(w, o, name)
    if result == NONE:
        diagnostic_value(w, o, name, 1)
        return NONE
    if get(o, rec(o, result)) != get(o, 56):
        diagnostic_value(w, o, name, 1)
        return NONE
    if value_type(w, result) > 12 and get(o, rec(o, result) + 8) == 0:
        diagnostic_value(w, o, name, 2)
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
        diagnostic_record(o, TYPE, D_owner_required, 0, 0)
        return 0
    i = 0
    while i < get(o, 64):
        other = live_item(o, i)
        if active(o, other) != 0 and other != definition and cap(o, other, 16) == definition:
            diagnostic_record(o, LOAN, D_owner_borrowed, 0, 0)
            return 0
        i = i + 1
    return 1

def access(w:mutbuf, o:mutbuf, definition:u64, mutable:u64) -> u64:
    typ = value_type(w, definition)
    if (mutable != 0 and typ != 16) or (mutable == 0 and typ != 15 and typ != 16):
        diagnostic_record(o, TYPE, D_view_required, 0, 0)
        return 0
    if children(o, definition) != 0:
        diagnostic_record(o, LOAN, D_parent_suspended, 0, 0)
        return 0
    return 1

def borrow(w:mutbuf, o:mutbuf, source:u64, output:u64, mutable:u64, chain_head:u64) -> u64:
    typ = value_type(w, source)
    permission = typ == 14
    if chain_head == 0:
        permission = typ == 13 or typ == 16 or (mutable == 0 and typ == 15)
    if permission == False:
        diagnostic_record(o, LOAN, D_borrow_permission, 0, 0)
        return 0
    mark = get(o, 112)
    put(o, 112, mark + 1)
    put(o, rec(o, source) + 96, mark)
    parent = cap(o, source, 24)
    while parent != NONE:
        if active(o, parent) == 0:
            diagnostic_record(o, LOAN, D_parent_graph, 0, 0)
            return 0
        if get(o, rec(o, parent) + 96) == mark:
            diagnostic_record(o, LOAN, D_parent_graph, 0, 0)
            return 0
        put(o, rec(o, parent) + 96, mark)
        parent = cap(o, parent, 24)
    root = cap(o, source, 16)
    i = 0
    while i < get(o, 64):
        other = live_item(o, i)
        if active(o, other) != 0 and cap(o, other, 16) == root and get(o, rec(o, other) + 96) != mark:
            if mutable != 0 or value_type(w, other) == 16:
                diagnostic_record(o, LOAN, D_borrow_conflict, 0, 0)
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

def local_types(s:readbuf, w:mutbuf, o:mutbuf, ins:u64, a:u64, r:u64, policy:u64, diagnostic_spec:u64) -> u64:
    attrs = field(w, ins, K_attrs)
    attr = (r >> 40) & 255
    if count(w, attrs) != choose(attr == 0, 0, 1):
        diagnostic_record(o, FORMAT, D_attributes, field(w, ins, K_op), diagnostic_spec)
        return 0
    attrval = child(w, attrs)
    if attr != 0:
        if attribute_name(w, attrval) != attr:
            diagnostic_record(o, FORMAT, D_attributes, field(w, ins, K_op), diagnostic_spec)
            return 0
    args = field(w, ins, K_args)
    out = field(w, ins, K_out)
    ac = a >> 56
    rc = (r >> 32) & 255
    if ac != 255:
        if count(w, args) != ac:
            diagnostic_record(o, TYPE, D_operand_count, field(w, ins, K_op), diagnostic_spec)
            return 0
        i = 0
        while i < ac:
            typ = value_type(w, argument(w, o, ins, i))
            if rule_match(w, o, ins, typ, (a >> (i * 8)) & 255) == 0:
                diagnostic_record(o, choose((a & 281474976710656) != 0, LOAN, TYPE), D_operand_types, field(w, ins, K_op), diagnostic_spec)
                return 0
            i = i + 1
    if rc != 255:
        if count(w, out) != rc:
            diagnostic_record(o, TYPE, D_output_count, field(w, ins, K_op), diagnostic_spec)
            return 0
        i = 0
        while i < rc:
            typ = value_type(w, output_id(w, o, ins, i))
            if rule_match(w, o, ins, typ, (r >> (i * 8)) & 255) == 0:
                diagnostic_record(o, TYPE, D_output_types, field(w, ins, K_op), diagnostic_spec)
                return 0
            i = i + 1
    special = r >> 56
    effects = (r >> 48) & 255
    if special == 1:
        if literal(s, w, attrval, value_type(w, output_id(w, o, ins, 0))) == 0:
            diagnostic_record(o, TYPE, D_constant, field(w, ins, K_op), diagnostic_spec)
            return 0
    if special == 2:
        mode = cast_mode(w, attrval)
        if mode == 0:
            diagnostic_record(o, TYPE, D_integer_cast, field(w, ins, K_op), diagnostic_spec)
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
            if cap(o, name, 32) != 0:
                diagnostic_record(o, LOAN, D_end_external, 0, 0)
            else:
                if children(o, name) != 0:
                    diagnostic_record(o, LOAN, D_end_children, 0, 0)
        if kind == 3 or kind == 4:
            access(w, o, name, choose(kind == 4, 1, 0))
        if kind == 5:
            other = argument(w, o, ins, (code >> 6) & 3)
            if cap(o, name, 16) == cap(o, other, 16):
                diagnostic_record(o, LOAN, D_owner_alias, field(w, ins, K_op), 0)
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
        diagnostic_record(o, NAME, D_callee_identifier, 0, 0)
        return NONE
    context = get(o, 96)
    put(o, 96, 0)
    result = symbol(w, o, name, 1, 0, 0)
    put(o, 96, context)
    if result == NONE:
        diagnostic_record(o, CALL, D_unknown_callee, 0, 0)
    return result

def call_instruction(w:mutbuf, o:mutbuf, ins:u64) -> u64:
    fn = callee(w, o, child(w, field(w, ins, K_attrs)))
    if get(o, 0) != 0:
        return 0
    args = field(w, ins, K_args)
    params = field(w, fn, K_params)
    if count(w, args) != count(w, params):
        diagnostic_record(o, CALL, D_call_arity, 0, 0)
        return 0
    i = 0
    while i < count(w, args):
        actual = argument(w, o, ins, i)
        typ = value_type(w, actual)
        formal = type_id(w, field(w, item(w, params, i), K_type))
        if typ != formal and (formal != 15 or typ != 16):
            diagnostic_record(o, CALL, D_call_argument, 0, 0)
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
                diagnostic_record(o, RESOURCE, D_call_duplicate_owner, 0, 0)
                return 0
            if (typ == 15 or typ == 16) and (previous_type == 15 or previous_type == 16):
                previous_formal = type_id(w, field(w, item(w, params, j), K_type))
                if cap(o, previous, 16) == cap(o, actual, 16) and (previous_formal == 16 or formal == 16):
                    diagnostic_record(o, LOAN, D_call_exclusive_alias, 0, 0)
                    return 0
            j = j + 1
        i = i + 1
    out = field(w, ins, K_out)
    returns = field(w, fn, K_returns)
    if count(w, out) != count(w, returns):
        diagnostic_record(o, TYPE, D_call_outputs, returns, 0)
        return 0
    i = 0
    while i < count(w, returns):
        if value_type(w, output_id(w, o, ins, i)) != type_id(w, item(w, returns, i)):
            diagnostic_record(o, TYPE, D_call_outputs, returns, 0)
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
        # A later result of this call must see every earlier returned loan.
        # Otherwise two exclusive results for one actual root can be admitted.
        if typ > 12:
            append_live(o, actual)
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
            # Calls already publish resources incrementally during admission.
            if value_type(w, name) > 12 and text_is(w, field(w, ins, K_op), L_call) == 0:
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
            diagnostic_record(o, CFG, D_branch_condition, 0, 0)
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
        diagnostic_record(o, EFFECT, D_missing_effects, get(o, 72) & (mask ^ 15), 0)
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
        diagnostic_record(o, TYPE, D_return_types, 0, 0)
        return 0
    i = 0
    while i < count(w, values):
        if value_type(w, definition(w, o, item(w, values, i))) != type_id(w, item(w, returns, i)):
            diagnostic_record(o, TYPE, D_return_types, 0, 0)
            return 0
        i = i + 1
    mark = get(o, 112)
    put(o, 112, mark + 1)
    i = 0
    while i < count(w, values):
        name = definition(w, o, item(w, values, i))
        if value_type(w, name) >= 15:
            if get(o, rec(o, name) + 96) == mark:
                diagnostic_record(o, LOAN, D_return_duplicate_loan, 0, 0)
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
                diagnostic_record(o, RETURN_LOAN, D_return_origin, 0, 0)
                return 0
            if same_text(w, stored_origin, origin) == 0 or children(o, name) != 0 or direct == False:
                diagnostic_record(o, RETURN_LOAN, D_return_origin, 0, 0)
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
                diagnostic_record(o, RESOURCE, D_return_duplicate_owner, 0, 0)
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
            diagnostic_record(o, RESOURCE, D_return_live, 0, 0)
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
        diagnostic_record(o, CFG, D_unchecked_blocks, 0, 0)
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
            diagnostic_record(o, CFG, D_edge_types, 0, 0)
            return last
        i = i + 1
    stamp = edge + 1
    i = 0
    while i < count(w, args):
        name = definition(w, o, item(w, args, i))
        if value_type(w, name) > 12:
            at = rec(o, name)
            if get(o, at + 80) == stamp:
                diagnostic_record(o, RESOURCE, D_edge_duplicate, 0, 0)
                return last
            put(o, at + 80, stamp)
            put(o, at + 88, definition(w, o, field(w, item(w, params, i), K_name)))
        i = i + 1
    i = 0
    while i < get(o, 64):
        name = live_item(o, i)
        if active(o, name) != 0 and cap(o, name, 32) == 0 and get(o, rec(o, name) + 80) != stamp:
            diagnostic_record(o, RESOURCE, D_edge_live, 0, 0)
            return last
        i = i + 1
    i = 0
    while i < count(w, args):
        name = definition(w, o, item(w, args, i))
        if value_type(w, name) > 12:
            root = cap(o, name, 16)
            parent = cap(o, name, 24)
            if get(o, rec(o, root) + 80) != stamp:
                diagnostic_record(o, LOAN, D_edge_loan_graph, 0, 0)
                return last
            root = get(o, rec(o, root) + 88)
            if parent != NONE:
                if get(o, rec(o, parent) + 80) != stamp:
                    diagnostic_record(o, LOAN, D_edge_loan_graph, 0, 0)
                    return last
                parent = get(o, rec(o, parent) + 88)
            destination = get(o, rec(o, name) + 88)
            at = rec(o, destination)
            if get(o, base + target * 32 + 8) != 0:
                if get(o, at + 48) != root or get(o, at + 56) != parent or get(o, at + 64) != cap(o, name, 32) or get(o, at + 72) != cap(o, name, 40):
                    diagnostic_record(o, LOAN, D_edge_predecessors, 0, 0)
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
def diagnostic_state_bytes(size:u64) -> u64:
    bound = ((size + 1) >> 1) + 1
    if bound > 262144:
        bound = 262144
    slots = 2
    while slots < bound * 4:
        slots = slots * 2
    return 128 + slots * 24 + 4096 * 40 + bound * 120 + 576

def diagnostic_reset(o:mutbuf) -> u64:
    base = length(o) - 576
    put(o, base, 3544385976484841800)
    put(o, base + 8, 1)
    put(o, base + 16, 0)
    put(o, base + 24, 0)
    put(o, base + 32, 0)
    put(o, base + 40, 512)
    put(o, base + 48, 0)
    put(o, base + 56, 0)
    return 0

def diagnostic_status(w:mutbuf, o:mutbuf, status:u64, family:u64) -> u64:
    base = length(o) - 576
    site = get(o, base + 48)
    if site != 0:
        # Capture every state-dependent insertion before the state is reused.
        a = get(o, base + 56)
        b = get(o, base + 64)
        diagnostic_pool(o)
        end = diagnostic_format(w, o, site, a, b)
        if end == NONE:
            return ABI
        put(o, base + 8, 2)
        put(o, base + 24, family)
        put(o, base + 32, end - 16384)
        put(o, base + 40, base - 16384)
        put(o, base + 48, 16384)
        put(o, base + 56, 0)
    put(o, base + 16, status)
    return status

def diagnostic_copy_name(w:mutbuf, o:mutbuf, at:u64, node:u64) -> u64:
    start = get(w, 64 + node * 56 + 24)
    size = count(w, node)
    i = 0
    while i < size:
        store(o, at + i, byte(w, start + i))
        i = i + 1
    return at + size

def diagnostic_value(w:mutbuf, o:mutbuf, name:u64, family:u64) -> u64:
    # Every reference, not just every definition, passed identifier() during
    # complete declaration admission before the original value() lookup.
    fn = field(w, get(o, 80), K_name)
    block = field(w, get(o, 56) - 1, K_id)
    if count(w, name) > 128 or count(w, fn) > 128 or count(w, block) > 128:
        put(o, 0, ABI)
        return 0
    size = 25 + count(w, name)
    code = RESOURCE
    if family == 1:
        size = count(w, fn) + 1 + count(w, block) + 27 + count(w, name)
        code = SSA
    if size > 512:
        put(o, 0, ABI)
        return 0
    base = length(o) - 576
    at = base + 64
    if family == 1:
        at = diagnostic_copy_name(w, o, at, fn)
        store(o, at, 47)
        at = diagnostic_copy_name(w, o, at + 1, block)
        at = diagnostic_undefined_text(o, at)
    else:
        at = diagnostic_consumed_text(o, at)
    at = diagnostic_copy_name(w, o, at, name)
    # A complete payload precedes its family/length; f0 publishes status last.
    put(o, base + 24, family)
    put(o, base + 32, size)
    put(o, 0, code)
    return 0

def diagnostic_undefined_text(o:mutbuf, at:u64) -> u64:
    store(o, at + 0, 58)
    store(o, at + 1, 32)
    store(o, at + 2, 117)
    store(o, at + 3, 110)
    store(o, at + 4, 100)
    store(o, at + 5, 101)
    store(o, at + 6, 102)
    store(o, at + 7, 105)
    store(o, at + 8, 110)
    store(o, at + 9, 101)
    store(o, at + 10, 100)
    store(o, at + 11, 47)
    store(o, at + 12, 110)
    store(o, at + 13, 111)
    store(o, at + 14, 110)
    store(o, at + 15, 108)
    store(o, at + 16, 111)
    store(o, at + 17, 99)
    store(o, at + 18, 97)
    store(o, at + 19, 108)
    store(o, at + 20, 32)
    store(o, at + 21, 118)
    store(o, at + 22, 97)
    store(o, at + 23, 108)
    store(o, at + 24, 117)
    store(o, at + 25, 101)
    store(o, at + 26, 32)
    return at + 27

def diagnostic_consumed_text(o:mutbuf, at:u64) -> u64:
    store(o, at + 0, 117)
    store(o, at + 1, 115)
    store(o, at + 2, 101)
    store(o, at + 3, 32)
    store(o, at + 4, 111)
    store(o, at + 5, 102)
    store(o, at + 6, 32)
    store(o, at + 7, 99)
    store(o, at + 8, 111)
    store(o, at + 9, 110)
    store(o, at + 10, 115)
    store(o, at + 11, 117)
    store(o, at + 12, 109)
    store(o, at + 13, 101)
    store(o, at + 14, 100)
    store(o, at + 15, 32)
    store(o, at + 16, 114)
    store(o, at + 17, 101)
    store(o, at + 18, 115)
    store(o, at + 19, 111)
    store(o, at + 20, 117)
    store(o, at + 21, 114)
    store(o, at + 22, 99)
    store(o, at + 23, 101)
    store(o, at + 24, 32)
    return at + 25

def diagnostic_record(o:mutbuf, code:u64, site:u64, a:u64, b:u64) -> u64:
    # This runs at the original first-refusal edge. No formatter runs until
    # every policy frame has returned to f0 with this status.
    base = length(o) - 576
    put(o, base + 48, site)
    put(o, base + 56, a)
    put(o, base + 64, b)
    put(o, 0, code)
    return 0

def diagnostic_span(w:mutbuf, o:mutbuf, at:u64, start:u64, size:u64, pool:u64) -> u64:
    end = length(o) - 576
    if at > end or size > end - at:
        return NONE
    i = 0
    while i < size:
        value = 0
        if pool == 0:
            value = byte(w, start + i)
        else:
            value = byte(o, start + i)
        store(o, at + i, value)
        i = i + 1
    return at + size

def diagnostic_type_list(w:mutbuf, o:mutbuf, at:u64, array:u64) -> u64:
    at = diagnostic_span(w, o, at, D_open_list, 1, 1)
    node = child(w, array)
    first = True
    while node != NONE and at != NONE:
        if first == False:
            at = diagnostic_span(w, o, at, D_comma, 2, 1)
        at = diagnostic_span(w, o, at, D_quote, 1, 1)
        at = diagnostic_span(w, o, at, get(w, 64 + node * 56 + 24), count(w, node), 0)
        at = diagnostic_span(w, o, at, D_quote, 1, 1)
        first = False
        node = next_node(w, node)
    return diagnostic_span(w, o, at, D_close_list, 1, 1)

def diagnostic_action(w:mutbuf, o:mutbuf, at:u64, action:u64, a:u64, b:u64) -> u64:
    kind = action & 255
    start = (action >> 8) & 16777215
    size = action >> 32
    pool = 1
    if kind == 2:
        start = get(w, 64 + a * 56 + 24)
        size = count(w, a)
        pool = 0
    if kind == 3:
        descriptor = get(o, b + start)
        start = descriptor & 4294967295
        size = descriptor >> 32
    if kind == 4:
        return diagnostic_type_list(w, o, at, a)
    if kind == 5:
        start = D_digits + b
        size = 1
    if kind == 6:
        descriptor = get(o, D_effects + a * 8)
        start = descriptor & 4294967295
        size = descriptor >> 32
    return diagnostic_span(w, o, at, start, size, pool)

def diagnostic_format(w:mutbuf, o:mutbuf, site:u64, a:u64, b:u64) -> u64:
    descriptor = get(o, site * 8)
    position = descriptor & 4294967295
    stop = position + (descriptor >> 32) * 8
    at = 16384
    while position < stop:
        at = diagnostic_action(w, o, at, get(o, position), a, b)
        if at == NONE:
            return NONE
        position = position + 8
    return at

def diagnostic_words(o:mutbuf, at:u64, a:u64, b:u64, c:u64, d:u64, e:u64, f:u64, g:u64, h:u64) -> u64:
    put(o, at, a)
    put(o, at + 8, b)
    put(o, at + 16, c)
    put(o, at + 24, d)
    put(o, at + 32, e)
    put(o, at + 40, f)
    put(o, at + 48, g)
    put(o, at + 56, h)
    return 0

'''


# Authoring-time constants only. The HIA refusal edge selects a program and
# its actual decoded node/bitmask inputs; Python never selects runtime text.
DIAGNOSTIC_ROWS = (
    ('owner_required', ('operation requires an owner',)),
    ('owner_borrowed', ('owner moved/dropped/returned while borrowed',)),
    ('view_required', ('memory access requires appropriate view',)),
    ('parent_suspended', ('parent view is suspended until child loans end',)),
    ('borrow_permission', ('invalid borrow permission',)),
    ('parent_graph', ('invalid loan parent graph',)),
    ('borrow_conflict', ('conflicting live borrow',)),
    ('attributes', (2, ': expected exactly ', (3, 0), ' attributes')),
    ('operand_count', (2, ': wrong operand count')),
    ('operand_types', (2, ': operand types must match ', (3, 8))),
    ('output_count', (2, ': wrong output count')),
    ('output_types', (2, ': output types must match ', (3, 16))),
    ('constant', ('constant must be an exactly typed scalar',)),
    ('integer_cast', ('unsupported integer cast',)),
    ('end_external', ("callee cannot end its caller's loan",)),
    ('end_children', ('end child loans before their parent',)),
    ('owner_alias', (2, ' may not alias one owner')),
    ('callee_identifier', ('callee: invalid/reserved ASCII identifier',)),
    ('unknown_callee', ('unknown callee',)),
    ('call_arity', ('call arity mismatch',)),
    ('call_argument', ('call argument type mismatch',)),
    ('call_duplicate_owner', ('owner supplied twice to call',)),
    ('call_exclusive_alias', ('aliased exclusive call arguments',)),
    ('call_outputs', ('call: output types must be ', 4)),
    ('branch_condition', ('branch condition is not bool',)),
    ('missing_effects', (6,)),
    ('return_types', ('return type/arity mismatch',)),
    ('return_duplicate_loan', ('same loan capability returned twice',)),
    ('return_origin', ('returned loan must be its declared parameter or a direct child',)),
    ('return_duplicate_owner', ('same owner returned twice',)),
    ('return_live', ('return leaves live owner/local loan',)),
    ('unchecked_blocks', ('not all blocks were checked',)),
    ('edge_types', ('edge values do not match block parameter types',)),
    ('edge_duplicate', ('linear capability duplicated across an edge',)),
    ('edge_live', ('edge drops a live owner or local loan',)),
    ('edge_loan_graph', ('loan must travel with its owner/parent capability',)),
    ('edge_predecessors', ('predecessors disagree on loan origins/permissions',)),
    ('opcode_version', (2, ' requires HIA program v', 5)),
    ('unsupported_opcode', ('unsupported opcode ', 2)),
)


DECLARATION_DIAGNOSTIC_ROWS = (
    ("program_fields", ("program: expected exactly functions, module, schema",)),
    ("program_fields_exports", ("program: expected exactly exports, functions, module, schema",)),
    ("program_schema", ("unsupported program schema",)),
    ("module_identifier", ("module: invalid/reserved ASCII identifier",)),
    ("function_inventory", ("invalid function inventory",)),
    ("duplicate_function", ("duplicate function",)),
    ("exports_list", ("explicit scalar exports: expected value list",)),
    ("exports_identifier", ("explicit scalar exports: invalid/reserved ASCII identifier",)),
    ("duplicate_export", ("duplicate explicit scalar export",)),
    ("missing_export", ("explicit export names a missing function",)),
    ("resource_export", ("public exports cannot carry resource descriptors",)),
    ("function_fields", ("function: expected exactly blocks, effects, entry, name, params, returns",)),
    ("function_fields_loans", ("function: expected exactly blocks, effects, entry, name, params, return_loans, returns",)),
    ("function_identifier", ("function: invalid/reserved ASCII identifier",)),
    ("function_runtime_collision", ("function collides with native runtime symbol",)),
    ("returns_list", ("returns must be a list",)),
    ("closed_primitive_type", ("type is outside the closed primitive profile",)),
    ("loan_version", ("call loans require the v8 parameter-return contract",)),
    ("return_origin_arity", ("return_loans must match the return arity",)),
    ("nonloan_origin", ("nonloan result requires a null return_loans entry",)),
    ("invalid_loan_origin", ("borrowed result must name an input loan with sufficient permission",)),
    ("declared_effects", ("unknown/duplicate function effect",)),
    ("entry_identifier", ("entry: invalid/reserved ASCII identifier",)),
    ("block_inventory", ("invalid block inventory",)),
    ("block_fields", ("block: expected exactly id, ops, params, term",)),
    ("block_identifier", ("block id: invalid/reserved ASCII identifier",)),
    ("duplicate_block", ("duplicate block",)),
    ("operations_list", ("block operations must be a list",)),
    ("instruction_fields", ("instruction: expected exactly args, attrs, op, out",)),
    ("opcode_text", ("opcode must be text",)),
    ("attributes_object", ("instruction attributes must be an object",)),
    ("duplicate_definition", ("SSA value ", 2, " is defined more than once")),
    ("entry_parameters", ("entry parameters must equal the function signature",)),
    ("missing_block", ("jump to missing block",)),
    ("incoming_entry", ("entry cannot have incoming CFG edges; use a loop header",)),
    ("edge_arity", ("edge arity differs from block parameters",)),
    ("unreachable_block", ("unreachable blocks are not admitted",)),
    ("chain_version", ("recursive chain types require HIA program v7",)),
    ("function_parameters_list", ("function parameters: expected parameter list",)),
    ("function_parameters_fields", ("function parameters: expected exactly name, type",)),
    ("function_parameters_identifier", ("function parameters: invalid/reserved ASCII identifier",)),
    ("function_parameters_duplicate", ("function parameters: duplicate parameter ", 2)),
    ("block_parameters_list", ("block parameters: expected parameter list",)),
    ("block_parameters_fields", ("block parameters: expected exactly name, type",)),
    ("block_parameters_identifier", ("block parameters: invalid/reserved ASCII identifier",)),
    ("block_parameters_duplicate", ("block parameters: duplicate parameter ", 2)),
    ("instruction_outputs_list", ("instruction outputs: expected parameter list",)),
    ("instruction_outputs_fields", ("instruction outputs: expected exactly name, type",)),
    ("instruction_outputs_identifier", ("instruction outputs: invalid/reserved ASCII identifier",)),
    ("instruction_outputs_duplicate", ("instruction outputs: duplicate parameter ", 2)),
    ("instruction_arguments_list", ("instruction arguments: expected value list",)),
    ("instruction_arguments_identifier", ("instruction arguments: invalid/reserved ASCII identifier",)),
    ("return_values_list", ("return values: expected value list",)),
    ("return_values_identifier", ("return values: invalid/reserved ASCII identifier",)),
    ("edge_arguments_list", ("edge arguments: expected value list",)),
    ("edge_arguments_identifier", ("edge arguments: invalid/reserved ASCII identifier",)),
    ("cfg_edge_fields", ("CFG edge: expected exactly args, target",)),
    ("edge_target_identifier", ("edge target: invalid/reserved ASCII identifier",)),
    ("missing_terminator", ("missing terminator",)),
    ("unknown_terminator", ("unknown terminator",)),
    ("ret_fields", ("ret: expected exactly op, values",)),
    ("jump_fields", ("jump: expected exactly args, op, target",)),
    ("branch_fields", ("branch: expected exactly cond, else, op, then",)),
    ("trap_fields", ("trap: expected exactly code, op",)),
    ("branch_condition_identifier", ("branch condition: invalid/reserved ASCII identifier",)),
    ("unknown_trap", ("unknown trap code",)),
)
DIAGNOSTIC_ROWS += DECLARATION_DIAGNOSTIC_ROWS


def declaration_diagnostics(nodes, sites):
    """Attach native message identities to existing declaration refusals.

    The reference messages contain no repr of malformed values. Only duplicate
    admitted identifiers are inserted. The inverse below removes actual added
    records/context parameters and joins the two original short-circuit guards;
    it must recover every original declaration function AST exactly.
    """
    import copy
    original = copy.deepcopy(nodes)
    by_name = {node.name: node for node in nodes}
    changed = []
    split_count = 0
    for function_name, condition in (
        ('check_function', 'identifier(w, name) == 0 or runtime_name(w, name) != 0'),
        ('connect', 'target == 18446744073709551615 or target == entry'),
    ):
        wanted = ast.dump(ast.parse(condition, mode='eval').body, include_attributes=False)
        class Split(ast.NodeTransformer):
            def visit_If(self, node):
                nonlocal split_count
                node = self.generic_visit(node)
                if ast.dump(node.test, include_attributes=False) != wanted:
                    return node
                if node.orelse or len(node.body) != 1 or not isinstance(node.body[0], ast.Return):
                    raise ValueError('declaration split preimage differs')
                first = copy.deepcopy(node)
                second = copy.deepcopy(node)
                first.test, second.test = copy.deepcopy(node.test.values)
                first._diagnostic_split_first = True
                second._diagnostic_split_second = True
                split_count += 1
                return [first, second]
        by_name[function_name] = Split().visit(by_name[function_name])
    if split_count != 2:
        raise ValueError('both original short-circuit guards must be present')
    term = by_name['terminator']
    position = next(index for index, node in enumerate(term.body)
                    if isinstance(node, ast.Assign) and len(node.targets) == 1
                    and isinstance(node.targets[0], ast.Name) and node.targets[0].id == 'op')
    guard = ast.parse('if kind(w, op) != 4:\n    return 4294967286\n').body[0]
    guard._diagnostic_text_guard = True
    term.body.insert(position + 1, guard)
    # Every original text comparison already rejects a non-string before
    # accessing its lexeme, so the new explicit distinction preserves CFG code.
    text_is = by_name['text_is']
    first = text_is.body[0]
    if not (isinstance(first, ast.If) and len(first.body) == 1
            and isinstance(first.body[0], ast.Return)
            and isinstance(first.body[0].value, ast.Constant)
            and first.body[0].value.value == 0):
        raise ValueError('text_is non-string precondition differs')
    expected_guard = ast.parse('kind(w, node) != 4', mode='eval').body
    if ast.dump(first.test, include_attributes=False) != ast.dump(expected_guard, include_attributes=False):
        raise ValueError('text_is must reject every non-string first')

    contexts = {
        ('program_shape', 'names'): ['exports_list'],
        ('check_function', 'parameters'): ['function_parameters_list', 'block_parameters_list',
                                          'instruction_outputs_list'],
        ('check_function', 'names'): ['instruction_arguments_list'],
        ('terminator', 'names'): ['return_values_list', 'edge_arguments_list'],
        ('edge', 'names'): ['edge_arguments_list'],
    }
    call_counts = {}
    for function_name, node in by_name.items():
        class Calls(ast.NodeTransformer):
            def visit_Call(self, call):
                call = self.generic_visit(call)
                name = call.func.id if isinstance(call.func, ast.Name) else None
                if name not in {'parameters', 'names', 'edge', 'terminator'}:
                    return call
                key = (function_name, name)
                ordinal = call_counts.get(key, 0)
                call_counts[key] = ordinal + 1
                if name in {'names', 'parameters'}:
                    values = contexts.get(key)
                    if values is None or ordinal >= len(values):
                        raise ValueError('unclassified declaration context call: ' + repr(key))
                    context = ast.Constant(sites[values[ordinal]])
                    if name == 'names':
                        call.args.insert(1, ast.Name(id='o', ctx=ast.Load()))
                    call.args.append(context)
                else:
                    call.args.insert(1, ast.Name(id='o', ctx=ast.Load()))
                call._diagnostic_context_call = name
                return call
        by_name[function_name] = Calls().visit(node)
    expected_calls = {key: len(value) for key, value in contexts.items()}
    expected_calls.update({('check_function', 'terminator'): 1, ('terminator', 'edge'): 2})
    if call_counts != expected_calls:
        raise ValueError('declaration call inventory differs: ' + repr(call_counts))
    for name in ('parameters', 'names', 'edge', 'terminator'):
        node = by_name[name]
        if name != 'parameters':
            node.args.args.insert(1, ast.arg(arg='o', annotation=ast.Name(id='mutbuf', ctx=ast.Load())))
        if name in {'parameters', 'names'}:
            node.args.args.append(ast.arg(arg='context', annotation=ast.Name(id='u64', ctx=ast.Load())))
        node._diagnostic_context_signature = name
    for base, labels in (
        ('function_parameters_list', ('function_parameters_fields', 'function_parameters_identifier',
                                      'function_parameters_duplicate')),
        ('block_parameters_list', ('block_parameters_fields', 'block_parameters_identifier',
                                   'block_parameters_duplicate')),
        ('instruction_outputs_list', ('instruction_outputs_fields', 'instruction_outputs_identifier',
                                      'instruction_outputs_duplicate')),
    ):
        if [sites[label] for label in labels] != [sites[base] + value for value in (1, 2, 3)]:
            raise ValueError('parameter diagnostic context is not contiguous')
    for base, following in (
        ('exports_list', 'exports_identifier'), ('instruction_arguments_list', 'instruction_arguments_identifier'),
        ('return_values_list', 'return_values_identifier'), ('edge_arguments_list', 'edge_arguments_identifier'),
    ):
        if sites[following] != sites[base] + 1:
            raise ValueError('name diagnostic context is not contiguous')

    FMT, NAME, TYPE, LOAN, EFFECT, CFG, SSA = (0xfffffffb, 0xfffffffa, 0xfffffff9,
                                              0xfffffff8, 0xfffffff7, 0xfffffff6, 0xfffffff5)
    rules = {
        'program_shape': [
            (FMT, 'choose(exports != 18446744073709551615, D_program_fields_exports, D_program_fields)', '0'),
            (0xfffffff4, 'D_program_schema', '0'),
            (NAME, 'D_module_identifier', '0'),
            (FMT, 'D_function_inventory', '0'),
            (NAME, 'D_duplicate_function', '0'),
            (NAME, 'D_duplicate_export', '0'),
            (0xfffffff3, 'D_missing_export', '0'),
            (0xfffffff2, 'D_resource_export', '0'),
            (0xfffffff2, 'D_resource_export', '0'),
        ],
        'check_function': [
            (FMT, 'choose((fields & K_return_loans) != 0, D_function_fields_loans, D_function_fields)', '0'),
            (NAME, 'D_function_identifier', '0'), (NAME, 'D_function_runtime_collision', '0'),
            (TYPE, 'D_returns_list', '0'), (TYPE, 'D_closed_primitive_type', '0'),
            (LOAN, 'D_loan_version', '0'), (LOAN, 'D_return_origin_arity', '0'),
            (LOAN, 'D_nonloan_origin', '0'), (LOAN, 'D_invalid_loan_origin', '0'),
            (LOAN, 'D_invalid_loan_origin', '0'), (LOAN, 'D_invalid_loan_origin', '0'),
            (EFFECT, 'D_declared_effects', '0'), (EFFECT, 'D_declared_effects', '0'),
            (NAME, 'D_entry_identifier', '0'), (CFG, 'D_block_inventory', '0'),
            (FMT, 'D_block_fields', '0'), (NAME, 'D_block_identifier', '0'),
            (CFG, 'D_duplicate_block', '0'), (FMT, 'D_operations_list', '0'),
            (FMT, 'D_instruction_fields', '0'), (FMT, 'D_opcode_text', '0'),
            (FMT, 'D_attributes_object', '0'),
            (CFG, 'D_entry_parameters', '0'), (CFG, 'D_entry_parameters', '0'),
            (CFG, 'D_unreachable_block', '0'), (TYPE, 'D_chain_version', '0'),
        ],
        'parameters': [
            (FMT, 'context', '0'), (FMT, 'context + 1', '0'), (NAME, 'context + 2', '0'),
            (TYPE, 'D_closed_primitive_type', '0'), (SSA, 'context + 3', 'name'),
        ],
        'definitions': [(SSA, 'D_duplicate_definition', 'field(w, item, K_name)')],
        'names': [(FMT, 'context', '0'), (NAME, 'context + 1', '0')],
        'edge': [(FMT, 'D_cfg_edge_fields', '0'), (NAME, 'D_edge_target_identifier', '0')],
        'terminator': [
            (CFG, 'D_missing_terminator', '0'), (CFG, 'D_missing_terminator', '0'),
            (FMT, 'D_ret_fields', '0'), (FMT, 'D_jump_fields', '0'),
            (NAME, 'D_edge_target_identifier', '0'), (FMT, 'D_branch_fields', '0'),
            (NAME, 'D_branch_condition_identifier', '0'), (FMT, 'D_trap_fields', '0'),
            (CFG, 'D_unknown_trap', '0'), (CFG, 'D_unknown_terminator', '0'),
        ],
        'connect': [(CFG, 'D_missing_block', '0'), (CFG, 'D_incoming_entry', '0'),
                    (CFG, 'D_edge_arity', '0')],
    }
    constants = {'D_' + key: value for key, value in sites.items()}
    constants.update({'K_' + key: 1 << index for index, key in enumerate(KEYS)})
    class ExpandDiagnostic(ast.NodeTransformer):
        def visit_Name(self, node):
            return ast.copy_location(ast.Constant(constants[node.id]), node) if node.id in constants else node
    records = []
    for function_name, cases in rules.items():
        index = 0
        class Records(ast.NodeTransformer):
            def visit_Return(self, node):
                nonlocal index
                if not (isinstance(node.value, ast.Constant) and node.value.value in
                        {FMT, NAME, TYPE, LOAN, EFFECT, CFG, SSA, 0xfffffff4, 0xfffffff3, 0xfffffff2}):
                    return node
                if index >= len(cases) or node.value.value != cases[index][0]:
                    raise ValueError('declaration refusal inventory differs at ' + function_name + ':' + str(index))
                code, site, argument = cases[index]
                call = ast.parse('diagnostic_record(o, ' + str(code) + ', ' + site + ', ' + argument + ', 0)').body[0]
                call = ExpandDiagnostic().visit(call)
                call._diagnostic_record = True
                records.append({'function': function_name, 'ordinal': index, 'code': code,
                                'site': site, 'argument': argument})
                index += 1
                return [call, node]
        by_name[function_name] = Records().visit(by_name[function_name])
        if index != len(cases):
            raise ValueError('declaration refusal count differs for ' + function_name)
    result = [by_name[node.name] for node in nodes]
    class Inverse(ast.NodeTransformer):
        def visit_Expr(self, node):
            return None if getattr(node, '_diagnostic_record', False) else self.generic_visit(node)
        def visit_Call(self, node):
            node = self.generic_visit(node)
            name = getattr(node, '_diagnostic_context_call', None)
            if name in {'names', 'parameters'}:
                node.args.pop()
            if name in {'names', 'edge', 'terminator'}:
                node.args.pop(1)
            return node
        def visit_FunctionDef(self, node):
            node = self.generic_visit(node)
            name = getattr(node, '_diagnostic_context_signature', None)
            if name in {'names', 'parameters'}:
                node.args.args.pop()
            if name in {'names', 'edge', 'terminator'}:
                node.args.args.pop(1)
            return node
        def visit_If(self, node):
            node = self.generic_visit(node)
            if getattr(node, '_diagnostic_text_guard', False):
                expected = ast.parse('if kind(w, op) != 4:\n    return 4294967286\n').body[0]
                if ast.dump(node, include_attributes=False) != ast.dump(expected, include_attributes=False):
                    raise ValueError('non-string guard inverse differs')
                return None
            return node
        def generic_visit(self, node):
            node = super().generic_visit(node)
            for field, value in ast.iter_fields(node):
                if not isinstance(value, list):
                    continue
                output = []
                at = 0
                while at < len(value):
                    first = value[at]
                    if isinstance(first, ast.If) and getattr(first, '_diagnostic_split_first', False):
                        if at + 1 >= len(value):
                            raise ValueError('split guard second half absent')
                        second = value[at + 1]
                        if (not isinstance(second, ast.If) or not getattr(second, '_diagnostic_split_second', False)
                                or first.orelse or second.orelse
                                or ast.dump(ast.Module(body=first.body, type_ignores=[]), include_attributes=False)
                                   != ast.dump(ast.Module(body=second.body, type_ignores=[]), include_attributes=False)):
                            raise ValueError('split guard inverse changed')
                        output.append(ast.If(test=ast.BoolOp(op=ast.Or(), values=[first.test, second.test]),
                                             body=first.body, orelse=[]))
                        at += 2
                    else:
                        output.append(first)
                        at += 1
                setattr(node, field, output)
            return node
    restored = Inverse().visit(copy.deepcopy(ast.Module(body=result, type_ignores=[])))
    wanted = ast.Module(body=original, type_ignores=[])
    if ast.dump(restored, include_attributes=False) != ast.dump(wanted, include_attributes=False):
        raise ValueError('declaration diagnostic inverse does not preserve original policy AST')
    global DECLARATION_DIAGNOSTIC_AUDIT
    DECLARATION_DIAGNOSTIC_AUDIT = {
        'original_functions': len(original), 'instrumented_functions': sorted(rules),
        'original_policy_inverse_ast_equal': True, 'split_original_short_circuit_guards': split_count,
        'nonstring_terminator_keeps_original_cfg_status': True, 'records': records,
        'context_call_inventory': [{'function': key[0], 'callee': key[1], 'count': value}
                                   for key, value in sorted(call_counts.items())],
        'native_or_vm_execution': False,
    }
    return result


def diagnostic_tables():
    import struct
    sites = {name: index + 1 for index, (name, _) in enumerate(DIAGNOSTIC_ROWS)}
    pool = bytearray((len(sites) + 1) * 8)
    catalog = {name: len(pool) + index * 24 for index, name in enumerate(OPCODES)}
    pool.extend(bytes(len(catalog) * 24))
    effects = len(pool)
    pool.extend(bytes(16 * 8))
    strings = {}
    def literal(text):
        if text not in strings:
            raw = text.encode('ascii')
            start = len(pool)
            pool.extend(raw)
            strings[text] = (start, len(raw))
        return strings[text]
    def descriptor(text):
        start, size = literal(text)
        return start | (size << 32)
    for name, spec in OPCODES.items():
        struct.pack_into('<3Q', pool, catalog[name],
                         descriptor(', '.join(spec.attributes)),
                         descriptor(repr(spec.operands)), descriptor(repr(spec.results)))
    for mask in range(16):
        names = sorted(name for index, name in enumerate(('alloc', 'read', 'write', 'trap'))
                       if mask & (1 << index))
        struct.pack_into('<Q', pool, effects + mask * 8,
                         descriptor('missing effects ' + repr(names)))
    layout = {'effects': effects, 'digits': literal('0123456789')[0],
              'open_list': literal('[')[0], 'close_list': literal(']')[0],
              'quote': literal("'")[0], 'comma': literal(', ')[0]}
    for name, parts in DIAGNOSTIC_ROWS:
        actions = []
        for part in parts:
            if type(part) is str:
                start, size = literal(part)
                actions.append(1 | (start << 8) | (size << 32))
            elif type(part) is int:
                actions.append(part)
            else:
                tag, offset = part
                actions.append(tag | (offset << 8))
        start = len(pool)
        pool.extend(struct.pack('<' + 'Q' * len(actions), *actions))
        struct.pack_into('<Q', pool, sites[name] * 8, start | (len(actions) << 32))
    pool.extend(bytes((-len(pool)) % 64))
    if len(pool) > 16384:
        raise ValueError('native diagnostic constant table exceeds reserved original state prefix')
    lines = ['def diagnostic_pool(o:mutbuf) -> u64:']
    for at in range(0, len(pool), 64):
        words = struct.unpack_from('<8Q', pool, at)
        lines.append('    diagnostic_words(o, ' + str(at) + ', ' +
                     ', '.join(map(str, words)) + ')')
    lines.append('    return 0')
    return '\n'.join(lines) + '\n', sites, catalog, layout, bytes(pool)

def source_program():
    declarations=ast.parse(declaration_source()).body
    # Retain the complete declarations policy; only its already-admitted SSA
    # symbol value becomes the original parameter node for body-state lookup.
    defs=next(n for n in declarations if n.name=='definitions')
    call=next(n for n in ast.walk(defs) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id=='symbol')
    assert isinstance(call.args[-1],ast.Constant) and call.args[-1].value==0
    call.args[-1]=ast.Name(id='item',ctx=ast.Load())
    pool_source, diagnostic_sites, diagnostic_catalog, diagnostic_layout, _ = diagnostic_tables()
    declarations = declaration_diagnostics(declarations, diagnostic_sites)
    text=BODY + pool_source
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
        text+='        if get(o, 24) < '+str(spec.since)+':\n            diagnostic_record(o, OPCODE, D_opcode_version, op, '+str(spec.since)+')\n            return 0\n'
        text+='        return local_types(s, w, o, ins, '+str(a)+', '+str(r)+', '+str(policy)+', '+str(diagnostic_catalog[spec.name])+')\n'
    text+='    diagnostic_record(o, OPCODE, D_unsupported_opcode, op, 0)\n    return 0\n'
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
    constants={**ERRORS, **{'K_'+name:1<<i for i,name in enumerate(KEYS)},
               **{'D_'+name:value for name,value in diagnostic_sites.items()},
               **{'D_'+name:value for name,value in diagnostic_layout.items()}}
    literals={'L_'+name:packed(name) for name in ('branch','ret','trap','jump','call')}
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
    path=Path(__file__).resolve().parents[1]/'examples/hia_bootstrap/core_admission.hepta'
    path.write_text(render_assembly(document()));print(path.name,path.stat().st_size)
