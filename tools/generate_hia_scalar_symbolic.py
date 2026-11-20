"""Author HIA checked integer/Boolean expressions for an external SMT engine."""
import ast
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_scalar_reference_native import OPCODES
from hepta.hia_scalar_symbolic_native import (
    CONTROL_KINDS, CONTROL_MAGIC, MAGIC, MAX_BLOCKS, MAX_EDGES, MAX_NODES,
    MAX_OPERATIONS, MAX_PARAMETERS, MAX_RETURNS,
    OPERATIONS, ORDER_MAGIC, RESULT, TOTALITY_MAGIC, TOTALITY_TERMINATORS,
)
from tools.generate_hia_scalar_reference import ReferenceBuilder
from tools.generate_hia_elf_linker import SOURCE as SUPPORT
from tools.generate_hia_selfhost import compact_authoring_cfg, total_scalar_functions


SOURCE = '''
def recipe(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) >= 8 and uint(s, 0, 8) == @ORDER_MAGIC@:
        return acyclic_order(s, o, w)
    if length(s) >= 8 and uint(s, 0, 8) == @CONTROL_MAGIC@:
        return control(s, o)
    if length(s) >= 8 and uint(s, 0, 8) == @TOTALITY_MAGIC@:
        return structural_totality(s, o)
    if length(s) != 64 or length(o) < 64 + 32 * @MAX_NODES@:
        return 4294967295
    if uint(s, 0, 8) != @MAGIC@:
        return 4294967295
    op = uint(s, 8, 8)
    dst = uint(s, 16, 8)
    ds = uint(s, 24, 8)
    src = uint(s, 32, 8)
    ss = uint(s, 40, 8)
    constant = uint(s, 48, 8)
    translation = uint(s, 56, 8)
    if op > @select@ or ds > 1 or ss > 1 or translation > 1:
        return 4294967295
    if kind_valid(dst, ds) == 0 or kind_valid(src, ss) == 0:
        return 4294967295
    put(o, 0, @RESULT@)
    put(o, 8, 0)
    put(o, 24, 0)
    value = 0
    if op == 0:
        if dst == 1:
            value = node(o, @n.boolean@, constant, 0, 0)
        elif dst == 0:
            value = literal(o, 0, 8, 0)
        else:
            value = literal(o, constant, dst, ds)
    elif op <= @int.mul.checked@:
        operation = @n.mul@
        if op == @int.add.wrap@ or op == @int.add.checked@:
            operation = @n.add@
        elif op == @int.sub.wrap@ or op == @int.sub.checked@:
            operation = @n.sub@
        value = node(o, operation, 0, 1, 0)
        if op >= @int.add.checked@:
            lhs = widen(o, 0, dst, ds)
            rhs = widen(o, 1, dst, ds)
            full = node(o, operation, lhs, rhs, 0)
            if translation == 0:
                expected = widen(o, value, dst, ds)
                trap(o, 1, node(o, @n.ne@, full, expected, 0))
            else:
                trap(o, 1, overflow(o, full, 2 * dst, dst, ds))
    elif op == @int.div.checked@ or op == @int.rem.checked@:
        zero = literal(o, 0, dst, 0)
        trap(o, 2, node(o, @n.eq@, 1, zero, 0))
        operation = @n.udiv@
        if op == @int.rem.checked@:
            operation = @n.urem@
        if ds == 1:
            minimum = literal(o, 0 - (1 << (dst - 1)), dst, 1)
            negative_one = literal(o, 18446744073709551615, dst, 1)
            at_minimum = node(o, @n.eq@, 0, minimum, 0)
            divisor_negative = node(o, @n.eq@, 1, negative_one, 0)
            trap(o, 1, node(o, @n.and@, at_minimum, divisor_negative, 0))
            operation = @n.sdiv@
            if op == @int.rem.checked@:
                operation = @n.srem@
        value = node(o, operation, 0, 1, 0)
    elif op == @int.shl.checked@ or op == @int.shr.checked@:
        width = literal(o, dst, dst, 0)
        trap(o, 1, node(o, @n.uge@, 1, width, 0))
        operation = @n.shl@
        if op == @int.shr.checked@:
            operation = @n.lshr@
            if ds == 1:
                operation = @n.ashr@
        value = node(o, operation, 0, 1, 0)
    elif op == @int.neg.checked@:
        value = node(o, @n.neg@, 0, 0, 0)
        condition = 0
        if translation == 0:
            lhs = widen(o, 0, dst, ds)
            wide_neg = node(o, @n.neg@, lhs, 0, 0)
            rhs = widen(o, value, dst, ds)
            condition = node(o, @n.ne@, wide_neg, rhs, 0)
        elif ds == 1:
            minimum = literal(o, 0 - (1 << (dst - 1)), dst, 1)
            condition = node(o, @n.eq@, 0, minimum, 0)
        else:
            zero = literal(o, 0, dst, 0)
            condition = node(o, @n.ne@, 0, zero, 0)
        trap(o, 1, condition)
    elif op >= @bit.and@ and op <= @bit.not@:
        value = node(o, @n.bvand@ + op - @bit.and@, 0, 1, 0)
    elif op == @compare.eq@ or op == @compare.ne@:
        value = node(o, @n.eq@ + op - @compare.eq@, 0, 1, 0)
    elif op >= @compare.lt@ and op <= @compare.ge@:
        start = @n.ult@
        if ss == 1:
            start = @n.slt@
        value = node(o, start + op - @compare.lt@, 0, 1, 0)
    elif op == @bool.and@:
        value = node(o, @n.and@, 0, 1, 0)
    elif op == @bool.or@:
        value = node(o, @n.or@, 0, 1, 0)
    elif op == @bool.not@:
        value = node(o, @n.not@, 0, 0, 0)
    elif op == @cast.wrap@ or op == @cast.checked@:
        if dst < src:
            value = node(o, @n.extract@, 0, dst - 1, 0)
        elif dst > src or translation == 0:
            value = widen(o, 0, dst - src, ss)
        if op == @cast.checked@:
            if translation == 0:
                initial = node(o, @n.bv2int@, 0, ss, 0)
                final = node(o, @n.bv2int@, value, ds, 0)
                trap(o, 1, node(o, @n.ne@, initial, final, 0))
            else:
                width = src + 1
                if dst > src:
                    width = dst + 1
                full = widen(o, 0, width - src, ss)
                trap(o, 1, signed_bounds(o, full, width, dst, ds))
    else:
        value = node(o, @n.select@, 0, 1, 2)
    put(o, 16, value)
    return 64 + 32 * get(o, 8)

def control(s:readbuf, o:mutbuf) -> u32:
    if length(s) != 24 or length(o) < 64 + 32 * @MAX_EDGES@:
        return 4294967295
    kind = uint(s, 8, 8)
    edges = uint(s, 16, 8)
    if kind < @c.join@ or kind > @c.observe@ or edges > @MAX_EDGES@:
        return 4294967295
    if kind >= @c.split@ and edges != 0:
        return 4294967295
    put(o, 0, @RESULT@)
    put(o, 8, 0)
    put(o, 24, 1)
    if kind == @c.join@:
        put(o, 56, edges)
        if edges == 0:
            first = control_node(o, @n.boolean@, 0, 0, 0)
        else:
            first = control_node(o, @n.or_inputs@, edges, 0, 0)
    elif kind == @c.phi@:
        put(o, 56, 2 * edges + 1)
        first = 2 * edges
        if edges == 1:
            first = 1
        else:
            i = 0
            while i < edges:
                first = control_node(o, @n.select@, i, edges + i, first)
                i = i + 1
    elif kind == @c.split@:
        put(o, 56, 2)
        put(o, 24, 2)
        first = control_node(o, @n.and@, 0, 1, 0)
        inverse = control_node(o, @n.not@, 1, 0, 0)
        second = control_node(o, @n.and@, 0, inverse, 0)
        put(o, 32, second)
    else:
        put(o, 56, 3)
        first = control_node(o, @n.select@, 0, 1, 2)
    put(o, 16, first)
    return 64 + 32 * get(o, 8)

def control_node(o:mutbuf, kind:u64, a:u64, b:u64, c:u64) -> u64:
    return node(o, kind, a, b, c) - 3 + get(o, 56)

def acyclic_order(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 56 or length(o) < 24 + 8 * @MAX_BLOCKS@ or length(w) < 8 * @MAX_BLOCKS@:
        return 4294967295
    count = uint(s, 8, 8)
    operations = uint(s, 16, 8)
    parameters = uint(s, 24, 8)
    returns = uint(s, 32, 8)
    flags = uint(s, 40, 8)
    if count == 0 or flags > 7 or uint(s, 48, 8) != 0:
        return 4294967295
    put(o, 0, @RESULT@)
    put(o, 16, 0)
    if count > @MAX_BLOCKS@ or operations > @MAX_OPERATIONS@:
        return order_refusal(o, 1)
    if parameters > @MAX_PARAMETERS@ or returns > @MAX_RETURNS@:
        return order_refusal(o, 2)
    if (flags & 1) != 0:
        return order_refusal(o, 3)
    if (flags & 2) != 0:
        return order_refusal(o, 4)
    if (flags & 4) != 0:
        return order_refusal(o, 5)
    if length(s) != 56 + 16 * count:
        return 4294967295
    i = 0
    while i < count:
        put(w, 8 * i, 0)
        i = i + 1
    i = 0
    while i < 2 * count:
        target = uint(s, 56 + 8 * i, 8)
        if target > count:
            return 4294967295
        if target != 0:
            slot = 8 * (target - 1)
            put(w, slot, get(w, slot) + 1)
        i = i + 1
    next = 0
    i = 0
    while i < count:
        if get(w, 8 * i) == 0:
            put(o, 24 + 8 * next, i + 1)
            next = next + 1
        i = i + 1
    head = 0
    while head < next:
        subject = get(o, 24 + 8 * head)
        i = 0
        while i < 2:
            target = uint(s, 56 + 16 * (subject - 1) + 8 * i, 8)
            if target != 0:
                slot = 8 * (target - 1)
                inbound = get(w, slot)
                if inbound == 0:
                    return 4294967295
                put(w, slot, inbound - 1)
                if inbound == 1:
                    put(o, 24 + 8 * next, target)
                    next = next + 1
            i = i + 1
        head = head + 1
    if next != count:
        return order_refusal(o, 6)
    put(o, 8, 0)
    put(o, 16, count)
    return 24 + 8 * count

def order_refusal(o:mutbuf, reason:u64) -> u32:
    put(o, 8, reason)
    return 24

def kind_valid(width:u64, signed:u64) -> u64:
    if width == 0 or width == 1:
        return 1 - signed
    if width == 8 or width == 16 or width == 32 or width == 64:
        return 1
    return 0

def node(o:mutbuf, kind:u64, a:u64, b:u64, c:u64) -> u64:
    count = get(o, 8)
    at = 64 + 32 * count
    put(o, at, kind)
    put(o, at + 8, a)
    put(o, at + 16, b)
    put(o, at + 24, c)
    put(o, 8, count + 1)
    return 3 + count

def literal(o:mutbuf, number:u64, width:u64, signed:u64) -> u64:
    return node(o, @n.literal@, number, width, signed)

def widen(o:mutbuf, value:u64, extra:u64, signed:u64) -> u64:
    return node(o, @n.zext@ - signed, value, extra, 0)

def trap(o:mutbuf, code:u64, condition:u64) -> u64:
    count = get(o, 24)
    at = 32 + 16 * count
    put(o, at, code)
    put(o, at + 8, condition)
    put(o, 24, count + 1)
    return 0

def high(width:u64, signed:u64) -> u64:
    return 18446744073709551615 >> (64 - width + signed)

def lower(width:u64, signed:u64) -> u64:
    if signed == 1:
        return 0 - (1 << (width - 1))
    return 0

def signed_bounds(o:mutbuf, full:u64, width:u64, original:u64, signed:u64) -> u64:
    lo = literal(o, lower(original, signed), width, signed)
    hi = literal(o, high(original, signed), width, 0)
    smaller = node(o, @n.slt@, full, lo, 0)
    larger = node(o, @n.sgt@, full, hi, 0)
    return node(o, @n.or@, smaller, larger, 0)

def overflow(o:mutbuf, full:u64, width:u64, original:u64, signed:u64) -> u64:
    hi = literal(o, high(original, signed), width, 0)
    if signed == 0:
        return node(o, @n.not@, node(o, @n.ule@, full, hi, 0), 0, 0)
    lo = literal(o, lower(original, signed), width, signed)
    first = node(o, @n.sge@, full, lo, 0)
    second = node(o, @n.sle@, full, hi, 0)
    return node(o, @n.not@, node(o, @n.and@, first, second, 0), 0, 0)
'''

TOTALITY_SOURCE = '''
def structural_totality(s:readbuf, o:mutbuf) -> u32:
    if length(s) < 24 or length(o) < 16:
        return 4294967295
    blocks = uint(s, 8, 8)
    operations = uint(s, 16, 8)
    if blocks == 0 or blocks > @MAX_BLOCKS@ or operations > @MAX_OPERATIONS@:
        return 4294967295
    start = 24 + blocks
    if length(s) != start + operations:
        return 4294967295
    put(o, 0, @RESULT@)
    put(o, 8, 0)
    at = 24
    while at < start:
        term = byte(s, at)
        if term != @t.ret@ and term != @t.jump@ and term != @t.branch@:
            return 16
        at = at + 1
    while at < length(s):
        op = byte(s, at)
        if op >= 64 or ((@NONTRAPPING@ >> op) & 1) == 0:
            return 16
        at = at + 1
    put(o, 8, 1)
    return 16

'''


NONTRAPPING_OPS = ('int.add.wrap', 'int.sub.wrap', 'int.mul.wrap', 'bit.and', 'bit.or', 'bit.xor',
                   'bit.not', 'compare.eq', 'compare.ne', 'compare.lt', 'compare.le',
                   'compare.gt', 'compare.ge', 'bool.not', 'bool.and', 'bool.or', 'select')


def document():
    constants = {'MAGIC': MAGIC, 'RESULT': RESULT, 'MAX_NODES': MAX_NODES, 'ORDER_MAGIC': ORDER_MAGIC,
                 'MAX_BLOCKS': MAX_BLOCKS, 'MAX_OPERATIONS': MAX_OPERATIONS,
                 'MAX_PARAMETERS': MAX_PARAMETERS, 'MAX_RETURNS': MAX_RETURNS,
                 'CONTROL_MAGIC': CONTROL_MAGIC, 'MAX_EDGES': MAX_EDGES, **OPCODES,
                 'TOTALITY_MAGIC': TOTALITY_MAGIC,
                 'NONTRAPPING': 1 | sum(1 << OPCODES[name] for name in NONTRAPPING_OPS),
                 **{'t.' + name: code for name, code in TOTALITY_TERMINATORS.items()},
                 **{'c.' + name: code for name, code in CONTROL_KINDS.items()},
                 **{'n.' + name: code for name, code in OPERATIONS.items()}}
    support = SUPPORT[SUPPORT.index('\ndef uint('):SUPPORT.index('\ndef copy_bytes(')]
    source = SOURCE + support + TOTALITY_SOURCE
    for name, value in constants.items():
        source = source.replace(f'@{name}@', str(value))
    nodes = ast.parse(source).body
    names = {node.name: f'f{index}' for index, node in enumerate(nodes)}
    signatures = {node.name: ([arg.annotation.id for arg in node.args.args], node.returns.id)
                  for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = ReferenceBuilder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(value) for value in builder.params],
                          'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
                          'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8', 'module': 'scalar_symbolic',
                                  'functions': functions})


if __name__ == '__main__':
    output = Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap/scalar_symbolic.hepta'
    output.write_text(render_assembly(document()))
