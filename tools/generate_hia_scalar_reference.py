"""Author the independent reference ALU using ordinary HIA Core operations."""

import ast
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_scalar_reference_native import MAGIC, OPCODES, RESULT
from tools.generate_hia_elf_linker import LinkerBuilder, SOURCE as STATIC_SOURCE
from tools.generate_hia_selfhost import compact_authoring_cfg, total_scalar_functions


SOURCE = '''
def execute(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) != 56:
        return 4294967295
    if length(o) < 24:
        return 4294967294
    if uint(s, 0, 8) != @MAGIC@:
        return 4294967295
    op = uint(s, 8, 8)
    width = uint(s, 16, 8)
    flags = uint(s, 24, 8)
    if op == 0 or op > @select@ or flags > 15:
        return 4294967295
    if width != 1 and width != 8 and width != 16 and width != 32 and width != 64:
        return 4294967295
    if width == 1 and (flags & 1) != 0:
        return 4294967295
    wordmask = 18446744073709551615 >> (64 - width)
    signbit = 1 << (width - 1)
    signed = flags & 1
    negative_a = (flags >> 1) & 1
    negative_b = (flags >> 2) & 1
    a = uint(s, 32, 8)
    b = uint(s, 40, 8)
    c = uint(s, 48, 8)
    value = 0
    error = 0
    if op <= @int.mul.checked@:
        checked = op >= @int.add.checked@
        if op == @int.add.wrap@ or op == @int.add.checked@:
            value = a + b
            if checked:
                if signed == 0 and value < a:
                    error = 1
                elif signed != 0 and (((a ^ value) & (b ^ value)) >> 63) != 0:
                    error = 1
        elif op == @int.sub.wrap@ or op == @int.sub.checked@:
            value = a - b
            if checked:
                if signed == 0 and a < b:
                    error = 1
                elif signed != 0 and (((a ^ b) & (a ^ value)) >> 63) != 0:
                    error = 1
        else:
            value = a * b
            if checked and product_fits(a, b, negative_a, negative_b, signed, wordmask, signbit) == 0:
                error = 1
        if checked and normalize(value, wordmask, signbit, signed) != value:
            error = 1
    elif op == @int.div.checked@ or op == @int.rem.checked@:
        if b == 0:
            error = 2
        elif signed != 0 and a == 0 - signbit and b == 18446744073709551615:
            error = 3
        else:
            lhs = magnitude(a, negative_a)
            rhs = magnitude(b, negative_b)
            if op == @int.div.checked@:
                value = lhs // rhs
                if negative_a != negative_b:
                    value = 0 - value
            else:
                value = lhs % rhs
                if negative_a != 0:
                    value = 0 - value
    elif op == @int.shl.checked@ or op == @int.shr.checked@:
        if b >= width:
            error = 4
        elif op == @int.shl.checked@:
            value = a << b
        else:
            value = a >> b
            if signed != 0 and negative_a != 0:
                value = value | (18446744073709551615 ^ (18446744073709551615 >> b))
    elif op == @int.neg.checked@:
        value = 0 - a
        if (signed == 0 and a != 0) or a == 0 - signbit or normalize(value, wordmask, signbit, signed) != value:
            error = 1
    elif op == @bit.and@ or op == @bool.and@:
        value = a & b
    elif op == @bit.or@ or op == @bool.or@:
        value = a | b
    elif op == @bit.xor@:
        value = a ^ b
    elif op == @bit.not@:
        value = a ^ 18446744073709551615
    elif op == @bool.not@:
        value = a ^ 1
    elif op >= @compare.eq@ and op <= @compare.ge@:
        value = comparison(op, a, b, negative_a, negative_b)
    elif op == @cast.wrap@ or op == @cast.checked@:
        value = normalize(a, wordmask, signbit, signed)
        if op == @cast.checked@:
            target_negative = 0
            if signed != 0 and (value >> 63) != 0:
                target_negative = 1
            if value != a or target_negative != negative_a:
                error = 1
    else:
        value = c
        if a != 0:
            value = b
    if error != 0:
        value = 0
    else:
        value = normalize(value, wordmask, signbit, signed)
    put(o, 0, @RESULT@)
    put(o, 8, error)
    put(o, 16, value)
    return 24

def product_fits(a:u64, b:u64, negative_a:u64, negative_b:u64, signed:u64, wordmask:u64, signbit:u64) -> u64:
    limit = wordmask
    if signed != 0:
        limit = signbit
        if negative_a == negative_b:
            limit = limit - 1
    lhs = magnitude(a, negative_a)
    rhs = magnitude(b, negative_b)
    if rhs != 0 and lhs > limit // rhs:
        return 0
    return 1

def magnitude(value:u64, negative:u64) -> u64:
    if negative == 0:
        return value
    return 0 - value

def normalize(value:u64, wordmask:u64, signbit:u64, signed:u64) -> u64:
    result = value & wordmask
    if signed != 0 and (result & signbit) != 0:
        result = result | (18446744073709551615 ^ wordmask)
    return result

def comparison(op:u64, a:u64, b:u64, negative_a:u64, negative_b:u64) -> u64:
    equal = a == b and negative_a == negative_b
    less = negative_a > negative_b or (negative_a == negative_b and a < b)
    matched = equal
    if op == @compare.ne@:
        matched = not equal
    elif op == @compare.lt@:
        matched = less
    elif op == @compare.le@:
        matched = less or equal
    elif op == @compare.gt@:
        matched = not less and not equal
    elif op == @compare.ge@:
        matched = not less
    if matched:
        return 1
    return 0
'''

class ReferenceBuilder(LinkerBuilder):
    def expr(self, value):
        if isinstance(value, ast.UnaryOp) and isinstance(value.op, ast.Not):
            return self.op('bool.not', [self.expr(value.operand)], 'bool')
        return super().expr(value)


def document():
    constants = {'MAGIC': MAGIC, 'RESULT': RESULT, **OPCODES}
    source = SOURCE
    for name, number in constants.items():
        source = source.replace(f'@{name}@', str(number))
    support = STATIC_SOURCE.split('\ndef within(', 1)[1]
    nodes = ast.parse(source + '\ndef within(' + support).body
    names = {node.name: f'f{index}' for index, node in enumerate(nodes)}
    signatures = {node.name: ([arg.annotation.id for arg in node.args.args], node.returns.id) for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = ReferenceBuilder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(value) for value in builder.params],
                          'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
                          'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8', 'module': 'scalar_reference',
                                  'functions': functions})


if __name__ == '__main__':
    output = Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap/scalar_reference.hepta'
    output.write_text(render_assembly(document()))
