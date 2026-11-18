"""Author the independent reference ALU using ordinary HIA Core operations."""

import ast
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_scalar_reference_native import MAGIC, OPCODES, RESULT
from hepta.hia_scalar_reference_wire import PROGRAM_MAGIC, PROGRAM_RESULT
from tools.generate_hia_elf_linker import LinkerBuilder, SOURCE as STATIC_SOURCE
from tools.generate_hia_selfhost import compact_authoring_cfg, total_scalar_functions


SOURCE = '''
def execute(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 8:
        return 4294967295
    if uint(s, 0, 8) == @PROGRAM_MAGIC@:
        return reference_program(s, o, w)
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
    put(o, 0, @RESULT@)
    calculate(op, width, flags, uint(s, 32, 8), uint(s, 40, 8), uint(s, 48, 8), o, 8)
    return 24

def calculate(op:u64, width:u64, flags:u64, a:u64, b:u64, c:u64, o:mutbuf, at:u64) -> u64:
    wordmask = 18446744073709551615 >> (64 - width)
    signbit = 1 << (width - 1)
    signed = flags & 1
    negative_a = (flags >> 1) & 1
    negative_b = (flags >> 2) & 1
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
    put(o, at, error)
    put(o, at + 8, value)
    return error

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

def reference_program(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 72 or length(s) > 8388608:
        return 4294967295
    if uint(s, 8, 8) == 0 or uint(s, 8, 8) > 10000000:
        return 4294967295
    depth = uint(s, 16, 8)
    registers = uint(s, 24, 8)
    bounce = uint(s, 32, 8)
    arguments = uint(s, 40, 8)
    arg_count = uint(s, 48, 8)
    result_count = uint(s, 56, 8)
    if depth == 0 or depth > 256 or registers == 0 or registers > 4096 or bounce == 0 or bounce > 4096 - registers:
        return 4294967295
    stride = (registers + bounce + 1) * 8
    if arg_count > registers or result_count > bounce or within(length(s), arguments, arg_count * 8) == 0:
        return 4294967295
    if length(w) < 64 + stride * depth or length(o) < 32 + result_count * 8:
        return 4294967294
    put(w, 0, 0)
    put(w, 16, depth)
    put(w, 24, stride)
    put(w, 32, registers * 8)
    put(w, 40, 0)
    i = 0
    while i < arg_count:
        put(w, 64 + i * 8, uint(s, arguments + i * 8, 8))
        i = i + 1
    status = run_program(s, w, uint(s, 64, 8))
    if status >= 12:
        return 4294967295
    put(o, 0, @PROGRAM_RESULT@)
    put(o, 8, status)
    put(o, 16, get(w, 0))
    put(o, 24, get(w, 40))
    if status != 0:
        return 32
    i = 0
    while i < result_count:
        put(o, 32 + i * 8, get(w, 64 + registers * 8 + i * 8))
        i = i + 1
    return 32 + result_count * 8

def tick(s:readbuf, w:mutbuf) -> u64:
    steps = get(w, 0) + 1
    put(w, 0, steps)
    if steps > uint(s, 8, 8):
        return 0
    return 1

def gather(s:readbuf, w:mutbuf, listing:u64, count:u64, frame:u64, target:u64) -> u64:
    if count > 4096 or within(length(s), listing, count * 8) == 0:
        return 0
    i = 0
    while i < count:
        slot = uint(s, listing + i * 8, 8)
        if slot >= get(w, 32) // 8:
            return 0
        put(w, target + i * 8, get(w, frame + slot * 8))
        i = i + 1
    return 1

def run_program(s:readbuf, w:mutbuf, start:u64) -> u64:
    if tick(s, w) == 0:
        return 5
    frame = 64
    depth = 0
    stride = get(w, 24)
    pc = start
    while pc != 0:
        if within(length(s), pc, 64) == 0:
            return 12
        if tick(s, w) == 0:
            return 5
        op = uint(s, pc, 8)
        if op >= 1 and op <= @select@:
            status = scalar_command(s, w, pc, frame, op)
            if status != 0:
                return status
            pc = pc + 64
        elif op == 32:
            slot = uint(s, pc + 8, 8)
            if slot >= get(w, 32) // 8:
                return 12
            put(w, frame + slot * 8, uint(s, pc + 16, 8))
            pc = pc + 64
        elif op == 33:
            if depth + 1 >= get(w, 16):
                return 6
            pc = enter_call(s, w, pc, frame)
            if pc == 0:
                return 12
            frame = frame + stride
            depth = depth + 1
            if tick(s, w) == 0:
                return 5
        elif op == 34:
            count = uint(s, pc + 16, 8)
            if count > (stride - get(w, 32) - 8) // 8:
                return 12
            if gather(s, w, uint(s, pc + 8, 8), count, frame, frame + get(w, 32)) == 0:
                return 12
            if depth == 0:
                if count != uint(s, 56, 8):
                    return 12
                return 0
            return_pc = get(w, frame + stride - 8)
            if complete_call(s, w, return_pc, frame, count) == 0:
                return 12
            frame = frame - stride
            depth = depth - 1
            pc = return_pc + 64
        elif op == 35:
            trap = uint(s, pc + 8, 8)
            if trap >= 5:
                return 12
            return 7 + trap
        elif op == 36 or op == 37:
            edge = uint(s, pc + 8, 8)
            if op == 37:
                if edge >= get(w, 32) // 8:
                    return 12
                if get(w, frame + edge * 8) != 0:
                    edge = uint(s, pc + 16, 8)
                else:
                    edge = uint(s, pc + 24, 8)
            pc = transfer(s, w, edge, frame)
        else:
            return 12
    return 12

def scalar_command(s:readbuf, w:mutbuf, pc:u64, frame:u64, op:u64) -> u64:
    limit = get(w, 32) // 8
    target = uint(s, pc + 8, 8)
    one = uint(s, pc + 16, 8)
    two = uint(s, pc + 24, 8)
    three = uint(s, pc + 32, 8)
    if target >= limit or one >= limit or two >= limit or three >= limit:
        return 12
    width = uint(s, pc + 40, 8)
    if width != 1 and width != 8 and width != 16 and width != 32 and width != 64:
        return 12
    types = uint(s, pc + 48, 8)
    a = get(w, frame + one * 8)
    b = get(w, frame + two * 8)
    c = get(w, frame + three * 8)
    flags = (types & 1) | ((a >> 62) & types & 2) | ((b >> 61) & types & 4)
    status = calculate(op, width, flags, a, b, c, w, 48)
    if status != 0:
        put(w, 40, uint(s, pc + 56, 8))
        return status
    put(w, frame + target * 8, get(w, 56))
    return 0

def enter_call(s:readbuf, w:mutbuf, pc:u64, frame:u64) -> u64:
    callee = uint(s, pc + 8, 8)
    if callee >= 1024 or within(length(s), 64 + callee * 8, 8) == 0:
        return 0
    count = uint(s, pc + 24, 8)
    if count > get(w, 32) // 8:
        return 0
    child = frame + get(w, 24)
    if gather(s, w, uint(s, pc + 16, 8), count, frame, child) == 0:
        return 0
    put(w, child + get(w, 24) - 8, pc)
    return uint(s, 64 + callee * 8, 8)

def complete_call(s:readbuf, w:mutbuf, pc:u64, child:u64, count:u64) -> u64:
    out = uint(s, pc + 32, 8)
    returns = uint(s, pc + 40, 8)
    if returns != count or within(length(s), out, returns * 8) == 0:
        return 0
    frame = child - get(w, 24)
    slot = 0
    while slot < returns:
        target = uint(s, out + slot * 8, 8)
        if target >= get(w, 32) // 8:
            return 0
        put(w, frame + target * 8, get(w, child + get(w, 32) + slot * 8))
        slot = slot + 1
    return 1

def transfer(s:readbuf, w:mutbuf, edge:u64, frame:u64) -> u64:
    if within(length(s), edge, 24) == 0:
        return 0
    count = uint(s, edge + 16, 8)
    if count > get(w, 32) // 8 or count > (get(w, 24) - get(w, 32) - 8) // 8:
        return 0
    bounce = frame + get(w, 32)
    if gather(s, w, uint(s, edge + 8, 8), count, frame, bounce) == 0:
        return 0
    i = 0
    while i < count:
        put(w, frame + i * 8, get(w, bounce + i * 8))
        i = i + 1
    return uint(s, edge, 8)
'''

class ReferenceBuilder(LinkerBuilder):
    def expr(self, value):
        if isinstance(value, ast.UnaryOp) and isinstance(value.op, ast.Not):
            return self.op('bool.not', [self.expr(value.operand)], 'bool')
        return super().expr(value)


def document():
    constants = {'MAGIC': MAGIC, 'RESULT': RESULT, 'PROGRAM_MAGIC': PROGRAM_MAGIC,
                 'PROGRAM_RESULT': PROGRAM_RESULT, **OPCODES}
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
