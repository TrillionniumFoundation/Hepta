"""Unbounded exact-integer arithmetic selected by the context HIA controller.

Inputs use two's-complement little-endian representation and exact-int tags.
The HIA kernel chooses the operation from the issued context action. Foreign
number protocols receive an explicit interop result, never a Python numeric
answer masquerading as a native integer result. All storage bounds derive from
the actual two operands; no decimal, bit-width or source-size quota is added.
"""
from __future__ import annotations

import ast

from tools.hia_native_bigints import BODY as BIGINT_BODY

MAGIC = int.from_bytes(b'HIACTM01', 'little')
RESULT_MAGIC = int.from_bytes(b'HIACTN01', 'little')

BODY = r'''
def ctx_math_main(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 64 or length(o) < 32:
        return 4294967293
    if read_word(s, 0) != @MATH_MAGIC@ or read_word(s, 48) != 0 or read_word(s, 56) != 0:
        return 4294967293
    operation = ctx_math_operation(read_word(s, 8))
    if operation == 0 or read_word(s, 16) > 1 or read_word(s, 24) > 1:
        return 4294967293
    left_size = read_word(s, 32)
    right_size = read_word(s, 40)
    if left_size > length(s) - 64 or right_size != length(s) - 64 - left_size:
        return 4294967293
    if (read_word(s, 16) == 0 and left_size != 0) or (read_word(s, 16) == 1 and left_size == 0):
        return 4294967293
    if (read_word(s, 24) == 0 and right_size != 0) or (read_word(s, 24) == 1 and right_size == 0):
        return 4294967293
    if read_word(s, 16) == 0 or read_word(s, 24) == 0:
        ctx_math_header(o, 1, 0, read_word(s, 8))
        return 32
    capacity = (length(s) - 64) // 4 + 4
    if capacity > 576460752303423484:
        return 4294967294
    stride = 24 + capacity * 8
    if stride > length(w) // 4 or capacity > (length(o) - 32) // 4 or length(o) - 32 - capacity * 4 < 1:
        return 4294967294
    big_init(w, 0, capacity)
    big_init(w, stride, capacity)
    big_init(w, stride * 2, capacity)
    big_init(w, stride * 3, capacity)
    ctx_math_load(s, w, 0, 64, left_size)
    ctx_math_load(s, w, stride, 64 + left_size, right_size)
    if operation >= 4 and operation <= 6:
        order = big_cmp(w, 0, stride)
        answer = choose(operation == 4, choose(order == 2, 1, 0), choose(operation == 5, choose(order != 2, 1, 0), choose(order != 0, 1, 0)))
        ctx_math_header(o, 2, 1, read_word(s, 8))
        store(o, 32, answer)
        return 32
    if ctx_math_calculate(w, operation, stride) == 0:
        return 4294967293
    return ctx_math_store(w, stride * 2, o, read_word(s, 8))

def ctx_math_calculate(w:mutbuf, operation:u64, stride:u64) -> u64:
    if operation == 1:
        return big_add(w, stride * 2, 0, stride)
    if operation == 2:
        return big_sub(w, stride * 2, 0, stride)
    if operation == 3:
        return big_mul(w, stride * 2, 0, stride)
    if operation == 7:
        big_set_u64(w, stride * 3, 0, 1000000)
        if big_cmp(w, stride, stride * 3) != 0:
            return 0
        return ctx_math_floor_million(w, stride * 2, 0, stride * 3)
    if operation == 8:
        if ctx_big_get(w, stride + 8) != 0:
            return 0
        if ctx_big_get(w, 0) != 0:
            return big_set_u64(w, stride * 2, 0, 0)
        return big_copy(w, stride * 2, 0)
    return 0

def ctx_math_floor_million(w:mutbuf, out:u64, value:u64, scratch:u64) -> u64:
    index = ctx_big_get(w, value + 8)
    used = 0
    remainder = 0
    while index != 0:
        index = index - 1
        current = (remainder << 32) | big_limb(w, value, index)
        digit = current // 1000000
        remainder = current % 1000000
        ctx_big_put(w, out + 24 + index * 8, digit)
        if digit != 0 and used == 0:
            used = index + 1
    ctx_big_put(w, out, 0)
    ctx_big_put(w, out + 8, used)
    if ctx_big_get(w, value) != 0:
        if remainder != 0:
            big_set_u64(w, scratch, 0, 1)
            if big_add(w, out, out, scratch) == 0:
                return 0
        if ctx_big_get(w, out + 8) != 0:
            ctx_big_put(w, out, 1)
    return 1

def ctx_math_load(s:readbuf, w:mutbuf, out:u64, at:u64, count:u64) -> u64:
    negative = byte(s, at + count - 1) >> 7
    carry = negative
    used = 0
    index = 0
    while index < count:
        digit = byte(s, at + index)
        if negative != 0:
            digit = 255 - digit + carry
            carry = digit >> 8
            digit = digit & 255
        limb = index // 4
        if index % 4 == 0:
            ctx_big_put(w, out + 24 + limb * 8, 0)
        ctx_big_put(w, out + 24 + limb * 8, ctx_big_get(w, out + 24 + limb * 8) | (digit << ((index % 4) * 8)))
        if digit != 0:
            used = limb + 1
        index = index + 1
    ctx_big_put(w, out, choose(used == 0, 0, negative))
    ctx_big_put(w, out + 8, used)
    return 1

def ctx_math_store(w:mutbuf, value:u64, o:mutbuf, action:u64) -> u32:
    count = big_byte_length(w, value) + 1
    negative = ctx_big_get(w, value)
    carry = negative
    index = 0
    while index < count:
        digit = big_byte(w, value, index)
        if negative != 0:
            digit = 255 - digit + carry
            carry = digit >> 8
            digit = digit & 255
        store(o, 32 + index, digit)
        index = index + 1
    ctx_math_header(o, 0, count, action)
    return 32

def ctx_math_header(o:mutbuf, kind:u64, count:u64, action:u64) -> u64:
    ctx_big_put(o, 0, @MATH_RESULT_MAGIC@)
    ctx_big_put(o, 8, kind)
    ctx_big_put(o, 16, count)
    ctx_big_put(o, 24, action)
    return 0

def ctx_big_get(w:mutbuf, at:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(w, at + i) << (i * 8))
        i = i + 1
    return value

def ctx_big_put(w:mutbuf, at:u64, value:u64) -> u64:
    i = 0
    while i < 8:
        store(w, at + i, value >> (i * 8))
        i = i + 1
    return value
'''

# HIA's table selects the numeric policy from the already-issued action.
OPERATIONS = {14: 1, 17: 4, 26: 5, 27: 5, 28: 4, 35: 4,
              206: 2, 207: 3, 208: 4, 212: 6,
              304: 3, 404: 3, 305: 1, 405: 1, 307: 2, 502: 2,
              308: 7, 503: 7, 309: 8, 504: 8}


def body():
    source = BODY.replace('@MATH_MAGIC@', str(MAGIC)).replace('@MATH_RESULT_MAGIC@', str(RESULT_MAGIC))
    source += '\ndef ctx_math_operation(action:u64) -> u64:\n'
    for action, operation in sorted(OPERATIONS.items()):
        source += f'    if action == {action}:\n        return {operation}\n'
    source += '    return 0\n'
    class Helpers(ast.NodeTransformer):
        def visit_Call(self, node):
            self.generic_visit(node)
            if isinstance(node.func, ast.Name) and node.func.id in ('get', 'put'):
                node.func.id = 'ctx_big_' + node.func.id
            return node
    # Only byte-address helper names differ; the shared arithmetic bodies are
    # mechanically preserved and independently guarded by the source tests.
    native = Helpers().visit(ast.parse(BIGINT_BODY))
    return source + '\n' + ast.unparse(ast.fix_missing_locations(native)) + '\n'
