"""HIA authoring for the public interpreter's non-const scalar operations.

This module only emits typed HIA.  The selected execution path evaluates the
emitted program, including signed arithmetic, range checks and first-trap
selection; it never calls these Python authoring helpers at runtime.

``vm_scalar`` accepts canonical low-width raw words.  Its host supplies the
ordinary ``get``/``put`` byte-offset helpers.  Workspace words at byte offsets
96 and 104 hold the first error and its output type.  A successful operation
does not change either word; an existing error prevents all further work.
"""
from __future__ import annotations

import ast

from tools.generate_hia_selfhost import Builder


class ScalarBuilder(Builder):
    """Add only unsigned division/remainder to the restricted authoring DSL."""

    def expr(self, value):
        if isinstance(value, ast.BinOp) and isinstance(value.op, (ast.FloorDiv, ast.Mod)):
            left, right = self.expr(value.left), self.expr(value.right)
            if left[1] != 'u64' or right[1] != 'u64':
                raise ValueError('scalar authoring division/remainder requires u64')
            opcode = 'int.div.checked' if isinstance(value.op, ast.FloorDiv) else 'int.rem.checked'
            return self.op(opcode, [left, right], 'u64')
        return super().expr(value)


BODY = r'''
def vm_s_width(t:u64) -> u64:
    if t == 1 or t == 5:
        return 8
    if t == 2 or t == 6:
        return 16
    if t == 3 or t == 7:
        return 32
    if t == 4 or t == 8 or t == 9 or t == 10:
        return 64
    return 0

def vm_s_signed(t:u64) -> bool:
    return t == 1 or t == 2 or t == 3 or t == 4 or t == 9

def vm_s_mask(t:u64) -> u64:
    width = vm_s_width(t)
    if width == 64:
        return 18446744073709551615
    if width == 0:
        return 0
    return (1 << width) - 1

def vm_s_sign(t:u64) -> u64:
    width = vm_s_width(t)
    if width == 0:
        return 0
    return 1 << (width - 1)

def vm_s_value(t:u64, value:u64) -> bool:
    if t >= 1 and t <= 10:
        return (value & vm_s_mask(t)) == value
    if t == 11:
        return value <= 1
    if t == 12:
        return value == 0
    return False

def vm_s_fail(w:mutbuf, error:u64, t:u64) -> u64:
    if get(w, 96) == 0:
        put(w, 96, error)
        put(w, 104, t)
    return 0

def vm_s_magnitude(value:u64, mask:u64, sign:u64) -> u64:
    if (value & sign) != 0:
        return (0 - value) & mask
    return value

def vm_s_add_sub(w:mutbuf, op:u64, t:u64, a:u64, b:u64) -> u64:
    mask = vm_s_mask(t)
    value = (a + b) & mask
    if op == 4 or op == 5:
        value = (a - b) & mask
    if op == 3 or op == 5:
        return value
    if vm_s_signed(t) == False:
        if op == 2 and a > mask - b:
            return vm_s_fail(w, 1, t)
        if op == 4 and a < b:
            return vm_s_fail(w, 1, t)
        return value
    sign = vm_s_sign(t)
    if op == 2 and ((a ^ value) & (b ^ value) & sign) != 0:
        return vm_s_fail(w, 1, t)
    if op == 4 and ((a ^ b) & (a ^ value) & sign) != 0:
        return vm_s_fail(w, 1, t)
    return value

def vm_s_multiply(w:mutbuf, op:u64, t:u64, a:u64, b:u64) -> u64:
    mask = vm_s_mask(t)
    if op == 7:
        return (a * b) & mask
    if vm_s_signed(t) == False:
        if b != 0 and a > mask // b:
            return vm_s_fail(w, 1, t)
        return (a * b) & mask
    sign = vm_s_sign(t)
    left = vm_s_magnitude(a, mask, sign)
    right = vm_s_magnitude(b, mask, sign)
    negative = ((a ^ b) & sign) != 0
    limit = sign - 1
    if negative:
        limit = sign
    if right != 0 and left > limit // right:
        return vm_s_fail(w, 1, t)
    value = left * right
    if negative:
        value = (0 - value) & mask
    return value

def vm_s_div_rem(w:mutbuf, op:u64, t:u64, a:u64, b:u64) -> u64:
    if b == 0:
        return vm_s_fail(w, 2, t)
    if vm_s_signed(t) == False:
        if op == 8:
            return a // b
        return a % b
    mask = vm_s_mask(t)
    sign = vm_s_sign(t)
    if a == sign and b == mask:
        return vm_s_fail(w, 3, t)
    left = vm_s_magnitude(a, mask, sign)
    right = vm_s_magnitude(b, mask, sign)
    if op == 8:
        value = left // right
        if ((a ^ b) & sign) != 0:
            value = (0 - value) & mask
        return value
    value = left % right
    if (a & sign) != 0:
        value = (0 - value) & mask
    return value

def vm_s_shift(w:mutbuf, op:u64, t:u64, a:u64, b:u64) -> u64:
    width = vm_s_width(t)
    if b >= width:
        return vm_s_fail(w, 4, t)
    mask = vm_s_mask(t)
    if op == 10:
        return (a << b) & mask
    if b == 0:
        return a
    value = a >> b
    if vm_s_signed(t) and (a & vm_s_sign(t)) != 0:
        value = value | (mask ^ (mask >> b))
    return value

def vm_s_bits_neg(w:mutbuf, op:u64, t:u64, a:u64, b:u64) -> u64:
    if op == 12:
        return a & b
    if op == 13:
        return a | b
    if op == 14:
        return a ^ b
    mask = vm_s_mask(t)
    if op == 15:
        return a ^ mask
    if vm_s_signed(t):
        if a == vm_s_sign(t):
            return vm_s_fail(w, 1, t)
    else:
        if a != 0:
            return vm_s_fail(w, 1, t)
    return (0 - a) & mask

def vm_s_integer(w:mutbuf, op:u64, t:u64, a:u64, b:u64) -> u64:
    if op <= 5:
        return vm_s_add_sub(w, op, t, a, b)
    if op <= 7:
        return vm_s_multiply(w, op, t, a, b)
    if op <= 9:
        return vm_s_div_rem(w, op, t, a, b)
    if op <= 11:
        return vm_s_shift(w, op, t, a, b)
    return vm_s_bits_neg(w, op, t, a, b)

def vm_s_compare(w:mutbuf, op:u64, at:u64, a:u64, b:u64) -> u64:
    if at == 11:
        if op != 17 and op != 18:
            return vm_s_fail(w, 255, 11)
    else:
        if vm_s_width(at) == 0:
            return vm_s_fail(w, 255, 11)
    if vm_s_value(at, a) == False or vm_s_value(at, b) == False:
        return vm_s_fail(w, 255, 11)
    if vm_s_signed(at):
        sign = vm_s_sign(at)
        a = a ^ sign
        b = b ^ sign
    if op == 17:
        return choose(a == b, 1, 0)
    if op == 18:
        return choose(a != b, 1, 0)
    if op == 19:
        return choose(a < b, 1, 0)
    if op == 20:
        return choose(a <= b, 1, 0)
    if op == 21:
        return choose(a > b, 1, 0)
    return choose(a >= b, 1, 0)

def vm_s_boolean(w:mutbuf, op:u64, a:u64, b:u64) -> u64:
    if a > 1:
        return vm_s_fail(w, 255, 11)
    if op == 23:
        return 1 - a
    if b > 1:
        return vm_s_fail(w, 255, 11)
    if op == 24:
        return a & b
    return a | b

def vm_s_cast(w:mutbuf, t:u64, at:u64, a:u64, mode:u64) -> u64:
    source_mask = vm_s_mask(at)
    target_mask = vm_s_mask(t)
    if mode == 2:
        value = a
        if vm_s_signed(at) and (a & vm_s_sign(at)) != 0:
            value = a | (18446744073709551615 ^ source_mask)
        return value & target_mask
    if mode != 1:
        return vm_s_fail(w, 255, t)
    if vm_s_signed(at) and (a & vm_s_sign(at)) != 0:
        if vm_s_signed(t) == False:
            return vm_s_fail(w, 1, t)
        magnitude = (0 - a) & source_mask
        if magnitude > vm_s_sign(t):
            return vm_s_fail(w, 1, t)
        return (0 - magnitude) & target_mask
    limit = target_mask
    if vm_s_signed(t):
        limit = vm_s_sign(t) - 1
    if a > limit:
        return vm_s_fail(w, 1, t)
    return a

def vm_scalar(w:mutbuf, op:u64, t:u64, at:u64, a:u64, b:u64, c:u64, mode:u64) -> u64:
    if get(w, 96) != 0:
        return 0
    if op >= 2 and op <= 16:
        if t != at or vm_s_width(t) == 0 or vm_s_value(t, a) == False:
            return vm_s_fail(w, 255, t)
        if op != 15 and op != 16 and vm_s_value(t, b) == False:
            return vm_s_fail(w, 255, t)
        return vm_s_integer(w, op, t, a, b)
    if op >= 17 and op <= 22:
        if t != 11:
            return vm_s_fail(w, 255, t)
        return vm_s_compare(w, op, at, a, b)
    if op >= 23 and op <= 25:
        if t != 11 or at != 11:
            return vm_s_fail(w, 255, t)
        return vm_s_boolean(w, op, a, b)
    if op == 26:
        if vm_s_width(t) == 0 or vm_s_width(at) == 0 or vm_s_value(at, a) == False:
            return vm_s_fail(w, 255, t)
        return vm_s_cast(w, t, at, a, mode)
    if op == 27:
        if at != 11 or a > 1 or vm_s_value(t, b) == False or vm_s_value(t, c) == False:
            return vm_s_fail(w, 255, t)
        return choose(a == 1, b, c)
    return vm_s_fail(w, 255, t)
'''
