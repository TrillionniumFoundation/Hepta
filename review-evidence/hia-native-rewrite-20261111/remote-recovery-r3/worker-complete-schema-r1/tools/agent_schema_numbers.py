"""Exact numeric predicates/order for existing HIAGRF01 schema values.

The full validator embeds these HIA functions. Arbitrary integer magnitude is
read directly; binary64 is compared as an exact dyadic rational, never through
host decimal parsing or a narrowed integer conversion. This is NEW UNEXECUTED.
"""
NUMBERS=r'''
def sn_kind(g:readbuf, identifier:u64) -> u64:
    return sn_word(g, 64 + (identifier - 1) * 64)

def sn_bits(g:readbuf, identifier:u64) -> u64:
    at = 64 + (identifier - 1) * 64
    return sn_word(g, sn_word(g, at + 8))

def sn_finite(g:readbuf, identifier:u64) -> u64:
    kind = sn_kind(g, identifier)
    if kind == 2:
        return 1
    if kind != 3:
        return 0
    return choose(((sn_bits(g, identifier) >> 52) & 2047) != 2047, 1, 0)

def sn_integral(g:readbuf, identifier:u64) -> u64:
    kind = sn_kind(g, identifier)
    if kind == 2:
        return 1
    if kind != 3:
        return 0
    bits = sn_bits(g, identifier) & 9223372036854775807
    exponent = (bits >> 52) & 2047
    if exponent == 2047:
        return 0
    if bits == 0:
        return 1
    if exponent < 1023:
        return 0
    if exponent >= 1075:
        return 1
    mask = (1 << (1075 - exponent)) - 1
    return choose((bits & mask) == 0, 1, 0)

def sn_nan(g:readbuf, identifier:u64) -> u64:
    if sn_kind(g, identifier) != 3:
        return 0
    bits = sn_bits(g, identifier)
    if ((bits >> 52) & 2047) != 2047:
        return 0
    return choose((bits & 4503599627370495) != 0, 1, 0)

def sn_sign(g:readbuf, identifier:u64) -> u64:
    at = 64 + (identifier - 1) * 64
    if sn_word(g, at) == 2:
        if sn_word(g, at + 16) == 0:
            return 0
        return sn_word(g, at + 48)
    bits = sn_bits(g, identifier)
    if (bits & 9223372036854775807) == 0:
        return 0
    return bits >> 63

def sn_int_order(g:readbuf, left:u64, right:u64) -> u64:
    a = 64 + (left - 1) * 64
    b = 64 + (right - 1) * 64
    an = sn_word(g, a + 16)
    bn = sn_word(g, b + 16)
    if an < bn:
        return 0
    if an > bn:
        return 2
    ap = sn_word(g, a + 8)
    bp = sn_word(g, b + 8)
    while an != 0:
        an = an - 1
        av = byte(g, ap + an)
        bv = byte(g, bp + an)
        if av < bv:
            return 0
        if av > bv:
            return 2
    return 1

def sn_int_float_order(g:readbuf, integer:u64, floating:u64) -> u64:
    at = 64 + (integer - 1) * 64
    size = sn_word(g, at + 16)
    bits = sn_bits(g, floating) & 9223372036854775807
    if bits == 0:
        return choose(size == 0, 1, 2)
    if size == 0:
        return 0
    exponent = (bits >> 52) & 2047
    if exponent == 2047:
        return 0
    if exponent < 1023:
        return 2
    if size > 128:
        return 2
    start = sn_word(g, at + 8)
    top = byte(g, start + size - 1)
    highest = (size - 1) * 8
    while top > 1:
        top = top >> 1
        highest = highest + 1
    floating_highest = exponent - 1023
    if highest < floating_highest:
        return 0
    if highest > floating_highest:
        return 2
    significand = (bits & 4503599627370495) | 4503599627370496
    position = highest + 1
    while position != 0:
        position = position - 1
        actual = (byte(g, start + (position >> 3)) >> (position & 7)) & 1
        expected = 0
        if exponent >= 1075:
            shift = exponent - 1075
            if position >= shift:
                expected = (significand >> (position - shift)) & 1
        else:
            shift = 1075 - exponent
            expected = (significand >> (position + shift)) & 1
        if actual < expected:
            return 0
        if actual > expected:
            return 2
    if exponent < 1075:
        if (significand & ((1 << (1075 - exponent)) - 1)) != 0:
            return 0
    return 1

def sn_order(g:readbuf, left:u64, right:u64) -> u64:
    left_kind = sn_kind(g, left)
    right_kind = sn_kind(g, right)
    if left_kind != 2 and left_kind != 3:
        return 3
    if right_kind != 2 and right_kind != 3:
        return 3
    if sn_nan(g, left) != 0 or sn_nan(g, right) != 0:
        return 3
    ls = sn_sign(g, left)
    rs = sn_sign(g, right)
    if ls != rs:
        return choose(ls != 0, 0, 2)
    order = 1
    if left_kind == 2:
        if right_kind == 2:
            order = sn_int_order(g, left, right)
        else:
            order = sn_int_float_order(g, left, right)
    else:
        if right_kind == 2:
            order = 2 - sn_int_float_order(g, right, left)
        else:
            a = sn_bits(g, left) & 9223372036854775807
            b = sn_bits(g, right) & 9223372036854775807
            if a < b:
                order = 0
            elif a > b:
                order = 2
    if ls != 0:
        order = 2 - order
    return order

def sn_word(g:readbuf, at:u64) -> u64:
    value = 0
    index = 0
    while index < 8:
        value = value | (byte(g, at + index) << (index * 8))
        index = index + 1
    return value

def sn_u64_float_order(value:u64, bits:u64) -> u64:
    magnitude = bits & 9223372036854775807
    exponent = (bits >> 52) & 2047
    fraction = bits & 4503599627370495
    if exponent == 2047 and fraction != 0:
        return 3
    if magnitude == 0:
        return choose(value == 0, 1, 2)
    if (bits >> 63) != 0:
        return 2
    if exponent == 2047:
        return 0
    if exponent < 1023:
        return choose(value == 0, 0, 2)
    if exponent >= 1087:
        return 0
    significand = fraction | 4503599627370496
    integral = 0
    tail = 0
    if exponent >= 1075:
        integral = significand << (exponent - 1075)
    else:
        shift = 1075 - exponent
        integral = significand >> shift
        tail = significand & ((1 << shift) - 1)
    if value < integral:
        return 0
    if value > integral:
        return 2
    return choose(tail == 0, 1, 0)

def sn_unsigned_order(g:readbuf, value:u64, identifier:u64) -> u64:
    at = 64 + (identifier - 1) * 64
    kind = sn_word(g, at)
    if kind == 3:
        return sn_u64_float_order(value, sn_bits(g, identifier))
    if kind != 2:
        return 3
    size = sn_word(g, at + 16)
    if size == 0:
        return choose(value == 0, 1, 2)
    if sn_word(g, at + 48) != 0:
        return 2
    if size > 8:
        return 0
    start = sn_word(g, at + 8)
    number = 0
    index = 0
    while index < size:
        number = number | (byte(g, start + index) << (index * 8))
        index = index + 1
    if value < number:
        return 0
    if value > number:
        return 2
    return 1
'''
