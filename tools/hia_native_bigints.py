"""Shared HIA sign/magnitude arithmetic for resource-analysis owners.

This is authoring input, never a hosted arithmetic fallback. Callers provide
the ordinary byte-addressed ``get``/``put`` helpers and an owned ``mutbuf``.

An object occupies ``24 + 8 * capacity`` bytes. Its header is sign (0/1),
used limb count, and capacity; little-endian base-2**32 limbs follow, each in
one u64 storage word. Zero has sign=used=0. A nonzero highest limb is required.
Capacity comes from the caller's actual representation/storage proof; this
module has no numeric, source-node, bit-width or limb-count quota.

Except big_init/big_valid, arithmetic requires canonical live objects whose
storage regions do not overlap. Output may be exactly an operand for copy,
add, sub and shl. Mul requires a distinct output and capacity >= len(a)+len(b)
for nonzero operands. Every insufficient-capacity or prohibited-alias refusal
returns zero before changing output. Successful writes return one; comparisons
return 0 for equal, 1 for less and 2 for greater. Byte export returns one/zero.
Import reads raw little-endian magnitude bytes already held in the same arena;
its source range must not overlap the destination object. Export uses a
separate output buffer. Neither operation applies a decimal-digit policy.
"""

BODY = r'''
def big_init(w:mutbuf, out:u64, capacity:u64) -> u64:
    if out > length(w) or length(w) - out < 24:
        return 0
    if capacity > (length(w) - out - 24) // 8:
        return 0
    put(w, out, 0)
    put(w, out + 8, 0)
    put(w, out + 16, capacity)
    return 1

def big_valid(w:mutbuf, value:u64) -> u64:
    if value > length(w) or length(w) - value < 24:
        return 0
    count = get(w, value + 8)
    capacity = get(w, value + 16)
    if capacity > (length(w) - value - 24) // 8 or count > capacity or get(w, value) > 1:
        return 0
    if count == 0:
        return choose(get(w, value) == 0, 1, 0)
    if get(w, value + 16 + count * 8) == 0:
        return 0
    index = 0
    while index < count:
        if get(w, value + 24 + index * 8) > 4294967295:
            return 0
        index = index + 1
    return 1

def big_set_u64(w:mutbuf, out:u64, negative:u64, value:u64) -> u64:
    count = choose(value == 0, 0, 1)
    if value > 4294967295:
        count = 2
    if negative > 1 or count > get(w, out + 16):
        return 0
    if count != 0:
        put(w, out + 24, value & 4294967295)
    if count == 2:
        put(w, out + 32, value >> 32)
    put(w, out, choose(count == 0, 0, negative))
    put(w, out + 8, count)
    return 1

def big_limb(w:mutbuf, value:u64, index:u64) -> u64:
    if index >= get(w, value + 8):
        return 0
    return get(w, value + 24 + index * 8)

def big_copy(w:mutbuf, out:u64, value:u64) -> u64:
    count = get(w, value + 8)
    negative = get(w, value)
    if count > get(w, out + 16):
        return 0
    index = 0
    while index < count:
        put(w, out + 24 + index * 8, get(w, value + 24 + index * 8))
        index = index + 1
    put(w, out, negative)
    put(w, out + 8, count)
    return 1

def big_bit_length(w:mutbuf, value:u64) -> u64:
    count = get(w, value + 8)
    if count == 0:
        return 0
    high = get(w, value + 16 + count * 8)
    bits = (count - 1) * 32
    while high != 0:
        high = high >> 1
        bits = bits + 1
    return bits

def big_cmp_abs(w:mutbuf, left:u64, right:u64) -> u64:
    count = get(w, left + 8)
    other = get(w, right + 8)
    if count != other:
        return choose(count < other, 1, 2)
    while count != 0:
        count = count - 1
        a = big_limb(w, left, count)
        b = big_limb(w, right, count)
        if a != b:
            return choose(a < b, 1, 2)
    return 0

def big_cmp(w:mutbuf, left:u64, right:u64) -> u64:
    negative = get(w, left)
    if negative != get(w, right):
        return choose(negative != 0, 1, 2)
    result = big_cmp_abs(w, left, right)
    if negative != 0 and result != 0:
        return 3 - result
    return result

def big_add_abs(w:mutbuf, out:u64, left:u64, right:u64) -> u64:
    count = choose(get(w, left + 8) > get(w, right + 8), get(w, left + 8), get(w, right + 8))
    index = 0
    carry = 0
    while index < count:
        value = big_limb(w, left, index) + big_limb(w, right, index) + carry
        carry = value >> 32
        index = index + 1
    used = count + carry
    if used > get(w, out + 16):
        return 0
    index = 0
    carry = 0
    while index < count:
        value = big_limb(w, left, index) + big_limb(w, right, index) + carry
        put(w, out + 24 + index * 8, value & 4294967295)
        carry = value >> 32
        index = index + 1
    if carry != 0:
        put(w, out + 24 + count * 8, carry)
    put(w, out, 0)
    put(w, out + 8, used)
    return 1

def big_sub_abs(w:mutbuf, out:u64, left:u64, right:u64) -> u64:
    if big_cmp_abs(w, left, right) == 1:
        return 0
    count = get(w, left + 8)
    index = 0
    borrow = 0
    used = 0
    while index < count:
        a = big_limb(w, left, index)
        b = big_limb(w, right, index) + borrow
        value = (a - b) & 4294967295
        borrow = choose(a < b, 1, 0)
        if value != 0:
            used = index + 1
        index = index + 1
    if used > get(w, out + 16):
        return 0
    index = 0
    borrow = 0
    while index < used:
        a = big_limb(w, left, index)
        b = big_limb(w, right, index) + borrow
        put(w, out + 24 + index * 8, (a - b) & 4294967295)
        borrow = choose(a < b, 1, 0)
        index = index + 1
    put(w, out, 0)
    put(w, out + 8, used)
    return 1

def big_add_signed(w:mutbuf, out:u64, left:u64, right:u64, subtract:u64) -> u64:
    negative = get(w, left)
    other = get(w, right) ^ subtract
    result = 0
    if negative == other:
        result = big_add_abs(w, out, left, right)
    else:
        order = big_cmp_abs(w, left, right)
        if order != 1:
            result = big_sub_abs(w, out, left, right)
        else:
            result = big_sub_abs(w, out, right, left)
            negative = other
    if result != 0:
        put(w, out, choose(get(w, out + 8) == 0, 0, negative))
    return result

def big_add(w:mutbuf, out:u64, left:u64, right:u64) -> u64:
    return big_add_signed(w, out, left, right, 0)

def big_sub(w:mutbuf, out:u64, left:u64, right:u64) -> u64:
    return big_add_signed(w, out, left, right, 1)

def big_mul(w:mutbuf, out:u64, left:u64, right:u64) -> u64:
    if out == left or out == right:
        return 0
    a_count = get(w, left + 8)
    b_count = get(w, right + 8)
    if a_count == 0 or b_count == 0:
        return big_set_u64(w, out, 0, 0)
    if a_count > get(w, out + 16) or b_count > get(w, out + 16) - a_count:
        return 0
    count = a_count + b_count
    index = 0
    while index < count:
        put(w, out + 24 + index * 8, 0)
        index = index + 1
    index = 0
    while index < a_count:
        inner = 0
        carry = 0
        while inner < b_count:
            at = out + 24 + (index + inner) * 8
            value = big_limb(w, left, index) * big_limb(w, right, inner) + get(w, at) + carry
            put(w, at, value & 4294967295)
            carry = value >> 32
            inner = inner + 1
        put(w, out + 24 + (index + b_count) * 8, carry)
        index = index + 1
    while count != 0 and get(w, out + 16 + count * 8) == 0:
        count = count - 1
    put(w, out, choose(count == 0, 0, get(w, left) ^ get(w, right)))
    put(w, out + 8, count)
    return 1

def big_shl(w:mutbuf, out:u64, value:u64, amount:u64) -> u64:
    count = get(w, value + 8)
    negative = get(w, value)
    if count == 0:
        return big_set_u64(w, out, 0, 0)
    words = amount // 32
    bits = amount % 32
    if words > get(w, out + 16) or count > get(w, out + 16) - words:
        return 0
    used = count + words
    if bits != 0 and (big_limb(w, value, count - 1) >> (32 - bits)) != 0:
        used = used + 1
    if used > get(w, out + 16):
        return 0
    index = used
    while index != 0:
        index = index - 1
        limb = 0
        if index >= words:
            limb = (big_limb(w, value, index - words) << bits) & 4294967295
            if bits != 0 and index > words:
                limb = limb | (big_limb(w, value, index - words - 1) >> (32 - bits))
        put(w, out + 24 + index * 8, limb)
    put(w, out, negative)
    put(w, out + 8, used)
    return 1

def big_import_le(w:mutbuf, out:u64, source:u64, count:u64, negative:u64) -> u64:
    if source > length(w) or count > length(w) - source or negative > 1:
        return 0
    if count == 0:
        if negative != 0:
            return 0
        return big_set_u64(w, out, 0, 0)
    if byte(w, source + count - 1) == 0:
        return 0
    used = count // 4 + choose(count % 4 != 0, 1, 0)
    if used > get(w, out + 16):
        return 0
    index = 0
    while index < used:
        value = 0
        inner = 0
        while inner < 4 and index * 4 + inner < count:
            value = value | (byte(w, source + index * 4 + inner) << (inner * 8))
            inner = inner + 1
        put(w, out + 24 + index * 8, value)
        index = index + 1
    put(w, out, negative)
    put(w, out + 8, used)
    return 1

def big_byte_length(w:mutbuf, value:u64) -> u64:
    bits = big_bit_length(w, value)
    return bits // 8 + choose(bits % 8 != 0, 1, 0)

def big_byte(w:mutbuf, value:u64, index:u64) -> u64:
    return (big_limb(w, value, index // 4) >> ((index % 4) * 8)) & 255

def big_export_le(w:mutbuf, value:u64, out:mutbuf, at:u64, extent:u64) -> u64:
    count = big_byte_length(w, value)
    if at > length(out) or extent > length(out) - at or count > extent:
        return 0
    index = 0
    while index < count:
        store(out, at + index, big_byte(w, value, index))
        index = index + 1
    return 1
'''
