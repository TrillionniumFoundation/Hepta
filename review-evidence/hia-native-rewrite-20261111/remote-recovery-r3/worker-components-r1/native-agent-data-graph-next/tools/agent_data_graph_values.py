"""Full issued Agent-data arena value materialization into HIAGRF01.

NEW UNEXECUTED DEVELOPMENT. Native binary64 is a real deferred peer, requested
in the original source-order, children-before-parent callback traversal.
No host object, numeric conversion, schema choice or semantic plan is used.
"""
VALUES=r'''
def dg_walk(s:readbuf, r:readbuf, w:mutbuf) -> u32:
    while dg_get(w, D_SP) != 0:
        frame = dg_get(w, D_STACK) + (dg_get(w, D_SP) - 1) * 24
        node = dg_get(w, frame)
        at = 64 + node * 56
        kind = dg_word(s, at)
        dg_put(w, D_CURRENT, node + 1)
        if dg_get(w, frame + 8) == 0:
            dg_put(w, frame + 8, 1)
            if kind == 5 or kind == 6:
                dg_put(w, frame + 16, dg_word(s, at + 24))
        child = dg_get(w, frame + 16)
        if child != DG_MAX:
            dg_put(w, frame + 16, dg_word(s, 64 + child * 56 + 16))
            if dg_push(w, child) == 0:
                return dg_refuse(w, 10)
        else:
            if kind == 7:
                dg_put(w, D_PENDING_NODE, node)
                dg_put(w, D_NUMBER_START, dg_word(s, at + 24))
                dg_put(w, D_NUMBER_BYTES, dg_word(s, at + 32))
                dg_put(w, D_BINARY_STATUS, 0)
                dg_put(w, D_PHASE, 31)
                return dg_event(w, 2)
            if dg_value(s, r, w, node) == 0:
                if dg_get(w, D_ERROR) != 0:
                    dg_put(w, D_PHASE, 91)
                    return dg_event(w, 3)
                return dg_refuse(w, 11)
            dg_put(w, D_SP, dg_get(w, D_SP) - 1)
    graph = dg_get(w, D_GRAPH)
    total = dg_get(w, D_DATABASE) + dg_get(w, D_POOL_USED)
    if total > dg_get(w, D_GRAPH_MAX):
        return dg_refuse(w, 12)
    dg_put(w, graph, DG_GRAPH)
    dg_put(w, graph + 8, dg_get(w, 168))
    dg_put(w, graph + 16, dg_get(w, D_NODES) + dg_get(w, D_KEYS))
    dg_put(w, graph + 24, 1)
    dg_put(w, graph + 32, dg_get(w, D_EDGES))
    dg_put(w, graph + 40, dg_get(w, D_POOL_USED))
    dg_put(w, graph + 48, total)
    dg_put(w, graph + 56, 0)
    dg_put(w, D_GRAPH_TOTAL, total)
    dg_put(w, D_PHASE, 90)
    return dg_event(w, 0)

def dg_value(s:readbuf, r:readbuf, w:mutbuf, node:u64) -> u64:
    at = 64 + node * 56
    kind = dg_word(s, at)
    if kind < 3:
        target = dg_node_zero(w, node + 1)
        if kind != 0:
            dg_put(w, target, 1)
            dg_put(w, target + 48, kind - 1)
        return 1
    if kind == 3:
        return dg_integer(r, w, node + 1, dg_word(s, at + 24), dg_word(s, at + 32))
    if kind == 4:
        return dg_string(s, w, node + 1, dg_word(s, at + 24), dg_word(s, at + 32))
    if kind == 5 or kind == 6:
        return dg_container(s, w, node)
    return 0

def dg_reserve(w:mutbuf, size:u64) -> u64:
    used = dg_get(w, D_POOL_USED)
    if used > dg_get(w, D_POOL_BOUND) or size > dg_get(w, D_POOL_BOUND) - used:
        return DG_MAX
    position = dg_get(w, D_DATABASE) + used
    dg_put(w, D_POOL_USED, used + size)
    return position

def dg_utf8(s:readbuf, start:u64, size:u64) -> u64:
    at = start
    end = start + size
    count = 0
    while at < end:
        first = byte(s, at)
        width = 0
        value = 0
        minimum = 0
        if first < 128:
            width = 1
            value = first
        elif first >= 194 and first <= 223:
            width = 2
            value = first & 31
            minimum = 128
        elif first >= 224 and first <= 239:
            width = 3
            value = first & 15
            minimum = 2048
        elif first >= 240 and first <= 244:
            width = 4
            value = first & 7
            minimum = 65536
        else:
            return DG_MAX
        if width > end - at:
            return DG_MAX
        offset = 1
        while offset < width:
            unit = byte(s, at + offset)
            if unit < 128 or unit > 191:
                return DG_MAX
            value = (value << 6) | (unit & 63)
            offset = offset + 1
        if value < minimum or value > 1114111:
            return DG_MAX
        if value >= 55296 and value <= 57343:
            return DG_MAX
        count = count + 1
        at = at + width
    return count

def dg_string(s:readbuf, w:mutbuf, identifier:u64, start:u64, size:u64) -> u64:
    chars = dg_utf8(s, start, size)
    if chars == DG_MAX:
        return 0
    position = dg_reserve(w, size)
    if position == DG_MAX:
        return 0
    target = dg_node_zero(w, identifier)
    dg_put(w, target, 4)
    dg_put(w, target + 8, position)
    dg_put(w, target + 16, size)
    dg_put(w, target + 48, chars)
    copy_bytes(w, s, dg_get(w, D_GRAPH) + position, start, size)
    return 1

def dg_integer(r:readbuf, w:mutbuf, identifier:u64, start:u64, size:u64) -> u64:
    end = start + size
    at = start
    negative = 0
    if byte(r, at) == 45:
        negative = 1
        at = at + 1
    if at == end:
        return 0
    digits = end - at
    first = byte(r, at)
    if first < 48 or first > 57:
        return 0
    if first == 48 and digits != 1:
        return 0
    check = at
    while check < end:
        unit = byte(r, check)
        if unit < 48 or unit > 57:
            return 0
        check = check + 1
    dg_put(w, D_ACTUAL_DIGITS, digits)
    maximum = dg_get(w, 176)
    if maximum != 0 and digits > maximum:
        dg_digit_error(w, maximum, digits)
        return 0
    before = dg_get(w, D_POOL_USED)
    bound = ((size + 1) >> 1) + 3
    position = dg_reserve(w, bound)
    if position == DG_MAX:
        return 0
    buffer = dg_get(w, D_GRAPH) + position
    limbs = 0
    while at < end:
        count = 0
        multiplier = 1
        carry = 0
        while count < 9 and at < end:
            carry = carry * 10 + byte(r, at) - 48
            multiplier = multiplier * 10
            count = count + 1
            at = at + 1
        index = 0
        while index < limbs:
            value = dg_limb(w, buffer + index * 4) * multiplier + carry
            dg_store_limb(w, buffer + index * 4, value & 4294967295)
            carry = value >> 32
            index = index + 1
        if carry != 0:
            if limbs * 4 + 4 > bound:
                return 0
            dg_store_limb(w, buffer + limbs * 4, carry)
            limbs = limbs + 1
    extent = limbs * 4
    while extent != 0 and byte(w, buffer + extent - 1) == 0:
        extent = extent - 1
    dg_put(w, D_POOL_USED, before + extent)
    target = dg_node_zero(w, identifier)
    dg_put(w, target, 2)
    dg_put(w, target + 8, position)
    dg_put(w, target + 16, extent)
    if extent != 0:
        dg_put(w, target + 48, negative)
    return 1

def dg_limb(w:mutbuf, at:u64) -> u64:
    return byte(w, at) | (byte(w, at + 1) << 8) | (byte(w, at + 2) << 16) | (byte(w, at + 3) << 24)

def dg_store_limb(w:mutbuf, at:u64, value:u64) -> u64:
    store(w, at, value & 255)
    store(w, at + 1, (value >> 8) & 255)
    store(w, at + 2, (value >> 16) & 255)
    store(w, at + 3, (value >> 24) & 255)
    return value

def dg_container(s:readbuf, w:mutbuf, node:u64) -> u64:
    at = 64 + node * 56
    kind = dg_word(s, at)
    count = dg_word(s, at + 32)
    edge = dg_get(w, dg_get(w, D_EDGEMAP) + node * 8)
    graph = dg_get(w, D_GRAPH)
    edges = graph + 64 + (dg_get(w, D_NODES) + dg_get(w, D_KEYS)) * 64
    target = dg_node_zero(w, node + 1)
    dg_put(w, target, kind)
    dg_put(w, target + 24, edge)
    dg_put(w, target + 32, count)
    dg_put(w, target + 40, node + 1)
    child = dg_word(s, at + 24)
    index = 0
    while index < count:
        if kind == 6:
            record = 64 + child * 56
            key = dg_get(w, dg_get(w, D_KEYMAP) + child * 8)
            if dg_string(s, w, key, dg_word(s, record + 40), dg_word(s, record + 48)) == 0:
                return 0
            dg_put(w, edges + edge * 8, key)
            edge = edge + 1
        dg_put(w, edges + edge * 8, child + 1)
        edge = edge + 1
        child = dg_word(s, 64 + child * 56 + 16)
        index = index + 1
    if kind == 6:
        child = dg_word(s, at + 24)
        index = 0
        while index < count:
            record = 64 + child * 56
            if dg_key(s, w, node + 1, dg_word(s, record + 40), dg_word(s, record + 48)) == 0:
                return 0
            child = dg_word(s, record + 16)
            index = index + 1
    return 1

def dg_key(s:readbuf, w:mutbuf, parent:u64, start:u64, size:u64) -> u64:
    hash = 14695981039346656037 ^ parent
    at = start
    end = start + size
    while at < end:
        hash = (hash ^ byte(s, at)) * 1099511628211
        at = at + 1
    slot = hash & dg_get(w, D_MASK)
    scanned = 0
    while scanned <= dg_get(w, D_MASK):
        record = dg_get(w, D_HASH) + slot * 32
        owner = dg_get(w, record)
        if owner == 0:
            dg_put(w, record, parent)
            dg_put(w, record + 8, start)
            dg_put(w, record + 16, size)
            dg_put(w, record + 24, hash)
            return 1
        if owner == parent and dg_get(w, record + 16) == size and dg_get(w, record + 24) == hash:
            other = dg_get(w, record + 8)
            equal = 1
            at = 0
            while at < size:
                if byte(s, start + at) != byte(s, other + at):
                    equal = 0
                at = at + 1
            if equal != 0:
                return 0
        slot = (slot + 1) & dg_get(w, D_MASK)
        scanned = scanned + 1
    return 0

def dg_binary_reply(s:readbuf, r:readbuf, w:mutbuf) -> u64:
    if dg_get(w, DG_RESPONSE) != DG_REPLY:
        return dg_refuse(w, 20)
    if dg_get(w, 264) != dg_get(w, 136) or dg_get(w, 272) != dg_get(w, 144):
        return dg_refuse(w, 21)
    if dg_get(w, 280) != dg_get(w, D_SEQ) or dg_get(w, 304) != dg_get(w, D_PENDING_NODE) + 1:
        return dg_refuse(w, 22)
    if dg_get(w, 312) != 0:
        return dg_refuse(w, 23)
    status = dg_get(w, 288)
    extent = dg_get(w, 296)
    if status > 4294967295:
        return dg_refuse(w, 24)
    dg_put(w, D_BINARY_STATUS, status)
    if status == 8:
        if extent != 8:
            return dg_refuse(w, 25)
        bits = dg_get(w, DG_RESPONSE_VALUE)
        if ((bits >> 52) & 2047) == 2047:
            return dg_refuse(w, 26)
        position = dg_reserve(w, 8)
        if position == DG_MAX:
            return dg_refuse(w, 27)
        target = dg_node_zero(w, dg_get(w, D_PENDING_NODE) + 1)
        dg_put(w, target, 3)
        dg_put(w, target + 8, position)
        dg_put(w, target + 16, 8)
        dg_put(w, dg_get(w, D_GRAPH) + position, bits)
        dg_put(w, D_SP, dg_get(w, D_SP) - 1)
        dg_put(w, D_PHASE, 30)
        return 0
    if extent != 0:
        return dg_refuse(w, 28)
    if status == 4294967292:
        dg_float_error(w, 2)
    elif status == 4294967295:
        dg_float_error(w, 3)
    else:
        dg_float_error(w, 4)
    dg_put(w, D_PHASE, 91)
    return dg_event(w, 3)

def dg_divide_ten(value:u64) -> u64:
    quotient = 0
    remainder = 0
    bit = 64
    while bit != 0:
        bit = bit - 1
        remainder = (remainder << 1) | ((value >> bit) & 1)
        if remainder >= 10:
            remainder = remainder - 10
            quotient = quotient | (1 << bit)
    return quotient

def dg_text_decimal(w:mutbuf, value:u64) -> u64:
    count = 0
    while value >= 10:
        divided = dg_divide_ten(value)
        store(w, DG_DECIMAL + count, 48 + value - divided * 10)
        value = divided
        count = count + 1
    store(w, DG_DECIMAL + count, 48 + value)
    count = count + 1
    while count != 0:
        count = count - 1
        position = dg_get(w, D_TEXT_SIZE)
        store(w, DG_TEXT + position, byte(w, DG_DECIMAL + count))
        dg_put(w, D_TEXT_SIZE, position + 1)
    return 0

def dg_digit_error(w:mutbuf, maximum:u64, actual:u64) -> u64:
    dg_put(w, D_ERROR, 1)
    dg_put(w, D_TEXT_SIZE, 0)
    dg_literal_digit_prefix(w)
    dg_text_decimal(w, maximum)
    dg_literal_digit_middle(w)
    dg_text_decimal(w, actual)
    dg_literal_digit_suffix(w)
    return 0

def dg_float_error(w:mutbuf, kind:u64) -> u64:
    dg_put(w, D_ERROR, kind)
    dg_put(w, D_TEXT_SIZE, 0)
    if kind == 2:
        dg_literal_nonfinite(w)
    elif kind == 3:
        dg_literal_syntax(w)
    else:
        dg_literal_converter(w)
    return 0
'''
LITERALS={
 'digit_prefix':b'Exceeds the limit (',
 'digit_middle':b' digits) for integer string conversion: value has ',
 'digit_suffix':b' digits; use sys.set_int_max_str_digits() to increase the limit',
 'nonfinite':b'nonfinite JSON number',
 'syntax':b'invalid JSON number syntax',
 'converter':b'native decimal conversion private profile refused',
}
