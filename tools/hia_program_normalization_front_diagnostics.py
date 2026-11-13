"""Author native diagnostic facts for the original public JSON input boundary.

Development candidate only. Policy and failure order stay in these HIA bodies;
foreign code may reproduce a native-proved scalar diagnostic, never parse or
serialize the complete input graph. The existing generic preflight is retained.
The main loop is a mechanical derivative of e03 preflight (blob 73d0b3b...),
with a distinct reason receipt and a detailed, otherwise identical string scan.
"""

SOURCE = r'''
def cj_preflight(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) > 8388608 or length(w) < 128:
        return 19
    maximum = get(w, 48)
    maximum_depth = get(w, 56)
    if maximum < 1 or maximum > 1048576 or maximum_depth > 128:
        return 19
    if length(w) < 128 + (maximum_depth + 1) * 32:
        return 19
    # Even before a missing value is found, every inserted key consumed at
    # least four wire bytes, except the one currently waiting for its value.
    key_bound = choose(maximum < (length(s) >> 2) + 1, maximum, (length(s) >> 2) + 1)
    slots = 2
    while slots < key_bound * 2:
        slots = slots * 2
    if length(o) < slots * 8:
        return 19
    clear = 0
    while clear < slots * 8:
        put(o, clear, 0)
        clear = clear + 8
    put(w, 0, 0)
    nodes = 0
    depth = 0
    want_value = True
    done = False
    while True:
        index = whitespace(s, get(w, 0))
        put(w, 0, index)
        if done:
            if index == length(s):
                put(w, 64, nodes)
                return 0
            return 3
        if want_value:
            if index >= length(s):
                return 4
            nodes = nodes + 1
            if nodes > maximum or depth > maximum_depth:
                return 2
            ch = byte(s, index)
            if ch == 91 or ch == 123:
                slot = 128 + depth * 32
                put(w, slot, choose(ch == 91, 1, 2))
                put(w, slot + 8, 0)
                put(w, slot + 16, index + 1)
                depth = depth + 1
                put(w, 0, index + 1)
            else:
                if ch == 34:
                    result = cj_string(s, w)
                    if result != 0:
                        return result
                else:
                    result = atom(s, index)
                    if result == 4294967295:
                        return 5
                    put(w, 0, result)
                if depth == 0:
                    done = True
                else:
                    put(w, 128 + (depth - 1) * 32 + 8, 5)
            want_value = False
        else:
            if depth == 0:
                return 19
            slot = 128 + (depth - 1) * 32
            kind = get(w, slot)
            state = get(w, slot + 8)
            ch = 256
            if index < length(s):
                ch = byte(s, index)
            closing = False
            if kind == 1:
                if state == 0 or state == 1:
                    if state == 0 and ch == 93:
                        closing = True
                    else:
                        put(w, slot + 8, 4)
                        want_value = True
                else:
                    if state != 5:
                        return 19
                    if ch == 44:
                        put(w, 0, index + 1)
                        put(w, slot + 8, 1)
                    else:
                        if ch == 93:
                            closing = True
                        else:
                            return 6
            else:
                if state == 0 or state == 1:
                    if state == 0 and ch == 125:
                        closing = True
                    else:
                        if ch != 34:
                            return 7
                        result = cj_string(s, w)
                        if result != 0:
                            return result
                        result = insert_key(s, o, w, slots, get(w, slot + 16), index + 1)
                        if result == 4:
                            return 10
                        if result != 0:
                            return 19
                        put(w, slot + 8, 2)
                else:
                    if state == 2:
                        if ch != 58:
                            return 8
                        put(w, 0, index + 1)
                        put(w, slot + 8, 3)
                    else:
                        if state == 3:
                            put(w, slot + 8, 4)
                            want_value = True
                        else:
                            if state != 5:
                                return 19
                            if ch == 44:
                                put(w, 0, index + 1)
                                put(w, slot + 8, 1)
                            else:
                                if ch == 125:
                                    closing = True
                                else:
                                    return 9
            if closing:
                put(w, 0, index + 1)
                depth = depth - 1
                if depth == 0:
                    done = True
                else:
                    put(w, 128 + (depth - 1) * 32 + 8, 5)
    return 19

def cj_string(s:readbuf, w:mutbuf) -> u64:
    index = get(w, 0)
    if index >= length(s) or byte(s, index) != 34:
        return 11
    index = index + 1
    hash = 14695981039346656037
    while index < length(s):
        ch = byte(s, index)
        if ch == 34:
            put(w, 0, index + 1)
            put(w, 40, hash)
            return 0
        if ch < 32:
            return 12
        if ch == 92:
            at = index + 1
            if at >= length(s):
                return 13
            esc = byte(s, at)
            simple = esc == 34 or esc == 92 or esc == 47 or esc == 98 or esc == 102 or esc == 110 or esc == 114 or esc == 116
            if simple == False:
                if esc != 117:
                    return 14
                # The original scanner checks four remaining Unicode
                # characters before asking whether those characters are hex.
                # Whole-input UTF-8 was already admitted. Count only these
                # four raw codepoint starts, including any closing quote or
                # later text; do not use byte length or stop at token end.
                if cj_four_characters(s, at + 1) == 0:
                    return 14
                point = hex4(s, at + 1)
                if point == 4294967295:
                    return 15
                at = at + 5
                if point >= 55296 and point <= 56319:
                    if length(s) - at < 6:
                        return 16
                    if byte(s, at) != 92 or byte(s, at + 1) != 117:
                        return 16
                    low = hex4(s, at + 2)
                    if low < 56320 or low > 57343:
                        return 16
                else:
                    if point >= 56320 and point <= 57343:
                        return 17
        unit = decoded(s, index)
        point = unit & 4294967295
        if point >= 1114112:
            return 19
        hash = (hash ^ point) * 1099511628211
        index = unit >> 32
    return 18

def cj_error(w:mutbuf, status:u64, reason:u64, at:u64, size:u64, digits:u64, input_size:u64) -> u32:
    put(w, 0, DIAGNOSTIC_REPLY_MAGIC)
    put(w, 8, status)
    put(w, 16, digits)
    put(w, 24, input_size)
    put(w, 32, reason)
    put(w, 40, at)
    put(w, 48, size)
    put(w, 56, 1)
    return status

def cj_integer_error(s:readbuf, w:mutbuf, count:u64, digits:u64) -> u32:
    node = 0
    while node < count:
        record = 64 + node * 56
        if get(w, record) == 3:
            at = get(w, record + 24)
            size = get(w, record + 32)
            if at > length(s) or size == 0 or size > length(s) - at:
                return BAD_INTERNAL
            decimal_digits = size
            if byte(s, at) == 45:
                decimal_digits = decimal_digits - 1
            if digits != 0 and decimal_digits > digits:
                return cj_error(w, BAD_INTEGER, 20, at, size, digits, length(s))
        node = node + 1
    return BAD_INTERNAL

def cj_four_characters(s:readbuf, index:u64) -> u64:
    count = 0
    while count < 4:
        if index >= length(s):
            return 0
        first = byte(s, index)
        size = 1
        if first >= 128:
            if first < 224:
                size = 2
            else:
                if first < 240:
                    size = 3
                else:
                    size = 4
        if size > length(s) - index:
            return 0
        index = index + size
        count = count + 1
    return 1

'''
