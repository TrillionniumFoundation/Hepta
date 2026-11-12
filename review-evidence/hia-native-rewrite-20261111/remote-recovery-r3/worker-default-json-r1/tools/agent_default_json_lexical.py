"""Exact default raw Unicode, regex-number masking and first admission order.

NEW UNEXECUTED. This is the ordinary decode_data path, not the independently
selected Agent-data decoder profile. Complete UTF-8 decoding / strict string
encoding precedes the 8 MiB gate; only fractional/exponent lexemes outside
strings are replaced before the complete integer JSON preflight.
"""
LEXICAL=r'''
def gc_utf8_failure(w:mutbuf, end:u64, reason:u64) -> u64:
    gc_put(w, G_UTF8_END, end)
    gc_put(w, G_UTF8_REASON, reason)
    return 0

def gc_point(s:readbuf, w:mutbuf, at:u64, end:u64, allow_surrogate:u64) -> u64:
    if at >= end or end > length(s):
        return gc_utf8_failure(w, at, 4)
    first = byte(s, at)
    width = 0
    value = 0
    lower = 128
    upper = 191
    if first < 128:
        width = 1
        value = first
    elif first >= 194 and first <= 223:
        width = 2
        value = first & 31
    elif first >= 224 and first <= 239:
        width = 3
        value = first & 15
        if first == 224:
            lower = 160
        elif first == 237 and allow_surrogate == 0:
            upper = 159
    elif first >= 240 and first <= 244:
        width = 4
        value = first & 7
        if first == 240:
            lower = 144
        elif first == 244:
            upper = 143
    else:
        return gc_utf8_failure(w, at + 1, 1)
    offset = 1
    while offset < width:
        if offset >= end - at:
            return gc_utf8_failure(w, end, 3)
        unit = byte(s, at + offset)
        if unit < 128 or unit > 191:
            return gc_utf8_failure(w, at + offset, 2)
        if offset == 1 and (unit < lower or unit > upper):
            return gc_utf8_failure(w, at + offset, 2)
        value = (value << 6) | (unit & 63)
        offset = offset + 1
    gc_put(w, G_UTF8_NEXT, at + width)
    gc_put(w, G_UTF8_VALUE, value)
    gc_put(w, G_UTF8_REASON, 0)
    gc_put(w, G_UTF8_END, at + width)
    return 1

def gc_validate_unicode(s:readbuf, w:mutbuf) -> u64:
    kind = gc_get(w, 168)
    if kind != 4 and kind != 9:
        gc_simple_error(w, 1, 1, 1)
        return 0
    index = 0
    position = 0
    while index < length(s):
        if byte(s, index) < 128:
            begin = index
            while index < length(s) and byte(s, index) < 128:
                index = index + 1
            position = position + index - begin
            gc_put(w, G_UTF8_NEXT, index)
            gc_put(w, G_UTF8_VALUE, byte(s, index - 1))
            gc_put(w, G_UTF8_REASON, 0)
            gc_put(w, G_UTF8_END, index)
        else:
            if gc_point(s, w, index, length(s), choose(kind == 4, 1, 0)) == 0:
                if kind == 4:
                    gc_bad(w, 10)
                    return 0
                gc_put(w, G_ERROR_START, index)
                gc_put(w, G_ERROR_END, gc_get(w, G_UTF8_END))
                gc_put(w, G_ERROR_AUX, byte(s, index))
                gc_decode_error(w, gc_get(w, G_UTF8_REASON))
                return 0
            value = gc_get(w, G_UTF8_VALUE)
            if kind == 4 and value >= 55296 and value <= 57343:
                gc_put(w, G_ERROR_START, position)
                gc_put(w, G_ERROR_AUX, value)
                index = gc_get(w, G_UTF8_NEXT)
                position = position + 1
                scanning = 1
                while scanning != 0 and index < length(s):
                    if gc_point(s, w, index, length(s), 1) == 0:
                        gc_bad(w, 11)
                        return 0
                    value = gc_get(w, G_UTF8_VALUE)
                    if value >= 55296 and value <= 57343:
                        index = gc_get(w, G_UTF8_NEXT)
                        position = position + 1
                    else:
                        scanning = 0
                gc_put(w, G_ERROR_END, position)
                gc_encode_error(w)
                return 0
            index = gc_get(w, G_UTF8_NEXT)
            position = position + 1
    return 1

def gc_digit(unit:u64) -> u64:
    return choose(unit >= 48 and unit <= 57, 1, 0)

def gc_number(s:readbuf, w:mutbuf, start:u64) -> u64:
    size = length(s)
    cursor = start
    gc_put(w, G_TOKEN_FLOAT, 0)
    gc_put(w, G_TOKEN_DIGITS, 0)
    gc_put(w, G_TOKEN_END, start)
    if cursor >= size:
        return start
    if byte(s, cursor) == 45:
        cursor = cursor + 1
    if cursor >= size or gc_digit(byte(s, cursor)) == 0:
        return start
    integer_start = cursor
    if byte(s, cursor) == 48:
        cursor = cursor + 1
    else:
        while cursor < size and gc_digit(byte(s, cursor)) != 0:
            cursor = cursor + 1
    gc_put(w, G_TOKEN_DIGITS, cursor - integer_start)
    scan = cursor
    begin = cursor
    if cursor < size and byte(s, cursor) == 46:
        scan = cursor + 1
        begin = scan
        while scan < size and gc_digit(byte(s, scan)) != 0:
            scan = scan + 1
        if scan != begin:
            cursor = scan
            gc_put(w, G_TOKEN_FLOAT, 1)
    if cursor < size and (byte(s, cursor) == 69 or byte(s, cursor) == 101):
        scan = cursor + 1
        if scan < size and (byte(s, scan) == 43 or byte(s, scan) == 45):
            scan = scan + 1
        begin = scan
        while scan < size and gc_digit(byte(s, scan)) != 0:
            scan = scan + 1
        if scan != begin:
            cursor = scan
            gc_put(w, G_TOKEN_FLOAT, 1)
    gc_put(w, G_TOKEN_END, cursor)
    return cursor

def gc_mask(s:readbuf, w:mutbuf) -> u64:
    index = 0
    previous = 0
    output = 0
    while index < length(s):
        unit = byte(s, index)
        if unit == 34:
            index = index + 1
            scanning = 1
            while scanning != 0 and index < length(s):
                unit = byte(s, index)
                if unit == 92:
                    index = index + choose(length(s) - index >= 2, 2, 1)
                elif unit == 34:
                    index = index + 1
                    scanning = 0
                else:
                    index = index + 1
        elif unit == 45 or gc_digit(unit) != 0:
            end = gc_number(s, w, index)
            if end == index:
                index = index + 1
            else:
                if gc_get(w, G_TOKEN_FLOAT) != 0:
                    copy_bytes(w, s, GC_MASK + output, previous, index - previous)
                    output = output + index - previous
                    store(w, GC_MASK + output, 48)
                    output = output + 1
                    previous = end
                index = end
        else:
            index = index + 1
    copy_bytes(w, s, GC_MASK + output, previous, length(s) - previous)
    output = output + length(s) - previous
    if output > length(s):
        return gc_bad(w, 12)
    gc_put(w, G_MASK_BYTES, output)
    return 0

def gc_key_capacity(size:u64) -> u64:
    bound = (size >> 2) + 1
    if bound > 262144:
        bound = 262144
    slots = 2
    while slots < bound * 2:
        slots = slots << 1
    return slots * 8

def gc_begin_preflight(w:mutbuf) -> u64:
    fill_range(w, GC_PEER_CONFIG, 128, 0)
    gc_put(w, GC_PEER_CONFIG + 48, 262144)
    gc_put(w, GC_PEER_CONFIG + 56, 128)
    gc_put(w, G_INPUT_OWNER, 1)
    gc_put(w, G_INPUT_AT, GC_MASK)
    gc_put(w, G_INPUT_SIZE, gc_get(w, G_MASK_BYTES))
    gc_put(w, G_OUTPUT_CAP, gc_key_capacity(gc_get(w, G_MASK_BYTES)))
    gc_put(w, G_WORK_CAP, 4256)
    gc_put(w, G_CONFIG_AT, GC_PEER_CONFIG)
    gc_put(w, G_CONFIG_SIZE, 128)
    return gc_request(w, 1, 20)

def gc_step(s:readbuf, r:readbuf, w:mutbuf) -> u64:
    if length(r) != 0:
        return gc_bad(w, 13)
    if gc_get(w, G_PHASE) == 1:
        if gc_validate_unicode(s, w) == 0:
            if gc_get(w, G_PHASE) == 91:
                return 3
            return gc_bad(w, 14)
        if length(s) > 8388608:
            return gc_simple_error(w, 1, 2, 2)
        gc_put(w, G_NEED, GC_MASK + length(s))
        gc_put(w, G_PHASE, 10)
    if gc_get(w, G_PHASE) != 10:
        return gc_bad(w, 15)
    if length(w) < gc_get(w, G_NEED):
        return 1
    if gc_mask(s, w) != 0:
        return 4
    return gc_begin_preflight(w)
'''
