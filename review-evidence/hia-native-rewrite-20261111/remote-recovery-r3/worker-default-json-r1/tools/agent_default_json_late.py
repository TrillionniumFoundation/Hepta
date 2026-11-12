"""Default original-JSON callback order after a successful masked preflight.

The original raw decoder may discover a later syntax error before Python's
source-order parse_float/parse_int callback would run. This HIA parser is used
only for that exact raw-syntax branch. It consumes the original source once and
calls the actual binary64 peer at each reached float; it stops at the first
ordinary callback or syntax error. It constructs no host object or extra tree.
"""
LATE=r'''
def gc_space(s:readbuf, start:u64) -> u64:
    at = start
    while at < length(s):
        value = byte(s, at)
        if value != 32 and value != 9 and value != 10 and value != 13:
            return at
        at = at + 1
    return at

def gc_finish_value(w:mutbuf) -> u64:
    depth = gc_get(w, G_DEPTH)
    if depth == 0:
        if gc_get(w, G_ROOT_DONE) != 0:
            return gc_bad(w, 60)
        gc_put(w, G_ROOT_DONE, 1)
        return 0
    at = GC_STACK + (depth - 1) * 16
    kind = gc_get(w, at)
    state = gc_get(w, at + 8)
    if kind == 5:
        if state > 1:
            return gc_bad(w, 61)
        gc_put(w, at + 8, 2)
    elif kind == 6:
        if state != 3:
            return gc_bad(w, 62)
        gc_put(w, at + 8, 4)
    else:
        return gc_bad(w, 63)
    return 0

def gc_open_container(w:mutbuf, kind:u64) -> u64:
    depth = gc_get(w, G_DEPTH)
    if depth >= 129:
        return gc_bad(w, 64)
    at = GC_STACK + depth * 16
    gc_put(w, at, kind)
    gc_put(w, at + 8, 0)
    gc_put(w, G_DEPTH, depth + 1)
    gc_put(w, G_CURSOR, gc_get(w, G_CURSOR) + 1)
    return 0

def gc_close_container(w:mutbuf) -> u64:
    depth = gc_get(w, G_DEPTH)
    if depth == 0:
        return gc_bad(w, 65)
    gc_put(w, G_DEPTH, depth - 1)
    gc_put(w, G_CURSOR, gc_get(w, G_CURSOR) + 1)
    return gc_finish_value(w)

def gc_late_string(s:readbuf, w:mutbuf) -> u64:
    cursor = gc_get(w, G_CURSOR)
    if cursor >= length(s) or byte(s, cursor) != 34:
        return gc_bad(w, 66)
    cursor = cursor + 1
    while cursor < length(s):
        unit = byte(s, cursor)
        if unit == 34:
            gc_put(w, G_CURSOR, cursor + 1)
            return 0
        if unit == 92:
            if length(s) - cursor < 2:
                return gc_bad(w, 67)
            cursor = cursor + 2
        else:
            cursor = cursor + 1
    return gc_bad(w, 68)

def gc_late_literal(s:readbuf, w:mutbuf) -> u64:
    at = gc_get(w, G_CURSOR)
    count = 0
    if length(s) - at >= 4:
        if byte(s, at) == 110 and byte(s, at + 1) == 117 and byte(s, at + 2) == 108 and byte(s, at + 3) == 108:
            count = 4
        elif byte(s, at) == 116 and byte(s, at + 1) == 114 and byte(s, at + 2) == 117 and byte(s, at + 3) == 101:
            count = 4
    if count == 0 and length(s) - at >= 5:
        if byte(s, at) == 102 and byte(s, at + 1) == 97 and byte(s, at + 2) == 108 and byte(s, at + 3) == 115 and byte(s, at + 4) == 101:
            count = 5
    if count == 0:
        return gc_json_error(s, w, 41, at)
    gc_put(w, G_CURSOR, at + count)
    return gc_finish_value(w)

def gc_late_number(s:readbuf, w:mutbuf) -> u64:
    start = gc_get(w, G_CURSOR)
    end = gc_number(s, w, start)
    if end == start:
        return gc_json_error(s, w, 41, start)
    gc_put(w, G_CURSOR, end)
    if gc_get(w, G_TOKEN_FLOAT) == 0:
        maximum = gc_get(w, 176)
        actual = gc_get(w, G_TOKEN_DIGITS)
        if maximum != 0 and actual > maximum:
            return gc_digit_error(w, maximum, actual)
        gc_put(w, G_NUMBER_COUNT, gc_get(w, G_NUMBER_COUNT) + 1)
        return gc_finish_value(w)
    gc_put(w, G_NUMBER_START, start)
    gc_put(w, G_NUMBER_SIZE, end - start)
    gc_put(w, G_BINARY_ATTEMPTS, gc_get(w, G_BINARY_ATTEMPTS) + 1)
    gc_put(w, G_INPUT_OWNER, 0)
    gc_put(w, G_INPUT_AT, start)
    gc_put(w, G_INPUT_SIZE, end - start)
    gc_put(w, G_OUTPUT_CAP, 8)
    gc_put(w, G_WORK_CAP, 4096)
    gc_put(w, G_CONFIG_AT, 0)
    gc_put(w, G_CONFIG_SIZE, 0)
    return gc_request(w, 4, 51)

def gc_late_value(s:readbuf, w:mutbuf) -> u64:
    at = gc_get(w, G_CURSOR)
    if at >= length(s):
        return gc_json_error(s, w, 41, at)
    unit = byte(s, at)
    if unit == 91:
        return gc_open_container(w, 5)
    if unit == 123:
        return gc_open_container(w, 6)
    if unit == 34:
        result = gc_late_string(s, w)
        if result != 0:
            return result
        return gc_finish_value(w)
    if unit == 45 or gc_digit(unit) != 0:
        return gc_late_number(s, w)
    return gc_late_literal(s, w)

def gc_late_array(s:readbuf, w:mutbuf, frame:u64, state:u64) -> u64:
    at = gc_get(w, G_CURSOR)
    if state == 0 and at < length(s) and byte(s, at) == 93:
        return gc_close_container(w)
    if state < 2:
        return gc_late_value(s, w)
    if state != 2:
        return gc_bad(w, 69)
    if at < length(s):
        unit = byte(s, at)
        if unit == 93:
            return gc_close_container(w)
        if unit == 44:
            gc_put(w, frame + 8, 1)
            gc_put(w, G_CURSOR, at + 1)
            return 0
    return gc_json_error(s, w, 42, at)

def gc_late_object(s:readbuf, w:mutbuf, frame:u64, state:u64) -> u64:
    at = gc_get(w, G_CURSOR)
    if state == 0 or state == 1:
        if state == 0 and at < length(s) and byte(s, at) == 125:
            return gc_close_container(w)
        if at >= length(s) or byte(s, at) != 34:
            return gc_json_error(s, w, 43, at)
        result = gc_late_string(s, w)
        if result != 0:
            return result
        gc_put(w, frame + 8, 2)
        return 0
    if state == 2:
        if at >= length(s) or byte(s, at) != 58:
            return gc_json_error(s, w, 44, at)
        gc_put(w, frame + 8, 3)
        gc_put(w, G_CURSOR, at + 1)
        return 0
    if state == 3:
        return gc_late_value(s, w)
    if state != 4:
        return gc_bad(w, 70)
    if at < length(s):
        unit = byte(s, at)
        if unit == 125:
            return gc_close_container(w)
        if unit == 44:
            gc_put(w, frame + 8, 1)
            gc_put(w, G_CURSOR, at + 1)
            return 0
    return gc_json_error(s, w, 42, at)

def gc_late_binary(r:readbuf, w:mutbuf) -> u64:
    if gc_ack(r, w, 4) == 0:
        return gc_bad(w, 71)
    status = gc_get(w, G_ACTUAL_STATUS)
    gc_put(w, G_PEER, 0)
    gc_put(w, G_PENDING, 0)
    if status == 4294967292:
        if length(r) != 0:
            return gc_bad(w, 72)
        return gc_simple_error(w, 1, 3, 5)
    if status != 8 or length(r) != 8:
        return gc_bad(w, 73)
    if ((gc_word(r, 0) >> 52) & 2047) == 2047:
        return gc_bad(w, 74)
    gc_put(w, G_NUMBER_COUNT, gc_get(w, G_NUMBER_COUNT) + 1)
    gc_put(w, G_PHASE, 50)
    return gc_finish_value(w)

def gc_step(s:readbuf, r:readbuf, w:mutbuf) -> u64:
    if gc_get(w, G_PREFLIGHT_PASSED) != 1 or gc_get(w, G_DECODE_ATTEMPTS) != 1:
        return gc_bad(w, 75)
    if gc_get(w, G_PHASE) == 51:
        result = gc_late_binary(r, w)
        if result != 0:
            return result
    elif gc_get(w, G_PHASE) != 50 or length(r) != 0:
        return gc_bad(w, 76)
    while gc_get(w, G_PHASE) == 50:
        at = gc_space(s, gc_get(w, G_CURSOR))
        gc_put(w, G_CURSOR, at)
        depth = gc_get(w, G_DEPTH)
        if depth == 0:
            if gc_get(w, G_ROOT_DONE) != 0:
                if at < length(s):
                    return gc_json_error(s, w, 40, at)
                return gc_bad(w, 77)
            result = gc_late_value(s, w)
        else:
            frame = GC_STACK + (depth - 1) * 16
            kind = gc_get(w, frame)
            state = gc_get(w, frame + 8)
            if kind == 5:
                result = gc_late_array(s, w, frame, state)
            elif kind == 6:
                result = gc_late_object(s, w, frame, state)
            else:
                return gc_bad(w, 78)
        if result != 0:
            return result
    return gc_bad(w, 79)
'''
