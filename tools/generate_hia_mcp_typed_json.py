"""Shared HIA lexer for serde_json 1.0.151 IgnoredAny values.

IGNORED_VALUE is an authoring string. It expects byte/store/getn,
hex_digit_value and NONE helpers supplied by its policy. ignored_value(w,
start,end,stack_start,stack_bytes) returns the first byte after one complete
value, or NONE. Unknown strings consume JSON escapes without validating UTF-8
or surrogate pairing, exactly as serde's ignore_str; known fields and root
keys must still pass their ordinary strict typed/string decoder. The caller
owns both buffer bounds and the nonoverlapping byte-stack capability.
"""

IGNORED_VALUE=r'''
def ignored_space(w:mutbuf, at:u64, end:u64) -> u64:
    while at < end:
        value = byte(w, at)
        if value != 32 and value != 9 and value != 10 and value != 13:
            return at
        at = at + 1
    return at

def ignored_string(w:mutbuf, at:u64, end:u64) -> u64:
    if at >= end or byte(w, at) != 34:
        return NONE
    at = at + 1
    while at < end:
        value = byte(w, at)
        at = at + 1
        if value == 34:
            return at
        if value < 32:
            return NONE
        if value == 92:
            if at == end:
                return NONE
            value = byte(w, at)
            at = at + 1
            if value == 117:
                if end - at < 4:
                    return NONE
                count = 0
                while count < 4:
                    if hex_digit_value(byte(w, at + count)) == NONE:
                        return NONE
                    count = count + 1
                at = at + 4
            elif value != 34 and value != 92 and value != 47 and value != 98 and value != 102 and value != 110 and value != 114 and value != 116:
                return NONE
    return NONE

def ignored_atom(w:mutbuf, at:u64, end:u64) -> u64:
    if at >= end:
        return NONE
    value = byte(w, at)
    if value == 110:
        return choose(end - at >= 4 and getn(w, at, 4) == 1819047278, at + 4, NONE)
    if value == 116:
        return choose(end - at >= 4 and getn(w, at, 4) == 1702195828, at + 4, NONE)
    if value == 102:
        return choose(end - at >= 5 and getn(w, at, 5) == 435728179558, at + 5, NONE)
    if value == 45:
        at = at + 1
        if at == end:
            return NONE
        value = byte(w, at)
    if value == 48:
        at = at + 1
        if at < end and byte(w, at) >= 48 and byte(w, at) <= 57:
            return NONE
    elif value >= 49 and value <= 57:
        at = at + 1
        while at < end and byte(w, at) >= 48 and byte(w, at) <= 57:
            at = at + 1
    else:
        return NONE
    if at < end and byte(w, at) == 46:
        at = at + 1
        first = at
        while at < end and byte(w, at) >= 48 and byte(w, at) <= 57:
            at = at + 1
        if first == at:
            return NONE
    if at < end and (byte(w, at) == 101 or byte(w, at) == 69):
        at = at + 1
        if at < end and (byte(w, at) == 43 or byte(w, at) == 45):
            at = at + 1
        first = at
        while at < end and byte(w, at) >= 48 and byte(w, at) <= 57:
            at = at + 1
        if first == at:
            return NONE
    return at

def ignored_value(w:mutbuf, at:u64, end:u64, stack:u64, capacity:u64) -> u64:
    if capacity == 0:
        return NONE
    store(w, stack, 0)
    depth = 1
    while depth != 0:
        state = byte(w, stack + depth - 1)
        if state == 9:
            return at
        at = ignored_space(w, at, end)
        if at == end:
            return NONE
        value = byte(w, at)
        if state == 2 or state == 8:
            if value == 44:
                store(w, stack + depth - 1, choose(state == 2, 3, 5))
                at = at + 1
            elif value == choose(state == 2, 93, 125):
                depth = depth - 1
                at = at + 1
            else:
                return NONE
        elif state == 4 or state == 5:
            if state == 4 and value == 125:
                depth = depth - 1
                at = at + 1
            else:
                at = ignored_string(w, at, end)
                if at == NONE:
                    return NONE
                store(w, stack + depth - 1, 6)
        elif state == 6:
            if value != 58:
                return NONE
            store(w, stack + depth - 1, 7)
            at = at + 1
        elif state == 1 and value == 93:
            depth = depth - 1
            at = at + 1
        else:
            store(w, stack + depth - 1, choose(state == 0, 9, choose(state == 7, 8, 2)))
            if value == 91 or value == 123:
                if depth >= capacity:
                    return NONE
                store(w, stack + depth, choose(value == 91, 1, 4))
                depth = depth + 1
                at = at + 1
            elif value == 34:
                at = ignored_string(w, at, end)
                if at == NONE:
                    return NONE
            else:
                at = ignored_atom(w, at, end)
                if at == NONE:
                    return NONE
    return NONE
'''
