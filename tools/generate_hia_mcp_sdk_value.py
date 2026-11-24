"""Streaming serde Value validation for the native MCP SDK boundary.

This source is composed with the existing canonical Value module. The caller
selects its private validation operation with an output extent of LIMIT + 1;
the normal LIMIT-byte canonicalization operation is unchanged. Validation
retains only the 127-container state stack, so opaque SDK fields do not gain
the smaller retained-arena node limit of the native HIA request gate.
"""

SOURCE = r'''
def sdk_value(s:readbuf, w:mutbuf) -> u32:
    if length(s) > 8388608 or length(w) < 32768:
        return 4294967280
    at = 0
    if length(s) >= 3 and byte(s, 0) == 239 and byte(s, 1) == 187 and byte(s, 2) == 191:
        at = 3
    store(w, 20000, 0)
    depth = 1
    while depth != 0:
        state = byte(w, 20000 + depth - 1)
        at = whitespace(s, at)
        if state == 9:
            return choose(at == length(s), 1, 4294967280)
        if at == length(s):
            return 4294967280
        value = byte(s, at)
        if state == 2 or state == 8:
            if value == 44:
                store(w, 20000 + depth - 1, choose(state == 2, 3, 5))
                at = at + 1
            elif value == choose(state == 2, 93, 125):
                depth = depth - 1
                at = at + 1
            else:
                return 4294967280
        elif state == 4 or state == 5:
            if state == 4 and value == 125:
                depth = depth - 1
                at = at + 1
            else:
                at = sdk_string(s, at)
                if at == 18446744073709551615:
                    return 4294967280
                store(w, 20000 + depth - 1, 6)
        elif state == 6:
            if value != 58:
                return 4294967280
            store(w, 20000 + depth - 1, 7)
            at = at + 1
        elif state == 1 and value == 93:
            depth = depth - 1
            at = at + 1
        else:
            store(w, 20000 + depth - 1, choose(state == 0, 9, choose(state == 7, 8, 2)))
            if value == 91 or value == 123:
                if depth >= 128:
                    return 4294967280
                store(w, 20000 + depth, choose(value == 91, 1, 4))
                depth = depth + 1
                at = at + 1
            elif value == 34:
                at = sdk_string(s, at)
                if at == 18446744073709551615:
                    return 4294967280
            else:
                end = atom(s, at)
                if end == 4294967295:
                    return 4294967280
                if value < 97 and stored_integer(s, at, end - at) == 0:
                    if widen(decimal_convert(s, w, at, end - at)) != 8:
                        return 4294967280
                at = end
    return 4294967280

def sdk_string(s:readbuf, at:u64) -> u64:
    if at >= length(s) or byte(s, at) != 34:
        return 18446744073709551615
    at = at + 1
    while at < length(s):
        unit = decoded(s, at)
        value = unit & 4294967295
        if value == 1114113:
            return 18446744073709551615
        at = unit >> 32
        if value == 1114112:
            return at
    return 18446744073709551615
'''
