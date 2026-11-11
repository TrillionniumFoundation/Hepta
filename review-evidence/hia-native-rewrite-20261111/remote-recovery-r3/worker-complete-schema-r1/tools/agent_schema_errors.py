"""Full native error publication and catch unwinding for the schema owner.

Schema text is label + ': ' + original reason. Wire text retains E_HIA_EDIT.
A caught schema exception is rendered before its frame is unwound; foreign wire
errors are never consumed by matches(). Output growth does not repeat a peer.
"""
SCHEMA_REASONS={
1:'not allowed',2:'expected ',3:'constant differs',4:'not in the declared choices',
5:'does not match oneOf',6:'does not match anyOf',7:'forbidden shape',
8:'missing fields ',9:'unknown field ',10:'object field count is outside limits',
11:'array length is outside limits',12:'duplicate array item',
13:'array does not contain the required item',14:'string length is outside limits',
15:'string does not match the declared pattern',16:'number is outside limits'}
WIRE_REASONS={
1:'invalid JSON output byte budget',2:'JSON string exceeds byte budget before encoding',
3:'unpaired Unicode surrogate in UTF-8 JSON',4:'JSON input exceeds nesting depth before encoding',
5:'JSON input exceeds node/byte budget',6:'JSON container exceeds queued-node/byte budget',
7:'cyclic JSON container',8:'unsupported JSON object key',9:'JSON key exceeds numeric byte budget',
10:'nonfinite JSON object key',11:'JSON key exceeds byte budget',
12:'JSON object key collision after JSON conversion',13:'JSON integer exceeds byte budget',
14:'non-JSON in-process value',15:'invalid bounded JSON',16:'JSON encoding exceeds byte budget'}
TEXTS={**{300+k:v for k,v in SCHEMA_REASONS.items()},400:'arguments',
       **{500+k:'E_HIA_EDIT: '+v for k,v in WIRE_REASONS.items()},
       601:'unsupported catalog JSON-Schema vocabulary'}
ERRORS=r'''
def sv_decimal_size(value:u64) -> u64:
    size = 1
    while value >= 10:
        value = value / 10
        size = size + 1
    return size

def sv_write_decimal(w:mutbuf, start:u64, value:u64) -> u64:
    size = sv_decimal_size(value)
    index = size
    while index != 0:
        index = index - 1
        store(w, start + index, 48 + (value % 10))
        value = value / 10
    return size

def sv_add_size(w:mutbuf, first:u64, second:u64) -> u64:
    if second > SV_MAX - first:
        return sv_badset(w, 130)
    return first + second

def sv_literal(w:mutbuf, start:u64, identifier:u64) -> u64:
    size = sv_text_size(identifier)
    index = 0
    while index < size:
        word = sv_text_word(identifier, index >> 3)
        remaining = size - index
        if remaining >= 8:
            sv_put(w, start + index, word)
            index = index + 8
        else:
            part = 0
            while part < remaining:
                store(w, start + index + part, (word >> (part * 8)) & 255)
                part = part + 1
            index = size
    return size

def sv_graph_text_size(g:readbuf, w:mutbuf, identifier:u64) -> u64:
    at = sv_node(g, w, identifier)
    if at == 0:
        return 0
    if sn_word(g, at) != 4:
        return sv_badset(w, 131)
    return sn_word(g, at + 16)

def sv_graph_text(g:readbuf, w:mutbuf, start:u64, identifier:u64) -> u64:
    size = sv_graph_text_size(g, w, identifier)
    if sv_get(w, V_BAD) != 0:
        return 0
    at = sv_node(g, w, identifier)
    copy_bytes(w, g, start, sn_word(g, at + 8), size)
    return size

def sv_label(g:readbuf, w:mutbuf, start:u64, path:u64) -> u64:
    size = sv_get(w, path + 24)
    cursor = path
    while cursor != 0:
        kind = sv_get(w, cursor + 8)
        value = sv_get(w, cursor + 16)
        parent = sv_get(w, cursor)
        if kind == 0:
            sv_graph_text(g, w, start, value)
        elif kind == 3:
            sv_literal(w, start, 400)
        elif kind == 1:
            at = start + sv_get(w, parent + 24)
            store(w, at, 46)
            sv_graph_text(g, w, at + 1, value)
        elif kind == 2:
            at = start + sv_get(w, parent + 24)
            store(w, at, 91)
            count = sv_write_decimal(w, at + 1, value)
            store(w, at + 1 + count, 93)
        else:
            return sv_badset(w, 132)
        cursor = parent
    return size

def sv_missing_size(g:readbuf, w:mutbuf, head:u64) -> u64:
    total = 0
    cursor = head
    first = 1
    while cursor != 0:
        if first == 0:
            total = sv_add_size(w, total, 2)
        size = sv_graph_text_size(g, w, sv_get(w, cursor + 8))
        total = sv_add_size(w, total, size)
        first = 0
        cursor = sv_get(w, cursor)
    return total

def sv_missing_text(g:readbuf, w:mutbuf, start:u64, head:u64) -> u64:
    at = start
    cursor = head
    first = 1
    while cursor != 0:
        if first == 0:
            store(w, at, 44)
            store(w, at + 1, 32)
            at = at + 2
        at = at + sv_graph_text(g, w, at, sv_get(w, cursor + 8))
        first = 0
        cursor = sv_get(w, cursor)
    return at - start

def sv_error_size(g:readbuf, w:mutbuf) -> u64:
    domain = sv_get(w, V_ERROR_DOMAIN)
    reason = sv_get(w, V_ERROR_REASON)
    if domain == 2:
        if reason == 0 or reason > 16:
            return sv_badset(w, 133)
        return sv_text_size(500 + reason)
    if domain == 3:
        if reason != 1:
            return sv_badset(w, 134)
        return sv_text_size(601)
    if domain != 1 or reason == 0 or reason > 16:
        return sv_badset(w, 135)
    frame = sv_get(w, V_ERROR_FRAME)
    path = sv_get(w, frame + F_PATH)
    size = sv_add_size(w, sv_get(w, path + 24), 2)
    size = sv_add_size(w, size, sv_text_size(300 + reason))
    argument = sv_get(w, V_ERROR_ARG)
    if reason == 2 or reason == 9:
        size = sv_add_size(w, size, sv_graph_text_size(g, w, argument))
    elif reason == 8:
        size = sv_add_size(w, size, sv_missing_size(g, w, argument))
    return size

def sv_error_text(g:readbuf, w:mutbuf, start:u64) -> u64:
    domain = sv_get(w, V_ERROR_DOMAIN)
    reason = sv_get(w, V_ERROR_REASON)
    if domain == 2:
        return sv_literal(w, start, 500 + reason)
    if domain == 3:
        return sv_literal(w, start, 601)
    frame = sv_get(w, V_ERROR_FRAME)
    path = sv_get(w, frame + F_PATH)
    at = start + sv_label(g, w, start, path)
    store(w, at, 58)
    store(w, at + 1, 32)
    at = at + 2
    at = at + sv_literal(w, at, 300 + reason)
    argument = sv_get(w, V_ERROR_ARG)
    if reason == 2 or reason == 9:
        at = at + sv_graph_text(g, w, at, argument)
    elif reason == 8:
        at = at + sv_missing_text(g, w, at, argument)
    return at - start

def sv_step(g:readbuf, r:readbuf, w:mutbuf) -> u64:
    if sv_get(w, V_FLOW) != 80:
        return sv_badset(w, 136)
    if sv_get(w, V_ERROR_FRAME) != sv_get(w, V_FRAME):
        return sv_badset(w, 137)
    size = sv_error_size(g, w)
    if sv_get(w, V_BAD) != 0:
        return 0
    if sv_require(w, size) == 0:
        return 0
    at = sv_alloc(w, size)
    actual = sv_error_text(g, w, at)
    if sv_get(w, V_BAD) != 0:
        return 0
    if actual != size:
        return sv_badset(w, 138)
    sv_put(w, V_ERROR_PTR, at)
    sv_put(w, V_ERROR_BYTES, size)
    sv_clear_response(w)
    return sv_after_error(w)
'''
