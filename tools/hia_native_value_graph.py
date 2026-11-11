"""Ordinary HIA emitters for the generic native object transport.

Users provide append_byte/emit and their private S/O_BYTES constants. These
functions encode complete logical values, source-node references and array
concatenations. They contain no language or instruction policy.
"""

BODY = r'''
def graph_word(o:mutbuf, w:mutbuf, value:u64) -> u64:
    at = get(w, S + 24)
    if at > O_BYTES or O_BYTES - at < 8:
        put(w, S + 32, 1)
        return 0
    put(o, at, value)
    put(w, S + 24, at + 8)
    return 0

def graph_begin(o:mutbuf, w:mutbuf, kind:u64, count:u64) -> u64:
    at = get(w, S + 24)
    graph_word(o, w, kind)
    graph_word(o, w, 0)
    graph_word(o, w, count)
    return at

def graph_end(o:mutbuf, w:mutbuf, at:u64) -> u64:
    if get(w, S + 32) != 0:
        return 0
    put(o, at + 8, get(w, S + 24) - at - 16)
    return 0

def graph_string(o:mutbuf, w:mutbuf, n:u64, a:u64, b:u64, c:u64) -> u64:
    graph_word(o, w, 4)
    graph_word(o, w, n)
    emit(o, w, n, a, b, c)
    return 0

def graph_null(o:mutbuf, w:mutbuf) -> u64:
    graph_word(o, w, 0)
    graph_word(o, w, 0)
    return 0

def graph_ref(o:mutbuf, w:mutbuf, original:u64) -> u64:
    graph_word(o, w, 8)
    graph_word(o, w, 8)
    graph_word(o, w, original)
    return 0

def graph_concat(o:mutbuf, w:mutbuf, originals:u64, count:u64) -> u64:
    graph_word(o, w, 9)
    graph_word(o, w, 8 + count * 8)
    graph_word(o, w, count)
    i = 0
    while i < count:
        graph_word(o, w, get(w, originals + i * 8))
        i = i + 1
    return 0
'''

# Opt-in extension: keeping BODY byte-for-byte stable also preserves every
# existing checked generator's function inventory and compiled image.
EXTERNAL_BODY = r'''
def graph_external_ref(o:mutbuf, w:mutbuf, identifier:u64) -> u64:
    graph_word(o, w, 10)
    graph_word(o, w, 8)
    graph_word(o, w, identifier)
    return 0

def graph_external_concat(o:mutbuf, w:mutbuf, identifiers:u64, count:u64) -> u64:
    graph_word(o, w, 11)
    graph_word(o, w, 8 + count * 8)
    graph_word(o, w, count)
    i = 0
    while i < count:
        graph_word(o, w, get(w, identifiers + i * 8))
        i = i + 1
    return 0
'''

# Opt-in encodings for owners that preserve a later foreign serialization
# boundary. Existing BODY/EXTERNAL_BODY remain byte-for-byte unchanged.
# BINARY_BODY uses the shared big_* arithmetic representation; append_byte is
# the caller's ordinary checked byte writer at S+24.
BINARY_BODY = r'''
def graph_binary_integer(o:mutbuf, w:mutbuf, value:u64) -> u64:
    count = big_byte_length(w, value)
    graph_word(o, w, 12)
    graph_word(o, w, count + 1)
    append_byte(o, w, get(w, value))
    index = 0
    while index < count:
        append_byte(o, w, big_byte(w, value, index))
        index = index + 1
    return 0

def graph_object(o:mutbuf, w:mutbuf, identifier:u64) -> u64:
    graph_word(o, w, 13)
    graph_word(o, w, 8)
    graph_word(o, w, identifier)
    return 0
'''
