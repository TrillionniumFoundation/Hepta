"""Shared HIA decoding of persisted host job metadata.

NORMALIZE uses the caller's RAW_JSON/NONE constants and getn/copy_bytes helpers.
It preserves the encoded 4 MiB limit while producing at most 8 MiB of UTF-8/WTF-8.
The metadata decoder follows Python json.loads(bytes) syntax and string rules.
"""
from tools.generate_hia_json_decode import source_program as json_source

MAXIMUM_METADATA_DEPTH = ((32 << 20) - 128) // 48 - 1


NORMALIZE = r'''
def normalize_json(w:mutbuf, source:u64, size:u64) -> u64:
    if size > 4194304:
        return NONE
    width = 1
    big = 0
    at = 0
    if size >= 4 and getn(w, source, 4) == 4294836224:
        width = 4
        big = 1
        at = 4
    elif size >= 4 and getn(w, source, 4) == 65279:
        width = 4
        at = 4
    elif size >= 3 and getn(w, source, 3) == 12565487:
        at = 3
    elif size >= 2 and getn(w, source, 2) == 65534:
        width = 2
        big = 1
        at = 2
    elif size >= 2 and getn(w, source, 2) == 65279:
        width = 2
        at = 2
    elif size >= 4:
        if byte(w, source) == 0:
            width = choose(byte(w, source + 1) == 0, 4, 2)
            big = 1
        elif byte(w, source + 1) == 0:
            width = choose(byte(w, source + 2) == 0 and byte(w, source + 3) == 0, 4, 2)
    elif size == 2:
        if byte(w, source) == 0:
            width = 2
            big = 1
        elif byte(w, source + 1) == 0:
            width = 2
    if width == 1:
        copy_bytes(w, RAW_JSON, source + at, size - at)
        return size - at
    if (size - at) % width != 0:
        return NONE
    written = 0
    while at < size:
        cp = encoding_word(w, source + at, width, big)
        at = at + width
        if width == 2 and cp >= 55296 and cp <= 56319 and at + 2 <= size:
            low = encoding_word(w, source + at, 2, big)
            if low >= 56320 and low <= 57343:
                cp = 65536 + (cp - 55296) * 1024 + low - 56320
                at = at + 2
        if cp > 1114111 or written + 4 > 8388608:
            return NONE
        written = put_utf8(w, RAW_JSON + written, cp) - RAW_JSON
    return written

def encoding_word(w:mutbuf, source:u64, width:u64, big:u64) -> u64:
    if big == 0:
        return getn(w, source, width)
    value = 0
    index = 0
    while index < width:
        value = value * 256 + byte(w, source + index)
        index = index + 1
    return value

def put_utf8(w:mutbuf, at:u64, cp:u64) -> u64:
    if cp < 128:
        store(w, at, cp)
        return at + 1
    if cp < 2048:
        store(w, at, 192 | (cp >> 6))
        store(w, at + 1, 128 | (cp & 63))
        return at + 2
    if cp < 65536:
        store(w, at, 224 | (cp >> 12))
        store(w, at + 1, 128 | ((cp >> 6) & 63))
        store(w, at + 2, 128 | (cp & 63))
        return at + 3
    store(w, at, 240 | (cp >> 18))
    store(w, at + 1, 128 | ((cp >> 12) & 63))
    store(w, at + 2, 128 | ((cp >> 6) & 63))
    store(w, at + 3, 128 | (cp & 63))
    return at + 4
'''


def metadata_json_source():
    source = json_source(wire_spans=True)
    source = source.replace('maximum > 1048576', 'maximum > 2097152')
    # The native decoder uses an explicit stack.  CPython's incidental C-stack
    # exhaustion is not a metadata syntax rule; use the fixed 32 MiB workspace.
    source = source.replace('maximum_depth > 128',
                            f'maximum_depth > {MAXIMUM_METADATA_DEPTH}')
    old = 'if same_key(s, item & 4294967295, start) == 1:\n                return 4'
    if source.count(old) != 1:
        raise ValueError('metadata duplicate-key admission point changed')
    source = source.replace(old, old.replace('return 4', 'return 0'))
    old = '''        if cp >= 55296 and cp <= 56319:
            if index + 6 > size:
                return (6 << 32) | 1114113
            if byte(s, index) != 92 or byte(s, index + 1) != 117:
                return (6 << 32) | 1114113
            low = hex4(s, index + 2)
            if low < 56320 or low > 57343:
                return (6 << 32) | 1114113
            cp = 65536 + (cp - 55296) * 1024 + low - 56320
            index = index + 6
        else:
            if cp >= 56320 and cp <= 57343:
                return (7 << 32) | 1114113'''
    new = '''        if cp >= 55296 and cp <= 56319 and index + 6 <= size:
            if byte(s, index) == 92 and byte(s, index + 1) == 117:
                low = hex4(s, index + 2)
                if low >= 56320 and low <= 57343:
                    cp = 65536 + (cp - 55296) * 1024 + low - 56320
                    index = index + 6'''
    if source.count(old) != 1:
        raise ValueError('metadata surrogate admission point changed')
    source = source.replace(old, new)
    old = '''    if cp >= 55296 and cp <= 57343:
        return (20 << 32) | 1114113
'''
    if source.count(old) != 1:
        raise ValueError('metadata surrogatepass decoding point changed')
    source = source.replace(old, '')
    old = '''def atom(s:readbuf, index:u64) -> u64:
    size = length(s)
'''
    new = old + '''    if size - index >= 3:
        if byte(s, index) == 78 and byte(s, index + 1) == 97 and byte(s, index + 2) == 78:
            return index + 3
    first = index
    if byte(s, first) == 45:
        first = first + 1
    if size - first >= 8:
        if byte(s, first) == 73 and byte(s, first + 1) == 110 and byte(s, first + 2) == 102 and byte(s, first + 3) == 105 and byte(s, first + 4) == 110 and byte(s, first + 5) == 105 and byte(s, first + 6) == 116 and byte(s, first + 7) == 121:
            return first + 8
'''
    if source.count(old) != 1:
        raise ValueError('metadata nonfinite admission point changed')
    source = source.replace(old, new)
    old = '''def wire_atom(s:readbuf, index:u64) -> u64:
    end = atom(s, index)
    size = length(s)
    if end >= size or byte(s, index) >= 97:
        return end
    if byte(s, end) == 46:
        fraction = end + 1
        end = digit_end(s, fraction)
        if end == fraction:
            return 4294967295
    if end < size and (byte(s, end) == 101 or byte(s, end) == 69):
        exponent = end + 1
        if exponent < size and (byte(s, exponent) == 43 or byte(s, exponent) == 45):
            exponent = exponent + 1
        end = digit_end(s, exponent)
        if end == exponent:
            return 4294967295
    return end
'''
    new = '''def wire_atom(s:readbuf, index:u64) -> u64:
    end = atom(s, index)
    size = length(s)
    if end == 4294967295:
        return end
    first = index
    if byte(s, first) == 45:
        first = first + 1
    if first >= size:
        return 4294967295
    point = byte(s, first)
    if point < 48 or point > 57:
        return end
    floating = False
    if end < size and byte(s, end) == 46:
        floating = True
        fraction = end + 1
        end = digit_end(s, fraction)
        if end == fraction:
            return 4294967295
    if end < size and (byte(s, end) == 101 or byte(s, end) == 69):
        floating = True
        exponent = end + 1
        if exponent < size and (byte(s, exponent) == 43 or byte(s, exponent) == 45):
            exponent = exponent + 1
        end = digit_end(s, exponent)
        if end == exponent:
            return 4294967295
    if floating == False and end - first > 4300:
        return 4294967295
    return end
'''
    if source.count(old) != 1:
        raise ValueError('metadata integer conversion limit point changed')
    return source.replace(old, new)
