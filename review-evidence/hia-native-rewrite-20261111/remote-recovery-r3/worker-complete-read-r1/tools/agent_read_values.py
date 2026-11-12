"""hia_read's complete integer/slice, UTF-8, base64 and page-value owner.

Only immutable artifact bytes are inspected. UTF-8 is decided on the complete
artifact before decoding the slice; the original negative offset is retained
for the next-cursor arithmetic. No Python codec or numeric conversion is called.
"""
VALUES=r'''
def rd_values(g:readbuf, r:readbuf, w:mutbuf) -> u64:
    phase = rd_get(w, R_PHASE)
    if phase == 20:
        if rd_get(w, R_PEER) != P_ARTIFACT_VIEW:
            return rd_badset(w, 200)
        if rd_get(w, R_REPLY_LEASE) != rd_get(w, R_ARTIFACT_LEASE):
            return rd_badset(w, 201)
        if length(r) != rd_get(w, R_ARTIFACT_SIZE) or rd_get(w, R_REPLY_AT) != 0 or rd_get(w, R_REPLY_SIZE) != length(r):
            return rd_badset(w, 202)
        if rd_limit(g, w) == 0:
            return 0
        kind = rd_get(w, R_OFFSET_KIND)
        if kind == 0:
            return rd_error(w, 2, 21)
        if kind == 3:
            return rd_error(w, 2, 22)
        if kind == 4:
            return rd_error(w, 2, 23)
        if kind == 9:
            return rd_error(w, 2, 24)
        if kind != 2:
            return rd_badset(w, 203)
        n = length(r)
        first = rd_clip(rd_get(w, R_OFFSET_SIGN), rd_get(w, R_OFFSET_MAG), n)
        if rd_sum(w, rd_get(w, R_LIMIT)) == 0:
            return 0
        last = rd_clip(rd_get(w, R_NEXT_SIGN), rd_get(w, R_NEXT_MAG), n)
        size = 0
        if last > first:
            size = last - first
        if size > 65536:
            return rd_badset(w, 204)
        if RD_PAGE + size > length(w):
            rd_put(w, R_NEED, RD_PAGE + size)
            return 0
        rd_put(w, R_SLICE_START, first)
        rd_put(w, R_CHUNK_BYTES, size)
        end = rd_prefix(r, w, 0, n)
        rd_put(w, R_ENCODING, choose(end == n, 0, 1))
        copy_bytes(w, r, RD_PAGE, first, size)
        rd_put(w, R_HAVE_REPLY, 0)
        rd_put(w, R_PHASE, 21)
        return 0
    if phase == 21:
        size = rd_get(w, R_CHUNK_BYTES)
        chars = 0
        encoded = 0
        if rd_get(w, R_ENCODING) == 0:
            end = rd_prefix_work(w, RD_PAGE, size)
            size = end - RD_PAGE
            rd_put(w, R_CHUNK_BYTES, size)
            chars = rd_get(w, R_UTF8_CHARS)
            encoded = size
        else:
            # Exact ceil(size/3)*4 for size <= 65536, using an unsigned
            # multiplication identity whose product is below 2**49.
            encoded = (((size + 2) * 2863311531) >> 33) * 4
            chars = encoded
        rd_put(w, R_CONTENT_BYTES, encoded)
        rd_put(w, R_CONTENT_CHARS, chars)
        if rd_graph_begin(w, 1, 0, encoded) == 0:
            return 0
        if rd_graph_content(w, 1) == 0 or rd_graph_finish(w) == 0:
            return 0
        rd_put(w, R_PHASE, 22)
        return 0
    return rd_badset(w, 205)

def rd_limit(g:readbuf, w:mutbuf) -> u64:
    identifier = rd_get(w, R_MAX_BYTES)
    if identifier == 0:
        rd_put(w, R_LIMIT, 65536)
        return 1
    at = rd_node(g, w, identifier)
    if at == 0:
        return 0
    kind = rd_word(g, at)
    value = 0
    if kind == 2:
        size = rd_word(g, at + 16)
        if rd_word(g, at + 48) != 0 or size > 3:
            return rd_badset(w, 206)
        i = 0
        while i < size:
            value = value | (byte(g, rd_word(g, at + 8) + i) << (i * 8))
            i = i + 1
    elif kind == 3:
        bits = rd_word(g, rd_word(g, at + 8))
        exponent = (bits >> 52) & 2047
        if (bits >> 63) != 0 or exponent < 1032 or exponent > 1039:
            return rd_badset(w, 207)
        significand = (bits & 4503599627370495) | 4503599627370496
        shift = 1075 - exponent
        if (significand & ((1 << shift) - 1)) != 0:
            return rd_badset(w, 208)
        value = significand >> shift
    else:
        return rd_badset(w, 209)
    if value < 512 or value > 65536:
        return rd_badset(w, 210)
    rd_put(w, R_LIMIT, value)
    return 1

def rd_sum(w:mutbuf, addend:u64) -> u64:
    magnitude = rd_get(w, R_OFFSET_MAG)
    sign = rd_get(w, R_OFFSET_SIGN)
    next_sign = 0
    next_magnitude = 0
    if sign != 0:
        if magnitude > addend:
            next_sign = 1
            next_magnitude = magnitude - addend
        else:
            next_magnitude = addend - magnitude
    else:
        if addend > RD_MAX - magnitude:
            return rd_badset(w, 211)
        next_magnitude = magnitude + addend
    rd_put(w, R_NEXT_SIGN, next_sign)
    rd_put(w, R_NEXT_MAG, next_magnitude)
    return 1

def rd_clip(sign:u64, magnitude:u64, size:u64) -> u64:
    if sign != 0:
        if magnitude >= size:
            return 0
        return size - magnitude
    if magnitude >= size:
        return size
    return magnitude

def rd_graph_content(w:mutbuf, id:u64) -> u64:
    size = rd_get(w, R_CONTENT_BYTES)
    begin = rd_graph_pool(w, size)
    if begin == 0:
        return 0
    out = RD_GRAPH_BASE + begin
    n = rd_get(w, R_CHUNK_BYTES)
    if rd_get(w, R_ENCODING) == 0:
        i = 0
        while i < n:
            store(w, out + i, byte(w, RD_PAGE + i))
            i = i + 1
        if size != n:
            return rd_badset(w, 212)
    else:
        i = 0
        written = 0
        while i < n:
            a = byte(w, RD_PAGE + i)
            b = 0
            c = 0
            if i + 1 < n:
                b = byte(w, RD_PAGE + i + 1)
            if i + 2 < n:
                c = byte(w, RD_PAGE + i + 2)
            store(w, out + written, rd_base64_digit(a >> 2))
            store(w, out + written + 1, rd_base64_digit(((a & 3) << 4) | (b >> 4)))
            third = 61
            fourth = 61
            if i + 1 < n:
                third = rd_base64_digit(((b & 15) << 2) | (c >> 6))
            if i + 2 < n:
                fourth = rd_base64_digit(c & 63)
            store(w, out + written + 2, third)
            store(w, out + written + 3, fourth)
            written = written + 4
            i = i + 3
        if written != size:
            return rd_badset(w, 213)
    return rd_graph_node(w, id, 4, begin, size, 0, 0, rd_get(w, R_CONTENT_CHARS))

def rd_base64_digit(value:u64) -> u64:
    if value < 26:
        return 65 + value
    if value < 52:
        return 97 + value - 26
    if value < 62:
        return 48 + value - 52
    if value == 62:
        return 43
    return 47
'''
PREFIX=r'''
def rd_prefix(s:readbuf, w:mutbuf, start:u64, size:u64) -> u64:
    position = start
    end = start + size
    chars = 0
    while position < end:
        first = byte(s, position)
        if first < 128:
            while position < end and byte(s, position) < 128:
                chars = chars + 1
                position = position + 1
        else:
            count = 0
            point = 0
            minimum = 0
            if first >= 194 and first <= 223:
                count = 2
                point = first & 31
                minimum = 128
            elif first >= 224 and first <= 239:
                count = 3
                point = first & 15
                minimum = 2048
            elif first >= 240 and first <= 244:
                count = 4
                point = first & 7
                minimum = 65536
            else:
                rd_put(w, R_UTF8_CHARS, chars)
                return position
            if count > end - position:
                rd_put(w, R_UTF8_CHARS, chars)
                return position
            i = 1
            while i < count:
                unit = byte(s, position + i)
                if unit < 128 or unit > 191:
                    rd_put(w, R_UTF8_CHARS, chars)
                    return position
                point = (point << 6) | (unit & 63)
                i = i + 1
            if point < minimum or point > 1114111 or (point >= 55296 and point <= 57343):
                rd_put(w, R_UTF8_CHARS, chars)
                return position
            position = position + count
            chars = chars + 1
    rd_put(w, R_UTF8_CHARS, chars)
    return position
'''
# The workspace variant has one mutable argument. Passing the same mutable
# buffer twice to an HIA function is neither necessary nor permitted.
WORK_PREFIX=PREFIX.replace(
 'def rd_prefix(s:readbuf, w:mutbuf, start:u64, size:u64)',
 'def rd_prefix_work(w:mutbuf, start:u64, size:u64)').replace('byte(s,','byte(w,')
