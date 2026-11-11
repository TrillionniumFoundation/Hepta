"""Complete native canonical writer after the original GraphLease preflight."""
BODY = r'''
def emit(s:readbuf, r:readbuf, w:mutbuf) -> u32:
    if length(w) < MIN_WORK:
        if length(w) >= 768:
            return refused(w, 40)
        return BAD
    if graph(s, r, w) == 0:
        return refused(w, 41)
    if get(w, S_FLAGS) == 6:
        return cli_emit(s, w)
    if get(w, S_PHASE) == 2:
        required = MIN_WORK + get(w, S_MAXIMUM)
        if required > length(w):
            put(w, S_NEED, required)
            return event(w, 1)
        put(w, S_OUTBASE, MIN_WORK)
        put(w, S_ARENA, required)
        put(w, S_CUR, get(w, S_ROOT))
        put(w, S_LEVEL, 0)
        put(w, S_STAGE, 0)
        put(w, S_OUTLEN, 0)
        put(w, S_PHASE, 3)
    if get(w, S_PHASE) != 3:
        return refused(w, 42)
    while get(w, S_PHASE) == 3:
        stage = get(w, S_STAGE)
        ok = 0
        if stage == 0:
            ok = emit_value(s, w)
        elif stage == 1:
            ok = emit_next(s, w)
        elif stage == 2:
            ok = emit_prepare(s, w)
        else:
            return refused(w, 43)
        if ok == 0:
            return pending(w)
    if get(w, S_PHASE) != 90:
        return refused(w, 44)
    return event(w, 0)

def append(w:mutbuf, value:u64) -> u64:
    size = get(w, S_OUTLEN)
    if size >= get(w, S_MAXIMUM):
        return error(w, 16, 0)
    if get(w, S_FLAGS) == 6:
        mode = get(w, S_CLI_MODE)
        if mode != 1 and mode != 2:
            return abi(w, 91)
        if mode == 2:
            if size >= get(w, S_CLI_MEASURED):
                return abi(w, 92)
            store(w, get(w, S_OUTBASE) + size, value)
    else:
        store(w, get(w, S_OUTBASE) + size, value)
    put(w, S_OUTLEN, size + 1)
    return 1

def append_text(s:readbuf, w:mutbuf) -> u64:
    i = 0
    while i < get(w, S_TMPSIZE):
        if append(w, text_byte(s, w, get(w, S_TMPKIND), get(w, S_TMPOFF), i)) == 0:
            return 0
        i = i + 1
    return 1

def unicode_escape(w:mutbuf, point:u64) -> u64:
    if append(w, 92) == 0 or append(w, 117) == 0:
        return 0
    i = 4
    while i > 0:
        i = i - 1
        digit = (point >> (i * 4)) & 15
        if append(w, choose(digit < 10, digit + 48, digit + 87)) == 0:
            return 0
    return 1

def emit_string(s:readbuf, w:mutbuf, at:u64) -> u64:
    if append(w, 34) == 0:
        return 0
    pos = read(s, at + 8)
    end = pos + read(s, at + 16)
    while pos < end:
        point = unit(s, w, pos, end)
        if point == MAX:
            return 0
        next_pos = get(w, S_NEXT)
        if point == 34 or point == 92:
            if append(w, 92) == 0 or append(w, point) == 0:
                return 0
        elif point == 8 or point == 9 or point == 10 or point == 12 or point == 13:
            letter = 98
            if point == 9:
                letter = 116
            elif point == 10:
                letter = 110
            elif point == 12:
                letter = 102
            elif point == 13:
                letter = 114
            if append(w, 92) == 0 or append(w, letter) == 0:
                return 0
        elif point < 32 or (point >= 127 and (get(w, S_FLAGS) & 1) != 0):
            if point <= 65535:
                if unicode_escape(w, point) == 0:
                    return 0
            else:
                scalar = point - 65536
                if unicode_escape(w, 55296 + (scalar >> 10)) == 0:
                    return 0
                if unicode_escape(w, 56320 + (scalar & 1023)) == 0:
                    return 0
        else:
            while pos < next_pos:
                if append(w, byte(s, pos)) == 0:
                    return 0
                pos = pos + 1
        pos = next_pos
    return append(w, 34)

def emit_value(s:readbuf, w:mutbuf) -> u64:
    at = node(s, w, get(w, S_CUR))
    if at == 0:
        return 0
    kind = read(s, at)
    if kind == 5 or kind == 6 or kind == 7:
        if emit_container(w, at, kind, read(s, at + 32)) == 0:
            return 0
        return 1
    mark = get(w, S_ARENA)
    ok = 0
    if kind == 4:
        ok = emit_string(s, w, at)
    elif kind == 2:
        if integer_text(s, w, at) != 0:
            ok = append_text(s, w)
    elif kind == 3:
        if floating(s, w, at, 0) != 0:
            ok = append_text(s, w)
    elif kind == 0 or kind == 1:
        literal(w, choose(kind == 0, 0, read(s, at + 48) + 1))
        ok = append_text(s, w)
    else:
        abi(w, 45)
    put(w, S_ARENA, mark)
    if ok == 0:
        return 0
    put(w, S_STAGE, 1)
    return 1

def emit_container(w:mutbuf, at:u64, kind:u64, count:u64) -> u64:
    if append(w, choose(kind == 6, 123, 91)) == 0:
        return 0
    if count == 0:
        if append(w, choose(kind == 6, 125, 93)) == 0:
            return 0
        put(w, S_STAGE, 1)
        return 1
    if get(w, S_LEVEL) >= 129:
        return abi(w, 46)
    frame = FRAME_BASE + get(w, S_LEVEL) * 64
    put(w, frame, get(w, S_CUR))
    put(w, frame + 8, kind)
    put(w, frame + 16, count)
    put(w, frame + 24, 0)
    put(w, frame + 32, 0)
    put(w, frame + 40, get(w, S_ARENA))
    put(w, frame + 48, 0)
    put(w, frame + 56, 0)
    put(w, S_LEVEL, get(w, S_LEVEL) + 1)
    put(w, S_STAGE, choose(kind == 6, 2, 1))
    return 1

def emit_prepare(s:readbuf, w:mutbuf) -> u64:
    if get(w, S_LEVEL) == 0:
        return abi(w, 47)
    frame = FRAME_BASE + (get(w, S_LEVEL) - 1) * 64
    total = get(w, frame + 16)
    if total > MAX >> 4:
        return abi(w, 48)
    base = reserve(w, total * 16)
    if base == 0:
        return 0
    i = 0
    while i < total:
        put(w, base + i * 8, i)
        i = i + 1
    if (get(w, S_FLAGS) & 2) != 0:
        at = node(s, w, get(w, frame))
        if at == 0:
            return 0
        if sort_keys(s, w, at, base, base + total * 8, total) == 0:
            return 0
    put(w, frame + 48, base)
    put(w, S_STAGE, 1)
    return 1

def emit_next(s:readbuf, w:mutbuf) -> u64:
    if get(w, S_LEVEL) == 0:
        put(w, S_PHASE, 90)
        return 1
    frame = FRAME_BASE + (get(w, S_LEVEL) - 1) * 64
    at = node(s, w, get(w, frame))
    if at == 0:
        return 0
    index = get(w, frame + 24)
    if index == get(w, frame + 16):
        if append(w, choose(get(w, frame + 8) == 6, 125, 93)) == 0:
            return 0
        put(w, S_ARENA, get(w, frame + 40))
        put(w, S_LEVEL, get(w, S_LEVEL) - 1)
        return 1
    if get(w, frame + 8) == 6:
        if get(w, frame + 56) == 2:
            put(w, frame + 56, 0)
        if get(w, frame + 56) == 0:
            if index != 0 and append(w, 44) == 0:
                return 0
            put(w, frame + 56, 1)
        original = get(w, get(w, frame + 48) + index * 8)
        key = edge(s, w, at, original * 2)
        if key == 0:
            return 0
        if emit_key(s, w, key) == 0:
            return 0
        if append(w, 58) == 0:
            return 0
        child = edge(s, w, at, original * 2 + 1)
        put(w, frame + 56, 2)
    else:
        if index != 0 and append(w, 44) == 0:
            return 0
        child = edge(s, w, at, index)
    if child == 0:
        return 0
    put(w, frame + 24, index + 1)
    put(w, S_CUR, child)
    put(w, S_STAGE, 0)
    return 1

def emit_key(s:readbuf, w:mutbuf, identifier:u64) -> u64:
    at = node(s, w, identifier)
    if at == 0:
        return 0
    if read(s, at) == 4:
        return emit_string(s, w, at)
    mark = get(w, S_ARENA)
    if key_text(s, w, at) == 0:
        put(w, S_ARENA, mark)
        return 0
    ok = 0
    if append(w, 34) != 0:
        if append_text(s, w) != 0:
            ok = append(w, 34)
    put(w, S_ARENA, mark)
    return ok

def sort_keys(s:readbuf, w:mutbuf, at:u64, base:u64, temp:u64, count:u64) -> u64:
    width = 1
    while width < count:
        left = 0
        while left < count:
            middle = choose(width < count - left, left + width, count)
            right = choose(width < count - middle, middle + width, count)
            if merge_keys(s, w, at, base, temp, left, middle, right) == 0:
                return 0
            left = right
        i = 0
        while i < count:
            put(w, base + i * 8, get(w, temp + i * 8))
            i = i + 1
        width = width * 2
    return 1

def merge_keys(s:readbuf, w:mutbuf, at:u64, base:u64, temp:u64, left:u64, middle:u64, right:u64) -> u64:
    i = left
    j = middle
    out = left
    while out < right:
        take_left = j == right
        if i < middle and j < right:
            comparison = compare_index(s, w, at, get(w, base + i * 8), get(w, base + j * 8))
            if comparison == 3:
                return error(w, 15, 2)
            if comparison == MAX:
                return 0
            take_left = comparison != 2
        elif i == middle:
            take_left = False
        if take_left:
            put(w, temp + out * 8, get(w, base + i * 8))
            i = i + 1
        else:
            put(w, temp + out * 8, get(w, base + j * 8))
            j = j + 1
        out = out + 1
    return 1

def compare_index(s:readbuf, w:mutbuf, at:u64, left:u64, right:u64) -> u64:
    a = edge(s, w, at, left * 2)
    b = edge(s, w, at, right * 2)
    if a == 0 or b == 0:
        return MAX
    x = node(s, w, a)
    y = node(s, w, b)
    if x == 0 or y == 0:
        return MAX
    return compare_keys(s, x, y)

def compare_keys(s:readbuf, a:u64, b:u64) -> u64:
    ak = read(s, a)
    bk = read(s, b)
    if ak == 4 and bk == 4:
        i = 0
        al = read(s, a + 16)
        bl = read(s, b + 16)
        while i < al and i < bl:
            x = byte(s, read(s, a + 8) + i)
            y = byte(s, read(s, b + 8) + i)
            if x != y:
                return choose(x < y, 1, 2)
            i = i + 1
        if al == bl:
            return 0
        return choose(al < bl, 1, 2)
    if ak < 1 or ak > 3 or bk < 1 or bk > 3:
        return 3
    return compare_numbers(s, a, b)

def number_sign(s:readbuf, at:u64) -> u64:
    if read(s, at) == 2:
        return read(s, at + 48)
    if read(s, at) == 3:
        bits = read(s, read(s, at + 8))
        if (bits & 9223372036854775807) != 0:
            return bits >> 63
    return 0

def number_width(s:readbuf, at:u64) -> u64:
    if read(s, at) == 2:
        return bit_length(s, at)
    if read(s, at) == 1:
        return read(s, at + 48)
    bits = read(s, read(s, at + 8))
    if ((bits >> 52) & 2047) != 0:
        return 53
    mantissa = bits & 4503599627370495
    count = 0
    while mantissa != 0:
        count = count + 1
        mantissa = mantissa >> 1
    return count

def number_top(s:readbuf, at:u64, width:u64) -> u64:
    if width == 0:
        return 0
    if read(s, at) != 3:
        return width + 2048
    exponent = (read(s, read(s, at + 8)) >> 52) & 2047
    if exponent == 0:
        return width + 974
    return width + exponent + 973

def number_bit(s:readbuf, at:u64, width:u64, index:u64) -> u64:
    if index >= width:
        return 0
    shift = width - index - 1
    kind = read(s, at)
    if kind == 2:
        value = byte(s, read(s, at + 8) + (shift >> 3))
        return (value >> (shift & 7)) & 1
    if kind == 1:
        return 1
    bits = read(s, read(s, at + 8))
    value = bits & 4503599627370495
    if ((bits >> 52) & 2047) != 0:
        value = value | 4503599627370496
    return (value >> shift) & 1

def compare_numbers(s:readbuf, a:u64, b:u64) -> u64:
    sign = number_sign(s, a)
    other = number_sign(s, b)
    if sign != other:
        return choose(sign != 0, 1, 2)
    aw = number_width(s, a)
    bw = number_width(s, b)
    topa = number_top(s, a, aw)
    topb = number_top(s, b, bw)
    comparison = 0
    if topa != topb:
        comparison = choose(topa < topb, 1, 2)
    else:
        width = choose(aw > bw, aw, bw)
        i = 0
        while i < width and comparison == 0:
            x = number_bit(s, a, aw, i)
            y = number_bit(s, b, bw, i)
            if x != y:
                comparison = choose(x < y, 1, 2)
            i = i + 1
    if sign != 0 and comparison != 0:
        return 3 - comparison
    return comparison

def cli_start(w:mutbuf, mode:u64) -> u64:
    put(w, S_CLI_MODE, mode)
    put(w, S_OUTBASE, MIN_WORK)
    arena = MIN_WORK
    if mode == 2:
        arena = MIN_WORK + get(w, S_CLI_MEASURED)
    put(w, S_ARENA, arena)
    put(w, S_CUR, get(w, S_ROOT))
    put(w, S_LEVEL, 0)
    put(w, S_STAGE, 0)
    put(w, S_OUTLEN, 0)
    put(w, S_PHASE, 3)
    return 1

def cli_emit(s:readbuf, w:mutbuf) -> u32:
    phase = get(w, S_PHASE)
    if phase == 2:
        if get(w, S_CLI_MODE) != 0 or get(w, S_CLI_MEASURED) != 0:
            return refused(w, 93)
        cli_start(w, 1)
    elif phase == 4:
        measured = get(w, S_CLI_MEASURED)
        if get(w, S_CLI_MODE) != 1 or measured == 0 or measured != get(w, S_OUTLEN):
            return refused(w, 94)
        if measured > CLI_MAXIMUM or get(w, S_LEVEL) != 0 or get(w, S_OUTBASE) != MIN_WORK:
            return refused(w, 95)
        required = MIN_WORK + measured
        if required > length(w):
            put(w, S_NEED, required)
            return event(w, 1)
        cli_start(w, 2)
    if get(w, S_PHASE) != 3 or (get(w, S_CLI_MODE) != 1 and get(w, S_CLI_MODE) != 2):
        return refused(w, 96)
    while get(w, S_PHASE) == 3:
        stage = get(w, S_STAGE)
        ok = 0
        if stage == 0:
            ok = emit_value(s, w)
        elif stage == 1:
            ok = emit_next(s, w)
        elif stage == 2:
            ok = emit_prepare(s, w)
        else:
            return refused(w, 43)
        if ok == 0:
            return pending(w)
        if get(w, S_PHASE) == 90:
            if get(w, S_CLI_MODE) == 1:
                measured = get(w, S_OUTLEN)
                if measured == 0 or measured > CLI_MAXIMUM:
                    return refused(w, 97)
                put(w, S_CLI_MEASURED, measured)
                put(w, S_PHASE, 4)
                required = MIN_WORK + measured
                if required > length(w):
                    put(w, S_NEED, required)
                    return event(w, 1)
                cli_start(w, 2)
            else:
                if get(w, S_OUTLEN) != get(w, S_CLI_MEASURED):
                    return refused(w, 98)
                return event(w, 0)
    return refused(w, 44)
'''

