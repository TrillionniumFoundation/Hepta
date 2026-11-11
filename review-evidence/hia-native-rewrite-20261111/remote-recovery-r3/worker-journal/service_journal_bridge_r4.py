"""Complete HIA transport/state owner for the existing selected Agent journal.

NEW DEVELOPMENT SOURCE. No ordinary Worker selector or whole-Worker claim.
The fixed executor owns only exact native calls, immutable source leases, and
buffer allocation/copy. All allocation sizes, original stage gates, state
commit points, diagnostic selection, and reply projection are HIA decisions.
"""
CONSTANTS = {
    'COMMAND': int.from_bytes(b'HIASJB01', 'little'),
    'ACK': int.from_bytes(b'HIASJA01', 'little'),
    'EVENT': int.from_bytes(b'HIASJE01', 'little'),
    'STATE': int.from_bytes(b'HIASJW01', 'little'),
    'JOURNAL': int.from_bytes(b'HIAJRN02', 'little'),
    'BAD': 0xfffffffd, 'MAX': (1 << 64) - 1,
    'LIMIT': 8 << 20, 'HEADER': 16 << 20, 'PRIVATE': 32768,
    'MIN_WORK': 4096, 'OUTPUT': 4096, 'SAVED': 512,
}
BODY = r'''
def service_journal(s:readbuf, r:readbuf, w:mutbuf) -> u32:
    if length(w) < MIN_WORK:
        return BAD
    if get(w, 8) == 5:
        return BAD
    if length(r) != 128:
        return refuse(w, 1)
    if word(r, 0) == COMMAND:
        return begin(s, r, w)
    if word(r, 0) == ACK:
        return replied(s, r, w)
    return refuse(w, 2)

def begin(s:readbuf, r:readbuf, w:mutbuf) -> u32:
    if word(r, 8) == 0 or word(r, 16) == 0 or word(r, 24) > 10 or word(r, 48) > 1:
        return refuse(w, 3)
    i = 64
    while i < 128:
        if word(r, i) != 0:
            return refuse(w, 4)
        i = i + 8
    raw = word(r, 32)
    foreign = word(r, 40)
    if foreign > MAX - raw or raw + foreign != length(s):
        return refuse(w, 5)
    if get(w, 8) == 0:
        i = 0
        while i < MIN_WORK:
            if byte(w, i) != 0:
                return refuse(w, 6)
            i = i + 1
        put(w, 0, STATE)
        put(w, 16, word(r, 8))
        put(w, 24, 0)
        put(w, 8, 1)
    if get(w, 0) != STATE or get(w, 16) != word(r, 8):
        return refuse(w, 7)
    if get(w, 8) == 2:
        if command_same(r, w) == 0:
            return refuse(w, 8)
        return prepare(s, w)
    if get(w, 8) != 1 or get(w, 24) == MAX or word(r, 16) != get(w, 24) + 1:
        return refuse(w, 9)
    copy_bytes(w, r, 1024, 0, 128)
    put(w, 24, word(r, 16))
    put(w, 40, word(r, 24))
    put(w, 64, raw)
    put(w, 72, foreign)
    put(w, 80, word(r, 56))
    put(w, 88, word(r, 48))
    put(w, 48, 0)
    put(w, 128, 0)
    put(w, 136, 0)
    put(w, 144, 0)
    put(w, 152, 0)
    put(w, 160, 0)
    put(w, 168, 0)
    put(w, 176, 0)
    put(w, 184, 0)
    put(w, 192, 0)
    put(w, 200, 0)
    put(w, 208, 0)
    put(w, 216, 0)
    if word(r, 24) != 10 and raw > LIMIT:
        return error(w, 1, 1)
    if foreign > 262144 or (word(r, 24) != 0 and foreign != 0):
        return error(w, 6, 2)
    size = choose(word(r, 24) == 10, 0, raw)
    nodes = (size + 1) >> 1
    nodes = nodes + 1
    if nodes > 262144:
        nodes = 262144
    arena = 64 + nodes * 56 + size
    if arena < 4256:
        arena = 4256
    keys = (size >> 2) + 1
    if keys > 262144:
        keys = 262144
    slots = 2
    while slots < keys * 2:
        slots = slots << 1
    keybytes = slots * 8
    if keybytes < 6320:
        keybytes = 6320
    scratch = 4256 + keybytes
    if scratch < arena:
        scratch = arena
    scratch = scratch + PRIVATE + foreign
    output_size = HEADER + 512
    scratch_offset = OUTPUT + output_size + 64
    if scratch_offset > MAX - scratch or scratch_offset + scratch > MAX - 64:
        return refuse(w, 10)
    put(w, 96, OUTPUT)
    put(w, 104, output_size)
    put(w, 112, scratch_offset)
    put(w, 120, scratch)
    put(w, 56, scratch_offset + scratch + 64)
    put(w, 8, 2)
    return prepare(s, w)

def command_same(r:readbuf, w:mutbuf) -> u64:
    i = 0
    while i < 128:
        if byte(r, i) != byte(w, 1024 + i):
            return 0
        i = i + 1
    return 1

def prepare(s:readbuf, w:mutbuf) -> u32:
    if length(s) != get(w, 64) + get(w, 72):
        return refuse(w, 11)
    if length(w) < get(w, 56):
        return event(w, 1)
    output = get(w, 96)
    scratch = get(w, 112)
    size = get(w, 120)
    fill_range(w, output, get(w, 104) + 64, 0)
    fill_range(w, scratch, size + 64, 0)
    copy_state(w, scratch + size - PRIVATE, SAVED)
    copy_bytes(w, s, scratch + size - PRIVATE - get(w, 72), get(w, 64), get(w, 72))
    put(w, scratch + size - PRIVATE + 336, get(w, 72))
    put(w, scratch + size - PRIVATE + 344, get(w, 88))
    put(w, scratch, get(w, 40))
    put(w, scratch + 8, get(w, 80))
    i = 0
    while i < 64:
        store(w, output + get(w, 104) + i, i)
        store(w, scratch + size + i, i)
        i = i + 1
    put(w, 8, 3)
    return event(w, 2)

def replied(s:readbuf, r:readbuf, w:mutbuf) -> u32:
    if get(w, 0) != STATE or get(w, 8) != 3:
        return refuse(w, 12)
    if length(w) < get(w, 56):
        return refuse(w, 17)
    if word(r, 8) != get(w, 16) or word(r, 16) != get(w, 24) or word(r, 24) != get(w, 32):
        return refuse(w, 13)
    if word(r, 40) != get(w, 64) or word(r, 48) != get(w, 104) or word(r, 56) != get(w, 120):
        return refuse(w, 14)
    if word(r, 32) > 0xffffffff or word(r, 64) > 1 or length(s) != get(w, 64) + get(w, 72):
        return refuse(w, 15)
    i = 72
    while i < 128:
        if word(r, i) != 0:
            return refuse(w, 16)
        i = i + 8
    put(w, 48, word(r, 32))
    if word(r, 64) != 1:
        return error(w, 6, 3)
    i = 0
    while i < 64:
        if byte(w, get(w, 96) + get(w, 104) + i) != i or byte(w, get(w, 112) + get(w, 120) + i) != i:
            return error(w, 6, 3)
        i = i + 1
    code = get(w, 48)
    if code == 0xffffffe8:
        reason = get(w, OUTPUT + HEADER)
        if get(w, 40) != 3 or syntax_valid(reason) == 0:
            return error(w, 6, 4)
        put(w, 168, 1)
        put(w, 176, 0)
        say(w, "HIA JSON preflight: ")
        syntax_message(w, reason)
        return error_done(w)
    if code == 0xffffffe7:
        start = get(w, OUTPUT + HEADER)
        end = get(w, OUTPUT + HEADER + 8)
        reason = get(w, OUTPUT + HEADER + 16)
        if get(w, 40) != 10 or start >= end or end > get(w, 64) or reason < 1 or reason > 3:
            return error(w, 6, 5)
        return unicode_error(s, w, start, end, reason)
    if code == 0xffffffe4:
        return original_syntax_error(s, w)
    if code == 0xffffffe6 or code == 0xffffffe5:
        if get(w, 40) != 3:
            return error(w, 6, 6)
        if code == 0xffffffe6:
            return error(w, 4, 7)
        return error(w, 1, 8)
    if code == 0xffffffff or code == 0xfffffffc or code == 0xfffffffe or code == 0xfffffff0 or code == 0xffffffea:
        if get(w, 40) == 3 and get(w, 88) != 0:
            if code == 0xfffffffe:
                return error(w, 1, 9)
            if code == 0xffffffff:
                return error(w, 1, 10)
            if code == 0xfffffffc:
                return error(w, 1, 11)
        if code == 0xffffffff:
            return error(w, 1, 12)
        if code == 0xfffffffc:
            return error(w, 1, 13)
        if code == 0xfffffffe:
            return error(w, 1, 14)
        if code == 0xfffffff0:
            return error(w, 1, 15)
        return error(w, 1, 16)
    if code == 0xfffffffd:
        return error(w, 6, 17)
    return accept(w)

def action_valid(stage:u64, code:u64) -> u64:
    if stage == 0:
        return choose(code == 1 or code == 2 or code == 7 or code == 11, 1, 0)
    if stage == 1:
        return choose(code == 3 or code == 4 or code == 11, 1, 0)
    if stage == 2 or stage == 4:
        return choose(code == 1, 1, 0)
    if stage == 3:
        return choose(code == 5 or code == 6 or code == 11, 1, 0)
    if stage == 5:
        return choose(code == 1 or code == 8, 1, 0)
    if stage == 6:
        return choose(code == 0 or code == 9, 1, 0)
    if stage == 7:
        return choose(code == 0, 1, 0)
    if stage == 8:
        return choose(code == 0 or code == 10, 1, 0)
    if stage == 9:
        return choose(code == 12 or code == 11, 1, 0)
    return choose(stage == 10 and code == 13, 1, 0)

def accept(w:mutbuf) -> u32:
    state = OUTPUT + HEADER
    code = get(w, 48)
    phase = get(w, state + 8)
    if get(w, state) != JOURNAL or action_valid(get(w, 40), code) == 0 or get(w, state + 48) != code:
        return error(w, 6, 18)
    if phase > 11 or phase == 9:
        return error(w, 6, 18)
    if get(w, state + 16) > 12 or get(w, state + 24) > 1 or get(w, state + 32) > 1 or get(w, state + 40) > 1:
        return error(w, 6, 18)
    status = get(w, state + 264)
    response = get(w, state + 272)
    cost = get(w, state + 280)
    flags = get(w, state + 288)
    if status > 2 or response > LIMIT or cost > LIMIT or flags > 3:
        return error(w, 6, 18)
    if byte(w, SAVED + 192) != 0:
        if saved_identity_ascii(w) == 0:
            return 512
        i = 64
        while i < 258:
            if byte(w, state + i) != byte(w, SAVED + i):
                return error(w, 6, 19)
            i = i + 1
    if code == 10:
        if (flags != 1 and flags != 3) or response == 0 or cost == 0 or status == 0:
            return error(w, 6, 20)
    elif code == 9:
        if flags != 2 or response == 0 or cost != 0 or status != 1:
            return error(w, 6, 20)
    elif flags != 0 or response != 0 or cost != 0 or status != 0:
        return error(w, 6, 20)
    extent = 0
    if get(w, 40) == 3:
        extent = get(w, get(w, 112) + 32)
        if extent < 64 or extent > get(w, 120) - PRIVATE:
            return error(w, 6, 21)
    copy_state(w, SAVED, state)
    put(w, 128, flags)
    put(w, 136, status)
    put(w, 144, response)
    put(w, 152, cost)
    put(w, 160, extent)
    put(w, 8, 1)
    return event(w, 0)

def error(w:mutbuf, kind:u64, reason:u64) -> u32:
    put(w, 168, kind)
    put(w, 176, 0)
    put(w, 184, reason)
    error_message(w, reason)
    return error_done(w)

def error_done(w:mutbuf) -> u32:
    put(w, 128, 0)
    put(w, 136, 0)
    put(w, 144, 0)
    put(w, 152, 0)
    put(w, 160, 0)
    put(w, 8, 1)
    return event(w, 3)

def emit(w:mutbuf, value:u64) -> u64:
    size = get(w, 176)
    if size >= 2048:
        put(w, 8, 5)
        return 0
    store(w, 2048 + size, value)
    put(w, 176, size + 1)
    return 1

def literal(w:mutbuf, size:u64, a:u64, b:u64, c:u64, d:u64) -> u64:
    i = 0
    while i < size:
        wordvalue = a
        if i >= 24:
            wordvalue = d
        elif i >= 16:
            wordvalue = c
        elif i >= 8:
            wordvalue = b
        emit(w, (wordvalue >> ((i & 7) * 8)) & 255)
        i = i + 1
    return 0

def decimal(w:mutbuf, value:u64) -> u64:
    if value == 0:
        emit(w, 48)
        return 0
    count = 0
    while value != 0:
        quotient = divide_ten(value)
        store(w, 1184 + count, value - quotient * 10 + 48)
        value = quotient
        count = count + 1
    while count != 0:
        count = count - 1
        emit(w, byte(w, 1184 + count))
    return 0

def divide_ten(value:u64) -> u64:
    quotient = 0
    remainder = 0
    bit = 64
    while bit != 0:
        bit = bit - 1
        remainder = (remainder << 1) | ((value >> bit) & 1)
        if remainder >= 10:
            remainder = remainder - 10
            quotient = quotient | (1 << bit)
    return quotient

def unicode_error(s:readbuf, w:mutbuf, start:u64, end:u64, reason:u64) -> u32:
    put(w, 168, 7)
    put(w, 176, 0)
    put(w, 184, reason)
    put(w, 192, start)
    put(w, 200, end)
    say(w, "'utf-8' codec can't decode ")
    if end == start + 1:
        say(w, "byte 0x")
        value = byte(s, start)
        a = value >> 4
        b = value & 15
        emit(w, choose(a < 10, a + 48, a + 87))
        emit(w, choose(b < 10, b + 48, b + 87))
        say(w, " in position ")
        decimal(w, start)
    else:
        say(w, "bytes in position ")
        decimal(w, start)
        emit(w, 45)
        decimal(w, end - 1)
    say(w, ": ")
    if reason == 1:
        say(w, "invalid start byte")
    elif reason == 2:
        say(w, "invalid continuation byte")
    else:
        say(w, "unexpected end of data")
    return error_done(w)

def saved_identity_ascii(w:mutbuf) -> u64:
    i = 0
    while i < 66:
        value = byte(w, SAVED + 192 + i)
        if value >= 128:
            put(w, 168, 7)
            put(w, 176, 0)
            put(w, 184, 4)
            put(w, 192, i)
            put(w, 200, i + 1)
            say(w, "'ascii' codec can't decode byte 0x")
            a = value >> 4
            b = value & 15
            emit(w, choose(a < 10, a + 48, a + 87))
            emit(w, choose(b < 10, b + 48, b + 87))
            say(w, " in position ")
            decimal(w, i)
            say(w, ": ordinal not in range(128)")
            error_done(w)
            return 0
        i = i + 1
    return 1

def utf8(s:readbuf, w:mutbuf) -> u64:
    i = 0
    size = get(w, 64)
    while i < size:
        lead = byte(s, i)
        if lead < 128:
            i = i + 1
        else:
            width = 0
            if lead >= 194 and lead <= 223:
                width = 2
            elif lead >= 224 and lead <= 239:
                width = 3
            elif lead >= 240 and lead <= 244:
                width = 4
            if width == 0:
                unicode_error(s, w, i, i + 1, 1)
                return 0
            j = 1
            while j < width:
                if i + j >= size:
                    unicode_error(s, w, i, size, 3)
                    return 0
                value = byte(s, i + j)
                valid = choose(value >= 128 and value <= 191, 1, 0)
                if j == 1:
                    if (lead == 224 and value < 160) or (lead == 237 and value >= 160) or (lead == 240 and value < 144) or (lead == 244 and value >= 144):
                        valid = 0
                if valid == 0:
                    unicode_error(s, w, i, i + j, 2)
                    return 0
                j = j + 1
            i = i + width
    return 1

def original_syntax_error(s:readbuf, w:mutbuf) -> u32:
    reason = get(w, OUTPUT + HEADER)
    position = get(w, OUTPUT + HEADER + 8)
    line = get(w, OUTPUT + HEADER + 16)
    column = get(w, OUTPUT + HEADER + 24)
    if get(w, 40) != 3 or get(w, 88) != 0 or original_valid(reason) == 0 or position > get(w, 64):
        return error(w, 6, 22)
    if utf8(s, w) == 0:
        return 512
    charpos = 0
    rawpos = 0
    lines = 1
    lastline = 0
    while rawpos < get(w, 64):
        value = byte(s, rawpos)
        if charpos < position and value == 10:
            lines = lines + 1
            lastline = charpos + 1
        if value < 128:
            rawpos = rawpos + 1
        elif value < 224:
            rawpos = rawpos + 2
        elif value < 240:
            rawpos = rawpos + 3
        else:
            rawpos = rawpos + 4
        charpos = charpos + 1
    columns = position - lastline + 1
    if lines != line or columns != column:
        return error(w, 6, 23)
    put(w, 168, 8)
    put(w, 176, 0)
    put(w, 184, reason)
    put(w, 192, position)
    put(w, 200, line)
    put(w, 208, column)
    original_message(w, reason)
    say(w, ": line ")
    decimal(w, line)
    say(w, " column ")
    decimal(w, column)
    say(w, " (char ")
    decimal(w, position)
    emit(w, 41)
    return error_done(w)

def refuse(w:mutbuf, reason:u64) -> u32:
    put(w, 8, 5)
    put(w, 216, reason)
    event(w, 4)
    return BAD

def event(w:mutbuf, action:u64) -> u32:
    if get(w, 32) == MAX:
        put(w, 8, 5)
        return BAD
    put(w, 32, get(w, 32) + 1)
    put(w, 256, EVENT)
    put(w, 264, action)
    put(w, 272, get(w, 16))
    put(w, 280, get(w, 24))
    put(w, 288, get(w, 32))
    put(w, 296, get(w, 40))
    put(w, 304, choose(action == 1, get(w, 56), 0))
    put(w, 312, get(w, 64))
    put(w, 320, 0)
    put(w, 328, get(w, 96))
    put(w, 336, get(w, 104))
    put(w, 344, get(w, 112))
    put(w, 352, get(w, 120))
    put(w, 360, get(w, 48))
    put(w, 368, SAVED)
    put(w, 376, 512)
    put(w, 384, get(w, 128))
    put(w, 392, get(w, 136))
    put(w, 400, OUTPUT)
    put(w, 408, get(w, 144))
    put(w, 416, OUTPUT + LIMIT)
    put(w, 424, get(w, 152))
    put(w, 432, get(w, 112))
    put(w, 440, get(w, 160))
    put(w, 448, get(w, 168))
    put(w, 456, 2048)
    put(w, 464, get(w, 176))
    put(w, 472, get(w, 184))
    put(w, 480, get(w, 192))
    put(w, 488, get(w, 200))
    put(w, 496, get(w, 208))
    put(w, 504, get(w, 216))
    return 512

def copy_state(w:mutbuf, target:u64, source:u64) -> u64:
    i = 0
    while i < 512:
        store(w, target + i, byte(w, source + i))
        i = i + 1
    return 0

def word(s:readbuf, offset:u64) -> u64:
    result = 0
    i = 0
    while i < 8:
        result = result | (byte(s, offset + i) << (i * 8))
        i = i + 1
    return result

def get(w:mutbuf, offset:u64) -> u64:
    result = 0
    i = 0
    while i < 8:
        result = result | (byte(w, offset + i) << (i * 8))
        i = i + 1
    return result

def put(w:mutbuf, offset:u64, value:u64) -> u64:
    i = 0
    while i < 8:
        store(w, offset + i, (value >> (i * 8)) & 255)
        i = i + 1
    return value
'''
ERROR_MESSAGES = {
 1:'journal JSON must be bytes within 8 MiB',
 2:'invalid journal foreign-type observation',
 3:'native journal violated buffer custody',
 4:'invalid native cached JSON syntax diagnostic',
 5:'invalid native UTF-8 codec diagnostic',
 6:'invalid native cached JSON structural diagnostic',
 7:'HIA JSON exceeds node/depth budget before decoding',
 8:'HIA JSON preflight: duplicate decoded object key',
 9:'HIA JSON preflight: node/depth budget exceeded',
 10:'HIA JSON decoder: invalid JSON syntax or Unicode',
 11:'HIA JSON decoder: duplicate decoded object key',
 12:'invalid JSON syntax or Unicode',
 13:'duplicate decoded object key',
 14:'JSON node/depth budget exceeded',
 15:'nonfinite number or integer conversion limit',
 16:'E_HIA_EDIT: JSON encoding exceeds byte budget',
 17:'native journal rejected its protocol phase or scratch profile',
 18:'invalid native journal instruction',
 19:'native journal changed admitted request identity',
 20:'invalid native journal write instruction',
 21:'invalid native journal arena extent',
 22:'invalid native original JSON syntax diagnostic',
 23:'native original JSON position disagrees with foreign text',
}
ORIGINAL_MESSAGES = {9:'Expecting value',10:'Expecting value',12:'Extra data',
14:"Expecting ',' delimiter",18:"Expecting ',' delimiter",
16:'Expecting property name enclosed in double quotes',17:"Expecting ':' delimiter"}
