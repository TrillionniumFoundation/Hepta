"""New reconstructed file policy owner. No old missing-run identity.
The native HIA owns path encoding, file eligibility, reads, close ordering and text.
The carrier exposes fixed OPEN/FSTAT/READ/CLOSE results only.
"""
BODY=r'''
def entry(s:readbuf, r:readbuf, w:mutbuf) -> u32:
    if length(w) < 1024:
        return BAD
    if get(w, 8) != 0:
        return BAD
    if get(w, 0) == 0:
        if length(r) != 0 or source_admission(s, w) == 0:
            return refuse(w)
        put(w, 0, STATE_MAGIC)
        put(w, 16, 1)
        put(w, 24, length(s))
        put(w, 32, uint(s, 16))
        put(w, 40, uint(s, 24))
        put(w, 48, uint(s, 32))
        put(w, 56, uint(s, 40))
        put(w, 64, PATH + uint(s, 40) + 2)
        put(w, 232, uint(s, 24))
        copy_bytes(w, s, 512, 0, 64)
    elif get(w, 0) != STATE_MAGIC or equal_command(s, w) == 0:
        return refuse(w)
    phase = get(w, 16)
    if phase == 1:
        if length(r) != 0 or get(w, 80) != 0 or get(w, 40) != get(w, 232) or get(w, 64) != PATH + get(w, 56) + 2:
            return refuse(w)
        if length(w) < get(w, 64):
            return growing(w)
        return initialize_path(s, w)
    if phase == 7:
        if get(w, 80) != 1 or get(w, 88) != 3 or get(w, 200) != 0 or length(r) != 96:
            return refuse(w)
        if reply_admission(r, w) == 0:
            return refuse(w)
        if get(w, 176) != PATH + get(w, 56) + 2 or get(w, 48) + 1 > MAX - get(w, 176):
            return refuse(w)
        if get(w, 64) != get(w, 176) + get(w, 48) + 1:
            return refuse(w)
        i = 0
        while i < 96:
            if byte(r, i) != byte(w, 576 + i):
                return refuse(w)
            i = i + 1
        if length(w) < get(w, 64):
            return growing(w)
        return begin_read(w)
    if phase < 2 or phase > 5 or get(w, 88) != phase:
        return refuse(w)
    if (phase == 2 and get(w, 80) != 0) or (phase != 2 and get(w, 80) != 1):
        return refuse(w)
    if reply_admission(r, w) == 0:
        return refuse(w)
    if phase == 2:
        return opened(r, w)
    if phase == 3:
        return stated(r, w)
    if phase == 4:
        return read_result(r, w)
    return closed(r, w)

def source_admission(s:readbuf, w:mutbuf) -> u64:
    if length(s) < 64 or uint(s, 0) != COMMAND or uint(s, 8) != 1:
        return 0
    if uint(s, 16) == 0 or uint(s, 24) == 0 or uint(s, 48) != 64 or uint(s, 56) != length(s):
        return 0
    if uint(s, 40) != length(s) - 64 or uint(s, 40) > MAX - PATH - 2:
        return 0
    if uint(s, 32) == MAX:
        return 0
    at = 64
    while at < length(s):
        if point(s, w, at, length(s)) == MAX:
            return 0
        at = get(w, 168)
    return 1

def equal_command(s:readbuf, w:mutbuf) -> u64:
    if length(s) != get(w, 24) or length(s) < 64:
        return 0
    i = 0
    while i < 64:
        if byte(s, i) != byte(w, 512 + i):
            return 0
        i = i + 1
    if uint(s, 16) != get(w, 32) or uint(s, 32) != get(w, 48) or uint(s, 40) != get(w, 56):
        return 0
    if get(w, 64) < PATH + get(w, 56) + 2:
        return 0
    return 1

def refuse(w:mutbuf) -> u32:
    put(w, 8, 1)
    output(w, 6)
    return BAD

def output(w:mutbuf, action:u64) -> u64:
    i = 0
    while i < 128:
        store(w, 256 + i, 0)
        i = i + 1
    put(w, 256, EVENT)
    put(w, 264, action)
    put(w, 272, get(w, 32))
    put(w, 280, get(w, 40))
    if action >= 2 and action <= 5:
        put(w, 288, 1)
    if action == 2:
        put(w, 296, PATH)
        put(w, 304, get(w, 72))
        put(w, 312, OPEN_FLAGS)
    if action == 4:
        put(w, 320, get(w, 120))
    if action == 0:
        put(w, 328, get(w, 104))
        if get(w, 104) != 0:
            put(w, 336, DIAG)
            put(w, 344, get(w, 160))
        else:
            put(w, 352, get(w, 176))
            put(w, 360, get(w, 96))
        put(w, 376, get(w, 112))
    if action == 1:
        put(w, 368, get(w, 64))
    return 0

def growing(w:mutbuf) -> u32:
    output(w, 1)
    return GROW

def issue(w:mutbuf, action:u64) -> u32:
    if get(w, 40) == MAX:
        return refuse(w)
    put(w, 40, get(w, 40) + 1)
    put(w, 16, action)
    put(w, 88, action)
    output(w, action)
    return 128

def finish(w:mutbuf) -> u32:
    if get(w, 80) != 0:
        return refuse(w)
    put(w, 16, 6)
    diagnostic(w)
    if get(w, 8) != 0:
        return refuse(w)
    output(w, 0)
    return 128

def closing(w:mutbuf, error:u64, cause:u64) -> u32:
    put(w, 104, error)
    put(w, 112, cause)
    return issue(w, 5)

def reply_admission(r:readbuf, w:mutbuf) -> u64:
    if length(r) < 96 or uint(r, 0) != ACK or uint(r, 8) != get(w, 32) or uint(r, 16) != get(w, 40):
        return 0
    action = get(w, 88)
    if uint(r, 24) != action or uint(r, 72) != length(r) or uint(r, 80) != 0 or uint(r, 88) != 0:
        return 0
    status = uint(r, 32)
    if status > 1:
        return 0
    if status == 1:
        if length(r) != 96 or uint(r, 40) != 0 or uint(r, 48) != 0 or uint(r, 64) != 0:
            return 0
        if uint(r, 56) == 0 or uint(r, 56) > 4095:
            return 0
        return 1
    if uint(r, 56) != 0:
        return 0
    if action == 4:
        if uint(r, 48) != 0 or uint(r, 40) != uint(r, 64) or uint(r, 40) > get(w, 120):
            return 0
        if uint(r, 64) != length(r) - 96:
            return 0
        return 1
    if length(r) != 96 or uint(r, 64) != 0:
        return 0
    if action == 2:
        if uint(r, 40) != 1 or uint(r, 48) != 0:
            return 0
    elif action == 3:
        if uint(r, 40) > 4294967295:
            return 0
    elif action == 5:
        if uint(r, 40) != 0 or uint(r, 48) != 0:
            return 0
    else:
        return 0
    return 1

def initialize_path(s:readbuf, w:mutbuf) -> u32:
    normalize(s, w)
    if unicode_failure(w) != 0:
        put(w, 104, 5)
        return finish(w)
    if get(w, 216) != 0:
        put(w, 104, 4)
        return finish(w)
    encode_path(w)
    put(w, 16, 2)
    put(w, 88, 2)
    output(w, 2)
    return 128

def normalize(s:readbuf, w:mutbuf) -> u64:
    leading = 0
    while leading < get(w, 56) and byte(s, 64 + leading) == 47:
        leading = leading + 1
    out = PATH
    if leading != 0:
        store(w, out, 47)
        out = out + 1
        if leading == 2:
            store(w, out, 47)
            out = out + 1
    at = 64 + leading
    end = length(s)
    while at < end:
        while at < end and byte(s, at) == 47:
            at = at + 1
        begin = at
        while at < end and byte(s, at) != 47:
            at = at + 1
        size = at - begin
        if size != 0:
            if size != 1 or byte(s, begin) != 46:
                if out != PATH and byte(w, out - 1) != 47:
                    store(w, out, 47)
                    out = out + 1
                copy_bytes(w, s, out, begin, size)
                out = out + size
    if out == PATH:
        store(w, out, 46)
        out = out + 1
    put(w, 72, out - PATH)
    return 0

def unicode_failure(w:mutbuf) -> u64:
    at = PATH
    end = PATH + get(w, 72)
    index = 0
    put(w, 216, 0)
    while at < end:
        cp = point_mut(w, at, end)
        if cp == MAX:
            put(w, 8, 1)
            return 1
        if cp >= 55296 and cp <= 57343:
            start = index
            first = cp
            failed = 0
            run = 1
            while at < end and run != 0:
                cp = point_mut(w, at, end)
                if cp < 55296 or cp > 57343:
                    run = 0
                else:
                    if cp < 56448 or cp > 56575:
                        if failed == 0:
                            start = index
                            first = cp
                        failed = 1
                    at = get(w, 168)
                    index = index + 1
            if failed != 0:
                put(w, 136, first)
                put(w, 144, start)
                put(w, 152, index)
                return 1
        else:
            if cp == 0:
                put(w, 216, 1)
            at = get(w, 168)
            index = index + 1
    return 0

def encode_path(w:mutbuf) -> u64:
    at = PATH
    out = PATH
    end = PATH + get(w, 72)
    while at < end:
        cp = point_mut(w, at, end)
        next_at = get(w, 168)
        if cp >= 56448 and cp <= 56575:
            store(w, out, cp - 56320)
            out = out + 1
        else:
            while at < next_at:
                store(w, out, byte(w, at))
                at = at + 1
                out = out + 1
        at = next_at
    store(w, out, 0)
    put(w, 72, out - PATH)
    put(w, 176, PATH + get(w, 56) + 2)
    return 0

def opened(r:readbuf, w:mutbuf) -> u32:
    if uint(r, 32) != 0:
        if uint(r, 56) == 4:
            return issue(w, 2)
        put(w, 104, 1)
        put(w, 112, uint(r, 56))
        return finish(w)
    put(w, 80, 1)
    put(w, 200, 1)
    return issue(w, 3)

def stated(r:readbuf, w:mutbuf) -> u32:
    if get(w, 200) != 0:
        if uint(r, 32) != 0:
            if uint(r, 56) == 9:
                put(w, 224, 1)
                return closing(w, 1, 9)
        elif (uint(r, 40) & 61440) == 16384:
            put(w, 224, 1)
            return closing(w, 1, 21)
        put(w, 200, 0)
        return issue(w, 3)
    if uint(r, 32) != 0:
        return closing(w, 1, uint(r, 56))
    size = uint(r, 48)
    if (uint(r, 40) & 61440) != 32768 or ((size & 9223372036854775808) == 0 and size > get(w, 48)):
        return closing(w, 2, 0)
    if get(w, 48) + 1 > MAX - get(w, 176):
        return refuse(w)
    put(w, 64, get(w, 176) + get(w, 48) + 1)
    if length(w) < get(w, 64):
        copy_bytes(w, r, 576, 0, 96)
        put(w, 16, 7)
        return growing(w)
    return begin_read(w)

def begin_read(w:mutbuf) -> u32:
    if get(w, 176) != PATH + get(w, 56) + 2 or get(w, 64) != get(w, 176) + get(w, 48) + 1:
        return refuse(w)
    put(w, 96, 0)
    put(w, 128, 0)
    put(w, 120, get(w, 48) + 1)
    return issue(w, 4)

def read_result(r:readbuf, w:mutbuf) -> u32:
    if get(w, 176) != PATH + get(w, 56) + 2:
        return refuse(w)
    if get(w, 96) > get(w, 48) + 1 or get(w, 120) != get(w, 48) + 1 - get(w, 96):
        return refuse(w)
    if get(w, 176) > length(w) or get(w, 48) + 1 > length(w) - get(w, 176):
        return refuse(w)
    if uint(r, 32) != 0:
        error = uint(r, 56)
        if error == 4:
            return issue(w, 4)
        if error == 11:
            if get(w, 96) == 0:
                put(w, 128, 1)
            return closing(w, 0, 0)
        return closing(w, 1, error)
    count = uint(r, 40)
    copy_bytes(w, r, get(w, 176) + get(w, 96), 96, count)
    put(w, 96, get(w, 96) + count)
    if count == 0 or get(w, 96) == get(w, 48) + 1:
        return closing(w, 0, 0)
    put(w, 120, get(w, 48) + 1 - get(w, 96))
    return issue(w, 4)

def closed(r:readbuf, w:mutbuf) -> u32:
    if get(w, 224) > 1 or get(w, 128) > 1 or get(w, 104) > 2:
        return refuse(w)
    if get(w, 224) != 0 and (get(w, 104) != 1 or (get(w, 112) != 9 and get(w, 112) != 21)):
        return refuse(w)
    put(w, 80, 0)
    if uint(r, 32) != 0 and get(w, 224) == 0:
        put(w, 104, 1)
        put(w, 112, uint(r, 56))
    if get(w, 104) == 0:
        if get(w, 128) != 0:
            put(w, 104, 6)
        elif get(w, 96) > get(w, 48):
            put(w, 104, 3)
    return finish(w)

def diag_byte(w:mutbuf, value:u64) -> u64:
    count = get(w, 160)
    if count >= 256:
        put(w, 8, 1)
        return 0
    store(w, DIAG + count, value)
    put(w, 160, count + 1)
    return 0

def quotient_ten(value:u64) -> u64:
    bit = 64
    quotient = 0
    remainder = 0
    while bit != 0:
        bit = bit - 1
        remainder = (remainder << 1) | ((value >> bit) & 1)
        if remainder >= 10:
            remainder = remainder - 10
            quotient = quotient | (1 << bit)
    return quotient

def diag_number(w:mutbuf, value:u64) -> u64:
    count = 0
    if value == 0:
        diag_byte(w, 48)
        return 0
    while value != 0:
        next_value = quotient_ten(value)
        store(w, 768 + count, 48 + value - next_value * 10)
        count = count + 1
        value = next_value
    while count != 0:
        count = count - 1
        diag_byte(w, byte(w, 768 + count))
    return 0

def hex_digit(value:u64) -> u64:
    if value < 10:
        return 48 + value
    return 87 + value

def diagnostic(w:mutbuf) -> u64:
    put(w, 160, 0)
    error = get(w, 104)
    if error == 0:
        return 0
    if error >= 1 and error <= 4:
        text(w, error - 1)
    elif error == 6:
        text(w, 4)
    elif error == 5:
        text(w, 5)
        if get(w, 152) == get(w, 144) + 1:
            text(w, 6)
            value = get(w, 136)
            shift = 16
            while shift != 0:
                shift = shift - 4
                diag_byte(w, hex_digit((value >> shift) & 15))
            text(w, 7)
            diag_number(w, get(w, 144))
        else:
            text(w, 8)
            diag_number(w, get(w, 144))
            diag_byte(w, 45)
            diag_number(w, get(w, 152) - 1)
        text(w, 9)
    else:
        put(w, 8, 1)
    return 0
'''
