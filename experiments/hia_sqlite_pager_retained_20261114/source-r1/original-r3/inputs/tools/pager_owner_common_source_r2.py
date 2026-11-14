"""Shared HIA helpers for the Pager owner. No host I/O or host state machine."""
SOURCE = r'''
def zero_event_tail(s:readbuf) -> u64:
    index = 96
    while index < 128:
        if byte(s, index) != 0:
            return 0
        index = index + 1
    return 1

def issue(o:mutbuf, w:mutbuf, phase:u64, operation:u64, handle:u64, a:u64, b:u64, c:u64) -> u32:
    if get(w, 24) == 18446744073709551615:
        put(w, 80, 7)
        put(w, 352, get(w, 8))
        put(w, 8, 203)
        return outcome(o, w, 132)
    put(w, 8, phase)
    put(w, 24, get(w, 24) + 1)
    put(w, 32, operation)
    put(w, 40, handle)
    put(w, 48, a)
    put(w, 56, b)
    put(w, 64, c)
    put(o, 0, REQUEST_MAGIC)
    put(o, 8, 2)
    put(o, 16, get(w, 16))
    put(o, 24, get(w, 24))
    put(o, 32, operation)
    put(o, 40, handle)
    put(o, 48, a)
    put(o, 56, b)
    put(o, 64, c)
    index = 72
    while index < 128:
        put(o, index, 0)
        index = index + 8
    return 1

def reissue(o:mutbuf, w:mutbuf) -> u32:
    # Only HIA decides EINTR retry, with a fresh sequence for each OS attempt.
    return issue(o, w, get(w, 8), get(w, 384), get(w, 40), get(w, 48), get(w, 56), get(w, 64))

def outcome(o:mutbuf, w:mutbuf, status:u64) -> u32:
    put(o, 0, OUTPUT_MAGIC)
    put(o, 8, 2)
    put(o, 16, get(w, 16))
    put(o, 24, status)
    put(o, 32, get(w, 80))
    put(o, 40, get(w, 88))
    put(o, 48, get(w, 352))
    put(o, 56, get(w, 96))
    put(o, 64, get(w, 104))
    put(o, 72, get(w, 128))
    put(o, 80, get(w, 136))
    put(o, 88, get(w, 144))
    put(o, 96, get(w, 152))
    put(o, 104, get(w, 224))
    put(o, 112, get(w, 232))
    put(o, 120, get(w, 280))
    return status

def fail(o:mutbuf, w:mutbuf, kind:u64, raw:u64) -> u32:
    if get(w, 80) == 0:
        put(w, 80, kind)
        put(w, 88, raw)
        put(w, 352, get(w, 8))
    return cleanup(o, w)

def cleanup(o:mutbuf, w:mutbuf) -> u32:
    if (get(w, 104) & 16) != 0:
        return issue(o, w, 100, 4, 2, 2, 123 + get(w, 160), 1)
    if (get(w, 104) & 32) != 0:
        return issue(o, w, 101, 4, 2, 2, 120, 1)
    if (get(w, 104) & 64) != 0:
        return issue(o, w, 102, 4, 2, 2, 122, 1)
    if (get(w, 104) & 8) != 0:
        return issue(o, w, 103, 4, 2, 2, 123 + get(w, 160), 1)
    if (get(w, 96) & 16) != 0:
        return issue(o, w, 104, 8, 2, 1, 0, 0)
    if (get(w, 96) & 8) != 0:
        return issue(o, w, 105, 8, 2, 0, 0, 0)
    if (get(w, 104) & 4) != 0:
        return issue(o, w, 106, 4, 2, 2, 128, 1)
    if (get(w, 96) & 4) != 0:
        return issue(o, w, 107, 9, 2, 0, 0, 0)
    if (get(w, 96) & 2) != 0:
        return issue(o, w, 108, 9, 1, 0, 0, 0)
    if (get(w, 104) & 2) != 0:
        return issue(o, w, 109, 4, 0, 2, 1073741826, 510)
    if (get(w, 104) & 1) != 0:
        return issue(o, w, 110, 4, 0, 2, 1073741824, 1)
    if (get(w, 96) & 1) != 0:
        return issue(o, w, 111, 9, 0, 0, 0, 0)
    put(w, 8, 202)
    return outcome(o, w, choose(get(w, 80) == 0, 130, 131))

def cleanup_return(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    phase = get(w, 8)
    if phase == 107 or phase == 108 or phase == 111:
        # Linux close consumes the descriptor even when reporting EINTR.
        # It must never be retried: another allocation could reuse its number.
        if phase == 107:
            put(w, 96, get(w, 96) & 251)
        elif phase == 108:
            put(w, 96, get(w, 96) & 253)
        else:
            put(w, 96, get(w, 96) & 254)
        if word(s, 48) != 0 or word(s, 56) != 0:
            append_cleanup_error(w, phase, word(s, 48))
            if get(w, 80) == 0:
                put(w, 80, 1)
                put(w, 88, word(s, 48))
                put(w, 352, phase)
        return cleanup(o, w)
    if word(s, 48) != 0 or word(s, 56) != 0:
        # No guessed unlock/unmap success. This is an owned, failed terminal.
        # The process custodian must retain it or observe process termination.
        append_cleanup_error(w, phase, word(s, 48))
        if get(w, 80) == 0:
            put(w, 80, 1)
            put(w, 88, word(s, 48))
            put(w, 352, phase)
        put(w, 8, 203)
        return outcome(o, w, 132)
    if phase == 100:
        put(w, 104, get(w, 104) & 239)
    elif phase == 101:
        put(w, 104, get(w, 104) & 223)
    elif phase == 102:
        put(w, 104, get(w, 104) & 191)
    elif phase == 103:
        put(w, 104, get(w, 104) & 247)
    elif phase == 104:
        put(w, 96, get(w, 96) & 239)
    elif phase == 105:
        put(w, 96, get(w, 96) & 247)
    elif phase == 106:
        put(w, 104, get(w, 104) & 251)
    elif phase == 109:
        put(w, 104, get(w, 104) & 253)
    elif phase == 110:
        put(w, 104, get(w, 104) & 254)
    else:
        put(w, 8, 203)
        return outcome(o, w, 132)
    return cleanup(o, w)


def append_cleanup_error(w:mutbuf, phase:u64, raw:u64) -> u64:
    # First business/OS error stays unchanged. Keep the last cleanup error
    # plus the complete bounded cleanup error sequence, including close errors.
    put(w, 368, raw)
    put(w, 376, phase)
    count = get(w, 392)
    if count < 12:
        put(w, 768 + count * 16, phase)
        put(w, 776 + count * 16, raw)
        put(w, 392, count + 1)
    return 0

def regular_stat(s:readbuf) -> u64:
    if word(s, 48) != 0 or word(s, 56) != 144:
        return 0
    if (le(s, 152, 4) & 61440) != 32768:
        return 0
    if word(s, 144) == 0 or word(s, 176) > 9223372036854775807:
        return 0
    return 1

def is_busy(raw:u64) -> u64:
    return choose(raw == 18446744073709551605 or raw == 18446744073709551603, 1, 0)

def word(s:readbuf, at:u64) -> u64:
    return le(s, at, 8)

def le(s:readbuf, at:u64, count:u64) -> u64:
    value = 0
    index = 0
    while index < count:
        value = value | (byte(s, at + index) << (index * 8))
        index = index + 1
    return value

def get(w:mutbuf, at:u64) -> u64:
    value = 0
    index = 0
    while index < 8:
        value = value | (byte(w, at + index) << (index * 8))
        index = index + 1
    return value

def get32(w:mutbuf, at:u64) -> u64:
    return byte(w, at) | (byte(w, at + 1) << 8) | (byte(w, at + 2) << 16) | (byte(w, at + 3) << 24)

def get16(w:mutbuf, at:u64) -> u64:
    return byte(w, at) | (byte(w, at + 1) << 8)

def put(w:mutbuf, at:u64, value:u64) -> u64:
    index = 0
    while index < 8:
        store(w, at + index, (value >> (index * 8)) & 255)
        index = index + 1
    return 0

def be_mut(w:mutbuf, at:u64, count:u64) -> u64:
    value = 0
    index = 0
    while index < count:
        value = (value << 8) | byte(w, at + index)
        index = index + 1
    return value

def same(s:readbuf, a:u64, w:mutbuf, b:u64, count:u64) -> u64:
    index = 0
    while index < count:
        if byte(s, a + index) != byte(w, b + index):
            return 0
        index = index + 1
    return 1

def copy_mut(w:mutbuf, dst:u64, src:u64, count:u64) -> u64:
    index = 0
    while index < count:
        store(w, dst + index, byte(w, src + index))
        index = index + 1
    return 0
'''
