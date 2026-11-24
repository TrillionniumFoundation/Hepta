"""Author bounded JSON-line ingress and connection session transitions in HIA."""
from tools.generate_hia_mcp_service_owner_common import authored

SOURCE = r'''
def advance(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    phase = get(w, 0)
    result = get(w, 8)
    if phase == 0:
        put(w, 200, 0)
        put(w, FRAME_DISCARD, 0)
        put(w, 208, 0)
        put(w, 216, 0)
        put(w, 224, 0)
        put(w, 184, 0)
        put(w, 192, 0)
        return call(o, w, 50, 72, 0, 3, 0, 0, 0, 0, 0)
    if phase == 50:
        if failed(result):
            return 0
        return call(o, w, 51, 72, 0, 4, result | 2048, 0, 0, 0, 0)
    if phase == 51:
        if failed(result):
            return 0
        return consume(o, w)
    if phase == 1:
        if result == NEG4 or result == NEG11:
            return read_more(o, w)
        if failed(result) or result > 65536:
            return 0
        put(w, 208, result)
        put(w, 216, 0)
        if result == 0:
            put(w, 224, 1)
        return consume(o, w)
    if phase == 11:
        if result == 0:
            put(w, 200, 0)
            return consume(o, w)
        if result != 1 and result != 160:
            return 0
        put(w, SDK_STATUS, result)
        if result == 160:
            copy_state(w, PURE_OUTPUT, SDK_DESCRIPTOR, 160)
        return pure(o, w, 10, P_SESSION, REQUEST, get(w, 200), SESSION_OUT, 16777728, SESSION_WORK, W_SESSION)
    if phase == 10:
        if result == 4294967274:
            return call(o, w, 999, 60, 1, 0, 0, 0, 0, 0, 0)
        if result == 0:
            put(w, 200, 0)
            return consume(o, w)
        if result == 4294967275:
            if get(w, SESSION_OUT) != DISPATCH_MAGIC:
                return 0
            if get(w, SESSION_OUT + 8) == 2 or get(w, SESSION_OUT + 8) == 5:
                copy_state(w, SESSION_OUT, SCHEDULE_DESCRIPTOR, 96)
                return enter(w, 6, 0)
            if get(w, SESSION_OUT + 8) == 6:
                copy_state(w, SESSION_OUT, SCHEDULE_DESCRIPTOR, 96)
                return enter(w, 6, 200)
            return enter(w, 3, 0)
        if result > 16777728:
            return 0
        return write_line(w, SESSION_OUT, result)
    if phase == 20:
        if result == NEG4:
            return write_more(o, w)
        if failed(result) or result == 0 or result > get(w, 240) - get(w, 248):
            return 0
        put(w, 248, get(w, 248) + result)
        if get(w, 248) != get(w, 240):
            return write_more(o, w)
        return enter(w, 2, 30)
    if phase == 19:
        return write_more(o, w)
    if phase == 30:
        if get(w, 184) == 1:
            return call(o, w, 999, 60, 0, 0, 0, 0, 0, 0, 0)
        if get(w, SESSION_PHASE) == 3:
            return call(o, w, 999, 60, 1, 0, 0, 0, 0, 0, 0)
        put(w, 200, 0)
        put(w, 64, get(w, 176))
        return consume(o, w)
    if phase == 2:
        return call(o, w, 1, 0, 0, READ_CHUNK, 65536, 0, 0, 0, 12)
    return 0

def consume(o:mutbuf, w:mutbuf) -> u32:
    cursor = get(w, 216)
    end = get(w, 208)
    length = get(w, 200)
    discarding = get(w, FRAME_DISCARD)
    while cursor < end:
        ch = byte(w, READ_CHUNK + cursor)
        cursor = cursor + 1
        if ch == 10:
            if discarding == 1:
                discarding = 0
                length = 0
            else:
                if length != 0 and byte(w, REQUEST + length - 1) == 13:
                    length = length - 1
                put(w, 216, cursor)
                put(w, 200, length)
                put(w, FRAME_DISCARD, 0)
                return pure(o, w, 11, P_SDK, REQUEST, length, PURE_OUTPUT, 160, PURE_WORK, 32768)
        elif discarding == 0:
            if length == REQUEST_CAP:
                discarding = 1
                length = 0
            else:
                store(w, REQUEST + length, ch)
                length = length + 1
    put(w, 200, length)
    put(w, 216, cursor)
    put(w, FRAME_DISCARD, discarding)
    if get(w, 224) == 1:
        put(w, 200, 0)
        return enter(w, 6, 100)
    return read_more(o, w)

def read_more(o:mutbuf, w:mutbuf) -> u32:
    return enter(w, 6, 100)

def write_line(w:mutbuf, source:u64, size:u64) -> u32:
    put(w, 232, source)
    put(w, 240, size)
    put(w, 248, 0)
    return enter(w, 2, 19)

def write_more(o:mutbuf, w:mutbuf) -> u32:
    return call(o, w, 20, 1, 1, get(w, 232) + get(w, 248), get(w, 240) - get(w, 248), 0, 0, 0, 12)
'''


def source():
    return authored(SOURCE, extra={'DISPATCH_MAGIC': int.from_bytes(b'HIAMSQ01', 'little')})
