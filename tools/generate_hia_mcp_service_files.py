"""Author HIA stable file capture, fixed SHA admission and sealed custody."""
from tools.generate_hia_mcp_service_owner_common import authored

SOURCE = r'''
def advance(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    phase = get(w, 0)
    result = get(w, 8)
    if phase == 0:
        if get(w, 1016) == 2:
            if get(w, 1112) > get(w, 1080) or get(w, 1088) > STATE_BYTES or get(w, 1112) > STATE_BYTES - get(w, 1088):
                return 0
            put(w, 1168, 0)
            put(w, 1128, NONE)
            return sha(o, w, 46, 0, 1)
        if get(w, 1016) == 1:
            put(w, 1112, 0)
            put(w, 1120, 0)
            put(w, 1128, NONE)
            return call(o, w, 40, 257, get(w, 1024), get(w, 1032), 657408, 0, 0, 0, 12)
        if get(w, 1016) != 0 or (get(w, 1032) != 1 and path_ok(w, get(w, 1024), get(w, 1032)) == False) or byte(w, get(w, 1024)) != 47:
            return 0
        store(w, 12288, 47)
        store(w, 12289, 0)
        put(w, 1056, 1)
        return call(o, w, 1, 257, NEG100, 12288, 720896, 0, 0, 0, 12)
    if phase == 1:
        if failed(result) or result < 3:
            return 0
        put(w, 1040, result)
        if get(w, 1032) == 1:
            return call(o, w, 4, 5, get(w, 1040), 9216, 0, 0, 0, 0, 12)
        return next_part(o, w)
    if phase == 2:
        if failed(result) or result < 3:
            return 0
        put(w, 1072, result)
        return call(o, w, 3, 3, get(w, 1040), 0, 0, 0, 0, 0, 0)
    if phase == 3:
        if failed(result):
            return 0
        put(w, 1040, get(w, 1072))
        return call(o, w, 4, 5, get(w, 1040), 9216, 0, 0, 0, 0, 12)
    if phase == 4:
        if failed(result) or getn(w, 9240, 4) & 61440 != 16384:
            return 0
        if get(w, 1056) >= get(w, 1032):
            owner = getn(w, 9244, 4)
            if (owner != get(w, 24) and owner != 0) or getn(w, 9240, 4) & 18 != 0:
                return 0
            return enter(w, get(w, 1000), get(w, 1008))
        return next_part(o, w)
    if phase >= 40 and phase <= 59:
        return read_file(o, w, phase, result)
    if phase >= 60 and phase <= 69:
        return seal_file(o, w, phase, result)
    return 0

def next_part(o:mutbuf, w:mutbuf) -> u32:
    at = get(w, 1056)
    start = at
    size = get(w, 1032)
    source = get(w, 1024)
    while at < size and byte(w, source + at) != 47:
        at = at + 1
    if at == start or at - start > 255:
        return 0
    end = copy_state(w, source + start, 12288, at - start)
    store(w, end, 0)
    put(w, 1056, at + 1)
    return call(o, w, 2, 257, get(w, 1040), 12288, 720896, 0, 0, 0, 12)

def safe_capture(w:mutbuf) -> bool:
    mode = getn(w, 9496, 4)
    owner = getn(w, 9500, 4)
    expected = choose(get(w, 1096) == 2, 0, get(w, 24))
    return mode & 61440 == 32768 and get(w, 9488) == 1 and owner == expected and mode & 18 == 0 and (get(w, 1096) != 1 or mode & 511 == 384)

def read_file(o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if phase == 40:
        if failed(result) or result < 3:
            return 0
        put(w, 1040, result)
        put(w, 1120, 1)
        return call(o, w, 41, 5, result, 9472, 0, 0, 0, 0, 12)
    if phase == 41:
        if failed(result) or safe_capture(w) == False or get(w, 9520) > get(w, 1080):
            return 0
        return file_read(o, w)
    if phase == 42:
        if result == NEG4:
            return file_read(o, w)
        if failed(result) or result > get(w, 1080) - get(w, 1112):
            return 0
        if result != 0:
            put(w, 1112, get(w, 1112) + result)
            return file_read(o, w)
        if get(w, 1112) != get(w, 9520):
            return 0
        return call(o, w, 43, 5, get(w, 1040), 9728, 0, 0, 0, 0, 12)
    if phase == 43:
        if failed(result) or same_stamp(w, 9472, 9728) == False:
            return 0
        return call(o, w, 44, 262, get(w, 1024), get(w, 1032), 9984, 256, 0, 0, 60)
    if phase == 44:
        if failed(result) or same_stamp(w, 9472, 9984) == False:
            return 0
        return call(o, w, 45, 3, get(w, 1040), 0, 0, 0, 0, 0, 0)
    if phase == 45:
        if failed(result):
            return 0
        put(w, 1168, 0)
        return sha(o, w, 46, 0, 1)
    if phase == 46 or phase == 47:
        if result != 0:
            return 0
        if get(w, 1168) == get(w, 1112):
            return sha(o, w, 48, 2, 1)
        size = get(w, 1112) - get(w, 1168)
        if size > 65536:
            size = 65536
        copy_state(w, get(w, 1088) + get(w, 1168), SHA_INPUT + 1, size)
        put(w, 1168, get(w, 1168) + size)
        return sha(o, w, 47, 1, size + 1)
    if phase == 48:
        if result != 32:
            return 0
        if get(w, 1136) != NONE and equal(w, SHA_OUTPUT, get(w, 1136), 32) == False:
            return 0
        end = text_memfd(w, 12128)
        store(w, end, 0)
        return call(o, w, 60, 319, 12128, 3, 0, 0, 0, 0, 3)
    return 0

def file_read(o:mutbuf, w:mutbuf) -> u32:
    size = get(w, 1080) - get(w, 1112)
    target = get(w, 1088) + get(w, 1112)
    if size == 0:
        size = 1
        target = 12544
    return call(o, w, 42, 0, get(w, 1040), target, size, 0, 0, 0, 12)

def seal_file(o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if phase == 60:
        if failed(result) or result < 3:
            return 0
        put(w, 1128, result)
        put(w, 1168, 0)
        return seal_write(o, w)
    if phase == 61:
        if result == NEG4:
            return seal_write(o, w)
        if failed(result) or result == 0 or result > get(w, 1112) - get(w, 1168):
            return 0
        put(w, 1168, get(w, 1168) + result)
        return seal_write(o, w)
    if phase == 62:
        if result != 0:
            return 0
        return call(o, w, 63, 72, get(w, 1128), 1033, 15, 0, 0, 0, 0)
    if phase == 63:
        if failed(result):
            return 0
        return call(o, w, 64, 72, get(w, 1128), 1034, 0, 0, 0, 0, 0)
    if phase == 64:
        if result != 15:
            return 0
        return enter(w, get(w, 1000), get(w, 1008))
    return 0

def seal_write(o:mutbuf, w:mutbuf) -> u32:
    if get(w, 1168) == get(w, 1112):
        return call(o, w, 62, 8, get(w, 1128), 0, 0, 0, 0, 0, 0)
    return call(o, w, 61, 1, get(w, 1128), get(w, 1088) + get(w, 1168), get(w, 1112) - get(w, 1168), 0, 0, 0, 12)
'''


def source():
    return authored(SOURCE, text={'memfd': 'hia-mcp-captured-role'})
