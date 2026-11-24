"""Shared HIA descriptor walks and stable bounded registry captures."""
from tools.generate_hia_mcp_job_bridge_common import authored

SOURCE=r'''
def advance(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    phase = get(w, 0)
    result = get(w, 8)
    if phase == 0:
        if get(w, 1016) == 1:
            put(w, 1112, 0)
            put(w, 1120, 0)
            return call(o, w, 40, 257, get(w, 1024), get(w, 1032), 657408, 0, 0, 0, 12)
        if get(w, 1016) != 0 or filesystem_path_ok(w, get(w, 1024), get(w, 1032)) == False:
            return 0
        store(w, 12288, 47)
        store(w, 12289, 0)
        put(w, 1056, 1)
        return call(o, w, 1, 257, NEG100, 12288, 720896, 0, 0, 0, 12)
    if phase == 1:
        if failed(result) or result < 3:
            return 0
        put(w, 1040, result)
        return next_part(o, w)
    if phase == 2:
        if result == NEG2 and get(w, 1064) != 0:
            return call(o, w, 10, 258, get(w, 1040), 12288, 448, 0, 0, 0, 12)
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
            if getn(w, 9244, 4) != get(w, 24) or getn(w, 9240, 4) & 4095 != 448:
                return 0
            return enter(w, get(w, 1000), get(w, 1008))
        return next_part(o, w)
    if phase == 10:
        if failed(result) and result != NEG17:
            return 0
        return call(o, w, 11, 74, get(w, 1040), 0, 0, 0, 0, 0, 0)
    if phase == 11:
        if failed(result):
            return 0
        return call(o, w, 2, 257, get(w, 1040), 12288, 720896, 0, 0, 0, 12)
    if phase >= 40 and phase <= 49:
        return read_file(o, w, phase, result)
    return 0

def next_part(o:mutbuf, w:mutbuf) -> u32:
    at = get(w, 1056)
    size = get(w, 1032)
    source = get(w, 1024)
    going = True
    start = at
    while going:
        while at < size and byte(w, source + at) == 47:
            at = at + 1
        if at == size:
            put(w, 1056, size)
            return call(o, w, 4, 5, get(w, 1040), 9216, 0, 0, 0, 0, 12)
        start = at
        while at < size and byte(w, source + at) != 47:
            at = at + 1
        if at - start != 1 or byte(w, source + start) != 46:
            going = False
    if at - start > 255:
        return 0
    end = copy_state(w, source + start, 12288, at - start)
    store(w, end, 0)
    put(w, 1056, choose(at < size, at + 1, size))
    return call(o, w, 2, 257, get(w, 1040), 12288, 720896, 0, 0, 0, 12)

def read_file(o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if phase == 40:
        if result == NEG2 and get(w, 1104) != 0:
            return enter(w, get(w, 1000), get(w, 1008))
        if failed(result) or result < 3:
            return file_error(w)
        put(w, 1040, result)
        put(w, 1120, 1)
        return call(o, w, 41, 5, result, 9472, 0, 0, 0, 0, 12)
    if phase == 41:
        if failed(result) or safe_regular(w, 9472, get(w, 1096)) == False or get(w, 9520) > get(w, 1080):
            return file_error(w)
        return file_read(o, w)
    if phase == 42:
        if result == NEG4:
            return file_read(o, w)
        if failed(result) or result > get(w, 1080) - get(w, 1112):
            return file_error(w)
        if result != 0:
            put(w, 1112, get(w, 1112) + result)
            return file_read(o, w)
        if get(w, 1112) != get(w, 9520):
            return file_error(w)
        return call(o, w, 43, 5, get(w, 1040), 9728, 0, 0, 0, 0, 12)
    if phase == 43:
        if failed(result) or same_stamp(w, 9472, 9728) == False:
            return file_error(w)
        return call(o, w, 44, 262, get(w, 1024), get(w, 1032), 9984, 256, 0, 0, 60)
    if phase == 44:
        if failed(result) or same_stamp(w, 9472, 9984) == False:
            return file_error(w)
        return call(o, w, 45, 3, get(w, 1040), 0, 0, 0, 0, 0, 0)
    if phase == 45:
        if failed(result):
            return file_error(w)
        return enter(w, get(w, 1000), get(w, 1008))
    return file_error(w)

def file_read(o:mutbuf, w:mutbuf) -> u32:
    size = get(w, 1080) - get(w, 1112)
    target = get(w, 1088) + get(w, 1112)
    if size == 0:
        size = 1
        target = 12544
    return call(o, w, 42, 0, get(w, 1040), target, size, 0, 0, 0, 12)
def file_error(w:mutbuf) -> u32:
    if get(w, 1136) == 0:
        return 0
    put(w, 1144, 1)
    return enter(w, get(w, 1000), get(w, 1008))

'''

def source():
    return authored(SOURCE)
