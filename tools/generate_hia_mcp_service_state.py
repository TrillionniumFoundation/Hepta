"""Author canonical state creation and lifetime controller locks in HIA."""
from tools.generate_hia_mcp_service_owner_common import authored

SOURCE = r'''
def advance(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    phase = get(w, 0)
    result = get(w, 8)
    if phase == 0:
        put(w, 1424, 1)
        store(w, 12288, 47)
        store(w, 12289, 0)
        return call(o, w, 1, 257, NEG100, 12288, 589824, 0, 0, 0, 12)
    if phase == 1:
        if failed(result) or result < 3:
            return 0
        put(w, 1408, result)
        return next_part(o, w)
    if phase == 2:
        if result == NEG2:
            return call(o, w, 3, 258, get(w, 1408), 12288, 448, 0, 0, 0, 12)
        if failed(result) or result < 3:
            return 0
        put(w, 1416, result)
        return call(o, w, 5, 3, get(w, 1408), 0, 0, 0, 0, 0, 0)
    if phase == 3:
        if failed(result) and result != NEG17:
            return 0
        return call(o, w, 4, 257, get(w, 1408), 12288, 589824, 0, 0, 0, 12)
    if phase == 4:
        if failed(result) or result < 3:
            return 0
        put(w, 1416, result)
        return call(o, w, 5, 3, get(w, 1408), 0, 0, 0, 0, 0, 0)
    if phase == 5:
        if failed(result):
            return 0
        put(w, 1408, get(w, 1416))
        return next_part(o, w)
    if phase == 10:
        if failed(result) or private_directory(w, 9216) == False:
            return 0
        put(w, 384, get(w, 1408))
        at = text_fd(w, 12288)
        at = decimal(w, at, get(w, 384))
        store(w, at, 0)
        return call(o, w, 11, 89, 12288, 16384, 4096, 0, 0, 0, 15)
    if phase == 11:
        if failed(result) or result == 0 or result >= 4096 or byte(w, 16384) != 47:
            return 0
        store(w, 16384 + result, 0)
        put(w, 1432, result)
        return call(o, w, 12, 262, NEG100, 16384, 9472, 0, 0, 0, 60)
    if phase == 12:
        if failed(result) or private_directory(w, 9472) == False or equal(w, 9216, 9472, 16) == False:
            return 0
        at = get(w, 64)
        end = copy_state(w, 16384, at, get(w, 1432))
        store(w, end, 0)
        bind(w, S_STATE_ROOT, at, end - at)
        put(w, 64, end + 1)
        put(w, 1440, 0)
        return next_lock(o, w)
    if phase >= 20 and phase <= 29:
        return locks(o, w, phase, result)
    if phase >= 40 and phase <= 49:
        return subdirectories(o, w, phase, result)
    if phase >= 50 and phase <= 55:
        return replay_cache(o, w, phase, result)
    return 0

def next_part(o:mutbuf, w:mutbuf) -> u32:
    at = get(w, 1424)
    size = get(w, S_STATE_ROOT + 8)
    source = get(w, S_STATE_ROOT)
    while at < size and byte(w, source + at) == 47:
        at = at + 1
    if at == size:
        return call(o, w, 10, 5, get(w, 1408), 9216, 0, 0, 0, 0, 12)
    start = at
    while at < size and byte(w, source + at) != 47:
        at = at + 1
    if at - start > 255:
        return 0
    end = copy_state(w, source + start, 12288, at - start)
    store(w, end, 0)
    put(w, 1424, at)
    return call(o, w, 2, 257, get(w, 1408), 12288, 589824, 0, 0, 0, 12)

def private_directory(w:mutbuf, at:u64) -> bool:
    mode = getn(w, at + 24, 4)
    return mode & 61440 == 16384 and mode & 4095 == 448 and getn(w, at + 28, 4) == get(w, 24)

def next_lock(o:mutbuf, w:mutbuf) -> u32:
    index = get(w, 1440)
    if index == 2:
        put(w, 1440, 0)
        return next_directory(o, w)
    if index == 0:
        end = text_owner_lock(w, 12288)
    else:
        end = text_legacy_lock(w, 12288)
    store(w, end, 0)
    return call(o, w, 20, 257, get(w, 384), 12288, 657474, 384, 0, 0, 12)

def locks(o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if phase == 20:
        if failed(result) or result < 3:
            return 0
        put(w, 1456, result)
        return call(o, w, 21, 5, result, 9472, 0, 0, 0, 0, 12)
    if phase == 21:
        if failed(result) or safe_regular(w, 9472, 0) == False:
            return 0
        if getn(w, 9496, 4) & 63 != 0:
            if get(w, 1440) == 0:
                return 0
            return call(o, w, 22, 91, get(w, 1456), 384, 0, 0, 0, 0, 0)
        return call(o, w, 23, 73, get(w, 1456), 6, 0, 0, 0, 0, 0)
    if phase == 22:
        if failed(result):
            return 0
        return call(o, w, 23, 73, get(w, 1456), 6, 0, 0, 0, 0, 0)
    if phase == 23:
        if failed(result):
            return 0
        put(w, 392 + get(w, 1440) * 8, get(w, 1456))
        put(w, 1440, get(w, 1440) + 1)
        return next_lock(o, w)
    return 0

def next_directory(o:mutbuf, w:mutbuf) -> u32:
    index = get(w, 1440)
    if index == 2:
        end = text_replay(w, 12288)
        store(w, end, 0)
        return call(o, w, 50, 319, 12288, 3, 0, 0, 0, 0, 3)
    if index == 0:
        end = text_jobs(w, 12288)
    else:
        end = text_audit(w, 12288)
    store(w, end, 0)
    return call(o, w, 40, 258, get(w, 384), 12288, 448, 0, 0, 0, 12)

def subdirectories(o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if phase == 40:
        if failed(result) and result != NEG17:
            return 0
        return call(o, w, 41, 257, get(w, 384), 12288, 720896, 0, 0, 0, 12)
    if phase == 41:
        if failed(result) or result < 3:
            return 0
        put(w, 1456, result)
        return call(o, w, 42, 91, result, 448, 0, 0, 0, 0, 0)
    if phase == 42:
        if failed(result):
            return 0
        return call(o, w, 43, 3, get(w, 1456), 0, 0, 0, 0, 0, 0)
    if phase == 43:
        if failed(result):
            return 0
        put(w, 1440, get(w, 1440) + 1)
        return next_directory(o, w)
    return 0

def replay_cache(o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if phase == 50:
        if failed(result) or result < 3:
            return 0
        put(w, 408, result)
        return call(o, w, 51, 77, result, 8388608, 0, 0, 0, 0, 0)
    if phase == 51:
        if failed(result):
            return 0
        return call(o, w, 52, 91, get(w, 408), 384, 0, 0, 0, 0, 0)
    if phase == 52:
        if failed(result):
            return 0
        return call(o, w, 53, 72, get(w, 408), 1033, 7, 0, 0, 0, 0)
    if phase == 53:
        if failed(result):
            return 0
        return call(o, w, 54, 72, get(w, 408), 1034, 0, 0, 0, 0, 0)
    if phase == 54:
        if result != 7:
            return 0
        return enter(w, 1, 30)
    return 0
'''


def source():
    return authored(SOURCE, text={'fd': '/proc/self/fd/', 'owner_lock': 'controller.owner.lock',
        'legacy_lock': 'controller.lock', 'jobs': 'jobs', 'audit': 'audit',
        'replay': 'hia-mcp-replay-cache'})
