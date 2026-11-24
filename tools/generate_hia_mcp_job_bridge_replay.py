"""HIA parent-lifetime predecessor replay snapshots under the owner POSIX lock.

The parent supplies one zero-initialized, fixed-size writable memfd. HIA alone
selects, validates and publishes two independently committed bounded snapshots.
An unchanged authority/root/epoch never reinterprets a changed predecessor
namespace as a missing old identity. Failed scans preserve the previous slot.
"""
from tools.generate_hia_mcp_job_bridge_common import authored

SOURCE=r'''
def advance(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    phase = get(w, 0)
    result = get(w, 8)
    if phase >= 100:
        return publication(o, w, phase, result)
    if phase >= 20:
        return cached_body(o, w, phase, result)
    if phase == 0:
        put(w, 2880, NONE)
        put(w, 2888, 0)
        if get(w, 272) == 0:
            return enter(w, 2, 83)
        return call(o, w, 1, 72, get(w, 272), 1034, 0, 0, 0, 0, 0)
    if phase == 1:
        if result != 7:
            return 0
        return call(o, w, 2, 5, get(w, 272), 9216, 0, 0, 0, 0, 12)
    if phase == 2:
        if failed(result) or getn(w, 9240, 4) & 65535 != 33152 or getn(w, 9244, 4) != get(w, 24) or get(w, 9232) != 0 or get(w, 9264) != 8388608:
            return 0
        return call(o, w, 3, 5, get(w, 1304), 15360, 0, 0, 0, 0, 12)
    if phase == 3:
        if failed(result):
            return 0
        return sha(o, w, 4, 0, 1)
    if phase == 4:
        if result != 0:
            return 0
        at = cp(w, S_HOST, SHA_INPUT + 1)
        store(w, at, 0)
        at = cp(w, S_JOB_KEY, at + 1)
        return sha(o, w, 5, 1, at - SHA_INPUT)
    if phase == 5:
        if result != 0:
            return 0
        return sha(o, w, 6, 2, 1)
    if phase == 6:
        if result != 32:
            return 0
        copy_state(w, SHA_OUTPUT, 220512, 32)
        put(w, 2896, 0)
        return read_header(o, w)
    if phase == 10:
        if result == NEG4:
            return read_header(o, w)
        if result != 128:
            return 0
        header = 32000 + get(w, 2896) * 128
        if get(w, header) != 0:
            if header_valid(w, header) == False:
                return 0
            generation = get(w, header + 8)
            if generation == get(w, 2888):
                return 0
            if generation > get(w, 2888):
                put(w, 2888, generation)
                put(w, 2880, get(w, 2896))
        if get(w, 2896) == 0:
            put(w, 2896, 1)
            return read_header(o, w)
        if get(w, 2880) == NONE:
            return enter(w, 2, 83)
        header = 32000 + get(w, 2880) * 128
        put(w, 2912, get(w, header + 16))
        put(w, 2920, 0)
        return read_body(o, w)
    return 0

def read_header(o:mutbuf, w:mutbuf) -> u32:
    return call(o, w, 10, 17, get(w, 272), 32000 + get(w, 2896) * 128, 128, get(w, 2896) * 4194304, 0, 0, 12)

def header_valid(w:mutbuf, header:u64) -> bool:
    if get(w, header) != REPLAY_MAGIC or get(w, header + 8) == 0 or get(w, header + 24) > 65536 or get(w, header + 32) == 0 or get(w, header + 56) != 0:
        return False
    a = get(w, header + 40)
    b = get(w, header + 48)
    if a == 0 or a > 4096 or b == 0 or b > 4096 or get(w, header + 16) != 432 + a + b + get(w, header + 24) * 32:
        return False
    return get(w, header + 96) == 0 and get(w, header + 104) == 0 and get(w, header + 112) == 0 and get(w, header + 120) == 0

def read_body(o:mutbuf, w:mutbuf) -> u32:
    return call(o, w, 20, 17, get(w, 272), ARENA + get(w, 2920), get(w, 2912) - get(w, 2920), get(w, 2880) * 4194304 + 128 + get(w, 2920), 0, 0, 12)

def cached_body(o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if phase == 20:
        if result == NEG4:
            return read_body(o, w)
        if failed(result) or result == 0 or result > get(w, 2912) - get(w, 2920):
            return 0
        put(w, 2920, get(w, 2920) + result)
        if get(w, 2920) < get(w, 2912):
            return read_body(o, w)
        put(w, 2928, 0)
        return sha(o, w, 21, 0, 1)
    if phase == 21 or phase == 22:
        if result != 0:
            return 0
        if get(w, 2928) == get(w, 2912):
            return sha(o, w, 23, 2, 1)
        return hash_body(o, w, 22)
    if phase == 23:
        header = 32000 + get(w, 2880) * 128
        if result != 32 or equal(w, SHA_OUTPUT, header + 64, 32) == False:
            return 0
        if snapshot_matches(w, header) == False:
            return enter(w, 2, 83)
        if owner_stamp_equal(w, ARENA + 288, 15360) == False:
            return 0
        at = ARENA + 432 + get(w, header + 40) + get(w, header + 48)
        index = 0
        while index < get(w, header + 24):
            if equal(w, 220512, at + index * 32, 32):
                return 0
            index = index + 1
        return close_predecessor(o, w)
    return 0

def hash_body(o:mutbuf, w:mutbuf, phase:u64) -> u32:
    size = get(w, 2912) - get(w, 2928)
    if size > 65536:
        size = 65536
    copy_state(w, ARENA + get(w, 2928), SHA_INPUT + 1, size)
    put(w, 2928, get(w, 2928) + size)
    return sha(o, w, phase, 1, size + 1)

def owner_stamp_equal(w:mutbuf, left:u64, right:u64) -> bool:
    return get(w, left) == get(w, right) and get(w, left + 8) == get(w, right + 8) and get(w, left + 16) == get(w, right + 16) and getn(w, left + 24, 4) == getn(w, right + 24, 4) and getn(w, left + 28, 4) == getn(w, right + 28, 4) and get(w, left + 48) == get(w, right + 48) and equal(w, left + 88, right + 88, 32)

def snapshot_matches(w:mutbuf, header:u64) -> bool:
    a = get(w, header + 40)
    b = get(w, header + 48)
    if get(w, header + 32) != get(w, 1744) or get(w, ARENA) != get(w, 17408) or get(w, ARENA + 8) != get(w, 17416) or get(w, ARENA + 144) != get(w, 17792) or get(w, ARENA + 152) != get(w, 17800):
        return False
    if owner_stamp_equal(w, ARENA, 17408) == False:
        return False
    return path_equal(w, ARENA + 432, a, get(w, S_FENCE_ROOT), get(w, S_FENCE_ROOT + 8)) and path_equal(w, ARENA + 432 + a, b, get(w, S_PREDECESSOR), get(w, S_PREDECESSOR + 8))

def publication(o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if phase == 100:
        if get(w, 272) == 0:
            return close_predecessor(o, w)
        if get(w, 2888) == NONE:
            return 0
        put(w, 2952, choose(get(w, 2880) == 0, 1, 0))
        put(w, 2960, get(w, 2888) + 1)
        if prepare_snapshot(w) == False:
            return 0
        put(w, 2928, 0)
        return sha(o, w, 101, 0, 1)
    if phase == 101 or phase == 102:
        if result != 0:
            return 0
        if get(w, 2928) == get(w, 2912):
            return sha(o, w, 103, 2, 1)
        return hash_body(o, w, 102)
    if phase == 103:
        if result != 32:
            return 0
        copy_state(w, SHA_OUTPUT, 32448, 32)
        put(w, 32640, 0)
        return call(o, w, 110, 18, get(w, 272), 32640, 8, get(w, 2952) * 4194304, 0, 0, 12)
    if phase == 110:
        if result == NEG4:
            return call(o, w, 110, 18, get(w, 272), 32640, 8, get(w, 2952) * 4194304, 0, 0, 12)
        if result != 8:
            return 0
        put(w, 2944, 0)
        return write_body(o, w)
    if phase == 111:
        if result == NEG4:
            return write_body(o, w)
        if failed(result) or result == 0 or result > get(w, 2912) - get(w, 2944):
            return 0
        put(w, 2944, get(w, 2944) + result)
        if get(w, 2944) < get(w, 2912):
            return write_body(o, w)
        return call(o, w, 112, 18, get(w, 272), 32392, 120, get(w, 2952) * 4194304 + 8, 0, 0, 12)
    if phase == 112:
        if result == NEG4:
            return call(o, w, 112, 18, get(w, 272), 32392, 120, get(w, 2952) * 4194304 + 8, 0, 0, 12)
        if result != 120:
            return 0
        return call(o, w, 113, 18, get(w, 272), 32384, 8, get(w, 2952) * 4194304, 0, 0, 12)
    if phase == 113:
        if result == NEG4:
            return call(o, w, 113, 18, get(w, 272), 32384, 8, get(w, 2952) * 4194304, 0, 0, 12)
        if result != 8:
            return 0
        return close_predecessor(o, w)
    if phase == 130:
        if failed(result) or get(w, 1480) != 0:
            return 0
        return enter(w, 6, 40)
    return 0

def prepare_snapshot(w:mutbuf) -> bool:
    copy_state(w, 17408, ARENA, 144)
    copy_state(w, 17792, ARENA + 144, 144)
    copy_state(w, 15360, ARENA + 288, 144)
    at = cp(w, S_FENCE_ROOT, ARENA + 432)
    at = cp(w, S_PREDECESSOR, at)
    count = 0
    index = 0
    while index < 131072:
        if byte(w, 229376 + index // 8) & (1 << (index % 8)) != 0:
            at = copy_state(w, SCAN_HASHES + index * 32, at, 32)
            count = count + 1
        index = index + 1
    if count != get(w, 1456) or count > 65536 or at - ARENA > 4194176:
        return False
    put(w, 2912, at - ARENA)
    index = 0
    while index < 128:
        store(w, 32384 + index, 0)
        index = index + 1
    put(w, 32384, REPLAY_MAGIC)
    put(w, 32392, get(w, 2960))
    put(w, 32400, get(w, 2912))
    put(w, 32408, count)
    put(w, 32416, get(w, 1744))
    put(w, 32424, get(w, S_FENCE_ROOT + 8))
    put(w, 32432, get(w, S_PREDECESSOR + 8))
    return True

def write_body(o:mutbuf, w:mutbuf) -> u32:
    return call(o, w, 111, 18, get(w, 272), ARENA + get(w, 2944), get(w, 2912) - get(w, 2944), get(w, 2952) * 4194304 + 128 + get(w, 2944), 0, 0, 12)

def close_predecessor(o:mutbuf, w:mutbuf) -> u32:
    return call(o, w, 130, 3, get(w, 1304), 0, 0, 0, 0, 0, 0)
'''

def source():
    return authored(SOURCE,extra={'REPLAY_MAGIC':int.from_bytes(b'HIAJRC01','little')})
