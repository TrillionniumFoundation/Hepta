"""HIA bootstrap admission and immutable fixed-role custody."""
from tools.generate_hia_mcp_job_bridge_common import authored

SOURCE = r'''
def advance(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    phase = get(w, 0)
    result = get(w, 8)
    if phase == 0:
        if length(w) != STATE_BYTES or length(o) != 128 or admit(s, w) == 0:
            return 0
        return call(o, w, 1, 107, 0, 0, 0, 0, 0, 0, 0)
    if phase == 1:
        put(w, 24, result)
        return call(o, w, 2, 39, 0, 0, 0, 0, 0, 0, 0)
    if phase == 2:
        put(w, 32, result)
        return call(o, w, 3, 110, 0, 0, 0, 0, 0, 0, 0)
    if phase == 3:
        if result != get(w, 40):
            return 0
        return call(o, w, 4, 228, 1, 8192, 0, 0, 0, 0, 12)
    if phase == 4:
        if failed(result) or get(w, 8192) * 1000000000 + get(w, 8200) >= get(w, 48):
            return 0
        put(w, 128, 0)
        return next_image(s, o, w)
    if phase >= 10 and phase <= 19:
        return image(s, o, w, phase, result)
    if phase == 900:
        return call(o, w, 901, 1, 1, get(w, 704) + get(w, 720), get(w, 712) - get(w, 720), 0, 0, 0, 12)
    if phase == 901:
        if result == NEG4:
            return enter(w, 0, 900)
        if failed(result) or result == 0 or result > get(w, 712) - get(w, 720):
            return 0
        put(w, 720, get(w, 720) + result)
        if get(w, 720) < get(w, 712):
            return enter(w, 0, 900)
        return call(o, w, 999, 60, 0, 0, 0, 0, 0, 0, 0)
    return 0

def admit(s:readbuf, w:mutbuf) -> u64:
    if length(s) < 904 or length(s) > INPUT_BYTES or uint(s, 0) != BOOT_MAGIC:
        return 0
    if uint(s, 32) != 12 or uint(s, 56) > 7 or uint(s, 16) < 2 or uint(s, 16) > 2147483647:
        return 0
    if uint(s, 56) & 4 != 0 and uint(s, 56) & 2 == 0:
        return 0
    business = uint(s, 8)
    fence = uint(s, 40)
    owner = uint(s, 48)
    if business < 72 or business > INPUT_BYTES - 832 or fence > 4096 or owner > 3:
        return 0
    lease = choose(uint(s, 56) & 2 != 0, choose(uint(s, 56) & 4 != 0, 40, 32), 0)
    prefix = 832 + lease
    if length(s) != prefix + fence + owner + business:
        return 0
    if lease != 0:
        if uint(s, 832) != choose(lease == 40, LEASE_CACHE_MAGIC, LEASE_MAGIC):
            return 0
        index = 0
        while index < choose(lease == 40, 4, 3):
            descriptor = uint(s, 840 + index * 8)
            if descriptor < 3 or descriptor > 2147483647:
                return 0
            earlier = 0
            while earlier < index:
                if descriptor == uint(s, 840 + earlier * 8):
                    return 0
                earlier = earlier + 1
            role = 0
            while role < 12:
                if descriptor == uint(s, 72 + role * 64):
                    return 0
                role = role + 1
            put(w, choose(index == 3, 272, 240 + index * 8), descriptor)
            index = index + 1
        put(w, 264, 1)
    if (fence == 0) != (owner == 0) or (fence == 0 and uint(s, 56) & 1 != 0):
        return 0
    put(w, 40, uint(s, 16))
    put(w, 48, uint(s, 24))
    put(w, 56, business)
    put(w, 64, CACHE)
    at = CACHE
    if fence != 0:
        copy_input(s, w, prefix, at, fence)
        store(w, at + fence, 0)
        if filesystem_path_ok(w, at, fence) == False:
            return 0
        bind(w, S_FENCE_ROOT, at, fence)
        at = at + fence + 1
        copy_input(s, w, prefix + fence, at, owner)
        if text_is(w, at, owner, 0) == False and text_is(w, at, owner, 1) == False:
            return 0
        bind(w, S_SELF_OWNER, at, owner)
        at = at + owner
    put(w, 64, at)
    start = prefix + fence + owner
    copy_input(s, w, start, INITIAL, business)
    if get(w, INITIAL) != BUSINESS_MAGIC or get(w, INITIAL + 56) != 64 or get(w, INITIAL + 64) != 0:
        return 0
    cursor = INITIAL + 72
    index = 0
    while index < 7:
        size = get(w, INITIAL + 8 + index * 8)
        cap = choose(index < 5, 524288, choose(index == 5, 4096, 64))
        if size == 0 or size > cap or size > INITIAL + business - cursor:
            return 0
        bind(w, TABLE + index * 16, cursor, size)
        cursor = cursor + size
        index = index + 1
    if cursor != INITIAL + business or filesystem_path_ok(w, get(w, S_STATE_ROOT), get(w, S_STATE_ROOT + 8)) == False or lowerhex(w, get(w, S_CATALOG), 64) == False:
        return 0
    index = 0
    while index < 12:
        row = 64 + index * 64
        descriptor = uint(s, row + 8)
        size = uint(s, row + 16)
        if uint(s, row) != index + 1 or descriptor < 3 or descriptor > 2147483647 or size < 64 or size > 16777216 or uint(s, row + 56) != 0:
            return 0
        if index != 10 and size > 4194304:
            return 0
        earlier = 0
        while earlier < index:
            if descriptor == uint(s, 72 + earlier * 64):
                return 0
            earlier = earlier + 1
        put(w, 4096 + index * 64, descriptor)
        put(w, 4104 + index * 64, size)
        copy_input(s, w, row + 24, 4112 + index * 64, 32)
        index = index + 1
    return 1

def next_image(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if get(w, 128) == 12:
        return enter(w, 1, 0)
    put(w, 136, 4096 + get(w, 128) * 64)
    put(w, 144, 0)
    return call(o, w, 10, 72, get(w, get(w, 136)), 1034, 0, 0, 0, 0, 0)

def image(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if phase == 10:
        if result != 15:
            return 0
        return call(o, w, 11, 5, get(w, get(w, 136)), 8192, 0, 0, 0, 0, 12)
    if phase == 11:
        if failed(result) or getn(w, 8216, 4) & 61440 != 32768 or get(w, 8240) != get(w, get(w, 136) + 8):
            return 0
        return sha(o, w, 12, 0, 1)
    if phase == 12 or phase == 14:
        if result != 0:
            return 0
        if get(w, 144) == get(w, get(w, 136) + 8):
            return sha(o, w, 15, 2, 1)
        return image_read(o, w)
    if phase == 13:
        if result == NEG4:
            return image_read(o, w)
        expected = get(w, get(w, 136) + 8) - get(w, 144)
        if expected > 65536:
            expected = 65536
        if result != expected:
            return 0
        if get(w, 144) == 0:
            if getn(w, SHA_INPUT + 1, 7) != ELF_PREFIX or getn(w, SHA_INPUT + 19, 2) != 62:
                return 0
            kind = getn(w, SHA_INPUT + 17, 2)
            if kind != 2 and (get(w, 128) != 10 or kind != 3):
                return 0
        put(w, 144, get(w, 144) + result)
        return sha(o, w, 14, 1, result + 1)
    if phase == 15:
        if result != 32 or equal(w, SHA_OUTPUT, get(w, 136) + 16, 32) == False:
            return 0
        return call(o, w, 16, 72, get(w, get(w, 136)), 2, 1, 0, 0, 0, 0)
    if phase == 16:
        if failed(result):
            return 0
        put(w, 128, get(w, 128) + 1)
        return next_image(s, o, w)
    return 0

def image_read(o:mutbuf, w:mutbuf) -> u32:
    size = get(w, get(w, 136) + 8) - get(w, 144)
    if size > 65536:
        size = 65536
    return call(o, w, 13, 17, get(w, get(w, 136)), SHA_INPUT + 1, size, get(w, 144), 0, 0, 12)
'''

def source():
    return authored(SOURCE,extra={'LEASE_MAGIC':int.from_bytes(b'HIAOWN01','little'),
      'LEASE_CACHE_MAGIC':int.from_bytes(b'HIAOWN02','little'),
      'BOOT_MAGIC':int.from_bytes(b'HIAMBI01','little'),
                    'BUSINESS_MAGIC':int.from_bytes(b'HIAMJB01','little'),
                    'ELF_PREFIX':int.from_bytes(b'\x7fELF\x02\x01\x01','little'),
                    '_checks':('v4','v11')})
