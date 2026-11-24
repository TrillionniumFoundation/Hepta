"""HIA four-page collector with joined, sealed read-only observations.

Each child inherits the original request and only enters the existing READ
owner. A window joins every child, validates every page and retains only its
contiguous prefix. Neither child nor parent has a launch continuation.
"""
from tools.generate_hia_mcp_job_bridge_common import authored

SOURCE=r'''
def advance(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    phase = get(w, 0)
    result = get(w, 8)
    if phase >= 90:
        return worker(o, w, phase, result)
    if phase == 0:
        put(w, 2704, get(w, 2088))
        count = get(w, 2040) - get(w, 2088)
        put(w, 2712, choose(count > 4, 4, count))
        put(w, 2720, 0)
        put(w, 2728, 0)
        put(w, 2800, 0)
        put(w, 2064, get(w, 2064) + 1)
        put(w, 2048, get(w, 2048) + get(w, 2712))
        index = 0
        while index < 256:
            store(w, 36000 + index, 0)
            index = index + 1
        return spawn(o, w)
    if phase == 1:
        row = 36000 + get(w, 2720) * 64
        if failed(result) or result < 3:
            put(w, row + 16, 1)
            put(w, row + 24, 65 << 8)
            return spawned(o, w)
        put(w, row, result)
        return call(o, w, 2, 57, 0, 0, 0, 0, 0, 0, 0)
    if phase == 2:
        row = 36000 + get(w, 2720) * 64
        if failed(result):
            put(w, row + 16, 1)
            put(w, row + 24, 65 << 8)
            return spawned(o, w)
        if result == 0:
            put(w, 2272, 1)
            put(w, 2752, get(w, row))
            offset = (get(w, 2704) + get(w, 2720)) * 16384
            put(w, 1936, choose(offset < get(w, 1920), offset, get(w, 1920)))
            put(w, 1944, choose(offset < get(w, 1928), offset, get(w, 1928)))
            put(w, 1904, 2)
            return call(o, w, 90, 157, 1, 9, 0, 0, 0, 0, 0)
        put(w, row + 8, result)
        return spawned(o, w)
    if phase == 10:
        put(w, 2736, 0)
        put(w, 2744, 0)
        return wait_next(o, w)
    if phase == 11:
        row = 36000 + get(w, 2736) * 64
        if result == NEG4:
            return call(o, w, 11, 61, get(w, row + 8), 31400, 1, 0, 0, 0, 12)
        if failed(result) or (result != 0 and result != get(w, row + 8)):
            put(w, row + 16, 1)
            put(w, row + 24, 65 << 8)
        elif result == 0:
            put(w, 2744, get(w, 2744) + 1)
        else:
            put(w, row + 16, 1)
            put(w, row + 24, getn(w, 31400, 4))
        put(w, 2736, get(w, 2736) + 1)
        return wait_next(o, w)
    if phase == 12:
        if failed(result):
            return 0
        if get(w, 9216) * 1000000000 + get(w, 9224) >= get(w, 48):
            put(w, 2736, 0)
            return kill_next(o, w)
        put(w, 31416, 0)
        put(w, 31424, 1000000)
        return call(o, w, 13, 35, 31416, 0, 0, 0, 0, 0, 3)
    if phase == 13:
        if failed(result) and result != NEG4:
            return 0
        return enter(w, 10, 10)
    if phase == 16:
        row = 36000 + get(w, 2736) * 64
        return call(o, w, 17, 61, get(w, row + 8), 31400, 0, 0, 0, 0, 12)
    if phase == 17:
        row = 36000 + get(w, 2736) * 64
        if result == NEG4:
            return call(o, w, 17, 61, get(w, row + 8), 31400, 0, 0, 0, 0, 12)
        put(w, row + 16, 1)
        put(w, row + 24, 65 << 8)
        put(w, row + 40, 2)
        put(w, 2736, get(w, 2736) + 1)
        return kill_next(o, w)
    if phase == 20:
        return collect_next(o, w)
    if phase == 21:
        if result != 15:
            return transport_error(o, w, 1)
        row = 36000 + get(w, 2728) * 64
        return call(o, w, 22, 17, get(w, row), 30600, 32, 0, 0, 0, 12)
    if phase == 22:
        if result == NEG4:
            row = 36000 + get(w, 2728) * 64
            return call(o, w, 22, 17, get(w, row), 30600, 32, 0, 0, 0, 12)
        if result != 32 or get(w, 30600) != PAGE_MAGIC or get(w, 30608) > 2 or get(w, 30616) > 8388608:
            return transport_error(o, w, 1)
        row = 36000 + get(w, 2728) * 64
        put(w, row + 32, get(w, 30616))
        put(w, row + 56, get(w, 30624))
        if get(w, 30608) != 0:
            return transport_error(o, w, get(w, 30608))
        put(w, 2816, 0)
        return page_read(o, w)
    if phase == 23:
        if result == NEG4:
            return page_read(o, w)
        row = 36000 + get(w, 2728) * 64
        if failed(result) or result == 0 or result > get(w, row + 32) - get(w, 2816):
            return transport_error(o, w, 1)
        put(w, 2816, get(w, 2816) + result)
        if get(w, 2816) < get(w, row + 32):
            return page_read(o, w)
        put(w, 624, get(w, 2816))
        return enter(w, 5, 400)
    if phase == 30:
        return close_page(o, w)
    if phase == 31:
        record_failure(w, get(w, 2200), get(w, 2208))
        return close_page(o, w)
    if phase == 33:
        put(w, 2728, get(w, 2728) + 1)
        return collect_next(o, w)
    return 0

def spawn(o:mutbuf, w:mutbuf) -> u32:
    at = text_page(w, 31300)
    store(w, at, 0)
    return call(o, w, 1, 319, 31300, 3, 0, 0, 0, 0, 3)

def spawned(o:mutbuf, w:mutbuf) -> u32:
    put(w, 2720, get(w, 2720) + 1)
    if get(w, 2720) < get(w, 2712):
        return spawn(o, w)
    return enter(w, 10, 10)

def wait_next(o:mutbuf, w:mutbuf) -> u32:
    while get(w, 2736) < get(w, 2712):
        row = 36000 + get(w, 2736) * 64
        if get(w, row + 16) == 0:
            return call(o, w, 11, 61, get(w, row + 8), 31400, 1, 0, 0, 0, 12)
        put(w, 2736, get(w, 2736) + 1)
    if get(w, 2744) == 0:
        return enter(w, 10, 20)
    return call(o, w, 12, 228, 1, 9216, 0, 0, 0, 0, 12)

def kill_next(o:mutbuf, w:mutbuf) -> u32:
    while get(w, 2736) < get(w, 2712):
        row = 36000 + get(w, 2736) * 64
        if get(w, row + 16) == 0:
            return call(o, w, 16, 62, get(w, row + 8), 9, 0, 0, 0, 0, 0)
        put(w, 2736, get(w, 2736) + 1)
    return enter(w, 10, 20)

def collect_next(o:mutbuf, w:mutbuf) -> u32:
    if get(w, 2728) == get(w, 2712):
        if get(w, 2800) != 0:
            put(w, 2200, get(w, 2784))
            put(w, 2208, get(w, 2792))
            return enter(w, 5, 700)
        return enter(w, 5, 403)
    row = 36000 + get(w, 2728) * 64
    offset = (get(w, 2704) + get(w, 2728)) * 16384
    put(w, 1936, choose(offset < get(w, 1920), offset, get(w, 1920)))
    put(w, 1944, choose(offset < get(w, 1928), offset, get(w, 1928)))
    if get(w, row + 24) != 0:
        return transport_error(o, w, choose(get(w, row + 40) == 2, 2, 1))
    return call(o, w, 21, 72, get(w, row), 1034, 0, 0, 0, 0, 0)

def page_read(o:mutbuf, w:mutbuf) -> u32:
    row = 36000 + get(w, 2728) * 64
    if get(w, row + 32) == 0:
        return transport_error(o, w, 1)
    return call(o, w, 23, 17, get(w, row), CHILD_OUT + get(w, 2816), get(w, row + 32) - get(w, 2816), 32 + get(w, 2816), 0, 0, 12)

def transport_error(o:mutbuf, w:mutbuf, cause:u64) -> u32:
    record_failure(w, 6, cause)
    return close_page(o, w)

def record_failure(w:mutbuf, stage:u64, cause:u64) -> u64:
    row = 36000 + get(w, 2728) * 64
    put(w, row + 48, stage)
    put(w, row + 40, cause)
    if get(w, 2800) == 0:
        put(w, 2800, 1)
        put(w, 2784, stage)
        put(w, 2792, cause)
    return 0

def close_page(o:mutbuf, w:mutbuf) -> u32:
    row = 36000 + get(w, 2728) * 64
    put(w, 2088, get(w, 2704) + get(w, 2728) + 1)
    if get(w, row) < 3:
        return enter(w, 10, 33)
    return call(o, w, 33, 3, get(w, row), 0, 0, 0, 0, 0, 0)

def worker(o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if phase == 90:
        if failed(result):
            return 0
        return call(o, w, 91, 110, 0, 0, 0, 0, 0, 0, 0)
    if phase == 91:
        if result != get(w, 32):
            return 0
        return call(o, w, 92, 228, 1, 9216, 0, 0, 0, 0, 12)
    if phase == 92:
        if failed(result):
            return 0
        put(w, 2760, get(w, 9216) * 1000000000 + get(w, 9224))
        return enter(w, 3, 200)
    if phase == 100:
        put(w, 2776, choose(get(w, 608) == 1, 2, choose(child_ok(w), 0, 1)))
        if child_ok(w) == False:
            put(w, 624, 0)
            return call(o, w, 103, 228, 1, 9216, 0, 0, 0, 0, 12)
        return decode(o, w, 101, CHILD_OUT, get(w, 624))
    if phase == 101:
        if result >= 4294967292:
            put(w, 2776, 1)
            put(w, 624, 0)
            return call(o, w, 103, 228, 1, 9216, 0, 0, 0, 0, 12)
        put(w, 1600, 10)
        put(w, 1608, 102)
        put(w, 1616, 3)
        return enter(w, 8, 0)
    if phase == 102:
        return call(o, w, 103, 228, 1, 9216, 0, 0, 0, 0, 12)
    if phase == 103:
        if failed(result):
            return 0
        put(w, 30600, PAGE_MAGIC)
        put(w, 30608, get(w, 2776))
        put(w, 30616, get(w, 624))
        put(w, 30624, get(w, 9216) * 1000000000 + get(w, 9224) - get(w, 2760))
        put(w, 2768, 0)
        return write_header(o, w)
    if phase == 104:
        if result == NEG4:
            return write_header(o, w)
        if failed(result) or result == 0 or result > 32 - get(w, 2768):
            return 0
        put(w, 2768, get(w, 2768) + result)
        if get(w, 2768) < 32:
            return write_header(o, w)
        put(w, 2768, 0)
        return write_payload(o, w)
    if phase == 105:
        if result == NEG4:
            return write_payload(o, w)
        if failed(result) or result == 0 or result > get(w, 624) - get(w, 2768):
            return 0
        put(w, 2768, get(w, 2768) + result)
        return write_payload(o, w)
    if phase == 106:
        if failed(result):
            return 0
        return call(o, w, 107, 60, 0, 0, 0, 0, 0, 0, 0)
    return 0

def write_header(o:mutbuf, w:mutbuf) -> u32:
    return call(o, w, 104, 1, get(w, 2752), 30600 + get(w, 2768), 32 - get(w, 2768), 0, 0, 0, 12)

def write_payload(o:mutbuf, w:mutbuf) -> u32:
    if get(w, 2768) == get(w, 624):
        return call(o, w, 106, 72, get(w, 2752), 1033, 15, 0, 0, 0, 0)
    return call(o, w, 105, 1, get(w, 2752), CHILD_OUT + get(w, 2768), get(w, 624) - get(w, 2768), 0, 0, 0, 12)
'''


def source():
    return authored(SOURCE,text={'page':'hia-mcp-read-page'},extra={'PAGE_MAGIC':int.from_bytes(b'HIAJPG01','little')})
