"""Author bounded concurrent MCP request processes and serialized replies.

Complete responses remain private until their request process has exited.
The connection can still answer discovery and ping while a durable call waits.
Capacity applies backpressure; it never retries or invents a new request key.
"""
from tools.generate_hia_mcp_service_owner_common import authored

SOURCE = r'''
def advance(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    phase = get(w, 0)
    result = get(w, 8)
    if phase == 0:
        put(w, 1600, 0)
        row = free_slot(w)
        if row == NONE:
            return scan_start(w)
        put(w, 1560, row)
        put(w, 1664, get(w, 32))
        end = text_response(w, 12288)
        store(w, end, 0)
        return call(o, w, 1, 319, 12288, 3, 0, 0, 0, 0, 3)
    if phase == 1:
        if failed(result) or result < 3:
            return 0
        put(w, 1568, result)
        end = text_failure(w, 12288)
        store(w, end, 0)
        return call(o, w, 2, 319, 12288, 3, 0, 0, 0, 0, 3)
    if phase == 2:
        if failed(result) or result < 3:
            return 0
        put(w, 1576, result)
        at = get(w, SCHEDULE_DESCRIPTOR + 16)
        size = get(w, SCHEDULE_DESCRIPTOR + 24)
        if at > get(w, 200) or size > get(w, 200) - at or size == 0:
            return 0
        put(w, 1688, 0)
        return pure(o, w, 210, P_SDK, REQUEST + at, size, PURE_OUTPUT, 8389120, PURE_WORK, 32768)
    if phase == 210:
        if result == 0 or result > 8388608:
            if get(w, 1688) == 1:
                return enter(w, 2, 30)
            return 0
        if get(w, 1688) == 0:
            end = text_error_prefix(w, PURE_INPUT)
            end = copy_state(w, PURE_OUTPUT, end, result)
            put(w, 1672, end - PURE_INPUT)
            end = text_error_suffix(w, end)
            put(w, 1584, end - PURE_INPUT)
            put(w, 1592, 0)
        return identity(o, w, 10, result)
    if phase == 3:
        if result == NEG4:
            return backup_write(o, w)
        if failed(result) or result == 0 or result > get(w, 1584) - get(w, 1592):
            return 0
        put(w, 1592, get(w, 1592) + result)
        if get(w, 1592) < get(w, 1584):
            return backup_write(o, w)
        return call(o, w, 4, 72, get(w, 1576), 1033, 15, 0, 0, 0, 0)
    if phase == 4:
        if failed(result):
            return 0
        if get(w, 440) == NONE:
            return 0
        put(w, 440, get(w, 440) + 1)
        put(w, 448, get(w, 440))
        put(w, 432, (get(w, 1560) - TASK_TABLE) // TASK_BYTES)
        return call(o, w, 20, 57, 0, 0, 0, 0, 0, 0, 0)
    if phase >= 10 and phase <= 13:
        return identity(o, w, phase, result)
    if phase == 20:
        if failed(result):
            return 0
        if result == 0:
            return call(o, w, 21, 157, 1, 9, 0, 0, 0, 0, 0)
        row = get(w, 1560)
        put(w, row, result)
        put(w, row + 8, get(w, 1568))
        put(w, row + 16, get(w, 1576))
        put(w, row + 24, 0)
        put(w, row + 32, 0)
        tool = get(w,SCHEDULE_DESCRIPTOR+32)
        metadata = get(w,SCHEDULE_DESCRIPTOR+8) == 2 and tool >= 13 and tool <= 15
        put(w,row+40,choose(metadata,1,0))
        put(w, row + 64, get(w, 1672))
        put(w, row + 80, 0)
        put(w, row + 88, 0)
        copy_state(w, 1712, row + 96, 32)
        put(w, 192, get(w, 192) + 1)
        return enter(w, 2, 30)
    if phase >= 21 and phase <= 25:
        return request_child(o, w, phase, result)
    if phase == 100:
        put(w, 1600, 1)
        return scan_start(w)
    if phase == 101:
        return scan(o, w)
    if phase == 102:
        if result == NEG4:
            return call(o, w, 102, 61, get(w, get(w, 1616)), 8256, 1, 0, 0, 0, 12)
        if failed(result) or (result != 0 and result != get(w, get(w, 1616))):
            return 0
        if result != 0:
            row = get(w, 1616)
            put(w, row + 24, 1)
            put(w, row + 32, getn(w, 8256, 4))
            put(w, 1624, row)
            return collect(o, w)
        put(w, 1608, get(w, 1608) + 1)
        return scan(o, w)
    if phase == 106:
        if failed(result) and result != NEG4:
            return 0
        if result != NEG4 and get(w, 1600) == 1 and get(w, 224) == 0 and getn(w, 8294, 2) & 57 != 0:
            return enter(w, 2, 2)
        return scan_start(w)
    if phase >= 120 and phase <= 129:
        return publication(o, w, phase, result)
    if phase == 131 or phase == 132:
        return large_publication(o,w,phase,result)
    if phase >= 200 and phase <= 202:
        return cancellation(o, w, phase, result)
    return 0

def free_slot(w:mutbuf) -> u64:
    index = 0
    while index < TASK_COUNT:
        row = TASK_TABLE + index * TASK_BYTES
        if get(w, row) == 0:
            return row
        index = index + 1
    return NONE

def backup_write(o:mutbuf, w:mutbuf) -> u32:
    return call(o, w, 3, 1, get(w, 1576), PURE_INPUT + get(w, 1592), get(w, 1584) - get(w, 1592), 0, 0, 0, 12)

def request_child(o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if failed(result):
        return 0
    if phase == 21:
        return call(o, w, 22, 110, 0, 0, 0, 0, 0, 0, 0)
    if phase == 22:
        if result != get(w, 1664):
            return 0
        return call(o, w, 23, 39, 0, 0, 0, 0, 0, 0, 0)
    if phase == 23:
        if result == 0:
            return 0
        put(w, 32, result)
        return call(o, w, 24, 33, get(w, 1568), 1, 0, 0, 0, 0, 0)
    if phase == 24:
        if result != 1:
            return 0
        put(w, 184, 1)
        copy_state(w, SCHEDULE_DESCRIPTOR, SESSION_OUT, 96)
        put(w, 50000, 1)
        put(w, 50008, 64 + get(w, 432))
        put(w, 50016, 1)
        put(w, 50024, 0)
        return call(o, w, 25, 72, get(w, 416), 6, 50000, 0, 0, 0, 48)
    if phase == 25:
        if result != 0:
            return 0
        return enter(w, 3, 0)
    return 0

def scan_start(w:mutbuf) -> u32:
    put(w, 1608, 0)
    return enter(w, 6, 101)

def scan(o:mutbuf, w:mutbuf) -> u32:
    index = get(w, 1608)
    while index < TASK_COUNT:
        row = TASK_TABLE + index * TASK_BYTES
        if get(w, row) != 0:
            if get(w, row + 24) != 0:
                put(w, 1624, row)
                return collect(o, w)
            put(w, 1608, index)
            put(w, 1616, row)
            return call(o, w, 102, 61, get(w, row), 8256, 1, 0, 0, 0, 12)
        index = index + 1
    if get(w, 1600) == 0 and free_slot(w) != NONE:
        return enter(w, 6, 0)
    if get(w, 224) == 1 and get(w, 192) == 0:
        return call(o, w, 999, 60, choose(get(w, SESSION_PHASE) == 0, 1, 0), 0, 0, 0, 0, 0, 0)
    descriptor = choose(get(w, 1600) == 1 and get(w, 224) == 0, 0, 4294967295)
    put(w, 8288, descriptor | 4294967296)
    return call(o, w, 106, 7, 8288, 1, 100, 0, 0, 0, 3)

def collect(o:mutbuf, w:mutbuf) -> u32:
    row = get(w, 1624)
    descriptor = choose(get(w, row + 32) == 0 and get(w, row + 80) == 0, get(w, row + 8), get(w, row + 16))
    put(w, 1632, descriptor)
    put(w, 1656, 0)
    return call(o, w, 120, 5, descriptor, 9216, 0, 0, 0, 0, 12)

def fallback(o:mutbuf, w:mutbuf) -> u32:
    row = get(w, 1624)
    if get(w, 1632) == get(w, row + 16):
        return 0
    put(w, 1632, get(w, row + 16))
    return call(o, w, 120, 5, get(w, 1632), 9216, 0, 0, 0, 0, 12)

def publication(o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if phase == 120:
        maximum = choose(get(w,get(w,1624)+40) == 1,METADATA_REPLY_MAX,8389120)
        if failed(result) or get(w, 9264) < 2 or get(w, 9264) > maximum:
            return fallback(o, w)
        put(w, 1640, get(w, 9264))
        if get(w, 1632) == get(w, get(w, 1624) + 8):
            return call(o, w, 122, 72, get(w, 1632), 1033, 15, 0, 0, 0, 0)
        return read_result(o, w)
    if phase == 122:
        if failed(result):
            return fallback(o, w)
        if get(w,1640) > 8389120:
            return large_begin(o,w)
        return read_result(o, w)
    if phase == 123:
        if result == NEG4:
            return read_result(o, w)
        if failed(result) or result == 0 or result > get(w, 1640) - get(w, 1656):
            return 0
        put(w, 1656, get(w, 1656) + result)
        if get(w, 1656) < get(w, 1640):
            return read_result(o, w)
        if get(w, get(w, 1624) + 80) != 0:
            end = text_cancel_suffix(w, SESSION_OUT + get(w, get(w, 1624) + 64))
            put(w, 1640, end - SESSION_OUT)
        put(w, 1648, 0)
        return write_result(o, w)
    if phase == 124:
        if result == NEG4:
            return write_result(o, w)
        if failed(result) or result == 0 or result > get(w, 1640) - get(w, 1648):
            return 0
        put(w, 1648, get(w, 1648) + result)
        if get(w, 1648) < get(w, 1640):
            return write_result(o, w)
        return call(o, w, 125, 3, get(w, get(w, 1624) + 8), 0, 0, 0, 0, 0, 0)
    if phase == 125:
        if failed(result):
            return 0
        return call(o, w, 126, 3, get(w, get(w, 1624) + 16), 0, 0, 0, 0, 0, 0)
    if phase == 126:
        if failed(result):
            return 0
        put(w, get(w, 1624), 0)
        put(w, get(w, 1624) + 24, 0)
        put(w, 192, get(w, 192) - 1)
        if get(w, 1600) == 0:
            return enter(w, 6, 0)
        return scan_start(w)
    return 0

def read_result(o:mutbuf, w:mutbuf) -> u32:
    return call(o, w, 123, 17, get(w, 1632), SESSION_OUT + get(w, 1656), get(w, 1640) - get(w, 1656), get(w, 1656), 0, 0, 12)

def write_result(o:mutbuf, w:mutbuf) -> u32:
    return call(o, w, 124, 1, 1, SESSION_OUT + get(w, 1648), get(w, 1640) - get(w, 1648), 0, 0, 0, 12)

def identity(o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if phase == 10:
        if result == 0 or result > 8388608:
            return 0
        put(w, 1480, PURE_OUTPUT)
        put(w, 1488, result)
        put(w, 1496, 0)
        return sha(o, w, 11, 0, 1)
    if phase == 11 or phase == 12:
        if result != 0:
            return 0
        if get(w, 1496) == get(w, 1488):
            return sha(o, w, 13, 2, 1)
        size = get(w, 1488) - get(w, 1496)
        if size > 65536:
            size = 65536
        copy_state(w, get(w, 1480) + get(w, 1496), SHA_INPUT + 1, size)
        put(w, 1496, get(w, 1496) + size)
        return sha(o, w, 12, 1, size + 1)
    if phase == 13:
        if result != 32:
            return 0
        if get(w, 1688) == 0:
            copy_state(w, SHA_OUTPUT, 1712, 32)
            return backup_write(o, w)
        index = 0
        while index < TASK_COUNT:
            row = TASK_TABLE + index * TASK_BYTES
            if get(w, row) != 0 and get(w, row + 24) == 0 and equal(w, row + 96, SHA_OUTPUT, 32):
                put(w, 1704, row)
                return call(o, w, 201, 61, get(w, row), 8256, 1, 0, 0, 0, 12)
            index = index + 1
        return enter(w, 2, 30)
    return 0

def cancellation(o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if phase == 200:
        at = get(w, SCHEDULE_DESCRIPTOR + 16)
        size = get(w, SCHEDULE_DESCRIPTOR + 24)
        if at > get(w, 200) or size > get(w, 200) - at or size == 0:
            return 0
        put(w, 1688, 1)
        return pure(o, w, 210, P_SDK, REQUEST + at, size, PURE_OUTPUT, 8389120, PURE_WORK, 32768)
    if phase == 201:
        row = get(w, 1704)
        if result == NEG4:
            return call(o, w, 201, 61, get(w, row), 8256, 1, 0, 0, 0, 12)
        if failed(result) or (result != 0 and result != get(w, row)):
            return 0
        if result != 0:
            put(w, row + 24, 1)
            put(w, row + 32, getn(w, 8256, 4))
            return enter(w, 2, 30)
        return call(o, w, 202, 62, get(w, row), 9, 0, 0, 0, 0, 0)
    if phase == 202:
        if result == 0:
            put(w, get(w, 1704) + 80, 1)
        return enter(w, 2, 30)
    return 0

def large_begin(o:mutbuf,w:mutbuf) -> u32:
    return large_read(o,w)

def large_read(o:mutbuf,w:mutbuf) -> u32:
    used = get(w,1656)
    size = get(w,1640)-used
    if size > 65536:
        size = 65536
    return call(o,w,131,17,get(w,1632),SESSION_OUT,size,used,0,0,12)

def large_write(o:mutbuf,w:mutbuf) -> u32:
    used = get(w,1648)
    return call(o,w,132,1,1,SESSION_OUT+used,get(w,PUBLISH_CHUNK)-used,0,0,0,12)

def large_publication(o:mutbuf,w:mutbuf,phase:u64,result:u64) -> u32:
    if phase == 131:
        if result == NEG4:
            return large_read(o,w)
        if failed(result) or result == 0 or result > 65536 or result > get(w,1640)-get(w,1656):
            return 0
        put(w,1656,get(w,1656)+result)
        put(w,PUBLISH_CHUNK,result)
        put(w,1648,0)
        return large_write(o,w)
    if result == NEG4:
        return large_write(o,w)
    if failed(result) or result == 0 or result > get(w,PUBLISH_CHUNK)-get(w,1648):
        return 0
    put(w,1648,get(w,1648)+result)
    if get(w,1648) != get(w,PUBLISH_CHUNK):
        return large_write(o,w)
    if get(w,1656) < get(w,1640):
        return large_read(o,w)
    return call(o,w,125,3,get(w,get(w,1624)+8),0,0,0,0,0,0)

'''


def source():
    return authored(SOURCE, text={'response': 'hia-mcp-response', 'failure': 'hia-mcp-failure',
        'error_prefix': '{"jsonrpc":"2.0","id":',
        'error_suffix': ',"error":{"code":-32603,"message":"Native HIA request observation unavailable; repeat only the original request"}}\n',
        'cancel_suffix': ',"error":{"code":-32800,"message":"Request cancelled"}}\n'}, extra={
        'METADATA_REPLY_MAX': (72 << 20)+512,
        'PUBLISH_CHUNK': (128 << 20)+66000})
