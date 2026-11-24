"""Native request audit channel with one daemon for the controller lifetime.

Atomic packets and slot generations preserve independent request cancellation.
The daemon retains shared layout capabilities and each live ticket descriptor.
"""
from tools.generate_hia_mcp_service_owner_common import authored

SOURCE = r'''
def advance(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    phase = get(w, 0)
    result = get(w, 8)
    if phase == 0:
        put(w, 2016, 1)
        put(w, 2024, 0)
        mode = get(w, 1920)
        if mode == 2:
            if get(w, 456) != 1 or get(w, 1904) < 1 or get(w, 1864) < 3:
                put(w, 456, 0)
                return audit_return(w)
            finish_frame(w)
            return acquire_channel(o, w)
        put(w, 456, 0)
        if begin_frame(w) == False:
            return audit_return(w)
        if mode == 1:
            if get(w, 1904) < 1 or get(w, 1864) < 3:
                return audit_return(w)
            return acquire_channel(o, w)
        put(w, 1856, NONE)
        put(w, 1864, NONE)
        put(w, 1904, 0)
        return call(o, w, 1, 53, 1, 524293, 0, 50240, 0, 0, 192)
    if phase >= 1 and phase <= 4:
        return prepare_channel(o, w, phase, result)
    if phase == 20:
        if failed(result):
            return audit_fail(o, w)
        if result == 0:
            return call(o, w, 60, 157, 1, 9, 0, 0, 0, 0, 0)
        put(w, 1904, result)
        return call(o, w, 21, 3, get(w, 1856), 0, 0, 0, 0, 0, 0)
    if phase == 21:
        put(w, 1856, NONE)
        if result != 0:
            return audit_fail(o, w)
        return acquire_channel(o, w)
    if phase == 25:
        if result == NEG4:
            return acquire_channel(o, w)
        if result != 0:
            return audit_fail(o, w)
        put(w, 2024, 1)
        return write_packet(o, w)
    if phase == 26:
        if result == NEG4:
            return write_packet(o, w)
        if result == NEG11:
            return poll_channel(o, w, 27, 4)
        if result != get(w, 1936):
            return audit_fail(o, w)
        return read_packet(o, w)
    if phase == 27:
        if failed(result) and result != NEG4:
            return audit_fail(o, w)
        return write_packet(o, w)
    if phase == 40:
        return received(o, w, result)
    if phase == 41:
        if failed(result) and result != NEG4:
            return audit_fail(o, w)
        return read_packet(o, w)
    if phase == 42:
        if result == NEG4:
            return call(o, w, 42, 61, get(w, 1904), 50264, 1, 0, 0, 0, 12)
        if result != 0:
            put(w, 1904, 0)
            return audit_fail(o, w)
        put(w, 2016, 0)
        return release_channel(o, w, 50)
    if phase == 50:
        put(w, 2024, 0)
        if result != 0:
            return audit_fail(o, w)
        return audit_return(w)
    if phase >= 60 and phase <= 69:
        return child_setup(o, w, phase, result)
    if phase >= 80 and phase <= 85:
        return teardown(o, w, phase, result)
    return audit_fail(o, w)

def prepare_channel(o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if failed(result):
        return audit_fail(o, w)
    if phase == 1:
        put(w, 1856, getn(w, 50240, 4))
        put(w, 1864, getn(w, 50244, 4))
        if get(w, 1856) < 3 or get(w, 1864) < 3 or get(w, 1856) == get(w, 1864):
            return audit_fail(o, w)
        return call(o, w, 2, 72, get(w, 1864), 4, 2048, 0, 0, 0, 0)
    if phase == 2:
        end = text_helper(w, 50816)
        store(w, end, 0)
        put(w, 50944, 50816)
        put(w, 50952, NONE)
        store(w, 51008, 0)
        return relocate(o, w, 3, 50944, 2, 51024)
    if phase == 3:
        return relocate(o, w, 4, 53248, get(w, 104) + 1, 55296)
    return call(o, w, 20, 57, 0, 0, 0, 0, 0, 0, 0)

# Byte one serializes complete packet/reply exchanges. Byte zero remains the
# audit daemon's independent durable-store mutex; each worker holds its own
# byte 64+slot lease until exit. A cancelled caller releases only its locks.
def acquire_channel(o:mutbuf, w:mutbuf) -> u32:
    zero_frame(w, 50112, 32)
    put(w, 50112, 1)
    put(w, 50120, 1)
    put(w, 50128, 1)
    return call(o, w, 25, 72, get(w, 416), 7, 50112, 0, 0, 0, 48)

def release_channel(o:mutbuf, w:mutbuf, phase:u64) -> u32:
    put(w, 50112, 2)
    return call(o, w, phase, 72, get(w, 416), 6, 50112, 0, 0, 0, 48)

def write_packet(o:mutbuf, w:mutbuf) -> u32:
    return call(o, w, 26, 44, get(w, 1864), AUDIT_WIRE, get(w, 1936), 16384, 0, 0, 12)

def read_packet(o:mutbuf, w:mutbuf) -> u32:
    return call(o, w, 40, 45, get(w, 1864), AUDIT_REPLY, 513, 0, 0, 0, 12)

def poll_channel(o:mutbuf, w:mutbuf, phase:u64, events:u64) -> u32:
    put(w, 50272, get(w, 1864) | (events << 32))
    return call(o, w, phase, 7, 50272, 1, 100, 0, 0, 0, 3)

def received(o:mutbuf, w:mutbuf, result:u64) -> u32:
    if result == NEG4:
        return read_packet(o, w)
    if result == NEG11:
        return poll_channel(o, w, 41, 1)
    if result != 512 or response_shape(w) == False:
        return audit_fail(o, w)
    mode = get(w, 1920)
    slot = get(w, AUDIT_REPLY + 88)
    generation = get(w, AUDIT_REPLY + 96)
    if mode != 0 and (slot != get(w, 432) or generation != get(w, 448)):
        if slot >= 32 or generation == 0 or get(w, AUDIT_REPLY + 16) == 0:
            return audit_fail(o, w)
        # The packet from a cancelled predecessor is consumed under the same
        # channel lease; it cannot be mistaken for this live slot generation.
        return read_packet(o, w)
    if response_ok(w) == False:
        return audit_fail(o, w)
    if mode == 0:
        return call(o, w, 42, 61, get(w, 1904), 50264, 1, 0, 0, 0, 12)
    if mode == 1:
        copy_state(w, AUDIT_REPLY + 128, 50624, 64)
        bind(w, S_AUDIT_ID, 50624, 64)
        put(w, 456, 1)
    else:
        put(w, 456, 0)
    put(w, 2016, 0)
    return release_channel(o, w, 50)

def response_shape(w:mutbuf) -> bool:
    if get(w, AUDIT_REPLY) != AUDIT_RESPONSE_MAGIC or get(w, AUDIT_REPLY + 8) != 1:
        return False
    if get(w, AUDIT_REPLY + 16) > 2 or get(w, AUDIT_REPLY + 24) > 2:
        return False
    id_bytes = get(w, AUDIT_REPLY + 40)
    if (id_bytes != 0 and id_bytes != 64) or get(w, AUDIT_REPLY + 48) > 1 or get(w, AUDIT_REPLY + 72) > 1:
        return False
    error = get(w, AUDIT_REPLY + 104)
    if error > 256 or get(w, AUDIT_REPLY + 112) != 0 or get(w, AUDIT_REPLY + 120) != 0:
        return False
    index = 128
    if id_bytes == 64:
        if lowerhex(w, AUDIT_REPLY + 128, 64) == False:
            return False
        index = 192
    while index < 192:
        if get(w, AUDIT_REPLY + index) != 0:
            return False
        index = index + 8
    index = 192 + error
    while index < 512:
        if byte(w, AUDIT_REPLY + index) != 0:
            return False
        index = index + 1
    return True

def response_ok(w:mutbuf) -> bool:
    mode = get(w, 1920)
    if get(w, AUDIT_REPLY + 16) != mode or get(w, AUDIT_REPLY + 24) != 0:
        return False
    if get(w, AUDIT_REPLY + 32) != 0 or get(w, AUDIT_REPLY + 104) != 0:
        return False
    if mode == 0:
        return get(w, AUDIT_REPLY + 40) == 0 and get(w, AUDIT_REPLY + 88) == NONE and get(w, AUDIT_REPLY + 96) == 0
    if get(w, AUDIT_REPLY + 40) != 64 or get(w, AUDIT_REPLY + 88) != get(w, 432) or get(w, AUDIT_REPLY + 96) != get(w, 448):
        return False
    return mode != 2 or equal(w, AUDIT_REPLY + 128, get(w, S_AUDIT_ID), 64)

def audit_fail(o:mutbuf, w:mutbuf) -> u32:
    put(w, 2016, 1)
    put(w, 456, 0)
    if get(w, 2024) != 0:
        return release_channel(o, w, 80)
    if get(w, 1920) != 0:
        return audit_return(w)
    if get(w, 1904) > 0:
        return call(o, w, 81, 62, get(w, 1904), 9, 0, 0, 0, 0, 0)
    return close_start(w)

def close_start(w:mutbuf) -> u32:
    put(w, 2008, 0)
    return enter(w, 9, 83)

def teardown(o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if phase == 80:
        put(w, 2024, 0)
        return audit_fail(o, w)
    if phase == 81:
        return call(o, w, 82, 61, get(w, 1904), 50264, 0, 0, 0, 0, 12)
    if phase == 82:
        if result == NEG4:
            return call(o, w, 82, 61, get(w, 1904), 50264, 0, 0, 0, 0, 12)
        put(w, 1904, 0)
        return close_start(w)
    if phase == 84:
        put(w, 1856 + get(w, 2008) * 8, NONE)
        put(w, 2008, get(w, 2008) + 1)
    index = get(w, 2008)
    while index < 2:
        fd = get(w, 1856 + index * 8)
        if fd != NONE and fd >= 3:
            put(w, 2008, index)
            return call(o, w, 84, 3, fd, 0, 0, 0, 0, 0, 0)
        index = index + 1
    return audit_return(w)

def child_setup(o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if failed(result):
        return call(o, w, 69, 60, 127, 0, 0, 0, 0, 0, 0)
    if phase == 60:
        return call(o, w, 61, 110, 0, 0, 0, 0, 0, 0, 0)
    if phase == 61:
        if result != get(w, 424):
            return call(o, w, 69, 60, 127, 0, 0, 0, 0, 0, 0)
        return call(o, w, 62, 33, get(w, 1856), 0, 0, 0, 0, 0, 0)
    if phase == 62:
        return call(o, w, 63, 33, get(w, 1856), 1, 0, 0, 0, 0, 0)
    if phase == 63:
        return call(o, w, 64, 436, 3, 4294967295, 4, 0, 0, 0, 0)
    if phase == 64:
        return call(o, w, 65, 72, get(w, 384), 2, 0, 0, 0, 0, 0)
    if phase == 65:
        return call(o, w, 66, 72, get(w, 416), 2, 0, 0, 0, 0, 0)
    if phase == 66:
        return call(o, w, 67, 322, get(w, role_record(21)), 51008, 51024, 55296, 4096, 0, 252)
    return call(o, w, 69, 60, 127, 0, 0, 0, 0, 0, 0)

def begin_frame(w:mutbuf) -> bool:
    mode = get(w, 1920)
    if mode > 1 or get(w, S_STATE_ROOT + 8) == 0 or get(w, S_STATE_ROOT + 8) > 4096:
        return False
    zero_frame(w, AUDIT_WIRE, 512)
    put(w, AUDIT_WIRE, AUDIT_BEGIN_MAGIC)
    put(w, AUDIT_WIRE + 8, 1)
    put(w, AUDIT_WIRE + 16, mode)
    put(w, AUDIT_WIRE + 24, 512 + get(w, S_STATE_ROOT + 8))
    put(w, AUDIT_WIRE + 32, get(w, 384))
    put(w, AUDIT_WIRE + 40, get(w, 416))
    put(w, AUDIT_WIRE + 48, choose(mode == 0, NONE, get(w, 432)))
    put(w, AUDIT_WIRE + 56, get(w, 32))
    put(w, AUDIT_WIRE + 64, choose(mode == 0, 0, get(w, 448)))
    put(w, AUDIT_WIRE + 72, get(w, 424))
    put(w, AUDIT_WIRE + 80, get(w, S_STATE_ROOT + 8))
    if mode == 1:
        size = get(w, S_TOOL + 8)
        if size < 3 or size > 66 or get(w, S_AUDIT_OWNER + 8) != 64:
            return False
        copy_state(w, get(w, S_AUDIT_OWNER), AUDIT_WIRE + 128, 64)
        if get(w, 264) == 12:
            end = text_read(w, AUDIT_WIRE + 192)
            put(w, AUDIT_WIRE + 88, end - AUDIT_WIRE - 192)
        else:
            copy_state(w, get(w, S_TOOL) + 1, AUDIT_WIRE + 192, size - 2)
            put(w, AUDIT_WIRE + 88, size - 2)
    cp(w, S_STATE_ROOT, AUDIT_WIRE + 512)
    reset_io(w, 512 + get(w, S_STATE_ROOT + 8))
    return True


def finish_frame(w:mutbuf) -> u64:
    zero_frame(w, AUDIT_WIRE, 128)
    put(w, AUDIT_WIRE, AUDIT_FINISH_MAGIC)
    put(w, AUDIT_WIRE + 8, 1)
    put(w, AUDIT_WIRE + 16, 2)
    put(w, AUDIT_WIRE + 24, 128)
    put(w, AUDIT_WIRE + 32, get(w, 464))
    put(w, AUDIT_WIRE + 40, get(w, 432))
    put(w, AUDIT_WIRE + 48, get(w, 448))
    put(w, AUDIT_WIRE + 56, get(w, 32))
    cp(w, S_AUDIT_ID, AUDIT_WIRE + 64)
    reset_io(w, 128)
    return 0


def reset_io(w:mutbuf, size:u64) -> u64:
    put(w, 1928, 0)
    put(w, 1936, size)
    put(w, 1944, 0)
    put(w, 1952, 0)
    zero_frame(w, AUDIT_REPLY, 1024)
    return 0


def zero_frame(w:mutbuf, at:u64, size:u64) -> u64:
    index = 0
    while index < size:
        put(w, at + index, 0)
        index = index + 8
    return 0


def audit_return(w:mutbuf) -> u32:
    return enter(w, get(w, 1992), get(w, 2000))

'''


def source():
    return authored(SOURCE, text={'helper': 'hia-mcp-request-audit', 'read': 'hia_read'}, extra={
        'AUDIT_BEGIN_MAGIC': int.from_bytes(b'HIAAUD01', 'little'),
        'AUDIT_FINISH_MAGIC': int.from_bytes(b'HIAAUF01', 'little'),
        'AUDIT_RESPONSE_MAGIC': int.from_bytes(b'HIAAUO01', 'little'),
    })
