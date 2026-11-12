"""Complete native ObjectToken JSON/spool and final-Core continuation owner.

RECONSTRUCTED-DEVELOPMENT-r1. Both consumers receive the same immutable actual
producer frame. No new aggregate Core/output quota is introduced: the original
snapshot and byte gates run only at final ADMIT. The fixed executor owns only
buffer allocation, exact calls, protection and append-only private spool I/O.
"""
from __future__ import annotations

BODY = r'''
def lower_stream(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < MIN_WORK:
        return ABI
    if length(o) < 128 or acknowledge(s, w, DRIVER_STREAM) == 0:
        return refuse(w, 400)
    while get(w, L_STATUS) == 1:
        result = stream_step(o, w)
        if result != 0:
            return result
    return refuse(w, 401)

def stream_step(o:mutbuf, w:mutbuf) -> u64:
    phase = get(w, C_PHASE)
    if phase >= 30000 and phase < 30400:
        return stream_initialize(o, w)
    if phase >= 30400 and phase < 30500:
        return stream_register(o, w)
    if phase >= 31000 and phase < 31200:
        return stream_producer(o, w)
    if phase >= 32000 and phase < 32200:
        return json_step(o, w)
    if phase >= 32200 and phase < 32400:
        return stream_drain(o, w)
    if phase >= 32400 and phase < 32600:
        return json_opaque_step(o, w)
    if phase >= 33000 and phase < 33300:
        return core_step(o, w)
    if phase >= 33500 and phase < 33600:
        return stream_finish(o, w)
    if phase >= 34000 and phase < 34100:
        return core_admit_step(o, w)
    return refuse(w, 402)

def stream_shape(w:mutbuf) -> u64:
    mode = get(w, L_STREAM_MODE)
    source = get(w, L_STREAM_SOURCE)
    if get(w, L_PRODUCER_KIND) != 0 or get(w, L_PRODUCER_SEQUENCE) != 0:
        return 0
    if mode == 1 and source == B_FUNCTION_SOURCE:
        if get(w, L_PRODUCER_IMAGE) != I_FUNCTION_RENDER or get(w, L_PRODUCER_MAGIC) != FN_STREAM:
            return 0
        if get(w, L_PRODUCER_WORK) != B_FUNCTION_WORK or get(w, L_PRODUCER_OUTPUT) != B_FUNCTION_OUTPUT:
            return 0
        if get(w, L_STREAM_SOURCE_EXTENT) != get(w, C_FN_SOURCE_BYTES):
            return 0
        put(w, L_STREAM_PACKET_SLOT, B_FUNCTION_PACKET)
        put(w, L_STREAM_PACKET_BYTES, get(w, C_FN_PACKET_BYTES))
        put(w, L_STREAM_DEST_DRIVER, DRIVER_MAIN)
    elif mode == 1 and source == B_HELPER_SOURCE:
        if get(w, L_PRODUCER_IMAGE) != 0 or get(w, L_PRODUCER_MAGIC) != HELPER_STREAM_MAGIC:
            return 0
        if get(w, L_PRODUCER_WORK) != B_EMPTY or get(w, L_PRODUCER_OUTPUT) != B_WIRE_COPY:
            return 0
        if get(w, L_STREAM_SOURCE_EXTENT) != get(w, L_INDEX_SOURCE_BYTES):
            return 0
        put(w, L_STREAM_PACKET_SLOT, B_HELPER_VALUE)
        put(w, L_STREAM_PACKET_BYTES, get(w, L_HELPER_VALUE_BYTES))
        put(w, L_STREAM_DEST_DRIVER, DRIVER_SERVICES)
    elif mode == 2 and source == B_OUTER_SOURCE:
        if get(w, L_PRODUCER_IMAGE) != I_OUTER_RENDER or get(w, L_PRODUCER_MAGIC) != OUT_STREAM:
            return 0
        if get(w, L_PRODUCER_WORK) != B_OUTER_WORK or get(w, L_PRODUCER_OUTPUT) != B_OUTER_OUTPUT:
            return 0
        if get(w, L_STREAM_SOURCE_EXTENT) != get(w, C_OUT_SOURCE_BYTES):
            return 0
        put(w, L_STREAM_PACKET_SLOT, B_OUTER_PACKET)
        put(w, L_STREAM_PACKET_BYTES, get(w, C_OUT_PACKET_BYTES))
        put(w, L_STREAM_DEST_DRIVER, DRIVER_MAIN)
    else:
        return 0
    size = get(w, L_STREAM_PACKET_BYTES)
    if size < 16 or size > PACKET_LIMIT or inside(w, get(w, L_STREAM_PACKET_SLOT), 0, size) == 0:
        return 0
    if inside(w, source, 0, get(w, L_STREAM_SOURCE_EXTENT)) == 0:
        return 0
    put(w, L_STREAM_FILE, mode - 1)
    put(w, L_STREAM_OFFSET, choose(mode == 1, get(w, L_SPOOL_BYTES), 0))
    return 1

def stream_initialize(o:mutbuf, w:mutbuf) -> u64:
    phase = get(w, C_PHASE)
    if phase == 30000:
        if stream_shape(w) == 0 or advance(w, L_STREAM_NUMBER) == 0:
            return refuse(w, 403)
        put(w, L_JSON_SEQUENCE, 0)
        put(w, L_JSON_PSEQ, 0)
        put(w, L_JSON_ACTION, 0)
        put(w, L_JSON_PAYLOAD, 0)
        put(w, L_JSON_TOTAL, 0)
        put(w, L_JSON_ROOT, 0)
        put(w, L_CORE_SEQUENCE, 0)
        put(w, L_CORE_PSEQ, 0)
        put(w, L_CORE_ACTION, 0)
        put(w, L_CORE_ROOT, 0)
        put(w, L_CORE_NODES, 0)
        put(w, L_CORE_DEPTH, MAX)
        put(w, L_CORE_MASK, 0)
        put(w, L_CORE_UNKNOWN, 0)
        put(w, L_CORE_LATE, 0)
        put(w, L_CORE_QUERY_SEQUENCE, 0)
        put(w, L_OPAQUE_QUERY, 0)
        put(w, L_OPAQUE_REMAIN, 0)
        put(w, L_OPAQUE_REGISTER_INDEX, 0)
        put(w, L_STREAM_LENGTH, 0)
        put(w, L_STREAM_FINISHED, 0)
        return release(o, w, B_OBJECT_JSON, 30001)
    if phase == 30001:
        return release(o, w, B_CORE_VISITOR, 30002)
    if phase == 30002:
        return grow(o, w, B_OBJECT_JSON, 262272, 30003)
    if phase == 30003:
        return grow(o, w, B_CORE_VISITOR, 131328, 30004)
    if phase == 30004:
        return grow(o, w, B_HASH_WORK, 1184, 30005)
    if phase == 30005:
        return grow(o, w, B_HASH_OUTPUT, 32, 30006)
    if phase == 30006:
        return grow(o, w, B_HASH_INPUT, 65537, 30007)
    if phase == 30007:
        return grow(o, w, B_OPAQUE_REPLY, 65600, 30008)
    if phase == 30008:
        store(w, WIRE, 0)
        return invoke(o, w, I_SHA_STREAM, B_CONTROLLER, WIRE, 1, B_HASH_OUTPUT, 32, B_HASH_WORK, 1184, B_HASH_OUTPUT, 0, 0, 30009)
    if phase == 30009:
        if get(w, C_RETURN) != 0:
            return refuse(w, 404)
        if get(w, L_STREAM_MODE) == 2:
            put(w, L_FINAL_BYTES, 0)
            return file_create(o, w, 1, 30100)
        put(w, C_PHASE, 30100)
        return 0
    if phase == 30100:
        put(w, L_JSON_PENDING, 1)
        wire8(w, JSON_INIT, get(w, C_LEASE), get(w, L_STREAM_NUMBER), get(w, L_PRODUCER_MAGIC), 0, get(w, L_PRODUCER_REQUEST), get(w, L_PRODUCER_SERIAL), get(w, L_PRODUCER_SLOTS))
        return invoke(o, w, I_OBJECT_JSON, B_CONTROLLER, WIRE, 64, get(w, L_STREAM_PACKET_SLOT), get(w, L_STREAM_PACKET_BYTES), B_OBJECT_JSON, cap(w, B_OBJECT_JSON), B_OBJECT_JSON, 1024, 128, 32000)
    if phase == 30200:
        wire8(w, CORE_INIT, get(w, C_LEASE), get(w, L_STREAM_NUMBER), get(w, L_PRODUCER_MAGIC), 0, get(w, L_PRODUCER_REQUEST), get(w, L_PRODUCER_SERIAL), get(w, L_PRODUCER_SLOTS))
        put(w, WIRE + 64, get(w, L_STREAM_MODE))
        put(w, WIRE + 72, 0)
        return invoke(o, w, I_CORE_VISITOR, B_CONTROLLER, WIRE, 80, get(w, L_STREAM_SOURCE), get(w, L_STREAM_SOURCE_EXTENT), B_CORE_VISITOR, cap(w, B_CORE_VISITOR), B_CORE_VISITOR, 1024, 128, 30201)
    if phase == 30201:
        if core_event(w, 1) == 0:
            return refuse(w, 405)
        if get(w, L_STREAM_MODE) == 2:
            put(w, C_PHASE, 30400)
        else:
            put(w, C_PHASE, 31000)
        return 0
    return refuse(w, 406)

def registered_row(w:mutbuf, handle:u64) -> u64:
    row = object_row(w, handle)
    if row == 0 or get(w, row) != handle or get(w, row + 56) != 6:
        return 0
    offset = get(w, row + 8)
    size = get(w, row + 16)
    if size < 2 or size > 2305843009213693951:
        return 0
    if offset > get(w, L_SPOOL_BYTES) or size > get(w, L_SPOOL_BYTES) - offset:
        return 0
    if get(w, row + 64) == 0 or get(w, row + 64) > 262145:
        return 0
    if get(w, row + 72) != MAX and get(w, row + 72) > 262145:
        return 0
    if get(w, row + 104) != 1 and get(w, row + 104) != 2:
        return 0
    if get(w, row + 112) != 0 or get(w, row + 120) != 0:
        return 0
    return row

def stream_register(o:mutbuf, w:mutbuf) -> u64:
    phase = get(w, C_PHASE)
    if phase == 30400:
        index = get(w, L_OPAQUE_REGISTER_INDEX)
        while index < OBJECT_COUNT and get(w, OBJECT_BASE + index * OBJECT_STRIDE) == 0:
            index = index + 1
        put(w, L_OPAQUE_REGISTER_INDEX, index)
        if index == OBJECT_COUNT:
            put(w, C_PHASE, 31000)
            return 0
        row = registered_row(w, OBJECTS + index)
        if row == 0:
            return refuse(w, 407)
        wire8(w, JSON_REGISTER, get(w, C_LEASE), get(w, L_STREAM_NUMBER), get(w, L_JSON_SEQUENCE), get(w, row), get(w, row + 16), get(w, row + 24), get(w, row + 32))
        put(w, WIRE + 64, get(w, row + 40))
        put(w, WIRE + 72, get(w, row + 48))
        put(w, WIRE + 80, 0)
        put(w, WIRE + 88, 0)
        put(w, L_JSON_PENDING, 2)
        return invoke(o, w, I_OBJECT_JSON, B_CONTROLLER, WIRE, 96, get(w, L_STREAM_PACKET_SLOT), get(w, L_STREAM_PACKET_BYTES), B_OBJECT_JSON, cap(w, B_OBJECT_JSON), B_OBJECT_JSON, 1024, 128, 32000)
    if phase == 30402:
        return json_continue(o, w, 32000)
    if phase == 30403:
        put(w, L_OPAQUE_REGISTER_INDEX, get(w, L_OPAQUE_REGISTER_INDEX) + 1)
        put(w, C_PHASE, 30400)
        return 0
    return refuse(w, 408)

def stream_frame(w:mutbuf) -> u64:
    size = get(w, C_RETURN)
    if size < 64 or size > OWNER_OUTPUT_BYTES or get(w, OBS) != get(w, L_PRODUCER_MAGIC):
        return 0
    if get(w, OBS + 8) != 0 or get(w, OBS + 16) != get(w, L_PRODUCER_SEQUENCE) or get(w, OBS + 24) > 1:
        return 0
    if get(w, OBS + 32) != get(w, L_PRODUCER_SERIAL) or get(w, OBS + 40) != get(w, L_PRODUCER_SLOTS):
        return 0
    if get(w, OBS + 48) != get(w, L_PRODUCER_REQUEST) or get(w, OBS + 56) != size - 64:
        return 0
    if get(w, L_PRODUCER_SEQUENCE) == MAX:
        return 0
    put(w, L_PRODUCER_BYTES, size)
    put(w, L_PRODUCER_FINAL, get(w, OBS + 24))
    return 1

def stream_producer(o:mutbuf, w:mutbuf) -> u64:
    phase = get(w, C_PHASE)
    if phase == 31000:
        if get(w, L_PRODUCER_IMAGE) == 0:
            return view(o, w, B_WIRE_COPY, 0, 80, 31002)
        return invoke(o, w, get(w, L_PRODUCER_IMAGE), B_EMPTY, 0, 0, get(w, L_PRODUCER_OUTPUT), OWNER_OUTPUT_BYTES, get(w, L_PRODUCER_WORK), cap(w, get(w, L_PRODUCER_WORK)), get(w, L_PRODUCER_OUTPUT), 0, 64, 31001)
    if phase == 31002:
        if get(w, C_RETURN) != 0 or get(w, L_PRODUCER_SEQUENCE) != 0 or get(w, OBS + 24) != 1:
            return refuse(w, 409)
        if get(w, OBS + 64) != 0 or get(w, OBS + 72) != 0:
            return refuse(w, 410)
        put(w, C_RETURN, 80)
        put(w, C_PHASE, 31001)
        return 0
    if phase == 31001:
        if stream_frame(w) == 0:
            return refuse(w, 411)
        put(w, L_JSON_PENDING, 3)
        return invoke(o, w, I_OBJECT_JSON, get(w, L_PRODUCER_OUTPUT), 0, get(w, L_PRODUCER_BYTES), get(w, L_STREAM_PACKET_SLOT), get(w, L_STREAM_PACKET_BYTES), B_OBJECT_JSON, cap(w, B_OBJECT_JSON), B_OBJECT_JSON, 1024, 128, 32000)
    return refuse(w, 412)

def json_event(w:mutbuf) -> u64:
    if get(w, OBS) != JSON_EVENT or get(w, OBS + 16) != 0:
        return 0
    if get(w, OBS + 24) != get(w, C_LEASE) or get(w, OBS + 32) != get(w, L_STREAM_NUMBER):
        return 0
    seq = get(w, L_JSON_SEQUENCE)
    if seq == MAX or get(w, OBS + 48) != seq + 1:
        return 0
    size = get(w, OBS + 64)
    total = get(w, L_JSON_TOTAL)
    if size > 65408 or get(w, C_RETURN) != 1152 + size or get(w, OBS + 56) != 1152:
        return 0
    if total > MAX - size or get(w, OBS + 72) != total + size:
        return 0
    if get(w, OBS + 112) != 0 or get(w, OBS + 120) != 0:
        return 0
    context = get(w, L_JSON_PENDING)
    if context == 1 or context == 2:
        if size != 0 or total != 0 or get(w, OBS + 40) != 0:
            return 0
    elif context == 3:
        if get(w, L_PRODUCER_SEQUENCE) == MAX or get(w, OBS + 40) != get(w, L_PRODUCER_SEQUENCE) + 1:
            return 0
    else:
        return 0
    action = get(w, OBS + 8)
    if json_shape(w, action, context) == 0:
        return 0
    put(w, L_JSON_SEQUENCE, seq + 1)
    put(w, L_JSON_PSEQ, get(w, OBS + 40))
    put(w, L_JSON_ACTION, action)
    put(w, L_JSON_PAYLOAD, size)
    put(w, L_JSON_TOTAL, total + size)
    put(w, L_JSON_A0, get(w, OBS + 80))
    put(w, L_JSON_A1, get(w, OBS + 88))
    put(w, L_JSON_A2, get(w, OBS + 96))
    put(w, L_JSON_A3, get(w, OBS + 104))
    return 1

def json_shape(w:mutbuf, action:u64, context:u64) -> u64:
    a = get(w, OBS + 80)
    b = get(w, OBS + 88)
    c = get(w, OBS + 96)
    d = get(w, OBS + 104)
    if action == 3:
        if a <= cap(w, B_OBJECT_JSON) or b != cap(w, B_OBJECT_JSON) or d != 0:
            return 0
        if context == 1 and c != 10:
            return 0
        if context == 2 and c != 1:
            return 0
        if context == 3 and c != 0:
            return 0
        return 1
    if context == 1:
        if action != 1 or a != 0 or b != 0 or c != 0 or d != 0:
            return 0
        return 1
    if context == 2:
        if action != 1 or a != OBJECTS + get(w, L_OPAQUE_REGISTER_INDEX) or b != 0 or c != 0 or d != 0:
            return 0
        return 1
    if action == 1 or action == 2:
        if a != 0 or b != 0 or c != 0 or d != 0:
            return 0
        if action == 1 and (get(w, L_PRODUCER_FINAL) != 0 or get(w, L_OPAQUE_REMAIN) != 0):
            return 0
        if action == 2 and get(w, OBS + 64) != 65408:
            return 0
        return 1
    if action == 4:
        if get(w, L_STREAM_MODE) != 2 or a < OBJECTS or b == 0 or d != 65536:
            return 0
        return 1
    if action == 5:
        if get(w, L_PRODUCER_FINAL) != 1 or get(w, L_OPAQUE_REMAIN) != 0:
            return 0
        if a > 6 or a == 3 or b == 0 or c != 0 or d != 0:
            return 0
        return 1
    return 0

def json_continue(o:mutbuf, w:mutbuf, next:u64) -> u64:
    wire8(w, JSON_CONT, get(w, C_LEASE), get(w, L_STREAM_NUMBER), get(w, L_JSON_SEQUENCE), 0, 0, 0, 0)
    return invoke(o, w, I_OBJECT_JSON, B_CONTROLLER, WIRE, 32, get(w, L_STREAM_PACKET_SLOT), get(w, L_STREAM_PACKET_BYTES), B_OBJECT_JSON, cap(w, B_OBJECT_JSON), B_OBJECT_JSON, 1024, 128, next)

def json_step(o:mutbuf, w:mutbuf) -> u64:
    phase = get(w, C_PHASE)
    if phase == 32000:
        if json_event(w) == 0:
            return refuse(w, 413)
        if get(w, L_JSON_PAYLOAD) != 0:
            put(w, C_PHASE, 32200)
        else:
            put(w, C_PHASE, 32100)
        return 0
    if phase == 32010:
        return json_continue(o, w, 32000)
    if phase == 32100:
        action = get(w, L_JSON_ACTION)
        context = get(w, L_JSON_PENDING)
        if get(w, L_STREAM_LENGTH) != get(w, L_JSON_TOTAL):
            return refuse(w, 414)
        if action == 3:
            next = 32010
            if context == 1:
                next = 30100
            elif context == 2:
                next = 30402
            return grow(o, w, B_OBJECT_JSON, get(w, L_JSON_A0), next)
        if context == 1:
            put(w, C_PHASE, 30200)
            return 0
        if context == 2:
            put(w, C_PHASE, 30403)
            return 0
        if action == 2:
            put(w, C_PHASE, 32010)
            return 0
        if action == 4:
            put(w, C_PHASE, 32400)
            return 0
        if action == 5:
            put(w, L_JSON_ROOT, get(w, L_JSON_A0))
        put(w, C_PHASE, 33000)
        return 0
    return refuse(w, 415)

def stream_drain(o:mutbuf, w:mutbuf) -> u64:
    phase = get(w, C_PHASE)
    if phase == 32200:
        store(w, WIRE, 1)
        return copy(o, w, B_CONTROLLER, WIRE, B_HASH_INPUT, 0, 1, 32201)
    if phase == 32201:
        return copy(o, w, B_OBJECT_JSON, 1152, B_HASH_INPUT, 1, get(w, L_JSON_PAYLOAD), 32202)
    if phase == 32202:
        return invoke(o, w, I_SHA_STREAM, B_HASH_INPUT, 0, 1 + get(w, L_JSON_PAYLOAD), B_HASH_OUTPUT, 32, B_HASH_WORK, 1184, B_HASH_OUTPUT, 0, 0, 32203)
    if phase == 32203:
        if get(w, C_RETURN) != 0:
            return refuse(w, 416)
        at = get(w, L_FINAL_BYTES)
        if get(w, L_STREAM_MODE) == 1:
            at = get(w, L_SPOOL_BYTES)
        return file_append(o, w, get(w, L_STREAM_FILE), at, B_OBJECT_JSON, 1152, get(w, L_JSON_PAYLOAD), 32204)
    if phase == 32204:
        size = get(w, L_JSON_PAYLOAD)
        if get(w, L_STREAM_LENGTH) > MAX - size:
            return refuse(w, 417)
        put(w, L_STREAM_LENGTH, get(w, L_STREAM_LENGTH) + size)
        if get(w, L_STREAM_MODE) == 1:
            put(w, L_SPOOL_BYTES, get(w, L_SPOOL_BYTES) + size)
        else:
            put(w, L_FINAL_BYTES, get(w, L_FINAL_BYTES) + size)
        put(w, C_PHASE, 32100)
        return 0
    return refuse(w, 418)

def json_opaque_step(o:mutbuf, w:mutbuf) -> u64:
    phase = get(w, C_PHASE)
    if phase == 32400:
        row = registered_row(w, get(w, L_JSON_A0))
        if row == 0:
            return refuse(w, 419)
        chunk = get(w, L_JSON_A2)
        if chunk == 0:
            if get(w, L_OPAQUE_REMAIN) != 0 or get(w, L_OPAQUE_QUERY) == MAX:
                return refuse(w, 420)
            if get(w, L_JSON_A1) != get(w, L_OPAQUE_QUERY) + 1:
                return refuse(w, 421)
            put(w, L_OPAQUE_QUERY, get(w, L_JSON_A1))
            put(w, L_OPAQUE_ROW, row)
            put(w, L_OPAQUE_OFFSET, 0)
            put(w, L_OPAQUE_REMAIN, get(w, row + 16))
        else:
            if row != get(w, L_OPAQUE_ROW) or get(w, L_JSON_A1) != get(w, L_OPAQUE_QUERY):
                return refuse(w, 422)
            if get(w, L_OPAQUE_CHUNK) == MAX or chunk != get(w, L_OPAQUE_CHUNK) + 1 or get(w, L_OPAQUE_REMAIN) == 0:
                return refuse(w, 423)
        put(w, L_OPAQUE_CHUNK, chunk)
        size = minimum(get(w, L_OPAQUE_REMAIN), 65536)
        put(w, L_OPAQUE_COPY_BYTES, size)
        wire8(w, JSON_OPAQUE, get(w, C_LEASE), get(w, L_STREAM_NUMBER), get(w, L_JSON_SEQUENCE), get(w, row), get(w, L_OPAQUE_QUERY), chunk, choose(size == get(w, L_OPAQUE_REMAIN), 1, 0))
        return copy(o, w, B_CONTROLLER, WIRE, B_OPAQUE_REPLY, 0, 64, 32401)
    if phase == 32401:
        row = get(w, L_OPAQUE_ROW)
        at = get(w, row + 8) + get(w, L_OPAQUE_OFFSET)
        return file_read(o, w, 0, at, B_OPAQUE_REPLY, 64, get(w, L_OPAQUE_COPY_BYTES), 32402)
    if phase == 32402:
        size = get(w, L_OPAQUE_COPY_BYTES)
        if size == 0 or size > get(w, L_OPAQUE_REMAIN):
            return refuse(w, 424)
        put(w, L_OPAQUE_OFFSET, get(w, L_OPAQUE_OFFSET) + size)
        put(w, L_OPAQUE_REMAIN, get(w, L_OPAQUE_REMAIN) - size)
        return invoke(o, w, I_OBJECT_JSON, B_OPAQUE_REPLY, 0, 64 + size, get(w, L_STREAM_PACKET_SLOT), get(w, L_STREAM_PACKET_BYTES), B_OBJECT_JSON, cap(w, B_OBJECT_JSON), B_OBJECT_JSON, 1024, 128, 32000)
    return refuse(w, 425)

def core_event(w:mutbuf, context:u64) -> u64:
    if get(w, C_RETURN) != 1152 or get(w, OBS) != CORE_EVENT:
        return 0
    if get(w, OBS + 24) != get(w, C_LEASE) or get(w, OBS + 32) != get(w, L_STREAM_NUMBER):
        return 0
    seq = get(w, L_CORE_SEQUENCE)
    if seq == MAX or get(w, OBS + 48) != seq + 1:
        return 0
    root = get(w, OBS + 56)
    nodes = get(w, OBS + 64)
    depth = get(w, OBS + 72)
    if root > 6 or root == 3 or nodes > 262145:
        return 0
    if depth != MAX and depth > 262145:
        return 0
    if get(w, OBS + 112) > 2047 or get(w, OBS + 120) > 1:
        return 0
    action = get(w, OBS + 8)
    if core_shape(w, context, action) == 0:
        return 0
    put(w, L_CORE_SEQUENCE, seq + 1)
    put(w, L_CORE_PSEQ, get(w, OBS + 40))
    put(w, L_CORE_ACTION, action)
    put(w, L_CORE_ROOT, root)
    put(w, L_CORE_NODES, nodes)
    put(w, L_CORE_DEPTH, depth)
    put(w, L_CORE_MASK, get(w, OBS + 112))
    put(w, L_CORE_UNKNOWN, get(w, OBS + 120))
    put(w, L_CORE_LATE, get(w, OBS + 104))
    return 1

def core_shape(w:mutbuf, context:u64, action:u64) -> u64:
    status = get(w, OBS + 16)
    pseq = get(w, OBS + 40)
    needed = get(w, OBS + 80)
    handle = get(w, OBS + 88)
    query = get(w, OBS + 96)
    late = get(w, OBS + 104)
    if context == 1:
        if action != 1 or status != 1 or pseq != 0 or get(w, OBS + 56) != 0:
            return 0
        if get(w, OBS + 64) != 0 or get(w, OBS + 72) != MAX or needed != 0 or handle != 0 or query != 0 or late != 0:
            return 0
        if get(w, OBS + 112) != 0 or get(w, OBS + 120) != 0:
            return 0
        return 1
    if context == 3:
        if action != 7 or status != 2 or pseq != get(w, L_CORE_PSEQ) or needed != 0 or handle != 0 or query != 0 or late > 3:
            return 0
        if get(w, OBS + 56) != get(w, L_CORE_ROOT) or get(w, OBS + 64) != get(w, L_CORE_NODES) or get(w, OBS + 72) != get(w, L_CORE_DEPTH):
            return 0
        if get(w, OBS + 112) != get(w, L_CORE_MASK) or get(w, OBS + 120) != get(w, L_CORE_UNKNOWN):
            return 0
        if get(w, L_ADMIT_SNAPSHOT) != 0 and late != get(w, L_ADMIT_SNAPSHOT):
            return 0
        return 1
    if context != 2:
        return 0
    if action == 3 or action == 4:
        if status != 1 or pseq != get(w, L_PRODUCER_SEQUENCE) or late != 0:
            return 0
        if action == 3:
            if needed <= cap(w, B_CORE_VISITOR) or handle != 0 or query != 0:
                return 0
        else:
            if needed != 0 or get(w, L_STREAM_MODE) != 2 or registered_row(w, handle) == 0:
                return 0
            if get(w, L_CORE_QUERY_SEQUENCE) == MAX or query != get(w, L_CORE_QUERY_SEQUENCE) + 1:
                return 0
        return 1
    if action == 1 or action == 5:
        if needed != 0 or handle != 0 or query != 0 or get(w, L_PRODUCER_SEQUENCE) == MAX or pseq != get(w, L_PRODUCER_SEQUENCE) + 1:
            return 0
        if action == 1:
            if status != 1 or get(w, L_PRODUCER_FINAL) != 0 or late != 0:
                return 0
        else:
            if status != 2 or get(w, L_PRODUCER_FINAL) != 1 or get(w, OBS + 64) == 0 or late > 2:
                return 0
            if get(w, L_STREAM_MODE) == 1 and late != 0:
                return 0
        return 1
    return 0

def core_step(o:mutbuf, w:mutbuf) -> u64:
    phase = get(w, C_PHASE)
    if phase == 33000:
        return invoke(o, w, I_CORE_VISITOR, get(w, L_PRODUCER_OUTPUT), 0, get(w, L_PRODUCER_BYTES), get(w, L_STREAM_SOURCE), get(w, L_STREAM_SOURCE_EXTENT), B_CORE_VISITOR, cap(w, B_CORE_VISITOR), B_CORE_VISITOR, 1024, 128, 33001)
    if phase == 33001:
        if core_event(w, 2) == 0:
            return refuse(w, 426)
        action = get(w, L_CORE_ACTION)
        if action == 3:
            return grow(o, w, B_CORE_VISITOR, get(w, OBS + 80), 33002)
        if action == 4:
            put(w, L_CORE_QUERY_SEQUENCE, get(w, OBS + 96))
            put(w, L_OPAQUE_ROW, registered_row(w, get(w, OBS + 88)))
            put(w, C_PHASE, 33200)
            return 0
        if get(w, L_CORE_PSEQ) != get(w, L_JSON_PSEQ):
            return refuse(w, 427)
        if action == 1:
            if get(w, L_JSON_ACTION) != 1 or advance(w, L_PRODUCER_SEQUENCE) == 0:
                return refuse(w, 428)
            put(w, C_PHASE, 31000)
            return 0
        if get(w, L_JSON_ACTION) != 5 or get(w, L_CORE_ROOT) != get(w, L_JSON_ROOT):
            return refuse(w, 429)
        put(w, C_PHASE, 33500)
        return 0
    if phase == 33002:
        wire8(w, CORE_CONT, get(w, C_LEASE), get(w, L_STREAM_NUMBER), get(w, L_CORE_SEQUENCE), 0, 0, 0, 0)
        return invoke(o, w, I_CORE_VISITOR, B_CONTROLLER, WIRE, 32, get(w, L_STREAM_SOURCE), get(w, L_STREAM_SOURCE_EXTENT), B_CORE_VISITOR, cap(w, B_CORE_VISITOR), B_CORE_VISITOR, 1024, 128, 33001)
    if phase == 33200:
        row = get(w, L_OPAQUE_ROW)
        if row == 0:
            return refuse(w, 430)
        wire8(w, CORE_OPAQUE, get(w, C_LEASE), get(w, L_STREAM_NUMBER), get(w, L_CORE_SEQUENCE), get(w, row), get(w, row + 56), get(w, row + 64), get(w, row + 72))
        put(w, WIRE + 64, get(w, row + 16))
        put(w, WIRE + 72, get(w, row + 24))
        put(w, WIRE + 80, get(w, row + 32))
        put(w, WIRE + 88, get(w, row + 40))
        put(w, WIRE + 96, get(w, row + 48))
        put(w, WIRE + 104, 0)
        put(w, WIRE + 112, 0)
        put(w, WIRE + 120, 0)
        return invoke(o, w, I_CORE_VISITOR, B_CONTROLLER, WIRE, 128, get(w, L_STREAM_SOURCE), get(w, L_STREAM_SOURCE_EXTENT), B_CORE_VISITOR, cap(w, B_CORE_VISITOR), B_CORE_VISITOR, 1024, 128, 33001)
    return refuse(w, 431)

def stream_finish(o:mutbuf, w:mutbuf) -> u64:
    phase = get(w, C_PHASE)
    if phase == 33500:
        if get(w, L_STREAM_LENGTH) == 0 or get(w, L_STREAM_LENGTH) != get(w, L_JSON_TOTAL):
            return refuse(w, 432)
        store(w, WIRE, 2)
        return invoke(o, w, I_SHA_STREAM, B_CONTROLLER, WIRE, 1, B_HASH_OUTPUT, 32, B_HASH_WORK, 1184, B_HASH_OUTPUT, 0, 32, 33501)
    if phase == 33501:
        if get(w, C_RETURN) != 32:
            return refuse(w, 433)
        put(w, L_DIGEST0, get(w, OBS))
        put(w, L_DIGEST1, get(w, OBS + 8))
        put(w, L_DIGEST2, get(w, OBS + 16))
        put(w, L_DIGEST3, get(w, OBS + 24))
        if get(w, L_STREAM_MODE) == 2:
            if get(w, L_FINAL_BYTES) != get(w, L_STREAM_LENGTH):
                return refuse(w, 434)
            return file_seal(o, w, 1, 33502)
        if get(w, L_SPOOL_BYTES) < get(w, L_STREAM_OFFSET) or get(w, L_SPOOL_BYTES) - get(w, L_STREAM_OFFSET) != get(w, L_STREAM_LENGTH):
            return refuse(w, 435)
        put(w, C_PHASE, 33502)
        return 0
    if phase == 33502:
        return release(o, w, B_OBJECT_JSON, 33503)
    if phase == 33503:
        if get(w, L_STREAM_MODE) == 1:
            return release(o, w, B_CORE_VISITOR, 33504)
        put(w, C_PHASE, 33504)
        return 0
    if phase == 33504:
        put(w, L_STREAM_FINISHED, 1)
        return switch(o, w, get(w, L_STREAM_DEST_DRIVER), get(w, L_STREAM_RETURN))
    return refuse(w, 436)

def core_admit_step(o:mutbuf, w:mutbuf) -> u64:
    phase = get(w, C_PHASE)
    if phase == 34000:
        if get(w, L_STREAM_MODE) != 2 or get(w, L_STREAM_FINISHED) != 1 or get(w, L_CORE_ACTION) != 5:
            return refuse(w, 437)
        if get(w, L_CORE_ROOT) != 6 or get(w, L_CORE_MASK) != 1920 or get(w, L_CORE_UNKNOWN) != 0:
            return refuse(w, 438)
        put(w, L_ADMIT_SNAPSHOT, get(w, L_CORE_LATE))
        wire8(w, CORE_ADMIT, get(w, C_LEASE), get(w, L_STREAM_NUMBER), get(w, L_CORE_SEQUENCE), get(w, L_FINAL_BYTES), get(w, L_DIGEST0), get(w, L_DIGEST1), get(w, L_DIGEST2))
        put(w, WIRE + 64, get(w, L_DIGEST3))
        put(w, WIRE + 72, 0)
        return invoke(o, w, I_CORE_VISITOR, B_CONTROLLER, WIRE, 80, get(w, L_STREAM_SOURCE), get(w, L_STREAM_SOURCE_EXTENT), B_CORE_VISITOR, cap(w, B_CORE_VISITOR), B_CORE_VISITOR, 1024, 128, 34001)
    if phase == 34001:
        if core_event(w, 3) == 0:
            return refuse(w, 439)
        put(w, L_STREAM_FINISHED, 2)
        return release(o, w, B_CORE_VISITOR, 34002)
    if phase == 34002:
        return switch(o, w, DRIVER_MAIN, get(w, L_STREAM_RETURN))
    return refuse(w, 440)
'''
