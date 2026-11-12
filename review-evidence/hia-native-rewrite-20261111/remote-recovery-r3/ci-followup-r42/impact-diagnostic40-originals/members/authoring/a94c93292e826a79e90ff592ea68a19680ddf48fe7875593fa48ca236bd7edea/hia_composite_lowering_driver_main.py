"""Complete function/outer continuation owner, new reconstructed development.

The HIA state machine follows the actual selected semantic images. It does not
plan source lowering, expand source references in the host, or relax any late
Core boundary. No public selector or qualification is introduced by this file.
"""
from __future__ import annotations

BODY = r'''
def lower_main(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < MIN_WORK:
        return ABI
    if length(o) < 128:
        return refuse(w, 100)
    if get(w, L_MAGIC) == 0:
        if begin_lower(s, w) == 0:
            return refuse(w, 101)
    elif acknowledge(s, w, DRIVER_MAIN) == 0:
        return refuse(w, 102)
    while get(w, L_STATUS) == 1:
        result = main_step(o, w)
        if result != 0:
            return result
    return refuse(w, 103)

def begin_lower(s:readbuf, w:mutbuf) -> u64:
    if length(s) != 128 or word(s, 0) != EVENT_MAGIC or word(s, 8) != CTOR_HANDOFF:
        return 0
    if word(s, 16) == 0 or word(s, 16) != get(w, C_LEASE) or word(s, 24) != get(w, C_SEQUENCE):
        return 0
    if get(w, C_PENDING) != 0 or cap(w, B_CONTROLLER) != length(w):
        return 0
    if word(s, 32) != get(w, C_ERROR_GROUP) or word(s, 40) != get(w, C_FINAL_ERROR):
        return 0
    if word(s, 48) != get(w, C_CTOR_STAGE) or word(s, 56) != get(w, C_PROFILE):
        return 0
    if word(s, 64) != get(w, C_CTOR_REQUEST) or word(s, 72) != B_IR:
        return 0
    if word(s, 80) != get(w, C_IR_ROOT) or word(s, 88) != get(w, C_IR_EXTENT):
        return 0
    if word(s, 96) != get(w, C_TYPES_LIVE) or word(s, 104) != get(w, C_FN_PACKET_BYTES):
        return 0
    if word(s, 112) != get(w, C_OUT_PACKET_BYTES) or word(s, 120) != 0:
        return 0
    if get(w, C_ERROR_GROUP) > 2:
        return 0
    if get(w, C_ERROR_GROUP) == 0:
        if get(w, C_FINAL_ERROR) != 0 or get(w, C_CTOR_STAGE) != 3 or get(w, C_TYPES_LIVE) != 1:
            return 0
        if get(w, C_PROFILE) < 1 or get(w, C_PROFILE) > 4 or get(w, C_LEGACY) > 1:
            return 0
        if cap(w, B_TYPES) != TYPES_BYTES or cap(w, B_TYPE_OUTPUT) != TYPE_OUTPUT_BYTES or cap(w, B_TRANSPORT) < 4096:
            return 0
        if get(w, C_FN_PACKET_BYTES) < 16 or get(w, C_FN_PACKET_BYTES) > PACKET_LIMIT:
            return 0
        if get(w, C_OUT_PACKET_BYTES) < 16 or get(w, C_OUT_PACKET_BYTES) > PACKET_LIMIT:
            return 0
        if inside(w, B_FUNCTION_PACKET, 0, get(w, C_FN_PACKET_BYTES)) == 0:
            return 0
        if inside(w, B_OUTER_PACKET, 0, get(w, C_OUT_PACKET_BYTES)) == 0:
            return 0
        if get(w, C_FN_SOURCE_BYTES) < 82 or get(w, C_FN_SOURCE_BYTES) > SOURCE_LEASE_LIMIT:
            return 0
        if get(w, C_OUT_SOURCE_BYTES) < 82 or get(w, C_OUT_SOURCE_BYTES) > SOURCE_LEASE_LIMIT:
            return 0
        if inside(w, B_FUNCTION_SOURCE, 0, get(w, C_FN_SOURCE_BYTES)) == 0:
            return 0
        if inside(w, B_OUTER_SOURCE, 0, get(w, C_OUT_SOURCE_BYTES)) == 0:
            return 0
    i = 24
    while i < 64:
        if cap(w, i) != 0:
            return 0
        i = i + 1
    zero(w, 8192, MIN_WORK - 8192)
    put(w, L_MAGIC, LOWER_MAGIC)
    put(w, L_STATUS, 1)
    put(w, L_DRIVER, DRIVER_MAIN)
    put(w, L_OUT_PHASE, MAX)
    put(w, L_FN_KERNEL, I_FUNCTION_ADMIT)
    put(w, L_STREAM_NUMBER, get(w, C_IR_STREAM))
    put(w, C_PHASE, 10000)
    return 1

def valid_function_error(error:u64) -> u64:
    if error >= 1 and error <= 17:
        return 1
    if error >= 20 and error <= 65:
        return 1
    if error >= 200 and error <= 223:
        return 1
    if error >= 1001 and error <= 1019:
        return 1
    if error >= 1200 and error <= 1206:
        return 1
    if error == 999:
        return 1
    return 0

def function_frame(w:mutbuf) -> u64:
    if get(w, C_RETURN) != 64 or get(w, OBS) != FN_FRAME or get(w, OBS + 56) != 0:
        return 0
    action = get(w, OBS + 8)
    error = get(w, OBS + 16)
    serial = get(w, OBS + 32)
    slots = get(w, OBS + 40)
    request = get(w, OBS + 48)
    if action != 0 and action != 1 and action != 2 and action != 10 and action != 20 and action != 21 and action != 30:
        return 0
    if serial < get(w, L_FN_SERIAL) or serial > 8192 or slots < get(w, L_FN_SLOTS):
        return 0
    if request < get(w, L_FN_REQUEST):
        return 0
    if request != get(w, L_FN_REQUEST):
        if get(w, L_FN_REQUEST) == MAX or request != get(w, L_FN_REQUEST) + 1:
            return 0
    if action == 1:
        if valid_function_error(error) == 0:
            return 0
    elif error != 0:
        return 0
    put(w, L_FN_ACTION, action)
    put(w, L_FN_ERROR, error)
    put(w, L_FN_PHASE, get(w, OBS + 24))
    put(w, L_FN_SERIAL, serial)
    put(w, L_FN_SLOTS, slots)
    put(w, L_FN_OBS_REQUEST, request)
    return 1

def outer_frame(w:mutbuf) -> u64:
    if get(w, C_RETURN) != 64 or get(w, OBS) != OUT_FRAME or get(w, L_OUT_PHASE) == 2000:
        return 0
    action = get(w, OBS + 8)
    error = get(w, OBS + 16)
    phase = get(w, OBS + 24)
    request = get(w, OBS + 32)
    handle = get(w, OBS + 40)
    functions = get(w, OBS + 48)
    helpers = get(w, OBS + 56)
    previous = get(w, L_OUT_PHASE)
    if error != 0 and error != 1 and error != 999:
        return 0
    if functions < get(w, L_OUT_FUNCTIONS) or functions > 1024 or helpers < get(w, L_OUT_HELPERS) or helpers > 720:
        return 0
    accepted = False
    if error != 0:
        accepted = action == 1 and phase == 2000 and handle == 0 and request == get(w, L_OUT_REQUEST)
        accepted = accepted and functions == get(w, L_OUT_FUNCTIONS) and helpers == get(w, L_OUT_HELPERS)
        accepted = accepted and ((error == 1 and previous == 0) or (error == 999 and previous == 10))
    elif action == 0 and handle == 0 and request == get(w, L_OUT_REQUEST):
        if previous == MAX:
            accepted = phase == 0 and request == 0 and functions == 0 and helpers == 0
        elif previous == 11:
            accepted = phase == 0 and functions == get(w, L_OUT_FUNCTIONS) and helpers == get(w, L_OUT_HELPERS)
        elif previous == 21:
            accepted = phase == 10 and functions == get(w, L_OUT_FUNCTIONS) and helpers == get(w, L_OUT_HELPERS)
    elif action == 2 and handle == 0 and previous == 0:
        accepted = functions == get(w, L_OUT_FUNCTIONS) and helpers == get(w, L_OUT_HELPERS)
        if phase == 10:
            accepted = accepted and get(w, L_OUT_REQUEST) != MAX and request == get(w, L_OUT_REQUEST) + 1
        else:
            accepted = accepted and phase == 2000 and request == get(w, L_OUT_REQUEST)
    elif action == 3 and previous == 10 and phase == 20 and handle == 0:
        accepted = request == get(w, L_OUT_REQUEST) and functions == get(w, L_OUT_FUNCTIONS) and helpers == get(w, L_OUT_HELPERS)
    elif action == 4 and previous == 10 and phase == 11:
        accepted = request == get(w, L_OUT_REQUEST) and functions == get(w, L_OUT_FUNCTIONS) + 1
        accepted = accepted and helpers == get(w, L_OUT_HELPERS) and handle == OBJECTS + get(w, L_OUT_FUNCTIONS)
    elif action == 7 and previous == 20 and phase == 22 and handle == 0:
        accepted = request == get(w, L_OUT_REQUEST) and functions == get(w, L_OUT_FUNCTIONS) and helpers == get(w, L_OUT_HELPERS)
    elif action == 5 and previous == 22 and phase == 21:
        accepted = request == get(w, L_OUT_REQUEST) and functions == get(w, L_OUT_FUNCTIONS)
        accepted = accepted and helpers == get(w, L_OUT_HELPERS) + 1 and handle == OBJECTS + 1024 + get(w, L_OUT_HELPERS)
    elif action == 6 and previous == 22 and phase == 10 and handle == 0:
        accepted = request == get(w, L_OUT_REQUEST) and functions == get(w, L_OUT_FUNCTIONS) and helpers == get(w, L_OUT_HELPERS)
    if accepted == False:
        return 0
    put(w, L_OUT_PHASE, phase)
    put(w, L_OUT_REQUEST, request)
    put(w, L_OUT_FUNCTIONS, functions)
    put(w, L_OUT_HELPERS, helpers)
    put(w, L_OUT_ACTION, action)
    put(w, L_OUT_ERROR, error)
    put(w, L_OUT_HANDLE, handle)
    return 1

def producer(w:mutbuf, image:u64, work:u64, output:u64, magic:u64, kind:u64, request:u64, serial:u64, slots:u64, source:u64, extent:u64) -> u64:
    put(w, L_PRODUCER_IMAGE, image)
    put(w, L_PRODUCER_WORK, work)
    put(w, L_PRODUCER_OUTPUT, output)
    put(w, L_PRODUCER_MAGIC, magic)
    put(w, L_PRODUCER_KIND, kind)
    put(w, L_PRODUCER_REQUEST, request)
    put(w, L_PRODUCER_SERIAL, serial)
    put(w, L_PRODUCER_SLOTS, slots)
    put(w, L_PRODUCER_SEQUENCE, 0)
    put(w, L_PRODUCER_FINAL, 0)
    put(w, L_PRODUCER_BYTES, 0)
    put(w, L_STREAM_SOURCE, source)
    put(w, L_STREAM_SOURCE_EXTENT, extent)
    return 0

def function_producer(w:mutbuf, kind:u64) -> u64:
    return producer(w, I_FUNCTION_RENDER, B_FUNCTION_WORK, B_FUNCTION_OUTPUT, FN_STREAM, kind, get(w, L_FN_REQUEST), get(w, L_FN_SERIAL), get(w, L_FN_SLOTS), B_FUNCTION_SOURCE, get(w, C_FN_SOURCE_BYTES))

def outer_producer(w:mutbuf, kind:u64) -> u64:
    return producer(w, I_OUTER_RENDER, B_OUTER_WORK, B_OUTER_OUTPUT, OUT_STREAM, kind, get(w, L_OUT_REQUEST), 0, 0, B_OUTER_SOURCE, get(w, C_OUT_SOURCE_BYTES))

def commit_object(w:mutbuf, kind:u64, request:u64) -> u64:
    handle = get(w, L_OUT_HANDLE)
    row = object_row(w, handle)
    if row == 0 or get(w, row) != 0 or get(w, L_CORE_ROOT) != 6:
        return 0
    if kind != 1 and kind != 2:
        return 0
    if kind == 1 and handle >= OBJECTS + 1024:
        return 0
    if kind == 2 and handle < OBJECTS + 1024:
        return 0
    if get(w, L_STREAM_OFFSET) > get(w, L_SPOOL_BYTES):
        return 0
    if get(w, L_STREAM_LENGTH) == 0 or get(w, L_STREAM_LENGTH) != get(w, L_SPOOL_BYTES) - get(w, L_STREAM_OFFSET):
        return 0
    put(w, row + 8, get(w, L_STREAM_OFFSET))
    put(w, row + 16, get(w, L_STREAM_LENGTH))
    put(w, row + 24, get(w, L_DIGEST0))
    put(w, row + 32, get(w, L_DIGEST1))
    put(w, row + 40, get(w, L_DIGEST2))
    put(w, row + 48, get(w, L_DIGEST3))
    put(w, row + 56, get(w, L_CORE_ROOT))
    put(w, row + 64, get(w, L_CORE_NODES))
    put(w, row + 72, get(w, L_CORE_DEPTH))
    put(w, row + 80, get(w, L_CORE_MASK))
    put(w, row + 88, get(w, L_CORE_UNKNOWN))
    put(w, row + 96, request)
    put(w, row + 104, kind)
    put(w, row, handle)
    return 1

def main_step(o:mutbuf, w:mutbuf) -> u32:
    phase = get(w, C_PHASE)
    if phase == 10000:
        if get(w, C_ERROR_GROUP) != 0:
            return finish(o, w, get(w, C_ERROR_GROUP), get(w, C_FINAL_ERROR), get(w, C_CTOR_REQUEST))
        return grow(o, w, B_FUNCTION_WORK, FUNCTION_BYTES, 10001)
    if phase == 10001:
        return grow(o, w, B_FUNCTION_OUTPUT, OWNER_OUTPUT_BYTES, 10002)
    if phase == 10002:
        return invoke(o, w, I_FUNCTION_ADMIT, B_FUNCTION_PACKET, 0, get(w, C_FN_PACKET_BYTES), B_FUNCTION_OUTPUT, OWNER_OUTPUT_BYTES, B_FUNCTION_WORK, FUNCTION_BYTES, B_FUNCTION_OUTPUT, 0, 64, 10003)
    if phase == 10003:
        if function_frame(w) == 0 or get(w, L_FN_ACTION) != 0 or get(w, L_FN_OBS_REQUEST) != 0:
            return refuse(w, 104)
        if get(w, L_FN_SERIAL) != 0 or get(w, L_FN_SLOTS) != 0:
            return refuse(w, 105)
        return grow(o, w, B_OUTER_WORK, OUTER_BYTES, 10004)
    if phase == 10004:
        return grow(o, w, B_OUTER_OUTPUT, OWNER_OUTPUT_BYTES, 10005)
    if phase == 10005:
        return invoke(o, w, I_OUTER_OWNER, B_OUTER_PACKET, 0, get(w, C_OUT_PACKET_BYTES), B_OUTER_OUTPUT, OWNER_OUTPUT_BYTES, B_OUTER_WORK, OUTER_BYTES, B_OUTER_OUTPUT, 0, 64, 10006)
    if phase == 10006:
        if outer_frame(w) == 0 or get(w, L_OUT_ACTION) != 0:
            return refuse(w, 106)
        return file_create(o, w, 0, 11000)
    if phase == 11000:
        if get(w, L_OUT_PHASE) != 0 or get(w, L_OUT_ACTION) != 0:
            return refuse(w, 107)
        return invoke(o, w, I_OUTER_OWNER, B_TYPES, 0, TYPES_BYTES, B_OUTER_OUTPUT, OWNER_OUTPUT_BYTES, B_OUTER_WORK, OUTER_BYTES, B_OUTER_OUTPUT, 0, 64, 11010)
    if phase == 11010:
        if outer_frame(w) == 0:
            return refuse(w, 108)
        if get(w, L_OUT_ERROR) == 1:
            return finish(o, w, 5, 1, get(w, L_OUT_REQUEST))
        if get(w, L_OUT_ERROR) != 0 or get(w, L_OUT_ACTION) != 2:
            return refuse(w, 109)
        if get(w, L_OUT_PHASE) == 2000:
            return file_seal(o, w, 0, 15000)
        if get(w, L_OUT_PHASE) != 10:
            return refuse(w, 110)
        outer_producer(w, 1)
        put(w, L_IR_RETURN, 11100)
        return switch(o, w, DRIVER_SERVICES, 20000)
    if phase == 11100:
        put(w, C_OWNER_TARGET, 3)
        put(w, C_PACKET_RETURN, 11110)
        return switch(o, w, DRIVER_SERVICES, 21000)
    if phase == 11110:
        if get(w, C_PACKET_BYTES) < 17 or get(w, C_PACKET_BYTES) > 144:
            return refuse(w, 111)
        put(w, L_FN_HELPERS, 0)
        put(w, L_DELEGATE_GROUP, 0)
        put(w, L_DELEGATE_ERROR, 0)
        put(w, L_DELEGATE_REQUEST, 0)
        put(w, L_FN_KERNEL, I_FUNCTION_ADMIT)
        return invoke(o, w, I_FUNCTION_ADMIT, get(w, C_PACKET_SLOT), get(w, C_PACKET_OFFSET), get(w, C_PACKET_BYTES), B_FUNCTION_OUTPUT, OWNER_OUTPUT_BYTES, B_FUNCTION_WORK, FUNCTION_BYTES, B_FUNCTION_OUTPUT, 0, 64, 11120)
    if phase == 11120:
        if function_frame(w) == 0 or get(w, L_FN_ACTION) != 0 or get(w, L_FN_OBS_REQUEST) != get(w, L_FN_REQUEST):
            return refuse(w, 112)
        put(w, C_PHASE, 12000)
        return 0
    if phase == 12000:
        return invoke(o, w, get(w, L_FN_KERNEL), B_TYPES, 0, TYPES_BYTES, B_FUNCTION_OUTPUT, OWNER_OUTPUT_BYTES, B_FUNCTION_WORK, FUNCTION_BYTES, B_FUNCTION_OUTPUT, 0, 64, 12010)
    if phase == 12010:
        if function_frame(w) == 0:
            return refuse(w, 113)
        action = get(w, L_FN_ACTION)
        if action == 1:
            if get(w, L_FN_OBS_REQUEST) != get(w, L_FN_REQUEST):
                return refuse(w, 114)
            put(w, L_META_RETURN, 12310)
            return switch(o, w, DRIVER_SERVICES, 25000)
        if action == 10 or action == 21:
            put(w, L_FN_KERNEL, I_FUNCTION_RECORDS)
            put(w, C_PHASE, 12000)
            return 0
        if action == 20:
            put(w, L_FN_KERNEL, I_FUNCTION_TERMS)
            put(w, C_PHASE, 12000)
            return 0
        if action == 30:
            put(w, L_FN_KERNEL, I_FUNCTION_ADVANCED)
            put(w, C_PHASE, 12000)
            return 0
        if action != 2:
            return refuse(w, 115)
        if get(w, L_FN_PHASE) == 2000:
            if get(w, L_FN_OBS_REQUEST) != get(w, L_FN_REQUEST):
                return refuse(w, 116)
            function_producer(w, 0)
            put(w, L_STREAM_MODE, 1)
            put(w, L_STREAM_RETURN, 12510)
            return switch(o, w, DRIVER_STREAM, 30000)
        if get(w, L_FN_REQUEST) == MAX or get(w, L_FN_OBS_REQUEST) != get(w, L_FN_REQUEST) + 1:
            return refuse(w, 117)
        put(w, L_FN_REQUEST, get(w, L_FN_OBS_REQUEST))
        put(w, L_DELEGATE_GROUP, 0)
        put(w, L_DELEGATE_ERROR, 0)
        put(w, L_DELEGATE_REQUEST, 0)
        kind = MAX
        if get(w, L_FN_KERNEL) == I_FUNCTION_ADMIT:
            kind = 2
        function_producer(w, kind)
        put(w, L_IR_RETURN, 12210)
        return switch(o, w, DRIVER_SERVICES, 20000)
    if phase == 12210:
        kind = get(w, L_PRODUCER_KIND)
        put(w, L_SERVICE_KIND, kind)
        put(w, L_SERVICE_RETURN, 12220)
        if kind >= 2 and kind <= 5:
            return switch(o, w, DRIVER_SERVICES, 22000)
        if kind == 6 and get(w, L_FN_KERNEL) != I_FUNCTION_ADMIT:
            return switch(o, w, DRIVER_SERVICES, 23000)
        return refuse(w, 118)
    if phase == 12220:
        if get(w, C_PACKET_BYTES) == 0:
            return refuse(w, 119)
        return invoke(o, w, get(w, L_FN_KERNEL), get(w, C_PACKET_SLOT), get(w, C_PACKET_OFFSET), get(w, C_PACKET_BYTES), B_FUNCTION_OUTPUT, OWNER_OUTPUT_BYTES, B_FUNCTION_WORK, FUNCTION_BYTES, B_FUNCTION_OUTPUT, 0, 64, 12230)
    if phase == 12230:
        if function_frame(w) == 0 or get(w, L_FN_OBS_REQUEST) != get(w, L_FN_REQUEST):
            return refuse(w, 120)
        if get(w, L_FN_ACTION) == 1:
            if get(w, L_FN_ERROR) != 999 or get(w, L_DELEGATE_GROUP) == 0 or get(w, L_DELEGATE_REQUEST) != get(w, L_FN_REQUEST):
                return refuse(w, 121)
            put(w, L_META_RETURN, 12310)
            return switch(o, w, DRIVER_SERVICES, 25000)
        if get(w, L_FN_ACTION) != 0:
            return refuse(w, 122)
        put(w, C_PHASE, 12000)
        return 0
    if phase == 12310:
        if get(w, L_FN_ERROR) == 999:
            if get(w, L_DELEGATE_GROUP) == 0 or get(w, L_DELEGATE_REQUEST) != get(w, L_FN_REQUEST):
                return refuse(w, 123)
            put(w, L_FINAL_GROUP, get(w, L_DELEGATE_GROUP))
            put(w, L_FINAL_ERROR, get(w, L_DELEGATE_ERROR))
        else:
            put(w, L_FINAL_GROUP, 3)
            put(w, L_FINAL_ERROR, get(w, L_FN_ERROR))
        wire8(w, OUT_FAIL, get(w, L_OUT_REQUEST), 0, 0, 0, 0, 0, 0)
        return invoke(o, w, I_OUTER_OWNER, B_CONTROLLER, WIRE, 32, B_OUTER_OUTPUT, OWNER_OUTPUT_BYTES, B_OUTER_WORK, OUTER_BYTES, B_OUTER_OUTPUT, 0, 64, 12320)
    if phase == 12320:
        if outer_frame(w) == 0 or get(w, L_OUT_ERROR) != 999 or get(w, L_OUT_ACTION) != 1:
            return refuse(w, 124)
        return finish(o, w, get(w, L_FINAL_GROUP), get(w, L_FINAL_ERROR), get(w, L_FN_REQUEST))
    if phase == 12510:
        put(w, L_META_RETURN, 12520)
        return switch(o, w, DRIVER_SERVICES, 25000)
    if phase == 12520:
        if get(w, L_CORE_ROOT) != 6 or get(w, L_CORE_UNKNOWN) != 0:
            return refuse(w, 125)
        if get(w, L_CORE_MASK) != 63 and get(w, L_CORE_MASK) != 127:
            return refuse(w, 126)
        return invoke(o, w, I_OUTER_OWNER, B_FUNCTION_WORK, 0, FUNCTION_BYTES, B_OUTER_OUTPUT, OWNER_OUTPUT_BYTES, B_OUTER_WORK, OUTER_BYTES, B_OUTER_OUTPUT, 0, 64, 13010)
    if phase == 13010:
        if outer_frame(w) == 0 or get(w, L_OUT_ACTION) != 4:
            return refuse(w, 127)
        if commit_object(w, 1, get(w, L_OUT_REQUEST)) == 0:
            return refuse(w, 128)
        put(w, L_FN_COUNT, get(w, L_OUT_FUNCTIONS))
        wire8(w, OUT_ACK, get(w, L_OUT_REQUEST), 1, get(w, L_OUT_HANDLE), 0, 0, 0, 0)
        return invoke(o, w, I_OUTER_OWNER, B_CONTROLLER, WIRE, 32, B_OUTER_OUTPUT, OWNER_OUTPUT_BYTES, B_OUTER_WORK, OUTER_BYTES, B_OUTER_OUTPUT, 0, 64, 13020)
    if phase == 13020:
        if outer_frame(w) == 0 or get(w, L_OUT_ACTION) != 0 or get(w, L_OUT_PHASE) != 0:
            return refuse(w, 129)
        put(w, C_PHASE, 11000)
        return 0
    if phase == 15000:
        outer_producer(w, 0)
        put(w, L_STREAM_MODE, 2)
        put(w, L_STREAM_RETURN, 15010)
        return switch(o, w, DRIVER_STREAM, 30000)
    if phase == 15010:
        if get(w, L_CORE_ROOT) != 6 or get(w, L_CORE_UNKNOWN) != 0 or get(w, L_CORE_MASK) != 1920:
            return refuse(w, 130)
        put(w, L_STREAM_RETURN, 15020)
        return switch(o, w, DRIVER_STREAM, 34000)
    if phase == 15020:
        error = get(w, L_CORE_LATE)
        if error > 3:
            return refuse(w, 131)
        if error != 0:
            return finish(o, w, 6, error, get(w, L_OUT_REQUEST))
        return finish(o, w, 0, 0, get(w, L_OUT_REQUEST))
    return refuse(w, 132)
'''
