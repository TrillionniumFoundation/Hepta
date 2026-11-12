"""Native service, source-index, and metadata continuations for full lowering.

RECONSTRUCTED-DEVELOPMENT-r1. This module is paired with the independent helper
transport owner; no Python value decoder or type materializer is invoked.
"""
from __future__ import annotations

BODY = r'''
def lower_services(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < MIN_WORK:
        return ABI
    if length(o) < 128 or acknowledge(s, w, DRIVER_SERVICES) == 0:
        return refuse(w, 200)
    while get(w, L_STATUS) == 1:
        result = services_step(o, w)
        if result != 0:
            return result
    return refuse(w, 201)

def services_step(o:mutbuf, w:mutbuf) -> u64:
    phase = get(w, C_PHASE)
    if phase >= 20000 and phase < 21000:
        return ir_step(o, w)
    if phase >= 21000 and phase < 22000:
        return owner_projection_step(o, w)
    if phase >= 22000 and phase < 23000:
        return type_service_step(o, w)
    if phase >= 23000 and phase < 24000:
        return helper_service_step(o, w)
    if phase >= 25000 and phase < 26000:
        return metadata_step(o, w)
    if phase >= 26000 and phase < 27000:
        return index_step(o, w)
    if phase >= 28000 and phase < 29000:
        return query_step(o, w)
    return refuse(w, 202)

def producer_frame(w:mutbuf) -> u64:
    size = get(w, C_RETURN)
    if size < 64 or size > OWNER_OUTPUT_BYTES or get(w, OBS) != get(w, L_PRODUCER_MAGIC):
        return 0
    kind = get(w, OBS + 8)
    if get(w, L_PRODUCER_KIND) == MAX:
        if get(w, L_PRODUCER_MAGIC) != FN_STREAM or kind < 2 or kind > 6:
            return 0
        put(w, L_PRODUCER_KIND, kind)
    elif kind != get(w, L_PRODUCER_KIND):
        return 0
    if get(w, OBS + 16) != get(w, L_PRODUCER_SEQUENCE) or get(w, OBS + 24) > 1:
        return 0
    if get(w, OBS + 32) != get(w, L_PRODUCER_SERIAL) or get(w, OBS + 40) != get(w, L_PRODUCER_SLOTS):
        return 0
    if get(w, OBS + 48) != get(w, L_PRODUCER_REQUEST) or get(w, OBS + 56) != size - 64:
        return 0
    put(w, L_PRODUCER_BYTES, size)
    put(w, L_PRODUCER_FINAL, get(w, OBS + 24))
    return 1

def ir_event(w:mutbuf, initial:u64) -> u64:
    if get(w, C_RETURN) != 1152 or get(w, OBS) != IR_EVENT:
        return 0
    if get(w, OBS + 24) != get(w, C_LEASE) or get(w, OBS + 32) != get(w, C_IR_STREAM):
        return 0
    if get(w, C_IR_ESEQ) == MAX or get(w, OBS + 48) != get(w, C_IR_ESEQ) + 1:
        return 0
    if get(w, OBS + 88) != 0 or get(w, OBS + 96) != 0 or get(w, OBS + 104) != 0 or get(w, OBS + 112) != 0 or get(w, OBS + 120) != 0:
        return 0
    action = get(w, OBS + 8)
    if initial != 0:
        if action != 1 or get(w, OBS + 16) != 1 or get(w, OBS + 40) != 0:
            return 0
        if get(w, OBS + 56) != 0 or get(w, OBS + 64) != 0 or get(w, OBS + 72) != 131328 or get(w, OBS + 80) != 0:
            return 0
    elif action == 3:
        if get(w, OBS + 16) != 1 or get(w, OBS + 40) != get(w, L_PRODUCER_SEQUENCE):
            return 0
        if get(w, OBS + 80) <= cap(w, B_IR):
            return 0
    elif action == 1 or action == 5:
        if get(w, L_PRODUCER_SEQUENCE) == MAX or get(w, OBS + 40) != get(w, L_PRODUCER_SEQUENCE) + 1:
            return 0
        if get(w, OBS + 80) != 0:
            return 0
        if action == 1:
            if get(w, OBS + 16) != 1 or get(w, L_PRODUCER_FINAL) != 0:
                return 0
        else:
            if get(w, OBS + 16) != 2 or get(w, L_PRODUCER_FINAL) != 1 or get(w, OBS + 64) == 0:
                return 0
    else:
        return 0
    if get(w, OBS + 72) < 131328 or get(w, OBS + 72) > cap(w, B_IR):
        return 0
    put(w, C_IR_ESEQ, get(w, OBS + 48))
    put(w, C_IR_PSEQ, get(w, OBS + 40))
    put(w, C_IR_ROOT, get(w, OBS + 56))
    put(w, C_IR_NODES, get(w, OBS + 64))
    put(w, C_IR_EXTENT, get(w, OBS + 72))
    put(w, L_IR_ACTION, action)
    return 1

def ir_step(o:mutbuf, w:mutbuf) -> u64:
    phase = get(w, C_PHASE)
    if phase == 20000:
        if advance(w, L_STREAM_NUMBER) == 0:
            return ABI
        put(w, C_IR_STREAM, get(w, L_STREAM_NUMBER))
        put(w, C_IR_ESEQ, 0)
        put(w, C_IR_PSEQ, 0)
        put(w, C_IR_ROOT, 0)
        put(w, C_IR_NODES, 0)
        put(w, C_IR_EXTENT, 0)
        return release(o, w, B_IR, 20001)
    if phase == 20001:
        return grow(o, w, B_IR, 131328, 20002)
    if phase == 20002 or phase == 20020:
        return invoke(o, w, get(w, L_PRODUCER_IMAGE), B_EMPTY, 0, 0, get(w, L_PRODUCER_OUTPUT), OWNER_OUTPUT_BYTES, get(w, L_PRODUCER_WORK), cap(w, get(w, L_PRODUCER_WORK)), get(w, L_PRODUCER_OUTPUT), 0, 64, 20003)
    if phase == 20003:
        if producer_frame(w) == 0:
            return refuse(w, 203)
        if get(w, C_IR_ESEQ) != 0:
            put(w, C_PHASE, 20006)
            return 0
        wire8(w, IR_INIT, get(w, C_LEASE), get(w, C_IR_STREAM), get(w, L_PRODUCER_MAGIC), get(w, L_PRODUCER_KIND), get(w, L_PRODUCER_REQUEST), get(w, L_PRODUCER_SERIAL), get(w, L_PRODUCER_SLOTS))
        return invoke(o, w, I_IR, B_CONTROLLER, WIRE, 64, get(w, L_STREAM_SOURCE), get(w, L_STREAM_SOURCE_EXTENT), B_IR, cap(w, B_IR), B_IR, 1024, 128, 20004)
    if phase == 20004:
        if ir_event(w, 1) == 0:
            return refuse(w, 204)
        put(w, C_PHASE, 20006)
        return 0
    if phase == 20006:
        return invoke(o, w, I_IR, get(w, L_PRODUCER_OUTPUT), 0, get(w, L_PRODUCER_BYTES), get(w, L_STREAM_SOURCE), get(w, L_STREAM_SOURCE_EXTENT), B_IR, cap(w, B_IR), B_IR, 1024, 128, 20007)
    if phase == 20007:
        if ir_event(w, 0) == 0:
            return refuse(w, 205)
        if get(w, L_IR_ACTION) == 3:
            return grow(o, w, B_IR, get(w, OBS + 80), 20008)
        if advance(w, L_PRODUCER_SEQUENCE) == 0:
            return ABI
        if get(w, L_IR_ACTION) == 1:
            put(w, C_PHASE, 20020)
            return 0
        return switch(o, w, DRIVER_MAIN, get(w, L_IR_RETURN))
    if phase == 20008:
        wire8(w, IR_CONT, get(w, C_LEASE), get(w, C_IR_STREAM), get(w, C_IR_ESEQ), 0, 0, 0, 0)
        return invoke(o, w, I_IR, B_CONTROLLER, WIRE, 32, get(w, L_STREAM_SOURCE), get(w, L_STREAM_SOURCE_EXTENT), B_IR, cap(w, B_IR), B_IR, 1024, 128, 20007)
    return refuse(w, 206)

def owner_projection_step(o:mutbuf, w:mutbuf) -> u64:
    phase = get(w, C_PHASE)
    if phase == 21000:
        if get(w, C_OWNER_TARGET) != 3 or get(w, L_PRODUCER_MAGIC) != OUT_STREAM or get(w, L_PRODUCER_KIND) != 1:
            return refuse(w, 207)
        return release(o, w, B_PROJECTOR, 21001)
    if phase == 21001:
        return grow(o, w, B_PROJECTOR, 512, 21002)
    if phase == 21002:
        wire8(w, OWNER_CONFIG, 3, get(w, C_LEASE), get(w, C_IR_STREAM), get(w, L_PRODUCER_REQUEST), 0, 0, 0)
        zero(w, WIRE + 64, 64)
        return copy(o, w, B_CONTROLLER, WIRE, B_PROJECTOR, 128, 128, 21003)
    if phase == 21003:
        return invoke(o, w, I_OWNER_PACKET, B_IR, 0, get(w, C_IR_EXTENT), get(w, L_STREAM_SOURCE), get(w, L_STREAM_SOURCE_EXTENT), B_PROJECTOR, cap(w, B_PROJECTOR), B_PROJECTOR, 0, 128, 21004)
    if phase == 21004:
        if get(w, C_RETURN) != 128 or get(w, OBS) != OWNER_EVENT or get(w, OBS + 16) != 3:
            return refuse(w, 208)
        if get(w, OBS + 24) != get(w, C_LEASE) or get(w, OBS + 32) != get(w, C_IR_STREAM) or get(w, OBS + 40) != get(w, L_PRODUCER_REQUEST):
            return refuse(w, 209)
        if get(w, OBS + 48) != 0 or get(w, OBS + 56) != 0 or get(w, OBS + 88) != 0:
            return refuse(w, 210)
        if get(w, OBS + 96) != 0 or get(w, OBS + 104) != 0 or get(w, OBS + 112) != 0 or get(w, OBS + 120) != 0:
            return refuse(w, 211)
        if get(w, OBS + 8) == 1:
            if get(w, OBS + 80) <= cap(w, B_PROJECTOR):
                return refuse(w, 212)
            return grow(o, w, B_PROJECTOR, get(w, OBS + 80), 21003)
        if get(w, OBS + 8) != 0 or get(w, OBS + 72) < 17 or get(w, OBS + 72) > 144:
            return refuse(w, 213)
        if inside(w, B_PROJECTOR, get(w, OBS + 64), get(w, OBS + 72)) == 0:
            return refuse(w, 214)
        if get(w, OBS + 80) != get(w, OBS + 64) + get(w, OBS + 72):
            return refuse(w, 215)
        put(w, C_PACKET_SLOT, B_PROJECTOR)
        put(w, C_PACKET_OFFSET, get(w, OBS + 64))
        put(w, C_PACKET_BYTES, get(w, OBS + 72))
        return switch(o, w, DRIVER_MAIN, get(w, C_PACKET_RETURN))
    return refuse(w, 216)

def json_workspace(w:mutbuf, size:u64) -> u64:
    slots = 2
    while slots < (size >> 5) * 2:
        slots = slots * 2
    index = 128 + slots * 16
    bitmap = (size + 7) >> 3
    stack = (index + bitmap + 7) & (MAX - 7)
    frames = ((size * 2863311531) >> 36) + 1
    put(w, C_BITMAP_OFFSET, index)
    put(w, C_BITMAP_BYTES, bitmap)
    return stack + frames * 32

def index_step(o:mutbuf, w:mutbuf) -> u64:
    phase = get(w, C_PHASE)
    if phase == 26000:
        size = get(w, C_PACKET_BYTES)
        if size < 16 or size > PACKET_LIMIT or inside(w, get(w, C_PACKET_SLOT), get(w, C_PACKET_OFFSET), size) == 0:
            return refuse(w, 217)
        put(w, L_INDEX_PACKET_SLOT, get(w, C_PACKET_SLOT))
        put(w, L_INDEX_PACKET_OFFSET, get(w, C_PACKET_OFFSET))
        put(w, L_INDEX_PACKET_BYTES, size)
        put(w, L_INDEX_WORK_BYTES, json_workspace(w, size))
        put(w, L_INDEX_OUTPUT_BYTES, 64 + size * 6)
        return grow(o, w, B_PACKET_WORK, get(w, L_INDEX_WORK_BYTES), 26001)
    if phase == 26001:
        return grow(o, w, B_PACKET_JSON, get(w, L_INDEX_OUTPUT_BYTES), 26002)
    if phase == 26002:
        wire8(w, PACKET_JSON_MAGIC, 0, 0, 0, 0, 0, 0, 0)
        zero(w, WIRE + 64, 64)
        return copy(o, w, B_CONTROLLER, WIRE, B_PACKET_WORK, 0, 128, 26003)
    if phase == 26003:
        return invoke(o, w, I_PACKET_JSON, get(w, L_INDEX_PACKET_SLOT), get(w, L_INDEX_PACKET_OFFSET), get(w, L_INDEX_PACKET_BYTES), B_PACKET_JSON, get(w, L_INDEX_OUTPUT_BYTES), B_PACKET_WORK, get(w, L_INDEX_WORK_BYTES), B_PACKET_JSON, 0, 64, 26004)
    if phase == 26004:
        if get(w, C_RETURN) < 65 or get(w, C_RETURN) > get(w, L_INDEX_OUTPUT_BYTES):
            return refuse(w, 218)
        if get(w, OBS) != PACKET_JSON_MAGIC or get(w, OBS + 8) != 0 or get(w, OBS + 16) != 64:
            return refuse(w, 219)
        if get(w, OBS + 24) != get(w, C_RETURN) - 64 or get(w, OBS + 32) == 0 or get(w, OBS + 40) != get(w, L_INDEX_PACKET_BYTES):
            return refuse(w, 220)
        if get(w, OBS + 48) != get(w, C_BITMAP_OFFSET) or get(w, OBS + 56) != get(w, C_BITMAP_BYTES):
            return refuse(w, 221)
        put(w, C_JSON_BYTES, get(w, OBS + 24))
        if get(w, L_INDEX_TARGET) == 0:
            put(w, C_PHASE, get(w, L_INDEX_RETURN))
            return 0
        size = get(w, L_INDEX_PACKET_BYTES)
        extent = ((64 + size + 7) & (MAX - 7)) + get(w, C_BITMAP_BYTES)
        put(w, L_INDEX_SOURCE_BYTES, extent)
        return release(o, w, get(w, L_INDEX_TARGET), 26005)
    if phase == 26005:
        return grow(o, w, get(w, L_INDEX_TARGET), get(w, L_INDEX_SOURCE_BYTES), 26006)
    if phase == 26006:
        size = get(w, L_INDEX_PACKET_BYTES)
        wire8(w, SOURCE_MAGIC, size, get(w, C_BITMAP_BYTES), 64, (64 + size + 7) & (MAX - 7), get(w, L_INDEX_SOURCE_BYTES), 0, 0)
        return copy(o, w, B_CONTROLLER, WIRE, get(w, L_INDEX_TARGET), 0, 64, 26007)
    if phase == 26007:
        return copy(o, w, get(w, L_INDEX_PACKET_SLOT), get(w, L_INDEX_PACKET_OFFSET), get(w, L_INDEX_TARGET), 64, get(w, L_INDEX_PACKET_BYTES), 26008)
    if phase == 26008:
        offset = (64 + get(w, L_INDEX_PACKET_BYTES) + 7) & (MAX - 7)
        return copy(o, w, B_PACKET_WORK, get(w, C_BITMAP_OFFSET), get(w, L_INDEX_TARGET), offset, get(w, C_BITMAP_BYTES), 26009)
    if phase == 26009:
        return protect(o, w, get(w, L_INDEX_TARGET), 1, 26010)
    if phase == 26010:
        put(w, C_PHASE, get(w, L_INDEX_RETURN))
        return 0
    return refuse(w, 222)

def type_event(w:mutbuf, operation:u64, request:u64) -> u64:
    if get(w, C_RETURN) != 128 or get(w, OBS) != TYPE_EVENT:
        return 0
    if get(w, OBS + 16) != get(w, C_LEASE) or get(w, OBS + 24) != get(w, C_TYPE_SEQUENCE):
        return 0
    if get(w, OBS + 32) != request or get(w, OBS + 40) != operation:
        return 0
    if get(w, OBS + 8) == 1:
        if get(w, OBS + 48) != 0 or get(w, OBS + 56) != 0 or get(w, OBS + 88) != 0 or get(w, OBS + 96) != 0 or get(w, OBS + 104) != 0 or get(w, OBS + 112) != 0:
            return 0
        if get(w, OBS + 120) <= cap(w, B_TRANSPORT):
            return 0
    elif get(w, OBS + 8) == 0:
        if get(w, OBS + 48) > 50 or get(w, OBS + 120) != 0:
            return 0
    else:
        return 0
    return 1

def type_service_step(o:mutbuf, w:mutbuf) -> u64:
    phase = get(w, C_PHASE)
    if phase == 22000:
        if get(w, C_TYPES_LIVE) != 1 or get(w, L_SERVICE_KIND) < 2 or get(w, L_SERVICE_KIND) > 5:
            return refuse(w, 223)
        if get(w, L_PRODUCER_MAGIC) != FN_STREAM or get(w, L_PRODUCER_KIND) != get(w, L_SERVICE_KIND) or get(w, L_PRODUCER_REQUEST) != get(w, L_FN_REQUEST):
            return refuse(w, 224)
        put(w, L_SERVICE_TARGET, 3)
        if get(w, L_FN_KERNEL) == I_FUNCTION_ADMIT:
            if get(w, L_SERVICE_KIND) != 2:
                return refuse(w, 225)
            put(w, L_SERVICE_TARGET, 2)
        return release(o, w, B_REQUEST, 22001)
    if phase == 22001:
        return grow(o, w, B_REQUEST, 512, 22002)
    if phase == 22002:
        wire8(w, TYPE_REQUEST_CONFIG, 2, get(w, L_SERVICE_KIND), get(w, C_LEASE), get(w, C_IR_STREAM), get(w, L_FN_REQUEST), 0, 0)
        zero(w, WIRE + 64, 64)
        return copy(o, w, B_CONTROLLER, WIRE, B_REQUEST, 128, 128, 22003)
    if phase == 22003:
        return invoke(o, w, I_TYPE_REQUEST, B_IR, 0, get(w, C_IR_EXTENT), B_FUNCTION_SOURCE, get(w, C_FN_SOURCE_BYTES), B_REQUEST, cap(w, B_REQUEST), B_REQUEST, 0, 128, 22004)
    if phase == 22004:
        if get(w, C_RETURN) != 128 or get(w, OBS) != TYPE_REQUEST_EVENT:
            return refuse(w, 226)
        operation = get(w, L_SERVICE_KIND)
        if operation == 5:
            operation = 6
        if get(w, OBS + 24) != get(w, L_SERVICE_KIND) or get(w, OBS + 32) != get(w, L_FN_REQUEST):
            return refuse(w, 227)
        if get(w, OBS + 16) != operation:
            if get(w, OBS + 8) != 1 or get(w, OBS + 16) != 0 or get(w, OBS + 64) != 0 or get(w, OBS + 72) != get(w, OBS + 56):
                return refuse(w, 227)
        if get(w, OBS + 40) != get(w, C_LEASE) or get(w, OBS + 48) != get(w, C_IR_STREAM):
            return refuse(w, 228)
        if get(w, OBS + 80) != 0 or get(w, OBS + 88) != 0 or get(w, OBS + 96) != 0 or get(w, OBS + 104) != 0 or get(w, OBS + 112) != 0 or get(w, OBS + 120) != 0:
            return refuse(w, 229)
        if get(w, OBS + 8) == 1:
            if get(w, OBS + 72) <= cap(w, B_REQUEST) or get(w, OBS + 56) > MAX - get(w, OBS + 64) or get(w, OBS + 72) != get(w, OBS + 56) + get(w, OBS + 64):
                return refuse(w, 230)
            return grow(o, w, B_REQUEST, get(w, OBS + 72), 22003)
        if get(w, OBS + 8) != 0 or get(w, OBS + 64) < 16 or get(w, OBS + 64) > PACKET_LIMIT:
            return refuse(w, 231)
        if inside(w, B_REQUEST, get(w, OBS + 56), get(w, OBS + 64)) == 0:
            return refuse(w, 232)
        if get(w, OBS + 72) != get(w, OBS + 56) + get(w, OBS + 64):
            return refuse(w, 233)
        put(w, C_TYPE_OP, operation)
        put(w, C_PACKET_SLOT, B_REQUEST)
        put(w, C_PACKET_OFFSET, get(w, OBS + 56))
        put(w, C_PACKET_BYTES, get(w, OBS + 64))
        put(w, L_INDEX_TARGET, 0)
        put(w, L_INDEX_RETURN, 22100)
        put(w, C_PHASE, 26000)
        return 0
    if phase == 22100:
        if advance(w, C_TYPE_SEQUENCE) == 0:
            return ABI
        put(w, C_WIRE_BYTES, 64 + get(w, C_PACKET_BYTES))
        return grow(o, w, B_TYPE_WIRE, get(w, C_WIRE_BYTES), 22101)
    if phase == 22101:
        wire8(w, TYPE_BEGIN, get(w, C_LEASE), get(w, C_TYPE_SEQUENCE), get(w, C_TYPE_OP), get(w, L_FN_REQUEST), get(w, C_PACKET_BYTES), 0, 0)
        return copy(o, w, B_CONTROLLER, WIRE, B_TYPE_WIRE, 0, 64, 22102)
    if phase == 22102:
        return copy(o, w, B_REQUEST, get(w, C_PACKET_OFFSET), B_TYPE_WIRE, 64, get(w, C_PACKET_BYTES), 22103)
    if phase == 22103:
        return invoke(o, w, I_TYPE_COMMANDS, B_TYPE_WIRE, 0, get(w, C_WIRE_BYTES), B_TYPE_EVENT, 128, B_TRANSPORT, cap(w, B_TRANSPORT), B_TYPE_EVENT, 0, 128, 22104)
    if phase == 22104:
        if type_event(w, get(w, C_TYPE_OP), get(w, L_FN_REQUEST)) == 0:
            return refuse(w, 234)
        if get(w, OBS + 8) == 1:
            return grow(o, w, B_TRANSPORT, get(w, OBS + 120), 22103)
        if get(w, OBS + 48) != 0 or get(w, OBS + 56) != 0 or get(w, OBS + 88) != 0 or get(w, OBS + 96) != 0 or get(w, OBS + 104) != 0 or get(w, OBS + 112) != 0:
            return refuse(w, 235)
        return invoke(o, w, I_TYPES, B_PACKET_JSON, 64, get(w, C_JSON_BYTES), B_TYPE_OUTPUT, TYPE_OUTPUT_BYTES, B_TYPES, TYPES_BYTES, B_TYPE_OUTPUT, 0, 64, 22200)
    if phase == 22200:
        if get(w, C_RETURN) < 64 or get(w, C_RETURN) > TYPE_OUTPUT_BYTES:
            return refuse(w, 236)
        put(w, C_FRAME_BYTES, get(w, C_RETURN))
        put(w, C_WIRE_BYTES, 64 + get(w, C_RETURN))
        return grow(o, w, B_TYPE_WIRE, get(w, C_WIRE_BYTES), 22201)
    if phase == 22201:
        wire8(w, TYPE_REPLY, get(w, C_LEASE), get(w, C_TYPE_SEQUENCE), get(w, C_TYPE_OP), get(w, L_FN_REQUEST), get(w, C_FRAME_BYTES), 0, 0)
        return copy(o, w, B_CONTROLLER, WIRE, B_TYPE_WIRE, 0, 64, 22202)
    if phase == 22202:
        return copy(o, w, B_TYPE_OUTPUT, 0, B_TYPE_WIRE, 64, get(w, C_FRAME_BYTES), 22203)
    if phase == 22203:
        return invoke(o, w, I_TYPE_REPLY, B_TYPE_WIRE, 0, get(w, C_WIRE_BYTES), B_TYPE_EVENT, 128, B_TRANSPORT, cap(w, B_TRANSPORT), B_TYPE_EVENT, 0, 128, 22204)
    if phase == 22204:
        if type_event(w, get(w, C_TYPE_OP), get(w, L_FN_REQUEST)) == 0:
            return refuse(w, 237)
        if get(w, OBS + 8) == 1:
            return grow(o, w, B_TRANSPORT, get(w, OBS + 120), 22203)
        put(w, C_TYPE_ERROR, get(w, OBS + 48))
        if get(w, C_TYPE_ERROR) != 0:
            put(w, L_DELEGATE_GROUP, 2)
            put(w, L_DELEGATE_ERROR, get(w, C_TYPE_ERROR))
            put(w, L_DELEGATE_REQUEST, get(w, L_FN_REQUEST))
        return release(o, w, B_RESPONSE, 22300)
    if phase == 22300:
        return grow(o, w, B_RESPONSE, 512, 22301)
    if phase == 22301:
        wire8(w, TYPE_RESPONSE_CONFIG, get(w, L_SERVICE_TARGET), get(w, L_SERVICE_KIND), get(w, L_FN_REQUEST), get(w, C_LEASE), get(w, C_TYPE_SEQUENCE), get(w, C_TYPE_OP), 0)
        zero(w, WIRE + 64, 64)
        return copy(o, w, B_CONTROLLER, WIRE, B_RESPONSE, 128, 128, 22302)
    if phase == 22302:
        return invoke(o, w, I_TYPE_RESPONSE, B_TYPE_EVENT, 0, 128, B_TRANSPORT, cap(w, B_TRANSPORT), B_RESPONSE, cap(w, B_RESPONSE), B_RESPONSE, 0, 128, 22303)
    if phase == 22303:
        if get(w, C_RETURN) != 128 or get(w, OBS) != TYPE_RESPONSE_EVENT:
            return refuse(w, 238)
        if get(w, OBS + 16) != get(w, L_SERVICE_TARGET) or get(w, OBS + 24) != get(w, L_SERVICE_KIND) or get(w, OBS + 32) != get(w, L_FN_REQUEST):
            return refuse(w, 239)
        if get(w, OBS + 40) != get(w, C_LEASE) or get(w, OBS + 48) != get(w, C_TYPE_SEQUENCE) or get(w, OBS + 56) != 512:
            return refuse(w, 240)
        if get(w, OBS + 80) != get(w, C_TYPE_ERROR) or get(w, OBS + 88) != get(w, C_TYPE_OP) or get(w, OBS + 96) != 0:
            return refuse(w, 241)
        if get(w, OBS + 104) != 0 or get(w, OBS + 112) != 0 or get(w, OBS + 120) != 0:
            return refuse(w, 242)
        if get(w, OBS + 72) != 512 + get(w, OBS + 64):
            return refuse(w, 243)
        if get(w, OBS + 8) == 1:
            if get(w, OBS + 72) <= cap(w, B_RESPONSE):
                return refuse(w, 244)
            return grow(o, w, B_RESPONSE, get(w, OBS + 72), 22302)
        if get(w, OBS + 8) != 0 or get(w, OBS + 64) < 32 or inside(w, B_RESPONSE, 512, get(w, OBS + 64)) == 0:
            return refuse(w, 245)
        put(w, C_PACKET_SLOT, B_RESPONSE)
        put(w, C_PACKET_OFFSET, 512)
        put(w, C_PACKET_BYTES, get(w, OBS + 64))
        return switch(o, w, DRIVER_MAIN, get(w, L_SERVICE_RETURN))
    return refuse(w, 246)

def query_event(w:mutbuf, identifier:u64, sequence:u64) -> u64:
    if get(w, C_RETURN) != 128 or get(w, OBS) != TYPE_EVENT or get(w, OBS + 8) != 0:
        return 0
    if get(w, OBS + 16) != get(w, C_LEASE) or get(w, OBS + 24) != get(w, C_TYPE_SEQUENCE) or get(w, OBS + 32) != sequence:
        return 0
    if get(w, OBS + 40) != 0 or get(w, OBS + 48) != 0 or get(w, OBS + 56) != identifier:
        return 0
    if get(w, OBS + 88) != 4 or get(w, OBS + 96) != 1 or get(w, OBS + 120) != 0:
        return 0
    if get(w, OBS + 112) < 16 or inside(w, B_TRANSPORT, get(w, OBS + 104), get(w, OBS + 112)) == 0:
        return 0
    return 1

def query_step(o:mutbuf, w:mutbuf) -> u64:
    phase = get(w, C_PHASE)
    if phase == 28000:
        if get(w, L_QUERY_ID) == 0 or get(w, L_QUERY_ID) > 4294967295:
            return refuse(w, 247)
        if advance(w, L_QUERY_SEQUENCE) == 0:
            return ABI
        return grow(o, w, B_QUERY_EVENT, 128, 28001)
    if phase == 28001:
        wire8(w, TYPE_QUERY, get(w, C_LEASE), get(w, C_TYPE_SEQUENCE), get(w, L_QUERY_SEQUENCE), get(w, L_QUERY_ID), 0, 0, 0)
        return invoke(o, w, I_TYPE_COMMANDS, B_CONTROLLER, WIRE, 64, B_QUERY_EVENT, 128, B_TRANSPORT, cap(w, B_TRANSPORT), B_QUERY_EVENT, 0, 128, 28002)
    if phase == 28002:
        if query_event(w, get(w, L_QUERY_ID), get(w, L_QUERY_SEQUENCE)) == 0:
            return refuse(w, 248)
        put(w, C_PHASE, get(w, L_QUERY_RETURN))
        return 0
    return refuse(w, 249)

def metadata_step(o:mutbuf, w:mutbuf) -> u64:
    phase = get(w, C_PHASE)
    if phase == 25000:
        wire8(w, FN_META_REQ, 0, 0, 0, 0, 0, 0, 0)
        return invoke(o, w, I_FUNCTION_RECORDS, B_CONTROLLER, WIRE, 16, B_FUNCTION_OUTPUT, OWNER_OUTPUT_BYTES, B_FUNCTION_WORK, FUNCTION_BYTES, B_FUNCTION_OUTPUT, 0, 64, 25001)
    if phase == 25001:
        if get(w, C_RETURN) < 64 or get(w, C_RETURN) > OWNER_OUTPUT_BYTES or get(w, OBS) != FN_META or get(w, OBS + 56) != 0:
            return refuse(w, 250)
        if get(w, OBS + 8) != get(w, L_FN_SERIAL) or get(w, OBS + 16) != get(w, L_FN_SLOTS):
            return refuse(w, 251)
        if get(w, OBS + 40) != get(w, L_FN_ERROR) or get(w, OBS + 48) != get(w, L_FN_REQUEST):
            return refuse(w, 252)
        if get(w, OBS + 24) > 720 or get(w, OBS + 32) > 720:
            return refuse(w, 253)
        if get(w, C_RETURN) != 64 + get(w, OBS + 24) * 24 + get(w, OBS + 32) * 8:
            return refuse(w, 254)
        put(w, L_META_SIZE, get(w, C_RETURN))
        put(w, L_META_COUNT, get(w, OBS + 24))
        put(w, L_META_APPEND, get(w, OBS + 32))
        put(w, L_META_INDEX, 0)
        put(w, L_META_PREVIOUS, 0)
        return protect(o, w, B_FUNCTION_OUTPUT, 1, 25002)
    if phase == 25002:
        if get(w, L_META_INDEX) == get(w, L_META_COUNT):
            put(w, L_META_INDEX, 0)
            put(w, C_PHASE, 25010)
            return 0
        return view(o, w, B_FUNCTION_OUTPUT, 64 + get(w, L_META_INDEX) * 24, 24, 25003)
    if phase == 25003:
        put(w, L_META_ID, get(w, OBS))
        put(w, L_META_OP, get(w, OBS + 8))
        put(w, L_META_NAME, get(w, OBS + 16))
        if get(w, L_META_OP) > 4 or get(w, L_META_NAME) <= get(w, L_META_PREVIOUS) or get(w, L_META_NAME) > get(w, L_FN_SERIAL):
            return refuse(w, 256)
        put(w, L_QUERY_ID, get(w, L_META_ID))
        put(w, L_QUERY_RETURN, 25004)
        put(w, C_PHASE, 28000)
        return 0
    if phase == 25004:
        i = 0
        while i < get(w, L_META_INDEX):
            row = CACHE_PENDING + i * 24
            if get(w, row) == get(w, L_META_ID) and get(w, row + 8) == get(w, L_META_OP):
                return refuse(w, 257)
            i = i + 1
        row = CACHE_PENDING + get(w, L_META_INDEX) * 24
        put(w, row, get(w, L_META_ID))
        put(w, row + 8, get(w, L_META_OP))
        put(w, row + 16, get(w, L_META_NAME))
        put(w, L_META_PREVIOUS, get(w, L_META_NAME))
        put(w, L_META_INDEX, get(w, L_META_INDEX) + 1)
        put(w, C_PHASE, 25002)
        return 0
    if phase == 25010:
        if get(w, L_META_APPEND) != get(w, L_FN_HELPERS):
            return refuse(w, 255)
        if get(w, L_META_INDEX) == get(w, L_META_APPEND):
            put(w, C_PHASE, 25012)
            return 0
        return view(o, w, B_FUNCTION_OUTPUT, 64 + get(w, L_META_COUNT) * 24 + get(w, L_META_INDEX) * 8, 8, 25011)
    if phase == 25011:
        if get(w, OBS) != get(w, HELPER_REQUESTS + get(w, L_META_INDEX) * 8):
            return refuse(w, 258)
        if get(w, L_META_INDEX) != 0 and get(w, OBS) <= get(w, HELPER_REQUESTS + (get(w, L_META_INDEX) - 1) * 8):
            return refuse(w, 259)
        put(w, L_META_INDEX, get(w, L_META_INDEX) + 1)
        put(w, C_PHASE, 25010)
        return 0
    if phase == 25012:
        i = 0
        while i < get(w, L_META_COUNT) * 24:
            store(w, CACHE_COMMITTED + i, byte(w, CACHE_PENDING + i))
            i = i + 1
        put(w, L_COMMITTED_CACHE_COUNT, get(w, L_META_COUNT))
        put(w, L_FN_HELPERS, 0)
        return protect(o, w, B_FUNCTION_OUTPUT, 0, 25013)
    if phase == 25013:
        return switch(o, w, DRIVER_MAIN, get(w, L_META_RETURN))
    return refuse(w, 260)
'''

from tools.hia_composite_lowering_driver_helper import BODY as HELPER_BODY
BODY += '\n' + HELPER_BODY
