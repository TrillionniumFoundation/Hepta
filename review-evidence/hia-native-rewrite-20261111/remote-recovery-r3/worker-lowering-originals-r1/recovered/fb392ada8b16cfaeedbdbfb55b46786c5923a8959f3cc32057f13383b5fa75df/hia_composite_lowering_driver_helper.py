"""Complete helper-service continuation inside the native lowering driver.

This code routes actual IR, actual type QUERY events, actual helper invocation,
outer leases, complete value indexing, native Core streaming, and the exact
numeric-error continuation. The helper packet itself is owned by the separate
HIA helper transport kernel. No descriptor or Core plan is interpreted in Python.
"""
from __future__ import annotations

BODY = r'''
def helper_event(w:mutbuf) -> u64:
    if get(w, C_RETURN) != 256 or get(w, OBS) != HELPER_EVENT:
        return 0
    if get(w, OBS + 16) != get(w, L_HELPER_LEASE) or get(w, OBS + 24) != get(w, L_FN_REQUEST):
        return 0
    if get(w, OBS + 32) != get(w, C_LEASE) or get(w, OBS + 40) != get(w, C_IR_STREAM):
        return 0
    if get(w, OBS + 48) != get(w, C_LEASE) or get(w, OBS + 56) != get(w, C_TYPE_SEQUENCE):
        return 0
    if get(w, OBS + 184) != 0:
        return 0
    action = get(w, OBS + 8)
    # The request owner publishes STARTSERIAL only after the issued task and
    # step QUERYs. Initial metadata and QUERY growth still carry zero here.
    # Actual helper invocation and every reply must bind the published value.
    if action == 3 or action == 4 or get(w, L_CALL_IMAGE) == I_HELPER_REPLY:
        if get(w, OBS + 80) != get(w, L_FN_SERIAL):
            return 0
    elif get(w, OBS + 80) != 0 and get(w, OBS + 80) != get(w, L_FN_SERIAL):
        return 0
    i = 216
    while i < 256:
        if get(w, OBS + i) != 0:
            return 0
        i = i + 8
    action = get(w, OBS + 8)
    if action == 2:
        if get(w, OBS + 176) <= cap(w, B_HELPER_TRANSPORT):
            return 0
    elif action != 1 and action != 3 and action != 4:
        return 0
    elif get(w, OBS + 176) != 0:
        return 0
    return 1

def helper_call(o:mutbuf, w:mutbuf, phase:u64) -> u64:
    return invoke(o, w, get(w, L_CALL_IMAGE), get(w, L_CALL_FIRST), get(w, L_CALL_OFFSET), get(w, L_CALL_EXTENT), get(w, L_CALL_SECOND), get(w, L_CALL_SECOND_EXTENT), B_HELPER_TRANSPORT, cap(w, B_HELPER_TRANSPORT), B_HELPER_TRANSPORT, 0, 256, phase)

def helper_input(w:mutbuf, image:u64, first:u64, offset:u64, size:u64, second:u64, secondsize:u64) -> u64:
    put(w, L_CALL_IMAGE, image)
    put(w, L_CALL_FIRST, first)
    put(w, L_CALL_OFFSET, offset)
    put(w, L_CALL_EXTENT, size)
    put(w, L_CALL_SECOND, second)
    put(w, L_CALL_SECOND_EXTENT, secondsize)
    return 0

def helper_service_step(o:mutbuf, w:mutbuf) -> u64:
    phase = get(w, C_PHASE)
    if phase >= 23400:
        return helper_service_tail(o, w)
    if phase == 23000:
        if get(w, L_SERVICE_KIND) != 6 or get(w, L_FN_KERNEL) == I_FUNCTION_ADMIT:
            return refuse(w, 300)
        if get(w, L_PRODUCER_MAGIC) != FN_STREAM or get(w, L_PRODUCER_KIND) != 6 or get(w, L_PRODUCER_REQUEST) != get(w, L_FN_REQUEST):
            return refuse(w, 301)
        if get(w, L_FN_REQUEST) == 0 or get(w, L_QUERY_SEQUENCE) == MAX:
            return refuse(w, 302)
        put(w, L_HELPER_LEASE, get(w, L_FN_REQUEST))
        put(w, L_HELPER_QUERY_FIRST, get(w, L_QUERY_SEQUENCE) + 1)
        put(w, L_HELPER_QUERY_LAST, get(w, L_QUERY_SEQUENCE))
        return release(o, w, B_HELPER_TRANSPORT, 23001)
    if phase == 23001:
        return grow(o, w, B_HELPER_TRANSPORT, 4096, 23002)
    if phase == 23002:
        wire8(w, HELPER_CONFIG, get(w, L_HELPER_LEASE), get(w, C_LEASE), get(w, C_IR_STREAM), get(w, L_FN_REQUEST), get(w, L_FN_SERIAL), get(w, L_FN_SLOTS), get(w, C_LEASE))
        zero(w, WIRE + 64, 64)
        put(w, WIRE + 64, get(w, C_TYPE_SEQUENCE))
        put(w, WIRE + 72, get(w, L_HELPER_QUERY_FIRST))
        return copy(o, w, B_CONTROLLER, WIRE, B_HELPER_TRANSPORT, 256, 128, 23003)
    if phase == 23003:
        helper_input(w, I_HELPER_REQUEST, B_IR, 0, get(w, C_IR_EXTENT), B_FUNCTION_SOURCE, get(w, C_FN_SOURCE_BYTES))
        put(w, C_PHASE, 23004)
        return 0
    if phase == 23004:
        return helper_call(o, w, 23005)
    if phase == 23005:
        if helper_event(w) == 0:
            return refuse(w, 303)
        action = get(w, OBS + 8)
        if action == 2:
            return grow(o, w, B_HELPER_TRANSPORT, get(w, OBS + 176), 23004)
        if action == 1:
            if get(w, L_QUERY_SEQUENCE) == MAX or get(w, OBS + 64) != get(w, L_QUERY_SEQUENCE) + 1:
                return refuse(w, 304)
            if get(w, OBS + 72) == 0 or get(w, OBS + 72) > 4294967295:
                return refuse(w, 305)
            if get(w, OBS + 120) != 64 or inside(w, B_HELPER_TRANSPORT, get(w, OBS + 112), 64) == 0:
                return refuse(w, 306)
            put(w, L_HELPER_QUERY_SEQ, get(w, OBS + 64))
            put(w, L_HELPER_QUERY_ID, get(w, OBS + 72))
            put(w, L_HELPER_WIRE_OFFSET, get(w, OBS + 112))
            return view(o, w, B_HELPER_TRANSPORT, get(w, L_HELPER_WIRE_OFFSET), 64, 23010)
        if action != 3 or get(w, OBS + 64) != get(w, L_QUERY_SEQUENCE):
            return refuse(w, 307)
        if get(w, OBS + 120) < 16 or get(w, OBS + 120) > 131072:
            return refuse(w, 308)
        if inside(w, B_HELPER_TRANSPORT, get(w, OBS + 112), get(w, OBS + 120)) == 0:
            return refuse(w, 309)
        put(w, L_HELPER_WIRE_OFFSET, get(w, OBS + 112))
        put(w, L_HELPER_WIRE_BYTES, get(w, OBS + 120))
        return release(o, w, B_HELPER_WORK, 23100)
    if phase == 23010:
        if get(w, OBS) != TYPE_QUERY or get(w, OBS + 8) != get(w, C_LEASE) or get(w, OBS + 16) != get(w, C_TYPE_SEQUENCE):
            return refuse(w, 310)
        if get(w, OBS + 24) != get(w, L_HELPER_QUERY_SEQ) or get(w, OBS + 32) != get(w, L_HELPER_QUERY_ID):
            return refuse(w, 311)
        if get(w, OBS + 40) != 0 or get(w, OBS + 48) != 0 or get(w, OBS + 56) != 0:
            return refuse(w, 312)
        return grow(o, w, B_QUERY_EVENT, 128, 23011)
    if phase == 23011:
        return invoke(o, w, I_TYPE_COMMANDS, B_HELPER_TRANSPORT, get(w, L_HELPER_WIRE_OFFSET), 64, B_QUERY_EVENT, 128, B_TRANSPORT, cap(w, B_TRANSPORT), B_QUERY_EVENT, 0, 128, 23012)
    if phase == 23012:
        if query_event(w, get(w, L_HELPER_QUERY_ID), get(w, L_HELPER_QUERY_SEQ)) == 0:
            return refuse(w, 313)
        put(w, L_QUERY_SEQUENCE, get(w, L_HELPER_QUERY_SEQ))
        put(w, L_HELPER_QUERY_LAST, get(w, L_QUERY_SEQUENCE))
        helper_input(w, I_HELPER_REQUEST, B_QUERY_EVENT, 0, 128, B_TRANSPORT, cap(w, B_TRANSPORT))
        put(w, C_PHASE, 23004)
        return 0
    if phase == 23100:
        return grow(o, w, B_HELPER_WORK, HELPER_BYTES, 23101)
    if phase == 23101:
        return release(o, w, B_HELPER_OUTPUT, 23102)
    if phase == 23102:
        return grow(o, w, B_HELPER_OUTPUT, HELPER_OUTPUT_BYTES, 23103)
    if phase == 23103:
        return invoke(o, w, I_OUTER_OWNER, B_FUNCTION_WORK, 0, FUNCTION_BYTES, B_OUTER_OUTPUT, OWNER_OUTPUT_BYTES, B_OUTER_WORK, OUTER_BYTES, B_OUTER_OUTPUT, 0, 64, 23104)
    if phase == 23104:
        if outer_frame(w) == 0 or get(w, L_OUT_ACTION) != 3 or get(w, L_OUT_PHASE) != 20:
            return refuse(w, 314)
        return invoke(o, w, I_HELPER_OWNER, B_HELPER_TRANSPORT, get(w, L_HELPER_WIRE_OFFSET), get(w, L_HELPER_WIRE_BYTES), B_HELPER_OUTPUT, HELPER_OUTPUT_BYTES, B_HELPER_WORK, HELPER_BYTES, B_HELPER_OUTPUT, 0, 64, 23105)
    if phase == 23105:
        put(w, L_HELPER_ACTUAL_RETURN, get(w, C_RETURN))
        wire8(w, OUT_HELPER_HEADER, get(w, L_OUT_REQUEST), get(w, C_RETURN), HELPER_OUTPUT_BYTES, 0, 0, 0, 0)
        i = 0
        while i < 64:
            store(w, WIRE + 32 + i, byte(w, OBS + i))
            i = i + 1
        return invoke(o, w, I_OUTER_OWNER, B_HELPER_WORK, 0, HELPER_BYTES, B_OUTER_OUTPUT, OWNER_OUTPUT_BYTES, B_OUTER_WORK, OUTER_BYTES, B_OUTER_OUTPUT, 0, 64, 23106)
    if phase == 23106:
        if outer_frame(w) == 0 or get(w, L_OUT_ACTION) != 7 or get(w, L_OUT_PHASE) != 22:
            return refuse(w, 315)
        return invoke(o, w, I_OUTER_OWNER, B_CONTROLLER, WIRE, 96, B_OUTER_OUTPUT, OWNER_OUTPUT_BYTES, B_OUTER_WORK, OUTER_BYTES, B_OUTER_OUTPUT, 0, 64, 23107)
    if phase == 23107:
        if outer_frame(w) == 0:
            return refuse(w, 316)
        if get(w, L_OUT_ACTION) != 5 and get(w, L_OUT_ACTION) != 6:
            return refuse(w, 317)
        if get(w, L_HELPER_ACTUAL_RETURN) < 64 or get(w, L_HELPER_ACTUAL_RETURN) > HELPER_OUTPUT_BYTES:
            return refuse(w, 318)
        helper_input(w, I_HELPER_REPLY, B_HELPER_OUTPUT, 0, get(w, L_HELPER_ACTUAL_RETURN), B_HELPER_WORK, HELPER_BYTES)
        put(w, C_PHASE, 23200)
        return 0
    if phase == 23200:
        return helper_call(o, w, 23201)
    if phase == 23201:
        if helper_event(w) == 0:
            return refuse(w, 319)
        if get(w, OBS + 8) == 2:
            return grow(o, w, B_HELPER_TRANSPORT, get(w, OBS + 176), 23200)
        if get(w, OBS + 8) != 4 or get(w, OBS + 64) != get(w, L_QUERY_SEQUENCE):
            return refuse(w, 320)
        if get(w, OBS + 96) > 3 or get(w, OBS + 88) < get(w, L_FN_SERIAL) or get(w, OBS + 88) > 8192:
            return refuse(w, 321)
        if get(w, OBS + 96) != get(w, WIRE + 40) or get(w, OBS + 88) != get(w, WIRE + 48) or get(w, OBS + 104) != get(w, WIRE + 56):
            return refuse(w, 322)
        if get(w, OBS + 200) != 64 or get(w, OBS + 208) != get(w, L_HELPER_ACTUAL_RETURN):
            return refuse(w, 323)
        if inside(w, B_HELPER_TRANSPORT, get(w, OBS + 192), 64) == 0:
            return refuse(w, 324)
        put(w, L_HELPER_ERROR, get(w, OBS + 96))
        put(w, L_HELPER_SERIAL, get(w, OBS + 88))
        put(w, L_HELPER_NAME_ID, get(w, OBS + 104))
        put(w, L_HELPER_VALUE_OFFSET, get(w, OBS + 128))
        put(w, L_HELPER_VALUE_BYTES, get(w, OBS + 136))
        put(w, L_HELPER_CONT_OFFSET, get(w, OBS + 144))
        put(w, L_HELPER_CONT_BYTES, get(w, OBS + 152))
        put(w, L_HELPER_HEADER_OFFSET, get(w, OBS + 192))
        put(w, L_HELPER_EXTENT, get(w, OBS + 208))
        if get(w, L_HELPER_CONT_BYTES) != 64 + get(w, OBS + 168):
            return refuse(w, 325)
        if get(w, OBS + 168) != 0 and get(w, OBS + 160) != get(w, L_HELPER_CONT_OFFSET) + 64:
            return refuse(w, 325)
        if inside(w, B_HELPER_TRANSPORT, get(w, OBS + 160), get(w, OBS + 168)) == 0:
            return refuse(w, 325)
        if get(w, L_HELPER_CONT_BYTES) < 64 or get(w, L_HELPER_CONT_BYTES) > 79 or inside(w, B_HELPER_TRANSPORT, get(w, L_HELPER_CONT_OFFSET), get(w, L_HELPER_CONT_BYTES)) == 0:
            return refuse(w, 326)
        if get(w, L_HELPER_ERROR) == 0:
            if get(w, L_OUT_ACTION) != 5 or get(w, L_OUT_PHASE) != 21 or get(w, L_HELPER_VALUE_BYTES) < 24:
                return refuse(w, 327)
            if get(w, L_HELPER_VALUE_BYTES) > PACKET_LIMIT or inside(w, B_HELPER_TRANSPORT, get(w, L_HELPER_VALUE_OFFSET), get(w, L_HELPER_VALUE_BYTES)) == 0:
                return refuse(w, 328)
        else:
            if get(w, L_OUT_ACTION) != 6 or get(w, L_OUT_PHASE) != 10 or get(w, L_HELPER_VALUE_BYTES) != 0:
                return refuse(w, 329)
            if inside(w, B_HELPER_TRANSPORT, get(w, L_HELPER_VALUE_OFFSET), 0) == 0:
                return refuse(w, 329)
        return view(o, w, B_HELPER_TRANSPORT, get(w, L_HELPER_HEADER_OFFSET), 64, 23202)
    if phase == 23202:
        i = 0
        while i < 64:
            if byte(w, OBS + i) != byte(w, WIRE + 32 + i):
                return refuse(w, 330)
            i = i + 1
        return view(o, w, B_HELPER_TRANSPORT, get(w, L_HELPER_CONT_OFFSET), 64, 23203)
    if phase == 23203:
        if get(w, OBS) != LOWER_RESPONSE_MAGIC or get(w, OBS + 8) != get(w, L_FN_REQUEST) or get(w, OBS + 16) != 6:
            return refuse(w, 331)
        if get(w, OBS + 24) != get(w, L_HELPER_ERROR) or get(w, OBS + 32) != 0 or get(w, OBS + 40) != get(w, L_HELPER_SERIAL):
            return refuse(w, 332)
        if get(w, OBS + 48) != get(w, L_HELPER_CONT_BYTES) - 64 or get(w, OBS + 56) != 0:
            return refuse(w, 333)
        if get(w, L_HELPER_ERROR) != 0:
            put(w, L_DELEGATE_GROUP, 4)
            put(w, L_DELEGATE_ERROR, get(w, L_HELPER_ERROR))
            put(w, L_DELEGATE_REQUEST, get(w, L_FN_REQUEST))
            put(w, C_PHASE, 23500)
            return 0
        return release(o, w, B_HELPER_VALUE, 23300)
    if phase == 23300:
        return grow(o, w, B_HELPER_VALUE, get(w, L_HELPER_VALUE_BYTES), 23301)
    if phase == 23301:
        return copy(o, w, B_HELPER_TRANSPORT, get(w, L_HELPER_VALUE_OFFSET), B_HELPER_VALUE, 0, get(w, L_HELPER_VALUE_BYTES), 23302)
    if phase == 23302:
        return protect(o, w, B_HELPER_VALUE, 1, 23303)
    if phase == 23303:
        put(w, C_PACKET_SLOT, B_HELPER_VALUE)
        put(w, C_PACKET_OFFSET, 0)
        put(w, C_PACKET_BYTES, get(w, L_HELPER_VALUE_BYTES))
        put(w, L_INDEX_TARGET, B_HELPER_SOURCE)
        put(w, L_INDEX_RETURN, 23400)
        put(w, C_PHASE, 26000)
        return 0
    return refuse(w, 339)

def helper_service_tail(o:mutbuf, w:mutbuf) -> u64:
    phase = get(w, C_PHASE)
    if phase == 23400:
        return grow(o, w, B_WIRE_COPY, 80, 23401)
    if phase == 23401:
        wire8(w, HELPER_STREAM_MAGIC, 0, 0, 1, get(w, L_HELPER_SERIAL), get(w, L_FN_SLOTS), get(w, L_FN_REQUEST), 16)
        put(w, WIRE + 64, 0)
        put(w, WIRE + 72, 0)
        return copy(o, w, B_CONTROLLER, WIRE, B_WIRE_COPY, 0, 80, 23402)
    if phase == 23402:
        producer(w, 0, B_EMPTY, B_WIRE_COPY, HELPER_STREAM_MAGIC, 0, get(w, L_FN_REQUEST), get(w, L_HELPER_SERIAL), get(w, L_FN_SLOTS), B_HELPER_SOURCE, get(w, L_INDEX_SOURCE_BYTES))
        put(w, L_STREAM_MODE, 1)
        put(w, L_STREAM_RETURN, 23410)
        return switch(o, w, DRIVER_STREAM, 30000)
    if phase == 23410:
        if get(w, L_CORE_ROOT) != 6 or get(w, L_CORE_UNKNOWN) != 0 or get(w, L_CORE_MASK) != 63:
            return refuse(w, 334)
        if commit_object(w, 2, get(w, L_FN_REQUEST)) == 0:
            return refuse(w, 335)
        put(w, L_HELP_COUNT, get(w, L_OUT_HELPERS))
        wire8(w, OUT_ACK, get(w, L_OUT_REQUEST), 2, get(w, L_OUT_HANDLE), 0, 0, 0, 0)
        return invoke(o, w, I_OUTER_OWNER, B_CONTROLLER, WIRE, 32, B_OUTER_OUTPUT, OWNER_OUTPUT_BYTES, B_OUTER_WORK, OUTER_BYTES, B_OUTER_OUTPUT, 0, 64, 23411)
    if phase == 23411:
        if outer_frame(w) == 0 or get(w, L_OUT_ACTION) != 0 or get(w, L_OUT_PHASE) != 10:
            return refuse(w, 336)
        count = get(w, L_FN_HELPERS)
        if count >= 720:
            return refuse(w, 337)
        if count != 0 and get(w, HELPER_REQUESTS + (count - 1) * 8) >= get(w, L_FN_REQUEST):
            return refuse(w, 338)
        put(w, HELPER_REQUESTS + count * 8, get(w, L_FN_REQUEST))
        put(w, L_FN_HELPERS, count + 1)
        put(w, C_PHASE, 23500)
        return 0
    if phase == 23500:
        return grow(o, w, B_WIRE_COPY, 80, 23501)
    if phase == 23501:
        return copy(o, w, B_HELPER_TRANSPORT, get(w, L_HELPER_CONT_OFFSET), B_WIRE_COPY, 0, get(w, L_HELPER_CONT_BYTES), 23502)
    if phase == 23502:
        return release(o, w, B_HELPER_TRANSPORT, 23503)
    if phase == 23503:
        return release(o, w, B_HELPER_OUTPUT, 23504)
    if phase == 23504:
        return release(o, w, B_HELPER_WORK, 23505)
    if phase == 23505:
        return release(o, w, B_HELPER_VALUE, 23506)
    if phase == 23506:
        return release(o, w, B_HELPER_SOURCE, 23507)
    if phase == 23507:
        put(w, C_PACKET_SLOT, B_WIRE_COPY)
        put(w, C_PACKET_OFFSET, 0)
        put(w, C_PACKET_BYTES, get(w, L_HELPER_CONT_BYTES))
        return switch(o, w, DRIVER_MAIN, get(w, L_SERVICE_RETURN))
    return refuse(w, 339)
'''
