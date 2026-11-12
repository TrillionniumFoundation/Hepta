"""Shared native control protocol for complete composite lowering.

RECONSTRUCTED-DEVELOPMENT-r1, authored after the workspace reset.
This is new development source, not a recovery of the unavailable Stage12 source.
The generated HIA owns every continuation. The fixed executor only applies the
explicit buffer/call/stream operations below. No production selector is added.
"""
from __future__ import annotations

def magic(text: str) -> int:
    assert len(text) == 8
    return int.from_bytes(text.encode("ascii"), "little")

CONSTANTS = {
    "ABI": 0xFFFFFFFD, "MAX": (1 << 64) - 1,
    "MIN_WORK": 1 << 20,
    "EVENT_MAGIC": magic("HIACDE01"), "ACK_MAGIC": magic("HIACDA01"),
    "LOWER_MAGIC": magic("HIALDS01"),
    "CTOR_HANDOFF": 7, "DRIVER_MAIN": 40, "DRIVER_SERVICES": 41,
    "DRIVER_STREAM": 42,
    "C_MAGIC": 0, "C_STATUS": 8, "C_LEASE": 16, "C_SEQUENCE": 24,
    "C_PHASE": 32, "C_PENDING": 40, "C_NEXT": 48, "C_RETURN": 56,
    "C_OBSERVE": 64, "C_ALLOC_SLOT": 72, "C_ALLOC_BYTES": 80,
    "C_SOURCE_EXTENT": 88, "C_LEGACY": 96, "C_CTOR_STAGE": 104,
    "C_PROFILE": 112, "C_CTOR_REQUEST": 120,
    "C_TYPES_LIVE": 168, "C_IR_STREAM": 176, "C_IR_ACTION": 184,
    "C_IR_PSEQ": 192, "C_IR_ESEQ": 200, "C_IR_FINAL": 208,
    "C_FRAME_BYTES": 216, "C_IR_ROOT": 224, "C_IR_NODES": 232,
    "C_IR_EXTENT": 240, "C_OWNER_TARGET": 248,
    "C_PACKET_SLOT": 256, "C_PACKET_OFFSET": 264, "C_PACKET_BYTES": 272,
    "C_JSON_RETURN": 280, "C_JSON_BYTES": 288,
    "C_BITMAP_OFFSET": 296, "C_BITMAP_BYTES": 304,
    "C_LEASE_TARGET": 312, "C_LEASE_RETURN": 320, "C_LEASE_BYTES": 328,
    "C_CTOR_PACKET_BYTES": 336, "C_CTOR_SOURCE_BYTES": 344,
    "C_TYPE_OP": 352, "C_TYPE_SEQUENCE": 360, "C_TYPE_ERROR": 368,
    "C_WIRE_BYTES": 376, "C_RESPONSE_OFFSET": 384, "C_RESPONSE_BYTES": 392,
    "C_FN_PACKET_BYTES": 400, "C_OUT_PACKET_BYTES": 408,
    "C_FN_SOURCE_BYTES": 416, "C_OUT_SOURCE_BYTES": 424,
    "C_PACKET_DEST": 432, "C_PACKET_RETURN": 440,
    "C_ERROR_GROUP": 456, "C_FINAL_ERROR": 464, "C_REASON": 472,
    "OBS": 512, "ARGS": 1024, "WIRE": 2048, "CAPS": 4096,
    "B_EMPTY": 0, "B_SOURCE": 1, "B_CONTROLLER": 2,
    "B_PROJECTOR": 4, "B_CTOR_PACKET": 5, "B_CTOR_SOURCE": 6,
    "B_PACKET_JSON": 7, "B_PACKET_WORK": 8,
    "B_CTOR_WORK": 9, "B_CTOR_OUTPUT": 10,
    "B_IR": 11, "B_REQUEST": 12, "B_TYPE_WIRE": 13,
    "B_TRANSPORT": 14, "B_TYPE_EVENT": 15,
    "B_TYPES": 16, "B_TYPE_OUTPUT": 17, "B_RESPONSE": 18,
    "B_FUNCTION_PACKET": 20, "B_OUTER_PACKET": 21,
    "B_FUNCTION_SOURCE": 22, "B_OUTER_SOURCE": 23,
    "B_FUNCTION_WORK": 24, "B_FUNCTION_OUTPUT": 25,
    "B_OUTER_WORK": 26, "B_OUTER_OUTPUT": 27,
    "B_HELPER_TRANSPORT": 28, "B_HELPER_OUTPUT": 29,
    "B_HELPER_WORK": 30, "B_HASH_WORK": 31, "B_HASH_OUTPUT": 32,
    "B_HASH_INPUT": 33, "B_OBJECT_JSON": 34, "B_CORE_VISITOR": 35,
    "B_WIRE_COPY": 36, "B_METADATA": 37, "B_HELPER_VALUE": 38,
    "B_HELPER_SOURCE": 39, "B_SPOOL_CHUNK": 40,
    "B_OPAQUE_REPLY": 41, "B_QUERY_EVENT": 42,
    "I_OWNER_PACKET": 1, "I_PACKET_JSON": 2,
    "I_CTOR_OWNER": 3, "I_CTOR_RENDER": 4,
    "I_IR": 5, "I_TYPE_REQUEST": 6, "I_TYPE_COMMANDS": 7,
    "I_TYPES": 8, "I_TYPE_REPLY": 9, "I_TYPE_RESPONSE": 10,
    "I_FUNCTION_ADMIT": 11, "I_FUNCTION_RECORDS": 12,
    "I_FUNCTION_ADVANCED": 13, "I_FUNCTION_TERMS": 14,
    "I_FUNCTION_RENDER": 15, "I_OUTER_OWNER": 16,
    "I_OUTER_RENDER": 17, "I_HELPER_REQUEST": 18,
    "I_HELPER_REPLY": 19, "I_HELPER_OWNER": 20,
    "I_OBJECT_JSON": 21, "I_SHA_STREAM": 22, "I_CORE_VISITOR": 23,
    "TYPES_BYTES": 128 << 20, "TYPE_OUTPUT_BYTES": 64 << 20,
    "FUNCTION_BYTES": 192 << 20, "OUTER_BYTES": 80 << 20,
    "HELPER_BYTES": 2 << 20, "HELPER_OUTPUT_BYTES": 4 << 20,
    "OWNER_OUTPUT_BYTES": 65536,
    "PACKET_LIMIT": 64 << 20,
    "SOURCE_LEASE_LIMIT": 75497536,
    "OBJECTS": 1 << 63, "OBJECT_BASE": 65536,
    "OBJECT_STRIDE": 128, "OBJECT_COUNT": 1744,
    "CACHE_COMMITTED": 294912, "CACHE_PENDING": 327680,
    "HELPER_REQUESTS": 360448,
    "FN_FRAME": magic("HIAFAD01"), "FN_STREAM": magic("HIAFNC01"),
    "FN_NEXT": magic("HIAFNX01"), "FN_META_REQ": magic("HIAFMQ01"),
    "FN_META": magic("HIAFMD01"),
    "OUT_FRAME": magic("HIAOTR01"), "OUT_STREAM": magic("HIAOTK01"),
    "OUT_ACK": magic("HIAOTA01"), "OUT_FAIL": magic("HIAOTF01"),
    "OUT_HELPER_HEADER": magic("HIAOTH01"),
    "IR_INIT": magic("HIAOII01"), "IR_CONT": magic("HIAOIC01"),
    "IR_EVENT": magic("HIAOIE01"),
    "OWNER_CONFIG": magic("HIAOPP01"), "OWNER_EVENT": magic("HIAOPE01"),
    "TYPE_BEGIN": magic("HIATRB01"), "TYPE_REPLY": magic("HIATRR01"),
    "TYPE_QUERY": magic("HIATRQ01"), "TYPE_EVENT": magic("HIATRE01"),
    "TYPE_REQUEST_CONFIG": magic("HIASVP01"),
    "TYPE_REQUEST_EVENT": magic("HIASVE01"),
    "TYPE_RESPONSE_CONFIG": magic("HIASRP01"),
    "TYPE_RESPONSE_EVENT": magic("HIASRE01"),
    "HELPER_CONFIG": magic("HIAHRI01"), "HELPER_EVENT": magic("HIAHRE01"),
    "HELPER_FRAME": magic("HIATHP01"),
    "PACKET_JSON_MAGIC": magic("HIAPJS01"), "SOURCE_MAGIC": magic("HIASIL01"),
    "JSON_INIT": magic("HIAOJI01"), "JSON_CONT": magic("HIAOJC01"),
    "JSON_REGISTER": magic("HIAOJG01"), "JSON_OPAQUE": magic("HIAOJQ01"),
    "JSON_EVENT": magic("HIAOJE01"),
    "CORE_INIT": magic("HIACSB01"), "CORE_CONT": magic("HIACSC01"),
    "CORE_OPAQUE": magic("HIACSO01"), "CORE_ADMIT": magic("HIACSA01"),
    "CORE_EVENT": magic("HIACSE01"),
    "LOWER_RESPONSE_MAGIC": magic("HIAFLR01"),
    "HELPER_STREAM_MAGIC": magic("HIAHLP01"),
}
_FIELDS = (
    "MAGIC", "STATUS", "DRIVER", "NEXT_DRIVER",
    "FN_KERNEL", "FN_PHASE", "FN_SERIAL", "FN_SLOTS", "FN_REQUEST", "FN_ERROR",
    "FN_COUNT", "HELP_COUNT", "OUT_PHASE", "OUT_REQUEST", "OUT_FUNCTIONS",
    "OUT_HELPERS", "OUT_ACTION", "OUT_HANDLE", "OUT_ERROR",
    "DELEGATE_GROUP", "DELEGATE_ERROR", "DELEGATE_REQUEST",
    "QUERY_SEQUENCE", "SERVICE_KIND", "SERVICE_RETURN", "FN_HELPERS",
    "META_COUNT", "META_APPEND", "META_SIZE", "META_INDEX", "META_PREVIOUS",
    "META_RETURN", "META_ID", "META_OP", "META_NAME", "META_QUERY",
    "CURRENT_HANDLE", "CURRENT_OBJECT", "SPOOL_BYTES", "FINAL_BYTES",
    "STREAM_MODE", "STREAM_RETURN", "STREAM_NUMBER",
    "PRODUCER_IMAGE", "PRODUCER_WORK", "PRODUCER_OUTPUT", "PRODUCER_MAGIC",
    "PRODUCER_KIND", "PRODUCER_REQUEST", "PRODUCER_SERIAL", "PRODUCER_SLOTS",
    "PRODUCER_SEQUENCE", "PRODUCER_FINAL", "PRODUCER_BYTES",
    "STREAM_SOURCE", "STREAM_SOURCE_EXTENT", "STREAM_PACKET_BYTES",
    "IR_RETURN", "IR_FIRST", "IR_ACTIVE", "IR_ACTION",
    "JSON_SEQUENCE", "JSON_PSEQ", "JSON_ACTION", "JSON_PAYLOAD", "JSON_TOTAL",
    "JSON_A0", "JSON_A1", "JSON_A2", "JSON_A3", "JSON_PENDING",
    "CORE_SEQUENCE", "CORE_PSEQ", "CORE_ACTION", "CORE_PENDING",
    "CORE_ROOT", "CORE_NODES", "CORE_DEPTH", "CORE_MASK", "CORE_UNKNOWN",
    "CORE_LATE", "STREAM_OFFSET", "STREAM_LENGTH",
    "DIGEST0", "DIGEST1", "DIGEST2", "DIGEST3",
    "OPAQUE_ROW", "OPAQUE_OFFSET", "OPAQUE_REMAIN", "OPAQUE_CHUNK",
    "OPAQUE_QUERY", "OPAQUE_REGISTER_INDEX", "OPAQUE_RETURN",
    "HELPER_LEASE", "HELPER_QUERY_FIRST", "HELPER_QUERY_LAST",
    "HELPER_ERROR", "HELPER_SERIAL", "HELPER_NAME_ID",
    "HELPER_VALUE_OFFSET", "HELPER_VALUE_BYTES",
    "HELPER_CONT_OFFSET", "HELPER_CONT_BYTES",
    "HELPER_HEADER_OFFSET", "HELPER_EXTENT", "HELPER_ACTUAL_RETURN",
    "HELPER_WIRE_OFFSET", "HELPER_WIRE_BYTES", "HELPER_RETURN",
    "HELPER_QUERY_ID", "HELPER_QUERY_SEQ", "HELPER_QUERY_MODE",
    "HELPER_FRAME_SOURCE", "HELPER_FRAME_SOURCE_EXTENT",
    "INDEX_RETURN", "INDEX_TARGET", "INDEX_PACKET_SLOT", "INDEX_PACKET_OFFSET",
    "INDEX_PACKET_BYTES", "INDEX_SOURCE_BYTES",
    "CALL_FIRST", "CALL_OFFSET", "CALL_EXTENT", "CALL_SECOND", "CALL_SECOND_EXTENT",
    "CALL_WORK", "CALL_WORK_EXTENT", "CALL_IMAGE",
    "QUERY_ID", "QUERY_RETURN", "QUERY_KIND",
    "RECORD_COMMIT_RETURN", "FINAL_GROUP", "FINAL_ERROR", "FINAL_REQUEST",
    "FN_ACTION", "FN_OBS_REQUEST",
    "SERVICE_TARGET", "INDEX_WORK_BYTES", "INDEX_OUTPUT_BYTES",
    "COMMITTED_CACHE_COUNT",
    "STREAM_PACKET_SLOT", "STREAM_FILE", "STREAM_DEST_DRIVER",
    "JSON_ROOT", "CORE_QUERY_SEQUENCE", "OPAQUE_COPY_BYTES",
    "STREAM_FINISHED", "ADMIT_SNAPSHOT",
    "CTOR_ACTION", "CTOR_PHASE", "CTOR_PENDING", "CTOR_WAITING",
    "CTOR_ISSUED_PHASE", "CTOR_PROFILE_SET", "CTOR_COMPLETED", "CTOR_ERROR",
    "CTOR_NODE", "CTOR_NODE_INDEX", "CTOR_PROJECT_TARGET", "CTOR_PROJECT_DEST",
    "CTOR_PROJECT_RETURN", "CTOR_PROJECT_STREAM", "CTOR_PROJECT_REQUEST",
)
CONSTANTS.update({"L_" + key: 8192 + 8 * index for index, key in enumerate(_FIELDS)})
assert 8192 + 8 * len(_FIELDS) < 12288
assert CONSTANTS["OBJECT_BASE"] + 128 * 1744 <= CONSTANTS["CACHE_COMMITTED"]
assert CONSTANTS["CACHE_PENDING"] + 720 * 24 <= CONSTANTS["HELPER_REQUESTS"]

COMMON = r'''
def word(s:readbuf, at:u64) -> u64:
    i = 0
    value = 0
    while i < 8:
        value = value | (byte(s, at + i) << (i * 8))
        i = i + 1
    return value

def get(w:mutbuf, at:u64) -> u64:
    i = 0
    value = 0
    while i < 8:
        value = value | (byte(w, at + i) << (i * 8))
        i = i + 1
    return value

def put(w:mutbuf, at:u64, value:u64) -> u64:
    i = 0
    while i < 8:
        store(w, at + i, (value >> (i * 8)) & 255)
        i = i + 1
    return 0

def zero(w:mutbuf, at:u64, size:u64) -> u64:
    i = 0
    while i < size:
        store(w, at + i, 0)
        i = i + 1
    return 0

def refuse(w:mutbuf, reason:u64) -> u32:
    put(w, L_MAGIC, LOWER_MAGIC)
    put(w, L_STATUS, 3)
    put(w, C_REASON, reason)
    return ABI

def args(w:mutbuf, a:u64, b:u64, c:u64, d:u64, e:u64, f:u64, g:u64, h:u64, i:u64, j:u64, k:u64, l:u64) -> u64:
    put(w, ARGS, a)
    put(w, ARGS + 8, b)
    put(w, ARGS + 16, c)
    put(w, ARGS + 24, d)
    put(w, ARGS + 32, e)
    put(w, ARGS + 40, f)
    put(w, ARGS + 48, g)
    put(w, ARGS + 56, h)
    put(w, ARGS + 64, i)
    put(w, ARGS + 72, j)
    put(w, ARGS + 80, k)
    put(w, ARGS + 88, l)
    return 0

def event(o:mutbuf, w:mutbuf, opcode:u64, phase:u64) -> u32:
    seq = get(w, C_SEQUENCE)
    if get(w, L_STATUS) != 1 or get(w, C_PENDING) != 0 or seq == MAX:
        return refuse(w, 1)
    put(w, C_SEQUENCE, seq + 1)
    put(w, C_PENDING, opcode)
    put(w, C_NEXT, phase)
    put(o, 0, EVENT_MAGIC)
    put(o, 8, opcode)
    put(o, 16, get(w, C_LEASE))
    put(o, 24, seq + 1)
    i = 0
    while i < 96:
        store(o, 32 + i, byte(w, ARGS + i))
        i = i + 1
    return 128

def acknowledge(s:readbuf, w:mutbuf, driver:u64) -> u64:
    if get(w, L_MAGIC) != LOWER_MAGIC or get(w, L_STATUS) != 1:
        return 0
    pending = get(w, C_PENDING)
    if pending == 0 or length(s) < 64:
        return 0
    if get(w, L_DRIVER) != driver:
        if pending != 8 or get(w, L_NEXT_DRIVER) != driver:
            return 0
    elif pending == 8:
        return 0
    observed = get(w, C_OBSERVE)
    if observed > 256 or length(s) != 64 + observed:
        return 0
    if word(s, 0) != ACK_MAGIC or word(s, 8) != get(w, C_LEASE) or word(s, 16) != get(w, C_SEQUENCE):
        return 0
    if word(s, 24) != pending or word(s, 32) != 0 or word(s, 48) != observed or word(s, 56) != 0:
        return 0
    if pending != 1 and pending != 14 and word(s, 40) != 0:
        return 0
    if pending == 14 and word(s, 40) != 0:
        return 0
    if pending == 2:
        put(w, CAPS + get(w, C_ALLOC_SLOT) * 8, get(w, C_ALLOC_BYTES))
    if pending == 5:
        put(w, CAPS + get(w, ARGS) * 8, 0)
    if pending == 8:
        put(w, L_DRIVER, driver)
        put(w, L_NEXT_DRIVER, 0)
    put(w, C_RETURN, word(s, 40))
    i = 0
    while i < observed:
        store(w, OBS + i, byte(s, 64 + i))
        i = i + 1
    put(w, C_PENDING, 0)
    put(w, C_PHASE, get(w, C_NEXT))
    put(w, C_OBSERVE, 0)
    return 1

def cap(w:mutbuf, slot:u64) -> u64:
    if slot >= 64:
        return 0
    return get(w, CAPS + slot * 8)

def inside(w:mutbuf, slot:u64, offset:u64, size:u64) -> u64:
    extent = cap(w, slot)
    if slot >= 64 or offset > extent or size > extent - offset:
        return 0
    return 1

def grow(o:mutbuf, w:mutbuf, slot:u64, size:u64, phase:u64) -> u32:
    if slot == 0 or slot == 1 or slot == 2 or slot >= 64 or size == 0:
        return refuse(w, 2)
    if cap(w, slot) >= size:
        put(w, C_PHASE, phase)
        return 0
    put(w, C_ALLOC_SLOT, slot)
    put(w, C_ALLOC_BYTES, size)
    put(w, C_OBSERVE, 0)
    args(w, slot, size, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    return event(o, w, 2, phase)

def release(o:mutbuf, w:mutbuf, slot:u64, phase:u64) -> u32:
    if slot < 4 or slot >= 64:
        return refuse(w, 3)
    if cap(w, slot) == 0:
        put(w, C_PHASE, phase)
        return 0
    put(w, C_OBSERVE, 0)
    args(w, slot, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    return event(o, w, 5, phase)

def clear(o:mutbuf, w:mutbuf, slot:u64, offset:u64, size:u64, phase:u64) -> u32:
    if slot < 4 or inside(w, slot, offset, size) == 0:
        return refuse(w, 4)
    put(w, C_OBSERVE, 0)
    args(w, slot, offset, size, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    return event(o, w, 3, phase)

def copy(o:mutbuf, w:mutbuf, source:u64, at:u64, target:u64, to:u64, size:u64, phase:u64) -> u32:
    if source == target or target < 4 or inside(w, source, at, size) == 0 or inside(w, target, to, size) == 0:
        return refuse(w, 5)
    put(w, C_OBSERVE, 0)
    args(w, source, at, target, to, size, 0, 0, 0, 0, 0, 0, 0)
    return event(o, w, 4, phase)

def protect(o:mutbuf, w:mutbuf, slot:u64, readonly:u64, phase:u64) -> u32:
    if slot < 4 or slot >= 64 or cap(w, slot) == 0 or readonly > 1:
        return refuse(w, 6)
    put(w, C_OBSERVE, 0)
    args(w, slot, readonly, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    return event(o, w, 6, phase)

def invoke(o:mutbuf, w:mutbuf, image:u64, first:u64, at:u64, size:u64, second:u64, secondsize:u64, work:u64, worksize:u64, observe:u64, offset:u64, count:u64, phase:u64) -> u32:
    if first == second or first == work or second == work or image == 0 or image > 23:
        return refuse(w, 7)
    if inside(w, first, at, size) == 0 or inside(w, second, 0, secondsize) == 0 or inside(w, work, 0, worksize) == 0:
        return refuse(w, 8)
    if count > 256 or inside(w, observe, offset, count) == 0:
        return refuse(w, 9)
    put(w, C_OBSERVE, count)
    args(w, image, first, at, size, second, secondsize, work, worksize, observe, offset, count, 0)
    return event(o, w, 1, phase)

def view(o:mutbuf, w:mutbuf, slot:u64, offset:u64, count:u64, phase:u64) -> u32:
    if count > 256 or inside(w, slot, offset, count) == 0:
        return refuse(w, 10)
    put(w, C_OBSERVE, count)
    args(w, slot, offset, count, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    return event(o, w, 14, phase)

def switch(o:mutbuf, w:mutbuf, target:u64, phase:u64) -> u32:
    if target < 40 or target > 42 or target == get(w, L_DRIVER):
        return refuse(w, 11)
    put(w, L_NEXT_DRIVER, target)
    put(w, C_OBSERVE, 0)
    args(w, target, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    return event(o, w, 8, phase)

def file_create(o:mutbuf, w:mutbuf, file:u64, phase:u64) -> u32:
    if file > 1:
        return refuse(w, 12)
    put(w, C_OBSERVE, 0)
    args(w, file, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    return event(o, w, 10, phase)

def file_append(o:mutbuf, w:mutbuf, file:u64, at:u64, slot:u64, offset:u64, size:u64, phase:u64) -> u32:
    if file > 1 or at >= OBJECTS or size >= OBJECTS or size > OBJECTS - 1 - at:
        return refuse(w, 13)
    if inside(w, slot, offset, size) == 0:
        return refuse(w, 14)
    put(w, C_OBSERVE, 0)
    args(w, file, at, slot, offset, size, 0, 0, 0, 0, 0, 0, 0)
    return event(o, w, 11, phase)

def file_read(o:mutbuf, w:mutbuf, file:u64, at:u64, slot:u64, offset:u64, size:u64, phase:u64) -> u32:
    if file > 1 or at >= OBJECTS or size >= OBJECTS or size > OBJECTS - 1 - at:
        return refuse(w, 15)
    if slot < 4 or inside(w, slot, offset, size) == 0:
        return refuse(w, 16)
    put(w, C_OBSERVE, 0)
    args(w, file, at, slot, offset, size, 0, 0, 0, 0, 0, 0, 0)
    return event(o, w, 12, phase)

def file_seal(o:mutbuf, w:mutbuf, file:u64, phase:u64) -> u32:
    if file > 1:
        return refuse(w, 17)
    put(w, C_OBSERVE, 0)
    args(w, file, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    return event(o, w, 13, phase)

def wire8(w:mutbuf, a:u64, b:u64, c:u64, d:u64, e:u64, f:u64, g:u64, h:u64) -> u64:
    put(w, WIRE, a)
    put(w, WIRE + 8, b)
    put(w, WIRE + 16, c)
    put(w, WIRE + 24, d)
    put(w, WIRE + 32, e)
    put(w, WIRE + 40, f)
    put(w, WIRE + 48, g)
    put(w, WIRE + 56, h)
    return 0

def minimum(left:u64, right:u64) -> u64:
    if left < right:
        return left
    return right

def advance(w:mutbuf, field:u64) -> u64:
    value = get(w, field)
    if value == MAX:
        refuse(w, 18)
        return 0
    value = value + 1
    put(w, field, value)
    return value

def object_row(w:mutbuf, handle:u64) -> u64:
    if handle < OBJECTS or handle - OBJECTS >= OBJECT_COUNT:
        return 0
    return OBJECT_BASE + (handle - OBJECTS) * OBJECT_STRIDE

def finish(o:mutbuf, w:mutbuf, group:u64, error:u64, request:u64) -> u32:
    if get(w, L_STATUS) != 1 or get(w, C_PENDING) != 0:
        return refuse(w, 19)
    put(w, L_STATUS, 2)
    put(w, L_FINAL_GROUP, group)
    put(w, L_FINAL_ERROR, error)
    put(w, L_FINAL_REQUEST, request)
    put(o, 0, EVENT_MAGIC)
    put(o, 8, 7)
    put(o, 16, get(w, C_LEASE))
    put(o, 24, get(w, C_SEQUENCE))
    put(o, 32, group)
    put(o, 40, error)
    put(o, 48, request)
    put(o, 56, get(w, L_FN_SERIAL))
    put(o, 64, get(w, L_FN_SLOTS))
    put(o, 72, get(w, L_FN_COUNT))
    put(o, 80, get(w, L_HELP_COUNT))
    put(o, 88, get(w, L_FINAL_BYTES))
    put(o, 96, get(w, L_DIGEST0))
    put(o, 104, get(w, L_DIGEST1))
    put(o, 112, get(w, L_DIGEST2))
    put(o, 120, get(w, L_DIGEST3))
    return 128
'''
