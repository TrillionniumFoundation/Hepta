"""HIA edit main admission and exact issued Core source continuation.

This first authored controller transfers to the separately developed query
controller after the full actual program child, receipt/hash join, integer
codec and bitmap issuer. It is not a complete edit executable by itself.
"""
from edit_authoring import source,document as build,write
from hia_edit_controller_common import CONSTANTS as BASE,ALL
CONSTANTS=dict(BASE)
CONSTANTS.update(ARENA_BYTES=64+56*262144+(8<<20),KEY_BYTES=8*2*262144,
    CODEC_BYTES=64+49*262144+(8<<20)+8*2*262144,
    CORE_DIAGNOSTIC=int.from_bytes(b'HIACDT01','little'))
BODY=r'''
def edit_main(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) != MIN_WORK:
        return ABI
    if length(o) < 128:
        return refuse(w, 1100)
    if get(w, C_MAGIC) == 0 and get(w, L_MAGIC) == 0:
        if edit_begin(s, w) == 0:
            return refuse(w, 1101)
    elif get(w, C_MAGIC) != EDIT_STATE or acknowledge(s, w, MAIN) == 0:
        return refuse(w, 1102)
    while get(w, L_STATUS) == 1:
        phase = get(w, C_PHASE)
        if phase >= 300 and phase < 320:
            result = import_hash_step(o, w)
        elif phase >= 26000 and phase < 27000:
            result = index_step(o, w)
        elif phase >= 40000 and phase < 40100:
            result = edit_simple_step(o, w)
        elif phase >= 45000 and phase < 45100:
            result = edit_publish_step(o, w)
        else:
            result = edit_main_step(o, w)
        if result != 0:
            return result
    return refuse(w, 1103)

def edit_begin(s:readbuf, w:mutbuf) -> u64:
    if length(s) != 64 or word(s, 0) != EDIT_INIT or word(s, 56) != 0:
        return 0
    lease = word(s, 8)
    mode = word(s, 16)
    if lease == 0 or lease > MAX - 3 or mode < 1 or mode > 6:
        return 0
    if word(s, 32) != cap(w, B_PROGRAM) or word(s, 40) != cap(w, B_QUERY_GRAPH) or word(s, 48) != cap(w, B_RESPONSE_GRAPH):
        return 0
    if cap(w, B_EMPTY) != 1 or cap(w, B_CONTROLLER) != MIN_WORK:
        return 0
    slot = 3
    while slot < 64:
        if slot != B_QUERY_GRAPH and slot != B_RESPONSE_GRAPH and cap(w, slot) != 0:
            return 0
        slot = slot + 1
    at = 0
    while at < MIN_WORK:
        if at < CAPS or at >= CAPS + 512:
            if byte(w, at) != 0:
                return 0
        at = at + 1
    put(w, C_MAGIC, EDIT_STATE)
    put(w, C_STATUS, 1)
    put(w, C_LEASE, lease)
    put(w, L_MAGIC, LOWER_MAGIC)
    put(w, L_STATUS, 1)
    put(w, L_DRIVER, MAIN)
    put(w, E_MODE, mode)
    put(w, E_DIGITS, word(s, 24))
    put(w, E_REQUEST, 1)
    put(w, C_PHASE, 1)
    if mode >= 5:
        put(w, C_PHASE, 200)
    return 1

def program_child(o:mutbuf, w:mutbuf, next:u64) -> u32:
    if cap(w, B_PROGRAM_FRAME) != 0 or get(w, C_LEASE) > MAX - 3:
        return refuse(w, 1104)
    put(w, E_CHILD_LEASE, get(w, C_LEASE) + 1)
    put(w, E_CHILD_TARGET, B_PROGRAM_FRAME)
    put(w, C_OBSERVE, 160)
    args(w, 2, B_PROGRAM, 0, minimum(cap(w, B_PROGRAM), INPUT_LIMIT + 1), B_PROGRAM_FRAME, get(w, E_CHILD_LEASE), get(w, E_DIGITS), 0, 0, 0, 0, 0)
    return event(o, w, 15, next)

def program_child_frame(w:mutbuf) -> u64:
    if get(w, C_RETURN) != 128 or get(w, OBS) != EVENT_MAGIC or get(w, OBS + 8) != 7:
        return 0
    if get(w, OBS + 136) != B_PROGRAM_FRAME or get(w, OBS + 152) != 0 or cap(w, B_PROGRAM_FRAME) != 0:
        return 0
    role = get(w, OBS + 144)
    group = get(w, OBS + 32)
    error = get(w, OBS + 40)
    if group != 0:
        if role != 44 and role != 46:
            return 0
        if role == 44:
            if get(w, OBS + 16) != get(w, E_CHILD_LEASE) or group != 7:
                return 0
        elif get(w, OBS + 16) != get(w, E_CHILD_LEASE) + 1 or get(w, OBS + 24) == 0:
            return 0
        if group > 10 or error == 0:
            return 0
        copy_local(w, E_CHILD_EVENT, OBS, 128)
        put(w, E_ERROR_GROUP, group)
        put(w, E_ERROR_CODE, error)
        extent = get(w, OBS + 128)
        if group == 8:
            if role != 46 or extent < 65:
                return 0
            put(w, CAPS + B_PROGRAM_FRAME * 8, extent)
            put(w, E_ERROR_BYTES, extent)
            return 3
        if extent != 0:
            return 0
        return 2
    if error != 0 or role != 46 or get(w, OBS + 48) != 56 or get(w, OBS + 56) != 256:
        return 0
    if get(w, OBS + 16) != get(w, E_CHILD_LEASE) + 1 or get(w, OBS + 24) == 0:
        return 0
    size = get(w, OBS + 88)
    if size == 0 or size > INPUT_LIMIT or get(w, OBS + 128) != 256 + size:
        return 0
    put(w, CAPS + B_PROGRAM_FRAME * 8, 256 + size)
    put(w, E_CORE_BYTES, size)
    put(w, E_CHILD_SEQUENCE, get(w, OBS + 24))
    copy_local(w, E_CHILD_EVENT, OBS, 128)
    return 1

def program_receipt_header(w:mutbuf) -> u64:
    if get(w, OBS) != PROGRAM_RECEIPT or get(w, OBS + 8) != 1:
        return 0
    if get(w, OBS + 16) != get(w, E_CHILD_LEASE) + 1 or get(w, OBS + 24) != get(w, E_CHILD_SEQUENCE):
        return 0
    kind = get(w, OBS + 32)
    version = get(w, OBS + 40)
    core = get(w, OBS + 48)
    if kind > 1 or version < 1 or version > 8 or core < 1 or core > 8:
        return 0
    if get(w, E_CHILD_EVENT + 64) != kind or get(w, E_CHILD_EVENT + 72) != version or get(w, E_CHILD_EVENT + 80) != core:
        return 0
    input = get(w, OBS + 56)
    if input == 0 or input > INPUT_LIMIT or get(w, OBS + 64) != get(w, E_CORE_BYTES):
        return 0
    if get(w, OBS + 144) != 45 or get(w, OBS + 160) != 56 or get(w, OBS + 168) != 256 or get(w, OBS + 176) != 1 or get(w, OBS + 184) != kind:
        return 0
    at = 192
    while at < 256:
        if get(w, OBS + at) != 0:
            return 0
        at = at + 8
    if kind == 0:
        if version != core or input != get(w, E_CORE_BYTES) or get(w, OBS + 72) != 0 or get(w, OBS + 152) != 0:
            return 0
        if same_digest(w, OBS + 80, OBS + 112) == 0:
            return 0
    else:
        if version > 4 or get(w, OBS + 72) != input or get(w, OBS + 152) != 52:
            return 0
        if (version == 1 and core != 6) or (version == 4 and core != 8):
            return 0
        if (version == 2 or version == 3) and core != 7:
            return 0
    if same_digest(w, OBS + 112, E_CHILD_EVENT + 96) == 0:
        return 0
    put(w, E_KIND, kind)
    put(w, E_VERSION, version)
    put(w, E_CORE_VERSION, core)
    put(w, E_INPUT_BYTES, input)
    copy_digest(w, E_INPUT_HASH, OBS + 80)
    copy_digest(w, E_CORE_HASH, OBS + 112)
    return 1

def core_arena_header(w:mutbuf) -> u64:
    result = get(w, C_RETURN)
    count = get(w, OBS + 8)
    if result < 64 or result > ARENA_BYTES or get(w, OBS) != ARENA_MAGIC or count == 0 or count > NODES:
        return 0
    if get(w, OBS + 16) != 64 + count * 56 or get(w, OBS + 24) != result or get(w, OBS + 32) != result:
        return 0
    if get(w, OBS + 40) != get(w, E_CORE_BYTES) or get(w, OBS + 48) != 1 or get(w, OBS + 56) != 0:
        return 0
    put(w, E_ARENA_USED, result)
    put(w, E_NODE_COUNT, count)
    return 1

def core_packet_header(w:mutbuf) -> u64:
    result = get(w, C_RETURN)
    if result < 80 or result > CODEC_BYTES or get(w, OBS) != JSON_PACKET_MAGIC:
        return 0
    if get(w, OBS + 8) != 0 or get(w, OBS + 16) != 64 or get(w, OBS + 24) != result - 64:
        return 0
    if get(w, OBS + 32) != get(w, E_NODE_COUNT) or get(w, OBS + 40) != get(w, E_CORE_BYTES) or get(w, OBS + 48) != 0 or get(w, OBS + 56) != get(w, E_DIGITS):
        return 0
    put(w, E_PACKET_BYTES, result - 64)
    put(w, C_PACKET_SLOT, B_CODEC)
    put(w, C_PACKET_OFFSET, 64)
    put(w, C_PACKET_BYTES, result - 64)
    put(w, L_INDEX_TARGET, B_CORE_SOURCE)
    put(w, L_INDEX_RETURN, 40)
    put(w, C_PHASE, 26000)
    return 1

def edit_main_step(o:mutbuf, w:mutbuf) -> u64:
    phase = get(w, C_PHASE)
    if phase == 1:
        return program_child(o, w, 2)
    if phase == 2:
        result = program_child_frame(w)
        if result == 0:
            return refuse(w, 1105)
        if result == 2:
            return edit_child_refusal(o, w)
        if result == 3:
            return view(o, w, B_PROGRAM_FRAME, 0, 64, 60)
        return view(o, w, B_PROGRAM_FRAME, 0, 256, 3)
    if phase == 3:
        if program_receipt_header(w) == 0:
            return refuse(w, 1106)
        return grow(o, w, B_CORE, get(w, E_CORE_BYTES), 4)
    if phase == 4:
        return copy(o, w, B_PROGRAM_FRAME, 256, B_CORE, 0, get(w, E_CORE_BYTES), 5)
    if phase == 5:
        return protect(o, w, B_CORE, 1, 6)
    if phase == 6:
        return hash_start(w, B_CORE, get(w, E_CORE_BYTES), E_ACTUAL_CORE_HASH, 7)
    if phase == 7:
        if same_digest(w, E_ACTUAL_CORE_HASH, E_CORE_HASH) == 0:
            return refuse(w, 1107)
        return grow(o, w, B_DECODE_ARENA, ARENA_BYTES, 8)
    if phase == 8:
        return grow(o, w, B_DECODE_WORK, KEY_BYTES, 9)
    if phase == 9:
        return grow(o, w, B_CODEC, CODEC_BYTES, 10)
    if phase == 10:
        wire8(w, 0, 0, 0, 0, 0, 0, NODES, DEPTH)
        return copy(o, w, B_CONTROLLER, WIRE, B_DECODE_WORK, 0, 64, 11)
    if phase == 11:
        return invoke(o, w, 24, B_CORE, 0, get(w, E_CORE_BYTES), B_DECODE_ARENA, ARENA_BYTES, B_DECODE_WORK, KEY_BYTES, B_DECODE_ARENA, 0, 64, 12)
    if phase == 12:
        if core_arena_header(w) == 0:
            return refuse(w, 1108)
        wire8(w, JSON_PACKET_MAGIC, get(w, E_DIGITS), 0, 0, 0, 0, 0, 0)
        return copy(o, w, B_CONTROLLER, WIRE, B_CODEC, 0, 64, 13)
    if phase == 13:
        return invoke(o, w, 25, B_DECODE_ARENA, 0, get(w, E_ARENA_USED), B_CORE, get(w, E_CORE_BYTES), B_CODEC, CODEC_BYTES, B_CODEC, 0, 64, 14)
    if phase == 14:
        if core_packet_header(w) == 0:
            return refuse(w, 1109)
        return 0
    if phase == 40:
        if get(w, C_JSON_BYTES) != get(w, E_CORE_BYTES) or cap(w, B_CORE_SOURCE) != get(w, L_INDEX_SOURCE_BYTES):
            return refuse(w, 1110)
        return hash_view_start(w, B_PACKET_JSON, 64, get(w, C_JSON_BYTES), E_ACTUAL_CORE_HASH, 41)
    if phase == 41:
        if same_digest(w, E_ACTUAL_CORE_HASH, E_CORE_HASH) == 0:
            return refuse(w, 1111)
        return release(o, w, B_DECODE_ARENA, 42)
    if phase == 42:
        return release(o, w, B_DECODE_WORK, 43)
    if phase == 43:
        return release(o, w, B_CODEC, 44)
    if phase == 44:
        return release(o, w, B_PACKET_JSON, 45)
    if phase == 45:
        return release(o, w, B_PACKET_WORK, 46)
    if phase == 46:
        return switch(o, w, QUERY, 1000)
    if phase == 60:
        if get(w, OBS) != CORE_DIAGNOSTIC or get(w, OBS + 8) != 1:
            return refuse(w, 1114)
        if get(w, OBS + 16) != get(w, E_ERROR_CODE) or get(w, OBS + 24) == 0 or get(w, OBS + 24) > 92:
            return refuse(w, 1115)
        if get(w, OBS + 40) != get(w, E_ERROR_BYTES) or get(w, OBS + 32) != get(w, E_ERROR_BYTES) - 64:
            return refuse(w, 1116)
        if get(w, OBS + 48) == 0 or get(w, OBS + 48) > NODES or get(w, OBS + 56) != 0:
            return refuse(w, 1117)
        return edit_error_start(w, 2, 8, get(w, E_ERROR_CODE), B_PROGRAM_FRAME, 64, get(w, OBS + 32))
    if phase == 200:
        return switch(o, w, QUERY, 2000)
    return refuse(w, 1112)

def edit_child_refusal(o:mutbuf, w:mutbuf) -> u32:
    if get(w, C_PENDING) != 0 or get(w, L_STATUS) != 1:
        return refuse(w, 1113)
    put(w, L_STATUS, 2)
    zero(o, 0, 128)
    put(o, 0, EVENT_MAGIC)
    put(o, 8, 7)
    put(o, 16, get(w, C_LEASE))
    put(o, 24, get(w, C_SEQUENCE))
    put(o, 32, get(w, E_ERROR_GROUP))
    put(o, 40, get(w, E_ERROR_CODE))
    put(o, 72, get(w, E_MODE))
    # Full dynamic diagnostic view forwarding is a separate pending upgrade
    # of the immutable program child; no category is represented as full text.
    return 128
'''
def source_program():return source(BODY+'\n'+ALL,CONSTANTS,'edit_main')
def document():return build(source_program(),'agent_edit_main')
if __name__=='__main__':write(document(),'agent_edit_main.hiaasm')
