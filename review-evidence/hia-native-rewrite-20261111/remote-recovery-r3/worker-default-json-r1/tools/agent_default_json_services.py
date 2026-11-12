"""Actual native preflight -> raw decoder -> DataGraph service continuation.

No component is selected by user JSON. The fixed coordinator binds exact images
and immutable same-context leases; this owner validates every actual return and
retains the ordinary order. Syntax-only raw decoding is not allowed to publish
a later grammar error before earlier json.loads numeric callbacks.
"""
SERVICES=r'''
def gc_begin_decoder(w:mutbuf) -> u64:
    size = gc_get(w, G_RAW_BYTES)
    bound = ((size + 1) >> 1) + 1
    if bound > 262144:
        bound = 262144
    output = 64 + bound * 56 + size
    if output < 4256:
        output = 4256
    workspace = gc_key_capacity(size)
    if workspace < 6320:
        workspace = 6320
    fill_range(w, GC_PEER_CONFIG, 128, 0)
    gc_put(w, GC_PEER_CONFIG + 48, 262144)
    gc_put(w, GC_PEER_CONFIG + 56, 128)
    gc_put(w, G_INPUT_OWNER, 0)
    gc_put(w, G_INPUT_AT, 0)
    gc_put(w, G_INPUT_SIZE, size)
    gc_put(w, G_OUTPUT_CAP, output)
    gc_put(w, G_WORK_CAP, workspace)
    gc_put(w, G_CONFIG_AT, GC_PEER_CONFIG)
    gc_put(w, G_CONFIG_SIZE, 128)
    if gc_get(w, G_DECODE_ATTEMPTS) != 0:
        return gc_bad(w, 30)
    gc_put(w, G_DECODE_ATTEMPTS, 1)
    return gc_request(w, 2, 30)

def gc_preflight_result(r:readbuf, w:mutbuf) -> u64:
    if gc_ack(r, w, 1) == 0 or length(r) != 4256:
        return gc_bad(w, 31)
    status = gc_get(w, G_ACTUAL_STATUS)
    reason = gc_word(r, 32)
    if status > 4:
        return gc_bad(w, 32)
    if status == 1:
        if reason == 0 or reason > 20:
            return gc_bad(w, 33)
    elif reason != 0:
        return gc_bad(w, 34)
    if status == 1:
        return gc_simple_error(w, 2, 100 + reason, 100 + reason)
    if status == 2:
        return gc_simple_error(w, 3, 1, 3)
    if status == 4:
        return gc_simple_error(w, 2, 2, 4)
    if status == 3:
        return gc_bad(w, 35)
    gc_put(w, G_PREFLIGHT_PASSED, 1)
    return gc_begin_decoder(w)

def gc_begin_values(w:mutbuf) -> u64:
    fill_range(w, GC_PEER_CONFIG, 128, 0)
    gc_put(w, GC_PEER_CONFIG, GC_VALUES_COMMAND)
    gc_put(w, GC_PEER_CONFIG + 8, gc_get(w, 192))
    gc_put(w, GC_PEER_CONFIG + 16, gc_get(w, 144))
    gc_put(w, GC_PEER_CONFIG + 24, gc_get(w, 184))
    gc_put(w, GC_PEER_CONFIG + 32, gc_get(w, 152))
    gc_put(w, GC_PEER_CONFIG + 40, gc_get(w, 160))
    gc_put(w, GC_PEER_CONFIG + 48, gc_get(w, 176))
    gc_put(w, GC_PEER_CONFIG + 56, gc_get(w, G_ARENA_EXTENT))
    gc_put(w, GC_PEER_CONFIG + 64, gc_get(w, G_RAW_BYTES))
    gc_put(w, G_INPUT_OWNER, 2)
    gc_put(w, G_INPUT_AT, 0)
    gc_put(w, G_INPUT_SIZE, gc_get(w, G_ARENA_EXTENT))
    gc_put(w, G_OUTPUT_CAP, 0)
    gc_put(w, G_WORK_CAP, 4096)
    gc_put(w, G_CONFIG_AT, GC_PEER_CONFIG)
    gc_put(w, G_CONFIG_SIZE, 128)
    return gc_request(w, 3, 40)

def gc_decoder_result(r:readbuf, w:mutbuf) -> u64:
    if gc_get(w, G_PREFLIGHT_PASSED) != 1 or gc_get(w, G_DECODE_ATTEMPTS) != 1:
        return gc_bad(w, 36)
    if gc_ack(r, w, 2) == 0:
        return gc_bad(w, 37)
    status = gc_get(w, G_ACTUAL_STATUS)
    if status == 4294967295:
        if length(r) != 0:
            return gc_bad(w, 38)
        gc_put(w, G_CURSOR, 0)
        gc_put(w, G_DEPTH, 0)
        gc_put(w, G_ROOT_DONE, 0)
        gc_put(w, G_PHASE, 50)
        gc_put(w, G_PEER, 0)
        gc_put(w, G_PENDING, 0)
        return 5
    if status < 64 or status > gc_get(w, G_OUTPUT_CAP) or length(r) != status:
        return gc_bad(w, 39)
    if gc_word(r, 0) != GC_ARENA:
        return gc_bad(w, 40)
    nodes = gc_word(r, 8)
    if nodes == 0 or nodes > 262144:
        return gc_bad(w, 41)
    if gc_word(r, 16) != 64 + nodes * 56 or gc_word(r, 16) > length(r):
        return gc_bad(w, 42)
    if gc_word(r, 24) != length(r) or gc_word(r, 32) != length(r):
        return gc_bad(w, 43)
    if gc_word(r, 40) != gc_get(w, G_RAW_BYTES) or gc_word(r, 48) != 1 or gc_word(r, 56) != 0:
        return gc_bad(w, 44)
    gc_put(w, G_ARENA_EXTENT, length(r))
    return gc_begin_values(w)

def gc_foreign_error_text(r:readbuf, w:mutbuf, at:u64, size:u64) -> u64:
    if at > length(r) or size == 0 or size > length(r) - at or size > GC_TEXT_CAP:
        return 0
    cursor = at
    while cursor < at + size:
        if gc_point(r, w, cursor, at + size, 0) == 0:
            return 0
        cursor = gc_get(w, G_UTF8_NEXT)
    copy_bytes(w, r, GC_TEXT, at, size)
    gc_put(w, G_TEXT_SIZE, size)
    return 1

def gc_values_result(r:readbuf, w:mutbuf) -> u64:
    if gc_ack(r, w, 3) == 0:
        return gc_bad(w, 45)
    if gc_get(w, G_ACTUAL_STATUS) != 2240:
        return gc_bad(w, 46)
    at = 2048
    if gc_word(r, at) != GC_VALUES_EVENT:
        return gc_bad(w, 47)
    if gc_word(r, at + 16) != gc_get(w, 192) or gc_word(r, at + 24) != gc_get(w, 144):
        return gc_bad(w, 48)
    if gc_word(r, at + 32) == 0 or gc_word(r, at + 40) != gc_get(w, 160):
        return gc_bad(w, 49)
    if gc_word(r, at + 48) != gc_get(w, 184) or gc_word(r, at + 56) != gc_get(w, 152):
        return gc_bad(w, 50)
    if gc_word(r, at + 64) != 0 or gc_word(r, at + 88) != 0 or gc_word(r, at + 96) != 0:
        return gc_bad(w, 51)
    if gc_word(r, at + 136) != gc_get(w, 176):
        return gc_bad(w, 52)
    if gc_word(r, at + 160) != 0 or gc_word(r, at + 176) != 0 or gc_word(r, at + 184) != 0:
        return gc_bad(w, 53)
    gc_put(w, G_VALUES_SEQ, gc_word(r, at + 32))
    gc_put(w, G_VALUES_WORK_EXTENT, length(r))
    action = gc_word(r, at + 8)
    if action == 3:
        if gc_word(r, at + 168) != 91 or gc_word(r, at + 72) != 0 or gc_word(r, at + 80) != 0:
            return gc_bad(w, 54)
        kind = gc_word(r, at + 112)
        if kind == 0 or kind > 4:
            return gc_bad(w, 55)
        if gc_foreign_error_text(r, w, gc_word(r, at + 120), gc_word(r, at + 128)) == 0:
            return gc_bad(w, 56)
        gc_put(w, G_ERROR_AUX, gc_word(r, at + 144))
        if kind == 1:
            return gc_error(w, 2, 1)
        if kind == 2 or kind == 3:
            return gc_error(w, 1, kind + 1)
        return gc_error(w, 7, 1)
    if action != 0 or gc_word(r, at + 168) != 90 or gc_word(r, at + 112) != 0:
        return gc_bad(w, 57)
    if gc_word(r, at + 120) != 0 or gc_word(r, at + 128) != 0:
        return gc_bad(w, 58)
    graph = gc_word(r, at + 72)
    size = gc_word(r, at + 80)
    if graph > length(r) or size < 64 or size > length(r) - graph:
        return gc_bad(w, 59)
    if gc_word(r, graph) != GC_GRAPH or gc_word(r, graph + 8) != gc_get(w, 160):
        return gc_bad(w, 60)
    if gc_word(r, graph + 16) == 0 or gc_word(r, graph + 24) != 1:
        return gc_bad(w, 61)
    if gc_word(r, graph + 48) != size or gc_word(r, graph + 56) != 0:
        return gc_bad(w, 62)
    gc_put(w, G_RESULT_OWNER, 2)
    gc_put(w, G_RESULT_AT, graph)
    gc_put(w, G_RESULT_SIZE, size)
    gc_put(w, G_PEER, 0)
    gc_put(w, G_PENDING, 0)
    gc_put(w, G_PHASE, 90)
    return 0

def gc_step(s:readbuf, r:readbuf, w:mutbuf) -> u64:
    phase = gc_get(w, G_PHASE)
    if phase == 20:
        return gc_preflight_result(r, w)
    if phase == 30:
        return gc_decoder_result(r, w)
    if phase == 40:
        return gc_values_result(r, w)
    return gc_bad(w, 63)
'''
