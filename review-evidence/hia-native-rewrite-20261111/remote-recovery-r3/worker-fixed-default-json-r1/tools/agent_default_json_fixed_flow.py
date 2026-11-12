"""Actual-peer orchestration for the default DataJSON fixed native component.

NEW UNEXECUTED. Every peer command is copied from its real HIA issuer; every
continuation carries the actual return and actual same-invocation output view.
No Python parser, numeric formatter or Graph materializer is a runtime peer.
"""
FLOW=r'''
def fd_move(w:mutbuf, target:u64, source:u64, size:u64) -> u64:
    index = 0
    while index < size:
        store(w, target + index, byte(w, source + index))
        index = index + 1
    return 0

def fd_initial(s:readbuf, w:mutbuf) -> u64:
    if length(s) != 64 or fd_word(s, 0) != FD_START or fd_word(s, 8) != 1:
        return 0
    if fd_word(s, 16) < 128:
        return 0
    at = 24
    while at < 64:
        if fd_word(s, at) != 0:
            return 0
        at = at + 8
    at = 0
    while at < FD_MIN:
        if byte(w, at) != 0:
            return 0
        at = at + 1
    fd_put(w, F_MAGIC, FD_STATE)
    fd_put(w, F_STATUS, 1)
    fd_put(w, F_LEASE, 1)
    fd_put(w, F_INPUT_BYTES, fd_word(s, 16))
    fd_put(w, FD_CAPS + B_INPUT * 8, fd_word(s, 16))
    fd_put(w, FD_CAPS + B_CONTROL * 8, length(w))
    fd_put(w, FD_CAPS + B_FRAME * 8, 128)
    fd_put(w, F_PHASE, 1)
    return 1

def fd_input_header(w:mutbuf) -> u64:
    if fd_get(w, FD_OBS) != FD_INPUT or fd_get(w, FD_OBS + 8) != 1:
        return 0
    if fd_get(w, FD_OBS + 16) == 0 or fd_get(w, FD_OBS + 24) == 0:
        return 0
    if fd_get(w, FD_OBS + 32) == 0 or fd_get(w, FD_OBS + 40) == 0:
        return 0
    if fd_get(w, FD_OBS + 64) == 0 or fd_get(w, FD_OBS + 72) == 0:
        return 0
    digits = fd_get(w, FD_OBS + 56)
    if digits != 0 and digits < 640:
        return 0
    if fd_get(w, FD_OBS + 80) != fd_get(w, F_INPUT_BYTES) - 128:
        return 0
    at = 88
    while at < 128:
        if fd_get(w, FD_OBS + at) != 0:
            return 0
        at = at + 8
    fd_move(w, FD_INPUT_HEADER, FD_OBS, 128)
    fd_put(w, F_INV, fd_get(w, FD_OBS + 16))
    fd_put(w, F_CALL, fd_get(w, FD_OBS + 24))
    fd_put(w, F_RAW_LEASE, fd_get(w, FD_OBS + 32))
    fd_put(w, F_GRAPH_LEASE, fd_get(w, FD_OBS + 40))
    fd_put(w, F_KIND, fd_get(w, FD_OBS + 48))
    fd_put(w, F_DIGITS, digits)
    fd_put(w, F_ARENA_LEASE, fd_get(w, FD_OBS + 64))
    fd_put(w, F_VALUES_LEASE, fd_get(w, FD_OBS + 72))
    fd_put(w, F_RAW_BYTES, fd_get(w, FD_OBS + 80))
    return 1

def fd_start_step(o:mutbuf, w:mutbuf) -> u32:
    phase = fd_get(w, F_PHASE)
    if phase == 1:
        return fd_view(o, w, B_INPUT, 0, 128, 10)
    if phase == 10:
        if fd_input_header(w) == 0:
            return fd_refuse(w, 100)
        size = fd_get(w, F_RAW_BYTES)
        if size == 0:
            size = 1
        return fd_grow(o, w, B_RAW, size, 11)
    if phase == 11:
        return fd_copy(o, w, B_INPUT, 128, B_RAW, 0, fd_get(w, F_RAW_BYTES), 12)
    if phase == 12:
        return fd_protect(o, w, B_RAW, 1, 13)
    if phase == 13:
        return fd_grow(o, w, B_PREFIX, 8192, 14)
    if phase == 14:
        fill_range(w, FD_WIRE, 128, 0)
        fd_put(w, FD_WIRE, FD_PREFIX_COMMAND)
        fd_put(w, FD_WIRE + 8, fd_get(w, F_INV))
        fd_put(w, FD_WIRE + 16, fd_get(w, F_CALL))
        fd_put(w, FD_WIRE + 24, fd_get(w, F_RAW_LEASE))
        fd_put(w, FD_WIRE + 32, fd_get(w, F_GRAPH_LEASE))
        fd_put(w, FD_WIRE + 40, fd_get(w, F_KIND))
        fd_put(w, FD_WIRE + 48, fd_get(w, F_DIGITS))
        fd_put(w, FD_WIRE + 56, fd_get(w, F_ARENA_LEASE))
        fd_put(w, FD_WIRE + 64, fd_get(w, F_VALUES_LEASE))
        fd_put(w, FD_WIRE + 72, fd_get(w, F_RAW_BYTES))
        return fd_copy(o, w, B_CONTROL, FD_WIRE, B_PREFIX, 128, 128, 15)
    if phase == 15:
        fd_put(w, F_PREFIX_ROLE, 1)
        fd_put(w, F_REPLY_SLOT, 0)
        fd_put(w, F_REPLY_SIZE, 0)
        fd_put(w, F_PHASE, 100)
        return 0
    return fd_refuse(w, 101)

def fd_validate_prefix(w:mutbuf) -> u64:
    if fd_get(w, F_RETURN) != 2304 or fd_get(w, FD_OBS) != FD_PREFIX_EVENT:
        return 0
    if fd_get(w, FD_OBS + 16) != fd_get(w, F_INV) or fd_get(w, FD_OBS + 24) != fd_get(w, F_CALL):
        return 0
    prior = fd_get(w, F_PREFIX_SEQ)
    if prior == FD_MAX or fd_get(w, FD_OBS + 32) != prior + 1:
        return 0
    if fd_get(w, FD_OBS + 40) != fd_get(w, F_RAW_LEASE):
        return 0
    if fd_get(w, FD_OBS + 48) != fd_get(w, F_GRAPH_LEASE):
        return 0
    if fd_get(w, FD_OBS + 56) != fd_get(w, F_KIND) or fd_get(w, FD_OBS + 64) != fd_get(w, F_DIGITS):
        return 0
    if fd_get(w, FD_OBS + 248) != 0:
        return 0
    phase = fd_get(w, FD_OBS + 72)
    if fd_get(w, FD_OBS + 80) != fd_role(phase):
        return 0
    fd_move(w, FD_PREFIX_FRAME, FD_OBS, 256)
    fd_put(w, F_PREFIX_SEQ, prior + 1)
    fd_put(w, F_PREFIX_PHASE, phase)
    return 1

def fd_peer_input(w:mutbuf) -> u64:
    owner = fd_prefix_word(w, 14)
    at = fd_prefix_word(w, 15)
    size = fd_prefix_word(w, 16)
    slot = 0
    bound = 0
    if owner == 0:
        slot = B_RAW
        bound = fd_get(w, F_RAW_BYTES)
    elif owner == 1:
        slot = B_PREFIX
        bound = fd_cap(w, B_PREFIX)
    elif owner == 2:
        slot = B_PEER_OUTPUT
        bound = fd_get(w, F_ARENA_SIZE)
    else:
        return 0
    if at > bound or size > bound - at:
        return 0
    if fd_prefix_word(w, 19) > fd_cap(w, B_PREFIX):
        return 0
    if fd_prefix_word(w, 20) > fd_cap(w, B_PREFIX) - fd_prefix_word(w, 19):
        return 0
    fd_put(w, F_INPUT_SLOT, slot)
    fd_put(w, F_INPUT_AT, at)
    fd_put(w, F_INPUT_SIZE, size)
    fd_put(w, F_OUTPUT_CAP, fd_prefix_word(w, 17))
    fd_put(w, F_WORK_CAP, fd_prefix_word(w, 18))
    fd_put(w, F_CONFIG_AT, fd_prefix_word(w, 19))
    fd_put(w, F_CONFIG_SIZE, fd_prefix_word(w, 20))
    return 1

def fd_begin_peer(w:mutbuf) -> u64:
    peer = fd_prefix_word(w, 12)
    if fd_prefix_word(w, 13) != fd_get(w, F_PREFIX_SEQ) or fd_prefix_word(w, 11) != 0:
        return 0
    if fd_role(fd_prefix_word(w, 9)) == 0 or fd_peer_input(w) == 0:
        return 0
    fd_put(w, F_PREFIX_ROLE, fd_prefix_word(w, 10))
    fd_put(w, F_PEER, peer)
    fd_put(w, F_PEER_SEQ, fd_prefix_word(w, 13))
    fd_put(w, F_OUTPUT_SLOT, B_PEER_OUTPUT)
    fd_put(w, F_WORK_SLOT, B_PEER_WORK)
    if peer == 1:
        if fd_prefix_word(w, 9) != 20 or fd_prefix_word(w, 14) != 1:
            return 0
        if fd_get(w, F_CONFIG_SIZE) != 128 or fd_get(w, F_WORK_CAP) != 4256:
            return 0
        if fd_get(w, F_OUTPUT_CAP) == 0:
            return 0
        fd_put(w, F_PEER_IMAGE, 4)
    elif peer == 2:
        if fd_prefix_word(w, 9) != 30 or fd_prefix_word(w, 14) != 0:
            return 0
        if fd_get(w, F_CONFIG_SIZE) != 128 or fd_get(w, F_WORK_CAP) < 6320:
            return 0
        if fd_get(w, F_OUTPUT_CAP) < 4256:
            return 0
        fd_put(w, F_PEER_IMAGE, 5)
    elif peer == 3:
        if fd_prefix_word(w, 9) != 40 or fd_prefix_word(w, 14) != 2:
            return 0
        if fd_get(w, F_CONFIG_SIZE) != 128 or fd_get(w, F_OUTPUT_CAP) != 0:
            return 0
        if fd_get(w, F_WORK_CAP) != 4096 or fd_get(w, F_VALUES_STARTED) != 0:
            return 0
        if fd_get(w, F_INPUT_AT) != 0 or fd_get(w, F_INPUT_SIZE) != fd_get(w, F_ARENA_SIZE):
            return 0
        fd_put(w, F_VALUES_STARTED, 1)
        fd_put(w, F_PHASE, 300)
        return 1
    elif peer == 4:
        if fd_prefix_word(w, 9) != 51 or fd_prefix_word(w, 14) != 0:
            return 0
        if fd_get(w, F_CONFIG_SIZE) != 0 or fd_get(w, F_OUTPUT_CAP) != 8:
            return 0
        if fd_get(w, F_WORK_CAP) != 4096:
            return 0
        fd_put(w, F_OUTPUT_SLOT, B_BITS)
        fd_put(w, F_WORK_SLOT, B_BINARY_WORK)
        fd_put(w, F_PEER_IMAGE, 7)
    else:
        return 0
    fd_put(w, F_PHASE, 200)
    return 1

def fd_begin_result(w:mutbuf) -> u64:
    action = fd_prefix_word(w, 1)
    owner = fd_prefix_word(w, 21)
    at = fd_prefix_word(w, 22)
    size = fd_prefix_word(w, 23)
    source = B_PREFIX
    if action == 0:
        if owner != 2 or fd_prefix_word(w, 9) != 90:
            return 0
        if fd_get(w, F_REPLY_SLOT) != B_VALUES or size < 64:
            return 0
        index = 24
        while index < 31:
            if fd_prefix_word(w, index) != 0:
                return 0
            index = index + 1
        source = B_VALUES
    elif action == 3:
        if owner != 1 or fd_prefix_word(w, 9) != 91:
            return 0
        if fd_prefix_word(w, 24) == 0 or fd_prefix_word(w, 24) > 7:
            return 0
        if size == 0 or size > 1024:
            return 0
    else:
        return 0
    if size > FD_MAX - 256 or fd_inside(w, source, at, size) == 0:
        return 0
    fd_put(w, F_RESULT_KIND, action)
    fd_put(w, F_RESULT_SOURCE, source)
    fd_put(w, F_RESULT_AT, at)
    fd_put(w, F_RESULT_SIZE, size)
    fd_put(w, F_PHASE, 400)
    return 1

def fd_prefix_step(o:mutbuf, w:mutbuf) -> u32:
    if fd_get(w, F_PHASE) == 100:
        return fd_call(o, w, fd_get(w, F_PREFIX_ROLE), B_RAW, 0, fd_get(w, F_RAW_BYTES), fd_get(w, F_REPLY_SLOT), fd_get(w, F_REPLY_SIZE), B_PREFIX, fd_cap(w, B_PREFIX), B_PREFIX, 2048, 256, 101)
    if fd_get(w, F_PHASE) != 101 or fd_validate_prefix(w) == 0:
        return fd_refuse(w, 110)
    action = fd_prefix_word(w, 1)
    if action == 1:
        if fd_prefix_word(w, 10) != fd_get(w, F_PREFIX_ROLE):
            return fd_refuse(w, 111)
        need = fd_prefix_word(w, 11)
        if need <= fd_cap(w, B_PREFIX):
            return fd_refuse(w, 112)
        return fd_grow(o, w, B_PREFIX, need, 100)
    if action == 5:
        if fd_prefix_word(w, 10) == 0:
            return fd_refuse(w, 113)
        fd_put(w, F_PREFIX_ROLE, fd_prefix_word(w, 10))
        fd_put(w, F_PHASE, 100)
        return 0
    if action == 2:
        if fd_begin_peer(w) == 0:
            return fd_refuse(w, 114)
        return 0
    if fd_begin_result(w) == 0:
        return fd_refuse(w, 115)
    return 0

def fd_prepare_prefix_reply(w:mutbuf) -> u64:
    fill_range(w, FD_WIRE, 128, 0)
    fd_put(w, FD_WIRE, FD_PREFIX_ACK)
    fd_put(w, FD_WIRE + 8, fd_get(w, F_INV))
    fd_put(w, FD_WIRE + 16, fd_get(w, F_CALL))
    fd_put(w, FD_WIRE + 24, fd_get(w, F_PEER_SEQ))
    fd_put(w, FD_WIRE + 32, fd_get(w, F_PEER))
    fd_put(w, FD_WIRE + 40, fd_get(w, F_ACTUAL))
    fd_put(w, FD_WIRE + 48, fd_get(w, F_REPLY_SIZE))
    fd_put(w, FD_WIRE + 56, fd_get(w, F_REPLY_WORK_BYTES))
    fd_put(w, FD_WIRE + 64, fd_get(w, F_OUTPUT_LEASE))
    fd_put(w, FD_WIRE + 72, fd_get(w, F_WORKSPACE_LEASE))
    fd_put(w, FD_WIRE + 80, fd_get(w, F_RAW_LEASE))
    fd_put(w, FD_WIRE + 88, fd_get(w, F_OUTPUT_CAP))
    fd_put(w, FD_WIRE + 96, fd_get(w, F_INPUT_SIZE))
    return 0

def fd_simple_step(o:mutbuf, w:mutbuf) -> u32:
    phase = fd_get(w, F_PHASE)
    if phase == 200:
        return fd_grow(o, w, fd_get(w, F_OUTPUT_SLOT), fd_get(w, F_OUTPUT_CAP), 201)
    if phase == 201:
        return fd_grow(o, w, fd_get(w, F_WORK_SLOT), fd_get(w, F_WORK_CAP), 202)
    if phase == 202:
        return fd_clear(o, w, fd_get(w, F_OUTPUT_SLOT), 0, fd_get(w, F_OUTPUT_CAP), 203)
    if phase == 203:
        return fd_clear(o, w, fd_get(w, F_WORK_SLOT), 0, fd_get(w, F_WORK_CAP), 204)
    if phase == 204:
        if fd_get(w, F_CONFIG_SIZE) == 0:
            fd_put(w, F_PHASE, 205)
            return 0
        return fd_copy(o, w, B_PREFIX, fd_get(w, F_CONFIG_AT), fd_get(w, F_WORK_SLOT), 0, fd_get(w, F_CONFIG_SIZE), 205)
    if phase == 205:
        return fd_call(o, w, fd_get(w, F_PEER_IMAGE), fd_get(w, F_INPUT_SLOT), fd_get(w, F_INPUT_AT), fd_get(w, F_INPUT_SIZE), fd_get(w, F_OUTPUT_SLOT), fd_get(w, F_OUTPUT_CAP), fd_get(w, F_WORK_SLOT), fd_get(w, F_WORK_CAP), 0, 0, 0, 206)
    if phase == 206:
        actual = fd_get(w, F_RETURN)
        peer = fd_get(w, F_PEER)
        fd_put(w, F_ACTUAL, actual)
        fd_put(w, F_REPLY_WORK_BYTES, fd_get(w, F_WORK_CAP))
        fd_put(w, F_WORKSPACE_LEASE, fd_get(w, F_INV))
        fd_put(w, F_OUTPUT_LEASE, 0)
        if peer == 1:
            fd_put(w, F_REPLY_SLOT, B_PEER_WORK)
            fd_put(w, F_REPLY_SIZE, fd_get(w, F_WORK_CAP))
        elif peer == 2:
            extent = 0
            if actual <= fd_get(w, F_OUTPUT_CAP):
                extent = actual
            fd_put(w, F_REPLY_SLOT, B_PEER_OUTPUT)
            fd_put(w, F_REPLY_SIZE, extent)
            fd_put(w, F_ARENA_SIZE, extent)
            fd_put(w, F_OUTPUT_LEASE, fd_get(w, F_ARENA_LEASE))
        elif peer == 4:
            fd_put(w, F_REPLY_SLOT, B_BITS)
            fd_put(w, F_REPLY_SIZE, choose(actual == 8, 8, 0))
        else:
            return fd_refuse(w, 120)
        fd_put(w, F_PHASE, 207)
        return 0
    if phase == 207:
        fd_prepare_prefix_reply(w)
        return fd_copy(o, w, B_CONTROL, FD_WIRE, B_PREFIX, 256, 128, 100)
    return fd_refuse(w, 121)

def fd_validate_values(w:mutbuf) -> u64:
    if fd_get(w, F_RETURN) != 2240 or fd_get(w, FD_OBS) != FD_VALUES_EVENT:
        return 0
    if fd_get(w, FD_OBS + 16) != fd_get(w, F_VALUES_LEASE) or fd_get(w, FD_OBS + 24) != fd_get(w, F_CALL):
        return 0
    prior = fd_get(w, F_VALUES_SEQ)
    if prior == FD_MAX or fd_get(w, FD_OBS + 32) != prior + 1:
        return 0
    if fd_get(w, FD_OBS + 40) != fd_get(w, F_GRAPH_LEASE):
        return 0
    if fd_get(w, FD_OBS + 48) != fd_get(w, F_ARENA_LEASE) or fd_get(w, FD_OBS + 56) != fd_get(w, F_RAW_LEASE):
        return 0
    if fd_get(w, FD_OBS + 136) != fd_get(w, F_DIGITS):
        return 0
    if fd_get(w, FD_OBS + 176) != 0 or fd_get(w, FD_OBS + 184) != 0:
        return 0
    fd_move(w, FD_VALUES_FRAME, FD_OBS, 192)
    fd_put(w, F_VALUES_SEQ, prior + 1)
    return 1

def fd_values_step(o:mutbuf, w:mutbuf) -> u32:
    phase = fd_get(w, F_PHASE)
    if phase == 300:
        return fd_grow(o, w, B_VALUES, 4096, 301)
    if phase == 301:
        return fd_clear(o, w, B_VALUES, 0, 4096, 302)
    if phase == 302:
        return fd_copy(o, w, B_PREFIX, fd_get(w, F_CONFIG_AT), B_VALUES, 128, 128, 303)
    if phase == 303:
        return fd_call(o, w, 6, B_PEER_OUTPUT, 0, fd_get(w, F_ARENA_SIZE), B_RAW, fd_get(w, F_RAW_BYTES), B_VALUES, fd_cap(w, B_VALUES), B_VALUES, 2048, 192, 304)
    if phase == 304:
        if fd_validate_values(w) == 0:
            return fd_refuse(w, 130)
        action = fd_values_word(w, 1)
        if action == 1:
            need = fd_values_word(w, 8)
            if need <= fd_cap(w, B_VALUES):
                return fd_refuse(w, 131)
            return fd_grow(o, w, B_VALUES, need, 303)
        if action == 2:
            start = fd_values_word(w, 11)
            size = fd_values_word(w, 12)
            if start > fd_get(w, F_RAW_BYTES) or size == 0 or size > fd_get(w, F_RAW_BYTES) - start:
                return fd_refuse(w, 132)
            if fd_values_word(w, 13) == 0:
                return fd_refuse(w, 133)
            fd_put(w, F_NUMBER_AT, start)
            fd_put(w, F_NUMBER_SIZE, size)
            fd_put(w, F_VALUES_NODE, fd_values_word(w, 13))
            fd_put(w, F_PHASE, 310)
            return 0
        if action != 0 and action != 3:
            return fd_refuse(w, 134)
        fd_put(w, F_ACTUAL, 2240)
        fd_put(w, F_REPLY_SLOT, B_VALUES)
        fd_put(w, F_REPLY_SIZE, fd_cap(w, B_VALUES))
        fd_put(w, F_REPLY_WORK_BYTES, fd_cap(w, B_VALUES))
        fd_put(w, F_OUTPUT_LEASE, fd_get(w, F_VALUES_LEASE))
        fd_put(w, F_WORKSPACE_LEASE, fd_get(w, F_VALUES_LEASE))
        fd_put(w, F_PHASE, 207)
        return 0
    if phase == 310:
        return fd_grow(o, w, B_BITS, 8, 311)
    if phase == 311:
        return fd_grow(o, w, B_BINARY_WORK, 4096, 312)
    if phase == 312:
        return fd_clear(o, w, B_BITS, 0, 8, 313)
    if phase == 313:
        return fd_clear(o, w, B_BINARY_WORK, 0, 4096, 314)
    if phase == 314:
        return fd_call(o, w, 7, B_RAW, fd_get(w, F_NUMBER_AT), fd_get(w, F_NUMBER_SIZE), B_BITS, 8, B_BINARY_WORK, 4096, B_BITS, 0, 8, 315)
    if phase == 315:
        actual = fd_get(w, F_RETURN)
        fill_range(w, FD_WIRE, 72, 0)
        fd_put(w, FD_WIRE, FD_VALUES_ACK)
        fd_put(w, FD_WIRE + 8, fd_get(w, F_VALUES_LEASE))
        fd_put(w, FD_WIRE + 16, fd_get(w, F_CALL))
        fd_put(w, FD_WIRE + 24, fd_get(w, F_VALUES_SEQ))
        fd_put(w, FD_WIRE + 32, actual)
        fd_put(w, FD_WIRE + 40, choose(actual == 8, 8, 0))
        fd_put(w, FD_WIRE + 48, fd_get(w, F_VALUES_NODE))
        fd_move(w, FD_WIRE + 64, FD_OBS, 8)
        return fd_copy(o, w, B_CONTROL, FD_WIRE, B_VALUES, 256, 72, 303)
    return fd_refuse(w, 135)

def fd_finish_step(o:mutbuf, w:mutbuf) -> u32:
    phase = fd_get(w, F_PHASE)
    if phase == 400:
        return fd_grow(o, w, B_RESULT, 256 + fd_get(w, F_RESULT_SIZE), 401)
    if phase == 401:
        return fd_copy(o, w, B_PREFIX, 2048, B_RESULT, 0, 256, 402)
    if phase == 402:
        return fd_copy(o, w, fd_get(w, F_RESULT_SOURCE), fd_get(w, F_RESULT_AT), B_RESULT, 256, fd_get(w, F_RESULT_SIZE), 403)
    if phase == 403:
        return fd_protect(o, w, B_RESULT, 1, 404)
    if phase == 404:
        fd_put(w, F_CLEAN_SLOT, 4)
        fd_put(w, F_PHASE, 405)
        return 0
    if phase == 405:
        slot = fd_get(w, F_CLEAN_SLOT)
        if slot < 12:
            fd_put(w, F_CLEAN_SLOT, slot + 1)
            return fd_release(o, w, slot, 405)
        fd_put(w, F_STATUS, 2)
        fd_put(o, 0, FD_EVENT)
        fd_put(o, 8, 7)
        fd_put(o, 16, fd_get(w, F_LEASE))
        fd_put(o, 24, fd_get(w, F_SEQ))
        fd_put(o, 32, choose(fd_get(w, F_RESULT_KIND) == 0, 0, 1))
        fd_put(o, 40, B_RESULT)
        fd_put(o, 48, 0)
        fd_put(o, 56, 256 + fd_get(w, F_RESULT_SIZE))
        fd_put(o, 64, 0)
        fd_put(o, 72, 0)
        fd_put(o, 80, 0)
        fill_range(o, 88, 40, 0)
        return 128
    return fd_refuse(w, 140)

def fd_entry(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < FD_MIN:
        return FD_BAD
    if length(o) < 128:
        return fd_refuse(w, 150)
    if fd_get(w, F_MAGIC) == 0:
        if fd_initial(s, w) == 0:
            return fd_refuse(w, 151)
    else:
        if fd_get(w, F_MAGIC) != FD_STATE or fd_get(w, F_STATUS) != 1:
            return FD_BAD
        if fd_ack(s, w) == 0:
            return fd_refuse(w, 152)
    while fd_get(w, F_STATUS) == 1:
        phase = fd_get(w, F_PHASE)
        result = FD_BAD
        if phase < 100:
            result = fd_start_step(o, w)
        elif phase < 200:
            result = fd_prefix_step(o, w)
        elif phase < 300:
            result = fd_simple_step(o, w)
        elif phase < 400:
            result = fd_values_step(o, w)
        elif phase < 500:
            result = fd_finish_step(o, w)
        else:
            return fd_refuse(w, 153)
        if result != 0:
            return result
    return fd_refuse(w, 154)
'''
