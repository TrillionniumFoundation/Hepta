"""Initializer P16/P17/P18 common transport, NEW unexecuted r1.

Actual initializer, registry, program child, decoder and Graph leases are issued
inside one fixed private invocation. Headers correlate those actual calls; they
do not authenticate an arbitrary external Graph, record, arena or peer reply.
Short workspace and every BAD require the caller to retire the entire route.
"""
FIELDS=(
 "MAGIC","PHASE","BAD","SEQUENCE","INV","CALL","LEASE","PENDING","PEER",
 "DIGITS","ORIGIN","INITIALIZER_BYTES","GRAPH_LEASE","GRAPH_BYTES",
 "REG_SEQUENCE","REG_PREVIOUS","REG_ACTIVE","ISSUED","ARG","BORROW_ROOT",
 "WIRE_ROLE","WIRE_NEED","INPUT_AT","INPUT_BYTES","INPUT_TREE","CHILD_MODE",
 "FRAME_AT","FRAME_BYTES","CORE_AT","CORE_BYTES","TEXT_AT","TEXT_BYTES",
 "ERROR_DOMAIN","NEED","RETRY","KERNEL","SAVE_END","PACKET_AT","PACKET_BYTES",
 "FOREIGN","OUTPUT","ITEM","HANDLE0","HANDLE1","HANDLE2","OLD_NODES",
 "OLD_EDGES","OLD_POOL","NEW_NODES","NEW_EDGES","NEW_POOL","NEW_BYTES",
 "DECODER_OUT","DECODER_WORK","ARENA_AT","ARENA_BYTES","DG_SEQUENCE",
 "DG_NEED","DG_STARTED","RESULT_KIND","REPLY_BYTES","LAST_PENDING")
BODY=r'''
def pb_event(w:mutbuf, action:u64) -> u32:
    sequence = iv_get(w, P_SEQUENCE)
    if sequence == IV_MAX:
        iv_put(w, P_PHASE, 99)
        return IV_BAD
    iv_put(w, P_SEQUENCE, sequence + 1)
    fill_range(w, PB_EVENT_AT, 256, 0)
    iv_put(w, PB_EVENT_AT, PB_EVENT)
    iv_put(w, PB_EVENT_AT + 8, action)
    iv_put(w, PB_EVENT_AT + 16, iv_get(w, P_INV))
    iv_put(w, PB_EVENT_AT + 24, iv_get(w, P_CALL))
    iv_put(w, PB_EVENT_AT + 32, iv_get(w, P_LEASE))
    iv_put(w, PB_EVENT_AT + 40, sequence + 1)
    iv_put(w, PB_EVENT_AT + 48, iv_get(w, P_PHASE))
    iv_put(w, PB_EVENT_AT + 56, iv_get(w, P_BAD))
    iv_put(w, PB_EVENT_AT + 64, iv_get(w, P_PENDING))
    iv_put(w, PB_EVENT_AT + 72, iv_get(w, P_PEER))
    iv_put(w, PB_EVENT_AT + 80, iv_get(w, P_ORIGIN))
    iv_put(w, PB_EVENT_AT + 88, iv_get(w, P_DIGITS))
    iv_put(w, PB_EVENT_AT + 96, iv_get(w, P_NEED))
    if action == 2:
        iv_put(w, PB_EVENT_AT + 104, 1)
        iv_put(w, PB_EVENT_AT + 112, PB_REG_COMMAND)
        iv_put(w, PB_EVENT_AT + 120, 128)
        if iv_get(w, P_PHASE) == 35:
            iv_put(w, PB_EVENT_AT + 176, iv_get(w, P_PACKET_AT))
            iv_put(w, PB_EVENT_AT + 184, iv_get(w, P_PACKET_BYTES))
    elif action == 3:
        iv_put(w, PB_EVENT_AT + 104, iv_get(w, P_WIRE_ROLE))
        iv_put(w, PB_EVENT_AT + 112, PB_WIRE_COMMAND)
        iv_put(w, PB_EVENT_AT + 120, 64)
        iv_put(w, PB_EVENT_AT + 128, 1)
        iv_put(w, PB_EVENT_AT + 144, iv_get(w, P_GRAPH_BYTES))
        iv_put(w, PB_EVENT_AT + 152, iv_get(w, P_WIRE_NEED))
        iv_put(w, PB_EVENT_AT + 168, choose(iv_get(w, P_PHASE) == 11, 1, 0))
    elif action == 4:
        iv_put(w, PB_EVENT_AT + 104, 4)
        iv_put(w, PB_EVENT_AT + 112, iv_get(w, P_INPUT_AT) - 64)
        iv_put(w, PB_EVENT_AT + 120, iv_get(w, P_INPUT_BYTES) + 64)
    elif action == 5:
        iv_put(w, PB_EVENT_AT + 104, 5)
        iv_put(w, PB_EVENT_AT + 112, PB_DECODER_CONFIG)
        iv_put(w, PB_EVENT_AT + 120, 64)
        iv_put(w, PB_EVENT_AT + 128, 3)
        iv_put(w, PB_EVENT_AT + 136, iv_get(w, P_CORE_AT))
        iv_put(w, PB_EVENT_AT + 144, iv_get(w, P_CORE_BYTES))
        iv_put(w, PB_EVENT_AT + 152, iv_get(w, P_DECODER_WORK))
        iv_put(w, PB_EVENT_AT + 160, iv_get(w, P_DECODER_OUT))
        iv_put(w, PB_EVENT_AT + 168, 1)
    elif action == 6:
        iv_put(w, PB_EVENT_AT + 104, 6)
        iv_put(w, PB_EVENT_AT + 112, PB_DG_CONFIG)
        iv_put(w, PB_EVENT_AT + 120, 128)
        iv_put(w, PB_EVENT_AT + 128, 3)
        iv_put(w, PB_EVENT_AT + 136, iv_get(w, P_ARENA_AT))
        iv_put(w, PB_EVENT_AT + 144, iv_get(w, P_ARENA_BYTES))
        iv_put(w, PB_EVENT_AT + 152, iv_get(w, P_DG_NEED))
        iv_put(w, PB_EVENT_AT + 168, choose(iv_get(w, P_DG_STARTED) == 0, 1, 0))
        iv_put(w, PB_EVENT_AT + 176, iv_get(w, P_CORE_AT))
        iv_put(w, PB_EVENT_AT + 184, iv_get(w, P_CORE_BYTES))
    iv_put(w, PB_EVENT_AT + 192, iv_get(w, P_REG_SEQUENCE))
    iv_put(w, PB_EVENT_AT + 200, iv_get(w, P_REG_ACTIVE))
    iv_put(w, PB_EVENT_AT + 208, iv_get(w, P_GRAPH_LEASE))
    iv_put(w, PB_EVENT_AT + 216, iv_get(w, P_GRAPH_BYTES))
    if action == 0:
        iv_put(w, PB_EVENT_AT + 224, PB_REPLY)
        iv_put(w, PB_EVENT_AT + 232, iv_get(w, P_REPLY_BYTES))
    iv_put(w, PB_EVENT_AT + 240, iv_get(w, P_KERNEL))
    return PB_EVENT_END

def pb_fail(w:mutbuf, reason:u64) -> u32:
    iv_bad(w, reason)
    iv_put(w, P_PHASE, 99)
    pb_event(w, 7)
    return IV_BAD

def pb_local_copy(w:mutbuf, target:u64, source:u64, count:u64) -> u64:
    if target > length(w) or count > length(w) - target:
        return iv_bad(w, 900)
    if source > length(w) or count > length(w) - source:
        return iv_bad(w, 901)
    if target > source and target - source < count:
        index = count
        while index > 0:
            index = index - 1
            store(w, target + index, byte(w, source + index))
    else:
        index = 0
        while index < count:
            store(w, target + index, byte(w, source + index))
            index = index + 1
    return 1

def pb_same_source(s:readbuf, w:mutbuf) -> u64:
    if length(s) != iv_get(w, P_GRAPH_BYTES):
        return iv_bad(w, 902)
    index = 0
    while index < 64:
        if byte(s, index) != byte(w, PB_SOURCE_HEADER + index):
            return iv_bad(w, 903)
        index = index + 1
    return 1

def pb_require(r:readbuf, w:mutbuf, needed:u64) -> u64:
    if needed < PB_MIN:
        return iv_bad(w, 904)
    if needed > length(w):
        iv_put(w, P_NEED, needed)
        if iv_get(w, P_RETRY) == 0:
            copy_bytes(w, r, PB_SAVED_COMMAND, 0, 128)
        iv_put(w, P_RETRY, 1)
        return 0
    iv_put(w, P_NEED, 0)
    iv_put(w, P_RETRY, 0)
    return 1

def pb_header(s:readbuf, r:readbuf, w:mutbuf, kernel:u64) -> u64:
    if length(r) < 128 or iv_word(r, 0) != PB_COMMAND:
        return iv_bad(w, 905)
    if iv_word(r, 16) == 0 or iv_word(r, 24) == 0 or iv_word(r, 32) == 0:
        return iv_bad(w, 906)
    if iv_word(r, 32) > IV_MAX - 4 or iv_word(r, 64) != length(r) - 128:
        return iv_bad(w, 907)
    if iv_word(r, 112) != 0 or iv_word(r, 120) != 0:
        return iv_bad(w, 908)
    if iv_word(r, 48) != iv_word(s, 8) or iv_word(r, 56) != length(s):
        return iv_bad(w, 909)
    if iv_get(w, P_MAGIC) == 0:
        if kernel != 1 or iv_word(r, 8) != 1 or iv_word(r, 40) != 0:
            return iv_bad(w, 910)
        return 1
    if iv_get(w, P_MAGIC) != PB_STATE or iv_get(w, P_KERNEL) != kernel:
        return iv_bad(w, 911)
    if iv_word(r, 16) != iv_get(w, P_INV) or iv_word(r, 24) != iv_get(w, P_CALL):
        return iv_bad(w, 912)
    if iv_word(r, 32) != iv_get(w, P_LEASE):
        return iv_bad(w, 913)
    if iv_get(w, P_RETRY) == 1:
        index = 0
        while index < 128:
            if byte(r, index) != byte(w, PB_SAVED_COMMAND + index):
                return iv_bad(w, 914)
            index = index + 1
    elif iv_word(r, 40) != iv_get(w, P_SEQUENCE):
        return iv_bad(w, 915)
    if iv_word(r, 8) != 8 and pb_same_source(s, w) == 0:
        return 0
    return 1

def pb_registry_command(w:mutbuf, mode:u64) -> u64:
    if iv_get(w, P_REG_PREVIOUS) == IV_MAX:
        return iv_bad(w, 916)
    iv_put(w, P_REG_ACTIVE, iv_get(w, P_REG_PREVIOUS) + 1)
    fill_range(w, PB_REG_COMMAND, 128, 0)
    iv_put(w, PB_REG_COMMAND, PB_REG_MAGIC)
    iv_put(w, PB_REG_COMMAND + 8, mode)
    iv_put(w, PB_REG_COMMAND + 16, iv_get(w, P_INV))
    iv_put(w, PB_REG_COMMAND + 24, iv_get(w, P_CALL))
    iv_put(w, PB_REG_COMMAND + 32, iv_get(w, P_REG_ACTIVE))
    iv_put(w, PB_REG_COMMAND + 40, iv_get(w, P_REG_SEQUENCE))
    iv_put(w, PB_REG_COMMAND + 48, iv_get(w, P_GRAPH_LEASE))
    iv_put(w, PB_REG_COMMAND + 56, iv_get(w, P_GRAPH_BYTES))
    iv_put(w, PB_REG_COMMAND + 96, iv_get(w, P_ORIGIN))
    if mode == 6:
        iv_put(w, PB_REG_COMMAND + 80, iv_get(w, P_ARG))
    return 1

def pb_registry_callback(r:readbuf, w:mutbuf, action:u64) -> u64:
    if length(r) != 384 or iv_word(r, 72) != 768 or iv_word(r, 80) != 1:
        return iv_bad(w, 917)
    if iv_word(r, 88) != 256 or iv_word(r, 96) != 0 or iv_word(r, 104) != 0:
        return iv_bad(w, 918)
    if iv_word(r, 128) != PB_REG_EVENT or iv_word(r, 136) != action:
        return iv_bad(w, 919)
    if iv_word(r, 144) != iv_get(w, P_INV) or iv_word(r, 152) != iv_get(w, P_CALL):
        return iv_bad(w, 920)
    if iv_get(w, P_REG_SEQUENCE) == IV_MAX or iv_word(r, 160) != iv_get(w, P_REG_SEQUENCE) + 1:
        return iv_bad(w, 921)
    if iv_word(r, 168) != iv_get(w, P_REG_ACTIVE):
        return iv_bad(w, 922)
    if iv_word(r, 176) != iv_get(w, P_GRAPH_LEASE) or iv_word(r, 184) != iv_get(w, P_GRAPH_BYTES):
        return iv_bad(w, 923)
    if iv_word(r, 320) != iv_get(w, P_ISSUED) or iv_word(r, 328) != iv_get(w, P_ORIGIN):
        return iv_bad(w, 924)
    if iv_word(r, 344) != 0 or iv_word(r, 352) != 0 or iv_word(r, 376) != 0:
        return iv_bad(w, 925)
    return 1

def pb_start_reserve(w:mutbuf) -> u32:
    if pb_registry_command(w, 2) == 0:
        return pb_fail(w, 926)
    iv_put(w, P_KERNEL, 2)
    iv_put(w, P_PHASE, 30)
    return pb_event(w, 2)

def pb_import_command(w:mutbuf) -> u32:
    fill_range(w, PB_REG_COMMAND, 128, 0)
    iv_put(w, PB_REG_COMMAND, PB_REG_MAGIC)
    iv_put(w, PB_REG_COMMAND + 8, 3)
    iv_put(w, PB_REG_COMMAND + 16, iv_get(w, P_INV))
    iv_put(w, PB_REG_COMMAND + 24, iv_get(w, P_CALL))
    iv_put(w, PB_REG_COMMAND + 32, iv_get(w, P_REG_ACTIVE))
    iv_put(w, PB_REG_COMMAND + 40, iv_get(w, P_REG_SEQUENCE))
    iv_put(w, PB_REG_COMMAND + 48, iv_get(w, P_GRAPH_LEASE))
    iv_put(w, PB_REG_COMMAND + 56, iv_get(w, P_GRAPH_BYTES))
    iv_put(w, PB_REG_COMMAND + 64, iv_get(w, P_PACKET_BYTES))
    iv_put(w, PB_REG_COMMAND + 96, iv_get(w, P_ORIGIN))
    iv_put(w, PB_REG_COMMAND + 104, iv_get(w, P_PACKET_BYTES))
    iv_put(w, P_PHASE, 35)
    return pb_event(w, 2)
'''
