"""Actual program receipt -> issued initializer Graph values, NEW r1.

The source is the current private registry Graph. Callbacks are copied from the
actual registry, source-bound decoder and DataGraph executions. Core bytes and
the original program input stay in this route until every result is imported.
No Graph handle or record grants namespace authority.
"""
BODY=r'''
def pb_atom_header(w:mutbuf, size:u64, kind:u64, chars:u64) -> u64:
    at = iv_get(w, P_PACKET_AT)
    fill_range(w, at, 128, 0)
    iv_put(w, at, IV_GRAPH)
    iv_put(w, at + 8, iv_get(w, P_FOREIGN))
    iv_put(w, at + 16, 1)
    iv_put(w, at + 24, 1)
    iv_put(w, at + 40, size)
    iv_put(w, at + 48, 128 + size)
    iv_put(w, at + 64, kind)
    iv_put(w, at + 72, 128)
    iv_put(w, at + 80, size)
    iv_put(w, at + 112, chars)
    iv_put(w, P_PACKET_BYTES, 128 + size)
    return 1

def pb_record_packet(w:mutbuf) -> u64:
    at = iv_get(w, P_PACKET_AT)
    input_size = iv_get(w, P_INPUT_BYTES)
    frame_size = iv_get(w, P_FRAME_BYTES)
    pb_atom_header(w, 64 + input_size + frame_size, 9, 0)
    record = at + 128
    iv_put(w, record, PB_RECORD)
    iv_put(w, record + 8, 1)
    iv_put(w, record + 16, iv_get(w, P_INV))
    iv_put(w, record + 24, iv_get(w, P_CALL))
    iv_put(w, record + 32, iv_get(w, P_PENDING))
    iv_put(w, record + 40, input_size)
    iv_put(w, record + 48, iv_get(w, P_INPUT_TREE))
    iv_put(w, record + 56, frame_size)
    if pb_local_copy(w, record + 64, iv_get(w, P_INPUT_AT), input_size) == 0:
        return 0
    return pb_local_copy(w, record + 64 + input_size, iv_get(w, P_FRAME_AT), frame_size)

def pb_hex_packet(w:mutbuf) -> u64:
    pb_atom_header(w, 64, 4, 64)
    output = iv_get(w, P_PACKET_AT) + 128
    input = iv_get(w, P_FRAME_AT) + 256 + 112
    index = 0
    while index < 32:
        value = byte(w, input + index)
        high = value >> 4
        low = value & 15
        store(w, output + index * 2, choose(high < 10, high + 48, high + 87))
        store(w, output + index * 2 + 1, choose(low < 10, low + 48, low + 87))
        index = index + 1
    return 1

def pb_decoder_start(w:mutbuf) -> u32:
    size = iv_get(w, P_CORE_BYTES)
    bound = ((size + 1) >> 1) + 1
    if bound > 262144:
        bound = 262144
    output = 64 + bound * 56 + size
    if output < 2208:
        output = 2208
    keys = (size >> 2) + 1
    if keys > 262144:
        keys = 262144
    slots = 2
    while slots < keys * 2:
        slots = slots << 1
    workspace = slots * 8
    if workspace < 3248:
        workspace = 3248
    iv_put(w, P_DECODER_OUT, output)
    iv_put(w, P_DECODER_WORK, workspace)
    fill_range(w, PB_DECODER_CONFIG, 64, 0)
    iv_put(w, PB_DECODER_CONFIG + 48, 262144)
    iv_put(w, PB_DECODER_CONFIG + 56, 64)
    iv_put(w, P_PHASE, 31)
    return pb_event(w, 5)

def pb_reserved(s:readbuf, r:readbuf, w:mutbuf) -> u32:
    if iv_get(w, P_PHASE) != 30 or pb_registry_callback(r, w, 2) == 0:
        return pb_fail(w, 1040)
    foreign = iv_word(r, 200)
    output = iv_word(r, 208)
    if foreign <= iv_get(w, P_GRAPH_LEASE) or foreign == IV_MAX or output != foreign + 1:
        return pb_fail(w, 1041)
    index = 0
    while index < 32:
        expected = 0
        if index == 0:
            expected = PB_REG_EVENT
        elif index == 1:
            expected = 2
        elif index == 2:
            expected = iv_get(w, P_INV)
        elif index == 3:
            expected = iv_get(w, P_CALL)
        elif index == 4:
            expected = iv_get(w, P_REG_SEQUENCE) + 1
        elif index == 5:
            expected = iv_get(w, P_REG_ACTIVE)
        elif index == 6:
            expected = iv_get(w, P_GRAPH_LEASE)
        elif index == 7:
            expected = length(s)
        elif index == 9:
            expected = foreign
        elif index == 10:
            expected = output
        elif index == 24:
            expected = iv_get(w, P_ISSUED)
        elif index == 25:
            expected = iv_get(w, P_ORIGIN)
        elif index == 26:
            expected = iv_word(s, 16)
        elif index == 29:
            expected = iv_get(w, P_REG_PREVIOUS)
        elif index == 30:
            expected = 10
        if iv_word(r, 128 + index * 8) != expected:
            return pb_fail(w, 1042)
        index = index + 1
    item = iv_get(w, P_ITEM)
    peer = iv_get(w, P_PEER)
    if item > choose(peer == 17, 1, 2):
        return pb_fail(w, 1043)
    packet_size = 0
    if peer == 17:
        packet_size = 128 + iv_get(w, P_TEXT_BYTES)
    elif item == 0:
        input_size = iv_get(w, P_INPUT_BYTES)
        frame_size = iv_get(w, P_FRAME_BYTES)
        if input_size > IV_MAX - 192 or frame_size > IV_MAX - 192 - input_size:
            return pb_fail(w, 1044)
        packet_size = 192 + input_size + frame_size
    elif item == 2:
        packet_size = 192
    end = iv_get(w, P_SAVE_END)
    if packet_size > IV_MAX - end:
        return pb_fail(w, 1045)
    if pb_require(r, w, end + packet_size) == 0:
        return pb_event(w, 1)
    iv_put(w, P_FOREIGN, foreign)
    iv_put(w, P_OUTPUT, output)
    iv_put(w, P_REG_SEQUENCE, iv_word(r, 160))
    iv_put(w, P_OLD_NODES, iv_word(s, 16))
    iv_put(w, P_OLD_EDGES, iv_word(s, 32))
    iv_put(w, P_OLD_POOL, iv_word(s, 40))
    iv_put(w, P_PACKET_AT, end)
    if peer == 17:
        size = iv_get(w, P_TEXT_BYTES)
        chars = 0
        if item == 0:
            chars = pb_utf8(w, iv_get(w, P_TEXT_AT), size)
            if chars == IV_MAX:
                return pb_fail(w, 1046)
        pb_atom_header(w, size, choose(item == 0, 4, 9), chars)
        if pb_local_copy(w, end + 128, iv_get(w, P_TEXT_AT), size) == 0:
            return pb_fail(w, 1047)
    elif item == 0:
        if pb_record_packet(w) == 0:
            return pb_fail(w, 1048)
    elif item == 1:
        return pb_decoder_start(w)
    else:
        pb_hex_packet(w)
    if iv_get(w, P_PACKET_BYTES) != packet_size:
        return pb_fail(w, 1049)
    return pb_import_command(w)

def pb_decoder_header(r:readbuf, w:mutbuf) -> u64:
    if iv_word(r, 80) != 5 or iv_word(r, 104) != 0:
        return iv_bad(w, 1050)
    output = iv_word(r, 88)
    workspace = iv_word(r, 96)
    if output != iv_get(w, P_DECODER_OUT) or workspace != iv_get(w, P_DECODER_WORK):
        return iv_bad(w, 1051)
    if output > length(r) - 128 or workspace != length(r) - 128 - output:
        return iv_bad(w, 1052)
    size = iv_word(r, 72)
    if size < 64 or size > output or iv_word(r, 128) != PB_DATA_ARENA:
        return iv_bad(w, 1053)
    nodes = iv_word(r, 136)
    if nodes == 0 or nodes > 262144 or iv_word(r, 144) != 64 + nodes * 56:
        return iv_bad(w, 1054)
    if 64 + nodes * 56 > size or iv_word(r, 152) != size or iv_word(r, 160) != size:
        return iv_bad(w, 1055)
    if iv_word(r, 168) != iv_get(w, P_CORE_BYTES) or iv_word(r, 176) != 1 or iv_word(r, 184) != 0:
        return iv_bad(w, 1056)
    if iv_word(r, 128 + output + 48) != 262144 or iv_word(r, 128 + output + 56) != 64:
        return iv_bad(w, 1057)
    return 1

def pb_decoded(r:readbuf, w:mutbuf) -> u32:
    if iv_get(w, P_PHASE) != 31 or iv_get(w, P_ITEM) != 1 or iv_get(w, P_PEER) == 17:
        return pb_fail(w, 1058)
    if pb_decoder_header(r, w) == 0:
        return pb_fail(w, 1059)
    size = iv_word(r, 72)
    at = iv_get(w, P_SAVE_END)
    if size > IV_MAX - at:
        return pb_fail(w, 1060)
    if pb_require(r, w, at + size) == 0:
        return pb_event(w, 1)
    copy_bytes(w, r, at, 128, size)
    iv_put(w, P_ARENA_AT, at)
    iv_put(w, P_ARENA_BYTES, size)
    fill_range(w, PB_DG_CONFIG, 128, 0)
    iv_put(w, PB_DG_CONFIG, PB_DG_COMMAND)
    iv_put(w, PB_DG_CONFIG + 8, iv_get(w, P_INV))
    iv_put(w, PB_DG_CONFIG + 16, iv_get(w, P_CALL))
    iv_put(w, PB_DG_CONFIG + 24, iv_get(w, P_LEASE) + 1)
    iv_put(w, PB_DG_CONFIG + 32, iv_get(w, P_LEASE) + 2)
    iv_put(w, PB_DG_CONFIG + 40, iv_get(w, P_FOREIGN))
    iv_put(w, PB_DG_CONFIG + 48, iv_get(w, P_DIGITS))
    iv_put(w, PB_DG_CONFIG + 56, size)
    iv_put(w, PB_DG_CONFIG + 64, iv_get(w, P_CORE_BYTES))
    iv_put(w, P_DG_SEQUENCE, 0)
    iv_put(w, P_DG_NEED, 4096)
    iv_put(w, P_DG_STARTED, 0)
    iv_put(w, P_PHASE, 32)
    return pb_event(w, 6)

def pb_data_graph_header(r:readbuf, w:mutbuf) -> u64:
    extent = length(r) - 128
    if iv_word(r, 72) != 2240 or iv_word(r, 80) != 6 or iv_word(r, 88) != extent:
        return iv_bad(w, 1061)
    if iv_word(r, 96) != 0 or iv_word(r, 104) != 0 or extent < iv_get(w, P_DG_NEED) or extent < 4096:
        return iv_bad(w, 1062)
    if iv_word(r, 128 + 512) != PB_DG_STATE:
        return iv_bad(w, 1063)
    index = 0
    while index < 128:
        expected = byte(w, PB_DG_CONFIG + index)
        if byte(r, 128 + 128 + index) != expected or byte(r, 128 + 1024 + index) != expected:
            return iv_bad(w, 1064)
        index = index + 1
    index = 0
    while index < 64:
        if byte(r, 128 + 1152 + index) != byte(w, iv_get(w, P_ARENA_AT) + index):
            return iv_bad(w, 1065)
        index = index + 1
    event = 128 + 2048
    if iv_word(r, event) != PB_DG_EVENT:
        return iv_bad(w, 1066)
    if iv_word(r, event + 16) != iv_get(w, P_INV) or iv_word(r, event + 24) != iv_get(w, P_CALL):
        return iv_bad(w, 1067)
    if iv_get(w, P_DG_SEQUENCE) == IV_MAX or iv_word(r, event + 32) != iv_get(w, P_DG_SEQUENCE) + 1:
        return iv_bad(w, 1068)
    if iv_word(r, event + 40) != iv_get(w, P_FOREIGN) or iv_word(r, event + 48) != iv_get(w, P_LEASE) + 1:
        return iv_bad(w, 1069)
    if iv_word(r, event + 56) != iv_get(w, P_LEASE) + 2 or iv_word(r, event + 136) != iv_get(w, P_DIGITS):
        return iv_bad(w, 1070)
    if iv_word(r, event + 88) != 0 or iv_word(r, event + 96) != 0:
        return iv_bad(w, 1071)
    if iv_word(r, event + 112) != 0 or iv_word(r, event + 120) != 0 or iv_word(r, event + 128) != 0:
        return iv_bad(w, 1072)
    if iv_word(r, event + 152) != 0 or iv_word(r, event + 160) != 0 or iv_word(r, event + 176) != 0 or iv_word(r, event + 184) != 0:
        return iv_bad(w, 1073)
    if iv_word(r, 128 + 520) != iv_word(r, event + 168) or iv_word(r, 128 + 528) != iv_word(r, event + 32):
        return iv_bad(w, 1074)
    action = iv_word(r, event + 8)
    if action == 1:
        phase = iv_word(r, event + 168)
        if phase != 10 and phase != 20:
            return iv_bad(w, 1075)
        if iv_word(r, event + 64) <= extent or iv_word(r, event + 72) != 0 or iv_word(r, event + 80) != 0:
            return iv_bad(w, 1076)
    elif action == 0:
        if iv_word(r, event + 64) != 0 or iv_word(r, event + 168) != 90:
            return iv_bad(w, 1077)
        at = iv_word(r, event + 72)
        size = iv_word(r, event + 80)
        if at < 4096 or at > extent or size > extent - at:
            return iv_bad(w, 1078)
        if iv_shape(r, w, 128 + at, size, iv_get(w, P_FOREIGN)) == 0:
            return 0
        if iv_word(r, 128 + at + 24) != 1:
            return iv_bad(w, 1079)
    else:
        return iv_bad(w, 1080)
    return 1

def pb_data_graph(r:readbuf, w:mutbuf) -> u32:
    if iv_get(w, P_PHASE) != 32 or pb_data_graph_header(r, w) == 0:
        return pb_fail(w, 1081)
    event = 128 + 2048
    if iv_word(r, event + 8) == 1:
        iv_put(w, P_DG_SEQUENCE, iv_word(r, event + 32))
        iv_put(w, P_DG_STARTED, 1)
        iv_put(w, P_DG_NEED, iv_word(r, event + 64))
        return pb_event(w, 6)
    source = iv_word(r, event + 72)
    size = iv_word(r, event + 80)
    at = iv_get(w, P_ARENA_AT)
    if iv_get(w, P_ARENA_BYTES) > IV_MAX - at:
        return pb_fail(w, 1082)
    at = at + iv_get(w, P_ARENA_BYTES)
    if size > IV_MAX - at:
        return pb_fail(w, 1083)
    if pb_require(r, w, at + size) == 0:
        return pb_event(w, 1)
    copy_bytes(w, r, at, 128 + source, size)
    iv_put(w, P_DG_SEQUENCE, iv_word(r, event + 32))
    iv_put(w, P_DG_STARTED, 1)
    iv_put(w, P_PACKET_AT, at)
    iv_put(w, P_PACKET_BYTES, size)
    return pb_import_command(w)

def pb_complete_reply(w:mutbuf) -> u32:
    peer = iv_get(w, P_PEER)
    fill_range(w, PB_REPLY, 256, 0)
    iv_put(w, PB_REPLY, IS_REPLY)
    iv_put(w, PB_REPLY + 8, iv_get(w, P_INV))
    iv_put(w, PB_REPLY + 16, iv_get(w, P_CALL))
    iv_put(w, PB_REPLY + 24, iv_get(w, P_PENDING))
    iv_put(w, PB_REPLY + 32, peer)
    iv_put(w, PB_REPLY + 48, choose(peer == 17, 12, 11))
    iv_put(w, PB_REPLY + 64, iv_get(w, P_HANDLE0))
    iv_put(w, PB_REPLY + 72, iv_get(w, P_HANDLE1))
    iv_put(w, PB_REPLY + 80, choose(peer == 17, 0, iv_get(w, P_HANDLE2)))
    iv_put(w, PB_REPLY + 120, 256)
    if peer != 17:
        if pb_local_copy(w, PB_REPLY + 128, iv_get(w, P_FRAME_AT) + 368, 32) == 0:
            return pb_fail(w, 1084)
    iv_put(w, P_REPLY_BYTES, 256)
    iv_put(w, P_PHASE, 90)
    return pb_event(w, 0)

def pb_bound(s:readbuf, r:readbuf, w:mutbuf) -> u32:
    if iv_get(w, P_PHASE) != 35 or iv_word(r, 96) != 0 or iv_word(r, 104) != 0:
        return pb_fail(w, 1085)
    if rs_bound_header(s, r, w) == 0 or rs_bound_bytes(s, w) == 0:
        return pb_fail(w, 1086)
    handle = PB_HANDLE + iv_get(w, P_ISSUED) + 1
    item = iv_get(w, P_ITEM)
    if item > choose(iv_get(w, P_PEER) == 17, 1, 2):
        return pb_fail(w, 1087)
    iv_put(w, P_HANDLE0 + item * 8, handle)
    iv_put(w, P_REG_SEQUENCE, iv_word(r, 160))
    iv_put(w, P_REG_PREVIOUS, iv_get(w, P_REG_ACTIVE))
    iv_put(w, P_GRAPH_LEASE, iv_get(w, P_OUTPUT))
    iv_put(w, P_GRAPH_BYTES, length(s))
    iv_put(w, P_ISSUED, iv_get(w, P_ISSUED) + 1)
    copy_bytes(w, s, PB_SOURCE_HEADER, 0, 64)
    if item == choose(iv_get(w, P_PEER) == 17, 1, 2):
        return pb_complete_reply(w)
    iv_put(w, P_ITEM, item + 1)
    return pb_start_reserve(w)

def initializer_program_output(s:readbuf, r:readbuf, w:mutbuf) -> u32:
    if length(w) < PB_MIN:
        return IV_BAD
    if iv_get(w, P_PHASE) == 99 or iv_get(w, P_PHASE) == 90:
        return IV_BAD
    if length(s) < 64 or pb_header(s, r, w, 2) == 0:
        return pb_fail(w, 1088)
    mode = iv_word(r, 8)
    if mode == 5:
        return pb_reserved(s, r, w)
    if mode == 6:
        return pb_decoded(r, w)
    if mode == 7:
        return pb_data_graph(r, w)
    if mode == 8:
        return pb_bound(s, r, w)
    return pb_fail(w, 1089)
'''
