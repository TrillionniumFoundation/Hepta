"""Actual initializer request through native program/assembly child, NEW unexecuted r2.

The only supported input sequence is the original constructor's P16, P17, P18.
Its P16 document is produced by the source-bound initializer value owner mode 4.
This route does not define a new arbitrary-object public capture boundary.
"""
BODY=r'''
def pb_initializer(r:readbuf, w:mutbuf) -> u64:
    size = iv_word(r, 80)
    if iv_word(r, 72) != 2304 or size < 8192 or size > length(r) - 128:
        return iv_bad(w, 930)
    if iv_word(r, 88) != 768 or iv_word(r, 96) != 256 or iv_word(r, 104) != 0:
        return iv_bad(w, 931)
    if length(r) - 128 - size != 256:
        return iv_bad(w, 932)
    base = 128
    event = base + 2048
    if iv_word(r, base + I_MAGIC) != IS_STATE or iv_word(r, base + I_STATUS) != 2:
        return iv_bad(w, 933)
    peer = iv_word(r, base + I_PEER)
    if peer < 16 or peer > 18 or iv_word(r, base + I_PHASE) != peer + 48:
        return iv_bad(w, 934)
    if iv_word(r, base + I_INV) != iv_get(w, P_INV) or iv_word(r, base + I_CALL) != iv_get(w, P_CALL):
        return iv_bad(w, 935)
    sequence = iv_word(r, base + I_SEQ)
    if sequence == 0 or sequence == IV_MAX or iv_word(r, base + I_PENDING) != sequence:
        return iv_bad(w, 936)
    if iv_word(r, base + I_HAVE_REPLY) != 0 or iv_word(r, base + I_BAD_REASON) != 0:
        return iv_bad(w, 937)
    origin = iv_word(r, base + I_SOURCE_LEASE)
    digits = iv_word(r, base + I_DIGITS)
    if origin == 0 or digits > 4294967295 or (digits != 0 and digits < 640):
        return iv_bad(w, 938)
    if iv_word(r, base + I_SOURCE_ROOT) == 0 or iv_word(r, base + I_OP) != 0:
        return iv_bad(w, 939)
    argument = iv_word(r, base + I_ARG0)
    if argument <= PB_HANDLE:
        return iv_bad(w, 940)
    if peer == 17 and argument != iv_word(r, base + I_PROGRAM):
        return iv_bad(w, 941)
    if peer == 18 and argument != iv_word(r, base + I_ASSEMBLY):
        return iv_bad(w, 942)
    index = 1
    while index < 6:
        if iv_word(r, base + I_ARG0 + index * 8) != 0:
            return iv_bad(w, 943)
        index = index + 1
    if iv_word(r, base + I_VIEW_OWNER) != 0 or iv_word(r, base + I_VIEW_AT) != 0:
        return iv_bad(w, 944)
    if iv_word(r, base + I_VIEW_BYTES) != 0 or iv_word(r, base + I_LITERAL_BYTES) != 0:
        return iv_bad(w, 945)
    index = 0
    while index < 32:
        expected = 0
        if index == 0:
            expected = IS_EVENT
        elif index == 1:
            expected = 2
        elif index == 2:
            expected = iv_get(w, P_INV)
        elif index == 3:
            expected = iv_get(w, P_CALL)
        elif index == 4 or index == 7:
            expected = sequence
        elif index == 5:
            expected = peer + 48
        elif index == 6:
            expected = peer
        elif index == 9:
            expected = origin
        elif index == 10:
            expected = iv_word(r, base + I_SOURCE_ROOT)
        elif index == 11:
            expected = digits
        elif index == 12:
            expected = iv_word(r, base + I_STORE)
        elif index == 14:
            expected = argument
        elif index == 23:
            expected = 5120
        elif index == 25:
            expected = 4096
        elif index == 26:
            expected = 512
        if iv_word(r, event + index * 8) != expected:
            return iv_bad(w, 946)
        index = index + 1
    iv_put(w, P_PENDING, sequence)
    iv_put(w, P_PEER, peer)
    iv_put(w, P_ORIGIN, origin)
    iv_put(w, P_DIGITS, digits)
    iv_put(w, P_ARG, argument)
    iv_put(w, P_INITIALIZER_BYTES, size)
    iv_put(w, P_CHILD_MODE, peer - 15)
    copy_bytes(w, r, PB_INITIALIZER_EVENT, event, 256)
    copy_bytes(w, r, PB_ORIGINAL_DIGEST, base + I_DIGEST0, 32)
    return 1

def pb_begin(s:readbuf, r:readbuf, w:mutbuf) -> u32:
    if iv_get(w, P_MAGIC) != 0 or iv_word(r, 40) != 0:
        return pb_fail(w, 947)
    index = 0
    while index < PB_MIN:
        if byte(w, index) != 0:
            return pb_fail(w, 948)
        index = index + 1
    iv_put(w, P_MAGIC, PB_STATE)
    iv_put(w, P_KERNEL, 1)
    iv_put(w, P_INV, iv_word(r, 16))
    iv_put(w, P_CALL, iv_word(r, 24))
    iv_put(w, P_LEASE, iv_word(r, 32))
    if iv_shape(s, w, 0, length(s), iv_word(r, 48)) == 0:
        return pb_fail(w, 949)
    iv_put(w, P_GRAPH_LEASE, iv_word(s, 8))
    iv_put(w, P_GRAPH_BYTES, length(s))
    copy_bytes(w, s, PB_SOURCE_HEADER, 0, 64)
    if pb_initializer(r, w) == 0 or rs_previous_registry(s, r, w) == 0:
        return pb_fail(w, 950)
    if iv_get(w, P_ARG) > PB_HANDLE + iv_get(w, P_ISSUED):
        return pb_fail(w, 951)
    if iv_get(w, P_PEER) == 16:
        prior = 128 + iv_get(w, P_INITIALIZER_BYTES)
        if iv_word(r, prior) != RS_PURE_EVENT or iv_word(r, prior + 8) != 4:
            return pb_fail(w, 952)
        if iv_word(r, prior + 48) != 9 or iv_word(r, prior + 72) != 2 or iv_word(r, prior + 240) != 4:
            return pb_fail(w, 953)
        if iv_word(r, prior + 192) != iv_get(w, P_ARG):
            return pb_fail(w, 954)
    if pb_registry_command(w, 6) == 0:
        return pb_fail(w, 955)
    iv_put(w, P_PHASE, 10)
    return pb_event(w, 2)

def pb_program_command(w:mutbuf) -> u32:
    at = PB_DATA
    fill_range(w, at, 64, 0)
    iv_put(w, at, PB_PROGRAM_COMMAND)
    iv_put(w, at + 8, iv_get(w, P_LEASE))
    iv_put(w, at + 16, iv_get(w, P_PENDING))
    iv_put(w, at + 24, iv_get(w, P_DIGITS))
    iv_put(w, at + 32, iv_get(w, P_INPUT_BYTES))
    iv_put(w, at + 40, iv_get(w, P_CHILD_MODE))
    iv_put(w, at + 48, iv_get(w, P_INPUT_TREE))
    iv_put(w, P_INPUT_AT, PB_DATA + 64)
    iv_put(w, P_SAVE_END, PB_DATA + 64 + iv_get(w, P_INPUT_BYTES))
    iv_put(w, P_PHASE, 20)
    return pb_event(w, 4)

def pb_record_input(s:readbuf, w:mutbuf, at:u64, size:u64) -> u64:
    if size < 64 or iv_word(s, at) != PB_RECORD or iv_word(s, at + 8) != 1:
        return iv_bad(w, 956)
    if iv_word(s, at + 16) != iv_get(w, P_INV) or iv_word(s, at + 24) != iv_get(w, P_CALL):
        return iv_bad(w, 957)
    old_pending = iv_word(s, at + 32)
    if old_pending == 0 or old_pending >= iv_get(w, P_PENDING):
        return iv_bad(w, 958)
    input_size = iv_word(s, at + 40)
    tree = iv_word(s, at + 48)
    frame_size = iv_word(s, at + 56)
    if tree > 1 or input_size > size - 64 or frame_size != size - 64 - input_size:
        return iv_bad(w, 959)
    frame = at + 64 + input_size
    if frame_size < 513 or iv_word(s, frame) != PB_PROGRAM_RESULT or iv_word(s, frame + 8) != 1:
        return iv_bad(w, 960)
    old_lease = iv_word(s, frame + 16)
    if old_lease == 0 or old_lease > IV_MAX - 3 or iv_word(s, frame + 24) != old_pending:
        return iv_bad(w, 961)
    if iv_word(s, frame + 32) != 1 or iv_word(s, frame + 40) != 1:
        return iv_bad(w, 962)
    if iv_word(s, frame + 48) != 0 or iv_word(s, frame + 56) != 0 or iv_word(s, frame + 64) != 0:
        return iv_bad(w, 963)
    core_size = iv_word(s, frame + 104)
    if core_size == 0 or core_size > 8388608 or frame_size != 512 + core_size:
        return iv_bad(w, 964)
    if iv_word(s, frame + 72) != frame_size or iv_word(s, frame + 80) != 256 or iv_word(s, frame + 88) != 256:
        return iv_bad(w, 965)
    if iv_word(s, frame + 96) != 512 or iv_word(s, frame + 112) != 512 or iv_word(s, frame + 120) != core_size:
        return iv_bad(w, 966)
    index = 128
    while index < 256:
        if iv_word(s, frame + index) != 0:
            return iv_bad(w, 967)
        index = index + 8
    receipt = frame + 256
    if iv_word(s, receipt) != PB_PROGRAM_RECEIPT or iv_word(s, receipt + 8) != 1:
        return iv_bad(w, 968)
    if iv_word(s, receipt + 16) != old_lease + 2 or iv_word(s, receipt + 24) == 0:
        return iv_bad(w, 969)
    kind = iv_word(s, receipt + 32)
    version = iv_word(s, receipt + 40)
    core_version = iv_word(s, receipt + 48)
    canonical_input = iv_word(s, receipt + 56)
    if kind > 1 or iv_word(s, receipt + 64) != core_size:
        return iv_bad(w, 970)
    if version == 0 or version > choose(kind == 0, 8, 4):
        return iv_bad(w, 1090)
    if canonical_input == 0 or canonical_input > 8388608:
        return iv_bad(w, 1091)
    if kind == 0 and core_version != version:
        return iv_bad(w, 1092)
    if kind == 1 and core_version != choose(version == 1, 6, choose(version == 4, 8, 7)):
        return iv_bad(w, 1093)
    if iv_word(s, receipt + 72) != choose(kind == 0, 0, canonical_input):
        return iv_bad(w, 1094)
    if iv_word(s, receipt + 144) != 45 or iv_word(s, receipt + 152) != choose(kind == 0, 0, 52):
        return iv_bad(w, 1095)
    if iv_word(s, receipt + 160) != 56 or iv_word(s, receipt + 168) != 256:
        return iv_bad(w, 1096)
    if iv_word(s, receipt + 176) != 1 or iv_word(s, receipt + 184) != kind:
        return iv_bad(w, 1097)
    index = 192
    while index < 256:
        if iv_word(s, receipt + index) != 0:
            return iv_bad(w, 1098)
        index = index + 8
    index = 0
    while index < 32:
        if byte(s, receipt + 112 + index) != byte(w, PB_ORIGINAL_DIGEST + index):
            return iv_bad(w, 971)
        index = index + 1
    iv_put(w, P_INPUT_TREE, choose(kind == 0, 0, tree))
    iv_put(w, P_INPUT_BYTES, choose(kind == 0, core_size, input_size))
    iv_put(w, P_INPUT_AT, choose(kind == 0, frame + 512, at + 64))
    return 1

def pb_borrow(s:readbuf, r:readbuf, w:mutbuf) -> u32:
    if iv_get(w, P_PHASE) != 10 or pb_registry_callback(r, w, 5) == 0:
        return pb_fail(w, 972)
    root = iv_word(r, 288)
    if root == 0 or root > iv_word(s, 16) or iv_word(r, 296) != iv_get(w, P_ARG):
        return pb_fail(w, 973)
    if iv_word(r, 192) != 0 or iv_word(r, 264) != 1 or iv_word(r, 272) != 0 or iv_word(r, 280) != length(s):
        return pb_fail(w, 974)
    if iv_word(r, 304) != 1024 or iv_word(r, 312) != 64 or iv_word(r, 336) != iv_word(s, 16):
        return pb_fail(w, 975)
    if iv_word(r, 360) != iv_get(w, P_REG_ACTIVE) or iv_word(r, 368) != 0:
        return pb_fail(w, 976)
    iv_put(w, P_BORROW_ROOT, root)
    peer = iv_get(w, P_PEER)
    if peer != 16:
        node = root * 64
        expected_kind = choose(peer == 17, 9, 4)
        if iv_word(s, node) != expected_kind or iv_valid_node(s, w, 0, length(s), root) == 0:
            return pb_fail(w, 977)
        at = iv_word(s, node + 8)
        size = iv_word(s, node + 16)
        if peer == 17:
            if pb_record_input(s, w, at, size) == 0:
                return pb_fail(w, 978)
            at = iv_get(w, P_INPUT_AT)
            size = iv_get(w, P_INPUT_BYTES)
        else:
            iv_put(w, P_INPUT_TREE, 0)
            iv_put(w, P_INPUT_BYTES, size)
        if size > IV_MAX - PB_DATA - 64:
            return pb_fail(w, 979)
        if pb_require(r, w, PB_DATA + 64 + size) == 0:
            return pb_event(w, 1)
        copy_bytes(w, s, PB_DATA + 64, at, size)
    iv_put(w, P_REG_SEQUENCE, iv_word(r, 160))
    iv_put(w, P_REG_PREVIOUS, iv_word(r, 360))
    if peer != 16:
        return pb_program_command(w)
    fill_range(w, PB_WIRE_COMMAND, 64, 0)
    iv_put(w, PB_WIRE_COMMAND, PB_WIRE_MAGIC)
    iv_put(w, PB_WIRE_COMMAND + 8, iv_get(w, P_GRAPH_LEASE))
    iv_put(w, PB_WIRE_COMMAND + 16, iv_get(w, P_PENDING))
    iv_put(w, PB_WIRE_COMMAND + 24, root)
    iv_put(w, PB_WIRE_COMMAND + 32, 8388608)
    iv_put(w, PB_WIRE_COMMAND + 48, iv_get(w, P_DIGITS))
    iv_put(w, P_WIRE_ROLE, 2)
    iv_put(w, P_WIRE_NEED, 32768)
    iv_put(w, P_PHASE, 11)
    return pb_event(w, 3)

def pb_wire(r:readbuf, w:mutbuf) -> u32:
    phase = iv_get(w, P_PHASE)
    if phase < 11 or phase > 13 or iv_word(r, 72) != 128 or iv_word(r, 80) != iv_get(w, P_WIRE_ROLE):
        return pb_fail(w, 980)
    extent = iv_word(r, 88)
    if extent < 32768 or extent != length(r) - 128 or iv_word(r, 96) != 0 or iv_word(r, 104) != 0:
        return pb_fail(w, 981)
    if iv_word(r, 128) != PB_WIRE_EVENT:
        return pb_fail(w, 982)
    index = 1
    while index < 7:
        if iv_word(r, 128 + (index + 1) * 8) != iv_get(w, PB_WIRE_COMMAND + index * 8):
            return pb_fail(w, 983)
        index = index + 1
    if iv_word(r, 192) != 0 or iv_word(r, 200) != 0 or iv_word(r, 248) != 0:
        return pb_fail(w, 984)
    action = iv_word(r, 136)
    if action == 1:
        if iv_word(r, 208) <= extent or iv_word(r, 216) != 0 or iv_word(r, 224) != 0 or iv_word(r, 232) != 0:
            return pb_fail(w, 985)
        iv_put(w, P_WIRE_NEED, iv_word(r, 208))
        iv_put(w, P_PHASE, 12)
        return pb_event(w, 3)
    if action == 2:
        if iv_get(w, P_WIRE_ROLE) != 2 or iv_word(r, 232) != 2:
            return pb_fail(w, 986)
        if iv_word(r, 216) != 0 or iv_word(r, 224) != 0:
            return pb_fail(w, 987)
        iv_put(w, P_WIRE_ROLE, 3)
        iv_put(w, P_WIRE_NEED, extent)
        iv_put(w, P_PHASE, 12)
        return pb_event(w, 3)
    if action != 0 or iv_get(w, P_WIRE_ROLE) != 3 or iv_word(r, 232) != 0:
        return pb_fail(w, 988)
    at = iv_word(r, 216)
    size = iv_word(r, 224)
    if at > extent or size > extent - at or size > 8388608:
        return pb_fail(w, 989)
    iv_put(w, P_PHASE, 13)
    if pb_require(r, w, PB_DATA + 64 + size) == 0:
        return pb_event(w, 1)
    copy_bytes(w, r, PB_DATA + 64, 128 + at, size)
    iv_put(w, P_INPUT_BYTES, size)
    iv_put(w, P_INPUT_TREE, 1)
    return pb_program_command(w)

def pb_result_failure(r:readbuf, w:mutbuf, at:u64, size:u64, mode:u64) -> u64:
    domain = iv_word(r, at + 48)
    if domain < 1 or domain > 2 or (mode == 1 and domain != 1) or (mode == 3 and domain != 2):
        return iv_bad(w, 995)
    if domain == 1:
        if iv_word(r, at + 56) != 0 or iv_word(r, at + 64) != 0:
            return iv_bad(w, 996)
    elif iv_word(r, at + 56) < 1 or iv_word(r, at + 56) > 3:
        return iv_bad(w, 997)
    index = 80
    while index < 112:
        if iv_word(r, at + index) != 0:
            return iv_bad(w, 998)
        index = index + 8
    if iv_word(r, at + 112) != 256 or iv_word(r, at + 120) != size - 256:
        return iv_bad(w, 999)
    code_size = iv_word(r, at + 136)
    if size < 264 or iv_word(r, at + 128) != 256 or code_size < 6 or code_size > size - 258:
        return iv_bad(w, 1000)
    if byte(r, at + 256 + code_size) != 58 or byte(r, at + 257 + code_size) != 32:
        return iv_bad(w, 1099)
    if byte(r, at + 256) != 69 or byte(r, at + 257) != 95 or byte(r, at + 258) != 72:
        return iv_bad(w, 1100)
    if byte(r, at + 259) != 73 or byte(r, at + 260) != 65 or byte(r, at + 261) != 95:
        return iv_bad(w, 1101)
    index = 0
    while index < code_size:
        ch = byte(r, at + 256 + index)
        if (ch < 65 or ch > 90) and ch != 95 and (ch < 48 or ch > 57):
            return iv_bad(w, 1102)
        index = index + 1
    return 1

def pb_result_success(r:readbuf, w:mutbuf, at:u64, size:u64, mode:u64) -> u64:
    kind = iv_word(r, at + 40)
    domain = iv_word(r, at + 48)
    if kind != choose(mode == 2, 2, 1) or domain != 0:
        return iv_bad(w, 1001)
    if iv_word(r, at + 56) != 0 or iv_word(r, at + 64) != 0:
        return iv_bad(w, 1002)
    core = iv_word(r, at + 104)
    if size < 512 or core == 0 or core > 8388608 or core > size - 512:
        return iv_bad(w, 1003)
    if iv_word(r, at + 80) != 256 or iv_word(r, at + 88) != 256 or iv_word(r, at + 96) != 512:
        return iv_bad(w, 1004)
    if iv_word(r, at + 128) != 0 or iv_word(r, at + 136) != 0:
        return iv_bad(w, 1005)
    if kind == 1:
        if size != 512 + core or iv_word(r, at + 112) != 512 or iv_word(r, at + 120) != core:
            return iv_bad(w, 1006)
    else:
        if iv_word(r, at + 112) != 512 + core or iv_word(r, at + 120) != size - 512 - core:
            return iv_bad(w, 1007)
    receipt = at + 256
    if iv_word(r, receipt) != PB_PROGRAM_RECEIPT or iv_word(r, receipt + 8) != 1:
        return iv_bad(w, 1008)
    if iv_word(r, receipt + 16) != iv_get(w, P_LEASE) + 2 or iv_word(r, receipt + 24) == 0:
        return iv_bad(w, 1009)
    source_kind = iv_word(r, receipt + 32)
    version = iv_word(r, receipt + 40)
    core_version = iv_word(r, receipt + 48)
    input_size = iv_word(r, receipt + 56)
    if source_kind > 1 or input_size == 0 or input_size > 8388608 or iv_word(r, receipt + 64) != core:
        return iv_bad(w, 1010)
    if version == 0 or version > choose(source_kind == 0, 8, 4):
        return iv_bad(w, 1011)
    if source_kind == 0 and core_version != version:
        return iv_bad(w, 1012)
    if source_kind == 1:
        expected_version = choose(version == 1, 6, choose(version == 4, 8, 7))
        if core_version != expected_version:
            return iv_bad(w, 1013)
    if iv_word(r, receipt + 72) != choose(source_kind == 0, 0, input_size):
        return iv_bad(w, 1014)
    if iv_word(r, receipt + 144) != 45 or iv_word(r, receipt + 152) != choose(source_kind == 0, 0, 52):
        return iv_bad(w, 1015)
    if iv_word(r, receipt + 160) != 56 or iv_word(r, receipt + 168) != 256:
        return iv_bad(w, 1016)
    if iv_word(r, receipt + 176) != 1 or iv_word(r, receipt + 184) != source_kind:
        return iv_bad(w, 1017)
    index = 192
    while index < 256:
        if iv_word(r, receipt + index) != 0:
            return iv_bad(w, 1018)
        index = index + 8
    if iv_get(w, P_PEER) == 17:
        index = 0
        while index < 32:
            if byte(r, receipt + 112 + index) != byte(w, PB_ORIGINAL_DIGEST + index):
                return iv_bad(w, 1103)
            index = index + 1
    iv_put(w, P_CORE_BYTES, core)
    iv_put(w, P_TEXT_BYTES, choose(kind == 2, iv_word(r, at + 120), 0))
    return 1

def pb_result_frame(r:readbuf, w:mutbuf, at:u64, size:u64) -> u64:
    if size < 256 or at > length(r) or size > length(r) - at:
        return iv_bad(w, 990)
    if iv_word(r, at) != PB_PROGRAM_RESULT or iv_word(r, at + 8) != 1:
        return iv_bad(w, 991)
    if iv_word(r, at + 16) != iv_get(w, P_LEASE) or iv_word(r, at + 24) != iv_get(w, P_PENDING):
        return iv_bad(w, 992)
    mode = iv_get(w, P_CHILD_MODE)
    kind = iv_word(r, at + 40)
    domain = iv_word(r, at + 48)
    if iv_word(r, at + 32) != mode or iv_word(r, at + 72) != size:
        return iv_bad(w, 993)
    index = 144
    while index < 256:
        if iv_word(r, at + index) != 0:
            return iv_bad(w, 994)
        index = index + 8
    if kind == 4:
        if pb_result_failure(r, w, at, size, mode) == 0:
            return 0
    else:
        if pb_result_success(r, w, at, size, mode) == 0:
            return 0
    iv_put(w, P_RESULT_KIND, kind)
    iv_put(w, P_ERROR_DOMAIN, domain)
    return 1

def pb_program_result(r:readbuf, w:mutbuf) -> u32:
    if iv_get(w, P_PHASE) != 20 or iv_word(r, 80) != 4 or iv_word(r, 104) != 0:
        return pb_fail(w, 1019)
    out_size = iv_word(r, 88)
    err_size = iv_word(r, 96)
    if out_size > length(r) - 128 or err_size != length(r) - 128 - out_size or err_size < 128:
        return pb_fail(w, 1020)
    status = iv_word(r, 72)
    if status != 0 and status != 2:
        return pb_fail(w, 1021)
    term = 128 + out_size
    frame = choose(status == 0, 128, term + 128)
    size = choose(status == 0, out_size, err_size - 128)
    if status == 0:
        if err_size != 128:
            return pb_fail(w, 1022)
    elif out_size != 0:
        return pb_fail(w, 1023)
    if pb_result_frame(r, w, frame, size) == 0:
        return pb_fail(w, 1024)
    if (iv_get(w, P_RESULT_KIND) == 4) != (status == 2):
        return pb_fail(w, 1025)
    index = 0
    while index < 16:
        expected = 0
        if index == 0:
            expected = PB_CARRIER_EVENT
        elif index == 1:
            expected = 7
        elif index == 2:
            expected = iv_get(w, P_LEASE)
        elif index == 3:
            expected = iv_word(r, term + 24)
            if expected == 0:
                return pb_fail(w, 1026)
        elif index == 4:
            expected = choose(status == 2, 1, 0)
        elif index == 5 or index == 10:
            expected = iv_get(w, P_ERROR_DOMAIN)
        elif index == 6:
            expected = 30
        elif index == 8 or index == 11:
            expected = size
        elif index == 9:
            expected = iv_get(w, P_RESULT_KIND)
        if iv_word(r, term + index * 8) != expected:
            return pb_fail(w, 1027)
        index = index + 1
    end = iv_get(w, P_SAVE_END)
    if size > IV_MAX - end:
        return pb_fail(w, 1028)
    if pb_require(r, w, end + size) == 0:
        return pb_event(w, 1)
    copy_bytes(w, r, end, frame, size)
    iv_put(w, P_FRAME_AT, end)
    iv_put(w, P_FRAME_BYTES, size)
    iv_put(w, P_SAVE_END, end + size)
    if status == 2:
        fill_range(w, PB_REPLY, 256, 0)
        iv_put(w, PB_REPLY, IS_REPLY)
        iv_put(w, PB_REPLY + 8, iv_get(w, P_INV))
        iv_put(w, PB_REPLY + 16, iv_get(w, P_CALL))
        iv_put(w, PB_REPLY + 24, iv_get(w, P_PENDING))
        iv_put(w, PB_REPLY + 32, iv_get(w, P_PEER))
        iv_put(w, PB_REPLY + 40, 1)
        iv_put(w, PB_REPLY + 96, iv_get(w, P_LEASE))
        iv_put(w, PB_REPLY + 104, 256)
        iv_put(w, PB_REPLY + 112, size)
        iv_put(w, PB_REPLY + 120, 256 + size)
        if pb_local_copy(w, PB_REPLY + 256, end, size) == 0:
            return pb_fail(w, 1029)
        iv_put(w, P_REPLY_BYTES, 256 + size)
        iv_put(w, P_PHASE, 90)
        return pb_event(w, 0)
    iv_put(w, P_CORE_AT, end + 512)
    iv_put(w, P_TEXT_AT, end + 512 + iv_get(w, P_CORE_BYTES))
    iv_put(w, P_ITEM, 0)
    return pb_start_reserve(w)

def initializer_program_input(s:readbuf, r:readbuf, w:mutbuf) -> u32:
    if length(w) < PB_MIN:
        return IV_BAD
    if iv_get(w, P_PHASE) == 99 or iv_get(w, P_PHASE) == 90:
        return IV_BAD
    if length(s) < 64 or pb_header(s, r, w, 1) == 0:
        return pb_fail(w, 1030)
    mode = iv_word(r, 8)
    if mode == 1:
        return pb_begin(s, r, w)
    if mode == 2:
        return pb_borrow(s, r, w)
    if mode == 3:
        return pb_wire(r, w)
    if mode == 4:
        return pb_program_result(r, w)
    return pb_fail(w, 1031)
'''
