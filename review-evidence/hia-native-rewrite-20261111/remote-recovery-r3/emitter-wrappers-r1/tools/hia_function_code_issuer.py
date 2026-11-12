"""HIA Function tape -> actual stateful Code command/ACK continuation.
The fixed caller only holds immutable inputs, grows peers, and forwards views.
"""
import ast
def magic(value):return int.from_bytes(value.encode("ascii"),"little")
TAPE_OWNER_SHA="e61fcb540bbe51a0e85dc09cd9afa3813b6ba24d6739da2912269c10ce1522eb"
CONSTANTS=dict(MAX=(1<<64)-1,BAD=0xfffffffd,GROW=0xfffffffe,MIN_WORK=8192,CONFIG=128,
 COMMAND_AT=4096,TAPE_BASE=12288,TAPE_RECORDS=12544,STATE=magic("HIAFLIS1"),
 INPUT=magic("HIAFLC01"),EVENT=magic("HIAFLIE1"),TAPE=magic("HIAFLT01"),
 TAPE_EVENT=magic("HIAFLE01"),CODE_COMMAND=magic("HIAXCC01"),CODE_GRAPH=magic("HIAXGR01"),
 CODE_EVENT=magic("HIAXCE01"),RESULT=magic("HIAFLR01"),TEXT_AT=2048)
PERSIST=("MAGIC","LEASE","REQUEST","CONTROL_SEQ","CODE_LEASE","CODE_SEQ","FRAME_LEASE","FRAME_REQUEST",
 "FN_INDEX","TAPE_BYTES","TAPE_CAP","RECORD_N","RECORD_INDEX","SERIAL","CODE_BYTES","LABEL_N","FIX_N","REL_N",
 "BEGIN","BEGUN","OP","PACKET_N","PHASE","POISON")
SCRATCH=("BAD","NEED","ACTION","DOMAIN","ERROR","LEASE","REQUEST","CTRL","CODE_LEASE","CODE_SEQ",
 "INDEX","SERIAL","CODE_N","LABEL_N","FIX_N","REL_N","BEGIN","BEGUN","ROW","OP","ARGC","EFFECT",
 "POOL","POOL_N","RECORD_N","TAPE_USED","RESULT_AT","RESULT_N","NAME_AT","NAME_N","FINAL_SERIAL",
 "RETURN","PACKET_N","PEER_CODE","PEER_WORK")
CONSTANTS.update({"P_"+name:256+8*i for i,name in enumerate(PERSIST)})
CONSTANTS.update({"S_"+name:512+8*i for i,name in enumerate(SCRATCH)})
MESSAGE="E_HIA_PROGRAM_LIMIT: direct code exceeds the 16 MiB text budget"
CONSTANTS["MESSAGE_N"]=len(MESSAGE)
BODY=r'''
def issue_function(s:readbuf, r:readbuf, w:mutbuf) -> u32:
    if length(w) < MIN_WORK:
        if length(w) >= 512:
            put(w, P_POISON, 1)
        return BAD
    fill_range(w, 0, 128, 0)
    fill_range(w, 512, 512, 0)
    message(w)
    if get(w, P_POISON) != 0:
        fail(w, 1)
    elif control(s, r, w) != 0:
        if get(w, CONFIG + 40) == 1:
            begin(s, r, w)
        else:
            acknowledge_code(s, r, w)
        if get(w, S_BAD) == 0:
            plan_result(s, r, w)
    if get(w, S_BAD) != 0:
        issue_event(w, 3)
        return BAD
    if get(w, S_NEED) > length(w):
        issue_event(w, 4)
        return GROW
    commit(s, r, w)
    if get(w, S_BAD) != 0:
        issue_event(w, 3)
        return BAD
    issue_event(w, get(w, S_ACTION))
    return 128

def word(s:readbuf, at:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(s, at + i) << (i * 8))
        i = i + 1
    return value

def get(w:mutbuf, at:u64) -> u64:
    value = 0
    i = 0
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

def fail(w:mutbuf, reason:u64) -> u64:
    if get(w, S_BAD) == 0:
        put(w, S_BAD, reason)
    put(w, P_POISON, 1)
    return 0

def control(s:readbuf, r:readbuf, w:mutbuf) -> u64:
    if get(w, CONFIG) != INPUT or get(w, CONFIG + 8) != 1:
        return fail(w, 2)
    if get(w, CONFIG + 16) == 0 or get(w, CONFIG + 24) == 0 or get(w, CONFIG + 32) == 0:
        return fail(w, 3)
    kind = get(w, CONFIG + 40)
    if kind != 1 and kind != 2:
        return fail(w, 4)
    if get(w, CONFIG + 48) == 0 or get(w, CONFIG + 56) == 0 or get(w, CONFIG + 64) == 0 or get(w, CONFIG + 72) == 0:
        return fail(w, 5)
    if get(w, CONFIG + 112) != 0 or get(w, CONFIG + 120) != 0:
        return fail(w, 6)
    put(w, S_LEASE, get(w, CONFIG + 16))
    put(w, S_REQUEST, get(w, CONFIG + 24))
    put(w, S_CTRL, get(w, CONFIG + 32))
    put(w, S_CODE_LEASE, get(w, CONFIG + 48))
    put(w, S_CODE_SEQ, get(w, CONFIG + 56))
    put(w, S_RETURN, get(w, CONFIG + 104))
    if get(w, S_RETURN) != 128 and get(w, S_RETURN) != GROW:
        return fail(w, 7)
    if tape(s, w) == 0 or peer(r, w) == 0:
        return 0
    if kind == 1:
        if get(w, S_CTRL) != 1:
            return fail(w, 8)
        at = 256
        while at < 448:
            if get(w, at) != 0:
                return fail(w, 9)
            at = at + 8
    else:
        if get(w, P_MAGIC) != STATE or get(w, P_PHASE) != 1 or get(w, P_POISON) != 0:
            return fail(w, 10)
        if get(w, P_CONTROL_SEQ) == MAX or get(w, S_CTRL) != get(w, P_CONTROL_SEQ) + 1:
            return fail(w, 11)
        if get(w, S_LEASE) != get(w, P_LEASE) or get(w, S_REQUEST) != get(w, P_REQUEST):
            return fail(w, 12)
        if get(w, S_CODE_LEASE) != get(w, P_CODE_LEASE) or get(w, S_CODE_SEQ) != get(w, P_CODE_SEQ):
            return fail(w, 13)
        if get(w, CONFIG + 64) != get(w, P_FRAME_LEASE) or get(w, CONFIG + 72) != get(w, P_FRAME_REQUEST) or get(w, CONFIG + 80) != get(w, P_FN_INDEX):
            return fail(w, 14)
        if get(w, S_TAPE_USED) != get(w, P_TAPE_BYTES) or length(s) != get(w, P_TAPE_CAP) or get(w, S_RECORD_N) != get(w, P_RECORD_N):
            return fail(w, 15)
    return 1

def tape(s:readbuf, w:mutbuf) -> u64:
    if length(s) < TAPE_RECORDS:
        return fail(w, 16)
    if word(s, 0) != TAPE_EVENT or word(s, 8) != 1 or word(s, 16) != 0:
        return fail(w, 17)
    if word(s, 24) != get(w, CONFIG + 64) or word(s, 32) != get(w, CONFIG + 72) or word(s, 40) != get(w, CONFIG + 80):
        return fail(w, 18)
    used = word(s, 48)
    if used < TAPE_RECORDS or used > length(s) or used != get(w, CONFIG + 88):
        return fail(w, 19)
    if word(s, 56) != TAPE_BASE or word(s, 64) != used - TAPE_BASE or word(s, 96) != 0 or word(s, 104) != 0 or word(s, 112) != 0 or word(s, 120) != 0:
        return fail(w, 20)
    if word(s, TAPE_BASE) != TAPE or word(s, TAPE_BASE + 8) != 1 or word(s, TAPE_BASE + 16) != get(w, CONFIG + 64):
        return fail(w, 21)
    if word(s, TAPE_BASE + 24) != get(w, CONFIG + 72) or word(s, TAPE_BASE + 32) != get(w, CONFIG + 80):
        return fail(w, 22)
    count = word(s, TAPE_BASE + 40)
    if count < 2 or count > (used - TAPE_RECORDS) >> 7 or word(s, TAPE_BASE + 48) != TAPE_RECORDS:
        return fail(w, 23)
    pool = TAPE_RECORDS + count * 128
    if word(s, TAPE_BASE + 56) != pool or word(s, TAPE_BASE + 64) != used - pool or word(s, TAPE_BASE + 72) != used:
        return fail(w, 24)
    if word(s, 72) != count or word(s, 80) != word(s, TAPE_BASE + 88) or word(s, 88) != word(s, TAPE_BASE + 112):
        return fail(w, 25)
    if word(s, TAPE_BASE + 80) == 0 or word(s, TAPE_BASE + 80) > word(s, TAPE_BASE + 88):
        return fail(w, 26)
    at = TAPE_BASE + 144
    while at < TAPE_RECORDS:
        if word(s, at) != 0:
            return fail(w, 27)
        at = at + 8
    put(w, S_POOL, pool)
    put(w, S_POOL_N, used - pool)
    put(w, S_RECORD_N, count)
    put(w, S_TAPE_USED, used)
    put(w, S_NAME_AT, word(s, TAPE_BASE + 96))
    put(w, S_NAME_N, word(s, TAPE_BASE + 104))
    put(w, S_FINAL_SERIAL, word(s, TAPE_BASE + 88))
    if string_span(w, get(w, S_NAME_AT), get(w, S_NAME_N)) == 0:
        return 0
    return 1

def string_span(w:mutbuf, at:u64, count:u64) -> u64:
    if at < get(w, S_POOL) or at > get(w, S_TAPE_USED) or count > get(w, S_TAPE_USED) - at:
        return fail(w, 28)
    return 1

def peer(r:readbuf, w:mutbuf) -> u64:
    if length(r) < 128 or get(w, CONFIG + 96) < 64:
        return fail(w, 29)
    if word(r, 0) != CODE_EVENT or word(r, 8) != 1 or word(r, 24) != get(w, S_CODE_LEASE) or word(r, 32) != get(w, S_CODE_SEQ):
        return fail(w, 30)
    action = word(r, 16)
    if action > 2 or word(r, 40) > 44 or word(r, 120) != 0:
        return fail(w, 31)
    if word(r, 72) > get(w, CONFIG + 96) - 64:
        return fail(w, 32)
    if action == 1:
        if get(w, S_RETURN) != GROW or word(r, 48) != 0 or word(r, 104) != 0 or word(r, 112) != 0:
            return fail(w, 33)
        if word(r, 56) <= get(w, CONFIG + 96) and word(r, 64) <= length(r):
            return fail(w, 34)
    else:
        if get(w, S_RETURN) != 128 or word(r, 56) > get(w, CONFIG + 96) or word(r, 64) > length(r):
            return fail(w, 35)
        if action == 0:
            if word(r, 48) != 0 or word(r, 104) != 0 or word(r, 112) != 0:
                return fail(w, 36)
        else:
            if word(r, 48) == 0 or word(r, 48) > 16 or word(r, 112) == 0:
                return fail(w, 37)
            at = word(r, 104)
            size = word(r, 112)
            if at > length(r) or size > length(r) - at:
                return fail(w, 38)
    put(w, S_CODE_N, word(r, 72))
    put(w, S_LABEL_N, word(r, 80))
    put(w, S_FIX_N, word(r, 88))
    put(w, S_REL_N, word(r, 96))
    put(w, S_PEER_CODE, word(r, 56))
    put(w, S_PEER_WORK, word(r, 64))
    return 1

def begin(s:readbuf, r:readbuf, w:mutbuf) -> u64:
    if word(r, 16) != 0:
        return fail(w, 39)
    put(w, S_SERIAL, word(s, TAPE_BASE + 80))
    put(w, S_INDEX, 0)
    put(w, S_ACTION, 1)
    return 0

def current_record(s:readbuf, w:mutbuf, index:u64) -> u64:
    if index >= get(w, S_RECORD_N):
        return fail(w, 40)
    at = TAPE_RECORDS + index * 128
    opcode = word(s, at)
    argc = word(s, at + 8)
    serial = word(s, at + 16)
    effect = word(s, at + 24)
    if opcode < 2 or opcode == 3 or opcode > 44 or argc != arity(opcode):
        return fail(w, 41)
    if serial < get(w, S_SERIAL) or serial > get(w, S_FINAL_SERIAL):
        return fail(w, 42)
    if effect > 3 or (effect != 0 and opcode != 2):
        return fail(w, 43)
    if index == 0 and (effect != 1 or serial != word(s, TAPE_BASE + 80)):
        return fail(w, 44)
    if index != 0 and effect == 1:
        return fail(w, 45)
    if index + 1 == get(w, S_RECORD_N):
        if effect != 3 or serial != get(w, S_FINAL_SERIAL):
            return fail(w, 46)
    elif effect == 3:
        return fail(w, 47)
    j = 32 + argc * 24
    while j < 128:
        if word(s, at + j) != 0:
            return fail(w, 48)
        j = j + 8
    put(w, S_ROW, at)
    put(w, S_OP, opcode)
    put(w, S_ARGC, argc)
    put(w, S_EFFECT, effect)
    put(w, S_SERIAL, serial)
    return 1

def acknowledge_code(s:readbuf, r:readbuf, w:mutbuf) -> u64:
    put(w, S_SERIAL, get(w, P_SERIAL))
    put(w, S_BEGIN, get(w, P_BEGIN))
    put(w, S_BEGUN, get(w, P_BEGUN))
    put(w, S_INDEX, get(w, P_RECORD_INDEX))
    if current_record(s, w, get(w, S_INDEX)) == 0:
        return 0
    if get(w, S_OP) != get(w, P_OP) or word(r, 40) != get(w, P_OP) or get(w, S_SERIAL) != get(w, P_SERIAL):
        return fail(w, 49)
    if get(w, S_CODE_N) < get(w, P_CODE_BYTES) or get(w, S_LABEL_N) < get(w, P_LABEL_N) or get(w, S_FIX_N) < get(w, P_FIX_N) or get(w, S_REL_N) < get(w, P_REL_N):
        return fail(w, 50)
    action = word(r, 16)
    if action == 1:
        if get(w, S_CODE_N) != get(w, P_CODE_BYTES) or get(w, S_LABEL_N) != get(w, P_LABEL_N) or get(w, S_FIX_N) != get(w, P_FIX_N) or get(w, S_REL_N) != get(w, P_REL_N):
            return fail(w, 51)
        put(w, S_ACTION, 5)
        return 0
    if action == 2:
        put(w, S_ACTION, 2)
        put(w, S_DOMAIN, 1)
        put(w, S_ERROR, word(r, 48))
        put(w, S_RESULT_AT, word(r, 104))
        put(w, S_RESULT_N, word(r, 112))
        return 0
    effect = get(w, S_EFFECT)
    if effect == 1:
        if get(w, S_BEGUN) != 0:
            return fail(w, 52)
        put(w, S_BEGIN, get(w, S_CODE_N))
        put(w, S_BEGUN, 1)
    elif get(w, S_BEGUN) != 1:
        return fail(w, 53)
    if effect == 2 and get(w, S_CODE_N) > 16777216:
        put(w, S_ACTION, 2)
        put(w, S_DOMAIN, 2)
        put(w, S_ERROR, 1)
        put(w, S_RESULT_AT, TEXT_AT)
        put(w, S_RESULT_N, MESSAGE_N)
        return 0
    put(w, S_INDEX, get(w, S_INDEX) + 1)
    put(w, S_ACTION, choose(get(w, S_INDEX) == get(w, S_RECORD_N), 0, 1))
    return 0

def magnitude_bytes(value:u64) -> u64:
    count = 0
    while value != 0:
        count = count + 1
        value = value >> 8
    return count

def plan_packet(s:readbuf, w:mutbuf) -> u64:
    if current_record(s, w, get(w, S_INDEX)) == 0:
        return 0
    row = get(w, S_ROW)
    total = 128 + (1 + get(w, S_ARGC)) * 64 + get(w, S_ARGC) * 8
    i = 0
    while i < get(w, S_ARGC):
        kind = word(s, row + 32 + i * 24)
        value = word(s, row + 40 + i * 24)
        size = word(s, row + 48 + i * 24)
        if kind < 2:
            if size != 0 or (kind == 1 and value == 0):
                return fail(w, 54)
            size = magnitude_bytes(value)
        elif kind == 2:
            if string_span(w, value, size) == 0:
                return 0
            j = 0
            while j < size:
                if byte(s, value + j) > 127:
                    return fail(w, 55)
                j = j + 1
        else:
            return fail(w, 56)
        if size > MAX - total:
            return fail(w, 57)
        total = total + size
        i = i + 1
    if total > MAX - COMMAND_AT:
        return fail(w, 58)
    put(w, S_PACKET_N, total)
    put(w, S_NEED, COMMAND_AT + total)
    return 0

def plan_result(s:readbuf, r:readbuf, w:mutbuf) -> u64:
    action = get(w, S_ACTION)
    if action == 1:
        if get(w, S_CODE_SEQ) == MAX:
            return fail(w, 59)
        plan_packet(s, w)
    elif action == 5:
        if get(w, P_PACKET_N) == 0 or get(w, P_PACKET_N) > length(w) - COMMAND_AT:
            return fail(w, 60)
        put(w, S_PACKET_N, get(w, P_PACKET_N))
        put(w, S_NEED, MIN_WORK)
    elif action == 2:
        size = get(w, S_RESULT_N)
        if size > MAX - COMMAND_AT:
            return fail(w, 61)
        put(w, S_NEED, COMMAND_AT + size)
    elif action == 0:
        if get(w, S_BEGUN) != 1 or get(w, S_CODE_N) < get(w, S_BEGIN):
            return fail(w, 62)
        if get(w, S_NAME_N) > MAX - COMMAND_AT - 320:
            return fail(w, 63)
        put(w, S_NEED, COMMAND_AT + 320 + get(w, S_NAME_N))
    else:
        return fail(w, 64)
    return 0

def graph_node(w:mutbuf, index:u64, kind:u64, at:u64, size:u64, first:u64, count:u64, identity:u64, aux:u64) -> u64:
    row = COMMAND_AT + 128 + (index - 1) * 64
    put(w, row, kind)
    put(w, row + 8, at)
    put(w, row + 16, size)
    put(w, row + 24, first)
    put(w, row + 32, count)
    put(w, row + 40, identity)
    put(w, row + 48, aux)
    return 0

def packet(s:readbuf, w:mutbuf) -> u64:
    at = COMMAND_AT
    total = get(w, S_PACKET_N)
    count = get(w, S_ARGC)
    fill_range(w, at, total, 0)
    put(w, at, CODE_COMMAND)
    put(w, at + 8, 1)
    put(w, at + 16, get(w, S_CODE_LEASE))
    put(w, at + 24, get(w, S_CODE_SEQ) + 1)
    put(w, at + 32, get(w, S_OP))
    put(w, at + 40, total - 64)
    put(w, at + 48, 1)
    put(w, at + 64, CODE_GRAPH)
    put(w, at + 72, get(w, S_CODE_LEASE))
    put(w, at + 80, count + 1)
    put(w, at + 88, 1)
    put(w, at + 96, count)
    pool = 128 + (count + 1) * 64 + count * 8
    put(w, at + 104, total - pool)
    put(w, at + 112, total - 64)
    graph_node(w, 1, 5, 0, 0, 0, count, 1, 0)
    row = get(w, S_ROW)
    i = 0
    while i < count:
        put(w, at + 128 + (count + 1) * 64 + i * 8, i + 2)
        kind = word(s, row + 32 + i * 24)
        value = word(s, row + 40 + i * 24)
        size = word(s, row + 48 + i * 24)
        if kind == 2:
            graph_node(w, i + 2, 4, pool - 64, size, 0, 0, 0, size)
            copy_bytes(w, s, at + pool, value, size)
        else:
            size = magnitude_bytes(value)
            graph_node(w, i + 2, 2, pool - 64, size, 0, 0, 0, kind)
            j = 0
            while j < size:
                store(w, at + pool + j, (value >> (j * 8)) & 255)
                j = j + 1
        pool = pool + size
        i = i + 1
    if pool != total:
        return fail(w, 65)
    put(w, S_CODE_SEQ, get(w, S_CODE_SEQ) + 1)
    return 0

def copy_local(w:mutbuf, target:u64, source:u64, count:u64) -> u64:
    i = 0
    while i < count:
        store(w, target + i, byte(w, source + i))
        i = i + 1
    return 0

def result(s:readbuf, w:mutbuf) -> u64:
    fill_range(w, COMMAND_AT, 320 + get(w, S_NAME_N), 0)
    put(w, COMMAND_AT, RESULT)
    put(w, COMMAND_AT + 8, 1)
    put(w, COMMAND_AT + 16, get(w, S_LEASE))
    put(w, COMMAND_AT + 24, get(w, S_REQUEST))
    put(w, COMMAND_AT + 32, get(w, CONFIG + 80))
    put(w, COMMAND_AT + 40, get(w, S_CODE_LEASE))
    put(w, COMMAND_AT + 48, get(w, S_CODE_SEQ))
    put(w, COMMAND_AT + 56, get(w, S_BEGIN))
    put(w, COMMAND_AT + 64, get(w, S_CODE_N))
    put(w, COMMAND_AT + 72, word(s, TAPE_BASE + 112))
    put(w, COMMAND_AT + 80, get(w, S_SERIAL))
    put(w, COMMAND_AT + 88, COMMAND_AT + 256)
    put(w, COMMAND_AT + 96, get(w, S_NAME_N))
    copy_bytes(w, s, COMMAND_AT + 256, get(w, S_NAME_AT), get(w, S_NAME_N))
    start = COMMAND_AT + 256 + get(w, S_NAME_N)
    function_prefix(w, start)
    end = decimal(w, start + 16, get(w, CONFIG + 80))
    put(w, COMMAND_AT + 104, start)
    put(w, COMMAND_AT + 112, end - start)
    put(w, COMMAND_AT + 120, end - COMMAND_AT)
    put(w, S_RESULT_N, end - COMMAND_AT)
    return 0

def commit(s:readbuf, r:readbuf, w:mutbuf) -> u64:
    action = get(w, S_ACTION)
    if action == 1:
        packet(s, w)
    elif action == 2:
        if get(w, S_DOMAIN) == 1:
            copy_bytes(w, r, COMMAND_AT, get(w, S_RESULT_AT), get(w, S_RESULT_N))
        else:
            copy_local(w, COMMAND_AT, get(w, S_RESULT_AT), get(w, S_RESULT_N))
    elif action == 0:
        result(s, w)
    if get(w, S_BAD) != 0:
        return 0
    put(w, P_MAGIC, STATE)
    put(w, P_LEASE, get(w, S_LEASE))
    put(w, P_REQUEST, get(w, S_REQUEST))
    put(w, P_CONTROL_SEQ, get(w, S_CTRL))
    put(w, P_CODE_LEASE, get(w, S_CODE_LEASE))
    put(w, P_CODE_SEQ, get(w, S_CODE_SEQ))
    put(w, P_FRAME_LEASE, get(w, CONFIG + 64))
    put(w, P_FRAME_REQUEST, get(w, CONFIG + 72))
    put(w, P_FN_INDEX, get(w, CONFIG + 80))
    put(w, P_TAPE_BYTES, get(w, S_TAPE_USED))
    put(w, P_TAPE_CAP, length(s))
    put(w, P_RECORD_N, get(w, S_RECORD_N))
    put(w, P_RECORD_INDEX, get(w, S_INDEX))
    put(w, P_SERIAL, get(w, S_SERIAL))
    put(w, P_CODE_BYTES, get(w, S_CODE_N))
    put(w, P_LABEL_N, get(w, S_LABEL_N))
    put(w, P_FIX_N, get(w, S_FIX_N))
    put(w, P_REL_N, get(w, S_REL_N))
    put(w, P_BEGIN, get(w, S_BEGIN))
    put(w, P_BEGUN, get(w, S_BEGUN))
    put(w, P_OP, get(w, S_OP))
    put(w, P_PACKET_N, get(w, S_PACKET_N))
    put(w, P_PHASE, choose(action == 0, 2, choose(action == 2, 3, 1)))
    return 0

def issue_event(w:mutbuf, action:u64) -> u64:
    put(w, 0, EVENT)
    put(w, 8, 1)
    put(w, 16, action)
    put(w, 24, get(w, S_LEASE))
    put(w, 32, get(w, S_REQUEST))
    put(w, 40, get(w, S_CTRL))
    put(w, 48, get(w, CONFIG + 80))
    put(w, 56, get(w, S_CODE_LEASE))
    put(w, 64, get(w, S_CODE_SEQ))
    put(w, 72, get(w, S_INDEX))
    put(w, 80, get(w, S_SERIAL))
    if action == 1 or action == 5:
        put(w, 88, COMMAND_AT)
        put(w, 96, get(w, S_PACKET_N))
    elif action == 0 or action == 2:
        put(w, 88, COMMAND_AT)
        put(w, 96, get(w, S_RESULT_N))
    if action == 2:
        put(w, 104, get(w, S_DOMAIN))
        put(w, 112, get(w, S_ERROR))
    elif action == 4:
        put(w, 104, get(w, S_NEED))
    elif action == 5:
        put(w, 104, get(w, S_PEER_CODE))
        put(w, 112, get(w, S_PEER_WORK))
    put(w, 120, get(w, S_BAD))
    return 0
'''

ARITIES=(3,1,0,1,1,1,2,1,2,2,3,3,3,3,3,2,2,2,2,2,2,2,3,3,3,2,2,2,2,2,2,1,1,1,1,1,1,0,2,3,1,1,0,0,0,0)
def source(frame_owner):
    constants=dict(CONSTANTS)
    original={n.name:n for n in ast.parse(frame_owner.BODY).body}
    helpers=[original["divide"],original["decimal"]]
    fields=["def message(w:mutbuf)->u64:"]
    value=MESSAGE.encode("ascii")
    for i in range(0,len(value),8):
        fields.append("    put(w,%d,%d)"%(constants["TEXT_AT"]+i,int.from_bytes(value[i:i+8].ljust(8,b"\0"),"little")))
    fields.append("    return 0")
    prefix=["def function_prefix(w:mutbuf,start:u64)->u64:"]
    value=b"__hia_native_fn_"
    assert len(value)==16
    for i in range(0,len(value),8):
        prefix.append("    put(w,start+%d,%d)"%(i,int.from_bytes(value[i:i+8],"little")))
    prefix.append("    return 0")
    arity=["def arity(op:u64)->u64:"]
    for count in (0,1,2,3):
        indices=[i for i,n in enumerate(ARITIES) if n==count]
        arity+=["    if "+" or ".join("op == "+str(i) for i in indices)+":","        return "+str(count)]
    arity.append("    return 4")
    nodes=ast.parse(BODY+"\n"+"\n".join(fields+prefix+arity)).body+helpers
    names={n.name:n for n in nodes};assert len(names)==len(nodes)
    for node in nodes:
        if node.name in ("word","get"):
            arg="s" if node.name=="word" else "w"
            node.body=ast.parse("return "+" | ".join("(byte(%s,at+%d)<<%d)"%(arg,i,8*i) for i in range(8))).body
        elif node.name=="put":
            node.body=ast.parse("\n".join("store(w,at+%d,(value>>%d)&255)"%(i,8*i) for i in range(8))+"\nreturn 0").body
    return "\n".join(ast.unparse(ast.fix_missing_locations(n)) for n in nodes)+"\n",constants,dict(
        status="NEW_AUTHORING_UNEXECUTED",scope="NATIVE_FUNCTION_TAPE_ACTUAL_CODE_CONTINUATION",
        tape_owner_sha256=TAPE_OWNER_SHA,actual_Code_event_and_workspace_required=True,
        actual_code_and_work_capacities_required=True,all_command_graph_bytes_native=True,
        exact_per_command_serial_and_offset_commit=True,Code_GROW_same_command_no_duplicate_commit=True,
        own_GROW_same_immutable_inputs_before_commit=True,block_text_budget=16777216,
        checked_Core_and_actual_frame_and_tape_issuers_required=True,header_is_authentication=False,
        whole_Emitter=False,whole_backend=False,installed=False,cold=False)
