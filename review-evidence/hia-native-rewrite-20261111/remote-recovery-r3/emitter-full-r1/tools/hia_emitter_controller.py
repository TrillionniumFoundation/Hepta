"""Persistent HIA _Emitter orchestration, with only fixed buffer/call mechanics.
The caller captures an actually admitted Core, checked machine plan and original
byte-export object Graph. This is a development component, not the public build
frontend or an admission substitute. No caller chooses instructions or symbols.
"""
import ast
import copy
def magic(s):return int.from_bytes(s.encode("ascii"),"little")
COMMON_SHA="fe63327671ea51ca950b955512a0f574d706176a4a8d050e3f8f12c83ef5e3a1"
PREPARE_SHA="662e4dfc95c70c43495554dfd01cb3042176044bd8f63d10413e29a00cc7e1f2"
FINISH_SHA="66b6480a3f6f37985fc4d97c4d54de848bb7fcd247591f04542df7e94570337c"
CONSTANTS=dict(MAX=(1<<64)-1,BAD=0xfffffffd,GROW=0xfffffffe,MIN_WORK=1<<20,
 INIT=magic("HIAEMB01"),LOWER_MAGIC=magic("HIAEMS01"),RESULT=magic("HIAMER01"),
 GRAPH=magic("HIAGRF01"),REGISTRY=magic("HIAEMR01"),
 PREP_COMMAND=magic("HIAEMC01"),PREP_EVENT=magic("HIAEME01"),
 NORM=magic("HIAEMN01"),INVENTORY=magic("HIAEMP01"),
 FRAME_COMMAND=magic("HIAPFC01"),FRAME_EVENT=magic("HIAPFE01"),
 TAPE_EVENT=magic("HIAFLE01"),WRAP_COMMAND=magic("HIAWRC01"),
 WRAP_EVENT=magic("HIAWRE01"),ISSUER_INPUT=magic("HIAFLC01"),
 ISSUER_EVENT=magic("HIAFLIE1"),ISSUER_RESULT=magic("HIAFLR01"),
 WRAP_INPUT=magic("HIAWIC01"),WRAP_ISSUER_EVENT=magic("HIAWIE01"),
 WRAP_RESULT=magic("HIAWIR01"),CODE_COMMAND=magic("HIAXCC01"),
 CODE_GRAPH=magic("HIAXGR01"),CODE_EVENT=magic("HIAXCE01"),
 FINAL_EVENT=magic("HIAXFE01"),FINISH_EVENT=magic("HIAEMF01"),
 BRIDGE=magic("HIAEMG01"),ELF_EVENT=magic("HIAELE01"),
 DRIVER=11,REG_AT=65536,
 B_COMMAND=4,B_PREP=5,B_NORM=6,B_INVENTORY=7,B_FRAME=8,B_TAPE=9,
 B_ISSUER=10,B_CODE=11,B_CODE_WORK=12,B_FINAL=13,B_FINISH=14,
 B_ELF=15,B_REGISTRY=16,B_ERROR=17,B_RESULT=18,
 I_PREPARE=1,I_FRAME=2,I_TAPE=3,I_ISSUER=4,I_WRAP=5,I_WRAP_ISSUER=6,
 I_ENCODER=7,I_FINAL=8,I_FINISH=9,I_ELF=10)
FIELDS=("REQUEST","GRAPH_LEASE","CODE_LEASE","ROOT","GRAPH_N","STRUCTURED",
 "MODE","NORM_N","NORM_GRAPH","FOREIGN_N","INV_N","INV_ORDER",
 "FN_N","ALIGN","POSITION","LOOP","INDEX","SERIAL","CODE_SEQ","CODE_N",
 "LABEL_N","FIX_N","REL_N","FOREIGN_POS","WRAP_KIND","EXTENT","TAPE_USED",
 "ISSUER_CTRL","ISSUER_KIND","PEER_SEQ","PEER_RETURN","ISSUER_REQUEST",
 "RECORD_N","GLOBAL_N","NAME_START","NAMES_N","REG_N","ROW","NAME_AT",
 "NAME_N","NAME_DONE","NAME_CHUNK","RESULT_AT","RESULT_N","FRAME",
 "BEGIN","END","ERROR_DOMAIN","ERROR_ID","ERROR_SLOT","ERROR_AT","ERROR_N",
 "CALL_IMAGE","CALL_FIRST","CALL_AT","CALL_N","CALL_SECOND","CALL_SECOND_N",
 "CALL_WORK","CALL_MIN","CALL_REPLY",
 "CONFIG_SOURCE","CONFIG_AT","CONFIG_N","CONFIG_TARGET","CONFIG_TO",
 "CONFIG_MIN","CONFIG_RO","CONFIG_AFTER",
 "COPY_SOURCE","COPY_AT","COPY_N","COPY_TARGET","COPY_TO","COPY_RO","COPY_AFTER",
 "CODE_FIRST","CODE_AT","CODE_PACKET_N","CODE_OP","CODE_PENDING","CODE_AFTER",
 "CODE_ISSUED","CODE_NEED","CODE_WORK_NEED",
 "ELF_GRAPH","ELF_GRAPH_N","ELF_COMMAND","TEXT_AT","TEXT_N","OBJECT_AT","OBJECT_N",
 "FINAL_N","LAST_COMPONENT","LAST_ACTION","ISSUER_PACKET_N")
CONSTANTS.update({"E_"+name:10000+8*i for i,name in enumerate(FIELDS)})
BODY=r'''
def emitter_control(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < MIN_WORK or length(o) < 128:
        return BAD
    if get(w, L_MAGIC) == 0:
        if emitter_begin(s, o, w) == 0:
            return refuse(w, 1000)
    elif acknowledge(s, w, DRIVER) == 0:
        return refuse(w, 1001)
    result = 0
    while result == 0:
        if get(w, L_STATUS) != 1:
            return refuse(w, 1002)
        result = emitter_step(o, w)
    return result

def emitter_begin(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    if length(s) < 192 or word(s, 0) != INIT or word(s, 8) != 1:
        return 0
    if word(s, 16) == 0 or word(s, 24) == 0 or word(s, 32) == 0 or word(s, 40) == 0:
        return 0
    if word(s, 48) == 0 or word(s, 56) != length(s) - 128 or word(s, 64) > 1:
        return 0
    at = 72
    while at < 128:
        if word(s, at) != 0:
            return 0
        at = at + 8
    if word(s, 128) != GRAPH or word(s, 136) != word(s, 32):
        return 0
    if word(s, 152) != word(s, 48) or word(s, 176) != word(s, 56):
        return 0
    if get(w, L_STATUS) != 0 or get(w, C_PENDING) != 0 or get(w, C_SEQUENCE) != 0:
        return 0
    fill_range(w, 0, MIN_WORK, 0)
    put(w, L_MAGIC, LOWER_MAGIC)
    put(w, L_STATUS, 1)
    put(w, L_DRIVER, DRIVER)
    put(w, C_LEASE, word(s, 16))
    put(w, E_REQUEST, word(s, 24))
    put(w, E_GRAPH_LEASE, word(s, 32))
    put(w, E_CODE_LEASE, word(s, 40))
    put(w, E_ROOT, word(s, 48))
    put(w, E_GRAPH_N, word(s, 56))
    put(w, E_STRUCTURED, word(s, 64))
    put(w, CAPS + 8, length(s))
    put(w, CAPS + 16, length(w))
    put(w, CAPS + 24, length(o))
    put(w, C_PHASE, 10)
    return 1

def set_phase(w:mutbuf, phase:u64) -> u64:
    put(w, C_PHASE, phase)
    return 0

def local_copy(w:mutbuf, target:u64, source:u64, size:u64) -> u64:
    i = 0
    while i < size:
        store(w, target + i, byte(w, source + i))
        i = i + 1
    return 0

def capacity(need:u64, old:u64) -> u64:
    if need <= old:
        return old
    if old <= MAX >> 1 and old * 2 > need:
        return old * 2
    return need

def peer_header(w:mutbuf, expected:u64) -> u64:
    if get(w, C_RETURN) != 128 and get(w, C_RETURN) != GROW:
        return 0
    if get(w, OBS) != expected or get(w, OBS + 8) != 1 or get(w, OBS + 120) != 0:
        return 0
    return 1

def fail_peer(w:mutbuf, domain:u64, error:u64, slot:u64, at:u64, count:u64) -> u64:
    if domain == 0 or count == 0 or inside(w, slot, at, count) == 0:
        return refuse(w, 1003)
    put(w, E_ERROR_DOMAIN, domain)
    put(w, E_ERROR_ID, error)
    put(w, E_ERROR_SLOT, slot)
    put(w, E_ERROR_AT, at)
    put(w, E_ERROR_N, count)
    return set_phase(w, 8000)

def config_request(w:mutbuf, source:u64, at:u64, size:u64, target:u64, to:u64, need:u64, readonly:u64, after:u64) -> u64:
    if size == 0 or target < 4 or readonly > 1 or need < to or size > need - to:
        return refuse(w, 1004)
    put(w, E_CONFIG_SOURCE, source)
    put(w, E_CONFIG_AT, at)
    put(w, E_CONFIG_N, size)
    put(w, E_CONFIG_TARGET, target)
    put(w, E_CONFIG_TO, to)
    put(w, E_CONFIG_MIN, need)
    put(w, E_CONFIG_RO, readonly)
    put(w, E_CONFIG_AFTER, after)
    return set_phase(w, 6000)

def call_request(w:mutbuf, image:u64, first:u64, at:u64, size:u64, second:u64, secondsize:u64, work:u64, minimum:u64, reply:u64) -> u64:
    put(w, E_CALL_IMAGE, image)
    put(w, E_CALL_FIRST, first)
    put(w, E_CALL_AT, at)
    put(w, E_CALL_N, size)
    put(w, E_CALL_SECOND, second)
    put(w, E_CALL_SECOND_N, secondsize)
    put(w, E_CALL_WORK, work)
    put(w, E_CALL_MIN, minimum)
    put(w, E_CALL_REPLY, reply)
    return set_phase(w, 5000)

def copy_request(w:mutbuf, source:u64, at:u64, size:u64, target:u64, to:u64, readonly:u64, after:u64) -> u64:
    if size == 0 or to > MAX - size:
        return refuse(w, 1005)
    put(w, E_COPY_SOURCE, source)
    put(w, E_COPY_AT, at)
    put(w, E_COPY_N, size)
    put(w, E_COPY_TARGET, target)
    put(w, E_COPY_TO, to)
    put(w, E_COPY_RO, readonly)
    put(w, E_COPY_AFTER, after)
    return set_phase(w, 6500)

def pure_grow(o:mutbuf, w:mutbuf, needed:u64) -> u32:
    slot = get(w, E_CALL_WORK)
    if get(w, C_RETURN) != GROW or needed <= cap(w, slot):
        return refuse(w, 1006)
    return grow(o, w, slot, capacity(needed, cap(w, slot)), 5002)

def preparation_command(w:mutbuf, mode:u64, after:u64) -> u64:
    fill_range(w, WIRE, 128, 0)
    put(w, WIRE, PREP_COMMAND)
    put(w, WIRE + 8, 1)
    put(w, WIRE + 16, get(w, E_GRAPH_LEASE))
    put(w, WIRE + 24, get(w, E_REQUEST))
    put(w, WIRE + 32, mode)
    put(w, WIRE + 40, get(w, E_CODE_LEASE))
    put(w, WIRE + 48, get(w, E_STRUCTURED))
    put(w, WIRE + 56, get(w, E_ROOT))
    put(w, WIRE + 64, get(w, E_GRAPH_N))
    put(w, E_MODE, mode)
    return config_request(w, 2, WIRE, 128, B_COMMAND, 0, 1024, 1, after)

def prep_reply(o:mutbuf, w:mutbuf, after:u64) -> u32:
    if peer_header(w, PREP_EVENT) == 0 or get(w, OBS + 24) != get(w, E_GRAPH_LEASE):
        return refuse(w, 1010)
    if get(w, OBS + 32) != get(w, E_REQUEST) or get(w, OBS + 96) != get(w, E_MODE) or get(w, OBS + 104) != get(w, E_ROOT):
        return refuse(w, 1011)
    action = get(w, OBS + 16)
    if action == 1:
        return pure_grow(o, w, get(w, OBS + 48))
    if get(w, C_RETURN) != 128 or action > 2:
        return refuse(w, 1012)
    if action == 2:
        return fail_peer(w, 2, get(w, OBS + 40), B_PREP, get(w, OBS + 56), get(w, OBS + 64))
    if get(w, OBS + 40) != 0 or get(w, OBS + 48) > cap(w, B_PREP):
        return refuse(w, 1013)
    if get(w, OBS + 56) != 8192 or get(w, OBS + 64) != get(w, OBS + 48) - 8192:
        return refuse(w, 1014)
    put(w, E_RESULT_N, get(w, OBS + 64))
    return set_phase(w, after)

def initial_steps(o:mutbuf, w:mutbuf, phase:u64) -> u32:
    if phase == 10:
        return preparation_command(w, 0, 11)
    if phase == 11:
        return call_request(w, I_PREPARE, 1, 128, get(w, E_GRAPH_N), B_COMMAND, 128, B_PREP, 8192, 12)
    if phase == 12:
        return prep_reply(o, w, 13)
    if phase == 13:
        return view(o, w, B_PREP, 8192, 128, 14)
    if phase == 14:
        if get(w, OBS) != NORM or get(w, OBS + 8) != 1:
            return refuse(w, 1015)
        if get(w, OBS + 16) != get(w, E_GRAPH_LEASE) or get(w, OBS + 24) != get(w, E_REQUEST):
            return refuse(w, 1016)
        n = get(w, OBS + 32)
        graph = get(w, OBS + 48)
        if n > 128 or get(w, OBS + 40) != 8320 or graph != 8320 + n * 32:
            return refuse(w, 1017)
        if get(w, OBS + 56) != get(w, E_GRAPH_N) or get(w, OBS + 64) != get(w, E_ROOT):
            return refuse(w, 1018)
        if get(w, OBS + 72) != get(w, E_GRAPH_N) or get(w, OBS + 80) != get(w, E_STRUCTURED):
            return refuse(w, 1019)
        at = 88
        while at < 128:
            if get(w, OBS + at) != 0:
                return refuse(w, 1020)
            at = at + 8
        if graph > MAX - get(w, E_GRAPH_N) or graph + get(w, E_GRAPH_N) - 8192 != get(w, E_RESULT_N):
            return refuse(w, 1021)
        put(w, E_FOREIGN_N, n)
        put(w, E_NORM_GRAPH, graph - 8192)
        put(w, E_NORM_N, get(w, E_RESULT_N))
        return copy_request(w, B_PREP, 8192, get(w, E_RESULT_N), B_NORM, 0, 1, 20)
    if phase == 20:
        return preparation_command(w, 1, 21)
    if phase == 21:
        return call_request(w, I_PREPARE, 1, 128, get(w, E_GRAPH_N), B_COMMAND, 128, B_PREP, 8192, 22)
    if phase == 22:
        return prep_reply(o, w, 23)
    if phase == 23:
        put(w, E_CODE_FIRST, B_PREP)
        put(w, E_CODE_AT, 8192)
        put(w, E_CODE_PACKET_N, get(w, E_RESULT_N))
        put(w, E_CODE_OP, 0)
        put(w, E_CODE_PENDING, 1)
        put(w, E_CODE_AFTER, 30)
        put(w, E_CODE_ISSUED, 0)
        put(w, E_CODE_NEED, 64)
        put(w, E_CODE_WORK_NEED, 4096)
        return set_phase(w, 7000)
    if phase == 30:
        return preparation_command(w, 2, 31)
    if phase == 31:
        return call_request(w, I_PREPARE, 1, 128, get(w, E_GRAPH_N), B_COMMAND, 128, B_PREP, 8192, 32)
    if phase == 32:
        return prep_reply(o, w, 33)
    if phase == 33:
        return view(o, w, B_PREP, 8192, 256, 34)
    if phase == 34:
        return inventory_received(w)
    return refuse(w, 1022)

def inventory_received(w:mutbuf) -> u64:
    if get(w, OBS) != INVENTORY or get(w, OBS + 8) != 1:
        return refuse(w, 1023)
    if get(w, OBS + 16) != get(w, E_GRAPH_LEASE) or get(w, OBS + 24) != get(w, E_REQUEST):
        return refuse(w, 1024)
    count = get(w, OBS + 56)
    if count > (MAX - 8448) >> 7:
        return refuse(w, 1025)
    order = 8448 + count * 48
    if get(w, OBS + 64) != 8448 or get(w, OBS + 72) != order or get(w, OBS + 88) != order + count * 8:
        return refuse(w, 1026)
    if get(w, OBS + 96) != get(w, E_GRAPH_N) or get(w, OBS + 104) != get(w, E_ROOT):
        return refuse(w, 1027)
    if get(w, OBS + 88) - 8192 != get(w, E_RESULT_N):
        return refuse(w, 1028)
    align = get(w, OBS + 80)
    if align != 1 and align != 16 and align != 32 and align != 64:
        return refuse(w, 1029)
    at = 112
    while at < 256:
        if get(w, OBS + at) != 0:
            return refuse(w, 1030)
        at = at + 8
    names = REG_AT + 256 + count * 128
    if names > length(w):
        return refuse(w, 1031)
    put(w, E_FN_N, count)
    put(w, E_ALIGN, align)
    put(w, E_INV_ORDER, order - 8192)
    put(w, E_INV_N, get(w, E_RESULT_N))
    put(w, E_NAME_START, names)
    return copy_request(w, B_PREP, 8192, get(w, E_RESULT_N), B_INVENTORY, 0, 1, 200)
'''

BODY += r'''
def single_code_packet(w:mutbuf, opcode:u64, after:u64) -> u64:
    if get(w, E_CODE_SEQ) == MAX or (opcode != 1 and opcode != 45):
        return refuse(w, 1040)
    count = choose(opcode == 1, 1, 0)
    total = choose(opcode == 1, 265, 192)
    fill_range(w, WIRE, total, 0)
    put(w, WIRE, CODE_COMMAND)
    put(w, WIRE + 8, 1)
    put(w, WIRE + 16, get(w, E_CODE_LEASE))
    put(w, WIRE + 24, get(w, E_CODE_SEQ) + 1)
    put(w, WIRE + 32, opcode)
    put(w, WIRE + 40, total - 64)
    put(w, WIRE + 48, 1)
    put(w, WIRE + 64, CODE_GRAPH)
    put(w, WIRE + 72, get(w, E_CODE_LEASE))
    put(w, WIRE + 80, count + 1)
    put(w, WIRE + 88, 1)
    put(w, WIRE + 96, count)
    put(w, WIRE + 104, count)
    put(w, WIRE + 112, total - 64)
    put(w, WIRE + 128, 5)
    put(w, WIRE + 160, count)
    put(w, WIRE + 168, 1)
    if count != 0:
        put(w, WIRE + 192, 2)
        put(w, WIRE + 200, 200)
        put(w, WIRE + 208, 1)
        put(w, WIRE + 256, 2)
        store(w, WIRE + 264, get(w, E_ALIGN))
    put(w, E_CODE_FIRST, B_COMMAND)
    put(w, E_CODE_AT, 0)
    put(w, E_CODE_PACKET_N, total)
    put(w, E_CODE_OP, opcode)
    put(w, E_CODE_PENDING, get(w, E_CODE_SEQ) + 1)
    put(w, E_CODE_AFTER, after)
    put(w, E_CODE_ISSUED, 0)
    put(w, E_CODE_NEED, cap(w, B_CODE))
    put(w, E_CODE_WORK_NEED, cap(w, B_CODE_WORK))
    return config_request(w, 2, WIRE, total, B_COMMAND, 0, 1024, 1, 7000)

def loop_steps(o:mutbuf, w:mutbuf, phase:u64) -> u32:
    if phase == 200:
        if get(w, E_POSITION) == get(w, E_FN_N):
            if get(w, E_LOOP) == 0:
                put(w, E_LOOP, 1)
                put(w, E_POSITION, 0)
            else:
                return set_phase(w, 4000)
        return view(o, w, B_INVENTORY, get(w, E_INV_ORDER) + get(w, E_POSITION) * 8, 8, 201)
    if phase == 201:
        if get(w, OBS) >= get(w, E_FN_N):
            return refuse(w, 1041)
        put(w, E_INDEX, get(w, OBS))
        return single_code_packet(w, 1, 210)
    if phase == 210:
        if get(w, E_LOOP) == 0:
            return frame_command(w)
        put(w, E_FOREIGN_POS, 0)
        put(w, E_WRAP_KIND, 1)
        put(w, E_EXTENT, 0)
        return set_phase(w, 250)
    if phase == 211:
        return call_request(w, I_FRAME, B_NORM, get(w, E_NORM_GRAPH), get(w, E_GRAPH_N),
            B_COMMAND, 96, B_FRAME, 4096, 212)
    if phase == 212:
        return frame_reply(o, w)
    if phase == 213:
        return protect(o, w, B_FRAME, 1, 214)
    if phase == 214:
        return call_request(w, I_TAPE, B_NORM, get(w, E_NORM_GRAPH), get(w, E_GRAPH_N),
            B_FRAME, cap(w, B_FRAME), B_TAPE, 12288, 215)
    if phase == 215:
        return tape_reply(o, w, 0)
    if phase == 250:
        if get(w, E_FOREIGN_POS) == get(w, E_FOREIGN_N):
            return wrapper_command(w)
        return view(o, w, B_NORM, 128 + get(w, E_FOREIGN_POS) * 32, 32, 251)
    if phase == 251:
        if get(w, OBS) == 0 or get(w, OBS + 8) >= get(w, E_FN_N) or get(w, OBS + 24) != 0:
            return refuse(w, 1042)
        if get(w, OBS + 16) == 0 or get(w, OBS + 16) > 1048576:
            return refuse(w, 1043)
        if get(w, OBS + 8) == get(w, E_INDEX):
            put(w, E_WRAP_KIND, 2)
            put(w, E_EXTENT, get(w, OBS + 16))
            return wrapper_command(w)
        put(w, E_FOREIGN_POS, get(w, E_FOREIGN_POS) + 1)
        return set_phase(w, 250)
    if phase == 252:
        return call_request(w, I_WRAP, B_NORM, get(w, E_NORM_GRAPH), get(w, E_GRAPH_N),
            B_COMMAND, 96, B_TAPE, 12288, 253)
    if phase == 253:
        return tape_reply(o, w, 1)
    if phase == 290:
        if get(w, E_POSITION) == MAX:
            return refuse(w, 1044)
        put(w, E_POSITION, get(w, E_POSITION) + 1)
        return set_phase(w, 200)
    return refuse(w, 1045)

def frame_command(w:mutbuf) -> u64:
    fill_range(w, WIRE, 96, 0)
    put(w, WIRE, FRAME_COMMAND)
    put(w, WIRE + 8, 1)
    put(w, WIRE + 16, get(w, E_GRAPH_LEASE))
    put(w, WIRE + 24, get(w, E_REQUEST))
    put(w, WIRE + 32, get(w, E_INDEX))
    put(w, WIRE + 40, get(w, E_SERIAL))
    put(w, WIRE + 48, get(w, E_ROOT))
    return config_request(w, 2, WIRE, 96, B_COMMAND, 0, 1024, 1, 211)

def wrapper_command(w:mutbuf) -> u64:
    frame_command(w)
    put(w, WIRE, WRAP_COMMAND)
    put(w, WIRE + 56, get(w, E_WRAP_KIND))
    put(w, WIRE + 64, get(w, E_EXTENT))
    put(w, E_CONFIG_AFTER, 252)
    return 0

def frame_reply(o:mutbuf, w:mutbuf) -> u32:
    if peer_header(w, FRAME_EVENT) == 0 or get(w, OBS + 24) != get(w, E_GRAPH_LEASE):
        return refuse(w, 1050)
    if get(w, OBS + 32) != get(w, E_REQUEST) or get(w, OBS + 40) != get(w, E_INDEX) or get(w, OBS + 112) != get(w, E_ROOT):
        return refuse(w, 1051)
    if get(w, OBS + 16) == 1:
        return pure_grow(o, w, get(w, OBS + 56))
    if get(w, C_RETURN) != 128:
        return refuse(w, 1052)
    if get(w, OBS + 16) == 2:
        return fail_peer(w, 2, get(w, OBS + 48), B_FRAME, get(w, OBS + 96), get(w, OBS + 104))
    if get(w, OBS + 16) != 0 or get(w, OBS + 48) != 0 or get(w, OBS + 56) > cap(w, B_FRAME):
        return refuse(w, 1053)
    if get(w, E_SERIAL) == MAX or get(w, OBS + 88) != get(w, E_SERIAL) + 1:
        return refuse(w, 1054)
    return set_phase(w, 213)

def tape_reply(o:mutbuf, w:mutbuf, wrapper:u64) -> u32:
    expected = choose(wrapper == 0, TAPE_EVENT, WRAP_EVENT)
    if peer_header(w, expected) == 0 or get(w, OBS + 24) != get(w, E_GRAPH_LEASE):
        return refuse(w, 1055)
    if get(w, OBS + 32) != get(w, E_REQUEST) or get(w, OBS + 40) != get(w, E_INDEX):
        return refuse(w, 1056)
    action = get(w, OBS + 16)
    if action == 1:
        return pure_grow(o, w, get(w, OBS + 48))
    if get(w, C_RETURN) != 128:
        return refuse(w, 1057)
    if wrapper == 1 and action == 2:
        return fail_peer(w, 2, get(w, OBS + 112), B_TAPE, get(w, OBS + 96), get(w, OBS + 104))
    if wrapper == 1 and action == 4:
        if get(w, E_WRAP_KIND) != 1 or get(w, OBS + 80) != get(w, E_SERIAL):
            return refuse(w, 1058)
        return set_phase(w, 290)
    if action != 0 or get(w, OBS + 48) > cap(w, B_TAPE) or get(w, OBS + 48) < 12544:
        return refuse(w, 1059)
    if get(w, OBS + 56) != 12288 or get(w, OBS + 64) != get(w, OBS + 48) - 12288:
        return refuse(w, 1060)
    if get(w, OBS + 80) < get(w, E_SERIAL):
        return refuse(w, 1061)
    put(w, E_TAPE_USED, get(w, OBS + 48))
    return set_phase(w, 300)

def issuer_config(w:mutbuf) -> u64:
    fill_range(w, WIRE, 128, 0)
    put(w, WIRE, choose(get(w, E_LOOP) == 0, ISSUER_INPUT, WRAP_INPUT))
    put(w, WIRE + 8, 1)
    put(w, WIRE + 16, get(w, C_LEASE))
    put(w, WIRE + 24, get(w, E_REQUEST))
    put(w, WIRE + 32, get(w, E_ISSUER_CTRL))
    put(w, WIRE + 40, get(w, E_ISSUER_KIND))
    put(w, WIRE + 48, get(w, E_CODE_LEASE))
    put(w, WIRE + 56, get(w, E_PEER_SEQ))
    put(w, WIRE + 64, get(w, E_GRAPH_LEASE))
    put(w, WIRE + 72, get(w, E_REQUEST))
    put(w, WIRE + 80, get(w, E_INDEX))
    put(w, WIRE + 88, get(w, E_TAPE_USED))
    put(w, WIRE + 96, cap(w, B_CODE))
    put(w, WIRE + 104, get(w, E_PEER_RETURN))
    return config_request(w, 2, WIRE, 128, B_ISSUER, 128, 8192, 0, 305)

def issuer_steps(o:mutbuf, w:mutbuf, phase:u64) -> u32:
    if phase == 300:
        return protect(o, w, B_TAPE, 1, 301)
    if phase == 301:
        return grow(o, w, B_ISSUER, 8192, 302)
    if phase == 302:
        return protect(o, w, B_ISSUER, 0, 303)
    if phase == 303:
        return clear(o, w, B_ISSUER, 0, cap(w, B_ISSUER), 304)
    if phase == 304:
        put(w, E_ISSUER_CTRL, 1)
        put(w, E_ISSUER_KIND, 1)
        put(w, E_PEER_SEQ, get(w, E_CODE_SEQ))
        put(w, E_PEER_RETURN, 128)
        return issuer_config(w)
    if phase == 305:
        return call_request(w, choose(get(w, E_LOOP) == 0, I_ISSUER, I_WRAP_ISSUER),
            B_TAPE, 0, cap(w, B_TAPE), B_CODE_WORK, cap(w, B_CODE_WORK), B_ISSUER, 8192, 306)
    if phase == 306:
        return issuer_reply(o, w)
    if phase == 312:
        return view(o, w, B_ISSUER, 4096, 64, 313)
    if phase == 313:
        if get(w, OBS) != CODE_COMMAND or get(w, OBS + 8) != 1 or get(w, OBS + 16) != get(w, E_CODE_LEASE):
            return refuse(w, 1062)
        if get(w, OBS + 24) != get(w, E_CODE_PENDING) or get(w, OBS + 32) > 44:
            return refuse(w, 1063)
        if get(w, OBS + 40) != get(w, E_CODE_PACKET_N) - 64 or get(w, OBS + 48) != 1 or get(w, OBS + 56) != 0:
            return refuse(w, 1064)
        put(w, E_CODE_OP, get(w, OBS + 32))
        return set_phase(w, 7000)
    if phase == 320:
        put(w, E_ISSUER_KIND, 2)
        return issuer_config(w)
    if phase == 330:
        return view(o, w, B_ISSUER, get(w, E_RESULT_AT), 256, 331)
    if phase == 331:
        return result_header(w)
    if phase == 332:
        if get(w, E_NAME_DONE) == get(w, E_NAME_N):
            return record_commit(w)
        n = minimum(256, get(w, E_NAME_N) - get(w, E_NAME_DONE))
        put(w, E_NAME_CHUNK, n)
        return view(o, w, B_ISSUER, get(w, E_NAME_AT) + get(w, E_NAME_DONE), n, 333)
    if phase == 333:
        local_copy(w, get(w, E_NAME_START) + get(w, E_NAMES_N) + get(w, E_NAME_DONE),
            OBS, get(w, E_NAME_CHUNK))
        put(w, E_NAME_DONE, get(w, E_NAME_DONE) + get(w, E_NAME_CHUNK))
        return set_phase(w, 332)
    return refuse(w, 1065)

def issuer_reply(o:mutbuf, w:mutbuf) -> u32:
    expected = choose(get(w, E_LOOP) == 0, ISSUER_EVENT, WRAP_ISSUER_EVENT)
    if peer_header(w, expected) == 0 or get(w, OBS + 24) != get(w, C_LEASE) or get(w, OBS + 32) != get(w, E_REQUEST):
        return refuse(w, 1070)
    if get(w, OBS + 40) != get(w, E_ISSUER_CTRL) or get(w, OBS + 48) != get(w, E_INDEX) or get(w, OBS + 56) != get(w, E_CODE_LEASE):
        return refuse(w, 1071)
    action = get(w, OBS + 16)
    if action == 4:
        return pure_grow(o, w, get(w, OBS + 104))
    if get(w, C_RETURN) != 128 or get(w, E_ISSUER_CTRL) == MAX:
        return refuse(w, 1072)
    put(w, E_ISSUER_CTRL, get(w, E_ISSUER_CTRL) + 1)
    if get(w, OBS + 80) < get(w, E_SERIAL):
        return refuse(w, 1073)
    put(w, E_SERIAL, get(w, OBS + 80))
    if get(w, OBS + 88) != 4096 or inside(w, B_ISSUER, 4096, get(w, OBS + 96)) == 0:
        return refuse(w, 1074)
    if action == 2:
        if get(w, OBS + 64) != get(w, E_CODE_SEQ) or get(w, OBS + 104) < 1 or get(w, OBS + 104) > 2:
            return refuse(w, 1075)
        return fail_peer(w, get(w, OBS + 104), get(w, OBS + 112),
            B_ISSUER, 4096, get(w, OBS + 96))
    if action == 0:
        if get(w, OBS + 64) != get(w, E_CODE_SEQ) or get(w, OBS + 96) < 256:
            return refuse(w, 1076)
        put(w, E_RESULT_AT, 4096)
        put(w, E_RESULT_N, get(w, OBS + 96))
        return set_phase(w, 330)
    if action != 1 and action != 5:
        return refuse(w, 1077)
    if action == 1:
        if get(w, E_CODE_SEQ) == MAX or get(w, OBS + 64) != get(w, E_CODE_SEQ) + 1:
            return refuse(w, 1078)
        put(w, E_CODE_PENDING, get(w, OBS + 64))
        put(w, E_ISSUER_PACKET_N, get(w, OBS + 96))
        put(w, E_CODE_PACKET_N, get(w, OBS + 96))
        put(w, E_CODE_NEED, cap(w, B_CODE))
        put(w, E_CODE_WORK_NEED, cap(w, B_CODE_WORK))
    else:
        if get(w, E_PEER_RETURN) != GROW or get(w, OBS + 64) != get(w, E_CODE_PENDING):
            return refuse(w, 1079)
        if get(w, OBS + 96) != get(w, E_ISSUER_PACKET_N):
            return refuse(w, 1080)
        if get(w, OBS + 104) <= cap(w, B_CODE) and get(w, OBS + 112) <= cap(w, B_CODE_WORK):
            return refuse(w, 1081)
        put(w, E_CODE_NEED, capacity(get(w, OBS + 104), cap(w, B_CODE)))
        put(w, E_CODE_WORK_NEED, capacity(get(w, OBS + 112), cap(w, B_CODE_WORK)))
    put(w, E_CODE_FIRST, B_ISSUER)
    put(w, E_CODE_AT, 4096)
    put(w, E_CODE_ISSUED, 1)
    put(w, E_CODE_AFTER, 320)
    return set_phase(w, choose(action == 1, 312, 7000))

def result_header(w:mutbuf) -> u64:
    expected = choose(get(w, E_LOOP) == 0, ISSUER_RESULT, WRAP_RESULT)
    if get(w, OBS) != expected or get(w, OBS + 8) != 1:
        return refuse(w, 1082)
    if get(w, OBS + 16) != get(w, C_LEASE) or get(w, OBS + 24) != get(w, E_REQUEST) or get(w, OBS + 32) != get(w, E_INDEX):
        return refuse(w, 1083)
    if get(w, OBS + 40) != get(w, E_CODE_LEASE) or get(w, OBS + 48) != get(w, E_CODE_SEQ):
        return refuse(w, 1084)
    begin = get(w, OBS + 56)
    end = get(w, OBS + 64)
    frame = get(w, OBS + 72)
    if begin >= end or end != get(w, E_CODE_N) or frame == 0 or frame > 65536 or (frame & 15) != 0:
        return refuse(w, 1085)
    if get(w, OBS + 80) != get(w, E_SERIAL) or get(w, OBS + 120) != get(w, E_RESULT_N):
        return refuse(w, 1086)
    name = get(w, OBS + 104)
    size = get(w, OBS + 112)
    if name < 4352 or size == 0 or name > 4096 + get(w, E_RESULT_N) or size > 4096 + get(w, E_RESULT_N) - name:
        return refuse(w, 1087)
    if get(w, E_LOOP) == 1:
        if get(w, OBS + 128) != get(w, E_WRAP_KIND) or get(w, OBS + 136) != get(w, E_EXTENT) or get(w, OBS + 144) != 1:
            return refuse(w, 1088)
    at = choose(get(w, E_LOOP) == 0, 128, 152)
    while at < 256:
        if get(w, OBS + at) != 0:
            return refuse(w, 1089)
        at = at + 8
    count = get(w, E_RECORD_N)
    if (get(w, E_LOOP) == 0 and count != get(w, E_POSITION)) or (get(w, E_LOOP) == 1 and count < get(w, E_FN_N)):
        return refuse(w, 1090)
    if count >= get(w, E_FN_N) * 2 or REG_AT + 256 + (count + 1) * 64 > get(w, E_NAME_START):
        return refuse(w, 1091)
    if count != 0 and begin < get(w, REG_AT + 256 + (count - 1) * 64 + 40):
        return refuse(w, 1092)
    available = length(w) - get(w, E_NAME_START)
    if get(w, E_NAMES_N) > available or size > available - get(w, E_NAMES_N):
        return refuse(w, 1093)
    put(w, E_ROW, REG_AT + 256 + count * 64)
    put(w, E_NAME_AT, name)
    put(w, E_NAME_N, size)
    put(w, E_NAME_DONE, 0)
    put(w, E_BEGIN, begin)
    put(w, E_END, end)
    put(w, E_FRAME, frame)
    return set_phase(w, 332)

def record_commit(w:mutbuf) -> u64:
    row = get(w, E_ROW)
    if row != REG_AT + 256 + get(w, E_RECORD_N) * 64 or get(w, E_NAME_DONE) != get(w, E_NAME_N):
        return refuse(w, 1094)
    fill_range(w, row, 64, 0)
    put(w, row, get(w, E_INDEX))
    put(w, row + 8, choose(get(w, E_LOOP) == 0, 0, get(w, E_WRAP_KIND)))
    put(w, row + 16, get(w, E_NAMES_N))
    put(w, row + 24, get(w, E_NAME_N))
    put(w, row + 32, get(w, E_BEGIN))
    put(w, row + 40, get(w, E_END))
    put(w, row + 48, get(w, E_FRAME))
    put(w, E_NAMES_N, get(w, E_NAMES_N) + get(w, E_NAME_N))
    put(w, E_RECORD_N, get(w, E_RECORD_N) + 1)
    if get(w, E_LOOP) == 1:
        put(w, E_GLOBAL_N, get(w, E_GLOBAL_N) + 1)
    return set_phase(w, 290)
'''

BODY += r'''
def registry_header(w:mutbuf) -> u64:
    count = get(w, E_RECORD_N)
    if count != get(w, E_FN_N) + get(w, E_GLOBAL_N):
        return refuse(w, 1100)
    pool = 256 + count * 64
    if get(w, E_NAMES_N) > MAX - pool:
        return refuse(w, 1101)
    fill_range(w, REG_AT, 256, 0)
    put(w, REG_AT, REGISTRY)
    put(w, REG_AT + 8, 1)
    put(w, REG_AT + 16, get(w, C_LEASE))
    put(w, REG_AT + 24, get(w, E_REQUEST))
    put(w, REG_AT + 32, get(w, E_GRAPH_LEASE))
    put(w, REG_AT + 40, get(w, E_ROOT))
    put(w, REG_AT + 48, get(w, E_GRAPH_N))
    put(w, REG_AT + 56, get(w, E_CODE_LEASE))
    put(w, REG_AT + 64, get(w, E_CODE_SEQ))
    put(w, REG_AT + 72, count)
    put(w, REG_AT + 80, 256)
    put(w, REG_AT + 88, pool)
    put(w, REG_AT + 96, pool + get(w, E_NAMES_N))
    put(w, REG_AT + 104, get(w, E_CODE_N))
    put(w, REG_AT + 112, get(w, E_SERIAL))
    put(w, REG_AT + 120, get(w, E_FN_N))
    put(w, REG_AT + 128, get(w, E_GLOBAL_N))
    put(w, REG_AT + 136, get(w, E_ALIGN))
    i = 0
    while i < count:
        at = REG_AT + 256 + i * 64
        if get(w, at + 16) > get(w, E_NAMES_N):
            return refuse(w, 1102)
        put(w, at + 16, pool + get(w, at + 16))
        i = i + 1
    put(w, E_REG_N, pool + get(w, E_NAMES_N))
    return set_phase(w, 4001)

def finish_reply(o:mutbuf, w:mutbuf, mode:u64, after:u64) -> u32:
    if peer_header(w, FINISH_EVENT) == 0 or get(w, OBS + 24) != get(w, C_LEASE) or get(w, OBS + 32) != get(w, E_REQUEST):
        return refuse(w, 1103)
    if get(w, OBS + 40) != mode or get(w, OBS + 80) != get(w, E_CODE_LEASE) or get(w, OBS + 88) != get(w, E_CODE_SEQ):
        return refuse(w, 1104)
    if get(w, OBS + 104) != get(w, E_RECORD_N) or get(w, OBS + 112) != get(w, E_GLOBAL_N):
        return refuse(w, 1105)
    action = get(w, OBS + 16)
    if action == 1:
        return pure_grow(o, w, get(w, OBS + 56))
    if get(w, C_RETURN) != 128:
        return refuse(w, 1106)
    if action == 2:
        return fail_peer(w, 2, get(w, OBS + 48), B_FINISH, get(w, OBS + 64), get(w, OBS + 72))
    if action != 0 or get(w, OBS + 48) != 0:
        return refuse(w, 1107)
    if mode == 1:
        if get(w, OBS + 64) != 0 or get(w, OBS + 72) != 0 or get(w, OBS + 96) != get(w, E_CODE_N):
            return refuse(w, 1108)
    else:
        if get(w, OBS + 64) != 8192 or inside(w, B_FINISH, 8192, get(w, OBS + 72)) == 0:
            return refuse(w, 1109)
        put(w, E_RESULT_N, get(w, OBS + 72))
    return set_phase(w, after)

def final_steps(o:mutbuf, w:mutbuf, phase:u64) -> u32:
    if phase == 4000:
        return registry_header(w)
    if phase == 4001:
        return grow(o, w, B_REGISTRY, get(w, E_REG_N), 4002)
    if phase == 4002:
        return copy(o, w, 2, REG_AT, B_REGISTRY, 0, 256 + get(w, E_RECORD_N) * 64, 4003)
    if phase == 4003:
        return copy(o, w, 2, get(w, E_NAME_START), B_REGISTRY, 256 + get(w, E_RECORD_N) * 64, get(w, E_NAMES_N), 4004)
    if phase == 4004:
        return protect(o, w, B_REGISTRY, 1, 4005)
    if phase == 4005:
        return call_request(w, I_FINISH, 1, 128, get(w, E_GRAPH_N),
            B_REGISTRY, get(w, E_REG_N), B_FINISH, 8192, 4006)
    if phase == 4006:
        return finish_reply(o, w, 1, 4007)
    if phase == 4007:
        return single_code_packet(w, 45, 4100)
    if phase == 4100:
        put(w, REG_AT + 64, get(w, E_CODE_SEQ))
        return protect(o, w, B_REGISTRY, 0, 4101)
    if phase == 4101:
        return copy(o, w, 2, REG_AT + 64, B_REGISTRY, 64, 8, 4102)
    if phase == 4102:
        return protect(o, w, B_REGISTRY, 1, 4103)
    if phase == 4103:
        return protect(o, w, B_CODE, 1, 4104)
    if phase == 4104:
        return call_request(w, I_FINAL, B_CODE, 0, cap(w, B_CODE),
            B_CODE_WORK, cap(w, B_CODE_WORK), B_FINAL, 4096, 4105)
    if phase == 4105:
        return finalizer_reply(o, w)
    if phase == 4106:
        return protect(o, w, B_FINAL, 1, 4107)
    if phase == 4107:
        return call_request(w, I_FINISH, B_REGISTRY, 0, get(w, E_REG_N),
            B_FINAL, cap(w, B_FINAL), B_FINISH, 8192, 4108)
    if phase == 4108:
        return finish_reply(o, w, 2, 4109)
    if phase == 4109:
        return view(o, w, B_FINISH, 8192, 128, 4110)
    if phase == 4110:
        return bridge_received(w)
    if phase == 4111:
        return protect(o, w, B_FINISH, 1, 4112)
    if phase == 4112:
        return call_request(w, I_ELF, B_FINISH, get(w, E_ELF_GRAPH), get(w, E_ELF_GRAPH_N),
            B_COMMAND, 96, B_ELF, 4096, 4113)
    if phase == 4113:
        return elf_reply(o, w)
    if phase == 4114:
        return protect(o, w, B_ELF, 1, 4200)
    if phase == 4200:
        return publish_result(w)
    if phase == 4201:
        return terminal(o, w, 0)
    return refuse(w, 1110)

def finalizer_reply(o:mutbuf, w:mutbuf) -> u32:
    if peer_header(w, FINAL_EVENT) == 0 or get(w, OBS + 112) != 0 or get(w, OBS + 24) != get(w, E_CODE_LEASE) or get(w, OBS + 32) != get(w, E_CODE_SEQ):
        return refuse(w, 1111)
    action = get(w, OBS + 16)
    if action == 1:
        return pure_grow(o, w, get(w, OBS + 48))
    if get(w, C_RETURN) != 128:
        return refuse(w, 1112)
    if action == 2:
        return fail_peer(w, 1, get(w, OBS + 40), B_FINAL, get(w, OBS + 96), get(w, OBS + 104))
    if action != 0 or get(w, OBS + 40) != 0 or get(w, OBS + 56) != 4096:
        return refuse(w, 1113)
    if get(w, OBS + 72) < get(w, E_CODE_N) or get(w, OBS + 72) - get(w, E_CODE_N) > 4:
        return refuse(w, 1114)
    put(w, E_FINAL_N, get(w, OBS + 72))
    return set_phase(w, 4106)

def bridge_received(w:mutbuf) -> u64:
    if get(w, OBS) != BRIDGE or get(w, OBS + 8) != 1 or get(w, OBS + 16) != get(w, C_LEASE) or get(w, OBS + 24) != get(w, E_REQUEST):
        return refuse(w, 1115)
    if get(w, OBS + 32) != get(w, E_CODE_LEASE) or get(w, OBS + 40) != get(w, E_CODE_SEQ):
        return refuse(w, 1116)
    graph = get(w, OBS + 48)
    size = get(w, OBS + 56)
    command = get(w, OBS + 64)
    if graph != 8320 or graph > MAX - size or command != graph + size or get(w, OBS + 72) != 96:
        return refuse(w, 1117)
    if inside(w, B_FINISH, graph, size) == 0 or inside(w, B_FINISH, command, 96) == 0:
        return refuse(w, 1118)
    if get(w, OBS + 80) != 2 or get(w, OBS + 96) != get(w, E_FINAL_N):
        return refuse(w, 1119)
    if get(w, OBS + 104) != get(w, E_RECORD_N) or get(w, OBS + 112) != choose(get(w, E_ALIGN) < 16, 16, get(w, E_ALIGN)) or get(w, OBS + 120) != 0:
        return refuse(w, 1120)
    if inside(w, B_FINISH, get(w, OBS + 88), get(w, OBS + 96)) == 0:
        return refuse(w, 1121)
    put(w, E_ELF_GRAPH, graph)
    put(w, E_ELF_GRAPH_N, size)
    put(w, E_ELF_COMMAND, command)
    put(w, E_TEXT_AT, get(w, OBS + 88))
    put(w, E_TEXT_N, get(w, OBS + 96))
    return config_request(w, B_FINISH, command, 96, B_COMMAND, 0, 1024, 1, 4111)

def elf_reply(o:mutbuf, w:mutbuf) -> u32:
    if peer_header(w, ELF_EVENT) == 0 or get(w, OBS + 24) != get(w, C_LEASE) or get(w, OBS + 32) != get(w, E_REQUEST):
        return refuse(w, 1122)
    action = get(w, OBS + 16)
    if action == 1:
        return pure_grow(o, w, get(w, OBS + 48))
    if get(w, C_RETURN) != 128:
        return refuse(w, 1123)
    if action == 2:
        return fail_peer(w, 1, get(w, OBS + 40), B_ELF, get(w, OBS + 56), get(w, OBS + 64))
    if action != 0 or get(w, OBS + 40) != 0 or get(w, OBS + 64) == 0:
        return refuse(w, 1124)
    if inside(w, B_ELF, get(w, OBS + 56), get(w, OBS + 64)) == 0:
        return refuse(w, 1125)
    put(w, E_OBJECT_AT, get(w, OBS + 56))
    put(w, E_OBJECT_N, get(w, OBS + 64))
    return set_phase(w, 4114)

def publish_result(w:mutbuf) -> u64:
    fill_range(w, WIRE, 256, 0)
    put(w, WIRE, RESULT)
    put(w, WIRE + 8, 1)
    put(w, WIRE + 16, get(w, C_LEASE))
    put(w, WIRE + 24, get(w, E_REQUEST))
    put(w, WIRE + 32, 1)
    put(w, WIRE + 40, 128)
    put(w, WIRE + 48, get(w, E_GRAPH_N))
    put(w, WIRE + 56, get(w, E_GRAPH_LEASE))
    put(w, WIRE + 64, B_REGISTRY)
    put(w, WIRE + 72, 0)
    put(w, WIRE + 80, get(w, E_REG_N))
    put(w, WIRE + 88, get(w, E_CODE_LEASE))
    put(w, WIRE + 96, get(w, E_CODE_SEQ))
    put(w, WIRE + 104, get(w, E_SERIAL))
    put(w, WIRE + 112, get(w, E_FN_N))
    put(w, WIRE + 120, get(w, E_GLOBAL_N))
    put(w, WIRE + 128, B_FINISH)
    put(w, WIRE + 136, get(w, E_TEXT_AT))
    put(w, WIRE + 144, get(w, E_TEXT_N))
    put(w, WIRE + 152, B_ELF)
    put(w, WIRE + 160, get(w, E_OBJECT_AT))
    put(w, WIRE + 168, get(w, E_OBJECT_N))
    put(w, WIRE + 176, B_NORM)
    put(w, WIRE + 184, get(w, E_NORM_GRAPH))
    put(w, WIRE + 192, get(w, E_GRAPH_N))
    put(w, WIRE + 200, B_INVENTORY)
    put(w, WIRE + 208, get(w, E_INV_N))
    put(w, WIRE + 216, get(w, E_LABEL_N))
    put(w, WIRE + 224, get(w, E_FIX_N))
    put(w, WIRE + 232, get(w, E_REL_N))
    return copy_request(w, 2, WIRE, 256, B_RESULT, 0, 1, 4201)

def terminal(o:mutbuf, w:mutbuf, failure:u64) -> u32:
    if get(w, L_STATUS) != 1 or get(w, C_PENDING) != 0:
        return refuse(w, 1126)
    put(w, L_STATUS, 2)
    fill_range(o, 0, 128, 0)
    put(o, 0, EVENT_MAGIC)
    put(o, 8, 7)
    put(o, 16, get(w, C_LEASE))
    put(o, 24, get(w, C_SEQUENCE))
    put(o, 32, choose(failure == 0, 0, get(w, E_ERROR_DOMAIN)))
    put(o, 40, choose(failure == 0, 0, get(w, E_ERROR_ID)))
    put(o, 48, choose(failure == 0, B_RESULT, B_ERROR))
    put(o, 56, 0)
    put(o, 64, choose(failure == 0, 256, get(w, E_ERROR_N)))
    put(o, 72, get(w, E_CODE_SEQ))
    put(o, 80, get(w, E_CODE_N))
    put(o, 88, get(w, E_SERIAL))
    put(o, 96, get(w, E_RECORD_N))
    put(o, 104, get(w, E_GLOBAL_N))
    put(o, 112, get(w, E_REQUEST))
    return 128

def mechanics_steps(o:mutbuf, w:mutbuf, phase:u64) -> u32:
    if phase == 5000:
        if cap(w, get(w, E_CALL_WORK)) != 0:
            return protect(o, w, get(w, E_CALL_WORK), 0, 5001)
        return set_phase(w, 5001)
    if phase == 5001:
        return grow(o, w, get(w, E_CALL_WORK), get(w, E_CALL_MIN), 5002)
    if phase == 5002:
        return invoke(o, w, get(w, E_CALL_IMAGE), get(w, E_CALL_FIRST), get(w, E_CALL_AT),
            get(w, E_CALL_N), get(w, E_CALL_SECOND), get(w, E_CALL_SECOND_N),
            get(w, E_CALL_WORK), cap(w, get(w, E_CALL_WORK)), get(w, E_CALL_WORK), 0, 128,
            get(w, E_CALL_REPLY))
    if phase == 6000:
        if cap(w, get(w, E_CONFIG_TARGET)) != 0:
            return protect(o, w, get(w, E_CONFIG_TARGET), 0, 6001)
        return set_phase(w, 6001)
    if phase == 6001:
        return grow(o, w, get(w, E_CONFIG_TARGET), get(w, E_CONFIG_MIN), 6002)
    if phase == 6002:
        return copy(o, w, get(w, E_CONFIG_SOURCE), get(w, E_CONFIG_AT),
            get(w, E_CONFIG_TARGET), get(w, E_CONFIG_TO), get(w, E_CONFIG_N), 6003)
    if phase == 6003:
        if get(w, E_CONFIG_RO) != 0:
            return protect(o, w, get(w, E_CONFIG_TARGET), 1, get(w, E_CONFIG_AFTER))
        return set_phase(w, get(w, E_CONFIG_AFTER))
    if phase == 6500:
        if cap(w, get(w, E_COPY_TARGET)) != 0:
            return protect(o, w, get(w, E_COPY_TARGET), 0, 6501)
        return set_phase(w, 6501)
    if phase == 6501:
        return grow(o, w, get(w, E_COPY_TARGET), get(w, E_COPY_TO) + get(w, E_COPY_N), 6502)
    if phase == 6502:
        return copy(o, w, get(w, E_COPY_SOURCE), get(w, E_COPY_AT),
            get(w, E_COPY_TARGET), get(w, E_COPY_TO), get(w, E_COPY_N), 6503)
    if phase == 6503:
        if get(w, E_COPY_RO) != 0:
            return protect(o, w, get(w, E_COPY_TARGET), 1, get(w, E_COPY_AFTER))
        return set_phase(w, get(w, E_COPY_AFTER))
    if phase == 8000:
        return copy_request(w, get(w, E_ERROR_SLOT), get(w, E_ERROR_AT),
            get(w, E_ERROR_N), B_ERROR, 0, 1, 8001)
    if phase == 8001:
        return terminal(o, w, 1)
    return refuse(w, 1130)

def code_steps(o:mutbuf, w:mutbuf, phase:u64) -> u32:
    if phase == 7000:
        return protect(o, w, get(w, E_CODE_FIRST), 1, 7001)
    if phase == 7001:
        return grow(o, w, B_CODE, get(w, E_CODE_NEED), 7002)
    if phase == 7002:
        return grow(o, w, B_CODE_WORK, get(w, E_CODE_WORK_NEED), 7003)
    if phase == 7003:
        return invoke(o, w, I_ENCODER, get(w, E_CODE_FIRST), get(w, E_CODE_AT),
            get(w, E_CODE_PACKET_N), B_CODE, cap(w, B_CODE), B_CODE_WORK,
            cap(w, B_CODE_WORK), B_CODE_WORK, 0, 128, 7004)
    if phase == 7004:
        return code_reply(w)
    return refuse(w, 1131)

def code_reply(w:mutbuf) -> u64:
    if peer_header(w, CODE_EVENT) == 0 or get(w, OBS + 24) != get(w, E_CODE_LEASE) or get(w, OBS + 32) != get(w, E_CODE_PENDING):
        return refuse(w, 1132)
    if get(w, OBS + 40) != get(w, E_CODE_OP):
        return refuse(w, 1133)
    action = get(w, OBS + 16)
    count = get(w, OBS + 72)
    labels = get(w, OBS + 80)
    fixes = get(w, OBS + 88)
    rels = get(w, OBS + 96)
    if count < get(w, E_CODE_N) or labels < get(w, E_LABEL_N) or fixes < get(w, E_FIX_N) or rels < get(w, E_REL_N):
        return refuse(w, 1134)
    if action == 1:
        if get(w, C_RETURN) != GROW or get(w, OBS + 48) != 0:
            return refuse(w, 1135)
        if count != get(w, E_CODE_N) or labels != get(w, E_LABEL_N) or fixes != get(w, E_FIX_N) or rels != get(w, E_REL_N):
            return refuse(w, 1136)
        if get(w, OBS + 56) <= cap(w, B_CODE) and get(w, OBS + 64) <= cap(w, B_CODE_WORK):
            return refuse(w, 1137)
        put(w, E_CODE_NEED, capacity(get(w, OBS + 56), cap(w, B_CODE)))
        put(w, E_CODE_WORK_NEED, capacity(get(w, OBS + 64), cap(w, B_CODE_WORK)))
    else:
        if get(w, C_RETURN) != 128 or get(w, E_CODE_SEQ) == MAX or get(w, E_CODE_PENDING) != get(w, E_CODE_SEQ) + 1:
            return refuse(w, 1138)
        if action != 0 and action != 2 and action != 4:
            return refuse(w, 1139)
        if (get(w, E_CODE_OP) == 45 and action != 4) or (get(w, E_CODE_OP) != 45 and action == 4):
            return refuse(w, 1140)
        if action != 2 and (get(w, OBS + 48) != 0 or get(w, OBS + 104) != 0 or get(w, OBS + 112) != 0):
            return refuse(w, 1141)
        if get(w, E_CODE_OP) == 45 and (count != get(w, E_CODE_N) or labels != get(w, E_LABEL_N) or fixes != get(w, E_FIX_N) or rels != get(w, E_REL_N)):
            return refuse(w, 1142)
        put(w, E_CODE_SEQ, get(w, E_CODE_PENDING))
        put(w, E_CODE_N, count)
        put(w, E_LABEL_N, labels)
        put(w, E_FIX_N, fixes)
        put(w, E_REL_N, rels)
    put(w, E_PEER_SEQ, get(w, E_CODE_PENDING))
    put(w, E_PEER_RETURN, get(w, C_RETURN))
    if get(w, E_CODE_ISSUED) != 0:
        return set_phase(w, 320)
    if action == 1:
        return set_phase(w, 7001)
    if action == 2:
        return fail_peer(w, 1, get(w, OBS + 48), B_CODE_WORK, get(w, OBS + 104), get(w, OBS + 112))
    return set_phase(w, get(w, E_CODE_AFTER))

def emitter_step(o:mutbuf, w:mutbuf) -> u64:
    phase = get(w, C_PHASE)
    if phase < 100:
        return initial_steps(o, w, phase)
    if phase < 300:
        return loop_steps(o, w, phase)
    if phase < 400:
        return issuer_steps(o, w, phase)
    if phase >= 4000 and phase < 4300:
        return final_steps(o, w, phase)
    if phase >= 7000 and phase < 7100:
        return code_steps(o, w, phase)
    return mechanics_steps(o, w, phase)
'''

def source(common_owner):
    constants=dict(common_owner.CONSTANTS)
    constants.update(CONSTANTS)
    # The generic protocol's pending/action/sequence checks are unchanged.
    # Only the selected image upper bound is narrowed for this independent set.
    common=common_owner.COMMON
    assert common.count("image > 23")==1
    common=common.replace("image > 23","image > 10",1)
    common_nodes={n.name:copy.deepcopy(n) for n in ast.parse(common).body}
    current={n.name:copy.deepcopy(n) for n in ast.parse(BODY).body}
    assert set(current).isdisjoint(common_nodes)
    names={**current,**common_nodes}
    live={"emitter_control"};pending=["emitter_control"]
    while pending:
        for call in ast.walk(names[pending.pop()]):
            if isinstance(call,ast.Call) and isinstance(call.func,ast.Name):
                name=call.func.id
                if name in names and name not in live:
                    live.add(name);pending.append(name)
    nodes=[n for name,n in names.items() if name in live]
    for node in nodes:
        if node.name in ("word","get"):
            arg="s" if node.name=="word" else "w"
            node.body=ast.parse("return "+" | ".join("(byte(%s,at+%d)<<%d)"%(arg,i,i*8) for i in range(8))).body
        elif node.name=="put":
            node.body=ast.parse("\n".join("store(w,at+%d,(value>>%d)&255)"%(i,i*8) for i in range(8))+"\nreturn 0").body
    return "\n".join(ast.unparse(ast.fix_missing_locations(n)) for n in nodes)+"\n",constants,dict(
        status="NEW_UNEXECUTED",scope="NATIVE_EMITTER_PERSISTENT_FIXED_MECHANICS_CONTROLLER",
        common_protocol_sha256=COMMON_SHA,prepare_sha256=PREPARE_SHA,finish_sha256=FINISH_SHA,
        runtime_instruction_or_symbol_construction_by_host=False,
        actual_Core_checked_plan_and_origin_issuer_required=True,header_is_authentication=False,
        code_init_before_profile=True,function_order_native=True,align_before_every_wrapper_even_skip=True,
        late_exports_count_text_gates=True,original_Code_finalizer_then_actual_ELF_writer=True,
        every_GROW_keeps_original_immutable_inputs=True,aggregate_record_commit_after_complete_name_copy=True,
        private_one_megabyte_controller_sufficient_for_existing_1024_function_admission=True,
        controller_permanent_BAD=True,full_outer_emit_program_machine=False,
        original_source_target_plan_admission_and_object_inspection_still_required=True,
        installed=False,cold=False)
