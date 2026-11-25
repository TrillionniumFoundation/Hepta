"""Author a native scalar proof owner; all admission and claims are HIA policy."""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_system_jobctl_request import document

ROOT=Path(__file__).resolve().parents[1]
SOURCE=Path('examples/hia_bootstrap/native_scalar_proof_policy.hepta')
M=lambda s:int.from_bytes(s.encode(),'little')
C={
'REQUEST_MAGIC':M('HIAMVP01'),'REPLY_MAGIC':M('HIAMVR01'),
'GRAPH_MAGIC':M('HIABVP01'),'CIRCUIT_MAGIC':M('HIABVC01'),
'PLAN_MAGIC':M('HIABVS03'),'FORMULA_MAGIC':M('HIACNX02'),
'LEARNING_MAGIC':M('HIACNL05'),'RESTART_MAGIC':M('HIACNG06'),
'SOLVED_MAGIC':M('HIACNR02'),'WITNESS_MAGIC':M('HIABVW01'),
'TABLE_MAGIC':M('HIABVT01'),'WIRE_MAGIC':M('HIAERW01'),
'VM_MAGIC':M('HIASPG01'),'VM_REPLY':M('HIASPR01'),'SELECTION_MAGIC':M('HIAPSL01'),
'NONE':(1<<64)-1,'BAD':4294967293,'FILE_MAX':8<<20,
'WORK_MAX':256<<20,'OUTPUT_MAX':262144,
'NAME':4096,'ARGUMENTS':8192,'WITNESS_WORDS':8704,'SIGNATURE1':12288,'SIGNATURE2':12800,'TOKENS':16384,
'WHOLE_ID':1024,'HASH_RESULT':1056,'RAW_BEFORE':1088,'RAW_AFTER':1120,
'CORE_BEFORE':1152,'CORE_AFTER':1184,'HASH_WORK':2048,
'CANON1':1<<20,'CANON2':9<<20,'GRAPH1':17<<20,'GRAPH2':21<<20,
'JOINED':25<<20,'CIRCUIT':33<<20,'FORMULA':34<<20,'MODEL':38<<20,
'REPLAY_INPUT':40<<20,'REPLAY_WIRE':49<<20,
'OBS1':81<<20,'OBS2':(81<<20)+4096,'ROLE_OUTPUT':82<<20,
'ROLE_WORK':146<<20,'GRAPH_CAP':4<<20,'REPLAY_CAP':32<<20,
'SELECT1':210<<20,'SELECT2':218<<20,
'CNF_OUTPUT':10808,'CNF_WORK':294912,'CNF_ENCODE_WORK':98848,
'CNF_FORMULA_CAP':196608,
}
POLICY=r'''
def native_scalar_proof_policy(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) != WORK_MAX or length(o) != OUTPUT_MAX:
        return BAD
    phase = get(w, 0)
    if phase == 0:
        return admit(s, o, w)
    if get(w, 104) != 0:
        put(w, 520, 0)
        return unknown(o, w, 14)
    if phase < 90 and now(w) >= get(w, 272):
        return unknown(o, w, 12)
    result = get(w, 72)
    if phase <= 19:
        return prepare(s, o, w, phase, result)
    if phase >= 20 and phase <= 24:
        return solve(o, w, phase, result)
    if phase >= 25 and phase <= 29:
        return replay(o, w, phase, result)

    if phase == 30:
        return word_table_reply(o, w, result)
    if phase == 31:
        if result != 32:
            return unknown(o, w, 14)
        put(w, 568, 1)
        return dispatch(w, 23, 5, 1, FORMULA, get(w, 544), MODEL, 32 + (get(w, 472) + 7) // 8, ROLE_WORK, get(w, 552))
    if phase == 32:
        if result != 32:
            return unknown(o, w, 14)
        put(w, 568, 1)
        return dispatch(w, 30, 5, 1, FORMULA, get(w, 424) + 8, MODEL, 32, ROLE_WORK, choose(get(w, 432) == 0, 8, 8 * get(w, 432)))
    if phase == 33:
        if result != 32:
            return unknown(o, w, 14)
        put(w, 568, 1)
        return hash(w, 90, 2, 0, get(w, 96), HASH_RESULT)
    if phase == 91:
        if result != 32:
            put(w, 312, 0)
            put(w, 320, 14)
            put(w, 528, 1)
        else:
            put(w, 536, 1)
        if now(w) >= get(w, 272) and get(w, 312) != 0:
            put(w, 312, 0)
            put(w, 320, 12)
            put(w, 528, 1)
        return receipt(o, w)
    if phase == 90:
        if result != 32 or same(w, WHOLE_ID, HASH_RESULT, 32) == False:
            put(w, 312, 0)
            put(w, 320, 13)
            put(w, 528, 1)
        if now(w) >= get(w, 272) and get(w, 312) != 0:
            put(w, 312, 0)
            put(w, 320, 12)
            put(w, 528, 1)
        return close_identity(w)
    return unknown(o, w, 14)

def admit(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 64 or uint(s, 0) != REQUEST_MAGIC:
        return BAD
    mode = uint(s, 8)
    budget = uint(s, 16)
    name = uint(s, 24)
    before = uint(s, 32)
    after = uint(s, 40)
    if mode < 1 or mode > 2 or budget < 1 or budget > 60000:
        return BAD
    if name > 128 or before == 0 or before > FILE_MAX or after > FILE_MAX:
        return BAD
    if (mode == 1 and after != 0) or (mode == 2 and after == 0):
        return BAD
    if uint(s, 48) != 0 or uint(s, 56) != 0 or length(s) != 64 + name + before + after:
        return BAD
    if name != 0:
        i = 0
        while i < name:
            c = byte(s, 64 + i)
            if ((c >= 65 and c <= 90) or (c >= 97 and c <= 122) or c == 95 or (i != 0 and c >= 48 and c <= 57)) == False:
                return BAD
            store(w, NAME + i, c)
            i = i + 1
    start = now(w)
    if start > NONE - budget * 1000000:
        return BAD
    put(w, 256, mode)
    put(w, 264, start)
    put(w, 272, start + budget * 1000000)
    put(w, 280, budget)
    put(w, 288, name)
    put(w, 296, before)
    put(w, 304, after)
    put(w, 312, 0)
    put(w, 320, 0)
    put(w, 328, 0)
    put(w, 336, 0)
    put(w, 344, 64 + name)
    put(w, 352, 64 + name + before)
    put(w, 360, 0)
    put(w, 368, 0)
    put(w, 376, 0)
    put(w, 384, 0)
    put(w, 392, 0)
    put(w, 400, 0)
    put(w, 408, 0)
    put(w, 416, 0)
    put(w, 424, 0)
    put(w, 432, 0)
    put(w, 440, 0)
    put(w, 448, 0)
    put(w, 456, 0)
    put(w, 464, 0)
    put(w, 472, 0)
    put(w, 480, 0)
    put(w, 488, 0)
    put(w, 496, 0)
    put(w, 504, 0)
    put(w, 512, 0)
    put(w, 520, 0)
    put(w, 528, 0)
    put(w, 536, 0)
    put(w, 544, 0)
    put(w, 552, 0)
    put(w, 560, 0)
    put(w, 568, 0)
    put(w, 576, 0)
    put(w, 584, 0)
    put(w, 592, 0)
    return hash(w, 1, 2, 0, get(w, 96), WHOLE_ID)

def prepare(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if phase == 1:
        if result != 32:
            return unknown(o, w, 14)
        put(w, 520, 1)
        return hash(w, 2, 0, get(w, 344), get(w, 296), RAW_BEFORE)
    if phase == 2:
        if result != 32:
            return unknown(o, w, 14)
        put(w, 512, get(w, 512) | 1)
        return dispatch(w, 3, 2, 0, get(w, 344), get(w, 296), ROLE_OUTPUT, 67108864, ROLE_WORK, 33554432)
    if phase == 3:
        if result != 0:
            put(w, 480, result)
            return unknown(o, w, 2)
        put(w, 328, 1)
        return canonical(w, 4, get(w, 344), get(w, 296), CANON1)
    if phase == 4:
        if result == 0 or result > FILE_MAX:
            return unknown(o, w, 14)
        put(w, 360, result)
        return hash(w, 5, 1, CANON1, result, CORE_BEFORE)
    if phase == 5:
        if result != 32:
            return unknown(o, w, 14)
        put(w, 512, get(w, 512) | 2)
        if get(w, 256) == 2:
            return hash(w, 7, 0, get(w, 352), get(w, 304), RAW_AFTER)
        return selection(w, 12, CANON1, get(w, 360), SELECT1)
    if phase == 6:
        if result == 4294967292:
            return profile_failure(o, w)
        if accept_graph(w, result, GRAPH1, 1) == False:
            return unknown(o, w, 14)
        put(w, 376, result)
        if get(w, 256) == 1:
            return begin_solver(o, w)
        return graph(w, 11, CANON2, get(w, 368), GRAPH2)
    if phase == 7:
        if result != 32:
            return unknown(o, w, 14)
        put(w, 512, get(w, 512) | 4)
        return dispatch(w, 8, 2, 0, get(w, 352), get(w, 304), ROLE_OUTPUT, 67108864, ROLE_WORK, 33554432)
    if phase == 8:
        if result != 0:
            put(w, 480, result)
            return unknown(o, w, 3)
        put(w, 336, 1)
        return canonical(w, 9, get(w, 352), get(w, 304), CANON2)
    if phase == 9:
        if result == 0 or result > FILE_MAX:
            return unknown(o, w, 14)
        put(w, 368, result)
        return hash(w, 10, 1, CANON2, result, CORE_AFTER)
    if phase == 10:
        if result != 32:
            return unknown(o, w, 14)
        put(w, 512, get(w, 512) | 8)
        return selection(w, 12, CANON1, get(w, 360), SELECT1)
    if phase == 11:
        if result == 4294967292:
            return profile_failure(o, w)
        if accept_graph(w, result, GRAPH2, 0) == False:
            return unknown(o, w, 14)
        put(w, 384, result)
        n = 16 + 8 * (get(w, GRAPH1 + 16) + get(w, GRAPH1 + 24))
        if same(w, GRAPH1 + 16, GRAPH2 + 16, n) == False or same(w, SIGNATURE1, SIGNATURE2, n - 16) == False:
            return unknown(o, w, 5)
        return begin_solver(o, w)
    if phase == 12:
        if selection_valid(w, SELECT1, result) == False:
            return unknown(o, w, 14)
        put(w, 584, result)
        if get(w, 256) == 2:
            return selection(w, 13, CANON2, get(w, 368), SELECT2)
        return choose_selected(o, w)
    if phase == 13:
        if selection_valid(w, SELECT2, result) == False:
            return unknown(o, w, 14)
        put(w, 592, result)
        return choose_selected(o, w)
    return unknown(o, w, 14)

def selection(w:mutbuf, phase:u64, source:u64, size:u64, output:u64) -> u32:
    n = get(w, 288)
    put(w, output, NONE - 2)
    if n != 0:
        put(w, output, NONE - 3)
        put(w, output + 8, n)
        copy(w, NAME, output + 16, n)
    return dispatch(w, phase, 4, 1, source, size, output, FILE_MAX, ROLE_WORK, 33554432)

def selection_valid(w:mutbuf, at:u64, size:u64) -> bool:
    if size < 128 or size > FILE_MAX or get(w, at) != SELECTION_MAGIC or get(w, at + 72) != size:
        return False
    if get(w, at + 8) > 1 or get(w, at + 32) > 1 or get(w, at + 16) == 0:
        return False
    i = 80
    while i < 128:
        if get(w, at + i) != 0:
            return False
        i = i + 8
    selected = get(w, at + 24)
    parameters = get(w, at + 40)
    returns = get(w, at + 48)
    name = get(w, at + 56)
    signature = get(w, at + 64)
    if selected == NONE:
        return size == 128 and parameters == 0 and returns == 0 and name == 0 and signature == 0 and get(w, at + 32) == 0
    if selected >= get(w, at + 16) or name == 0 or name > 128 or parameters > FILE_MAX // 8 or returns > FILE_MAX // 8:
        return False
    if signature != 8 * (parameters + returns) or 128 + name + signature != size:
        return False
    i = 0
    while i < name:
        c = byte(w, at + 128 + i)
        if ((c >= 65 and c <= 90) or (c >= 97 and c <= 122) or c == 95 or (i != 0 and c >= 48 and c <= 57)) == False:
            return False
        i = i + 1
    if get(w, 288) != 0 and (get(w, 288) != name or same(w, NAME, at + 128, name) == False):
        return False
    i = 0
    while i < signature:
        typ = get(w, at + 128 + name + i)
        if typ > 12 or (typ == 0 and get(w, at + 32) == 1):
            return False
        i = i + 8
    return True

def choose_selected(o:mutbuf, w:mutbuf) -> u32:
    total = get(w, 256) == 1
    if get(w, SELECT1 + 8) == 0 or (total == False and get(w, SELECT2 + 8) == 0):
        return unknown(o, w, 19)
    if get(w, 288) == 0:
        if get(w, SELECT1 + 16) != 1 or (total == False and get(w, SELECT2 + 16) != 1):
            return unknown(o, w, 16)
        if get(w, SELECT1 + 24) == NONE:
            return unknown(o, w, 14)
        n = get(w, SELECT1 + 56)
        copy(w, SELECT1 + 128, NAME, n)
        put(w, 288, n)
    if get(w, SELECT1 + 24) == NONE:
        return unknown(o, w, 16)
    if total == False:
        if get(w, SELECT2 + 24) == NONE or get(w, SELECT2 + 56) != get(w, 288) or same(w, NAME, SELECT2 + 128, get(w, 288)) == False:
            return unknown(o, w, 16)
    if get(w, SELECT1 + 32) == 0 or (total == False and get(w, SELECT2 + 32) == 0):
        return unknown(o, w, 20)
    if total == False:
        if get(w, SELECT1 + 40) != get(w, SELECT2 + 40) or get(w, SELECT1 + 48) != get(w, SELECT2 + 48):
            return unknown(o, w, 5)
        if same(w, SELECT1 + 128 + get(w, SELECT1 + 56), SELECT2 + 128 + get(w, SELECT2 + 56), get(w, SELECT1 + 64)) == False:
            return unknown(o, w, 5)
    return graph(w, 6, CANON1, get(w, 360), GRAPH1)

def profile_failure(o:mutbuf, w:mutbuf) -> u32:
    reason = get(w, ROLE_WORK + 80)
    if reason == 1:
        return unknown(o, w, 19)
    if reason == 2:
        return unknown(o, w, 16)
    if reason == 3:
        return unknown(o, w, 20)
    if reason >= 4 and reason <= 9:
        return unknown(o, w, 17 + reason)
    return unknown(o, w, 14)

def canonical(w:mutbuf, phase:u64, source:u64, size:u64, output:u64) -> u32:
    put(w, ROLE_WORK + 48, 262144)
    put(w, ROLE_WORK + 56, 64)
    return dispatch(w, phase, 3, 0, source, size, output, FILE_MAX, ROLE_WORK, 33554432)

def graph(w:mutbuf, phase:u64, source:u64, size:u64, output:u64) -> u32:
    n = get(w, 288)
    put(w, output, NONE)
    if n != 0:
        put(w, output, NONE - 1)
        put(w, output + 8, n)
        copy(w, NAME, output + 16, n)
    return dispatch(w, phase, 4, 1, source, size, output, GRAPH_CAP, ROLE_WORK, 33554432)

def accept_graph(w:mutbuf, size:u64, base:u64, first:u64) -> bool:
    if size < 56 or size > GRAPH_CAP or get(w, base) != GRAPH_MAGIC or get(w, base + 8) != 1:
        return False
    inputs = get(w, base + 16)
    outputs = get(w, base + 24)
    if inputs > 32 or outputs > 16 or 56 + 8 * (inputs + outputs) > size:
        return False
    at = get(w, ROLE_WORK + 48)
    name = get(w, ROLE_WORK + 56)
    if name == 0 or name > 128 or at > 33554432 or name > 33554432 - at:
        return False
    if get(w, 288) != 0:
        if name != get(w, 288) or same(w, NAME, ROLE_WORK + at, name) == False:
            return False
    else:
        copy(w, ROLE_WORK + at, NAME, name)
        put(w, 288, name)
    signature = get(w, ROLE_WORK + 64)
    signature_count = get(w, ROLE_WORK + 72)
    if signature_count != inputs + outputs or signature > 33554432 or 8 * signature_count > 33554432 - signature:
        return False
    copy(w, ROLE_WORK + signature, choose(first == 1, SIGNATURE1, SIGNATURE2), 8 * signature_count)
    if first == 1:
        put(w, 392, inputs)
        put(w, 400, outputs)
    return True

def begin_solver(o:mutbuf, w:mutbuf) -> u32:
    if get(w, 256) == 1 and structural_totality(w):
        put(w, 408, 1)
        return decided(w, 1, 10)
    if get(w, 256) == 2 and get(w, 376) == get(w, 384) and same(w, GRAPH1, GRAPH2, get(w, 376)):
        put(w, 408, 2)
        return decided(w, 1, 11)
    header = 32 + 8 * (get(w, 392) + get(w, 400))
    size = get(w, 376)
    copy(w, GRAPH1, JOINED, size)
    if get(w, 256) == 2:
        put(w, JOINED + 8, 2)
        copy(w, GRAPH2 + header, JOINED + size, get(w, 384) - header)
        size = size + get(w, 384) - header
    put(w, 416, size)
    if size > 131072:
        return fallback(o, w)
    put(w, 408, 3)
    return dispatch(w, 20, 5, 1, JOINED, size, CIRCUIT, CNF_OUTPUT, ROLE_WORK, CNF_WORK)

def structural_totality(w:mutbuf) -> bool:
    base = GRAPH1
    end = base + get(w, 376)
    at = base + 32 + 8 * (get(w, 392) + get(w, 400))
    if get(w, at) != end - at:
        return False
    blocks = get(w, at + 8)
    at = at + 24
    i = 0
    while i < blocks:
        if at > end or end - at < 64:
            return False
        params = get(w, at)
        ops = get(w, at + 8)
        term = get(w, at + 16)
        left = get(w, at + 40)
        right = get(w, at + 56)
        if term != 1 and term != 3 and term != 4:
            return False
        size = 64 + 8 * (params + left + right) + 48 * ops
        if size > end - at:
            return False
        ins = at + 64 + 8 * params
        j = 0
        while j < ops:
            op = get(w, ins + j * 48)
            if ((op >= 2 and op <= 20) or op == 32) == False:
                return False
            j = j + 1
        at = at + size
        i = i + 1
    return at == end

def solve(o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if phase == 20:
        if result == 4294967292:
            return fallback(o, w)
        if result < 32 or result > CNF_OUTPUT or get(w, CIRCUIT) != CIRCUIT_MAGIC or get(w, CIRCUIT + 24) != 0:
            return unknown(o, w, 14)
        nodes = get(w, CIRCUIT + 8)
        pairs = get(w, CIRCUIT + 16)
        if nodes > 256 or pairs > 16 or result != 32 + 40 * nodes + 16 * pairs:
            return unknown(o, w, 14)
        put(w, 424, result)
        put(w, 432, nodes)
        put(w, 440, pairs)
        put(w, FORMULA, PLAN_MAGIC)
        put(w, FORMULA + 8, (get(w, 272) - now(w)) // 1000000)
        put(w, FORMULA + 16, 0)
        put(w, FORMULA + 24, 0)
        i = 0
        while i < nodes:
            put(w, FORMULA + 32 + 16 * i, get(w, CIRCUIT + 32 + 40 * i))
            put(w, FORMULA + 40 + 16 * i, get(w, CIRCUIT + 40 + 40 * i))
            i = i + 1
        return dispatch(w, 21, 5, 1, FORMULA, 32 + 16 * nodes, MODEL, 32, ROLE_WORK, 0)
    if phase == 21:
        if result != 32 or get(w, MODEL) != PLAN_MAGIC:
            return unknown(o, w, 14)
        steps = get(w, MODEL + 8)
        learning = get(w, MODEL + 16)
        restart = get(w, MODEL + 24)
        if steps == 0 or steps > 10000000 or learning > 1 or restart > 1:
            return unknown(o, w, 14)
        put(w, 448, steps)
        put(w, 456, learning)
        put(w, 464, restart)
        put(w, CIRCUIT + 24, steps)
        return dispatch(w, 22, 5, 1, CIRCUIT, get(w, 424), FORMULA, CNF_FORMULA_CAP, ROLE_WORK, CNF_ENCODE_WORK)
    if phase == 22:
        if result == 4294967292:
            return word_table(o, w)
        if result < 40 or result > CNF_FORMULA_CAP or get(w, FORMULA) != FORMULA_MAGIC:
            return unknown(o, w, 14)
        variables = get(w, FORMULA + 8)
        clauses = get(w, FORMULA + 16)
        entries = get(w, FORMULA + 32)
        if variables > 4096 or clauses > 65536 or entries > 1048576 or result != 40 + 2 * entries or get(w, FORMULA + 24) != get(w, 448):
            return unknown(o, w, 14)
        put(w, 472, variables)
        put(w, 488, clauses)
        copy(w, ROLE_WORK + 32, TOKENS, 128 * get(w, 432))
        work = 28672
        if get(w, 456) == 1 or get(w, 464) == 1:
            put(w, FORMULA, choose(get(w, 464) == 1, RESTART_MAGIC, LEARNING_MAGIC))
            work = 28680 + 8194 * 8 + 2 * (clauses + 4096) * 32 + 602120
        put(w, 544, result)
        put(w, 552, work)
        return hash(w, 31, 1, FORMULA, result, 1248)
    if phase == 23:
        if result < 32 or result > 544 or get(w, MODEL) != SOLVED_MAGIC or get(w, MODEL + 16) != get(w, 472):
            return unknown(o, w, 14)
        verdict = get(w, MODEL + 8)
        cost = get(w, MODEL + 24)
        if verdict > 2 or cost > get(w, 448) or (verdict != 1 and result != 32):
            return unknown(o, w, 14)
        if verdict == 0:
            if cost != get(w, 448):
                return unknown(o, w, 14)
            return word_table(o, w)
        put(w, 576, verdict)
        if verdict == 2:
            return decided(w, 1, choose(get(w, 256) == 1, 10, 11))
        if result != 32 + (get(w, 472) + 7) // 8 or extract_model(w) == False:
            return unknown(o, w, 14)
        return check_witness(w)
    if phase == 24:
        if result != 1:
            return unknown(o, w, 8)
        return project_replay(w, 25, CANON1, get(w, 360))
    return unknown(o, w, 14)

def extract_model(w:mutbuf) -> bool:
    bit = 1
    parameter = 0
    words = 0
    node = 0
    while parameter < get(w, 392):
        typ = get(w, GRAPH1 + 32 + 8 * parameter)
        value = 0
        if typ != 65:
            width = typ & 127
            if width != 1 and width != 8 and width != 16 and width != 32 and width != 64:
                return False
            while node < get(w, 432) and get(w, CIRCUIT + 32 + 40 * node) != 1:
                node = node + 1
            if node == get(w, 432) or get(w, CIRCUIT + 40 + 40 * node) != width:
                return False
            i = 0
            while i < width:
                token = getn(w, TOKENS + 128 * node + 2 * i, 2)
                if token != 2 * (bit + 1) or bit >= get(w, 472):
                    return False
                value = value | (((byte(w, MODEL + 32 + bit // 8) >> (bit & 7)) & 1) << i)
                bit = bit + 1
                i = i + 1
            put(w, WITNESS_WORDS + 8 * words, value)
            words = words + 1
            node = node + 1
        put(w, ARGUMENTS + 8 * parameter, argument_word(value, typ))
        parameter = parameter + 1
    put(w, 496, words)
    return True

def check_witness(w:mutbuf) -> u32:
    size = get(w, 424)
    copy(w, CIRCUIT, FORMULA, size)
    put(w, FORMULA, WITNESS_MAGIC)
    put(w, FORMULA + 24, 0)
    copy(w, WITNESS_WORDS, FORMULA + size, 8 * get(w, 496))
    return dispatch(w, 24, 5, 1, FORMULA, size + 8 * get(w, 496), MODEL, 32, ROLE_WORK, choose(get(w, 432) == 0, 8, 8 * get(w, 432)))

def word_table(o:mutbuf, w:mutbuf) -> u32:
    bits = 0
    i = 0
    while i < get(w, 432):
        if get(w, CIRCUIT + 32 + i * 40) == 1:
            bits = bits + get(w, CIRCUIT + 40 + i * 40)
        i = i + 1
    if bits > 16:
        return fallback(o, w)
    put(w, 504, bits)
    size = get(w, 424)
    copy(w, CIRCUIT, FORMULA, size)
    put(w, FORMULA, TABLE_MAGIC)
    put(w, FORMULA + 24, 0)
    budget = ((get(w, 272) - now(w)) // 1000000) * 16384
    if budget > 33554432:
        budget = 33554432
    put(w, FORMULA + size, budget)
    put(w, 408, 4)
    return hash(w, 32, 1, FORMULA, size, 1248)

def word_table_reply(o:mutbuf, w:mutbuf, result:u64) -> u32:
    if result == 4294967292:
        return fallback(o, w)
    if result != 32 or get(w, MODEL) != TABLE_MAGIC:
        return unknown(o, w, 14)
    verdict = get(w, MODEL + 8)
    assignment = get(w, MODEL + 16)
    checked = get(w, MODEL + 24)
    put(w, 576, verdict)
    put(w, 560, checked)
    if verdict == 2:
        if assignment != 0 or checked != (1 << get(w, 504)):
            return unknown(o, w, 14)
        return decided(w, 1, choose(get(w, 256) == 1, 10, 11))
    if verdict != 1 or assignment >= (1 << get(w, 504)) or checked != assignment + 1:
        return unknown(o, w, 14)
    bit = 0
    parameter = 0
    words = 0
    while parameter < get(w, 392):
        typ = get(w, GRAPH1 + 32 + 8 * parameter)
        value = 0
        if typ != 65:
            width = typ & 127
            value = (assignment >> bit) & mask(width)
            bit = bit + width
            put(w, WITNESS_WORDS + 8 * words, value)
            words = words + 1
        put(w, ARGUMENTS + 8 * parameter, argument_word(value, typ))
        parameter = parameter + 1
    if bit != get(w, 504):
        return unknown(o, w, 14)
    put(w, 496, words)
    return check_witness(w)

def fallback(o:mutbuf, w:mutbuf) -> u32:
    return unknown(o, w, 6)

def project_replay(w:mutbuf, phase:u64, core:u64, size:u64) -> u32:
    store(w, REPLAY_INPUT, 91)
    copy(w, core, REPLAY_INPUT + 1, size)
    at = REPLAY_INPUT + 1 + size
    store(w, at, 44)
    store(w, at + 1, 34)
    copy(w, NAME, at + 2, get(w, 288))
    at = at + 2 + get(w, 288)
    store(w, at, 34)
    store(w, at + 1, 44)
    store(w, at + 2, 48)
    store(w, at + 3, 93)
    return dispatch(w, phase, 6, 1, REPLAY_INPUT, at + 4 - REPLAY_INPUT, REPLAY_WIRE, REPLAY_CAP, ROLE_WORK, 50331648)

def replay(o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if phase == 25 or phase == 28:
        if result < 64 or result > REPLAY_CAP or get(w, REPLAY_WIRE) != WIRE_MAGIC:
            return unknown(o, w, 14)
        registers = get(w, REPLAY_WIRE + 8)
        bounce = get(w, REPLAY_WIRE + 16)
        end = get(w, REPLAY_WIRE + 24)
        count = get(w, REPLAY_WIRE + 32)
        if count != get(w, 400) or end < 64 or result != end + 8 * count or get(w, REPLAY_WIRE + 40) != 0 or get(w, REPLAY_WIRE + 48) != 0 or get(w, REPLAY_WIRE + 56) != 0:
            return unknown(o, w, 14)
        if registers + bounce > 524288 or end > REPLAY_CAP - 8 * get(w, 392):
            return unknown(o, w, 14)
        i = 0
        while i < count:
            if reference_type_identity(get(w, REPLAY_WIRE + end + 8 * i)) != get(w, SIGNATURE1 + 8 * (get(w, 392) + i)):
                return unknown(o, w, 14)
            i = i + 1
        put(w, REPLAY_WIRE, VM_MAGIC)
        put(w, REPLAY_WIRE + 8, 2178)
        put(w, REPLAY_WIRE + 16, 256)
        put(w, REPLAY_WIRE + 24, registers)
        put(w, REPLAY_WIRE + 32, bounce)
        put(w, REPLAY_WIRE + 40, end)
        put(w, REPLAY_WIRE + 48, get(w, 392))
        put(w, REPLAY_WIRE + 56, count)
        copy(w, ARGUMENTS, REPLAY_WIRE + end, 8 * get(w, 392))
        i = 0
        while i < 64:
            put(w, ROLE_WORK + i, 0)
            i = i + 8
        return dispatch(w, choose(phase == 25, 26, 29), 7, 1, REPLAY_WIRE, end + 8 * get(w, 392), choose(phase == 25, OBS1, OBS2), 32 + 8 * count, ROLE_WORK, 64 + 8 * (registers + bounce + 1))
    if phase == 26:
        if observation(w, OBS1, result) == False:
            return unknown(o, w, 14)
        if get(w, 256) == 1:
            if get(w, OBS1 + 8) == 0:
                return unknown(o, w, 8)
            return decided(w, 2, 9)
        return project_replay(w, 28, CANON2, get(w, 368))
    if phase == 29:
        if observation(w, OBS2, result) == False:
            return unknown(o, w, 14)
        left = trap_code(get(w, OBS1 + 8))
        right = trap_code(get(w, OBS2 + 8))
        different = left != right
        if left == 0 and right == 0:
            i = 0
            while i < get(w, 400):
                typ = get(w, GRAPH1 + 32 + 8 * (get(w, 392) + i))
                if typ != 65:
                    width = typ & 127
                    if (get(w, OBS1 + 32 + 8 * i) & mask(width)) != (get(w, OBS2 + 32 + 8 * i) & mask(width)):
                        different = True
                i = i + 1
        if different == False:
            return unknown(o, w, 8)
        return decided(w, 2, 9)
    return unknown(o, w, 14)

def observation(w:mutbuf, at:u64, size:u64) -> bool:
    if size < 32 or get(w, at) != VM_REPLY or get(w, at + 16) > 2179:
        return False
    status = get(w, at + 8)
    if status == 0:
        return size == 32 + 8 * get(w, 400)
    return status != 5 and status != 6 and status <= 11 and size == 32

def trap_code(status:u64) -> u64:
    if status == 0:
        return 0
    if status == 2 or status == 9:
        return 3
    if status == 7:
        return 5
    if status == 10:
        return 2
    if status == 11:
        return 1
    return 4

def decided(w:mutbuf, status:u64, reason:u64) -> u32:
    put(w, 312, status)
    put(w, 320, reason)
    if status == 1:
        put(w, 576, 2)
    if get(w, 568) == 0 and get(w, 376) >= 56:
        return hash(w, 33, 1, GRAPH1, get(w, 376), 1248)
    return hash(w, 90, 2, 0, get(w, 96), HASH_RESULT)

def unknown(o:mutbuf, w:mutbuf, reason:u64) -> u32:
    put(w, 312, 0)
    put(w, 320, reason)
    if reason == 12 or reason == 13:
        put(w, 528, 1)
    if get(w, 520) == 1 and get(w, 0) < 90:
        return hash(w, 90, 2, 0, get(w, 96), HASH_RESULT)
    return receipt(o, w)

def close_identity(w:mutbuf) -> u32:
    at = lit(w, 55000, 89)
    i = 0
    while i < 32:
        value = byte(w, WHOLE_ID + i)
        first = value >> 4
        second = value & 15
        store(w, at, first + choose(first < 10, 48, 87))
        store(w, at + 1, second + choose(second < 10, 48, 87))
        at = at + 2
        i = i + 1
    store(w, at, 34)
    store(w, at + 1, 125)
    return hash(w, 91, 1, 55000, at + 2 - 55000, 1216)

def now(w:mutbuf) -> u64:
    return get(w, 80) * 1000000000 + get(w, 88)

def hash(w:mutbuf, phase:u64, bank:u64, at:u64, size:u64, target:u64) -> u32:
    return dispatch(w, phase, 1, bank, at, size, target, 32, HASH_WORK, 1184)

def dispatch(w:mutbuf, phase:u64, role:u64, bank:u64, at:u64, size:u64, output:u64, capacity:u64, work:u64, extent:u64) -> u32:
    put(w, 0, phase)
    put(w, 8, role)
    put(w, 16, bank)
    put(w, 24, at)
    put(w, 32, size)
    put(w, 40, output)
    put(w, 48, capacity)
    put(w, 56, work)
    put(w, 64, extent)
    return 1

def argument_word(value:u64, typ:u64) -> u64:
    if typ > 128:
        width = typ & 127
        if ((value >> (width - 1)) & 1) != 0:
            return value | (NONE ^ mask(width))
    return value

def mask(width:u64) -> u64:
    if width == 64:
        return NONE
    return (1 << width) - 1

def uint(s:readbuf, at:u64) -> u64:
    result = 0
    i = 0
    while i < 8:
        result = result | (byte(s, at + i) << (8 * i))
        i = i + 1
    return result

def get(w:mutbuf, at:u64) -> u64:
    result = 0
    i = 0
    while i < 8:
        result = result | (byte(w, at + i) << (8 * i))
        i = i + 1
    return result

def getn(w:mutbuf, at:u64, count:u64) -> u64:
    result = 0
    i = 0
    while i < count:
        result = result | (byte(w, at + i) << (8 * i))
        i = i + 1
    return result

def put(w:mutbuf, at:u64, value:u64) -> u64:
    i = 0
    while i < 8:
        store(w, at + i, (value >> (8 * i)) & 255)
        i = i + 1
    return 0

def copy(w:mutbuf, source:u64, target:u64, size:u64) -> u64:
    i = 0
    while i < size:
        store(w, target + i, byte(w, source + i))
        i = i + 1
    return 0

def same(w:mutbuf, first:u64, second:u64, size:u64) -> bool:
    i = 0
    while i < size:
        if byte(w, first + i) != byte(w, second + i):
            return False
        i = i + 1
    return True
'''

LITERALS={
1:'{"schema":',2:'"hepta.hia.scalar-totality.v1"',3:'"hepta.hia.translation-validation.v1"',
4:',"profile":',5:'"hia.scalar-acyclic-bitvector-totality.v1"',6:'"hia.scalar-acyclic-bitvector-traps.v1"',
7:',"status":',8:'"unknown"',9:'"proved"',10:'"disproved"',
11:',"function":',12:'null',13:',"scope":"selected_public_scalar_function"',
14:',"program_sha256":',15:',"input_sha256":',16:',"before_sha256":',17:',"after_sha256":',
18:',"before_input_sha256":',19:',"after_input_sha256":',20:',"validator_sha256":',
21:',"structural_verification":',22:'{"before":',23:',"after":',24:'true',25:'false',
26:',"reason":',27:',"counterexample":',28:'{"arguments":',29:',"parameter_types":',
30:',"observation":',31:',"outcome_tag":',32:',"before":',33:',"after":',
34:'{"status":"returned","values":',35:'{"status":"trapped","code":',
36:'"allocation"',37:'"bounds"',38:'"division_by_zero"',39:'"overflow"',40:'"user"',
41:',"solver":{"name":',42:'"hia-structural-totality"',43:'"hia-native-graph-identity"',
44:'"hia-native-cnf-totality"',45:'"hia-native-cnf-translation"',
46:',"version":"1","result":',47:'"not_run"',48:'"sat"',49:'"unsat"',
50:',"timeout_ms":',51:',"identity":{"native_closure_sha256":',
52:'},"discharge":{"method":',53:'"native_hia_structural_scalar_dag"',
54:'"native_hia_typed_graph_identity"',55:'"native_hia_cnf"',
56:'"native_hia_exhaustive_word_table"',57:',"formula_sha256":',
58:',"nodes":',59:',"variables":',60:',"clauses":',61:',"assignments_checked":',
62:',"claims":{"canonical_core_reverified":',63:',"all_inputs_return_normally_proved":',
64:',"all_input_behavior_equivalence_proved":',65:',"first_trap_code_preserved":',
66:',"resource_bounds_proved":false,"encoder_refinement_machine_proved":false,"whole_language_soundness_proved":false,"backend_refinement_proved":false,"native_backend_refinement_proved":false,"global_optimality_proved":false,"all_programs_of_this_profile_proved":false,"serialized_receipt_authorizes_execution":false}',
67:',"wall_ns":',68:',"execution_authority":false,"proof_scope_schema":"hepta.hia.scalar-proof-scope.v1"',
69:',"subject":{"kind":',70:'"canonical_core"',71:'"canonical_core_comparison"',
72:',"selection":"selected_public_scalar_function"',
73:',"property":',
74:'{"id":"all_input_normal_return","statement":"For every well-typed argument tuple, the selected function reaches a normal Core return with no specified Core trap or missing symbolic outcome."}',
75:'{"id":"all_input_return_and_first_trap_equivalence","statement":"For every well-typed argument tuple, the selected before and after functions have the same return values or the same first specified Core trap code."}',
76:',"checker":{"name":',77:'"hepta.hia_scalar_totality.validate_scalar_totality"',
78:'"hepta.hia_translation_validation.validate_translation"',
79:',"kind":"trusted_executable_hia_scalar_checker","method":',
80:',"source_identity":{"native-closure.image.bin":',81:'},"source_identity_sha256":',
82:',"runtime":{"implementation":"HIA-native","version":"1"},"machine_checked_implementation":false}',
83:',"proved_meaning":"The identified native HIA checker established only the stated property for the exact Core subject within this scalar profile. Implementation soundness, whole-language safety and execution authority are not established."',
84:',"assumptions":[{"id":"typed_inputs","statement":"Every quantified argument has the selected freshly verified Core signature."},{"id":"core_semantics","statement":"The primitive v1-v7 scalar semantics, first-trap ordering and declared profile define observations."},{"id":"trusted_implementation","statement":"The native HIA verifier, graph projection, solver, and independent Core interpreter are trusted implementations, not machine-proved."},{"id":"loaded_source","statement":"The actual embedded native closure is read-only, hashed before and after checking, and executes without hostile process or hardware modification."},{"id":"point_of_use","statement":"Consumers rebind exact inputs and recompute; a serialized receipt grants no execution authority."}]',
85:',"unproved_obligations":[{"id":"checker_soundness","statement":"Machine-checked implementation correctness remains open."},{"id":"whole_language","statement":"Programs and constructs outside this selected scalar profile are not covered."},{"id":"other_exports","statement":"Other public exports require independent checks."},{"id":"core_to_machine","statement":"Compilation and actual machine-code refinement require separate validation."},{"id":"abi_ffi_loading","statement":"ABI, FFI, image custody, mapping and lifetime require separate validation."},{"id":"resources","statement":"Physical resource, instruction, wall-time, energy and performance bounds are not proved."},{"id":"concurrency","statement":"Concurrency, signals, faults, side channels and hostile process modification are outside the proof."}',
86:',{"id":"normal_return_totality","statement":"Equivalence may preserve a trap and does not imply normal return for every input."}',
87:',{"id":"requested_property","statement":"The requested property is not established; inspect the status, reason and any replayed counterexample."}',
88:',"limits":["Only the selected public scalar function is covered.","Acyclic v1-v7 scalar Core; calls, resources and floating point are outside this primitive profile.","All stages use one proof deadline, including admission, encoding, search, replay and identity closure; this is not a hard process timeout.","Exact native code bytes and all externally loaded objects need separate custody and lifetime validation.","A consumer must recompute fresh proof results at the point of use."]',
89:'{"native-closure.image.bin":"',
90:',"request_input_sha256":',91:',"before_request_input_sha256":',92:',"after_request_input_sha256":',
101:'"invalid_solver_timeout"',102:'"invalid_before_program"',103:'"invalid_after_program"',
104:'"native_scalar_profile_unavailable"',105:'"signature_mismatch"',
106:'"native_general_solver_not_yet_connected"',107:'"solver_unknown"',
108:'"counterexample_replay_disagrees_with_encoder"',109:'"behavioral_counterexample_replayed"',
110:'"native_trap_predicate_unsatisfiable"',111:'"all_input_behavior_difference_unsatisfiable"',
112:'"proof_deadline_exhausted"',113:'"scope_checker_identity_changed_or_unavailable"',
114:'"native_proof_component_unavailable"',115:'"invalid_native_proof_layout"',
116:'"missing_or_ambiguous_function"',117:'"nonreturning_counterexample_replayed"',
118:'"native_structural_nontrapping_dag"',
119:'"core_schema_outside_qualified_v1_v7_profile"',120:'"not_a_public_scalar_entrypoint"',
121:'"symbolic_program_budget_exceeded"',122:'"symbolic_signature_budget_exceeded"',
123:'"resource_effects_outside_scalar_profile"',124:'"resource_types_outside_scalar_profile"',
125:'"operation_outside_scalar_profile"',126:'"cyclic_cfg_outside_profile"',127:'"invalid_program"',
201:'"bool"',202:'"unit"',203:'"u8"',204:'"u16"',205:'"u32"',206:'"u64"',
207:'"i8"',208:'"i16"',209:'"i32"',210:'"i64"',211:'"usize"',212:'"isize"',
}
RENDER=r'''
def receipt(o:mutbuf, w:mutbuf) -> u32:
    total = get(w, 256) == 1
    status = get(w, 312)
    at = lit(o, 64, 1)
    at = lit(o, at, choose(total, 2, 3))
    at = lit(o, at, 4)
    at = lit(o, at, choose(total, 5, 6))
    at = lit(o, at, 7)
    at = lit(o, at, 8 + status)
    at = lit(o, at, 11)
    at = function_name(o, w, at)
    at = lit(o, at, 13)
    at = identities(o, w, at)
    at = lit(o, at, 20)
    at = digest(o, w, at, WHOLE_ID, get(w, 520) == 1)
    at = lit(o, at, 21)
    if total:
        at = boolean(o, at, get(w, 328) == 1)
    else:
        at = lit(o, at, 22)
        at = boolean(o, at, get(w, 328) == 1)
        at = lit(o, at, 23)
        at = boolean(o, at, get(w, 336) == 1)
        at = emit(o, at, 125)
    at = lit(o, at, 26)
    reason = get(w, 320)
    if reason == 2 and total:
        reason = 27
    if reason == 9 and total:
        reason = 17
    if reason == 10 and get(w, 408) == 1:
        reason = 18
    at = lit(o, at, 100 + reason)
    at = lit(o, at, 27)
    if status == 2:
        at = counterexample(o, w, at)
    else:
        at = lit(o, at, 12)
    at = solver_report(o, w, at)
    at = lit(o, at, 62)
    verified = get(w, 328) == 1 and (total or get(w, 336) == 1) and get(w, 528) == 0
    at = boolean(o, at, verified)
    if total:
        at = lit(o, at, 63)
        at = boolean(o, at, status == 1)
    else:
        at = lit(o, at, 64)
        at = boolean(o, at, status == 1)
        at = lit(o, at, 65)
        at = boolean(o, at, status == 1)
    at = lit(o, at, 66)
    at = lit(o, at, 67)
    at = unsigned(o, w, at, now(w) - get(w, 264))
    at = lit(o, at, 68)
    at = lit(o, at, 69)
    at = lit(o, at, choose(total, 70, 71))
    at = lit(o, at, 11)
    at = function_name(o, w, at)
    at = lit(o, at, 72)
    at = identities(o, w, at)
    at = emit(o, at, 125)
    at = lit(o, at, 73)
    at = lit(o, at, choose(total, 74, 75))
    at = lit(o, at, 76)
    at = lit(o, at, choose(total, 77, 78))
    at = lit(o, at, 79)
    at = method(o, w, at)
    at = lit(o, at, 80)
    at = digest(o, w, at, WHOLE_ID, get(w, 520) == 1)
    at = lit(o, at, 81)
    at = digest(o, w, at, 1216, get(w, 536) == 1)
    at = lit(o, at, 82)
    at = lit(o, at, 83)
    at = lit(o, at, 84)
    at = lit(o, at, 85)
    if total == False:
        at = lit(o, at, 86)
    if status != 1:
        at = lit(o, at, 87)
    at = emit(o, at, 93)
    at = lit(o, at, 88)
    at = emit(o, at, 125)
    if at > length(o):
        return BAD
    put(o, 0, REPLY_MAGIC)
    put(o, 8, get(w, 256))
    put(o, 16, status)
    put(o, 24, at - 64)
    put(o, 32, now(w) - get(w, 264))
    put(o, 40, 0)
    put(o, 48, 0)
    put(o, 56, 0)
    return at

def identities(o:mutbuf, w:mutbuf, at:u64) -> u64:
    flags = get(w, 512)
    if get(w, 256) == 1:
        at = lit(o, at, 14)
        at = digest(o, w, at, CORE_BEFORE, (flags & 2) != 0)
        at = lit(o, at, 15)
        at = digest(o, w, at, CORE_BEFORE, (flags & 2) != 0)
        at = lit(o, at, 90)
        return digest(o, w, at, RAW_BEFORE, (flags & 1) != 0)
    at = lit(o, at, 16)
    at = digest(o, w, at, CORE_BEFORE, (flags & 2) != 0)
    at = lit(o, at, 17)
    at = digest(o, w, at, CORE_AFTER, (flags & 8) != 0)
    at = lit(o, at, 18)
    at = digest(o, w, at, CORE_BEFORE, (flags & 2) != 0)
    at = lit(o, at, 19)
    at = digest(o, w, at, CORE_AFTER, (flags & 8) != 0)
    at = lit(o, at, 91)
    at = digest(o, w, at, RAW_BEFORE, (flags & 1) != 0)
    at = lit(o, at, 92)
    return digest(o, w, at, RAW_AFTER, (flags & 4) != 0)

def solver_report(o:mutbuf, w:mutbuf, at:u64) -> u64:
    at = lit(o, at, 41)
    method_id = get(w, 408)
    if method_id == 1:
        at = lit(o, at, 42)
    elif method_id == 2:
        at = lit(o, at, 43)
    else:
        at = lit(o, at, choose(get(w, 256) == 1, 44, 45))
    at = lit(o, at, 46)
    at = lit(o, at, 47 + get(w, 576))
    at = lit(o, at, 50)
    at = unsigned(o, w, at, get(w, 280))
    at = lit(o, at, 51)
    at = digest(o, w, at, WHOLE_ID, get(w, 520) == 1)
    at = lit(o, at, 52)
    at = method(o, w, at)
    at = lit(o, at, 57)
    at = digest(o, w, at, 1248, get(w, 568) == 1)
    at = lit(o, at, 58)
    at = unsigned(o, w, at, get(w, 432))
    at = lit(o, at, 59)
    at = unsigned(o, w, at, get(w, 472))
    at = lit(o, at, 60)
    at = unsigned(o, w, at, get(w, 488))
    at = lit(o, at, 61)
    at = unsigned(o, w, at, get(w, 560))
    at = emit(o, at, 125)
    return emit(o, at, 125)

def method(o:mutbuf, w:mutbuf, at:u64) -> u64:
    kind = get(w, 408)
    if kind < 1 or kind > 4:
        return lit(o, at, 47)
    return lit(o, at, 52 + kind)

def function_name(o:mutbuf, w:mutbuf, at:u64) -> u64:
    size = get(w, 288)
    if size == 0:
        return lit(o, at, 12)
    at = emit(o, at, 34)
    i = 0
    while i < size:
        at = emit(o, at, byte(w, NAME + i))
        i = i + 1
    return emit(o, at, 34)

def counterexample(o:mutbuf, w:mutbuf, at:u64) -> u64:
    at = lit(o, at, 28)
    at = values(o, w, at, ARGUMENTS, 0, get(w, 392))
    at = lit(o, at, 29)
    at = emit(o, at, 91)
    i = 0
    while i < get(w, 392):
        if i != 0:
            at = emit(o, at, 44)
        at = lit(o, at, 200 + get(w, SIGNATURE1 + 8 * i))
        i = i + 1
    at = emit(o, at, 93)
    if get(w, 256) == 1:
        at = lit(o, at, 30)
        at = observed(o, w, at, OBS1)
        at = lit(o, at, 31)
        at = unsigned(o, w, at, trap_code(get(w, OBS1 + 8)))
    else:
        at = lit(o, at, 32)
        at = observed(o, w, at, OBS1)
        at = lit(o, at, 33)
        at = observed(o, w, at, OBS2)
    return emit(o, at, 125)

def observed(o:mutbuf, w:mutbuf, at:u64, observation:u64) -> u64:
    if get(w, observation + 8) == 0:
        at = lit(o, at, 34)
        at = values(o, w, at, observation + 32, get(w, 392), get(w, 400))
    else:
        at = lit(o, at, 35)
        at = lit(o, at, 35 + trap_code(get(w, observation + 8)))
    return emit(o, at, 125)

def values(o:mutbuf, w:mutbuf, at:u64, source:u64, type_start:u64, count:u64) -> u64:
    at = emit(o, at, 91)
    i = 0
    while i < count:
        if i != 0:
            at = emit(o, at, 44)
        typ = get(w, GRAPH1 + 32 + 8 * (type_start + i))
        value = get(w, source + 8 * i)
        if typ == 65:
            at = lit(o, at, 12)
        elif typ == 1:
            at = boolean(o, at, value != 0)
        else:
            width = typ & 127
            value = value & mask(width)
            if typ > 128 and ((value >> (width - 1)) & 1) != 0:
                at = emit(o, at, 45)
                value = (0 - value) & mask(width)
            at = unsigned(o, w, at, value)
        i = i + 1
    return emit(o, at, 93)

def boolean(o:mutbuf, at:u64, value:bool) -> u64:
    return lit(o, at, choose(value, 24, 25))

def digest(o:mutbuf, w:mutbuf, at:u64, source:u64, available:bool) -> u64:
    if available == False:
        return lit(o, at, 12)
    at = emit(o, at, 34)
    at = hex_bytes(o, w, at, source, 32)
    return emit(o, at, 34)

def hex_bytes(o:mutbuf, w:mutbuf, at:u64, source:u64, size:u64) -> u64:
    i = 0
    while i < size:
        value = byte(w, source + i)
        first = value >> 4
        second = value & 15
        at = emit(o, at, first + choose(first < 10, 48, 87))
        at = emit(o, at, second + choose(second < 10, 48, 87))
        i = i + 1
    return at

def unsigned(o:mutbuf, w:mutbuf, at:u64, value:u64) -> u64:
    count = 0
    while value >= 10:
        store(w, 768 + count, value % 10 + 48)
        value = value // 10
        count = count + 1
    at = emit(o, at, value + 48)
    while count != 0:
        count = count - 1
        at = emit(o, at, byte(w, 768 + count))
    return at

def emit(o:mutbuf, at:u64, value:u64) -> u64:
    if at < length(o):
        store(o, at, value)
    return at + 1

def putn(o:mutbuf, at:u64, value:u64, count:u64) -> u64:
    i = 0
    while i < count:
        if at + i < length(o):
            store(o, at + i, (value >> (8 * i)) & 255)
        i = i + 1
    return 0
'''

def literal_source():
    groups=[]
    current=[]
    size=0
    for identity,value in sorted(LITERALS.items()):
        raw=value.encode()
        if current and size+len(raw)>1024:
            groups.append(current)
            current=[]
            size=0
        current.append((identity,raw))
        size+=len(raw)
    if current:
        groups.append(current)
    lines=['def lit(o:mutbuf, at:u64, identity:u64) -> u64:']
    for index,group in enumerate(groups):
        lines.extend((f'    if identity <= {group[-1][0]}:',f'        return literal_part_{index}(o, at, identity)'))
    lines.append('    return at')
    for index,group in enumerate(groups):
        lines.extend(('',f'def literal_part_{index}(o:mutbuf, at:u64, identity:u64) -> u64:'))
        for identity,raw in group:
            lines.append(f'    if identity == {identity}:')
            for offset in range(0,len(raw),8):
                part=raw[offset:offset+8]
                lines.append(f'        putn(o, at + {offset}, {int.from_bytes(part,"little")}, {len(part)})')
            lines.append(f'        return at + {len(raw)}')
        lines.append('    return at')
    return '\n'.join(lines)

def source_program():
    from hepta.hia_scalar_reference_wire import TYPES
    rank={name:i+1 for i,name in enumerate(('bool','unit','u8','u16','u32','u64','i8','i16','i32','i64','usize','isize'))}
    types=['def reference_type_identity(value:u64) -> u64:']
    for i,name in enumerate(TYPES):
        types.extend((f'    if value == {i}:',f'        return {rank[name]}'))
    types.append('    return 0')
    body=POLICY+'\n'+RENDER+'\n'+literal_source()+'\n'+'\n'.join(types)
    for key in sorted(C,key=len,reverse=True):
        body=re.sub(r'\b'+key+r'\b',str(C[key]),body)
    return body

def program():
    return document(source_program(),'native_scalar_proof_policy')

if __name__=='__main__':
    (ROOT/SOURCE).write_text(render_assembly(program()))
