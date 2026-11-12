"""Pure HIA stateful Code encoder and independent value finalizer.
New authoring: no host opcode, branch-displacement or relocation encoding.
"""
import ast
from hashlib import sha256

def magic(text):
    return int.from_bytes(text.encode("ascii"), "little")

REFERENCE_SHA="8795fb4e5034673401f5f6a5a60e57872c48a3982dbdcb4d3b8198ee7b3f41a9"
REGISTERS=("rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi",
           "r8","r9","r10","r11","r12","r13","r14","r15")
CONDITIONS={"o":0,"no":1,"b":2,"c":2,"nae":2,"ae":3,"nb":3,"nc":3,
 "e":4,"z":4,"ne":5,"nz":5,"be":6,"na":6,"a":7,"nbe":7,"s":8,"ns":9,
 "p":10,"pe":10,"np":11,"po":11,"l":12,"nge":12,"ge":13,"nl":13,
 "le":14,"ng":14,"g":15,"nle":15}
OPERATIONS=("init","align","offset","emit","label","jmp","jcc","call",
 "mov_rr","mov_imm","load","store","lea","load_u8","store_u8",
 "add","sub","and_","or_","xor","cmp","test","alu_imm","shift","shift_imm",
 "shift_cl","shl","shr","sar","imul","imul_rr","mul","imul_full","div","idiv",
 "neg","bitnot","cqo","setcc","cmov","push","pop","ret","leave","ud2","finalize")
ARITIES=(3,1,0,1,1,1,2,1,2,2,3,3,3,3,3,2,2,2,2,2,2,2,3,3,3,2,2,2,2,2,2,1,1,1,1,1,1,0,2,3,1,1,0,0,0,0)
ERRORS=("unknown x86-64 register","operand is outside signed disp32/imm32",
 "unknown x86-64 condition","scratch registers must bijectively rename r10/r11",
 "unreviewed immediate move selection","unreviewed immediate arithmetic selection",
 "unreviewed function alignment","encoded instructions must be bytes",
 "x86-64 image exceeds code byte limit","empty, oversized or duplicate machine label",
 "invalid branch target","invalid call symbol","immediate is outside the 64-bit word",
 "unsupported immediate ALU operation","unsupported shift operation",
 "shift count must be 0..63 or cl","unresolved machine label: ")
CONSTANTS=dict(MAX=(1<<64)-1,BAD=0xfffffffd,GROW=0xfffffffe,
 MIN_WORK=4096,MAX_CODE=67108864,CODE_BASE=64,
 COMMAND=magic("HIAXCC01"),GRAPH=magic("HIAXGR01"),STATE=magic("HIAXMS01"),
 CODE=magic("HIAXCS01"),EVENT=magic("HIAXCE01"),FINAL_EVENT=magic("HIAXFE01"),
 OUTPUT_GRAPH=magic("HIAGRF01"),INDEX=640,LITERAL_DATA=2048,PLAN=3072,
 REGISTRY=magic("HIAXRG01"),FIXUP=magic("HIAXFX01"),RELOCATION=magic("HIAXRL01"),FINAL_TEXT=1024,
 MAX_REL_GRAPH=((1<<64)-10)//9)
PERSIST=("MAGIC","LEASE","SEQ","POISON","ALIVE","USED","CODE_N","TREE","REG_N",
 "LABEL_N","FIX_HEAD","FIX_TAIL","FIX_N","REL_HEAD","REL_TAIL","REL_N",
 "SWAP","MOVE","ALU","LAST_OP")
SCRATCH=("BAD","ERROR","LEASE","SEQ","OP","NODES","EDGES","DATABASE","ROOT",
 "A0","A1","A2","FIRST","SECOND","PLAN_MODE","RAW_AT","NAME_AT","NAME_N",
 "NAME_CHARS","FOUND","PARENT","SIDE","RECORD","NEW_CODE","NEW_USED","LATE",
 "NEED_CODE","NEED_WORK","VALUE","INIT_SWAP","INIT_MOVE","INIT_ALU")
CONSTANTS.update({"P_"+v:128+i*8 for i,v in enumerate(PERSIST)})
CONSTANTS.update({"S_"+v:320+i*8 for i,v in enumerate(SCRATCH)})
LITERALS={**{"error"+str(i+1):s for i,s in enumerate(ERRORS)},
 **{"reg_"+s:s for s in REGISTERS},**{"cc_"+s:s for s in CONDITIONS},
 "movabs":"movabs","movcompact":"mov32_if_exact","imm32":"imm32",
 "immcompact":"imm8_if_exact","add":"add","or":"or","and":"and","sub":"sub",
 "xor":"xor","cmp":"cmp","shl":"shl","shr":"shr","sar":"sar","cl":"cl",
 "offset":"offset","symbol":"symbol","type":"type","addend":"addend"}

ENCODER=r'''
def encode_command(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < MIN_WORK:
        return BAD
    fill_range(w, 0, 128, 0)
    fill_range(w, 320, MIN_WORK - 320, 0)
    literal_table(w)
    if get(w, P_POISON) != 0:
        abi(w, 1)
    elif frame(s, w) != 0:
        if session(o, w) != 0:
            if operands(s, w) != 0:
                plan_command(s, w)
                if get(w, S_BAD) == 0 and get(w, S_ERROR) == 0:
                    reserve(s, o, w)
                    if get(w, S_BAD) == 0 and get(w, S_NEED_CODE) <= length(o) and get(w, S_NEED_WORK) <= length(w):
                        commit(s, o, w)
    if get(w, S_BAD) != 0:
        event(w, 3)
        return BAD
    if get(w, S_NEED_CODE) > length(o) or get(w, S_NEED_WORK) > length(w):
        event(w, 1)
        return GROW
    if get(w, S_ERROR) != 0:
        completed(o, w)
        event(w, 2)
        return 128
    completed(o, w)
    if get(w, S_OP) == 45:
        event(w, 4)
    else:
        event(w, 0)
    return 128

def abi(w:mutbuf, reason:u64) -> u64:
    if get(w, S_BAD) == 0:
        put(w, S_BAD, reason)
    put(w, P_POISON, 1)
    return 0

def error(w:mutbuf, reason:u64) -> u64:
    if get(w, S_ERROR) == 0:
        put(w, S_ERROR, reason)
    return 0

def event(w:mutbuf, action:u64) -> u64:
    at = 0
    count = 0
    if action == 2:
        row = INDEX + (get(w, S_ERROR) - 1) * 16
        at = get(w, row)
        count = get(w, row + 8)
    put(w, 0, EVENT)
    put(w, 8, 1)
    put(w, 16, action)
    put(w, 24, get(w, S_LEASE))
    put(w, 32, get(w, S_SEQ))
    put(w, 40, get(w, S_OP))
    put(w, 48, choose(action == 2, get(w, S_ERROR), 0))
    put(w, 56, get(w, S_NEED_CODE))
    put(w, 64, get(w, S_NEED_WORK))
    put(w, 72, get(w, P_CODE_N))
    put(w, 80, get(w, P_LABEL_N))
    put(w, 88, get(w, P_FIX_N))
    put(w, 96, get(w, P_REL_N))
    put(w, 104, at)
    put(w, 112, count)
    put(w, 120, get(w, S_BAD))
    return 0

def frame(s:readbuf, w:mutbuf) -> u64:
    if length(s) < 128:
        return abi(w, 2)
    if word(s, 0) != COMMAND or word(s, 8) != 1 or word(s, 16) == 0 or word(s, 24) == 0:
        return abi(w, 3)
    if word(s, 32) > 45 or word(s, 40) != length(s) - 64 or word(s, 56) != 0:
        return abi(w, 4)
    if word(s, 64) != GRAPH or word(s, 72) != word(s, 16) or word(s, 120) != 0:
        return abi(w, 5)
    nodes = word(s, 80)
    edges = word(s, 96)
    if nodes == 0 or nodes > (MAX - 128) >> 6:
        return abi(w, 6)
    end = 128 + nodes * 64
    if edges > (MAX - end) >> 3:
        return abi(w, 7)
    end = end + edges * 8
    if end > length(s) or word(s, 104) != length(s) - end or word(s, 112) != length(s) - 64:
        return abi(w, 8)
    root = word(s, 88)
    if root == 0 or root > nodes or word(s, 48) != root:
        return abi(w, 9)
    put(w, S_LEASE, word(s, 16))
    put(w, S_SEQ, word(s, 24))
    put(w, S_OP, word(s, 32))
    put(w, S_NODES, nodes)
    put(w, S_EDGES, edges)
    put(w, S_DATABASE, end)
    put(w, S_ROOT, root)
    return 1

def session(o:mutbuf, w:mutbuf) -> u64:
    if get(w, S_OP) == 0:
        if get(w, S_SEQ) != 1:
            return abi(w, 10)
        at = 128
        while at < 288:
            if get(w, at) != 0:
                return abi(w, 11)
            at = at + 8
        at = 0
        while at < length(o) and at < 64:
            if byte(o, at) != 0:
                return abi(w, 12)
            at = at + 1
        return 1
    if get(w, P_MAGIC) != STATE or get(w, P_ALIVE) != 1 or get(w, P_LEASE) != get(w, S_LEASE):
        return abi(w, 13)
    if get(w, P_SEQ) == MAX or get(w, S_SEQ) != get(w, P_SEQ) + 1:
        return abi(w, 14)
    if get(w, P_USED) < MIN_WORK or get(w, P_USED) > length(w) or (get(w, P_USED) & 7) != 0:
        return abi(w, 15)
    if get(w, P_CODE_N) > MAX_CODE or length(o) < CODE_BASE or get(w, P_CODE_N) > length(o) - CODE_BASE:
        return abi(w, 16)
    if get(o, 0) != CODE or get(o, 8) != get(w, P_LEASE) or get(o, 16) != get(w, P_SEQ) or get(o, 24) != get(w, P_CODE_N):
        return abi(w, 17)
    at = 32
    while at < 64:
        if get(o, at) != 0:
            return abi(w, 18)
        at = at + 8
    if get(w, P_SWAP) > 1 or get(w, P_MOVE) > 1 or get(w, P_ALU) > 1 or get(w, P_LABEL_N) > get(w, P_REG_N):
        return abi(w, 19)
    return 1

def node(s:readbuf, w:mutbuf, identifier:u64) -> u64:
    if identifier == 0 or identifier > get(w, S_NODES):
        return abi(w, 20)
    at = 128 + (identifier - 1) * 64
    kind = word(s, at)
    if kind > 11 or word(s, at + 56) != 0:
        return abi(w, 21)
    first = word(s, at + 24)
    count = word(s, at + 32)
    if kind == 5 or kind == 6 or kind == 7:
        if word(s, at + 8) != 0 or word(s, at + 16) != 0 or word(s, at + 40) == 0 or word(s, at + 48) != 0:
            return abi(w, 22)
        if kind == 6:
            if count > MAX >> 1:
                return abi(w, 23)
            count = count * 2
        if first > get(w, S_EDGES) or count > get(w, S_EDGES) - first:
            return abi(w, 24)
        return at
    if first != 0 or count != 0 or word(s, at + 40) != 0:
        return abi(w, 25)
    begin = word(s, at + 8)
    count = word(s, at + 16)
    aux = word(s, at + 48)
    if kind == 0 or kind == 1 or kind == 8:
        if begin != 0 or count != 0 or (kind == 1 and aux > 1) or (kind != 1 and aux != 0):
            return abi(w, 26)
        return at
    if begin > MAX - 64:
        return abi(w, 27)
    begin = begin + 64
    if begin < get(w, S_DATABASE) or begin > length(s) or count > length(s) - begin:
        return abi(w, 28)
    if kind == 2:
        if aux > 1 or (count == 0 and aux != 0):
            return abi(w, 29)
        if count > 0 and byte(s, begin + count - 1) == 0:
            return abi(w, 30)
    elif kind == 3:
        if count != 8 or aux != 0:
            return abi(w, 31)
    elif kind == 9 or kind == 10:
        if aux != 0:
            return abi(w, 32)
    return at

def edge(s:readbuf, w:mutbuf, at:u64, index:u64) -> u64:
    count = word(s, at + 32)
    if word(s, at) == 6:
        count = count * 2
    if index >= count:
        return abi(w, 33)
    result = word(s, 128 + get(w, S_NODES) * 64 + (word(s, at + 24) + index) * 8)
    if result == 0 or result > get(w, S_NODES):
        return abi(w, 34)
    return result

def operands(s:readbuf, w:mutbuf) -> u64:
    at = node(s, w, get(w, S_ROOT))
    if at == 0:
        return 0
    count = arity(get(w, S_OP))
    if word(s, at) != 5 or word(s, at + 32) != count:
        return abi(w, 35)
    i = 0
    while i < count:
        put(w, S_A0 + i * 8, edge(s, w, at, i))
        i = i + 1
    return choose(get(w, S_BAD) == 0, 1, 0)

def unicode_count(s:readbuf, w:mutbuf, at:u64, count:u64) -> u64:
    end = at + count
    points = 0
    while at < end:
        first = byte(s, at)
        width = 1
        if first >= 128:
            if first >= 194 and first <= 223:
                width = 2
            elif first >= 224 and first <= 239:
                width = 3
            elif first >= 240 and first <= 244:
                width = 4
            else:
                return abi(w, 36)
        if width > end - at:
            return abi(w, 37)
        i = 1
        while i < width:
            part = byte(s, at + i)
            if part < 128 or part > 191:
                return abi(w, 38)
            i = i + 1
        if width > 1:
            second = byte(s, at + 1)
            if (first == 224 and second < 160) or (first == 240 and second < 144) or (first == 244 and second > 143):
                return abi(w, 39)
        points = points + 1
        at = at + width
    return points

def literal_equal(s:readbuf, w:mutbuf, at:u64, literal:u64, subclass:u64) -> u64:
    kind = word(s, at)
    if kind != 4 and (subclass == 0 or kind != 11):
        return 0
    row = INDEX + literal * 16
    count = get(w, row + 8)
    if word(s, at + 16) != count:
        return 0
    i = 0
    while i < count:
        if byte(s, 64 + word(s, at + 8) + i) != byte(w, get(w, row) + i):
            return 0
        i = i + 1
    if word(s, at + 48) != count:
        return abi(w, 40)
    return 1

def integer(s:readbuf, w:mutbuf, identifier:u64, mode:u64, reason:u64) -> u64:
    at = node(s, w, identifier)
    if at == 0:
        return 0
    if word(s, at) != 2 or word(s, at + 16) > 8:
        return error(w, reason)
    size = word(s, at + 16)
    value = 0
    i = 0
    while i < size:
        value = value | (byte(s, 64 + word(s, at + 8) + i) << (i * 8))
        i = i + 1
    negative = word(s, at + 48)
    if mode == 1:
        if (negative == 0 and value >= 2147483648) or (negative != 0 and value > 2147483648):
            return error(w, reason)
    elif mode == 2:
        if negative != 0 and value > 9223372036854775808:
            return error(w, reason)
    elif negative != 0:
        return error(w, reason)
    if negative != 0:
        value = 0 - value
    return value

def name(s:readbuf, w:mutbuf, identifier:u64, symbol:u64, reason:u64) -> u64:
    at = node(s, w, identifier)
    if at == 0:
        return 0
    if word(s, at) != 4 or word(s, at + 16) == 0:
        return error(w, reason)
    begin = 64 + word(s, at + 8)
    size = word(s, at + 16)
    points = unicode_count(s, w, begin, size)
    if get(w, S_BAD) != 0:
        return 0
    if points != word(s, at + 48):
        return abi(w, 41)
    if symbol == 0:
        if points > 512:
            return error(w, reason)
    else:
        if size > 192:
            return error(w, reason)
        i = 0
        while i < size:
            c = byte(s, begin + i)
            alpha = c == 95 or (c >= 65 and c <= 90) or (c >= 97 and c <= 122)
            if alpha == False and (i == 0 or c < 48 or c > 57):
                return error(w, reason)
            i = i + 1
    put(w, S_NAME_AT, begin)
    put(w, S_NAME_N, size)
    put(w, S_NAME_CHARS, points)
    return 1

def get(w:mutbuf, at:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(w, at + i) << (i * 8))
        i = i + 1
    return value

def word(s:readbuf, at:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(s, at + i) << (i * 8))
        i = i + 1
    return value

def put(w:mutbuf, at:u64, value:u64) -> u64:
    i = 0
    while i < 8:
        store(w, at + i, (value >> (i * 8)) & 255)
        i = i + 1
    return 0
'''


ENCODER+=r'''
def register(s:readbuf, w:mutbuf, identifier:u64) -> u64:
    at = node(s, w, identifier)
    if at == 0:
        return 0
    index = 0
    while index < 16:
        if literal_equal(s, w, at, L_REG0 + index, 0) != 0:
            if get(w, P_SWAP) != 0 and (index == 10 or index == 11):
                index = index ^ 1
            return index
        index = index + 1
    return error(w, 1)

def condition(s:readbuf, w:mutbuf, identifier:u64) -> u64:
    at = node(s, w, identifier)
    if at == 0:
        return 0
    index = 0
    while index < 30:
        if literal_equal(s, w, at, L_CC0 + index, 0) != 0:
            return condition_value(index)
        index = index + 1
    return error(w, 3)

def named_choice(s:readbuf, w:mutbuf, identifier:u64, first:u64, second:u64, reason:u64) -> u64:
    at = node(s, w, identifier)
    if at == 0:
        return 0
    if literal_equal(s, w, at, first, 0) != 0:
        return 0
    if literal_equal(s, w, at, second, 0) != 0:
        return 1
    return error(w, reason)

def initialize(s:readbuf, w:mutbuf) -> u64:
    mapping = node(s, w, get(w, S_A0))
    if mapping == 0:
        return 0
    if word(s, mapping) != 0:
        if word(s, mapping) != 6 or word(s, mapping + 32) != 2:
            return error(w, 4)
        keys = 0
        values = 0
        swap = 0
        index = 0
        while index < 2:
            key = node(s, w, edge(s, w, mapping, index * 2))
            value = node(s, w, edge(s, w, mapping, index * 2 + 1))
            if key == 0 or value == 0:
                return 0
            k = 0
            v = 0
            if literal_equal(s, w, key, L_REG0 + 10, 1) != 0:
                k = 1
            elif literal_equal(s, w, key, L_REG0 + 11, 1) != 0:
                k = 2
            if literal_equal(s, w, value, L_REG0 + 10, 0) != 0:
                v = 1
            elif literal_equal(s, w, value, L_REG0 + 11, 0) != 0:
                v = 2
            if k == 0 or v == 0:
                return error(w, 4)
            keys = keys | k
            values = values | v
            if k != v:
                swap = 1
            index = index + 1
        if keys != 3 or values != 3:
            return error(w, 4)
        put(w, S_INIT_SWAP, swap)
    move = named_choice(s, w, get(w, S_A1), L_MOVABS, L_MOVCOMPACT, 5)
    if get(w, S_ERROR) != 0 or get(w, S_BAD) != 0:
        return 0
    alu = named_choice(s, w, get(w, S_A2), L_IMM32, L_IMMCOMPACT, 6)
    put(w, S_INIT_MOVE, move)
    put(w, S_INIT_ALU, alu)
    return 0

def planned_byte(w:mutbuf, value:u64) -> u64:
    at = get(w, S_FIRST)
    if at >= 32:
        return abi(w, 42)
    store(w, PLAN + at, value & 255)
    put(w, S_FIRST, at + 1)
    return 0

def planned_integer(w:mutbuf, value:u64, count:u64) -> u64:
    i = 0
    while i < count:
        planned_byte(w, value >> (i * 8))
        i = i + 1
    return 0

def move_plan(w:mutbuf, reg:u64, value:u64) -> u64:
    if get(w, P_MOVE) != 0 and value < 4294967296:
        if reg >= 8:
            planned_byte(w, 65)
        planned_byte(w, 184 + (reg & 7))
        planned_integer(w, value, 4)
    else:
        planned_byte(w, 72 | (reg >> 3))
        planned_byte(w, 184 + (reg & 7))
        planned_integer(w, value, 8)
    return 0

def rr_plan(s:readbuf, w:mutbuf, regid:u64, rmid:u64, opcode:u64, extra:u64) -> u64:
    r = register(s, w, regid)
    if get(w, S_BAD) != 0 or get(w, S_ERROR) != 0:
        return 0
    m = register(s, w, rmid)
    if get(w, S_BAD) != 0 or get(w, S_ERROR) != 0:
        return 0
    planned_byte(w, 72 | ((r >> 3) << 2) | (m >> 3))
    if extra != 0:
        planned_byte(w, 15)
    planned_byte(w, opcode)
    planned_byte(w, 192 | ((r & 7) << 3) | (m & 7))
    return 0

def mem_plan(s:readbuf, w:mutbuf, op:u64) -> u64:
    regid = get(w, S_A0)
    baseid = get(w, S_A1)
    dispid = get(w, S_A2)
    if op == 11 or op == 14:
        regid = get(w, S_A2)
        baseid = get(w, S_A0)
        dispid = get(w, S_A1)
    r = register(s, w, regid)
    if get(w, S_BAD) != 0 or get(w, S_ERROR) != 0:
        return 0
    b = register(s, w, baseid)
    if get(w, S_BAD) != 0 or get(w, S_ERROR) != 0:
        return 0
    displacement = integer(s, w, dispid, 1, 2)
    if get(w, S_BAD) != 0 or get(w, S_ERROR) != 0:
        return 0
    rex = choose(op == 14, 64, 72)
    planned_byte(w, rex | ((r >> 3) << 2) | (b >> 3))
    opcode = 139
    if op == 11:
        opcode = 137
    elif op == 12:
        opcode = 141
    elif op == 13:
        opcode = 182
        planned_byte(w, 15)
    elif op == 14:
        opcode = 136
    planned_byte(w, opcode)
    planned_byte(w, 128 | ((r & 7) << 3) | (b & 7))
    if (b & 7) == 4:
        planned_byte(w, 36)
    planned_integer(w, displacement, 4)
    return 0

def alu_plan(s:readbuf, w:mutbuf) -> u64:
    at = node(s, w, get(w, S_A0))
    if at == 0:
        return 0
    group = MAX
    if literal_equal(s, w, at, L_ADD, 0) != 0:
        group = 0
    elif literal_equal(s, w, at, L_OR, 0) != 0:
        group = 1
    elif literal_equal(s, w, at, L_AND, 0) != 0:
        group = 4
    elif literal_equal(s, w, at, L_SUB, 0) != 0:
        group = 5
    elif literal_equal(s, w, at, L_XOR, 0) != 0:
        group = 6
    elif literal_equal(s, w, at, L_CMP, 0) != 0:
        group = 7
    if group == MAX:
        return error(w, 14)
    r = register(s, w, get(w, S_A1))
    if get(w, S_BAD) != 0 or get(w, S_ERROR) != 0:
        return 0
    value = integer(s, w, get(w, S_A2), 1, 2)
    if get(w, S_BAD) != 0 or get(w, S_ERROR) != 0:
        return 0
    compact = get(w, P_ALU) != 0 and (value <= 127 or value >= MAX - 127)
    planned_byte(w, 72 | (r >> 3))
    planned_byte(w, choose(compact, 131, 129))
    planned_byte(w, 192 | (group << 3) | (r & 7))
    planned_integer(w, value, choose(compact, 1, 4))
    return 0

def shift_plan(s:readbuf, w:mutbuf, op:u64) -> u64:
    group = 0
    regid = get(w, S_A0)
    countid = get(w, S_A1)
    if op <= 25:
        at = node(s, w, get(w, S_A0))
        if at == 0:
            return 0
        if literal_equal(s, w, at, L_SHL, 0) != 0:
            group = 4
        elif literal_equal(s, w, at, L_SHR, 0) != 0:
            group = 5
        elif literal_equal(s, w, at, L_SAR, 0) != 0:
            group = 7
        else:
            return error(w, 15)
        regid = get(w, S_A1)
        countid = get(w, S_A2)
    else:
        group = choose(op == 26, 4, choose(op == 27, 5, 7))
    r = register(s, w, regid)
    if get(w, S_BAD) != 0 or get(w, S_ERROR) != 0:
        return 0
    is_cl = op == 25
    value = 0
    if is_cl == False:
        at = node(s, w, countid)
        if at == 0:
            return 0
        is_cl = literal_equal(s, w, at, L_CL, 1) != 0
        if is_cl == False:
            value = integer(s, w, countid, 3, 16)
            if get(w, S_BAD) != 0 or get(w, S_ERROR) != 0:
                return 0
            if value >= 64:
                return error(w, 16)
    planned_byte(w, 72 | (r >> 3))
    planned_byte(w, choose(is_cl, 211, 193))
    planned_byte(w, 192 | (group << 3) | (r & 7))
    if is_cl == False:
        planned_byte(w, value)
    return 0

def label_plan(s:readbuf, w:mutbuf, op:u64) -> u64:
    identifier = get(w, S_A0)
    cc = 0
    if op == 6:
        cc = condition(s, w, identifier)
        if get(w, S_BAD) != 0 or get(w, S_ERROR) != 0:
            return 0
        identifier = get(w, S_A1)
    reason = choose(op == 4, 10, choose(op == 7, 12, 11))
    if name(s, w, identifier, choose(op == 7, 1, 0), reason) == 0:
        return 0
    found = lookup(s, w)
    if get(w, S_BAD) != 0:
        return 0
    if op == 4:
        if found != 0 and get(w, found + 32) != 0:
            return error(w, 10)
        put(w, S_RECORD, 3)
        return 0
    if op == 5:
        planned_byte(w, 233)
    elif op == 6:
        planned_byte(w, 15)
        planned_byte(w, 128 + cc)
    else:
        planned_byte(w, 232)
    put(w, S_SECOND, 4)
    put(w, S_RECORD, choose(op == 7, 2, 1))
    return 0

def ordinary_plan(s:readbuf, w:mutbuf, op:u64) -> u64:
    if op == 9:
        r = register(s, w, get(w, S_A0))
        if get(w, S_BAD) != 0 or get(w, S_ERROR) != 0:
            return 0
        value = integer(s, w, get(w, S_A1), 2, 13)
        if get(w, S_BAD) == 0 and get(w, S_ERROR) == 0:
            move_plan(w, r, value)
        return 0
    if op == 38:
        cc = condition(s, w, get(w, S_A0))
        if get(w, S_BAD) != 0 or get(w, S_ERROR) != 0:
            return 0
        r = register(s, w, get(w, S_A1))
        if get(w, S_BAD) != 0 or get(w, S_ERROR) != 0:
            return 0
        move_plan(w, r, 0)
        count = get(w, S_FIRST)
        planned_byte(w, 64 | (r >> 3))
        planned_byte(w, 15)
        planned_byte(w, 144 + cc)
        planned_byte(w, 192 | (r & 7))
        put(w, S_FIRST, count)
        put(w, S_SECOND, 4)
        return 0
    if op == 39:
        cc = condition(s, w, get(w, S_A0))
        if get(w, S_BAD) != 0 or get(w, S_ERROR) != 0:
            return 0
        return rr_plan(s, w, get(w, S_A1), get(w, S_A2), 64 + cc, 1)
    if op == 8:
        return rr_plan(s, w, get(w, S_A1), get(w, S_A0), 137, 0)
    if op >= 15 and op <= 21:
        return rr_plan(s, w, get(w, S_A1), get(w, S_A0), rr_opcode(op), 0)
    if op == 29 or op == 30:
        return rr_plan(s, w, get(w, S_A0), get(w, S_A1), 175, 1)
    if op >= 31 and op <= 36:
        r = register(s, w, get(w, S_A0))
        if get(w, S_BAD) != 0 or get(w, S_ERROR) != 0:
            return 0
        group = choose(op <= 34, op - 27, choose(op == 35, 3, 2))
        planned_byte(w, 72 | (r >> 3))
        planned_byte(w, 247)
        planned_byte(w, 192 | (group << 3) | (r & 7))
        return 0
    if op == 40 or op == 41:
        r = register(s, w, get(w, S_A0))
        if get(w, S_BAD) != 0 or get(w, S_ERROR) != 0:
            return 0
        if r >= 8:
            planned_byte(w, 65)
        planned_byte(w, choose(op == 40, 80, 88) + (r & 7))
        return 0
    if op == 37:
        planned_byte(w, 72)
        planned_byte(w, 153)
    elif op == 42:
        planned_byte(w, 195)
    elif op == 43:
        planned_byte(w, 201)
    elif op == 44:
        planned_byte(w, 15)
        planned_byte(w, 11)
    return 0

def plan_command(s:readbuf, w:mutbuf) -> u64:
    op = get(w, S_OP)
    if op == 0:
        return initialize(s, w)
    if op == 1:
        boundary = integer(s, w, get(w, S_A0), 3, 7)
        if get(w, S_BAD) != 0 or get(w, S_ERROR) != 0:
            return 0
        if boundary != 1 and boundary != 16 and boundary != 32 and boundary != 64:
            return error(w, 7)
        put(w, S_FIRST, (0 - get(w, P_CODE_N)) & (boundary - 1))
        put(w, S_PLAN_MODE, 2)
        return 0
    if op == 2 or op == 45:
        return 0
    if op == 3:
        at = node(s, w, get(w, S_A0))
        if at == 0:
            return 0
        if word(s, at) != 9 and word(s, at) != 10:
            return error(w, 8)
        put(w, S_FIRST, word(s, at + 16))
        put(w, S_RAW_AT, 64 + word(s, at + 8))
        put(w, S_PLAN_MODE, 1)
        return 0
    if op >= 4 and op <= 7:
        return label_plan(s, w, op)
    if op >= 10 and op <= 14:
        return mem_plan(s, w, op)
    if op == 22:
        return alu_plan(s, w)
    if op >= 23 and op <= 28:
        return shift_plan(s, w, op)
    return ordinary_plan(s, w, op)
'''


ENCODER+=r'''
def registry_node(w:mutbuf, at:u64) -> u64:
    used = get(w, P_USED)
    if at < MIN_WORK or (at & 7) != 0 or at > used or used - at < 80:
        return abi(w, 43)
    begin = get(w, at)
    size = get(w, at + 8)
    if begin != at + 80 or size == 0 or size > 2048 or size > used - begin:
        return abi(w, 44)
    if get(w, at + 16) == 0 or get(w, at + 16) > 512 or get(w, at + 32) > 1:
        return abi(w, 45)
    if get(w, at + 24) > MAX_CODE or get(w, at + 56) == 0 or get(w, at + 56) > get(w, P_REG_N):
        return abi(w, 46)
    if get(w, at + 72) != REGISTRY:
        return abi(w, 47)
    return at

def lookup(s:readbuf, w:mutbuf) -> u64:
    current = get(w, P_TREE)
    parent = 0
    side = 0
    steps = 0
    while current != 0:
        if steps >= get(w, P_REG_N) or registry_node(w, current) == 0:
            return abi(w, 48)
        size = get(w, current + 8)
        common = choose(size < get(w, S_NAME_N), size, get(w, S_NAME_N))
        index = 0
        relation = 0
        while index < common and relation == 0:
            left = byte(s, get(w, S_NAME_AT) + index)
            right = byte(w, get(w, current) + index)
            if left < right:
                relation = 1
            elif left > right:
                relation = 2
            index = index + 1
        if relation == 0:
            if get(w, S_NAME_N) < size:
                relation = 1
            elif get(w, S_NAME_N) > size:
                relation = 2
        if relation == 0:
            put(w, S_FOUND, current)
            return current
        parent = current
        side = choose(relation == 1, 0, 1)
        current = get(w, current + 40 + side * 8)
        steps = steps + 1
    put(w, S_PARENT, parent)
    put(w, S_SIDE, side)
    return 0

def height(w:mutbuf, at:u64) -> u64:
    if at == 0:
        return 0
    if registry_node(w, at) == 0:
        return 0
    return get(w, at + 56)

def update_height(w:mutbuf, at:u64) -> u64:
    left = height(w, get(w, at + 40))
    right = height(w, get(w, at + 48))
    put(w, at + 56, choose(left > right, left, right) + 1)
    return 0

def replace_parent(w:mutbuf, previous:u64, replacement:u64, parent:u64) -> u64:
    if parent == 0:
        if get(w, P_TREE) != previous:
            return abi(w, 49)
        put(w, P_TREE, replacement)
    else:
        if registry_node(w, parent) == 0:
            return 0
        if get(w, parent + 40) == previous:
            put(w, parent + 40, replacement)
        elif get(w, parent + 48) == previous:
            put(w, parent + 48, replacement)
        else:
            return abi(w, 50)
    put(w, replacement + 64, parent)
    return 0

def rotate_left(w:mutbuf, at:u64) -> u64:
    right = get(w, at + 48)
    if right == 0 or registry_node(w, right) == 0:
        return abi(w, 51)
    middle = get(w, right + 40)
    if middle != 0 and registry_node(w, middle) == 0:
        return 0
    replace_parent(w, at, right, get(w, at + 64))
    if get(w, S_BAD) != 0:
        return 0
    put(w, at + 48, middle)
    if middle != 0:
        put(w, middle + 64, at)
    put(w, right + 40, at)
    put(w, at + 64, right)
    update_height(w, at)
    update_height(w, right)
    return right

def rotate_right(w:mutbuf, at:u64) -> u64:
    left = get(w, at + 40)
    if left == 0 or registry_node(w, left) == 0:
        return abi(w, 52)
    middle = get(w, left + 48)
    if middle != 0 and registry_node(w, middle) == 0:
        return 0
    replace_parent(w, at, left, get(w, at + 64))
    if get(w, S_BAD) != 0:
        return 0
    put(w, at + 40, middle)
    if middle != 0:
        put(w, middle + 64, at)
    put(w, left + 48, at)
    put(w, at + 64, left)
    update_height(w, at)
    update_height(w, left)
    return left

def rebalance(w:mutbuf, start:u64) -> u64:
    current = start
    steps = 0
    while current != 0:
        if steps >= get(w, P_REG_N) or registry_node(w, current) == 0:
            return abi(w, 53)
        left = height(w, get(w, current + 40))
        right = height(w, get(w, current + 48))
        update_height(w, current)
        top = current
        if left > right + 1:
            child = get(w, current + 40)
            if height(w, get(w, child + 48)) > height(w, get(w, child + 40)):
                rotate_left(w, child)
            top = rotate_right(w, current)
        elif right > left + 1:
            child = get(w, current + 48)
            if height(w, get(w, child + 40)) > height(w, get(w, child + 48)):
                rotate_right(w, child)
            top = rotate_left(w, current)
        if get(w, S_BAD) != 0 or top == 0:
            return 0
        current = get(w, top + 64)
        steps = steps + 1
    return 0

def reserve(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    if get(w, S_OP) == 0:
        put(w, S_NEED_CODE, CODE_BASE)
        put(w, S_NEED_WORK, MIN_WORK)
        return 0
    old_code = get(w, P_CODE_N)
    used = get(w, P_USED)
    first = get(w, S_FIRST)
    second = get(w, S_SECOND)
    if first > MAX_CODE - old_code:
        return error(w, 9)
    new_code = old_code + first
    if second > MAX_CODE - new_code:
        put(w, S_LATE, 1)
    else:
        new_code = new_code + second
    record = get(w, S_RECORD)
    if record != 0 and get(w, S_FOUND) == 0:
        extra = 80 + ((get(w, S_NAME_N) + 7) & (MAX - 7))
        if extra > MAX - used:
            return abi(w, 54)
        used = used + extra
    if record == 1 or record == 2:
        if used > MAX - 32:
            return abi(w, 55)
        used = used + 32
    put(w, S_NEW_CODE, new_code)
    put(w, S_NEW_USED, used)
    put(w, S_NEED_CODE, CODE_BASE + new_code)
    put(w, S_NEED_WORK, used)
    return 0

def intern(s:readbuf, w:mutbuf) -> u64:
    found = get(w, S_FOUND)
    if found != 0:
        return found
    at = get(w, P_USED)
    extra = 80 + ((get(w, S_NAME_N) + 7) & (MAX - 7))
    fill_range(w, at, extra, 0)
    put(w, at, at + 80)
    put(w, at + 8, get(w, S_NAME_N))
    put(w, at + 16, get(w, S_NAME_CHARS))
    put(w, at + 56, 1)
    put(w, at + 64, get(w, S_PARENT))
    put(w, at + 72, REGISTRY)
    copy_bytes(w, s, at + 80, get(w, S_NAME_AT), get(w, S_NAME_N))
    put(w, P_USED, at + extra)
    put(w, P_REG_N, get(w, P_REG_N) + 1)
    parent = get(w, S_PARENT)
    if parent == 0:
        if get(w, P_TREE) != 0:
            return abi(w, 56)
        put(w, P_TREE, at)
    else:
        if registry_node(w, parent) == 0:
            return 0
        side = 40 + get(w, S_SIDE) * 8
        if get(w, parent + side) != 0:
            return abi(w, 57)
        put(w, parent + side, at)
        rebalance(w, parent)
    return at

def append_record(w:mutbuf, node_at:u64, kind:u64, offset:u64) -> u64:
    at = get(w, P_USED)
    fill_range(w, at, 32, 0)
    put(w, at + 8, offset)
    put(w, at + 16, node_at)
    put(w, at + 24, choose(kind == 1, FIXUP, RELOCATION))
    head = choose(kind == 1, P_FIX_HEAD, P_REL_HEAD)
    tail = choose(kind == 1, P_FIX_TAIL, P_REL_TAIL)
    count = choose(kind == 1, P_FIX_N, P_REL_N)
    previous = get(w, tail)
    if previous == 0:
        if get(w, head) != 0 or get(w, count) != 0:
            return abi(w, 58)
        put(w, head, at)
    else:
        if previous < MIN_WORK or previous > at or at - previous < 32 or (previous & 7) != 0:
            return abi(w, 59)
        if get(w, previous) != 0 or get(w, previous + 24) != choose(kind == 1, FIXUP, RELOCATION):
            return abi(w, 60)
        put(w, previous, at)
    put(w, tail, at)
    put(w, count, get(w, count) + 1)
    put(w, P_USED, at + 32)
    return 0

def commit(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    if get(w, S_ERROR) != 0:
        return 0
    if get(w, S_OP) == 0:
        put(w, P_MAGIC, STATE)
        put(w, P_LEASE, get(w, S_LEASE))
        put(w, P_ALIVE, 1)
        put(w, P_USED, MIN_WORK)
        put(w, P_SWAP, get(w, S_INIT_SWAP))
        put(w, P_MOVE, get(w, S_INIT_MOVE))
        put(w, P_ALU, get(w, S_INIT_ALU))
        return 0
    count = get(w, S_FIRST)
    old = get(w, P_CODE_N)
    mode = get(w, S_PLAN_MODE)
    if mode == 1:
        copy_bytes(o, s, CODE_BASE + old, get(w, S_RAW_AT), count)
    elif mode == 2:
        fill_range(o, CODE_BASE + old, count, 144)
    else:
        index = 0
        while index < count:
            store(o, CODE_BASE + old + index, byte(w, PLAN + index))
            index = index + 1
    put(w, P_CODE_N, old + count)
    record = get(w, S_RECORD)
    if record != 0:
        target = intern(s, w)
        if get(w, S_BAD) != 0:
            return 0
        if record == 3:
            if get(w, target + 32) != 0:
                return abi(w, 61)
            put(w, target + 24, old)
            put(w, target + 32, 1)
            put(w, P_LABEL_N, get(w, P_LABEL_N) + 1)
        else:
            append_record(w, target, record, old + count)
    if get(w, S_BAD) != 0:
        return 0
    if get(w, S_LATE) != 0:
        return error(w, 9)
    second = get(w, S_SECOND)
    if second != 0:
        if record == 1 or record == 2:
            fill_range(o, CODE_BASE + old + count, second, 0)
        else:
            index = 0
            while index < second:
                store(o, CODE_BASE + old + count + index, byte(w, PLAN + count + index))
                index = index + 1
        put(w, P_CODE_N, old + count + second)
    if get(w, P_USED) != get(w, S_NEW_USED) or get(w, P_CODE_N) != get(w, S_NEW_CODE):
        return abi(w, 62)
    return 0

def completed(o:mutbuf, w:mutbuf) -> u64:
    if get(w, S_OP) == 0 and get(w, S_ERROR) != 0:
        put(w, P_MAGIC, STATE)
        put(w, P_LEASE, get(w, S_LEASE))
        put(w, P_ALIVE, 0)
        put(w, P_USED, MIN_WORK)
        put(w, P_SEQ, get(w, S_SEQ))
        put(w, P_LAST_OP, 0)
        return 0
    put(w, P_SEQ, get(w, S_SEQ))
    put(w, P_LAST_OP, get(w, S_OP))
    put(o, 0, CODE)
    put(o, 8, get(w, P_LEASE))
    put(o, 16, get(w, P_SEQ))
    put(o, 24, get(w, P_CODE_N))
    fill_range(o, 32, 32, 0)
    return 0
'''


FINAL=r'''
def finalize_code(s:readbuf, r:readbuf, w:mutbuf) -> u32:
    if length(w) < MIN_WORK:
        return BAD
    fill_range(w, 0, MIN_WORK, 0)
    literal_table(w)
    if final_state(s, r, w) != 0:
        final_measure(s, r, w)
    if get(w, F_BAD) != 0:
        final_event(w, 3)
        return BAD
    if get(w, F_ERROR) != 0:
        final_error_text(r, w)
        if get(w, F_BAD) != 0:
            final_event(w, 3)
            return BAD
        final_event(w, 2)
        return 128
    if get(w, F_NEED) > length(w):
        final_event(w, 1)
        return GROW
    final_graph(s, r, w)
    if get(w, F_BAD) != 0:
        final_event(w, 3)
        return BAD
    final_event(w, 0)
    return 128

def final_bad(w:mutbuf, reason:u64) -> u64:
    if get(w, F_BAD) == 0:
        put(w, F_BAD, reason)
    return 0

def final_event(w:mutbuf, action:u64) -> u64:
    put(w, 0, FINAL_EVENT)
    put(w, 8, 1)
    put(w, 16, action)
    put(w, 24, get(w, F_LEASE))
    put(w, 32, get(w, F_SEQ))
    put(w, 40, get(w, F_ERROR))
    put(w, 48, get(w, F_NEED))
    put(w, 56, choose(action == 0, MIN_WORK, 0))
    put(w, 64, choose(action == 0, get(w, F_GRAPH_N), 0))
    put(w, 72, get(w, F_FINAL_N))
    put(w, 80, get(w, F_FIX_N))
    put(w, 88, get(w, F_REL_N))
    put(w, 96, choose(action == 2, FINAL_TEXT, 0))
    put(w, 104, choose(action == 2, get(w, F_TEXT_N), 0))
    put(w, 112, get(w, F_BAD))
    put(w, 120, 0)
    return 0

def final_state(s:readbuf, r:readbuf, w:mutbuf) -> u64:
    if length(s) < CODE_BASE or length(r) < MIN_WORK:
        return final_bad(w, 1)
    if word(r, P_MAGIC) != STATE or word(r, P_POISON) != 0 or word(r, P_ALIVE) != 1 or word(r, P_LEASE) == 0:
        return final_bad(w, 2)
    if word(r, P_SEQ) == 0 or word(r, P_LAST_OP) != 45:
        return final_bad(w, 3)
    used = word(r, P_USED)
    count = word(r, P_CODE_N)
    if used < MIN_WORK or used > length(r) or (used & 7) != 0 or count > MAX_CODE or count > length(s) - CODE_BASE:
        return final_bad(w, 4)
    if word(s, 0) != CODE or word(s, 8) != word(r, P_LEASE) or word(s, 16) != word(r, P_SEQ) or word(s, 24) != count:
        return final_bad(w, 5)
    index = 32
    while index < 64:
        if word(s, index) != 0:
            return final_bad(w, 6)
        index = index + 8
    if word(r, 0) != EVENT or word(r, 8) != 1 or word(r, 16) != 4 or word(r, 24) != word(r, P_LEASE):
        return final_bad(w, 7)
    if word(r, 32) != word(r, P_SEQ) or word(r, 40) != 45 or word(r, 48) != 0 or word(r, 56) != CODE_BASE + count:
        return final_bad(w, 8)
    if word(r, 64) != used or word(r, 72) != count or word(r, 80) != word(r, P_LABEL_N):
        return final_bad(w, 9)
    if word(r, 88) != word(r, P_FIX_N) or word(r, 96) != word(r, P_REL_N):
        return final_bad(w, 10)
    if word(r, 104) != 0 or word(r, 112) != 0 or word(r, 120) != 0:
        return final_bad(w, 11)
    if word(r, P_SWAP) > 1 or word(r, P_MOVE) > 1 or word(r, P_ALU) > 1 or word(r, P_LABEL_N) > word(r, P_REG_N):
        return final_bad(w, 12)
    available = used - MIN_WORK
    if word(r, P_REG_N) > (available >> 6) or word(r, P_FIX_N) > (available >> 5) or word(r, P_REL_N) > (available >> 5):
        return final_bad(w, 13)
    if (word(r, P_TREE) == 0) != (word(r, P_REG_N) == 0):
        return final_bad(w, 14)
    put(w, F_LEASE, word(r, P_LEASE))
    put(w, F_SEQ, word(r, P_SEQ))
    put(w, F_USED, used)
    put(w, F_CODE_N, count)
    put(w, F_FINAL_N, count)
    put(w, F_FIX_N, word(r, P_FIX_N))
    put(w, F_REL_N, word(r, P_REL_N))
    put(w, F_REG_N, word(r, P_REG_N))
    return 1

def final_registry(r:readbuf, w:mutbuf, at:u64) -> u64:
    used = get(w, F_USED)
    if at < MIN_WORK or (at & 7) != 0 or at > used or used - at < 80:
        return final_bad(w, 15)
    begin = word(r, at)
    count = word(r, at + 8)
    if begin != at + 80 or count == 0 or count > 2048 or count > used - begin:
        return final_bad(w, 16)
    if word(r, at + 16) == 0 or word(r, at + 16) > 512 or word(r, at + 32) > 1:
        return final_bad(w, 17)
    if word(r, at + 24) > MAX_CODE or word(r, at + 56) == 0 or word(r, at + 56) > get(w, F_REG_N) or word(r, at + 72) != REGISTRY:
        return final_bad(w, 18)
    return at

def final_record(r:readbuf, w:mutbuf, at:u64, tag:u64) -> u64:
    used = get(w, F_USED)
    if at < MIN_WORK or (at & 7) != 0 or at > used or used - at < 32:
        return final_bad(w, 19)
    if word(r, at + 24) != tag or word(r, at + 8) == 0 or word(r, at + 8) > get(w, F_CODE_N):
        return final_bad(w, 20)
    return final_registry(r, w, word(r, at + 16))

def final_fixups(r:readbuf, w:mutbuf) -> u64:
    index = 0
    previous = 0
    last_offset = 0
    at = word(r, P_FIX_HEAD)
    while index < get(w, F_FIX_N):
        target = final_record(r, w, at, FIXUP)
        if target == 0:
            return 0
        offset = word(r, at + 8)
        if offset < last_offset:
            return final_bad(w, 21)
        last_offset = offset
        if word(r, target + 32) == 0:
            put(w, F_ERROR, 17)
            put(w, F_NAME_AT, word(r, target))
            put(w, F_NAME_N, word(r, target + 8))
            return 0
        if offset + 4 > get(w, F_FINAL_N):
            put(w, F_FINAL_N, offset + 4)
        previous = at
        at = word(r, at)
        index = index + 1
    if at != 0 or previous != word(r, P_FIX_TAIL):
        return final_bad(w, 22)
    return 1

def final_relmeasure(r:readbuf, w:mutbuf) -> u64:
    index = 0
    previous = 0
    last_offset = 0
    at = word(r, P_REL_HEAD)
    scalar = get(w, F_FINAL_N) + 24
    while index < get(w, F_REL_N):
        target = final_record(r, w, at, RELOCATION)
        if target == 0:
            return 0
        offset = word(r, at + 8)
        if offset < last_offset:
            return final_bad(w, 23)
        last_offset = offset
        size = word(r, target + 8)
        if size > 192:
            return final_bad(w, 24)
        i = 0
        while i < size:
            c = byte(r, word(r, target) + i)
            alpha = c == 95 or (c >= 65 and c <= 90) or (c >= 97 and c <= 122)
            if alpha == False and (i == 0 or c < 48 or c > 57):
                return final_bad(w, 25)
            i = i + 1
        extra = magnitude_bytes(offset) + size
        if extra > MAX - scalar:
            return final_bad(w, 26)
        scalar = scalar + extra
        previous = at
        at = word(r, at)
        index = index + 1
    if at != 0 or previous != word(r, P_REL_TAIL):
        return final_bad(w, 27)
    put(w, F_SCALAR_N, scalar)
    return 1

def final_measure(s:readbuf, r:readbuf, w:mutbuf) -> u64:
    if final_fixups(r, w) == 0:
        return 0
    if final_relmeasure(r, w) == 0:
        return 0
    count = get(w, F_REL_N)
    if count > MAX_REL_GRAPH:
        return final_bad(w, 28)
    nodes = 9 + count * 3
    edges = 2 + count * 9
    if nodes > (MAX - 64) >> 6:
        return final_bad(w, 29)
    base = 64 + nodes * 64
    if edges > (MAX - base) >> 3:
        return final_bad(w, 30)
    base = base + edges * 8
    if get(w, F_SCALAR_N) > MAX - base:
        return final_bad(w, 31)
    graph_size = base + get(w, F_SCALAR_N)
    if graph_size > MAX - MIN_WORK:
        return final_bad(w, 32)
    put(w, F_NODE_N, nodes)
    put(w, F_EDGE_N, edges)
    put(w, F_POOL, base)
    put(w, F_GRAPH_N, graph_size)
    put(w, F_NEED, MIN_WORK + graph_size)
    return 1

def final_error_text(r:readbuf, w:mutbuf) -> u64:
    row = INDEX + 16 * 16
    prefix = get(w, row + 8)
    if prefix + get(w, F_NAME_N) > MIN_WORK - FINAL_TEXT:
        return final_bad(w, 33)
    i = 0
    while i < prefix:
        store(w, FINAL_TEXT + i, byte(w, get(w, row) + i))
        i = i + 1
    copy_bytes(w, r, FINAL_TEXT + prefix, get(w, F_NAME_AT), get(w, F_NAME_N))
    put(w, F_TEXT_N, prefix + get(w, F_NAME_N))
    return 0

def magnitude_bytes(value:u64) -> u64:
    count = 0
    while value != 0:
        value = value >> 8
        count = count + 1
    return count

def graph_node(w:mutbuf, identifier:u64, kind:u64, begin:u64, size:u64, first:u64, count:u64, identity:u64, aux:u64) -> u64:
    at = MIN_WORK + 64 + (identifier - 1) * 64
    put(w, at, kind)
    put(w, at + 8, begin)
    put(w, at + 16, size)
    put(w, at + 24, first)
    put(w, at + 32, count)
    put(w, at + 40, identity)
    put(w, at + 48, aux)
    return 0

def graph_edge(w:mutbuf, index:u64, identifier:u64) -> u64:
    put(w, MIN_WORK + 64 + get(w, F_NODE_N) * 64 + index * 8, identifier)
    return 0

def graph_literal(w:mutbuf, identifier:u64, literal:u64, cursor:u64) -> u64:
    row = INDEX + literal * 16
    count = get(w, row + 8)
    i = 0
    while i < count:
        store(w, MIN_WORK + cursor + i, byte(w, get(w, row) + i))
        i = i + 1
    graph_node(w, identifier, 4, cursor, count, 0, 0, 0, count)
    return cursor + count

def graph_unsigned(w:mutbuf, identifier:u64, cursor:u64, value:u64, negative:u64) -> u64:
    size = magnitude_bytes(value)
    i = 0
    while i < size:
        store(w, MIN_WORK + cursor + i, (value >> (i * 8)) & 255)
        i = i + 1
    graph_node(w, identifier, 2, cursor, size, 0, 0, 0, negative)
    return cursor + size

def graph_relocations(r:readbuf, w:mutbuf, cursor0:u64) -> u64:
    at = word(r, P_REL_HEAD)
    index = 0
    cursor = cursor0
    count = get(w, F_REL_N)
    while index < count:
        target = word(r, at + 16)
        identifier = 10 + index * 3
        first = 2 + count + index * 8
        graph_node(w, identifier, 6, 0, 0, first, 4, identifier, 0)
        graph_edge(w, 2 + index, identifier)
        graph_edge(w, first, 4)
        graph_edge(w, first + 1, identifier + 1)
        graph_edge(w, first + 2, 5)
        graph_edge(w, first + 3, identifier + 2)
        graph_edge(w, first + 4, 6)
        graph_edge(w, first + 5, 8)
        graph_edge(w, first + 6, 7)
        graph_edge(w, first + 7, 9)
        cursor = graph_unsigned(w, identifier + 1, cursor, word(r, at + 8), 0)
        size = word(r, target + 8)
        copy_bytes(w, r, MIN_WORK + cursor, word(r, target), size)
        graph_node(w, identifier + 2, 4, cursor, size, 0, 0, 0, size)
        cursor = cursor + size
        at = word(r, at)
        index = index + 1
    return cursor

def final_graph(s:readbuf, r:readbuf, w:mutbuf) -> u64:
    fill_range(w, MIN_WORK, get(w, F_GRAPH_N), 0)
    put(w, MIN_WORK, OUTPUT_GRAPH)
    put(w, MIN_WORK + 8, get(w, F_LEASE))
    put(w, MIN_WORK + 16, get(w, F_NODE_N))
    put(w, MIN_WORK + 24, 1)
    put(w, MIN_WORK + 32, get(w, F_EDGE_N))
    put(w, MIN_WORK + 40, get(w, F_SCALAR_N))
    put(w, MIN_WORK + 48, get(w, F_GRAPH_N))
    graph_node(w, 1, 5, 0, 0, 0, 2, 1, 0)
    graph_node(w, 2, 9, get(w, F_POOL), get(w, F_FINAL_N), 0, 0, 0, 0)
    graph_node(w, 3, 5, 0, 0, 2, get(w, F_REL_N), 3, 0)
    graph_edge(w, 0, 2)
    graph_edge(w, 1, 3)
    cursor = get(w, F_POOL)
    copy_bytes(w, s, MIN_WORK + cursor, CODE_BASE, get(w, F_CODE_N))
    at = word(r, P_FIX_HEAD)
    index = 0
    while index < get(w, F_FIX_N):
        target = word(r, at + 16)
        offset = word(r, at + 8)
        value = word(r, target + 24) - offset - 4
        j = 0
        while j < 4:
            store(w, MIN_WORK + cursor + offset + j, (value >> (j * 8)) & 255)
            j = j + 1
        at = word(r, at)
        index = index + 1
    cursor = cursor + get(w, F_FINAL_N)
    cursor = graph_literal(w, 4, L_OFFSET, cursor)
    cursor = graph_literal(w, 5, L_SYMBOL, cursor)
    cursor = graph_literal(w, 6, L_TYPE, cursor)
    cursor = graph_literal(w, 7, L_ADDEND, cursor)
    cursor = graph_unsigned(w, 8, cursor, 4, 0)
    cursor = graph_unsigned(w, 9, cursor, 4, 1)
    cursor = graph_relocations(r, w, cursor)
    if cursor != get(w, F_GRAPH_N):
        return final_bad(w, 34)
    return 0
'''


FINAL_FIELDS=("BAD","ERROR","LEASE","SEQ","USED","CODE_N","FIX_N","REL_N",
 "FINAL_N","NODE_N","EDGE_N","POOL","GRAPH_N","NEED","NAME_AT","NAME_N",
 "REG_N","SCALAR_N","TEXT_N")
CONSTANTS.update({"F_"+v:128+i*8 for i,v in enumerate(FINAL_FIELDS)})

def source(component):
    if component not in ("encoder","finalizer"):
        raise ValueError("unknown native x64 component")
    constants=dict(CONSTANTS)
    raw=bytearray(constants["LITERAL_DATA"])
    assert constants["INDEX"]+len(LITERALS)*16<=constants["LITERAL_DATA"]
    for index,(name,value) in enumerate(LITERALS.items()):
        constants["L_"+name.upper()]=index
        data=value.encode("ascii");begin=len(raw);raw.extend(data)
        entry=constants["INDEX"]+index*16
        raw[entry:entry+8]=begin.to_bytes(8,"little")
        raw[entry+8:entry+16]=len(data).to_bytes(8,"little")
    constants["L_REG0"]=constants["L_REG_RAX"]
    constants["L_CC0"]=constants["L_CC_O"]
    assert len(raw)<=constants["PLAN"]
    assert max(constants["S_"+name]+8 for name in SCRATCH)<=constants["INDEX"]
    assert max(constants["F_"+name]+8 for name in FINAL_FIELDS)<=constants["INDEX"]
    writes=[(at,int.from_bytes(raw[at:at+8].ljust(8,b"\0"),"little"))
            for at in range(constants["INDEX"],len(raw),8) if any(raw[at:at+8])]
    helpers=[];calls=[]
    for start in range(0,len(writes),16):
        name="literal_"+str(start//16);calls.append("    "+name+"(w)")
        lines=["def "+name+"(w:mutbuf) -> u64:"]
        lines+=["    put(w, %d, %d)"%(at,value) for at,value in writes[start:start+16]]
        lines+=["    return 0"];helpers.append("\n".join(lines))
    helpers.append("def literal_table(w:mutbuf) -> u64:\n"+"\n".join(calls)+"\n    return 0")
    arity=["def arity(op:u64) -> u64:"]
    for count in (0,1,2,3):
        selected=[str(i) for i,n in enumerate(ARITIES) if n==count]
        arity+=["    if "+" or ".join("op == "+i for i in selected)+":","        return "+str(count)]
    arity+=["    return 4"];helpers.append("\n".join(arity))
    cc=["def condition_value(index:u64) -> u64:"]
    for index,(_,value) in enumerate(CONDITIONS.items()):
        cc+=["    if index == "+str(index)+":","        return "+str(value)]
    cc+=["    return 0"];helpers.append("\n".join(cc))
    opcode=["def rr_opcode(op:u64) -> u64:"]
    for op,value in ((15,1),(16,41),(17,33),(18,9),(19,49),(20,57),(21,133)):
        opcode+=["    if op == "+str(op)+":","        return "+str(value)]
    opcode+=["    return 0"];helpers.append("\n".join(opcode))
    allnodes=ast.parse(ENCODER+"\n"+FINAL+"\n"+"\n".join(helpers)).body
    names={node.name:node for node in allnodes}
    assert len(names)==len(allnodes)
    entry="encode_command" if component=="encoder" else "finalize_code"
    live={entry};pending=[entry]
    while pending:
        node=names[pending.pop()]
        for call in ast.walk(node):
            if isinstance(call,ast.Call) and isinstance(call.func,ast.Name):
                name=call.func.id
                if name in names and name not in live:
                    live.add(name);pending.append(name)
    nodes=[names[entry]]+[n for n in allnodes if n.name in live and n.name!=entry]
    for node in nodes:
        if node.name in ("word","get"):
            argument="s" if node.name=="word" else "w"
            node.body=ast.parse("return "+" | ".join("(byte(%s, at + %d) << %d)"%(argument,i,8*i) for i in range(8))).body
        elif node.name=="put":
            node.body=ast.parse("\n".join("store(w, at + %d, (value >> %d) & 255)"%(i,8*i) for i in range(8))+"\nreturn 0").body
    return "\n".join(ast.unparse(ast.fix_missing_locations(n)) for n in nodes)+"\n",constants,dict(
        status="NEW_AUTHORING_ONLY",component=component,reference_sha256=REFERENCE_SHA,
        operations=list(OPERATIONS),complete_original_Code_public_methods=True,
        mechanical_private_argument_graph=True,graph_magic="HIAXGR01",
        immutable_inputs_across_GROW_required=True,header_is_authentication=False,
        original_code_limit=67108864,finalized_copy_may_extend_to=67108868,
        no_total_labels_relocations_bytes_or_calls_quota=True,
        native_AVL_copied_names=True,native_instruction_and_fixup_bytes=True,
        ordinary_later_error_preserves_partial_state=True,
        finalize_does_not_mutate_code_or_metadata=True,
        arbitrary_foreign_callbacks_or_direct_internal_mutation_closed=False)
