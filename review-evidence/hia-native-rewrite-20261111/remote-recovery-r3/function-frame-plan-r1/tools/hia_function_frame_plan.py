"""Pure HIA per-function stack, value and staging planner.
The input is a private immutable Graph of [admitted Core, checked machine plan].
This is not Core admission or a replacement machine-plan validator.
"""
import ast

def magic(text):return int.from_bytes(text.encode("ascii"),"little")

REFERENCE_SHA="bf953a8b85d1ebc6b9d7a90fbbcaa4137e40ed214c2ede2af1a13cfc01b1c07c"
PLAN_REFERENCE_SHA="ae3e54c4dc3299ba9b6d0a9b4caec55e26f3233e5699d3a0cab7deb1337efb8a"
CONSTANTS=dict(MAX=(1<<64)-1,BAD=0xfffffffd,GROW=0xfffffffe,BASE=4096,
 GRAPH=magic("HIAGRF01"),COMMAND=magic("HIAPFC01"),EVENT=magic("HIAPFE01"),
 PLAN=magic("HIAPFN01"),INDEX=1024,DATA=2048,HEADER=4096,RECORDS=4608,
 MAX_FRAME=65536,ERROR_AT=512)
FIELDS=("BAD","ERROR","LEASE","SEQ","FN_INDEX","SERIAL","NODES","EDGES","DATA","ROOT",
 "CORE","PLAN","FUNCTIONS","FN","NAME","BLOCKS","REGMAP","ORDER","SELECT",
 "VALUE_N","BLOCK_N","CALL_N","EDGE_N","RET_N","MOVE_N",
 "VALUE_AT","BLOCK_AT","CALL_AT","EDGE_AT","RET_AT","MOVE_AT",
 "VHASH_AT","VHASH_N","BHASH_AT","BHASH_N","ORDER_AT","SAVED_AT","TRAP_AT",
 "CURSOR","FRAME","EDGE_WORDS","CALL_WORDS","RESULT_WORDS","EDGE_SLOT","CALL_SLOT",
 "RESULT_SLOT","TEMPORARY","SAVED_MASK","SAVED_N","NEED","ENTRY","PARAM_AT","PARAM_N",
 "TRAP_N","ERROR_N","VALUE_NEXT","CALL_NEXT","EDGE_NEXT","RET_NEXT","MOVE_NEXT",
 "BLOCK_NEXT","DISTINCT","FN_COUNT","REG_COUNT")
CONSTANTS.update({"S_"+name:256+i*8 for i,name in enumerate(FIELDS)})
# Mutable scratch is 256..767; errors use 768..1023.
CONSTANTS["ERROR_AT"]=768
LITERALS=("functions","name","blocks","params","ops","out","type","op","args","term",
 "id","entry","target","then","else","values","attrs","function",
 "value_registers","instruction_selection","scalar_select","block_order",
 "buffer","readbuf","mutbuf","branch","cmov_scalar","call","jump","ret","trap",
 "rbx","r12","r13","r14","r15","r8","r9",
 "E_HIA_PROGRAM_LIMIT: function stack frame exceeds 64 KiB: ")
BODY=r'''
def function_plan(s:readbuf, r:readbuf, w:mutbuf) -> u32:
    if length(w) < BASE:
        return BAD
    fill_range(w, 0, BASE, 0)
    literal_table(w)
    if frame(s, r, w) != 0:
        if selection(s, w) != 0:
            census(s, w)
            if get(w, S_BAD) == 0:
                layout(w)
                if get(w, S_BAD) == 0 and get(w, S_NEED) <= length(w):
                    fill_range(w, HEADER, get(w, S_NEED) - HEADER, 0)
                    definitions(s, w)
                    registers(s, w)
                    staging(s, w)
                    if get(w, S_BAD) == 0:
                        finish_frame(s, w)
                        if get(w, S_ERROR) == 0 and get(w, S_BAD) == 0:
                            moves(s, w, 0)
                            if get(w, S_BAD) == 0:
                                reserve_moves(w)
                                if get(w, S_BAD) == 0 and get(w, S_NEED) <= length(w):
                                    moves(s, w, 1)
                                    order(s, w)
                                    trap_label(w)
                                    header(s, w)
    if get(w, S_BAD) != 0:
        event(w, 3)
        return BAD
    if get(w, S_ERROR) != 0:
        event(w, 2)
        return 128
    if get(w, S_NEED) > length(w):
        event(w, 1)
        return GROW
    event(w, 0)
    return 128

def abi(w:mutbuf, reason:u64) -> u64:
    if get(w, S_BAD) == 0:
        put(w, S_BAD, reason)
    return 0

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

def event(w:mutbuf, action:u64) -> u64:
    put(w, 0, EVENT)
    put(w, 8, 1)
    put(w, 16, action)
    put(w, 24, get(w, S_LEASE))
    put(w, 32, get(w, S_SEQ))
    put(w, 40, get(w, S_FN_INDEX))
    put(w, 48, get(w, S_ERROR))
    put(w, 56, get(w, S_NEED))
    put(w, 64, choose(action == 0, HEADER, 0))
    put(w, 72, choose(action == 0, get(w, S_NEED) - HEADER, 0))
    put(w, 80, get(w, S_FRAME))
    put(w, 88, get(w, S_SERIAL) + choose(action == 0, 1, 0))
    put(w, 96, choose(action == 2, ERROR_AT, 0))
    put(w, 104, get(w, S_ERROR_N))
    put(w, 112, get(w, S_ROOT))
    put(w, 120, get(w, S_BAD))
    return 0

def frame(s:readbuf, r:readbuf, w:mutbuf) -> u64:
    if length(r) != 96 or length(s) < 128:
        return abi(w, 1)
    if word(r, 0) != COMMAND or word(r, 8) != 1 or word(r, 16) == 0 or word(r, 24) == 0:
        return abi(w, 2)
    at = 56
    while at < 96:
        if word(r, at) != 0:
            return abi(w, 3)
        at = at + 8
    put(w, S_LEASE, word(r, 16))
    put(w, S_SEQ, word(r, 24))
    put(w, S_FN_INDEX, word(r, 32))
    put(w, S_SERIAL, word(r, 40))
    if word(s, 0) != GRAPH or word(s, 8) != word(r, 16) or word(s, 56) != 0:
        return abi(w, 4)
    nodes = word(s, 16)
    edges = word(s, 32)
    if nodes == 0 or nodes > (MAX - 64) >> 6:
        return abi(w, 5)
    end = 64 + nodes * 64
    if edges > (MAX - end) >> 3:
        return abi(w, 6)
    end = end + edges * 8
    if end > length(s) or word(s, 40) != length(s) - end or word(s, 48) != length(s):
        return abi(w, 7)
    if word(s, 24) == 0 or word(s, 24) > nodes or word(s, 24) != word(r, 48):
        return abi(w, 8)
    put(w, S_NODES, nodes)
    put(w, S_EDGES, edges)
    put(w, S_DATA, end)
    put(w, S_ROOT, word(s, 24))
    return 1

def node(s:readbuf, w:mutbuf, identifier:u64) -> u64:
    if identifier == 0 or identifier > get(w, S_NODES):
        return abi(w, 9)
    at = 64 + (identifier - 1) * 64
    kind = word(s, at)
    if word(s, at + 56) != 0 or kind > 6:
        return abi(w, 10)
    if kind == 5 or kind == 6:
        if word(s, at + 8) != 0 or word(s, at + 16) != 0 or word(s, at + 40) == 0 or word(s, at + 48) != 0:
            return abi(w, 11)
        first = word(s, at + 24)
        count = word(s, at + 32)
        if kind == 6:
            if count > MAX >> 1:
                return abi(w, 12)
            count = count * 2
        if first > get(w, S_EDGES) or count > get(w, S_EDGES) - first:
            return abi(w, 13)
    elif word(s, at + 24) != 0 or word(s, at + 32) != 0 or word(s, at + 40) != 0:
        return abi(w, 14)
    elif kind == 4 or kind == 2 or kind == 3:
        begin = word(s, at + 8)
        size = word(s, at + 16)
        if begin < get(w, S_DATA) or begin > length(s) or size > length(s) - begin:
            return abi(w, 15)
        if kind == 3 and (size != 8 or word(s, at + 48) != 0):
            return abi(w, 16)
        if kind == 2 and (word(s, at + 48) > 1 or (size == 0 and word(s, at + 48) != 0)):
            return abi(w, 17)
    elif word(s, at + 8) != 0 or word(s, at + 16) != 0 or (kind == 0 and word(s, at + 48) != 0) or (kind == 1 and word(s, at + 48) > 1):
        return abi(w, 18)
    return at

def typed(s:readbuf, w:mutbuf, identifier:u64, kind:u64) -> u64:
    at = node(s, w, identifier)
    if at == 0:
        return 0
    if word(s, at) != kind:
        return abi(w, 19)
    return at

def edge(s:readbuf, w:mutbuf, at:u64, index:u64) -> u64:
    count = word(s, at + 32)
    if word(s, at) == 6:
        count = count * 2
    if index >= count:
        return abi(w, 20)
    identifier = word(s, 64 + get(w, S_NODES) * 64 + (word(s, at + 24) + index) * 8)
    if identifier == 0 or identifier > get(w, S_NODES):
        return abi(w, 21)
    return identifier

def literal(s:readbuf, w:mutbuf, identifier:u64, index:u64) -> u64:
    at = typed(s, w, identifier, 4)
    if at == 0:
        return 0
    row = INDEX + index * 16
    size = get(w, row + 8)
    if word(s, at + 16) != size:
        return 0
    i = 0
    while i < size:
        if byte(s, word(s, at + 8) + i) != byte(w, get(w, row) + i):
            return 0
        i = i + 1
    return 1

def equal(s:readbuf, w:mutbuf, left:u64, right:u64) -> u64:
    a = typed(s, w, left, 4)
    b = typed(s, w, right, 4)
    if a == 0 or b == 0:
        return 0
    size = word(s, a + 16)
    if size != word(s, b + 16):
        return 0
    i = 0
    while i < size:
        if byte(s, word(s, a + 8) + i) != byte(s, word(s, b + 8) + i):
            return 0
        i = i + 1
    return 1

def field(s:readbuf, w:mutbuf, identifier:u64, index:u64, required:u64) -> u64:
    at = typed(s, w, identifier, 6)
    if at == 0:
        return 0
    i = 0
    while i < word(s, at + 32):
        key = edge(s, w, at, i * 2)
        if literal(s, w, key, index) != 0:
            return edge(s, w, at, i * 2 + 1)
        if get(w, S_BAD) != 0:
            return 0
        i = i + 1
    if required != 0:
        return abi(w, 22)
    return 0

def named(s:readbuf, w:mutbuf, identifier:u64, name:u64) -> u64:
    if identifier == 0:
        return 0
    at = typed(s, w, identifier, 6)
    if at == 0:
        return 0
    i = 0
    while i < word(s, at + 32):
        if equal(s, w, edge(s, w, at, i * 2), name) != 0:
            return edge(s, w, at, i * 2 + 1)
        if get(w, S_BAD) != 0:
            return 0
        i = i + 1
    return 0

def width(s:readbuf, w:mutbuf, typ:u64) -> u64:
    if literal(s, w, typ, L_BUFFER) != 0 or literal(s, w, typ, L_READBUF) != 0 or literal(s, w, typ, L_MUTBUF) != 0:
        return 2
    return 1

def selection(s:readbuf, w:mutbuf) -> u64:
    root = typed(s, w, get(w, S_ROOT), 5)
    if root == 0 or word(s, root + 32) != 2:
        return abi(w, 23)
    core = edge(s, w, root, 0)
    plan = edge(s, w, root, 1)
    functions = field(s, w, core, L_FUNCTIONS, 1)
    array = typed(s, w, functions, 5)
    if array == 0 or get(w, S_FN_INDEX) >= word(s, array + 32):
        return abi(w, 24)
    put(w, S_FN_COUNT, word(s, array + 32))
    fn = edge(s, w, array, get(w, S_FN_INDEX))
    name = field(s, w, fn, L_NAME, 1)
    if typed(s, w, name, 4) == 0:
        return 0
    blocks = field(s, w, fn, L_BLOCKS, 1)
    if typed(s, w, blocks, 5) == 0:
        return 0
    put(w, S_CORE, core)
    put(w, S_FUNCTIONS, functions)
    put(w, S_FN, fn)
    put(w, S_NAME, name)
    put(w, S_BLOCKS, blocks)
    p = node(s, w, plan)
    if p == 0:
        return 0
    if word(s, p) != 0:
        if word(s, p) != 6:
            return abi(w, 25)
        put(w, S_PLAN, plan)
        mapping = field(s, w, plan, L_VALUE_REGISTERS, 0)
        put(w, S_REGMAP, named(s, w, mapping, name))
        mapping = field(s, w, plan, L_BLOCK_ORDER, 0)
        put(w, S_ORDER, named(s, w, mapping, name))
        choices = field(s, w, plan, L_INSTRUCTION_SELECTION, 0)
        if choices != 0:
            scalar = field(s, w, choices, L_SCALAR_SELECT, 0)
            if scalar != 0:
                if literal(s, w, scalar, L_CMOV_SCALAR) != 0:
                    put(w, S_SELECT, 1)
                elif literal(s, w, scalar, L_BRANCH) == 0:
                    return abi(w, 26)
    return choose(get(w, S_BAD) == 0, 1, 0)

def list_count(s:readbuf, w:mutbuf, identifier:u64) -> u64:
    at = typed(s, w, identifier, 5)
    if at == 0:
        return 0
    return word(s, at + 32)

def census(s:readbuf, w:mutbuf) -> u64:
    blocks = typed(s, w, get(w, S_BLOCKS), 5)
    put(w, S_BLOCK_N, word(s, blocks + 32))
    b = 0
    while b < get(w, S_BLOCK_N) and get(w, S_BAD) == 0:
        block = edge(s, w, blocks, b)
        params = field(s, w, block, L_PARAMS, 1)
        put(w, S_VALUE_N, get(w, S_VALUE_N) + list_count(s, w, params))
        ops = typed(s, w, field(s, w, block, L_OPS, 1), 5)
        if ops == 0:
            return 0
        i = 0
        while i < word(s, ops + 32) and get(w, S_BAD) == 0:
            ins = edge(s, w, ops, i)
            outs = field(s, w, ins, L_OUT, 1)
            put(w, S_VALUE_N, get(w, S_VALUE_N) + list_count(s, w, outs))
            op = field(s, w, ins, L_OP, 1)
            if literal(s, w, op, L_CALL) != 0:
                put(w, S_CALL_N, get(w, S_CALL_N) + 1)
            i = i + 1
        term = field(s, w, block, L_TERM, 1)
        op = field(s, w, term, L_OP, 1)
        if literal(s, w, op, L_JUMP) != 0:
            put(w, S_EDGE_N, get(w, S_EDGE_N) + 1)
        elif literal(s, w, op, L_BRANCH) != 0:
            put(w, S_EDGE_N, get(w, S_EDGE_N) + 2)
        elif literal(s, w, op, L_RET) != 0:
            put(w, S_RET_N, get(w, S_RET_N) + 1)
        elif literal(s, w, op, L_TRAP) == 0:
            return abi(w, 27)
        b = b + 1
    return 0

def reserve(w:mutbuf, count:u64, size:u64, field_at:u64) -> u64:
    at = get(w, S_NEED)
    if size == 0 or count > divide(MAX, size):
        return abi(w, 28)
    amount = count * size
    if amount > MAX - at:
        return abi(w, 29)
    put(w, field_at, at)
    put(w, S_NEED, at + amount)
    return at

def capacity(w:mutbuf, count:u64) -> u64:
    if count > MAX >> 2:
        return abi(w, 30)
    result = 4
    while result < count * 2:
        result = result * 2
    return result

def layout(w:mutbuf) -> u64:
    put(w, S_NEED, RECORDS)
    reserve(w, get(w, S_VALUE_N), 64, S_VALUE_AT)
    reserve(w, get(w, S_BLOCK_N), 64, S_BLOCK_AT)
    reserve(w, get(w, S_CALL_N), 96, S_CALL_AT)
    reserve(w, get(w, S_EDGE_N), 96, S_EDGE_AT)
    reserve(w, get(w, S_RET_N), 64, S_RET_AT)
    put(w, S_VHASH_N, capacity(w, get(w, S_VALUE_N)))
    put(w, S_BHASH_N, capacity(w, get(w, S_BLOCK_N)))
    reserve(w, get(w, S_VHASH_N), 8, S_VHASH_AT)
    reserve(w, get(w, S_BHASH_N), 8, S_BHASH_AT)
    reserve(w, get(w, S_BLOCK_N), 8, S_ORDER_AT)
    reserve(w, 5, 16, S_SAVED_AT)
    reserve(w, 64, 1, S_TRAP_AT)
    put(w, S_MOVE_AT, get(w, S_NEED))
    return 0

def hash_name(s:readbuf, w:mutbuf, identifier:u64) -> u64:
    at = typed(s, w, identifier, 4)
    if at == 0:
        return 0
    value = 14695981039346656037
    i = 0
    while i < word(s, at + 16):
        value = (value ^ byte(s, word(s, at + 8) + i)) * 1099511628211
        i = i + 1
    return value

def lookup(s:readbuf, w:mutbuf, name:u64, kind:u64, record:u64) -> u64:
    at = get(w, S_VHASH_AT)
    count = get(w, S_VHASH_N)
    if kind != 0:
        at = get(w, S_BHASH_AT)
        count = get(w, S_BHASH_N)
    index = hash_name(s, w, name) & (count - 1)
    visits = 0
    while visits < count and get(w, S_BAD) == 0:
        old = get(w, at + index * 8)
        if old == 0:
            if record != 0:
                put(w, at + index * 8, record)
                if kind == 0:
                    put(w, S_DISTINCT, get(w, S_DISTINCT) + 1)
                return record
            return abi(w, 31)
        other = get(w, old)
        if kind != 0:
            other = get(w, old + 8)
        if equal(s, w, name, other) != 0:
            if record != 0:
                put(w, at + index * 8, record)
                return record
            return old
        index = (index + 1) & (count - 1)
        visits = visits + 1
    return abi(w, 32)

def allocate(w:mutbuf, words:u64) -> u64:
    if words > (MAX - get(w, S_CURSOR)) >> 3:
        return abi(w, 33)
    cursor = get(w, S_CURSOR) + words * 8
    put(w, S_CURSOR, cursor)
    return 0 - cursor

def add_definitions(s:readbuf, w:mutbuf, identifier:u64, block:u64) -> u64:
    at = typed(s, w, identifier, 5)
    if at == 0:
        return 0
    total = 0
    i = 0
    while i < word(s, at + 32) and get(w, S_BAD) == 0:
        value = edge(s, w, at, i)
        name = field(s, w, value, L_NAME, 1)
        typ = field(s, w, value, L_TYPE, 1)
        words = width(s, w, typ)
        n = get(w, S_VALUE_NEXT)
        if n >= get(w, S_VALUE_N):
            return abi(w, 34)
        row = get(w, S_VALUE_AT) + n * 64
        put(w, row, name)
        put(w, row + 8, typ)
        put(w, row + 16, words)
        put(w, row + 24, allocate(w, words))
        put(w, row + 40, value)
        put(w, row + 48, block)
        put(w, row + 56, n)
        lookup(s, w, name, 0, row)
        put(w, S_VALUE_NEXT, n + 1)
        total = total + words
        i = i + 1
    return total

def definitions(s:readbuf, w:mutbuf) -> u64:
    put(w, S_CURSOR, 8)
    blocks = typed(s, w, get(w, S_BLOCKS), 5)
    b = 0
    while b < get(w, S_BLOCK_N) and get(w, S_BAD) == 0:
        block = edge(s, w, blocks, b)
        params = field(s, w, block, L_PARAMS, 1)
        opsid = field(s, w, block, L_OPS, 1)
        term = field(s, w, block, L_TERM, 1)
        name = field(s, w, block, L_ID, 1)
        row = get(w, S_BLOCK_AT) + b * 64
        put(w, row, block)
        put(w, row + 8, name)
        put(w, row + 16, params)
        put(w, row + 24, opsid)
        put(w, row + 32, term)
        words = add_definitions(s, w, params, b)
        put(w, row + 40, words)
        put(w, row + 48, b)
        if words > get(w, S_EDGE_WORDS):
            put(w, S_EDGE_WORDS, words)
        lookup(s, w, name, 1, row)
        ops = typed(s, w, opsid, 5)
        if ops == 0:
            return 0
        i = 0
        while i < word(s, ops + 32) and get(w, S_BAD) == 0:
            ins = edge(s, w, ops, i)
            add_definitions(s, w, field(s, w, ins, L_OUT, 1), b)
            i = i + 1
        b = b + 1
    return 0

def register_code(s:readbuf, w:mutbuf, name:u64) -> u64:
    i = 0
    while i < 7:
        if literal(s, w, name, L_RBX + i) != 0:
            return i + 1
        i = i + 1
    return abi(w, 35)

def registers(s:readbuf, w:mutbuf) -> u64:
    mapping = get(w, S_REGMAP)
    if mapping == 0:
        return 0
    at = typed(s, w, mapping, 6)
    if at == 0:
        return 0
    put(w, S_REG_COUNT, word(s, at + 32))
    i = 0
    while i < word(s, at + 32) and get(w, S_BAD) == 0:
        name = edge(s, w, at, i * 2)
        code = register_code(s, w, edge(s, w, at, i * 2 + 1))
        row = lookup(s, w, name, 0, 0)
        if row == 0 or code == 0:
            return 0
        put(w, row + 32, code)
        if code <= 5:
            put(w, S_SAVED_MASK, get(w, S_SAVED_MASK) | (1 << (code - 1)))
        i = i + 1
    return 0

def argument_words(s:readbuf, w:mutbuf, identifier:u64, definitions:u64) -> u64:
    at = typed(s, w, identifier, 5)
    if at == 0:
        return 0
    total = 0
    i = 0
    while i < word(s, at + 32) and get(w, S_BAD) == 0:
        child = edge(s, w, at, i)
        words = 0
        if definitions == 0:
            row = lookup(s, w, child, 0, 0)
            if row == 0:
                return 0
            words = get(w, row + 16)
        else:
            words = width(s, w, field(s, w, child, L_TYPE, 1))
        total = total + words
        i = i + 1
    return total

def call_record(s:readbuf, w:mutbuf, ins:u64, block:u64, opindex:u64) -> u64:
    n = get(w, S_CALL_NEXT)
    if n >= get(w, S_CALL_N):
        return abi(w, 36)
    row = get(w, S_CALL_AT) + n * 96
    args = field(s, w, ins, L_ARGS, 1)
    outs = field(s, w, ins, L_OUT, 1)
    a = argument_words(s, w, args, 0)
    b = argument_words(s, w, outs, 1)
    put(w, row, block)
    put(w, row + 8, opindex)
    put(w, row + 16, ins)
    put(w, row + 24, args)
    put(w, row + 32, outs)
    put(w, row + 40, a)
    put(w, row + 48, b)
    put(w, row + 72, field(s, w, field(s, w, ins, L_ATTRS, 1), L_FUNCTION, 1))
    if a > get(w, S_CALL_WORDS):
        put(w, S_CALL_WORDS, a)
    if b > get(w, S_RESULT_WORDS):
        put(w, S_RESULT_WORDS, b)
    put(w, S_CALL_NEXT, n + 1)
    return 0

def edge_record(s:readbuf, w:mutbuf, term:u64, block:u64, side:u64) -> u64:
    n = get(w, S_EDGE_NEXT)
    if n >= get(w, S_EDGE_N):
        return abi(w, 37)
    row = get(w, S_EDGE_AT) + n * 96
    target = field(s, w, term, L_TARGET, 1)
    args = field(s, w, term, L_ARGS, 1)
    destination = lookup(s, w, target, 1, 0)
    if destination == 0:
        return 0
    words = argument_words(s, w, args, 0)
    if words != get(w, destination + 40):
        return abi(w, 38)
    put(w, row, block)
    put(w, row + 8, side)
    put(w, row + 16, term)
    put(w, row + 24, target)
    put(w, row + 32, args)
    put(w, row + 40, words)
    put(w, row + 64, destination)
    put(w, S_EDGE_NEXT, n + 1)
    return 0

def return_record(s:readbuf, w:mutbuf, term:u64, block:u64) -> u64:
    n = get(w, S_RET_NEXT)
    if n >= get(w, S_RET_N):
        return abi(w, 39)
    row = get(w, S_RET_AT) + n * 64
    values = field(s, w, term, L_VALUES, 1)
    put(w, row, block)
    put(w, row + 8, term)
    put(w, row + 16, values)
    put(w, row + 24, argument_words(s, w, values, 0))
    put(w, S_RET_NEXT, n + 1)
    return 0

def staging(s:readbuf, w:mutbuf) -> u64:
    b = 0
    while b < get(w, S_BLOCK_N) and get(w, S_BAD) == 0:
        row = get(w, S_BLOCK_AT) + b * 64
        ops = typed(s, w, get(w, row + 24), 5)
        if ops == 0:
            return 0
        i = 0
        while i < word(s, ops + 32) and get(w, S_BAD) == 0:
            ins = edge(s, w, ops, i)
            if literal(s, w, field(s, w, ins, L_OP, 1), L_CALL) != 0:
                call_record(s, w, ins, b, i)
            i = i + 1
        term = get(w, row + 32)
        op = field(s, w, term, L_OP, 1)
        if literal(s, w, op, L_JUMP) != 0:
            edge_record(s, w, term, b, 0)
        elif literal(s, w, op, L_BRANCH) != 0:
            edge_record(s, w, field(s, w, term, L_THEN, 1), b, 1)
            edge_record(s, w, field(s, w, term, L_ELSE, 1), b, 2)
        elif literal(s, w, op, L_RET) != 0:
            return_record(s, w, term, b)
        b = b + 1
    return 0

def finish_frame(s:readbuf, w:mutbuf) -> u64:
    put(w, S_EDGE_SLOT, allocate(w, choose(get(w, S_EDGE_WORDS) == 0, 1, get(w, S_EDGE_WORDS))))
    put(w, S_CALL_SLOT, allocate(w, choose(get(w, S_CALL_WORDS) == 0, 1, get(w, S_CALL_WORDS))))
    put(w, S_RESULT_SLOT, allocate(w, choose(get(w, S_RESULT_WORDS) == 0, 1, get(w, S_RESULT_WORDS))))
    put(w, S_TEMPORARY, allocate(w, 4))
    i = 0
    saved = 0
    while i < 5:
        if (get(w, S_SAVED_MASK) & (1 << i)) != 0:
            at = get(w, S_SAVED_AT) + saved * 16
            put(w, at, i + 1)
            put(w, at + 8, allocate(w, 1))
            saved = saved + 1
        i = i + 1
    put(w, S_SAVED_N, saved)
    if get(w, S_CURSOR) > MAX - 15:
        return abi(w, 40)
    size = (get(w, S_CURSOR) + 15) & (MAX - 15)
    put(w, S_FRAME, size)
    if size > MAX_FRAME:
        put(w, S_ERROR, 1)
        literal_at = INDEX + L_FRAME_ERROR * 16
        prefix = get(w, literal_at + 8)
        i = 0
        while i < prefix:
            store(w, ERROR_AT + i, byte(w, get(w, literal_at) + i))
            i = i + 1
        name = typed(s, w, get(w, S_NAME), 4)
        if name == 0:
            return 0
        count = word(s, name + 16)
        if count > INDEX - ERROR_AT - prefix:
            return abi(w, 41)
        copy_bytes(w, s, ERROR_AT + prefix, word(s, name + 8), count)
        put(w, S_ERROR_N, prefix + count)
    elif get(w, S_SERIAL) == MAX:
        return abi(w, 42)
    return 0

def move_list(s:readbuf, w:mutbuf, identifier:u64, definitions:u64, write:u64) -> u64:
    at = typed(s, w, identifier, 5)
    if at == 0:
        return 0
    start = get(w, S_MOVE_NEXT)
    i = 0
    while i < word(s, at + 32) and get(w, S_BAD) == 0:
        child = edge(s, w, at, i)
        name = child
        if definitions != 0:
            name = field(s, w, child, L_NAME, 1)
        row = lookup(s, w, name, 0, 0)
        if row == 0:
            return 0
        count = get(w, row + 16)
        if definitions != 0:
            count = width(s, w, field(s, w, child, L_TYPE, 1))
        j = 0
        while j < count:
            n = get(w, S_MOVE_NEXT)
            if write != 0:
                if n >= get(w, S_MOVE_N):
                    return abi(w, 43)
                target = get(w, S_MOVE_AT) + n * 32
                put(w, target, row)
                put(w, target + 8, j)
                put(w, target + 16, get(w, row + 24) + j * 8)
                put(w, target + 24, get(w, row + 32))
            put(w, S_MOVE_NEXT, n + 1)
            j = j + 1
        i = i + 1
    return get(w, S_MOVE_AT) + start * 32

def moves(s:readbuf, w:mutbuf, write:u64) -> u64:
    put(w, S_MOVE_NEXT, 0)
    params = field(s, w, get(w, S_FN), L_PARAMS, 1)
    put(w, S_PARAM_AT, move_list(s, w, params, 1, write))
    put(w, S_PARAM_N, get(w, S_MOVE_NEXT))
    i = 0
    while i < get(w, S_CALL_N) and get(w, S_BAD) == 0:
        at = get(w, S_CALL_AT) + i * 96
        put(w, at + 56, move_list(s, w, get(w, at + 24), 0, write))
        put(w, at + 64, move_list(s, w, get(w, at + 32), 1, write))
        i = i + 1
    i = 0
    while i < get(w, S_EDGE_N) and get(w, S_BAD) == 0:
        at = get(w, S_EDGE_AT) + i * 96
        put(w, at + 48, move_list(s, w, get(w, at + 32), 0, write))
        target = get(w, at + 64)
        put(w, at + 56, move_list(s, w, get(w, target + 16), 1, write))
        i = i + 1
    i = 0
    while i < get(w, S_RET_N) and get(w, S_BAD) == 0:
        at = get(w, S_RET_AT) + i * 64
        put(w, at + 32, move_list(s, w, get(w, at + 16), 0, write))
        i = i + 1
    if write == 0:
        put(w, S_MOVE_N, get(w, S_MOVE_NEXT))
    elif get(w, S_MOVE_NEXT) != get(w, S_MOVE_N):
        return abi(w, 44)
    return 0

def reserve_moves(w:mutbuf) -> u64:
    put(w, S_NEED, get(w, S_MOVE_AT))
    reserve(w, get(w, S_MOVE_N), 32, S_MOVE_AT)
    return 0

def order(s:readbuf, w:mutbuf) -> u64:
    entry = field(s, w, get(w, S_FN), L_ENTRY, 1)
    put(w, S_ENTRY, lookup(s, w, entry, 1, 0))
    selected = get(w, S_ORDER)
    at = 0
    if selected != 0:
        at = typed(s, w, selected, 5)
        if at == 0 or word(s, at + 32) != get(w, S_BLOCK_N):
            return abi(w, 45)
    i = 0
    while i < get(w, S_BLOCK_N) and get(w, S_BAD) == 0:
        row = get(w, S_BLOCK_AT) + i * 64
        if selected != 0:
            row = lookup(s, w, edge(s, w, at, i), 1, 0)
        put(w, get(w, S_ORDER_AT) + i * 8, row)
        i = i + 1
    return 0

def divide(numerator:u64, denominator:u64) -> u64:
    if denominator == 0:
        return 0
    result = 0
    remainder = 0
    bit = 64
    while bit != 0:
        bit = bit - 1
        carry = remainder >> 63
        remainder = (remainder << 1) | ((numerator >> bit) & 1)
        if carry != 0 or remainder >= denominator:
            remainder = remainder - denominator
            result = result | (1 << bit)
    return result

def decimal(w:mutbuf, at:u64, value:u64) -> u64:
    power = 1
    while power <= divide(value, 10):
        power = power * 10
    cursor = at
    remaining = value
    while power != 0:
        digit = divide(remaining, power)
        store(w, cursor, 48 + digit)
        cursor = cursor + 1
        remaining = remaining - digit * power
        power = divide(power, 10)
    return cursor

def trap_label(w:mutbuf) -> u64:
    at = get(w, S_TRAP_AT)
    store(w, at, 102)
    store(w, at + 1, 110)
    cursor = decimal(w, at + 2, get(w, S_FN_INDEX))
    store(w, cursor, 95)
    store(w, cursor + 1, 116)
    store(w, cursor + 2, 114)
    store(w, cursor + 3, 97)
    store(w, cursor + 4, 112)
    store(w, cursor + 5, 95)
    cursor = decimal(w, cursor + 6, get(w, S_SERIAL) + 1)
    put(w, S_TRAP_N, cursor - at)
    return 0

def header(s:readbuf, w:mutbuf) -> u64:
    put(w, HEADER, PLAN)
    put(w, HEADER + 8, 1)
    put(w, HEADER + 16, get(w, S_LEASE))
    put(w, HEADER + 24, get(w, S_SEQ))
    put(w, HEADER + 32, get(w, S_FN_INDEX))
    put(w, HEADER + 40, get(w, S_FN))
    put(w, HEADER + 48, get(w, S_NAME))
    put(w, HEADER + 56, get(w, S_FRAME))
    put(w, HEADER + 64, get(w, S_CURSOR))
    put(w, HEADER + 72, get(w, S_SERIAL))
    put(w, HEADER + 80, get(w, S_SERIAL) + 1)
    put(w, HEADER + 88, get(w, S_SELECT))
    put(w, HEADER + 96, get(w, S_VALUE_N))
    put(w, HEADER + 104, get(w, S_BLOCK_N))
    put(w, HEADER + 112, get(w, S_CALL_N))
    put(w, HEADER + 120, get(w, S_EDGE_N))
    put(w, HEADER + 128, get(w, S_RET_N))
    put(w, HEADER + 136, get(w, S_MOVE_N))
    put(w, HEADER + 144, get(w, S_VALUE_AT))
    put(w, HEADER + 152, get(w, S_BLOCK_AT))
    put(w, HEADER + 160, get(w, S_CALL_AT))
    put(w, HEADER + 168, get(w, S_EDGE_AT))
    put(w, HEADER + 176, get(w, S_RET_AT))
    put(w, HEADER + 184, get(w, S_MOVE_AT))
    put(w, HEADER + 192, get(w, S_VHASH_AT))
    put(w, HEADER + 200, get(w, S_VHASH_N))
    put(w, HEADER + 208, get(w, S_BHASH_AT))
    put(w, HEADER + 216, get(w, S_BHASH_N))
    put(w, HEADER + 224, get(w, S_ORDER_AT))
    put(w, HEADER + 232, get(w, S_ENTRY))
    put(w, HEADER + 240, get(w, S_EDGE_WORDS))
    put(w, HEADER + 248, get(w, S_CALL_WORDS))
    put(w, HEADER + 256, get(w, S_RESULT_WORDS))
    put(w, HEADER + 264, get(w, S_EDGE_SLOT))
    put(w, HEADER + 272, get(w, S_CALL_SLOT))
    put(w, HEADER + 280, get(w, S_RESULT_SLOT))
    put(w, HEADER + 288, get(w, S_TEMPORARY))
    put(w, HEADER + 296, get(w, S_SAVED_N))
    put(w, HEADER + 304, get(w, S_SAVED_AT))
    put(w, HEADER + 312, get(w, S_PARAM_AT))
    put(w, HEADER + 320, get(w, S_PARAM_N))
    put(w, HEADER + 328, get(w, S_TRAP_AT))
    put(w, HEADER + 336, get(w, S_TRAP_N))
    put(w, HEADER + 344, get(w, S_NEED) - HEADER)
    put(w, HEADER + 352, length(s))
    put(w, HEADER + 360, get(w, S_ROOT))
    put(w, HEADER + 368, get(w, S_FN_COUNT))
    put(w, HEADER + 376, get(w, S_DISTINCT))
    put(w, HEADER + 384, get(w, S_REG_COUNT))
    return 0
'''

def source():
    constants=dict(CONSTANTS)
    data=bytearray(constants["DATA"])
    for index,value in enumerate(LITERALS):
        name=("FRAME_ERROR" if value.startswith("E_HIA_") else value.upper().strip("_"))
        constants["L_"+name]=index
        raw=value.encode("ascii");start=len(data);data.extend(raw)
        at=constants["INDEX"]+index*16
        data[at:at+8]=start.to_bytes(8,"little")
        data[at+8:at+16]=len(raw).to_bytes(8,"little")
    assert constants["INDEX"]+16*len(LITERALS)<=constants["DATA"]
    assert len(data)<constants["BASE"]
    assert max(constants["S_"+name]+8 for name in FIELDS)<=constants["ERROR_AT"]
    writes=[(at,int.from_bytes(data[at:at+8].ljust(8,b"\0"),"little"))
            for at in range(constants["INDEX"],len(data),8) if any(data[at:at+8])]
    helpers=[];calls=[]
    for start in range(0,len(writes),16):
        name="literal_"+str(start//16);calls.append("    "+name+"(w)")
        helpers.append("def "+name+"(w:mutbuf) -> u64:\n"+
            "\n".join("    put(w, %d, %d)"%pair for pair in writes[start:start+16])+"\n    return 0")
    helpers.append("def literal_table(w:mutbuf) -> u64:\n"+"\n".join(calls)+"\n    return 0")
    nodes=ast.parse(BODY+"\n"+"\n".join(helpers)).body
    header=next(node for node in nodes if node.name=="header")
    assert isinstance(header.body[-1],ast.Return)
    statements=header.body[:-1];parts=[]
    for at in range(0,len(statements),12):
        part=ast.FunctionDef(name="header_"+str(at//12),args=ast.parse(
            "def f(s:readbuf,w:mutbuf)->u64:\n    return 0").body[0].args,
            body=statements[at:at+12]+[ast.Return(value=ast.Constant(0))],
            decorator_list=[],returns=ast.Name(id="u64",ctx=ast.Load()))
        parts.append(part)
    header.body=[ast.Expr(value=ast.Call(func=ast.Name(id=n.name,ctx=ast.Load()),
        args=[ast.Name(id="s",ctx=ast.Load()),ast.Name(id="w",ctx=ast.Load())],keywords=[])) for n in parts]
    header.body.append(ast.Return(value=ast.Constant(0)))
    nodes.extend(parts)
    for node in nodes:
        if node.name in ("word","get"):
            argument="s" if node.name=="word" else "w"
            node.body=ast.parse("return "+" | ".join("(byte(%s, at + %d) << %d)"%(argument,i,8*i) for i in range(8))).body
        elif node.name=="put":
            node.body=ast.parse("\n".join("store(w, at + %d, (value >> %d) & 255)"%(i,8*i) for i in range(8))+"\nreturn 0").body
    return "\n".join(ast.unparse(ast.fix_missing_locations(n)) for n in nodes)+"\n",constants,dict(
        scope="PRIVATE_ADMITTED_FUNCTION_FRAME_AND_STAGING",reference_sha256=REFERENCE_SHA,
        plan_reference_sha256=PLAN_REFERENCE_SHA,original_function_allocation_order=True,
        checked_plan_and_Core_issuer_required=True,header_is_authentication=False,
        code_emission=False,Core_admission=False,machine_plan_validation=False,
        full_backend=False,frame_limit=65536,language_function_limit_not_reduced=True)
