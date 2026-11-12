"""Pure HIA ELF64 ET_REL writer over actual private issued Graph values.
NEW authoring. Python here only constructs immutable HIA source.
"""
import ast
from hashlib import sha256
def magic(text):return int.from_bytes(text.encode("ascii"),"little")
REFERENCE_SHA="c77cc453d33058ccbeea9e056191001982892a3e59386958090122ccf487c101"
CONSTANTS=dict(MAX=(1<<64)-1,BAD=0xfffffffd,GROW=0xfffffffe,MIN_WORK=4096,
 GRAPH=magic("HIAGRF01"),COMMAND=magic("HIAELC01"),EVENT=magic("HIAELE01"),
 MAX_OBJECT=67108864,MAX_SYMBOLS=65536,INDEX=1024,LITERAL_DATA=1536)
FIELDS=("LEASE","SEQ","BAD","ERROR","NEED","PHASE","NODES","EDGES","DATABASE",
 "ROOT","ALIGN","CODE_AT","CODE_N","SYMS","RELS","SYM_N","REL_N","REG_BASE",
 "REG_CAP","REG_N","TREE","SPANS","RELOC","SCRATCH","OVERCOUNT","NAME_AT",
 "NAME_N","NEW","ROW0","ROW1","ROW2","ROW3","LOCAL","GLOBAL","UNDEF","TEXT_O",
 "REL_O","SYM_O","STR_O","SHSTR_O","NOTE_O","SH_O","OBJECT_N","OUT_AT",
 "RESULT_AT","RESULT_N","STR_N")
CONSTANTS.update({"S_"+name:256+i*8 for i,name in enumerate(FIELDS)})
ERRORS=(
 "unreviewed text section alignment",
 "nonempty bounded immutable machine bytes required",
 "invalid symbol or relocation inventory",
 "invalid function symbol record",
 "invalid ELF symbol name",
 "duplicate or out-of-range function symbol",
 "function symbol ranges overlap",
 "only explicit PLT32 call relocations are supported",
 "call relocation does not point to an E8 placeholder",
 "duplicate or overlapping call relocations",
 "ELF symbol inventory exceeds limit",
 "ELF object exceeds byte budget")
LITERALS={**{"error"+str(i+1):v for i,v in enumerate(ERRORS)},
 "name":"name","offset":"offset","size":"size","global":"global",
 "symbol":"symbol","type":"type","addend":"addend",
 "sections":"\0.text\0.rela.text\0.symtab\0.strtab\0.shstrtab\0.note.GNU-stack\0"}
BODY=r'''
def elf_object(s:readbuf, r:readbuf, w:mutbuf) -> u32:
    if length(w) < MIN_WORK:
        return BAD
    fill_range(w, 0, MIN_WORK, 0)
    literal_table(w)
    run(s, r, w)
    if get(w, S_BAD) != 0:
        event(w, 3)
        return BAD
    if get(w, S_ERROR) != 0:
        event(w, 2)
        return 128
    if get(w, S_NEED) > length(w):
        event(w, 1)
        return GROW
    if get(w, S_RESULT_N) == 0:
        abi(w, 90)
        event(w, 3)
        return BAD
    event(w, 0)
    return 128

def run(s:readbuf, r:readbuf, w:mutbuf) -> u64:
    if header(s, r, w) == 0:
        return 0
    put(w, S_PHASE, 1)
    if arguments(s, w) == 0:
        return 0
    put(w, S_PHASE, 2)
    if scratch(w) == 0:
        return 0
    if definitions(s, w) == 0:
        return 0
    put(w, S_PHASE, 3)
    sort_pairs(w, get(w, S_SPANS), get(w, S_SYM_N))
    i = 1
    while i < get(w, S_SYM_N):
        if get(w, get(w, S_SPANS) + i * 16) < get(w, get(w, S_SPANS) + (i - 1) * 16 + 8):
            return semantic(w, 7)
        i = i + 1
    put(w, S_PHASE, 4)
    if relocations(s, w) == 0:
        return 0
    sort_pairs(w, get(w, S_RELOC), get(w, S_REL_N))
    i = 1
    while i < get(w, S_REL_N):
        if get(w, get(w, S_RELOC) + i * 16) - get(w, get(w, S_RELOC) + (i - 1) * 16) < 5:
            return semantic(w, 10)
        i = i + 1
    put(w, S_PHASE, 5)
    if get(w, S_OVERCOUNT) != 0 or get(w, S_REG_N) + 2 > MAX_SYMBOLS:
        return semantic(w, 11)
    put(w, S_UNDEF, get(w, S_REG_N) - get(w, S_SYM_N))
    if layout(w) == 0:
        return 0
    put(w, S_PHASE, 6)
    if get(w, S_NEED) > length(w):
        return 0
    return emit(s, w)

def abi(w:mutbuf, reason:u64) -> u64:
    if get(w, S_BAD) == 0:
        put(w, S_BAD, reason)
    return 0

def semantic(w:mutbuf, reason:u64) -> u64:
    if get(w, S_ERROR) == 0:
        put(w, S_ERROR, reason)
    return 0

def event(w:mutbuf, action:u64) -> u64:
    at = 0
    size = 0
    if action == 0:
        at = get(w, S_RESULT_AT)
        size = get(w, S_RESULT_N)
    elif action == 2:
        entry = INDEX + (get(w, S_ERROR) - 1) * 16
        at = get(w, entry)
        size = get(w, entry + 8)
    put(w, 0, EVENT)
    put(w, 8, 1)
    put(w, 16, action)
    put(w, 24, get(w, S_LEASE))
    put(w, 32, get(w, S_SEQ))
    put(w, 40, choose(action == 2, get(w, S_ERROR), 0))
    put(w, 48, get(w, S_NEED))
    put(w, 56, at)
    put(w, 64, size)
    put(w, 72, get(w, S_LOCAL))
    put(w, 80, get(w, S_GLOBAL))
    put(w, 88, get(w, S_UNDEF))
    put(w, 96, get(w, S_REL_N))
    put(w, 104, get(w, S_ALIGN))
    put(w, 112, get(w, S_PHASE))
    put(w, 120, get(w, S_BAD))
    return 0

def header(s:readbuf, r:readbuf, w:mutbuf) -> u64:
    if length(s) < 64 or length(r) != 96:
        return abi(w, 1)
    if word(s, 0) != GRAPH or word(s, 8) == 0 or word(s, 56) != 0:
        return abi(w, 2)
    count = word(s, 16)
    edges = word(s, 32)
    if count == 0 or count > (MAX - 64) >> 6:
        return abi(w, 3)
    edgebase = 64 + count * 64
    if edges > (MAX - edgebase) >> 3:
        return abi(w, 4)
    data = edgebase + edges * 8
    if data > length(s) or word(s, 40) != length(s) - data or word(s, 48) != length(s):
        return abi(w, 5)
    root = word(s, 24)
    if root == 0 or root > count:
        return abi(w, 6)
    if word(r, 0) != COMMAND or word(r, 8) != 1 or word(r, 16) != word(s, 8):
        return abi(w, 7)
    if word(r, 24) == 0 or word(r, 32) != length(s) or word(r, 40) != root:
        return abi(w, 8)
    at = 48
    while at < 96:
        if word(r, at) != 0:
            return abi(w, 9)
        at = at + 8
    put(w, S_LEASE, word(r, 16))
    put(w, S_SEQ, word(r, 24))
    put(w, S_NODES, count)
    put(w, S_EDGES, edges)
    put(w, S_DATABASE, data)
    put(w, S_ROOT, root)
    return 1

def node(s:readbuf, w:mutbuf, identifier:u64) -> u64:
    if identifier == 0 or identifier > get(w, S_NODES):
        return abi(w, 10)
    at = 64 + (identifier - 1) * 64
    kind = word(s, at)
    if kind > 9 or word(s, at + 56) != 0:
        return abi(w, 11)
    if kind == 5 or kind == 6 or kind == 7:
        if word(s, at + 8) != 0 or word(s, at + 16) != 0 or word(s, at + 40) == 0 or word(s, at + 48) != 0:
            return abi(w, 12)
        first = word(s, at + 24)
        count = word(s, at + 32)
        if kind == 6:
            if count > MAX >> 1:
                return abi(w, 13)
            count = count * 2
        if first > get(w, S_EDGES) or count > get(w, S_EDGES) - first:
            return abi(w, 14)
        return at
    if word(s, at + 24) != 0 or word(s, at + 32) != 0 or word(s, at + 40) != 0:
        return abi(w, 15)
    begin = word(s, at + 8)
    count = word(s, at + 16)
    aux = word(s, at + 48)
    if kind == 0 or kind == 1 or kind == 8:
        if begin != 0 or count != 0:
            return abi(w, 16)
        if (kind == 1 and aux > 1) or (kind != 1 and aux != 0):
            return abi(w, 17)
        return at
    if begin < get(w, S_DATABASE) or begin > length(s) or count > length(s) - begin:
        return abi(w, 18)
    if kind == 2:
        if aux > 1 or (count == 0 and aux != 0):
            return abi(w, 19)
        if count > 0 and byte(s, begin + count - 1) == 0:
            return abi(w, 20)
    elif kind == 3:
        if count != 8 or aux != 0:
            return abi(w, 21)
    elif kind == 9:
        if aux != 0:
            return abi(w, 22)
    return at

def edge(s:readbuf, w:mutbuf, at:u64, index:u64) -> u64:
    count = word(s, at + 32)
    if word(s, at) == 6:
        count = count * 2
    if index >= count:
        return abi(w, 23)
    value = word(s, 64 + get(w, S_NODES) * 64 + (word(s, at + 24) + index) * 8)
    if value == 0 or value > get(w, S_NODES):
        return abi(w, 24)
    return value

def unsigned_value(s:readbuf, w:mutbuf, identifier:u64) -> u64:
    at = node(s, w, identifier)
    if at == 0:
        return MAX
    if word(s, at) != 2 or word(s, at + 48) != 0 or word(s, at + 16) > 8:
        return MAX
    value = 0
    i = 0
    while i < word(s, at + 16):
        value = value | (byte(s, word(s, at + 8) + i) << (i * 8))
        i = i + 1
    return value

def minus_four(s:readbuf, w:mutbuf, identifier:u64) -> u64:
    at = node(s, w, identifier)
    if at == 0:
        return 0
    if word(s, at) != 2 or word(s, at + 48) != 1 or word(s, at + 16) != 1:
        return 0
    return choose(byte(s, word(s, at + 8)) == 4, 1, 0)

def arguments(s:readbuf, w:mutbuf) -> u64:
    root = node(s, w, get(w, S_ROOT))
    if root == 0:
        return 0
    if word(s, root) != 5 or word(s, root + 32) != 4:
        return abi(w, 25)
    alignment = unsigned_value(s, w, edge(s, w, root, 0))
    if alignment != 16 and alignment != 32 and alignment != 64:
        return semantic(w, 1)
    put(w, S_ALIGN, alignment)
    code = node(s, w, edge(s, w, root, 1))
    if code == 0:
        return 0
    size = word(s, code + 16)
    if word(s, code) != 9 or size == 0 or size > MAX_OBJECT:
        return semantic(w, 2)
    put(w, S_CODE_AT, word(s, code + 8))
    put(w, S_CODE_N, size)
    symbols = node(s, w, edge(s, w, root, 2))
    if symbols == 0:
        return 0
    if word(s, symbols) != 5 or word(s, symbols + 32) == 0 or word(s, symbols + 32) >= MAX_SYMBOLS:
        return semantic(w, 3)
    rels = node(s, w, edge(s, w, root, 3))
    if rels == 0:
        return 0
    # The multiplicative division is exact for the already bounded u26 size.
    maximum = (size * 3435973837) >> 34
    if word(s, rels) != 5 or word(s, rels + 32) > maximum:
        return semantic(w, 3)
    put(w, S_SYMS, symbols)
    put(w, S_RELS, rels)
    put(w, S_SYM_N, word(s, symbols + 32))
    put(w, S_REL_N, word(s, rels + 32))
    return 1

def scratch(w:mutbuf) -> u64:
    capacity = get(w, S_SYM_N) + get(w, S_REL_N)
    if capacity > MAX_SYMBOLS:
        capacity = MAX_SYMBOLS
    put(w, S_REG_CAP, capacity)
    put(w, S_REG_BASE, MIN_WORK)
    spans = MIN_WORK + capacity * 96
    rels = spans + get(w, S_SYM_N) * 16
    end = rels + get(w, S_REL_N) * 16
    put(w, S_SPANS, spans)
    put(w, S_RELOC, rels)
    put(w, S_SCRATCH, end)
    put(w, S_NEED, end)
    if end > length(w):
        return 0
    fill_range(w, MIN_WORK, end - MIN_WORK, 0)
    return 1

def key_equal(s:readbuf, w:mutbuf, at:u64, literal:u64) -> u64:
    if word(s, at) != 4:
        return 0
    offset = get(w, INDEX + literal * 16)
    count = get(w, INDEX + literal * 16 + 8)
    if word(s, at + 16) != count:
        return 0
    i = 0
    while i < count:
        if byte(s, word(s, at + 8) + i) != byte(w, offset + i):
            return 0
        i = i + 1
    if word(s, at + 48) != count:
        return abi(w, 26)
    return 1

def record(s:readbuf, w:mutbuf, identifier:u64, relocation:u64) -> u64:
    at = node(s, w, identifier)
    if at == 0:
        return 0
    if word(s, at) != 6 or word(s, at + 32) != 4:
        return 0
    mask = 0
    i = 0
    while i < 4:
        key = node(s, w, edge(s, w, at, i * 2))
        value = edge(s, w, at, i * 2 + 1)
        if key == 0 or value == 0:
            return 0
        column = 4
        if relocation == 0:
            if key_equal(s, w, key, L_name) != 0:
                column = 0
            elif key_equal(s, w, key, L_offset) != 0:
                column = 1
            elif key_equal(s, w, key, L_size) != 0:
                column = 2
            elif key_equal(s, w, key, L_global) != 0:
                column = 3
        else:
            if key_equal(s, w, key, L_offset) != 0:
                column = 0
            elif key_equal(s, w, key, L_symbol) != 0:
                column = 1
            elif key_equal(s, w, key, L_type) != 0:
                column = 2
            elif key_equal(s, w, key, L_addend) != 0:
                column = 3
        if column == 4:
            return 0
        bit = 1 << column
        if (mask & bit) != 0:
            return 0
        mask = mask | bit
        put(w, S_ROW0 + column * 8, value)
        i = i + 1
    return choose(mask == 15, 1, 0)

def name(s:readbuf, w:mutbuf, identifier:u64) -> u64:
    at = node(s, w, identifier)
    if at == 0:
        return 0
    size = word(s, at + 16)
    if word(s, at) != 4 or size == 0 or size > 192:
        return semantic(w, 5)
    begin = word(s, at + 8)
    i = 0
    while i < size:
        part = byte(s, begin + i)
        alpha = (part >= 65 and part <= 90) or (part >= 97 and part <= 122) or part == 95
        if not alpha and (i == 0 or part < 48 or part > 57):
            return semantic(w, 5)
        i = i + 1
    if word(s, at + 48) != size:
        return abi(w, 27)
    put(w, S_NAME_AT, begin)
    put(w, S_NAME_N, size)
    return 1

def reg(w:mutbuf, index:u64) -> u64:
    return get(w, S_REG_BASE) + (index - 1) * 96

def height(w:mutbuf, index:u64) -> u64:
    if index == 0:
        return 0
    return get(w, reg(w, index) + 80)

def update_height(w:mutbuf, index:u64) -> u64:
    at = reg(w, index)
    left = height(w, get(w, at + 64))
    right = height(w, get(w, at + 72))
    put(w, at + 80, choose(left > right, left, right) + 1)
    return 0

def attach(w:mutbuf, old:u64, replacement:u64) -> u64:
    parent = get(w, reg(w, old) + 88)
    if parent == 0:
        put(w, S_TREE, replacement)
    else:
        at = reg(w, parent)
        if get(w, at + 64) == old:
            put(w, at + 64, replacement)
        else:
            put(w, at + 72, replacement)
    put(w, reg(w, replacement) + 88, parent)
    return 0

def rotate_left(w:mutbuf, index:u64) -> u64:
    at = reg(w, index)
    next = get(w, at + 72)
    middle = get(w, reg(w, next) + 64)
    attach(w, index, next)
    put(w, reg(w, next) + 64, index)
    put(w, at + 88, next)
    put(w, at + 72, middle)
    if middle != 0:
        put(w, reg(w, middle) + 88, index)
    update_height(w, index)
    update_height(w, next)
    return next

def rotate_right(w:mutbuf, index:u64) -> u64:
    at = reg(w, index)
    next = get(w, at + 64)
    middle = get(w, reg(w, next) + 72)
    attach(w, index, next)
    put(w, reg(w, next) + 72, index)
    put(w, at + 88, next)
    put(w, at + 64, middle)
    if middle != 0:
        put(w, reg(w, middle) + 88, index)
    update_height(w, index)
    update_height(w, next)
    return next

def rebalance(w:mutbuf, index:u64) -> u64:
    current = index
    while current != 0:
        at = reg(w, current)
        left = get(w, at + 64)
        right = get(w, at + 72)
        lh = height(w, left)
        rh = height(w, right)
        update_height(w, current)
        if lh > rh + 1:
            child = reg(w, left)
            if height(w, get(w, child + 72)) > height(w, get(w, child + 64)):
                rotate_left(w, left)
            current = rotate_right(w, current)
        elif rh > lh + 1:
            child = reg(w, right)
            if height(w, get(w, child + 64)) > height(w, get(w, child + 72)):
                rotate_right(w, right)
            current = rotate_left(w, current)
        current = get(w, reg(w, current) + 88)
    return 0

def name_order(s:readbuf, w:mutbuf, index:u64) -> u64:
    at = reg(w, index)
    size = get(w, S_NAME_N)
    other = get(w, at + 8)
    count = choose(size < other, size, other)
    i = 0
    while i < count:
        a = byte(s, get(w, S_NAME_AT) + i)
        b = byte(s, get(w, at) + i)
        if a < b:
            return 1
        if a > b:
            return 2
        i = i + 1
    if size < other:
        return 1
    if size > other:
        return 2
    return 0

def register_name(s:readbuf, w:mutbuf) -> u64:
    parent = 0
    current = get(w, S_TREE)
    direction = 0
    put(w, S_NEW, 0)
    while current != 0:
        direction = name_order(s, w, current)
        if direction == 0:
            return current
        parent = current
        current = get(w, reg(w, current) + choose(direction == 1, 64, 72))
    if get(w, S_REG_N) == get(w, S_REG_CAP):
        put(w, S_OVERCOUNT, 1)
        return 0
    current = get(w, S_REG_N) + 1
    put(w, S_REG_N, current)
    at = reg(w, current)
    put(w, at, get(w, S_NAME_AT))
    put(w, at + 8, get(w, S_NAME_N))
    put(w, at + 80, 1)
    put(w, at + 88, parent)
    if parent == 0:
        put(w, S_TREE, current)
    else:
        put(w, reg(w, parent) + choose(direction == 1, 64, 72), current)
        rebalance(w, parent)
    put(w, S_NEW, 1)
    return current

def first_name(w:mutbuf) -> u64:
    current = get(w, S_TREE)
    if current == 0:
        return 0
    while get(w, reg(w, current) + 64) != 0:
        current = get(w, reg(w, current) + 64)
    return current

def next_name(w:mutbuf, index:u64) -> u64:
    current = get(w, reg(w, index) + 72)
    if current != 0:
        while get(w, reg(w, current) + 64) != 0:
            current = get(w, reg(w, current) + 64)
        return current
    current = index
    parent = get(w, reg(w, current) + 88)
    while parent != 0:
        if get(w, reg(w, parent) + 64) == current:
            return parent
        current = parent
        parent = get(w, reg(w, current) + 88)
    return 0

def definitions(s:readbuf, w:mutbuf) -> u64:
    i = 0
    while i < get(w, S_SYM_N):
        identifier = edge(s, w, get(w, S_SYMS), i)
        if record(s, w, identifier, 0) == 0:
            return semantic(w, 4)
        if name(s, w, get(w, S_ROW0)) == 0:
            return 0
        global_node = node(s, w, get(w, S_ROW3))
        if global_node == 0:
            return 0
        offset = unsigned_value(s, w, get(w, S_ROW1))
        size = unsigned_value(s, w, get(w, S_ROW2))
        if word(s, global_node) != 1 or offset >= get(w, S_CODE_N) or size == 0 or size > get(w, S_CODE_N):
            return semantic(w, 6)
        if size > get(w, S_CODE_N) - offset:
            return semantic(w, 6)
        index = register_name(s, w)
        if index == 0 or get(w, S_NEW) == 0:
            return semantic(w, 6)
        at = reg(w, index)
        put(w, at + 16, 1)
        put(w, at + 24, offset)
        put(w, at + 32, size)
        exported = word(s, global_node + 48)
        put(w, at + 40, exported)
        if exported == 0:
            put(w, S_LOCAL, get(w, S_LOCAL) + 1)
        else:
            put(w, S_GLOBAL, get(w, S_GLOBAL) + 1)
        put(w, get(w, S_SPANS) + i * 16, offset)
        put(w, get(w, S_SPANS) + i * 16 + 8, offset + size)
        i = i + 1
    return choose(get(w, S_BAD) == 0, 1, 0)

def relocations(s:readbuf, w:mutbuf) -> u64:
    i = 0
    while i < get(w, S_REL_N):
        identifier = edge(s, w, get(w, S_RELS), i)
        if record(s, w, identifier, 1) == 0:
            return semantic(w, 8)
        offset = unsigned_value(s, w, get(w, S_ROW0))
        typ = unsigned_value(s, w, get(w, S_ROW2))
        if offset < 1 or offset >= get(w, S_CODE_N) - 3 or typ != 4:
            return semantic(w, 8)
        if minus_four(s, w, get(w, S_ROW3)) == 0:
            return semantic(w, 8)
        if name(s, w, get(w, S_ROW1)) == 0:
            return 0
        position = get(w, S_CODE_AT) + offset
        if byte(s, position - 1) != 232:
            return semantic(w, 9)
        j = 0
        while j < 4:
            if byte(s, position + j) != 0:
                return semantic(w, 9)
            j = j + 1
        index = register_name(s, w)
        put(w, get(w, S_RELOC) + i * 16, offset)
        put(w, get(w, S_RELOC) + i * 16 + 8, index)
        i = i + 1
    return choose(get(w, S_BAD) == 0, 1, 0)

def pair_greater(w:mutbuf, base:u64, a:u64, b:u64) -> u64:
    left = get(w, base + a * 16)
    right = get(w, base + b * 16)
    if left > right:
        return 1
    if left < right:
        return 0
    return choose(get(w, base + a * 16 + 8) > get(w, base + b * 16 + 8), 1, 0)

def pair_swap(w:mutbuf, base:u64, a:u64, b:u64) -> u64:
    x = get(w, base + a * 16)
    y = get(w, base + a * 16 + 8)
    put(w, base + a * 16, get(w, base + b * 16))
    put(w, base + a * 16 + 8, get(w, base + b * 16 + 8))
    put(w, base + b * 16, x)
    put(w, base + b * 16 + 8, y)
    return 0

def sift(w:mutbuf, base:u64, count:u64, start:u64) -> u64:
    root = start
    while root < count:
        child = root * 2 + 1
        if child >= count:
            break
        if child + 1 < count:
            if pair_greater(w, base, child + 1, child) != 0:
                child = child + 1
        if pair_greater(w, base, root, child) != 0:
            break
        pair_swap(w, base, root, child)
        root = child
    return 0

def sort_pairs(w:mutbuf, base:u64, count:u64) -> u64:
    i = count >> 1
    while i > 0:
        i = i - 1
        sift(w, base, count, i)
    remaining = count
    while remaining > 1:
        remaining = remaining - 1
        pair_swap(w, base, 0, remaining)
        sift(w, base, remaining, 0)
    return 0

def layout(w:mutbuf) -> u64:
    strings = 1
    current = first_name(w)
    visited = 0
    while current != 0:
        at = reg(w, current)
        put(w, at + 48, strings)
        strings = strings + get(w, at + 8) + 1
        visited = visited + 1
        current = next_name(w, current)
    if visited != get(w, S_REG_N):
        return abi(w, 28)
    put(w, S_STR_N, strings)
    put(w, S_TEXT_O, 64)
    rels = (64 + get(w, S_CODE_N) + 7) & (MAX - 7)
    symbols = rels + get(w, S_REL_N) * 24
    strtab = symbols + (get(w, S_REG_N) + 2) * 24
    shstr = strtab + strings
    note = shstr + L_sections_N
    section = (note + 7) & (MAX - 7)
    total = section + 448
    put(w, S_REL_O, rels)
    put(w, S_SYM_O, symbols)
    put(w, S_STR_O, strtab)
    put(w, S_SHSTR_O, shstr)
    put(w, S_NOTE_O, note)
    put(w, S_SH_O, section)
    put(w, S_OBJECT_N, total)
    if total > MAX_OBJECT:
        return semantic(w, 12)
    output = (get(w, S_SCRATCH) + 15) & (MAX - 15)
    put(w, S_OUT_AT, output)
    put(w, S_NEED, output + total)
    return 1

def emit(s:readbuf, w:mutbuf) -> u64:
    output = get(w, S_OUT_AT)
    total = get(w, S_OBJECT_N)
    fill_range(w, output, total, 0)
    copy_bytes(w, s, output + 64, get(w, S_CODE_AT), get(w, S_CODE_N))
    # ELF identification and exact ELF64 little-endian ET_REL header.
    put(w, output, 282584257676671)
    put16(w, output + 16, 1)
    put16(w, output + 18, 62)
    put32(w, output + 20, 1)
    put(w, output + 40, get(w, S_SH_O))
    put16(w, output + 52, 64)
    put16(w, output + 58, 64)
    put16(w, output + 60, 7)
    put16(w, output + 62, 5)
    # The null symbol is zero-filled; index1 is local STT_SECTION for .text.
    put(w, output + get(w, S_SYM_O) + 24, 281487861612544)
    current = first_name(w)
    while current != 0:
        at = reg(w, current)
        copy_bytes(w, s, output + get(w, S_STR_O) + get(w, at + 48), get(w, at), get(w, at + 8))
        current = next_name(w, current)
    index = 2
    group = 0
    while group < 3:
        current = first_name(w)
        while current != 0:
            at = reg(w, current)
            defined = get(w, at + 16)
            exported = get(w, at + 40)
            chosen = (group == 0 and defined == 1 and exported == 0) or (group == 1 and defined == 1 and exported == 1) or (group == 2 and defined == 0)
            if chosen:
                put(w, at + 56, index)
                symbol_entry(w, output + get(w, S_SYM_O) + index * 24, at)
                index = index + 1
            current = next_name(w, current)
        group = group + 1
    if index != get(w, S_REG_N) + 2:
        return abi(w, 29)
    i = 0
    while i < get(w, S_REL_N):
        at = get(w, S_RELOC) + i * 16
        destination = output + get(w, S_REL_O) + i * 24
        put(w, destination, get(w, at))
        put(w, destination + 8, (get(w, reg(w, get(w, at + 8)) + 56) << 32) | 4)
        put(w, destination + 16, MAX - 3)
        i = i + 1
    i = 0
    while i < L_sections_N:
        store(w, output + get(w, S_SHSTR_O) + i, byte(w, L_sections_AT + i))
        i = i + 1
    section_headers(w, output)
    put(w, S_PHASE, 7)
    put(w, S_RESULT_AT, output)
    put(w, S_RESULT_N, total)
    return 1

def symbol_entry(w:mutbuf, destination:u64, at:u64) -> u64:
    put32(w, destination, get(w, at + 48))
    if get(w, at + 16) == 0:
        store(w, destination + 4, 16)
        return 0
    if get(w, at + 40) == 0:
        store(w, destination + 4, 2)
        store(w, destination + 5, 2)
    else:
        store(w, destination + 4, 18)
    put16(w, destination + 6, 1)
    put(w, destination + 8, get(w, at + 24))
    put(w, destination + 16, get(w, at + 32))
    return 0

def section(w:mutbuf, where:u64, name:u64, typ:u64, flags:u64, offset:u64, size:u64, link:u64, info:u64, alignment:u64, entry:u64) -> u64:
    put32(w, where, name)
    put32(w, where + 4, typ)
    put(w, where + 8, flags)
    put(w, where + 24, offset)
    put(w, where + 32, size)
    put32(w, where + 40, link)
    put32(w, where + 44, info)
    put(w, where + 48, alignment)
    put(w, where + 56, entry)
    return 0

def section_headers(w:mutbuf, output:u64) -> u64:
    base = output + get(w, S_SH_O)
    section(w, base + 64, SECTION_text, 1, 6, 64, get(w, S_CODE_N), 0, 0, get(w, S_ALIGN), 0)
    section(w, base + 128, SECTION_rela, 4, 0, get(w, S_REL_O), get(w, S_REL_N) * 24, 3, 1, 8, 24)
    section(w, base + 192, SECTION_symtab, 2, 0, get(w, S_SYM_O), (get(w, S_REG_N) + 2) * 24, 4, get(w, S_LOCAL) + 2, 8, 24)
    section(w, base + 256, SECTION_strtab, 3, 0, get(w, S_STR_O), get(w, S_STR_N), 0, 0, 1, 0)
    section(w, base + 320, SECTION_shstrtab, 3, 0, get(w, S_SHSTR_O), L_sections_N, 0, 0, 1, 0)
    section(w, base + 384, SECTION_note, 1, 0, get(w, S_NOTE_O), 0, 0, 0, 1, 0)
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

def put16(w:mutbuf, at:u64, value:u64) -> u64:
    store(w, at, value & 255)
    store(w, at + 1, (value >> 8) & 255)
    return 0

def put32(w:mutbuf, at:u64, value:u64) -> u64:
    store(w, at, value & 255)
    store(w, at + 1, (value >> 8) & 255)
    store(w, at + 2, (value >> 16) & 255)
    store(w, at + 3, (value >> 24) & 255)
    return 0
'''

def source():
    constants=dict(CONSTANTS)
    raw=bytearray(constants["LITERAL_DATA"])
    for index,(name,value) in enumerate(LITERALS.items()):
        constants["L_"+name]=index
        data=value.encode("ascii");begin=len(raw);raw.extend(data)
        entry=constants["INDEX"]+index*16
        raw[entry:entry+8]=begin.to_bytes(8,"little")
        raw[entry+8:entry+16]=len(data).to_bytes(8,"little")
        constants["L_"+name+"_AT"]=begin
        constants["L_"+name+"_N"]=len(data)
    for key,name in (("text",".text"),("rela",".rela.text"),("symtab",".symtab"),
                     ("strtab",".strtab"),("shstrtab",".shstrtab"),("note",".note.GNU-stack")):
        constants["SECTION_"+key]=LITERALS["sections"].index(name+"\0")
    assert len(raw)<constants["MIN_WORK"]
    assert max(constants["S_"+name]+8 for name in FIELDS)<=constants["INDEX"]
    writes=[(at,int.from_bytes(raw[at:at+8].ljust(8,b"\0"),"little"))
            for at in range(constants["INDEX"],len(raw),8) if any(raw[at:at+8])]
    helpers=[];calls=[]
    for start in range(0,len(writes),16):
        name="literal_"+str(start//16);calls.append("    "+name+"(w)")
        lines=["def "+name+"(w:mutbuf) -> u64:"]
        lines+=["    put(w, %d, %d)"%(at,value) for at,value in writes[start:start+16]]
        lines+=["    return 0"];helpers.append("\n".join(lines))
    body=BODY+"\n"+"\n".join(helpers)+"\ndef literal_table(w:mutbuf) -> u64:\n"+"\n".join(calls)+"\n    return 0\n"
    nodes=ast.parse(body).body
    for node in nodes:
        if node.name in ("word","get"):
            argument="s" if node.name=="word" else "w"
            node.body=ast.parse("return "+" | ".join("(byte(%s, at + %d) << %d)"%(argument,i,8*i) for i in range(8))).body
        elif node.name=="put":
            node.body=ast.parse("\n".join("store(w, at + %d, (value >> %d) & 255)"%(i,8*i) for i in range(8))+"\nreturn 0").body
    return "\n".join(ast.unparse(ast.fix_missing_locations(n)) for n in nodes)+"\n",constants,dict(
        status="NEW_AUTHORING_ONLY",reference_sha256=REFERENCE_SHA,
        private_graph_kind_layout="HIAGRF01-64-64-8",
        root_items=["text_alignment","code","symbols","relocations"],
        actual_immutable_input_leases_required=True,header_is_authority=False,
        exact_output_byte_limit=67108864,exact_symbol_limit=65536,
        no_JSON_depth_or_node_quota=True,no_total_calls_quota=True,
        native_AVL_names=True,native_heapsort_spans_and_relocations=True,
        full_ELF_bytes_native=True,all_twelve_original_error_messages=True,
        grow_pure_recompute_same_immutable_inputs=True,
        arbitrary_foreign_Python_callbacks_and_subclass_keys_closed=False)
