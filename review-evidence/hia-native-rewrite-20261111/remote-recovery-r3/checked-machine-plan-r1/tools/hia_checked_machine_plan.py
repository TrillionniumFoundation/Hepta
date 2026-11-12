"""Native checked-machine-plan value checks over a private immutable Graph.

This author owns the exact-dict snapshot gate and the plan/schema/lifetime checks.
Between these two generated images a fixed HIA caller must complete the original
bounded canonical wire operation (flags 2, 8 MiB, the actual integer digit limit).
The semantic image alone is not a public plan admission entry or a Core verifier.
"""
import ast

def magic(text):return int.from_bytes(text.encode("ascii"),"little")
REFERENCE_SHA="ae3e54c4dc3299ba9b6d0a9b4caec55e26f3233e5699d3a0cab7deb1337efb8a"
CORE_REFERENCE_SHA="76a222745e13fe29825a661be206243f137ada7b57292b07ab7513a40146fb92"
GRAPH_COMMON_SHA="32ceeceb285f9d3d3250a920c40ebd7bac8e1a44460c5321d714f6f5a0da2b3c"
VALUE_TYPES=("i8","u8","i16","u16","i32","u32","i64","u64","isize","usize","bool")
REGISTERS=("rbx","r12","r13","r14","r15","r8","r9")
LEAF_OPS=("const","int.add.wrap","int.add.checked","int.sub.wrap","int.sub.checked",
 "int.mul.wrap","int.mul.checked","int.div.checked","int.rem.checked",
 "int.shl.checked","int.shr.checked","int.neg.checked","int.cast",
 "bit.and","bit.or","bit.xor","bit.not","compare.eq","compare.ne","compare.lt",
 "compare.le","compare.gt","compare.ge","bool.and","bool.or","bool.not","select",
 "buffer.len","buffer.load","buffer.store")
MESSAGES=(
 "plan must be an object",
 "plan requires bounded plain JSON data",
 "unknown plan schema",
 "plan has missing or unreviewed fields",
 "plan belongs to a different Core",
 "invalid block order map",
 "unknown function in block order",
 "block order must name every member exactly once",
 "function order must name every member exactly once",
 "scratch assignment must bijectively rename only r10 and r11",
 "instruction choices must be explicit and complete",
 "unreviewed immediate move encoding",
 "unreviewed immediate arithmetic encoding",
 "unreviewed function alignment",
 "unreviewed scalar select encoding",
 "value_registers must be a function map",
 "unknown function in value register assignment",
 "value registers must be explicit assignments admitted by this plan version",
 "caller-clobbered value registers require a leaf opcode whitelist; no calls, swap or allocation/bulk helpers",
 "leaf registers require scalar/borrowed parameters and scalar returns",
 "register assignment requires an existing integer or boolean SSA value",
 "interfering values ")
LITERALS={x:x for x in ("schema","core_sha256","block_order","function_order","scratch_registers",
 "instruction_selection","function_alignment","value_registers","functions","name","blocks","id",
 "params","returns","ops","out","type","args","term","op","values","cond","then","else",
 "move_immediate","alu_immediate","scalar_select","r10","r11","movabs","mov32_if_exact","imm32",
 "imm8_if_exact","branch","cmov_scalar","ret","jump","readbuf","mutbuf")}
LITERALS.update({"schema_v1":"hepta.hia.agent.block-layout.v1",
 "schema_v2":"hepta.hia.agent.machine-plan.v2","schema_v3":"hepta.hia.agent.machine-plan.v3",
 "schema_v4":"hepta.hia.agent.machine-plan.v4",
 **{"type_"+str(i):v for i,v in enumerate(VALUE_TYPES)},
 **{"reg_"+str(i+1):v for i,v in enumerate(REGISTERS)},
 **{"leaf_"+str(i):v for i,v in enumerate(LEAF_OPS)},
 **{"error_"+str(i+1):"E_HIA_MACHINE_PLAN: "+v for i,v in enumerate(MESSAGES)},
 "slash":"/","colon":": ","and":" and ","share":" share "})
CONSTANTS=dict(MAX=(1<<64)-1,BAD=0xfffffffd,GROW=0xfffffffe,MIN_WORK=32768,
 GRAPH=magic("HIAGRF01"),COMMAND=magic("HIAMPC01"),EVENT=magic("HIAMPE01"),
 RESULT=magic("HIAMPR01"),INDEX=2048,DATA=8192,ERROR_AT=20480,
 FRAME_BASE=24576,BASE=32768,MAX_NODES=262144,MAX_DEPTH=64)
FIELDS=("BAD","ERROR","LEASE","REQUEST","MODE","ROOT","CORE","PLAN","NODES","EDGES","DATABASE",
 "VISITED","QUEUED","DEPTH","CUR","NEED","VERSION","FUNCTIONS","FN_N","NEXT_KEY","NEXT_VALUE",
 "HASH_AT","HASH_N","DEF_AT","DEF_N","DEF_NEXT","VECTOR_AT","VECTOR_N","BLOCK_INDEX",
 "FN","FN_NAME","BLOCKS","MAPPING","LEAF","REG_LIMIT","ERROR_SIZE","PHASE",
 "ERROR_LEFT","ERROR_RIGHT","ERROR_BLOCK","ERROR_REG")
CONSTANTS.update({"S_"+name:256+i*8 for i,name in enumerate(FIELDS)})
BODY=r'''
def plan_snapshot_gate(s:readbuf, r:readbuf, w:mutbuf) -> u32:
    if length(w) < MIN_WORK:
        return BAD
    fill_range(w, 0, MIN_WORK, 0)
    literal_table(w)
    if frame(s, r, w, 0) != 0:
        put(w, S_PHASE, 1)
        at = node(s, w, get(w, S_PLAN))
        if at != 0:
            if word(s, at) != 6:
                semantic(w, 1)
            else:
                snapshot(s, w)
    return finish(s, r, w)

def plan_semantics(s:readbuf, r:readbuf, w:mutbuf) -> u32:
    if length(w) < MIN_WORK:
        return BAD
    fill_range(w, 0, MIN_WORK, 0)
    literal_table(w)
    if frame(s, r, w, 1) != 0:
        put(w, S_PHASE, 2)
        validate_plan(s, r, w)
    return finish(s, r, w)

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

def abi(w:mutbuf, reason:u64) -> u64:
    if get(w, S_BAD) == 0:
        put(w, S_BAD, reason)
    return 0

def semantic(w:mutbuf, reason:u64) -> u64:
    if get(w, S_ERROR) == 0:
        put(w, S_ERROR, reason)
    return 0

def frame(s:readbuf, r:readbuf, w:mutbuf, mode:u64) -> u64:
    put(w, S_NEED, MIN_WORK)
    if length(s) < 64 or length(r) != 128:
        return abi(w, 1)
    if word(r, 0) != COMMAND or word(r, 8) != 1 or word(r, 16) == 0 or word(r, 24) == 0:
        return abi(w, 2)
    if word(r, 48) != mode or word(r, 56) != 0 or word(r, 40) != length(s):
        return abi(w, 3)
    at = 96
    while at < 128:
        if word(r, at) != 0:
            return abi(w, 4)
        at = at + 8
    if word(s, 0) != GRAPH or word(s, 8) != word(r, 16) or word(s, 56) != 0:
        return abi(w, 5)
    nodes = word(s, 16)
    edges = word(s, 32)
    if nodes == 0 or nodes > (MAX - 64) >> 6:
        return abi(w, 6)
    end = 64 + nodes * 64
    if edges > (MAX - end) >> 3:
        return abi(w, 7)
    end = end + edges * 8
    if end > length(s) or word(s, 40) != length(s) - end or word(s, 48) != length(s):
        return abi(w, 8)
    if word(s, 24) == 0 or word(s, 24) > nodes or word(r, 32) != word(s, 24):
        return abi(w, 9)
    put(w, S_LEASE, word(r, 16))
    put(w, S_REQUEST, word(r, 24))
    put(w, S_ROOT, word(r, 32))
    put(w, S_MODE, mode)
    put(w, S_NODES, nodes)
    put(w, S_EDGES, edges)
    put(w, S_DATABASE, end)
    root = node(s, w, get(w, S_ROOT))
    if root == 0:
        return 0
    if word(s, root) != 5 or word(s, root + 32) != 2:
        return abi(w, 10)
    put(w, S_CORE, edge(s, w, root, 0))
    put(w, S_PLAN, edge(s, w, root, 1))
    return choose(get(w, S_BAD) == 0, 1, 0)

def node(s:readbuf, w:mutbuf, identifier:u64) -> u64:
    if identifier == 0 or identifier > get(w, S_NODES):
        return abi(w, 11)
    at = 64 + (identifier - 1) * 64
    kind = word(s, at)
    if kind > 11 or word(s, at + 56) != 0:
        return abi(w, 12)
    if kind == 5 or kind == 6 or kind == 7:
        if word(s, at + 8) != 0 or word(s, at + 16) != 0 or word(s, at + 40) == 0 or word(s, at + 48) != 0:
            return abi(w, 13)
        first = word(s, at + 24)
        count = word(s, at + 32)
        if kind == 6:
            if count > MAX >> 1:
                return abi(w, 14)
            count = count * 2
        if first > get(w, S_EDGES) or count > get(w, S_EDGES) - first:
            return abi(w, 15)
        return at
    if word(s, at + 24) != 0 or word(s, at + 32) != 0 or word(s, at + 40) != 0:
        return abi(w, 16)
    begin = word(s, at + 8)
    count = word(s, at + 16)
    aux = word(s, at + 48)
    if kind == 0 or kind == 1 or kind == 8:
        if begin != 0 or count != 0:
            return abi(w, 17)
        if (kind == 1 and aux > 1) or (kind != 1 and aux != 0):
            return abi(w, 18)
        return at
    if begin < get(w, S_DATABASE) or begin > length(s) or count > length(s) - begin:
        return abi(w, 19)
    if kind == 2:
        if aux > 1 or (count == 0 and aux != 0):
            return abi(w, 20)
        if count > 0 and byte(s, begin + count - 1) == 0:
            return abi(w, 21)
    elif kind == 3:
        if count != 8 or aux != 0:
            return abi(w, 22)
    elif kind == 9 or kind == 10:
        if aux != 0:
            return abi(w, 23)
    return at

def typed(s:readbuf, w:mutbuf, identifier:u64, kind:u64) -> u64:
    at = node(s, w, identifier)
    if at == 0:
        return 0
    if word(s, at) != kind:
        return abi(w, 24)
    return at

def kind_is(s:readbuf, w:mutbuf, identifier:u64, kind:u64) -> u64:
    if identifier == 0:
        return 0
    at = node(s, w, identifier)
    if at == 0:
        return 0
    return choose(word(s, at) == kind, 1, 0)

def edge(s:readbuf, w:mutbuf, at:u64, index:u64) -> u64:
    count = word(s, at + 32)
    if word(s, at) == 6:
        count = count * 2
    if index >= count:
        return abi(w, 25)
    value = word(s, 64 + get(w, S_NODES) * 64 + (word(s, at + 24) + index) * 8)
    if value == 0 or value > get(w, S_NODES):
        return abi(w, 26)
    return value

def literal(s:readbuf, w:mutbuf, identifier:u64, index:u64) -> u64:
    if identifier == 0:
        return 0
    at = node(s, w, identifier)
    if at == 0 or word(s, at) != 4:
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

def same(s:readbuf, w:mutbuf, left:u64, right:u64) -> u64:
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

def less(s:readbuf, w:mutbuf, left:u64, right:u64) -> u64:
    a = typed(s, w, left, 4)
    b = typed(s, w, right, 4)
    if a == 0 or b == 0:
        return 0
    an = word(s, a + 16)
    bn = word(s, b + 16)
    i = 0
    while i < an and i < bn:
        x = byte(s, word(s, a + 8) + i)
        y = byte(s, word(s, b + 8) + i)
        if x < y:
            return 1
        if x > y:
            return 0
        i = i + 1
    return choose(an < bn, 1, 0)

def field(s:readbuf, w:mutbuf, identifier:u64, index:u64, required:u64) -> u64:
    at = typed(s, w, identifier, 6)
    if at == 0:
        return 0
    i = 0
    while i < word(s, at + 32):
        if literal(s, w, edge(s, w, at, i * 2), index) != 0:
            return edge(s, w, at, i * 2 + 1)
        if get(w, S_BAD) != 0:
            return 0
        i = i + 1
    if required != 0:
        return abi(w, 27)
    return 0

def snapshot(s:readbuf, w:mutbuf) -> u64:
    put(w, S_VISITED, 0)
    put(w, S_QUEUED, 1)
    put(w, S_DEPTH, 0)
    put(w, S_CUR, get(w, S_PLAN))
    running = 1
    while running != 0 and get(w, S_BAD) == 0 and get(w, S_ERROR) == 0:
        queued = get(w, S_QUEUED)
        if queued == 0:
            return abi(w, 28)
        put(w, S_QUEUED, queued - 1)
        count = get(w, S_VISITED) + 1
        depth = get(w, S_DEPTH)
        put(w, S_VISITED, count)
        if count > MAX_NODES or depth > MAX_DEPTH:
            return semantic(w, 2)
        at = node(s, w, get(w, S_CUR))
        if at == 0:
            return 0
        kind = word(s, at)
        if kind == 5 or kind == 6:
            i = 0
            while i < depth:
                if get(w, FRAME_BASE + i * 32) == get(w, S_CUR):
                    return semantic(w, 2)
                i = i + 1
            children = word(s, at + 32)
            if children > MAX_NODES - count - get(w, S_QUEUED):
                return semantic(w, 2)
            if kind == 6:
                i = 0
                while i < children:
                    key = node(s, w, edge(s, w, at, i * 2))
                    if key == 0:
                        return 0
                    if word(s, key) != 4:
                        return semantic(w, 2)
                    i = i + 1
            put(w, S_QUEUED, get(w, S_QUEUED) + children)
            frame_at = FRAME_BASE + depth * 32
            put(w, frame_at, get(w, S_CUR))
            put(w, frame_at + 8, at)
            put(w, frame_at + 16, 0)
            put(w, frame_at + 24, kind)
            put(w, S_DEPTH, depth + 1)
        elif kind != 0 and kind != 1 and kind != 2 and kind != 4:
            return semantic(w, 2)
        running = snapshot_next(s, w)
    return choose(get(w, S_BAD) == 0 and get(w, S_ERROR) == 0, 1, 0)

def snapshot_next(s:readbuf, w:mutbuf) -> u64:
    while get(w, S_DEPTH) != 0:
        frame_at = FRAME_BASE + (get(w, S_DEPTH) - 1) * 32
        at = get(w, frame_at + 8)
        index = get(w, frame_at + 16)
        if index < word(s, at + 32):
            put(w, frame_at + 16, index + 1)
            child = index
            if get(w, frame_at + 24) == 6:
                child = index * 2 + 1
            put(w, S_CUR, edge(s, w, at, child))
            return choose(get(w, S_BAD) == 0, 1, 0)
        put(w, S_DEPTH, get(w, S_DEPTH) - 1)
    if get(w, S_QUEUED) != 0:
        return abi(w, 29)
    return 0

def next_entry(s:readbuf, w:mutbuf, identifier:u64, previous:u64) -> u64:
    at = typed(s, w, identifier, 6)
    if at == 0:
        return 0
    best = 0
    value = 0
    i = 0
    while i < word(s, at + 32) and get(w, S_BAD) == 0:
        key = edge(s, w, at, i * 2)
        eligible = 1
        if previous != 0:
            eligible = less(s, w, previous, key)
        if eligible != 0:
            if best == 0:
                best = key
                value = edge(s, w, at, i * 2 + 1)
            elif less(s, w, key, best) != 0:
                best = key
                value = edge(s, w, at, i * 2 + 1)
        i = i + 1
    put(w, S_NEXT_KEY, best)
    put(w, S_NEXT_VALUE, value)
    return best

def plan_fields(s:readbuf, w:mutbuf) -> u64:
    at = node(s, w, get(w, S_PLAN))
    if at == 0:
        return 0
    if word(s, at) != 6:
        return semantic(w, 1)
    schema = field(s, w, get(w, S_PLAN), L_SCHEMA, 0)
    version = schema_version(s, w, schema)
    if version == 0:
        return semantic(w, 3)
    put(w, S_VERSION, version)
    expected = 7
    count = 3
    if version >= 2:
        expected = 127
        count = 7
    if version >= 3:
        expected = 255
        count = 8
    if word(s, at + 32) != count:
        return semantic(w, 4)
    mask = 0
    i = 0
    while i < count:
        bit = field_bit(s, w, edge(s, w, at, i * 2))
        if bit == 0 or (mask & bit) != 0:
            return semantic(w, 4)
        mask = mask | bit
        i = i + 1
    if mask != expected:
        return semantic(w, 4)
    return choose(get(w, S_BAD) == 0, 1, 0)

def core_hash(s:readbuf, r:readbuf, w:mutbuf) -> u64:
    at = node(s, w, field(s, w, get(w, S_PLAN), L_CORE_SHA256, 1))
    if at == 0:
        return 0
    if word(s, at) != 4 or word(s, at + 16) != 64:
        return semantic(w, 5)
    i = 0
    while i < 32:
        value = byte(r, 64 + i)
        hi = value >> 4
        lo = value & 15
        hi = choose(hi < 10, 48 + hi, 87 + hi)
        lo = choose(lo < 10, 48 + lo, 87 + lo)
        if byte(s, word(s, at + 8) + i * 2) != hi or byte(s, word(s, at + 8) + i * 2 + 1) != lo:
            return semantic(w, 5)
        i = i + 1
    return 1

def find_function(s:readbuf, w:mutbuf, name:u64) -> u64:
    functions = typed(s, w, get(w, S_FUNCTIONS), 5)
    if functions == 0:
        return 0
    i = 0
    while i < get(w, S_FN_N) and get(w, S_BAD) == 0:
        fn = edge(s, w, functions, i)
        if same(s, w, name, field(s, w, fn, L_NAME, 1)) != 0:
            return fn
        i = i + 1
    return 0

def permutation(s:readbuf, w:mutbuf, order:u64, members:u64, key:u64, reason:u64) -> u64:
    at = node(s, w, order)
    other = typed(s, w, members, 5)
    if at == 0 or other == 0:
        return 0
    count = word(s, other + 32)
    if word(s, at) != 5 or word(s, at + 32) != count:
        return semantic(w, reason)
    i = 0
    while i < count:
        if kind_is(s, w, edge(s, w, at, i), 4) == 0:
            return semantic(w, reason)
        i = i + 1
    if count > (MAX - BASE) >> 3:
        return abi(w, 30)
    need = BASE + count * 8
    if need > get(w, S_NEED):
        put(w, S_NEED, need)
    if need > length(w):
        return 0
    fill_range(w, BASE, count * 8, 0)
    i = 0
    while i < count and get(w, S_BAD) == 0:
        name = edge(s, w, at, i)
        found = MAX
        j = 0
        while j < count and found == MAX:
            item = edge(s, w, other, j)
            candidate = field(s, w, item, key, 1)
            if same(s, w, name, candidate) != 0:
                found = j
            j = j + 1
        if found == MAX:
            return semantic(w, reason)
        if get(w, BASE + found * 8) != 0:
            return semantic(w, reason)
        put(w, BASE + found * 8, 1)
        i = i + 1
    return choose(get(w, S_BAD) == 0, 1, 0)

def block_orders(s:readbuf, w:mutbuf) -> u64:
    identifier = field(s, w, get(w, S_PLAN), L_BLOCK_ORDER, 1)
    at = node(s, w, identifier)
    if at == 0:
        return 0
    if word(s, at) != 6 or (word(s, at + 32) == 0 and get(w, S_VERSION) == 1):
        return semantic(w, 6)
    previous = 0
    visited = 0
    while visited < word(s, at + 32):
        previous = next_entry(s, w, identifier, previous)
        if previous == 0:
            return abi(w, 31)
        order = get(w, S_NEXT_VALUE)
        fn = find_function(s, w, previous)
        if get(w, S_BAD) != 0:
            return 0
        if fn == 0:
            return semantic(w, 7)
        blocks = field(s, w, fn, L_BLOCKS, 1)
        if permutation(s, w, order, blocks, L_ID, 8) == 0:
            return 0
        visited = visited + 1
    return 1

def scratch(s:readbuf, w:mutbuf) -> u64:
    identifier = field(s, w, get(w, S_PLAN), L_SCRATCH_REGISTERS, 1)
    at = node(s, w, identifier)
    if at == 0:
        return 0
    if word(s, at) != 6 or word(s, at + 32) != 2:
        return semantic(w, 10)
    a = field(s, w, identifier, L_R10, 0)
    b = field(s, w, identifier, L_R11, 0)
    if literal(s, w, a, L_R10) != 0 and literal(s, w, b, L_R11) != 0:
        return 1
    if literal(s, w, a, L_R11) != 0 and literal(s, w, b, L_R10) != 0:
        return 1
    return semantic(w, 10)

def choices(s:readbuf, w:mutbuf) -> u64:
    identifier = field(s, w, get(w, S_PLAN), L_INSTRUCTION_SELECTION, 1)
    at = node(s, w, identifier)
    if at == 0:
        return 0
    expected = choose(get(w, S_VERSION) >= 3, 3, 2)
    if word(s, at) != 6 or word(s, at + 32) != expected:
        return semantic(w, 11)
    move = field(s, w, identifier, L_MOVE_IMMEDIATE, 0)
    alu = field(s, w, identifier, L_ALU_IMMEDIATE, 0)
    select = 0
    if expected == 3:
        select = field(s, w, identifier, L_SCALAR_SELECT, 0)
    if move == 0 or alu == 0 or (expected == 3 and select == 0):
        return semantic(w, 11)
    if literal(s, w, move, L_MOVABS) == 0 and literal(s, w, move, L_MOV32_IF_EXACT) == 0:
        return semantic(w, 12)
    if literal(s, w, alu, L_IMM32) == 0 and literal(s, w, alu, L_IMM8_IF_EXACT) == 0:
        return semantic(w, 13)
    align = node(s, w, field(s, w, get(w, S_PLAN), L_FUNCTION_ALIGNMENT, 1))
    if align == 0:
        return 0
    if word(s, align) != 2 or word(s, align + 16) != 1 or word(s, align + 48) != 0:
        return semantic(w, 14)
    value = byte(s, word(s, align + 8))
    if value != 1 and value != 16 and value != 32 and value != 64:
        return semantic(w, 14)
    if expected == 3:
        if literal(s, w, select, L_BRANCH) == 0 and literal(s, w, select, L_CMOV_SCALAR) == 0:
            return semantic(w, 15)
    return 1

def mapping_shape(s:readbuf, w:mutbuf) -> u64:
    at = node(s, w, get(w, S_MAPPING))
    if at == 0:
        return 0
    if word(s, at) != 6:
        return semantic(w, 18)
    put(w, S_LEAF, 0)
    i = 0
    while i < word(s, at + 32):
        name = edge(s, w, at, i * 2)
        reg = edge(s, w, at, i * 2 + 1)
        if kind_is(s, w, name, 4) == 0:
            return semantic(w, 18)
        code = register_code(s, w, reg)
        if code == 0 or code > get(w, S_REG_LIMIT):
            return semantic(w, 18)
        if code > 5:
            put(w, S_LEAF, 1)
        i = i + 1
    return choose(get(w, S_BAD) == 0, 1, 0)

def leaf_check(s:readbuf, w:mutbuf) -> u64:
    if get(w, S_LEAF) == 0:
        return 1
    blocks = typed(s, w, get(w, S_BLOCKS), 5)
    if blocks == 0:
        return 0
    b = 0
    while b < word(s, blocks + 32):
        block = edge(s, w, blocks, b)
        ops = typed(s, w, field(s, w, block, L_OPS, 1), 5)
        if ops == 0:
            return 0
        i = 0
        while i < word(s, ops + 32):
            instruction = edge(s, w, ops, i)
            if leaf_opcode(s, w, field(s, w, instruction, L_OP, 1)) == 0:
                return semantic(w, 19)
            i = i + 1
        b = b + 1
    params = typed(s, w, field(s, w, get(w, S_FN), L_PARAMS, 1), 5)
    returns = typed(s, w, field(s, w, get(w, S_FN), L_RETURNS, 1), 5)
    if params == 0 or returns == 0:
        return 0
    i = 0
    while i < word(s, params + 32):
        param = edge(s, w, params, i)
        typ = field(s, w, param, L_TYPE, 1)
        if scalar_type(s, w, typ) == 0 and literal(s, w, typ, L_READBUF) == 0 and literal(s, w, typ, L_MUTBUF) == 0:
            return semantic(w, 20)
        i = i + 1
    i = 0
    while i < word(s, returns + 32):
        if scalar_type(s, w, edge(s, w, returns, i)) == 0:
            return semantic(w, 20)
        i = i + 1
    return choose(get(w, S_BAD) == 0, 1, 0)

def count_definitions(s:readbuf, w:mutbuf) -> u64:
    blocks = typed(s, w, get(w, S_BLOCKS), 5)
    if blocks == 0:
        return 0
    count = 0
    b = 0
    while b < word(s, blocks + 32):
        block = edge(s, w, blocks, b)
        params = typed(s, w, field(s, w, block, L_PARAMS, 1), 5)
        ops = typed(s, w, field(s, w, block, L_OPS, 1), 5)
        if params == 0 or ops == 0:
            return 0
        amount = word(s, params + 32)
        if amount > MAX - count:
            return abi(w, 32)
        count = count + amount
        i = 0
        while i < word(s, ops + 32):
            instruction = edge(s, w, ops, i)
            out = typed(s, w, field(s, w, instruction, L_OUT, 1), 5)
            if out == 0:
                return 0
            amount = word(s, out + 32)
            if amount > MAX - count:
                return abi(w, 33)
            count = count + amount
            i = i + 1
        b = b + 1
    if count > (MAX - BASE) >> 6:
        return abi(w, 34)
    def_end = BASE + count * 64
    if count > (MAX - 1) >> 1:
        return abi(w, 35)
    capacity = 2
    while capacity < count * 2 + 1:
        if capacity > MAX >> 1:
            return abi(w, 36)
        capacity = capacity * 2
    if capacity > (MAX - def_end) >> 3:
        return abi(w, 37)
    vector = def_end + capacity * 8
    if count > (MAX - vector) >> 3:
        return abi(w, 38)
    block_index = vector + count * 8
    block_count = word(s, blocks + 32)
    if block_count == MAX or block_count + 1 > (MAX - block_index) >> 3:
        return abi(w, 49)
    need = block_index + (block_count + 1) * 8
    if need > get(w, S_NEED):
        put(w, S_NEED, need)
    put(w, S_DEF_AT, BASE)
    put(w, S_DEF_N, count)
    put(w, S_DEF_NEXT, 0)
    put(w, S_HASH_AT, def_end)
    put(w, S_HASH_N, capacity)
    put(w, S_VECTOR_AT, vector)
    put(w, S_BLOCK_INDEX, block_index)
    if need > length(w):
        return 0
    fill_range(w, BASE, need - BASE, 0)
    return 1

def name_hash(s:readbuf, w:mutbuf, name:u64) -> u64:
    at = typed(s, w, name, 4)
    if at == 0:
        return 0
    value = 14695981039346656037
    i = 0
    while i < word(s, at + 16):
        value = (value ^ byte(s, word(s, at + 8) + i)) * 1099511628211
        i = i + 1
    return value

def definition(s:readbuf, w:mutbuf, name:u64, insert:u64) -> u64:
    count = get(w, S_HASH_N)
    index = name_hash(s, w, name) & (count - 1)
    visits = 0
    while visits < count and get(w, S_BAD) == 0:
        slot = get(w, S_HASH_AT) + index * 8
        old = get(w, slot)
        if old == 0:
            if insert != 0:
                put(w, slot, insert)
            return insert
        if same(s, w, name, get(w, old)) != 0:
            if insert != 0:
                return abi(w, 39)
            return old
        index = (index + 1) & (count - 1)
        visits = visits + 1
    return abi(w, 40)

def add_definitions(s:readbuf, w:mutbuf, identifier:u64, block:u64, first:u64) -> u64:
    at = typed(s, w, identifier, 5)
    if at == 0:
        return 0
    i = 0
    while i < word(s, at + 32):
        value = edge(s, w, at, i)
        name = field(s, w, value, L_NAME, 1)
        typ = field(s, w, value, L_TYPE, 1)
        n = get(w, S_DEF_NEXT)
        if n >= get(w, S_DEF_N):
            return abi(w, 41)
        row = get(w, S_DEF_AT) + n * 64
        put(w, row, name)
        put(w, row + 8, typ)
        put(w, row + 16, block)
        put(w, row + 24, first)
        put(w, row + 32, first)
        if definition(s, w, name, row) == 0:
            return 0
        put(w, S_DEF_NEXT, n + 1)
        i = i + 1
    return 1

def fill_definitions(s:readbuf, w:mutbuf) -> u64:
    blocks = typed(s, w, get(w, S_BLOCKS), 5)
    if blocks == 0:
        return 0
    b = 0
    while b < word(s, blocks + 32):
        block = edge(s, w, blocks, b)
        put(w, get(w, S_BLOCK_INDEX) + b * 8, get(w, S_DEF_NEXT))
        if add_definitions(s, w, field(s, w, block, L_PARAMS, 1), b, 0) == 0:
            return 0
        ops = typed(s, w, field(s, w, block, L_OPS, 1), 5)
        if ops == 0:
            return 0
        i = 0
        while i < word(s, ops + 32):
            instruction = edge(s, w, ops, i)
            if add_definitions(s, w, field(s, w, instruction, L_OUT, 1), b, i + 1) == 0:
                return 0
            i = i + 1
        b = b + 1
    put(w, get(w, S_BLOCK_INDEX) + b * 8, get(w, S_DEF_NEXT))
    if get(w, S_DEF_NEXT) != get(w, S_DEF_N):
        return abi(w, 42)
    return 1

def assign_values(s:readbuf, w:mutbuf) -> u64:
    at = typed(s, w, get(w, S_MAPPING), 6)
    if at == 0:
        return 0
    i = 0
    while i < word(s, at + 32):
        name = edge(s, w, at, i * 2)
        row = definition(s, w, name, 0)
        if get(w, S_BAD) != 0:
            return 0
        if row == 0:
            return semantic(w, 21)
        if scalar_type(s, w, get(w, row + 8)) == 0:
            return semantic(w, 21)
        code = register_code(s, w, edge(s, w, at, i * 2 + 1))
        put(w, row + 40, code)
        i = i + 1
    return choose(get(w, S_BAD) == 0, 1, 0)

def use_value(s:readbuf, w:mutbuf, name:u64, block:u64, position:u64) -> u64:
    row = definition(s, w, name, 0)
    if row == 0:
        return abi(w, 43)
    if get(w, row + 16) != block or get(w, row + 24) > position:
        return abi(w, 44)
    put(w, row + 32, position)
    return 1

def use_list(s:readbuf, w:mutbuf, identifier:u64, block:u64, position:u64) -> u64:
    at = typed(s, w, identifier, 5)
    if at == 0:
        return 0
    i = 0
    while i < word(s, at + 32):
        if use_value(s, w, edge(s, w, at, i), block, position) == 0:
            return 0
        i = i + 1
    return 1

def use_terminal(s:readbuf, w:mutbuf, term:u64, block:u64, position:u64) -> u64:
    op = field(s, w, term, L_OP, 1)
    if literal(s, w, op, L_RET) != 0:
        return use_list(s, w, field(s, w, term, L_VALUES, 1), block, position)
    if literal(s, w, op, L_JUMP) != 0:
        return use_list(s, w, field(s, w, term, L_ARGS, 1), block, position)
    if literal(s, w, op, L_BRANCH) != 0:
        if use_value(s, w, field(s, w, term, L_COND, 1), block, position) == 0:
            return 0
        yes = field(s, w, term, L_THEN, 1)
        no = field(s, w, term, L_ELSE, 1)
        if use_list(s, w, field(s, w, yes, L_ARGS, 1), block, position) == 0:
            return 0
        return use_list(s, w, field(s, w, no, L_ARGS, 1), block, position)
    return choose(get(w, S_BAD) == 0, 1, 0)

def vector_less(s:readbuf, w:mutbuf, left:u64, right:u64) -> u64:
    a = get(w, left + 40)
    b = get(w, right + 40)
    if a != b:
        return choose(a < b, 1, 0)
    a = get(w, left + 24)
    b = get(w, right + 24)
    if a != b:
        return choose(a < b, 1, 0)
    return less(s, w, get(w, left), get(w, right))

def vector_swap(w:mutbuf, a:u64, b:u64) -> u64:
    base = get(w, S_VECTOR_AT)
    value = get(w, base + a * 8)
    put(w, base + a * 8, get(w, base + b * 8))
    put(w, base + b * 8, value)
    return 0

def sift(s:readbuf, w:mutbuf, root:u64, count:u64) -> u64:
    base = get(w, S_VECTOR_AT)
    running = 1
    while running != 0:
        if root >= count >> 1:
            return 0
        child = root * 2 + 1
        if child >= count:
            return 0
        if child + 1 < count:
            if vector_less(s, w, get(w, base + child * 8), get(w, base + (child + 1) * 8)) != 0:
                child = child + 1
        if vector_less(s, w, get(w, base + root * 8), get(w, base + child * 8)) == 0:
            return 0
        vector_swap(w, root, child)
        root = child
    return 0

def check_intervals(s:readbuf, w:mutbuf, block:u64, block_name:u64) -> u64:
    count = 0
    i = get(w, get(w, S_BLOCK_INDEX) + block * 8)
    end = get(w, get(w, S_BLOCK_INDEX) + (block + 1) * 8)
    if i > end or end > get(w, S_DEF_N):
        return abi(w, 50)
    while i < end:
        row = get(w, S_DEF_AT) + i * 64
        if get(w, row + 40) != 0:
            put(w, get(w, S_VECTOR_AT) + count * 8, row)
            count = count + 1
        i = i + 1
    put(w, S_VECTOR_N, count)
    i = count >> 1
    while i > 0:
        i = i - 1
        sift(s, w, i, count)
    i = count
    while i > 1:
        i = i - 1
        vector_swap(w, 0, i)
        sift(s, w, 0, i)
    i = 1
    while i < count:
        left = get(w, get(w, S_VECTOR_AT) + (i - 1) * 8)
        right = get(w, get(w, S_VECTOR_AT) + i * 8)
        if get(w, left + 40) == get(w, right + 40) and get(w, left + 32) >= get(w, right + 24):
            put(w, S_ERROR_LEFT, get(w, left))
            put(w, S_ERROR_RIGHT, get(w, right))
            put(w, S_ERROR_BLOCK, block_name)
            put(w, S_ERROR_REG, get(w, left + 40))
            return semantic(w, 22)
        i = i + 1
    return choose(get(w, S_BAD) == 0, 1, 0)

def lifetimes(s:readbuf, w:mutbuf) -> u64:
    blocks = typed(s, w, get(w, S_BLOCKS), 5)
    if blocks == 0:
        return 0
    b = 0
    while b < word(s, blocks + 32):
        block = edge(s, w, blocks, b)
        ops = typed(s, w, field(s, w, block, L_OPS, 1), 5)
        if ops == 0:
            return 0
        i = 0
        while i < word(s, ops + 32):
            instruction = edge(s, w, ops, i)
            if use_list(s, w, field(s, w, instruction, L_ARGS, 1), b, i + 1) == 0:
                return 0
            i = i + 1
        if use_terminal(s, w, field(s, w, block, L_TERM, 1), b, word(s, ops + 32) + 1) == 0:
            return 0
        if check_intervals(s, w, b, field(s, w, block, L_ID, 1)) == 0:
            return 0
        b = b + 1
    return 1

def value_registers(s:readbuf, w:mutbuf) -> u64:
    identifier = field(s, w, get(w, S_PLAN), L_VALUE_REGISTERS, 1)
    at = node(s, w, identifier)
    if at == 0:
        return 0
    if word(s, at) != 6:
        return semantic(w, 16)
    put(w, S_REG_LIMIT, choose(get(w, S_VERSION) == 4, 7, 5))
    i = 0
    while i < word(s, at + 32):
        name = edge(s, w, at, i * 2)
        if kind_is(s, w, name, 4) == 0:
            return semantic(w, 17)
        fn = find_function(s, w, name)
        if get(w, S_BAD) != 0:
            return 0
        if fn == 0:
            return semantic(w, 17)
        i = i + 1
    previous = 0
    visited = 0
    while visited < word(s, at + 32):
        previous = next_entry(s, w, identifier, previous)
        if previous == 0:
            return abi(w, 45)
        put(w, S_FN_NAME, previous)
        put(w, S_FN, find_function(s, w, previous))
        put(w, S_MAPPING, get(w, S_NEXT_VALUE))
        put(w, S_BLOCKS, field(s, w, get(w, S_FN), L_BLOCKS, 1))
        if mapping_shape(s, w) == 0 or leaf_check(s, w) == 0:
            return 0
        if count_definitions(s, w) == 0 or fill_definitions(s, w) == 0:
            return 0
        if assign_values(s, w) == 0 or lifetimes(s, w) == 0:
            return 0
        visited = visited + 1
    return 1

def validate_plan(s:readbuf, r:readbuf, w:mutbuf) -> u64:
    if plan_fields(s, w) == 0 or core_hash(s, r, w) == 0:
        return 0
    put(w, S_PHASE, 3)
    functions = field(s, w, get(w, S_CORE), L_FUNCTIONS, 1)
    at = typed(s, w, functions, 5)
    if at == 0:
        return 0
    put(w, S_FUNCTIONS, functions)
    put(w, S_FN_N, word(s, at + 32))
    if block_orders(s, w) == 0:
        return 0
    if get(w, S_VERSION) >= 2:
        order = field(s, w, get(w, S_PLAN), L_FUNCTION_ORDER, 1)
        if permutation(s, w, order, functions, L_NAME, 9) == 0:
            return 0
        if scratch(s, w) == 0 or choices(s, w) == 0:
            return 0
    if get(w, S_VERSION) >= 3:
        put(w, S_PHASE, 4)
        if value_registers(s, w) == 0:
            return 0
    put(w, S_PHASE, 5)
    return choose(get(w, S_BAD) == 0 and get(w, S_ERROR) == 0, 1, 0)

def error_literal(w:mutbuf, index:u64) -> u64:
    row = INDEX + index * 16
    size = get(w, row + 8)
    at = ERROR_AT + get(w, S_ERROR_SIZE)
    if size > FRAME_BASE - at:
        return abi(w, 46)
    i = 0
    while i < size:
        store(w, at + i, byte(w, get(w, row) + i))
        i = i + 1
    put(w, S_ERROR_SIZE, get(w, S_ERROR_SIZE) + size)
    return 1

def error_name(s:readbuf, w:mutbuf, identifier:u64) -> u64:
    at = typed(s, w, identifier, 4)
    if at == 0:
        return 0
    size = word(s, at + 16)
    target = ERROR_AT + get(w, S_ERROR_SIZE)
    if size > FRAME_BASE - target:
        return abi(w, 47)
    copy_bytes(w, s, target, word(s, at + 8), size)
    put(w, S_ERROR_SIZE, get(w, S_ERROR_SIZE) + size)
    return 1

def error_text(s:readbuf, w:mutbuf) -> u64:
    put(w, S_ERROR_SIZE, 0)
    reason = get(w, S_ERROR)
    if reason == 0 or reason > 22:
        return abi(w, 48)
    error_literal(w, L_ERROR_1 + reason - 1)
    if reason == 22:
        error_name(s, w, get(w, S_FN_NAME))
        error_literal(w, L_SLASH)
        error_name(s, w, get(w, S_ERROR_BLOCK))
        error_literal(w, L_COLON)
        error_name(s, w, get(w, S_ERROR_LEFT))
        error_literal(w, L_AND)
        error_name(s, w, get(w, S_ERROR_RIGHT))
        error_literal(w, L_SHARE)
        error_literal(w, L_REG_1 + get(w, S_ERROR_REG) - 1)
    return choose(get(w, S_BAD) == 0, 1, 0)

def finish(s:readbuf, r:readbuf, w:mutbuf) -> u32:
    action = 0
    returned = 128
    at = 0
    size = 0
    if get(w, S_BAD) == 0 and get(w, S_ERROR) != 0:
        error_text(s, w)
    if get(w, S_BAD) != 0:
        action = 3
        returned = BAD
    elif get(w, S_ERROR) != 0:
        action = 2
        at = ERROR_AT
        size = get(w, S_ERROR_SIZE)
    elif get(w, S_NEED) > length(w):
        action = 1
        returned = GROW
    elif get(w, S_MODE) == 1:
        at = 1024
        size = 128
        put(w, at, RESULT)
        put(w, at + 8, 1)
        put(w, at + 16, get(w, S_LEASE))
        put(w, at + 24, get(w, S_REQUEST))
        put(w, at + 32, get(w, S_CORE))
        put(w, at + 40, get(w, S_PLAN))
        put(w, at + 48, get(w, S_VERSION))
        put(w, at + 56, length(s))
        copy_bytes(w, r, at + 64, 64, 32)
    put(w, 0, EVENT)
    put(w, 8, 1)
    put(w, 16, action)
    put(w, 24, get(w, S_LEASE))
    put(w, 32, get(w, S_REQUEST))
    put(w, 40, get(w, S_MODE))
    put(w, 48, get(w, S_ERROR))
    put(w, 56, get(w, S_NEED))
    put(w, 64, at)
    put(w, 72, size)
    put(w, 80, get(w, S_VERSION))
    put(w, 88, get(w, S_VISITED))
    put(w, 96, get(w, S_PLAN))
    put(w, 104, get(w, S_CORE))
    put(w, 112, get(w, S_PHASE))
    put(w, 120, get(w, S_BAD))
    return returned
'''

def source(mode):
    if mode not in ("snapshot","semantics"):raise ValueError(mode)
    entry={"snapshot":"plan_snapshot_gate","semantics":"plan_semantics"}[mode]
    constants=dict(CONSTANTS)
    helpers=[]
    for name,values,prefix,base in (
        ("schema_version",tuple(range(1,5)),"SCHEMA_V",1),
        ("register_code",REGISTERS,"REG_",1),
        ("scalar_type",VALUE_TYPES,"TYPE_",0),
        ("leaf_opcode",LEAF_OPS,"LEAF_",0)):
        lines=["def "+name+"(s:readbuf,w:mutbuf,name:u64)->u64:"]
        for i,value in enumerate(values):
            suffix=str(value) if name=="schema_version" else str(i+base)
            result=i+1 if name in ("schema_version","register_code") else 1
            lines.extend(("    if literal(s,w,name,L_"+prefix+suffix+") != 0:","        return "+str(result)))
        lines.append("    return 0");helpers.append("\n".join(lines))
    fields=("schema","core_sha256","block_order","function_order","scratch_registers",
            "instruction_selection","function_alignment","value_registers")
    helpers.append("def field_bit(s:readbuf,w:mutbuf,name:u64)->u64:\n"+
        "\n".join("    if literal(s,w,name,L_"+name.upper()+") != 0:\n        return "+str(1<<i)
                  for i,name in enumerate(fields))+"\n    return 0")
    body=ast.parse(BODY+"\n"+"\n".join(helpers)).body
    names={node.name:node for node in body}
    live={entry};pending=[entry]
    while pending:
        for call in ast.walk(names[pending.pop()]):
            if isinstance(call,ast.Call) and isinstance(call.func,ast.Name):
                name=call.func.id
                if name in names and name not in live:live.add(name);pending.append(name)
    selected=[node for node in body if node.name in live]
    # Keep contiguous error/register ranges, since the HIA renderer indexes them.
    literals=dict(LITERALS)
    data=bytearray(constants["DATA"])
    for index,(name,value) in enumerate(literals.items()):
        constants["L_"+name.upper()]=index
        raw=value.encode("ascii");offset=len(data);data.extend(raw)
        at=constants["INDEX"]+index*16
        data[at:at+8]=offset.to_bytes(8,"little")
        data[at+8:at+16]=len(raw).to_bytes(8,"little")
    assert constants["INDEX"]+len(literals)*16<=constants["DATA"]
    assert len(data)<constants["ERROR_AT"]
    writes=[(at,int.from_bytes(data[at:at+8].ljust(8,b"\0"),"little"))
        for at in range(constants["INDEX"],len(data),8) if any(data[at:at+8])]
    init=[];calls=[]
    for at in range(0,len(writes),16):
        name="literal_"+str(at//16);calls.append("    "+name+"(w)")
        init.append("def "+name+"(w:mutbuf)->u64:\n"+
            "\n".join("    put(w,%d,%d)"%row for row in writes[at:at+16])+"\n    return 0")
    init.append("def literal_table(w:mutbuf)->u64:\n"+"\n".join(calls)+"\n    return 0")
    selected.extend(ast.parse("\n".join(init)).body)
    for node in selected:
        if node.name in ("word","get"):
            arg="s" if node.name=="word" else "w"
            node.body=ast.parse("return "+" | ".join("(byte(%s,at+%d)<<%d)"%(arg,i,8*i) for i in range(8))).body
        elif node.name=="put":
            node.body=ast.parse("\n".join("store(w,at+%d,(value>>%d)&255)"%(i,8*i) for i in range(8))+"\nreturn 0").body
    selected.sort(key=lambda n:0 if n.name==entry else 1)
    return "\n".join(ast.unparse(ast.fix_missing_locations(node)) for node in selected)+"\n",constants,dict(
        status="NEW_UNEXECUTED",mode=mode,reference_sha256=REFERENCE_SHA,
        Core_reference_sha256=CORE_REFERENCE_SHA,private_actual_admitted_Core_required=True,
        immutable_Graph_and_actual_native_predecessor_required=True,
        header_is_authentication=False,whole_plan_admission=False,
        snapshot_then_actual_bounded_wire_then_semantics_required=True,
        full_bounded_wire_flags=2,full_bounded_wire_maximum=8388608,
        semantic_dictionary_iteration_matches_canonical_sorted_decode=True,
        exact_tuple_subclass_float_cycle_and_depth_snapshot_gate=True,
        no_stack_frame_or_bootstrap_language_quota_added=True,
        register_witness_JSON_not_exported=True,public_backend=False,installed=False,cold=False)
