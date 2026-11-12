"""Pure HIA complete _Function instruction-choice tape.
Only development authoring uses Python. Runtime input is the actual immutable
Core Graph and the native Function frame planner's actual readonly workspace.
Every opcode, argument, label, serial boundary and staging choice is made in HIA.
"""
import ast
REFERENCE_SHA="bf953a8b85d1ebc6b9d7a90fbbcaa4137e40ed214c2ede2af1a13cfc01b1c07c"
FRAME_OWNER_SHA="27a817d4cb0d3c8131efa4c8474779f55d74d618124a987a551cb26b3e18ddbd"
def magic(value):return int.from_bytes(value.encode("ascii"),"little")
CONSTANTS=dict(MAX=(1<<64)-1,BAD=0xfffffffd,GROW=0xfffffffe,
 BASE=12288,HEADER=12288,RECORDS=12544,INDEX=3072,DATA=6144,
 ARGUMENTS=768,LABELS=1024,GRAPH=magic("HIAGRF01"),PLAN=magic("HIAPFN01"),
 FRAME_EVENT=magic("HIAPFE01"),EVENT=magic("HIAFLE01"),TAPE=magic("HIAFLT01"))
FIELDS=("BAD","LEASE","REQUEST","FN_INDEX","NODES","EDGES","DATA","ROOT","CORE","FUNCTIONS",
 "FN","NAME","FRAME","SERIAL_START","SERIAL","USED","VALUE_AT","VALUE_N","BLOCK_AT","BLOCK_N",
 "VHASH_AT","VHASH_N","BHASH_AT","BHASH_N","ORDER_AT","SELECT","ENTRY","EDGE_SLOT","CALL_SLOT",
 "RESULT_SLOT","TEMPORARY","SAVED_AT","SAVED_N","TRAP_AT","TRAP_N","WRITE","COUNT","BYTES",
 "EXPECTED_COUNT","EXPECTED_BYTES","POOL","NEED","NAME_AT","NAME_N","PARAMS")
CONSTANTS.update({"S_"+name:128+8*i for i,name in enumerate(FIELDS)})
LITERALS={name.upper():name for name in (
 "functions","params","returns","blocks","op","args","attrs","out","name","type","id","term",
 "entry","value","mode","target","then","else","values","function","checked","unit","bool",
 "i8","u8","i16","u16","i32","u32","i64","u64","isize","usize","buffer","readbuf","mutbuf","chain",
 "rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi","r8","r9","r10","r11","r12","r13","r14","r15",
 "o","b","ae","e","ne","be","a","l","ge","le","g","and","or","xor","sub","shl","shr","sar",
 "division","select_yes","select_done","drop_done","alloc_empty","alloc_failed","alloc_done",
 "bulk_done","push_failed","push_done","pop_empty","pop_done","chain_drop_loop","chain_drop_node",
 "chain_drop_done","branch_else")}
LITERALS.update({name.upper().replace(".","_"):name for name in (
 "const","int.cast","int.neg.checked","select","bool.not","bool.and","bool.or",
 "bit.and","bit.or","bit.xor","bit.not","compare.eq","compare.ne","compare.lt","compare.le",
 "compare.gt","compare.ge","int.add.checked","int.sub.checked","int.mul.checked",
 "int.add.wrap","int.sub.wrap","int.mul.wrap","int.div.checked","int.rem.checked",
 "int.shl.checked","int.shr.checked","buffer.new","buffer.try_new","buffer.len","borrow.read",
 "borrow.mut","loan.end","owner.move","owner.drop","buffer.load","buffer.store","buffer.fill",
 "buffer.copy","buffer.move_within","buffer.swap","buffer.copy_range","buffer.fill_range","call",
 "chain.empty","chain.try_push","chain.pop","chain.is_empty","chain.head_read","chain.head_mut",
 "jump","branch","ret","trap")})
LITERALS.update(BLOCK_PREFIX="_block_",FUNCTION_PREFIX="__hia_native_fn_",COND="cond")
LITERALS.update({name.upper():name for name in ("calloc","malloc","free","memset","memcpy","memmove","abort")})

BODY=r'''
def lower_function(s:readbuf, r:readbuf, w:mutbuf) -> u32:
    if length(w) < BASE:
        return BAD
    fill_range(w, 0, BASE, 0)
    literal_table(w)
    if source_frame(s, r, w) != 0:
        lower_body(s, r, w)
        if get(w, S_BAD) == 0:
            count = get(w, S_COUNT)
            size = get(w, S_BYTES)
            if count > (MAX - RECORDS) >> 7:
                abi(w, 100)
            else:
                pool = RECORDS + count * 128
                if size > MAX - pool:
                    abi(w, 101)
                else:
                    put(w, S_POOL, pool)
                    put(w, S_NEED, pool + size)
                    if pool + size <= length(w):
                        put(w, S_EXPECTED_COUNT, count)
                        put(w, S_EXPECTED_BYTES, size)
                        put(w, S_WRITE, 1)
                        put(w, S_COUNT, 0)
                        put(w, S_BYTES, 0)
                        put(w, S_SERIAL, get(w, S_SERIAL_START))
                        fill_range(w, HEADER, pool + size - HEADER, 0)
                        lower_body(s, r, w)
                        if get(w, S_COUNT) != count or get(w, S_BYTES) != size:
                            abi(w, 102)
                        if get(w, S_BAD) == 0:
                            tape_header(s, r, w)
    if get(w, S_BAD) != 0:
        lower_event(w, 3)
        return BAD
    if get(w, S_NEED) > length(w):
        lower_event(w, 1)
        return GROW
    lower_event(w, 0)
    return 128

def lower_event(w:mutbuf, action:u64) -> u64:
    put(w, 0, EVENT)
    put(w, 8, 1)
    put(w, 16, action)
    put(w, 24, get(w, S_LEASE))
    put(w, 32, get(w, S_REQUEST))
    put(w, 40, get(w, S_FN_INDEX))
    put(w, 48, get(w, S_NEED))
    put(w, 56, choose(action == 0, HEADER, 0))
    put(w, 64, choose(action == 0, get(w, S_NEED) - HEADER, 0))
    put(w, 72, get(w, S_COUNT))
    put(w, 80, get(w, S_SERIAL))
    put(w, 88, get(w, S_FRAME))
    put(w, 96, 0)
    put(w, 104, 0)
    put(w, 112, 0)
    put(w, 120, get(w, S_BAD))
    return 0

def span(r:readbuf, w:mutbuf, at:u64, count:u64, stride:u64) -> u64:
    if at < 4608 or at > get(w, S_USED) or (at & 7) != 0 or stride == 0:
        return abi(w, 103)
    if count > divide(get(w, S_USED) - at, stride):
        return abi(w, 104)
    return 1

def source_frame(s:readbuf, r:readbuf, w:mutbuf) -> u64:
    if length(s) < 128 or length(r) < 4608:
        return abi(w, 105)
    if word(s, 0) != GRAPH or word(s, 8) == 0 or word(s, 56) != 0:
        return abi(w, 106)
    nodes = word(s, 16)
    if nodes == 0 or nodes > (MAX - 64) >> 6:
        return abi(w, 107)
    end = 64 + nodes * 64
    edges = word(s, 32)
    if edges > (MAX - end) >> 3:
        return abi(w, 108)
    end = end + edges * 8
    if end > length(s) or word(s, 40) != length(s) - end or word(s, 48) != length(s):
        return abi(w, 109)
    put(w, S_LEASE, word(s, 8))
    put(w, S_NODES, nodes)
    put(w, S_EDGES, edges)
    put(w, S_DATA, end)
    put(w, S_ROOT, word(s, 24))
    if word(r, 0) != FRAME_EVENT or word(r, 8) != 1 or word(r, 16) != 0:
        return abi(w, 110)
    if word(r, 24) != get(w, S_LEASE) or word(r, 32) == 0 or word(r, 48) != 0:
        return abi(w, 111)
    if word(r, 56) > length(r) or word(r, 56) < 4608 or word(r, 64) != 4096 or word(r, 72) != word(r, 56) - 4096:
        return abi(w, 112)
    if word(r, 96) != 0 or word(r, 104) != 0 or word(r, 112) != get(w, S_ROOT) or word(r, 120) != 0:
        return abi(w, 113)
    put(w, S_USED, word(r, 56))
    put(w, S_REQUEST, word(r, 32))
    put(w, S_FN_INDEX, word(r, 40))
    if word(r, 4096) != PLAN or word(r, 4104) != 1 or word(r, 4112) != get(w, S_LEASE):
        return abi(w, 114)
    if word(r, 4120) != get(w, S_REQUEST) or word(r, 4128) != get(w, S_FN_INDEX):
        return abi(w, 115)
    if word(r, 4440) != get(w, S_USED) - 4096 or word(r, 4448) != length(s) or word(r, 4456) != get(w, S_ROOT):
        return abi(w, 116)
    at = 4488
    while at < 4608:
        if word(r, at) != 0:
            return abi(w, 117)
        at = at + 8
    frame = word(r, 4152)
    if frame == 0 or frame > 65536 or (frame & 15) != 0 or frame != word(r, 80):
        return abi(w, 118)
    if word(r, 4168) == MAX or word(r, 4176) != word(r, 4168) + 1 or word(r, 4176) != word(r, 88):
        return abi(w, 119)
    if word(r, 4184) > 1 or word(r, 4392) > 5:
        return abi(w, 120)
    put(w, S_FRAME, frame)
    put(w, S_SERIAL_START, word(r, 4176))
    put(w, S_SERIAL, word(r, 4176))
    put(w, S_SELECT, word(r, 4184))
    plan_arrays(r, w)
    if get(w, S_BAD) != 0:
        return 0
    root = typed(s, w, get(w, S_ROOT), 5)
    if root == 0 or word(s, root + 32) != 2:
        return abi(w, 121)
    core = edge(s, w, root, 0)
    functions = typed(s, w, field(s, w, core, L_FUNCTIONS, 1), 5)
    if functions == 0 or get(w, S_FN_INDEX) >= word(s, functions + 32) or word(r, 4464) != word(s, functions + 32):
        return abi(w, 122)
    fn = edge(s, w, functions, get(w, S_FN_INDEX))
    name = field(s, w, fn, L_NAME, 1)
    if fn != word(r, 4136) or name != word(r, 4144) or typed(s, w, name, 4) == 0:
        return abi(w, 123)
    put(w, S_CORE, core)
    put(w, S_FUNCTIONS, functions)
    put(w, S_FN, fn)
    put(w, S_NAME, name)
    put(w, S_PARAMS, field(s, w, fn, L_PARAMS, 1))
    return choose(get(w, S_BAD) == 0, 1, 0)

def plan_arrays(r:readbuf, w:mutbuf) -> u64:
    i = 0
    while i < 6:
        stride = 64
        if i == 2 or i == 3:
            stride = 96
        elif i == 5:
            stride = 32
        span(r, w, word(r, 4240 + i * 8), word(r, 4192 + i * 8), stride)
        i = i + 1
    put(w, S_VALUE_AT, word(r, 4240))
    put(w, S_VALUE_N, word(r, 4192))
    put(w, S_BLOCK_AT, word(r, 4248))
    put(w, S_BLOCK_N, word(r, 4200))
    put(w, S_VHASH_AT, word(r, 4288))
    put(w, S_VHASH_N, word(r, 4296))
    put(w, S_BHASH_AT, word(r, 4304))
    put(w, S_BHASH_N, word(r, 4312))
    i = 0
    while i < 2:
        count = word(r, 4296 + i * 16)
        if count == 0 or (count & (count - 1)) != 0:
            return abi(w, 124)
        span(r, w, word(r, 4288 + i * 16), count, 8)
        i = i + 1
    put(w, S_ORDER_AT, word(r, 4320))
    put(w, S_ENTRY, word(r, 4328))
    span(r, w, get(w, S_ORDER_AT), get(w, S_BLOCK_N), 8)
    put(w, S_EDGE_SLOT, word(r, 4360))
    put(w, S_CALL_SLOT, word(r, 4368))
    put(w, S_RESULT_SLOT, word(r, 4376))
    put(w, S_TEMPORARY, word(r, 4384))
    put(w, S_SAVED_N, word(r, 4392))
    put(w, S_SAVED_AT, word(r, 4400))
    span(r, w, get(w, S_SAVED_AT), get(w, S_SAVED_N), 16)
    put(w, S_TRAP_AT, word(r, 4424))
    put(w, S_TRAP_N, word(r, 4432))
    if get(w, S_TRAP_AT) < 4608 or get(w, S_TRAP_AT) > get(w, S_USED) or get(w, S_TRAP_N) > get(w, S_USED) - get(w, S_TRAP_AT):
        return abi(w, 125)
    if get(w, S_TRAP_N) == 0 or get(w, S_TRAP_N) > 512:
        return abi(w, 126)
    return 0

def record(r:readbuf, w:mutbuf, at:u64, kind:u64) -> u64:
    base = get(w, S_VALUE_AT)
    count = get(w, S_VALUE_N)
    if kind != 0:
        base = get(w, S_BLOCK_AT)
        count = get(w, S_BLOCK_N)
    if at < base or (at - base) >> 6 >= count or ((at - base) & 63) != 0:
        return abi(w, 127)
    return at

def value_record(s:readbuf, r:readbuf, w:mutbuf, name:u64) -> u64:
    count = get(w, S_VHASH_N)
    index = hash_name(s, w, name) & (count - 1)
    visited = 0
    while visited < count and get(w, S_BAD) == 0:
        old = word(r, get(w, S_VHASH_AT) + index * 8)
        if old == 0 or record(r, w, old, 0) == 0:
            return abi(w, 128)
        if equal(s, w, name, word(r, old)) != 0:
            if word(r, old + 16) == 0 or word(r, old + 16) > 2 or word(r, old + 32) > 7:
                return abi(w, 129)
            offset = word(r, old + 24)
            if offset > MAX - 7 or offset < 0 - get(w, S_FRAME):
                return abi(w, 130)
            return old
        index = (index + 1) & (count - 1)
        visited = visited + 1
    return abi(w, 131)

def item(s:readbuf, w:mutbuf, identifier:u64, index:u64) -> u64:
    at = typed(s, w, identifier, 5)
    if at == 0:
        return 0
    return edge(s, w, at, index)

def items(s:readbuf, w:mutbuf, identifier:u64) -> u64:
    at = typed(s, w, identifier, 5)
    if at == 0:
        return 0
    return word(s, at + 32)

def output_name(s:readbuf, w:mutbuf, outputs:u64, index:u64) -> u64:
    return field(s, w, item(s, w, outputs, index), L_NAME, 1)

def typ(s:readbuf, r:readbuf, w:mutbuf, name:u64) -> u64:
    row = value_record(s, r, w, name)
    if row == 0:
        return 16
    return type_code(s, w, word(r, row + 8))

def signed_type(typ:u64) -> u64:
    return choose(typ == 2 or typ == 4 or typ == 6 or typ == 8 or typ == 10, 1, 0)

def type_bits(typ:u64) -> u64:
    if typ == 2 or typ == 3:
        return 8
    if typ == 4 or typ == 5:
        return 16
    if typ == 6 or typ == 7:
        return 32
    return 64

def arg_number(w:mutbuf, index:u64, value:u64, negative:u64) -> u64:
    put(w, ARGUMENTS + index * 24, negative)
    put(w, ARGUMENTS + index * 24 + 8, value)
    put(w, ARGUMENTS + index * 24 + 16, 0)
    return 0

def arg_signed(w:mutbuf, index:u64, value:u64) -> u64:
    if (value >> 63) != 0:
        return arg_number(w, index, 0 - value, 1)
    return arg_number(w, index, value, 0)

def arg_string(w:mutbuf, index:u64, origin:u64, at:u64, size:u64) -> u64:
    put(w, ARGUMENTS + index * 24, origin)
    put(w, ARGUMENTS + index * 24 + 8, at)
    put(w, ARGUMENTS + index * 24 + 16, size)
    return 0

def arg_literal(w:mutbuf, index:u64, literal_index:u64) -> u64:
    return arg_string(w, index, 2, get(w, INDEX + literal_index * 16), get(w, INDEX + literal_index * 16 + 8))

def copy_local(w:mutbuf, target:u64, source:u64, count:u64) -> u64:
    i = 0
    while i < count:
        store(w, target + i, byte(w, source + i))
        i = i + 1
    return 0

def pool(s:readbuf, r:readbuf, w:mutbuf, origin:u64, at:u64, count:u64) -> u64:
    end = get(w, S_BYTES)
    if count > MAX - end:
        return abi(w, 132)
    limit = length(w)
    if origin == 3:
        limit = length(s)
    elif origin == 4:
        limit = get(w, S_USED)
    elif origin != 2:
        return abi(w, 133)
    if at > limit or count > limit - at:
        return abi(w, 134)
    target = get(w, S_POOL) + end
    if get(w, S_WRITE) != 0:
        if end > get(w, S_EXPECTED_BYTES) or count > get(w, S_EXPECTED_BYTES) - end:
            return abi(w, 135)
        if origin == 2:
            copy_local(w, target, at, count)
        elif origin == 3:
            copy_bytes(w, s, target, at, count)
        else:
            copy_bytes(w, r, target, at, count)
    put(w, S_BYTES, end + count)
    return target

def emit(s:readbuf, r:readbuf, w:mutbuf, operation:u64, count:u64, effect:u64) -> u64:
    if get(w, S_BAD) != 0:
        return 0
    number = get(w, S_COUNT)
    if number == MAX or count > 3 or operation > 44 or effect > 3:
        return abi(w, 136)
    target = RECORDS
    if get(w, S_WRITE) != 0:
        if number >= get(w, S_EXPECTED_COUNT):
            return abi(w, 137)
        target = RECORDS + number * 128
        put(w, target, operation)
        put(w, target + 8, count)
        put(w, target + 16, get(w, S_SERIAL))
        put(w, target + 24, effect)
    i = 0
    while i < count and get(w, S_BAD) == 0:
        row = ARGUMENTS + i * 24
        kind = get(w, row)
        value = get(w, row + 8)
        size = get(w, row + 16)
        if kind > 1:
            value = pool(s, r, w, kind, value, size)
            kind = 2
        elif size != 0 or (kind == 1 and value == 0):
            return abi(w, 138)
        if get(w, S_WRITE) != 0:
            put(w, target + 32 + i * 24, kind)
            put(w, target + 40 + i * 24, value)
            put(w, target + 48 + i * 24, size)
        i = i + 1
    put(w, S_COUNT, number + 1)
    return 0

def code0(s:readbuf, r:readbuf, w:mutbuf, operation:u64, effect:u64) -> u64:
    return emit(s, r, w, operation, 0, effect)

def code1(s:readbuf, r:readbuf, w:mutbuf, operation:u64, first:u64) -> u64:
    arg_literal(w, 0, first)
    return emit(s, r, w, operation, 1, 0)

def code2(s:readbuf, r:readbuf, w:mutbuf, operation:u64, first:u64, second:u64) -> u64:
    arg_literal(w, 0, first)
    arg_literal(w, 1, second)
    return emit(s, r, w, operation, 2, 0)

def immediate(s:readbuf, r:readbuf, w:mutbuf, register:u64, value:u64) -> u64:
    arg_literal(w, 0, register)
    arg_number(w, 1, value, 0)
    return emit(s, r, w, 9, 2, 0)

def memory(s:readbuf, r:readbuf, w:mutbuf, operation:u64, first:u64, second:u64, displacement:u64) -> u64:
    arg_literal(w, 0, first)
    if operation == 11 or operation == 14:
        arg_signed(w, 1, displacement)
        arg_literal(w, 2, second)
    else:
        arg_literal(w, 1, second)
        arg_signed(w, 2, displacement)
    return emit(s, r, w, operation, 3, 0)

def alu_immediate(s:readbuf, r:readbuf, w:mutbuf, operation:u64, register:u64, value:u64) -> u64:
    arg_literal(w, 0, operation)
    arg_literal(w, 1, register)
    arg_signed(w, 2, value)
    return emit(s, r, w, 22, 3, 0)

def shift_immediate(s:readbuf, r:readbuf, w:mutbuf, operation:u64, register:u64, value:u64) -> u64:
    arg_literal(w, 0, operation)
    arg_literal(w, 1, register)
    arg_number(w, 2, value, 0)
    return emit(s, r, w, 24, 3, 0)

def normalize(s:readbuf, r:readbuf, w:mutbuf, register:u64, typ:u64) -> u64:
    if typ == 0:
        immediate(s, r, w, register, 0)
    elif typ == 1:
        alu_immediate(s, r, w, L_AND, register, 1)
    elif typ < 12 and type_bits(typ) < 64:
        shift_immediate(s, r, w, L_SHL, register, 64 - type_bits(typ))
        shift_immediate(s, r, w, choose(signed_type(typ) != 0, L_SAR, L_SHR), register, 64 - type_bits(typ))
    return 0

def load_value(s:readbuf, r:readbuf, w:mutbuf, name:u64, register:u64, word_index:u64) -> u64:
    row = value_record(s, r, w, name)
    if row == 0:
        return 0
    if word_index >= word(r, row + 16):
        return abi(w, 139)
    selected = word(r, row + 32)
    if selected != 0:
        if word_index != 0:
            return abi(w, 140)
        return code2(s, r, w, 8, register, saved_register(selected))
    return memory(s, r, w, 10, register, L_RBP, word(r, row + 24) + word_index * 8)

def store_value(s:readbuf, r:readbuf, w:mutbuf, name:u64, register:u64, word_index:u64) -> u64:
    row = value_record(s, r, w, name)
    if row == 0:
        return 0
    if word_index >= word(r, row + 16):
        return abi(w, 141)
    selected = word(r, row + 32)
    if selected != 0:
        if word_index != 0:
            return abi(w, 142)
        return code2(s, r, w, 8, saved_register(selected), register)
    return memory(s, r, w, 11, L_RBP, register, word(r, row + 24) + word_index * 8)

def value_immediate(s:readbuf, r:readbuf, w:mutbuf, name:u64, value:u64, word_index:u64) -> u64:
    immediate(s, r, w, L_RAX, value)
    return store_value(s, r, w, name, L_RAX, word_index)

def value_copy(s:readbuf, r:readbuf, w:mutbuf, source:u64, destination:u64) -> u64:
    row = value_record(s, r, w, source)
    if row == 0:
        return 0
    i = 0
    while i < word(r, row + 16) and get(w, S_BAD) == 0:
        load_value(s, r, w, source, L_RAX, i)
        store_value(s, r, w, destination, L_RAX, i)
        i = i + 1
    return 0

def trap_if(s:readbuf, r:readbuf, w:mutbuf, condition:u64) -> u64:
    arg_literal(w, 0, condition)
    arg_string(w, 1, 4, get(w, S_TRAP_AT), get(w, S_TRAP_N))
    return emit(s, r, w, 6, 2, 0)

def trap_jump(s:readbuf, r:readbuf, w:mutbuf) -> u64:
    arg_string(w, 0, 4, get(w, S_TRAP_AT), get(w, S_TRAP_N))
    return emit(s, r, w, 5, 1, 0)

def compare_immediate(s:readbuf, r:readbuf, w:mutbuf, register:u64, value:u64) -> u64:
    immediate(s, r, w, L_R11, value)
    return code2(s, r, w, 20, register, L_R11)

def range_check(s:readbuf, r:readbuf, w:mutbuf, register:u64, target:u64, source:u64) -> u64:
    before = signed_type(source)
    after = signed_type(target)
    bits = type_bits(target)
    old_bits = type_bits(source)
    if before != 0 and (after == 0 or bits < old_bits):
        value = 0
        if after != 0:
            value = 0 - (1 << (bits - 1))
        compare_immediate(s, r, w, register, value)
        trap_if(s, r, w, L_L)
    high = 0
    if before != 0:
        high = choose(bits < old_bits, 1, 0)
    elif after != 0:
        high = choose(bits <= old_bits, 1, 0)
    else:
        high = choose(bits < old_bits, 1, 0)
    if high != 0:
        value = MAX
        if after != 0:
            value = (1 << (bits - 1)) - 1
        elif bits < 64:
            value = (1 << bits) - 1
        compare_immediate(s, r, w, register, value)
        trap_if(s, r, w, choose(before != 0, L_G, L_A))
    return 0

def narrow(s:readbuf, r:readbuf, w:mutbuf, typ:u64, checked:u64) -> u64:
    if checked != 0 and type_bits(typ) < 64:
        range_check(s, r, w, L_RAX, typ, choose(signed_type(typ) != 0, 8, 9))
    return normalize(s, r, w, L_RAX, typ)

def make_label(w:mutbuf, suffix:u64, slot:u64) -> u64:
    if get(w, S_SERIAL) == MAX or slot >= 8:
        return abi(w, 143)
    put(w, S_SERIAL, get(w, S_SERIAL) + 1)
    start = LABELS + slot * 256
    store(w, start + 8, 102)
    store(w, start + 9, 110)
    end = decimal(w, start + 10, get(w, S_FN_INDEX))
    store(w, end, 95)
    end = end + 1
    at = get(w, INDEX + suffix * 16)
    size = get(w, INDEX + suffix * 16 + 8)
    if size > 256 - (end - start) - 22:
        return abi(w, 144)
    copy_local(w, end, at, size)
    end = end + size
    store(w, end, 95)
    end = decimal(w, end + 1, get(w, S_SERIAL))
    put(w, start, end - start - 8)
    return start

def label_command(s:readbuf, r:readbuf, w:mutbuf, operation:u64, condition:u64, slot:u64) -> u64:
    if slot >= 8:
        return abi(w, 145)
    start = LABELS + slot * 256
    count = choose(operation == 6, 2, 1)
    if operation == 6:
        arg_literal(w, 0, condition)
    arg_string(w, count - 1, 2, start + 8, get(w, start))
    return emit(s, r, w, operation, count, 0)

def block_command(s:readbuf, r:readbuf, w:mutbuf, operation:u64, name:u64) -> u64:
    row = typed(s, w, name, 4)
    if row == 0:
        return 0
    start = LABELS + 7 * 256
    store(w, start + 8, 102)
    store(w, start + 9, 110)
    end = decimal(w, start + 10, get(w, S_FN_INDEX))
    copy_local(w, end, get(w, INDEX + L_BLOCK_PREFIX * 16), 7)
    end = end + 7
    size = word(s, row + 16)
    if size > start + 256 - end:
        return abi(w, 146)
    copy_bytes(w, s, end, word(s, row + 8), size)
    put(w, start, end + size - start - 8)
    return label_command(s, r, w, operation, 0, 7)

def call_function(s:readbuf, r:readbuf, w:mutbuf, name:u64) -> u64:
    at = get(w, S_FUNCTIONS)
    index = 0
    found = MAX
    while index < word(s, at + 32) and get(w, S_BAD) == 0:
        fn = edge(s, w, at, index)
        if equal(s, w, field(s, w, fn, L_NAME, 1), name) != 0:
            found = index
        index = index + 1
    if found == MAX:
        return abi(w, 147)
    start = LABELS + 6 * 256
    copy_local(w, start + 8, get(w, INDEX + L_FUNCTION_PREFIX * 16), 16)
    end = decimal(w, start + 24, found)
    put(w, start, end - start - 8)
    return label_command(s, r, w, 7, 0, 6)


def constant(s:readbuf, w:mutbuf, identifier:u64) -> u64:
    at = node(s, w, identifier)
    if at == 0:
        return 0
    kind = word(s, at)
    if kind == 0:
        return 0
    if kind == 1:
        return word(s, at + 48)
    if kind != 2 or word(s, at + 16) > 8:
        return abi(w, 148)
    i = 0
    value = 0
    while i < word(s, at + 16):
        value = value | (byte(s, word(s, at + 8) + i) << (i * 8))
        i = i + 1
    if word(s, at + 48) != 0:
        value = 0 - value
    return value

def arithmetic(s:readbuf, r:readbuf, w:mutbuf, opcode:u64, args:u64, output:u64, typ:u64) -> u64:
    checked = choose(opcode == O_INT_ADD_CHECKED or opcode == O_INT_SUB_CHECKED or opcode == O_INT_MUL_CHECKED, 1, 0)
    load_value(s, r, w, item(s, w, args, 0), L_RAX, 0)
    load_value(s, r, w, item(s, w, args, 1), L_RCX, 0)
    if opcode == O_INT_MUL_CHECKED or opcode == O_INT_MUL_WRAP:
        if checked != 0 and signed_type(typ) == 0:
            code1(s, r, w, 31, L_RCX)
            code2(s, r, w, 21, L_RDX, L_RDX)
            trap_if(s, r, w, L_NE)
        else:
            code2(s, r, w, 30, L_RAX, L_RCX)
            if checked != 0:
                trap_if(s, r, w, L_O)
    else:
        selected = choose(opcode == O_INT_ADD_CHECKED or opcode == O_INT_ADD_WRAP, 15, 16)
        code2(s, r, w, selected, L_RAX, L_RCX)
        if checked != 0:
            trap_if(s, r, w, choose(signed_type(typ) != 0, L_O, L_B))
    narrow(s, r, w, typ, checked)
    return store_value(s, r, w, output, L_RAX, 0)

def division(s:readbuf, r:readbuf, w:mutbuf, opcode:u64, args:u64, output:u64, typ:u64) -> u64:
    load_value(s, r, w, item(s, w, args, 0), L_RAX, 0)
    load_value(s, r, w, item(s, w, args, 1), L_RCX, 0)
    code2(s, r, w, 21, L_RCX, L_RCX)
    trap_if(s, r, w, L_E)
    if signed_type(typ) != 0:
        make_label(w, L_DIVISION, 0)
        compare_immediate(s, r, w, L_RAX, 0 - (1 << (type_bits(typ) - 1)))
        label_command(s, r, w, 6, L_NE, 0)
        compare_immediate(s, r, w, L_RCX, MAX)
        trap_if(s, r, w, L_E)
        label_command(s, r, w, 4, 0, 0)
        code0(s, r, w, 37, 0)
        code1(s, r, w, 34, L_RCX)
    else:
        code2(s, r, w, 19, L_RDX, L_RDX)
        code1(s, r, w, 33, L_RCX)
    if opcode == O_INT_REM_CHECKED:
        code2(s, r, w, 8, L_RAX, L_RDX)
    return store_value(s, r, w, output, L_RAX, 0)

def shift_operation(s:readbuf, r:readbuf, w:mutbuf, opcode:u64, args:u64, output:u64, typ:u64) -> u64:
    load_value(s, r, w, item(s, w, args, 0), L_RAX, 0)
    load_value(s, r, w, item(s, w, args, 1), L_RCX, 0)
    compare_immediate(s, r, w, L_RCX, type_bits(typ))
    trap_if(s, r, w, L_AE)
    selected = choose(opcode == O_INT_SHL_CHECKED, L_SHL, choose(signed_type(typ) != 0, L_SAR, L_SHR))
    code2(s, r, w, 25, selected, L_RAX)
    narrow(s, r, w, typ, 0)
    return store_value(s, r, w, output, L_RAX, 0)

def bit_operation(s:readbuf, r:readbuf, w:mutbuf, opcode:u64, args:u64, output:u64, typ:u64) -> u64:
    load_value(s, r, w, item(s, w, args, 0), L_RAX, 0)
    if opcode == O_BIT_NOT:
        code1(s, r, w, 36, L_RAX)
    else:
        load_value(s, r, w, item(s, w, args, 1), L_RCX, 0)
        selected = choose(opcode == O_BIT_AND, 17, choose(opcode == O_BIT_OR, 18, 19))
        code2(s, r, w, selected, L_RAX, L_RCX)
    narrow(s, r, w, typ, 0)
    return store_value(s, r, w, output, L_RAX, 0)

def comparison(s:readbuf, r:readbuf, w:mutbuf, opcode:u64, args:u64, output:u64, typ:u64) -> u64:
    load_value(s, r, w, item(s, w, args, 0), L_RAX, 0)
    load_value(s, r, w, item(s, w, args, 1), L_RCX, 0)
    code2(s, r, w, 20, L_RAX, L_RCX)
    predicate = L_E
    if opcode == O_COMPARE_NE:
        predicate = L_NE
    elif opcode == O_COMPARE_LT:
        predicate = choose(signed_type(typ) != 0, L_L, L_B)
    elif opcode == O_COMPARE_LE:
        predicate = choose(signed_type(typ) != 0, L_LE, L_BE)
    elif opcode == O_COMPARE_GT:
        predicate = choose(signed_type(typ) != 0, L_G, L_A)
    elif opcode == O_COMPARE_GE:
        predicate = choose(signed_type(typ) != 0, L_GE, L_AE)
    code2(s, r, w, 38, predicate, L_RAX)
    return store_value(s, r, w, output, L_RAX, 0)

def select_operation(s:readbuf, r:readbuf, w:mutbuf, args:u64, output:u64) -> u64:
    if get(w, S_SELECT) != 0:
        load_value(s, r, w, item(s, w, args, 0), L_RAX, 0)
        code2(s, r, w, 21, L_RAX, L_RAX)
        load_value(s, r, w, item(s, w, args, 2), L_RAX, 0)
        load_value(s, r, w, item(s, w, args, 1), L_RCX, 0)
        arg_literal(w, 0, L_NE)
        arg_literal(w, 1, L_RAX)
        arg_literal(w, 2, L_RCX)
        emit(s, r, w, 39, 3, 0)
        store_value(s, r, w, output, L_RAX, 0)
    else:
        make_label(w, L_SELECT_YES, 0)
        make_label(w, L_SELECT_DONE, 1)
        load_value(s, r, w, item(s, w, args, 0), L_RAX, 0)
        code2(s, r, w, 21, L_RAX, L_RAX)
        label_command(s, r, w, 6, L_NE, 0)
        value_copy(s, r, w, item(s, w, args, 2), output)
        label_command(s, r, w, 5, 0, 1)
        label_command(s, r, w, 4, 0, 0)
        value_copy(s, r, w, item(s, w, args, 1), output)
        label_command(s, r, w, 4, 0, 1)
    return 0

def scalar_operation(s:readbuf, r:readbuf, w:mutbuf, opcode:u64, args:u64, outputs:u64, attrs:u64) -> u64:
    output = output_name(s, w, outputs, 0)
    t = 0
    if items(s, w, args) != 0:
        t = typ(s, r, w, item(s, w, args, 0))
    if opcode == O_CONST:
        value_immediate(s, r, w, output, constant(s, w, field(s, w, attrs, L_VALUE, 1)), 0)
    elif opcode == O_INT_ADD_CHECKED or opcode == O_INT_ADD_WRAP or opcode == O_INT_SUB_CHECKED or opcode == O_INT_SUB_WRAP or opcode == O_INT_MUL_CHECKED or opcode == O_INT_MUL_WRAP:
        arithmetic(s, r, w, opcode, args, output, t)
    elif opcode == O_INT_DIV_CHECKED or opcode == O_INT_REM_CHECKED:
        division(s, r, w, opcode, args, output, t)
    elif opcode == O_INT_SHL_CHECKED or opcode == O_INT_SHR_CHECKED:
        shift_operation(s, r, w, opcode, args, output, t)
    elif opcode == O_INT_NEG_CHECKED:
        load_value(s, r, w, item(s, w, args, 0), L_RAX, 0)
        if signed_type(t) != 0:
            code1(s, r, w, 35, L_RAX)
            trap_if(s, r, w, L_O)
            narrow(s, r, w, t, 1)
        else:
            code2(s, r, w, 21, L_RAX, L_RAX)
            trap_if(s, r, w, L_NE)
        store_value(s, r, w, output, L_RAX, 0)
    elif opcode == O_BIT_AND or opcode == O_BIT_OR or opcode == O_BIT_XOR or opcode == O_BIT_NOT:
        bit_operation(s, r, w, opcode, args, output, t)
    elif opcode == O_COMPARE_EQ or opcode == O_COMPARE_NE or opcode == O_COMPARE_LT or opcode == O_COMPARE_LE or opcode == O_COMPARE_GT or opcode == O_COMPARE_GE:
        comparison(s, r, w, opcode, args, output, t)
    elif opcode == O_BOOL_NOT or opcode == O_BOOL_AND or opcode == O_BOOL_OR:
        load_value(s, r, w, item(s, w, args, 0), L_RAX, 0)
        if opcode == O_BOOL_NOT:
            alu_immediate(s, r, w, L_XOR, L_RAX, 1)
        else:
            load_value(s, r, w, item(s, w, args, 1), L_RCX, 0)
            code2(s, r, w, choose(opcode == O_BOOL_AND, 17, 18), L_RAX, L_RCX)
        store_value(s, r, w, output, L_RAX, 0)
    elif opcode == O_INT_CAST:
        load_value(s, r, w, item(s, w, args, 0), L_RAX, 0)
        destination = typ(s, r, w, output)
        if literal(s, w, field(s, w, attrs, L_MODE, 1), L_CHECKED) != 0:
            range_check(s, r, w, L_RAX, destination, t)
        normalize(s, r, w, L_RAX, destination)
        store_value(s, r, w, output, L_RAX, 0)
    elif opcode == O_SELECT:
        select_operation(s, r, w, args, output)
    else:
        return abi(w, 149)
    return 0


def allocate_buffer(s:readbuf, r:readbuf, w:mutbuf, size:u64, outputs:u64, trapping:u64) -> u64:
    make_label(w, L_ALLOC_EMPTY, 0)
    make_label(w, L_ALLOC_FAILED, 1)
    make_label(w, L_ALLOC_DONE, 2)
    output = output_name(s, w, outputs, 0)
    load_value(s, r, w, size, L_RSI, 0)
    code2(s, r, w, 21, L_RSI, L_RSI)
    label_command(s, r, w, 6, L_E, 0)
    compare_immediate(s, r, w, L_RSI, MAX >> 1)
    label_command(s, r, w, 6, L_A, 1)
    immediate(s, r, w, L_RDI, 1)
    code1(s, r, w, 7, L_CALLOC)
    code2(s, r, w, 21, L_RAX, L_RAX)
    label_command(s, r, w, 6, L_E, 1)
    store_value(s, r, w, output, L_RAX, 0)
    load_value(s, r, w, size, L_RAX, 0)
    store_value(s, r, w, output, L_RAX, 1)
    if trapping == 0:
        value_immediate(s, r, w, output_name(s, w, outputs, 1), 1, 0)
    label_command(s, r, w, 5, 0, 2)
    label_command(s, r, w, 4, 0, 0)
    value_immediate(s, r, w, output, 0, 0)
    value_immediate(s, r, w, output, 0, 1)
    if trapping == 0:
        value_immediate(s, r, w, output_name(s, w, outputs, 1), 1, 0)
    label_command(s, r, w, 5, 0, 2)
    label_command(s, r, w, 4, 0, 1)
    if trapping != 0:
        trap_jump(s, r, w)
    else:
        value_immediate(s, r, w, output, 0, 0)
        value_immediate(s, r, w, output, 0, 1)
        value_immediate(s, r, w, output_name(s, w, outputs, 1), 0, 0)
    label_command(s, r, w, 4, 0, 2)
    return 0

def range_guard(s:readbuf, r:readbuf, w:mutbuf, buffer:u64, offset:u64, size:u64) -> u64:
    load_value(s, r, w, buffer, L_RAX, 1)
    load_value(s, r, w, offset, L_RCX, 0)
    code2(s, r, w, 20, L_RCX, L_RAX)
    trap_if(s, r, w, L_A)
    code2(s, r, w, 16, L_RAX, L_RCX)
    load_value(s, r, w, size, L_RCX, 0)
    code2(s, r, w, 20, L_RCX, L_RAX)
    return trap_if(s, r, w, L_A)

def bulk(s:readbuf, r:readbuf, w:mutbuf, opcode:u64, args:u64) -> u64:
    make_label(w, L_BULK_DONE, 0)
    if opcode == O_BUFFER_FILL:
        load_value(s, r, w, item(s, w, args, 0), L_RDX, 1)
    elif opcode == O_BUFFER_COPY:
        load_value(s, r, w, item(s, w, args, 2), L_RDX, 0)
        i = 0
        while i < 2:
            load_value(s, r, w, item(s, w, args, i), L_RAX, 1)
            code2(s, r, w, 20, L_RDX, L_RAX)
            trap_if(s, r, w, L_A)
            i = i + 1
    elif opcode == O_BUFFER_FILL_RANGE:
        range_guard(s, r, w, item(s, w, args, 0), item(s, w, args, 1), item(s, w, args, 2))
        load_value(s, r, w, item(s, w, args, 2), L_RDX, 0)
    elif opcode == O_BUFFER_MOVE_WITHIN:
        range_guard(s, r, w, item(s, w, args, 0), item(s, w, args, 1), item(s, w, args, 3))
        range_guard(s, r, w, item(s, w, args, 0), item(s, w, args, 2), item(s, w, args, 3))
        load_value(s, r, w, item(s, w, args, 3), L_RDX, 0)
    else:
        range_guard(s, r, w, item(s, w, args, 0), item(s, w, args, 2), item(s, w, args, 4))
        range_guard(s, r, w, item(s, w, args, 1), item(s, w, args, 3), item(s, w, args, 4))
        load_value(s, r, w, item(s, w, args, 4), L_RDX, 0)
    code2(s, r, w, 21, L_RDX, L_RDX)
    label_command(s, r, w, 6, L_E, 0)
    load_value(s, r, w, item(s, w, args, 0), L_RDI, 0)
    if opcode == O_BUFFER_FILL or opcode == O_BUFFER_FILL_RANGE:
        if opcode == O_BUFFER_FILL_RANGE:
            load_value(s, r, w, item(s, w, args, 1), L_RAX, 0)
            code2(s, r, w, 15, L_RDI, L_RAX)
        index = choose(opcode == O_BUFFER_FILL, 1, 3)
        load_value(s, r, w, item(s, w, args, index), L_RSI, 0)
        code1(s, r, w, 7, L_MEMSET)
    else:
        index = choose(opcode == O_BUFFER_MOVE_WITHIN, 0, 1)
        load_value(s, r, w, item(s, w, args, index), L_RSI, 0)
        if opcode == O_BUFFER_MOVE_WITHIN or opcode == O_BUFFER_COPY_RANGE:
            index = choose(opcode == O_BUFFER_MOVE_WITHIN, 1, 2)
            load_value(s, r, w, item(s, w, args, index), L_RAX, 0)
            code2(s, r, w, 15, L_RDI, L_RAX)
            load_value(s, r, w, item(s, w, args, index + 1), L_RAX, 0)
            code2(s, r, w, 15, L_RSI, L_RAX)
        code1(s, r, w, 7, choose(opcode == O_BUFFER_MOVE_WITHIN, L_MEMMOVE, L_MEMCPY))
    return label_command(s, r, w, 4, 0, 0)

def push_chain(s:readbuf, r:readbuf, w:mutbuf, args:u64, outputs:u64) -> u64:
    make_label(w, L_PUSH_FAILED, 0)
    make_label(w, L_PUSH_DONE, 1)
    immediate(s, r, w, L_RDI, 24)
    code1(s, r, w, 7, L_MALLOC)
    code2(s, r, w, 21, L_RAX, L_RAX)
    label_command(s, r, w, 6, L_E, 0)
    store_value(s, r, w, output_name(s, w, outputs, 0), L_RAX, 0)
    code2(s, r, w, 8, L_RDX, L_RAX)
    load_value(s, r, w, item(s, w, args, 1), L_RAX, 0)
    memory(s, r, w, 11, L_RDX, L_RAX, 0)
    load_value(s, r, w, item(s, w, args, 1), L_RAX, 1)
    memory(s, r, w, 11, L_RDX, L_RAX, 8)
    load_value(s, r, w, item(s, w, args, 0), L_RAX, 0)
    memory(s, r, w, 11, L_RDX, L_RAX, 16)
    value_immediate(s, r, w, output_name(s, w, outputs, 1), 0, 0)
    value_immediate(s, r, w, output_name(s, w, outputs, 1), 0, 1)
    value_immediate(s, r, w, output_name(s, w, outputs, 2), 1, 0)
    label_command(s, r, w, 5, 0, 1)
    label_command(s, r, w, 4, 0, 0)
    value_copy(s, r, w, item(s, w, args, 0), output_name(s, w, outputs, 0))
    value_copy(s, r, w, item(s, w, args, 1), output_name(s, w, outputs, 1))
    value_immediate(s, r, w, output_name(s, w, outputs, 2), 0, 0)
    return label_command(s, r, w, 4, 0, 1)

def pop_chain(s:readbuf, r:readbuf, w:mutbuf, arg:u64, outputs:u64) -> u64:
    make_label(w, L_POP_EMPTY, 0)
    make_label(w, L_POP_DONE, 1)
    load_value(s, r, w, arg, L_RDI, 0)
    code2(s, r, w, 21, L_RDI, L_RDI)
    label_command(s, r, w, 6, L_E, 0)
    word_index = 0
    while word_index < 2:
        memory(s, r, w, 10, L_RAX, L_RDI, word_index * 8)
        store_value(s, r, w, output_name(s, w, outputs, 1), L_RAX, word_index)
        word_index = word_index + 1
    memory(s, r, w, 10, L_RAX, L_RDI, 16)
    store_value(s, r, w, output_name(s, w, outputs, 0), L_RAX, 0)
    code1(s, r, w, 7, L_FREE)
    value_immediate(s, r, w, output_name(s, w, outputs, 2), 1, 0)
    label_command(s, r, w, 5, 0, 1)
    label_command(s, r, w, 4, 0, 0)
    value_immediate(s, r, w, output_name(s, w, outputs, 0), 0, 0)
    value_immediate(s, r, w, output_name(s, w, outputs, 1), 0, 0)
    value_immediate(s, r, w, output_name(s, w, outputs, 1), 0, 1)
    value_immediate(s, r, w, output_name(s, w, outputs, 2), 0, 0)
    return label_command(s, r, w, 4, 0, 1)

def drop_chain(s:readbuf, r:readbuf, w:mutbuf, arg:u64) -> u64:
    make_label(w, L_CHAIN_DROP_LOOP, 0)
    make_label(w, L_CHAIN_DROP_NODE, 1)
    make_label(w, L_CHAIN_DROP_DONE, 2)
    load_value(s, r, w, arg, L_RAX, 0)
    memory(s, r, w, 11, L_RBP, L_RAX, get(w, S_TEMPORARY))
    label_command(s, r, w, 4, 0, 0)
    memory(s, r, w, 10, L_RDX, L_RBP, get(w, S_TEMPORARY))
    code2(s, r, w, 21, L_RDX, L_RDX)
    label_command(s, r, w, 6, L_E, 2)
    memory(s, r, w, 10, L_RAX, L_RDX, 16)
    memory(s, r, w, 11, L_RBP, L_RAX, get(w, S_TEMPORARY) + 8)
    memory(s, r, w, 10, L_RDI, L_RDX, 0)
    code2(s, r, w, 21, L_RDI, L_RDI)
    label_command(s, r, w, 6, L_E, 1)
    code1(s, r, w, 7, L_FREE)
    label_command(s, r, w, 4, 0, 1)
    memory(s, r, w, 10, L_RDI, L_RBP, get(w, S_TEMPORARY))
    code1(s, r, w, 7, L_FREE)
    memory(s, r, w, 10, L_RAX, L_RBP, get(w, S_TEMPORARY) + 8)
    memory(s, r, w, 11, L_RBP, L_RAX, get(w, S_TEMPORARY))
    label_command(s, r, w, 5, 0, 0)
    return label_command(s, r, w, 4, 0, 2)

def byte_operation(s:readbuf, r:readbuf, w:mutbuf, opcode:u64, args:u64, outputs:u64) -> u64:
    load_value(s, r, w, item(s, w, args, 0), L_RDX, 1)
    load_value(s, r, w, item(s, w, args, 1), L_RCX, 0)
    code2(s, r, w, 20, L_RCX, L_RDX)
    trap_if(s, r, w, L_AE)
    if opcode == O_BUFFER_SWAP:
        load_value(s, r, w, item(s, w, args, 2), L_R8, 0)
        code2(s, r, w, 20, L_R8, L_RDX)
        trap_if(s, r, w, L_AE)
        load_value(s, r, w, item(s, w, args, 0), L_RDI, 0)
        code2(s, r, w, 8, L_RSI, L_RDI)
        code2(s, r, w, 15, L_RDI, L_RCX)
        code2(s, r, w, 15, L_RSI, L_R8)
        memory(s, r, w, 13, L_RAX, L_RDI, 0)
        memory(s, r, w, 13, L_RCX, L_RSI, 0)
        memory(s, r, w, 14, L_RDI, L_RCX, 0)
        memory(s, r, w, 14, L_RSI, L_RAX, 0)
    else:
        load_value(s, r, w, item(s, w, args, 0), L_RAX, 0)
        code2(s, r, w, 15, L_RAX, L_RCX)
        if opcode == O_BUFFER_LOAD:
            memory(s, r, w, 13, L_RAX, L_RAX, 0)
            store_value(s, r, w, output_name(s, w, outputs, 0), L_RAX, 0)
        else:
            load_value(s, r, w, item(s, w, args, 2), L_RCX, 0)
            memory(s, r, w, 14, L_RAX, L_RCX, 0)
    return 0

def resource_operation(s:readbuf, r:readbuf, w:mutbuf, opcode:u64, args:u64, outputs:u64) -> u64:
    if opcode == O_LOAN_END:
        return 0
    if opcode == O_CHAIN_EMPTY:
        return value_immediate(s, r, w, output_name(s, w, outputs, 0), 0, 0)
    first = item(s, w, args, 0)
    if opcode == O_OWNER_MOVE or opcode == O_BORROW_READ or opcode == O_BORROW_MUT:
        value_copy(s, r, w, first, output_name(s, w, outputs, 0))
    elif opcode == O_BUFFER_NEW or opcode == O_BUFFER_TRY_NEW:
        allocate_buffer(s, r, w, first, outputs, choose(opcode == O_BUFFER_NEW, 1, 0))
    elif opcode == O_BUFFER_LEN:
        load_value(s, r, w, first, L_RAX, 1)
        store_value(s, r, w, output_name(s, w, outputs, 0), L_RAX, 0)
    elif opcode == O_OWNER_DROP:
        if typ(s, r, w, first) == 15:
            drop_chain(s, r, w, first)
        else:
            make_label(w, L_DROP_DONE, 0)
            load_value(s, r, w, first, L_RDI, 0)
            code2(s, r, w, 21, L_RDI, L_RDI)
            label_command(s, r, w, 6, L_E, 0)
            code1(s, r, w, 7, L_FREE)
            label_command(s, r, w, 4, 0, 0)
    elif opcode == O_BUFFER_LOAD or opcode == O_BUFFER_STORE or opcode == O_BUFFER_SWAP:
        byte_operation(s, r, w, opcode, args, outputs)
    elif opcode == O_BUFFER_FILL or opcode == O_BUFFER_COPY or opcode == O_BUFFER_MOVE_WITHIN or opcode == O_BUFFER_COPY_RANGE or opcode == O_BUFFER_FILL_RANGE:
        bulk(s, r, w, opcode, args)
    elif opcode == O_CHAIN_IS_EMPTY:
        load_value(s, r, w, first, L_RAX, 0)
        code2(s, r, w, 21, L_RAX, L_RAX)
        code2(s, r, w, 38, L_E, L_RAX)
        store_value(s, r, w, output_name(s, w, outputs, 0), L_RAX, 0)
    elif opcode == O_CHAIN_HEAD_READ or opcode == O_CHAIN_HEAD_MUT:
        load_value(s, r, w, first, L_RDX, 0)
        code2(s, r, w, 21, L_RDX, L_RDX)
        trap_if(s, r, w, L_E)
        word_index = 0
        while word_index < 2:
            memory(s, r, w, 10, L_RAX, L_RDX, word_index * 8)
            store_value(s, r, w, output_name(s, w, outputs, 0), L_RAX, word_index)
            word_index = word_index + 1
    elif opcode == O_CHAIN_TRY_PUSH:
        push_chain(s, r, w, args, outputs)
    elif opcode == O_CHAIN_POP:
        pop_chain(s, r, w, first, outputs)
    else:
        return abi(w, 150)
    return 0


def block_record(s:readbuf, r:readbuf, w:mutbuf, name:u64) -> u64:
    count = get(w, S_BHASH_N)
    index = hash_name(s, w, name) & (count - 1)
    visited = 0
    while visited < count and get(w, S_BAD) == 0:
        old = word(r, get(w, S_BHASH_AT) + index * 8)
        if old == 0 or record(r, w, old, 1) == 0:
            return abi(w, 151)
        if equal(s, w, name, word(r, old + 8)) != 0:
            return old
        index = (index + 1) & (count - 1)
        visited = visited + 1
    return abi(w, 152)

def prologue(s:readbuf, r:readbuf, w:mutbuf) -> u64:
    code1(s, r, w, 40, L_RBP)
    code2(s, r, w, 8, L_RBP, L_RSP)
    remaining = get(w, S_FRAME)
    while remaining != 0 and get(w, S_BAD) == 0:
        amount = choose(remaining < 4096, remaining, 4096)
        alu_immediate(s, r, w, L_SUB, L_RSP, amount)
        memory(s, r, w, 10, L_R11, L_RSP, 0)
        remaining = remaining - amount
    i = 0
    while i < get(w, S_SAVED_N) and get(w, S_BAD) == 0:
        at = get(w, S_SAVED_AT) + i * 16
        selected = word(r, at)
        if selected == 0 or selected > 5:
            return abi(w, 153)
        memory(s, r, w, 11, L_RBP, saved_register(selected), word(r, at + 8))
        i = i + 1
    memory(s, r, w, 11, L_RBP, L_RSI, 0 - 8)
    params = get(w, S_PARAMS)
    at = typed(s, w, params, 5)
    if at == 0:
        return 0
    i = 0
    n = 0
    while i < word(s, at + 32) and get(w, S_BAD) == 0:
        value = edge(s, w, at, i)
        name = field(s, w, value, L_NAME, 1)
        t = type_code(s, w, field(s, w, value, L_TYPE, 1))
        width = choose(t >= 12 and t <= 14, 2, 1)
        j = 0
        while j < width and get(w, S_BAD) == 0:
            memory(s, r, w, 10, L_RAX, L_RDI, n * 8)
            store_value(s, r, w, name, L_RAX, j)
            n = n + 1
            j = j + 1
        i = i + 1
    entry = get(w, S_ENTRY)
    if record(r, w, entry, 1) == 0:
        return 0
    return block_command(s, r, w, 5, word(r, entry + 8))

def call_operation(s:readbuf, r:readbuf, w:mutbuf, args:u64, outputs:u64, attrs:u64) -> u64:
    count = items(s, w, args)
    i = 0
    n = 0
    while i < count and get(w, S_BAD) == 0:
        name = item(s, w, args, i)
        row = value_record(s, r, w, name)
        if row == 0:
            return 0
        j = 0
        while j < word(r, row + 16) and get(w, S_BAD) == 0:
            load_value(s, r, w, name, L_RAX, j)
            memory(s, r, w, 11, L_RBP, L_RAX, get(w, S_CALL_SLOT) + n * 8)
            n = n + 1
            j = j + 1
        i = i + 1
    memory(s, r, w, 12, L_RDI, L_RBP, get(w, S_CALL_SLOT))
    memory(s, r, w, 12, L_RSI, L_RBP, get(w, S_RESULT_SLOT))
    call_function(s, r, w, field(s, w, attrs, L_FUNCTION, 1))
    count = items(s, w, outputs)
    i = 0
    n = 0
    while i < count and get(w, S_BAD) == 0:
        name = output_name(s, w, outputs, i)
        row = value_record(s, r, w, name)
        if row == 0:
            return 0
        j = 0
        while j < word(r, row + 16) and get(w, S_BAD) == 0:
            memory(s, r, w, 10, L_RAX, L_RBP, get(w, S_RESULT_SLOT) + n * 8)
            store_value(s, r, w, name, L_RAX, j)
            n = n + 1
            j = j + 1
        i = i + 1
    return 0

def operation(s:readbuf, r:readbuf, w:mutbuf, ins:u64) -> u64:
    opcode = operation_code(s, w, field(s, w, ins, L_OP, 1))
    args = field(s, w, ins, L_ARGS, 1)
    outputs = field(s, w, ins, L_OUT, 1)
    attrs = field(s, w, ins, L_ATTRS, 1)
    if get(w, S_BAD) != 0:
        return 0
    if opcode <= SCALAR_COUNT:
        return scalar_operation(s, r, w, opcode, args, outputs, attrs)
    if opcode == O_CALL:
        return call_operation(s, r, w, args, outputs, attrs)
    return resource_operation(s, r, w, opcode, args, outputs)

def edge_transfer(s:readbuf, r:readbuf, w:mutbuf, target:u64, args:u64) -> u64:
    count = items(s, w, args)
    i = 0
    n = 0
    while i < count and get(w, S_BAD) == 0:
        name = item(s, w, args, i)
        row = value_record(s, r, w, name)
        if row == 0:
            return 0
        j = 0
        while j < word(r, row + 16) and get(w, S_BAD) == 0:
            load_value(s, r, w, name, L_RAX, j)
            memory(s, r, w, 11, L_RBP, L_RAX, get(w, S_EDGE_SLOT) + n * 8)
            n = n + 1
            j = j + 1
        i = i + 1
    block = block_record(s, r, w, target)
    if block == 0:
        return 0
    params = word(r, block + 16)
    count = items(s, w, params)
    i = 0
    n = 0
    while i < count and get(w, S_BAD) == 0:
        value = item(s, w, params, i)
        name = field(s, w, value, L_NAME, 1)
        t = type_code(s, w, field(s, w, value, L_TYPE, 1))
        width = choose(t >= 12 and t <= 14, 2, 1)
        j = 0
        while j < width and get(w, S_BAD) == 0:
            memory(s, r, w, 10, L_RAX, L_RBP, get(w, S_EDGE_SLOT) + n * 8)
            store_value(s, r, w, name, L_RAX, j)
            n = n + 1
            j = j + 1
        i = i + 1
    return block_command(s, r, w, 5, target)

def return_values(s:readbuf, r:readbuf, w:mutbuf, values:u64) -> u64:
    memory(s, r, w, 10, L_R10, L_RBP, 0 - 8)
    count = items(s, w, values)
    i = 0
    n = 0
    while i < count and get(w, S_BAD) == 0:
        name = item(s, w, values, i)
        row = value_record(s, r, w, name)
        if row == 0:
            return 0
        j = 0
        while j < word(r, row + 16) and get(w, S_BAD) == 0:
            load_value(s, r, w, name, L_RAX, j)
            memory(s, r, w, 11, L_R10, L_RAX, n * 8)
            n = n + 1
            j = j + 1
        i = i + 1
    i = 0
    while i < get(w, S_SAVED_N) and get(w, S_BAD) == 0:
        at = get(w, S_SAVED_AT) + i * 16
        selected = word(r, at)
        if selected == 0 or selected > 5:
            return abi(w, 154)
        memory(s, r, w, 10, saved_register(selected), L_RBP, word(r, at + 8))
        i = i + 1
    code0(s, r, w, 43, 0)
    return code0(s, r, w, 42, 0)

def terminator(s:readbuf, r:readbuf, w:mutbuf, term:u64) -> u64:
    opcode = field(s, w, term, L_OP, 1)
    if literal(s, w, opcode, L_JUMP) != 0:
        edge_transfer(s, r, w, field(s, w, term, L_TARGET, 1), field(s, w, term, L_ARGS, 1))
    elif literal(s, w, opcode, L_BRANCH) != 0:
        make_label(w, L_BRANCH_ELSE, 3)
        condition = field(s, w, term, L_COND, 1)
        load_value(s, r, w, condition, L_RAX, 0)
        code2(s, r, w, 21, L_RAX, L_RAX)
        label_command(s, r, w, 6, L_E, 3)
        side = field(s, w, term, L_THEN, 1)
        edge_transfer(s, r, w, field(s, w, side, L_TARGET, 1), field(s, w, side, L_ARGS, 1))
        label_command(s, r, w, 4, 0, 3)
        side = field(s, w, term, L_ELSE, 1)
        edge_transfer(s, r, w, field(s, w, side, L_TARGET, 1), field(s, w, side, L_ARGS, 1))
    elif literal(s, w, opcode, L_TRAP) != 0:
        trap_jump(s, r, w)
    elif literal(s, w, opcode, L_RET) != 0:
        return_values(s, r, w, field(s, w, term, L_VALUES, 1))
    else:
        return abi(w, 155)
    return 0

def lower_body(s:readbuf, r:readbuf, w:mutbuf) -> u64:
    name = typed(s, w, get(w, S_NAME), 4)
    if name == 0:
        return 0
    put(w, S_NAME_N, word(s, name + 16))
    put(w, S_NAME_AT, pool(s, r, w, 3, word(s, name + 8), word(s, name + 16)))
    code0(s, r, w, 2, 1)
    prologue(s, r, w)
    index = 0
    while index < get(w, S_BLOCK_N) and get(w, S_BAD) == 0:
        block = word(r, get(w, S_ORDER_AT) + index * 8)
        if record(r, w, block, 1) == 0:
            return 0
        block_command(s, r, w, 4, word(r, block + 8))
        ops = typed(s, w, word(r, block + 24), 5)
        if ops == 0:
            return 0
        i = 0
        while i < word(s, ops + 32) and get(w, S_BAD) == 0:
            operation(s, r, w, edge(s, w, ops, i))
            i = i + 1
        terminator(s, r, w, word(r, block + 32))
        code0(s, r, w, 2, 2)
        index = index + 1
    arg_string(w, 0, 4, get(w, S_TRAP_AT), get(w, S_TRAP_N))
    emit(s, r, w, 4, 1, 0)
    code1(s, r, w, 7, L_ABORT)
    code0(s, r, w, 44, 0)
    code0(s, r, w, 2, 3)
    return 0

def tape_header(s:readbuf, r:readbuf, w:mutbuf) -> u64:
    put(w, HEADER, TAPE)
    put(w, HEADER + 8, 1)
    put(w, HEADER + 16, get(w, S_LEASE))
    put(w, HEADER + 24, get(w, S_REQUEST))
    put(w, HEADER + 32, get(w, S_FN_INDEX))
    put(w, HEADER + 40, get(w, S_COUNT))
    put(w, HEADER + 48, RECORDS)
    put(w, HEADER + 56, get(w, S_POOL))
    put(w, HEADER + 64, get(w, S_BYTES))
    put(w, HEADER + 72, get(w, S_NEED))
    put(w, HEADER + 80, get(w, S_SERIAL_START))
    put(w, HEADER + 88, get(w, S_SERIAL))
    put(w, HEADER + 96, get(w, S_NAME_AT))
    put(w, HEADER + 104, get(w, S_NAME_N))
    put(w, HEADER + 112, get(w, S_FRAME))
    put(w, HEADER + 120, length(s))
    put(w, HEADER + 128, get(w, S_ROOT))
    put(w, HEADER + 136, get(w, S_USED))
    return 0
'''

SCALAR_OPS=("const","int.cast","int.neg.checked","select","bool.not","bool.and","bool.or",
 "bit.and","bit.or","bit.xor","bit.not","compare.eq","compare.ne","compare.lt","compare.le",
 "compare.gt","compare.ge","int.add.checked","int.sub.checked","int.mul.checked",
 "int.add.wrap","int.sub.wrap","int.mul.wrap","int.div.checked","int.rem.checked",
 "int.shl.checked","int.shr.checked")
RESOURCE_OPS=("buffer.new","buffer.try_new","buffer.len","borrow.read","borrow.mut","loan.end",
 "owner.move","owner.drop","buffer.load","buffer.store","buffer.fill","buffer.copy","buffer.move_within",
 "buffer.swap","buffer.copy_range","buffer.fill_range","chain.empty","chain.try_push","chain.pop",
 "chain.is_empty","chain.head_read","chain.head_mut")
TYPES=("unit","bool","i8","u8","i16","u16","i32","u32","i64","u64","isize","usize","buffer","readbuf","mutbuf","chain")
SHARED=("abi","word","get","put","node","typed","edge","literal","equal","field","hash_name","divide","decimal")
def source(frame_owner):
    constants=dict(CONSTANTS);constants["SCALAR_COUNT"]=len(SCALAR_OPS)
    operations=SCALAR_OPS+RESOURCE_OPS+("call",)
    assert len(operations)==len(set(operations))
    for i,name in enumerate(operations,1):constants["O_"+name.upper().replace(".","_")]=i
    raw=bytearray(constants["DATA"])
    assert constants["INDEX"]+len(LITERALS)*16<=constants["DATA"]
    for index,(name,value) in enumerate(LITERALS.items()):
        constants["L_"+name]=index
        data=value.encode("ascii");begin=len(raw);raw.extend(data)
        at=constants["INDEX"]+index*16
        raw[at:at+8]=begin.to_bytes(8,"little")
        raw[at+8:at+16]=len(data).to_bytes(8,"little")
    assert len(raw)<=constants["BASE"]
    writes=[(at,int.from_bytes(raw[at:at+8].ljust(8,b"\0"),"little"))
            for at in range(constants["INDEX"],len(raw),8) if any(raw[at:at+8])]
    helpers=[];calls=[]
    for start in range(0,len(writes),64):
        name="literal_"+str(start//64);calls.append("    "+name+"(w)")
        helpers.append("def "+name+"(w:mutbuf) -> u64:\n"+
            "\n".join("    put(w, %d, %d)"%pair for pair in writes[start:start+64])+"\n    return 0")
    helpers.append("def literal_table(w:mutbuf) -> u64:\n"+"\n".join(calls)+"\n    return 0")
    types=["def type_code(s:readbuf,w:mutbuf,name:u64)->u64:"]
    for i,name in enumerate(TYPES):
        types+=["    if literal(s,w,name,L_"+name.upper()+") != 0:","        return "+str(i)]
    types+=["    abi(w,156)","    return 16"];helpers.append("\n".join(types))
    regs=["def saved_register(index:u64)->u64:"]
    for i,name in enumerate(("rbx","r12","r13","r14","r15","r8","r9"),1):
        regs+=["    if index == "+str(i)+":","        return L_"+name.upper()]
    regs+=["    return L_RAX"];helpers.append("\n".join(regs))
    opcodes=["def operation_code(s:readbuf,w:mutbuf,name:u64)->u64:"]
    for i,name in enumerate(operations,1):
        opcodes+=["    if literal(s,w,name,L_"+name.upper().replace(".","_")+") != 0:",
                  "        return "+str(i)]
    opcodes+=["    abi(w,157)","    return 0"];helpers.append("\n".join(opcodes))
    original={n.name:n for n in ast.parse(frame_owner.BODY).body}
    assert all(name in original for name in SHARED)
    shared=[original[name] for name in SHARED]
    nodes=ast.parse(BODY+"\n"+"\n".join(helpers)).body+shared
    names={n.name:n for n in nodes};assert len(names)==len(nodes)
    live={"lower_function"};pending=["lower_function"]
    while pending:
        for call in ast.walk(names[pending.pop()]):
            if isinstance(call,ast.Call) and isinstance(call.func,ast.Name):
                name=call.func.id
                if name in names and name not in live:
                    live.add(name);pending.append(name)
    nodes=[n for n in nodes if n.name in live]
    for node in nodes:
        if node.name in ("word","get"):
            arg="s" if node.name=="word" else "w"
            node.body=ast.parse("return "+" | ".join("(byte(%s,at+%d)<<%d)"%(arg,i,8*i) for i in range(8))).body
        elif node.name=="put":
            node.body=ast.parse("\n".join("store(w,at+%d,(value>>%d)&255)"%(i,8*i) for i in range(8))+"\nreturn 0").body
    return "\n".join(ast.unparse(ast.fix_missing_locations(n)) for n in nodes)+"\n",constants,dict(
        status="NEW_AUTHORING_UNEXECUTED",scope="COMPLETE_PRIVATE_FUNCTION_LOWERING_TAPE",
        reference_sha256=REFERENCE_SHA,frame_owner_sha256=FRAME_OWNER_SHA,
        exact_original_operations=list(operations),complete_Function_render_choice=True,
        private_admitted_Core_and_checked_plan_required=True,profile_gate_upstream_required=True,
        original_code_method_order=True,per_command_serial_commit_records=True,
        actual_Code_ack_required=True,block_budget_requires_actual_Code_offset=True,
        no_host_instruction_selection_or_machine_bytes=True,header_is_authentication=False,
        whole_Emitter=False,foreign_entry_wrappers=False,whole_backend=False,installed=False,cold=False)
