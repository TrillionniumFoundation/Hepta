"""Native Emitter preparation over actual Core, checked plan and raw byte exports.
This author constructs HIA source only. No production function order, manifest
normalization, instruction choice, Code packet or ELF byte is supplied by host.
"""
import ast
def magic(s):return int.from_bytes(s.encode("ascii"),"little")
FRAME_SHA="27a817d4cb0d3c8131efa4c8474779f55d74d618124a987a551cb26b3e18ddbd"
ELF_SHA="84bbd81168ca645807ce0095755bb6e74efb1ffd9419cec3473a439e34dca985"
REFERENCE_SHA="bf953a8b85d1ebc6b9d7a90fbbcaa4137e40ed214c2ede2af1a13cfc01b1c07c"
BYTE_SHA="0bb40a17f76c27146a48a6d3d229228c9a89bfd96d4b9d65b3b9c70215a3edd6"
TYPES=("i8","u8","i16","u16","i32","u32","i64","u64","isize","usize","bool","unit","buffer","readbuf","mutbuf","chain")
OPCODES=("const","int.cast","int.neg.checked","select","bool.not","bool.and","bool.or",
 "bit.and","bit.or","bit.xor","bit.not","compare.eq","compare.ne","compare.lt","compare.le","compare.gt","compare.ge",
 "int.add.checked","int.sub.checked","int.mul.checked","int.add.wrap","int.sub.wrap","int.mul.wrap",
 "int.div.checked","int.rem.checked","int.shl.checked","int.shr.checked",
 "buffer.new","buffer.try_new","buffer.len","borrow.read","borrow.mut","loan.end","owner.move","owner.drop",
 "buffer.load","buffer.store","buffer.fill","buffer.copy","buffer.move_within","buffer.swap","buffer.copy_range",
 "buffer.fill_range","call","chain.empty","chain.try_push","chain.pop","chain.is_empty","chain.head_read","chain.head_mut")
RESERVED=("abort","calloc","malloc","free","memset","memcpy","memmove","_init","_fini",
 "__gmon_start__","__cxa_finalize","__dso_handle","_ITM_registerTMCloneTable","_ITM_deregisterTMCloneTable")
ERRORS=(
 "E_HIA_BYTE_ABI: borrowed-byte exports require a bounded immutable tuple",
 "E_HIA_BYTE_ABI: borrowed-byte profile cannot extend a nominal/scalar export contract",
 "E_HIA_BYTE_ABI: invalid or duplicate borrowed-byte export",
 "E_HIA_BYTE_ABI: borrowed-byte export conflicts with the closed native ABI",
 "E_HIA_BYTE_ABI: borrowed-byte export names a missing function",
 "E_HIA_BYTE_ABI: borrowed-byte export requires loans, scalars and one u32 result",
 "E_HIA_PROGRAM_PROFILE: Core schema lacks a reviewed direct lowering",
 "E_HIA_PROGRAM_PROFILE: terminator lacks a reviewed direct lowering",
 "E_HIA_PROGRAM_PROFILE: opcode lacks a reviewed direct lowering",
 "E_HIA_PROGRAM_PROFILE: type lacks a reviewed direct lowering")
LITERALS={"functions":"functions","name":"name","params":"params","returns":"returns","blocks":"blocks",
 "term":"term","op":"op","ops":"ops","out":"out","type":"type","exports":"exports","schema":"schema",
 "function_order":"function_order","function_alignment":"function_alignment",
 "scratch_registers":"scratch_registers","instruction_selection":"instruction_selection",
 "move_immediate":"move_immediate","alu_immediate":"alu_immediate",
 "r10":"r10","r11":"r11","movabs":"movabs","movcompact":"mov32_if_exact",
 "imm32":"imm32","immcompact":"imm8_if_exact","layout_v1":"hepta.hia.agent.block-layout.v1",
 "ret":"ret","jump":"jump","branch":"branch","trap":"trap",
 **{"type_"+x:x for x in TYPES},**{"opcode_"+str(i):v for i,v in enumerate(OPCODES)},
 **{"reserved_"+str(i):v for i,v in enumerate(RESERVED)},
 **{"schema_"+str(i):"hepta.hia.program.v"+str(i) for i in range(1,9)},
 **{"error"+str(i+1):v for i,v in enumerate(ERRORS)}}
BODY=r'''
def emitter_prepare(s:readbuf, r:readbuf, w:mutbuf) -> u32:
    if length(w) < MIN_WORK:
        return BAD
    fill_range(w, 0, MIN_WORK, 0)
    literal_table(w)
    if input_frame(s, r, w) != 0:
        if get(w, I_MODE) == 0:
            normalize_foreign(s, w)
        elif get(w, I_MODE) == 1:
            if code_options(s, w) != 0:
                init_packet(w)
        else:
            if profile(s, w) != 0:
                inventory(s, w)
    if get(w, S_BAD) != 0:
        prepared_event(w, 3)
        return BAD
    if get(w, I_ERROR) != 0:
        prepared_event(w, 2)
        return 128
    if get(w, I_NEED) > length(w):
        prepared_event(w, 1)
        return GROW
    prepared_event(w, 0)
    return 128

def semantic(w:mutbuf, reason:u64) -> u64:
    if get(w, I_ERROR) == 0:
        put(w, I_ERROR, reason)
    return 0

def prepared_event(w:mutbuf, action:u64) -> u64:
    at = 0
    size = 0
    if action == 0:
        at = BASE
        size = get(w, I_NEED) - BASE
    elif action == 2:
        row = INDEX + (L_ERROR1 + get(w, I_ERROR) - 1) * 16
        at = get(w, row)
        size = get(w, row + 8)
    put(w, 0, EVENT)
    put(w, 8, 1)
    put(w, 16, action)
    put(w, 24, get(w, S_LEASE))
    put(w, 32, get(w, S_SEQ))
    put(w, 40, get(w, I_ERROR))
    put(w, 48, get(w, I_NEED))
    put(w, 56, at)
    put(w, 64, size)
    put(w, 72, get(w, S_FN_COUNT))
    put(w, 80, get(w, I_ALIGN))
    put(w, 88, get(w, I_FOREIGN_N))
    put(w, 96, get(w, I_MODE))
    put(w, 104, get(w, S_ROOT))
    put(w, 112, get(w, I_PHASE))
    put(w, 120, get(w, S_BAD))
    return 0

def input_frame(s:readbuf, r:readbuf, w:mutbuf) -> u64:
    if length(s) < 64 or length(r) != 128:
        return abi(w, 201)
    if word(r, 0) != COMMAND or word(r, 8) != 1 or word(r, 16) == 0 or word(r, 24) == 0:
        return abi(w, 202)
    if word(r, 32) > 2 or word(r, 40) == 0 or word(r, 48) > 1 or word(r, 64) != length(s):
        return abi(w, 203)
    at = 72
    while at < 128:
        if word(r, at) != 0:
            return abi(w, 204)
        at = at + 8
    if word(s, 0) != GRAPH or word(s, 8) != word(r, 16) or word(s, 56) != 0:
        return abi(w, 205)
    nodes = word(s, 16)
    edges = word(s, 32)
    if nodes == 0 or nodes > (MAX - 64) >> 6:
        return abi(w, 206)
    end = 64 + nodes * 64
    if edges > (MAX - end) >> 3:
        return abi(w, 207)
    end = end + edges * 8
    if end > length(s) or word(s, 40) != length(s) - end or word(s, 48) != length(s):
        return abi(w, 208)
    if word(s, 24) == 0 or word(s, 24) > nodes or word(r, 56) != word(s, 24):
        return abi(w, 209)
    put(w, S_LEASE, word(r, 16))
    put(w, S_SEQ, word(r, 24))
    put(w, I_MODE, word(r, 32))
    put(w, I_CODE_LEASE, word(r, 40))
    put(w, I_STRUCTURED, word(r, 48))
    put(w, S_NODES, nodes)
    put(w, S_EDGES, edges)
    put(w, S_DATA, end)
    put(w, S_ROOT, word(s, 24))
    root = typed(s, w, get(w, S_ROOT), 5)
    if root == 0 or word(s, root + 32) != 3:
        return abi(w, 210)
    put(w, S_CORE, edge(s, w, root, 0))
    put(w, S_PLAN, edge(s, w, root, 1))
    put(w, I_FOREIGN, edge(s, w, root, 2))
    put(w, I_NEED, BASE)
    return choose(get(w, S_BAD) == 0, 1, 0)

def magnitude(s:readbuf, w:mutbuf, at:u64) -> u64:
    if word(s, at) != 2 or word(s, at + 48) != 0 or word(s, at + 16) > 8:
        return 0
    value = 0
    i = 0
    while i < word(s, at + 16):
        value = value | (byte(s, word(s, at + 8) + i) << (i * 8))
        i = i + 1
    return value

def text_less(s:readbuf, w:mutbuf, left:u64, right:u64) -> u64:
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

def function_list(s:readbuf, w:mutbuf) -> u64:
    functions = field(s, w, get(w, S_CORE), L_FUNCTIONS, 1)
    at = typed(s, w, functions, 5)
    if at == 0:
        return 0
    put(w, S_FUNCTIONS, functions)
    put(w, S_FN_COUNT, word(s, at + 32))
    return at

def function_index(s:readbuf, w:mutbuf, name:u64) -> u64:
    at = typed(s, w, get(w, S_FUNCTIONS), 5)
    if at == 0:
        return MAX
    i = 0
    while i < word(s, at + 32):
        fn = edge(s, w, at, i)
        fnname = field(s, w, fn, L_NAME, 1)
        if equal(s, w, name, fnname) != 0:
            return i
        if get(w, S_BAD) != 0:
            return MAX
        i = i + 1
    return MAX

def reserved_name(s:readbuf, w:mutbuf, name:u64) -> u64:
    at = typed(s, w, name, 4)
    if at == 0:
        return 0
    begin = word(s, at + 8)
    if word(s, at + 16) >= 6:
        if byte(s, begin) == 95 and byte(s, begin + 1) == 95 and byte(s, begin + 2) == 104 and byte(s, begin + 3) == 105 and byte(s, begin + 4) == 97 and byte(s, begin + 5) == 95:
            return 1
    return reserved_literal(s, w, name)

def byte_signature(s:readbuf, w:mutbuf, fn:u64) -> u64:
    params = typed(s, w, field(s, w, fn, L_PARAMS, 1), 5)
    returns = typed(s, w, field(s, w, fn, L_RETURNS, 1), 5)
    if params == 0 or returns == 0:
        return 0
    loans = 0
    badtype = 0
    i = 0
    while i < word(s, params + 32):
        param = edge(s, w, params, i)
        typ = field(s, w, param, L_TYPE, 1)
        code = reviewed_type(s, w, typ)
        if code == 13 or code == 14:
            loans = loans + 1
        elif code > 10:
            badtype = 1
        i = i + 1
    if get(w, S_BAD) != 0:
        return 0
    if loans == 0 or loans > 8 or badtype != 0 or word(s, returns + 32) != 1:
        return semantic(w, 6)
    if literal(s, w, edge(s, w, returns, 0), L_TYPE_U32) == 0:
        return semantic(w, 6)
    return 1

def normalize_pair(s:readbuf, w:mutbuf, array:u64, i:u64) -> u64:
    pair = node(s, w, edge(s, w, array, i))
    if pair == 0:
        return 0
    if word(s, pair) != 7 or word(s, pair + 32) != 2:
        return semantic(w, 3)
    name = edge(s, w, pair, 0)
    limit = node(s, w, edge(s, w, pair, 1))
    text = node(s, w, name)
    if limit == 0 or text == 0:
        return 0
    if word(s, text) != 4 or word(s, limit) != 2:
        return semantic(w, 3)
    extent = magnitude(s, w, limit)
    if extent == 0 or extent > 1048576:
        return semantic(w, 3)
    j = 0
    while j < i:
        if equal(s, w, name, get(w, BASE + 128 + j * 32)) != 0:
            return semantic(w, 3)
        j = j + 1
    if reserved_name(s, w, name) != 0:
        return semantic(w, 4)
    index = function_index(s, w, name)
    if get(w, S_BAD) != 0:
        return 0
    if index == MAX:
        return semantic(w, 5)
    functions = typed(s, w, get(w, S_FUNCTIONS), 5)
    fn = edge(s, w, functions, index)
    if byte_signature(s, w, fn) == 0:
        return 0
    at = BASE + 128 + i * 32
    put(w, at, name)
    put(w, at + 8, index)
    put(w, at + 16, extent)
    put(w, at + 24, 0)
    return 1

def normalize_sort(s:readbuf, w:mutbuf) -> u64:
    count = get(w, I_FOREIGN_N)
    i = 1
    while i < count:
        j = i
        while j > 0:
            right = BASE + 128 + j * 32
            left = right - 32
            if text_less(s, w, get(w, right), get(w, left)) == 0:
                j = 0
            else:
                k = 0
                while k < 32:
                    value = get(w, right + k)
                    put(w, right + k, get(w, left + k))
                    put(w, left + k, value)
                    k = k + 8
                j = j - 1
        i = i + 1
    return 0

def normalize_finish(s:readbuf, w:mutbuf) -> u64:
    graph = BASE + 128 + get(w, I_FOREIGN_N) * 32
    fill_range(w, BASE, 128, 0)
    put(w, BASE, NORMALIZED)
    put(w, BASE + 8, 1)
    put(w, BASE + 16, get(w, S_LEASE))
    put(w, BASE + 24, get(w, S_SEQ))
    put(w, BASE + 32, get(w, I_FOREIGN_N))
    put(w, BASE + 40, BASE + 128)
    put(w, BASE + 48, graph)
    put(w, BASE + 56, length(s))
    put(w, BASE + 64, get(w, S_ROOT))
    put(w, BASE + 72, length(s))
    put(w, BASE + 80, get(w, I_STRUCTURED))
    copy_bytes(w, s, graph, 0, length(s))
    put(w, graph + 64 + (get(w, S_ROOT) - 1) * 64 + 32, 2)
    return 1

def normalize_foreign(s:readbuf, w:mutbuf) -> u64:
    put(w, I_PHASE, 1)
    at = node(s, w, get(w, I_FOREIGN))
    if at == 0:
        return 0
    if word(s, at) != 7 or word(s, at + 32) > 128:
        return semantic(w, 1)
    count = word(s, at + 32)
    put(w, I_FOREIGN_N, count)
    graph = BASE + 128 + count * 32
    if length(s) > MAX - graph:
        return abi(w, 211)
    put(w, I_NEED, graph + length(s))
    if count != 0:
        if get(w, I_STRUCTURED) != 0:
            return semantic(w, 2)
        if field(s, w, get(w, S_CORE), L_EXPORTS, 0) != 0:
            return semantic(w, 2)
        if get(w, S_BAD) != 0 or function_list(s, w) == 0:
            return 0
    if get(w, I_NEED) > length(w):
        return 0
    i = 0
    while i < count:
        if normalize_pair(s, w, at, i) == 0:
            return 0
        i = i + 1
    normalize_sort(s, w)
    if get(w, S_BAD) != 0:
        return 0
    return normalize_finish(s, w)

def code_options(s:readbuf, w:mutbuf) -> u64:
    put(w, I_ALIGN, 1)
    plan = node(s, w, get(w, S_PLAN))
    if plan == 0:
        return 0
    if word(s, plan) == 0:
        return 1
    if word(s, plan) != 6:
        return abi(w, 212)
    schema = field(s, w, get(w, S_PLAN), L_SCHEMA, 1)
    if literal(s, w, schema, L_LAYOUT_V1) != 0:
        return 1
    put(w, I_OPTIONS, 1)
    scratch = field(s, w, get(w, S_PLAN), L_SCRATCH_REGISTERS, 1)
    a = field(s, w, scratch, L_R10, 1)
    b = field(s, w, scratch, L_R11, 1)
    if literal(s, w, a, L_R10) != 0 and literal(s, w, b, L_R11) != 0:
        put(w, I_SWAP, 0)
    elif literal(s, w, a, L_R11) != 0 and literal(s, w, b, L_R10) != 0:
        put(w, I_SWAP, 1)
    else:
        return abi(w, 213)
    options = field(s, w, get(w, S_PLAN), L_INSTRUCTION_SELECTION, 1)
    move = field(s, w, options, L_MOVE_IMMEDIATE, 1)
    alu = field(s, w, options, L_ALU_IMMEDIATE, 1)
    if literal(s, w, move, L_MOVABS) != 0:
        put(w, I_MOVE, 0)
    elif literal(s, w, move, L_MOVCOMPACT) != 0:
        put(w, I_MOVE, 1)
    else:
        return abi(w, 214)
    if literal(s, w, alu, L_IMM32) != 0:
        put(w, I_ALU, 0)
    elif literal(s, w, alu, L_IMMCOMPACT) != 0:
        put(w, I_ALU, 1)
    else:
        return abi(w, 215)
    return choose(get(w, S_BAD) == 0, 1, 0)

def packet_node(w:mutbuf, identifier:u64, kind:u64, begin:u64, count:u64, first:u64, children:u64, object_id:u64, aux:u64) -> u64:
    at = BASE + 128 + (identifier - 1) * 64
    put(w, at, kind)
    put(w, at + 8, begin)
    put(w, at + 16, count)
    put(w, at + 24, first)
    put(w, at + 32, children)
    put(w, at + 40, object_id)
    put(w, at + 48, aux)
    return 0

def packet_string(w:mutbuf, identifier:u64, literal_id:u64, cursor:u64) -> u64:
    row = INDEX + literal_id * 16
    count = get(w, row + 8)
    packet_node(w, identifier, 4, cursor - 64, count, 0, 0, 0, count)
    i = 0
    while i < count:
        store(w, BASE + cursor + i, byte(w, get(w, row) + i))
        i = i + 1
    return cursor + count

def init_packet(w:mutbuf) -> u64:
    put(w, I_PHASE, 2)
    nodes = 4
    edges = 3
    if get(w, I_OPTIONS) != 0:
        nodes = 6
        edges = 7
    move = choose(get(w, I_MOVE) == 0, L_MOVABS, L_MOVCOMPACT)
    alu = choose(get(w, I_ALU) == 0, L_IMM32, L_IMMCOMPACT)
    pool = 128 + nodes * 64 + edges * 8
    total = pool + get(w, INDEX + move * 16 + 8) + get(w, INDEX + alu * 16 + 8)
    if get(w, I_OPTIONS) != 0:
        total = total + 6
    put(w, I_NEED, BASE + total)
    if get(w, I_NEED) > length(w):
        return 0
    fill_range(w, BASE, total, 0)
    put(w, BASE, CODE_COMMAND)
    put(w, BASE + 8, 1)
    put(w, BASE + 16, get(w, I_CODE_LEASE))
    put(w, BASE + 24, 1)
    put(w, BASE + 32, 0)
    put(w, BASE + 40, total - 64)
    put(w, BASE + 48, 1)
    put(w, BASE + 64, CODE_GRAPH)
    put(w, BASE + 72, get(w, I_CODE_LEASE))
    put(w, BASE + 80, nodes)
    put(w, BASE + 88, 1)
    put(w, BASE + 96, edges)
    put(w, BASE + 104, total - pool)
    put(w, BASE + 112, total - 64)
    packet_node(w, 1, 5, 0, 0, 0, 3, 1, 0)
    edge_at = BASE + 128 + nodes * 64
    put(w, edge_at, 2)
    if get(w, I_OPTIONS) == 0:
        packet_node(w, 2, 0, 0, 0, 0, 0, 0, 0)
        put(w, edge_at + 8, 3)
        put(w, edge_at + 16, 4)
        pool = packet_string(w, 3, move, pool)
        pool = packet_string(w, 4, alu, pool)
    else:
        packet_node(w, 2, 6, 0, 0, 3, 2, 2, 0)
        put(w, edge_at + 8, 5)
        put(w, edge_at + 16, 6)
        put(w, edge_at + 24, 3)
        put(w, edge_at + 32, choose(get(w, I_SWAP) == 0, 3, 4))
        put(w, edge_at + 40, 4)
        put(w, edge_at + 48, choose(get(w, I_SWAP) == 0, 4, 3))
        pool = packet_string(w, 3, L_R10, pool)
        pool = packet_string(w, 4, L_R11, pool)
        pool = packet_string(w, 5, move, pool)
        pool = packet_string(w, 6, alu, pool)
    if pool != total:
        return abi(w, 216)
    return 1

def types_review(s:readbuf, w:mutbuf, identifier:u64, definitions:u64) -> u64:
    at = typed(s, w, identifier, 5)
    if at == 0:
        return 0
    good = 1
    i = 0
    while i < word(s, at + 32):
        name = edge(s, w, at, i)
        if definitions != 0:
            name = field(s, w, name, L_TYPE, 1)
        if reviewed_type(s, w, name) == 16:
            good = 0
        if get(w, S_BAD) != 0:
            return 0
        i = i + 1
    return good

def function_profile(s:readbuf, w:mutbuf, fn:u64) -> u64:
    good = types_review(s, w, field(s, w, fn, L_PARAMS, 1), 1)
    if types_review(s, w, field(s, w, fn, L_RETURNS, 1), 0) == 0:
        good = 0
    if get(w, S_BAD) != 0:
        return 0
    blocks = typed(s, w, field(s, w, fn, L_BLOCKS, 1), 5)
    if blocks == 0:
        return 0
    i = 0
    while i < word(s, blocks + 32):
        block = edge(s, w, blocks, i)
        if types_review(s, w, field(s, w, block, L_PARAMS, 1), 1) == 0:
            good = 0
        if get(w, S_BAD) != 0:
            return 0
        term = field(s, w, block, L_TERM, 1)
        op = field(s, w, term, L_OP, 1)
        if literal(s, w, op, L_RET) == 0 and literal(s, w, op, L_JUMP) == 0 and literal(s, w, op, L_BRANCH) == 0 and literal(s, w, op, L_TRAP) == 0:
            return semantic(w, 8)
        ops = typed(s, w, field(s, w, block, L_OPS, 1), 5)
        if ops == 0:
            return 0
        j = 0
        while j < word(s, ops + 32):
            instruction = edge(s, w, ops, j)
            name = field(s, w, instruction, L_OP, 1)
            if reviewed_opcode(s, w, name) == 0:
                return semantic(w, 9)
            if types_review(s, w, field(s, w, instruction, L_OUT, 1), 1) == 0:
                good = 0
            if get(w, S_BAD) != 0:
                return 0
            j = j + 1
        i = i + 1
    if good == 0:
        return semantic(w, 10)
    return 1

def profile(s:readbuf, w:mutbuf) -> u64:
    put(w, I_PHASE, 3)
    schema = field(s, w, get(w, S_CORE), L_SCHEMA, 1)
    if reviewed_schema(s, w, schema) == 0:
        return semantic(w, 7)
    at = function_list(s, w)
    if at == 0:
        return 0
    i = 0
    while i < word(s, at + 32):
        if function_profile(s, w, edge(s, w, at, i)) == 0:
            return 0
        i = i + 1
    return choose(get(w, S_BAD) == 0, 1, 0)

def inventory_order(s:readbuf, w:mutbuf) -> u64:
    order = 0
    plan = node(s, w, get(w, S_PLAN))
    if plan == 0:
        return 0
    put(w, I_ALIGN, 1)
    if word(s, plan) != 0:
        if word(s, plan) != 6:
            return abi(w, 217)
        identifier = field(s, w, get(w, S_PLAN), L_FUNCTION_ALIGNMENT, 0)
        if identifier != 0:
            at = node(s, w, identifier)
            if at == 0:
                return 0
            value = magnitude(s, w, at)
            if value != 1 and value != 16 and value != 32 and value != 64:
                return abi(w, 218)
            put(w, I_ALIGN, value)
        order = field(s, w, get(w, S_PLAN), L_FUNCTION_ORDER, 0)
    count = get(w, S_FN_COUNT)
    base = get(w, I_ORDER_AT)
    i = 0
    if order == 0:
        while i < count:
            put(w, base + i * 8, i)
            i = i + 1
        return 1
    array = typed(s, w, order, 5)
    if array == 0 or word(s, array + 32) != count:
        return abi(w, 219)
    while i < count:
        index = function_index(s, w, edge(s, w, array, i))
        if index == MAX:
            return abi(w, 220)
        j = 0
        while j < i:
            if get(w, base + j * 8) == index:
                return abi(w, 221)
            j = j + 1
        put(w, base + i * 8, index)
        i = i + 1
    return choose(get(w, S_BAD) == 0, 1, 0)

def inventory_header(s:readbuf, w:mutbuf) -> u64:
    fill_range(w, BASE, 256, 0)
    put(w, BASE, INVENTORY)
    put(w, BASE + 8, 1)
    put(w, BASE + 16, get(w, S_LEASE))
    put(w, BASE + 24, get(w, S_SEQ))
    put(w, BASE + 32, get(w, S_CORE))
    put(w, BASE + 40, get(w, S_PLAN))
    put(w, BASE + 48, get(w, S_FUNCTIONS))
    put(w, BASE + 56, get(w, S_FN_COUNT))
    put(w, BASE + 64, BASE + 256)
    put(w, BASE + 72, get(w, I_ORDER_AT))
    put(w, BASE + 80, get(w, I_ALIGN))
    put(w, BASE + 88, get(w, I_NEED))
    put(w, BASE + 96, length(s))
    put(w, BASE + 104, get(w, S_ROOT))
    return 1

def inventory(s:readbuf, w:mutbuf) -> u64:
    count = get(w, S_FN_COUNT)
    if count > MAX_INVENTORY_FUNCTIONS:
        return abi(w, 222)
    # Each row is 48 bytes; the order vector adds 8 bytes per function.
    put(w, I_ORDER_AT, BASE + 256 + count * 48)
    put(w, I_NEED, BASE + 256 + count * 56)
    if get(w, I_NEED) > length(w):
        return 0
    fill_range(w, BASE, get(w, I_NEED) - BASE, 0)
    functions = typed(s, w, get(w, S_FUNCTIONS), 5)
    if functions == 0:
        return 0
    i = 0
    while i < count:
        fn = edge(s, w, functions, i)
        name = field(s, w, fn, L_NAME, 1)
        at = typed(s, w, name, 4)
        if at == 0:
            return 0
        row = BASE + 256 + i * 48
        put(w, row, fn)
        put(w, row + 8, name)
        put(w, row + 16, word(s, at + 8))
        put(w, row + 24, word(s, at + 16))
        i = i + 1
    if inventory_order(s, w) == 0:
        return 0
    return inventory_header(s, w)
'''
def source(frame_owner,elf_owner):
    shared_names=("abi","word","get","put","typed","edge","literal","equal","field")
    shared={n.name:n for n in ast.parse(frame_owner.BODY).body}
    elf={n.name:n for n in ast.parse(elf_owner.BODY).body}
    constants=dict(frame_owner.CONSTANTS)
    constants.update(MIN_WORK=8192,BASE=8192,INDEX=2048,DATA=4096,
        COMMAND=magic("HIAEMC01"),EVENT=magic("HIAEME01"),
        NORMALIZED=magic("HIAEMN01"),INVENTORY=magic("HIAEMP01"),
        CODE_COMMAND=magic("HIAXCC01"),CODE_GRAPH=magic("HIAXGR01"))
    constants["S_DATABASE"]=constants["S_DATA"]
    constants["MAX_INVENTORY_FUNCTIONS"]=((1<<64)-1-8192-256)//56
    fields=("MODE","CODE_LEASE","STRUCTURED","FOREIGN","ERROR","NEED","ALIGN","FOREIGN_N",
            "OPTIONS","SWAP","MOVE","ALU","ORDER_AT","PHASE")
    constants.update({"I_"+name:1024+i*8 for i,name in enumerate(fields)})
    literals=dict(LITERALS);data=bytearray(constants["DATA"]);helpers=[]
    for index,(key,value) in enumerate(literals.items()):
        constants["L_"+key.upper()]=index
        raw=value.encode("ascii");start=len(data);data.extend(raw)
        at=constants["INDEX"]+index*16
        data[at:at+8]=start.to_bytes(8,"little");data[at+8:at+16]=len(raw).to_bytes(8,"little")
    assert constants["INDEX"]+len(literals)*16<=constants["DATA"]
    assert len(data)<constants["MIN_WORK"]
    writes=[(at,int.from_bytes(data[at:at+8].ljust(8,b"\0"),"little"))
            for at in range(constants["INDEX"],len(data),8) if any(data[at:at+8])]
    calls=[]
    for start in range(0,len(writes),16):
        name="literal_"+str(start//16);calls.append("    "+name+"(w)")
        helpers.append("def "+name+"(w:mutbuf)->u64:\n"+
            "\n".join("    put(w,%d,%d)"%item for item in writes[start:start+16])+"\n    return 0")
    helpers.append("def literal_table(w:mutbuf)->u64:\n"+"\n".join(calls)+"\n    return 0")
    for name,values,offset,prefix,miss in(
        ("reviewed_type",TYPES,0,"TYPE_",16),("reviewed_opcode",OPCODES,1,"OPCODE_",0),
        ("reserved_literal",RESERVED,1,"RESERVED_",0),("reviewed_schema",tuple(range(1,9)),1,"SCHEMA_",0)):
        lines=["def "+name+"(s:readbuf,w:mutbuf,name:u64)->u64:"]
        for i,value in enumerate(values):
            suffix=str(i) if name in("reviewed_opcode","reserved_literal") else str(value).upper()
            result=i+offset if name=="reviewed_type" else 1
            lines+=["    if literal(s,w,name,L_"+prefix+suffix+") != 0:","        return "+str(result)]
        lines+=["    return "+str(miss)];helpers.append("\n".join(lines))
    # Raw capture preserves bytearray and str subclasses as tags 10 and 11.
    # They are legal private transport records, then rejected by exact-type
    # normalization in HIA. Do not change the separately frozen ELF writer.
    node_source=ast.unparse(elf["node"])
    assert node_source.count("kind > 9")==1 and node_source.count("elif kind == 9:")==1
    node_source=node_source.replace("kind > 9","kind > 11").replace(
        "elif kind == 9:","elif kind == 9 or kind == 10:")
    raw_node=ast.parse(node_source).body[0]
    nodes=ast.parse(BODY+"\n"+"\n".join(helpers)).body+[shared[n] for n in shared_names]+[raw_node]
    names={n.name:n for n in nodes};assert len(names)==len(nodes)
    live={"emitter_prepare"};pending=["emitter_prepare"]
    while pending:
        for call in ast.walk(names[pending.pop()]):
            if isinstance(call,ast.Call) and isinstance(call.func,ast.Name):
                name=call.func.id
                if name in names and name not in live:live.add(name);pending.append(name)
    nodes=[n for n in nodes if n.name in live]
    for node in nodes:
        if node.name in("word","get"):
            arg="s" if node.name=="word" else "w"
            node.body=ast.parse("return "+" | ".join("(byte(%s,at+%d)<<%d)"%(arg,i,8*i) for i in range(8))).body
        elif node.name=="put":
            node.body=ast.parse("\n".join("store(w,at+%d,(value>>%d)&255)"%(i,8*i) for i in range(8))+"\nreturn 0").body
    return "\n".join(ast.unparse(ast.fix_missing_locations(n)) for n in nodes)+"\n",constants,dict(
        status="NEW_UNEXECUTED",scope="RAW_BYTE_MANIFEST_NORMALIZATION_CODE_INIT_AND_EMITTER_PROFILE",
        backend_reference_sha256=REFERENCE_SHA,byte_reference_sha256=BYTE_SHA,
        frame_dependency_sha256=FRAME_SHA,elf_graph_dependency_sha256=ELF_SHA,
        actual_Core_checked_plan_and_origin_issuer_required=True,header_is_authentication=False,
        mode_order="normalize -> checked-plan validation upstream -> init -> actual Code ACK -> profile",
        tuple_and_bool_integer_distinctions_preserved=True,
        original_profile_schema_term_opcode_then_function_types_order=True,
        original_function_order_and_alignment_not_selected_by_host=True,
        projected_Graph_root_only_changes_three_to_two_children=True,
        no_new_language_function_block_or_operation_quota=True,
        whole_Emitter=False,outer_emit_program_machine=False,installed=False,cold=False)
