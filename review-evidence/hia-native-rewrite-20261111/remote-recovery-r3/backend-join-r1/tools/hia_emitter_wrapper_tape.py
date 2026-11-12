"""HIA scalar and synchronous borrowed-byte entry-wrapper instruction tape.
Development authoring composes exact shared tape helpers. The runtime decides
all guards, register moves, labels, stack words, offsets and Code operations.
The input Graph and the optional borrowed-byte request require actual private
Core / manifest issuers; wire headers do not authenticate foreign objects.
"""
import ast
REFERENCE_SHA="bf953a8b85d1ebc6b9d7a90fbbcaa4137e40ed214c2ede2af1a13cfc01b1c07c"
BYTE_REFERENCE_SHA="0bb40a17f76c27146a48a6d3d229228c9a89bfd96d4b9d65b3b9c70215a3edd6"
TAPE_OWNER_SHA="e61fcb540bbe51a0e85dc09cd9afa3813b6ba24d6739da2912269c10ce1522eb"
FRAME_OWNER_SHA="27a817d4cb0d3c8131efa4c8474779f55d74d618124a987a551cb26b3e18ddbd"
def magic(value):return int.from_bytes(value.encode("ascii"),"little")
EXTRA_LITERALS={
 "EXPORTS":"exports","NATIVE_PREFIX":"__hia_",
 "INIT":"_init","FINI":"_fini","GMON":"__gmon_start__","CXA":"__cxa_finalize",
 "DSO":"__dso_handle","ITM_REGISTER":"_ITM_registerTMCloneTable",
 "ITM_DEREGISTER":"_ITM_deregisterTMCloneTable",
 "BYTE_REJECT1":"byte_abi_reject_1","BYTE_REJECT2":"byte_abi_reject_2",
 "BYTE_REJECT3":"byte_abi_reject_3","BYTE_REJECT4":"byte_abi_reject_4",
 "BYTE_RANGE":"byte_abi_range","BYTE_DISJOINT":"byte_abi_disjoint",
 "SCALAR_CONFLICT":"E_HIA_PROGRAM_ABI: export conflicts with the closed runtime or loader ABI",
 "SCALAR_FRAME":"E_HIA_PROGRAM_LIMIT: entry wrapper exceeds the stack budget",
 "BYTE_FRAME":"E_HIA_PROGRAM_LIMIT: borrowed-byte wrapper exceeds the stack budget"}
WRAPPER_CONSTANTS=dict(COMMAND=magic("HIAWRC01"),EVENT=magic("HIAWRE01"),
 TAPE=magic("HIAWRT01"),W_KIND=512,W_EXTENT=520,W_WORDS=528,W_RANGE_N=536,
 W_RETURN=544,W_ERROR=552,W_ERROR_AT=560,W_ERROR_N=568,WR_RANGES=8192)
BODY=r'''
def wrapper_tape(s:readbuf, r:readbuf, w:mutbuf) -> u32:
    if length(w) < BASE:
        return BAD
    fill_range(w, 0, BASE, 0)
    literal_table(w)
    if wrapper_source(s, r, w) != 0:
        admitted = wrapper_admit(s, w)
        if admitted != 0 and get(w, W_ERROR) == 0 and get(w, S_BAD) == 0:
            wrapper_body(s, r, w)
            if get(w, S_BAD) == 0:
                count = get(w, S_COUNT)
                size = get(w, S_BYTES)
                if count > (MAX - RECORDS) >> 7:
                    abi(w, 200)
                else:
                    pool_at = RECORDS + count * 128
                    if size > MAX - pool_at:
                        abi(w, 201)
                    else:
                        put(w, S_POOL, pool_at)
                        put(w, S_NEED, pool_at + size)
                        if pool_at + size <= length(w):
                            put(w, S_EXPECTED_COUNT, count)
                            put(w, S_EXPECTED_BYTES, size)
                            put(w, S_WRITE, 1)
                            put(w, S_COUNT, 0)
                            put(w, S_BYTES, 0)
                            put(w, S_SERIAL, get(w, S_SERIAL_START))
                            fill_range(w, HEADER, pool_at + size - HEADER, 0)
                            wrapper_body(s, r, w)
                            if get(w, S_COUNT) != count or get(w, S_BYTES) != size:
                                abi(w, 202)
                            if get(w, S_BAD) == 0:
                                wrapper_header(s, r, w)
        elif get(w, S_BAD) == 0 and get(w, W_ERROR) == 0:
            wrapper_event(w, 4)
            return 128
    if get(w, S_BAD) != 0:
        wrapper_event(w, 3)
        return BAD
    if get(w, W_ERROR) != 0:
        wrapper_event(w, 2)
        return 128
    if get(w, S_NEED) > length(w):
        wrapper_event(w, 1)
        return GROW
    wrapper_event(w, 0)
    return 128

def wrapper_event(w:mutbuf, action:u64) -> u64:
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
    put(w, 96, choose(action == 2, get(w, W_ERROR_AT), 0))
    put(w, 104, choose(action == 2, get(w, W_ERROR_N), 0))
    put(w, 112, choose(action == 2, get(w, W_ERROR), 0))
    put(w, 120, get(w, S_BAD))
    return 0

def wrapper_source(s:readbuf, r:readbuf, w:mutbuf) -> u64:
    if length(s) < 128 or length(r) != 96:
        return abi(w, 203)
    if word(r, 0) != COMMAND or word(r, 8) != 1 or word(r, 16) == 0 or word(r, 24) == 0:
        return abi(w, 204)
    if word(r, 72) != 0 or word(r, 80) != 0 or word(r, 88) != 0:
        return abi(w, 205)
    kind = word(r, 56)
    extent = word(r, 64)
    if kind != 1 and kind != 2:
        return abi(w, 206)
    if (kind == 1 and extent != 0) or (kind == 2 and (extent == 0 or extent > 1048576)):
        return abi(w, 207)
    if word(s, 0) != GRAPH or word(s, 8) != word(r, 16) or word(s, 56) != 0:
        return abi(w, 208)
    nodes = word(s, 16)
    edges = word(s, 32)
    if nodes == 0 or nodes > (MAX - 64) >> 6:
        return abi(w, 209)
    end = 64 + nodes * 64
    if edges > (MAX - end) >> 3:
        return abi(w, 210)
    end = end + edges * 8
    if end > length(s) or word(s, 40) != length(s) - end or word(s, 48) != length(s):
        return abi(w, 211)
    if word(s, 24) == 0 or word(s, 24) > nodes or word(s, 24) != word(r, 48):
        return abi(w, 212)
    put(w, S_LEASE, word(r, 16))
    put(w, S_REQUEST, word(r, 24))
    put(w, S_FN_INDEX, word(r, 32))
    put(w, S_SERIAL_START, word(r, 40))
    put(w, S_SERIAL, word(r, 40))
    put(w, S_ROOT, word(r, 48))
    put(w, S_NODES, nodes)
    put(w, S_EDGES, edges)
    put(w, S_DATA, end)
    put(w, S_USED, 96)
    put(w, S_NEED, BASE)
    put(w, W_KIND, kind)
    put(w, W_EXTENT, extent)
    root = typed(s, w, get(w, S_ROOT), 5)
    if root == 0 or word(s, root + 32) != 2:
        return abi(w, 213)
    core = edge(s, w, root, 0)
    functions = typed(s, w, field(s, w, core, L_FUNCTIONS, 1), 5)
    if functions == 0 or get(w, S_FN_INDEX) >= word(s, functions + 32):
        return abi(w, 214)
    fn = edge(s, w, functions, get(w, S_FN_INDEX))
    name = field(s, w, fn, L_NAME, 1)
    if typed(s, w, name, 4) == 0:
        return 0
    params = field(s, w, fn, L_PARAMS, 1)
    returns = field(s, w, fn, L_RETURNS, 1)
    if typed(s, w, params, 5) == 0 or typed(s, w, returns, 5) == 0:
        return 0
    put(w, S_CORE, core)
    put(w, S_FUNCTIONS, functions)
    put(w, S_FN, fn)
    put(w, S_NAME, name)
    put(w, S_PARAMS, params)
    put(w, W_RETURN, returns)
    return choose(get(w, S_BAD) == 0, 1, 0)

def wrapper_error(w:mutbuf, identifier:u64, literal_index:u64) -> u64:
    put(w, W_ERROR, identifier)
    put(w, W_ERROR_AT, get(w, INDEX + literal_index * 16))
    put(w, W_ERROR_N, get(w, INDEX + literal_index * 16 + 8))
    return 0

def wrapper_frame(w:mutbuf, words:u64) -> u64:
    if words > ((MAX - 15) >> 3) - 1:
        return abi(w, 215)
    frame_bytes = ((words + 1) * 8 + 15) & (MAX - 15)
    put(w, W_WORDS, words)
    put(w, S_FRAME, frame_bytes)
    if frame_bytes > 65536:
        if get(w, W_KIND) == 1:
            return wrapper_error(w, 2, L_SCALAR_FRAME)
        return wrapper_error(w, 3, L_BYTE_FRAME)
    return 1

def wrapper_admit(s:readbuf, w:mutbuf) -> u64:
    if get(w, W_KIND) == 2:
        return wrapper_borrowed_admit(s, w)
    allowed = field(s, w, get(w, S_CORE), L_EXPORTS, 0)
    if get(w, S_BAD) != 0:
        return 0
    if allowed != 0:
        admitted = 0
        n = items(s, w, allowed)
        i = 0
        while i < n and get(w, S_BAD) == 0:
            if equal(s, w, item(s, w, allowed, i), get(w, S_NAME)) != 0:
                admitted = 1
            i = i + 1
        if admitted == 0:
            return 0
    params = get(w, S_PARAMS)
    n = items(s, w, params)
    i = 0
    while i < n and get(w, S_BAD) == 0:
        p = item(s, w, params, i)
        kind = type_code(s, w, field(s, w, p, L_TYPE, 1))
        if kind == 0 or kind >= 12:
            return 0
        i = i + 1
    returns = get(w, W_RETURN)
    if items(s, w, returns) > 1:
        return 0
    if items(s, w, returns) == 1:
        if type_code(s, w, item(s, w, returns, 0)) >= 12:
            return 0
    if wrapper_forbidden(s, w, get(w, S_NAME)) != 0:
        return wrapper_error(w, 1, L_SCALAR_CONFLICT)
    return wrapper_frame(w, n)

def wrapper_borrowed_admit(s:readbuf, w:mutbuf) -> u64:
    if wrapper_forbidden(s, w, get(w, S_NAME)) != 0:
        return abi(w, 216)
    if field(s, w, get(w, S_CORE), L_EXPORTS, 0) != 0:
        return abi(w, 217)
    returns = get(w, W_RETURN)
    if items(s, w, returns) != 1:
        return abi(w, 218)
    if type_code(s, w, item(s, w, returns, 0)) != 7:
        return abi(w, 219)
    params = get(w, S_PARAMS)
    n = items(s, w, params)
    i = 0
    words = 0
    ranges = 0
    while i < n and get(w, S_BAD) == 0:
        kind = type_code(s, w, field(s, w, item(s, w, params, i), L_TYPE, 1))
        if words > MAX - 2:
            return abi(w, 220)
        if kind == 13 or kind == 14:
            if ranges >= 8:
                return abi(w, 221)
            put(w, WR_RANGES + ranges * 16, words)
            put(w, WR_RANGES + ranges * 16 + 8, choose(kind == 14, 1, 0))
            ranges = ranges + 1
            words = words + 2
        elif kind == 0 or kind >= 12:
            return abi(w, 222)
        else:
            words = words + 1
        i = i + 1
    if ranges == 0:
        return abi(w, 223)
    put(w, W_RANGE_N, ranges)
    return wrapper_frame(w, words)

def wrapper_prologue(s:readbuf, r:readbuf, w:mutbuf) -> u64:
    code1(s, r, w, 40, L_RBP)
    code2(s, r, w, 8, L_RBP, L_RSP)
    remaining = get(w, S_FRAME)
    while remaining != 0 and get(w, S_BAD) == 0:
        amount = choose(remaining > 4096, 4096, remaining)
        alu_immediate(s, r, w, L_SUB, L_RSP, amount)
        memory(s, r, w, 10, L_R11, L_RSP, 0)
        remaining = remaining - amount
    return 0

def wrapper_register(index:u64) -> u64:
    if index == 0:
        return L_RDI
    if index == 1:
        return L_RSI
    if index == 2:
        return L_RDX
    if index == 3:
        return L_RCX
    if index == 4:
        return L_R8
    return L_R9

def wrapper_capture_word(s:readbuf, r:readbuf, w:mutbuf, index:u64, kind:u64) -> u64:
    if index < 6:
        code2(s, r, w, 8, L_RAX, wrapper_register(index))
    else:
        memory(s, r, w, 10, L_RAX, L_RBP, 16 + (index - 6) * 8)
    normalize(s, r, w, L_RAX, kind)
    memory(s, r, w, 11, L_RBP, L_RAX, 0 - get(w, S_FRAME) + index * 8)
    return 0

def wrapper_capture(s:readbuf, r:readbuf, w:mutbuf) -> u64:
    params = get(w, S_PARAMS)
    n = items(s, w, params)
    i = 0
    index = 0
    while i < n and get(w, S_BAD) == 0:
        kind = type_code(s, w, field(s, w, item(s, w, params, i), L_TYPE, 1))
        if kind == 13 or kind == 14:
            wrapper_capture_word(s, r, w, index, 9)
            wrapper_capture_word(s, r, w, index + 1, 9)
            index = index + 2
        else:
            wrapper_capture_word(s, r, w, index, kind)
            index = index + 1
        i = i + 1
    if index != get(w, W_WORDS):
        return abi(w, 224)
    return 0

def wrapper_label(w:mutbuf, literal_index:u64, slot:u64) -> u64:
    if get(w, S_SERIAL) == MAX or slot >= 8:
        return abi(w, 225)
    put(w, S_SERIAL, get(w, S_SERIAL) + 1)
    start = LABELS + slot * 256
    n = get(w, INDEX + literal_index * 16 + 8)
    if n > 226:
        return abi(w, 226)
    copy_local(w, start + 8, get(w, INDEX + literal_index * 16), n)
    store(w, start + 8 + n, 95)
    end = decimal(w, start + 9 + n, get(w, S_SERIAL))
    put(w, start, end - start - 8)
    return start

def wrapper_load(s:readbuf, r:readbuf, w:mutbuf, index:u64, register:u64) -> u64:
    return memory(s, r, w, 10, register, L_RBP, 0 - get(w, S_FRAME) + index * 8)

def wrapper_range(s:readbuf, r:readbuf, w:mutbuf, index:u64) -> u64:
    wrapper_load(s, r, w, index + 1, L_RCX)
    immediate(s, r, w, L_RDX, get(w, W_EXTENT))
    code2(s, r, w, 20, L_RCX, L_RDX)
    label_command(s, r, w, 6, L_A, 0)
    wrapper_load(s, r, w, index, L_RAX)
    wrapper_label(w, L_BYTE_RANGE, 4)
    code2(s, r, w, 21, L_RCX, L_RCX)
    label_command(s, r, w, 6, L_E, 4)
    code2(s, r, w, 21, L_RAX, L_RAX)
    label_command(s, r, w, 6, L_E, 1)
    code2(s, r, w, 15, L_RAX, L_RCX)
    label_command(s, r, w, 6, L_B, 2)
    label_command(s, r, w, 4, 0, 4)
    return 0

def wrapper_pair(s:readbuf, r:readbuf, w:mutbuf, left:u64, right:u64) -> u64:
    wrapper_label(w, L_BYTE_DISJOINT, 5)
    wrapper_load(s, r, w, left + 1, L_RCX)
    code2(s, r, w, 21, L_RCX, L_RCX)
    label_command(s, r, w, 6, L_E, 5)
    wrapper_load(s, r, w, right + 1, L_RDX)
    code2(s, r, w, 21, L_RDX, L_RDX)
    label_command(s, r, w, 6, L_E, 5)
    wrapper_load(s, r, w, left, L_RAX)
    code2(s, r, w, 15, L_RAX, L_RCX)
    wrapper_load(s, r, w, right, L_RCX)
    code2(s, r, w, 20, L_RAX, L_RCX)
    label_command(s, r, w, 6, L_BE, 5)
    code2(s, r, w, 15, L_RCX, L_RDX)
    wrapper_load(s, r, w, left, L_RAX)
    code2(s, r, w, 20, L_RCX, L_RAX)
    label_command(s, r, w, 6, L_BE, 5)
    label_command(s, r, w, 5, 0, 3)
    label_command(s, r, w, 4, 0, 5)
    return 0

def wrapper_guards(s:readbuf, r:readbuf, w:mutbuf) -> u64:
    wrapper_label(w, L_BYTE_REJECT1, 0)
    wrapper_label(w, L_BYTE_REJECT2, 1)
    wrapper_label(w, L_BYTE_REJECT3, 2)
    wrapper_label(w, L_BYTE_REJECT4, 3)
    i = 0
    while i < get(w, W_RANGE_N) and get(w, S_BAD) == 0:
        wrapper_range(s, r, w, get(w, WR_RANGES + i * 16))
        i = i + 1
    i = 0
    while i < get(w, W_RANGE_N) and get(w, S_BAD) == 0:
        j = i + 1
        while j < get(w, W_RANGE_N) and get(w, S_BAD) == 0:
            left = WR_RANGES + i * 16
            right = WR_RANGES + j * 16
            if get(w, left + 8) != 0 or get(w, right + 8) != 0:
                wrapper_pair(s, r, w, get(w, left), get(w, right))
            j = j + 1
        i = i + 1
    return 0

def wrapper_body(s:readbuf, r:readbuf, w:mutbuf) -> u64:
    name = typed(s, w, get(w, S_NAME), 4)
    if name == 0:
        return 0
    put(w, S_NAME_N, word(s, name + 16))
    put(w, S_NAME_AT, pool(s, r, w, 3, word(s, name + 8), word(s, name + 16)))
    code0(s, r, w, 2, 1)
    wrapper_prologue(s, r, w)
    wrapper_capture(s, r, w)
    if get(w, W_KIND) == 2:
        wrapper_guards(s, r, w)
    memory(s, r, w, 12, L_RDI, L_RBP, 0 - get(w, S_FRAME))
    memory(s, r, w, 12, L_RSI, L_RBP, 0 - 8)
    call_function(s, r, w, get(w, S_NAME))
    returns = get(w, W_RETURN)
    if items(s, w, returns) != 0:
        kind = type_code(s, w, item(s, w, returns, 0))
        if kind != 0:
            memory(s, r, w, 10, L_RAX, L_RBP, 0 - 8)
            normalize(s, r, w, L_RAX, kind)
    code0(s, r, w, 43, 0)
    code0(s, r, w, 42, 0)
    if get(w, W_KIND) == 2:
        status = 1
        while status <= 4 and get(w, S_BAD) == 0:
            label_command(s, r, w, 4, 0, status - 1)
            immediate(s, r, w, L_RAX, status << 32)
            code0(s, r, w, 43, 0)
            code0(s, r, w, 42, 0)
            status = status + 1
    code0(s, r, w, 2, 3)
    return 0

def wrapper_header(s:readbuf, r:readbuf, w:mutbuf) -> u64:
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
    put(w, HEADER + 136, 96)
    put(w, HEADER + 144, get(w, W_KIND))
    put(w, HEADER + 152, get(w, W_EXTENT))
    return 0
'''

def source(frame_owner,tape_owner):
    body,constants,_=tape_owner.source(frame_owner)
    constants=dict(constants);constants.update(WRAPPER_CONSTANTS)
    originals={n.name:n for n in ast.parse(body).body}
    custom=ast.parse(BODY).body
    forbidden=["def wrapper_forbidden(s:readbuf,w:mutbuf,name:u64)->u64:"]
    keys=("ABORT","CALLOC","MALLOC","FREE","MEMSET","MEMCPY","MEMMOVE",
          "INIT","FINI","GMON","CXA","DSO","ITM_REGISTER","ITM_DEREGISTER")
    for key in keys:
        forbidden+=["    if literal(s,w,name,L_"+key+") != 0:","        return 1"]
    forbidden+=["    row=typed(s,w,name,4)","    if row == 0:","        return 0",
        "    if word(s,row+16) < 6:","        return 0","    i=0",
        "    while i < 6:","        if byte(s,word(s,row+8)+i) != byte(w,get(w,INDEX+L_NATIVE_PREFIX*16)+i):",
        "            return 0","        i=i+1","    return 1"]
    custom+=ast.parse("\n".join(forbidden)).body
    names=dict(originals);names.update({n.name:n for n in custom})
    names["literal_table"]=ast.parse("def literal_table(w:mutbuf)->u64:\n    return 0").body[0]
    live={"wrapper_tape"};pending=["wrapper_tape"]
    while pending:
        for call in ast.walk(names[pending.pop()]):
            if isinstance(call,ast.Call) and isinstance(call.func,ast.Name):
                name=call.func.id
                if name in names and name not in live:
                    live.add(name);pending.append(name)
    used={n.id for name in live for n in ast.walk(names[name])
          if isinstance(n,ast.Name) and isinstance(n.ctx,ast.Load) and n.id.startswith("L_")}
    literals=dict(tape_owner.LITERALS);literals.update(EXTRA_LITERALS)
    active=[(name,value) for name,value in literals.items() if "L_"+name in used]
    assert {"L_"+name for name,value in active}==used
    data=bytearray(constants["DATA"])
    for index,(name,value) in enumerate(active):
        constants["L_"+name]=index;raw=value.encode("ascii");begin=len(data);data.extend(raw)
        at=constants["INDEX"]+index*16
        data[at:at+8]=begin.to_bytes(8,"little");data[at+8:at+16]=len(raw).to_bytes(8,"little")
    assert constants["INDEX"]+len(active)*16<=constants["DATA"]
    assert len(data)<=constants["WR_RANGES"]
    writes=[(at,int.from_bytes(data[at:at+8].ljust(8,b"\0"),"little"))
            for at in range(constants["INDEX"],len(data),8) if any(data[at:at+8])]
    helpers=[];calls=[]
    for start in range(0,len(writes),32):
        name="wrapper_literals_"+str(start//32);calls.append("    "+name+"(w)")
        helpers+=ast.parse("def "+name+"(w:mutbuf)->u64:\n"+
            "\n".join("    put(w,%d,%d)"%pair for pair in writes[start:start+32])+"\n    return 0").body
    names["literal_table"]=ast.parse("def literal_table(w:mutbuf)->u64:\n"+"\n".join(calls)+"\n    return 0").body[0]
    order=["wrapper_tape"]+[n.name for n in custom if n.name!="wrapper_tape"]
    order += [name for name in originals if name not in order]
    nodes=[names[name] for name in order if name in live]+helpers
    assert len(nodes)==len({n.name for n in nodes})
    return "\n".join(ast.unparse(ast.fix_missing_locations(n)) for n in nodes)+"\n",constants,dict(
        status="NEW_UNEXECUTED",scope="SCALAR_AND_BORROWED_BYTE_WRAPPER_TAPE",
        reference_sha256=REFERENCE_SHA,byte_reference_sha256=BYTE_REFERENCE_SHA,
        original_frame_limit=65536,original_extent_limit=1048576,original_loan_range_limit=8,
        actual_private_Core_and_normalized_manifest_required=True,header_is_authentication=False,
        scalar_eligibility_before_reserved_name=True,all_arguments_saved_before_guards=True,
        original_extent_null_address_alias_first_error_order=True,
        original_wrapper_label_serial_order=True,complete_original_Code_command_order=True,
        host_instruction_selection=False,whole_Emitter=False,whole_backend=False,installed=False,cold=False)
