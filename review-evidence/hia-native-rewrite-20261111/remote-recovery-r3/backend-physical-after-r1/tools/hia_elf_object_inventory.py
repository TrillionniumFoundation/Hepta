"""Pure HIA ELF64/62 object inventory and direct-backend closed ABI gate.
New source-only owner. Preserves qualified_object + ELF branch of
inspect_object_symbols + hia_program_native._inspect_object in original order.
Other object formats and shared-library inspection are separate scopes.
"""
import ast
def magic(text):return int.from_bytes(text.encode("ascii"),"little")
STRUCTURE_SHA="4fb0b3d962e4b7f6ba508257bf605f4403d402e4f3d7e05cffa084b91651f5a8"
SYMBOLS_SHA="aff81d724d08ed4a8c3189e3370f75e234daa010ec9e9855aedc1019d55a693f"
BACKEND_SHA="bf953a8b85d1ebc6b9d7a90fbbcaa4137e40ed214c2ede2af1a13cfc01b1c07c"
ELF_AVL_OWNER_SHA="84bbd81168ca645807ce0095755bb6e74efb1ffd9419cec3473a439e34dca985"
CONSTANTS=dict(MAX=(1<<64)-1,BAD=0xfffffffd,GROW=0xfffffffe,MIN_WORK=4096,BASE=8192,
 COMMAND=magic("HIAMIC01"),EVENT=magic("HIAMIE01"),INDEX=1024,DATA=1536)
FIELDS=("LEASE","REQUEST","EXPECTED_LEASE","BAD","ERROR","NEED","RESULT_AT","RESULT_N",
 "EXPECTED_N","EXPECTED_ROWS","SHOFF","SECTION_N","OBSERVED","REG_BASE","REG_N","TREE",
 "NAME_AT","NAME_N","NEW","DEFINED_N","UNDEFINED_N","MATCHED_N","POLICY_BAD","PHASE","OUT","POS","WRITE")
CONSTANTS.update({"S_"+name:256+i*8 for i,name in enumerate(FIELDS)})
ERRORS=(
 "E_OBJECT_SYMBOL_SHAPE: unqualified object structure",
 "E_OBJECT_SYMBOL_TABLE: invalid ELF symbol inventory",
 "E_OBJECT_SYMBOL_TABLE: ELF symbol strings missing",
 "E_OBJECT_SYMBOL_TABLE: ELF names outside file",
 "E_OBJECT_SYMBOL_EXPORT_KIND: unreviewed ELF symbol binding",
 "E_OBJECT_SYMBOL_NAME: bad ELF name",
 "E_OBJECT_SYMBOL_NAME: unterminated name",
 "E_OBJECT_SYMBOL_NAME: non-ASCII symbol",
 "E_OBJECT_SYMBOL_DUPLICATE: export also imported",
 "E_OBJECT_SYMBOL_WEAK: checked C function export cannot be interposed",
 "E_OBJECT_SYMBOL_LOCATION: invalid ELF function section",
 "E_OBJECT_SYMBOL_LOCATION: ELF function outside executable section",
 "E_OBJECT_SYMBOL_DUPLICATE: ELF function identity reused",
 "E_OBJECT_SYMBOL_EXPORT_KIND: unexpected defined ELF global",
 "E_OBJECT_SYMBOL_TABLE: no ELF symbol table",
 "E_OBJECT_SYMBOL_EXPORT: no defined function exports",
 "E_HIA_PROGRAM_NATIVE: object import/export inventory differs from the closed ABI")
LITERALS={**{"ERROR_"+str(i+1):v for i,v in enumerate(ERRORS)},
 "DEFINED":"{\"defined\":[","UNDEFINED":"],\"undefined\":[","END":"]}",
 **{"IMPORT_"+str(i):v for i,v in enumerate(("abort","calloc","malloc","free","memset","memcpy","memmove"))}}
AVL_NAMES=("reg","height","update_height","attach","rotate_left","rotate_right","rebalance","name_order","first_name","next_name","word","get","put")
BODY=r'''
def inspect_object(s:readbuf, r:readbuf, w:mutbuf) -> u32:
    if length(w) < MIN_WORK:
        return BAD
    fill_range(w, 0, MIN_WORK, 0)
    literal_table(w)
    put(w, S_NEED, MIN_WORK)
    put(w, S_REG_BASE, BASE)
    if command(s, r, w) != 0:
        inspect(s, r, w)
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
        abi(w, 20)
        event(w, 3)
        return BAD
    event(w, 0)
    return 128

def abi(w:mutbuf, reason:u64) -> u64:
    if get(w, S_BAD) == 0:
        put(w, S_BAD, reason)
    return 0

def semantic(w:mutbuf, reason:u64) -> u64:
    if get(w, S_ERROR) == 0:
        put(w, S_ERROR, reason)
    return 0

def event(w:mutbuf, action:u64) -> u64:
    at = get(w, S_RESULT_AT)
    size = get(w, S_RESULT_N)
    domain = 0
    if action == 2:
        reason = get(w, S_ERROR)
        at = get(w, INDEX + (reason - 1) * 16)
        size = get(w, INDEX + (reason - 1) * 16 + 8)
        domain = choose(reason == 17, 2, 1)
    if action == 1 or action == 3:
        at = 0
        size = 0
    put(w, 0, EVENT)
    put(w, 8, 1)
    put(w, 16, action)
    put(w, 24, get(w, S_LEASE))
    put(w, 32, get(w, S_REQUEST))
    put(w, 40, get(w, S_EXPECTED_LEASE))
    put(w, 48, domain)
    put(w, 56, choose(action == 2, get(w, S_ERROR), 0))
    put(w, 64, get(w, S_NEED))
    put(w, 72, at)
    put(w, 80, size)
    put(w, 88, get(w, S_DEFINED_N))
    put(w, 96, get(w, S_UNDEFINED_N))
    put(w, 104, get(w, S_REG_N))
    put(w, 112, get(w, S_PHASE))
    put(w, 120, get(w, S_BAD))
    return 0

def inside(total:u64, at:u64, count:u64) -> u64:
    return choose(at <= total and count <= total - at, 1, 0)

def command(s:readbuf, r:readbuf, w:mutbuf) -> u64:
    if length(r) < 128:
        return abi(w, 1)
    if word(r, 0) != COMMAND or word(r, 8) != 1 or word(r, 16) == 0 or word(r, 24) == 0 or word(r, 32) == 0:
        return abi(w, 2)
    if word(r, 40) != length(s) or word(r, 56) != 128 or word(r, 80) != length(r):
        return abi(w, 3)
    count = word(r, 48)
    if count > (MAX - 128) >> 4:
        return abi(w, 4)
    data = 128 + count * 16
    if data > length(r) or word(r, 64) != data or word(r, 72) != length(r) - data:
        return abi(w, 5)
    at = 88
    while at < 128:
        if word(r, at) != 0:
            return abi(w, 6)
        at = at + 8
    i = 0
    while i < count:
        at = word(r, 128 + i * 16)
        size = word(r, 136 + i * 16)
        if at < data or inside(length(r), at, size) == 0:
            return abi(w, 7)
        i = i + 1
    put(w, S_LEASE, word(r, 16))
    put(w, S_REQUEST, word(r, 24))
    put(w, S_EXPECTED_LEASE, word(r, 32))
    put(w, S_EXPECTED_N, count)
    put(w, S_EXPECTED_ROWS, 128)
    return 1

def read_le(s:readbuf, at:u64, size:u64) -> u64:
    value = 0
    i = 0
    while i < size:
        value = value | (byte(s, at + i) << (i * 8))
        i = i + 1
    return value

def structure(s:readbuf, w:mutbuf) -> u64:
    if length(s) < 64:
        return semantic(w, 1)
    if read_le(s, 0, 4) != 1179403647 or byte(s, 4) != 2 or byte(s, 5) != 1:
        return semantic(w, 1)
    if read_le(s, 16, 2) != 1 or read_le(s, 18, 2) != 62 or read_le(s, 52, 2) != 64:
        return semantic(w, 1)
    table = word(s, 40)
    count = read_le(s, 60, 2)
    if table < 64 or read_le(s, 58, 2) != 64 or count == 0 or count > 4096:
        return semantic(w, 1)
    if inside(length(s), table, count * 64) == 0:
        return semantic(w, 1)
    i = 0
    while i < count:
        at = table + i * 64
        kind = read_le(s, at + 4, 4)
        offset = word(s, at + 24)
        size = word(s, at + 32)
        if kind == 0:
            if i != 0 or size != 0:
                return semantic(w, 1)
        elif kind != 8:
            if size != 0 and (offset < 64 or inside(length(s), offset, size) == 0):
                return semantic(w, 1)
        i = i + 1
    put(w, S_SHOFF, table)
    put(w, S_SECTION_N, count)
    return 1

def multiple24(value:u64) -> u64:
    remainder = value
    step = 24
    while step <= remainder and step <= MAX >> 1:
        step = step << 1
    while step >= 24:
        if remainder >= step:
            remainder = remainder - step
        step = step >> 1
    return choose(remainder == 0, 1, 0)

def inspect(s:readbuf, r:readbuf, w:mutbuf) -> u64:
    put(w, S_PHASE, 1)
    if structure(s, w) == 0:
        return 0
    put(w, S_PHASE, 2)
    i = 0
    while i < get(w, S_SECTION_N):
        at = get(w, S_SHOFF) + i * 64
        if read_le(s, at + 4, 4) == 2:
            put(w, S_OBSERVED, 1)
            if table_symbols(s, w, at) == 0:
                return 0
        i = i + 1
    if get(w, S_OBSERVED) == 0:
        return semantic(w, 15)
    if get(w, S_DEFINED_N) == 0:
        return semantic(w, 16)
    put(w, S_PHASE, 3)
    if closed_abi(s, r, w) == 0:
        return 0
    put(w, S_PHASE, 4)
    return publish(s, w)

def table_symbols(s:readbuf, w:mutbuf, section:u64) -> u64:
    link = read_le(s, section + 40, 4)
    offset = word(s, section + 24)
    size = word(s, section + 32)
    entsize = word(s, section + 56)
    if link >= get(w, S_SECTION_N) or entsize != 24 or multiple24(size) == 0:
        return semantic(w, 2)
    strsec = get(w, S_SHOFF) + link * 64
    if read_le(s, strsec + 4, 4) != 3:
        return semantic(w, 3)
    names = word(s, strsec + 24)
    names_size = word(s, strsec + 32)
    if inside(length(s), names, names_size) == 0:
        return semantic(w, 4)
    pos = offset
    end = offset + size
    while pos < end:
        if one_symbol(s, w, pos, names, names_size) == 0:
            return 0
        pos = pos + 24
    return 1

def parsed_name(s:readbuf, w:mutbuf, at:u64, end:u64) -> u64:
    current = at
    done = 0
    invalid = 0
    while current < end and done == 0:
        part = byte(s, current)
        if part == 0:
            done = 1
        else:
            if part >= 128:
                invalid = 1
            current = current + 1
    if done == 0:
        return semantic(w, 7)
    if invalid != 0:
        return semantic(w, 8)
    put(w, S_NAME_AT, at)
    put(w, S_NAME_N, current - at)
    return 1

def one_symbol(s:readbuf, w:mutbuf, pos:u64, names:u64, names_size:u64) -> u64:
    name_off = read_le(s, pos, 4)
    info = byte(s, pos + 4)
    section = read_le(s, pos + 6, 2)
    binding = info >> 4
    kind = info & 15
    if name_off == 0:
        return 1
    if binding > 2:
        return semantic(w, 5)
    if binding == 0:
        return 1
    if name_off >= names_size:
        return semantic(w, 6)
    if parsed_name(s, w, names + name_off, names + names_size) == 0:
        return 0
    if get(w, S_NAME_N) == 0:
        return 1
    if section == 0:
        identifier = register_name(s, w)
        if identifier == 0:
            return 0
        at = reg(w, identifier)
        if get(w, at + 16) & 1 != 0:
            return semantic(w, 9)
        if get(w, at + 16) & 2 == 0:
            put(w, at + 16, get(w, at + 16) | 2)
            put(w, S_UNDEFINED_N, get(w, S_UNDEFINED_N) + 1)
        return 1
    if kind != 2:
        return semantic(w, 14)
    if binding != 1:
        return semantic(w, 10)
    if section >= get(w, S_SECTION_N):
        return semantic(w, 11)
    sec = get(w, S_SHOFF) + section * 64
    section_kind = read_le(s, sec + 4, 4)
    flags = word(s, sec + 8)
    section_bytes = word(s, sec + 32)
    value = word(s, pos + 8)
    size = word(s, pos + 16)
    if section_kind != 1 or flags & 6 != 6 or size == 0 or value >= section_bytes:
        return semantic(w, 12)
    if size > section_bytes - value:
        return semantic(w, 12)
    identifier = register_name(s, w)
    if identifier == 0:
        return 0
    at = reg(w, identifier)
    if get(w, at + 16) & 3 != 0:
        return semantic(w, 13)
    put(w, at + 16, get(w, at + 16) | 1)
    put(w, S_DEFINED_N, get(w, S_DEFINED_N) + 1)
    return 1

def register_name(s:readbuf, w:mutbuf) -> u64:
    parent = 0
    current = get(w, S_TREE)
    direction = 0
    while current != 0:
        direction = name_order(s, w, current)
        if direction == 0:
            return current
        parent = current
        current = get(w, reg(w, current) + choose(direction == 1, 64, 72))
    current = get(w, S_REG_N) + 1
    if current > (MAX - BASE) // 96:
        return abi(w, 8)
    needed = BASE + current * 96
    if needed > length(w):
        if length(w) <= MAX >> 1 and length(w) * 2 > needed:
            needed = length(w) * 2
        put(w, S_NEED, needed)
        return 0
    put(w, S_REG_N, current)
    at = reg(w, current)
    fill_range(w, at, 96, 0)
    put(w, at, get(w, S_NAME_AT))
    put(w, at + 8, get(w, S_NAME_N))
    put(w, at + 80, 1)
    put(w, at + 88, parent)
    if parent == 0:
        put(w, S_TREE, current)
    else:
        put(w, reg(w, parent) + choose(direction == 1, 64, 72), current)
        rebalance(w, parent)
    return current

def expected_order(s:readbuf, r:readbuf, w:mutbuf, index:u64, at:u64, size:u64) -> u64:
    node_at = reg(w, index)
    other = get(w, node_at + 8)
    count = choose(size < other, size, other)
    i = 0
    while i < count:
        a = byte(r, at + i)
        b = byte(s, get(w, node_at) + i)
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

def expected_find(s:readbuf, r:readbuf, w:mutbuf, at:u64, size:u64) -> u64:
    current = get(w, S_TREE)
    while current != 0:
        order = expected_order(s, r, w, current, at, size)
        if order == 0:
            return current
        current = get(w, reg(w, current) + choose(order == 1, 64, 72))
    return 0

def import_equal(s:readbuf, w:mutbuf, node:u64, index:u64) -> u64:
    at = reg(w, node)
    literal = INDEX + (L_IMPORT_0 + index) * 16
    count = get(w, literal + 8)
    if count != get(w, at + 8):
        return 0
    i = 0
    while i < count:
        if byte(s, get(w, at) + i) != byte(w, get(w, literal) + i):
            return 0
        i = i + 1
    return 1

def closed_abi(s:readbuf, r:readbuf, w:mutbuf) -> u64:
    i = 0
    while i < get(w, S_EXPECTED_N):
        row = get(w, S_EXPECTED_ROWS) + i * 16
        found = expected_find(s, r, w, word(r, row), word(r, row + 8))
        if found == 0:
            put(w, S_POLICY_BAD, 1)
        else:
            at = reg(w, found)
            if get(w, at + 16) & 1 == 0:
                put(w, S_POLICY_BAD, 1)
            elif get(w, at + 16) & 4 == 0:
                put(w, at + 16, get(w, at + 16) | 4)
                put(w, S_MATCHED_N, get(w, S_MATCHED_N) + 1)
        i = i + 1
    if get(w, S_POLICY_BAD) != 0 or get(w, S_MATCHED_N) != get(w, S_DEFINED_N):
        return semantic(w, 17)
    current = first_name(w)
    while current != 0:
        if get(w, reg(w, current) + 16) & 2 != 0:
            admitted = 0
            i = 0
            while i < 7:
                if import_equal(s, w, current, i) != 0:
                    admitted = 1
                i = i + 1
            if admitted == 0:
                return semantic(w, 17)
        current = next_name(w, current)
    return 1

def output_byte(w:mutbuf, value:u64) -> u64:
    at = get(w, S_POS)
    if get(w, S_WRITE) != 0:
        store(w, get(w, S_OUT) + at, value)
    put(w, S_POS, at + 1)
    return 0

def output_literal(w:mutbuf, index:u64) -> u64:
    at = get(w, INDEX + index * 16)
    count = get(w, INDEX + index * 16 + 8)
    i = 0
    while i < count:
        output_byte(w, byte(w, at + i))
        i = i + 1
    return 0

def output_name(s:readbuf, w:mutbuf, node:u64) -> u64:
    at = reg(w, node)
    start = get(w, at)
    size = get(w, at + 8)
    output_byte(w, 34)
    i = 0
    while i < size:
        value = byte(s, start + i)
        if value == 34 or value == 92:
            output_byte(w, 92)
            output_byte(w, value)
        elif value == 8 or value == 9 or value == 10 or value == 12 or value == 13:
            output_byte(w, 92)
            escaped = 98
            if value == 9:
                escaped = 116
            elif value == 10:
                escaped = 110
            elif value == 12:
                escaped = 102
            elif value == 13:
                escaped = 114
            output_byte(w, escaped)
        elif value < 32:
            output_byte(w, 92)
            output_byte(w, 117)
            output_byte(w, 48)
            output_byte(w, 48)
            high = value >> 4
            low = value & 15
            output_byte(w, choose(high < 10, high + 48, high + 87))
            output_byte(w, choose(low < 10, low + 48, low + 87))
        else:
            output_byte(w, value)
        i = i + 1
    output_byte(w, 34)
    return 0

def output_list(s:readbuf, w:mutbuf, bit:u64) -> u64:
    current = first_name(w)
    seen = 0
    while current != 0:
        if get(w, reg(w, current) + 16) & bit != 0:
            if seen != 0:
                output_byte(w, 44)
            output_name(s, w, current)
            seen = seen + 1
        current = next_name(w, current)
    return seen

def output_json(s:readbuf, w:mutbuf) -> u64:
    put(w, S_POS, 0)
    output_literal(w, L_DEFINED)
    if output_list(s, w, 1) != get(w, S_DEFINED_N):
        return abi(w, 9)
    output_literal(w, L_UNDEFINED)
    if output_list(s, w, 2) != get(w, S_UNDEFINED_N):
        return abi(w, 10)
    output_literal(w, L_END)
    return 1

def publish(s:readbuf, w:mutbuf) -> u64:
    put(w, S_WRITE, 0)
    if output_json(s, w) == 0:
        return 0
    count = get(w, S_POS)
    begin = BASE + get(w, S_REG_N) * 96
    if count > MAX - begin:
        return abi(w, 11)
    put(w, S_NEED, begin + count)
    if get(w, S_NEED) > length(w):
        return 0
    put(w, S_OUT, begin)
    put(w, S_WRITE, 1)
    if output_json(s, w) == 0:
        return 0
    if get(w, S_POS) != count:
        return abi(w, 12)
    put(w, S_RESULT_AT, begin)
    put(w, S_RESULT_N, count)
    put(w, S_PHASE, 5)
    return 1
'''

def source(elf_owner):
 constants=dict(CONSTANTS)
 # Author-time exact constant only; no FloorDiv reaches the HIA Builder.
 constants["MAX_REGISTRY_N"]=((1<<64)-1-constants["BASE"])//96
 body=BODY.replace("(MAX - BASE) // 96","MAX_REGISTRY_N")
 helpers={n.name:n for n in ast.parse(elf_owner.BODY).body}
 assert set(AVL_NAMES)<=set(helpers)
 raw=bytearray(constants["DATA"])
 for index,(name,text) in enumerate(LITERALS.items()):
  data=text.encode("ascii");at=len(raw);raw.extend(data)
  constants["L_"+name]=index
  pos=constants["INDEX"]+index*16
  raw[pos:pos+8]=at.to_bytes(8,"little");raw[pos+8:pos+16]=len(data).to_bytes(8,"little")
 assert constants["INDEX"]+16*len(LITERALS)<=constants["DATA"]
 assert len(raw)<constants["MIN_WORK"]
 assert max(constants["S_"+n]+8 for n in FIELDS)<=constants["INDEX"]
 writes=[(at,int.from_bytes(raw[at:at+8].ljust(8,b"\0"),"little"))
         for at in range(constants["INDEX"],len(raw),8) if any(raw[at:at+8])]
 chunks=[];calls=[]
 for start in range(0,len(writes),16):
  name="literal_"+str(start//16);calls.append("    "+name+"(w)")
  lines=["def "+name+"(w:mutbuf) -> u64:"]
  lines+=["    put(w, %d, %d)"%row for row in writes[start:start+16]]
  lines.append("    return 0");chunks.append("\n".join(lines))
 body+="\n"+"\n".join(ast.unparse(helpers[n]) for n in AVL_NAMES)+"\n"+"\n".join(chunks)
 body+="\ndef literal_table(w:mutbuf) -> u64:\n"+"\n".join(calls)+"\n    return 0\n"
 nodes=ast.parse(body).body
 for node in nodes:
  if node.name in("word","get"):
   arg="s" if node.name=="word" else "w"
   node.body=ast.parse("return "+" | ".join("(byte(%s, at + %d) << %d)"%(arg,i,i*8) for i in range(8))).body
  elif node.name=="put":
   node.body=ast.parse("\n".join("store(w, at + %d, (value >> %d) & 255)"%(i,i*8) for i in range(8))+"\nreturn 0").body
 return "\n".join(ast.unparse(ast.fix_missing_locations(n)) for n in nodes)+"\n",constants,dict(
  status="NEW_SOURCE_ONLY",scope="ELF64_62_OBJECT_SYMBOLS_AND_DIRECT_BACKEND_INVENTORY",
  original_structure_sha256=STRUCTURE_SHA,original_symbols_sha256=SYMBOLS_SHA,
  original_backend_sha256=BACKEND_SHA,AVL_helper_owner_sha256=ELF_AVL_OWNER_SHA,
  complete_original_ELF_symbol_error_order=True,all_header_and_section_skips_preserved=True,
  no_new_ELF_symbol_or_byte_quota=True,not_CO_FF_or_MachO=True,not_shared_inspection=True,
  actual_object_and_expected_export_issuer_required=True,header_is_authentication=False,
  pure_recompute_same_immutable_inputs_on_GROW=True,
  host_instruction_symbol_or_ELF_generation=False,full_public_backend=False)
