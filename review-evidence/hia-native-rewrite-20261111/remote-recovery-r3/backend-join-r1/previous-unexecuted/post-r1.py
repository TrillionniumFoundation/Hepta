"""Native post-Emitter expected-export issuer and complete machine metadata.

This pure HIA owner consumes the actual completed Emitter registry and the
actual normalized foreign rows retained by its HIA parent. Mode 0 issues the
full independent inspector command. Mode 1 serializes all non-byte fields of
the original HIAProgramMachine, plus actual text digest for later build use.
Neither mode admits Core or authenticates externally supplied private frames.
"""
import ast
def magic(s):return int.from_bytes(s.encode("ascii"),"little")
COMMON_SHA="fe63327671ea51ca950b955512a0f574d706176a4a8d050e3f8f12c83ef5e3a1"
BACKEND_SHA="bf953a8b85d1ebc6b9d7a90fbbcaa4137e40ed214c2ede2af1a13cfc01b1c07c"
INVENTORY_SHA="5b8807b7eaee30a04c12fe2d96a5c457abb0a6f2517804e6b001fbbfc32d16ce"
CONSTANTS=dict(MAX=(1<<64)-1,BAD=0xfffffffd,GROW=0xfffffffe,MIN_WORK=8192,
 COMMAND=magic("HIABPC01"),EVENT=magic("HIABPE01"),REGISTRY=magic("HIAEMR01"),
 INSPECTOR=magic("HIAMIC01"),BASE=8192,INDEX=2048,DATA=3072,SORT=4096,
 MAX_OBJECT=64<<20)
FIELDS=("BAD","ERROR","NEED","LEASE","REQUEST","MODE","FN_N","GLOBAL_N","FOREIGN_N",
 "RECORD_N","POOL","RESULT_AT","RESULT_N","PHASE","POS","WRITE")
CONSTANTS.update({"S_"+key:256+i*8 for i,key in enumerate(FIELDS)})
LITERALS={
 "ERR_OBJECT":"E_HIA_PROGRAM_LIMIT: object exceeds artifact byte budget",
 "ERR_STALE":"E_HIA_PROGRAM_STALE: verifier/emitter changed during generation",
 "CORE":"{\"core_sha256\":\"","EXPORTS":"\",\"exports\":[","FOREIGN":"],\"foreign_buffer_exports\":[",
 "FRAMES":"],\"function_frames\":[","IMPLEMENTATION":"],\"implementation_sha256\":\"",
 "INPUT":"\",\"input_sha256\":\"","TEXT":"\",\"machine_text_sha256\":\"",
 "PLAN":"\",\"machine_plan_sha256\":","PROFILE":",\"profile\":\"",
 "SCALAR":"hepta.hia.program.direct-linux-x86_64.v1",
 "BYTE":"hepta.hia.program.direct-linux-x86_64-borrowed-bytes.v1",
 "OBJECT":"\",\"sha256\":\"","TARGET":"\",\"target\":\"x86_64-unknown-linux-gnu\"}",
 "NULL":"null"}
BODY=r'''
def backend_post(s:readbuf,r:readbuf,w:mutbuf)->u32:
    if length(w) < MIN_WORK:
        return BAD
    fill_range(w,0,MIN_WORK,0)
    literal_table(w)
    put(w,S_NEED,MIN_WORK)
    if private_header(s,r,w) != 0:
        if object_budget(r,w) != 0:
            if registry_rows(s,r,w) != 0:
                sort_globals(s,w)
                if get(w,S_MODE) == 0:
                    expected_command(s,r,w)
                elif implementation_unchanged(r,w) != 0:
                    metadata(s,r,w)
    if get(w,S_BAD) != 0:
        post_event(w,3)
        return BAD
    if get(w,S_ERROR) != 0:
        post_event(w,2)
        return 128
    if get(w,S_NEED) > length(w):
        post_event(w,1)
        return GROW
    if get(w,S_RESULT_N) == 0:
        abi(w,40)
        post_event(w,3)
        return BAD
    post_event(w,0)
    return 128

def abi(w:mutbuf,reason:u64)->u64:
    if get(w,S_BAD) == 0:
        put(w,S_BAD,reason)
    return 0

def semantic(w:mutbuf,error:u64)->u64:
    put(w,S_ERROR,error)
    return 0

def private_header(s:readbuf,r:readbuf,w:mutbuf)->u64:
    if length(r) < 512 or length(s) < 256 or word(r,0) != COMMAND or word(r,8) != 1:
        return abi(w,1)
    mode = word(r,16)
    if mode > 1 or word(r,24) == 0 or word(r,32) == 0 or word(r,40) == 0 or word(r,48) == 0:
        return abi(w,2)
    if word(r,56) == 0 or word(r,64) != length(s) or word(r,88) == 0 or word(r,96) == 0:
        return abi(w,3)
    functions = word(r,104)
    globals = word(r,112)
    foreign = word(r,120)
    if functions == 0 or functions > 1024 or globals == 0 or globals > 128 or foreign > globals:
        return abi(w,4)
    if word(r,128) != 512 or word(r,136) != foreign*32 or length(r) != 512+foreign*32:
        return abi(w,5)
    plan = word(r,144)
    version = word(r,152)
    if plan > 1 or word(r,160) > 1:
        return abi(w,6)
    if (plan == 0 and version != 0) or (plan != 0 and (version == 0 or version > 4)):
        return abi(w,7)
    at = 168
    while at < 192:
        if word(r,at) != 0:
            return abi(w,8)
        at = at+8
    at = 416
    while at < 512:
        if word(r,at) != 0:
            return abi(w,9)
        at = at+8
    if plan == 0:
        at = 384
        while at < 416:
            if byte(r,at) != 0:
                return abi(w,10)
            at = at+1
    if word(s,0) != REGISTRY or word(s,8) != 1 or word(s,16) != word(r,40) or word(s,24) != word(r,32):
        return abi(w,11)
    if word(s,32) != word(r,48) or word(s,40) != word(r,56) or word(s,56) != word(r,88) or word(s,64) != word(r,96):
        return abi(w,12)
    if word(s,120) != functions or word(s,128) != globals or word(s,72) != functions+globals:
        return abi(w,13)
    count = functions+globals
    pool = 256+count*64
    if pool > length(s) or word(s,80) != 256 or word(s,88) != pool or word(s,96) != length(s):
        return abi(w,14)
    if word(s,104) > word(r,80) or word(r,80)-word(s,104) > 4:
        return abi(w,15)
    alignment = word(s,136)
    if alignment != 1 and alignment != 16 and alignment != 32 and alignment != 64:
        return abi(w,16)
    at = 144
    while at < 256:
        if word(s,at) != 0:
            return abi(w,17)
        at = at+8
    i = 0
    while i < foreign:
        at = 512+i*32
        if word(r,at) == 0 or word(r,at+8) >= functions or word(r,at+16) == 0 or word(r,at+16) > 1048576 or word(r,at+24) != 0:
            return abi(w,18)
        j = 0
        while j < i:
            if word(r,512+j*32+8) == word(r,at+8):
                return abi(w,19)
            j = j+1
        i = i+1
    put(w,S_LEASE,word(r,24))
    put(w,S_REQUEST,word(r,32))
    put(w,S_MODE,mode)
    put(w,S_FN_N,functions)
    put(w,S_GLOBAL_N,globals)
    put(w,S_FOREIGN_N,foreign)
    put(w,S_RECORD_N,count)
    put(w,S_POOL,pool)
    put(w,S_PHASE,1)
    return 1

def object_budget(r:readbuf,w:mutbuf)->u64:
    if word(r,72) > MAX_OBJECT:
        return semantic(w,1)
    return 1

def row_name_equal(s:readbuf,left:u64,right:u64)->u64:
    count = word(s,left+24)
    if count != word(s,right+24):
        return 0
    i = 0
    while i < count:
        if byte(s,word(s,left+16)+i) != byte(s,word(s,right+16)+i):
            return 0
        i = i+1
    return 1

def registry_rows(s:readbuf,r:readbuf,w:mutbuf)->u64:
    functions = get(w,S_FN_N)
    globals = get(w,S_GLOBAL_N)
    count = get(w,S_RECORD_N)
    cursor = get(w,S_POOL)
    borrowed = 0
    i = 0
    while i < count:
        at = 256+i*64
        index = word(s,at)
        kind = word(s,at+8)
        name_at = word(s,at+16)
        name_n = word(s,at+24)
        begin = word(s,at+32)
        end = word(s,at+40)
        frame = word(s,at+48)
        if index >= functions or name_at != cursor or name_n == 0 or name_n > 128 or name_n > length(s)-cursor or word(s,at+56) != 0:
            return abi(w,20)
        if begin > end or end > word(r,80):
            return abi(w,21)
        if frame > 65536 or frame & 15 != 0:
            return abi(w,22)
        if i < functions:
            if kind != 0 or frame == 0:
                return abi(w,23)
            j = 0
            while j < i:
                if word(s,256+j*64) == index:
                    return abi(w,24)
                j = j+1
        else:
            if kind == 0 or kind > 2:
                return abi(w,25)
            j = functions
            while j < i:
                if row_name_equal(s,at,256+j*64) != 0:
                    return abi(w,26)
                j = j+1
            if kind == 2:
                found = 0
                j = 0
                while j < get(w,S_FOREIGN_N):
                    if word(r,520+j*32) == index:
                        found = found+1
                    j = j+1
                if found != 1:
                    return abi(w,27)
                borrowed = borrowed+1
            put(w,SORT+(i-functions)*8,i)
        cursor = cursor+name_n
        i = i+1
    if borrowed != get(w,S_FOREIGN_N) or cursor != length(s):
        return abi(w,28)
    put(w,S_PHASE,2)
    return 1

def row_less(s:readbuf,left:u64,right:u64)->u64:
    a = 256+left*64
    b = 256+right*64
    an = word(s,a+24)
    bn = word(s,b+24)
    i = 0
    while i < an and i < bn:
        x = byte(s,word(s,a+16)+i)
        y = byte(s,word(s,b+16)+i)
        if x < y:
            return 1
        if x > y:
            return 0
        i = i+1
    return choose(an < bn,1,0)

def sort_globals(s:readbuf,w:mutbuf)->u64:
    i = 1
    while i < get(w,S_GLOBAL_N):
        j = i
        while j > 0:
            left = get(w,SORT+(j-1)*8)
            right = get(w,SORT+j*8)
            if row_less(s,right,left) == 0:
                j = 0
            else:
                put(w,SORT+(j-1)*8,right)
                put(w,SORT+j*8,left)
                j = j-1
        i = i+1
    return 0

def expected_command(s:readbuf,r:readbuf,w:mutbuf)->u64:
    count = get(w,S_GLOBAL_N)
    data = 128+count*16
    total = data
    i = 0
    while i < count:
        row = 256+get(w,SORT+i*8)*64
        total = total+word(s,row+24)
        i = i+1
    put(w,S_NEED,BASE+total)
    put(w,S_PHASE,3)
    if BASE+total > length(w):
        return 0
    fill_range(w,BASE,total,0)
    put(w,BASE,INSPECTOR)
    put(w,BASE+8,1)
    put(w,BASE+16,get(w,S_LEASE))
    put(w,BASE+24,get(w,S_REQUEST))
    put(w,BASE+32,word(r,40))
    put(w,BASE+40,word(r,72))
    put(w,BASE+48,count)
    put(w,BASE+56,128)
    put(w,BASE+64,data)
    put(w,BASE+72,total-data)
    put(w,BASE+80,total)
    cursor = data
    i = 0
    while i < count:
        row = 256+get(w,SORT+i*8)*64
        name_at = word(s,row+16)
        name_n = word(s,row+24)
        put(w,BASE+128+i*16,cursor)
        put(w,BASE+136+i*16,name_n)
        copy_bytes(w,s,BASE+cursor,name_at,name_n)
        cursor = cursor+name_n
        i = i+1
    if cursor != total:
        return abi(w,29)
    put(w,S_RESULT_AT,BASE)
    put(w,S_RESULT_N,total)
    put(w,S_PHASE,4)
    return 1

def implementation_unchanged(r:readbuf,w:mutbuf)->u64:
    i = 0
    while i < 32:
        if byte(r,256+i) != byte(r,288+i):
            return semantic(w,2)
        i = i+1
    return 1

def output_byte(w:mutbuf,value:u64)->u64:
    at = get(w,S_POS)
    if at == MAX:
        return abi(w,30)
    if get(w,S_WRITE) != 0:
        store(w,BASE+at,value)
    put(w,S_POS,at+1)
    return 1

def output_literal(w:mutbuf,index:u64)->u64:
    at = get(w,INDEX+index*16)
    count = get(w,INDEX+index*16+8)
    i = 0
    while i < count:
        output_byte(w,byte(w,at+i))
        i = i+1
    return 1

def output_decimal(w:mutbuf,value:u64)->u64:
    divisor = 10000000000000000000
    started = 0
    while divisor != 0:
        digit = 0
        while value >= divisor:
            value = value-divisor
            digit = digit+1
        if digit != 0 or started != 0 or divisor == 1:
            output_byte(w,48+digit)
            started = 1
        # Exact unsigned division by ten through a bounded binary divider.
        divisor = div10(divisor)
    return 1

def div10(value:u64)->u64:
    result = 0
    remainder = 0
    bit = 64
    while bit != 0:
        bit = bit-1
        remainder = (remainder << 1) | ((value >> bit) & 1)
        result = result << 1
        if remainder >= 10:
            remainder = remainder-10
            result = result | 1
    return result

def output_name(s:readbuf,w:mutbuf,row:u64)->u64:
    at = word(s,row+16)
    count = word(s,row+24)
    output_byte(w,34)
    i = 0
    while i < count:
        c = byte(s,at+i)
        if c == 34 or c == 92:
            output_byte(w,92)
            output_byte(w,c)
        elif c < 32:
            output_byte(w,92)
            output_byte(w,117)
            output_byte(w,48)
            output_byte(w,48)
            high = c >> 4
            low = c & 15
            output_byte(w,choose(high < 10,high+48,high+87))
            output_byte(w,choose(low < 10,low+48,low+87))
        else:
            output_byte(w,c)
        i = i+1
    output_byte(w,34)
    return 1

def output_hash(r:readbuf,w:mutbuf,at:u64)->u64:
    i = 0
    while i < 32:
        value = byte(r,at+i)
        high = value >> 4
        low = value & 15
        output_byte(w,choose(high < 10,high+48,high+87))
        output_byte(w,choose(low < 10,low+48,low+87))
        i = i+1
    return 1

def export_names(s:readbuf,w:mutbuf)->u64:
    i = 0
    while i < get(w,S_GLOBAL_N):
        if i != 0:
            output_byte(w,44)
        output_name(s,w,256+get(w,SORT+i*8)*64)
        i = i+1
    return 1

def foreign_names(s:readbuf,r:readbuf,w:mutbuf)->u64:
    i = 0
    seen = 0
    while i < get(w,S_GLOBAL_N):
        row = 256+get(w,SORT+i*8)*64
        if word(s,row+8) == 2:
            extent = 0
            j = 0
            while j < get(w,S_FOREIGN_N):
                if word(r,520+j*32) == word(s,row):
                    extent = word(r,528+j*32)
                j = j+1
            if seen != 0:
                output_byte(w,44)
            output_byte(w,91)
            output_name(s,w,row)
            output_byte(w,44)
            output_decimal(w,extent)
            output_byte(w,93)
            seen = seen+1
        i = i+1
    return 1

def function_frames(s:readbuf,w:mutbuf)->u64:
    i = 0
    while i < get(w,S_FN_N):
        if i != 0:
            output_byte(w,44)
        output_byte(w,91)
        output_name(s,w,256+i*64)
        output_byte(w,44)
        output_decimal(w,word(s,256+i*64+48))
        output_byte(w,93)
        i = i+1
    return 1

def emit_metadata(s:readbuf,r:readbuf,w:mutbuf)->u64:
    put(w,S_POS,0)
    output_literal(w,L_CORE)
    output_hash(r,w,192)
    output_literal(w,L_EXPORTS)
    export_names(s,w)
    output_literal(w,L_FOREIGN)
    foreign_names(s,r,w)
    output_literal(w,L_FRAMES)
    function_frames(s,w)
    output_literal(w,L_IMPLEMENTATION)
    output_hash(r,w,256)
    output_literal(w,L_INPUT)
    output_hash(r,w,224)
    output_literal(w,L_TEXT)
    output_hash(r,w,352)
    output_literal(w,L_PLAN)
    if word(r,144) == 0:
        output_literal(w,L_NULL)
    else:
        output_byte(w,34)
        output_hash(r,w,384)
        output_byte(w,34)
    output_literal(w,L_PROFILE)
    output_literal(w,choose(get(w,S_FOREIGN_N) == 0,L_SCALAR,L_BYTE))
    output_literal(w,L_OBJECT)
    output_hash(r,w,320)
    output_literal(w,L_TARGET)
    return 1

def metadata(s:readbuf,r:readbuf,w:mutbuf)->u64:
    put(w,S_PHASE,5)
    put(w,S_WRITE,0)
    emit_metadata(s,r,w)
    count = get(w,S_POS)
    if count > MAX-BASE:
        return abi(w,31)
    put(w,S_NEED,BASE+count)
    if BASE+count > length(w):
        return 0
    put(w,S_WRITE,1)
    emit_metadata(s,r,w)
    if get(w,S_POS) != count:
        return abi(w,32)
    put(w,S_RESULT_AT,BASE)
    put(w,S_RESULT_N,count)
    put(w,S_PHASE,6)
    return 1

def post_event(w:mutbuf,action:u64)->u64:
    at = get(w,S_RESULT_AT)
    size = get(w,S_RESULT_N)
    if action == 2:
        index = choose(get(w,S_ERROR) == 1,L_ERR_OBJECT,L_ERR_STALE)
        at = get(w,INDEX+index*16)
        size = get(w,INDEX+index*16+8)
    elif action != 0:
        at = 0
        size = 0
    put(w,0,EVENT)
    put(w,8,1)
    put(w,16,action)
    put(w,24,get(w,S_LEASE))
    put(w,32,get(w,S_REQUEST))
    put(w,40,get(w,S_MODE))
    put(w,48,get(w,S_ERROR))
    put(w,56,get(w,S_NEED))
    put(w,64,at)
    put(w,72,size)
    put(w,80,get(w,S_FN_N))
    put(w,88,get(w,S_GLOBAL_N))
    put(w,96,get(w,S_FOREIGN_N))
    put(w,104,0)
    put(w,112,get(w,S_PHASE))
    put(w,120,get(w,S_BAD))
    return 0
'''
def source(common):
 constants=dict(CONSTANTS)
 raw=bytearray(constants["DATA"]);helpers=[];calls=[]
 for i,(name,value) in enumerate(LITERALS.items()):
  constants["L_"+name]=i
  encoded=value.encode("ascii");at=len(raw);raw.extend(encoded)
  row=constants["INDEX"]+i*16
  raw[row:row+8]=at.to_bytes(8,"little");raw[row+8:row+16]=len(encoded).to_bytes(8,"little")
 assert constants["INDEX"]+len(LITERALS)*16<=constants["DATA"]
 assert len(raw)<constants["SORT"]
 writes=[(at,int.from_bytes(raw[at:at+8].ljust(8,b"\0"),"little"))
         for at in range(constants["INDEX"],len(raw),8) if any(raw[at:at+8])]
 for at in range(0,len(writes),16):
  name="literal_"+str(at//16);calls.append("    "+name+"(w)")
  helpers.append("def "+name+"(w:mutbuf)->u64:\n"+"\n".join(
   "    put(w,%d,%d)"%item for item in writes[at:at+16])+"\n    return 0")
 helpers.append("def literal_table(w:mutbuf)->u64:\n"+"\n".join(calls)+"\n    return 0")
 shared={n.name:n for n in ast.parse(common.COMMON).body}
 body=BODY+"\n"+"\n".join(helpers)+"\""
 # The additional quote above is removed explicitly below; no generated code
 # may be inferred from an AST until the independent builder parses it.
 body=body[:-1]
 nodes=ast.parse(body).body+[shared[name] for name in ("word","get","put")]
 for n in nodes:
  if n.name in ("word","get"):
   arg="s" if n.name=="word" else "w"
   n.body=ast.parse("return "+" | ".join("(byte(%s,at+%d)<<%d)"%(arg,i,i*8) for i in range(8))).body
  elif n.name=="put":
   n.body=ast.parse("\n".join("store(w,at+%d,(value>>%d)&255)"%(i,i*8) for i in range(8))+"\nreturn 0").body
 return "\n".join(ast.unparse(ast.fix_missing_locations(n)) for n in nodes)+"\n",constants,dict(
  status="NEW_UNEXECUTED",scope="ACTUAL_EMITTER_EXPORT_ISSUER_AND_COMPLETE_MACHINE_METADATA",
  actual_native_sha_required=True,complete_actual_registry_and_normalized_rows_required=True,
  immutable_Core_and_implementation_authority_remain_upstream=True,headers_are_not_authentication=True,
  original_exports_sorted_and_function_frames_in_emission_order=True,
  two_phase_measure_fill=True,object_inspection_required_between_modes=True,
  public_emit_program_machine=False,compile_program_machine=False,installed=False)
