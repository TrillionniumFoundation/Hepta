"""Native post-Emitter command issuer from actual inventory and original Graph.

The caller mechanically concatenates the full frozen inventory and normalized
foreign rows. Only HIA selects function names and constructs HIABPC01 fields.
The complete admitted Graph and all producer views must remain privately issued
and immutable; numeric identities are bindings, not external authentication.
"""
import ast
def magic(s):return int.from_bytes(s.encode("ascii"),"little")
COMMON_SHA="fe63327671ea51ca950b955512a0f574d706176a4a8d050e3f8f12c83ef5e3a1"
PREPARE_SHA="da2a957ed48c1fce78c7b931b6b6e3833522271d0fe0578b248e367820ebfb3f"
POST_SHA="955ede388d85f85e4651637ad9b3051e607d2eeef55548ea5b7dc2d721f01e45"
CONSTANTS=dict(MAX=(1<<64)-1,BAD=0xfffffffd,GROW=0xfffffffe,MIN_WORK=8192,
 QUERY=magic("HIABCQ01"),COMMAND=magic("HIABPC01"),EVENT=magic("HIABQE01"),
 GRAPH=magic("HIAGRF01"),INVENTORY=magic("HIAEMP01"),BASE=8192)
FIELDS=("BAD","NEED","LEASE","REQUEST","FUNCTIONS","GLOBALS","FOREIGN",
 "INVENTORY_AT","INVENTORY_N","NODES","DATA","POOL","NAME_N","PHASE","RESULT_N")
CONSTANTS.update({"Q_"+name:256+i*8 for i,name in enumerate(FIELDS)})
BODY=r'''
def backend_command(s:readbuf,r:readbuf,w:mutbuf)->u32:
    if length(w) < MIN_WORK:
        return BAD
    fill_range(w,0,MIN_WORK,0)
    put(w,Q_NEED,MIN_WORK)
    if command_header(s,r,w) != 0:
        if command_names(s,r,w) != 0:
            command_write(s,r,w)
    if get(w,Q_BAD) != 0:
        command_event(w,3)
        return BAD
    if get(w,Q_NEED) > length(w):
        command_event(w,1)
        return GROW
    command_event(w,0)
    return 128

def command_bad(w:mutbuf,reason:u64)->u64:
    if get(w,Q_BAD) == 0:
        put(w,Q_BAD,reason)
    return 0

def command_header(s:readbuf,r:readbuf,w:mutbuf)->u64:
    if length(s) < 64 or length(r) < 512 or word(r,0) != QUERY or word(r,8) != 1 or word(r,16) != 0:
        return command_bad(w,1)
    if word(r,24) == 0 or word(r,32) == 0 or word(r,40) == 0 or word(r,48) == 0:
        return command_bad(w,2)
    if word(r,56) == 0 or word(r,88) == 0 or word(r,96) == 0 or word(r,160) > 1:
        return command_bad(w,3)
    functions = word(r,104)
    globals = word(r,112)
    foreign = word(r,120)
    if functions == 0 or functions > 1024 or globals == 0 or globals > 128 or foreign > globals:
        return command_bad(w,4)
    inventory = 512+foreign*32
    inventory_n = 256+functions*56
    if word(r,128) != 512 or word(r,136) != foreign*32 or word(r,168) != inventory:
        return command_bad(w,5)
    if word(r,176) != inventory_n or word(r,184) != length(r) or length(r) != inventory+inventory_n:
        return command_bad(w,6)
    if word(s,0) != GRAPH or word(s,8) != word(r,48) or word(s,24) != word(r,56) or word(s,48) != length(s) or word(s,56) != 0:
        return command_bad(w,7)
    nodes = word(s,16)
    edges = word(s,32)
    if nodes == 0 or nodes > (MAX-64) >> 6 or word(r,56) > nodes:
        return command_bad(w,8)
    edgebase = 64+nodes*64
    if edges > (MAX-edgebase) >> 3:
        return command_bad(w,9)
    data = edgebase+edges*8
    if data > length(s) or word(s,40) != length(s)-data:
        return command_bad(w,10)
    at = inventory
    if word(r,at) != INVENTORY or word(r,at+8) != 1 or word(r,at+16) != word(r,48) or word(r,at+24) != word(r,32):
        return command_bad(w,11)
    if word(r,at+56) != functions or word(r,at+64) != 8448 or word(r,at+72) != 8448+functions*48:
        return command_bad(w,12)
    if word(r,at+88) != 8192+inventory_n or word(r,at+96) != length(s) or word(r,at+104) != word(r,56):
        return command_bad(w,13)
    i = 112
    while i < 256:
        if word(r,at+i) != 0:
            return command_bad(w,14)
        i = i+8
    i = 416
    while i < 512:
        if word(r,i) != 0:
            return command_bad(w,15)
        i = i+8
    put(w,Q_LEASE,word(r,24))
    put(w,Q_REQUEST,word(r,32))
    put(w,Q_FUNCTIONS,functions)
    put(w,Q_GLOBALS,globals)
    put(w,Q_FOREIGN,foreign)
    put(w,Q_INVENTORY_AT,inventory)
    put(w,Q_INVENTORY_N,inventory_n)
    put(w,Q_NODES,nodes)
    put(w,Q_DATA,data)
    put(w,Q_PHASE,1)
    return 1

def command_names(s:readbuf,r:readbuf,w:mutbuf)->u64:
    i = 0
    count = get(w,Q_FUNCTIONS)
    names = 0
    while i < count:
        row = get(w,Q_INVENTORY_AT)+256+i*48
        fn = word(r,row)
        name = word(r,row+8)
        if fn == 0 or fn > get(w,Q_NODES) or name == 0 or name > get(w,Q_NODES):
            return command_bad(w,16)
        if word(s,64+(fn-1)*64) != 6:
            return command_bad(w,17)
        at = 64+(name-1)*64
        offset = word(s,at+8)
        size = word(s,at+16)
        if word(s,at) != 4 or offset < get(w,Q_DATA) or offset > length(s) or size > length(s)-offset:
            return command_bad(w,18)
        if size == 0 or size > 128 or word(s,at+24) != 0 or word(s,at+32) != 0:
            return command_bad(w,19)
        if word(s,at+40) != 0 or word(s,at+48) != size or word(s,at+56) != 0:
            return command_bad(w,20)
        if word(r,row+16) != offset or word(r,row+24) != size or word(r,row+32) != 0 or word(r,row+40) != 0:
            return command_bad(w,21)
        names = names+size
        i = i+1
    pool = 512+get(w,Q_FOREIGN)*32+count*16
    put(w,Q_POOL,pool)
    put(w,Q_NAME_N,names)
    put(w,Q_RESULT_N,pool+names)
    put(w,Q_NEED,BASE+pool+names)
    put(w,Q_PHASE,2)
    return 1

def command_write(s:readbuf,r:readbuf,w:mutbuf)->u64:
    if get(w,Q_NEED) > length(w):
        return 0
    copy_bytes(w,r,BASE,0,512+get(w,Q_FOREIGN)*32)
    put(w,BASE,COMMAND)
    put(w,BASE+168,512+get(w,Q_FOREIGN)*32)
    put(w,BASE+176,get(w,Q_POOL))
    put(w,BASE+184,get(w,Q_RESULT_N))
    cursor = get(w,Q_POOL)
    i = 0
    while i < get(w,Q_FUNCTIONS):
        row = get(w,Q_INVENTORY_AT)+256+i*48
        size = word(r,row+24)
        target = BASE+512+get(w,Q_FOREIGN)*32+i*16
        put(w,target,cursor)
        put(w,target+8,size)
        copy_bytes(w,s,BASE+cursor,word(r,row+16),size)
        cursor = cursor+size
        i = i+1
    if cursor != get(w,Q_RESULT_N):
        return command_bad(w,22)
    put(w,Q_PHASE,3)
    return 1

def command_event(w:mutbuf,action:u64)->u64:
    put(w,0,EVENT)
    put(w,8,1)
    put(w,16,action)
    put(w,24,get(w,Q_LEASE))
    put(w,32,get(w,Q_REQUEST))
    put(w,40,0)
    put(w,48,0)
    put(w,56,get(w,Q_NEED))
    put(w,64,choose(action == 0,BASE,0))
    put(w,72,choose(action == 0,get(w,Q_RESULT_N),0))
    put(w,80,get(w,Q_FUNCTIONS))
    put(w,88,get(w,Q_GLOBALS))
    put(w,96,get(w,Q_FOREIGN))
    put(w,104,0)
    put(w,112,get(w,Q_PHASE))
    put(w,120,get(w,Q_BAD))
    return 0
'''
def source(common):
 shared={n.name:n for n in ast.parse(common.COMMON).body}
 nodes=ast.parse(BODY).body+[shared[name] for name in ("word","get","put")]
 for n in nodes:
  if n.name in ("word","get"):
   arg="s" if n.name=="word" else "w"
   n.body=ast.parse("return "+" | ".join("(byte(%s,at+%d)<<%d)"%(arg,i,i*8) for i in range(8))).body
  elif n.name=="put":
   n.body=ast.parse("\n".join("store(w,at+%d,(value>>%d)&255)"%(i,i*8) for i in range(8))+"\nreturn 0").body
 return "\n".join(ast.unparse(ast.fix_missing_locations(n)) for n in nodes)+"\n",dict(CONSTANTS),dict(
  status="NEW_UNEXECUTED",scope="ACTUAL_NATIVE_POST_EMITTER_COMMAND_ISSUER",
  complete_actual_inventory_required=True,complete_native_normalized_rows_required=True,
  same_privately_issued_admitted_Graph_required=True,host_selects_names=False,
  function_names_follow_actual_Core_indices=True,headers_are_not_authentication=True,
  source_sha256=PREPARE_SHA,post_owner_sha256=POST_SHA,
  public_emit_program_machine=False,compile_program_machine=False,installed=False)
