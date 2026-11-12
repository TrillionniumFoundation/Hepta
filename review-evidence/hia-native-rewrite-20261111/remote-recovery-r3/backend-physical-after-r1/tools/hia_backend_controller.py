"""HIA-owned checked-plan, full Emitter, inspector and digest join.

This new component starts from an actually admitted immutable Core Graph plus
the exact raw plan and borrowed-export captures. The upstream Core re-admission,
source-file authority and public Python-object boundary are explicit, separate
obligations. All successful machine bytes, plan checks, symbol inspection,
digests, names, frames and result fields below are produced by actual HIA.
"""
import ast,copy
def magic(value):return int.from_bytes(value.encode("ascii"),"little")
COMMON_SHA="fe63327671ea51ca950b955512a0f574d706176a4a8d050e3f8f12c83ef5e3a1"
FORWARDER_SHA="d089e80fc78c8c3e2d2234aea587c38bbd5caa757178bf1f93845b15c2fe474c"
POST_SHA="955ede388d85f85e4651637ad9b3051e607d2eeef55548ea5b7dc2d721f01e45"
ISSUER_SHA="97fb41eb1d4215b081a341b91b26502182ed4592871ccc79ec70b8137af1d17a"
CONSTANTS=dict(MAX=(1<<64)-1,BAD=0xfffffffd,GROW=0xfffffffe,MIN_WORK=1<<20,
 DRIVER=20,LOWER_MAGIC=magic("HIABBS01"),INIT=magic("HIABBI01"),
 GRAPH=magic("HIAGRF01"),EMITTER_INIT=magic("HIAEMB01"),PLAN_INIT=magic("HIAMPB01"),
 PREP_COMMAND=magic("HIAEMC01"),PREP_EVENT=magic("HIAEME01"),NORM=magic("HIAEMN01"),
 PLAN_RESULT=magic("HIAMPD01"),EMITTER_RESULT=magic("HIAMER01"),
 INVENTORY=magic("HIAEMP01"),REGISTRY=magic("HIAEMR01"),
 POST_QUERY=magic("HIABCQ01"),POST_COMMAND=magic("HIABPC01"),
 POST_QUERY_EVENT=magic("HIABQE01"),POST_EVENT=magic("HIABPE01"),
 INSPECT_EVENT=magic("HIAMIE01"),RESULT=magic("HIABMR01"),
 B_COMMAND=4,B_PREP=6,B_NORM=10,B_PLAN=11,B_POST_COMMAND=12,B_POST=13,
 B_INSPECT_COMMAND=14,B_INSPECT=15,B_HASH_INPUT=16,B_HASH_OUT=17,B_HASH_WORK=18,
 B_META=19,B_RESULT=35,B_ERROR=36,B_CAPSULE=37,B_ISSUE=38,
 I_PREPARE=1,I_INSPECT=17,I_POST=18,I_HASH=19,I_ISSUE=21,
 HASHES=25000,SAVED_EMITTER=25400,SAVED_INVENTORY=25656,
 H_CORE=25000,H_INPUT=25032,H_IMPL_BEFORE=25064,H_IMPL_AFTER=25096,
 H_OBJECT=25128,H_TEXT=25160,H_PLAN=25192,INPUT_HEADER=320,HASH_CHUNK=1048576)
_FIELDS=("REQUEST","GRAPH_LEASE","CODE_LEASE","PLAN_LEASE","EMITTER_LEASE",
 "ROOT","GRAPH_N","STRUCTURED","DIGITS","CORE","PLAN","FOREIGN","NODES",
 "FOREIGN_N","NORM_N","NORM_GRAPH","HAS_PLAN","PLAN_N","PLAN_VERSION",
 "FN_N","GLOBAL_N","CODE_SEQ","REG_N","TEXT_AT","TEXT_N","OBJECT_AT","OBJECT_N",
 "INV_N","POST_N","CAPSULE_N","META_N","ERROR_DOMAIN","ERROR_ID","ERROR_N",
 "CALL_ROLE","CALL_FIRST","CALL_AT","CALL_N","CALL_SECOND","CALL_SECOND_N",
 "CALL_WORK","CALL_MIN","CALL_REPLY","CALL_OBS_AT","CALL_OBS_N",
 "COPY_SOURCE","COPY_AT","COPY_N","COPY_TARGET","COPY_TO","COPY_NEED","COPY_RO","COPY_AFTER",
 "PURE_NEED","PURE_PHASE","POST_MODE","INSPECT_COMMAND_N","INSPECT_N",
 "HASH_SOURCE","HASH_AT","HASH_N","HASH_DONE","HASH_DEST","HASH_AFTER","HASH_TAKE",
 "STALE","CHILD_SERIAL","CHILD_CODE_N","CHILD_RECORDS","NORMALIZED_GRAPH_AT","INSPECT_AT")
CONSTANTS.update({"O_"+name:30000+8*i for i,name in enumerate(_FIELDS)})
assert 30000+8*len(_FIELDS)<32000
BODY=r'''
def backend_controller(s:readbuf,o:mutbuf,w:mutbuf)->u32:
    if length(w) < MIN_WORK or length(o) < 128:
        return BAD
    if get(w,L_MAGIC) == 0:
        if outer_begin(s,w) == 0:
            return refuse(w,3000)
    elif acknowledge(s,w,DRIVER) == 0:
        return refuse(w,3001)
    result = 0
    while result == 0:
        if get(w,L_STATUS) != 1:
            return refuse(w,3002)
        current = get(w,C_PHASE)
        if current >= 12000 and current < 12100:
            result = cb_step(o,w)
        elif current >= 13000 and current < 13100:
            result = hash_step(o,w)
        elif current >= 10000:
            result = outer_mechanics(o,w)
        else:
            result = outer_step(o,w)
    return result

def outer_begin(s:readbuf,w:mutbuf)->u64:
    if length(s) < INPUT_HEADER+64 or word(s,0) != INIT or word(s,8) != 1:
        return 0
    outer = word(s,16)
    code = word(s,40)
    planlease = word(s,48)
    emitterlease = word(s,56)
    if outer == 0 or code == 0 or planlease == 0 or emitterlease == 0 or word(s,24) == 0 or word(s,32) == 0:
        return 0
    if outer == planlease or outer == emitterlease or planlease == emitterlease:
        return 0
    root = word(s,64)
    size = word(s,72)
    if root == 0 or size != length(s)-INPUT_HEADER or word(s,80) > 1:
        return 0
    at = 96
    while at < 128:
        if word(s,at) != 0:
            return 0
        at = at+8
    at = 256
    while at < INPUT_HEADER:
        if word(s,at) != 0:
            return 0
        at = at+8
    graph = INPUT_HEADER
    if word(s,graph) != GRAPH or word(s,graph+8) != word(s,32) or word(s,graph+24) != root:
        return 0
    if word(s,graph+48) != size or word(s,graph+56) != 0:
        return 0
    nodes = word(s,graph+16)
    edges = word(s,graph+32)
    if nodes == 0 or nodes > (MAX-64) >> 6 or root > nodes:
        return 0
    edgebase = 64+nodes*64
    if edges > (MAX-edgebase) >> 3:
        return 0
    data = edgebase+edges*8
    if data > size or word(s,graph+40) != size-data:
        return 0
    row = graph+64+(root-1)*64
    if word(s,row) != 5 or word(s,row+8) != 0 or word(s,row+16) != 0 or word(s,row+32) != 3:
        return 0
    if word(s,row+40) == 0 or word(s,row+48) != 0 or word(s,row+56) != 0:
        return 0
    first = word(s,row+24)
    if first > edges or edges-first < 3:
        return 0
    at = graph+edgebase+first*8
    core = word(s,at)
    plan = word(s,at+8)
    foreign = word(s,at+16)
    if core == 0 or core > nodes or plan == 0 or plan > nodes or foreign == 0 or foreign > nodes:
        return 0
    if get(w,L_STATUS) != 0 or get(w,C_PENDING) != 0 or get(w,C_SEQUENCE) != 0:
        return 0
    fill_range(w,0,MIN_WORK,0)
    put(w,L_MAGIC,LOWER_MAGIC)
    put(w,L_STATUS,1)
    put(w,L_DRIVER,DRIVER)
    put(w,C_LEASE,outer)
    put(w,O_REQUEST,word(s,24))
    put(w,O_GRAPH_LEASE,word(s,32))
    put(w,O_CODE_LEASE,code)
    put(w,O_PLAN_LEASE,planlease)
    put(w,O_EMITTER_LEASE,emitterlease)
    put(w,O_ROOT,root)
    put(w,O_GRAPH_N,size)
    put(w,O_STRUCTURED,word(s,80))
    put(w,O_DIGITS,word(s,88))
    put(w,O_CORE,core)
    put(w,O_PLAN,plan)
    put(w,O_FOREIGN,foreign)
    put(w,O_NODES,nodes)
    put(w,O_HAS_PLAN,choose(word(s,graph+64+(plan-1)*64) == 0,0,1))
    copy_bytes(w,s,HASHES,128,128)
    put(w,CAPS+8,length(s))
    put(w,CAPS+16,length(w))
    put(w,CAPS+24,128)
    put(w,C_PHASE,10)
    return 1

def outer_phase(w:mutbuf,next:u64)->u64:
    put(w,C_PHASE,next)
    return 0

def outer_local_copy(w:mutbuf,target:u64,source:u64,count:u64)->u64:
    i = 0
    while i < count:
        store(w,target+i,byte(w,source+i))
        i = i+1
    return 0

def outer_copy(w:mutbuf,source:u64,at:u64,count:u64,target:u64,to:u64,need:u64,readonly:u64,after:u64)->u64:
    if target < 4 or readonly > 1 or to > need or count > need-to or inside(w,source,at,count) == 0:
        return refuse(w,3003)
    put(w,O_COPY_SOURCE,source)
    put(w,O_COPY_AT,at)
    put(w,O_COPY_N,count)
    put(w,O_COPY_TARGET,target)
    put(w,O_COPY_TO,to)
    put(w,O_COPY_NEED,need)
    put(w,O_COPY_RO,readonly)
    put(w,O_COPY_AFTER,after)
    return outer_phase(w,11000)

def outer_call(w:mutbuf,role:u64,first:u64,at:u64,count:u64,second:u64,second_n:u64,work:u64,minimum:u64,after:u64)->u64:
    if role != I_PREPARE and role != I_INSPECT and role != I_POST and role != I_ISSUE:
        return refuse(w,3004)
    put(w,O_CALL_ROLE,role)
    put(w,O_CALL_FIRST,first)
    put(w,O_CALL_AT,at)
    put(w,O_CALL_N,count)
    put(w,O_CALL_SECOND,second)
    put(w,O_CALL_SECOND_N,second_n)
    put(w,O_CALL_WORK,work)
    put(w,O_CALL_MIN,minimum)
    put(w,O_CALL_REPLY,after)
    put(w,O_CALL_OBS_AT,0)
    put(w,O_CALL_OBS_N,128)
    put(w,O_PURE_NEED,minimum)
    put(w,O_PURE_PHASE,0)
    return outer_phase(w,10000)

def outer_grow(o:mutbuf,w:mutbuf,needed:u64,current:u64)->u64:
    slot = get(w,O_CALL_WORK)
    if get(w,C_RETURN) != GROW or needed <= cap(w,slot) or needed < get(w,O_PURE_NEED) or current < get(w,O_PURE_PHASE):
        return refuse(w,3005)
    put(w,O_PURE_NEED,needed)
    put(w,O_PURE_PHASE,current)
    return grow(o,w,slot,needed,10002)

def outer_error(w:mutbuf,domain:u64,error:u64,source:u64,at:u64,count:u64)->u64:
    if domain == 0 or domain > 4 or error == 0 or count == 0 or inside(w,source,at,count) == 0:
        return refuse(w,3006)
    put(w,O_ERROR_DOMAIN,domain)
    put(w,O_ERROR_ID,error)
    put(w,O_ERROR_N,count)
    return outer_copy(w,source,at,count,B_ERROR,0,count,1,900)

def outer_mechanics(o:mutbuf,w:mutbuf)->u64:
    current = get(w,C_PHASE)
    if current == 10000:
        slot = get(w,O_CALL_WORK)
        if cap(w,slot) != 0:
            return protect(o,w,slot,0,10001)
        return outer_phase(w,10001)
    if current == 10001:
        return grow(o,w,get(w,O_CALL_WORK),get(w,O_CALL_MIN),10002)
    if current == 10002:
        slot = get(w,O_CALL_WORK)
        return invoke(o,w,get(w,O_CALL_ROLE),get(w,O_CALL_FIRST),get(w,O_CALL_AT),
            get(w,O_CALL_N),get(w,O_CALL_SECOND),get(w,O_CALL_SECOND_N),
            slot,cap(w,slot),slot,get(w,O_CALL_OBS_AT),get(w,O_CALL_OBS_N),get(w,O_CALL_REPLY))
    if current == 11000:
        target = get(w,O_COPY_TARGET)
        if cap(w,target) != 0:
            return protect(o,w,target,0,11001)
        return outer_phase(w,11001)
    if current == 11001:
        return grow(o,w,get(w,O_COPY_TARGET),get(w,O_COPY_NEED),11002)
    if current == 11002:
        return copy(o,w,get(w,O_COPY_SOURCE),get(w,O_COPY_AT),get(w,O_COPY_TARGET),
            get(w,O_COPY_TO),get(w,O_COPY_N),11003)
    if current == 11003:
        return protect(o,w,get(w,O_COPY_TARGET),get(w,O_COPY_RO),get(w,O_COPY_AFTER))
    return refuse(w,3007)

def prepare_command(w:mutbuf)->u64:
    fill_range(w,WIRE,128,0)
    put(w,WIRE,PREP_COMMAND)
    put(w,WIRE+8,1)
    put(w,WIRE+16,get(w,O_GRAPH_LEASE))
    put(w,WIRE+24,get(w,O_REQUEST))
    put(w,WIRE+40,get(w,O_CODE_LEASE))
    put(w,WIRE+48,get(w,O_STRUCTURED))
    put(w,WIRE+56,get(w,O_ROOT))
    put(w,WIRE+64,get(w,O_GRAPH_N))
    return outer_copy(w,2,WIRE,128,B_COMMAND,0,128,1,11)

def preparation_reply(o:mutbuf,w:mutbuf)->u64:
    if get(w,OBS) != PREP_EVENT or get(w,OBS+8) != 1 or get(w,OBS+120) != 0:
        return refuse(w,3010)
    if get(w,OBS+24) != get(w,O_GRAPH_LEASE) or get(w,OBS+32) != get(w,O_REQUEST):
        return refuse(w,3011)
    if get(w,OBS+96) != 0 or get(w,OBS+104) != get(w,O_ROOT) or get(w,OBS+112) != 1:
        return refuse(w,3012)
    action = get(w,OBS+16)
    needed = get(w,OBS+48)
    at = get(w,OBS+56)
    count = get(w,OBS+64)
    if action == 1:
        if get(w,OBS+40) != 0 or at != 0 or count != 0:
            return refuse(w,3013)
        return outer_grow(o,w,needed,1)
    if get(w,C_RETURN) != 128 or action > 2:
        return refuse(w,3014)
    if action == 2:
        error = get(w,OBS+40)
        if error == 0 or error > 6:
            return refuse(w,3015)
        return outer_error(w,2,error,B_PREP,at,count)
    if get(w,OBS+40) != 0 or needed < 8320 or needed > cap(w,B_PREP) or at != 8192 or count != needed-8192:
        return refuse(w,3016)
    put(w,O_NORM_N,count)
    return outer_phase(w,13)

def normalized_header(w:mutbuf)->u64:
    if get(w,OBS) != NORM or get(w,OBS+8) != 1 or get(w,OBS+16) != get(w,O_GRAPH_LEASE) or get(w,OBS+24) != get(w,O_REQUEST):
        return refuse(w,3017)
    count = get(w,OBS+32)
    graph = 8320+count*32
    if count > 128 or get(w,OBS+40) != 8320 or get(w,OBS+48) != graph:
        return refuse(w,3018)
    if get(w,OBS+56) != get(w,O_GRAPH_N) or get(w,OBS+64) != get(w,O_ROOT) or get(w,OBS+72) != get(w,O_GRAPH_N) or get(w,OBS+80) != get(w,O_STRUCTURED):
        return refuse(w,3019)
    if get(w,O_NORM_N) != 128+count*32+get(w,O_GRAPH_N):
        return refuse(w,3020)
    i = 88
    while i < 128:
        if get(w,OBS+i) != 0:
            return refuse(w,3021)
        i = i+8
    put(w,O_FOREIGN_N,count)
    put(w,O_NORM_GRAPH,128+count*32)
    return outer_copy(w,B_PREP,8192,get(w,O_NORM_N),B_NORM,0,get(w,O_NORM_N),1,15)

def plan_input(w:mutbuf)->u64:
    if get(w,O_HAS_PLAN) == 0:
        return outer_phase(w,30)
    fill_range(w,WIRE,128,0)
    put(w,WIRE,PLAN_INIT)
    put(w,WIRE+8,1)
    put(w,WIRE+16,get(w,O_PLAN_LEASE))
    put(w,WIRE+24,get(w,O_REQUEST))
    put(w,WIRE+32,get(w,O_GRAPH_LEASE))
    put(w,WIRE+40,get(w,O_ROOT))
    put(w,WIRE+48,get(w,O_GRAPH_N))
    put(w,WIRE+56,get(w,O_DIGITS))
    outer_local_copy(w,WIRE+64,H_CORE,32)
    return outer_copy(w,2,WIRE,128,CB_INPUT_SLOT,0,128+get(w,O_GRAPH_N),0,21)

def child_error(w:mutbuf,kind:u64)->u64:
    at = CB_TERMINAL_AT
    domain = get(w,at+32)
    error = get(w,at+40)
    slot = get(w,at+48)
    offset = get(w,at+56)
    count = get(w,at+64)
    if kind == 1:
        if domain != 3 or error == 0 or error > 22 or slot != 10:
            return refuse(w,3022)
    else:
        if (domain != 1 and domain != 2) or slot != 17:
            return refuse(w,3023)
    if offset != 0 or count == 0 or cb_readonly(w,slot) != 1 or cb_inside(w,slot,offset,count) == 0:
        return refuse(w,3024)
    return outer_error(w,choose(kind == 1,2,domain),error,cb_slot(w,slot),offset,count)

def plan_terminal(w:mutbuf)->u64:
    at = CB_TERMINAL_AT
    if get(w,at+72) != get(w,O_REQUEST) or get(w,at+80) != get(w,O_GRAPH_LEASE):
        return refuse(w,3025)
    if get(w,at+88) != get(w,O_PLAN) or get(w,at+96) != get(w,O_CORE):
        return refuse(w,3026)
    if get(w,at+32) != 0:
        return child_error(w,1)
    if get(w,at+40) != 0 or get(w,at+48) != 9 or get(w,at+56) != 0 or get(w,at+64) != 256:
        return refuse(w,3027)
    if cb_readonly(w,9) != 1 or cb_inside(w,9,0,256) == 0:
        return refuse(w,3028)
    return outer_phase(w,23)

def plan_descriptor(w:mutbuf)->u64:
    if get(w,OBS) != PLAN_RESULT or get(w,OBS+8) != 1 or get(w,OBS+16) != get(w,O_PLAN_LEASE) or get(w,OBS+24) != get(w,O_REQUEST):
        return refuse(w,3030)
    if get(w,OBS+32) != get(w,O_GRAPH_LEASE) or get(w,OBS+40) != 1 or get(w,OBS+48) != 128 or get(w,OBS+56) != get(w,O_GRAPH_N):
        return refuse(w,3031)
    if get(w,OBS+64) != get(w,O_CORE) or get(w,OBS+72) != get(w,O_PLAN):
        return refuse(w,3032)
    version = get(w,OBS+80)
    size = get(w,OBS+104)
    if version == 0 or version > 4 or version != get(w,CB_TERMINAL_AT+104) or size != get(w,CB_TERMINAL_AT+112):
        return refuse(w,3033)
    if get(w,OBS+88) != 8 or get(w,OBS+96) != 0 or size == 0 or size > 8388608:
        return refuse(w,3034)
    if get(w,OBS+112) != 7 or get(w,OBS+120) != 0:
        return refuse(w,3035)
    if cb_readonly(w,8) != 1 or cb_inside(w,8,0,size) == 0 or cb_readonly(w,7) != 1:
        return refuse(w,3036)
    i = 0
    while i < 32:
        if byte(w,OBS+128+i) != byte(w,H_CORE+i):
            return refuse(w,3037)
        i = i+1
    if get(w,OBS+160) != get(w,CB_TERMINAL_AT+120) or get(w,OBS+168) != get(w,O_DIGITS) or get(w,OBS+176) != 2 or get(w,OBS+184) != 8388608:
        return refuse(w,3038)
    i = 192
    while i < 256:
        if get(w,OBS+i) != 0:
            return refuse(w,3039)
        i = i+8
    put(w,O_PLAN_N,size)
    put(w,O_PLAN_VERSION,version)
    return outer_copy(w,cb_slot(w,8),0,size,B_PLAN,0,size,1,25)

def emitter_input(w:mutbuf)->u64:
    fill_range(w,WIRE,128,0)
    put(w,WIRE,EMITTER_INIT)
    put(w,WIRE+8,1)
    put(w,WIRE+16,get(w,O_EMITTER_LEASE))
    put(w,WIRE+24,get(w,O_REQUEST))
    put(w,WIRE+32,get(w,O_GRAPH_LEASE))
    put(w,WIRE+40,get(w,O_CODE_LEASE))
    put(w,WIRE+48,get(w,O_ROOT))
    put(w,WIRE+56,get(w,O_GRAPH_N))
    put(w,WIRE+64,get(w,O_STRUCTURED))
    return outer_copy(w,2,WIRE,128,CB_INPUT_SLOT,0,128+get(w,O_GRAPH_N),0,31)

def emitter_terminal(w:mutbuf)->u64:
    at = CB_TERMINAL_AT
    if get(w,at+112) != get(w,O_REQUEST) or get(w,at+120) != 0:
        return refuse(w,3040)
    if get(w,at+32) != 0:
        return child_error(w,2)
    if get(w,at+40) != 0 or get(w,at+48) != 18 or get(w,at+56) != 0 or get(w,at+64) != 256:
        return refuse(w,3041)
    if cb_readonly(w,18) != 1 or cb_inside(w,18,0,256) == 0:
        return refuse(w,3042)
    put(w,O_CODE_SEQ,get(w,at+72))
    put(w,O_CHILD_CODE_N,get(w,at+80))
    put(w,O_CHILD_SERIAL,get(w,at+88))
    put(w,O_CHILD_RECORDS,get(w,at+96))
    put(w,O_GLOBAL_N,get(w,at+104))
    return outer_phase(w,33)

def emitter_descriptor(w:mutbuf)->u64:
    if get(w,OBS) != EMITTER_RESULT or get(w,OBS+8) != 1 or get(w,OBS+16) != get(w,O_EMITTER_LEASE) or get(w,OBS+24) != get(w,O_REQUEST):
        return refuse(w,3043)
    if get(w,OBS+32) != 1 or get(w,OBS+40) != 128 or get(w,OBS+48) != get(w,O_GRAPH_N) or get(w,OBS+56) != get(w,O_GRAPH_LEASE):
        return refuse(w,3044)
    if get(w,OBS+64) != 16 or get(w,OBS+72) != 0 or get(w,OBS+88) != get(w,O_CODE_LEASE) or get(w,OBS+96) != get(w,O_CODE_SEQ):
        return refuse(w,3045)
    functions = get(w,OBS+112)
    globals = get(w,OBS+120)
    if functions == 0 or functions > 1024 or globals == 0 or globals > 128 or globals != get(w,O_GLOBAL_N):
        return refuse(w,3046)
    if functions+globals != get(w,O_CHILD_RECORDS) or get(w,OBS+104) != get(w,O_CHILD_SERIAL):
        return refuse(w,3047)
    if get(w,OBS+128) != 14 or get(w,OBS+152) != 15 or get(w,OBS+176) != 6 or get(w,OBS+200) != 7:
        return refuse(w,3048)
    if get(w,OBS+184) != get(w,O_NORM_GRAPH) or get(w,OBS+192) != get(w,O_GRAPH_N):
        return refuse(w,3049)
    if get(w,OBS+208) != 256+functions*56 or get(w,OBS+240) != 0 or get(w,OBS+248) != 0:
        return refuse(w,3050)
    if cb_readonly(w,16) != 1 or cb_inside(w,16,0,get(w,OBS+80)) == 0:
        return refuse(w,3051)
    if cb_readonly(w,14) != 1 or cb_inside(w,14,get(w,OBS+136),get(w,OBS+144)) == 0:
        return refuse(w,3052)
    if cb_readonly(w,15) != 1 or cb_inside(w,15,get(w,OBS+160),get(w,OBS+168)) == 0:
        return refuse(w,3053)
    if cb_readonly(w,6) != 1 or cb_inside(w,6,get(w,O_NORM_GRAPH),get(w,O_GRAPH_N)) == 0:
        return refuse(w,3054)
    if cb_readonly(w,7) != 1 or cb_inside(w,7,0,get(w,OBS+208)) == 0:
        return refuse(w,3055)
    if get(w,OBS+144) == 0 or get(w,OBS+168) == 0:
        return refuse(w,3056)
    put(w,O_FN_N,functions)
    put(w,O_REG_N,get(w,OBS+80))
    put(w,O_TEXT_AT,get(w,OBS+136))
    put(w,O_TEXT_N,get(w,OBS+144))
    put(w,O_OBJECT_AT,get(w,OBS+160))
    put(w,O_OBJECT_N,get(w,OBS+168))
    put(w,O_INV_N,get(w,OBS+208))
    outer_local_copy(w,SAVED_EMITTER,OBS,256)
    return outer_phase(w,35)

def capsule_header(w:mutbuf)->u64:
    fill_range(w,WIRE,512,0)
    put(w,WIRE,POST_QUERY)
    put(w,WIRE+8,1)
    put(w,WIRE+24,get(w,C_LEASE))
    put(w,WIRE+32,get(w,O_REQUEST))
    put(w,WIRE+40,get(w,O_EMITTER_LEASE))
    put(w,WIRE+48,get(w,O_GRAPH_LEASE))
    put(w,WIRE+56,get(w,O_ROOT))
    put(w,WIRE+64,get(w,O_REG_N))
    put(w,WIRE+72,get(w,O_OBJECT_N))
    put(w,WIRE+80,get(w,O_TEXT_N))
    put(w,WIRE+88,get(w,O_CODE_LEASE))
    put(w,WIRE+96,get(w,O_CODE_SEQ))
    put(w,WIRE+104,get(w,O_FN_N))
    put(w,WIRE+112,get(w,O_GLOBAL_N))
    put(w,WIRE+120,get(w,O_FOREIGN_N))
    put(w,WIRE+128,512)
    put(w,WIRE+136,get(w,O_FOREIGN_N)*32)
    put(w,WIRE+144,get(w,O_HAS_PLAN))
    put(w,WIRE+152,get(w,O_PLAN_VERSION))
    put(w,WIRE+160,get(w,O_STRUCTURED))
    at = 512+get(w,O_FOREIGN_N)*32
    size = at+get(w,O_INV_N)
    put(w,WIRE+168,at)
    put(w,WIRE+176,get(w,O_INV_N))
    put(w,WIRE+184,size)
    outer_local_copy(w,WIRE+192,HASHES,224)
    put(w,O_CAPSULE_N,size)
    return outer_copy(w,2,WIRE,512,B_CAPSULE,0,size,0,36)

def issuer_reply(o:mutbuf,w:mutbuf)->u64:
    if get(w,OBS) != POST_QUERY_EVENT or get(w,OBS+8) != 1 or get(w,OBS+24) != get(w,C_LEASE):
        return refuse(w,3060)
    if get(w,OBS+32) != get(w,O_REQUEST) or get(w,OBS+40) != 0 or get(w,OBS+48) != 0:
        return refuse(w,3061)
    if get(w,OBS+80) != get(w,O_FN_N) or get(w,OBS+88) != get(w,O_GLOBAL_N) or get(w,OBS+96) != get(w,O_FOREIGN_N):
        return refuse(w,3062)
    if get(w,OBS+104) != 0 or get(w,OBS+120) != 0:
        return refuse(w,3063)
    action = get(w,OBS+16)
    needed = get(w,OBS+56)
    if action == 1:
        if get(w,OBS+64) != 0 or get(w,OBS+72) != 0 or get(w,OBS+112) != 2:
            return refuse(w,3064)
        return outer_grow(o,w,needed,2)
    if action != 0 or get(w,C_RETURN) != 128 or get(w,OBS+112) != 3:
        return refuse(w,3065)
    size = get(w,OBS+72)
    if get(w,OBS+64) != 8192 or size < 512 or needed != 8192+size or needed > cap(w,B_ISSUE):
        return refuse(w,3066)
    put(w,O_POST_N,size)
    return outer_copy(w,B_ISSUE,8192,size,B_POST_COMMAND,0,size,1,40)

def post_reply(o:mutbuf,w:mutbuf)->u64:
    mode = get(w,O_POST_MODE)
    if get(w,OBS) != POST_EVENT or get(w,OBS+8) != 1 or get(w,OBS+24) != get(w,C_LEASE) or get(w,OBS+32) != get(w,O_REQUEST):
        return refuse(w,3070)
    if get(w,OBS+40) != mode or get(w,OBS+80) != get(w,O_FN_N) or get(w,OBS+88) != get(w,O_GLOBAL_N) or get(w,OBS+96) != get(w,O_FOREIGN_N):
        return refuse(w,3071)
    if get(w,OBS+104) != 0 or get(w,OBS+120) != 0:
        return refuse(w,3072)
    action = get(w,OBS+16)
    error = get(w,OBS+48)
    needed = get(w,OBS+56)
    offset = get(w,OBS+64)
    size = get(w,OBS+72)
    phase = get(w,OBS+112)
    if action == 1:
        if error != 0 or offset != 0 or size != 0 or phase != choose(mode == 0,3,5):
            return refuse(w,3073)
        return outer_grow(o,w,needed,phase)
    if get(w,C_RETURN) != 128:
        return refuse(w,3074)
    if action == 2:
        if get(w,O_PURE_PHASE) != 0:
            return refuse(w,3075)
        if error == 1:
            if mode != 0 or get(w,O_OBJECT_N) <= 67108864 or phase != 1:
                return refuse(w,3076)
        elif error == 2:
            if mode != 1 or get(w,O_STALE) != 1 or phase != 2:
                return refuse(w,3077)
        else:
            return refuse(w,3078)
        return outer_error(w,2,error,B_POST,offset,size)
    if action != 0 or error != 0 or offset != 8192 or size == 0 or needed != offset+size or needed > cap(w,B_POST):
        return refuse(w,3079)
    if phase != choose(mode == 0,4,6):
        return refuse(w,3080)
    if mode == 0:
        if size < 128 or get(w,O_OBJECT_N) > 67108864:
            return refuse(w,3081)
        put(w,O_INSPECT_COMMAND_N,size)
        return outer_copy(w,B_POST,8192,size,B_INSPECT_COMMAND,0,size,1,42)
    if get(w,O_STALE) != 0:
        return refuse(w,3082)
    put(w,O_META_N,size)
    return outer_copy(w,B_POST,8192,size,B_META,0,size,1,60)

def inspect_reply(o:mutbuf,w:mutbuf)->u64:
    if get(w,OBS) != INSPECT_EVENT or get(w,OBS+8) != 1 or get(w,OBS+24) != get(w,C_LEASE):
        return refuse(w,3090)
    if get(w,OBS+32) != get(w,O_REQUEST) or get(w,OBS+40) != get(w,O_EMITTER_LEASE) or get(w,OBS+120) != 0:
        return refuse(w,3091)
    action = get(w,OBS+16)
    domain = get(w,OBS+48)
    error = get(w,OBS+56)
    needed = get(w,OBS+64)
    offset = get(w,OBS+72)
    size = get(w,OBS+80)
    phase = get(w,OBS+112)
    if phase == 0 or phase > 5:
        return refuse(w,3092)
    if action == 1:
        if domain != 0 or error != 0 or offset != 0 or size != 0 or (phase != 2 and phase != 4):
            return refuse(w,3093)
        return outer_grow(o,w,needed,phase)
    if get(w,C_RETURN) != 128 or phase < get(w,O_PURE_PHASE):
        return refuse(w,3094)
    if action == 2:
        if error == 0 or error > 17 or domain != choose(error == 17,2,1):
            return refuse(w,3095)
        if phase == 5:
            return refuse(w,3096)
        return outer_error(w,choose(domain == 1,4,2),error,B_INSPECT,offset,size)
    if action != 0 or domain != 0 or error != 0 or phase != 5:
        return refuse(w,3097)
    if get(w,OBS+88) != get(w,O_GLOBAL_N) or get(w,OBS+104) < get(w,OBS+88):
        return refuse(w,3098)
    if get(w,OBS+96) != get(w,OBS+104)-get(w,OBS+88) or get(w,OBS+96) > 7:
        return refuse(w,3099)
    if offset < 8192 or size == 0 or needed < offset or size != needed-offset or needed > cap(w,B_INSPECT):
        return refuse(w,3100)
    put(w,O_INSPECT_AT,offset)
    put(w,O_INSPECT_N,size)
    return outer_phase(w,44)

def implementation_checked(w:mutbuf)->u64:
    i = 0
    changed = 0
    while i < 32:
        if byte(w,H_IMPL_BEFORE+i) != byte(w,H_IMPL_AFTER+i):
            changed = 1
        i = i+1
    put(w,O_STALE,changed)
    if changed != 0:
        return outer_phase(w,50)
    return hash_start(w,cb_slot(w,15),get(w,O_OBJECT_AT),get(w,O_OBJECT_N),H_OBJECT,46)

def post_mode_one(w:mutbuf)->u64:
    put(w,WIRE,1)
    put(w,O_POST_MODE,1)
    return outer_copy(w,2,WIRE,8,B_POST_COMMAND,16,get(w,O_POST_N),0,51)

def post_hashes(w:mutbuf)->u64:
    outer_local_copy(w,WIRE,H_OBJECT,96)
    return outer_copy(w,2,WIRE,96,B_POST_COMMAND,320,get(w,O_POST_N),1,52)

def final_descriptor(w:mutbuf)->u64:
    if get(w,CB_ACTIVE) != 2 or get(w,CB_KIND) != 2 or get(w,O_META_N) == 0:
        return refuse(w,3110)
    fill_range(w,WIRE,512,0)
    put(w,WIRE,RESULT)
    put(w,WIRE+8,1)
    put(w,WIRE+16,get(w,C_LEASE))
    put(w,WIRE+24,get(w,O_REQUEST))
    put(w,WIRE+32,get(w,O_GRAPH_LEASE))
    put(w,WIRE+40,get(w,O_CODE_LEASE))
    put(w,WIRE+48,get(w,O_PLAN_LEASE))
    put(w,WIRE+56,get(w,O_EMITTER_LEASE))
    put(w,WIRE+64,cb_slot(w,15))
    put(w,WIRE+72,get(w,O_OBJECT_AT))
    put(w,WIRE+80,get(w,O_OBJECT_N))
    put(w,WIRE+88,cb_slot(w,14))
    put(w,WIRE+96,get(w,O_TEXT_AT))
    put(w,WIRE+104,get(w,O_TEXT_N))
    put(w,WIRE+112,B_META)
    put(w,WIRE+128,get(w,O_META_N))
    put(w,WIRE+136,cb_slot(w,16))
    put(w,WIRE+152,get(w,O_REG_N))
    put(w,WIRE+160,choose(get(w,O_HAS_PLAN) == 0,0,B_PLAN))
    put(w,WIRE+176,get(w,O_PLAN_N))
    put(w,WIRE+184,get(w,O_HAS_PLAN))
    put(w,WIRE+192,get(w,O_PLAN_VERSION))
    put(w,WIRE+200,get(w,O_FOREIGN_N))
    put(w,WIRE+208,get(w,O_FN_N))
    put(w,WIRE+216,get(w,O_GLOBAL_N))
    put(w,WIRE+224,get(w,O_CODE_SEQ))
    put(w,WIRE+232,get(w,O_STRUCTURED))
    put(w,WIRE+240,get(w,O_CHILD_SERIAL))
    put(w,WIRE+248,get(w,O_CHILD_RECORDS))
    outer_local_copy(w,WIRE+256,HASHES,224)
    return outer_copy(w,2,WIRE,512,B_RESULT,0,512,1,61)

def outer_terminal(o:mutbuf,w:mutbuf,domain:u64,error:u64,slot:u64,count:u64)->u64:
    if get(w,L_STATUS) != 1 or get(w,C_PENDING) != 0 or inside(w,slot,0,count) == 0:
        return refuse(w,3111)
    put(w,L_STATUS,2)
    put(w,C_PHASE,999)
    put(o,0,EVENT_MAGIC)
    put(o,8,7)
    put(o,16,get(w,C_LEASE))
    put(o,24,get(w,C_SEQUENCE))
    put(o,32,domain)
    put(o,40,error)
    put(o,48,slot)
    put(o,56,0)
    put(o,64,count)
    put(o,72,get(w,O_META_N))
    put(o,80,get(w,O_OBJECT_N))
    put(o,88,get(w,O_TEXT_N))
    put(o,96,get(w,O_PLAN_N))
    put(o,104,get(w,O_FN_N))
    put(o,112,get(w,O_GLOBAL_N))
    put(o,120,get(w,O_REQUEST))
    return 128

def hash_start(w:mutbuf,source:u64,at:u64,count:u64,destination:u64,after:u64)->u64:
    if count > 2305843009213693951 or inside(w,source,at,count) == 0:
        return refuse(w,3120)
    if destination != H_OBJECT and destination != H_TEXT and destination != H_PLAN:
        return refuse(w,3121)
    put(w,O_HASH_SOURCE,source)
    put(w,O_HASH_AT,at)
    put(w,O_HASH_N,count)
    put(w,O_HASH_DONE,0)
    put(w,O_HASH_DEST,destination)
    put(w,O_HASH_AFTER,after)
    put(w,O_HASH_TAKE,0)
    return outer_phase(w,13000)

def hash_command(w:mutbuf,opcode:u64,after:u64)->u64:
    store(w,WIRE,opcode)
    return outer_copy(w,2,WIRE,1,B_HASH_INPUT,0,1,1,after)

def hash_step(o:mutbuf,w:mutbuf)->u64:
    phase = get(w,C_PHASE)
    if phase == 13000:
        return grow(o,w,B_HASH_OUT,32,13001)
    if phase == 13001:
        return grow(o,w,B_HASH_WORK,1184,13002)
    if phase == 13002:
        return hash_command(w,0,13003)
    if phase == 13003:
        return invoke(o,w,I_HASH,B_HASH_INPUT,0,1,B_HASH_OUT,32,B_HASH_WORK,1184,B_HASH_OUT,0,0,13004)
    if phase == 13004:
        if get(w,C_RETURN) != 0:
            return refuse(w,3122)
        return outer_phase(w,13010)
    if phase == 13010:
        if get(w,O_HASH_DONE) == get(w,O_HASH_N):
            return hash_command(w,2,13020)
        if get(w,O_HASH_DONE) > get(w,O_HASH_N):
            return refuse(w,3123)
        count = minimum(get(w,O_HASH_N)-get(w,O_HASH_DONE),HASH_CHUNK)
        put(w,O_HASH_TAKE,count)
        store(w,WIRE,1)
        return outer_copy(w,2,WIRE,1,B_HASH_INPUT,0,count+1,0,13011)
    if phase == 13011:
        return copy(o,w,get(w,O_HASH_SOURCE),get(w,O_HASH_AT)+get(w,O_HASH_DONE),
            B_HASH_INPUT,1,get(w,O_HASH_TAKE),13012)
    if phase == 13012:
        return protect(o,w,B_HASH_INPUT,1,13013)
    if phase == 13013:
        return invoke(o,w,I_HASH,B_HASH_INPUT,0,get(w,O_HASH_TAKE)+1,
            B_HASH_OUT,32,B_HASH_WORK,1184,B_HASH_OUT,0,0,13014)
    if phase == 13014:
        if get(w,C_RETURN) != 0 or get(w,O_HASH_TAKE) == 0:
            return refuse(w,3124)
        put(w,O_HASH_DONE,get(w,O_HASH_DONE)+get(w,O_HASH_TAKE))
        return outer_phase(w,13010)
    if phase == 13020:
        return invoke(o,w,I_HASH,B_HASH_INPUT,0,1,B_HASH_OUT,32,B_HASH_WORK,1184,B_HASH_OUT,0,32,13021)
    if phase == 13021:
        if get(w,C_RETURN) != 32:
            return refuse(w,3125)
        outer_local_copy(w,get(w,O_HASH_DEST),OBS,32)
        return outer_phase(w,get(w,O_HASH_AFTER))
    return refuse(w,3126)

def outer_front_step(o:mutbuf,w:mutbuf)->u64:
    phase = get(w,C_PHASE)
    if phase == 10:
        return prepare_command(w)
    if phase == 11:
        return outer_call(w,I_PREPARE,1,INPUT_HEADER,get(w,O_GRAPH_N),B_COMMAND,128,B_PREP,8192,12)
    if phase == 12:
        return preparation_reply(o,w)
    if phase == 13:
        return view(o,w,B_PREP,8192,128,14)
    if phase == 14:
        return normalized_header(w)
    if phase == 15:
        return release(o,w,B_PREP,20)
    if phase == 20:
        return plan_input(w)
    if phase == 21:
        return copy(o,w,B_NORM,get(w,O_NORM_GRAPH),CB_INPUT_SLOT,128,get(w,O_GRAPH_N),210)
    if phase == 210:
        return protect(o,w,CB_INPUT_SLOT,1,211)
    if phase == 211:
        return cb_start(w,1,get(w,O_PLAN_LEASE),22)
    if phase == 22:
        return plan_terminal(w)
    if phase == 23:
        return view(o,w,cb_slot(w,9),0,256,24)
    if phase == 24:
        return plan_descriptor(w)
    if phase == 25:
        return cb_retire(w,26)
    if phase == 26:
        return hash_start(w,B_PLAN,0,get(w,O_PLAN_N),H_PLAN,30)
    if phase == 30:
        return emitter_input(w)
    if phase == 31:
        return copy(o,w,1,INPUT_HEADER,CB_INPUT_SLOT,128,get(w,O_GRAPH_N),310)
    if phase == 310:
        return protect(o,w,CB_INPUT_SLOT,1,311)
    if phase == 311:
        return cb_start(w,2,get(w,O_EMITTER_LEASE),32)
    if phase == 32:
        return emitter_terminal(w)
    if phase == 33:
        return view(o,w,cb_slot(w,18),0,256,34)
    if phase == 34:
        return emitter_descriptor(w)
    return refuse(w,3130)

def outer_post_step(o:mutbuf,w:mutbuf)->u64:
    phase = get(w,C_PHASE)
    if phase == 35:
        return capsule_header(w)
    if phase == 36:
        return copy(o,w,B_NORM,128,B_CAPSULE,512,get(w,O_FOREIGN_N)*32,37)
    if phase == 37:
        return copy(o,w,cb_slot(w,7),0,B_CAPSULE,512+get(w,O_FOREIGN_N)*32,get(w,O_INV_N),38)
    if phase == 38:
        return protect(o,w,B_CAPSULE,1,39)
    if phase == 39:
        return outer_call(w,I_ISSUE,1,INPUT_HEADER,get(w,O_GRAPH_N),B_CAPSULE,get(w,O_CAPSULE_N),B_ISSUE,8192,390)
    if phase == 390:
        return issuer_reply(o,w)
    if phase == 40:
        put(w,O_POST_MODE,0)
        return outer_call(w,I_POST,cb_slot(w,16),0,get(w,O_REG_N),B_POST_COMMAND,get(w,O_POST_N),B_POST,8192,41)
    if phase == 41:
        return post_reply(o,w)
    if phase == 42:
        return outer_call(w,I_INSPECT,cb_slot(w,15),get(w,O_OBJECT_AT),get(w,O_OBJECT_N),
            B_INSPECT_COMMAND,get(w,O_INSPECT_COMMAND_N),B_INSPECT,4096,43)
    if phase == 43:
        return inspect_reply(o,w)
    if phase == 44:
        return protect(o,w,B_INSPECT,1,45)
    if phase == 45:
        return implementation_checked(w)
    if phase == 46:
        return hash_start(w,cb_slot(w,14),get(w,O_TEXT_AT),get(w,O_TEXT_N),H_TEXT,50)
    if phase == 50:
        return post_mode_one(w)
    if phase == 51:
        return post_hashes(w)
    if phase == 52:
        return outer_call(w,I_POST,cb_slot(w,16),0,get(w,O_REG_N),B_POST_COMMAND,get(w,O_POST_N),B_POST,8192,53)
    if phase == 53:
        return post_reply(o,w)
    if phase == 60:
        return final_descriptor(w)
    if phase == 61:
        return outer_terminal(o,w,0,0,B_RESULT,512)
    if phase == 900:
        return outer_terminal(o,w,get(w,O_ERROR_DOMAIN),get(w,O_ERROR_ID),B_ERROR,get(w,O_ERROR_N))
    return refuse(w,3131)

def outer_step(o:mutbuf,w:mutbuf)->u64:
    phase = get(w,C_PHASE)
    if phase < 35 or phase == 210 or phase == 211 or phase == 310 or phase == 311:
        return outer_front_step(o,w)
    return outer_post_step(o,w)

'''
def source(common,forwarder):
 constants=dict(common.CONSTANTS)
 constants.update(forwarder.CONSTANTS)
 constants.update(CONSTANTS)
 nodes=ast.parse(BODY+"\n"+forwarder.BODY+"\n"+common.COMMON).body
 functions={node.name:node for node in nodes}
 assert len(functions)==len(nodes)
 reachable={"backend_controller"}
 pending=["backend_controller"]
 while pending:
  name=pending.pop()
  for called in ast.walk(functions[name]):
   if isinstance(called,ast.Call) and isinstance(called.func,ast.Name):
    other=called.func.id
    if other in functions and other not in reachable:
     reachable.add(other);pending.append(other)
 selected=[copy.deepcopy(functions["backend_controller"])]
 selected += [copy.deepcopy(node) for node in nodes if node.name in reachable and node.name!="backend_controller"]
 for node in selected:
  if node.name in ("word","get"):
   arg="s" if node.name=="word" else "w"
   node.body=ast.parse("return "+" | ".join("(byte(%s,at+%d)<<%d)"%(arg,i,i*8) for i in range(8))).body
  elif node.name=="put":
   node.body=ast.parse("\n".join("store(w,at+%d,(value>>%d)&255)"%(i,i*8) for i in range(8))+"\nreturn 0").body
 assert constants["CB_TERMINAL_AT"]+128<=constants["HASHES"]
 assert constants["HASHES"]+224<=constants["SAVED_EMITTER"]
 assert constants["SAVED_EMITTER"]+256<=constants["SAVED_INVENTORY"]
 assert constants["SAVED_INVENTORY"]+256<30000
 return "\n".join(ast.unparse(ast.fix_missing_locations(node)) for node in selected)+"\n",constants,dict(
  status="NEW_UNEXECUTED",scope="ACTUAL_CHECKED_PLAN_EMITTER_INSPECTOR_DIGEST_METADATA_JOIN",
  entry_role=20,private_input_header_bytes=320,header_is_authentication=False,
  graph_requires_actual_admitted_Core_and_actual_private_plan_and_foreign_capture=True,
  implementation_before_after_actual_file_authority_is_upstream=True,
  normalized_borrowed_exports_before_checked_plan=True,
  actual_checked_plan_then_unchanged_eleven_Emitter_images=True,
  actual_independent_object_inspection_before_implementation_recheck=True,
  actual_incremental_SHA_for_plan_object_and_text=True,
  all_names_metadata_expected_exports_and_result_fields_native=True,
  original_error_text_views_preserved=True,
  child_slot_and_sequence_forwarding_is_HIA_owned=True,
  finite_child_kinds=["checked-plan","complete-Emitter"],no_recursion=True,
  original_allocation_and_semantic_limits_unchanged=True,
  successful_views_retained_readonly_until_parent_release=True,
  full_public_admission_and_implementation_file_authority_join=False,
  public_emit_program_machine=False,compile_program_machine=False,installed=False,cold=False)
