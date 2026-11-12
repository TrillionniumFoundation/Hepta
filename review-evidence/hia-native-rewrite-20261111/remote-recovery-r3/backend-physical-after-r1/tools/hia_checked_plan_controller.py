"""Native checked-plan continuation: strict snapshot, actual wire, semantics.

Only this HIA controller chooses calls, growth, copies, permissions and terminal
publication. The fixed development executor does not inspect a plan or Graph.
Actual admitted Core and immutable source issuance remain upstream obligations.
"""
import ast,copy
def magic(value):return int.from_bytes(value.encode("ascii"),"little")
COMMON_SHA="fe63327671ea51ca950b955512a0f574d706176a4a8d050e3f8f12c83ef5e3a1"
OWNER_SHA="8fd64a521afb771255d112e40fe7586b1c46c69f343fe5bdd6d42e643d205336"
CONSTANTS=dict(MAX=(1<<64)-1,BAD=0xfffffffd,GROW=0xfffffffe,MIN_WORK=1<<20,
 DRIVER=5,INIT=magic("HIAMPB01"),LOWER_MAGIC=magic("HIAMPS01"),
 GRAPH=magic("HIAGRF01"),PLAN_COMMAND=magic("HIAMPC01"),
 PLAN_EVENT=magic("HIAMPE01"),PLAN_RESULT=magic("HIAMPR01"),
 RESULT=magic("HIAMPD01"),WIRE_COMMAND=magic("HIAGWC01"),
 WIRE_EVENT=magic("HIAGWE01"),PEER_MIN=32768,PLAN_MAX=8388608,
 HASH=30000,ERROR_TEXT=30256,
 B_COMMAND=4,B_SNAPSHOT=5,B_WIRE=6,B_SEMANTICS=7,B_CANONICAL=8,B_RESULT=9,B_ERROR=10)
_FIELDS=("REQUEST","GRAPH_LEASE","ROOT","GRAPH_N","NODES","CORE","PLAN","DIGITS",
 "VERSION","CANONICAL_N","WIRE_ROLE","WIRE_PHASE","MODE","ERROR","ERROR_SLOT",
 "ERROR_AT","ERROR_N","CALL_ROLE","CALL_WORK","CALL_REPLY",
 "CONFIG_SOURCE","CONFIG_AT","CONFIG_N","CONFIG_TARGET","CONFIG_NEED","CONFIG_AFTER",
 "COPY_SOURCE","COPY_AT","COPY_N","COPY_TARGET","COPY_AFTER",
 "SNAPSHOT_N","PURE_NEED","PURE_PHASE","PEER_NEED")
CONSTANTS.update({"P_"+name:20000+i*8 for i,name in enumerate(_FIELDS)})
BODY=r'''
def plan_controller(s:readbuf,o:mutbuf,w:mutbuf)->u32:
    if length(w) < MIN_WORK or length(o) < 128:
        return BAD
    if get(w,L_MAGIC) == 0:
        if begin(s,w) == 0:
            return refuse(w,1000)
    elif acknowledge(s,w,DRIVER) == 0:
        return refuse(w,1001)
    result = 0
    while result == 0:
        if get(w,L_STATUS) != 1:
            return refuse(w,1002)
        result = step(o,w)
    return result

def begin(s:readbuf,w:mutbuf)->u64:
    if length(s) < 192 or word(s,0) != INIT or word(s,8) != 1:
        return 0
    if word(s,16) == 0 or word(s,24) == 0 or word(s,32) == 0:
        return 0
    if word(s,40) == 0 or word(s,48) != length(s)-128:
        return 0
    at = 96
    while at < 128:
        if word(s,at) != 0:
            return 0
        at = at + 8
    if word(s,128) != GRAPH or word(s,136) != word(s,32) or word(s,184) != 0:
        return 0
    nodes = word(s,144)
    edges = word(s,160)
    if nodes == 0 or nodes > (MAX-64) >> 6:
        return 0
    edgebase = 64 + nodes*64
    if edges > (MAX-edgebase) >> 3:
        return 0
    database = edgebase + edges*8
    if database > word(s,48) or word(s,168) != word(s,48)-database or word(s,176) != word(s,48):
        return 0
    root = word(s,40)
    if root != word(s,152) or root > nodes:
        return 0
    row = 128 + 64 + (root-1)*64
    if word(s,row) != 5 or word(s,row+32) != 2 or word(s,row+8) != 0 or word(s,row+16) != 0:
        return 0
    if word(s,row+40) == 0 or word(s,row+48) != 0 or word(s,row+56) != 0:
        return 0
    first = word(s,row+24)
    if first > edges or edges-first < 2:
        return 0
    core = word(s,128+edgebase+first*8)
    plan = word(s,128+edgebase+(first+1)*8)
    if core == 0 or core > nodes or plan == 0 or plan > nodes:
        return 0
    if get(w,L_STATUS) != 0 or get(w,C_PENDING) != 0 or get(w,C_SEQUENCE) != 0:
        return 0
    fill_range(w,0,MIN_WORK,0)
    put(w,L_MAGIC,LOWER_MAGIC)
    put(w,L_STATUS,1)
    put(w,L_DRIVER,DRIVER)
    put(w,C_LEASE,word(s,16))
    put(w,P_REQUEST,word(s,24))
    put(w,P_GRAPH_LEASE,word(s,32))
    put(w,P_ROOT,root)
    put(w,P_GRAPH_N,word(s,48))
    put(w,P_DIGITS,word(s,56))
    put(w,P_NODES,nodes)
    put(w,P_CORE,core)
    put(w,P_PLAN,plan)
    copy_bytes(w,s,HASH,64,32)
    put(w,CAPS+8,length(s))
    put(w,CAPS+16,length(w))
    put(w,CAPS+24,128)
    put(w,C_PHASE,10)
    return 1

def phase(w:mutbuf,value:u64)->u64:
    put(w,C_PHASE,value)
    return 0

def larger(needed:u64,old:u64)->u64:
    if old <= MAX >> 1 and needed < old*2:
        return old*2
    return needed

def config(w:mutbuf,source:u64,at:u64,count:u64,target:u64,need:u64,after:u64)->u64:
    if count == 0 or target < 4 or need < count or inside(w,source,at,count) == 0:
        return refuse(w,1003)
    put(w,P_CONFIG_SOURCE,source)
    put(w,P_CONFIG_AT,at)
    put(w,P_CONFIG_N,count)
    put(w,P_CONFIG_TARGET,target)
    put(w,P_CONFIG_NEED,need)
    put(w,P_CONFIG_AFTER,after)
    return phase(w,6000)

def copy_result(w:mutbuf,source:u64,at:u64,count:u64,target:u64,after:u64)->u64:
    if count == 0 or target < 4 or inside(w,source,at,count) == 0:
        return refuse(w,1004)
    put(w,P_COPY_SOURCE,source)
    put(w,P_COPY_AT,at)
    put(w,P_COPY_N,count)
    put(w,P_COPY_TARGET,target)
    put(w,P_COPY_AFTER,after)
    return phase(w,6500)

def call(w:mutbuf,role:u64,work:u64,after:u64)->u64:
    put(w,P_CALL_ROLE,role)
    put(w,P_CALL_WORK,work)
    put(w,P_CALL_REPLY,after)
    return phase(w,5000)

def reject(w:mutbuf,error:u64,slot:u64,at:u64,count:u64)->u64:
    if error == 0 or error > 22 or count == 0 or inside(w,slot,at,count) == 0:
        return refuse(w,1005)
    put(w,P_ERROR,error)
    put(w,P_ERROR_SLOT,slot)
    put(w,P_ERROR_AT,at)
    put(w,P_ERROR_N,count)
    return phase(w,8000)

def plan_command(w:mutbuf,mode:u64,after:u64)->u64:
    fill_range(w,WIRE,128,0)
    put(w,WIRE,PLAN_COMMAND)
    put(w,WIRE+8,1)
    put(w,WIRE+16,get(w,P_GRAPH_LEASE))
    put(w,WIRE+24,get(w,P_REQUEST))
    put(w,WIRE+32,get(w,P_ROOT))
    put(w,WIRE+40,get(w,P_GRAPH_N))
    put(w,WIRE+48,mode)
    i = 0
    while i < 32:
        store(w,WIRE+64+i,byte(w,HASH+i))
        i = i + 1
    put(w,P_MODE,mode)
    put(w,P_PURE_NEED,PEER_MIN)
    put(w,P_PURE_PHASE,0)
    return config(w,2,WIRE,128,B_COMMAND,128,after)

def plan_reply(o:mutbuf,w:mutbuf,mode:u64,after:u64)->u64:
    if get(w,OBS) != PLAN_EVENT or get(w,OBS+8) != 1 or get(w,OBS+120) != 0:
        return refuse(w,1010)
    if get(w,OBS+24) != get(w,P_GRAPH_LEASE) or get(w,OBS+32) != get(w,P_REQUEST):
        return refuse(w,1011)
    if get(w,OBS+40) != mode or mode != get(w,P_MODE):
        return refuse(w,1012)
    if get(w,OBS+96) != get(w,P_PLAN) or get(w,OBS+104) != get(w,P_CORE):
        return refuse(w,1013)
    action = get(w,OBS+16)
    error = get(w,OBS+48)
    needed = get(w,OBS+56)
    offset = get(w,OBS+64)
    size = get(w,OBS+72)
    version = get(w,OBS+80)
    current = get(w,OBS+112)
    slot = get(w,P_CALL_WORK)
    if needed < PEER_MIN or needed < get(w,P_PURE_NEED) or current < get(w,P_PURE_PHASE):
        return refuse(w,1014)
    if mode == 0:
        if slot != B_SNAPSHOT or current != 1 or version != 0 or needed != PEER_MIN:
            return refuse(w,1015)
    else:
        if slot != B_SEMANTICS or current < 2 or current > 5 or get(w,OBS+88) != 0 or version > 4:
            return refuse(w,1016)
    if action == 1:
        if mode == 0 or get(w,C_RETURN) != GROW or error != 0 or offset != 0 or size != 0:
            return refuse(w,1017)
        if needed <= cap(w,slot) or current == 2 or current == 5:
            return refuse(w,1018)
        put(w,P_PURE_NEED,needed)
        put(w,P_PURE_PHASE,current)
        return grow(o,w,slot,larger(needed,cap(w,slot)),5002)
    if get(w,C_RETURN) != 128 or action > 2 or needed > cap(w,slot):
        return refuse(w,1019)
    if action == 2:
        if mode == 0:
            if error != 1 and error != 2:
                return refuse(w,1020)
        else:
            if error < 3 or error > 22:
                return refuse(w,1021)
            if (error <= 5 and current != 2) or (error >= 6 and error <= 15 and current != 3) or (error >= 16 and current != 4):
                return refuse(w,1022)
        if offset != 20480 or size == 0 or size > 4096:
            return refuse(w,1023)
        return reject(w,error,slot,offset,size)
    if error != 0:
        return refuse(w,1024)
    if mode == 0:
        if offset != 0 or size != 0 or get(w,OBS+88) == 0 or get(w,OBS+88) > 262144:
            return refuse(w,1025)
        put(w,P_SNAPSHOT_N,get(w,OBS+88))
    else:
        if current != 5 or version == 0 or offset != 1024 or size != 128:
            return refuse(w,1026)
        put(w,P_VERSION,version)
    return phase(w,after)

def wire_request(w:mutbuf)->u64:
    wire8(w,WIRE_COMMAND,get(w,P_GRAPH_LEASE),get(w,P_REQUEST),get(w,P_PLAN),
        PLAN_MAX,2,get(w,P_DIGITS),0)
    put(w,P_WIRE_ROLE,2)
    put(w,P_WIRE_PHASE,1)
    return config(w,2,WIRE,64,B_COMMAND,128,21)

def bounded_error(w:mutbuf)->u64:
    bounded_error_literal(w)
    return reject(w,2,2,ERROR_TEXT,68)

def wire_reply(o:mutbuf,w:mutbuf)->u64:
    if get(w,C_RETURN) != 128 or get(w,OBS) != WIRE_EVENT or get(w,OBS+120) != 0:
        return refuse(w,1030)
    if get(w,OBS+16) != get(w,P_GRAPH_LEASE) or get(w,OBS+24) != get(w,P_REQUEST) or get(w,OBS+32) != get(w,P_PLAN):
        return refuse(w,1031)
    if get(w,OBS+40) != PLAN_MAX or get(w,OBS+48) != 2 or get(w,OBS+56) != get(w,P_DIGITS):
        return refuse(w,1032)
    action = get(w,OBS+8)
    code = get(w,OBS+64)
    cause = get(w,OBS+72)
    needed = get(w,OBS+80)
    offset = get(w,OBS+88)
    count = get(w,OBS+96)
    current = get(w,OBS+112)
    role = get(w,P_WIRE_ROLE)
    if role != 2 and role != 3:
        return refuse(w,1033)
    if current < get(w,P_WIRE_PHASE):
        return refuse(w,1034)
    if action == 1:
        if code != 0 or cause != 0 or offset != 0 or count != 0 or get(w,OBS+104) != 0:
            return refuse(w,1035)
        if (role == 2 and current != 1) or (role == 3 and current != 2 and current != 3):
            return refuse(w,1036)
        if needed <= cap(w,B_WIRE):
            return refuse(w,1037)
        put(w,P_WIRE_PHASE,current)
        return grow(o,w,B_WIRE,larger(needed,cap(w,B_WIRE)),25)
    if action == 2:
        if role != 2 or code != 0 or cause != 0 or current != 2 or get(w,OBS+104) != 2:
            return refuse(w,1038)
        if offset != 0 or count != 0 or needed > cap(w,B_WIRE):
            return refuse(w,1039)
        put(w,P_WIRE_ROLE,3)
        put(w,P_WIRE_PHASE,2)
        return phase(w,25)
    if action == 3:
        if code == 0 or code > 16 or cause > 1 or current != 99:
            return refuse(w,1040)
        if offset != 0 or count != 0 or get(w,OBS+104) != 0:
            return refuse(w,1041)
        return bounded_error(w)
    if action != 0 or role != 3 or current != 90 or code != 0 or cause != 0 or get(w,OBS+104) != 0:
        return refuse(w,1042)
    if count == 0 or count > PLAN_MAX or needed > cap(w,B_WIRE):
        return refuse(w,1043)
    put(w,P_CANONICAL_N,count)
    return copy_result(w,B_WIRE,offset,count,B_CANONICAL,30)

def check_descriptor(w:mutbuf)->u64:
    if get(w,OBS) != PLAN_RESULT or get(w,OBS+8) != 1:
        return refuse(w,1050)
    if get(w,OBS+16) != get(w,P_GRAPH_LEASE) or get(w,OBS+24) != get(w,P_REQUEST):
        return refuse(w,1051)
    if get(w,OBS+32) != get(w,P_CORE) or get(w,OBS+40) != get(w,P_PLAN):
        return refuse(w,1052)
    if get(w,OBS+48) != get(w,P_VERSION) or get(w,OBS+56) != get(w,P_GRAPH_N):
        return refuse(w,1053)
    i = 0
    while i < 32:
        if byte(w,OBS+64+i) != byte(w,HASH+i):
            return refuse(w,1054)
        i = i + 1
    at = 96
    while at < 128:
        if get(w,OBS+at) != 0:
            return refuse(w,1055)
        at = at + 8
    return phase(w,35)

def make_result(w:mutbuf)->u64:
    fill_range(w,WIRE,256,0)
    put(w,WIRE,RESULT)
    put(w,WIRE+8,1)
    put(w,WIRE+16,get(w,C_LEASE))
    put(w,WIRE+24,get(w,P_REQUEST))
    put(w,WIRE+32,get(w,P_GRAPH_LEASE))
    put(w,WIRE+40,1)
    put(w,WIRE+48,128)
    put(w,WIRE+56,get(w,P_GRAPH_N))
    put(w,WIRE+64,get(w,P_CORE))
    put(w,WIRE+72,get(w,P_PLAN))
    put(w,WIRE+80,get(w,P_VERSION))
    put(w,WIRE+88,B_CANONICAL)
    put(w,WIRE+96,0)
    put(w,WIRE+104,get(w,P_CANONICAL_N))
    put(w,WIRE+112,B_SEMANTICS)
    put(w,WIRE+120,0)
    i = 0
    while i < 32:
        store(w,WIRE+128+i,byte(w,HASH+i))
        i = i + 1
    put(w,WIRE+160,get(w,P_SNAPSHOT_N))
    put(w,WIRE+168,get(w,P_DIGITS))
    put(w,WIRE+176,2)
    put(w,WIRE+184,PLAN_MAX)
    return config(w,2,WIRE,256,B_RESULT,256,36)

def terminal(o:mutbuf,w:mutbuf,error:u64)->u32:
    if get(w,L_STATUS) != 1 or get(w,C_PENDING) != 0:
        return refuse(w,1060)
    put(w,L_STATUS,2)
    fill_range(o,0,128,0)
    put(o,0,EVENT_MAGIC)
    put(o,8,7)
    put(o,16,get(w,C_LEASE))
    put(o,24,get(w,C_SEQUENCE))
    if error == 0:
        put(o,48,B_RESULT)
        put(o,64,256)
    else:
        put(o,32,3)
        put(o,40,get(w,P_ERROR))
        put(o,48,B_ERROR)
        put(o,64,get(w,P_ERROR_N))
    put(o,72,get(w,P_REQUEST))
    put(o,80,get(w,P_GRAPH_LEASE))
    put(o,88,get(w,P_PLAN))
    put(o,96,get(w,P_CORE))
    put(o,104,get(w,P_VERSION))
    put(o,112,get(w,P_CANONICAL_N))
    put(o,120,get(w,P_SNAPSHOT_N))
    return 128

def step(o:mutbuf,w:mutbuf)->u64:
    current = get(w,C_PHASE)
    if current == 10:
        return plan_command(w,0,12)
    if current == 12:
        return call(w,1,B_SNAPSHOT,13)
    if current == 13:
        return plan_reply(o,w,0,20)
    if current == 20:
        return wire_request(w)
    if current == 21:
        return grow(o,w,B_WIRE,PEER_MIN,22)
    if current == 22:
        return clear(o,w,B_WIRE,0,cap(w,B_WIRE),23)
    if current == 23 or current == 25:
        return call(w,get(w,P_WIRE_ROLE),B_WIRE,24)
    if current == 24:
        return wire_reply(o,w)
    if current == 30:
        return plan_command(w,1,31)
    if current == 31:
        return call(w,4,B_SEMANTICS,32)
    if current == 32:
        return plan_reply(o,w,1,33)
    if current == 33:
        return view(o,w,B_SEMANTICS,1024,128,34)
    if current == 34:
        return check_descriptor(w)
    if current == 35:
        return protect(o,w,B_SEMANTICS,1,37)
    if current == 37:
        return make_result(w)
    if current == 36:
        return terminal(o,w,0)
    if current == 5000:
        if cap(w,get(w,P_CALL_WORK)) != 0:
            return protect(o,w,get(w,P_CALL_WORK),0,5001)
        return phase(w,5001)
    if current == 5001:
        return grow(o,w,get(w,P_CALL_WORK),PEER_MIN,5002)
    if current == 5002:
        size = 128
        if get(w,P_CALL_ROLE) == 2 or get(w,P_CALL_ROLE) == 3:
            size = 64
        slot = get(w,P_CALL_WORK)
        return invoke(o,w,get(w,P_CALL_ROLE),1,128,get(w,P_GRAPH_N),B_COMMAND,
            size,slot,cap(w,slot),slot,0,128,get(w,P_CALL_REPLY))
    if current == 6000:
        if cap(w,get(w,P_CONFIG_TARGET)) != 0:
            return protect(o,w,get(w,P_CONFIG_TARGET),0,6001)
        return phase(w,6001)
    if current == 6001:
        return grow(o,w,get(w,P_CONFIG_TARGET),get(w,P_CONFIG_NEED),6002)
    if current == 6002:
        return copy(o,w,get(w,P_CONFIG_SOURCE),get(w,P_CONFIG_AT),
            get(w,P_CONFIG_TARGET),0,get(w,P_CONFIG_N),6003)
    if current == 6003:
        return protect(o,w,get(w,P_CONFIG_TARGET),1,get(w,P_CONFIG_AFTER))
    if current == 6500:
        if cap(w,get(w,P_COPY_TARGET)) != 0:
            return protect(o,w,get(w,P_COPY_TARGET),0,6501)
        return phase(w,6501)
    if current == 6501:
        return grow(o,w,get(w,P_COPY_TARGET),get(w,P_COPY_N),6502)
    if current == 6502:
        return copy(o,w,get(w,P_COPY_SOURCE),get(w,P_COPY_AT),
            get(w,P_COPY_TARGET),0,get(w,P_COPY_N),6503)
    if current == 6503:
        return protect(o,w,get(w,P_COPY_TARGET),1,get(w,P_COPY_AFTER))
    if current == 8000:
        return copy_result(w,get(w,P_ERROR_SLOT),get(w,P_ERROR_AT),
            get(w,P_ERROR_N),B_ERROR,8001)
    if current == 8001:
        return terminal(o,w,1)
    return refuse(w,1061)
'''
def source(common):
    constants=dict(common.CONSTANTS);constants.update(CONSTANTS)
    message=b"E_HIA_MACHINE_PLAN: plan requires bounded plain JSON data"
    # Kept as an exact length constant, not a host runtime error formatter.
    body=BODY.replace("ERROR_TEXT,68)","ERROR_TEXT,"+str(len(message))+")")
    helper="def bounded_error_literal(w:mutbuf)->u64:\n"
    helper+="\n".join("    store(w,ERROR_TEXT+%d,%d)"%(i,c) for i,c in enumerate(message))
    helper+="\n    return 0\n"
    old=common.COMMON
    assert old.count("image > 23")==1
    old=old.replace("image > 23","image > 4")
    own={n.name:copy.deepcopy(n) for n in ast.parse(body+"\n"+helper).body}
    shared={n.name:copy.deepcopy(n) for n in ast.parse(old).body}
    assert set(own).isdisjoint(shared)
    names={**own,**shared};live={"plan_controller"};pending=["plan_controller"]
    while pending:
        for call in ast.walk(names[pending.pop()]):
            if isinstance(call,ast.Call) and isinstance(call.func,ast.Name):
                name=call.func.id
                if name in names and name not in live:
                    live.add(name);pending.append(name)
    nodes=[node for name,node in names.items() if name in live]
    for node in nodes:
        if node.name in ("word","get"):
            arg="s" if node.name=="word" else "w"
            node.body=ast.parse("return "+" | ".join("(byte(%s,at+%d)<<%d)"%(arg,i,8*i) for i in range(8))).body
        elif node.name=="put":
            node.body=ast.parse("\n".join("store(w,at+%d,(value>>%d)&255)"%(i,8*i) for i in range(8))+"\nreturn 0").body
    return "\n".join(ast.unparse(ast.fix_missing_locations(n)) for n in nodes)+"\n",constants,dict(
        status="NEW_UNEXECUTED",scope="ACTUAL_NATIVE_PLAN_SNAPSHOT_WIRE_SEMANTIC_JOIN",
        owner_sha256=OWNER_SHA,common_sha256=COMMON_SHA,
        pure_snapshot_before_actual_bounded_wire=True,
        original_sorted_canonical_plan_before_schema_checks=True,
        full_original_plan_canonical_bytes=True,
        canonical_hash_must_be_computed_by_later_native_outer=True,
        reference_Graph_lease_retained_after_success=True,
        controller_permanent_BAD=True,private_peer_headers_are_not_authentication=True,
        Core_admission_and_public_foreign_capture_required=True,
        standalone_preservation_witness_not_exported=True,
        public_emit_program_machine=False,installed=False,cold=False)
