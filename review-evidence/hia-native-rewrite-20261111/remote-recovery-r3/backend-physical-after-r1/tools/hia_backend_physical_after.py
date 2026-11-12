"""Physical implementation-after join for the exact post-Core backend.
New authoring only. The original 21-role composition is a separate artifact.
Role20 hands the shared private controller context to fixed role23 only after
actual ELF inventory success. Role23 runs the unchanged implementation owner
as role22 and its actual SHA as role19, then returns to20. No host file policy.
"""
import ast,copy
from hashlib import sha256
BASE_SHA="35ce9e9fccfb0601d3d000834c241ae9140eb70449fabc2747ae19e84c1d2a05"
COMMON_SHA="fe63327671ea51ca950b955512a0f574d706176a4a8d050e3f8f12c83ef5e3a1"
FILES_SHA="a7fc5e1f656fdf4bacc3e35b754cc6f113c0b257b49dcc13c9a03fa5a23fc871"
def magic(text):return int.from_bytes(text.encode("ascii"),"little")
EXTRA=dict(PHYSICAL_INIT=magic("HIABFI01"),FILES_INIT=magic("HIAIFI01"),
 FILES_RESULT=magic("HIAIFR01"),FILES_FAILURE=magic("HIABFE01"),
 FILES_DRIVER=23,FILES_OWNER=22,FILES_HASH=19,
 FILES_INPUT=39,FILES_WORK=40,FILES_OUTPUT=41,FILES_ACK=42,
 FILES_SLOT_BASE=39,FILES_EVENT=32256,FILES_TERMINAL=32384,
 FILES_DESCRIPTOR=32512,FILES_WORK_BYTES=65536,FILES_INPUT_HEADER=64)
FIELDS=("STATE","LEASE","LAST","OP","OBSERVED","READONLY","FIRST","FIRST_N",
 "RETIRE","KIND","ERROR_OP","ERRNO","PATH_N","DONE","FILE_BYTES","HASH_BYTES",
 "CLOSE_ERRNO","FILE_INDEX","HAS_FILENAME","DIRECTORY_AT","DIRECTORY_N",
 "ERROR_N","RETURNED")
EXTRA.update({"F_"+name:32000+8*i for i,name in enumerate(FIELDS)})
assert 32000+8*len(FIELDS)<=32256
PARENT=r'''
def backend_files_header(s:readbuf)->u64:
    directory = word(s,96)
    size = word(s,104)
    lease = word(s,112)
    if directory != INPUT_HEADER+word(s,72) or directory > length(s) or size != length(s)-directory or size > MAX-64:
        return 0
    if lease == 0 or lease == word(s,16) or lease == word(s,48) or lease == word(s,56) or word(s,120) != 0:
        return 0
    at = 0
    while at < size:
        if byte(s,directory+at) == 0:
            return 0
        at = at+1
    at = 224
    while at < 256:
        if byte(s,at) != 0:
            return 0
        at = at+1
    return 1

def backend_files_start(w:mutbuf)->u64:
    if get(w,F_STATE) != 0 or get(w,CB_ACTIVE) != 2 or get(w,CB_KIND) != 2:
        return refuse(w,4200)
    slot = FILES_INPUT
    while slot <= 49:
        if cap(w,slot) != 0:
            return refuse(w,4201)
        slot = slot+1
    fill_range(w,WIRE,64,0)
    put(w,WIRE,FILES_INIT)
    put(w,WIRE+8,1)
    put(w,WIRE+16,get(w,F_LEASE))
    put(w,WIRE+24,get(w,O_REQUEST))
    put(w,WIRE+32,64)
    put(w,WIRE+40,get(w,F_DIRECTORY_N))
    put(w,WIRE+48,64+get(w,F_DIRECTORY_N))
    put(w,F_STATE,1)
    put(w,F_READONLY,3)
    put(w,F_FIRST,FILES_INPUT)
    put(w,F_FIRST_N,64+get(w,F_DIRECTORY_N))
    return outer_copy(w,2,WIRE,64,FILES_INPUT,0,64+get(w,F_DIRECTORY_N),0,450)

def backend_files_handoff(o:mutbuf,w:mutbuf,target:u64,phase:u64)->u64:
    current = get(w,L_DRIVER)
    if (current != 20 or target != 23 or phase != 14000) and (current != 23 or target != 20 or phase != 453):
        return refuse(w,4202)
    put(w,L_NEXT_DRIVER,target)
    put(w,C_OBSERVE,0)
    args(w,target,0,0,0,0,0,0,0,0,0,0,0)
    return event(o,w,8,phase)

def backend_files_resumed(o:mutbuf,w:mutbuf)->u64:
    if get(w,F_STATE) != 4 or get(w,F_RETURNED) != 1 or get(w,C_RETURN) != 0:
        return refuse(w,4203)
    slot = FILES_INPUT
    while slot <= 49:
        if cap(w,slot) != 0:
            return refuse(w,4204)
        slot = slot+1
    put(w,F_RETURNED,2)
    kind = get(w,F_KIND)
    if kind == 0:
        outer_local_copy(w,WIRE,H_IMPL_AFTER,32)
        return outer_copy(w,2,WIRE,32,B_POST_COMMAND,288,get(w,O_POST_N),1,454)
    if kind == 1:
        if get(w,F_ERRNO) == 0 or get(w,F_ERRNO) > 4095:
            return refuse(w,4205)
        return outer_terminal(o,w,5,get(w,F_ERRNO),B_ERROR,get(w,F_ERROR_N))
    if kind == 2:
        return outer_terminal(o,w,6,1,B_ERROR,get(w,F_ERROR_N))
    return refuse(w,4206)
'''
CHILD=r'''
def backend_files_driver(s:readbuf,o:mutbuf,w:mutbuf)->u32:
    if length(w) < MIN_WORK or length(o) < 128:
        return ABI
    if files_parent_ack(s,w) == 0:
        return refuse(w,4300)
    result = 0
    while result == 0:
        if get(w,L_STATUS) != 1 or get(w,L_DRIVER) != FILES_DRIVER:
            return refuse(w,4301)
        phase = get(w,C_PHASE)
        if phase < 14000 or phase > 14090:
            return refuse(w,4302)
        result = files_bridge_step(o,w,phase)
    return result

def files_parent_ack(s:readbuf,w:mutbuf)->u64:
    if get(w,C_PENDING) != 19:
        return acknowledge(s,w,FILES_DRIVER)
    if get(w,L_MAGIC) != LOWER_MAGIC or get(w,L_STATUS) != 1 or get(w,L_DRIVER) != FILES_DRIVER:
        return 0
    observed = get(w,C_OBSERVE)
    if (observed != 0 and observed != 144) or length(s) != 64+observed:
        return 0
    if word(s,0) != ACK_MAGIC or word(s,8) != get(w,C_LEASE) or word(s,16) != get(w,C_SEQUENCE):
        return 0
    if word(s,24) != 19 or word(s,32) != 0 or word(s,48) != observed or word(s,56) != 0:
        return 0
    if get(w,F_STATE) != 1 or get(w,F_OP) != 19 or get(w,C_NEXT) != 14030:
        return 0
    operation = get(w,FILES_EVENT+32)
    if operation == 4:
        if observed != 144:
            return 0
    elif observed != 0 or operation == 0 or operation > 3:
        return 0
    put(w,C_RETURN,word(s,40))
    at = 0
    while at < observed:
        store(w,OBS+at,byte(s,64+at))
        at = at+1
    put(w,C_PENDING,0)
    put(w,C_PHASE,get(w,C_NEXT))
    put(w,C_OBSERVE,0)
    return 1

def files_bridge_slot(slot:u64)->u64:
    if slot == 0:
        return 0
    if slot == 1:
        return FILES_INPUT
    if slot == 2:
        return FILES_WORK
    if slot == 3:
        return FILES_OUTPUT
    if slot < 4 or slot > 10:
        return MAX
    return FILES_SLOT_BASE+slot

def files_bridge_inside(w:mutbuf,slot:u64,at:u64,size:u64)->u64:
    mapped = files_bridge_slot(slot)
    if mapped == MAX:
        return 0
    return inside(w,mapped,at,size)

def files_bridge_readonly(w:mutbuf,slot:u64)->u64:
    if slot > 10:
        return 0
    return (get(w,F_READONLY) >> slot) & 1

def files_bridge_tail(w:mutbuf,first:u64)->u64:
    while first < 128:
        if get(w,FILES_EVENT+first) != 0:
            return 0
        first = first+8
    return 1

def files_bridge_phase(w:mutbuf,phase:u64)->u64:
    put(w,C_PHASE,phase)
    return 0

def files_bridge_call(o:mutbuf,w:mutbuf)->u64:
    at = FILES_EVENT+32
    first = get(w,at+8)
    second = get(w,at+32)
    work = get(w,at+48)
    observe = get(w,at+64)
    count = get(w,at+80)
    if get(w,at) != 2 or first != 6 or second != 7 or work != 8 or observe != 7:
        return refuse(w,4310)
    if get(w,at+16) != 0 or get(w,at+40) != 32 or get(w,at+56) != 1184 or get(w,at+72) != 0:
        return refuse(w,4311)
    if (count != 0 and count != 32) or files_bridge_tail(w,120) == 0:
        return refuse(w,4312)
    if files_bridge_readonly(w,first) != 1 or files_bridge_readonly(w,second) != 0 or files_bridge_readonly(w,work) != 0:
        return refuse(w,4313)
    if files_bridge_inside(w,first,0,get(w,at+24)) == 0:
        return refuse(w,4314)
    if files_bridge_inside(w,second,0,32) == 0 or files_bridge_inside(w,work,0,1184) == 0:
        return refuse(w,4315)
    put(w,F_OBSERVED,count)
    return invoke(o,w,FILES_HASH,files_bridge_slot(first),0,get(w,at+24),
        files_bridge_slot(second),32,files_bridge_slot(work),1184,
        files_bridge_slot(observe),0,count,14030)

def files_bridge_copy(o:mutbuf,w:mutbuf)->u64:
    at = FILES_EVENT+32
    first = get(w,at)
    target = get(w,at+16)
    count = get(w,at+32)
    if first == target or target < 4 or target > 10 or files_bridge_tail(w,72) == 0:
        return refuse(w,4316)
    if files_bridge_inside(w,first,get(w,at+8),count) == 0 or files_bridge_inside(w,target,get(w,at+24),count) == 0:
        return refuse(w,4317)
    if files_bridge_readonly(w,target) != 0:
        return refuse(w,4318)
    return copy(o,w,files_bridge_slot(first),get(w,at+8),
        files_bridge_slot(target),get(w,at+24),count,14030)

def files_bridge_simple(o:mutbuf,w:mutbuf)->u64:
    operation = get(w,F_OP)
    at = FILES_EVENT+32
    slot = get(w,at)
    if operation == 14:
        count = get(w,at+16)
        if count > 256 or files_bridge_tail(w,56) == 0 or files_bridge_inside(w,slot,get(w,at+8),count) == 0:
            return refuse(w,4319)
        put(w,F_OBSERVED,count)
        return view(o,w,files_bridge_slot(slot),get(w,at+8),count,14030)
    if slot < 4 or slot > 10:
        return refuse(w,4320)
    mapped = files_bridge_slot(slot)
    if operation == 2:
        size = get(w,at+8)
        if size == 0 or size <= cap(w,mapped) or files_bridge_tail(w,48) == 0:
            return refuse(w,4321)
        return grow(o,w,mapped,size,14030)
    if operation == 3:
        if files_bridge_tail(w,56) == 0 or files_bridge_readonly(w,slot) != 0:
            return refuse(w,4322)
        if files_bridge_inside(w,slot,get(w,at+8),get(w,at+16)) == 0:
            return refuse(w,4323)
        return clear(o,w,mapped,get(w,at+8),get(w,at+16),14030)
    if operation == 5:
        if cap(w,mapped) == 0 or files_bridge_tail(w,40) == 0:
            return refuse(w,4324)
        return release(o,w,mapped,14030)
    if operation == 6:
        readonly = get(w,at+8)
        if readonly > 1 or cap(w,mapped) == 0 or files_bridge_tail(w,48) == 0:
            return refuse(w,4325)
        return protect(o,w,mapped,readonly,14030)
    return refuse(w,4326)

def files_bridge_sys(o:mutbuf,w:mutbuf)->u64:
    at = FILES_EVENT+32
    kind = get(w,at)
    put(w,F_OBSERVED,0)
    put(w,C_OBSERVE,0)
    if kind == 1:
        if get(w,at+8) != 4 or get(w,at+16) != 0 or get(w,at+32) != 524288 or files_bridge_tail(w,72) == 0:
            return refuse(w,4330)
        size = get(w,at+24)
        if size == 0 or files_bridge_readonly(w,4) != 1 or files_bridge_inside(w,4,0,size) == 0:
            return refuse(w,4331)
        args(w,1,files_bridge_slot(4),0,size,524288,0,0,0,0,0,0,0)
    elif kind == 2 or kind == 4:
        slot = choose(kind == 2,5,10)
        count = choose(kind == 2,65536,144)
        if get(w,at+8) != 1 or get(w,at+16) != slot or get(w,at+24) != 0 or get(w,at+32) != count:
            return refuse(w,4332)
        if files_bridge_tail(w,72) == 0 or files_bridge_readonly(w,slot) != 0 or files_bridge_inside(w,slot,0,count) == 0:
            return refuse(w,4333)
        if kind == 4:
            put(w,F_OBSERVED,144)
            put(w,C_OBSERVE,144)
        args(w,kind,1,files_bridge_slot(slot),0,count,0,0,0,0,0,0,0)
    elif kind == 3:
        if get(w,at+8) != 1 or files_bridge_tail(w,48) == 0:
            return refuse(w,4334)
        args(w,3,1,0,0,0,0,0,0,0,0,0,0)
    else:
        return refuse(w,4335)
    return event(o,w,19,14030)

def files_bridge_received(o:mutbuf,w:mutbuf)->u64:
    if get(w,C_RETURN) != 128 or get(w,OBS) != EVENT_MAGIC or get(w,OBS+16) != get(w,F_LEASE):
        return refuse(w,4340)
    operation = get(w,OBS+8)
    sequence = get(w,OBS+24)
    if operation == 7:
        if sequence != get(w,F_LAST):
            return refuse(w,4341)
        at = 0
        while at < 128:
            store(w,FILES_TERMINAL+at,byte(w,OBS+at))
            at = at+1
        put(w,F_STATE,2)
        return files_bridge_phase(w,14040)
    if get(w,F_LAST) == MAX or sequence != get(w,F_LAST)+1:
        return refuse(w,4342)
    if operation != 1 and operation != 2 and operation != 3 and operation != 4 and operation != 5 and operation != 6 and operation != 14 and operation != 19:
        return refuse(w,4343)
    at = 0
    while at < 128:
        store(w,FILES_EVENT+at,byte(w,OBS+at))
        at = at+1
    put(w,F_LAST,sequence)
    put(w,F_OP,operation)
    put(w,F_OBSERVED,0)
    if operation == 1:
        return files_bridge_call(o,w)
    if operation == 4:
        return files_bridge_copy(o,w)
    if operation == 19:
        return files_bridge_sys(o,w)
    return files_bridge_simple(o,w)

def files_bridge_ack(w:mutbuf)->u64:
    observed = get(w,F_OBSERVED)
    operation = get(w,F_OP)
    if observed > 256:
        return refuse(w,4344)
    if operation != 1 and operation != 19 and get(w,C_RETURN) != 0:
        return refuse(w,4345)
    if operation == 2 or operation == 5 or operation == 6:
        slot = get(w,FILES_EVENT+32)
        if slot < 4 or slot > 10:
            return refuse(w,4346)
        readonly = get(w,F_READONLY) & (MAX ^ (1 << slot))
        if operation == 6 and get(w,FILES_EVENT+40) != 0:
            readonly = readonly | (1 << slot)
        put(w,F_READONLY,readonly)
    fill_range(w,WIRE,320,0)
    put(w,WIRE,ACK_MAGIC)
    put(w,WIRE+8,get(w,F_LEASE))
    put(w,WIRE+16,get(w,F_LAST))
    put(w,WIRE+24,operation)
    put(w,WIRE+40,get(w,C_RETURN))
    put(w,WIRE+48,observed)
    at = 0
    while at < observed:
        store(w,WIRE+64+at,byte(w,OBS+at))
        at = at+1
    put(w,F_FIRST,FILES_ACK)
    put(w,F_FIRST_N,64+observed)
    return files_bridge_phase(w,14031)

def files_bridge_terminal(w:mutbuf)->u64:
    at = FILES_TERMINAL
    kind = get(w,at+32)
    if kind > 2 or get(w,at+48) != 9 or get(w,at+56) != 0 or get(w,at+64) != 128:
        return refuse(w,4350)
    if get(w,at+72) > 20 or files_bridge_readonly(w,9) != 1 or files_bridge_inside(w,9,0,128) == 0:
        return refuse(w,4351)
    position = 96
    while position < 128:
        if get(w,at+position) != 0:
            return refuse(w,4352)
        position = position+8
    return files_bridge_phase(w,14041)

def files_bridge_descriptor(w:mutbuf)->u64:
    if get(w,OBS) != FILES_RESULT or get(w,OBS+8) != 1 or get(w,OBS+16) != get(w,F_LEASE) or get(w,OBS+24) != get(w,O_REQUEST):
        return refuse(w,4353)
    kind = get(w,OBS+32)
    count = get(w,OBS+40)
    operation = get(w,OBS+64)
    number = get(w,OBS+72)
    fileindex = get(w,OBS+80)
    close = get(w,OBS+104)
    filename = get(w,OBS+112)
    if kind != get(w,FILES_TERMINAL+32) or count != get(w,FILES_TERMINAL+72):
        return refuse(w,4354)
    if get(w,OBS+48) != get(w,FILES_TERMINAL+80) or get(w,OBS+56) != get(w,FILES_TERMINAL+88):
        return refuse(w,4355)
    if operation != get(w,FILES_TERMINAL+40) or get(w,OBS+120) != 0 or filename > 1:
        return refuse(w,4356)
    if kind == 0:
        if count != 20 or operation != 0 or number != 0 or fileindex != 0 or close != 0 or filename != 0:
            return refuse(w,4357)
        if get(w,OBS+88) != 7 or get(w,OBS+96) != 32 or files_bridge_readonly(w,7) != 1 or files_bridge_inside(w,7,0,32) == 0:
            return refuse(w,4358)
    else:
        if kind > 2 or count >= 20 or fileindex != count or get(w,OBS+88) != 4:
            return refuse(w,4359)
        size = get(w,OBS+96)
        if size == 0 or size == MAX or files_bridge_readonly(w,4) != 1 or files_bridge_inside(w,4,0,size+1) == 0:
            return refuse(w,4360)
        if kind == 1:
            if operation == 0 or operation > 5 or number == 0 or number > 4095 or close > 4095:
                return refuse(w,4361)
            if filename != choose(operation == 1 or operation == 5,1,0):
                return refuse(w,4362)
            if close != 0 and (operation != 3 or close != number):
                return refuse(w,4363)
        else:
            if operation != 2 or number != 0 or close != 0 or filename != 0:
                return refuse(w,4364)
        put(w,F_PATH_N,size)
    put(w,F_KIND,kind)
    put(w,F_ERROR_OP,operation)
    put(w,F_ERRNO,number)
    put(w,F_DONE,count)
    put(w,F_FILE_BYTES,get(w,OBS+48))
    put(w,F_HASH_BYTES,get(w,OBS+56))
    put(w,F_FILE_INDEX,fileindex)
    put(w,F_CLOSE_ERRNO,close)
    put(w,F_HAS_FILENAME,filename)
    at = 0
    while at < 128:
        store(w,FILES_DESCRIPTOR+at,byte(w,OBS+at))
        at = at+1
    return files_bridge_phase(w,choose(kind == 0,14043,14050))

def files_bridge_error_header(w:mutbuf)->u64:
    if get(w,F_PATH_N) > MAX-128:
        return refuse(w,4365)
    size = 128+get(w,F_PATH_N)
    put(w,F_ERROR_N,size)
    fill_range(w,WIRE,128,0)
    put(w,WIRE,FILES_FAILURE)
    put(w,WIRE+8,1)
    put(w,WIRE+16,get(w,C_LEASE))
    put(w,WIRE+24,get(w,O_REQUEST))
    put(w,WIRE+32,get(w,F_LEASE))
    put(w,WIRE+40,get(w,F_KIND))
    put(w,WIRE+48,get(w,F_ERROR_OP))
    put(w,WIRE+56,get(w,F_ERRNO))
    put(w,WIRE+64,get(w,F_FILE_INDEX))
    put(w,WIRE+72,get(w,F_CLOSE_ERRNO))
    put(w,WIRE+80,get(w,F_HAS_FILENAME))
    put(w,WIRE+88,128)
    put(w,WIRE+96,get(w,F_PATH_N))
    put(w,WIRE+104,size)
    return files_bridge_phase(w,14051)

def files_bridge_step(o:mutbuf,w:mutbuf,phase:u64)->u64:
    if phase == 14000:
        if get(w,F_STATE) != 1 or get(w,F_LAST) != 0 or get(w,F_RETURNED) != 0:
            return refuse(w,4370)
        return grow(o,w,FILES_WORK,FILES_WORK_BYTES,14001)
    if phase == 14001:
        return clear(o,w,FILES_WORK,0,FILES_WORK_BYTES,14002)
    if phase == 14002:
        return grow(o,w,FILES_OUTPUT,128,14003)
    if phase == 14003:
        return clear(o,w,FILES_OUTPUT,0,128,14004)
    if phase == 14004:
        return grow(o,w,FILES_ACK,320,14010)
    if phase == 14010:
        if get(w,F_STATE) != 1:
            return refuse(w,4371)
        return invoke(o,w,FILES_OWNER,get(w,F_FIRST),0,get(w,F_FIRST_N),
            FILES_OUTPUT,128,FILES_WORK,FILES_WORK_BYTES,FILES_OUTPUT,0,128,14011)
    if phase == 14011:
        return files_bridge_received(o,w)
    if phase == 14030:
        return files_bridge_ack(w)
    if phase == 14031:
        return protect(o,w,FILES_ACK,0,14032)
    if phase == 14032:
        return copy(o,w,2,WIRE,FILES_ACK,0,get(w,F_FIRST_N),14033)
    if phase == 14033:
        return protect(o,w,FILES_ACK,1,14010)
    if phase == 14040:
        return files_bridge_terminal(w)
    if phase == 14041:
        return view(o,w,files_bridge_slot(9),0,128,14042)
    if phase == 14042:
        return files_bridge_descriptor(w)
    if phase == 14043:
        return view(o,w,files_bridge_slot(7),0,32,14044)
    if phase == 14044:
        at = 0
        while at < 32:
            store(w,H_IMPL_AFTER+at,byte(w,OBS+at))
            at = at+1
        return files_bridge_phase(w,14060)
    if phase == 14050:
        return files_bridge_error_header(w)
    if phase == 14051:
        return grow(o,w,B_ERROR,get(w,F_ERROR_N),14052)
    if phase == 14052:
        return copy(o,w,2,WIRE,B_ERROR,0,128,14053)
    if phase == 14053:
        return copy(o,w,files_bridge_slot(4),0,B_ERROR,128,get(w,F_PATH_N),14054)
    if phase == 14054:
        return protect(o,w,B_ERROR,1,14060)
    if phase == 14060:
        if get(w,F_STATE) != 2:
            return refuse(w,4372)
        put(w,F_STATE,3)
        put(w,F_RETIRE,FILES_INPUT)
        return files_bridge_phase(w,14061)
    if phase == 14061:
        slot = get(w,F_RETIRE)
        if slot > 49:
            return files_bridge_phase(w,14062)
        put(w,F_RETIRE,slot+1)
        return release(o,w,slot,14061)
    if phase == 14062:
        put(w,F_STATE,4)
        put(w,F_RETURNED,1)
        return backend_files_handoff(o,w,20,453)
    return refuse(w,4373)
'''
def replace_one(text,old,new):
 assert old!=new and text.count(old)==1,(old,text.count(old))
 out=text.replace(old,new,1)
 assert out.count(new)==1 and out.replace(new,old,1)==text
 return out
def changed_body(backend,raw):
 assert sha256(raw).hexdigest()==BASE_SHA
 body=backend.BODY
 edits=[]
 def change(old,new):
  nonlocal body
  body=replace_one(body,old,new);edits.append(dict(old=old,new=new))
 change('word(s,0) != INIT or word(s,8) != 1',
        'word(s,0) != PHYSICAL_INIT or word(s,8) != 2')
 change('size != length(s)-INPUT_HEADER','size > length(s)-INPUT_HEADER')
 change('''    at = 96
    while at < 128:
        if word(s,at) != 0:
            return 0
        at = at+8
''','''    if backend_files_header(s) == 0:
        return 0
''')
 change('''    copy_bytes(w,s,HASHES,128,128)
''','''    copy_bytes(w,s,HASHES,128,96)
    put(w,F_LEASE,word(s,112))
    put(w,F_DIRECTORY_AT,word(s,96))
    put(w,F_DIRECTORY_N,word(s,104))
''')
 change('''    if phase == 45:
        return implementation_checked(w)
''','''    if phase == 45:
        return backend_files_start(w)
    if phase == 450:
        return copy(o,w,1,get(w,F_DIRECTORY_AT),FILES_INPUT,64,get(w,F_DIRECTORY_N),451)
    if phase == 451:
        return protect(o,w,FILES_INPUT,1,452)
    if phase == 452:
        return backend_files_handoff(o,w,23,14000)
    if phase == 453:
        return backend_files_resumed(o,w)
    if phase == 454:
        return implementation_checked(w)
''')
 restored=body
 for row in reversed(edits):
  assert restored.count(row["new"])==1
  restored=restored.replace(row["new"],row["old"],1)
 assert restored==backend.BODY
 return body,edits
def source(common,forwarder,backend,raw,role):
 assert role in (20,23)
 body,edits=changed_body(backend,raw)
 constants=dict(common.CONSTANTS)
 constants.update(forwarder.CONSTANTS)
 constants.update(backend.CONSTANTS)
 constants.update(EXTRA)
 entry="backend_controller" if role==20 else "backend_files_driver"
 extra=PARENT if role==20 else CHILD+"\n"+PARENT
 nodes=ast.parse(body+"\n"+forwarder.BODY+"\n"+extra+"\n"+common.COMMON).body
 functions={node.name:node for node in nodes}
 assert len(functions)==len(nodes)
 keep={entry};todo=[entry]
 while todo:
  for node in ast.walk(functions[todo.pop()]):
   if isinstance(node,ast.Call) and isinstance(node.func,ast.Name):
    name=node.func.id
    if name in functions and name not in keep:keep.add(name);todo.append(name)
 selected=[copy.deepcopy(functions[entry])]
 selected.extend(copy.deepcopy(node) for node in nodes if node.name in keep and node.name!=entry)
 for node in selected:
  if node.name in ("word","get"):
   arg="s" if node.name=="word" else "w"
   node.body=ast.parse("return "+" | ".join("(byte(%s,at+%d)<<%d)"%(arg,i,8*i) for i in range(8))).body
  elif node.name=="put":
   node.body=ast.parse("\n".join("store(w,at+%d,(value>>%d)&255)"%(i,8*i) for i in range(8))+"\nreturn 0").body
 assert constants["O_INSPECT_AT"]+8<32000
 assert constants["F_RETURNED"]+8<=constants["FILES_EVENT"]
 assert constants["FILES_EVENT"]+128==constants["FILES_TERMINAL"]
 assert constants["FILES_TERMINAL"]+128==constants["FILES_DESCRIPTOR"]
 assert constants["FILES_DESCRIPTOR"]+128<constants["MIN_WORK"]
 return "\n".join(ast.unparse(ast.fix_missing_locations(node)) for node in selected)+"\n",constants,dict(
  status="NEW_UNEXECUTED",role=role,entry=entry,
  exact_parent_edits=edits,base_author_sha256=BASE_SHA,
  unchanged_implementation_owner_sha256=FILES_SHA,
  implementation_after_is_actual_file_child_after_ELF_inventory=True,
  implementation_before_authority_still_issued_by_parent=True,
  no_precomputed_after_digest_in_input=True,all_original_backend_semantic_owners_unchanged=True,
  files_fixed_roles={"root":22,"hash":19,"mechanical_driver":23},
  only_shared_context_switch_edges=[[20,23],[23,20]],
  separate_file_slots=list(range(39,50)),
  actual_FD_source_and_RO_immutable_lifetimes_required=True,
  error_capsule_retains_actual_errno_and_complete_path=True,
  full_public_error_presentation=False,whole_public_build=False,
  installed=False,cold=False,AST=0,B3=0,VM=0,native=0)
