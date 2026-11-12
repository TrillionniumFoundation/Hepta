"""HIA-owned finite child-command forwarding for the native machine backend.
Development source only. The two immutable child programs are the existing
checked-plan controller and the existing complete Emitter controller. This
library maps their logical slots and image roles; no host inspects their policy.
"""
import ast
COMMON_SHA="fe63327671ea51ca950b955512a0f574d706176a4a8d050e3f8f12c83ef5e3a1"
PLAN_SHA="d15c8141db699d1f6df0e6753f6220905903911cf6bd1a01accc41fbbf5103f6"
EMITTER_SHA="7b706ef28c91d57a36d567ce701501dfa9ed025f4e27278cf629ace6bf011398"
CONSTANTS=dict(CB_ACK_SLOT=5,CB_INPUT_SLOT=7,CB_WORK_SLOT=8,CB_OUTPUT_SLOT=9,
 CB_SLOT_BASE=16,CB_FIRST_PHASE=12000,CB_EVENT_AT=24128,CB_TERMINAL_AT=24256)
FIELDS=("ACTIVE","KIND","LEASE","AFTER","LAST","OP","OBSERVED","FIRST",
 "FIRST_N","READONLY","ROLE","LIMIT","CURRENT","RETIRE_AFTER","RETURN")
CONSTANTS.update({"CB_"+name:24000+8*i for i,name in enumerate(FIELDS)})
assert max(CONSTANTS["CB_"+name]+8 for name in FIELDS)<=CONSTANTS["CB_EVENT_AT"]
BODY=r'''
def cb_slot(w:mutbuf,slot:u64)->u64:
    if slot > get(w,CB_LIMIT):
        refuse(w,2000)
        return MAX
    if slot == 0:
        return 0
    if slot == 1:
        return CB_INPUT_SLOT
    if slot == 2:
        return CB_WORK_SLOT
    if slot == 3:
        return CB_OUTPUT_SLOT
    return CB_SLOT_BASE+slot

def cb_readonly(w:mutbuf,slot:u64)->u64:
    if slot > get(w,CB_LIMIT):
        return 0
    return (get(w,CB_READONLY) >> slot) & 1

def cb_inside(w:mutbuf,slot:u64,at:u64,count:u64)->u64:
    actual = cb_slot(w,slot)
    if actual == MAX:
        return 0
    return inside(w,actual,at,count)

def cb_zero_tail(w:mutbuf,first:u64)->u64:
    at = first
    while at < 128:
        if get(w,CB_EVENT_AT+at) != 0:
            return 0
        at = at+8
    return 1

def cb_phase(w:mutbuf,next:u64)->u64:
    put(w,C_PHASE,next)
    return 0

def cb_start(w:mutbuf,kind:u64,lease:u64,after:u64)->u64:
    if get(w,CB_ACTIVE) != 0 or (kind != 1 and kind != 2) or lease == 0 or lease == get(w,C_LEASE):
        return refuse(w,2001)
    if cap(w,CB_INPUT_SLOT) < 192 or cap(w,CB_WORK_SLOT) != 0 or cap(w,CB_OUTPUT_SLOT) != 0 or cap(w,CB_ACK_SLOT) != 0:
        return refuse(w,2002)
    slot = 20
    while slot <= 34:
        if cap(w,slot) != 0:
            return refuse(w,2003)
        slot = slot+1
    fill_range(w,24000,384,0)
    put(w,CB_ACTIVE,1)
    put(w,CB_KIND,kind)
    put(w,CB_LEASE,lease)
    put(w,CB_AFTER,after)
    put(w,CB_LIMIT,choose(kind == 1,10,18))
    put(w,CB_ROLE,choose(kind == 1,16,11))
    put(w,CB_READONLY,3)
    put(w,CB_FIRST,CB_INPUT_SLOT)
    put(w,CB_FIRST_N,cap(w,CB_INPUT_SLOT))
    return cb_phase(w,12000)

def cb_retire(w:mutbuf,after:u64)->u64:
    if get(w,CB_ACTIVE) != 2:
        return refuse(w,2004)
    put(w,CB_ACTIVE,3)
    put(w,CB_CURRENT,4)
    put(w,CB_RETIRE_AFTER,after)
    return cb_phase(w,12080)

def cb_role(w:mutbuf,image:u64)->u64:
    if get(w,CB_KIND) == 1:
        if image == 0 or image > 4:
            return 0
        return image+11
    if get(w,CB_KIND) == 2:
        if image == 0 or image > 10:
            return 0
        return image
    return 0

def cb_call(o:mutbuf,w:mutbuf)->u64:
    at = CB_EVENT_AT+32
    role = cb_role(w,get(w,at))
    first = get(w,at+8)
    second = get(w,at+32)
    work = get(w,at+48)
    observe = get(w,at+64)
    count = get(w,at+80)
    if role == 0 or first == second or first == work or second == work or work < 4:
        return refuse(w,2005)
    if cb_zero_tail(w,120) == 0 or count > 256:
        return refuse(w,2006)
    if cb_inside(w,first,get(w,at+16),get(w,at+24)) == 0:
        return refuse(w,2007)
    if cb_inside(w,second,0,get(w,at+40)) == 0 or cb_inside(w,work,0,get(w,at+56)) == 0:
        return refuse(w,2008)
    if cb_inside(w,observe,get(w,at+72),count) == 0 or cb_readonly(w,work) != 0:
        return refuse(w,2009)
    if role == 7:
        if second < 4 or cb_readonly(w,second) != 0:
            return refuse(w,2010)
    put(w,CB_OBSERVED,count)
    return invoke(o,w,role,cb_slot(w,first),get(w,at+16),get(w,at+24),
        cb_slot(w,second),get(w,at+40),cb_slot(w,work),get(w,at+56),
        cb_slot(w,observe),get(w,at+72),count,12030)

def cb_simple(o:mutbuf,w:mutbuf)->u64:
    op = get(w,CB_OP)
    at = CB_EVENT_AT+32
    first = get(w,at)
    if op == 14:
        count = get(w,at+16)
        if cb_zero_tail(w,56) == 0 or count > 256 or cb_inside(w,first,get(w,at+8),count) == 0:
            return refuse(w,2011)
        put(w,CB_OBSERVED,count)
        return view(o,w,cb_slot(w,first),get(w,at+8),count,12030)
    if first < 4 or first > get(w,CB_LIMIT):
        return refuse(w,2012)
    mapped = cb_slot(w,first)
    if op == 2:
        size = get(w,at+8)
        if cb_zero_tail(w,48) == 0 or size == 0 or size <= cap(w,mapped):
            return refuse(w,2013)
        return grow(o,w,mapped,size,12030)
    if op == 3:
        offset = get(w,at+8)
        count = get(w,at+16)
        if cb_zero_tail(w,56) == 0 or cb_inside(w,first,offset,count) == 0 or cb_readonly(w,first) != 0:
            return refuse(w,2014)
        return clear(o,w,mapped,offset,count,12030)
    if op == 5:
        if cb_zero_tail(w,40) == 0 or cap(w,mapped) == 0:
            return refuse(w,2015)
        return release(o,w,mapped,12030)
    if op == 6:
        readonly = get(w,at+8)
        if cb_zero_tail(w,48) == 0 or readonly > 1 or cap(w,mapped) == 0:
            return refuse(w,2016)
        return protect(o,w,mapped,readonly,12030)
    return refuse(w,2017)

def cb_copy(o:mutbuf,w:mutbuf)->u64:
    at = CB_EVENT_AT+32
    first = get(w,at)
    target = get(w,at+16)
    count = get(w,at+32)
    if first == target or target < 4 or cb_zero_tail(w,72) == 0:
        return refuse(w,2018)
    if cb_inside(w,first,get(w,at+8),count) == 0 or cb_inside(w,target,get(w,at+24),count) == 0:
        return refuse(w,2019)
    if cb_readonly(w,target) != 0:
        return refuse(w,2020)
    return copy(o,w,cb_slot(w,first),get(w,at+8),cb_slot(w,target),get(w,at+24),count,12030)

def cb_received(o:mutbuf,w:mutbuf)->u64:
    if get(w,C_RETURN) != 128 or get(w,OBS) != EVENT_MAGIC or get(w,OBS+16) != get(w,CB_LEASE):
        return refuse(w,2021)
    op = get(w,OBS+8)
    sequence = get(w,OBS+24)
    if op == 7:
        if sequence != get(w,CB_LAST):
            return refuse(w,2022)
        at = 0
        while at < 128:
            store(w,CB_TERMINAL_AT+at,byte(w,OBS+at))
            at = at+1
        put(w,CB_ACTIVE,2)
        return cb_phase(w,get(w,CB_AFTER))
    if get(w,CB_LAST) == MAX or sequence != get(w,CB_LAST)+1:
        return refuse(w,2023)
    if op != 1 and op != 2 and op != 3 and op != 4 and op != 5 and op != 6 and op != 14:
        return refuse(w,2024)
    at = 0
    while at < 128:
        store(w,CB_EVENT_AT+at,byte(w,OBS+at))
        at = at+1
    put(w,CB_LAST,sequence)
    put(w,CB_OP,op)
    put(w,CB_OBSERVED,0)
    if op == 1:
        return cb_call(o,w)
    if op == 4:
        return cb_copy(o,w)
    return cb_simple(o,w)

def cb_ack(w:mutbuf)->u64:
    observed = get(w,CB_OBSERVED)
    op = get(w,CB_OP)
    if observed > 256 or (op != 1 and get(w,C_RETURN) != 0):
        return refuse(w,2025)
    if op == 2 or op == 5 or op == 6:
        slot = get(w,CB_EVENT_AT+32)
        if slot < 4 or slot > get(w,CB_LIMIT):
            return refuse(w,2026)
        readonly = get(w,CB_READONLY) & (MAX ^ (1 << slot))
        if op == 6 and get(w,CB_EVENT_AT+40) != 0:
            readonly = readonly | (1 << slot)
        put(w,CB_READONLY,readonly)
    fill_range(w,WIRE,320,0)
    put(w,WIRE,ACK_MAGIC)
    put(w,WIRE+8,get(w,CB_LEASE))
    put(w,WIRE+16,get(w,CB_LAST))
    put(w,WIRE+24,op)
    put(w,WIRE+40,get(w,C_RETURN))
    put(w,WIRE+48,observed)
    i = 0
    while i < observed:
        store(w,WIRE+64+i,byte(w,OBS+i))
        i = i+1
    put(w,CB_FIRST,CB_ACK_SLOT)
    put(w,CB_FIRST_N,64+observed)
    return cb_phase(w,12031)

def cb_step(o:mutbuf,w:mutbuf)->u64:
    phase = get(w,C_PHASE)
    if get(w,CB_ACTIVE) == 3:
        if phase == 12080:
            slot = get(w,CB_CURRENT)
            if slot > 18:
                return cb_phase(w,12082)
            put(w,CB_CURRENT,slot+1)
            return release(o,w,CB_SLOT_BASE+slot,12080)
        if phase == 12082:
            return release(o,w,CB_ACK_SLOT,12083)
        if phase == 12083:
            return release(o,w,CB_INPUT_SLOT,12084)
        if phase == 12084:
            return release(o,w,CB_OUTPUT_SLOT,12085)
        if phase == 12085:
            return release(o,w,CB_WORK_SLOT,12086)
        if phase == 12086:
            after = get(w,CB_RETIRE_AFTER)
            fill_range(w,24000,384,0)
            return cb_phase(w,after)
        return refuse(w,2027)
    if get(w,CB_ACTIVE) != 1:
        return refuse(w,2028)
    if phase == 12000:
        return protect(o,w,CB_INPUT_SLOT,1,12001)
    if phase == 12001:
        return grow(o,w,CB_WORK_SLOT,1048576,12002)
    if phase == 12002:
        return clear(o,w,CB_WORK_SLOT,0,1048576,12003)
    if phase == 12003:
        return grow(o,w,CB_OUTPUT_SLOT,128,12004)
    if phase == 12004:
        return clear(o,w,CB_OUTPUT_SLOT,0,128,12005)
    if phase == 12005:
        return grow(o,w,CB_ACK_SLOT,320,12010)
    if phase == 12010:
        return invoke(o,w,get(w,CB_ROLE),get(w,CB_FIRST),0,get(w,CB_FIRST_N),
            CB_OUTPUT_SLOT,128,CB_WORK_SLOT,1048576,CB_OUTPUT_SLOT,0,128,12011)
    if phase == 12011:
        return cb_received(o,w)
    if phase == 12030:
        return cb_ack(w)
    if phase == 12031:
        return protect(o,w,CB_ACK_SLOT,0,12032)
    if phase == 12032:
        return copy(o,w,2,WIRE,CB_ACK_SLOT,0,get(w,CB_FIRST_N),12033)
    if phase == 12033:
        return protect(o,w,CB_ACK_SLOT,1,12010)
    return refuse(w,2029)
'''
def metadata():
 return dict(status="NEW_UNEXECUTED",scope="FINITE_HIA_CHILD_COMMAND_TRANSLATION",
  common_sha256=COMMON_SHA,checked_plan_controller_sha256=PLAN_SHA,
  original_emitter_controller_sha256=EMITTER_SHA,
  children_are_actual_native_images=True,parent_owns_sequence_and_slot_translation=True,
  child_image_roles={"plan":[12,13,14,15],"emitter":list(range(1,11))},
  child_controller_roles={"plan":16,"emitter":11},
  child_logical_slot_maxima={"plan":10,"emitter":18},
  no_recursion_or_arbitrary_child_role=True,complete_actual_ACK_and_observation_forwarded=True,
  no_json_or_instruction_decisions_in_host=True,private_actual_immutable_issuer_required=True,
  header_is_authentication=False,AST=0,generation=0,B3=0,VM=0,native=0)
