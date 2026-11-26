"""Shared-arena BG Runtime provider with explicit native retirement custody.

The enclosing owner captures the fixed provider, Value, carrier and payload
bindings. This variant borrows the existing carrier registry and initializes
only its common payload registry. Earlier standalone provider source is retained.
"""
from pathlib import Path
import ast,re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
from tools import generate_hia_multiversion_background_runtime as original
ROOT=Path(__file__).resolve().parents[1]
C=dict(original.C)
C.update({k:int.from_bytes(v.encode(),'little')for k,v in dict(
 CONTROL='HIAGPCQ1',STATE='HIAGPCX1',CAPTURE_REQUEST='HIAMVBQ2',TYPED_REQUEST='HIAMVBQ3',
 TYPED_REPLY='HIAMVBO2',HPRIVATE='HIAMVHA1',HACK='HIAMVHA2',
 VQ='HIABVQ01',VQ2='HIABVQ02',VQ5='HIABVQ05',VR='HIABVR01',VR2='HIABVR02').items()})
C.update(TYPED=720,VCAP=728,V_PENDING=752,H_PENDING=760,ACK_KNOWN=768,ACK_CONSUMED=776,
 INPUT_KNOWN=784,INPUT_CONSUMED=792,INPUT_PENDING=800,STALLED=808,QUAR=816,FREE_AT=824,
 FREE_NEXT=832,SCAN=840,CONTROL_OP=848,RESUMING=856,SELF=864,BIND_NONCE=872,
 REGISTRY=896,VALUE_CONTEXT=904,SAVED_RETURN=960,SAVED_N=984,SAVED_POINTER=992,
 SAVED_KIND=1000,SAVED_COMMITTED=1008,SAVED_TRANSFER=1016)
OVERRIDES=r'''
def generation_lease_owner_provider(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(o)<4096 or length(w)!=768:
        return 4294967293
    phase=get(o,PH)
    if phase==0:
        return begin(s,o,w)
    if phase<100:
        return start(s,o,w,phase)
    if phase<200:
        return lock_step(s,o,w,phase)
    if phase<300:
        return dispatch(s,o,w,phase)
    if phase<400:
        return handle_step(s,o,w,phase)
    if phase<500:
        return effect_step(s,o,w,phase)
    if phase<600:
        return payload_step(s,o,w,phase)
    if phase<700:
        return capture_runtime(s,o,w,phase)
    if phase<800:
        return retry_pending(s,o,w,phase)
    return cleanup(s,o,w,phase)

def begin(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)<128:
        return 4294967293
    magic=word(s,0)
    op=word(s,8)
    family=0
    if magic==CONTROL:
        family=1
        if length(s)!=128 or op>4:
            return 4294967293
        at=16
        while at<128:
            if word(s,at)!=0:
                return 4294967293
            at=at+8
    else:
        if magic==CAPTURE_REQUEST:
            family=2
            if op!=3:
                return 4294967293
        elif magic==TYPED_REQUEST:
            family=3
        elif magic!=REQUEST:
            return 4294967293
        if op==0 or op>6 or (op==6 and magic!=TYPED_REQUEST):
            return 4294967293
        if op==2:
            gn=word(s,56)
            en=word(s,64)
            raw=word(s,72)
            measure=word(s,80)
            if gn==0 or en==0 or raw>8388608 or measure>8388608 or word(s,88)>=9223372036854775808:
                return 4294967293
            if word(s,40)==0 or word(s,48)!=512 or word(s,104)>1 or word(s,112)!=0 or word(s,120)!=0:
                return 4294967293
            if word(s,104)==0 and measure!=0:
                return 4294967293
            remain=length(s)-128
            if gn>remain or en>remain-gn or raw>remain-gn-en or measure!=remain-gn-en-raw:
                return 4294967293
            if length(s)>NONE-128:
                return 4294967293
        else:
            if length(s)!=128:
                return 4294967293
            at=40
            if op==5:
                at=64
            if op==6:
                at=16
            while at<128:
                if word(s,at)!=0:
                    return 4294967293
                at=at+8
    zero(o,128,3968)
    put(o,OP,op)
    put(o,FAMILY,family)
    put(o,TYPED,choose(family==0,0,1))
    put(o,INPUT_KNOWN,1)
    put(o,FD0,NONE)
    put(o,FD1,NONE)
    put(o,KIND,4)
    return system(o,10,228,12,1,CLOCK,0,0,0,0)

def start(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==10:
        if get(o,FB)==NONE-3:
            return system(o,10,228,12,1,CLOCK,0,0,0,0)
        if get(o,FB)!=0 or get(o,CLOCK)>18446744073 or get(o,CLOCK+8)>=1000000000:
            return fail(o,3)
        now=get(o,CLOCK)*1000000000
        if get(o,CLOCK+8)>NONE-now:
            return fail(o,3)
        put(o,STARTED,now+get(o,CLOCK+8))
        if get(o,FAMILY)!=1 and get(o,OP)==2:
            if decimal(s,128,word(s,56))==0 or decimal(s,128+word(s,56),word(s,64))==0:
                return 4294967293
        return system(o,1,39,0,0,0,0,0,0,0)
    if phase==1:
        pid=get(o,FB)
        if pid==0 or pid>=NEGATIVE:
            return fail(o,3)
        put(o,PID,pid)
        put(o,PH,5)
        return 15
    if phase==5:
        own=get(o,896)
        parent=get(o,904)
        if own==0 or parent>NONE-2048 or own!=parent+1280:
            return fail(o,3)
        if get(w,0)!=STATE or get(w,8)!=get(o,PID) or get(w,40)!=parent or get(w,48)!=own or get(w,56)!=get(o,912):
            return fail(o,3)
        if get(w,64)!=parent+256 or get(w,72)!=256 or get(w,80)!=get(o,944) or get(w,88)!=parent+512 or get(w,96)!=256:
            return fail(o,3)
        if get(w,104)!=get(o,936) or get(w,112)!=own+512 or get(w,120)!=256 or get(w,128)==0 or get(w,16)>6:
            return fail(o,3)
        at=136
        while at<512:
            if get(w,at)!=0:
                return fail(o,3)
            at=at+8
        put(o,SELF,get(w,48))
        put(o,BIND_NONCE,get(w,128))
        put(o,REGISTRY,get(w,64))
        put(o,VALUE_CONTEXT,get(w,88))
        return memory(o,6,0,get(w,88)+152,3,RBUF,8)
    if phase==6:
        if get(o,RBUF)!=get(o,BIND_NONCE):
            return fail(o,3)
        if get(o,FAMILY)==1 or get(o,OP)==6:
            return lock(o,110)
        return allocate(o,3,CHILD_BYTES+4096)
    if phase==3:
        if get(o,FB)==0:
            return fail(o,2)
        put(o,CHILD,get(o,FB))
        put(o,PIN,get(o,FB)+CHILD_BYTES)
        zero(o,PIN_ROW,64)
        put(o,PIN_ROW,get(o,PID))
        put(o,PIN_ROW+8,get(o,BIND_NONCE))
        put(o,PIN_ROW+40,get(o,CHILD))
        put(o,PIN_ROW+48,CHILD_BYTES+4096)
        put(o,PIN_ROW+56,get(o,SELF))
        return lock(o,110)
    return fail(o,3)

def lock_step(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==100:
        if get(o,FB)==0:
            put(o,HELD,1)
            return again(o,get(o,LOCK_NEXT))
        put(o,TIMEOUT,0)
        put(o,TIMEOUT+8,1000000)
        return system(o,101,202,193,24,128,1,TIMEOUT,0,0)
    if phase==101:
        return atom(o,100,2,0,1)
    if phase==102:
        return system(o,103,202,1,24,129,2147483647,0,0,0)
    if phase==103:
        return again(o,get(o,LOCK_NEXT))
    if phase==110:
        if get(o,FAMILY)==1:
            return control(o,w)
        if get(o,OP)==6:
            put(o,RESUMING,1)
            put(o,SCAN,get(w,32))
            return again(o,700)
        if get(w,16)!=1:
            return fail(o,3)
        put(o,PIN_ROW+24,get(w,32))
        return memory(o,112,3,PIN_ROW,0,get(o,PIN),64)
    if phase==112:
        if get(w,32)!=0:
            return write_pointer(o,111,get(w,32)+16,get(o,PIN))
        return again(o,111)
    if phase==111:
        put(w,32,get(o,PIN))
        put(o,ACTIVE,1)
        return unlock(o,200)
    return fail(o,3)

def control(o:mutbuf,w:mutbuf) -> u32:
    op=get(o,OP)
    state=get(w,16)
    if op==4:
        if state==6:
            put(o,INPUT_KNOWN,0)
            put(o,INPUT_PENDING,1)
            return fail(o,3)
        put(o,RESUMING,1)
        put(o,SCAN,get(w,32))
        return again(o,700)
    if op==0:
        if state!=0 or get(w,32)!=0:
            return fail(o,3)
        put(w,16,4)
        payload_request(o,0)
        return payload(o,214)
    if op==1:
        if state!=1 or get(w,32)!=0 or get(w,512+16)!=0 or get(w,512+24)!=0:
            if get(w,32)!=0:
                put(o,INPUT_PENDING,1)
            return fail(o,3)
        put(w,16,2)
        return fail(o,0)
    if op==2:
        if state!=2:
            return fail(o,3)
        put(w,16,1)
        return fail(o,0)
    if op==3:
        if state==3:
            return fail(o,0)
        if (state!=2 and state!=5) or get(w,32)!=0:
            return fail(o,3)
        put(w,16,5)
        payload_request(o,5)
        return payload(o,215)
    return fail(o,3)

def dispatch(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==200:
        op=get(o,OP)
        if get(o,FAMILY)==2:
            value_request(o,VQ,5)
            put(o,HREQ+24,word(s,16))
            put(o,HREQ+32,word(s,24))
            put(o,HREQ+40,word(s,32))
            return value(o,600)
        if op==5:
            payload_request(o,3)
            put(o,HREQ+24,word(s,40))
            put(o,HREQ+32,word(s,48))
            put(o,HREQ+40,word(s,56))
            return payload(o,530)
        if op==4:
            private_request(o,3)
            put(o,HREQ+24,word(s,16))
            put(o,HREQ+32,word(s,24))
            put(o,HREQ+40,word(s,32))
            return handles(o,310)
        handles_request(o,2)
        put(o,HREQ+24,word(s,16))
        put(o,HREQ+32,word(s,24))
        put(o,HREQ+40,word(s,32))
        put(o,HANDLE_ACTION,op)
        return handles(o,300)
    if phase==214 or phase==215:
        if get(o,FB)!=0 or get(o,POUT)!=PREPMAG:
            put(w,16,6)
            put(o,INPUT_KNOWN,0)
            put(o,INPUT_PENDING,1)
            return fail(o,3)
        if get(o,POUT+8)!=0:
            if phase==214 and get(w,512)==0:
                put(w,16,0)
            put(o,INPUT_PENDING,choose(phase==215,1,0))
            return fail(o,3)
        put(w,16,choose(phase==214,1,3))
        return fail(o,0)
    return fail(o,3)

def capture_runtime(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==600 or phase==602:
        if get(o,FB)!=0:
            return stall(o,2)
        return memory(o,phase+1,0,get(o,CHILD),3,RBUF,128)
    if phase==601:
        if get(o,RBUF)!=VR:
            return stall(o,2)
        if get(o,RBUF+8)!=0:
            return fail(o,choose(get(o,RBUF+8)==5,2,3))
        if get(o,RBUF+24)==0:
            return stall(o,2)
        within(o,RBUF+24,VCAP,24)
        value_request(o,VQ5,49)
        within(o,VCAP,HREQ+24,24)
        return value(o,602)
    if phase==603:
        if get(o,RBUF)!=VR:
            return stall(o,2)
        if get(o,RBUF+8)!=0:
            return fail(o,3)
        if get(o,RBUF+16)!=1 or get(o,RBUF+24)==0:
            return fail(o,3)
        handles_request(o,2)
        within(o,RBUF+24,HREQ+24,24)
        put(o,HANDLE_ACTION,3)
        return handles(o,300)
    return stall(o,2)

def handle_step(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==300 or phase==310 or phase==312:
        if get(o,FB)!=0:
            return stall(o,2)
        return memory(o,phase+1,0,get(o,CHILD),3,RBUF,128)
    if phase==301:
        if get(o,RBUF)!=HREPMAG:
            return stall(o,2)
        if get(o,RBUF+8)!=0:
            return fail(o,choose(get(o,RBUF+8)==4,2,3))
        if get(o,RBUF+24)==0:
            return stall(o,2)
        within(o,RBUF+24,CLONE,24)
        put(o,HAVE_CLONE,1)
        if get(o,RBUF+16)!=1:
            return fail(o,3)
        if get(o,HANDLE_ACTION)==3:
            within(o,CLONE,RETURN_CAP,24)
            zero(o,CLONE,24)
            put(o,HAVE_CLONE,0)
            put(o,KIND,3)
            return fail(o,0)
        private_request(o,6)
        within(o,CLONE,HREQ+24,24)
        return handles(o,312)
    if phase==311:
        if carrier_facts(o,3)==False:
            put(o,INPUT_KNOWN,0)
            return stall(o,2)
        put(o,INPUT_KNOWN,get(o,ACK_KNOWN))
        put(o,INPUT_CONSUMED,get(o,ACK_CONSUMED))
        put(o,INPUT_PENDING,get(o,RBUF+112))
        if get(o,ACK_KNOWN)==0:
            return stall(o,2)
        if get(o,RBUF+112)!=0:
            put(o,H_PENDING,1)
            return stall(o,1)
        return fail(o,choose(get(o,RBUF+8)==0,0,3))
    if phase==313:
        if carrier_facts(o,6)==False or get(o,RBUF+8)!=0 or get(o,ACK_KNOWN)!=1 or get(o,ACK_CONSUMED)!=0 or get(o,RBUF+112)!=0 or get(o,RBUF+16)!=1 or get(o,RBUF+40)==0:
            return stall(o,2)
        put(o,OBJ,get(o,RBUF+40))
        return ordinary_handle_step(s,o,w,302)
    return ordinary_handle_step(s,o,w,phase)

def payload_step(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==530:
        if get(o,FB)!=0 or get(o,POUT)!=PREPMAG:
            put(o,INPUT_KNOWN,0)
            return fail(o,3)
        status=get(o,POUT+8)
        if status==0:
            put(o,INPUT_CONSUMED,1)
            return fail(o,0)
        if status==9:
            put(o,INPUT_KNOWN,0)
        return fail(o,3)
    return ordinary_payload_step(s,o,w,phase)

def retry_pending(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==700:
        if get(o,SCAN)==0:
            if get(o,QUAR)!=0:
                put(o,INPUT_PENDING,1)
                return fail(o,3)
            return fail(o,0)
        return memory(o,701,0,get(o,SCAN),3,PIN_ROW,64)
    if phase==701:
        if get(o,PIN_ROW)!=get(o,PID) or get(o,PIN_ROW+8)!=get(o,BIND_NONCE) or get(o,PIN_ROW+56)!=get(o,SELF) or get(o,PIN_ROW+48)!=CHILD_BYTES+4096 or get(o,PIN_ROW+40)>NONE-CHILD_BYTES or get(o,PIN_ROW+40)+CHILD_BYTES!=get(o,SCAN):
            put(o,INPUT_KNOWN,0)
            put(o,INPUT_PENDING,1)
            return fail(o,3)
        state=get(o,PIN_ROW+32)
        if state!=1:
            if state==3:
                put(o,QUAR,2)
                put(o,INPUT_KNOWN,0)
            elif state>3:
                put(o,INPUT_KNOWN,0)
                put(o,INPUT_PENDING,1)
                return fail(o,3)
            put(o,SCAN,get(o,PIN_ROW+24))
            return again(o,700)
        put(o,72,get(o,SCAN))
        return write_pointer(o,702,get(o,SCAN)+32,2)
    if phase==702:
        # PH/FB are the current continuation, not retained operation custody.
        # Restoring them would resume the saved phase952 instead of phase703.
        return memory(o,703,0,get(o,72)+144,3,144,3952)
    if phase==703:
        record=get(o,72)
        if get(o,CHILD)>NONE-CHILD_BYTES or get(o,CHILD)+CHILD_BYTES!=record or get(o,REGISTRY)!=get(w,64) or get(o,VALUE_CONTEXT)!=get(w,88) or get(o,SELF)!=get(w,48) or get(o,BIND_NONCE)!=get(w,128):
            put(o,HELD,1)
            put(o,INPUT_KNOWN,0)
            put(o,INPUT_PENDING,1)
            put(o,STATUS,3)
            return write_pointer(o,704,record+32,3)
        put(o,PIN,record)
        put(o,ACTIVE,1)
        put(o,HELD,1)
        put(o,RESUMING,1)
        put(o,TYPED,1)
        put(o,FAMILY,3)
        put(o,OP,6)
        put(o,KIND,4)
        put(o,STATUS,0)
        put(o,STALLED,0)
        put(o,QUAR,0)
        put(o,INPUT_KNOWN,1)
        put(o,INPUT_CONSUMED,0)
        put(o,INPUT_PENDING,0)
        put(o,SAVED_TRANSFER,0)
        zero(o,SAVED_RETURN,56)
        put(o,FREE_NEXT,900)
        return unlock(o,900)
    if phase==704:
        return unlock(o,980)
    return fail(o,3)

def cleanup(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==900:
        if get(o,STALLED)!=0:
            return again(o,950)
        if get(o,HELD)!=0:
            return unlock(o,900)
        if get(o,VCAP)!=0:
            value_request(o,VQ2,29)
            within(o,VCAP,HREQ+24,24)
            return value(o,940)
        if get(o,V_PENDING)!=0:
            value_request(o,VQ2,31)
            return value(o,942)
        if get(o,H_PENDING)!=0:
            if get(o,RESUMING)==0:
                return stall(o,1)
            private_request(o,7)
            return handles(o,944)
        if get(o,FD0)!=NONE:
            put(o,FREE_AT,FD0)
            return system(o,920,436,0,get(o,FD0),get(o,FD0),0,0,0,0)
        if get(o,FD1)!=NONE:
            put(o,FREE_AT,FD1)
            return system(o,920,436,0,get(o,FD1),get(o,FD1),0,0,0,0)
        if get(o,PACKET)!=0:
            put(o,FREE_AT,PACKET)
            put(o,FREE_NEXT,900)
            return deallocate(o,930,get(o,PACKET))
        if get(o,OWNED)!=0:
            put(o,FREE_AT,OWNED)
            put(o,FREE_NEXT,900)
            return deallocate(o,930,get(o,OWNED))
        if get(o,DROP_RESULT)!=0:
            if get(o,TYPED)!=0:
                put(o,DROP_RESULT,0)
                return again(o,900)
            payload_request(o,3)
            within(o,RETURN_CAP,HREQ+24,24)
            return payload(o,901)
        if get(o,HAVE_CLONE)!=0:
            private_request(o,3)
            within(o,CLONE,HREQ+24,24)
            return handles(o,902)
        if get(o,ACTIVE)!=0:
            return lock(o,909)
        if get(o,CHILD)!=0:
            return lock(o,937)
        return finish(o)
    if phase==901:
        if get(o,FB)!=0 or get(o,POUT)!=PREPMAG or get(o,POUT+8)!=0:
            return stall(o,2)
        put(o,DROP_RESULT,0)
        zero(o,RETURN_CAP,24)
        put(o,RETURN_N,0)
        put(o,RETURN_POINTER,0)
        return again(o,900)
    if phase==902:
        if get(o,FB)!=0:
            return stall(o,2)
        return memory(o,903,0,get(o,CHILD),3,RBUF,128)
    if phase==903:
        if carrier_facts(o,3)==False or get(o,ACK_KNOWN)==0:
            return stall(o,2)
        if get(o,ACK_CONSUMED)!=0:
            put(o,HAVE_CLONE,0)
            zero(o,CLONE,24)
        if get(o,RBUF+112)!=0:
            put(o,H_PENDING,1)
        if get(o,RBUF+8)!=0:
            if get(o,ACK_CONSUMED)!=0 and get(o,RBUF+112)==0:
                return stall(o,2)
            return stall(o,1)
        return again(o,900)
    if phase==909:
        return memory(o,910,0,get(o,PIN),3,PIN_ROW,64)
    if phase==910:
        if get(o,PIN_ROW)!=get(o,PID) or get(o,PIN_ROW+8)!=get(o,BIND_NONCE) or get(o,PIN_ROW+40)!=get(o,CHILD) or get(o,PIN_ROW+48)!=CHILD_BYTES+4096 or get(o,PIN_ROW+56)!=get(o,SELF):
            return stall(o,2)
        return deallocate(o,911,get(o,CHILD))
    if phase==911:
        if get(o,FB)!=0:
            return stall(o,1)
        put(o,CHILD,0)
        if get(o,PIN_ROW+16)!=0:
            return write_pointer(o,912,get(o,PIN_ROW+16)+24,get(o,PIN_ROW+24))
        put(w,32,get(o,PIN_ROW+24))
        return again(o,912)
    if phase==912:
        if get(o,PIN_ROW+24)!=0:
            return write_pointer(o,913,get(o,PIN_ROW+24)+16,get(o,PIN_ROW+16))
        return again(o,913)
    if phase==913:
        put(o,ACTIVE,0)
        put(o,PIN,0)
        if get(o,RESUMING)!=0:
            put(o,SCAN,get(w,32))
            return again(o,700)
        return unlock(o,980)
    if phase==920:
        if get(o,FB)!=0:
            return stall(o,1)
        put(o,get(o,FREE_AT),NONE)
        return again(o,900)
    if phase==930:
        if get(o,FB)!=0:
            put(o,FREE_NEXT,900)
            return stall(o,1)
        put(o,get(o,FREE_AT),0)
        return again(o,get(o,FREE_NEXT))
    if phase==937:
        put(o,PIN_ROW+24,get(w,32))
        return memory(o,938,3,PIN_ROW,0,get(o,PIN),64)
    if phase==938:
        if get(w,32)!=0:
            return write_pointer(o,939,get(w,32)+16,get(o,PIN))
        return again(o,939)
    if phase==939:
        put(w,32,get(o,PIN))
        put(o,ACTIVE,1)
        if get(o,STALLED)!=0:
            return again(o,951)
        return again(o,909)
    if phase==940 or phase==942 or phase==944:
        if get(o,FB)!=0:
            return stall(o,2)
        return memory(o,phase+1,0,get(o,CHILD),3,RBUF,128)
    if phase==941:
        if value_facts(o,29)==False or get(o,ACK_KNOWN)==0:
            return stall(o,2)
        if get(o,ACK_CONSUMED)!=0:
            zero(o,VCAP,24)
        if get(o,RBUF+80)!=0:
            put(o,V_PENDING,1)
        if get(o,RBUF+8)!=0:
            if get(o,RBUF+8)==1 or (get(o,ACK_CONSUMED)!=0 and get(o,RBUF+80)==0):
                return stall(o,2)
            return stall(o,1)
        return again(o,900)
    if phase==943:
        if value_facts(o,31)==False:
            return stall(o,2)
        if get(o,RBUF+8)!=0:
            return stall(o,1)
        put(o,V_PENDING,0)
        return again(o,900)
    if phase==945:
        if carrier_facts(o,7)==False or get(o,ACK_KNOWN)==0:
            return stall(o,2)
        if get(o,RBUF+8)!=0 or get(o,RBUF+112)!=0:
            return stall(o,1)
        put(o,H_PENDING,0)
        put(o,INPUT_PENDING,0)
        return again(o,900)
    if phase==950:
        if get(o,ACTIVE)==0:
            if get(o,CHILD)==0:
                if get(o,HELD)!=0:
                    return unlock(o,980)
                return finish(o)
            if get(o,HELD)==0:
                return lock(o,937)
            return again(o,937)
        if get(o,HELD)==0:
            return lock(o,951)
        return again(o,951)
    if phase==951:
        if get(o,RETURN_CAP)!=0 and (get(o,DROP_RESULT)==0 or get(o,TYPED)!=0):
            within(o,RETURN_CAP,SAVED_RETURN,24)
            put(o,SAVED_N,get(o,RETURN_N))
            put(o,SAVED_POINTER,get(o,RETURN_POINTER))
            put(o,SAVED_KIND,get(o,KIND))
            put(o,SAVED_COMMITTED,get(o,COMMITTED))
            put(o,SAVED_TRANSFER,1)
            zero(o,RETURN_CAP,24)
            put(o,RETURN_N,0)
            put(o,RETURN_POINTER,0)
            put(o,DROP_RESULT,0)
        put(o,INPUT_PENDING,1)
        return memory(o,952,3,128,0,get(o,PIN)+128,3968)
    if phase==952:
        return write_pointer(o,953,get(o,PIN)+32,choose(get(o,QUAR)==2,3,1))
    if phase==953:
        return unlock(o,980)
    if phase==980:
        return finish(o)
    return stall(o,2)

def carrier_facts(o:mutbuf,op:u64) -> bool:
    if get(o,RBUF)!=HACK:
        return False
    known=get(o,RBUF+96)
    consumed=get(o,RBUF+104)
    pending=get(o,RBUF+112)
    if known>1 or consumed>1 or pending>1 or (known==0 and (consumed!=0 or pending!=0)):
        return False
    if (op==6 or op==7) and consumed!=0:
        return False
    if get(o,RBUF+8)==0:
        if known!=1 or pending!=0:
            return False
        if consumed!=choose(op==3,1,0):
            return False
    put(o,ACK_KNOWN,known)
    put(o,ACK_CONSUMED,consumed)
    return True

def value_facts(o:mutbuf,op:u64) -> bool:
    if get(o,RBUF)!=VR2:
        return False
    status=get(o,RBUF+8)
    pending=get(o,RBUF+80)
    known=get(o,RBUF+88)
    consumed=get(o,RBUF+96)
    if pending>1 or known>1 or consumed>1:
        return False
    if status!=0 and status!=1 and status!=6 and status!=11:
        return False
    if known==0 and (status!=11 or consumed!=0 or pending!=0):
        return False
    if op==31 and (known!=1 or consumed!=0 or status==1):
        return False
    if status==0 and (known!=1 or pending!=0 or consumed!=choose(op==29,1,0)):
        return False
    if status==1 and (known!=1 or consumed!=0 or pending!=0):
        return False
    if status==6 and (known!=1 or consumed!=0):
        return False
    at=16
    while at<128:
        if at!=80 and at!=88 and at!=96 and get(o,RBUF+at)!=0:
            return False
        at=at+8
    put(o,ACK_KNOWN,known)
    put(o,ACK_CONSUMED,consumed)
    return True

def private_request(o:mutbuf,op:u64) -> u64:
    zero(o,HREQ,128)
    put(o,HREQ,HPRIVATE)
    put(o,HREQ+8,op)
    if op!=7:
        put(o,HREQ+16,1)
    return 0

def value_request(o:mutbuf,magic:u64,op:u64) -> u64:
    zero(o,HREQ,128)
    put(o,HREQ,magic)
    put(o,HREQ+8,op)
    return 0

def handles(o:mutbuf,next:u64) -> u32:
    return role(o,next,12,3,HREQ,128,0,get(o,CHILD),CHILD_BYTES,0,get(o,REGISTRY),256)

def value(o:mutbuf,next:u64) -> u32:
    return role(o,next,16,3,HREQ,128,0,get(o,CHILD),32768,0,get(o,VALUE_CONTEXT),256)

def stall(o:mutbuf,kind:u64) -> u32:
    put(o,STATUS,3)
    put(o,STALLED,1)
    put(o,QUAR,kind)
    return again(o,950)

def finish(o:mutbuf) -> u32:
    zero(o,0,128)
    put(o,0,choose(get(o,TYPED)!=0,TYPED_REPLY,REPLY))
    put(o,8,get(o,STATUS))
    put(o,16,get(o,KIND))
    put(o,24,get(o,RETURN_POINTER))
    put(o,32,get(o,RETURN_N))
    if get(o,DROP_RESULT)==0 or get(o,TYPED)!=0:
        within(o,RETURN_CAP,40,24)
    put(o,64,get(o,COMMITTED))
    if get(o,SAVED_TRANSFER)!=0:
        put(o,16,get(o,SAVED_KIND))
        put(o,24,get(o,SAVED_POINTER))
        put(o,32,get(o,SAVED_N))
        within(o,SAVED_RETURN,40,24)
        put(o,64,get(o,SAVED_COMMITTED))
    if get(o,TYPED)!=0:
        put(o,72,get(o,INPUT_KNOWN))
        put(o,80,get(o,INPUT_CONSUMED))
        put(o,88,get(o,INPUT_PENDING))
    return 0
'''
def source_program():
    functions={n.name:n for n in ast.parse(original.SOURCE).body if isinstance(n,ast.FunctionDef)}
    old=functions.pop('multiversion_background_runtime')
    remainder=functions['handle_step']
    remainder.name='ordinary_handle_step'
    remainder.body=[n for n in remainder.body if not(isinstance(n,ast.If)and isinstance(n.test,ast.Compare)and isinstance(n.test.left,ast.Name)and n.test.left.id=='phase'and isinstance(n.test.comparators[0],ast.Constant)and n.test.comparators[0].value in(300,301,310,311))]
    functions['ordinary_handle_step']=remainder
    payload_remainder=functions['payload_step']
    payload_remainder.name='ordinary_payload_step'
    payload_remainder.body=[n for n in payload_remainder.body if not(isinstance(n,ast.If)and isinstance(n.test,ast.Compare)and isinstance(n.test.left,ast.Name)and n.test.left.id=='phase'and isinstance(n.test.comparators[0],ast.Constant)and n.test.comparators[0].value==530)]
    functions['ordinary_payload_step']=payload_remainder
    for node in ast.parse(OVERRIDES).body:
        functions[node.name]=node
    text='\n\n'.join(ast.unparse(functions[n])for n in ['generation_lease_owner_provider']+[n for n in functions if n!='generation_lease_owner_provider'])
    old_free='''old = get(o, PACKET)
            put(o, PACKET, 0)
            return deallocate(o, 500, old)'''
    new_free='''put(o, FREE_AT, PACKET)
            put(o, FREE_NEXT, 500)
            return deallocate(o, 930, get(o, PACKET))'''
    assert text.count(old_free)==1
    text=text.replace(old_free,new_free)
    exception=next(n for n in ast.parse(original.source_program()).body if n.name=='exception_text')
    text+='\n'+ast.unparse(exception)+'\n'
    for key,value in sorted(C.items(),key=lambda x:-len(x[0])):
        text=re.sub(r'\b'+key+r'\b',str(value),text)
    return text
def program():return document(source_program(),'generation_lease_owner_provider')
def main():
    p=ROOT/'examples/hia_bootstrap/generation_lease_owner_provider.hepta'
    doc=program();p.write_text(render_assembly(doc))
    print(p.name,p.stat().st_size,len(doc['functions']),sum(len(f['blocks'])for f in doc['functions']),sum(len(b['ops'])for f in doc['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
