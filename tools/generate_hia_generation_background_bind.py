"""Fixed installed BackgroundOptimizer binding and native public dispatch.

The root owns the global-resource borrow, BG/loader allocation, both lifetime
guards and the fixed catalog export addresses. Requests never carry addresses,
paths, tool descriptors, a table or support-mask bits.
"""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
ROOT=Path(__file__).resolve().parents[1]
C={k:int.from_bytes(v.encode(),"little")for k,v in dict(
 Q="HIAGBNQ1",R="HIAGBNR1",OWNER="HIAGLOW1",TAG="HIAGBAM1",SIDECAR="HIAGSCX1",
 GLOBAL_Q="HIAGGIQ1",GLOBAL_R="HIAGGIR1",
 LOADER_Q="HIANLCQ1",LOADER_R="HIANLCR1",
 BG_INIT="HIABGNI2",BG_CONTROL="HIABGCQ1",BG_R="HIABGCR1",BG_STATE="HIABGNC1",
 PUBLIC_Q="HIABGPQ1",PRIVATE_Q="HIABGPX1",PUBLIC_R="HIABGPR1",
 RFQ="HIAVRFQ1",RFR="HIAVRFR1",VALUE_Q="HIABVQ05",VALUE_R="HIABVR01").items()}
C.update(BAD=4294967293,NONE=(1<<64)-1,OUT=3145728,CHILD_N=2097152,
 META=2097152,PH=2097280,FB=2097288,OP=2097296,STATUS=2097304,DETAIL=2097312,
 HELD=2097320,PID=2097328,RESUME=2097336,NEXT=2097344,KNOWN=2097352,PENDING=2097360,
 RC=2097368,ERROR_STATUS=2097376,ERROR_DETAIL=2097384,CLAIM=2097392,RETURN=2097400,
 SELF=2097664,ENTRY=2097672,ROOT_ENTRY=2097680,VALUE_ENTRY=2097688,
 GLOBAL_ENTRY=2097696,LOADER_ENTRY=2097704,FINALIZER_ENTRY=2097712,SIDECAR_ENTRY=2097720,
 M=2098176,N=2098688,FRAME=2101248,CHILD=2113536,SNAP=2265088,
 ANCHOR=7340544,SPAN=27262976,LOADER_AT=4096,LOADER_N=26214400,
 MP=2098208,MN=2098216,MS=2098224,STAGE=2098232,BUSY=2098240,ACTIVE=2098248,
 ROOT_GUARD=2098256,SIDECAR_GUARD=2098264,GCAP=2098272,GPENDING=2098296,
 LCAP=2098304,LSTARTED=2098328,LPENDING=2098336,BSTARTED=2098344,BPENDING=2098352,
 EXPORTS=2098360,BG_NONCE=2098392,GLOBAL_NONCE=2098400,VALUE_NONCE=2098408,
 TOOLS=2098424,SOURCEFD=2098448,THRESHOLD=2098456,THRESHOLD_N=2098464,
 THRESHOLD_FD=2098472,DIGITS=2098480,LAST_STATUS=2098488,LAST_DETAIL=2098496,
 UNKNOWN=2098504,BOUND_GLOBAL=2098512,BOUND_LOADER=2098520,BOUND_VALUE=2098528,
 CONTEXT_ENTRY=2098536,CODE=2273280)
SOURCE=r'''
def background_bind(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase=get(o,PH)
    r=get(o,FB)
    if phase==0:
        return begin(s,o,w)
    if phase>=1 and phase<=4:
        return entry_lock(s,o,w,phase,r)
    if phase>=10 and phase<100:
        return initializing(s,o,w,phase,r)
    if phase>=100 and phase<200:
        return closing(s,o,w,phase,r)
    if phase==700:
        if r!=0:
            return broken_locked(o,w,r)
        put(o,PH,701)
        return 3
    if phase==701:
        put(o,HELD,0)
        return system(o,702,202,1,64,129,2147483647,0,0,0)
    if phase==702:
        return again(o,get(o,NEXT))
    if phase==790:
        return reply(o,w)
    if phase==800:
        return forwarded(s,o,w)
    if phase==801:
        put(o,RC,r)
        put(o,RESUME,1)
        return lock(o,2)
    if phase==802:
        if r!=0 or valid_anchor(o,N)==0:
            return broken_locked(o,w,802)
        within(o,M,N,512)
        if get(o,ACTIVE)==0:
            return broken_locked(o,w,803)
        put(o,ACTIVE,get(o,ACTIVE)-1)
        return save_release(o,w,803)
    if phase==803:
        return 0
    if phase==900:
        if r!=0 or valid_anchor(o,N)==0 or get(o,N+64)!=1:
            return broken_locked(o,w,900)
        if get(o,N+72)!=0:
            return broken_locked(o,w,901)
        if get(o,RETURN)==1:
            if get(w,680)!=190 or get(w,872)!=0 or get(w,880)!=0 or get(w,888)!=0:
                return broken_locked(o,w,903)
            if get(o,MS)!=2 or get(o,BSTARTED)!=2 or get(o,BG_NONCE)==0:
                return broken_locked(o,w,904)
            put(w,872,get(o,MP))
            put(w,880,512)
            put(w,888,get(o,BG_NONCE))
            put(w,680,254)
        if get(o,RETURN)==2:
            if get(w,680)!=190 and get(w,680)!=254:
                return broken_locked(o,w,905)
            if get(w,872)!=0 and (get(w,872)!=get(o,N+32) or get(w,880)!=512 or get(w,888)!=get(o,BG_NONCE)):
                return broken_locked(o,w,906)
            put(w,680,get(w,680)&18446744073709551551)
            zero(w,872,24)
        if get(o,MS)==4:
            if get(o,ROOT_GUARD)!=1 or get(o,SIDECAR_GUARD)!=1 or get(w,72)==0 or get(w,1208)==0:
                return broken_locked(o,w,902)
            put(w,72,get(w,72)-1)
            put(w,1208,get(w,1208)-1)
            put(o,ROOT_GUARD,0)
            put(o,SIDECAR_GUARD,0)
        put(o,BUSY,0)
        return save_release(o,w,790)
    return BAD

def begin(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(o)<OUT or length(w)!=2048:
        return BAD
    op=NONE
    if length(s)==128 and word(s,0)==Q and word(s,8)<=4 and word(s,8)!=3:
        if empty(s,16,112)==0:
            return BAD
        op=word(s,8)
    if length(s)==192 and (word(s,0)==PUBLIC_Q or word(s,0)==PRIVATE_Q):
        op=10
    if length(s)==128 and word(s,0)==RFQ:
        if word(s,8)>1 or word(s,16)==0 or word(s,24)!=6 or word(s,32)==0 or word(s,40)==0 or word(s,48)==0:
            return BAD
        if empty(s,56,72)==0:
            return BAD
        op=11
    if op==NONE:
        return BAD
    zero(o,META+144,368)
    zero(o,M,1024)
    put(o,OP,op)
    put(o,KNOWN,1)
    return system(o,1,39,0,0,0,0,0,0,0)

def entry_lock(s:readbuf,o:mutbuf,w:mutbuf,phase:u64,r:u64) -> u32:
    if phase==1:
        if r==0 or failed(r):
            put(o,KNOWN,0)
            return unowned_reply(o,w,1,r)
        put(o,PID,r)
        if get(w,0)!=OWNER or get(w,8)!=r or get(w,16)!=get(o,SELF) or get(w,24)!=get(o,ROOT_ENTRY):
            return BAD
        if get(w,40)!=get(o,VALUE_ENTRY) or get(w,48)!=get(o,SELF)+512 or get(w,56)!=256:
            return BAD
        if get(w,80)!=1 or get(w,664)==0 or get(w,640)!=get(o,FINALIZER_ENTRY):
            return BAD
        if get(o,OP)==11 and word(s,16)!=get(w,664):
            return BAD
        return lock(o,2)
    if phase==2:
        if r!=0:
            if r!=1:
                return unowned_reply(o,w,5,r)
            put(o,META+768,0)
            put(o,META+776,10000000)
            return system(o,3,202,193,64,128,1,META+768,0,0)
        put(o,HELD,1)
        if get(w,80)!=1 or get(w,1088)==0 or get(w,1096)!=8388608 or get(w,1088)>NONE-8388608:
            return finish_locked(o,w,6,0)
        resume=get(o,RESUME)
        if resume==1:
            return memory(o,802,0,get(w,1088)+ANCHOR,3,N,512)
        if resume==2:
            return memory(o,900,0,get(w,1088)+ANCHOR,3,N,512)
        return memory(o,4,0,get(w,1088)+ANCHOR,3,M,512)
    if phase==3:
        if failed(r) and r!=18446744073709551612 and r!=18446744073709551605 and r!=18446744073709551506:
            return unowned_reply(o,w,1,r)
        return lock(o,2)
    if phase==4:
        if r!=0:
            return broken_locked(o,w,r)
        return dispatch(s,o,w)
    return BAD

def valid_anchor(o:mutbuf,at:u64) -> u64:
    if get(o,at)!=TAG or get(o,at+8)!=get(o,PID) or get(o,at+16)!=get(o,SELF) or get(o,at+24)!=get(o,ENTRY):
        return 0
    if get(o,at+336)!=get(o,GLOBAL_ENTRY) or get(o,at+344)!=get(o,LOADER_ENTRY) or get(o,at+352)!=get(o,VALUE_ENTRY):
        return 0
    if get(o,at+48)<1 or get(o,at+48)>5 or get(o,at+64)>1:
        return 0
    if get(o,at+32)!=0 and (get(o,at+40)!=SPAN or get(o,at+32)>NONE-SPAN):
        return 0
    return 1

def dispatch(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    op=get(o,OP)
    if get(o,M)==0:
        if op!=0:
            return finish_locked(o,w,6,0)
        i=0
        while i<512:
            if get(o,M+i)!=0:
                return finish_locked(o,w,5,i)
            i=i+8
        return new_binding(o,w)
    if valid_anchor(o,M)==0:
        return finish_locked(o,w,5,1)
    if get(o,MS)==4:
        if op==0:
            return new_binding(o,w)
        if op==10 or op==11:
            return finish_locked(o,w,6,0)
        return finish_locked(o,w,0,0)
    if get(o,UNKNOWN)!=0 or get(o,MS)==5:
        put(o,KNOWN,0)
        put(o,PENDING,1)
        return finish_locked(o,w,5,get(o,LAST_DETAIL))
    if op==2:
        return finish_locked(o,w,0,0)
    if op==10 or op==11:
        if get(o,BUSY)!=0 or get(o,MS)!=2:
            return finish_locked(o,w,6,0)
        if get(o,ACTIVE)==NONE:
            return finish_locked(o,w,6,1)
        put(o,ACTIVE,get(o,ACTIVE)+1)
        return save_release(o,w,800)
    if op==0:
        return finish_locked(o,w,6,0)
    if get(o,BUSY)!=0 or get(o,ACTIVE)!=0:
        return finish_locked(o,w,6,get(o,ACTIVE))
    put(o,BUSY,1)
    put(o,MS,3)
    return save_release(o,w,100)

def new_binding(o:mutbuf,w:mutbuf) -> u32:
    if get(w,1144)!=2 or get(w,1136)!=SIDECAR or get(w,680)!=190:
        return finish_locked(o,w,6,2)
    if get(w,1152)==0 or get(w,1160)!=212992 or get(w,1176)!=get(o,SIDECAR_ENTRY) or get(w,1168)==0:
        return finish_locked(o,w,6,2)
    if get(w,72)==NONE or get(w,1208)==NONE:
        return finish_locked(o,w,6,3)
    if get(w,872)!=0 or get(w,880)!=0 or get(w,888)!=0:
        return finish_locked(o,w,5,4)
    zero(o,M,512)
    put(o,M,TAG)
    put(o,M+8,get(o,PID))
    put(o,M+16,get(o,SELF))
    put(o,M+24,get(o,ENTRY))
    put(o,MS,1)
    put(o,BUSY,1)
    put(o,ROOT_GUARD,1)
    put(o,SIDECAR_GUARD,1)
    put(o,VALUE_NONCE,get(w,664))
    put(o,BOUND_GLOBAL,get(o,GLOBAL_ENTRY))
    put(o,BOUND_LOADER,get(o,LOADER_ENTRY))
    put(o,BOUND_VALUE,get(o,VALUE_ENTRY))
    put(w,72,get(w,72)+1)
    put(w,1208,get(w,1208)+1)
    return save_release(o,w,10)

def initializing(s:readbuf,o:mutbuf,w:mutbuf,phase:u64,r:u64) -> u32:
    if phase==10:
        put(o,STAGE,10)
        return system(o,11,9,0,0,SPAN,3,34,NONE,0)
    if phase==11:
        if r==0 or failed(r):
            return initial_fail(o,w,1,r)
        put(o,MP,r)
        put(o,MN,SPAN)
        put(o,STAGE,20)
        return global_call(o,20,2)
    if phase==20:
        if global_reply(o,r)==0 or get(o,CHILD+88)!=1:
            return quarantine(o,w,20)
        if get(o,CHILD+96)==1:
            if cap_shape(o,CHILD+24)==0:
                return quarantine(o,w,21)
            within(o,GCAP,CHILD+24,24)
        if get(o,CHILD+8)!=0 or get(o,CHILD+80)!=0 or get(o,GCAP)==0:
            put(o,GPENDING,get(o,CHILD+80))
            return initial_fail(o,w,get(o,CHILD+8),get(o,CHILD+112))
        i=0
        while i<3:
            fd=get(o,CHILD+48+i*8)
            if fd<3 or fd>2147483647:
                return quarantine(o,w,22)
            put(o,TOOLS+i*8,fd)
            i=i+1
        if get(o,CHILD+72)>2147483647 or get(o,CHILD+128)==0 or get(o,CHILD+136)!=10100891:
            return quarantine(o,w,23)
        if get(o,CHILD+144)>2147483647 or get(o,CHILD+152)==0:
            return quarantine(o,w,24)
        put(o,SOURCEFD,get(o,CHILD+72))
        put(o,THRESHOLD,get(o,CHILD+128))
        put(o,THRESHOLD_N,get(o,CHILD+136))
        put(o,THRESHOLD_FD,get(o,CHILD+144))
        put(o,GLOBAL_NONCE,get(o,CHILD+152))
        put(o,DIGITS,get(o,CHILD+160))
        put(o,LSTARTED,1)
        put(o,STAGE,30)
        return loader_call(o,30,0)
    if phase==30:
        if loader_reply(o,r)==0 or get(o,CHILD+88)!=1:
            return quarantine(o,w,30)
        put(o,LPENDING,get(o,CHILD+80))
        if get(o,CHILD+104)==1:
            put(o,LSTARTED,3)
        if get(o,CHILD+8)!=0 or get(o,CHILD+16)!=2 or get(o,CHILD+80)!=0:
            return initial_fail(o,w,get(o,CHILD+8),get(o,CHILD+112))
        put(o,LSTARTED,2)
        put(o,STAGE,40)
        return loader_call(o,40,2)
    if phase==40:
        if loader_reply(o,r)==0 or get(o,CHILD+88)!=1:
            return quarantine(o,w,40)
        if get(o,CHILD+96)==1:
            if cap_shape(o,CHILD+24)==0:
                return quarantine(o,w,41)
            within(o,LCAP,CHILD+24,24)
        put(o,LPENDING,get(o,CHILD+80))
        if get(o,CHILD+8)!=0 or get(o,CHILD+80)!=0 or get(o,LCAP)==0:
            return initial_fail(o,w,get(o,CHILD+8),get(o,CHILD+112))
        if get(o,CHILD+48)!=4:
            return quarantine(o,w,42)
        i=0
        while i<4:
            if get(o,CHILD+128+i*8)==0:
                return quarantine(o,w,43)
            put(o,EXPORTS+i*8,get(o,CHILD+128+i*8))
            i=i+1
        # The fixed child exports are E9 rel32 stubs. Its context records the
        # actual inner mechanical entry, whose identity remains distinct.
        return memory(o,41,0,get(o,EXPORTS+8),3,CODE,5)
    if phase==41:
        if r!=0 or byte(o,CODE)!=233:
            return quarantine(o,w,44)
        displacement=0
        i=0
        while i<4:
            displacement=displacement|(byte(o,CODE+1+i)<<(i*8))
            i=i+1
        entry=get(o,EXPORTS+8)
        if entry>NONE-5:
            return quarantine(o,w,45)
        entry=entry+5
        if displacement>=2147483648:
            back=4294967296-displacement
            if entry<back:
                return quarantine(o,w,46)
            entry=entry-back
        else:
            if entry>NONE-displacement:
                return quarantine(o,w,46)
            entry=entry+displacement
        if entry==0:
            return quarantine(o,w,47)
        put(o,CONTEXT_ENTRY,entry)
        zero(o,FRAME,256)
        put(o,FRAME,BG_INIT)
        put(o,FRAME+16,get(o,SELF))
        put(o,FRAME+24,2048)
        within(o,FRAME+32,TOOLS,24)
        put(o,FRAME+56,get(o,THRESHOLD))
        put(o,FRAME+64,get(o,THRESHOLD_N))
        put(o,FRAME+72,get(o,DIGITS))
        put(o,FRAME+80,get(o,SOURCEFD))
        put(o,BSTARTED,1)
        put(o,STAGE,50)
        return call_context(o,50,256)
    if phase==50:
        if bg_reply(o,r)==0:
            return quarantine(o,w,50)
        has_pending=get(o,CHILD+64)!=0 or get(o,CHILD+72)!=0
        put(o,BPENDING,choose(has_pending,1,0))
        if get(o,CHILD+8)!=0 or get(o,CHILD+24)!=1 or get(o,CHILD+80)!=0:
            return initial_fail(o,w,get(o,CHILD+8),50)
        put(o,BSTARTED,2)
        return memory(o,51,0,get(o,MP),3,SNAP,256)
    if phase==51:
        if r!=0 or get(o,SNAP)!=BG_STATE or get(o,SNAP+8)!=get(o,PID) or get(o,SNAP+16)!=get(o,MP):
            return quarantine(o,w,51)
        if get(o,SNAP+24)!=get(o,CONTEXT_ENTRY) or get(o,SNAP+32)!=get(o,VALUE_ENTRY):
            return quarantine(o,w,52)
        if get(o,SNAP+40)!=get(o,SELF)+512 or get(o,SNAP+48)!=256 or get(o,SNAP+128)==0:
            return quarantine(o,w,53)
        if get(o,SNAP+136)!=get(w,664) or get(o,SNAP+168)!=1 or get(o,SNAP+232)!=get(o,SELF):
            return quarantine(o,w,54)
        put(o,BG_NONCE,get(o,SNAP+128))
        put(o,MS,2)
        put(o,STAGE,0)
        put(o,RETURN,1)
        return complete(o,w,0,0)
    return BAD

def closing(s:readbuf,o:mutbuf,w:mutbuf,phase:u64,r:u64) -> u32:
    if phase==100:
        if get(o,BSTARTED)!=0 and get(o,BSTARTED)!=3:
            return memory(o,101,0,get(o,MP),3,SNAP,256)
        return again(o,120)
    if phase==101:
        if r!=0:
            return quarantine(o,w,101)
        if get(o,SNAP)==0:
            i=0
            while i<256:
                if get(o,SNAP+i)!=0:
                    return quarantine(o,w,102)
                i=i+8
            put(o,BSTARTED,3)
            return again(o,120)
        if get(o,SNAP)!=BG_STATE or get(o,SNAP+16)!=get(o,MP) or get(o,SNAP+8)!=get(o,PID):
            return quarantine(o,w,103)
        state=get(o,SNAP+168)
        if state==3:
            put(o,BSTARTED,3)
            return again(o,120)
        if state==1:
            return context_control(o,102,1)
        if state==2 or state==4:
            return context_control(o,103,4)
        return quarantine(o,w,104)
    if phase==102:
        if bg_reply(o,r)==0:
            return quarantine(o,w,105)
        if get(o,CHILD+8)==6 and get(o,CHILD+24)==1 and get(o,ERROR_STATUS)==0:
            put(o,MS,2)
            return complete(o,w,6,get(o,CHILD+48))
        if get(o,CHILD+8)!=0 or get(o,CHILD+24)!=2:
            return parked(o,w,get(o,CHILD+8),106)
        return context_control(o,103,3)
    if phase==103:
        if bg_reply(o,r)==0:
            return quarantine(o,w,107)
        has_pending=get(o,CHILD+64)!=0 or get(o,CHILD+72)!=0
        put(o,BPENDING,choose(has_pending,1,0))
        if get(o,CHILD+8)!=0 or get(o,CHILD+24)!=3 or get(o,CHILD+64)!=0 or get(o,CHILD+80)!=0:
            return parked(o,w,get(o,CHILD+8),108)
        put(o,BSTARTED,3)
        return again(o,120)
    if phase==120:
        zero(o,FRAME,128)
        put(o,FRAME,VALUE_Q)
        put(o,FRAME+8,56)
        return role(o,121,12)
    if phase==121:
        if r!=0 or get(o,CHILD)!=VALUE_R:
            return quarantine(o,w,121)
        if get(o,CHILD+8)!=0 or get(w,632)!=0:
            return parked(o,w,11,122)
        put(o,BPENDING,0)
        if get(o,LCAP)!=0:
            return loader_call(o,130,3)
        return again(o,131)
    if phase==130:
        if loader_reply(o,r)==0 or get(o,CHILD+88)!=1:
            return quarantine(o,w,130)
        if get(o,CHILD+96)==1:
            zero(o,LCAP,24)
        put(o,LPENDING,get(o,CHILD+80))
        if get(o,LCAP)!=0:
            return parked(o,w,get(o,CHILD+8),131)
        return again(o,131)
    if phase==131:
        if get(o,LSTARTED)==1:
            return memory(o,134,0,get(o,MP)+LOADER_AT,3,SNAP,4096)
        if get(o,LSTARTED)!=0 and get(o,LSTARTED)!=3:
            if get(o,LPENDING)!=0:
                return loader_call(o,132,4)
            return loader_call(o,132,1)
        return again(o,140)
    if phase==132:
        if loader_reply(o,r)==0 or get(o,CHILD+88)!=1:
            return quarantine(o,w,132)
        put(o,LPENDING,get(o,CHILD+80))
        if get(o,CHILD+104)!=1 or get(o,CHILD+80)!=0:
            return parked(o,w,get(o,CHILD+8),133)
        put(o,LSTARTED,3)
        zero(o,EXPORTS,32)
        return again(o,140)
    if phase==134:
        if r!=0:
            return quarantine(o,w,134)
        if get(o,SNAP)==0:
            i=0
            while i<4096:
                if get(o,SNAP+i)!=0:
                    return quarantine(o,w,135)
                i=i+8
            put(o,LSTARTED,3)
            return again(o,140)
        return loader_call(o,132,1)
    if phase==140:
        if get(o,GCAP)!=0:
            return global_call(o,141,3)
        if get(o,GPENDING)!=0:
            return global_call(o,142,4)
        return again(o,150)
    if phase==141:
        if global_reply(o,r)==0 or get(o,CHILD+88)!=1:
            return quarantine(o,w,141)
        if get(o,CHILD+96)==1:
            zero(o,GCAP,24)
        put(o,GPENDING,get(o,CHILD+80))
        if get(o,GCAP)!=0:
            return parked(o,w,get(o,CHILD+8),142)
        return again(o,140)
    if phase==142:
        if global_reply(o,r)==0 or get(o,CHILD+88)!=1:
            return quarantine(o,w,143)
        put(o,GPENDING,get(o,CHILD+80))
        if get(o,CHILD+80)!=0 or get(o,CHILD+8)!=0:
            return parked(o,w,get(o,CHILD+8),144)
        return again(o,150)
    if phase==150:
        if get(o,MP)!=0:
            return system(o,151,11,0,get(o,MP),get(o,MN),0,0,0,0)
        return again(o,152)
    if phase==151:
        if r!=0:
            return parked(o,w,11,r)
        put(o,MP,0)
        put(o,MN,0)
        return again(o,152)
    if phase==152:
        put(o,MS,4)
        put(o,STAGE,0)
        put(o,RETURN,2)
        return complete(o,w,get(o,ERROR_STATUS),get(o,ERROR_DETAIL))
    return BAD

def forwarded(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    put(o,PH,801)
    if get(o,OP)==11:
        return 15
    return 14

def global_call(o:mutbuf,next:u64,op:u64) -> u32:
    zero(o,FRAME,128)
    put(o,FRAME,GLOBAL_Q)
    put(o,FRAME+8,op)
    if op==3:
        within(o,FRAME+24,GCAP,24)
    return role(o,next,10)

def loader_call(o:mutbuf,next:u64,op:u64) -> u32:
    zero(o,FRAME,128)
    put(o,FRAME,LOADER_Q)
    put(o,FRAME+8,op)
    if op==0:
        put(o,FRAME+16,1)
    if op==3:
        within(o,FRAME+24,LCAP,24)
    return role(o,next,11)

def context_control(o:mutbuf,next:u64,op:u64) -> u32:
    zero(o,FRAME,128)
    put(o,FRAME,BG_CONTROL)
    put(o,FRAME+8,op)
    return call_context(o,next,128)

def call_context(o:mutbuf,next:u64,n:u64) -> u32:
    put(o,META,n)
    return role(o,next,13)

def role(o:mutbuf,next:u64,action:u64) -> u32:
    zero(o,CHILD,192)
    put(o,PH,next)
    return action

def global_reply(o:mutbuf,r:u64) -> u64:
    if r!=0 or get(o,CHILD)!=GLOBAL_R:
        return 0
    if get(o,CHILD+80)>1 or get(o,CHILD+88)>1 or get(o,CHILD+96)>1 or get(o,CHILD+104)>1:
        return 0
    return 1

def loader_reply(o:mutbuf,r:u64) -> u64:
    if r!=0 or get(o,CHILD)!=LOADER_R:
        return 0
    if get(o,CHILD+80)>1 or get(o,CHILD+88)>1 or get(o,CHILD+96)>1 or get(o,CHILD+104)>1:
        return 0
    return 1

def bg_reply(o:mutbuf,r:u64) -> u64:
    if r!=0 or get(o,CHILD)!=BG_R or get(o,CHILD+16)!=1:
        return 0
    if get(o,CHILD+64)>1 or get(o,CHILD+72)>1 or get(o,CHILD+80)!=0 or get(o,CHILD+88)>1:
        return 0
    return 1

def initial_fail(o:mutbuf,w:mutbuf,status:u64,detail:u64) -> u32:
    put(o,ERROR_STATUS,choose(status==0,11,status))
    put(o,ERROR_DETAIL,detail)
    put(o,MS,3)
    return again(o,100)

def parked(o:mutbuf,w:mutbuf,status:u64,detail:u64) -> u32:
    put(o,PENDING,1)
    put(o,MS,3)
    return complete(o,w,choose(status==0,11,status),detail)

def quarantine(o:mutbuf,w:mutbuf,detail:u64) -> u32:
    put(o,MS,5)
    put(o,UNKNOWN,1)
    put(o,KNOWN,0)
    put(o,PENDING,1)
    return complete(o,w,5,detail)

def complete(o:mutbuf,w:mutbuf,status:u64,detail:u64) -> u32:
    put(o,STATUS,status)
    put(o,DETAIL,detail)
    put(o,LAST_STATUS,status)
    put(o,LAST_DETAIL,detail)
    put(o,RESUME,2)
    return lock(o,2)

def finish_locked(o:mutbuf,w:mutbuf,status:u64,detail:u64) -> u32:
    put(o,STATUS,status)
    put(o,DETAIL,detail)
    put(o,NEXT,790)
    put(o,PH,701)
    return 3

def broken_locked(o:mutbuf,w:mutbuf,detail:u64) -> u32:
    put(o,KNOWN,0)
    put(o,PENDING,1)
    return finish_locked(o,w,5,detail)

def save_release(o:mutbuf,w:mutbuf,next:u64) -> u32:
    put(o,NEXT,next)
    return memory(o,700,3,M,0,get(w,1088)+ANCHOR,512)

def unowned_reply(o:mutbuf,w:mutbuf,status:u64,detail:u64) -> u32:
    put(o,STATUS,status)
    put(o,DETAIL,detail)
    return reply(o,w)

def reply(o:mutbuf,w:mutbuf) -> u32:
    zero(o,0,128)
    if get(o,OP)==11:
        put(o,0,RFR)
        put(o,8,11)
        put(o,16,get(o,KNOWN))
        put(o,32,1)
        return 0
    if get(o,OP)==10:
        put(o,0,PUBLIC_R)
        put(o,8,get(o,STATUS))
        put(o,56,get(o,KNOWN))
        put(o,80,choose(get(o,KNOWN)==0,1,0))
        put(o,88,get(o,PENDING))
        put(o,96,get(o,DETAIL))
        return 0
    put(o,0,R)
    put(o,8,get(o,STATUS))
    put(o,16,get(o,MS))
    put(o,24,get(o,KNOWN))
    has_pending=get(o,PENDING)!=0 or get(o,GPENDING)!=0 or get(o,LPENDING)!=0 or get(o,BPENDING)!=0 or get(o,MS)==1 or get(o,MS)==3 or get(o,MS)==5
    put(o,32,choose(has_pending,1,0))
    put(o,40,choose(get(o,MS)==4,1,0))
    put(o,48,get(o,DETAIL))
    put(o,56,get(o,ACTIVE))
    put(o,64,get(o,STAGE))
    put(o,72,get(o,ROOT_GUARD)+get(o,SIDECAR_GUARD))
    put(o,80,get(w,680))
    put(o,88,choose(get(o,GCAP)!=0,1,0))
    put(o,96,choose(get(o,LCAP)!=0,1,0))
    return 0

def lock(o:mutbuf,next:u64) -> u32:
    put(o,PH,next)
    return 2

def memory(o:mutbuf,next:u64,sm:u64,source:u64,dm:u64,target:u64,n:u64) -> u32:
    put(o,META,sm)
    put(o,META+8,source)
    put(o,META+16,dm)
    put(o,META+24,target)
    put(o,META+32,n)
    put(o,PH,next)
    return 7

def system(o:mutbuf,next:u64,number:u64,mask:u64,a:u64,b:u64,c:u64,d:u64,e:u64,f:u64) -> u32:
    put(o,META,number)
    put(o,META+8,mask)
    put(o,META+16,a)
    put(o,META+24,b)
    put(o,META+32,c)
    put(o,META+40,d)
    put(o,META+48,e)
    put(o,META+56,f)
    put(o,PH,next)
    return 1

def again(o:mutbuf,next:u64) -> u32:
    put(o,PH,next)
    return 4

def cap_shape(o:mutbuf,at:u64) -> u64:
    return choose(get(o,at)!=0 and get(o,at+8)!=0 and get(o,at+16)!=0,1,0)

def empty(s:readbuf,at:u64,n:u64) -> u64:
    i=0
    while i<n:
        if byte(s,at+i)!=0:
            return 0
        i=i+1
    return 1

def failed(n:u64) -> bool:
    return n>=18446744073709547521

def choose(test:bool,yes:u64,no:u64) -> u64:
    if test:
        return yes
    return no

def word(s:readbuf,at:u64) -> u64:
    return word_load(s,at)

def get(w:mutbuf,at:u64) -> u64:
    return word_load(w,at)

def put(w:mutbuf,at:u64,n:u64) -> u64:
    i=0
    while i<8:
        store(w,at+i,(n>>(8*i))&255)
        i=i+1
    return 0

def zero(w:mutbuf,at:u64,n:u64) -> u64:
    fill_range(w,at,n,0)
    return 0

def within(w:mutbuf,to:u64,at:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(w,to+i,byte(w,at+i))
        i=i+1
    return 0
'''
def source_program():
    s=SOURCE
    for name,value in sorted(C.items(),key=lambda row:-len(row[0])):
        s=re.sub(r"\b"+name+r"\b",str(value),s)
    return s
def main():
    tree=document(source_program(),"generation_background_bind")
    path=ROOT/"examples/hia_bootstrap/generation_background_bind.hepta"
    path.write_text(render_assembly(tree))
    print(path.name,path.stat().st_size,len(tree["functions"]),sum(len(f["blocks"])for f in tree["functions"]),sum(len(b["ops"])for f in tree["functions"]for b in f["blocks"]),flush=True)
if __name__=="__main__":main()
