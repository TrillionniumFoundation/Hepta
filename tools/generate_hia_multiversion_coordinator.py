"""HIA coordinator for the owned in-process scalar-generation runtime.

The companion owns sequencing and mutation under explicit writer, selection,
lease, and cancellation locks. Its action records are a private native ABI:
an application cannot supply proof/build/readback acknowledgements. The final
runtime adapter supplies only results of the requested fixed native owner or
mechanical operation. This module alone is not a public runtime or a complete
qualification claim.
"""
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
ROOT=Path(__file__).resolve().parents[1]
MAGIC=int.from_bytes(b'HIAMVC01','little')
STATE=int.from_bytes(b'HIAMVS01','little')
NONE=(1<<64)-1
# Output is the per-invocation continuation; w is the common runtime state.
# Lock actions use codes 1 writer, 2 selection, 3 lease, 4 cancellation.
# Pinned HIA owners: 20 capture/admit, 21 scalar profile, 22 fresh proof,
# 23 actual native build/seal/load/mapping/VM probes, 24 measurement,
# 25 retention, 26 retirement; mechanical facts 30 clock,31 allocation,
# 32 typed call,33 directory preparation,34 lease lookup.
SOURCE=r'''
def multiversion_coordinator(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s) < 96 or length(o) < 4096 or length(w) < 24576:
        return 4294967295
    phase=get(o,0)
    if phase == 0:
        return begin(s,o,w)
    if phase >= 800 and phase <= 899:
        return finish(s,o,w,phase)
    if phase >= 100 and phase <= 199:
        return construct(s,o,w,phase)
    if phase >= 200 and phase <= 299:
        return publish(s,o,w,phase)
    if phase >= 300 and phase <= 399:
        return lease(s,o,w,phase)
    if phase >= 400 and phase <= 499:
        return rollback(s,o,w,phase)
    if phase >= 500 and phase <= 599:
        return close_runtime(s,o,w,phase)
    if phase >= 600 and phase <= 699:
        return cleanup(s,o,w,phase)
    if phase >= 700 and phase <= 799:
        return cancellation(s,o,w,phase)
    return 4294967295

def begin(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if word(s,0) != MAGIC or word(s,80) != 0 or word(s,88) != 0:
        return 4294967295
    op=word(s,8)
    if op > 11:
        return 4294967295
    put(o,16,op)
    put(o,24,0)
    put(o,32,NONE)
    put(o,40,NONE)
    put(o,48,word(s,32))
    put(o,56,word(s,40))
    put(o,64,word(s,48))
    put(o,72,0)
    put(o,80,word(s,56))
    put(o,96,word(s,64))
    put(o,104,0)
    put(o,112,0)
    put(o,120,0)
    put(o,128,0)
    put(o,136,0)
    put(o,144,0)
    put(o,152,0)
    if op == 0:
        return construct(s,o,w,100)
    if get(w,0) != STATE or word(s,16) != get(w,8) or word(s,24) != get(w,16):
        return fail(o,1)
    put(o,264,0)
    put(o,272,NONE)
    put(o,280,0)
    if op == 1:
        return lock(o,1,201)
    if op == 2:
        return issue(o,30,200,0,0)
    if op == 3:
        return lock(o,2,300)
    if op == 4 or op == 5 or op == 6:
        return issue(o,34,310,word(s,32),word(s,40))
    if op == 7:
        return lock(o,1,400)
    if op == 8:
        return lock(o,1,500)
    if op == 9:
        return lock(o,1,600)
    if op == 10:
        return lock(o,2,620)
    return lock(o,4,700)

def construct(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase == 100:
        if word(s,16) == 0 and word(s,24) == 0:
            return fail(o,2)
        if word(s,32) < 1 or word(s,32) > 30000:
            return fail(o,3)
        if word(s,40) < 2 or word(s,40) > 64 or word(s,48) > 1:
            return fail(o,4)
        if get(w,0) != 0:
            return fail(o,1)
        put(w,0,STATE)
        put(w,8,word(s,16))
        put(w,16,word(s,24))
        put(w,24,0)
        put(w,32,1)
        put(w,40,0)
        put(w,48,NONE)
        put(w,56,word(s,40))
        put(w,64,word(s,32))
        put(w,72,word(s,48))
        put(w,80,0)
        put(w,88,0)
        put(w,96,NONE)
        put(w,104,0)
        put(w,112,0)
        put(w,120,0)
        index=0
        while index < 64:
            clear_record(w,index)
            index=index+1
        put(o,40,0)
        put(o,136,0)
        return issue(o,20,101,0,0)
    if phase == 101:
        if get(o,8) != 0:
            put(w,24,1)
            return fail(o,10)
        return issue(o,21,102,get(w,72),0)
    if phase == 102:
        if get(o,8) != 0:
            put(w,24,1)
            return fail(o,11)
        return issue(o,33,103,0,0)
    if phase == 103:
        if get(o,8) != 0:
            put(w,24,1)
            put(o,120,12)
            return issue(o,36,107,0,0)
        reserve(w,0,0,1)
        return issue(o,23,104,0,1)
    if phase == 104:
        if get(o,8) != 0:
            put(w,24,1)
            put(o,120,13)
            put(o,144,106)
            return dispose_prepared(o,w)
        put(w,512,2)
        put(w,80,1)
        put(w,48,0)
        put(w,96,NONE)
        put(o,32,0)
        return done(o)
    if phase == 106:
        put(o,120,13)
        return issue(o,36,107,0,0)
    if phase == 107:
        return fail(o,get(o,120))
    return fail(o,127)

def publish(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    conditional=get(o,16)==2
    if phase == 200:
        if get(o,8) != 0:
            return fail(o,14)
        put(o,72,get(o,176))
        if conditional:
            if get(o,64) >= 9223372036854775808 or get(o,96) > 1:
                return fail(o,15)
            if word(s,72) != NONE:
                if get(o,96) != 0 or word(s,72) > get(o,72):
                    return fail(o,16)
                put(o,72,word(s,72))
        return lock(o,1,201)
    if phase == 201:
        if get(o,8) != 0:
            return fail(o,17)
        held(o,1)
        return lock(o,2,202)
    if phase == 202:
        if get(o,8) != 0:
            return fail(o,17)
        held(o,2)
        if get(w,24) != 0:
            return fail(o,18)
        if conditional:
            if current_matches(o,w)==0:
                return fail(o,19)
            return issue(o,35,231,get(o,80),0)
        return publish_admission(o,w)
    if phase == 231:
        if get(o,8)!=0:
            return fail(o,37)
        if get(o,184)!=0:
            return fail(o,21)
        return issue(o,30,203,0,0)
    if phase == 203:
        if get(o,8) != 0:
            return fail(o,14)
        if elapsed(o) > get(o,64):
            return fail(o,20)
        return lock(o,4,204)
    if phase == 204:
        if get(o,8) != 0:
            return fail(o,17)
        held(o,4)
        # Cancellation state is an actual native token observation, never a
        # caller flag. It is protected by the requested token mutex.
        if get(o,192) != 0:
            return fail(o,22)
        return unlock(o,4,205)
    if phase == 205:
        return publish_admission(o,w)
    if phase == 206:
        if get(o,16)==1:
            return issue(o,38,219,0,0)
        return issue(o,20,207,0,0)
    if phase == 219:
        if get(o,8)!=0:
            clear_record(w,get(o,40))
            put(w,96,NONE)
            put(o,40,NONE)
            return fail(o,29)
        return issue(o,20,207,0,0)
    if phase == 207:
        if get(o,8) != 0:
            return prepare_failed(o,w,10)
        return issue(o,21,208,get(w,72),1)
    if phase == 208:
        if get(o,8) != 0:
            return prepare_failed(o,w,11)
        if get(o,96) != 0:
            return issue(o,24,209,0,get(o,40))
        return issue(o,22,210,get(o,40),0)
    if phase == 209:
        if get(o,8) != 0:
            return prepare_failed(o,w,23)
        return issue(o,22,210,get(o,40),0)
    if phase == 210:
        if get(o,8) != 0:
            return prepare_failed(o,w,24)
        if conditional:
            return issue(o,35,232,get(o,80),0)
        return issue(o,23,214,get(o,40),0)
    if phase == 232:
        if get(o,8)!=0:
            return prepare_failed(o,w,37)
        if get(o,184)!=0:
            return prepare_failed(o,w,21)
        return issue(o,30,211,0,0)
    if phase == 211:
        if get(o,8) != 0:
            return prepare_failed(o,w,14)
        if elapsed(o) > get(o,64):
            return prepare_failed(o,w,20)
        return issue(o,23,214,get(o,40),0)
    if phase == 212:
        if get(o,8) != 0:
            return prepare_failed(o,w,17)
        held(o,4)
        if get(o,184) != 0:
            return prepare_failed(o,w,21)
        return unlock(o,4,213)
    if phase == 213:
        return issue(o,23,214,get(o,40),0)
    if phase == 214:
        if get(o,8) != 0:
            return prepare_failed(o,w,13)
        return lock(o,2,215)
    if phase == 215:
        if get(o,8) != 0:
            return prepare_failed(o,w,17)
        held(o,2)
        if get(w,24) != 0:
            return prepare_failed(o,w,18)
        if conditional and current_matches(o,w)==0:
            return prepare_failed(o,w,19)
        return lock(o,4,216)
    if phase == 216:
        if get(o,8) != 0:
            return prepare_failed(o,w,17)
        held(o,4)
        if get(o,184) != 0:
            return prepare_failed(o,w,21)
        if conditional:
            return issue(o,30,217,0,0)
        if get(o,192)!=0:
            return prepare_failed(o,w,22)
        return select_prepared(o,w)
    if phase == 217:
        if get(o,8) != 0:
            return prepare_failed(o,w,14)
        if elapsed(o) > get(o,64):
            return prepare_failed(o,w,20)
        if get(o,192)!=0:
            return prepare_failed(o,w,22)
        return issue(o,30,233,0,0)
    if phase == 233:
        if get(o,8)!=0:
            return prepare_failed(o,w,14)
        if elapsed(o)>get(o,64):
            return prepare_failed(o,w,20)
        if get(o,96) != 0:
            return issue(o,24,218,1,get(o,40))
        return select_prepared(o,w)
    if phase == 218:
        if get(o,8) != 0:
            return prepare_failed(o,w,23)
        return select_prepared(o,w)
    if phase == 220:
        # On a failed acknowledgement read the same owned token's actual
        # commit marker before choosing rollback or resource retirement.
        if get(o,8) != 0:
            if get(o,192)==0:
                put(w,48,get(o,152))
                put(w,40,get(w,40)-1)
                put(w,record(get(o,40)),1)
                put(w,80,get(w,80)-1)
                return prepare_failed(o,w,25)
            put(o,104,1)
            put(w,96,NONE)
            return fail(o,25)
        put(o,104,1)
        put(w,96,NONE)
        event(o,w,choose(conditional,2,1),get(o,136))
        previous=get(o,152)
        if get(w,record(previous)+16)==1:
            return done(o)
        put(o,32,previous)
        put(o,144,222)
        return issue(o,25,660,previous,3)
    if phase == 222:
        return done(o)
    if phase == 230:
        return fail(o,get(o,120))
    return fail(o,127)

def publish_admission(o:mutbuf,w:mutbuf) -> u32:
    if get(w,80)+get(w,88) >= get(w,56):
        return fail(o,26)
    slot=free_slot(w)
    if slot==NONE:
        return fail(o,27)
    number=get(w,32)
    if number==NONE:
        return fail(o,28)
    put(w,32,number+1)
    reserve(w,slot,number,0)
    put(o,40,slot)
    put(o,136,number)
    return unlock(o,2,206)

def select_prepared(o:mutbuf,w:mutbuf) -> u32:
    slot=get(o,40)
    if slot >= 64 or get(w,record(slot)) != 1:
        return prepare_failed(o,w,27)
    previous=get(w,48)
    if previous >= 64 or get(w,record(previous)) != 2:
        return prepare_failed(o,w,27)
    if get(w,40)==NONE:
        return prepare_failed(o,w,28)
    put(o,152,previous)
    put(w,record(slot),2)
    put(w,80,get(w,80)+1)
    put(w,48,slot)
    put(w,40,get(w,40)+1)
    put(o,32,slot)
    # The token owner action has no user callback and stores its committed
    # marker while both selection and cancellation locks remain held.
    return issue(o,35,220,get(o,80),1)

def lease(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase == 300:
        if get(o,8)!=0:
            return fail(o,17)
        held(o,2)
        if get(w,24)!=0:
            return fail(o,18)
        slot=get(w,48)
        if slot>=64 or get(w,record(slot))!=2:
            return fail(o,27)
        put(o,32,slot)
        return issue(o,31,301,slot,get(w,40))
    if phase == 301:
        if get(o,8)!=0:
            return fail(o,29)
        return issue(o,25,302,get(o,32),1)
    if phase == 302:
        if get(o,8)!=0:
            return fail(o,30)
        return done(o)
    if phase == 310:
        if get(o,8)!=0:
            return fail(o,31)
        put(o,32,get(o,200))
        return lock(o,3,311)
    if phase == 311:
        if get(o,8)!=0:
            return fail(o,17)
        held(o,3)
        if get(o,16)==6:
            return done(o)
        return issue(o,25,312,get(o,32),6)
    if phase == 312:
        if get(o,8)!=1 and get(o,8)!=2:
            return fail(o,30)
        if get(o,16)==5:
            return lock(o,2,315)
        if get(o,8)!=1:
            return fail(o,32)
        return issue(o,32,313,get(o,32),0)
    if phase == 313:
        if get(o,8)!=0:
            return fail(o,33)
        return done(o)
    if phase == 315:
        if get(o,8)!=0:
            return fail(o,17)
        held(o,2)
        return issue(o,25,316,get(o,32),2)
    if phase == 316:
        if get(o,8)>1:
            return fail(o,30)
        slot=get(o,32)
        if slot>=64 or (get(w,record(slot))&2)==0:
            return done(o)
        if get(w,record(slot)+8)!=get(o,272):
            return done(o)
        put(o,144,317)
        return issue(o,25,661,slot,5)
    if phase == 317:
        return done(o)
    return fail(o,127)

def rollback(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==400:
        if get(o,8)!=0:
            return fail(o,17)
        held(o,1)
        return lock(o,2,401)
    if phase==401:
        if get(o,8)!=0:
            return fail(o,17)
        held(o,2)
        if get(w,24)!=0:
            return fail(o,18)
        previous=get(w,48)
        if previous==0:
            put(o,32,0)
            return done(o)
        if previous>=64 or get(w,512)!=2 or get(w,40)==NONE:
            return fail(o,27)
        put(w,48,0)
        put(w,40,get(w,40)+1)
        event(o,w,3,0)
        put(o,32,previous)
        put(o,144,402)
        return issue(o,25,660,previous,3)
    if phase==402:
        put(o,32,0)
        return done(o)
    return fail(o,127)

def close_runtime(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==500:
        if get(o,8)!=0:
            return fail(o,17)
        held(o,1)
        return lock(o,2,501)
    if phase==501:
        if get(o,8)!=0:
            return fail(o,17)
        held(o,2)
        put(w,24,1)
        put(w,48,NONE)
        put(o,224,0)
        put(o,232,0)
        return close_next(o,w)
    if phase==503:
        if get(o,120)!=0 and get(o,232)==0:
            put(o,232,get(o,120))
        put(o,120,0)
        put(o,224,get(o,224)+1)
        return close_next(o,w)
    if phase==504:
        if get(o,232)!=0:
            return fail(o,get(o,232))
        if get(o,8)!=0:
            return fail(o,34)
        return done(o)
    return fail(o,127)

def close_next(o:mutbuf,w:mutbuf) -> u32:
    i=get(o,224)
    while i<64:
        if (get(w,record(i))&2)!=0:
            put(o,224,i)
            put(o,32,i)
            put(o,144,503)
            return issue(o,25,660,i,3)
        i=i+1
    if get(w,80)==0:
        return issue(o,36,504,0,0)
    put(o,8,0)
    put(o,0,504)
    return 100

def cleanup(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==600:
        if get(o,8)!=0:
            return fail(o,17)
        held(o,1)
        return lock(o,2,601)
    if phase==601:
        if get(o,8)!=0:
            return fail(o,17)
        held(o,2)
        put(o,224,0)
        return cleanup_next(o,w)
    if phase==603:
        if get(o,216)!=0:
            release_record(w,get(o,32))
        if get(o,8)!=0:
            return fail(o,35)
        put(o,224,get(o,224)+1)
        return cleanup_next(o,w)
    if phase==604:
        if get(o,8)!=0:
            return fail(o,34)
        return issue(o,37,621,0,0)
    if phase==620:
        if get(o,8)!=0:
            return fail(o,17)
        held(o,2)
        return issue(o,37,621,0,0)
    if phase==621:
        if get(o,8)!=0:
            return fail(o,36)
        return done(o)
    if phase==650:
        slot=get(o,40)
        if get(o,216)!=0 and slot<64:
            release_record(w,slot)
        if get(o,8)!=0:
            return continue_cleanup(o,35)
        put(o,0,get(o,144))
        return 100
    if phase==660:
        if get(o,8)!=0:
            return continue_cleanup(o,30)
        return issue(o,25,661,get(o,32),5)
    if phase==661:
        if get(o,8)>=4294967280:
            return continue_cleanup(o,30)
        if (get(o,8)&8)==0:
            put(o,0,get(o,144))
            return 100
        # Register ownership before the leaf retirement claim or any release.
        slot=get(o,32)
        if slot>=64 or (get(w,record(slot))&2)==0:
            return continue_cleanup(o,27)
        return issue(o,26,662,slot,0)
    if phase==662:
        slot=get(o,32)
        if get(o,280)!=0 and (get(w,record(slot))&4)==0:
            put(w,record(slot),6)
            put(w,88,get(w,88)+1)
        if get(o,8)!=0:
            return continue_cleanup(o,35)
        if get(o,280)==0:
            return continue_cleanup(o,35)
        return issue(o,25,663,slot,4)
    if phase==663:
        if get(o,8)>1:
            return continue_cleanup(o,30)
        slot=get(o,32)
        if get(w,record(slot))==6:
            put(w,record(slot),4)
            put(w,80,get(w,80)-1)
        return issue(o,26,664,slot,2)
    if phase==664:
        if get(o,216)!=0:
            number=get(w,record(get(o,32))+8)
            release_record(w,get(o,32))
        else:
            number=get(w,record(get(o,32))+8)
        if get(o,8)!=0:
            return continue_cleanup(o,35)
        if get(o,144)!=603:
            event(o,w,4,number)
            if get(w,24)!=0 and get(w,80)==0:
                return issue(o,36,665,0,0)
        put(o,0,get(o,144))
        return 100
    if phase==665:
        if get(o,8)!=0:
            return continue_cleanup(o,34)
        put(o,0,get(o,144))
        return 100
    if phase==680:
        if get(o,8)!=0:
            return fail(o,17)
        held(o,2)
        return dispose_prepared(o,w)
    if phase==681:
        return prepare_dispose(o,w)
    return fail(o,127)

def cleanup_next(o:mutbuf,w:mutbuf) -> u32:
    i=get(o,224)
    while i<64:
        if (get(w,record(i))&4)!=0:
            put(o,224,i)
            put(o,32,i)
            if get(w,record(i))==6:
                put(o,144,603)
                return issue(o,25,661,i,5)
            # Mode 3 retries path cleanup only. fd/dlclose and identity-close
            # uncertainty remain with the same existing retirement owner.
            return issue(o,26,603,i,3)
        i=i+1
    if get(w,24)!=0 and get(w,80)==0:
        return issue(o,36,604,0,0)
    return issue(o,37,621,0,0)

def cancellation(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==700:
        if get(o,8)!=0:
            return fail(o,17)
        held(o,4)
        if get(o,192)!=0:
            put(o,240,0)
            return done(o)
        return issue(o,35,701,get(o,80),2)
    if phase==701:
        if get(o,8)!=0:
            return fail(o,37)
        put(o,240,1)
        return done(o)
    return fail(o,127)

def prepare_failed(o:mutbuf,w:mutbuf,error:u64) -> u32:
    put(o,120,error)
    if get(o,104)!=0:
        return fail(o,error)
    if get(o,40)==NONE:
        return fail(o,error)
    # Cleanup registration must be performed under the selection lock.
    put(o,144,230)
    if (get(o,24)&8)!=0:
        return unlock(o,4,681)
    return prepare_dispose(o,w)

def prepare_dispose(o:mutbuf,w:mutbuf) -> u32:
    if (get(o,24)&2)==0:
        return lock(o,2,680)
    return dispose_prepared(o,w)

def dispose_prepared(o:mutbuf,w:mutbuf) -> u32:
    slot=get(o,40)
    if get(o,264)==0:
        clear_record(w,slot)
        put(w,96,NONE)
        put(o,0,get(o,144))
        return 100
    if get(o,264)==2:
        if slot<64 and get(w,record(slot))==1:
            put(w,record(slot),4)
            put(w,88,get(w,88)+1)
        put(w,96,NONE)
        put(o,0,get(o,144))
        return 100
    if slot<64 and get(w,record(slot))==1:
        put(w,record(slot),4)
        put(w,88,get(w,88)+1)
    put(w,96,NONE)
    return issue(o,26,650,slot,1)

def continue_cleanup(o:mutbuf,error:u64) -> u32:
    put(o,120,error)
    put(o,0,get(o,144))
    return 100

def finish(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==800:
        heldmask=get(o,24)
        if (heldmask&8)!=0:
            return unlock(o,4,800)
        if (heldmask&2)!=0:
            return unlock(o,2,800)
        if (heldmask&4)!=0:
            return unlock(o,3,800)
        if (heldmask&1)!=0:
            return unlock(o,1,800)
        put(o,0,801)
        return 101
    if phase==801:
        return narrow(get(o,120))
    return 4294967295

def current_matches(o:mutbuf,w:mutbuf) -> u64:
    slot=get(w,48)
    if slot>=64:
        return 0
    return choose(get(w,record(slot)+8)==get(o,48) and get(w,40)==get(o,56),1,0)

def elapsed(o:mutbuf) -> u64:
    now=get(o,176)
    started=get(o,72)
    return choose(now>=started,now-started,NONE)

def reserve(w:mutbuf,slot:u64,number:u64,baseline:u64) -> u64:
    clear_record(w,slot)
    put(w,record(slot),1)
    put(w,record(slot)+8,number)
    put(w,record(slot)+16,baseline)
    put(w,96,slot)
    return 0

def release_record(w:mutbuf,slot:u64) -> u64:
    if slot<64 and get(w,record(slot))==4:
        put(w,88,get(w,88)-1)
        clear_record(w,slot)
    return 0

def clear_record(w:mutbuf,slot:u64) -> u64:
    i=0
    while i<256:
        store(w,record(slot)+i,0)
        i=i+1
    return 0

def free_slot(w:mutbuf) -> u64:
    i=0
    while i<64:
        if get(w,record(i))==0:
            return i
        i=i+1
    return NONE

def event(o:mutbuf,w:mutbuf,kind:u64,number:u64) -> u64:
    head=get(w,112)
    at=17408+head*48
    put(w,at,kind)
    put(w,at+8,number)
    put(w,at+16,get(w,40))
    put(w,at+24,choose(kind==2,elapsed(o),0))
    put(w,at+32,choose(kind==2,get(o,64),0))
    put(w,at+40,0)
    put(w,112,choose(head==127,0,head+1))
    if get(w,104)<128:
        put(w,104,get(w,104)+1)
    return 0

def record(slot:u64) -> u64:
    return 512+slot*256

def held(o:mutbuf,which:u64) -> u64:
    put(o,24,get(o,24)|(1<<(which-1)))
    return 0

def lock(o:mutbuf,which:u64,next:u64) -> u32:
    return issue(o,1,next,which,0)

def unlock(o:mutbuf,which:u64,next:u64) -> u32:
    put(o,24,get(o,24)&(NONE^(1<<(which-1))))
    return issue(o,2,next,which,0)

def issue(o:mutbuf,action:u64,next:u64,a:u64,b:u64) -> u32:
    put(o,0,next)
    put(o,160,action)
    put(o,168,a)
    put(o,248,b)
    return narrow(action)

def done(o:mutbuf) -> u32:
    put(o,0,800)
    return 100

def fail(o:mutbuf,error:u64) -> u32:
    put(o,120,error)
    put(o,0,800)
    return 100

def word(s:readbuf,at:u64) -> u64:
    result=0
    i=0
    while i<8:
        result=result|(byte(s,at+i)<<(8*i))
        i=i+1
    return result

def get(s:mutbuf,at:u64) -> u64:
    result=0
    i=0
    while i<8:
        result=result|(byte(s,at+i)<<(8*i))
        i=i+1
    return result

def put(o:mutbuf,at:u64,value:u64) -> u64:
    i=0
    while i<8:
        store(o,at+i,(value>>(8*i))&255)
        i=i+1
    return 0

def narrow(value:u64) -> u32:
    return value
'''
def source_program():
    return SOURCE.replace('MAGIC',str(MAGIC)).replace('STATE',str(STATE)).replace('NONE',str(NONE))
def main():
    source=source_program()
    # Artifact-publication builder retains exact control-flow; no target
    # compilation occurs in this development author.
    tree=document(source,'multiversion_coordinator')
    path=ROOT/'examples/hia_bootstrap/multiversion_coordinator.hepta'
    path.write_text(render_assembly(tree))
    print('MULTIVERSION_COORDINATOR',len(tree['functions']),sum(len(f['blocks']) for f in tree['functions']),sum(len(b['ops']) for f in tree['functions'] for b in f['blocks']),path.stat().st_size)
if __name__=='__main__':main()
