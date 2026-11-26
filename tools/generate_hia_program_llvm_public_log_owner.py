"""Native ownership of one public command log and its in-progress row."""
from tools import generate_hia_clang_capture_common as common
C=dict(PHASE=256,RESULT=264,ERROR=272,ERROR_NO=280,
 L_STATE=104,L_MODE=112,L_BASE=312,L_SOURCE=320,L_SN=328,L_OUTPUT=336,L_ON=344,
 L_OP=304,L_MAP=352,L_MAP_CAP=360,L_MAP_NEED=368,L_INDEX=376,L_COUNT=384,
 L_CLEAN_INDEX=392,L_KEEP=400,L_PRIMARY=408,L_ATTACHED=416,L_RETIRING=424,
 L_MAP_PENDING=432,L_QUEUE_PENDING=440,L_CLEAN_ERROR=448,L_UNKNOWN=456,
 L_TOKEN=72,L_TOKEN_HELD=96,L_REFS=512,L_RQ=2048,L_VR=4096,
 L_REQUEST=int.from_bytes(b'HIALLVQ1','little'),L_REPLY=int.from_bytes(b'HIALLVR1','little'),
 L_BIND=int.from_bytes(b'HIALLVB1','little'),
 V1=int.from_bytes(b'HIABVR01','little'),V2=int.from_bytes(b'HIABVR02','little'),
 Q5=int.from_bytes(b'HIABVQ05','little'),Q6=int.from_bytes(b'HIABVQ06','little'),
 Q7=int.from_bytes(b'HIABVQ07','little'),Q9=int.from_bytes(b'HIABVQ09','little'),Q10=int.from_bytes(b'HIABVQ10','little'))
SOURCE=r'''
def advance(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase=get(w,PHASE)
    r=get(w,RESULT)
    if phase==0:
        return begin(s,o,w)
    if phase==10:
        if valid(w,V1)==False:
            return log_unknown(w)
        if get(w,L_VR+8)!=0 or get(w,L_VR+16)!=5:
            return log_fail(w,2,get(w,L_VR+8))
        request(w,Q6,21)
        return value(w,11,L_RQ,128)
    if phase==11:
        if valid(w,V1)==False:
            return log_unknown(w)
        if get(w,L_VR+24)!=0:
            if get(w,L_VR+32)==0 or get(w,L_VR+40)==0:
                return log_unknown(w)
            copy_within(w,L_VR+24,L_TOKEN,24)
            put(w,L_TOKEN_HELD,1)
        if get(w,L_VR+8)!=0 or get(w,L_TOKEN_HELD)!=1:
            return log_fail(w,5,get(w,L_VR+8))
        request(w,Q5,91)
        i=0
        while i<24:
            store(w,L_RQ+24+i,byte(s,40+i))
            i=i+1
        return value(w,12,L_RQ,128)
    if phase==12:
        if hold(w,0)==False:
            return log_fail(w,5,get(w,L_VR+8))
        put(w,L_STATE,1)
        put(w,L_PRIMARY,1)
        put(w,L_KEEP,1)
        return cleaning(w)
    if phase==20:
        if failed(r):
            return log_fail(w,5,errno(r))
        put(w,L_MAP,r)
        put(w,L_MAP_CAP,get(w,L_MAP_NEED))
        request(w,Q10,1)
        put(w,L_RQ+96,word(s,96))
        return copying(w,21,get(w,L_BASE)+L_RQ,r,128)
    if phase==21:
        if r!=0:
            return log_unknown(w)
        return copying(w,22,get(w,L_SOURCE)+128,get(w,L_MAP)+128,word(s,96))
    if phase==22:
        if r!=0:
            return log_unknown(w)
        return invoke(w,23,1,get(w,L_MAP),128+word(s,96),get(w,L_BASE)+L_VR,16384,0,0)
    if phase==23:
        slot=choose(get(w,L_OP)==0,1,2)
        if hold(w,slot)==False:
            return log_fail(w,5,get(w,L_VR+8))
        request(w,Q6,7)
        argument(w,24,slot)
        return value(w,24,L_RQ,128)
    if phase==24:
        if valid(w,V1)==False:
            return log_unknown(w)
        if get(w,L_VR+8)!=0 or get(w,L_VR+16)!=6:
            return log_fail(w,2,get(w,L_VR+8))
        if get(w,L_OP)==0:
            request(w,Q7,16)
            argument(w,24,0)
            argument(w,48,1)
            return value(w,25,L_RQ,128)
        put(w,L_COUNT,get(w,L_VR+48))
        put(w,L_INDEX,0)
        return next_patch(w)
    if phase==25:
        if valid(w,V1)==False:
            return log_unknown(w)
        if get(w,L_VR+8)!=0:
            return log_fail(w,5,get(w,L_VR+8))
        put(w,L_ATTACHED,1)
        put(w,L_STATE,2)
        put(w,L_PRIMARY,1)
        put(w,L_KEEP,2)
        return cleaning(w)
    if phase==30:
        if hold(w,2)==False:
            return log_fail(w,5,get(w,L_VR+8))
        request(w,Q6,7)
        argument(w,24,2)
        return value(w,24,L_RQ,128)
    if phase==32:
        if valid(w,V1)==False:
            return log_unknown(w)
        if get(w,L_VR+8)!=0 or get(w,L_VR+64)!=1 or get(w,L_VR+48)!=get(w,L_COUNT):
            return log_fail(w,5,get(w,L_VR+8))
        if get(w,L_VR+8192+16)==0 or get(w,L_VR+8192+40)==0:
            return log_unknown(w)
        copy_within(w,L_VR+8192+16,L_REFS+96,24)
        put(w,L_REFS+120,1)
        copy_within(w,L_VR+8192+40,L_REFS+128,24)
        put(w,L_REFS+152,1)
        request(w,Q6,10)
        argument(w,24,1)
        argument(w,48,3)
        argument(w,72,4)
        return value(w,33,L_RQ,128)
    if phase==33:
        if valid(w,V1)==False:
            return log_unknown(w)
        if get(w,L_VR+8)!=0:
            return log_fail(w,5,get(w,L_VR+8))
        return drop_ref(w,34,3)
    if phase==34:
        if released(w,L_REFS+96)==False:
            return log_release_pending(w)
        return drop_ref(w,35,4)
    if phase==35:
        if released(w,L_REFS+128)==False:
            return log_release_pending(w)
        put(w,L_INDEX,get(w,L_INDEX)+1)
        return next_patch(w)
    if phase==600:
        i=get(w,L_CLEAN_INDEX)
        while i>get(w,L_KEEP):
            i=i-1
            put(w,L_CLEAN_INDEX,i)
            if get(w,L_REFS+i*32+24)!=0:
                return drop_ref(w,601,i)
        return jump(w,602)
    if phase==601:
        if released(w,L_REFS+get(w,L_CLEAN_INDEX)*32)==False:
            return log_release_pending(w)
        return jump(w,600)
    if phase==602:
        if get(w,L_MAP)!=0:
            return call(o,w,603,11,get(w,L_MAP),get(w,L_MAP_CAP),0,0,0,0,0)
        return jump(w,604)
    if phase==603:
        if failed(r):
            put(w,L_CLEAN_ERROR,11)
            put(w,ERROR_NO,errno(r))
            put(w,L_STATE,5)
            return log_reply(o,w)
        put(w,L_MAP,0)
        put(w,L_MAP_CAP,0)
        return jump(w,604)
    if phase==604:
        if get(w,L_RETIRING)!=0 and get(w,L_TOKEN_HELD)!=0:
            request(w,Q5,92)
            copy_within(w,L_TOKEN,L_RQ+24,24)
            return value(w,605,L_RQ,128)
        return retry_facts(w)
    if phase==605:
        if valid(w,V2)==False or get(w,L_VR+88)!=1 or get(w,L_VR+120)!=1:
            return log_unknown(w)
        put(w,L_MAP_PENDING,get(w,L_VR+104))
        put(w,L_QUEUE_PENDING,get(w,L_VR+112))
        if get(w,L_VR+96)!=1:
            return log_release_pending(w)
        clear(w,L_TOKEN,24)
        put(w,L_TOKEN_HELD,0)
        return retry_facts(w)
    if phase==606:
        if valid(w,V2)==False or get(w,L_VR+88)!=1 or get(w,L_VR+120)!=1:
            return log_unknown(w)
        put(w,L_MAP_PENDING,get(w,L_VR+104))
        put(w,L_QUEUE_PENDING,get(w,L_VR+112))
        if get(w,L_MAP_PENDING)!=0:
            return log_release_pending(w)
        status=get(w,L_VR+8)
        if status!=0 and status!=6 and (status!=11 or get(w,L_QUEUE_PENDING)==0):
            return log_release_pending(w)
        if get(w,L_RETIRING)!=0:
            put(w,L_STATE,6)
        return log_reply(o,w)
    if phase==699:
        return log_reply(o,w)
    return 4294967293

def begin(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if get(w,L_MODE)==0:
        put(w,ERROR,0)
        put(w,ERROR_NO,0)
        put(w,L_CLEAN_ERROR,0)
        put(w,L_PRIMARY,0)
        put(w,L_OP,4)
        put(w,L_STATE,3)
        put(w,L_RETIRING,0)
        request(w,Q6,7)
        i=0
        while i<24:
            store(w,L_RQ+24+i,byte(s,40+i))
            i=i+1
        return value(w,10,L_RQ,128)
    if length(s)<128 or word(s,0)!=L_REQUEST or word(s,8)>3:
        return 4294967293
    op=word(s,8)
    if word(s,96)!=length(s)-128:
        return 4294967293
    if (op<2 and word(s,96)==0) or (op>=2 and word(s,96)!=0):
        return 4294967293
    i=16
    while i<128:
        skip=i==96 or (op==2 and i>=24 and i<48)
        if skip==False and word(s,i)!=0:
            return 4294967293
        i=i+8
    if op==0 and get(w,L_STATE)!=1:
        return 4294967293
    if (op==1 or op==2) and get(w,L_STATE)!=2:
        return 4294967293
    put(w,ERROR,0)
    put(w,ERROR_NO,0)
    put(w,L_CLEAN_ERROR,0)
    put(w,L_PRIMARY,0)
    if get(w,L_UNKNOWN)!=0:
        put(w,ERROR,19)
        return log_reply(o,w)
    put(w,L_OP,op)
    if op==3:
        if get(w,L_STATE)==6:
            put(w,L_PRIMARY,1)
            return log_reply(o,w)
        put(w,L_RETIRING,1)
        put(w,L_KEEP,0)
        put(w,L_PRIMARY,1)
        return cleaning(w)
    put(w,L_RETIRING,0)
    if op==2:
        request(w,Q5,91)
        i=0
        while i<24:
            store(w,L_RQ+24+i,byte(s,24+i))
            i=i+1
        return value(w,30,L_RQ,128)
    if word(s,96)>9223372036854771584:
        return log_fail(w,5,12)
    need=(word(s,96)+128+4095)&18446744073709547520
    put(w,L_MAP_NEED,need)
    return call(o,w,20,9,0,need,3,34,NONE,0,0)

def next_patch(w:mutbuf) -> u32:
    if get(w,L_INDEX)==get(w,L_COUNT):
        put(w,L_STATE,1)
        put(w,L_PRIMARY,1)
        put(w,L_ATTACHED,0)
        put(w,L_KEEP,1)
        return cleaning(w)
    request(w,Q9,23)
    argument(w,24,2)
    put(w,L_RQ+104,get(w,L_INDEX))
    put(w,L_RQ+112,1)
    return value(w,32,L_RQ,128)

def invoke(w:mutbuf,next:u64,role:u64,si:u64,sn:u64,oi:u64,on:u64,wi:u64,wn:u64) -> u32:
    put(w,PHASE,next)
    put(w,160,role)
    put(w,168,si)
    put(w,176,sn)
    put(w,184,oi)
    put(w,192,on)
    put(w,200,wi)
    put(w,208,wn)
    return 2

def value(w:mutbuf,next:u64,si:u64,sn:u64) -> u32:
    return invoke(w,next,1,get(w,L_BASE)+si,sn,get(w,L_BASE)+L_VR,16384,0,0)

def copying(w:mutbuf,next:u64,si:u64,oi:u64,n:u64) -> u32:
    return invoke(w,next,0,si,n,oi,n,0,0)

def request(w:mutbuf,magic:u64,op:u64) -> u64:
    clear(w,L_RQ,128)
    put(w,L_RQ,magic)
    put(w,L_RQ+8,op)
    return 0

def argument(w:mutbuf,at:u64,index:u64) -> u64:
    copy_within(w,L_REFS+index*32,L_RQ+at,24)
    return 0

def copy_within(w:mutbuf,source:u64,target:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(w,target+i,byte(w,source+i))
        i=i+1
    return 0

def valid(w:mutbuf,magic:u64) -> bool:
    return get(w,RESULT)==0 and get(w,L_VR)==magic

def hold(w:mutbuf,index:u64) -> bool:
    if valid(w,V1)==False:
        put(w,L_UNKNOWN,1)
        return False
    if get(w,L_VR+24)!=0:
        if get(w,L_VR+32)==0 or get(w,L_VR+40)==0:
            put(w,L_UNKNOWN,1)
            return False
        copy_within(w,L_VR+24,L_REFS+index*32,24)
        put(w,L_REFS+index*32+24,1)
    return get(w,L_VR+8)==0 and get(w,L_REFS+index*32+24)==1

def drop_ref(w:mutbuf,next:u64,index:u64) -> u32:
    request(w,Q5,78)
    argument(w,24,index)
    return value(w,next,L_RQ,128)

def released(w:mutbuf,slot:u64) -> bool:
    if valid(w,V2)==False or get(w,L_VR+88)!=1 or get(w,L_VR+120)!=1:
        put(w,L_UNKNOWN,1)
        return False
    put(w,L_MAP_PENDING,get(w,L_VR+104))
    put(w,L_QUEUE_PENDING,get(w,L_VR+112))
    if get(w,L_VR+96)!=1:
        return False
    if get(w,L_VR+8)!=0 and get(w,L_VR+112)==0:
        put(w,L_CLEAN_ERROR,get(w,L_VR+8))
    clear(w,slot,32)
    return True

def retry_facts(w:mutbuf) -> u32:
    request(w,Q5,93)
    return value(w,606,L_RQ,128)

def cleaning(w:mutbuf) -> u32:
    put(w,L_CLEAN_INDEX,5)
    return jump(w,600)

def log_fail(w:mutbuf,error:u64,detail:u64) -> u32:
    if get(w,L_UNKNOWN)!=0:
        return log_unknown(w)
    if get(w,ERROR)==0:
        put(w,ERROR,error)
        put(w,ERROR_NO,detail)
    if get(w,L_MODE)==0:
        put(w,L_KEEP,0)
        put(w,L_RETIRING,1)
    else:
        put(w,L_KEEP,choose(get(w,L_ATTACHED)!=0,2,1))
    put(w,L_STATE,4)
    return cleaning(w)

def log_unknown(w:mutbuf) -> u32:
    put(w,L_UNKNOWN,1)
    put(w,ERROR,19)
    put(w,L_STATE,5)
    return jump(w,699)

def log_release_pending(w:mutbuf) -> u32:
    put(w,L_CLEAN_ERROR,11)
    put(w,L_STATE,5)
    return jump(w,699)

def log_reply(o:mutbuf,w:mutbuf) -> u32:
    clear(o,0,128)
    put(o,0,L_REPLY)
    error=choose(get(w,ERROR)==0,get(w,L_CLEAN_ERROR),get(w,ERROR))
    put(o,8,choose(get(w,L_UNKNOWN)!=0,19,error))
    put(o,16,get(w,ERROR_NO))
    put(o,24,get(w,L_OP))
    put(o,32,get(w,L_STATE))
    put(o,40,get(w,L_PRIMARY))
    put(o,48,get(w,L_REFS+24))
    put(o,56,get(w,L_REFS+56))
    put(o,64,get(w,L_REFS+88)+get(w,L_REFS+120)+get(w,L_REFS+152))
    put(o,72,get(w,L_UNKNOWN))
    pending=get(w,L_MAP)!=0 or get(w,L_MAP_PENDING)!=0 or get(w,L_QUEUE_PENDING)!=0
    put(o,80,choose(pending,1,0))
    put(o,88,choose(get(w,L_UNKNOWN)==0,1,0))
    put(o,96,choose(get(w,L_STATE)==6,1,0))
    pending=get(w,L_MAP)!=0 or get(w,L_MAP_PENDING)!=0
    put(o,104,choose(pending,1,0))
    put(o,112,get(w,L_QUEUE_PENDING))
    put(o,120,1)
    return 0
'''
def main():
 saved=dict(common.C)
 try:
  common.C.update(C)
  return common.write_module('program_llvm_public_log_owner',SOURCE,'advance')
 finally:
  common.C.clear();common.C.update(saved)
if __name__=='__main__':main()
