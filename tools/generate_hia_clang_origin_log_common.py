"""Private log hooks share actual Clang, Value and command-row custody."""
from tools import generate_hia_clang_origin_error_common as original
C=dict(original.C)
C.update(
 L_MODE=2560,L_NEXT=2568,L_ACTIVE=2576,L_ERROR=2584,L_DETAIL=2592,
 L_ENABLED=2600,L_LOG_CLOSED=2608,L_CWD_ACTIVE=2616,L_FD=2624,L_FD_HELD=2632,L_FD_UNKNOWN=2640,
 L_CWD_N=2648,L_INDEX=2656,L_OFFSET=2664,L_AMOUNT=2672,L_REQUIRED=2680,L_INPUT_N=2688,L_JSON_N=2696,
 L_COPY_TO=2704,L_CLEAN_INDEX=2712,L_MAP_INDEX=2720,L_QUEUE=2728,L_UNKNOWN=2736,L_RETIRING=2744,
 L_FRAME_N=2752,L_AFTER=2760,L_READ_SLOT=2768,L_READ_N=2776,L_READ_TO=2784,L_READ_OFFSET=2792,
 L_READ_NEXT=2800,L_INT_SLOT=2808,L_INT_TO=2816,L_INT_NEXT=2824,L_INT_SIGN=2832,
 L_OS_INDEX=2840,L_OS_OFFSET=2848,L_OS_FLAGS=2856,L_MEMORY_ATTEMPT=2864,L_REPLACED=2872,
 L_IN=2880,L_JSON=2896,L_TEXT=2912,L_TEXT_OUT=2928,L_REPR=2944,L_SPARE=2960,
 L_LOG_STATUS=2976,L_LOG_DETAIL=2984,L_LOG_PRIMARY=2992,L_CWD_RETIRED=3000,
 L_FAILURE_CONTEXT=3008,L_FAILURE_CAP=3016,L_VALUE_PENDING=3024,
 L_REPLACEMENT_PENDING=3032,L_REPLACEMENT_CLEAN=3040,L_REPLACEMENT_ERRNO=3048,
 L_LOG_WORK=290<<20,L_CWD_WORK=291<<20,L_CODEC_WORK=(291<<20)+262144,
 L_HEADER=(291<<20)+262400,L_FIELDS=(291<<20)+262656,L_REFS=(291<<20)+263168,
 L_RQ=(291<<20)+266240,L_VR=(291<<20)+270336,L_OS_HEADER=(291<<20)+304128,
 L_OS_FIELDS=(291<<20)+304256,L_REPR_WORK=(291<<20)+327680,
 L_LOG_CONTEXT=int.from_bytes(b'HIALLVW1','little'),
 L_LOG_REQUEST=int.from_bytes(b'HIALLVQ1','little'),L_LOG_REPLY=int.from_bytes(b'HIALLVR1','little'),
 L_CODEC_REQUEST=int.from_bytes(b'HIALLGQ2','little'),L_OS_REQUEST=int.from_bytes(b'HIACLOM1','little'),
 L_CWD_REQUEST=int.from_bytes(b'HIAGPAQ1','little'),L_CWD_REPLY=int.from_bytes(b'HIAGPAR1','little'),
 L_EARLY_REQUEST=int.from_bytes(b'HIACVEH1','little'),L_EARLY_REPLY=int.from_bytes(b'HIACVEHR','little'),
 L_EXCEPTION_REQUEST=int.from_bytes(b'HIACVLE1','little'),L_EXCEPTION_REPLY=int.from_bytes(b'HIACVLER','little'),
 L_Q5=int.from_bytes(b'HIABVQ05','little'),L_Q6=int.from_bytes(b'HIABVQ06','little'),
 L_Q7=int.from_bytes(b'HIABVQ07','little'),L_Q11=int.from_bytes(b'HIABVQ11','little'),
 L_V1=int.from_bytes(b'HIABVR01','little'),L_V2=int.from_bytes(b'HIABVR02','little'),
 L_REPR_REQUEST=int.from_bytes(b'HIAREPR1','little'),
 R_LOG_CODEC=16,R_LOG_OWNER=17,R_LOG_EARLY=18,R_LOG_CWD=19,R_LOG_VALUE=20,
 R_LOG_REPR=21,R_LOG_EXCEPTION=22)
COMMON=original.COMMON+r'''
def l_logger(w:mutbuf) -> bool:
    return get(w,L_LOG_WORK)!=0

def l_start(w:mutbuf,mode:u64,next:u64) -> u32:
    if l_logger(w)==False:
        return jump(w,next)
    if get(w,L_LOG_WORK)!=L_LOG_CONTEXT or get(w,L_LOG_WORK+8)!=p_at(w,L_LOG_WORK) or get(w,L_LOG_WORK+24)!=65536:
        put(w,P_UNKNOWN,1)
        return p_fail(w,E_CONTEXT,2000)
    if get(w,L_ACTIVE)!=0 or get(w,L_UNKNOWN)!=0 or get(w,L_LOG_CLOSED)!=0:
        return p_fail(w,E_CONTEXT,2001)
    if get(w,L_FD_HELD)!=0 or get(w,L_CWD_ACTIVE)!=0:
        return p_fail(w,E_CONTEXT,2002)
    i=0
    while i<6:
        if get(w,L_IN+i*16)!=0:
            return p_fail(w,E_CONTEXT,2003)
        i=i+1
    i=0
    while i<32:
        if get(w,L_REFS+i*32+24)!=0:
            return p_fail(w,E_CONTEXT,2004)
        i=i+1
    put(w,L_ENABLED,1)
    put(w,L_ACTIVE,1)
    put(w,L_MODE,mode)
    put(w,L_NEXT,next)
    put(w,L_ERROR,0)
    put(w,L_DETAIL,0)
    put(w,L_MEMORY_ATTEMPT,0)
    put(w,L_REPLACED,0)
    clear(w,L_FIELDS,256)
    clear(w,L_REFS,1024)
    clear(w,L_HEADER,128)
    put(w,L_HEADER,L_CODEC_REQUEST)
    put(w,L_HEADER+8,mode)
    return jump(w,choose(mode==2,2100,2000))

def l_fail(w:mutbuf,error:u64,detail:u64) -> u32:
    if get(w,L_ERROR)==0:
        put(w,L_ERROR,error)
        put(w,L_DETAIL,detail)
    put(w,L_NEXT,900)
    if error==E_MEMORY and get(w,L_MEMORY_ATTEMPT)==0 and get(w,L_UNKNOWN)==0:
        put(w,L_MEMORY_ATTEMPT,1)
        return jump(w,2700)
    put(w,L_CLEAN_INDEX,32)
    return jump(w,2500)

def l_unknown(w:mutbuf,detail:u64) -> u32:
    put(w,L_UNKNOWN,1)
    put(w,P_UNKNOWN,1)
    return l_fail(w,E_CONTEXT,detail)

def l_request(w:mutbuf,magic:u64,op:u64) -> u64:
    clear(w,L_RQ,256)
    clear(w,L_VR,32768)
    put(w,L_RQ,magic)
    put(w,L_RQ+8,op)
    return 0

def l_arg(w:mutbuf,to:u64,slot:u64) -> u64:
    p_saved_copy(w,L_REFS+slot*32,L_RQ+to,24)
    return 0

def l_value(w:mutbuf,next:u64,n:u64) -> u32:
    return p_invoke(w,next,R_LOG_VALUE,p_at(w,L_RQ),n,p_at(w,L_VR),32768,0,0)

def l_query(w:mutbuf,next:u64,magic:u64,op:u64,slot:u64) -> u32:
    l_request(w,magic,op)
    l_arg(w,24,slot)
    return l_value(w,next,128)

def l_valid(w:mutbuf,magic:u64) -> bool:
    return get(w,RESULT)==0 and get(w,L_VR)==magic

def l_ordinary(w:mutbuf) -> bool:
    return l_valid(w,L_V1) and get(w,L_VR+8)==0

def l_hold_at(w:mutbuf,slot:u64,at:u64) -> bool:
    if get(w,L_REFS+slot*32+24)!=0:
        return False
    if get(w,at)==0 or get(w,at+8)==0 or get(w,at+16)==0:
        return False
    p_saved_copy(w,at,L_REFS+slot*32,24)
    put(w,L_REFS+slot*32+24,1)
    return True

def l_hold(w:mutbuf,slot:u64) -> bool:
    if l_valid(w,L_V1)==False:
        return False
    if get(w,L_VR+24)!=0:
        if l_hold_at(w,slot,L_VR+24)==False:
            return False
    return get(w,L_VR+8)==0 and get(w,L_REFS+slot*32+24)==1

def l_value_failed(w:mutbuf,detail:u64) -> u32:
    if l_valid(w,L_V1)==False:
        return l_unknown(w,detail)
    if get(w,L_VR+8)==5:
        return l_fail(w,E_MEMORY,12)
    return l_fail(w,E_CONTEXT,detail)

def l_field(w:mutbuf,index:u64,kind:u64,source:u64,n:u64) -> u64:
    at=L_FIELDS+index*32
    put(w,at,source)
    put(w,at+8,n)
    put(w,at+16,kind)
    header=choose(index<4,16+index*8,80+(index-4)*8)
    put(w,L_HEADER+header,n)
    return 0

def l_newmap(o:mutbuf,w:mutbuf,next:u64,n:u64) -> u32:
    if n==0 or n>9223372036854771712:
        return l_fail(w,E_MEMORY,12)
    put(w,L_REQUIRED,(n+4095)&18446744073709547520)
    return call(o,w,next,9,0,get(w,L_REQUIRED),3,34,NONE,0,0)

def l_keepmap(w:mutbuf,slot:u64) -> bool:
    r=get(w,RESULT)
    if failed(r) or r==0 or get(w,slot)!=0:
        return False
    put(w,slot,r)
    put(w,slot+8,get(w,L_REQUIRED))
    return True

def l_read(w:mutbuf,slot:u64,n:u64,to:u64,next:u64) -> u32:
    put(w,L_READ_SLOT,slot)
    put(w,L_READ_N,n)
    put(w,L_READ_TO,to)
    put(w,L_READ_OFFSET,0)
    put(w,L_READ_NEXT,next)
    return jump(w,2400)

def l_integer(w:mutbuf,slot:u64,to:u64,next:u64,allow_none:u64) -> u32:
    put(w,L_INT_SLOT,slot)
    put(w,L_INT_TO,to)
    put(w,L_INT_NEXT,next)
    put(w,L_INT_SIGN,allow_none)
    return l_query(w,2200,L_Q6,7,slot)

def l_unsigned(w:mutbuf,n:u64) -> u64:
    put(w,L_AMOUNT,0)
    if n==0 or n>20:
        return 0
    value=0
    i=0
    while i<n:
        ch=byte(w,L_VR+8192+i)
        if ch<48 or ch>57 or value>(NONE-(ch-48))//10:
            return 0
        value=value*10+ch-48
        i=i+1
    put(w,L_AMOUNT,1)
    return value

def l_drop(w:mutbuf,next:u64,slot:u64) -> u32:
    return l_query(w,next,L_Q5,78,slot)

def l_dropped(w:mutbuf,slot:u64) -> bool:
    if l_valid(w,L_V2)==False or get(w,L_VR+88)!=1 or get(w,L_VR+96)>1 or get(w,L_VR+104)>1 or get(w,L_VR+112)>1 or get(w,L_VR+120)!=1:
        put(w,L_UNKNOWN,1)
        return False
    put(w,L_QUEUE,get(w,L_QUEUE)|get(w,L_VR+112))
    put(w,L_VALUE_PENDING,get(w,L_VALUE_PENDING)|get(w,L_VR+104))
    if get(w,L_VR+96)==1:
        clear(w,L_REFS+slot*32,32)
    return get(w,L_VR+96)==1 and get(w,L_VR+104)==0

def l_live(w:mutbuf) -> bool:
    if get(w,L_ACTIVE)!=0 or get(w,L_FD_HELD)!=0 or get(w,L_CWD_ACTIVE)!=0 or get(w,L_VALUE_PENDING)!=0 or get(w,L_UNKNOWN)!=0:
        return True
    i=0
    while i<6:
        if get(w,L_IN+i*16)!=0:
            return True
        i=i+1
    i=0
    while i<32:
        if get(w,L_REFS+i*32+24)!=0:
            return True
        i=i+1
    if l_logger(w) and get(w,L_LOG_CLOSED)==0:
        return True
    return False
'''
def write_module(name,source,entry='advance'):
 original.origin.base.capture.C.update(C)
 return original.origin.base.capture.write_module(name,source+'\n'+COMMON,entry)
