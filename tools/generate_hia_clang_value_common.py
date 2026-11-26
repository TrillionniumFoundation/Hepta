"""Fixed actual-Value binding and custody for Runtime's native Clang adapter."""
from tools import generate_hia_clang_capture_common as base
C=dict(PHASE=256,RESULT=264,ERROR=272,ERROR_NO=280,
 A_UNKNOWN=288,A_TOKEN_PENDING=304,A_ROLE=320,A_SI=328,A_SN=336,A_OI=344,A_ON=352,A_WI=360,A_WN=368,
 A_MODE=128,A_STATE=136,A_BASE=144,A_SOURCE=152,A_SOURCE_N=160,A_OUTPUT=168,A_OUTPUT_N=176,
 A_TOKEN=72,A_TOKEN_HELD=96,A_ORIGIN_FD=104,A_ORIGIN_HELD=112,A_VALUE_ENTRY=40,A_VALUE_WORK=48,A_VALUE_WORK_N=56,
 A_TARGET=856,A_COMPILE_KIND=864,A_LAYOUT=872,A_CLOSE_METHOD=880,A_CLOSE_UNKNOWN=888,A_STAT=98304,
 A_CORE_N=384,A_ABI_N=392,A_PATH_N=400,A_STRUCTURED_N=408,
 A_SELECTED=416,A_KIND=424,A_RAW_N=432,A_OFFSET=440,A_AMOUNT=448,
 A_RAW_MAP=456,A_RAW_CAP=464,A_FS_MAP=472,A_FS_CAP=480,A_FS_N=488,
 A_FRAME=496,A_FRAME_CAP=504,A_FRAME_N=512,A_FRAME_TOOL=520,A_FRAME_PATH=528,A_FRAME_ABI=536,
 A_INNER_ACTIVE=544,A_INNER_RETIRED=552,A_CLEAN_INDEX=560,A_MAP_INDEX=568,A_CLEAN_ERROR=576,A_CLEAN_ERRNO=584,
 A_CALL_SLOT=592,A_CALL_DISPOSITION=600,A_RAW_VALUE_ERROR=608,A_BYTE_ORIGIN=616,A_ERROR_KIND=624,
 A_INPUT_BASE=648,A_PATH_INDEX=656,A_PATH_COUNT=664,A_JOIN_N=672,A_ITEM_N=680,A_ITEM_OFFSET=688,A_PATH_MAP=696,A_PATH_CAP=704,
 A_ERROR_SELECTOR=720,A_ERROR_CLASS=728,A_NAME_INDEX=736,A_NAME_N=744,A_NAME_OFFSET=752,A_NAME_LENGTH=760,A_NAME1_N=768,A_NAME2_N=776,A_ERROR_N=784,A_ERROR_SLOT=792,A_WHICH_ACTIVE=800,A_WHICH_STATUS=808,A_WHICH_DETAIL=816,A_WHICH_PATH_N=824,A_WHICH_DIRECT=832,A_BUFFER_OP=640,
 A_WHICH_WORK=73728,A_WHICH_OUT=77824,A_ERROR_FRAME=131072,A_NAME1=196608,A_NAME2=196864,
 A_REFS=1024,A_RQ=4096,A_VR=8192,A_CODEC_WORK=65536,A_INNER_OUT=524288,A_INNER_WORK=2097152,
 A_WORK=538968064,A_REPLY_N=1049088,A_VR_N=32768,
 A_REQUEST=int.from_bytes(b'HIAMVBC1','little'),A_REPLY=int.from_bytes(b'HIAMVCR1','little'),
 A_BIND2=int.from_bytes(b'HIAMVCB2','little'),A_PUBLIC_REQUEST=int.from_bytes(b'HIACVPC1','little'),
 A_RAW_ORIGIN_REQUEST=int.from_bytes(b'HIACLB02','little'),
 A_BIND=int.from_bytes(b'HIAMVCB1','little'),A_BIND_REPLY=int.from_bytes(b'HIAMVCBR','little'),
 A_EXCEPTION=int.from_bytes(b'HIAMVCE1','little'),A_EXCEPTION_REPLY=int.from_bytes(b'HIAMVCER','little'),
 A_CONTEXT=int.from_bytes(b'HIACVBW1','little'),
 A_RAW_REQUEST=int.from_bytes(b'HIACLB01','little'),A_RAW_REPLY=int.from_bytes(b'HIACLR01','little'),
 A_CODEC_REQUEST=int.from_bytes(b'HIAGTCQ1','little'),A_CODEC_REPLY=int.from_bytes(b'HIAGTCR1','little'),
 A_V1=int.from_bytes(b'HIABVQ01','little'),A_V2=int.from_bytes(b'HIABVQ02','little'),A_V3=int.from_bytes(b'HIABVQ03','little'),A_V4=int.from_bytes(b'HIABVQ04','little'),A_V5=int.from_bytes(b'HIABVQ05','little'),A_V6=int.from_bytes(b'HIABVQ06','little'),
 A_R1=int.from_bytes(b'HIABVR01','little'),A_R2=int.from_bytes(b'HIABVR02','little'),
 A_NATIVE=int.from_bytes(b'HIAVNO01','little'))
COMMON=r'''
def a_at(w:mutbuf,n:u64) -> u64:
    return get(w,A_BASE)+n

def a_invoke(w:mutbuf,next:u64,role:u64,si:u64,sn:u64,oi:u64,on:u64,wi:u64,wn:u64) -> u32:
    put(w,PHASE,next)
    put(w,A_ROLE,role)
    put(w,A_SI,si)
    put(w,A_SN,sn)
    put(w,A_OI,oi)
    put(w,A_ON,on)
    put(w,A_WI,wi)
    put(w,A_WN,wn)
    return 2

def a_copy(w:mutbuf,next:u64,source:u64,destination:u64,n:u64) -> u32:
    return a_invoke(w,next,0,source,n,destination,n,0,0)

def a_within(w:mutbuf,to:u64,source:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(w,to+i,byte(w,source+i))
        i=i+1
    return 0

def a_request(w:mutbuf,magic:u64,op:u64) -> u64:
    clear(w,A_RQ,128)
    clear(w,A_VR,A_VR_N)
    put(w,A_RQ,magic)
    put(w,A_RQ+8,op)
    return 0

def a_arg(w:mutbuf,slot:u64,at:u64) -> u64:
    a_within(w,A_RQ+at,A_REFS+slot*32,24)
    return 0

def a_value(w:mutbuf,next:u64,n:u64) -> u32:
    return a_invoke(w,next,1,a_at(w,A_RQ),n,a_at(w,A_VR),A_VR_N,get(w,A_VALUE_WORK),get(w,A_VALUE_WORK_N))

def a_simple(w:mutbuf,next:u64,magic:u64,op:u64,slot:u64) -> u32:
    a_request(w,magic,op)
    if slot!=NONE:
        a_arg(w,slot,24)
    return a_value(w,next,128)

def a_ordinary(w:mutbuf) -> bool:
    return get(w,RESULT)==0 and get(w,A_VR)==A_R1 and get(w,A_VR+8)==0

def a_capture(w:mutbuf,slot:u64,at:u64) -> bool:
    if get(w,A_REFS+slot*32+24)!=0 or get(w,at)==0:
        return False
    a_within(w,A_REFS+slot*32,at,24)
    put(w,A_REFS+slot*32+24,1)
    return True

def a_fail(w:mutbuf,error:u64,detail:u64) -> u32:
    if get(w,ERROR)==0:
        put(w,ERROR,error)
        put(w,ERROR_NO,detail)
    put(w,A_STATE,3)
    if error!=19 and get(w,A_REFS+15*32+24)==0 and get(w,A_ERROR_SELECTOR)==0:
        put(w,A_ERROR_SELECTOR,detail)
        return jump(w,1000)
    return jump(w,700)

def a_unknown(w:mutbuf,detail:u64) -> u32:
    put(w,A_UNKNOWN,1)
    return a_fail(w,19,detail)

def a_value_failed(w:mutbuf,detail:u64) -> u32:
    if get(w,RESULT)!=0 or get(w,A_VR)!=A_R1:
        return a_unknown(w,detail)
    put(w,A_RAW_VALUE_ERROR,get(w,A_VR+8))
    return a_fail(w,16,detail)

def a_newmap(o:mutbuf,w:mutbuf,next:u64,n:u64) -> u32:
    if n==0 or n>9223372036854771712:
        return a_fail(w,18,12)
    return call(o,w,next,9,0,(n+4095)&18446744073709547520,3,34,NONE,0,0)

def a_cap_drop_valid(w:mutbuf) -> bool:
    return get(w,RESULT)==0 and get(w,A_VR)==A_R2 and get(w,A_VR+88)==1 and get(w,A_VR+96)<=1 and get(w,A_VR+80)<=1 and get(w,A_VR+104)<=1 and get(w,A_VR+112)<=1 and get(w,A_VR+120)==1

def a_clean_error(w:mutbuf,error:u64,detail:u64) -> u64:
    if get(w,A_CLEAN_ERROR)==0:
        put(w,A_CLEAN_ERROR,error)
        put(w,A_CLEAN_ERRNO,detail)
    return 0
'''
def write_module(name,source,entry='advance'):
 base.C.update(C)
 return base.write_module(name,source+'\n'+COMMON,entry)
