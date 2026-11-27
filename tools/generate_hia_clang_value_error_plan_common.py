"""Private HIA-authored exception recipes and actual Value custody.

Recipes are generated inside the bound native adapter. No public request
accepts a recipe, an entry address or an ownership claim.
"""
from tools import generate_hia_clang_value_error_common as base
C=dict(base.C)
C.update(A_V7=int.from_bytes(b'HIABVQ07','little'),
 E_PLAN_COUNT=3072,E_PLAN_INDEX=3080,E_TEXT_N=3088,E_FACT=3096,E_CODE=3104,
 E_ERRNO=3112,E_PHASE=3120,E_CLASS=3128,E_MESSAGE=3136,E_FN_PTR=3144,E_FN_N=3152,
 E_ROW=3160,E_OP=3168,E_DST=3176,E_AMOUNT=3184,E_INPUT_PTR=3192,E_INPUT_N=3200,
 E_OUT_BASE=3208,E_OUT_N=3216,E_TEMP=3224,E_STAGE=3232,E_BAD=3240,E_STARTED=3248,
 E_CAPTURE=3256,E_CAUSE=3264,E_FILENAME=3272,E_FACT_KIND=3280,E_NEXT=3288,
 E_PLAN=327680,E_TEXT=393216,E_TEXT_CAP=131072,E_PLAN_CAP=1024,
 E_SEG_AT=3640,E_SEG_COUNT=3648,E_SEG_INDEX=3656,E_SEG_N=3664,E_CLOSE_NEXT=3672,
 E_EARLY=3680,E_EARLY_PHASE=3688,E_EARLY_RESULT=3696,E_EARLY_ERROR=3704,
 E_EARLY_ERRNO=3712,E_EARLY_STATE=3720,E_EARLY_SELECTOR=3728,E_EARLY_RESERVED=3736,
 E_LOG_STATUS=3928,E_LOG_COMMIT=3936,E_LOG_STARTED=3944,
 E_CLEAN_STAGE=3952,E_TOP_ERROR=3960,E_TOP_ERRNO=3968,E_CLEAN_REF=3976,
 E_PATH_N=3984,E_PATH_NODE=3992,E_PATH_DEPTH=4000,E_CLEAN_MAP=4008,
 E_CLEAN_CAP=4016,E_PATH_POS=4024,E_PATH_PREV=4032,E_PATH_EXTRA=4040,
 E_PATH_EXTRA_N=4048,E_PATH_IS_EXTRA=4056,E_LOG_NEW=4064,E_LOG_OLD=4072,E_LOG_TMP=4080,
 E_REAP_MAP=327552,E_REAP_CAP=327560,E_REAP_N=327568,E_REAP_KIND=327576)
COMMON=r'''
def e_row(w:mutbuf,op:u64,dst:u64,a:u64,b:u64,c:u64,d:u64,e:u64,f:u64) -> u64:
    n=get(w,E_PLAN_COUNT)
    if n>=E_PLAN_CAP:
        put(w,E_BAD,1)
        return 0
    at=E_PLAN+n*64
    put(w,at,op)
    put(w,at+8,dst)
    put(w,at+16,a)
    put(w,at+24,b)
    put(w,at+32,c)
    put(w,at+40,d)
    put(w,at+48,e)
    put(w,at+56,f)
    put(w,E_PLAN_COUNT,n+1)
    return 0

def e_scalar(w:mutbuf,slot:u64,kind:u64,ptr:u64,n:u64,value:u64) -> u64:
    return e_row(w,1,slot,kind,ptr,n,value,0,0)

def e_none(w:mutbuf,slot:u64) -> u64:
    return e_scalar(w,slot,0,0,0,0)

def e_number(w:mutbuf,slot:u64,value:u64,signed:u64) -> u64:
    start=get(w,E_TEXT_N)
    if start>E_TEXT_CAP-32:
        put(w,E_BAD,1)
        return 0
    at=start
    negative=signed!=0 and value>9223372036854775807
    if negative:
        store(w,E_TEXT+at,45)
        at=at+1
        value=0-value
    digits=at
    more=True
    while more:
        store(w,E_TEXT+at,48+value%10)
        at=at+1
        value=value//10
        if value==0:
            more=False
    i=digits
    j=at-1
    while i<j:
        b=byte(w,E_TEXT+i)
        store(w,E_TEXT+i,byte(w,E_TEXT+j))
        store(w,E_TEXT+j,b)
        i=i+1
        j=j-1
    put(w,E_TEXT_N,at)
    return e_scalar(w,slot,2,a_at(w,E_TEXT+start),at-start,0)

def e_list(w:mutbuf,slot:u64) -> u64:
    return e_row(w,2,slot,0,0,0,0,0,0)

def e_append(w:mutbuf,container:u64,value:u64) -> u64:
    return e_row(w,3,NONE,container,value,0,0,0,0)

def e_tuple(w:mutbuf,dst:u64,source:u64) -> u64:
    return e_row(w,4,dst,source,0,0,0,0,0)

def e_dict(w:mutbuf,slot:u64) -> u64:
    return e_row(w,5,slot,0,0,0,0,0,0)

def e_item(w:mutbuf,container:u64,key:u64,value:u64) -> u64:
    return e_row(w,6,NONE,container,key,value,0,0,0)

def e_class(w:mutbuf,slot:u64,id:u64) -> u64:
    return e_row(w,7,slot,id,0,0,0,0,0)

def e_exception(w:mutbuf,dst:u64,cls:u64,args:u64,namespace:u64) -> u64:
    return e_row(w,8,dst,cls,args,namespace,0,0,0)

def e_os(w:mutbuf,dst:u64,cls:u64,args:u64) -> u64:
    return e_row(w,9,dst,cls,args,0,0,0,0)

def e_chain(w:mutbuf,exception:u64,value:u64,selector:u64) -> u64:
    return e_row(w,11,NONE,exception,value,selector,0,0,0)

def e_drop(w:mutbuf,slot:u64) -> u64:
    return e_row(w,12,NONE,slot,0,0,0,0,0)

def e_fs(w:mutbuf,slot:u64,ptr:u64,n:u64) -> u64:
    return e_row(w,14,slot,ptr,n,0,0,0,0)

def e_strerror(w:mutbuf,slot:u64,number:u64) -> u64:
    return e_row(w,15,slot,number,0,0,0,0,0)

def e_digits(w:mutbuf,value:u64) -> u64:
    start=get(w,E_TEXT_N)
    if start>E_TEXT_CAP-32:
        put(w,E_BAD,1)
        return 0
    at=start
    more=True
    while more:
        store(w,E_TEXT+at,48+value%10)
        at=at+1
        value=value//10
        if value==0:
            more=False
    i=start
    j=at-1
    while i<j:
        b=byte(w,E_TEXT+i)
        store(w,E_TEXT+i,byte(w,E_TEXT+j))
        store(w,E_TEXT+j,b)
        i=i+1
        j=j-1
    put(w,E_TEXT_N,at)
    return at-start

def e_segment(w:mutbuf,kind:u64,ptr:u64,n:u64,number:u64) -> u64:
    at=get(w,E_TEXT_N)
    if at>E_TEXT_CAP-32:
        put(w,E_BAD,1)
        return 0
    put(w,E_TEXT+at,kind)
    put(w,E_TEXT+at+8,ptr)
    put(w,E_TEXT+at+16,n)
    put(w,E_TEXT+at+24,number)
    put(w,E_TEXT_N,at+32)
    return E_TEXT+at

def e_segments(w:mutbuf,slot:u64,at:u64,count:u64) -> u64:
    return e_row(w,18,slot,at,count,0,0,0,0)

def e_parts(w:mutbuf,dst:u64,exception:u64) -> u64:
    return e_row(w,19,dst,exception,0,0,0,0,0)

def e_arg(w:mutbuf,slot:u64,at:u64) -> bool:
    if slot>=63 or get(w,A_REFS+slot*32+24)!=1:
        return False
    a_arg(w,slot,at)
    return True
'''
def write_module(name,source,entry='advance'):
 base.C.update(C)
 return base.write_module(name,source+'\n'+COMMON,entry)
