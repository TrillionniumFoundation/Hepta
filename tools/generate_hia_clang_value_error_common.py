"""Extended native Clang Value state with private deferred Value entries."""
from tools import generate_hia_clang_value_common as original
C=dict(original.C)
C.update(A_WINDOWS=896,A_XMAP=184,A_XCAP=192,A_XSRC=200,A_XN=208,
 A_XOFF=216,A_XNEXT=224,A_XKIND=232,A_XSLOT=240,A_PATH_STR_MODE=248,
 A_V7=int.from_bytes(b'HIABVQ07','little'),A_V9=int.from_bytes(b'HIABVQ09','little'),
 A_V11=int.from_bytes(b'HIABVQ11','little'),A_DEFERRED=3920)
COMMON=original.COMMON
old="""def a_value(w:mutbuf,next:u64,n:u64) -> u32:
    return a_invoke(w,next,1,a_at(w,A_RQ),n,a_at(w,A_VR),A_VR_N,get(w,A_VALUE_WORK),get(w,A_VALUE_WORK_N))"""
new=r'''def a_value(w:mutbuf,next:u64,n:u64) -> u32:
    magic=get(w,A_RQ)
    op=get(w,A_RQ+8)
    if magic==A_V1:
        if op==3 or op==12 or op==16 or op==18 or op==24:
            magic=A_V7
        elif op==23:
            magic=A_V9
        elif op==2 or op==4 or op==7 or op==8 or op==9 or op==10 or op==17 or op==19 or op==21 or op==26:
            magic=A_V6
    if magic==A_V3 and op==32:
        magic=A_V11
    elif magic==A_V4 and (op==40 or op==43):
        magic=A_V11
    elif magic==A_V5:
        if a_deferred_opcode(op):
            magic=A_V11
    put(w,A_RQ,magic)
    put(w,A_DEFERRED,choose(magic==A_V11 or (magic==A_V5 and op==115),1,0))
    return a_invoke(w,next,1,a_at(w,A_RQ),n,a_at(w,A_VR),A_VR_N,get(w,A_VALUE_WORK),get(w,A_VALUE_WORK_N))

def a_deferred_opcode(op:u64) -> bool:
    if op==57 or op==75 or op==87 or op==98 or op==99 or op==100:
        return True
    return op>=101 and op<=112

def a_deferred_reply(w:mutbuf) -> u64:
    if get(w,A_DEFERRED)==0:
        return 0
    put(w,A_DEFERRED,0)
    if get(w,RESULT)!=0 or get(w,A_VR+128)!=0x3130445642414948 or get(w,A_VR+136)!=1 or get(w,A_VR+144)>1 or get(w,A_VR+152)>1 or get(w,A_VR+160)!=1:
        put(w,A_UNKNOWN,1)
        return 0
    if get(w,A_VR+144)!=0 or get(w,A_VR+152)!=0:
        put(w,A_TOKEN_PENDING,1)
    return 0'''
assert COMMON.count(old)==1
COMMON=COMMON.replace(old,new)
def write_module(name,source,entry='advance'):
 original.base.C.update(C)
 return original.base.write_module(name,source+'\n'+COMMON,entry)
