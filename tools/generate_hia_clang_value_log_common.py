"""Production logger custody on the same captured Clang Value arena."""
from tools import generate_hia_clang_value_error_plan_common as original
C=dict(original.C)
C.update(
 A_LOG_REQUEST=int.from_bytes(b'HIACVPL1','little'),
 A_LOG_BIND=int.from_bytes(b'HIALLVB1','little'),
 A_LOG_CALL=int.from_bytes(b'HIALLVQ1','little'),
 A_LOG_REPLY=int.from_bytes(b'HIALLVR1','little'),
 A_LOG_CONTEXT=int.from_bytes(b'HIALLVW1','little'),
 A_LOG_WORK=2097152+(290<<20),A_LOG_RETURN=2097152+3056,A_LOG_PASS=2097152+3064,
 A_LOG_CHILD_BIND=23,A_LOG_CHILD_CALL=24)
COMMON=r'''
def alog_live(w:mutbuf) -> bool:
    return get(w,A_LOG_WORK)!=0 and get(w,A_LOG_WORK+104)!=6

def alog_bound(w:mutbuf) -> bool:
    return get(w,A_LOG_WORK)==A_LOG_CONTEXT and get(w,A_LOG_WORK+8)==a_at(w,A_LOG_WORK) and get(w,A_LOG_WORK+24)==65536 and get(w,A_LOG_WORK+40)==get(w,A_VALUE_ENTRY) and get(w,A_LOG_WORK+48)==get(w,A_VALUE_WORK) and get(w,A_LOG_WORK+56)==get(w,A_VALUE_WORK_N) and get(w,A_LOG_WORK+64)==get(w,64)

def alog_call(w:mutbuf,next:u64,role:u64) -> u32:
    return a_invoke(w,next,role,a_at(w,A_RQ),128,a_at(w,A_VR),128,a_at(w,A_LOG_WORK),65536)

def alog_valid(w:mutbuf) -> bool:
    return get(w,RESULT)==0 and get(w,A_VR)==A_LOG_REPLY and get(w,A_VR+88)==1 and get(w,A_VR+72)==0 and get(w,A_VR+104)<=1 and get(w,A_VR+112)<=1 and get(w,A_VR+120)==1

def alog_reject(w:mutbuf) -> u32:
    put(w,ERROR,16)
    put(w,ERROR_NO,2301)
    put(w,A_ERROR_SELECTOR,2301)
    put(w,A_STATE,3)
    put(w,E_PLAN_COUNT,0)
    put(w,E_PLAN_INDEX,0)
    put(w,E_TEXT_N,0)
    put(w,E_BAD,0)
    put(w,E_STARTED,1)
    n=alog_message(w)
    e_class(w,16,45)
    e_scalar(w,17,4,a_at(w,E_TEXT),n,0)
    e_list(w,18)
    e_append(w,18,17)
    e_tuple(w,19,18)
    e_exception(w,15,16,19,NONE)
    return jump(w,1600)
'''
raw=b'E_HIA_COMMAND_LOG: command log must be a plain list'
COMMON+='\ndef alog_message(w:mutbuf) -> u64:\n'
for at in range(0,len(raw),8):
 piece=raw[at:at+8]
 if len(piece)==8:COMMON+=f'    put(w,E_TEXT+{at},{int.from_bytes(piece,"little")})\n'
 else:
  for i,b in enumerate(piece):COMMON+=f'    store(w,E_TEXT+{at+i},{b})\n'
COMMON+=f'    put(w,E_TEXT_N,{len(raw)})\n    return {len(raw)}\n'
def write_module(name,source,entry='advance'):
 original.C.update(C)
 return original.write_module(name,source+'\n'+COMMON,entry)
