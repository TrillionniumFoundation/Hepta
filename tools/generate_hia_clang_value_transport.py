"""Native-owned coercion buffers and original Clang producer invocation."""
from tools.generate_hia_clang_value_common import write_module
SOURCE=r'''
def advance(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase=get(w,PHASE)
    r=get(w,RESULT)
    if phase>=600 and phase<650:
        return which_bytes(o,w,phase)
    if phase==500:
        return a_newmap(o,w,501,128+get(w,A_RAW_N))
    if phase==508:
        return a_newmap(o,w,505,128+get(w,A_RAW_N))
    if phase==501:
        if failed(r):
            return a_fail(w,18,errno(r))
        put(w,A_RAW_MAP,r)
        put(w,A_RAW_CAP,(get(w,A_RAW_N)+4223)&18446744073709547520)
        return a_buffer(w,502,0,0,0,r,get(w,A_RAW_CAP))
    if phase==502:
        if r!=0:
            return a_unknown(w,502)
        put(w,A_OFFSET,0)
        return read_value(w)
    if phase==503:
        if a_ordinary(w)==False or get(w,A_VR+64)!=get(w,A_AMOUNT):
            return a_value_failed(w,503)
        return a_copy(w,504,a_at(w,A_VR+8192),get(w,A_RAW_MAP)+128+get(w,A_OFFSET),get(w,A_AMOUNT))
    if phase==504:
        if r!=0:
            return a_unknown(w,504)
        put(w,A_OFFSET,get(w,A_OFFSET)+get(w,A_AMOUNT))
        return read_value(w)
    if phase==505:
        if failed(r):
            return a_fail(w,18,errno(r))
        put(w,A_FS_MAP,r)
        put(w,A_FS_CAP,(get(w,A_RAW_N)+4223)&18446744073709547520)
        if get(w,A_KIND)==7:
            put(w,A_FS_N,get(w,A_RAW_N))
            return a_copy(w,509,get(w,A_RAW_MAP)+128,get(w,A_FS_MAP)+128,get(w,A_RAW_N))
        clear(w,A_CODEC_WORK,32)
        return a_invoke(w,506,3,get(w,A_RAW_MAP),128+get(w,A_RAW_N),get(w,A_FS_MAP),get(w,A_FS_CAP),a_at(w,A_CODEC_WORK),32)
    if phase==506:
        if r!=0:
            return a_unknown(w,506)
        return a_copy(w,507,get(w,A_FS_MAP),a_at(w,A_RQ),128)
    if phase==507:
        if r!=0 or get(w,A_RQ)!=A_CODEC_REPLY:
            return a_unknown(w,507)
        if get(w,A_RQ+8)!=0:
            return a_fail(w,17,get(w,A_RQ+8))
        n=get(w,A_RQ+16)
        if n>get(w,A_RAW_N):
            return a_unknown(w,507)
        put(w,A_FS_N,n)
        return frame_begin(o,w)
    if phase==509:
        if r!=0:
            return a_unknown(w,509)
        return which_begin(w)
    if phase==510:
        if failed(r):
            return a_fail(w,18,errno(r))
        put(w,A_FRAME,r)
        put(w,A_FRAME_CAP,(get(w,A_FRAME_N)+4095)&18446744073709547520)
        return a_buffer(w,511,1,get(w,A_SOURCE),get(w,A_SOURCE_N),r,get(w,A_FRAME_CAP))
    if phase==511:
        if r!=0:
            return a_unknown(w,511)
        return a_copy(w,512,get(w,A_FS_MAP)+128,get(w,A_FRAME)+get(w,A_FRAME_TOOL),get(w,A_FS_N))
    if phase==512:
        if r!=0:
            return a_unknown(w,512)
        clear(w,A_INNER_OUT,512)
        put(w,A_INNER_ACTIVE,1)
        return a_invoke(w,513,choose(get(w,A_ORIGIN_HELD)==1,6,2),get(w,A_FRAME),get(w,A_FRAME_N),a_at(w,A_INNER_OUT),A_REPLY_N,a_at(w,A_INNER_WORK),536870912)
    if phase==513:
        if r!=0 or get(w,A_INNER_OUT)!=A_RAW_REPLY:
            return a_unknown(w,513)
        if get(w,A_INNER_OUT+344)>1 or get(w,A_INNER_OUT+352)>1 or get(w,A_INNER_OUT+360)>1:
            return a_unknown(w,513)
        if get(w,A_INNER_OUT+344)==0:
            put(w,A_UNKNOWN,1)
        put(w,A_STATE,3)
        if get(w,A_INNER_OUT+8)!=0:
            return a_fail(w,get(w,A_INNER_OUT+8),10000+get(w,A_INNER_OUT+16))
        return jump(w,700)
    return 4294967293

def a_buffer(w:mutbuf,next:u64,op:u64,si:u64,sn:u64,oi:u64,on:u64) -> u32:
    put(w,640,op)
    return a_invoke(w,next,4,si,sn,oi,on,a_at(w,0),A_WORK)

def read_value(w:mutbuf) -> u32:
    at=get(w,A_OFFSET)
    n=get(w,A_RAW_N)
    if at==n:
        return jump(w,508)
    amount=n-at
    if amount>8192:
        amount=8192
    put(w,A_AMOUNT,amount)
    a_request(w,A_V6,19)
    a_arg(w,get(w,A_SELECTED),24)
    put(w,A_RQ+104,at)
    put(w,A_RQ+112,amount)
    return a_value(w,503,128)

def which_begin(w:mutbuf) -> u32:
    put(w,A_BUFFER_OP,3)
    return a_invoke(w,600,4,get(w,A_FS_MAP)+128,get(w,A_FS_N),get(w,A_FS_MAP)+96,32,a_at(w,0),A_WORK)

def which_bytes(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==600:
        if get(w,RESULT)!=0:
            return a_unknown(w,600)
        n=get(w,A_FS_N)
        if get(w,A_BYTE_ORIGIN)==0 and get(w,A_WHICH_DIRECT)==0:
            n=0
        put(w,A_WHICH_ACTIVE,1)
        return a_invoke(w,601,5,get(w,A_FS_MAP)+96,32+n,a_at(w,A_WHICH_OUT),128,a_at(w,A_WHICH_WORK),4096)
    if phase==601:
        if get(w,RESULT)!=0 or get(w,A_WHICH_OUT)!=0x3130525743414948 or get(w,A_WHICH_OUT+64)!=1:
            return a_unknown(w,601)
        status=get(w,A_WHICH_OUT+8)
        if status==3:
            return a_fail(w,18,get(w,A_WHICH_OUT+16))
        if get(w,A_BYTE_ORIGIN)==0 and get(w,A_WHICH_DIRECT)==0 and get(w,A_WHICH_WORK+136)!=0:
            return a_fail(w,16,602)
        if status==0:
            return a_fail(w,16,601)
        if status==1:
            return a_fail(w,4,601)
        return a_unknown(w,601)
    return 4294967293

def allocation(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if get(w,PHASE)!=508:
        return 4294967293
    return a_newmap(o,w,505,128+get(w,A_RAW_N))

def frame_begin(o:mutbuf,w:mutbuf) -> u32:
    total=256+get(w,A_CORE_N)+get(w,A_ABI_N)
    pn=get(w,A_PATH_N)
    tool=get(w,A_FS_N)
    if pn>9223372036854771712-total or tool>9223372036854771712-total-pn:
        return a_fail(w,18,12)
    put(w,A_FRAME_N,total+pn+tool)
    put(w,A_FRAME_TOOL,256+get(w,A_CORE_N))
    put(w,A_FRAME_PATH,256+get(w,A_CORE_N)+tool)
    put(w,A_FRAME_ABI,256+get(w,A_CORE_N)+tool+pn)
    return a_newmap(o,w,510,total+pn+tool)
'''
if __name__=='__main__':write_module('clang_value_transport',SOURCE)
