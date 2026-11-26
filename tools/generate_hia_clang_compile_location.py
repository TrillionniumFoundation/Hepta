"""Native installation-relative source identity and actual image origin custody."""
from tools.generate_hia_clang_compile_common import write_module
SOURCE=r'''
def advance(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase=get(w,PHASE)
    r=get(w,RESULT)
    if phase==20:
        put(w,P_CATALOG_TEMPLATE,get(w,P_CATALOG))
        put(w,P_CATALOG_TEMPLATE_N,get(w,P_CATALOG_N))
        clear(w,P_ORIGIN_INFO,32)
        put(w,PHASE,21)
        return 3
    if phase==21:
        if r!=1 or get(w,P_ORIGIN_INFO)==0:
            return p_fail(w,E_CONTEXT,21)
        put(w,P_ORIGIN_PTR,get(w,P_ORIGIN_INFO))
        put(w,P_ORIGIN_N,0)
        return peek(w)
    if phase==22:
        if r==0:
            if get(w,P_ORIGIN_N)==0:
                return p_fail(w,E_CONTEXT,22)
            return p_frame(o,w,32+get(w,P_ORIGIN_N),23)
        n=get(w,P_ORIGIN_N)
        if n>=9223372036854771712 or get(w,P_ORIGIN_PTR)>NONE-n-1:
            return p_fail(w,E_MEMORY,12)
        put(w,P_ORIGIN_N,n+1)
        return peek(w)
    if phase==23:
        return p_buffer(w,24,1,get(w,P_ORIGIN_PTR),get(w,P_ORIGIN_N),get(w,P_FRAME),get(w,P_FRAME_CAP))
    if phase==24:
        if r!=32+get(w,P_ORIGIN_N):
            return p_fail(w,E_CONTEXT,24)
        put(w,P_PATH_ACTIVE,1)
        return p_invoke(w,25,R_PATH,get(w,P_FRAME),r,p_at(w,P_SUBOUT),128,p_at(w,P_PATH_WORK),200704)
    if phase==25:
        if r!=0 or get(w,P_SUBOUT)!=PATH_REPLY:
            put(w,P_UNKNOWN,1)
            return p_fail(w,E_CONTEXT,25)
        if get(w,P_SUBOUT+8)!=0:
            return p_fail(w,E_OS,errno(get(w,P_SUBOUT+16)))
        if get(w,P_SUBOUT+88)!=1 or get(w,P_SUBOUT+96)!=1 or get(w,P_SUBOUT+104)!=0 or get(w,P_SUBOUT+112)!=1 or get(w,P_SUBOUT+120)!=0:
            return p_fail(w,E_CONTEXT,25)
        if get(w,P_SUBOUT+32)==NONE or get(w,P_SUBOUT+48)!=15:
            return p_fail(w,E_CONTEXT,25)
        put(w,P_PATH_FD,get(w,P_SUBOUT+32))
        n=get(w,P_SUBOUT+40)
        if n==0 or n>9223372036854771712:
            return p_fail(w,E_MEMORY,12)
        put(w,P_ORIGIN_N,n)
        size=(n+4096)&18446744073709547520
        put(w,P_ORIGIN_CAP,size)
        return call(o,w,26,9,0,size,3,34,NONE,0,0)
    if phase==26:
        if failed(r):
            return p_fail(w,E_MEMORY,errno(r))
        put(w,P_ORIGIN_MAP,r)
        put(w,P_IO_AT,0)
        return read_origin(o,w)
    if phase==27:
        if failed(r):
            if errno(r)==4:
                return read_origin(o,w)
            return p_fail(w,E_OS,errno(r))
        if r==0 or r>get(w,P_ORIGIN_N)-get(w,P_IO_AT):
            return p_fail(w,E_OS,5)
        put(w,P_IO_AT,get(w,P_IO_AT)+r)
        return read_origin(o,w)
    if phase==28:
        if r!=0:
            return p_fail(w,E_CONTEXT,28)
        return p_buffer(w,29,11,get(w,P_CATALOG_TEMPLATE),get(w,P_CATALOG_TEMPLATE_N),p_at(w,P_SMALL),64)
    if phase==29:
        if r!=0:
            return p_fail(w,E_CONTEXT,29)
        return call(o,w,30,9,0,get(w,P_CATALOG_NEED),3,34,NONE,0,0)
    if phase==30:
        if failed(r):
            return p_fail(w,E_MEMORY,errno(r))
        put(w,P_CATALOG_MAP,r)
        put(w,P_CATALOG_CAP,get(w,P_CATALOG_NEED))
        return p_copy(w,31,get(w,P_ORIGIN_MAP),r,get(w,P_ORIGIN_DIR_N))
    if phase==31:
        if r!=0:
            return p_fail(w,E_CONTEXT,31)
        return p_buffer(w,32,12,get(w,P_CATALOG_TEMPLATE),get(w,P_CATALOG_TEMPLATE_N),get(w,P_CATALOG_MAP),get(w,P_CATALOG_CAP))
    if phase==32:
        if r!=0 or get(w,P_CATALOG_READY)!=1:
            return p_fail(w,E_CONTEXT,32)
        clear(w,P_SMALL,32)
        put(w,P_SMALL,PATH_REQUEST)
        put(w,P_SMALL+8,2)
        return p_invoke(w,33,R_PATH,p_at(w,P_SMALL),32,p_at(w,P_SUBOUT),128,p_at(w,P_PATH_WORK),200704)
    if phase==33:
        if r!=0 or get(w,P_SUBOUT)!=PATH_REPLY:
            put(w,P_UNKNOWN,1)
            return p_fail(w,E_CONTEXT,33)
        if get(w,P_SUBOUT+96)!=1:
            put(w,P_UNKNOWN,1)
            return p_fail(w,E_CLEANUP,33)
        if get(w,P_SUBOUT+88)!=0 or get(w,P_SUBOUT+104)!=1:
            return p_fail(w,E_CLEANUP,errno(get(w,P_SUBOUT+16)))
        put(w,P_PATH_ACTIVE,0)
        put(w,P_PATH_FD,NONE)
        return call(o,w,34,11,get(w,P_ORIGIN_MAP),get(w,P_ORIGIN_CAP),0,0,0,0,0)
    if phase==34:
        if failed(r):
            return p_fail(w,E_OS,errno(r))
        put(w,P_ORIGIN_MAP,0)
        put(w,P_ORIGIN_CAP,0)
        return p_identity(w,3,0)
    return 4294967293

def peek(w:mutbuf) -> u32:
    put(w,P_PEEK_PTR,get(w,P_ORIGIN_PTR)+get(w,P_ORIGIN_N))
    put(w,PHASE,22)
    return 4

def read_origin(o:mutbuf,w:mutbuf) -> u32:
    at=get(w,P_IO_AT)
    n=get(w,P_ORIGIN_N)
    if at==n:
        return p_buffer(w,28,10,get(w,P_ORIGIN_MAP),n,p_at(w,P_SMALL),64)
    return call(o,w,27,17,get(w,P_PATH_FD),get(w,P_ORIGIN_MAP)+at,n-at,at,0,0,0)
'''
if __name__=='__main__':write_module('clang_compile_location',SOURCE)
