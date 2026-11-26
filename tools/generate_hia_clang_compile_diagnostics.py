"""Owned sealed diagnostic descriptors from actual retained capture bytes."""
from tools.generate_hia_clang_compile_common import write_module
SOURCE=r'''
def advance(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase=get(w,PHASE)
    r=get(w,RESULT)
    if phase==880:
        index=get(w,P_DIAG_INDEX)
        at=P_CAPTURE_OUT+get(w,P_CAP_INDEX)*256
        ptr=get(w,at+72+index*16)
        n=get(w,at+80+index*16)
        if n!=0 and ptr==0:
            return p_fail(w,E_CONTEXT,880)
        put(w,P_IO_PTR,ptr)
        put(w,P_IO_TOTAL,n)
        put(w,P_IO_AT,0)
        name(w)
        return call(o,w,881,319,P_SMALL,3,0,0,0,0,3)
    if phase==881:
        if failed(r):
            return p_fail(w,E_OS,errno(r))
        put(w,P_STDOUT+get(w,P_DIAG_INDEX)*8,r)
        put(w,P_IO_FD,r)
        return call(o,w,882,77,r,get(w,P_IO_TOTAL),0,0,0,0,0)
    if phase==882:
        if failed(r):
            return p_fail(w,E_OS,errno(r))
        return writing(o,w)
    if phase==883:
        if failed(r):
            if errno(r)==4:
                return writing(o,w)
            return p_fail(w,E_OS,errno(r))
        if r==0 or r>get(w,P_IO_TOTAL)-get(w,P_IO_AT):
            return p_fail(w,E_OS,5)
        put(w,P_IO_AT,get(w,P_IO_AT)+r)
        return writing(o,w)
    if phase==884:
        if failed(r):
            return p_fail(w,E_OS,errno(r))
        index=get(w,P_DIAG_INDEX)
        put(w,P_STDOUT_N+index*8,get(w,P_IO_TOTAL))
        put(w,P_DIAG_READY,get(w,P_DIAG_READY)|(1<<index))
        if index==0:
            put(w,P_DIAG_INDEX,1)
            return jump(w,880)
        return jump(w,get(w,P_DIAG_NEXT))
    return 4294967293

def writing(o:mutbuf,w:mutbuf) -> u32:
    at=get(w,P_IO_AT)
    n=get(w,P_IO_TOTAL)
    if at==n:
        return call(o,w,884,72,get(w,P_IO_FD),1033,15,0,0,0,0)
    return call(o,w,883,18,get(w,P_IO_FD),get(w,P_IO_PTR)+at,n-at,at,0,0,0)

def name(w:mutbuf) -> u64:
    put(w,P_SMALL,7956005807396907368)
    put(w,P_SMALL+8,418565190756)
    return 0
'''
if __name__=='__main__':write_module('clang_compile_diagnostics',SOURCE)
