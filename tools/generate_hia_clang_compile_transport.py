"""Actual fixed-role file/capture calls, allocations and owned descriptor retirement."""
from tools.generate_hia_clang_compile_common import write_module
SOURCE=r'''
def advance(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase=get(w,PHASE)
    r=get(w,RESULT)
    if phase==810 or phase==811:
        return p_allocation(w)
    if phase==820:
        return p_buffer(w,821,4,get(w,P_STRINGS),get(w,P_STRINGS_CAP),get(w,P_FRAME),get(w,P_FRAME_CAP))
    if phase==821:
        if r!=193+get(w,P_FILE_PATH_N)+get(w,P_EXPECT_N):
            return p_fail(w,E_CONTEXT,821)
        put(w,P_LAST_FRAME_N,r)
        if get(w,P_EXPECT_N)!=0:
            return p_copy(w,822,get(w,P_EXPECT_PTR),get(w,P_FRAME)+193+get(w,P_FILE_PATH_N),get(w,P_EXPECT_N))
        return jump(w,823)
    if phase==822:
        if r!=0:
            return p_fail(w,E_CONTEXT,822)
        return jump(w,823)
    if phase==823:
        put(w,P_FILE_ACTIVE,get(w,P_FILE_ACTIVE)|(1<<get(w,P_FILE_INDEX)))
        return p_invoke(w,825,R_FILE,get(w,P_FRAME),get(w,P_LAST_FRAME_N),p_at(w,P_SUBOUT),256,p_at(w,p_file_work(w)),1056768)
    if phase==825:
        if r!=0 or get(w,P_SUBOUT)!=FILE_REPLY:
            put(w,P_UNKNOWN,1)
            return p_fail(w,E_CONTEXT,825)
        if get(w,P_SUBOUT+168)!=1:
            put(w,P_UNKNOWN,1)
        if get(w,P_SUBOUT+8)!=0 or get(w,P_SUBOUT+160)!=0 and get(w,P_FILE_MODE)!=1:
            error=E_TOOL
            if get(w,P_FILE_INDEX)==1:
                error=E_ARTIFACT
            elif get(w,P_FILE_INDEX)==2:
                error=E_PUBLICATION
            return p_fail(w,error,get(w,P_SUBOUT+16))
        p_saved_copy(w,P_SUBOUT,P_FILE_RESULT,256)
        if get(w,P_FILE_MODE)==1:
            return jump(w,get(w,P_FILE_NEXT))
        clear(w,P_SMALL,192)
        put(w,P_SMALL,FILE_REQUEST)
        put(w,P_SMALL+8,3)
        return p_invoke(w,826,R_FILE,p_at(w,P_SMALL),192,p_at(w,P_SUBOUT),256,p_at(w,p_file_work(w)),1056768)
    if phase==826:
        if r!=0 or get(w,P_SUBOUT)!=FILE_REPLY:
            put(w,P_UNKNOWN,1)
            return p_fail(w,E_CONTEXT,826)
        if get(w,P_SUBOUT+168)!=1:
            put(w,P_UNKNOWN,1)
            return p_fail(w,E_CLEANUP,826)
        if get(w,P_SUBOUT+8)!=0 or get(w,P_SUBOUT+160)!=0 or get(w,P_SUBOUT+176)!=1:
            return p_fail(w,E_CLEANUP,get(w,P_SUBOUT+16))
        put(w,P_FILE_ACTIVE,get(w,P_FILE_ACTIVE)&(NONE^(1<<get(w,P_FILE_INDEX))))
        return jump(w,get(w,P_FILE_NEXT))
    if phase==844:
        if failed(r):
            return p_fail(w,E_MEMORY,errno(r))
        put(w,P_CAPTURE_ARENA,r)
        put(w,P_CAPTURE_ARENA_CAP,393216)
        return jump(w,840)
    if phase==840:
        if get(w,P_CAPTURE_ARENA)==0:
            return call(o,w,844,9,0,393216,3,34,NONE,0,0)
        return p_buffer(w,841,5,get(w,P_STRINGS),get(w,P_STRINGS_CAP),get(w,P_FRAME),get(w,P_FRAME_CAP))
    if phase==841:
        if r<128 or r>get(w,P_FRAME_CAP):
            return p_fail(w,E_CONTEXT,841)
        index=get(w,P_CAP_INDEX)
        put(w,P_CAPTURE_ACTIVE,get(w,P_CAPTURE_ACTIVE)|(1<<index))
        return p_invoke(w,842,R_CAPTURE,get(w,P_FRAME),r,get(w,P_CAPTURE_ARENA)+index*131072+65536,256,get(w,P_CAPTURE_ARENA)+index*131072,P_CAPTURE_STRIDE)
    if phase==842:
        if r!=0:
            put(w,P_UNKNOWN,1)
            return p_fail(w,E_CONTEXT,842)
        index=get(w,P_CAP_INDEX)
        return p_copy(w,843,get(w,P_CAPTURE_ARENA)+index*131072+65536,p_at(w,P_CAPTURE_OUT+index*256),256)
    if phase==843:
        at=P_CAPTURE_OUT+get(w,P_CAP_INDEX)*256
        if r!=0 or get(w,at)!=CAPTURE_REPLY:
            put(w,P_UNKNOWN,1)
            return p_fail(w,E_CONTEXT,842)
        if get(w,at+240)!=0:
            put(w,P_UNKNOWN,1)
        put(w,P_EXIT_KNOWN,get(w,at+24))
        put(w,P_ACTUAL_EXIT,get(w,at+32))
        if get(w,at+8)!=0 or get(w,at+136)!=0 or get(w,at+24)!=1:
            error=E_TOOL
            if get(w,P_CAP_INDEX)==2:
                error=E_COMPILE
            return p_fail(w,error,get(w,at+8))
        return jump(w,get(w,P_CAPTURE_NEXT))
    if phase==870:
        if failed(r):
            if errno(r)==38:
                put(w,P_CLOSE_METHOD,1)
                return call(o,w,871,3,get(w,get(w,P_FD_SLOT)),0,0,0,0,0,0)
            return close_failure(w,errno(r),False)
        put(w,get(w,P_FD_SLOT),NONE)
        return jump(w,get(w,P_IO_NEXT))
    if phase==871:
        if failed(r):
            return close_failure(w,errno(r),True)
        put(w,get(w,P_FD_SLOT),NONE)
        return jump(w,get(w,P_IO_NEXT))
    return 4294967293

def close_failure(w:mutbuf,number:u64,unknown:bool) -> u32:
    if unknown:
        put(w,P_CLOSE_UNKNOWN,1)
        put(w,P_UNKNOWN,1)
    put(w,P_CLEAN_ERROR,E_CLEANUP)
    put(w,P_CLEAN_ERRNO,number)
    if get(w,P_DRAINING)!=0:
        return jump(w,999)
    return p_fail(w,E_OS,number)
'''
if __name__=='__main__':write_module('clang_compile_transport',SOURCE)
