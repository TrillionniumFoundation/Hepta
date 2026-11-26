"""Exact native custody acknowledgements and post-build owned resource retirement."""
from tools.generate_hia_clang_compile_common import write_module
SOURCE=r'''
def advance(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase=get(w,PHASE)
    r=get(w,RESULT)
    if phase==900:
        put(w,P_DRAINING,1)
        if get(w,P_UNKNOWN)!=0:
            return finish(o,w)
        if get(w,P_RETIRING)==0 and get(w,P_DIAG_ATTEMPTED)==0 and get(w,P_CAPTURE_ACTIVE)!=0:
            at=P_CAPTURE_OUT+get(w,P_CAP_INDEX)*256
            if get(w,at)==CAPTURE_REPLY:
                put(w,P_DIAG_ATTEMPTED,1)
                put(w,P_DIAG_INDEX,0)
                put(w,P_DIAG_NEXT,901)
                return jump(w,880)
        return jump(w,901)
    if phase==901:
        if get(w,P_PUBLISHED)!=0 and get(w,P_PUB_COMPLETE)==0:
            return call(o,w,902,6,get(w,P_STRINGS)+get(w,P_DEST_OFF),P_STAT,0,0,0,0,12)
        return jump(w,905)
    if phase==902:
        if failed(r):
            if errno(r)!=2 and errno(r)!=20:
                return cleanup_failed(o,w,errno(r))
            put(w,P_PUBLISHED,0)
            return jump(w,905)
        recognized=get(w,P_STAT+24)&61440==32768 and get(w,P_STAT)==get(w,P_STAGE_ID) and get(w,P_STAT+8)==get(w,P_STAGE_ID+8)
        if recognized==False:
            put(w,P_PUBLISHED,0)
            return jump(w,905)
        return call(o,w,903,87,get(w,P_STRINGS)+get(w,P_DEST_OFF),0,0,0,0,0,0)
    if phase==903:
        if failed(r):
            if errno(r)!=2:
                return cleanup_failed(o,w,errno(r))
        else:
            put(w,P_WITHDRAWN,1)
        put(w,P_PUBLISHED,0)
        return jump(w,905)
    if phase==905:
        if get(w,P_DIR_CREATED)==0:
            return jump(w,920)
        if get(w,P_DIRECTORY_FD)==NONE or get(w,P_PARENT_FD)==NONE:
            put(w,P_UNKNOWN,1)
            return cleanup_failed(o,w,116)
        clear(w,P_SMALL,148)
        put(w,P_SMALL,RMT_REQUEST)
        n=128
        if get(w,P_RMT_ACTIVE)==0:
            put(w,P_SMALL+16,get(w,P_DIRECTORY_FD))
            put(w,P_SMALL+24,get(w,P_PARENT_FD))
            put(w,P_SMALL+32,20)
            p_saved_copy(w,P_TEMP_NAME,P_SMALL+128,20)
            n=148
            put(w,P_RMT_ACTIVE,1)
        else:
            put(w,P_SMALL+8,choose(get(w,P_RMT_ABORT)!=0,2,1))
        return p_invoke(w,906,R_RMTREE,p_at(w,P_SMALL),n,p_at(w,P_SUBOUT),128,p_at(w,P_RMT_WORK),4096)
    if phase==906:
        if r!=0 or get(w,P_SUBOUT)!=RMT_REPLY:
            put(w,P_UNKNOWN,1)
            return cleanup_failed(o,w,906)
        if get(w,P_SUBOUT+32)!=1:
            put(w,P_UNKNOWN,1)
            return cleanup_failed(o,w,906)
        if get(w,P_SUBOUT+56)!=0:
            put(w,P_ROOT_REMOVED,1)
        if get(w,P_SUBOUT+40)==0 and get(w,P_SUBOUT+48)==1:
            put(w,P_RMT_ACTIVE,0)
            put(w,P_DIR_CREATED,0)
            if get(w,P_SUBOUT+8)!=0 or get(w,P_SUBOUT+56)==0:
                put(w,P_CLEAN_ERROR,E_CLEANUP)
                put(w,P_CLEAN_ERRNO,errno(get(w,P_SUBOUT+16)))
            return jump(w,920)
        number=errno(get(w,P_SUBOUT+16))
        if get(w,P_RMT_ABORT)==0 and (number==2 or number==20 or number==116):
            put(w,P_RMT_ABORT,1)
            return jump(w,905)
        return cleanup_failed(o,w,number)
    if phase==920:
        return p_close(o,w,P_SOURCE_FD,921)
    if phase==921:
        return p_close(o,w,P_MISC_FD,922)
    if phase==922:
        return p_close(o,w,P_DIRECTORY_FD,923)
    if phase==923:
        return p_close(o,w,P_PARENT_FD,924)
    if phase==924:
        if get(w,P_RETIRING)==0:
            return finish(o,w)
        return p_close(o,w,P_STDOUT,925)
    if phase==925:
        return p_close(o,w,P_STDERR,926)
    if phase==926:
        put(w,P_CLEAN_INDEX,0)
        return jump(w,930)
    if phase==930:
        index=get(w,P_CLEAN_INDEX)
        while index<3 and get(w,P_CAPTURE_ACTIVE)&(1<<index)==0:
            index=index+1
        if index==3:
            put(w,P_CLEAN_INDEX,0)
            return jump(w,940)
        put(w,P_CLEAN_INDEX,index)
        clear(w,P_SMALL,128)
        put(w,P_SMALL,CAPTURE_REQUEST)
        put(w,P_SMALL+8,1)
        return p_invoke(w,931,R_CAPTURE,p_at(w,P_SMALL),128,p_at(w,P_SUBOUT),256,get(w,P_CAPTURE_ARENA)+index*131072,P_CAPTURE_STRIDE)
    if phase==931:
        index=get(w,P_CLEAN_INDEX)
        if r!=0 or get(w,P_SUBOUT)!=CAPTURE_REPLY:
            put(w,P_UNKNOWN,1)
            return cleanup_failed(o,w,931)
        return p_copy(w,932,get(w,P_CAPTURE_ARENA)+index*131072,p_at(w,P_SMALL),4096)
    if phase==932:
        index=get(w,P_CLEAN_INDEX)
        if r!=0 or get(w,P_SMALL+1848)!=0:
            put(w,P_UNKNOWN,1)
            return cleanup_failed(o,w,931)
        if get(w,P_SUBOUT+8)!=0 or get(w,P_SUBOUT+136)!=0 or get(w,P_SMALL+616)!=0:
            return cleanup_failed(o,w,get(w,P_SUBOUT+16))
        put(w,P_CAPTURE_ACTIVE,get(w,P_CAPTURE_ACTIVE)&(NONE^(1<<index)))
        put(w,P_CLEAN_INDEX,index+1)
        return jump(w,930)
    if phase==940:
        index=get(w,P_CLEAN_INDEX)
        while index<3 and get(w,P_FILE_ACTIVE)&(1<<index)==0:
            index=index+1
        if index==3:
            return jump(w,950)
        put(w,P_CLEAN_INDEX,index)
        put(w,P_FILE_INDEX,index)
        clear(w,P_SMALL,192)
        put(w,P_SMALL,FILE_REQUEST)
        put(w,P_SMALL+8,3)
        return p_invoke(w,941,R_FILE,p_at(w,P_SMALL),192,p_at(w,P_SUBOUT),256,p_at(w,p_file_work(w)),1056768)
    if phase==941:
        if r!=0 or get(w,P_SUBOUT)!=FILE_REPLY:
            put(w,P_UNKNOWN,1)
            return cleanup_failed(o,w,941)
        if get(w,P_SUBOUT+168)!=1:
            put(w,P_UNKNOWN,1)
            return cleanup_failed(o,w,941)
        if get(w,P_SUBOUT+160)!=0 or get(w,P_SUBOUT+176)!=1:
            return cleanup_failed(o,w,get(w,P_SUBOUT+16))
        index=get(w,P_CLEAN_INDEX)
        put(w,P_FILE_ACTIVE,get(w,P_FILE_ACTIVE)&(NONE^(1<<index)))
        put(w,P_CLEAN_INDEX,index+1)
        return jump(w,940)
    if phase==950:
        if get(w,P_ID_ACTIVE)==0:
            return jump(w,952)
        clear(w,P_SMALL,32)
        put(w,P_SMALL,ID_REQUEST)
        put(w,P_SMALL+8,1)
        return p_invoke(w,951,R_IDENTITY,p_at(w,P_SMALL),32,p_at(w,P_SUBOUT),128,p_at(w,P_ID_WORK),2097152)
    if phase==951:
        if r!=0 or get(w,P_SUBOUT)!=ID_REPLY:
            put(w,P_UNKNOWN,1)
            return cleanup_failed(o,w,951)
        if get(w,P_SUBOUT+72)!=1:
            put(w,P_UNKNOWN,1)
            return cleanup_failed(o,w,951)
        if get(w,P_SUBOUT+64)!=0 or get(w,P_SUBOUT+80)!=1:
            return cleanup_failed(o,w,get(w,P_SUBOUT+16))
        put(w,P_ID_ACTIVE,0)
        return jump(w,952)
    if phase==952:
        if get(w,P_PATH_ACTIVE)==0:
            return jump(w,954)
        clear(w,P_SMALL,32)
        put(w,P_SMALL,PATH_REQUEST)
        put(w,P_SMALL+8,2)
        return p_invoke(w,953,R_PATH,p_at(w,P_SMALL),32,p_at(w,P_SUBOUT),128,p_at(w,P_PATH_WORK),200704)
    if phase==953:
        if r!=0 or get(w,P_SUBOUT)!=PATH_REPLY:
            put(w,P_UNKNOWN,1)
            return cleanup_failed(o,w,953)
        if get(w,P_SUBOUT+96)!=1:
            put(w,P_UNKNOWN,1)
            return cleanup_failed(o,w,953)
        if get(w,P_SUBOUT+88)!=0 or get(w,P_SUBOUT+104)!=1:
            return cleanup_failed(o,w,get(w,P_SUBOUT+16))
        put(w,P_PATH_ACTIVE,0)
        put(w,P_PATH_FD,NONE)
        return jump(w,954)
    if phase==954:
        if get(w,P_WHICH_ACTIVE)==0:
            put(w,P_CLEAN_INDEX,0)
            return jump(w,970)
        clear(w,P_SMALL,32)
        put(w,P_SMALL,WHICH_REQUEST)
        put(w,P_SMALL+8,1)
        return p_invoke(w,955,R_WHICH,p_at(w,P_SMALL),32,p_at(w,P_SUBOUT),128,p_at(w,P_WHICH_WORK),4096)
    if phase==955:
        if r!=0 or get(w,P_SUBOUT)!=WHICH_REPLY:
            put(w,P_UNKNOWN,1)
            return cleanup_failed(o,w,955)
        if get(w,P_SUBOUT+64)!=1:
            put(w,P_UNKNOWN,1)
            return cleanup_failed(o,w,955)
        if get(w,P_SUBOUT+56)!=0 or get(w,P_SUBOUT+72)!=1:
            return cleanup_failed(o,w,get(w,P_SUBOUT+16))
        put(w,P_WHICH_ACTIVE,0)
        put(w,P_CLEAN_INDEX,0)
        return jump(w,970)
    if phase==970:
        index=get(w,P_CLEAN_INDEX)
        while index<7 and get(w,map_slot(index))==0:
            index=index+1
        if index==7:
            return finish(o,w)
        put(w,P_CLEAN_INDEX,index)
        slot=map_slot(index)
        return call(o,w,971,11,get(w,slot),get(w,slot+8),0,0,0,0,0)
    if phase==971:
        if failed(r):
            return cleanup_failed(o,w,errno(r))
        index=get(w,P_CLEAN_INDEX)
        put(w,map_slot(index),0)
        put(w,map_slot(index)+8,0)
        put(w,P_CLEAN_INDEX,index+1)
        return jump(w,970)
    if phase==999:
        return finish(o,w)
    return 4294967293

def map_slot(index:u64) -> u64:
    if index==0:
        return P_FRAME
    if index==1:
        return P_STRINGS
    if index==2:
        return P_OBJ_OUT
    if index==3:
        return P_OBJ_WORK
    if index==4:
        return P_CAPTURE_ARENA
    if index==5:
        return P_ORIGIN_MAP
    return P_CATALOG_MAP

def cleanup_failed(o:mutbuf,w:mutbuf,number:u64) -> u32:
    put(w,P_CLEAN_ERROR,E_CLEANUP)
    put(w,P_CLEAN_ERRNO,number)
    return finish(o,w)

def finish(o:mutbuf,w:mutbuf) -> u32:
    clear(o,0,512)
    put(o,0,P_REPLY)
    fds=0
    i=P_STDOUT
    while i<=P_MISC_FD:
        if get(w,i)!=NONE:
            fds=fds+1
        i=i+8
    maps=0
    i=0
    while i<7:
        if get(w,map_slot(i))!=0:
            maps=maps+1
        i=i+1
    children=get(w,P_WHICH_ACTIVE)|get(w,P_PATH_ACTIVE)|get(w,P_FILE_ACTIVE)|get(w,P_CAPTURE_ACTIVE)|get(w,P_ID_ACTIVE)|get(w,P_RMT_ACTIVE)
    namespace=get(w,P_DIR_CREATED)!=0 or get(w,P_PUBLISHED)!=0 and get(w,P_PUB_COMPLETE)==0
    pending=fds!=0 or maps!=0 or children!=0 or namespace or get(w,P_UNKNOWN)!=0
    retired=get(w,P_RETIRING)!=0 and pending==False
    error=get(w,ERROR)
    detail=get(w,ERROR_NO)
    if get(w,P_RETIRING)!=0:
        error=0
        detail=0
    if get(w,P_CLEAN_ERROR)!=0:
        error=E_CLEANUP
        detail=get(w,P_CLEAN_ERRNO)
    if get(w,P_UNKNOWN)!=0:
        error=E_CONTEXT
    put(o,8,error)
    put(o,16,detail)
    put(o,24,get(w,P_ACTUAL_EXIT))
    put(o,32,get(w,P_EXIT_KNOWN))
    put(o,40,get(w,P_ERROR_PHASE))
    put(o,48,get(w,P_SCHEMA))
    put(o,56,get(w,P_CORE_N))
    put(o,64,get(w,P_ABI_N))
    put(o,72,get(w,P_PATH_N))
    if get(w,P_RETIRING)==0:
        put(o,80,get(w,P_RECEIPT_N))
    stdout=NONE
    stderr=NONE
    if get(w,P_DIAG_READY)&1!=0:
        stdout=get(w,P_STDOUT)
    if get(w,P_DIAG_READY)&2!=0:
        stderr=get(w,P_STDERR)
    put(o,88,stdout)
    put(o,96,stderr)
    put(o,112,get(w,P_STDOUT_N))
    put(o,120,get(w,P_STDERR_N))
    put(o,128,get(w,P_WITHDRAWN))
    put(o,136,get(w,P_PUB_COMPLETE))
    i=0
    while i<32:
        store(o,160+i,byte(w,P_CORE_SHA+i))
        store(o,192+i,byte(w,P_ABI_SHA+i))
        store(o,224+i,byte(w,P_IR_SHA+i))
        store(o,256+i,byte(w,P_TOOL_SHA+i))
        store(o,288+i,byte(w,P_ART_SHA+i))
        i=i+1
    state=0
    if pending:
        state=1
    if get(w,P_UNKNOWN)!=0:
        state=2
    put(o,336,state)
    put(o,344,choose(get(w,P_UNKNOWN)==0,1,0))
    put(o,352,choose(retired,1,0))
    put(o,360,choose(pending,1,0))
    put(o,368,get(w,P_CLEAN_ERROR))
    put(o,376,get(w,P_CLEAN_ERRNO))
    put(o,384,get(w,P_ROOT_REMOVED))
    put(o,392,fds)
    put(o,400,maps)
    put(o,408,children)
    if retired:
        clear(w,0,4096)
    return 0
'''
if __name__=='__main__':write_module('clang_compile_cleanup',SOURCE)
