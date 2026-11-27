"""Actual pre-decode byte custody and final-close/evidence facts for origin capture."""
from tools.generate_hia_clang_origin_error_capture_common import write_module
from tools.generate_hia_clang_capture_storage import SOURCE as ORIGINAL
def change(source,old,new):
 assert source.count(old)==1,(old,source.count(old))
 return source.replace(old,new)
SOURCE=ORIGINAL
SOURCE=change(SOURCE,
"""            put(w,ERROR_STREAM,get(w,READ_INDEX))
            return jump(w,480)""",
"""            put(w,ERROR_STREAM,get(w,READ_INDEX))
            slot=RAW_OUT+get(w,READ_INDEX)*24
            if get(w,CAP_DECODE_PTR)!=0:
                return storage_error(w,E_CONTEXT,452)
            put(w,CAP_DECODE_PTR,get(w,slot))
            put(w,CAP_DECODE_N,get(w,slot+8))
            put(w,CAP_DECODE_CAP,get(w,slot+16))
            clear(w,slot,24)
            return jump(w,480)""")
SOURCE=change(SOURCE,
"""    if get(w,ERROR)!=0:
        return jump(w,500)
    put(w,READ_INDEX,0)""",
"""    if get(w,ERROR)!=0:
        put(w,CAP_EVIDENCE_COMPLETE,1)
        return jump(w,500)
    put(w,READ_INDEX,0)""")
SOURCE=change(SOURCE,
"""    if get(w,ERROR)!=0:
        put(w,EVIDENCE_ERROR,code)""",
"""    if get(w,ERROR)!=0:
        put(w,CAP_EVIDENCE_PHASE,get(w,PHASE))
        put(w,EVIDENCE_ERROR,code)""")
SOURCE=change(SOURCE,
"""    while i<5:
        if get(w,INPUT_FD+i*8)!=NONE:
            put(w,CLEAN_INDEX,i)
            return close_fd(o,w,501,get(w,INPUT_FD+i*8),i)
        i=i+1""",
"""    while i<5:
        index=choose(i<3,2-i,i)
        if get(w,INPUT_FD+index*8)!=NONE:
            put(w,CLEAN_INDEX,i)
            return close_fd(o,w,501,get(w,INPUT_FD+index*8),index)
        i=i+1""")
SOURCE=change(SOURCE,
"""        i=get(w,CLEAN_INDEX)
        put(w,CLEAN_INDEX,i+1)
        if failed(result):
            cleanup_error(w,E_CLEANUP,errno(result))
            first_error(w,E_CLEANUP,errno(result))
            put(w,CLEAN_PENDING,get(w,CLEAN_PENDING)|2)
        else:
            put(w,INPUT_FD+i*8,NONE)""",
"""        i=get(w,CLEAN_INDEX)
        index=choose(i<3,2-i,i)
        put(w,CLEAN_INDEX,i+1)
        if failed(result):
            if i<3:
                put(w,CAP_CLOSE_ERROR,errno(result))
                put(w,CAP_CLOSE_COUNT,get(w,CAP_CLOSE_COUNT)+1)
                put(w,CAP_CLOSE_ERRORS+i*8,errno(result))
            cleanup_error(w,E_CLEANUP,errno(result))
            first_error(w,E_CLEANUP,errno(result))
            put(w,CLEAN_PENDING,get(w,CLEAN_PENDING)|2)
        else:
            put(w,INPUT_FD+index*8,NONE)""")
SOURCE=change(SOURCE,
"""    if index==4:
        return PATH_WORK
    return ENV_PATH_BUFFER""",
"""    if index==4:
        return PATH_WORK
    if index==6:
        return CAP_DECODE_PTR
    return ENV_PATH_BUFFER""")
SOURCE=change(SOURCE,
"""    if index==4:
        return PATH_CAP
    return ENV_PATH_ALLOC""",
"""    if index==4:
        return PATH_CAP
    if index==6:
        return CAP_DECODE_CAP
    return ENV_PATH_ALLOC""")
SOURCE=change(SOURCE,
"""    while i<6:
        slot=release_slot(i)""",
"""    while i<7:
        slot=release_slot(i)""")
SOURCE=change(SOURCE,
"""            if get(w,RELEASE_INDEX)<4:
                put(w,get(w,RELEASE_SLOT)+8,0)""",
"""            if get(w,RELEASE_INDEX)<4 or get(w,RELEASE_INDEX)==6:
                put(w,get(w,RELEASE_SLOT)+8,0)""")
SOURCE=change(SOURCE,
"""        put(w,FD_RETRY_PENDING,0)
        return retire_fds(o,w)""",
"""        put(w,FD_RETRY_PENDING,0)
        if get(w,CLEAN_PENDING)&1!=0 and get(w,SPAWNED)!=0 and get(w,PID)!=0 and get(w,RETURN_KNOWN)==0:
            return call(o,w,703,61,get(w,PID),STAT,1,0,0,0,12)
        return retire_fds(o,w)
    if phase==703:
        if failed(result):
            if errno(result)==4:
                return call(o,w,703,61,get(w,PID),STAT,1,0,0,0,12)
            put(w,RETIRE_ERROR,E_OS)
            put(w,RETIRE_ERRNO,errno(result))
        elif result==get(w,PID):
            status=get(w,STAT)&4294967295
            if (status&127)==127 or status==65535:
                put(w,RETIRE_ERROR,E_OWNERSHIP)
                put(w,RETIRE_ERRNO,0)
            else:
                code=0-(status&127)
                if (status&127)==0:
                    code=(status>>8)&255
                put(w,RETURN_CODE,code)
                put(w,RETURN_KNOWN,1)
                put(w,CLEAN_PENDING,get(w,CLEAN_PENDING)&18446744073709551614)
        elif result!=0:
            put(w,RETIRE_ERROR,E_OWNERSHIP)
            put(w,RETIRE_ERRNO,0)
        return retire_fds(o,w)""")
if __name__=='__main__':write_module('clang_origin_error_capture_storage',SOURCE,'storage')
