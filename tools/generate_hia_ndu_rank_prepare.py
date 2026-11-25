"""Complete rank admission and fresh candidate preparation, in HIA."""
from pathlib import Path
import ast
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_system_jobctl_request import document
from tools.generate_hia_ndu_rank_owner_common import C,common_source,resolve
ROOT=Path(__file__).resolve().parents[1]
C.update({'AD_RESULT':45056,'SNAP_FRAME':4480,'SNAP_N':4488})
SOURCE=r'''
def rank_prepare(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(o)<65536:
        return 4294967293
    phase=get(o,PHASE)
    if phase>=9000:
        return error_steps(s,o,w)
    if phase>=100 and phase<140:
        return normalization(s,o,w)
    if phase>=50 and phase<80:
        return observed(s,o,w)
    if phase>=21 and phase<40:
        return candidates(s,o,w)
    return initial(s,o,w)

def initial(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase=get(o,PHASE)
    if phase==0:
        if length(s)<128 or read(s,0)!=RANK_REQUEST or read(s,8)!=1:
            return terminal(o,4)
        bn=read(s,16)
        an=read(s,24)
        if bn>length(s)-128 or an!=length(s)-128-bn:
            return terminal(o,4)
        i=32
        while i<128:
            if read(s,i)!=0:
                return terminal(o,4)
            i=i+8
        put(o,ARGS_AT,128+bn)
        put(o,ARGS_N,an)
        put(o,CURRENT,0)
        if get(o,START)!=0:
            put(o,FEEDBACK,0)
            put(o,PHASE,1)
            return 3
        return clock(o,1)
    if phase==1:
        if get(o,FEEDBACK)!=0:
            return terminal(o,4)
        if get(o,START)==0:
            put(o,START,now(o))
        return norm_start(o,0,2,128,read(s,16),10)
    if phase==10:
        return decode_at(o,1,get(o,ROWS+R_CORE),get(o,ROWS+R_CORE_N),11)
    if phase==11:
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        put(o,BCORE_ARENA,get(o,RET_ARENA))
        put(o,BCORE_AN,get(o,RET_ARENA_N))
        return capture_at(o,2,get(o,ARGS_AT),get(o,ARGS_N),12)
    if phase==12:
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        put(o,ARGS_ARENA,get(o,RET_ARENA))
        put(o,ARGS_AN,get(o,RET_ARENA_N))
        frame_begin(o,128)
        put(o,FRAME_HEADER,AD_REQUEST)
        put(o,FRAME_HEADER+8,4)
        put(o,FRAME_HEADER+24,get(o,ARGS_N))
        put(o,FRAME_HEADER+32,get(o,ARGS_AN))
        put(o,FRAME_HEADER+40,get(o,ROWS+R_CORE_N))
        put(o,FRAME_HEADER+48,get(o,BCORE_AN))
        copy_control(o,FRAME_HEADER+64,ROWS+R_CORE_HASH,32)
        frame_part(o,2,get(o,ARGS_AT),get(o,ARGS_N))
        frame_part(o,1,get(o,ARGS_ARENA),get(o,ARGS_AN))
        frame_part(o,1,get(o,ROWS+R_CORE),get(o,ROWS+R_CORE_N))
        frame_part(o,1,get(o,BCORE_ARENA),get(o,BCORE_AN))
        return frame_start(o,14)
    if phase==14:
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        put(o,AD_FRAME,get(o,RET_AT))
        put(o,AD_N,get(o,RET_N))
        put(o,AD_ACTION,4)
        put(o,AD_BITS,0)
        put(o,AD_INVALID,0)
        return admission_call(o,w,4,0,16)
    if phase==16:
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        at=get(o,RET_AT)
        if get(o,RET_AUX)!=8192 or get(w,at)!=AD_REPLY:
            return terminal(o,4)
        status=get(w,at+8)
        if status==1:
            return direct_error(o,at+1024,get(w,at+248))
        copy_work_control(o,AD_RESULT,w,at,1024)
        put(o,TOP,at)
        if status==2:
            return call_role(o,BINARY64_ROLE,2,get(o,ARGS_AT)+get(o,AD_RESULT+168),get(o,AD_RESULT+176),8,4096,17)
        if status!=4:
            return terminal(o,4)
        put(o,GENERATION,get(o,AD_RESULT+32))
        put(o,TIMEOUT,get(o,AD_RESULT+40))
        put(o,BRIDGE_BITS,get(o,AD_RESULT+64))
        put(o,BRIDGE_INTEGER,get(o,AD_RESULT+72))
        put(o,FUNCTION_N,get(o,AD_RESULT+96))
        copy_control(o,FUNCTION_BYTES,AD_RESULT+512,get(o,FUNCTION_N))
        put(o,OBJECTIVE_NODE,get(o,AD_RESULT+104))
        put(o,BRIDGE_NODE,get(o,AD_RESULT+112))
        put(o,CANDIDATES_NODE,get(o,AD_RESULT+120))
        put(o,OBS_NODE,get(o,AD_RESULT+128))
        return canonical_at(o,2,get(o,ARGS_AT),get(o,ARGS_N),get(o,ARGS_ARENA),get(o,ARGS_AN),get(o,OBJECTIVE_NODE),1,18)
    if phase==17:
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        put(o,AD_BITS,0)
        put(o,AD_INVALID,1)
        if get(o,RET_AUX)==8:
            put(o,AD_BITS,get(w,get(o,RET_AT)))
            put(o,AD_INVALID,0)
        put(o,TOP,get(o,RET_AT))
        put(o,AD_ACTION,5)
        return admission_call(o,w,5,0,16)
    if phase==18:
        if get(o,RET_STATUS)==7:
            return direct_error(o,get(o,RET_AT),get(o,RET_N))
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        put(o,OBJECTIVE_AT,get(o,RET_AT))
        put(o,OBJECTIVE_N,get(o,RET_N))
        return admission_call(o,w,get(o,AD_ACTION)-4,0,19)
    if phase==19:
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        at=get(o,RET_AT)
        if get(o,RET_AUX)!=8192 or get(w,at)!=AD_REPLY:
            return terminal(o,4)
        if get(w,at+8)==1:
            return direct_error(o,at+1024,get(w,at+248))
        if get(w,at+8)!=0:
            return terminal(o,4)
        put(o,CALLS,get(w,at+48))
        put(o,CAP,get(w,at+56))
        put(o,TOP,at)
        frame_begin(o,128)
        put(o,FRAME_HEADER,COST_REQUEST)
        put(o,FRAME_HEADER+16,get(o,CAP))
        return frame_start(o,80)
    if phase==80:
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        put(o,TEMP,get(o,RET_AT))
        return call_role(o,COST_ROLE,1,get(o,RET_AT),get(o,RET_N),256,256,81)
    if phase==81:
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        at=get(o,RET_AT)
        if get(o,RET_AUX)!=0 or get(w,at)!=COST_REPLY:
            return terminal(o,4)
        if get(w,at+16)!=0:
            if get(w,at+16)==1:
                return literal_error(o,4,1,11)
            return literal_error(o,4,1,10)
        put(o,CAP_Q32,get(w,at+40))
        put(o,TOP,get(o,TEMP))
        put(o,PHASE,20)
        return 3
    if phase==20:
        at=get(o,TOP)
        if needed(o,w,at+8)==False:
            if get(o,ALLOC_FAILED)!=0:
                return terminal(o,3)
            return 2
        put(w,at,31078114724635233)
        put(o,ROWS+R_ID,at)
        put(o,ROWS+R_ID_N,7)
        put(o,TOP,at+8)
        put(o,CURRENT,1)
        put(o,PHASE,21)
        return 3
    return terminal(o,4)

def admission_call(o:mutbuf,w:mutbuf,action:u64,index:u64,next:u64) -> u32:
    at=get(o,AD_FRAME)
    put(w,at,AD_REQUEST)
    put(w,at+8,action)
    put(w,at+16,index)
    put(w,at+56,0)
    put(w,at+96,0)
    if action==1 or action==5:
        put(w,at+56,get(o,AD_BITS))
        put(w,at+96,get(o,AD_INVALID))
    count=get(w,get(o,ARGS_ARENA)+8)
    if get(w,get(o,BCORE_ARENA)+8)>count:
        count=get(w,get(o,BCORE_ARENA)+8)
    return call_role(o,ADMISSION_ROLE,1,at,get(o,AD_N),8192,131072+count,next)

def candidates(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase=get(o,PHASE)
    if phase==21:
        return admission_call(o,w,2,get(o,CURRENT)-1,22)
    if phase==22:
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        at=get(o,RET_AT)
        if get(o,RET_AUX)!=8192 or get(w,at)!=AD_REPLY:
            return terminal(o,4)
        if get(w,at+8)==1:
            return direct_error(o,at+1024,get(w,at+248))
        put(o,COUNT,get(w,at+80))
        if get(w,at+8)==3:
            put(o,TOP,at)
            put(o,PHASE,50)
            return 3
        if get(w,at+8)!=0:
            return terminal(o,4)
        copy_work_control(o,AD_RESULT,w,at,1024)
        put(o,TOP,at)
        r=row(o)
        a=get(o,ARGS_ARENA)
        id=get(o,AD_RESULT+136)
        action=get(o,AD_RESULT+144)
        put(o,r+R_ID,a+node(w,a,id,24))
        put(o,r+R_ID_N,node(w,a,id,32))
        put(o,r+R_ACTION,a+node(w,a,action,24))
        put(o,r+R_ACTION_N,node(w,a,action,32))
        put(o,r+R_PROGRAM_NODE,get(o,AD_RESULT+152))
        if get(o,AD_RESULT+160)==4:
            return norm_start(o,get(o,CURRENT),1,a+get(o,AD_RESULT+224),get(o,AD_RESULT+232),30)
        if get(o,SNAP_N)!=0:
            put(w,get(o,SNAP_FRAME)+8,get(o,r+R_PROGRAM_NODE))
            return call_role(o,SNAPSHOT_ROLE,1,get(o,SNAP_FRAME),get(o,SNAP_N),2048,131072+get(w,get(o,ARGS_ARENA)+8),24)
        frame_begin(o,128)
        put(o,FRAME_HEADER,SNAP_REQUEST)
        put(o,FRAME_HEADER+8,get(o,r+R_PROGRAM_NODE))
        put(o,FRAME_HEADER+16,get(o,ARGS_N))
        put(o,FRAME_HEADER+24,get(o,ARGS_AN))
        frame_part(o,2,get(o,ARGS_AT),get(o,ARGS_N))
        frame_part(o,1,get(o,ARGS_ARENA),get(o,ARGS_AN))
        return frame_start(o,23)
    if phase==23:
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        put(o,SNAP_FRAME,get(o,RET_AT))
        put(o,SNAP_N,get(o,RET_N))
        return call_role(o,SNAPSHOT_ROLE,1,get(o,RET_AT),get(o,RET_N),2048,131072+get(w,get(o,ARGS_ARENA)+8),24)
    if phase==24:
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        at=get(o,RET_AT)
        if get(o,RET_AUX)!=0 or get(w,at)!=SNAP_REPLY:
            return terminal(o,4)
        if get(w,at+8)!=0:
            return candidate_json_error(o,at+128,get(w,at+48),30)
        if get(o,STRUCT_N)==0:
            frame_begin(o,128)
            put(o,FRAME_HEADER,STRUCT_REQUEST)
            put(o,FRAME_HEADER+8,get(o,row(o)+R_PROGRAM_NODE))
            put(o,FRAME_HEADER+16,get(o,ARGS_N))
            put(o,FRAME_HEADER+24,get(o,ARGS_AN))
            put(o,FRAME_HEADER+32,get(o,THRESHOLD_N))
            put(o,FRAME_HEADER+40,get(o,INT_DIGITS))
            frame_part(o,2,get(o,ARGS_AT),get(o,ARGS_N))
            frame_part(o,1,get(o,ARGS_ARENA),get(o,ARGS_AN))
            frame_part(o,0,get(o,THRESHOLD_PTR),get(o,THRESHOLD_N))
            return frame_start(o,25)
        put(o,PHASE,26)
        return 3
    if phase==25:
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        put(o,STRUCT_FRAME,get(o,RET_AT))
        put(o,STRUCT_N,get(o,RET_N))
        put(o,PHASE,26)
        return 3
    if phase==26:
        put(w,get(o,STRUCT_FRAME)+8,get(o,row(o)+R_PROGRAM_NODE))
        return call_role(o,STRUCTURE_ROLE,1,get(o,STRUCT_FRAME),get(o,STRUCT_N),1024,4202496+get(w,get(o,ARGS_ARENA)+8),27)
    if phase==27:
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        at=get(o,RET_AT)
        if get(o,RET_AUX)!=0 or get(w,at)!=STRUCT_REPLY:
            return terminal(o,4)
        if get(w,at+8)!=0:
            if get(w,at+16)==9:
                return candidate_format_error(o,30)
            return candidate_json_error(o,at+128,get(w,at+40),30)
        return canonical_at(o,2,get(o,ARGS_AT),get(o,ARGS_N),get(o,ARGS_ARENA),get(o,ARGS_AN),get(o,row(o)+R_PROGRAM_NODE),1,28)
    if phase==28:
        if get(o,RET_STATUS)==7:
            return candidate_format_error(o,30)
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        return norm_start(o,get(o,CURRENT),1,get(o,RET_AT),get(o,RET_N),30)
    if phase==30:
        put(o,CURRENT,get(o,CURRENT)+1)
        put(o,PHASE,21)
        return 3
    return terminal(o,4)

def candidate_json_error(o:mutbuf,at:u64,n:u64,next:u64) -> u32:
    put(o,ERROR_AT,at)
    put(o,ERROR_N,n)
    put(o,ERROR_RETURN,next)
    return decode_at(o,1,at,n,130)

def candidate_format_error(o:mutbuf,next:u64) -> u32:
    n=literal(o,61000,9)
    frame_begin(o,0)
    frame_part(o,3,61000,n)
    put(o,ERROR_RETURN,next)
    return frame_start(o,132)

def observed(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase=get(o,PHASE)
    if phase==50:
        return admission_call(o,w,3,0,51)
    if phase==51:
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        at=get(o,RET_AT)
        if get(o,RET_AUX)!=8192 or get(w,at)!=AD_REPLY:
            return terminal(o,4)
        if get(w,at+8)==1:
            return direct_error(o,at+1024,get(w,at+248))
        if get(w,at+8)!=0:
            return terminal(o,4)
        put(o,SUPPLIED,get(w,at+216))
        put(o,COUNT,get(w,at+80))
        i=0
        while i<=get(o,COUNT):
            r=ROWS+i*ROW_SIZE
            q=at+2048+i*96
            put(o,r+R_OBS_NODE,get(w,q))
            put(o,r+R_RUNTIME,get(w,q+8))
            put(o,r+R_UNCERTAINTY,get(w,q+16))
            put(o,r+R_SEARCH,get(w,q+24))
            put(o,r+R_OBS_DIGEST,get(w,q+32))
            i=i+1
        put(o,TOP,at)
        put(o,OBS_ITER,0)
        put(o,PHASE,52)
        return 3
    if phase==52:
        if get(o,OBS_ITER)>get(o,COUNT):
            return canonical_at(o,2,get(o,ARGS_AT),get(o,ARGS_N),get(o,ARGS_ARENA),get(o,ARGS_AN),get(o,OBS_NODE),0,55)
        r=ROWS+get(o,OBS_ITER)*ROW_SIZE
        return canonical_at(o,2,get(o,ARGS_AT),get(o,ARGS_N),get(o,ARGS_ARENA),get(o,ARGS_AN),get(o,r+R_OBS_NODE),0,53)
    if phase==53:
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        r=ROWS+get(o,OBS_ITER)*ROW_SIZE
        put(o,r+R_OBS,get(o,RET_AT))
        put(o,r+R_OBS_N,get(o,RET_N))
        put(o,OBS_ITER,get(o,OBS_ITER)+1)
        put(o,PHASE,52)
        return 3
    if phase==55:
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        put(o,OBS_AT,get(o,RET_AT))
        put(o,OBS_N,get(o,RET_N))
        put(o,CURRENT,1)
        put(o,PHASE,300)
        return 3
    return terminal(o,4)

def normalization(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase=get(o,PHASE)
    r=ROWS+get(o,NORM_KIND)*ROW_SIZE
    if phase==100:
        if get(o,NORM_N)>8388608:
            if get(o,NORM_KIND)==0:
                return literal_error(o,3,1,8)
            n=literal(o,61000,8)
            frame_begin(o,0)
            frame_part(o,3,61000,n)
            put(o,ERROR_RETURN,get(o,NORM_RETURN))
            return frame_start(o,132)
        put(o,INPUT_REGION,get(o,NORM_REGION))
        put(o,INPUT_AT,get(o,NORM_AT))
        put(o,INPUT_N,get(o,NORM_N))
        put(o,PARAM,1)
        put(o,PARAM2,get(o,NORMALIZER_FD))
        put(o,PARAM3,NONE)
        put(o,PARAM4,16777280)
        put(o,PARAM5,65536)
        put(o,PARAM6,0)
        return start_task(o,T_PROCESS,101)
    if phase==101:
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        if get(o,RET_AUX)!=0:
            if get(o,RET_AUX)!=512 and get(o,RET_AUX)!=768:
                return terminal(o,4)
            put(o,INPUT_REGION,get(o,NORM_REGION))
            put(o,INPUT_AT,get(o,NORM_AT))
            put(o,INPUT_N,get(o,NORM_N))
            put(o,PARAM,4)
            put(o,PARAM2,get(o,NORMALIZER_FD))
            put(o,PARAM3,NONE)
            put(o,PARAM4,67108864)
            put(o,PARAM5,65536)
            put(o,PARAM6,0)
            return start_task(o,T_PROCESS,110)
        at=get(o,RET_AT)
        n=get(o,RET_N)
        if n<64 or get(w,at)!=NORMAL_REPLY or get(w,at+8)>1 or get(w,at+16)!=0 or get(w,at+24)!=0 or get(w,at+48)!=0 or get(w,at+56)!=0:
            return terminal(o,4)
        jn=get(w,at+32)
        cn=get(w,at+40)
        if jn==0 or cn==0 or jn>8388608 or cn>8388608 or jn>n-64 or cn!=n-64-jn:
            return terminal(o,4)
        put(o,r+R_ORIGINAL,at+64)
        put(o,r+R_ORIGINAL_N,jn)
        put(o,r+R_CORE,at+64+jn)
        put(o,r+R_CORE_N,cn)
        put(o,r+R_VERIFIED,1)
        return hash_at(o,1,at+64,jn,102)
    if phase==102:
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        copy_control(o,r+R_INPUT_HASH,DIGEST_OUT,32)
        return hash_at(o,1,get(o,r+R_CORE),get(o,r+R_CORE_N),103)
    if phase==103:
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        copy_control(o,r+R_CORE_HASH,DIGEST_OUT,32)
        put(o,PHASE,get(o,NORM_RETURN))
        return 3
    if phase==110:
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        if get(o,RET_AUX)!=512:
            return terminal(o,4)
        return decode_at(o,1,get(o,RET_AT),get(o,RET_N),111)
    if phase==111:
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        a=get(o,RET_ARENA)
        diagnostics=field(w,a,0,2)
        first=node(w,a,diagnostics,24)
        message=field(w,a,first,1)
        if node(w,a,diagnostics,0)!=5 or node(w,a,message,0)!=4:
            return terminal(o,4)
        at=a+node(w,a,message,24)
        n=node(w,a,message,32)
        if get(o,NORM_KIND)==0:
            return message_error(o,3,1,1,at,n)
        put(o,r+R_VERIFIED,0)
        put(o,r+R_REASON,1)
        put(o,r+R_ERROR,at)
        put(o,r+R_ERROR_N,n)
        put(o,PHASE,get(o,NORM_RETURN))
        return 3
    if phase==130:
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        a=get(o,RET_ARENA)
        message=field(w,a,0,1)
        if node(w,a,message,0)!=4:
            return terminal(o,4)
        r=row(o)
        put(o,r+R_VERIFIED,0)
        put(o,r+R_REASON,1)
        put(o,r+R_ERROR,a+node(w,a,message,24))
        put(o,r+R_ERROR_N,node(w,a,message,32))
        put(o,PHASE,get(o,ERROR_RETURN))
        return 3
    if phase==132:
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        r=row(o)
        put(o,r+R_VERIFIED,0)
        put(o,r+R_REASON,1)
        put(o,r+R_ERROR,get(o,RET_AT))
        put(o,r+R_ERROR_N,get(o,RET_N))
        put(o,PHASE,get(o,ERROR_RETURN))
        return 3
    return terminal(o,4)
'''
def source_program():
 text=SOURCE+'\n'+common_source()
 text=text.replace('31082583641187169',str(int.from_bytes(b'abstain\0','little')))
 return resolve(text)
def program():return document(source_program(),'ndu_rank_prepare')
if __name__=='__main__':
 path=ROOT/'examples/hia_bootstrap/ndu_rank_prepare.hepta';path.write_text(render_assembly(program()));print(path.name,path.stat().st_size,flush=True)
