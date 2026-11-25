"""Complete proof, cost, advisory ranking and final rank decision in HIA."""
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_system_jobctl_request import document
from tools.generate_hia_ndu_rank_owner_common import C,common_source,resolve
ROOT=Path(__file__).resolve().parents[1]
C.update({
 'SEARCH_LOW':5000,'SEARCH_HIGH':5008,'OBJECTIVE_HASH':5024,'OBS_HASH':5056,'REQUEST_HASH':5088,'RESPONSE_HASH':5120,
 'REQUEST_AT':5152,'REQUEST_N':5160,'REQUEST_ARENA':5168,'REQUEST_AN':5176,'RESPONSE_AT':5184,'RESPONSE_N':5192,'RESPONSE_ARENA':5200,'RESPONSE_AN':5208,
 'IDENTITY_AT':5216,'IDENTITY_N':5224,'SELECTION_AT':5232,'SELECTION_N':5240,'SELECTED':5248,'FINAL_REASON':5256,'ADMITTED':5264,
 'NATIVE_REMAIN_SIGN':5272,'NATIVE_REMAIN_LOW':5280,'NATIVE_REMAIN_HIGH':5288,'NATIVE_INVOKED':5296,'NATIVE_REASON':5304,'NATIVE_DURATION':5312,
 'PURE_COST':53248,
 'PROOF_KIND':5400,'PROOF_RETURN':5408,'PROOF_ROW':5416,'PROOF_START':5424,'PROOF_TIMEOUT':5432,'PROOF_WALL':5440,'PROOF_JSON':5448,'PROOF_N':5456,'PROOF_ARENA':5464,'PROOF_AN':5472,'PROOF_PROVED':5480,
 'CAND_ARENA':5488,'CAND_AN':5496,'FINAL_PROOF_AT':5504,'FINAL_PROOF_N':5512,'FINAL_ADMISSION_AT':5520,'FINAL_ADMISSION_N':5528,
 'FINAL_SOLVER':5808,'FINAL_TIMEOUT':5816,'FINAL_WALL':5824,'FINAL_TARGET':5832,'ACTUAL_ADAPTER':5840,'TOTAL_LOW':5848,'TOTAL_HIGH':5856,'MARGIN_SIGN':5864,'MARGIN_LOW':5872,'MARGIN_HIGH':5880,
 'COSTS_AT':5888,'COSTS_N':5896,'REPORTS_AT':5904,'REPORTS_N':5912,'NATIVE_ADMISSION_AT':5920,'NATIVE_ADMISSION_N':5928,'FINAL_REPORT_AT':5936,'FINAL_REPORT_N':5944,
 'NATIVE_TIMEOUT_AT':5952,'NATIVE_TIMEOUT_N':5960,'NATIVE_WORK':5968,'NATIVE_WORK_N':5976,'NATIVE_OUTPUT':5984,'NULL_AT':6000,'NULL_N':6008,'NATIVE_FRAME_AT':6016,
 'FINAL_COST':6144,'NATIVE_PATH_AT':6032,'NATIVE_PATH_N':6040,'ERROR_FRAME_AT':6048,'ERROR_FRAME_N':6056,'ERROR_REQUIRED':6064,'NATIVE_IDENTITY_SOURCE':6072,'FINAL_PROOF_ARENA':6080,'FINAL_PROOF_AN':6088,'PROOF_TEMP':6096,
 'T_FD_READ':8,'NATIVE_ERROR_ROLE':19,'NATIVE_ERROR_REQUEST':int.from_bytes(b'HIANER01','little'),
 'R_NATIVE_COST':616,'R_NATIVE_UNCERTAINTY':624,'R_NATIVE_RESOURCE':632,'R_PROOF_ARENA':648,'R_PROOF_AN':656,
 'UNCHANGED_REQUEST':int.from_bytes(b'HIANUC01','little'),'UNCHANGED_REPLY':int.from_bytes(b'HIANUR01','little'),
 'BINDING_REQUEST':int.from_bytes(b'HIANBD01','little'),'BINDING_REPLY':int.from_bytes(b'HIANBDR1','little'),
 'PROOF_REQUEST':int.from_bytes(b'HIAPPR01','little'),'PROOF_REPLY':int.from_bytes(b'HIAMVR01','little'),
 'BUDGET_REQUEST':int.from_bytes(b'HIANRB01','little'),'BUDGET_REPLY':int.from_bytes(b'HIANBR01','little'),
 'NATIVE_REQUEST':int.from_bytes(b'HIANBO01','little'),'NATIVE_REPLY':int.from_bytes(b'HIANOR01','little'),
 'SELECTION_REQUEST':int.from_bytes(b'HIANSQ01','little'),'SELECTION_REPLY':int.from_bytes(b'HIANSR01','little')
})
SOURCE=r'''
def rank_decide(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase=get(o,PHASE)
    if phase>=9000:
        return error_steps(s,o,w)
    if phase<400:
        return candidate_proofs(s,o,w)
    if phase<450:
        return fresh_proof(s,o,w)
    if phase<600:
        return ranking_rows(s,o,w)
    if phase<700:
        return native_advice(s,o,w)
    if phase<800:
        return final_gate(s,o,w)
    return final_report(s,o,w)

def cost_frame(o:mutbuf,mode:u64,index:u64,elapsed:u64,next:u64) -> u32:
    frame_begin(o,128)
    put(o,FRAME_HEADER,COST_REQUEST)
    put(o,FRAME_HEADER+8,mode)
    put(o,FRAME_HEADER+16,get(o,ROWS+R_RUNTIME))
    put(o,FRAME_HEADER+24,get(o,ROWS+R_UNCERTAINTY))
    put(o,FRAME_HEADER+32,get(o,ROWS+index*ROW_SIZE+R_RUNTIME))
    put(o,FRAME_HEADER+40,get(o,ROWS+index*ROW_SIZE+R_UNCERTAINTY))
    put(o,FRAME_HEADER+48,get(o,CALLS))
    put(o,FRAME_HEADER+56,get(o,SUPPLIED))
    put(o,FRAME_HEADER+64,elapsed)
    put(o,FRAME_HEADER+72,get(o,CAP))
    put(o,FRAME_HEADER+80,get(o,TIMEOUT))
    return frame_start(o,next)

def cost_call(o:mutbuf,next:u64) -> u32:
    if get(o,RET_STATUS)!=0:
        return task_failure(o)
    put(o,TEMP,get(o,RET_AT))
    return call_role(o,COST_ROLE,1,get(o,RET_AT),get(o,RET_N),256,256,next)

def cost_result(o:mutbuf,w:mutbuf) -> bool:
    if get(o,RET_STATUS)!=0 or get(o,RET_AUX)!=0 or get(w,get(o,RET_AT))!=COST_REPLY:
        return False
    copy_work_control(o,PURE_COST,w,get(o,RET_AT),256)
    put(o,TOP,get(o,TEMP))
    return True

def measured_digest(o:mutbuf,w:mutbuf,index:u64) -> bool:
    r=ROWS+index*ROW_SIZE
    a=get(o,ARGS_ARENA)
    id=get(o,r+R_OBS_DIGEST)
    at=a+node(w,a,id,24)
    i=0
    while i<32:
        value=byte(o,r+R_CORE_HASH+i)
        high=value>>4
        low=value&15
        if byte(w,at+i*2)!=hex_digit(high) or byte(w,at+i*2+1)!=hex_digit(low):
            return False
        i=i+1
    return True

def hex_digit(value:u64) -> u64:
    if value<10:
        return value+48
    return value+87

def candidate_proofs(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase=get(o,PHASE)
    if phase==300:
        at=get(o,TOP)
        if needed(o,w,at+8)==False:
            if get(o,ALLOC_FAILED)!=0:
                return terminal(o,3)
            return 2
        put(w,at,1819047278)
        put(o,NULL_AT,at)
        put(o,NULL_N,4)
        put(o,TOP,at+8)
        put(o,CURRENT,1)
        put(o,PHASE,301)
        return 3
    if phase==301:
        if get(o,CURRENT)>get(o,COUNT):
            return clock(o,390)
        r=row(o)
        if get(o,r+R_VERIFIED)==0:
            put(o,CURRENT,get(o,CURRENT)+1)
            return 3
        if measured_digest(o,w,get(o,CURRENT))==False:
            n=literal(o,61000,14)
            frame_begin(o,0)
            frame_part(o,3,61000,n)
            frame_part(o,1,get(o,r+R_ID),get(o,r+R_ID_N))
            return frame_start(o,302)
        put(o,PROOF_TEMP,get(o,TOP))
        return decode_at(o,1,get(o,r+R_CORE),get(o,r+R_CORE_N),303)
    if phase==302:
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        return message_error(o,4,1,1,get(o,RET_AT),get(o,RET_N))
    if phase==303:
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        put(o,CAND_ARENA,get(o,RET_ARENA))
        put(o,CAND_AN,get(o,RET_ARENA_N))
        r=row(o)
        frame_begin(o,128)
        put(o,FRAME_HEADER,UNCHANGED_REQUEST)
        put(o,FRAME_HEADER+8,get(o,FUNCTION_N))
        put(o,FRAME_HEADER+16,get(o,ROWS+R_CORE_N))
        put(o,FRAME_HEADER+24,get(o,BCORE_AN))
        put(o,FRAME_HEADER+32,get(o,r+R_CORE_N))
        put(o,FRAME_HEADER+40,get(o,CAND_AN))
        frame_part(o,3,FUNCTION_BYTES,get(o,FUNCTION_N))
        frame_part(o,1,get(o,ROWS+R_CORE),get(o,ROWS+R_CORE_N))
        frame_part(o,1,get(o,BCORE_ARENA),get(o,BCORE_AN))
        frame_part(o,1,get(o,r+R_CORE),get(o,r+R_CORE_N))
        frame_part(o,1,get(o,CAND_ARENA),get(o,CAND_AN))
        return frame_start(o,304)
    if phase==304:
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        count=get(w,get(o,BCORE_ARENA)+8)
        if get(w,get(o,CAND_ARENA)+8)>count:
            count=get(w,get(o,CAND_ARENA)+8)
        return call_role(o,UNCHANGED_ROLE,1,get(o,RET_AT),get(o,RET_N),64,131072+count,305)
    if phase==305:
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        at=get(o,RET_AT)
        if get(o,RET_AUX)!=0 or get(w,at)!=UNCHANGED_REPLY:
            return terminal(o,4)
        if get(w,at+8)==0:
            put(o,row(o)+R_REASON,2)
            put(o,TOP,get(o,PROOF_TEMP))
            put(o,CURRENT,get(o,CURRENT)+1)
            put(o,PHASE,301)
            return 3
        return clock(o,306)
    if phase==306:
        if get(o,FEEDBACK)!=0:
            return terminal(o,4)
        return cost_frame(o,1,get(o,CURRENT),now(o)-get(o,START),307)
    if phase==307:
        return cost_call(o,308)
    if phase==308:
        if cost_result(o,w)==False or get(o,PURE_COST+16)!=0:
            return terminal(o,4)
        r=row(o)
        copy_control(o,r+R_COST_REPLY,PURE_COST,256)
        put(o,r+R_HAS_COST,1)
        reason=get(o,PURE_COST+24)
        if reason!=0:
            if reason>4:
                return terminal(o,4)
            put(o,r+R_REASON,reason+2)
            put(o,TOP,get(o,PROOF_TEMP))
            put(o,CURRENT,get(o,CURRENT)+1)
            put(o,PHASE,301)
            return 3
        put(o,r+R_PROOF_STARTED,1)
        put(o,r+R_TIMEOUT,get(o,PURE_COST+32))
        put(o,PROOF_TIMEOUT,get(o,PURE_COST+32))
        put(o,PROOF_KIND,1)
        put(o,PROOF_ROW,get(o,CURRENT))
        put(o,PROOF_RETURN,310)
        put(o,PHASE,400)
        return 3
    if phase==310:
        r=row(o)
        put(o,r+R_PROOF,get(o,PROOF_TEMP))
        put(o,r+R_PROOF_N,get(o,PROOF_N))
        put(o,r+R_PROOF_ARENA,get(o,PROOF_TEMP)+get(o,PROOF_N))
        put(o,r+R_PROOF_AN,get(o,PROOF_AN))
        put(o,r+R_WALL,get(o,PROOF_WALL))
        put(o,r+R_EQ,get(o,PROOF_PROVED))
        put(o,r+R_CHECKED,get(o,PROOF_PROVED))
        put(o,r+R_REASON,8-get(o,PROOF_PROVED))
        put(o,PHASE,311)
        return move(o,1,get(o,PROOF_TEMP),1,get(o,PROOF_JSON),get(o,PROOF_N))
    if phase==311:
        put(o,PHASE,312)
        return move(o,1,get(o,PROOF_TEMP)+get(o,PROOF_N),1,get(o,PROOF_ARENA),get(o,PROOF_AN))
    if phase==312:
        put(o,TOP,get(o,PROOF_TEMP)+get(o,PROOF_N)+get(o,PROOF_AN))
        put(o,CURRENT,get(o,CURRENT)+1)
        put(o,PHASE,301)
        return 3
    if phase==390:
        if get(o,FEEDBACK)!=0:
            return terminal(o,4)
        elapsed=now(o)-get(o,START)
        low=get(o,SUPPLIED)+elapsed
        put(o,SEARCH_LOW,low)
        put(o,SEARCH_HIGH,0)
        if low<elapsed:
            put(o,SEARCH_HIGH,1)
        report_begin(o,0,2)
        copy_control(o,FRAME_HEADER+128,ROWS+R_CORE_HASH,32)
        copy_control(o,FRAME_HEADER+160,ROWS+R_INPUT_HASH,32)
        report_part(o,0,1,get(o,OBJECTIVE_AT),get(o,OBJECTIVE_N))
        report_part(o,1,3,FUNCTION_BYTES,get(o,FUNCTION_N))
        return frame_start(o,391)
    if phase==391:
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        return report_start(o,392)
    if phase==392:
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        return hash_at(o,1,get(o,RET_AT),get(o,RET_N),393)
    if phase==393:
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        copy_control(o,OBJECTIVE_HASH,DIGEST_OUT,32)
        put(o,CURRENT,0)
        put(o,PHASE,500)
        return 3
    return terminal(o,4)

def fresh_proof(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase=get(o,PHASE)
    r=ROWS+get(o,PROOF_ROW)*ROW_SIZE
    if phase==400:
        return clock(o,401)
    if phase==401:
        if get(o,FEEDBACK)!=0:
            return terminal(o,4)
        put(o,PROOF_START,now(o))
        frame_begin(o,64)
        put(o,FRAME_HEADER,PROOF_REQUEST)
        put(o,FRAME_HEADER+8,2)
        put(o,FRAME_HEADER+16,get(o,PROOF_TIMEOUT))
        put(o,FRAME_HEADER+24,get(o,FUNCTION_N))
        put(o,FRAME_HEADER+32,get(o,ROWS+R_ORIGINAL_N))
        put(o,FRAME_HEADER+40,get(o,r+R_ORIGINAL_N))
        frame_part(o,3,FUNCTION_BYTES,get(o,FUNCTION_N))
        frame_part(o,1,get(o,ROWS+R_ORIGINAL),get(o,ROWS+R_ORIGINAL_N))
        frame_part(o,1,get(o,r+R_ORIGINAL),get(o,r+R_ORIGINAL_N))
        return frame_start(o,402)
    if phase==402:
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        put(o,INPUT_REGION,1)
        put(o,INPUT_AT,get(o,RET_AT))
        put(o,INPUT_N,get(o,RET_N))
        put(o,PARAM,2)
        put(o,PARAM2,get(o,PROOF_FD))
        put(o,PARAM3,get(o,PROOF_START)+(get(o,PROOF_TIMEOUT)+60000)*1000000)
        put(o,PARAM4,67108864)
        put(o,PARAM5,65536)
        put(o,PARAM6,0)
        return start_task(o,T_PROCESS,403)
    if phase==403:
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        at=get(o,RET_AT)
        n=get(o,RET_N)
        if get(o,RET_AUX)!=0 or n<64 or get(w,at)!=PROOF_REPLY or get(w,at+8)!=2 or get(w,at+16)>3 or get(w,at+24)!=n-64 or get(w,at+40)!=0 or get(w,at+48)!=0 or get(w,at+56)!=0:
            return terminal(o,4)
        put(o,PROOF_JSON,at+64)
        put(o,PROOF_N,n-64)
        return decode_at(o,1,at+64,n-64,404)
    if phase==404:
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        put(o,PROOF_ARENA,get(o,RET_ARENA))
        put(o,PROOF_AN,get(o,RET_ARENA_N))
        frame_begin(o,256)
        put(o,FRAME_HEADER,BINDING_REQUEST)
        put(o,FRAME_HEADER+16,get(o,PROOF_N))
        put(o,FRAME_HEADER+24,get(o,PROOF_AN))
        put(o,FRAME_HEADER+56,get(o,FUNCTION_N))
        copy_control(o,FRAME_HEADER+64,ROWS+R_CORE_HASH,32)
        copy_control(o,FRAME_HEADER+96,r+R_CORE_HASH,32)
        copy_control(o,FRAME_HEADER+128,ROWS+R_INPUT_HASH,32)
        copy_control(o,FRAME_HEADER+160,r+R_INPUT_HASH,32)
        frame_part(o,3,FUNCTION_BYTES,get(o,FUNCTION_N))
        frame_part(o,1,get(o,PROOF_JSON),get(o,PROOF_N))
        frame_part(o,1,get(o,PROOF_ARENA),get(o,PROOF_AN))
        return frame_start(o,405)
    if phase==405:
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        return call_role(o,BINDING_ROLE,1,get(o,RET_AT),get(o,RET_N),1024,131072+get(w,get(o,PROOF_ARENA)+8),406)
    if phase==406:
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        at=get(o,RET_AT)
        if get(o,RET_AUX)!=0 or get(w,at)!=BINDING_REPLY or get(w,at+8)!=0 or get(w,at+16)>1:
            return terminal(o,4)
        put(o,PROOF_PROVED,get(w,at+16))
        return clock(o,407)
    if phase==407:
        if get(o,FEEDBACK)!=0:
            return terminal(o,4)
        put(o,PROOF_WALL,now(o)-get(o,PROOF_START))
        put(o,PHASE,get(o,PROOF_RETURN))
        return 3
    return terminal(o,4)

def product(o:mutbuf,at:u64,left:u64,right:u64) -> u64:
    p0=(left&4294967295)*(right&4294967295)
    p1=(left>>32)*(right&4294967295)
    p2=(left&4294967295)*(right>>32)
    high=(left>>32)*(right>>32)+(p1>>32)+(p2>>32)
    low=p0+(p1<<32)
    if low<p0:
        high=high+1
    last=low+(p2<<32)
    if last<low:
        high=high+1
    put(o,at,last)
    put(o,at+8,high)
    return 0

def q32_frame(o:mutbuf,low:u64,high:u64,next:u64) -> u32:
    frame_begin(o,128)
    put(o,FRAME_HEADER,COST_REQUEST)
    put(o,FRAME_HEADER+16,low)
    put(o,FRAME_HEADER+24,high)
    return frame_start(o,next)

def q32_error(o:mutbuf) -> u32:
    if get(o,PURE_COST+16)==1:
        return literal_error(o,4,1,11)
    if get(o,PURE_COST+16)==2:
        return literal_error(o,4,1,10)
    return terminal(o,4)

def native_row_frame(o:mutbuf) -> u32:
    r=row(o)
    report_begin(o,3,1)
    put(o,FRAME_HEADER+64,get(o,r+R_NATIVE_COST))
    put(o,FRAME_HEADER+72,get(o,r+R_NATIVE_UNCERTAINTY))
    put(o,FRAME_HEADER+80,get(o,r+R_NATIVE_RESOURCE))
    if get(o,CURRENT)!=0:
        put(o,FRAME_HEADER+88,1-get(o,r+R_EQ))
    copy_control(o,FRAME_HEADER+128,r+R_SUPPORT_HASH,32)
    report_part(o,0,1,get(o,r+R_ID),get(o,r+R_ID_N))
    return frame_start(o,560)

def ranking_rows(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase=get(o,PHASE)
    r=row(o)
    if phase==500:
        if get(o,CURRENT)>get(o,COUNT):
            put(o,PHASE,580)
            return 3
        return cost_frame(o,3,get(o,CURRENT),get(o,SEARCH_LOW)-get(o,SUPPLIED),501)
    if phase==501:
        return cost_call(o,502)
    if phase==502:
        if cost_result(o,w)==False or get(o,PURE_COST+16)!=0:
            return terminal(o,4)
        product(o,r+672,get(o,r+R_UNCERTAINTY),get(o,CALLS))
        if get(o,CURRENT)==0:
            return q32_frame(o,get(o,PURE_COST+64),get(o,PURE_COST+72),503)
        low=get(o,PURE_COST+80)+get(o,SEARCH_LOW)
        high=get(o,PURE_COST+88)+get(o,SEARCH_HIGH)
        if low<get(o,PURE_COST+80):
            high=high+1
        return q32_frame(o,low,high,503)
    if phase==503:
        return cost_call(o,504)
    if phase==504:
        if cost_result(o,w)==False:
            return terminal(o,4)
        if get(o,PURE_COST+16)!=0:
            return q32_error(o)
        put(o,r+R_NATIVE_COST,get(o,PURE_COST+40))
        return q32_frame(o,get(o,r+672),get(o,r+680),505)
    if phase==505:
        return cost_call(o,506)
    if phase==506:
        if cost_result(o,w)==False:
            return terminal(o,4)
        if get(o,PURE_COST+16)!=0:
            return q32_error(o)
        put(o,r+R_NATIVE_UNCERTAINTY,get(o,PURE_COST+40))
        if get(o,CURRENT)==0:
            put(o,r+R_NATIVE_RESOURCE,0)
            put(o,PHASE,510)
            return 3
        return q32_frame(o,get(o,SEARCH_LOW),get(o,SEARCH_HIGH),507)
    if phase==507:
        return cost_call(o,508)
    if phase==508:
        if cost_result(o,w)==False:
            return terminal(o,4)
        if get(o,PURE_COST+16)!=0:
            return q32_error(o)
        put(o,r+R_NATIVE_RESOURCE,get(o,PURE_COST+40))
        put(o,PHASE,510)
        return 3
    if phase==510:
        if get(o,CURRENT)==0:
            report_begin(o,1,1)
            copy_control(o,FRAME_HEADER+128,ROWS+R_CORE_HASH,32)
            report_part(o,0,1,get(o,ROWS+R_OBS),get(o,ROWS+R_OBS_N))
            return frame_start(o,511)
        if get(o,r+R_PROOF_N)!=0:
            return canonical_at(o,1,get(o,r+R_PROOF),get(o,r+R_PROOF_N),get(o,r+R_PROOF_ARENA),get(o,r+R_PROOF_AN),0,0,520)
        put(o,PHASE,521)
        return 3
    if phase==511:
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        return report_start(o,512)
    if phase==512:
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        return hash_at(o,1,get(o,RET_AT),get(o,RET_N),513)
    if phase==513:
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        copy_control(o,r+R_SUPPORT_HASH,DIGEST_OUT,32)
        return native_row_frame(o)
    if phase==520:
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        put(o,r+R_PROOF,get(o,RET_AT))
        put(o,r+R_PROOF_N,get(o,RET_N))
        put(o,PHASE,521)
        return 3
    if phase==521:
        report_begin(o,2,5)
        put(o,FRAME_HEADER+64,get(o,r+R_VERIFIED))
        put(o,FRAME_HEADER+72,get(o,r+R_EQ))
        put(o,FRAME_HEADER+80,get(o,r+R_REASON))
        put(o,FRAME_HEADER+88,get(o,r+R_HAS_COST))
        put(o,FRAME_HEADER+96,get(o,r+R_PROOF_STARTED))
        put(o,FRAME_HEADER+104,get(o,r+R_TIMEOUT))
        put(o,FRAME_HEADER+112,get(o,r+R_WALL))
        copy_control(o,FRAME_HEADER+384,r+R_COST_REPLY,256)
        report_part(o,0,1,get(o,r+R_ID),get(o,r+R_ID_N))
        report_part(o,1,1,get(o,r+R_ACTION),get(o,r+R_ACTION_N))
        report_part(o,2,1,get(o,r+R_OBS),get(o,r+R_OBS_N))
        if get(o,r+R_PROOF_N)!=0:
            report_part(o,3,1,get(o,r+R_PROOF),get(o,r+R_PROOF_N))
        else:
            report_part(o,3,1,get(o,NULL_AT),4)
        report_part(o,4,1,get(o,r+R_ERROR),get(o,r+R_ERROR_N))
        return frame_start(o,522)
    if phase==522:
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        return report_start(o,523)
    if phase==523:
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        put(o,r+R_REPORT,get(o,RET_AT))
        put(o,r+R_REPORT_N,get(o,RET_N))
        return capture_at(o,1,get(o,RET_AT),get(o,RET_N),525)
    if phase==525:
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        return canonical_at(o,1,get(o,r+R_REPORT),get(o,r+R_REPORT_N),get(o,RET_ARENA),get(o,RET_ARENA_N),0,1,526)
    if phase==526:
        if get(o,RET_STATUS)==7:
            return direct_error(o,get(o,RET_AT),get(o,RET_N))
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        put(o,r+R_REPORT,get(o,RET_AT))
        put(o,r+R_REPORT_N,get(o,RET_N))
        return hash_at(o,1,get(o,RET_AT),get(o,RET_N),524)
    if phase==524:
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        copy_control(o,r+R_SUPPORT_HASH,DIGEST_OUT,32)
        return native_row_frame(o)
    if phase==560:
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        return report_start(o,561)
    if phase==561:
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        put(o,r+R_NATIVE_ROW,get(o,RET_AT))
        put(o,r+R_NATIVE_ROW_N,get(o,RET_N))
        put(o,CURRENT,get(o,CURRENT)+1)
        put(o,PHASE,500)
        return 3
    if phase==580:
        report_begin(o,4,get(o,COUNT)+1)
        put(o,FRAME_HEADER+64,get(o,GENERATION))
        put(o,FRAME_HEADER+72,get(o,CAP_Q32))
        copy_control(o,FRAME_HEADER+128,OBJECTIVE_HASH,32)
        i=0
        while i<=get(o,COUNT):
            r=ROWS+i*ROW_SIZE
            report_part(o,i,1,get(o,r+R_NATIVE_ROW),get(o,r+R_NATIVE_ROW_N))
            i=i+1
        return frame_start(o,581)
    if phase==581:
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        return report_start(o,582)
    if phase==582:
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        put(o,REQUEST_AT,get(o,RET_AT))
        put(o,REQUEST_N,get(o,RET_N))
        return decode_at(o,1,get(o,RET_AT),get(o,RET_N),583)
    if phase==583:
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        put(o,REQUEST_ARENA,get(o,RET_ARENA))
        put(o,REQUEST_AN,get(o,RET_ARENA_N))
        return hash_at(o,1,get(o,REQUEST_AT),get(o,REQUEST_N),584)
    if phase==584:
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        copy_control(o,REQUEST_HASH,DIGEST_OUT,32)
        return clock(o,585)
    if phase==585:
        if get(o,FEEDBACK)!=0:
            return terminal(o,4)
        return cost_frame(o,3,0,now(o)-get(o,START),586)
    if phase==586:
        return cost_call(o,587)
    if phase==587:
        if cost_result(o,w)==False or get(o,PURE_COST+16)!=0:
            return terminal(o,4)
        put(o,NATIVE_REMAIN_SIGN,get(o,PURE_COST+96))
        put(o,NATIVE_REMAIN_LOW,get(o,PURE_COST+104))
        put(o,NATIVE_REMAIN_HIGH,get(o,PURE_COST+112))
        put(o,NATIVE_TIMEOUT_AT,get(o,NULL_AT))
        put(o,NATIVE_TIMEOUT_N,4)
        put(o,NATIVE_INVOKED,0)
        put(o,NATIVE_REASON,0)
        put(o,FINAL_REASON,0)
        put(o,SELECTED,0)
        if get(o,NATIVE_REMAIN_SIGN)!=0 or (get(o,NATIVE_REMAIN_LOW)==0 and get(o,NATIVE_REMAIN_HIGH)==0):
            put(o,PHASE,700)
            return 3
        if get(o,NATIVE_REMAIN_HIGH)!=0:
            return terminal(o,4)
        frame_begin(o,64)
        put(o,FRAME_HEADER,BUDGET_REQUEST)
        put(o,FRAME_HEADER+8,get(o,BRIDGE_BITS))
        put(o,FRAME_HEADER+16,get(o,BRIDGE_INTEGER))
        put(o,FRAME_HEADER+24,get(o,NATIVE_REMAIN_LOW))
        return frame_start(o,588)
    if phase==588:
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        return call_role(o,BUDGET_ROLE,1,get(o,RET_AT),get(o,RET_N),64,4096,589)
    if phase==589:
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        at=get(o,RET_AT)
        if get(o,RET_AUX)!=0 or get(w,at)!=BUDGET_REPLY or get(w,at+8)!=0:
            return terminal(o,4)
        put(o,NATIVE_DURATION,get(w,at+32))
        if get(w,at+24)==1:
            value=get(w,at+48)
            if value==0 or value>60:
                return terminal(o,4)
            if value>=10:
                store(w,at+48,48+value//10)
                store(w,at+49,48+value%10)
                put(o,NATIVE_TIMEOUT_N,2)
            else:
                store(w,at+48,48+value)
                put(o,NATIVE_TIMEOUT_N,1)
            put(o,NATIVE_TIMEOUT_AT,at+48)
            put(o,PHASE,600)
            return 3
        return call_role(o,FORMAT_ROLE,1,at+16,8,32,8192,590)
    if phase==590:
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        if get(o,RET_AUX)==0 or get(o,RET_AUX)>32:
            return terminal(o,4)
        put(o,NATIVE_TIMEOUT_AT,get(o,RET_AT))
        put(o,NATIVE_TIMEOUT_N,get(o,RET_AUX))
        put(o,PHASE,600)
        return 3
    return terminal(o,4)

def view_ok(w:mutbuf,base:u64,size:u64,at:u64,n:u64) -> bool:
    if base>length(w) or size>length(w)-base or at>size or n>size-at:
        return False
    return True

def native_advice(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase=get(o,PHASE)
    if phase>=650:
        return native_error(s,o,w)
    if phase==600:
        frame_begin(o,128)
        put(o,FRAME_HEADER,NATIVE_REQUEST)
        put(o,FRAME_HEADER+8,get(o,REQUEST_N))
        put(o,FRAME_HEADER+24,get(o,NATIVE_DURATION))
        frame_part(o,1,get(o,REQUEST_AT),get(o,REQUEST_N))
        a=get(o,ARGS_ARENA)
        bridge=get(o,BRIDGE_NODE)
        if bridge==NONE:
            put(o,FRAME_HEADER+16,4)
            frame_part(o,1,get(o,NULL_AT),4)
        else:
            slot=24
            if node(w,a,bridge,0)>=4:
                slot=56
            at=node(w,a,bridge,slot)
            n=node(w,a,bridge,slot+8)
            if at>get(o,ARGS_N) or n>get(o,ARGS_N)-at:
                return terminal(o,4)
            put(o,FRAME_HEADER+16,n)
            frame_part(o,2,get(o,ARGS_AT)+at,n)
        return frame_start(o,601)
    if phase==601:
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        put(o,NATIVE_FRAME_AT,get(o,RET_AT))
        action=call_role(o,NATIVE_ROLE,1,get(o,RET_AT),get(o,RET_N),128,201326592,602)
        put(o,PARAM5,1)
        return action
    if phase==602:
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        at=get(o,RET_AT)
        wb=get(o,RET_WORK)
        wn=get(o,RET_WORK_N)
        put(o,NATIVE_OUTPUT,at)
        put(o,NATIVE_WORK,wb)
        put(o,NATIVE_WORK_N,wn)
        if get(w,at)!=NATIVE_REPLY or get(w,at+8)>3:
            return terminal(o,4)
        status=get(w,at+8)
        if status==3:
            return terminal(o,2)
        if status!=0:
            if get(w,at+16)==41:
                if get(w,at+112)!=NONE:
                    return terminal(o,4)
                put(o,NATIVE_REASON,1)
                put(o,FINAL_REASON,1)
                put(o,TOP,get(o,NATIVE_FRAME_AT))
                put(o,PHASE,700)
                return 3
            put(o,PHASE,650)
            return 3
        if get(w,at+72)!=1007 or get(w,at+64)!=0 or get(w,at+112)!=NONE or get(w,at+32)>1048576 or get(w,at+40)>1048576:
            return terminal(o,4)
        if view_ok(w,wb,wn,get(w,at+80),get(w,at+32))==False or view_ok(w,wb,wn,get(w,at+96),get(w,at+48))==False:
            return terminal(o,4)
        put(o,RESPONSE_AT,get(o,NATIVE_FRAME_AT))
        put(o,RESPONSE_N,get(w,at+32))
        put(o,IDENTITY_AT,get(o,NATIVE_FRAME_AT)+get(w,at+32))
        put(o,IDENTITY_N,get(w,at+48))
        put(o,NATIVE_IDENTITY_SOURCE,wb+get(w,at+96))
        put(o,PHASE,603)
        return move(o,1,get(o,RESPONSE_AT),1,wb+get(w,at+80),get(w,at+32))
    if phase==603:
        at=get(o,NATIVE_OUTPUT)
        put(o,PHASE,604)
        return move(o,1,get(o,IDENTITY_AT),1,get(o,NATIVE_IDENTITY_SOURCE),get(o,IDENTITY_N))
    if phase==604:
        put(o,TOP,get(o,IDENTITY_AT)+get(o,IDENTITY_N))
        return decode_at(o,1,get(o,RESPONSE_AT),get(o,RESPONSE_N),605)
    if phase==605:
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        put(o,RESPONSE_ARENA,get(o,RET_ARENA))
        put(o,RESPONSE_AN,get(o,RET_ARENA_N))
        frame_begin(o,256)
        put(o,FRAME_HEADER,BINDING_REQUEST)
        put(o,FRAME_HEADER+8,1)
        put(o,FRAME_HEADER+16,get(o,REQUEST_N))
        put(o,FRAME_HEADER+24,get(o,REQUEST_AN))
        put(o,FRAME_HEADER+32,get(o,RESPONSE_N))
        put(o,FRAME_HEADER+40,get(o,RESPONSE_AN))
        put(o,FRAME_HEADER+48,get(o,GENERATION))
        copy_control(o,FRAME_HEADER+64,REQUEST_HASH,32)
        frame_part(o,1,get(o,REQUEST_AT),get(o,REQUEST_N))
        frame_part(o,1,get(o,REQUEST_ARENA),get(o,REQUEST_AN))
        frame_part(o,1,get(o,RESPONSE_AT),get(o,RESPONSE_N))
        frame_part(o,1,get(o,RESPONSE_ARENA),get(o,RESPONSE_AN))
        return frame_start(o,606)
    if phase==606:
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        count=get(w,get(o,REQUEST_ARENA)+8)
        if get(w,get(o,RESPONSE_ARENA)+8)>count:
            count=get(w,get(o,RESPONSE_ARENA)+8)
        return call_role(o,BINDING_ROLE,1,get(o,RET_AT),get(o,RET_N),1024,131072+count,607)
    if phase==607:
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        at=get(o,RET_AT)
        if get(o,RET_AUX)!=0 or get(w,at)!=BINDING_REPLY:
            return terminal(o,4)
        if get(w,at+8)!=0:
            return direct_error(o,at+128,get(w,at+32))
        if get(w,at+16)!=1:
            return terminal(o,4)
        put(o,NATIVE_INVOKED,1)
        put(o,NATIVE_REASON,2)
        return canonical_at(o,1,get(o,RESPONSE_AT),get(o,RESPONSE_N),get(o,RESPONSE_ARENA),get(o,RESPONSE_AN),0,0,608)
    if phase==608:
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        put(o,RESPONSE_AT,get(o,RET_AT))
        put(o,RESPONSE_N,get(o,RET_N))
        return hash_at(o,1,get(o,RET_AT),get(o,RET_N),609)
    if phase==609:
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        copy_control(o,RESPONSE_HASH,DIGEST_OUT,32)
        return decode_at(o,1,get(o,RESPONSE_AT),get(o,RESPONSE_N),610)
    if phase==610:
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        put(o,RESPONSE_ARENA,get(o,RET_ARENA))
        put(o,RESPONSE_AN,get(o,RET_ARENA_N))
        frame_begin(o,128)
        put(o,FRAME_HEADER,SELECTION_REQUEST)
        put(o,FRAME_HEADER+8,get(o,REQUEST_N))
        put(o,FRAME_HEADER+16,get(o,REQUEST_AN))
        put(o,FRAME_HEADER+24,get(o,RESPONSE_N))
        put(o,FRAME_HEADER+32,get(o,RESPONSE_AN))
        copy_control(o,FRAME_HEADER+64,REQUEST_HASH,32)
        copy_control(o,FRAME_HEADER+96,RESPONSE_HASH,32)
        frame_part(o,1,get(o,REQUEST_AT),get(o,REQUEST_N))
        frame_part(o,1,get(o,REQUEST_ARENA),get(o,REQUEST_AN))
        frame_part(o,1,get(o,RESPONSE_AT),get(o,RESPONSE_N))
        frame_part(o,1,get(o,RESPONSE_ARENA),get(o,RESPONSE_AN))
        return frame_start(o,611)
    if phase==611:
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        return call_role(o,SELECTION_ROLE,1,get(o,RET_AT),get(o,RET_N),32832,8388608,612)
    if phase==612:
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        at=get(o,RET_AT)
        if get(w,at)!=SELECTION_REPLY or get(w,at+16)>32768 or get(o,RET_AUX)!=64+get(w,at+16):
            return terminal(o,4)
        if get(w,at+8)!=0:
            return decode_at(o,1,at+64,get(w,at+16),620)
        selected=get(w,at+24)
        if selected>get(o,COUNT):
            return terminal(o,4)
        put(o,SELECTION_AT,at+64)
        put(o,SELECTION_N,get(w,at+16))
        put(o,SELECTED,selected)
        put(o,FINAL_REASON,3)
        if selected==0 and get(w,at+48)==3:
            put(o,FINAL_REASON,2)
        put(o,PHASE,700)
        return 3
    if phase==620:
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        a=get(o,RET_ARENA)
        message=field(w,a,0,1)
        if node(w,a,message,0)!=4:
            return terminal(o,4)
        n=literal(o,61000,15)
        frame_begin(o,0)
        frame_part(o,3,61000,n)
        frame_part(o,1,a+node(w,a,message,24),node(w,a,message,32))
        return frame_start(o,621)
    if phase==621:
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        return message_error(o,4,1,1,get(o,RET_AT),get(o,RET_N))
    return terminal(o,4)

def native_error(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase=get(o,PHASE)
    at=get(o,NATIVE_OUTPUT)
    wb=get(o,NATIVE_WORK)
    wn=get(o,NATIVE_WORK_N)
    if phase==650:
        fd=get(w,at+112)
        put(o,NATIVE_PATH_AT,get(o,NULL_AT))
        put(o,NATIVE_PATH_N,0)
        if fd!=NONE:
            if fd<3 or fd>2147483647:
                return terminal(o,4)
            put(o,PARAM,fd)
            put(o,PARAM2,get(w,at+120))
            return start_task(o,T_FD_READ,651)
        put(o,PHASE,652)
        return 3
    if phase==651:
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        put(o,NATIVE_PATH_AT,get(o,RET_AT))
        put(o,NATIVE_PATH_N,get(o,RET_N))
        put(o,PHASE,652)
        return 3
    if phase==652:
        if view_ok(w,wb,wn,2048,160)==False:
            return terminal(o,4)
        no=get(w,wb+2176)
        nn=get(w,wb+2184)
        ro=get(w,wb+2192)
        rn=get(w,wb+2200)
        if view_ok(w,wb,wn,no,nn)==False or view_ok(w,wb,wn,ro,rn)==False:
            return terminal(o,4)
        frame_begin(o,128)
        put(o,FRAME_HEADER,NATIVE_ERROR_REQUEST)
        put(o,FRAME_HEADER+8,get(w,at+16))
        put(o,FRAME_HEADER+16,get(w,at+24))
        put(o,FRAME_HEADER+24,get(w,at+104))
        put(o,FRAME_HEADER+32,get(o,NATIVE_PATH_N))
        put(o,FRAME_HEADER+40,128)
        put(o,FRAME_HEADER+48,nn)
        put(o,FRAME_HEADER+56,rn)
        frame_part(o,1,get(o,NATIVE_PATH_AT),get(o,NATIVE_PATH_N))
        frame_part(o,1,wb+2048,128)
        frame_part(o,1,wb+no,nn)
        frame_part(o,1,wb+ro,rn)
        return frame_start(o,653)
    if phase==653:
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        put(o,ERROR_FRAME_AT,get(o,RET_AT))
        put(o,ERROR_FRAME_N,get(o,RET_N))
        return call_role(o,NATIVE_ERROR_ROLE,1,get(o,RET_AT),get(o,RET_N),0,32768,654)
    if phase==654:
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        if get(o,RET_AUX)!=18446744073709551614:
            return terminal(o,4)
        n=get(w,get(o,RET_WORK))
        if n==0:
            return terminal(o,4)
        put(o,ERROR_REQUIRED,n)
        return call_role(o,NATIVE_ERROR_ROLE,1,get(o,ERROR_FRAME_AT),get(o,ERROR_FRAME_N),n,32768,655)
    if phase==655:
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        if get(o,RET_AUX)!=get(o,ERROR_REQUIRED):
            return terminal(o,4)
        return direct_error(o,get(o,RET_AT),get(o,ERROR_REQUIRED))
    return terminal(o,4)

def final_gate(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase=get(o,PHASE)
    if phase==700:
        if get(o,SELECTED)==0:
            return clock(o,720)
        if get(o,SELECTED)>get(o,COUNT) or get(o,ROWS+get(o,SELECTED)*ROW_SIZE+R_CHECKED)!=1:
            return literal_error(o,4,1,13)
        return clock(o,701)
    if phase==701:
        if get(o,FEEDBACK)!=0:
            return terminal(o,4)
        put(o,FINAL_TARGET,get(o,SELECTED))
        put(o,FINAL_SOLVER,0)
        put(o,FINAL_TIMEOUT,0)
        put(o,FINAL_WALL,0)
        return cost_frame(o,2,get(o,SELECTED),now(o)-get(o,START),702)
    if phase==702:
        return cost_call(o,703)
    if phase==703:
        if cost_result(o,w)==False or get(o,PURE_COST+16)!=0:
            return terminal(o,4)
        copy_control(o,FINAL_COST,PURE_COST,256)
        reason=get(o,PURE_COST+24)
        if reason!=0:
            if reason<5 or reason>8:
                return terminal(o,4)
            put(o,SELECTED,0)
            put(o,FINAL_REASON,reason-1)
            return clock(o,720)
        put(o,FINAL_SOLVER,1)
        put(o,FINAL_TIMEOUT,get(o,PURE_COST+32))
        put(o,PROOF_TIMEOUT,get(o,PURE_COST+32))
        put(o,PROOF_KIND,2)
        put(o,PROOF_ROW,get(o,SELECTED))
        put(o,PROOF_RETURN,710)
        put(o,PHASE,400)
        return 3
    if phase==710:
        put(o,FINAL_PROOF_AT,get(o,PROOF_JSON))
        put(o,FINAL_PROOF_N,get(o,PROOF_N))
        put(o,FINAL_PROOF_ARENA,get(o,PROOF_ARENA))
        put(o,FINAL_PROOF_AN,get(o,PROOF_AN))
        put(o,FINAL_WALL,get(o,PROOF_WALL))
        if get(o,PROOF_PROVED)==0:
            put(o,SELECTED,0)
            put(o,FINAL_REASON,8)
        return clock(o,720)
    if phase==720:
        if get(o,FEEDBACK)!=0:
            return terminal(o,4)
        put(o,ACTUAL_ADAPTER,now(o)-get(o,START))
        return cost_frame(o,3,get(o,SELECTED),get(o,ACTUAL_ADAPTER),721)
    if phase==721:
        return cost_call(o,722)
    if phase==722:
        if cost_result(o,w)==False or get(o,PURE_COST+16)!=0:
            return terminal(o,4)
        put(o,TOTAL_LOW,get(o,PURE_COST+48))
        put(o,TOTAL_HIGH,get(o,PURE_COST+56))
        put(o,MARGIN_SIGN,get(o,PURE_COST+120))
        put(o,MARGIN_LOW,get(o,PURE_COST+128))
        put(o,MARGIN_HIGH,get(o,PURE_COST+136))
        put(o,ADMITTED,0)
        if get(o,SELECTED)!=0:
            reason=get(o,PURE_COST+24)
            if reason==5 or reason==6:
                put(o,SELECTED,0)
                put(o,FINAL_REASON,reason-1)
            elif reason==0:
                if get(o,MARGIN_SIGN)!=0 or (get(o,MARGIN_LOW)==0 and get(o,MARGIN_HIGH)==0):
                    return terminal(o,4)
                put(o,ADMITTED,1)
                put(o,FINAL_REASON,9)
            else:
                return terminal(o,4)
        put(o,PHASE,800)
        return 3
    return terminal(o,4)

def final_report(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase=get(o,PHASE)
    if phase==800:
        report_begin(o,7,0)
        put(o,FRAME_HEADER+64,get(o,SUPPLIED))
        put(o,FRAME_HEADER+72,get(o,ACTUAL_ADAPTER))
        put(o,FRAME_HEADER+80,get(o,TOTAL_LOW))
        put(o,FRAME_HEADER+88,get(o,TOTAL_HIGH))
        put(o,FRAME_HEADER+96,get(o,SEARCH_LOW))
        put(o,FRAME_HEADER+104,get(o,SEARCH_HIGH))
        return frame_start(o,801)
    if phase==801:
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        return report_start(o,802)
    if phase==802:
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        put(o,COSTS_AT,get(o,RET_AT))
        put(o,COSTS_N,get(o,RET_N))
        report_begin(o,5,1)
        put(o,FRAME_HEADER+64,get(o,NATIVE_INVOKED))
        put(o,FRAME_HEADER+72,get(o,NATIVE_REASON))
        put(o,FRAME_HEADER+320,get(o,NATIVE_REMAIN_SIGN))
        put(o,FRAME_HEADER+328,get(o,NATIVE_REMAIN_LOW))
        put(o,FRAME_HEADER+336,get(o,NATIVE_REMAIN_HIGH))
        report_part(o,0,1,get(o,NATIVE_TIMEOUT_AT),get(o,NATIVE_TIMEOUT_N))
        return frame_start(o,803)
    if phase==803:
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        return report_start(o,804)
    if phase==804:
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        put(o,NATIVE_ADMISSION_AT,get(o,RET_AT))
        put(o,NATIVE_ADMISSION_N,get(o,RET_N))
        if get(o,FINAL_TARGET)==0:
            put(o,PHASE,810)
            return 3
        r=ROWS+get(o,FINAL_TARGET)*ROW_SIZE
        report_begin(o,6,1)
        put(o,FRAME_HEADER+64,get(o,FINAL_SOLVER))
        put(o,FRAME_HEADER+72,get(o,FINAL_TIMEOUT))
        put(o,FRAME_HEADER+80,get(o,FINAL_WALL))
        copy_control(o,FRAME_HEADER+384,FINAL_COST,256)
        report_part(o,0,1,get(o,r+R_ID),get(o,r+R_ID_N))
        return frame_start(o,805)
    if phase==805:
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        return report_start(o,806)
    if phase==806:
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        put(o,FINAL_ADMISSION_AT,get(o,RET_AT))
        put(o,FINAL_ADMISSION_N,get(o,RET_N))
        put(o,PHASE,810)
        return 3
    if phase==810:
        report_begin(o,9,get(o,COUNT))
        i=0
        while i<get(o,COUNT):
            r=ROWS+(i+1)*ROW_SIZE
            report_part(o,i,1,get(o,r+R_REPORT),get(o,r+R_REPORT_N))
            i=i+1
        return frame_start(o,811)
    if phase==811:
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        return report_start(o,812)
    if phase==812:
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        put(o,REPORTS_AT,get(o,RET_AT))
        put(o,REPORTS_N,get(o,RET_N))
        if get(o,FINAL_PROOF_N)==0:
            put(o,PHASE,820)
            return 3
        return canonical_at(o,1,get(o,FINAL_PROOF_AT),get(o,FINAL_PROOF_N),get(o,FINAL_PROOF_ARENA),get(o,FINAL_PROOF_AN),0,0,813)
    if phase==813:
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        put(o,FINAL_PROOF_AT,get(o,RET_AT))
        put(o,FINAL_PROOF_N,get(o,RET_N))
        put(o,PHASE,820)
        return 3
    if phase==820:
        if get(o,IDENTITY_N)==0:
            return hash_at(o,1,get(o,OBS_AT),get(o,OBS_N),830)
        return decode_at(o,1,get(o,IDENTITY_AT),get(o,IDENTITY_N),821)
    if phase==821:
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        return canonical_at(o,1,get(o,IDENTITY_AT),get(o,IDENTITY_N),get(o,RET_ARENA),get(o,RET_ARENA_N),0,0,822)
    if phase==822:
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        put(o,IDENTITY_AT,get(o,RET_AT))
        put(o,IDENTITY_N,get(o,RET_N))
        return hash_at(o,1,get(o,OBS_AT),get(o,OBS_N),830)
    if phase==830:
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        copy_control(o,OBS_HASH,DIGEST_OUT,32)
        r=ROWS+get(o,SELECTED)*ROW_SIZE
        report_begin(o,8,13)
        put(o,FRAME_HEADER+64,get(o,GENERATION))
        put(o,FRAME_HEADER+72,get(o,ADMITTED))
        put(o,FRAME_HEADER+80,get(o,FINAL_REASON))
        copy_control(o,FRAME_HEADER+128,ROWS+R_CORE_HASH,32)
        copy_control(o,FRAME_HEADER+160,ROWS+R_INPUT_HASH,32)
        copy_control(o,FRAME_HEADER+192,OBJECTIVE_HASH,32)
        copy_control(o,FRAME_HEADER+224,OBS_HASH,32)
        copy_control(o,FRAME_HEADER+256,REQUEST_HASH,32)
        put(o,FRAME_HEADER+320,get(o,MARGIN_LOW))
        put(o,FRAME_HEADER+328,get(o,MARGIN_HIGH))
        report_part(o,0,3,FUNCTION_BYTES,get(o,FUNCTION_N))
        report_part(o,1,1,get(o,OBJECTIVE_AT),get(o,OBJECTIVE_N))
        report_part(o,2,1,get(o,r+R_ID),get(o,r+R_ID_N))
        report_part(o,3,1,get(o,r+R_CORE),get(o,r+R_CORE_N))
        report_part(o,4,1,get(o,COSTS_AT),get(o,COSTS_N))
        report_part(o,5,1,get(o,REPORTS_AT),get(o,REPORTS_N))
        optional_part(o,6,get(o,FINAL_PROOF_AT),get(o,FINAL_PROOF_N))
        optional_part(o,7,get(o,FINAL_ADMISSION_AT),get(o,FINAL_ADMISSION_N))
        report_part(o,8,1,get(o,NATIVE_ADMISSION_AT),get(o,NATIVE_ADMISSION_N))
        report_part(o,9,1,get(o,REQUEST_AT),get(o,REQUEST_N))
        optional_part(o,10,get(o,RESPONSE_AT),get(o,RESPONSE_N))
        optional_part(o,11,get(o,IDENTITY_AT),get(o,IDENTITY_N))
        optional_part(o,12,get(o,SELECTION_AT),get(o,SELECTION_N))
        return frame_start(o,831)
    if phase==831:
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        return report_start(o,832)
    if phase==832:
        if get(o,RET_STATUS)!=0:
            return task_failure(o)
        put(o,RESULT_STATUS,0)
        put(o,RESULT_KIND,1)
        put(o,RESULT_AT,get(o,RET_AT))
        put(o,RESULT_N,get(o,RET_N))
        put(o,PHASE,9990)
        return 3
    return terminal(o,4)

def optional_part(o:mutbuf,index:u64,at:u64,n:u64) -> u64:
    if n==0:
        return report_part(o,index,1,get(o,NULL_AT),4)
    return report_part(o,index,1,at,n)
'''
def source_program():return resolve(SOURCE+'\n'+common_source())
def program():return document(source_program(),'ndu_rank_decide')
if __name__=='__main__':
 path=ROOT/'examples/hia_bootstrap/ndu_rank_decide.hepta';path.write_text(render_assembly(program()));print(path.name,path.stat().st_size,flush=True)
