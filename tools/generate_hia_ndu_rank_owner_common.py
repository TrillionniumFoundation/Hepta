"""Shared private rank owner control layout and HIA frame helpers."""
import ast,re,json
from tools.generate_hia_ndu_rank_tasks import CONSTANTS as TASK_CONSTANTS,SOURCE as TASK_SOURCE
C=dict(TASK_CONSTANTS)
C.update({
 'RESULT_STATUS':4000,'RESULT_KIND':4008,'RESULT_AT':4016,'RESULT_N':4024,'RESULT_ELAPSED':4032,
 'START':4096,'ARGS_N':4104,'ARGS_AT':4112,'ARGS_ARENA':4120,'ARGS_AN':4128,'BCORE_ARENA':4136,'BCORE_AN':4144,
 'AD_FRAME':4152,'AD_N':4160,'AD_ACTION':4168,'AD_BITS':4176,'AD_INVALID':4184,
 'GENERATION':4192,'TIMEOUT':4200,'BRIDGE_BITS':4208,'BRIDGE_INTEGER':4216,'CALLS':4224,'CAP':4232,'CAP_Q32':4240,'COUNT':4248,'CURRENT':4256,
 'OBJECTIVE_NODE':4264,'BRIDGE_NODE':4272,'CANDIDATES_NODE':4280,'OBS_NODE':4288,'OBJECTIVE_AT':4296,'OBJECTIVE_N':4304,'OBS_AT':4312,'OBS_N':4320,'SUPPLIED':4328,
 'NORM_KIND':4336,'NORM_RETURN':4344,'NORM_REGION':4352,'NORM_AT':4360,'NORM_N':4368,'NORM_FRAME':4376,'NORM_RAWN':4384,'NORM_WAIT':4392,
 'ERROR_AT':4400,'ERROR_N':4408,'ERROR_RETURN':4416,'STRUCT_FRAME':4424,'STRUCT_N':4432,'TEMP':4440,'CAN_TEMP':4448,'FUNCTION_N':4456,'OLD_TOP':4464,'OBS_ITER':4472,
 'FUNCTION_BYTES':53760,'REPORT_TABLE':56864,'REPORT_CURSOR':56848,
 'ERROR_TYPE_N':6504,'ERROR_REGION':6512,'ERROR_MESSAGE_AT':6520,'ERROR_MESSAGE_N':6528,'ERROR_STATUS':6536,
 'ROWS':8192,'ROW_SIZE':1024,
 'R_ID':0,'R_ID_N':8,'R_ACTION':16,'R_ACTION_N':24,'R_PROGRAM_NODE':32,
 'R_ORIGINAL':40,'R_ORIGINAL_N':48,'R_CORE':56,'R_CORE_N':64,'R_VERIFIED':72,'R_INPUT_HASH':80,'R_CORE_HASH':112,
 'R_OBS_NODE':144,'R_OBS':152,'R_OBS_N':160,'R_RUNTIME':168,'R_UNCERTAINTY':176,'R_SEARCH':184,'R_OBS_DIGEST':192,
 'R_PROOF':200,'R_PROOF_N':208,'R_REPORT':216,'R_REPORT_N':224,'R_REASON':232,'R_EQ':240,'R_HAS_COST':248,'R_PROOF_STARTED':256,'R_TIMEOUT':264,'R_WALL':272,'R_COST_REPLY':288,
 'R_ERROR':544,'R_ERROR_N':552,'R_CHECKED':560,'R_SUPPORT_HASH':568,'R_NATIVE_ROW':600,'R_NATIVE_ROW_N':608,
 'RANK_REQUEST':int.from_bytes(b'HIANRK01','little'),'NORMAL_REPLY':int.from_bytes(b'HIAVCF01','little'),'AD_REQUEST':int.from_bytes(b'HIANRA01','little'),'AD_REPLY':int.from_bytes(b'HIANDR01','little'),
 'SNAP_REQUEST':int.from_bytes(b'HIANVS01','little'),'SNAP_REPLY':int.from_bytes(b'HIANVR01','little'),'STRUCT_REQUEST':int.from_bytes(b'HIABST01','little'),'STRUCT_REPLY':int.from_bytes(b'HIABSR01','little'),
 'COST_REQUEST':int.from_bytes(b'HIANRC01','little'),'COST_REPLY':int.from_bytes(b'HIANRR01','little'),'REPORT_REQUEST':int.from_bytes(b'HIANRP01','little')
})
LITERALS={
1:'abstain',2:'null',3:'HIAProgramRejected',4:'OptimizationRejected',5:'MemoryError',6:'RuntimeError',7:'KeyboardInterrupt',
8:'E_HIA_LIMIT: program exceeds byte budget',9:'E_HIA_FORMAT: invalid/deep UTF-8 JSON',
10:'E_HIA_NDU: cost exceeds the Q32.32 millisecond range',11:'E_HIA_NDU: nanoseconds must be a bounded exact integer',
12:'native rank internal operation failed',13:'E_HIA_NDU: advisory result has no independently proved program',
14:'E_HIA_NDU: candidate measurement belongs to a different program: ',
15:'E_HIA_NDU: ',16:'ScalarSelectionRejected'
}
HELPERS=r'''
def start_task(o:mutbuf,task:u64,next:u64) -> u32:
    put(o,TASK,task)
    put(o,STEP,0)
    put(o,RESUME,next)
    put(o,BASE,get(o,TOP))
    put(o,RET_STATUS,NONE)
    return 3

def task_failure(o:mutbuf) -> u32:
    status=get(o,RET_STATUS)
    if status==3:
        return terminal(o,3)
    if status==5:
        return terminal(o,2)
    return terminal(o,4)

def terminal(o:mutbuf,status:u64) -> u32:
    put(o,RESULT_STATUS,status)
    put(o,RESULT_KIND,2)
    put(o,RESULT_AT,0)
    put(o,RESULT_N,0)
    put(o,PHASE,9990)
    return 3

def direct_error(o:mutbuf,at:u64,n:u64) -> u32:
    put(o,RESULT_STATUS,1)
    put(o,RESULT_KIND,2)
    put(o,RESULT_AT,at)
    put(o,RESULT_N,n)
    put(o,PHASE,9990)
    return 3

def message_error(o:mutbuf,type:u64,status:u64,region:u64,at:u64,n:u64) -> u32:
    put(o,ERROR_TYPE_N,literal(o,60000,type))
    put(o,ERROR_REGION,region)
    put(o,ERROR_MESSAGE_AT,at)
    put(o,ERROR_MESSAGE_N,n)
    put(o,ERROR_STATUS,status)
    put(o,PHASE,9000)
    return 3

def literal_error(o:mutbuf,type:u64,status:u64,message:u64) -> u32:
    n=literal(o,61000,message)
    return message_error(o,type,status,3,61000,n)

def frame_begin(o:mutbuf,n:u64) -> u64:
    zero(o,FRAME_HEADER,768)
    put(o,FRAME_HEADER_N,n)
    put(o,FRAME_COUNT,0)
    return 0

def frame_part(o:mutbuf,region:u64,at:u64,n:u64) -> u64:
    count=get(o,FRAME_COUNT)
    if count>=64:
        put(o,FRAME_COUNT,65)
        return 0
    put(o,FRAME_PARTS+24*count,region)
    put(o,FRAME_PARTS+24*count+8,at)
    put(o,FRAME_PARTS+24*count+16,n)
    put(o,FRAME_COUNT,count+1)
    return 0

def frame_start(o:mutbuf,next:u64) -> u32:
    return start_task(o,T_ASSEMBLE,next)

def report_begin(o:mutbuf,action:u64,count:u64) -> u64:
    frame_begin(o,768)
    put(o,FRAME_HEADER,REPORT_REQUEST)
    put(o,FRAME_HEADER+8,action)
    put(o,FRAME_HEADER+24,count)
    put(o,REPORT_CURSOR,768+count*16)
    frame_part(o,3,REPORT_TABLE,count*16)
    return 0

def report_part(o:mutbuf,index:u64,region:u64,at:u64,n:u64) -> u64:
    put(o,REPORT_TABLE+index*16,get(o,REPORT_CURSOR))
    put(o,REPORT_TABLE+index*16+8,n)
    put(o,REPORT_CURSOR,get(o,REPORT_CURSOR)+n)
    frame_part(o,region,at,n)
    return 0

def report_start(o:mutbuf,next:u64) -> u32:
    put(o,INPUT_REGION,1)
    put(o,INPUT_AT,get(o,RET_AT))
    put(o,INPUT_N,get(o,RET_N))
    put(o,TOP,get(o,RET_AT))
    return start_task(o,T_REPORT,next)

def call_role(o:mutbuf,role:u64,region:u64,at:u64,n:u64,on:u64,wn:u64,next:u64) -> u32:
    put(o,INPUT_REGION,region)
    put(o,INPUT_AT,at)
    put(o,INPUT_N,n)
    put(o,PARAM,role)
    put(o,PARAM2,wn)
    put(o,PARAM3,on)
    put(o,PARAM5,0)
    return start_task(o,T_CALL,next)

def decode_at(o:mutbuf,region:u64,at:u64,n:u64,next:u64) -> u32:
    put(o,INPUT_REGION,region)
    put(o,INPUT_AT,at)
    put(o,INPUT_N,n)
    put(o,PARAM,0)
    return start_task(o,T_DECODE,next)

def capture_at(o:mutbuf,region:u64,at:u64,n:u64,next:u64) -> u32:
    put(o,INPUT_REGION,region)
    put(o,INPUT_AT,at)
    put(o,INPUT_N,n)
    put(o,PARAM,1)
    return start_task(o,T_DECODE,next)

def canonical_at(o:mutbuf,region:u64,at:u64,n:u64,aa:u64,an:u64,root:u64,checked:u64,next:u64) -> u32:
    put(o,INPUT_REGION,region)
    put(o,INPUT_AT,at)
    put(o,INPUT_N,n)
    put(o,ARENA_AT,aa)
    put(o,ARENA_N,an)
    put(o,ROOT_NODE,root)
    put(o,PARAM,checked)
    return start_task(o,T_CANONICAL,next)

def hash_at(o:mutbuf,region:u64,at:u64,n:u64,next:u64) -> u32:
    put(o,INPUT_REGION,region)
    put(o,INPUT_AT,at)
    put(o,INPUT_N,n)
    return start_task(o,T_SHA,next)

def norm_start(o:mutbuf,kind:u64,region:u64,at:u64,n:u64,next:u64) -> u32:
    put(o,NORM_KIND,kind)
    put(o,NORM_REGION,region)
    put(o,NORM_AT,at)
    put(o,NORM_N,n)
    put(o,NORM_RETURN,next)
    put(o,PHASE,100)
    return 3

def row(o:mutbuf) -> u64:
    return ROWS+get(o,CURRENT)*ROW_SIZE

def node(w:mutbuf,a:u64,index:u64,slot:u64) -> u64:
    if index>=get(w,a+8):
        return NONE
    return get(w,a+64+index*72+slot)

def field(w:mutbuf,a:u64,parent:u64,label:u64) -> u64:
    if node(w,a,parent,0)!=6:
        return NONE
    child=node(w,a,parent,24)
    while child!=NONE:
        if name_id(w,a+node(w,a,child,40),node(w,a,child,48))==label:
            return child
        child=node(w,a,child,16)
    return NONE

def name_id(w:mutbuf,at:u64,n:u64) -> u64:
    if n==7 and bytes_equal_literal(w,at,28555976301389165,7):
        return 1
    if n==11 and get(w,at)==8391162084801472868 and bytes_equal_literal(w,at+8,7564643,3):
        return 2
    return 0

def bytes_equal_literal(w:mutbuf,at:u64,value:u64,n:u64) -> bool:
    i=0
    while i<n:
        if byte(w,at+i)!=((value>>(i*8))&255):
            return False
        i=i+1
    return True

def copy_control(o:mutbuf,to:u64,source_at:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(o,to+i,byte(o,source_at+i))
        i=i+1
    return 0

def copy_work_control(o:mutbuf,to:u64,w:mutbuf,source_at:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(o,to+i,byte(w,source_at+i))
        i=i+1
    return 0

def read(s:readbuf,at:u64) -> u64:
    value=0
    i=0
    while i<8:
        value=value|(byte(s,at+i)<<(i*8))
        i=i+1
    return value

def clock(o:mutbuf,next:u64) -> u32:
    put(o,PHASE,next)
    return syscall(o,228,12,1,3200,0,0,0,0)

def now(o:mutbuf) -> u64:
    return get(o,3200)*1000000000+get(o,3208)

def error_steps(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase=get(o,PHASE)
    if phase==9000:
        report_begin(o,10,2)
        report_part(o,0,3,60000,get(o,ERROR_TYPE_N))
        report_part(o,1,get(o,ERROR_REGION),get(o,ERROR_MESSAGE_AT),get(o,ERROR_MESSAGE_N))
        return frame_start(o,9001)
    if phase==9001:
        if get(o,RET_STATUS)!=0:
            return terminal(o,3)
        return report_start(o,9002)
    if phase==9002:
        if get(o,RET_STATUS)!=0:
            return terminal(o,3)
        put(o,RESULT_STATUS,get(o,ERROR_STATUS))
        put(o,RESULT_KIND,2)
        put(o,RESULT_AT,get(o,RET_AT))
        put(o,RESULT_N,get(o,RET_N))
        put(o,PHASE,9990)
        return 3
    return terminal(o,4)
'''
def common_source():
 wanted={'get','put','zero','needed','call','move','syscall'}
 extra='\n'.join(ast.unparse(n)for n in ast.parse(TASK_SOURCE).body if n.name in wanted)
 text=HELPERS+'\n'+extra+'\ndef literal(o:mutbuf,at:u64,id:u64) -> u64:\n'
 for ident,value in LITERALS.items():
  data=value.encode();text+=f'    if id=={ident}:\n'
  for off in range(0,len(data),8):text+=f'        put(o,at+{off},{int.from_bytes(data[off:off+8],"little")})\n'
  text+=f'        return {len(data)}\n'
 text+='    return 0\n'
 # Exact short decoded-key labels used only on already verified native diagnostics.
 text=text.replace('28555976301389165',str(int.from_bytes(b'message','little'))).replace('8391162084801472868',str(int.from_bytes(b'diagnost','little'))).replace('7564643',str(int.from_bytes(b'ics','little')))
 return text
def resolve(text):
 for name,value in sorted(C.items(),key=lambda x:-len(x[0])):
  text=re.sub(r'\b'+name+r'\b',str(value),text)
 return text
