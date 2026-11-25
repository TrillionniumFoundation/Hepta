"""Pure HIA construction and accounting of shared BackgroundOptimizer results.

The controller captures actual job/time observations and owns the input
capabilities. A separate private continuation profile observes commitment and
Future state only at their original positions after the cost mutations. This policy only calls the fixed mutable value primitive through
the standard private continuation ABI. It never settles the ledger itself.
"""
from pathlib import Path
import json,re
from tools.generate_hia_result_value_common import ROOT,document,render_assembly,resolve
CAPS=512;REQUEST=8192;VALUE_OUT=12288;CLEANUP=100000
SLOTS={}
def slot(name):
 if name not in SLOTS:SLOTS[name]=len(SLOTS)+1
 return SLOTS[name]
def loc(name):return CAPS+slot(name)*32
LITERALS=[]
def lit(value):
 raw=value.encode()if isinstance(value,str)else value
 if raw not in LITERALS:LITERALS.append(raw)
 return LITERALS.index(raw)+1
STEPS=[]
def emit(label,body):
 assert label not in {x[0]for x in STEPS},label
 STEPS.append((label,body))
def jump(label):return f'return advance(w,@{label}@)'
def call(op,a=None,b=None,c=None,dest=None,arg0=0,arg1=0,literal=0,allow=0):
 def action(next):
  return f'return invoke(o,w,{op},{slot(a)if a else 0},{slot(b)if b else 0},{slot(c)if c else 0},{slot(dest)if dest else 0},{arg0},{arg1},{literal},@{next}@,{allow})'
 return action
def get(source,key,dest,optional=False):return call(9,source,'k:'+key,dest=dest,allow=int(optional))
def put(target,key,value):return call(10,target,'k:'+key,value)
def drop(name):
 def action(next):
  return f'if get(w,{loc(name)+24})==0:\n    {jump(next)}\n'+call(6,name)(next)
 return action
def series(prefix,actions,next):
 for i,action in enumerate(actions):
  label=f'{prefix}_{i}';after=f'{prefix}_{i+1}'if i+1<len(actions)else next
  emit(label,action(after))
 return prefix+'_0'
def generated():
 SLOTS.clear();LITERALS.clear();STEPS.clear()
 for name in('borrow_meta','borrow_result','meta','result','receipt','observed','temporary','costs','worker','wall','now','submitted','started','submit','enqueued','queue','receipt_costs','ranking','admission','invoked','bridge','reported','reported_copy','copy_key','copy_value','zero','one','false','true','pending','cancelled','finished','cancel_reason','scope'):slot(name)
 base_pairs=[('job','job'),('status','status'),('reason','reason'),('generation','expected_generation'),('epoch','expected_selection_epoch'),('function','function'),('before_sha256','before_sha256'),('before_input_sha256','before_input_sha256'),('original_baseline_sha256','original_baseline_sha256')]
 receipt_keys=('schema','job','reason','expected_generation','expected_selection_epoch','before_sha256','selected_id','publication_committed')
 ranking_cost_keys=('supplied_search_ns','actual_adapter_ns','total_search_ns','search_at_native_rank_ns')
 keys=list(dict.fromkeys([x for pair in base_pairs for x in pair]+list(receipt_keys)+list(ranking_cost_keys)+[
 'submit_work_ns','costs','epoch','decision_generation','now_ns','submitted_ns','work_started_ns','enqueued_ns',
 'job_wall_before_future_completion_ns','worker_elapsed_ns','observed_submit_and_worker_ns','publication_committed',
 'execution_status','future_state_at_accounting','status_scope','detail','queue_wait_ns','ranking','ranking_returned',
 'native_rank_admission','invoked','native_rank_invoked','request_sha256','native_request_sha256',
 'bridge','binary_sha256','native_binary_sha256','reported_ranking_costs','publication','publication_returned']))
 for key in keys:slot('k:'+key)
 # First operations acquire independently owned references to actual objects.
 emit('start',call(5,'borrow_meta',dest='meta')('meta_type'))
 emit('meta_type',f'if get(w,176)!=6:\n    return stop(w,2)\nif readword(s,8)==1:\n    '+call(5,'borrow_result',dest='result')('result_type')+'\n'+jump('constants_0'))
 emit('result_type','if get(w,176)!=6:\n    return stop(w,2)\n'+jump('constants_0'))
 constants=[call(2,dest='k:'+key,arg0=4,literal=lit(key))for key in keys]
 constants +=[call(2,dest='zero',arg0=2,literal=lit('0')),call(2,dest='one',arg0=2,literal=lit('1')),call(2,dest='false',arg0=1),call(2,dest='true',arg0=1,arg1=1)]
 for name,text in [('pending','pending'),('cancelled','cancelled'),('finished','finished'),('cancel_reason','publication_cancelled_before_commit'),('scope','execution outcome observed at cost accounting; not a Future terminal-state claim')]:
  constants.append(call(2,dest=name,arg0=4,literal=lit(text)))
 series('constants',constants,'mode')
 emit('mode','if readword(s,8)==0:\n    '+jump('base_0')+'\n'+jump('account_0'))
 template={"schema":"hepta.hia.background-optimization.v1","job":0,"status":"","reason":"","expected_generation":0,"expected_selection_epoch":0,"decision_generation":0,"function":"","before_sha256":"","before_input_sha256":"","original_baseline_sha256":"","selected_id":"abstain","ranking":None,"publication":None,"costs":{"submit_work_ns":0},"claims":{"state_layout_migration":False,"general_live_code_patch":False,"performance_improvement_established":False,"measurements_independently_attested":False,"backend_refinement_proved":False,"global_optimality_established":False}}
 actions=[call(1,dest='result',literal=lit(json.dumps(template,separators=(',',':'))))]
 for before,after in base_pairs:actions +=[get('meta',before,'temporary'),put('result',after,'temporary'),drop('temporary')]
 actions +=[get('meta','epoch','temporary'),call(24,'temporary','one',dest='wall'),put('result','decision_generation','wall'),get('result','costs','costs'),get('meta','submit_work_ns','submit'),put('costs','submit_work_ns','submit')]
 series('base',actions,'success')
 # Actual elapsed integers are captured by the controller, then calculated here.
 series('account',[get('result','costs','costs'),get('meta','now_ns','now'),get('meta','submitted_ns','submitted'),get('meta','work_started_ns','started')],'worker')
 emit('worker','if get(w,176)==0:\n    '+call(5,'zero',dest='worker')('timing_0')+'\n'+call(24,'now','started',dest='worker',arg0=1)('timing_0'))
 series('timing',[get('meta','submit_work_ns','submit'),call(24,'now','submitted',dest='wall',arg0=1),call(24,'submit','worker',dest='observed'),put('costs','job_wall_before_future_completion_ns','wall'),put('costs','worker_elapsed_ns','worker'),put('costs','observed_submit_and_worker_ns','observed')],'committed')
 emit('committed','if get(w,240)!=0:\n    return observe(o,w,1,@committed_write@)\n'+jump('committed_write'))
 emit('committed_write','if get(w,224)==0:\n    '+put('result','publication_committed','false')('future')+'\n'+put('result','publication_committed','true')('future'))
 emit('future','if get(w,240)!=0:\n    return observe(o,w,2,@future_choice@)\n'+jump('future_choice'))
 emit('future_choice','if get(w,232)==1:\n    '+jump('cancel_0')+'\n'+jump('receipt_0'))
 series('cancel',[put('result','status','cancelled'),put('result','reason','cancel_reason')],'receipt_0')
 actions=[call(4,dest='receipt')]
 for key in receipt_keys:actions +=[get('result',key,'temporary'),put('receipt',key,'temporary'),drop('temporary')]
 actions +=[get('result','status','temporary'),put('receipt','execution_status','temporary'),drop('temporary')]
 series('receipt',actions,'future_state')
 emit('future_state','if get(w,232)==0:\n    '+put('receipt','future_state_at_accounting','pending')('receipt_more_0')+'\nif get(w,232)==1:\n    '+put('receipt','future_state_at_accounting','cancelled')('receipt_more_0')+'\n'+put('receipt','future_state_at_accounting','finished')('receipt_more_0'))
 series('receipt_more',[put('receipt','status_scope','scope'),call(4,dest='receipt_costs'),call(7,'costs')],'copy_begin')
 emit('copy_begin','if get(w,176)!=6:\n    return stop(w,2)\nput(w,192,0)\nput(w,200,get(w,184))\n'+jump('copy_next'))
 emit('copy_next','if get(w,192)>=get(w,200):\n    '+jump('receipt_after_copy_0')+'\n'+call(23,'costs',arg0='get(w,192)',arg1=1)('copy_take'))
 emit('copy_take',f'if get(w,{VALUE_OUT+64})!=1:\n    return stop(w,11)\ncopy(w,{loc("copy_key")},{VALUE_OUT+8192+16},24)\nput(w,{loc("copy_key")+24},1)\ncopy(w,{loc("copy_value")},{VALUE_OUT+8192+40},24)\nput(w,{loc("copy_value")+24},1)\n'+call(10,'receipt_costs','copy_key','copy_value')('copy_drop_0'))
 series('copy_drop',[drop('copy_key'),drop('copy_value')],'copy_advance')
 emit('copy_advance','put(w,192,get(w,192)+1)\n'+jump('copy_next'))
 series('receipt_after_copy',[put('receipt','costs','receipt_costs'),get('result','detail','temporary',True)],'detail')
 emit('detail','if get(w,168)==0:\n    '+put('receipt','detail','temporary')('detail_drop_0')+'\n'+jump('detail_drop_0'))
 series('detail_drop',[drop('temporary'),call(7,'started')],'queue')
 emit('queue','if get(w,176)==0:\n    '+jump('queue_work_0')+'\n'+jump('ranking_0'))
 series('queue_work',[get('meta','enqueued_ns','enqueued'),call(24,'now','enqueued',dest='queue',arg0=1),put('receipt_costs','queue_wait_ns','queue')],'ranking_0')
 series('ranking',[get('result','ranking','ranking',True)],'ranking_type')
 emit('ranking_type','if get(w,168)==0 and get(w,176)==6:\n    '+put('receipt','ranking_returned','true')('admission_0')+'\n'+put('receipt','ranking_returned','false')('publication_0'))
 series('admission',[get('ranking','native_rank_admission','admission',True)],'admission_type')
 emit('admission_type','if get(w,168)==0 and get(w,176)==6:\n    '+get('admission','invoked','invoked',True)('invoked_type')+'\n'+jump('invoked_false'))
 emit('invoked_type','if get(w,168)==0 and get(w,176)==1:\n    '+call(19,'invoked',arg1=1)('invoked_bool')+'\n'+jump('invoked_false'))
 emit('invoked_bool',f'if byte(w,{VALUE_OUT+8192})==1:\n    '+put('receipt','native_rank_invoked','true')('request_0')+'\n'+jump('invoked_false'))
 emit('invoked_false',put('receipt','native_rank_invoked','false')('request_0'))
 series('request',[get('ranking','request_sha256','temporary',True)],'request_type')
 emit('request_type','if get(w,168)==0 and get(w,176)==4:\n    '+put('receipt','native_request_sha256','temporary')('request_drop_0')+'\n'+jump('request_drop_0'))
 series('request_drop',[drop('temporary'),get('ranking','bridge','bridge',True)],'bridge_type')
 emit('bridge_type','if get(w,168)==0 and get(w,176)==6:\n    '+get('bridge','binary_sha256','temporary',True)('binary_type')+'\n'+jump('reported_0'))
 emit('binary_type','if get(w,168)==0 and get(w,176)==4:\n    '+put('receipt','native_binary_sha256','temporary')('binary_drop_0')+'\n'+jump('binary_drop_0'))
 series('binary_drop',[drop('temporary')],'reported_0')
 series('reported',[get('ranking','costs','reported',True)],'reported_type')
 emit('reported_type','if get(w,168)==0 and get(w,176)==6:\n    '+call(4,dest='reported_copy')('reported_get_0')+'\n'+jump('publication_0'))
 for i,key in enumerate(ranking_cost_keys):
  emit('reported_get_'+str(i),get('reported',key,'temporary',True)('reported_type_'+str(i)))
  emit('reported_type_'+str(i),'if get(w,168)==0 and get(w,176)==2:\n    '+put('reported_copy',key,'temporary')('reported_drop_'+str(i))+'\n'+jump('reported_drop_'+str(i)))
  emit('reported_drop_'+str(i),drop('temporary')('reported_get_'+str(i+1)if i+1<len(ranking_cost_keys)else'reported_finish'))
 emit('reported_finish',put('receipt','reported_ranking_costs','reported_copy')('publication_0'))
 series('publication',[get('result','publication','temporary',True)],'publication_type')
 emit('publication_type','if get(w,168)==0 and get(w,176)==6:\n    '+put('receipt','publication_returned','true')('success')+'\n'+put('receipt','publication_returned','false')('success'))
 emit('success','return stop(w,0)')
 assert len(SLOTS)<128,(len(SLOTS),SLOTS)
 numbers={label:i+1 for i,(label,_)in enumerate(STEPS)}
 text=COMMON
 text=text.replace('START_STEP',str(numbers['start']))
 for key,value in [('CAPS',CAPS),('REQUEST',REQUEST),('VALUE_OUT',VALUE_OUT),('CLEANUP',CLEANUP),('SLOT_COUNT',len(SLOTS)+1),('META_BORROW',loc('borrow_meta')),('RESULT_BORROW',loc('borrow_result')),('RESULT_SLOT',slot('result')),('RECEIPT_SLOT',slot('receipt')),('OBSERVED_SLOT',slot('observed')),('MAGIC',int.from_bytes(b'HIABRP01','little')),('OBSERVED_MAGIC',int.from_bytes(b'HIABRP02','little')),('OBSERVATION_REQUEST',int.from_bytes(b'HIABROQ1','little')),('REPLY',int.from_bytes(b'HIABRR01','little')),('CONTEXT',int.from_bytes(b'HIABRC01','little')),('VALUE_MAGIC',int.from_bytes(b'HIABVQ01','little')),('VALUE_REPLY',int.from_bytes(b'HIABVR01','little'))]:
  text=re.sub(r'\b'+key+r'\b',str(value),text)
 lines=['def dispatch(s:readbuf,o:mutbuf,w:mutbuf) -> u64:','    step=get(w,128)']
 for group,start in enumerate(range(0,len(STEPS),48)):
  end=min(start+48,len(STEPS));lines +=[f'    if step<={end}:',f'        return dispatch_{group}(s,o,w)']
 lines +=['    return stop(w,11)'];text+='\n'+'\n'.join(lines)+'\n'
 for group,start in enumerate(range(0,len(STEPS),48)):
  lines=[f'def dispatch_{group}(s:readbuf,o:mutbuf,w:mutbuf) -> u64:','    step=get(w,128)']
  for label,body in STEPS[start:start+48]:
   body=re.sub(r'@([a-zA-Z0-9_]+)@',lambda m:str(numbers[m[1]]),body)
   lines +=[f'    if step=={numbers[label]}:']+['        '+x for x in body.splitlines()]
  lines +=['    return stop(w,11)'];text+='\n'+'\n'.join(lines)+'\n'
 lines=['def literal(w:mutbuf,at:u64,number:u64) -> u64:']
 for group,start in enumerate(range(0,len(LITERALS),16)):
  end=min(start+16,len(LITERALS));lines +=[f'    if number<={end}:',f'        return literal_{group}(w,at,number)']
 lines.append('    return 0');text+='\n'+'\n'.join(lines)+'\n'
 for group,start in enumerate(range(0,len(LITERALS),16)):
  lines=[f'def literal_{group}(w:mutbuf,at:u64,number:u64) -> u64:']
  for i,raw in enumerate(LITERALS[start:start+16],start+1):
   lines.append(f'    if number=={i}:')
   for off in range(0,len(raw)//8*8,8):lines.append(f'        put(w,at+{off},{int.from_bytes(raw[off:off+8],"little")})')
   for off in range(len(raw)//8*8,len(raw)):lines.append(f'        store(w,at+{off},{raw[off]})')
   lines.append(f'        return {len(raw)}')
  lines.append('    return 0');text+='\n'+'\n'.join(lines)+'\n'
 return resolve('background_optimizer_report',text)

COMMON=r'''
def background_optimizer_report(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(o)<8192 or length(w)<32768:
        return 4294967293
    phase=get(o,128)
    if phase==0:
        if length(s)!=128 or readword(s,8)>1:
            return 4294967293
        magic=readword(s,0)
        if magic!=MAGIC and magic!=OBSERVED_MAGIC:
            return 4294967293
        if magic==OBSERVED_MAGIC and (readword(s,8)!=1 or readword(s,16)!=0 or readword(s,72)!=0):
            return 4294967293
        if readword(s,16)>1 or readword(s,72)>2:
            return 4294967293
        if readword(s,8)==0 and (readword(s,16)!=0 or readword(s,48)!=0 or readword(s,56)!=0 or readword(s,64)!=0 or readword(s,72)!=0):
            return 4294967293
        at=80
        while at<128:
            if readword(s,at)!=0:
                return 4294967293
            at=at+8
        if get(w,0)!=CONTEXT or get(w,8)==0 or get(w,16)==0 or get(w,24)<256:
            return 4294967293
        at=32
        while at<128:
            if get(w,at)!=0:
                return 4294967293
            at=at+8
        zero(o,0,256)
        zero(w,128,32768-128)
        from_input(s,w,META_BORROW,24,24)
        from_input(s,w,RESULT_BORROW,48,24)
        put(w,128,START_STEP)
        put(w,224,readword(s,16))
        put(w,232,readword(s,72))
        put(w,240,choose(magic==OBSERVED_MAGIC,1,0))
        put(o,128,1)
    elif phase!=1:
        return 4294967293
    observation=get(w,248)
    if observation!=0:
        put(w,248,0)
        value=get(o,144)
        if get(o,136)!=0 or observation>2 or value>choose(observation==1,1,2):
            return stop(w,11)
        put(w,choose(observation==1,224,232),value)
    pending=get(w,136)
    if pending!=0:
        put(w,136,0)
        status=get(w,VALUE_OUT+8)
        if get(o,136)!=0 or get(w,VALUE_OUT)!=VALUE_REPLY:
            status=11
        put(w,168,status)
        put(w,176,get(w,VALUE_OUT+16))
        put(w,184,get(w,VALUE_OUT+48))
        if pending==2:
            if status!=0 and get(w,144)==0:
                put(w,144,11)
            zero(w,CAPS+get(w,208)*32,32)
        elif status!=0:
            if get(w,160)!=1 or status!=3:
                return stop(w,status)
        else:
            dest=get(w,152)
            if dest!=0:
                if get(w,VALUE_OUT+24)==0 or get(w,CAPS+dest*32+24)!=0:
                    return stop(w,11)
                copy(w,CAPS+dest*32,VALUE_OUT+24,24)
                put(w,CAPS+dest*32+24,1)
            source=get(w,208)
            if source!=0:
                zero(w,CAPS+source*32,32)
    if get(w,128)==CLEANUP:
        return cleanup(o,w)
    return dispatch(s,o,w)
def observe(o:mutbuf,w:mutbuf,kind:u64,next:u64) -> u64:
    put(w,128,next)
    put(w,248,kind)
    zero(o,0,128)
    put(o,0,OBSERVATION_REQUEST)
    put(o,8,kind)
    put(o,136,18446744073709551615)
    put(o,144,18446744073709551615)
    return 11
def advance(w:mutbuf,next:u64) -> u64:
    put(w,128,next)
    return 10
def stop(w:mutbuf,error:u64) -> u64:
    put(w,144,error)
    put(w,216,1)
    put(w,128,CLEANUP)
    return 10
def invoke(o:mutbuf,w:mutbuf,op:u64,a:u64,b:u64,c:u64,dest:u64,arg0:u64,arg1:u64,text:u64,next:u64,allow:u64) -> u64:
    zero(w,REQUEST,128)
    put(w,REQUEST,VALUE_MAGIC)
    put(w,REQUEST+8,op)
    copy(w,REQUEST+24,CAPS+a*32,24)
    copy(w,REQUEST+48,CAPS+b*32,24)
    copy(w,REQUEST+72,CAPS+c*32,24)
    n=literal(w,REQUEST+128,text)
    put(w,REQUEST+96,n)
    put(w,REQUEST+104,arg0)
    put(w,REQUEST+112,arg1)
    put(w,152,dest)
    put(w,160,allow)
    put(w,208,choose(op==6,a,0))
    put(w,136,choose(next==CLEANUP,2,1))
    put(w,128,next)
    put(o,0,get(w,8))
    put(o,8,17)
    put(o,16,REQUEST)
    put(o,24,128+n)
    put(o,32,VALUE_OUT)
    put(o,40,16384)
    put(o,48,get(w,16))
    put(o,56,get(w,24))
    return 4
def cleanup(o:mutbuf,w:mutbuf) -> u64:
    i=get(w,216)
    while i<SLOT_COUNT:
        put(w,216,i+1)
        keep=get(w,144)==0 and (i==RESULT_SLOT or i==RECEIPT_SLOT or i==OBSERVED_SLOT)
        if get(w,CAPS+i*32+24)!=0 and keep==False:
            return invoke(o,w,6,i,0,0,0,0,0,0,CLEANUP,0)
        i=i+1
    zero(o,0,128)
    put(o,0,REPLY)
    put(o,8,get(w,144))
    if get(w,144)==0:
        to_output(w,o,24,CAPS+RESULT_SLOT*32,24)
        to_output(w,o,48,CAPS+RECEIPT_SLOT*32,24)
        to_output(w,o,72,CAPS+OBSERVED_SLOT*32,24)
        put(w,CAPS+RESULT_SLOT*32+24,0)
        put(w,CAPS+RECEIPT_SLOT*32+24,0)
        put(w,CAPS+OBSERVED_SLOT*32+24,0)
    put(o,128,2)
    return 0
'''
def source_program():return generated()
def program():return document(source_program(),'background_optimizer_report')
if __name__=='__main__':
 p=ROOT/'examples/hia_bootstrap/background_optimizer_report.hepta'
 tree=program();p.write_text(render_assembly(tree));print(p.name,p.stat().st_size,len(tree['functions']),sum(len(f['blocks'])for f in tree['functions']),sum(len(b['ops'])for f in tree['functions']for b in f['blocks']),max(len(b['params'])for f in tree['functions']for b in f['blocks']),flush=True)
