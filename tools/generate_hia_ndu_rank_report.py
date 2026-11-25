"""Canonical rank reports, with 128-bit cost magnitudes and no output byte quota."""
from pathlib import Path
import ast,json,re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_system_jobctl_request import document
from tools.generate_hia_ndu_rank_admission import source_program as admission_source
ROOT=Path(__file__).resolve().parents[1]
LITERALS={}
def token(text):
    if text not in LITERALS:LITERALS[text]=len(LITERALS)+1
    return f'literal(o,w,{LITERALS[text]})'
def fields(name,entries):
    code=[f'def {name}(s:readbuf,o:mutbuf,w:mutbuf) -> u64:','    '+token('{')]
    first=True
    for key,expr,condition in entries:
        indent='    '
        if condition:code+=['    if '+condition+':'];indent='        '
        code += [indent+token((''if first else ',')+json.dumps(key)+':'),indent+expr]
        first=False
    code+=['    '+token('}'),'    return 0'];return '\n'.join(code)+'\n'
P=lambda i:f'part(s,o,w,{i},False,0)'
Q=lambda i:f'part(s,o,w,{i},True,0)'
H=lambda i:f'digest(s,o,w,{128+i*32})'
N=lambda i:f'number(o,w,readword(s,{64+i*8}),0,False)'
B=lambda i:f'boolean(o,w,readword(s,{64+i*8}))'
COST=lambda lo,hi,sign:f'number(o,w,readword(s,{384+lo}),readword(s,{384+hi}),'+('False'if sign is None else f'readword(s,{384+sign})!=0')+')'
def record(name,mapping):
    return fields(name,[(key,*mapping[key]) for key in sorted(mapping)])
SOURCE=r'''
def rank_report(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)<768 or length(o)<64 or length(w)<4096 or readword(s,0)!=REQUEST:
        return 4294967293
    action=readword(s,8)
    if action==11:
        return return_order(s,o,w)
    mode=readword(s,16)
    count=readword(s,24)
    if action>10 or mode>1 or count>64 or count>(length(s)-768)//16:
        return 4294967293
    if (action==0 and count!=2) or (action==1 and count!=1) or (action==2 and count!=5) or (action==3 and count!=1) or (action==4 and (count==0 or count>33)) or (action==5 and count!=1) or (action==6 and count!=1) or (action==7 and count!=0) or (action==8 and count!=13) or (action==10 and count!=2):
        return 4294967293
    i=32
    while i<64:
        if readword(s,i)!=0:
            return 4294967293
        i=i+8
    i=640
    while i<768:
        if readword(s,i)!=0:
            return 4294967293
        i=i+8
    at=768+count*16
    i=0
    while i<count:
        start=readword(s,768+i*16)
        n=readword(s,776+i*16)
        if start!=at or n>length(s)-at:
            return 4294967293
        at=at+n
        i=i+1
    if at!=length(s) or fields_valid(s,action)==False:
        return 4294967293
    zero(w,0,4096)
    render(s,o,w,action)
    if get(w,16)!=0:
        return 4294967293
    needed=get(w,0)
    if mode==1:
        if needed>length(o)-64:
            return 4294967294
        put(w,0,0)
        put(w,8,1)
        render(s,o,w,action)
        if get(w,0)!=needed or get(w,16)!=0:
            return 4294967293
    zero(o,0,64)
    put(o,0,REPLY)
    put(o,8,needed)
    put(o,16,action)
    return 0

def fields_valid(s:readbuf,action:u64) -> bool:
    if action==2:
        if readword(s,64)>1 or readword(s,72)>1 or readword(s,80)<1 or readword(s,80)>8 or readword(s,88)>1 or readword(s,96)>1:
            return False
        if readword(s,96)==1 and (readword(s,88)==0 or readword(s,104)==0 or readword(s,104)>5000):
            return False
        if readword(s,88)==1 and (readword(s,384)!=COST_REPLY or readword(s,392)!=1 or readword(s,400)!=0):
            return False
    if action==3 and (readword(s,88)>1 or readword(s,64)>9223372036854775807 or readword(s,72)>9223372036854775807 or readword(s,80)>9223372036854775807):
        return False
    if action==4 and (readword(s,64)==0 or readword(s,72)>9223372036854775807):
        return False
    if action==5 and (readword(s,64)>1 or readword(s,72)>2 or readword(s,320)>1):
        return False
    if action==6 and (readword(s,64)>1 or readword(s,384)!=COST_REPLY or readword(s,392)!=2 or readword(s,400)!=0):
        return False
    if action==6 and readword(s,64)==1 and (readword(s,72)==0 or readword(s,72)>5000):
        return False
    if action==8 and (readword(s,64)==0 or readword(s,72)>1 or readword(s,80)>9):
        return False
    if (action==2 and readword(s,88)==1) or action==6:
        if readword(s,480)>1 or readword(s,504)>1:
            return False
    return True

def render(s:readbuf,o:mutbuf,w:mutbuf,action:u64) -> u64:
    if action==0:
        return objective(s,o,w)
    if action==1:
        return support(s,o,w)
    if action==2:
        return candidate(s,o,w)
    if action==3:
        return cost_row(s,o,w)
    if action==4:
        return native_request(s,o,w)
    if action==5:
        return native_admission(s,o,w)
    if action==6:
        return selected_proof(s,o,w)
    if action==7:
        return costs(s,o,w)
    if action==8:
        return final_report(s,o,w)
    if action==9:
        return array(s,o,w)
    return exception(s,o,w)

def emit(o:mutbuf,w:mutbuf,value:u64) -> u64:
    at=get(w,0)
    if at==18446744073709551615:
        put(w,16,1)
        return 0
    if get(w,8)==1:
        store(o,64+at,value)
    put(w,0,at+1)
    return 0

def word(o:mutbuf,w:mutbuf,value:u64,n:u64) -> u64:
    i=0
    while i<n:
        emit(o,w,(value>>(i*8))&255)
        i=i+1
    return 0

def part(s:readbuf,o:mutbuf,w:mutbuf,index:u64,quoted:bool,maximum:u64) -> u64:
    start=readword(s,768+index*16)
    n=readword(s,776+index*16)
    if quoted:
        emit(o,w,34)
    at=0
    points=0
    going=True
    while at<n and going:
        value=byte(s,start+at)
        if (value&192)!=128:
            points=points+1
            if maximum!=0 and points>maximum:
                going=False
        if going:
            if quoted:
                quote_byte(o,w,value)
            else:
                emit(o,w,value)
            at=at+1
    if quoted:
        emit(o,w,34)
    return 0

def quote_byte(o:mutbuf,w:mutbuf,value:u64) -> u64:
    if value<32:
        emit(o,w,92)
        escape=0
        if value==8:
            escape=98
        elif value==9:
            escape=116
        elif value==10:
            escape=110
        elif value==12:
            escape=102
        elif value==13:
            escape=114
        if escape!=0:
            emit(o,w,escape)
        else:
            word(o,w,3158133,3)
            emit(o,w,hex_digit(value>>4))
            emit(o,w,hex_digit(value&15))
    else:
        if value==34 or value==92:
            emit(o,w,92)
        emit(o,w,value)
    return 0

def hex_digit(value:u64) -> u64:
    return value+choose(value<10,48,87)

def digest(s:readbuf,o:mutbuf,w:mutbuf,at:u64) -> u64:
    emit(o,w,34)
    i=0
    while i<32:
        value=byte(s,at+i)
        emit(o,w,hex_digit(value>>4))
        emit(o,w,hex_digit(value&15))
        i=i+1
    emit(o,w,34)
    return 0

def number(o:mutbuf,w:mutbuf,low:u64,high:u64,negative:bool) -> u64:
    if low==0 and high==0:
        return emit(o,w,48)
    if negative:
        emit(o,w,45)
    count=0
    while low!=0 or high!=0:
        qhi=high//10
        carry=high%10
        first=(carry<<32)|(low>>32)
        upper=first//10
        carry=first%10
        last=(carry<<32)|(low&4294967295)
        lower=last//10
        digit=last%10
        store(w,128+count,48+digit)
        count=count+1
        low=(upper<<32)|lower
        high=qhi
    while count!=0:
        count=count-1
        emit(o,w,byte(w,128+count))
    return 0

def final_margin(s:readbuf,o:mutbuf,w:mutbuf) -> u64:
    if readword(s,72)==0:
        return emit(o,w,48)
    return number(o,w,readword(s,320),readword(s,328),False)

def array(s:readbuf,o:mutbuf,w:mutbuf) -> u64:
    emit(o,w,91)
    i=0
    while i<readword(s,24):
        if i!=0:
            emit(o,w,44)
        part(s,o,w,i,False,0)
        i=i+1
    emit(o,w,93)
    return 0

def zero(w:mutbuf,at:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(w,at+i,0)
        i=i+1
    return 0
'''
def source_program():
    LITERALS.clear()
    text=SOURCE
    text+=record('objective',{'schema':(token('"hepta.hia.ndu-optimization.v1"'),None),'objective':(P(0),None),'function':(Q(1),None),'before_sha256':(H(0),None),'before_input_sha256':(H(1),None)})
    text+=record('support',{'observation':(P(0),None),'program':(H(0),None)})
    text+=record('candidate',{
      'id':(Q(0),None),'action':(Q(1),None),'core_verified':(B(0),None),'observation':(P(2),None),
      'equivalence_proved':(B(1),None),'proof':(P(3),None),
      'detail':('part(s,o,w,4,True,1024)','readword(s,80)==1'),
      'reason':('candidate_reason(o,w,readword(s,80))',None),
      'preproof_cost_lower_bound_ns':(COST(48,56,None),'readword(s,88)==1'),
      'proof_remaining_budget_ns':(COST(104,112,96),'readword(s,88)==1'),
      'proof_remaining_margin_ns':(COST(128,136,120),'readword(s,88)==1'),
      'proof_timeout_ms':(N(5),'readword(s,96)==1'),'proof_wall_ns':(N(6),'readword(s,96)==1')})
    text+=record('cost_row',{'id':(Q(0),None),'cost_q32':(N(0),None),'uncertainty_q32':(N(1),None),'resource_q32':(N(2),None),'hard_violation':(B(3),None),'support_sha256':(H(0),None)})
    text+=record('native_request',{'schema':(token('"hepta.hia.ndu-request.v1"'),None),'objective_sha256':(H(0),None),'generation':(N(0),None),'resource_cap_q32':(N(1),None),'candidates':('array(s,o,w)',None)})
    text+=record('native_admission',{'invoked':(B(0),None),'remaining_budget_ns':('number(o,w,readword(s,328),readword(s,336),readword(s,320)!=0)',None),'timeout_s':(P(0),None),'reason':('admission_reason(o,w,readword(s,72))',None)})
    text+=record('selected_proof',{'candidate_id':(Q(0),None),'spent_search_ns':(COST(48,56,None),None),'remaining_budget_ns':(COST(104,112,96),None),'remaining_margin_ns':(COST(128,136,120),None),'solver_started':(B(0),None),'timeout_ms':(N(1),'readword(s,64)==1'),'wall_ns':(N(2),'readword(s,64)==1')})
    text+=record('costs',{'supplied_search_ns':(N(0),None),'actual_adapter_ns':(N(1),None),'total_search_ns':('number(o,w,readword(s,80),readword(s,88),False)',None),'search_at_native_rank_ns':('number(o,w,readword(s,96),readword(s,104),False)',None),'publication_preparation_included':(token('false'),None)})
    claims={'ndu_is_advisory':True,'unproved_candidate_admitted':False,'all_other_functions_unchanged':True,'resource_bounds_proved':False,'measurements_independently_attested':False,'native_backend_refinement_proved':False,'global_optimality_established':False,'incremental_advantage_established':False}
    text+=record('final_report',{'schema':(token('"hepta.hia.ndu-optimization.v1"'),None),'before_sha256':(H(0),None),'before_input_sha256':(H(1),None),'function':(Q(0),None),'generation':(N(0),None),'objective':(P(1),None),'objective_sha256':(H(2),None),'observations_sha256':(H(3),None),'selected_id':(Q(2),None),'admitted':(B(1),None),'reason':('final_reason(o,w,readword(s,80))',None),'selected_program':(P(3),None),'net_margin_ns':('final_margin(s,o,w)',None),'costs':(P(4),None),'candidate_reports':(P(5),None),'selected_fresh_proof':(P(6),None),'selected_proof_admission':(P(7),None),'native_rank_admission':(P(8),None),'native_request':(P(9),None),'request_sha256':(H(4),None),'native_response':(P(10),None),'bridge':(P(11),None),'selection_resolution':(P(12),None),'claims':(token(json.dumps(claims,sort_keys=True,separators=(',',':'))),None),'cost_model':(token(json.dumps('incumbent lower bound versus candidate upper bound; all search charged once; trusted host observations')),None)})
    text+=record('exception',{'type':(Q(0),None),'message':(Q(1),None)})
    tables={
      'candidate_reason':{1:'canonical_verifier_rejected',2:'unselected_function_or_module_changed',3:'search_budget_exhausted_before_proof',4:'cost_dominated_before_proof',5:'search_budget_insufficient_for_proof',6:'cost_margin_insufficient_for_proof',7:'proved',8:'behavior_not_proved'},
      'admission_reason':{0:'search_budget_exhausted_before_native',1:'native_identity_admission_exhausted_budget',2:'actual_native_response_received'},
      'final_reason':{0:'search_budget_exhausted_before_native',1:'native_identity_admission_exhausted_budget',2:'caller_pareto_tie_retained_incumbent',3:'native_evaluator_abstained',4:'actual_search_budget_exceeded',5:'no_robust_net_saving_after_search',6:'selected_proof_budget_insufficient',7:'selected_proof_margin_insufficient',8:'selected_candidate_fresh_proof_failed',9:'fresh_proof_and_robust_cost_gate_passed'}}
    for name,values in tables.items():
        text+='\ndef '+name+'(o:mutbuf,w:mutbuf,value:u64) -> u64:\n'
        for key,value in values.items():text+=f'    if value=={key}:\n        return {token(json.dumps(value))}\n'
        text+='    return 0\n'
    text+='\ndef boolean(o:mutbuf,w:mutbuf,value:u64) -> u64:\n    if value==0:\n        return '+token('false')+'\n    return '+token('true')+'\n'
    text+='\ndef literal(o:mutbuf,w:mutbuf,id:u64) -> u64:\n'
    for value,key in LITERALS.items():
        raw=value.encode();text+=f'    if id=={key}:\n'
        for i in range(0,len(raw),8):
            chunk=raw[i:i+8];text+=f'        word(o,w,{int.from_bytes(chunk,"little")},{len(chunk)})\n'
        text+='        return 0\n'
    text+='    return 0\n'
    wanted={'get','put','choose'}
    helpers=[ast.unparse(n) for n in ast.parse(admission_source()).body if n.name in wanted]
    text+='\n'+'\n'.join(helpers)+'\n'
    from tools.generate_hia_ndu_rank_report_order import source_program as order_source
    text+='\n'+order_source()
    text+='\ndef readword(s:readbuf,at:u64) -> u64:\n    value=0\n    i=0\n    while i<8:\n        value=value|(byte(s,at+i)<<(i*8))\n        i=i+1\n    return value\n'
    for key,value in {'REQUEST':int.from_bytes(b'HIANRP01','little'),'REPLY':int.from_bytes(b'HIANPR01','little'),'COST_REPLY':int.from_bytes(b'HIANRR01','little')}.items():
        text=re.sub(r'\b'+key+r'\b',str(value),text)
    return text
def program():return document(source_program(),'ndu_rank_report')
if __name__=='__main__':
    path=ROOT/'examples/hia_bootstrap/ndu_rank_report.hepta';path.write_text(render_assembly(program()));print(path.name,path.stat().st_size,flush=True)
