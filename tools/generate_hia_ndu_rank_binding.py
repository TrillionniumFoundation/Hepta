"""Bind fresh rank proof and native response bytes to the owner's exact request."""
from pathlib import Path
import ast,json,re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_system_jobctl_request import document
from tools.generate_hia_ndu_rank_admission import source_program as admission_source
from tools.generate_hia_ndu_rank_selection import literal_function
from tools.generate_hia_worker_request import decimal_program
ROOT=Path(__file__).resolve().parents[1]
LABELS={1:'schema',2:'upstream_commit',3:'entry_point',4:'reference_entry_point',5:'authority',6:'objective_sha256',7:'generation',8:'request_sha256',9:'proves_program_safety',10:'global_optimality_established',11:'evaluation_digest_v2',12:'evaluation_policy_digest',13:'utility_profile_digest',14:'advisory_recommendation',15:'candidates',16:'id',17:'hard_violation',18:'profile',19:'status',20:'scope',21:'function',22:'before_sha256',23:'after_sha256',24:'before_input_sha256',25:'after_input_sha256',101:'hepta.hia.ndu-native-response.v1',102:'d3c2d760eca5065fc966820379c35c6e8d56e855',103:'hepta.hia.ndu_evaluator.v1',104:'codex_hepta_ndu::evaluate_candidates_with_policy',105:'ADVISORY_ONLY',106:'hepta.hia.translation-validation.v1',107:'hia.scalar-acyclic-bitvector-traps.v1',108:'proved',109:'selected_public_scalar_function'}
ERRORS={1:('OptimizationRejected','E_HIA_NDU: native evaluator response does not bind the exact request'),2:('OptimizationRejected','E_HIA_NDU: native evaluator returned a malformed digest'),3:('OptimizationRejected','E_HIA_NDU: native evaluator recommended an unavailable or unproved candidate'),4:('TypeError',"cannot use 'list' as a dict key (unhashable type: 'list')"),5:('TypeError',"cannot use 'dict' as a dict key (unhashable type: 'dict')")}
SOURCE=r'''
def rank_binding(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)<256 or length(w)<131072 or read64(s,0)!=REQUEST or read64(s,8)>1:
        return 4294967293
    mode=read64(s,8)
    name_n=read64(s,56)
    if name_n>128 or name_n>length(s)-256:
        return 4294967293
    if mode==0:
        if name_n==0 or read64(s,48)!=0 or read64(s,32)!=0 or read64(s,40)!=0:
            return 4294967293
    else:
        if name_n!=0 or read64(s,48)==0:
            return 4294967293
        i=96
        while i<192:
            if read64(s,i)!=0:
                return 4294967293
            i=i+8
    i=192
    while i<256:
        if read64(s,i)!=0:
            return 4294967293
        i=i+8
    at=256+name_n
    i=0
    while i<2:
        jn=read64(s,16+i*16)
        an=read64(s,24+i*16)
        if (jn==0)!=(an==0) or (jn==0 and (i==0 or mode==1)) or jn>length(s)-at:
            return 4294967293
        put(w,i*16,at)
        at=at+jn
        put(w,i*16+8,at)
        if an>length(s)-at:
            return 4294967293
        if an!=0 and arena_valid(s,w,at,an,jn)==False:
            return 4294967293
        at=at+an
        i=i+1
    if at!=length(s):
        return 4294967293
    error=0
    proved=False
    if mode==0:
        proved=proof_binding(s,w)
    else:
        error=response_binding(s,w)
        proved=error==0
    put(w,512,0)
    if error!=0:
        error_literal(w,error)
    n=get(w,512)
    if length(o)<128 or n>length(o)-128:
        return 4294967294
    zero(o,128)
    put(o,0,REPLY)
    put(o,8,choose(error==0,0,choose(error<4,1,2)))
    put(o,16,choose(proved,1,0))
    put(o,24,error)
    put(o,32,n)
    i=0
    while i<n:
        store(o,128+i,byte(w,65536+i))
        i=i+1
    return 0

def proof_binding(s:readbuf,w:mutbuf) -> bool:
    a=get(w,8)
    if nodeword(s,a,0,0)!=6:
        return False
    if string_id(s,a,field(s,a,0,1))!=106 or string_id(s,a,field(s,a,0,18))!=107 or string_id(s,a,field(s,a,0,19))!=108 or string_id(s,a,field(s,a,0,20))!=109:
        return False
    node=field(s,a,0,21)
    if nodeword(s,a,node,0)!=4 or same(s,a+nodeword(s,a,node,24),nodeword(s,a,node,32),256,read64(s,56))==False:
        return False
    i=0
    while i<4:
        if digest_binding(s,a,field(s,a,0,22+i),64+i*32)==False:
            return False
        i=i+1
    return True

def response_binding(s:readbuf,w:mutbuf) -> u64:
    a=get(w,24)
    q=get(w,8)
    if nodeword(s,a,0,0)!=6 or nodeword(s,q,0,0)!=6:
        return 1
    key=1
    while key<=5:
        if string_id(s,a,field(s,a,0,key))!=100+key:
            return 1
        key=key+1
    if same_node(s,a,field(s,a,0,6),q,field(s,q,0,6))==False or digest_binding(s,a,field(s,a,0,8),64)==False:
        return 1
    if numeric_equal(s,w,get(w,16),a,field(s,a,0,7),read64(s,48))==False:
        return 1
    if numeric_equal(s,w,get(w,16),a,field(s,a,0,9),0)==False or numeric_equal(s,w,get(w,16),a,field(s,a,0,10),0)==False:
        return 1
    key=11
    while key<=13:
        if digest(s,a,field(s,a,0,key))==False:
            return 2
        key=key+1
    recommendation=field(s,a,0,14)
    if recommendation==18446744073709551615 or nodeword(s,a,recommendation,0)==0:
        return 0
    kind=nodeword(s,a,recommendation,0)
    if kind==5:
        return 4
    if kind==6:
        return 5
    if kind!=4:
        return 3
    candidates=field(s,q,0,15)
    if nodeword(s,q,candidates,0)!=5:
        return 1
    child=nodeword(s,q,candidates,24)
    while child!=18446744073709551615:
        if same_node(s,a,recommendation,q,field(s,q,child,16)):
            if nodeword(s,q,field(s,q,child,17),0)==1:
                return 0
            return 3
        child=nodeword(s,q,child,16)
    return 3

def numeric_equal(s:readbuf,w:mutbuf,json:u64,a:u64,node:u64,wanted:u64) -> bool:
    kind=nodeword(s,a,node,0)
    if kind==1:
        return wanted==0
    if kind==2:
        return wanted==1
    if kind!=3:
        return False
    start=json+nodeword(s,a,node,24)
    n=nodeword(s,a,node,32)
    floating=False
    i=0
    while i<n:
        c=byte(s,start+i)
        if c==46 or c==101 or c==69:
            floating=True
        i=i+1
    if floating==False:
        value=integer(s,w,json,a,node,18446744073709551615)
        return get(w,520)==1 and value==wanted
    if widen(decimal_convert(s,w,start,n))!=8:
        return False
    bits=get(w,length(w)-8192+8000)
    if (bits&9223372036854775807)==0:
        return wanted==0
    if (bits>>63)!=0:
        return False
    exponent=(bits>>52)&2047
    if exponent<1023 or exponent>1086:
        return False
    mantissa=(bits&4503599627370495)|4503599627370496
    shift=exponent-1023
    value=0
    if shift<=52:
        amount=52-shift
        if (mantissa&((1<<amount)-1))!=0:
            return False
        value=mantissa>>amount
    else:
        value=mantissa<<(shift-52)
    return value==wanted

def emit(w:mutbuf,value:u64) -> u64:
    at=get(w,512)
    if at<1024:
        store(w,65536+at,value)
    put(w,512,at+1)
    return 0

def widen(value:u32) -> u64:
    return value
'''
def source_program():
    wanted={'arena_valid','nodeword','field','string_id','read64','readn','get','put','same','same_node','zero','choose','digest','digest_binding','integer'}
    helpers=[ast.unparse(n) for n in ast.parse(admission_source()).body if n.name in wanted]
    assert len(helpers)==len(wanted)
    text=SOURCE+'\n'+'\n'.join(helpers)+'\n'+decimal_program()+'\n'
    lines=['def label(s:readbuf,at:u64,n:u64) -> u64:']
    for ident,label in LABELS.items():
        raw=label.encode();parts=[f'n=={len(raw)}']+[f'readn(s,at+{i},{len(raw[i:i+8])})=={int.from_bytes(raw[i:i+8],"little")}'for i in range(0,len(raw),8)]
        lines+=['    if '+' and '.join(parts)+':',f'        return {ident}']
    lines.append('    return 0');text+='\n'+'\n'.join(lines)+'\n'
    text+=literal_function('error_literal',{i:json.dumps({'type':k,'message':v},sort_keys=True,separators=(',',':')) for i,(k,v)in ERRORS.items()})
    for key,value in {'REQUEST':int.from_bytes(b'HIANBD01','little'),'REPLY':int.from_bytes(b'HIANBDR1','little')}.items():
        text=re.sub(r'\b'+key+r'\b',str(value),text)
    return text
def program():return document(source_program(),'ndu_rank_binding')
if __name__=='__main__':
    path=ROOT/'examples/hia_bootstrap/ndu_rank_binding.hepta';path.write_text(render_assembly(program()));print(path.name,path.stat().st_size,flush=True)
