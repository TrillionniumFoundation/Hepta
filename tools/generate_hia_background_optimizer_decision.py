"""Ordered decision stages for the native BackgroundOptimizer.

Only the enclosing native owner supplies digests from its captured immutable
inputs and actual clocks. This leaf neither performs nor asserts a proof.
Fresh source verification is an explicit continuation between stages 1 and 2.
"""
from pathlib import Path
import ast,json,re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
from tools.generate_hia_background_optimizer_admission import source_program as admission_program
from tools.generate_hia_ndu_rank_cost import SOURCE as cost_source
from tools.generate_hia_worker_request import decimal_program
ROOT=Path(__file__).resolve().parents[1]
LABELS={1:'schema',2:'before_sha256',3:'before_input_sha256',4:'function',5:'generation',6:'observations_sha256',7:'objective',8:'objective_sha256',9:'selected_id',10:'admitted',11:'costs',12:'actual_adapter_ns',13:'total_search_ns',14:'observations',15:'search_ns',16:'supplied_search_ns',17:'net_margin_ns',18:'candidates',19:'id',20:'program',21:'selected_program',22:'abstain',23:'program_sha256',24:'expected_calls',25:'resource_cap_ns',26:'runtime_ns',27:'uncertainty_ns',100:'hepta.hia.ndu-optimization.v1'}
ERRORS={
1:('BackgroundOptimizationRejected','E_HIA_BACKGROUND: ranking does not bind the submitted incumbent, observations and generation'),
2:('BackgroundOptimizationRejected','E_HIA_BACKGROUND: ranking objective or generation has changed'),
3:('BackgroundOptimizationRejected','E_HIA_BACKGROUND: ranking objective digest does not bind this snapshot'),
4:('BackgroundOptimizationRejected','E_HIA_BACKGROUND: ranking admission fields have the wrong exact types'),
5:('BackgroundOptimizationRejected','E_HIA_BACKGROUND: ranking lacks measured search costs'),
6:('BackgroundOptimizationRejected','E_HIA_BACKGROUND: actual ranking cost must be an exact bounded integer'),
7:('BackgroundOptimizationRejected','E_HIA_BACKGROUND: reported ranking duration exceeds the observed invocation'),
8:('BackgroundOptimizationRejected','E_HIA_BACKGROUND: total search cost must be an exact bounded integer'),
9:('BackgroundOptimizationRejected','E_HIA_BACKGROUND: supplied search cost must be an exact bounded integer'),
10:('BackgroundOptimizationRejected','E_HIA_BACKGROUND: reported supplied search cost must be an exact bounded integer'),
11:('BackgroundOptimizationRejected','E_HIA_BACKGROUND: ranking search costs do not bind the submitted observations'),
12:('BackgroundOptimizationRejected','E_HIA_BACKGROUND: nonadmission must select abstain with zero margin'),
13:('BackgroundOptimizationRejected','E_HIA_BACKGROUND: ranking selected an unavailable candidate'),
14:('BackgroundOptimizationRejected','E_HIA_BACKGROUND: ranking selected source differs from the submitted candidate'),
15:('BackgroundOptimizationRejected','E_HIA_BACKGROUND: measured costs belong to a different program'),
16:('BackgroundOptimizationRejected','E_HIA_BACKGROUND: expected calls must be an exact bounded integer'),
17:('BackgroundOptimizationRejected','E_HIA_BACKGROUND: resource cap must be an exact bounded integer'),
18:('BackgroundOptimizationRejected','E_HIA_BACKGROUND: incumbent runtime must be an exact bounded integer'),
19:('BackgroundOptimizationRejected','E_HIA_BACKGROUND: incumbent uncertainty must be an exact bounded integer'),
20:('BackgroundOptimizationRejected','E_HIA_BACKGROUND: candidate runtime must be an exact bounded integer'),
21:('BackgroundOptimizationRejected','E_HIA_BACKGROUND: candidate uncertainty must be an exact bounded integer'),
22:('BackgroundOptimizationRejected','E_HIA_BACKGROUND: ranking has no positive bound net margin within its search budget'),
100:('TypeError',"'NoneType' object is not subscriptable"),
101:('TypeError',"'bool' object is not subscriptable"),
102:('TypeError',"'int' object is not subscriptable"),
103:('TypeError',"'float' object is not subscriptable"),
104:('TypeError',"string indices must be integers, not 'str'"),
105:('TypeError','list indices must be integers or slices, not str'),
110:('TypeError',"'NoneType' object is not iterable"),
111:('TypeError',"'bool' object is not iterable"),
112:('TypeError',"'int' object is not iterable"),
113:('TypeError',"'float' object is not iterable"),
114:('TypeError',"cannot use 'list' as a dict key (unhashable type: 'list')"),
115:('TypeError',"cannot use 'dict' as a dict key (unhashable type: 'dict')"),
}
C={'REQUEST':int.from_bytes(b'HIABDC01','little'),'REPLY':int.from_bytes(b'HIABDR01','little'),
 'NONE':(1<<64)-1,'MAX':(1<<63)-1,'MASK':(1<<32)-1,'BAD':4294967293,'SHORT':4294967294}
SOURCE=r'''
def background_optimizer_decision(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)<512 or length(w)<131072 or read64(s,0)!=REQUEST:
        return BAD
    if length(o)<256:
        return SHORT
    if frame(s,w)!=0:
        return BAD
    mode=read64(s,8)
    error=0
    if mode==0:
        error=initial(s,w)
    elif mode==1:
        error=costs_and_selection(s,w)
    else:
        error=selected_source(s,w)
        if error==0:
            error=net_margin(s,w)
        if error==0 and mode==3:
            error=prepare_budget(s,w)
    if error==BAD:
        return BAD
    put(w,128,error)
    zero(o,0,256)
    put(o,0,REPLY)
    put(o,8,choose(error==0,0,1))
    put(o,16,mode)
    i=0
    while i<224:
        put(o,24+i,get(w,128+i))
        i=i+8
    return 0

def frame(s:readbuf,w:mutbuf) -> u64:
    mode=read64(s,8)
    if mode>3 or read64(s,88)!=0:
        return BAD
    i=312
    while i<512:
        if read64(s,i)!=0:
            return BAD
        i=i+8
    if mode!=3 and (read64(s,288)!=0 or read64(s,296)!=0 or read64(s,304)!=0):
        return BAD
    zero(w,0,4096)
    at=512
    i=0
    while i<2:
        rn=read64(s,16+i*16)
        an=read64(s,24+i*16)
        if rn==0 or rn>length(s)-at:
            return BAD
        put(w,i*16,at)
        at=at+rn
        put(w,i*16+8,at)
        if an>length(s)-at or arena_valid(s,w,at,an,rn)==False:
            return BAD
        at=at+an
        i=i+1
    zero(w,0,4096)
    first=512
    put(w,0,first)
    first=first+read64(s,16)
    put(w,8,first)
    first=first+read64(s,24)
    put(w,16,first)
    first=first+read64(s,32)
    put(w,24,first)
    i=0
    while i<4:
        n=read64(s,48+i*8)
        if n>length(s)-at:
            return BAD
        put(w,32+i*8,at)
        at=at+n
        i=i+1
    if at!=length(s) or read64(s,56)==0 or decimal_valid(s,get(w,40),read64(s,56))==False:
        return BAD
    if nodeword(s,get(w,8),0,0)!=6:
        return BAD
    return 0

def initial(s:readbuf,w:mutbuf) -> u64:
    a=get(w,24)
    if nodeword(s,a,0,0)!=6 or string_id(s,a,field(s,a,0,1))!=100:
        return 1
    if digest_binding(s,a,field(s,a,0,2),96)==False or digest_binding(s,a,field(s,a,0,3),128)==False:
        return 1
    fn=field(s,a,0,4)
    if nodeword(s,a,fn,0)!=4 or same(s,a+nodeword(s,a,fn,24),nodeword(s,a,fn,32),get(w,32),read64(s,48))==False:
        return 1
    gen=field(s,a,0,5)
    if number_equals_decimal(s,w,get(w,16),a,gen,get(w,40),read64(s,56))==False:
        return 1
    if digest_binding(s,a,field(s,a,0,6),160)==False:
        return 1
    if integer_node(s,get(w,16),a,gen)==False:
        return 2
    put(w,168,1)
    put(w,240,field(s,a,0,7))
    put(w,248,field(s,get(w,8),0,7))
    return 0

def costs_and_selection(s:readbuf,w:mutbuf) -> u64:
    a=get(w,24)
    if same(s,get(w,48),read64(s,64),get(w,56),read64(s,72))==False:
        return 2
    if digest_binding(s,a,field(s,a,0,8),192)==False:
        return 3
    selected=field(s,a,0,9)
    admitted=field(s,a,0,10)
    ak=nodeword(s,a,admitted,0)
    if (ak!=1 and ak!=2) or nodeword(s,a,selected,0)!=4:
        return 4
    put(w,216,selected)
    costs=field(s,a,0,11)
    if nodeword(s,a,costs,0)!=6:
        return 5
    actual=integer(s,w,get(w,16),a,field(s,a,costs,12),MAX)
    if get(w,520)==0:
        return 6
    if actual>read64(s,80):
        return 7
    put(w,176,actual)
    total=integer(s,w,get(w,16),a,field(s,a,costs,13),MAX)
    if get(w,520)==0:
        return 8
    put(w,184,total)
    error=sum_observations(s,w)
    if error!=0:
        return error
    supplied=integer(s,w,get(w,16),a,field(s,a,costs,16),MAX)
    if get(w,520)==0:
        return 10
    if get(w,608)!=0 or get(w,600)!=supplied or total!=supplied+actual:
        return 11
    if ak==1:
        margin=field(s,a,0,17)
        if string_id(s,a,selected)!=22 or exact_zero(s,w,get(w,16),a,margin)==False:
            return 12
        put(w,168,0)
        return 0
    return select_candidate(s,w)

def sum_observations(s:readbuf,w:mutbuf) -> u64:
    a=get(w,8)
    observed=field(s,a,0,14)
    if nodeword(s,a,observed,0)!=6:
        return BAD
    child=nodeword(s,a,observed,24)
    while child!=NONE:
        node=required(s,w,a,child,15)
        if get(w,128)!=0:
            return get(w,128)
        value=integer(s,w,get(w,0),a,node,MAX)
        if get(w,520)==0:
            return 9
        add_pair(w,600,get(w,600),get(w,608),value,0)
        child=nodeword(s,a,child,16)
    return 0

def select_candidate(s:readbuf,w:mutbuf) -> u64:
    a=get(w,8)
    report=get(w,24)
    selected=get(w,216)
    candidates=field(s,a,0,18)
    kind=nodeword(s,a,candidates,0)
    if kind!=5:
        if kind==4 or kind==6:
            if nodeword(s,a,candidates,32)!=0:
                return 104
            return 13
        return 110+scalar_category(s,get(w,0),a,candidates)
    found=NONE
    child=nodeword(s,a,candidates,24)
    while child!=NONE:
        id=required(s,w,a,child,19)
        if get(w,128)!=0:
            return get(w,128)
        k=nodeword(s,a,id,0)
        if k==5:
            return 114
        if k==6:
            return 115
        if same_string_node(s,a,id,report,selected):
            found=child
        child=nodeword(s,a,child,16)
    if string_id(s,report,selected)==22 or found==NONE:
        return 13
    program=required(s,w,a,found,20)
    if get(w,128)!=0:
        return get(w,128)
    put(w,224,program)
    put(w,232,field(s,report,0,21))
    put(w,168,2)
    return 0

def selected_source(s:readbuf,w:mutbuf) -> u64:
    if same(s,224,32,256,32)==False:
        return 14
    a=get(w,8)
    report=get(w,24)
    selected=field(s,report,0,9)
    if nodeword(s,report,selected,0)!=4:
        return BAD
    observed=field(s,a,0,14)
    if nodeword(s,a,observed,0)!=6:
        return BAD
    selected_row=field_text(s,a,observed,report+nodeword(s,report,selected,24),nodeword(s,report,selected,32))
    if selected_row==NONE:
        put(w,136,1)
        put(w,144,selected)
        return 299
    incumbent=required(s,w,a,observed,22)
    if get(w,128)!=0:
        return get(w,128)
    hash=required(s,w,a,selected_row,23)
    if get(w,128)!=0:
        return get(w,128)
    if digest_binding(s,a,hash,224)==False:
        return 15
    hash=required(s,w,a,incumbent,23)
    if get(w,128)!=0:
        return get(w,128)
    if digest_binding(s,a,hash,96)==False:
        return 15
    put(w,312,selected_row)
    put(w,320,incumbent)
    return 0

def net_margin(s:readbuf,w:mutbuf) -> u64:
    a=get(w,8)
    report=get(w,24)
    objective=field(s,a,0,7)
    node=required(s,w,a,objective,24)
    if get(w,128)!=0:
        return get(w,128)
    calls=integer(s,w,get(w,0),a,node,MAX)
    if get(w,520)==0 or calls==0:
        return 16
    node=required(s,w,a,objective,25)
    if get(w,128)!=0:
        return get(w,128)
    cap=integer(s,w,get(w,0),a,node,MAX)
    if get(w,520)==0:
        return 17
    put(w,192,cap)
    i=0
    while i<4:
        row=choose(i<2,get(w,320),get(w,312))
        node=required(s,w,a,row,26+(i&1))
        if get(w,128)!=0:
            return get(w,128)
        value=integer(s,w,get(w,0),a,node,MAX)
        if get(w,520)==0:
            return 18+i
        put(w,640+i*8,value)
        i=i+1
    lower=0
    if get(w,640)>get(w,648):
        lower=get(w,640)-get(w,648)
    upper=get(w,656)+get(w,664)
    costs=field(s,report,0,11)
    actual=integer(s,w,get(w,16),report,field(s,report,costs,12),MAX)
    if get(w,520)==0:
        return BAD
    total=integer(s,w,get(w,16),report,field(s,report,costs,13),MAX)
    if get(w,520)==0:
        return BAD
    put(w,176,actual)
    put(w,184,total)
    multiply(w,672,lower,calls)
    multiply(w,688,upper,calls)
    add_pair(w,704,get(w,688),get(w,696),total,0)
    difference(w,720,get(w,672),get(w,680),get(w,704),get(w,712))
    if get(w,720)!=0 or (get(w,728)==0 and get(w,736)==0) or total>cap:
        return 22
    margin=field(s,report,0,17)
    if integer_equals_pair(s,w,get(w,16),report,margin,get(w,728),get(w,736))==False:
        return 22
    put(w,200,get(w,728))
    put(w,208,get(w,736))
    put(w,216,field(s,report,0,9))
    put(w,168,3)
    return 0

def prepare_budget(s:readbuf,w:mutbuf) -> u64:
    started=read64(s,296)
    handoff=read64(s,304)
    actual=get(w,176)
    if handoff<started or handoff-started<actual:
        return BAD
    elapsed=handoff-started-actual
    add_pair(w,752,elapsed,0,read64(s,288),0)
    put(w,264,get(w,752))
    put(w,272,get(w,760))
    difference(w,768,get(w,200),get(w,208),get(w,752),get(w,760))
    add_pair(w,792,get(w,752),get(w,760),get(w,184),0)
    difference(w,808,get(w,192),0,get(w,792),get(w,800))
    put(w,280,get(w,768))
    put(w,288,get(w,776))
    put(w,296,get(w,784))
    budget=0
    if get(w,768)==0 and (get(w,784)!=0 or get(w,776)>1) and get(w,808)==0:
        if get(w,824)==0:
            budget=get(w,816)
            if get(w,784)==0 and get(w,776)-1<budget:
                budget=get(w,776)-1
    put(w,304,budget)
    return 0

def required(s:readbuf,w:mutbuf,a:u64,node:u64,id:u64) -> u64:
    kind=nodeword(s,a,node,0)
    if kind!=6:
        if kind==4:
            put(w,128,104)
        elif kind==5:
            put(w,128,105)
        else:
            raw=choose(a==get(w,8),get(w,0),get(w,16))
            put(w,128,100+scalar_category(s,raw,a,node))
        return NONE
    result=field(s,a,node,id)
    if result==NONE:
        put(w,128,200+id)
    return result

def scalar_category(s:readbuf,raw:u64,a:u64,node:u64) -> u64:
    kind=nodeword(s,a,node,0)
    if kind==1 or kind==2:
        return 1
    if kind==3:
        return choose(integer_node(s,raw,a,node),2,3)
    return 0

def exact_zero(s:readbuf,w:mutbuf,raw:u64,a:u64,node:u64) -> bool:
    value=integer(s,w,raw,a,node,MAX)
    return get(w,520)!=0 and value==0

def integer_node(s:readbuf,raw:u64,a:u64,node:u64) -> bool:
    if nodeword(s,a,node,0)!=3:
        return False
    at=raw+nodeword(s,a,node,24)
    n=nodeword(s,a,node,32)
    if n==0:
        return False
    i=0
    if byte(s,at)==45:
        i=1
    if i==n:
        return False
    while i<n:
        c=byte(s,at+i)
        if c<48 or c>57:
            return False
        i=i+1
    return True

def number_equals_decimal(s:readbuf,w:mutbuf,raw:u64,a:u64,node:u64,wanted:u64,n:u64) -> bool:
    kind=nodeword(s,a,node,0)
    if kind==1 or kind==2:
        return n==1 and byte(s,wanted)==47+kind
    if kind!=3:
        return False
    at=raw+nodeword(s,a,node,24)
    size=nodeword(s,a,node,32)
    if integer_node(s,raw,a,node):
        if size==2 and byte(s,at)==45 and byte(s,at+1)==48:
            return n==1 and byte(s,wanted)==48
        return same(s,at,size,wanted,n)
    if widen(decimal_convert(s,w,at,size))!=8:
        return False
    bits=get(w,length(w)-8192+8000)
    if (bits&9223372036854775807)==0:
        return n==1 and byte(s,wanted)==48
    if (bits>>63)!=0:
        return False
    exponent=(bits>>52)&2047
    if exponent<1023 or exponent==2047:
        return False
    mantissa=(bits&4503599627370495)|4503599627370496
    shift=exponent-1023
    if shift<=52:
        amount=52-shift
        if (mantissa&((1<<amount)-1))!=0:
            return False
        mantissa=mantissa>>amount
        shift=0
    else:
        shift=shift-52
    used=word_decimal(w,2048,mantissa)
    while shift>0:
        carry=0
        i=0
        while i<used:
            value=byte(w,2048+i)*2+carry
            store(w,2048+i,value%10)
            carry=value//10
            i=i+1
        if carry!=0:
            store(w,2048+used,carry)
            used=used+1
        shift=shift-1
    if used!=n:
        return False
    i=0
    while i<n:
        if byte(s,wanted+i)!=48+byte(w,2048+n-1-i):
            return False
        i=i+1
    return True

def word_decimal(w:mutbuf,at:u64,value:u64) -> u64:
    size=0
    while value!=0 or size==0:
        store(w,at+size,value%10)
        value=value//10
        size=size+1
    return size

def integer_equals_pair(s:readbuf,w:mutbuf,raw:u64,a:u64,node:u64,low:u64,high:u64) -> bool:
    if integer_node(s,raw,a,node)==False:
        return False
    size=0
    while high!=0 or low!=0 or size==0:
        carry=high%10
        high=high//10
        upper=(carry<<32)|(low>>32)
        first=upper//10
        carry=upper%10
        lower=(carry<<32)|(low&MASK)
        low=(first<<32)|(lower//10)
        store(w,3072+size,lower%10)
        size=size+1
    at=raw+nodeword(s,a,node,24)
    n=nodeword(s,a,node,32)
    if n!=size:
        return False
    i=0
    while i<n:
        if byte(s,at+i)!=48+byte(w,3072+n-1-i):
            return False
        i=i+1
    return True

def field_text(s:readbuf,a:u64,node:u64,at:u64,n:u64) -> u64:
    if nodeword(s,a,node,0)!=6:
        return NONE
    child=nodeword(s,a,node,24)
    while child!=NONE:
        if same(s,a+nodeword(s,a,child,40),nodeword(s,a,child,48),at,n):
            return child
        child=nodeword(s,a,child,16)
    return NONE
'''
def source_program():
    wanted={'arena_valid','nodeword','read64','get','put','zero','choose','same','field','string_id','same_string_node','integer','digest_binding','hex_digit','decimal_valid','widen'}
    helpers=[ast.unparse(n)for n in ast.parse(admission_program()).body if n.name in wanted]
    assert len(helpers)==len(wanted)
    arithmetic=[ast.unparse(n)for n in ast.parse(cost_source).body if n.name in {'multiply','add_pair','difference'}]
    text=SOURCE+'\n'+'\n'.join(helpers+arithmetic)+'\n'+decimal_program().replace('if n == 0 or n > 8388608:','if n == 0:')
    groups=[list(LABELS.items())[i:i+8]for i in range(0,len(LABELS),8)]
    lines=['def label(s:readbuf,at:u64,n:u64) -> u64:']
    for i in range(len(groups)):lines +=[f'    value=label_{i}(s,at,n)','    if value!=0:','        return value']
    lines +=['    return 0'];text+='\n'+'\n'.join(lines)+'\n'
    for i,group in enumerate(groups):
        lines=[f'def label_{i}(s:readbuf,at:u64,n:u64) -> u64:']
        for ident,label in group:
            raw=label.encode();parts=[f'n=={len(raw)}']+[f'readn(s,at+{j},{len(raw[j:j+8])})=={int.from_bytes(raw[j:j+8],"little")}'for j in range(0,len(raw),8)]
            lines+=['    if '+' and '.join(parts)+':',f'        return {ident}']
        lines+=['    return 0'];text+='\n'+'\n'.join(lines)+'\n'
    text+='\ndef readn(s:readbuf,at:u64,n:u64) -> u64:\n    result=0\n    i=0\n    while i<n:\n        result=result|(byte(s,at+i)<<(i*8))\n        i=i+1\n    return result\n'
    for key,value in sorted(C.items(),key=lambda x:-len(x[0])):text=re.sub(r'\b'+key+r'\b',str(value),text)
    return text
def program():return document(source_program(),'background_optimizer_decision')
def main():
    tree=program();target=ROOT/'examples/hia_bootstrap/background_optimizer_decision.hepta'
    target.write_text(render_assembly(tree));print(target.name,target.stat().st_size,len(tree['functions']),sum(len(f['blocks'])for f in tree['functions']),sum(len(b['ops'])for f in tree['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
