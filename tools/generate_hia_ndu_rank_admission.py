"""Typed NDU caller admission from the caller's own native JSON arenas."""
from pathlib import Path
import ast,re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_system_jobctl_request import document
from tools.generate_hia_native_public_proof_receipt import POLICY
from tools import generate_hia_ndu_rank_selection as selection
ROOT=Path(__file__).resolve().parents[1]
C={'REQUEST':int.from_bytes(b'HIANRA01','little'),'REPLY':int.from_bytes(b'HIANDR01','little'),'BAD':4294967293,'SHORT':4294967294,'NONE':(1<<64)-1,'MAX':(1<<63)-1,'R':2048,'ROWS':8192,'SEEN':131072,'JSON':65536,'SIXTY':4633641066610819072}
LABELS={1:'function',2:'generation',3:'timeout_ms',4:'bridge_timeout_s',5:'objective',6:'candidates',7:'observations',8:'bridge',9:'expected_calls',10:'resource_cap_ns',11:'target',12:'measurement_profile',13:'id',14:'action',15:'program',16:'runtime_ns',17:'uncertainty_ns',18:'search_ns',19:'program_sha256',20:'exports',21:'functions',22:'name',23:'params',24:'returns',25:'type',101:'abstain'}
for i,name in enumerate(['bool','i16','i32','i64','i8','isize','u16','u32','u64','u8','unit','usize'],201):LABELS[i]=name
ERRORS={1:'function must name an existing public scalar entrypoint',2:'generation must be a bounded exact integer',3:'timeout_ms must be a bounded exact integer',4:'bridge timeout must be finite and at most sixty seconds',5:'objective has an unexpected shape',6:'expected_calls must be a bounded exact integer',7:'resource_cap_ns must be a bounded exact integer',8:'objective target must be bounded text',9:'objective measurement_profile must be bounded text',10:'at most thirty-two finite proposals are allowed',11:'candidate requires only id, action and program',12:'candidate id is invalid, reserved or duplicated',13:'candidate action must be bounded text',14:'observations must cover exactly abstain and all proposals',15:'observation has an unexpected shape',16:'observation must identify exact canonical program bytes',17:'runtime_ns must be a bounded exact integer',18:'uncertainty_ns must be a bounded exact integer',19:'search_ns must be a bounded exact integer',20:'baseline measurement belongs to a different program',21:'aggregate measured search cost must be a bounded exact integer'}
SOURCE=r'''
def rank_admission(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)<128 or length(w)<131072 or read64(s,0)!=REQUEST or read64(s,8)>3:
        return BAD
    if read64(s,96)>1 or read64(s,104)!=0 or read64(s,112)!=0 or read64(s,120)!=0:
        return BAD
    action=read64(s,8)
    if action!=1 and (read64(s,56)!=0 or read64(s,96)!=0):
        return BAD
    if action<2 and read64(s,16)!=0:
        return BAD
    at=128
    i=0
    while i<2:
        jn=read64(s,24+i*16)
        an=read64(s,32+i*16)
        if jn==0 or an==0 or jn>length(s)-at:
            return BAD
        put(w,i*16,at)
        at=at+jn
        put(w,i*16+8,at)
        if an>length(s)-at or arena_valid(s,w,at,an,jn)==False:
            return BAD
        at=at+an
        i=i+1
    if at!=length(s) or nodeword(s,get(w,8),0,0)!=6 or nodeword(s,get(w,24),0,0)!=6:
        return BAD
    if length(o)<8192:
        return SHORT
    zero_range(w,R,1024)
    zero_range(w,ROWS,3168)
    put(w,R,REPLY)
    put(w,R+24,read64(s,16))
    error=0
    if action<2:
        error=options(s,w,action)
    elif action==2:
        error=candidate(s,w,read64(s,16))
    else:
        error=observations(s,w)
    put(w,512,0)
    if error!=0:
        put(w,R+8,1)
        put(w,R+16,error)
        literal(w,1)
        error_literal(w,error)
        literal(w,2)
        put(w,R+248,get(w,512))
    zero(o,8192)
    copy_to(w,R,o,0,1024)
    if error!=0:
        copy_to(w,JSON,o,1024,get(w,512))
    elif action==3:
        copy_to(w,ROWS,o,2048,3168)
    return 8192

def options(s:readbuf,w:mutbuf,action:u64) -> u64:
    a=get(w,8)
    function=field(s,a,0,1)
    if scalar_entrypoint(s,w,function)==False:
        return 1
    n=nodeword(s,a,function,32)
    put(w,R+96,n)
    copy_input(s,a+nodeword(s,a,function,24),w,R+512,n)
    generation=1
    node=field(s,a,0,2)
    if node!=NONE:
        generation=integer(s,w,get(w,0),a,node,NONE)
        if get(w,520)==0 or generation==0:
            return 2
    put(w,R+32,generation)
    timeout=2000
    node=field(s,a,0,3)
    if node!=NONE:
        timeout=integer(s,w,get(w,0),a,node,5000)
        if get(w,520)==0 or timeout==0:
            return 3
    put(w,R+40,timeout)
    node=field(s,a,0,4)
    if node==NONE:
        put(w,R+64,4621819117588971520)
    else:
        if nodeword(s,a,node,0)!=3:
            return 4
        start=get(w,0)+nodeword(s,a,node,24)
        extent=nodeword(s,a,node,32)
        fractional=False
        pos=0
        while pos<extent:
            ch=byte(s,start+pos)
            if ch==46 or ch==101 or ch==69:
                fractional=True
            pos=pos+1
        if fractional:
            if action==0:
                put(w,R+8,2)
                put(w,R+168,nodeword(s,a,node,24))
                put(w,R+176,extent)
                return 0
            bits=read64(s,56)
            if read64(s,96)!=0 or bits==0 or bits>SIXTY:
                return 4
            put(w,R+64,bits)
        else:
            value=integer(s,w,get(w,0),a,node,60)
            if get(w,520)==0 or value==0:
                return 4
            put(w,R+64,integer_bits(value))
            put(w,R+72,1)
    objective=field(s,a,0,5)
    if nodeword(s,a,objective,0)!=6 or nodeword(s,a,objective,32)!=4:
        return 5
    key=9
    while key<=12:
        if field(s,a,objective,key)==NONE:
            return 5
        key=key+1
    calls=integer(s,w,get(w,0),a,field(s,a,objective,9),MAX)
    if get(w,520)==0 or calls==0:
        return 6
    cap=integer(s,w,get(w,0),a,field(s,a,objective,10),MAX)
    if get(w,520)==0:
        return 7
    put(w,R+48,calls)
    put(w,R+56,cap)
    key=11
    while key<=12:
        if bounded_text(s,a,field(s,a,objective,key),256)==False:
            return key-3
        key=key+1
    put(w,R+104,objective)
    put(w,R+112,field(s,a,0,8))
    put(w,R+120,field(s,a,0,6))
    put(w,R+128,field(s,a,0,7))
    return 0

def candidate(s:readbuf,w:mutbuf,index:u64) -> u64:
    a=get(w,8)
    candidates=field(s,a,0,6)
    count=nodeword(s,a,candidates,32)
    if nodeword(s,a,candidates,0)!=5 or count>32:
        return 10
    put(w,R+80,count)
    if index>=count:
        put(w,R+8,3)
        return 0
    node=nodeword(s,a,candidates,24)
    i=0
    while i<index:
        node=nodeword(s,a,node,16)
        i=i+1
    if nodeword(s,a,node,0)!=6 or nodeword(s,a,node,32)!=3:
        return 11
    key=13
    while key<=15:
        if field(s,a,node,key)==NONE:
            return 11
        key=key+1
    id=field(s,a,node,13)
    if valid_id(s,a,id)==False or string_id(s,a,id)==101:
        return 12
    previous=nodeword(s,a,candidates,24)
    i=0
    while i<index:
        if same_node(s,a,id,a,field(s,a,previous,13)):
            return 12
        previous=nodeword(s,a,previous,16)
        i=i+1
    name=field(s,a,node,14)
    if bounded_text(s,a,name,256)==False:
        return 13
    program=field(s,a,node,15)
    kind=nodeword(s,a,program,0)
    put(w,R+136,id)
    put(w,R+144,name)
    put(w,R+152,program)
    put(w,R+160,kind)
    slot=choose(kind>=4,56,24)
    put(w,R+168,nodeword(s,a,program,slot))
    put(w,R+176,nodeword(s,a,program,slot+8))
    if kind==4:
        put(w,R+224,nodeword(s,a,program,24))
        put(w,R+232,nodeword(s,a,program,32))
    return 0

def observations(s:readbuf,w:mutbuf) -> u64:
    a=get(w,8)
    candidates=field(s,a,0,6)
    count=nodeword(s,a,candidates,32)
    if nodeword(s,a,candidates,0)!=5 or count>32:
        return 10
    node=field(s,a,0,7)
    if nodeword(s,a,node,0)!=6 or nodeword(s,a,node,32)!=count+1:
        return 14
    child=nodeword(s,a,node,24)
    i=0
    while i<count+1:
        found=observation_index(s,w,child,candidates,count)
        if found==NONE:
            return 14
        put(w,ROWS+found*96,child)
        child=nodeword(s,a,child,16)
        i=i+1
    child=nodeword(s,a,node,24)
    total=0
    high=0
    i=0
    while i<count+1:
        found=observation_index(s,w,child,candidates,count)
        row=ROWS+found*96
        if nodeword(s,a,child,0)!=6 or nodeword(s,a,child,32)!=4:
            return 15
        key=16
        while key<=19:
            if field(s,a,child,key)==NONE:
                return 15
            key=key+1
        id=field(s,a,child,19)
        if digest(s,a,id)==False:
            return 16
        put(w,row+32,id)
        key=16
        while key<=18:
            value=integer(s,w,get(w,0),a,field(s,a,child,key),MAX)
            if get(w,520)==0:
                return key+1
            put(w,row+8+(key-16)*8,value)
            if key==18:
                new=total+value
                if new<total:
                    high=high+1
                total=new
            key=key+1
        child=nodeword(s,a,child,16)
        i=i+1
    if digest_binding(s,a,get(w,ROWS+32),64)==False:
        return 20
    if high!=0 or total>MAX:
        return 21
    put(w,R+80,count)
    put(w,R+216,total)
    return 0

def observation_index(s:readbuf,w:mutbuf,node:u64,candidates:u64,count:u64) -> u64:
    a=get(w,8)
    start=a+nodeword(s,a,node,40)
    extent=nodeword(s,a,node,48)
    if label(s,start,extent)==101:
        return 0
    child=nodeword(s,a,candidates,24)
    i=0
    while i<count:
        id=field(s,a,child,13)
        if nodeword(s,a,id,0)==4 and same(s,start,extent,a+nodeword(s,a,id,24),nodeword(s,a,id,32)):
            return i+1
        child=nodeword(s,a,child,16)
        i=i+1
    return NONE

def scalar_entrypoint(s:readbuf,w:mutbuf,function:u64) -> bool:
    a=get(w,8)
    core=get(w,24)
    if nodeword(s,a,function,0)!=4 or nodeword(s,a,function,32)>128:
        return False
    exports=field(s,core,0,20)
    if exports!=NONE:
        if nodeword(s,core,exports,0)!=5:
            return False
        child=nodeword(s,core,exports,24)
        while child!=NONE:
            if same_node(s,a,function,core,child):
                return True
            child=nodeword(s,core,child,16)
        return False
    functions=field(s,core,0,21)
    if nodeword(s,core,functions,0)!=5:
        return False
    child=nodeword(s,core,functions,24)
    while child!=NONE:
        if same_node(s,a,function,core,field(s,core,child,22)):
            return scalar_signature(s,core,child)
        child=nodeword(s,core,child,16)
    return False

def scalar_signature(s:readbuf,core:u64,function:u64) -> bool:
    key=23
    while key<=24:
        array=field(s,core,function,key)
        if nodeword(s,core,array,0)!=5:
            return False
        child=nodeword(s,core,array,24)
        while child!=NONE:
            type=child
            if key==23:
                type=field(s,core,child,25)
            id=string_id(s,core,type)
            if id<201 or id>212:
                return False
            child=nodeword(s,core,child,16)
        key=key+1
    return True

def bounded_text(s:readbuf,a:u64,node:u64,maximum:u64) -> bool:
    if nodeword(s,a,node,0)!=4:
        return False
    start=a+nodeword(s,a,node,24)
    n=nodeword(s,a,node,32)
    count=0
    i=0
    while i<n:
        if (byte(s,start+i)&192)!=128:
            count=count+1
            if count>maximum:
                return False
        i=i+1
    return count!=0

def integer_bits(value:u64) -> u64:
    width=0
    copy=value
    while copy!=0:
        width=width+1
        copy=copy>>1
    return ((1022+width)<<52)|((value<<(53-width))&4503599627370495)

def copy_input(s:readbuf,at:u64,w:mutbuf,target:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(w,target+i,byte(s,at+i))
        i=i+1
    return 0

def copy_to(w:mutbuf,at:u64,o:mutbuf,target:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(o,target+i,byte(w,at+i))
        i=i+1
    return 0

def zero_range(w:mutbuf,at:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(w,at+i,0)
        i=i+1
    return 0

def emit(w:mutbuf,value:u64) -> u64:
    at=get(w,512)
    if at<1024:
        store(w,JSON+at,value)
    put(w,512,at+1)
    return 0
'''
def source_program():
    text=SOURCE
    wanted={'integer','same_node','same','field','string_id','nodeword','read64','readn','get','put','zero','choose','valid_id','digest','digest_binding'}
    for node in ast.parse(selection.source_program()).body:
        if node.name in wanted:text+='\n'+ast.unparse(node)+'\n'
    arena='def arena_valid('+POLICY.split('def arena_valid(',1)[1].split('\ndef nodeword(',1)[0]
    old='    first=64+72*count\n    if count==0 or count>131073 or first>size:\n        return False'
    new='    if count==0 or count>(size-64)//72 or count>length(w)-SEEN:\n        return False\n    first=64+72*count'
    assert arena.count(old)==1;arena=arena.replace(old,new);text+='\n'+arena
    lines=['def label(s:readbuf,at:u64,n:u64) -> u64:']
    for ident,label in LABELS.items():
        raw=label.encode();parts=[f'n=={len(raw)}']+[f'readn(s,at+{i},{len(raw[i:i+8])})=={int.from_bytes(raw[i:i+8],"little")}' for i in range(0,len(raw),8)]
        lines+=['    if '+' and '.join(parts)+':',f'        return {ident}']
    lines.append('    return 0');text+='\n'+'\n'.join(lines)+'\n'
    text+=selection.literal_function('literal',{1:'{"type":"OptimizationRejected","message":"E_HIA_NDU: ',2:'"}'})+selection.literal_function('error_literal',ERRORS)
    for key,value in sorted(C.items(),key=lambda x:-len(x[0])):text=re.sub(r'\b'+key+r'\b',str(value),text)
    return text
def program():return document(source_program(),'ndu_rank_admission')
if __name__=='__main__':
    target=ROOT/'examples/hia_bootstrap/ndu_rank_admission.hepta';target.write_text(render_assembly(program()));print(target.name,target.stat().st_size,flush=True)
