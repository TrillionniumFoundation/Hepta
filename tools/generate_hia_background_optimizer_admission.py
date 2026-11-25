"""Ordered private admission stages for the background coordinator.

These stages consume freshly owned JSON and actual runtime snapshot payloads.
They are not public proof or runtime authority. The enclosing native owner
retains its actual runtime capability and performs path and Core callbacks
between the stages in the original constructor/submit order.
"""
from pathlib import Path
import ast,json,re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
from tools.generate_hia_worker_request import decimal_program
from tools.generate_hia_background_optimizer_structure import SOURCE as structure_source
ROOT=Path(__file__).resolve().parents[1]
LABELS={1:'max_pending',2:'timeout_ms',3:'bridge_timeout_s',4:'bridge',5:'binary',6:'build_receipt',7:'function',8:'exports',9:'functions',10:'name',11:'params',12:'returns',13:'type',14:'objective',15:'target',16:'observations',17:'abstain',18:'program_sha256',19:'wait',20:'cancel_pending',50:'x86_64-unknown-linux-gnu'}
for i,name in enumerate(['bool','i16','i32','i64','i8','isize','u16','u32','u64','u8','unit','usize'],100):LABELS[i]=name
ERRORS={
1:'a ScalarMultiversionRuntime is required',
2:'max_pending must be an exact integer from one to eight',
3:'translation validation timeout must be 1..5000 milliseconds',
4:'bridge timeout must be finite and at most sixty seconds',
5:'bridge requires binary and build_receipt paths',
6:'function must name a public scalar entrypoint',
7:'supplied immutable baseline does not bind the runtime baseline',
8:'runtime is closed',
9:'current native source is untracked; observations cannot be silently rebased',
10:'objective target must match the native runtime target',
11:'incumbent observation does not bind the current source',
12:'shutdown flags must be exact booleans',
13:'background coordinator has one shutdown owner',
}
C={'INPUT':int.from_bytes(b'HIABAD01','little'),'OUTPUT':int.from_bytes(b'HIABAR01','little'),
 'SNAPSHOT':int.from_bytes(b'HIAMVBS1','little'),'ARENA':5208772604367785521,'NONE':(1<<64)-1,'BAD':4294967293,'SHORT':4294967294}
SOURCE=r'''
def background_optimizer_admission(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)<256 or length(w)<131072 or read64(s,0)!=INPUT:
        return BAD
    if length(o)<512:
        return SHORT
    if admission_frame(s,w)!=0:
        return BAD
    mode=read64(s,8)
    error=0
    if mode==0:
        error=options(s,w,get(w,0))
    elif mode==1:
        error=function_gate(s,w,get(w,0),get(w,8))
    elif mode==2:
        error=constructor_binding(s,w,get(w,16))
    elif mode==3:
        error=objective_gate(s,get(w,0))
    elif mode==4:
        error=current(s,w,get(w,16))
    elif mode==5:
        error=incumbent_gate(s,get(w,0))
    elif mode==6:
        error=same_snapshot(s,w,get(w,16))
    elif mode==7:
        error=shutdown_flags(s,w,get(w,0))
    elif mode==8:
        error=13
    else:
        error=1
    return finish(o,w,error)

def constructor_binding(s:readbuf,w:mutbuf,at:u64) -> u64:
    flags=read64(s,at+16)
    if (flags&1)!=0 or (flags&2)==0 or same(s,at+64,32,80,32)==False or same(s,at+96,32,112,32)==False:
        return 7
    return current(s,w,at)

def objective_gate(s:readbuf,a:u64) -> u64:
    objective=field(s,a,0,14)
    if nodeword(s,a,objective,0)!=6 or string_id(s,a,field(s,a,objective,15))!=50:
        return 10
    return 0

def incumbent_gate(s:readbuf,a:u64) -> u64:
    observed=field(s,a,0,16)
    incumbent=field(s,a,observed,17)
    if nodeword(s,a,observed,0)!=6 or nodeword(s,a,incumbent,0)!=6 or digest_binding(s,a,field(s,a,incumbent,18),80)==False:
        return 11
    return 0

def same_snapshot(s:readbuf,w:mutbuf,at:u64) -> u64:
    flags=read64(s,at+16)
    if (flags&1)==0 and (flags&4)!=0:
        if same(s,at+256,read64(s,at+24),get(w,24),read64(s,48)) and same(s,at+256+read64(s,at+24),read64(s,at+32),get(w,32),read64(s,56)):
            put(w,184,1)
    return 0

def shutdown_flags(s:readbuf,w:mutbuf,a:u64) -> u64:
    wait=strict_bool(s,a,field(s,a,0,19))
    cancel=strict_bool(s,a,field(s,a,0,20))
    if wait==2 or cancel==2:
        return 12
    put(w,128,wait)
    put(w,136,cancel)
    return 0

def strict_bool(s:readbuf,a:u64,node:u64) -> u64:
    if node==NONE:
        return 1
    kind=nodeword(s,a,node,0)
    if kind==1:
        return 0
    if kind==2:
        return 1
    return 2

def admission_frame(s:readbuf,w:mutbuf) -> u64:
    mode=read64(s,8)
    if mode>9:
        return BAD
    i=208
    while i<256:
        if read64(s,i)!=0:
            return BAD
        i=i+8
    on=read64(s,16)
    oa=read64(s,24)
    cn=read64(s,32)
    ca=read64(s,40)
    gn=read64(s,48)
    en=read64(s,56)
    sn=read64(s,64)
    if read64(s,72)!=0:
        return BAD
    at=256
    if on>length(s)-at:
        return BAD
    a=at+on
    if oa>length(s)-a or (on==0)!=(oa==0):
        return BAD
    if oa!=0 and arena_valid(s,w,a,oa,on)==False:
        return BAD
    at=a+oa
    if cn>length(s)-at:
        return BAD
    c=at+cn
    if ca>length(s)-c or (cn==0)!=(ca==0):
        return BAD
    if ca!=0 and arena_valid(s,w,c,ca,cn)==False:
        return BAD
    at=c+ca
    if gn>length(s)-at:
        return BAD
    gen=at
    at=at+gn
    if en>length(s)-at:
        return BAD
    epoch=at
    at=at+en
    if sn!=length(s)-at:
        return BAD
    if sn!=0 and snapshot_valid(s,at,sn)==False:
        return BAD
    if gn!=0 and decimal_valid(s,gen,gn)==False:
        return BAD
    if en!=0 and decimal_valid(s,epoch,en)==False:
        return BAD
    if (mode==0 or mode==1 or mode==3 or mode==5 or mode==7) and (oa==0 or nodeword(s,a,0,0)!=6):
        return BAD
    if mode==1 and (ca==0 or nodeword(s,c,0,0)!=6):
        return BAD
    if (mode==2 or mode==4 or mode==6) and sn==0:
        return BAD
    if mode==6 and (gn==0 or en==0):
        return BAD
    zero(w,0,1024)
    put(w,0,a)
    put(w,8,c)
    put(w,16,at)
    put(w,24,gen)
    put(w,32,epoch)
    return 0

def options(s:readbuf,w:mutbuf,a:u64) -> u64:
    node=field(s,a,0,1)
    maximum=8
    if node!=NONE:
        maximum=integer(s,w,256,a,node,8)
        if get(w,520)==0 or maximum==0:
            return 2
    put(w,128,maximum)
    node=field(s,a,0,2)
    timeout=2000
    if node!=NONE:
        timeout=integer(s,w,256,a,node,5000)
        if get(w,520)==0 or timeout==0:
            return 3
    put(w,136,timeout)
    node=field(s,a,0,3)
    bits=4621819117588971520
    exact=0
    if node!=NONE:
        if nodeword(s,a,node,0)!=3:
            return 4
        at=256+nodeword(s,a,node,24)
        n=nodeword(s,a,node,32)
        value=integer(s,w,256,a,node,60)
        if get(w,520)!=0:
            if value==0:
                return 4
            exact=1
        if widen(decimal_convert(s,w,at,n))!=8:
            return 4
        bits=get(w,length(w)-8192+8000)
        if bits==0 or bits>4633641066610819072:
            return 4
    put(w,144,bits)
    put(w,152,exact)
    bridge=field(s,a,0,4)
    if nodeword(s,a,bridge,0)!=6 or nodeword(s,a,bridge,32)!=2 or field(s,a,bridge,5)==NONE or field(s,a,bridge,6)==NONE:
        return 5
    first=nodeword(s,a,bridge,24)
    put(w,160,first)
    put(w,168,nodeword(s,a,first,16))
    put(w,192,field(s,a,0,7))
    return 0

def function_gate(s:readbuf,w:mutbuf,a:u64,c:u64) -> u64:
    name=field(s,a,0,7)
    if nodeword(s,a,name,0)!=4:
        return 6
    put(w,192,name)
    exports=field(s,c,0,8)
    if exports!=NONE:
        if nodeword(s,c,exports,0)!=5:
            return BAD
        child=nodeword(s,c,exports,24)
        while child!=NONE:
            if same_string_node(s,a,name,c,child):
                return 0
            child=nodeword(s,c,child,16)
        return 6
    functions=field(s,c,0,9)
    if nodeword(s,c,functions,0)!=5:
        return BAD
    child=nodeword(s,c,functions,24)
    while child!=NONE:
        if same_string_node(s,a,name,c,field(s,c,child,10)) and scalar_signature(s,c,child):
            return 0
        child=nodeword(s,c,child,16)
    return 6

def scalar_signature(s:readbuf,a:u64,fn:u64) -> bool:
    params=field(s,a,fn,11)
    returns=field(s,a,fn,12)
    if nodeword(s,a,params,0)!=5 or nodeword(s,a,returns,0)!=5:
        return False
    child=nodeword(s,a,params,24)
    while child!=NONE:
        id=string_id(s,a,field(s,a,child,13))
        if id<100 or id>=112:
            return False
        child=nodeword(s,a,child,16)
    child=nodeword(s,a,returns,24)
    while child!=NONE:
        id=string_id(s,a,child)
        if id<100 or id>=112:
            return False
        child=nodeword(s,a,child,16)
    return True

def current(s:readbuf,w:mutbuf,snapshot:u64) -> u64:
    flags=read64(s,snapshot+16)
    if (flags&1)!=0:
        return 8
    if (flags&4)!=0:
        if same(s,snapshot+128,32,80,32) and same(s,snapshot+160,32,112,32):
            put(w,176,0)
            return 0
        if same(s,snapshot+128,32,144,32) and same(s,snapshot+160,32,176,32):
            put(w,176,1)
            return 0
    return 9

def snapshot_valid(s:readbuf,at:u64,n:u64) -> bool:
    if n<256 or read64(s,at)!=SNAPSHOT or read64(s,at+8)!=0 or read64(s,at+16)>7 or read64(s,at+40)!=n or read64(s,at+48)!=0 or read64(s,at+56)!=0:
        return False
    i=224
    while i<256:
        if read64(s,at+i)!=0:
            return False
        i=i+8
    gn=read64(s,at+24)
    en=read64(s,at+32)
    if gn>n-256 or en!=n-256-gn or en==0 or decimal_valid(s,at+256+gn,en)==False:
        return False
    if (read64(s,at+16)&4)!=0:
        return gn!=0 and decimal_valid(s,at+256,gn)
    return gn==0

def decimal_valid(s:readbuf,at:u64,n:u64) -> bool:
    if n==0 or (n>1 and byte(s,at)==48):
        return False
    i=0
    while i<n:
        value=byte(s,at+i)
        if value<48 or value>57:
            return False
        i=i+1
    return True

def integer(s:readbuf,w:mutbuf,raw:u64,a:u64,node:u64,maximum:u64) -> u64:
    put(w,520,0)
    if nodeword(s,a,node,0)!=3:
        return 0
    start=raw+nodeword(s,a,node,24)
    n=nodeword(s,a,node,32)
    if n==2 and byte(s,start)==45 and byte(s,start+1)==48:
        put(w,520,1)
        return 0
    value=0
    i=0
    if n==0:
        return 0
    while i<n:
        ch=byte(s,start+i)
        if ch<48 or ch>57 or value>maximum//10 or (value==maximum//10 and ch-48>maximum%10):
            return 0
        value=value*10+ch-48
        i=i+1
    put(w,520,1)
    return value

def field(s:readbuf,a:u64,node:u64,id:u64) -> u64:
    if nodeword(s,a,node,0)!=6:
        return NONE
    child=nodeword(s,a,node,24)
    while child!=NONE:
        if label(s,a+nodeword(s,a,child,40),nodeword(s,a,child,48))==id:
            return child
        child=nodeword(s,a,child,16)
    return NONE

def string_id(s:readbuf,a:u64,node:u64) -> u64:
    if nodeword(s,a,node,0)!=4:
        return NONE
    return label(s,a+nodeword(s,a,node,24),nodeword(s,a,node,32))

def same_string_node(s:readbuf,a:u64,x:u64,b:u64,y:u64) -> bool:
    if nodeword(s,a,x,0)!=4 or nodeword(s,b,y,0)!=4:
        return False
    return same(s,a+nodeword(s,a,x,24),nodeword(s,a,x,32),b+nodeword(s,b,y,24),nodeword(s,b,y,32))

def same(s:readbuf,a:u64,an:u64,b:u64,bn:u64) -> bool:
    if an!=bn:
        return False
    i=0
    while i<an:
        if byte(s,a+i)!=byte(s,b+i):
            return False
        i=i+1
    return True

def digest_binding(s:readbuf,a:u64,node:u64,at:u64) -> bool:
    if nodeword(s,a,node,0)!=4 or nodeword(s,a,node,32)!=64:
        return False
    source=a+nodeword(s,a,node,24)
    i=0
    while i<32:
        ch=byte(s,at+i)
        if byte(s,source+i*2)!=hex_digit(ch>>4) or byte(s,source+i*2+1)!=hex_digit(ch&15):
            return False
        i=i+1
    return True

def hex_digit(value:u64) -> u64:
    return choose(value<10,48+value,87+value)

def finish(o:mutbuf,w:mutbuf,error:u64) -> u32:
    if error==BAD:
        return BAD
    zero(o,0,128)
    put(o,0,OUTPUT)
    put(o,8,choose(error==0,0,1))
    put(o,16,error)
    i=128
    while i<=192:
        put(o,i-96,get(w,i))
        i=i+8
    if error!=0:
        put(o,24,error_json(o,error))
    return 0

def widen(value:u32) -> u64:
    return value
'''
def source_program():
    wanted={'arena_valid','nodeword','read64','get','put','zero','choose'}
    helpers=[ast.unparse(n).replace('SEEN','0') for n in ast.parse(structure_source).body if n.name in wanted]
    text=SOURCE+'\n'+'\n'.join(helpers)+'\n'+decimal_program().replace('if n == 0 or n > 8388608:','if n == 0:')
    groups=[list(LABELS.items())[i:i+8] for i in range(0,len(LABELS),8)]
    lines=['def label(s:readbuf,at:u64,n:u64) -> u64:']
    for index in range(len(groups)):
        lines += [f'    value=label_{index}(s,at,n)','    if value!=0:','        return value']
    lines += ['    return 0']
    text+='\n'+'\n'.join(lines)+'\n'
    for index,group in enumerate(groups):
        lines=[f'def label_{index}(s:readbuf,at:u64,n:u64) -> u64:']
        for ident,name in group:
            raw=name.encode();parts=[f'n=={len(raw)}']+[f'byte(s,at+{i})=={b}'for i,b in enumerate(raw)]
            lines+=['    if '+' and '.join(parts)+':',f'        return {ident}']
        lines+=['    return 0'];text+='\n'+'\n'.join(lines)+'\n'
    prefix=b'{"message":"E_HIA_BACKGROUND: '
    suffix=b'","type":"BackgroundOptimizationRejected"}'
    text+='\ndef error_json(o:mutbuf,id:u64) -> u64:\n    prefix=error_prefix(o)\n    size=error_message(o,id)\n    tail=error_suffix(o,128+prefix+size)\n    return prefix+size+tail\n'
    lines=['def error_message(o:mutbuf,id:u64) -> u64:']
    for ident in ERRORS:lines +=[f'    if id=={ident}:',f'        return error_{ident}(o)']
    lines+=['    return 0'];text+='\n'+'\n'.join(lines)+'\n'
    text+='\ndef error_prefix(o:mutbuf) -> u64:\n'+'\n'.join(f'    store(o,{128+i},{b})'for i,b in enumerate(prefix))+f'\n    return {len(prefix)}\n'
    text+='\ndef error_suffix(o:mutbuf,at:u64) -> u64:\n'+'\n'.join(f'    store(o,at+{i},{b})'for i,b in enumerate(suffix))+f'\n    return {len(suffix)}\n'
    for ident,message in ERRORS.items():
        raw=message.encode()
        assert prefix+raw+suffix==json.dumps({'type':'BackgroundOptimizationRejected','message':'E_HIA_BACKGROUND: '+message},sort_keys=True,separators=(',',':')).encode()
        text+='\n'+f'def error_{ident}(o:mutbuf) -> u64:\n'+'\n'.join(f'    store(o,{128+len(prefix)+i},{b})'for i,b in enumerate(raw))+f'\n    return {len(raw)}\n'
    for key,value in sorted(C.items(),key=lambda x:-len(x[0])):text=re.sub(r'\b'+key+r'\b',str(value),text)
    return text
def main():
    doc=document(source_program(),'background_optimizer_admission')
    target=ROOT/'examples/hia_bootstrap/background_optimizer_admission.hepta'
    target.write_text(render_assembly(doc));print(target.name,target.stat().st_size,len(doc['functions']),sum(len(f['blocks'])for f in doc['functions']),flush=True)
if __name__=='__main__':main()
