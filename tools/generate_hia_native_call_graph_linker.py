"""Native HIA final framing for independently generated call-closure graphs.

Inputs are private artifacts from one current native owner invocation. This
role checks all view extents and the selected signature; the general component
still independently validates and projects actual summaries and operations.
"""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from hepta.hia_cnf_native import SCALAR_SUMMARY,TUPLE_SUMMARY
from tools.generate_hia_cold_document import document
from tools.generate_hia_cold_sha_alias import Builder
ROOT=Path(__file__).resolve().parents[1]
C={'REQUEST':int.from_bytes(b'HIACGL01','little'),'BUNDLE':int.from_bytes(b'HIACCL01','little'),
   'INVENTORY':int.from_bytes(b'HIACSU01','little'),'GRAPH':int.from_bytes(b'HIABVP02','little'),
   'SCALAR':SCALAR_SUMMARY,'TUPLE':TUPLE_SUMMARY,'BAD':4294967293,'CAP':4294967292,'SIGNATURE':4294967291}
POLICY=r'''
def native_call_graph_linker(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)<128 or length(w)<8192 or read(s,0)!=REQUEST:
        return BAD
    mode=read(s,8)
    if mode<1 or mode>3:
        return BAD
    i=64
    while i<128:
        if read(s,i)!=0:
            return BAD
        i=i+8
    left=read(s,16)
    right=read(s,24)
    sa=read(s,32)
    sb=read(s,40)
    if left<26752 or left>16777216 or right>16777216 or sa>268435456 or sb>268435456:
        return BAD
    if mode!=2 and (right!=0 or sb!=0 or read(s,56)!=0):
        return BAD
    if mode==2 and right<26752:
        return BAD
    if left+right+sa+sb!=length(s)-128:
        return BAD
    fill_range(w,0,8192,0)
    put(w,0,mode)
    result=plan_side(s,w,128,left,128+left+right,sa,read(s,48),0)
    if result!=0:
        return result
    sides=1
    if mode==2:
        result=plan_side(s,w,128+left,right,128+left+right+sa,sb,read(s,56),1)
        if result!=0:
            return result
        if same_signature(s,w)==False:
            return SIGNATURE
        sides=2
    types=get(w,128+32)
    tail=types+get(w,128+88)
    if sides==2:
        tail=tail+get(w,384+88)
    size=tail+get(w,128+80)
    if sides==2:
        size=size+get(w,384+80)
    if size>16777216 or size>length(o):
        return CAP
    body_at=types
    tail_at=tail
    side=0
    while side<sides:
        row=128+256*side
        put(w,row+96,body_at)
        put(w,row+104,tail_at)
        body_at=body_at+get(w,row+88)
        tail_at=tail_at+get(w,row+80)
        side=side+1
    copy_input(s,o,0,get(w,128+8),types)
    word_store(o,8,mode)
    word_store(o,32,tail)
    side=0
    while side<sides:
        emit_side(s,o,w,side)
        side=side+1
    return size

def read(s:readbuf,at:u64) -> u64:
    return word_load(s,at)

def get(w:mutbuf,at:u64) -> u64:
    return word_load(w,at)

def put(w:mutbuf,at:u64,value:u64) -> u64:
    word_store(w,at,value)
    return 0

def inventory_valid(s:readbuf,base:u64,size:u64,target:u64) -> bool:
    if size<64 or read(s,base)!=INVENTORY or read(s,base+8)!=target or read(s,base+16)!=size:
        return False
    if target>16 or 64+16*target>size:
        return False
    i=24
    while i<64:
        if read(s,base+i)!=0:
            return False
        i=i+8
    at=64+16*target
    i=0
    while i<target:
        offset=read(s,base+64+16*i)
        amount=read(s,base+72+16*i)
        if offset!=at or amount<56 or amount>41943424 or amount>size-at:
            return False
        at=at+amount
        i=i+1
    return at==size

def plan_side(s:readbuf,w:mutbuf,base:u64,size:u64,inventory:u64,invent_size:u64,target:u64,side:u64) -> u64:
    functions=read(s,base+8)
    if read(s,base)!=BUNDLE or functions==0 or functions>16 or target>=functions or read(s,base+16)!=functions-1:
        return BAD
    if read(s,base+24)>32 or read(s,base+32)>512 or read(s,base+40)>33 or read(s,base+56)!=size or read(s,base+64)!=26752 or read(s,base+72)>512:
        return BAD
    i=80
    while i<128:
        if read(s,base+i)!=0:
            return BAD
        i=i+8
    if inventory_valid(s,inventory,invent_size,target)==False:
        return BAD
    row=128+256*side
    put(w,row,base)
    put(w,row+56,inventory)
    put(w,row+64,invent_size)
    put(w,row+72,target)
    put(w,row+120,size)
    result=plan_target(s,w,row)
    if result!=0:
        return result
    i=0
    while i<get(w,row+48):
        result=plan_one_fix(s,w,row,side,i)
        if result!=0:
            return result
        i=i+1
    return 0

def plan_target(s:readbuf,w:mutbuf,row:u64) -> u64:
    base=get(w,row)
    size=get(w,row+120)
    record=base+128+640*get(w,row+72)
    start=read(s,record+8)
    graph_size=read(s,record+16)
    tail=read(s,record+24)
    inputs=read(s,record+48)
    outputs=read(s,record+56)
    types=40+8*(inputs+outputs)
    if inputs>32 or outputs>16 or read(s,record+72)!=inputs+outputs:
        return BAD
    if start<26752 or start>size or graph_size>size-start or types+24>tail or tail>graph_size:
        return BAD
    graph=base+start
    if read(s,graph)!=GRAPH or read(s,graph+8)!=3 or read(s,graph+16)!=inputs or read(s,graph+24)!=outputs or read(s,graph+32)!=tail:
        return BAD
    first=read(s,record+32)
    count=read(s,record+40)
    if first>read(s,base+72) or count>read(s,base+72)-first:
        return BAD
    put(w,row+8,graph)
    put(w,row+16,graph_size)
    put(w,row+24,tail)
    put(w,row+32,types)
    put(w,row+40,first)
    put(w,row+48,count)
    put(w,row+88,tail-types)
    put(w,row+80,graph_size-tail)
    put(w,row+112,0)
    return 0

def plan_one_fix(s:readbuf,w:mutbuf,row:u64,side:u64,index:u64) -> u64:
    base=get(w,row)
    graph=get(w,row+8)
    tail=get(w,row+24)
    size=get(w,row+16)
    fix=base+10368+32*(get(w,row+40)+index)
    offset=read(s,fix+8)
    callee=read(s,fix+16)
    if read(s,fix)!=get(w,row+72) or callee>=get(w,row+72) or read(s,fix+24)!=0 or offset<get(w,row+32)+24 or offset>tail or 48>tail-offset:
        return BAD
    if read(s,graph+offset)!=40 or read(s,graph+offset+16)!=0:
        return BAD
    args=read(s,graph+offset+24)
    argc=read(s,graph+offset+32)
    if args<tail or args>size or argc>32 or 8*argc>size-args:
        return BAD
    mask=get(w,row+112)
    if mask&(1<<callee)==0:
        inventory=get(w,row+56)
        summary=inventory+read(s,inventory+64+16*callee)
        amount=read(s,inventory+72+16*callee)
        if summary_valid(s,base,callee,summary,amount)==False:
            return BAD
        appended=get(w,row+80)
        put(w,4096+256*side+8*callee,appended)
        appended=appended+amount
        if appended>16777216:
            return CAP
        put(w,row+80,appended)
        put(w,row+112,mask|(1<<callee))
    return 0

def summary_valid(s:readbuf,bundle:u64,callee:u64,summary:u64,size:u64) -> bool:
    record=bundle+128+640*callee
    nodes=read(s,summary+8)
    inputs=read(s,record+48)
    outputs=read(s,record+56)
    if inputs>32 or outputs>16 or nodes==0 or nodes>1048576 or nodes<inputs or read(s,summary+16)!=inputs:
        return False
    tail=32+40*nodes
    types=tail+24+16*outputs
    if outputs==1:
        types=tail+32
        if read(s,summary)!=SCALAR:
            return False
    elif read(s,summary)!=TUPLE or read(s,summary+24)!=outputs:
        return False
    if types+8*inputs!=size:
        return False
    graph=bundle+read(s,record+8)
    graph_size=read(s,record+16)
    if read(s,record+8)<26752 or read(s,record+8)>read(s,bundle+56) or graph_size>read(s,bundle+56)-read(s,record+8) or graph_size<40+8*(inputs+outputs):
        return False
    if outputs==1:
        if read(s,summary+24)!=read(s,graph+40+8*inputs):
            return False
    else:
        i=0
        while i<outputs:
            if read(s,summary+tail+24+16*i)!=read(s,graph+40+8*(inputs+i)):
                return False
            i=i+1
    i=0
    while i<inputs:
        if read(s,summary+types+8*i)!=read(s,graph+40+8*i):
            return False
        i=i+1
    return True

def same_signature(s:readbuf,w:mutbuf) -> bool:
    a=get(w,128)+128+640*get(w,128+72)
    b=get(w,384)+128+640*get(w,384+72)
    if read(s,a+48)!=read(s,b+48) or read(s,a+56)!=read(s,b+56):
        return False
    count=read(s,a+72)
    i=0
    while i<count:
        if read(s,a+256+8*i)!=read(s,b+256+8*i):
            return False
        i=i+1
    return True

def copy_input(s:readbuf,o:mutbuf,target:u64,source:u64,size:u64) -> u64:
    i=0
    while i+8<=size:
        word_store(o,target+i,word_load(s,source+i))
        i=i+8
    while i<size:
        store(o,target+i,byte(s,source+i))
        i=i+1
    return 0

def emit_side(s:readbuf,o:mutbuf,w:mutbuf,side:u64) -> u64:
    row=128+256*side
    base=get(w,row)
    graph=get(w,row+8)
    oldtail=get(w,row+24)
    types=get(w,row+32)
    body=get(w,row+96)
    tail=get(w,row+104)
    copy_input(s,o,body,graph+types,get(w,row+88))
    copy_input(s,o,tail,graph+oldtail,get(w,row+16)-oldtail)
    mask=get(w,row+112)
    inventory=get(w,row+56)
    i=0
    while i<get(w,row+72):
        if mask&(1<<i)!=0:
            copy_input(s,o,tail+get(w,4096+256*side+8*i),inventory+read(s,inventory+64+16*i),read(s,inventory+72+16*i))
        i=i+1
    i=0
    while i<get(w,row+48):
        fix=base+10368+32*(get(w,row+40)+i)
        oldrow=read(s,fix+8)
        outrow=body+oldrow-types
        callee=read(s,fix+16)
        word_store(o,outrow+16,tail+get(w,4096+256*side+8*callee))
        word_store(o,outrow+24,tail+read(s,graph+oldrow+24)-oldtail)
        i=i+1
    return 0
'''
def policy_source():
    source=POLICY
    for name,value in sorted(C.items(),key=lambda p:-len(p[0])):
        source=re.sub(r'\b'+name+r'\b',str(value),source)
    return source
def program():
    return document(policy_source(),'native_call_graph_linker',builder_type=Builder)
if __name__=='__main__':
    tree=program();p=ROOT/'examples/hia_bootstrap/native_call_graph_linker.hepta';p.write_text(render_assembly(tree))
    print(p.stat().st_size,len(tree['functions']),sum(len(f['blocks']) for f in tree['functions']),sum(len(b['ops']) for f in tree['functions'] for b in f['blocks']),flush=True)
