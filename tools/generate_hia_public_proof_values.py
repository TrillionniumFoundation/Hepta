"""Author typed JSON/span adaptation for the common native public proof owner.

Arenas are produced by the same owner's actual wire-spans JSON decoder. The
private boundary never accepts an external arena or a caller's proof assertion.
"""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_system_jobctl_request import document
from tools import generate_hia_native_public_proof_receipt as receipt
ROOT=Path(__file__).resolve().parents[1]
C={'REQUEST':int.from_bytes(b'HIAJPV01','little'),'CLASSIFY':int.from_bytes(b'HIAPTV01','little'),'SELECT':int.from_bytes(b'HIAJPS01','little'),'BAD':0xfffffffd,'NONE':0xffffffffffffffff,'SEEN':512}
SOURCE=r'''
def values(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)<256 or length(w)<262144 or read64(s,0)!=REQUEST:
        return BAD
    action=read64(s,8)
    maximum=read64(s,16)
    default=read64(s,24)
    flags=read64(s,32)
    count=read64(s,104)
    if action>2 or maximum==0 or maximum>60000 or default==0 or default>maximum or count>3:
        return BAD
    if (action!=1 and flags!=0) or (action==1 and (flags==0 or flags>3)):
        return BAD
    if read64(s,112)!=0 or read64(s,120)!=0:
        return BAD
    i=176
    while i<256:
        if read64(s,i)!=0:
            return BAD
        i=i+8
    at=256
    i=0
    while i<3:
        jn=read64(s,128+i*16)
        an=read64(s,136+i*16)
        if i>=count:
            if jn!=0 or an!=0:
                return BAD
            put(w,i*16,0)
            put(w,i*16+8,0)
        else:
            if jn==0 or an==0 or jn>length(s)-at:
                return BAD
            put(w,i*16,at)
            at=at+jn
            if an>length(s)-at:
                return BAD
            put(w,i*16+8,at)
            if arena_valid(s,w,at,an,jn)==False:
                return BAD
            at=at+an
        i=i+1
    if at!=length(s):
        return BAD
    if valid_ref(s,w,40)==False or valid_ref(s,w,56)==False or valid_ref(s,w,72)==False:
        return BAD
    if action==0:
        return classify_values(s,o,w)
    if action==1:
        return rebind_values(s,o,w)
    return select_value(s,o,w)

def valid_ref(s:readbuf,w:mutbuf,at:u64) -> bool:
    doc=read64(s,at)
    node=read64(s,at+8)
    if doc==NONE or node==NONE:
        return doc==NONE and node==NONE
    if doc>=read64(s,104):
        return False
    base=get(w,doc*16+8)
    return node<read64(s,base+8)

def ref_kind(s:readbuf,w:mutbuf,at:u64) -> u64:
    doc=read64(s,at)
    if doc==NONE:
        return 0
    return nodeword(s,get(w,doc*16+8),read64(s,at+8),0)

def classify_values(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(o)<64:
        return BAD
    timeout_kind=0
    magnitude=read64(s,24)
    doc=read64(s,56)
    if doc!=NONE:
        base=get(w,doc*16+8)
        node=read64(s,64)
        if nodeword(s,base,node,0)!=3:
            timeout_kind=3
            magnitude=0
        else:
            start=get(w,doc*16)+nodeword(s,base,node,24)
            n=nodeword(s,base,node,32)
            negative=False
            floating=False
            overflow=False
            pos=0
            magnitude=0
            if byte(s,start)==45:
                negative=True
                pos=1
            if pos==n:
                return BAD
            while pos<n:
                c=byte(s,start+pos)
                if c==46 or c==101 or c==69:
                    floating=True
                elif c<48 or c>57:
                    if c!=43 and c!=45:
                        return BAD
                    floating=True
                elif overflow==False:
                    digit=c-48
                    if magnitude>1844674407370955161 or (magnitude==1844674407370955161 and digit>5):
                        overflow=True
                    else:
                        magnitude=magnitude*10+digit
                pos=pos+1
            if floating:
                timeout_kind=3
                magnitude=0
            elif overflow:
                timeout_kind=2
                magnitude=0
            elif negative and magnitude!=0:
                timeout_kind=1
    function_kind=0
    n=0
    start=0
    doc=read64(s,40)
    if doc!=NONE:
        base=get(w,doc*16+8)
        node=read64(s,48)
        kind=nodeword(s,base,node,0)
        if kind==4:
            function_kind=1
            n=nodeword(s,base,node,32)
            if n>129:
                n=129
            start=base+nodeword(s,base,node,24)
        elif kind!=0:
            function_kind=2
    if n>length(o)-64:
        return BAD
    put(o,0,CLASSIFY)
    put(o,8,read64(s,16))
    put(o,16,timeout_kind)
    put(o,24,magnitude)
    put(o,32,read64(s,96))
    put(o,40,function_kind)
    put(o,48,read64(s,88))
    put(o,56,n)
    i=0
    while i<n:
        store(o,64+i,byte(s,start+i))
        i=i+1
    return 64+n

def select_value(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(o)<64:
        return BAD
    doc=read64(s,72)
    node=read64(s,80)
    supported=False
    if doc!=NONE:
        base=get(w,doc*16+8)
        supported=nodeword(s,base,node,0)==6
        if supported:
            supported=string_is(s,base,field(s,base,node,6),7) and string_is(s,base,field(s,base,node,5),8)
    selected_doc=NONE
    selected_node=NONE
    raw=0
    n=0
    fallback=False
    if supported:
        selected_doc=read64(s,40)
        selected_node=read64(s,48)
        if ref_kind(s,w,40)==0:
            fallback=True
            base=get(w,doc*16+8)
            selected_node=field(s,base,node,1)
            selected_doc=doc
            if selected_node==NONE:
                selected_doc=NONE
        if selected_doc!=NONE:
            base=get(w,selected_doc*16+8)
            slot=choose(nodeword(s,base,selected_node,0)>=4,56,24)
            raw=nodeword(s,base,selected_node,slot)
            n=nodeword(s,base,selected_node,slot+8)
    put(o,0,SELECT)
    put(o,8,choose(supported,1,0))
    put(o,16,selected_doc)
    put(o,24,selected_node)
    put(o,32,raw)
    put(o,40,n)
    put(o,48,choose(fallback,1,0))
    put(o,56,0)
    return 64

def replacement(s:readbuf,w:mutbuf,kind:u64) -> u64:
    ref=choose(kind==1,40,56)
    doc=read64(s,ref)
    if doc==NONE:
        if kind==1:
            put(w,224,0)
            put(w,232,4)
            return 4
        value=read64(s,24)
        size=1
        while value>=10:
            value=value//10
            size=size+1
        put(w,224,0)
        put(w,232,size)
        return size
    base=get(w,doc*16+8)
    node=read64(s,ref+8)
    slot=choose(nodeword(s,base,node,0)>=4,56,24)
    raw=get(w,doc*16)+nodeword(s,base,node,slot)
    n=nodeword(s,base,node,slot+8)
    put(w,224,raw)
    put(w,232,n)
    return n

def add_patch(s:readbuf,w:mutbuf,base:u64,node:u64,kind:u64,count:u64) -> bool:
    if node==NONE or count>=4:
        return False
    slot=choose(nodeword(s,base,node,0)>=4,56,24)
    put(w,64+count*24,nodeword(s,base,node,slot))
    put(w,72+count*24,nodeword(s,base,node,slot+8))
    put(w,80+count*24,kind)
    return True

def rebind_values(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    doc=read64(s,72)
    if doc==NONE or read64(s,80)!=0:
        return BAD
    base=get(w,doc*16+8)
    if nodeword(s,base,0,0)!=6 or string_is(s,base,field(s,base,0,5),9)==False:
        return BAD
    count=0
    flags=read64(s,32)
    if (flags&1)!=0:
        if add_patch(s,w,base,field(s,base,0,1),1,count)==False:
            return BAD
        count=count+1
        subject=field(s,base,0,2)
        if add_patch(s,w,base,field(s,base,subject,1),1,count)==False:
            return BAD
        count=count+1
    if (flags&2)!=0:
        solver=field(s,base,0,3)
        if add_patch(s,w,base,field(s,base,solver,4),2,count)==False:
            return BAD
        count=count+1
        top=field(s,base,0,4)
        if top!=NONE:
            if add_patch(s,w,base,top,2,count)==False:
                return BAD
            count=count+1
    i=0
    while i<count:
        j=i+1
        while j<count:
            if get(w,64+j*24)<get(w,64+i*24):
                k=0
                while k<24:
                    a=get(w,64+i*24+k)
                    b=get(w,64+j*24+k)
                    put(w,64+i*24+k,b)
                    put(w,64+j*24+k,a)
                    k=k+8
            j=j+1
        i=i+1
    total=read64(s,128+doc*16)
    original=total
    previous=0
    i=0
    while i<count:
        start=get(w,64+i*24)
        n=get(w,72+i*24)
        if start<previous or start>original or n>original-start or n>total:
            return BAD
        previous=start+n
        total=total-n
        i=i+1
    if total>length(o):
        return BAD
    i=0
    while i<count:
        rn=replacement(s,w,get(w,80+i*24))
        if rn>length(o)-total:
            return BAD
        total=total+rn
        i=i+1
    if total>=4294967280:
        return BAD
    at=0
    position=0
    json=get(w,doc*16)
    i=0
    while i<count:
        start=get(w,64+i*24)
        at=copy_bytes(s,o,json+position,start-position,at)
        kind=get(w,80+i*24)
        replacement(s,w,kind)
        raw=get(w,224)
        n=get(w,232)
        if raw!=0:
            at=copy_bytes(s,o,raw,n,at)
        elif kind==1:
            store(o,at,110)
            store(o,at+1,117)
            store(o,at+2,108)
            store(o,at+3,108)
            at=at+4
        else:
            value=read64(s,24)
            j=n
            while j!=0:
                j=j-1
                store(o,at+j,48+value%10)
                value=value//10
            at=at+n
        position=start+get(w,72+i*24)
        i=i+1
    return copy_bytes(s,o,json+position,original-position,at)

def copy_bytes(s:readbuf,o:mutbuf,start:u64,n:u64,at:u64) -> u64:
    i=0
    while i<n:
        store(o,at+i,byte(s,start+i))
        i=i+1
    return at+n

def field(s:readbuf,base:u64,node:u64,key:u64) -> u64:
    if nodeword(s,base,node,0)!=6:
        return NONE
    child=nodeword(s,base,node,24)
    while child!=NONE:
        if label(s,base+nodeword(s,base,child,40),nodeword(s,base,child,48))==key:
            return child
        child=nodeword(s,base,child,16)
    return NONE

def string_is(s:readbuf,base:u64,node:u64,labelid:u64) -> bool:
    if nodeword(s,base,node,0)!=4:
        return False
    return label(s,base+nodeword(s,base,node,24),nodeword(s,base,node,32))==labelid

def nodeword(s:readbuf,base:u64,node:u64,slot:u64) -> u64:
    if node==NONE or node>=read64(s,base+8):
        return NONE
    return read64(s,base+64+node*72+slot)

def read64(s:readbuf,at:u64) -> u64:
    return readn(s,at,8)

def readn(s:readbuf,at:u64,n:u64) -> u64:
    value=0
    i=0
    while i<n:
        value=value|(byte(s,at+i)<<(i*8))
        i=i+1
    return value

def get(w:mutbuf,at:u64) -> u64:
    value=0
    i=0
    while i<8:
        value=value|(byte(w,at+i)<<(i*8))
        i=i+1
    return value

def put(w:mutbuf,at:u64,value:u64) -> u64:
    i=0
    while i<8:
        store(w,at+i,(value>>(i*8))&255)
        i=i+1
    return 0

def choose(test:bool,a:u64,b:u64) -> u64:
    if test:
        return a
    return b
'''

def source_program():
    arena=receipt.POLICY.split('def arena_valid(',1)[1].split('\ndef nodeword(',1)[0]
    arena='def arena_valid('+arena
    arena=arena.replace('    first=64+72*count\n    if count==0 or count>131073 or first>size:', '    if count==0 or count>131073:\n        return False\n    first=64+72*count\n    if first>size:')
    labels=['function','subject','solver','timeout_ms','status','schema','hepta.hia.translation-validation.v1','proved','unknown']
    lines=['def label(s:readbuf,at:u64,n:u64) -> u64:']
    for ident,label in enumerate(labels,1):
        raw=label.encode();parts=[f'n=={len(raw)}']+[f'readn(s,at+{i},{len(raw[i:i+8])})=={int.from_bytes(raw[i:i+8],"little")}' for i in range(0,len(raw),8)]
        lines+=['    if '+' and '.join(parts)+':',f'        return {ident}']
    lines.append('    return 0')
    text=SOURCE+'\n'+arena+'\n'+'\n'.join(lines)
    for name,value in sorted(C.items(),key=lambda p:-len(p[0])):
        text=re.sub(r'\b'+name+r'\b',str(value),text)
    return text

if __name__=='__main__':
    tree=document(source_program(),'public_proof_values')
    p=ROOT/'examples/hia_bootstrap/public_proof_values.hepta'
    p.write_text(render_assembly(tree))
    print(p.name,p.stat().st_size,len(tree['functions']),sum(len(f['blocks']) for f in tree['functions']),sum(len(b['ops']) for f in tree['functions'] for b in f['blocks']),flush=True)
