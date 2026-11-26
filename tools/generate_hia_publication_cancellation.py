"""Author a native public cancellation facade over the actual held token kernel.

Authoring only. Product execution is the generated HIA plus fixed mechanical
roles. No public operation commits a token or exports its workspace address.
"""
from pathlib import Path
import json, re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document

ROOT = Path(__file__).resolve().parents[1]
C = {
    'MAGIC': int.from_bytes(b'HIAPCQ01', 'little'),
    'REPLY': int.from_bytes(b'HIAPCR01', 'little'),
    'HANDLES': int.from_bytes(b'HIAMVHQ1', 'little'),
    'HREPLY': int.from_bytes(b'HIAMVHR1', 'little'),
    'EFFECTS': int.from_bytes(b'HIAMVEX1', 'little'),
    'EREPLY': int.from_bytes(b'HIAMVER1', 'little'),
    'KERNEL': int.from_bytes(b'HIAMVFQ1', 'little'),
    'KREPLY': int.from_bytes(b'HIAMVFR1', 'little'),
    'MAX': (1 << 64) - 1, 'BAD': 4294967293,
    'OUT': (96 << 20) + 16384, 'CHILD': 16384,
    'RQ': 4096, 'PHASE': 256, 'FEEDBACK': 384,
}
ERROR = 'E_HIA_MULTIVERSION: publication cancellation has one synchronization owner'

SOURCE = r'''
def public(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!=64 or length(o)<OUT or length(w)<256:
        return BAD
    phase=get(o,PHASE)
    if phase==0:
        return begin(s,o,w)
    if phase!=1:
        return BAD
    if get(o,FEEDBACK)!=0 or get(o,CHILD)!=HREPLY:
        return finish(o,5,0,0)
    status=get(o,CHILD+8)
    if status!=0:
        public_status=5
        if status==1:
            public_status=1
        elif status==4:
            public_status=2
        elif status==5:
            public_status=3
        return finish(o,public_status,0,0)
    op=word_load(s,8)
    if op==1 or op==2:
        if get(o,CHILD+16)!=1 or get(o,CHILD+24)==0:
            return finish(o,5,0,0)
        return finish(o,0,2,0)
    if op==7 or op==8:
        return finish(o,4,0,0)
    if op>=4 and op<=6:
        at=get(o,CHILD+56)
        if get(o,CHILD+48)!=0 or at!=1048576 or get(o,CHILD+64)!=1024:
            return finish(o,5,0,0)
        if get(o,CHILD+at)!=EREPLY or get(o,CHILD+at+8)!=0:
            return finish(o,5,0,0)
        value=get(o,CHILD+at+16)
        if value>1:
            return finish(o,5,0,0)
        return finish(o,0,1,value)
    return finish(o,0,0,0)

def begin(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if word_load(s,0)!=MAGIC or word_load(s,8)>10:
        return BAD
    op=word_load(s,8)
    i=16
    while i<64:
        used=op>=2 and op<=8 and i<=32
        if used==False and word_load(s,i)!=0:
            return BAD
        i=i+8
    zero(o,128,8192-128)
    zero(o,CHILD,128)
    childop=op
    if op>=4 and op<=6:
        childop=4
    elif op==7 or op==8:
        childop=6
    elif op==9:
        childop=5
    elif op==10:
        childop=7
    put(o,RQ,HANDLES)
    put(o,RQ+8,childop)
    n=128
    if op>=2 and op<=8:
        copy_source(s,o,16,RQ+24,24)
    if op==1 or (op>=4 and op<=6):
        n=384
        put(o,RQ+72,256)
        put(o,RQ+128,EFFECTS)
        if op>=4 and op<=6:
            put(o,RQ+136,op+3)
    put(o,0,n)
    put(o,PHASE,1)
    return 12

def finish(o:mutbuf,status:u64,kind:u64,value:u64) -> u32:
    zero(o,0,128)
    put(o,0,REPLY)
    put(o,8,status)
    put(o,16,kind)
    if kind==2:
        within(o,24,CHILD+24,24)
    if kind==1:
        put(o,48,value)
    put(o,64,get(o,CHILD+48))
    put(o,72,get(o,CHILD+88))
    put(o,80,get(o,CHILD+72))
    put(o,88,get(o,CHILD+80))
    if status==4:
        put(o,56,error_text(o))
    return 0
'''

EFFECT_SOURCE = r'''
def token_effects(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!=256 or length(o)<8192 or length(w)<512:
        return BAD
    phase=get(o,PHASE)
    if phase==0:
        if word_load(s,0)!=EFFECTS:
            return BAD
        op=word_load(s,8)
        if op!=0 and op!=7 and op!=8 and op!=9 and op!=13:
            return BAD
        i=16
        while i<256:
            if op==13 and i==72:
                if word_load(s,i)!=MAX:
                    return BAD
            elif word_load(s,i)!=0:
                return BAD
            i=i+8
        zero(o,128,8192-128)
        kernelop=0
        if op==7:
            kernelop=8
        elif op==8 or op==9:
            kernelop=9
        elif op==13:
            kernelop=10
        put(o,2048,KERNEL)
        put(o,2056,kernelop)
        put(o,PHASE,1)
        return 12
    if phase!=1:
        return BAD
    rc=get(o,FEEDBACK)
    if get(o,4096)!=KREPLY or get(o,4104)!=rc:
        return effect_finish(o,65,0)
    if rc!=0:
        return effect_finish(o,rc,0)
    value=0
    op=word_load(s,8)
    if op==7:
        value=get(o,4112)
    elif op==8:
        value=choose(get(o,4128)==1,1,0)
    elif op==9:
        value=choose(get(o,4128)==2,1,0)
    return effect_finish(o,0,value)

def effect_finish(o:mutbuf,status:u64,value:u64) -> u32:
    zero(o,0,1024)
    put(o,0,EREPLY)
    put(o,8,status)
    put(o,16,value)
    put(o,96,MAX)
    put(o,104,MAX)
    return status
'''

HELPERS = r'''
def get(w:mutbuf,at:u64) -> u64:
    return word_load(w,at)
def put(w:mutbuf,at:u64,value:u64) -> u64:
    i=0
    while i<8:
        store(w,at+i,(value>>(i*8))&255)
        i=i+1
    return 0
def zero(w:mutbuf,at:u64,n:u64) -> u64:
    fill_range(w,at,n,0)
    return 0
def copy_source(s:readbuf,o:mutbuf,at:u64,to:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(o,to+i,byte(s,at+i))
        i=i+1
    return 0
def within(w:mutbuf,to:u64,at:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(w,to+i,byte(w,at+i))
        i=i+1
    return 0
'''

def source_program(effects=False):
    source = (EFFECT_SOURCE if effects else SOURCE) + HELPERS
    if not effects:
        raw = json.dumps({'class':'MultiversionRejected','message':ERROR},sort_keys=True,separators=(',',':')).encode()
        source += '\ndef error_text(o:mutbuf) -> u64:\n'
        for i in range(0,len(raw),8):
            source += f'    put(o,{128+i},{int.from_bytes(raw[i:i+8].ljust(8,b"\0"),"little")})\n'
        source += f'    return {len(raw)}\n'
    for key,value in sorted(C.items(),key=lambda x:-len(x[0])):
        source=re.sub(r'\b'+key+r'\b',str(value),source)
    return source

def main():
    for effects,name in [(False,'publication_cancellation_public'),(True,'publication_cancellation_effects')]:
        d=document(source_program(effects),name)
        path=ROOT/'examples/hia_bootstrap'/f'{name}.hepta'
        path.write_text(render_assembly(d))
        print(path.name,path.stat().st_size,len(d['functions']),sum(len(f['blocks']) for f in d['functions']))

if __name__=='__main__':
    main()
