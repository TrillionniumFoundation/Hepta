"""Original caller-owned snapshot gates over a fresh immutable JSON tree.

Only native JSON-owned values enter this role. External class identity, cycles,
non-string host keys and concurrent foreign-container capture belong to their
typed native boundary, not a caller-asserted arena.
"""
from pathlib import Path
import ast,json,re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_system_jobctl_request import document
from tools.generate_hia_ndu_rank_admission import source_program as admission_source
from tools.generate_hia_ndu_rank_selection import literal_function
ROOT=Path(__file__).resolve().parents[1]
ERRORS={1:('E_HIA_LIMIT','caller-owned tree exceeds snapshot budget'),2:('E_HIA_LIMIT','caller-owned tree exceeds queued-node budget'),3:('E_HIA_FORMAT','unsupported caller-owned JSON node')}
SOURCE=r'''
def rank_snapshot(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)<128 or length(w)<131072 or read64(s,0)!=REQUEST:
        return 4294967293
    root=read64(s,8)
    jn=read64(s,16)
    an=read64(s,24)
    if jn==0 or an==0 or jn>length(s)-128 or an!=length(s)-128-jn:
        return 4294967293
    i=32
    while i<128:
        if read64(s,i)!=0:
            return 4294967293
        i=i+8
    a=128+jn
    if arena_valid(s,w,a,an,jn)==False or root>=read64(s,a+8):
        return 4294967293
    put(w,0,a)
    put(w,8,root)
    put(w,16,0)
    put(w,24,0)
    kind=nodeword(s,a,root,0)
    error=0
    if kind==5 or kind==6:
        error=snapshot(s,w)
    put(w,512,0)
    if error!=0:
        error_literal(w,error)
    n=get(w,512)
    if length(o)<128 or n>length(o)-128:
        return 4294967294
    zero(o,128)
    put(o,0,REPLY)
    put(o,8,choose(error!=0,1,0))
    put(o,16,error)
    put(o,24,kind)
    put(o,32,get(w,16))
    put(o,40,get(w,24))
    put(o,48,n)
    put(o,56,root)
    if kind==4:
        put(o,64,nodeword(s,a,root,24))
        put(o,72,nodeword(s,a,root,32))
    i=0
    while i<n:
        store(o,128+i,byte(w,65536+i))
        i=i+1
    return 0

def snapshot(s:readbuf,w:mutbuf) -> u64:
    a=get(w,0)
    root=get(w,8)
    node=root
    depth=0
    count=0
    queued=1
    going=True
    while going:
        queued=queued-1
        count=count+1
        put(w,16,count)
        put(w,24,queued)
        if count>262144 or depth>64:
            return 1
        kind=nodeword(s,a,node,0)
        descended=False
        if kind==5 or kind==6:
            children=nodeword(s,a,node,32)
            if children>262144-count-queued:
                return 2
            queued=queued+children
            put(w,24,queued)
            if children!=0:
                node=nodeword(s,a,node,24)
                depth=depth+1
                descended=True
        elif kind==3:
            at=128+nodeword(s,a,node,24)
            n=nodeword(s,a,node,32)
            i=0
            while i<n:
                c=byte(s,at+i)
                if c==46 or c==101 or c==69:
                    return 3
                i=i+1
        elif kind>6:
            return 3
        if descended==False:
            moving=True
            while moving:
                if node==root:
                    going=False
                    moving=False
                else:
                    sibling=nodeword(s,a,node,16)
                    if sibling!=18446744073709551615:
                        node=sibling
                        moving=False
                    else:
                        node=nodeword(s,a,node,8)
                        depth=depth-1
    return 0

def emit(w:mutbuf,value:u64) -> u64:
    at=get(w,512)
    if at<1024:
        store(w,65536+at,value)
    put(w,512,at+1)
    return 0
'''
def source_program():
    wanted={'arena_valid','nodeword','read64','readn','get','put','zero','choose'}
    helpers=[ast.unparse(n)for n in ast.parse(admission_source()).body if n.name in wanted]
    assert len(helpers)==len(wanted)
    text=SOURCE+'\n'+'\n'.join(helpers)+'\n'
    text+=literal_function('error_literal',{i:json.dumps({'type':'HIAProgramRejected','code':code,'message':code+': '+message},sort_keys=True,separators=(',',':')) for i,(code,message)in ERRORS.items()})
    for key,value in {'REQUEST':int.from_bytes(b'HIANVS01','little'),'REPLY':int.from_bytes(b'HIANVR01','little')}.items():
        text=re.sub(r'\b'+key+r'\b',str(value),text)
    return text
def program():return document(source_program(),'ndu_rank_snapshot')
if __name__=='__main__':
    path=ROOT/'examples/hia_bootstrap/ndu_rank_snapshot.hepta';path.write_text(render_assembly(program()));print(path.name,path.stat().st_size,flush=True)
