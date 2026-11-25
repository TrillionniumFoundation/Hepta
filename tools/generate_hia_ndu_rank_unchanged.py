"""Compare unselected functions and module data on freshly normalized Core."""
from pathlib import Path
import ast,re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_system_jobctl_request import document
from tools.generate_hia_ndu_rank_admission import source_program as admission_source
ROOT=Path(__file__).resolve().parents[1]
SOURCE=r'''
def rank_unchanged(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)<128 or length(w)<131072 or read64(s,0)!=REQUEST:
        return 4294967293
    name_n=read64(s,8)
    if name_n==0 or name_n>128 or name_n>length(s)-128:
        return 4294967293
    at=48
    while at<128:
        if read64(s,at)!=0:
            return 4294967293
        at=at+8
    at=128+name_n
    i=0
    while i<2:
        jn=read64(s,16+i*16)
        an=read64(s,24+i*16)
        if jn==0 or an==0 or jn>length(s)-at:
            return 4294967293
        put(w,i*16,at)
        at=at+jn
        put(w,i*16+8,at)
        if an>length(s)-at or arena_valid(s,w,at,an,jn)==False:
            return 4294967293
        at=at+an
        i=i+1
    if at!=length(s) or length(o)<64:
        return 4294967293
    a=get(w,8)
    b=get(w,24)
    an=field(s,a,0,21)
    bn=field(s,b,0,21)
    if nodeword(s,a,0,0)!=6 or nodeword(s,b,0,0)!=6 or nodeword(s,a,an,0)!=5 or nodeword(s,b,bn,0)!=5:
        return 4294967293
    reason=0
    ax=nodeword(s,a,an,56)
    bx=nodeword(s,b,bn,56)
    ae=ax+nodeword(s,a,an,64)
    be=bx+nodeword(s,b,bn,64)
    if same(s,get(w,0),ax,get(w,16),bx)==False or same(s,get(w,0)+ae,read64(s,16)-ae,get(w,16)+be,read64(s,32)-be)==False:
        reason=1
    else:
        ac=remaining(s,a,nodeword(s,a,an,24),name_n)
        bc=remaining(s,b,nodeword(s,b,bn,24),name_n)
        while ac!=18446744073709551615 and bc!=18446744073709551615 and reason==0:
            if nodeword(s,a,ac,0)!=6 or nodeword(s,b,bc,0)!=6:
                return 4294967293
            if same(s,get(w,0)+nodeword(s,a,ac,56),nodeword(s,a,ac,64),get(w,16)+nodeword(s,b,bc,56),nodeword(s,b,bc,64))==False:
                reason=2
            ac=remaining(s,a,nodeword(s,a,ac,16),name_n)
            bc=remaining(s,b,nodeword(s,b,bc,16),name_n)
        if reason==0 and (ac!=18446744073709551615 or bc!=18446744073709551615):
            reason=3
    zero(o,64)
    put(o,0,REPLY)
    put(o,8,choose(reason==0,1,0))
    put(o,16,reason)
    return 0

def remaining(s:readbuf,a:u64,node:u64,name_n:u64) -> u64:
    searching=True
    while node!=18446744073709551615 and searching:
        name=field(s,a,node,22)
        if nodeword(s,a,name,0)==4 and same(s,128,name_n,a+nodeword(s,a,name,24),nodeword(s,a,name,32)):
            node=nodeword(s,a,node,16)
        else:
            searching=False
    return node
'''
def source_program():
    wanted={'arena_valid','nodeword','field','label','read64','readn','get','put','same','zero','choose'}
    helpers=[ast.unparse(n) for n in ast.parse(admission_source()).body if n.name in wanted]
    assert len(helpers)==len(wanted)
    text=SOURCE+'\n'+'\n'.join(helpers)+'\n'
    for key,value in {'REQUEST':int.from_bytes(b'HIANUC01','little'),'REPLY':int.from_bytes(b'HIANUR01','little')}.items():
        text=re.sub(r'\b'+key+r'\b',str(value),text)
    return text
def program():return document(source_program(),'ndu_rank_unchanged')
if __name__=='__main__':
    path=ROOT/'examples/hia_bootstrap/ndu_rank_unchanged.hepta';path.write_text(render_assembly(program()));print(path.name,path.stat().st_size,flush=True)
