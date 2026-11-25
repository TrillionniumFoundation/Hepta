"""Canonicalize an owned JSON subtree with full-width output sizing."""
from pathlib import Path
import ast,re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_system_jobctl_request import document
from tools.generate_hia_ndu_rank_admission import source_program as admission_source
from tools.generate_hia_worker_request import canonical_program,decimal_program,format_program
ROOT=Path(__file__).resolve().parents[1]
ENTRY=r'''
def rank_canonical(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)<128 or length(w)<131072 or length(o)<64 or read64(s,0)!=REQUEST:
        return 4294967293
    action=read64(s,8)
    root=read64(s,16)
    jn=read64(s,24)
    an=read64(s,32)
    if action>1 or jn==0 or an==0 or jn>length(s)-128 or an!=length(s)-128-jn:
        return 4294967293
    at=40
    while at<128:
        if read64(s,at)!=0:
            return 4294967293
        at=at+8
    if an>length(w)-16384 or arena_valid(s,w,128+jn,an,jn)==False or root>=read64(s,128+jn+8):
        return 4294967293
    i=0
    while i<an:
        store(w,i,byte(s,128+jn+i))
        i=i+1
    private=length(w)-16384
    put(w,private,0)
    put(w,private+8,root)
    put(w,private+16,0)
    result=serialize(s,o,w)
    if result!=0:
        return 4294967280
    if get(w,private+16)!=0:
        return 4294967293
    needed=get(w,56)
    if action==1:
        if needed>length(o)-64:
            return 4294967294
        put(w,private,1)
        result=serialize(s,o,w)
        if result!=0 or get(w,private+16)!=0 or get(w,56)!=needed:
            return 4294967293
    zero(o,64)
    put(o,0,REPLY)
    put(o,8,needed)
    put(o,16,root)
    put(o,24,jn)
    put(o,32,an)
    return 0

def append_byte(o:mutbuf,w:mutbuf,value:u64) -> u64:
    at=get(w,56)
    private=length(w)-16384
    if at==18446744073709551615:
        put(w,private+16,1)
        return 0
    if get(w,private)==1:
        store(o,64+at,value)
    put(w,56,at+1)
    return 0

def fractional(s:readbuf,start:u64,size:u64) -> bool:
    at=0
    while at<size:
        value=byte(s,start+at)
        if value==46 or value==101 or value==69:
            return True
        at=at+1
    return False

def widen(value:u32) -> u64:
    return value
'''
def source_program():
    serializer=canonical_program()
    serializer=serializer.replace('* 56','* 72')
    serializer=serializer.replace('    node = 0','    root = get(w, length(w)-16384+8)\n    node = root')
    serializer=serializer.replace('if parent != 18446744073709551615:', 'if node != root:')
    serializer=serializer.replace('if parent == 18446744073709551615:', 'if node == root:')
    serializer=serializer.replace('                sibling = get(w, record + 16)\n','                sibling = get(w, record + 16)\n                if node == root:\n                    sibling = 18446744073709551615\n')
    old='            start = get(w, record + 24)\n            size = get(w, record + 32)'
    assert serializer.count(old)==1
    serializer=serializer.replace(old,old+'\n            if kind != 4:\n                start = start + 128\n            if kind == 3 and fractional(s,start,size):\n                kind = 7')
    for indent in ('        ','    '):
        old=indent+'if get(w, 56) > 8388608:\n'+indent+'    return 4294967274\n'
        assert old in serializer
        serializer=serializer.replace(old,'')
    serializer=serializer.replace('    return get(w, 56)\n','    return 0\n')
    serializer='\n'.join(ast.unparse(n) for n in ast.parse(serializer).body if n.name!='append_byte')+'\n'
    wanted={'arena_valid','nodeword','read64','readn','get','put','zero','choose'}
    helpers=[ast.unparse(n)for n in ast.parse(admission_source()).body if n.name in wanted]
    assert len(helpers)==len(wanted)
    decimal=decimal_program()
    # This private aggregate serializer does not impose the separate original
    # Core byte limit on unrelated transport values. The limb algorithm is unchanged.
    decimal=decimal.replace('if n == 0 or n > 8388608:', 'if n == 0:')
    text=ENTRY+'\n'+serializer+'\n'+'\n'.join(helpers)+'\n'+decimal+'\n'+format_program()
    for key,value in {'REQUEST':int.from_bytes(b'HIANJQ01','little'),'REPLY':int.from_bytes(b'HIANKJ01','little')}.items():
        text=re.sub(r'\b'+key+r'\b',str(value),text)
    names=[n.name for n in ast.parse(text).body];assert len(names)==len(set(names))
    return text
def program():return document(source_program(),'ndu_rank_canonical')
if __name__=='__main__':
    path=ROOT/'examples/hia_bootstrap/ndu_rank_canonical.hepta';path.write_text(render_assembly(program()));print(path.name,path.stat().st_size,flush=True)
