"""Private native Clang generation beside the preserved GX1/GX2 profiles.

GX3 accepts the actual enclosing Runtime's strong clang Value capability.
The fixed child prepare owns its token/Clang/image resources. Every failed
holder returns the existing registration-required state before retirement.
"""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_multiversion_runtime_generation as original
ROOT=Path(__file__).resolve().parents[1]
C=dict(original.C,
 CAPTURED=int.from_bytes(b'HIAMVGX2','little'),CLANG_REQUEST=int.from_bytes(b'HIAMVGX3','little'),
 CAPTURE_INTAKE=int.from_bytes(b'HIAMVNQ2','little'),
 CLANG_PREPARE=int.from_bytes(b'HIAMVGF2','little'),CLANG_REPLY=int.from_bytes(b'HIAMVGR2','little'),
 CAPTURE_MODE=400,CLANG_MODE=3072,CLANG_CAP=3080,CLANG_PRIMARY=3104,CLANG_DETAIL=3112)
def replace_once(source,old,new):
    assert source.count(old)==1,(old,source.count(old))
    return source.replace(old,new,1)
EXTRA=r'''
def clang_begin(o:mutbuf,w:mutbuf) -> u32:
    put(w,CTRL+2800,1)
    cn=get(w,CTRL+120)
    an=get(w,CTRL+128)
    pn=get(w,CTRL+160)
    zero(w,FRAME,256)
    put(w,FRAME,CLANG_PREPARE)
    put(w,FRAME+24,get(w,CTRL+104))
    put(w,FRAME+40,cn)
    put(w,FRAME+48,an)
    put(w,FRAME+56,pn)
    copy(w,CTRL+CLANG_CAP,FRAME+64,24)
    copy(w,CORE,FRAME+256,cn)
    copy(w,ABI,FRAME+256+cn,an)
    copy(w,PATH,FRAME+256+cn+an,pn)
    return role(o,w,40,9,FRAME,256+cn+an+pn,OUT,1050624,0,WORK)

def clang_retire(o:mutbuf,w:mutbuf) -> u32:
    zero(w,FRAME,256)
    put(w,FRAME,CLANG_PREPARE)
    put(w,FRAME+8,1)
    return role(o,w,41,9,FRAME,256,OUT,2048,0,WORK)

def clang_result(o:mutbuf,w:mutbuf,retiring:bool) -> u32:
    raw=get(w,CTRL+8)
    put(w,CTRL+40,raw)
    if raw!=0 or get(w,OUT)!=CLANG_REPLY or get(w,OUT+344)!=1 or get(w,OUT+352)>1 or get(w,OUT+360)>1:
        put(w,CTRL+32,7)
        return finish(o,w,10)
    copy(w,OUT,CTRL+512,2048)
    put(w,CTRL+512,PREPARE_REPLY)
    if get(w,OUT+352)!=1:
        put(w,CTRL+512+1176,get(w,CTRL+512+1176)&18446744073709551607)
    if retiring:
        put(w,CTRL+32,7)
        if get(w,OUT+352)!=1 or get(w,OUT+360)!=0:
            put(w,CTRL+184,get(w,OUT+8))
            put(w,CTRL+192,get(w,OUT+376))
            return finish(o,w,5)
        if get(w,CTRL+232)==0:
            put(w,CTRL+184,get(w,CTRL+CLANG_PRIMARY))
            put(w,CTRL+192,get(w,CTRL+CLANG_DETAIL))
            put(w,CTRL+512+8,get(w,CTRL+CLANG_PRIMARY))
            return finish(o,w,4)
        put(w,CTRL+184,0)
        put(w,CTRL+192,0)
        return finish(o,w,0)
    if get(w,OUT+8)!=0 or get(w,OUT+40)!=1:
        put(w,CTRL+CLANG_PRIMARY,get(w,OUT+8))
        put(w,CTRL+CLANG_DETAIL,get(w,OUT+24))
        put(w,CTRL+184,get(w,OUT+8))
        put(w,CTRL+192,get(w,OUT+24))
        if get(w,OUT+392)==1:
            put(w,CTRL+168,1)
            put(w,CTRL+32,6)
            return finish(o,w,8)
        put(w,CTRL+32,7)
        return finish(o,w,4)
    put(w,CTRL+32,4)
    return finish(o,w,0)

def choose(condition:bool,yes:u64,no:u64) -> u64:
    if condition:
        return yes
    return no
'''
def source_program():
    s=original.SOURCE
    s=replace_once(s,'    if phase==32:\n        return after_retirement(o,w)\n',
        '    if phase==32:\n        return after_retirement(o,w)\n    if phase==40:\n        return clang_result(o,w,False)\n    if phase==41:\n        return clang_result(o,w,True)\n')
    s=replace_once(s,'    if length(s)<256 or readword(s,0)!=REQUEST:\n',
        '    if length(s)<256 or (readword(s,0)!=REQUEST and readword(s,0)!=CAPTURED and readword(s,0)!=CLANG_REQUEST):\n')
    s=replace_once(s,'    op=readword(s,8)\n',
        '''    op=readword(s,8)
    if readword(s,0)==CAPTURED and (op!=0 or readword(s,72)!=1):
        return 4294967293
    if readword(s,0)==CLANG_REQUEST and op!=0:
        return 4294967293
''')
    s=replace_once(s,'        return prepare_begin(o,w)\n',
        '        if get(w,CTRL+CLANG_MODE)==1:\n            return clang_begin(o,w)\n        return prepare_begin(o,w)\n')
    s=replace_once(s,'        put(w,CTRL+232,1)\n        return retire(o,w,1)\n',
        '        put(w,CTRL+232,1)\n        if get(w,CTRL+CLANG_MODE)==1:\n            put(w,CTRL+168,1)\n            put(w,CTRL+32,6)\n            return finish(o,w,8)\n        return retire(o,w,1)\n')
    s=replace_once(s,'    put(w,CTRL+168,0)\n    return prepare_subrole(o,w,8)\n',
        '    put(w,CTRL+168,0)\n    if get(w,CTRL+CLANG_MODE)==1:\n        return clang_retire(o,w)\n    return prepare_subrole(o,w,8)\n')
    s=replace_once(s,'    i=224\n    while i<256:\n',
        '''    i=224
    if readword(s,0)==CLANG_REQUEST:
        if readword(s,224)==0:
            return 4294967293
        i=248
    while i<256:
''')
    s=replace_once(s,'    put(w,CTRL+16,STATE)\n',
        '''    put(w,CTRL+16,STATE)
    captured=readword(s,0)==CAPTURED
    if readword(s,0)==CLANG_REQUEST and isbase==1:
        captured=True
    put(w,CTRL+CAPTURE_MODE,choose(captured,1,0))
    put(w,CTRL+CLANG_MODE,choose(readword(s,0)==CLANG_REQUEST,1,0))
    if readword(s,0)==CLANG_REQUEST:
        copy_input(s,224,w,CTRL+CLANG_CAP,24)
''')
    s=replace_once(s,'    put(w,FRAME,INTAKE)\n',
        '    put(w,FRAME,choose(get(w,CTRL+CAPTURE_MODE)==1,CAPTURE_INTAKE,INTAKE))\n')
    s=replace_once(s,'get(w,OUT+248)!=63',
        'get(w,OUT+248)!=choose(get(w,CTRL+CAPTURE_MODE)==1,61,63)')
    s+='\n'+EXTRA
    for key,value in sorted(C.items(),key=lambda row:-len(row[0])):
        s=re.sub(r'\b'+key+r'\b',str(value),s)
    return s
def main():
    t=document(source_program(),'generation_lease_owner_generation_clang')
    p=ROOT/'examples/hia_bootstrap/generation_lease_owner_generation_clang.hepta'
    p.write_text(render_assembly(t))
    print(p.name,p.stat().st_size,len(t['functions']),sum(len(f['blocks'])for f in t['functions']),sum(len(b['ops'])for f in t['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
