"""Registered GX3 Clang generations without changing the original effects domain.

The explicit EX5 constructor and EX6 publication profiles borrow a real Value
cap held by their enclosing native operation. Runtime state/lease/list mutex
ordering, original writer serialization and all retirement ACKs are preserved.
"""
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_generation_lease_owner_generation_effects as base
from tools import generate_hia_multiversion_runtime_effects as original
from tools import generate_hia_multiversion_public_lease_admission as public
ROOT=Path(__file__).resolve().parents[1]
C=dict(original.C,CLANG_INITIAL=int.from_bytes(b'HIAMVEX5','little'),
 CLANG_PUBLISH=int.from_bytes(b'HIAMVEX6','little'),CLANG_GEN=int.from_bytes(b'HIAMVGX3','little'))
def replace(s,old,new):
 old=public.substitute(old,C);new=public.substitute(new,C)
 assert s.count(old)==1,(old,s.count(old))
 return s.replace(old,new)
def full_source():
 s=base.source_program()
 s=replace(s,'word(s,0)!=TIMED_REQUEST and word(s,0)!=',
   'word(s,0)!=TIMED_REQUEST and word(s,0)!=CLANG_INITIAL and word(s,0)!=CLANG_PUBLISH and word(s,0)!=')
 s=replace(s,'    public=word(s,0)==PUBLIC_REQUEST or word(s,0)==TIMED_REQUEST\n',
 '''    if word(s,0)==CLANG_INITIAL:
        if word(s,8)!=0 or word(s,224)==0:
            return 4294967293
    if word(s,0)==CLANG_PUBLISH:
        if (word(s,8)!=1 and word(s,8)!=2) or word(s,16)==0:
            return 4294967293
    public=word(s,0)==PUBLIC_REQUEST or word(s,0)==TIMED_REQUEST or word(s,0)==CLANG_INITIAL or word(s,0)==CLANG_PUBLISH
''')
 s=replace(s,'    if ext:\n        gn=word(s,224)\n',
  '    if ext and word(s,0)!=CLANG_INITIAL:\n        gn=word(s,224)\n')
 s=replace(s,'    while i<256:\n        if word(s,i)!=0:\n',
  '    if word(s,0)==CLANG_INITIAL:\n        i=248\n    while i<256:\n        if word(s,i)!=0:\n')
 s=replace(s,'            put(o,I_PUBLIC,get(w,416))\n',
 '''            put(o,I_PUBLIC,get(w,416))
            if get(o,OP)==1 or get(o,OP)==2:
                if (get(w,432)==1)!=(word(s,0)==CLANG_PUBLISH):
                    return result(o,w,1)
''')
 s=replace(s,'        put(w,416,get(o,I_PUBLIC))\n',
  '        put(w,416,get(o,I_PUBLIC))\n        put(w,432,choose(word(s,0)==CLANG_INITIAL,1,0))\n')
 s=replace(s,'    put(o,FRAME,GENREQ)\n    put(o,FRAME+16,get(w,64))\n',
 '''    put(o,FRAME,GENREQ)
    if get(w,432)==1:
        put(o,FRAME,CLANG_GEN)
        if get(o,OP)==0:
            copy_input(s,224,o,FRAME+224,24)
        else:
            copy_input(s,16,o,FRAME+224,24)
    put(o,FRAME+16,get(w,64))
''')
 return s
def source_program():
 import re
 s=full_source()
 match=re.search(r'def begin_generation\(.*?(?=\ndef |\Z)',s,re.S)
 assert match
 return s[:match.start()]+'def begin_generation(s:readbuf,o:mutbuf,w:mutbuf) -> u32:\n    return 33\n'+s[match.end():]
def main():
 tree=document(source_program(),'generation_lease_owner_runtime_effects')
 path=ROOT/'examples/hia_bootstrap/generation_lease_owner_runtime_effects.hepta'
 path.write_text(render_assembly(tree))
 print(path.name,path.stat().st_size,len(tree['functions']),sum(len(f['blocks'])for f in tree['functions']),sum(len(b['ops'])for f in tree['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
