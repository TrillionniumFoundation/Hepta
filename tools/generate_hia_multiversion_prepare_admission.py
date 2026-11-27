"""Fresh raw MV admission, preserving the original private normalization profile.

HIAMVNQ2 receives only a composition-captured integer policy. It invokes the
shared verify_program raw leaf and the qualified no-deadline normalization
process. HIAMVNQ1 remains the previous private normalization contract.
"""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_multiversion_prepare_intake import SOURCE as LEGACY, C as LEGACY_C
ROOT=Path(__file__).resolve().parents[1]
C=dict(LEGACY_C)
C.update(STRICT=int.from_bytes(b'HIAMVNQ2','little'),
         PSTRICT=int.from_bytes(b'HIAMVPS2','little'),
         STRICT_MODE=376,INTEGER_POLICY=384,PREF_WORK=(60<<20))
def replace_once(text,old,new):
    assert text.count(old)==1,(old,text.count(old))
    return text.replace(old,new)
SOURCE=replace_once(LEGACY,
    "if length(s)<128 or readword(s,0)!=REQUEST or readword(s,8)>1:",
    "if length(s)<128 or (readword(s,0)!=REQUEST and readword(s,0)!=STRICT) or readword(s,8)>1:")
SOURCE=replace_once(SOURCE,
    "    if readword(s,16)<3 or readword(s,16)>2147483647 or readword(s,24)==0:\n        return 4294967293",
    """    strict=readword(s,0)==STRICT
    if readword(s,16)<3 or readword(s,16)>2147483647:
        return 4294967293
    if (strict==False and readword(s,24)==0) or (strict and (readword(s,24)!=0 or readword(s,32)!=0)):
        return 4294967293
    digits=readword(s,48)
    if strict and digits!=0 and (digits<640 or digits>2147483647):
        return 4294967293""")
SOURCE=replace_once(SOURCE,
    "    if n>8388608 or length(s)-128!=n:",
    "    if (strict==False and n>8388608) or length(s)-128!=n:")
SOURCE=replace_once(SOURCE,
    "    i=48\n    while i<128:",
    "    i=48\n    if strict:\n        i=56\n    while i<128:")
SOURCE=replace_once(SOURCE,
    "    copy_input(s,128,w,RAW,n)\n    put(w,360,readword(s,16))\n    return guard(o,w,1)",
    """    put(w,STRICT_MODE,0)
    if strict:
        put(w,STRICT_MODE,1)
        put(w,INTEGER_POLICY,digits)
    put(w,360,readword(s,16))
    if strict and n>8388608:
        return fail(o,w,1,201)
    copy_input(s,128,w,RAW,n)
    if strict:
        zero(w,PREF_WORK,4096)
        put(w,PREF_WORK+80,digits)
        return role(w,9,7,RAW,n,PWORK,4194304,PREF_WORK,4096)
    return guard(o,w,1)""")
SOURCE=replace_once(SOURCE,
    "def normalized(o:mutbuf,w:mutbuf,phase:u64,result:u64) -> u32:\n    if phase==1:",
    """def normalized(o:mutbuf,w:mutbuf,phase:u64,result:u64) -> u32:
    if phase==9:
        if result==1 or result==4:
            return fail(o,w,1,202)
        if result==2:
            return fail(o,w,1,203)
        if result==5:
            return fail(o,w,1,205)
        if result!=0:
            return fail(o,w,8,201)
        return guard(o,w,1)
    if phase==1:""")
SOURCE=replace_once(SOURCE,
    "    put(w,PIN,PREQUEST)",
    "    put(w,PIN,PREQUEST)\n    if get(w,STRICT_MODE)==1:\n        put(w,PIN,PSTRICT)")
SOURCE=replace_once(SOURCE,
    "def guard(o:mutbuf,w:mutbuf,next:u64) -> u32:\n    put(w,344,next)",
    """def guard(o:mutbuf,w:mutbuf,next:u64) -> u32:
    if get(w,STRICT_MODE)==1:
        put(w,0,next)
        put(w,8,0)
        return 6
    put(w,344,next)""")
def source_program():
    s=SOURCE
    for k,v in sorted(C.items(),key=lambda x:-len(x[0])):s=re.sub(r'\b'+k+r'\b',str(v),s)
    return s
def main():
    t=document(source_program(),'multiversion_prepare_admission')
    p=ROOT/'examples/hia_bootstrap/multiversion_prepare_admission.hepta'
    p.write_text(render_assembly(t))
    print(p.name,p.stat().st_size,len(t['functions']),sum(len(f['blocks']) for f in t['functions']),sum(len(b['ops']) for f in t['functions'] for b in f['blocks']),flush=True)
if __name__=='__main__':main()
