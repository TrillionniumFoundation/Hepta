"""New constructor-aware session profile; the installed frontend profile is unchanged."""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
from tools import generate_hia_generation_runtime_frontend_proxy as prior
ROOT=Path(__file__).resolve().parents[1]
C=dict(prior.C,FACTORY_ENTRY=688,FQ=int.from_bytes(b'HIARTCQ1','little'),FACTORY=int.from_bytes(b'HIARTFW1','little'))
def replace(s,a,b):
 assert s.count(a)==1,(a,s.count(a));return s.replace(a,b,1)
def source_program():
 s=prior.SOURCE
 s=replace(s,'get(o,ROLE)>4','get(o,ROLE)>5')
 s=replace(s,'        if get(o,ROLE)>=3:\n','        if get(o,ROLE)==3 or get(o,ROLE)==4:\n')
 old='''        if valid_session(o)==0 or get(o,SM+40)!=1 or get(o,SM+48)!=0 or get(o,SM+56)!=1:
            return fail_locked(o)
        if get(o,M+400)==0:
            return fail_locked(o)
        put(o,SM+48,1)
        return capture(o,w)
'''
 s=replace(s,old,'''        if get(o,ROLE)==0 and get(o,MODE)==1:
            return memory(o,65,0,get(o,FRONT)+524288,3,FH,512)
        return reuse_session(o,w)
''')
 s=replace(s,'    if phase==30:\n','''    if phase==65:
        if r!=0:
            return fail_locked(o)
        if get(o,FH)!=0:
            if get(o,FH)!=FACTORY or get(o,FH+8)!=get(o,PID) or get(o,FH+16)!=get(o,FRONT) or get(o,FH+24)!=get(o,ROOT_PTR):
                return fail_locked(o)
            if get(o,FH+48)!=3 or get(o,FH+32)!=0 or get(o,FH+80)!=0 or get(o,FH+88)!=1:
                return fail_locked(o)
        return reuse_session(o,w)
    if phase==30:
''')
 assert s.count('if get(o,ROLE)<3:')==3
 s=s.replace('if get(o,ROLE)<3:','if get(o,ROLE)<3 or get(o,ROLE)==5:')
 s=replace(s,'    if role==3:\n','''    if role==5:
        if length(s)!=256 or word(s,0)!=FQ or word(s,8)>1 or get(o,WORK_N)!=1048576 or get(o,OUTPUT_N)<1048576:
            return 0
        i=16
        while i<256:
            used=word(s,8)==0 and i>=24 and i<=184
            if used==False and word(s,i)!=0:
                return 0
            i=i+8
        if word(s,8)==0 and (word(s,24)==0 or word(s,48)==0):
            return 0
        return 1
    if role==3:
''')
 s=replace(s,'    put(o,TARGET,get(o,M+184+get(o,ROLE)*8))\n','''    if get(o,ROLE)==5:
        put(o,TARGET,get(o,FACTORY_ENTRY))
    else:
        put(o,TARGET,get(o,M+184+get(o,ROLE)*8))
''')
 s+='''\ndef reuse_session(o:mutbuf,w:mutbuf) -> u32:
    if valid_session(o)==0 or get(o,SM+40)!=1 or get(o,SM+48)!=0 or get(o,SM+56)!=1:
        return fail_locked(o)
    if get(o,M+400)==0:
        return fail_locked(o)
    put(o,SM+48,1)
    return capture(o,w)
'''
 for k,v in sorted(C.items(),key=lambda x:-len(x[0])):s=re.sub(r'\b'+k+r'\b',str(v),s)
 return s
def main():
 t=document(source_program(),'generation_runtime_factory_proxy')
 p=ROOT/'examples/hia_bootstrap/generation_runtime_factory_proxy.hepta';p.write_text(render_assembly(t))
 print(p.name,p.stat().st_size,len(t['functions']),sum(len(f['blocks'])for f in t['functions']),sum(len(b['ops'])for f in t['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
