"""Compose the public call-proof front-end from the shared native owner.

The same normalizer, captured-child process, digest lifetime and public JSON
roles are used. Direct calls add their existing profile and ten-role proof
child; this is a private component endpoint for final facade qualification.
"""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_system_jobctl_request import document
from tools import generate_hia_public_scalar_proof as shared
ROOT=Path(__file__).resolve().parents[1]
M=shared.M
C={**shared.C,'REQUEST':M('HIAPPC01'),'REPLY':M('HIAMCR01'),
   'PROOF':M('HIAMCP02'),'RREQUEST':M('HIAJPC01')}
def replace_one(text,old,new):
 assert text.count(old)==1,(old,text.count(old))
 return text.replace(old,new,1)
def source_program():
 source=shared.SOURCE
 source=replace_one(source,'if mode<1 or mode>3 or name>128','if mode<1 or mode>2 or name>128')
 source=replace_one(source,'claim>262144','claim!=0')
 old='if mode==2 and (second==0 or claim!=0):'
 new='if mode==2 and claim!=0:'
 if old in source:source=replace_one(source,old,new)
 else:assert new in source
 source=replace_one(source,'budget<=60000','budget<=10000')
 source=replace_one(source,'    if phase==80:\n        zero(w,PIN,192)','''    if phase==80:
        if get(w,N1+24)!=0 or (get(w,256)==2 and get(w,N2+24)!=0):
            put(w,544,19)
            return prepare_result(o,w)
        zero(w,PIN,192)''')
 # Late closure preserves fresh call-closure metadata while clearing all
 # positive claims. Invalid or absent child arenas are never reused.
 source=replace_one(source,'    if action==0 or action==2:\n        an=get(w,768)','    if action==0 or action==2 or (action==1 and get(w,776)>=64 and get(w,768)>0):\n        an=get(w,768)')
 source=source.replace('7957704883298780518',str(M('function')))
 # The mechanical path/inventory helpers have identical owned storage.
 for key in ('INV','WHOLE'):assert C[key]==shared.C[key]
 resolved=shared.source_program()
 source+=resolved[resolved.index('\ndef self_path('):]
 for name,value in sorted(C.items(),key=lambda x:-len(x[0])):source=re.sub(r'\b'+name+r'\b',str(value),source)
 return source
def program():return document(source_program(),'public_call_proof')
if __name__=='__main__':
 tree=program();p=ROOT/'examples/hia_bootstrap/public_call_proof.hepta';p.write_text(render_assembly(tree))
 print(p.name,p.stat().st_size,len(tree['functions']),sum(len(f['blocks']) for f in tree['functions']),sum(len(b['ops']) for f in tree['functions'] for b in f['blocks']),flush=True)
