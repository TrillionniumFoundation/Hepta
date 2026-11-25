"""Author the native public direct-call proof receipt adapter.

Reuses the qualified public JSON/diagnostic and digest-binding semantics.
Only call profiles, original call diagnostics and call implementation identity
differ. This role never turns a caller receipt into proof authority.
"""
from pathlib import Path
import ast,re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_system_jobctl_request import document
from tools import generate_hia_native_public_proof_receipt as shared
from tools import generate_hia_native_call_proof_policy as base
ROOT=Path(__file__).resolve().parents[1]
SOURCE_PATH='examples/hia_bootstrap/native_public_call_proof_receipt.hepta'
C={**shared.C,**base.C,**{k:v for k,v in shared.C.items() if k not in base.C},
   'PUB_REQUEST':int.from_bytes(b'HIAJPC01','little')}
LABELS={**shared.LABELS,40:'implementation',41:'call_expansions',42:'call_closure',43:'call_closures',
 101:'hepta.hia.scalar-call-totality.v1',102:'hepta.hia.scalar-call-validation.v1',
 103:'hia.scalar-acyclic-direct-calls-bitvector-totality.v1',
 104:'hia.scalar-acyclic-direct-calls-bitvector-first-traps.v1',
 109:'symbolic_call_expansion_budget_exceeded'}
EXTRA={**shared.EXTRA,509:',"error_type":"HIAProgramRejected"'}
IDENTITIES=shared.IDENTITIES
def replace_one(text,old,new):
 assert text.count(old)==1,(old,text.count(old))
 return text.replace(old,new,1)
POLICY=shared.POLICY
POLICY=replace_one(POLICY,'def public_proof_receipt(','def public_call_proof_receipt(')
POLICY=replace_one(POLICY,'if action>3 or mode<1','if action>1 or mode<1')
POLICY=replace_one(POLICY,'    if action==3:\n        return receipt_selection(s,o,w)\n','')
POLICY=replace_one(POLICY,'    if action==2:\n        if large and string_id(s,arena,field(s,arena,0,2))!=105:\n            return BAD\n        return verify_fresh(s,o,w)\n','')
# Drop the primitive saved-translation receipt operations: calls expose fresh
# totality/equivalence, and do not acquire a second saved-receipt authority API.
drop={'receipt_selection','verify_fresh','verify_key','scope_key','receipt_error'}
POLICY='\n\n'.join(ast.get_source_segment(POLICY,n) for n in ast.parse(POLICY).body if isinstance(n,ast.FunctionDef) and n.name not in drop)+'\n'
POLICY=replace_one(POLICY,'        if key==12:\n','        if key==40:\n            return patch_object(s,o,w,node,6,at,depth+1)\n        if key==41 and read64(s,16)==1 and string_id(s,get(w,CTX+8),field(s,get(w,CTX+8),0,36))==109:\n            return unsigned(o,w,at,0)\n        if key==12:\n')
POLICY=replace_one(POLICY,'    elif path==4 and key==22:\n','    elif (path==4 or path==6) and key==22:\n')
POLICY=replace_one(POLICY,'    subject=field(s,arena,0,17)\n','''    implementation=field(s,arena,0,40)
    if nodeword(s,arena,implementation,0)!=6 or nodeword(s,arena,implementation,32)!=1:
        return BAD
    if digest_matches(s,arena,field(s,arena,implementation,22),288)==False:
        return BAD
    subject=field(s,arena,0,17)
''')
POLICY=replace_one(POLICY,'        if key==12:\n','        if key==25:\n            return unsigned(o,w,at,read64(s,40))\n        if key==12:\n')
POLICY=replace_one(POLICY,'    result=base_receipt(o,w)\n','    result=base_receipt(s,o,w)\n')
POLICY=replace_one(POLICY,'    if get(w,DIAG_LARGE)!=0:\n        return append_large_diagnostic(s,o,w,result)\n','    if get(w,DIAG_LARGE)!=0 and read64(s,16)==1:\n        return append_large_diagnostic(s,o,w,result)\n')
POLICY=replace_one(POLICY,'def validation_fields(o:mutbuf,w:mutbuf,at:u64) -> u64:\n    if get(w,DIAG_SIZE)==0:\n','def validation_fields(o:mutbuf,w:mutbuf,at:u64) -> u64:\n    if get(w,256)==2 and get(w,DIAG_CODE)!=0:\n        return lit(o,at,509)\n    if get(w,DIAG_SIZE)==0:\n')
def source_program():
 render=base.RENDER.replace('def receipt(o:mutbuf, w:mutbuf)', 'def base_receipt(s:readbuf,o:mutbuf, w:mutbuf)')
 first=render.index('\ndef identities(')
 last=render.index('\ndef solver_report(',first)
 render=render[:first]+'\n'+IDENTITIES+render[last:]
 old='    at = identities(o, w, at)'
 assert render.count(old)==2
 render=render.replace(old,'    put(w, SUBJECT, 0)\n'+old,1)
 at=render.index(old,render.index(old)+len(old))
 render=render[:at]+'    put(w, SUBJECT, 1)\n'+render[at:]
 render=replace_one(render,'    at = lit(o, at, 100 + reason)','''    if total==False and get(w,DIAG_CODE)!=0:
        if get(w,DIAG_LARGE)!=0:
            at=input_copy(s,o,at,get(w,DIAG_RAW),get(w,DIAG_RAW_N))
        else:
            at=quote_work(o,w,at,DIAG_TEXT,get(w,DIAG_SIZE))
    else:
        at = lit(o, at, 100 + reason)''')
 render=replace_one(render,'    at = lit(o, at, 27)','    at = validation_fields(o, w, at)\n    at = lit(o, at, 27)')
 render=replace_one(render,'    if status == 2:\n        at = counterexample(o, w, at)\n    else:\n        at = lit(o, at, 12)','    at = lit(o, at, 12)')
 remove={'counterexample','observed','values','closure_subject','closure_report','closure_names','name_before'}
 render='\n\n'.join(ast.get_source_segment(render,n) for n in ast.parse(render).body if isinstance(n,ast.FunctionDef) and n.name not in remove)+'\n'
 render=render.replace('closure_report(o,w,at)','closure_report(s,o,w,at)').replace('closure_subject(o,w,at)','closure_subject(s,o,w,at)')
 render+=r'''
def closure_subject(s:readbuf,o:mutbuf,w:mutbuf,at:u64) -> u64:
    total=get(w,256)==1
    at=lit(o,at,choose(total,401,402))
    arena=get(w,CTX+8)
    node=NONE
    if read64(s,352)!=0:
        node=field(s,arena,0,choose(total,42,43))
    if node!=NONE and nodeword(s,arena,node,0)==5:
        return copy_node(s,o,get(w,CTX),arena,node,at)
    at=emit(o,at,91)
    if total==False:
        at=emit(o,at,91)
        at=emit(o,at,93)
        at=emit(o,at,44)
        at=emit(o,at,91)
        at=emit(o,at,93)
    return emit(o,at,93)

def closure_report(s:readbuf,o:mutbuf,w:mutbuf,at:u64) -> u64:
    at=closure_subject(s,o,w,at)
    at=lit(o,at,403)
    arena=get(w,CTX+8)
    node=NONE
    if read64(s,352)!=0:
        node=field(s,arena,0,41)
    if node!=NONE:
        kind=nodeword(s,arena,node,0)
        if kind==3 or kind==5:
            return copy_node(s,o,get(w,CTX),arena,node,at)
    if get(w,256)==1:
        return emit(o,at,48)
    at=emit(o,at,91)
    at=emit(o,at,48)
    at=emit(o,at,44)
    at=emit(o,at,48)
    return emit(o,at,93)
'''

 wanted={'get','getn','put','now','mask','trap_code'}
 helpers=[ast.get_source_segment(base.POLICY,node) for node in ast.parse(base.POLICY).body if isinstance(node,ast.FunctionDef) and node.name in wanted]
 assert len(helpers)==len(wanted)
 old_literals=base.LITERALS
 try:
  base.LITERALS={**old_literals,**EXTRA}
  literals=base.literal_source()
 finally:base.LITERALS=old_literals
 entries=list(LABELS.items());groups=[entries[i:i+12] for i in range(0,len(entries),12)]
 labels=['def label(s:readbuf,at:u64,n:u64) -> u64:']
 for i,group in enumerate(groups):labels += [f'    answer=label_part_{i}(s,at,n)','    if answer!=0:','        return answer']
 labels.append('    return 0')
 for i,group in enumerate(groups):
  labels += ['',f'def label_part_{i}(s:readbuf,at:u64,n:u64) -> u64:']
  for key,value in group:
   raw=value.encode()
   parts=[f'n=={len(raw)}']+[f'readn(s,at+{i},{len(raw[i:i+8])})=={int.from_bytes(raw[i:i+8],"little")}' for i in range(0,len(raw),8)]
   labels += ['    if '+' and '.join(parts)+':',f'        return {key}']
  labels.append('    return 0')
 source=POLICY+'\n'+render+'\n'+'\n\n'.join(helpers)+'\n'+literals+'\n'+'\n'.join(labels)
 for name,value in sorted(C.items(),key=lambda x:-len(x[0])):source=re.sub(r'\b'+name+r'\b',str(value),source)
 return source
def program():return document(source_program(),'native_public_call_proof_receipt')
if __name__=='__main__':
 tree=program();p=ROOT/SOURCE_PATH;p.write_text(render_assembly(tree))
 print(p.name,p.stat().st_size,len(tree['functions']),sum(len(f['blocks']) for f in tree['functions']),sum(len(b['ops']) for f in tree['functions'] for b in f['blocks']),flush=True)
