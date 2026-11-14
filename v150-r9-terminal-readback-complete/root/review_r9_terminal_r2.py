from pathlib import Path
import ast,base64,hashlib,json,os
ROOT=Path('/tmp/hia-progress-v150-20261114-dda7')
AUTHOR=Path('/tmp/hia-r9-controls-terminal-reader-r2-dda7')
def pin(b):return {'bytes':len(b),'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest(),'sha256':hashlib.sha256(b).hexdigest()}
def bodies(b):
 lines=b.splitlines(keepends=True)
 return {n.name:b''.join(lines[n.lineno-1:n.end_lineno]) for n in ast.parse(b).body if isinstance(n,ast.FunctionDef)}
def apply(before,changes):
 after=before
 for e in changes:
  a=e['before'].encode();b=e['after'].encode();assert after.count(a)==e['count'];after=after.replace(a,b)
 check=after
 for e in reversed(changes):
  a=e['before'].encode();b=e['after'].encode();assert check.count(b)==e['count'];check=check.replace(b,a)
 assert check==before
 return after
i=json.loads((AUTHOR/'EXACT-INVERSE-R2.json').read_bytes());prior=json.loads((AUTHOR/'prior-r1/EXACT-INVERSE.json').read_bytes())
original=base64.b64decode(i['R4_original_raw_base64'],validate=True)
assert pin(original)==i['R4_original'] and pin(original)['git_blob']=='ced99939a0e7de4c1841503112949ea525fdfee1'
assert original==base64.b64decode(prior['original_raw_base64'],validate=True)
r1=apply(original,prior['edits'])
assert len(prior['edits'])==25 and r1==(AUTHOR/'prior-r1/verify_terminal.py').read_bytes()
assert pin(r1)==i['R1']==prior['after'] and i['R1_edits']==prior['edits']
r2=apply(r1,i['edits']);assert len(i['edits'])==2
assert r2==(AUTHOR/'verify_terminal.py').read_bytes()==base64.b64decode(i['R2_raw_base64'],validate=True)
assert pin(r2)==i['R2'] and pin(r2)['git_blob']=='b97a012ee2ce1870aa4a1e39195f0523c60cd4b6'
helpers=['canonical','dump','full','git_tree','j','native_frames','need','pin','read','seven','tree_state','vm_frames']
for n in helpers:assert bodies(original)[n]==bodies(r1)[n]==bodies(r2)[n]
imports={n.names[0].name for n in ast.parse(r2).body if isinstance(n,ast.Import)}
assert imports=={'argparse','hashlib','json','os','stat','time','traceback'}
launch=json.loads((AUTHOR/'LAUNCH.json').read_bytes())
assert launch['reader']['identity']==pin(r2) and launch['products']==launch['project_imports']==0
assert launch['maximum_actual_invocations']==1 and launch['automatic_retry'] is False
assert not os.path.lexists(launch['output'])
review={'schema':'hia.root.R9.terminal-R2.independent-author-review.v1','status':'PASS_TWO_LAYER_WHOLE_INVERSE_STATIC_REVIEW_ONLY','reader':pin(r2),'launch':pin((AUTHOR/'LAUNCH.json').read_bytes()),'R4_to_R1_edits':25,'R1_to_R2_edits':2,'original_helpers_entirely_equal':helpers,'complete_input_role_assertions_preserved':True,'new_R4_R9_full_initial_buffer_comparison':True,'R1_metadata_precheck_failure_preserved':True,'new_reader_executions':0,'product_executions':0,'original_product_status':'FAIL_VM_FUEL'}
with (ROOT/'R9-TERMINAL-R2-ROOT-REVIEW.json').open('x')as f:json.dump(review,f,sort_keys=True,indent=2);f.write('\n')
print(json.dumps(review,sort_keys=True))
