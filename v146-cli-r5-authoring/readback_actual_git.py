"""Reconstruct the complete R5 author package from actual Git GET responses."""
import ast, base64, hashlib, json, stat, zlib
from copy import deepcopy
from pathlib import Path
R=Path(__file__).absolute().parent
def enc(v):return (json.dumps(v,sort_keys=True,indent=2,ensure_ascii=True,allow_nan=False)+'\n').encode()
def pin(b,m='100644'):return dict(bytes=len(b),mode=m,sha256=hashlib.sha256(b).hexdigest(),git_blob=hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest())
def seven(s):return [s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def put(n,v):
 b=enc(v)
 with (R/n).open('xb') as f:f.write(b)
 return dict(file=n,pin=pin(b))
rows=json.loads((R/'PUBLICATION-INPUTS.json').read_bytes());fetched={}
for row in rows:
 n=Path(row['file']).name
 post=json.loads((R/'GIT-ACK'/(n+'.POST.json')).read_bytes());get=json.loads((R/'GIT-ACK'/(n+'.GET.json')).read_bytes())
 assert not post.get('isError') and not get.get('isError') and post['structuredContent']['sha']==row['pin']['git_blob']
 b=get['structuredContent']['content'].encode();assert pin(b)==row['pin'] and b==(R/row['file']).read_bytes()
 fetched[row['file']]=json.loads(b)
m=fetched['MANIFEST.json'];chunks=[]
for i,row in enumerate(m['parts']):
 p=fetched[row['file']];b=base64.b64decode(p['data'],validate=True)
 assert p['index']==i and p['count']==len(m['parts']) and p['offset']==sum(map(len,chunks)) and pin(b)==p['decoded_pin']
 chunks.append(b)
z=b''.join(chunks);assert pin(z)==m['compressed_pin'] and z==(R/'AUTHORING.zlib').read_bytes()
raw=zlib.decompress(z);assert pin(raw)==m['payload_pin'];payload=json.loads(raw)
assert len(payload['files'])==m['complete_files']==33
by={}
for row in payload['files']:
 b=row['text'].encode();assert pin(b,row['pin']['mode'])==row['pin']
 p=Path(row['path']);s=p.lstat();current=p.read_bytes();t=p.lstat()
 assert stat.S_ISREG(s.st_mode) and stat.S_IMODE(s.st_mode)==row['posix_mode'] and current==b and seven(s)==seven(t)==row['seven_stats']
 by[row['logical']]=b
assert [{k:v for k,v in row.items() if k!='text'} for row in payload['files']]==m['files']
projection=json.loads(by['author/BINDER-PROJECTION.json']);text=by['author/bind_positions_plan.py'].decode();inverse=text
for edit in reversed(projection['edits']):
 assert inverse.count(edit['after'])==edit['count'];inverse=inverse.replace(edit['after'],edit['before'])
assert inverse.encode()==by['author/before/bind_context_plan.py']
of={n.name:ast.get_source_segment(inverse,n) for n in ast.parse(inverse).body if isinstance(n,ast.FunctionDef)}
nf={n.name:ast.get_source_segment(text,n) for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)}
assert set(nf)==set(of)|{'admit_current_failure'} and all(nf[k]==v for k,v in of.items() if k!='prepare')
old=json.loads(by['author/before/EXECUTION-PLAN.json']);new=json.loads(by['author/PROPOSED-EXECUTION-PLAN.json'])
keys=('source','source_manifest','source_modes','source_tree','adapter_files','attempt','controls','predecessor_evidence');inv=deepcopy(new)
for key in keys:inv[key]=old[key]
assert {k for k in old if old[k]!=new[k]}==set(keys) and enc(inv)==by['author/before/EXECUTION-PLAN.json']
assert new['predecessor_evidence']['parts'][:5]==old['predecessor_evidence']['parts'] and len(new['predecessor_evidence']['parts'])==6 and new['predecessor_evidence']['row_count']==64615
before=by['author/before/run_inspect_cli_controls.py'];after=by['author/run_inspect_cli_controls.py'];a=b"and type(value['row_count']) is int and value['row_count'] == 61683";b=a.replace(b'61683',b'64615')
assert before.count(a)==after.count(b)==1 and after.replace(b,a,1)==before
for name,key in [('inspect_cli_control_support.py','r4_control_support_copy'),('test_inspect_cli_witness_controls.py','r4_witness_tests_copy')]:
 assert pin(by['author/'+name])==old['controls'][key]['pin']
sp=json.loads(by['author/OPERAND-PROJECTION.json']);inverse=by['repair/after/operand.py'].decode()
for edit in reversed(sp['edits']):
 assert inverse.count(edit['after'])==1;inverse=inverse.replace(edit['after'],edit['before'],1)
assert inverse.encode()==by['repair/before/operand.py']
terminal=json.loads(by['history/R4-ROOT-TERMINAL.json']);inventory=json.loads(by['history/R4-ROOT-INVENTORY.json'])
history=json.loads(by['author/PREDECESSORS-005-R4-FAILURE.json'])
request=json.loads(by['author/PREPARATION-PLAN.json'])
assert terminal['inventory']==pin(by['history/R4-ROOT-INVENTORY.json']) and terminal['raw_files']==len(inventory)==2930
assert history==[request['failure_terminal'],request['failure_inventory']]+[{k:v[k] for k in ('path','pin','posix_mode')} for v in inventory.values()]
assert len(history)==2932 and sum(r['pin']['bytes'] for r in history[2:])==terminal['raw_bytes']==22039778
assert pin(by['history/R4-PREPARATION-REQUEST.json'])==request['original_preparation']['pin']
core=fetched['CORE-REVIEW-CAPSULE.json'];cz=base64.b64decode(core['data'],validate=True);assert pin(cz)==core['compressed_pin']
cr=zlib.decompress(cz);assert pin(cr)==core['payload_pin']
for row in json.loads(cr)['files']:assert by[row['logical']]==row['text'].encode()
proof=dict(status='PASS_ACTUAL_GIT_FULL_AUTHORING_READBACK',actual_ack_full_get_blobs=len(rows),complete_files=33,file_bytes=m['file_bytes'],payload_pin=m['payload_pin'],compressed_pin=m['compressed_pin'],all_current_file_bytes_modes_seven_stats_equal=True,whole_binder_inverse=True,original_seven_helper_bodies_equal=True,whole_executor_inverse=True,whole_plan_inverse=True,whole_operand_inverse=True,all_original_five_part_descriptors_unchanged=True,new_R4_history_rows_exact=2932,source_materializations=0,binder_executions=0,product_executions=0)
pr=put('ACTUAL-GIT-READBACK.json',proof);script=dict(file='readback_actual_git.py',pin=pin(Path(__file__).read_bytes()))
recipe=dict(schema='hepta.immutable-git-recipe.v1',repository='TrillionniumFoundation/Hepta',leaves=rows+[script,pr],scope='R5 operand-position independent materialization and execution binding authoring only',complete_authoring_files=33,parts=len(m['parts']),decoded_payload=m['payload_pin'],actual_readback=proof,source_only_recipe=m['source_only_recipe'],r4_binding_recipe=m['r4_binding_recipe'],existing_five_predecessor_parts=m['prior_five_parts'],R4_failure_terminal='1205d0eacbcca0e536e9b785662ca4e2479bd05d',R4_failure_inventory='83f1057a2037fe5391c18895d011d31c26940813',full_historical_raw_not_repacked_here=True,future_root=m['future_root'],no_execution_authorization=True)
rr=put('MOUNT-RECIPE.json',recipe)
handoff=dict(schema='hepta.hia.inspect-cli-r5-binding-handoff.v1',state='AUTHORING_ONLY_UNEXECUTED',root='/tmp/hia-inspect-cli-controls-r5-dda7',recipe=rr,core=rows[0],full_manifest=rows[1],actual_git_readback=pr,preparation_launch=json.loads(by['author/PREPARATION-LAUNCH.json']),binder=projection['after'],source_only_recipe=m['source_only_recipe'],future_source_tree=new['source_tree'],source_files=3191,predecessor_rows=64615,unchanged_method_invocations=76,unchanged_groups=18,unchanged_fresh_compiles=7,source_materializations=0,binder_executions=0,product_executions=0)
hr=put('HANDOFF.json',handoff)
put('FOLLOWUP-PUBLICATION-INPUTS.json',[script,pr,rr,hr])
print(json.dumps(dict(proof=pr,recipe=rr,handoff=hr,files=33,parts=len(m['parts']),product_executions=0,binder_executions=0),sort_keys=True))
