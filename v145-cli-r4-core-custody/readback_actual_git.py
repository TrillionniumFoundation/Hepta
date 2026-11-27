"""Actual GET reconstruction and full small-capsule readback, zero products."""
import base64, hashlib, json, stat, zlib
from copy import deepcopy
from pathlib import Path
R=Path(__file__).absolute().parent
def enc(v): return (json.dumps(v,sort_keys=True,indent=2,ensure_ascii=True,allow_nan=False)+'\n').encode()
def pin(b,mode='100644'): return dict(bytes=len(b),mode=mode,sha256=hashlib.sha256(b).hexdigest(),git_blob=hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest())
def seven(s): return [s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def put(n,v):
 b=enc(v)
 with (R/n).open('xb') as f: f.write(b)
 return dict(file=n,pin=pin(b))
rows=json.loads((R/'PUBLICATION-INPUTS.json').read_bytes()); fetched={}
for row in rows:
 n=Path(row['file']).name
 post=json.loads((R/'GIT-ACK'/(n+'.POST.json')).read_bytes())
 get=json.loads((R/'GIT-ACK'/(n+'.GET.json')).read_bytes())
 assert not post.get('isError') and not get.get('isError')
 assert post['structuredContent']['sha']==row['pin']['git_blob']
 b=get['structuredContent']['content'].encode()
 assert pin(b)==row['pin'] and b==(R/row['file']).read_bytes()
 fetched[row['file']]=json.loads(b)
m=fetched['MANIFEST.json']; chunks=[]
for i,row in enumerate(m['parts']):
 part=fetched[row['file']]; b=base64.b64decode(part['data'],validate=True)
 assert part['index']==i and part['count']==3 and part['offset']==sum(map(len,chunks))
 assert pin(b)==part['decoded_pin']; chunks.append(b)
z=b''.join(chunks); assert pin(z)==m['compressed_pin'] and z==(R/'AUTHORING.zlib').read_bytes()
raw=zlib.decompress(z); assert pin(raw)==m['payload_pin']
p=json.loads(raw); assert len(p['files'])==m['complete_files']==32
byname={}
for row in p['files']:
 b=row['text'].encode(); assert pin(b,row['pin']['mode'])==row['pin']
 path=Path(row['path']); s=path.lstat(); current=path.read_bytes(); t=path.lstat()
 assert stat.S_ISREG(s.st_mode) and stat.S_IMODE(s.st_mode)==row['posix_mode']
 assert current==b and seven(s)==seven(t)==row['seven_stats']
 byname[row['logical']]=b
assert [{k:v for k,v in row.items() if k!='text'} for row in p['files']]==m['files']
old=json.loads(byname['before/EXECUTION-PLAN.json']); new=json.loads(byname['author/PROPOSED-EXECUTION-PLAN.json'])
keys=('source','source_manifest','source_modes','source_tree','adapter_files','attempt','controls','predecessor_evidence')
assert {k for k in old if old[k]!=new[k]}==set(keys)
inverse=deepcopy(new)
for k in keys: inverse[k]=old[k]
assert enc(inverse)==byname['before/EXECUTION-PLAN.json']
assert new['predecessor_evidence']['parts'][:4]==old['predecessor_evidence']['parts']
assert new['predecessor_evidence']['row_count']==61683 and len(new['predecessor_evidence']['parts'])==5
oldrun=byname['before/run_inspect_cli_controls.py']; run=byname['author/run_inspect_cli_controls.py']
a=b"and type(value['row_count']) is int and value['row_count'] == 61550"; b=a.replace(b'61550',b'61683')
assert oldrun.count(a)==run.count(b)==1 and run.replace(b,a,1)==oldrun
assert byname['before/records.py'].replace(b'from __future__ import annotations\n',b'from __future__ import annotations\nimport copy\n',1)==byname['after/records.py']
core=fetched['CORE-REVIEW-CAPSULE.json']; cz=base64.b64decode(core['data'],validate=True)
assert pin(cz)==core['compressed_pin']; cr=zlib.decompress(cz); assert pin(cr)==core['payload_pin']
for row in json.loads(cr)['files']: assert byname[row['logical']]==row['text'].encode()
proof=dict(status='PASS_ACTUAL_GIT_FULL_AUTHORING_READBACK',actual_ack_full_get_blobs=len(rows),
 complete_files=32,file_bytes=m['file_bytes'],payload_pin=m['payload_pin'],compressed_pin=m['compressed_pin'],
 all_current_file_bytes_modes_seven_stats_equal=True,whole_runner_inverse=True,whole_plan_inverse=True,
 all_original_four_part_descriptors_unchanged=True,source_materializations=0,binder_executions=0,product_executions=0)
pr=put('ACTUAL-GIT-READBACK.json',proof)
script=dict(file='readback_actual_git.py',pin=pin(Path(__file__).read_bytes()))
leaves=rows+[script,pr]
recipe=dict(schema='hepta.immutable-git-recipe.v1',repository='TrillionniumFoundation/Hepta',leaves=leaves,
 scope='R4 module-context independent materialization/binding authoring only',
 complete_authoring_files=32,parts=3,decoded_payload=m['payload_pin'],actual_readback=proof,
 records_source_recipe='9606fac9bac72bfbd56802705820b467631e530c',
 existing_failure_custody='5f3c6b23d33dc437d4dc2a4146fe272bcc05f0a7',
 existing_four_predecessor_parts=old['predecessor_evidence']['parts'],
 future_root='/dev/shm/hia-inspect-cli-controls-r4-dda7',no_execution_authorization=True)
rr=put('MOUNT-RECIPE.json',recipe)
put('FOLLOWUP-PUBLICATION-INPUTS.json',[script,pr,rr])
print(json.dumps(dict(proof=pr,recipe=rr,files=32,parts=3,product_executions=0,binder_executions=0),sort_keys=True))
