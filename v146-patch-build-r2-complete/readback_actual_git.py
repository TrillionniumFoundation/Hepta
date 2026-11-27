"""Reconstruct existing evidence from immutable Git GETs; execute no product."""
import base64,gzip,hashlib,json,os,stat
from pathlib import Path
R=Path(__file__).absolute().parent
def enc(v):return (json.dumps(v,sort_keys=True,indent=2,ensure_ascii=True,allow_nan=False)+'\n').encode()
def pin(b):return dict(bytes=len(b),git_blob=hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest(),sha256=hashlib.sha256(b).hexdigest())
def seven(s):return [s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def original(row):
 p=Path(row['path']);s=p.lstat();assert stat.S_ISREG(s.st_mode) and stat.S_IMODE(s.st_mode)==row['mode'] and seven(s)==row['seven_stat']
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  assert seven(os.fstat(fd))==seven(s);pieces=[];remaining=s.st_size+1
  while remaining:
   b=os.read(fd,min(1<<20,remaining))
   if not b:break
   pieces.append(b);remaining-=len(b)
  b=b''.join(pieces);assert len(b)==s.st_size and seven(os.fstat(fd))==seven(s)
 finally:os.close(fd)
 assert seven(p.lstat())==seven(s) and pin(b)==row['pin'];return b
def put(name,value):
 b=enc(value)
 with (R/name).open('xb') as f:f.write(b)
 return dict(file=name,pin=dict(pin(b),mode='100644'))
rows=json.loads((R/'PUBLICATION-INPUTS.json').read_bytes());values={}
for row in rows:
 n=Path(row['file']).name
 post=json.loads((R/'GIT-ACK'/(n+'.POST.json')).read_bytes());get=json.loads((R/'GIT-ACK'/(n+'.GET.json')).read_bytes())
 assert not post.get('isError') and not get.get('isError') and post['structuredContent']['sha']==row['pin']['git_blob']
 b=get['structuredContent']['content'].encode();assert dict(pin(b),mode='100644')==row['pin'] and b==(R/row['file']).read_bytes();values[row['file']]=json.loads(b)
m=values['MANIFEST.json'];chunks=[]
for i,row in enumerate(m['parts']):
 part=values[row['file']];b=base64.b64decode(part['data'],validate=True)
 assert part['ordinal']==i and part['count']==len(m['parts']) and part['offset']==sum(map(len,chunks)) and pin(b)==part['decoded_pin'];chunks.append(b)
archive=b''.join(chunks);assert pin(archive)==m['archive_pin'] and archive==(R/'COMPLETE-EVIDENCE.json.gz').read_bytes()
raw=gzip.decompress(archive);assert pin(raw)==m['payload_pin'];payload=json.loads(raw)
assert payload['files']==m['files'] and payload['directories']==m['directories'] and payload['kind']==m['kind']
objects={}
for key,row in payload['objects'].items():
 b=base64.b64decode(row['data'],validate=True);assert pin(b)==row['pin'] and key==row['pin']['sha256'];objects[key]=b
assert len(objects)==m['unique_objects'] and sum(map(len,objects.values()))==m['unique_bytes']
by={}
for row in payload['files']:
 b=objects[row['object']];assert pin(b)==row['pin'] and original(row)==b;by[row['logical']]=b
assert len(payload['files'])==m['logical_files'] and sum(x['pin']['bytes'] for x in payload['files'])==m['logical_bytes']
for row in payload['directories'].values():
 s=Path(row['path']).lstat();assert stat.S_ISDIR(s.st_mode) and stat.S_IMODE(s.st_mode)==row['mode'] and seven(s)==row['seven_stat']
plan=json.loads(by['custody/PLAN.json']);kind=m['kind'];scope=plan[kind]
if kind=='patch':
 inventory=json.loads(by['root/patch-build-r2-root-inventory.json']);terminal=json.loads(by['root/patch-build-r2-root-terminal.json'])
 assert inventory==scope['raw_inventory']==payload['raw_inventory'] and len(inventory)==43 and terminal['raw_files']==43 and terminal['raw_bytes']==9137879
 assert pin(by['root/patch-build-r2-root-terminal.json'])['git_blob']=='6b6f950ae84b66e2538bca7778b2da3db9607d61'
 assert terminal['inventory']==pin(by['root/patch-build-r2-root-inventory.json'])
 actual_rows={row['logical']:row for row in payload['files'] if row['logical'].startswith('actual-raw/')}
 assert len(actual_rows)==43 and sum(row['pin']['bytes'] for row in actual_rows.values())==9137879
 for label,row in inventory.items():assert {key:actual_rows['actual-raw/'+label][key] for key in ('path','pin','mode','seven_stat')}==row
 assert len(scope['author_files'])==24 and len(scope['root_files'])==11 and len(payload['directories'])==5
 author_names=set();directory_names=set()
 for prefix,base in [('build-R1',Path('/tmp/hia-patch-result-execution-r1-dda7/build')),('build-R2',Path('/tmp/hia-patch-result-execution-r1-dda7/build-r2'))]:
  for d,sub,files in os.walk(base,followlinks=False):
   p=Path(d);relative=p.relative_to(base).as_posix();directory_names.add(prefix+('/'+relative if relative!='.' else ''))
   for n in sub:assert stat.S_ISDIR((p/n).lstat().st_mode)
   for n in files:author_names.add(prefix+'/'+(p/n).relative_to(base).as_posix())
 assert author_names==set(scope['author_files']) and directory_names==set(payload['directories'])
else:
 assert kind=='preflight' and len(scope['files'])==7
 assert pin(by['actual-preflight'])['git_blob']=='dc12465086bf8386fa9a6a9e1eb89b376ae76fb5'
 assert pin(by['position-proof'])['git_blob']=='196d623ba33a6f45bc1f594c8c5b53df06e23f3b'
 assert pin(by['position-reader'])['git_blob']=='7c59e5d269fe049ff1f7833bee213997decb62f9'
assert m['git_api_response_files_in_payload']==m['credential_urls_in_payload']==0
assert payload['no_git_api_responses_or_credential_urls'] is True
outer=Path('/tmp/hia-r5-preflight-patch-build-custody-outer-dda7')/kind;outer_files=[]
for p in sorted(outer.iterdir()):
 s=p.lstat();b=p.read_bytes();assert stat.S_ISREG(s.st_mode) and seven(p.lstat())==seven(s)
 outer_files.append(dict(path=str(p),pin=pin(b),mode=stat.S_IMODE(s.st_mode),seven_stat=seven(s),data=base64.b64encode(b).decode()))
assert len(outer_files)==4 and json.loads((outer/'OUTER.json').read_bytes())['returncode']==0
proof=dict(status='PASS_ACTUAL_GIT_COMPLETE_EVIDENCE_READBACK',kind=kind,actual_ack_full_get_blobs=len(rows),logical_files=m['logical_files'],logical_bytes=m['logical_bytes'],unique_objects=m['unique_objects'],unique_bytes=m['unique_bytes'],directories=m['directory_count'],archive_pin=m['archive_pin'],payload_pin=m['payload_pin'],all_current_original_bytes_modes_seven_stats_equal=True,all_directory_metadata_and_author_pathsets_equal=True,original_scope_raw_files=m['scope_raw_files'],original_scope_raw_bytes=m['scope_raw_bytes'],root_observations_preserved_not_reexecuted=True,git_api_responses_in_payload=0,credential_urls_in_payload=0,sealer_outer_complete_files=outer_files,product_calls=0,binder_calls=0,preflight_reexecutions=0)
pr=put('ACTUAL-GIT-READBACK.json',proof);script=dict(file='readback_actual_git.py',pin=dict(pin(Path(__file__).read_bytes()),mode='100644'))
recipe=dict(schema='hepta.immutable-git-recipe.v1',repository='TrillionniumFoundation/Hepta',leaves=rows+[script,pr],scope=kind+' complete original custody only',logical_files=m['logical_files'],logical_bytes=m['logical_bytes'],directories=m['directory_count'],archive_pin=m['archive_pin'],parts=len(m['parts']),actual_readback=pr,previous_author_recipe=m.get('previous_author_recipe'),root_terminal='6b6f950ae84b66e2538bca7778b2da3db9607d61' if kind=='patch' else 'dc12465086bf8386fa9a6a9e1eb89b376ae76fb5',no_products_by_sealer=True,no_qualification_transferred=True)
rr=put('MOUNT-RECIPE.json',recipe);put('FOLLOWUP-PUBLICATION-INPUTS.json',[script,pr,rr])
print(json.dumps(dict(kind=kind,proof=pr,recipe=rr,logical_files=m['logical_files'],parts=len(m['parts'])),sort_keys=True))
