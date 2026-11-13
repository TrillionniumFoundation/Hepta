"""Create a lossless archive from an already-audited explicit file inventory.
No project imports, qualification, C build, VM, native entry, or SQL.
This packages either PASS or HOLD evidence without reclassifying it.
"""
from pathlib import Path
import base64, gzip, hashlib, io, json, os, stat, tarfile
ROOT=Path(__file__).resolve().parent
TASK=ROOT.parent
PLAN=TASK/"sqlite-btree-cell-source-r1"
def identity(s):
 return [s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def digest(raw):
 return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'git_blob_sha1':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}
def read(path,maximum=128<<20):
 p=Path(path);assert p.is_absolute() and p.resolve(strict=True)==p
 old=p.lstat();assert stat.S_ISREG(old.st_mode) and old.st_nlink==1 and old.st_size<=maximum
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 with os.fdopen(fd,'rb') as stream:
  assert identity(os.fstat(stream.fileno()))==identity(old)
  raw=stream.read();assert identity(os.fstat(stream.fileno()))==identity(old)
 assert len(raw)==old.st_size and identity(p.lstat())==identity(old)
 return raw,{'path':str(p),**digest(raw),'identity':identity(old)}
def create(path,raw):
 path.parent.mkdir(parents=True,exist_ok=True)
 with path.open('xb') as stream:
  assert stream.write(raw)==len(raw);stream.flush();os.fsync(stream.fileno())
 os.chmod(path,0o400);body,pin=read(path);assert body==raw;return pin
def wire(value):return (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
def main():
 # The only executions represented here are Root's already closed R1/R2/R3 attempts.
 qraw,qp=read(PLAN/'REQUEST-r3.json');q=json.loads(qraw)
 assert qp['sha256']=='7ea44a52b41c63e4cfe6e05f2fa5a6c3d579b34153e08b11cc093c720f66db26'
 assert len(q['inputs'])==50 and q['expected_vm_returns']==339 and len(q['expected_ids'])==12
 assert q['qualification_seconds']==180 and q['cleanup_seconds']==3
 payload={}
 def add(name,path):
  assert name not in payload and not name.startswith('/') and '..' not in Path(name).parts
  payload[name]=read(path)
 def collect(prefix,base):
  for parent,dirs,names in os.walk(base,followlinks=False):
   for name in dirs:assert stat.S_ISDIR((Path(parent)/name).lstat().st_mode)
   for name in sorted(names):
    p=Path(parent)/name;add(prefix+'/'+str(p.relative_to(base)),p)
 collect('plan',PLAN)
 for n in (2,3):
  actual=TASK/('sqlite-btree-cell-source12-actual-r%d'%n)
  for name in ('owner.json','owner.json.request.json','OWNER-WRAPPER.json'):
   read(actual/name)
  life=json.loads(read(actual/'owner.json')[0]);c=life['cleanup']
  assert c['complete'] is True and c['observed_echild'] is True and c['leader_reaped'] is True
  assert c['remaining_direct_children']==[] and c['errors']==[] and c['deadline_exceeded'] is False
  assert life['returncode']==(1 if n==2 else 0) and life['timed_out'] is False
  collect('actual-r%d'%n,actual)
  assert len([x for x in payload if x.startswith('actual-r%d/'%n)])==21
 for n in (1,2,3):
  collect('independent-audit-r%d'%n,TASK/('sqlite-btree-cell-source12-actual-audit-r%d'%n))
 audits={}
 for n in (2,3):
  raw=payload['independent-audit-r%d/AUDIT.json'%n][0];a=json.loads(raw)
  assert a['readback_complete'] is True and a['errors']==[]
  assert a['VM']['calls']==339 and a['VM']['successes']==253 and a['VM']['refusals']==86
  assert a['status']==('SOURCE12_BTREE_CELL_HOLD_ORIGINALS_VERIFIED' if n==2 else 'SOURCE12_BTREE_CELL_VM_PASS_ONLY')
  audits[str(n)]={'path':'independent-audit-r%d/AUDIT.json'%n,**digest(raw)}
 assert payload['actual-r2/tests/VM-RAW.json'][0]==payload['actual-r3/tests/VM-RAW.json'][0]
 # Include Root's frozen launch, failure, correction drafts, owner and h-job originals.
 roots=sorted(TASK.glob('root-btree*'))
 assert 5<=len(roots)<=100
 for p in roots:
  assert stat.S_ISREG(p.lstat().st_mode)
  add('root-proof/'+p.name,p)
 assert any(b'1a1d3f606e3-392-25b' in raw for name,(raw,p) in payload.items() if name.startswith('root-proof/'))
 # Every frozen external input is included in full, not just its hash.
 paths={p['path'] for raw,p in payload.values()}
 for i,row in enumerate(q['inputs']):
  raw,p=read(row['path'])
  assert all(p[k]==row[k] for k in ('path','bytes','sha256','identity'))
  if row['path'] not in paths:
   add('external-inputs/%03d-%s'%(i,Path(row['path']).name),row['path'])
   paths.add(row['path'])
 # Include the complete original shared source catalog's 1686 full files.
 catalog=json.loads(read(q['source_catalog'])[0]);assert len(catalog)==1686
 total=0
 for name,row in sorted(catalog.items()):
  add('source/'+name,row['path']);raw,p=payload['source/'+name]
  assert p['path']==str(Path(q['source_root'])/name)
  assert all(p[k]==row[k] for k in ('path','bytes','sha256','identity'))
  assert p['git_blob_sha1']==row['git_blob'];total+=len(raw)
 assert total==40890650
 for name in ('READER-PREPARATION.json','package_combined.py','restore_originals.py'):
  add('packaging/'+name,ROOT/name)
 add('packaging-history/package_originals-unexecuted.py',
     TASK/'sqlite-btree-cell-source12-complete-publication-r1/package_originals.py')
 buffer=io.BytesIO()
 with tarfile.open(fileobj=buffer,mode='w',format=tarfile.PAX_FORMAT) as archive:
  for name,(raw,pin) in sorted(payload.items()):
   member=tarfile.TarInfo(name);member.size=len(raw);member.mode=stat.S_IMODE(pin['identity'][2])
   member.mtime=0;member.uid=member.gid=0;member.uname=member.gname=''
   archive.addfile(member,io.BytesIO(raw))
 tar=buffer.getvalue();packed=gzip.compress(tar,compresslevel=6,mtime=0)
 packed_pin=create(ROOT/'originals.tar.gz',packed)
 restored=gzip.decompress(packed);assert restored==tar
 with tarfile.open(fileobj=io.BytesIO(restored),mode='r:') as archive:
  members=archive.getmembers();assert [m.name for m in members]==sorted(payload)
  for member in members:
   raw,pin=payload[member.name]
   assert member.isfile() and archive.extractfile(member).read()==raw
   assert member.mode==stat.S_IMODE(pin['identity'][2])
 parts=[]
 for n,offset in enumerate(range(0,len(packed),196608)):
  chunk=packed[offset:offset+196608];name='carriers/part-%03d.b64'%n
  pin=create(ROOT/name,base64.b64encode(chunk)+b'\n')
  parts.append({'path':name,'offset':offset,'decoded':digest(chunk),
                **{k:pin[k] for k in ('bytes','sha256','git_blob_sha1')}})
 assert b''.join(base64.b64decode(read(ROOT/p['path'])[0]) for p in parts)==packed
 mirrors=[]
 for name,(raw,pin) in sorted(payload.items()):
  if name.startswith('source/') or len(raw)>262144:continue
  try:raw.decode('utf-8')
  except UnicodeError:continue
  path='text/'+name;copy=create(ROOT/path,raw)
  mirrors.append({'path':path,**{k:copy[k] for k in ('bytes','sha256','git_blob_sha1')}})
 for name,(raw,pin) in payload.items():
  body,after=read(pin['path']);assert body==raw and after==pin
 scope={
  'R1':{'hjob':'1a1d3f606e3-392-25b','status':'PRE_OWNER_SCHEMA_REFUSAL',
        'owner_runs':0,'VM_calls':0,'generation_runs':0},
  'R2':{'hjob':'1a1d3ff7808-392-263','status':'HOLD','owner_runs':1,'methods':12,
        'VM_calls':339,'method_successes':11,'only_failure':'original Core arguments cap 17 > 16'},
  'R3':{'hjob':'1a1d4091afb-392-27a','status':'SOURCE12_BTREE_CELL_VM_PASS_ONLY',
        'owner_runs':1,'methods':12,'VM_calls':339,'method_successes':12,'all_original_nine_caps_pass':True},
  'qualification_repeated_by_archiver':False,'C_native_SQL_runs':0,
  'domain':'one bounded selected-cell layout, not whole page/tree/pager/SQL/AgentStore'}
 manifest={'schema':'hia.sqlite-btree-cell.source12-combined-archive.v1',
  'status':'R3_SOURCE_VM_PASS_WITH_R1_AND_R2_FAILURES_PRESERVED',
  'qualification_repeated':False,'attempts':scope,'independent_audits':audits,
  'original_count':len(payload),'original_bytes':sum(len(raw) for raw,pin in payload.values()),
  'originals':[{'name':name,'original_path':pin['path'],
    **{k:pin[k] for k in ('bytes','sha256','git_blob_sha1','identity')}}
    for name,(raw,pin) in sorted(payload.items())],
  'archive':{k:packed_pin[k] for k in ('bytes','sha256','git_blob_sha1')},
  'tar':digest(tar),'parts':parts,'text_mirrors':mirrors,
  'complete_roundtrip':True,'original_bytes_and_identities_unchanged_after':True,
  'complete_source_files':1686,'complete_source_bytes':40890650,
  'root_originals':[p.name for p in roots]}
 manifest_raw=(json.dumps(manifest,sort_keys=True,separators=(',',':'))+'\n').encode()
 mp=create(ROOT/'ARCHIVE-MANIFEST.json',manifest_raw)
 handoff={'schema':'hia.sqlite-btree-cell.source12-combined-handoff.v1',
  'parent_commit':'fbbac0417195122a3261a1bfc708e997a8cd69e5',
  'git_prefix':'experiments/hia_sqlite_btree_cell_20261113/source12-r1-r2-r3-actual-r1',
  'attempts':scope,'independent_audits':audits,'archive_manifest':digest(manifest_raw),
  'archive':digest(packed),'tar':digest(tar),'original_count':len(payload),
  'original_bytes':manifest['original_bytes'],'all_frozen_input_bodies_included':True,
  'all_1686_shared_source_bodies_included':True,'all_R2_R3_actual_bodies_included':True,
  'R2_R3_VM_bytes_identical':True,
  'R3_hia':digest(payload['actual-r3/tests/sqlite_btree_cell.hiaasm'][0]),
  'root_originals':manifest['root_originals'],
  'execution_authority':'Root only; no new qualification from this archive',
  'publication_status':'GIT_OBJECTS_PENDING'}
 hp=create(ROOT/'HANDOFF.json',wire(handoff))
 publish=[{'path':'ARCHIVE-MANIFEST.json',**digest(manifest_raw)},
          {'path':'HANDOFF.json',**digest(read(ROOT/'HANDOFF.json')[0])},
          {'path':'restore_originals.py',**digest(read(ROOT/'restore_originals.py')[0])},
          {'path':'package_combined.py',**digest(read(ROOT/'package_combined.py')[0])}]
 publish+=parts+mirrors
 pp=create(ROOT/'PUBLISH.json',wire({'files':publish,'unique_blob_count':len({x['git_blob_sha1'] for x in publish}),
                                    'parent':handoff['parent_commit'],'prefix':handoff['git_prefix']}))
 print(json.dumps({'manifest':mp,'handoff':hp,'publish':pp,'archive':packed_pin,
                   'originals':len(payload),'original_bytes':manifest['original_bytes'],
                   'parts':len(parts),'text_mirrors':len(mirrors),'qualification_executed':False}))
if __name__=='__main__':main()
