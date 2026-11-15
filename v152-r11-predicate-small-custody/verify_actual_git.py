"""Decode only actual saved Git GET responses; no product execution."""
from pathlib import Path
import base64,hashlib,json,stat,zlib
R=Path(__file__).resolve().parent
FIELDS=('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
def enc(v):return (json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def pin(b):return {'bytes':len(b),'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest(),'sha256':hashlib.sha256(b).hexdigest()}
def read(p):
 p=Path(p);s=p.lstat();assert stat.S_ISREG(s.st_mode) and s.st_nlink==1
 b=p.read_bytes();e=p.lstat();assert len(b)==s.st_size and all(getattr(s,k)==getattr(e,k) for k in FIELDS)
 return b,stat.S_IMODE(s.st_mode),{k:getattr(s,k) for k in FIELDS}
def write(n,b):
 p=R/n
 with p.open('xb') as f:f.write(b)
 p.chmod(0o644);assert read(p)[0]==b
plan=json.loads(read(R/'PUBLISH-PLAN.json')[0]);assert len(plan)==24
contents={};receipts=[]
for i,row in enumerate(plan):
 stem=R/'GIT-ACK'/(str(i).zfill(3)+'-'+row['mount'].replace('/','_'))
 post=json.loads(read(Path(str(stem)+'.POST.json'))[0])
 get=json.loads(read(Path(str(stem)+'.GET.json'))[0])
 assert post['structuredContent']['sha']==row['identity']['git_blob']
 raw=get['structuredContent']['content'].encode()
 assert pin(raw)==row['identity'] and raw==read(row['path'])[0]
 contents[row['mount']]=raw
 receipts.append({'mount':row['mount'],'identity':pin(raw),'POST_acknowledged':True,'actual_full_GET_bytes_equal':True})
idx=json.loads(contents['AUTHOR-INDEX.json']);assert idx['file_count']==30
capsule=b''.join(contents[row['mount']] for row in idx['parts'])
assert pin(capsule)==idx['capsule'] and capsule==read(R/'AUTHOR-CAPSULE.json')[0]
w=json.loads(capsule);compressed=base64.b64decode(w['data'],validate=True)
assert pin(compressed)==w['compressed']
d=zlib.decompressobj();decoded=d.decompress(compressed,w['decoded']['bytes']+1)
assert d.eof and not d.unused_data and not d.unconsumed_tail and pin(decoded)==w['decoded']
files=json.loads(decoded)['files'];assert set(files)==set(idx['files'])
verified={}
for name,row in files.items():
 raw=base64.b64decode(row['data_base64'],validate=True);authority=idx['files'][name]
 b,m,s=read(authority['path'])
 assert raw==b and pin(raw)==row['identity']==authority['identity']
 assert m==row['mode']==authority['mode'] and s==authority['seven_stats']
 verified[name]={'identity':pin(raw),'mode':m,'seven_stats':s,'path':authority['path']}
assert sum(v['identity']['bytes'] for v in verified.values())==idx['logical_bytes']==10109927
roots={'boundary-reader':Path('/tmp/hia-r11-predicate-terminal-reader-r1-dda7'),
       'dual-proof-binder':Path('/tmp/hia-r11-controls-author-r2-dda7')}
additions={}
for label,root in roots.items():
 old={n[len(label)+1:] for n in verified if n.startswith(label+'/')}
 current={p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file()}
 assert old<=current
 additions[label]=sorted(current-old)
proof={'schema':'hia.R11.predicate-reader-and-unbound-dual-proof.actual-Git-readback.v1',
 'status':'PASS_ACTUAL_REMOTE_PAYLOAD_GET_AND_COMPLETE_30_FILE_DECODE',
 'leaves':receipts,'capsule':pin(capsule),'index':pin(contents['AUTHOR-INDEX.json']),
 'files':verified,'file_count':30,'logical_bytes':10109927,
 'all_24_actual_POST_and_full_GET':True,'strict_base64_zlib_eof_no_trailing':True,
 'all_snapshot_bytes_mode_and_seven_stats_current_equal':True,
 'snapshot_pathset_exact_against_original_index':True,
 'current_append_only_files_outside_this_frozen_author_snapshot':additions,
 'boundary_actual_raw_included':False,'boundary_actual_independent_outputs_included':False,
 'later_actual_bound_R2_files_included':False,'Root_later_binder_receipts_included':False,
 'products':0,'binders_executed_by_this_reader':0}
write('ACTUAL-GIT-READBACK.json',enc(proof))
follow=[]
for n in ('verify_actual_git.py','ACTUAL-GIT-READBACK.json'):
 follow.append({'mount':n,'path':str(R/n),'identity':pin(read(R/n)[0])})
write('FOLLOWUP-PUBLISH-PLAN.json',enc(follow))
print(json.dumps({'status':proof['status'],'proof':pin(enc(proof)),'files':30,'logical_bytes':10109927,
                  'current_extra_counts':{k:len(v) for k,v in additions.items()},'products':0},sort_keys=True))
