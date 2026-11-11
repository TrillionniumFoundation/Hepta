import hashlib,json,os,stat,sys
from pathlib import Path
ROOT=Path('/home/qian-qi/he26v66devr2-ingress-r1')
expected=json.loads(sys.stdin.buffer.read(65537))
assert len(expected)==18
def read(path,cap,mode=None):
 fd=os.open(path,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW)
 with os.fdopen(fd,'rb')as f:
  a=os.fstat(f.fileno());assert stat.S_ISREG(a.st_mode)and a.st_uid==os.geteuid()and a.st_nlink==1
  if mode is not None:assert stat.S_IMODE(a.st_mode)==mode
  raw=f.read(cap+1);assert len(raw)<=cap
  b=os.fstat(f.fileno())
 assert (a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)==(b.st_dev,b.st_ino,b.st_size,b.st_mtime_ns,b.st_ctime_ns)
 c=path.lstat();assert(a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)==(c.st_dev,c.st_ino,c.st_size,c.st_mtime_ns,c.st_ctime_ns)
 return raw,a
names=['ingress.json','guard/guardian.json','guard/child.stdout.log','guard/child.stderr.log','guard/request.json','launch-intent.json']
files=[]
for name in names:
 p=ROOT/name;raw,s=read(p,65536)
 files.append({'path':str(p),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'text':raw.decode('utf-8')})
values={Path(f['path']).relative_to(ROOT).as_posix():f for f in files}
report=json.loads(values['ingress.json']['text']);guard=json.loads(values['guard/guardian.json']['text']);life=guard['lifecycle'];cleanup=life['cleanup']
assert report['status']=='PUBLIC_SOURCE_INGRESS_READY_PENDING_OUTER_GUARDIAN'
assert report['source_package_commit']=='fdb40f161907d0c4722ea14ca933945d33ec4990'
assert len(report['get_attempts'])==len(report['files'])==len(report['final_readbacks'])==2
assert report['source_preparation_started'] is False and report['whole_native_delivery_qualified'] is False
assert guard['status']=='EXTERNAL_OWNED_PROCESS_COMPLETED' and guard['input_identity_preserved'] is True
assert guard['source_identities_before']==guard['source_identities_after']==expected
assert guard['external_controller_seconds']==900
assert guard['command']==['/home/qian-qi/hia-e26e-python314-linux-r1/venv/bin/python','-B',str(ROOT/'control/download_public_source.py')]
assert guard['cwd']==str(ROOT) and guard['lifecycle_implementation_sha256']=='36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2'
assert life['status']=='OWNED_PROCESS_COMPLETED' and life['returncode']==0 and life['exit_observed_before_deadline'] is True
assert life['timed_out'] is False and not life.get('interrupted_signals') and not life.get('owner_error')
assert life['event_overflow'] is False and all(x['kind']!='owned_child_sigkill' for x in life['events'])
assert cleanup['complete'] is True and cleanup['observed_echild'] is True and cleanup['leader_reaped'] is True
assert cleanup['errors']==[] and cleanup['remaining_direct_children']==[]
assert guard['logs']=={str(ROOT/n):values[n]['sha256'] for n in ['guard/child.stdout.log','guard/child.stderr.log']}
inputs=[]
for name,size,sha,blob in [('e09-program-and-declared-source.tar.xz',5829996,'f0f0a0fd570fa2d260d95f25193b1d9571d9614bbc7ab1c22607f23112ae5428','ff3ff3b9fe91d76952d2a4e84e0f33c5a09a1ede'),('canonical-e09-development-package.json',473051,'7a45af0a08d837c3ecba97cd47b54e1a3eb8838c838d03a14a82d58df3e799af','c3faf7709057a6024decfc0aa2c0e001565511ba')]:
 p=ROOT/'inputs'/name;raw,s=read(p,size,0o400)
 assert len(raw)==size and hashlib.sha256(raw).hexdigest()==sha and hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==blob
 facts={'name':name,'path':str(p),'size':size,'sha256':sha,'git_blob_sha1':blob,'mode':oct(s.st_mode),'uid':s.st_uid,'nlink':s.st_nlink}
 inputs.append(facts)
 for key in ['files','final_readbacks']:
  rows=[r for r in report[key]if r['name']==name];assert len(rows)==1
  assert all(rows[0][k]==v for k,v in facts.items())and rows[0]['readback_verified'] is True
print(json.dumps({'schema':'hia.canonical-ingress-readonly-terminal-readback.v1','status':'INGRESS_STRICT_READBACK_READY','whole_native_delivery_qualified':False,'files':files,'inputs':inputs,'guardian_natural_cleanup_verified':True,'old_input_identity_count':len(expected)},sort_keys=True))
