"""Actual blocked-publication registry-flock differential, private mount namespace.

A full output pipe proves the owner reached a write before the independent
contender attempts flock. Historical native v3 is an intentional negative
control. No owner image, threshold, or original error assertion is changed.
"""
from pathlib import Path
from hashlib import sha256
import argparse,base64,datetime,errno,fcntl,json,os,signal,subprocess,threading,time,traceback
p=argparse.ArgumentParser(description=__doc__)
for name in ('native','oracle','negative','output'):p.add_argument('--'+name,type=Path,required=True)
for name in ('native','oracle','negative'):p.add_argument('--'+name+'-sha256',required=True)
a=p.parse_args();assert os.geteuid()==0
assert os.readlink('/proc/self/ns/mnt')!=os.readlink('/proc/1/ns/mnt')
Q=a.output.absolute();Q.mkdir(mode=0o700)
images={k:getattr(a,k).resolve(strict=True) for k in ('oracle','negative','native')}
pins={k:getattr(a,k+'_sha256') for k in images}
for k,v in images.items():assert sha256(v.read_bytes()).hexdigest()==pins[k]
identity='native-observe';nonce='a'*32
boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
record=dict(job_id=identity,unit=f'hepta-job-{identity}.service',request_digest='0'*64,boot_id=boot,nonce=nonce,invocation_id=None,launch_state='launched',created_unix_ms=1)
def encode(v):return json.dumps(v,ensure_ascii=True,separators=(',',':')).encode()+b'\n'
def properties(foreign=False):
 p=dict(LoadState='loaded',ActiveState='active',SubState='running',Result='success',InvocationID='b'*32,Description='foreign' if foreign else f'Hepta Runtime {identity} {nonce}',ExecMainStatus='0',ExecMainCode='0')
 return ''.join(k+'='+v+'\n' for k,v in p.items()).encode()
fixture=Q/'systemctl-fixture'
fixture.write_text('''#!/usr/bin/python3
import base64,json,os,sys
from pathlib import Path
p=Path(os.environ['HIA_JOBCTL_QA_FACTS']);c=json.loads(p.read_text())
with (p.parent/'calls.jsonl').open('a') as f:f.write(json.dumps(sys.argv[1:])+'\\n')
show=sys.argv[1]=='show'
if show:os.write(1,base64.b64decode(c['show']))
else:
 raw=base64.b64decode(c['stderr']);pos=0
 while pos<len(raw):pos+=os.write(2,raw[pos:])
sys.exit(0 if show else c['stop_rc'])
''');fixture.chmod(0o755)
def mount(source,target):subprocess.run(['/usr/bin/mount','--bind',str(source),str(target)],check=True,capture_output=True)
def unmount(target):subprocess.run(['/usr/bin/umount',str(target)],check=True,capture_output=True)
cases=[dict(name='status-stdout',op='status',fd=1),dict(name='cancel-stdout',op='cancel',fd=1),dict(name='record-stderr',op='status',fd=2,invalid_record=True),dict(name='properties-stderr',op='status',fd=2,foreign=True),dict(name='stop-stream-stderr',op='cancel',fd=2,stop_rc=17,stderr=(bytes(range(256))*257+b'\xe2\x82'))]
report=dict(status='running',pins=pins,started=datetime.datetime.now(datetime.timezone.utc).isoformat(),cases=[],scope='actual original/new/historical owner blocked publication with independent registry flock')
def save():(Q/'qualification.json').write_text(json.dumps(report,indent=2)+'\n')
def run(c,label):
 root=Q/c['name']/label;root.mkdir(parents=True)
 varlib=root/'varlib';reg=varlib/'hepta-runtime-jobctl'/identity;reg.mkdir(parents=True)
 (reg/'record.json').write_bytes(b'{' if c.get('invalid_record') else encode(record));(varlib/('hepta-job-'+identity)).mkdir()
 facts={'show':base64.b64encode(properties(c.get('foreign',False))).decode(),'stop_rc':c.get('stop_rc',0),'stderr':base64.b64encode(c.get('stderr',b'')).decode()}
 fact=root/'facts.json';fact.write_text(json.dumps(facts))
 mount(varlib,'/var/lib');child=None;readfd=writefd=None;reader=None;chunks=[]
 try:
  readfd,writefd=os.pipe();capacity=fcntl.fcntl(writefd,fcntl.F_GETPIPE_SZ)
  sentinel=b'\xa5'*capacity;used=0
  while used<capacity:used+=os.write(writefd,sentinel[used:])
  kw=dict(stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={'PATH':'','HIA_JOBCTL_QA_FACTS':str(fact),'LC_ALL':'C.UTF-8'},start_new_session=True)
  kw['stdout' if c['fd']==1 else 'stderr']=writefd
  child=subprocess.Popen([str(images[label])],**kw);os.close(writefd);writefd=None
  child.stdin.write(encode(dict(op=c['op'],job_id=identity)));child.stdin.close();child.stdin=None
  blocked=None;deadline=time.monotonic()+5
  while time.monotonic()<deadline:
   assert child.poll() is None,(c['name'],label,'exited before blocked publication',child.returncode)
   syscall=Path(f'/proc/{child.pid}/syscall').read_text().strip()
   wchan=Path(f'/proc/{child.pid}/wchan').read_text().strip()
   fields=syscall.split()
   if fields and fields[0] in ('1','20') and int(fields[1],0)==c['fd'] and 'pipe' in wchan:
    blocked=dict(syscall=syscall,wchan=wchan);break
   time.sleep(.005)
  assert blocked,(c['name'],label,'no blocked write witness')
  lockpath=varlib/'hepta-runtime-jobctl/lock';assert lockpath.exists()
  fd=os.open(lockpath,os.O_RDWR);acquired=False
  try:
   try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);acquired=True
   except BlockingIOError:pass
   if acquired:fcntl.flock(fd,fcntl.LOCK_UN)
  finally:os.close(fd)
  expected=label!='negative';assert acquired==expected,(c['name'],label,'flock state',acquired,expected,blocked)
  def drain():
   while True:
    raw=os.read(readfd,65536)
    if not raw:break
    chunks.append(raw)
  reader=threading.Thread(target=drain,daemon=True);reader.start()
  stdout,stderr=child.communicate(timeout=15);reader.join(3);assert not reader.is_alive()
  captured=b''.join(chunks);assert captured.startswith(sentinel);captured=captured[capacity:]
  if c['fd']==1:stdout=captured
  else:stderr=captured
  assert stdout is not None and stderr is not None
  (root/'stdout').write_bytes(stdout);(root/'stderr').write_bytes(stderr)
  result=dict(rc=child.returncode,stdout_sha256=sha256(stdout).hexdigest(),stderr_sha256=sha256(stderr).hexdigest(),stdout_bytes=len(stdout),stderr_bytes=len(stderr),flock_acquired_while_blocked=acquired,blocked=blocked,pipe_capacity=capacity)
  if child.returncode==0:result['json']=json.loads(stdout)
  result['calls']=[json.loads(x) for x in (root/'calls.jsonl').read_text().splitlines()] if (root/'calls.jsonl').exists() else []
  (root/'result.json').write_text(json.dumps(result,indent=2)+'\n');return result
 finally:
  if child is not None and child.poll() is None:
   os.killpg(child.pid,signal.SIGKILL);child.communicate()
  if writefd is not None:os.close(writefd)
  if readfd is not None:os.close(readfd)
  unmount('/var/lib')
mount(fixture,'/usr/bin/systemctl');save()
try:
 for c in cases:
  rows={k:run(c,k) for k in ('oracle','negative','native')}
  fields=('rc','stderr_sha256','calls')
  for k in ('negative','native'):
   assert all(rows['oracle'][f]==rows[k][f] for f in fields),(c['name'],k,rows)
   assert rows['oracle'].get('json')==rows[k].get('json'),(c['name'],k,'response JSON')
   if rows['oracle']['rc']!=0:assert rows['oracle']['stdout_bytes']==rows[k]['stdout_bytes']==0
  report['cases'].append(dict(name=c['name'],passed=True,observations=rows));save();print('LOCK',c['name'],'PASS',flush=True)
 for k,v in images.items():assert sha256(v.read_bytes()).hexdigest()==pins[k]
 report.update(status='passed',case_count=len(cases),actual_processes=3*len(cases),finished=datetime.datetime.now(datetime.timezone.utc).isoformat());save();print('LOCK PUBLICATION PASS',len(cases),flush=True)
except BaseException:report.update(status='failed',error=traceback.format_exc());save();raise
finally:unmount('/usr/bin/systemctl')
