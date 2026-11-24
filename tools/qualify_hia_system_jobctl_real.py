"""Exercise installed root Jobctl and actual systemd DynamicUser jobs.

Requires sudo unshare --mount --propagation private. The policy overlay is private;
the manager, installed fixed helper, transient units and durable state are real.
The workload is an owned fixture, not a real jadx/ghidra provider.
"""
from pathlib import Path
import os,subprocess,json,time,hashlib,datetime,uuid,traceback,stat,pty,termios,select,errno
import argparse,grp
parser=argparse.ArgumentParser(description='Real systemd lifecycle with the exact installed HIA system Jobctl')
for field in ('output','reference','native','native-sha256'):parser.add_argument('--'+field,required=True)
args=parser.parse_args()
ROOT=Path(__file__).resolve().parents[1]
D=Path(args.output).resolve()
assert os.geteuid()==0
assert os.readlink('/proc/self/ns/mnt')!=os.readlink('/proc/1/ns/mnt'), 'run inside a private mount namespace'
assert Path(args.native).resolve()==Path('/usr/local/libexec/hepta-runtime-jobctl')
os.umask(0o022);D.mkdir(mode=0o755,exist_ok=False)
for n in ('etc-upper','etc-work'):(D/n).mkdir(mode=0o755)
subprocess.run(['mount','-t','overlay','overlay','-o',f"lowerdir=/etc,upperdir={D/'etc-upper'},workdir={D/'etc-work'}",'/etc'],check=True)
workspace=Path('/var/lib/hepta-runtime/workspaces')/('hia-native-jobctl-qa-'+uuid.uuid4().hex)
workspace.mkdir(mode=0o2770);os.chown(workspace,0,grp.getgrnam('hepta-workspace').gr_gid);workspace.chmod(0o2770)
policy=Path('/etc/hepta-runtime/job-policy.json');policy.parent.mkdir(mode=0o755,exist_ok=True)
policy.write_text(json.dumps({'workspace':str(workspace),'max_timeout_seconds':60,'max_cpu_percent':100,'max_memory_bytes':268435456})+'\n');policy.chmod(0o600)
source=(ROOT/'tools/hia_system_jobctl_supervisor_fixture.c').read_text()
source=source.replace('(long)getpid());','(long)getpid() + (enabled("QA_CLAIM_WRONG_PID")?1:0));',1)
helper='static const char *state_path(const char *suffix){static char b[4096];const char *s=getenv("QA_STATE");if(!s||snprintf(b,sizeof b,"%s/%s",s,suffix)>=(int)sizeof b)_exit(95);return b;}\n'
source=source.replace('extern char **environ;',helper+'extern char **environ;')
for path in ['engine-scratch/claim.json','engine-scratch/nested','engine-scratch/nested/content','ready']:
 source=source.replace('"/state/'+path+'"','state_path("'+path+'")')
(D/'fixture.c').write_text(source)
subprocess.run(['cc','-O2','-Wall','-Wextra','-Werror',str(D/'fixture.c'),'-o',str(workspace/'fixture')],check=True);(workspace/'fixture').chmod(0o555)
native=Path(args.native);reference=Path(args.reference)
pin=hashlib.sha256(native.read_bytes()).hexdigest();assert pin==args.native_sha256
r={'phase':'running','scope':'real system systemd and DynamicUser with exact installed HIA Jobctl; original Rust observes the same terminal jobs','native_sha256':pin,'fixture_sha256':hashlib.sha256((workspace/'fixture').read_bytes()).hexdigest(),'workspace':str(workspace),'cases':[],'started':datetime.datetime.now(datetime.timezone.utc).isoformat()}
def save():(D/'qualification.json').write_text(json.dumps(r,indent=2)+'\n')
def invoke(binary,q):
 p=subprocess.run([str(binary)],input=(json.dumps(q,ensure_ascii=False,separators=(',',':'))+'\n').encode(),capture_output=True,timeout=30)
 out={'binary':str(binary),'request':q,'rc':p.returncode,'stdout':p.stdout.decode(errors='replace'),'stderr':p.stderr.decode(errors='replace')}
 current['calls'].append(out);save();assert p.returncode==0 and not p.stderr,out
 return json.loads(p.stdout)
def start_pty(binary,q):
 master,slave=pty.openpty()
 attrs=termios.tcgetattr(slave);attrs[3]&=~termios.ECHO;termios.tcsetattr(slave,termios.TCSANOW,attrs)
 def setup():
  os.setsid()
  import fcntl
  fcntl.ioctl(0,termios.TIOCSCTTY,0)
 p=subprocess.Popen([str(binary)],stdin=slave,stdout=slave,stderr=slave,preexec_fn=setup,close_fds=True);os.close(slave)
 os.write(master,(json.dumps(q,separators=(',',':'))+'\n').encode())
 raw=b'';deadline=time.monotonic()+30
 while time.monotonic()<deadline:
  if select.select([master],[],[],.1)[0]:
   try:b=os.read(master,65536)
   except OSError as e:
    if e.errno==errno.EIO:break
    raise
   if not b:break
   raw+=b
  if p.poll() is not None and not select.select([master],[],[],0)[0]:break
 os.close(master);rc=p.wait(timeout=5)
 current['pty']={'binary':str(binary),'rc':rc,'output_hex':raw.hex()};save()
 assert rc==0 and b'PTY-OK' in raw and b'"pty_exit_code":0' in raw,(rc,raw)
 return raw
cases=[
 ('exit7',{'env':{'QA_OUT':'19073','QA_ERR':'17031','QA_EXIT':'7'}},7),
 ('stdin',{'stdin':'hello\nΩ🙂\u0000binary','env':{'QA_STDIN':'1'}},0),
 ('truncated',{'env':{'QA_OUT':str((16<<20)+1),'QA_ERR':'4097'}},0),
 ('timeout',{'timeout_seconds':1,'env':{'QA_SLEEP_MS':'5000'}},124),
 ('cancel',{'env':{'QA_SLEEP_MS':'5000','QA_OUT':'17','QA_ERR':'19'}},143),
 ('engine-adopt',{'args':['rea-static-worker'],'stdin':'{"schema":"hepta.rea.static-request.v1","profile":{"provider":"jadx"}}','env':{'QA_CLAIM':'1'}},0),
 ('engine-ghidra',{'args':['rea-static-worker'],'stdin':'{"schema":"hepta.rea.static-request.v1","profile":{"provider":"ghidra"}}','env':{'QA_CLAIM':'1'}},0),
 ('engine-bad-claim',{'args':['rea-static-worker'],'stdin':'{"schema":"hepta.rea.static-request.v1","profile":{"provider":"jadx"}}','env':{'QA_CLAIM':'1','QA_CLAIM_WRONG_PID':'1'}},0),
 ('ordinary-engine-shape',{'args':['rea-static-worker'],'stdin':'{"schema":"hepta.rea.static-request.v1","profile":{"provider":"other"}}','env':{'QA_CLAIM':'1'}},0),
 ('engine-descendant',{'args':['rea-static-worker'],'stdin':'{"schema":"hepta.rea.static-request.v1","profile":{"provider":"jadx"}}','env':{'QA_CLAIM':'1','QA_DESCENDANT':'1','QA_DESC_MS':'5000'}},0),
 ('engine-no-adoption',{'args':['rea-static-worker'],'stdin':'{"schema":"hepta.rea.static-request.v1","profile":{"provider":"jadx"}}'},0),
 ('pty-native',{'op':'pty','executable':'/usr/bin/sh','args':['-c','printf PTY-OK; exit 7']},7),
 ('pty-reference',{'op':'pty','executable':'/usr/bin/sh','args':['-c','printf PTY-OK; exit 7']},7),
]
save()
try:
 for name,change,exit_code in cases:
  job='hia-native-systemd-'+uuid.uuid4().hex
  assert not (Path('/var/lib/hepta-runtime-jobctl')/job).exists()
  state=Path('/var/lib')/('hepta-job-'+job)
  current={'name':name,'job_id':job,'calls':[],'phase':'running'};r['cases'].append(current);save()
  q={'op':'start','job_id':job,'executable':str(workspace/'fixture'),'args':[],'timeout_seconds':15,'cpu_quota_percent':100,'memory_max_bytes':134217728,'nice':10,**change}
  if not name.startswith('pty-'):q['env']={'QA_STATE':str(state),**q.get('env',{})}
  if name.startswith('pty-'):start_pty(reference if name=='pty-reference' else native,q)
  else:
   accepted=invoke(native,q);assert accepted['ok'] and accepted['backend']=='systemd_system'
  if name=='cancel':
   deadline=time.monotonic()+10
   while not (state/'ready').exists():
    assert time.monotonic()<deadline
    time.sleep(.01)
   current['cancel_reply']=invoke(native,{'op':'cancel','job_id':job})
  for _ in range(1000):
   status=invoke(native,{'op':'status','job_id':job})
   if status.get('terminal_publication_confirmed') is True:break
   time.sleep(.02)
  else:raise AssertionError(('terminal timeout',name,status))
  original=invoke(reference,{'op':'status','job_id':job});assert original==status,(original,status)
  for offset in ([0,16380] if name in ['exit7','truncated'] else [0]):
   read=invoke(native,{'op':'read','job_id':job,'stdout_offset':offset,'stderr_offset':(0 if name=='truncated' else offset),'limit':65536})
   expected=invoke(reference,{'op':'read','job_id':job,'stdout_offset':offset,'stderr_offset':(0 if name=='truncated' else offset),'limit':65536});assert read==expected,(expected,read)
  raw=(state/'exit.json').read_bytes();witness=json.loads((state/'exit.witness').read_bytes())
  assert witness['exit_sha256']==hashlib.sha256(raw).hexdigest()
  result=json.loads(raw)
  if name=='cancel':
   # Original systemd KillMode=control-group sends TERM concurrently with the supervisor's owned-child KILL.
   # A confirmed TERM child exit is 143; an unreaped child killed by cancellation is 137.
   assert result['exit_code'] in (137,143),(name,result)
   current['cancellation_signal_race']='original group TERM versus owned-child KILL'
  else:assert result['exit_code']==exit_code,(name,result)
  if name=='timeout':assert result['timed_out'] is True
  if name=='cancel':assert result['cancelled'] is True
  if name=='truncated':
   assert result['capture']['stdout']['seen']==(16<<20)+1 and result['capture']['stdout']['saved']==16<<20
   assert result['capture']['stdout']['truncated'] is True
  if name=='stdin':assert (state/'stdout.log').read_bytes()==change['stdin'].encode()
  if name.startswith('engine-'):
   cleanup=result['scratch_cleanup']
   assert cleanup['original_child_reaped'] is True and cleanup['original_process_group_stopped'] is True
   if name in ('engine-no-adoption','engine-bad-claim'):assert cleanup['worker_adopted'] is False
   else:assert cleanup['worker_adopted'] and cleanup['removed'] and cleanup['durable']
  if name=='ordinary-engine-shape':assert result.get('scratch_cleanup') is None and not (state/'engine-scratch').exists()
  current.update(phase='passed',exit=result,witness=witness,state_uid=state.stat().st_uid,terminal_same_original=True)
  assert current['state_uid']!=0
  save();print(json.dumps({'name':name,'phase':'passed','job':job,'exit_code':exit_code}),flush=True)
 assert hashlib.sha256(native.read_bytes()).hexdigest()==pin
 r['phase']='passed';r['finished']=datetime.datetime.now(datetime.timezone.utc).isoformat();save()
 print('ALL_REAL_SYSTEMD_PASSED',len(cases),hashlib.sha256((D/'qualification.json').read_bytes()).hexdigest(),flush=True)
except BaseException as e:
 r['phase']='failed';r['error']=repr(e);save();traceback.print_exc()
 subprocess.run(['/usr/bin/systemctl','stop','--',f'hepta-job-{job}.service'],capture_output=True,timeout=10)
 raise
