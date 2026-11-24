from pathlib import Path
from hashlib import sha256
import base64,datetime,json,os,re,shutil,signal,stat,subprocess,sys,time,traceback

D=Path(sys.argv[1]).resolve();assert os.geteuid()==0
os.umask(0o022)
faults=len(sys.argv)>2 and sys.argv[2]=='--faults'
only=sys.argv[2] if len(sys.argv)>2 and not faults else None
subprocess.run(['/usr/bin/mount','-t','tmpfs','-o','mode=0755','hia-supervisor-private-varlib','/var/lib'],check=True)
assert ' - tmpfs hia-supervisor-private-varlib ' in Path('/proc/self/mountinfo').read_text()
root=Path('/var/lib/supervisor-qa');root.mkdir(mode=0o755)
for name in ['usr','proc','dev','etc','workspace','state','credentials','qa','tmp']:(root/name).mkdir(mode=0o755)
for path in ['/usr','/proc']:
 subprocess.run(['/usr/bin/mount','--bind',path,str(root/path[1:])],check=True)
for name in ['lib','lib64','bin','sbin']:
 p=Path('/'+name)
 if p.is_symlink():(root/name).symlink_to(os.readlink(p))
 elif p.exists():
  (root/name).mkdir();subprocess.run(['/usr/bin/mount','--bind',str(p),str(root/name)],check=True)
for name in ['null','zero','urandom']:
 p=root/'dev'/name;p.touch();subprocess.run(['/usr/bin/mount','--bind','/dev/'+name,str(p)],check=True)
uid=65534;gid=65534
for name in ['workspace','state','credentials','tmp']:os.chown(root/name,uid,gid)
(root/'tmp').chmod(0o1777)
for name in ['jobctl-reference','jobctl-native']:
 p=root/'qa'/name;p.write_bytes((D/name).read_bytes());p.chmod(0o555)
if faults:
 p=root/'qa/fault-tracer';p.write_bytes((D/'fault-tracer').read_bytes());p.chmod(0o555)
p=root/'workspace/fixture';p.write_bytes((D/'fixture').read_bytes());p.chmod(0o555)
for name,content,mode in [('script','printf script-ok; exit 7\n',0o555),('denied','not executable\n',0o444),('shell-script','#!/bin/sh\nprintf shell-ok; exit 9\n',0o555)]:
 p=root/'workspace'/name;p.write_text(content);p.chmod(mode)
(root/'workspace/sub').mkdir(mode=0o755)
(root/'workspace/fixture-link').symlink_to('fixture')
boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
cases=[]
def case(name,**kw):cases.append(dict(name=name,**kw))
case('captured-empty',trace=True)
case('captured-small',env={'QA_OUT':'65537','QA_ERR':'65539'})
case('captured-exact-cap',env={'QA_OUT':str(16<<20),'QA_ERR':str(16<<20)})
case('captured-cap-plus-one',env={'QA_OUT':str((16<<20)+1),'QA_ERR':str((16<<20)+1)})
case('captured-hot-streams',env={'QA_OUT':str((64<<20)+1),'QA_ERR':str((64<<20)+1)})
case('captured-exit7',env={'QA_OUT':'13','QA_ERR':'17','QA_EXIT':'7'})
case('captured-signal',env={'QA_OUT':'13','QA_ERR':'17','QA_SIGNAL':'15'})
case('captured-stdin',request={'stdin':'hello\nΩ🙂\0binary'},env={'QA_STDIN':'1'})
case('captured-empty-stdin',request={'stdin':''},env={'QA_STDIN':'1'})
case('captured-env',env={'QA_ENV':'1','':'empty','HOME':'custom','Z':'last','A':'first','HEPTA_RUNTIME_JOB_ID':'forbidden','HEPTA_RUNTIME_ENGINE_SCRATCH':'removed','é':'值'})
case('captured-args',request={'args':['','Ω','🙂','quote"','line\n']},env={'QA_ARGV':'1'})
case('captured-timeout',request={'timeout_seconds':0},env={'QA_SLEEP_MS':'5000'})
case('captured-drain',env={'QA_DESCENDANT':'1','QA_DESC_MS':'1200','QA_OUT':'3','QA_ERR':'5'})
case('captured-drain-stdout',env={'QA_DESCENDANT':'1','QA_DESC_STDERR_CLOSE':'1','QA_DESC_MS':'1200','QA_OUT':'3','QA_ERR':'5'})
for sig in [signal.SIGTERM,signal.SIGINT,signal.SIGHUP]:case('captured-cancel-'+str(int(sig)),env={'QA_SLEEP_MS':'5000','QA_OUT':'3','QA_ERR':'5'},parent_signal=sig)
case('spawn-missing',request={'executable':'/workspace/missing'})
case('spawn-directory',request={'executable':'/workspace/sub'})
case('spawn-denied',request={'executable':'/workspace/denied'})
case('spawn-format-absolute',request={'executable':'/workspace/script'})
case('spawn-format-search',request={'executable':'script'},env={'PATH':'/workspace'})
case('spawn-search-empty-segment',request={'executable':'fixture'},env={'PATH':':'})
case('spawn-search-missing-first',request={'executable':'fixture'},env={'PATH':'/absent:/workspace'})
case('spawn-shell-script',request={'executable':'/workspace/shell-script'})
case('spawn-symlink',request={'executable':'/workspace/fixture-link'})
case('spawn-args-nul',request={'args':['a\0b']})
case('spawn-env-nul',env={'A':'a\0b'})
case('spawn-env-key-nul',env={'a\0b':'x'})
case('spawn-exe-nul',request={'executable':'/workspace/fix\0ture'})
case('spawn-cwd-nul',request={'cwd':'/project/\0sub'})
case('spawn-large-argv',request={'args':['']*300000})
case('cwd-outside',request={'cwd':'/project-other'})
case('cwd-missing',request={'cwd':'/project/missing'})
case('cwd-normalization',request={'cwd':'/project//./sub/..','executable':'/project//./fixture'})
case('stdout-exists',setup='stdout-exists')
case('stderr-exists',setup='stderr-exists')
case('stdout-symlink',setup='stdout-symlink')
case('stderr-directory',setup='stderr-directory')
case('publication-readonly',setup='publication-readonly')
case('identity-mismatch',spec={'request_job_id':'other'})
case('boot-mismatch',spec={'boot_id':'other'})
case('captured-protocol-mismatch',spec={'terminal_protocol':'pty_v1'})
case('spec-sequence',sequence=True)
case('pty-empty',interactive=True)
case('pty-output',interactive=True,env={'QA_OUT':'17','QA_ERR':'19','QA_EXIT':'7'})
case('pty-stdin',interactive=True,env={'QA_STDIN':'1'},input=b'inherited\ninput')
case('pty-timeout',interactive=True,request={'timeout_seconds':0},env={'QA_SLEEP_MS':'5000'})
case('pty-cancel',interactive=True,env={'QA_SLEEP_MS':'5000'},parent_signal=signal.SIGTERM)
engine='{"schema":"hepta.rea.static-request.v1","profile":{"provider":"jadx"}}'
case('engine-adopt',request={'args':['rea-static-worker'],'stdin':engine},env={'QA_CLAIM':'1'})
case('engine-no-adoption',request={'args':['rea-static-worker'],'stdin':engine})
case('engine-descendant',request={'args':['rea-static-worker'],'stdin':engine},env={'QA_CLAIM':'1','QA_DESCENDANT':'1','QA_DESC_MS':'5000'})
case('engine-timeout',request={'args':['rea-static-worker'],'stdin':engine,'timeout_seconds':0},env={'QA_SLEEP_MS':'5000'})
case('engine-cancel',request={'args':['rea-static-worker'],'stdin':engine},env={'QA_CLAIM':'1','QA_SLEEP_MS':'5000'},parent_signal=signal.SIGTERM)
if faults:
 cases=[]
 for selector in ['sync.stdout','sync.stderr','sync.parent.1','sync.parent.2','sync.tmp.1','sync.tmp.2','open.stdout','open.stderr','open.parent','open.tmp.1','open.tmp.2','rename.1','rename.2']:
  for effect in ['eio','eintr']:case(selector+'-'+effect,fault=(selector,effect),env={'QA_OUT':'19073','QA_ERR':'17031'})
 for selector in ['write.stdout','write.stderr','write.tmp.1','write.tmp.2']:
  for effect in ['eio','eintr','zero','short']:case(selector+'-'+effect,fault=(selector,effect),env={'QA_OUT':'19073','QA_ERR':'17031'})
 for selector in ['read.pipe','poll']:
  for effect in ['eio','eintr']:case(selector+'-'+effect,fault=(selector,effect),env={'QA_OUT':'19073','QA_ERR':'17031'})
 for selector in ['wait.try','wait.block','kill']:
  for effect in ['eio','eintr']:case(selector+'-'+effect,fault=(selector,effect),request={'timeout_seconds':0 if selector!='wait.try' else 30},env={'QA_SLEEP_MS':'5000'})
if only:cases=[c for c in cases if c['name']==only];assert cases

def reset():
 for name in ['state','credentials']:
  p=root/name;p.chmod(0o755)
  for child in p.iterdir():
   if child.is_dir() and not child.is_symlink():shutil.rmtree(child)
   else:child.unlink()
def child_setup():
 os.chroot(root);os.chdir('/');os.setgroups([]);os.setgid(gid);os.setuid(uid);os.umask(0o022)
def normalize(value):
 if isinstance(value,list):return [normalize(v) for v in value]
 if not isinstance(value,dict):return value
 out={k:normalize(v) for k,v in value.items()}
 for key in ['device','inode']:
  if key in out:assert type(out[key]) is int and out[key]>=0;out[key]='<directory-'+key+'>'
 if 'at_unix_ms' in out:
  assert type(out['at_unix_ms']) is int and abs(out['at_unix_ms']-time.time_ns()//1000000)<120000;out['at_unix_ms']='<realtime>'
 return out
def inventory():
 out={};state=root/'state';exit_raw=(state/'exit.json').read_bytes() if (state/'exit.json').exists() else None
 if (state/'exit.witness').exists():
  witness=json.loads((state/'exit.witness').read_bytes());assert exit_raw is not None and witness['exit_sha256']==sha256(exit_raw).hexdigest()
 for p in [state,*sorted(state.rglob('*'))]:
  st=p.lstat();key=str(p.relative_to(state));item={'mode':stat.S_IMODE(st.st_mode),'kind':stat.S_IFMT(st.st_mode),'uid':st.st_uid}
  if p.is_symlink():item['target']=os.readlink(p)
  elif p.is_file():
   raw=p.read_bytes();item['bytes']=len(raw)
   if p.name in ['exit.json','exit.witness','engine-scratch.json','engine-scratch.retained.json']:
    value=json.loads(raw);item['value']=normalize(value);item['newline']=raw.endswith(b'\n');item.pop('bytes')
    if p.name=='exit.witness':item['value']['exit_sha256']='<matching-exit-bytes-sha256>'
    if p.name=='exit.json' and 'scratch_cleanup' not in value:item['exact_bytes_without_time']=re.sub(rb'"at_unix_ms":\d+',b'"at_unix_ms":0',raw).decode()
   elif p.name=='ready':assert int(raw)>0;item['pid']='<original-child>';item.pop('bytes')
   else:item['sha256']=sha256(raw).hexdigest()
  out[key]=item
 return out

r={'phase':'running','cases':[],'scope':'Original unprivileged supervisor under private mount and PID namespaces; real child exec, files, logs, process groups, and durable terminal receipts','error_diagnostics_exact':True}
rp=D/(('supervisor-faults-v3' if faults else 'supervisor-qualification-v4')+('-'+only if only else '')+'.json')
def save():rp.write_text(json.dumps(r,indent=2,ensure_ascii=False)+'\n')
save()
try:
 for c in cases:
  samples=[]
  for name in ['jobctl-reference','jobctl-native']:
   reset();q={'op':'start','job_id':'qualified-job','executable':'/project/fixture','args':[],'env':c.get('env',{}),**c.get('request',{})}
   spec={'request':q,'nonce':'nonce-Ω🙂','boot_id':boot,'workspace':'/project'}
   for k,v in c.get('spec',{}).items():
    if k=='request_job_id':q['job_id']=v
    else:spec[k]=v
   if c.get('sequence'):spec=[spec['request'],spec['nonce'],spec['boot_id'],spec['workspace']]
   raw=json.dumps(spec,ensure_ascii=False,separators=(',',':')).encode();assert len(raw)<=1048576
   (root/'credentials/spec').write_bytes(raw);(root/'credentials/spec').chmod(0o444)
   setup=c.get('setup')
   if setup in ['stdout-exists','stderr-exists']:
    p=root/'state'/('stdout.log' if setup=='stdout-exists' else 'stderr.log');p.write_bytes(b'original-file');p.chmod(0o644)
   if setup=='stdout-symlink':(root/'state/stdout.log').symlink_to('/workspace/denied')
   if setup=='stderr-directory':(root/'state/stderr.log').mkdir()
   if setup=='publication-readonly':(root/'state').chmod(0o555)
   mode='supervise-pty' if c.get('interactive') else 'supervise'
   argv=['/qa/'+name,mode,'qualified-job'];trace=None
   if c.get('fault'):
    argv=['/qa/fault-tracer',*c['fault'],'/tmp/fault-fired',*argv]
   if c.get('trace') and name=='jobctl-native':
    trace=root/'tmp/captured-empty.trace';argv=['/usr/bin/strace','-f','-qq','-s','180','-e','trace=execve,execveat,wait4,waitid,fsync,rename,openat,close,kill','-o','/tmp/captured-empty.trace',*argv]
   begin=time.monotonic();process=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={'CREDENTIALS_DIRECTORY':'/credentials','STATE_DIRECTORY':'/state'},preexec_fn=child_setup,start_new_session=True)
   try:
    if 'parent_signal' in c:
     for _ in range(5000):
      if (root/'state/ready').exists():break
      if process.poll() is not None:raise AssertionError(('supervisor exited before workload readiness',c['name'],name,process.returncode))
      time.sleep(.002)
     else:raise AssertionError(('workload readiness timeout',c['name'],name))
     time.sleep(.03);os.kill(process.pid,c['parent_signal'])
    stdout,stderr=process.communicate(c.get('input',b''),timeout=120)
   finally:
    try:os.killpg(process.pid,signal.SIGKILL)
    except ProcessLookupError:pass
   if trace is not None and trace.exists():(D/'captured-empty-native.trace').write_bytes(trace.read_bytes())
   if c.get('fault'):assert (root/'tmp/fault-fired').read_bytes()==b'1',('fault did not fire',c['name'],name,stderr.decode(errors='replace'))
   inv=inventory();sample={'rc':process.returncode,'stdout_hex':stdout.hex(),'stderr_hex':stderr.hex(),'inventory':inv,'seconds':time.monotonic()-begin}
   samples.append(sample)
   # Namespace is private; reap orphaned fixture descendants after each case.
   while True:
    try:
     pid,_=os.waitpid(-1,os.WNOHANG)
     if pid==0:break
    except ChildProcessError:break
  expected,actual=samples
  compared=['rc','stdout_hex','inventory','stderr_hex']
  passed=all(expected[k]==actual[k] for k in compared)
  r['cases'].append({'name':c['name'],'equal':passed,'reference':expected,'native':actual});r['phase']='running' if passed else 'failed';save()
  print(json.dumps({'name':c['name'],'equal':passed,'reference_rc':expected['rc'],'native_rc':actual['rc'],'seconds':actual['seconds']}),flush=True)
  if not passed:raise AssertionError(c['name'])
 r.update(phase='passed',case_count=len(cases));save()
except BaseException as error:r.update(phase='failed',error=repr(error));save();traceback.print_exc();raise
