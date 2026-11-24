from pathlib import Path
from hashlib import sha256
import json,os,re,signal,stat,subprocess,sys,time

D=Path(sys.argv[1]);assert os.geteuid()==0
os.umask(0o022)
for target,name in [('/var/lib','hia-start-private-varlib'),('/etc','hia-start-private-etc')]:
 subprocess.run(['/usr/bin/mount','-t','tmpfs','-o','mode=0755',name,target],check=True)
mounts=Path('/proc/self/mountinfo').read_text()
assert all(' - tmpfs '+n+' ' in mounts for n in ['hia-start-private-varlib','hia-start-private-etc'])
workspace=Path('/var/lib/hepta-runtime/workspaces/qa');workspace.mkdir(parents=True)
policy=Path('/etc/hepta-runtime/job-policy.json');policy.parent.mkdir();policy.write_text(json.dumps({'workspace':str(workspace)}));policy.chmod(0o600)
registry=Path('/var/lib/hepta-runtime-jobctl');probe=Path('/var/lib/qa-probes');probe.mkdir(mode=0o755)
native=probe/'jobctl-native';reference=probe/'jobctl-reference'
for dst,src in [(native,D/'jobctl-native'),(reference,D/'jobctl-reference')]:dst.write_bytes(src.read_bytes());dst.chmod(0o555)
stub=probe/'fixture';stub.write_bytes((D/'fixture').read_bytes());stub.chmod(0o555)
for target in ['/usr/bin/systemd-run','/usr/bin/systemctl']:
 subprocess.run(['/usr/bin/mount','--bind',str(stub),target],check=True)
assert all(' '+target+' ' in Path('/proc/self/mountinfo').read_text() for target in ['/usr/bin/systemd-run','/usr/bin/systemctl'])
default={'op':'start','job_id':'job-start-1','executable':'/usr/bin/true'}
cases=[]
def case(name,**kw):cases.append(dict(name=name,**kw))
case('captured-success',trace=True)
case('captured-output',env={'HIA_START_OUT':'65537','HIA_START_ERR':'65539'})
case('captured-output-large',env={'HIA_START_OUT':'67108865','HIA_START_ERR':'67108865'})
case('captured-not-found',env={'HIA_START_LOAD':'not-found'})
case('captured-show-nonzero',env={'HIA_START_SHOW_RC':'17'})
case('captured-invocation-empty',env={'HIA_START_INVOCATION':''})
case('captured-description-wrong',env={'HIA_START_DESCRIPTION':'wrong'})
case('captured-launch-failure',env={'HIA_START_RUN_RC':'17'})
case('captured-failure-stderr',env={'HIA_START_RUN_RC':'17','HIA_START_RUN_MODE':'stderr-invalid'})
case('captured-child-signal',env={'HIA_START_CHILD_SIGNAL':'15'})
case('unicode-resources',request={'args':['Ω','😀','\n'],'env':{'Z':'z','A':'a'},'stdin':'stdin\n','timeout_seconds':23,'nice':0,'cpu_quota_percent':3,'memory_max_bytes':67108864})
case('pty-success',request={'op':'pty'})
case('pty-exit17',request={'op':'pty'},env={'HIA_START_RUN_RC':'17'})
case('pty-child-signal',request={'op':'pty'},env={'HIA_START_CHILD_SIGNAL':'15'})
case('pty-poll-empty',request={'op':'pty'},env={'HIA_START_INVOCATION':''})
case('pty-not-found',request={'op':'pty'},env={'HIA_START_LOAD':'not-found'})
case('pty-wait',request={'op':'pty'},env={'HIA_START_DELAY_MS':'150'})
for sig in [signal.SIGTERM,signal.SIGINT,signal.SIGHUP]:
 case('pty-cancel-'+str(sig),request={'op':'pty'},env={'HIA_START_DELAY_MS':'30000'},parent_signal=sig)
case('pty-cancel-stop-failure',request={'op':'pty'},env={'HIA_START_DELAY_MS':'30000','HIA_START_STOP_RC':'7'},parent_signal=signal.SIGTERM)
for n in [128,4095,4096,4097,8191,8192,8193,16383]:
 case('pty-stdin-'+str(n),request={'op':'pty'},env={'HIA_START_RUN_MODE':'stdin'},json_bytes=n,tail=b'T'*12000)

def discard(path):
 if path.is_symlink() or path.is_file() or (path.exists() and not path.is_dir()):path.unlink()
 elif path.is_dir():
  for p in path.iterdir():discard(p)
  path.rmdir()
def normalize(value):
 if not isinstance(value,dict):return value
 out=dict(value)
 if 'nonce' in out:
  assert re.fullmatch('[0-9a-f]{32}',out['nonce']);out['nonce']='<kernel-nonce>'
 if 'created_unix_ms' in out:
  assert type(out['created_unix_ms']) is int and abs(out['created_unix_ms']-time.time_ns()//1000000)<20000;out['created_unix_ms']='<realtime>'
 return out
def inventory():
 out={}
 for p in [registry,*sorted(registry.rglob('*'))] if registry.exists() else []:
  st=p.lstat();n=str(p.relative_to(registry));n=re.sub(r'\.tmp-\d+$','.tmp-PID',n)
  item={'mode':stat.S_IMODE(st.st_mode),'kind':stat.S_IFMT(st.st_mode),'uid':st.st_uid}
  if p.is_file():
   raw=p.read_bytes()
   if p.name in ['spec.json','record.json']:item.update(value=normalize(json.loads(raw)),newline=raw.endswith(b'\n'))
   else:item['sha256']=sha256(raw).hexdigest()
  if p.is_symlink():item['target']=os.readlink(p)
  out[n]=item
 return out
rows=[]
for c in cases:
 samples=[]
 for image in [reference,native]:
  discard(registry)
  for n in ['launch-count','show-count','stop-count','launch-argv']:discard(probe/n)
  q={**default,**c.get('request',{})}
  if 'json_bytes' in c:
   q['stdin']='';raw=json.dumps(q,separators=(',',':'),ensure_ascii=False).encode();q['stdin']='x'*(c['json_bytes']-len(raw))
  raw=json.dumps(q,separators=(',',':'),ensure_ascii=False).encode()
  stdin=probe/'input';stdin.write_bytes(raw+b'\n'+c.get('tail',b''))
  command=[str(image)]
  if c.get('trace') and image==native:
   command=['/usr/bin/strace','-f','-qq','-s','200','-e','trace=execve,execveat,wait4,fsync,renameat,rename,flock','-o',str(D/(c['name']+'.trace')),*command]
  started=time.monotonic()
  with stdin.open('rb') as stream:
   process=subprocess.Popen(command,stdin=stream,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={'PATH':'',**c.get('env',{})},cwd=workspace,start_new_session=True)
   try:
    if 'parent_signal' in c:
     for _ in range(1000):
      record=registry/q['job_id']/'record.json'
      if record.exists() and json.loads(record.read_bytes()).get('launch_state')=='launched':break
      if process.poll() is not None:break
      time.sleep(.002)
     else:raise AssertionError(('start readiness timeout',c['name'],image))
     time.sleep(.02);os.kill(process.pid,c['parent_signal'])
    stdout,stderr=process.communicate(timeout=40)
   finally:
    try:os.killpg(process.pid,signal.SIGKILL)
    except ProcessLookupError:pass
  prefix=b''
  if c.get('tail'):
   used=len(raw)+1;skipped=((used+8191)//8192)*8192-used;prefix=c['tail'][skipped:]
  assert stdout.startswith(prefix),(c['name'],image.name,'stdin-prefix',stdout[:100])
  response=stdout[len(prefix):]
  parsed=json.loads(response) if response else None
  if process.returncode==0:assert stderr==b'' and response.endswith(b'\n'),(c['name'],image.name,stderr)
  inv=inventory()
  argv=(probe/'launch-argv').read_bytes() if (probe/'launch-argv').exists() else b''
  argv=re.sub(rb'(Description=Hepta Runtime [^ ]+ )[0-9a-f]{32}',rb'\1<kernel-nonce>',argv)
  counts={n:(probe/(n+'-count')).stat().st_size if (probe/(n+'-count')).exists() else 0 for n in ['launch','show','stop']}
  samples.append({'rc':process.returncode,'response':parsed,'prefix_sha256':sha256(prefix).hexdigest(),'inventory':inv,'argv_hex':argv.hex(),'counts':counts,'stderr_hex':stderr.hex(),'seconds':time.monotonic()-started})
 expected,actual=samples
 compared=['rc','response','prefix_sha256','inventory','argv_hex','counts']
 passed=all(expected[k]==actual[k] for k in compared)
 row={'case':c['name'],'passed':passed,'reference':expected,'native':actual};rows.append(row)
 print(json.dumps(row,ensure_ascii=False),flush=True)
 (D/'qualification.json').write_text(json.dumps({'status':'running' if passed else 'failed','cases':rows,'error_diagnostics_exact':False,'scope':'Complete START/PTY control, argv, process, binding, cancellation, and persistent registry under private fixed external command fixtures'},indent=2)+'\n')
 if not passed:raise SystemExit(1)
(D/'qualification.json').write_text(json.dumps({'status':'passed','cases':rows,'error_diagnostics_exact':False,'scope':'Complete START/PTY control, argv, process, binding, cancellation, and persistent registry under private fixed external command fixtures; actual systemd and DynamicUser supervisor remain separate'},indent=2)+'\n')
print(json.dumps({'status':'passed','cases':len(rows)}),flush=True)
