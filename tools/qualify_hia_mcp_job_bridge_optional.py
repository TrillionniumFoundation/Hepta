"""External real-SSH optional-profile comparison, using the frozen Rust provider."""
from pathlib import Path
from hashlib import sha256
import argparse,fcntl,importlib.util,json,os,struct,subprocess,sys,time

# This CLI operates only on an explicitly prepared private SSH namespace.
# Its fault injection changes the entry copy below --area, never a host entry.

parser=argparse.ArgumentParser()
parser.add_argument('--area',type=Path,required=True)
parser.add_argument('--source',type=Path,required=True)
parser.add_argument('--image',type=Path,required=True)
parser.add_argument('--runtime',type=Path,required=True)
a=parser.parse_args();D=a.area.resolve(strict=True);sys.path.insert(0,str(a.source))
assert (D/'libexec/hepta-runtime-job-entry').resolve(strict=True).is_relative_to(D)
from tools.hia_agent_native_transport import MCPStdio
base=json.loads((D/'runtime-config-bound.json').read_bytes())
host_name=base['hia_worker']['host']
controller=Path(base['hosts'][host_name]['native_jobs']['entry']['executable']).parent
manifest=controller/'hia-controller.json'
names=('hia-worker-prepare','hia-job-receipt','hia-job-entry','hia-job-submit',
       'hia-job-observation','hia-job-cancel','hia-job-launch','hia-job-supervisor',
       'hia-agent-mcp-terminal','hia-agent-mcp-response-schema','/usr/bin/ssh',
       'hia-agent-mcp-proof-schema')
canonical=lambda v:json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
rows=[]

class Client:
 def __init__(self,config,area,state=None):
  self.config=config;self.area=area;area.mkdir(mode=0o700,exist_ok=True)
  self.state=state or area/'controller-state';self.state.mkdir(mode=0o700,exist_ok=True)
  self.profile=config['hia_worker'];self.host=config['hosts'][host_name]
  self.fds=[];self.roles=[];self.counter=0
  self.directory=self.keep(os.open(self.state,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC));self.locks=[]
  for name in ('controller.owner.lock','controller.lock'):
   fd=self.keep(os.open(self.state/name,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_CLOEXEC,0o600))
   fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);self.locks.append(fd)
  self.cache=self.keep(os.memfd_create('optional-replay',os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING))
  os.ftruncate(self.cache,8388608);os.fchmod(self.cache,0o600);fcntl.fcntl(self.cache,fcntl.F_ADD_SEALS,7)
  for index,name in enumerate(names,1):
   path=Path(name) if name.startswith('/') else controller/name;raw=path.read_bytes()
   fd=self.keep(os.memfd_create('optional-role',os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING));at=0
   while at<len(raw):at+=os.write(fd,raw[at:])
   os.fchmod(fd,0o500);fcntl.fcntl(fd,fcntl.F_ADD_SEALS,15)
   self.roles.append(struct.pack('<QQQ32sQ',index,fd,len(raw),sha256(raw).digest(),0))
 def keep(self,fd):self.fds.append(fd);return fd
 def invoke(self,section='manifest'):
  self.counter+=1;prefix=self.area/f'{self.counter:03d}'
  parts=[canonical(self.profile),canonical(self.host),canonical({'section':section}),
         canonical({'section':section}),canonical('hia_describe'),str(self.state).encode(),self.profile['catalog_sha256'].encode()]
  business=struct.pack('<8s8Q',b'HIAMJB01',*map(len,parts),0)+b''.join(parts)
  wire=struct.pack('<8s7Q',b'HIAMBI01',len(business),os.getpid(),(1<<64)-1,12,0,0,6)
  wire+=b''.join(self.roles)+struct.pack('<8s4Q',b'HIAOWN02',self.directory,*self.locks,self.cache)+business
  prefix.with_suffix('.input').write_bytes(wire)
  start=time.monotonic();run=subprocess.run([str(a.image)],input=wire,pass_fds=self.fds,
      env={**os.environ,'PATH':''},cwd=self.area,capture_output=True,timeout=180)
  prefix.with_suffix('.stdout').write_bytes(run.stdout);prefix.with_suffix('.stderr').write_bytes(run.stderr)
  result={'returncode':run.returncode,'seconds':time.monotonic()-start,'stdout_bytes':len(run.stdout),
          'stderr_bytes':len(run.stderr),'request_sha256':sha256(business).hexdigest()}
  if run.stdout:result['response']=json.loads(run.stdout)
  assert run.returncode==0 and not run.stderr and 'response' in result,result
  return result
 def close(self):
  for fd in reversed(self.fds):os.close(fd)
  self.fds=[]

def jobs(state):
 return {p.name:json.loads(p.read_bytes()) for p in sorted((state/'jobs').glob('*.json'))}

def oracle(config,state,area):
 area.mkdir(mode=0o700);cfg=json.loads(json.dumps(config));cfg['state_dir']=str(state)
 path=area/'runtime-config.json';path.write_bytes(canonical(cfg)+b'\n');path.chmod(0o600)
 command=[str(a.runtime),'mcp','--path',str(D),'--runtime-config',str(path),
          '--hia-controller-manifest',str(manifest),'--hia-controller-sha256',sha256(manifest.read_bytes()).hexdigest()]
 env={k:v for k,v in os.environ.items() if not k.startswith(('HEPTA_HIA_','HIA_LOCAL_MCP_','HIA_TRANSPORT_'))}
 env['PATH']='/usr/bin';env['RUST_LOG']='warn';transport=None
 try:
  transport=MCPStdio(command,cwd=D,env=env,timeout=180)
  response=transport._domain_result(transport.rpc('tools/call',{'name':'hia_describe','arguments':{'section':'manifest'}}))
  (area/'response.json').write_bytes(canonical(response)+b'\n')
  return response
 finally:
  if transport is not None:
   (area/'protocol.json').write_text(json.dumps(transport.protocol_records,indent=2)+'\n')
   (area/'stderr').write_text(transport.stderr());transport.close()

def record(name,**facts):
 rows.append({'case':name,'passed':True,**facts})
 (D/'qualification.json').write_text(json.dumps({'status':'running','rows':rows},indent=2)+'\n')
 print(name,'PASS',flush=True)

config=json.loads(json.dumps(base));config['hosts'][host_name].pop('native_jobs')
entry=D/'libexec/hepta-runtime-job-entry';entry_bytes=entry.read_bytes()
try:
 client=Client(config,D/'normal')
 initial=client.invoke();record('None-absent-first-real-native-dispatch',result=initial)
 for i in range(600):
  current=client.invoke()
  if current['response']['status']=='completed':break
  assert current['response']['status']=='accepted',current
  time.sleep(.1)
 else:raise AssertionError('original job did not complete')
 baseline=jobs(client.state);assert len(baseline)==1
 record('None-absent-original-complete-output',result=current,jobs=baseline)
 client.host['native_jobs']=None
 null=client.invoke();assert null['response']==current['response'] and jobs(client.state)==baseline
 record('None-null-same-job-same-receipt',result=null)
 client.host['native_jobs']=base['hosts'][host_name]['native_jobs']
 some=client.invoke();assert some['response']==current['response'] and jobs(client.state)==baseline
 record('Some-explicit-same-job-same-receipt',result=some)
 client.host.pop('native_jobs');state=client.state;client.close()
 original=oracle(config,state,D/'normal-original')
 assert original==current['response'] and jobs(state)==baseline,(original,current)
 record('frozen-Rust-None-observes-native-original-job',response=original)
 # Conversely the original provider creates a fresh real job using its legacy
 # Python transport. Native observation must preserve that already-owned job.
 inverse_state=D/'original-created-state';inverse_state.mkdir(mode=0o700)
 original=oracle(config,inverse_state,D/'original-created')
 client=Client(config,D/'original-created-native',state=inverse_state)
 for i in range(600):
  current=client.invoke()
  if current['response']['status']=='completed':break
  assert current['response']['status']=='accepted',current
  time.sleep(.1)
 else:raise AssertionError('original-created job did not complete')
 inverse_jobs=jobs(inverse_state);assert len(inverse_jobs)==1
 client.close();again=oracle(config,inverse_state,D/'original-created-replay')
 assert again==current['response'] and jobs(inverse_state)==inverse_jobs,(again,current)
 record('native-None-observes-original-Python-created-job',response=again,jobs=inverse_jobs)
 for fault in ('absent','not-executable'):
  if fault=='absent':entry.rename(entry.with_suffix('.held'))
  else:entry.chmod(0o400)
  client=Client(config,D/('entry-'+fault))
  initial=client.invoke();snapshot=jobs(client.state);assert len(snapshot)==1
  original_record=next(iter(snapshot.values()));assert original_record['launch_state']=='launch_unknown'
  assert initial['response']['status']=='accepted',initial
  repeated=client.invoke();assert repeated['response']['status']=='unknown' and jobs(client.state)==snapshot
  record('entry-'+fault+'-retains-unknown-no-relaunch',first=initial,replay=repeated,jobs=snapshot)
  if fault=='absent':entry.with_suffix('.held').rename(entry)
  else:entry.chmod(0o500)
  restored=client.invoke();assert restored['response']==repeated['response'] and jobs(client.state)==snapshot
  state=client.state;client.close()
  original=oracle(config,state,D/('entry-'+fault+'-original'))
  assert original==restored['response'] and jobs(state)==snapshot,(original,restored)
  record('entry-'+fault+'-restoration-and-original-replay-no-relaunch',response=original)
 assert entry.read_bytes()==entry_bytes
 result={'status':'passed','scope':'real OpenSSH and actual user systemd optional Operator native_jobs transport and same-job frozen Rust cross-observation; privileged Isolated transport qualified separately',
         'image':str(a.image),'image_sha256':sha256(a.image.read_bytes()).hexdigest(),
         'runtime':str(a.runtime),'runtime_sha256':sha256(a.runtime.read_bytes()).hexdigest(),
         'manifest_sha256':sha256(manifest.read_bytes()).hexdigest(),'fixed_entry_sha256':sha256(entry_bytes).hexdigest(),
         'rows':rows,'cases':len(rows)}
 (D/'qualification.json').write_text(json.dumps(result,indent=2)+'\n');print('OPTIONAL OPERATOR PASS',len(rows),flush=True)
finally:
 if 'client' in globals():client.close()
 if entry.with_suffix('.held').exists():entry.with_suffix('.held').rename(entry)
 entry.chmod(0o500)
