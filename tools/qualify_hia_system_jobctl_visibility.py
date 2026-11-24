"""Preserve original complete process-group visibility admission under real systemd."""
from pathlib import Path
import subprocess,os,json,uuid,hashlib,time,datetime,traceback
import argparse,grp
parser=argparse.ArgumentParser(description='Original and native fail closed under restricted process visibility')
for field in ('output','fixture','reference','native','native-sha256'):parser.add_argument('--'+field,required=True)
args=parser.parse_args()
D=Path(args.output).resolve()
assert os.geteuid()==0
os.umask(0o022);D.mkdir(mode=0o755)
workspace=Path('/var/lib/hepta-runtime/workspaces')/('hia-native-original-pair-'+uuid.uuid4().hex);workspace.mkdir(mode=0o2770);os.chown(workspace,0,grp.getgrnam('hepta-workspace').gr_gid);workspace.chmod(0o2770)
fixture=Path(args.fixture)
(workspace/'fixture').write_bytes(fixture.read_bytes());(workspace/'fixture').chmod(0o555)
bins={'original':Path(args.reference),'native':Path(args.native)}
assert hashlib.sha256(bins['native'].read_bytes()).hexdigest()==args.native_sha256
qa_entries=Path('/usr/local/libexec')/('hia-jobctl-qualification-'+uuid.uuid4().hex);qa_entries.mkdir(mode=0o755)
r={'entry_directory':str(qa_entries),'phase':'running','scope':'actual original and native supervisors in real system systemd under unchanged ProtectProc=invisible isolation','cases':[]}
def save():(D/'qualification.json').write_text(json.dumps(r,indent=2)+'\n')
save()
try:
 for label,binary in bins.items():
  local=qa_entries/('jobctl-'+label);local.write_bytes(binary.read_bytes());local.chmod(0o555)
  job='hia-real-visibility-'+uuid.uuid4().hex;nonce=uuid.uuid4().hex;state=Path('/var/lib')/('hepta-job-'+job)
  q={'op':'start','job_id':job,'executable':str(workspace/'fixture'),'args':['rea-static-worker'],'env':{'QA_STATE':str(state),'QA_CLAIM':'1','QA_DESCENDANT':'1','QA_DESC_MS':'5000'},'stdin':'{"schema":"hepta.rea.static-request.v1","profile":{"provider":"jadx"}}','cwd':str(workspace),'timeout_seconds':15,'cpu_quota_percent':100,'memory_max_bytes':134217728,'nice':10}
  spec={'request':q,'nonce':nonce,'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'workspace':str(workspace),'terminal_protocol':'captured_v1'}
  credential=D/(label+'-spec.json');credential.write_text(json.dumps(spec,separators=(',',':'))+'\n');credential.chmod(0o600)
  unit='hepta-job-'+job+'.service'
  props=[f'Description=Hepta Runtime {job} {nonce}','DynamicUser=yes','Slice=hepta-runtime-jobs.slice','SupplementaryGroups=hepta-workspace',f'StateDirectory=hepta-job-{job}','StateDirectoryMode=0700',f'LoadCredential=spec:{credential}',f'BindPaths={workspace}:/workspace','WorkingDirectory=/workspace','InaccessiblePaths=-/var/lib/hepta-runtime -/etc/hepta-runtime -/run/user -/run/dbus -/run/systemd/private -/run/docker.sock -/run/libvirt','ProtectHome=yes','ProtectSystem=strict','PrivateTmp=yes','PrivateDevices=yes','NoNewPrivileges=yes','CapabilityBoundingSet=','RestrictSUIDSGID=yes','ProtectKernelTunables=yes','ProtectKernelModules=yes','ProtectControlGroups=yes','RestrictRealtime=yes','LockPersonality=yes','ProtectProc=invisible','KillMode=control-group','TimeoutStopSec=3s','TasksMax=infinity','UMask=0007','MemorySwapMax=0','CPUQuota=100%','MemoryMax=134217728','Nice=10','RuntimeMaxSec=25s','PrivateNetwork=yes','RestrictAddressFamilies=AF_UNIX AF_NETLINK']
  cmd=['/usr/bin/systemd-run','--quiet','--wait','--collect','--unit',unit,*[x for p in props for x in ['--property',p]],'--',str(local),'supervise',job]
  p=subprocess.run(cmd,capture_output=True,timeout=40)
  r['active_case']={'label':label,'job_id':job,'command':cmd,'returncode':p.returncode,'stdout':p.stdout.decode(errors='replace'),'stderr':p.stderr.decode(errors='replace')};save()
  assert p.returncode==1,(label,p.returncode,p.stderr)
  assert not (state/'exit.json').exists() and not (state/'exit.witness').exists()
  raw=(state/'engine-scratch.retained.json').read_bytes();ret=json.loads(raw)
  assert ret['error']=='engine original-group visibility is restricted'
  for k in ['removed','durable','worker_adopted','original_process_group_stopped','original_child_reaped']:assert ret[k] is False
  assert state.stat().st_uid!=0
  logs=subprocess.run(['/usr/bin/journalctl','--no-pager','-o','json','-u',unit],capture_output=True,check=True).stdout
  messages=[v['MESSAGE'] for line in logs.splitlines() if isinstance(v:=json.loads(line),dict) and isinstance(v.get('MESSAGE'),str) and v['MESSAGE'].startswith('jobctl: ')]
  assert messages==['jobctl: engine original-group visibility is restricted'],(label,messages)
  normalized=dict(ret)
  for key in ['job_id','launch_nonce','device','inode']:
   normalized[key]='<'+key+'>'
  r['cases'].append({'label':label,'image_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'job_id':job,'command':cmd,'returncode':p.returncode,'stdout_hex':p.stdout.hex(),'stderr_hex':p.stderr.hex(),'state_uid':state.stat().st_uid,'retained':ret,'normalized_retained':normalized,'journal_error_messages':messages,'terminal_absent':True});save()
 assert r['cases'][0]['normalized_retained']==r['cases'][1]['normalized_retained']
 r['phase']='passed';save();print('PROTECTPROC_ORIGINAL_NATIVE_PASS',hashlib.sha256((D/'qualification.json').read_bytes()).hexdigest(),flush=True)
except BaseException as e:r['phase']='failed';r['error']=repr(e);save();traceback.print_exc();raise
