from pathlib import Path
from hashlib import sha256
import argparse
import contextlib,fcntl,json,os,struct,subprocess,sys,time
parser=argparse.ArgumentParser(description='Exercise the native controller installer refusal and publication boundaries.')
parser.add_argument('--source',type=Path,default=Path(__file__).resolve().parents[1])
parser.add_argument('--release',type=Path,required=True)
parser.add_argument('--runner',type=Path,required=True)
parser.add_argument('--component',type=Path,required=True)
parser.add_argument('--output',type=Path,required=True)
args=parser.parse_args()
S=args.source.resolve(strict=True);sys.path.insert(0,str(S))
from tools.generate_hia_controller_install import ROLES
stage=args.release.resolve(strict=True)
elf=args.component.resolve(strict=True)
D=args.output.resolve();D.mkdir(mode=0o700,exist_ok=False)
tools=[args.runner.resolve(strict=True),stage/'hia-directory-package-build',stage/'hia-release']
role_bytes={n:(stage/n).read_bytes() for n in ROLES}
tool_bytes=[p.read_bytes() for p in tools]
cases=('unsealed_request','unsealed_runner','wrong_tool_pin','wrong_role_pin','expired_deadline',
       'duplicate_capability','same_directory_inode','nonempty_scratch','missing_role','symlink_role',
       'writable_role','bound_wrong_protocol','nonzero_reserved')
results=[]
for case in cases:
 C=D/case;C.mkdir(mode=0o700);depot=C/'controller';depot.mkdir(mode=0o700);scratch=C/'scratch';scratch.mkdir(mode=0o700)
 release=stage;payloads=role_bytes.copy()
 if case in ('missing_role','symlink_role','writable_role','bound_wrong_protocol'):
  release=C/'release';release.mkdir(mode=0o700)
  if case=='bound_wrong_protocol':payloads['hia-worker-prepare']=payloads['hia-agent-mcp-catalog']
  for name,raw in payloads.items():
   if name=='hia-worker-prepare' and case=='missing_role':continue
   if name=='hia-worker-prepare' and case=='symlink_role':
    (release/name).symlink_to(stage/name);continue
   (release/name).write_bytes(raw);(release/name).chmod(0o400 if name.endswith('.json') else 0o500)
  if case=='writable_role':(release/'hia-worker-prepare').chmod(0o777)
 if case=='nonempty_scratch':(scratch/'preexisting').write_bytes(b'preserve')
 rolepins=[sha256(payloads[n]).digest() for n in ROLES]
 with contextlib.ExitStack() as stack:
  def keep(fd):stack.callback(os.close,fd);return fd
  def sealed(name,raw,mode,seal=True):
   fd=keep(os.memfd_create(name,os.MFD_ALLOW_SEALING|os.MFD_CLOEXEC));at=0
   while at<len(raw):at+=os.write(fd,raw[at:])
   os.fchmod(fd,mode)
   if seal:fcntl.fcntl(fd,fcntl.F_ADD_SEALS,15)
   os.lseek(fd,0,os.SEEK_SET);return fd
  caps=[keep(os.open(p,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)) for p in (release,depot,depot if case=='same_directory_inode' else scratch)]
  caps.extend(sealed('controller-tool',raw,0o500,not(case=='unsealed_runner' and i==0)) for i,raw in enumerate(tool_bytes))
  fields=list(caps)
  if case=='duplicate_capability':fields[2]=fields[1]
  deadline=time.monotonic_ns()+30_000_000_000
  if case=='expired_deadline':deadline=time.monotonic_ns()-1
  reserved=[0]*6
  if case=='nonzero_reserved':reserved[2]=1
  request=bytearray(struct.pack('<8s15Q',b'HIACTI01',0,deadline,*fields,14,*reserved)+b''.join(sha256(raw).digest() for raw in tool_bytes)+b''.join(rolepins))
  if case=='wrong_tool_pin':request[128]^=1
  if case=='wrong_role_pin':request[224]^=1
  assert len(request)==672
  src=sealed('controller-request',request,0o400,case!='unsealed_request')
  executable=sealed('controller-install',elf.read_bytes(),0o500)
  command=[f'/proc/self/fd/{executable}']
  if case=='bound_wrong_protocol':
   command=['/usr/bin/strace','-f','-qq','-s','80','-o',str(C/'trace.log'),'-e','trace=process',*command]
  before=time.monotonic()
  run=subprocess.run(command,stdin=src,capture_output=True,pass_fds=(*caps,executable),env={'PATH':''},cwd=C,timeout=40)
  row={'case':case,'rc':run.returncode,'stdout_bytes':len(run.stdout),'stderr_bytes':len(run.stderr),'elapsed':time.monotonic()-before,
       'published_entries':len(list(depot.iterdir()))}
  assert run.returncode!=0 and not run.stdout and not run.stderr,row
  assert not list(depot.iterdir()),row
  if case=='nonempty_scratch':assert (scratch/'preexisting').read_bytes()==b'preserve'
  if case=='bound_wrong_protocol':
   trace=(C/'trace.log').read_text();row['actual_native_child_exec']=trace.count('execveat(')
   assert row['actual_native_child_exec']>=2,row
  results.append(row);print(json.dumps(row),flush=True)
report={'status':'passed','count':len(results),'component_sha256':sha256(elf.read_bytes()).hexdigest(),
        'scope':'native controller strict refusal gates; failure-private scratch remains caller owned','cases':results}
(D/'report.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'status':'passed','count':len(results)}),flush=True)
