from pathlib import Path
from hashlib import sha256
import argparse
import contextlib,fcntl,json,os,struct,subprocess,sys,time
parser=argparse.ArgumentParser(description='Qualify native v26 controller assembly and probes against an independently supplied Store.')
parser.add_argument('--source',type=Path,default=Path(__file__).resolve().parents[1])
parser.add_argument('--release',type=Path,required=True)
parser.add_argument('--runner',type=Path,required=True)
parser.add_argument('--component',type=Path,required=True)
parser.add_argument('--output',type=Path,required=True)
args=parser.parse_args()
S=args.source.resolve(strict=True);sys.path.insert(0,str(S))
from tools.generate_hia_controller_install import ROLES,ROLE_LIMITS
stage=args.release.resolve(strict=True)
elf=args.component.resolve(strict=True)
D=args.output.resolve();D.mkdir(mode=0o700,exist_ok=False)
depot=D/'controller';depot.mkdir(mode=0o700)
scratch=D/'scratch';scratch.mkdir(mode=0o700)
roles={n:sha256((stage/n).read_bytes()).hexdigest() for n in ROLES}
tools=[args.runner.resolve(strict=True),stage/'hia-directory-package-build',stage/'hia-release']
record={'scope':'actual native v26 controller assembly from supplied Store roles; installer component, not the complete Worker and Store gate',
 'component_sha256':sha256(elf.read_bytes()).hexdigest(),'roles':roles,
 'tools':[{'path':str(p),'sha256':sha256(p.read_bytes()).hexdigest()} for p in tools]}
with contextlib.ExitStack() as stack:
 def keep(fd): stack.callback(os.close,fd);return fd
 def sealed(name,raw,mode):
  fd=keep(os.memfd_create(name,os.MFD_ALLOW_SEALING|os.MFD_CLOEXEC))
  at=0
  while at<len(raw):at+=os.write(fd,raw[at:])
  os.fchmod(fd,mode);fcntl.fcntl(fd,fcntl.F_ADD_SEALS,15);os.lseek(fd,0,os.SEEK_SET)
  return fd
 caps=[keep(os.open(p,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)) for p in (stage,depot,scratch)]
 caps.extend(sealed('controller-tool',p.read_bytes(),0o500) for p in tools)
 request=struct.pack('<8s15Q',b'HIACTI01',0,time.monotonic_ns()+90_000_000_000,*caps,len(ROLES),*([0]*6))
 request+=b''.join(bytes.fromhex(t['sha256']) for t in record['tools'])
 request+=b''.join(bytes.fromhex(roles[n]) for n in ROLES)
 assert len(request)==832
 source=sealed('controller-request',request,0o400)
 executable=sealed('hia-controller-install',elf.read_bytes(),0o500)
 before=time.monotonic()
 run=subprocess.run(['/usr/bin/strace','-f','-qq','-s','160','-o',str(D/'trace.log'),
  '-e','trace=process,file,desc',f'/proc/self/fd/{executable}'],stdin=source,
  capture_output=True,pass_fds=(*caps,executable),env={'PATH':''},cwd=D,timeout=120)
 record.update(rc=run.returncode,elapsed=time.monotonic()-before,stdout_bytes=len(run.stdout),stderr_bytes=len(run.stderr))
 (D/'stdout.bin').write_bytes(run.stdout);(D/'stderr.bin').write_bytes(run.stderr)
 (D/'observation.json').write_text(json.dumps(record,indent=2)+'\n')
 print(json.dumps({k:record[k] for k in ('rc','elapsed','stdout_bytes','stderr_bytes')}),flush=True)
 if run.returncode:
  print('trace_tail','\n'.join((D/'trace.log').read_text().splitlines()[-14:]),flush=True)
  raise SystemExit(run.returncode)
 assert len(run.stdout)==96 and not run.stderr
 magic,protocol,files,package,manifest,reserved=struct.unpack('<8sQQ32s32sQ',run.stdout)
 assert (magic,protocol,files,reserved)==(b'HIACTO01',26,20,0)
 installed=depot/package.hex()
 expected=(json.dumps({'schema':'hepta.hia.mcp.controller.v26','files':roles},sort_keys=True,separators=(',',':'))+'\n').encode()
 assert (installed/'hia-controller.json').read_bytes()==expected
 assert sha256(expected).digest()==manifest
 assert sorted(p.name for p in installed.iterdir())==sorted((*ROLES,'hia-controller.json'))
 assert all(sha256((installed/n).read_bytes()).hexdigest()==roles[n] for n in ROLES)
 assert not list(scratch.iterdir()),list(scratch.iterdir())
 assert all(sha256((stage/n).read_bytes()).hexdigest()==roles[n] for n in ROLES)
 trace=(D/'trace.log').read_text()
 executed=[r for r in trace.splitlines() if 'execve(' in r or 'execveat(' in r]
 assert not any('python' in r or '/bin/sh' in r or '/usr/bin/cc' in r for r in executed),executed
 record.update(status='passed',controller_package_sha256=package.hex(),controller_manifest_sha256=manifest.hex(),
              independent_inventory_matches=True,scratch_empty=True,exec_records=executed)
 (D/'qualification.json').write_text(json.dumps(record,indent=2)+'\n')
 print(json.dumps({'status':'passed','package_sha256':package.hex(),'manifest_sha256':manifest.hex(),'exec_count':len(executed)}),flush=True)
