from pathlib import Path
from hashlib import sha256
import argparse
import contextlib,fcntl,json,os,struct,subprocess,sys,time
parser=argparse.ArgumentParser(description='Qualify closed native source roles and exact original Worker-entry packing.')
parser.add_argument('--source',type=Path,default=Path(__file__).resolve().parents[1])
parser.add_argument('--kit',type=Path,required=True)
parser.add_argument('--controller-reference',type=Path,required=True)
parser.add_argument('--worker-reference',type=Path,required=True)
parser.add_argument('--output',type=Path,required=True)
args=parser.parse_args()
S=args.source.resolve(strict=True);H=S/'examples/hia_bootstrap';sys.path.insert(0,str(S))
from tools.build_hia_source_build import _named_source_request
from tools.build_hia_native_store_release import _member_with_objects
from tools.generate_hia_native_filter import read_adapter_binding,verify_adapter,elf_header
from tools.generate_hia_installed_worker_entry import ADAPTER
D=args.output.resolve();D.mkdir(mode=0o700)
controller_reference=args.controller_reference.resolve(strict=True)
captured={}
def source(p):
 raw=p.read_bytes();captured[str(p)]=sha256(raw).hexdigest();return raw
filter_source=source(H/'source_filter_member.hepta')
compiler_source=source(H/'selfhost.hepta')
sha_source=source(H/'sha256_stream.hepta')
kit_builder=args.kit.resolve(strict=True)
def call(executable,wire):
 return subprocess.run([str(executable),'build'],input=wire,capture_output=True,env={'PATH':''},timeout=180)
def build(role,primary,packer,companions):
 R=D/role;R.mkdir(mode=0o700)
 kit={'source_build_policy.hepta':filter_source,'selfhost.hepta':compiler_source,'source_build_packer.hepta':source(H/(packer+'.hepta'))}
 r=call(kit_builder,_named_source_request(kit,tag=b'HIAKIT01'))
 assert r.returncode==0 and not r.stderr,(role,'kit',r.returncode,r.stderr[:100])
 builder=R/'builder';builder.write_bytes(r.stdout);builder.chmod(0o500)
 parts={role+'.hepta':source(H/(primary+'.hepta'))}
 for module in companions:parts[module+'.hepta']=source(H/(module+'.hepta'))
 r=call(builder,_named_source_request(parts,tag=(b'HIASRC01' if len(parts)==1 else b'HIAMUL01')))
 assert r.returncode==0 and not r.stderr,(role,'member',r.returncode,r.stderr[:100])
 elf,images=(r.stdout,{}) if len(parts)==1 else _member_with_objects(r.stdout,parts)
 output=R/role;output.write_bytes(elf);output.chmod(0o500)
 permuted=dict(reversed(list(parts.items())))
 r=call(builder,_named_source_request(permuted,tag=(b'HIASRC01' if len(permuted)==1 else b'HIAMUL01')))
 assert r.returncode==0 and not r.stderr
 other,oi=(r.stdout,{}) if len(permuted)==1 else _member_with_objects(r.stdout,permuted)
 assert other==elf and oi==images
 bads=[('wrong primary module',{**parts,role+'.hepta':sha_source}),
       ('unknown primary alias',{('wrong-'+k if k==role+'.hepta' else k):v for k,v in parts.items()}),
       ('extra unknown source',{**parts,'unrelated.hepta':sha_source})]
 if companions:
  bads.extend([('missing required companion',{k:v for k,v in parts.items() if k!=companions[0]+'.hepta'}),
               ('wrong companion module',{**parts,companions[0]+'.hepta':parts[role+'.hepta']})])
 cases=[]
 for label,bad in bads:
  r=call(builder,_named_source_request(bad,tag=(b'HIASRC01' if len(bad)==1 else b'HIAMUL01')))
  assert r.returncode!=0 and not r.stdout,(role,label,r.returncode,len(r.stdout))
  cases.append({'case':label,'rc':r.returncode,'stdout_bytes':len(r.stdout)})
 result={'role':role,'elf_sha256':sha256(elf).hexdigest(),'bytes':len(elf),
         'ordered_sources':list(parts),'source_order_independent':True,'negative_cases':cases}
 (R/'report.json').write_text(json.dumps(result,indent=2)+'\n')
 return output,elf,result
controller,ce,cr=build('hia-controller-install','controller_install','controller_install_packer',['controller_probe','sha256_stream'])
assert ce==controller_reference.read_bytes()
print(json.dumps(cr),flush=True)
packer,pe,pr=build('hia-installed-worker-entry-pack','installed_worker_entry_packer','native_filter_packer',[])
original=args.worker_reference.resolve(strict=True).read_bytes()
binding=read_adapter_binding(source(H/'installed_worker_entry_packer.hepta'),source(S/ADAPTER),calls=3)
code=original[len(elf_header())+binding[1]:]
verify_adapter(original,code,binding,entries=(0,0,0))
packet=struct.pack('<8sQ',b'HIAWEP01',len(code))+code
with contextlib.ExitStack() as stack:
 fd=os.memfd_create('installed-entry-rawpack',os.MFD_ALLOW_SEALING|os.MFD_CLOEXEC);stack.callback(os.close,fd)
 os.write(fd,pe);os.fchmod(fd,0o500);fcntl.fcntl(fd,fcntl.F_ADD_SEALS,15)
 r=subprocess.run(['/usr/bin/strace','-f','-qq','-s','80','-e','trace=process','-o',str(D/'rawpack.trace'),f'/proc/self/fd/{fd}'],
   input=packet,capture_output=True,pass_fds=(fd,),env={'PATH':''},timeout=30)
 assert r.returncode==0 and not r.stderr and r.stdout==original,(r.returncode,len(r.stdout))
 (D/'roundtrip-worker').write_bytes(r.stdout)
 rawcases=[]
 bad=[('wrong magic',b'X'+packet[1:]),('truncated payload',packet[:-1]),('extra byte',packet+b'\0'),
      ('empty image',struct.pack('<8sQ',b'HIAWEP01',0)),('too large',struct.pack('<8sQ',b'HIAWEP01',1<<20)+bytes(1<<20))]
 for label,wire in bad:
  r=subprocess.run([f'/proc/self/fd/{fd}'],input=wire,capture_output=True,pass_fds=(fd,),env={'PATH':''},timeout=30)
  assert r.returncode!=0 and not r.stdout and not r.stderr,(label,r.returncode,len(r.stdout))
  rawcases.append({'case':label,'rc':r.returncode,'stdout_bytes':len(r.stdout)})
trace=(D/'rawpack.trace').read_text()
assert 'execve("/proc/self/fd/' in trace and 'python' not in trace
assert all(sha256(Path(p).read_bytes()).hexdigest()==pin for p,pin in captured.items())
pr.update(original_worker_sha256=sha256(original).hexdigest(),roundtrip_exact=True,raw_packet_refusals=rawcases)
report={'status':'passed','scope':'strict named source roles and original HIA installed-entry packer as native byte filter; component only',
        'source_filter_sha256':sha256(filter_source).hexdigest(),'sources':captured,'controller':cr,'entry_pack':pr}
(D/'report.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(pr),flush=True)
