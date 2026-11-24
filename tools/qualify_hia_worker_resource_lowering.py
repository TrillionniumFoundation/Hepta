"""Compare native URI lowering with the original compiled public Read plan.

This qualification executes sealed-input ELF processes. It compares every
lowered plan byte, verifies public Read remains unchanged, and exercises
malformed inputs. It does not qualify a complete cold or ordinary release.
"""
from pathlib import Path
from hashlib import sha256
import argparse
import ctypes
import fcntl
import hashlib
import json
import mmap
import os
import struct
import subprocess
import sys
import traceback

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.generate_hia_mcp_stdio_packer import MAGIC, MODES

def run(exe,payload,good=True):
 fd=os.memfd_create('read-request-qualification',os.MFD_ALLOW_SEALING|os.MFD_CLOEXEC)
 os.write(fd,payload);os.fchmod(fd,0o400);fcntl.fcntl(fd,fcntl.F_ADD_SEALS,15);os.lseek(fd,0,0)
 try:p=subprocess.run([str(exe)],stdin=fd,capture_output=True,timeout=20,env={'PATH':''})
 finally:os.close(fd)
 if good: assert p.returncode==0 and not p.stderr,(exe.name,p.returncode,p.stderr,len(p.stdout))
 else: assert p.returncode!=0 and not p.stdout,(exe.name,p.returncode,len(p.stdout))
 return p.stdout
def wire(x):return json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()

def main():
 parser=argparse.ArgumentParser(description=__doc__)
 for name in ('source-build','reference-source','packer-flat','request','output'):
  parser.add_argument('--'+name,type=Path,required=True)
 args=parser.parse_args()
 D=args.output;D.mkdir(mode=0o700,exist_ok=False)
 SEED=args.source_build
 inputs={str(p):sha256(p.read_bytes()).hexdigest() for p in
         (args.source_build,args.reference_source,args.packer_flat,args.request)}
 report={'scope':'resource lowering versus original Read plan, actual standalone ELF',
         'status':'running','cases':[],'inputs':inputs,'whole_release_qualified':False}
 try:
  source=args.reference_source
  r=subprocess.run([str(SEED),'compile'],input=source.read_bytes(),capture_output=True,timeout=120);assert r.returncode==0
  pack=args.packer_flat.read_bytes();mm=mmap.mmap(-1,len(pack),prot=7);mm.write(pack)
  f=ctypes.CFUNCTYPE(ctypes.c_uint32,ctypes.c_void_p,ctypes.c_size_t,ctypes.c_void_p,ctypes.c_size_t,ctypes.c_void_p,ctypes.c_size_t)(ctypes.addressof(ctypes.c_ubyte.from_buffer(mm)))
  request=struct.pack('<2Q',MAGIC,MODES['read-request'])+r.stdout;inp=ctypes.create_string_buffer(request);out=ctypes.create_string_buffer((1<<20)+4096)
  n=f(inp,len(request),out,len(out),None,0);assert 64<=n<len(out)
  old=D/'reference-read-request';old.write_bytes(out.raw[:n]);old.chmod(0o500)
  report.update(original_source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),original_elf_sha256=hashlib.sha256(old.read_bytes()).hexdigest(),new_elf_sha256=hashlib.sha256(args.request.read_bytes()).hexdigest())
  cat='b6b8054ce46ae9ceac260e99a3d1beaf5d6c9343bc4c6e5d96281eedd3c3edfd'
  refs=[{'id':'a','sha256':'a'*64,'uri':'hia://artifacts/a'},
        {'id':'a/b:c-._9','sha256':'0123456789abcdef'*4,'uri':'hia://artifacts/a-._~9'},
        {'id':'Z'*192,'sha256':'f'*64,'uri':'hia://artifacts/'+'Z'*192}]
  native=args.request
  for i,ref in enumerate(refs):
   for limit in [None,512,513,1024,65535,65536]:
    args={'uri':ref['uri']}
    if limit is not None:args['max_bytes']=limit
    admitted={'arguments':args,'catalog_sha256':cat,'profile_sha256':'a'*64,'schema':'hia-agent-worker-request-v1','tool':'hia_resource_read'}
    plan=run(native,wire(admitted));head=struct.unpack_from('<8s7Q',plan)
    expected_limit=65536 if limit is None else limit
    assert head[0]==b'HIAARD01' and head[1:4]==(5,expected_limit,0) and head[5]==0 and head[7]==len(plan),head
    identity=ref['id'].encode();bound=run(native,struct.pack('<8s5Q',b'HIAURB01',len(plan),len(identity),64,0,0)+plan+identity+ref['sha256'].encode())
    normal_args={'catalog_sha256':cat,'artifact':ref,'max_bytes':expected_limit}
    expected=run(old,wire(normal_args));assert bound==expected,(i,limit,len(bound),len(expected))
    converted=run(native,b'HIAURJ01'+bound);size,=struct.unpack_from('<Q',converted)
    assert size==len(converted)-8 and json.loads(converted[8:])==normal_args
    assert run(native,wire(normal_args))==expected
    report['cases'].append({'ref':i,'max_bytes':limit,'exact_original_plan':True,'lowered_arguments_exact':True})
  for label,mutate in [
   ('unknown-argument',lambda x:x['arguments'].update(extra=1)),
   ('wrong-tool',lambda x:x.update(tool='hia_resource_read_extra')),
   ('bad-uri',lambda x:x['arguments'].update(uri='file:///etc/passwd')),
   ('uri-too-long',lambda x:x['arguments'].update(uri='hia://artifacts/'+'a'*193)),
   ('bool-max',lambda x:x['arguments'].update(max_bytes=True)),
   ('small-max',lambda x:x['arguments'].update(max_bytes=511)),
   ('large-max',lambda x:x['arguments'].update(max_bytes=65537)),
   ('unknown-envelope',lambda x:x.update(extra=1)),
   ('bad-catalog',lambda x:x.update(catalog_sha256='x'*64)),
  ]:
   value={'arguments':{'uri':'hia://artifacts/a'},'catalog_sha256':cat,'profile_sha256':'a'*64,'schema':'hia-agent-worker-request-v1','tool':'hia_resource_read'}
   mutate(value);run(native,wire(value),good=False);report['cases'].append({'refusal':label,'passed':True})
  assert all(sha256(Path(name).read_bytes()).hexdigest()==pin for name,pin in inputs.items())
  report['status']='passed'
 except BaseException:
  report['status']='failed';report['failure']=traceback.format_exc();raise
 finally:
  (D/'qualification.json').write_text(json.dumps(report,indent=2))
  print(json.dumps({'status':report['status'],'cases':len(report['cases']),'failure':report.get('failure')}),flush=True)


if __name__=='__main__':
 main()
