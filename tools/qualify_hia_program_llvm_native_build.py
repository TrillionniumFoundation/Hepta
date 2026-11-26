"""Development-only reproducible construction of the native LLVM emitter.

The release consumes HIA sources and its fixed ABI bridge. Python is an author
and independent byte oracle, never a production input or runtime callback.
"""
from pathlib import Path
import argparse,ctypes as C,hashlib,importlib,json,mmap,struct,subprocess,sys,time,traceback
from tools import generate_hia_program_llvm_packer as spec
from tools.qualify_hia_publication_cancellation import Image,address
ROOT=Path(__file__).resolve().parents[1]
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def native_run(flat,wire):
 image=Image(flat);source=C.create_string_buffer(wire)
 with mmap.mmap(-1,32<<20)as output,mmap.mmap(-1,16<<20)as workspace:
  n=image.entry(source,len(wire),address(output),len(output),address(workspace),len(workspace))
  assert 0<n<len(output),hex(n)
  return bytes(output[:n])
def controls(flat,parts):
 image=Image(flat);rows=[]
 for mode in (0,1):
  wire=b'HIALLPK1'+struct.pack('<12Q',10,*map(len,parts),mode)+b''.join(parts)
  expected=spec.reference_object(parts)if mode==0 else spec.reference_flat(parts)
  bad=[('short-header',wire[:103]),('truncated-role',wire[:-1]),('trailing-byte',wire+b'x')]
  for name,offset,value in [('magic',0,0),('role-count-low',8,9),('role-count-high',8,11),('unknown-mode',96,2)]:
   changed=bytearray(wire);struct.pack_into('<Q',changed,offset,value);bad.append((name,bytes(changed)))
  for index,role in enumerate(spec.ROLES):
   for name,value in [('empty',0),('oversize',4194305)]:
    changed=bytearray(wire);struct.pack_into('<Q',changed,16+index*8,value);bad.append((name+'-'+role,bytes(changed)))
  with mmap.mmap(-1,32<<20)as output,mmap.mmap(-1,1<<20)as workspace:
   for name,raw in bad:
    source=C.create_string_buffer(raw);output[:128]=b'\xa5'*128
    rc=image.entry(source,len(raw),address(output),len(output),address(workspace),len(workspace))
    assert rc==0xffffffff and output[:128]==b'\xa5'*128,(mode,name,rc)
    rows.append(dict(mode=mode,name=name))
   source=C.create_string_buffer(wire)
   for name,outn,workn in [('short-output',len(expected)-1,len(workspace)),('short-workspace',len(output),511)]:
    output[:128]=b'\xa5'*128
    rc=image.entry(source,len(wire),address(output),outn,address(workspace),workn)
    assert rc==0xfffffffe and output[:128]==b'\xa5'*128,(mode,name,rc)
    rows.append(dict(mode=mode,name=name))
 return rows
def build(compiler,out):
 out.mkdir(mode=0o700);record=dict(schema='hepta.hia.program-llvm-native-construction.v2',passed=False,whole_llvm_qualified=False,whole_native_runtime_qualified=False,modules=[],products={},source_files={},development_sources={},commands=[])
 def save():(out/'build.json').write_text(json.dumps(record,indent=2)+'\n')
 def run(name,args,data=None):
  start=time.monotonic();r=subprocess.run(list(map(str,args)),input=data,capture_output=True,cwd=ROOT,timeout=30)
  (out/(name+'.stdout')).write_bytes(r.stdout);(out/(name+'.stderr')).write_bytes(r.stderr)
  record['commands'].append(dict(name=name,returncode=r.returncode,seconds=time.monotonic()-start,timeout_seconds=30));save()
  assert r.returncode==0,(name,r.returncode,r.stderr[-8000:]);return r.stdout
 try:
  assert pin(compiler.read_bytes())==dict(bytes=813129,sha256='494833999e25ac74ea6ad1de41235c01bfa036951f212604026cb8be686c78af')
  bridge=ROOT/'tools/hia_program_llvm_bridge.S'
  run('bridge.assemble',['/usr/bin/as','--64',bridge,'-o',out/'bridge.o'])
  run('bridge.text',['/usr/bin/objcopy','-O','binary','-j','.text',out/'bridge.o',out/'bridge.bin'])
  assert (out/'bridge.bin').read_bytes()==spec.BRIDGE
  symbols=run('bridge.symbols',['/usr/bin/nm','-n',out/'bridge.o']).decode()
  positions={r.split()[2]:int(r.split()[0],16)for r in symbols.splitlines()if len(r.split())==3}
  assert positions['hia_program_llvm']==0 and positions['hia_llvm_bridge_end']==len(spec.BRIDGE)
  assert spec.FIXUPS==tuple((r,positions['hia_llvm_'+r+'_hole'])for r in spec.ROLES)
  relocs=run('bridge.relocations',['/usr/bin/readelf','-rW',out/'bridge.o']).decode()
  assert 'R_X86_64_'not in relocs
  for role in ('scalar','memory','bulk','flow','module','analysis','vector','outline','owner','packer'):
   name='program_llvm_'+role
   for index in range(2):
    run(name+'.generate'+str(index),[sys.executable,'-m','tools.generate_hia_'+name])
    generated=(ROOT/'examples/hia_bootstrap'/(name+'.hepta')).read_bytes()
    decoded=(ROOT/'examples/hia_bootstrap/program_llvm_decode.hepta').read_bytes()if role=='owner'else None
    if index==0:first=generated;first_decode=decoded
    else:assert first==generated and first_decode==decoded
  flats={}
  for name in ['program_llvm_'+r for r in spec.ROLES]+['program_llvm_packer','multiversion_runtime_linker']:
   rel='examples/hia_bootstrap/'+name+'.hepta';raw=(ROOT/rel).read_bytes()
   a=run(name+'.compile1',[compiler,'compile'],raw);b=run(name+'.compile2',[compiler,'compile'],raw)
   assert a and a==b;flats[name]=a;(out/(name+'.flat')).write_bytes(a)
   record['modules'].append(dict(name=name,source=pin(raw),flat=pin(a),double_compile=True));record['source_files'][rel]=pin(raw)
   print('LLVM_REPRODUCIBLE_COMPILE',name,len(a),flush=True)
  parts=[flats['program_llvm_'+r]for r in spec.ROLES]
  for mode,name in [(0,'program-llvm.o'),(1,'program-llvm.flat')]:
   frame=b'HIALLPK1'+struct.pack('<12Q',10,*map(len,parts),mode)+b''.join(parts)
   raw=native_run(flats['program_llvm_packer'],frame)
   assert raw==(spec.reference_object(parts)if mode==0 else spec.reference_flat(parts))
   (out/name).write_bytes(raw);record['products'][name]=pin(raw)
  so=native_run(flats['multiversion_runtime_linker'],(out/'program-llvm.o').read_bytes())
  assert so[:4]==b'\x7fELF';(out/'program-llvm.so').write_bytes(so);record['products']['program-llvm.so']=pin(so)
  record['packer_controls']=controls(flats['program_llvm_packer'],parts)
  record['source_files']['tools/hia_program_llvm_bridge.S']=pin(bridge.read_bytes())
  for path in sorted(ROOT.glob('tools/*program_llvm*.py')):record['development_sources'][str(path.relative_to(ROOT))]=pin(path.read_bytes())
  for rel,pinned in record['source_files'].items():assert pin((ROOT/rel).read_bytes())==pinned
  record.update(passed=True,native_construction_qualified=True,mechanical_bridge_exact=True,native_pack_reference_equal=True,native_shared_link=True,platform_imports=[],role_limit_bytes=4194304,text_limit_bytes=16777216)
  print('LLVM_REPRODUCIBLE_BUILD_PASS',json.dumps(record['products']),len(record['packer_controls']),flush=True)
 except BaseException as error:record['error']=repr(error);record['traceback']=traceback.format_exc();raise
 finally:save()
def main():
 p=argparse.ArgumentParser();p.add_argument('--compiler',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();build(a.compiler,a.output)
if __name__=='__main__':main()
