"""Development-only reproducible build of the native capture component.

Production inputs are HIA sources and the fixed mechanical bridge. Python only
authors/checks sources, runs the retained compiler and compares ELF bytes.
"""
from pathlib import Path
import argparse,hashlib,importlib,json,os,struct,subprocess,sys,time,traceback
from tools import qualify_hia_generation_lease_owner as owner
from tools import generate_hia_clang_capture_packer as spec
ROOT=Path(__file__).resolve().parents[1]
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def build(compiler,out):
 out.mkdir(mode=0o700);record=dict(schema='hepta.hia.clang-capture-native-construction.v2',passed=False,whole_capture_qualified=False,modules=[],products={},source_files={},development_sources={},commands=[])
 def save():(out/'build.json').write_text(json.dumps(record,indent=2)+'\n')
 def run(name,args,data=None):
  start=time.monotonic();r=subprocess.run(list(map(str,args)),input=data,capture_output=True,cwd=ROOT,timeout=30)
  (out/(name+'.stdout')).write_bytes(r.stdout);(out/(name+'.stderr')).write_bytes(r.stderr)
  record['commands'].append(dict(name=name,returncode=r.returncode,seconds=time.monotonic()-start,timeout_seconds=30));save()
  assert r.returncode==0,(name,r.returncode,r.stderr[-8000:]);return r.stdout
 try:
  assert pin(compiler.read_bytes())==dict(bytes=813129,sha256='494833999e25ac74ea6ad1de41235c01bfa036951f212604026cb8be686c78af')
  bridge=ROOT/'tools/hia_clang_capture_bridge.S'
  run('bridge.assemble',['/usr/bin/as','--64',bridge,'-o',out/'bridge.o'])
  run('bridge.text',['/usr/bin/objcopy','-O','binary','-j','.text',out/'bridge.o',out/'bridge.bin'])
  assert (out/'bridge.bin').read_bytes()==spec.BRIDGE
  symbols=run('bridge.symbols',['/usr/bin/nm','-n',out/'bridge.o']).decode()
  positions={r.split()[2]:int(r.split()[0],16)for r in symbols.splitlines()if len(r.split())==3}
  assert positions['hia_clang_capture']==0 and positions['hia_clang_capture_bridge_end']==len(spec.BRIDGE)
  assert spec.FIXUPS==tuple((r,positions['clang_capture_'+r+'_hole'])for r in spec.ROLES)
  relocs=run('bridge.relocations',['/usr/bin/readelf','-rW',out/'bridge.o']).decode()
  rows=[r.split()for r in relocs.splitlines()if 'R_X86_64_'in r]
  assert len(rows)==1 and int(rows[0][0],16)==spec.DLSYM_AT and rows[0][2]=='R_X86_64_PLT32' and rows[0][4:]==['dlsym','-','4']
  names=['clang_capture_'+r for r in spec.ROLES]+['clang_capture_packer']
  for name in names:
   for i in range(2):
    run(name+'.generate'+str(i),[sys.executable,'-m','tools.generate_hia_'+name])
    raw=(ROOT/'examples/hia_bootstrap'/(name+'.hepta')).read_bytes()
    if i==0:first=raw
    else:assert first==raw
  flats={}
  for name in names+['multiversion_runtime_linker']:
   rel='examples/hia_bootstrap/'+name+'.hepta';raw=(ROOT/rel).read_bytes()
   a=run(name+'.compile1',[compiler,'compile'],raw);b=run(name+'.compile2',[compiler,'compile'],raw)
   assert a and a==b;flats[name]=a;(out/(name+'.flat')).write_bytes(a)
   record['modules'].append(dict(name=name,source=pin(raw),flat=pin(a),double_compile=True));record['source_files'][rel]=pin(raw)
  parts=[flats['clang_capture_'+r]for r in spec.ROLES]
  frame=b'HIACCPK1'+struct.pack('<6Q',5,*map(len,parts))+b''.join(parts)
  obj=owner.old.run_packer(flats['clang_capture_packer'],frame);assert obj==spec.reference_object(parts)
  so=owner.old.run_packer(flats['multiversion_runtime_linker'],obj)
  assert so[:4]==b'\x7fELF'
  for name,raw in [('clang-capture.o',obj),('clang-capture.so',so)]:
   (out/name).write_bytes(raw);record['products'][name]=pin(raw)
  record['source_files']['tools/hia_clang_capture_bridge.S']=pin(bridge.read_bytes())
  for path in sorted(ROOT.glob('tools/*clang_capture*.py')):record['development_sources'][str(path.relative_to(ROOT))]=pin(path.read_bytes())
  for rel,pinned in record['source_files'].items():assert pin((ROOT/rel).read_bytes())==pinned
  record.update(passed=True,native_construction_qualified=True,mechanical_bridge_exact=True,native_pack_reference_equal=True,platform_imports=['dlsym'],role_limit_bytes=4194304,text_limit_bytes=16777216)
  print('CAPTURE_REPRODUCIBLE_BUILD_PASS',json.dumps(record['products']),flush=True)
 except BaseException as error:record['error']=repr(error);record['traceback']=traceback.format_exc();raise
 finally:save()
def main():
 p=argparse.ArgumentParser();p.add_argument('--compiler',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();build(a.compiler,a.output)
if __name__=='__main__':main()
