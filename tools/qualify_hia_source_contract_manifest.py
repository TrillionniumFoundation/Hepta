"""External qualification for the native manifest converter and metadata template."""
from pathlib import Path
from hashlib import sha256
import argparse,copy,ctypes,json,mmap,os,struct,subprocess,time,traceback

MAX=8<<20;U64=(1<<64)-1

def sxm(rows):
 return b'HIASXM01'+struct.pack('<3Q',len(rows),1,0)+b''.join(struct.pack('<2Q',len(path),size)+pin+path for path,size,pin in rows)
def spi(rows):
 return b'HIASPI01'+struct.pack('<Q',len(rows))+b''.join(struct.pack('<Q',len(path))+pin+path for path,size,pin in rows)
def record(name,size=0):
 raw=name.encode() if isinstance(name,str) else name
 return raw,size,sha256(raw).digest()
def path_of_size(index,size):
 pieces=[];remaining=size
 while remaining>255:pieces.append(b'x'*255);remaining-=256
 assert 1<=remaining<=255
 pieces.append(b'x'*remaining);raw=b'/'.join(pieces)
 raw=f'{index:04x}'.encode()+raw[4:]
 assert len(raw)==size
 return raw

def main():
 ap=argparse.ArgumentParser();ap.add_argument('--source',type=Path,required=True);ap.add_argument('--products',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args();a.output.mkdir(mode=0o700)
 source=a.source;d=a.products;out=a.output;converter=d/'hia-source-contract-manifest';producer=d/'hia-source-contract';flat=(d/'source_contract_manifest.flat').read_bytes()
 report={'passed':False,'scope':'Source-manifest projection and current native metadata; no product activation and no claim that projection rehashes physical files','products':{p.name:{'path':str(p),'sha256':sha256(p.read_bytes()).hexdigest()} for p in (converter,producer)},'cases':[]}
 def save():(out/'qualification.json').write_text(json.dumps(report,indent=2)+'\n')
 def run(name,raw,expected=None,exe=converter):
  t=time.monotonic_ns();r=subprocess.run([str(exe)],input=raw,capture_output=True,env={'PATH':''},timeout=30)
  row={'case':name,'input_bytes':len(raw),'input_sha256':sha256(raw).hexdigest(),'returncode':r.returncode,'stdout_bytes':len(r.stdout),'stdout_sha256':sha256(r.stdout).hexdigest(),'stderr_hex':r.stderr.hex(),'elapsed_ns':time.monotonic_ns()-t,'passed':False};report['cases'].append(row)
  if expected is None:assert r.returncode!=0 and not r.stdout and not r.stderr,(name,r.returncode,r.stdout[:100],r.stderr)
  else:assert r.returncode==0 and not r.stderr and r.stdout==expected,(name,r.returncode,len(r.stdout),len(expected),r.stderr)
  row['passed']=True;return r.stdout
 try:
  valid=[('one-empty-file',[record('a.hepta')]),('actual-file-upper-bound',[record('a.hepta',67108864)]),('sorted-cases',[record('A'),record('A.a'),record('a'),record('z/z')]),('component-255',[record('a'*255)]),('path-4095',[record(path_of_size(1,4095))]),('count-4096',[record(f'{i:04x}.hepta',i) for i in range(4096)])]
  for name,rows in valid:run(name,sxm(rows),spi(rows))
  rows=[record(path_of_size(i,2000 if i<4095 else 1968),i) for i in range(4096)];large=sxm(rows);assert len(large)==MAX;run('exact-eight-MiB-input',large,spi(rows));too=list(rows);p,z,h=too[-1];too[-1]=(p+b'x',z,h);run('eight-MiB-plus-one',sxm(too))
  base=sxm([record('alpha.hepta',17),record('zeta.hepta',31)])
  for n in range(len(base)):run(f'truncated-{n}',base[:n])
  for position,values in [(8,(0,4097,U64)),(16,(0,2,U64)),(24,(1,U64)),(32,(0,4096,U64)),(40,(67108865,U64))]:
   for value in values:
    raw=bytearray(base);struct.pack_into('<Q',raw,position,value);run(f'field-{position}-{value}',bytes(raw))
  for name,raw in [('bad-magic',b'BADMAGIC'+base[8:]),('tail',base+b'x'),('zero-digest',base[:48]+bytes(32)+base[80:]),('duplicate',sxm([record('a'),record('a')])),('reverse',sxm([record('b'),record('a')]))]:run(name,raw)
  for name in (b'',b'/a',b'a/',b'a//b',b'.',b'..',b'.git',b'__pycache__',b'a/.',b'a/..',b'a/.git/b',b'a/__pycache__/b',b'a'*256,b'a b',b'a\\b',b'a"b',b'a\x00b',b'a\nb',b'a\x7fb',b'a\xffb'):
   run('invalid-path-'+name.hex(),sxm([record(name)]))
  # Every nonreserved printable byte is checked at a path position against the
  # source-contract ASCII alphabet. Physical capture restrictions are explicit.
  allowed=set(b'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._')
  for ch in range(256):
   row=record(b'a'+bytes([ch])+b'z')
   run(f'path-byte-{ch}',sxm([row]),spi([row]) if ch in allowed or ch==47 else None)
  # Native six-word ABI: no partially committed output on refused input or a
  # short output extent. The wrapper itself always supplies distinct views.
  image=mmap.mmap(-1,len(flat),prot=mmap.PROT_READ|mmap.PROT_WRITE|mmap.PROT_EXEC);image.write(flat)
  addr=ctypes.addressof(ctypes.c_char.from_buffer(image));fn=ctypes.CFUNCTYPE(ctypes.c_uint32,ctypes.c_void_p,ctypes.c_uint64,ctypes.c_void_p,ctypes.c_uint64,ctypes.c_void_p,ctypes.c_uint64)(addr)
  expected=spi([record('alpha.hepta',17),record('zeta.hepta',31)]);buf=ctypes.create_string_buffer(base);abi=0
  for cap in range(len(expected)):
   target=ctypes.create_string_buffer(bytes([165])*(len(expected)+32));work=ctypes.create_string_buffer(bytes([77])*32)
   r=fn(ctypes.addressof(buf),len(base),ctypes.addressof(target)+16,cap,ctypes.addressof(work),32)
   assert r==0xfffffffe and target.raw[:-1]==bytes([165])*(len(expected)+32) and work.raw[:-1]==bytes([77])*32,(cap,r)
   abi+=1
  for raw in (b'',base[:-1],base+b'x',b'BADMAGIC'+base[8:]):
   ib=ctypes.create_string_buffer(raw);target=ctypes.create_string_buffer(bytes([165])*256)
   r=fn(ctypes.addressof(ib),len(raw),ctypes.addressof(target)+16,224,0,0);assert r>=0xfffffff0 and target.raw[:-1]==bytes([165])*256;abi+=1
  for n in (MAX+1,U64):
   target=ctypes.create_string_buffer(bytes([165])*256);r=fn(0,n,ctypes.addressof(target)+16,224,0,0);assert r==0xffffffff and target.raw[:-1]==bytes([165])*256;abi+=1
  target=ctypes.create_string_buffer(bytes([165])*(len(expected)+32));r=fn(ctypes.addressof(buf),len(base),ctypes.addressof(target)+16,len(expected),0,0)
  assert r==len(expected) and target.raw[16:16+r]==expected and target.raw[:16]==bytes([165])*16 and target.raw[16+r:-1]==bytes([165])*16;abi+=1
  report['native_flat_ABI_no_partial_output_cases']=abi
  # Current actual file capture: all rows are derived from existing, stable
  # files and byte hashes, never a fabricated digest for a missing final source.
  names=['docs/HIA_SELFHOST_CORE_SUPPORT.json','docs/HIA_NATIVE_SELFHOST_METADATA.json','docs/HIA_HISTORICAL_QUALIFICATION_PROVENANCE.json','docs/HIA_NATIVE_SELFHOST_METADATA_MIGRATION.json','examples/hia_bootstrap/source_contract_manifest.hepta','examples/hia_bootstrap/source_contract_generate.hepta','examples/hia_bootstrap/seed_backend.hepta']
  captured=[]
  for rel in sorted(names):
   p=source/rel;s0=p.stat();raw=p.read_bytes();s1=p.stat();assert (s0.st_size,s0.st_mtime_ns,s0.st_ctime_ns)==(s1.st_size,s1.st_mtime_ns,s1.st_ctime_ns);captured.append((rel.encode(),len(raw),sha256(raw).digest()))
  inventory=run('actual-captured-files',sxm(captured),spi(captured));metadata=(source/'docs/HIA_NATIVE_SELFHOST_METADATA.json').read_bytes();needle=b'"files": {}';assert metadata.count(needle)==1
  mapping={p.decode():h.hex() for p,n,h in captured if p!=b'docs/HIA_SELFHOST_CORE_SUPPORT.json'}
  expected_json=metadata.replace(needle,b'"files": '+json.dumps(mapping,sort_keys=True,separators=(',',':')).encode())
  packet=b'HIASCG01'+struct.pack('<3Q',len(metadata),len(inventory),0)+metadata+inventory
  first=run('native-template-contract-projection',packet,expected_json,producer);(out/'actual-native-contract.json').write_bytes(first)
  # The generated self member is a real existing file for this second capture;
  # its digest changes but is excluded by the original native contract rule.
  frozen=[]
  for p,n,h in captured:
   if p==b'docs/HIA_SELFHOST_CORE_SUPPORT.json':frozen.append((p,len(first),sha256((out/'actual-native-contract.json').read_bytes()).digest()))
   else:frozen.append((p,n,h))
  frozen_inventory=run('actual-frozen-self-capture',sxm(frozen),spi(frozen));packet=b'HIASCG01'+struct.pack('<3Q',len(metadata),len(frozen_inventory),0)+metadata+frozen_inventory
  second=run('strict-frozen-generated-contract-byte-equality',packet,first,producer);assert second==first
  without=[x for x in frozen if x[0]!=b'docs/HIA_SELFHOST_CORE_SUPPORT.json'];inv=run('missing-self-converter-only',sxm(without),spi(without));packet=b'HIASCG01'+struct.pack('<3Q',len(metadata),len(inv),0)+metadata+inv;run('producer-missing-self-refusal',packet,None,producer)
  report['actual_captured_sources']=[{'path':p.decode(),'bytes':n,'sha256':h.hex()} for p,n,h in captured];report['generated_contract_sha256']=sha256(first).hexdigest();report['frozen_self_recapture_is_real_file']=True;report['independent_expected_projection']='literal field projection and canonical map over fresh actual file bytes';report['physical_file_custody_not_delegated_to_converter']=True
  original=json.loads((source/'docs/HIA_SELFHOST_CORE_SUPPORT.json').read_bytes());current=json.loads(metadata);migration=json.loads((source/'docs/HIA_NATIVE_SELFHOST_METADATA_MIGRATION.json').read_bytes());provenance=json.loads((source/'docs/HIA_HISTORICAL_QUALIFICATION_PROVENANCE.json').read_bytes())
  def leaves(v,p=()):
   if isinstance(v,dict):
    for k,x in v.items():yield from leaves(x,p+(k,))
   elif isinstance(v,list):
    for i,x in enumerate(v):yield from leaves(x,p+(i,))
   else:yield p,v
  current_leaves=dict(leaves(current));numbers=booleans=0
  for p,v in leaves(original):
   if type(v) is bool:assert p in current_leaves and current_leaves[p] is v,p;booleans+=1
   elif type(v) in (int,float):assert p in current_leaves and type(current_leaves[p]) is type(v) and current_leaves[p]==v,p;numbers+=1
  for key in ('limits','abi','support','syntax','profile','compiler_symbols','capacity_derivation'):assert original[key]==current[key],key
  for key in ('fixed_point','generation_order','modified_fixed_point','modified_order','source_modification'):assert original['required_replay'][key]==current['required_replay'][key],key
  assert numbers==migration['original_numeric_leaves_preserved']==346 and booleans==migration['original_boolean_leaves_preserved']==427
  assert migration['production_bindings_replaced']==26 and migration['source_identity_roles_migrated']==6 and migration['historical_qualification_references_moved']==30
  assert migration['whole_native_qualification_claimed'] is False
  assert provenance['original_qualification_references']==30 and all(x['live_dependency'] is False for x in provenance['records'])
  assert sha256((source/'docs/HIA_SELFHOST_CORE_SUPPORT.json').read_bytes()).hexdigest()==migration['source_contract_sha256']==provenance['base_contract_sha256']
  assert not any(isinstance(v,str) and any(t in v for t in ('.py','.pyi','.rs','rust/')) for p,v in leaves(current))
  report['metadata_migration']={'numeric_leaves_preserved':numbers,'boolean_leaves_preserved':booleans,'production_bindings':26,'identity_roles':6,'historical_qualification_paths':30,'budgets_and_fixed_point_unchanged':True,'whole_native_claimed':False}
  report['passed']=True;report['case_count']=len(report['cases']);save();print('CONTRACT_QUALIFICATION_PASS',report['case_count'],abi,report['generated_contract_sha256'],flush=True)
 except BaseException:
  report['error']=traceback.format_exc();save();print(report['error'],flush=True);raise
if __name__=='__main__':main()
