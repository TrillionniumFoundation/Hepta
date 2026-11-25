"""Native packer grammar/transactional boundaries and mechanical provenance."""
from pathlib import Path
import argparse,ctypes as C,hashlib,importlib,json,struct,subprocess
from tools.qualify_hia_multiversion_components import Image
ROOT=Path(__file__).resolve().parents[1]
sha=lambda b:hashlib.sha256(b).hexdigest()
def main():
 p=argparse.ArgumentParser();p.add_argument('--directory',type=Path,required=True);p.add_argument('--kind',choices=('proof','build'),required=True);a=p.parse_args();D=a.directory;kind=a.kind
 m=importlib.import_module('tools.generate_hia_multiversion_prepare_'+kind+'_packer')
 record=json.loads((D/'build.json').read_text());parts=[Path(r['path']).read_bytes() for r in record['roles']]
 count=len(parts);magic=b'HIAMVFP1' if kind=='proof' else b'HIAMVBP1';head=16+8*count
 def packet(xs):return struct.pack('<8s'+str(len(xs)+1)+'Q',magic,len(xs),*map(len,xs))+b''.join(xs)
 packer=Image(D/('multiversion_prepare_'+kind+'_packer.flat'));linker=Image(record['linker']['path'])
 expected=m.reference_object(parts)
 def call(raw,cap=None,workcap=1<<20):
  cap=len(expected) if cap is None else cap
  o=C.create_string_buffer(max(1,cap));C.memset(o,0xa5,len(o));w=C.create_string_buffer(max(1,workcap))
  s=C.create_string_buffer(raw,max(1,len(raw)));r=packer.entry(s,len(raw),o,cap,w,workcap)
  assert s.raw==(raw or b'\0')
  return r,o.raw[:cap]
 base=packet(parts);rc,out=call(base);assert rc==len(expected) and out==expected
 linked=C.create_string_buffer(len(expected)+65536);w=C.create_string_buffer(1<<20)
 n=linker(out,linked,w);assert sha(linked.raw[:n])==record['image_sha256']
 rows=[{'case':'actual-native-ET_REL-and-shared-ELF','bytes':len(expected),'sha256':sha(expected),'image_sha256':sha(linked.raw[:n])}]
 for name,binary,holes in [('prepare_'+kind,m.OUTER,m.OUTER_HOLES),('prepare_process',m.proc.BRIDGE,m.proc.HOLES)]:
  source=ROOT/'tools'/('hia_multiversion_'+name+'_bridge.S');obj=D/(name+'-mechanical.o');raw=D/(name+'-mechanical.bin')
  subprocess.run(['/usr/bin/as','--64','--fatal-warnings','-o',str(obj),str(source)],check=True,capture_output=True)
  subprocess.run(['/usr/bin/objcopy','-O','binary','--only-section=.text',str(obj),str(raw)],check=True,capture_output=True)
  assert raw.read_bytes()==binary
  actual={}
  for line in subprocess.check_output(['/usr/bin/nm','-an',str(obj)],text=True).splitlines():
   xs=line.split()
   if len(xs)==3 and xs[2].endswith('_hole'):actual[xs[2][:-5]]=int(xs[0],16)
  assert actual==holes
  rows.append({'case':'actual-mechanical-'+name,'source_sha256':sha(source.read_bytes()),'bytes':len(binary),'sha256':sha(binary),'holes':actual})
 variants=[('magic',b'INVALID!'+base[8:]),('short-header',base[:head-1]),('truncated',base[:-1]),('tail',base+b' ')]
 for at in range(8,head,8):
  for value in ([0,count-1,count+1,2**64-1] if at==8 else [0,4194305,2**64-1]):
   raw=bytearray(base);struct.pack_into('<Q',raw,at,value);variants.append((str(at)+'-'+str(value),bytes(raw)))
 for label,raw in variants:
  rc,out=call(raw);assert rc>=0xfffffff0 and out==b'\xa5'*len(out),(label,rc);rows.append({'case':'refusal-'+label,'status':rc,'no_output_mutation':True})
 for cap in (0,63,len(expected)-1):
  rc,out=call(base,cap);assert rc==0xfffffffe and out==b'\xa5'*len(out);rows.append({'case':'short-output-'+str(cap),'status':rc})
 rc,out=call(base,workcap=327);assert rc==0xfffffffe and out==b'\xa5'*len(out);rows.append({'case':'workspace-327','status':rc})
 long=[parts[0]+bytes(4194304-len(parts[0]))]+parts[1:];long_expected=m.reference_object(long);rc,out=call(packet(long),len(long_expected));assert rc==len(long_expected) and out==long_expected;rows.append({'case':'actual-four-MiB-policy','bytes':len(out),'sha256':sha(out)})
 rc,out=call(packet([bytes(4194304)]*count));assert rc>=0xfffffff0 and out==b'\xa5'*len(out);rows.append({'case':'original-sixteen-MiB-text-budget','status':rc})
 report={'schema':'hepta.hia.multiversion-prepare-packaging.v1','kind':kind,'whole_native_runtime':False,'passed':len(rows),'failed':0,'packer':packer.pin,'cases':rows}
 (D/'packaging-qualification.json').write_text(json.dumps(report,indent=2)+'\n');print('PREPARE_PACK_PASS',kind,len(rows),flush=True)
if __name__=='__main__':main()
