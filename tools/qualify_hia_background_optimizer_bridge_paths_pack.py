from pathlib import Path
import argparse,ctypes as C,hashlib,json,struct,subprocess,tempfile
from tools.qualify_hia_multiversion_components import Image
from tools.generate_hia_background_optimizer_bridge_paths_packer import reference_object,BRIDGE,HOLES
def main():
 p=argparse.ArgumentParser();p.add_argument('--directory',type=Path,required=True);p.add_argument('--source',type=Path,required=True);p.add_argument('--policy',type=Path,required=True);a=p.parse_args();D=a.directory
 image=Image(D/'packer.flat');flat=a.policy.read_bytes();raw=struct.pack('<8sQQ',b'HIABBPP1',1,len(flat))+flat;expected=reference_object([flat]);w=C.create_string_buffer(1<<20);rows=[]
 def call(name,wire,on,valid):
  s=C.create_string_buffer(wire);out=C.create_string_buffer(on);C.memset(out,0xa5,len(out));before=out.raw
  rc=image(wire,out,w)
  if valid:assert rc==len(expected) and out.raw[:rc]==expected,(name,rc,len(expected))
  else:assert rc>=0xfffffff0 and out.raw==before,(name,rc)
  rows.append({'name':name,'returncode':rc,'passed':True})
 call('exact-object',raw,len(expected),True)
 for n in (0,1,7,8,15,16,23,24,len(raw)-1):call('truncated-'+str(n),raw[:n],len(expected),False)
 for at,value in ((0,0),(8,0),(8,2),(8,(1<<64)-1),(16,0),(16,len(flat)-1),(16,len(flat)+1),(16,(1<<64)-1)):
  x=bytearray(raw);struct.pack_into('<Q',x,at,value);call('word-'+str(at)+'-'+str(value),bytes(x),len(expected),False)
 call('extra-byte',raw+b'x',len(expected),False)
 for n in (0,1,63,len(expected)-1):call('short-output-'+str(n),raw,n,False)
 src=a.source/'tools/hia_background_optimizer_bridge_paths_bridge.S'
 with tempfile.TemporaryDirectory(prefix='bg-mechanical-') as tmp:
  t=Path(tmp);subprocess.run(['as','--64','-o',str(t/'bridge.o'),str(src)],check=True);subprocess.run(['objcopy','-O','binary','--only-section=.text',str(t/'bridge.o'),str(t/'bridge.bin')],check=True)
  actual=(t/'bridge.bin').read_bytes();assert actual==BRIDGE;rows.append({'name':'readable-mechanical-source-full-prefix','bytes':len(actual),'passed':True})
 assert expected[:64]==(D/'component.o').read_bytes()[:64] and expected==(D/'component.o').read_bytes()
 report={'schema':'hepta.hia.background-bridge-paths-pack.qualification.v1','whole_native_runtime':False,'passed':len(rows),'failed':0,'cases':rows,'native_packer_sha256':hashlib.sha256((D/'packer.flat').read_bytes()).hexdigest(),'object_sha256':hashlib.sha256(expected).hexdigest(),'source_sha256':hashlib.sha256(src.read_bytes()).hexdigest(),'mechanical_assembly_used_only_as_external_source_provenance_check':True}
 (D/'packer-qualification.json').write_text(json.dumps(report,indent=2)+'\n');print('BG_BRIDGE_PATHS_PACK_QUALIFIED',len(rows),flush=True)
if __name__=='__main__':main()
