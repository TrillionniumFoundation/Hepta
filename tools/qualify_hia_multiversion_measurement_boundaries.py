"""Actual measurement policy continuation checks; no synthetic success in production."""
from pathlib import Path
import argparse,ctypes as C,hashlib,json,struct
from tools.qualify_hia_multiversion_components import Image
from tools.qualify_hia_multiversion_measurement_owner import frame
from tests.test_hia_publication_measurement_native import measurement
def get(b,at):return struct.unpack_from('<Q',b,at)[0]
def put(b,at,x):struct.pack_into('<Q',b,at,x)
def main():
 p=argparse.ArgumentParser();p.add_argument('--directory',type=Path,required=True);a=p.parse_args();D=a.directory
 build=json.loads((D/'owner-build.json').read_text());parts={r['role']:Path(r['path']) for r in build['roles']}
 owner=Image(parts['owner']);numeric=Image(parts['measurement']);digest=Image(parts['hash'])
 raw=frame(measurement(),17);rows=[]
 def start():
  s=C.create_string_buffer(raw,len(raw));o=C.create_string_buffer(32768);w=C.create_string_buffer(131072)
  r=owner.entry(s,len(raw),o,len(o),w,len(w));assert r==1
  q=[get(o,i*8) for i in range(6)];r=numeric.entry(C.byref(w,q[0]),q[1],C.byref(w,q[2]),q[3],C.byref(w,q[4]),q[5]);assert r==176;put(w,4104,r)
  return s,o,w
 def run(name,changes,expect=0xfffffffd,hashphase=False):
  s,o,w=start()
  if hashphase:
   assert owner.entry(s,len(raw),o,len(o),w,len(w))==2
   q=[get(o,i*8) for i in range(6)];r=digest.entry(C.byref(w,q[0]),q[1],C.byref(w,q[2]),q[3],C.byref(w,q[4]),q[5]);assert r==32;put(w,4104,r)
  for at,v in changes:put(w,at,v)
  result=owner.entry(s,len(raw),o,len(o),w,len(w));assert result==expect,(name,result,expect)
  assert s.raw==raw
  rows.append({'case':name,'changes':changes,'returncode':result})
 for value in (0,175,177,0xffffffff,176+(1<<32)):run('numeric-return-'+str(value),[(4104,value)])
 for at,value,label in [(64064,0,'magic'),(64072,2,'status'),(64080,128,'mask'),(64088,16,'samples'),(64216,2,'calls'),(64224,2,'horizon'),(64232,0,'eligibility'),(64208,2,'changed'),(64144,2,'observed-sign'),(64168,2,'charged-sign'),(32,11,'preparation-range')]:
  run('numeric-'+label,[(at,value)])
 run('finite-policy-refusal',[(64072,1)],0)
 run('unknown-phase',[(4096,99)])
 for value in (0,31,33,0xffffffff,32+(1<<32)):run('hash-return-'+str(value),[(4104,value)],hashphase=True)
 # Same actual three kernels through the public fixed wrapper versus individual
 # continuation calls prove the dispatch is neither omitted nor reordered.
 s,o,w=start();assert owner.entry(s,len(raw),o,len(o),w,len(w))==2
 q=[get(o,i*8) for i in range(6)];r=digest.entry(C.byref(w,q[0]),q[1],C.byref(w,q[2]),q[3],C.byref(w,q[4]),q[5]);put(w,4104,r)
 assert owner.entry(s,len(raw),o,len(o),w,len(w))==0
 from tools.qualify_hia_multiversion_measurement_owner import Native
 rc,whole=Native(D).run(raw);assert rc==0
 n=128+get(o,24)+get(o,32);assert whole[:n]==o.raw[:n];rows.append({'case':'all-three-actual-roles-fixed-wrapper-byte-identical','bytes':n})
 result={'schema':'hepta.hia.multiversion-measurement-owner-boundaries.v1','whole_native_runtime':False,'passed':len(rows),'failed':0,'image_sha256':build['image_sha256'],'cases':rows}
 (D/'owner-boundary-qualification.json').write_text(json.dumps(result,indent=2)+'\n');print('MEASUREMENT_OWNER_BOUNDARIES_PASS',len(rows),flush=True)
if __name__=='__main__':main()
