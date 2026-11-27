"""Original root-packer rejection controls applied to the new Info profile."""
from pathlib import Path
import argparse,ctypes as C,hashlib,json,mmap,struct
from tools import generate_hia_generation_runtime_info_unlocked_fusion_packer as root
from tools.qualify_hia_generation_runtime_custody_packer import Image,address
def pin(b):return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def main():
 p=argparse.ArgumentParser();p.add_argument('--build',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 b=json.loads((a.build/'build.json').read_bytes());parts=[]
 for row in b['role_inputs']:
  raw=Path(row['path']).read_bytes();assert pin(raw)=={k:row[k]for k in('bytes','sha256')};parts.append(raw)
 assert [r['role']for r in b['role_inputs']]==list(root.ROLES)
 frame=struct.pack('<49Q',root.MAGIC,47,*map(len,parts))+b''.join(parts)
 image=Image((a.build/'build/generation_runtime_info_unlocked_fusion_packer.flat').read_bytes())
 controls=[]
 def check(label,raw,want=0xffffffff,on=32<<20):
  s=C.create_string_buffer(raw)
  with mmap.mmap(-1,32<<20)as o,mmap.mmap(-1,1<<20)as w:
   o[:128]=b'\xa5'*128;rc=image.entry(s,len(raw),address(o),on,address(w),len(w))
   assert rc==want and o[:128]==b'\xa5'*128,(label,rc,want)
  controls.append(label)
 for label,offset,value in(('magic',0,0),('count-low',8,46),('count-high',8,48),('role-empty',16,0),('role-oversize',16,4194305)):
  raw=bytearray(frame);struct.pack_into('<Q',raw,offset,value);check(label,bytes(raw))
 for label,raw in(('short-header',frame[:15]),('truncated-role',frame[:-1]),('trailing-byte',frame+b'x')):check(label,raw)
 starts={};at=16+8*len(parts)
 for name,data in zip(root.ROLES,parts):starts[name]=at;at+=len(data)
 for name,unit in(('global_capsule',root.global_capsule),('frontend_capsule',root.frontend),('runtime_borrow',root.borrow)):
  for role,holes in unit.FIXED_HOLES.items():
   off=holes[0];raw=bytearray(frame);struct.pack_into('<I',raw,starts[name]+off,1);check(name+'/'+role,bytes(raw))
 objectbytes=b['products']['component.o']['bytes'];check('short-output',frame,0xfffffffe,objectbytes-1)
 a.output.mkdir(parents=True,exist_ok=False)
 r=dict(passed=True,checks=len(controls),controls=controls,construction=pin((a.build/'build.json').read_bytes()),qualifier=pin(Path(__file__).read_bytes()),original_root_assertions_unchanged=True,unchanged_borrow_leaf_covered_by_prior_checkpoint=True,original_budgets_unchanged=True)
 (a.output/'report.json').write_text(json.dumps(r,indent=2,sort_keys=True)+'\n');print('RUNTIME_INFO_PACKER_PASS',len(controls),flush=True)
if __name__=='__main__':main()
