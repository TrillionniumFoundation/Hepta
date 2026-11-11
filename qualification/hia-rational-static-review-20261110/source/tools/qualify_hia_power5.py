"""Native paged 5^k bridge primitive oracle, not complete float conversion."""
from pathlib import Path
from hashlib import sha256
import argparse,ctypes,json,random,shutil,sys
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
def main():
 p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert shutil.disk_usage('/workspace').free>700*1024**2;a.output.mkdir(parents=True,exist_ok=False)
 from hepta.hia_agent_assembly import assemble_program
 from hepta.hia_program_native import build_program_machine
 raw=(ROOT/'hepta/native_numeric/json_power5.hiaasm').read_bytes();core=assemble_program(raw);(a.output/'core.json').write_bytes(core.canonical_bytes)
 receipt=build_program_machine(core,a.output/'power5.so',linker='ld',foreign_buffer_exports=(('pow5_init',256),('pow5_step',256)));(a.output/'BUILD.json').write_text(json.dumps({'source_sha256':sha256(raw).hexdigest(),'receipt':receipt},indent=2)+'\n')
 lib=ctypes.CDLL(str(a.output/'power5.so'));init=lib.pow5_init;step=lib.pow5_step
 init.argtypes=[ctypes.c_void_p,ctypes.c_uint64,ctypes.c_uint64,ctypes.c_uint64,ctypes.c_bool];init.restype=ctypes.c_uint64
 step.argtypes=[ctypes.c_void_p,ctypes.c_uint64]*2+[ctypes.c_uint64,ctypes.c_uint32];step.restype=ctypes.c_uint64
 def convert(magnitude,exponent,from_one=False,event=0,fail_page=None):
  limbs=(magnitude.bit_length()+31)//32;pages={}
  for index in range(limbs):pages.setdefault(index//32,(ctypes.c_uint64*32)())[index%32]=(magnitude>>(32*index))&0xffffffff
  st=(ctypes.c_uint64*32)();action=init(st,256,limbs,exponent,from_one);calls=1
  while action==1:
   request=st[11]
   if request==fail_page:return {'status':'private_page_failure','materialized':False}
   pg=pages.setdefault(request,(ctypes.c_uint64*32)());before=(st[1],st[11],st[16],st[19]);action=step(st,256,pg,256,request,event);calls+=1
   if action==1:assert (st[1],st[11],st[16],st[19])!=before,'native no-progress'
  if action==5:return {'status':'cancelled','materialized':False}
  assert action==2,action
  binary=[]
  for i in range(st[10]):binary.append(bytes(pages[i//32])[(i%32)*8:(i%32)*8+4])
  return {'status':'ok','value':int.from_bytes(b''.join(binary),'little'),'calls':calls,'pages':len(pages)}
 rows=[];powers=(0,1,12,13,14,31,128,1024,4096)
 for exponent in powers:
  actual=convert(0,exponent,from_one=True);assert actual['value']==5**exponent;rows.append({'kind':'native_from_one','exponent':exponent,'calls':actual['calls'],'pages':actual['pages']})
 for magnitude in (0,1,(1<<64)-1,(1<<1024)+1):
  for exponent in powers:
   actual=convert(magnitude,exponent);assert actual['value']==magnitude*5**exponent;rows.append({'kind':'existing_paged_coefficient','input_bits':magnitude.bit_length(),'exponent':exponent,'calls':actual['calls'],'pages':actual['pages']})
 rng=random.Random(518791)
 for _ in range(32):
  magnitude=rng.getrandbits(rng.randrange(1,4097));exponent=rng.randrange(1000);actual=convert(magnitude,exponent);assert actual['value']==magnitude*5**exponent;rows.append({'kind':'random_coefficient','input_bits':magnitude.bit_length(),'exponent':exponent,'calls':actual['calls'],'pages':actual['pages']})
 failures=[]
 for event in (3,9):
  result=convert(1,4096,event=event);assert not result['materialized'];failures.append({'event':event,'result':result})
 result=convert(1<<2048,1,fail_page=1);assert not result['materialized'];failures.append({'missing_page':result})
 st=(ctypes.c_uint64*32)();assert init(st,256,1,1,False)==1;page=(ctypes.c_uint64*32)();page[0]=1;before=(bytes(st),bytes(page));assert step(st,256,page,256,1,0)==4;assert (bytes(st),bytes(page))==before;failures.append({'wrong_page_refused_before_write':True})
 for size in (0,255,257):
  before=bytes(st);assert init(st,size,0,1,True)==4;assert bytes(st)==before
 st=(ctypes.c_uint64*32)();assert init(st,256,2,1,False)==1;page=(ctypes.c_uint64*32)();page[0]=1;page[1]=1<<32;assert step(st,256,page,256,0,0)==4;failures.append({'malformed_limb_aborts_private_result':'earlier scratch writes are not a rollback claim'})
 report={'status':'passed','source_sha256':sha256(raw).hexdigest(),'observations':len(rows),'rows':rows,'failures':failures,'native_owns':'factor/round count/page traversal/limb multiplication/carry/from-one initialization/cancellation','host':'opaque page storage and binary integer materialization only','oracle':'Python integer power/multiply only in test','complete_rational_bridge':False,'normal_Worker_migration':False,'not_cost':True}
 (a.output/'REPORT.json').write_text(json.dumps(report,indent=2)+'\n');(a.output/'SHA256.json').write_text(json.dumps({str(p.relative_to(a.output)):sha256(p.read_bytes()).hexdigest() for p in a.output.rglob('*') if p.is_file() and p.name!='SHA256.json'},indent=2)+'\n');print('PASS native HIA paged power5',len(rows),'oracle observations')
if __name__=='__main__':main()
