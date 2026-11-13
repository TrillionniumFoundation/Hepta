"""Native paged shifted compare/subtract oracle; no host arithmetic in driver."""
from pathlib import Path
from hashlib import sha256
import argparse,ctypes,json,random,shutil,sys
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT));NONE=(1<<64)-1

def main():
 p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert shutil.disk_usage('/workspace').free>700*1024**2;a.output.mkdir(parents=True,exist_ok=False)
 from hepta.hia_agent_assembly import assemble_program
 from hepta.hia_program_native import build_program_machine
 raw=(ROOT/'hepta/native_numeric/json_rational_limb.hiaasm').read_bytes();core=assemble_program(raw);(a.output/'core.json').write_bytes(core.canonical_bytes)
 receipt=build_program_machine(core,a.output/'limb.so',linker='ld',foreign_buffer_exports=(('rational_init',256),('rational_step',256)));(a.output/'BUILD.json').write_text(json.dumps({'source_sha256':sha256(raw).hexdigest(),'receipt':receipt},indent=2)+'\n')
 lib=ctypes.CDLL(str(a.output/'limb.so'));init=lib.rational_init;step=lib.rational_step
 init.argtypes=[ctypes.c_void_p,ctypes.c_uint64,ctypes.c_uint32]+[ctypes.c_uint64]*3;init.restype=ctypes.c_uint64
 step.argtypes=[ctypes.c_void_p,ctypes.c_uint64]*4+[ctypes.c_uint64]*3+[ctypes.c_uint32];step.restype=ctypes.c_uint64
 def pages(value):
  length=(value.bit_length()+31)//32;result={}
  for i in range(length):result.setdefault(i//32,(ctypes.c_uint64*32)())[i%32]=(value>>(32*i))&0xffffffff
  return length,result
 def operation(left,right,shift,mode=1,event=0,fail=False):
  alen,apages=pages(left);blen,bpages=pages(right);state=(ctypes.c_uint64*32)();action=init(state,256,mode,alen,blen,shift);calls=1;zeroa=(ctypes.c_uint64*32)();zerob=(ctypes.c_uint64*32)();zeroc=(ctypes.c_uint64*32)()
  while action==1:
   aid,bid,cid=state[10],state[11],state[12]
   if fail:return {'status':'private_page_failure','materialized':False}
   before=state[8];action=step(state,256,zeroa if aid==NONE else apages[aid],256,zerob if bid==NONE else bpages[bid],256,zeroc if cid==NONE else bpages[cid],256,aid,bid,cid,event);calls+=1
   if action==1:assert state[8]!=before,'native no-progress'
  if action in (4,5):return {'status':'rejected' if action==4 else 'cancelled','materialized':False,'calls':calls}
  assert action==2,action
  if mode==1:return {'status':'ok','relation':ctypes.c_int64(state[14]).value,'calls':calls}
  binary=[]
  for i in range(alen):binary.append(bytes(apages[i//32])[(i%32)*8:(i%32)*8+4])
  return {'status':'ok','difference':int.from_bytes(b''.join(binary),'little'),'calls':calls}
 cases=[]
 for shift in (0,1,31,32,33,1023,1024,1025):
  for left,right in ((0,0),(0,1),(1,0),((1<<2048)-1,(1<<1024)+1),(1<<2048,1),((1<<1030)+3,(1<<7)+1)):
   cases.append((left,right,shift))
 rng=random.Random(617913)
 for _ in range(80):cases.append((rng.getrandbits(rng.randrange(4097)),rng.getrandbits(rng.randrange(2049)),rng.randrange(1100)))
 rows=[]
 for left,right,shift in cases:
  expected=(left>(right<<shift))-(left<(right<<shift));actual=operation(left,right,shift);assert actual['status']=='ok' and actual['relation']==expected,(left.bit_length(),right.bit_length(),shift,actual,expected)
  diff=operation(left,right,shift,2)
  if expected>=0:assert diff['status']=='ok' and diff['difference']==left-(right<<shift)
  else:assert diff['status']=='rejected' and not diff['materialized']
  rows.append({'left_bits':left.bit_length(),'right_bits':right.bit_length(),'shift':shift,'relation':expected,'compare_calls':actual['calls'],'subtract_status':diff['status'],'subtract_calls':diff['calls']})
 failures=[]
 for event in (3,9):
  result=operation(100,1,1,event=event);assert not result['materialized'];failures.append({'event':event,'result':result})
 result=operation(100,1,1,fail=True);assert not result['materialized'];failures.append({'missing_page':result})
 st=(ctypes.c_uint64*32)();assert init(st,256,1,1,1,0)==1;pg=(ctypes.c_uint64*32)();pg[0]=1;bp=(ctypes.c_uint64*32)();cp=(ctypes.c_uint64*32)();before=(bytes(st),bytes(pg));assert step(st,256,pg,256,bp,256,cp,256,99,st[11],st[12],0)==4;assert (bytes(st),bytes(pg))==before;failures.append({'wrong_page_refused_before_write':True})
 report={'status':'passed','source_sha256':sha256(raw).hexdigest(),'compare_observations':len(rows),'subtract_observations':len(rows),'rows':rows,'failures':failures,'native_owns':'page selection, virtual shifted words, direction, compare result, borrow, and continuation','host':'opaque pages and binary materialization; expected bigint semantics only in independent oracle','raw_private_underflow_not_rollback_claim':True,'complete_rational_bridge':False,'normal_Worker_migration':False,'not_cost':True}
 (a.output/'REPORT.json').write_text(json.dumps(report,indent=2)+'\n');(a.output/'SHA256.json').write_text(json.dumps({str(p.relative_to(a.output)):sha256(p.read_bytes()).hexdigest() for p in a.output.rglob('*') if p.is_file() and p.name!='SHA256.json'},indent=2)+'\n');print('PASS native HIA shifted limb',len(rows),'compare +',len(rows),'subtract oracle observations')
if __name__=='__main__':main()
