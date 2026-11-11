"""Real HIA rational quotient/sticky/RNE qualification; no decimal JSON bridge claim."""
from pathlib import Path
from hashlib import sha256
from fractions import Fraction
import argparse,ctypes,json,random,shutil,struct,sys
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT));NONE=(1<<64)-1

def main():
 p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert shutil.disk_usage('/workspace').free>700*1024**2;a.output.mkdir(parents=True,exist_ok=False)
 from hepta.hia_agent_assembly import assemble_program
 from hepta.hia_program_native import build_program_machine
 raw=(ROOT/'hepta/native_numeric/json_quotient.hiaasm').read_bytes();core=assemble_program(raw);(a.output/'core.json').write_bytes(core.canonical_bytes)
 exports=('quotient_init','quotient_step','quotient_round_prepare','binary64_page','rational_step','pow5_multiply_page')
 receipt=build_program_machine(core,a.output/'quotient.so',linker='ld',foreign_buffer_exports=tuple((name,256) for name in exports));(a.output/'BUILD.json').write_text(json.dumps({'source_sha256':sha256(raw).hexdigest(),'receipt':receipt},indent=2)+'\n')
 lib=ctypes.CDLL(str(a.output/'quotient.so'))
 init=lib.quotient_init;control=lib.quotient_step;prepare=lib.quotient_round_prepare;bitscan=lib.binary64_page;limbstep=lib.rational_step;multiply=lib.pow5_multiply_page
 pair=[ctypes.c_void_p,ctypes.c_uint64]
 init.argtypes=pair*4+[ctypes.c_uint64]*2+[ctypes.c_int64,ctypes.c_bool]
 control.argtypes=pair*4+[ctypes.c_uint32];prepare.argtypes=pair*3;bitscan.argtypes=pair*2+[ctypes.c_uint64,ctypes.c_uint32];limbstep.argtypes=pair*4+[ctypes.c_uint64]*3+[ctypes.c_uint32];multiply.argtypes=pair*2+[ctypes.c_uint64]
 for fn in (init,control,prepare,bitscan,limbstep,multiply):fn.restype=ctypes.c_uint64
 def pages(value):
  limbs=(value.bit_length()+31)//32;result={}
  for i in range(limbs):result.setdefault(i//32,(ctypes.c_uint64*32)())[i%32]=(value>>(32*i))&0xffffffff
  return limbs,result
 def convert(numerator,denominator,scale=0,negative=False,cancel=False,fail=False):
  nl,apages=pages(numerator);dl,bpages=pages(denominator);st=(ctypes.c_uint64*32)();op=(ctypes.c_uint64*32)();sa=(ctypes.c_uint64*16)();sb=(ctypes.c_uint64*16)();zeros=[(ctypes.c_uint64*32)() for _ in range(3)];calls=0
  action=init(st,256,op,256,sa,128,sb,128,nl,dl,scale,negative);calls+=1
  if cancel:
   assert control(st,256,op,256,sa,128,sb,128,3)==8
   return {'status':'cancelled','materialized':False}
  while action not in (6,7,8):
   if fail:return {'status':'private_page_failure','materialized':False}
   if action in (1,2):
    state=sa if action==1 else sb;store=apages if action==1 else bpages
    while True:
     requested=state[3];reply=bitscan(state,128,store[requested],256,requested,0);calls+=1
     if reply==1:continue
     assert reply in (2,3),('bitlength',reply);break
   elif action in (3,4):
    while True:
     aid,bid,cid=op[10],op[11],op[12]
     reply=limbstep(op,256,zeros[0] if aid==NONE else apages[aid],256,zeros[1] if bid==NONE else bpages[bid],256,zeros[2] if cid==NONE else bpages[cid],256,aid,bid,cid,0);calls+=1
     if reply==1:continue
     assert reply==2,('limb',action,reply,list(st));break
   elif action==5:
    while True:
     requested=op[11];page=apages.setdefault(requested,(ctypes.c_uint64*32)());reply=multiply(op,256,page,256,requested);calls+=1
     if reply==2:continue
     assert reply==3,('multiply',reply);break
   else:raise AssertionError(('controller action',action,list(st)))
   action=control(st,256,op,256,sa,128,sb,128,0);calls+=1
  if action in (7,8):return {'status':'rejected','materialized':False,'calls':calls}
  quotient,sticky,binary_scale=st[8],st[10],ctypes.c_int64(st[14]).value
  rs=(ctypes.c_uint64*16)();pg=(ctypes.c_uint64*32)();assert prepare(st,256,rs,128,pg,256)==1;reply=bitscan(rs,128,pg,256,0,0);assert reply in (2,3)
  word=rs[9];value=struct.unpack('>d',word.to_bytes(8,'big'))[0]
  return {'status':'overflow' if reply==3 else 'finite','bits':f'{word:016x}','hex':value.hex(),'quotient':quotient,'sticky':bool(sticky),'binary_scale':binary_scale,'calls':calls}
 def expected(n,d,scale,negative):
  if not n:return {'quotient':0,'sticky':False,'binary_scale':0,'bits':'8000000000000000' if negative else '0000000000000000'}
  e=n.bit_length()-d.bit_length()
  if (n<(d<<e)) if e>=0 else ((n<<(-e))<d):e-=1
  k=53-e;q,r=divmod(n<<k,d) if k>=0 else divmod(n,d<<(-k));combined=e-53+max(-(1<<40),min(1<<40,scale))
  if scale>20000:bits='fff0000000000000' if negative else '7ff0000000000000'
  elif scale<-20000:bits='8000000000000000' if negative else '0000000000000000'
  else:
   ratio=Fraction(n<<scale,d) if scale>=0 else Fraction(n,d<<(-scale))
   if negative:ratio=-ratio
   try:value=float(ratio)
   except OverflowError:value=float('-inf') if negative else float('inf')
   bits=struct.pack('>d',value).hex()
  return {'quotient':q,'sticky':bool(r),'binary_scale':combined,'bits':bits}
 cases=[(0,1,0),(1,1,0),(1,3,0),(2,3,0),(3,2,0),(1,10,0),(1,5**324,-324),(1,5**325,-325),((1<<53)+1,1,-53),((1<<53)-1,1,971),(1,1,(1<<63)-1),(1,1,-(1<<63))]
 rng=random.Random(311919)
 for _ in range(24):
  n=rng.getrandbits(rng.randrange(1,4097)) or 1;d=rng.getrandbits(rng.randrange(1,4097)) or 1;scale=rng.choice((-1074,-53,0,1023));cases.append((n,d,scale))
 rows=[]
 for n,d,scale in cases:
  for negative in (False,True):
   oracle=expected(n,d,scale,negative);actual=convert(n,d,scale,negative);row={'numerator_bits':n.bit_length(),'denominator_bits':d.bit_length(),'scale':scale,'negative':negative,'expected':oracle,'actual':actual};rows.append(row);(a.output/'OBSERVATIONS.json').write_text(json.dumps(rows,indent=2)+'\n');assert all(actual[k]==v for k,v in oracle.items()),row
 rejected=convert(1,0);assert rejected['status']=='rejected' and not rejected['materialized'];cancelled=convert(1,3,cancel=True);failure=convert(1,3,fail=True);assert not cancelled['materialized'] and not failure['materialized']
 report={'status':'passed','source_sha256':sha256(raw).hexdigest(),'IEEE_and_exact_quotient_observations':len(rows),'zero_denominator':rejected,'cancel':cancelled,'page_failure':failure,'native':'normalization, page arithmetic, quotient bits, remainder sticky, and binary64 RNE handoff','host':'opaque page dispatch and struct.unpack bits only','oracle':'Fraction/Python integer/float only in independent qualification','complete_decimal_bridge':False,'normal_Worker_migration':False,'not_cost':True}
 (a.output/'REPORT.json').write_text(json.dumps(report,indent=2)+'\n');(a.output/'SHA256.json').write_text(json.dumps({str(p.relative_to(a.output)):sha256(p.read_bytes()).hexdigest() for p in a.output.rglob('*') if p.is_file() and p.name!='SHA256.json'},indent=2)+'\n');print('PASS native HIA rational quotient',len(rows),'exact quotient/sticky and IEEE observations')
if __name__=='__main__':main()
