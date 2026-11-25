"""Fresh native stage-order and same-holder retirement integration gates."""
from pathlib import Path
import argparse,ctypes as C,json,os,struct,time
from tools.qualify_hia_multiversion_runtime_generation import Generation,request,rawdoc,scalar_program,get,sha,sealed,NONE
from tools.qualify_hia_multiversion_prepare_intake import abi_bytes
from hepta.hia_multiversion import _admit,MultiversionRejected
def main():
 p=argparse.ArgumentParser();p.add_argument('--component',required=True,type=Path);p.add_argument('--output',required=True,type=Path)
 for key in ('normalizer','proof','builder'):p.add_argument('--'+key,required=True,type=Path)
 a=p.parse_args();d=a.output;d.mkdir(parents=True,exist_ok=False);lib=C.CDLL(str(a.component))
 files=[(sealed(x.read_bytes()),x.read_bytes()) for x in (a.normalizer,a.proof,a.builder)];rows=[];start=time.monotonic_ns()
 def closefds(out):
  for at in (96,104,512+104,512+112):
   fd=get(out,at)
   if fd!=NONE and fd>=3:
    try:os.close(fd)
    except OSError:pass
 def call(g,name,op):
  rc,out,ns=g.operation(op);(d/(name+'.reply')).write_bytes(out);closefds(out);return rc,out,ns
 def init(name,doc,base=None,prove=False,edit=None):
  g=Generation(lib);path=d/(name+'.so');bp=ba=b''
  if base is not None:
   q,signatures,_=_admit(base);bp=q.canonical_bytes;ba=abi_bytes(q,signatures)
  packet=request(rawdoc(doc),bp,ba,os.fsencode(path),files,baseline=base is None,prove=prove)
  if edit:packet=edit(bytearray(packet))
  rc,out,ns=g.stage(packet);closefds(out);return g,path,rc,out
 def case(name,**facts):rows.append(dict(case=name,**facts));print('GENERATION_BOUNDARY_PASS',name,flush=True)
 for slot,value in [(0,0),(8,7),(16,2),(24,NONE),(32,2147483648),(40,0),(40,30001),(48,0),(56,0),(64,2),(72,2),(80,8388609),(88,8388609),(96,5137),(104,0),(104,4096),(112,8),(120,1),(224,1),(248,1)]:
  g=Generation(lib);path=d/('bad-'+str(slot)+'-'+str(value)+'.so');packet=bytearray(request(rawdoc(scalar_program()),b'',b'',os.fsencode(path),files,baseline=True));struct.pack_into('<Q',packet,slot,value)
  before=set(os.listdir('/proc/self/fd'));rc,out,ns=g.stage(bytes(packet));assert rc==0xfffffffd and out==bytes([0xa5])*4096,(slot,value,rc)
  assert set(os.listdir('/proc/self/fd'))==before and not path.exists()
  case('private-'+str(slot)+'-'+str(value),rc=rc);g.close_memory()
 for name,raw in [('short',b''),('trailing',b'X')]:
  g=Generation(lib);packet=request(rawdoc(scalar_program()),b'',b'',os.fsencode(d/(name+'.so')),files,baseline=True)
  packet=packet[:255] if name=='short' else packet+raw
  rc,out,ns=g.stage(packet);assert rc==0xfffffffd and out==bytes([0xa5])*4096
  case(name,rc=rc);g.close_memory()
 # Actual totality is before candidate ABI mismatch. Both inputs are accepted
 # by the original profile; division by zero must fail at the proof stage.
 zero=scalar_program('int.div.checked',value=0,typ='u8');zero['functions'][0]['effects']=['trap']
 try:_admit(zero,prove_total=True)
 except MultiversionRejected as e:original=str(e)
 else:raise AssertionError('original accepted division by zero')
 g,path,rc,out=init('totality-before-abi',zero,scalar_program(None,typ='u64'),True);assert rc==0
 rc,out,ns=call(g,'totality-before-abi-profile',1);assert rc==3 and not path.exists(),(rc,out[:128])
 assert get(out,112)==0
 case('totality-before-abi',rc=rc,original_error=original);g.close_memory()
 g,path,rc,out=init('abi-mismatch',scalar_program(None,typ='u8'),scalar_program(None,typ='u64'));assert rc==0
 rc,out,ns=call(g,'abi-mismatch-profile',1);assert rc==2 and not path.exists()
 case('abi-mismatch',rc=rc);g.close_memory()
 # Fresh actual builder failure must be held, registered, and only then retired.
 g,path,rc,out=init('bad-builder-pin',scalar_program(),edit=lambda b:bytes(b[:192])+bytes(32)+bytes(b[224:]));assert rc==0
 assert call(g,'bad-builder-pin-profile',1)[0]==0
 rc,out,ns=call(g,'bad-builder-pin-build',3);assert rc==8 and get(out,16)==6 and not path.exists(),(rc,out[:128])
 rc,out,ns=call(g,'bad-builder-pin-registered-release',6);assert rc==4 and not path.exists()
 case('builder-pin-failure-registered-before-release',rc=rc,nested=get(out,40));g.close_memory()
 # Image/path replacement preserves the foreign object and the same old owner.
 g,path,rc,out=init('replacement',scalar_program());assert rc==0
 assert call(g,'replacement-profile',1)[0]==0
 assert call(g,'replacement-build',3)[0]==0
 pin,sealedfd,library=get(g.w,32),get(g.w,48),get(g.w,56)
 original_path=path.with_suffix('.held');path.rename(original_path);path.write_bytes(b'foreign replacement')
 rc,out,ns=call(g,'replacement-pending',4);assert rc==8 and get(g.w,56)==library
 os.fstat(pin);os.fstat(sealedfd);assert path.read_bytes()==b'foreign replacement'
 rc,out,ns=call(g,'replacement-registered-release',6);assert rc==0
 retirement=out[512+1152:512+1152+768];flags=get(retirement,24);assert not(flags&8) and flags&4
 assert path.read_bytes()==b'foreign replacement' and get(g.w,56)==0 and get(g.w,48)==NONE
 held=os.open('/dev/null',os.O_RDONLY)
 try:
  assert call(g,'replacement-repeat-pending',4)[0]==8
  rc,out,ns=call(g,'replacement-repeat-release',6);assert rc==0
  os.fstat(held);assert path.read_bytes()==b'foreign replacement'
 finally:os.close(held)
 path.unlink();original_path.rename(path)
 assert call(g,'replacement-restored-pending',4)[0]==8
 rc,out,ns=call(g,'replacement-restored-release',6);assert rc==0 and not path.exists()
 assert get(out,512+1152+24)&8
 case('replacement-retry-same-holder',complete=True,foreign_preserved=True,descriptor_reuse_preserved=True);g.close_memory()
 for fd,b in files:os.close(fd)
 report=dict(schema='hepta.hia.multiversion-runtime-generation-boundary.v1',whole_native_runtime=False,passed=len(rows),failed=0,image_sha256=sha(a.component.read_bytes()),elapsed_ns=time.monotonic_ns()-start,cases=rows)
 (d/'qualification.json').write_text(json.dumps(report,indent=2)+'\n');print('GENERATION_BOUNDARY_QUALIFIED',len(rows),flush=True)
if __name__=='__main__':main()
