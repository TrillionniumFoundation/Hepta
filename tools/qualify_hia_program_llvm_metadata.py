"""Actual completed emitter workspace metadata, with the original public oracle."""
from pathlib import Path
import argparse,ctypes as C,hashlib,json,mmap,struct,traceback
SIG=C.CFUNCTYPE(C.c_uint32,*([C.c_void_p,C.c_uint64]*3))
def function(name):
 return dict(name=name,params=[dict(name='x',type='u64')],returns=['u64'],effects=[],entry='entry',blocks=[dict(id='entry',params=[dict(name='x',type='u64')],ops=[],term=dict(op='ret',values=['x']))])
def main():
 p=argparse.ArgumentParser();p.add_argument('--library',type=Path,required=True);p.add_argument('--metadata',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();a.output.mkdir(mode=0o700)
 from hepta.hia_program import verify_program
 from hepta import hia_program_llvm as original
 lib=C.CDLL(str(a.library));emitter=lib.hia_program_llvm;emitter.argtypes=[C.c_void_p,C.c_uint64]*3;emitter.restype=C.c_uint32
 raw=a.metadata.read_bytes();code=mmap.mmap(-1,len(raw),prot=mmap.PROT_READ|mmap.PROT_WRITE);code.write(raw);anchor=(C.c_ubyte*len(raw)).from_buffer(code)
 libc=C.CDLL(None);libc.mprotect.argtypes=[C.c_void_p,C.c_size_t,C.c_int];assert libc.mprotect(C.addressof(anchor),len(raw),mmap.PROT_READ|mmap.PROT_EXEC)==0
 meta=SIG(C.addressof(anchor));request=C.create_string_buffer(b'HIALLM01'+bytes(24));rows=[]
 report=dict(passed=False,schema='hepta.hia.llvm-metadata-qualification.v1',whole_clang_outer_qualified=False,cases=rows,metadata_sha256=hashlib.sha256(raw).hexdigest())
 def save():(a.output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
 try:
  for version,names in [(v,['zulu','Alpha','zero'])for v in range(1,10)]+[(9,['export_'+str(i).zfill(3)for i in reversed(range(128))])]:
   doc=dict(schema='hepta.hia.program.v'+str(version),module='native_metadata_qa',functions=[function(name)for name in names])
   program=verify_program(doc)
   for target in range(3):
    oracle=original.emit_program_llvm(program,target=(original.TARGET,original.TARGET_AARCH64,original.TARGET_RISCV64)[target])
    core=program.canonical_bytes;wire=b'HIALLV01'+struct.pack('<7Q',target,0,len(core),0,0,0,0)+core;source=C.create_string_buffer(wire)
    with mmap.mmap(-1,16<<20)as output,mmap.mmap(-1,128<<20)as work:
     ob=(C.c_ubyte*(16<<20)).from_buffer(output);wb=(C.c_ubyte*(128<<20)).from_buffer(work);out=C.create_string_buffer(65536)
     try:
      ir_n=emitter(source,len(wire),ob,len(ob),wb,len(wb));assert 0<ir_n<=16<<20
      assert bytes(output[:ir_n])==oracle.text.encode()
      size=meta(request,32,out,65536,wb,len(wb));assert 64<=size<=65536
      v=struct.unpack_from('<8Q',out);assert bytes(out)[:8]==b'HIALLR01'and v[1:6]==(version,target,0,len(names),ir_n)and v[6]==size-64,v
      found=[];at=64
      for _ in range(v[4]):
       n=struct.unpack_from('<Q',out,at)[0];at+=8;found.append(bytes(out)[at:at+n].decode('ascii'));at+=n
      assert at==size and tuple(found)==oracle.exports,(found,oracle.exports)
      rows.append(dict(version=version,target=target,exports=len(names),bytes=size,actual_native_ir_equal=True,metadata_equal=True));save()
     finally:del ob,wb
  report['passed']=True;save();print(json.dumps(dict(passed=True,cases=len(rows),report=str(a.output/'report.json'))),flush=True)
 except BaseException:
  report['error']=traceback.format_exc();save();raise
 finally:
  del meta,anchor;code.close()
if __name__=='__main__':main()
