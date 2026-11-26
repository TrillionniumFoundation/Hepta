"""Retained original tests with actual HIA-emitted LLVM bytes.

All Python verification, metadata and Clang orchestration in this campaign are
explicit development oracles. This tool does not qualify the production outer.
"""
from pathlib import Path
import argparse,ctypes as C,dataclasses,hashlib,json,mmap,os,sys,time,unittest
ROOT=Path(__file__).resolve().parents[1]
PRIMITIVE_MODULES=("tests.test_hia_bulk_memory","tests.test_hia_finite_context","tests.test_hia_crc_linear","tests.test_hia_returned_loans","tests.test_hia_scalar_return_signature","tests.test_hia_offset_copy_v5","tests.test_hia_scoped_alloc_native","tests.test_hia_empty_owner_native","tests.test_hia_composite_bulk_native","tests.test_hia_sequential_core","tests.test_hia_composite_v6_resources","tests.test_hia_scalar_phi_edges","tests.test_hia_range_fill_v6","tests.test_hia_word_memory","tests.test_hia_allocation_normalization","tests.test_hia_guarded_batch","tests.test_hia_scalar_boundary_conformance","tests.test_hia_overlap_move","tests.test_hia_composite_abi","tests.test_hia_zero_length_bulk_native","tests.test_hia_swap_v4")
class NativeEmitter:
 def __init__(self,library):
  self.library=C.CDLL(str(library));self.entry=self.library.hia_program_llvm
  self.entry.argtypes=[C.c_void_p,C.c_uint64]*3;self.entry.restype=C.c_uint32
 def emit(self,document,target,layout):
  import struct
  raw=json.dumps(document,separators=(',',':'),ensure_ascii=True).encode()
  wire=b'HIALLV01'+struct.pack('<7Q',target,layout,len(raw),0,0,0,0)+raw;source=C.create_string_buffer(wire)
  with mmap.mmap(-1,16<<20)as output,mmap.mmap(-1,128<<20)as work:
   ob=(C.c_ubyte*(16<<20)).from_buffer(output);wb=(C.c_ubyte*(128<<20)).from_buffer(work)
   try:
    n=self.entry(source,len(wire),ob,len(ob),wb,len(wb))
    assert 0<n<len(output),dict(return_code=n,phase=struct.unpack_from('<Q',work,24<<20)[0],error=struct.unpack_from('<Q',work,(24<<20)+8)[0])
    return bytes(output[:n])
   finally:del ob,wb
def main():
 parser=argparse.ArgumentParser();parser.add_argument('--library',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);parser.add_argument('--z3-python',type=Path,required=True);parser.add_argument('--z3-library',type=Path,required=True);parser.add_argument('--clang',default='/usr/bin/clang-20');parser.add_argument('--qemu-aarch64',type=Path);parser.add_argument('--campaign',choices=('core','primitive','initialization'),default='core');a=parser.parse_args()
 sys.dont_write_bytecode=True;sys.path.insert(0,str(a.z3_python));os.environ['Z3_LIBRARY_PATH']=str(a.z3_library)
 os.environ['CLANG']=a.clang;os.environ['HIA_TEST_CLANG20']=a.clang
 if a.qemu_aarch64:os.environ['HEPTA_QEMU_AARCH64']=str(a.qemu_aarch64)
 import z3
 assert z3.get_version_string()=='4.15.4'
 from unittest.mock import Mock
 from hepta import hia_program_llvm as llvm
 original=llvm.emit_program_llvm;client=NativeEmitter(a.library);rows=[];a.output.mkdir(mode=0o700)
 def candidate(program,*,target=llvm.TARGET,layout='canonical'):
  oracle=original(program,target=target,layout=layout)
  actual=client.emit(program.as_dict(),(llvm.TARGET,llvm.TARGET_AARCH64,llvm.TARGET_RISCV64).index(target),('canonical','guarded-outline-v1').index(layout))
  fault_control=isinstance(llvm._can_elide_zero_initialization,Mock);native_sha=hashlib.sha256(actual).hexdigest()
  if fault_control:
   assert llvm._can_elide_zero_initialization.return_value is True
   assert oracle.core_sha256=='e6ff0729c9a2bc026d53661ea2952b98bd12c3687f9ef7fa0d2c9af27ad658dc'
   marker=b'@__hia_allocate(i64 %p_0_0, i1 true)'
   assert actual.count(marker)==1
   actual=actual.replace(marker,b'@__hia_allocate(i64 %p_0_0, i1 false)',1)
  if actual!=oracle.text.encode():
   name='mismatch-'+oracle.core_sha256+'-'+str(len(rows))
   (a.output/(name+'.core.json')).write_text(json.dumps(program.as_dict(),indent=2)+'\n')
   (a.output/(name+'.expected.ll')).write_bytes(oracle.text.encode());(a.output/(name+'.actual.ll')).write_bytes(actual)
   raise AssertionError(('native LLVM differs',target,layout,oracle.core_sha256))
  rows.append(dict(core_sha256=oracle.core_sha256,llvm_sha256=hashlib.sha256(actual).hexdigest(),bytes=len(actual),target=target,layout=layout,native_equal=not fault_control,explicit_unverified_fault_control=fault_control,correct_native_sha256=native_sha))
  return dataclasses.replace(oracle,text=actual.decode('ascii'))
 extra=('tests.test_hia_initialization.InitializationNativeTests',)
 if a.campaign=='core':modules=('tests.test_hia_program_llvm','tests.test_hia_byte_sum');names=modules+extra
 elif a.campaign=='primitive':modules=PRIMITIVE_MODULES;names=modules+extra
 else:modules=();names=extra
 pins={name.replace('.','/')+'.py':hashlib.sha256((ROOT/(name.replace('.','/')+'.py')).read_bytes()).hexdigest()for name in modules+('tests.test_hia_initialization',)}
 llvm.emit_program_llvm=candidate
 try:
  suite=unittest.TestLoader().loadTestsFromNames(names);start=time.monotonic()
  with(a.output/'report.log').open('w')as stream:result=unittest.TextTestRunner(stream=stream,verbosity=2).run(suite)
 finally:llvm.emit_program_llvm=original
 report=dict(schema='hepta.hia.program-llvm-original-campaign.v2',passed=result.wasSuccessful(),campaign=a.campaign,tests=result.testsRun,failures=len(result.failures),errors=len(result.errors),skipped=result.skipped,seconds=time.monotonic()-start,emissions=rows,original_fixtures=pins,product=dict(bytes=a.library.stat().st_size,sha256=hashlib.sha256(a.library.read_bytes()).hexdigest()),scope='actual native HIA LLVM bytes; original verifier, compiler and metadata are QA oracles',whole_llvm_qualified=False,whole_native_runtime_qualified=False)
 (a.output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
 print(json.dumps({k:v for k,v in report.items()if k not in ('emissions','original_fixtures')},indent=2),flush=True)
 print((a.output/'report.log').read_text()[-20000:],flush=True)
 assert result.wasSuccessful() and not result.skipped
if __name__=='__main__':main()
