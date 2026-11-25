"""Development-only construction of exact decimal algorithm data.

The production structure role consumes the captured .hiadat bytes. GMP is
only an authoring aid; it is not a runtime or native reconstruction dependency.
"""
from pathlib import Path
from hashlib import sha256
import argparse,ctypes as C,ctypes.util,json,os
BITS=33554432
DIGITS=10100891
def decimal_threshold():
 class MPZ(C.Structure):
  _fields_=[('allocated',C.c_int),('used',C.c_int),('limbs',C.POINTER(C.c_ulong))]
 g=C.CDLL(ctypes.util.find_library('gmp'))
 init=getattr(g,'__gmpz_init');init.argtypes=[C.POINTER(MPZ)];init.restype=None
 setui=getattr(g,'__gmpz_set_ui');setui.argtypes=[C.POINTER(MPZ),C.c_ulong];setui.restype=None
 shift=getattr(g,'__gmpz_mul_2exp');shift.argtypes=[C.POINTER(MPZ),C.POINTER(MPZ),C.c_ulong];shift.restype=None
 size=getattr(g,'__gmpz_sizeinbase');size.argtypes=[C.POINTER(MPZ),C.c_int];size.restype=C.c_size_t
 render=getattr(g,'__gmpz_get_str');render.argtypes=[C.c_void_p,C.c_int,C.POINTER(MPZ)];render.restype=C.c_void_p
 clear=getattr(g,'__gmpz_clear');clear.argtypes=[C.POINTER(MPZ)];clear.restype=None
 value=MPZ();init(C.byref(value))
 try:
  setui(C.byref(value),1);shift(C.byref(value),C.byref(value),BITS)
  assert size(C.byref(value),2)==BITS+1
  out=C.create_string_buffer(size(C.byref(value),10)+2)
  assert render(out,10,C.byref(value))==C.addressof(out)
  raw=out.value
 finally:clear(C.byref(value))
 assert len(raw)==DIGITS and raw.isdigit() and raw[0]!=48
 assert raw[-128:]==str(pow(2,BITS,10**128)).zfill(128).encode()
 return raw
def main():
 p=argparse.ArgumentParser();p.add_argument('--output',type=Path,default=Path(__file__).resolve().parents[1]/'examples/hia_bootstrap/background_optimizer_integer_threshold.hiadat');a=p.parse_args()
 raw=decimal_threshold()
 if a.output.exists():
  assert a.output.read_bytes()==raw,'existing source algorithm data differs'
 else:
  fd=os.open(a.output,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_CLOEXEC,0o644)
  try:
   at=0
   while at<len(raw):
    n=os.write(fd,raw[at:]);assert n>0;at+=n
   os.fsync(fd)
  finally:os.close(fd)
 print(json.dumps({'path':str(a.output),'bytes':len(raw),'sha256':sha256(raw).hexdigest(),'mathematical_value':'2^33554432','no_runtime_GMP':True}),flush=True)
if __name__=='__main__':main()
